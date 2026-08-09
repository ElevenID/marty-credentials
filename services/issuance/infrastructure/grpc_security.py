"""Fail-closed service authentication for issuance gRPC clients and server."""

from __future__ import annotations

import hmac
import logging
import os

import grpc
from grpc import aio as grpc_aio

logger = logging.getLogger(__name__)

_SERVICE_TOKEN_HEADER = "x-service-token"
_DEV_ENVIRONMENTS = {"development", "dev", "local", "test"}
_PLACEHOLDER_PREFIXES = (
    "change-me",
    "change_me",
    "changeme",
    "replace-me",
    "replace_me",
)


def _is_development() -> bool:
    return os.environ.get("ENVIRONMENT", "development").lower() in _DEV_ENVIRONMENTS


def read_service_token() -> str:
    """Read the service token from an environment value or mounted secret file."""
    token = os.environ.get("GRPC_SERVICE_TOKEN", "").strip()
    token_file = os.environ.get("GRPC_SERVICE_TOKEN_FILE", "").strip()
    if token and token_file:
        raise RuntimeError(
            "Both GRPC_SERVICE_TOKEN and GRPC_SERVICE_TOKEN_FILE are set; choose one."
        )
    if token_file:
        try:
            with open(token_file, encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError as exc:
            raise RuntimeError(f"Unable to read GRPC_SERVICE_TOKEN_FILE: {token_file}") from exc

    if _is_development():
        return token
    if not token:
        raise RuntimeError(
            "GRPC_SERVICE_TOKEN or GRPC_SERVICE_TOKEN_FILE is required outside "
            "development environments."
        )
    if token.lower().startswith(_PLACEHOLDER_PREFIXES):
        raise RuntimeError("GRPC_SERVICE_TOKEN must not be a placeholder in production.")
    if len(token) < 32:
        raise RuntimeError("GRPC_SERVICE_TOKEN must contain at least 32 characters in production.")
    return token


class ServiceTokenClientInterceptor(
    grpc_aio.UnaryUnaryClientInterceptor,
    grpc_aio.UnaryStreamClientInterceptor,
    grpc_aio.StreamUnaryClientInterceptor,
    grpc_aio.StreamStreamClientInterceptor,
):
    """Attach the service token to every outbound RPC call shape."""

    def __init__(self, token: str) -> None:
        self._token = token

    def _authenticated_details(self, client_call_details):
        metadata = list(client_call_details.metadata or [])
        metadata.append((_SERVICE_TOKEN_HEADER, self._token))
        return client_call_details._replace(metadata=metadata)

    async def intercept_unary_unary(self, continuation, client_call_details, request):
        return await continuation(self._authenticated_details(client_call_details), request)

    async def intercept_unary_stream(self, continuation, client_call_details, request):
        return await continuation(self._authenticated_details(client_call_details), request)

    async def intercept_stream_unary(self, continuation, client_call_details, request_iterator):
        return await continuation(
            self._authenticated_details(client_call_details), request_iterator
        )

    async def intercept_stream_stream(self, continuation, client_call_details, request_iterator):
        return await continuation(
            self._authenticated_details(client_call_details), request_iterator
        )


class ServiceAuthInterceptor(grpc_aio.ServerInterceptor):
    """Reject inbound calls without the configured service token."""

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)
        if handler is None:
            return None
        token = dict(handler_call_details.invocation_metadata).get(
            _SERVICE_TOKEN_HEADER,
            "",
        )
        if hmac.compare_digest(token, self._expected_token):
            return handler

        logger.warning("Rejected unauthenticated gRPC call to %s", handler_call_details.method)

        async def abort_unary(request, context):
            await context.abort(
                grpc.StatusCode.UNAUTHENTICATED,
                "Missing or invalid service token",
            )

        async def abort_stream(request, context):
            await context.abort(
                grpc.StatusCode.UNAUTHENTICATED,
                "Missing or invalid service token",
            )
            if False:  # pragma: no cover - keeps this an async generator
                yield None

        handler_kwargs = {
            "request_deserializer": handler.request_deserializer,
            "response_serializer": handler.response_serializer,
        }
        if handler.unary_unary:
            return grpc.unary_unary_rpc_method_handler(abort_unary, **handler_kwargs)
        if handler.unary_stream:
            return grpc.unary_stream_rpc_method_handler(abort_stream, **handler_kwargs)
        if handler.stream_unary:
            return grpc.stream_unary_rpc_method_handler(abort_unary, **handler_kwargs)
        return grpc.stream_stream_rpc_method_handler(abort_stream, **handler_kwargs)

    def __init__(self, expected_token: str) -> None:
        self._expected_token = expected_token


def server_interceptors() -> list[grpc_aio.ServerInterceptor]:
    """Build mandatory production server authentication interceptors."""
    token = read_service_token()
    return [ServiceAuthInterceptor(token)] if token else []


def create_service_channel(target: str) -> grpc_aio.Channel:
    """Create a channel that authenticates to Marty internal gRPC services."""
    token = read_service_token()
    interceptors = [ServiceTokenClientInterceptor(token)] if token else None
    ca_path = (
        os.environ.get("GRPC_TLS_CA_CERT", "").strip() or os.environ.get("GRPC_CA_CERT", "").strip()
    )
    if ca_path:
        try:
            with open(ca_path, "rb") as handle:
                credentials = grpc.ssl_channel_credentials(root_certificates=handle.read())
        except OSError as exc:
            raise RuntimeError(f"Unable to read GRPC_TLS_CA_CERT: {ca_path}") from exc
        return grpc_aio.secure_channel(
            target,
            credentials,
            interceptors=interceptors,
        )
    return grpc_aio.insecure_channel(target, interceptors=interceptors)
