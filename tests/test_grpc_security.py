"""Regression tests for the issuance service's internal gRPC boundary."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import grpc
import pytest
from issuance.infrastructure.grpc_security import (
    ServiceAuthInterceptor,
    ServiceTokenClientInterceptor,
    create_service_channel,
    read_service_token,
    server_interceptors,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.delenv("GRPC_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("GRPC_SERVICE_TOKEN_FILE", raising=False)
    monkeypatch.delenv("GRPC_TLS_CA_CERT", raising=False)
    monkeypatch.delenv("GRPC_CA_CERT", raising=False)


def test_production_requires_service_token(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")

    with pytest.raises(RuntimeError, match="GRPC_SERVICE_TOKEN.*required"):
        read_service_token()


@pytest.mark.parametrize("token", ["change_me_grpc_token", "too-short"])
def test_production_rejects_weak_service_token(monkeypatch, token):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("GRPC_SERVICE_TOKEN", token)

    with pytest.raises(RuntimeError):
        read_service_token()


def test_secret_file_configures_server_and_client(monkeypatch, tmp_path):
    token_file = tmp_path / "grpc_service_token"
    token = "a" * 48
    token_file.write_text(token + "\n", encoding="utf-8")
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("GRPC_SERVICE_TOKEN_FILE", str(token_file))

    interceptors = server_interceptors()
    assert len(interceptors) == 1
    assert isinstance(interceptors[0], ServiceAuthInterceptor)

    with patch(
        "issuance.infrastructure.grpc_security.grpc_aio.insecure_channel"
    ) as channel_factory:
        channel_factory.return_value = MagicMock()
        channel = create_service_channel("credential-template:9003")

    assert channel is channel_factory.return_value
    client_interceptors = channel_factory.call_args.kwargs["interceptors"]
    assert len(client_interceptors) == 1
    assert isinstance(client_interceptors[0], ServiceTokenClientInterceptor)
    assert client_interceptors[0]._token == token


def test_environment_and_file_are_mutually_exclusive(monkeypatch, tmp_path):
    token_file = tmp_path / "grpc_service_token"
    token_file.write_text("b" * 48, encoding="utf-8")
    monkeypatch.setenv("GRPC_SERVICE_TOKEN", "c" * 48)
    monkeypatch.setenv("GRPC_SERVICE_TOKEN_FILE", str(token_file))

    with pytest.raises(RuntimeError, match="Both GRPC_SERVICE_TOKEN"):
        read_service_token()


def test_client_interceptor_covers_every_rpc_cardinality():
    interceptor = ServiceTokenClientInterceptor("a" * 48)

    assert isinstance(interceptor, grpc.aio.UnaryUnaryClientInterceptor)
    assert isinstance(interceptor, grpc.aio.UnaryStreamClientInterceptor)
    assert isinstance(interceptor, grpc.aio.StreamUnaryClientInterceptor)
    assert isinstance(interceptor, grpc.aio.StreamStreamClientInterceptor)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("factory", "cardinality"),
    [
        (grpc.unary_unary_rpc_method_handler, "unary_unary"),
        (grpc.unary_stream_rpc_method_handler, "unary_stream"),
        (grpc.stream_unary_rpc_method_handler, "stream_unary"),
        (grpc.stream_stream_rpc_method_handler, "stream_stream"),
    ],
)
async def test_rejection_preserves_rpc_cardinality(factory, cardinality):
    original = factory(lambda request, context: None)
    continuation = AsyncMock(return_value=original)
    details = SimpleNamespace(method="/issuance.Test/Call", invocation_metadata=())

    rejected = await ServiceAuthInterceptor("a" * 48).intercept_service(
        continuation,
        details,
    )

    assert getattr(rejected, cardinality) is not None


def test_issuance_code_has_no_raw_grpc_channel_bypass():
    helper = ROOT / "services/issuance/infrastructure/grpc_security.py"
    offenders = []
    for path in (ROOT / "services/issuance").rglob("*.py"):
        if path == helper:
            continue
        if ".insecure_channel(" in path.read_text(encoding="utf-8"):
            offenders.append(path.relative_to(ROOT).as_posix())

    assert offenders == []
