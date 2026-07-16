"""Portable outbound clients for Canvas LTI Advantage services.

Canvas exposes AGS and NRPS as services that an LTI tool calls.  This module
intentionally contains no Canvas webhook behavior; callers provide a signed
client assertion and the URLs obtained from a verified LTI launch.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from issuance.application.canvas_feature_flags import (
    private_canvas_origin_allowlist,
    self_managed_canvas_origin_allowlist,
)

AGS_RESULT_READ_SCOPE = "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly"
NRPS_MEMBERSHIP_READ_SCOPE = "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"
CANVAS_LTI_TRUST_HOSTED_GLOBAL = "hosted_global"
CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN = "self_managed_same_origin"
CANVAS_LTI_TRUST_PROFILES = frozenset(
    {
        CANVAS_LTI_TRUST_HOSTED_GLOBAL,
        CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN,
    }
)
CANVAS_TOKEN_RESPONSE_MAX_BYTES = 64 * 1024
CANVAS_COLLECTION_PAGE_MAX_BYTES = 8 * 1024 * 1024
CANVAS_COLLECTION_MAX_PAGES = 200


class CanvasLtiServiceError(RuntimeError):
    """A portable LTI service could not be authorized or read safely."""

    def __init__(
        self,
        message: str,
        *,
        retry_after_seconds: int | None = None,
        reauthorization_required: bool = False,
        retryable: bool = True,
    ) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds
        self.reauthorization_required = reauthorization_required
        self.retryable = retryable


@dataclass(frozen=True)
class CanvasLtiAccessToken:
    value: str
    expires_in: int | None = None
    scope: str | None = None


def parse_canvas_retry_after(value: str | None, *, now: datetime | None = None) -> int | None:
    """Parse Canvas' delta-seconds or HTTP-date Retry-After value safely."""

    normalized = str(value or "").strip()
    if not normalized:
        return None
    try:
        return max(0, min(int(normalized), 86400))
    except (TypeError, ValueError):
        pass
    try:
        retry_at = parsedate_to_datetime(normalized)
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        current = now or datetime.now(UTC)
        return max(0, min(int((retry_at - current).total_seconds()), 86400))
    except (TypeError, ValueError, OverflowError):
        return None


def normalize_canvas_https_origin(value: str) -> str:
    parsed = urlparse(str(value or "").strip())
    try:
        port = parsed.port
    except ValueError as exc:
        raise CanvasLtiServiceError("Canvas origins must contain a valid HTTPS port") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise CanvasLtiServiceError("Canvas origins must use HTTPS without embedded credentials")
    hostname = parsed.hostname.lower().rstrip(".")
    host = f"[{hostname}]" if ":" in hostname else hostname
    return f"https://{host}{f':{port}' if port not in {None, 443} else ''}"


def _is_private_canvas_hostname(hostname: str) -> bool:
    normalized = hostname.lower().rstrip(".")
    if normalized == "localhost" or normalized.endswith(".localhost") or normalized.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return bool(
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def _normalized_private_canvas_origins() -> frozenset[str]:
    origins: set[str] = set()
    for configured in private_canvas_origin_allowlist():
        try:
            parsed = urlparse(configured)
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                continue
            origins.add(normalize_canvas_https_origin(configured))
        except CanvasLtiServiceError:
            # Invalid operator entries never broaden private-network access.
            continue
    return frozenset(origins)


def validate_canvas_origin(value: str) -> str:
    """Normalize a pinned Canvas origin and gate private deployments explicitly."""

    origin = normalize_canvas_https_origin(value)
    hostname = urlparse(origin).hostname or ""
    allowlisted_origins = _normalized_private_canvas_origins()
    private_resolution = _is_private_canvas_hostname(hostname)
    try:
        resolved = {
            item[4][0]
            for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
            if item[4]
        }
        private_resolution = private_resolution or any(
            _is_private_canvas_hostname(address) for address in resolved
        )
    except OSError as exc:
        environment = os.environ.get(
            "ENVIRONMENT", os.environ.get("APP_ENV", "development")
        ).strip().lower()
        if environment in {"production", "prod"}:
            raise CanvasLtiServiceError(
                "Canvas origin DNS resolution failed closed"
            ) from exc
    if private_resolution and origin not in allowlisted_origins:
        raise CanvasLtiServiceError(
            "Private Canvas origins require an exact CANVAS_PRIVATE_ORIGIN_ALLOWLIST entry"
        )
    return origin


def _canvas_origin_is_private_allowlisted(origin: str) -> bool:
    return origin in _normalized_private_canvas_origins()


def _resolved_canvas_addresses(hostname: str, port: int) -> tuple[str, ...]:
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
            if item[4]
        }
    except OSError as exc:
        raise CanvasLtiServiceError("Canvas origin DNS resolution failed closed") from exc
    if not addresses:
        raise CanvasLtiServiceError("Canvas origin DNS resolution returned no addresses")
    return tuple(sorted(addresses, key=lambda item: (":" in item, item)))


class PinnedCanvasAsyncTransport(httpx.AsyncBaseTransport):
    """Resolve and validate each Canvas request before connecting to that exact IP.

    Rewriting the connection URL prevents a second resolver lookup between the
    SSRF check and the TCP connection. The original Host header and TLS SNI are
    retained so hosted Canvas virtual hosts and certificate checks keep working.
    """

    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._injected_transport = transport
        self._origin_transports: dict[str, httpx.AsyncBaseTransport] = {}

    def _transport_for_origin(self, origin: str) -> httpx.AsyncBaseTransport:
        if self._injected_transport is not None:
            return self._injected_transport
        transport = self._origin_transports.get(origin)
        if transport is None:
            # httpcore keys pooled connections by the rewritten IP origin. A
            # separate pool per original hostname prevents a TLS connection
            # established with one SNI name from being reused for another
            # Canvas hostname that happens to share the same CDN address.
            transport = httpx.AsyncHTTPTransport(
                trust_env=False,
                retries=0,
            )
            self._origin_transports[origin] = transport
        return transport

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        origin = normalize_canvas_https_origin(str(request.url))
        hostname = request.url.host.lower().rstrip(".")
        port = request.url.port or 443
        addresses = _resolved_canvas_addresses(hostname, port)
        private_addresses = [address for address in addresses if _is_private_canvas_hostname(address)]
        if (
            _is_private_canvas_hostname(hostname) or private_addresses
        ) and not _canvas_origin_is_private_allowlisted(origin):
            raise CanvasLtiServiceError(
                "Private Canvas origins require an exact CANVAS_PRIVATE_ORIGIN_ALLOWLIST entry"
            )

        # Reject mixed public/private DNS answers unless the exact origin was
        # explicitly approved. Otherwise resolver ordering could bypass the gate.
        resolved_address = addresses[0]
        original_host = f"[{hostname}]" if ":" in hostname else hostname
        if port != 443:
            original_host = f"{original_host}:{port}"
        headers = request.headers.copy()
        headers["Host"] = original_host
        extensions = dict(request.extensions)
        extensions["sni_hostname"] = hostname
        pinned_request = httpx.Request(
            method=request.method,
            url=request.url.copy_with(host=resolved_address),
            headers=headers,
            stream=request.stream,
            extensions=extensions,
        )
        return await self._transport_for_origin(origin).handle_async_request(
            pinned_request
        )

    async def aclose(self) -> None:
        if self._injected_transport is not None:
            await self._injected_transport.aclose()
            return
        for transport in self._origin_transports.values():
            await transport.aclose()


def canvas_http_client(*, timeout: float = 15.0) -> httpx.AsyncClient:
    """Create a no-redirect, no-proxy client with DNS-pinned Canvas transport."""

    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
        transport=PinnedCanvasAsyncTransport(),
    )


def hosted_canvas_lti_profile(canvas_origin: str) -> dict[str, str]:
    """Return Instructure's documented environment-specific hosted LTI trust."""

    normalized_origin = normalize_canvas_https_origin(canvas_origin)
    hostname = (urlparse(normalized_origin).hostname or "").lower()
    if ".beta.instructure.com" in hostname or hostname == "canvas.beta.instructure.com":
        environment = "beta"
        issuer = "https://canvas.beta.instructure.com"
        sso_origin = "https://sso.beta.canvaslms.com"
    elif ".test.instructure.com" in hostname or hostname == "canvas.test.instructure.com":
        environment = "test"
        issuer = "https://canvas.test.instructure.com"
        sso_origin = "https://sso.test.canvaslms.com"
    else:
        environment = "production"
        issuer = "https://canvas.instructure.com"
        sso_origin = "https://sso.canvaslms.com"
    return {
        "trust_profile": CANVAS_LTI_TRUST_HOSTED_GLOBAL,
        "environment": environment,
        "issuer": issuer,
        "authorization_endpoint": f"{sso_origin}/api/lti/authorize_redirect",
        "jwks_uri": f"{sso_origin}/api/lti/security/jwks",
        "token_endpoint": f"{normalized_origin}/login/oauth2/token",
    }


def _normalized_self_managed_canvas_origins() -> frozenset[str]:
    origins: set[str] = set()
    for configured in self_managed_canvas_origin_allowlist():
        try:
            parsed = urlparse(configured)
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                continue
            origins.add(normalize_canvas_https_origin(configured))
        except CanvasLtiServiceError:
            # Invalid operator entries never broaden trust.
            continue
    return frozenset(origins)


def resolve_canvas_lti_trust_profile(canvas_origin: str) -> str:
    """Select trust using only the operator's exact-origin allowlist."""

    normalized_origin = normalize_canvas_https_origin(canvas_origin)
    if normalized_origin in _normalized_self_managed_canvas_origins():
        return CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN
    return CANVAS_LTI_TRUST_HOSTED_GLOBAL


def canvas_lti_trust_profile(
    canvas_origin: str,
    trust_profile: str,
) -> dict[str, str]:
    """Derive the only accepted LTI endpoints for a persisted trust mode.

    Endpoint URLs are never accepted from a management caller. In particular,
    self-managed trust is available only for an exact operator-approved origin,
    and removing that approval makes all subsequent use fail closed.
    """

    normalized_origin = normalize_canvas_https_origin(canvas_origin)
    normalized_profile = str(trust_profile or "").strip()
    if normalized_profile == CANVAS_LTI_TRUST_HOSTED_GLOBAL:
        return hosted_canvas_lti_profile(normalized_origin)
    if normalized_profile != CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN:
        raise CanvasLtiServiceError("Canvas LTI trust profile is unsupported")
    if normalized_origin not in _normalized_self_managed_canvas_origins():
        raise CanvasLtiServiceError(
            "Self-managed Canvas LTI trust requires an exact "
            "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST entry"
        )
    return {
        "trust_profile": CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN,
        "environment": "self_managed",
        "issuer": normalized_origin,
        "authorization_endpoint": f"{normalized_origin}/api/lti/authorize_redirect",
        "jwks_uri": f"{normalized_origin}/api/lti/security/jwks",
        "token_endpoint": f"{normalized_origin}/login/oauth2/token",
    }


async def _read_limited_canvas_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    label: str,
    max_bytes: int = 1024 * 1024,
) -> dict[str, Any]:
    try:
        async with client.stream("GET", url, headers={"Accept": "application/json"}) as response:
            if response.is_redirect:
                raise CanvasLtiServiceError(f"Canvas {label} returned a redirect")
            response.raise_for_status()
            payload = await read_limited_canvas_json_response(
                response,
                label=label,
                max_bytes=max_bytes,
            )
    except CanvasLtiServiceError:
        raise
    except httpx.HTTPError as exc:
        raise CanvasLtiServiceError(f"Canvas {label} could not be fetched safely") from exc
    if not isinstance(payload, dict):
        raise CanvasLtiServiceError(f"Canvas {label} returned an unexpected document")
    return payload


async def read_limited_canvas_json_response(
    response: httpx.Response,
    *,
    label: str,
    max_bytes: int,
) -> Any:
    """Decode a Canvas JSON response without permitting an unbounded body read."""

    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    declared_size = response.headers.get("Content-Length")
    if declared_size:
        try:
            if int(declared_size) > max_bytes:
                raise CanvasLtiServiceError(
                    f"Canvas {label} exceeds the response size limit"
                )
        except ValueError:
            # A malformed Content-Length does not become trusted; the streamed
            # byte counter below remains authoritative.
            pass
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > max_bytes:
            raise CanvasLtiServiceError(
                f"Canvas {label} exceeds the response size limit"
            )
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanvasLtiServiceError(f"Canvas {label} was not valid JSON") from exc


async def probe_canvas_lti_platform(
    base_url: str,
    *,
    trust_profile: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Probe an unmodified Canvas instance using server-derived LTI trust.

    Hosted Canvas does not expose LTI platform metadata at the institution's
    generic ``/.well-known`` URL. Its LTI issuer, OIDC authorization endpoint,
    and launch JWKS are environment-specific and domain-independent, while the
    client-credentials token endpoint remains on the institution Canvas origin.
    """

    canvas_origin = validate_canvas_origin(base_url)
    selected_trust_profile = (
        str(trust_profile).strip()
        if trust_profile is not None
        else resolve_canvas_lti_trust_profile(canvas_origin)
    )
    profile = canvas_lti_trust_profile(canvas_origin, selected_trust_profile)
    environment = profile["environment"]
    issuer = profile["issuer"]
    authorization_endpoint = profile["authorization_endpoint"]
    jwks_uri = profile["jwks_uri"]
    token_endpoint = profile["token_endpoint"]
    async with canvas_http_client(timeout=timeout) as client:
        jwks = await _read_limited_canvas_json(client, jwks_uri, label="JWKS")
        if not isinstance(jwks.get("keys"), list) or not jwks["keys"]:
            raise CanvasLtiServiceError("Canvas JWKS does not include any keys")
    configuration = {
        "issuer": issuer,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "jwks_uri": jwks_uri,
        "canvas_environment": environment,
        "lti_trust_profile": profile["trust_profile"],
        "metadata_source": (
            "operator_allowlisted_self_managed_canvas_profile"
            if profile["trust_profile"] == CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN
            else "documented_hosted_canvas_profile"
        ),
    }
    return {
        "canvas_base_url": canvas_origin,
        "lti_trust_profile": profile["trust_profile"],
        "issuer": issuer,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "jwks_uri": jwks_uri,
        "registration_endpoint": None,
        "raw_openid_configuration": configuration,
        "jwks_json": jwks,
    }


def validate_lti_service_url(
    service_url: str,
    *,
    expected_origin: str | None = None,
) -> str:
    """Reject unsafe service URLs and optionally pin them to an exact origin.

    Hosted Canvas uses global LTI issuer/OIDC domains but may advertise AGS and
    NRPS services on an institution domain. A signed launch, not issuer-origin
    equality, establishes the first service URL. Pagination is then constrained
    to that first service origin.
    """

    value = str(service_url or "").strip()
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise CanvasLtiServiceError("Canvas LTI service URLs must use HTTPS")
    service_origin = validate_canvas_origin(value)
    if expected_origin is not None and service_origin != validate_canvas_origin(expected_origin):
        raise CanvasLtiServiceError("Canvas LTI service URL changed origin")
    return value


async def request_lti_access_token(
    *,
    client: httpx.AsyncClient,
    token_endpoint: str,
    client_id: str,
    client_assertion: str,
    scopes: list[str],
    platform_issuer: str,
) -> CanvasLtiAccessToken:
    endpoint = validate_lti_service_url(token_endpoint)
    try:
        async with client.stream(
            "POST",
            endpoint,
            data={
                "grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
                "client_id": client_id,
                "scope": " ".join(scopes),
            },
            headers={"Accept": "application/json"},
            follow_redirects=False,
        ) as response:
            if response.is_redirect:
                raise CanvasLtiServiceError("Canvas LTI token endpoint returned a redirect")
            if response.status_code == 429:
                raise CanvasLtiServiceError(
                    "Canvas LTI token request was rate limited",
                    retry_after_seconds=parse_canvas_retry_after(
                        response.headers.get("Retry-After")
                    )
                    or 0,
                )
            if response.status_code in {401, 403}:
                raise CanvasLtiServiceError(
                    "Canvas rejected the LTI service client assertion or requested scopes"
                )
            response.raise_for_status()
            payload = await read_limited_canvas_json_response(
                response,
                label="LTI token response",
                max_bytes=CANVAS_TOKEN_RESPONSE_MAX_BYTES,
            )
    except CanvasLtiServiceError:
        raise
    except httpx.HTTPError as exc:
        raise CanvasLtiServiceError("Canvas LTI token request transport failed") from exc
    token = payload.get("access_token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token.strip():
        raise CanvasLtiServiceError("Canvas LTI token response did not contain an access token")
    return CanvasLtiAccessToken(
        value=token.strip(),
        expires_in=payload.get("expires_in") if isinstance(payload.get("expires_in"), int) else None,
        scope=payload.get("scope") if isinstance(payload.get("scope"), str) else None,
    )


async def _get_lti_collection(
    *,
    client: httpx.AsyncClient,
    url: str,
    access_token: str,
    platform_issuer: str,
    accept: str,
    params: dict[str, str] | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    next_url = validate_lti_service_url(url)
    service_origin = validate_canvas_origin(next_url)
    headers = {"Authorization": f"Bearer {access_token}", "Accept": accept}
    items: list[dict[str, Any]] = []
    query = params
    visited_pages: set[str] = set()
    page_count = 0
    while next_url and len(items) < limit:
        request_url = str(httpx.URL(next_url).copy_merge_params(query or {}))
        if request_url in visited_pages:
            raise CanvasLtiServiceError(
                "Canvas LTI service pagination repeated a page",
                retryable=False,
            )
        visited_pages.add(request_url)
        page_count += 1
        if page_count > CANVAS_COLLECTION_MAX_PAGES:
            raise CanvasLtiServiceError(
                "Canvas LTI service pagination exceeded the page limit",
                retryable=False,
            )
        try:
            async with client.stream(
                "GET",
                next_url,
                headers=headers,
                params=query,
                follow_redirects=False,
            ) as response:
                if response.is_redirect:
                    raise CanvasLtiServiceError("Canvas LTI service returned a redirect")
                if response.status_code == 429:
                    raise CanvasLtiServiceError(
                        "Canvas LTI service read was rate limited",
                        retry_after_seconds=parse_canvas_retry_after(
                            response.headers.get("Retry-After")
                        )
                        or 0,
                    )
                if response.status_code in {401, 403}:
                    raise CanvasLtiServiceError(
                        "Canvas rejected the LTI service access token or scope"
                    )
                response.raise_for_status()
                payload = await read_limited_canvas_json_response(
                    response,
                    label="LTI service collection page",
                    max_bytes=CANVAS_COLLECTION_PAGE_MAX_BYTES,
                )
                candidate = (
                    response.links.get("next", {}).get("url")
                    if response.links
                    else None
                )
        except CanvasLtiServiceError:
            raise
        except httpx.HTTPError as exc:
            raise CanvasLtiServiceError("Canvas LTI service transport failed") from exc
        if isinstance(payload, list):
            page = payload
        elif isinstance(payload, dict) and isinstance(payload.get("members"), list):
            page = payload["members"]
        else:
            page = None
        if not isinstance(page, list):
            raise CanvasLtiServiceError("Canvas LTI service returned an unexpected collection")
        if any(not isinstance(item, dict) for item in page):
            raise CanvasLtiServiceError(
                "Canvas LTI service returned a malformed collection",
                retryable=False,
            )
        items.extend(page)
        if len(items) > limit or (candidate and len(items) >= limit):
            # A partial authoritative collection must not be interpreted as a
            # successful negative observation. Callers can choose a larger,
            # still-bounded limit for roster-sized collections.
            raise CanvasLtiServiceError(
                "Canvas LTI service collection exceeded the completeness limit",
                retryable=False,
            )
        next_url = (
            validate_lti_service_url(candidate, expected_origin=service_origin)
            if candidate and len(items) < limit
            else ""
        )
        query = None
    return items[:limit]


async def read_ags_results(
    *,
    client: httpx.AsyncClient,
    results_url: str,
    access_token: str,
    platform_issuer: str,
    user_id: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    params = {"user_id": user_id} if user_id else None
    return await _get_lti_collection(
        client=client,
        url=results_url,
        access_token=access_token,
        platform_issuer=platform_issuer,
        accept="application/vnd.ims.lis.v2.resultcontainer+json",
        params=params,
        limit=limit,
    )


async def read_nrps_memberships(
    *,
    client: httpx.AsyncClient,
    memberships_url: str,
    access_token: str,
    platform_issuer: str,
    limit: int = 500,
) -> list[dict[str, Any]]:
    return await _get_lti_collection(
        client=client,
        url=memberships_url,
        access_token=access_token,
        platform_issuer=platform_issuer,
        accept="application/vnd.ims.lti-nrps.v2.membershipcontainer+json",
        limit=limit,
    )
