"""Canvas OAuth helpers for organization-scoped REST API connections."""

from __future__ import annotations

import time
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlencode

import httpx
from issuance.application.canvas_lti_services import (
    CANVAS_TOKEN_RESPONSE_MAX_BYTES,
    CanvasLtiServiceError,
    parse_canvas_retry_after,
    read_limited_canvas_json_response,
    validate_canvas_origin,
)


class CanvasOAuthError(RuntimeError):
    def __init__(self, message: str, *, retry_after_seconds: int | None = None) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


# Canvas Developer Key scopes are deliberately selected through product
# capabilities.  Management clients must not be able to submit an arbitrary
# Canvas scope string and silently expand an organization's API access.
CANVAS_OAUTH_CAPABILITY_SCOPES: dict[str, tuple[str, ...]] = {
    "catalog": (
        "url:GET|/api/v1/courses",
        "url:GET|/api/v1/courses/:course_id/assignments",
        "url:GET|/api/v1/courses/:course_id/modules",
    ),
    "native_activity_scores": (
        "url:GET|/api/v1/courses/:course_id/assignments/:assignment_id/submissions/:user_id",
    ),
    "course_completion": (
        "url:GET|/api/v1/courses/:course_id/users/:user_id/progress",
    ),
    "module_completion": (
        "url:GET|/api/v1/courses/:course_id/modules/:id",
    ),
    "background_roster": (
        "url:GET|/api/v1/courses/:course_id/users",
        "url:GET|/api/v1/courses/:course_id/enrollments",
        "url:GET|/api/v1/courses/:course_id/bulk_user_progress",
    ),
}

_CANVAS_OAUTH_CAPABILITY_ALIASES = {
    "scope_catalog.read": "catalog",
    "assignment_submission.read": "native_activity_scores",
    "quiz_submission.read": "native_activity_scores",
    "course_progress.read": "course_completion",
    "module_progress.read": "module_completion",
}


def normalize_canvas_oauth_capabilities(capabilities: Iterable[str]) -> list[str]:
    requested = []
    for raw_capability in capabilities:
        capability = str(raw_capability or "").strip()
        capability = _CANVAS_OAUTH_CAPABILITY_ALIASES.get(capability, capability)
        if capability and capability not in requested:
            requested.append(capability)
    if not requested:
        raise CanvasOAuthError("At least one Canvas OAuth capability is required")
    unknown = sorted(set(requested) - set(CANVAS_OAUTH_CAPABILITY_SCOPES))
    if unknown:
        raise CanvasOAuthError("Unsupported Canvas OAuth capabilities: " + ", ".join(unknown))
    return requested


def canvas_oauth_scopes_for_capabilities(capabilities: Iterable[str]) -> list[str]:
    """Resolve named product capabilities to a deterministic least-privilege scope set."""

    requested = normalize_canvas_oauth_capabilities(capabilities)
    scopes: list[str] = []
    for capability in requested:
        for scope in CANVAS_OAUTH_CAPABILITY_SCOPES[capability]:
            if scope not in scopes:
                scopes.append(scope)
    return scopes


def canvas_oauth_authorization_url(
    *, canvas_base_url: str, client_id: str, redirect_uri: str, state: str, scopes: list[str]
) -> str:
    try:
        base = validate_canvas_origin(canvas_base_url)
    except CanvasLtiServiceError as exc:
        raise CanvasOAuthError(str(exc)) from exc
    return f"{base}/login/oauth2/auth?{urlencode({'client_id': client_id, 'response_type': 'code', 'redirect_uri': redirect_uri, 'state': state, 'scope': ' '.join(scopes)})}"


def _validate_canvas_endpoint(url: str, canvas_base_url: str) -> None:
    try:
        endpoint_origin = validate_canvas_origin(url)
        platform_origin = validate_canvas_origin(canvas_base_url)
    except CanvasLtiServiceError as exc:
        raise CanvasOAuthError(str(exc)) from exc
    if endpoint_origin != platform_origin:
        raise CanvasOAuthError("Canvas OAuth endpoint does not match the registered HTTPS platform origin")


async def exchange_canvas_oauth_code(
    *, client: httpx.AsyncClient, canvas_base_url: str, client_id: str, client_secret: str, code: str, redirect_uri: str
) -> dict[str, Any]:
    try:
        canvas_origin = validate_canvas_origin(canvas_base_url)
    except CanvasLtiServiceError as exc:
        raise CanvasOAuthError(str(exc)) from exc
    endpoint = f"{canvas_origin}/login/oauth2/token"
    _validate_canvas_endpoint(endpoint, canvas_origin)
    try:
        async with client.stream(
            "POST",
            endpoint,
            data={"grant_type": "authorization_code", "client_id": client_id, "client_secret": client_secret, "code": code, "redirect_uri": redirect_uri},
            headers={"Accept": "application/json"},
            follow_redirects=False,
        ) as response:
            if response.is_redirect:
                raise CanvasOAuthError("Canvas OAuth token endpoint returned a redirect")
            if response.status_code == 429:
                raise CanvasOAuthError(
                    "Canvas OAuth token exchange was rate limited",
                    retry_after_seconds=parse_canvas_retry_after(
                        response.headers.get("Retry-After")
                    )
                    or 0,
                )
            if response.status_code in {400, 401, 403}:
                raise CanvasOAuthError(
                    "Canvas rejected the OAuth authorization code or client credentials"
                )
            response.raise_for_status()
            payload = await read_limited_canvas_json_response(
                response,
                label="OAuth token response",
                max_bytes=CANVAS_TOKEN_RESPONSE_MAX_BYTES,
            )
    except CanvasOAuthError:
        raise
    except CanvasLtiServiceError as exc:
        raise CanvasOAuthError(
            "Canvas OAuth token endpoint could not be reached safely",
            retry_after_seconds=exc.retry_after_seconds,
        ) from exc
    except httpx.HTTPError as exc:
        raise CanvasOAuthError("Canvas OAuth token endpoint transport failed") from exc
    if not isinstance(payload, dict) or not payload.get("access_token"):
        raise CanvasOAuthError("Canvas OAuth response did not contain an access token")
    payload["obtained_at"] = int(time.time())
    return payload


async def refresh_canvas_oauth_token(
    *, client: httpx.AsyncClient, canvas_base_url: str, client_id: str, client_secret: str, refresh_token: str
) -> dict[str, Any]:
    try:
        canvas_origin = validate_canvas_origin(canvas_base_url)
    except CanvasLtiServiceError as exc:
        raise CanvasOAuthError(str(exc)) from exc
    endpoint = f"{canvas_origin}/login/oauth2/token"
    _validate_canvas_endpoint(endpoint, canvas_origin)
    try:
        async with client.stream(
            "POST",
            endpoint,
            data={"grant_type": "refresh_token", "client_id": client_id, "client_secret": client_secret, "refresh_token": refresh_token},
            headers={"Accept": "application/json"},
            follow_redirects=False,
        ) as response:
            if response.is_redirect:
                raise CanvasOAuthError("Canvas OAuth refresh endpoint returned a redirect")
            if response.status_code == 429:
                raise CanvasOAuthError(
                    "Canvas OAuth refresh was rate limited",
                    retry_after_seconds=parse_canvas_retry_after(
                        response.headers.get("Retry-After")
                    )
                    or 0,
                )
            if response.status_code in {400, 401, 403}:
                # The refresh coordinator uses the stable HTTP code marker to
                # distinguish a rejected/invalid grant from a transient outage
                # and fail the connection into reauthorization-required state.
                raise CanvasOAuthError(
                    f"Canvas OAuth refresh failed with HTTP {response.status_code}"
                )
            response.raise_for_status()
            payload = await read_limited_canvas_json_response(
                response,
                label="OAuth refresh response",
                max_bytes=CANVAS_TOKEN_RESPONSE_MAX_BYTES,
            )
    except CanvasOAuthError:
        raise
    except CanvasLtiServiceError as exc:
        raise CanvasOAuthError(
            "Canvas OAuth refresh endpoint could not be reached safely",
            retry_after_seconds=exc.retry_after_seconds,
        ) from exc
    except httpx.HTTPError as exc:
        raise CanvasOAuthError("Canvas OAuth refresh transport failed") from exc
    if not isinstance(payload, dict) or not payload.get("access_token"):
        raise CanvasOAuthError("Canvas OAuth refresh response did not contain an access token")
    payload.setdefault("refresh_token", refresh_token)
    payload["obtained_at"] = int(time.time())
    return payload


async def revoke_canvas_oauth_token(
    *,
    client: httpx.AsyncClient,
    canvas_base_url: str,
    access_token: str,
) -> None:
    try:
        canvas_origin = validate_canvas_origin(canvas_base_url)
    except CanvasLtiServiceError as exc:
        raise CanvasOAuthError(str(exc)) from exc
    endpoint = f"{canvas_origin}/login/oauth2/token"
    _validate_canvas_endpoint(endpoint, canvas_origin)
    try:
        async with client.stream(
            "DELETE",
            endpoint,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            follow_redirects=False,
        ) as response:
            if response.is_redirect:
                raise CanvasOAuthError("Canvas OAuth revocation endpoint returned a redirect")
            if response.status_code == 429:
                raise CanvasOAuthError(
                    "Canvas OAuth token revocation was rate limited",
                    retry_after_seconds=parse_canvas_retry_after(
                        response.headers.get("Retry-After")
                    )
                    or 0,
                )
            if response.status_code not in {200, 204, 404}:
                raise CanvasOAuthError(
                    f"Canvas OAuth token revocation failed with HTTP {response.status_code}"
                )
    except CanvasOAuthError:
        raise
    except CanvasLtiServiceError as exc:
        raise CanvasOAuthError(
            "Canvas OAuth revocation endpoint could not be reached safely",
            retry_after_seconds=exc.retry_after_seconds,
        ) from exc
    except httpx.HTTPError as exc:
        raise CanvasOAuthError("Canvas OAuth revocation transport failed") from exc
