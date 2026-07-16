"""Persisted, replay-safe Canvas OAuth authorization transactions."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from issuance.application.canvas_lti_services import (
    CanvasLtiServiceError,
    normalize_canvas_https_origin,
)
from issuance.domain.entities import (
    CanvasOAuthAuthorization,
    CanvasOAuthConnectionStatus,
)
from issuance.domain.ports import IIssuanceRepository


def hash_canvas_oauth_state(raw_state: str) -> str:
    """Hash a high-entropy OAuth state before database lookup or persistence."""

    if not raw_state or len(raw_state) < 32:
        raise ValueError("Canvas OAuth state is invalid")
    return hashlib.sha256(raw_state.encode("utf-8")).hexdigest()


async def create_canvas_oauth_authorization_transaction(
    *,
    repo: IIssuanceRepository,
    organization_id: str,
    platform_id: str,
    canvas_base_url: str,
    platform_config_version: int,
    client_id: str,
    client_secret_ref: str,
    capabilities: list[str],
    scopes: list[str],
    redirect_uri: str,
    ttl_seconds: int = 600,
) -> tuple[str, CanvasOAuthAuthorization]:
    """Persist one-time state plus immutable client identity and secret reference."""

    if not organization_id or not platform_id:
        raise ValueError("organization_id and platform_id are required")
    if not canvas_base_url or not client_id or not client_secret_ref:
        raise ValueError("Canvas OAuth client_id and client_secret_ref are required")
    try:
        normalized_canvas_base_url = normalize_canvas_https_origin(canvas_base_url)
    except CanvasLtiServiceError as exc:
        raise ValueError("Canvas OAuth canvas_base_url must be a valid HTTPS origin") from exc
    if platform_config_version < 1:
        raise ValueError("Canvas platform_config_version is invalid")
    if not capabilities or not scopes:
        raise ValueError("Canvas OAuth capabilities and derived scopes are required")
    if not str(redirect_uri or "").startswith("https://"):
        raise ValueError("Canvas OAuth redirect_uri must use HTTPS")
    raw_state = secrets.token_urlsafe(48)
    authorization = CanvasOAuthAuthorization(
        organization_id=organization_id,
        platform_id=platform_id,
        canvas_base_url=normalized_canvas_base_url,
        platform_config_version=platform_config_version,
        client_id=client_id,
        client_secret_ref=client_secret_ref,
        state_hash=hash_canvas_oauth_state(raw_state),
        capabilities=list(dict.fromkeys(capabilities)),
        scopes=list(dict.fromkeys(scopes)),
        redirect_uri=redirect_uri,
        expires_at=datetime.now(timezone.utc)
        + timedelta(seconds=max(60, min(int(ttl_seconds), 900))),
    )
    await repo.save_canvas_oauth_authorization(authorization)
    return raw_state, authorization


async def consume_canvas_oauth_authorization_transaction(
    *,
    repo: IIssuanceRepository,
    raw_state: str,
) -> CanvasOAuthAuthorization | None:
    """Atomically consume the authorization represented by a raw state."""

    return await repo.consume_canvas_oauth_authorization(hash_canvas_oauth_state(raw_state))


async def queue_canvas_oauth_revocation(
    *,
    repo: IIssuanceRepository,
    organization_id: str,
    platform_id: str,
    reason_code: str,
) -> bool:
    """CAS-transition a live grant into the worker's durable revocation queue."""

    connection = await repo.get_canvas_oauth_connection(organization_id, platform_id)
    if connection is None:
        return True
    if connection.status == CanvasOAuthConnectionStatus.REVOCATION_PENDING:
        return True
    lease_owner = f"oauth-revoke-queue:{uuid.uuid4()}"
    leased = await repo.begin_canvas_oauth_revocation(
        organization_id=organization_id,
        platform_id=platform_id,
        expected_updated_at=connection.updated_at,
        lease_owner=lease_owner,
        lease_seconds=60,
    )
    if leased is None:
        current = await repo.get_canvas_oauth_connection(organization_id, platform_id)
        return bool(
            current is None
            or current.status == CanvasOAuthConnectionStatus.REVOCATION_PENDING
        )
    return await repo.reschedule_canvas_oauth_revocation(
        organization_id=organization_id,
        platform_id=platform_id,
        lease_owner=lease_owner,
        retry_at=datetime.now(timezone.utc),
        error_code=str(reason_code or "canvas_oauth_revocation_requested")[:120],
    )
