"""Helpers for recording canonical issuance delivery targets."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from issuance.domain.entities import (
    Application,
    CredentialDeliveryRecord,
    CredentialDeliveryStatus,
    DeliveryTarget,
    IssuanceTransaction,
    IssuedCredential,
)
from issuance.domain.ports import IIssuanceRepository
from issuance.application.canvas_runtime import normalize_canvas_feature_flags

logger = logging.getLogger(__name__)

_DELIVERY_MODES = {"wallet_only", "wallet_plus_canvas_mirror"}


def normalize_delivery_mode(value: str | None) -> str:
    mode = (value or "wallet_only").strip() or "wallet_only"
    if mode not in _DELIVERY_MODES:
        raise ValueError(
            f"Invalid delivery_mode '{mode}'. Must be one of {sorted(_DELIVERY_MODES)}"
        )
    return mode


def delivery_mode_from_integration_context(integration_context: dict[str, Any] | None) -> str:
    if not isinstance(integration_context, dict):
        return "wallet_only"
    delivery = integration_context.get("delivery")
    delivery = delivery if isinstance(delivery, dict) else {}
    raw_mode = integration_context.get("delivery_mode") or delivery.get("mode")
    try:
        return normalize_delivery_mode(raw_mode)
    except ValueError:
        return "wallet_only"


def canvas_program_binding_id_from_integration_context(integration_context: dict[str, Any] | None) -> str | None:
    if not isinstance(integration_context, dict):
        return None
    canvas = integration_context.get("canvas")
    canvas = canvas if isinstance(canvas, dict) else {}
    for candidate in (
        canvas.get("canvas_program_binding_id"),
        integration_context.get("canvas_program_binding_id"),
    ):
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def canvas_context_from_integration_context(integration_context: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(integration_context, dict):
        return {}
    canvas = integration_context.get("canvas")
    return canvas if isinstance(canvas, dict) else {}


def canvas_deployment_profile_delivery_metadata(app: Application | None) -> dict[str, Any]:
    """Return the Canvas deployment-profile snapshot to copy into delivery records."""

    canvas = canvas_context_from_integration_context(getattr(app, "integration_context", None))
    feature_flags = normalize_canvas_feature_flags(canvas.get("feature_flags"))
    metadata: dict[str, Any] = {}
    for source_key, target_key in (
        ("canvas_platform_id", "canvas_platform_id"),
        ("canvas_program_binding_id", "canvas_program_binding_id"),
        ("deployment_profile_id", "deployment_profile_id"),
        ("delivery_mode", "canvas_binding_delivery_mode"),
    ):
        value = canvas.get(source_key)
        if value:
            metadata[target_key] = str(value)
    if feature_flags:
        metadata["canvas_feature_flags"] = feature_flags
    return metadata


def canvas_delivery_feature_enabled(metadata: dict[str, Any] | None, flag: str) -> bool:
    flags = normalize_canvas_feature_flags((metadata or {}).get("canvas_feature_flags"))
    if not flags:
        return True
    return bool(flags.get(flag, False))


def build_delivery_record_id(
    credential_id: str,
    delivery_target: DeliveryTarget,
    scope_id: str | None = None,
) -> str:
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"{credential_id}:{delivery_target.value}:{scope_id or '-'}",
        )
    )


async def record_post_issuance_deliveries(
    repo: IIssuanceRepository,
    tx: IssuanceTransaction,
    credential: IssuedCredential,
    *,
    delivered_target: DeliveryTarget,
    delivery_metadata: dict[str, Any] | None = None,
) -> list[CredentialDeliveryRecord]:
    """Persist canonical delivery records for issued credentials.

    The canonical issuance always records the actual delivery channel that just
    succeeded (wallet or DIDComm). When Canvas mirroring is requested, this
    function also creates a pending or failed Canvas delivery record that a
    future publisher can process.
    """

    now = datetime.now(timezone.utc)
    saved_records: list[CredentialDeliveryRecord] = []

    delivered_record = CredentialDeliveryRecord(
        id=build_delivery_record_id(credential.id, delivered_target),
        credential_id=credential.id,
        transaction_id=tx.id,
        organization_id=credential.organization_id,
        delivery_target=delivered_target,
        delivery_mode=tx.delivery_mode or "wallet_only",
        status=CredentialDeliveryStatus.DELIVERED,
        metadata=delivery_metadata or {},
        created_at=now,
        updated_at=now,
    )
    await repo.save_delivery_record(delivered_record)
    saved_records.append(delivered_record)

    if not tx.should_mirror_to_canvas:
        return saved_records

    app: Application | None = None
    if tx.application_id:
        app = await repo.get_application(tx.application_id)

    canvas_profile_metadata = canvas_deployment_profile_delivery_metadata(app)
    canvas_program_binding_id = None
    if app is not None:
        canvas_program_binding_id = canvas_program_binding_id_from_integration_context(app.integration_context)

    canvas_account_id: str | None = None
    canvas_error: str | None = None
    mirror_target_enabled = False
    publish_gate_enabled = canvas_delivery_feature_enabled(canvas_profile_metadata, "enable_canvas_mirror_publish")
    if not publish_gate_enabled:
        canvas_error = "Canvas mirror publish is disabled by deployment profile"
    elif canvas_program_binding_id:
        binding = await repo.get_canvas_program_binding(canvas_program_binding_id)
        if binding is None:
            canvas_error = f"Canvas program binding {canvas_program_binding_id} was not found"
        elif not binding.enabled:
            canvas_error = f"Canvas program binding {canvas_program_binding_id} is disabled"
        else:
            platform = await repo.get_canvas_platform(binding.platform_id)
            if platform is None:
                canvas_error = f"Canvas platform {binding.platform_id} was not found"
            elif not platform.enabled:
                canvas_account_id = platform.canvas_account_id
                canvas_error = f"Canvas platform {binding.platform_id} is disabled"
            else:
                mirror_target_enabled = True
                canvas_account_id = platform.canvas_account_id
                canvas_profile_metadata = {
                    **canvas_profile_metadata,
                    "canvas_platform_id": platform.id,
                    "canvas_program_binding_id": binding.id,
                }
                if binding.canvas_credentials:
                    canvas_profile_metadata["canvas_credentials"] = dict(binding.canvas_credentials)
    else:
        canvas_error = "Canvas mirroring requested but no canvas_program_binding_id was provided"

    canvas_metadata = {
        "application_id": tx.application_id,
        "source_delivery_target": delivered_target.value,
        "queue": "canvas_credentials_mirror",
        "delivery_destination_id": "dd-canvas-credentials-institutional",
        "delivery_destination_mode": "organization_mirror",
        "delivery_destination_provider": "canvas_credentials",
        **canvas_profile_metadata,
    }
    if not publish_gate_enabled:
        canvas_metadata.update(
            {
                "canvas_feature_gate_blocked": True,
                "canvas_feature_gate": "enable_canvas_mirror_publish",
                "retryable": False,
            }
        )
    canvas_record = CredentialDeliveryRecord(
        id=build_delivery_record_id(
            credential.id,
            DeliveryTarget.CANVAS_CREDENTIALS,
            canvas_program_binding_id,
        ),
        credential_id=credential.id,
        transaction_id=tx.id,
        organization_id=credential.organization_id,
        delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
        delivery_mode=tx.delivery_mode or "wallet_only",
        status=(
            CredentialDeliveryStatus.PENDING
            if mirror_target_enabled
            else CredentialDeliveryStatus.FAILED
        ),
        canvas_account_id=canvas_account_id,
        last_error=canvas_error,
        metadata=canvas_metadata,
        created_at=now,
        updated_at=now,
    )
    await repo.save_delivery_record(canvas_record)
    saved_records.append(canvas_record)

    if canvas_error:
        logger.warning(
            "Canvas mirror record for credential=%s queued as failed: %s",
            credential.id,
            canvas_error,
        )

    return saved_records
