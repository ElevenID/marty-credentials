"""Shared application approval and issuance orchestration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    IssuanceStatus,
    IssuanceTransaction,
)
from issuance.domain.ports import IIssuanceRepository

IssuerContextApplier = Callable[[IssuanceTransaction], Awaitable[None]]


@dataclass(frozen=True)
class CredentialContext:
    credential_type: str = "org.iso.18013.5.1.mDL"
    credential_vct: str | None = None
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt"
    revocation_profile_id: str | None = None
    wallet_configs: tuple[dict[str, Any], ...] = ()
    selective_disclosure_claims: tuple[str, ...] = ()
    zk_predicate_claims: tuple[str, ...] = ()
    validity_days: int = 365
    renewable: bool = False
    renewal_window_days: int = 30
    issuer_profile_id: str | None = None
    issuer_mode: str = "org_managed"
    issuer_algorithm: str | None = None
    issuer_key_id: str | None = None


def credential_context_from_template_snapshot(snapshot: dict[str, Any]) -> CredentialContext:
    """Build issuance settings from the exact validated credential-template snapshot.

    Canvas approval uses this instead of the historical mDL fallbacks.  The
    snapshot is captured during binding validation so a later template change
    invalidates readiness rather than silently changing an in-flight award.
    """

    if not isinstance(snapshot, dict) or not snapshot:
        raise ValueError("Credential template snapshot is required")
    remote_signing_config = (
        snapshot.get("remote_signing_config")
        if isinstance(snapshot.get("remote_signing_config"), dict)
        else {}
    )
    credential_type = str(snapshot.get("credential_type") or "").strip()
    payload_format = str(snapshot.get("credential_payload_format") or "").strip()
    revocation_profile_id = str(snapshot.get("revocation_profile_id") or "").strip()
    issuer_profile_id = str(snapshot.get("issuer_profile_id") or "").strip()
    issuer_algorithm = str(
        snapshot.get("issuer_algorithm")
        or snapshot.get("signing_algorithm")
        or remote_signing_config.get("algorithm")
        or ""
    ).strip()
    issuer_key_id = str(
        snapshot.get("issuer_key_id")
        or remote_signing_config.get("signing_key_reference")
        or ""
    ).strip()
    if not credential_type:
        raise ValueError("Credential template snapshot is missing credential_type")
    normalized_credential_type = "".join(
        character for character in credential_type.lower() if character.isalnum()
    )
    if normalized_credential_type not in {
        "openbadge",
        "openbadgev2",
        "openbadgev3",
        "openbadgecredential",
    }:
        raise ValueError("Canvas issuance requires an Open Badge credential template")
    if not payload_format:
        raise ValueError("Credential template snapshot is missing credential_payload_format")
    if not revocation_profile_id:
        raise ValueError("Credential template snapshot is missing revocation_profile_id")
    if not issuer_profile_id:
        raise ValueError("Credential template snapshot is missing issuer_profile_id")
    if str(snapshot.get("key_access_mode") or "").strip().upper() != "REMOTE_SIGNING":
        raise ValueError("Credential template snapshot must use REMOTE_SIGNING")
    if not issuer_algorithm:
        raise ValueError("Credential template snapshot is missing issuer_algorithm")
    if issuer_algorithm not in {"ES256", "ES384", "RS256", "EdDSA"}:
        raise ValueError("Credential template snapshot uses an unsupported issuer_algorithm")
    if not issuer_key_id:
        raise ValueError("Credential template snapshot is missing issuer_key_id")

    validity = snapshot.get("validity_rules") if isinstance(snapshot.get("validity_rules"), dict) else {}
    validity_days = int(validity.get("default_validity_days") or 365)
    renewal_window_days = int(validity.get("renewal_window_days") or 30)
    return CredentialContext(
        credential_type=credential_type,
        credential_vct=str(snapshot.get("vct") or "").strip() or None,
        credential_payload_format=payload_format,
        revocation_profile_id=revocation_profile_id,
        wallet_configs=tuple(
            dict(item) for item in (snapshot.get("wallet_configs") or []) if isinstance(item, dict)
        ),
        selective_disclosure_claims=tuple(
            str(item) for item in (snapshot.get("selective_disclosure_fields") or []) if str(item)
        ),
        zk_predicate_claims=tuple(
            str(item) for item in (snapshot.get("zk_predicate_claims") or []) if str(item)
        ),
        validity_days=max(1, validity_days),
        renewable=bool(validity.get("renewable", False)),
        renewal_window_days=max(1, renewal_window_days),
        issuer_profile_id=issuer_profile_id,
        issuer_mode=str(snapshot.get("issuer_mode") or "org_managed"),
        issuer_algorithm=issuer_algorithm,
        issuer_key_id=issuer_key_id,
    )


def _delivery_mode_from_context(integration_context: dict[str, Any] | None) -> str:
    if not isinstance(integration_context, dict):
        return "wallet_only"
    delivery = integration_context.get("delivery")
    if not isinstance(delivery, dict):
        delivery = {}
    raw_mode = integration_context.get("delivery_mode") or delivery.get("mode")
    return str(raw_mode or "wallet_only")


def _is_canvas_bound_application(app: Application) -> bool:
    integration_context = app.integration_context if isinstance(app.integration_context, dict) else {}
    canvas = integration_context.get("canvas")
    if not isinstance(canvas, dict):
        return False
    source = str(canvas.get("source") or "").strip().lower()
    return bool(
        str(canvas.get("canvas_platform_id") or "").strip()
        or str(canvas.get("canvas_program_binding_id") or "").strip()
        or str(canvas.get("canvas_account_id") or "").strip()
        or source.startswith("canvas")
    )


async def approve_application_for_issuance(
    *,
    repo: IIssuanceRepository,
    app: Application,
    template: ApplicationTemplate,
    reviewer_id: str,
    review_notes: str,
    credential_context: CredentialContext | None = None,
    issuer_context_applier: IssuerContextApplier | None = None,
) -> IssuanceTransaction:
    """Approve an application and create or refresh its issuance transaction."""

    if not template.credential_template_id:
        raise ValueError("Application template missing credential template ID")
    if app.status not in (ApplicationStatus.PENDING, ApplicationStatus.APPROVED):
        raise ValueError(f"Cannot approve application in {app.status} status")

    canvas_application = _is_canvas_bound_application(app)
    existing_tx: IssuanceTransaction | None = None
    if app.issuance_transaction_id:
        existing_tx = await repo.get_transaction(app.issuance_transaction_id)
    if existing_tx and existing_tx.status == IssuanceStatus.PENDING and not existing_tx.is_expired:
        tx = existing_tx
        tx.delivery_mode = _delivery_mode_from_context(app.integration_context)
        if credential_context is not None:
            tx.credential_type = credential_context.credential_type
            tx.credential_payload_format = credential_context.credential_payload_format
            tx.revocation_profile_id = credential_context.revocation_profile_id
            tx.wallet_configs = [dict(item) for item in credential_context.wallet_configs]
            tx.selective_disclosure_claims = list(credential_context.selective_disclosure_claims)
            tx.zk_predicate_claims = list(credential_context.zk_predicate_claims)
            tx.validity_days = credential_context.validity_days
            tx.renewable = credential_context.renewable
            tx.renewal_window_days = credential_context.renewal_window_days
            tx.issuer_profile_id = credential_context.issuer_profile_id
            tx.issuer_mode = credential_context.issuer_mode
            if credential_context.credential_vct:
                tx.claims = {**tx.claims, "_vct": credential_context.credential_vct}
        if issuer_context_applier is not None:
            await issuer_context_applier(tx)
        if not canvas_application:
            await repo.save_transaction(tx)
    else:
        merged_claims = {**app.form_data}
        default_credential_type = str(
            merged_claims.pop("_credential_type", "")
            or (app.integration_context or {}).get("credential_type")
            or "org.iso.18013.5.1.mDL"
        )
        default_credential_vct = (
            str(
                merged_claims.get("_vct")
                or (app.integration_context or {}).get("credential_vct")
                or ""
            )
            or None
        )
        context = credential_context or CredentialContext(
            credential_type=default_credential_type,
            credential_vct=default_credential_vct,
        )
        if context.credential_vct:
            merged_claims["_vct"] = context.credential_vct
        tx = IssuanceTransaction(
            organization_id=app.organization_id,
            credential_template_id=template.credential_template_id,
            applicant_id=app.applicant_identifier,
            application_id=app.id,
            subject_did=None,
            delivery_mode=_delivery_mode_from_context(app.integration_context),
            claims=merged_claims,
            credential_type=context.credential_type,
            credential_payload_format=context.credential_payload_format,
            revocation_profile_id=context.revocation_profile_id,
            wallet_configs=[dict(item) for item in context.wallet_configs],
            selective_disclosure_claims=list(context.selective_disclosure_claims),
            zk_predicate_claims=list(context.zk_predicate_claims),
            validity_days=context.validity_days,
            renewable=context.renewable,
            renewal_window_days=context.renewal_window_days,
            issuer_profile_id=context.issuer_profile_id,
            issuer_mode=context.issuer_mode,
        )
        if issuer_context_applier is not None:
            await issuer_context_applier(tx)
        if not canvas_application:
            await repo.save_transaction(tx)

    now = datetime.now(UTC)
    if canvas_application:
        prepared_transaction_id = tx.id
        canonical_app, tx, already_issued = await repo.reserve_canvas_application_issuance(
            tx,
            reviewer_id=reviewer_id,
            review_notes=review_notes,
            reviewed_at=now,
        )
        app.status = canonical_app.status
        app.review_notes = canonical_app.review_notes
        app.reviewer_id = canonical_app.reviewer_id
        app.reviewed_at = canonical_app.reviewed_at
        app.issuance_transaction_id = canonical_app.issuance_transaction_id
        app.credential_id = canonical_app.credential_id
        app.updated_at = canonical_app.updated_at
        if already_issued:
            raise ValueError("Canvas application already has an issued credential")
        if (
            tx.id != prepared_transaction_id
            and tx.status in {IssuanceStatus.AUTHORIZED, IssuanceStatus.SIGNING}
        ):
            raise ValueError("Canvas credential claim is already in progress")
        return tx

    app.status = ApplicationStatus.APPROVED
    app.review_notes = review_notes
    app.reviewer_id = reviewer_id
    app.reviewed_at = now
    app.issuance_transaction_id = tx.id
    app.updated_at = now
    await repo.save_application(app)
    return tx
