"""Shared application approval and issuance orchestration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
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


def _delivery_mode_from_context(integration_context: dict[str, Any] | None) -> str:
    if not isinstance(integration_context, dict):
        return "wallet_only"
    delivery = integration_context.get("delivery")
    if not isinstance(delivery, dict):
        delivery = {}
    raw_mode = integration_context.get("delivery_mode") or delivery.get("mode")
    return str(raw_mode or "wallet_only")


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

    existing_tx: IssuanceTransaction | None = None
    if app.issuance_transaction_id:
        existing_tx = await repo.get_transaction(app.issuance_transaction_id)
    if existing_tx and existing_tx.status == IssuanceStatus.PENDING and not existing_tx.is_expired:
        tx = existing_tx
        tx.delivery_mode = _delivery_mode_from_context(app.integration_context)
        if issuer_context_applier is not None:
            await issuer_context_applier(tx)
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
        )
        if issuer_context_applier is not None:
            await issuer_context_applier(tx)
        await repo.save_transaction(tx)

    now = datetime.now(timezone.utc)
    app.status = ApplicationStatus.APPROVED
    app.review_notes = review_notes
    app.reviewer_id = reviewer_id
    app.reviewed_at = now
    app.issuance_transaction_id = tx.id
    app.updated_at = now
    await repo.save_application(app)
    return tx
