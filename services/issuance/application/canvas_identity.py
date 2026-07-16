"""Verified Canvas learner identity joins for portable LTI/REST evidence."""

from __future__ import annotations

from datetime import datetime, timezone

from issuance.domain.entities import CanvasLearnerIdentity, CanvasLearnerIdentityStatus
from issuance.domain.ports import IIssuanceRepository


async def record_verified_canvas_lti_subject(
    *,
    repo: IIssuanceRepository,
    organization_id: str,
    platform_id: str,
    deployment_id: str,
    lti_subject: str,
) -> CanvasLearnerIdentity:
    """Persist the opaque subject namespace before a numeric Canvas join exists."""

    values = {
        "organization_id": str(organization_id or "").strip(),
        "platform_id": str(platform_id or "").strip(),
        "deployment_id": str(deployment_id or "").strip(),
        "lti_subject": str(lti_subject or "").strip(),
    }
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise ValueError(f"Missing verified Canvas subject fields: {', '.join(missing)}")

    now = datetime.now(timezone.utc)
    identity = await repo.get_canvas_learner_identity_by_subject(**values)
    if identity is None:
        identity = CanvasLearnerIdentity(
            **values,
            status=CanvasLearnerIdentityStatus.SUBJECT_VERIFIED,
        )
    identity.verified_at = now
    identity.updated_at = now
    await repo.save_canvas_learner_identity(identity)
    return identity


async def link_verified_canvas_learner_identity(
    *,
    repo: IIssuanceRepository,
    organization_id: str,
    platform_id: str,
    deployment_id: str,
    lti_subject: str,
    canvas_user_id: str,
    sis_user_id: str | None = None,
) -> CanvasLearnerIdentity:
    """Join IDs asserted by a verified LTI launch, quarantining conflicts.

    Email is deliberately absent from this interface. Callers may pass a SIS ID
    only when the institution explicitly enabled exact SIS identifier joins.
    """

    values = {
        "organization_id": str(organization_id or "").strip(),
        "platform_id": str(platform_id or "").strip(),
        "deployment_id": str(deployment_id or "").strip(),
        "lti_subject": str(lti_subject or "").strip(),
        "canvas_user_id": str(canvas_user_id or "").strip(),
    }
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise ValueError(f"Missing verified Canvas identity fields: {', '.join(missing)}")

    existing_subject = await repo.get_canvas_learner_identity_by_subject(
        organization_id=values["organization_id"],
        platform_id=values["platform_id"],
        deployment_id=values["deployment_id"],
        lti_subject=values["lti_subject"],
    )
    existing_numeric = await repo.get_canvas_learner_identity_by_canvas_user(
        organization_id=values["organization_id"],
        platform_id=values["platform_id"],
        deployment_id=values["deployment_id"],
        canvas_user_id=values["canvas_user_id"],
    )
    now = datetime.now(timezone.utc)

    conflict = False
    reasons: list[str] = []
    if existing_subject is not None and existing_subject.canvas_user_id not in {
        None,
        values["canvas_user_id"],
    }:
        conflict = True
        reasons.append("LTI subject was previously linked to another Canvas user")
    if existing_numeric is not None and existing_numeric.lti_subject != values["lti_subject"]:
        conflict = True
        reasons.append("Canvas user was previously linked to another LTI subject")

    identity = existing_subject or CanvasLearnerIdentity(
        organization_id=values["organization_id"],
        platform_id=values["platform_id"],
        deployment_id=values["deployment_id"],
        lti_subject=values["lti_subject"],
    )
    identity.canvas_user_id = values["canvas_user_id"]
    identity.sis_user_id = str(sis_user_id).strip() if sis_user_id else None
    identity.verified_at = now
    identity.updated_at = now
    if conflict:
        identity.status = CanvasLearnerIdentityStatus.QUARANTINED
        identity.conflict_reason = "; ".join(reasons)
        if existing_numeric is not None and existing_numeric.id != identity.id:
            existing_numeric.status = CanvasLearnerIdentityStatus.QUARANTINED
            existing_numeric.conflict_reason = identity.conflict_reason
            existing_numeric.updated_at = now
            await repo.save_canvas_learner_identity(existing_numeric)
    else:
        identity.status = CanvasLearnerIdentityStatus.LINKED
        identity.conflict_reason = None
    await repo.save_canvas_learner_identity(identity)
    return identity
