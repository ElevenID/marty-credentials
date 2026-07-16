"""Fail-closed authorization for Canvas-bound wallet credential claims.

Canvas evidence can change after an offer is created.  Approval therefore is
not sufficient authorization to sign: the credential endpoint must bind the
transaction back to the active, currently validated Canvas configuration and
re-evaluate the current authoritative evidence heads immediately before
signing.

The helper deliberately returns ``False`` for applications that have no Canvas
integration marker.  Ordinary OID4VCI issuance retains its existing behavior.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from issuance.application.application_approval import (
    CredentialContext,
    credential_context_from_template_snapshot,
)
from issuance.application.canvas_feature_flags import (
    portable_canvas_enabled_for_organization,
)
from issuance.application.canvas_readiness import (
    canvas_binding_is_ready_for_activation,
)
from issuance.application.evidence_policy import (
    evaluate_application_evidence_policy,
)
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    CanvasEvidenceRequirement,
    EvidenceFact,
    IssuanceTransaction,
)
from issuance.domain.ports import IIssuanceRepository

DEFAULT_CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS = 15 * 60
CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_ENV = (
    "CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS"
)


class CanvasIssuanceGuardError(RuntimeError):
    """Internal denial carrying a stable, non-sensitive audit code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _deny(code: str) -> None:
    raise CanvasIssuanceGuardError(code)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _canvas_context(app: Application) -> dict[str, Any] | None:
    integration_context = (
        app.integration_context if isinstance(app.integration_context, dict) else {}
    )
    value = integration_context.get("canvas")
    if not isinstance(value, dict):
        return None
    source = _text(value.get("source")).lower()
    has_canvas_marker = bool(
        _text(value.get("canvas_platform_id"))
        or _text(value.get("canvas_program_binding_id"))
        or _text(value.get("canvas_account_id"))
        or source.startswith("canvas")
    )
    return dict(value) if has_canvas_marker else None


def _evidence_max_age_seconds(value: int | None) -> int:
    if value is None:
        raw = os.environ.get(
            CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_ENV,
            str(DEFAULT_CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS),
        )
        try:
            value = int(raw)
        except (TypeError, ValueError):
            _deny("evidence_freshness_configuration_invalid")
    if isinstance(value, bool) or value <= 0:
        _deny("evidence_freshness_configuration_invalid")
    return value


def canvas_evidence_observation_is_fresh(
    observed_at: datetime,
    *,
    now: datetime | None = None,
    max_age_seconds: int | None = None,
) -> bool:
    """Apply the issuance freshness policy to an authoritative observation."""

    if not isinstance(observed_at, datetime):
        return False
    evaluated_at = _utc(now or datetime.now(UTC))
    observed = _utc(observed_at)
    age_seconds = (evaluated_at - observed).total_seconds()
    return 0 <= age_seconds <= _evidence_max_age_seconds(max_age_seconds)


def _template_id(snapshot: Mapping[str, Any]) -> str:
    return _text(
        snapshot.get("id")
        or snapshot.get("credential_template_id")
        or snapshot.get("template_id")
    )


def _credential_context_from_current_snapshot(
    binding: Any,
    *,
    organization_id: str,
) -> CredentialContext:
    snapshot = (
        binding.credential_template_snapshot
        if isinstance(binding.credential_template_snapshot, dict)
        else {}
    )
    if (
        _template_id(snapshot) != binding.credential_template_id
        or _text(snapshot.get("organization_id")) != organization_id
        or _text(snapshot.get("status")).lower() != "active"
    ):
        _deny("canvas_credential_template_snapshot_mismatch")
    try:
        context = credential_context_from_template_snapshot(dict(snapshot))
    except (TypeError, ValueError):
        _deny("canvas_credential_template_snapshot_invalid")
    signing = (
        snapshot.get("remote_signing_config")
        if isinstance(snapshot.get("remote_signing_config"), dict)
        else {}
    )
    issuer_did = _text(snapshot.get("issuer_did"))
    verification_method_id = _text(signing.get("verification_method_id"))
    if (
        not issuer_did.startswith("did:")
        or not _text(signing.get("signing_service_id"))
        or not _text(signing.get("signing_key_reference"))
        or not verification_method_id.startswith(issuer_did + "#")
        or _text(signing.get("key_purpose") or "vc_jwt_issuer")
        != "vc_jwt_issuer"
    ):
        _deny("canvas_credential_template_snapshot_invalid")
    return context


def _canvas_resources_active(platform: Any, binding: Any) -> bool:
    return bool(
        platform.enabled
        and platform.archived_at is None
        and _text(platform.registration_status).lower() in {"installed", "verified"}
        and binding.enabled
        and binding.archived_at is None
        and binding.activated_at is not None
    )


async def canvas_approval_credential_context(
    *,
    repo: IIssuanceRepository,
    app: Application,
    template: Any,
) -> CredentialContext | None:
    """Resolve the current Canvas snapshot for manual approval.

    A non-Canvas application returns ``None`` so its existing approval behavior
    is unchanged.  A Canvas-marked application either receives the exact
    persisted credential context or fails closed.
    """

    canvas = _canvas_context(app)
    if canvas is None:
        return None
    if not portable_canvas_enabled_for_organization(app.organization_id):
        _deny("canvas_rollout_disabled")
    platform_id = _text(canvas.get("canvas_platform_id"))
    binding_id = _text(canvas.get("canvas_program_binding_id"))
    if not platform_id or not binding_id or not app.organization_id:
        _deny("canvas_transaction_context_incomplete")
    platform = await repo.get_canvas_platform_for_org(app.organization_id, platform_id)
    binding = await repo.get_canvas_program_binding_for_org(
        app.organization_id,
        binding_id,
    )
    if platform is None or binding is None:
        _deny("canvas_resource_ownership_mismatch")
    if not _canvas_resources_active(platform, binding):
        _deny("canvas_resources_inactive")
    if not canvas_binding_is_ready_for_activation(binding):
        _deny("canvas_readiness_not_current")
    if (
        template is None
        or template.id != app.application_template_id
        or template.id != binding.application_template_id
        or template.organization_id != app.organization_id
        or _text(getattr(template, "status", "")).lower() != "active"
        or template.credential_template_id != binding.credential_template_id
        or binding.platform_id != platform.id
        or _text(canvas.get("canvas_platform_id")) != platform.id
        or _text(canvas.get("canvas_program_binding_id")) != binding.id
        or _text(canvas.get("canvas_account_id")) != platform.canvas_account_id
        or _text(canvas.get("application_template_id")) != binding.application_template_id
        or _text(canvas.get("credential_template_id")) != binding.credential_template_id
        or not _text(canvas.get("lti_subject"))
    ):
        _deny("canvas_transaction_context_mismatch")
    return _credential_context_from_current_snapshot(
        binding,
        organization_id=app.organization_id,
    )


def _binding_and_transaction_context_match(
    *,
    app: Application,
    canvas: Mapping[str, Any],
    binding: Any,
    platform: Any,
    template: Any,
    tx: IssuanceTransaction,
) -> bool:
    if (
        app.organization_id != tx.organization_id
        or app.status != ApplicationStatus.APPROVED
        or app.issuance_transaction_id != tx.id
        or app.application_template_id != binding.application_template_id
        or template.id != binding.application_template_id
        or template.organization_id != tx.organization_id
        or _text(getattr(template, "status", "")).lower() != "active"
        or template.credential_template_id != binding.credential_template_id
        or tx.credential_template_id != binding.credential_template_id
        or binding.platform_id != platform.id
        or _text(canvas.get("canvas_platform_id")) != platform.id
        or _text(canvas.get("canvas_program_binding_id")) != binding.id
        or _text(canvas.get("canvas_account_id")) != platform.canvas_account_id
        or _text(canvas.get("application_template_id")) != binding.application_template_id
        or _text(canvas.get("credential_template_id")) != binding.credential_template_id
        or not _text(canvas.get("lti_subject"))
    ):
        return False

    try:
        expected = _credential_context_from_current_snapshot(
            binding,
            organization_id=tx.organization_id,
        )
    except CanvasIssuanceGuardError:
        return False

    snapshot = binding.credential_template_snapshot

    if (
        tx.credential_type != expected.credential_type
        or tx.credential_payload_format != expected.credential_payload_format
        or tx.revocation_profile_id != expected.revocation_profile_id
        or tx.issuer_profile_id != expected.issuer_profile_id
        or tx.issuer_mode != expected.issuer_mode
        or tx.validity_days != expected.validity_days
        or tx.renewable != expected.renewable
        or tx.renewal_window_days != expected.renewal_window_days
        or tx.wallet_configs != [dict(item) for item in expected.wallet_configs]
        or tx.selective_disclosure_claims
        != list(expected.selective_disclosure_claims)
        or tx.zk_predicate_claims != list(expected.zk_predicate_claims)
        or _text((tx.claims or {}).get("_vct"))
        != _text(expected.credential_vct)
    ):
        return False

    signing = (
        snapshot.get("remote_signing_config")
        if isinstance(snapshot.get("remote_signing_config"), dict)
        else {}
    )
    return bool(
        _text(signing.get("signing_service_id"))
        and tx.signing_service_id == _text(signing.get("signing_service_id"))
        and _text(snapshot.get("issuer_did"))
        and tx.issuer_did_override == _text(snapshot.get("issuer_did"))
    )


def _resolved_issuer_context_matches(
    binding: Any,
    resolved: Mapping[str, Any] | None,
) -> bool:
    if not isinstance(resolved, Mapping):
        return False
    snapshot = binding.credential_template_snapshot
    expected_signing = (
        snapshot.get("remote_signing_config")
        if isinstance(snapshot.get("remote_signing_config"), dict)
        else {}
    )
    profile = (
        resolved.get("issuer_profile")
        if isinstance(resolved.get("issuer_profile"), Mapping)
        else {}
    )
    service = (
        resolved.get("service")
        if isinstance(resolved.get("service"), Mapping)
        else {}
    )

    def first(*values: Any) -> str:
        return next((_text(value) for value in values if _text(value)), "")

    expected_algorithm = first(
        snapshot.get("issuer_algorithm"),
        snapshot.get("signing_algorithm"),
        expected_signing.get("algorithm"),
    )
    actual_algorithm = first(
        resolved.get("algorithm"),
        profile.get("algorithm"),
        service.get("algorithm"),
    )
    service_algorithms = {
        _text(value)
        for value in (service.get("algorithms") or [])
        if _text(value)
    }
    algorithm_matches = (
        actual_algorithm == expected_algorithm
        if actual_algorithm
        else expected_algorithm in service_algorithms
    )
    return bool(
        first(resolved.get("issuer_profile_id"), profile.get("id"))
        == _text(snapshot.get("issuer_profile_id"))
        and _text(profile.get("status")).lower() == "active"
        and first(resolved.get("issuer_did"), profile.get("issuer_did"))
        == _text(snapshot.get("issuer_did"))
        and first(
            resolved.get("signing_service_id"),
            profile.get("signing_service_id"),
            service.get("id"),
        )
        == _text(expected_signing.get("signing_service_id"))
        and first(
            resolved.get("signing_key_reference"),
            profile.get("signing_key_reference"),
            service.get("key_reference"),
        )
        == _text(expected_signing.get("signing_key_reference"))
        and first(
            resolved.get("verification_method_id"),
            profile.get("verification_method_id"),
        )
        == _text(expected_signing.get("verification_method_id"))
        and first(resolved.get("key_purpose"), profile.get("key_purpose"))
        == _text(expected_signing.get("key_purpose") or "vc_jwt_issuer")
        and algorithm_matches
    )


def _fact_matches_requirement(
    fact: EvidenceFact,
    requirement: CanvasEvidenceRequirement,
    *,
    app: Application,
    lti_subject: str,
) -> bool:
    if (
        fact.organization_id != app.organization_id
        or fact.application_id != app.id
        or fact.subject_id != lti_subject
        or fact.provider != "canvas"
        or fact.requirement_id != requirement.requirement_id
        or fact.fact_type != requirement.fact_type.value
        or _text((fact.source or {}).get("source")) != requirement.source.value
        or not fact.logical_key
        or not fact.source_revision
        or not fact.payload_hash
    ):
        return False
    expected_scope = requirement.scope.to_dict()
    actual_scope = fact.scope if isinstance(fact.scope, dict) else {}
    return all(
        _text(actual_scope.get(key)) == _text(expected)
        for key, expected in expected_scope.items()
    )


def _fact_is_verified_and_fresh(
    fact: EvidenceFact,
    *,
    now: datetime,
    max_age_seconds: int,
) -> bool:
    if _text((fact.verification or {}).get("status")).upper() != "VERIFIED":
        return False
    return canvas_evidence_observation_is_fresh(
        fact.observed_at,
        now=now,
        max_age_seconds=max_age_seconds,
    )


async def require_canvas_issuance_ready(
    *,
    repo: IIssuanceRepository,
    tx: IssuanceTransaction,
    now: datetime | None = None,
    evidence_max_age_seconds: int | None = None,
    resolved_issuer_context: Mapping[str, Any] | None = None,
) -> bool:
    """Authorize a Canvas-bound transaction from current persisted state.

    Returns ``True`` when the transaction is Canvas-bound and passes every
    check, or ``False`` when it belongs to a non-Canvas application.  Any
    Canvas inconsistency raises :class:`CanvasIssuanceGuardError`.
    """

    if not tx.application_id:
        return False
    app = await repo.get_application(tx.application_id)
    if app is None:
        # Without a Canvas marker this remains an ordinary issuance transaction.
        return False
    canvas = _canvas_context(app)
    if canvas is None:
        return False
    if not portable_canvas_enabled_for_organization(tx.organization_id):
        _deny("canvas_rollout_disabled")

    max_age = _evidence_max_age_seconds(evidence_max_age_seconds)
    evaluated_at = _utc(now or datetime.now(UTC))
    platform_id = _text(canvas.get("canvas_platform_id"))
    binding_id = _text(canvas.get("canvas_program_binding_id"))
    if not platform_id or not binding_id or not tx.organization_id:
        _deny("canvas_transaction_context_incomplete")

    platform = await repo.get_canvas_platform_for_org(tx.organization_id, platform_id)
    binding = await repo.get_canvas_program_binding_for_org(
        tx.organization_id,
        binding_id,
    )
    if platform is None or binding is None:
        _deny("canvas_resource_ownership_mismatch")
    if (
        not _canvas_resources_active(platform, binding)
    ):
        _deny("canvas_resources_inactive")
    if not canvas_binding_is_ready_for_activation(binding):
        _deny("canvas_readiness_not_current")

    template = await repo.get_application_template(app.application_template_id)
    if template is None or not _binding_and_transaction_context_match(
        app=app,
        canvas=canvas,
        binding=binding,
        platform=platform,
        template=template,
        tx=tx,
    ):
        _deny("canvas_transaction_context_mismatch")
    if not _resolved_issuer_context_matches(binding, resolved_issuer_context):
        _deny("canvas_resolved_issuer_context_mismatch")

    try:
        requirements = binding.typed_evidence_requirements
    except (TypeError, ValueError):
        _deny("canvas_requirements_invalid")
    facts = await repo.list_current_evidence_facts_for_application(
        app.id,
        organization_id=app.organization_id,
    )
    required = [requirement for requirement in requirements if requirement.required]
    lti_subject = _text(canvas.get("lti_subject"))
    for requirement in required:
        candidates = [
            fact
            for fact in facts
            if fact.requirement_id == requirement.requirement_id
        ]
        if len(candidates) != 1:
            _deny("required_evidence_head_missing_or_ambiguous")
        fact = candidates[0]
        if not _fact_matches_requirement(
            fact,
            requirement,
            app=app,
            lti_subject=lti_subject,
        ):
            _deny("required_evidence_head_mismatch")
        if not _fact_is_verified_and_fresh(
            fact,
            now=evaluated_at,
            max_age_seconds=max_age,
        ):
            _deny("required_evidence_head_unverified_or_stale")

    policy_set_id = (
        binding.approval_policy_set_id or template.approval_policy_set_id
    )
    policy_set = None
    if policy_set_id:
        policy_set = await repo.get_approval_policy_set(
            app.organization_id,
            policy_set_id,
        )
    decision = evaluate_application_evidence_policy(
        app=app,
        template=template,
        binding=binding,
        requirements=requirements,
        facts=facts,
        policy_set=policy_set,
    )
    if not decision.allowed:
        _deny("current_evidence_policy_denied")
    return True
