from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from issuance.application import canvas_issuance_guard
from issuance.application.canvas_issuance_guard import (
    CanvasIssuanceGuardError,
    canvas_approval_credential_context,
    require_canvas_issuance_ready,
)
from issuance.application.evidence_policy import EvidencePolicyDecision
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    CanvasPlatform,
    CanvasProgramBinding,
    EvidenceFact,
    IssuanceStatus,
    IssuanceTransaction,
)
from issuance.infrastructure.adapters.memory_repository import (
    InMemoryIssuanceRepository,
)

NOW = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)


def _snapshot() -> dict:
    return {
        "id": "credential-template-1",
        "organization_id": "org-1",
        "status": "ACTIVE",
        "credential_type": "OpenBadgeCredential",
        "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
        "revocation_profile_id": "status-profile-1",
        "issuer_profile_id": "issuer-profile-1",
        "issuer_did": "did:web:issuer.example:orgs:org-1",
        "issuer_key_id": "badge-key-1",
        "issuer_algorithm": "ES256",
        "key_access_mode": "REMOTE_SIGNING",
        "remote_signing_config": {
            "provider": "managed-signing-service",
            "signing_service_id": "kms-service-1",
            "signing_key_reference": "badge-key-1",
            "verification_method_id": (
                "did:web:issuer.example:orgs:org-1#badge-key-1"
            ),
            "key_purpose": "vc_jwt_issuer",
        },
    }


def _resolved_context(*, key_reference: str = "badge-key-1") -> dict:
    issuer_did = "did:web:issuer.example:orgs:org-1"
    verification_method_id = f"{issuer_did}#badge-key-1"
    return {
        "issuer_profile_id": "issuer-profile-1",
        "issuer_did": issuer_did,
        "signing_service_id": "kms-service-1",
        "signing_key_reference": key_reference,
        "verification_method_id": verification_method_id,
        "key_purpose": "vc_jwt_issuer",
        "algorithm": "ES256",
        "issuer_profile": {
            "id": "issuer-profile-1",
            "status": "active",
            "issuer_did": issuer_did,
            "signing_service_id": "kms-service-1",
            "signing_key_reference": key_reference,
            "verification_method_id": verification_method_id,
            "key_purpose": "vc_jwt_issuer",
        },
        "service": {
            "id": "kms-service-1",
            "algorithm": "ES256",
            "key_reference": key_reference,
        },
    }


async def _ready_case(
    monkeypatch: pytest.MonkeyPatch,
    *,
    observed_at: datetime = NOW,
    verification_status: str = "VERIFIED",
) -> tuple[
    InMemoryIssuanceRepository,
    IssuanceTransaction,
    CanvasPlatform,
    CanvasProgramBinding,
    EvidenceFact,
]:
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1")
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="platform-1",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url="https://school.instructure.com",
        registration_status="installed",
        enabled=True,
    )
    requirement = {
        "requirement_id": "assignment-score",
        "source": "canvas_rest",
        "fact_type": "canvas.assignment_score",
        "scope": {"course_id": "42", "activity_id": "9"},
        "pass_rule": {"min_score_percent": 80},
        "required": True,
    }
    binding = CanvasProgramBinding(
        id="binding-1",
        organization_id="org-1",
        platform_id=platform.id,
        application_template_id="application-template-1",
        credential_template_id="credential-template-1",
        evidence_requirements=[requirement],
        config_version=4,
        validated_config_version=4,
        readiness_checks=[
            {
                "code": "production_contract",
                "component": "binding",
                "status": "ready",
                "blocking": True,
                "remediation": "",
                "timestamp": NOW.isoformat(),
            }
        ],
        readiness_validated_at=datetime.now(UTC),
        activated_at=NOW,
        credential_template_snapshot=_snapshot(),
        enabled=True,
    )
    template = ApplicationTemplate(
        id=binding.application_template_id,
        organization_id="org-1",
        credential_template_id=binding.credential_template_id,
        status="ACTIVE",
    )
    app = Application(
        id="application-1",
        organization_id="org-1",
        application_template_id=template.id,
        applicant_identifier="learner-1",
        status=ApplicationStatus.APPROVED,
        issuance_transaction_id="transaction-1",
        integration_context={
            "canvas": {
                "source": "canvas_lti_bootstrap",
                "canvas_account_id": platform.canvas_account_id,
                "canvas_platform_id": platform.id,
                "canvas_program_binding_id": binding.id,
                "application_template_id": template.id,
                "credential_template_id": binding.credential_template_id,
                "lti_subject": "opaque-lti-subject",
            }
        },
    )
    tx = IssuanceTransaction(
        id=app.issuance_transaction_id,
        organization_id=app.organization_id,
        application_id=app.id,
        credential_template_id=binding.credential_template_id,
        status=IssuanceStatus.AUTHORIZED,
        credential_type="OpenBadgeCredential",
        credential_payload_format="w3c_vcdm_v2_sd_jwt",
        revocation_profile_id="status-profile-1",
        issuer_profile_id="issuer-profile-1",
        issuer_did_override="did:web:issuer.example:orgs:org-1",
        signing_service_id="kms-service-1",
    )
    fact = EvidenceFact(
        id="fact-1",
        organization_id=app.organization_id,
        application_id=app.id,
        subject_id="opaque-lti-subject",
        provider="canvas",
        fact_type="canvas.assignment_score",
        scope={"course_id": "42", "activity_id": "9"},
        assertion={"score_percent": 92},
        verification={"status": verification_status, "method": "CANVAS_OAUTH_API_READ"},
        source={"source": "canvas_rest"},
        requirement_id="assignment-score",
        logical_key="platform-1:binding-1:assignment-score:learner-1",
        source_revision="revision-1",
        payload_hash="payload-1",
        observed_at=observed_at,
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)
    await repo.save_application_template(template)
    await repo.save_application(app)
    await repo.save_transaction(tx)
    await repo.record_evidence_revision(fact)
    monkeypatch.setattr(
        canvas_issuance_guard,
        "evaluate_application_evidence_policy",
        lambda **_kwargs: EvidencePolicyDecision(allowed=True, engine="test"),
    )
    return repo, tx, platform, binding, fact


@pytest.mark.asyncio
async def test_canvas_guard_allows_only_current_bound_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, tx, _platform, _binding, _fact = await _ready_case(monkeypatch)

    guarded = await require_canvas_issuance_ready(
        repo=repo,
        tx=tx,
        now=NOW,
        evidence_max_age_seconds=15 * 60,
        resolved_issuer_context=_resolved_context(),
    )

    assert guarded is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("global_enabled", "pilot_organizations"),
    [("false", "org-1"), ("true", "org-other")],
)
async def test_canvas_claim_guard_fails_closed_outside_rollout(
    monkeypatch: pytest.MonkeyPatch,
    global_enabled: str,
    pilot_organizations: str,
) -> None:
    repo, tx, _platform, _binding, _fact = await _ready_case(monkeypatch)
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", global_enabled)
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", pilot_organizations)

    with pytest.raises(CanvasIssuanceGuardError) as exc_info:
        await require_canvas_issuance_ready(
            repo=repo,
            tx=tx,
            now=NOW,
            evidence_max_age_seconds=15 * 60,
            resolved_issuer_context=_resolved_context(),
        )

    assert exc_info.value.code == "canvas_rollout_disabled"


@pytest.mark.asyncio
async def test_canvas_approval_guard_fails_closed_when_pilot_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, _tx, _platform, binding, _fact = await _ready_case(monkeypatch)
    app = await repo.get_application("application-1")
    template = await repo.get_application_template(binding.application_template_id)
    assert app is not None
    assert template is not None
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "false")

    with pytest.raises(CanvasIssuanceGuardError) as exc_info:
        await canvas_approval_credential_context(
            repo=repo,
            app=app,
            template=template,
        )

    assert exc_info.value.code == "canvas_rollout_disabled"


@pytest.mark.asyncio
async def test_non_canvas_issuance_is_not_subject_to_canvas_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    app = Application(
        id="ordinary-application",
        organization_id="org-1",
        application_template_id="ordinary-template",
        status=ApplicationStatus.APPROVED,
        integration_context={"source": "admin"},
    )
    tx = IssuanceTransaction(
        id="ordinary-transaction",
        organization_id="org-1",
        application_id=app.id,
        status=IssuanceStatus.AUTHORIZED,
    )
    await repo.save_application(app)

    monkeypatch.setattr(
        canvas_issuance_guard,
        "evaluate_application_evidence_policy",
        lambda **_kwargs: pytest.fail("non-Canvas policy must not be evaluated"),
    )

    assert await require_canvas_issuance_ready(repo=repo, tx=tx, now=NOW) is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("foreign_platform", "canvas_resource_ownership_mismatch"),
        ("inactive_binding", "canvas_resources_inactive"),
        ("stale_readiness", "canvas_readiness_not_current"),
        ("expired_readiness", "canvas_readiness_not_current"),
        ("template_drift", "canvas_transaction_context_mismatch"),
    ],
)
async def test_canvas_guard_rejects_inactive_stale_or_mismatched_context(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_code: str,
) -> None:
    repo, tx, platform, binding, _fact = await _ready_case(monkeypatch)
    if mutation == "foreign_platform":
        platform.organization_id = "org-2"
    elif mutation == "inactive_binding":
        binding.enabled = False
    elif mutation == "stale_readiness":
        binding.config_version += 1
    elif mutation == "expired_readiness":
        binding.readiness_validated_at = datetime.now(UTC) - timedelta(minutes=16)
    else:
        tx.credential_template_id = "credential-template-drifted"

    with pytest.raises(CanvasIssuanceGuardError) as exc_info:
        await require_canvas_issuance_ready(
            repo=repo,
            tx=tx,
            now=NOW,
            evidence_max_age_seconds=15 * 60,
            resolved_issuer_context=_resolved_context(),
        )

    assert exc_info.value.code == expected_code


@pytest.mark.asyncio
async def test_canvas_approval_rejects_expired_readiness_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, _tx, _platform, binding, _fact = await _ready_case(monkeypatch)
    app = await repo.get_application("application-1")
    template = await repo.get_application_template(binding.application_template_id)
    assert app is not None
    assert template is not None
    binding.readiness_validated_at = datetime.now(UTC) - timedelta(minutes=16)

    with pytest.raises(CanvasIssuanceGuardError) as exc_info:
        await canvas_approval_credential_context(
            repo=repo,
            app=app,
            template=template,
        )

    assert exc_info.value.code == "canvas_readiness_not_current"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("verification_status", "observed_at"),
    [
        ("UNVERIFIED", NOW),
        ("VERIFIED", NOW - timedelta(seconds=901)),
        ("VERIFIED", NOW + timedelta(seconds=1)),
    ],
)
async def test_canvas_guard_requires_verified_fresh_current_heads(
    monkeypatch: pytest.MonkeyPatch,
    verification_status: str,
    observed_at: datetime,
) -> None:
    repo, tx, _platform, _binding, _fact = await _ready_case(
        monkeypatch,
        observed_at=observed_at,
        verification_status=verification_status,
    )

    with pytest.raises(CanvasIssuanceGuardError) as exc_info:
        await require_canvas_issuance_ready(
            repo=repo,
            tx=tx,
            now=NOW,
            evidence_max_age_seconds=15 * 60,
            resolved_issuer_context=_resolved_context(),
        )

    assert exc_info.value.code == "required_evidence_head_unverified_or_stale"


@pytest.mark.asyncio
async def test_canvas_guard_uses_configured_evidence_freshness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, tx, _platform, _binding, _fact = await _ready_case(
        monkeypatch,
        observed_at=NOW - timedelta(minutes=20),
    )
    monkeypatch.setenv("CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS", "1800")

    assert await require_canvas_issuance_ready(
        repo=repo,
        tx=tx,
        now=NOW,
        resolved_issuer_context=_resolved_context(),
    ) is True


@pytest.mark.asyncio
async def test_canvas_guard_requires_current_policy_permit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, tx, _platform, _binding, _fact = await _ready_case(monkeypatch)
    monkeypatch.setattr(
        canvas_issuance_guard,
        "evaluate_application_evidence_policy",
        lambda **_kwargs: EvidencePolicyDecision(allowed=False, engine="test"),
    )

    with pytest.raises(CanvasIssuanceGuardError) as exc_info:
        await require_canvas_issuance_ready(
            repo=repo,
            tx=tx,
            now=NOW,
            resolved_issuer_context=_resolved_context(),
        )

    assert exc_info.value.code == "current_evidence_policy_denied"


@pytest.mark.asyncio
async def test_canvas_guard_rejects_resolved_kms_key_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, tx, _platform, _binding, _fact = await _ready_case(monkeypatch)

    with pytest.raises(CanvasIssuanceGuardError) as exc_info:
        await require_canvas_issuance_ready(
            repo=repo,
            tx=tx,
            now=NOW,
            resolved_issuer_context=_resolved_context(key_reference="rotated-without-readiness"),
        )

    assert exc_info.value.code == "canvas_resolved_issuer_context_mismatch"


@pytest.mark.asyncio
async def test_credential_route_returns_one_sanitized_canvas_denial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from issuance.infrastructure.api import routes

    repo, tx, _platform, binding, _fact = await _ready_case(monkeypatch)
    binding.enabled = False

    response = await routes._canvas_pre_signing_guard_response(tx=tx, repo=repo)

    assert response is not None
    assert response.status_code == 400
    assert json.loads(response.body) == {
        "error": "invalid_credential_request",
        "error_description": "Credential eligibility requirements are not satisfied",
    }
    assert b"binding" not in response.body
    assert b"canvas" not in response.body.lower()


@pytest.mark.asyncio
async def test_credential_route_leaves_non_canvas_transaction_unchanged() -> None:
    from issuance.infrastructure.api import routes

    repo = InMemoryIssuanceRepository()
    app = Application(
        id="ordinary-application",
        organization_id="org-1",
        application_template_id="ordinary-template",
        integration_context={},
    )
    tx = IssuanceTransaction(
        id="ordinary-transaction",
        organization_id="org-1",
        application_id=app.id,
    )
    await repo.save_application(app)

    assert await routes._canvas_pre_signing_guard_response(tx=tx, repo=repo) is None


@pytest.mark.asyncio
async def test_credential_route_sanitizes_unexpected_guard_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from issuance.infrastructure.api import routes

    async def explode(**_kwargs):
        raise RuntimeError("secret internal policy detail")

    monkeypatch.setattr(routes, "require_canvas_issuance_ready", explode)
    response = await routes._canvas_pre_signing_guard_response(
        tx=IssuanceTransaction(id="transaction-1"),
        repo=InMemoryIssuanceRepository(),
    )

    assert response is not None
    assert response.status_code == 400
    assert b"secret" not in response.body
    assert json.loads(response.body)["error"] == "invalid_credential_request"


@pytest.mark.asyncio
async def test_manual_canvas_approval_uses_persisted_snapshot_and_required_kms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from issuance.infrastructure.api import application_routes, routes

    repo, _old_tx, _platform, binding, _fact = await _ready_case(monkeypatch)
    app = await repo.get_application("application-1")
    assert app is not None
    app.status = ApplicationStatus.PENDING
    app.issuance_transaction_id = None
    await repo.save_application(app)

    required_calls: list[str] = []

    async def apply_required(tx):
        required_calls.append(tx.id)
        tx.issuer_did_override = "did:web:issuer.example:orgs:org-1"
        tx.signing_service_id = "kms-service-1"
        return {"signing_key_reference": "badge-key-1"}

    monkeypatch.setattr(
        application_routes,
        "apply_required_remote_issuer_context",
        apply_required,
    )
    monkeypatch.setattr(
        application_routes.httpx,
        "AsyncClient",
        lambda **_kwargs: pytest.fail(
            "Canvas approval must not fetch a live credential template"
        ),
    )

    response = await application_routes.approve_application(
        app.id,
        routes.ApplicationApproval(review_notes="Pilot administrator approval"),
        trusted_organization_id="org-1",
        repo=repo,
    )

    tx = await repo.get_transaction(response.issuance_transaction_id)
    assert tx is not None
    assert required_calls == [tx.id]
    assert tx.credential_template_id == binding.credential_template_id
    assert tx.credential_type == "OpenBadgeCredential"
    assert tx.credential_payload_format == "w3c_vcdm_v2_sd_jwt"
    assert tx.revocation_profile_id == "status-profile-1"
    assert tx.issuer_profile_id == "issuer-profile-1"
    assert tx.issuer_did_override == "did:web:issuer.example:orgs:org-1"
    assert tx.signing_service_id == "kms-service-1"

    template = await repo.get_application_template(app.application_template_id)
    refreshed = await application_routes._get_or_refresh_transaction(
        app,
        repo,
        template,
    )
    assert refreshed.id == tx.id
    assert required_calls == [tx.id, tx.id]
    assert refreshed.revocation_profile_id == "status-profile-1"


@pytest.mark.asyncio
async def test_manual_canvas_approval_fails_closed_on_stale_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fastapi import HTTPException
    from issuance.infrastructure.api import application_routes, routes

    repo, _old_tx, _platform, binding, _fact = await _ready_case(monkeypatch)
    app = await repo.get_application("application-1")
    assert app is not None
    app.status = ApplicationStatus.PENDING
    app.issuance_transaction_id = None
    binding.config_version += 1

    monkeypatch.setattr(
        application_routes.httpx,
        "AsyncClient",
        lambda **_kwargs: pytest.fail("stale Canvas approval must not call services"),
    )
    with pytest.raises(HTTPException) as exc_info:
        await application_routes.approve_application(
            app.id,
            routes.ApplicationApproval(review_notes="Should fail"),
            trusted_organization_id="org-1",
            repo=repo,
        )

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "Canvas application is not ready for approval"
    assert app.status == ApplicationStatus.PENDING
    assert app.issuance_transaction_id is None


@pytest.mark.asyncio
async def test_manual_non_canvas_approval_keeps_live_template_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from issuance.infrastructure.api import application_routes, routes

    repo = InMemoryIssuanceRepository()
    template = ApplicationTemplate(
        id="ordinary-template",
        organization_id="org-1",
        credential_template_id="ordinary-credential-template",
        status="ACTIVE",
    )
    app = Application(
        id="ordinary-application",
        organization_id="org-1",
        application_template_id=template.id,
        applicant_identifier="ordinary-holder",
        status=ApplicationStatus.PENDING,
        integration_context={},
    )
    await repo.save_application_template(template)
    await repo.save_application(app)

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {
                "credential_type": "EmployeeCredential",
                "vct": "https://issuer.example/credentials/employee",
            }

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, _url):
            return Response()

    ordinary_calls: list[str] = []

    async def apply_ordinary(tx):
        ordinary_calls.append(tx.id)
        return None

    async def reject_required(_tx):
        pytest.fail("non-Canvas approval must not use the Canvas KMS contract")

    monkeypatch.setattr(application_routes.httpx, "AsyncClient", lambda **_kwargs: Client())
    monkeypatch.setattr(application_routes, "apply_remote_issuer_context", apply_ordinary)
    monkeypatch.setattr(
        application_routes,
        "apply_required_remote_issuer_context",
        reject_required,
    )

    response = await application_routes.approve_application(
        app.id,
        routes.ApplicationApproval(review_notes="Ordinary approval"),
        trusted_organization_id="org-1",
        repo=repo,
    )

    tx = await repo.get_transaction(response.issuance_transaction_id)
    assert tx is not None
    assert ordinary_calls == [tx.id]
    assert tx.credential_type == "EmployeeCredential"
    assert tx.claims["_vct"] == "https://issuer.example/credentials/employee"
