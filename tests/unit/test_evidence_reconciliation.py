"""Tests for Canvas evidence policy reconciliation."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
_SERVICES = os.path.join(_REPO_ROOT, "services")
_PYTHON = os.path.join(_REPO_ROOT, "python")

for _path in (_SERVICES, _PYTHON):
    if _path not in sys.path:
        sys.path.insert(0, _path)

CONTRACT = json.loads(
    (Path(_REPO_ROOT) / "contracts" / "issuance-internal-applications.json").read_text(
        encoding="utf-8"
    )
)

from issuance.application.evidence_reconciliation import (
    build_canvas_evidence_reconciliation_report,
    reconcile_canvas_evidence_transitions,
)
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    CanvasEventReceipt,
    CanvasPlatform,
    CanvasProgramBinding,
    EvidenceFact,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository


def _verified_canvas_fact(
    *,
    application_id: str,
    organization_id: str = "org-123",
    fact_id: str = "fact-123",
) -> EvidenceFact:
    return EvidenceFact(
        id=fact_id,
        organization_id=organization_id,
        application_id=application_id,
        subject_id="ada@example.com",
        provider="canvas",
        fact_type="canvas.course_completion",
        scope={
            "canvas_account_id": "acct-1",
            "course_id": "course-42",
            "user_id": "user-7",
        },
        assertion={
            "completed": True,
            "completion_at": "2026-05-07T12:34:56Z",
        },
        verification={
            "method": "SIGNED_WEBHOOK",
            "status": "VERIFIED",
            "verified_at": "2026-05-07T12:35:00+00:00",
        },
        source={
            "receipt_id": "receipt-123",
            "provider_event_id": "evt-123",
        },
        created_at=datetime.now(timezone.utc),
    )


async def _seed_canvas_application(
    repo: InMemoryIssuanceRepository,
    *,
    app_id: str = "app-123",
    status: ApplicationStatus = ApplicationStatus.PENDING,
    policy: dict | None = None,
) -> Application:
    template = ApplicationTemplate(
        id="application-template-1",
        organization_id="org-123",
        credential_template_id="credential-template-1",
        evidence_requirements=["canvas.course_completion"],
    )
    platform = CanvasPlatform(
        id="canvas-platform-1",
        organization_id="org-123",
        canvas_account_id="acct-1",
    )
    binding = CanvasProgramBinding(
        id="canvas-binding-1",
        organization_id="org-123",
        platform_id=platform.id,
        credential_template_id="credential-template-1",
        application_template_id=template.id,
        auto_approve_on_evidence=True,
        evidence_requirements=["canvas.course_completion"],
        canvas_scope={"course_id": "course-42"},
    )
    integration_context = {
        "canvas": {
            "canvas_platform_id": platform.id,
            "canvas_program_binding_id": binding.id,
            "canvas_account_id": platform.canvas_account_id,
        }
    }
    if policy is not None:
        integration_context["policy"] = policy
    app = Application(
        id=app_id,
        organization_id="org-123",
        application_template_id=template.id,
        applicant_identifier="ada@example.com",
        form_data={"email": "ada@example.com"},
        integration_context=integration_context,
        status=status,
    )
    await repo.save_application_template(template)
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)
    await repo.save_application(app)
    await repo.save_evidence_fact(_verified_canvas_fact(application_id=app.id))
    return app


async def test_reconcile_evaluates_missing_policy_and_creates_issuance_transaction() -> None:
    expected = CONTRACT["lifecycle"]["reconciliation_outcomes"][
        "evaluate_missing_policy"
    ]
    repo = InMemoryIssuanceRepository()
    app = await _seed_canvas_application(repo)

    result = await reconcile_canvas_evidence_transitions(
        repo=repo,
        organization_id="org-123",
    )

    stored_app = await repo.get_application(app.id)
    for metric, value in expected["metrics"].items():
        assert result.metrics[metric] == value
    assert stored_app is not None
    assert stored_app.status.value == expected["application_status"]
    assert stored_app.reviewer_id == expected["reviewer_id"]
    assert (stored_app.issuance_transaction_id is not None) is expected[
        "transaction_created"
    ]
    assert stored_app.integration_context["policy"]["allowed"] is expected[
        "policy_allowed"
    ]

    tx = await repo.get_transaction(stored_app.issuance_transaction_id)
    assert tx is not None
    assert tx.application_id == app.id
    events = await repo.list_events_for_application(app.id)
    event_types = [event.event_type.value for event in events]
    for event_type in expected["event_types"]:
        assert event_type in event_types


async def test_reconcile_recovers_existing_policy_permit_without_transaction() -> None:
    expected = CONTRACT["lifecycle"]["reconciliation_outcomes"][
        "recover_existing_permit"
    ]
    repo = InMemoryIssuanceRepository()
    app = await _seed_canvas_application(
        repo,
        app_id="app-policy-permit-no-tx",
        status=ApplicationStatus.APPROVED,
        policy={
            "allowed": True,
            "engine": "cedar",
            "policy_source": "bundled",
            "policy_set_id": None,
            "reasons": [],
            "errors": [],
            "context": {"all_required_evidence_satisfied": True},
        },
    )

    result = await reconcile_canvas_evidence_transitions(
        repo=repo,
        organization_id="org-123",
        application_id=app.id,
    )

    stored_app = await repo.get_application(app.id)
    assert result.records[0].action == expected["action"]
    assert result.metrics["evaluated_policies"] == expected["evaluated_policies"]
    assert result.metrics["approval_issuance_successes"] == expected[
        "approval_issuance_successes"
    ]
    assert stored_app is not None
    assert stored_app.status.value == expected["application_status"]
    assert (stored_app.issuance_transaction_id is not None) is expected[
        "transaction_created"
    ]


async def test_reconciliation_report_flags_stale_receipt_without_mutating_application() -> None:
    expected = CONTRACT["lifecycle"]["reconciliation_outcomes"][
        "dry_run_stale_receipt"
    ]
    repo = InMemoryIssuanceRepository()
    app = await _seed_canvas_application(repo, app_id="app-stale-receipt")
    await repo.save_canvas_event_receipt(
        CanvasEventReceipt(
            id="receipt-123",
            provider_event_id="evt-123",
            organization_id="org-123",
            credential_template_id="credential-template-1",
            canvas_account_id="acct-1",
            payload_hash="payload-hash",
            issuance_response={
                "application_id": app.id,
                "evidence_facts": [],
            },
            status="evidence_received",
        )
    )

    result = await build_canvas_evidence_reconciliation_report(
        repo=repo,
        organization_id="org-123",
    )

    stored_app = await repo.get_application(app.id)
    assert result.dry_run is expected["dry_run"]
    assert result.records[0].action == expected["action"]
    assert result.metrics["stale_receipts"] == expected["stale_receipts"]
    assert result.stale_receipts[0].reasons == expected["reasons"]
    assert stored_app is not None
    assert ("policy" in stored_app.integration_context) is expected[
        "application_mutated"
    ]
    assert (stored_app.issuance_transaction_id is not None) is expected[
        "application_mutated"
    ]
