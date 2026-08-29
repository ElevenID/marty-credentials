from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi import HTTPException
from issuance.domain.entities import CanvasPlatform, CanvasProgramBinding
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import canvas_routes

CONTRACT = json.loads(
    (Path(__file__).parents[2] / "contracts" / "issuance-canvas-lti-foundation.json").read_text(
        encoding="utf-8"
    )
)
POLICY = CONTRACT["launch"]["ags_line_item_pinning"]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", POLICY["cases"], ids=lambda case: case["name"])
async def test_ags_line_item_pinning_cases(case: dict[str, object]) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="platform-1",
        organization_id="org-1",
        canvas_account_id="account-1",
    )
    scope = {"course_id": "course-1", "resource_id": "resource-1"}
    if case["requirement_source"] == "canvas_rest":
        scope["activity_id"] = "assignment-1"
    if case["existing_line_item_url"] is not None:
        scope["line_item_url"] = case["existing_line_item_url"]
    binding = CanvasProgramBinding(
        id="binding-1",
        organization_id=platform.organization_id,
        platform_id=platform.id,
        application_template_id="application-1",
        credential_template_id="credential-1",
        evidence_requirements=[
            {
                "requirement_id": "score-1",
                "source": case["requirement_source"],
                "fact_type": "canvas.assignment_score",
                "scope": scope,
                "pass_rule": {"min_score_percent": 80},
                "required": True,
            }
        ],
        config_version=4,
        validated_config_version=4,
        readiness_checks=[{"code": "ready", "status": "ready", "blocking": True}],
        readiness_validated_at=datetime.now(UTC),
        activated_at=datetime.now(UTC),
        credential_template_snapshot={"id": "credential-1"},
        enabled=True,
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)
    custom = {
        "canvas_program_binding_id": case["signed_binding_id"],
        "canvas_requirement_id": case["signed_requirement_id"],
        "canvas_resource_id": case["signed_resource_id"],
    }
    ags = {"lineitem": case["line_item_url"]} if case["line_item_url"] else {}
    invocation = canvas_routes._persist_verified_ags_line_item(
        platform=platform,
        binding=binding,
        verified_launch={"raw_claims": {"custom": custom, "ags_endpoint": ags}},
        repo=repo,
    )

    if case["status_code"] == 200:
        assert await invocation is case["changed"]
        stored = await repo.get_canvas_program_binding(binding.id)
        assert stored is not None
        if case["changed"]:
            assert stored.config_version == 5
            assert stored.enabled is False
            assert stored.validated_config_version is None
            assert stored.readiness_checks == []
            assert stored.readiness_validated_at is None
            assert stored.activated_at is None
            assert stored.credential_template_snapshot == {}
            assert stored.evidence_requirements[0]["scope"]["line_item_url"] == case["line_item_url"]
        else:
            assert stored.config_version == 4
            assert stored.enabled is True
    else:
        with pytest.raises(HTTPException) as exc_info:
            await invocation
        assert exc_info.value.status_code == case["status_code"]
        if "detail" in case:
            assert exc_info.value.detail == case["detail"]
        else:
            assert str(exc_info.value.detail).startswith(str(case["detail_prefix"]))


def test_ags_line_item_pinning_uses_only_signed_inputs_and_resets_readiness() -> None:
    assert POLICY["incomplete_claim_policy"] == "no-op"
    assert POLICY["idempotent"] is True
    assert POLICY["matching_requirement_source"] == "ags_result"
    assert all(value.startswith("signed-") for value in POLICY["authoritative_inputs"])
    assert set(POLICY["changed_binding_policy"]["reset_fields"]) == {
        "validated_config_version",
        "readiness_checks",
        "readiness_validated_at",
        "activated_at",
        "credential_template_snapshot",
    }
