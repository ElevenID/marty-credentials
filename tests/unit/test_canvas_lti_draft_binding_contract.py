from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from issuance.domain.entities import CanvasPlatform, CanvasProgramBinding
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import canvas_routes

CONTRACT = json.loads(
    (Path(__file__).parents[2] / "contracts" / "issuance-canvas-lti-foundation.json").read_text(
        encoding="utf-8"
    )
)
POLICY = CONTRACT["launch"]["draft_binding_fallback"]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", POLICY["cases"], ids=lambda case: case["name"])
async def test_draft_binding_fallback_cases(
    monkeypatch: pytest.MonkeyPatch,
    case: dict[str, object],
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="platform-1",
        organization_id="org-1",
        canvas_account_id="account-1",
    )
    await repo.save_canvas_platform(platform)
    for candidate in case["candidates"]:
        binding = CanvasProgramBinding(
            id=candidate["id"],
            organization_id=platform.organization_id,
            platform_id=platform.id,
            application_template_id=f"application-{candidate['id']}",
            credential_template_id=f"credential-{candidate['id']}",
            canvas_scope={"course_id": candidate["course_id"]},
            enabled=False,
            archived_at=datetime.now(UTC) if candidate["archived"] else None,
        )
        await repo.save_canvas_program_binding(binding)

    monkeypatch.setattr(
        canvas_routes,
        "resolve_canvas_program_binding_for_scope",
        AsyncMock(return_value=(platform, None)),
    )
    custom = {"canvas_course_id": "course-1"}
    if case["requested_binding_id"] is not None:
        custom["canvas_program_binding_id"] = case["requested_binding_id"]
    verified = {
        "message_type": case["message_type"],
        "roles": case["roles"],
        "raw_claims": {"custom": custom},
    }

    actual_platform, binding = await canvas_routes._resolve_lti_program_binding(
        platform=platform,
        verified=verified,
        repo=repo,
    )

    assert actual_platform is platform
    assert (binding.id if binding else None) == case["expected_binding_id"]


def test_draft_binding_fallback_is_staff_only_unique_and_signed() -> None:
    assert POLICY["normal_resolution_precedes_fallback"] is True
    assert POLICY["learner_fallback_forbidden"] is True
    assert POLICY["unique_candidate_required"] is True
    assert POLICY["archived_candidates_forbidden"] is True
    assert POLICY["requested_binding_source"].startswith("signed-custom-claim:")
