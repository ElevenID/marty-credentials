from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import HTTPException
from issuance.domain.entities import CanvasPlatform
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import canvas_routes

CONTRACT = json.loads(
    (Path(__file__).parents[2] / "contracts" / "issuance-canvas-lti-foundation.json").read_text(
        encoding="utf-8"
    )
)
POLICY = CONTRACT["launch"]["jwt"]["jwks_refresh_policy"]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", POLICY["cases"], ids=lambda case: case["name"])
async def test_jwks_refresh_policy_cases(
    monkeypatch: pytest.MonkeyPatch,
    case: dict[str, object],
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-jwks-contract",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        canvas_base_url=(
            "https://canvas.example.edu" if case["canvas_base_url"] else None
        ),
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.instructure.com",
        lti_jwks_json={"keys": [{"kid": "old-kid"}]},
    )
    refreshed = replace(platform)
    refreshed.lti_jwks_json = {"keys": [{"kid": "new-kid"}]}
    unknown_kid = RuntimeError(f"{POLICY['unknown_kid_marker']} new-kid")
    invalid_signature = RuntimeError("LTI signature verification failed")
    results: list[object] = []
    for outcome in (case["first_verification"], case.get("second_verification")):
        if outcome == "unknown_kid":
            results.append(unknown_kid)
        elif outcome == "invalid_signature":
            results.append(invalid_signature)
        elif outcome == "succeeds":
            results.append({"issuer": platform.lti_issuer})

    def verify_side_effect(**_kwargs: object) -> dict[str, object]:
        result = results.pop(0)
        if isinstance(result, Exception):
            raise result
        assert isinstance(result, dict)
        return result

    verify = Mock(side_effect=verify_side_effect)
    monkeypatch.setattr(canvas_routes, "_verify_lti_launch_with_platform", verify)
    refresh = AsyncMock(return_value=(refreshed, {"jwks_json": refreshed.lti_jwks_json}))
    if case.get("refresh") == "fails":
        refresh.side_effect = RuntimeError("Canvas metadata probe failed")
    monkeypatch.setattr(canvas_routes, "_refresh_canvas_platform_jwks", refresh)

    if case["status_code"] == 200:
        actual_platform, verified = await canvas_routes._verify_lti_launch_with_jwks_refresh(
            platform=platform,
            id_token="header.payload.signature",
            expected_nonce="nonce-1",
            repo=repo,
        )
        assert actual_platform is refreshed
        assert verified == {"issuer": platform.lti_issuer}
    else:
        with pytest.raises(HTTPException) as exc_info:
            await canvas_routes._verify_lti_launch_with_jwks_refresh(
                platform=platform,
                id_token="header.payload.signature",
                expected_nonce="nonce-1",
                repo=repo,
            )
        assert exc_info.value.status_code == case["status_code"]
        assert str(exc_info.value.detail).startswith(str(case["detail_prefix"]))

    assert verify.call_count == case["verification_attempts"]
    assert refresh.await_count == case["refresh_attempts"]


def test_jwks_refresh_policy_is_bounded_and_fail_closed() -> None:
    assert POLICY["maximum_refreshes"] == 1
    assert POLICY["maximum_verification_attempts"] == 2
    assert POLICY["requires_canvas_base_url"] is True
    assert POLICY["persist_before_retry"] is True
    assert POLICY["reuse_persisted_trust_profile"] is True
    assert POLICY["state_remains_consumed_on_failure"] is True
