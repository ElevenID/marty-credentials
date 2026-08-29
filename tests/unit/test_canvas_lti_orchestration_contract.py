from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from issuance.domain.entities import CanvasPlatform, CanvasProgramBinding
from issuance.infrastructure.api import canvas_routes
from starlette.requests import Request

CONTRACT = json.loads(
    (Path(__file__).parents[2] / "contracts" / "issuance-canvas-lti-foundation.json").read_text(
        encoding="utf-8"
    )
)
POLICY = CONTRACT["launch"]["orchestration"]


def _request() -> Request:
    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/integrations/canvas/lti/platforms/platform-1/launch",
            "headers": [(b"content-type", b"application/json")],
        },
        receive,
    )


class _Repository:
    def __init__(self, calls: list[str], platform: CanvasPlatform) -> None:
        self.calls = calls
        self.platform = platform
        self.state = SimpleNamespace(
            platform_id=platform.id,
            status="pending",
            is_expired=False,
            nonce="nonce-1",
        )

    async def get_canvas_platform(self, platform_id: str) -> CanvasPlatform | None:
        self.calls.append("load-platform")
        return self.platform if platform_id == self.platform.id else None

    async def get_canvas_lti_launch_state(self, state: str) -> object | None:
        self.calls.append("load-state")
        return self.state if state == "state-1" else None

    async def consume_canvas_lti_launch_state(self, state: str) -> object | None:
        self.calls.append("consume-state-atomically")
        return self.state if state == "state-1" else None

    async def save_canvas_platform(self, platform: CanvasPlatform) -> None:
        self.calls.append("persist-platform-validation-state")
        self.platform = platform


def _install_harness(
    monkeypatch: pytest.MonkeyPatch,
    *,
    failure_stage: str | None = None,
) -> tuple[list[str], _Repository]:
    calls: list[str] = []
    platform = CanvasPlatform(
        id="platform-1",
        organization_id="org-1",
        canvas_account_id="account-1",
    )
    binding = CanvasProgramBinding(
        id="binding-1",
        organization_id="org-1",
        platform_id="platform-1",
        config_version=4,
    )
    repository = _Repository(calls, platform)

    def authorize(_organization_id: str) -> None:
        calls.append("authorize-and-validate-platform")

    async def parse(_request: Request) -> tuple[str, str]:
        calls.append("parse-submission")
        return "header.payload.signature", "state-1"

    async def verify(**_kwargs: object) -> tuple[CanvasPlatform, dict[str, object]]:
        calls.append("verify-jwt-with-bounded-jwks-refresh")
        if failure_stage == "verify-jwt-with-bounded-jwks-refresh":
            raise HTTPException(status_code=400, detail="verification failed")
        return platform, {"raw_claims": {}, "roles": ["Learner"]}

    async def identity(**_kwargs: object) -> None:
        calls.append("persist-verified-identity")

    async def resolve(**_kwargs: object) -> tuple[CanvasPlatform, CanvasProgramBinding | None]:
        calls.append("resolve-binding-and-feature-gate")
        return platform, None if failure_stage == "resolve-binding-and-feature-gate" else binding

    async def persist_ags(**_kwargs: object) -> bool:
        calls.append("persist-verified-ags-line-item")
        return False

    def project(**_kwargs: object) -> object:
        calls.append("project-private-response")
        return SimpleNamespace(lti_capabilities={"names_roles": True})

    def merge(**_kwargs: object) -> dict[str, object]:
        calls.append("merge-binding-capability-snapshot")
        return {"verified_binding_launches": {"binding-1": {"names_roles": True}}}

    monkeypatch.setattr(canvas_routes, "_require_portable_canvas_pilot", authorize)
    monkeypatch.setattr(canvas_routes, "_validate_lti_ready_platform", lambda _platform: None)
    monkeypatch.setattr(canvas_routes, "_parse_lti_launch_submission", parse)
    monkeypatch.setattr(canvas_routes, "_verify_lti_launch_with_jwks_refresh", verify)
    monkeypatch.setattr(canvas_routes, "_record_verified_canvas_launch_identity", identity)
    monkeypatch.setattr(canvas_routes, "_resolve_lti_program_binding", resolve)
    monkeypatch.setattr(canvas_routes, "_require_canvas_feature", lambda *_args: None)
    monkeypatch.setattr(canvas_routes, "_persist_verified_ags_line_item", persist_ags)
    monkeypatch.setattr(canvas_routes, "_lti_launch_response", project)
    monkeypatch.setattr(canvas_routes, "_lti_signed_canvas_identifier", lambda *_args: "course-1")
    monkeypatch.setattr(canvas_routes, "merge_verified_lti_binding_capabilities", merge)
    return calls, repository


@pytest.mark.asyncio
async def test_launch_orchestration_replays_the_frozen_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls, repository = _install_harness(monkeypatch)

    platform, consumed_state, response = await canvas_routes._verify_canvas_lti_launch_submission(
        platform_id="platform-1",
        request=_request(),
        repo=repository,
    )

    assert calls == POLICY["ordered_stages"]
    assert platform is repository.platform
    assert consumed_state is repository.state
    assert response.lti_capabilities == {"names_roles": True}
    assert platform.registration_status == "verified"
    assert platform.capability_snapshot == {
        "verified_binding_launches": {"binding-1": {"names_roles": True}}
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("case", POLICY["failure_cases"], ids=lambda case: case["name"])
async def test_launch_orchestration_preserves_irreversible_failure_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    case: dict[str, object],
) -> None:
    failure_stage = str(case["failure_stage"])
    calls, repository = _install_harness(monkeypatch, failure_stage=failure_stage)

    with pytest.raises(HTTPException):
        await canvas_routes._verify_canvas_lti_launch_submission(
            platform_id="platform-1",
            request=_request(),
            repo=repository,
        )

    assert calls[:-1] == case["completed_stages"]
    assert calls[-1] == failure_stage
    assert ("consume-state-atomically" in calls) is case["state_consumed"]
    assert ("persist-verified-identity" in calls) is case["identity_persisted"]
    assert ("persist-platform-validation-state" in calls) is case["capability_snapshot_persisted"]


def test_launch_orchestration_contract_pins_irreversible_ordering() -> None:
    assert POLICY["invariants"] == {
        "state_consumed_before_jwt_verification": True,
        "state_restored_after_downstream_failure": False,
        "identity_persisted_before_binding_resolution": True,
        "ags_pin_persisted_before_response_projection": True,
        "capability_snapshot_persisted_last": True,
        "public_response_returned_only_after_all_persistence": True,
    }
