from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from issuance.application.canvas_lti_capability_snapshots import (
    merge_verified_lti_binding_capabilities,
)

CONTRACT = json.loads(
    (Path(__file__).parents[2] / "contracts" / "issuance-canvas-lti-foundation.json").read_text(
        encoding="utf-8"
    )
)
POLICY = CONTRACT["launch"]["capability_snapshot_persistence"]
VERIFIED_AT = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize("case", POLICY["cases"], ids=lambda case: case["name"])
def test_capability_snapshot_persistence_cases(case: dict[str, object]) -> None:
    snapshot: dict[str, object] = {"diagnostic_from_last_launch": "replace-me"}
    prior = case["prior"]
    if isinstance(prior, dict):
        prior = dict(prior)
        snapshot_key = str(prior.pop("snapshot_key"))
        snapshot["verified_binding_launches"] = {snapshot_key: prior}

    actual = merge_verified_lti_binding_capabilities(
        capability_snapshot=snapshot,
        launch_capabilities=dict(case["launch_capabilities"]),
        binding_id=str(case["binding_id"]),
        binding_config_version=int(case["binding_config_version"]),
        signed_course_id=str(case["signed_course_id"]),
        line_item_configuration_changed=bool(case["line_item_configuration_changed"]),
        verified_at=VERIFIED_AT,
    )

    binding_id = str(case["binding_id"])
    launches = actual["verified_binding_launches"]
    assert isinstance(launches, dict)
    assert launches[binding_id] == case["expected_binding_capabilities"]
    for key, value in dict(case["launch_capabilities"]).items():
        assert actual[key] == value
    assert actual["verified_binding_id"] == binding_id
    assert actual["verified_binding_config_version"] == case["binding_config_version"]
    assert actual["verified_course_id"] == case["signed_course_id"]
    assert actual["verified_at"] == VERIFIED_AT.isoformat()
    if case.get("preserve_other_binding"):
        assert isinstance(prior, dict)
        assert launches[str(case["prior"]["snapshot_key"])] == prior


def test_capability_snapshot_contract_is_binding_indexed_and_fail_closed_on_drift() -> None:
    assert POLICY["authority"] == "verified-signed-launch-claims"
    assert POLICY["authorization_index"] == "verified_binding_launches"
    assert set(POLICY["carry_prior_requires"]) == {
        "same-binding",
        "same-course",
        "same-config",
    }
    assert POLICY["ags_pin_version_exception"] == ("one-version-behind-only-when-line-item-changed")
    assert POLICY["verified_ags_line_items"] == "sorted-deduplicated-union"
