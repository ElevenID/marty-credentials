"""Language-neutral JSON observations of the real legacy result projection."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from issuance import canvas_worker

FIXTURE = json.loads(
    (Path(__file__).resolve().parents[2] / "contracts/canvas-worker-result-oracle.json").read_text(
        encoding="utf-8"
    )
)


@pytest.mark.parametrize("field", FIXTURE["allowed_fields"])
@pytest.mark.parametrize("case", FIXTURE["value_cases"], ids=lambda case: case["name"])
def test_every_allowed_field_uses_the_observed_json_projection(field: str, case: dict) -> None:
    value = json.loads(case["input_json"])
    supplied = {field: value, "provider_payload": {"synthetic": "discard"}}
    before = copy.deepcopy(supplied)
    observed = canvas_worker._safe_result(supplied)

    assert json.dumps(supplied, sort_keys=True) == json.dumps(before, sort_keys=True)
    assert observed is not supplied
    if case.get("omitted"):
        assert observed == {}
    else:
        expected = json.loads(case["expected_json"])
        assert observed == {field: expected}
        # Python considers True == 1 and False == 0; value equality alone would
        # miss a JSON type regression in the Rust parity boundary.
        assert type(observed[field]) is type(expected)


@pytest.mark.parametrize("field", FIXTURE["unknown_fields"])
@pytest.mark.parametrize("case", FIXTURE["value_cases"], ids=lambda case: case["name"])
def test_unknown_fields_are_omitted_for_every_json_value_type(field: str, case: dict) -> None:
    assert canvas_worker._safe_result({field: json.loads(case["input_json"])}) == {}


def test_projection_preserves_the_complete_allowlist_without_mutating_its_input() -> None:
    supplied = {field: index for index, field in enumerate(FIXTURE["allowed_fields"])}
    before = supplied.copy()
    assert canvas_worker._safe_result(supplied) == before
    assert supplied == before


def test_projection_of_an_empty_result_is_empty() -> None:
    assert canvas_worker._safe_result({}) == {}


@pytest.mark.parametrize("value", [b"synthetic", (1, 2), {1, 2}, object()])
def test_non_json_provider_values_are_not_persisted(value: object) -> None:
    assert canvas_worker._safe_result({"application_id": value}) == {}
