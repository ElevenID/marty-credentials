"""Observe the real legacy worker using portable configuration fixtures.

These observations do not authorize Rust cutover: explicitly flagged cases
still require a documented compatibility or hardening decision.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path

import pytest
from issuance.canvas_worker import CanvasSyncWorkerConfig

FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[2] / "contracts/canvas-worker-configuration-oracle.json"
    ).read_text(encoding="utf-8")
)
NUMERIC_ENVIRONMENT = FIXTURE["integer_environment"] + FIXTURE["float_environment"]
MALFORMED_CASES = [
    (name, value)
    for kind in ("integer", "float")
    for name in FIXTURE[f"{kind}_environment"]
    for value in FIXTURE[f"malformed_{kind}_values"]
]


@pytest.fixture(autouse=True)
def _isolated_worker_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in NUMERIC_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CANVAS_SYNC_WORKER_ID", "oracle-worker")


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda case: case["name"])
def test_configuration_matches_legacy_observation(
    case: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name, value in case["environment"].items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)

    observed = asdict(CanvasSyncWorkerConfig.from_env())
    expected = FIXTURE["defaults"] | case["expected"]
    if case.get("generated_identity"):
        identity = observed.pop("worker_id")
        expected.pop("worker_id")
        assert re.fullmatch(r".+-\d+-[0-9a-f]{8}", identity)
        assert CanvasSyncWorkerConfig.from_env().worker_id != identity
    assert observed == expected


@pytest.mark.parametrize(("name", "value"), MALFORMED_CASES)
def test_malformed_numeric_configuration_fails_startup(
    name: str, value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        CanvasSyncWorkerConfig.from_env()
