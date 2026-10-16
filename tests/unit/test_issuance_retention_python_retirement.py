"""Current source retirement and frozen retention behavior boundaries."""

import json
from pathlib import Path

from tests.retired_python_source import has_source

ROOT = Path(__file__).resolve().parents[2]


RETIRED = {
    ("GET", "/v1/issuance/organizations/{organization_id}/retention"),
    ("POST", "/v1/issuance/organizations/{organization_id}/retention/purge"),
}


def test_retention_and_passport_python_owner_is_removed() -> None:
    assert not has_source(ROOT / "services" / "issuance")


def test_frozen_retention_contract_remains_available_to_rust() -> None:
    contract = json.loads(
        (ROOT / "contracts/issuance-retention-management.json").read_text(encoding="utf-8")
    )
    assert contract["schema"] == "marty.issuance-retention-management/v1"
    assert {(row["method"], row["path"]) for row in contract["routes"]} == RETIRED
