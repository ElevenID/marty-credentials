"""Keep the frozen discovery vectors available to the Rust owner."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads(
    (ROOT / "contracts/issuance-static-discovery.json").read_text(encoding="utf-8")
)


def test_contract_partitions_database_backed_metadata_explicitly() -> None:
    assert len(CONTRACT["cases"]) == 6
    assert CONTRACT["remaining_tenant_backed_operations"] == [
        "get_org_issuer_metadata",
        "get_org_issuer_metadata_credential_manager",
        "get_org_issuer_metadata_apple_wallet",
    ]
    assert not (ROOT / "services" / "issuance").exists()
