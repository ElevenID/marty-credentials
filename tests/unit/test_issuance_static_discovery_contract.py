from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads(
    (ROOT / "contracts/issuance-static-discovery.json").read_text(encoding="utf-8")
)


def test_static_discovery_contract_matches_python_oracle(monkeypatch) -> None:
    from issuance import main
    from issuance.infrastructure.api import routes

    inputs = CONTRACT["inputs"]
    monkeypatch.setattr(routes, "ISSUER_BASE_URL", inputs["issuer_base_url"])
    monkeypatch.setenv("ISSUER_DISPLAY_NAME", inputs["issuer_display_name"])
    monkeypatch.setenv("TOKEN_HMAC_KEY", "test-only-not-a-secret")

    client = TestClient(main.create_app())
    for case in CONTRACT["cases"]:
        response = client.request(case["method"], case["path"])
        assert response.status_code == case["status_code"], case["operation"]
        assert response.headers["content-type"].split(";", 1)[0] == case["content_type"]
        assert response.json() == case["body"], case["operation"]


def test_removed_discovery_fork_stays_unroutable(monkeypatch) -> None:
    from issuance import main

    monkeypatch.setenv("TOKEN_HMAC_KEY", "test-only-not-a-secret")
    client = TestClient(main.create_app())
    for path in CONTRACT["rejected_paths"]:
        assert client.get(path).status_code == 404


def test_contract_partitions_database_backed_metadata_explicitly() -> None:
    assert len(CONTRACT["cases"]) == 6
    assert CONTRACT["remaining_tenant_backed_operations"] == [
        "get_org_issuer_metadata",
        "get_org_issuer_metadata_credential_manager",
        "get_org_issuer_metadata_apple_wallet",
    ]
