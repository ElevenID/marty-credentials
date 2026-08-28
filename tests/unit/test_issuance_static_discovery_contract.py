from __future__ import annotations

import json
import re
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
    request_id = CONTRACT["transport"]["request_id"]
    for case in CONTRACT["cases"]:
        response = client.request(
            case["method"],
            case["path"],
            headers={request_id["request_header"]: request_id["propagated_value"]},
        )
        assert response.status_code == case["status_code"], case["operation"]
        assert response.headers["content-type"].split(";", 1)[0] == case["content_type"]
        assert response.json() == case["body"], case["operation"]
        assert response.headers[request_id["response_header"]] == request_id["propagated_value"]

    generated = client.get(CONTRACT["cases"][0]["path"])
    assert re.fullmatch(
        request_id["generated_pattern"],
        generated.headers[request_id["response_header"]],
    )
    empty = client.get(CONTRACT["cases"][0]["path"], headers={request_id["request_header"]: ""})
    assert re.fullmatch(
        request_id["generated_pattern"],
        empty.headers[request_id["response_header"]],
    )


def test_static_discovery_contract_matches_cors_transport(monkeypatch) -> None:
    from issuance import main

    cors = CONTRACT["transport"]["cors"]
    monkeypatch.setenv("TOKEN_HMAC_KEY", "test-only-not-a-secret")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", cors["allowed_origin"])
    client = TestClient(main.create_app())

    simple = client.get(CONTRACT["cases"][0]["path"], headers={"origin": cors["allowed_origin"]})
    for name, value in cors["simple_response_headers"].items():
        assert simple.headers[name] == value

    for contract_key in (
        "preflight",
        "denied_preflight",
        "denied_method_preflight",
    ):
        case = cors[contract_key]
        response = client.request(case["method"], case["path"], headers=case["request_headers"])
        assert response.status_code == case["status_code"]
        assert response.text == case["body"]
        for name, value in case["response_headers"].items():
            assert response.headers[name] == value

    wildcard = cors["wildcard_simple_request"]
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", wildcard["configured_origin"])
    wildcard_client = TestClient(main.create_app())
    wildcard_response = wildcard_client.get(
        CONTRACT["cases"][0]["path"], headers={"origin": wildcard["request_origin"]}
    )
    for name, value in wildcard["response_headers"].items():
        assert wildcard_response.headers[name] == value


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
