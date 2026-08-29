from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads(
    (ROOT / "contracts/issuance-tenant-discovery.json").read_text(encoding="utf-8")
)


class ContractRepository:
    def __init__(self, inputs: dict[str, Any]) -> None:
        self.inputs = inputs
        self.requested_organizations: list[str] = []

    def _scope(self, organization_id: str) -> None:
        assert organization_id == self.inputs["organization_id"]
        self.requested_organizations.append(organization_id)

    async def get_credential_types_for_org(self, organization_id: str) -> list[str]:
        self._scope(organization_id)
        return self.inputs["credential_types"]

    async def get_credential_type_formats_for_org(
        self, organization_id: str
    ) -> list[tuple[str, list[str]]]:
        self._scope(organization_id)
        return [
            (credential_type, formats)
            for credential_type, formats in self.inputs["credential_type_formats"]
        ]

    async def get_credential_display_metadata_for_org(
        self, organization_id: str
    ) -> dict[str, dict[str, Any]]:
        self._scope(organization_id)
        return self.inputs["display_metadata"]


def expected_body(inputs: dict[str, Any], variant: dict[str, Any]) -> dict[str, Any]:
    issuer = (
        f"{inputs['issuer_base_url']}/org/{inputs['organization_id']}{variant['issuer_suffix']}"
    )
    return {
        "credential_issuer": issuer,
        "authorization_servers": [issuer],
        "display": [{"name": inputs["issuer_display_name"], "locale": "en-US"}],
        "credential_endpoint": f"{inputs['issuer_base_url']}/v1/issuance/credential",
        "nonce_endpoint": f"{inputs['issuer_base_url']}/v1/issuance/nonce",
        "deferred_credential_endpoint": (
            f"{inputs['issuer_base_url']}/v1/issuance/deferred-credential"
        ),
        "notification_endpoint": f"{inputs['issuer_base_url']}/v1/issuance/notification",
        "credential_configurations_supported": variant["credential_configurations_supported"],
    }


def test_tenant_discovery_contract_matches_python_oracle(monkeypatch) -> None:
    from issuance import main
    from issuance.infrastructure.api import routes, signing_context

    inputs = CONTRACT["inputs"]
    repository = ContractRepository(inputs)
    resolver_calls: list[dict[str, Any]] = []

    async def resolve(organization_id: str, **kwargs: Any) -> dict[str, Any]:
        resolver_calls.append({"organization_id": organization_id, **kwargs})
        requirement = inputs["required_key_attestation_by_format"][kwargs["credential_format"]]
        return {
            "issuer_profile": {
                "key_attestation_policy": {
                    "mode": "required",
                    "required_key_storage": requirement.get("key_storage", []),
                    "required_user_authentication": requirement.get("user_authentication", []),
                }
            }
        }

    monkeypatch.setattr(main, "_repo", repository)
    monkeypatch.setattr(signing_context, "resolve_remote_issuer_context", resolve)
    monkeypatch.setattr(routes, "ISSUER_BASE_URL", inputs["issuer_base_url"])
    monkeypatch.setenv("ISSUER_DISPLAY_NAME", inputs["issuer_display_name"])
    monkeypatch.setenv("TOKEN_HMAC_KEY", "test-only-not-a-secret")
    client = TestClient(main.create_app())

    for variant in CONTRACT["variants"]:
        resolver_calls.clear()
        repository.requested_organizations.clear()
        response = client.get(variant["path"])
        assert response.status_code == 200, variant["operation"]
        assert response.headers["content-type"].split(";", 1)[0] == "application/json"
        assert response.json() == expected_body(inputs, variant), variant["operation"]
        assert resolver_calls == variant["expected_resolver_calls"]
        assert repository.requested_organizations
        assert set(repository.requested_organizations) == {inputs["organization_id"]}


def test_tenant_discovery_fails_closed_when_proof_policy_is_unavailable(
    monkeypatch,
) -> None:
    from issuance import main
    from issuance.infrastructure.api import routes, signing_context

    inputs = CONTRACT["inputs"]

    async def unavailable(_organization_id: str, **_kwargs: Any) -> None:
        raise RuntimeError("ambiguous issuer profiles")

    monkeypatch.setattr(main, "_repo", ContractRepository(inputs))
    monkeypatch.setattr(signing_context, "resolve_remote_issuer_context", unavailable)
    monkeypatch.setattr(routes, "ISSUER_BASE_URL", inputs["issuer_base_url"])
    monkeypatch.setenv("ISSUER_DISPLAY_NAME", inputs["issuer_display_name"])
    monkeypatch.setenv("TOKEN_HMAC_KEY", "test-only-not-a-secret")
    client = TestClient(main.create_app())
    expected = CONTRACT["failure"]["resolver_unavailable"]

    for variant in CONTRACT["variants"]:
        response = client.get(variant["path"])
        assert response.status_code == expected["status_code"], variant["operation"]
        assert response.json() == expected["body"], variant["operation"]
