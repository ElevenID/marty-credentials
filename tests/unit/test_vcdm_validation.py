"""Production-boundary tests for W3C VCDM v2 credential input."""

from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi import HTTPException
from issuance.domain.vcdm_validation import (
    BASE_CONTEXT,
    VcdmValidationError,
    validate_credential_document,
    validate_related_resource_digests,
)


def _credential() -> dict:
    return {
        "@context": [
            BASE_CONTEXT,
            {"ExampleCredential": "https://issuer.example.test/ExampleCredential"},
        ],
        "type": ["VerifiableCredential", "ExampleCredential"],
        "issuer": "did:web:issuer.example.test",
        "credentialSubject": {"id": "did:example:subject", "name": "Ada"},
    }


def _official_baseline() -> dict:
    return {
        "@context": [BASE_CONTEXT],
        "type": ["VerifiableCredential"],
        "credentialSubject": {"id": "did:example:subject"},
    }


def test_accepts_complete_document_and_issuer_injection_baseline() -> None:
    validate_credential_document(
        _credential(),
        issuer_did="did:web:issuer.example.test",
    )
    validate_credential_document(
        _official_baseline(),
        issuer_did="did:web:issuer.example.test",
    )


def test_accepts_multiple_subjects_object_issuer_and_known_context_term() -> None:
    credential = _official_baseline()
    credential["@context"].append("https://www.w3.org/ns/credentials/examples/v2")
    credential["type"].append("RelationshipCredential")
    credential["issuer"] = {
        "id": "did:web:issuer.example.test",
        "name": {"@value": "Issuer", "@language": "en"},
    }
    credential["credentialSubject"] = [
        {"id": "did:example:subject"},
        {"id": "did:example:other"},
    ]
    credential["name"] = [
        {"@value": "Dog", "@language": "en"},
        {"@value": "Chien", "@language": "fr"},
    ]

    validate_credential_document(
        credential,
        issuer_did="did:web:issuer.example.test",
    )


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        (lambda value: value.update({"@context": BASE_CONTEXT}), "invalid_context"),
        (lambda value: value.update({"credentialSubject": []}), "invalid_subject"),
        (lambda value: value.update({"id": None}), "invalid_id"),
        (
            lambda value: value.update({"credentialStatus": {"id": "did:example:status"}}),
            "invalid_type",
        ),
        (
            lambda value: value.update({"credentialSchema": {"type": "JsonSchema"}}),
            "invalid_type",
        ),
        (lambda value: value.update({"name": {"@value": 4}}), "invalid_language_value"),
        (lambda value: value.update({"validFrom": "not-a-date"}), "invalid_validity"),
        (
            lambda value: value.update({"relatedResource": {"id": "https://resource.example"}}),
            "invalid_related_resource",
        ),
        (
            lambda value: value.update(
                {
                    "validFrom": "2030-01-01T00:00:00Z",
                    "validUntil": "2020-01-01T00:00:00Z",
                }
            ),
            "invalid_validity",
        ),
        (
            lambda value: value["@context"].append(
                {"VerifiableCredential": "https://example.test/bad"}
            ),
            "invalid_context",
        ),
        (lambda value: value.update({"proof": {}}), "credential_must_be_unsigned"),
    ],
)
def test_rejects_malformed_documents(mutation, expected_code: str) -> None:
    credential = _credential()
    mutation(credential)

    with pytest.raises(VcdmValidationError) as exc_info:
        validate_credential_document(
            credential,
            issuer_did="did:web:issuer.example.test",
        )

    assert exc_info.value.code == expected_code


def test_rejects_issuer_that_does_not_match_did_first_resolution_input() -> None:
    with pytest.raises(VcdmValidationError) as exc_info:
        validate_credential_document(
            _credential(),
            issuer_did="did:web:other.example.test",
        )

    assert exc_info.value.code == "issuer_did_mismatch"


@pytest.mark.asyncio
async def test_related_resource_digest_validation_uses_real_bytes() -> None:
    content = b"official context bytes"
    digest = base64.b64encode(hashlib.sha384(content).digest()).decode("ascii")
    credential = _official_baseline()
    credential["relatedResource"] = {
        "id": BASE_CONTEXT,
        "digestSRI": f"sha384-{digest}",
    }
    requested: list[str] = []

    async def fetch_resource(resource_id: str) -> bytes:
        requested.append(resource_id)
        return content

    validate_credential_document(credential)
    await validate_related_resource_digests(
        credential,
        fetch_resource=fetch_resource,
    )
    assert requested == [BASE_CONTEXT]

    credential["relatedResource"]["digestSRI"] = "sha384-wrong"
    with pytest.raises(VcdmValidationError) as exc_info:
        await validate_related_resource_digests(
            credential,
            fetch_resource=fetch_resource,
        )
    assert exc_info.value.code == "related_resource_digest_mismatch"


@pytest.mark.asyncio
async def test_production_resource_policy_requires_an_exact_https_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from issuance.infrastructure.api import routes

    content = b"official context bytes"
    digest = base64.b64encode(hashlib.sha256(content).digest()).decode("ascii")
    credential = _official_baseline()
    credential["relatedResource"] = {
        "id": BASE_CONTEXT,
        "digestSRI": f"sha256-{digest}",
    }

    monkeypatch.delenv("VCDM_RELATED_RESOURCE_URLS", raising=False)
    with pytest.raises(HTTPException) as exc_info:
        await routes._validate_vcdm_related_resources(credential)
    assert exc_info.value.detail["error"] == "related_resource_validation_not_configured"

    client_options: dict = {}

    class Response:
        status_code = 200

        def __init__(self, body: bytes) -> None:
            self.content = body

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, resource_id: str):
            assert resource_id == BASE_CONTEXT
            return Response(content)

    def create_client(**kwargs):
        client_options.update(kwargs)
        return Client()

    monkeypatch.setenv("VCDM_RELATED_RESOURCE_URLS", BASE_CONTEXT)
    monkeypatch.setattr(routes.httpx, "AsyncClient", create_client)
    await routes._validate_vcdm_related_resources(credential)

    assert client_options["follow_redirects"] is False
    assert client_options["timeout"] == 10.0
