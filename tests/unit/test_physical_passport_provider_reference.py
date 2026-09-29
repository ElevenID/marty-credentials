"""Language-neutral remote-provider reference before the physical-passport Rust port."""

from __future__ import annotations

import hashlib
import hmac
import json
from copy import deepcopy
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException

from services.issuance.infrastructure.adapters import (
    emrtd_signer_client as signer,
)
from services.issuance.infrastructure.adapters import (
    personalization_bureau_client as bureau,
)

ROOT = Path(__file__).resolve().parents[2]
DELTA = json.loads(
    (ROOT / "contracts/physical-passport-provider-reference-v2.json").read_text(encoding="utf-8")
)
ROLLBACK_DELTA_PATH = ROOT / "contracts/physical-passport-provider-reference-v3.json"
ROLLBACK_DELTA = json.loads(ROLLBACK_DELTA_PATH.read_text(encoding="utf-8"))
FROZEN_V1 = json.loads(
    (ROOT / "contracts/physical-passport-provider-reference.json").read_text(encoding="utf-8")
)
REFERENCE = deepcopy(FROZEN_V1)
REFERENCE["schema"] = DELTA["schema"]
REFERENCE["python_source_sha256"].update(DELTA["python_source_sha256"])
REFERENCE["python_source_sha256"].update(ROLLBACK_DELTA["python_source_sha256"])
REFERENCE["signer"]["request"]["issuer_did"] = DELTA["issuer_did"]
REFERENCE["signer"]["http"]["json"]["issuer_did"] = DELTA["issuer_did"]


def _client_with(handler, clients: list[httpx.AsyncClient]):
    original = httpx.AsyncClient

    def make_client(*, timeout):
        client = original(transport=httpx.MockTransport(handler), timeout=timeout)
        clients.append(client)
        return client

    return make_client


def _job() -> bureau.PersonalizationJob:
    values = dict(REFERENCE["bureau"]["job"])
    values["data_groups"] = {int(number): value for number, value in values["data_groups"].items()}
    return bureau.PersonalizationJob(**values)


def test_provider_reference_pins_reviewed_python_sources() -> None:
    assert REFERENCE["schema"] == "elevenid.physical-passport-provider-reference/v2"
    assert FROZEN_V1["schema"] == "elevenid.physical-passport-provider-reference/v1"
    assert DELTA["base"] == "contracts/physical-passport-provider-reference.json"
    base_source = (ROOT / DELTA["base"]).read_bytes().replace(b"\r\n", b"\n")
    assert DELTA["base_sha256"] == hashlib.sha256(base_source).hexdigest()
    assert ROLLBACK_DELTA["base"] == "contracts/physical-passport-provider-reference-v2.json"
    assert ROLLBACK_DELTA["base_sha256"] == hashlib.sha256(
        (ROOT / ROLLBACK_DELTA["base"]).read_bytes().replace(b"\r\n", b"\n")
    ).hexdigest()
    assert set(REFERENCE["python_source_sha256"]) == {
        "services/issuance/infrastructure/adapters/emrtd_signer_client.py",
        "services/issuance/infrastructure/adapters/personalization_bureau_client.py",
    }
    for source, expected in REFERENCE["python_source_sha256"].items():
        actual = hashlib.sha256((ROOT / source).read_text(encoding="utf-8").encode()).hexdigest()
        assert actual == expected


@pytest.mark.parametrize("scenario", REFERENCE["signer"]["capabilities"])
def test_signer_mode_is_explicit_and_remote_takes_precedence(
    monkeypatch: pytest.MonkeyPatch, scenario: dict[str, object]
) -> None:
    monkeypatch.setenv("ICAO_DOCUMENT_SIGNER_URL", scenario["url"])
    monkeypatch.setenv("PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED", scenario["allow_self_signed"])
    assert signer.signer_capabilities() == scenario["expected"]


@pytest.mark.asyncio
async def test_remote_signer_request_success_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = REFERENCE["signer"]["http"]
    observed: list[httpx.Request] = []
    clients: list[httpx.AsyncClient] = []
    response: dict[str, object] = {"status": 200, "body": REFERENCE["signer"]["success"]}

    def handle(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(response["status"], json=response["body"])

    monkeypatch.setenv("ICAO_DOCUMENT_SIGNER_URL", "https://synthetic-signer.invalid/")
    monkeypatch.setenv("ICAO_DOCUMENT_SIGNER_API_KEY", "synthetic-signer-key")
    monkeypatch.setattr(httpx, "AsyncClient", _client_with(handle, clients))
    request = REFERENCE["signer"]["request"]
    args = {
        **{key: value for key, value in request.items() if key != "data_groups"},
        "data_groups": {int(key): value for key, value in request["data_groups"].items()},
    }

    assert await signer.sign_emrtd(**args) == REFERENCE["signer"]["success"]
    assert observed[-1].method == expected["method"]
    assert observed[-1].url.path == expected["path"]
    assert observed[-1].headers["authorization"] == expected["authorization"]
    assert json.loads(observed[-1].content) == expected["json"]
    assert clients[-1].timeout.read == expected["timeout_seconds"]

    legacy_args = {key: value for key, value in args.items() if key != "issuer_did"}
    assert await signer.sign_emrtd(**legacy_args) == REFERENCE["signer"]["success"]
    assert json.loads(observed[-1].content) == FROZEN_V1["signer"]["http"]["json"]

    response["body"] = {"sod_der_base64": "U09E"}
    with pytest.raises(RuntimeError, match=REFERENCE["signer"]["incomplete_error"]):
        await signer.sign_emrtd(**args)
    response["status"] = 503
    with pytest.raises(httpx.HTTPStatusError):
        await signer.sign_emrtd(**args)


@pytest.mark.asyncio
async def test_managed_issuer_did_cannot_use_self_signed_test_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ICAO_DOCUMENT_SIGNER_URL", raising=False)
    monkeypatch.setenv("PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED", "true")
    with pytest.raises(RuntimeError, match="profile-backed document signer"):
        await signer.sign_emrtd(
            country_code="USA", organization="org-reference",
            issuer_did="did:web:issuer.example:orgs:org-reference",
            data_groups={1: "ZzE="},
        )


@pytest.mark.asyncio
async def test_managed_issuer_did_is_bound_to_active_organization_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    key_file = tmp_path / "signing_keys_internal_api_key"
    key_file.write_text("k" * 32, encoding="ascii")
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_URL", "http://signing-keys:8017/internal")
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY_FILE", str(key_file))
    did = "did:web:issuer.example:orgs:org-reference"
    observed: list[httpx.Request] = []
    resolved = {
        "organization_id": "org-reference",
        "issuer_did": did,
        "key_purpose": "x509_doc_signer",
        "issuer_profile": {"credential_format": "ICAO_EMRTD"},
    }

    def handle(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(200, json=resolved)

    original = httpx.AsyncClient

    def client(*, timeout: float, follow_redirects: bool) -> httpx.AsyncClient:
        return original(
            transport=httpx.MockTransport(handle),
            timeout=timeout,
            follow_redirects=follow_redirects,
        )

    monkeypatch.setattr(httpx, "AsyncClient", client)
    await signer.require_managed_issuer_identity("org-reference", did)
    assert observed[-1].method == "POST"
    assert observed[-1].url.path == "/internal/compat/resolve-issuer-did"
    assert observed[-1].url.query == b""
    assert json.loads(observed[-1].content) == {
        "organization_id": "org-reference",
        "issuer_did": did,
        "credential_format": "ICAO_EMRTD",
        "key_purpose": "x509_doc_signer",
        "algorithm": "",
    }
    assert observed[-1].headers["x-api-key"] == "k" * 32
    resolved["organization_id"] = "foreign-organization"
    with pytest.raises(HTTPException) as foreign:
        await signer.require_managed_issuer_identity("org-reference", did)
    assert foreign.value.status_code == 422
    resolved["organization_id"] = "org-reference"
    resolved["issuer_did"] = "did:web:foreign.example"
    with pytest.raises(HTTPException) as wrong_did:
        await signer.require_managed_issuer_identity("org-reference", did)
    assert wrong_did.value.status_code == 422
    monkeypatch.delenv("SIGNING_KEYS_INTERNAL_API_KEY_FILE")
    with pytest.raises(HTTPException) as unavailable:
        await signer.require_managed_issuer_identity("org-reference", did)
    assert unavailable.value.status_code == 503


@pytest.mark.asyncio
async def test_bureau_submit_and_poll_preserve_wire_contract(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    expected = REFERENCE["bureau"]
    observed: list[httpx.Request] = []
    clients: list[httpx.AsyncClient] = []
    response: dict[str, object] = {
        "status": expected["accepted"]["http_status"],
        "body": expected["accepted"]["response"],
    }

    def handle(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(response["status"], json=response["body"])

    monkeypatch.setattr(bureau, "BUREAU_URL", "https://synthetic-bureau.invalid")
    monkeypatch.setattr(bureau, "BUREAU_API_KEY", "synthetic-bureau-key")
    monkeypatch.setattr(httpx, "AsyncClient", _client_with(handle, clients))

    submitted = await bureau.submit_personalization_job(_job())
    wire = expected["submit_http"]
    assert observed[-1].method == wire["method"]
    assert observed[-1].url.path == wire["path"]
    assert observed[-1].headers["authorization"] == wire["authorization"]
    assert json.loads(observed[-1].content) == wire["json"]
    assert clients[-1].timeout.read == wire["timeout_seconds"]
    assert submitted.bureau_job_id == expected["accepted"]["response"]["bureau_job_id"]
    assert submitted.status.value == expected["accepted"]["job_status"]
    assert submitted.tracking_number == expected["accepted"]["response"]["tracking_number"]

    for document_type in ("TD1", "TD2"):
        job = _job()
        job.document_type = document_type
        await bureau.submit_personalization_job(job)
        assert json.loads(observed[-1].content)["document_type"] == document_type

    response["status"] = expected["rejected"]["http_status"]
    response["body"] = {"error": "synthetic-private-applicant"}
    rejected = await bureau.submit_personalization_job(_job())
    assert rejected.status.value == expected["rejected"]["job_status"]
    assert rejected.error_message == expected["rejected"]["error_message"]
    assert rejected.bureau_job_id is None
    assert "synthetic-private-applicant" not in caplog.text

    response["status"] = 200
    response["body"] = expected["poll_http"]["response"]
    assert await bureau.poll_job_status("bureau-reference") == expected["poll_http"]["response"]
    poll = expected["poll_http"]
    assert observed[-1].method == poll["method"]
    assert observed[-1].url.path == poll["path"]
    assert observed[-1].headers["authorization"] == poll["authorization"]
    assert clients[-1].timeout.read == poll["timeout_seconds"]


@pytest.mark.asyncio
async def test_bureau_batch_preserves_envelope_and_out_of_order_job_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wire = REFERENCE["bureau"]["batch_http"]
    observed: list[httpx.Request] = []
    clients: list[httpx.AsyncClient] = []
    response: dict[str, object] = {"status": 202, "body": wire["response"]}

    def handle(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(response["status"], json=response["body"])

    monkeypatch.setattr(bureau, "BUREAU_URL", "https://synthetic-bureau.invalid")
    monkeypatch.setattr(bureau, "BUREAU_API_KEY", "synthetic-bureau-key")
    monkeypatch.setattr(httpx, "AsyncClient", _client_with(handle, clients))
    second = _job()
    second.id = "job-second"
    second.application_id = "app-second"
    second.country_code = "GBR"
    second.data_groups = {3: "Aw=="}
    batch = bureau.PersonalizationBatch(
        id="batch-reference",
        organization_id="org-reference",
        jobs=[_job(), second],
    )

    result = await bureau.submit_personalization_batch(batch)
    assert observed[-1].method == wire["method"]
    assert observed[-1].url.path == wire["path"]
    assert observed[-1].headers["authorization"] == wire["authorization"]
    assert json.loads(observed[-1].content) == wire["json"]
    assert clients[-1].timeout.read == wire["timeout_seconds"]
    assert result.status.value == wire["response"]["status"]
    assert [(job.id, job.bureau_job_id, job.status.value) for job in result.jobs] == [
        ("job-reference", "bureau-reference", "QUEUED"),
        ("job-second", "bureau-second", "PRINTING"),
    ]

    response["status"] = 503
    response["body"] = {"error": "synthetic-only"}
    failed = await bureau.submit_personalization_batch(batch)
    assert failed.status.value == wire["failure_status"]


def test_bureau_api_key_file_is_supported_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    key_file = tmp_path / "bureau-key"
    key_file.write_text("synthetic-bureau-key\n", encoding="ascii")
    monkeypatch.setattr(bureau, "BUREAU_API_KEY", "")
    monkeypatch.setenv("PERSONALIZATION_BUREAU_API_KEY_FILE", str(key_file))
    monkeypatch.setattr(bureau, "BUREAU_URL", "https://synthetic-bureau.invalid")
    assert bureau._bureau_api_key() == "synthetic-bureau-key"
    assert bureau.is_bureau_configured()

    monkeypatch.setattr(bureau, "BUREAU_API_KEY", "conflicting-key")
    with pytest.raises(RuntimeError, match="Conflicting"):
        bureau._bureau_api_key()
    assert not bureau.is_bureau_configured()
    monkeypatch.setattr(bureau, "BUREAU_API_KEY", "")

    key_file.unlink()
    with pytest.raises(RuntimeError, match="unavailable"):
        bureau._bureau_api_key()
    assert not bureau.is_bureau_configured()


def test_bureau_webhook_verification_and_event_projection(monkeypatch: pytest.MonkeyPatch) -> None:
    webhook = REFERENCE["webhook"]
    body = webhook["body"].encode()
    monkeypatch.setattr(bureau, "BUREAU_WEBHOOK_SECRET", webhook["secret"])
    signature = hmac.new(webhook["secret"].encode(), body, hashlib.sha256).hexdigest()
    assert bureau.verify_webhook_signature(body, signature)
    assert not bureau.verify_webhook_signature(body + b" ", signature)
    assert not bureau.verify_webhook_signature(body, "0" * len(signature))

    job_id, status, metadata = bureau.parse_webhook_event(json.loads(body))
    assert job_id == webhook["bureau_job_id"]
    assert status.value == webhook["status"]
    assert metadata == webhook["metadata"]

    monkeypatch.setattr(bureau, "BUREAU_WEBHOOK_SECRET", "")
    assert not bureau.verify_webhook_signature(body, signature)
