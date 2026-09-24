from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException
from pydantic import ValidationError

from services.issuance.infrastructure.adapters.emrtd_signer_client import signer_capabilities
from services.issuance.infrastructure.adapters.personalization_bureau_client import ProductionStatus
from services.issuance.infrastructure.api import physical_document_routes as routes
from services.issuance.infrastructure.api.physical_document_routes import (
    PassportApplicationRequest,
    _production_status,
    _safe_response,
)

REFERENCE = (
    Path(__file__).resolve().parents[2] / "contracts/physical-passport-python-route-reference.json"
)


def _reference() -> dict:
    return json.loads(REFERENCE.read_text(encoding="utf-8"))


def _job() -> dict:
    now = datetime(2026, 7, 11, tzinfo=UTC)
    return {
        "id": "job-1",
        "organization_id": "org-1",
        "flow_execution_id": "flow-1",
        "application_id": "application-1",
        "application_template_id": "template-1",
        "credential_template_id": "credential-1",
        "delivery_destination_profile_id": "bureau-1",
        "document_type": "TD3",
        "country_code": "USA",
        "secure_artifact_reference": "physical-artifact://job-1",
        "secure_artifact_ciphertext": "synthetic-encrypted-artifact",
        "sod_sha256": None,
        "bureau_job_id": None,
        "tracking_number": None,
        "status": "DRAFT",
        "quality_result": None,
        "error_code": None,
        "error_message": None,
        "submitted_at": None,
        "completed_at": None,
        "created_at": now,
        "updated_at": now,
    }


def test_passport_reference_pins_exact_source_and_all_routes() -> None:
    reference = _reference()
    assert reference["schema"] == "elevenid.physical-passport-python-route-reference/v1"
    assert reference["source_hash_encoding"] == "utf8-lf"
    assert reference["qualification"] == "route-boundary-only; no native cutover or Python deletion"
    assert len(reference["remaining_oracles"]) == 3
    root = Path(__file__).resolve().parents[2]
    assert set(reference["sources"]) == {
        "services/issuance/infrastructure/api/physical_document_routes.py",
        "services/issuance/infrastructure/adapters/emrtd_signer_client.py",
        "services/issuance/infrastructure/adapters/personalization_bureau_client.py",
    }
    for relative_path, digest in reference["sources"].items():
        source = (root / relative_path).read_bytes()
        assert b"\r" not in source.replace(b"\r\n", b"")
        assert hashlib.sha256(source.replace(b"\r\n", b"\n")).hexdigest() == digest
    actual = {
        (method, route.path)
        for route in routes.physical_document_router.routes
        for method in route.methods
        if method in {"GET", "POST"}
    }
    expected = {(item["method"], item["path"]) for item in reference["operations"]}
    assert actual == expected
    assert len(expected) == 9


def test_passport_reference_keeps_durable_and_tenant_gates_explicit() -> None:
    reference = _reference()
    durable = reference["durable_repository_reference"]
    assert durable["oracle"] == "tests/test_physical_passport_repository_postgres.py"
    assert "PostgreSQL" in durable["database"]
    assert "new engine and session" in durable["restart"]
    assert "Fernet-encrypted" in durable["artifact"]
    assert durable["lifecycle"] == [
        "DRAFT",
        "DATA_GENERATED",
        "SOD_SIGNED",
        "QUALITY_CHECK",
        "READY_FOR_ACTIVATION",
        "ACTIVE",
    ]
    assert "encrypted empty object" in durable["activation"]
    assert "signed SHIPPED event" in durable["webhook"]
    assert "not live provider transport or tenant authorization" in durable["qualification"]
    assert (Path(__file__).resolve().parents[2] / durable["oracle"]).is_file()

    boundary = reference["tenant_boundary_observation"]
    assert not routes.physical_document_router.dependencies
    assert all(not route.dependencies for route in routes.physical_document_router.routes)
    assert "no route-level API-key" in boundary["router"]
    assert "X-API-Key" in boundary["flow_consumer"]
    assert "before native cutover or Python deletion" in boundary["unresolved_gate"]


@pytest.mark.asyncio
async def test_passport_capability_blockers_preserve_order_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PHYSICAL_DOCUMENT_ARTIFACT_KEY", raising=False)
    monkeypatch.setattr(
        routes,
        "signer_capabilities",
        lambda: {"configured": False, "mode": "UNAVAILABLE", "blockers": ["Signer unavailable"]},
    )
    monkeypatch.setattr(routes, "is_bureau_configured", lambda: False)
    blocked = await routes.get_physical_document_capabilities()
    assert blocked == {
        "supported": False,
        "signer": {"configured": False, "mode": "UNAVAILABLE", "blockers": ["Signer unavailable"]},
        "bureau_configured": False,
        "encrypted_artifact_store": False,
        "blockers": [
            "Signer unavailable",
            "Configure PHYSICAL_DOCUMENT_ARTIFACT_KEY for encrypted sensitive artifacts.",
            "Configure PERSONALIZATION_BUREAU_URL for production handoff.",
        ],
    }
    monkeypatch.setenv("PHYSICAL_DOCUMENT_ARTIFACT_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(
        routes,
        "signer_capabilities",
        lambda: {"configured": True, "mode": "EXTERNAL", "blockers": []},
    )
    monkeypatch.setattr(routes, "is_bureau_configured", lambda: True)
    ready = await routes.get_physical_document_capabilities()
    assert ready["supported"] is True
    assert ready["bureau_configured"] is True
    assert ready["encrypted_artifact_store"] is True
    assert ready["blockers"] == []


@pytest.mark.parametrize("invalid_key", ["synthetic-invalid-key", "⚠"])
@pytest.mark.asyncio
async def test_passport_capabilities_reject_invalid_artifact_key(
    monkeypatch: pytest.MonkeyPatch, invalid_key: str
) -> None:
    monkeypatch.setenv("PHYSICAL_DOCUMENT_ARTIFACT_KEY", invalid_key)
    monkeypatch.setattr(
        routes,
        "signer_capabilities",
        lambda: {"configured": True, "mode": "EXTERNAL", "blockers": []},
    )
    monkeypatch.setattr(routes, "is_bureau_configured", lambda: True)
    result = await routes.get_physical_document_capabilities()
    assert result["supported"] is False
    assert result["encrypted_artifact_store"] is False
    assert result["blockers"] == [
        "PHYSICAL_DOCUMENT_ARTIFACT_KEY is invalid for encrypted sensitive artifacts."
    ]
    with pytest.raises(HTTPException) as rejected:
        routes._fernet()
    assert rejected.value.status_code == 503


@pytest.mark.asyncio
async def test_passport_create_encrypts_artifact_and_returns_only_safe_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = Fernet.generate_key()
    monkeypatch.setenv("PHYSICAL_DOCUMENT_ARTIFACT_KEY", key.decode())
    inserted = {}
    commits = []

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def execute(self, statement):
            inserted.update(statement.compile().params)

        async def commit(self):
            commits.append(True)

    monkeypatch.setattr(routes, "_factory", lambda: lambda: Session())
    payload = PassportApplicationRequest(
        organization_id="org-1",
        flow_execution_id="flow-1",
        application_template_id="template-1",
        credential_template_id="credential-1",
        delivery_destination_profile_id="bureau-1",
        country_code="USA",
        applicant={"name": "Synthetic Applicant"},
        mrz={"line_1": "SYNTHETIC1", "line_2": "SYNTHETIC2"},
        data_groups={"DG1": "ZzE=", "DG2": "ZzI="},
    )
    response = await routes.create_passport_application(payload)
    assert commits == [True]
    assert response["status"] == _reference()["operations"][1]["outcome"]
    assert response["secure_artifact_reference"] == f"physical-artifact://{inserted['id']}"
    assert json.loads(Fernet(key).decrypt(inserted["secure_artifact_ciphertext"].encode())) == {
        "applicant": payload.applicant,
        "mrz": payload.mrz,
        "data_groups": payload.data_groups,
    }
    assert not {"secure_artifact_ciphertext", "applicant", "mrz", "data_groups"} & response.keys()


@pytest.mark.asyncio
async def test_passport_route_lifecycle_preserves_effects_and_scrubs_artifact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _job()
    updates = []
    signing = []
    submissions = []
    polls = []
    artifact = {
        "mrz": {"line_1": "SYNTHETIC1", "line_2": "SYNTHETIC2"},
        "data_groups": {"DG1": "ZzE=", "DG2": "ZzI="},
    }
    key = Fernet.generate_key()
    monkeypatch.setenv("PHYSICAL_DOCUMENT_ARTIFACT_KEY", key.decode())

    async def get_job(application_id):
        assert application_id == "application-1"
        return dict(row)

    async def update_job(application_id, **values):
        assert application_id == "application-1"
        updates.append(dict(values))
        row.update(values)
        return dict(row)

    async def sign(**values):
        signing.append(values)
        return {"sod_der_base64": "U09E", "dsc_cert_pem": "synthetic-cert"}

    async def submit(job):
        submissions.append(job)
        return SimpleNamespace(
            status=ProductionStatus.QUEUED,
            bureau_job_id="bureau-job-1",
            tracking_number="track-1",
            error_message=None,
        )

    async def poll(bureau_job_id):
        polls.append(bureau_job_id)
        return {"status": "ENCODING", "tracking_number": "track-2"}

    monkeypatch.setattr(routes, "_get_job", get_job)
    monkeypatch.setattr(routes, "_update_job", update_job)
    monkeypatch.setattr(routes, "_decrypt_artifact", lambda _row: artifact)
    monkeypatch.setattr(routes, "sign_emrtd", sign)
    monkeypatch.setattr(routes, "submit_personalization_job", submit)
    monkeypatch.setattr(routes, "poll_job_status", poll)

    reference = _reference()["operations"]
    assert (await routes.generate_passport_data_groups("application-1"))["status"] == reference[2][
        "outcome"
    ]
    sod = await routes.generate_passport_sod("application-1")
    assert sod["status"] == reference[3]["outcome"]
    assert sod["sod_sha256"] == hashlib.sha256(b"SOD").hexdigest()
    assert len(signing) == 1 and signing[0]["data_groups"] == {1: "ZzE=", 2: "ZzI="}

    submitted = await routes.submit_passport_personalization("application-1")
    assert submitted["status"] == reference[4]["outcome"]
    assert len(signing) == 2 and len(submissions) == 1
    assert submissions[0].mrz_line_1 == "SYNTHETIC1"
    assert submissions[0].data_groups == {1: "ZzE=", 2: "ZzI="}
    assert updates[-1]["bureau_job_id"] == "bureau-job-1"
    assert isinstance(updates[-1]["submitted_at"], datetime)

    production = await routes.get_passport_production_status("application-1")
    assert production["status"] == reference[5]["outcome"]
    assert production["tracking_number"] == "track-2"
    assert polls == ["bureau-job-1"]

    with pytest.raises(HTTPException) as early_quality:
        await routes.record_passport_quality_result(
            "application-1", routes.QualityResultRequest(passed=True)
        )
    assert early_quality.value.status_code == 409
    assert (
        early_quality.value.detail
        == _reference()["negative_observations"]["quality_before_bureau_ready"]["detail"]
    )

    row["status"] = "QUALITY_CHECK"
    quality = await routes.record_passport_quality_result(
        "application-1", routes.QualityResultRequest(passed=True), x_user_id="reviewer-1"
    )
    assert quality["status"] == reference[6]["outcome"]
    assert quality["quality_result"]["checked_by"] == "reviewer-1"
    assert quality["quality_result"]["failure_codes"] == []

    activated = await routes.activate_passport("application-1")
    assert activated["status"] == reference[7]["outcome"]
    assert isinstance(activated["completed_at"], datetime)
    assert Fernet(key).decrypt(row["secure_artifact_ciphertext"].encode()) == b"{}"
    assert not {"secure_artifact_ciphertext", "applicant", "mrz", "data_groups"} & activated.keys()


@pytest.mark.asyncio
async def test_passport_activation_denial_does_not_update_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _job()
    row["status"] = "READY_FOR_ACTIVATION"
    updates = []

    async def get_job(_application_id):
        return row

    async def update_job(*_args, **values):
        updates.append(values)
        return row

    monkeypatch.setattr(routes, "_get_job", get_job)
    monkeypatch.setattr(routes, "_update_job", update_job)
    with pytest.raises(HTTPException) as denied:
        await routes.activate_passport("application-1")
    assert denied.value.status_code == 409
    assert (
        denied.value.detail
        == _reference()["negative_observations"]["activation_without_passing_quality"]["detail"]
    )
    assert updates == []


@pytest.mark.asyncio
async def test_passport_invalid_groups_and_signer_failure_are_effect_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _job()
    updates = []
    bureau_calls = []

    async def get_job(_application_id):
        return row

    async def update_job(*_args, **values):
        updates.append(values)
        return row

    async def failed_sign(**_values):
        raise HTTPException(status_code=503, detail="Signer unavailable")

    async def bureau_call(_job):
        bureau_calls.append(True)

    monkeypatch.setattr(routes, "_get_job", get_job)
    monkeypatch.setattr(routes, "_update_job", update_job)
    monkeypatch.setattr(
        routes, "_decrypt_artifact", lambda _row: {"mrz": {}, "data_groups": {"DG1": "ZzE="}}
    )
    monkeypatch.setattr(routes, "sign_emrtd", failed_sign)
    monkeypatch.setattr(routes, "submit_personalization_job", bureau_call)
    with pytest.raises(HTTPException) as missing_group:
        await routes.generate_passport_data_groups("application-1")
    assert missing_group.value.status_code == 422
    assert updates == []

    monkeypatch.setattr(
        routes,
        "_decrypt_artifact",
        lambda _row: {"mrz": {}, "data_groups": {"DG1": "ZzE=", "DG2": "ZzI="}},
    )
    with pytest.raises(HTTPException) as unavailable:
        await routes.submit_passport_personalization("application-1")
    assert unavailable.value.status_code == 503
    assert updates == [] and bureau_calls == []


@pytest.mark.asyncio
async def test_passport_failed_quality_and_terminal_status_skip_bureau_poll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _job()
    row.update(status="READY_FOR_ACTIVATION", bureau_job_id="bureau-job-1")
    updates = []
    polls = []

    async def get_job(_application_id):
        return dict(row)

    async def update_job(_application_id, **values):
        updates.append(values)
        row.update(values)
        return dict(row)

    async def poll(_bureau_job_id):
        polls.append(True)
        return {"status": "DELIVERED"}

    monkeypatch.setattr(routes, "_get_job", get_job)
    monkeypatch.setattr(routes, "_update_job", update_job)
    monkeypatch.setattr(routes, "poll_job_status", poll)
    failed = await routes.record_passport_quality_result(
        "application-1",
        routes.QualityResultRequest(passed=False, failure_codes=["IMAGE_BLUR"]),
        x_user_id="reviewer-1",
    )
    assert failed["status"] == "FAILED"
    assert failed["quality_result"]["failure_codes"] == ["IMAGE_BLUR"]
    assert failed["error_code"] == "QUALITY_CHECK_FAILED"
    terminal = await routes.get_passport_production_status("application-1")
    assert terminal["status"] == "FAILED"
    assert polls == [] and len(updates) == 1


@pytest.mark.asyncio
async def test_passport_webhook_rejects_untrusted_and_unknown_events_before_update(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b'{"synthetic":"event"}'
    updates = []
    lookups = []
    verified = []
    result_application_id = None

    class Request:
        async def body(self):
            return body

    class Result:
        def scalar_one_or_none(self):
            return result_application_id

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def execute(self, statement):
            lookups.append(statement)
            return Result()

    def verify(raw, signature):
        verified.append((raw, signature))
        return signature == "valid-signature"

    async def update_job(application_id, **values):
        updates.append((application_id, values))
        return _job()

    monkeypatch.setattr(routes, "verify_webhook_signature", verify)
    monkeypatch.setattr(
        routes,
        "parse_webhook_event",
        lambda _payload: (
            "bureau-job-1",
            ProductionStatus.FAILED,
            {"tracking_number": "track-3", "error_message": "synthetic failure"},
        ),
    )
    monkeypatch.setattr(routes, "_factory", lambda: lambda: Session())
    monkeypatch.setattr(routes, "_update_job", update_job)

    negative = _reference()["negative_observations"]
    with pytest.raises(HTTPException) as bad_signature:
        await routes.personalization_webhook(Request(), "wrong-signature")
    assert bad_signature.value.status_code == negative["invalid_webhook_signature"]["status"]
    assert bad_signature.value.detail == negative["invalid_webhook_signature"]["detail"]
    assert lookups == [] and updates == []

    with pytest.raises(HTTPException) as unknown_job:
        await routes.personalization_webhook(Request(), "valid-signature")
    assert unknown_job.value.status_code == negative["unknown_webhook_job"]["status"]
    assert unknown_job.value.detail == negative["unknown_webhook_job"]["detail"]
    assert len(lookups) == 1 and updates == []

    result_application_id = "application-1"
    assert await routes.personalization_webhook(Request(), "valid-signature") == {"accepted": True}
    assert verified == [
        (body, "wrong-signature"),
        (body, "valid-signature"),
        (body, "valid-signature"),
    ]
    assert updates == [
        (
            "application-1",
            {
                "status": "FAILED",
                "tracking_number": "track-3",
                "error_message": "synthetic failure",
            },
        )
    ]


def test_signer_capabilities_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ICAO_DOCUMENT_SIGNER_URL", raising=False)
    monkeypatch.delenv("PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED", raising=False)

    result = signer_capabilities()

    assert result["configured"] is False
    assert result["mode"] == "UNAVAILABLE"
    assert result["blockers"]


def test_passport_application_requires_dg1_and_dg2() -> None:
    with pytest.raises(ValidationError, match="DG1 and DG2 are required"):
        PassportApplicationRequest(
            organization_id="org-1",
            flow_execution_id="flow-execution-1",
            application_template_id="application-template-1",
            credential_template_id="credential-template-1",
            delivery_destination_profile_id="bureau-1",
            country_code="USA",
            applicant={"name": "Example"},
            mrz={"line_1": "one", "line_2": "two"},
            data_groups={"DG1": base64.b64encode(b"dg1").decode()},
        )


def test_physical_document_response_never_exposes_sensitive_artifacts() -> None:
    now = datetime.now(UTC)
    response = _safe_response(
        {
            "id": "job-1",
            "organization_id": "org-1",
            "flow_execution_id": "flow-1",
            "application_id": "application-1",
            "credential_template_id": "credential-1",
            "delivery_destination_profile_id": "bureau-1",
            "document_type": "TD3",
            "country_code": "USA",
            "secure_artifact_reference": "physical-artifact://job-1",
            "secure_artifact_ciphertext": "encrypted-applicant-biometric-dgs",
            "sod_sha256": "hash",
            "bureau_job_id": None,
            "tracking_number": None,
            "status": "DRAFT",
            "quality_result": None,
            "error_code": None,
            "error_message": None,
            "submitted_at": None,
            "completed_at": None,
            "created_at": now,
            "updated_at": now,
        }
    )

    assert response["secure_artifact_reference"] == "physical-artifact://job-1"
    assert "secure_artifact_ciphertext" not in response
    assert "sod_sha256" not in response
    assert "data_groups" not in response
    assert "applicant" not in response


@pytest.mark.parametrize(
    ("bureau_status", "job_status"),
    [
        (ProductionStatus.QUEUED, "SUBMITTED"),
        (ProductionStatus.ENCODING, "IN_PRODUCTION"),
        (ProductionStatus.QUALITY_CHECK, "QUALITY_CHECK"),
        (ProductionStatus.DELIVERED, "READY_FOR_ACTIVATION"),
        (ProductionStatus.FAILED, "FAILED"),
    ],
)
def test_bureau_status_maps_to_mip_lifecycle(
    bureau_status: ProductionStatus, job_status: str
) -> None:
    assert _production_status(bureau_status) == job_status
