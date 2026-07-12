from __future__ import annotations

import base64
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from services.issuance.infrastructure.adapters.emrtd_signer_client import signer_capabilities
from services.issuance.infrastructure.adapters.personalization_bureau_client import ProductionStatus
from services.issuance.infrastructure.api.physical_document_routes import (
    PassportApplicationRequest,
    _production_status,
    _safe_response,
)


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
    now = datetime.now(timezone.utc)
    response = _safe_response({
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
    })

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
def test_bureau_status_maps_to_mip_lifecycle(bureau_status: ProductionStatus, job_status: str) -> None:
    assert _production_status(bureau_status) == job_status
