"""MIP 0.3.1 physical ICAO document production endpoints."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Annotated, Literal

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from issuance.infrastructure.adapters.emrtd_signer_client import sign_emrtd, signer_capabilities
from issuance.infrastructure.adapters.personalization_bureau_client import (
    PersonalizationJob,
    ProductionStatus,
    is_bureau_configured,
    parse_webhook_event,
    poll_job_status,
    submit_personalization_job,
    verify_webhook_signature,
)
from issuance.infrastructure.models import physical_document_jobs_table


physical_document_router = APIRouter(prefix="/v1/passport", tags=["physical-documents"])
_session_factory: async_sessionmaker[AsyncSession] | None = None


def configure_physical_document_store(factory: async_sessionmaker[AsyncSession] | None) -> None:
    global _session_factory
    _session_factory = factory


def _factory() -> async_sessionmaker[AsyncSession]:
    if _session_factory is None:
        raise HTTPException(status_code=503, detail="Physical document job store is unavailable")
    return _session_factory


def _fernet() -> Fernet:
    key = os.environ.get("PHYSICAL_DOCUMENT_ARTIFACT_KEY", "").strip()
    if not key:
        raise HTTPException(
            status_code=503,
            detail="PHYSICAL_DOCUMENT_ARTIFACT_KEY is required for encrypted document artifacts",
        )
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=503, detail="PHYSICAL_DOCUMENT_ARTIFACT_KEY is invalid") from exc


class PassportApplicationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str
    flow_execution_id: str
    application_template_id: str
    credential_template_id: str
    delivery_destination_profile_id: str = Field(max_length=128)
    document_type: Literal["TD1", "TD2", "TD3"] = "TD3"
    country_code: str = Field(pattern=r"^[A-Z]{3}$")
    applicant: dict[str, Any]
    mrz: dict[str, str]
    data_groups: dict[str, str]

    @field_validator("data_groups")
    @classmethod
    def validate_data_groups(cls, value: dict[str, str]) -> dict[str, str]:
        if not {"DG1", "DG2"}.issubset(value):
            raise ValueError("DG1 and DG2 are required")
        for name, content in value.items():
            if not name.startswith("DG") or not name[2:].isdigit():
                raise ValueError(f"Invalid data group name: {name}")
            base64.b64decode(content, validate=True)
        return value


class QualityResultRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passed: bool
    failure_codes: list[str] = Field(default_factory=list)


def _safe_response(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "organization_id": row["organization_id"],
        "flow_execution_id": row["flow_execution_id"],
        "application_id": row["application_id"],
        "credential_template_id": row["credential_template_id"],
        "delivery_destination_profile_id": row["delivery_destination_profile_id"],
        "document_type": row["document_type"],
        "country_code": row["country_code"],
        "secure_artifact_reference": row["secure_artifact_reference"],
        "bureau_job_id": row["bureau_job_id"],
        "tracking_number": row["tracking_number"],
        "status": row["status"],
        "quality_result": row["quality_result"],
        "error_code": row["error_code"],
        "error_message": row["error_message"],
        "submitted_at": row["submitted_at"],
        "completed_at": row["completed_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


async def _get_job(application_id: str) -> dict[str, Any]:
    async with _factory()() as session:
        result = await session.execute(
            select(physical_document_jobs_table).where(
                physical_document_jobs_table.c.application_id == application_id
            )
        )
        row = result.mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="Physical document application not found")
        return dict(row)


async def _update_job(application_id: str, **values: Any) -> dict[str, Any]:
    values["updated_at"] = datetime.now(timezone.utc)
    async with _factory()() as session:
        result = await session.execute(
            physical_document_jobs_table.update()
            .where(physical_document_jobs_table.c.application_id == application_id)
            .values(**values)
            .returning(physical_document_jobs_table)
        )
        row = result.mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="Physical document application not found")
        await session.commit()
        return dict(row)


def _decrypt_artifact(row: dict[str, Any]) -> dict[str, Any]:
    try:
        plaintext = _fernet().decrypt(row["secure_artifact_ciphertext"].encode("ascii"))
        return json.loads(plaintext)
    except (InvalidToken, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="Secure physical document artifact cannot be decrypted") from exc


def _numbered_data_groups(artifact: dict[str, Any]) -> dict[int, str]:
    return {int(name[2:]): content for name, content in artifact["data_groups"].items()}


def _production_status(status: ProductionStatus) -> str:
    return {
        ProductionStatus.QUEUED: "SUBMITTED",
        ProductionStatus.PRINTING: "IN_PRODUCTION",
        ProductionStatus.ENCODING: "IN_PRODUCTION",
        ProductionStatus.QUALITY_CHECK: "QUALITY_CHECK",
        ProductionStatus.SHIPPED: "READY_FOR_ACTIVATION",
        ProductionStatus.DELIVERED: "READY_FOR_ACTIVATION",
        ProductionStatus.FAILED: "FAILED",
        ProductionStatus.CANCELLED: "CANCELLED",
    }[status]


@physical_document_router.get("/capabilities")
async def get_physical_document_capabilities() -> dict[str, Any]:
    signing = signer_capabilities()
    blockers = list(signing["blockers"])
    if not os.environ.get("PHYSICAL_DOCUMENT_ARTIFACT_KEY", "").strip():
        blockers.append("Configure PHYSICAL_DOCUMENT_ARTIFACT_KEY for encrypted sensitive artifacts.")
    if not is_bureau_configured():
        blockers.append("Configure PERSONALIZATION_BUREAU_URL for production handoff.")
    return {
        "supported": not blockers,
        "signer": signing,
        "bureau_configured": is_bureau_configured(),
        "encrypted_artifact_store": bool(os.environ.get("PHYSICAL_DOCUMENT_ARTIFACT_KEY", "").strip()),
        "blockers": blockers,
    }


@physical_document_router.post("/applications", status_code=201)
async def create_passport_application(payload: PassportApplicationRequest) -> dict[str, Any]:
    job_id = str(uuid.uuid4())
    application_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    artifact = {
        "applicant": payload.applicant,
        "mrz": payload.mrz,
        "data_groups": payload.data_groups,
    }
    ciphertext = _fernet().encrypt(json.dumps(artifact, separators=(",", ":")).encode()).decode("ascii")
    values = {
        "id": job_id,
        "organization_id": payload.organization_id,
        "flow_execution_id": payload.flow_execution_id,
        "application_id": application_id,
        "application_template_id": payload.application_template_id,
        "credential_template_id": payload.credential_template_id,
        "delivery_destination_profile_id": payload.delivery_destination_profile_id,
        "document_type": payload.document_type,
        "country_code": payload.country_code,
        "secure_artifact_ciphertext": ciphertext,
        "secure_artifact_reference": f"physical-artifact://{job_id}",
        "status": "DRAFT",
        "created_at": now,
        "updated_at": now,
    }
    async with _factory()() as session:
        await session.execute(physical_document_jobs_table.insert().values(**values))
        await session.commit()
    return _safe_response(values | {
        "sod_sha256": None, "bureau_job_id": None, "tracking_number": None,
        "quality_result": None, "error_code": None, "error_message": None,
        "submitted_at": None, "completed_at": None,
    })


@physical_document_router.post("/applications/{application_id}/generate-sod")
async def generate_passport_sod(application_id: str) -> dict[str, Any]:
    row = await _get_job(application_id)
    artifact = _decrypt_artifact(row)
    signed = await sign_emrtd(
        country_code=row["country_code"],
        organization=row["organization_id"],
        data_groups=_numbered_data_groups(artifact),
    )
    sod_hash = hashlib.sha256(base64.b64decode(signed["sod_der_base64"], validate=True)).hexdigest()
    updated = await _update_job(application_id, status="SOD_SIGNED", sod_sha256=sod_hash)
    return {**_safe_response(updated), "sod_sha256": sod_hash}


@physical_document_router.post("/applications/{application_id}/generate-data-groups")
async def generate_passport_data_groups(application_id: str) -> dict[str, Any]:
    row = await _get_job(application_id)
    artifact = _decrypt_artifact(row)
    data_groups = _numbered_data_groups(artifact)
    if not {1, 2}.issubset(data_groups):
        raise HTTPException(status_code=422, detail="DG1 and DG2 are required for physical document issuance")
    updated = await _update_job(application_id, status="DATA_GENERATED")
    return _safe_response(updated)


@physical_document_router.post("/applications/{application_id}/submit-personalization")
async def submit_passport_personalization(application_id: str) -> dict[str, Any]:
    row = await _get_job(application_id)
    artifact = _decrypt_artifact(row)
    signed = await sign_emrtd(
        country_code=row["country_code"],
        organization=row["organization_id"],
        data_groups=_numbered_data_groups(artifact),
    )
    job = await submit_personalization_job(PersonalizationJob(
        id=row["id"],
        application_id=row["application_id"],
        organization_id=row["organization_id"],
        country_code=row["country_code"],
        data_groups=_numbered_data_groups(artifact),
        sod_der_base64=signed["sod_der_base64"],
        dsc_cert_pem=signed["dsc_cert_pem"],
        mrz_line_1=artifact["mrz"].get("line_1", ""),
        mrz_line_2=artifact["mrz"].get("line_2", ""),
    ))
    updated = await _update_job(
        application_id,
        status=_production_status(job.status),
        bureau_job_id=job.bureau_job_id,
        tracking_number=job.tracking_number,
        error_code="BUREAU_SUBMISSION_FAILED" if job.status == ProductionStatus.FAILED else None,
        error_message=job.error_message,
        submitted_at=datetime.now(timezone.utc),
    )
    return _safe_response(updated)


@physical_document_router.get("/applications/{application_id}/production-status")
async def get_passport_production_status(application_id: str) -> dict[str, Any]:
    row = await _get_job(application_id)
    if row["bureau_job_id"] and row["status"] not in {"ACTIVE", "FAILED", "CANCELLED"}:
        bureau = await poll_job_status(row["bureau_job_id"])
        status = ProductionStatus(bureau["status"])
        row = await _update_job(
            application_id,
            status=_production_status(status),
            tracking_number=bureau.get("tracking_number") or row["tracking_number"],
            error_message=bureau.get("error_message"),
        )
    return _safe_response(row)


@physical_document_router.post("/applications/{application_id}/quality-verify")
async def record_passport_quality_result(
    application_id: str,
    payload: QualityResultRequest,
    x_user_id: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    row = await _get_job(application_id)
    if row["status"] not in {"QUALITY_CHECK", "READY_FOR_ACTIVATION"}:
        raise HTTPException(status_code=409, detail="Document is not ready for quality verification")
    quality_result = {
        "passed": payload.passed,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "checked_by": x_user_id,
        "failure_codes": payload.failure_codes,
    }
    updated = await _update_job(
        application_id,
        status="READY_FOR_ACTIVATION" if payload.passed else "FAILED",
        quality_result=quality_result,
        error_code=None if payload.passed else "QUALITY_CHECK_FAILED",
    )
    return _safe_response(updated)


@physical_document_router.post("/applications/{application_id}/activate")
async def activate_passport(application_id: str) -> dict[str, Any]:
    row = await _get_job(application_id)
    if row["status"] != "READY_FOR_ACTIVATION" or not (row["quality_result"] or {}).get("passed"):
        raise HTTPException(status_code=409, detail="A passing quality result is required before activation")
    updated = await _update_job(
        application_id,
        status="ACTIVE",
        completed_at=datetime.now(timezone.utc),
        secure_artifact_ciphertext=_fernet().encrypt(b"{}").decode("ascii"),
    )
    return _safe_response(updated)


@physical_document_router.post("/webhooks/personalization", include_in_schema=False)
async def personalization_webhook(
    request: Request,
    x_personalization_signature: Annotated[str, Header()],
) -> dict[str, bool]:
    body = await request.body()
    if not verify_webhook_signature(body, x_personalization_signature):
        raise HTTPException(status_code=401, detail="Invalid personalization webhook signature")
    payload = json.loads(body)
    bureau_job_id, status, metadata = parse_webhook_event(payload)
    async with _factory()() as session:
        result = await session.execute(
            select(physical_document_jobs_table.c.application_id).where(
                physical_document_jobs_table.c.bureau_job_id == bureau_job_id
            )
        )
        application_id = result.scalar_one_or_none()
    if not application_id:
        raise HTTPException(status_code=404, detail="Physical document job not found")
    await _update_job(
        application_id,
        status=_production_status(status),
        tracking_number=metadata.get("tracking_number"),
        error_message=metadata.get("error_message"),
    )
    return {"accepted": True}
