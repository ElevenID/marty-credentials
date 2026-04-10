"""
Personalization Bureau Adapter

Integrates with external passport/document personalization bureaus (e.g. IDEMIA,
Thales, Veridos, De La Rue) to submit physical ePassport production jobs and
track their status.

The bureau receives pre-signed EF.SOD + data group payloads and performs:
  1. Booklet printing (security features, UV/IR, holograms)
  2. Polycarbonate data page laser engraving
  3. Chip encoding (write DGs + SOD to ISO 14443 contactless IC)
  4. BAC key provisioning (derived from MRZ)
  5. Quality assurance read-back
  6. Lamination and binding

Configuration:
  PERSONALIZATION_BUREAU_URL    — Bureau HTTP API base URL
  PERSONALIZATION_BUREAU_API_KEY — API key for bureau authentication
  PERSONALIZATION_BUREAU_WEBHOOK_SECRET — HMAC secret for status webhooks
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

BUREAU_URL = os.environ.get("PERSONALIZATION_BUREAU_URL", "")
BUREAU_API_KEY = os.environ.get("PERSONALIZATION_BUREAU_API_KEY", "")
BUREAU_WEBHOOK_SECRET = os.environ.get("PERSONALIZATION_BUREAU_WEBHOOK_SECRET", "")


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class ProductionStatus(str, Enum):
    """Lifecycle status of a physical document production job."""
    QUEUED = "QUEUED"
    PRINTING = "PRINTING"
    ENCODING = "ENCODING"
    QUALITY_CHECK = "QUALITY_CHECK"
    SHIPPED = "SHIPPED"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass
class PersonalizationJob:
    """A job submitted to the personalization bureau."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    application_id: str = ""
    organization_id: str = ""
    country_code: str = ""

    # Payload sent to the bureau
    data_groups: dict[int, str] = field(default_factory=dict)  # DG number → base64 content
    sod_der_base64: str = ""
    dsc_cert_pem: str = ""
    mrz_line_1: str = ""
    mrz_line_2: str = ""

    # Bureau response
    bureau_job_id: str | None = None
    status: ProductionStatus = ProductionStatus.QUEUED
    tracking_number: str | None = None
    error_message: str | None = None

    # Timing
    submitted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None


@dataclass
class PersonalizationBatch:
    """A batch of personalization jobs for bulk submission."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    jobs: list[PersonalizationJob] = field(default_factory=list)
    status: ProductionStatus = ProductionStatus.QUEUED
    submitted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Bureau API client
# ---------------------------------------------------------------------------

def is_bureau_configured() -> bool:
    """Check if an external personalization bureau is configured."""
    return bool(BUREAU_URL)


async def submit_personalization_job(job: PersonalizationJob) -> PersonalizationJob:
    """Submit a single passport personalization job to the bureau.

    The bureau receives the signed data groups and SOD, then handles
    physical booklet production and chip encoding.

    Returns the job with bureau_job_id and updated status.
    """
    if not is_bureau_configured():
        raise RuntimeError(
            "Personalization bureau not configured. "
            "Set PERSONALIZATION_BUREAU_URL environment variable."
        )

    import httpx

    payload = {
        "job_id": job.id,
        "application_id": job.application_id,
        "organization_id": job.organization_id,
        "country_code": job.country_code,
        "document_type": "TD3",
        "data_groups": {
            f"DG{num}": content
            for num, content in sorted(job.data_groups.items())
        },
        "sod_der_base64": job.sod_der_base64,
        "dsc_cert_pem": job.dsc_cert_pem,
        "mrz": {
            "line_1": job.mrz_line_1,
            "line_2": job.mrz_line_2,
        },
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{BUREAU_URL}/v1/personalization/jobs",
            json=payload,
            headers={
                "Authorization": f"Bearer {BUREAU_API_KEY}",
                "Content-Type": "application/json",
            },
        )

        if resp.status_code not in (200, 201, 202):
            logger.error(
                "Bureau submission failed: status=%d body=%s",
                resp.status_code,
                resp.text[:500],
            )
            job.status = ProductionStatus.FAILED
            job.error_message = f"Bureau returned HTTP {resp.status_code}"
            return job

        data = resp.json()
        job.bureau_job_id = data.get("bureau_job_id") or data.get("job_id")
        job.status = ProductionStatus(data.get("status", "QUEUED"))
        job.tracking_number = data.get("tracking_number")
        logger.info(
            "Bureau job submitted: job_id=%s bureau_job_id=%s status=%s",
            job.id,
            job.bureau_job_id,
            job.status.value,
        )
        return job


async def submit_personalization_batch(batch: PersonalizationBatch) -> PersonalizationBatch:
    """Submit a batch of personalization jobs."""
    if not is_bureau_configured():
        raise RuntimeError("Personalization bureau not configured.")

    import httpx

    jobs_payload = []
    for job in batch.jobs:
        jobs_payload.append({
            "job_id": job.id,
            "application_id": job.application_id,
            "country_code": job.country_code,
            "data_groups": {
                f"DG{num}": content
                for num, content in sorted(job.data_groups.items())
            },
            "sod_der_base64": job.sod_der_base64,
            "dsc_cert_pem": job.dsc_cert_pem,
            "mrz": {"line_1": job.mrz_line_1, "line_2": job.mrz_line_2},
        })

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{BUREAU_URL}/v1/personalization/batches",
            json={
                "batch_id": batch.id,
                "organization_id": batch.organization_id,
                "jobs": jobs_payload,
            },
            headers={
                "Authorization": f"Bearer {BUREAU_API_KEY}",
                "Content-Type": "application/json",
            },
        )

        if resp.status_code not in (200, 201, 202):
            batch.status = ProductionStatus.FAILED
            logger.error("Bureau batch submission failed: %d", resp.status_code)
            return batch

        data = resp.json()
        batch.status = ProductionStatus(data.get("status", "QUEUED"))
        for job_data in data.get("jobs", []):
            for job in batch.jobs:
                if job.id == job_data.get("job_id"):
                    job.bureau_job_id = job_data.get("bureau_job_id")
                    job.status = ProductionStatus(job_data.get("status", "QUEUED"))
        return batch


async def poll_job_status(bureau_job_id: str) -> dict[str, Any]:
    """Poll the bureau for the current status of a production job."""
    if not is_bureau_configured():
        raise RuntimeError("Personalization bureau not configured.")

    import httpx

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(
            f"{BUREAU_URL}/v1/personalization/jobs/{bureau_job_id}",
            headers={"Authorization": f"Bearer {BUREAU_API_KEY}"},
        )
        resp.raise_for_status()
        return resp.json()


def verify_webhook_signature(payload_body: bytes, signature: str) -> bool:
    """Verify HMAC-SHA256 signature on bureau webhook callbacks.

    The bureau signs callback payloads with the shared secret.
    Returns True if the signature is valid.
    """
    if not BUREAU_WEBHOOK_SECRET:
        logger.warning("No webhook secret configured — skipping verification")
        return False

    expected = hmac.new(
        BUREAU_WEBHOOK_SECRET.encode("utf-8"),
        payload_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


def parse_webhook_event(payload: dict[str, Any]) -> tuple[str, ProductionStatus, dict[str, Any]]:
    """Parse a bureau webhook event payload.

    Returns (bureau_job_id, new_status, metadata).
    """
    bureau_job_id = payload["bureau_job_id"]
    status = ProductionStatus(payload["status"])
    metadata = {
        k: v for k, v in payload.items()
        if k not in ("bureau_job_id", "status")
    }
    return bureau_job_id, status, metadata
