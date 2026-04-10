"""
Unit tests for the personalization bureau adapter.

Tests cover domain types, webhook verification, payload construction,
and HTTP interactions via mocked httpx responses.
"""

import hashlib
import hmac as hmac_mod
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.issuance.infrastructure.adapters.personalization_bureau_client import (
    PersonalizationBatch,
    PersonalizationJob,
    ProductionStatus,
    is_bureau_configured,
    parse_webhook_event,
    poll_job_status,
    submit_personalization_batch,
    submit_personalization_job,
    verify_webhook_signature,
)


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class TestProductionStatus:

    def test_all_values(self):
        expected = {
            "QUEUED", "PRINTING", "ENCODING", "QUALITY_CHECK",
            "SHIPPED", "DELIVERED", "FAILED", "CANCELLED",
        }
        assert {s.value for s in ProductionStatus} == expected

    def test_string_coercion(self):
        assert ProductionStatus("QUEUED") == ProductionStatus.QUEUED


class TestPersonalizationJob:

    def test_defaults(self):
        job = PersonalizationJob()
        assert job.status == ProductionStatus.QUEUED
        assert job.bureau_job_id is None
        assert job.tracking_number is None
        assert job.error_message is None
        assert isinstance(job.submitted_at, datetime)

    def test_with_data_groups(self):
        job = PersonalizationJob(
            application_id="app-1",
            country_code="UTO",
            data_groups={1: "AQID", 2: "BAUG"},
            mrz_line_1="P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
            mrz_line_2="L898902C36UTO7408122F1204159ZE184226B<<<<<10",
        )
        assert job.data_groups[1] == "AQID"
        assert job.country_code == "UTO"

    def test_unique_ids(self):
        j1 = PersonalizationJob()
        j2 = PersonalizationJob()
        assert j1.id != j2.id


class TestPersonalizationBatch:

    def test_defaults(self):
        batch = PersonalizationBatch(organization_id="org-1")
        assert batch.status == ProductionStatus.QUEUED
        assert batch.jobs == []

    def test_with_jobs(self):
        jobs = [PersonalizationJob(), PersonalizationJob()]
        batch = PersonalizationBatch(jobs=jobs)
        assert len(batch.jobs) == 2


# ---------------------------------------------------------------------------
# Webhook verification
# ---------------------------------------------------------------------------

class TestWebhookVerification:

    def test_valid_signature(self, monkeypatch):
        secret = "test-secret-key"
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_WEBHOOK_SECRET",
            secret,
        )
        body = b'{"bureau_job_id":"123","status":"SHIPPED"}'
        sig = hmac_mod.new(secret.encode(), body, hashlib.sha256).hexdigest()
        assert verify_webhook_signature(body, sig) is True

    def test_invalid_signature(self, monkeypatch):
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_WEBHOOK_SECRET",
            "test-secret",
        )
        body = b'{"test": true}'
        assert verify_webhook_signature(body, "deadbeef") is False

    def test_no_secret_configured(self, monkeypatch):
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_WEBHOOK_SECRET",
            "",
        )
        assert verify_webhook_signature(b"anything", "anything") is False


class TestParseWebhookEvent:

    def test_parses_status_update(self):
        payload = {
            "bureau_job_id": "bureau-999",
            "status": "QUALITY_CHECK",
            "quality_score": 0.98,
            "reader_verify": True,
        }
        job_id, status, meta = parse_webhook_event(payload)
        assert job_id == "bureau-999"
        assert status == ProductionStatus.QUALITY_CHECK
        assert meta["quality_score"] == 0.98
        assert "bureau_job_id" not in meta
        assert "status" not in meta


# ---------------------------------------------------------------------------
# Bureau configuration check
# ---------------------------------------------------------------------------

class TestBureauConfiguration:

    def test_not_configured(self, monkeypatch):
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_URL",
            "",
        )
        assert is_bureau_configured() is False

    def test_configured(self, monkeypatch):
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_URL",
            "https://bureau.example.com",
        )
        assert is_bureau_configured() is True


# ---------------------------------------------------------------------------
# Submit job (mocked HTTP)
# ---------------------------------------------------------------------------

class TestSubmitJob:

    @pytest.fixture
    def sample_job(self):
        return PersonalizationJob(
            application_id="app-test",
            organization_id="org-test",
            country_code="UTO",
            data_groups={1: "YWJj"},
            sod_der_base64="c29kX2Rlcg==",
            dsc_cert_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            mrz_line_1="P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
            mrz_line_2="L898902C36UTO7408122F1204159ZE184226B<<<<<10",
        )

    async def test_not_configured_raises(self, monkeypatch, sample_job):
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_URL",
            "",
        )
        with pytest.raises(RuntimeError, match="not configured"):
            await submit_personalization_job(sample_job)

    async def test_successful_submission(self, monkeypatch, sample_job):
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_URL",
            "https://bureau.test",
        )
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_API_KEY",
            "test-key",
        )

        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_response.json.return_value = {
            "bureau_job_id": "bureau-abc",
            "status": "QUEUED",
            "tracking_number": "TRACK-001",
        }

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await submit_personalization_job(sample_job)

        assert result.bureau_job_id == "bureau-abc"
        assert result.status == ProductionStatus.QUEUED
        assert result.tracking_number == "TRACK-001"

        # Verify payload structure
        call_kwargs = mock_client.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["country_code"] == "UTO"
        assert "DG1" in payload["data_groups"]
        assert payload["mrz"]["line_1"].startswith("P<UTO")

    async def test_bureau_error_sets_failed(self, monkeypatch, sample_job):
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_URL",
            "https://bureau.test",
        )
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_API_KEY",
            "key",
        )

        mock_response = AsyncMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await submit_personalization_job(sample_job)

        assert result.status == ProductionStatus.FAILED
        assert "500" in result.error_message


# ---------------------------------------------------------------------------
# Submit batch (mocked HTTP)
# ---------------------------------------------------------------------------

class TestSubmitBatch:

    async def test_not_configured_raises(self, monkeypatch):
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_URL",
            "",
        )
        batch = PersonalizationBatch(organization_id="org-1", jobs=[PersonalizationJob()])
        with pytest.raises(RuntimeError, match="not configured"):
            await submit_personalization_batch(batch)

    async def test_successful_batch(self, monkeypatch):
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_URL",
            "https://bureau.test",
        )
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_API_KEY",
            "key",
        )

        job1 = PersonalizationJob(country_code="UTO")
        job2 = PersonalizationJob(country_code="GBR")
        batch = PersonalizationBatch(
            organization_id="org-1",
            jobs=[job1, job2],
        )

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "status": "QUEUED",
            "jobs": [
                {"job_id": job1.id, "bureau_job_id": "b-1", "status": "QUEUED"},
                {"job_id": job2.id, "bureau_job_id": "b-2", "status": "QUEUED"},
            ],
        }

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await submit_personalization_batch(batch)

        assert result.status == ProductionStatus.QUEUED
        assert result.jobs[0].bureau_job_id == "b-1"
        assert result.jobs[1].bureau_job_id == "b-2"


# ---------------------------------------------------------------------------
# Poll job status (mocked HTTP)
# ---------------------------------------------------------------------------

class TestPollJobStatus:

    async def test_not_configured_raises(self, monkeypatch):
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_URL",
            "",
        )
        with pytest.raises(RuntimeError, match="not configured"):
            await poll_job_status("bureau-123")

    async def test_successful_poll(self, monkeypatch):
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_URL",
            "https://bureau.test",
        )
        monkeypatch.setattr(
            "services.issuance.infrastructure.adapters.personalization_bureau_client.BUREAU_API_KEY",
            "key",
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "bureau_job_id": "bureau-123",
            "status": "ENCODING",
            "progress_percent": 60,
        }
        mock_response.raise_for_status = lambda: None

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await poll_job_status("bureau-123")

        assert result["status"] == "ENCODING"
        assert result["progress_percent"] == 60
