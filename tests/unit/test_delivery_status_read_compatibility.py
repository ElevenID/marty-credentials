"""Mixed-version delivery-record read compatibility."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from issuance.domain.entities import CredentialDeliveryStatus
from issuance.infrastructure.adapters.postgres_repository import PostgresIssuanceRepository


def _delivery_row(status: str) -> SimpleNamespace:
    now = datetime(2026, 9, 23, tzinfo=UTC)
    return SimpleNamespace(
        id="delivery-1",
        credential_id="credential-1",
        transaction_id="transaction-1",
        organization_id="organization-1",
        delivery_target="didcomm_v2",
        delivery_mode="wallet_only",
        status=status,
        canvas_account_id=None,
        external_credential_id=None,
        external_issuer_id=None,
        last_error=None,
        metadata={
            "encrypted_message": "must-not-appear-in-status-errors",
            "didcomm_transport_attempt_id": "must-not-appear-in-status-errors",
        },
        created_at=now,
        updated_at=now,
    )


@pytest.mark.parametrize(
    ("persisted_status", "management_status"),
    [
        pytest.param("transport_ready", CredentialDeliveryStatus.PENDING, id="ready"),
        pytest.param("transporting", CredentialDeliveryStatus.PENDING, id="in-flight"),
        pytest.param(
            "transport_retryable", CredentialDeliveryStatus.PENDING, id="retryable"
        ),
        pytest.param("transported", CredentialDeliveryStatus.DELIVERED, id="transported"),
        pytest.param("delivery_unknown", CredentialDeliveryStatus.PENDING, id="unknown"),
    ],
)
def test_postgres_mapper_projects_every_rust_delivery_status_for_management_reads(
    persisted_status: str,
    management_status: CredentialDeliveryStatus,
) -> None:
    record = PostgresIssuanceRepository._row_to_delivery_record(
        _delivery_row(persisted_status)
    )

    assert record.status is management_status


@pytest.mark.parametrize("status", list(CredentialDeliveryStatus))
def test_postgres_mapper_preserves_legacy_terminal_delivery_semantics(
    status: CredentialDeliveryStatus,
) -> None:
    record = PostgresIssuanceRepository._row_to_delivery_record(_delivery_row(status.value))

    assert record.status is status


def test_postgres_mapper_rejects_unknown_writer_status_without_exposing_row_secrets() -> None:
    with pytest.raises(ValueError) as exc_info:
        PostgresIssuanceRepository._row_to_delivery_record(_delivery_row("future_state"))

    message = str(exc_info.value)
    assert message == "unsupported credential delivery status"
    assert "future_state" not in message
    assert "encrypted_message" not in message
    assert "didcomm_transport_attempt_id" not in message
