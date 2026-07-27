from issuance.infrastructure.models import (
    issuance_transactions_table,
    oid4vci_client_assertions_table,
    oid4vci_registered_clients_table,
)


def test_registered_client_tables_are_tenant_scoped() -> None:
    assert set(oid4vci_registered_clients_table.primary_key.columns.keys()) == {
        "organization_id",
        "client_id",
    }
    assert set(oid4vci_client_assertions_table.primary_key.columns.keys()) == {
        "organization_id",
        "client_id",
        "jti",
    }
    assert oid4vci_registered_clients_table.c.jwks.nullable is False
    assert oid4vci_client_assertions_table.c.expires_at.nullable is False


def test_issuance_offer_persists_its_authorized_client_binding() -> None:
    assert "oid4vci_client_id" in issuance_transactions_table.c
    assert issuance_transactions_table.c.oid4vci_client_id.nullable is True
