"""Source-boundary checks for issuer signing and private repository code."""

from __future__ import annotations

from importlib import import_module
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_status_list_package_has_no_local_issuer_key_adapter() -> None:
    """Status-list code must receive a signer, never load issuer keys itself."""

    status_list = ROOT / "python" / "status_list"
    production_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(status_list.rglob("*.py"))
        if "tests" not in path.parts
    )

    assert "jwk_private_encrypted" not in production_source
    assert "subscription.models" not in production_source
    assert "register_issuer(" not in production_source
    assert '"private_key": private_key' not in production_source


def test_status_list_adapter_surface_exposes_no_signer() -> None:
    """Callers cannot select the removed process-local signing implementation."""

    adapter_surface = (
        ROOT / "python" / "status_list" / "infrastructure" / "adapters" / "__init__.py"
    ).read_text(encoding="utf-8")

    assert '"StatusListRouter"' in adapter_surface
    assert "RustSigningAdapter" not in adapter_surface
    assert "signing_adapter" not in adapter_surface


def test_issuance_service_has_no_database_or_process_local_issuer_signer() -> None:
    """Production issuance must delegate issuer signatures to managed custody."""

    service = ROOT / "services" / "issuance"
    production_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(service.rglob("*.py"))
        if "tests" not in path.parts and "migrations" not in path.parts
    )

    assert "ISSUER_KEY_MASTER_KEY" not in production_source
    assert "issuer_signing_keys_table" not in production_source
    assert "configure_issuer_key_store" not in production_source
    assert "get_or_generate_issuer_key" not in production_source
    assert "oid4vci_sign_credential(" not in production_source
    assert "_fix_mdoc_issuer_auth" not in production_source


def test_legacy_key_migration_fails_closed_before_dropping_storage(monkeypatch) -> None:
    """The destructive schema step cannot silently discard an issuer key."""

    migration = import_module(
        "issuance.infrastructure.migrations.versions."
        "20260807_1000_drop_legacy_issuer_signing_keys"
    )
    statements: list[str] = []
    monkeypatch.setattr(migration.op, "execute", lambda statement: statements.append(str(statement)))

    migration.upgrade()

    assert migration.down_revision == "issuance_tx_issuer_algorithm"
    assert len(statements) == 2
    assert "EXISTS" in statements[0]
    assert "legacy issuer signing keys remain in PostgreSQL" in statements[0]
    assert "managed custody" in statements[0]
    assert statements[1] == "DROP TABLE IF EXISTS issuance_service.issuer_signing_keys"
