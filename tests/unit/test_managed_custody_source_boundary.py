"""Source-boundary checks for issuer signing and private repository code."""

from __future__ import annotations

from importlib import import_module
from pathlib import Path

import pytest
from marty_credentials.native_backend import NativeOperationError
from sqlalchemy import create_engine, inspect

ROOT = Path(__file__).resolve().parents[2]


def test_duplicate_python_status_list_package_is_absent() -> None:
    """Status decisions live in canonical Rust and cannot return to Python."""

    status_package = ROOT / "python" / "status_list"
    assert not status_package.exists() or not any(status_package.rglob("*.py"))
    binding = (ROOT / "rust" / "marty-rs" / "src" / "status_list.rs").read_text(encoding="utf-8")
    assert (
        "pub use marty_python_adapters::status_list::compressed::register "
        "as register_status_list_module;"
    ) in binding
    production_binding = binding.split("#[cfg(test)]", 1)[0]
    assert "#[pyclass" not in production_binding
    assert "#[pymethods" not in production_binding


def test_integration_secret_crypto_uses_only_remote_envelope_transport() -> None:
    """The retained storage adapter cannot reintroduce local key custody."""

    adapter = (
        ROOT / "services" / "issuance" / "infrastructure" / "security" / "encryption.py"
    ).read_text(encoding="utf-8")

    assert "RemoteIntegrationSecretEncryption" in adapter
    assert '"INTEGRATION_SECRET_MASTER_KEY"' in adapter
    assert "/integration-secrets/{operation}" in adapter
    assert "require_marty_verification" not in adapter
    assert "aes_gcm_encrypt" not in adapter
    assert "aes_gcm_decrypt" not in adapter
    assert "cryptography" not in adapter
    assert "AESGCM" not in adapter


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


def test_retired_mdoc_pem_issuer_entry_points_are_absent() -> None:
    """The compatibility package must not advertise private-PEM mDoc issuance."""

    assert not (ROOT / "rust" / "marty-rs" / "src" / "mdoc" / "issuance.rs").exists()
    module = (ROOT / "python" / "marty_credentials" / "adapters" / "rust" / "mdoc.py").read_text(
        encoding="utf-8"
    )
    exports = (
        ROOT / "python" / "marty_credentials" / "adapters" / "rust" / "__init__.py"
    ).read_text(encoding="utf-8")
    for forbidden in ("RustMdocIssuer", "get_mdoc_issuer", "issuer_key_pem", "PreparedMdoc"):
        assert forbidden not in module
        assert forbidden not in exports
    rust_adapters = import_module("marty_credentials.adapters.rust")
    assert not hasattr(rust_adapters, "RustMdocIssuer")
    assert not hasattr(rust_adapters, "get_mdoc_issuer")


def test_python_adapter_factories_expose_no_local_issuer_or_key_manager() -> None:
    """Compatibility adapters cannot recreate locally generated issuer keys."""

    for relative in (
        "python/marty_credentials/adapters/rust/adapter.py",
        "python/marty_credentials/adapters/adapters/credentials/spruceid.py",
        "python/marty_credentials/adapters/adapters/credentials/__init__.py",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        for forbidden in ("generate_p256_did_jwk", "create_verifiable_credential"):
            assert forbidden not in source

    for name in (
        "marty_credentials.adapters.rust",
        "marty_credentials.adapters.adapters.credentials",
    ):
        adapter = import_module(name)
        for forbidden in ("get_key_manager", "get_issuer", "create_key_manager", "create_issuer"):
            assert not hasattr(adapter, forbidden)
        assert callable(adapter.get_wallet)
        assert callable(adapter.get_verifier)

    for name in ("marty_credentials", "marty_credentials.ports"):
        module = import_module(name)
        assert not hasattr(module, "IKeyManager")
        assert not hasattr(module, "ICredentialIssuer")

    for name in (
        "marty_credentials.adapters.persistence",
        "marty_credentials.adapters.adapters.credentials.persistence",
    ):
        module = import_module(name)
        assert not hasattr(module, "SQLAlchemyKeyManager")
        assert not hasattr(module, "KeyModel")
        assert hasattr(module, "SQLAlchemyCredentialWallet")


def test_fresh_credential_metadata_creates_no_private_key_table() -> None:
    """The compatibility ORM must not recreate a retired key table on a new DB."""

    models = import_module("marty_credentials.adapters.persistence.models")
    engine = create_engine("sqlite://")
    try:
        models.Base.metadata.create_all(engine)
        assert set(inspect(engine).get_table_names()) == {
            "credentials",
            "holders",
            "trust_registry",
            "verification_logs",
            "zk_challenges",
        }
        assert "selective_disclosure_keys" not in {
            column["name"] for column in inspect(engine).get_columns("credentials")
        }
    finally:
        engine.dispose()


def test_credential_wallet_adapters_share_one_persistence_model() -> None:
    """A nested adapter must not reintroduce a second credential schema."""

    canonical = import_module("marty_credentials.adapters.persistence.adapter")
    nested = import_module("marty_credentials.adapters.adapters.credentials.persistence")
    assert nested.Base is canonical.Base
    assert nested.CredentialModel is canonical.CredentialModel
    assert nested.SQLAlchemyCredentialWallet is canonical.SQLAlchemyCredentialWallet


def test_retired_multipaz_selection_does_not_fall_back_to_spruceid() -> None:
    """An explicit retired backend selection must fail closed."""

    adapters = import_module("marty_credentials.adapters.adapters.credentials")
    with pytest.raises((NativeOperationError, RuntimeError), match="retired|unavailable"):
        adapters.create_wallet(adapters.AdapterMode.MULTIPAZ)
    with pytest.raises((NativeOperationError, RuntimeError), match="retired|unavailable"):
        adapters.create_verifier(adapters.AdapterMode.MULTIPAZ)


def test_clean_install_migrations_never_create_private_key_storage() -> None:
    """Fresh databases must not create and later drop an issuer private-key table."""

    versions = ROOT / "services" / "issuance" / "infrastructure" / "migrations" / "versions"
    sources = [path.read_text(encoding="utf-8") for path in versions.glob("*.py")]
    assert sources
    for source in sources:
        assert "issuer_signing_keys" not in source
        assert "encrypted_jwk_json" not in source
