"""Source-boundary checks for issuer signing and private repository code."""

from __future__ import annotations

from pathlib import Path

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


def test_python_issuance_secret_storage_is_retired() -> None:
    assert not (ROOT / "services" / "issuance").exists()


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
