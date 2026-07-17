from __future__ import annotations

import ast
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))


def test_issuance_module_runs_the_created_app_without_development_reload() -> None:
    source = (ROOT / "services" / "issuance" / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
    ]

    assert calls
    production_call = calls[-1]
    assert isinstance(production_call.args[0], ast.Name)
    assert production_call.args[0].id == "app"
    reload_keyword = next(keyword for keyword in production_call.keywords if keyword.arg == "reload")
    assert isinstance(reload_keyword.value, ast.Constant)
    assert reload_keyword.value.value is False


def test_native_extension_capability_contract_accepts_complete_module(monkeypatch) -> None:
    from issuance.application import rust_integration

    complete_module = SimpleNamespace(
        **{
            capability: (lambda: None)
            for capability in rust_integration.REQUIRED_MARTY_RS_CAPABILITIES
        }
    )
    monkeypatch.setattr(rust_integration, "get_marty_rs", lambda: complete_module)

    rust_integration.validate_marty_rs_capabilities()


def test_native_extension_uses_maturin_package_name(monkeypatch) -> None:
    from issuance.application import rust_integration

    extension = SimpleNamespace()
    monkeypatch.setitem(sys.modules, "_marty_rs", extension)

    assert rust_integration.get_marty_rs() is extension


def test_native_extension_capability_contract_rejects_incomplete_module(monkeypatch) -> None:
    from issuance.application import rust_integration

    monkeypatch.setattr(rust_integration, "get_marty_rs", lambda: SimpleNamespace())

    with pytest.raises(RuntimeError, match="oid4vci_create_credential_offer"):
        rust_integration.validate_marty_rs_capabilities()


def test_issuance_image_uses_release_wheels_instead_of_sibling_sources() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY release-deps /release-deps" in dockerfile
    assert "pip install --no-cache-dir /release-deps/*.whl" in dockerfile
    assert "COPY marty-core/" not in dockerfile
