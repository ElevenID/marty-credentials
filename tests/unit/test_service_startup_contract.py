from __future__ import annotations

import ast
import json
import sys
import tomllib
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


def test_native_extension_rejects_nested_compatibility_package(monkeypatch) -> None:
    from issuance.application import rust_integration
    from marty_credentials.native_backend import NativeBackendUnavailable

    extension = SimpleNamespace()
    package = SimpleNamespace(_marty_rs=extension)
    monkeypatch.setitem(sys.modules, "_marty_rs", None)
    monkeypatch.setitem(sys.modules, "marty_rs", package)

    with pytest.raises(NativeBackendUnavailable):
        rust_integration.get_marty_rs()


def test_native_extension_uses_canonical_top_level_module(monkeypatch) -> None:
    from issuance.application import rust_integration

    extension = SimpleNamespace()
    monkeypatch.setitem(sys.modules, "marty_rs", None)
    monkeypatch.setitem(sys.modules, "_marty_rs", extension)

    assert rust_integration.get_marty_rs() is extension


def test_verification_native_contract_rejects_missing_capability(monkeypatch) -> None:
    from marty_credentials.native_backend import NativeBackendUnavailable
    from verification.application import rust_verifier

    monkeypatch.setattr(
        rust_verifier,
        "require_marty_rs",
        lambda capabilities=(): (_ for _ in ()).throw(
            NativeBackendUnavailable("missing verify_vcdm_data_integrity")
        ),
    )

    with pytest.raises(NativeBackendUnavailable, match="verify_vcdm_data_integrity"):
        rust_verifier.validate_marty_rs_capabilities()


def test_native_extension_capability_contract_rejects_incomplete_module(monkeypatch) -> None:
    from issuance.application import rust_integration

    monkeypatch.setattr(rust_integration, "get_marty_rs", lambda: SimpleNamespace())

    with pytest.raises(RuntimeError, match="oid4vci_create_credential_offer"):
        rust_integration.validate_marty_rs_capabilities()


def test_native_extension_capability_contract_requires_remote_mdoc_split_signing(monkeypatch) -> None:
    from issuance.application import rust_integration

    incomplete_module = SimpleNamespace(
        **{
            capability: (lambda: None)
            for capability in rust_integration.REQUIRED_MARTY_RS_CAPABILITIES
            if capability != "oid4vci_prepare_mdoc"
        }
    )
    monkeypatch.setattr(rust_integration, "get_marty_rs", lambda: incomplete_module)

    with pytest.raises(RuntimeError, match="oid4vci_prepare_mdoc"):
        rust_integration.validate_marty_rs_capabilities()


def test_key_attestation_binding_passes_only_the_exact_validated_token(monkeypatch) -> None:
    from issuance.application import rust_integration

    captured: tuple[object, ...] | None = None

    class Extension:
        def oid4vci_verify_key_attestation_bound_proof_jwt(self, *args):
            nonlocal captured
            captured = args
            return "", "nonce-1", '{"kty":"EC","crv":"P-256","x":"x","y":"y"}'

    monkeypatch.setattr(rust_integration, "get_marty_rs", lambda: Extension())

    result = rust_integration.verify_key_attestation_bound_proof_jwt(
        "proof.jwt.value",
        "validated.attestation.value",
        "nonce-1",
        "https://issuer.example/org/org-a",
    )

    assert result == (
        True,
        "",
        {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
        None,
    )
    assert captured == (
        "proof.jwt.value",
        "validated.attestation.value",
        "nonce-1",
        "https://issuer.example/org/org-a",
    )


def test_issuance_image_uses_release_wheels_instead_of_sibling_sources() -> None:
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")
    dependencies = json.loads((ROOT / "release" / "dependencies.json").read_text())
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))

    assert "COPY release-deps /release-deps" in dockerfile
    assert "pip install --no-cache-dir /release-deps/*.whl" in dockerfile
    assert "validate_marty_rs_capabilities()" in dockerfile
    assert "COPY python/marty_credentials /app/marty_credentials" in dockerfile
    assert "COPY marty-core/" not in dockerfile
    assert dependencies["marty-rs"]["repository"] == "ElevenID/marty-core"
    assert dependencies["marty-rs"]["asset"].startswith("marty_rs-")
    core_release = dependencies["marty-rs"]
    assert core_release["tag"] == f"v{core_release['version']}"
    assert core_release["asset"].startswith(f"marty_rs-{core_release['version']}-")
    assert len(core_release["commit"]) == 40
    assert len(core_release["sha256"]) == 64
    assert core_release["platform_assets"]["linux-x86_64"] == {
        "asset": core_release["asset"],
        "sha256": core_release["sha256"],
    }
    assert set(core_release["platform_assets"]) == {
        "linux-x86_64",
        "macos-arm64",
        "windows-x86_64",
    }
    core_revisions = {
        cargo["workspace"]["dependencies"][package]["rev"]
        for package in ("marty-crypto", "marty-verification", "marty-oid4vci")
    }
    assert core_revisions == {core_release["commit"]}


def test_release_images_use_the_pinned_canonical_core_wheel() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release-images.yml").read_text(
        encoding="utf-8"
    )
    verification_image = (ROOT / "services" / "verification" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    dependency_loop = "for dependency in marty-rs marty-msf marty-common; do"
    assert dependency_loop in workflow
    assert "draft-release.json" not in workflow
    assert "Draft must contain exactly one Linux x86_64 marty-rs wheel" not in workflow
    assert "marty_rs_asset_id" not in workflow
    assert "marty_rs_sha256=$(jq -r" in workflow
    assert "COPY python/marty_credentials /app/marty_credentials" in verification_image
    assert "validate_marty_rs_capabilities()" in verification_image


def test_native_wheel_is_an_explicit_non_bootstrapping_extra() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]

    assert not any(
        dependency.startswith("marty-rs") for dependency in project["dependencies"]
    )
    assert project["optional-dependencies"]["ffi"] == []
