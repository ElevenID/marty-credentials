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


@pytest.mark.parametrize(
    "relative_path",
    [
        Path("services/issuance/main.py"),
        Path("services/issuance/canvas_worker.py"),
    ],
)
def test_runtime_database_engines_hide_statement_parameters(relative_path: Path) -> None:
    tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
    engine_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "create_async_engine"
    ]

    assert len(engine_calls) == 1, relative_path
    hide_parameters = next(
        (keyword.value for keyword in engine_calls[0].keywords if keyword.arg == "hide_parameters"),
        None,
    )
    assert isinstance(hide_parameters, ast.Constant), relative_path
    assert hide_parameters.value is True, relative_path


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
    reload_keyword = next(
        keyword for keyword in production_call.keywords if keyword.arg == "reload"
    )
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


def test_native_extension_capability_contract_rejects_incomplete_module(monkeypatch) -> None:
    from issuance.application import rust_integration

    monkeypatch.setattr(rust_integration, "get_marty_rs", lambda: SimpleNamespace())

    with pytest.raises(RuntimeError, match="oid4vci_create_credential_offer"):
        rust_integration.validate_marty_rs_capabilities()


def test_native_extension_capability_contract_requires_remote_mdoc_split_signing(
    monkeypatch,
) -> None:
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


def test_native_extension_contract_requires_remote_jwt_prepare_and_assemble() -> None:
    from issuance.application import rust_integration

    assert {
        "oid4vci_prepare_sd_jwt",
        "oid4vci_assemble_sd_jwt",
        "oid4vci_prepare_jwt_vc",
        "oid4vci_prepare_open_badge_v3_jwt_vc",
        "oid4vci_assemble_jwt_vc",
    }.issubset(rust_integration.REQUIRED_MARTY_RS_CAPABILITIES)

    source = (ROOT / "services/issuance/application/rust_integration.py").read_text(
        encoding="utf-8"
    )
    sd_jwt_body = source.split("async def create_sd_jwt_vc_with_remote_signing", 1)[1].split(
        "async def create_jwt_vc_with_remote_signing", 1
    )[0]
    jwt_vc_body = source.split("async def create_jwt_vc_with_remote_signing", 1)[1].split(
        "_PRIVATE_JWK_MEMBERS", 1
    )[0]
    for prohibited in ("hashlib", "secrets.token_bytes", "encoded_header", "encoded_payload"):
        assert prohibited not in sd_jwt_body
        assert prohibited not in jwt_vc_body


def test_native_extension_contract_rejects_pre_profile_jwt_binding(monkeypatch) -> None:
    from issuance.application import rust_integration

    required = "oid4vci_prepare_open_badge_v3_jwt_vc"
    incomplete_module = SimpleNamespace(
        **{
            capability: (lambda: None)
            for capability in rust_integration.REQUIRED_MARTY_RS_CAPABILITIES
            if capability != required
        }
    )
    monkeypatch.setattr(rust_integration, "get_marty_rs", lambda: incomplete_module)

    with pytest.raises(RuntimeError, match=required):
        rust_integration.validate_marty_rs_capabilities()


@pytest.mark.asyncio
async def test_remote_jwt_signing_uses_native_opaque_preparation(monkeypatch) -> None:
    from issuance.application import rust_integration

    calls: list[tuple[str, object]] = []

    class Extension:
        def oid4vci_prepare_sd_jwt(self, *args):
            calls.append(("prepare_sd_jwt", args))
            return SimpleNamespace(signing_input="sd.header.payload")

        def oid4vci_assemble_sd_jwt(self, prepared, signature):
            calls.append(("assemble_sd_jwt", (prepared, signature)))
            return "sd.header.payload.AQID~", "urn:uuid:sd"

        def oid4vci_prepare_jwt_vc(self, *args):
            calls.append(("prepare_jwt_vc", args))
            return SimpleNamespace(signing_input="jwt.header.payload")

        def oid4vci_assemble_jwt_vc(self, prepared, signature):
            calls.append(("assemble_jwt_vc", (prepared, signature)))
            return "jwt.header.payload.AQID", "urn:uuid:jwt"

    async def remote_sign(message: bytes, algorithm: str | None):
        calls.append(("sign", (message, algorithm)))
        return {"signature_raw_b64": "AQID", "algorithm": algorithm}

    monkeypatch.setattr(rust_integration, "get_marty_rs", lambda: Extension())

    sd_jwt = await rust_integration.create_sd_jwt_vc_with_remote_signing(
        issuer_did="did:web:issuer.example",
        remote_sign=remote_sign,
        subject_id="did:key:holder",
        credential_type="AccessBadge",
        claims_json='{"name":"Alice"}',
        algorithm="ES256",
        verification_method_id="did:web:issuer.example#key-1",
    )
    jwt_vc = await rust_integration.create_jwt_vc_with_remote_signing(
        issuer_did="did:web:issuer.example",
        remote_sign=remote_sign,
        subject_id="did:key:holder",
        credential_type="AccessBadge",
        claims_json='{"name":"Alice"}',
        algorithm="ES256",
        verification_method_id="did:web:issuer.example#key-1",
    )

    assert sd_jwt == ("sd.header.payload.AQID~", "urn:uuid:sd")
    assert jwt_vc == ("jwt.header.payload.AQID", "urn:uuid:jwt")
    assert ("sign", (b"sd.header.payload", "ES256")) in calls
    assert ("sign", (b"jwt.header.payload", "ES256")) in calls
    assert any(name == "assemble_sd_jwt" for name, _ in calls)
    assert any(name == "assemble_jwt_vc" for name, _ in calls)


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
    verification_release = dependencies["marty-verification"]
    assert verification_release["repository"] == "ElevenID/marty-core"
    assert verification_release["tag"] == f"v{verification_release['version']}"
    assert verification_release["asset"].startswith(
        f"marty_verification_py-{verification_release['version']}-"
    )
    assert verification_release["commit"] == core_release["commit"]
    assert set(verification_release["platform_assets"]) == {
        "linux-x86_64",
        "macos-arm64",
        "windows-x86_64",
    }
    core_revisions = {
        cargo["workspace"]["dependencies"][package]["rev"]
        for package in ("marty-crypto", "marty-verification", "marty-oid4vci")
    }
    assert len(core_revisions) == 1
    source_revision = core_revisions.pop()
    assert len(source_revision) == 40

    ci_workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert f"MARTY_CORE_REVISION: {source_revision}" in ci_workflow
    assert "maturin build --release --compatibility off" in ci_workflow
    assert "name: core-python-${{ runner.os }}" in ci_workflow


def test_release_images_use_the_pinned_canonical_core_wheel() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release-images.yml").read_text(encoding="utf-8")
    verification_image = (ROOT / "services" / "verification" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    dependency_loop = "for dependency in marty-rs marty-verification marty-common; do"
    assert dependency_loop in workflow
    assert "draft-release.json" not in workflow
    assert "Draft must contain exactly one Linux x86_64 marty-rs wheel" not in workflow
    assert "marty_rs_asset_id" not in workflow
    assert "marty_rs_sha256=$(jq -r" in workflow
    assert "marty_verification_sha256=$(jq -r" in workflow
    assert "COPY python/marty_credentials /app/marty_credentials" in verification_image
    assert "ARG MARTY_VERIFICATION_WHEEL" in verification_image
    assert "ARG MARTY_VERIFICATION_SHA256" in verification_image
    assert "validate_marty_rs_capabilities()" in verification_image


def test_runtime_and_release_inputs_do_not_depend_on_python_mmf() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    dependencies = json.loads((ROOT / "release" / "dependencies.json").read_text(encoding="utf-8"))
    runtime_inputs = [
        ROOT / "services" / "Dockerfile",
        ROOT / "services" / "verification" / "Dockerfile",
        ROOT / "services" / "issuance" / "manage_migrations.py",
        ROOT / ".github" / "workflows" / "ci.yml",
        ROOT / ".github" / "workflows" / "release-images.yml",
    ]

    assert not any("marty-msf" in dependency.lower() for dependency in project["dependencies"])
    assert "marty-msf" not in dependencies
    for path in runtime_inputs:
        source = path.read_text(encoding="utf-8").lower()
        assert "marty_msf" not in source, path
        assert "marty-msf" not in source, path
        assert "from mmf" not in source, path
        assert "import mmf" not in source, path


def test_fastapi_form_parser_is_an_explicit_runtime_dependency() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert any(
        dependency.startswith("python-multipart>=") for dependency in project["dependencies"]
    )


def test_native_wheel_is_an_explicit_non_bootstrapping_extra() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert not any(dependency.startswith("marty-rs") for dependency in project["dependencies"])
    assert project["optional-dependencies"]["ffi"] == []
