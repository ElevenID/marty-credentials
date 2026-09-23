from __future__ import annotations

import ast
import asyncio
import json
import logging
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

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


def test_native_extension_does_not_require_retired_internal_didcomm_adapters(monkeypatch) -> None:
    from issuance.application import rust_integration

    retired = {"didcomm_decrypt", "didcomm_unpack_message"}
    assert retired.isdisjoint(rust_integration.REQUIRED_MARTY_RS_CAPABILITIES)
    assert all(not hasattr(rust_integration, name) for name in retired)
    # Outbound delivery remains supported, including authenticated encryption.
    assert {
        "didcomm_encrypt",
        "didcomm_encrypt_authcrypt",
        "didcomm_pack_credential",
        "didcomm_extract_endpoint",
        "didcomm_resolve_did_with_metadata",
    }.issubset(rust_integration.REQUIRED_MARTY_RS_CAPABILITIES)
    module = SimpleNamespace(
        **{name: (lambda: None) for name in rust_integration.REQUIRED_MARTY_RS_CAPABILITIES}
    )
    assert all(not hasattr(module, name) for name in retired)
    monkeypatch.setattr(rust_integration, "get_marty_rs", lambda: module)

    rust_integration.validate_marty_rs_capabilities()


def test_native_didcomm_owner_does_not_require_unreachable_python_crypto_bindings(
    monkeypatch,
) -> None:
    from issuance.application import rust_integration

    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", "native")
    monkeypatch.setenv("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance-native:8005")
    required = rust_integration.required_marty_rs_capabilities()
    assert {
        "didcomm_encrypt",
        "didcomm_encrypt_authcrypt",
        "didcomm_extract_endpoint",
        "didcomm_pack_credential",
        "didcomm_resolve_did_with_metadata",
    }.isdisjoint(required)
    module = SimpleNamespace(**{name: (lambda: None) for name in required})
    monkeypatch.setattr(rust_integration, "get_marty_rs", lambda: module)

    rust_integration.validate_marty_rs_capabilities()


@pytest.mark.parametrize(
    ("owner", "url"),
    [
        ("native", ""),
        ("other", "http://issuance-native:8005"),
        ("native", "file:///run/issuance.sock"),
        ("native", "http://user:secret@issuance-native:8005"),
        ("native", "http://issuance-native:8005/untrusted-path"),
        ("native", "http://issuance-native:not-a-port"),
        ("native", "http://issuance-native:0"),
        ("native", "http://issuance-native:65536"),
    ],
)
def test_native_didcomm_owner_configuration_fails_closed(monkeypatch, owner, url) -> None:
    from issuance.application.didcomm_owner import didcomm_delivery_owner

    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", owner)
    monkeypatch.setenv("ISSUANCE_NATIVE_SERVICE_URL", url)
    with pytest.raises(RuntimeError):
        didcomm_delivery_owner()


@pytest.mark.asyncio
async def test_legacy_didcomm_owner_readiness_never_contacts_native(monkeypatch) -> None:
    from issuance import main

    monkeypatch.delenv("DIDCOMM_DELIVERY_OWNER", raising=False)
    monkeypatch.delenv("ISSUANCE_NATIVE_SERVICE_URL", raising=False)

    class UnexpectedClient:
        def __init__(self, **_options) -> None:
            raise AssertionError("legacy readiness must not contact the native owner")

    monkeypatch.setattr(main.httpx, "AsyncClient", UnexpectedClient)

    await main._require_didcomm_owner_ready()


@pytest.mark.asyncio
async def test_native_didcomm_owner_readiness_is_bounded_and_ignores_ambient_proxy(
    monkeypatch,
) -> None:
    from issuance import main

    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", "native")
    monkeypatch.setenv("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance-native:8005")
    monkeypatch.setenv("HTTP_PROXY", "http://ambient-proxy.example:8080")
    observed = {}

    class Client:
        def __init__(self, **options) -> None:
            observed["options"] = options

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def get(self, url):
            observed["url"] = url
            return main.httpx.Response(
                200,
                request=main.httpx.Request("GET", url),
                json={"status": "healthy"},
            )

    monkeypatch.setattr(main.httpx, "AsyncClient", Client)

    await main._require_didcomm_owner_ready()

    assert observed == {
        "options": {
            "timeout": main.httpx.Timeout(5.0, connect=2.0),
            "follow_redirects": False,
            "trust_env": False,
        },
        "url": "http://issuance-native:8005/ready",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_kind", ["status", "transport"])
async def test_native_didcomm_owner_readiness_fails_closed_without_private_details(
    monkeypatch,
    caplog,
    failure_kind,
) -> None:
    from fastapi import HTTPException
    from issuance import main

    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", "native")
    monkeypatch.setenv("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance-native:8005")

    class Client:
        def __init__(self, **_options) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def get(self, url):
            request = main.httpx.Request("GET", url)
            if failure_kind == "transport":
                raise main.httpx.ConnectError("private-native-detail", request=request)
            return main.httpx.Response(
                503,
                request=request,
                text="private-native-detail",
            )

    monkeypatch.setattr(main.httpx, "AsyncClient", Client)

    with caplog.at_level(logging.WARNING), pytest.raises(HTTPException) as failure:
        await main._require_didcomm_owner_ready()

    assert failure.value.status_code == 503
    assert failure.value.detail == "Native issuance service is unavailable"
    assert "private-native-detail" not in caplog.text
    records = [
        record
        for record in caplog.records
        if record.name == "issuance.main" and "DIDComm owner" in record.getMessage()
    ]
    assert len(records) == 1


@pytest.mark.asyncio
async def test_native_didcomm_owner_does_not_treat_liveness_as_readiness(monkeypatch) -> None:
    from fastapi import HTTPException
    from issuance import main

    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", "native")
    monkeypatch.setenv("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance-native:8005")
    requested = []

    class Client:
        def __init__(self, **_options) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def get(self, url):
            requested.append(url)
            status = 200 if url.endswith("/health") else 503
            return main.httpx.Response(
                status,
                request=main.httpx.Request("GET", url),
            )

    monkeypatch.setattr(main.httpx, "AsyncClient", Client)

    with pytest.raises(HTTPException) as failure:
        await main._require_didcomm_owner_ready()

    assert failure.value.status_code == 503
    assert requested == ["http://issuance-native:8005/ready"]


@pytest.mark.asyncio
async def test_native_didcomm_owner_readiness_has_strict_wall_clock_deadline(
    monkeypatch,
    caplog,
) -> None:
    from fastapi import HTTPException
    from issuance import main

    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", "native")
    monkeypatch.setenv("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance-native:8005")
    monkeypatch.setattr(main, "_DIDCOMM_OWNER_READY_TIMEOUT_SECONDS", 0.01)

    class Client:
        def __init__(self, **_options) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def get(self, _url):
            await asyncio.Event().wait()

    monkeypatch.setattr(main.httpx, "AsyncClient", Client)

    with caplog.at_level(logging.WARNING), pytest.raises(HTTPException) as failure:
        await asyncio.wait_for(main._require_didcomm_owner_ready(), timeout=1.0)

    assert failure.value.status_code == 503
    assert failure.value.detail == "Native issuance service is unavailable"
    assert "TimeoutError" in caplog.text


@pytest.mark.asyncio
async def test_native_didcomm_owner_invalid_configuration_is_sanitized(
    monkeypatch,
    caplog,
) -> None:
    from fastapi import HTTPException
    from issuance import main

    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", "native")
    monkeypatch.setenv(
        "ISSUANCE_NATIVE_SERVICE_URL",
        "http://private-user:private-password@issuance-native:8005",
    )

    with caplog.at_level(logging.WARNING), pytest.raises(HTTPException) as failure:
        await main._require_didcomm_owner_ready()

    assert failure.value.status_code == 503
    assert failure.value.detail == "Native issuance service is unavailable"
    assert "private-user" not in caplog.text
    assert "private-password" not in caplog.text
    assert "RuntimeError" in caplog.text


@pytest.mark.asyncio
async def test_health_remains_local_liveness_when_native_owner_is_unavailable(
    monkeypatch,
) -> None:
    from issuance import main

    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", "native")
    monkeypatch.setenv("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance-native:8005")

    class UnexpectedClient:
        def __init__(self, **_options) -> None:
            raise AssertionError("liveness must not contact the native owner")

    monkeypatch.setattr(main.httpx, "AsyncClient", UnexpectedClient)
    application = main.create_app()
    health = next(
        route.endpoint
        for route in application.routes
        if getattr(route, "path", None) == "/health"
    )

    assert await health() == {"status": "healthy", "service": main.SERVICE_NAME}


@pytest.mark.asyncio
async def test_ready_endpoint_requires_selected_didcomm_owner(monkeypatch) -> None:
    from issuance import main

    require_owner = AsyncMock()
    monkeypatch.setattr(main, "_require_didcomm_owner_ready", require_owner)
    application = main.create_app()
    readiness = next(
        route.endpoint
        for route in application.routes
        if getattr(route, "path", None) == "/ready"
    )

    assert await readiness() == {"status": "ready", "service": main.SERVICE_NAME}
    require_owner.assert_awaited_once_with()


@pytest.mark.parametrize("missing", [True, False], ids=["missing", "noncallable"])
def test_native_extension_still_rejects_every_remaining_invalid_capability(
    monkeypatch,
    missing: bool,
) -> None:
    from issuance.application import rust_integration
    from marty_credentials.native_backend import NativeBackendUnavailable

    required = rust_integration.REQUIRED_MARTY_RS_CAPABILITIES
    assert required
    for capability in sorted(required):
        module = SimpleNamespace(**{name: (lambda: None) for name in required})
        if missing:
            delattr(module, capability)
        else:
            setattr(module, capability, object())
        monkeypatch.setattr(rust_integration, "get_marty_rs", lambda current=module: current)
        with pytest.raises(NativeBackendUnavailable) as failure:
            rust_integration.validate_marty_rs_capabilities()
        assert str(failure.value) == (
            "marty-rs native extension is missing required capabilities: " + capability
        )


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

    issuer_public_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": "issuer-public-x",
        "y": "issuer-public-y",
    }

    sd_jwt = await rust_integration.create_sd_jwt_vc_with_remote_signing(
        issuer_did="did:web:issuer.example",
        remote_sign=remote_sign,
        subject_id="did:key:holder",
        credential_type="AccessBadge",
        claims_json='{"name":"Alice"}',
        issuer_public_jwk=issuer_public_jwk,
        algorithm="ES256",
        verification_method_id="did:web:issuer.example#key-1",
    )
    jwt_vc = await rust_integration.create_jwt_vc_with_remote_signing(
        issuer_did="did:web:issuer.example",
        remote_sign=remote_sign,
        subject_id="did:key:holder",
        credential_type="AccessBadge",
        claims_json='{"name":"Alice"}',
        issuer_public_jwk=issuer_public_jwk,
        algorithm="ES256",
        verification_method_id="did:web:issuer.example#key-1",
    )

    assert sd_jwt == ("sd.header.payload.AQID~", "urn:uuid:sd")
    assert jwt_vc == ("jwt.header.payload.AQID", "urn:uuid:jwt")
    assert ("sign", (b"sd.header.payload", "ES256")) in calls
    assert ("sign", (b"jwt.header.payload", "ES256")) in calls
    expected_jwk_json = json.dumps(issuer_public_jwk, separators=(",", ":"))
    prepare_sd_args = next(value for name, value in calls if name == "prepare_sd_jwt")
    prepare_jwt_args = next(value for name, value in calls if name == "prepare_jwt_vc")
    assert prepare_sd_args[3] == expected_jwk_json
    assert prepare_jwt_args[3] == expected_jwk_json
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

    assert "COPY release-deps /release-deps" in dockerfile
    assert "pip install --no-cache-dir /release-deps/*.whl" in dockerfile
    assert "validate_marty_rs_capabilities()" in dockerfile
    assert "DIDCOMM_DELIVERY_OWNER=native" in dockerfile
    assert "ISSUANCE_NATIVE_SERVICE_URL=http://issuance-native:8005" in dockerfile
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
    assert verification_release["commit"] != core_release["commit"]
    assert set(verification_release["platform_assets"]) == {
        "linux-x86_64",
        "macos-arm64",
        "windows-x86_64",
    }
    source_revision = core_release["commit"]
    verification_source_revision = verification_release["commit"]
    assert len(source_revision) == 40
    assert len(verification_source_revision) == 40

    ci_workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert f"MARTY_RS_CORE_REVISION: {source_revision}" in ci_workflow
    assert (
        f"MARTY_VERIFICATION_CORE_REVISION: {verification_source_revision}"
        in ci_workflow
    )
    assert "maturin build --release --compatibility off" in ci_workflow
    assert "--features extension-module,kms-only,ephemeral-session-keys" in ci_workflow
    assert (
        "--features pyo3/extension-module,python,iaca,csca,eudi"
        in ci_workflow
    )
    assert "didcomm-local-keys" not in ci_workflow
    assert "name: core-python-${{ runner.os }}" in ci_workflow


def test_local_compatibility_binding_cannot_replace_the_production_core_wheel() -> None:
    from issuance.application import rust_integration

    local_source = (ROOT / "rust" / "marty-rs" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    dockerfile = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")
    python_ci = (ROOT / "scripts" / "run-python-ci.sh").read_text(encoding="utf-8")

    # This startup capability is owned by canonical Core and deliberately is
    # not exported by Credentials' separately tested compatibility extension.
    assert "canvas_normalize_base_url" in rust_integration.required_marty_rs_capabilities()
    assert "canvas_normalize_base_url" not in local_source
    assert "COPY release-deps /release-deps" in dockerfile
    assert "pip install --no-cache-dir /release-deps/*.whl" in dockerfile
    assert "pathlib.Path('release-deps').glob('*.whl')" in python_ci
    assert "DIDCOMM_DELIVERY_OWNER=native" in python_ci
    assert "ISSUANCE_NATIVE_SERVICE_URL=http://issuance-native:8005" in python_ci
    assert "local-wheels" not in dockerfile
    assert "local-wheels" not in python_ci


def test_release_image_uses_the_pinned_canonical_core_wheels() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release-images.yml").read_text(encoding="utf-8")
    issuance_image = (ROOT / "services" / "Dockerfile").read_text(encoding="utf-8")

    dependency_loop = "for dependency in marty-rs marty-verification marty-common; do"
    assert dependency_loop in workflow
    assert "draft-release.json" not in workflow
    assert "Draft must contain exactly one Linux x86_64 marty-rs wheel" not in workflow
    assert "marty_rs_asset_id" not in workflow
    assert "marty_rs_sha256=$(jq -r" in workflow
    assert "marty_verification_sha256=$(jq -r" in workflow
    assert "COPY python/marty_credentials /app/marty_credentials" in issuance_image
    assert "ARG MARTY_VERIFICATION_WHEEL" in issuance_image
    assert "ARG MARTY_VERIFICATION_SHA256" in issuance_image
    assert "validate_marty_rs_capabilities()" in issuance_image

    stable_release = (ROOT / ".github" / "workflows" / "release-stable.yml").read_text(
        encoding="utf-8"
    )
    python_ci = (ROOT / "scripts" / "run-python-ci.sh").read_text(encoding="utf-8")
    assert "bash scripts/run-python-ci.sh" in stable_release
    assert "DIDCOMM_DELIVERY_OWNER=native" in python_ci
    assert "ISSUANCE_NATIVE_SERVICE_URL=http://issuance-native:8005" in python_ci


def test_runtime_and_release_inputs_do_not_depend_on_python_mmf() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    dependencies = json.loads((ROOT / "release" / "dependencies.json").read_text(encoding="utf-8"))
    runtime_inputs = [
        ROOT / "services" / "Dockerfile",
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
