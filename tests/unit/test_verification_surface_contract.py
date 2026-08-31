"""Feature-loss gates for verification-image consolidation."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts" / "verification_surface_contract.py"
SPEC = importlib.util.spec_from_file_location("verification_surface_contract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
surface = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = surface
SPEC.loader.exec_module(surface)


def test_frozen_verification_surface_matches_python_oracle() -> None:
    surface.check_contract()


def test_contract_is_identical_on_supported_python_ast_versions() -> None:
    launcher = shutil.which("py")
    if launcher is None:
        pytest.skip("Python launcher is unavailable")
    inventory = subprocess.run(
        [launcher, "-0p"], capture_output=True, check=True, text=True
    ).stdout.splitlines()
    runtimes: dict[str, str] = {}
    for line in inventory:
        for version in ("3.11", "3.12"):
            if version in line:
                drive_separator = line.find(":\\")
                if drive_separator > 0:
                    runtimes[version] = line[drive_separator - 1 :].strip()
    if set(runtimes) != {"3.11", "3.12"}:
        pytest.skip("Both supported Python AST runtimes are unavailable")
    code = (
        "import runpy; "
        f"scope=runpy.run_path({str(SCRIPT)!r}); "
        "print(scope['_render'](scope['build_contract']()), end='')"
    )
    rendered = {
        version: subprocess.run(
            [runtime, "-c", code], capture_output=True, check=True, text=True, cwd=ROOT
        ).stdout
        for version, runtime in runtimes.items()
    }
    assert rendered["3.11"] == rendered["3.12"]


def test_contract_covers_every_current_runtime_boundary() -> None:
    contract = surface.build_contract()

    assert contract["schema"] == "marty.verification-runtime-surface/v1"
    assert contract["http"]["route_count"] == 7
    assert contract["migrations"]["revision_count"] == 2
    assert contract["migrations"]["heads"] == ["202608091200"]
    assert contract["runtime"]["modes"][0]["name"] == "api"
    assert contract["packaging"]["expose"] == "8006"
    assert contract["runtime"]["modes"][0]["port"] == contract["packaging"]["expose"]
    assert contract["runtime"]["modes"][0]["command"] == contract["packaging"]["command"]
    assert contract["runtime"]["modes"][1] | {"documentation_sha256": "ignored"} == {
        "name": "migrations",
        "command_prefix": ["python", "-m", "verification.manage_migrations"],
        "deployment_command": ["python", "-m", "verification.manage_migrations", "upgrade"],
        "supported_operations": ["current", "history", "upgrade"],
        "dispatch": {
            "upgrade": [
                {
                    "handler": "ensure_version_schema",
                    "arguments": ["database_url"],
                    "keywords": {},
                },
                {
                    "handler": "command.upgrade",
                    "arguments": ["config", "'head'"],
                    "keywords": {},
                },
            ],
            "current": [{"handler": "command.current", "arguments": ["config"], "keywords": {}}],
            "history": [
                {
                    "handler": "command.history",
                    "arguments": ["config"],
                    "keywords": {"verbose": "True"},
                }
            ],
        },
        "source": "services/verification/manage_migrations.py",
        "documentation_sha256": "ignored",
    }
    assert "http://localhost:8006/health" in contract["packaging"]["health_command"]


def test_contract_retains_public_routes_and_governed_purposes() -> None:
    contract = surface.build_contract()
    routes = {(route["method"], route["path"]) for route in contract["http"]["routes"]}

    assert routes == {
        ("GET", "/health"),
        ("GET", "/v1/verification/health"),
        ("GET", "/v1/verification/sessions/{session_id}"),
        ("POST", "/v1/verification/sessions"),
        ("POST", "/v1/verification/sessions/{session_id}/submit"),
        ("POST", "/v1/verification/verify"),
        ("POST", "/v1/verification/verify/vds-nc"),
    }
    assert contract["governance"]["purposes"] == [
        "verification.direct",
        "verification.session.create",
        "verification.vds-nc",
    ]
    assert contract["governance"]["processing_states"] == [
        "COMPLETED",
        "ERROR",
        "UNAVAILABLE",
        "UNSUPPORTED",
    ]


def test_contract_retains_request_and_result_shapes() -> None:
    models = {model["name"]: model for model in surface.build_contract()["dto"]["models"]}
    create_fields = {field["name"] for field in models["CreateSessionRequest"]["fields"]}
    result_fields = {field["name"] for field in models["VerificationResult"]["fields"]}

    assert create_fields == {
        "presentation_definition",
        "session_duration_seconds",
        "verifier_did",
    }
    assert {
        "canonical_result",
        "processing_status",
        "decision",
        "decision_code",
        "valid",
        "verified_claims",
        "verification_method",
        "error",
    } <= result_fields
    assert models["CreateSessionRequest"]["model_config"] == "ConfigDict(extra='forbid')"
    assert models["VerifyDirectRequest"]["model_config"] == "ConfigDict(extra='forbid')"
    assert [validator["name"] for validator in models["VerificationResult"]["validators"]] == [
        "derive_compatibility_projection"
    ]
    assert models["VerificationResult"]["validators"][0]["decorators"] == [
        "model_validator(mode='after')"
    ]


def test_contract_retains_authorization_and_error_mapping() -> None:
    contract = surface.build_contract()
    routes = {(route["method"], route["path"]): route for route in contract["http"]["routes"]}

    create = routes[("POST", "/v1/verification/sessions")]
    direct = routes[("POST", "/v1/verification/verify")]
    submit = routes[("POST", "/v1/verification/sessions/{session_id}/submit")]
    vds = routes[("POST", "/v1/verification/verify/vds-nc")]
    assert create["request_model"] == "CreateSessionRequest"
    assert create["dependencies"] == ["_authorize_session_create", "get_verification_service"]
    assert direct["dependencies"] == ["_authorize_direct_verify", "get_verification_service"]
    assert vds["dependencies"] == ["_authorize_vds_nc_verify", "get_credential_verifier"]
    assert submit["dependencies"] == ["get_verification_service"]
    submit_statuses = {error["status"] for error in submit["declared_errors"]}
    assert {
        400,
        404,
        409,
        410,
        422,
        500,
    } <= submit_statuses
    authorization = contract["authorization"]
    expected_header = {
        "alias": "X-API-Key",
        "annotation": "str | None",
        "default": "None",
    }
    assert authorization["api_key_header"] == expected_header
    assert authorization["purpose_wrappers"] == {
        "_authorize_direct_verify": {
            "purpose": "verification.direct",
            "header": expected_header,
            "forwarded_argument": "x_api_key",
        },
        "_authorize_session_create": {
            "purpose": "verification.session.create",
            "header": expected_header,
            "forwarded_argument": "x_api_key",
        },
        "_authorize_vds_nc_verify": {
            "purpose": "verification.vds-nc",
            "header": expected_header,
            "forwarded_argument": "x_api_key",
        },
    }
    assert {(error["status"], error["detail"]) for error in authorization["errors"]} == {
        (401, "Invalid or unauthorized API key"),
        (401, "X-API-Key header is missing"),
        (503, "Verification governance is unavailable"),
    }


def test_contract_retains_health_response_shapes() -> None:
    routes = {route["path"]: route for route in surface.build_contract()["http"]["routes"]}
    assert routes["/v1/verification/health"]["literal_response_shape"] == {
        "status": {"literal": "healthy"}
    }
    assert routes["/health"]["literal_response_shape"] == {
        "status": {"literal": "healthy"},
        "service": {"literal": "verification"},
        "native_backend": {"expression": "marty_rs_diagnostic(REQUIRED_MARTY_RS_CAPABILITIES)"},
    }


def test_contract_retains_fail_closed_configuration() -> None:
    variables = set(surface.build_contract()["configuration"]["environment_variables"])
    assert {
        "DATABASE_URL",
        "SIGNING_KEYS_INTERNAL_API_KEY",
        "SIGNING_KEYS_INTERNAL_API_KEY_FILE",
        "SIGNING_KEYS_INTERNAL_URL",
        "VERIFICATION_GOVERNANCE_JSON",
        "VERIFICATION_PROCESSING_LEASE_SECONDS",
    } <= variables
    governance = surface.build_contract()["governance"]
    assert len(governance["required_native_capabilities"]) == 13
    assert surface.build_contract()["runtime"]["startup_validation_hooks"] == [
        "load_governance",
        "validate_internal_resolver_configuration",
        "validate_marty_rs_capabilities",
    ]
    semantics = surface.build_contract()["configuration"]["semantics"]
    lease = semantics["processing_lease_seconds"]
    assert {key: value for key, value in lease.items() if key != "behavior_sha256"} == {
        "environment_variable": "VERIFICATION_PROCESSING_LEASE_SECONDS",
        "default": 60,
        "minimum": 5,
        "maximum": 300,
    }
    assert semantics["signing_keys"]["base_url_default"] == (
        "http://gateway:8000/internal/signing-keys"
    )
    assert semantics["signing_keys"]["api_key_precedence"] == ["name", "f'{name}_FILE'"]
    assert semantics["did_web_egress"]["requires_production_allowlist"] is True
    assert semantics["did_web_egress"]["requires_production_default_https_port"] is True
    assert semantics["database"]["api"] | {"behavior_sha256": "ignored"} == {
        "accepted_postgresql_driver_aliases": [
            "postgres",
            "postgresql",
            "postgresql+psycopg",
            "postgresql+psycopg2",
        ],
        "normalized_driver": "postgresql+asyncpg",
        "behavior_sha256": "ignored",
    }
    assert semantics["database"]["migrations"]["normalized_driver"] == "postgresql+psycopg"
    assert semantics["database"]["migrations"]["version_schema"] == "verification_service"


def _sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    service = tmp_path / "services" / "verification"
    service.parent.mkdir(parents=True)
    shutil.copytree(ROOT / "services" / "verification", service)
    manifest = tmp_path / "contracts" / "verification-runtime-surface.json"
    manifest.parent.mkdir()
    shutil.copy2(ROOT / "contracts" / "verification-runtime-surface.json", manifest)
    monkeypatch.setattr(surface, "ROOT", tmp_path)
    monkeypatch.setattr(surface, "SERVICE_ROOT", service)
    monkeypatch.setattr(surface, "MANIFEST", manifest)
    return service


def _assert_mutation_detected() -> None:
    with pytest.raises(surface.ContractError):
        surface.check_contract()


def test_route_authorization_mutation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    routes = service / "infrastructure" / "api" / "routes.py"
    routes.write_text(
        routes.read_text(encoding="utf-8").replace(
            "Depends(_authorize_direct_verify)", "Depends(_authorize_session_create)", 1
        ),
        encoding="utf-8",
    )
    _assert_mutation_detected()


def test_governance_purpose_mutation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    governance = service / "application" / "governance.py"
    governance.write_text(
        governance.read_text(encoding="utf-8").replace(
            'DIRECT_VERIFY_PURPOSE = "verification.direct"',
            'DIRECT_VERIFY_PURPOSE = "verification.direct.changed"',
        ),
        encoding="utf-8",
    )
    _assert_mutation_detected()


def test_startup_validation_mutation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    main = service / "main.py"
    main.write_text(
        main.read_text(encoding="utf-8").replace("    load_governance()\n", "", 1),
        encoding="utf-8",
    )
    _assert_mutation_detected()


def test_migration_semantic_mutation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    migration = (
        service
        / "infrastructure"
        / "migrations"
        / "versions"
        / "20260809_1200_atomic_verification_sessions.py"
    )
    migration.write_text(
        migration.read_text(encoding="utf-8").replace(
            "ux_verification_sessions_live_nonce", "ux_verification_sessions_live_nonce_changed"
        ),
        encoding="utf-8",
    )
    _assert_mutation_detected()


def test_contract_hashes_are_line_ending_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    migration = (
        service
        / "infrastructure"
        / "migrations"
        / "versions"
        / "20260809_1200_atomic_verification_sessions.py"
    )
    normalized = migration.read_text(encoding="utf-8").replace("\r\n", "\n")
    migration.write_bytes(normalized.encode("utf-8"))
    lf_contract = surface.build_contract()
    migration.write_bytes(normalized.replace("\n", "\r\n").encode("utf-8"))
    assert surface.build_contract() == lf_contract


@pytest.mark.parametrize(
    "wrapper",
    [
        "_authorize_session_create",
        "_authorize_direct_verify",
        "_authorize_vds_nc_verify",
    ],
)
def test_public_authorization_header_mutation_is_detected(
    wrapper: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    routes = service / "infrastructure" / "api" / "routes.py"
    signature = (
        f'async def {wrapper}(\n    x_api_key: str | None = Header(None, alias="X-API-Key"),'
    )
    routes.write_text(
        routes.read_text(encoding="utf-8").replace(
            "".join(signature),
            "".join(signature).replace("X-API-Key", "X-Changed-Key"),
        ),
        encoding="utf-8",
    )
    _assert_mutation_detected()


def test_authorization_error_mutation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    routes = service / "infrastructure" / "api" / "routes.py"
    routes.write_text(
        routes.read_text(encoding="utf-8").replace("status_code=401", "status_code=403", 1),
        encoding="utf-8",
    )
    _assert_mutation_detected()


def test_authorization_wrapper_purpose_mutation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    routes = service / "infrastructure" / "api" / "routes.py"
    routes.write_text(
        routes.read_text(encoding="utf-8").replace(
            "return await _authorize(DIRECT_VERIFY_PURPOSE, x_api_key)",
            "return await _authorize(SESSION_CREATE_PURPOSE, x_api_key)",
        ),
        encoding="utf-8",
    )
    _assert_mutation_detected()


def test_authorization_wrapper_forwarding_mutation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    routes = service / "infrastructure" / "api" / "routes.py"
    routes.write_text(
        routes.read_text(encoding="utf-8").replace(
            "return await _authorize(DIRECT_VERIFY_PURPOSE, x_api_key)",
            "return await _authorize(DIRECT_VERIFY_PURPOSE, None)",
        ),
        encoding="utf-8",
    )
    _assert_mutation_detected()


def test_authorization_dead_call_bypass_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    routes = service / "infrastructure" / "api" / "routes.py"
    routes.write_text(
        routes.read_text(encoding="utf-8").replace(
            "return await _authorize(DIRECT_VERIFY_PURPOSE, x_api_key)",
            "return await _authorize(DIRECT_VERIFY_PURPOSE, x_api_key) if False else None",
        ),
        encoding="utf-8",
    )
    _assert_mutation_detected()


def test_validator_decorator_mutation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    models = service / "infrastructure" / "api" / "models.py"
    models.write_text(
        models.read_text(encoding="utf-8").replace(
            '@model_validator(mode="after")', '@model_validator(mode="before")', 1
        ),
        encoding="utf-8",
    )
    _assert_mutation_detected()


def test_added_dto_mutation_is_detected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    models = service / "infrastructure" / "api" / "models.py"
    models.write_text(
        models.read_text(encoding="utf-8")
        + "\n\nclass AddedContractModel(BaseModel):\n    value: str\n",
        encoding="utf-8",
    )
    _assert_mutation_detected()


def test_inherited_dto_mutation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    models = service / "infrastructure" / "api" / "models.py"
    models.write_text(
        models.read_text(encoding="utf-8")
        + (
            "\n\nclass CommonContractModel(BaseModel):\n"
            "    common: str\n\n"
            "class SpecializedContractModel(CommonContractModel):\n"
            "    specialized: str\n"
        ),
        encoding="utf-8",
    )
    names = {model["name"] for model in surface.build_contract()["dto"]["models"]}
    assert {"CommonContractModel", "SpecializedContractModel"} <= names
    models_by_name = {model["name"]: model for model in surface.build_contract()["dto"]["models"]}
    assert models_by_name["SpecializedContractModel"]["bases"] == ["CommonContractModel"]
    assert {field["name"] for field in models_by_name["SpecializedContractModel"]["fields"]} == {
        "common",
        "specialized",
    }
    _assert_mutation_detected()


@pytest.mark.parametrize(
    ("relative", "old", "new"),
    [
        ("main.py", '"service": "verification",\n', ""),
        (
            "infrastructure/api/routes.py",
            'return {"status": "healthy"}',
            'return {"status": "ready"}',
        ),
    ],
)
def test_health_response_mutation_is_detected(
    relative: str,
    old: str,
    new: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    source = service / relative
    source.write_text(source.read_text(encoding="utf-8").replace(old, new, 1), encoding="utf-8")
    _assert_mutation_detected()


@pytest.mark.parametrize(
    ("relative", "old", "new"),
    [
        (
            "application/service.py",
            "DEFAULT_PROCESSING_LEASE_SECONDS = 60",
            "DEFAULT_PROCESSING_LEASE_SECONDS = 90",
        ),
        (
            "application/did_resolver.py",
            "http://gateway:8000/internal/signing-keys",
            "http://gateway:9000/internal/signing-keys",
        ),
        (
            "application/did_resolver.py",
            "direct = os.environ.get(name)",
            'direct = os.environ.get(f"{name}_FILE")',
        ),
        (
            "application/did_resolver.py",
            'environment in {"production", "prod"} and not configured_hosts',
            'environment in {"production", "prod"} and False',
        ),
    ],
)
def test_configuration_semantic_mutation_is_detected(
    relative: str,
    old: str,
    new: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    source = service / relative
    source.write_text(source.read_text(encoding="utf-8").replace(old, new, 1), encoding="utf-8")
    _assert_mutation_detected()


@pytest.mark.parametrize(
    ("relative", "old", "new"),
    [
        (
            "infrastructure/persistence/database.py",
            '"postgresql+psycopg2",',
            '"postgresql+pg8000",',
        ),
        (
            "infrastructure/persistence/database.py",
            'drivername="postgresql+asyncpg"',
            'drivername="postgresql+psycopg"',
        ),
        (
            "manage_migrations.py",
            'drivername="postgresql+psycopg"',
            'drivername="postgresql+psycopg2"',
        ),
        (
            "manage_migrations.py",
            'VERSION_SCHEMA = "verification_service"',
            'VERSION_SCHEMA = "public"',
        ),
    ],
)
def test_database_contract_mutation_is_detected(
    relative: str,
    old: str,
    new: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    source = service / relative
    source.write_text(source.read_text(encoding="utf-8").replace(old, new, 1), encoding="utf-8")
    _assert_mutation_detected()


def test_migration_cli_operation_mutation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    source = service / "manage_migrations.py"
    source.write_text(
        source.read_text(encoding="utf-8").replace(
            'choices=("upgrade", "current", "history")',
            'choices=("upgrade", "current")',
        ),
        encoding="utf-8",
    )
    _assert_mutation_detected()


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('command.upgrade(config, "head")', "command.current(config)"),
        ("        command.current(config)\n", "        pass\n"),
        ('if args.command == "upgrade":', 'if False == "upgrade":'),
    ],
)
def test_migration_cli_dispatch_mutation_is_detected(
    old: str,
    new: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    source = service / "manage_migrations.py"
    source.write_text(source.read_text(encoding="utf-8").replace(old, new, 1), encoding="utf-8")
    _assert_mutation_detected()
