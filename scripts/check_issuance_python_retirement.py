"""Fail-closed qualification gate for deleting Rust-owned issuance Python code."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "contracts/issuance-python-retirement-qualification.json"
QUALIFIED_STATE = "qualified"
BLOCKED_STATE = "blocked_pending_marty_ui_checkpoint"
EXPECTED_SCOPES = {
    "oid4vci-public-and-management-http",
    "canvas-mirror-http",
    "canvas-mirror-automation-loop",
}
EXPECTED_DELETIONS = {
    ("GET", "/v1/issuance/authorize"),
    ("GET", "/v1/issuance/credentials"),
    ("GET", "/v1/issuance/delivery-records/canvas-credentials/provenance"),
    ("GET", "/v1/issuance/organizations/{organization_id}/canvas-mirror-health"),
    ("POST", "/v1/issuance/deferred-credential"),
    ("POST", "/v1/issuance/delivery-records/canvas-credentials/process-pending"),
    (
        "POST",
        "/v1/issuance/delivery-records/canvas-credentials/process-status-sync-failures",
    ),
    ("POST", "/v1/issuance/delivery-records/canvas-credentials/run-automation-cycle"),
    ("POST", "/v1/issuance/notification"),
    ("POST", "/v1/issuance/par"),
    ("POST", "/v1/issuance/transactions/{tx_id}/revoke"),
    (
        "POST",
        "/v1/issued-credentials/{credential_id}/deliveries/canvas-credentials/publish",
    ),
    ("PUT", "/v1/issuance/oid4vci-clients"),
}
EXPECTED_RETAINED = {
    ("GET", "/v1/issuance/organizations/{organization_id}/retention"),
    ("POST", "/v1/issuance/organizations/{organization_id}/retention/purge"),
    ("POST", "/v1/passport/applications"),
    ("POST", "/v1/passport/applications/{application_id}/activate"),
    ("POST", "/v1/passport/applications/{application_id}/generate-data-groups"),
    ("POST", "/v1/passport/applications/{application_id}/generate-sod"),
    ("GET", "/v1/passport/applications/{application_id}/production-status"),
    ("POST", "/v1/passport/applications/{application_id}/quality-verify"),
    ("POST", "/v1/passport/applications/{application_id}/submit-personalization"),
    ("GET", "/v1/passport/capabilities"),
    ("POST", "/v1/passport/webhooks/personalization"),
}
EXPECTED_ARTIFACTS = {
    "contracts/issuance-universal-ownership.json",
    "contracts/issuance-native-coverage.json",
}
EXPECTED_LIFECYCLE_GATE = "canvas_mirror_worker_enabled_packaged_main_runs_and_shuts_down_cleanly"


class QualificationError(RuntimeError):
    """The pinned native checkpoint does not authorize the proposed retirement."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def _json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise QualificationError(f"Cannot read {path}: {type(error).__name__}") from None
    _require(isinstance(value, dict), f"{path} must contain a JSON object")
    return value


def _route_keys(rows: object, label: str) -> set[tuple[str, str]]:
    _require(isinstance(rows, list), f"{label} must be a list")
    keys: list[tuple[str, str]] = []
    for row in rows:
        _require(isinstance(row, dict), f"{label} contains a non-object")
        method, path = row.get("method"), row.get("path")
        _require(isinstance(method, str) and isinstance(path, str), f"{label} route is invalid")
        keys.append((method, path))
    _require(len(keys) == len(set(keys)), f"{label} contains duplicate routes")
    return set(keys)


def _git_head(checkout: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    _require(result.returncode == 0, "marty-ui checkout is not a Git worktree")
    return result.stdout.strip()


def _git_is_clean(checkout: Path) -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and not result.stdout.strip()


def _git_is_from_protected_main(checkout: Path, commit: str) -> bool:
    remote = subprocess.run(
        ["git", "remote", "get-url", "origin"],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    if remote.returncode != 0 or re.fullmatch(
        r"(?:https://github\.com/|git@github\.com:)ElevenID/marty-ui(?:\.git)?/?",
        remote.stdout.strip(),
        flags=re.IGNORECASE,
    ) is None:
        return False
    main = subprocess.run(
        ["git", "rev-parse", "--verify", "refs/remotes/origin/main^{commit}"],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    if main.returncode != 0:
        return False
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, main.stdout.strip()],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    return ancestor.returncode == 0


def verify(contract_path: Path, marty_ui: Path) -> dict:
    contract = _json(contract_path)
    _require(
        contract.get("schema") == "marty.issuance-python-retirement-qualification/v1",
        "Unknown retirement qualification schema",
    )
    authorized_scopes = contract.get("authorized_scopes", [])
    _require(
        isinstance(authorized_scopes, list)
        and len(authorized_scopes) == len(EXPECTED_SCOPES)
        and set(authorized_scopes) == EXPECTED_SCOPES,
        "Authorized scopes changed",
    )
    _require(
        _route_keys(contract.get("authorized_native_http_deletions"), "authorized deletions")
        == EXPECTED_DELETIONS,
        "Authorized deletion identities changed",
    )
    _require(
        _route_keys(contract.get("retained_python_http"), "retained Python routes")
        == EXPECTED_RETAINED,
        "Retained Python route identities changed",
    )
    _require(
        contract.get("required_packaged_main_lifecycle_gate") == EXPECTED_LIFECYCLE_GATE,
        "Packaged-main lifecycle gate changed",
    )
    _require(
        contract.get("full_python_service_deletion_authorized") is False,
        "Full Python service deletion is not authorized",
    )

    source = contract.get("source")
    _require(isinstance(source, dict), "Source checkpoint is missing")
    _require(source.get("repository") == "ElevenID/marty-ui", "Unexpected source repository")
    artifacts = source.get("artifacts")
    _require(isinstance(artifacts, list), "Source artifacts are missing")
    _require(len(artifacts) == len(EXPECTED_ARTIFACTS), "Source artifact set changed")
    artifact_map = {
        item.get("path"): item.get("sha256") for item in artifacts if isinstance(item, dict)
    }
    _require(set(artifact_map) == EXPECTED_ARTIFACTS, "Source artifact set changed")

    state = contract.get("state")
    if state == BLOCKED_STATE:
        _require(source.get("commit") is None, "Blocked checkpoint must not invent a commit")
        _require(
            all(value is None for value in artifact_map.values()),
            "Blocked checkpoint must not invent hashes",
        )
        raise QualificationError(
            "Retirement is blocked pending the post-#844/#845 marty-ui checkpoint"
        )
    _require(state == QUALIFIED_STATE, "Retirement qualification state is not recognized")

    commit = source.get("commit")
    _require(
        isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit),
        "Source commit is not immutable",
    )
    _require(_git_head(marty_ui) == commit, "marty-ui checkout does not match the pinned commit")
    _require(
        _git_is_clean(marty_ui), "marty-ui checkout has tracked changes outside the pinned commit"
    )
    _require(
        _git_is_from_protected_main(marty_ui, commit),
        "Pinned marty-ui commit is not proven reachable from fetched protected origin/main",
    )
    for relative, expected_digest in artifact_map.items():
        _require(
            isinstance(expected_digest, str) and re.fullmatch(r"[0-9a-f]{64}", expected_digest),
            f"Missing SHA-256 provenance for {relative}",
        )
        actual = hashlib.sha256((marty_ui / relative).read_bytes()).hexdigest()
        _require(actual == expected_digest, f"SHA-256 provenance mismatch for {relative}")

    ownership = _json(marty_ui / "contracts/issuance-universal-ownership.json")
    coverage = _json(marty_ui / "contracts/issuance-native-coverage.json")
    _require(
        ownership.get("schema") == "marty.issuance-universal-ownership/v1",
        "Unknown ownership schema",
    )
    _require(
        coverage.get("schema") == "marty.issuance-native-coverage/v1", "Unknown coverage schema"
    )
    retirement = ownership.get("rust_owned_python_retirement")
    _require(isinstance(retirement, dict), "Rust-owned Python retirement authorization is missing")
    _require(retirement.get("authorized") is True, "Rust-owned Python retirement is not authorized")
    source_scopes = retirement.get("scope", [])
    _require(
        isinstance(source_scopes, list)
        and len(source_scopes) == len(EXPECTED_SCOPES)
        and set(source_scopes) == EXPECTED_SCOPES,
        "Source retirement scopes changed",
    )
    _require(
        retirement.get("full_python_service_deletion_authorized") is False,
        "Source authorizes full Python deletion",
    )
    _require(
        ownership.get("python_deletion_authorized") is False,
        "Source authorizes full Python deletion",
    )

    native = _route_keys(coverage.get("native_http"), "native coverage")
    _require(native >= EXPECTED_DELETIONS, "A deleted route is not owned by native Rust")
    runtime_path = ownership.get("runtime_surface")
    _require(isinstance(runtime_path, str), "Runtime surface link is missing")
    surface = _json(marty_ui / runtime_path)
    complete = _route_keys(surface.get("http", {}).get("routes"), "runtime HTTP surface")
    _require(
        complete >= EXPECTED_DELETIONS,
        "An authorized deletion is absent from the frozen runtime surface",
    )
    _require(
        complete - native == EXPECTED_RETAINED,
        "Runtime surface minus native coverage is not the exact 11-route Python remainder",
    )
    _require(retirement.get("retained_http_route_count") == 11, "Retained route count changed")
    _require(
        _route_keys(ownership.get("retained_legacy_http"), "source retained routes")
        == EXPECTED_RETAINED,
        "Source retained-route allowlist changed",
    )

    _require(
        ownership.get("default_owner") == "issuance-native", "Default issuance owner is not native"
    )
    _require(ownership.get("retained_legacy_owner") == "issuance", "Explicit legacy owner changed")
    compositions = ownership.get("default_compositions")
    _require(isinstance(compositions, dict), "Default composition evidence is missing")
    _require(
        compositions
        == {
            "compose": "docker-compose.base.yml",
            "conformance": "scripts/conformance_stack.py",
            "envoy": "config/envoy/envoy.yaml",
            "kubernetes": "scripts/deploy-kubernetes.sh",
        },
        "Default composition evidence set changed",
    )
    compose_path = compositions.get("compose")
    _require(isinstance(compose_path, str), "Default Compose evidence is missing")
    compose = (marty_ui / compose_path).read_text(encoding="utf-8")
    _require(
        "ISSUANCE_NATIVE_SERVICE_URL: http://issuance-native:8005" in compose,
        "Gateway does not default to native HTTP",
    )
    _require(
        "ISSUANCE_GRPC_TARGET: issuance-native:9005" in compose, "Flow does not select native gRPC"
    )
    conformance = (marty_ui / compositions["conformance"]).read_text(encoding="utf-8")
    _require(
        re.search(r'--issuance-owner[\s\S]{0,200}default="native"', conformance) is not None,
        "Conformance does not default to native issuance",
    )
    kubernetes = (marty_ui / compositions["kubernetes"]).read_text(encoding="utf-8")
    _require(
        'K8S_ISSUANCE_NATIVE_ENABLED="${K8S_ISSUANCE_NATIVE_ENABLED-true}"' in kubernetes,
        "Kubernetes does not default native issuance on",
    )
    envoy = (marty_ui / compositions["envoy"]).read_text(encoding="utf-8")
    for prefix in ("/marty.ui.issuance.v1.IssuanceService/", "/v1/issuance/"):
        _require(
            re.search(
                rf'prefix: "{re.escape(prefix)}"[\s\S]{{0,200}}cluster: issuance_native_grpc',
                envoy,
            )
            is not None,
            f"Envoy does not route {prefix} to native issuance",
        )

    _require(
        retirement.get("packaged_main_lifecycle_gate") == EXPECTED_LIFECYCLE_GATE,
        "Source lifecycle gate changed",
    )
    published = (
        marty_ui / "rust/services/issuance/tests/canvas_published_schema_contract.rs"
    ).read_text(encoding="utf-8")
    lifecycle = (
        marty_ui / "rust/services/issuance/tests/support/canvas_status_runtime_contract.rs"
    ).read_text(encoding="utf-8")
    _require(EXPECTED_LIFECYCLE_GATE in published, "Packaged-main lifecycle test is absent")
    for evidence in (
        'env("CANVAS_MIRROR_WORKER_ENABLED", "true")',
        'args(["-TERM", &child.0.id().to_string()])',
        "external_credential_id='automation-external'",
        'stderr.contains("Issuance shutdown requested")',
    ):
        _require(evidence in lifecycle, f"Packaged-main lifecycle evidence is absent: {evidence}")

    return {
        "status": "qualified",
        "source_commit": commit,
        "authorized_route_count": len(EXPECTED_DELETIONS),
        "retained_python_route_count": len(EXPECTED_RETAINED),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--marty-ui", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = verify(arguments.contract.resolve(), arguments.marty_ui.resolve())
    except (QualificationError, OSError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
