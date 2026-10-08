"""Qualify complete Python issuance removal against an exact Rust checkout."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

from scripts import release_contract, release_service_handoff

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"[0-9a-f]{40}")
PASSPORT_ROUTES = {
    ("GET", "/v1/passport/applications/{application_id}/production-status"),
    ("GET", "/v1/passport/capabilities"),
    ("POST", "/v1/passport/applications"),
    ("POST", "/v1/passport/applications/{application_id}/activate"),
    ("POST", "/v1/passport/applications/{application_id}/generate-data-groups"),
    ("POST", "/v1/passport/applications/{application_id}/generate-sod"),
    ("POST", "/v1/passport/applications/{application_id}/quality-verify"),
    ("POST", "/v1/passport/applications/{application_id}/submit-personalization"),
    ("POST", "/v1/passport/webhooks/personalization"),
}


class RetirementError(RuntimeError):
    """The checked source does not qualify for full service retirement."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RetirementError(message)


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RetirementError(f"cannot read {path}") from error
    require(isinstance(value, dict), f"{path} is not a JSON object")
    return value


def route_keys(rows: list[dict]) -> set[tuple[str, str]]:
    result = {(row["method"], row["path"]) for row in rows}
    require(len(result) == len(rows), "route inventory contains duplicates")
    return result


def command_output(args: list[str], cwd: Path) -> str:
    completed = subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=False)
    require(completed.returncode == 0, f"command failed: {' '.join(args)}")
    return completed.stdout.strip()


def verify_protected_ui(marty_ui: Path, ui_commit: str) -> dict:
    require(
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", ui_commit, "refs/remotes/origin/main"],
            cwd=marty_ui,
            capture_output=True,
            check=False,
        ).returncode
        == 0,
        "UI commit is not on protected main",
    )
    pull = json.loads(
        command_output(
            [
                "gh", "pr", "view", "1178", "--repo", "ElevenID/marty-ui",
                "--json", "mergedAt,mergeCommit,baseRefName,headRefOid",
            ],
            marty_ui,
        )
    )
    require(pull.get("baseRefName") == "main" and pull.get("mergedAt"), "UI PR #1178 is not merged to main")
    require((pull.get("mergeCommit") or {}).get("oid") == ui_commit, "UI commit is not PR #1178's merge commit")
    checks = json.loads(
        command_output(
            ["gh", "pr", "checks", "1178", "--repo", "ElevenID/marty-ui", "--json", "name,state"],
            marty_ui,
        )
    )
    require(checks and all(row["state"] in {"SUCCESS", "SKIPPED", "NEUTRAL"} for row in checks), "UI PR checks are not settled and passing")
    required = {
        "Release Contract Tests",
        "Rust Service Tests (canvas)",
        "Rust Service Tests (contracts)",
        "Rust Service Images",
        "Passport Fence PostgreSQL",
        "Rust Passport Test-mode Image",
    }
    passed = {row["name"] for row in checks if row["state"] == "SUCCESS"}
    require(required <= passed, f"required UI checks did not pass: {sorted(required - passed)}")
    return {"ui_pr": 1178, "ui_pr_head": pull["headRefOid"], "required_checks": sorted(required)}


def verify(credentials: Path, marty_ui: Path, ui_commit: str) -> dict:
    require(SHA.fullmatch(ui_commit) is not None, "UI commit must be a full SHA")
    require(command_output(["git", "rev-parse", "HEAD"], marty_ui) == ui_commit, "UI checkout is not pinned")
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=marty_ui,
        capture_output=True,
        text=True,
        check=False,
    )
    require(dirty.returncode == 0 and not dirty.stdout.strip(), "UI checkout has local changes")
    protected = verify_protected_ui(marty_ui, ui_commit)

    require(not (credentials / "services/issuance").exists(), "Python issuance source remains")
    require(not (credentials / "services/Dockerfile").exists(), "Python issuance image remains")
    require(release_contract.SERVICES == (), "Credentials still releases a service image")
    require(
        release_service_handoff.build_service_matrix(credentials) == {"include": []},
        "Credentials service release matrix is not empty",
    )

    ci = (credentials / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for old_job in (
        "canvas-portable-migration:",
        "canvas-worker-consumer-ranges:",
        "issuance-idempotency-contract:",
        "oid4vci-capability-postgres:",
        "passport-retirement-provenance:",
    ):
        require(f"  {old_job}" not in ci, f"old Python CI job remains: {old_job}")
    python_ci = (credentials / "scripts/run-python-ci.sh").read_text(encoding="utf-8")
    require("from issuance" not in python_ci, "Python CI imports retired issuance")
    require("services/issuance" not in python_ci, "Python CI invokes retired issuance")

    current = read_json(credentials / "contracts/issuance-runtime-surface.json")
    frozen = read_json(marty_ui / "contracts/issuance-runtime-surface.json")
    native = read_json(marty_ui / "contracts/issuance-native-coverage.json")
    current_routes = route_keys(current["http"]["routes"])
    frozen_routes = route_keys(frozen["http"]["routes"])
    native_routes = route_keys(native["native_http"])
    require(len(current_routes) == current["http"]["route_count"] == 86, "current route floor changed")
    require(len(frozen_routes) == frozen["http"]["route_count"] == 131, "frozen route floor changed")
    require(len(native_routes) == 122, "native route coverage changed")
    require(frozen_routes - native_routes == PASSPORT_ROUTES, "passport route split changed")
    require(current_routes - native_routes == {("GET", "/ready")}, "current Python HTTP behavior lacks a Rust owner")
    require(current_routes.isdisjoint(PASSPORT_ROUTES), "passport Python route was reintroduced")
    current_grpc = {row["method"] for row in current["grpc"]["methods"]}
    frozen_grpc = {row["method"] for row in frozen["grpc"]["methods"]}
    require(
        current_grpc == frozen_grpc == set(native["native_grpc"])
        and len(current_grpc) == current["grpc"]["method_count"] == 12,
        "gRPC method coverage changed",
    )
    require(native["passport_http_implemented_separately"] == 9, "Rust passport count changed")
    for path in (
        "rust/services/issuance/src/passport_http.rs",
        "rust/services/issuance/migrations/0000_issuance_service_baseline.sql",
        "rust/services/issuance/migrations/0000_issuance_service_catalog.json",
        "rust/services/issuance/src/bin/canvas_sync_worker.rs",
        "rust/services/issuance/src/migration.rs",
        "scripts/run-passport-beta-aggregate-deploy.ps1",
        "scripts/collect_passport_beta_aggregate_acceptance.py",
        "rust/services/issuance/tests/credential_postgres_contract.rs",
        "rust/services/issuance/tests/credential_admission_behavior.rs",
        "rust/services/issuance/tests/canvas_sync_worker_postgres_contract.rs",
    ):
        require((marty_ui / path).is_file(), f"Rust evidence missing: {path}")

    return {
        "status": "qualified_source_only",
        "ui_commit": ui_commit,
        "current_http_routes": len(current_routes),
        "native_http_routes": len(native_routes),
        "grpc_methods": len(current_grpc),
        "passport_http_routes": len(PASSPORT_ROUTES),
        "service_images": 0,
        "beta_deployment_authorized": False,
        **protected,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--marty-ui", type=Path, required=True)
    parser.add_argument("--ui-commit", required=True)
    args = parser.parse_args()
    try:
        result = verify(ROOT, args.marty_ui.resolve(), args.ui_commit)
    except (OSError, KeyError, TypeError, json.JSONDecodeError, RetirementError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
