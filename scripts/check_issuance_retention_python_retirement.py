"""Fail-closed protected-main gate for the separate retention Python retirement."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from scripts import check_issuance_python_retirement as prior_gate

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "contracts/issuance-retention-python-retirement-qualification.json"
EXPECTED_DELETIONS = {
    ("GET", "/v1/issuance/organizations/{organization_id}/retention"),
    ("POST", "/v1/issuance/organizations/{organization_id}/retention/purge"),
}
EXPECTED_RETAINED = prior_gate.EXPECTED_RETAINED - EXPECTED_DELETIONS
EXPECTED_ARTIFACTS = {
    "contracts/issuance-universal-ownership.json",
    "contracts/issuance-native-coverage.json",
    "contracts/issuance-retention-management.json",
    "release/stack-lock.json",
}
EXPECTED_CREDENTIALS_SOURCE = "efd5da1e2d41419ce93721f98d314c7b911e6b5e"
EXPECTED_CREDENTIALS_DIGEST = (
    "sha256:e7bb482120837c68af6cec2f6d1d5276488de440b93fc811987860b7b99b4657"
)


def _artifact_map(source: dict, expected: set[str]) -> dict[str, str | None]:
    artifacts = source.get("artifacts")
    prior_gate._require(isinstance(artifacts, list), "Source artifacts are missing")
    prior_gate._require(len(artifacts) == len(expected), "Source artifact set changed")
    values = {item.get("path"): item.get("sha256") for item in artifacts if isinstance(item, dict)}
    prior_gate._require(set(values) == expected, "Source artifact set changed")
    return values


def _committed_blob(checkout: Path, commit: str, relative: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{commit}:{relative}"],
        cwd=checkout,
        check=False,
        capture_output=True,
    )
    prior_gate._require(result.returncode == 0, f"Prior source artifact is missing: {relative}")
    return result.stdout


def _verify_prior_retirement(contract: dict, checkout: Path) -> None:
    relative = contract.get("prior_retirement_qualification")
    prior_gate._require(
        relative == "contracts/issuance-python-retirement-qualification.json",
        "Prior retirement qualification link changed",
    )
    previous = prior_gate._json(ROOT / relative)
    prior_gate._require(previous.get("state") == "qualified", "Prior retirement is not qualified")
    prior_gate._require(
        prior_gate._route_keys(previous.get("authorized_native_http_deletions"), "prior deletions")
        == prior_gate.EXPECTED_DELETIONS,
        "Prior retirement deletion identities changed",
    )
    prior_gate._require(
        prior_gate._route_keys(previous.get("retained_python_http"), "prior retained routes")
        == prior_gate.EXPECTED_RETAINED,
        "Prior retirement retained routes changed",
    )
    source = previous.get("source")
    prior_gate._require(isinstance(source, dict), "Prior source checkpoint is missing")
    commit = source.get("commit")
    prior_gate._require(
        isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit),
        "Prior source commit is not immutable",
    )
    prior_gate._require(
        prior_gate._git_is_from_protected_main(checkout, commit),
        "Prior source is not reachable from protected main",
    )
    for relative, expected_digest in _artifact_map(source, prior_gate.EXPECTED_ARTIFACTS).items():
        prior_gate._require(
            isinstance(expected_digest, str) and re.fullmatch(r"[0-9a-f]{64}", expected_digest),
            f"Prior SHA-256 provenance is missing for {relative}",
        )
        actual = hashlib.sha256(_committed_blob(checkout, commit, relative)).hexdigest()
        prior_gate._require(actual == expected_digest, f"Prior SHA-256 mismatch for {relative}")


def verify(contract_path: Path, marty_ui: Path) -> dict:
    contract = prior_gate._json(contract_path)
    prior_gate._require(
        contract.get("schema") == "marty.issuance-retention-python-retirement-qualification/v1",
        "Unknown retention retirement schema",
    )
    prior_gate._require(
        prior_gate._route_keys(
            contract.get("authorized_native_http_deletions"), "retention deletions"
        )
        == EXPECTED_DELETIONS,
        "Retention deletion identities changed",
    )
    prior_gate._require(
        prior_gate._route_keys(contract.get("retained_python_http"), "retained routes")
        == EXPECTED_RETAINED,
        "Retained Python route identities changed",
    )
    prior_gate._require(
        contract.get("full_python_service_deletion_authorized") is False,
        "Full Python service deletion is not authorized",
    )
    source = contract.get("source")
    prior_gate._require(isinstance(source, dict), "Source checkpoint is missing")
    prior_gate._require(
        source.get("repository") == "ElevenID/marty-ui", "Unexpected source repository"
    )
    artifacts = _artifact_map(source, EXPECTED_ARTIFACTS)
    if contract.get("state") == "blocked_pending_retention_native_main":
        prior_gate._require(source.get("commit") is None, "Blocked checkpoint invented a commit")
        prior_gate._require(
            all(value is None for value in artifacts.values()),
            "Blocked checkpoint invented artifact hashes",
        )
        raise prior_gate.QualificationError("Retention retirement is blocked pending #849")
    prior_gate._require(contract.get("state") == "qualified", "Unknown qualification state")
    commit = source.get("commit")
    prior_gate._require(
        isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit),
        "Source commit is not immutable",
    )
    prior_gate._require(prior_gate._git_head(marty_ui) == commit, "UI checkout is not pinned")
    prior_gate._require(prior_gate._git_is_clean(marty_ui), "UI checkout has tracked changes")
    prior_gate._require(
        prior_gate._git_is_from_protected_main(marty_ui, commit),
        "Retention source is not reachable from protected main",
    )
    for relative, expected_digest in artifacts.items():
        prior_gate._require(
            isinstance(expected_digest, str) and re.fullmatch(r"[0-9a-f]{64}", expected_digest),
            f"Missing SHA-256 provenance for {relative}",
        )
        actual = hashlib.sha256((marty_ui / relative).read_bytes()).hexdigest()
        prior_gate._require(actual == expected_digest, f"SHA-256 mismatch for {relative}")

    _verify_prior_retirement(contract, marty_ui)
    ownership = prior_gate._json(marty_ui / "contracts/issuance-universal-ownership.json")
    coverage = prior_gate._json(marty_ui / "contracts/issuance-native-coverage.json")
    behavior = prior_gate._json(marty_ui / "contracts/issuance-retention-management.json")
    prior_gate._require(
        ownership.get("schema") == "marty.issuance-universal-ownership/v1",
        "Unknown ownership schema",
    )
    prior_gate._require(
        coverage.get("schema") == "marty.issuance-native-coverage/v1",
        "Unknown native coverage schema",
    )
    prior_gate._require(
        behavior.get("schema") == "marty.issuance-retention-management/v1"
        and prior_gate._route_keys(behavior.get("routes"), "retention behavior")
        == EXPECTED_DELETIONS,
        "Retention behavior contract changed",
    )
    native_rows = coverage.get("native_http")
    native = prior_gate._route_keys(native_rows, "native coverage")
    prior_gate._require(
        native >= EXPECTED_DELETIONS | prior_gate.EXPECTED_DELETIONS,
        "A deleted route is not owned by native Rust",
    )
    tagged = {
        (row.get("method"), row.get("path"))
        for row in native_rows
        if row.get("retention_behavior_contract") is True
    }
    prior_gate._require(tagged == EXPECTED_DELETIONS, "Retention native route tags changed")
    prior_gate._require(
        prior_gate._route_keys(ownership.get("retained_legacy_http"), "source retained routes")
        == EXPECTED_RETAINED,
        "Source retained-route allowlist changed",
    )
    retirement = ownership.get("rust_owned_python_retirement")
    prior_gate._require(isinstance(retirement, dict), "Source retirement gate is missing")
    prior_gate._require(
        retirement.get("retained_http_route_count") == 9
        and retirement.get("full_python_service_deletion_authorized") is False
        and ownership.get("python_deletion_authorized") is False,
        "Source authorizes the wrong Python remainder",
    )
    runtime_path = ownership.get("runtime_surface")
    prior_gate._require(isinstance(runtime_path, str), "Runtime surface link is missing")
    runtime = prior_gate._json(marty_ui / runtime_path)
    complete = prior_gate._route_keys(runtime.get("http", {}).get("routes"), "runtime HTTP surface")
    prior_gate._require(complete - native == EXPECTED_RETAINED, "Runtime Python remainder changed")

    stack = prior_gate._json(marty_ui / "release/stack-lock.json")
    prior_gate._require(stack.get("schema") == "marty.stack-lock/v1", "Unknown stack lock schema")
    components = [
        item
        for item in stack.get("components", [])
        if isinstance(item, dict) and item.get("name") == "marty-credentials-issuance"
    ]
    prior_gate._require(len(components) == 1, "Issuance release lock is missing or ambiguous")
    released = components[0]
    prior_gate._require(
        released.get("repository") == "ElevenID/marty-credentials"
        and released.get("version") == "0.1.78"
        and released.get("commit") == EXPECTED_CREDENTIALS_SOURCE,
        "Released Credentials source changed",
    )
    images = released.get("artifacts")
    prior_gate._require(
        isinstance(images, list)
        and len(images) == 1
        and isinstance(images[0], dict)
        and images[0].get("digest") == EXPECTED_CREDENTIALS_DIGEST,
        "Released Credentials image changed",
    )
    return {
        "status": "qualified",
        "source_commit": commit,
        "authorized_route_count": 2,
        "retained_python_route_count": 9,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--marty-ui", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = verify(arguments.contract.resolve(), arguments.marty_ui.resolve())
    except (prior_gate.QualificationError, OSError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
