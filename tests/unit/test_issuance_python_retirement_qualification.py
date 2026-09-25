from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from scripts import check_issuance_python_retirement as gate


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, str):
        path.write_text(value, encoding="utf-8")
    else:
        path.write_text(json.dumps(value), encoding="utf-8")


def _route_rows(keys: set[tuple[str, str]]) -> list[dict[str, str]]:
    return [{"method": method, "path": path} for method, path in sorted(keys)]


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, dict]:
    source = tmp_path / "marty-ui"
    coverage = {
        "schema": "marty.issuance-native-coverage/v1",
        "native_http": _route_rows(gate.EXPECTED_DELETIONS),
    }
    ownership = {
        "schema": "marty.issuance-universal-ownership/v1",
        "runtime_surface": "contracts/issuance-runtime-surface.json",
        "default_owner": "issuance-native",
        "retained_legacy_owner": "issuance",
        "retained_legacy_http": _route_rows(gate.EXPECTED_RETAINED),
        "python_deletion_authorized": False,
        "default_compositions": {
            "compose": "docker-compose.base.yml",
            "conformance": "scripts/conformance_stack.py",
            "envoy": "config/envoy/envoy.yaml",
            "kubernetes": "scripts/deploy-kubernetes.sh",
        },
        "rust_owned_python_retirement": {
            "authorized": True,
            "scope": sorted(gate.EXPECTED_SCOPES),
            "retained_http_route_count": 11,
            "packaged_main_lifecycle_gate": gate.EXPECTED_LIFECYCLE_GATE,
            "full_python_service_deletion_authorized": False,
        },
    }
    _write(source / "contracts/issuance-native-coverage.json", coverage)
    _write(source / "contracts/issuance-universal-ownership.json", ownership)
    _write(
        source / "contracts/issuance-runtime-surface.json",
        {"http": {"routes": _route_rows(gate.EXPECTED_DELETIONS | gate.EXPECTED_RETAINED)}},
    )
    _write(
        source / "docker-compose.base.yml",
        "ISSUANCE_NATIVE_SERVICE_URL: http://issuance-native:8005\n"
        "ISSUANCE_GRPC_TARGET: issuance-native:9005\n",
    )
    _write(
        source / "scripts/conformance_stack.py",
        'parser.add_argument("--issuance-owner", choices=("legacy", "native"), default="native")',
    )
    _write(
        source / "scripts/deploy-kubernetes.sh",
        'K8S_ISSUANCE_NATIVE_ENABLED="${K8S_ISSUANCE_NATIVE_ENABLED-true}"',
    )
    _write(
        source / "config/envoy/envoy.yaml",
        'prefix: "/marty.ui.issuance.v1.IssuanceService/"\n'
        "cluster: issuance_native_grpc\n"
        'prefix: "/v1/issuance/"\n'
        "cluster: issuance_native_grpc\n",
    )
    _write(
        source / "rust/services/issuance/tests/canvas_published_schema_contract.rs",
        gate.EXPECTED_LIFECYCLE_GATE,
    )
    _write(
        source / "rust/services/issuance/tests/support/canvas_status_runtime_contract.rs",
        "\n".join(
            (
                'env("CANVAS_MIRROR_WORKER_ENABLED", "true")',
                'args(["-TERM", &child.0.id().to_string()])',
                "external_credential_id='automation-external'",
                'logs.contains("Issuance shutdown requested")',
            )
        ),
    )
    _write(
        source / ".github/workflows/e2e-tests.yml",
        "\n".join(gate.EXPECTED_DEMO_WORKFLOW_MARKERS),
    )
    _write(
        source / "rust/crates/release-evidence/src/demo_qualification.rs",
        "\n".join(gate.EXPECTED_DEMO_VALIDATOR_MARKERS),
    )
    contract = json.loads(gate.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
    contract["state"] = "qualified"
    contract["source"]["commit"] = "a" * 40
    for artifact in contract["source"]["artifacts"]:
        artifact["sha256"] = hashlib.sha256((source / artifact["path"]).read_bytes()).hexdigest()
    contract_path = tmp_path / "qualification.json"
    _write(contract_path, contract)
    monkeypatch.setattr(gate, "_git_head", lambda _checkout: "a" * 40)
    monkeypatch.setattr(
        gate,
        "_git_blob",
        lambda checkout, _commit, relative: (checkout / relative).read_bytes(),
    )
    monkeypatch.setattr(gate, "_git_is_clean", lambda _checkout: True)
    monkeypatch.setattr(gate, "_git_is_from_protected_main", lambda _checkout, _commit: True)
    return contract_path, source, contract


def test_checked_in_contract_requires_pinned_checkout(tmp_path: Path) -> None:
    contract = json.loads(gate.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
    assert contract["state"] == "qualified"
    assert contract["source"]["commit"] == "207c84afc00b2f3b2b3db6b433823a9c7d59ab38"
    with pytest.raises(gate.QualificationError, match="not a Git worktree"):
        gate.verify(gate.DEFAULT_CONTRACT, tmp_path)


def test_exact_qualified_checkpoint_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    contract, source, _ = _fixture(tmp_path, monkeypatch)
    assert gate.verify(contract, source) == {
        "status": "qualified",
        "source_commit": "a" * 40,
        "authorized_route_count": 13,
        "retained_python_route_count": 11,
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value["authorized_scopes"].pop(), "Authorized scopes changed"),
        (
            lambda value: value["authorized_native_http_deletions"].pop(),
            "Authorized deletion identities changed",
        ),
        (
            lambda value: value.__setitem__("full_python_service_deletion_authorized", True),
            "Full Python service deletion",
        ),
        (
            lambda value: value["source"]["artifacts"].append(
                dict(value["source"]["artifacts"][0])
            ),
            "Source artifact set changed",
        ),
    ],
)
def test_local_authorization_cannot_be_broadened(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation,
    message: str,
) -> None:
    contract_path, source, contract = _fixture(tmp_path, monkeypatch)
    mutation(contract)
    _write(contract_path, contract)
    with pytest.raises(gate.QualificationError, match=message):
        gate.verify(contract_path, source)


def test_wrong_commit_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    contract, source, _ = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(gate, "_git_head", lambda _checkout: "b" * 40)
    with pytest.raises(gate.QualificationError, match="pinned commit"):
        gate.verify(contract, source)


def test_unmerged_feature_commit_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract, source, _ = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(gate, "_git_is_from_protected_main", lambda _checkout, _commit: False)
    with pytest.raises(gate.QualificationError, match="protected origin/main"):
        gate.verify(contract, source)


@pytest.mark.parametrize(
    ("remote_tip", "remote_exit", "expected"),
    [("b" * 40, 0, True), ("c" * 40, 0, False), ("", 1, False)],
)
def test_protected_main_provenance_requires_live_remote_tip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    remote_tip: str,
    remote_exit: int,
    expected: bool,
) -> None:
    calls = []

    def run(command, **_kwargs):
        calls.append(command)
        if command[1:3] == ["remote", "get-url"]:
            return subprocess.CompletedProcess(
                command, 0, "https://github.com/ElevenID/marty-ui.git\n"
            )
        if command[1] == "rev-parse":
            return subprocess.CompletedProcess(command, 0, "b" * 40 + "\n")
        if command[1] == "ls-remote":
            return subprocess.CompletedProcess(
                command, remote_exit, f"{remote_tip}\trefs/heads/main\n" if remote_tip else ""
            )
        if command[1] == "merge-base":
            return subprocess.CompletedProcess(command, 0, "")
        raise AssertionError(f"Unexpected git command: {command}")

    monkeypatch.setattr(gate.subprocess, "run", run)
    assert gate._git_is_from_protected_main(tmp_path, "a" * 40) is expected
    assert any(command[1] == "ls-remote" for command in calls)
    assert any(command[1] == "merge-base" for command in calls) is expected


def test_provenance_mismatch_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    contract, source, _ = _fixture(tmp_path, monkeypatch)
    path = source / "contracts/issuance-native-coverage.json"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(gate.QualificationError, match="provenance mismatch"):
        gate.verify(contract, source)


def test_checkout_line_ending_conversion_does_not_change_committed_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract_path, source, _ = _fixture(tmp_path, monkeypatch)
    relative = ".github/workflows/e2e-tests.yml"
    path = source / relative
    committed = path.read_bytes()
    path.write_bytes(committed.replace(b"\n", b"\r\n"))
    monkeypatch.setattr(
        gate,
        "_git_blob",
        lambda checkout, _commit, requested: (
            committed if requested == relative else (checkout / requested).read_bytes()
        ),
    )
    assert gate.verify(contract_path, source)["status"] == "qualified"


@pytest.mark.parametrize(
    ("relative", "marker", "message"),
    [
        (
            ".github/workflows/e2e-tests.yml",
            gate.EXPECTED_DEMO_WORKFLOW_MARKERS[0],
            "Recorder review provenance workflow is absent",
        ),
        (
            "rust/crates/release-evidence/src/demo_qualification.rs",
            gate.EXPECTED_DEMO_VALIDATOR_MARKERS[0],
            "Rust recorder review provenance validation is absent",
        ),
    ],
)
def test_qualified_retirement_requires_recorder_review_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    marker: str,
    message: str,
) -> None:
    contract_path, source, contract = _fixture(tmp_path, monkeypatch)
    path = source / relative
    path.write_text(path.read_text(encoding="utf-8").replace(marker, ""), encoding="utf-8")
    next(item for item in contract["source"]["artifacts"] if item["path"] == relative)["sha256"] = (
        hashlib.sha256(path.read_bytes()).hexdigest()
    )
    _write(contract_path, contract)
    with pytest.raises(gate.QualificationError, match=message):
        gate.verify(contract_path, source)


def test_unowned_deleted_route_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    contract, source, document = _fixture(tmp_path, monkeypatch)
    coverage_path = source / "contracts/issuance-native-coverage.json"
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    coverage["native_http"].pop()
    _write(coverage_path, coverage)
    for artifact in document["source"]["artifacts"]:
        if artifact["path"] == "contracts/issuance-native-coverage.json":
            artifact["sha256"] = hashlib.sha256(coverage_path.read_bytes()).hexdigest()
    _write(contract, document)
    with pytest.raises(gate.QualificationError, match="not owned by native Rust"):
        gate.verify(contract, source)


def test_runtime_remainder_must_be_exact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    contract, source, _ = _fixture(tmp_path, monkeypatch)
    runtime = source / "contracts/issuance-runtime-surface.json"
    value = json.loads(runtime.read_text(encoding="utf-8"))
    value["http"]["routes"].append({"method": "GET", "path": "/unowned"})
    _write(runtime, value)
    with pytest.raises(gate.QualificationError, match="exact 11-route"):
        gate.verify(contract, source)


def test_authorized_deletion_must_exist_in_frozen_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract, source, _ = _fixture(tmp_path, monkeypatch)
    runtime = source / "contracts/issuance-runtime-surface.json"
    value = json.loads(runtime.read_text(encoding="utf-8"))
    removed = next(
        row
        for row in value["http"]["routes"]
        if (row["method"], row["path"]) in gate.EXPECTED_DELETIONS
    )
    value["http"]["routes"].remove(removed)
    _write(runtime, value)
    with pytest.raises(gate.QualificationError, match="absent from the frozen runtime"):
        gate.verify(contract, source)


def test_packaged_lifecycle_and_default_routing_are_required(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract, source, _ = _fixture(tmp_path, monkeypatch)
    (source / "docker-compose.base.yml").write_text("services: {}\n", encoding="utf-8")
    with pytest.raises(gate.QualificationError, match="native HTTP"):
        gate.verify(contract, source)

    _write(
        source / "docker-compose.base.yml",
        "ISSUANCE_NATIVE_SERVICE_URL: http://issuance-native:8005\n"
        "ISSUANCE_GRPC_TARGET: issuance-native:9005\n",
    )
    (source / "rust/services/issuance/tests/canvas_published_schema_contract.rs").write_text(
        "", encoding="utf-8"
    )
    with pytest.raises(gate.QualificationError, match="lifecycle test is absent"):
        gate.verify(contract, source)
