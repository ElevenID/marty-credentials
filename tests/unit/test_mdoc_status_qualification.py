"""The owned KMS lane must discover and execute real signed-status parity."""

import importlib.util
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load_helper(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNNER = load_helper("mdoc_hsm_roundtrip", "scripts/test_mdoc_hsm_roundtrip.py")
LOCATOR = load_helper("locate_core_status_test", "scripts/ci/locate_core_status_test.py")


def test_omitted_option_preserves_preparation_only_mode():
    assert RUNNER.parse_args([]).core_status_test_binary is None


def test_missing_binary_argument_fails_before_kms_allocation(monkeypatch):
    monkeypatch.setattr(RUNNER.secrets, "token_hex", lambda _: pytest.fail("KMS allocated too early"))
    with pytest.raises(SystemExit):
        RUNNER.main(["--core-status-test-binary"])


@pytest.mark.parametrize("kind", ["missing", "directory", "not_executable", "symlink"])
def test_invalid_binary_fails_before_kms_allocation(tmp_path, monkeypatch, kind):
    binary = tmp_path / "core-test"
    if kind == "directory":
        binary.mkdir()
    elif kind == "not_executable":
        binary.write_text("not executable")
    elif kind == "symlink":
        binary.symlink_to(tmp_path / "missing-target")
    monkeypatch.setattr(RUNNER.secrets, "token_hex", lambda _: pytest.fail("KMS allocated too early"))
    with pytest.raises(ValueError, match="existing executable"):
        RUNNER.main(["--core-status-test-binary", str(binary)])


def test_unlaunchable_binary_fails_before_kms_allocation(tmp_path, monkeypatch):
    binary = tmp_path / "core-test"
    binary.write_text("not a native executable\n")
    binary.chmod(0o700)
    monkeypatch.setattr(RUNNER.secrets, "token_hex", lambda _: pytest.fail("KMS allocated too early"))
    with pytest.raises(ValueError, match="existing executable") as rejected:
        RUNNER.main(["--core-status-test-binary", str(binary)])
    assert isinstance(rejected.value.__cause__, OSError)


@pytest.mark.parametrize("listing", [
    "",
    "some_other_test: test\n",
    RUNNER.CORE_STATUS_TEST + "_similar: test\n",
    (RUNNER.CORE_STATUS_TEST + ": test\n") * 2,
    RUNNER.CORE_STATUS_TEST + ": test\nsome_other_test: test\n",
])
def test_wrong_or_ambiguous_discovery_fails_before_kms(tmp_path, monkeypatch, listing):
    binary = tmp_path / "core-test"
    binary.write_text("controlled discovery fixture")
    binary.chmod(0o700)
    monkeypatch.setattr(RUNNER.secrets, "token_hex", lambda _: pytest.fail("KMS allocated too early"))
    monkeypatch.setattr(
        RUNNER.subprocess, "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout=listing),
    )
    with pytest.raises(ValueError, match="exactly the managed"):
        RUNNER.main(["--core-status-test-binary", str(binary)])


def test_discovery_requires_the_exact_test_without_running_it(tmp_path, monkeypatch):
    binary = tmp_path / "core-test"
    binary.write_text("controlled discovery fixture")
    binary.chmod(0o700)

    def discover(command, **options):
        assert command == [
            str(binary), "--list", "--format", "terse", "--exact", RUNNER.CORE_STATUS_TEST
        ]
        assert options == {"check": True, "capture_output": True, "text": True, "timeout": 30}
        return subprocess.CompletedProcess(command, 0, stdout=RUNNER.CORE_STATUS_TEST + ": test\n")

    monkeypatch.setattr(RUNNER.subprocess, "run", discover)
    assert RUNNER.validate_core_status_test_binary(binary) == binary


@pytest.fixture
def cargo_artifact(tmp_path):
    checkout = tmp_path / "core"
    manifest = checkout / "marty-verification" / "Cargo.toml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("[package]\nname = 'marty-verification'\n")
    target = tmp_path / "core-target"
    binary = target / "debug" / "deps" / "marty_verification-test"
    binary.parent.mkdir(parents=True)
    binary.write_text("controlled artifact fixture")
    message = {
        "reason": "compiler-artifact",
        "manifest_path": str(manifest),
        "target": {"name": "marty_verification", "kind": ["cdylib", "rlib"]},
        "profile": {"test": True},
        "executable": str(binary),
    }
    return checkout, target, binary, message


def test_cargo_artifact_selection_binds_manifest_and_target(cargo_artifact):
    checkout, target, binary, message = cargo_artifact
    assert LOCATOR.locate(json.dumps(message), checkout, target) == binary


@pytest.mark.parametrize("change", ["missing", "duplicate", "manifest", "profile", "target", "outside", "symlink"])
def test_cargo_artifact_selection_rejects_substitutes(cargo_artifact, change, tmp_path):
    checkout, target, binary, message = cargo_artifact
    messages = [message]
    if change == "missing":
        messages = []
    elif change == "duplicate":
        messages.append(dict(message))
    elif change == "manifest":
        message["manifest_path"] = str(checkout / "other" / "Cargo.toml")
    elif change == "profile":
        message["profile"]["test"] = False
    elif change == "target":
        message["target"]["kind"] = ["bin"]
    else:
        outside = tmp_path / "substitute"
        outside.write_text("not the selected compiled test")
        if change == "outside":
            message["executable"] = str(outside)
        else:
            binary.unlink()
            binary.symlink_to(outside)
    with pytest.raises(ValueError):
        LOCATOR.locate("\n".join(json.dumps(m) for m in messages), checkout, target)


def report_with_cases(path, names, outcome=None):
    suite = ET.Element("testsuite")
    for name in names:
        case = ET.SubElement(suite, "testcase", name=name)
        if outcome:
            ET.SubElement(case, outcome)
    ET.ElementTree(suite).write(path)


def test_all_eight_signed_status_cases_must_pass(tmp_path):
    report = tmp_path / "report.xml"
    report_with_cases(report, sorted(RUNNER.STATUS_PYTHON_CASES))
    RUNNER.require_signed_status_python_cases(report)


@pytest.mark.parametrize("change", ["omitted", "duplicate", "skipped", "failure", "error"])
def test_incomplete_or_skipped_python_parity_is_not_success(tmp_path, change):
    report = tmp_path / "report.xml"
    names = sorted(RUNNER.STATUS_PYTHON_CASES)
    outcome = None
    if change == "omitted":
        names.pop()
    elif change == "duplicate":
        names[-1] = names[0]
    else:
        outcome = change
    report_with_cases(report, names, outcome)
    with pytest.raises(RuntimeError):
        RUNNER.require_signed_status_python_cases(report)


def test_ci_requires_live_parity_from_the_exact_pinned_core_checkout():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    job = workflow.split("  test-local-python-binding:\n", 1)[1].split("\n  security:\n", 1)[0]
    assert "repository: ElevenID/marty-core" in job
    assert "ref: ${{ env.MARTY_CORE_REVISION }}" in job
    assert 'test "$(git -C marty-core rev-parse HEAD)" = "$MARTY_CORE_REVISION"' in job
    assert "--features kms-only,mdoc-status-verification --lib --no-run" in job
    assert "locate_core_status_test.py" in job
    assert '--core-status-test-binary "$CORE_STATUS_TEST_BINARY"' in job
