"""Fail closed on incomplete capture, source drift, or failed test cleanup."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

SPEC = importlib.util.spec_from_file_location(
    "canvas_privacy_capture", Path(__file__).resolve().parents[2]
    / "scripts/capture_canvas_privacy_reference.py",
)
CAPTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPTURE)


def _report(case="case", *, when="call", passed=True, values=None):
    return SimpleNamespace(
        nodeid=case, when=when, passed=passed,
        user_properties=[] if values is None else [("canvas_privacy", value) for value in values],
    )


@pytest.mark.parametrize("values", [[], [{}, {}]])
def test_observation_cardinality_is_required(values) -> None:
    with pytest.raises(RuntimeError, match="one unique observation"):
        CAPTURE.Observations().pytest_runtest_logreport(_report(values=values))


def test_duplicate_case_is_rejected_and_non_call_reports_are_not_captured() -> None:
    observer = CAPTURE.Observations()
    for report in [_report(when="setup"), _report(when="teardown"), _report(passed=False)]:
        observer.pytest_runtest_logreport(report)
    assert observer.cases == {}
    report = _report(values=[{"boundary": "worker_error"}])
    observer.pytest_runtest_logreport(report)
    with pytest.raises(RuntimeError, match="one unique observation"):
        observer.pytest_runtest_logreport(report)


@pytest.mark.parametrize("missing", CAPTURE.EXPECTED_COUNTS)
def test_every_reference_boundary_must_be_complete(missing: str) -> None:
    observer = CAPTURE.Observations()
    for boundary, count in CAPTURE.EXPECTED_COUNTS.items():
        for index in range(count - (boundary == missing)):
            observer.cases[f"{boundary}-{index}"] = {"boundary": boundary}
    with pytest.raises(RuntimeError, match="incomplete"):
        observer.document()


def _matching_git(*arguments):
    if arguments[0] in {"diff", "ls-files"}:
        return ""
    path = arguments[-1].removeprefix(f"{CAPTURE.SOURCE_COMMIT}:")
    return CAPTURE.SOURCE_BLOBS[path]


@pytest.mark.parametrize("drift", ["source_blob", "working_blob", "untracked_runtime", "runtime_tree"])
def test_source_drift_prevents_test_execution(drift: str, monkeypatch: pytest.MonkeyPatch) -> None:
    def changed_git(*arguments):
        if drift == "runtime_tree" and arguments[0] == "diff":
            raise RuntimeError("Runtime tree changed")
        if ((drift == "source_blob" and arguments[0] == "rev-parse")
                or (drift == "working_blob" and arguments[0] == "hash-object")
                or (drift == "untracked_runtime" and arguments[0] == "ls-files")):
            return "changed"
        return _matching_git(*arguments)

    run_tests = Mock()
    monkeypatch.setattr(CAPTURE, "git", changed_git)
    monkeypatch.setattr(pytest, "main", run_tests)
    with pytest.raises(RuntimeError):
        CAPTURE.capture()
    run_tests.assert_not_called()


def test_failed_session_cannot_produce_a_document(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(CAPTURE, "git", _matching_git)
    monkeypatch.setattr(pytest, "main", lambda *_args, **_kwargs: pytest.ExitCode.TESTS_FAILED)
    # capture mutates only these test-runner settings; retain caller state in this unit test.
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    monkeypatch.delenv("PYTEST_ADDOPTS", raising=False)
    monkeypatch.setattr(CAPTURE.sys, "path", list(CAPTURE.sys.path))
    with pytest.raises(RuntimeError, match="did not pass"):
        CAPTURE.capture()


def test_source_revision_query_does_not_execute_capture(monkeypatch, capsys) -> None:
    observe = Mock()
    monkeypatch.setattr(CAPTURE, "capture", observe)
    monkeypatch.setattr(CAPTURE.sys, "argv", ["capture", "--source-commit"])
    assert CAPTURE.main() == 0
    assert capsys.readouterr().out.strip() == CAPTURE.SOURCE_COMMIT
    observe.assert_not_called()


def test_existing_capture_cannot_be_overwritten(monkeypatch, tmp_path) -> None:
    destination = tmp_path / "retained.json"
    destination.write_text("retained", encoding="utf-8")
    observe = Mock()
    monkeypatch.setattr(CAPTURE, "capture", observe)
    monkeypatch.setattr(CAPTURE.sys, "argv", ["capture", "--output", str(destination)])
    with pytest.raises(SystemExit) as caught:
        CAPTURE.main()
    assert caught.value.code == 2
    assert destination.read_text(encoding="utf-8") == "retained"
    observe.assert_not_called()


@pytest.mark.parametrize("matches", [False, True])
def test_verification_compares_regenerated_document_without_rewriting(monkeypatch, tmp_path, matches) -> None:
    destination = tmp_path / "frozen.json"
    original = b'{"observed": "retained"}\n'
    destination.write_bytes(original)
    observe = Mock(return_value={"observed": "retained" if matches else "different"})
    monkeypatch.setattr(CAPTURE, "capture", observe)
    monkeypatch.setattr(CAPTURE.sys, "argv", ["capture", "--verify", str(destination)])
    if matches:
        assert CAPTURE.main() == 0
    else:
        with pytest.raises(RuntimeError, match="differ from frozen reference"):
            CAPTURE.main()
    observe.assert_called_once_with()
    assert destination.read_bytes() == original


def test_new_capture_serializes_actual_observations_stably(monkeypatch, tmp_path) -> None:
    destination = tmp_path / "new.json"
    observed = {"z": "é🙂", "a": {"status": None, "completed": True}}
    monkeypatch.setattr(CAPTURE, "capture", Mock(return_value=observed))
    monkeypatch.setattr(CAPTURE.sys, "argv", ["capture", "--output", str(destination)])
    assert CAPTURE.main() == 0
    expected = json.dumps(observed, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    assert destination.read_bytes() == expected.encode("utf-8")
    assert json.loads(destination.read_text(encoding="utf-8")) == observed


@pytest.mark.parametrize("outside", [
    "issuance.canvas_worker", "issuance.infrastructure.api.signing_context",
])
def test_import_from_another_checkout_cannot_produce_a_document(monkeypatch, tmp_path, outside) -> None:
    monkeypatch.setattr(CAPTURE, "git", _matching_git)
    monkeypatch.setattr(pytest, "main", lambda *_args, **_kwargs: pytest.ExitCode.OK)
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    monkeypatch.delenv("PYTEST_ADDOPTS", raising=False)
    monkeypatch.setattr(CAPTURE.sys, "path", list(CAPTURE.sys.path))
    for module, path in (
        ("issuance.canvas_worker", "services/issuance/canvas_worker.py"),
        ("issuance.infrastructure.api.signing_context",
         "services/issuance/infrastructure/api/signing_context.py"),
    ):
        source = tmp_path / "outside.py" if module == outside else CAPTURE.ROOT / path
        monkeypatch.setitem(CAPTURE.sys.modules, module, SimpleNamespace(__file__=str(source)))
    document = Mock()
    monkeypatch.setattr(CAPTURE.Observations, "document", document)
    with pytest.raises(RuntimeError, match="loaded outside the owned source"):
        CAPTURE.capture()
    document.assert_not_called()


def test_python_quality_suite_requires_regeneration_from_pinned_source() -> None:
    script = (CAPTURE.ROOT / "scripts/run-python-ci.sh").read_text(encoding="utf-8")
    assert "capture_canvas_privacy_reference.py --source-commit" in script
    assert 'git fetch --no-tags --depth=1 origin "$privacy_source_commit"' in script
    assert "capture_canvas_privacy_reference.py --verify contracts/canvas-worker-privacy-reference.json" in script
