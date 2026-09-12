"""The historical oracle is isolated without weakening its source freeze."""

import importlib.util
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

SPEC = importlib.util.spec_from_file_location(
    "canvas_privacy_reference_runner", Path(__file__).resolve().parents[2]
    / "scripts/verify_canvas_privacy_reference.py",
)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
SOURCE = "d418ac0df283625f43b0c011fb1c72fd7d3013a9"


@pytest.mark.parametrize("declaration", [
    b"", b"SOURCE_COMMIT = 'main'", b"SOURCE_COMMIT = 1",
    b"SOURCE_COMMIT = str('a' * 40)",
    b"SOURCE_COMMIT = 'a' * 40", b"SOURCE_COMMIT = 'A' * 40",
    (f"SOURCE_COMMIT = '{SOURCE}'\n" * 2).encode(),
])
def test_source_revision_must_be_one_exact_literal(declaration) -> None:
    with pytest.raises(RuntimeError):
        RUNNER.source_commit(declaration)


def test_source_revision_is_read_from_the_immutable_capture_support() -> None:
    capture = f"SOURCE_COMMIT = '{SOURCE}'\nraise RuntimeError('must not execute')\n".encode()
    assert RUNNER.source_commit(capture) == SOURCE


@pytest.mark.parametrize("failure", [None, "capture", "checkout"])
@pytest.mark.parametrize("missing_source", [False, True])
def test_runner_stages_only_immutable_support_and_cleans_owned_checkout(
    monkeypatch, failure, missing_source,
) -> None:
    calls = []
    head = "a" * 40
    blobs = {path: f"# immutable {path}\n".encode() for path in RUNNER.SUPPORT}
    blobs[RUNNER.CAPTURE] = f"SOURCE_COMMIT = '{SOURCE}'\n".encode()
    blobs[RUNNER.ARTIFACT] = b'{"immutable":true}\n'
    checkout = None

    def git(root, *arguments):
        nonlocal checkout
        calls.append(arguments)
        if arguments == ("rev-parse", "HEAD"):
            return (SOURCE if root == checkout else head).encode()
        if arguments == ("rev-parse", "--show-toplevel"):
            return str(root).encode()
        if arguments[0] == "show":
            revision, path = arguments[1].split(":", 1)
            assert revision == head
            return blobs[path]
        if arguments[0] == "cat-file" and missing_source:
            raise subprocess.CalledProcessError(1, ["git", "cat-file"])
        if arguments[:2] == ("worktree", "add"):
            assert arguments[2:4] == ("--quiet", "--detach")
            assert arguments[-1] == SOURCE
            checkout = Path(arguments[-2])
            checkout.mkdir()
            if failure == "checkout":
                raise subprocess.CalledProcessError(1, ["git", "worktree", "add"])
        return b""

    def capture(command, **kwargs):
        assert command[:2] == [RUNNER.sys.executable, "-I"]
        assert kwargs["cwd"] == checkout
        assert kwargs["check"] is True and kwargs["timeout"] == 300
        assert not {"PYTHONPATH", "PYTHONHOME", "PYTEST_ADDOPTS", "PYTEST_PLUGINS",
                    "SIGNING_KEYS_INTERNAL_API_KEY", "ISSUANCE_API_KEY_FILE"} & kwargs["env"].keys()
        assert "--capture-root" in command and command[command.index("--source") + 1] == SOURCE
        assert {path.relative_to(checkout).as_posix() for path in checkout.rglob("*")
                if path.is_file()} == set(RUNNER.SUPPORT)
        assert all((checkout / path).read_bytes() == blobs[path] for path in RUNNER.SUPPORT)
        artifact = Path(command[command.index("--artifact") + 1])
        assert artifact.parent == checkout.parent and artifact.parent != checkout
        assert artifact.read_bytes() == blobs[RUNNER.ARTIFACT]
        if failure == "capture":
            raise subprocess.CalledProcessError(1, command)
        return SimpleNamespace(returncode=0)

    for name in ("PYTHONPATH", "PYTHONHOME", "PYTEST_ADDOPTS", "PYTEST_PLUGINS",
                 "SIGNING_KEYS_INTERNAL_API_KEY", "ISSUANCE_API_KEY_FILE"):
        monkeypatch.setenv(name, "synthetic-must-not-reach-child")
    monkeypatch.setattr(RUNNER, "git", git)
    run_capture = Mock(side_effect=capture)
    monkeypatch.setattr(RUNNER.subprocess, "run", run_capture)
    if failure:
        with pytest.raises(subprocess.CalledProcessError):
            RUNNER.verify()
    else:
        RUNNER.verify()
    assert calls[-1] == ("worktree", "remove", "--force", str(checkout))
    assert not checkout.parent.exists()
    assert run_capture.call_count == (failure != "checkout")
    fetches = [arguments for arguments in calls if arguments[0] == "fetch"]
    assert fetches == ([("fetch", "--no-tags", "--depth=1", "origin", SOURCE)] if missing_source else [])


@pytest.mark.parametrize("drift", ["root", "revision", "runtime", "untracked"])
def test_reference_guard_rejects_any_protected_source_drift(monkeypatch, tmp_path, drift) -> None:
    def git(root, *arguments):
        if arguments == ("rev-parse", "--show-toplevel"):
            return str(root / "wrong" if drift == "root" else root).encode()
        if arguments == ("rev-parse", "HEAD"):
            return ("changed" if drift == "revision" else SOURCE).encode()
        if arguments[0] == "diff" and drift == "runtime":
            raise subprocess.CalledProcessError(1, ["git", "diff"])
        return b"unexpected.py" if drift == "untracked" else b""

    monkeypatch.setattr(RUNNER, "git", git)
    with pytest.raises((RuntimeError, subprocess.CalledProcessError)):
        RUNNER.assert_reference(tmp_path, SOURCE)


@pytest.mark.parametrize("failure", [False, True])
def test_child_prioritizes_pinned_imports_and_rechecks_after_capture(monkeypatch, tmp_path, failure) -> None:
    events = []
    child_sys = SimpleNamespace(path=["ambient-site"], argv=[], modules={})
    monkeypatch.setattr(RUNNER, "sys", child_sys)
    monkeypatch.setattr(RUNNER, "assert_reference", lambda *_: events.append("source"))
    monkeypatch.setattr(RUNNER, "assert_owned_imports", lambda *_: events.append("imports"))

    def capture(path, *, run_name):
        events.append("capture")
        assert child_sys.path[:4] == [str(tmp_path), *(str(tmp_path / p) for p in RUNNER.SOURCE_ROOTS)]
        assert path == str(tmp_path / RUNNER.CAPTURE) and run_name == "__main__"
        assert child_sys.argv == [path, "--verify", str(tmp_path / "frozen.json")]
        raise SystemExit(1 if failure else 0)

    monkeypatch.setattr(RUNNER.runpy, "run_path", capture)
    with pytest.raises(SystemExit) as result:
        RUNNER.capture_reference(tmp_path, SOURCE, tmp_path / "frozen.json")
    assert result.value.code == int(failure)
    assert events == ["source", "capture", "source", "imports"]


@pytest.mark.parametrize("prefix", RUNNER.OWNED_IMPORTS)
@pytest.mark.parametrize("kind", ["file", "namespace", "missing"])
def test_every_owned_import_rejects_ambient_or_unknown_origin(monkeypatch, tmp_path, prefix, kind) -> None:
    attributes = {}
    outside = str(tmp_path.parent / "ambient.py")
    if kind == "file":
        attributes["__file__"] = outside
    if kind == "namespace":
        attributes["__path__"] = [str(tmp_path / prefix), outside]
    monkeypatch.setattr(RUNNER, "sys", SimpleNamespace(modules={prefix: SimpleNamespace(**attributes)}))
    with pytest.raises(RuntimeError, match="outside its checkout"):
        RUNNER.assert_owned_imports(tmp_path)


def test_pinned_owned_imports_and_unowned_site_dependencies_are_allowed(monkeypatch, tmp_path) -> None:
    modules = {
        prefix: SimpleNamespace(__file__=str(tmp_path / prefix / "__init__.py"))
        for prefix in RUNNER.OWNED_IMPORTS
    }
    modules["pytest"] = SimpleNamespace(__file__="ambient-site/pytest.py")
    monkeypatch.setattr(RUNNER, "sys", SimpleNamespace(modules=modules))
    RUNNER.assert_owned_imports(tmp_path)


@pytest.mark.parametrize("outside", [False, True])
def test_cleanup_cannot_remove_another_checkout(monkeypatch, tmp_path, outside) -> None:
    reference = tmp_path.parent / "user-tree" if outside else tmp_path / "reference"
    git = Mock(return_value=str(tmp_path / "wrong-root").encode())
    monkeypatch.setattr(RUNNER, "git", git)
    with pytest.raises(RuntimeError, match="Refusing cleanup"):
        RUNNER.remove_reference(tmp_path, reference)
    assert all(call.args[1] != "worktree" for call in git.call_args_list)
