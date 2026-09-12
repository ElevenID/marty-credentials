"""Verify frozen observations against isolated historical runtime source."""

from __future__ import annotations

import argparse
import ast
import os
import runpy
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPTURE = "scripts/capture_canvas_privacy_reference.py"
SUPPORT = (
    CAPTURE,
    "tests/unit/test_signing_context_error_bounds.py",
    "tests/unit/test_canvas_worker_error_privacy.py",
)
ARTIFACT = "contracts/canvas-worker-privacy-reference.json"
SOURCE_ROOTS = ("services", "python", "packages")
OWNED_IMPORTS = ("issuance", "marty_credentials", "marty_proto", "tests")


def git(root: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", *arguments], cwd=root, check=True, capture_output=True, timeout=120,
    ).stdout


def assert_reference(root: Path, source: str) -> None:
    if Path(git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve() != root.resolve():
        raise RuntimeError("Historical checkout root does not match its owned path")
    if git(root, "rev-parse", "HEAD").decode().strip() != source:
        raise RuntimeError("Historical checkout is not the pinned revision")
    git(root, "diff", "--quiet", "--no-ext-diff", source, "--", *SOURCE_ROOTS)
    if git(root, "ls-files", "--others", "--exclude-standard", "--", *SOURCE_ROOTS):
        raise RuntimeError("Historical checkout contains untracked runtime source")


def assert_owned_imports(root: Path) -> None:
    for name, module in tuple(sys.modules.items()):
        if name.split(".")[0] not in OWNED_IMPORTS:
            continue
        paths = list(getattr(module, "__path__", ()))
        location = getattr(module, "__file__", None)
        if location is not None:
            paths.append(location)
        if not paths or any(not Path(path).resolve().is_relative_to(root) for path in paths):
            raise RuntimeError("Historical capture imported owned code outside its checkout")


def capture_reference(root: Path, source: str, artifact: Path) -> None:
    """Called only in a fresh isolated Python process, never the current tests."""
    root = root.resolve()
    assert_reference(root, source)
    sys.path[:0] = [str(root), *(str(root / path) for path in SOURCE_ROOTS)]
    sys.argv = [str(root / CAPTURE), "--verify", str(artifact)]
    try:
        runpy.run_path(str(root / CAPTURE), run_name="__main__")
    finally:
        assert_reference(root, source)
        assert_owned_imports(root)


def source_commit(capture: bytes) -> str:
    values = [
        node.value for node in ast.parse(capture).body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "SOURCE_COMMIT" for target in node.targets)
    ]
    if len(values) != 1 or not isinstance(values[0], ast.Constant):
        raise RuntimeError("Historical capture must declare one literal source commit")
    source = values[0].value
    if (not isinstance(source, str) or len(source) != 40
            or any(character not in "0123456789abcdef" for character in source)):
        raise RuntimeError("Historical capture did not select an exact source commit")
    return source


def remove_reference(temporary: Path, reference: Path) -> None:
    if reference.resolve().parent != temporary.resolve():
        raise RuntimeError("Refusing cleanup outside the owned temporary directory")
    top = Path(git(reference, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if top != reference.resolve():
        raise RuntimeError("Refusing cleanup of a different checkout root")
    git(ROOT, "worktree", "remove", "--force", str(reference))


def verify() -> None:
    # Snapshot support and the oracle from one immutable current commit. Runtime
    # source is deliberately NOT copied from the current checkout.
    head = git(ROOT, "rev-parse", "HEAD").decode().strip()
    support = {path: git(ROOT, "show", f"{head}:{path}") for path in SUPPORT}
    frozen = git(ROOT, "show", f"{head}:{ARTIFACT}")
    source = source_commit(support[CAPTURE])
    try:
        git(ROOT, "cat-file", "-e", f"{source}^{{commit}}")
    except subprocess.CalledProcessError:
        git(ROOT, "fetch", "--no-tags", "--depth=1", "origin", source)

    with tempfile.TemporaryDirectory(prefix="credentials-privacy-reference-") as directory:
        temporary = Path(directory).resolve()
        reference = temporary / "reference"
        artifact = temporary / "frozen.json"
        try:
            git(ROOT, "worktree", "add", "--quiet", "--detach", str(reference), source)
            assert_reference(reference, source)
            for path, content in support.items():
                destination = reference / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
            artifact.write_bytes(frozen)
            # Preserve OS execution essentials, not operator service settings,
            # credential selectors or ambient Python/pytest import configuration.
            environment = {
                name: value for name, value in os.environ.items()
                if name.casefold() in {
                    "path", "systemroot", "windir", "temp", "tmp", "systemdrive",
                    "comspec", "pathext", "lang", "lc_all", "lc_ctype",
                }
            }
            subprocess.run(
                [sys.executable, "-I", str(Path(__file__).resolve()),
                 "--capture-root", str(reference), "--source", source,
                 "--artifact", str(artifact)],
                cwd=reference, env=environment, check=True, timeout=300,
            )
        finally:
            # The only force removal is this runner's freshly allocated child,
            # which contains intentionally staged test/support changes.
            if reference.exists():
                remove_reference(temporary, reference)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--source", help=argparse.SUPPRESS)
    parser.add_argument("--artifact", type=Path, help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.capture_root is not None:
        if arguments.source is None or arguments.artifact is None:
            parser.error("Isolated capture requires its source and artifact")
        capture_reference(arguments.capture_root, arguments.source, arguments.artifact)
    else:
        if arguments.source is not None or arguments.artifact is not None:
            parser.error("Capture arguments require an isolated root")
        verify()


if __name__ == "__main__":
    main()
