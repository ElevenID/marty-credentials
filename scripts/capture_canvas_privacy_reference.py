"""Capture actual observations from the existing hardened-reference tests.

No alternate worker, response parser or expected-output generator lives here.
Any failed test (including teardown) or changed runtime source prevents capture.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = "d418ac0df283625f43b0c011fb1c72fd7d3013a9"
SOURCE_BLOBS = {
    "services/issuance/canvas_worker.py": "82554ebbcef4c55aa0b23ecb945efdcc1f60a071",
    "services/issuance/infrastructure/api/signing_context.py":
        "5e84cfdcbdf289ec0059eb39dd54c4a5c79c5b3a",
}
TESTS = (
    "tests/unit/test_signing_context_error_bounds.py",
    "tests/unit/test_canvas_worker_error_privacy.py",
)
EXPECTED_COUNTS = {
    "signing_error_detail": 45,
    "signing_operation_error": 6,
    "worker_error": 12,
}
SOURCE_ROOTS = ("services", "python", "packages")


def git(*arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout.strip()


class Observations:
    def __init__(self) -> None:
        self.cases: dict[str, dict] = {}

    def pytest_runtest_logreport(self, report) -> None:
        if report.when != "call" or not report.passed:
            return
        values = [value for name, value in report.user_properties if name == "canvas_privacy"]
        if len(values) != 1 or report.nodeid in self.cases:
            raise RuntimeError("Expected one unique observation per passing privacy case")
        self.cases[report.nodeid] = values[0]

    def document(self) -> dict:
        counts = Counter(case["boundary"] for case in self.cases.values())
        if dict(counts) != EXPECTED_COUNTS:
            raise RuntimeError(f"Privacy capture is incomplete: {dict(counts)}")
        return {
            "schema": "marty.canvas-privacy-reference/v1",
            "source_commit": SOURCE_COMMIT,
            "source_blobs": SOURCE_BLOBS,
            "source_trees": {path: git("rev-parse", f"{SOURCE_COMMIT}:{path}")
                             for path in SOURCE_ROOTS},
            "test_blobs": {path: git("hash-object", path) for path in TESTS},
            "boundary": "actual reference helpers/worker cycles; in-memory repository and controlled adapters",
            "normalization": {
                "generated_job_ids": "<matching-job-id> only after exact log/outcome identity assertion",
                "timestamps": "presence and lease-state projections only; no clock mutation",
                "log_metadata": "producer snapshot before ambient formatter enrichment; rendered logs also checked",
                "http_input": "explicit supplied JSON bytes independent of HTTPX serializer spacing",
            },
            "counts": EXPECTED_COUNTS,
            "cases": [{"id": key, **self.cases[key]} for key in sorted(self.cases)],
        }


def capture() -> dict:
    git("diff", "--quiet", "--no-ext-diff", SOURCE_COMMIT, "--", *SOURCE_ROOTS)
    if git("ls-files", "--others", "--exclude-standard", "--", *SOURCE_ROOTS):
        raise RuntimeError("Untracked runtime source prevents reference capture")
    for path, expected in SOURCE_BLOBS.items():
        if git("rev-parse", f"{SOURCE_COMMIT}:{path}") != expected:
            raise RuntimeError(f"Protected reference provenance changed: {path}")
        if git("hash-object", path) != expected:
            raise RuntimeError(f"Working source differs from protected reference: {path}")
    # Only the named asyncio plugin is required. Do not inherit arbitrary local
    # pytest plugins or injected command-line options into a frozen observation.
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    os.environ.pop("PYTEST_ADDOPTS", None)
    sys.path.insert(0, str(ROOT))
    import pytest

    observer = Observations()
    result = pytest.main([
        *[str(ROOT / path) for path in TESTS],
        "--rootdir", str(ROOT), "-q", "--tb=short", "-p", "no:cacheprovider",
        "-p", "pytest_asyncio.plugin", "-o", "addopts=",
    ], plugins=[observer])
    if result != pytest.ExitCode.OK:
        raise RuntimeError(f"Privacy reference tests did not pass: exit {int(result)}")
    for module, path in (
        ("issuance.canvas_worker", "services/issuance/canvas_worker.py"),
        ("issuance.infrastructure.api.signing_context",
         "services/issuance/infrastructure/api/signing_context.py"),
    ):
        if Path(sys.modules[module].__file__).resolve() != (ROOT / path).resolve():
            raise RuntimeError(f"Reference module loaded outside the owned source: {module}")
    return observer.document()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=Path, help="Create a new capture; never overwrite")
    destination.add_argument("--verify", type=Path, help="Compare with an existing frozen capture")
    destination.add_argument("--source-commit", action="store_true", help="Print required reference revision")
    args = parser.parse_args()
    if args.source_commit:
        print(SOURCE_COMMIT)
        return 0
    if args.output is not None and args.output.exists():
        parser.error("Capture destination already exists")
    document = capture()
    if args.verify is not None:
        if json.loads(args.verify.read_text(encoding="utf-8")) != document:
            raise RuntimeError("Hardened privacy observations differ from frozen reference")
    else:
        with args.output.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(document, output, ensure_ascii=True, indent=2, sort_keys=True)
            output.write("\n")
    print("Hardened privacy reference: 63 observed cases passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
