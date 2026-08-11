from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[2] / "scripts" / "stable_tag_gate.py"
SPEC = importlib.util.spec_from_file_location("stable_tag_gate", SCRIPT)
assert SPEC and SPEC.loader
stable_tag_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stable_tag_gate)

COMMIT = "a" * 40
TAG_OBJECT = "b" * 40
POLICY = {
    "schema": stable_tag_gate.SCHEMA,
    "required_workflows": [
        {"path": ".github/workflows/ci.yml", "event": "push"},
        {"path": "dynamic/github-code-scanning/codeql", "event": "dynamic"},
    ],
}


def run(run_id: int, path: str, event: str, **updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": run_id,
        "path": path,
        "event": event,
        "status": "completed",
        "conclusion": "success",
        "head_sha": COMMIT,
    }
    value.update(updates)
    return value


def payload() -> dict[str, object]:
    return {
        "workflow_runs": [
            run(10, ".github/workflows/ci.yml", "push"),
            run(11, "dynamic/github-code-scanning/codeql", "dynamic"),
        ]
    }


def test_exact_head_terminal_workflows_pass() -> None:
    accepted = stable_tag_gate.validate_workflow_runs(payload(), POLICY, COMMIT, 99)
    assert [item["run_id"] for item in accepted] == [10, 11]


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"status": "in_progress", "conclusion": None}, "pending"),
        ({"conclusion": "failure"}, "did not succeed"),
        ({"head_sha": "c" * 40}, "missing"),
    ],
)
def test_pending_failing_or_different_head_workflow_blocks(
    updates: dict[str, object], message: str
) -> None:
    document = payload()
    document["workflow_runs"][0].update(updates)
    with pytest.raises(stable_tag_gate.StableTagGateError, match=message):
        stable_tag_gate.validate_workflow_runs(document, POLICY, COMMIT, 99)


def release_evidence() -> dict[str, object]:
    return {
        "schema": stable_tag_gate.SCHEMA,
        "repository": "ElevenID/marty-credentials",
        "tag": "v1.2.3",
        "source_sha": COMMIT,
        "preparation_run_id": 42,
        "required_workflows": [{"path": "ci", "run_id": 10}],
        "tag_object_sha": TAG_OBJECT,
        "peeled_source_sha": COMMIT,
    }


def preparation_run() -> dict[str, object]:
    return {
        "id": 42,
        "path": stable_tag_gate.PREPARATION_WORKFLOW,
        "event": "workflow_dispatch",
        "head_sha": COMMIT,
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
    }


def tag_message() -> str:
    return (
        "Release 1.2.3\n\n"
        f"Stable-Tag-Gate: {stable_tag_gate.SCHEMA}\n"
        "Preparation-Run: 42\n"
        f"Source-SHA: {COMMIT}\n"
    )


def test_exact_annotated_release_proof_passes() -> None:
    stable_tag_gate.validate_release_proof(
        "ElevenID/marty-credentials",
        "v1.2.3",
        COMMIT,
        "tag",
        TAG_OBJECT,
        tag_message(),
        preparation_run(),
        release_evidence(),
    )


def test_lightweight_tag_is_rejected_without_mutation() -> None:
    with pytest.raises(stable_tag_gate.StableTagGateError, match="annotated"):
        stable_tag_gate.validate_release_proof(
            "ElevenID/marty-credentials",
            "v1.2.3",
            COMMIT,
            "commit",
            TAG_OBJECT,
            tag_message(),
            preparation_run(),
            release_evidence(),
        )
