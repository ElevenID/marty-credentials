from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts" / "release_service_handoff.py"
SPEC = importlib.util.spec_from_file_location("release_service_handoff", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release_service_handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_service_handoff)
RELEASE_CONTRACT_SCRIPT = ROOT / "scripts" / "release_contract.py"
RELEASE_CONTRACT_SPEC = importlib.util.spec_from_file_location(
    "tag_scoped_release_contract", RELEASE_CONTRACT_SCRIPT
)
assert RELEASE_CONTRACT_SPEC is not None and RELEASE_CONTRACT_SPEC.loader is not None
release_contract = importlib.util.module_from_spec(RELEASE_CONTRACT_SPEC)
RELEASE_CONTRACT_SPEC.loader.exec_module(release_contract)


def _write_contract_repository(
    root: Path,
    assignment: str,
    *,
    dockerfiles: tuple[str, ...] = ("issuance", "verification"),
) -> Path:
    (root / "scripts").mkdir(parents=True)
    (root / "scripts" / "release_contract.py").write_text(f"{assignment}\n", encoding="utf-8")
    for service in dockerfiles:
        dockerfile = root / release_service_handoff.SERVICE_DOCKERFILES[service]
        dockerfile.parent.mkdir(parents=True, exist_ok=True)
        dockerfile.write_text("FROM scratch\n", encoding="utf-8")
    return root


def test_current_contract_produces_canonical_issuance_only_handoff() -> None:
    assert release_service_handoff.build_service_matrix(ROOT) == {
        "include": [{"service": "issuance", "dockerfile": "services/Dockerfile"}]
    }
    assert release_service_handoff.canonical_service_matrix(ROOT) == (
        '{"include":[{"dockerfile":"services/Dockerfile","service":"issuance"}]}'
    )


def test_historical_contract_produces_two_service_recovery_handoff(tmp_path: Path) -> None:
    repository = _write_contract_repository(
        tmp_path,
        'SERVICES = ("issuance", "verification")',
    )

    matrix = release_service_handoff.build_service_matrix(repository)

    assert matrix == {
        "include": [
            {"service": "issuance", "dockerfile": "services/Dockerfile"},
            {
                "service": "verification",
                "dockerfile": "services/verification/Dockerfile",
            },
        ]
    }
    assert json.loads(release_service_handoff.canonical_service_matrix(repository)) == matrix


def test_historical_partial_and_complete_drafts_use_both_service_contracts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(release_contract, "SERVICES", ("issuance", "verification"))
    stable = release_contract.stable_asset_names("0.1.7")
    partial = stable | {
        "marty-credentials-issuance.digest",
        "marty-credentials-issuance.spdx.json",
    }

    def payload(names: set[str]) -> dict[str, object]:
        return {
            "id": 1234,
            "tag_name": "v0.1.7",
            "target_commitish": "a" * 40,
            "draft": True,
            "prerelease": False,
            "assets": [{"name": name, "state": "uploaded"} for name in sorted(names)],
        }

    assert (
        release_contract.validate_release(
            payload(partial),
            release_id=1234,
            tag="v0.1.7",
            commit="a" * 40,
            phase="resumable",
        )
        == "build"
    )
    complete = release_contract.final_asset_names("0.1.7")
    assert {
        "marty-credentials-verification.digest",
        "marty-credentials-verification.spdx.json",
    } <= complete
    assert (
        release_contract.validate_release(
            payload(complete),
            release_id=1234,
            tag="v0.1.7",
            commit="a" * 40,
            phase="resumable",
        )
        == "complete"
    )
    assert (
        release_contract.validate_release(
            payload(complete),
            release_id=1234,
            tag="v0.1.7",
            commit="a" * 40,
            phase="complete-draft",
        )
        is None
    )


@pytest.mark.parametrize(
    ("assignment", "message"),
    [
        ("SERVICES = ()", "must not be empty"),
        ('SERVICES = ("issuance", "issuance")', "must not contain duplicates"),
        ('SERVICES = ("issuance", "future")', "is not allowed"),
        ('SERVICES = ("issuance", "bad/name")', "name is invalid"),
    ],
)
def test_service_handoff_rejects_empty_duplicate_unknown_or_invalid_services(
    tmp_path: Path, assignment: str, message: str
) -> None:
    repository = _write_contract_repository(tmp_path, assignment)

    with pytest.raises(release_service_handoff.ServiceHandoffError, match=message):
        release_service_handoff.build_service_matrix(repository)


@pytest.mark.parametrize(
    "assignment",
    [
        'SERVICES = ["issuance"]',
        'SERVICES = tuple(("issuance",))',
        'SERVICES = ("issuance",)\nSERVICES = ("verification",)',
    ],
)
def test_service_handoff_rejects_nonliteral_or_rebound_contracts(
    tmp_path: Path, assignment: str
) -> None:
    repository = _write_contract_repository(tmp_path, assignment)

    with pytest.raises(release_service_handoff.ServiceHandoffError):
        release_service_handoff.build_service_matrix(repository)


def test_service_handoff_requires_each_allowed_service_dockerfile(tmp_path: Path) -> None:
    repository = _write_contract_repository(
        tmp_path,
        'SERVICES = ("issuance", "verification")',
        dockerfiles=("issuance",),
    )

    with pytest.raises(
        release_service_handoff.ServiceHandoffError,
        match="verification.*Dockerfile",
    ):
        release_service_handoff.build_service_matrix(repository)
