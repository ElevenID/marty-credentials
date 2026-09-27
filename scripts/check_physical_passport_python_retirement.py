"""Fail closed until physical-passport Rust runtime acceptance is verifiable."""

from __future__ import annotations

import argparse
from pathlib import Path

from scripts import check_issuance_python_retirement as prior_gate

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "contracts/physical-passport-python-retirement-qualification.json"
EXPECTED_DELETIONS = {
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
EXPECTED_ARTIFACTS = {
    "contracts/issuance-physical-passport-native.json",
    "contracts/issuance-native-coverage.json",
    "contracts/issuance-universal-ownership.json",
    "docker-compose.profile.passport-native-beta.yml",
}


def verify(contract_path: Path) -> None:
    contract = prior_gate._json(contract_path)
    prior_gate._require(
        contract.get("schema") == "marty.physical-passport-python-retirement-qualification/v1",
        "Unknown passport retirement qualification schema",
    )
    prior_gate._require(
        prior_gate._route_keys(contract.get("authorized_python_route_deletions"), "passport deletions")
        == EXPECTED_DELETIONS,
        "Passport deletion identities changed",
    )
    prior_gate._require(
        contract.get("full_python_service_deletion_authorized") is False,
        "Full Python service deletion is not authorized",
    )
    source = contract.get("source")
    prior_gate._require(isinstance(source, dict), "Passport source checkpoint is missing")
    prior_gate._require(source.get("repository") == "ElevenID/marty-ui", "Unexpected source repository")
    artifacts = source.get("required_artifacts")
    prior_gate._require(
        isinstance(artifacts, list)
        and len(artifacts) == len(EXPECTED_ARTIFACTS)
        and set(artifacts) == EXPECTED_ARTIFACTS,
        "Passport source artifact set changed",
    )

    if contract.get("state") == "blocked_pending_beta_acceptance":
        prior_gate._require(
            source.get("protected_main_commit") is None
            and source.get("artifact_sha256") is None
            and contract.get("beta_acceptance_receipt") is None
            and contract.get("supported_consumer_cutover_receipt") is None,
            "Blocked passport qualification invented evidence",
        )
        raise prior_gate.QualificationError(
            "Passport Python retirement is blocked pending beta and supported-consumer acceptance"
        )

    prior_gate._require(contract.get("state") == "qualified", "Unknown passport qualification state")
    raise prior_gate.QualificationError(
        "Passport Python retirement is not qualified: protected-source, signed-release, "
        "beta runtime, physical bureau, and supported-consumer evidence need an executable "
        "verifier before Python deletion can be authorized"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    args = parser.parse_args()
    try:
        verify(args.contract)
    except prior_gate.QualificationError as error:
        parser.exit(1, f"{error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
