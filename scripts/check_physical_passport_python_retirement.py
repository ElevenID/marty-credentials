"""Fail closed until physical-passport Rust runtime acceptance is verifiable."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
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
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
REQUIRED_BETA_PROBES = {
    "managed_csca_dsc_chain",
    "sod_signature",
    "nine_route_gateway_flow",
    "packaged_image",
    "physical_bureau_submission",
    "physical_bureau_batch",
    "signed_bureau_callback",
    "legacy_drain",
    "rollback",
    "production_isolation",
    "physical_booklet_verified",
}
EXPECTED_SURFACES = {"base", "selfhost", "kubernetes"}
EXPECTED_BETA_SERVICES = {
    "gateway",
    "flow",
    "issuance-native",
    "signing-keys",
    "passport-callback-signer-supported",
    "passport-provider-ingress",
}
REQUIRED_SUPPORTED_PROBES = {
    "nine_route_gateway_flow",
    "managed_signer",
    "physical_bureau_callback",
    "released_image",
    "rollback",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _command(*args: str) -> str:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    prior_gate._require(result.returncode == 0, f"Evidence command failed: {args[0]} {args[1]}")
    return result.stdout


def _verified_run(run_id: int, source_commit: str, workflow: str) -> None:
    prior_gate._require(isinstance(run_id, int) and run_id > 0, "Acceptance run ID is invalid")
    run = json.loads(_command("gh", "api", f"repos/ElevenID/marty-ui/actions/runs/{run_id}"))
    prior_gate._require(
        run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and run.get("head_sha") == source_commit
        and run.get("head_branch") == "main"
        and run.get("path") == workflow
        and run.get("repository", {}).get("full_name") == "ElevenID/marty-ui"
        and run.get("head_repository", {}).get("full_name") == "ElevenID/marty-ui",
        "Acceptance artifact is not from a successful protected UI workflow run",
    )


def _run_artifact(run_id: int, artifact_name: str, digest: str, output: Path) -> dict:
    prior_gate._require(
        isinstance(artifact_name, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json", artifact_name) is not None,
        "Acceptance artifact name is invalid",
    )
    prior_gate._require(isinstance(digest, str) and SHA256.fullmatch(digest) is not None,
                        "Acceptance artifact digest is invalid")
    output.mkdir(parents=True, exist_ok=False)
    _command("gh", "run", "download", str(run_id), "--repo", "ElevenID/marty-ui",
             "--name", artifact_name.removesuffix(".json"), "--dir", str(output))
    artifact = output / artifact_name
    prior_gate._require(artifact.is_file(), "Acceptance artifact is missing from the run")
    prior_gate._require(artifact.stat().st_size <= 1024 * 1024, "Acceptance artifact is oversized")
    prior_gate._require(_sha256(artifact) == digest, "Acceptance artifact SHA-256 mismatch")
    return prior_gate._json(artifact)


def _protected_source(source: dict, marty_ui: Path) -> str:
    commit = source.get("protected_main_commit")
    prior_gate._require(isinstance(commit, str) and COMMIT.fullmatch(commit) is not None,
                        "Passport source commit is not immutable")
    prior_gate._require(prior_gate._git_head(marty_ui) == commit, "UI checkout is not pinned")
    clean = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all", "--ignored"],
        cwd=marty_ui, check=False, capture_output=True, text=True,
    )
    prior_gate._require(clean.returncode == 0 and not clean.stdout.strip(),
                        "Qualified UI source checkout has local or ignored files")
    prior_gate._require(prior_gate._git_is_from_protected_main(marty_ui, commit),
                        "Passport source is not on live protected UI main")
    hashes = source.get("artifact_sha256")
    prior_gate._require(isinstance(hashes, dict) and set(hashes) == EXPECTED_ARTIFACTS,
                        "Passport source artifact hashes are incomplete")
    for relative, expected in hashes.items():
        prior_gate._require(isinstance(expected, str) and SHA256.fullmatch(expected) is not None,
                            f"Passport artifact hash is invalid: {relative}")
        actual = hashlib.sha256(prior_gate._git_blob(marty_ui, commit, relative)).hexdigest()
        prior_gate._require(actual == expected, f"Passport artifact hash mismatch: {relative}")
    return commit


def _frozen_batch_parity(marty_ui: Path) -> None:
    """Run the shuffled-response Rust oracle from the qualified source checkout."""
    checkout = marty_ui.resolve()
    try:
        result = subprocess.run(
            ["cargo", "test", "--locked", "--manifest-path", str(checkout / "rust/Cargo.toml"),
             "-p", "marty-issuance-service", "--lib",
             "passport_bureau::tests::batch_submission_preserves_python_envelope_and_input_order",
             "--", "--exact"],
            cwd=checkout, capture_output=True, text=True, check=False, timeout=3600,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise prior_gate.QualificationError("Frozen Rust batch parity could not run") from exc
    prior_gate._require(result.returncode == 0 and re.search(r"\b1 passed; 0 failed;", result.stdout) is not None,
                        "Frozen Rust batch parity did not pass exactly one test")


def _beta_report(report: dict, commit: str, stack_sha256: str) -> None:
    prior_gate._require(report.get("schema") == "marty.passport-beta-acceptance/v1"
                        and report.get("status") == "accepted", "Beta report has not accepted passport")
    release = report.get("release")
    prior_gate._require(isinstance(release, dict)
                        and release.get("source_commit") == commit
                        and release.get("stack_manifest_sha256") == stack_sha256
                        and release.get("signed_manifest_verified") is True,
                        "Beta report release lineage mismatch")
    prior_gate._require(report.get("beta_origin") == "https://beta.elevenidllc.com",
                        "Beta report origin mismatch")
    deployment = report.get("deployment")
    prior_gate._require(isinstance(deployment, dict)
                        and deployment.get("provider_mode") == "physical"
                        and all(isinstance(deployment.get(name), str)
                                and SHA256.fullmatch(deployment[name]) is not None
                                for name in ("local_deployment_manifest_sha256",
                                             "source_manifest_sha256")),
                        "Beta deployment manifest provenance is missing")
    prior_gate._require(isinstance(report.get("runtime_images"), dict)
                        and set(report["runtime_images"]) == EXPECTED_BETA_SERVICES,
                        "Beta runtime service image set is incomplete")
    probes = report.get("probes")
    prior_gate._require(isinstance(probes, dict) and set(probes) >= REQUIRED_BETA_PROBES,
                        "Beta passport probes are incomplete")
    for name in REQUIRED_BETA_PROBES:
        probe = probes[name]
        prior_gate._require(isinstance(probe, dict) and probe.get("verified") is True
                            and probe.get("evidence") is not None,
                            f"Beta passport probe did not pass: {name}")
    batch = probes["physical_bureau_batch"]["evidence"]
    images = release.get("oci_digests")
    services = images.get("ghcr.io/elevenid/marty-ui-oss/services") if isinstance(images, dict) else None
    prior_gate._require(
        isinstance(batch, dict)
        and batch.get("provider_kind") == "physical"
        and batch.get("simulator_ids_absent") is True
        and batch.get("source_commit") == commit
        and batch.get("stack_manifest_sha256") == stack_sha256
        and isinstance(services, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", services) is not None
        and batch.get("services_oci_reference")
        == f"ghcr.io/elevenid/marty-ui-oss/services@{services}"
        and isinstance(batch.get("request_sha256"), str)
        and SHA256.fullmatch(batch["request_sha256"]) is not None
        and isinstance(batch.get("response_sha256"), str)
        and SHA256.fullmatch(batch["response_sha256"]) is not None
        and isinstance(batch.get("provider_receipt_sha256"), str)
        and SHA256.fullmatch(batch["provider_receipt_sha256"]) is not None,
        "Physical batch provider evidence is not bound to the signed beta source",
    )
    submitted = batch.get("submitted_job_sha256")
    returned = batch.get("returned_jobs")
    prior_gate._require(
        isinstance(submitted, list) and len(submitted) >= 2
        and all(isinstance(job, str) and SHA256.fullmatch(job) is not None for job in submitted)
        and len(set(submitted)) == len(submitted)
        and isinstance(returned, list) and len(returned) == len(submitted)
        and batch.get("http_status") in (200, 201, 202)
        and batch.get("batch_status") == "QUEUED"
        and all(isinstance(job, dict)
                and isinstance(job.get("source_job_sha256"), str)
                and SHA256.fullmatch(job["source_job_sha256"]) is not None
                and isinstance(job.get("bureau_job_sha256"), str)
                and SHA256.fullmatch(job["bureau_job_sha256"]) is not None
                and job.get("status") in {"QUEUED", "PRINTING", "ENCODING", "QUALITY_CHECK", "SHIPPED", "DELIVERED"}
                for job in returned)
        and {job["source_job_sha256"] for job in returned} == set(submitted)
        and len({job["bureau_job_sha256"] for job in returned}) == len(returned),
        "Physical batch provider exchange or job mapping is incomplete",
    )


def _supported_report(report: dict, commit: str, services_reference: str) -> None:
    prior_gate._require(report.get("schema") == "marty.passport-supported-consumer-acceptance/v1"
                        and report.get("status") == "accepted"
                        and report.get("source_commit") == commit,
                        "Supported consumer report lineage mismatch")
    surfaces = report.get("surfaces")
    prior_gate._require(isinstance(surfaces, dict) and set(surfaces) == EXPECTED_SURFACES,
                        "Supported consumer surfaces are incomplete")
    for name in EXPECTED_SURFACES:
        item = surfaces[name]
        prior_gate._require(isinstance(item, dict)
                            and item.get("runtime_accepted") is True
                            and item.get("rollback_accepted") is True,
                            f"Supported consumer runtime/rollback incomplete: {name}")
        probes = item.get("probes")
        prior_gate._require(isinstance(probes, dict)
                            and set(probes) >= REQUIRED_SUPPORTED_PROBES,
                            f"Supported consumer probes missing: {name}")
        for probe_name in REQUIRED_SUPPORTED_PROBES:
            probe = probes[probe_name]
            prior_gate._require(isinstance(probe, dict)
                                and probe.get("verified") is True
                                and isinstance(probe.get("evidence"), dict)
                                and bool(probe["evidence"]),
                                f"Supported consumer probe failed: {name}/{probe_name}")
        route_evidence = probes["nine_route_gateway_flow"]["evidence"]
        prior_gate._require(
            prior_gate._route_keys(route_evidence.get("routes"), f"{name} passport routes")
            == EXPECTED_DELETIONS
            and route_evidence.get("gateway_owner") == "rust"
            and route_evidence.get("flow_owner") == "rust"
            and route_evidence.get("unauthenticated_status") in (401, 403),
            f"Supported consumer route/auth evidence is incomplete: {name}",
        )
        signer = probes["managed_signer"]["evidence"]
        prior_gate._require(signer.get("mode") == "managed_kms"
                            and signer.get("chain_verified") is True,
                            f"Supported consumer managed signer evidence is incomplete: {name}")
        callback = probes["physical_bureau_callback"]["evidence"]
        prior_gate._require(callback.get("provider_kind") == "physical"
                            and callback.get("signature_verified") is True
                            and callback.get("organization_bound") is True,
                            f"Supported consumer physical callback evidence is incomplete: {name}")
        image = probes["released_image"]["evidence"]
        prior_gate._require(image.get("oci_reference") == services_reference
                            and image.get("source_commit") == commit
                            and isinstance(image.get("container_id"), str)
                            and bool(image["container_id"]),
                            f"Supported consumer released image evidence is incomplete: {name}")
        rollback = probes["rollback"]["evidence"]
        prior_gate._require(rollback.get("before_owner") == "rust"
                            and rollback.get("after_owner") == "python"
                            and rollback.get("nine_routes_restored") is True,
                            f"Supported consumer rollback evidence is incomplete: {name}")


def _signed_stack_manifest(tag: str, commit: str, expected_digest: str, output: Path) -> dict:
    prior_gate._require(isinstance(tag, str) and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag),
                        "Stack release tag is invalid")
    prior_gate._require(isinstance(expected_digest, str)
                        and SHA256.fullmatch(expected_digest) is not None,
                        "Stack manifest digest is invalid")
    output.mkdir(parents=True, exist_ok=False)
    _command("gh", "release", "download", tag, "--repo", "ElevenID/marty-ui",
             "--pattern", "stack-manifest.json", "--pattern", "SHA256SUMS", "--dir", str(output))
    manifest_path = output / "stack-manifest.json"
    sums_path = output / "SHA256SUMS"
    prior_gate._require(manifest_path.is_file() and sums_path.is_file(),
                        "Signed stack release artifacts are missing")
    prior_gate._require(_sha256(manifest_path) == expected_digest,
                        "Stack manifest SHA-256 mismatch")
    rows = sums_path.read_text(encoding="utf-8").splitlines()
    matches = [row for row in rows if row.endswith(" stack-manifest.json")]
    prior_gate._require(len(matches) == 1
                        and matches[0].split()[0] == expected_digest,
                        "Stack manifest release checksum mismatch")
    _command("gh", "attestation", "verify", str(manifest_path),
             "--repo", "ElevenID/marty-ui",
             "--signer-workflow", "ElevenID/marty-ui/.github/workflows/cd.yml",
             "--source-digest", commit,
             "--source-ref", "refs/heads/main")
    manifest = prior_gate._json(manifest_path)
    prior_gate._require(manifest.get("schema") == "marty.stack/v1"
                        and manifest.get("release") == f"marty-ui@{tag[1:]}",
                        "Stack manifest release identity mismatch")
    components = manifest.get("components")
    prior_gate._require(isinstance(components, list), "Stack release components missing")
    ui = [item for item in components if isinstance(item, dict)
          and item.get("name") == "marty-ui"
          and item.get("repository") == "ElevenID/marty-ui"]
    prior_gate._require(len(ui) == 1 and ui[0].get("commit") == commit,
                        "Stack manifest UI source mismatch")
    return manifest


def _image_digests(manifest: dict) -> dict[str, str]:
    ui_component = next(item for item in manifest["components"]
                        if isinstance(item, dict) and item.get("name") == "marty-ui")
    artifacts = ui_component.get("artifacts")
    prior_gate._require(isinstance(artifacts, list), "UI image artifacts are missing")
    images: dict[str, str] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict) or artifact.get("type") != "oci":
            continue
        uri, digest = artifact.get("uri"), artifact.get("digest")
        prior_gate._require(isinstance(uri, str) and isinstance(digest, str)
                            and re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None
                            and uri not in images, "UI image artifact is invalid")
        images[uri] = digest
    prior_gate._require(set(images) == {
        "ghcr.io/elevenid/marty-ui-oss/ui",
        "ghcr.io/elevenid/marty-ui-oss/services",
        "ghcr.io/elevenid/marty-ui-oss/migrations",
    } and len([item for item in artifacts if isinstance(item, dict)
               and item.get("type") == "oci"]) == 3,
        "UI image artifact set changed")
    return images


def _all_image_references(manifest: dict) -> dict[str, str]:
    references: dict[str, str] = {}
    for component in manifest["components"]:
        prior_gate._require(isinstance(component, dict), "Stack component is invalid")
        for artifact in component.get("artifacts", []):
            if not isinstance(artifact, dict) or artifact.get("type") != "oci":
                continue
            uri, digest = artifact.get("uri"), artifact.get("digest")
            prior_gate._require(isinstance(uri, str) and isinstance(digest, str)
                                and re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None,
                                "Stack OCI image identity is invalid")
            reference = f"{uri}@{digest}"
            prior_gate._require(reference not in references, "Duplicate stack image reference")
            references[reference] = digest
    prior_gate._require(bool(references), "Stack OCI image references are missing")
    return references


def _checkout_commit(contract_path: Path) -> str | None:
    """Select only a syntactically valid source pin; verify() proves its ancestry."""
    contract = prior_gate._json(contract_path)
    prior_gate._require(
        contract.get("schema") == "marty.physical-passport-python-retirement-qualification/v1",
        "Unknown passport retirement qualification schema",
    )
    if contract.get("state") == "blocked_pending_beta_acceptance":
        return None
    prior_gate._require(contract.get("state") == "qualified", "Unknown passport qualification state")
    source = contract.get("source")
    prior_gate._require(isinstance(source, dict)
                        and source.get("repository") == "ElevenID/marty-ui"
                        and isinstance(source.get("protected_main_commit"), str)
                        and COMMIT.fullmatch(source["protected_main_commit"]) is not None,
                        "Qualified passport checkout commit is invalid")
    return source["protected_main_commit"]


def verify(contract_path: Path, marty_ui: Path | None = None) -> None:
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
    prior_gate._require(marty_ui is not None, "Qualified passport source checkout is required")
    commit = _protected_source(source, marty_ui)
    beta = contract.get("beta_acceptance_receipt")
    supported = contract.get("supported_consumer_cutover_receipt")
    prior_gate._require(isinstance(beta, dict) and isinstance(supported, dict),
                        "Both passport acceptance receipts are required")
    prior_gate._require(beta.get("release_source_commit") == commit,
                        "Beta release source differs from qualified source")
    supported_commit = supported.get("protected_main_commit")
    prior_gate._require(supported.get("repository") == "ElevenID/marty-ui"
                        and supported_commit == commit,
                        "Supported consumer source differs from qualified source")
    with tempfile.TemporaryDirectory(prefix="passport-retirement-evidence-") as temporary:
        root = Path(temporary)
        stack_digest = beta.get("stack_manifest_sha256")
        manifest = _signed_stack_manifest(beta.get("release_tag"), commit,
                                          stack_digest, root / "stack")
        expected_images = _image_digests(manifest)
        _all_image_references(manifest)
        services_uri = "ghcr.io/elevenid/marty-ui-oss/services"
        services_digest = expected_images[services_uri]
        services_reference = f"{services_uri}@{services_digest}"
        beta_run = beta.get("beta_deployment_run_id")
        _verified_run(beta_run, commit, ".github/workflows/passport-beta-acceptance.yml")
        beta_report = _run_artifact(beta_run, beta.get("evidence_artifact"),
                                    beta.get("evidence_sha256"), root / "beta")
        beta_release = beta_report.get("release")
        prior_gate._require(isinstance(beta_release, dict)
                            and beta_release.get("oci_digests") == expected_images,
                            "Beta report image digests differ from signed release")
        _beta_report(beta_report, commit, stack_digest)
        _frozen_batch_parity(marty_ui)
        prior_gate._require(beta_report.get("deployment", {}).get("release_version")
                            == beta["release_tag"][1:],
                            "Beta deployment version differs from signed release")
        for service, image in beta_report["runtime_images"].items():
            prior_gate._require(isinstance(image, dict)
                                and image.get("oci_reference") == services_reference
                                and image.get("oci_digest") == services_digest
                                and re.fullmatch(r"sha256:[0-9a-f]{64}",
                                                 str(image.get("image_id", ""))) is not None
                                and isinstance(image.get("container_id"), str)
                                and bool(image["container_id"]),
                                f"Beta runtime image differs from signed release: {service}")
        supported_run = supported.get("acceptance_run_id")
        _verified_run(supported_run, commit,
                      ".github/workflows/passport-supported-consumer-acceptance.yml")
        supported_report = _run_artifact(supported_run, supported.get("evidence_artifact"),
                                         supported.get("evidence_sha256"), root / "supported")
        _supported_report(supported_report, commit, services_reference)
        prior_gate._require(supported_report.get("stack_manifest_sha256") == stack_digest
                            and supported_report.get("oci_digests") == expected_images,
                            "Supported consumer image lineage differs from beta release")
    raise prior_gate.QualificationError(
        "Physical booklet provider evidence and independent maintainer review are not yet "
        "machine-verifiable; passport Python retirement remains blocked"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--marty-ui", type=Path)
    parser.add_argument("--print-checkout-commit", action="store_true",
                        help="Print a validated qualified source pin for the CI checkout")
    args = parser.parse_args()
    try:
        if args.print_checkout_commit:
            commit = _checkout_commit(args.contract)
            if commit is not None:
                print(commit)
            return 0
        verify(args.contract, args.marty_ui)
    except prior_gate.QualificationError as error:
        parser.exit(1, f"{error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
