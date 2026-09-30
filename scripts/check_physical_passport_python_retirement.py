"""Fail closed until Rust passport route compatibility is verifiable."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import UTC, datetime
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
    "contracts/passport-rust-only-retirement-behavior.json",
    "contracts/passport-beta-cutover-drain-behavior.json",
    "contracts/passport-beta-scoped-write-fence-behavior.json",
    "docker-compose.passport-supported-disposable.yml",
}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
REQUIRED_PREDELETION_PROBES = {
    "managed_csca_dsc_chain",
    "sod_signature",
    "nine_route_gateway_flow",
    "packaged_image",
    "physical_bureau_submission",
    "physical_bureau_batch",
    "simulator_material_receipt",
    "signed_bureau_callback",
    "rust_restart_resume",
    "legacy_drain",
    "production_isolation",
    "physical_claim_boundary",
}
EXPECTED_SURFACES = {"base", "selfhost", "kubernetes"}
EXPECTED_SUPPORTED_SERVICES = {
    "gateway", "flow", "issuance-native", "signing-keys", "passport-callback-signer",
    "passport-beta-bureau",
}
EXPECTED_SUPPORTED_FLAGS = {
    "gateway": {"PASSPORT_NATIVE_GATEWAY_ENABLED", "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"},
    "flow": {"PASSPORT_NATIVE_FLOW_ENABLED", "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"},
    "issuance-native": {
        "PASSPORT_NATIVE_HTTP_ENABLED", "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED",
        "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED", "PASSPORT_KMS_ARTIFACTS_ENABLED",
        "PASSPORT_KMS_CALLBACKS_ENABLED",
    },
    "signing-keys": set(),
    "passport-callback-signer": {"PASSPORT_CALLBACK_SIGNER_ENABLED"},
    "passport-beta-bureau": {"PASSPORT_BETA_BUREAU_ENABLED"},
}
EXPECTED_PREDELETION_SERVICES = {
    "gateway",
    "flow",
    "issuance-native",
    "signing-keys",
    "passport-callback-signer",
    "passport-beta-bureau",
}
REQUIRED_SUPPORTED_PROBES = {
    "nine_route_gateway_flow",
    "managed_signer",
    "signed_bureau_callback",
    "released_image",
    "rust_restart_resume",
}


def _utc_time(value: object) -> datetime:
    prior_gate._require(isinstance(value, str), "Drain timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise prior_gate.QualificationError("Drain timestamp is invalid") from exc
    prior_gate._require(parsed.utcoffset() == UTC.utcoffset(parsed),
                        "Drain timestamp is not UTC")
    return parsed


def _direct_fence_probe(probe: object, database_uid: str, fence_epoch: int,
                        watermark: int, writer_role: str) -> tuple[datetime, str]:
    """Require an attested, database-bound rejection for every guarded surface."""
    prior_gate._require(
        isinstance(probe, dict)
        and probe.get("method") == "postgresql_transaction_rollback"
        and probe.get("database_uid") == database_uid
        and probe.get("session_user") == writer_role
        and probe.get("current_user") == writer_role
        and type(probe.get("fence_epoch")) is int
        and probe["fence_epoch"] == fence_epoch
        and type(probe.get("observation_watermark")) is int
        and probe["observation_watermark"] == watermark
        and isinstance(probe.get("rejections"), dict)
        and set(probe["rejections"]) == {
            "physical_document_jobs", "physical_flow_definitions",
            "physical_flow_instances"}
        and all(
            isinstance(probe["rejections"][surface], dict)
            and probe["rejections"][surface].get("valid_without_fence") is True
            and probe["rejections"][surface].get("sqlstate") == "55000"
            and probe["rejections"][surface].get("message") == message
            for surface, message in {
                "physical_document_jobs": "beta passport job writes are fenced",
                "physical_flow_definitions":
                    "beta physical-document Flow definition writes are fenced",
                "physical_flow_instances": "beta physical-document Flow writes are fenced",
            }.items()
        )
        and isinstance(probe.get("receipt_sha256"), str)
        and SHA256.fullmatch(probe["receipt_sha256"]) is not None,
        "Direct beta passport database write probe is incomplete",
    )
    return _utc_time(probe.get("observed_at_utc")), probe["receipt_sha256"]


def _managed_signer(evidence: dict, runtime: dict, organization_id: str) -> None:
    csca, dsc = evidence.get("csca"), evidence.get("dsc")
    prior_gate._require(
        evidence.get("mode") == "managed_kms"
        and evidence.get("issuer_profile_type") == "ICAO_EMRTD"
        and evidence.get("organization_id") == organization_id
        and evidence.get("chain_verified") is True
        and evidence.get("managed_kms_custody_verified") is True
        and evidence.get("private_key_exported") is False
        and evidence.get("signing_keys_container_id") == runtime["signing-keys"]["container_id"]
        and evidence.get("services_oci_reference") == runtime["signing-keys"]["oci_reference"]
        and isinstance(csca, dict) and isinstance(dsc, dict)
        and all(cert.get("status") == "active"
                and cert.get("organization_id") == organization_id
                and isinstance(cert.get("issuer_profile_commitment"), str)
                and SHA256.fullmatch(cert["issuer_profile_commitment"]) is not None
                and isinstance(cert.get("certificate_sha256"), str)
                and SHA256.fullmatch(cert["certificate_sha256"]) is not None
                for cert in (csca, dsc))
        and csca["certificate_sha256"] != dsc["certificate_sha256"]
        and csca["issuer_profile_commitment"] != dsc["issuer_profile_commitment"],
        "Organization-bound active managed CSCA/DSC signer evidence is incomplete",
    )


def _sod_against_signer(sod: dict, signer: dict) -> None:
    prior_gate._require(
        isinstance(sod, dict)
        and sod.get("signature_verified") is True
        and sod.get("chain_verified") is True
        and sod.get("native_generate_sod_verified") is True
        and sod.get("organization_id") == signer["organization_id"]
        and sod.get("dsc_issuer_profile_commitment") == signer["dsc"]["issuer_profile_commitment"]
        and sod.get("csca_certificate_sha256") == signer["csca"]["certificate_sha256"]
        and sod.get("dsc_certificate_sha256") == signer["dsc"]["certificate_sha256"]
        and isinstance(sod.get("sod_sha256"), str)
        and SHA256.fullmatch(sod["sod_sha256"]) is not None
        and isinstance(sod.get("source_job_commitment"), str)
        and SHA256.fullmatch(sod["source_job_commitment"]) is not None,
        "SOD was not verified against the active managed issuer certificates",
    )


def _restart_resume_evidence(
    resume: dict, prior_runtime: dict, runtime: dict, identity: dict,
    target: str, signer: dict, sod: dict, commit: str, services_reference: str,
) -> None:
    """Require one KMS-backed Rust job to survive a real native restart."""
    before, after = resume.get("before"), resume.get("after")
    current_ids = {item.get("container_id") for item in runtime.values()}
    prior_gate._require(
        isinstance(prior_runtime, dict)
        and prior_runtime.get("oci_reference") == services_reference
        and isinstance(prior_runtime.get("container_id"), str)
        and bool(prior_runtime["container_id"])
        and isinstance(prior_runtime.get("image_id"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", prior_runtime["image_id"]) is not None
        and _bound_to_surface(prior_runtime, identity, target)
        and prior_runtime["container_id"] not in current_ids
        and isinstance(prior_runtime.get("inspection_receipt_sha256"), str)
        and SHA256.fullmatch(prior_runtime["inspection_receipt_sha256"]) is not None
        and isinstance(before, dict) and isinstance(after, dict)
        and before.get("owner") == after.get("owner") == "rust"
        and before.get("issuance_native_container_id") == prior_runtime["container_id"]
        and after.get("issuance_native_container_id")
        == runtime["issuance-native"]["container_id"]
        and before["issuance_native_container_id"] != after["issuance_native_container_id"]
        and _bound_to_surface(before, identity, target)
        and _bound_to_surface(after, identity, target)
        and before.get("oci_reference") == after.get("oci_reference") == services_reference
        and before.get("image_id") == prior_runtime["image_id"]
        and after.get("image_id") == runtime["issuance-native"]["image_id"]
        and isinstance(before.get("job_commitment"), str)
        and SHA256.fullmatch(before["job_commitment"]) is not None
        and after.get("job_commitment") == before["job_commitment"]
        and before.get("organization_id") == after.get("organization_id")
        == signer["organization_id"]
        and before.get("dsc_issuer_profile_commitment")
        == after.get("dsc_issuer_profile_commitment")
        == signer["dsc"]["issuer_profile_commitment"]
        and before["job_commitment"] == sod["source_job_commitment"]
        and before.get("status") in {"SOD_SIGNED", "SUBMITTED", "IN_PRODUCTION"}
        and after.get("status") in {"SUBMITTED", "IN_PRODUCTION", "QUALITY_CHECK",
                                    "READY_FOR_ACTIVATION", "ACTIVE"}
        and after["status"] != before["status"]
        and resume.get("job_resumed") is True
        and resume.get("durable_record_verified") is True
        and resume.get("kms_signing_continuity_verified") is True
        and resume.get("gateway_owner") == "rust"
        and resume.get("flow_owner") == "rust"
        and resume.get("source_commit") == commit
        and resume.get("services_oci_reference") == services_reference,
        "Protected Rust restart or KMS job resume is incomplete",
    )


def _surface_identity(identity: dict, name: str, commit: str) -> str:
    prior_gate._require(isinstance(identity, dict), f"{name} resource identity missing")
    uid = identity.get("owner_uid")
    labels = identity.get("owner_labels")
    prior_gate._require(
        isinstance(uid, str) and bool(uid)
        and labels == {"source_commit": commit, "surface": name, "owner_uid": uid}
        and identity.get("production_resources_excluded") is True,
        f"{name} protected owner identity is incomplete",
    )
    if name == "kubernetes":
        prior_gate._require(
            identity.get("kind") == "kubernetes"
            and isinstance(identity.get("namespace"), str) and bool(identity["namespace"])
            and isinstance(identity.get("cluster_uid"), str) and bool(identity["cluster_uid"])
            and isinstance(identity.get("production_cluster_uid"), str)
            and bool(identity["production_cluster_uid"])
            and identity["cluster_uid"] != identity["production_cluster_uid"]
            and isinstance(identity.get("cluster_identity_attestation_sha256"), str)
            and SHA256.fullmatch(identity["cluster_identity_attestation_sha256"]) is not None,
            "Kubernetes namespace or protected cluster identity is incomplete",
        )
        return identity["namespace"]
    prior_gate._require(
        identity.get("kind") == "compose"
        and isinstance(identity.get("project_id"), str)
        and bool(identity["project_id"]),
        f"{name} Compose project identity is incomplete",
    )
    return identity["project_id"]


def _bound_to_surface(evidence: dict, identity: dict, target: str) -> bool:
    return (
        evidence.get("owner_uid") == identity["owner_uid"]
        and evidence.get("owner_labels") == identity["owner_labels"]
        and evidence.get("target") == target
        and (identity["kind"] != "kubernetes"
             or evidence.get("cluster_uid") == identity["cluster_uid"])
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _command(*args: str) -> str:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    prior_gate._require(result.returncode == 0, f"Evidence command failed: {args[0]} {args[1]}")
    return result.stdout


def _verified_run(run_id: int, source_commit: str, workflow: str) -> tuple[datetime, datetime]:
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
    started = _utc_time(run.get("created_at"))
    completed = _utc_time(run.get("updated_at"))
    prior_gate._require(started < completed, "Protected workflow completion time is invalid")
    return started, completed


def _run_artifact(run_id: int, artifact_name: str, digest: str, output: Path,
                  source_commit: str, workflow: str) -> dict:
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
    _command("gh", "attestation", "verify", str(artifact),
             "--repo", "ElevenID/marty-ui", "--signer-workflow",
             f"ElevenID/marty-ui/{workflow}", "--source-digest", source_commit,
             "--source-ref", "refs/heads/main")
    prior_gate._require(_sha256(artifact) == digest,
                        "Acceptance artifact changed during attestation verification")
    return prior_gate._json(artifact)


def _final_cutover_report(commit: str, deletion_head: str, output: Path) -> tuple[dict, datetime, datetime]:
    """Find the attested final drain produced for this exact deletion commit."""
    listing = json.loads(_command(
        "gh", "api",
        "repos/ElevenID/marty-ui/actions/workflows/passport-python-deletion-cutover.yml/runs"
        "?branch=main&status=success&per_page=100",
    ))
    runs = listing.get("workflow_runs") if isinstance(listing, dict) else None
    prior_gate._require(isinstance(runs, list), "Protected final cutover runs are unavailable")
    candidates = [run for run in runs if isinstance(run, dict)
                  and run.get("head_sha") == commit and run.get("head_branch") == "main"
                  and run.get("status") == "completed" and run.get("conclusion") == "success"]
    prior_gate._require(bool(candidates), "Final protected deletion cutover run is missing")
    candidates.sort(key=lambda run: str(run.get("updated_at", "")), reverse=True)
    for run in candidates:
        run_id = run.get("id")
        try:
            started, completed = _verified_run(
                run_id, commit, ".github/workflows/passport-python-deletion-cutover.yml",
            )
            name = f"passport-python-deletion-cutover-{run_id}"
            destination = output / str(run_id)
            destination.mkdir(parents=True, exist_ok=False)
            _command("gh", "run", "download", str(run_id), "--repo", "ElevenID/marty-ui",
                     "--name", name, "--dir", str(destination))
            artifact = destination / f"{name}.json"
            prior_gate._require(artifact.is_file() and artifact.stat().st_size <= 1024 * 1024,
                                "Final cutover artifact is missing or oversized")
            _command("gh", "attestation", "verify", str(artifact),
                     "--repo", "ElevenID/marty-ui",
                     "--signer-workflow",
                     "ElevenID/marty-ui/.github/workflows/passport-python-deletion-cutover.yml",
                     "--source-digest", commit, "--source-ref", "refs/heads/main")
            report = prior_gate._json(artifact)
            if isinstance(report, dict) and report.get("deletion_head") == deletion_head:
                return report, started, completed
        except prior_gate.QualificationError:
            continue
    raise prior_gate.QualificationError("No attested final cutover report names this deletion head")


def _retirement_pr_head(number: object) -> str:
    prior_gate._require(type(number) is int and number > 0,
                        "Retirement pull request number is missing")
    pr = json.loads(_command("gh", "api", f"repos/ElevenID/marty-credentials/pulls/{number}"))
    head = pr.get("head") if isinstance(pr, dict) else None
    base = pr.get("base") if isinstance(pr, dict) else None
    sha = head.get("sha") if isinstance(head, dict) else None
    head_repo = head.get("repo") if isinstance(head, dict) else None
    base_repo = base.get("repo") if isinstance(base, dict) else None
    prior_gate._require(
        isinstance(pr, dict) and pr.get("number") == number
        and isinstance(head, dict) and isinstance(base, dict)
        and isinstance(head_repo, dict)
        and head_repo.get("full_name") == "ElevenID/marty-credentials"
        and isinstance(base_repo, dict)
        and base_repo.get("full_name") == "ElevenID/marty-credentials"
        and base.get("ref") == "main"
        and isinstance(sha, str) and COMMIT.fullmatch(sha) is not None,
        "Retirement pull request head is not an exact same-repository main-base commit",
    )
    return sha


def _pull_request_lineage(number: int, deletion_head: str) -> None:
    """Reject a stale or unrelated PR event even if it names an attested head."""
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    prior_gate._require(os.environ.get("GITHUB_EVENT_NAME") == "pull_request"
                        and isinstance(event_path, str) and bool(event_path),
                        "Exact deletion-head qualification requires the pull-request event")
    event = prior_gate._json(Path(event_path))
    repository = event.get("repository") if isinstance(event, dict) else None
    pull = event.get("pull_request") if isinstance(event, dict) else None
    head = pull.get("head") if isinstance(pull, dict) else None
    base = pull.get("base") if isinstance(pull, dict) else None
    head_repo = head.get("repo") if isinstance(head, dict) else None
    base_repo = base.get("repo") if isinstance(base, dict) else None
    prior_gate._require(
        isinstance(event, dict) and event.get("number") == number
        and isinstance(repository, dict)
        and repository.get("full_name") == "ElevenID/marty-credentials"
        and isinstance(pull, dict) and pull.get("number") == number
        and isinstance(head, dict) and head.get("sha") == deletion_head
        and isinstance(head_repo, dict)
        and head_repo.get("full_name") == "ElevenID/marty-credentials"
        and isinstance(base, dict) and base.get("ref") == "main"
        and isinstance(base_repo, dict)
        and base_repo.get("full_name") == "ElevenID/marty-credentials",
        "Pull-request event does not name #305's exact same-repository main-base head",
    )
    prior_gate._require(_retirement_pr_head(number) == deletion_head,
                        "Pull-request deletion head is stale relative to the live PR")


def _post_pr_lineage(number: int, deletion_head: str) -> None:
    """Bind the running queue/main commit to the exact qualified deletion PR."""
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    running_sha = os.environ.get("GITHUB_SHA")
    prior_gate._require(event_name in {"merge_group", "push"}
                        and isinstance(event_path, str) and bool(event_path)
                        and isinstance(running_sha, str) and COMMIT.fullmatch(running_sha) is not None,
                        "Post-PR GitHub event provenance is missing")
    event = prior_gate._json(Path(event_path))
    repository = event.get("repository") if isinstance(event, dict) else None
    prior_gate._require(isinstance(repository, dict)
                        and repository.get("full_name")
                        == "ElevenID/marty-credentials",
                        "Post-PR event names another repository")
    checkout_head = _command("git", "-C", str(Path(__file__).resolve().parents[1]),
                             "rev-parse", "HEAD").strip()
    prior_gate._require(checkout_head == running_sha,
                        "Running checkout differs from the GitHub event commit")
    if event_name == "merge_group":
        group = event.get("merge_group")
        prior_gate._require(isinstance(group, dict)
                            and group.get("head_sha") == running_sha
                            and group.get("base_ref") == "refs/heads/main"
                            and isinstance(group.get("head_ref"), str)
                            and group["head_ref"].startswith(
                                "refs/heads/gh-readonly-queue/main/"),
                            "Running merge group is not a main queue commit")
        query = ("query { repository(owner: \"ElevenID\", name: \"marty-credentials\") "
                 f"{{ pullRequest(number: {number}) {{ headRefOid mergeQueueEntry "
                 "{ headCommit { oid } pullRequest { number headRefOid } } } } }")
        response = json.loads(_command("gh", "api", "graphql", "-f", f"query={query}"))
        repository = response.get("data", {}).get("repository") if isinstance(response, dict) else None
        pr = repository.get("pullRequest") if isinstance(repository, dict) else None
        entry = pr.get("mergeQueueEntry") if isinstance(pr, dict) else None
        queued_pr = entry.get("pullRequest") if isinstance(entry, dict) else None
        queued_commit = entry.get("headCommit") if isinstance(entry, dict) else None
        ancestor = queued_commit.get("oid") if isinstance(queued_commit, dict) else None
        prior_gate._require(isinstance(pr, dict) and pr.get("headRefOid") == deletion_head
                            and isinstance(queued_pr, dict)
                            and queued_pr.get("number") == number
                            and queued_pr.get("headRefOid") == deletion_head
                            and isinstance(ancestor, str)
                            and COMMIT.fullmatch(ancestor) is not None,
                            "Merge queue entry does not contain the exact deletion PR head")
    else:
        prior_gate._require(event.get("ref") == "refs/heads/main"
                            and event.get("after") == running_sha,
                            "Running push is not the protected main commit")
        pr = json.loads(_command(
            "gh", "api", f"repos/ElevenID/marty-credentials/pulls/{number}",
        ))
        ancestor = pr.get("merge_commit_sha") if isinstance(pr, dict) else None
        head = pr.get("head") if isinstance(pr, dict) else None
        prior_gate._require(isinstance(pr, dict) and pr.get("number") == number
                            and pr.get("merged") is True
                            and isinstance(head, dict) and head.get("sha") == deletion_head
                            and isinstance(ancestor, str)
                            and COMMIT.fullmatch(ancestor) is not None,
                            "Main push is not bound to the merged deletion PR")
    comparison = json.loads(_command(
        "gh", "api",
        f"repos/ElevenID/marty-credentials/compare/{ancestor}...{running_sha}",
    ))
    prior_gate._require(isinstance(comparison, dict)
                        and comparison.get("status") in {"ahead", "identical"},
                        "Running commit does not contain the deletion PR queue or merge commit")


def _successful_pr_gate(number: int, deletion_head: str, cutover_completed: datetime) -> None:
    listing = json.loads(_command(
        "gh", "api", "repos/ElevenID/marty-credentials/actions/workflows/ci.yml/runs"
        f"?event=pull_request&head_sha={deletion_head}&per_page=100",
    ))
    runs = listing.get("workflow_runs") if isinstance(listing, dict) else None
    prior_gate._require(isinstance(runs, list), "Deletion PR check runs are unavailable")
    for run in runs:
        if not isinstance(run, dict):
            continue
        prs = run.get("pull_requests")
        if not (run.get("event") == "pull_request"
                and run.get("head_sha") == deletion_head
                and run.get("head_branch")
                and run.get("path") == ".github/workflows/ci.yml"
                and run.get("status") == "completed"
                and run.get("conclusion") == "success"
                and isinstance(prs, list)
                and any(isinstance(pr, dict) and pr.get("number") == number for pr in prs)):
            continue
        run_id = run.get("id")
        attempt = run.get("run_attempt")
        suite_id = run.get("check_suite_id")
        if (type(run_id) is not int or run_id <= 0
                or type(attempt) is not int or attempt <= 0
                or type(suite_id) is not int or suite_id <= 0):
            continue
        suite = json.loads(_command(
            "gh", "api", f"repos/ElevenID/marty-credentials/check-suites/{suite_id}",
        ))
        app = suite.get("app") if isinstance(suite, dict) else None
        if not (isinstance(suite, dict)
                and suite.get("head_sha") == deletion_head
                and isinstance(app, dict) and app.get("slug") == "github-actions"):
            continue
        jobs_data = json.loads(_command(
            "gh", "api", f"repos/ElevenID/marty-credentials/actions/runs/{run_id}"
            f"/attempts/{attempt}/jobs"
            "?per_page=100",
        ))
        jobs = jobs_data.get("jobs") if isinstance(jobs_data, dict) else None
        if not isinstance(jobs, list):
            continue
        required = {"Passport Python Retirement Provenance", "CI Gate"}
        passed = {job.get("name") for job in jobs if isinstance(job, dict)
                  and job.get("run_id") == run_id
                  and job.get("head_sha") == deletion_head
                  and job.get("status") == "completed"
                  and job.get("conclusion") == "success"
                  and _utc_time(job.get("started_at")) > cutover_completed}
        if required <= passed:
            return
    raise prior_gate.QualificationError(
        "Exact deletion PR head lacks a successful post-cutover provenance and CI Gate run"
    )


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


def _predeletion_report(report: dict, commit: str, stack_sha256: str) -> None:
    prior_gate._require(report.get("schema") == "marty.passport-rust-predeletion-acceptance/v1"
                        and report.get("status") == "accepted",
                        "Protected disposable report has not accepted passport")
    _utc_time(report.get("accepted_at_utc"))
    release = report.get("release")
    prior_gate._require(isinstance(release, dict)
                        and release.get("source_commit") == commit
                        and release.get("stack_manifest_sha256") == stack_sha256
                        and release.get("signed_manifest_verified") is True,
                        "Protected disposable report release lineage mismatch")
    prior_gate._require(report.get("physical_claim") == "not_claimed",
                        "Disposable compatibility report must not claim a physical booklet")
    deployment = report.get("deployment")
    prior_gate._require(isinstance(deployment, dict)
                        and deployment.get("mode") == "disposable"
                        and deployment.get("provider_mode") == "simulator"
                        and deployment.get("resource_identity_verified") is True
                        and deployment.get("source_commit") == commit,
                        "Protected disposable resource identity is missing")
    target = _surface_identity(deployment, "base", commit)
    prior_gate._require("provider_ingress_runtime_image" not in report,
                        "Disposable simulator includes a provider ingress runtime")
    prior_gate._require(isinstance(report.get("runtime_images"), dict)
                        and set(report["runtime_images"]) == EXPECTED_PREDELETION_SERVICES,
                        "Disposable runtime service image set is incomplete")
    images = release.get("oci_digests")
    services_digest = (images.get("ghcr.io/elevenid/marty-ui-oss/services")
                       if isinstance(images, dict) else None)
    prior_gate._require(isinstance(services_digest, str)
                        and re.fullmatch(r"sha256:[0-9a-f]{64}", services_digest) is not None,
                        "Disposable signed services image digest is missing")
    services_reference = f"ghcr.io/elevenid/marty-ui-oss/services@{services_digest}"
    runtime_ids: set[str] = set()
    for service, runtime in report["runtime_images"].items():
        prior_gate._require(isinstance(runtime, dict)
                            and _bound_to_surface(runtime, deployment, target)
                            and runtime.get("oci_reference") == services_reference
                            and runtime.get("oci_digest") == services_digest
                            and isinstance(runtime.get("image_id"), str)
                            and re.fullmatch(r"sha256:[0-9a-f]{64}", runtime["image_id"]) is not None
                            and isinstance(runtime.get("container_id"), str)
                            and bool(runtime["container_id"])
                            and runtime["container_id"] not in runtime_ids
                            and isinstance(runtime.get("selectors"), dict)
                            and set(runtime["selectors"]) == EXPECTED_SUPPORTED_FLAGS[service]
                            and all(value is True for value in runtime["selectors"].values()),
                            f"Disposable released Rust runtime is incomplete: {service}")
        runtime_ids.add(runtime["container_id"])
    probes = report.get("probes")
    prior_gate._require(isinstance(probes, dict) and set(probes) >= REQUIRED_PREDELETION_PROBES,
                        "Protected disposable passport probes are incomplete")
    for name in REQUIRED_PREDELETION_PROBES:
        probe = probes[name]
        prior_gate._require(isinstance(probe, dict) and probe.get("verified") is True
                            and isinstance(probe.get("evidence"), dict)
                            and _bound_to_surface(probe["evidence"], deployment, target),
                            f"Disposable passport probe did not pass: {name}")
    boundary = probes["physical_claim_boundary"]["evidence"]
    prior_gate._require(isinstance(boundary, dict)
                        and boundary.get("physical_claim") == "not_claimed"
                        and boundary.get("booklet_verified") is False,
                        "Simulator acceptance must not claim a physical booklet")
    route = probes["nine_route_gateway_flow"]["evidence"]
    prior_gate._require(
        prior_gate._route_keys(route.get("routes"), "disposable passport routes")
        == EXPECTED_DELETIONS
        and route.get("gateway_owner") == "rust"
        and route.get("flow_owner") == "rust"
        and route.get("unauthenticated_status") in (401, 403)
        and route.get("cross_tenant_status") == 404
        and isinstance(route.get("organization_id"), str)
        and bool(route["organization_id"]),
        "Disposable route ownership or tenant isolation is incomplete",
    )
    signer = probes["managed_csca_dsc_chain"]["evidence"]
    sod = probes["sod_signature"]["evidence"]
    _managed_signer(signer, report["runtime_images"], route["organization_id"])
    _sod_against_signer(sod, signer)
    _restart_resume_evidence(
        probes["rust_restart_resume"]["evidence"],
        report.get("pre_restart_native_runtime"), report["runtime_images"],
        deployment, target, signer, sod, commit, services_reference,
    )
    callback = probes["signed_bureau_callback"]["evidence"]
    prior_gate._require(
        callback.get("provider_kind") == "simulator"
        and callback.get("signature_verified") is True
        and callback.get("organization_bound") is True
        and callback.get("organization_id") == route["organization_id"]
        and callback.get("flow_execution_verified") is True
        and callback.get("physical_claim") == "not_claimed",
        "Signed simulator callback or Flow execution is incomplete",
    )
    drain = probes["legacy_drain"]["evidence"]
    legacy_source = drain.get("legacy_source")
    prior_gate._require(
        drain.get("source_commit") == commit
        and drain.get("python_passport_writes_fenced") is True
        and isinstance(legacy_source, dict)
        and legacy_source.get("environment") == "beta"
        and isinstance(legacy_source.get("beta_cluster_uid"), str)
        and bool(legacy_source["beta_cluster_uid"])
        and legacy_source.get("database_cluster_uid") == legacy_source["beta_cluster_uid"]
        and legacy_source.get("writer_cluster_uid") == legacy_source["beta_cluster_uid"]
        and isinstance(legacy_source.get("beta_inventory_attestation_sha256"), str)
        and SHA256.fullmatch(legacy_source["beta_inventory_attestation_sha256"]) is not None
        and isinstance(legacy_source.get("database_uid"), str)
        and bool(legacy_source["database_uid"])
        and legacy_source["database_uid"] != deployment.get("database_uid")
        and isinstance(legacy_source.get("writer_deployment_uid"), str)
        and bool(legacy_source["writer_deployment_uid"])
        and legacy_source.get("writer_owner") == "python"
        and legacy_source.get("writer_database_role") == "marty"
        and isinstance(legacy_source.get("writer_image_digest"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", legacy_source["writer_image_digest"]) is not None
        and isinstance(legacy_source.get("writer_container_id"), str)
        and re.fullmatch(r"[0-9a-f]{64}", legacy_source["writer_container_id"]) is not None
        and legacy_source.get("writer_running_at_drain") is True
        and type(legacy_source.get("writer_generation_at_fence")) is int
        and legacy_source.get("writer_generation_at_drain") == legacy_source["writer_generation_at_fence"]
        and type(legacy_source.get("fence_watermark")) is int
        and type(legacy_source.get("drain_watermark")) is int
        and legacy_source["drain_watermark"] > legacy_source["fence_watermark"]
        and isinstance(legacy_source.get("drain_snapshot_attestation_sha256"), str)
        and SHA256.fullmatch(legacy_source["drain_snapshot_attestation_sha256"]) is not None
        and legacy_source.get("database_uid") == drain.get("count_source_database_uid")
        and type(drain.get("nonterminal_job_count")) is int
        and drain.get("nonterminal_job_count") == 0
        and type(drain.get("legacy_or_unknown_artifact_count")) is int
        and drain.get("legacy_or_unknown_artifact_count") == 0
        and type(drain.get("unreadable_artifact_count")) is int
        and drain.get("unreadable_artifact_count") == 0
        and type(drain.get("active_passport_flow_count")) is int
        and drain.get("active_passport_flow_count") == 0,
        "Legacy jobs, artifacts, or Flows have not drained",
    )
    fence = drain.get("passport_write_fence")
    prior_gate._require(
        isinstance(fence, dict)
        and fence.get("scope") == "physical_document_jobs_and_physical_flows"
        and fence.get("enabled") is True
        and fence.get("database_uid") == legacy_source["database_uid"]
        and fence.get("writer_deployment_uid") == legacy_source["writer_deployment_uid"]
        and fence.get("writer_container_id") == legacy_source["writer_container_id"]
        and fence.get("writer_generation") == legacy_source["writer_generation_at_drain"]
        and type(fence.get("fence_epoch")) is int and fence["fence_epoch"] > 0
        and isinstance(fence.get("verification_sha256"), str)
        and SHA256.fullmatch(fence["verification_sha256"]) is not None
        and fence.get("unrelated_issuance_continues") is True,
        "Scoped beta passport write fence is incomplete",
    )
    probe_checked, _ = _direct_fence_probe(
        fence.get("direct_database_probe"), legacy_source["database_uid"],
        fence["fence_epoch"], legacy_source["drain_watermark"],
        legacy_source["writer_database_role"],
    )
    prior_gate._require(_utc_time(legacy_source.get("fence_enabled_at_utc"))
                        < probe_checked <= _utc_time(legacy_source.get("drain_checked_at_utc")),
                        "Legacy drain did not follow the passport write fence")
    isolation = probes["production_isolation"]["evidence"]
    prior_gate._require(
        isolation.get("production_unchanged") is True
        and isolation.get("other_beta_resources_unchanged") is True
        and isolation.get("authorized_passport_fence_uid")
        == legacy_source["writer_deployment_uid"]
        and isolation.get("disposable_resource_identity_verified") is True,
        "Disposable acceptance changed production or unauthorized beta resources",
    )
    batch = probes["physical_bureau_batch"]["evidence"]
    images = release.get("oci_digests")
    services = images.get("ghcr.io/elevenid/marty-ui-oss/services") if isinstance(images, dict) else None
    prior_gate._require(
        isinstance(batch, dict)
        and batch.get("provider_kind") == "simulator"
        and batch.get("simulator_marker_verified") is True
        and batch.get("physical_claim") == "not_claimed"
        and batch.get("organization_id") == route["organization_id"]
        and batch.get("commitment_scheme") == "HMAC-SHA256"
        and batch.get("source_commit") == commit
        and batch.get("stack_manifest_sha256") == stack_sha256
        and isinstance(services, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", services) is not None
        and batch.get("services_oci_reference")
        == f"ghcr.io/elevenid/marty-ui-oss/services@{services}"
        and isinstance(batch.get("request_commitment"), str)
        and SHA256.fullmatch(batch["request_commitment"]) is not None
        and isinstance(batch.get("response_commitment"), str)
        and SHA256.fullmatch(batch["response_commitment"]) is not None
        and isinstance(batch.get("callback_receipt_sha256"), str)
        and SHA256.fullmatch(batch["callback_receipt_sha256"]) is not None,
        "Simulator batch compatibility evidence is not bound to the signed protected source",
    )
    submitted = batch.get("submitted_job_commitments")
    returned = batch.get("returned_jobs")
    receipts = batch.get("callback_receipts_sha256")
    prior_gate._require(
        isinstance(submitted, list) and len(submitted) >= 2
        and all(isinstance(job, str) and SHA256.fullmatch(job) is not None for job in submitted)
        and len(set(submitted)) == len(submitted)
        and submitted[0] == sod["source_job_commitment"]
        and isinstance(returned, list) and len(returned) == len(submitted)
        and batch.get("http_status") in (200, 201, 202)
        and batch.get("batch_status") == "QUEUED"
        and all(isinstance(job, dict)
                and isinstance(job.get("source_job_commitment"), str)
                and SHA256.fullmatch(job["source_job_commitment"]) is not None
                and isinstance(job.get("bureau_job_commitment"), str)
                and SHA256.fullmatch(job["bureau_job_commitment"]) is not None
                and job.get("status") in {"QUEUED", "PRINTING", "ENCODING", "QUALITY_CHECK", "SHIPPED", "DELIVERED"}
                for job in returned)
        and {job["source_job_commitment"] for job in returned} == set(submitted)
        and len({job["bureau_job_commitment"] for job in returned}) == len(returned),
        "Simulator batch exchange or job mapping is incomplete",
    )
    prior_gate._require(
        batch.get("native_binding_verified") is True
        and batch.get("native_completed_jobs") == len(submitted)
        and isinstance(receipts, list)
        and len(receipts) == len(submitted)
        and all(isinstance(receipt, str) and SHA256.fullmatch(receipt) is not None
                for receipt in receipts)
        and len(set(receipts)) == len(receipts)
        and receipts[0] == batch["callback_receipt_sha256"],
        "Simulator jobs and signed callback receipts did not complete on native issuance",
    )
    prior_gate._require(
        callback.get("receipt_sha256") == batch["callback_receipt_sha256"]
        and callback.get("callback_receipts_sha256") == receipts
        and callback.get("source_job_commitments") == submitted
        and callback.get("native_completed_jobs") == batch["native_completed_jobs"]
        and callback.get("native_container_id")
        == report["runtime_images"]["issuance-native"]["container_id"],
        "Signed callback is not bound to the native batch jobs and receipt",
    )
    returned_by_source = {job["source_job_commitment"]: job["bureau_job_commitment"]
                          for job in returned}
    callback_jobs = callback.get("jobs")
    prior_gate._require(
        isinstance(callback_jobs, list) and len(callback_jobs) == len(submitted)
        and all(
            isinstance(job, dict)
            and job.get("source_job_commitment") == source
            and job.get("bureau_job_commitment") == returned_by_source[source]
            and job.get("receipt_sha256") == receipts[index]
            and job.get("native_completed") is True
            and job.get("organization_id") == route["organization_id"]
            and job.get("native_container_id")
            == report["runtime_images"]["issuance-native"]["container_id"]
            for index, (source, job) in enumerate(zip(submitted, callback_jobs, strict=True))
        ),
        "Signed callback jobs are not bound to returned bureau jobs and native completion",
    )
    material = probes["simulator_material_receipt"]["evidence"]
    prior_gate._require(
        material.get("tenant_and_job_binding") is True
        and material.get("first_accepted_sod_der_matches_native") is True
        and material.get("first_accepted_dsc_der_matches_selected_chain") is True
        and material.get("first_accepted_dsc_pem_wire_matches_selected_chain") is True
        and material.get("source_job_id_commitment") == sod["source_job_commitment"]
        and material.get("bureau_job_id_commitment")
        == returned_by_source[sod["source_job_commitment"]]
        and material.get("sod_sha256") == sod["sod_sha256"]
        and material.get("dsc_certificate_sha256")
        == signer["dsc"]["certificate_sha256"],
        "First accepted simulator material differs from the selected managed SOD",
    )
    packaged = probes["packaged_image"]["evidence"]
    runtime_bureau = report["runtime_images"]["passport-beta-bureau"]
    prior_gate._require(
        isinstance(packaged, dict)
        and packaged.get("source_commit") == commit
        and packaged.get("stack_manifest_sha256") == stack_sha256
        and packaged.get("services_oci_reference") == batch["services_oci_reference"]
        and isinstance(runtime_bureau, dict)
        and isinstance(runtime_bureau.get("container_id"), str)
        and bool(runtime_bureau["container_id"])
        and packaged.get("runtime_container_id") == runtime_bureau["container_id"],
        "Packaged simulator image is not bound to the signed disposable runtime",
    )
    submission = probes["physical_bureau_submission"]["evidence"]
    prior_gate._require(
        isinstance(submission, dict)
        and submission.get("provider_kind") == "simulator"
        and submission.get("physical_claim") == "not_claimed"
        and all(submission.get(name) == batch.get(name) for name in (
            "source_commit", "stack_manifest_sha256", "services_oci_reference",
            "http_status", "batch_status", "request_commitment",
            "response_commitment", "submitted_job_commitments", "returned_jobs",
        )),
        "Simulator submission differs from the verified signed-release batch",
    )


def _supported_report(report: dict, commit: str, services_reference: str) -> None:
    prior_gate._require(report.get("schema") == "marty.passport-supported-consumer-acceptance/v1"
                        and report.get("status") == "accepted"
                        and report.get("source_commit") == commit
                        and report.get("physical_claim") == "not_claimed",
                        "Supported consumer report lineage mismatch")
    _utc_time(report.get("accepted_at_utc"))
    surfaces = report.get("surfaces")
    prior_gate._require(isinstance(surfaces, dict) and set(surfaces) == EXPECTED_SURFACES,
                        "Supported consumer surfaces are incomplete")
    owner_uids: set[str] = set()
    targets: set[str] = set()
    container_ids: set[str] = set()
    for name in EXPECTED_SURFACES:
        item = surfaces[name]
        prior_gate._require(isinstance(item, dict)
                            and item.get("runtime_accepted") is True,
                            f"Supported consumer Rust runtime incomplete: {name}")
        identity = item.get("identity")
        target = _surface_identity(identity, name, commit)
        prior_gate._require(identity["owner_uid"] not in owner_uids
                            and target not in targets,
                            f"Supported consumer owner identity reused: {name}")
        owner_uids.add(identity["owner_uid"])
        targets.add(target)
        runtime = item.get("runtime_images")
        prior_gate._require(isinstance(runtime, dict)
                            and set(runtime) == EXPECTED_SUPPORTED_SERVICES,
                            f"Supported consumer runtime service set is incomplete: {name}")
        for service, observed in runtime.items():
            prior_gate._require(
                isinstance(observed, dict)
                and observed.get("oci_reference") == services_reference
                and all(isinstance(observed.get(key), str) and observed[key]
                        for key in ("container_id", "image_id"))
                and isinstance(observed.get("selectors"), dict)
                and set(observed["selectors"]) == EXPECTED_SUPPORTED_FLAGS[service]
                and all(value is True for value in observed["selectors"].values())
                and _bound_to_surface(observed, identity, target)
                and observed["container_id"] not in container_ids,
                f"Supported consumer released runtime is incomplete: {name}/{service}",
            )
            container_ids.add(observed["container_id"])
        probes = item.get("probes")
        prior_gate._require(isinstance(probes, dict)
                            and set(probes) >= REQUIRED_SUPPORTED_PROBES,
                            f"Supported consumer probes missing: {name}")
        for probe_name in REQUIRED_SUPPORTED_PROBES:
            probe = probes[probe_name]
            prior_gate._require(isinstance(probe, dict)
                                and probe.get("verified") is True
                                and isinstance(probe.get("evidence"), dict)
                                and _bound_to_surface(probe["evidence"], identity, target),
                                f"Supported consumer probe failed: {name}/{probe_name}")
        route_evidence = probes["nine_route_gateway_flow"]["evidence"]
        prior_gate._require(
            prior_gate._route_keys(route_evidence.get("routes"), f"{name} passport routes")
            == EXPECTED_DELETIONS
            and route_evidence.get("gateway_owner") == "rust"
            and route_evidence.get("flow_owner") == "rust"
            and route_evidence.get("unauthenticated_status") in (401, 403)
            and route_evidence.get("cross_tenant_status") == 404
            and isinstance(route_evidence.get("organization_id"), str)
            and bool(route_evidence["organization_id"]),
            f"Supported consumer route/auth evidence is incomplete: {name}",
        )
        signer = probes["managed_signer"]["evidence"]
        _managed_signer(signer, runtime, route_evidence["organization_id"])
        _sod_against_signer(signer.get("sod", {}), signer)
        callback = probes["signed_bureau_callback"]["evidence"]
        prior_gate._require(callback.get("provider_kind") == "simulator"
                            and callback.get("signature_verified") is True
                            and callback.get("organization_bound") is True
                            and callback.get("organization_id") == route_evidence["organization_id"]
                            and callback.get("physical_claim") == "not_claimed",
                            f"Supported consumer callback compatibility evidence is incomplete: {name}")
        image = probes["released_image"]["evidence"]
        prior_gate._require(image.get("oci_reference") == services_reference
                            and image.get("source_commit") == commit
                            and image.get("container_id")
                            == runtime["gateway"]["container_id"],
                            f"Supported consumer released image evidence is incomplete: {name}")
        resume = probes["rust_restart_resume"]["evidence"]
        prior_runtime = item.get("pre_restart_native_runtime")
        _restart_resume_evidence(
            resume, prior_runtime, runtime, identity, target,
            signer, signer["sod"], commit, services_reference,
        )
        container_ids.add(prior_runtime["container_id"])


def _cutover_report(report: dict, commit: str, deletion_head: str,
                    legacy: dict, drain: dict, predeletion_run: int) -> datetime:
    prior_gate._require(
        report.get("schema") == "marty.passport-python-deletion-cutover/v1"
        and report.get("status") == "accepted"
        and report.get("rust_source_commit") == commit
        and report.get("deletion_head") == deletion_head
        and "supported_acceptance_run_id" not in report
        and report.get("predeletion_acceptance_run_id") == predeletion_run,
        "Final cutover is not bound to the exact deletion head and acceptance run",
    )
    source = report.get("legacy_source")
    counts = report.get("counts")
    fence = report.get("write_fence")
    prior_fence = drain.get("passport_write_fence")
    prior_gate._require(
        isinstance(source, dict)
        and source.get("environment") == "beta"
        and source.get("database_uid") == legacy["database_uid"]
        and source.get("beta_cluster_uid") == legacy["beta_cluster_uid"]
        and source.get("beta_inventory_attestation_sha256")
        == legacy["beta_inventory_attestation_sha256"]
        and source.get("writer_deployment_uid") == legacy["writer_deployment_uid"]
        and source.get("writer_image_digest") == legacy["writer_image_digest"]
        and source.get("writer_database_role") == legacy["writer_database_role"]
        and source.get("writer_generation") == legacy["writer_generation_at_drain"]
        and source.get("writer_container_id") == legacy["writer_container_id"]
        and source.get("writer_running") is True
        and type(source.get("final_watermark")) is int
        and source["final_watermark"] > legacy["drain_watermark"]
        and isinstance(source.get("final_snapshot_attestation_sha256"), str)
        and SHA256.fullmatch(source["final_snapshot_attestation_sha256"]) is not None
        and source["final_snapshot_attestation_sha256"]
        != legacy["drain_snapshot_attestation_sha256"]
        and isinstance(counts, dict)
        and counts.get("source_database_uid") == source["database_uid"]
        and all(type(counts.get(field)) is int and counts[field] == 0
                for field in ("nonterminal_job_count", "legacy_or_unknown_artifact_count",
                              "unreadable_artifact_count", "active_passport_flow_count"))
        and isinstance(fence, dict) and isinstance(prior_fence, dict)
        and isinstance(prior_fence.get("verification_sha256"), str)
        and SHA256.fullmatch(prior_fence["verification_sha256"]) is not None
        and type(prior_fence.get("fence_epoch")) is int
        and prior_fence["fence_epoch"] > 0
        and fence.get("enabled") is True
        and fence.get("database_uid") == source["database_uid"]
        and fence.get("writer_deployment_uid") == source["writer_deployment_uid"]
        and fence.get("writer_generation") == source["writer_generation"]
        and fence.get("writer_container_id") == source["writer_container_id"]
        and fence.get("scope") == "physical_document_jobs_and_physical_flows"
        and fence.get("verification_sha256")
        == prior_fence.get("verification_sha256")
        and fence.get("unrelated_issuance_continues") is True
        and type(fence.get("fence_epoch")) is int
        and fence["fence_epoch"] == prior_fence.get("fence_epoch")
        and report.get("production_unchanged") is True
        and report.get("other_beta_resources_unchanged") is True
        and report.get("authorized_passport_fence_uid") == source["writer_deployment_uid"]
        and report.get("authorized_fence_epoch") == fence["fence_epoch"],
        "Final beta-source drain or durable Python write fence is incomplete",
    )
    checked = _utc_time(report.get("checked_at_utc"))
    prior_probe_checked, prior_probe_digest = _direct_fence_probe(
        prior_fence.get("direct_database_probe"), legacy["database_uid"],
        prior_fence["fence_epoch"], legacy["drain_watermark"],
        legacy["writer_database_role"],
    )
    probe_checked, probe_digest = _direct_fence_probe(
        fence.get("direct_database_probe"), source["database_uid"],
        fence["fence_epoch"], source["final_watermark"],
        source["writer_database_role"],
    )
    prior_gate._require(checked > _utc_time(legacy["drain_checked_at_utc"]),
                        "Final cutover drain predates the protected acceptance drain")
    prior_gate._require(
        prior_probe_checked < probe_checked <= checked
        and probe_digest != prior_probe_digest,
        "Final direct database fence probe is stale",
    )
    prior_gate._require(drain.get("count_source_database_uid") == source["database_uid"],
                        "Final cutover counts are from another database")
    return checked


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
        contract.get("schema") == "marty.physical-passport-python-retirement-qualification/v3",
        "Unknown passport retirement qualification schema",
    )
    if contract.get("state") == "blocked_pending_protected_acceptance":
        return None
    prior_gate._require(contract.get("state") == "qualified", "Unknown passport qualification state")
    source = contract.get("source")
    prior_gate._require(isinstance(source, dict)
                        and source.get("repository") == "ElevenID/marty-ui"
                        and isinstance(source.get("protected_main_commit"), str)
                        and COMMIT.fullmatch(source["protected_main_commit"]) is not None,
                        "Qualified passport checkout commit is invalid")
    return source["protected_main_commit"]


def verify(contract_path: Path, marty_ui: Path | None = None,
           deletion_head: str | None = None, post_pr_check: bool = False) -> None:
    contract = prior_gate._json(contract_path)
    prior_gate._require(
        contract.get("schema") == "marty.physical-passport-python-retirement-qualification/v3",
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
    prior_gate._require(contract.get("retirement_pull_request_number") == 305,
                        "Retirement pull request identity changed")
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

    if contract.get("state") == "blocked_pending_protected_acceptance":
        prior_gate._require(
            source.get("protected_main_commit") is None
            and source.get("artifact_sha256") is None
            and contract.get("predeletion_acceptance_receipt") is None
            and contract.get("supported_consumer_cutover_receipt") is None,
            "Blocked passport qualification invented evidence",
        )
        raise prior_gate.QualificationError(
            "Passport Python retirement is blocked pending protected disposable acceptance"
        )

    prior_gate._require(contract.get("state") == "qualified", "Unknown passport qualification state")
    prior_gate._require(marty_ui is not None, "Qualified passport source checkout is required")
    commit = _protected_source(source, marty_ui)
    predeletion = contract.get("predeletion_acceptance_receipt")
    prior_gate._require(isinstance(predeletion, dict)
                        and contract.get("supported_consumer_cutover_receipt") is None,
                        "Protected KMS passport acceptance receipt is required")
    prior_gate._require(predeletion.get("release_source_commit") == commit,
                        "Predeletion release source differs from qualified source")
    with tempfile.TemporaryDirectory(prefix="passport-retirement-evidence-") as temporary:
        root = Path(temporary)
        stack_digest = predeletion.get("stack_manifest_sha256")
        manifest = _signed_stack_manifest(predeletion.get("release_tag"), commit,
                                          stack_digest, root / "stack")
        expected_images = _image_digests(manifest)
        _all_image_references(manifest)
        services_uri = "ghcr.io/elevenid/marty-ui-oss/services"
        services_digest = expected_images[services_uri]
        services_reference = f"{services_uri}@{services_digest}"
        predeletion_run = predeletion.get("acceptance_run_id")
        predeletion_started, predeletion_completed = _verified_run(
            predeletion_run, commit,
            ".github/workflows/passport-rust-predeletion-acceptance.yml",
        )
        predeletion_report = _run_artifact(
            predeletion_run, predeletion.get("evidence_artifact"),
            predeletion.get("evidence_sha256"), root / "predeletion", commit,
            ".github/workflows/passport-rust-predeletion-acceptance.yml",
        )
        predeletion_release = predeletion_report.get("release")
        prior_gate._require(isinstance(predeletion_release, dict)
                            and predeletion_release.get("oci_digests") == expected_images,
                            "Predeletion report image digests differ from signed release")
        _predeletion_report(predeletion_report, commit, stack_digest)
        _frozen_batch_parity(marty_ui)
        for service, image in predeletion_report["runtime_images"].items():
            prior_gate._require(isinstance(image, dict)
                                and image.get("oci_reference") == services_reference
                                and image.get("oci_digest") == services_digest
                                and re.fullmatch(r"sha256:[0-9a-f]{64}",
                                                 str(image.get("image_id", ""))) is not None
                                and isinstance(image.get("container_id"), str)
                                and bool(image["container_id"]),
                                f"Disposable runtime image differs from signed release: {service}")
        drain = predeletion_report["probes"]["legacy_drain"]["evidence"]
        legacy = drain["legacy_source"]
        predeletion_accepted = _utc_time(predeletion_report["accepted_at_utc"])
        fence_enabled = _utc_time(legacy["fence_enabled_at_utc"])
        drain_checked = _utc_time(legacy["drain_checked_at_utc"])
        prior_gate._require(
            fence_enabled < drain_checked < predeletion_started
            <= predeletion_accepted <= predeletion_completed,
            "Beta-source drain is outside protected Rust acceptance",
        )
        if post_pr_check:
            prior_gate._require(os.environ.get("GITHUB_EVENT_NAME") in {"merge_group", "push"},
                                "Post-PR exact-head check is only valid on merge_group or push")
            deletion_head = _retirement_pr_head(contract["retirement_pull_request_number"])
            _post_pr_lineage(contract["retirement_pull_request_number"], deletion_head)
        else:
            prior_gate._require(isinstance(deletion_head, str)
                                and COMMIT.fullmatch(deletion_head) is not None,
                                "Exact pull-request deletion head is required")
            _pull_request_lineage(contract["retirement_pull_request_number"], deletion_head)
        cutover, cutover_started, cutover_completed = _final_cutover_report(
            commit, deletion_head, root / "cutover",
        )
        checked = _cutover_report(cutover, commit, deletion_head, legacy, drain,
                                  predeletion_run)
        prior_gate._require(predeletion_completed < cutover_started <= checked
                            <= cutover_completed,
                            "Final deletion cutover did not follow protected acceptance")
        if post_pr_check:
            _successful_pr_gate(contract["retirement_pull_request_number"], deletion_head,
                                cutover_completed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--marty-ui", type=Path)
    parser.add_argument("--deletion-head", help="Exact pull-request head SHA from the event")
    parser.add_argument("--post-pr-check", action="store_true",
                        help="Recheck signed parity on merge_group or push after the PR cutover gate")
    parser.add_argument("--print-checkout-commit", action="store_true",
                        help="Print a validated qualified source pin for the CI checkout")
    args = parser.parse_args()
    try:
        if args.print_checkout_commit:
            commit = _checkout_commit(args.contract)
            if commit is not None:
                print(commit)
            return 0
        verify(args.contract, args.marty_ui, args.deletion_head, args.post_pr_check)
    except prior_gate.QualificationError as error:
        parser.exit(1, f"{error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
