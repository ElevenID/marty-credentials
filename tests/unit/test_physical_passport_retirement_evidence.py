"""Reject plausible but unbound physical-passport retirement evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts import check_physical_passport_python_retirement as gate

COMMIT = "a" * 40
STACK_DIGEST = "b" * 64
IMAGE_DIGESTS = {
    f"ghcr.io/elevenid/marty-ui-oss/{role}": f"sha256:{letter * 64}"
    for role, letter in (("ui", "c"), ("services", "d"), ("migrations", "e"))
}
SERVICES_REFERENCE = (
    "ghcr.io/elevenid/marty-ui-oss/services@"
    + IMAGE_DIGESTS["ghcr.io/elevenid/marty-ui-oss/services"]
)


def supported_surface() -> dict:
    return {
        "runtime_accepted": True,
        "rollback_accepted": True,
        "probes": {
            "nine_route_gateway_flow": {
                "verified": True,
                "evidence": {
                    "routes": [{"method": method, "path": path}
                               for method, path in sorted(gate.EXPECTED_DELETIONS)],
                    "gateway_owner": "rust",
                    "flow_owner": "rust",
                    "unauthenticated_status": 401,
                },
            },
            "managed_signer": {"verified": True, "evidence": {
                "mode": "managed_kms", "chain_verified": True,
            }},
            "physical_bureau_callback": {"verified": True, "evidence": {
                "provider_kind": "physical", "signature_verified": True,
                "organization_bound": True,
            }},
            "released_image": {"verified": True, "evidence": {
                "oci_reference": SERVICES_REFERENCE,
                "source_commit": COMMIT,
                "container_id": "container-one",
            }},
            "rollback": {"verified": True, "evidence": {
                "before_owner": "rust", "after_owner": "python",
                "nine_routes_restored": True,
            }},
        },
    }


def beta_report() -> dict:
    return {
        "schema": "marty.passport-beta-acceptance/v1",
        "status": "accepted",
        "release": {
            "source_commit": COMMIT,
            "stack_manifest_sha256": STACK_DIGEST,
            "oci_digests": IMAGE_DIGESTS,
            "signed_manifest_verified": True,
        },
        "beta_origin": "https://beta.elevenidllc.com",
        "deployment": {
            "provider_mode": "physical",
            "local_deployment_manifest_sha256": "f" * 64,
            "source_manifest_sha256": "1" * 64,
        },
        "runtime_images": {
            name: {"image_id": "sha256:" + "2" * 64}
            for name in gate.EXPECTED_BETA_SERVICES
        },
        "probes": {
            **{name: {"verified": True, "evidence": {"source": "test"}}
               for name in gate.REQUIRED_BETA_PROBES},
            "physical_bureau_batch": {"verified": True, "evidence": {
                "provider_kind": "physical",
                "simulator_ids_absent": True,
                "source_commit": COMMIT,
                "stack_manifest_sha256": STACK_DIGEST,
                "services_oci_reference": SERVICES_REFERENCE,
                "request_sha256": "4" * 64,
                "response_sha256": "5" * 64,
                "provider_receipt_sha256": "3" * 64,
                "http_status": 202,
                "batch_status": "QUEUED",
                "submitted_job_sha256": ["6" * 64, "7" * 64],
                "returned_jobs": [
                    {"source_job_sha256": "7" * 64, "bureau_job_sha256": "8" * 64, "status": "PRINTING"},
                    {"source_job_sha256": "6" * 64, "bureau_job_sha256": "9" * 64, "status": "QUEUED"},
                ],
            }},
        },
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda report: report.update(status="blocked"),
        lambda report: report["release"].update(source_commit="9" * 40),
        lambda report: report["release"].update(stack_manifest_sha256="9" * 64),
        lambda report: report.update(beta_origin="https://production.elevenidllc.com"),
        lambda report: report["deployment"].pop("source_manifest_sha256"),
        lambda report: report["runtime_images"].pop("passport-provider-ingress"),
        lambda report: report["runtime_images"].update({"passport-beta-bureau": {"image_id": "sha256:" + "2" * 64}}),
        lambda report: report["deployment"].update(provider_mode="simulator"),
        lambda report: report["probes"].pop("physical_booklet_verified"),
        lambda report: report["probes"]["physical_booklet_verified"].update(verified=False),
        lambda report: report["probes"]["signed_bureau_callback"].update(verified="true"),
        lambda report: report["probes"].pop("physical_bureau_batch"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(provider_kind="simulator"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(simulator_ids_absent="true"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(source_commit="9" * 40),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(services_oci_reference="unbound"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(request_sha256="unbound"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(provider_receipt_sha256="not-a-digest"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(submitted_job_sha256=["6" * 64]),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(http_status=503),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(batch_status="FAILED"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"]["returned_jobs"][0].update(bureau_job_sha256="invalid"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"]["returned_jobs"][0].update(source_job_sha256="6" * 64),
    ],
)
def test_beta_report_requires_exact_lineage_and_probes(mutate) -> None:
    report = beta_report()
    gate._beta_report(report, COMMIT, STACK_DIGEST)
    mutate(report)
    with pytest.raises(gate.prior_gate.QualificationError):
        gate._beta_report(report, COMMIT, STACK_DIGEST)


def test_frozen_batch_parity_requires_exact_passing_rust_test(monkeypatch, tmp_path: Path) -> None:
    invocations = []

    def run(args, **kwargs):
        invocations.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, "test result: ok. 1 passed; 0 failed; 0 ignored\n", "")

    monkeypatch.setattr(gate.subprocess, "run", run)
    gate._frozen_batch_parity(tmp_path)
    args, kwargs = invocations[0]
    assert args[0:3] == ["cargo", "test", "--locked"]
    assert kwargs["cwd"] == tmp_path.resolve()
    assert kwargs["timeout"] == 3600
    for stdout, code in (("test result: ok. 0 passed; 0 failed; 1 filtered out\n", 0),
                         ("test result: FAILED. 0 passed; 1 failed;\n", 1)):
        monkeypatch.setattr(gate.subprocess, "run", lambda *args, value=stdout, status=code, **kwargs:
                            subprocess.CompletedProcess(args, status, value, ""))
        with pytest.raises(gate.prior_gate.QualificationError, match="batch parity"):
            gate._frozen_batch_parity(tmp_path)
    monkeypatch.setattr(gate.subprocess, "run", lambda args, **kwargs:
                        (_ for _ in ()).throw(subprocess.TimeoutExpired(args, 3600)))
    with pytest.raises(gate.prior_gate.QualificationError, match="could not run"):
        gate._frozen_batch_parity(tmp_path)


def test_qualified_checkout_pin_rejects_malformed_or_wrong_repository(tmp_path: Path) -> None:
    record = qualified_record()
    path = tmp_path / "qualification.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    assert gate._checkout_commit(path) == COMMIT
    for field, value in (("protected_main_commit", "main; echo unsafe"),
                         ("protected_main_commit", "9" * 39),
                         ("repository", "untrusted/marty-ui")):
        altered = copy.deepcopy(record)
        altered["source"][field] = value
        path.write_text(json.dumps(altered), encoding="utf-8")
        with pytest.raises(gate.prior_gate.QualificationError):
            gate._checkout_commit(path)
    record["state"] = "blocked_pending_beta_acceptance"
    path.write_text(json.dumps(record), encoding="utf-8")
    assert gate._checkout_commit(path) is None


def test_supported_report_requires_each_runtime_and_rollback() -> None:
    report = {
        "schema": "marty.passport-supported-consumer-acceptance/v1",
        "status": "accepted",
        "source_commit": COMMIT,
        "surfaces": {name: supported_surface() for name in gate.EXPECTED_SURFACES},
    }
    gate._supported_report(report, COMMIT, SERVICES_REFERENCE)
    for name in gate.EXPECTED_SURFACES:
        changed = copy.deepcopy(report)
        changed["surfaces"][name]["rollback_accepted"] = False
        with pytest.raises(gate.prior_gate.QualificationError):
            gate._supported_report(changed, COMMIT, SERVICES_REFERENCE)
        changed = copy.deepcopy(report)
        changed["surfaces"][name]["probes"]["physical_bureau_callback"]["verified"] = False
        with pytest.raises(gate.prior_gate.QualificationError):
            gate._supported_report(changed, COMMIT, SERVICES_REFERENCE)


def test_run_identity_rejects_wrong_source_or_failed_workflow(monkeypatch) -> None:
    run = {
        "status": "completed",
        "conclusion": "success",
        "head_sha": COMMIT,
        "head_branch": "main",
        "path": ".github/workflows/passport-beta-acceptance.yml",
        "repository": {"full_name": "ElevenID/marty-ui"},
        "head_repository": {"full_name": "ElevenID/marty-ui"},
    }
    monkeypatch.setattr(gate, "_command", lambda *args: json.dumps(run))
    gate._verified_run(123, COMMIT, run["path"])
    for field, value in (("head_sha", "9" * 40), ("conclusion", "failure"),
                         ("head_branch", "feature"),
                         ("path", ".github/workflows/other.yml"),
                         ("repository", {"full_name": "other/repo"}),
                         ("head_repository", {"full_name": "other/repo"})):
        changed = dict(run, **{field: value})
        monkeypatch.setattr(gate, "_command", lambda *args, row=changed: json.dumps(row))
        with pytest.raises(gate.prior_gate.QualificationError):
            gate._verified_run(123, COMMIT, run["path"])


def test_downloaded_artifact_must_match_receipt_bytes(tmp_path: Path, monkeypatch) -> None:
    payload = b'{"schema":"test"}\n'
    digest = hashlib.sha256(payload).hexdigest()

    def download(*args: str) -> str:
        output = Path(args[-1])
        (output / "passport-beta-acceptance.json").write_bytes(payload)
        return ""

    monkeypatch.setattr(gate, "_command", download)
    assert gate._run_artifact(123, "passport-beta-acceptance.json", digest,
                              tmp_path / "exact")["schema"] == "test"
    with pytest.raises(gate.prior_gate.QualificationError, match="SHA-256 mismatch"):
        gate._run_artifact(123, "passport-beta-acceptance.json", "0" * 64,
                           tmp_path / "wrong")


def test_signed_stack_manifest_binds_release_and_source(tmp_path: Path, monkeypatch) -> None:
    manifest = {
        "schema": "marty.stack/v1",
        "release": "marty-ui@1.2.3",
        "components": [{"name": "marty-ui", "repository": "ElevenID/marty-ui",
                        "commit": COMMIT,
                        "artifacts": [{"type": "oci", "uri": uri, "digest": digest}
                                      for uri, digest in IMAGE_DIGESTS.items()]}],
    }
    manifest_bytes = json.dumps(manifest).encode()
    digest = hashlib.sha256(manifest_bytes).hexdigest()

    attestation_args: list[tuple[str, ...]] = []

    def command(*args: str) -> str:
        if args[1] == "release":
            output = Path(args[-1])
            (output / "stack-manifest.json").write_bytes(manifest_bytes)
            (output / "SHA256SUMS").write_text(f"{digest}  stack-manifest.json\n")
        if args[1] == "attestation":
            attestation_args.append(args)
        return ""

    monkeypatch.setattr(gate, "_command", command)
    checked = gate._signed_stack_manifest("v1.2.3", COMMIT, digest, tmp_path / "stack")
    assert gate._image_digests(checked) == IMAGE_DIGESTS
    assert set(gate._all_image_references(checked)) == {
        f"{uri}@{image_digest}" for uri, image_digest in IMAGE_DIGESTS.items()
    }
    assert "--signer-workflow" in attestation_args[0]
    assert "ElevenID/marty-ui/.github/workflows/cd.yml" in attestation_args[0]
    assert "--source-digest" in attestation_args[0]
    assert COMMIT in attestation_args[0]
    with pytest.raises(gate.prior_gate.QualificationError, match="source mismatch"):
        gate._signed_stack_manifest("v1.2.3", "9" * 40, digest, tmp_path / "other")
    duplicate = copy.deepcopy(checked)
    duplicate["components"][0]["artifacts"].append(copy.deepcopy(
        duplicate["components"][0]["artifacts"][0]
    ))
    with pytest.raises(gate.prior_gate.QualificationError, match="image artifact"):
        gate._image_digests(duplicate)


def qualified_record() -> dict:
    return {
        "schema": "marty.physical-passport-python-retirement-qualification/v1",
        "state": "qualified",
        "source": {
            "repository": "ElevenID/marty-ui",
            "protected_main_commit": COMMIT,
            "required_artifacts": sorted(gate.EXPECTED_ARTIFACTS),
            "artifact_sha256": dict.fromkeys(gate.EXPECTED_ARTIFACTS, "1" * 64),
        },
        "authorized_python_route_deletions": [
            {"method": method, "path": path}
            for method, path in sorted(gate.EXPECTED_DELETIONS)
        ],
        "full_python_service_deletion_authorized": False,
        "beta_acceptance_receipt": {
            "release_tag": "v1.2.3",
            "release_source_commit": COMMIT,
            "stack_manifest_sha256": STACK_DIGEST,
            "beta_deployment_run_id": 123,
            "evidence_artifact": "passport-beta-acceptance.json",
            "evidence_sha256": "3" * 64,
        },
        "supported_consumer_cutover_receipt": {
            "repository": "ElevenID/marty-ui",
            "protected_main_commit": COMMIT,
            "acceptance_run_id": 456,
            "evidence_artifact": "passport-supported-acceptance.json",
            "evidence_sha256": "4" * 64,
        },
    }


def supported_report() -> dict:
    return {
        "schema": "marty.passport-supported-consumer-acceptance/v1",
        "status": "accepted",
        "source_commit": COMMIT,
        "stack_manifest_sha256": STACK_DIGEST,
        "oci_digests": IMAGE_DIGESTS,
        "surfaces": {name: supported_surface() for name in gate.EXPECTED_SURFACES},
    }


def test_qualified_path_remains_closed_after_provenance_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = qualified_record()
    beta = beta_report()
    beta["deployment"]["release_version"] = "1.2.3"
    uri = "ghcr.io/elevenid/marty-ui-oss/services"
    digest = IMAGE_DIGESTS[uri]
    beta["runtime_images"] = {
        service: {
            "container_id": "container-one",
            "image_id": "sha256:" + "2" * 64,
            "oci_reference": f"{uri}@{digest}",
            "oci_digest": digest,
        }
        for service in gate.EXPECTED_BETA_SERVICES
    }
    supported = supported_report()
    manifest = {
        "components": [{
            "name": "marty-ui",
            "artifacts": [{"type": "oci", "uri": image_uri, "digest": image_digest}
                          for image_uri, image_digest in IMAGE_DIGESTS.items()],
        }],
    }
    monkeypatch.setattr(gate, "_protected_source", lambda *args: COMMIT)
    monkeypatch.setattr(gate, "_signed_stack_manifest", lambda *args: manifest)
    monkeypatch.setattr(gate, "_verified_run", lambda *args: None)
    monkeypatch.setattr(gate, "_frozen_batch_parity", lambda *args: None)
    monkeypatch.setattr(
        gate, "_run_artifact",
        lambda run_id, *args: beta if run_id == 123 else supported,
    )

    def check(candidate: dict, expected: str) -> None:
        path = tmp_path / "candidate.json"
        path.write_text(json.dumps(candidate), encoding="utf-8")
        with pytest.raises(gate.prior_gate.QualificationError, match=expected):
            gate.verify(path, tmp_path)

    check(record, "Physical booklet provider evidence")
    changed = copy.deepcopy(record)
    changed["beta_acceptance_receipt"]["release_source_commit"] = "9" * 40
    check(changed, "Beta release source")
    changed = copy.deepcopy(record)
    changed["supported_consumer_cutover_receipt"]["protected_main_commit"] = "9" * 40
    check(changed, "Supported consumer source")
    beta["release"]["oci_digests"] = {"wrong": "sha256:" + "9" * 64}
    check(record, "image digests")
    beta["release"]["oci_digests"] = IMAGE_DIGESTS
    beta["runtime_images"]["gateway"]["oci_reference"] = (
        "ghcr.io/elevenid/marty-ui-oss/ui@"
        + IMAGE_DIGESTS["ghcr.io/elevenid/marty-ui-oss/ui"]
    )
    check(record, "Beta runtime image differs")
    beta["runtime_images"]["gateway"]["oci_reference"] = SERVICES_REFERENCE
    supported["surfaces"].pop("kubernetes")
    check(record, "surfaces are incomplete")


def test_protected_source_rejects_fabricated_hashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = qualified_record()["source"]
    monkeypatch.setattr(gate.prior_gate, "_git_head", lambda path: COMMIT)
    monkeypatch.setattr(gate.subprocess, "run", lambda args, **kwargs:
                        subprocess.CompletedProcess(args, 0, "", ""))
    monkeypatch.setattr(gate.prior_gate, "_git_is_from_protected_main", lambda *args: True)
    monkeypatch.setattr(gate.prior_gate, "_git_blob", lambda *args: b"real committed source")
    with pytest.raises(gate.prior_gate.QualificationError, match="hash mismatch"):
        gate._protected_source(source, tmp_path)


def test_protected_source_rejects_untracked_or_ignored_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = qualified_record()["source"]
    monkeypatch.setattr(gate.prior_gate, "_git_head", lambda path: COMMIT)
    monkeypatch.setattr(gate.subprocess, "run", lambda args, **kwargs:
                        subprocess.CompletedProcess(args, 0, "!! .cargo/config.toml\n", ""))
    with pytest.raises(gate.prior_gate.QualificationError, match="local or ignored"):
        gate._protected_source(source, tmp_path)


def test_required_ci_gate_includes_passport_retirement_provenance() -> None:
    workflow = yaml.safe_load((gate.ROOT / ".github/workflows/ci.yml").read_text(
        encoding="utf-8"
    ))
    jobs = workflow["jobs"]
    assert "passport-retirement-provenance" in jobs
    gate_job = jobs["ci-gate"]
    assert "passport-retirement-provenance" in gate_job["needs"]
    assert gate_job["if"] == "always()"
    assert gate_job["env"]["RESULTS"] == "${{ join(needs.*.result, ' ') }}"
    assert 'test "$result" = success' in gate_job["steps"][0]["run"]
    steps = jobs["passport-retirement-provenance"]["steps"]
    pin = next(step for step in steps if step.get("name") == "Pin qualified passport source commit")
    assert "--print-checkout-commit" in pin["run"]
    assert 'git -C ../marty-ui merge-base --is-ancestor "$source_commit" refs/remotes/origin/main' in pin["run"]
    assert 'git -C ../marty-ui checkout --detach "$source_commit"' in pin["run"]
    assert any(step.get("with", {}).get("toolchain") == "1.95.0" for step in steps)
