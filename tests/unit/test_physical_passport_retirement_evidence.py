"""Reject unbound Rust route compatibility and invented physical claims."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
from datetime import UTC
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
ORGANIZATION = "org-marty"
PROFILE = "passport-managed-profile"


def identity(name: str) -> dict:
    uid = f"owner-{name}"
    result = {
        "owner_uid": uid,
        "owner_labels": {"source_commit": COMMIT, "surface": name, "owner_uid": uid},
        "production_resources_excluded": True,
    }
    if name == "kubernetes":
        result.update(kind="kubernetes", namespace="passport-test-namespace",
                      cluster_uid="test-cluster-uid", production_cluster_uid="prod-cluster-uid",
                      cluster_identity_attestation_sha256="b" * 64)
    else:
        result.update(kind="compose", project_id=f"passport-disposable-{name}")
    return result


def bound(evidence: dict, owner: dict) -> dict:
    evidence.update(owner_uid=owner["owner_uid"], owner_labels=owner["owner_labels"],
                    target=owner.get("project_id", owner.get("namespace")))
    if owner["kind"] == "kubernetes":
        evidence["cluster_uid"] = owner["cluster_uid"]
    return evidence


def managed_signer(container_id: str) -> dict:
    return {
        "mode": "managed_kms", "chain_verified": True, "private_key_exported": False,
        "issuer_profile_id": PROFILE, "issuer_profile_type": "ICAO_EMRTD",
        "issuer_profile_status": "active", "organization_id": ORGANIZATION,
        "signing_keys_container_id": container_id,
        "services_oci_reference": SERVICES_REFERENCE,
        "csca": {"status": "active", "organization_id": ORGANIZATION,
                 "issuer_profile_id": PROFILE, "certificate_sha256": "1" * 64,
                 "kms_key_ref": "transit/keys/passport-csca"},
        "dsc": {"status": "active", "organization_id": ORGANIZATION,
                "issuer_profile_id": PROFILE, "certificate_sha256": "2" * 64,
                "kms_key_ref": "transit/keys/passport-dsc"},
    }


def sod_evidence() -> dict:
    return {"signature_verified": True, "chain_verified": True,
            "organization_id": ORGANIZATION, "issuer_profile_id": PROFILE,
            "csca_certificate_sha256": "1" * 64,
            "dsc_certificate_sha256": "2" * 64}


def supported_surface(name: str) -> dict:
    routes = [{"method": method, "path": path}
              for method, path in sorted(gate.EXPECTED_DELETIONS)]
    owner = identity(name)
    signer = managed_signer(f"signing-keys-{name}-after")
    signer["sod"] = sod_evidence()
    callback = {"provider_kind": "simulator", "signature_verified": True,
                "organization_bound": True, "organization_id": ORGANIZATION,
                "physical_claim": "not_claimed"}

    surface = {
        "runtime_accepted": True,
        "identity": owner,
        "runtime_images": {
            service: {
                "container_id": f"{service}-{name}-after",
                "image_id": "sha256:" + "d" * 64,
                "oci_reference": SERVICES_REFERENCE,
                "selectors": dict.fromkeys(gate.EXPECTED_SUPPORTED_FLAGS[service], True),
            }
            for service in gate.EXPECTED_SUPPORTED_SERVICES
        },
        "probes": {
            "nine_route_gateway_flow": {
                "verified": True,
                "evidence": {
                    "routes": routes,
                    "gateway_owner": "rust",
                    "flow_owner": "rust",
                    "unauthenticated_status": 401,
                    "cross_tenant_status": 404,
                    "organization_id": ORGANIZATION,
                },
            },
            "managed_signer": {"verified": True, "evidence": signer},
            "signed_bureau_callback": {"verified": True, "evidence": callback},
            "released_image": {"verified": True, "evidence": {
                "oci_reference": SERVICES_REFERENCE,
                "source_commit": COMMIT,
                "container_id": f"gateway-{name}-after",
            }},
            "rust_restart_resume": {"verified": True, "evidence": {
                "before": {"owner": "rust", "issuance_native_container_id": f"issuance-native-{name}-before",
                           "image_id": "sha256:" + "d" * 64,
                           "oci_reference": SERVICES_REFERENCE,
                           "organization_id": ORGANIZATION, "issuer_profile_id": PROFILE,
                           "job_commitment": "5" * 64, "status": "SOD_SIGNED"},
                "after": {"owner": "rust", "issuance_native_container_id": f"issuance-native-{name}-after",
                          "image_id": "sha256:" + "d" * 64,
                          "oci_reference": SERVICES_REFERENCE,
                          "organization_id": ORGANIZATION, "issuer_profile_id": PROFILE,
                          "job_commitment": "5" * 64, "status": "SUBMITTED"},
                "job_resumed": True,
                "durable_record_verified": True,
                "kms_signing_continuity_verified": True,
                "gateway_owner": "rust",
                "flow_owner": "rust",
                "source_commit": COMMIT,
                "services_oci_reference": SERVICES_REFERENCE,
            }},
        },
        "pre_restart_native_runtime": {
            "container_id": f"issuance-native-{name}-before",
            "image_id": "sha256:" + "d" * 64,
            "oci_reference": SERVICES_REFERENCE,
            "inspection_receipt_sha256": "f" * 64,
        },
    }
    for runtime in surface["runtime_images"].values():
        bound(runtime, owner)
    bound(surface["pre_restart_native_runtime"], owner)
    for probe in surface["probes"].values():
        bound(probe["evidence"], owner)
    restart = surface["probes"]["rust_restart_resume"]["evidence"]
    bound(restart["before"], owner)
    bound(restart["after"], owner)
    return surface


def predeletion_report() -> dict:
    report = {
        "schema": "marty.passport-rust-predeletion-acceptance/v1",
        "status": "accepted",
        "accepted_at_utc": "2026-09-26T00:15:00Z",
        "physical_claim": "not_claimed",
        "release": {
            "source_commit": COMMIT,
            "stack_manifest_sha256": STACK_DIGEST,
            "oci_digests": IMAGE_DIGESTS,
            "signed_manifest_verified": True,
        },
        "deployment": {
            **identity("base"),
            "mode": "disposable",
            "provider_mode": "simulator",
            "resource_identity_verified": True,
            "source_commit": COMMIT,
            "database_uid": "disposable-db-uid",
        },
        "runtime_images": {
            name: {"image_id": "sha256:" + "d" * 64,
                   "container_id": f"{name}-base-after",
                   "oci_reference": SERVICES_REFERENCE}
            for name in gate.EXPECTED_PREDELETION_SERVICES
        },
        "probes": {
            **{name: {"verified": True, "evidence": {"source": "test"}}
               for name in gate.REQUIRED_PREDELETION_PROBES},
            "managed_csca_dsc_chain": {"verified": True, "evidence": {
                "mode": "managed_kms", "chain_verified": True,
                "private_key_exported": False,
            }},
            "sod_signature": {"verified": True, "evidence": {
                "signature_verified": True, "chain_verified": True,
            }},
            "nine_route_gateway_flow": {"verified": True, "evidence": {
                "routes": [{"method": method, "path": path}
                           for method, path in sorted(gate.EXPECTED_DELETIONS)],
                "gateway_owner": "rust", "flow_owner": "rust",
                "unauthenticated_status": 401, "cross_tenant_status": 404,
                "organization_id": ORGANIZATION,
            }},
            "signed_bureau_callback": {"verified": True, "evidence": {
                "provider_kind": "simulator", "signature_verified": True,
                "organization_bound": True, "flow_execution_verified": True,
                "organization_id": ORGANIZATION,
                "physical_claim": "not_claimed",
            }},
            "legacy_drain": {"verified": True, "evidence": {
                "source_commit": COMMIT, "python_passport_writes_fenced": True,
                "count_source_database_uid": "beta-legacy-db-uid",
                "legacy_source": {
                    "environment": "beta", "database_uid": "beta-legacy-db-uid",
                    "beta_cluster_uid": "beta-cluster-uid",
                    "database_cluster_uid": "beta-cluster-uid",
                    "writer_cluster_uid": "beta-cluster-uid",
                    "beta_inventory_attestation_sha256": "c" * 64,
                    "writer_deployment_uid": "beta-python-writer-uid",
                    "writer_owner": "python", "writer_image_digest": "sha256:" + "a" * 64,
                    "writer_database_role": "marty",
                    "writer_container_id": "a" * 64,
                    "writer_running_at_drain": True,
                    "writer_generation_at_fence": 3, "writer_generation_at_drain": 3,
                    "fence_watermark": 100, "drain_watermark": 101,
                    "drain_snapshot_attestation_sha256": "d" * 64,
                    "fence_enabled_at_utc": "2026-09-26T00:12:00Z",
                    "drain_checked_at_utc": "2026-09-26T00:14:00Z",
                },
                "passport_write_fence": {
                    "scope": "physical_document_jobs_and_physical_flows",
                    "enabled": True, "database_uid": "beta-legacy-db-uid",
                    "writer_deployment_uid": "beta-python-writer-uid",
                    "writer_container_id": "a" * 64,
                    "writer_generation": 3, "fence_epoch": 4,
                    "verification_sha256": "f" * 64,
                    "direct_database_probe": {
                        "method": "postgresql_transaction_rollback",
                        "database_uid": "beta-legacy-db-uid", "fence_epoch": 4,
                        "session_user": "marty", "current_user": "marty",
                        "observation_watermark": 101,
                        "observed_at_utc": "2026-09-26T00:13:00Z",
                        "receipt_sha256": "1" * 64,
                        "rejections": {
                            "physical_document_jobs": {"valid_without_fence": True,
                                "sqlstate": "55000", "message": "beta passport job writes are fenced"},
                            "physical_flow_definitions": {"valid_without_fence": True,
                                "sqlstate": "55000", "message": "beta physical-document Flow definition writes are fenced"},
                            "physical_flow_instances": {"valid_without_fence": True,
                                "sqlstate": "55000", "message": "beta physical-document Flow writes are fenced"},
                        },
                    },
                    "unrelated_issuance_continues": True,
                },
                "nonterminal_job_count": 0, "unreadable_artifact_count": 0,
                "legacy_or_unknown_artifact_count": 0,
                "active_passport_flow_count": 0,
            }},
            "production_isolation": {"verified": True, "evidence": {
                "production_unchanged": True, "other_beta_resources_unchanged": True,
                "authorized_passport_fence_uid": "beta-python-writer-uid",
                "disposable_resource_identity_verified": True,
            }},
            "physical_claim_boundary": {"verified": True, "evidence": {
                "physical_claim": "not_claimed", "booklet_verified": False,
            }},
            "physical_bureau_batch": {"verified": True, "evidence": {
                "provider_kind": "simulator",
                "simulator_marker_verified": True,
                "physical_claim": "not_claimed",
                "commitment_scheme": "HMAC-SHA256",
                "organization_id": ORGANIZATION,
                "source_commit": COMMIT,
                "stack_manifest_sha256": STACK_DIGEST,
                "services_oci_reference": SERVICES_REFERENCE,
                "request_commitment": "4" * 64,
                "response_commitment": "5" * 64,
                "callback_receipt_sha256": "3" * 64,
                "callback_receipts_sha256": ["3" * 64, "a" * 64],
                "native_binding_verified": True,
                "native_completed_jobs": 2,
                "http_status": 202,
                "batch_status": "QUEUED",
                "submitted_job_commitments": ["6" * 64, "7" * 64],
                "returned_jobs": [
                    {"source_job_commitment": "7" * 64, "bureau_job_commitment": "8" * 64, "status": "PRINTING"},
                    {"source_job_commitment": "6" * 64, "bureau_job_commitment": "9" * 64, "status": "QUEUED"},
                ],
            }},
        },
    }
    batch = report["probes"]["physical_bureau_batch"]["evidence"]
    report["probes"]["packaged_image"]["evidence"] = {
        "source_commit": COMMIT,
        "stack_manifest_sha256": STACK_DIGEST,
        "services_oci_reference": SERVICES_REFERENCE,
        "runtime_container_id": "passport-beta-bureau-base-after",
    }
    report["probes"]["physical_bureau_submission"]["evidence"] = {
        "provider_kind": "simulator", "physical_claim": "not_claimed",
        **{name: copy.deepcopy(batch[name]) for name in (
            "source_commit", "stack_manifest_sha256", "services_oci_reference",
            "http_status", "batch_status", "request_commitment",
            "response_commitment", "submitted_job_commitments", "returned_jobs",
        )},
    }
    report["probes"]["managed_csca_dsc_chain"]["evidence"] = managed_signer(
        "signing-keys-base-after")
    report["probes"]["sod_signature"]["evidence"] = sod_evidence()
    callback = report["probes"]["signed_bureau_callback"]["evidence"]
    callback.update(receipt_sha256=batch["callback_receipt_sha256"],
                    callback_receipts_sha256=batch["callback_receipts_sha256"],
                    source_job_commitments=batch["submitted_job_commitments"],
                    native_completed_jobs=batch["native_completed_jobs"],
                    native_container_id="issuance-native-base-after")
    returned_by_source = {job["source_job_commitment"]: job["bureau_job_commitment"]
                          for job in batch["returned_jobs"]}
    callback["jobs"] = [
        {"source_job_commitment": source,
         "bureau_job_commitment": returned_by_source[source],
         "receipt_sha256": batch["callback_receipts_sha256"][index],
         "native_completed": True, "organization_id": ORGANIZATION,
         "native_container_id": "issuance-native-base-after"}
        for index, source in enumerate(batch["submitted_job_commitments"])
    ]
    owner = report["deployment"]
    for runtime in report["runtime_images"].values():
        bound(runtime, owner)
    for probe in report["probes"].values():
        bound(probe["evidence"], owner)
    return report


@pytest.mark.parametrize(
    "mutate",
    [
        lambda report: report.update(status="blocked"),
        lambda report: report["release"].update(source_commit="9" * 40),
        lambda report: report["release"].update(stack_manifest_sha256="9" * 64),
        lambda report: report.update(physical_claim="booklet_verified"),
        lambda report: report["deployment"].update(mode="beta"),
        lambda report: report["deployment"].update(resource_identity_verified=False),
        lambda report: report["runtime_images"].pop("passport-beta-bureau"),
        lambda report: report["runtime_images"].update({"passport-provider-ingress": {"image_id": "sha256:" + "2" * 64}}),
        lambda report: report.update(provider_ingress_runtime_image={"image_id": "sha256:" + "2" * 64}),
        lambda report: report["deployment"].update(provider_mode="physical"),
        lambda report: report["probes"].pop("physical_claim_boundary"),
        lambda report: report["probes"]["physical_claim_boundary"]["evidence"].update(booklet_verified=True),
        lambda report: report["probes"]["nine_route_gateway_flow"]["evidence"].update(cross_tenant_status=200),
        lambda report: report["probes"]["managed_csca_dsc_chain"]["evidence"].update(private_key_exported=True),
        lambda report: report["probes"]["sod_signature"]["evidence"].update(signature_verified=False),
        lambda report: report["probes"]["signed_bureau_callback"]["evidence"].update(flow_execution_verified=False),
        lambda report: report["probes"]["legacy_drain"]["evidence"].update(nonterminal_job_count=1),
        lambda report: report["probes"]["legacy_drain"]["evidence"].update(unreadable_artifact_count=1),
        lambda report: report["probes"]["legacy_drain"]["evidence"].update(legacy_or_unknown_artifact_count=1),
        lambda report: report["probes"]["legacy_drain"]["evidence"].update(nonterminal_job_count=False),
        lambda report: report["probes"]["legacy_drain"]["evidence"].update(active_passport_flow_count=1),
        lambda report: report["probes"]["legacy_drain"]["evidence"].update(python_passport_writes_fenced=False),
        lambda report: report["probes"]["production_isolation"]["evidence"].update(production_unchanged=False),
        lambda report: report["probes"]["production_isolation"]["evidence"].update(
            authorized_passport_fence_uid="other-writer"),
        lambda report: report["probes"]["production_isolation"]["evidence"].update(
            other_beta_resources_unchanged=False),
        lambda report: report["probes"]["signed_bureau_callback"].update(verified="true"),
        lambda report: report["probes"].pop("physical_bureau_batch"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(provider_kind="physical"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(simulator_marker_verified="true"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(physical_claim="booklet_verified"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(commitment_scheme="SHA256"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(source_commit="9" * 40),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(services_oci_reference="unbound"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(request_commitment="unbound"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(callback_receipt_sha256="not-a-digest"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(submitted_job_commitments=["6" * 64]),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(http_status=503),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(batch_status="FAILED"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(native_binding_verified=False),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(native_completed_jobs=1),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(callback_receipts_sha256=[]),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(callback_receipts_sha256=["3" * 64, "3" * 64]),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"].update(callback_receipts_sha256=["a" * 64, "3" * 64]),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"]["returned_jobs"][0].update(bureau_job_commitment="invalid"),
        lambda report: report["probes"]["physical_bureau_batch"]["evidence"]["returned_jobs"][0].update(source_job_commitment="6" * 64),
        lambda report: report["probes"]["packaged_image"]["evidence"].update(source_commit="9" * 40),
        lambda report: report["probes"]["packaged_image"]["evidence"].update(services_oci_reference="unbound"),
        lambda report: report["probes"]["packaged_image"]["evidence"].update(runtime_container_id="other"),
        lambda report: report["probes"]["physical_bureau_submission"]["evidence"].update(provider_kind="physical"),
        lambda report: report["probes"]["physical_bureau_submission"]["evidence"].update(request_commitment="9" * 64),
        lambda report: report["probes"]["physical_bureau_submission"]["evidence"].update(returned_jobs=[]),
    ],
)
def test_predeletion_report_requires_exact_lineage_and_probes(mutate) -> None:
    report = predeletion_report()
    gate._predeletion_report(report, COMMIT, STACK_DIGEST)
    mutate(report)
    with pytest.raises(gate.prior_gate.QualificationError):
        gate._predeletion_report(report, COMMIT, STACK_DIGEST)


@pytest.mark.parametrize("mutate", [
    lambda r: r["runtime_images"]["signing-keys"].update(container_id="wrong"),
    lambda r: r["probes"]["managed_csca_dsc_chain"]["evidence"].update(
        issuer_profile_type="other"),
    lambda r: r["probes"]["managed_csca_dsc_chain"]["evidence"]["csca"].update(
        organization_id="other"),
    lambda r: r["probes"]["managed_csca_dsc_chain"]["evidence"]["dsc"].update(
        status="inactive"),
    lambda r: r["probes"]["managed_csca_dsc_chain"]["evidence"]["dsc"].update(
        kms_key_ref="transit/keys/passport-csca"),
    lambda r: r["probes"]["sod_signature"]["evidence"].update(
        dsc_certificate_sha256="9" * 64),
    lambda r: r["probes"]["signed_bureau_callback"]["evidence"].update(
        receipt_sha256="9" * 64),
    lambda r: r["probes"]["signed_bureau_callback"]["evidence"].update(
        source_job_commitments=["9" * 64]),
    lambda r: r["probes"]["signed_bureau_callback"]["evidence"].update(
        native_container_id="other"),
    lambda r: r["probes"]["signed_bureau_callback"]["evidence"]["jobs"][0].update(
        bureau_job_commitment="f" * 64),
    lambda r: r["probes"]["legacy_drain"]["evidence"]["legacy_source"].update(
        environment="disposable"),
    lambda r: r["probes"]["legacy_drain"]["evidence"]["legacy_source"].update(
        database_uid="disposable-db-uid"),
    lambda r: r["probes"]["legacy_drain"]["evidence"]["legacy_source"].update(
        writer_cluster_uid="other"),
    lambda r: r["probes"]["legacy_drain"]["evidence"]["legacy_source"].update(
        writer_generation_at_drain=4),
    lambda r: r["probes"]["legacy_drain"]["evidence"]["legacy_source"].update(
        writer_container_id="b" * 64),
    lambda r: r["probes"]["legacy_drain"]["evidence"]["legacy_source"].update(
        writer_running_at_drain=False),
    lambda r: r["probes"]["legacy_drain"]["evidence"]["legacy_source"].update(
        drain_watermark=99),
    lambda r: r["probes"]["legacy_drain"]["evidence"].update(
        count_source_database_uid="other"),
    lambda r: r["probes"]["legacy_drain"]["evidence"]["passport_write_fence"].update(
        scope="passport_routes_only"),
    lambda r: r["probes"]["legacy_drain"]["evidence"]["passport_write_fence"].update(
        enabled=False),
    lambda r: r["probes"]["legacy_drain"]["evidence"]["passport_write_fence"].update(
        direct_database_probe={"method": "gateway_api"}),
    lambda r: r["probes"]["legacy_drain"]["evidence"]["passport_write_fence"]["direct_database_probe"].update(
        current_user="postgres"),
    lambda r: r["probes"]["legacy_drain"]["evidence"]["passport_write_fence"]["direct_database_probe"]["rejections"]["physical_flow_instances"].update(
        sqlstate="23514"),
    lambda r: r["probes"]["legacy_drain"]["evidence"]["passport_write_fence"].update(
        unrelated_issuance_continues=False),
    lambda r: r["runtime_images"]["gateway"].update(owner_uid="other"),
    lambda r: r["probes"]["nine_route_gateway_flow"]["evidence"].update(
        owner_uid="other"),
])
def test_predeletion_rejects_unbound_signer_callback_drain_or_owner(mutate) -> None:
    report = predeletion_report()
    gate._predeletion_report(report, COMMIT, STACK_DIGEST)
    mutate(report)
    with pytest.raises(gate.prior_gate.QualificationError):
        gate._predeletion_report(report, COMMIT, STACK_DIGEST)


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
    record["state"] = "blocked_pending_protected_acceptance"
    path.write_text(json.dumps(record), encoding="utf-8")
    assert gate._checkout_commit(path) is None


def test_supported_report_requires_each_rust_runtime() -> None:
    report = {
        "schema": "marty.passport-supported-consumer-acceptance/v1",
        "status": "accepted",
        "accepted_at_utc": "2026-09-26T00:09:00Z",
        "physical_claim": "not_claimed",
        "source_commit": COMMIT,
        "surfaces": {name: supported_surface(name) for name in gate.EXPECTED_SURFACES},
    }
    gate._supported_report(report, COMMIT, SERVICES_REFERENCE)
    for name in gate.EXPECTED_SURFACES:
        changed = copy.deepcopy(report)
        changed["surfaces"][name]["runtime_accepted"] = False
        with pytest.raises(gate.prior_gate.QualificationError):
            gate._supported_report(changed, COMMIT, SERVICES_REFERENCE)
        changed = copy.deepcopy(report)
        changed["surfaces"][name]["probes"]["signed_bureau_callback"]["verified"] = False
        with pytest.raises(gate.prior_gate.QualificationError):
            gate._supported_report(changed, COMMIT, SERVICES_REFERENCE)


@pytest.mark.parametrize("change", [
    lambda resume, surface: resume["before"].update(owner="python"),
    lambda resume, surface: resume["after"].update(
        issuance_native_container_id=resume["before"]["issuance_native_container_id"]),
    lambda resume, surface: resume["after"].update(job_commitment="9" * 64),
    lambda resume, surface: resume["before"].update(
        issuance_native_container_id="arbitrary-before"),
    lambda resume, surface: surface["pre_restart_native_runtime"].update(
        owner_uid="other"),
    lambda resume, surface: resume["before"].update(issuer_profile_id="other"),
    lambda resume, surface: resume["after"].update(target="other-project"),
    lambda resume, surface: resume.update(job_resumed=False),
    lambda resume, surface: resume.update(durable_record_verified=False),
    lambda resume, surface: resume["after"].update(status="SOD_SIGNED"),
    lambda resume, surface: resume.update(kms_signing_continuity_verified=False),
    lambda resume, surface: resume.update(flow_owner="python"),
    lambda resume, surface: resume.update(source_commit="9" * 40),
    lambda resume, surface: surface["probes"]["nine_route_gateway_flow"]["evidence"].update(cross_tenant_status=200),
    lambda phase, surface: surface["probes"]["released_image"]["evidence"].update(
        container_id="gateway-before"),
    lambda resume, surface: surface["runtime_images"]["issuance-native"].update(
        container_id="issuance-native-wrong"),
    lambda resume, surface: surface["runtime_images"]["flow"].update(
        oci_reference="ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "9" * 64),
    lambda resume, surface: surface["runtime_images"]["signing-keys"].update(
        container_id="other"),
    lambda resume, surface: surface["probes"]["managed_signer"]["evidence"].update(
        issuer_profile_status="inactive"),
    lambda resume, surface: surface["probes"]["managed_signer"]["evidence"]["sod"].update(
        csca_certificate_sha256="9" * 64),
])
def test_supported_report_rejects_incomplete_rust_restart_resume(change) -> None:
    report = supported_report()
    surface = report["surfaces"]["base"]
    change(surface["probes"]["rust_restart_resume"]["evidence"], surface)
    with pytest.raises(gate.prior_gate.QualificationError):
        gate._supported_report(report, COMMIT, SERVICES_REFERENCE)


@pytest.mark.parametrize("mutate", [
    lambda r: r["surfaces"]["selfhost"].update(
        identity=copy.deepcopy(r["surfaces"]["base"]["identity"])),
    lambda r: r["surfaces"]["selfhost"]["identity"].update(
        owner_uid=r["surfaces"]["base"]["identity"]["owner_uid"]),
    lambda r: r["surfaces"]["kubernetes"]["identity"].update(
        cluster_uid="prod-cluster-uid"),
    lambda r: r["surfaces"]["kubernetes"]["identity"].update(
        cluster_identity_attestation_sha256="invalid"),
    lambda r: r["surfaces"]["kubernetes"]["runtime_images"]["gateway"].update(
        cluster_uid="other-cluster"),
    lambda r: r["surfaces"]["kubernetes"]["probes"]["nine_route_gateway_flow"]["evidence"].update(
        owner_uid="other"),
])
def test_supported_surfaces_reject_cloned_or_unprotected_identity(mutate) -> None:
    report = supported_report()
    gate._supported_report(report, COMMIT, SERVICES_REFERENCE)
    mutate(report)
    with pytest.raises(gate.prior_gate.QualificationError):
        gate._supported_report(report, COMMIT, SERVICES_REFERENCE)


def test_run_identity_rejects_wrong_source_or_failed_workflow(monkeypatch) -> None:
    run = {
        "status": "completed",
        "conclusion": "success",
        "head_sha": COMMIT,
        "head_branch": "main",
        "path": ".github/workflows/passport-rust-predeletion-acceptance.yml",
        "created_at": "2026-09-26T00:11:00Z",
        "updated_at": "2026-09-26T00:16:00Z",
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
        (output / "passport-rust-predeletion-acceptance.json").write_bytes(payload)
        return ""

    monkeypatch.setattr(gate, "_command", download)
    assert gate._run_artifact(123, "passport-rust-predeletion-acceptance.json", digest,
                              tmp_path / "exact")["schema"] == "test"
    with pytest.raises(gate.prior_gate.QualificationError, match="SHA-256 mismatch"):
        gate._run_artifact(123, "passport-rust-predeletion-acceptance.json", "0" * 64,
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
        "schema": "marty.physical-passport-python-retirement-qualification/v3",
        "state": "qualified",
        "retirement_pull_request_number": 305,
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
        "predeletion_acceptance_receipt": {
            "release_tag": "v1.2.3",
            "release_source_commit": COMMIT,
            "stack_manifest_sha256": STACK_DIGEST,
            "acceptance_run_id": 123,
            "evidence_artifact": "passport-rust-predeletion-acceptance.json",
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
        "physical_claim": "not_claimed",
        "source_commit": COMMIT,
        "accepted_at_utc": "2026-09-26T00:09:00Z",
        "legacy_source_binding": {"database_uid": "beta-legacy-db-uid",
                                  "writer_deployment_uid": "beta-python-writer-uid"},
        "stack_manifest_sha256": STACK_DIGEST,
        "oci_digests": IMAGE_DIGESTS,
        "surfaces": {name: supported_surface(name) for name in gate.EXPECTED_SURFACES},
    }


def final_cutover_report() -> dict:
    return {
        "schema": "marty.passport-python-deletion-cutover/v1",
        "status": "accepted",
        "rust_source_commit": COMMIT,
        "deletion_head": "e" * 40,
        "supported_acceptance_run_id": 456,
        "predeletion_acceptance_run_id": 123,
        "checked_at_utc": "2026-09-26T00:25:00Z",
        "production_unchanged": True,
        "other_beta_resources_unchanged": True,
        "authorized_passport_fence_uid": "beta-python-writer-uid",
        "authorized_fence_epoch": 4,
        "legacy_source": {
            "environment": "beta", "database_uid": "beta-legacy-db-uid",
            "beta_cluster_uid": "beta-cluster-uid",
            "beta_inventory_attestation_sha256": "c" * 64,
            "writer_deployment_uid": "beta-python-writer-uid",
            "writer_image_digest": "sha256:" + "a" * 64,
            "writer_database_role": "marty",
            "writer_generation": 3, "writer_container_id": "a" * 64,
            "writer_running": True,
            "final_watermark": 102,
            "final_snapshot_attestation_sha256": "e" * 64,
        },
        "counts": {
            "source_database_uid": "beta-legacy-db-uid",
            "nonterminal_job_count": 0, "legacy_or_unknown_artifact_count": 0,
            "unreadable_artifact_count": 0, "active_passport_flow_count": 0,
        },
        "write_fence": {
            "enabled": True, "database_uid": "beta-legacy-db-uid",
            "writer_deployment_uid": "beta-python-writer-uid",
            "writer_generation": 3, "writer_container_id": "a" * 64,
            "fence_epoch": 4,
            "scope": "physical_document_jobs_and_physical_flows",
            "verification_sha256": "f" * 64,
            "direct_database_probe": {
                "method": "postgresql_transaction_rollback",
                "database_uid": "beta-legacy-db-uid", "fence_epoch": 4,
                "session_user": "marty", "current_user": "marty",
                "observation_watermark": 102,
                "observed_at_utc": "2026-09-26T00:24:00Z",
                "receipt_sha256": "2" * 64,
                "rejections": {
                    "physical_document_jobs": {"valid_without_fence": True,
                        "sqlstate": "55000", "message": "beta passport job writes are fenced"},
                    "physical_flow_definitions": {"valid_without_fence": True,
                        "sqlstate": "55000", "message": "beta physical-document Flow definition writes are fenced"},
                    "physical_flow_instances": {"valid_without_fence": True,
                        "sqlstate": "55000", "message": "beta physical-document Flow writes are fenced"},
                },
            },
            "unrelated_issuance_continues": True,
        },
    }


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(deletion_head="9" * 40),
    lambda r: r.update(predeletion_acceptance_run_id=999),
    lambda r: r["legacy_source"].update(database_uid="disposable-db-uid"),
    lambda r: r["legacy_source"].update(writer_generation=4),
    lambda r: r["legacy_source"].update(writer_container_id="b" * 64),
    lambda r: r["legacy_source"].update(writer_running=False),
    lambda r: r["legacy_source"].update(final_watermark=99),
    lambda r: r["legacy_source"].update(final_watermark=101),
    lambda r: r["legacy_source"].update(final_watermark=101,
                                         final_snapshot_attestation_sha256="d" * 64),
    lambda r: r["counts"].update(source_database_uid="other"),
    lambda r: r["counts"].update(nonterminal_job_count=1),
    lambda r: r["write_fence"].update(enabled=False),
    lambda r: r["write_fence"].update(writer_generation=4),
    lambda r: r["write_fence"].update(writer_container_id="b" * 64),
    lambda r: r["write_fence"].update(scope="passport_routes_only"),
    lambda r: r["write_fence"].update(fence_epoch=5),
    lambda r: r["write_fence"].update(verification_sha256="b" * 64),
    lambda r: r["write_fence"]["direct_database_probe"].update(
        session_user="postgres"),
    lambda r: r["write_fence"]["direct_database_probe"]["rejections"]["physical_document_jobs"].update(
        valid_without_fence=False),
    lambda r: r["write_fence"]["direct_database_probe"]["rejections"]["physical_flow_definitions"].update(
        message="violates check constraint"),
    lambda r: r["write_fence"]["direct_database_probe"].update(
        method="gateway_api"),
    lambda r: r["write_fence"]["direct_database_probe"].update(
        observation_watermark=101),
    lambda r: r["write_fence"]["direct_database_probe"].update(
        observed_at_utc="2026-09-26T00:13:00Z"),
    lambda r: r["write_fence"]["direct_database_probe"].update(
        receipt_sha256="1" * 64),
    lambda r: r.update(authorized_passport_fence_uid="other-writer"),
    lambda r: r.update(other_beta_resources_unchanged=False),
    lambda r: r.update(checked_at_utc="2026-09-26T00:13:00Z"),
])
def test_final_cutover_rejects_wrong_head_resumed_writer_or_stale_drain(mutate) -> None:
    report = final_cutover_report()
    predeletion = predeletion_report()
    drain = predeletion["probes"]["legacy_drain"]["evidence"]
    gate._cutover_report(report, COMMIT, "e" * 40, drain["legacy_source"], drain, 456, 123)
    mutate(report)
    with pytest.raises(gate.prior_gate.QualificationError):
        gate._cutover_report(report, COMMIT, "e" * 40, drain["legacy_source"], drain, 456, 123)


def test_final_cutover_fetches_attested_report_for_exact_deletion_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = {"id": 789, "head_sha": COMMIT, "head_branch": "main",
           "status": "completed", "conclusion": "success", "updated_at": "2026-09-26T00:26:00Z"}
    attested: list[tuple[str, ...]] = []

    def command(*args: str) -> str:
        if args[0:2] == ("gh", "api"):
            return json.dumps({"workflow_runs": [run]})
        if args[0:3] == ("gh", "run", "download"):
            target = Path(args[-1]) / "passport-python-deletion-cutover-789.json"
            target.write_text(json.dumps(final_cutover_report()), encoding="utf-8")
        if args[0:3] == ("gh", "attestation", "verify"):
            attested.append(args)
        return ""

    from datetime import datetime

    monkeypatch.setattr(gate, "_command", command)
    monkeypatch.setattr(gate, "_verified_run", lambda *args: (
        datetime(2026, 9, 26, 0, 21, tzinfo=UTC),
        datetime(2026, 9, 26, 0, 26, tzinfo=UTC)))
    report, _, _ = gate._final_cutover_report(COMMIT, "e" * 40, tmp_path / "ok")
    assert report["deletion_head"] == "e" * 40
    assert attested and "--signer-workflow" in attested[0]
    with pytest.raises(gate.prior_gate.QualificationError, match="deletion head"):
        gate._final_cutover_report(COMMIT, "9" * 40, tmp_path / "wrong")


def test_post_pr_head_requires_exact_same_repository_pull_request(monkeypatch) -> None:
    pr = {"number": 305, "head": {"sha": "e" * 40,
                                   "repo": {"full_name": "ElevenID/marty-credentials"}},
          "base": {"ref": "main", "repo": {"full_name": "ElevenID/marty-credentials"}}}
    monkeypatch.setattr(gate, "_command", lambda *args: json.dumps(pr))
    assert gate._retirement_pr_head(305) == "e" * 40
    for mutate in (
        lambda row: row["head"].update(sha="9" * 39),
        lambda row: row["head"]["repo"].update(full_name="other/fork"),
        lambda row: row["base"].update(ref="other"),
        lambda row: row.update(number=306),
    ):
        changed = copy.deepcopy(pr)
        mutate(changed)
        monkeypatch.setattr(gate, "_command", lambda *args, value=changed: json.dumps(value))
        with pytest.raises(gate.prior_gate.QualificationError):
            gate._retirement_pr_head(305)


def test_pr_event_requires_exact_live_deletion_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    head = "e" * 40
    repo = {"full_name": "ElevenID/marty-credentials"}
    event = {"number": 305, "repository": repo,
             "pull_request": {"number": 305,
                              "head": {"sha": head, "repo": repo},
                              "base": {"ref": "main", "repo": repo}}}
    live = copy.deepcopy(event["pull_request"])
    path = tmp_path / "pr-event.json"
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))
    monkeypatch.setattr(gate, "_command", lambda *args: json.dumps(live))
    path.write_text(json.dumps(event), encoding="utf-8")
    gate._pull_request_lineage(305, head)
    for mutate in (
        lambda row: row.update(number=306),
        lambda row: row["pull_request"].update(number=306),
        lambda row: row["pull_request"]["head"].update(sha="9" * 40),
        lambda row: row["pull_request"]["head"].update(repo={"full_name": "other/fork"}),
        lambda row: row["pull_request"]["base"].update(ref="other"),
    ):
        changed = copy.deepcopy(event)
        mutate(changed)
        path.write_text(json.dumps(changed), encoding="utf-8")
        with pytest.raises(gate.prior_gate.QualificationError, match="same-repository"):
            gate._pull_request_lineage(305, head)
    path.write_text(json.dumps(event), encoding="utf-8")
    live["head"]["sha"] = "9" * 40
    with pytest.raises(gate.prior_gate.QualificationError, match="stale"):
        gate._pull_request_lineage(305, head)


def test_post_pr_lineage_requires_queue_or_merged_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    head = "e" * 40
    queued = "a" * 40
    running = "b" * 40
    event_path = tmp_path / "event.json"
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("GITHUB_SHA", running)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "merge_group")
    group_event = {"repository": {"full_name": "ElevenID/marty-credentials"},
                   "merge_group": {"head_sha": running,
                                   "base_ref": "refs/heads/main",
                                   "head_ref": "refs/heads/gh-readonly-queue/main/pr-305-test"}}
    queue = {"data": {"repository": {"pullRequest": {
        "headRefOid": head, "mergeQueueEntry": {
            "headCommit": {"oid": queued},
            "pullRequest": {"number": 305, "headRefOid": head},
        },
    }}}}
    comparison = {"status": "ahead"}

    def command(*args: str) -> str:
        if args[0] == "git":
            return running
        if "graphql" in args:
            query = args[-1].removeprefix("query=")
            assert query.count("{") == query.count("}")
            return json.dumps(queue)
        if "/compare/" in args[-1]:
            return json.dumps(comparison)
        return json.dumps({"number": 305, "merged": True,
                           "head": {"sha": head}, "merge_commit_sha": queued})

    monkeypatch.setattr(gate, "_command", command)
    event_path.write_text(json.dumps(group_event), encoding="utf-8")
    gate._post_pr_lineage(305, head)
    comparison["status"] = "diverged"
    with pytest.raises(gate.prior_gate.QualificationError, match="does not contain"):
        gate._post_pr_lineage(305, head)
    comparison["status"] = "ahead"
    monkeypatch.setattr(gate, "_command", lambda *args: "9" * 40 if args[0] == "git" else command(*args))
    with pytest.raises(gate.prior_gate.QualificationError, match="Running checkout differs"):
        gate._post_pr_lineage(305, head)
    monkeypatch.setattr(gate, "_command", command)
    queue["data"]["repository"]["pullRequest"]["mergeQueueEntry"]["pullRequest"]["headRefOid"] = "9" * 40
    with pytest.raises(gate.prior_gate.QualificationError, match="exact deletion PR head"):
        gate._post_pr_lineage(305, head)
    queue["data"]["repository"]["pullRequest"]["mergeQueueEntry"]["pullRequest"]["headRefOid"] = head
    group_event["merge_group"]["head_sha"] = "9" * 40
    event_path.write_text(json.dumps(group_event), encoding="utf-8")
    with pytest.raises(gate.prior_gate.QualificationError, match="main queue commit"):
        gate._post_pr_lineage(305, head)

    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    event_path.write_text(json.dumps({"repository": group_event["repository"],
                                      "ref": "refs/heads/main", "after": running}), encoding="utf-8")
    gate._post_pr_lineage(305, head)
    comparison["status"] = "diverged"
    with pytest.raises(gate.prior_gate.QualificationError, match="does not contain"):
        gate._post_pr_lineage(305, head)


def test_post_pr_gate_requires_successful_pr_checks_after_cutover(monkeypatch) -> None:
    from datetime import UTC, datetime

    cutover_completed = datetime(2026, 9, 26, 0, 26, tzinfo=UTC)
    run = {"id": 999, "run_attempt": 2, "check_suite_id": 888,
           "event": "pull_request", "head_sha": "e" * 40,
           "head_branch": "chore/retire-python-passport-after-beta-v1",
           "path": ".github/workflows/ci.yml", "status": "completed",
           "conclusion": "success", "created_at": "2026-09-26T00:20:00Z",
           "pull_requests": [{"number": 305}]}
    jobs = {"jobs": [{"name": name, "run_id": 999, "head_sha": "e" * 40,
                      "started_at": "2026-09-26T00:27:00Z",
                      "status": "completed", "conclusion": "success"}
                      for name in ("Passport Python Retirement Provenance", "CI Gate")]}
    suite = {"head_sha": "e" * 40, "app": {"slug": "github-actions"}}

    def install(candidate: dict, job_rows: dict) -> None:
        def command(*args: str) -> str:
            if "/jobs" in args[-1]:
                assert "/attempts/2/jobs" in args[-1]
                return json.dumps(job_rows)
            if "/check-suites/" in args[-1]:
                return json.dumps(suite)
            return json.dumps({"workflow_runs": [candidate]})

        monkeypatch.setattr(gate, "_command", command)

    install(run, jobs)
    gate._successful_pr_gate(305, "e" * 40, cutover_completed)
    assert run["created_at"] < "2026-09-26T00:26:00Z"
    for field, bad in (("head_sha", "9" * 40), ("conclusion", "failure"),
                       ("run_attempt", 0),
                       ("pull_requests", [{"number": 306}])):
        changed = copy.deepcopy(run)
        changed[field] = bad
        install(changed, jobs)
        with pytest.raises(gate.prior_gate.QualificationError, match="lacks a successful"):
            gate._successful_pr_gate(305, "e" * 40, cutover_completed)
    changed_jobs = copy.deepcopy(jobs)
    changed_jobs["jobs"][0]["conclusion"] = "failure"
    install(run, changed_jobs)
    with pytest.raises(gate.prior_gate.QualificationError, match="lacks a successful"):
        gate._successful_pr_gate(305, "e" * 40, cutover_completed)
    changed_jobs = copy.deepcopy(jobs)
    changed_jobs["jobs"][0]["started_at"] = "2026-09-26T00:25:00Z"
    install(run, changed_jobs)
    with pytest.raises(gate.prior_gate.QualificationError, match="lacks a successful"):
        gate._successful_pr_gate(305, "e" * 40, cutover_completed)
    install(run, jobs)
    suite["app"]["slug"] = "other-app"
    with pytest.raises(gate.prior_gate.QualificationError, match="lacks a successful"):
        gate._successful_pr_gate(305, "e" * 40, cutover_completed)
    suite["app"]["slug"] = "github-actions"
    suite["head_sha"] = "9" * 40
    with pytest.raises(gate.prior_gate.QualificationError, match="lacks a successful"):
        gate._successful_pr_gate(305, "e" * 40, cutover_completed)


def test_qualified_path_requires_complete_provenance_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = qualified_record()
    predeletion = predeletion_report()
    uri = "ghcr.io/elevenid/marty-ui-oss/services"
    digest = IMAGE_DIGESTS[uri]
    for image in predeletion["runtime_images"].values():
        image.update(oci_reference=f"{uri}@{digest}", oci_digest=digest)
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
    from datetime import datetime

    def verified_run(run_id, *args):
        if run_id == 123:
            return (datetime(2026, 9, 26, 0, 11, tzinfo=UTC),
                    datetime(2026, 9, 26, 0, 16, tzinfo=UTC))
        return (datetime(2026, 9, 26, 0, 0, tzinfo=UTC),
                datetime(2026, 9, 26, 0, 10, tzinfo=UTC))

    monkeypatch.setattr(gate, "_verified_run", verified_run)
    monkeypatch.setattr(gate, "_frozen_batch_parity", lambda *args: None)
    monkeypatch.setattr(gate.prior_gate, "_git_head", lambda *args: "e" * 40)
    monkeypatch.setattr(gate, "_final_cutover_report", lambda *args: (
        final_cutover_report(),
        datetime(2026, 9, 26, 0, 21, tzinfo=UTC),
        datetime(2026, 9, 26, 0, 26, tzinfo=UTC),
    ))
    monkeypatch.setattr(gate, "_retirement_pr_head", lambda number: "e" * 40)
    def pr_lineage(*args):
        gate.prior_gate._require(
            os.environ.get("GITHUB_EVENT_NAME") == "pull_request",
            "Exact deletion head needs a pull-request event",
        )

    monkeypatch.setattr(gate, "_pull_request_lineage", pr_lineage)
    lineage_calls: list[tuple] = []
    monkeypatch.setattr(gate, "_post_pr_lineage", lambda *args: lineage_calls.append(args))
    pr_gate_calls: list[tuple] = []
    monkeypatch.setattr(gate, "_successful_pr_gate", lambda *args: pr_gate_calls.append(args))
    monkeypatch.setattr(
        gate, "_run_artifact",
        lambda run_id, *args: predeletion if run_id == 123 else supported,
    )

    def check(candidate: dict, expected: str) -> None:
        path = tmp_path / "candidate.json"
        path.write_text(json.dumps(candidate), encoding="utf-8")
        with pytest.raises(gate.prior_gate.QualificationError, match=expected):
            gate.verify(path, tmp_path, deletion_head="e" * 40)

    path = tmp_path / "qualified.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    gate.verify(path, tmp_path, deletion_head="e" * 40)
    with pytest.raises(gate.prior_gate.QualificationError, match="Exact pull-request deletion head"):
        gate.verify(path, tmp_path)
    with pytest.raises(gate.prior_gate.QualificationError, match="exact deletion head"):
        gate.verify(path, tmp_path, deletion_head="9" * 40)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "merge_group")
    gate.verify(path, tmp_path, post_pr_check=True)
    assert pr_gate_calls and pr_gate_calls[-1][0:2] == (305, "e" * 40)
    assert lineage_calls == [(305, "e" * 40)]
    monkeypatch.setattr(gate, "_retirement_pr_head", lambda number: "9" * 40)
    with pytest.raises(gate.prior_gate.QualificationError, match="exact deletion head"):
        gate.verify(path, tmp_path, post_pr_check=True)
    monkeypatch.setattr(gate, "_retirement_pr_head", lambda number: "e" * 40)
    with pytest.raises(gate.prior_gate.QualificationError, match="Exact deletion head"):
        gate.verify(path, tmp_path, deletion_head="e" * 40)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    with pytest.raises(gate.prior_gate.QualificationError, match="only valid"):
        gate.verify(path, tmp_path, post_pr_check=True)
    monkeypatch.delenv("GITHUB_EVENT_NAME")
    changed = copy.deepcopy(record)
    changed["predeletion_acceptance_receipt"]["release_source_commit"] = "9" * 40
    check(changed, "Predeletion release source")
    changed = copy.deepcopy(record)
    changed["supported_consumer_cutover_receipt"]["protected_main_commit"] = "9" * 40
    check(changed, "Supported consumer source")
    predeletion["release"]["oci_digests"] = {"wrong": "sha256:" + "9" * 64}
    check(record, "image digests")
    predeletion["release"]["oci_digests"] = IMAGE_DIGESTS
    predeletion["runtime_images"]["gateway"]["oci_reference"] = (
        "ghcr.io/elevenid/marty-ui-oss/ui@"
        + IMAGE_DIGESTS["ghcr.io/elevenid/marty-ui-oss/ui"]
    )
    check(record, "Disposable runtime image differs")
    predeletion["runtime_images"]["gateway"]["oci_reference"] = SERVICES_REFERENCE
    supported["surfaces"].pop("kubernetes")
    check(record, "surfaces are incomplete")
    supported["surfaces"]["kubernetes"] = supported_surface("kubernetes")
    supported["legacy_source_binding"]["database_uid"] = "fresh-disposable-db"
    check(record, "not bound to the supported consumer")
    supported["legacy_source_binding"]["database_uid"] = "beta-legacy-db-uid"
    supported["accepted_at_utc"] = "2026-09-26T00:13:00Z"
    check(record, "Beta-source drain predates")
    supported["accepted_at_utc"] = "2026-09-26T00:09:00Z"
    predeletion["runtime_images"]["gateway"]["container_id"] = "different-gateway"
    check(record, "not bound to the supported consumer")
    predeletion["runtime_images"]["gateway"]["container_id"] = "gateway-base-after"
    predeletion["deployment"]["owner_uid"] = "different-owner"
    predeletion["deployment"]["owner_labels"]["owner_uid"] = "different-owner"
    for runtime in predeletion["runtime_images"].values():
        runtime["owner_uid"] = "different-owner"
        runtime["owner_labels"]["owner_uid"] = "different-owner"
    for probe in predeletion["probes"].values():
        probe["evidence"]["owner_uid"] = "different-owner"
        probe["evidence"]["owner_labels"]["owner_uid"] = "different-owner"
    check(record, "not bound to the supported consumer")


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
    assert jobs["passport-retirement-provenance"]["env"]["PASSPORT_DELETION_PR_HEAD"] == (
        "${{ github.event.pull_request.head.sha }}"
    )
    pin = next(step for step in steps if step.get("name") == "Pin qualified passport source commit")
    assert "--print-checkout-commit" in pin["run"]
    assert 'git -C ../marty-ui merge-base --is-ancestor "$source_commit" refs/remotes/origin/main' in pin["run"]
    assert 'git -C ../marty-ui checkout --detach "$source_commit"' in pin["run"]
    assert any(step.get("with", {}).get("toolchain") == "1.95.0" for step in steps)
    gate_step = next(step for step in steps if step.get("name")
                     == "Refuse Python deletion until passport acceptance is verifiable")
    assert '--deletion-head "$PASSPORT_DELETION_PR_HEAD"' in gate_step["run"]
    assert "--post-pr-check" in gate_step["run"]
