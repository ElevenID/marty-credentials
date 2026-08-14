"""Adapter facts to canonical Rust-owned verification decisions."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from marty_credentials.native_backend import require_marty_rs

from .governance import (
    VerificationGovernanceContext,
    canonical_digest,
    governance_from_snapshot,
)

CANONICAL_EVIDENCE_SCHEMA_VERSION = 2
CANONICAL_PROCESSING_STATUSES = frozenset({"COMPLETED", "UNSUPPORTED", "UNAVAILABLE", "ERROR"})

_CHECK_DEFINITIONS: dict[str, tuple[str, str, str, str]] = {
    "presentation.structure": (
        "STRUCTURE",
        "presentation_structure_valid",
        "PRESENTATION_STRUCTURE_VALID",
        "PRESENTATION_STRUCTURE_INVALID",
    ),
    "presentation.proof": (
        "PRESENTATION_PROOF",
        "presentation_proof_valid",
        "PRESENTATION_PROOF_VALID",
        "PRESENTATION_PROOF_INVALID",
    ),
    "credential.proof": (
        "CREDENTIAL_PROOF",
        "credential_proofs_valid",
        "CREDENTIAL_PROOFS_VALID",
        "CREDENTIAL_PROOFS_INVALID",
    ),
    "issuer.trust": (
        "ISSUER_TRUST",
        "trust_chain_valid",
        "ISSUER_TRUST_VALID",
        "ISSUER_TRUST_INVALID",
    ),
    "holder.binding": (
        "HOLDER_BINDING",
        "holder_binding_valid",
        "HOLDER_BINDING_VALID",
        "HOLDER_BINDING_INVALID",
    ),
    "transaction.binding": (
        "TRANSACTION_BINDING",
        "transaction_binding_valid",
        "TRANSACTION_BINDING_VALID",
        "TRANSACTION_BINDING_INVALID",
    ),
    "claim.constraints": (
        "CLAIM_CONSTRAINTS",
        "presentation_constraints_valid",
        "CLAIM_CONSTRAINTS_SATISFIED",
        "CLAIM_CONSTRAINTS_FAILED",
    ),
}


def adapter_processing_status(result: dict[str, Any]) -> str:
    """Preserve a trusted adapter's canonical state without allowing ambiguity.

    Older adapters omit ``processing_status`` and therefore retain the
    compatibility default of ``COMPLETED``. An explicit processing error or
    malformed state always becomes ``ERROR`` rather than being collapsed into
    a completed verification decision.
    """
    if result.get("processing_error") is True:
        return "ERROR"
    if "processing_status" not in result:
        return "COMPLETED"
    processing_status = result["processing_status"]
    if isinstance(processing_status, str) and processing_status in CANONICAL_PROCESSING_STATUSES:
        return processing_status
    return "ERROR"


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _input_digest(presentation: dict[str, Any] | str) -> str:
    if isinstance(presentation, str):
        encoded = presentation.encode("utf-8")
    else:
        encoded = json.dumps(
            presentation,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _terminal_check(
    *,
    check_id: str,
    category: str,
    outcome: str,
    code: str,
    component_id: str,
    evaluated_at: str,
    evidence_records: list[dict[str, str]],
) -> dict[str, Any]:
    evidence_refs: list[str] = []
    if outcome in {"PASSED", "FAILED"}:
        evidence_ref = f"urn:marty:evidence:{uuid.uuid4()}"
        evidence_refs.append(evidence_ref)
        evidence_records.append(
            {
                "id": evidence_ref,
                "check_id": check_id,
                "outcome": outcome,
                "code": code,
            }
        )
    return {
        "check_id": check_id,
        "category": category,
        "required": True,
        "outcome": outcome,
        "code": code,
        "component_id": component_id,
        "evaluated_at": evaluated_at,
        "evidence_refs": evidence_refs,
    }


def _status_check(
    result: dict[str, Any],
    *,
    component_id: str,
    evaluated_at: str,
    evidence_records: list[dict[str, str]],
) -> dict[str, Any]:
    checked = result.get("revocation_checked")
    status = str(result.get("revocation_status") or "UNKNOWN").upper()
    if checked is True and status == "VALID":
        outcome, code = "PASSED", "CREDENTIAL_STATUS_VALID"
    elif checked is True and status == "REVOKED":
        outcome, code = "FAILED", "CREDENTIAL_STATUS_REVOKED"
    elif checked is True:
        outcome, code = "ERROR", "CREDENTIAL_STATUS_UNRESOLVED"
    else:
        outcome, code = "NOT_PERFORMED", "CREDENTIAL_STATUS_NOT_CHECKED"
    return _terminal_check(
        check_id="credential.status",
        category="STATUS",
        outcome=outcome,
        code=code,
        component_id=component_id,
        evaluated_at=evaluated_at,
        evidence_records=evidence_records,
    )


def _mapped_check(
    check_id: str,
    result: dict[str, Any],
    *,
    component_id: str,
    evaluated_at: str,
    evidence_records: list[dict[str, str]],
) -> dict[str, Any]:
    if check_id == "credential.status":
        return _status_check(
            result,
            component_id=component_id,
            evaluated_at=evaluated_at,
            evidence_records=evidence_records,
        )
    category, field, passed_code, failed_code = _CHECK_DEFINITIONS[check_id]
    if result.get(field) is True:
        outcome, code = "PASSED", passed_code
    elif result.get(field) is False:
        outcome, code = "FAILED", failed_code
    else:
        outcome = "NOT_PERFORMED"
        code = f"{check_id.replace('.', '_').upper()}_NOT_PERFORMED"
    return _terminal_check(
        check_id=check_id,
        category=category,
        outcome=outcome,
        code=code,
        component_id=component_id,
        evaluated_at=evaluated_at,
        evidence_records=evidence_records,
    )


def build_canonical_result(
    *,
    governance: VerificationGovernanceContext,
    verification_id: str,
    transaction_id: str,
    presentation: dict[str, Any] | str,
    adapter_result: dict[str, Any],
    processing_status: str = "COMPLETED",
) -> dict[str, Any]:
    """Build and validate a claim-free canonical result in Core Rust."""
    evaluated_at = _timestamp()
    evidence_records: list[dict[str, str]] = []
    checks = [
        _mapped_check(
            check_id,
            adapter_result,
            component_id=governance.component.component_id,
            evaluated_at=evaluated_at,
            evidence_records=evidence_records,
        )
        for check_id in governance.policy.required_checks
    ]
    builder_input = {
        "verification_id": verification_id,
        "context": {
            "mode": "ONLINE",
            "verifier_id": governance.policy.verifier_id,
            "organization_id": governance.organization_id,
            "transaction_id": transaction_id,
            "audience": governance.policy.verifier_id,
        },
        "processing_status": processing_status,
        "evaluated_at": evaluated_at,
        "input_digest": _input_digest(presentation),
        "evidence_digest": canonical_digest(evidence_records),
        "policy": governance.policy.reference.as_dict(),
        "trust_profile": governance.trust_profile.reference.as_dict(),
        "components": [governance.component.as_dict()],
        "checks": checks,
    }
    native = require_marty_rs({"verification_build_decision_result"})
    canonical_result = json.loads(
        native.verification_build_decision_result(
            json.dumps(builder_input, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        )
    )
    return {
        "schema_version": CANONICAL_EVIDENCE_SCHEMA_VERSION,
        "governance": governance.snapshot(),
        "canonical_result": canonical_result,
        "evidence_records": evidence_records,
    }


def pending_evidence(governance: VerificationGovernanceContext) -> dict[str, Any]:
    """Persist the exact, secret-free authority selected at session creation."""
    return {
        "schema_version": CANONICAL_EVIDENCE_SCHEMA_VERSION,
        "state": "PENDING",
        "governance": governance.snapshot(),
    }


def canonical_result_from_evidence(evidence: Any) -> dict[str, Any] | None:
    """Return only a Core-reproducible result bound to its frozen governance."""
    if not isinstance(evidence, dict) or set(evidence) != {
        "schema_version",
        "governance",
        "canonical_result",
        "evidence_records",
    }:
        return None
    if evidence.get("schema_version") != CANONICAL_EVIDENCE_SCHEMA_VERSION:
        return None
    result = evidence.get("canonical_result")
    records = evidence.get("evidence_records")
    if not isinstance(result, dict) or not isinstance(records, list):
        return None
    try:
        governance = governance_from_snapshot(evidence.get("governance"))
        if result.get("policy") != governance.policy.reference.as_dict():
            return None
        if result.get("trust_profile") != governance.trust_profile.reference.as_dict():
            return None
        if result.get("components") != [governance.component.as_dict()]:
            return None
        context = result.get("context")
        if not isinstance(context, dict):
            return None
        if context.get("organization_id") != governance.organization_id:
            return None
        if context.get("verifier_id") != governance.policy.verifier_id:
            return None
        checks = result.get("checks")
        if not isinstance(checks, list):
            return None
        if tuple(check.get("check_id") for check in checks if isinstance(check, dict)) != (
            governance.policy.required_checks
        ):
            return None

        records_by_id: dict[str, dict[str, str]] = {}
        for record in records:
            if not isinstance(record, dict) or set(record) != {
                "id",
                "check_id",
                "outcome",
                "code",
            }:
                return None
            if not all(isinstance(value, str) for value in record.values()):
                return None
            record_id = record["id"]
            if record_id in records_by_id:
                return None
            records_by_id[record_id] = record

        referenced: set[str] = set()
        for check in checks:
            if not isinstance(check, dict):
                return None
            refs = check.get("evidence_refs")
            if not isinstance(refs, list) or not all(isinstance(ref, str) for ref in refs):
                return None
            for ref in refs:
                record = records_by_id.get(ref)
                if record is None or any(
                    record[field] != check.get(field) for field in ("check_id", "outcome", "code")
                ):
                    return None
                referenced.add(ref)
        if referenced != set(records_by_id):
            return None
        if result.get("evidence_digest") != canonical_digest(records):
            return None

        derived = {
            "schema_version",
            "decision",
            "decision_code",
            "valid",
            "reducer",
            "category_summaries",
        }
        builder_input = {key: value for key, value in result.items() if key not in derived}
        native = require_marty_rs({"verification_build_decision_result"})
        rebuilt = json.loads(
            native.verification_build_decision_result(
                json.dumps(
                    builder_input,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        )
    except Exception:
        return None
    return rebuilt if rebuilt == result else None
