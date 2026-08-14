"""Thin service-model adapter over canonical Rust evidence policy decisions."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from issuance.domain.entities import (
    Application,
    ApplicationTemplate,
    ApprovalPolicySet,
    CanvasEvidenceRequirement,
    EvidenceFact,
)
from marty_credentials.native_backend import require_marty_rs

_native = require_marty_rs(
    ("current_evidence_heads", "evaluate_application_evidence_policy")
)


@dataclass(frozen=True)
class EvidencePolicyDecision:
    allowed: bool
    engine: str
    policy_source: str = "bundled"
    policy_set_id: str | None = None
    reasons: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "engine": self.engine,
            "policy_source": self.policy_source,
            "policy_set_id": self.policy_set_id,
            "reasons": self.reasons,
            "errors": self.errors,
            "context": self.context,
        }


def _timestamp(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _fact_payload(fact: EvidenceFact) -> dict[str, Any]:
    return {
        "id": fact.id,
        "logical_key": fact.logical_key or fact.id,
        "provider": fact.provider,
        "fact_type": fact.fact_type,
        "subject_id": fact.subject_id,
        "requirement_id": fact.requirement_id or "",
        "scope": fact.scope or {},
        "assertion": fact.assertion or {},
        "verification": fact.verification or {},
        "source": fact.source or {},
        "effective_at": _timestamp(fact.effective_at),
        "observed_at": _timestamp(fact.observed_at),
        "created_at": _timestamp(fact.created_at),
    }


def _requirement_payload(requirement: Any) -> Any:
    if isinstance(requirement, CanvasEvidenceRequirement):
        return requirement.to_dict()
    return requirement


def _compact(value: Any) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def current_evidence_heads(facts: list[EvidenceFact]) -> list[EvidenceFact]:
    """Return the newest revision of every logical key, selected in Rust."""

    result = _native.current_evidence_heads(
        _compact({"facts": [_fact_payload(fact) for fact in facts]})
    )
    ordered_ids = json.loads(result)
    facts_by_id = {fact.id: fact for fact in facts}
    return [facts_by_id[fact_id] for fact_id in ordered_ids]


def evaluate_application_evidence_policy(
    *,
    app: Application,
    template: ApplicationTemplate | None,
    binding: Any | None,
    requirements: list[Any],
    facts: list[EvidenceFact],
    policy_set: ApprovalPolicySet | None = None,
    cedar_engine: Any | None = None,
) -> EvidencePolicyDecision:
    """Evaluate normalized evidence in the authoritative Rust/Cedar kernel.

    ``cedar_engine`` remains in the compatibility signature for older tests and
    callers, but production decisions always use the single native engine.
    """

    _ = cedar_engine
    request = {
        "app": {
            "id": app.id,
            "organization_id": app.organization_id,
            "status": getattr(app.status, "value", str(app.status)),
        },
        "template": (
            {"approval_policy_set_id": template.approval_policy_set_id}
            if template is not None
            else None
        ),
        "binding": (
            {
                "approval_policy_set_id": getattr(
                    binding, "approval_policy_set_id", None
                ),
                "auto_approve_on_evidence": bool(
                    getattr(binding, "auto_approve_on_evidence", False)
                ),
            }
            if binding is not None
            else None
        ),
        "requirements": [
            _requirement_payload(requirement) for requirement in requirements
        ],
        "facts": [_fact_payload(fact) for fact in facts],
        "policy_set": (
            {
                "id": policy_set.id,
                "status": policy_set.status,
                "policy_type": policy_set.policy_type,
                "cedar_policies": policy_set.cedar_policies,
            }
            if policy_set is not None
            else None
        ),
    }
    value = json.loads(_native.evaluate_application_evidence_policy(_compact(request)))
    return EvidencePolicyDecision(
        allowed=bool(value["allowed"]),
        engine=str(value["engine"]),
        policy_source=str(value["policy_source"]),
        policy_set_id=value.get("policy_set_id"),
        reasons=list(value.get("reasons") or []),
        errors=list(value.get("errors") or []),
        context=dict(value.get("context") or {}),
    )
