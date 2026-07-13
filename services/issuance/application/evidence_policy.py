"""Policy evaluation for normalized application evidence facts."""

from __future__ import annotations

import logging
import json
from dataclasses import dataclass, field
from typing import Any

from issuance.domain.entities import (
    Application,
    ApplicationTemplate,
    ApprovalPolicySet,
    EvidenceFact,
)

logger = logging.getLogger(__name__)
_APPROVAL_POLICY_TYPES = {"APPROVAL_RULES", "CUSTOM"}
_ACTIVE_POLICY_STATUSES = {"ACTIVE"}


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


def _requirement_type(requirement: Any) -> str:
    if isinstance(requirement, str):
        return requirement
    if isinstance(requirement, dict):
        for key in ("fact_type", "evidence_type", "type"):
            value = requirement.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def _requirement_scope(requirement: Any) -> dict[str, Any]:
    if not isinstance(requirement, dict):
        return {}
    scope = requirement.get("scope") or requirement.get("canvas_scope") or {}
    return scope if isinstance(scope, dict) else {}


def _requirement_provider(requirement: Any) -> str:
    if not isinstance(requirement, dict):
        return ""
    provider = requirement.get("provider")
    return provider if isinstance(provider, str) else ""


def _requirement_verification_method(requirement: Any) -> str:
    if not isinstance(requirement, dict):
        return ""
    method = requirement.get("verification_method")
    return method if isinstance(method, str) else ""


def _fact_verified(fact: EvidenceFact) -> bool:
    return str((fact.verification or {}).get("status") or "").upper() == "VERIFIED"


def _normalize_policy_value(value: str | None) -> str:
    return str(value or "").strip().upper()


def _enabled_cedar_policy_text(policy: dict[str, Any]) -> str:
    if policy.get("enabled") is False:
        return ""
    cedar_text = policy.get("cedar_text")
    return cedar_text.strip() if isinstance(cedar_text, str) else ""


def _normalize_cedar_policy_text(raw_policies: Any) -> str:
    if isinstance(raw_policies, str):
        stripped = raw_policies.strip()
        if not stripped:
            return ""
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return stripped
        return _normalize_cedar_policy_text(parsed)
    if isinstance(raw_policies, list):
        parts = [
            _enabled_cedar_policy_text(policy)
            for policy in raw_policies
            if isinstance(policy, dict)
        ]
        return "\n\n".join(part for part in parts if part)
    if isinstance(raw_policies, dict):
        if "cedar_policies" in raw_policies:
            return _normalize_cedar_policy_text(raw_policies.get("cedar_policies"))
        return _enabled_cedar_policy_text(raw_policies)
    return ""


def _numeric_value(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _comparison_satisfied(actual: Any, rule: Any) -> bool:
    actual_number = _numeric_value(actual)
    if actual_number is None:
        return False
    if isinstance(rule, dict):
        saw_operator = False
        comparisons = {
            ">=": lambda lhs, rhs: lhs >= rhs,
            "min": lambda lhs, rhs: lhs >= rhs,
            ">": lambda lhs, rhs: lhs > rhs,
            "<=": lambda lhs, rhs: lhs <= rhs,
            "max": lambda lhs, rhs: lhs <= rhs,
            "<": lambda lhs, rhs: lhs < rhs,
            "==": lambda lhs, rhs: lhs == rhs,
            "equals": lambda lhs, rhs: lhs == rhs,
        }
        for operator, compare in comparisons.items():
            if operator not in rule:
                continue
            saw_operator = True
            expected_number = _numeric_value(rule.get(operator))
            if expected_number is None or not compare(actual_number, expected_number):
                return False
        return saw_operator
    expected_number = _numeric_value(rule)
    return expected_number is not None and actual_number >= expected_number


def _string_rule_satisfied(actual: Any, expected: Any) -> bool:
    if isinstance(expected, list):
        return any(_string_rule_satisfied(actual, item) for item in expected)
    if isinstance(actual, list):
        return any(str(item).lower() == str(expected).lower() for item in actual)
    return str(actual or "").lower() == str(expected).lower()


def _path_value(root: Any, path: str) -> Any:
    path = str(path or "").strip()
    if not path:
        return None
    if path.startswith("$."):
        path = path[2:]
    elif path.startswith("$"):
        path = path[1:].lstrip(".")
    current = root
    for part in [segment for segment in path.split(".") if segment]:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (TypeError, ValueError, IndexError):
                return None
        else:
            return None
    return current


def _fact_rule_root(fact: EvidenceFact) -> dict[str, Any]:
    return {
        "assertion": fact.assertion or {},
        "scope": fact.scope or {},
        "verification": fact.verification or {},
        "source": fact.source or {},
        "provider": fact.provider,
        "fact_type": fact.fact_type,
        "subject_id": fact.subject_id,
    }


def _fact_path_value(fact: EvidenceFact, path: str) -> Any:
    normalized = str(path or "").strip()
    if normalized.startswith(("assertion.", "scope.", "verification.", "source.", "$.")):
        return _path_value(_fact_rule_root(fact), normalized)
    return _path_value(fact.assertion or {}, normalized)


def _path_condition_satisfied(fact: EvidenceFact, condition: Any) -> bool:
    if not isinstance(condition, dict):
        return bool(condition)
    if "all" in condition:
        items = condition.get("all")
        return isinstance(items, list) and all(_path_condition_satisfied(fact, item) for item in items)
    if "any" in condition:
        items = condition.get("any")
        return isinstance(items, list) and any(_path_condition_satisfied(fact, item) for item in items)
    if "not" in condition:
        return not _path_condition_satisfied(fact, condition.get("not"))

    path = condition.get("path")
    if not isinstance(path, str) or not path:
        return False
    actual = _fact_path_value(fact, path)
    operator = str(condition.get("op") or condition.get("operator") or "").lower()
    expected = condition.get("value")
    if not operator:
        operator = "eq" if "value" in condition else "exists"

    if operator in {"exists", "present"}:
        return actual is not None
    if operator in {"truthy", "true"}:
        return bool(actual)
    if operator in {"falsy", "false"}:
        return not bool(actual)
    if operator in {"eq", "equals", "=="}:
        return actual == expected
    if operator in {"neq", "not_equals", "!="}:
        return actual != expected
    if operator in {">=", "gt_eq", "gte", "min"}:
        actual_number = _numeric_value(actual)
        expected_number = _numeric_value(expected)
        return actual_number is not None and expected_number is not None and actual_number >= expected_number
    if operator in {">", "gt"}:
        actual_number = _numeric_value(actual)
        expected_number = _numeric_value(expected)
        return actual_number is not None and expected_number is not None and actual_number > expected_number
    if operator in {"<=", "lt_eq", "lte", "max"}:
        actual_number = _numeric_value(actual)
        expected_number = _numeric_value(expected)
        return actual_number is not None and expected_number is not None and actual_number <= expected_number
    if operator in {"<", "lt"}:
        actual_number = _numeric_value(actual)
        expected_number = _numeric_value(expected)
        return actual_number is not None and expected_number is not None and actual_number < expected_number
    if operator == "in":
        return isinstance(expected, list) and actual in expected
    if operator == "contains":
        if isinstance(actual, list):
            return expected in actual
        if isinstance(actual, str):
            return str(expected) in actual
        return False
    return False


def _pass_rule_satisfied(fact: EvidenceFact, requirement: Any) -> bool:
    if not isinstance(requirement, dict):
        return True
    pass_rule = requirement.get("pass_rule")
    if not isinstance(pass_rule, dict) or not pass_rule:
        return True
    if any(key in pass_rule for key in ("all", "any", "not", "path")):
        return _path_condition_satisfied(fact, pass_rule)
    assertion = fact.assertion or {}
    evaluated_rule = False
    bool_keys = ("completed", "submitted", "passed", "eligible")
    for key in bool_keys:
        if key in pass_rule:
            evaluated_rule = True
            if bool(assertion.get(key)) != bool(pass_rule.get(key)):
                return False
    numeric_keys = {
        "score": ("score", "min_score"),
        "score_percent": ("score_percent", "min_score_percent"),
    }
    for assertion_key, aliases in numeric_keys.items():
        for rule_key in aliases:
            if rule_key in pass_rule:
                evaluated_rule = True
                if not _comparison_satisfied(assertion.get(assertion_key), pass_rule.get(rule_key)):
                    return False
    string_keys = {
        "membership_status": ("membership_status", "status"),
        "roles": ("roles_include", "role", "role_includes"),
    }
    for assertion_key, aliases in string_keys.items():
        for rule_key in aliases:
            if rule_key in pass_rule:
                evaluated_rule = True
                if not _string_rule_satisfied(assertion.get(assertion_key), pass_rule.get(rule_key)):
                    return False
    return evaluated_rule


def _fact_satisfies_requirement(fact: EvidenceFact, requirement: Any) -> bool:
    requirement_provider = _requirement_provider(requirement)
    if requirement_provider and fact.provider != requirement_provider:
        return False
    requirement_type = _requirement_type(requirement)
    if requirement_type and fact.fact_type != requirement_type:
        return False
    requirement_method = _requirement_verification_method(requirement)
    if requirement_method and str((fact.verification or {}).get("method") or "") != requirement_method:
        return False
    requirement_scope = _requirement_scope(requirement)
    for key, expected in requirement_scope.items():
        if expected is None:
            continue
        if str(fact.scope.get(key) or "") != str(expected):
            return False
    return _fact_verified(fact) and _pass_rule_satisfied(fact, requirement)


def _summarize_requirements(
    *,
    requirements: list[Any],
    facts: list[EvidenceFact],
) -> tuple[int, int, bool, bool]:
    required_requirements = [
        requirement
        for requirement in requirements
        if not (isinstance(requirement, dict) and requirement.get("required") is False)
    ]
    if required_requirements:
        effective_requirements = required_requirements
    elif requirements:
        return 0, 0, False, True
    else:
        effective_requirements = ["canvas.course_completion"]
    satisfied = 0
    scope_matched = True
    for requirement in effective_requirements:
        requirement_provider = _requirement_provider(requirement)
        requirement_type = _requirement_type(requirement)
        requirement_scope = _requirement_scope(requirement)
        type_matches = [
            fact for fact in facts
            if (
                (not requirement_provider or fact.provider == requirement_provider)
                and (not requirement_type or fact.fact_type == requirement_type)
            )
        ]
        if requirement_scope and not any(
            all(str(fact.scope.get(key) or "") == str(value) for key, value in requirement_scope.items())
            for fact in type_matches
        ):
            scope_matched = False
        if any(_fact_satisfies_requirement(fact, requirement) for fact in facts):
            satisfied += 1
    required_count = len(effective_requirements)
    return required_count, satisfied, satisfied >= required_count, scope_matched


def _build_context(
    *,
    app: Application,
    binding: Any | None,
    requirements: list[Any],
    facts: list[EvidenceFact],
) -> dict[str, Any]:
    latest = facts[-1] if facts else None
    required_count, satisfied_count, all_satisfied, scope_matched = _summarize_requirements(
        requirements=requirements,
        facts=facts,
    )
    verified_count = sum(1 for fact in facts if _fact_verified(fact))
    provider = latest.provider if latest else "canvas"
    requirement_auto_issue = any(
        isinstance(requirement, dict)
        and bool(requirement.get("auto_issue_on_permit"))
        for requirement in requirements
    )
    return {
        "risk_score": 0,
        "document_verification_passed": True,
        "biometric_match_score": 100,
        "evidence_count": len(facts),
        "applicant_country": "US",
        "evidence_provider": provider,
        "evidence_fact_type": latest.fact_type if latest else "",
        "evidence_verification_status": (
            str((latest.verification or {}).get("status") or "UNVERIFIED").upper()
            if latest else "UNVERIFIED"
        ),
        "evidence_scope_matched": bool(scope_matched),
        "verified_evidence_count": verified_count,
        "required_evidence_count": required_count,
        "satisfied_requirement_count": satisfied_count,
        "all_required_evidence_satisfied": bool(all_satisfied),
        "auto_issue_eligible": bool(
            all_satisfied
            and (
                requirement_auto_issue
                or bool(binding and getattr(binding, "auto_approve_on_evidence", False))
            )
        ),
    }


def _build_entities(app: Application, facts: list[EvidenceFact]) -> list[dict[str, Any]]:
    org_id = app.organization_id
    app_uid = {"type": "MIP::Application", "id": app.id}
    entities: list[dict[str, Any]] = [
        {
            "uid": {"type": "MIP::ServiceAccount", "id": "canvas-evidence-policy"},
            "attrs": {"service_name": "canvas-evidence-policy"},
            "parents": [{"type": "MIP::Organization", "id": org_id}],
        },
        {
            "uid": {"type": "MIP::Organization", "id": org_id},
            "attrs": {},
            "parents": [],
        },
        {
            "uid": app_uid,
            "attrs": {"risk_score": 0, "status": app.status.value},
            "parents": [{"type": "MIP::Organization", "id": org_id}],
        },
    ]
    for fact in facts:
        entities.append(
            {
                "uid": {"type": "MIP::EvidenceFact", "id": fact.id},
                "attrs": {
                    "provider": fact.provider,
                    "fact_type": fact.fact_type,
                    "subject_id": fact.subject_id,
                    "verification_status": str((fact.verification or {}).get("status") or ""),
                },
                "parents": [
                    app_uid,
                    {"type": "MIP::Organization", "id": org_id},
                ],
            }
        )
    return entities


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
    """Evaluate whether normalized facts permit application approval."""

    context = _build_context(
        app=app,
        binding=binding,
        requirements=requirements,
        facts=facts,
    )
    policy_set_id = (
        getattr(binding, "approval_policy_set_id", None)
        or (getattr(template, "approval_policy_set_id", None) if template else None)
    )
    policy_source = "policy_set" if policy_set_id else "bundled"
    if cedar_engine is None:
        try:
            from marty_common import CedarEngine

            if policy_set_id:
                if policy_set is None:
                    return EvidencePolicyDecision(
                        allowed=False,
                        engine="policy_set_unavailable",
                        policy_source=policy_source,
                        policy_set_id=policy_set_id,
                        errors=[f"Approval PolicySet {policy_set_id} was not found for organization {app.organization_id}"],
                        context=context,
                    )
                status = _normalize_policy_value(policy_set.status)
                if status not in _ACTIVE_POLICY_STATUSES:
                    return EvidencePolicyDecision(
                        allowed=False,
                        engine="policy_set_inactive",
                        policy_source=policy_source,
                        policy_set_id=policy_set_id,
                        errors=[f"Approval PolicySet {policy_set_id} is not active"],
                        context=context,
                    )
                policy_type = _normalize_policy_value(policy_set.policy_type)
                if policy_type not in _APPROVAL_POLICY_TYPES:
                    return EvidencePolicyDecision(
                        allowed=False,
                        engine="policy_set_wrong_type",
                        policy_source=policy_source,
                        policy_set_id=policy_set_id,
                        errors=[f"PolicySet {policy_set_id} has unsupported approval policy_type {policy_set.policy_type!r}"],
                        context=context,
                    )
                policy_text = _normalize_cedar_policy_text(policy_set.cedar_policies)
                if not policy_text:
                    return EvidencePolicyDecision(
                        allowed=False,
                        engine="policy_set_empty",
                        policy_source=policy_source,
                        policy_set_id=policy_set_id,
                        errors=[f"Approval PolicySet {policy_set_id} has no enabled Cedar policies"],
                        context=context,
                    )
                cedar_engine = CedarEngine.with_approval_policy_text(policy_text)
            else:
                cedar_engine = CedarEngine.with_approval_rules()
        except Exception as exc:
            logger.warning("Cedar approval engine unavailable; denying approval: %s", exc)
            return EvidencePolicyDecision(
                allowed=False,
                engine="cedar_unavailable",
                policy_source=policy_source,
                policy_set_id=policy_set_id,
                errors=[str(exc)],
                context=context,
            )

    decision = cedar_engine.is_authorized(
        principal='MIP::ServiceAccount::"canvas-evidence-policy"',
        action='MIP::Action::"applications:approve"',
        resource=f'MIP::Application::"{app.id}"',
        context=context,
        entities=_build_entities(app, facts),
    )
    return EvidencePolicyDecision(
        allowed=bool(getattr(decision, "allowed", False)),
        engine="cedar",
        policy_source=policy_source,
        policy_set_id=policy_set_id,
        reasons=list(getattr(decision, "reasons", []) or []),
        errors=list(getattr(decision, "errors", []) or []),
        context=context,
    )
