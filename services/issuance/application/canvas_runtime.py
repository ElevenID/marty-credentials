"""Runtime helpers for resolving Canvas platform/program bindings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from issuance.domain.entities import (
    CanvasPlatform,
    CanvasProgramBinding,
)
from issuance.domain.ports import IIssuanceRepository

CANVAS_FEATURE_FLAG_KEYS = {
    "enable_canvas_evidence",
    "enable_canvas_lti",
    "enable_canvas_mirror_publish",
    "enable_canvas_mirror_ops",
    "enable_canvas_deep_linking",
    "enable_canvas_ags",
    "enable_canvas_nrps",
}

_SCOPE_ALIASES = {
    "canvas_account_id": ("canvas_account_id", "account_id"),
    "account_id": ("canvas_account_id", "account_id"),
    "course_id": ("course_id", "canvas_course_id", "canvas_context_id", "context_id"),
    "canvas_course_id": ("course_id", "canvas_course_id", "canvas_context_id", "context_id"),
    "canvas_context_id": ("course_id", "canvas_course_id", "canvas_context_id", "context_id"),
    "context_id": ("course_id", "canvas_course_id", "canvas_context_id", "context_id"),
    "assignment_id": ("assignment_id", "canvas_assignment_id", "resource_link_id"),
    "canvas_assignment_id": ("assignment_id", "canvas_assignment_id", "resource_link_id"),
    "module_id": ("module_id", "canvas_module_id"),
    "canvas_module_id": ("module_id", "canvas_module_id"),
    "quiz_id": ("quiz_id", "canvas_quiz_id"),
    "canvas_quiz_id": ("quiz_id", "canvas_quiz_id"),
    "user_id": ("user_id", "canvas_user_id", "subject_id"),
    "canvas_user_id": ("user_id", "canvas_user_id", "subject_id"),
    "subject_id": ("user_id", "canvas_user_id", "subject_id"),
    "enrollment_id": ("enrollment_id", "canvas_enrollment_id"),
    "canvas_enrollment_id": ("enrollment_id", "canvas_enrollment_id"),
}


@dataclass(frozen=True)
class CanvasRuntimeConfig:
    """Program-binding runtime view used by policy and evidence code."""

    id: str
    organization_id: str
    canvas_account_id: str
    credential_template_id: str
    application_template_id: str | None = None
    flow_mode: str = "elevenid_orchestrated_canvas_evidence"
    direct_issue_enabled: bool = False
    auto_approve_on_evidence: bool = False
    evidence_requirements: list[Any] | None = None
    delivery_mode: str = "wallet_only"
    approval_policy_set_id: str | None = None
    platform_id: str | None = None
    program_binding_id: str | None = None
    deployment_profile_id: str | None = None
    feature_flags: dict[str, bool] | None = None
    runtime_source: str = "program_binding"


def canvas_runtime_from_program_binding(
    *,
    platform: CanvasPlatform,
    binding: CanvasProgramBinding,
) -> CanvasRuntimeConfig:
    return CanvasRuntimeConfig(
        id=binding.id,
        organization_id=binding.organization_id,
        canvas_account_id=platform.canvas_account_id,
        credential_template_id=binding.credential_template_id,
        application_template_id=binding.application_template_id,
        flow_mode=binding.flow_mode,
        direct_issue_enabled=binding.direct_issue_enabled,
        auto_approve_on_evidence=binding.auto_approve_on_evidence,
        evidence_requirements=list(binding.evidence_requirements or []),
        delivery_mode=binding.delivery_mode or "wallet_only",
        approval_policy_set_id=binding.approval_policy_set_id,
        platform_id=platform.id,
        program_binding_id=binding.id,
        deployment_profile_id=binding.deployment_profile_id,
        feature_flags=dict(binding.feature_flags or {}),
        runtime_source="program_binding",
    )


def normalize_canvas_feature_flags(flags: dict[str, Any] | None) -> dict[str, bool]:
    """Return only Canvas gates, normalized to booleans."""

    if not isinstance(flags, dict):
        return {}
    return {key: bool(flags.get(key, False)) for key in CANVAS_FEATURE_FLAG_KEYS if key in flags}


def canvas_feature_enabled(config: CanvasRuntimeConfig | CanvasProgramBinding, flag: str) -> bool:
    """Evaluate a Canvas feature gate.

    Empty feature snapshots mean the binding is not deployment-profile gated.
    Once a binding has any Canvas flags, missing flags are treated as disabled so
    a deployment profile can be explicit.
    """

    flags = normalize_canvas_feature_flags(getattr(config, "feature_flags", None))
    if not flags:
        return True
    return bool(flags.get(flag, False))


def _scope_value(scope: dict[str, Any], key: str) -> Any:
    aliases = _SCOPE_ALIASES.get(key, (key,))
    for alias in aliases:
        value = scope.get(alias)
        if value is not None and value != "":
            return value
    return None


def canvas_scope_matches(expected_scope: dict[str, Any] | None, actual_scope: dict[str, Any]) -> bool:
    """Return true when a binding scope is empty or fully matched by actual Canvas context."""

    expected = expected_scope or {}
    for key, expected_value in expected.items():
        if expected_value is None or expected_value == "":
            continue
        actual_value = _scope_value(actual_scope, str(key))
        if actual_value is None or str(actual_value) != str(expected_value):
            return False
    return True


def lti_verified_launch_to_canvas_scope(
    verified_launch: dict[str, Any],
    *,
    canvas_account_id: str | None = None,
) -> dict[str, Any]:
    """Extract Canvas-ish scope values from a verified LTI launch."""

    context = verified_launch.get("context") if isinstance(verified_launch.get("context"), dict) else {}
    raw_claims = verified_launch.get("raw_claims") if isinstance(verified_launch.get("raw_claims"), dict) else {}
    resource_link = raw_claims.get("https://purl.imsglobal.org/spec/lti/claim/resource_link")
    if not isinstance(resource_link, dict):
        resource_link = raw_claims.get("resource_link") if isinstance(raw_claims.get("resource_link"), dict) else {}

    course_id = context.get("id") or context.get("context_id") or raw_claims.get("context_id")
    resource_link_id = resource_link.get("id") if isinstance(resource_link, dict) else None
    subject = verified_launch.get("subject") or raw_claims.get("sub")
    scope = {
        "canvas_account_id": canvas_account_id,
        "course_id": course_id,
        "canvas_course_id": course_id,
        "canvas_context_id": course_id,
        "context_id": course_id,
        "resource_link_id": resource_link_id,
        "subject_id": subject,
        "user_id": subject,
        "canvas_user_id": subject,
    }
    return {key: value for key, value in scope.items() if value is not None}


async def resolve_canvas_program_binding_for_scope(
    *,
    repo: IIssuanceRepository,
    organization_id: str,
    canvas_account_id: str,
    actual_scope: dict[str, Any],
    application_template_id: str | None = None,
) -> tuple[CanvasPlatform | None, CanvasProgramBinding | None]:
    """Resolve the enabled Canvas platform and the first matching program binding."""

    platform = await repo.get_canvas_platform_by_account_id(organization_id, canvas_account_id)
    if platform is None or not platform.enabled:
        return platform, None

    bindings = await repo.list_canvas_program_bindings(
        organization_id,
        platform_id=platform.id,
        application_template_id=application_template_id,
    )
    bindings.sort(key=lambda binding: binding.created_at)
    for binding in bindings:
        if not binding.enabled:
            continue
        if canvas_scope_matches(binding.canvas_scope, actual_scope):
            return platform, binding
    return platform, None
