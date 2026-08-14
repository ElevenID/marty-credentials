"""Thin Python models over canonical Rust verification governance."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from marty_credentials.native_backend import require_marty_rs

GOVERNANCE_ENV = "VERIFICATION_GOVERNANCE_JSON"
CREDENTIALS_COMPONENT_ID = "marty-credentials"
VERIFICATION_ADAPTER_ID = "verification-service"
SESSION_CREATE_PURPOSE = "verification.session.create"
DIRECT_VERIFY_PURPOSE = "verification.direct"
VDS_NC_VERIFY_PURPOSE = "verification.vds-nc"
ALLOWED_PURPOSES = frozenset(
    {SESSION_CREATE_PURPOSE, DIRECT_VERIFY_PURPOSE, VDS_NC_VERIFY_PURPOSE}
)
PURPOSE_REQUIRED_CHECKS = {
    SESSION_CREATE_PURPOSE: frozenset(
        {
            "presentation.structure",
            "presentation.proof",
            "credential.proof",
            "issuer.trust",
            "credential.status",
            "holder.binding",
            "transaction.binding",
            "claim.constraints",
        }
    ),
    DIRECT_VERIFY_PURPOSE: frozenset(
        {
            "presentation.structure",
            "presentation.proof",
            "credential.proof",
            "issuer.trust",
            "credential.status",
            "holder.binding",
            "transaction.binding",
            "claim.constraints",
        }
    ),
    VDS_NC_VERIFY_PURPOSE: frozenset({"credential.proof", "issuer.trust"}),
}
SUPPORTED_CHECKS = frozenset().union(*PURPOSE_REQUIRED_CHECKS.values())

_native = require_marty_rs(
    (
        "governance_authorize",
        "governance_canonical_digest",
        "governance_from_snapshot",
        "governance_require_purpose",
        "governance_resume",
        "governance_validate",
        "governance_validate_request",
    )
)


class GovernanceConfigurationError(RuntimeError):
    """The server-owned verification governance is missing or invalid."""


class GovernanceAuthorizationError(PermissionError):
    """The supplied caller credential is not authorized for the purpose."""


class GovernancePolicyMismatchError(ValueError):
    """A request does not match its caller-bound governed policy."""


def _compact(value: Any) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def canonical_digest(value: Any) -> str:
    """Digest canonical JSON in the authoritative Rust implementation."""

    try:
        return str(_native.governance_canonical_digest(_compact(value)))
    except (TypeError, ValueError) as exc:
        raise GovernanceConfigurationError("value is not canonical JSON") from exc


@dataclass(frozen=True)
class ProfileReference:
    id: str
    version: str
    content_digest: str

    def as_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "version": self.version,
            "content_digest": self.content_digest,
        }


@dataclass(frozen=True)
class ComponentReference:
    component_id: str
    version: str
    artifact_digest: str
    adapter_id: str
    adapter_version: str

    def as_dict(self) -> dict[str, str]:
        return {
            "component_id": self.component_id,
            "version": self.version,
            "artifact_digest": self.artifact_digest,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
        }


@dataclass(frozen=True)
class PolicyProfile:
    organization_id: str
    reference: ProfileReference
    verifier_id: str
    presentation_definition_digest: str
    required_checks: tuple[str, ...]


@dataclass(frozen=True)
class TrustProfile:
    organization_id: str
    reference: ProfileReference
    trusted_issuers: tuple[str, ...]
    allow_public_did_fallback: bool


@dataclass(frozen=True)
class VerificationGovernanceContext:
    client_id: str
    purpose: str
    organization_id: str
    policy: PolicyProfile
    trust_profile: TrustProfile
    component: ComponentReference

    def snapshot(self) -> dict[str, Any]:
        return {
            "client_id": self.client_id,
            "purpose": self.purpose,
            "organization_id": self.organization_id,
            "policy": {
                **self.policy.reference.as_dict(),
                "content": {
                    "verifier_id": self.policy.verifier_id,
                    "presentation_definition_digest": self.policy.presentation_definition_digest,
                    "required_checks": list(self.policy.required_checks),
                },
            },
            "trust_profile": {
                **self.trust_profile.reference.as_dict(),
                "content": {
                    "trusted_issuers": list(self.trust_profile.trusted_issuers),
                    "allow_public_did_fallback": self.trust_profile.allow_public_did_fallback,
                },
            },
            "component": self.component.as_dict(),
        }

    def require_purpose(self, purpose: str) -> None:
        try:
            _native.governance_require_purpose(
                _compact({"snapshot": self.snapshot(), "purpose": purpose})
            )
        except (TypeError, ValueError) as exc:
            raise GovernancePolicyMismatchError(str(exc)) from exc

    def validate_request(
        self,
        *,
        verifier_id: str,
        presentation_definition: dict[str, Any],
    ) -> None:
        try:
            _native.governance_validate_request(
                _compact(
                    {
                        "snapshot": self.snapshot(),
                        "verifier_id": verifier_id,
                        "presentation_definition": presentation_definition,
                    }
                )
            )
        except (TypeError, ValueError) as exc:
            message = str(exc)
            if "JSON compliant" in message:
                message = "presentation_definition is not canonical JSON"
            raise GovernancePolicyMismatchError(message) from exc


class GovernanceRegistry:
    """Validated native registry with Python response-model adaptation only."""

    def __init__(self, document: dict[str, Any]) -> None:
        self._document = document
        self.component = _component(document["component"])

    def authorize(self, api_key: str, purpose: str) -> VerificationGovernanceContext:
        try:
            result = _native.governance_authorize(
                _compact(
                    {
                        "governance": self._document,
                        "api_key": api_key,
                        "purpose": purpose,
                    }
                )
            )
        except PermissionError as exc:
            raise GovernanceAuthorizationError(str(exc)) from exc
        return _context(json.loads(result))

    def resume_session(self, snapshot: Any) -> VerificationGovernanceContext:
        try:
            result = _native.governance_resume(
                _compact({"governance": self._document, "snapshot": snapshot})
            )
        except (TypeError, ValueError) as exc:
            raise GovernanceConfigurationError(str(exc)) from exc
        return _context(json.loads(result))


def _reference(value: dict[str, Any]) -> ProfileReference:
    return ProfileReference(
        id=str(value["id"]),
        version=str(value["version"]),
        content_digest=str(value["content_digest"]),
    )


def _component(value: dict[str, Any]) -> ComponentReference:
    return ComponentReference(
        component_id=str(value["component_id"]),
        version=str(value["version"]),
        artifact_digest=str(value["artifact_digest"]),
        adapter_id=str(value["adapter_id"]),
        adapter_version=str(value["adapter_version"]),
    )


def _context(value: dict[str, Any]) -> VerificationGovernanceContext:
    policy = value["policy"]
    policy_content = policy["content"]
    trust = value["trust_profile"]
    trust_content = trust["content"]
    organization_id = str(value["organization_id"])
    return VerificationGovernanceContext(
        client_id=str(value["client_id"]),
        purpose=str(value["purpose"]),
        organization_id=organization_id,
        policy=PolicyProfile(
            organization_id=organization_id,
            reference=_reference(policy),
            verifier_id=str(policy_content["verifier_id"]),
            presentation_definition_digest=str(
                policy_content["presentation_definition_digest"]
            ),
            required_checks=tuple(policy_content["required_checks"]),
        ),
        trust_profile=TrustProfile(
            organization_id=organization_id,
            reference=_reference(trust),
            trusted_issuers=tuple(trust_content["trusted_issuers"]),
            allow_public_did_fallback=bool(
                trust_content["allow_public_did_fallback"]
            ),
        ),
        component=_component(value["component"]),
    )


@lru_cache(maxsize=8)
def parse_governance(raw: str) -> GovernanceRegistry:
    try:
        _native.governance_validate(raw)
        document = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise GovernanceConfigurationError(str(exc)) from exc
    return GovernanceRegistry(document)


def load_governance() -> GovernanceRegistry:
    raw = os.environ.get(GOVERNANCE_ENV, "")
    if not raw:
        raise GovernanceConfigurationError(f"{GOVERNANCE_ENV} is not configured")
    return parse_governance(raw)


def governance_from_snapshot(value: Any) -> VerificationGovernanceContext:
    try:
        result = _native.governance_from_snapshot(_compact({"snapshot": value}))
    except (TypeError, ValueError) as exc:
        raise GovernanceConfigurationError(str(exc)) from exc
    return _context(json.loads(result))
