"""Server-owned authorization and provenance for canonical verification."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from types import MappingProxyType
from typing import Any

GOVERNANCE_ENV = "VERIFICATION_GOVERNANCE_JSON"
CREDENTIALS_COMPONENT_ID = "marty-credentials"
VERIFICATION_ADAPTER_ID = "verification-service"
SESSION_CREATE_PURPOSE = "verification.session.create"
DIRECT_VERIFY_PURPOSE = "verification.direct"
VDS_NC_VERIFY_PURPOSE = "verification.vds-nc"
ALLOWED_PURPOSES = frozenset({SESSION_CREATE_PURPOSE, DIRECT_VERIFY_PURPOSE, VDS_NC_VERIFY_PURPOSE})
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
SUPPORTED_CHECKS = frozenset(
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
)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class GovernanceConfigurationError(RuntimeError):
    """The server-owned verification governance is missing or invalid."""


class GovernanceAuthorizationError(PermissionError):
    """The supplied caller credential is not authorized for the purpose."""


class GovernancePolicyMismatchError(ValueError):
    """A request does not match its caller-bound governed policy."""


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise GovernanceConfigurationError("value is not canonical JSON") from exc


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise GovernanceConfigurationError(f"duplicate JSON member: {key}")
        value[key] = item
    return value


def _reject_non_finite_json(value: str) -> Any:
    raise GovernanceConfigurationError(f"non-finite JSON number is not allowed: {value}")


def canonical_digest(value: Any) -> str:
    """Digest a JSON value using the repository's canonical JSON encoding."""
    return f"sha256:{hashlib.sha256(_canonical_json(value)).hexdigest()}"


def _require_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GovernanceConfigurationError(f"{field} must be an object")
    return value


def _require_exact_keys(value: dict[str, Any], field: str, keys: set[str]) -> None:
    actual = set(value)
    if actual != keys:
        raise GovernanceConfigurationError(
            f"{field} must contain exactly {sorted(keys)}; got {sorted(actual)}"
        )


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 255:
        raise GovernanceConfigurationError(f"{field} must be non-empty bounded text")
    return value


def _require_digest(value: Any, field: str) -> str:
    text = _require_text(value, field)
    if not _DIGEST_RE.fullmatch(text):
        raise GovernanceConfigurationError(f"{field} must be a lowercase SHA-256 digest")
    return text


def _require_organization_id(value: Any, field: str) -> str:
    text = _require_text(value, field)
    try:
        parsed = uuid.UUID(text)
    except ValueError as exc:
        raise GovernanceConfigurationError(f"{field} must be a canonical UUID") from exc
    if str(parsed) != text:
        raise GovernanceConfigurationError(f"{field} must be a canonical UUID")
    return text


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

    def require_purpose(self, purpose: str) -> None:
        if self.purpose != purpose:
            raise GovernancePolicyMismatchError(
                "verification governance context is not authorized for this purpose"
            )
        missing = PURPOSE_REQUIRED_CHECKS[purpose] - set(self.policy.required_checks)
        if missing:
            raise GovernancePolicyMismatchError(
                "verification policy is missing mandatory purpose checks"
            )

    def validate_request(
        self,
        *,
        verifier_id: str,
        presentation_definition: dict[str, Any],
    ) -> None:
        if verifier_id != self.policy.verifier_id:
            raise GovernancePolicyMismatchError(
                "verifier_id does not match the caller-bound verification policy"
            )
        try:
            definition_digest = canonical_digest(presentation_definition)
        except GovernanceConfigurationError as exc:
            raise GovernancePolicyMismatchError(
                "presentation_definition is not canonical JSON"
            ) from exc
        if definition_digest != self.policy.presentation_definition_digest:
            raise GovernancePolicyMismatchError(
                "presentation_definition does not match the caller-bound verification policy"
            )

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


@dataclass(frozen=True)
class _PurposeAuthorization:
    policy_id: str
    trust_profile_id: str


@dataclass(frozen=True)
class _ClientAuthorization:
    client_id: str
    api_key_sha256: str
    organization_id: str
    purposes: Mapping[str, _PurposeAuthorization]


@dataclass(frozen=True)
class GovernanceRegistry:
    component: ComponentReference
    policies: Mapping[tuple[str, str], PolicyProfile]
    trust_profiles: Mapping[tuple[str, str], TrustProfile]
    clients: tuple[_ClientAuthorization, ...]

    def authorize(self, api_key: str, purpose: str) -> VerificationGovernanceContext:
        if purpose not in ALLOWED_PURPOSES:
            raise GovernanceAuthorizationError("Unsupported verification purpose")
        if not api_key or len(api_key) > 4096:
            raise GovernanceAuthorizationError("Invalid or unauthorized API key")
        supplied_digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        matched: _ClientAuthorization | None = None
        for client in self.clients:
            if hmac.compare_digest(supplied_digest, client.api_key_sha256):
                matched = client
        if matched is None or purpose not in matched.purposes:
            raise GovernanceAuthorizationError("Invalid or unauthorized API key")
        purpose_authorization = matched.purposes[purpose]
        policy = self.policies[(matched.organization_id, purpose_authorization.policy_id)]
        trust_profile = self.trust_profiles[
            (matched.organization_id, purpose_authorization.trust_profile_id)
        ]
        return VerificationGovernanceContext(
            client_id=matched.client_id,
            purpose=purpose,
            organization_id=matched.organization_id,
            policy=policy,
            trust_profile=trust_profile,
            component=self.component,
        )

    def resume_session(self, snapshot: Any) -> VerificationGovernanceContext:
        """Re-authorize frozen profiles and bind work to the executing component."""
        frozen = governance_from_snapshot(snapshot)
        client = next(
            (candidate for candidate in self.clients if candidate.client_id == frozen.client_id),
            None,
        )
        if client is None or client.organization_id != frozen.organization_id:
            raise GovernanceConfigurationError(
                "governance_snapshot client is not registered for its organization"
            )
        authorization = client.purposes.get(frozen.purpose)
        if authorization is None:
            raise GovernanceConfigurationError(
                "governance_snapshot client is not authorized for its purpose"
            )
        if (
            authorization.policy_id != frozen.policy.reference.id
            or authorization.trust_profile_id != frozen.trust_profile.reference.id
        ):
            raise GovernanceConfigurationError(
                "governance_snapshot profiles are not authorized for its purpose"
            )
        registered_policy = self.policies.get(
            (frozen.organization_id, authorization.policy_id)
        )
        registered_trust = self.trust_profiles.get(
            (frozen.organization_id, authorization.trust_profile_id)
        )
        if registered_policy != frozen.policy or registered_trust != frozen.trust_profile:
            raise GovernanceConfigurationError(
                "governance_snapshot profiles do not match the registered authority"
            )
        return VerificationGovernanceContext(
            client_id=frozen.client_id,
            purpose=frozen.purpose,
            organization_id=frozen.organization_id,
            policy=frozen.policy,
            trust_profile=frozen.trust_profile,
            component=self.component,
        )


def _profile_reference(value: dict[str, Any], field: str) -> ProfileReference:
    return ProfileReference(
        id=_require_text(value.get("id"), f"{field}.id"),
        version=_require_text(value.get("version"), f"{field}.version"),
        content_digest=_require_digest(value.get("content_digest"), f"{field}.content_digest"),
    )


def _parse_component(value: Any) -> ComponentReference:
    value = _require_object(value, "component")
    _require_exact_keys(
        value,
        "component",
        {"component_id", "version", "artifact_digest", "adapter_id", "adapter_version"},
    )
    component = ComponentReference(
        component_id=_require_text(value["component_id"], "component.component_id"),
        version=_require_text(value["version"], "component.version"),
        artifact_digest=_require_digest(value["artifact_digest"], "component.artifact_digest"),
        adapter_id=_require_text(value["adapter_id"], "component.adapter_id"),
        adapter_version=_require_text(value["adapter_version"], "component.adapter_version"),
    )
    if component.component_id != CREDENTIALS_COMPONENT_ID:
        raise GovernanceConfigurationError(
            f"component.component_id must be {CREDENTIALS_COMPONENT_ID}"
        )
    if component.adapter_id != VERIFICATION_ADAPTER_ID:
        raise GovernanceConfigurationError(
            f"component.adapter_id must be {VERIFICATION_ADAPTER_ID}"
        )
    return component


def _parse_policy(value: Any, index: int) -> PolicyProfile:
    field = f"policies[{index}]"
    value = _require_object(value, field)
    _require_exact_keys(
        value,
        field,
        {"organization_id", "id", "version", "content_digest", "content"},
    )
    organization_id = _require_organization_id(value["organization_id"], f"{field}.organization_id")
    reference = _profile_reference(value, field)
    content = _require_object(value["content"], f"{field}.content")
    _require_exact_keys(
        content,
        f"{field}.content",
        {"verifier_id", "presentation_definition_digest", "required_checks"},
    )
    if canonical_digest(content) != reference.content_digest:
        raise GovernanceConfigurationError(f"{field}.content_digest does not match content")
    required_checks = content["required_checks"]
    if not isinstance(required_checks, list) or not required_checks:
        raise GovernanceConfigurationError(f"{field}.content.required_checks must be non-empty")
    if any(not isinstance(item, str) or item not in SUPPORTED_CHECKS for item in required_checks):
        raise GovernanceConfigurationError(f"{field}.content.required_checks is unsupported")
    if len(set(required_checks)) != len(required_checks):
        raise GovernanceConfigurationError(f"{field}.content.required_checks contains duplicates")
    return PolicyProfile(
        organization_id=organization_id,
        reference=reference,
        verifier_id=_require_text(content["verifier_id"], f"{field}.content.verifier_id"),
        presentation_definition_digest=_require_digest(
            content["presentation_definition_digest"],
            f"{field}.content.presentation_definition_digest",
        ),
        required_checks=tuple(required_checks),
    )


def _parse_trust_profile(value: Any, index: int) -> TrustProfile:
    field = f"trust_profiles[{index}]"
    value = _require_object(value, field)
    _require_exact_keys(
        value,
        field,
        {"organization_id", "id", "version", "content_digest", "content"},
    )
    organization_id = _require_organization_id(value["organization_id"], f"{field}.organization_id")
    reference = _profile_reference(value, field)
    content = _require_object(value["content"], f"{field}.content")
    _require_exact_keys(
        content,
        f"{field}.content",
        {"trusted_issuers", "allow_public_did_fallback"},
    )
    if canonical_digest(content) != reference.content_digest:
        raise GovernanceConfigurationError(f"{field}.content_digest does not match content")
    trusted_issuers = content["trusted_issuers"]
    if (
        not isinstance(trusted_issuers, list)
        or not trusted_issuers
        or any(
            not isinstance(issuer, str) or not issuer.startswith("did:") or len(issuer) > 255
            for issuer in trusted_issuers
        )
        or trusted_issuers != sorted(set(trusted_issuers))
    ):
        raise GovernanceConfigurationError(
            f"{field}.content.trusted_issuers must be a non-empty sorted unique list"
        )
    if content["allow_public_did_fallback"] is not False:
        raise GovernanceConfigurationError(
            f"{field}.content.allow_public_did_fallback must be false"
        )
    return TrustProfile(
        organization_id=organization_id,
        reference=reference,
        trusted_issuers=tuple(trusted_issuers),
        allow_public_did_fallback=False,
    )


def _parse_client(value: Any, index: int) -> _ClientAuthorization:
    field = f"clients[{index}]"
    value = _require_object(value, field)
    _require_exact_keys(
        value,
        field,
        {
            "client_id",
            "api_key_sha256",
            "organization_id",
            "purposes",
        },
    )
    api_key_sha256 = _require_text(value["api_key_sha256"], f"{field}.api_key_sha256")
    if not _HEX_DIGEST_RE.fullmatch(api_key_sha256):
        raise GovernanceConfigurationError(f"{field}.api_key_sha256 must be lowercase SHA-256")
    purposes_value = value["purposes"]
    if not isinstance(purposes_value, dict) or not purposes_value:
        raise GovernanceConfigurationError(f"{field}.purposes is invalid")
    purposes: dict[str, _PurposeAuthorization] = {}
    for purpose, authorization_value in purposes_value.items():
        if purpose not in ALLOWED_PURPOSES:
            raise GovernanceConfigurationError(f"{field}.purposes contains an invalid purpose")
        authorization = _require_object(
            authorization_value,
            f"{field}.purposes[{purpose}]",
        )
        _require_exact_keys(
            authorization,
            f"{field}.purposes[{purpose}]",
            {"policy_id", "trust_profile_id"},
        )
        purposes[purpose] = _PurposeAuthorization(
            policy_id=_require_text(
                authorization["policy_id"],
                f"{field}.purposes[{purpose}].policy_id",
            ),
            trust_profile_id=_require_text(
                authorization["trust_profile_id"],
                f"{field}.purposes[{purpose}].trust_profile_id",
            ),
        )
    return _ClientAuthorization(
        client_id=_require_text(value["client_id"], f"{field}.client_id"),
        api_key_sha256=api_key_sha256,
        organization_id=_require_organization_id(
            value["organization_id"], f"{field}.organization_id"
        ),
        purposes=MappingProxyType(purposes),
    )


@lru_cache(maxsize=8)
def parse_governance(raw: str) -> GovernanceRegistry:
    """Parse and validate an exact server-owned governance document."""
    try:
        payload = json.loads(
            raw,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_non_finite_json,
        )
    except json.JSONDecodeError as exc:
        raise GovernanceConfigurationError(f"{GOVERNANCE_ENV} must be valid JSON") from exc
    payload = _require_object(payload, GOVERNANCE_ENV)
    _require_exact_keys(
        payload,
        GOVERNANCE_ENV,
        {"component", "policies", "trust_profiles", "clients"},
    )
    if not all(
        isinstance(payload[name], list) and payload[name]
        for name in ("policies", "trust_profiles", "clients")
    ):
        raise GovernanceConfigurationError(
            "policies, trust_profiles, and clients must be non-empty lists"
        )

    component = _parse_component(payload["component"])
    policies_list = [_parse_policy(value, index) for index, value in enumerate(payload["policies"])]
    trust_list = [
        _parse_trust_profile(value, index) for index, value in enumerate(payload["trust_profiles"])
    ]
    clients = tuple(_parse_client(value, index) for index, value in enumerate(payload["clients"]))

    policies = {(item.organization_id, item.reference.id): item for item in policies_list}
    trust_profiles = {(item.organization_id, item.reference.id): item for item in trust_list}
    if len(policies) != len(policies_list):
        raise GovernanceConfigurationError("duplicate organization policy profile")
    if len(trust_profiles) != len(trust_list):
        raise GovernanceConfigurationError("duplicate organization trust profile")
    if len({client.api_key_sha256 for client in clients}) != len(clients):
        raise GovernanceConfigurationError("duplicate client API key digest")
    if len({client.client_id for client in clients}) != len(clients):
        raise GovernanceConfigurationError("duplicate client id")
    for client in clients:
        for purpose, authorization in client.purposes.items():
            policy_key = (client.organization_id, authorization.policy_id)
            trust_key = (client.organization_id, authorization.trust_profile_id)
            if policy_key not in policies:
                raise GovernanceConfigurationError(
                    f"client {client.client_id} purpose {purpose} references an unknown "
                    "organization policy"
                )
            if trust_key not in trust_profiles:
                raise GovernanceConfigurationError(
                    f"client {client.client_id} purpose {purpose} references an unknown "
                    "organization trust profile"
                )
            policy_checks = set(policies[policy_key].required_checks)
            missing = PURPOSE_REQUIRED_CHECKS[purpose] - policy_checks
            if missing:
                raise GovernanceConfigurationError(
                    f"client {client.client_id} policy is missing mandatory checks for "
                    f"{purpose}: {sorted(missing)}"
                )
    return GovernanceRegistry(
        component,
        MappingProxyType(policies),
        MappingProxyType(trust_profiles),
        clients,
    )


def load_governance() -> GovernanceRegistry:
    raw = os.environ.get(GOVERNANCE_ENV, "")
    if not raw:
        raise GovernanceConfigurationError(f"{GOVERNANCE_ENV} is not configured")
    return parse_governance(raw)


def governance_from_snapshot(value: Any) -> VerificationGovernanceContext:
    """Revalidate a persisted, secret-free governance snapshot."""
    value = _require_object(value, "governance_snapshot")
    _require_exact_keys(
        value,
        "governance_snapshot",
        {"client_id", "purpose", "organization_id", "policy", "trust_profile", "component"},
    )
    client_id = _require_text(value["client_id"], "governance_snapshot.client_id")
    purpose = _require_text(value["purpose"], "governance_snapshot.purpose")
    if purpose not in ALLOWED_PURPOSES:
        raise GovernanceConfigurationError("governance_snapshot.purpose is unsupported")
    organization_id = _require_organization_id(
        value["organization_id"], "governance_snapshot.organization_id"
    )
    policy_value = _require_object(value["policy"], "governance_snapshot.policy")
    trust_value = _require_object(value["trust_profile"], "governance_snapshot.trust_profile")
    policy = _parse_policy(
        {"organization_id": organization_id, **policy_value},
        0,
    )
    trust_profile = _parse_trust_profile(
        {"organization_id": organization_id, **trust_value},
        0,
    )
    missing = PURPOSE_REQUIRED_CHECKS[purpose] - set(policy.required_checks)
    if missing:
        raise GovernanceConfigurationError(
            f"governance_snapshot policy is missing mandatory purpose checks: {sorted(missing)}"
        )
    return VerificationGovernanceContext(
        client_id=client_id,
        purpose=purpose,
        organization_id=organization_id,
        policy=policy,
        trust_profile=trust_profile,
        component=_parse_component(value["component"]),
    )
