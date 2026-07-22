"""Composite, fail-closed readiness checks for portable Canvas bindings.

The management route is intentionally kept out of this module.  It fetches the
current credential/status documents, calls :func:`evaluate_canvas_binding_readiness`,
and persists the returned snapshot with :func:`apply_canvas_readiness_result`.
That keeps activation decisions deterministic and makes the persisted
``config_version`` part of the authorization boundary.

Persisted readiness includes a live KMS/DID sign-and-verify challenge, so it is
deliberately short-lived.  ``CANVAS_BINDING_READINESS_MAX_AGE_SECONDS`` controls
the cache lifetime and defaults to 900 seconds for the controlled pilot.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
)
from issuance.application.canvas_feature_flags import (
    portable_canvas_enabled_for_organization,
)
from issuance.application.canvas_lti_services import canvas_lti_trust_profile
from issuance.application.canvas_oauth import (
    CANVAS_OAUTH_CAPABILITY_SCOPES,
    canvas_oauth_scopes_for_capabilities,
)
from issuance.domain.entities import (
    ApplicationTemplate,
    CanvasEvidenceFactType,
    CanvasEvidenceSource,
    CanvasOAuthConnectionStatus,
    CanvasPlatform,
    CanvasProgramBinding,
    CanvasSyncReadinessState,
)
from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.api import signing_context

AGS_RESULT_READ_SCOPE = "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly"
SUPPORTED_ISSUER_ALGORITHMS = frozenset({"ES256", "ES384", "RS256", "EdDSA"})
SUPPORTED_OPEN_BADGE_PAYLOAD_FORMATS = frozenset(
    {
        "w3c_vcdm_v2_sd_jwt",
        "ietf_sd_jwt",
        "sd_jwt_vc",
        "vc+sd_jwt",
        "vc+sd-jwt",
        "dc+sd_jwt",
        "dc+sd-jwt",
    }
)
_PRIVATE_JWK_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
DEFAULT_CANVAS_BINDING_READINESS_MAX_AGE_SECONDS = 15 * 60
CANVAS_BINDING_READINESS_MAX_AGE_ENV = (
    "CANVAS_BINDING_READINESS_MAX_AGE_SECONDS"
)


@dataclass(frozen=True)
class CanvasReadinessCheck:
    """Stable readiness record stored on a Canvas program binding."""

    code: str
    component: str
    status: str
    blocking: bool
    remediation: str
    timestamp: str

    @property
    def passed(self) -> bool:
        return self.status in {"ready", "not_applicable"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "component": self.component,
            "status": self.status,
            "blocking": self.blocking,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class CanvasBindingReadiness:
    """Composite result plus the exact credential-template issuance snapshot."""

    organization_id: str
    platform_id: str
    binding_id: str
    config_version: int
    ready: bool
    checks: tuple[CanvasReadinessCheck, ...]
    credential_template_snapshot: dict[str, Any]
    evaluated_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "organization_id": self.organization_id,
            "platform_id": self.platform_id,
            "binding_id": self.binding_id,
            "config_version": self.config_version,
            "ready": self.ready,
            "checks": [check.to_dict() for check in self.checks],
            "credential_template_snapshot": copy.deepcopy(
                self.credential_template_snapshot
            ),
            "evaluated_at": self.evaluated_at.isoformat(),
        }


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        return current.replace(tzinfo=UTC)
    return current.astimezone(UTC)


def _readiness_max_age_seconds(value: int | None = None) -> int | None:
    """Return the configured readiness TTL, or ``None`` to fail closed."""

    if value is None:
        raw = os.environ.get(
            CANVAS_BINDING_READINESS_MAX_AGE_ENV,
            str(DEFAULT_CANVAS_BINDING_READINESS_MAX_AGE_SECONDS),
        )
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return None
    if isinstance(value, bool) or value <= 0:
        return None
    return value


def _status(value: Any) -> str:
    raw = getattr(value, "value", value)
    return str(raw or "").strip().lower()


def _string(value: Any) -> str:
    return str(value or "").strip()


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _first(*values: Any) -> str:
    for value in values:
        normalized = _string(value)
        if normalized:
            return normalized
    return ""


def _https_url(value: Any) -> bool:
    try:
        parsed = urlsplit(_string(value))
    except ValueError:
        return False
    return bool(
        parsed.scheme == "https"
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and not parsed.fragment
    )


def _check(
    *,
    code: str,
    component: str,
    ready: bool,
    blocking: bool,
    remediation: str,
    timestamp: str,
    applicable: bool = True,
) -> CanvasReadinessCheck:
    if not applicable:
        status = "not_applicable"
        remediation = ""
    elif ready:
        status = "ready"
        remediation = ""
    else:
        status = "failed" if blocking else "warning"
    return CanvasReadinessCheck(
        code=code,
        component=component,
        status=status,
        blocking=blocking,
        remediation=remediation,
        timestamp=timestamp,
    )


def _credential_template_id(template: Mapping[str, Any]) -> str:
    return _first(template.get("id"), template.get("credential_template_id"))


def _credential_type(template: Mapping[str, Any]) -> str:
    return _first(template.get("credential_type"), template.get("format"))


def _is_open_badge_type(value: str) -> bool:
    normalized = "".join(character for character in value.lower() if character.isalnum())
    return normalized in {
        "openbadge",
        "openbadgev2",
        "openbadgev3",
        "openbadgecredential",
    }


def _payload_format(template: Mapping[str, Any]) -> str:
    direct = _first(
        template.get("credential_payload_format"),
        template.get("payload_format"),
    )
    if direct:
        return direct
    formats = template.get("supported_formats")
    if isinstance(formats, list) and len(formats) == 1:
        return _string(formats[0])
    return ""


def _remote_format(payload_format: str) -> str:
    normalized = payload_format.lower().replace("-", "_")
    if normalized in {value.replace("-", "_") for value in SUPPORTED_OPEN_BADGE_PAYLOAD_FORMATS}:
        return "dc+sd-jwt"
    return payload_format


@dataclass(frozen=True)
class _ExpectedIssuer:
    profile_id: str
    issuer_did: str
    signing_service_id: str
    signing_key_reference: str
    verification_method_id: str
    algorithm: str
    key_purpose: str
    credential_format: str


def _expected_issuer(template: Mapping[str, Any]) -> _ExpectedIssuer:
    remote = _mapping(template.get("remote_signing_config"))
    payload_format = _payload_format(template)
    return _ExpectedIssuer(
        profile_id=_string(template.get("issuer_profile_id")),
        issuer_did=_string(template.get("issuer_did")),
        signing_service_id=_string(remote.get("signing_service_id")),
        signing_key_reference=_string(remote.get("signing_key_reference")),
        verification_method_id=_string(remote.get("verification_method_id")),
        algorithm=_first(
            template.get("issuer_algorithm"),
            template.get("signing_algorithm"),
            remote.get("algorithm"),
        ),
        key_purpose=_string(remote.get("key_purpose")) or "vc_jwt_issuer",
        credential_format=_remote_format(payload_format),
    )


def _issuer_configuration_valid(template: Mapping[str, Any]) -> bool:
    expected = _expected_issuer(template)
    return bool(
        _status(template.get("key_access_mode")) == "remote_signing"
        and expected.profile_id
        and expected.issuer_did.startswith("did:")
        and expected.signing_service_id
        and expected.signing_key_reference
        and expected.verification_method_id.startswith(expected.issuer_did + "#")
        and expected.algorithm in SUPPORTED_ISSUER_ALGORITHMS
        and expected.credential_format == "dc+sd-jwt"
    )


def _required_oauth_capabilities(binding: CanvasProgramBinding) -> set[str]:
    capabilities: set[str] = set()
    for requirement in binding.typed_evidence_requirements:
        if requirement.source != CanvasEvidenceSource.CANVAS_REST:
            continue
        if requirement.fact_type in {
            CanvasEvidenceFactType.ASSIGNMENT_SCORE,
            CanvasEvidenceFactType.QUIZ_SCORE,
        }:
            capabilities.add("native_activity_scores")
        elif requirement.fact_type == CanvasEvidenceFactType.COURSE_COMPLETION:
            capabilities.add("course_completion")
        elif requirement.fact_type == CanvasEvidenceFactType.MODULE_COMPLETION:
            capabilities.add("module_completion")
    feature_flags = _mapping(binding.feature_flags)
    if feature_flags.get("enable_canvas_nrps") or feature_flags.get(
        "enable_background_awards"
    ):
        capabilities.add("background_roster")
    return capabilities


def _required_oauth_scopes(capabilities: Iterable[str]) -> set[str]:
    requested = sorted(set(capabilities))
    if not requested:
        return set()
    return set(canvas_oauth_scopes_for_capabilities(requested))


def _lti_metadata_ready(platform: CanvasPlatform) -> bool:
    metadata = _mapping(platform.lti_openid_configuration)
    configured_issuer = _string(platform.lti_issuer)
    metadata_issuer = _string(metadata.get("issuer"))
    jwks_uri = _first(metadata.get("jwks_uri"), platform.lti_jwks_url)
    keys = _mapping(platform.lti_jwks_json).get("keys")
    try:
        expected = canvas_lti_trust_profile(
            _string(platform.canvas_base_url),
            _string(platform.lti_trust_profile),
        )
    except Exception:  # noqa: BLE001 - malformed/untrusted metadata fails readiness closed
        return False
    return bool(
        _https_url(platform.canvas_base_url)
        and configured_issuer == expected["issuer"]
        and metadata_issuer == expected["issuer"]
        and _string(metadata.get("authorization_endpoint"))
        == expected["authorization_endpoint"]
        and _string(metadata.get("token_endpoint")) == expected["token_endpoint"]
        and jwks_uri == expected["jwks_uri"]
        and _string(platform.lti_jwks_url) == expected["jwks_uri"]
        and isinstance(keys, list)
        and keys
        and platform.last_validated_at is not None
    )


def verified_canvas_binding_capabilities(
    platform: CanvasPlatform,
    binding: CanvasProgramBinding,
) -> dict[str, Any]:
    """Return launch capabilities proven for this exact binding revision.

    Canvas service URLs are launch-scoped.  A platform-level "last launch"
    snapshot is therefore not sufficient when one developer key serves more
    than one course.  Older unscoped snapshots intentionally fail closed and
    require one new verified launch before activation.
    """

    snapshot = _mapping(platform.capability_snapshot)
    launches = _mapping(snapshot.get("verified_binding_launches"))
    capabilities = _mapping(launches.get(binding.id))
    try:
        verified_version = int(capabilities.get("verified_binding_config_version"))
    except (TypeError, ValueError):
        return {}
    if (
        _string(capabilities.get("verified_binding_id")) != binding.id
        or verified_version != binding.config_version
    ):
        return {}
    return capabilities


def _verified_launch_matches_requirement_course(
    capabilities: Mapping[str, Any],
    requirements: Iterable[Any],
) -> bool:
    course_ids = {
        _string(requirement.scope.course_id)
        for requirement in requirements
        if _string(requirement.scope.course_id)
    }
    return bool(
        len(course_ids) == 1
        and _string(capabilities.get("verified_course_id")) in course_ids
    )


def _ags_ready(
    platform: CanvasPlatform,
    binding: CanvasProgramBinding,
    requirements: Iterable[Any],
) -> bool:
    capabilities = verified_canvas_binding_capabilities(platform, binding)
    scopes = {
        _string(scope)
        for scope in (capabilities.get("ags_scopes") or [])
        if _string(scope)
    }
    ags_requirements = [
        requirement
        for requirement in requirements
        if requirement.source == CanvasEvidenceSource.AGS_RESULT
    ]
    pinned_line_items = {
        _string(requirement.scope.line_item_url)
        for requirement in ags_requirements
        if _string(requirement.scope.line_item_url)
    }
    every_requirement_pinned = bool(ags_requirements) and all(
        _string(requirement.scope.resource_id)
        and _https_url(requirement.scope.line_item_url)
        for requirement in ags_requirements
    )
    verified_line_items = {
        _string(value)
        for value in capabilities.get("verified_ags_line_items", [])
        if _string(value)
    }
    launch_line_item = _string(capabilities.get("ags_lineitem_url"))
    if launch_line_item:
        verified_line_items.add(launch_line_item)
    verified_launch_matches = bool(
        pinned_line_items and pinned_line_items.issubset(verified_line_items)
    )
    return bool(
        capabilities.get("assignment_grade_services")
        and AGS_RESULT_READ_SCOPE in scopes
        and _https_url(
            capabilities.get("ags_lineitem_url")
            or capabilities.get("ags_lineitems_url")
        )
        and every_requirement_pinned
        and verified_launch_matches
        and _verified_launch_matches_requirement_course(
            capabilities,
            ags_requirements,
        )
    )


def _nrps_ready(
    platform: CanvasPlatform,
    binding: CanvasProgramBinding,
    requirements: Iterable[Any],
) -> bool:
    capabilities = verified_canvas_binding_capabilities(platform, binding)
    return bool(
        capabilities.get("names_roles")
        and _https_url(capabilities.get("nrps_context_memberships_url"))
        and _verified_launch_matches_requirement_course(
            capabilities,
            requirements,
        )
    )


def _application_template_ready(
    application_template: ApplicationTemplate | None,
    *,
    binding: CanvasProgramBinding,
) -> bool:
    return bool(
        application_template
        and application_template.id == binding.application_template_id
        and application_template.organization_id == binding.organization_id
        and _status(application_template.status) == "active"
    )


def _credential_template_ready(
    credential_template: Mapping[str, Any],
    *,
    binding: CanvasProgramBinding,
    application_template: ApplicationTemplate | None,
) -> bool:
    template_id = _credential_template_id(credential_template)
    organization_id = _string(credential_template.get("organization_id"))
    payload_format = _payload_format(credential_template)
    return bool(
        template_id
        and template_id == binding.credential_template_id
        and application_template
        and application_template.credential_template_id == template_id
        and organization_id == binding.organization_id
        and _status(credential_template.get("status")) == "active"
        and _is_open_badge_type(_credential_type(credential_template))
        and payload_format.lower() in SUPPORTED_OPEN_BADGE_PAYLOAD_FORMATS
    )


def _status_profile_ready(
    status_profile: Mapping[str, Any],
    *,
    credential_template: Mapping[str, Any],
    organization_id: str,
) -> bool:
    expected_id = _string(credential_template.get("revocation_profile_id"))
    actual_id = _first(status_profile.get("id"), status_profile.get("profile_id"))
    profile_org = _string(status_profile.get("organization_id"))
    return bool(
        expected_id
        and actual_id == expected_id
        and (not profile_org or profile_org == organization_id)
        and _status(status_profile.get("status")) == "active"
    )


def _b64url_decode(value: str) -> bytes:
    encoded = value.encode("ascii")
    return base64.urlsafe_b64decode(encoded + b"=" * ((4 - len(encoded) % 4) % 4))


def _b64url_uint(value: Any) -> int:
    raw = _b64url_decode(_string(value))
    if not raw:
        raise ValueError("JWK integer is empty")
    return int.from_bytes(raw, "big")


def _public_key_from_jwk(jwk: Mapping[str, Any], algorithm: str) -> Any:
    if _PRIVATE_JWK_FIELDS.intersection(jwk):
        raise ValueError("DID resolver returned private JWK material")
    key_type = _string(jwk.get("kty"))
    jwk_algorithm = _string(jwk.get("alg"))
    if jwk_algorithm and jwk_algorithm != algorithm:
        raise ValueError("DID JWK algorithm does not match the credential template")

    if algorithm == "RS256":
        if key_type != "RSA":
            raise ValueError("RS256 requires an RSA DID verification key")
        return rsa.RSAPublicNumbers(
            e=_b64url_uint(jwk.get("e")),
            n=_b64url_uint(jwk.get("n")),
        ).public_key()

    if algorithm in {"ES256", "ES384"}:
        expected_curve = "P-256" if algorithm == "ES256" else "P-384"
        curve: ec.EllipticCurve = (
            ec.SECP256R1() if algorithm == "ES256" else ec.SECP384R1()
        )
        if key_type != "EC" or _string(jwk.get("crv")) != expected_curve:
            raise ValueError(f"{algorithm} requires an {expected_curve} DID verification key")
        return ec.EllipticCurvePublicNumbers(
            x=_b64url_uint(jwk.get("x")),
            y=_b64url_uint(jwk.get("y")),
            curve=curve,
        ).public_key()

    if algorithm == "EdDSA":
        if key_type != "OKP" or _string(jwk.get("crv")) != "Ed25519":
            raise ValueError("EdDSA requires an Ed25519 DID verification key")
        return ed25519.Ed25519PublicKey.from_public_bytes(
            _b64url_decode(_string(jwk.get("x")))
        )

    raise ValueError("Unsupported issuer algorithm")


def _verify_challenge_signature(
    *,
    public_jwk: Mapping[str, Any],
    algorithm: str,
    payload: bytes,
    signature: bytes,
) -> None:
    key = _public_key_from_jwk(public_jwk, algorithm)
    if algorithm == "RS256":
        key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        return
    if algorithm in {"ES256", "ES384"}:
        coordinate_bytes = 32 if algorithm == "ES256" else 48
        if len(signature) == coordinate_bytes * 2:
            signature = encode_dss_signature(
                int.from_bytes(signature[:coordinate_bytes], "big"),
                int.from_bytes(signature[coordinate_bytes:], "big"),
            )
        digest = hashes.SHA256() if algorithm == "ES256" else hashes.SHA384()
        key.verify(signature, payload, ec.ECDSA(digest))
        return
    if algorithm == "EdDSA":
        key.verify(signature, payload)
        return
    raise ValueError("Unsupported issuer algorithm")


def _did_publishes_verification_method(
    resolution: Mapping[str, Any],
    verification_method_id: str,
) -> bool:
    document = _mapping(resolution.get("did_document"))
    methods = document.get("verificationMethod")
    assertions = document.get("assertionMethod")
    method_ids = {
        _string(item.get("id"))
        for item in (methods or [])
        if isinstance(item, Mapping)
    }
    assertion_ids = {
        _string(item.get("id")) if isinstance(item, Mapping) else _string(item)
        for item in (assertions or [])
    }
    return verification_method_id in method_ids and verification_method_id in assertion_ids


def _resolved_context_matches(
    context: Mapping[str, Any],
    expected: _ExpectedIssuer,
) -> bool:
    profile = _mapping(context.get("issuer_profile"))
    service = _mapping(context.get("service"))
    algorithms = service.get("algorithms")
    if not isinstance(algorithms, list):
        algorithms = [service.get("algorithm")] if service.get("algorithm") else []
    resolved_algorithm = _first(
        context.get("algorithm"),
        profile.get("algorithm"),
        service.get("algorithm"),
    )
    algorithm_matches = (
        resolved_algorithm == expected.algorithm
        if resolved_algorithm
        else expected.algorithm in {_string(value) for value in algorithms}
    )
    return bool(
        _first(context.get("issuer_profile_id"), profile.get("id"))
        == expected.profile_id
        and _status(profile.get("status")) == "active"
        and _first(context.get("issuer_did"), profile.get("issuer_did"))
        == expected.issuer_did
        and _first(
            context.get("signing_service_id"),
            profile.get("signing_service_id"),
            service.get("id"),
        )
        == expected.signing_service_id
        and _first(
            context.get("signing_key_reference"),
            profile.get("signing_key_reference"),
            service.get("key_reference"),
        )
        == expected.signing_key_reference
        and _first(
            context.get("verification_method_id"),
            profile.get("verification_method_id"),
        )
        == expected.verification_method_id
        and _first(context.get("key_purpose"), profile.get("key_purpose"))
        == expected.key_purpose
        and algorithm_matches
    )


async def run_canvas_kms_did_challenge(
    *,
    organization_id: str,
    credential_template: Mapping[str, Any],
) -> bool:
    """Resolve, sign, and locally verify an exact KMS/DID issuer challenge.

    Any malformed or mismatched response fails closed.  Callers should persist a
    successful check timestamp as the readiness cache; private key material is
    never accepted or loaded by the issuance service.
    """

    if not _issuer_configuration_valid(credential_template):
        return False
    expected = _expected_issuer(credential_template)
    try:
        context = await signing_context.resolve_remote_issuer_context(
            organization_id,
            issuer_profile_id=expected.profile_id,
            issuer_mode="org_managed",
            credential_format=expected.credential_format,
            key_purpose=expected.key_purpose,
            algorithm=expected.algorithm,
        )
        if not isinstance(context, Mapping) or not _resolved_context_matches(
            context, expected
        ):
            return False

        resolution = await signing_context.resolve_remote_issuer_did(
            organization_id,
            issuer_did=expected.issuer_did,
            verification_method_id=expected.verification_method_id,
            credential_format=expected.credential_format,
            key_purpose=expected.key_purpose,
            algorithm=expected.algorithm,
        )
        if not isinstance(resolution, Mapping):
            return False
        if _first(resolution.get("issuer_did")) != expected.issuer_did:
            return False
        if (
            _first(resolution.get("verification_method_id"))
            != expected.verification_method_id
        ):
            return False
        if not _did_publishes_verification_method(
            resolution, expected.verification_method_id
        ):
            return False
        did_profile = _mapping(resolution.get("issuer_profile"))
        if _first(did_profile.get("id")) != expected.profile_id:
            return False
        signing_service = _mapping(resolution.get("signing_service"))
        if _first(signing_service.get("id")) != expected.signing_service_id:
            return False
        public_jwk = resolution.get("public_jwk")
        if not isinstance(public_jwk, Mapping):
            return False
        if _first(public_jwk.get("kid")) != expected.verification_method_id:
            return False

        challenge = (
            b"marty-canvas-readiness-v1\x00"
            + organization_id.encode("utf-8")
            + b"\x00"
            + secrets.token_bytes(32)
        )
        signed = await signing_context.sign_payload_with_issuer_profile(
            organization_id=organization_id,
            issuer_profile_id=expected.profile_id,
            payload=challenge,
            algorithm=expected.algorithm,
            expected_issuer_did=expected.issuer_did,
            expected_verification_method_id=expected.verification_method_id,
        )
        if not isinstance(signed, Mapping):
            return False
        if _first(signed.get("algorithm")) != expected.algorithm:
            return False
        encoded_signature = _first(
            signed.get("signature_raw_b64"), signed.get("signature_b64")
        )
        if not encoded_signature:
            return False
        _verify_challenge_signature(
            public_jwk=public_jwk,
            algorithm=expected.algorithm,
            payload=challenge,
            signature=_b64url_decode(encoded_signature),
        )
        return True
    except Exception:  # noqa: BLE001 - an unavailable KMS/DID must fail readiness closed
        return False


def _template_snapshot_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode(
            "utf-8"
        )
    ).hexdigest()


def _snapshot_matches_current(
    binding: CanvasProgramBinding,
    credential_template: Mapping[str, Any],
) -> bool:
    current = _mapping(binding.credential_template_snapshot)
    if not current or binding.validated_config_version != binding.config_version:
        return True
    return _template_snapshot_digest(current) == _template_snapshot_digest(
        credential_template
    )


async def evaluate_canvas_binding_readiness(
    *,
    repo: IIssuanceRepository,
    platform: CanvasPlatform,
    binding: CanvasProgramBinding,
    application_template: ApplicationTemplate | None,
    credential_template: Mapping[str, Any] | None,
    credential_status_profile: Mapping[str, Any] | None,
    rollout_allowed: bool | None = None,
    now: datetime | None = None,
    worker_max_age_seconds: int = 120,
    learner_identity_status: str | None = None,
    evidence_observed_at: datetime | None = None,
    evidence_max_age_seconds: int = 900,
    lti_tool_signing_ready: bool = False,
) -> CanvasBindingReadiness:
    """Evaluate every production activation precondition in a stable order."""

    evaluated_at = _utc(now)
    timestamp = evaluated_at.isoformat()
    checks: list[CanvasReadinessCheck] = []
    credential = _mapping(credential_template)
    status_profile = _mapping(credential_status_profile)
    organization_matches = bool(
        platform.organization_id
        and platform.organization_id == binding.organization_id
        and platform.id == binding.platform_id
    )

    allowed = (
        portable_canvas_enabled_for_organization(binding.organization_id)
        if rollout_allowed is None
        else bool(rollout_allowed)
    )
    checks.append(
        _check(
            code="rollout_allowlist",
            component="rollout",
            ready=allowed,
            blocking=True,
            remediation="Enable portable Canvas and add this organization to the pilot allowlist.",
            timestamp=timestamp,
        )
    )
    checks.append(
        _check(
            code="tenant_ownership",
            component="security",
            ready=organization_matches,
            blocking=True,
            remediation="Recreate the binding under the organization that owns the Canvas platform.",
            timestamp=timestamp,
        )
    )
    checks.append(
        _check(
            code="platform_active",
            component="lti",
            ready=bool(
                platform.enabled
                and platform.archived_at is None
                and _status(platform.registration_status)
                in {"verified", "active", "installed", "ready"}
            ),
            blocking=True,
            remediation="Complete Canvas installation validation and enable the platform.",
            timestamp=timestamp,
        )
    )
    checks.append(
        _check(
            code="lti_installation",
            component="lti",
            ready=bool(
                _string(platform.lti_client_id)
                and _string(platform.lti_deployment_id)
            ),
            blocking=True,
            remediation="Enter the Canvas LTI client and deployment IDs.",
            timestamp=timestamp,
        )
    )
    checks.append(
        _check(
            code="lti_metadata",
            component="lti",
            ready=_lti_metadata_ready(platform),
            blocking=True,
            remediation="Probe and pin the Canvas HTTPS OIDC, token, and JWKS metadata again.",
            timestamp=timestamp,
        )
    )
    checks.append(
        _check(
            code="lti_tool_sign_verify_challenge",
            component="lti_tool_kms",
            ready=lti_tool_signing_ready,
            blocking=True,
            remediation=(
                "Configure the dedicated RS256 LTI tool key, publish its active kid, "
                "and rerun the live sign/verify challenge."
            ),
            timestamp=timestamp,
        )
    )

    requirements_valid = True
    requirements = []
    try:
        requirements = binding.typed_evidence_requirements
    except ValueError:
        requirements_valid = False
    checks.append(
        _check(
            code="typed_evidence_requirements",
            component="evidence",
            ready=requirements_valid,
            blocking=True,
            remediation="Replace legacy evidence JSON with uniquely identified typed Canvas requirements.",
            timestamp=timestamp,
        )
    )

    ags_required = any(
        requirement.source == CanvasEvidenceSource.AGS_RESULT
        for requirement in requirements
    )
    checks.append(
        _check(
            code="ags_result_capability",
            component="evidence",
            ready=_ags_ready(platform, binding, requirements),
            blocking=True,
            remediation="Launch the Deep Linked activity and grant AGS Result read access for its verified line item.",
            timestamp=timestamp,
            applicable=ags_required,
        )
    )

    background_awards = bool(
        _mapping(binding.feature_flags).get("enable_background_awards")
    )
    background_required = bool(
        _mapping(binding.feature_flags).get("enable_canvas_nrps")
        or (background_awards and ags_required)
    )
    checks.append(
        _check(
            code="nrps_roster_capability",
            component="evidence",
            ready=_nrps_ready(platform, binding, requirements),
            blocking=True,
            remediation="Grant NRPS membership access and complete a verified course launch.",
            timestamp=timestamp,
            applicable=background_required,
        )
    )

    required_capabilities: set[str] = set()
    capability_mapping_valid = requirements_valid
    if requirements_valid:
        try:
            required_capabilities = _required_oauth_capabilities(binding)
            if not required_capabilities.issubset(CANVAS_OAUTH_CAPABILITY_SCOPES):
                capability_mapping_valid = False
        except (RuntimeError, ValueError):
            capability_mapping_valid = False
    oauth_applicable = bool(required_capabilities) or not capability_mapping_valid
    checks.append(
        _check(
            code="oauth_capability_mapping",
            component="oauth",
            ready=capability_mapping_valid,
            blocking=True,
            remediation="Map every REST evidence rule to a supported least-privilege Canvas capability.",
            timestamp=timestamp,
            applicable=oauth_applicable,
        )
    )

    connection = None
    oauth_lookup_ok = True
    if oauth_applicable:
        try:
            connection = await repo.get_canvas_oauth_connection(
                binding.organization_id, platform.id
            )
        except Exception:  # noqa: BLE001 - readiness must fail closed
            oauth_lookup_ok = False
    connected = bool(
        oauth_lookup_ok
        and connection
        and _status(connection.status) == CanvasOAuthConnectionStatus.CONNECTED.value
        and not connection.reauthorization_required
        and _string(connection.access_token_secret_ref)
    )
    checks.append(
        _check(
            code="oauth_connection",
            component="oauth",
            ready=connected,
            blocking=True,
            remediation="Reconnect Canvas OAuth for this organization and platform.",
            timestamp=timestamp,
            applicable=oauth_applicable,
        )
    )
    required_scopes = (
        _required_oauth_scopes(required_capabilities)
        if capability_mapping_valid
        else set()
    )
    granted_capabilities = set(connection.capabilities if connection else [])
    granted_scopes = set(connection.scopes if connection else [])
    grant_ready = bool(
        connected
        and required_capabilities.issubset(granted_capabilities)
        and required_scopes.issubset(granted_scopes)
    )
    checks.append(
        _check(
            code="oauth_least_privilege_grant",
            component="oauth",
            ready=grant_ready,
            blocking=True,
            remediation="Reauthorize Canvas with every capability required by the current evidence rules.",
            timestamp=timestamp,
            applicable=oauth_applicable,
        )
    )

    heartbeat = None
    try:
        heartbeat = await repo.get_fresh_canvas_worker_heartbeat(
            role="canvas_sync", max_age_seconds=worker_max_age_seconds
        )
    except Exception:  # noqa: BLE001 - readiness must fail closed
        heartbeat = None
    checks.append(
        _check(
            code="worker_heartbeat",
            component="synchronization",
            ready=bool(
                heartbeat is not None
                and _mapping(heartbeat.metadata).get("processor_configured") is True
            ),
            blocking=True,
            remediation="Start the PostgreSQL-backed Canvas worker and restore its heartbeat.",
            timestamp=timestamp,
        )
    )

    sync_state: CanvasSyncReadinessState | None = None
    if organization_matches:
        try:
            observed_sync_state = await repo.get_canvas_sync_readiness_state(
                binding.organization_id,
                platform.id,
                binding.id,
                now=evaluated_at,
            )
            if isinstance(observed_sync_state, CanvasSyncReadinessState):
                sync_state = observed_sync_state
        except Exception:  # noqa: BLE001 - operational lookup must fail closed
            sync_state = None
    checks.append(
        _check(
            code="sync_dead_letter_jobs",
            component="synchronization",
            ready=bool(sync_state is not None and not sync_state.dead_lettered),
            blocking=True,
            remediation=(
                "Retry or resolve every dead-letter Canvas sync job for this "
                "platform and binding."
            ),
            timestamp=timestamp,
        )
    )
    checks.append(
        _check(
            code="sync_backlog_freshness",
            component="synchronization",
            ready=bool(sync_state is not None and not sync_state.stale_backlog),
            blocking=True,
            remediation=(
                "Restore Canvas worker capacity and clear synchronization work "
                "older than two target intervals."
            ),
            timestamp=timestamp,
        )
    )

    app_template_ready = _application_template_ready(
        application_template, binding=binding
    )
    checks.append(
        _check(
            code="application_template",
            component="templates",
            ready=app_template_ready,
            blocking=True,
            remediation="Link an active application template owned by this organization.",
            timestamp=timestamp,
        )
    )
    template_ready = _credential_template_ready(
        credential,
        binding=binding,
        application_template=application_template,
    )
    checks.append(
        _check(
            code="open_badge_template",
            component="templates",
            ready=template_ready,
            blocking=True,
            remediation="Link the same active, KMS-supported Open Badge template used by the application template.",
            timestamp=timestamp,
        )
    )
    checks.append(
        _check(
            code="credential_template_snapshot",
            component="templates",
            ready=bool(template_ready and _snapshot_matches_current(binding, credential)),
            blocking=True,
            remediation="Increment the binding configuration and revalidate the changed credential template.",
            timestamp=timestamp,
        )
    )
    checks.append(
        _check(
            code="credential_status_profile",
            component="credential_status",
            ready=bool(
                template_ready
                and _status_profile_ready(
                    status_profile,
                    credential_template=credential,
                    organization_id=binding.organization_id,
                )
            ),
            blocking=True,
            remediation="Attach an active organization-owned credential status profile to the Open Badge template.",
            timestamp=timestamp,
        )
    )

    issuer_config_ready = bool(
        app_template_ready
        and template_ready
        and _issuer_configuration_valid(credential)
    )
    checks.append(
        _check(
            code="kms_issuer_configuration",
            component="kms_did",
            ready=issuer_config_ready,
            blocking=True,
            remediation="Configure an active REMOTE_SIGNING issuer profile, service, key, DID verification method, and supported algorithm.",
            timestamp=timestamp,
        )
    )
    challenge_ready = False
    if organization_matches and issuer_config_ready:
        challenge_ready = await run_canvas_kms_did_challenge(
            organization_id=binding.organization_id,
            credential_template=credential,
        )
    checks.append(
        _check(
            code="kms_did_sign_verify_challenge",
            component="kms_did",
            ready=challenge_ready,
            blocking=True,
            remediation="Repair the exact KMS key/DID publication binding and rerun the live sign/verify challenge.",
            timestamp=timestamp,
        )
    )

    normalized_identity = _status(learner_identity_status)
    identity_applicable = learner_identity_status is not None
    identity_ready = normalized_identity in {"linked", "verified", "active"}
    checks.append(
        _check(
            code="learner_identity_mapping",
            component="identity",
            ready=identity_ready,
            blocking=False,
            remediation="Have this learner launch Marty in Canvas to establish the verified opaque-to-numeric identity link.",
            timestamp=timestamp,
            applicable=identity_applicable,
        )
    )
    freshness_applicable = evidence_observed_at is not None
    freshness_ready = False
    if evidence_observed_at is not None:
        observed = _utc(evidence_observed_at)
        freshness_ready = (
            observed <= evaluated_at
            and (evaluated_at - observed).total_seconds() <= evidence_max_age_seconds
        )
    checks.append(
        _check(
            code="learner_evidence_freshness",
            component="evidence",
            ready=freshness_ready,
            blocking=False,
            remediation="Enqueue a learner evidence refresh before approval.",
            timestamp=timestamp,
            applicable=freshness_applicable,
        )
    )

    ready = all(not check.blocking or check.passed for check in checks)
    return CanvasBindingReadiness(
        organization_id=binding.organization_id,
        platform_id=platform.id,
        binding_id=binding.id,
        config_version=binding.config_version,
        ready=ready,
        checks=tuple(checks),
        credential_template_snapshot=copy.deepcopy(credential) if template_ready else {},
        evaluated_at=evaluated_at,
    )


def apply_canvas_readiness_result(
    binding: CanvasProgramBinding,
    result: CanvasBindingReadiness,
) -> CanvasProgramBinding:
    """Apply a result to a binding without performing persistence.

    Stale or cross-binding results are rejected so activation cannot rely on a
    prior configuration version or another tenant's validation.
    """

    if (
        result.binding_id != binding.id
        or result.platform_id != binding.platform_id
        or result.organization_id != binding.organization_id
    ):
        raise ValueError("Canvas readiness result does not belong to this binding")
    if result.config_version != binding.config_version:
        raise ValueError("Canvas readiness result is stale for this binding version")
    binding.readiness_checks = [check.to_dict() for check in result.checks]
    binding.readiness_validated_at = result.evaluated_at
    binding.validated_config_version = result.config_version
    if result.ready:
        binding.credential_template_snapshot = copy.deepcopy(
            result.credential_template_snapshot
        )
    return binding


def canvas_binding_is_ready_for_activation(
    binding: CanvasProgramBinding,
    *,
    now: datetime | None = None,
    max_age_seconds: int | None = None,
) -> bool:
    """Authorize use only from a fresh, current-version readiness snapshot.

    The same predicate protects activation, learner launches, approval, and
    final signing.  A missing/malformed timestamp, clock-skewed future value,
    expired KMS/readiness snapshot, or invalid TTL configuration fails closed.
    """

    if (
        binding.archived_at is not None
        or binding.validated_config_version != binding.config_version
        or not isinstance(binding.readiness_validated_at, datetime)
        or not binding.readiness_checks
        or not binding.credential_template_snapshot
    ):
        return False
    max_age = _readiness_max_age_seconds(max_age_seconds)
    if max_age is None:
        return False
    evaluated_at = _utc(now)
    validated_at = _utc(binding.readiness_validated_at)
    age_seconds = (evaluated_at - validated_at).total_seconds()
    if age_seconds < 0 or age_seconds > max_age:
        return False
    for value in binding.readiness_checks:
        if not isinstance(value, Mapping):
            return False
        if bool(value.get("blocking")) and _status(value.get("status")) not in {
            "ready",
            "not_applicable",
        }:
            return False
    return True
