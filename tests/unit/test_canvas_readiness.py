from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from issuance.application import canvas_readiness
from issuance.application.canvas_oauth import canvas_oauth_scopes_for_capabilities
from issuance.application.canvas_readiness import (
    AGS_RESULT_READ_SCOPE,
    DEFAULT_CANVAS_BINDING_READINESS_MAX_AGE_SECONDS,
    apply_canvas_readiness_result,
    canvas_binding_is_ready_for_activation,
    evaluate_canvas_binding_readiness,
    verified_canvas_binding_capabilities,
)
from issuance.domain.entities import (
    ApplicationTemplate,
    CanvasOAuthConnection,
    CanvasPlatform,
    CanvasProgramBinding,
    CanvasWorkerHeartbeat,
)
from issuance.infrastructure.adapters.memory_repository import (
    InMemoryIssuanceRepository,
)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _uint(value: int, length: int | None = None) -> str:
    length = length or max(1, (value.bit_length() + 7) // 8)
    return _b64(value.to_bytes(length, "big"))


def _key_material(algorithm: str) -> tuple[Any, dict[str, Any]]:
    if algorithm == "RS256":
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private.public_key().public_numbers()
        return private, {
            "kty": "RSA",
            "n": _uint(numbers.n),
            "e": _uint(numbers.e),
            "alg": algorithm,
        }
    if algorithm in {"ES256", "ES384"}:
        curve = ec.SECP256R1() if algorithm == "ES256" else ec.SECP384R1()
        private = ec.generate_private_key(curve)
        numbers = private.public_key().public_numbers()
        coordinate_bytes = 32 if algorithm == "ES256" else 48
        return private, {
            "kty": "EC",
            "crv": "P-256" if algorithm == "ES256" else "P-384",
            "x": _uint(numbers.x, coordinate_bytes),
            "y": _uint(numbers.y, coordinate_bytes),
            "alg": algorithm,
        }
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    return private, {"kty": "OKP", "crv": "Ed25519", "x": _b64(public), "alg": "EdDSA"}


def _sign(private: Any, algorithm: str, payload: bytes) -> bytes:
    if algorithm == "RS256":
        return private.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    if algorithm in {"ES256", "ES384"}:
        digest = hashes.SHA256() if algorithm == "ES256" else hashes.SHA384()
        der = private.sign(payload, ec.ECDSA(digest))
        r, s = decode_dss_signature(der)
        size = 32 if algorithm == "ES256" else 48
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")
    return private.sign(payload)


def _fixtures(algorithm: str = "ES256") -> tuple[
    CanvasPlatform,
    CanvasProgramBinding,
    ApplicationTemplate,
    dict[str, Any],
    dict[str, Any],
]:
    now = datetime.now(UTC)
    platform = CanvasPlatform(
        id="platform-1",
        organization_id="org-1",
        canvas_account_id="account-1",
        display_name="Hosted Canvas",
        canvas_base_url="https://school.instructure.com",
        lti_client_id="10000000000001",
        lti_deployment_id="deployment-1",
        lti_issuer="https://canvas.instructure.com",
        lti_jwks_url="https://sso.canvaslms.com/api/lti/security/jwks",
        lti_jwks_json={"keys": [{"kid": "canvas-1", "kty": "RSA"}]},
        lti_openid_configuration={
            "issuer": "https://canvas.instructure.com",
            "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect",
            "token_endpoint": "https://school.instructure.com/login/oauth2/token",
            "jwks_uri": "https://sso.canvaslms.com/api/lti/security/jwks",
        },
        registration_status="verified",
        last_validated_at=now,
        capability_snapshot={
            "assignment_grade_services": True,
            "ags_lineitem_url": "https://school.instructure.com/api/lti/courses/1/line_items/2",
            "ags_scopes": [AGS_RESULT_READ_SCOPE],
            "names_roles": True,
            "nrps_context_memberships_url": "https://school.instructure.com/api/lti/courses/1/names_and_roles",
            "verified_binding_launches": {
                "binding-1": {
                    "assignment_grade_services": True,
                    "ags_lineitem_url": "https://school.instructure.com/api/lti/courses/1/line_items/2",
                    "ags_scopes": [AGS_RESULT_READ_SCOPE],
                    "names_roles": True,
                    "nrps_context_memberships_url": "https://school.instructure.com/api/lti/courses/1/names_and_roles",
                    "verified_binding_id": "binding-1",
                    "verified_binding_config_version": 1,
                    "verified_course_id": "1",
                    "verified_ags_line_items": [
                        "https://school.instructure.com/api/lti/courses/1/line_items/2"
                    ],
                }
            },
        },
        enabled=True,
    )
    binding = CanvasProgramBinding(
        id="binding-1",
        organization_id="org-1",
        platform_id=platform.id,
        application_template_id="application-template-1",
        credential_template_id="credential-template-1",
        evidence_requirements=[
            {
                "requirement_id": "marty-assignment",
                "source": "ags_result",
                "fact_type": "canvas.assignment_score",
                "scope": {
                    "course_id": "1",
                    "resource_id": "marty-resource-1",
                    "line_item_url": "https://school.instructure.com/api/lti/courses/1/line_items/2",
                },
                "pass_rule": {"min_score_percent": 80},
                "required": True,
            },
            {
                "requirement_id": "native-quiz",
                "source": "canvas_rest",
                "fact_type": "canvas.quiz_score",
                "scope": {"course_id": "1", "activity_id": "42"},
                "pass_rule": {"min_score_percent": 70},
                "required": True,
            },
            {
                "requirement_id": "course-complete",
                "source": "canvas_rest",
                "fact_type": "canvas.course_completion",
                "scope": {"course_id": "1"},
                "pass_rule": {"completed": True},
                "required": True,
            },
            {
                "requirement_id": "module-complete",
                "source": "canvas_rest",
                "fact_type": "canvas.module_completion",
                "scope": {"course_id": "1", "module_id": "9"},
                "pass_rule": {"completed": True},
                "required": True,
            },
        ],
        feature_flags={"enable_canvas_nrps": True},
        enabled=False,
    )
    application_template = ApplicationTemplate(
        id=binding.application_template_id,
        organization_id="org-1",
        credential_template_id=binding.credential_template_id,
        status="ACTIVE",
    )
    credential_template = {
        "id": binding.credential_template_id,
        "organization_id": "org-1",
        "status": "ACTIVE",
        "credential_type": "OpenBadgeCredential",
        "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
        "revocation_profile_id": "status-profile-1",
        "issuer_profile_id": "issuer-profile-1",
        "issuer_did": "did:web:issuer.example:orgs:org-1",
        "issuer_key_id": "badge-key-1",
        "issuer_algorithm": algorithm,
        "key_access_mode": "REMOTE_SIGNING",
        "remote_signing_config": {
            "provider": "managed-signing-service",
            "signing_service_id": "kms-service-1",
            "signing_key_reference": "badge-key-1",
            "verification_method_id": "did:web:issuer.example:orgs:org-1#badge-key-1",
            "key_purpose": "vc_jwt_issuer",
        },
    }
    status_profile = {
        "id": "status-profile-1",
        "organization_id": "org-1",
        "status": "ACTIVE",
    }
    return platform, binding, application_template, credential_template, status_profile


def test_launch_capabilities_are_scoped_to_exact_binding_and_version() -> None:
    platform, binding, *_rest = _fixtures()
    assert verified_canvas_binding_capabilities(platform, binding)

    other_binding = CanvasProgramBinding(
        id="binding-2",
        organization_id=binding.organization_id,
        platform_id=binding.platform_id,
        application_template_id="application-template-2",
        credential_template_id="credential-template-2",
    )
    assert verified_canvas_binding_capabilities(platform, other_binding) == {}

    binding.config_version += 1
    assert verified_canvas_binding_capabilities(platform, binding) == {}


async def _ready_repo(platform: CanvasPlatform) -> InMemoryIssuanceRepository:
    repo = InMemoryIssuanceRepository()
    capabilities = [
        "native_activity_scores",
        "course_completion",
        "module_completion",
        "background_roster",
    ]
    await repo.save_canvas_oauth_connection(
        CanvasOAuthConnection(
            organization_id="org-1",
            platform_id=platform.id,
            canvas_base_url=str(platform.canvas_base_url or ""),
            platform_config_version=platform.config_version,
            capabilities=capabilities,
            scopes=canvas_oauth_scopes_for_capabilities(capabilities),
            access_token_secret_ref="org_secret://org-1/access-token-1",
        )
    )
    await repo.upsert_canvas_worker_heartbeat(
        CanvasWorkerHeartbeat(
            worker_id="worker-1",
            role="canvas_sync",
            metadata={"processor_configured": True},
        )
    )
    return repo


def _install_kms_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    algorithm: str,
    signing_private: Any,
    public_jwk: dict[str, Any],
) -> None:
    vm = "did:web:issuer.example:orgs:org-1#badge-key-1"
    did = "did:web:issuer.example:orgs:org-1"
    public_jwk = {**public_jwk, "kid": vm}

    async def resolve_context(*args: Any, **kwargs: Any) -> dict[str, Any]:
        assert args == ("org-1",)
        assert kwargs == {
            "issuer_profile_id": "issuer-profile-1",
            "issuer_mode": "org_managed",
            "credential_format": "dc+sd-jwt",
            "key_purpose": "vc_jwt_issuer",
            "algorithm": algorithm,
        }
        return {
            "issuer_profile_id": "issuer-profile-1",
            "issuer_did": did,
            "signing_service_id": "kms-service-1",
            "signing_key_reference": "badge-key-1",
            "verification_method_id": vm,
            "key_purpose": "vc_jwt_issuer",
            "issuer_profile": {
                "id": "issuer-profile-1",
                "status": "active",
                "issuer_did": did,
                "signing_service_id": "kms-service-1",
                "signing_key_reference": "badge-key-1",
                "verification_method_id": vm,
                "key_purpose": "vc_jwt_issuer",
                "algorithm": algorithm,
            },
            "service": {"id": "kms-service-1", "algorithm": algorithm},
        }

    async def resolve_did(*args: Any, **kwargs: Any) -> dict[str, Any]:
        assert args == ("org-1",)
        assert kwargs["verification_method_id"] == vm
        return {
            "issuer_did": did,
            "verification_method_id": vm,
            "public_jwk": public_jwk,
            "issuer_profile": {"id": "issuer-profile-1", "status": "active"},
            "signing_service": {"id": "kms-service-1"},
            "did_document": {
                "id": did,
                "verificationMethod": [{"id": vm, "publicKeyJwk": public_jwk}],
                "assertionMethod": [vm],
            },
        }

    async def sign(**kwargs: Any) -> dict[str, Any]:
        assert kwargs["organization_id"] == "org-1"
        assert kwargs["signing_service_id"] == "kms-service-1"
        assert kwargs["key_reference"] == "badge-key-1"
        assert kwargs["algorithm"] == algorithm
        return {
            "algorithm": algorithm,
            "signature_raw_b64": _b64(
                _sign(signing_private, algorithm, kwargs["payload"])
            ),
        }

    monkeypatch.setattr(
        canvas_readiness.signing_context, "resolve_remote_issuer_context", resolve_context
    )
    monkeypatch.setattr(
        canvas_readiness.signing_context, "resolve_remote_issuer_did", resolve_did
    )
    monkeypatch.setattr(
        canvas_readiness.signing_context, "sign_payload_with_remote_service", sign
    )


def _by_code(result: Any, code: str) -> Any:
    return next(check for check in result.checks if check.code == code)


def test_lti_readiness_pins_documented_hosted_canvas_profile() -> None:
    platform, _binding, _application, _credential, _status_profile = _fixtures()

    assert canvas_readiness._lti_metadata_ready(platform) is True

    platform.lti_openid_configuration = {
        **platform.lti_openid_configuration,
        "authorization_endpoint": "https://school.instructure.com/api/lti/authorize_redirect",
    }
    assert canvas_readiness._lti_metadata_ready(platform) is False


def test_lti_readiness_pins_allowlisted_self_managed_canvas_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform, _binding, _application, _credential, _status_profile = _fixtures()
    origin = "https://canvas-test.elevenidllc.com"
    monkeypatch.setenv("CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST", origin)
    platform.canvas_base_url = origin
    platform.lti_trust_profile = "self_managed_same_origin"
    platform.lti_issuer = origin
    platform.lti_jwks_url = f"{origin}/api/lti/security/jwks"
    platform.lti_openid_configuration = {
        "issuer": origin,
        "authorization_endpoint": f"{origin}/api/lti/authorize_redirect",
        "token_endpoint": f"{origin}/login/oauth2/token",
        "jwks_uri": f"{origin}/api/lti/security/jwks",
    }

    assert canvas_readiness._lti_metadata_ready(platform) is True

    monkeypatch.setenv("CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST", "")
    assert canvas_readiness._lti_metadata_ready(platform) is False


@pytest.mark.asyncio
@pytest.mark.parametrize("algorithm", ["RS256", "ES256", "ES384", "EdDSA"])
async def test_composite_readiness_accepts_exact_live_kms_did_challenge(
    monkeypatch: pytest.MonkeyPatch,
    algorithm: str,
) -> None:
    platform, binding, application, credential, status_profile = _fixtures(algorithm)
    repo = await _ready_repo(platform)
    private, public_jwk = _key_material(algorithm)
    _install_kms_fakes(
        monkeypatch,
        algorithm=algorithm,
        signing_private=private,
        public_jwk=public_jwk,
    )

    result = await evaluate_canvas_binding_readiness(
        repo=repo,
        platform=platform,
        binding=binding,
        application_template=application,
        credential_template=credential,
        credential_status_profile=status_profile,
        rollout_allowed=True,
        lti_tool_signing_ready=True,
    )

    assert result.ready is True
    assert _by_code(result, "kms_did_sign_verify_challenge").status == "ready"
    assert _by_code(result, "lti_tool_sign_verify_challenge").status == "ready"
    assert _by_code(result, "oauth_least_privilege_grant").status == "ready"
    assert _by_code(result, "worker_heartbeat").status == "ready"
    assert all(
        set(check.to_dict())
        == {"code", "component", "status", "blocking", "remediation", "timestamp"}
        for check in result.checks
    )


@pytest.mark.asyncio
async def test_readiness_fails_closed_for_missing_grant_worker_and_inactive_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform, binding, application, credential, status_profile = _fixtures()
    application.status = "DRAFT"
    repo = InMemoryIssuanceRepository()
    await repo.save_canvas_oauth_connection(
        CanvasOAuthConnection(
            organization_id="org-1",
            platform_id=platform.id,
            canvas_base_url=str(platform.canvas_base_url or ""),
            platform_config_version=platform.config_version,
            capabilities=["native_activity_scores"],
            scopes=canvas_oauth_scopes_for_capabilities(["native_activity_scores"]),
            access_token_secret_ref="org_secret://org-1/access-token-1",
        )
    )

    async def forbidden(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError("KMS must not be called for an invalid template")

    monkeypatch.setattr(
        canvas_readiness.signing_context, "resolve_remote_issuer_context", forbidden
    )
    result = await evaluate_canvas_binding_readiness(
        repo=repo,
        platform=platform,
        binding=binding,
        application_template=application,
        credential_template=credential,
        credential_status_profile=status_profile,
        rollout_allowed=True,
        lti_tool_signing_ready=True,
    )

    assert result.ready is False
    assert _by_code(result, "application_template").status == "failed"
    assert _by_code(result, "oauth_least_privilege_grant").status == "failed"
    assert _by_code(result, "worker_heartbeat").status == "failed"
    assert _by_code(result, "kms_did_sign_verify_challenge").status == "failed"


@pytest.mark.asyncio
async def test_readiness_rejects_signature_from_a_different_kms_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform, binding, application, credential, status_profile = _fixtures("ES256")
    repo = await _ready_repo(platform)
    signing_private, _ = _key_material("ES256")
    _, published_public = _key_material("ES256")
    _install_kms_fakes(
        monkeypatch,
        algorithm="ES256",
        signing_private=signing_private,
        public_jwk=published_public,
    )

    result = await evaluate_canvas_binding_readiness(
        repo=repo,
        platform=platform,
        binding=binding,
        application_template=application,
        credential_template=credential,
        credential_status_profile=status_profile,
        rollout_allowed=True,
        lti_tool_signing_ready=True,
    )

    assert result.ready is False
    assert _by_code(result, "kms_issuer_configuration").status == "ready"
    assert _by_code(result, "kms_did_sign_verify_challenge").status == "failed"


@pytest.mark.asyncio
async def test_readiness_blocks_activation_when_lti_tool_key_challenge_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform, binding, application, credential, status_profile = _fixtures()
    repo = await _ready_repo(platform)
    private, public_jwk = _key_material("ES256")
    _install_kms_fakes(
        monkeypatch,
        algorithm="ES256",
        signing_private=private,
        public_jwk=public_jwk,
    )

    result = await evaluate_canvas_binding_readiness(
        repo=repo,
        platform=platform,
        binding=binding,
        application_template=application,
        credential_template=credential,
        credential_status_profile=status_profile,
        rollout_allowed=True,
        lti_tool_signing_ready=False,
    )

    assert result.ready is False
    check = _by_code(result, "lti_tool_sign_verify_challenge")
    assert check.status == "failed"
    assert check.blocking is True


@pytest.mark.asyncio
async def test_identity_and_freshness_are_per_learner_nonblocking_warnings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform, binding, application, credential, status_profile = _fixtures()
    repo = await _ready_repo(platform)
    private, public_jwk = _key_material("ES256")
    _install_kms_fakes(
        monkeypatch,
        algorithm="ES256",
        signing_private=private,
        public_jwk=public_jwk,
    )

    result = await evaluate_canvas_binding_readiness(
        repo=repo,
        platform=platform,
        binding=binding,
        application_template=application,
        credential_template=credential,
        credential_status_profile=status_profile,
        rollout_allowed=True,
        learner_identity_status="quarantined",
        evidence_observed_at=datetime.now(UTC) - timedelta(hours=1),
        lti_tool_signing_ready=True,
    )

    assert result.ready is True
    assert _by_code(result, "learner_identity_mapping").status == "warning"
    assert _by_code(result, "learner_identity_mapping").blocking is False
    assert _by_code(result, "learner_evidence_freshness").status == "warning"


@pytest.mark.asyncio
async def test_persisted_readiness_is_bound_to_current_config_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform, binding, application, credential, status_profile = _fixtures()
    repo = await _ready_repo(platform)
    private, public_jwk = _key_material("ES256")
    _install_kms_fakes(
        monkeypatch,
        algorithm="ES256",
        signing_private=private,
        public_jwk=public_jwk,
    )
    result = await evaluate_canvas_binding_readiness(
        repo=repo,
        platform=platform,
        binding=binding,
        application_template=application,
        credential_template=credential,
        credential_status_profile=status_profile,
        rollout_allowed=True,
        lti_tool_signing_ready=True,
    )

    apply_canvas_readiness_result(binding, result)
    assert canvas_binding_is_ready_for_activation(binding) is True
    assert binding.credential_template_snapshot == credential

    binding.config_version += 1
    assert canvas_binding_is_ready_for_activation(binding) is False
    with pytest.raises(ValueError, match="stale"):
        apply_canvas_readiness_result(binding, result)


@pytest.mark.asyncio
async def test_persisted_readiness_expires_with_pilot_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform, binding, application, credential, status_profile = _fixtures()
    repo = await _ready_repo(platform)
    private, public_jwk = _key_material("ES256")
    _install_kms_fakes(
        monkeypatch,
        algorithm="ES256",
        signing_private=private,
        public_jwk=public_jwk,
    )
    result = await evaluate_canvas_binding_readiness(
        repo=repo,
        platform=platform,
        binding=binding,
        application_template=application,
        credential_template=credential,
        credential_status_profile=status_profile,
        rollout_allowed=True,
        lti_tool_signing_ready=True,
    )
    apply_canvas_readiness_result(binding, result)

    boundary = result.evaluated_at + timedelta(
        seconds=DEFAULT_CANVAS_BINDING_READINESS_MAX_AGE_SECONDS
    )
    assert canvas_binding_is_ready_for_activation(binding, now=boundary) is True
    assert (
        canvas_binding_is_ready_for_activation(
            binding,
            now=boundary + timedelta(microseconds=1),
        )
        is False
    )


@pytest.mark.asyncio
async def test_persisted_readiness_ttl_is_env_configurable_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform, binding, application, credential, status_profile = _fixtures()
    repo = await _ready_repo(platform)
    private, public_jwk = _key_material("ES256")
    _install_kms_fakes(
        monkeypatch,
        algorithm="ES256",
        signing_private=private,
        public_jwk=public_jwk,
    )
    result = await evaluate_canvas_binding_readiness(
        repo=repo,
        platform=platform,
        binding=binding,
        application_template=application,
        credential_template=credential,
        credential_status_profile=status_profile,
        rollout_allowed=True,
        lti_tool_signing_ready=True,
    )
    apply_canvas_readiness_result(binding, result)
    after_twenty_minutes = result.evaluated_at + timedelta(minutes=20)

    monkeypatch.setenv("CANVAS_BINDING_READINESS_MAX_AGE_SECONDS", "1800")
    assert (
        canvas_binding_is_ready_for_activation(
            binding,
            now=after_twenty_minutes,
        )
        is True
    )

    monkeypatch.setenv("CANVAS_BINDING_READINESS_MAX_AGE_SECONDS", "invalid")
    assert (
        canvas_binding_is_ready_for_activation(
            binding,
            now=result.evaluated_at,
        )
        is False
    )


@pytest.mark.asyncio
async def test_persisted_readiness_rejects_missing_malformed_and_future_timestamps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform, binding, application, credential, status_profile = _fixtures()
    repo = await _ready_repo(platform)
    private, public_jwk = _key_material("ES256")
    _install_kms_fakes(
        monkeypatch,
        algorithm="ES256",
        signing_private=private,
        public_jwk=public_jwk,
    )
    result = await evaluate_canvas_binding_readiness(
        repo=repo,
        platform=platform,
        binding=binding,
        application_template=application,
        credential_template=credential,
        credential_status_profile=status_profile,
        rollout_allowed=True,
        lti_tool_signing_ready=True,
    )
    apply_canvas_readiness_result(binding, result)

    binding.readiness_validated_at = None
    assert canvas_binding_is_ready_for_activation(binding, now=result.evaluated_at) is False

    binding.readiness_validated_at = "not-a-timestamp"  # type: ignore[assignment]
    assert canvas_binding_is_ready_for_activation(binding, now=result.evaluated_at) is False

    binding.readiness_validated_at = result.evaluated_at + timedelta(seconds=1)
    assert canvas_binding_is_ready_for_activation(binding, now=result.evaluated_at) is False
