"""OID4VCI key-attestation orchestration over the canonical Rust kernel."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import ssl
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, cast

import httpx
from marty_credentials.native_backend import require_marty_rs

_marty_rs = require_marty_rs(
    (
        "key_attestation_policy",
        "key_attestation_route_proof",
        "key_attestation_validate",
        "key_attestation_validate_status_reference",
        "key_attestation_validate_status_token",
    )
)


class KeyAttestationError(ValueError):
    """A key attestation or its issuer-profile policy is invalid."""


StatusValidator = Callable[[Mapping[str, Any]], Awaitable[bool]]
ProofVerifier = Callable[
    [str, str | None, str | None],
    tuple[bool, str, dict[str, Any] | None, str | None],
]
BoundProofVerifier = Callable[
    [str, str, str | None, str | None],
    tuple[bool, str, dict[str, Any] | None, str | None],
]


@dataclass(frozen=True)
class KeyAttestationPolicy:
    mode: Literal["disabled", "optional", "required"]
    trusted_root_certificates_pem: tuple[str, ...]
    allowed_algorithms: frozenset[str]
    required_key_storage: frozenset[str]
    required_user_authentication: frozenset[str]
    max_age_seconds: int
    require_nonce: bool
    status_validation: Literal["disabled", "if_present", "required"]
    status_list_allowed_origins: tuple[str, ...]
    status_list_trusted_root_certificates_pem: tuple[str, ...]
    status_list_allowed_algorithms: frozenset[str]
    status_list_max_age_seconds: int
    status_list_allow_private_hosts: bool
    status_list_tls_ca_certificates_pem: tuple[str, ...]

    @classmethod
    def from_issuer_context(
        cls,
        issuer_context: Mapping[str, Any],
        *,
        organization_id: str,
    ) -> KeyAttestationPolicy:
        result = _native_json(
            _marty_rs.key_attestation_policy,
            {
                "issuer_context": dict(issuer_context),
                "organization_id": organization_id,
            },
        )
        return _policy_from_native(result)


@dataclass(frozen=True)
class ValidatedKeyAttestation:
    jwt: str
    attested_keys: tuple[dict[str, Any], ...]
    claims: Mapping[str, Any]


def _native_json(operation: Callable[[str], str], request: Mapping[str, Any]) -> dict[str, Any]:
    try:
        result = json.loads(operation(json.dumps(request, separators=(",", ":"))))
    except (RuntimeError, TypeError, ValueError) as exc:
        raise KeyAttestationError(str(exc)) from exc
    if not isinstance(result, dict):
        raise KeyAttestationError("Native key attestation operation returned an invalid result")
    return result


def _policy_from_native(value: Mapping[str, Any]) -> KeyAttestationPolicy:
    return KeyAttestationPolicy(
        mode=cast(Literal["disabled", "optional", "required"], value["mode"]),
        trusted_root_certificates_pem=tuple(value["trusted_root_certificates_pem"]),
        allowed_algorithms=frozenset(value["allowed_algorithms"]),
        required_key_storage=frozenset(value["required_key_storage"]),
        required_user_authentication=frozenset(value["required_user_authentication"]),
        max_age_seconds=value["max_age_seconds"],
        require_nonce=value["require_nonce"],
        status_validation=cast(
            Literal["disabled", "if_present", "required"], value["status_validation"]
        ),
        status_list_allowed_origins=tuple(value["status_list_allowed_origins"]),
        status_list_trusted_root_certificates_pem=tuple(
            value["status_list_trusted_root_certificates_pem"]
        ),
        status_list_allowed_algorithms=frozenset(value["status_list_allowed_algorithms"]),
        status_list_max_age_seconds=value["status_list_max_age_seconds"],
        status_list_allow_private_hosts=value["status_list_allow_private_hosts"],
        status_list_tls_ca_certificates_pem=tuple(value["status_list_tls_ca_certificates_pem"]),
    )


def _policy_payload(policy: KeyAttestationPolicy) -> dict[str, Any]:
    return {
        "mode": policy.mode,
        "trusted_root_certificates_pem": list(policy.trusted_root_certificates_pem),
        "allowed_algorithms": sorted(policy.allowed_algorithms),
        "required_key_storage": sorted(policy.required_key_storage),
        "required_user_authentication": sorted(policy.required_user_authentication),
        "max_age_seconds": policy.max_age_seconds,
        "require_nonce": policy.require_nonce,
        "status_validation": policy.status_validation,
        "status_list_allowed_origins": list(policy.status_list_allowed_origins),
        "status_list_trusted_root_certificates_pem": list(
            policy.status_list_trusted_root_certificates_pem
        ),
        "status_list_allowed_algorithms": sorted(policy.status_list_allowed_algorithms),
        "status_list_max_age_seconds": policy.status_list_max_age_seconds,
        "status_list_allow_private_hosts": policy.status_list_allow_private_hosts,
        "status_list_tls_ca_certificates_pem": list(policy.status_list_tls_ca_certificates_pem),
    }


async def validate_token_status_list_entry(
    status: Mapping[str, Any],
    policy: KeyAttestationPolicy,
    *,
    client: httpx.AsyncClient | None = None,
    now: datetime | None = None,
) -> bool:
    """Fetch a status-list token after Rust validates its reference and policy."""
    reference = _native_json(
        _marty_rs.key_attestation_validate_status_reference,
        {"status": dict(status), "policy": _policy_payload(policy)},
    )
    uri = cast(str, reference["uri"])
    hostname = cast(str, reference["hostname"])
    port = cast(int, reference["port"])
    index = cast(int, reference["index"])

    try:
        addresses = await asyncio.get_running_loop().getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise KeyAttestationError("Status-list hostname could not be resolved") from exc
    try:
        resolved_ips = {ipaddress.ip_address(item[4][0]) for item in addresses}
    except ValueError as exc:
        raise KeyAttestationError("Status-list hostname resolved to an invalid address") from exc
    if not resolved_ips:
        raise KeyAttestationError("Status-list hostname resolved to no addresses")
    if not reference["allow_private_hosts"] and any(
        not address.is_global for address in resolved_ips
    ):
        raise KeyAttestationError("Status-list hostname resolves to a non-public address")

    owned_client = client is None
    if owned_client:
        tls_context = ssl.create_default_context()
        for certificate in policy.status_list_tls_ca_certificates_pem:
            try:
                tls_context.load_verify_locations(cadata=certificate)
            except ssl.SSLError as exc:
                raise KeyAttestationError("Status-list TLS CA certificate is invalid") from exc
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(5.0),
            follow_redirects=False,
            verify=tls_context,
        )
    assert client is not None
    try:
        async with client.stream(
            "GET",
            uri,
            headers={"Accept": "application/statuslist+jwt"},
        ) as response:
            if not 200 <= response.status_code < 300:
                raise KeyAttestationError(
                    f"Status-list endpoint returned HTTP {response.status_code}"
                )
            content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
            if content_type != "application/statuslist+jwt":
                raise KeyAttestationError(
                    "Status-list endpoint did not return application/statuslist+jwt"
                )
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > 1_048_576:
                    raise KeyAttestationError("Status List Token response is too large")
    except httpx.HTTPError as exc:
        raise KeyAttestationError("Status-list endpoint request failed") from exc
    finally:
        if owned_client:
            await client.aclose()

    try:
        token = bytes(body).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise KeyAttestationError("Status List Token response is not ASCII") from exc
    current = now or datetime.now(UTC)
    try:
        value = _marty_rs.key_attestation_validate_status_token(
            json.dumps(
                {
                    "token": token,
                    "uri": uri,
                    "index": index,
                    "policy": _policy_payload(policy),
                    "now": current.isoformat(),
                },
                separators=(",", ":"),
            )
        )
    except (RuntimeError, TypeError, ValueError) as exc:
        raise KeyAttestationError(str(exc)) from exc
    return value == 0


async def validate_key_attestation_jwt(
    jwt: str,
    policy: KeyAttestationPolicy,
    *,
    expected_nonce: str | None,
    status_validator: StatusValidator | None = None,
    now: datetime | None = None,
) -> ValidatedKeyAttestation:
    """Validate a key attestation using the canonical Rust trust kernel."""
    current = now or datetime.now(UTC)
    result = _native_json(
        _marty_rs.key_attestation_validate,
        {
            "jwt": jwt,
            "policy": _policy_payload(policy),
            "expected_nonce": expected_nonce,
            "now": current.isoformat(),
        },
    )
    statuses = result.get("statuses", [])
    if statuses and policy.status_validation != "disabled":
        if status_validator is None:
            raise KeyAttestationError("No production status validator is configured")
        for entry in statuses:
            if not await status_validator(entry):
                raise KeyAttestationError("Key attestation status is revoked or invalid")
    return ValidatedKeyAttestation(
        jwt=result["jwt"],
        attested_keys=tuple(dict(key) for key in result["attested_keys"]),
        claims=result["claims"],
    )


async def verify_oid4vci_proof_with_issuer_policy(
    proof_jwt: str,
    *,
    issuer_context: Mapping[str, Any] | None,
    organization_id: str,
    expected_nonce: str | None,
    proof_verifier: ProofVerifier,
    bound_proof_verifier: BoundProofVerifier,
    issuer_url: str | None = None,
    status_validator: StatusValidator | None = None,
) -> tuple[bool, str, dict[str, Any] | None, str | None]:
    """Route proof verification through Rust-resolved tenant policy."""
    try:
        route = _native_json(
            _marty_rs.key_attestation_route_proof,
            {
                "proof_jwt": proof_jwt,
                "issuer_context": dict(issuer_context) if issuer_context is not None else None,
                "organization_id": organization_id,
            },
        )
        if route["action"] == "ordinary":
            return proof_verifier(proof_jwt, expected_nonce, issuer_url)

        policy = _policy_from_native(route["policy"])
        effective_status_validator = status_validator
        if effective_status_validator is None and policy.status_validation != "disabled":

            async def validate_status(entry: Mapping[str, Any]) -> bool:
                return await validate_token_status_list_entry(entry, policy)

            effective_status_validator = validate_status

        raw_attestation = cast(str, route["key_attestation"])
        validated = await validate_key_attestation_jwt(
            raw_attestation,
            policy,
            expected_nonce=expected_nonce,
            status_validator=effective_status_validator,
        )
        return bound_proof_verifier(
            proof_jwt,
            validated.jwt,
            expected_nonce,
            issuer_url,
        )
    except KeyAttestationError as exc:
        return False, "", None, str(exc)
