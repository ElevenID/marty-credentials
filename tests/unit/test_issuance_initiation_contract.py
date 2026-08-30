"""Language-neutral behavior floor for native issuance initiation."""

from __future__ import annotations

import inspect
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[2]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

from issuance.application.issuance_idempotency import (  # noqa: E402
    canonical_issuance_request,
    hash_idempotency_key,
    issuance_request_hash,
    normalize_idempotency_key,
)
from issuance.domain.entities import IssuanceTransaction  # noqa: E402
from issuance.infrastructure.adapters.delivery_records import (  # noqa: E402
    normalize_delivery_mode,
)
from issuance.infrastructure.api import routes  # noqa: E402
from marty_proto.v1 import issuance_service_pb2  # noqa: E402

CONTRACT = json.loads((ROOT / "contracts/issuance-initiation.json").read_text(encoding="utf-8"))


def _base_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "organization_id": "org-1",
        "issuer_did": "did:web:issuer.example",
    }
    request.update(overrides)
    return request


def test_initiation_transport_surface_is_frozen() -> None:
    http = CONTRACT["surface"]["http"]
    matching_routes = [
        route
        for route in routes.issuance_router.routes
        if route.path == http["path"] and http["method"] in route.methods
    ]
    assert len(matching_routes) == 1
    route = matching_routes[0]
    assert route.endpoint.__name__ == http["operation"]
    assert routes._verify_management_api_key in {
        dependency.call for dependency in route.dependant.dependencies
    }

    grpc_contract = CONTRACT["surface"]["grpc"]
    service = issuance_service_pb2.DESCRIPTOR.services_by_name["IssuanceService"]
    method = service.methods_by_name[grpc_contract["rpc"]]
    assert service.full_name == grpc_contract["service"]
    assert method.input_type.full_name == grpc_contract["request"]
    assert method.output_type.full_name == grpc_contract["response"]


def test_http_domain_request_shape_and_exclusivity_are_frozen() -> None:
    expected_fields = {
        field["name"] for field in CONTRACT["domain_request"]["fields"] if field["http"]
    }
    assert set(routes.InitiateIssuanceRequest.model_fields) == expected_fields
    assert routes.InitiateIssuanceRequest.model_config["extra"] == "forbid"

    rich = routes.InitiateIssuanceRequest(
        **_base_request(
            credential_template_id="template-1",
            application_id="application-1",
            applicant_id="applicant-1",
            subject_did="did:key:z6MkHolder",
            holder_did="did:key:z6MkHolder",
            authorized_client_id="client-1",
            delivery_mode="wallet_plus_canvas_mirror",
            credential_subject=[{"id": "did:key:z6MkHolder", "degree": "BSc"}],
        )
    )
    assert rich.delivery_mode == "wallet_plus_canvas_mirror"
    assert rich.claims == {}
    assert rich.credential_subject == [{"id": "did:key:z6MkHolder", "degree": "BSc"}]

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        routes.InitiateIssuanceRequest(**_base_request(unknown=True))
    with pytest.raises(ValidationError, match="at least 1 character"):
        routes.InitiateIssuanceRequest(**_base_request(issuer_did=""))

    for reserved in CONTRACT["domain_request"]["reserved_claim_fields"]:
        with pytest.raises(ValidationError, match="reserved for internal use"):
            routes.InitiateIssuanceRequest(**_base_request(claims={reserved: "value"}))

    with pytest.raises(ValidationError, match="credential_subject cannot be combined"):
        routes.InitiateIssuanceRequest(
            **_base_request(claims={}, credential_subject={"name": "Ada"})
        )
    with pytest.raises(ValidationError, match="credential_document cannot be combined"):
        routes.InitiateIssuanceRequest(
            **_base_request(
                claims={},
                credential_document={"@context": [], "type": []},
            )
        )


def test_grpc_projection_preserves_the_existing_transport_boundary() -> None:
    request_fields = {
        field.name: field.number
        for field in issuance_service_pb2.InitiateIssuanceRequest.DESCRIPTOR.fields
    }
    assert request_fields == CONTRACT["grpc_projection"]["field_numbers"]
    assert set(CONTRACT["grpc_projection"]["unsupported_domain_inputs"]) == {
        field["name"]
        for field in CONTRACT["domain_request"]["fields"]
        if field["http"] and not field["grpc"]
    }
    response_fields = [
        field.name for field in issuance_service_pb2.IssuanceResponse.DESCRIPTOR.fields
    ]
    assert response_fields == CONTRACT["response"]["fields"]

    grpc_source = inspect.getsource(
        __import__(
            "issuance.infrastructure.adapters.grpc_adapter",
            fromlist=["IssuanceServiceGrpc"],
        ).IssuanceServiceGrpc.InitiateIssuance
    )
    assert "tmpl_resp.selective_disclosure_fields" in grpc_source
    assert 'tmpl.get("selective_disclosure_fields")' in grpc_source
    assert "selective_disclosure_claims=selective_disclosure_claims" in grpc_source


def test_idempotency_and_delivery_vectors_are_frozen() -> None:
    vector = CONTRACT["idempotency"]["vector"]
    canonical = canonical_issuance_request(**vector["request"])
    assert canonical == vector["request"]
    assert hash_idempotency_key(vector["key"]) == vector["key_hash"]
    assert issuance_request_hash(canonical) == vector["request_hash"]
    assert normalize_idempotency_key(vector["key"]) == vector["key"]

    for invalid in (" padded", "padded "):
        with pytest.raises(ValueError, match="surrounding whitespace"):
            normalize_idempotency_key(invalid)
    for invalid in ("contains a space", "x" * 129):
        with pytest.raises(ValueError, match="1-128 ASCII"):
            normalize_idempotency_key(invalid)

    assert [
        normalize_delivery_mode(mode) for mode in CONTRACT["domain_request"]["delivery_modes"]
    ] == CONTRACT["domain_request"]["delivery_modes"]
    with pytest.raises(ValueError, match="Invalid delivery_mode"):
        normalize_delivery_mode("direct-kms")

    generated = IssuanceTransaction()
    assert uuid.UUID(generated.id).version == 4
    assert len(generated.pre_auth_code) == CONTRACT["transaction"]["pre_auth_code_encoded_length"]
    lifetime_minutes = (generated.expires_at - generated.created_at).total_seconds() / 60
    assert lifetime_minutes == pytest.approx(CONTRACT["transaction"]["offer_ttl_minutes"], abs=0.01)
    assert generated.created_at.tzinfo == UTC
    assert generated.created_at <= datetime.now(UTC)


def test_dependency_order_and_custody_boundary_are_frozen() -> None:
    source = inspect.getsource(routes.initiate_issuance)
    prefix_markers = [
        "normalize_idempotency_key",
        "normalize_delivery_mode",
        "GetOrganization",
        "get_oid4vci_client",
        "recover_transaction_idempotently",
    ]
    prefix_positions = [source.index(marker) for marker in prefix_markers]
    assert prefix_positions == sorted(prefix_positions)

    recovery_position = source.index("recover_transaction_idempotently")
    recovery_response_position = source.index(
        "_issuance_response_from_transaction", recovery_position
    )
    template_position = source.index("GetTemplate")
    assert recovery_position < recovery_response_position < template_position

    normal_path_markers = [
        "GetTemplate",
        "_require_active_revocation_profile_binding",
        "get_application",
        "apply_required_remote_issuer_context",
        "reserve_transaction_idempotently",
    ]
    normal_positions = [source.index(marker) for marker in normal_path_markers]
    assert normal_positions == sorted(normal_positions)
    assert normal_positions[-1] < source.rindex("_issuance_response_from_transaction")
    assert len(CONTRACT["dependency_order"]) == 12
    assert CONTRACT["idempotent_recovery_branch"][-1] == ("return-before-template-resolution")
    assert set(CONTRACT["domain_request"]["credential_subject_formats"]) == (
        routes._JWT_VC_PAYLOAD_FORMATS | routes._DATA_INTEGRITY_PAYLOAD_FORMATS
    )
    assert set(CONTRACT["domain_request"]["credential_document_formats"]) == (
        routes._DATA_INTEGRITY_PAYLOAD_FORMATS
    )

    for header in CONTRACT["issuer_custody"]["direct_http_headers_forbidden"]:
        with pytest.raises(routes.HTTPException) as rejected:
            routes._reject_direct_signing_headers({header: "caller-selected"})
        assert (
            rejected.value.status_code,
            rejected.value.detail,
        ) == (
            CONTRACT["issuer_custody"]["direct_header_failure"]["http_status"],
            CONTRACT["issuer_custody"]["direct_header_failure"]["detail"],
        )


@pytest.mark.asyncio
async def test_http_offer_projection_uses_only_the_committed_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def stable_offer(**values: object) -> str:
        return json.dumps(values, sort_keys=True, separators=(",", ":"))

    monkeypatch.setattr(routes, "oid4vci_create_credential_offer", stable_offer)
    transaction = IssuanceTransaction(
        id="tx-1",
        organization_id="org-1",
        credential_template_id="template-1",
        credential_type="EmployeeBadge",
        credential_payload_format="w3c_vcdm_v2_sd_jwt",
        pre_auth_code="pre-auth-1",
        wallet_configs=[
            {
                "wallet_id": "default-wallet",
                "display_name": "Default Wallet",
                "deep_link_scheme": "openid-credential-offer://",
            },
            {
                "wallet_id": "credential-manager",
                "display_name": "Credential Manager",
                "format_variant": "credential-manager",
                "deep_link_scheme": "marty-manager://offer",
            },
            {
                "wallet_id": "apple-wallet",
                "display_name": "Apple Wallet",
                "format_variant": "apple-wallet",
                "deep_link_scheme": "marty-apple://offer",
            },
            {
                "wallet_id": "didcomm-wallet",
                "display_name": "DIDComm Wallet",
                "format_variant": "didcomm_v2",
            },
        ],
    )
    request = routes.InitiateIssuanceRequest(**_base_request())

    response = await routes._issuance_response_from_transaction(
        tx=transaction,
        request=request,
        repo=object(),
    )

    assert response.id == transaction.id
    assert response.pre_auth_code == transaction.pre_auth_code
    assert set(response.credential_offer_uris) == {
        "default-wallet",
        "credential-manager",
        "apple-wallet",
        "didcomm-wallet",
    }
    assert response.credential_offer_uris["didcomm-wallet"] == (
        "didcomm://pending?transaction_id=tx-1"
    )
    assert response.credential_offer_labels == {
        "default-wallet": "Default Wallet",
        "credential-manager": "Credential Manager",
        "apple-wallet": "Apple Wallet",
        "didcomm-wallet": "DIDComm Wallet",
    }
    assert response.model_dump().keys() == set(CONTRACT["response"]["fields"])
