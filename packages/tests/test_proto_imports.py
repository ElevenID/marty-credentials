"""Regression tests for lazy protobuf package imports in marty-credentials."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))


def _clear_proto_modules() -> None:
    for name in list(sys.modules):
        if name == "marty_proto.v1" or name.startswith("marty_proto.v1."):
            sys.modules.pop(name, None)


@pytest.fixture(autouse=True)
def _isolate_proto_module_cache():
    """Keep lazy-import assertions from replacing a service's live stubs."""
    previous = {
        name: module
        for name, module in sys.modules.items()
        if name == "marty_proto.v1" or name.startswith("marty_proto.v1.")
    }
    _clear_proto_modules()
    try:
        yield
    finally:
        _clear_proto_modules()
        sys.modules.update(previous)


class TestProtoPackageLazyImports:
    def test_package_import_does_not_eagerly_import_all_submodules(self):
        _clear_proto_modules()

        pkg = importlib.import_module("marty_proto.v1")

        assert pkg.__all__
        assert "marty_proto.v1.auth_service_pb2" not in sys.modules
        assert "marty_proto.v1.issuance_service_pb2" not in sys.modules

    def test_direct_from_import_for_issuance_stubs(self):
        _clear_proto_modules()

        namespace: dict[str, object] = {}
        exec(
            "from marty_proto.v1 import issuance_service_pb2 as pb2, issuance_service_pb2_grpc",
            namespace,
            namespace,
        )

        assert namespace["pb2"].__name__ == "marty_proto.v1.issuance_service_pb2"
        assert (
            namespace["issuance_service_pb2_grpc"].__name__
            == "marty_proto.v1.issuance_service_pb2_grpc"
        )

    def test_multiple_stub_imports_share_same_package_instance(self):
        _clear_proto_modules()

        pkg = importlib.import_module("marty_proto.v1")
        issuance_pb2 = pkg.issuance_service_pb2
        auth_pb2 = pkg.auth_service_pb2

        assert issuance_pb2.__name__ == "marty_proto.v1.issuance_service_pb2"
        assert auth_pb2.__name__ == "marty_proto.v1.auth_service_pb2"
        assert sys.modules["marty_proto.v1"] is pkg

    def test_oid4vci_client_auth_fields_are_present_in_generated_contract(self):
        _clear_proto_modules()

        issuance_pb2 = importlib.import_module("marty_proto.v1.issuance_service_pb2")

        initiate_fields = issuance_pb2.InitiateIssuanceRequest.DESCRIPTOR.fields_by_name
        token_fields = issuance_pb2.ExchangeTokenRequest.DESCRIPTOR.fields_by_name

        assert initiate_fields["authorized_client_id"].number == 7
        assert initiate_fields["application_id"].number == 8
        assert initiate_fields["issuer_did"].number == 9
        assert initiate_fields["delivery_mode"].number == 10
        assert initiate_fields["idempotency_key"].number == 11
        assert initiate_fields["claims_json"].number == 12
        assert token_fields["client_assertion_type"].number == 7
        assert token_fields["client_assertion"].number == 8

    def test_credential_template_contract_preserves_did_first_identity(self):
        """The issuance client must decode the DID returned by template service.

        A stale descriptor silently treats a newer protobuf field as unknown.
        That makes a correctly persisted DID look absent and causes production
        issuance to reject the template as legacy.
        """
        _clear_proto_modules()

        template_pb2 = importlib.import_module("marty_proto.v1.credential_template_service_pb2")

        create_fields = template_pb2.CreateTemplateRequest.DESCRIPTOR.fields_by_name
        update_fields = template_pb2.UpdateTemplateRequest.DESCRIPTOR.fields_by_name
        response_fields = template_pb2.TemplateResponse.DESCRIPTOR.fields_by_name

        assert create_fields["issuer_did"].number == 21
        assert update_fields["issuer_did"].number == 13
        assert response_fields["issuer_did"].number == 28

        forbidden_custody_fields = {
            "issuer_profile_id",
            "issuer_key_id",
            "key_access_mode",
            "remote_signing_config_json",
        }
        for public_fields in (create_fields, update_fields, response_fields):
            assert forbidden_custody_fields.isdisjoint(public_fields)
