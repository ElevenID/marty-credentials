"""Wire-contract regressions required by the issuance service's default test run."""

from __future__ import annotations

from marty_proto.v1 import issuance_service_pb2


def test_exchange_token_request_preserves_registered_client_authentication_fields() -> None:
    """Reject stale generated stubs before they can weaken OID4VCI client auth.

    Protobuf silently discards unknown fields, so merely constructing a request
    is insufficient.  Assert both assigned field numbers and a wire round trip.
    """
    fields = issuance_service_pb2.ExchangeTokenRequest.DESCRIPTOR.fields_by_name
    assert fields["client_assertion_type"].number == 7
    assert fields["client_assertion"].number == 8

    request = issuance_service_pb2.ExchangeTokenRequest(
        grant_type="urn:ietf:params:oauth:grant-type:pre-authorized_code",
        pre_authorized_code="pre-auth-code",
        client_id="registered-client",
        client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-client-auth",
        client_assertion="signed-client-assertion",
    )
    decoded = issuance_service_pb2.ExchangeTokenRequest.FromString(request.SerializeToString())

    assert decoded.client_id == "registered-client"
    assert decoded.client_assertion_type.endswith("jwt-client-auth")
    assert decoded.client_assertion == "signed-client-assertion"
