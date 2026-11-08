"""Canonical mdoc preparation across a real, non-exportable external signer."""

import base64
import hashlib
import json
import os
import re
import ssl
import urllib.parse
import urllib.request
import uuid

import _marty_rs
import cbor2
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

PUBLIC_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
    "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
}
NAMESPACE = "org.iso.18013.5.1"
DOC_TYPE = "org.iso.18013.5.1.mDL"
CLAIMS = {"family_name": "Avery", "age_over_21": True, "score": 12.5}
CREDENTIAL_ID = "urn:uuid:00000000-0000-0000-0000-000000000789"


def prepare(public_jwk=PUBLIC_JWK, **overrides):
    arguments = {
        "issuer_id": "did:web:issuer.example",
        "verification_method_id": "did:web:issuer.example#mdoc-signing",
        "issuer_public_jwk_json": json.dumps(public_jwk),
        "doc_type": DOC_TYPE,
        "namespace": NAMESPACE,
        "claims_json": json.dumps(CLAIMS),
        "expiration_seconds": 3600,
        "credential_id": CREDENTIAL_ID,
        "holder_jwk_json": json.dumps(PUBLIC_JWK),
    }
    arguments.update(overrides)
    return _marty_rs.prepare_mdoc_for_hsm(**arguments)


def test_preparation_exposes_complete_signing_structure_and_retains_state_on_failure():
    prepared = prepare()
    payload = bytes(prepared.get_tbs_data())
    context, protected, external_aad, mso_bytes = cbor2.loads(payload)
    assert context == "Signature1"
    assert cbor2.loads(protected)[1] == -7  # ES256
    assert external_aad == b""
    mso = cbor2.loads(mso_bytes)
    assert isinstance(mso, cbor2.CBORTag) and mso.tag == 24
    assert cbor2.loads(mso.value)["docType"] == DOC_TYPE
    assert prepared.get_credential_id() == CREDENTIAL_ID
    with pytest.raises(ValueError):
        _marty_rs.complete_mdoc_with_signature(prepared, bytes(64))
    assert bytes(prepared.get_tbs_data()) == payload


@pytest.mark.parametrize(
    "overrides",
    [
        {"claims_json": '{"family_name":"Avery","family_name":"Changed"}'},
        {"verification_method_id": "did:web:other.example#mdoc-signing"},
        {"issuer_public_jwk_json": json.dumps({**PUBLIC_JWK, "d": "AA"})},
        {"holder_jwk_json": json.dumps({**PUBLIC_JWK, "d": "AA"})},
    ],
)
def test_core_rejects_ambiguous_claims_misbound_identity_and_private_keys(overrides):
    with pytest.raises(ValueError):
        prepare(**overrides)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("The disposable OpenBao endpoint must not redirect")


@pytest.fixture
def remote_signer():
    base = os.environ.get("MARTY_TEST_OPENBAO_URL")
    if not base:
        pytest.skip("Use scripts/test_mdoc_hsm_roundtrip.py for the external-signing regression")
    parsed = urllib.parse.urlsplit(base)
    assert parsed.scheme == "https" and parsed.hostname == "127.0.0.1"
    assert parsed.port and parsed.path in ("", "/")
    assert not (parsed.username or parsed.password or parsed.query or parsed.fragment)
    nonce = os.environ["MARTY_TEST_OPENBAO_DISPOSABLE_NONCE"]
    assert re.fullmatch(r"[0-9a-f]{48}", nonce), "Missing disposable instance marker"
    root_token = os.environ["MARTY_TEST_OPENBAO_TOKEN"]
    context = ssl.create_default_context(cafile=os.environ["MARTY_TEST_OPENBAO_CA_CERT"])
    client = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect()
    )

    def request(method, path, body=None, token=root_token):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(
            base.rstrip("/") + "/v1/" + path,
            data=data,
            method=method,
            headers={"X-Vault-Token": token, "Content-Type": "application/json"},
        )
        with client.open(req, timeout=10) as response:
            content = response.read()
        return json.loads(content) if content else {}

    marker = request("GET", "secret/data/marty-test-disposable-guard")
    assert marker["data"]["data"]["nonce"] == nonce, "Refusing an unmarked signing instance"
    name = "marty-credentials-mdoc-" + uuid.uuid4().hex
    sign_token = None
    key_created = False
    policy_created = False
    try:
        request(
            "POST",
            "transit/keys/" + name,
            {
                "type": "ecdsa-p256",
                "exportable": False,
                "allow_plaintext_backup": False,
            },
        )
        key_created = True
        key = request("GET", "transit/keys/" + name)["data"]
        assert not key["exportable"] and not key["allow_plaintext_backup"]
        public_key = serialization.load_pem_public_key(key["keys"]["1"]["public_key"].encode())
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        numbers = public_key.public_numbers()

        def coordinate(value):
            return base64.urlsafe_b64encode(value.to_bytes(32, "big")).decode().rstrip("=")

        public_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": coordinate(numbers.x),
            "y": coordinate(numbers.y),
        }
        request(
            "PUT",
            "sys/policies/acl/" + name,
            {
                "policy": f'path "transit/sign/{name}" {{ capabilities = ["update"] }}',
            },
        )
        policy_created = True
        sign_token = request(
            "POST",
            "auth/token/create",
            {
                "policies": [name],
                "ttl": "10m",
                "no_default_policy": True,
            },
        )["auth"]["client_token"]

        def sign(message):
            response = request(
                "POST",
                "transit/sign/" + name,
                {
                    "input": base64.b64encode(hashlib.sha256(message).digest()).decode(),
                    "prehashed": True,
                    "hash_algorithm": "sha2-256",
                },
                token=sign_token,
            )
            der = base64.b64decode(response["data"]["signature"].rsplit(":", 1)[1])
            r, s = utils.decode_dss_signature(der)
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")

        yield public_jwk, public_key, sign
    finally:
        if sign_token:
            request("POST", "auth/token/revoke", {"token": sign_token})
        if key_created:
            request("POST", "transit/keys/" + name + "/config", {"deletion_allowed": True})
            request("DELETE", "transit/keys/" + name)
        if policy_created:
            request("DELETE", "sys/policies/acl/" + name)


def test_external_signature_and_all_item_digests_survive_completion(remote_signer):
    public_jwk, public_key, sign = remote_signer
    prepared = prepare(public_jwk)
    original_tbs = bytes(prepared.get_tbs_data())
    assert bytes(prepared.get_tbs_data()) == original_tbs
    # Signing the bare MSO was the former boundary error: it must be rejected.
    mso_payload = cbor2.loads(original_tbs)[3]
    with pytest.raises(ValueError):
        prepared.complete_with_signature(sign(mso_payload))
    assert bytes(prepared.get_tbs_data()) == original_tbs

    signature = sign(original_tbs)
    issuer_signed = cbor2.loads(bytes(_marty_rs.complete_mdoc_with_signature(prepared, signature)))
    assert set(issuer_signed) == {"nameSpaces", "issuerAuth"}
    issuer_auth = issuer_signed["issuerAuth"]
    if isinstance(issuer_auth, cbor2.CBORTag):
        assert issuer_auth.tag == 18
        issuer_auth = issuer_auth.value
    protected, _unprotected, payload, actual_signature = issuer_auth
    reconstructed = cbor2.dumps(["Signature1", protected, b"", payload])
    assert reconstructed == original_tbs
    assert actual_signature == signature
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    public_key.verify(utils.encode_dss_signature(r, s), reconstructed, ec.ECDSA(hashes.SHA256()))

    mso_tag = cbor2.loads(payload)
    assert isinstance(mso_tag, cbor2.CBORTag) and mso_tag.tag == 24
    mso = cbor2.loads(mso_tag.value)
    assert mso["docType"] == DOC_TYPE and mso["digestAlgorithm"] == "SHA-256"
    assert set(mso["valueDigests"]) == {NAMESPACE}
    observed = {}
    for item in issuer_signed["nameSpaces"][NAMESPACE]:
        assert isinstance(item, cbor2.CBORTag) and item.tag == 24
        decoded = cbor2.loads(item.value)
        digest = hashlib.sha256(cbor2.dumps(item)).digest()
        assert digest == mso["valueDigests"][NAMESPACE][decoded["digestID"]]
        observed[decoded["elementIdentifier"]] = decoded["elementValue"]
    assert observed == CLAIMS
    holder_key = mso["deviceKeyInfo"]["deviceKey"]
    assert holder_key[-2] == base64.urlsafe_b64decode(PUBLIC_JWK["x"] + "=")
    assert holder_key[-3] == base64.urlsafe_b64decode(PUBLIC_JWK["y"] + "=")
    with pytest.raises(RuntimeError, match="already been completed"):
        prepared.complete_with_signature(signature)
    with pytest.raises(RuntimeError, match="already been completed"):
        prepared.get_tbs_data()
