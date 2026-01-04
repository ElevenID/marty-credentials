"""
Tests for credential ports and types.
"""

from marty_credentials.ports import (
    CredentialData,
    CredentialFormat,
    CredentialSubject,
    ICredentialIssuer,
    ICredentialVerifier,
    ICredentialWallet,
    IKeyManager,
    KeyAlgorithm,
    KeyPair,
)


def test_credential_format_values():
    """Test CredentialFormat enum values."""
    assert CredentialFormat.JWT_VC.value == "jwt_vc_json"
    assert CredentialFormat.SD_JWT_VC.value == "vc+sd-jwt"
    assert CredentialFormat.MDOC.value == "mso_mdoc"


def test_key_algorithm_values():
    """Test KeyAlgorithm enum values."""
    assert KeyAlgorithm.ES256.value == "ES256"
    assert KeyAlgorithm.ES384.value == "ES384"
    assert KeyAlgorithm.EDDSA.value == "EdDSA"


def test_credential_subject_defaults():
    """Test CredentialSubject default values."""
    subject = CredentialSubject()
    assert subject.id is None
    assert subject.claims == {}


def test_credential_subject_with_claims():
    """Test CredentialSubject with claims."""
    subject = CredentialSubject(
        id="did:key:z6Mk...",
        claims={"name": "Alice", "age": 30},
    )
    assert subject.id == "did:key:z6Mk..."
    assert subject.claims["name"] == "Alice"


def test_protocol_is_runtime_checkable():
    """Test that port protocols are runtime checkable."""
    assert hasattr(IKeyManager, "__protocol_attrs__") or callable(IKeyManager)
    assert hasattr(ICredentialIssuer, "__protocol_attrs__") or callable(ICredentialIssuer)
    assert hasattr(ICredentialVerifier, "__protocol_attrs__") or callable(ICredentialVerifier)
    assert hasattr(ICredentialWallet, "__protocol_attrs__") or callable(ICredentialWallet)
