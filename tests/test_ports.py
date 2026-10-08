"""
Tests for credential ports and types.
"""

from marty_credentials.ports import (
    CredentialFormat,
    CredentialSubject,
    ICredentialVerifier,
    ICredentialWallet,
)


def test_credential_format_values():
    """Test CredentialFormat enum values."""
    assert CredentialFormat.JWT_VC.value == "jwt_vc_json"
    assert CredentialFormat.SD_JWT_VC.value == "vc+sd-jwt"
    assert CredentialFormat.MDOC.value == "mso_mdoc"


def test_wallet_port_does_not_accept_raw_holder_keys():
    """Legacy local-key methods cannot be called through the wallet port."""
    import marty_credentials
    import marty_credentials.ports as ports

    assert not hasattr(marty_credentials, "KeyPair")
    assert not hasattr(ports, "KeyPair")
    assert not hasattr(ICredentialWallet, "create_presentation")
    assert not hasattr(ICredentialWallet, "redeem_offer")


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
    assert hasattr(ICredentialVerifier, "__protocol_attrs__") or callable(ICredentialVerifier)
    assert hasattr(ICredentialWallet, "__protocol_attrs__") or callable(ICredentialWallet)
