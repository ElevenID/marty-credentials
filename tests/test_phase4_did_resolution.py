"""Issuance regression retained from the retired Phase 4 verifier suite."""

from issuance.domain.entities import IssuedCredential


class TestIssuedCredentialIssuerDid:
    """Validate the issuer DID persisted with an issued credential."""

    def test_defaults_to_none(self) -> None:
        credential = IssuedCredential()

        assert credential.issuer_did is None

    def test_stores_issuer_did(self) -> None:
        credential = IssuedCredential(issuer_did="did:web:beta.elevenidllc.com:orgs:acme")

        assert credential.issuer_did == "did:web:beta.elevenidllc.com:orgs:acme"

    def test_stores_did_key_issuer(self) -> None:
        credential = IssuedCredential(
            issuer_did="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        )

        assert credential.issuer_did.startswith("did:key:")
