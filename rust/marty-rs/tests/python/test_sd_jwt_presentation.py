"""First-party regressions for the local Marty Python extension."""

from _marty_rs import SdJwtBuilder, SdJwtPresentation

_P256_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1Cek3aG+/jXX18nM
GCGseS2pT1GVwVJANTXqpPV7vsehRANCAAQ1Wc5LabMdwXpyPeC4SUuM5+8Kkzhu
JYxIARckk60pPjOAsKo8/yd9Sm1JIQ2Cc8FD6D3DQvyOZPyLiFcxDkHA
-----END PRIVATE KEY-----
"""


def _tamper_issuer_signature(sd_jwt: str) -> str:
    jwt_and_disclosures = sd_jwt.split("~")
    jwt = jwt_and_disclosures[0].split(".")
    replacement = "B" if jwt[2].startswith("A") else "A"
    jwt[2] = replacement + jwt[2][1:]
    jwt_and_disclosures[0] = ".".join(jwt)
    return "~".join(jwt_and_disclosures)


def test_python_presentation_boundary_preserves_caller_preverified_input() -> None:
    builder = SdJwtBuilder("https://issuer.example.com")
    builder.add_disclosable_claim("given_name", "Alice")
    issued = builder.build(_P256_PRIVATE_KEY, "ES256")
    disclosure = issued.split("~")[1]
    tampered = _tamper_issuer_signature(issued)

    presentation_builder = SdJwtPresentation(tampered)
    presentation_builder.disclose_claim("given_name")
    presentation = presentation_builder.create_presentation()

    assert presentation.split("~")[0] == tampered.split("~")[0]
    assert disclosure in presentation.split("~")[1:-1]
    assert presentation.endswith("~")
