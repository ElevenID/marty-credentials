from issuance.application.credential_vct import resolve_credential_vct


def test_resolve_credential_vct_preserves_profile_urn() -> None:
    assert (
        resolve_credential_vct(
            "urn:eudi:pid:1",
            "PID",
            "https://issuer.example",
        )
        == "urn:eudi:pid:1"
    )


def test_resolve_credential_vct_preserves_absolute_https_uri() -> None:
    assert (
        resolve_credential_vct(
            "https://issuer.example/types/employee",
            "EmployeeCredential",
            "https://issuer.example",
        )
        == "https://issuer.example/types/employee"
    )


def test_resolve_credential_vct_derives_fallback_for_missing_or_relative_value() -> None:
    assert (
        resolve_credential_vct(None, "PID", "https://issuer.example/")
        == "https://issuer.example/credentials/PID"
    )
    assert (
        resolve_credential_vct("PID", "PID", "https://issuer.example/")
        == "https://issuer.example/credentials/PID"
    )
