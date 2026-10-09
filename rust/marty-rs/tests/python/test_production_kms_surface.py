import _marty_rs


def test_production_module_excludes_local_private_key_operations():
    forbidden = {
        "generate_did_key",
        "generate_p256_key",
        "generate_p256_jwk",
        "generate_p384_key",
        "generate_rsa_key",
        "create_presentation",
        "create_verifiable_credential",
        "create_mdoc",
        "SdJwtBuilder",
        "SdJwtPresentation",
        "create_sd_jwt",
        "generate_bls12381_key",
        "bbs_sign",
        "issue_emrtd_passport",
        "issue_emrtd_passport_self_signed",
        "verify_jwt",  # Claims-only parsing must not masquerade as signature verification.
    }

    assert forbidden.isdisjoint(dir(_marty_rs))
    for safe_name in (
        "prepare_mdoc_for_hsm",
        "complete_mdoc_with_signature",
        "SdJwtVerifier",
        "verify_sd_jwt",
        "bbs_verify",
        "verify_vcdm_jwt",
    ):
        assert hasattr(_marty_rs, safe_name), safe_name
