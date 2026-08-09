import pytest

from issuance.application.application_approval import credential_context_from_template_snapshot


def test_canvas_credential_context_uses_validated_open_badge_snapshot() -> None:
    context = credential_context_from_template_snapshot(
        {
            "credential_type": "open_badge",
            "vct": "https://issuer.example/credentials/course-badge",
            "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
            "revocation_profile_id": "status-profile-1",
            "issuer_did": "did:web:issuer.example:orgs:org-1",
            "issuer_algorithm": "ES256",
            "wallet_configs": [{"credential_configuration_id": "open_badge#sd-jwt"}],
            "selective_disclosure_fields": ["achievement"],
            "validity_rules": {
                "default_validity_days": 730,
                "renewable": True,
                "renewal_window_days": 60,
            },
        }
    )

    assert context.credential_type == "open_badge"
    assert context.credential_payload_format == "w3c_vcdm_v2_sd_jwt"
    assert context.revocation_profile_id == "status-profile-1"
    assert context.issuer_did == "did:web:issuer.example:orgs:org-1"
    assert context.issuer_algorithm == "ES256"
    assert context.validity_days == 730
    assert context.renewable is True


@pytest.mark.parametrize(
    "missing",
    [
        "credential_type",
        "credential_payload_format",
        "revocation_profile_id",
        "issuer_did",
        "issuer_algorithm",
    ],
)
def test_canvas_credential_context_fails_closed_when_snapshot_is_incomplete(missing: str) -> None:
    snapshot = {
        "credential_type": "open_badge",
        "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
        "revocation_profile_id": "status-profile-1",
        "issuer_did": "did:web:issuer.example:orgs:org-1",
        "issuer_algorithm": "ES256",
    }
    snapshot.pop(missing)

    with pytest.raises(ValueError, match=missing):
        credential_context_from_template_snapshot(snapshot)


def test_canvas_credential_context_ignores_private_routing_selectors() -> None:
    context = credential_context_from_template_snapshot(
        {
            "credential_type": "open_badge_v2",
            "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
            "revocation_profile_id": "status-profile-1",
            "issuer_did": "did:web:issuer.example:orgs:org-1",
            "issuer_algorithm": "ES256",
            "issuer_profile_id": "attacker-selected-profile",
            "issuer_key_id": "attacker-selected-key",
            "key_access_mode": "LOCAL_PRIVATE_KEY",
            "remote_signing_config": {"provider": "attacker"},
        }
    )

    assert context.credential_type == "open_badge_v2"
    assert context.issuer_did == "did:web:issuer.example:orgs:org-1"
    assert not hasattr(context, "issuer_profile_id")
    assert not hasattr(context, "issuer_key_id")
