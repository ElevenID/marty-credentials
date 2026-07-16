from issuance.application.canvas_runtime import (
    canvas_scope_matches,
    lti_verified_launch_to_canvas_scope,
)


def test_verified_custom_claim_supplies_numeric_canvas_identity() -> None:
    scope = lti_verified_launch_to_canvas_scope(
        {
            "subject": "opaque-lti-subject",
            "context": {"id": "opaque-context"},
            "raw_claims": {
                "https://purl.imsglobal.org/spec/lti/claim/custom": {
                    "canvas_user_id": "1234",
                    "canvas_course_id": "5678",
                    "canvas_account_id": "90",
                }
            },
        },
        canvas_account_id="fallback-account",
    )

    assert scope["subject_id"] == "opaque-lti-subject"
    assert scope["lti_subject"] == "opaque-lti-subject"
    assert scope["canvas_user_id"] == "1234"
    assert scope["canvas_course_id"] == "5678"
    assert scope["canvas_account_id"] == "90"


def test_lti_subject_is_never_used_as_numeric_canvas_user_id() -> None:
    scope = lti_verified_launch_to_canvas_scope(
        {"subject": "opaque-lti-subject", "context": {"id": "course"}},
        canvas_account_id="account",
    )

    assert "canvas_user_id" not in scope
    assert "user_id" not in scope
    assert not canvas_scope_matches({"canvas_user_id": "opaque-lti-subject"}, scope)
    assert canvas_scope_matches({"subject_id": "opaque-lti-subject"}, scope)
