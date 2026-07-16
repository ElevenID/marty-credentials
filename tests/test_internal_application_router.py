from pydantic import ValidationError
import pytest

from issuance.infrastructure.api.routes import (
    ApplicationApproval,
    ApplicationRejection,
)
from issuance.infrastructure.api.application_routes import internal_application_router


def test_application_engine_is_internal_only() -> None:
    paths = {route.path for route in internal_application_router.routes}

    assert paths
    assert all(path.startswith("/internal/applications") for path in paths)
    assert all(not path.startswith("/v1/applications") for path in paths)


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (ApplicationApproval, {"reviewer_id": "spoofed"}),
        (ApplicationRejection, {"review_notes": "No", "reviewer_id": "spoofed"}),
    ],
)
def test_internal_decisions_reject_caller_supplied_reviewer_identity(model, payload) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(payload)
