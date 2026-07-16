from datetime import UTC, datetime

from issuance.domain.entities import EvidenceFact
from issuance.infrastructure.api.application_routes import _evidence_fact_to_response


def test_evidence_fact_response_exposes_canvas_revision_head_metadata() -> None:
    observed_at = datetime(2026, 7, 15, 8, 30, tzinfo=UTC)
    fact = EvidenceFact(
        id="fact-current",
        organization_id="org-1",
        application_id="application-1",
        subject_id="learner-1",
        provider="canvas",
        fact_type="canvas.assignment_score",
        scope={"course_id": "course-1", "activity_id": "assignment-1"},
        assertion={"score_percent": 95},
        verification={"status": "VERIFIED"},
        source={"source": "canvas_rest"},
        requirement_id="native-assignment",
        logical_key="logical-assignment",
        source_revision="revision-2",
        payload_hash="payload-2",
        observed_at=observed_at,
        effective_at=observed_at,
        superseded_fact_id="fact-prior",
    )

    response = _evidence_fact_to_response(fact)

    assert response.requirement_id == "native-assignment"
    assert response.logical_key == "logical-assignment"
    assert response.source_revision == "revision-2"
    assert response.payload_hash == "payload-2"
    assert response.observed_at == observed_at.isoformat()
    assert response.effective_at == observed_at.isoformat()
    assert response.superseded_fact_id == "fact-prior"
