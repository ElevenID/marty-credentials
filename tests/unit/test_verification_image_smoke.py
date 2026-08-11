from __future__ import annotations

import pytest

from scripts.smoke_verification_image import SmokeError, build_governance, smoke

IMAGE = "ghcr.io/elevenid/marty-credentials-verification@sha256:" + "a" * 64
POSTGRES = "docker.io/library/postgres@sha256:" + "b" * 64


def test_governance_binds_the_candidate_image_digest() -> None:
    governance = build_governance(IMAGE, "test-api-key")

    assert governance["component"]["artifact_digest"] == "sha256:" + "a" * 64
    assert len(governance["clients"][0]["api_key_sha256"]) == 64
    assert governance["policies"][0]["content"]["required_checks"] == [
        "presentation.structure",
        "presentation.proof",
        "credential.proof",
        "issuer.trust",
        "credential.status",
        "holder.binding",
        "transaction.binding",
        "claim.constraints",
    ]


def test_governance_accepts_an_immutable_local_image_id() -> None:
    governance = build_governance("sha256:" + "c" * 64, "test-api-key")

    assert governance["component"]["artifact_digest"] == "sha256:" + "c" * 64


@pytest.mark.parametrize(
    ("image", "postgres"),
    [
        ("ghcr.io/elevenid/verifier:latest", POSTGRES),
        (IMAGE, "postgres:latest"),
    ],
)
def test_smoke_rejects_mutable_image_references(image: str, postgres: str) -> None:
    with pytest.raises(SmokeError, match="pinned"):
        smoke(image, postgres)
