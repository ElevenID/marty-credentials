import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "python"))

from issuance.domain.entities import CredentialStatus
from issuance.infrastructure.api import routes


@pytest.mark.asyncio
async def test_credential_status_identifies_authoritative_issuer() -> None:
    credential = SimpleNamespace(
        id="urn:uuid:credential-123",
        issuer_did="did:jwk:issuer-key",
        status=CredentialStatus.ACTIVE,
        status_updated_at=datetime(2026, 7, 12, tzinfo=timezone.utc),
        revocation_reason=None,
    )
    repo = SimpleNamespace(get_credential=lambda _credential_id: None)

    async def get_credential(_credential_id: str):
        return credential

    repo.get_credential = get_credential

    response = await routes.get_credential_status(credential.id, repo=repo)

    assert response == {
        "id": credential.id,
        "issuer_did": "did:jwk:issuer-key",
        "status": "active",
        "status_updated_at": "2026-07-12T00:00:00+00:00",
        "reason": None,
    }
