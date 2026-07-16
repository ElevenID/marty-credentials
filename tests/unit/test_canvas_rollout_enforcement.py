from __future__ import annotations

import hashlib

import pytest
from fastapi import HTTPException
from issuance.domain.entities import (
    CanvasLtiLaunchState,
    CanvasOAuthAuthorization,
    CanvasPlatform,
    CanvasProgramBinding,
    CredentialDeliveryRecord,
    DeliveryTarget,
    IssuanceTransaction,
    IssuedCredential,
)
from issuance.infrastructure.adapters.canvas_credentials_adapter import (
    publish_canvas_credential_mirror,
    sync_canvas_credential_status,
)
from issuance.infrastructure.adapters.memory_repository import (
    InMemoryIssuanceRepository,
)
from issuance.infrastructure.api import canvas_routes
from starlette.requests import Request


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1),
            "server": ("test", 443),
        }
    )


async def _platform_and_binding(
    repo: InMemoryIssuanceRepository,
) -> tuple[CanvasPlatform, CanvasProgramBinding]:
    platform = CanvasPlatform(
        id="rollout-platform",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url="https://school.instructure.com",
        enabled=True,
    )
    binding = CanvasProgramBinding(
        id="rollout-binding",
        organization_id=platform.organization_id,
        platform_id=platform.id,
        application_template_id="application-template-1",
        credential_template_id="credential-template-1",
        enabled=True,
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)
    return platform, binding


@pytest.fixture(autouse=True)
def _disable_portable_canvas_pilot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "false")
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1")


@pytest.mark.asyncio
async def test_draft_and_read_only_management_remain_available() -> None:
    repo = InMemoryIssuanceRepository()
    platform, _binding = await _platform_and_binding(repo)

    response = await canvas_routes.get_canvas_platform(
        platform_id=platform.id,
        trusted_organization_id=platform.organization_id,
        repo=repo,
    )

    assert response.id == platform.id
    assert response.organization_id == platform.organization_id


@pytest.mark.asyncio
async def test_activation_fails_before_readiness_or_background_enqueue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform, binding = await _platform_and_binding(repo)
    validation_called = False

    async def forbidden_validation(**_kwargs):
        nonlocal validation_called
        validation_called = True
        raise AssertionError("readiness must not run outside the rollout")

    monkeypatch.setattr(
        canvas_routes,
        "_validate_managed_canvas_binding",
        forbidden_validation,
    )

    with pytest.raises(HTTPException) as exc_info:
        await canvas_routes.activate_canvas_program_binding(
            binding_id=binding.id,
            trusted_organization_id=platform.organization_id,
            repo=repo,
        )

    assert exc_info.value.status_code == 404
    assert validation_called is False


@pytest.mark.asyncio
async def test_launch_entry_points_fail_before_oidc_state_is_created_or_consumed() -> None:
    repo = InMemoryIssuanceRepository()
    platform, _binding = await _platform_and_binding(repo)

    with pytest.raises(HTTPException) as login_error:
        await canvas_routes._initiate_canvas_lti_login(
            platform_id=platform.id,
            request=_request(),
            repo=repo,
            redirect_uri="https://issuer.example/lti/launch",
        )
    with pytest.raises(HTTPException) as launch_error:
        await canvas_routes._verify_canvas_lti_launch_submission(
            platform_id=platform.id,
            request=_request(),
            repo=repo,
        )

    assert login_error.value.status_code == 404
    assert launch_error.value.status_code == 404


@pytest.mark.asyncio
async def test_stale_lti_session_cannot_bootstrap_an_application() -> None:
    repo = InMemoryIssuanceRepository()
    platform, _binding = await _platform_and_binding(repo)
    launch_state = CanvasLtiLaunchState(
        platform_id=platform.id,
        organization_id=platform.organization_id,
        canvas_account_id=platform.canvas_account_id,
    )

    with pytest.raises(HTTPException) as exc_info:
        await canvas_routes._find_or_create_lti_application(
            repo=repo,
            launch_state=launch_state,
            verified_launch={},
            mip_primitives={},
            session_values={},
            request=canvas_routes.CanvasLtiApplicationBootstrapRequest(),
        )

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_oauth_start_and_catalog_fail_before_canvas_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform, _binding = await _platform_and_binding(repo)
    token_lookup_called = False

    async def forbidden_token_lookup(**_kwargs):
        nonlocal token_lookup_called
        token_lookup_called = True
        raise AssertionError("Canvas token lookup must not run outside the rollout")

    monkeypatch.setattr(canvas_routes, "_canvas_admin_token", forbidden_token_lookup)

    with pytest.raises(HTTPException) as oauth_error:
        await canvas_routes.start_canvas_oauth_connection(
            platform_id=platform.id,
            request=canvas_routes.CanvasOAuthStartRequest(
                client_id="client-1",
                client_secret_secret_id="secret-1",
                capabilities=["catalog"],
            ),
            trusted_organization_id=platform.organization_id,
            repo=repo,
        )
    with pytest.raises(HTTPException) as catalog_error:
        await canvas_routes.discover_canvas_scope(
            platform_id=platform.id,
            request=canvas_routes.CanvasScopeDiscoveryRequest(),
            trusted_organization_id=platform.organization_id,
            repo=repo,
        )

    assert oauth_error.value.status_code == 404
    assert catalog_error.value.status_code == 404
    assert token_lookup_called is False


@pytest.mark.asyncio
async def test_pending_oauth_callback_is_consumed_without_token_exchange(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform, _binding = await _platform_and_binding(repo)
    state = "rollout-state-" + ("x" * 32)
    authorization = CanvasOAuthAuthorization(
        organization_id=platform.organization_id,
        platform_id=platform.id,
        canvas_base_url=str(platform.canvas_base_url),
        platform_config_version=platform.config_version,
        client_id="client-1",
        client_secret_ref="org_secret://org-1/secret-1",
        state_hash=hashlib.sha256(state.encode("utf-8")).hexdigest(),
        capabilities=["catalog"],
        scopes=["url:GET|/api/v1/courses"],
        redirect_uri=canvas_routes._canvas_oauth_redirect_uri(),
    )
    await repo.save_canvas_oauth_authorization(authorization)
    exchange_called = False

    async def forbidden_exchange(**_kwargs):
        nonlocal exchange_called
        exchange_called = True
        raise AssertionError("Canvas token exchange must not run outside the rollout")

    monkeypatch.setattr(canvas_routes, "exchange_canvas_oauth_code", forbidden_exchange)

    response = await canvas_routes.complete_canvas_oauth_connection(
        code="authorization-code",
        state=state,
        repo=repo,
    )

    assert response.status_code == 303
    assert "error_code=oauth_rollout_disabled" in response.headers["location"]
    assert exchange_called is False
    assert await repo.consume_canvas_oauth_authorization(
        authorization.state_hash
    ) is None


@pytest.mark.asyncio
async def test_canvas_credentials_delivery_and_status_network_are_blocked() -> None:
    credential = IssuedCredential(
        id="credential-1",
        transaction_id="transaction-1",
        organization_id="org-1",
    )
    transaction = IssuanceTransaction(
        id=credential.transaction_id,
        organization_id=credential.organization_id,
        credential_template_id="credential-template-1",
    )
    platform = CanvasPlatform(
        id="platform-1",
        organization_id=credential.organization_id,
        canvas_account_id="account-1",
    )
    delivery = CredentialDeliveryRecord(
        id="delivery-1",
        credential_id=credential.id,
        transaction_id=transaction.id,
        organization_id=credential.organization_id,
        delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
    )

    with pytest.raises(RuntimeError, match="delivery is not enabled"):
        await publish_canvas_credential_mirror(
            credential=credential,
            transaction=transaction,
            platform=platform,
            delivery_record=delivery,
        )
    with pytest.raises(RuntimeError, match="delivery is not enabled"):
        await sync_canvas_credential_status(
            credential=credential,
            platform=platform,
            delivery_record=delivery,
            lifecycle_action="suspend",
        )
