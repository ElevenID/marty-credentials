from issuance.application.canvas_feature_flags import (
    canvas_pilot_organizations,
    legacy_canvas_event_ingest_enabled,
    portable_canvas_enabled_for_organization,
    private_canvas_origin_allowlist,
)


def test_portable_canvas_requires_global_switch_and_explicit_org(monkeypatch):
    monkeypatch.delenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", raising=False)
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1, org-2")
    assert not portable_canvas_enabled_for_organization("org-1")

    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
    assert portable_canvas_enabled_for_organization("org-1")
    assert not portable_canvas_enabled_for_organization("org-3")
    assert canvas_pilot_organizations() == frozenset({"org-1", "org-2"})


def test_legacy_ingest_is_default_off(monkeypatch):
    monkeypatch.delenv("CANVAS_LEGACY_EVENT_INGEST_ENABLED", raising=False)
    assert not legacy_canvas_event_ingest_enabled()
    monkeypatch.setenv("CANVAS_LEGACY_EVENT_INGEST_ENABLED", "1")
    assert legacy_canvas_event_ingest_enabled()


def test_private_origin_allowlist_is_normalized(monkeypatch):
    monkeypatch.setenv(
        "CANVAS_PRIVATE_ORIGIN_ALLOWLIST",
        "https://canvas.internal.example/, HTTPS://CANVAS.PARTNER.EXAMPLE",
    )
    assert private_canvas_origin_allowlist() == frozenset(
        {"https://canvas.internal.example", "https://canvas.partner.example"}
    )
