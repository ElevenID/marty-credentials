"""Production rollout gates for the portable Canvas integration."""

from __future__ import annotations

import os


def _enabled(name: str, *, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def portable_canvas_enabled() -> bool:
    """Return whether the global portable-Canvas kill switch is open."""

    return _enabled("CANVAS_PORTABLE_INTEGRATION_ENABLED")


def canvas_pilot_organizations() -> frozenset[str]:
    """Return the explicit organization allowlist for the controlled pilot."""

    return frozenset(
        value.strip()
        for value in os.environ.get("CANVAS_PILOT_ORGANIZATION_IDS", "").split(",")
        if value.strip()
    )


def portable_canvas_enabled_for_organization(organization_id: str | None) -> bool:
    organization = str(organization_id or "").strip()
    return bool(
        portable_canvas_enabled()
        and organization
        and organization in canvas_pilot_organizations()
    )


def legacy_canvas_event_ingest_enabled() -> bool:
    """Compatibility switch for institution-specific inbound event adapters."""

    return _enabled("CANVAS_LEGACY_EVENT_INGEST_ENABLED")


def private_canvas_origin_allowlist() -> frozenset[str]:
    """Return operator-managed origins allowed to resolve to private networks."""

    return frozenset(
        value.strip().rstrip("/").lower()
        for value in os.environ.get("CANVAS_PRIVATE_ORIGIN_ALLOWLIST", "").split(",")
        if value.strip()
    )


def self_managed_canvas_origin_allowlist() -> frozenset[str]:
    """Return exact Canvas origins approved for same-origin LTI trust.

    This is deliberately separate from the private-network allowlist. A public
    self-managed Canvas deployment still needs an explicit trust-mode decision,
    while a private deployment must appear in both allowlists.
    """

    return frozenset(
        value.strip().rstrip("/").lower()
        for value in os.environ.get("CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST", "").split(",")
        if value.strip()
    )
