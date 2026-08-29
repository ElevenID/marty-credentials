from __future__ import annotations

from datetime import datetime
from typing import Any


def merge_verified_lti_binding_capabilities(
    *,
    capability_snapshot: dict[str, Any],
    launch_capabilities: dict[str, Any],
    binding_id: str,
    binding_config_version: int,
    signed_course_id: str,
    line_item_configuration_changed: bool,
    verified_at: datetime,
) -> dict[str, Any]:
    launches = (
        dict(capability_snapshot.get("verified_binding_launches") or {})
        if isinstance(capability_snapshot.get("verified_binding_launches"), dict)
        else {}
    )
    prior = (
        dict(launches.get(binding_id) or {}) if isinstance(launches.get(binding_id), dict) else {}
    )
    try:
        prior_version = int(prior.get("verified_binding_config_version"))
    except (TypeError, ValueError):
        prior_version = -1
    prior_course_id = str(prior.get("verified_course_id") or "").strip()
    can_carry_prior = bool(
        prior.get("verified_binding_id") == binding_id
        and prior_course_id == signed_course_id
        and (
            prior_version == binding_config_version
            or (line_item_configuration_changed and prior_version == binding_config_version - 1)
        )
    )
    binding_capabilities = prior if can_carry_prior else {}
    # Course-navigation launches can omit AGS while resource launches can omit
    # NRPS. Preserve verified positive claims for the same binding/course/config.
    for key, value in launch_capabilities.items():
        if (
            value is not None and value != "" and value is not False and value != []
        ) or key not in binding_capabilities:
            binding_capabilities[key] = value
    verified_line_items = {
        str(value).strip()
        for value in binding_capabilities.get("verified_ags_line_items", [])
        if str(value).strip()
    }
    current_line_item = str(launch_capabilities.get("ags_lineitem_url") or "").strip()
    if current_line_item:
        verified_line_items.add(current_line_item)
    binding_capabilities.update(
        {
            "verified_binding_id": binding_id,
            "verified_binding_config_version": binding_config_version,
            "verified_course_id": signed_course_id,
            "verified_at": verified_at.isoformat(),
            "verified_ags_line_items": sorted(verified_line_items),
        }
    )
    launches[binding_id] = binding_capabilities
    # Keep last-launch fields for diagnostics/backward-compatible display;
    # authorization decisions consume the binding-indexed snapshot.
    return {
        **launch_capabilities,
        "verified_binding_id": binding_id,
        "verified_binding_config_version": binding_config_version,
        "verified_course_id": signed_course_id,
        "verified_at": verified_at.isoformat(),
        "verified_binding_launches": launches,
    }
