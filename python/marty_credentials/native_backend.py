"""Canonical fail-closed loader for the Marty credential native extension."""

from __future__ import annotations

import importlib
from importlib import metadata
from types import ModuleType
from typing import Iterable


class NativeBackendUnavailable(RuntimeError):
    """Raised when the required native credential backend cannot be used."""


def require_marty_rs(capabilities: Iterable[str] = ()) -> ModuleType:
    """Load the one supported extension surface and validate its contract."""
    try:
        backend = importlib.import_module("_marty_rs")
    except ImportError as exc:
        raise NativeBackendUnavailable(
            "The _marty_rs native extension is required"
        ) from exc

    missing = sorted(
        capability
        for capability in capabilities
        if not callable(getattr(backend, capability, None))
    )
    if missing:
        raise NativeBackendUnavailable(
            "The _marty_rs native extension is missing required capabilities: "
            + ", ".join(missing)
        )
    return backend


def marty_rs_diagnostic(capabilities: Iterable[str] = ()) -> dict[str, object]:
    """Return backend/version details suitable for service health endpoints."""
    required = tuple(capabilities)
    try:
        backend = require_marty_rs(required)
    except NativeBackendUnavailable as exc:
        return {
            "available": False,
            "module": "_marty_rs",
            "version": None,
            "missing_capabilities": list(required),
            "error": str(exc),
        }
    try:
        version = metadata.version("marty-rs")
    except metadata.PackageNotFoundError:
        version = getattr(backend, "__version__", None)
    return {
        "available": True,
        "module": "_marty_rs",
        "version": version,
        "missing_capabilities": [],
        "error": None,
    }
