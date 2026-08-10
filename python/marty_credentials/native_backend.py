"""Canonical fail-closed loader for the Marty credential native extension."""

from __future__ import annotations

import importlib
from importlib import metadata
from types import ModuleType
from typing import Iterable


class NativeBackendUnavailable(RuntimeError):
    """Raised when the required native credential backend cannot be used."""


class NativeOperationError(RuntimeError):
    """Raised when a requested operation has no supported native implementation."""


def _require_backend(module_name: str, capabilities: Iterable[str]) -> ModuleType:
    """Load a native module and verify every requested callable capability."""
    try:
        backend = importlib.import_module(module_name)
    except ImportError as exc:
        raise NativeBackendUnavailable(
            f"The {module_name} native extension is required"
        ) from exc

    missing = sorted(
        capability
        for capability in capabilities
        if not callable(getattr(backend, capability, None))
    )
    if missing:
        raise NativeBackendUnavailable(
            f"The {module_name} native extension is missing required capabilities: "
            + ", ".join(missing)
        )
    return backend


def require_marty_rs(capabilities: Iterable[str] = ()) -> ModuleType:
    """Load the one supported extension surface and validate its contract."""
    return _require_backend("_marty_rs", capabilities)


def require_marty_verification(capabilities: Iterable[str] = ()) -> ModuleType:
    """Load the canonical verification extension and validate its contract."""
    return _require_backend("marty_verification", capabilities)


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


def marty_verification_diagnostic(
    capabilities: Iterable[str] = (),
) -> dict[str, object]:
    """Return verification backend/version details for service health checks."""
    required = tuple(capabilities)
    try:
        backend = require_marty_verification(required)
    except NativeBackendUnavailable as exc:
        return {
            "available": False,
            "module": "marty_verification",
            "version": None,
            "missing_capabilities": list(required),
            "error": str(exc),
        }
    try:
        version = metadata.version("marty-verification")
    except metadata.PackageNotFoundError:
        version = getattr(backend, "__version__", None)
    return {
        "available": True,
        "module": "marty_verification",
        "version": version,
        "missing_capabilities": [],
        "error": None,
    }
