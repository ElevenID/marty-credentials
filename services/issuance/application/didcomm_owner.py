"""Closed configuration for the DIDComm delivery implementation owner.

The legacy Python service remains the default for standalone deployments.  A
deployment that supplies the native Rust issuance service may select it
explicitly; that selection is fail-closed and never falls back to Python.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse

_OWNER_ENV = "DIDCOMM_DELIVERY_OWNER"
_NATIVE_URL_ENV = "ISSUANCE_NATIVE_SERVICE_URL"


@dataclass(frozen=True)
class DidcommDeliveryOwner:
    name: str
    native_service_url: str | None

    @property
    def is_native(self) -> bool:
        return self.name == "native"

    def endpoint(self, path: str) -> str:
        if not self.is_native or self.native_service_url is None:
            raise RuntimeError("Native DIDComm delivery is not selected")
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("Native issuance path must be absolute")
        return f"{self.native_service_url}{path}"


def didcomm_delivery_owner() -> DidcommDeliveryOwner:
    """Return the validated, deployment-owned DIDComm delivery selector."""

    owner = os.environ.get(_OWNER_ENV, "legacy").strip().lower()
    if owner not in {"legacy", "native"}:
        raise RuntimeError(f"{_OWNER_ENV} must be either legacy or native")

    configured_url = os.environ.get(_NATIVE_URL_ENV, "").strip()
    if owner == "legacy":
        return DidcommDeliveryOwner(name=owner, native_service_url=None)
    if not configured_url:
        raise RuntimeError(f"{_NATIVE_URL_ENV} is required when {_OWNER_ENV}=native")

    parsed = urlparse(configured_url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError(f"{_NATIVE_URL_ENV} has an invalid port") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or (port is not None and port == 0)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise RuntimeError(
            f"{_NATIVE_URL_ENV} must be an HTTP(S) origin without credentials, "
            "path, query, or fragment"
        )
    return DidcommDeliveryOwner(
        name=owner,
        native_service_url=configured_url.rstrip("/"),
    )
