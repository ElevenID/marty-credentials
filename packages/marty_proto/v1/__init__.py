"""Auto-generated protobuf and gRPC stubs for marty-ui services.

The generated modules are imported lazily to avoid circular-import traps during
service startup when a service requests one stub but the package would otherwise
eagerly import every other stub.
"""

from __future__ import annotations

from importlib import import_module

_SUBMODULES = {
    "auth_service_pb2",
    "auth_service_pb2_grpc",
    "credential_template_service_pb2",
    "credential_template_service_pb2_grpc",
    "document_signer_pb2",
    "document_signer_pb2_grpc",
    "event_stream_service_pb2",
    "event_stream_service_pb2_grpc",
    "flow_service_pb2",
    "flow_service_pb2_grpc",
    "issuance_service_pb2",
    "issuance_service_pb2_grpc",
    "notification_service_pb2",
    "notification_service_pb2_grpc",
    "organization_service_pb2",
    "organization_service_pb2_grpc",
    "presentation_policy_service_pb2",
    "presentation_policy_service_pb2_grpc",
    "revocation_profile_service_pb2",
    "revocation_profile_service_pb2_grpc",
    "verification_service_pb2",
    "verification_service_pb2_grpc",
}

__all__ = sorted(_SUBMODULES)


def __getattr__(name: str):
    if name in _SUBMODULES:
        module = import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + list(_SUBMODULES))
