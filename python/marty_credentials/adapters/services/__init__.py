"""Production-safe service adapters for credential operations."""

from .verification_service import VerificationService

__all__ = ["VerificationService"]


def __getattr__(name: str) -> object:
    if name == "IssuanceService":
        raise AttributeError(
            "IssuanceService is an explicit local-key compatibility adapter; "
            "production issuers must use the KMS-backed issuance service"
        )
    raise AttributeError(name)
