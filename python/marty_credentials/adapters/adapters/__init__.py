"""
Marty Plugin Adapters

This package contains adapter implementations for various external services
and vendor-specific integrations.

Structure:
- credentials/ - Credential adapter implementations (SpruceID, Multipaz)
"""

from . import credentials

__all__ = ["credentials"]
