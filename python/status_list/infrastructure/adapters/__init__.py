"""
Infrastructure Adapters - Status List

Contains adapters for external systems including:
- REST API adapters
- Cache adapters
"""

from status_list.infrastructure.adapters.rest_adapter import StatusListRouter

__all__ = [
    "StatusListRouter",
]
