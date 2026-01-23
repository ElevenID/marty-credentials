"""
MMF Plugin Layer - Status List

Contains the MMF plugin registration for the status list feature.
"""

from status_list.plugin.service_definition import StatusListPluginService
from status_list.plugin.config import StatusListPluginConfig

__all__ = [
    "StatusListPluginService",
    "StatusListPluginConfig",
]
