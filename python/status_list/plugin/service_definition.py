"""
Status List Plugin Service Definition

MMF plugin service that registers the status list feature
with the Marty Modular Framework.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from status_list.plugin.config import StatusListPluginConfig
from status_list.domain.value_objects import ShardConfig
from status_list.application.services.status_list_service import StatusListService
from status_list.application.services.credential_status_service import CredentialStatusService
from status_list.application.services.status_list_credential_service import StatusListCredentialService
from status_list.infrastructure.persistence.repository import (
    StatusListRepository,
    StatusEntryRepository,
)
from status_list.infrastructure.adapters.signing_adapter import RustSigningAdapter
from status_list.infrastructure.adapters.rest_adapter import create_status_list_router

logger = logging.getLogger(__name__)


class StatusListPluginService:
    """
    MMF Plugin Service for Status List feature.
    
    This service integrates the status list functionality with
    the Marty Modular Framework, handling:
    - Service initialization with dependency injection
    - Configuration management
    - Health checks
    - Lifecycle management
    
    Attributes:
        _name: Service name
        _version: Service version
        _config: Plugin configuration
        _initialized: Whether service is initialized
        _status_list_service: Core status list service
        _credential_status_service: Credential status service
        _status_list_credential_service: Status list credential service
    """
    
    def __init__(self, config: Optional[StatusListPluginConfig] = None) -> None:
        """
        Initialize the plugin service.
        
        Args:
            config: Optional plugin configuration
        """
        self._name = "status-list"
        self._version = "1.0.0"
        self._config = config or StatusListPluginConfig()
        self._initialized = False
        
        # Services (initialized later)
        self._status_list_service: Optional[StatusListService] = None
        self._credential_status_service: Optional[CredentialStatusService] = None
        self._status_list_credential_service: Optional[StatusListCredentialService] = None
        self._router = None
    
    @property
    def name(self) -> str:
        """Plugin service name."""
        return self._name
    
    @property
    def version(self) -> str:
        """Plugin service version."""
        return self._version
    
    @property
    def is_enabled(self) -> bool:
        """Check if the plugin is enabled."""
        return self._config.enabled
    
    @property
    def is_initialized(self) -> bool:
        """Check if the plugin is initialized."""
        return self._initialized
    
    async def initialize(self, context: Dict[str, Any]) -> None:
        """
        Initialize the plugin with MMF context.
        
        This is called by the MMF framework during startup.
        
        Args:
            context: MMF plugin context containing:
                - database: Database manager
                - event_bus: Event bus for publishing events
                - cache: Cache service (optional)
                - storage: Object storage (optional)
                - issuer_registry: Issuer registry for signing
        """
        if not self._config.enabled:
            logger.info("Status list plugin is disabled")
            return
        
        logger.info("Initializing status list plugin v%s", self._version)
        
        # Get dependencies from context
        database = context.get("database")
        event_bus = context.get("event_bus")
        cache = context.get("cache")
        storage = context.get("storage")
        issuer_registry = context.get("issuer_registry", {})
        
        if database is None:
            raise ValueError("Database manager required for status list plugin")
        
        # Create shard configuration
        shard_config = self._config.to_shard_config()
        
        # Get a database session factory
        async def get_session():
            async with database.session() as session:
                yield session
        
        # Initialize repositories with session from context
        # Note: In production, sessions would be managed per-request
        async with database.session() as session:
            status_list_repo = StatusListRepository(session)
            status_entry_repo = StatusEntryRepository(session)
            
            # Initialize signing adapter
            signing_adapter = RustSigningAdapter(
                issuer_registry=issuer_registry,
            )
            
            # Initialize application services
            self._status_list_service = StatusListService(
                status_list_repository=status_list_repo,
                status_entry_repository=status_entry_repo,
                event_publisher=event_bus,
                default_config=shard_config,
            )
            
            self._credential_status_service = CredentialStatusService(
                status_list_service=self._status_list_service,
                base_url=self._config.base_url,
            )
            
            self._status_list_credential_service = StatusListCredentialService(
                status_list_repository=status_list_repo,
                signing_service=signing_adapter,
                base_url=self._config.base_url,
                event_publisher=event_bus,
                cache=cache,
                storage=storage,
                config=shard_config,
            )
            
            # Create REST router
            self._router = create_status_list_router(
                status_list_service=self._status_list_service,
                credential_status_service=self._credential_status_service,
                status_list_credential_service=self._status_list_credential_service,
                config=shard_config,
            )
        
        self._initialized = True
        logger.info("Status list plugin initialized successfully")
    
    async def start(self) -> None:
        """Start the plugin service."""
        if not self._initialized:
            logger.warning("Status list plugin not initialized, skipping start")
            return
        
        logger.info("Status list plugin started")
    
    async def stop(self) -> None:
        """Stop the plugin service."""
        logger.info("Status list plugin stopped")
        self._initialized = False
    
    async def get_health_status(self) -> Dict[str, Any]:
        """
        Get the health status of the plugin.
        
        Returns:
            Health status dictionary
        """
        if not self._config.enabled:
            return {
                "status": "disabled",
                "name": self._name,
                "version": self._version,
            }
        
        if not self._initialized:
            return {
                "status": "not_initialized",
                "name": self._name,
                "version": self._version,
            }
        
        return {
            "status": "healthy",
            "name": self._name,
            "version": self._version,
            "config": {
                "base_url": self._config.base_url,
                "shard_size_bits": self._config.shard_size_bits,
                "cache_ttl_seconds": self._config.cache_ttl_seconds,
            },
        }
    
    def get_router(self):
        """
        Get the FastAPI router for this plugin.
        
        Returns:
            FastAPI APIRouter instance
        """
        return self._router
    
    def get_services(self) -> Dict[str, Any]:
        """
        Get the services provided by this plugin.
        
        Returns:
            Dictionary of service name to service instance
        """
        return {
            "status_list_service": self._status_list_service,
            "credential_status_service": self._credential_status_service,
            "status_list_credential_service": self._status_list_credential_service,
        }
    
    def get_credential_status_service(self) -> Optional[CredentialStatusService]:
        """
        Get the credential status service.
        
        This is the main service used by other modules (e.g., Open Badges)
        to integrate with status list functionality.
        
        Returns:
            CredentialStatusService if initialized, None otherwise
        """
        return self._credential_status_service
