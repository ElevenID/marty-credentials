"""Configuration management for marty-credentials"""
import os
from dataclasses import dataclass
from typing import Optional


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing"""
    pass


@dataclass
class CredentialsConfig:
    """Configuration for marty-credentials service"""
    
    # Base URLs
    achievement_base_url: str
    issuer_base_url: str
    credential_status_base_url: str
    
    # Database
    database_url: str
    
    # Cache
    redis_url: str
    cache_ttl_seconds: int = 300
    
    # OAuth2
    token_validation_endpoint: Optional[str] = None
    oauth_client_id: Optional[str] = None
    oauth_client_secret: Optional[str] = None
    
    # Events
    kafka_bootstrap_servers: Optional[str] = None
    event_topic_prefix: str = "marty.credentials.events"
    
    # Rate Limiting
    rate_limit_per_minute: int = 100
    rate_limit_window_seconds: int = 60
    
    # mDoc Verification
    trusted_mdoc_issuer_certs_path: Optional[str] = None
    
    # Feature Flags
    dev_mode: bool = False
    enable_metrics: bool = True
    enable_rate_limiting: bool = True
    enable_token_validation: bool = True
    enable_event_publishing: bool = True
    
    @classmethod
    def from_env(cls) -> "CredentialsConfig":
        """Load configuration from environment variables"""
        # Required configuration
        required_vars = {
            "DATABASE_URL": os.getenv("DATABASE_URL"),
            "REDIS_URL": os.getenv("REDIS_URL"),
        }
        
        missing = [k for k, v in required_vars.items() if not v]
        if missing:
            raise ConfigurationError(
                f"Missing required environment variables: {', '.join(missing)}"
            )
        
        # Optional with defaults
        return cls(
            # Base URLs (use defaults for dev mode)
            achievement_base_url=os.getenv(
                "ACHIEVEMENT_BASE_URL",
                "https://achievements.marty.dev"
            ),
            issuer_base_url=os.getenv(
                "ISSUER_BASE_URL",
                "https://issuer.marty.dev"
            ),
            credential_status_base_url=os.getenv(
                "STATUS_LIST_BASE_URL",
                "https://api.marty.dev"
            ),
            
            # Database
            database_url=required_vars["DATABASE_URL"],
            
            # Cache
            redis_url=required_vars["REDIS_URL"],
            cache_ttl_seconds=int(os.getenv("CACHE_TTL_SECONDS", "300")),
            
            # OAuth2
            token_validation_endpoint=os.getenv("TOKEN_VALIDATION_ENDPOINT"),
            oauth_client_id=os.getenv("OAUTH_CLIENT_ID"),
            oauth_client_secret=os.getenv("OAUTH_CLIENT_SECRET"),
            
            # Events
            kafka_bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS"),
            event_topic_prefix=os.getenv(
                "EVENT_TOPIC_PREFIX",
                "marty.credentials.events"
            ),
            
            # Rate Limiting
            rate_limit_per_minute=int(os.getenv("RATE_LIMIT_PER_MINUTE", "100")),
            rate_limit_window_seconds=int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60")),
            
            # mDoc Verification
            trusted_mdoc_issuer_certs_path=os.getenv("TRUSTED_MDOC_ISSUER_CERTS_PATH"),
            
            # Feature Flags
            dev_mode=os.getenv("DEV_MODE", "false").lower() == "true",
            enable_metrics=os.getenv("ENABLE_METRICS", "true").lower() == "true",
            enable_rate_limiting=os.getenv("ENABLE_RATE_LIMITING", "true").lower() == "true",
            enable_token_validation=os.getenv("ENABLE_TOKEN_VALIDATION", "true").lower() == "true",
            enable_event_publishing=os.getenv("ENABLE_EVENT_PUBLISHING", "true").lower() == "true",
        )
    
    def validate(self) -> None:
        """Validate configuration consistency"""
        if self.enable_token_validation and not self.oauth_client_id:
            if not self.dev_mode:
                raise ConfigurationError(
                    "OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET required when token validation is enabled"
                )
        
        if self.enable_event_publishing and not self.kafka_bootstrap_servers:
            if not self.dev_mode:
                raise ConfigurationError(
                    "KAFKA_BOOTSTRAP_SERVERS required when event publishing is enabled"
                )


# Global configuration instance
_config: Optional[CredentialsConfig] = None


def get_config() -> CredentialsConfig:
    """Get the global configuration instance"""
    global _config
    if _config is None:
        _config = CredentialsConfig.from_env()
        _config.validate()
    return _config


def set_config(config: CredentialsConfig) -> None:
    """Set the global configuration instance (for testing)"""
    global _config
    _config = config
