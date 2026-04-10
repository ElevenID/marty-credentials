"""Event publishing infrastructure"""
import json
import logging
from abc import ABC, abstractmethod
from typing import Optional

from marty_credentials.config import get_config
from marty_credentials.infrastructure.events import DomainEvent

logger = logging.getLogger(__name__)


class EventPublisherPort(ABC):
    """Port for publishing domain events"""
    
    @abstractmethod
    async def publish(self, event: DomainEvent) -> None:
        """Publish a domain event
        
        Args:
            event: The domain event to publish
        """
        pass


class LoggingEventPublisher(EventPublisherPort):
    """Event publisher that logs events (for development/testing)"""
    
    async def publish(self, event: DomainEvent) -> None:
        """Log the event"""
        logger.info(
            f"Event published: {event.event_type}",
            extra={
                "event_id": event.event_id,
                "event_type": event.event_type,
                "event_timestamp": event.event_timestamp.isoformat(),
                "event_data": event.__dict__
            }
        )


class KafkaEventPublisher(EventPublisherPort):
    """Event publisher that publishes to Kafka (production)"""
    
    def __init__(self, topic_prefix: Optional[str] = None):
        """Initialize Kafka event publisher
        
        Args:
            topic_prefix: Prefix for Kafka topics (defaults to config value)
        """
        config = get_config()
        self.topic_prefix = topic_prefix or config.event_topic_prefix
        self._producer = None
        
        # Lazy initialization - only create producer when needed
        if config.enable_event_publishing and config.kafka_bootstrap_servers:
            try:
                from aiokafka import AIOKafkaProducer
                self._producer_class = AIOKafkaProducer
                self._bootstrap_servers = config.kafka_bootstrap_servers
            except ImportError:
                logger.warning(
                    "aiokafka not installed. Install with: pip install aiokafka"
                )
                self._producer_class = None
        else:
            logger.info("Event publishing disabled or Kafka not configured")
    
    async def _ensure_producer(self):
        """Ensure producer is initialized"""
        if self._producer is None and self._producer_class:
            self._producer = self._producer_class(
                bootstrap_servers=self._bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None
            )
            await self._producer.start()
            logger.info("Kafka producer started")
    
    async def publish(self, event: DomainEvent) -> None:
        """Publish event to Kafka
        
        Args:
            event: The domain event to publish
        """
        await self._ensure_producer()
        
        if self._producer is None:
            # Kafka unavailable — log at error level since events will be lost
            logger.error(
                "Kafka producer not available, event DROPPED: %s (event_id=%s). "
                "Configure kafka_bootstrap_servers and ensure aiokafka is installed.",
                event.event_type,
                event.event_id,
                extra={"event": event.__dict__},
            )
            return
        
        # Determine topic from event type
        # e.g., "credential.issued" -> "marty.credentials.events.credential.issued"
        topic = f"{self.topic_prefix}.{event.event_type}"
        
        # Serialize event to dict
        event_data = {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "event_timestamp": event.event_timestamp.isoformat(),
            **{k: v for k, v in event.__dict__.items() 
               if k not in ['event_id', 'event_type', 'event_timestamp']}
        }
        
        # Use credential_id or event_id as message key for partitioning
        key = None
        if hasattr(event, 'credential_id'):
            key = event.credential_id
        elif hasattr(event, 'request_id'):
            key = event.request_id
        
        try:
            await self._producer.send_and_wait(topic, value=event_data, key=key)
            logger.debug(
                f"Published event to Kafka: {event.event_type}",
                extra={"topic": topic, "event_id": event.event_id}
            )
        except Exception as e:
            logger.error(
                f"Failed to publish event to Kafka: {e}",
                extra={"event": event_data, "error": str(e)}
            )
            raise
    
    async def close(self):
        """Close the Kafka producer"""
        if self._producer:
            await self._producer.stop()
            logger.info("Kafka producer stopped")


def create_event_publisher() -> EventPublisherPort:
    """Factory function to create the appropriate event publisher based on configuration
    
    Returns:
        EventPublisherPort implementation
    """
    config = get_config()
    
    if not config.enable_event_publishing:
        logger.info("Event publishing disabled, using logging publisher")
        return LoggingEventPublisher()
    
    if config.dev_mode or not config.kafka_bootstrap_servers:
        logger.info("Development mode or Kafka not configured, using logging publisher")
        return LoggingEventPublisher()
    
    logger.info("Production mode with Kafka configured, using Kafka publisher")
    return KafkaEventPublisher()
