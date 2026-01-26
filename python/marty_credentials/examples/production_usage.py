"""Example usage patterns for production-ready credential operations"""
import asyncio
from datetime import datetime
from uuid import uuid4

from redis.asyncio import Redis
from sqlalchemy.orm import Session

from marty_credentials.adapters.services.issuance_service import IssuanceService
from marty_credentials.adapters.services.verification_service import VerificationService
from marty_credentials.config import get_config
from marty_credentials.infrastructure.events import (
    CredentialIssuedEvent,
    CredentialVerifiedEvent,
    CredentialVerificationFailedEvent,
)
from marty_credentials.infrastructure.events.publisher import create_event_publisher
from marty_credentials.infrastructure.observability.rate_limiter import (
    RateLimiter,
    RateLimitExceededError,
)


async def example_credential_issuance_with_rate_limiting(
    db_session: Session,
    issuer_did: str,
    subject_did: str,
    credential_type: str,
    claims: dict,
):
    """Example: Issue credential with rate limiting and event publishing"""
    
    # Setup
    config = get_config()
    redis_client = Redis.from_url(config.redis_url, decode_responses=False)
    rate_limiter = RateLimiter(
        redis_client,
        default_limit=config.rate_limit_per_minute,
        window_seconds=config.rate_limit_window_seconds,
    )
    event_publisher = create_event_publisher()
    issuance_service = IssuanceService(db_session)
    
    try:
        # Check rate limit for issuer
        await rate_limiter.check_rate_limit(
            key=f"issuer:{issuer_did}",
            resource_type="issuer",
            resource_id=issuer_did,
        )
        
        # Issue credential (metrics automatically tracked)
        result = issuance_service.issue_w3c_vc(
            issuer_did=issuer_did,
            subject_did=subject_did,
            credential_type=credential_type,
            claims=claims,
            expiry_hours=24,
        )
        
        # Publish event
        await event_publisher.publish(
            CredentialIssuedEvent(
                event_id=str(uuid4()),
                event_timestamp=datetime.utcnow(),
                event_type="credential.issued",
                credential_id=str(result["credential_id"]),
                credential_type=credential_type,
                format=result["format"],
                issuer_id=issuer_did,
                holder_id=subject_did,
            )
        )
        
        return result
        
    except RateLimitExceededError as e:
        print(f"Rate limit exceeded. Retry after {e.retry_after_seconds} seconds")
        raise
    finally:
        await redis_client.close()


async def example_credential_verification_with_events(
    db_session: Session,
    credential: dict,
    verifier_did: str,
):
    """Example: Verify credential with event publishing"""
    
    # Setup
    event_publisher = create_event_publisher()
    verification_service = VerificationService(db_session)
    
    try:
        # Verify credential (metrics automatically tracked)
        result = verification_service.verify_w3c_vc(
            credential=credential,
            verifier_did=verifier_did,
        )
        
        if result["valid"]:
            # Publish success event
            await event_publisher.publish(
                CredentialVerifiedEvent(
                    event_id=str(uuid4()),
                    event_timestamp=datetime.utcnow(),
                    event_type="credential.verified",
                    credential_id=credential.get("id"),
                    credential_type="w3c_vc",
                    verifier_id=verifier_did,
                    verification_result=True,
                    verification_method="signature",
                    details=result.get("details"),
                )
            )
        else:
            # Publish failure event
            await event_publisher.publish(
                CredentialVerificationFailedEvent(
                    event_id=str(uuid4()),
                    event_timestamp=datetime.utcnow(),
                    event_type="credential.verification_failed",
                    credential_type="w3c_vc",
                    issuer=credential.get("issuer", "unknown"),
                    error=result.get("error", "Verification failed"),
                    error_details=result.get("details"),
                    verifier_id=verifier_did,
                )
            )
        
        return result
        
    except Exception as e:
        # Publish failure event
        await event_publisher.publish(
            CredentialVerificationFailedEvent(
                event_id=str(uuid4()),
                event_timestamp=datetime.utcnow(),
                event_type="credential.verification_failed",
                credential_type="w3c_vc",
                issuer=credential.get("issuer", "unknown"),
                error=str(e),
                error_details={"exception": type(e).__name__},
                verifier_id=verifier_did,
            )
        )
        raise


async def example_mdoc_verification_with_trusted_certs(
    db_session: Session,
    mdoc_presentation: bytes,
    verifier_did: str,
):
    """Example: Verify mDoc with trusted certificates"""
    
    # Setup - trusted certificates loaded from config automatically
    verification_service = VerificationService(db_session)
    event_publisher = create_event_publisher()
    
    try:
        # Verify mDoc (loads trusted certs from config.trusted_mdoc_issuer_certs_path)
        result = verification_service.verify_mdoc(
            mdoc_presentation=mdoc_presentation,
            verifier_did=verifier_did,
        )
        
        # Publish event
        if result["valid"]:
            await event_publisher.publish(
                CredentialVerifiedEvent(
                    event_id=str(uuid4()),
                    event_timestamp=datetime.utcnow(),
                    event_type="credential.verified",
                    credential_id=result.get("credential_id"),
                    credential_type="mdoc",
                    verifier_id=verifier_did,
                    verification_result=True,
                    verification_method="mdoc_signature",
                    details=result.get("details"),
                )
            )
        
        return result
        
    except Exception as e:
        print(f"mDoc verification failed: {e}")
        raise


async def example_rate_limit_management(redis_client: Redis, resource_key: str):
    """Example: Manage rate limits"""
    
    rate_limiter = RateLimiter(redis_client)
    
    # Check current usage
    current, remaining = await rate_limiter.get_current_usage(resource_key)
    print(f"Current usage: {current}/{rate_limiter.default_limit}")
    print(f"Remaining: {remaining}")
    
    # Reset rate limit (admin operation)
    await rate_limiter.reset_rate_limit(resource_key)
    print(f"Rate limit reset for {resource_key}")


async def example_multi_operation_with_all_features(
    db_session: Session,
    issuer_did: str,
    subject_did: str,
):
    """Example: Complete flow with all production features"""
    
    config = get_config()
    redis_client = Redis.from_url(config.redis_url, decode_responses=False)
    rate_limiter = RateLimiter(redis_client)
    event_publisher = create_event_publisher()
    
    issuance_service = IssuanceService(db_session)
    verification_service = VerificationService(db_session)
    
    try:
        # 1. Check rate limit
        print("Checking rate limit...")
        await rate_limiter.check_rate_limit(
            key=f"issuer:{issuer_did}",
            resource_type="issuer",
            resource_id=issuer_did,
        )
        
        # 2. Issue credential
        print("Issuing credential...")
        issue_result = issuance_service.issue_w3c_vc(
            issuer_did=issuer_did,
            subject_did=subject_did,
            credential_type="UniversityDegree",
            claims={"degree": "Bachelor of Science", "major": "Computer Science"},
            expiry_hours=24,
        )
        
        # 3. Publish issuance event
        print("Publishing issuance event...")
        await event_publisher.publish(
            CredentialIssuedEvent(
                event_id=str(uuid4()),
                event_timestamp=datetime.utcnow(),
                event_type="credential.issued",
                credential_id=str(issue_result["credential_id"]),
                credential_type="UniversityDegree",
                format="w3c_vc",
                issuer_id=issuer_did,
                holder_id=subject_did,
            )
        )
        
        # 4. Verify the credential
        print("Verifying credential...")
        verify_result = verification_service.verify_w3c_vc(
            credential=issue_result["credential"],
            verifier_did="did:example:verifier",
        )
        
        # 5. Publish verification event
        print("Publishing verification event...")
        await event_publisher.publish(
            CredentialVerifiedEvent(
                event_id=str(uuid4()),
                event_timestamp=datetime.utcnow(),
                event_type="credential.verified",
                credential_id=str(issue_result["credential_id"]),
                credential_type="UniversityDegree",
                verifier_id="did:example:verifier",
                verification_result=verify_result["valid"],
                verification_method="signature",
            )
        )
        
        print("✅ All operations completed successfully!")
        print(f"Credential ID: {issue_result['credential_id']}")
        print(f"Valid: {verify_result['valid']}")
        
        # Check metrics are being recorded (in Prometheus)
        # GET /metrics to see:
        # - credentials_issued_total
        # - credentials_verified_total
        # - credential_issuance_duration_seconds
        # - credential_verification_duration_seconds
        
    except RateLimitExceededError as e:
        print(f"❌ Rate limit exceeded: {e}")
        print(f"Retry after {e.retry_after_seconds} seconds")
    except Exception as e:
        print(f"❌ Operation failed: {e}")
        raise
    finally:
        await redis_client.close()


if __name__ == "__main__":
    # Run examples (requires proper setup)
    print("See function docstrings for usage examples")
    print("Configure environment variables before running:")
    print("  - DATABASE_URL")
    print("  - REDIS_URL")
    print("  - TRUSTED_MDOC_ISSUER_CERTS_PATH")
    print("  - KAFKA_BOOTSTRAP_SERVERS (optional)")
