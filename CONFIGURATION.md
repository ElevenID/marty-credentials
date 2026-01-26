# Production Configuration Guide

## Environment Variables Reference

### Required Configuration

```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/marty_credentials

# Redis (for caching and rate limiting)
REDIS_URL=redis://localhost:6379/0
```

### Security Configuration

```bash
# mDoc Trusted Certificates
# Path to trusted CA certificates for mDoc signature verification
# Can be a single .pem file or directory containing .pem files
TRUSTED_MDOC_ISSUER_CERTS_PATH=/etc/marty/certs/mdoc-issuers

# OAuth2 Token Validation
TOKEN_VALIDATION_ENDPOINT=https://auth.marty.dev/oauth/introspect
OAUTH_CLIENT_ID=marty-credentials-service
OAUTH_CLIENT_SECRET=<secret>
```

### Observability Configuration

```bash
# Metrics
ENABLE_METRICS=true

# Event Publishing
ENABLE_EVENT_PUBLISHING=true
KAFKA_BOOTSTRAP_SERVERS=localhost:9092,localhost:9093
EVENT_TOPIC_PREFIX=marty.credentials.events

# Rate Limiting
ENABLE_RATE_LIMITING=true
RATE_LIMIT_PER_MINUTE=100
RATE_LIMIT_WINDOW_SECONDS=60
```

### Base URLs

```bash
# Service URLs
ACHIEVEMENT_BASE_URL=https://achievements.marty.dev
ISSUER_BASE_URL=https://issuer.marty.dev
STATUS_LIST_BASE_URL=https://api.marty.dev
```

### Feature Flags

```bash
# Development Mode (disables strict validation)
DEV_MODE=false

# Enable/disable specific features
ENABLE_TOKEN_VALIDATION=true
ENABLE_RATE_LIMITING=true
ENABLE_METRICS=true
ENABLE_EVENT_PUBLISHING=true
```

### Cache Configuration

```bash
# Token cache TTL in seconds
CACHE_TTL_SECONDS=300  # 5 minutes
```

---

## Configuration Profiles

### Development Environment

```bash
# .env.development
DATABASE_URL=postgresql://localhost/marty_credentials_dev
REDIS_URL=redis://localhost:6379/1

DEV_MODE=true
ENABLE_METRICS=true
ENABLE_RATE_LIMITING=false
ENABLE_TOKEN_VALIDATION=false
ENABLE_EVENT_PUBLISHING=true

# Use logging event publisher instead of Kafka
# KAFKA_BOOTSTRAP_SERVERS not set

ACHIEVEMENT_BASE_URL=http://localhost:8001
ISSUER_BASE_URL=http://localhost:8002
STATUS_LIST_BASE_URL=http://localhost:8003
```

### Staging Environment

```bash
# .env.staging
DATABASE_URL=postgresql://staging-db.internal:5432/marty_credentials
REDIS_URL=redis://staging-redis.internal:6379/0

DEV_MODE=false
ENABLE_METRICS=true
ENABLE_RATE_LIMITING=true
ENABLE_TOKEN_VALIDATION=true
ENABLE_EVENT_PUBLISHING=true

KAFKA_BOOTSTRAP_SERVERS=staging-kafka.internal:9092
EVENT_TOPIC_PREFIX=staging.marty.credentials.events

TOKEN_VALIDATION_ENDPOINT=https://auth.staging.marty.dev/oauth/introspect
OAUTH_CLIENT_ID=marty-credentials-service
OAUTH_CLIENT_SECRET=<staging-secret>

TRUSTED_MDOC_ISSUER_CERTS_PATH=/app/config/certs/staging

RATE_LIMIT_PER_MINUTE=500
CACHE_TTL_SECONDS=300

ACHIEVEMENT_BASE_URL=https://achievements.staging.marty.dev
ISSUER_BASE_URL=https://issuer.staging.marty.dev
STATUS_LIST_BASE_URL=https://api.staging.marty.dev
```

### Production Environment

```bash
# .env.production
DATABASE_URL=postgresql://prod-db-primary.internal:5432/marty_credentials
REDIS_URL=redis://prod-redis-cluster.internal:6379/0

DEV_MODE=false
ENABLE_METRICS=true
ENABLE_RATE_LIMITING=true
ENABLE_TOKEN_VALIDATION=true
ENABLE_EVENT_PUBLISHING=true

KAFKA_BOOTSTRAP_SERVERS=prod-kafka-1.internal:9092,prod-kafka-2.internal:9092,prod-kafka-3.internal:9092
EVENT_TOPIC_PREFIX=marty.credentials.events

TOKEN_VALIDATION_ENDPOINT=https://auth.marty.dev/oauth/introspect
OAUTH_CLIENT_ID=marty-credentials-service
OAUTH_CLIENT_SECRET=<production-secret>

TRUSTED_MDOC_ISSUER_CERTS_PATH=/app/config/certs/production

# Higher limits for production
RATE_LIMIT_PER_MINUTE=1000
RATE_LIMIT_WINDOW_SECONDS=60
CACHE_TTL_SECONDS=600  # 10 minutes

ACHIEVEMENT_BASE_URL=https://achievements.marty.dev
ISSUER_BASE_URL=https://issuer.marty.dev
STATUS_LIST_BASE_URL=https://api.marty.dev
```

---

## Certificate Management

### mDoc Trusted Certificates

#### Single Certificate File
```bash
# Single issuer certificate
TRUSTED_MDOC_ISSUER_CERTS_PATH=/etc/marty/certs/issuer-ca.pem
```

File format (PEM):
```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKqzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
...
-----END CERTIFICATE-----
```

#### Multiple Certificates (Directory)
```bash
# Directory containing multiple issuer certificates
TRUSTED_MDOC_ISSUER_CERTS_PATH=/etc/marty/certs/mdoc-issuers/
```

Directory structure:
```
/etc/marty/certs/mdoc-issuers/
├── state-dmv-ca.pem
├── federal-agency-ca.pem
└── international-issuer-ca.pem
```

#### Certificate Updates
Certificates are loaded on service startup. To update:
1. Add/replace certificate files
2. Restart service or trigger reload

---

## Redis Configuration

### Standalone Redis
```bash
REDIS_URL=redis://localhost:6379/0
# With password:
REDIS_URL=redis://:password@localhost:6379/0
```

### Redis Sentinel
```bash
REDIS_URL=redis-sentinel://sentinel1:26379,sentinel2:26379/mymaster/0
```

### Redis Cluster
```bash
REDIS_URL=redis-cluster://node1:6379,node2:6379,node3:6379/0
```

### Redis with TLS
```bash
REDIS_URL=rediss://prod-redis.internal:6380/0
```

---

## Kafka Configuration

### Topics Created Automatically

Based on `EVENT_TOPIC_PREFIX`, the following topics are used:

- `{prefix}.credential.issued` - Credential issuance events
- `{prefix}.credential.verified` - Verification success events
- `{prefix}.credential.verification_failed` - Verification failure events
- `{prefix}.credential.revoked` - Revocation events
- `{prefix}.credential.status_updated` - Status change events
- `{prefix}.credential.presentation_requested` - VP request events
- `{prefix}.credential.presentation_submitted` - VP submission events

### Kafka with SASL Authentication

```bash
KAFKA_BOOTSTRAP_SERVERS=kafka.internal:9093
KAFKA_SECURITY_PROTOCOL=SASL_SSL
KAFKA_SASL_MECHANISM=PLAIN
KAFKA_SASL_USERNAME=marty-credentials
KAFKA_SASL_PASSWORD=<password>
```

---

## Validation

### Check Configuration

```python
from marty_credentials.config import get_config

config = get_config()
config.validate()  # Raises ConfigurationError if invalid
```

### Required Variables Check

The service will fail to start if these are missing:
- `DATABASE_URL`
- `REDIS_URL`

### Conditional Requirements

If `ENABLE_TOKEN_VALIDATION=true` and `DEV_MODE=false`:
- `OAUTH_CLIENT_ID` required
- `OAUTH_CLIENT_SECRET` required

If `ENABLE_EVENT_PUBLISHING=true` and `DEV_MODE=false`:
- `KAFKA_BOOTSTRAP_SERVERS` required

---

## Security Best Practices

1. **Never commit secrets** to version control
2. **Use secret management** (AWS Secrets Manager, HashiCorp Vault, etc.)
3. **Rotate credentials** regularly
4. **Use TLS** for all external connections
5. **Restrict certificate access** to service account only
6. **Monitor unauthorized access** via metrics and logs

---

## Troubleshooting

### Rate Limiting Issues

Check Redis connectivity:
```bash
redis-cli -h localhost -p 6379 ping
```

Check current rate limit:
```python
from redis.asyncio import Redis

redis = Redis.from_url("redis://localhost:6379")
current = await redis.get("rate_limit:issuer:did:example:123")
print(f"Current count: {current}")
```

### Event Publishing Issues

Check Kafka connectivity:
```bash
kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic marty.credentials.events.credential.issued \
  --from-beginning
```

### Certificate Loading Issues

Check certificate path:
```bash
ls -la /etc/marty/certs/mdoc-issuers/
openssl x509 -in /etc/marty/certs/mdoc-issuers/issuer.pem -text -noout
```

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## Metrics Endpoints

### Prometheus Metrics

Available at `/metrics`:

```bash
curl http://localhost:8000/metrics
```

Key metrics to monitor:
- `credentials_issued_total` - Issuance counter
- `credentials_verified_total` - Verification counter
- `credential_verification_failures_total` - Failure counter
- `credential_issuance_duration_seconds` - Issuance latency histogram
- `rate_limit_remaining` - Available rate limit quota

### Health Check

```bash
curl http://localhost:8000/health
```

Should return:
```json
{
  "status": "healthy",
  "redis": "connected",
  "database": "connected",
  "kafka": "connected"
}
```
