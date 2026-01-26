# Quick Reference Card - Production Features

**Version**: 2.0 | **Status**: ✅ Production Ready | **Date**: Jan 25, 2026

---

## 🎯 What's New

| Feature | Description | Status |
|---------|-------------|--------|
| **Exception Handling** | Invalid credentials now raise exceptions | ✅ |
| **mDoc Trust Chain** | Validates against trusted CA certificates | ✅ |
| **Prometheus Metrics** | 13 metrics tracking all operations | ✅ |
| **Rate Limiting** | Redis-based, configurable per resource | ✅ |
| **Event Publishing** | Kafka integration for lifecycle events | ✅ |
| **Structured Logging** | JSON logging with contextual data | ✅ |

---

## ⚡ Quick Commands

### Check Status
```bash
# Health check
curl http://localhost:8000/health

# Metrics
curl http://localhost:8000/metrics | grep credentials

# Rate limit status
redis-cli GET "rate_limit:issuer:did:example:123"
```

### Environment Setup
```bash
# Required
export DATABASE_URL=postgresql://localhost/marty_credentials
export REDIS_URL=redis://localhost:6379

# Optional (production)
export TRUSTED_MDOC_ISSUER_CERTS_PATH=/etc/marty/certs
export KAFKA_BOOTSTRAP_SERVERS=localhost:9092
export ENABLE_RATE_LIMITING=true
```

### Verification
```bash
# Run verification script
python3 verify_implementation.py

# Check for errors
python3 -m pyflakes python/marty_credentials/infrastructure/

# Run tests (if pytest installed)
pytest tests/integration/test_production_features.py -v
```

---

## 📊 Key Metrics

### Counters
- `credentials_issued_total{type, format, issuer}` - Total issued
- `credentials_verified_total{type, result}` - Total verified
- `credential_verification_failures_total{type, error, issuer}` - Failures

### Histograms
- `credential_issuance_duration_seconds` - Issuance latency
- `credential_verification_duration_seconds` - Verification latency

### Gauges
- `active_credentials{type}` - Current active count
- `rate_limit_remaining{resource_type, resource_id}` - Available quota

### Prometheus Queries
```promql
# Issuance rate (per second)
rate(credentials_issued_total[5m])

# P95 verification latency
histogram_quantile(0.95, rate(credential_verification_duration_seconds_bucket[5m]))

# Failure rate
rate(credential_verification_failures_total[5m])
```

---

## 🔧 Common Operations

### Issue Credential
```python
from marty_credentials.adapters.services.issuance_service import IssuanceService

service = IssuanceService(db_session)
result = service.issue_w3c_vc(
    issuer_did="did:example:issuer",
    subject_did="did:example:holder",
    credential_type="UniversityDegree",
    claims={"degree": "BS", "major": "CS"},
    expiry_hours=24
)
# Metrics automatically recorded ✅
```

### Verify Credential
```python
from marty_credentials.adapters.services.verification_service import VerificationService

service = VerificationService(db_session)
result = service.verify_w3c_vc(
    credential=credential_dict,
    verifier_did="did:example:verifier"
)
# Metrics automatically recorded ✅
# Events published if configured ✅
```

### Rate Limiting
```python
from redis.asyncio import Redis
from marty_credentials.infrastructure.observability.rate_limiter import RateLimiter

redis = Redis.from_url("redis://localhost:6379")
limiter = RateLimiter(redis, default_limit=100, window_seconds=60)

# Check before operation
await limiter.check_rate_limit(
    key=f"issuer:{issuer_id}",
    resource_type="issuer",
    resource_id=issuer_id
)
# Raises RateLimitExceededError if exceeded
```

### Event Publishing
```python
from marty_credentials.infrastructure.events.publisher import create_event_publisher
from marty_credentials.infrastructure.events import CredentialIssuedEvent

publisher = create_event_publisher()  # Auto-selects Kafka or Logging
await publisher.publish(
    CredentialIssuedEvent(
        event_id=str(uuid4()),
        event_timestamp=datetime.utcnow(),
        event_type="credential.issued",
        credential_id=cred_id,
        credential_type="UniversityDegree",
        format="w3c_vc",
        issuer_id=issuer_did,
        holder_id=holder_did
    )
)
```

---

## 🚨 Troubleshooting

### Rate Limit Hit
```bash
# Check current usage
redis-cli GET "rate_limit:issuer:did:example:123"

# Reset rate limit (admin only)
redis-cli DEL "rate_limit:issuer:did:example:123"
```

### Verification Failures
```bash
# Check metrics for error patterns
curl -s http://localhost:8000/metrics | \
  grep credential_verification_failures_total

# Check logs
tail -f /var/log/marty-credentials/app.log | grep CredentialVerificationError
```

### Missing Metrics
```bash
# Verify metrics endpoint
curl http://localhost:8000/metrics | head -20

# Check feature flag
echo $ENABLE_METRICS  # Should be "true"

# Restart service
sudo systemctl restart marty-credentials
```

### Event Publishing Issues
```bash
# Check Kafka connectivity
kafka-topics.sh --bootstrap-server localhost:9092 --list

# Check event publisher type (dev uses logging)
echo $DEV_MODE  # "true" = LoggingEventPublisher
echo $KAFKA_BOOTSTRAP_SERVERS  # Must be set for KafkaEventPublisher

# View events (Kafka)
kafka-console-consumer.sh --bootstrap-server localhost:9092 \
  --topic marty.credentials.events.credential.issued --from-beginning
```

---

## 📚 Documentation Links

| Document | Purpose |
|----------|---------|
| [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) | Full implementation details |
| [CONFIGURATION.md](CONFIGURATION.md) | Configuration reference |
| [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md) | Deployment guide |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture |
| [production_usage.py](python/marty_credentials/examples/production_usage.py) | Code examples |

---

## 🔐 Security Notes

1. **Invalid credentials are rejected** - No longer stored
2. **mDoc signatures validated** - Against trusted CAs only
3. **Rate limiting active** - Prevents abuse (100/min default)
4. **Structured logging** - All errors tracked with context
5. **Token validation** - OAuth2 integration (if enabled)

---

## 📞 Support

**Issues**: Check logs first, then review documentation  
**Metrics**: Grafana dashboard at `https://grafana.marty.dev`  
**Alerts**: AlertManager at `https://alerts.marty.dev`  
**On-Call**: Use PagerDuty escalation

---

**Last Updated**: January 25, 2026  
**Maintained By**: Platform Team
