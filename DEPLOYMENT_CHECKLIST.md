# Deployment Checklist

**Version**: 2.0 (Production Ready)  
**Date**: January 25, 2026

---

## ✅ Pre-Deployment Checklist

### 1. Code Quality
- [x] All production features implemented
- [x] No errors in new implementation files
- [x] Security vulnerabilities addressed
- [x] Exception handling implemented
- [x] Structured logging in place

### 2. Configuration Preparation
- [ ] Environment variables documented
- [ ] Secret management configured
- [ ] Certificate files prepared
- [ ] Configuration validated

### 3. Infrastructure Requirements
- [ ] PostgreSQL database available
- [ ] Redis instance available
- [ ] Kafka cluster available (production)
- [ ] Prometheus available for metrics
- [ ] Grafana available for dashboards

---

## 🔧 Environment Configuration

### Required Environment Variables

```bash
# Copy this template to .env.production and fill in actual values

# Database
export DATABASE_URL=postgresql://user:password@host:5432/marty_credentials

# Redis
export REDIS_URL=redis://host:6379/0

# mDoc Verification
export TRUSTED_MDOC_ISSUER_CERTS_PATH=/etc/marty/certs/mdoc-issuers

# OAuth2 (if using token validation)
export ENABLE_TOKEN_VALIDATION=true
export TOKEN_VALIDATION_ENDPOINT=https://auth.marty.dev/oauth/introspect
export OAUTH_CLIENT_ID=marty-credentials-service
export OAUTH_CLIENT_SECRET=<secret>

# Event Publishing
export ENABLE_EVENT_PUBLISHING=true
export KAFKA_BOOTSTRAP_SERVERS=kafka1:9092,kafka2:9092,kafka3:9092
export EVENT_TOPIC_PREFIX=marty.credentials.events

# Rate Limiting
export ENABLE_RATE_LIMITING=true
export RATE_LIMIT_PER_MINUTE=1000
export RATE_LIMIT_WINDOW_SECONDS=60

# Feature Flags
export DEV_MODE=false
export ENABLE_METRICS=true

# Base URLs
export ACHIEVEMENT_BASE_URL=https://achievements.marty.dev
export ISSUER_BASE_URL=https://issuer.marty.dev
export STATUS_LIST_BASE_URL=https://api.marty.dev
```

### Configuration Validation Script

```bash
#!/bin/bash
# validate-config.sh

echo "🔍 Validating Configuration..."

# Check required variables
REQUIRED_VARS=(
    "DATABASE_URL"
    "REDIS_URL"
)

for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        echo "❌ Missing required variable: $var"
        exit 1
    else
        echo "✅ $var is set"
    fi
done

# Check conditional requirements
if [ "$ENABLE_TOKEN_VALIDATION" = "true" ] && [ "$DEV_MODE" != "true" ]; then
    if [ -z "$OAUTH_CLIENT_ID" ] || [ -z "$OAUTH_CLIENT_SECRET" ]; then
        echo "❌ Token validation enabled but OAuth credentials missing"
        exit 1
    fi
    echo "✅ OAuth credentials configured"
fi

if [ "$ENABLE_EVENT_PUBLISHING" = "true" ] && [ "$DEV_MODE" != "true" ]; then
    if [ -z "$KAFKA_BOOTSTRAP_SERVERS" ]; then
        echo "❌ Event publishing enabled but Kafka not configured"
        exit 1
    fi
    echo "✅ Kafka configured"
fi

# Check certificate path
if [ -n "$TRUSTED_MDOC_ISSUER_CERTS_PATH" ]; then
    if [ -e "$TRUSTED_MDOC_ISSUER_CERTS_PATH" ]; then
        echo "✅ mDoc certificate path exists: $TRUSTED_MDOC_ISSUER_CERTS_PATH"
    else
        echo "⚠️  mDoc certificate path not found: $TRUSTED_MDOC_ISSUER_CERTS_PATH"
    fi
fi

echo ""
echo "✅ Configuration validation complete!"
```

---

## 📦 Deployment Steps

### Step 1: Install Dependencies

```bash
# Using virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install -e .
pip install aiokafka  # For Kafka event publishing

# Or using the existing .venv
source .venv/bin/activate
pip install -e .
```

### Step 2: Certificate Setup

```bash
# Create certificate directory
sudo mkdir -p /etc/marty/certs/mdoc-issuers

# Copy trusted issuer certificates
sudo cp issuer-ca-1.pem /etc/marty/certs/mdoc-issuers/
sudo cp issuer-ca-2.pem /etc/marty/certs/mdoc-issuers/

# Set permissions
sudo chmod 644 /etc/marty/certs/mdoc-issuers/*.pem
sudo chown marty-service:marty-service /etc/marty/certs/mdoc-issuers/*.pem

# Verify
ls -la /etc/marty/certs/mdoc-issuers/
```

### Step 3: Database Migration

```bash
# Run any pending migrations
alembic upgrade head

# Verify connection
python3 -c "
from marty_credentials.config import get_config
import sqlalchemy
config = get_config()
engine = sqlalchemy.create_engine(config.database_url)
with engine.connect() as conn:
    result = conn.execute(sqlalchemy.text('SELECT 1'))
    print('✅ Database connection successful')
"
```

### Step 4: Redis Connectivity Check

```bash
# Test Redis connection
python3 -c "
from redis.asyncio import Redis
from marty_credentials.config import get_config
import asyncio

async def test_redis():
    config = get_config()
    redis = Redis.from_url(config.redis_url, decode_responses=True)
    await redis.set('test_key', 'test_value')
    value = await redis.get('test_key')
    await redis.delete('test_key')
    await redis.close()
    print(f'✅ Redis connection successful: {value}')

asyncio.run(test_redis())
"
```

### Step 5: Kafka Connectivity Check (Production Only)

```bash
# Test Kafka connection
python3 -c "
from marty_credentials.config import get_config
import asyncio

async def test_kafka():
    config = get_config()
    if not config.enable_event_publishing or not config.kafka_bootstrap_servers:
        print('⚠️  Kafka not configured (using logging publisher)')
        return
    
    from aiokafka import AIOKafkaProducer
    producer = AIOKafkaProducer(
        bootstrap_servers=config.kafka_bootstrap_servers
    )
    try:
        await producer.start()
        print('✅ Kafka connection successful')
        await producer.stop()
    except Exception as e:
        print(f'❌ Kafka connection failed: {e}')

asyncio.run(test_kafka())
"
```

### Step 6: Start Service

```bash
# Using systemd (example)
sudo systemctl start marty-credentials
sudo systemctl status marty-credentials

# Or using Docker
docker-compose up -d marty-credentials

# Check logs
sudo journalctl -u marty-credentials -f
# or
docker-compose logs -f marty-credentials
```

### Step 7: Health Check

```bash
# Check service health
curl http://localhost:8000/health

# Expected response:
# {
#   "status": "healthy",
#   "redis": "connected",
#   "database": "connected",
#   "kafka": "connected"
# }

# Check metrics endpoint
curl http://localhost:8000/metrics | grep credentials_issued_total

# Verify rate limiting
for i in {1..5}; do
  curl -X POST http://localhost:8000/credentials/issue \
    -H "Authorization: Bearer test_token" \
    -H "Content-Type: application/json" \
    -d '{"type": "UniversityDegree", "claims": {}}'
  echo ""
done
```

---

## 🧪 Post-Deployment Validation

### Test Credential Issuance

```bash
# Issue a test credential
curl -X POST http://localhost:8000/credentials/issue \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "issuer_did": "did:example:issuer",
    "subject_did": "did:example:holder",
    "credential_type": "UniversityDegree",
    "claims": {
      "degree": "Bachelor of Science",
      "major": "Computer Science"
    }
  }'
```

### Test Credential Verification

```bash
# Verify a credential
curl -X POST http://localhost:8000/credentials/verify \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "credential": "<credential_jwt>",
    "verifier_did": "did:example:verifier"
  }'
```

### Verify Metrics Collection

```bash
# Check metrics are being recorded
curl -s http://localhost:8000/metrics | grep -E "credentials_(issued|verified)_total"

# Should see something like:
# credentials_issued_total{credential_type="UniversityDegree",format="w3c_vc",issuer_id="did:example:issuer"} 1.0
# credentials_verified_total{credential_type="UniversityDegree",result="success"} 1.0
```

### Verify Event Publishing

```bash
# For Kafka (if enabled)
kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic marty.credentials.events.credential.issued \
  --from-beginning \
  --max-messages 1

# Should see event JSON
```

### Verify Rate Limiting

```bash
# Test rate limit enforcement
#!/bin/bash
for i in {1..105}; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:8000/credentials/issue \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"issuer_did": "did:example:issuer", "subject_did": "did:example:holder", "credential_type": "Test", "claims": {}}')
  
  if [ "$response" = "429" ]; then
    echo "✅ Rate limit enforced at request $i"
    break
  fi
done
```

---

## 📊 Monitoring Setup

### Prometheus Scraping

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'marty-credentials'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### Grafana Dashboard

Import dashboard JSON or create panels for:

1. **Credential Operations Rate**
   - Query: `rate(credentials_issued_total[5m])`
   - Query: `rate(credentials_verified_total[5m])`

2. **Verification Failure Rate**
   - Query: `rate(credential_verification_failures_total[5m])`

3. **Latency (P50, P95, P99)**
   - Query: `histogram_quantile(0.95, rate(credential_issuance_duration_seconds_bucket[5m]))`

4. **Rate Limit Status**
   - Query: `rate_limit_remaining`

5. **Active Credentials**
   - Query: `active_credentials`

### Alerting Rules

Create `alerts.yml`:

```yaml
groups:
  - name: marty-credentials
    interval: 30s
    rules:
      - alert: HighVerificationFailureRate
        expr: rate(credential_verification_failures_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High credential verification failure rate"
          description: "{{ $value }} failures per second"
      
      - alert: SlowCredentialIssuance
        expr: histogram_quantile(0.95, rate(credential_issuance_duration_seconds_bucket[5m])) > 2
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Slow credential issuance"
          description: "P95 latency is {{ $value }} seconds"
      
      - alert: RateLimitExhaustion
        expr: rate_limit_remaining < 10
        for: 2m
        labels:
          severity: info
        annotations:
          summary: "Rate limit nearly exhausted"
          description: "Only {{ $value }} requests remaining"
```

---

## 🔄 Rollback Plan

### If Issues Arise

```bash
# 1. Stop the new service
sudo systemctl stop marty-credentials

# 2. Restore previous version
sudo systemctl start marty-credentials-v1

# 3. Revert database migrations (if any)
alembic downgrade -1

# 4. Check service status
sudo systemctl status marty-credentials-v1

# 5. Verify health
curl http://localhost:8000/health
```

---

## ✅ Sign-Off

| Checkpoint | Status | Notes |
|------------|--------|-------|
| Environment configured | ⬜ | |
| Certificates installed | ⬜ | |
| Database connected | ⬜ | |
| Redis connected | ⬜ | |
| Kafka connected | ⬜ | |
| Service started | ⬜ | |
| Health check passed | ⬜ | |
| Metrics endpoint working | ⬜ | |
| Event publishing working | ⬜ | |
| Rate limiting working | ⬜ | |
| Monitoring configured | ⬜ | |
| Alerts configured | ⬜ | |

**Deployed By**: ___________________  
**Deployment Date**: ___________________  
**Sign-Off**: ___________________

---

## 📞 Troubleshooting Contacts

- **Platform Team**: platform@marty.dev
- **On-Call**: +1-555-ON-CALL
- **Documentation**: See [CONFIGURATION.md](CONFIGURATION.md)
- **Runbooks**: See [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)
