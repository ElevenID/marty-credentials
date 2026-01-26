# Production Architecture Overview

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Marty Credentials Service                    │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                   API Layer (FastAPI)                     │  │
│  │  - POST /credentials/issue                                │  │
│  │  - POST /credentials/verify                               │  │
│  │  - GET  /metrics (Prometheus)                             │  │
│  └────────────────────┬─────────────────────────────────────┘  │
│                       │                                          │
│  ┌────────────────────▼─────────────────────────────────────┐  │
│  │              Rate Limiter (Redis)                         │  │
│  │  - Sliding window algorithm                               │  │
│  │  - Configurable limits per resource                       │  │
│  │  - Graceful degradation                                   │  │
│  └────────────────────┬─────────────────────────────────────┘  │
│                       │                                          │
│  ┌────────────────────▼─────────────────────────────────────┐  │
│  │              Service Layer                                │  │
│  │  ┌──────────────────────┐  ┌──────────────────────────┐  │  │
│  │  │  IssuanceService     │  │  VerificationService     │  │  │
│  │  │  - W3C VC           │  │  - Signature validation  │  │  │
│  │  │  - SD-JWT           │  │  - Revocation check      │  │  │
│  │  │  - mDoc             │  │  - Trust chain           │  │  │
│  │  │  - Open Badges      │  │  - Status verification   │  │  │
│  │  └──────────┬───────────┘  └───────────┬──────────────┘  │  │
│  │             │                           │                  │  │
│  │             └───────────┬───────────────┘                  │  │
│  │                         │                                  │  │
│  │            ┌────────────▼─────────────┐                   │  │
│  │            │   Metrics Collection     │                   │  │
│  │            │   - Counters             │                   │  │
│  │            │   - Histograms           │                   │  │
│  │            │   - Gauges               │                   │  │
│  │            └────────────┬─────────────┘                   │  │
│  │                         │                                  │  │
│  │            ┌────────────▼─────────────┐                   │  │
│  │            │   Event Publisher        │                   │  │
│  │            │   - CredentialIssued     │                   │  │
│  │            │   - CredentialVerified   │                   │  │
│  │            │   - VerificationFailed   │                   │  │
│  │            └────────────┬─────────────┘                   │  │
│  └─────────────────────────┼─────────────────────────────────┘  │
│                            │                                     │
│  ┌─────────────────────────▼─────────────────────────────────┐  │
│  │              Adapter Layer                                │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │  │
│  │  │ RustAdapter  │  │SpruceIDAdptr │  │PersistenceAdp│   │  │
│  │  │ (marty-rs)   │  │ (didkit)     │  │ (SQLAlchemy) │   │  │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │  │
│  └─────────┼──────────────────┼──────────────────┼───────────┘  │
└────────────┼──────────────────┼──────────────────┼──────────────┘
             │                  │                  │
    ┌────────▼────────┐  ┌─────▼──────┐  ┌───────▼────────┐
    │   Rust Core     │  │  SpruceID  │  │   PostgreSQL   │
    │  - COSE/CBOR    │  │   Library  │  │   Database     │
    │  - SD-JWT       │  │            │  │                │
    │  - mDoc (isomdl)│  │            │  │                │
    └─────────────────┘  └────────────┘  └────────────────┘
```

## External Dependencies

```
┌────────────────────────────────────────────────────────────────┐
│                   External Infrastructure                       │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │    Redis     │  │    Kafka     │  │  Prometheus  │         │
│  │              │  │              │  │              │         │
│  │ - Token      │  │ - Events     │  │ - Metrics    │         │
│  │   cache      │  │   pub/sub    │  │   scraping   │         │
│  │ - Rate       │  │ - Topic      │  │ - Alert      │         │
│  │   limiting   │  │   routing    │  │   rules      │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   Grafana    │  │ OAuth2       │  │  Trusted     │         │
│  │              │  │ Provider     │  │  CA Certs    │         │
│  │ - Dashboards │  │              │  │              │         │
│  │ - Alerts     │  │ - Token      │  │ - mDoc       │         │
│  │              │  │   validation │  │   issuers    │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└────────────────────────────────────────────────────────────────┘
```

## Data Flow: Credential Issuance

```
┌─────────────┐
│   Client    │
│  (Issuer)   │
└──────┬──────┘
       │ 1. POST /credentials/issue
       │    {type, claims, holder}
       ▼
┌─────────────────────────────────────────┐
│          Rate Limiter                   │
│  - Check: issuer:{did}                  │
│  - Limit: 100/min (default)             │
└──────┬──────────────────────────────────┘
       │ 2. Rate limit OK
       ▼
┌─────────────────────────────────────────┐
│       IssuanceService                   │
│  - Generate keys                        │
│  - Create credential                    │
│  - Sign (Rust/marty-rs)                 │
│  - Record metrics ⏱️                     │
└──────┬──────────────────────────────────┘
       │ 3. Credential created
       ▼
┌─────────────────────────────────────────┐
│       Store in Database                 │
│  - credential table                     │
│  - status: ACTIVE                       │
└──────┬──────────────────────────────────┘
       │ 4. Stored
       ▼
┌─────────────────────────────────────────┐
│       Publish Event                     │
│  - CredentialIssuedEvent                │
│  - To: marty.credentials.events.        │
│        credential.issued                │
└──────┬──────────────────────────────────┘
       │ 5. Event published
       ▼
┌─────────────────────────────────────────┐
│       Update Metrics                    │
│  - credentials_issued_total++ 📊        │
│  - credential_issuance_duration ⏱️      │
│  - active_credentials++                 │
└──────┬──────────────────────────────────┘
       │ 6. Response
       ▼
┌─────────────┐
│   Client    │
│  {jwt, id}  │
└─────────────┘
```

## Data Flow: Credential Verification

```
┌─────────────┐
│   Client    │
│ (Verifier)  │
└──────┬──────┘
       │ 1. POST /credentials/verify
       │    {credential, type}
       ▼
┌─────────────────────────────────────────┐
│      VerificationService                │
│  - Parse credential                     │
│  - Check signature                      │
│  - Load trusted certs 🔐                │
│  - Verify (Rust/marty-rs)               │
│  - Check revocation status              │
│  - Record metrics ⏱️                     │
└──────┬──────────────────────────────────┘
       │ 2. Verification result
       │
       ├─── Valid ✅
       │    │
       │    ▼
       │    ┌────────────────────────────┐
       │    │   Publish Success Event    │
       │    │   CredentialVerifiedEvent  │
       │    └────────────┬───────────────┘
       │                 │
       │                 ▼
       │    ┌────────────────────────────┐
       │    │    Update Metrics          │
       │    │  - verified_total(success) │
       │    │  - verification_duration   │
       │    └────────────────────────────┘
       │
       └─── Invalid ❌
            │
            ▼
            ┌────────────────────────────┐
            │  Raise Exception           │
            │  CredentialVerification    │
            │  Error                     │
            └────────────┬───────────────┘
                         │
                         ▼
            ┌────────────────────────────┐
            │   Publish Failure Event    │
            │   VerificationFailedEvent  │
            └────────────┬───────────────┘
                         │
                         ▼
            ┌────────────────────────────┐
            │    Update Metrics          │
            │  - failures_total++        │
            │  - by error_type           │
            └────────────────────────────┘
```

## Observability Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    Monitoring Pipeline                       │
│                                                               │
│  ┌────────────────┐                                          │
│  │ Credentials    │  /metrics                                │
│  │ Service        ├──────────────┐                           │
│  └────────────────┘              │                           │
│                                   ▼                           │
│                          ┌─────────────────┐                 │
│                          │   Prometheus    │                 │
│                          │   - Scrape      │                 │
│                          │   - Store TSDB  │                 │
│                          │   - Evaluate    │                 │
│                          │     alerts      │                 │
│                          └────────┬────────┘                 │
│                                   │                           │
│                    ┌──────────────┼──────────────┐           │
│                    │              │              │           │
│                    ▼              ▼              ▼           │
│          ┌──────────────┐  ┌──────────┐  ┌──────────────┐  │
│          │   Grafana    │  │Alertmngr │  │  Downstream  │  │
│          │  Dashboards  │  │  Alerts  │  │   Services   │  │
│          └──────────────┘  └──────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      Event Pipeline                          │
│                                                               │
│  ┌────────────────┐                                          │
│  │ Credentials    │  publish()                               │
│  │ Service        ├──────────────┐                           │
│  └────────────────┘              │                           │
│                                   ▼                           │
│                          ┌─────────────────┐                 │
│                          │     Kafka       │                 │
│                          │   - credential. │                 │
│                          │     issued      │                 │
│                          │   - credential. │                 │
│                          │     verified    │                 │
│                          │   - credential. │                 │
│                          │     revoked     │                 │
│                          └────────┬────────┘                 │
│                                   │                           │
│                    ┌──────────────┼──────────────┐           │
│                    │              │              │           │
│                    ▼              ▼              ▼           │
│          ┌──────────────┐  ┌──────────┐  ┌──────────────┐  │
│          │  Analytics   │  │  Audit   │  │  Downstream  │  │
│          │   Service    │  │  Logger  │  │   Services   │  │
│          └──────────────┘  └──────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Security Layers

```
┌─────────────────────────────────────────────────────────────┐
│                       Security Stack                         │
│                                                               │
│  Layer 1: Network                                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  - TLS/HTTPS                                          │   │
│  │  - Certificate validation                             │   │
│  │  - IP allowlisting (optional)                         │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  Layer 2: Authentication                                     │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  - OAuth2 token validation ✅                         │   │
│  │  - Token caching (Redis)                              │   │
│  │  - Token introspection                                │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  Layer 3: Rate Limiting                                      │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  - Per-issuer limits ✅                               │   │
│  │  - Per-verifier limits ✅                             │   │
│  │  - Sliding window (Redis)                             │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  Layer 4: Verification                                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  - Signature validation ✅                            │   │
│  │  - Trusted CA certificates ✅                         │   │
│  │  - Revocation checking                                │   │
│  │  - Expiration validation                              │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  Layer 5: Monitoring                                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  - Metrics collection ✅                              │   │
│  │  - Failure tracking ✅                                │   │
│  │  - Audit logging ✅                                   │   │
│  │  - Alerting on anomalies                              │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Key Improvements

| Component | Before | After |
|-----------|--------|-------|
| **Error Handling** | `print()` warnings | Exception raising ✅ |
| **mDoc Trust** | Empty cert list | Loaded trusted CAs ✅ |
| **Metrics** | None | 13 metrics ✅ |
| **Rate Limiting** | None | Redis-based ✅ |
| **Events** | None | Kafka publishing ✅ |
| **Logging** | Basic | Structured JSON ✅ |
| **Configuration** | Hardcoded | Environment-driven ✅ |

---

**Status**: Production Ready 🚀  
**Last Updated**: January 25, 2026
