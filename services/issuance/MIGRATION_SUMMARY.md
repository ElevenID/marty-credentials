<!-- markdownlint-disable-file -->
<!-- cspell:disable -->

# Issuance Service Migration Summary

> **Historical record:** This report describes an earlier Python MMF migration
> and is not a supported architecture or runbook. Issuance
> behavior now belongs to the Rust service plane in `marty-ui`, with shared
> protocol and platform behavior in `marty-core` and the `mmf-*` crates. Do not
> restore the Python framework imports, mounts, or build contexts shown below.

## Completed: Service Consolidation to marty-credentials

The issuance service has been successfully migrated from `marty-ui/services/issuance/` to `marty-credentials/services/issuance/` following the MMF (Marty Microservices Framework) hexagonal architecture pattern.

## What Was Done

### 1. **Created MMF Hexagonal Structure** ✅

```
marty-credentials/services/issuance/
├── domain/                          # Pure business logic (no dependencies)
│   ├── entities.py                  # IssuanceTransaction, IssuedCredential, Application, ApplicationTemplate
│   ├── ports.py                     # IIssuanceRepository interface
│   └── __init__.py
├── application/                     # Use cases and orchestration
│   ├── rust_integration.py          # Rust helpers; signing delegates to managed issuer profiles
│   └── __init__.py
├── infrastructure/                  # External system adapters
│   ├── models.py                    # SQLAlchemy table definitions
│   ├── adapters/
│   │   ├── memory_repository.py    # In-memory repo for dev/testing
│   │   ├── postgres_repository.py  # PostgreSQL implementation
│   │   └── __init__.py
│   ├── api/
│   │   ├── routes.py                # OID4VCI endpoints (/initiate, /token, /credential)
│   │   ├── application_routes.py    # Application workflow endpoints
│   │   └── __init__.py
│   ├── migrations/                  # Alembic database migrations (copied from old location)
│   │   ├── alembic.ini
│   │   ├── env.py
│   │   └── versions/
│   └── __init__.py
├── main.py                          # FastAPI application entry point
└── __init__.py
```

### 2. **Key Features**

- **No Mock Fallback Code**: `rust_integration.py` raises `ImportError` if Rust bindings unavailable (user requirement)
- **Repository Pattern**: Clean separation with `IIssuanceRepository` port and PostgreSQL/in-memory adapters
- **Complete OID4VCI Protocol**: All endpoints implemented (/initiate, /token, /credential, /offers, /transactions)
- **Credential Lifecycle**: Revoke, suspend, reinstate endpoints with RevocationProfile integration
- **Application Workflow**: Template and application management with approval/rejection flows
- **Dependency Injection**: FastAPI DI with repository override pattern

### 3. **Updated Docker Configuration** ✅

**Dockerfile** (`marty-credentials/services/Dockerfile`):
- Multi-stage build: Rust → Python → Final
- Builds marty-rs Python bindings via maturin
- Installs MMF as pip package
- Hardcoded dependencies (fastapi, uvicorn, sqlalchemy, asyncpg, etc.)
- Health check endpoint
- Runs: `uvicorn main:app --host 0.0.0.0 --port 8005`

**docker-compose.integration.yml**:
- Updated build context to `marty-credentials/services/Dockerfile`
- Removed `SERVICE_NAME` build arg (no longer needed)
- Removed `SERVICE_PORT` env var (hardcoded in main.py)
- Kept: `DATABASE_URL`, `REDIS_URL`, `ISSUER_BASE_URL`

### 4. **Migrations Copied** ✅

Copied from `marty-ui/services/issuance/infrastructure/migrations/`:
- `alembic.ini` - Alembic configuration
- `env.py` - Migration environment setup
- `script.py.mako` - Migration template
- `versions/` - All existing migration files:
  - `20260203_0225_735160618517_initial_issuance_schema.py`
  - `20260204_0030_add_application_tables.py`
  - `20260204_0100_add_application_id_to_issuance_transactions.py`

## Critical Code Changes

### Rust Integration (NO FALLBACK)

```python
# application/rust_integration.py
def get_marty_rs():
    try:
        import _marty_rs
        return _marty_rs
    except ImportError as e:
        logger.error("marty-rs bindings not available")
        raise ImportError(
            "marty-rs Python bindings are required for credential signing. "
            "Ensure the marty-bindings crate is built and installed."
        ) from e
```

### FastAPI Application

```python
# main.py
app = create_app()  # Module-level for uvicorn

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize PostgreSQL on startup
    engine = create_async_engine(config["database_url"], ...)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    _repo = PostgresIssuanceRepository(session_factory)
    yield
    await engine.dispose()
```

## Next Steps

### **IMMEDIATE: Test Migration** 🔄

Build and test the service:

```bash
cd /Volumes/Heart\ of\ Gold/Github/work/marty-credentials

# Build the service
docker compose -f docker-compose.integration.yml build issuance-service

# Start dependencies
docker compose -f docker-compose.integration.yml up -d postgres redis

# Start issuance service
docker compose -f docker-compose.integration.yml up issuance-service
```

**Verification checklist:**
- [ ] Service starts without errors
- [ ] Health check responds: `curl http://localhost:8005/health`
- [ ] Rust bindings load correctly (check logs for ImportError)
- [ ] Database migrations run successfully
- [ ] OID4VCI endpoints respond correctly:
  - `POST /v1/issuance/initiate`
  - `POST /v1/issuance/token`
  - `POST /v1/issuance/credential`

### **AFTER SUCCESSFUL TESTS: Cleanup** 🗑️

Delete old service:

```bash
rm -rf /Volumes/Heart\ of\ Gold/Github/work/marty-ui/services/issuance/
```

Update documentation:
- Remove marty-ui/services/issuance references
- Update architecture diagrams
- Document new service location in README

## Known Issues / Future Work

### 1. **Canonical Native Release Required**

`marty-core/marty-bindings` (`marty-rs`) and `marty-verification` are now the
authoritative Python-facing native backends. Production and CI install both
checksum-pinned wheels from the same immutable `marty-core` release. Missing or
incompatible bindings fail startup with typed native-backend errors; native
operation failures are also typed and never invoke Python cryptographic
fallbacks.

The next release must publish version `0.1.39` wheels for Linux x86_64, macOS
arm64, and Windows x86_64. Replace release-manifest placeholders with hashes
computed from the published assets before enabling the downstream production
builds.

### 2. **MMF Gateway Adapters Missing**

**Gap Identified**: MMF has `IServiceRegistry` and `GatewayService` abstractions but only `InMemoryServiceDiscoveryAdapter`

**Needed**:
- `ConsulAdapter` - For service discovery via Consul
- `KongRouteSynchronizer` - For dynamic route registration in Kong API Gateway

**Implementation location**: `marty-microservices-framework/mmf/discovery/adapters/`

### 3. **Configuration Management**

Current: Environment variables in docker-compose  
Future: Consider using MMF's configuration management patterns

### 4. **Observability**

Add:
- OpenTelemetry instrumentation
- Structured logging via MMF
- Metrics collection

## Architecture Compliance

✅ **Hexagonal Architecture (Ports & Adapters)**
- Domain layer: Pure business logic, no external dependencies
- Ports: `IIssuanceRepository` interface defining contracts
- Adapters: PostgreSQL, in-memory implementations of ports
- Infrastructure: HTTP API, database models, migrations

✅ **MMF Integration**
- Follows MMF directory structure
- Uses MMF patterns (will use service registry once adapters exist)
- Ready for Kong/Consul integration

✅ **Production Readiness**
- No cryptographic or protocol fallback code
- Typed, fail-closed native backend and operation errors
- Health checks
- Connection pooling
- Graceful shutdown

## References

- MMF Documentation: `marty-microservices-framework/README.md`
- Original Service: `marty-ui/services/issuance/main.py` (1,363 lines, TO BE DELETED)
- New Service: `marty-credentials/services/issuance/` (modular, ~600 lines total)
- Docker Build Context: Workspace root (requires marty-core, marty-credentials, marty-microservices-framework)
