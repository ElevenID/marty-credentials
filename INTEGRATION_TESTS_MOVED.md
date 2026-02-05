# Integration Tests Migration

## ✅ Completed Migration

Integration tests have been successfully migrated to a dedicated repository: **[marty-integration-tests](https://github.com/ElevenID/marty-integration-tests)**

## What Was Moved

The following was migrated from this repository to `marty-integration-tests`:

- ✅ All integration test files from `tests/integration/`
- ✅ Docker Compose configuration (`docker-compose.integration.yml`)
- ✅ Walt.ID wallet configuration (`config/wallet/`)
- ✅ Test helpers and fixtures
- ✅ CI/CD workflows for integration testing

## What Remains Here

This repository (`marty-credentials`) now contains only:

- ✅ Domain logic and business rules
- ✅ Unit tests for domain models
- ✅ Adapters and port interfaces
- ✅ Rust FFI bindings

## Running Integration Tests

To run the full integration test suite:

```bash
# Clone the integration test repository
git clone git@github.com:ElevenID/marty-integration-tests.git
cd marty-integration-tests

# Start services and run tests
make test

# Or manually
docker compose up -d
pytest tests/integration/ -v
```

## Benefits of Separation

1. **Clear Boundaries**: Domain logic separate from integration tests
2. **Independent Versioning**: Test suite evolves independently
3. **Simplified CI/CD**: Integration tests run in their own pipeline
4. **No Circular Dependencies**: Clean dependency graph
5. **Easier Onboarding**: Clone one repo, run all tests

## Migration Date

February 5, 2026

## Related Repositories

- **Domain Logic**: [marty-credentials](https://github.com/ElevenID/marty-credentials)
- **Services & Gateway**: [marty-ui](https://github.com/ElevenID/marty-ui)
- **Integration Tests**: [marty-integration-tests](https://github.com/ElevenID/marty-integration-tests) ⬅️ **New!**
- **Microservices Framework**: [marty-microservices-framework](https://github.com/ElevenID/marty-microservices-framework)
