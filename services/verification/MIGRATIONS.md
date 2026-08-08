# Verification persistence migrations

Run migrations as a deployment step before starting a new verification image:

```bash
DATABASE_URL=postgresql://... python -m verification.manage_migrations upgrade
```

The first migration creates the session table when absent, adds the versioned
`verification_evidence` record to existing installations, and permanently
redacts legacy raw presentations. The service continues to keep the nullable
`presentation_data` column for rolling compatibility, but application writes
always set it to `NULL`; only a SHA-256 digest is retained in decision evidence.

Migration versions are tracked in the service-owned `verification_service`
schema. The session table remains in `public` for compatibility with the
existing SQLAlchemy model and installations.
