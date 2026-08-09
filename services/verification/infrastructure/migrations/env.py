"""Alembic environment for verification-service-owned persistence."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config
target_metadata = config.attributes.get("target_metadata")

if config.config_file_name is not None:
    # Migrations run in-process during deployment and tests. Loading Alembic's
    # logger configuration must not disable existing service/audit loggers.
    fileConfig(config.config_file_name, disable_existing_loggers=False)


def _configure(**kwargs) -> None:
    context.configure(
        target_metadata=target_metadata,
        include_schemas=True,
        version_table_schema="verification_service",
        **kwargs,
    )


def run_migrations_offline() -> None:
    _configure(
        url=config.get_main_option("sqlalchemy.url"),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        _configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
