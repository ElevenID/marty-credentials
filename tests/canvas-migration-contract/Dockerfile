FROM python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b

ARG CONTRACT_SOURCE_REVISION=local-worktree

LABEL org.opencontainers.image.source="https://github.com/ElevenID/marty-credentials" \
      org.opencontainers.image.revision="${CONTRACT_SOURCE_REVISION}" \
      io.elevenid.canvas-migration.execution-boundary="docker-compose-one-shot"

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /contract

COPY tests/canvas-migration-contract/requirements.txt /contract/requirements.txt
RUN python -m pip install --no-deps --only-binary=:all: --require-hashes \
    --requirement /contract/requirements.txt

COPY services/issuance/infrastructure/migrations/ /contract/migrations/
COPY tests/canvas-migration-contract/run_contract.py /contract/run_contract.py

ENTRYPOINT ["python", "/contract/run_contract.py"]
