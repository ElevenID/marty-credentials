"""Prove that an immutable verification image migrates and starts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

IMAGE_RE = re.compile(r"^(?:[a-z0-9./_-]+@)?sha256:[0-9a-f]{64}$")
POSTGRES_RE = re.compile(r"^docker\.io/library/postgres@sha256:[0-9a-f]{64}$")
REQUIRED_CHECKS = [
    "presentation.structure",
    "presentation.proof",
    "credential.proof",
    "issuer.trust",
    "credential.status",
    "holder.binding",
    "transaction.binding",
    "claim.constraints",
]


class SmokeError(RuntimeError):
    """The immutable verification image failed its startup contract."""


def _run(arguments: list[str], *, label: str, timeout: int = 60) -> str:
    completed = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise SmokeError(f"{label} failed with exit code {completed.returncode}")
    return completed.stdout.strip()


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def build_governance(image: str, api_key: str) -> dict[str, object]:
    """Build the smallest valid startup governance document."""
    policy_content = {
        "verifier_id": "did:web:verifier.release.invalid",
        "presentation_definition_digest": "sha256:" + "1" * 64,
        "required_checks": REQUIRED_CHECKS,
    }
    trust_content = {
        "trusted_issuers": ["did:web:issuer.release.invalid"],
        "allow_public_did_fallback": False,
    }
    organization_id = str(uuid.uuid4())
    return {
        "component": {
            "component_id": "marty-credentials",
            "version": "release-candidate",
            "artifact_digest": image.rsplit("@", 1)[-1],
            "adapter_id": "verification-service",
            "adapter_version": "1.0.0",
        },
        "policies": [
            {
                "organization_id": organization_id,
                "id": "policy:startup",
                "version": "1.0.0",
                "content_digest": _canonical_digest(policy_content),
                "content": policy_content,
            }
        ],
        "trust_profiles": [
            {
                "organization_id": organization_id,
                "id": "trust:startup",
                "version": "1.0.0",
                "content_digest": _canonical_digest(trust_content),
                "content": trust_content,
            }
        ],
        "clients": [
            {
                "client_id": "release-startup-smoke",
                "api_key_sha256": hashlib.sha256(api_key.encode()).hexdigest(),
                "organization_id": organization_id,
                "purposes": {
                    "verification.session.create": {
                        "policy_id": "policy:startup",
                        "trust_profile_id": "trust:startup",
                    }
                },
            }
        ],
    }


def _wait_for_postgres(container: str) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        ready = subprocess.run(
            ["docker", "exec", container, "pg_isready", "-U", "postgres", "-d", "verifier"],
            capture_output=True,
            check=False,
        )
        if ready.returncode == 0:
            return
        time.sleep(1)
    raise SmokeError("digest-pinned PostgreSQL readiness timed out")


def _service_port(container: str) -> int:
    output = _run(
        ["docker", "port", container, "8006/tcp"],
        label="resolve verification service port",
    )
    try:
        return int(output.splitlines()[0].rsplit(":", 1)[1])
    except (IndexError, ValueError) as exc:
        raise SmokeError("verification service port mapping was invalid") from exc


def _wait_for_health(container: str, port: int) -> dict[str, Any]:
    deadline = time.monotonic() + 60
    url = f"http://127.0.0.1:{port}/health"
    while time.monotonic() < deadline:
        running = _run(
            ["docker", "inspect", "--format", "{{.State.Running}}", container],
            label="inspect verification service",
        )
        if running != "true":
            logs = subprocess.run(
                ["docker", "logs", container],
                capture_output=True,
                text=True,
                check=False,
            )
            diagnostic = (logs.stderr or logs.stdout).strip()[-4000:]
            raise SmokeError(
                "verification service exited before becoming healthy"
                + (f":\n{diagnostic}" if diagnostic else "")
            )
        try:
            with urllib.request.urlopen(url, timeout=2) as response:  # noqa: S310
                payload = json.load(response)
            if response.status == 200 and isinstance(payload, dict):
                return payload
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            pass
        time.sleep(1)
    raise SmokeError("verification service health timed out")


def smoke(image: str, postgres_image: str) -> dict[str, object]:
    """Run migrations and observe a real healthy process from exact images."""
    if not IMAGE_RE.fullmatch(image):
        raise SmokeError("verification image must be pinned by sha256 digest")
    if not POSTGRES_RE.fullmatch(postgres_image):
        raise SmokeError("PostgreSQL image must be the approved digest-pinned image")

    suffix = uuid.uuid4().hex[:12]
    network = f"credentials-release-{suffix}"
    postgres = f"credentials-release-db-{suffix}"
    service = f"credentials-release-verifier-{suffix}"
    password = secrets.token_urlsafe(32)
    api_key = secrets.token_urlsafe(32)
    database_url = f"postgresql+asyncpg://postgres:{password}@{postgres}:5432/verifier"
    governance = json.dumps(build_governance(image, api_key), separators=(",", ":"))

    try:
        _run(["docker", "network", "create", network], label="create release-smoke network")
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                postgres,
                "--network",
                network,
                "-e",
                f"POSTGRES_PASSWORD={password}",
                "-e",
                "POSTGRES_DB=verifier",
                postgres_image,
            ],
            label="start digest-pinned PostgreSQL",
        )
        _wait_for_postgres(postgres)
        _run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                network,
                "-e",
                f"DATABASE_URL={database_url}",
                image,
                "python",
                "manage_migrations.py",
                "upgrade",
            ],
            label="apply verification migrations",
            timeout=180,
        )
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                service,
                "--network",
                network,
                "-p",
                "127.0.0.1::8006",
                "-e",
                f"DATABASE_URL={database_url}",
                "-e",
                f"VERIFICATION_GOVERNANCE_JSON={governance}",
                "-e",
                f"SIGNING_KEYS_INTERNAL_API_KEY={secrets.token_urlsafe(32)}",
                "-e",
                "ENVIRONMENT=test",
                image,
            ],
            label="start verification service",
        )
        health = _wait_for_health(service, _service_port(service))
        if health.get("status") != "healthy" or health.get("service") != "verification":
            raise SmokeError("verification health response did not satisfy its contract")
        native = health.get("native_backend")
        if not isinstance(native, dict) or native.get("available") is not True:
            raise SmokeError("verification health did not report an available native backend")
        return {
            "schema": "marty.credentials-verification-startup-smoke/v1",
            "image": image,
            "postgres_image": postgres_image,
            "checks": ["migrations.applied", "service.started", "health.native-backend"],
        }
    finally:
        subprocess.run(
            ["docker", "container", "rm", "-f", service],
            capture_output=True,
            check=False,
        )
        subprocess.run(
            ["docker", "container", "rm", "-f", postgres],
            capture_output=True,
            check=False,
        )
        subprocess.run(
            ["docker", "network", "rm", network],
            capture_output=True,
            check=False,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--postgres-image", required=True)
    args = parser.parse_args()
    print(json.dumps(smoke(args.image, args.postgres_image), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
