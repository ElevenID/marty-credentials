"""Run both real Python consumers against isolated, ephemeral PostgreSQL.

No deployment endpoints or database credentials are accepted. Each mode gets a
new network-none database with no ports or persistent volume. The probe shares
only that network namespace, mounts this checkout read-only, and drops all caps.
"""

import argparse
import json
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABEL = "elevenid.test.canvas-consumer-range-oracle"


def docker(*arguments, timeout=60):
    result = subprocess.run(
        ["docker", *arguments], capture_output=True, text=True, timeout=timeout, check=False
    )
    if result.returncode:
        # Do not surface raw Docker/probe logs or environment/SQL values.
        raise RuntimeError(f"Docker {arguments[0]} failed (exit {result.returncode})")
    return result.stdout.strip()


def run(source, fixture):
    probe = None
    container = docker(
        "create",
        "--network",
        "none",
        "--label",
        f"{LABEL}=true",
        "--tmpfs",
        "/var/lib/postgresql/data",
        "--tmpfs",
        "/var/run/postgresql",
        "--env",
        "POSTGRES_USER=oracle",
        "--env",
        "POSTGRES_PASSWORD=synthetic-local-only",
        "--env",
        "POSTGRES_DB=canvas_range_oracle",
        fixture["observed_postgres_image"],
    )
    if not re.fullmatch(r"[0-9a-f]{64}", container):
        raise RuntimeError("Docker did not return an exact owned container ID")
    try:
        docker("start", container)
        for _ in range(60):
            # Readiness failures are transient, not a reason to recreate a DB.
            readiness = subprocess.run(
                [
                    "docker",
                    "exec",
                    container,
                    "pg_isready",
                    "-U",
                    "oracle",
                    "-d",
                    "canvas_range_oracle",
                ],
                capture_output=True,
                timeout=10,
                check=False,
            )
            if readiness.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("Owned PostgreSQL container did not become ready")
        environment = ["--env", "TOKEN_HMAC_KEY=synthetic-oracle-hmac-key-not-a-deployment-secret"]
        if source == "checkout":
            environment += ["--env", "PYTHONPATH=/verification/services:/app/services"]
        probe = docker(
            "create",
            "--network",
            f"container:{container}",
            "--read-only",
            "--label",
            f"{LABEL}=probe",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--mount",
            f"type=bind,source={ROOT},target=/verification,readonly",
            *environment,
            "--entrypoint",
            "python",
            fixture["observed_image"],
            "/verification/scripts/verify_canvas_worker_consumer_ranges.py",
            "--source",
            source,
        )
        if not re.fullmatch(r"[0-9a-f]{64}", probe):
            raise RuntimeError("Docker did not return an exact owned probe ID")
        docker("start", probe)
        exit_code = docker("wait", probe, timeout=180)
        raw = docker("logs", probe)
        report = json.loads(raw)
        if exit_code != "0":
            # The verifier emits only a sanitized failed-check identity. Raw
            # stderr (including migration and driver logs) remains suppressed.
            raise RuntimeError(f"Consumer oracle check failed: {report.get('check', 'unknown')}")
        if report["status"] != "passed" or report["cycle_cases"] != 36 or report["loop_cases"] != 3:
            raise RuntimeError("Incomplete consumer oracle report")
        return report
    finally:
        if probe is not None and re.fullmatch(r"[0-9a-f]{64}", probe):
            owned_probe = json.loads(docker("inspect", probe))[0]
            if (
                owned_probe["Id"] != probe
                or owned_probe["Config"]["Labels"].get(LABEL) != "probe"
                or owned_probe["HostConfig"]["NetworkMode"] != f"container:{container}"
            ):
                raise RuntimeError("Refusing cleanup: probe identity/topology mismatch")
            docker("rm", "--force", probe)
        owned = json.loads(docker("inspect", container))[0]
        if (
            owned["Id"] != container
            or owned["Config"]["Labels"].get(LABEL) != "true"
            or owned["HostConfig"]["NetworkMode"] != "none"
            or owned["HostConfig"].get("PortBindings")
            or set(owned["HostConfig"].get("Tmpfs", {}))
            != {"/var/lib/postgresql/data", "/var/run/postgresql"}
        ):
            raise RuntimeError("Refusing cleanup: disposable container identity/topology mismatch")
        docker("rm", "--force", container)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=("published", "checkout", "both"), default="both")
    arguments = parser.parse_args()
    fixture = json.loads(
        (ROOT / "contracts/canvas-worker-consumer-range-oracle.json").read_text(encoding="utf-8")
    )
    for key in ("observed_postgres_image", "observed_image"):
        image = fixture[key]
        if not re.fullmatch(r"[a-z0-9./-]+@sha256:[0-9a-f]{64}", image):
            raise RuntimeError("Oracle images must be immutable digest references")
        docker("pull", image, timeout=180)
    sources = ("published", "checkout") if arguments.source == "both" else (arguments.source,)
    for source in sources:
        print(json.dumps(run(source, fixture), sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as failure:
        message = str(failure) if type(failure) is RuntimeError else type(failure).__name__
        raise SystemExit(f"Canvas consumer oracle failed: {message}") from None
