#!/usr/bin/env python3
"""Run the mdoc boundary regression against an owned disposable TLS OpenBao."""

import argparse
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

IMAGE = "quay.io/openbao/openbao@sha256:6150c4a6b62067db6141c8da7a6a6b5763f4f47c315343d0c848b40fecdfd452"
ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bao-binary", type=Path, help="Use an explicitly supplied local OpenBao binary"
    )
    args = parser.parse_args()
    token = secrets.token_hex(32)
    nonce = secrets.token_hex(24)
    container = None
    process = None
    with tempfile.TemporaryDirectory(prefix="marty-credentials-mdoc-") as temporary:
        work = Path(temporary)
        ca = work / "vault-ca.pem"
        with (work / "server.log").open("wb") as log:
            try:
                if args.bao_binary:
                    with socket.socket() as listener:
                        listener.bind(("127.0.0.1", 0))
                        port = listener.getsockname()[1]
                    process = subprocess.Popen(
                        [
                            str(args.bao_binary.resolve()),
                            "server",
                            "-dev-tls",
                            "-dev-tls-cert-dir=" + str(work),
                            "-dev-listen-address=127.0.0.1:" + str(port),
                        ],
                        env={**os.environ, "BAO_DEV_ROOT_TOKEN_ID": token},
                        stdout=log,
                        stderr=log,
                    )
                else:
                    container = subprocess.check_output(
                        [
                            "docker",
                            "run",
                            "--rm",
                            "-d",
                            "--tmpfs",
                            "/tmp/certs:mode=0777",
                            "-e",
                            "BAO_DEV_ROOT_TOKEN_ID=" + token,
                            "-p",
                            "127.0.0.1::8200",
                            IMAGE,
                            "server",
                            "-dev-tls",
                            "-dev-tls-cert-dir=/tmp/certs",
                            "-dev-listen-address=:8200",
                        ],
                        text=True,
                    ).strip()
                    binding = subprocess.check_output(
                        ["docker", "port", container, "8200/tcp"], text=True
                    ).strip()
                    if not binding.startswith("127.0.0.1:"):
                        raise RuntimeError("The disposable instance is not bound to loopback")
                    port = int(binding.rsplit(":", 1)[1])
                base = "https://127.0.0.1:" + str(port)
                deadline = time.monotonic() + 30
                client = None
                while time.monotonic() < deadline:
                    if process and process.poll() is not None:
                        raise RuntimeError("The owned OpenBao process exited before TLS readiness")
                    if container:
                        result = subprocess.run(
                            ["docker", "exec", container, "cat", "/tmp/certs/vault-ca.pem"],
                            capture_output=True,
                            check=False,
                        )
                        if result.returncode == 0:
                            ca.write_bytes(result.stdout)
                    try:
                        context = ssl.create_default_context(cafile=str(ca))
                        client = urllib.request.build_opener(
                            urllib.request.ProxyHandler({}),
                            urllib.request.HTTPSHandler(context=context),
                        )
                        with client.open(base + "/v1/sys/health", timeout=2):
                            break
                    except (OSError, ValueError):
                        time.sleep(0.25)
                else:
                    raise RuntimeError(
                        "The disposable OpenBao did not become ready with verified TLS"
                    )

                def post(path, body):
                    request = urllib.request.Request(
                        base + "/v1/" + path,
                        method="POST",
                        data=json.dumps(body).encode(),
                        headers={"X-Vault-Token": token, "Content-Type": "application/json"},
                    )
                    with client.open(request, timeout=10):
                        pass

                post("secret/data/marty-test-disposable-guard", {"data": {"nonce": nonce}})
                post("sys/mounts/transit", {"type": "transit"})
                environment = {
                    **os.environ,
                    "MARTY_TEST_OPENBAO_URL": base,
                    "MARTY_TEST_OPENBAO_TOKEN": token,
                    "MARTY_TEST_OPENBAO_DISPOSABLE_NONCE": nonce,
                    "MARTY_TEST_OPENBAO_CA_CERT": str(ca),
                }
                return subprocess.call(
                    [
                        sys.executable,
                        "-m",
                        "pytest",
                        "-q",
                        "rust/marty-rs/tests/python/test_mdoc_hsm_roundtrip.py",
                    ],
                    cwd=ROOT,
                    env=environment,
                )
            finally:
                if process:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                if container:
                    subprocess.run(
                        ["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, check=False
                    )


if __name__ == "__main__":
    raise SystemExit(main())
