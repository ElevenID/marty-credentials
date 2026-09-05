"""Test owned resource cleanup and failure handling without contacting Docker."""

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "canvas_consumer_oracle_runner", ROOT / "scripts/run_canvas_worker_consumer_oracle.py"
)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
DATABASE_ID = "a" * 64
PROBE_ID = "b" * 64


class CanvasConsumerOracleRunnerTests(unittest.TestCase):
    def replay(self, *, fail_wait=False, fail_probe=False, network="none", wrong_probe_owner=False):
        calls = []
        report = {"status": "passed", "cycle_cases": 36, "loop_cases": 3}
        if fail_probe:
            report = {"status": "failed", "check": "Cycle result mismatch: batch_size/above_i64"}

        def docker(*arguments, **_):
            calls.append(arguments)
            operation = arguments[0]
            if operation == "create":
                return PROBE_ID if f"{RUNNER.LABEL}=probe" in arguments else DATABASE_ID
            if operation == "wait":
                if fail_wait:
                    raise subprocess.TimeoutExpired("docker wait", 180)
                return "1" if fail_probe else "0"
            if operation == "logs":
                return json.dumps(report)
            if operation == "inspect":
                probe = arguments[1] == PROBE_ID
                return json.dumps(
                    [
                        {
                            "Id": arguments[1],
                            "Config": {
                                "Labels": {
                                    RUNNER.LABEL: "wrong"
                                    if probe and wrong_probe_owner
                                    else "probe"
                                    if probe
                                    else "true"
                                }
                            },
                            "HostConfig": {
                                "NetworkMode": f"container:{DATABASE_ID}" if probe else network,
                                "PortBindings": {},
                                "Tmpfs": {
                                    "/var/lib/postgresql/data": "",
                                    "/var/run/postgresql": "",
                                },
                            },
                        }
                    ]
                )
            return ""

        with (
            patch.object(RUNNER, "docker", side_effect=docker),
            patch.object(RUNNER.subprocess, "run", return_value=SimpleNamespace(returncode=0)),
        ):
            try:
                actual = RUNNER.run(
                    "checkout",
                    {"observed_postgres_image": "postgres", "observed_image": "issuance"},
                )
            except Exception as error:
                return calls, error
        return calls, actual

    def test_success_removes_only_exact_probe_then_database(self):
        calls, actual = self.replay()
        self.assertEqual(actual["status"], "passed")
        self.assertEqual(
            [call for call in calls if call[0] == "rm"],
            [("rm", "--force", PROBE_ID), ("rm", "--force", DATABASE_ID)],
        )
        probe = next(
            call for call in calls if call[0] == "create" and f"{RUNNER.LABEL}=probe" in call
        )
        self.assertIn("--read-only", probe)
        self.assertIn("PYTHONPATH=/verification/services:/app/services", probe)
        self.assertIn(f"container:{DATABASE_ID}", probe)
        self.assertIn("ALL", probe)
        self.assertIn("no-new-privileges", probe)

    def test_timeout_does_not_restart_probe_and_still_cleans_both_owned_resources(self):
        calls, error = self.replay(fail_wait=True)
        self.assertIsInstance(error, subprocess.TimeoutExpired)
        self.assertEqual(len([call for call in calls if call[0] == "create"]), 2)
        self.assertEqual(
            [call for call in calls if call[0] == "rm"],
            [("rm", "--force", PROBE_ID), ("rm", "--force", DATABASE_ID)],
        )

    def test_failed_contract_propagates_failure_and_still_cleans_owned_resources(self):
        calls, error = self.replay(fail_probe=True)
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("Cycle result mismatch", str(error))
        self.assertEqual(len([call for call in calls if call[0] == "rm"]), 2)

    def test_database_topology_mismatch_refuses_database_removal(self):
        calls, error = self.replay(network="bridge")
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("topology mismatch", str(error))
        self.assertNotIn(("rm", "--force", DATABASE_ID), calls)

    def test_probe_owner_mismatch_refuses_removal(self):
        calls, error = self.replay(wrong_probe_owner=True)
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("probe identity", str(error))
        self.assertFalse(any(call[0] == "rm" for call in calls))


if __name__ == "__main__":
    unittest.main()
