"""Validate the portable range corpus and real startup acceptance without SQL.

The mandatory CI PostgreSQL lane separately replays every downstream case and
the actual worker loop. Passing these structural checks alone is not SQL parity.
"""

import itertools
import json
import os
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from issuance.canvas_worker import CanvasSyncWorkerConfig

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = json.loads(
    (ROOT / "contracts/canvas-worker-consumer-range-oracle.json").read_text(encoding="utf-8")
)


class CanvasWorkerConsumerRangeOracleTests(unittest.TestCase):
    def test_portable_inputs_cover_every_field_at_every_frozen_range(self):
        self.assertEqual(FIXTURE["schema"], "elevenid.canvas-worker-consumer-range-oracle/v1")
        self.assertEqual(FIXTURE["integer_encoding"], "base-10-string")
        self.assertEqual(
            set(FIXTURE["fields"]),
            {"batch_size", "lease_seconds", "schedule_limit", "oauth_revocation_limit"},
        )
        self.assertEqual(len(FIXTURE["inputs"]), 9)
        for value in FIXTURE["inputs"].values():
            self.assertIsInstance(value, str)
            self.assertIsNotNone(re.fullmatch(r"[1-9][0-9]*", value))
        self.assertEqual(len(FIXTURE["inputs"]["integer_digit_limit"]), 4300)
        self.assertEqual(FIXTURE["inputs"]["above_i64"], "9223372036854775808")
        self.assertEqual(FIXTURE["inputs"]["above_u64"], "18446744073709551616")
        expected = set(itertools.product(FIXTURE["fields"], FIXTURE["inputs"]))
        actual = [(case["field"], case["input"]) for case in FIXTURE["cases"]]
        self.assertEqual(set(actual), expected)
        self.assertEqual(len(actual), len(expected))

    def test_published_provenance_and_disposable_database_scope_are_frozen(self):
        self.assertEqual(FIXTURE["observed_source"], "85b128a85426b3f5aeaf6f948ba5dfa2836e95d8")
        self.assertEqual(
            FIXTURE["observed_source_sha256"],
            "c5a7a692af7a808486b0a42d379699222bdf01f3995181c16da9d3466666e90a",
        )
        self.assertEqual(
            FIXTURE["observed_repository_sha256"],
            "34ba42bd10227e0040c99378254c3652c388bab3131aadfdba2e0fe92cf89ccb",
        )
        self.assertEqual(
            FIXTURE["observation_sha256"],
            "67a26629d39ca1cb98a8be9732fcdf7a7386d005b563127beafc6dd308367925",
        )
        self.assertEqual(FIXTURE["migration_revisions"], ["merge_issuance_heads"])
        self.assertEqual(FIXTURE["observed_postgres_version"], "15.17")
        self.assertIn("empty published migrated tables", FIXTURE["database_scope"])
        for key in ("observed_image", "observed_postgres_image"):
            self.assertRegex(FIXTURE[key], r"@sha256:[0-9a-f]{64}$")

    def test_all_36_values_are_accepted_by_the_actual_configuration_factory(self):
        for case in FIXTURE["cases"]:
            with self.subTest(field=case["field"], input=case["input"]):
                value = FIXTURE["inputs"][case["input"]]
                environment = {
                    "CANVAS_SYNC_WORKER_ID": "consumer-range-oracle",
                    FIXTURE["fields"][case["field"]]: value,
                }
                with patch.dict(os.environ, environment, clear=True):
                    actual = CanvasSyncWorkerConfig.from_env()
                self.assertEqual(str(getattr(actual, case["field"])), value)
                self.assertEqual(FIXTURE["outcomes"][case["expected"]]["configuration"], "accepted")

    def test_expected_errors_occur_at_the_frozen_consumer_phase(self):
        self.assertEqual(len(FIXTURE["outcomes"]), 4)
        for case in FIXTURE["cases"]:
            with self.subTest(field=case["field"], input=case["input"]):
                expected = FIXTURE["outcomes"][case["expected"]]
                events = expected["events"]
                self.assertEqual(events[0], {"phase": "heartbeat", "event": "scheduling"})
                self.assertEqual(
                    events[1:3],
                    [
                        {"phase": "oauth_queue", "event": "start"},
                        {"phase": "oauth_queue", "event": "complete", "row_count": 0},
                    ],
                )
                if expected["cycle"] == "completed":
                    self.assertNotIn("legacy_error", expected)
                    self.assertFalse(any(event["event"] == "error" for event in events))
                else:
                    self.assertEqual(events[-1]["event"], "error")
                    self.assertIn(events[-1]["phase"], {"scheduling", "leasing"})
                    self.assertEqual(
                        {key: events[-1][key] for key in ("class", "driver_class", "sqlstate")},
                        expected["legacy_error"],
                    )
                # A huge OAuth limit must not be rejected at startup or at SQL;
                # the published repository caps to500 before machine binding.
                if case["field"] == "oauth_revocation_limit":
                    self.assertEqual(expected["cycle"], "completed")

    def test_error_loops_repeat_the_complete_sequence_and_stop_normally(self):
        cases = FIXTURE["loop_cases"]
        self.assertEqual(len(cases), 3)
        self.assertEqual(
            {case["field"] for case in cases}, {"batch_size", "lease_seconds", "schedule_limit"}
        )
        for case in cases:
            self.assertEqual(case["input"], "above_i64")
            self.assertEqual(case["cycles"], 2)
            self.assertTrue(case["stopped_normally"])
            self.assertEqual(FIXTURE["outcomes"][case["cycle_events_from"]]["cycle"], "error")


if __name__ == "__main__":
    unittest.main()
