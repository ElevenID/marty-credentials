"""Execute every portable numeric vector against the real Python configuration.

Integers use decimal strings so a fixture consumer cannot silently round values
above JSON/IEEE-754 or machine-integer limits. These are startup observations,
not permission to activate Rust before downstream and whole-worker parity.
"""

import json
import os
import re
import sys
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from issuance.canvas_worker import CanvasSyncWorkerConfig

FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[2] / "contracts/canvas-worker-numeric-lexical-oracle.json"
    ).read_text(encoding="utf-8")
)
INTEGER_FIELDS = {"batch_size", "lease_seconds", "schedule_limit", "oauth_revocation_limit"}


def portable_configuration(config: CanvasSyncWorkerConfig) -> dict:
    values = asdict(config)
    return {key: str(value) if key in INTEGER_FIELDS else value for key, value in values.items()}


class CanvasWorkerNumericOracleTests(unittest.TestCase):
    def test_fixture_has_exact_portable_structure_and_published_provenance(self) -> None:
        self.assertEqual(FIXTURE["schema"], "elevenid.canvas-worker-numeric-lexical-oracle/v1")
        self.assertEqual(FIXTURE["integer_encoding"], "base-10-string")
        self.assertEqual(FIXTURE["observed_source"], "85b128a85426b3f5aeaf6f948ba5dfa2836e95d8")
        self.assertEqual(FIXTURE["observed_source_path"], "services/issuance/canvas_worker.py")
        self.assertEqual(FIXTURE["observed_python_version"], "3.12.13")
        self.assertEqual(FIXTURE["integer_decimal_digit_limit"], 4300)
        self.assertEqual(
            FIXTURE["observed_image"],
            "ghcr.io/elevenid/marty-credentials-issuance@sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176",
        )
        self.assertEqual(
            FIXTURE["observed_source_sha256"],
            "c5a7a692af7a808486b0a42d379699222bdf01f3995181c16da9d3466666e90a",
        )
        self.assertEqual(
            FIXTURE["baseline_fixture_revision"],
            "85329f647c1d8c51ad709f1eed97cedcb3bb6464",
        )
        self.assertEqual(
            FIXTURE["baseline_fixture_sha256"],
            "1fb81c050ab1cdd34e992ad6a3eaf770df2def8073d5d6cb5895ba1c89355ade",
        )
        cases = FIXTURE["cases"]
        self.assertEqual(len(cases), 64)
        self.assertEqual(len({case["name"] for case in cases}), len(cases))
        # Guard decoded Unicode explicitly: an ANSI round trip must not turn
        # intended numeric inputs into unrelated malformed-string vectors.
        arabic_case = next(
            case for case in cases if case["name"] == "arabic_decimal_digits-integer"
        )
        self.assertEqual(arabic_case["environment"]["CANVAS_SYNC_SCHEDULE_LIMIT"], "\u0661\u0662")
        self.assertEqual(
            {next(iter(case["environment"])) for case in cases},
            {"CANVAS_SYNC_SCHEDULE_LIMIT", "CANVAS_SYNC_WORKER_POLL_SECONDS"},
        )
        for case in cases:
            with self.subTest(case=case["name"]):
                self.assertEqual(len(case["environment"]), 1)
                self.assertIsInstance(next(iter(case["environment"].values())), str)
                self.assertNotEqual("expected" in case, "expected_error" in case)
                if "expected" in case:
                    self.assertEqual(set(case["expected"]), set(FIXTURE["defaults"]))
                    for field in INTEGER_FIELDS:
                        value = case["expected"][field]
                        self.assertIsInstance(value, str)
                        self.assertIsNotNone(re.fullmatch(r"-?(0|[1-9][0-9]*)", value))
                else:
                    self.assertEqual(
                        case["expected_error"],
                        {
                            "phase": "configuration",
                            "category": "invalid_number",
                            "legacy_exception": "ValueError",
                        },
                    )

    def test_every_vector_matches_the_actual_configuration_factory(self) -> None:
        # A different interpreter policy must be reviewed, not silently treated
        # as proof for the selected published runtime. Do not skip its vectors.
        self.assertEqual(sys.get_int_max_str_digits(), FIXTURE["integer_decimal_digit_limit"])
        observed_count = 0
        for case in FIXTURE["cases"]:
            environment = {"CANVAS_SYNC_WORKER_ID": "oracle-worker", **case["environment"]}
            with self.subTest(case=case["name"]), patch.dict(os.environ, environment, clear=True):
                if "expected_error" in case:
                    with self.assertRaises(ValueError):
                        CanvasSyncWorkerConfig.from_env()
                else:
                    actual = portable_configuration(CanvasSyncWorkerConfig.from_env())
                    self.assertEqual(actual, case["expected"])
                observed_count += 1
        self.assertEqual(observed_count, 64)


if __name__ == "__main__":
    unittest.main()
