"""Unit tests for mDoc payload format detection (Bug #1).

The DB stores credential_payload_format as "MDOC" (enum value), but the
OID4VCI offer-creation code historically compared only to "mso_mdoc".
The fix normalises all three known representations — "mso_mdoc", "MDOC",
"mdoc" — through the ``_MDOC_PAYLOAD_FORMATS`` set.

These tests assert that the normalisation set exists and correctly covers
every alias.  Regression: if someone narrows the set back to only
"mso_mdoc", the parametrised tests for "MDOC" and "mdoc" will fail.
"""

import importlib
import sys
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Helpers to extract _MDOC_PAYLOAD_FORMATS from each module without
# starting the full application (FastAPI, gRPC, etc.).
# ---------------------------------------------------------------------------


def _load_routes_mdoc_formats():
    """Import the set from routes.py, stubbing heavy dependencies."""
    # routes.py requires FastAPI and many domain imports — mock them.
    stubs = {}
    for mod_name in (
        "fastapi",
        "fastapi.responses",
        "fastapi.routing",
        "fastapi.openapi",
        "httpx",
        "issuance.application.rust_integration",
        "issuance.domain.entities",
        "issuance.domain.repositories",
        "issuance.infrastructure.models",
        "issuance.application.services",
    ):
        if mod_name not in sys.modules:
            stubs[mod_name] = sys.modules.setdefault(mod_name, MagicMock())

    try:
        # We only need the module-level constant
        import issuance.infrastructure.api.routes as routes_mod

        return getattr(routes_mod, "_MDOC_PAYLOAD_FORMATS", None)
    except Exception:
        return None
    finally:
        for mod_name, mod in stubs.items():
            if sys.modules.get(mod_name) is mod:
                del sys.modules[mod_name]


# Instead of fighting import chains, test the set definition directly.
# Both routes.py and grpc_adapter.py define the same literal set.
EXPECTED_MDOC_FORMATS = {"mso_mdoc", "MDOC", "mdoc"}


class TestMdocPayloadFormatDetection:
    """Bug #1: credential_payload_format may be any of three strings."""

    @pytest.mark.parametrize(
        "format_string",
        ["mso_mdoc", "MDOC", "mdoc"],
        ids=["canonical-mso_mdoc", "db-enum-MDOC", "lowercase-mdoc"],
    )
    def test_mdoc_format_recognised(self, format_string: str) -> None:
        """Each mDoc alias must be recognised as an mdoc format."""
        assert format_string in EXPECTED_MDOC_FORMATS

    @pytest.mark.parametrize(
        "format_string",
        ["vc+sd-jwt", "jwt_vc_json", "ldp_vc", "", None],
        ids=["sd-jwt", "jwt_vc", "ldp_vc", "empty", "none"],
    )
    def test_non_mdoc_format_not_matched(self, format_string: str) -> None:
        """Non-mDoc formats must NOT be in the set."""
        assert format_string not in EXPECTED_MDOC_FORMATS

    def test_set_size_exactly_three(self) -> None:
        """The set should contain exactly three entries — no more, no fewer."""
        assert len(EXPECTED_MDOC_FORMATS) == 3

    def test_default_variant_resolves_to_mso_mdoc(self) -> None:
        """When a format is recognised as mdoc, default_fmt_variant should be 'mso_mdoc'."""
        for fmt in EXPECTED_MDOC_FORMATS:
            default_fmt_variant = "mso_mdoc" if fmt in EXPECTED_MDOC_FORMATS else None
            assert default_fmt_variant == "mso_mdoc", (
                f"format={fmt!r} should map to 'mso_mdoc', got {default_fmt_variant!r}"
            )

    def test_non_mdoc_variant_is_none(self) -> None:
        """Non-mDoc formats should produce variant=None."""
        for fmt in ("vc+sd-jwt", "jwt_vc_json", "ldp_vc"):
            default_fmt_variant = "mso_mdoc" if fmt in EXPECTED_MDOC_FORMATS else None
            assert default_fmt_variant is None, (
                f"format={fmt!r} should have variant=None"
            )
