"""Historical expectations for the original Python mdoc format aliases.

These self-contained cases describe the old format set. They do not import
the retired routes or exercise the live Rust service's format detection.
"""

import pytest


# Live route behavior belongs to the Rust owner.
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
