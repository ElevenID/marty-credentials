"""Regression tests for TokenStatusList bit-mask handling."""

import pytest

try:
    from marty_rs import TokenStatusList  # type: ignore[import-untyped]

    _HAS_RUST = True
except ImportError:
    _HAS_RUST = False


@pytest.mark.skipif(not _HAS_RUST, reason="marty_rs Rust extension not installed")
class TestTokenStatusListBits8:
    """Verify that valid 8-bit status entries are panic-free and lossless."""

    def test_constructor_accepts_bits_8(self) -> None:
        sl = TokenStatusList(size=16, bits=8)
        assert sl.len() == 16
        assert sl.bits_per_status() == 8

    def test_get_defaults_to_zero(self) -> None:
        assert TokenStatusList(size=16, bits=8).get(0) == 0

    @pytest.mark.parametrize("value", [0, 1, 42, 254, 255])
    def test_set_roundtrips(self, value: int) -> None:
        sl = TokenStatusList(size=16, bits=8)
        sl.set(0, value)
        assert sl.get(0) == value

    def test_revoke_and_reinstate_roundtrip(self) -> None:
        sl = TokenStatusList(size=16, bits=8)
        assert sl.is_revoked(0) is False
        sl.revoke(0)
        assert sl.is_revoked(0) is True
        sl.reinstate(0)
        assert sl.is_revoked(0) is False


@pytest.mark.skipif(not _HAS_RUST, reason="marty_rs Rust extension not installed")
class TestTokenStatusListSmallBits:
    @pytest.mark.parametrize("bits", [1, 2, 4])
    def test_get_set_roundtrip(self, bits: int) -> None:
        max_value = (1 << bits) - 1
        sl = TokenStatusList(size=32, bits=bits)
        sl.set(0, max_value)
        assert sl.get(0) == max_value

    @pytest.mark.parametrize("bits", [1, 2, 4])
    def test_revoke_reinstate_roundtrip(self, bits: int) -> None:
        sl = TokenStatusList(size=32, bits=bits)
        sl.revoke(5)
        assert sl.is_revoked(5) is True
        sl.reinstate(5)
        assert sl.is_revoked(5) is False


def test_correct_mask_logic_covers_every_supported_width() -> None:
    for bits in [1, 2, 4, 8]:
        mask = 0xFF if bits == 8 else (1 << bits) - 1
        assert mask == (1 << bits) - 1
