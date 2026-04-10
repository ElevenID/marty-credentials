"""Unit tests exposing the TokenStatusList bits=8 overflow bug.

Bug: ``TokenStatusList.get()`` and ``set()`` compute ``(1u8 << self.bits) - 1``
as a mask.  When ``bits=8``, this evaluates ``1u8 << 8`` which:
  - In debug builds: panics with "attempt to shift left with overflow"
  - In release builds: undefined behaviour (wraps to 0, mask becomes 255 → 0 - 1 = 255... or 0)

The constructor explicitly accepts bits=8 (``if ![1, 2, 4, 8].contains(&bits)``),
so this is a valid, accepted configuration that crashes at runtime.

The correct mask for bits=8 should be 0xFF (all bits set).

These tests also check the new ``set()`` validation which uses u16 for the
max-value check (safe) but then immediately computes the mask with u8 (unsafe).
"""

import pytest

# Try importing the compiled Rust extension.  If it's not available (no
# maturin develop), skip the tests gracefully.
try:
    from marty_rs import TokenStatusList  # type: ignore[import-untyped]
    _HAS_RUST = True
except ImportError:
    _HAS_RUST = False


@pytest.mark.skipif(not _HAS_RUST, reason="marty_rs Rust extension not installed")
class TestTokenStatusListBits8Overflow:
    """Expose the u8 shift-overflow bug when bits=8."""

    def test_constructor_accepts_bits_8(self) -> None:
        """bits=8 is explicitly in the allow-list and should not error."""
        sl = TokenStatusList(size=16, bits=8)
        assert sl.len() == 16
        assert sl.bits_per_status() == 8

    def test_get_with_bits_8_panics(self) -> None:
        """BUG: get() panics on bits=8 due to 1u8 << 8 overflow.

        This would be a PanicException in PyO3 (debug) or wrong result (release).
        """
        sl = TokenStatusList(size=16, bits=8)
        # In debug Rust builds, this raises a panic wrapped as a Python exception
        # In release builds, the mask may be 0 (wrong) — giving incorrect results
        with pytest.raises(BaseException):
            sl.get(0)

    def test_set_with_bits_8_panics(self) -> None:
        """BUG: set() panics on bits=8 due to 1u8 << 8 in mask computation.

        The max_value validation (line ~107, uses u16) passes fine for values 0-255,
        but the actual masking on the next line uses u8 and overflows.
        """
        sl = TokenStatusList(size=16, bits=8)
        with pytest.raises(BaseException):
            sl.set(0, 42)

    def test_is_revoked_with_bits_8_panics(self) -> None:
        """is_revoked() delegates to get() and inherits the overflow."""
        sl = TokenStatusList(size=16, bits=8)
        with pytest.raises(BaseException):
            sl.is_revoked(0)

    def test_revoke_with_bits_8_panics(self) -> None:
        """revoke() delegates to set(index, 1) and inherits the overflow."""
        sl = TokenStatusList(size=16, bits=8)
        with pytest.raises(BaseException):
            sl.revoke(0)


@pytest.mark.skipif(not _HAS_RUST, reason="marty_rs Rust extension not installed")
class TestTokenStatusListSmallBitsWork:
    """Contrast: bits=1/2/4 work correctly (no overflow)."""

    @pytest.mark.parametrize("bits", [1, 2, 4])
    def test_get_set_roundtrip(self, bits: int) -> None:
        """Set and get a value with bits < 8 — should work."""
        max_val = (1 << bits) - 1
        sl = TokenStatusList(size=32, bits=bits)
        sl.set(0, max_val)
        assert sl.get(0) == max_val

    @pytest.mark.parametrize("bits", [1, 2, 4])
    def test_revoke_reinstate_roundtrip(self, bits: int) -> None:
        sl = TokenStatusList(size=32, bits=bits)
        sl.revoke(5)
        assert sl.is_revoked(5) is True
        sl.reinstate(5)
        assert sl.is_revoked(5) is False


class TestTokenStatusListBits8MaskLogic:
    """Pure Python reproduction of the overflow logic to document the bug
    even when the Rust extension is not available."""

    def test_mask_computation_overflows_for_bits_8(self) -> None:
        """Demonstrate that (1u8 << 8) is invalid in any language with fixed-width integers."""
        bits = 8
        # Python integers are arbitrary-precision, so 1 << 8 = 256, but
        # cast to u8 that's 0 — which then -1 wraps to 255 (or panics).
        mask_u16 = (1 << bits) - 1  # 255 — correct
        assert mask_u16 == 255

        # Simulating u8 overflow:
        mask_u8_overflow = ((1 << bits) & 0xFF)  # 256 & 0xFF = 0
        mask_u8_result = (mask_u8_overflow - 1) & 0xFF  # (0 - 1) & 0xFF = 255
        # In Rust debug mode, this would panic before reaching the subtraction
        assert mask_u8_overflow == 0, "1u8 << 8 overflows to 0"

    def test_correct_fix_uses_special_case_for_bits_8(self) -> None:
        """The correct fix: mask = if bits == 8 { 0xFF } else { (1u8 << bits) - 1 }"""
        for bits in [1, 2, 4, 8]:
            if bits == 8:
                mask = 0xFF
            else:
                mask = (1 << bits) - 1
            expected = (1 << bits) - 1
            assert mask == expected, f"bits={bits}: mask should be {expected}"
