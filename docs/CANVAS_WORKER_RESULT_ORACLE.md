# Canvas worker result-projection oracle

`contracts/canvas-worker-result-oracle.json` contains portable JSON input/output
observations of the actual Python `_safe_result` function. The executable tests
call that function directly; they do not duplicate its implementation. The
observed worker blob is `b516ed3d0855f16e9ec899a452a22df49d2cafe5` at protected
source `d6b6dd67fd9674eb14388320e65d3ae9642b3b42`.

Each value case is exercised against all 17 allowed fields. Unknown fields,
including case/whitespace variants, are rejected for the same value matrix.
Inputs and expected values use JSON strings so consumers preserve the numeric
distinction between `1` and `1.0`, and can observe integers beyond `u64` without
an intermediate JavaScript parser rounding the fixture itself.

Observed behavior preserves null and boolean types, clamps negative integers to
zero, preserves positive integers, and limits strings to 200 Unicode code points.
That is not a UTF-8 byte limit or a grapheme-cluster limit. Arrays, objects and
floating-point numbers (including `1.0`) are omitted rather than coerced.
The tests additionally prove no input mutation, the complete allowlist in one
result, an empty result, and omission of representative non-JSON host values.

The large positive and negative integer cases require Rust reconciliation: do not silently
round or drop an observed integer, or claim full JSON numeric parity based only
on small counters. No runtime, dependency, crypto or consumer change is made by
this oracle. This fixture is not recursive secret redaction, provider error
sanitization, complete worker equivalence or authorization to delete Python.
Whole-worker, PostgreSQL, readiness, consumer-routing and beta acceptance gates
remain required. Rust should consume these fixtures around its canonical result
projection rather than copying Python implementation structure.

Source review of the currently unrouted Rust candidate finds integer branches
for `i64` and `u64`, but no branch that preserves integers beyond those ranges.
The beyond-`u64` preservation and below-`i64` clamping fixtures must be included in the future
executed differential, not filtered out to obtain a green result. This is a
source-review finding; no Rust differential or cutover pass is claimed here.
