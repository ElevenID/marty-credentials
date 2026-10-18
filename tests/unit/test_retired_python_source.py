from pathlib import Path

from tests.retired_python_source import has_source


def test_python_issuance_owner_stays_retired() -> None:
    """One source boundary for Rust-owned templates, applications and issuance.

    Route and behavior contracts remain in their dedicated tests; each feature
    does not need to repeat this identical whole-directory assertion.
    """
    root = Path(__file__).resolve().parents[2]
    assert not has_source(root / "services" / "issuance")


def test_retired_owner_gate_ignores_bytecode_but_rejects_reintroduced_source(
    tmp_path: Path,
) -> None:
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "issuer.cpython-312.pyc").write_bytes(b"old bytecode")
    assert not has_source(tmp_path)

    (tmp_path / "issuer.py").write_text("issuer_private_key = True", encoding="utf-8")
    assert has_source(tmp_path)

    (tmp_path / "issuer.py").unlink()
    (tmp_path / "issuer.pyc").write_bytes(b"sourceless bytecode")
    assert has_source(tmp_path)
