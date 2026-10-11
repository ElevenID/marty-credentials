from pathlib import Path

from tests.retired_python_source import has_source


def test_retired_owner_gate_ignores_bytecode_but_rejects_reintroduced_source(
    tmp_path: Path,
) -> None:
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "issuer.cpython-312.pyc").write_bytes(b"old bytecode")
    assert not has_source(tmp_path)

    (tmp_path / "issuer.py").write_text("issuer_private_key = True", encoding="utf-8")
    assert has_source(tmp_path)
