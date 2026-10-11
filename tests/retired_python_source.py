"""Detect retired Python source without treating ignored bytecode as source."""

from pathlib import Path


def has_source(directory: Path) -> bool:
    return any(path.is_file() and path.suffix != ".pyc" for path in directory.rglob("*"))
