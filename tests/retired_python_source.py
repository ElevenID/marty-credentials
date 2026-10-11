"""Detect retired Python source without treating ignored bytecode as source."""

from pathlib import Path


def has_source(directory: Path) -> bool:
    return any(
        path.is_file()
        and not (
            path.suffix == ".pyc"
            and "__pycache__" in path.relative_to(directory).parts[:-1]
        )
        for path in directory.rglob("*")
    )
