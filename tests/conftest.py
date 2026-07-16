"""Repository-wide pytest bootstrap for service modules."""

from __future__ import annotations

import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
for package_root in (REPOSITORY_ROOT / "services", REPOSITORY_ROOT / "python"):
    if str(package_root) not in sys.path:
        sys.path.insert(0, str(package_root))
