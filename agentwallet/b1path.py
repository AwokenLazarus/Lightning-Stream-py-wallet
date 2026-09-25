"""Put the B1 xbt402 library on sys.path. Keys still never live in this process's MCP layer."""

from __future__ import annotations

import os
import sys
from pathlib import Path

_B1 = Path(os.environ.get("B1_ROOT", Path.home() / "xbt-rnd" / "b1")).resolve()


def ensure_b1() -> Path:
    root = str(_B1)
    if root not in sys.path:
        sys.path.insert(0, root)
    return _B1
