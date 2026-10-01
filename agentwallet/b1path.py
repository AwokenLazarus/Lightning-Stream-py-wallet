"""Put the B1 xbt402 library on sys.path. Keys still never live in this process's MCP layer.

``B1_ROOT`` is required at import. This module does not guess a b1 working tree.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

B1_ROOT_REQUIRED = (
    "B1_ROOT is not set: point it at a b1 tree or snapshot "
    "(for example ~/xbt-rnd/b1, whose master is the accepted line, or a cmp-rails snapshot); "
    "B2 never guesses which b1 to test against"
)


def _b1_root() -> Path:
    raw = os.environ.get("B1_ROOT")
    if raw is None or not raw.strip():
        raise RuntimeError(B1_ROOT_REQUIRED)
    root = Path(raw).expanduser().resolve()
    if not (root / "xbt402").is_dir():
        raise RuntimeError(f"{B1_ROOT_REQUIRED} ({root} has no xbt402/ package)")
    return root


_B1 = _b1_root()


def ensure_b1() -> Path:
    root = str(_B1)
    if root not in sys.path:
        sys.path.insert(0, root)
    return _B1
