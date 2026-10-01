"""Load the shared B1_ROOT gate before any other test module.

Discovery sorts paths, so this file is imported first. It adds no tests.
On failure it exits the process: the loader would otherwise catch the
error and keep importing every other module.
"""

from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

try:
    runpy.run_path(str(Path(__file__).with_name("__init__.py")))
except RuntimeError as exc:
    sys.stderr.write(f"{exc}\n")
    os._exit(2)
