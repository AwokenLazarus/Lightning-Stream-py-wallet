"""Shared B1_ROOT gate for the suite.

``python -m unittest discover -s tests`` does not import this package: the
start directory is the top level, so each ``test_*.py`` loads as its own
module. ``test_000_b1_root.py`` runs this file first and exits the process
on failure, instead of recording one import error per module.
"""

from __future__ import annotations

import agentwallet.b1path  # noqa: F401  raises RuntimeError when B1_ROOT is unset or has no xbt402/
