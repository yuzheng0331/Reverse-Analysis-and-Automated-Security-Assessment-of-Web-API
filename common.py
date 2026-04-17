"""Top-level compatibility shim for historical imports.

Some modules import `from common import ...` expecting a top-level module.
This file re-exports the implementation under `phases/common.py` to avoid
ModuleNotFoundError when running the pipeline from the repository root.
"""
from __future__ import annotations

from phases.common import *  # noqa: F401,F403

__all__ = [name for name in dir() if not name.startswith("_")]

