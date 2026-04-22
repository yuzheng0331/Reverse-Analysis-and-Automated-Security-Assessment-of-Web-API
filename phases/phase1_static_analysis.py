#!/usr/bin/env python3
"""阶段 1：静态分析统一入口。"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import TextIO

from phases.common import BASE_DIR, DEFAULT_TARGET_URL, latest_matching_file, run_python_script, emit


def run_phase1(url: str, log_handle: TextIO | None = None) -> Path:
    run_python_script(BASE_DIR / "collect" / "static_analyze.py", ["--url", url], log_handle=log_handle)
    latest = latest_matching_file(BASE_DIR / "collect" / "static_analysis", "static_analysis_*.json")
    if not latest:
        raise FileNotFoundError("静态分析完成后未找到 static_analysis_*.json")
    emit(f"[阶段1] 静态分析结果: {latest}", log_handle)
    return latest


def main() -> None:
    parser = argparse.ArgumentParser(description="阶段1：执行静态分析")
    parser.add_argument("--url", default=DEFAULT_TARGET_URL, help="目标页面 URL")
    args = parser.parse_args()
    run_phase1(args.url)


if __name__ == "__main__":
    main()
