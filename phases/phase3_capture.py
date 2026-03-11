#!/usr/bin/env python3
"""阶段 3：Playwright 动态捕获统一入口。"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import TextIO

from common import BASE_DIR, DEFAULT_TARGET_URL, resolve_baseline_path, run_python_script, emit


def run_phase3(url: str, baseline: str | Path | None = None, log_handle: TextIO | None = None) -> Path:
    baseline_path = resolve_baseline_path(baseline, allow_tmp=False)
    run_python_script(
        BASE_DIR / "scripts" / "capture_baseline_playwright.py",
        ["--url", url, "--skeleton", str(baseline_path)],
        log_handle=log_handle,
    )
    emit(f"[阶段3] 动态捕获已回填到: {baseline_path}", log_handle)
    return baseline_path


def main() -> None:
    parser = argparse.ArgumentParser(description="阶段3：执行 Playwright 动态捕获")
    parser.add_argument("--url", default=DEFAULT_TARGET_URL, help="目标页面 URL")
    parser.add_argument("--baseline", help="指定基线文件路径；默认自动选择最新正式基线")
    args = parser.parse_args()
    run_phase3(args.url, args.baseline)


if __name__ == "__main__":
    main()
