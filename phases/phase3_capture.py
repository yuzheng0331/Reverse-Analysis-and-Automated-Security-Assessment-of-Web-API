#!/usr/bin/env python3
"""阶段 3：Playwright 动态捕获统一入口。"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import TextIO

from phases.common import BASE_DIR, DEFAULT_TARGET_URL, resolve_baseline_path, run_python_script, emit


def run_phase3(
    url: str,
    baseline: str | Path | None = None,
    concurrency: int = 4,
    settle_ms: int = 300,
    nav_timeout_ms: int = 10000,
    algo_batch: bool = True,
    log_handle: TextIO | None = None,
) -> Path:
    baseline_path = resolve_baseline_path(baseline, allow_tmp=False)
    run_python_script(
        BASE_DIR / "scripts" / "capture_baseline_playwright.py",
        [
            "--url", url,
            "--skeleton", str(baseline_path),
            "--concurrency", str(max(1, int(concurrency))),
            "--settle-ms", str(max(0, int(settle_ms))),
            "--nav-timeout-ms", str(max(1000, int(nav_timeout_ms))),
            "--algo-batch" if algo_batch else "--no-algo-batch",
        ],
        log_handle=log_handle,
    )
    emit(f"[阶段3] 动态捕获已回填到: {baseline_path}", log_handle)
    return baseline_path


def main() -> None:
    parser = argparse.ArgumentParser(description="阶段3：执行 Playwright 动态捕获")
    parser.add_argument("--url", default=DEFAULT_TARGET_URL, help="目标页面 URL")
    parser.add_argument("--baseline", help="指定基线文件路径；默认自动选择最新正式基线")
    parser.add_argument("--concurrency", type=int, default=4, help="并发捕获端点数量（默认 4）")
    parser.add_argument("--settle-ms", type=int, default=300, help="每端点触发后额外等待毫秒数（默认 300）")
    parser.add_argument("--nav-timeout-ms", type=int, default=10000, help="页面导航超时毫秒（默认 10000）")
    parser.add_argument("--algo-batch", dest="algo_batch", action="store_true", help="按算法分批并发（默认开启）")
    parser.add_argument("--no-algo-batch", dest="algo_batch", action="store_false", help="关闭按算法分批")
    parser.set_defaults(algo_batch=True)
    args = parser.parse_args()
    run_phase3(args.url, args.baseline, args.concurrency, args.settle_ms, args.nav_timeout_ms, args.algo_batch)


if __name__ == "__main__":
    main()
