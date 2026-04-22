#!/usr/bin/env python3
"""阶段 4：Handler 正确性验证统一入口。"""

from __future__ import annotations

import argparse
from typing import TextIO
from phases.common import BASE_DIR, resolve_baseline_path, run_python_script, summarize_verification, emit


def run_phase4(baseline: str | Path | None = None, interactive: bool = False, log_handle: TextIO | None = None) -> Path:
    baseline_path = resolve_baseline_path(baseline, allow_tmp=False)
    args = [str(baseline_path)]
    if interactive:
        args.append("--interactive")
    run_python_script(BASE_DIR / "scripts" / "verify_handlers.py", args, log_handle=log_handle)
    summary = summarize_verification(baseline_path)
    emit(f"[阶段4] 验证摘要: {summary}", log_handle)
    return baseline_path


def main() -> None:
    parser = argparse.ArgumentParser(description="阶段4：验证本地 Handler 与浏览器捕获结果是否一致")
    parser.add_argument("--baseline", help="指定基线文件路径；默认自动选择最新正式基线")
    parser.add_argument("--interactive", action="store_true", help="启用交互式 Payload 补全")
    args = parser.parse_args()
    run_phase4(args.baseline, args.interactive)


if __name__ == "__main__":
    main()
