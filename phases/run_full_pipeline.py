#!/usr/bin/env python3
"""全链路统一总控入口。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from common import DEFAULT_PASSWORD, DEFAULT_TARGET_URL, DEFAULT_USERNAME, emit
from phase1_static_analysis import run_phase1
from phase2_prepare_baseline import run_phase2
from phase3_capture import run_phase3
from phase4_verify_handlers import run_phase4
from phase5_assess import run_phase5
from phase6_generate_report import run_phase6


def main() -> None:
    parser = argparse.ArgumentParser(description="按阶段顺序执行完整链路：静态分析→基线→动态捕获→验证→评估→报告")
    parser.add_argument("--url", default=DEFAULT_TARGET_URL, help="目标页面 URL")
    parser.add_argument("--username", default=DEFAULT_USERNAME, help="填入 DOM / 基线的用户名")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="填入 DOM / 基线的密码")
    parser.add_argument("--phase5-send", action="store_true", help="在阶段5启用真实目标验证，将构造场景真正发送到目标 API")
    parser.add_argument("--phase5-timeout", type=float, default=10.0, help="阶段5真实发包超时时间（秒）")
    parser.add_argument("--log-file", default=str(BASE_DIR / "runtime" / "full_pipeline_utf8.log"), help="统一 UTF-8 日志文件路径；默认写入 runtime/full_pipeline_utf8.log")
    args = parser.parse_args()

    log_path = Path(args.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with open(log_path, "w", encoding="utf-8", newline="\n") as log_handle:
        emit(f"[总控] UTF-8 日志文件: {log_path}", log_handle)

        emit("[总控] 阶段1：静态分析", log_handle)
        run_phase1(args.url, log_handle)

        emit("[总控] 阶段2：生成基线并填充 Payload", log_handle)
        baseline_path = run_phase2(args.username, args.password, log_handle)

        emit("[总控] 阶段3：Playwright 动态捕获", log_handle)
        run_phase3(args.url, baseline_path, log_handle)

        emit("[总控] 阶段4：Handler 正确性验证", log_handle)
        run_phase4(baseline_path, False, log_handle)

        emit("[总控] 阶段5：安全评估", log_handle)
        run_phase5(
            baseline_path,
            ["default", "paper_v1"],
            log_handle,
            send_requests=args.phase5_send,
            timeout=args.phase5_timeout,
        )

        emit("[总控] 阶段6：生成报告与图表", log_handle)
        run_phase6(baseline_path, "paper_v1", log_handle)

        emit(f"[总控] 全链路完成，最终基线: {baseline_path}", log_handle)


if __name__ == "__main__":
    main()
