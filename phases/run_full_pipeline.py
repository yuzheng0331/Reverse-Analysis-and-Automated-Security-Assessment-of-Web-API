#!/usr/bin/env python3
"""全链路统一总控入口。"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from phases.common import DEFAULT_PASSWORD, DEFAULT_TARGET_URL, DEFAULT_USERNAME, emit
from phases.phase1_static_analysis import run_phase1
from phases.phase2_prepare_baseline import run_phase2
from phases.phase3_capture import run_phase3
from phases.phase4_verify_handlers import run_phase4
from phases.phase5_assess import run_phase5
from phases.phase6_generate_report import run_phase6


def main() -> None:
    parser = argparse.ArgumentParser(description="按阶段顺序执行完整链路：静态分析→基线→动态捕获→验证→评估→报告")
    parser.add_argument("--url", default="", help="目标页面 URL；为空时按 --layer 自动推断")
    parser.add_argument("--layer", type=int, default=1, help="当前测试层编号（用于自动推断 generated_layerN_sample.php）")
    parser.add_argument("--username", default=DEFAULT_USERNAME, help="填入 DOM / 基线的用户名")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="填入 DOM / 基线的密码")
    parser.add_argument("--phase5-timeout", type=float, default=10.0, help="阶段5真实发包超时时间（秒）")
    parser.add_argument("--phase5-include-unverified", action="store_true", help="阶段5纳入未通过 phase4 的端点进行诊断评估")
    parser.add_argument("--phase5-enhanced-fuzz-mode", action="store_true", help="阶段5启用增强模糊模式（不增加场景数，仅提升变异强度）")
    parser.add_argument("--phase3-concurrency", type=int, default=4, help="阶段3并发捕获端点数量（默认 4）")
    parser.add_argument("--phase3-settle-ms", type=int, default=300, help="阶段3每端点额外等待毫秒数（默认 300）")
    parser.add_argument("--phase3-nav-timeout-ms", type=int, default=10000, help="阶段3页面导航超时毫秒（默认 10000）")
    parser.add_argument("--phase3-no-algo-batch", action="store_true", help="关闭阶段3按算法分批并发（默认开启）")
    parser.add_argument("--log-file", default=str(BASE_DIR / "runtime" / "full_pipeline_utf8.log"), help="统一 UTF-8 日志文件路径；默认写入 runtime/full_pipeline_utf8.log")
    args = parser.parse_args()

    inferred_url = f"http://encrypt-labs-main-1/generated_layer{args.layer}_sample.php"
    target_url = args.url.strip() or inferred_url or DEFAULT_TARGET_URL

    log_path = Path(args.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    phase1_4_start = time.time()
    with open(log_path, "w", encoding="utf-8", newline="\n") as log_handle:
        emit(f"[总控] UTF-8 日志文件: {log_path}", log_handle)
        emit(f"[总控] 目标页面 URL: {target_url}", log_handle)

        emit("[总控] 阶段1：静态分析", log_handle)
        run_phase1(target_url, log_handle)

        emit("[总控] 阶段2：生成基线并填充 Payload", log_handle)
        baseline_path = run_phase2(args.username, args.password, log_handle)

        emit("[总控] 阶段3：Playwright 动态捕获", log_handle)
        run_phase3(
            target_url,
            baseline=baseline_path,
            concurrency=args.phase3_concurrency,
            settle_ms=args.phase3_settle_ms,
            nav_timeout_ms=args.phase3_nav_timeout_ms,
            algo_batch=(not args.phase3_no_algo_batch),
            log_handle=log_handle,
        )

        emit("[总控] 阶段4：Handler 正确性验证", log_handle)
        run_phase4(baseline_path, False, log_handle)

        phase1_4_end = time.time()
        emit("[总控] 阶段5：安全评估", log_handle)
        run_phase5(
            baseline_path,
            ["default", "paper_v1"],
            log_handle,
            timeout=args.phase5_timeout,
            include_unverified=args.phase5_include_unverified,
            enhanced_fuzz_mode=args.phase5_enhanced_fuzz_mode,
        )

        emit("[总控] 阶段6：生成报告与图表", log_handle)
        run_phase6(baseline_path, "paper_v1", log_handle)

        phase5_6_end = time.time()
        emit(f"[总控] 全链路完成，最终基线: {baseline_path}", log_handle)

    print(f"[总控] 阶段1-4总执行时长: {phase1_4_end - phase1_4_start:.2f} 秒")
    print(f"[总控] 阶段5-6总执行时长: {phase5_6_end - phase1_4_end:.2f} 秒")


if __name__ == "__main__":
    main()
