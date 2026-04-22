#!/usr/bin/env python3
"""阶段 5：安全评估统一入口。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TextIO

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from assess.assess_endpoint import BaselineAssessmentEngine
from phases.common import BASE_DIR, resolve_baseline_path, emit


DEFAULT_PROFILES = ["default", "paper_v1"]


def run_phase5(
    baseline: str | Path | None = None,
    profiles: list[str] | None = None,
    log_handle: TextIO | None = None,
    timeout: float = 10.0,
    include_unverified: bool = False,
    enhanced_fuzz_mode: bool = False,
) -> dict[str, Path]:
    baseline_path = resolve_baseline_path(baseline, allow_tmp=False)
    weights = BASE_DIR / "configs" / "scoring_profiles.yaml"
    output_dir = BASE_DIR / "assessment_results"
    generated: dict[str, Path] = {}

    emit(
        f"[阶段5] 评估模式: 真实目标验证 / timeout={timeout}s / fuzz_mode={'enhanced' if enhanced_fuzz_mode else 'standard'}",
        log_handle,
    )

    for profile in profiles or DEFAULT_PROFILES:
        engine = BaselineAssessmentEngine(
            output_dir=output_dir,
            timeout=timeout,
            scoring_profile=profile,
            scoring_config_path=weights,
            enhanced_fuzz_mode=bool(enhanced_fuzz_mode),
        )
        report = engine.assess(baseline_path=baseline_path, include_unverified=include_unverified)
        output_path = engine.save_report(report, f"assessment_profile_{profile}.json")
        generated[profile] = output_path
        emit(f"[阶段5] {profile} 评估结果: {output_path}", log_handle)

    return generated


def main() -> None:
    parser = argparse.ArgumentParser(description="阶段5：执行安全评估并生成不同评分 profile 的 assessment 结果")
    parser.add_argument("--baseline", help="指定基线文件路径；默认自动选择最新正式基线")
    parser.add_argument("--profiles", nargs="+", default=DEFAULT_PROFILES, help="要生成的评分 profile 列表")
    parser.add_argument("--timeout", type=float, default=10.0, help="真实发包超时时间（秒）")
    parser.add_argument("--include-unverified", action="store_true", help="纳入未通过 phase4 的端点进行诊断评估")
    parser.add_argument("--enhanced-fuzz-mode", action="store_true", help="启用增强模糊模式（不增加场景数，仅提升场景变异强度）")
    args = parser.parse_args()
    run_phase5(
        args.baseline,
        args.profiles,
        timeout=args.timeout,
        include_unverified=args.include_unverified,
        enhanced_fuzz_mode=args.enhanced_fuzz_mode,
    )


if __name__ == "__main__":
    main()
