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
from common import BASE_DIR, resolve_baseline_path, emit


DEFAULT_PROFILES = ["default", "paper_v1"]


def run_phase5(baseline: str | Path | None = None, profiles: list[str] | None = None, log_handle: TextIO | None = None) -> dict[str, Path]:
    baseline_path = resolve_baseline_path(baseline, allow_tmp=False)
    weights = BASE_DIR / "configs" / "scoring_profiles.yaml"
    output_dir = BASE_DIR / "assessment_results"
    generated: dict[str, Path] = {}

    for profile in profiles or DEFAULT_PROFILES:
        engine = BaselineAssessmentEngine(output_dir=output_dir, scoring_profile=profile, scoring_config_path=weights)
        report = engine.assess(baseline_path=baseline_path)
        output_path = engine.save_report(report, f"assessment_profile_{profile}.json")
        generated[profile] = output_path
        emit(f"[阶段5] {profile} 评估结果: {output_path}", log_handle)

    return generated


def main() -> None:
    parser = argparse.ArgumentParser(description="阶段5：执行安全评估并生成不同评分 profile 的 assessment 结果")
    parser.add_argument("--baseline", help="指定基线文件路径；默认自动选择最新正式基线")
    parser.add_argument("--profiles", nargs="+", default=DEFAULT_PROFILES, help="要生成的评分 profile 列表")
    args = parser.parse_args()
    run_phase5(args.baseline, args.profiles)


if __name__ == "__main__":
    main()

