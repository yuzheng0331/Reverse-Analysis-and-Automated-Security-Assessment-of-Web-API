#!/usr/bin/env python3
"""阶段 6：报告与图表生成统一入口。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TextIO

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from assess.report_gen import ReportGenerator
from phases.common import BASE_DIR, resolve_baseline_path, emit
from runtime.generate_profile_charts import generate_all_charts


def run_phase6(baseline: str | Path | None = None, profile: str = "paper_v1", log_handle: TextIO | None = None) -> dict[str, object]:
    baseline_path = resolve_baseline_path(baseline, allow_tmp=False)
    assessment_dir = BASE_DIR / "assessment_results"
    report_dir = BASE_DIR / "report"
    assessment_path = assessment_dir / f"assessment_profile_{profile}.json"
    if not assessment_path.exists():
        raise FileNotFoundError(f"未找到评估结果: {assessment_path}，请先运行阶段5")

    generator = ReportGenerator(output_dir=report_dir)
    if not generator.load_assessment(assessment_path):
        raise FileNotFoundError(f"无法加载 assessment 文件: {assessment_path}")
    generator.load_baseline(baseline_path)
    generator.load_static_analysis()
    generator.build_report_view()

    html_path = generator.generate_html(f"report_profile_{profile}.html")
    md_path = generator.generate_markdown(f"report_profile_{profile}.md")
    json_path = generator.generate_json(f"report_profile_{profile}.json")

    chart_paths = generate_all_charts(
        baseline_path=baseline_path,
        assessment_path=assessment_path,
        default_assessment_path=assessment_dir / "assessment_profile_default.json",
        paper_assessment_path=assessment_dir / "assessment_profile_paper_v1.json",
        output_dir=report_dir / "charts",
    )

    emit(f"[阶段6] HTML 报告: {html_path}", log_handle)
    emit(f"[阶段6] Markdown 报告: {md_path}", log_handle)
    emit(f"[阶段6] JSON 报告: {json_path}", log_handle)
    for chart_path in chart_paths:
        emit(f"[阶段6] 图表: {chart_path}", log_handle)

    return {
        "assessment": assessment_path,
        "html": html_path,
        "markdown": md_path,
        "json": json_path,
        "charts": chart_paths,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="阶段6：生成论文口径报告与图表")
    parser.add_argument("--baseline", help="指定基线文件路径；默认自动选择最新正式基线")
    parser.add_argument("--profile", default="paper_v1", help="用于报告生成的主评分 profile")
    args = parser.parse_args()
    run_phase6(args.baseline, args.profile)


if __name__ == "__main__":
    main()

