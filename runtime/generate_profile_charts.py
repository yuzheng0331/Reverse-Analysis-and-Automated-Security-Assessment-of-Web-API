from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from assess.common import latest_matching_file, load_json_file

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "Arial Unicode MS", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

COMPARISON_LABELS = {
    "MATCH": "严格匹配",
    "RSA_NONDETERMINISTIC_LOGIC_VALIDATED": "RSA/AESRSA逻辑验证",
    "NO_CRYPTO": "仅请求打包",
    "MISMATCH": "不匹配",
    "NONE": "未验证",
}

STATUS_ORDER = ["LOCAL_OK", "LOCAL_FAILED", "SKIPPED", "REMOTE_SENT"]
STATUS_COLORS = {
    "LOCAL_OK": "#2ca02c",
    "LOCAL_FAILED": "#d62728",
    "SKIPPED": "#ff7f0e",
    "REMOTE_SENT": "#1f77b4",
}


def _load_json(path: Path) -> Any:
    return load_json_file(path)


def _resolve_baseline_path(path: Path | None = None) -> Path:
    if path and path.exists():
        return path
    candidates = [
        item for item in (BASE_DIR / "baseline_samples").glob("baseline_skeletons_*.json")
        if ".tmp_" not in item.name and ".tmp" not in item.name
    ]
    if candidates:
        return max(candidates, key=lambda item: item.stat().st_mtime)
    fallback = list((BASE_DIR / "baseline_samples").glob("baseline_skeletons_*.json"))
    if not fallback:
        raise FileNotFoundError("未找到 baseline_skeletons_*.json")
    return max(fallback, key=lambda item: item.stat().st_mtime)


def _resolve_profile_assessment(profile: str) -> Path:
    fixed = BASE_DIR / "assessment_results" / f"assessment_profile_{profile}.json"
    if fixed.exists():
        return fixed

    candidates = sorted((BASE_DIR / "assessment_results").glob("assessment_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for candidate in candidates:
        try:
            data = _load_json(candidate)
        except Exception:
            continue
        if (data.get("source", {}) or {}).get("scoring_profile") == profile:
            return candidate
    raise FileNotFoundError(f"未找到 profile={profile} 对应的 assessment 文件")


def _resolve_assessment_path(path: Path | None = None) -> Path:
    if path and path.exists():
        return path
    try:
        return _resolve_profile_assessment("paper_v1")
    except FileNotFoundError:
        latest = latest_matching_file(BASE_DIR / "assessment_results", "assessment_*.json")
        if not latest:
            raise FileNotFoundError("未找到 assessment_*.json")
        return latest


def _ensure_output_dir(output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def _save_figure(fig: plt.Figure, path: Path) -> None:
    fig.tight_layout()
    fig.savefig(path, dpi=180, bbox_inches="tight")
    plt.close(fig)


def chart_workflow_overview(output_dir: Path) -> Path:
    fig, ax = plt.subplots(figsize=(14, 3.8))
    ax.axis("off")

    steps = [
        (0.08, "静态分析\nstatic_analysis_*.json"),
        (0.24, "基线骨架生成\nbaseline_skeletons_*.json"),
        (0.40, "Payload填充\nrequest.payload"),
        (0.56, "Playwright动态捕获\nruntime_params / captured"),
        (0.72, "Handler验证\nVERIFIED"),
        (0.88, "多场景安全评估\nassessment + report"),
    ]

    for x, label in steps:
        ax.text(
            x,
            0.5,
            label,
            ha="center",
            va="center",
            fontsize=12,
            bbox=dict(boxstyle="round,pad=0.5", facecolor="#eaf2ff", edgecolor="#4f81bd", linewidth=1.5),
            transform=ax.transAxes,
        )

    for idx in range(len(steps) - 1):
        x1 = steps[idx][0] + 0.075
        x2 = steps[idx + 1][0] - 0.075
        ax.annotate("", xy=(x2, 0.5), xytext=(x1, 0.5), xycoords="axes fraction", textcoords="axes fraction", arrowprops=dict(arrowstyle="->", lw=2, color="#666"))

    ax.set_title("工作流总览图", fontsize=16, pad=16)
    path = output_dir / "workflow_overview.png"
    _save_figure(fig, path)
    return path


def chart_validation_distribution(baseline_path: Path, output_dir: Path) -> Path:
    baseline = _load_json(baseline_path)
    counts: dict[str, int] = {}
    for entry in baseline:
        key = ((entry.get("validation", {}) or {}).get("comparison_result") or "NONE")
        counts[key] = counts.get(key, 0) + 1

    labels = [COMPARISON_LABELS.get(k, k) for k in counts.keys()]
    values = list(counts.values())
    colors = ["#4caf50", "#2196f3", "#9c27b0", "#f44336", "#9e9e9e"][: len(values)]

    fig, ax = plt.subplots(figsize=(8, 5))
    wedges, texts, autotexts = ax.pie(values, labels=labels, autopct="%1.0f%%", startangle=90, colors=colors, textprops={"fontsize": 11})
    for autotext in autotexts:
        autotext.set_color("white")
        autotext.set_fontsize(10)
    ax.set_title("验证口径分布图", fontsize=15)
    path = output_dir / "validation_comparison_distribution.png"
    _save_figure(fig, path)
    return path


def chart_endpoint_scores(assessment_path: Path, output_dir: Path) -> Path:
    assessment = _load_json(assessment_path)
    rows = assessment.get("assessments", []) or []
    rows = sorted(rows, key=lambda item: item.get("security_score", 0))
    labels = [item.get("endpoint_id", "unknown") for item in rows]
    values = [float(item.get("security_score", 0)) for item in rows]

    fig, ax = plt.subplots(figsize=(10, 5.5))
    bars = ax.barh(labels, values, color="#5b8ff9")
    ax.set_xlabel("安全评分")
    ax.set_ylabel("端点")
    ax.set_title("各端点安全评分柱状图", fontsize=15)
    ax.set_xlim(0, 100)
    for bar, value in zip(bars, values):
        ax.text(value + 1, bar.get_y() + bar.get_height() / 2, f"{value:.2f}", va="center", fontsize=9)
    path = output_dir / "endpoint_security_scores.png"
    _save_figure(fig, path)
    return path


def chart_profile_comparison(default_assessment_path: Path, paper_assessment_path: Path, output_dir: Path) -> Path:
    default_data = _load_json(default_assessment_path)
    paper_data = _load_json(paper_assessment_path)

    default_scores = {item.get("endpoint_id"): float(item.get("security_score", 0)) for item in (default_data.get("assessments", []) or [])}
    paper_scores = {item.get("endpoint_id"): float(item.get("security_score", 0)) for item in (paper_data.get("assessments", []) or [])}
    endpoints = sorted(set(default_scores.keys()) | set(paper_scores.keys()))

    x = list(range(len(endpoints)))
    width = 0.38

    fig, ax = plt.subplots(figsize=(12, 5.5))
    ax.bar([i - width / 2 for i in x], [default_scores.get(ep, 0) for ep in endpoints], width=width, label="default", color="#91cc75")
    ax.bar([i + width / 2 for i in x], [paper_scores.get(ep, 0) for ep in endpoints], width=width, label="paper_v1", color="#5470c6")
    ax.set_xticks(x)
    ax.set_xticklabels(endpoints, rotation=20)
    ax.set_ylim(0, 100)
    ax.set_ylabel("安全评分")
    ax.set_title("不同 profile 评分对比图", fontsize=15)
    ax.legend()
    path = output_dir / "profile_score_comparison.png"
    _save_figure(fig, path)
    return path


def chart_scenario_status_distribution(assessment_path: Path, output_dir: Path) -> Path:
    assessment = _load_json(assessment_path)
    rows = assessment.get("assessments", []) or []
    endpoint_labels = [item.get("endpoint_id", "unknown") for item in rows]
    counts_by_status = {status: [] for status in STATUS_ORDER}

    for item in rows:
        scenarios = item.get("scenario_results", []) or []
        local_counts = {status: 0 for status in STATUS_ORDER}
        for scenario in scenarios:
            status = str(scenario.get("status", "LOCAL_OK"))
            if status not in local_counts:
                local_counts[status] = 0
                if status not in counts_by_status:
                    counts_by_status[status] = []
            local_counts[status] += 1
        for status in counts_by_status.keys():
            counts_by_status[status].append(local_counts.get(status, 0))

    fig, ax = plt.subplots(figsize=(12, 6))
    left = [0] * len(endpoint_labels)
    ordered_statuses = [status for status in STATUS_ORDER if status in counts_by_status] + [status for status in counts_by_status if status not in STATUS_ORDER]
    for status in ordered_statuses:
        values = counts_by_status[status]
        ax.barh(endpoint_labels, values, left=left, label=status, color=STATUS_COLORS.get(status, None))
        left = [l + v for l, v in zip(left, values)]

    ax.set_xlabel("场景数量")
    ax.set_ylabel("端点")
    ax.set_title("场景执行状态分布图", fontsize=15)
    ax.legend(loc="lower right")
    path = output_dir / "scenario_status_distribution.png"
    _save_figure(fig, path)
    return path


def generate_all_charts(
    baseline_path: Path | None = None,
    assessment_path: Path | None = None,
    default_assessment_path: Path | None = None,
    paper_assessment_path: Path | None = None,
    output_dir: Path | None = None,
) -> list[Path]:
    baseline_path = _resolve_baseline_path(baseline_path)
    assessment_path = _resolve_assessment_path(assessment_path)
    default_assessment_path = default_assessment_path if default_assessment_path and default_assessment_path.exists() else _resolve_profile_assessment("default")
    paper_assessment_path = paper_assessment_path if paper_assessment_path and paper_assessment_path.exists() else _resolve_profile_assessment("paper_v1")
    output_dir = _ensure_output_dir(output_dir or (BASE_DIR / "report" / "charts"))

    generated = [
        chart_workflow_overview(output_dir),
        chart_validation_distribution(baseline_path, output_dir),
        chart_endpoint_scores(assessment_path, output_dir),
        chart_profile_comparison(default_assessment_path, paper_assessment_path, output_dir),
        chart_scenario_status_distribution(assessment_path, output_dir),
    ]
    return generated


def main() -> None:
    generated = generate_all_charts()
    for path in generated:
        print(path)


if __name__ == "__main__":
    main()

