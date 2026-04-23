from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import BoundaryNorm, ListedColormap

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

GATE_COLOR_MAP = {
    "NO_SCENARIO": "#e0e0e0",
    "SENDABLE": "#81c784",
    "UNMUTATABLE": "#bdbdbd",
    "MUTATION_NOT_EFFECTIVE": "#ffcc80",
    "SKIPPED_OTHER": "#ef9a9a",
    "RUNTIME_DEP_MISSING": "#b39ddb",
    "LOCAL_EXECUTION_ERROR": "#ef9a9a",
    "OTHER": "#90caf9",
}

REMOTE_STATUS_COLORS = {
    "未发起": "#9e9e9e",
    "已发送": "#1f77b4",
    "已响应": "#2ca02c",
    "错误": "#d62728",
}


def _classify_response_mode(remote_result: dict[str, Any]) -> str:
    if not isinstance(remote_result, dict):
        return "NOT_ATTEMPTED"
    if not remote_result.get("attempted"):
        return "NOT_ATTEMPTED"
    if remote_result.get("error"):
        return "TRANSPORT_ERROR"
    body = str(remote_result.get("body_preview") or "")
    body_lc = body.lower()
    status_code = remote_result.get("status_code")
    if isinstance(status_code, int) and status_code >= 500:
        return "SERVER_5XX"
    if "\"success\":true" in body_lc:
        return "APP_SUCCESS"
    if "invalid input" in body_lc or "invalid username" in body_lc:
        return "APP_INVALID_INPUT"
    if "missing" in body_lc or "no data" in body_lc:
        return "APP_MISSING_DATA"
    if "decrypt" in body_lc or "解密失败" in body:
        return "APP_DECRYPT_FAIL"
    if isinstance(status_code, int) and status_code >= 400:
        return "HTTP_4XX"
    if isinstance(status_code, int) and status_code >= 200:
        return "HTTP_OK_OTHER"
    return "UNKNOWN"


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


def _save_placeholder_chart(output_path: Path, title: str, message: str) -> Path:
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.axis("off")
    ax.text(0.5, 0.6, title, ha="center", va="center", fontsize=16, fontweight="bold")
    ax.text(0.5, 0.4, message, ha="center", va="center", fontsize=12, wrap=True)
    _save_figure(fig, output_path)
    return output_path


def _build_remote_summary(assessment: dict[str, Any]) -> dict[str, Any]:
    remote = assessment.get("remote_execution", {}) or {}
    if remote:
        return remote
    summary: dict[str, Any] = {
        "total_scenarios": 0,
        "attempted": 0,
        "responded": 0,
        "errors": 0,
        "not_attempted": 0,
        "status_code_counts": {},
        "error_counts": {},
        "avg_elapsed_ms": None,
        "p95_elapsed_ms": None,
    }
    elapsed_values: list[float] = []
    for endpoint in assessment.get("assessments", []) or []:
        for scenario in endpoint.get("scenario_results", []) or []:
            summary["total_scenarios"] += 1
            remote_result = scenario.get("remote_result", {}) or {}
            if not remote_result.get("attempted"):
                summary["not_attempted"] += 1
                continue
            summary["attempted"] += 1
            status_code = remote_result.get("status_code")
            if status_code is not None:
                key = str(status_code)
                summary["responded"] += 1
                summary["status_code_counts"][key] = summary["status_code_counts"].get(key, 0) + 1
            error = remote_result.get("error")
            if error:
                summary["errors"] += 1
                summary["error_counts"][error] = summary["error_counts"].get(error, 0) + 1
            elapsed_ms = remote_result.get("elapsed_ms")
            if isinstance(elapsed_ms, (int, float)):
                elapsed_values.append(float(elapsed_ms))
    if elapsed_values:
        ordered = sorted(elapsed_values)
        p95_index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * 0.95)))
        summary["avg_elapsed_ms"] = round(sum(ordered) / len(ordered), 2)
        summary["p95_elapsed_ms"] = round(ordered[p95_index], 2)
    return summary


def _build_endpoint_remote_rows(assessment: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for endpoint in assessment.get("assessments", []) or []:
        remote = endpoint.get("remote_execution", {}) or {}
        if not remote:
            scenarios = endpoint.get("scenario_results", []) or []
            remote = {
                "total_scenarios": len(scenarios),
                "attempted": 0,
                "responded": 0,
                "errors": 0,
                "not_attempted": len(scenarios),
                "status_code_counts": {},
            }
            for scenario in scenarios:
                remote_result = scenario.get("remote_result", {}) or {}
                if not remote_result.get("attempted"):
                    continue
                remote["attempted"] += 1
                remote["not_attempted"] = max(0, remote["not_attempted"] - 1)
                status_code = remote_result.get("status_code")
                if status_code is not None:
                    remote["responded"] += 1
                    key = str(status_code)
                    remote["status_code_counts"][key] = remote["status_code_counts"].get(key, 0) + 1
                if remote_result.get("error"):
                    remote["errors"] += 1
        rows.append({
            "endpoint_id": endpoint.get("endpoint_id", "unknown"),
            "attempted": int(remote.get("attempted", 0)),
            "responded": int(remote.get("responded", 0)),
            "errors": int(remote.get("errors", 0)),
            "not_attempted": int(remote.get("not_attempted", 0)),
        })
    return rows


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


def chart_endpoint_scenario_expectation_hit_matrix(assessment_path: Path, output_dir: Path) -> Path:
    assessment = _load_json(assessment_path)
    path = output_dir / "endpoint_scenario_expectation_hit_matrix.png"

    endpoints = assessment.get("assessments", []) or []
    if not endpoints:
        return _save_placeholder_chart(path, "端点-场景预期命中矩阵图", "当前 assessment 中没有端点数据。")

    scenario_ids: list[str] = []
    scenario_set: set[str] = set()
    for endpoint in endpoints:
        for scenario in endpoint.get("scenario_results", []) or []:
            scenario_id = str(scenario.get("scenario_id") or "unknown")
            if scenario_id not in scenario_set:
                scenario_set.add(scenario_id)
                scenario_ids.append(scenario_id)

    if not scenario_ids:
        return _save_placeholder_chart(path, "端点-场景预期命中矩阵图", "没有可用场景数据。")

    endpoint_labels: list[str] = []
    matrix: list[list[int]] = []
    for endpoint in endpoints:
        endpoint_labels.append(str(endpoint.get("endpoint_id") or "unknown"))
        index_map: dict[str, int] = {}
        for scenario in endpoint.get("scenario_results", []) or []:
            scenario_id = str(scenario.get("scenario_id") or "unknown")
            expectation = scenario.get("expectation", {}) or {}
            if not expectation.get("defined"):
                index_map[scenario_id] = -1
            else:
                index_map[scenario_id] = 1 if expectation.get("matched") else 0
        row = [index_map.get(scenario_id, -2) for scenario_id in scenario_ids]
        matrix.append(row)

    cmap = ListedColormap(["#e0e0e0", "#bdbdbd", "#e57373", "#81c784"])
    # -2:无该场景, -1:未定义预期, 0:未命中, 1:命中
    norm = BoundaryNorm([-2.5, -1.5, -0.5, 0.5, 1.5], cmap.N)

    fig_width = max(10.0, len(scenario_ids) * 0.75)
    fig_height = max(4.8, len(endpoint_labels) * 0.7)
    fig, ax = plt.subplots(figsize=(fig_width, fig_height))
    im = ax.imshow(matrix, cmap=cmap, norm=norm, aspect="auto")

    ax.set_xticks(range(len(scenario_ids)))
    ax.set_xticklabels(scenario_ids, rotation=35, ha="right")
    ax.set_yticks(range(len(endpoint_labels)))
    ax.set_yticklabels(endpoint_labels)
    ax.set_xlabel("场景 ID")
    ax.set_ylabel("端点")
    ax.set_title("端点-场景预期命中矩阵图", fontsize=15)

    for row_idx, row in enumerate(matrix):
        for col_idx, value in enumerate(row):
            marker = "NA" if value == -2 else ("U" if value == -1 else ("OK" if value == 1 else "X"))
            ax.text(col_idx, row_idx, marker, ha="center", va="center", fontsize=8, color="#222")

    colorbar = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    colorbar.set_ticks([-2, -1, 0, 1])
    colorbar.set_ticklabels(["无该场景", "未定义预期", "未命中", "命中"])

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


def chart_endpoint_scenario_state_machine_matrix(assessment_path: Path, output_dir: Path) -> Path:
    assessment = _load_json(assessment_path)
    path = output_dir / "endpoint_scenario_state_machine_matrix.png"

    endpoints = assessment.get("assessments", []) or []
    if not endpoints:
        return _save_placeholder_chart(path, "端点-场景状态机矩阵图", "当前 assessment 中没有端点数据。")

    scenario_ids: list[str] = []
    scenario_set: set[str] = set()
    for endpoint in endpoints:
        for scenario in endpoint.get("scenario_results", []) or []:
            scenario_id = str(scenario.get("scenario_id") or "unknown")
            if scenario_id not in scenario_set:
                scenario_set.add(scenario_id)
                scenario_ids.append(scenario_id)

    gate_order = [
        "NO_SCENARIO",
        "SENDABLE",
        "UNMUTATABLE",
        "MUTATION_NOT_EFFECTIVE",
        "SKIPPED_OTHER",
        "RUNTIME_DEP_MISSING",
        "LOCAL_EXECUTION_ERROR",
        "OTHER",
    ]
    gate_to_idx = {name: idx for idx, name in enumerate(gate_order)}

    endpoint_labels: list[str] = []
    matrix: list[list[int]] = []
    for endpoint in endpoints:
        endpoint_id = str(endpoint.get("endpoint_id") or "unknown")
        endpoint_labels.append(endpoint_id)

        scenario_gate_map: dict[str, str] = {}
        for scenario in endpoint.get("scenario_results", []) or []:
            scenario_id = str(scenario.get("scenario_id") or "unknown")
            gate_code = str(((scenario.get("local_gate", {}) or {}).get("code") or "OTHER"))
            if gate_code not in gate_to_idx:
                gate_code = "OTHER"
            scenario_gate_map[scenario_id] = gate_code

        row = [gate_to_idx[scenario_gate_map.get(sid, "NO_SCENARIO")] for sid in scenario_ids]
        matrix.append(row)

    cmap = ListedColormap([GATE_COLOR_MAP.get(gate, GATE_COLOR_MAP["OTHER"]) for gate in gate_order])
    norm = BoundaryNorm([i - 0.5 for i in range(len(gate_order) + 1)], cmap.N)

    fig_width = max(10.0, len(scenario_ids) * 0.75)
    fig_height = max(4.8, len(endpoint_labels) * 0.65)
    fig, ax = plt.subplots(figsize=(fig_width, fig_height))
    im = ax.imshow(matrix, cmap=cmap, norm=norm, aspect="auto")

    ax.set_xticks(range(len(scenario_ids)))
    ax.set_xticklabels(scenario_ids, rotation=35, ha="right")
    ax.set_yticks(range(len(endpoint_labels)))
    ax.set_yticklabels(endpoint_labels)
    ax.set_xlabel("场景 ID")
    ax.set_ylabel("端点")
    ax.set_title("端点-场景状态机矩阵图", fontsize=15)

    marker_map = {
        "NO_SCENARIO": "NA",
        "SENDABLE": "S",
        "UNMUTATABLE": "U",
        "MUTATION_NOT_EFFECTIVE": "M",
        "SKIPPED_OTHER": "K",
        "RUNTIME_DEP_MISSING": "R",
        "LOCAL_EXECUTION_ERROR": "E",
        "OTHER": "O",
    }
    idx_to_gate = {idx: gate for gate, idx in gate_to_idx.items()}

    for i, row in enumerate(matrix):
        for j, value_idx in enumerate(row):
            gate_name = idx_to_gate.get(value_idx, "OTHER")
            marker = marker_map.get(gate_name, "O")
            ax.text(j, i, marker, ha="center", va="center", fontsize=8, color="#222")

    colorbar = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    colorbar.set_ticks(list(range(len(gate_order))))
    colorbar.set_ticklabels(gate_order)
    _save_figure(fig, path)
    return path


def chart_remote_execution_overview(assessment_path: Path, output_dir: Path) -> Path:
    assessment = _load_json(assessment_path)
    remote = _build_remote_summary(assessment)
    path = output_dir / "remote_execution_overview.png"
    total = int(remote.get("total_scenarios", 0))
    if total <= 0:
        return _save_placeholder_chart(path, "在线验证执行总览图", "阶段5固定在线验证；当前 assessment 中没有可用场景数据。")

    categories = ["未发起", "已发送", "已响应", "错误"]
    values = [
        int(remote.get("not_attempted", 0)),
        int(remote.get("attempted", 0)),
        int(remote.get("responded", 0)),
        int(remote.get("errors", 0)),
    ]
    fig, ax = plt.subplots(figsize=(8.5, 5))
    bars = ax.bar(categories, values, color=[REMOTE_STATUS_COLORS[item] for item in categories])
    ax.set_ylabel("场景数量")
    ax.set_title("在线验证执行总览图", fontsize=15)
    ax.text(0.5, -0.18, "阶段5固定在线验证；\"未发起\"通常由门控跳过或请求不可落地导致。", transform=ax.transAxes, ha="center", va="top", fontsize=9, color="#555")
    for bar, value in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, value + 0.2, str(value), ha="center", va="bottom", fontsize=10)
    _save_figure(fig, path)
    return path


def chart_remote_status_code_distribution(assessment_path: Path, output_dir: Path) -> Path:
    assessment = _load_json(assessment_path)
    remote = _build_remote_summary(assessment)
    counts = remote.get("status_code_counts", {}) or {}
    path = output_dir / "remote_http_status_distribution.png"
    if not counts:
        mode_label = "阶段5按在线验证口径执行，但当前 assessment 尚未收到任何 HTTP 响应。"
        return _save_placeholder_chart(path, "远程HTTP状态码分布图", mode_label)

    labels = list(counts.keys())
    values = [counts[key] for key in labels]
    fig, ax = plt.subplots(figsize=(8.5, 5))
    bars = ax.bar(labels, values, color="#5470c6")
    ax.set_xlabel("HTTP 状态码")
    ax.set_ylabel("出现次数")
    ax.set_title("远程HTTP状态码分布图", fontsize=15)
    for bar, value in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, value + 0.2, str(value), ha="center", va="bottom", fontsize=10)
    _save_figure(fig, path)
    return path


def chart_endpoint_remote_coverage(assessment_path: Path, output_dir: Path) -> Path:
    assessment = _load_json(assessment_path)
    rows = _build_endpoint_remote_rows(assessment)
    path = output_dir / "endpoint_remote_coverage.png"
    if not rows:
        return _save_placeholder_chart(path, "端点在线验证覆盖图", "当前 assessment 中没有端点数据。")

    endpoint_labels = [row["endpoint_id"] for row in rows]
    not_attempted = [row["not_attempted"] for row in rows]
    responded = [row["responded"] for row in rows]
    errors = [row["errors"] for row in rows]
    in_flight_only = [max(0, row["attempted"] - row["responded"] - row["errors"]) for row in rows]

    fig, ax = plt.subplots(figsize=(12, 6))
    left = [0] * len(endpoint_labels)
    for label, values, color in [
        ("未发起", not_attempted, REMOTE_STATUS_COLORS["未发起"]),
        ("已响应", responded, REMOTE_STATUS_COLORS["已响应"]),
        ("错误", errors, REMOTE_STATUS_COLORS["错误"]),
        ("已发送未响应", in_flight_only, REMOTE_STATUS_COLORS["已发送"]),
    ]:
        ax.barh(endpoint_labels, values, left=left, label=label, color=color)
        left = [current + value for current, value in zip(left, values)]
    ax.set_xlabel("场景数量")
    ax.set_ylabel("端点")
    ax.set_title("端点在线验证覆盖图", fontsize=15)
    ax.legend(loc="lower right")
    _save_figure(fig, path)
    return path


def chart_scenario_response_mode_heatmap(assessment_path: Path, output_dir: Path) -> Path:
    assessment = _load_json(assessment_path)
    path = output_dir / "scenario_response_mode_heatmap.png"

    matrix_counts: dict[str, dict[str, int]] = {}
    categories_order: list[str] = []
    modes_order: list[str] = []

    for endpoint in assessment.get("assessments", []) or []:
        for scenario in endpoint.get("scenario_results", []) or []:
            category = str(scenario.get("category") or "unknown")
            remote = scenario.get("remote_result", {}) or {}
            mode = str(remote.get("response_mode") or _classify_response_mode(remote))
            if category not in matrix_counts:
                matrix_counts[category] = {}
                categories_order.append(category)
            matrix_counts[category][mode] = matrix_counts[category].get(mode, 0) + 1
            if mode not in modes_order:
                modes_order.append(mode)

    if not matrix_counts:
        return _save_placeholder_chart(path, "场景类别->响应模式热力图", "当前 assessment 中没有可用场景数据。")

    data = []
    for category in categories_order:
        row = [matrix_counts[category].get(mode, 0) for mode in modes_order]
        data.append(row)

    fig, ax = plt.subplots(figsize=(max(9.0, len(modes_order) * 1.2), max(4.5, len(categories_order) * 0.7)))
    im = ax.imshow(data, cmap="YlOrRd", aspect="auto")
    ax.set_xticks(range(len(modes_order)))
    ax.set_xticklabels(modes_order, rotation=25, ha="right")
    ax.set_yticks(range(len(categories_order)))
    ax.set_yticklabels(categories_order)
    ax.set_title("场景类别 -> 服务端响应模式热力图", fontsize=15)
    ax.set_xlabel("响应模式")
    ax.set_ylabel("场景类别")

    for i, row in enumerate(data):
        for j, val in enumerate(row):
            if val > 0:
                ax.text(j, i, str(val), ha="center", va="center", fontsize=9, color="#222")

    fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02, label="计数")
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

    for obsolete_name in [
        "scenario_status_distribution.png",
        "remote_http_status_distribution.png",
        "endpoint_state_machine_matrix.png",
    ]:
        obsolete_path = output_dir / obsolete_name
        if obsolete_path.exists():
            obsolete_path.unlink()

    generated = [
        chart_validation_distribution(baseline_path, output_dir),
        chart_endpoint_scores(assessment_path, output_dir),
        chart_profile_comparison(default_assessment_path, paper_assessment_path, output_dir),
        chart_endpoint_scenario_state_machine_matrix(assessment_path, output_dir),
        chart_endpoint_scenario_expectation_hit_matrix(assessment_path, output_dir),
        chart_remote_execution_overview(assessment_path, output_dir),
        chart_scenario_response_mode_heatmap(assessment_path, output_dir),
    ]
    return generated


def main() -> None:
    generated = generate_all_charts()
    for path in generated:
        print(path)


if __name__ == "__main__":
    main()

