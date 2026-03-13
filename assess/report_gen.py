#!/usr/bin/env python3
"""
Phase 6: Report Generator
=========================
基于当前工作流生成最终报告。

输入优先级：
1. assessment_results/assessment_*.json（必需）
2. baseline_samples/baseline_skeletons_*.json（可选，默认从 assessment.source 中回溯）
3. collect/static_analysis/static_analysis_*.json（可选，默认从 assessment.source 中回溯）
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from rich.console import Console

from assess.common import latest_matching_file, load_json_file

console = Console()

DEFAULT_ASSESSMENT_DIR = BASE_DIR / "assessment_results"
DEFAULT_OUTPUT_DIR = BASE_DIR / "report"
DEFAULT_BASELINE_DIR = BASE_DIR / "baseline_samples"
DEFAULT_STATIC_ANALYSIS_DIR = BASE_DIR / "collect" / "static_analysis"

COMPARISON_LABELS = {
    "MATCH": "严格匹配",
    "NO_CRYPTO": "无前端加密，仅完成请求打包",
    "RSA_NONDETERMINISTIC_LOGIC_VALIDATED": "RSA/AESRSA 非确定性密文，逻辑验证通过",
    "MISMATCH": "不匹配",
    "NONE": "未验证",
}

NON_CRYPTO_FLOW_STEPS = {"PAYLOADPACKING"}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang=\"zh-CN\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>API 安全评估报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; max-width: 1280px; margin: 0 auto; padding: 24px; background: #f6f8fa; color: #24292f; }}
        .header {{ background: linear-gradient(135deg, #1f6feb, #8250df); color: white; padding: 24px; border-radius: 12px; margin-bottom: 20px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }}
        .card {{ background: white; padding: 16px; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
        .section {{ background: white; padding: 18px; border-radius: 10px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border-bottom: 1px solid #d0d7de; padding: 10px; text-align: left; vertical-align: top; }}
        th {{ background: #f6f8fa; }}
        code {{ background: #f6f8fa; padding: 2px 6px; border-radius: 6px; }}
        ul {{ margin-top: 8px; }}
    </style>
</head>
<body>
    <div class=\"header\">
        <h1>Web API 前端加密逆向与安全评估报告</h1>
        <p>报告 ID: {report_id}</p>
        <p>生成时间: {generated_at}</p>
    </div>

    <div class=\"grid\">
        <div class=\"card\"><h3>总体评分</h3><div>{overall_score:.2f} / 100</div></div>
        <div class="card"><h3>协议层评分</h3><div>{protocol_score:.2f} / 100</div></div>
        <div class="card"><h3>业务层评分</h3><div>{business_score:.2f} / 100</div></div>
        <div class=\"card\"><h3>评估端点数</h3><div>{assessed_endpoints}</div></div>
        <div class=\"card\"><h3>发现总数</h3><div>{findings_total}</div></div>
        <div class=\"card\"><h3>验证通过基线</h3><div>{verified_entries}</div></div>
    </div>

    <div class=\"section\"><h2>执行摘要</h2><p>{executive_summary}</p></div>
    <div class=\"section\"><h2>工作流摘要</h2>{workflow_summary}</div>
    <div class=\"section\"><h2>在线验证摘要</h2>{remote_summary}</div>
    <div class=\"section\"><h2>评分配置</h2>{scoring_summary}</div>
    <div class=\"section\"><h2>基线验证摘要</h2>{baseline_summary}</div>
    <div class=\"section\"><h2>静态分析上下文</h2>{static_summary}</div>
    <div class=\"section\"><h2>端点结果</h2>{endpoint_table}</div>
    <div class=\"section\"><h2>基线缺口与回溯建议</h2>{gap_section}</div>
    <div class=\"section\"><h2>局限性与后续建议</h2>{limitations_section}</div>
</body>
</html>"""

MARKDOWN_TEMPLATE = """# Web API 前端加密逆向与安全评估报告

- **报告 ID**: {report_id}
- **生成时间**: {generated_at}

## 执行摘要

{executive_summary}

## 工作流摘要

{workflow_summary}

## 在线验证摘要

{remote_summary}

## 评分配置

{scoring_summary}

## 基线验证摘要

{baseline_summary}

## 静态分析上下文

{static_summary}

## 评估统计

| 指标 | 数值 |
|---|---:|
| 总体评分 | {overall_score:.2f} |
| 协议层评分 | {protocol_score:.2f} |
| 业务层评分 | {business_score:.2f} |
| 评估端点数 | {assessed_endpoints} |
| 发现总数 | {findings_total} |
| 验证通过 | {verified_entries} |

## 端点结果

{endpoint_table}

## 基线缺口与回溯建议

{gap_section}

## 局限性与后续建议

{limitations_section}
"""


def extract_skip_reason(scenario: dict[str, Any]) -> Optional[str]:
    structured = scenario.get("skip_reason")
    if structured:
        return str(structured)
    if str(scenario.get("status")) != "SKIPPED":
        return None
    for item in scenario.get("observations", []) or []:
        if item:
            return str(item)
    remote_error = (scenario.get("remote_result", {}) or {}).get("error")
    return str(remote_error) if remote_error else None


class ReportGenerator:
    def __init__(self, output_dir: Path = DEFAULT_OUTPUT_DIR):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.assessment_data: Optional[dict[str, Any]] = None
        self.baseline_data: Optional[list[dict[str, Any]]] = None
        self.static_analysis_data: Optional[dict[str, Any]] = None
        self.report_view: Optional[dict[str, Any]] = None

    def load_assessment(self, assessment_path: Path) -> bool:
        if not assessment_path.exists():
            console.print(f"[red]评估结果不存在:[/red] {assessment_path}")
            return False
        self.assessment_data = load_json_file(assessment_path)
        return True

    def load_baseline(self, baseline_path: Optional[Path] = None) -> bool:
        resolved = baseline_path or self._infer_baseline_path()
        if not resolved or not resolved.exists():
            return False
        data = load_json_file(resolved)
        if isinstance(data, list):
            self.baseline_data = data
            return True
        return False

    def load_static_analysis(self, static_path: Optional[Path] = None) -> bool:
        resolved = static_path or self._infer_static_analysis_path()
        if not resolved or not resolved.exists():
            return False
        self.static_analysis_data = load_json_file(resolved)
        return True

    def _infer_baseline_path(self) -> Optional[Path]:
        baseline_file = ((self.assessment_data or {}).get("source", {}) or {}).get("baseline_file")
        if baseline_file:
            candidate = Path(baseline_file)
            if candidate.exists():
                return candidate
        return latest_matching_file(DEFAULT_BASELINE_DIR, "baseline_skeletons_*.json")

    def _infer_static_analysis_path(self) -> Optional[Path]:
        static_file = ((self.assessment_data or {}).get("source", {}) or {}).get("static_analysis_file")
        if static_file:
            candidate = Path(static_file)
            if candidate.exists():
                return candidate
        return latest_matching_file(DEFAULT_STATIC_ANALYSIS_DIR, "static_analysis_*.json")

    def _build_baseline_summary(self) -> dict[str, Any]:
        summary: dict[str, Any] = {"total": 0, "verified": 0, "status_counts": {}, "comparison_counts": {}}
        if not self.baseline_data:
            return summary
        summary["total"] = len(self.baseline_data)
        for entry in self.baseline_data:
            if entry.get("validation", {}).get("verified"):
                summary["verified"] += 1
            status = entry.get("status", "UNKNOWN")
            summary["status_counts"][status] = summary["status_counts"].get(status, 0) + 1
            comparison = entry.get("validation", {}).get("comparison_result", "NONE")
            label = COMPARISON_LABELS.get(comparison, comparison)
            summary["comparison_counts"][label] = summary["comparison_counts"].get(label, 0) + 1
        return summary

    def _build_static_summary(self) -> dict[str, Any]:
        if not self.static_analysis_data:
            return {}
        return {
            "target_url": self.static_analysis_data.get("target_url"),
            "analyzed_at": self.static_analysis_data.get("analyzed_at"),
            "summary": self.static_analysis_data.get("summary", {}),
        }

    def _build_gap_items(self) -> list[dict[str, Any]]:
        if not self.assessment_data:
            return []
        seen: set[tuple[Any, Any, Any]] = set()
        items: list[dict[str, Any]] = []
        for gap in self.assessment_data.get("baseline_gap_summary", []) or []:
            key = (gap.get("code"), gap.get("field"), gap.get("adjustment"))
            if key in seen:
                continue
            seen.add(key)
            items.append(gap)
        return items

    def _build_remote_summary(self) -> dict[str, Any]:
        remote = ((self.assessment_data or {}).get("remote_execution", {}) or {})
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
        for assessment in (self.assessment_data or {}).get("assessments", []) or []:
            for scenario in assessment.get("scenario_results", []) or []:
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

    def _build_endpoint_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for item in (self.assessment_data or {}).get("assessments", []) or []:
            scenario_details = []
            for scenario in item.get("scenario_results", []) or []:
                scenario_details.append({
                    "scenario_id": scenario.get("scenario_id"),
                    "status": scenario.get("status"),
                    "skip_reason": extract_skip_reason(scenario),
                })
            display_algorithms = self._filter_display_algorithms(item.get("algorithms", []))
            rows.append({
                "endpoint_id": item.get("endpoint_id"),
                "endpoint": item.get("endpoint"),
                "risk_level": item.get("risk_level"),
                "security_score": item.get("security_score"),
                "protocol_score": item.get("protocol_score"),
                "business_score": item.get("business_score"),
                "algorithms": display_algorithms,
                "findings": [finding.get("title") for finding in item.get("findings", [])],
                "scenario_details": scenario_details,
                "remote_execution": item.get("remote_execution", {}) or {},
                "error_portrait": item.get("error_portrait", {}) or {},
            })
        return rows

    def _filter_display_algorithms(self, algorithms: list[Any]) -> list[str]:
        filtered: list[str] = []
        for raw in algorithms or []:
            name = str(raw).strip()
            if not name:
                continue
            if name.upper() in NON_CRYPTO_FLOW_STEPS:
                continue
            if name in filtered:
                continue
            filtered.append(name)
        return filtered

    def _build_scoring_summary(self) -> dict[str, Any]:
        scoring = (self.assessment_data or {}).get("scoring", {}) or {}
        if not scoring:
            return {}
        return {
            "profile": scoring.get("profile"),
            "description": scoring.get("description"),
            "config_file": scoring.get("config_file"),
            "base_score": scoring.get("base_score"),
            "risk_thresholds": scoring.get("risk_thresholds", {}) or {},
            "severity_penalties": scoring.get("severity_penalties", {}) or {},
            "finding_category_multipliers": scoring.get("finding_category_multipliers", {}) or {},
            "scenario_status_penalties": scoring.get("scenario_status_penalties", {}) or {},
            "scenario_category_multipliers": scoring.get("scenario_category_multipliers", {}) or {},
            "baseline_gap_penalty": scoring.get("baseline_gap_penalty", {}) or {},
            "layer_score_weights": scoring.get("layer_score_weights", {}) or {},
        }

    def _build_limitations(self, gap_items: list[dict[str, Any]], remote_summary: dict[str, Any]) -> list[str]:
        limitations: list[str] = []
        if not self.baseline_data:
            limitations.append("未加载 baseline 文件，因此报告中的基线统计与状态分布可能不完整。")
        if not self.static_analysis_data:
            limitations.append("未加载 static analysis 文件，因此无法展示完整的静态上下文摘要。")
        if gap_items:
            limitations.append("部分端点仍缺少结构化字段，导致自动化只能完成本地重放，无法稳定完成所有变异请求的最终组装。")
        send_requests = ((self.assessment_data or {}).get("source", {}) or {}).get("send_requests")
        if not send_requests:
            limitations.append("本次报告中的“安全评估阶段真实请求发送”默认为关闭，即阶段5未向目标 API 真实发包；但阶段3 Playwright 动态捕获仍已在真实浏览器环境中执行前端逻辑，并用于回填运行时参数与基线密文。")
        elif remote_summary.get("attempted", 0) == 0:
            limitations.append("阶段5虽已开启真实目标验证模式，但没有任何场景成功进入远程发送；请检查目标地址、网络连通性、请求组包完整性或服务可用性。")
        return limitations

    def build_report_view(self) -> dict[str, Any]:
        if not self.assessment_data:
            raise ValueError("尚未加载 assessment 数据")
        summary = self.assessment_data.get("summary", {})
        baseline_summary = self._build_baseline_summary()
        static_summary = self._build_static_summary()
        remote_summary = self._build_remote_summary()
        gap_items = self._build_gap_items()
        self.report_view = {
            "report_id": self.assessment_data.get("report_id", f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "executive_summary": self.generate_executive_summary(),
            "overall_score": summary.get("overall_score", 0.0),
            "protocol_score": summary.get("protocol_score", 0.0),
            "business_score": summary.get("business_score", 0.0),
            "assessed_endpoints": summary.get("assessed_endpoints", 0),
            "findings_total": summary.get("findings_total", 0),
            "verified_entries": summary.get("verified_entries_total", 0),
            "workflow_summary": {
                "baseline_file": ((self.assessment_data or {}).get("source", {}) or {}).get("baseline_file"),
                "static_analysis_file": ((self.assessment_data or {}).get("source", {}) or {}).get("static_analysis_file"),
                "send_requests": ((self.assessment_data or {}).get("source", {}) or {}).get("send_requests"),
                "assessment_mode": "真实目标验证" if ((self.assessment_data or {}).get("source", {}) or {}).get("send_requests") else "本地预评估",
                "send_requests_note": "该字段仅表示阶段5安全评估是否向目标 API 真实发包；不代表阶段3 Playwright 动态捕获。阶段3 仍会在真实浏览器页面中执行前端逻辑并捕获密文/运行时参数。",
                "timeout_seconds": ((self.assessment_data or {}).get("source", {}) or {}).get("timeout_seconds"),
                "scoring_profile": ((self.assessment_data or {}).get("source", {}) or {}).get("scoring_profile"),
                "scoring_config_file": ((self.assessment_data or {}).get("source", {}) or {}).get("scoring_config_file"),
            },
            "remote_summary": remote_summary,
            "scoring_summary": self._build_scoring_summary(),
            "baseline_summary": baseline_summary,
            "static_summary": static_summary,
            "endpoint_rows": self._build_endpoint_rows(),
            "gap_items": gap_items,
            "error_clusters": (self.assessment_data or {}).get("error_clusters", {}) or {},
            "limitations": [],
        }
        self.report_view["limitations"] = self._build_limitations(gap_items, remote_summary)
        return self.report_view

    def generate_executive_summary(self) -> str:
        if not self.assessment_data:
            return "没有可用的评估结果。"
        summary = self.assessment_data.get("summary", {})
        severity = summary.get("by_severity", {})
        critical = severity.get("critical", 0)
        high = severity.get("high", 0)
        score = summary.get("overall_score", 0)
        assessed = summary.get("assessed_endpoints", 0)
        remote_attempted = summary.get("remote_attempted", 0)
        send_requests = ((self.assessment_data or {}).get("source", {}) or {}).get("send_requests")

        if critical > 0:
            risk_text = f"本次评估共发现 {critical} 个严重问题，需要优先修复。"
        elif high > 0:
            risk_text = f"本次评估未发现严重问题，但存在 {high} 个高风险问题。"
        else:
            risk_text = "本次评估未发现严重或高风险问题，但仍需结合基线缺口继续完善自动化链路。"

        if score >= 80:
            score_text = "从当前自动化结果看，整体风险较低。"
        elif score >= 60:
            score_text = "从当前自动化结果看，整体风险处于中等水平。"
        elif score >= 40:
            score_text = "从当前自动化结果看，整体风险较高。"
        else:
            score_text = "从当前自动化结果看，整体风险很高，需要尽快处理。"

        mode_text = f"阶段5运行于{'真实目标验证' if send_requests else '本地预评估'}模式"
        if send_requests:
            mode_text += f"，已尝试远程发送 {remote_attempted} 个场景。"
        else:
            mode_text += "，当前结果以离线协议层分析为主。"
        return f"共评估 {assessed} 个已验证端点。{risk_text}{score_text}{mode_text}"

    def _format_mapping_html(self, mapping: dict[str, Any]) -> str:
        if not mapping:
            return "<li>无</li>"
        return "".join(f"<li><code>{key}</code>: {value}</li>" for key, value in mapping.items())

    def _format_mapping_md(self, mapping: dict[str, Any]) -> str:
        if not mapping:
            return "- 无"
        return "\n".join(f"- `{key}`: {value}" for key, value in mapping.items())

    def _workflow_summary_html(self) -> str:
        data = self.report_view["workflow_summary"]
        return (
            f"<ul>"
            f"<li>Baseline: <code>{data.get('baseline_file') or 'N/A'}</code></li>"
            f"<li>Static Analysis: <code>{data.get('static_analysis_file') or 'N/A'}</code></li>"
            f"<li>阶段5评估模式: {data.get('assessment_mode')}</li>"
            f"<li>安全评估阶段真实请求发送: {data.get('send_requests')}</li>"
            f"<li>说明: {data.get('send_requests_note')}</li>"
            f"<li>超时设置: {data.get('timeout_seconds')} 秒</li>"
            f"<li>评分 Profile: <code>{data.get('scoring_profile') or 'default'}</code></li>"
            f"<li>评分配置文件: <code>{data.get('scoring_config_file') or 'N/A'}</code></li>"
            f"</ul>"
        )

    def _remote_summary_html(self) -> str:
        data = self.report_view.get("remote_summary", {}) or {}
        workflow = self.report_view.get("workflow_summary", {}) or {}
        if not workflow.get("send_requests"):
            return "<p>当前为本地预评估模式：阶段5未真实发包，在线验证统计为空。是否发网由阶段5入口的 --send / --phase5-send 控制。</p>"
        avg_elapsed = data.get("avg_elapsed_ms") if data.get("avg_elapsed_ms") is not None else "N/A"
        p95_elapsed = data.get("p95_elapsed_ms") if data.get("p95_elapsed_ms") is not None else "N/A"
        mode_clusters = (self.report_view.get("error_clusters", {}) or {}).get("global_mode_counts", {}) or {}
        return (
            f"<ul>"
            f"<li>场景总数: {data.get('total_scenarios', 0)}</li>"
            f"<li>已尝试远程发送: {data.get('attempted', 0)}</li>"
            f"<li>收到 HTTP 响应: {data.get('responded', 0)}</li>"
            f"<li>远程发送错误: {data.get('errors', 0)}</li>"
            f"<li>未发起远程发送: {data.get('not_attempted', 0)}</li>"
            f"<li>平均耗时: {avg_elapsed} ms</li>"
            f"<li>P95 耗时: {p95_elapsed} ms</li>"
            f"<li>HTTP 状态码分布<ul>{self._format_mapping_html(data.get('status_code_counts', {}) or {})}</ul></li>"
            f"<li>远程错误分布<ul>{self._format_mapping_html(data.get('error_counts', {}) or {})}</ul></li>"
            f"<li>响应语义聚类<ul>{self._format_mapping_html(mode_clusters)}</ul></li>"
            f"</ul>"
        )

    def _scoring_summary_html(self) -> str:
        data = self.report_view.get("scoring_summary", {}) or {}
        if not data:
            return "<p>评估结果中未包含评分配置。</p>"
        gap_penalty = data.get("baseline_gap_penalty", {}) or {}
        layer_weights = data.get("layer_score_weights", {}) or {}
        return (
            f"<p>{data.get('description') or '未提供说明'}</p>"
            f"<ul>"
            f"<li>Profile: <code>{data.get('profile') or 'default'}</code></li>"
            f"<li>配置文件: <code>{data.get('config_file') or 'N/A'}</code></li>"
            f"<li>基础分: {data.get('base_score')}</li>"
            f"<li>风险阈值<ul>{self._format_mapping_html(data.get('risk_thresholds', {}))}</ul></li>"
            f"<li>严重级别扣分<ul>{self._format_mapping_html(data.get('severity_penalties', {}))}</ul></li>"
            f"<li>发现类别系数<ul>{self._format_mapping_html(data.get('finding_category_multipliers', {}))}</ul></li>"
            f"<li>场景状态扣分<ul>{self._format_mapping_html(data.get('scenario_status_penalties', {}))}</ul></li>"
            f"<li>场景类别系数<ul>{self._format_mapping_html(data.get('scenario_category_multipliers', {}))}</ul></li>"
            f"<li>基线缺口惩罚: 每项 {gap_penalty.get('per_gap')}，累计上限 {gap_penalty.get('max_total')}</li>"
            f"<li>分层评分权重<ul>{self._format_mapping_html(layer_weights)}</ul></li>"
            f"</ul>"
        )

    def _baseline_summary_html(self) -> str:
        summary = self.report_view["baseline_summary"]
        if not summary.get("total"):
            return "<p>未加载 baseline 文件。</p>"
        status_rows = "".join(f"<li>{key}: {value}</li>" for key, value in (summary.get("status_counts", {}) or {}).items())
        comparison_rows = "".join(f"<li>{key}: {value}</li>" for key, value in (summary.get("comparison_counts", {}) or {}).items())
        return (
            f"<p>总基线数: {summary.get('total')}，验证通过: {summary.get('verified')}</p>"
            f"<p><strong>Status 分布</strong></p><ul>{status_rows}</ul>"
            f"<p><strong>Comparison 分布</strong></p><ul>{comparison_rows}</ul>"
        )

    def _static_summary_html(self) -> str:
        static_summary = self.report_view["static_summary"]
        if not static_summary:
            return "<p>未加载 static analysis 文件。</p>"
        summary = static_summary.get("summary", {}) or {}
        return (
            f"<ul>"
            f"<li>目标页面: <code>{static_summary.get('target_url')}</code></li>"
            f"<li>分析时间: {static_summary.get('analyzed_at')}</li>"
            f"<li>端点总数: {summary.get('total_endpoints')}</li>"
            f"<li>加密模式数: {summary.get('total_crypto_patterns')}</li>"
            f"<li>安全发现数: {summary.get('total_security_findings')}</li>"
            f"</ul>"
        )

    def _endpoint_table_html(self) -> str:
        rows = []
        send_requests = self.report_view.get("workflow_summary", {}).get("send_requests")
        for item in self.report_view["endpoint_rows"]:
            finding_html = "<br>".join(item.get("findings") or ["无"])
            scenario_html = "<br>".join(
                f"{detail.get('scenario_id')}: {detail.get('status')}（原因: {detail.get('skip_reason')}）"
                if detail.get("status") == "SKIPPED" and detail.get("skip_reason")
                else f"{detail.get('scenario_id')}: {detail.get('status')}"
                for detail in item.get("scenario_details", [])
            ) or "无"
            remote = item.get("remote_execution", {}) or {}
            if remote.get("attempted", 0) > 0:
                remote_html = (
                    f"已发 {remote.get('attempted', 0)} / 响应 {remote.get('responded', 0)} / 错误 {remote.get('errors', 0)}"
                    f"<br>状态码: {', '.join(f'{k}:{v}' for k, v in (remote.get('status_code_counts', {}) or {}).items()) or '无'}"
                )
            else:
                remote_html = "未发网" if not send_requests else "未成功发起远程发送"
            rows.append(
                f"<tr>"
                f"<td><code>{item.get('endpoint_id')}</code></td>"
                f"<td>{item.get('endpoint')}</td>"
                f"<td>{item.get('security_score')}</td>"
                f"<td>P:{item.get('protocol_score')} / B:{item.get('business_score')}</td>"
                f"<td>{item.get('risk_level')}</td>"
                f"<td>{', '.join(item.get('algorithms') or [])}</td>"
                f"<td>{finding_html}</td>"
                f"<td>{remote_html}</td>"
                f"<td>{', '.join(f'{k}:{v}' for k, v in (item.get('error_portrait', {}).get('response_mode_counts', {}) or {}).items()) or '无'}</td>"
                f"<td>{scenario_html}</td>"
                f"</tr>"
            )
        return (
            "<table><thead><tr><th>Endpoint ID</th><th>URL</th><th>评分</th><th>分层评分</th><th>风险</th><th>算法</th><th>发现</th><th>在线验证</th><th>失败画像</th><th>场景状态</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    def _gap_section_html(self) -> str:
        if not self.report_view["gap_items"]:
            return "<p>未检测到明显的基线结构缺口。</p>"
        items = []
        for gap in self.report_view["gap_items"]:
            items.append(
                f"<li><strong>{gap.get('code')}</strong> - 字段 <code>{gap.get('field')}</code>：{gap.get('reason')}"
                f"<br>应回溯阶段：{gap.get('required_phase')}"
                f"<br>建议：{gap.get('adjustment')}</li>"
            )
        return f"<ul>{''.join(items)}</ul>"

    def _limitations_html(self) -> str:
        if not self.report_view.get("limitations"):
            return "<p>无。</p>"
        return "<ul>" + "".join(f"<li>{item}</li>" for item in self.report_view["limitations"]) + "</ul>"

    def _workflow_summary_md(self) -> str:
        data = self.report_view["workflow_summary"]
        return (
            f"- Baseline: `{data.get('baseline_file') or 'N/A'}`\n"
            f"- Static Analysis: `{data.get('static_analysis_file') or 'N/A'}`\n"
            f"- 阶段5评估模式: {data.get('assessment_mode')}\n"
            f"- 安全评估阶段真实请求发送: {data.get('send_requests')}\n"
            f"- 说明: {data.get('send_requests_note')}\n"
            f"- 超时设置: {data.get('timeout_seconds')} 秒\n"
            f"- 评分 Profile: `{data.get('scoring_profile') or 'default'}`\n"
            f"- 评分配置文件: `{data.get('scoring_config_file') or 'N/A'}`"
        )

    def _remote_summary_md(self) -> str:
        data = self.report_view.get("remote_summary", {}) or {}
        workflow = self.report_view.get("workflow_summary", {}) or {}
        if not workflow.get("send_requests"):
            return "当前为本地预评估模式：阶段5未真实发包，在线验证统计为空。是否发网由阶段5入口的 `--send` / `--phase5-send` 控制。"
        avg_elapsed = data.get("avg_elapsed_ms") if data.get("avg_elapsed_ms") is not None else "N/A"
        p95_elapsed = data.get("p95_elapsed_ms") if data.get("p95_elapsed_ms") is not None else "N/A"
        mode_clusters = (self.report_view.get("error_clusters", {}) or {}).get("global_mode_counts", {}) or {}
        return (
            f"- 场景总数: {data.get('total_scenarios', 0)}\n"
            f"- 已尝试远程发送: {data.get('attempted', 0)}\n"
            f"- 收到 HTTP 响应: {data.get('responded', 0)}\n"
            f"- 远程发送错误: {data.get('errors', 0)}\n"
            f"- 未发起远程发送: {data.get('not_attempted', 0)}\n"
            f"- 平均耗时: {avg_elapsed} ms\n"
            f"- P95 耗时: {p95_elapsed} ms\n\n"
            f"**HTTP 状态码分布**\n{self._format_mapping_md(data.get('status_code_counts', {}) or {})}\n\n"
            f"**远程错误分布**\n{self._format_mapping_md(data.get('error_counts', {}) or {})}\n\n"
            f"**响应语义聚类**\n{self._format_mapping_md(mode_clusters)}"
        )

    def _scoring_summary_md(self) -> str:
        data = self.report_view.get("scoring_summary", {}) or {}
        if not data:
            return "评估结果中未包含评分配置。"
        gap_penalty = data.get("baseline_gap_penalty", {}) or {}
        layer_weights = data.get("layer_score_weights", {}) or {}
        return (
            f"- Profile: `{data.get('profile') or 'default'}`\n"
            f"- 说明: {data.get('description') or '未提供说明'}\n"
            f"- 配置文件: `{data.get('config_file') or 'N/A'}`\n"
            f"- 基础分: {data.get('base_score')}\n"
            f"- 基线缺口惩罚: 每项 {gap_penalty.get('per_gap')}，累计上限 {gap_penalty.get('max_total')}\n"
            f"- 分层评分权重: protocol={layer_weights.get('protocol', 'N/A')} / business={layer_weights.get('business', 'N/A')}\n\n"
            f"**风险阈值**\n{self._format_mapping_md(data.get('risk_thresholds', {}))}\n\n"
            f"**严重级别扣分**\n{self._format_mapping_md(data.get('severity_penalties', {}))}\n\n"
            f"**发现类别系数**\n{self._format_mapping_md(data.get('finding_category_multipliers', {}))}\n\n"
            f"**场景状态扣分**\n{self._format_mapping_md(data.get('scenario_status_penalties', {}))}\n\n"
            f"**场景类别系数**\n{self._format_mapping_md(data.get('scenario_category_multipliers', {}))}"
        )

    def _baseline_summary_md(self) -> str:
        summary = self.report_view["baseline_summary"]
        if not summary.get("total"):
            return "未加载 baseline 文件。"
        status_lines = "\n".join(f"- {key}: {value}" for key, value in (summary.get("status_counts", {}) or {}).items())
        comparison_lines = "\n".join(f"- {key}: {value}" for key, value in (summary.get("comparison_counts", {}) or {}).items())
        return (
            f"- 总基线数: {summary.get('total')}\n"
            f"- 验证通过: {summary.get('verified')}\n\n"
            f"**Status 分布**\n{status_lines}\n\n"
            f"**Comparison 分布**\n{comparison_lines}"
        )

    def _static_summary_md(self) -> str:
        static_summary = self.report_view["static_summary"]
        if not static_summary:
            return "未加载 static analysis 文件。"
        summary = static_summary.get("summary", {}) or {}
        return (
            f"- 目标页面: `{static_summary.get('target_url')}`\n"
            f"- 分析时间: {static_summary.get('analyzed_at')}\n"
            f"- 端点总数: {summary.get('total_endpoints')}\n"
            f"- 加密模式数: {summary.get('total_crypto_patterns')}\n"
            f"- 安全发现数: {summary.get('total_security_findings')}"
        )

    def _endpoint_table_md(self) -> str:
        lines = ["| Endpoint ID | URL | 评分 | 分层评分 | 风险 | 算法 | 发现 | 在线验证 | 失败画像 | 场景状态 |", "|---|---|---:|---|---|---|---|---|---|---|"]
        send_requests = self.report_view.get("workflow_summary", {}).get("send_requests")
        for item in self.report_view["endpoint_rows"]:
            findings = "<br>".join(item.get("findings") or ["无"])
            scenario_status = "<br>".join(
                f"{detail.get('scenario_id')}:{detail.get('status')}（原因: {detail.get('skip_reason')}）"
                if detail.get("status") == "SKIPPED" and detail.get("skip_reason")
                else f"{detail.get('scenario_id')}:{detail.get('status')}"
                for detail in item.get("scenario_details", [])
            ) or "无"
            remote = item.get("remote_execution", {}) or {}
            if remote.get("attempted", 0) > 0:
                remote_summary = (
                    f"已发{remote.get('attempted', 0)} / 响应{remote.get('responded', 0)} / 错误{remote.get('errors', 0)}"
                    f"<br>状态码:{', '.join(f'{k}:{v}' for k, v in (remote.get('status_code_counts', {}) or {}).items()) or '无'}"
                )
            else:
                remote_summary = "未发网" if not send_requests else "未成功发起远程发送"
            lines.append(
                f"| {item.get('endpoint_id')} | {item.get('endpoint')} | {item.get('security_score')} | P:{item.get('protocol_score')} / B:{item.get('business_score')} | {item.get('risk_level')} | {', '.join(item.get('algorithms') or [])} | {findings} | {remote_summary} | {', '.join(f'{k}:{v}' for k, v in (item.get('error_portrait', {}).get('response_mode_counts', {}) or {}).items()) or '无'} | {scenario_status} |"
            )
        return "\n".join(lines)

    def _gap_section_md(self) -> str:
        if not self.report_view["gap_items"]:
            return "未检测到明显的基线结构缺口。"
        lines = []
        for gap in self.report_view["gap_items"]:
            lines.append(
                f"- **{gap.get('code')}** / `{gap.get('field')}`\n"
                f"  - 原因: {gap.get('reason')}\n"
                f"  - 回溯阶段: {gap.get('required_phase')}\n"
                f"  - 建议: {gap.get('adjustment')}"
            )
        return "\n".join(lines)

    def _limitations_md(self) -> str:
        if not self.report_view.get("limitations"):
            return "无。"
        return "\n".join(f"- {item}" for item in self.report_view["limitations"])

    def generate_html(self, filename: Optional[str] = None) -> Path:
        if not self.report_view:
            self.build_report_view()
        filename = filename or f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"
        output_path = self.output_dir / filename
        content = HTML_TEMPLATE.format(
            report_id=self.report_view["report_id"],
            generated_at=self.report_view["generated_at"],
            overall_score=self.report_view["overall_score"],
            protocol_score=self.report_view["protocol_score"],
            business_score=self.report_view["business_score"],
            assessed_endpoints=self.report_view["assessed_endpoints"],
            findings_total=self.report_view["findings_total"],
            verified_entries=self.report_view["verified_entries"],
            executive_summary=self.report_view["executive_summary"],
            workflow_summary=self._workflow_summary_html(),
            remote_summary=self._remote_summary_html(),
            scoring_summary=self._scoring_summary_html(),
            baseline_summary=self._baseline_summary_html(),
            static_summary=self._static_summary_html(),
            endpoint_table=self._endpoint_table_html(),
            gap_section=self._gap_section_html(),
            limitations_section=self._limitations_html(),
        )
        output_path.write_text(content, encoding="utf-8")
        console.print(f"[green][OK] 已生成 HTML 报告:[/green] {output_path}")
        return output_path

    def generate_markdown(self, filename: Optional[str] = None) -> Path:
        if not self.report_view:
            self.build_report_view()
        filename = filename or f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md"
        output_path = self.output_dir / filename
        content = MARKDOWN_TEMPLATE.format(
            report_id=self.report_view["report_id"],
            generated_at=self.report_view["generated_at"],
            executive_summary=self.report_view["executive_summary"],
            workflow_summary=self._workflow_summary_md(),
            remote_summary=self._remote_summary_md(),
            scoring_summary=self._scoring_summary_md(),
            baseline_summary=self._baseline_summary_md(),
            static_summary=self._static_summary_md(),
            overall_score=self.report_view["overall_score"],
            protocol_score=self.report_view["protocol_score"],
            business_score=self.report_view["business_score"],
            assessed_endpoints=self.report_view["assessed_endpoints"],
            findings_total=self.report_view["findings_total"],
            verified_entries=self.report_view["verified_entries"],
            endpoint_table=self._endpoint_table_md(),
            gap_section=self._gap_section_md(),
            limitations_section=self._limitations_md(),
        )
        output_path.write_text(content, encoding="utf-8")
        console.print(f"[green][OK] 已生成 Markdown 报告:[/green] {output_path}")
        return output_path

    def generate_json(self, filename: Optional[str] = None) -> Path:
        if not self.report_view:
            self.build_report_view()
        filename = filename or f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        output_path = self.output_dir / filename
        output_path.write_text(json.dumps(self.report_view, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"[green][OK] 已生成 JSON 报告:[/green] {output_path}")
        return output_path

    def display_preview(self) -> None:
        if not self.report_view:
            self.build_report_view()
        console.print(
            f"[bold]报告预览[/bold]\n"
            f"总体评分: {self.report_view['overall_score']:.2f}/100\n"
            f"评估端点: {self.report_view['assessed_endpoints']}\n"
            f"发现总数: {self.report_view['findings_total']}\n"
            f"已验证基线: {self.report_view['verified_entries']}"
        )


def resolve_assessment_file(file_arg: Optional[str], assessment_dir: Path) -> Optional[Path]:
    if file_arg:
        candidate = Path(file_arg)
        return candidate if candidate.exists() else None
    return latest_matching_file(assessment_dir, "assessment_*.json")


def main() -> None:
    parser = argparse.ArgumentParser(description="生成当前工作流的最终报告")
    parser.add_argument("--assessment", type=Path, default=DEFAULT_ASSESSMENT_DIR, help=f"assessment 目录，默认: {DEFAULT_ASSESSMENT_DIR}")
    parser.add_argument("--file", help="指定 assessment JSON 文件")
    parser.add_argument("--baseline", help="可选，指定 baseline JSON 文件")
    parser.add_argument("--static-analysis", help="可选，指定 static analysis JSON 文件")
    parser.add_argument("--format", choices=["html", "markdown", "json", "all"], default="all", help="输出格式")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_DIR, help=f"报告输出目录，默认: {DEFAULT_OUTPUT_DIR}")
    args = parser.parse_args()

    assessment_file = resolve_assessment_file(args.file, args.assessment)
    if not assessment_file:
        console.print("[red]未找到 assessment 结果，请先运行 assess/assess_endpoint.py[/red]")
        return

    console.print(f"[cyan]使用 assessment:[/cyan] {assessment_file}")
    generator = ReportGenerator(output_dir=args.output)
    if not generator.load_assessment(assessment_file):
        return
    generator.load_baseline(Path(args.baseline) if args.baseline else None)
    generator.load_static_analysis(Path(args.static_analysis) if args.static_analysis else None)
    generator.build_report_view()
    generator.display_preview()

    if args.format in {"html", "all"}:
        generator.generate_html()
    if args.format in {"markdown", "all"}:
        generator.generate_markdown()
    if args.format in {"json", "all"}:
        generator.generate_json()


if __name__ == "__main__":
    main()
