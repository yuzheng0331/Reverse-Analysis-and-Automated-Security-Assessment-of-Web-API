#!/usr/bin/env python3
"""
单端点多场景调试脚本：打印原包与所有场景的变异包/响应包/判定诊断。

用途：
- 以“单端点、全场景”方式观察请求构造与判定结果。
- 明确区分：
  1) 原包重建来源（baseline_replay 产出的本地重建包）
  2) baseline_replay 作为场景本身的评估结果
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from assess.assess_endpoint import (
    BaselineAssessmentEngine,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_SCORING_CONFIG,
    resolve_baseline_path,
)
from assess.common import load_json_file, utc_now

# Windows 控制台常见编码为 GBK，强制切到 UTF-8 避免调试输出因 Unicode 字符中断。
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _is_password_prehash_entry(entry: dict[str, Any]) -> bool:
    execution_flow = ((entry.get("meta", {}) or {}).get("execution_flow", []) or [])
    for step in execution_flow:
        args = step.get("runtime_args", {}) or {}
        if str(args.get("scenario", "")).strip() == "PasswordPreHash":
            return True
    return False


def _filter_scenarios(
    scenarios: list[dict[str, Any]],
    scenario_id: Optional[str],
) -> list[dict[str, Any]]:
    if not scenario_id:
        return scenarios
    selected = [item for item in scenarios if str(item.get("scenario_id")) == scenario_id]
    if selected:
        return selected
    available = ", ".join(str(item.get("scenario_id")) for item in scenarios)
    raise ValueError(f"未找到场景: {scenario_id}。可用场景: {available}")


def _find_latest_fetch_trace(entry: dict[str, Any]) -> Optional[dict[str, Any]]:
    trace = ((entry.get("validation", {}) or {}).get("trace", []) or [])
    for item in reversed(trace):
        if isinstance(item, dict) and item.get("type") == "FETCH":
            return item
    return None


def _compact_request_preview(preview: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(preview, dict):
        return {"available": False}
    return {
        "available": True,
        "body_type": preview.get("body_type"),
        "send_ready": preview.get("send_ready"),
        "missing_fields": preview.get("missing_fields"),
        "headers": preview.get("headers"),
        "body_json": preview.get("body_json"),
        "body_text": preview.get("body_text"),
        "resolved_fields": preview.get("resolved_fields"),
    }


def _build_match_diagnosis(expectation: dict[str, Any], remote_result: dict[str, Any]) -> dict[str, Any]:
    """输出命中判定依据，便于调试“泛化+诊断”口径。"""
    expectation = expectation or {}
    remote_result = remote_result or {}

    matched = expectation.get("matched")
    mode_match = expectation.get("remote_mode_match")
    layer_match = expectation.get("response_layer_match")
    mode = expectation.get("actual_remote_mode") or remote_result.get("response_mode")
    layers = expectation.get("actual_response_layers") or remote_result.get("response_layers") or {}

    reason_parts: list[str] = []
    if mode_match is True:
        reason_parts.append("远程模式命中")
    elif mode_match is False:
        reason_parts.append("远程模式未命中")
    else:
        reason_parts.append("远程模式未评估")

    if layer_match is True:
        reason_parts.append("三层规则命中")
    elif layer_match is False:
        reason_parts.append("三层规则未命中")
    else:
        reason_parts.append("三层规则未评估")

    final_reason = "；".join(reason_parts)
    if matched is True:
        final_reason = f"命中：{final_reason}"
    elif matched is False:
        final_reason = f"未命中：{final_reason}"
    else:
        final_reason = f"未评估：{final_reason}"

    return {
        "matched": matched,
        "waive_penalty": expectation.get("waive_penalty"),
        "decision_reason": final_reason,
        "actual_remote_mode": mode,
        "actual_response_layers": layers,
        "expected_remote_modes": expectation.get("expected_remote_modes", []),
        "expected_layer_rules": expectation.get("expected_layer_rules", []),
        "remote_mode_match": mode_match,
        "response_layer_match": layer_match,
    }


def _build_scenario_packet(scenario: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    remote_result = result.get("remote_result", {}) or {}
    expectation = result.get("expectation", {}) or {}
    return {
        "scenario_id": scenario.get("scenario_id"),
        "scenario_title": scenario.get("title"),
        "scenario_category": scenario.get("category"),
        "is_baseline_replay": str(scenario.get("scenario_id")) == "baseline_replay",
        "mutated_packet": {
            "request_preview": _compact_request_preview(result.get("request_preview")),
            "scenario_status": result.get("status"),
            "skip_reason": result.get("skip_reason"),
            "local_error": (result.get("local_replay", {}) or {}).get("error"),
        },
        "response_packet": {
            "remote_result": remote_result,
            "expectation": expectation,
            "judgement": _build_match_diagnosis(expectation, remote_result),
            "observations": result.get("observations"),
        },
    }


def _dynamic_endpoint_evidence(entry: dict[str, Any]) -> dict[str, Any]:
    validation = (entry.get("validation", {}) or {})
    dynamic_meta = (validation.get("dynamic", {}) or {})
    hint = (dynamic_meta.get("hint", {}) or {})
    if not hint:
        hint = ((entry.get("meta", {}) or {}).get("dynamic_endpoint_hint", {}) or {})
    observed = (dynamic_meta.get("observed", {}) or {})
    if not observed:
        observed = (validation.get("dynamic_observed", {}) or {})
    runtime_params = (validation.get("runtime_params", {}) or {})
    execution_flow = ((entry.get("meta", {}) or {}).get("execution_flow", []) or [])
    pack_fields: list[str] = []
    has_derive_or_sign = False
    for step in execution_flow:
        step_type = str(step.get("step_type", "")).lower()
        if step_type.startswith("derive_") or step_type == "sign":
            has_derive_or_sign = True
        if step_type == "pack":
            structure = (((step.get("runtime_args", {}) or {}).get("packing_info", {}) or {}).get("structure", {}) or {})
            pack_fields.extend(str(key) for key in structure.keys())

    dynamic_markers = {"key", "iv", "nonce", "timestamp", "signature", "sign", "token", "public_key", "message"}
    runtime_hits = sorted([str(key) for key in runtime_params.keys() if str(key) in dynamic_markers])
    pack_hits = sorted([field for field in set(pack_fields) if field in dynamic_markers])
    return {
        "hint": hint,
        "observed": observed,
        "runtime_param_hits": runtime_hits,
        "pack_field_hits": pack_hits,
        "has_derive_or_sign": has_derive_or_sign,
    }


def _annotate_non_sendable_reason(packet: dict[str, Any]) -> None:
    mp = packet.get("mutated_packet", {}) or {}
    rp = packet.get("response_packet", {}) or {}
    status = str(mp.get("scenario_status") or "")
    skip_reason = str(mp.get("skip_reason") or "")
    remote_attempted = bool(((rp.get("remote_result", {}) or {}).get("attempted")))

    note = None
    code = None
    if status == "SKIPPED":
        if "payload 变异未映射到最终请求体" in skip_reason or "变异未映射到最终请求体" in skip_reason:
            code = "MUTATION_NOT_EFFECTIVE"
            note = "变异未落地到最终发送包，场景按无效变异跳过。"
        elif "未找到可篡改目标字段" in skip_reason or "无法执行协议篡改场景" in skip_reason:
            code = "UNMUTATABLE"
            note = "端点不支持该变异或缺少目标字段，场景跳过且不参与未命中。"
        else:
            code = "SKIPPED_OTHER"
            note = "场景被跳过，请结合 skip_reason 与 observations 继续排查。"
    elif status == "LOCAL_FAILED" and not remote_attempted:
        code = "LOCAL_FAILURE_BLOCKED_SEND"
        note = "本地明确失败，按策略禁止发送，避免污染在线验证。"

    if code:
        packet["local_gate"] = {
            "code": code,
            "note": note,
            "skip_reason": skip_reason or None,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="调试单端点多场景原包/变异包/响应包")
    parser.add_argument("--baseline", help="baseline JSON 路径（默认最新 baseline_skeletons_*.json）")
    parser.add_argument("--endpoint-id", required=True, help="目标端点 ID，如 aes/rsa/des")
    parser.add_argument("--scenario-id", help="可选：仅调试指定场景 ID；不传则输出该端点全部场景")
    parser.add_argument("--timeout", type=float, default=10.0, help="真实发包超时（秒）")
    parser.add_argument("--capture-page-url", help="动态端点场景前 fresh capture 的页面 URL（建议传 easy.php）")
    parser.add_argument("--output-json", help="可选：将调试结果保存到 JSON 文件")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    baseline_path = resolve_baseline_path(args.baseline)
    baseline_data = load_json_file(baseline_path)
    if not isinstance(baseline_data, list):
        raise ValueError("baseline 文件格式错误：应为列表")

    entry = None
    for item in baseline_data:
        if str((item.get("meta", {}) or {}).get("id")) == str(args.endpoint_id):
            entry = item
            break
    if not entry:
        all_ids = [str((item.get("meta", {}) or {}).get("id")) for item in baseline_data]
        raise ValueError(f"未找到 endpoint_id={args.endpoint_id}。可用: {', '.join(all_ids)}")

    engine = BaselineAssessmentEngine(
        output_dir=Path(DEFAULT_OUTPUT_DIR),
        timeout=float(args.timeout),
        capture_page_url=args.capture_page_url,
        scoring_profile="default",
        scoring_config_path=Path(DEFAULT_SCORING_CONFIG),
    )

    payload = copy.deepcopy(((entry.get("request", {}) or {}).get("payload", {}) or {}))
    if not isinstance(payload, dict):
        raise ValueError("该端点 payload 非字典格式，当前调试脚本仅支持 JSON-like payload。")

    if _is_password_prehash_entry(entry):
        scenarios = engine._build_password_prehash_scenarios(payload)
    else:
        scenarios = engine._build_scenarios(payload)

    baseline_scenario = next((s for s in scenarios if str(s.get("scenario_id")) == "baseline_replay"), None)
    if not baseline_scenario:
        raise ValueError("未找到 baseline_replay 场景。")

    is_dynamic_endpoint = bool(engine._is_dynamic_endpoint(entry))

    # 动态端点：每个场景前 fresh capture；静态端点：沿用本地重建。
    baseline_entry = entry
    baseline_capture_note = None
    if is_dynamic_endpoint:
        baseline_entry, baseline_capture_note = engine._fresh_capture_dynamic_entry(entry)
    baseline_result = engine._run_scenario(baseline_entry, payload, baseline_scenario, baseline_request_preview=None)
    if baseline_capture_note:
        observations = baseline_result.get("observations") or []
        observations.insert(0, baseline_capture_note)
        baseline_result["observations"] = observations
    baseline_preview = baseline_result.get("request_preview")

    scenario_packets: list[dict[str, Any]] = [_build_scenario_packet(baseline_scenario, baseline_result)]
    selected_scenarios = _filter_scenarios(scenarios, args.scenario_id)
    for scenario in selected_scenarios:
        if str(scenario.get("scenario_id")) == "baseline_replay":
            continue
        scenario_entry = entry
        capture_note = None
        if is_dynamic_endpoint:
            scenario_entry, capture_note = engine._fresh_capture_dynamic_entry(entry)
        result = engine._run_scenario(scenario_entry, payload, scenario, baseline_request_preview=baseline_preview)
        if capture_note:
            observations = result.get("observations") or []
            observations.insert(0, capture_note)
            result["observations"] = observations
        scenario_packets.append(_build_scenario_packet(scenario, result))

    for packet in scenario_packets:
        _annotate_non_sendable_reason(packet)

    trace_fetch = _find_latest_fetch_trace(entry)
    dynamic_evidence = _dynamic_endpoint_evidence(entry)
    debug_result = {
        "generated_at": utc_now(),
        "baseline_file": str(baseline_path),
        "endpoint": {
            "id": (entry.get("meta", {}) or {}).get("id"),
            "url": (entry.get("meta", {}) or {}).get("url"),
            "method": (entry.get("meta", {}) or {}).get("method"),
            "trigger_function": (entry.get("meta", {}) or {}).get("trigger_function"),
            "dynamic_endpoint": is_dynamic_endpoint,
            "dynamic_evidence": dynamic_evidence,
        },
        "mode": {
            "send": True,
            "timeout": float(args.timeout),
            "dynamic_endpoint_strategy": "fresh_capture_per_scenario" if is_dynamic_endpoint else "local_rebuild_then_send",
            "capture_page_url": args.capture_page_url,
        },
        "raw_packet": {
            "from_capture_trace": trace_fetch,
            "from_reconstructed_baseline": _compact_request_preview(baseline_preview),
            "scenario_status": baseline_result.get("status"),
            "local_error": (baseline_result.get("local_replay", {}) or {}).get("error"),
            "explain": "原包中的重建包来源于 baseline_replay 场景执行结果，用于作为后续各变异场景的对照基准。",
        },
        "scenario_packets": scenario_packets,
        "stats": {
            "total_scenarios": len(scenario_packets),
            "status_counts": {
                "REMOTE_SENT": sum(1 for item in scenario_packets if ((item.get("mutated_packet", {}) or {}).get("scenario_status") == "REMOTE_SENT")),
                "LOCAL_OK": sum(1 for item in scenario_packets if ((item.get("mutated_packet", {}) or {}).get("scenario_status") == "LOCAL_OK")),
                "LOCAL_FAILED": sum(1 for item in scenario_packets if ((item.get("mutated_packet", {}) or {}).get("scenario_status") == "LOCAL_FAILED")),
                "SKIPPED": sum(1 for item in scenario_packets if ((item.get("mutated_packet", {}) or {}).get("scenario_status") == "SKIPPED")),
            },
        },
    }

    if args.output_json:
        output_path = Path(args.output_json)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(debug_result, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps(debug_result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())









