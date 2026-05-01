#!/usr/bin/env python3
"""
Phase 5: Endpoint Security Assessment
====================================
基于统一基线 JSON 执行安全性评估。
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import copy
import hashlib
import hmac
import json
import random
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich import box

try:
    import requests
except ImportError:
    requests = None

try:
    from playwright.async_api import async_playwright
except ImportError:
    async_playwright = None

from assess.common import latest_matching_file, load_json_file, load_yaml_file, save_json_file, safe_json_dumps, truncate_text, utc_now
from handlers.base import CryptoContext
from handlers.operations import VariableDerivationOperation
from handlers.registry import get_registry
from scripts.capture_baseline_playwright import build_dynamic_observed

console = Console()
DEFAULT_BASELINE_DIR = BASE_DIR / "baseline_samples"
DEFAULT_STATIC_ANALYSIS_DIR = BASE_DIR / "collect" / "static_analysis"
DEFAULT_OUTPUT_DIR = BASE_DIR / "assessment_results"
DEFAULT_SCORING_CONFIG = BASE_DIR / "configs" / "scoring_profiles.yaml"
CAPTURE_SCRIPT_PATH = BASE_DIR / "scripts" / "capture_baseline_playwright.py"

FINDING_LIBRARY = {
    "CRYPTO_WEAK_DES": {
        "title": "使用弱加密算法 DES",
        "severity": "critical",
        "category": "cryptography",
        "description": "前端仍在使用 DES，这是一种已不推荐使用的弱加密算法。",
        "remediation": "替换为 AES-GCM、AES-CBC + 完整性保护等现代方案。",
        "cwe_id": "CWE-327",
    },
    "CRYPTO_HARDCODED_KEY": {
        "title": "前端存在硬编码密钥或固定密钥材料",
        "severity": "critical",
        "category": "cryptography",
        "description": "前端静态代码中暴露了固定 key / iv / secret，攻击者可以直接提取并离线重放。",
        "remediation": "移除前端硬编码秘密，改为服务端协商或使用真正的临时凭据。",
        "cwe_id": "CWE-321",
    },
    "CRYPTO_STATIC_IV": {
        "title": "存在固定或可预测的 IV",
        "severity": "high",
        "category": "cryptography",
        "description": "固定 IV 会降低分组加密方案的安全性，容易导致模式泄露。",
        "remediation": "为每次加密生成新的随机 IV，并随请求安全传输。",
        "cwe_id": "CWE-329",
    },
    "AUTH_SIGNATURE_BYPASS_RISK": {
        "title": "签名输入规则未结构化，可能影响验证与评估完整性",
        "severity": "medium",
        "category": "authentication",
        "description": "当前基线缺少结构化的签名输入拼接规则，导致本地无法稳定重建签名链。",
        "remediation": "在静态分析阶段输出结构化的签名输入表达式，并在捕获阶段回填 nonce / timestamp 等动态参数。",
        "cwe_id": "CWE-347",
    },
    "ASSESSMENT_BASELINE_GAP": {
        "title": "基线缺少关键结构化字段，影响自动化评估",
        "severity": "medium",
        "category": "configuration",
        "description": "当前基线信息不足以自动重建完整请求或变异场景。",
        "remediation": "补齐静态分析、基线生成或动态捕获阶段的关键字段。",
        "cwe_id": None,
    },
    "SERVER_BEHAVIOR_UNVERIFIED": {
        "title": "服务端行为未验证（低防护告警）",
        "severity": "low",
        "category": "authentication",
        "description": "当前端点在阶段5未获得有效服务端响应，无法确认服务端是否对篡改请求执行了严格校验。",
        "remediation": "恢复目标服务可用性并重跑真实发包评估，重点检查重放、签名/时间戳/nonce 校验是否生效。",
        "cwe_id": None,
    },
    "AUTH_SESSION_BINDING_MISSING": {
        "title": "服务端依赖型动态端点缺少会话绑定",
        "severity": "high",
        "category": "authentication",
        "description": "端点依赖服务端下发动态材料，但跨会话重放仍被接受，存在会话绑定缺失风险。",
        "remediation": "将动态材料与服务端会话（如 PHPSESSID）绑定，并在校验中强制验证绑定关系。",
        "cwe_id": "CWE-384",
    },
    "INTERLAYER_WEAK_EFFECT": {
        "title": "夹层防护效果不足",
        "severity": "high",
        "category": "authentication",
        "description": "关键协议篡改场景未被有效拦截，夹层链路存在可绕过风险。",
        "remediation": "统一校验签名、编码与密文语义的一致性，并确保篡改后在服务端被拒绝。",
        "cwe_id": "CWE-345",
    },
}

TAMPER_FIELD_ALIASES = {
    "timestamp": ["ts", "time", "signTimestamp", "requestTime"],
    "signature": ["sign", "sig", "token", "mac"],
    "nonce": ["nonceStr", "rand", "random"],
    "encryptedData": ["encrypted", "ciphertext", "cipher", "data"],
    "data": ["payload", "encryptedData", "ciphertext"],
    "random": ["rand", "nonce", "nonceStr"],
}

SCENARIO_LAYER_MAP = {
    "baseline_replay": "protocol",
    "crypto_protocol_tamper": "protocol",
    "password_prehash_tamper": "protocol",
    "plaintext_mutation": "business",
    "boundary_anomaly": "protocol",
    "payload_structure_variation": "business",
    "auth_context_variation": "business",
}

FINDING_LAYER_MAP = {
    "cryptography": "protocol",
    "configuration": "protocol",
    "authentication": "business",
    "credential_handling": "business",
}

# Interlayer-specific key scenarios for effectiveness scoring.
INTERLAYER_KEY_SCENARIOS: dict[str, set[str]] = {
    "HEADER_SIGN_LAYER": {
        "crypto_remove_security_field",
        "crypto_signature_corruption",
        "crypto_stale_timestamp",
    },
    "ENCODING_LAYER": {
        "crypto_ciphertext_truncate",
        "payload_type_confusion",
        "payload_missing_field",
    },
}


def first_payload_key(payload: dict[str, Any], preferred: list[str]) -> Optional[str]:
    for key in preferred:
        if key in payload and isinstance(payload[key], str):
            return key
    for key, value in payload.items():
        if isinstance(value, str):
            return key
    return None


def decode_hex_or_utf8(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if value is None:
        return b""
    if not isinstance(value, str):
        return str(value).encode("utf-8")
    value = value.strip()
    if len(value) % 2 == 0 and len(value) > 0:
        try:
            return binascii.unhexlify(value)
        except (binascii.Error, ValueError):
            pass
    return value.encode("utf-8")


def _response_protocol_layer(remote_result: dict[str, Any]) -> str:
    """协议层：仅依据传输状态和 HTTP 状态码分类。"""
    if not isinstance(remote_result, dict):
        return "NOT_ATTEMPTED"
    if not remote_result.get("attempted"):
        return "NOT_ATTEMPTED"
    if remote_result.get("error"):
        return "TRANSPORT_ERROR"
    status_code = remote_result.get("status_code")
    if isinstance(status_code, int):
        if status_code >= 500:
            return "SERVER_5XX"
        if status_code >= 400:
            return "HTTP_4XX"
        if status_code >= 200:
            return "HTTP_2XX"
        return "HTTP_OTHER"
    return "HTTP_UNKNOWN"


def _response_structure_layer(remote_result: dict[str, Any]) -> str:
    """结构层：仅依据响应体可解析性与结构特征分类。"""
    body_preview = str(remote_result.get("body_preview") or "").strip()
    if not body_preview:
        return "BODY_EMPTY"

    try:
        parsed = json.loads(body_preview)
    except Exception:
        parsed = None

    if isinstance(parsed, dict):
        keys = {str(key).lower() for key in parsed.keys()}
        if {"success", "error", "code", "message"} & keys:
            return "JSON_APP_STRUCTURED"
        return "JSON_OBJECT"
    if isinstance(parsed, list):
        return "JSON_ARRAY"

    body_lc = body_preview.lower()
    if "<html" in body_lc or "<body" in body_lc:
        return "HTML_TEXT"
    return "PLAIN_TEXT"


def _response_semantic_layer(remote_result: dict[str, Any]) -> str:
    """语义层：关键词规则匹配，不依赖 AI。"""
    body_preview = str(remote_result.get("body_preview") or "")
    body_lc = body_preview.lower()

    # 常见失败语义优先匹配，避免被“ok/success”噪声误判。
    if "invalid input" in body_lc or "invalid username" in body_lc or "signature mismatch" in body_lc:
        return "APP_INVALID_INPUT"
    if "no data" in body_lc or "missing" in body_lc:
        return "APP_MISSING_DATA"
    if "decrypt" in body_lc or "解密失败" in body_preview or "解密" in body_preview:
        return "APP_DECRYPT_FAIL"

    # JSON 结构化成功语义（泛化规则）
    try:
        parsed = json.loads(body_preview)
    except Exception:
        parsed = None

    if isinstance(parsed, dict):
        success_value = parsed.get("success")
        if success_value is True:
            return "APP_SUCCESS"
        if success_value is False:
            # 很多站点使用 200 + {"success": false} 表示业务拒绝。
            return "APP_REJECTED"

        code_value = parsed.get("code")
        status_value = str(parsed.get("status") or "").strip().lower()
        message_value = str(parsed.get("message") or parsed.get("msg") or "").strip().lower()
        if code_value in {0, "0", 200, "200"}:
            return "APP_SUCCESS"
        if status_value in {"ok", "success", "passed"}:
            return "APP_SUCCESS"
        if message_value and any(token in message_value for token in ["success", "ok", "passed", "成功"]):
            return "APP_SUCCESS"

    # 非 JSON 的简化成功语义兜底
    if "\"success\":true" in body_lc:
        return "APP_SUCCESS"
    if "\"success\":false" in body_lc:
        return "APP_REJECTED"
    if any(token in body_lc for token in ["ok", "passed"]):
        return "APP_SUCCESS"
    return "UNKNOWN"


def build_response_layers(remote_result: dict[str, Any]) -> dict[str, str]:
    """构建三层判定快照，便于解释响应分类来源。"""
    return {
        "protocol": _response_protocol_layer(remote_result),
        "structure": _response_structure_layer(remote_result),
        "semantic": _response_semantic_layer(remote_result),
    }


def classify_response_mode(remote_result: dict[str, Any]) -> str:
    """三层融合：协议层优先，语义层补充，最后协议兜底。"""
    layers = build_response_layers(remote_result)
    protocol = layers.get("protocol")
    semantic = layers.get("semantic")

    if protocol in {"NOT_ATTEMPTED", "TRANSPORT_ERROR", "SERVER_5XX"}:
        return str(protocol)
    if semantic and semantic != "UNKNOWN":
        return str(semantic)
    if protocol == "HTTP_4XX":
        return "HTTP_4XX"
    if protocol == "HTTP_2XX":
        return "HTTP_OK_OTHER"
    return "UNKNOWN"


def _normalize_expected_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _normalize_layer_rule(rule: dict[str, Any]) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for key in ["protocol", "structure", "semantic"]:
        normalized[key] = _normalize_expected_list(rule.get(key))
    return normalized


def _extract_expected_layer_rules(expected: dict[str, Any]) -> list[dict[str, list[str]]]:
    rules: list[dict[str, list[str]]] = []
    single = expected.get("response_layer_expectations")
    if isinstance(single, dict):
        rules.append(_normalize_layer_rule(single))
    any_of = expected.get("response_layer_any_of")
    if isinstance(any_of, list):
        for item in any_of:
            if isinstance(item, dict):
                rules.append(_normalize_layer_rule(item))
    return rules


def _match_layer_rules(actual_layers: dict[str, str], expected_rules: list[dict[str, list[str]]]) -> Optional[bool]:
    if not expected_rules:
        return None
    for rule in expected_rules:
        hit = True
        for key in ["protocol", "structure", "semantic"]:
            expected_values = rule.get(key) or []
            if expected_values and str(actual_layers.get(key) or "") not in expected_values:
                hit = False
                break
        if hit:
            return True
    return False


def evaluate_scenario_expectation(
    scenario: dict[str, Any],
    status: str,
    remote_result: dict[str, Any],
) -> dict[str, Any]:
    """评估场景实际结果是否符合预期。

    口径说明：预期命中仅基于远程响应模式，
    本地失败类型与状态仅作为备注信息，不参与 matched 判定。
    """
    expected = scenario.get("expected_outcome") or {}
    if not isinstance(expected, dict) or not expected:
        return {
            "defined": False,
            "matched": None,
            "waive_penalty": False,
            "remote_mode_match": None,
            "actual_remote_mode": str(remote_result.get("response_mode") or classify_response_mode(remote_result)),
        }

    expected_remote_modes = _normalize_expected_list(expected.get("remote_response_modes"))
    expected_layer_rules = _extract_expected_layer_rules(expected)

    actual_remote_mode = str(remote_result.get("response_mode") or classify_response_mode(remote_result))
    actual_response_layers = remote_result.get("response_layers") or build_response_layers(remote_result)

    remote_mode_match = None
    layer_match = _match_layer_rules(actual_response_layers, expected_layer_rules)
    if expected_remote_modes:
        remote_mode_match = actual_remote_mode in expected_remote_modes

    matched: Optional[bool] = None
    if remote_mode_match is not None:
        matched = bool(remote_mode_match)

    return {
        "defined": True,
        "matched": matched,
        "waive_penalty": bool(expected.get("waive_penalty_on_match", True)),
        "remote_mode_match": remote_mode_match,
        "response_layer_match": layer_match,
        "actual_remote_mode": actual_remote_mode,
        "actual_response_layers": actual_response_layers,
        "expected_remote_modes": expected_remote_modes,
        "expected_layer_rules": expected_layer_rules,
    }


def summarize_response_modes(scenario_results: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for scenario in scenario_results:
        remote = scenario.get("remote_result", {}) or {}
        mode = str(remote.get("response_mode") or classify_response_mode(remote))
        counts[mode] = counts.get(mode, 0) + 1
    top_mode = None
    if counts:
        top_mode = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]
    return {
        "response_mode_counts": counts,
        "top_failure_mode": top_mode,
    }


class LocalFlowExecutor:
    def __init__(self, entry: dict[str, Any]):
        self.entry = copy.deepcopy(entry)
        self.execution_flow = self.entry.get("meta", {}).get("execution_flow", [])
        self.runtime_params = self.entry.get("validation", {}).get("runtime_params", {}) or {}
        self.request_headers = self.entry.get("request", {}).get("headers", {}) or {}
        self.registry = get_registry()

    def execute(
        self,
        payload: dict[str, Any],
        allow_captured_message_fallback: bool = False,
        removed_fields: Optional[set[str]] = None,
    ) -> dict[str, Any]:
        removed_set = {str(item) for item in (removed_fields or set()) if str(item)}
        state: dict[str, Any] = {
            "payload": copy.deepcopy(payload),
            "outputs": {},
            "key": self.runtime_params.get("key"),
            "iv": self.runtime_params.get("iv"),
            "public_key": self.runtime_params.get("public_key"),
            "last_output": None,
            "request_preview": None,
            "removed_fields": removed_set,
            "limitations": [],
            "logs": [],
            "derivation_cache": {},
        }
        for index, step in enumerate(self.execution_flow):
            step_type = str(step.get("step_type", "")).lower()
            try:
                if step_type == "init":
                    state["logs"].append(f"step {index}: init")
                    continue
                if step_type in {"setkey", "setiv", "hardcoded_secret"}:
                    self._apply_static_material(step, state)
                    continue
                if step_type.startswith("derive_"):
                    self._apply_derivation(step, payload, state)
                    continue
                if step_type in {"encrypt", "sign"}:
                    self._execute_crypto_step(step, payload, state, allow_captured_message_fallback)
                    continue
                if step_type == "pack":
                    state["request_preview"] = self._build_request_preview(step, payload, state)
                    continue
                state["limitations"].append(f"未处理的 step_type: {step_type}")
            except Exception as exc:
                return {"success": False, "error": f"步骤 {index} ({step_type}) 执行失败: {exc}", "named_outputs": state["outputs"], "request_preview": state.get("request_preview"), "limitations": state["limitations"], "logs": state["logs"]}
        return {"success": True, "error": None, "named_outputs": state["outputs"], "final_output": state.get("last_output"), "request_preview": state.get("request_preview"), "limitations": state["limitations"], "logs": state["logs"]}

    def _apply_static_material(self, step: dict[str, Any], state: dict[str, Any]) -> None:
        args = step.get("runtime_args", {}) or {}
        algorithm = str(step.get("algorithm", "")).upper()
        if algorithm == "RSA" and args.get("public_key"):
            state["public_key"] = args["public_key"]
            return
        if args.get("key") is not None and state.get("key") is None:
            state["key"] = args["key"]
        if args.get("iv") is not None and state.get("iv") is None:
            state["iv"] = args["iv"]

    def _apply_derivation(self, step: dict[str, Any], payload: dict[str, Any], state: dict[str, Any]) -> None:
        target = str(step.get("step_type", "")).replace("derive_", "")
        derivation = (step.get("runtime_args", {}) or {}).get("derivation")

        if target == "key" and state.get("key") is not None:
            state["logs"].append("derive_key skipped: reuse captured runtime key")
            return
        if target == "iv" and state.get("iv") is not None:
            state["logs"].append("derive_iv skipped: reuse captured runtime iv")
            return

        operation = VariableDerivationOperation()
        context = CryptoContext(plaintext=payload)
        if state.get("key") is not None:
            context.key = state.get("key")
        if state.get("iv") is not None:
            context.iv = state.get("iv")
        context.extra_params.update({"target": target, "derivation": derivation, "base_payload": payload})
        result = operation.execute(context)
        if result.success:
            if target == "key":
                state["key"] = result.context.key
            elif target == "iv":
                state["iv"] = result.context.iv
            return

        # 降级解释器：用于兼容静态分析输出中较复杂的 derivation 节点。
        fallback_value = self._evaluate_dynamic_derivation(derivation, payload, state)
        if fallback_value is None:
            raise ValueError(result.error)
        if target == "key":
            state["key"] = fallback_value
        elif target == "iv":
            state["iv"] = fallback_value
        state["logs"].append(f"derive_{target} fallback evaluator applied")

    def _execute_crypto_step(self, step: dict[str, Any], payload: dict[str, Any], state: dict[str, Any], allow_captured_message_fallback: bool) -> None:
        operation_name = self._map_operation(str(step.get("algorithm", "")), str(step.get("step_type", "")).lower())
        operation_class = self.registry.get_operation(operation_name) if operation_name else None
        if not operation_name or not operation_class:
            raise ValueError(f"无法映射操作 {step.get('algorithm')}:{step.get('step_type')}")
        source_expression = step.get("input_expression") or self._extract_primary_input_expression(step.get("context", ""))
        input_value, input_source = self._resolve_expression(source_expression, payload, state, allow_captured_message_fallback)
        if input_source == "missing" and step.get("input_derivation"):
            input_value = self._evaluate_dynamic_derivation(step.get("input_derivation"), payload, state)
            input_source = "input_derivation"
        source_expression_text = str(source_expression or "").strip()
        preferred_keys = step.get("input_source_keys")
        if (not isinstance(preferred_keys, list) or not preferred_keys) and source_expression_text in {"jsonData", "dataString", "formData", "dataToSend", "dataPacket"}:
            preferred_keys = self._infer_input_keys_from_hints(source_expression_text)

        if (
            isinstance(input_value, str)
            and (source_expression_text.startswith("JSON.stringify(") or source_expression_text in {"jsonData", "dataString", "formData", "dataToSend", "dataPacket"})
            and isinstance(payload, dict)
            and isinstance(preferred_keys, list)
            and preferred_keys
        ):
            ordered_json = self._stringify_with_preferred_order(payload, preferred_keys)
            if ordered_json is not None:
                input_value = ordered_json
                input_source = f"{input_source}:ordered"
        if input_source == "missing":
            raise ValueError(f"缺少结构化输入表达式，无法解析: {source_expression or '[empty]'}")
        context = CryptoContext(plaintext=input_value)
        runtime_args = step.get("runtime_args", {}) or {}
        mode_value = runtime_args.get("mode") or step.get("mode")
        padding_value = runtime_args.get("padding") or step.get("padding")
        input_encoding_value = runtime_args.get("input_encoding") or step.get("input_encoding")
        output_encoding_value = runtime_args.get("output_encoding") or step.get("output_encoding")

        if mode_value not in [None, ""]:
            context.mode = str(mode_value)
        if padding_value not in [None, ""]:
            context.padding = str(padding_value)
        if input_encoding_value not in [None, ""]:
            context.input_encoding = str(input_encoding_value)
        if output_encoding_value not in [None, ""]:
            context.output_encoding = str(output_encoding_value)

        key_encoding_value = runtime_args.get("key_encoding") or step.get("key_encoding")
        iv_encoding_value = runtime_args.get("iv_encoding") or step.get("iv_encoding")
        if key_encoding_value not in [None, ""]:
            context.extra_params["key_encoding"] = str(key_encoding_value)
        if iv_encoding_value not in [None, ""]:
            context.extra_params["iv_encoding"] = str(iv_encoding_value)
        if state.get("key") is not None:
            context.key = state["key"]
        if state.get("iv") is not None:
            context.iv = state["iv"]
        if state.get("public_key"):
            context.extra_params["public_key"] = state["public_key"]
        result = operation_class().execute(context)
        if not result.success:
            raise ValueError(result.error)
        output_variable = step.get("output_variable")
        if output_variable:
            state["outputs"][output_variable] = result.output
        state["last_output"] = result.output

    def _infer_input_keys_from_hints(self, expression_name: str) -> list[str]:
        hints = ((self.entry.get("meta", {}) or {}).get("hints", []) or [])
        pattern = re.compile(r"Inferred Payload Keys for '\s*([^']+)\s*':\s*(\[[^\]]*\])")
        for item in hints:
            hint_text = str(item or "")
            match = pattern.search(hint_text)
            if not match:
                continue
            var_name = str(match.group(1) or "").strip()
            if var_name != expression_name:
                continue
            raw_list = match.group(2)
            try:
                parsed = json.loads(raw_list)
            except Exception:
                continue
            if isinstance(parsed, list) and parsed:
                return [str(v) for v in parsed if str(v)]
        return []

    def _build_request_preview(self, step: dict[str, Any], payload: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        runtime_args = step.get("runtime_args", {}) or {}
        packing_info = runtime_args.get("packing_info", {}) or {}
        packing_type = packing_info.get("type", "unknown")
        resolved_fields: dict[str, Any] = {}
        missing_fields: list[str] = []
        body_text: Optional[str] = None
        body_json: Optional[dict[str, Any]] = None
        optional_fields = {
            str(item)
            for item in (packing_info.get("optional_fields", []) or [])
            if isinstance(item, str) and item.strip()
        }
        unresolved = object()
        field_sources = packing_info.get("field_sources", {}) or {}
        auto_base64_fields: set[str] = set()
        trace = (self.entry.get("validation", {}) or {}).get("trace", []) or []

        def lookup_capture_field(field_name: str) -> Any:
            """Fallback to captured FETCH body value when local material is insufficient."""
            for item in reversed(trace):
                if not isinstance(item, dict) or str(item.get("type")) != "FETCH":
                    continue
                body_json = item.get("body_json")
                if isinstance(body_json, dict) and field_name in body_json:
                    return body_json.get(field_name)
                body_form = item.get("body_form")
                if isinstance(body_form, dict) and field_name in body_form:
                    return body_form.get(field_name)
            return unresolved

        def infer_auto_structure() -> dict[str, str]:
            structure = packing_info.get("structure", {}) or {}
            if isinstance(structure, dict) and structure:
                return structure
            outputs = state.get("outputs", {}) or {}

            # 从 capture 的 FETCH 字段名推断结构，但值仍使用本地重算输出，避免直接回放 capture 值。
            trace = (self.entry.get("validation", {}) or {}).get("trace", []) or []
            fetch_field_names: list[str] = []
            for item in reversed(trace):
                if not isinstance(item, dict) or str(item.get("type")) != "FETCH":
                    continue
                body_form = item.get("body_form")
                if isinstance(body_form, dict) and body_form:
                    fetch_field_names = [str(k) for k in body_form.keys()]
                    break
            if fetch_field_names and outputs:
                preferred_output_names = ["encryptedData", "encrypted", "ciphertext", "data", "random", "signature"]
                output_name = None
                for name in preferred_output_names:
                    if name in outputs:
                        output_name = name
                        break
                if output_name is None and len(outputs) == 1:
                    output_name = str(next(iter(outputs.keys())))
                if output_name:
                    inferred: dict[str, str] = {}
                    captured_fetch_body_form: dict[str, Any] = {}
                    for item in reversed(trace):
                        if not isinstance(item, dict) or str(item.get("type")) != "FETCH":
                            continue
                        if isinstance(item.get("body_form"), dict):
                            captured_fetch_body_form = item.get("body_form") or {}
                        break
                    for field_name in fetch_field_names:
                        if field_name in outputs:
                            inferred[field_name] = field_name
                        elif field_name in {"encryptedData", "encrypted", "ciphertext", "data", "random"}:
                            inferred[field_name] = output_name
                        elif field_name in {"iv", "nonce", "timestamp", "signature", "sign", "token"}:
                            inferred[field_name] = field_name

                        sample_val = captured_fetch_body_form.get(field_name)
                        if field_name == "iv" and isinstance(sample_val, str):
                            sample_text = sample_val.strip()
                            is_hex_like = bool(re.fullmatch(r"[0-9a-fA-F]+", sample_text)) and len(sample_text) % 2 == 0
                            if sample_text and ("=" in sample_text or "+" in sample_text or "/" in sample_text) and not is_hex_like:
                                auto_base64_fields.add("iv")
                    if inferred:
                        return inferred

            preferred_names = ["encryptedData", "encrypted", "ciphertext", "data", "random"]
            for name in preferred_names:
                if name in outputs:
                    return {name: name}
            if len(outputs) == 1:
                only_name = next(iter(outputs.keys()))
                return {str(only_name): str(only_name)}
            return {}

        def is_optional_field(field_name: str) -> bool:
            if field_name in optional_fields:
                return True
            source_meta = field_sources.get(field_name, {}) if isinstance(field_sources, dict) else {}
            return isinstance(source_meta, dict) and bool(source_meta.get("optional"))

        def resolve_value(field_name: str, name: str) -> Any:
            field_sources = packing_info.get("field_sources", {}) or {}
            field_source = field_sources.get(field_name, {}) if isinstance(field_sources, dict) else {}
            derivations = packing_info.get("value_derivations", {}) or {}

            if name in state["outputs"]:
                return state["outputs"][name]
            if name in payload:
                return payload[name]

            removed_fields = state.get("removed_fields", set())
            is_removed = str(field_name) in removed_fields or str(name) in removed_fields
            if (not is_removed) and name in self.runtime_params:
                val = self.runtime_params[name]
                if field_name in auto_base64_fields and str(field_name) == "iv" and isinstance(val, str):
                    text = val.strip()
                    if re.fullmatch(r"[0-9a-fA-F]+", text or "") and len(text) % 2 == 0:
                        try:
                            return base64.b64encode(binascii.unhexlify(text)).decode("ascii")
                        except Exception:
                            return val
                return val
            alias_map = {
                "encryptedTimestamp": ["random"],
                "random": ["encryptedTimestamp"],
                "encrypted": ["encryptedData"],
                "encryptedData": ["encrypted"],
            }
            for alias in alias_map.get(name, []):
                if alias in state["outputs"]:
                    return state["outputs"][alias]
                if alias in payload:
                    return payload[alias]
                if (not is_removed) and alias in self.runtime_params:
                    return self.runtime_params[alias]

            if isinstance(field_source, dict):
                bridge_name = str(field_source.get("bridge_from_output") or "")
                if bridge_name and bridge_name in state["outputs"]:
                    bridged = state["outputs"][bridge_name]
                    bridge_transform = str(field_source.get("bridge_transform") or "").lower()
                    if bridge_transform == "hex" and isinstance(bridged, str):
                        try:
                            return base64.b64decode(bridged).hex()
                        except Exception:
                            return bridged
                    return bridged

            captured_value = lookup_capture_field(field_name)
            if captured_value is not unresolved:
                return captured_value
            return unresolved

        def to_transport_value(value: Any) -> Any:
            # JS URLSearchParams serializes null as "null"; keep JSON null as None.
            return "null" if value is None else value

        if packing_type == "json":
            structure = infer_auto_structure()
            body_json = {}
            for field_name, source_name in structure.items():
                value = resolve_value(str(field_name), str(source_name))
                if value is unresolved:
                    if not is_optional_field(str(field_name)):
                        missing_fields.append(f"{field_name} <- {source_name}")
                    continue
                body_json[field_name] = value
                resolved_fields[field_name] = value
            if not missing_fields:
                body_text = json.dumps(body_json, ensure_ascii=False)
        elif packing_type == "url_search_params":
            structure = infer_auto_structure()
            params: dict[str, Any] = {}
            for field_name, source_name in structure.items():
                value = resolve_value(str(field_name), str(source_name))
                if value is unresolved:
                    if not is_optional_field(str(field_name)):
                        missing_fields.append(f"{field_name} <- {source_name}")
                    continue
                wire_value = to_transport_value(value)
                params[field_name] = wire_value
                resolved_fields[field_name] = wire_value
            if not missing_fields:
                body_text = urllib.parse.urlencode(params)
        elif packing_type == "template":
            template = str(packing_info.get("template", ""))
            insertions = packing_info.get("insertions", []) or []
            body_text = template
            for insertion in insertions:
                variable = insertion.get("variable")
                value = resolve_value(str(variable), str(variable))
                if value is unresolved:
                    missing_fields.append(str(variable))
                    continue
                wire_value = to_transport_value(value)
                body_text = body_text.replace(f"{{{{{variable}}}}}", urllib.parse.quote_plus(str(wire_value)))
                resolved_fields[str(variable)] = wire_value
            if missing_fields:
                body_text = None
        else:
            missing_fields.append(f"不支持的 packing type: {packing_type}")

        preview_headers = copy.deepcopy(self.request_headers)
        request_url = str((self.entry.get("meta", {}) or {}).get("url") or "")
        signature_value = None
        for key_name in ["signature", "sign", "sig", "token", "mac", "hmac"]:
            if key_name in state.get("outputs", {}):
                signature_value = state["outputs"].get(key_name)
                if signature_value is not None:
                    break

        def infer_signature_placement() -> str:
            # 1) 优先读取 sign 步骤显式 placement。
            for flow_step in self.execution_flow:
                if str(flow_step.get("step_type", "")).lower() != "sign":
                    continue
                flow_args = flow_step.get("runtime_args", {}) or {}
                explicit = str(flow_args.get("placement") or flow_args.get("signature_placement") or "").strip().lower()
                if explicit in {"header", "body", "query"}:
                    return explicit

            # 2) 若原请求头含签名头，判定为 header。
            if isinstance(preview_headers, dict):
                for hk in list(preview_headers.keys()):
                    if str(hk).strip().lower() in {"x-signature", "signature", "x-sign"}:
                        return "header"

            # 3) 若 capture 的 FETCH URL 含 signature 参数，判定为 query。
            trace_items = (self.entry.get("validation", {}) or {}).get("trace", []) or []
            for item in reversed(trace_items):
                if not isinstance(item, dict) or str(item.get("type")) != "FETCH":
                    continue
                fetch_url = str(item.get("url") or "")
                if "signature=" in fetch_url or "sig=" in fetch_url:
                    return "query"

            # 4) 若结构化打包包含 signature 字段，判定为 body。
            structure = packing_info.get("structure", {}) or {}
            if isinstance(structure, dict):
                for field_name in structure.keys():
                    if str(field_name).strip().lower() in {"signature", "sign", "sig", "token", "mac", "hmac"}:
                        return "body"

            # 5) 默认 body。
            return "body"

        if signature_value is not None:
            placement = infer_signature_placement()
            signature_text = str(signature_value)
            if placement == "header" and isinstance(preview_headers, dict):
                injected = False
                for hk in list(preview_headers.keys()):
                    if str(hk).strip().lower() in {"x-signature", "signature", "x-sign"}:
                        preview_headers[hk] = signature_text
                        injected = True
                if not injected:
                    preview_headers["X-Signature"] = signature_text
            elif placement == "query":
                parsed = urllib.parse.urlparse(request_url)
                query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                query_pairs.append(("signature", signature_text))
                request_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query_pairs)))
            else:
                # 若 pack 阶段已结构化给出 signature，则���持其值，不用旧输出覆盖。
                existing_sig = resolved_fields.get("signature")
                if existing_sig not in (None, ""):
                    signature_text = str(existing_sig)
                if packing_type == "json" and isinstance(body_json, dict):
                    body_json["signature"] = signature_text
                    resolved_fields["signature"] = signature_text
                    body_text = json.dumps(body_json, ensure_ascii=False)
                elif packing_type == "url_search_params":
                    current_pairs = urllib.parse.parse_qsl(body_text or "", keep_blank_values=True) if isinstance(body_text, str) else []
                    if not any(str(k) == "signature" for k, _ in current_pairs):
                        current_pairs.append(("signature", signature_text))
                    body_text = urllib.parse.urlencode(current_pairs)
                    resolved_fields["signature"] = signature_text
                elif packing_type == "template" and isinstance(body_text, str):
                    if "signature=" not in body_text:
                        sep = "&" if body_text else ""
                        body_text = f"{body_text}{sep}signature={urllib.parse.quote_plus(signature_text)}"
                    resolved_fields["signature"] = signature_text

        return {
            "body_type": packing_type,
            "headers": preview_headers,
            "url_override": request_url,
            "resolved_fields": resolved_fields,
            "missing_fields": missing_fields,
            "body_text": body_text,
            "body_json": body_json,
            "send_ready": not missing_fields and (body_text is not None or body_json is not None),
        }

    def _evaluate_dynamic_derivation(self, derivation: dict[str, Any], payload: dict[str, Any], state: dict[str, Any]) -> Any:
        if not isinstance(derivation, dict):
            return derivation
        node_type = derivation.get("type")
        if node_type == "source":
            key_name = derivation.get("value")
            if key_name in payload:
                return payload.get(key_name)
            if key_name in self.runtime_params:
                return self.runtime_params.get(key_name)
            if key_name in state.get("outputs", {}):
                return state["outputs"].get(key_name)
            return None
        if node_type == "literal":
            return derivation.get("value")
        if node_type == "identifier":
            name = derivation.get("name")
            if name in state.get("outputs", {}):
                return state["outputs"].get(name)
            if name in payload:
                return payload.get(name)
            if name in self.runtime_params:
                return self.runtime_params.get(name)
            if name == "timestamp":
                return int(time.time())
            return name
        if node_type == "binary_op":
            left = self._evaluate_dynamic_derivation(derivation.get("left"), payload, state)
            right = self._evaluate_dynamic_derivation(derivation.get("right"), payload, state)
            if derivation.get("op") == "+":
                return f"{'' if left is None else left}{'' if right is None else right}"
            return None
        if node_type == "logical_op":
            left = self._evaluate_dynamic_derivation(derivation.get("left"), payload, state)
            right = self._evaluate_dynamic_derivation(derivation.get("right"), payload, state)
            op = str(derivation.get("op") or "")
            if op == "||":
                return left if left not in (None, "", False) else right
            if op == "&&":
                return right if left not in (None, "", False) else left
            return left if left is not None else right
        if node_type == "op":
            input_val = self._evaluate_dynamic_derivation(derivation.get("input"), payload, state)
            args = [self._evaluate_dynamic_derivation(arg, payload, state) for arg in derivation.get("args", [])]
            op_name = derivation.get("op")
            if op_name == "JSON.stringify":
                return safe_json_dumps(input_val)
            if op_name in {"Base64.parse", "Utf8.parse"}:
                return input_val
            if op_name == "toString":
                if isinstance(input_val, float) and args and args[0] == 36:
                    return f"0.{format(int(abs(input_val) * 10**16), 'x')}"
                return str(input_val)
            if op_name == "substring":
                start = int(args[0]) if len(args) > 0 and args[0] is not None else 0
                end = int(args[1]) if len(args) > 1 and args[1] is not None else None
                return str(input_val)[start:end]
            if op_name == "slice":
                start = int(args[0]) if len(args) > 0 and args[0] is not None else 0
                end = int(args[1]) if len(args) > 1 and args[1] is not None else None
                return str(input_val)[start:end]
            if op_name == "padEnd":
                width = int(args[0]) if len(args) > 0 and args[0] is not None else len(str(input_val))
                fillchar = str(args[1]) if len(args) > 1 and args[1] is not None else " "
                text = str(input_val)
                if len(text) >= width:
                    return text
                return text + (fillchar * (width - len(text)))[: width - len(text)]
            return input_val
        if node_type == "call":
            callee = derivation.get("callee")
            cache = state.setdefault("derivation_cache", {}) if isinstance(state, dict) else {}
            cache_key = str(derivation.get("expression") or f"call:{callee}:{json.dumps(derivation, ensure_ascii=False, sort_keys=True)}")
            if cache_key in cache:
                return cache.get(cache_key)
            if callee in {"CryptoJS.HmacSHA256", "HmacSHA256"}:
                args = derivation.get("args", []) or []
                message = self._evaluate_dynamic_derivation(args[0], payload, state) if len(args) > 0 else ""
                secret = self._evaluate_dynamic_derivation(args[1], payload, state) if len(args) > 1 else ""
                msg_bytes = str("" if message is None else message).encode("utf-8")
                key_bytes = str("" if secret is None else secret).encode("utf-8")
                value = hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()
                cache[cache_key] = value
                return value
            if callee == "Math.random":
                value = random.random()
                cache[cache_key] = value
                return value
            if callee == "Math.floor":
                expression = derivation.get("expression", "")
                if "Date.now() / 1000" in expression:
                    value = int(time.time())
                    cache[cache_key] = value
                    return value
                value = int(time.time())
                cache[cache_key] = value
                return value
            if callee == "CryptoJS.lib.WordArray.random":
                size = 16
                args = derivation.get("args", []) or []
                if args:
                    parsed_size = self._evaluate_dynamic_derivation(args[0], payload, state)
                    if isinstance(parsed_size, (int, float)):
                        size = max(1, int(parsed_size))
                value = secrets.token_hex(size)
                cache[cache_key] = value
                return value
            value = derivation.get("expression")
            cache[cache_key] = value
            return value
        if node_type == "member_access":
            input_val = self._evaluate_dynamic_derivation(derivation.get("input"), payload, state)
            if isinstance(input_val, dict):
                return input_val.get(derivation.get("property"))
            return None
        return None

    def _extract_primary_input_expression(self, context_text: str) -> Optional[str]:
        text = str(context_text or "").strip()
        if not text:
            return None
        open_index = text.find("(")
        if open_index == -1:
            return None
        depth = 0
        argument_chars: list[str] = []
        for char in text[open_index + 1 :]:
            if char == "(":
                depth += 1
                argument_chars.append(char)
                continue
            if char == ")":
                if depth == 0:
                    break
                depth -= 1
                argument_chars.append(char)
                continue
            if char == "," and depth == 0:
                break
            argument_chars.append(char)
        expression = "".join(argument_chars).strip()
        return expression or None

    def _resolve_expression(self, expression: Optional[str], payload: dict[str, Any], state: dict[str, Any], allow_captured_message_fallback: bool) -> tuple[Any, str]:
        if not expression:
            if allow_captured_message_fallback and self.runtime_params.get("message") is not None:
                return self.runtime_params["message"], "captured_message_fallback"
            return None, "missing"
        expr = expression.strip()
        if expr in state["outputs"]:
            return state["outputs"][expr], f"named_output:{expr}"
        if expr in payload:
            return payload[expr], f"payload:{expr}"
        if expr in self.runtime_params:
            return self.runtime_params[expr], f"runtime:{expr}"
        if expr in {"jsonData", "dataString", "formData", "dataToSend"}:
            # baseline_replay 场景优先复用 capture 的 message，避免字段顺序差异导致密文偏移。
            if allow_captured_message_fallback and self.runtime_params.get("message") is not None:
                return self.runtime_params["message"], "captured_message_fallback"
            return safe_json_dumps(payload), f"synthetic_json:{expr}"
        if expr in {"dataToSign", "signData", "signatureInput"}:
            if self.runtime_params.get("message") is not None:
                return self.runtime_params["message"], "runtime_message"
            if allow_captured_message_fallback and self.runtime_params.get("message") is not None:
                return self.runtime_params["message"], "captured_message_fallback"
            return safe_json_dumps(payload), f"synthetic_sign_input:{expr}"
        if expr.startswith("JSON.stringify(") and expr.endswith(")"):
            inner = expr[len("JSON.stringify(") : -1].strip()
            value, source = self._resolve_expression(inner, payload, state, allow_captured_message_fallback)
            if source == "missing":
                return None, source
            if isinstance(value, (dict, list)):
                return safe_json_dumps(value), f"json_stringify:{source}"
            return safe_json_dumps(value) if not isinstance(value, str) else value, f"json_stringify:{source}"
        if expr.startswith("CryptoJS.enc.Base64.stringify(") and expr.endswith(")"):
            inner = expr[len("CryptoJS.enc.Base64.stringify(") : -1].strip()
            value, source = self._resolve_expression(inner, payload, state, allow_captured_message_fallback)
            if source == "missing":
                return None, source
            encoded = base64.b64encode(decode_hex_or_utf8(value)).decode("ascii")
            return encoded, f"cryptojs_base64_stringify:{source}"
        if expr.endswith(".toString(CryptoJS.enc.Base64)"):
            base_name = expr.split(".", 1)[0]
            raw_value, source = self._resolve_expression(base_name, payload, state, allow_captured_message_fallback)
            if source == "missing":
                return None, source
            encoded = base64.b64encode(decode_hex_or_utf8(raw_value)).decode("ascii")
            return encoded, f"base64:{source}"
        if expr.endswith(".toString()"):
            base_name = expr.split(".", 1)[0]
            raw_value, source = self._resolve_expression(base_name, payload, state, allow_captured_message_fallback)
            if source == "missing":
                return None, source
            return str(raw_value), f"stringify:{source}"
        if expr in {"key", "iv", "publicKey"}:
            mapping = {"key": state.get("key"), "iv": state.get("iv"), "publicKey": state.get("public_key")}
            value = mapping.get(expr)
            if value is not None:
                return value, f"state:{expr}"

        # 常见变量别名：兼容 aesKey / aesIv 等命名。
        expr_lc = expr.lower()
        key_aliases = {"aeskey", "secretkey", "sessionkey", "symmetrickey"}
        iv_aliases = {"aesiv", "sessioniv", "vectoriv", "initvector"}
        if expr_lc in key_aliases and state.get("key") is not None:
            return state.get("key"), f"state_alias:{expr}=>key"
        if expr_lc in iv_aliases and state.get("iv") is not None:
            return state.get("iv"), f"state_alias:{expr}=>iv"

        if allow_captured_message_fallback and self.runtime_params.get("message") is not None:
            return self.runtime_params["message"], "captured_message_fallback"
        return None, "missing"

    def _stringify_with_preferred_order(self, payload: dict[str, Any], preferred_keys: list[Any]) -> Optional[str]:
        if not isinstance(payload, dict):
            return None
        ordered: dict[str, Any] = {}
        seen: set[str] = set()
        for key in preferred_keys:
            key_text = str(key)
            if key_text in payload and key_text not in seen:
                ordered[key_text] = payload[key_text]
                seen.add(key_text)
        for key, value in payload.items():
            if key not in seen:
                ordered[key] = value
        return safe_json_dumps(ordered)

    def _map_operation(self, algorithm: str, step_type: str) -> Optional[str]:
        algo = algorithm.upper()
        mapping = {
            "AES": {"encrypt": "aes_encrypt"},
            "DES": {"encrypt": "des_encrypt"},
            "RSA": {"encrypt": "rsa_encrypt"},
            "HMACSHA256": {"sign": "hmac_sha256"},
            "HMACSHA256()": {"sign": "hmac_sha256"},
            "MD5": {"sign": "md5", "encrypt": "md5"},
            "SHA256": {"sign": "sha256", "encrypt": "sha256"},
        }
        return mapping.get(algo, {}).get(step_type)


class BaselineAssessmentEngine:
    def _detect_signature_bypass_from_scenarios(self, scenario_results: list[dict[str, Any]]) -> dict[str, Any]:
        """通过协议篡改场景结果识别签名绕过风险。"""
        candidate_ids = {"crypto_remove_security_field", "crypto_signature_corruption"}
        for item in scenario_results:
            scenario_id = str(item.get("scenario_id") or "")
            if scenario_id not in candidate_ids:
                continue
            expectation = item.get("expectation", {}) if isinstance(item.get("expectation"), dict) else {}
            remote_result = item.get("remote_result", {}) if isinstance(item.get("remote_result"), dict) else {}
            if not bool(expectation.get("defined")):
                continue
            if expectation.get("matched") is False and bool(remote_result.get("attempted")):
                return {
                    "triggered": True,
                    "evidence": f"scenario:{scenario_id}|mode:{expectation.get('actual_remote_mode')}",
                }
        return {"triggered": False, "evidence": None}
    def __init__(
        self,
        output_dir: Path,
        timeout: float = 10.0,
        scoring_profile: str = "default",
        scoring_config_path: Path = DEFAULT_SCORING_CONFIG,
        capture_page_url: Optional[str] = None,
        strict_baseline_replay: bool = False,
        enhanced_fuzz_mode: bool = False,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.scoring_config_path = Path(scoring_config_path)
        self.scoring_profile_name = scoring_profile
        self.scoring_profile = self._load_scoring_profile(self.scoring_config_path, scoring_profile)
        self.capture_page_url = (capture_page_url or "").strip() or None
        self.strict_baseline_replay = bool(strict_baseline_replay)
        self.enhanced_fuzz_mode = bool(enhanced_fuzz_mode)
        self._layer2_sample_pool_map: Optional[dict[str, dict[str, Any]]] = None
        self._layer2_sample_pool_mtime: Optional[float] = None

    def _layer2_pool_path(self) -> Path:
        return BASE_DIR / "runtime" / "api_lab_builder" / "layer2_sample_pool.yaml"

    def _normalize_layer2_stack_token(self, algorithm_stack: Any) -> str:
        text = str(algorithm_stack or "").strip().upper()
        if not text:
            return ""
        if "HMAC" in text:
            return "hmac"
        if "AES" in text and "RSA" in text:
            return "aesrsa"
        if "RSA" in text:
            return "rsa"
        if "AES" in text:
            return "aes"
        if "DES" in text:
            return "des"
        return re.sub(r"[^a-z0-9]+", "", text.lower())

    def _load_layer2_sample_pool_map(self) -> dict[str, dict[str, Any]]:
        pool_path = self._layer2_pool_path()
        if not pool_path.exists():
            return {}

        mtime = pool_path.stat().st_mtime
        if self._layer2_sample_pool_map is not None and self._layer2_sample_pool_mtime == mtime:
            return self._layer2_sample_pool_map

        mapping: dict[str, dict[str, Any]] = {}
        try:
            raw = load_yaml_file(pool_path)
        except Exception:
            self._layer2_sample_pool_map = {}
            self._layer2_sample_pool_mtime = mtime
            return {}

        rows = raw if isinstance(raw, list) else []
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            token = self._normalize_layer2_stack_token(row.get("algorithm_stack"))
            if not token:
                continue
            grouped.setdefault(token, []).append(row)

        for token, items in grouped.items():
            for index, row in enumerate(items, start=1):
                endpoint_id = f"layer2_{token}_{index:04d}"
                mapping[endpoint_id] = {
                    "interlayers": row.get("interlayers", []) if isinstance(row.get("interlayers"), list) else [],
                    "risk_tags": row.get("risk_tags", []) if isinstance(row.get("risk_tags"), list) else [],
                    "algo_params": row.get("algo_params", {}) if isinstance(row.get("algo_params"), dict) else {},
                    "signature_strategy": row.get("signature_strategy", {}) if isinstance(row.get("signature_strategy"), dict) else {},
                }

        self._layer2_sample_pool_map = mapping
        self._layer2_sample_pool_mtime = mtime
        return mapping

    def _load_scoring_profile(self, config_path: Path, profile_name: str) -> dict[str, Any]:
        if not config_path.exists():
            raise FileNotFoundError(f"未找到评分配置文件: {config_path}")
        raw = load_yaml_file(config_path) or {}
        profiles = raw.get("profiles", {}) or {}
        active = profile_name or raw.get("active_profile") or "default"
        profile = profiles.get(active)
        if not isinstance(profile, dict):
            available = ", ".join(sorted(profiles.keys()))
            raise ValueError(f"未找到评分 profile: {active}。可用 profile: {available}")
        normalized = copy.deepcopy(profile)
        normalized.setdefault("description", "未提供说明")
        normalized.setdefault("base_score", 100.0)
        normalized.setdefault("risk_thresholds", {"low": 80.0, "medium": 60.0, "high": 40.0})
        normalized.setdefault("severity_penalties", {"critical": 30.0, "high": 20.0, "medium": 10.0, "low": 5.0, "info": 0.0})
        normalized.setdefault("finding_category_multipliers", {"default": 1.0})
        normalized.setdefault("scenario_status_penalties", {"LOCAL_FAILED": 0.0, "SKIPPED": 0.0, "LOCAL_OK": 0.0, "REMOTE_SENT": 0.0})
        normalized.setdefault("scenario_category_multipliers", {"default": 1.0})
        normalized.setdefault("expectation_mismatch_penalties", {"default": 2.0, "baseline_replay": 8.0})
        normalized.setdefault("baseline_gap_penalty", {"per_gap": 3.0, "max_total": 15.0})
        normalized.setdefault(
            "interlayer_scoring",
            {
                "state_multipliers": {
                    "no_interlayer": 1.0,
                    "interlayer_effective": 1.0,
                    "interlayer_invalid": 1.25,
                },
                "endpoint_penalties": {
                    "no_interlayer": 0.0,
                    "interlayer_effective": 0.0,
                    "interlayer_invalid": 2.0,
                },
            },
        )
        normalized["profile_name"] = active
        normalized["config_file"] = str(config_path)
        return normalized

    def _current_scoring_summary(self) -> dict[str, Any]:
        return {
            "profile": self.scoring_profile.get("profile_name"),
            "description": self.scoring_profile.get("description"),
            "config_file": self.scoring_profile.get("config_file"),
            "base_score": self.scoring_profile.get("base_score"),
            "risk_thresholds": copy.deepcopy(self.scoring_profile.get("risk_thresholds", {})),
            "severity_penalties": copy.deepcopy(self.scoring_profile.get("severity_penalties", {})),
            "finding_category_multipliers": copy.deepcopy(self.scoring_profile.get("finding_category_multipliers", {})),
            "scenario_status_penalties": copy.deepcopy(self.scoring_profile.get("scenario_status_penalties", {})),
            "scenario_category_multipliers": copy.deepcopy(self.scoring_profile.get("scenario_category_multipliers", {})),
            "expectation_mismatch_penalties": copy.deepcopy(self.scoring_profile.get("expectation_mismatch_penalties", {})),
            "baseline_gap_penalty": copy.deepcopy(self.scoring_profile.get("baseline_gap_penalty", {})),
            "interlayer_scoring": copy.deepcopy(self.scoring_profile.get("interlayer_scoring", {})),
            "layer_score_weights": copy.deepcopy(self.scoring_profile.get("layer_score_weights", {"protocol": 0.5, "business": 0.5})),
        }

    def _lookup_weight(self, mapping: dict[str, Any], key: str, default: float = 1.0) -> float:
        if not isinstance(mapping, dict):
            return float(default)
        if key in mapping:
            return float(mapping[key])
        return float(mapping.get("default", default))

    def _is_password_prehash_path(self, entry: dict[str, Any], static_endpoint_info: dict[str, Any]) -> bool:
        """判断当前端点是否属于 PasswordPreHash 特例路径。"""
        operations = (static_endpoint_info or {}).get("operations", []) or []
        for op in operations:
            for detail in op.get("details", []) or []:
                if str(detail.get("scenario", "")).strip() == "PasswordPreHash":
                    return True

        # 兜底：如果静态 map 不完整，尝试从基线执行流识别
        execution_flow = ((entry.get("meta", {}) or {}).get("execution_flow", []) or [])
        for step in execution_flow:
            args = step.get("runtime_args", {}) or {}
            if str(args.get("scenario", "")).strip() == "PasswordPreHash":
                return True
        return False

    def assess(
        self,
        baseline_path: Path,
        static_analysis_path: Optional[Path] = None,
        endpoint_id: Optional[str] = None,
        include_unverified: bool = False,
    ) -> dict[str, Any]:
        baseline_data = load_json_file(baseline_path)
        if not isinstance(baseline_data, list):
            raise ValueError("基线文件格式错误：预期为列表")
        static_data = self._load_static_analysis(baseline_data, static_analysis_path)
        endpoint_map = (static_data or {}).get("endpoint_crypto_map", {})
        verified_entries = []
        skipped_entries = []
        for entry in baseline_data:
            current_id = entry.get("meta", {}).get("id")
            if endpoint_id and current_id != endpoint_id:
                continue
            endpoint_url = entry.get("meta", {}).get("url", "")
            static_endpoint_info = endpoint_map.get(endpoint_url, {}) if isinstance(endpoint_map, dict) else {}
            if entry.get("validation", {}).get("verified"):
                verified_entries.append(entry)
            elif self._is_password_prehash_path(entry, static_endpoint_info):
                # 特例路径允许跳过 handler 验证门，直接做认证抗性评估
                verified_entries.append(entry)
            elif include_unverified and entry.get("validation", {}).get("captured_ciphertext"):
                # 诊断模式：允许纳入有 capture 但未通过 phase4 的端点，用于定位阶段性问题。
                verified_entries.append(entry)
            else:
                skipped_entries.append({"endpoint_id": current_id, "reason": "validation.verified != true"})
        assessments = []
        gap_summary = []
        scenario_total = 0
        findings_total = 0
        server_unverified_endpoints = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        with Progress() as progress:
            task = progress.add_task("评估端点中...", total=len(verified_entries))
            for entry in verified_entries:
                assessment = self._assess_entry(entry, baseline_path, endpoint_map)
                assessments.append(assessment)
                scenario_total += len(assessment.get("scenario_results", []))
                findings_total += len(assessment.get("findings", []))
                if not (assessment.get("server_verification", {}) or {}).get("verified", False):
                    server_unverified_endpoints += 1
                for finding in assessment.get("findings", []):
                    severity = finding.get("severity", "info")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                gap_summary.extend(assessment.get("baseline_gaps", []))
                progress.advance(task)
        overall_score = sum(item.get("security_score", 0.0) for item in assessments) / len(assessments) if assessments else 0.0
        protocol_avg = sum(float(item.get("protocol_score", 0.0)) for item in assessments) / len(assessments) if assessments else 0.0
        business_avg = sum(float(item.get("business_score", 0.0)) for item in assessments) / len(assessments) if assessments else 0.0
        remote_summary = self._summarize_remote_execution([
            scenario
            for assessment in assessments
            for scenario in (assessment.get("scenario_results", []) or [])
        ])
        global_error_clusters = self._summarize_error_clusters(assessments)
        return {
            "report_id": f"ASM-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "generated_at": utc_now(),
            "source": {
                "baseline_file": str(baseline_path),
                "static_analysis_file": str(static_analysis_path or "") if static_analysis_path else self._infer_static_path_from_baselines(baseline_data),
                "send_requests": True,
                "dynamic_endpoint_strategy": "server_dependent_per_scenario_else_once_per_endpoint",
                "capture_page_url": self.capture_page_url,
                "timeout_seconds": self.timeout,
                "fuzz_mode": "enhanced" if self.enhanced_fuzz_mode else "standard",
                "scoring_profile": self.scoring_profile_name,
                "scoring_config_file": str(self.scoring_config_path),
            },
            "scoring": self._current_scoring_summary(),
            "summary": {
                "baseline_entries_total": len(baseline_data),
                "verified_entries_total": len(verified_entries),
                "assessed_endpoints": len(assessments),
                "skipped_entries": len(skipped_entries),
                "scenario_results_total": scenario_total,
                "findings_total": findings_total,
                "by_severity": severity_counts,
                "overall_score": round(overall_score, 2),
                "protocol_score": round(protocol_avg, 2),
                "business_score": round(business_avg, 2),
                "scoring_profile": self.scoring_profile_name,
                "remote_attempted": remote_summary.get("attempted", 0),
                "remote_responded": remote_summary.get("responded", 0),
                "remote_errors": remote_summary.get("errors", 0),
                "server_unverified_endpoints": server_unverified_endpoints,
            },
            "remote_execution": remote_summary,
            "error_clusters": global_error_clusters,
            "skipped_entries": skipped_entries,
            "baseline_gap_summary": gap_summary,
            "assessments": assessments,
        }

    def _summarize_error_clusters(self, assessments: list[dict[str, Any]]) -> dict[str, Any]:
        mode_counts: dict[str, int] = {}
        endpoint_top_modes: dict[str, str] = {}
        for item in assessments:
            portrait = item.get("error_portrait", {}) or {}
            endpoint_id = str(item.get("endpoint_id") or "unknown")
            top = portrait.get("top_failure_mode")
            if top:
                endpoint_top_modes[endpoint_id] = top
            for mode, count in (portrait.get("response_mode_counts", {}) or {}).items():
                mode_counts[mode] = mode_counts.get(mode, 0) + int(count)
        sorted_modes = sorted(mode_counts.items(), key=lambda kv: (-kv[1], kv[0]))
        return {
            "global_mode_counts": {k: v for k, v in sorted_modes},
            "endpoint_top_modes": endpoint_top_modes,
        }

    def save_report(self, report: dict[str, Any], filename: Optional[str] = None) -> Path:
        if not filename:
            filename = f"assessment_{report.get('report_id', utc_now().replace(':', '').replace('-', ''))}.json"
        output_path = self.output_dir / filename
        save_json_file(output_path, report)
        return output_path

    def _load_static_analysis(self, baseline_data: list[dict[str, Any]], static_analysis_path: Optional[Path]) -> Optional[dict[str, Any]]:
        if static_analysis_path:
            if not static_analysis_path.exists():
                raise FileNotFoundError(f"静态分析文件不存在: {static_analysis_path}")
            data = load_json_file(static_analysis_path)
            return data if isinstance(data, dict) else None

        inferred_path = self._infer_static_path_from_baselines(baseline_data)
        if inferred_path:
            candidate = Path(inferred_path)
            if candidate.exists():
                data = load_json_file(candidate)
                return data if isinstance(data, dict) else None

        latest = latest_matching_file(DEFAULT_STATIC_ANALYSIS_DIR, "static_analysis_*.json")
        if latest and latest.exists():
            data = load_json_file(latest)
            return data if isinstance(data, dict) else None
        return None

    def _infer_static_path_from_baselines(self, baseline_data: list[dict[str, Any]]) -> Optional[str]:
        for entry in baseline_data:
            source_name = entry.get("meta", {}).get("source_analysis_file")
            if source_name:
                return str(DEFAULT_STATIC_ANALYSIS_DIR / source_name)
        return None

    def _make_finding(self, finding_id: str, evidence: str) -> dict[str, Any]:
        template = FINDING_LIBRARY[finding_id]
        return {
            "id": finding_id,
            "title": template["title"],
            "severity": template["severity"],
            "category": template["category"],
            "description": template["description"],
            "evidence": evidence,
            "remediation": template["remediation"],
            "cwe_id": template["cwe_id"],
        }

    def _detect_baseline_gaps(self, entry: dict[str, Any]) -> list[dict[str, Any]]:
        meta = entry.get("meta", {})
        validation = entry.get("validation", {})
        payload = entry.get("request", {}).get("payload", {}) or {}
        execution_flow = meta.get("execution_flow", []) or []
        runtime_params = validation.get("runtime_params", {}) or {}
        gaps: list[dict[str, Any]] = []

        def add_gap(code: str, field_name: str, reason: str, phase: str, suggestion: str) -> None:
            gaps.append({"code": code, "field": field_name, "reason": reason, "required_phase": phase, "adjustment": suggestion})

        pack_steps = [step for step in execution_flow if str(step.get("step_type", "")).lower() == "pack"]
        if validation.get("verified") and entry.get("status") != "VERIFIED":
            add_gap("STATUS_NOT_SYNCED", "status", "validation.verified 已为 true，但 status 仍未同步为 VERIFIED。", "阶段4-Handler验证", "在 verify_handlers / pipeline 中验证成功后同步回写 status=VERIFIED。")
        if not pack_steps:
            add_gap("MISSING_PACK_STEP", "meta.execution_flow[*].pack", "缺少结构化 pack 步骤，无法自动组装最终请求体。", "阶段2-静态分析 与 阶段3-基线生成", "AST 分析需稳定提取 fetch/body 打包方式，并在 init_baselines 中写入 packing_info。")

        named_outputs = {step.get("output_variable") for step in execution_flow if step.get("output_variable")}
        sign_like_outputs = {
            "signature", "sign", "sig", "token", "mac", "hmac"
        }
        has_sign_step = any(str(step.get("step_type", "")).lower() == "sign" for step in execution_flow)
        available_names = set(payload.keys()) | set(runtime_params.keys()) | {item for item in named_outputs if item}
        for pack_step in pack_steps:
            packing_info = (pack_step.get("runtime_args", {}) or {}).get("packing_info", {}) or {}
            structure = packing_info.get("structure", {}) or {}
            field_sources = packing_info.get("field_sources", {}) or {}
            value_derivations = packing_info.get("value_derivations", {}) or {}
            for field_name, source_name in structure.items():
                if source_name in available_names:
                    continue
                field_source = field_sources.get(field_name, {}) if isinstance(field_sources, dict) else {}
                if isinstance(field_source, dict) and field_source.get("derivation"):
                    continue
                # 允许通过 packing_info.value_derivations 声明的中间值作为可解析来源。
                if isinstance(value_derivations, dict) and source_name in value_derivations:
                    continue
                # 常见签名变量在部分端点由 sign 步骤隐式产出，避免误报结构缺口。
                if has_sign_step and str(source_name).lower() in sign_like_outputs:
                    continue
                add_gap("UNRESOLVED_PACK_REFERENCE", f"packing_info.structure.{field_name}", f"打包字段引用了未结构化输出变量 '{source_name}'，本地无法稳定重建。", "阶段2-静态分析 与 阶段3-基线生成", "除 output_variable 外，还应输出可直接引用的中间结果名或编码转换步骤。")

        crypto_steps = [step for step in execution_flow if str(step.get("step_type", "")).lower() in {"encrypt", "sign"}]
        for step in crypto_steps:
            if not step.get("context"):
                add_gap("MISSING_INPUT_CONTEXT", "meta.execution_flow[*].context", "加密/签名步骤缺少上下文，无法分析输入来源。", "阶段2-静态分析", "为每个原语 step 输出结构化 input_expression，而不是仅依赖模糊上下文。")
            input_expression = str(step.get("input_expression") or "").strip()
            input_source_keys = step.get("input_source_keys")
            if input_expression.startswith("JSON.stringify(") and not (isinstance(input_source_keys, list) and input_source_keys):
                add_gap(
                    "JSON_STRINGIFY_ORDER_GAP",
                    "meta.execution_flow[*].input_source_keys",
                    "JSON.stringify 输入缺少字段顺序元数据，重建请求时可能出现字段顺序偏移。",
                    "阶段2-静态分析 与 阶段3-基线生成",
                    "为 encrypt/sign 产物补齐 input_source_keys（按原始对象声明顺序）。",
                )

            runtime_args = step.get("runtime_args", {}) or {}
            step_type = str(step.get("step_type", "")).lower()
            algorithm = str(step.get("algorithm", "")).upper()
            context_text = str(step.get("context") or "")
            input_expr_text = str(step.get("input_expression") or "")
            output_transform_text = str(step.get("output_transform") or "")
            combined_text = " ".join([context_text, input_expr_text, output_transform_text]).lower()

            # 仅在存在明确编码语法线索时判缺口，避免把默认编码路径误判为结构化缺失。
            inferable_fields: list[str] = []
            if "cryptojs.enc." in combined_text and ".parse" in combined_text:
                inferable_fields.append("input_encoding")
            if ".tostring(" in combined_text and "cryptojs.enc." in combined_text:
                inferable_fields.append("output_encoding")
            if algorithm in {"AES", "DES", "TRIPLEDES", "RABBIT", "RC4", "RC4DROP"}:
                if "cryptojs.enc." in context_text.lower() and ".parse" in context_text.lower():
                    inferable_fields.append("key_encoding")
                if "iv" in context_text.lower() and "cryptojs.enc." in context_text.lower() and ".parse" in context_text.lower():
                    inferable_fields.append("iv_encoding")

                # derive_* 步骤中的 __gen_parse_material("...", "utf8|hex|...") 也属于明确可推断线索。
                for derive_step in execution_flow:
                    derive_type = str(derive_step.get("step_type", "")).lower()
                    if derive_type not in {"derive_key", "derive_iv"}:
                        continue
                    derivation = (derive_step.get("runtime_args", {}) or {}).get("derivation") or {}
                    if not isinstance(derivation, dict):
                        continue
                    if str(derivation.get("type") or "") != "call":
                        continue
                    callee = str(derivation.get("callee") or "")
                    if callee != "__gen_parse_material":
                        continue
                    args = derivation.get("args") or []
                    if len(args) < 2:
                        continue
                    if derive_type == "derive_key":
                        inferable_fields.append("key_encoding")
                    if derive_type == "derive_iv":
                        inferable_fields.append("iv_encoding")

            for field_name in sorted(set(inferable_fields)):
                if field_name == "key_encoding":
                    def _derive_key_has_encoding(candidate: dict[str, Any]) -> bool:
                        if str(candidate.get("step_type", "")).lower() != "derive_key":
                            return False
                        runtime = candidate.get("runtime_args", {}) or {}
                        if runtime.get("key_encoding") not in [None, ""]:
                            return True
                        derivation = runtime.get("derivation") or {}
                        if not isinstance(derivation, dict):
                            return False
                        if str(derivation.get("type") or "") != "call":
                            return False
                        if str(derivation.get("callee") or "") != "__gen_parse_material":
                            return False
                        args = derivation.get("args") or []
                        if len(args) < 2:
                            return False
                        arg2 = args[1]
                        if isinstance(arg2, dict):
                            return str(arg2.get("type") or "") == "literal" and str(arg2.get("value") or "") != ""
                        return str(arg2) != ""

                    has_derive_key_encoding = any(
                        _derive_key_has_encoding(candidate)
                        for candidate in execution_flow
                    )
                    if has_derive_key_encoding:
                        continue
                if field_name == "iv_encoding":
                    def _derive_iv_has_encoding(candidate: dict[str, Any]) -> bool:
                        if str(candidate.get("step_type", "")).lower() != "derive_iv":
                            return False
                        runtime = candidate.get("runtime_args", {}) or {}
                        if runtime.get("iv_encoding") not in [None, ""]:
                            return True
                        derivation = runtime.get("derivation") or {}
                        if not isinstance(derivation, dict):
                            return False
                        if str(derivation.get("type") or "") != "call":
                            return False
                        if str(derivation.get("callee") or "") != "__gen_parse_material":
                            return False
                        args = derivation.get("args") or []
                        if len(args) < 2:
                            return False
                        arg2 = args[1]
                        if isinstance(arg2, dict):
                            return str(arg2.get("type") or "") == "literal" and str(arg2.get("value") or "") != ""
                        return str(arg2) != ""

                    has_derive_iv_encoding = any(
                        _derive_iv_has_encoding(candidate)
                        for candidate in execution_flow
                    )
                    if has_derive_iv_encoding:
                        continue
                if runtime_args.get(field_name) not in [None, ""]:
                    continue
                add_gap(
                    "MISSING_ENCODING_METADATA",
                    f"meta.execution_flow[*].runtime_args.{field_name}",
                    f"{step_type.upper()} 步骤存在可推断线索但缺少 {field_name}，可能导致本地重建编码语义与前端不一致。",
                    "阶段2-静态分析 与 阶段3-基线生成",
                    "在 AST 解析中提取并透传 input/output/key/iv 编码元数据，写入 runtime_args。",
                )

        if has_sign_step and runtime_params.get("message") and not any(step.get("input_expression") or step.get("input_derivation") for step in crypto_steps):
            add_gap("MISSING_SIGN_INPUT_RULE", "meta.execution_flow[*].input_expression", "已捕获 message，但缺少结构化签名输入规则，变异后无法本地重新生成签名。", "阶段2-静态分析 与 阶段3-基线生成", "为 sign 步骤输出 input_expression / input_derivation，并记录 dataToSign 的拼接规则。")

        if validation.get("verified") and not runtime_params and meta.get("crypto_algorithms") not in ([], ["PayloadPacking"]):
            add_gap("MISSING_RUNTIME_PARAMS", "validation.runtime_params", "已验证端点却缺少运行时参数，动态 Key/IV/Nonce 场景无法重放。", "阶段4-动态捕获", "在 Hook 中把 key / iv / nonce / timestamp / message 等运行时数据完整回填到 validation.runtime_params。")

        return gaps

    def _collect_static_findings(self, entry: dict[str, Any], baseline_gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        meta = entry.get("meta", {})
        validation = entry.get("validation", {}) if isinstance(entry.get("validation"), dict) else {}
        algorithms = [str(item).upper() for item in meta.get("crypto_algorithms", [])]
        execution_flow = meta.get("execution_flow", []) or []
        runtime_params = validation.get("runtime_params", {}) if isinstance(validation.get("runtime_params"), dict) else {}
        findings = []

        def _derivation_has_material_literal(derivation: Any) -> bool:
            if not isinstance(derivation, dict):
                return False
            dtype = str(derivation.get("type") or "")
            if dtype == "literal" and str(derivation.get("value") or "").strip() != "":
                return True
            if dtype == "call" and str(derivation.get("callee") or "") == "__gen_parse_material":
                args = derivation.get("args") or []
                if args:
                    first = args[0]
                    if isinstance(first, dict) and str(first.get("type") or "") == "literal":
                        return str(first.get("value") or "").strip() != ""
                    if isinstance(first, str):
                        return first.strip() != ""
                return False
            for key in ["input", "left", "right"]:
                if _derivation_has_material_literal(derivation.get(key)):
                    return True
            for arg in derivation.get("args", []) or []:
                if _derivation_has_material_literal(arg):
                    return True
            return False

        if "DES" in algorithms:
            findings.append(self._make_finding("CRYPTO_WEAK_DES", meta.get("url", "unknown")))

        for step in execution_flow:
            step_type = str(step.get("step_type", "")).lower()
            args = step.get("runtime_args", {}) or {}
            if step_type == "setkey" and args.get("key"):
                findings.append(self._make_finding("CRYPTO_HARDCODED_KEY", step.get("context", "setkey")))
            if step_type == "setiv" and args.get("iv"):
                findings.append(self._make_finding("CRYPTO_STATIC_IV", step.get("context", "setiv")))
            if step_type == "derive_key" and _derivation_has_material_literal(args.get("derivation")):
                findings.append(self._make_finding("CRYPTO_HARDCODED_KEY", step.get("context", "derive_key")))
            if step_type == "derive_iv" and _derivation_has_material_literal(args.get("derivation")):
                findings.append(self._make_finding("CRYPTO_STATIC_IV", step.get("context", "derive_iv")))

        if any(gap.get("code") == "MISSING_SIGN_INPUT_RULE" for gap in baseline_gaps):
            findings.append(self._make_finding("AUTH_SIGNATURE_BYPASS_RISK", meta.get("url", "unknown")))

        # 结构化兜底：存在 hash+pack，但没有 sign/签名字段，通常代表签名规则未落地。
        step_types = {str(step.get("step_type", "")).lower() for step in execution_flow if isinstance(step, dict)}
        has_hash_step = "hash" in step_types
        has_pack_step = "pack" in step_types
        has_sign_step = "sign" in step_types
        has_signature_runtime = any(key in {"signature", "sign", "sig", "token", "mac", "hmac"} for key in (str(k).lower() for k in runtime_params.keys()))
        if has_hash_step and has_pack_step and not has_sign_step and not has_signature_runtime:
            findings.append(self._make_finding("AUTH_SIGNATURE_BYPASS_RISK", "hash+pack_without_sign_step"))

        if baseline_gaps:
            findings.append(self._make_finding("ASSESSMENT_BASELINE_GAP", "; ".join(sorted({gap.get('field', 'unknown') for gap in baseline_gaps}))))

        dedup: dict[tuple[str, str], dict[str, Any]] = {}
        for finding in findings:
            dedup[(finding["id"], finding["evidence"])] = finding
        return list(dedup.values())

    def _expected_outcome(self, remote_modes: list[str], layer_any_of: Optional[list[dict[str, Any]]] = None) -> dict[str, Any]:
        outcome: dict[str, Any] = {
            "remote_response_modes": remote_modes,
            "waive_penalty_on_match": True,
        }
        if layer_any_of:
            outcome["response_layer_any_of"] = layer_any_of
        return outcome

    def _is_anti_replay_sensitive_endpoint(self, entry: Optional[dict[str, Any]], payload: Optional[dict[str, Any]] = None) -> bool:
        if not isinstance(entry, dict):
            return False
        meta = entry.get("meta", {}) if isinstance(entry.get("meta"), dict) else {}
        endpoint_id = str(meta.get("id") or "").lower()
        endpoint_url = str(meta.get("url") or "").lower()
        if any(token in endpoint_id for token in ["norepeater", "signdata", "nonce", "timestamp"]):
            return True
        if any(token in endpoint_url for token in ["norepeater", "signdata", "nonce", "timestamp"]):
            return True

        validation = entry.get("validation", {}) if isinstance(entry.get("validation"), dict) else {}
        runtime_params = validation.get("runtime_params", {}) if isinstance(validation.get("runtime_params"), dict) else {}
        runtime_keys = {str(key).lower() for key in runtime_params.keys()}
        if {"nonce", "timestamp"}.issubset(runtime_keys):
            return True
        if "signature" in runtime_keys:
            return True

        # 捕获态常把防重放字段留在加密前 message（例如 RSA data 包裹）。
        message_raw = runtime_params.get("message")
        if isinstance(message_raw, str) and message_raw.strip().startswith("{"):
            try:
                parsed_message = json.loads(message_raw)
                if isinstance(parsed_message, dict):
                    msg_keys = {str(key).lower() for key in parsed_message.keys()}
                    if {"nonce", "timestamp"}.issubset(msg_keys) or "signature" in msg_keys:
                        return True
            except Exception:
                pass

        trace = validation.get("trace", []) if isinstance(validation.get("trace"), list) else []
        for item in trace:
            if not isinstance(item, dict):
                continue
            if str(item.get("type") or "") != "FETCH":
                continue
            body_form = item.get("body_form", {}) if isinstance(item.get("body_form"), dict) else {}
            fetch_keys = {str(key).lower() for key in body_form.keys()}
            if {"nonce", "timestamp"}.issubset(fetch_keys) or "signature" in fetch_keys:
                return True

        hints = meta.get("hints", []) if isinstance(meta.get("hints"), list) else []
        for hint in hints:
            hint_text = str(hint).lower()
            if "inferred payload keys" in hint_text and "nonce" in hint_text and "timestamp" in hint_text:
                return True
            if "signature" in hint_text and ("nonce" in hint_text or "timestamp" in hint_text):
                return True

        flow = meta.get("execution_flow", []) if isinstance(meta.get("execution_flow"), list) else []
        for step in flow:
            step_type = str(step.get("step_type") or "").lower()
            if step_type == "sign":
                return True
            runtime_args = step.get("runtime_args", {}) if isinstance(step.get("runtime_args"), dict) else {}
            anti = str(runtime_args.get("anti_replay") or "").lower()
            if anti and anti != "none":
                return True
            packing_info = runtime_args.get("packing_info", {}) if isinstance(runtime_args.get("packing_info"), dict) else {}
            structure = packing_info.get("structure", {}) if isinstance(packing_info.get("structure"), dict) else {}
            keys = {str(k).lower() for k in structure.keys()}
            if {"nonce", "timestamp"}.issubset(keys):
                return True

        if isinstance(payload, dict):
            keys = {str(k).lower() for k in payload.keys()}
            if "nonce" in keys and "timestamp" in keys:
                return True
        return False

    def _detect_anti_replay_mechanism(self, entry: Optional[dict[str, Any]], payload: Optional[dict[str, Any]] = None) -> str:
        """识别端点的防重放机制，用于 baseline_replay 预期细分。"""
        if not isinstance(entry, dict):
            return "none"

        observed_keys: set[str] = set()
        meta = entry.get("meta", {}) if isinstance(entry.get("meta"), dict) else {}
        validation = entry.get("validation", {}) if isinstance(entry.get("validation"), dict) else {}

        runtime_params = validation.get("runtime_params", {}) if isinstance(validation.get("runtime_params"), dict) else {}
        observed_keys.update(str(key).lower() for key in runtime_params.keys())

        trace = validation.get("trace", []) if isinstance(validation.get("trace"), list) else []
        for item in trace:
            if not isinstance(item, dict):
                continue
            body_form = item.get("body_form", {}) if isinstance(item.get("body_form"), dict) else {}
            observed_keys.update(str(key).lower() for key in body_form.keys())

        flow = meta.get("execution_flow", []) if isinstance(meta.get("execution_flow"), list) else []
        for step in flow:
            runtime_args = step.get("runtime_args", {}) if isinstance(step.get("runtime_args"), dict) else {}
            packing_info = runtime_args.get("packing_info", {}) if isinstance(runtime_args.get("packing_info"), dict) else {}
            structure = packing_info.get("structure", {}) if isinstance(packing_info.get("structure"), dict) else {}
            observed_keys.update(str(key).lower() for key in structure.keys())
            sign_field = str(runtime_args.get("signature_field") or "").strip().lower()
            if sign_field:
                observed_keys.add(sign_field)

        if isinstance(payload, dict):
            observed_keys.update(str(key).lower() for key in payload.keys())

        has_nonce = bool({"nonce", "noncestr", "random", "rand"} & observed_keys)
        has_timestamp = bool({"timestamp", "ts", "time", "signtimestamp", "requesttime"} & observed_keys)
        has_signature = bool({"signature", "sign", "sig", "token", "mac", "hmac"} & observed_keys)

        if has_nonce and has_timestamp and has_signature:
            return "nonce_timestamp_signature"
        if has_nonce and has_timestamp:
            return "nonce_timestamp"
        if has_timestamp and has_signature:
            return "timestamp_signature"
        if has_nonce and has_signature:
            return "nonce_signature"
        if has_nonce:
            return "nonce_only"
        if has_timestamp:
            return "timestamp_only"
        if has_signature:
            return "signature_only"
        return "none"

    def _extract_interlayer_signals(self, entry: Optional[dict[str, Any]]) -> dict[str, Any]:
        """提取夹层信号：只识别，不改变远程预期集合。"""
        layers: set[str] = set()
        entry_declared_layers: set[str] = set()
        source_tags: list[str] = []
        item = entry if isinstance(entry, dict) else {}
        meta = item.get("meta", {}) if isinstance(item.get("meta"), dict) else {}
        request = item.get("request", {}) if isinstance(item.get("request"), dict) else {}
        validation = item.get("validation", {}) if isinstance(item.get("validation"), dict) else {}

        def _norm(value: Any) -> str:
            return str(value or "").strip().lower()

        def _has_base64_signal(text: Any) -> bool:
            t = _norm(text)
            if not t:
                return False
            return any(marker in t for marker in ["base64", "cryptojs.enc.base64", "btoa(", "atob(", "base64_encode", "base64_decode"])

        def _flow_steps() -> list[dict[str, Any]]:
            flow = meta.get("execution_flow", []) if isinstance(meta.get("execution_flow"), list) else []
            return [step for step in flow if isinstance(step, dict)]

        flow_steps = _flow_steps()
        algorithms = {
            str(algo).strip().upper()
            for algo in (meta.get("crypto_algorithms", []) if isinstance(meta.get("crypto_algorithms"), list) else [])
            if str(algo).strip()
        }
        for step in flow_steps:
            algo = str(step.get("algorithm") or "").strip().upper()
            if algo:
                algorithms.add(algo)
        has_non_hmac_algo = bool(algorithms - {"HMACSHA256", "HMACSHA256()", "PLAINTEXT_HMAC"})

        # 显式字段优先。
        for raw_layers in [item.get("interlayers"), meta.get("interlayers")]:
            if isinstance(raw_layers, list):
                for name in raw_layers:
                    text = str(name).strip().upper()
                    if text:
                        layers.add(text)
                        entry_declared_layers.add(text)
                        source_tags.append("explicit")

        # 风险标签中的夹层痕迹。
        risk_tags: list[Any] = []
        if isinstance(item.get("risk_tags"), list):
            risk_tags.extend(item.get("risk_tags") or [])
        if isinstance(meta.get("risk_tags"), list):
            risk_tags.extend(meta.get("risk_tags") or [])
        for tag in risk_tags:
            text = str(tag).strip().upper()
            if text in {"HEADER_SIGN_LAYER", "ENCODING_LAYER"}:
                layers.add(text)
                entry_declared_layers.add(text)
                source_tags.append("risk_tag")

        # 对 layer2 端点回补样本池元数据，提升非 HMAC 路径识别率。
        endpoint_id = str(meta.get("id") or item.get("endpoint_id") or "").strip()
        layer2_pool_matched = False
        layer2_pool_layers: set[str] = set()
        if endpoint_id.startswith("layer2_"):
            layer2_map = self._load_layer2_sample_pool_map()
            layer2_meta = layer2_map.get(endpoint_id, {}) if isinstance(layer2_map, dict) else {}
            if isinstance(layer2_meta, dict) and layer2_meta:
                layer2_pool_matched = True
                for name in layer2_meta.get("interlayers", []) or []:
                    text = str(name).strip().upper()
                    if text:
                        layers.add(text)
                        layer2_pool_layers.add(text)
                        source_tags.append("layer2_pool_interlayers")

                for tag in layer2_meta.get("risk_tags", []) or []:
                    text = str(tag).strip().upper()
                    if text in {"HEADER_SIGN_LAYER", "ENCODING_LAYER"}:
                        layers.add(text)
                        layer2_pool_layers.add(text)
                        source_tags.append("layer2_pool_risk_tags")

                algo_params = layer2_meta.get("algo_params", {}) if isinstance(layer2_meta.get("algo_params"), dict) else {}
                if _has_base64_signal(algo_params.get("plaintext_encoding")):
                    layers.add("ENCODING_LAYER")
                    layer2_pool_layers.add("ENCODING_LAYER")
                    source_tags.append("layer2_pool_plaintext_encoding")

                signature_strategy = layer2_meta.get("signature_strategy", {}) if isinstance(layer2_meta.get("signature_strategy"), dict) else {}
                placement = _norm(signature_strategy.get("placement"))
                if placement == "header":
                    layers.add("HEADER_SIGN_LAYER")
                    layer2_pool_layers.add("HEADER_SIGN_LAYER")
                    source_tags.append("layer2_pool_signature_placement")

        # 推断：Header 签名可视作 HEADER_SIGN_LAYER 信号。
        headers = request.get("headers") if isinstance(request.get("headers"), dict) else {}
        header_keys = {str(k).lower() for k in headers.keys()} if isinstance(headers, dict) else set()
        if {"x-signature", "signature", "x-sign"} & header_keys:
            layers.add("HEADER_SIGN_LAYER")
            source_tags.append("header_infer")

        # 推断：执行流中 sign 步骤显式声明 header placement。
        if has_non_hmac_algo:
            for step in flow_steps:
                if _norm(step.get("step_type")) != "sign":
                    continue
                runtime_args = step.get("runtime_args", {}) if isinstance(step.get("runtime_args"), dict) else {}
                placement = _norm(runtime_args.get("placement") or runtime_args.get("signature_placement") or step.get("signature_placement"))
                if placement == "header":
                    layers.add("HEADER_SIGN_LAYER")
                    source_tags.append("flow_sign_header")
                    break

        # 推断：trace 捕获到签名头字段。
        trace = validation.get("trace", []) if isinstance(validation.get("trace"), list) else []
        for trace_item in trace:
            if not isinstance(trace_item, dict):
                continue
            trace_headers = trace_item.get("headers") if isinstance(trace_item.get("headers"), dict) else {}
            trace_header_keys = {str(k).lower() for k in trace_headers.keys()} if isinstance(trace_headers, dict) else set()
            if {"x-signature", "signature", "x-sign"} & trace_header_keys:
                layers.add("HEADER_SIGN_LAYER")
                source_tags.append("trace_header_infer")
                break

        # 推断：执行流存在显式 Base64 编码语义（针对非 HMAC 路径）。
        if has_non_hmac_algo:
            for step in flow_steps:
                runtime_args = step.get("runtime_args", {}) if isinstance(step.get("runtime_args"), dict) else {}
                enc_fields = [
                    runtime_args.get("input_encoding"),
                    runtime_args.get("output_encoding"),
                    runtime_args.get("key_encoding"),
                    runtime_args.get("iv_encoding"),
                    step.get("input_encoding"),
                    step.get("output_encoding"),
                    step.get("key_encoding"),
                    step.get("iv_encoding"),
                ]
                if any(_has_base64_signal(v) for v in enc_fields):
                    layers.add("ENCODING_LAYER")
                    source_tags.append("flow_encoding_metadata")
                    break
                if any(
                    _has_base64_signal(v)
                    for v in [
                        step.get("context"),
                        step.get("input_expression"),
                        step.get("output_transform"),
                        runtime_args.get("context"),
                    ]
                ):
                    layers.add("ENCODING_LAYER")
                    source_tags.append("flow_encoding_expression")
                    break

        # layer2 样本池命中时，以池内声明为准，避免控制组被启发式误判。
        if layer2_pool_matched:
            authoritative_layers = sorted(set(layer2_pool_layers))
            authoritative_tags = sorted({tag for tag in source_tags if tag.startswith("layer2_pool_")})
            authoritative_tags.append("layer2_pool_authoritative")
            return {
                "enabled": bool(authoritative_layers),
                "layers": authoritative_layers,
                "primary": authoritative_layers[0] if authoritative_layers else "NONE",
                "source_tags": sorted(set(authoritative_tags)),
            }

        unique_layers = sorted(layers)
        return {
            "enabled": bool(unique_layers),
            "layers": unique_layers,
            "primary": unique_layers[0] if unique_layers else "NONE",
            "source_tags": sorted(set(source_tags)),
        }

    def _mark_interlayer_key_scenarios(self, scenarios: list[dict[str, Any]], interlayer_signals: dict[str, Any]) -> None:
        """基于夹层信号标记关键场景，不改 expected_outcome。"""
        if not interlayer_signals.get("enabled"):
            return
        layers = [str(name).upper() for name in (interlayer_signals.get("layers") or [])]
        key_ids: set[str] = set()
        for layer in layers:
            key_ids.update(INTERLAYER_KEY_SCENARIOS.get(layer, set()))

        for scenario in scenarios:
            sid = str(scenario.get("scenario_id", ""))
            if sid in key_ids:
                scenario["interlayer_key_scenario"] = True
                scenario["interlayer_layers"] = layers
                # Header 签名夹层下，增强篡改候选字段（仅增强动作，不改预期模式）。
                if "HEADER_SIGN_LAYER" in layers and sid in {"crypto_remove_security_field", "crypto_signature_corruption"}:
                    request_tamper = scenario.get("request_tamper") if isinstance(scenario.get("request_tamper"), dict) else {}
                    fields = [str(x) for x in (request_tamper.get("fields", []) or [])]
                    for extra in ["x-signature", "x-sign", "signature", "sign", "sig"]:
                        if extra not in fields:
                            fields.append(extra)
                    request_tamper["fields"] = fields
                    scenario["request_tamper"] = request_tamper

    def _summarize_interlayer_effectiveness(
        self,
        interlayer_signals: dict[str, Any],
        scenario_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """夹层有效性：关键场景任一失败即判定夹层失效。"""
        key_items = [item for item in scenario_results if bool(item.get("interlayer_key_scenario"))]
        inferred_layers: set[str] = set()
        inferred_source = False

        # 当上游尚未产出 interlayer 标签时，从协议篡改场景反推是否存在夹层语义。
        if not key_items:
            layer_by_scenario: dict[str, str] = {}
            for layer_name, scenario_ids in INTERLAYER_KEY_SCENARIOS.items():
                for scenario_id in scenario_ids:
                    layer_by_scenario[scenario_id] = layer_name
            inferred_mismatch_count = 0
            for item in scenario_results:
                scenario_id = str(item.get("scenario_id") or "")
                if scenario_id not in layer_by_scenario:
                    continue
                expectation = item.get("expectation", {}) if isinstance(item.get("expectation"), dict) else {}
                remote_result = item.get("remote_result", {}) if isinstance(item.get("remote_result"), dict) else {}
                if not bool(expectation.get("defined")):
                    continue
                if not bool(remote_result.get("attempted")):
                    continue
                key_items.append(item)
                inferred_layers.add(layer_by_scenario[scenario_id])
                if expectation.get("matched") is False:
                    inferred_mismatch_count += 1
            inferred_source = bool(key_items) and inferred_mismatch_count > 0
            if not inferred_source:
                key_items = []
                inferred_layers = set()

        if not interlayer_signals.get("enabled") and not inferred_source:
            return {
                "state": "no_interlayer",
                "enabled": False,
                "layers": [],
                "key_scenarios_total": 0,
                "key_scenarios_failed": 0,
                "failed_scenarios": [],
                "rule": "no_interlayer",
            }

        failed: list[dict[str, Any]] = []
        for item in key_items:
            status = str(item.get("status", ""))
            expectation = item.get("expectation", {}) if isinstance(item.get("expectation"), dict) else {}
            matched = expectation.get("matched")
            if inferred_source:
                # 推断模式下仅以远程预期失配作为失败证据，避免把不可执行场景误判为夹层失效。
                should_fail = matched is False
            else:
                should_fail = status == "SKIPPED" or status == "LOCAL_FAILED" or matched is False
            if should_fail:
                failed.append(
                    {
                        "scenario_id": item.get("scenario_id"),
                        "status": status,
                        "matched": matched,
                        "skip_reason": item.get("skip_reason"),
                    }
                )

        state = "interlayer_invalid" if failed else "interlayer_effective"
        layers = interlayer_signals.get("layers", [])
        source_tags = list(interlayer_signals.get("source_tags", []) or [])
        if inferred_source:
            layers = sorted(set([str(layer).upper() for layer in layers] + list(inferred_layers)))
            source_tags = sorted(set(source_tags + ["scenario_expectation_infer"]))

        return {
            "state": state,
            "enabled": True,
            "layers": layers,
            "key_scenarios_total": len(key_items),
            "key_scenarios_failed": len(failed),
            "failed_scenarios": failed,
            "rule": "any_key_scenario_failed=>interlayer_invalid",
            "source_tags": source_tags,
        }

    def _enhance_common_scenarios(self, scenarios: list[dict[str, Any]], text_key: Optional[str]) -> None:
        """增强模糊模式：不增加场景，仅提高现有场景的变异强度。"""
        if not self.enhanced_fuzz_mode:
            return
        for item in scenarios:
            sid = str(item.get("scenario_id", ""))
            payload_mutation = item.get("payload_mutation", {}) if isinstance(item.get("payload_mutation"), dict) else {}
            request_tamper = item.get("request_tamper", {}) if isinstance(item.get("request_tamper"), dict) else {}

            if sid == "plaintext_mutation_sqli" and text_key:
                payload_mutation.setdefault("set", {})
                payload_mutation["set"][text_key] = "' OR 1=1 -- /*probe*/ UNION SELECT NULL#"

            if sid == "boundary_long_string" and text_key:
                old = str((payload_mutation.get("set", {}) or {}).get(text_key, "A"))
                payload_mutation.setdefault("set", {})
                payload_mutation["set"][text_key] = old * 4

            if sid == "special_chars_payload" and text_key:
                payload_mutation.setdefault("set", {})
                payload_mutation["set"][text_key] = "\x00\x1f\u2028\u2029'\"\\/%0a%0d<script>alert(1)</script>中文🚧"

            if sid == "payload_type_confusion" and text_key:
                payload_mutation.setdefault("set", {})
                payload_mutation["set"][text_key] = {
                    "nested": {"arr": [1, "2", True, None], "obj": {"a": "b"}},
                    "type": "object_confusion",
                }

            if sid == "crypto_stale_timestamp":
                item["meta_mutations"] = [{"op": "set", "path": "validation.runtime_params.timestamp", "value": 0}]
                if request_tamper:
                    request_tamper["value"] = 0

            if sid == "crypto_signature_corruption":
                item["meta_mutations"] = [{"op": "set", "path": "validation.runtime_params.signature", "value": "zzzz_NOT_HEX_deadbeef_0000"}]
                if request_tamper:
                    request_tamper["value"] = "zzzz_NOT_HEX_deadbeef_0000"

            if sid == "crypto_ciphertext_truncate" and request_tamper:
                request_tamper["length"] = 4

            if sid == "crypto_duplicate_timestamp" and request_tamper:
                request_tamper["value"] = "0"

    def _enhance_prehash_scenarios(self, scenarios: list[dict[str, Any]], hash_field: Optional[str]) -> None:
        if not self.enhanced_fuzz_mode:
            return
        for item in scenarios:
            sid = str(item.get("scenario_id", ""))
            request_tamper = item.get("request_tamper", {}) if isinstance(item.get("request_tamper"), dict) else {}
            if sid == "prehash_stale_timestamp":
                item["meta_mutations"] = [{"op": "set", "path": "validation.runtime_params.timestamp", "value": 0}]
                if request_tamper:
                    request_tamper["value"] = 0
            if sid == "prehash_nonce_reuse":
                item["meta_mutations"] = [{"op": "set", "path": "validation.runtime_params.nonce", "value": "REPLAY_NONCE_FIXED_000"}]
                if request_tamper:
                    request_tamper["value"] = "REPLAY_NONCE_FIXED_000"
            if sid == "prehash_credential_mismatch" and hash_field:
                payload_mutation = item.get("payload_mutation", {}) if isinstance(item.get("payload_mutation"), dict) else {}
                payload_mutation.setdefault("set", {})
                payload_mutation["set"][hash_field] = "00bad_hash_payload_deadbeef"

    def _build_scenarios(
        self,
        payload: dict[str, Any],
        meta: Optional[dict[str, Any]] = None,
        entry: Optional[dict[str, Any]] = None,
    ) -> list[dict[str, Any]]:
        # 诊断口径：基线重放应尽量成功，否则视为安全/可用性风险信号。
        endpoint_meta = meta if isinstance(meta, dict) else {}
        endpoint_id = str((endpoint_meta.get("id") or "")).lower()
        endpoint_url = str((endpoint_meta.get("url") or "")).lower()
        anti_replay_sensitive = self._is_anti_replay_sensitive_endpoint(entry, payload)
        anti_replay_mechanism = self._detect_anti_replay_mechanism(entry, payload)
        algorithms = {
            str(item).strip().upper()
            for item in (endpoint_meta.get("crypto_algorithms", []) if isinstance(endpoint_meta.get("crypto_algorithms"), list) else [])
            if str(item).strip()
        }
        is_des_path = (
            endpoint_id == "des"
            or endpoint_url.endswith("/des.php")
            or "DES" in algorithms
        )

        # baseline_replay 按攻击场景处理：无论是否存在防重放机制，均默认期望“失败响应”。
        expected_baseline_modes = ["APP_REJECTED", "APP_INVALID_INPUT", "APP_MISSING_DATA", "APP_DECRYPT_FAIL", "HTTP_4XX"]
        expected_baseline_layers = [
            {"protocol": ["HTTP_2XX"], "semantic": ["APP_REJECTED", "APP_INVALID_INPUT", "APP_MISSING_DATA", "APP_DECRYPT_FAIL"]},
            {"protocol": ["HTTP_4XX"]},
        ]
        def _unique(values: list[str]) -> list[str]:
            seen: set[str] = set()
            result: list[str] = []
            for item in values:
                text = str(item)
                if text in seen:
                    continue
                seen.add(text)
                result.append(text)
            return result

        scenario_modes: dict[str, list[str]] = {
            # 文本变异：以业务拒绝类为主，保留协议层兜底。
            "plaintext_mutation_sqli": ["APP_INVALID_INPUT", "APP_REJECTED", "HTTP_4XX"],
            "boundary_empty_string": ["APP_INVALID_INPUT", "APP_MISSING_DATA", "APP_REJECTED", "HTTP_4XX"],
            # 超长输入更容易触发构包/解密路径异常，保留 NOT_ATTEMPTED 与 APP_DECRYPT_FAIL。
            "boundary_long_string": ["APP_INVALID_INPUT", "APP_REJECTED", "HTTP_4XX", "APP_DECRYPT_FAIL", "NOT_ATTEMPTED"],
            "special_chars_payload": ["APP_INVALID_INPUT", "APP_REJECTED", "HTTP_4XX"],
            "auth_context_variation": ["APP_INVALID_INPUT", "APP_REJECTED", "HTTP_4XX"],
            # 结构错配优先落在输入/结构拒绝，不默认放宽到解密失败。
            "payload_type_confusion": ["APP_INVALID_INPUT", "APP_REJECTED", "HTTP_4XX"],
            "payload_missing_field": ["APP_MISSING_DATA", "APP_REJECTED", "HTTP_4XX", "NOT_ATTEMPTED"],
            # 协议篡改场景：允许 APP_DECRYPT_FAIL 与 NOT_ATTEMPTED。
            "crypto_remove_security_field": ["APP_INVALID_INPUT", "APP_MISSING_DATA", "APP_REJECTED", "HTTP_4XX", "APP_DECRYPT_FAIL", "NOT_ATTEMPTED"],
            "crypto_stale_timestamp": ["APP_INVALID_INPUT", "APP_REJECTED", "HTTP_4XX", "NOT_ATTEMPTED"],
            "crypto_signature_corruption": ["APP_INVALID_INPUT", "APP_REJECTED", "HTTP_4XX", "NOT_ATTEMPTED"],
            "crypto_ciphertext_truncate": ["APP_INVALID_INPUT", "APP_REJECTED", "HTTP_4XX", "APP_DECRYPT_FAIL", "NOT_ATTEMPTED"],
            "crypto_duplicate_timestamp": ["APP_INVALID_INPUT", "APP_REJECTED", "HTTP_4XX", "NOT_ATTEMPTED"],
        }

        # DES 路径下，部分业务变异可能直接落到解密失败语义。
        if is_des_path:
            for sid in [
                "plaintext_mutation_sqli",
                "boundary_empty_string",
                "special_chars_payload",
                "auth_context_variation",
                "crypto_duplicate_timestamp",
            ]:
                scenario_modes[sid] = _unique(scenario_modes[sid] + ["APP_DECRYPT_FAIL"])

        # 仅在防重放敏感端点保留  missing_data 容忍，其他端点继续收敛。
        if anti_replay_sensitive or anti_replay_mechanism != "none":
            for sid in [
                "plaintext_mutation_sqli",
                "payload_type_confusion",
                "special_chars_payload",
                "auth_context_variation",
                "payload_missing_field",
            ]:
                scenario_modes[sid] = _unique(scenario_modes[sid] + ["APP_MISSING_DATA"])

        def _modes(scenario_id: str) -> list[str]:
            return list(scenario_modes.get(scenario_id, ["APP_INVALID_INPUT", "APP_REJECTED", "HTTP_4XX", "HTTP_OK_OTHER"]))
        scenarios = [
            {
                "scenario_id": "baseline_replay",
                "category": "baseline_replay",
                "title": "基线重放一致性检查",
                "payload_mutation": {"set": {}, "remove": []},
                "meta_mutations": [],
                "allow_captured_message_fallback": not self.strict_baseline_replay,
                "description": "使用原始基线 Payload 在本地重建加密与打包流程。",
                "expected_outcome": self._expected_outcome(
                    remote_modes=expected_baseline_modes,
                    layer_any_of=expected_baseline_layers,
                ),
            }
        ]

        text_key = first_payload_key(payload, ["username", "password", "id", "query"])
        payload_keys = list(payload.keys())
        if text_key:
            original_text = payload.get(text_key, "")
            scenarios.append({
                "scenario_id": "plaintext_mutation_sqli",
                "category": "plaintext_mutation",
                "title": f"明文注入测试：{text_key}",
                "payload_mutation": {"set": {text_key: f"{original_text}' OR '1'='1"}, "remove": []},
                "meta_mutations": [],
                "allow_captured_message_fallback": False,
                "description": f"对字段 {text_key} 注入常见 SQL 注入载荷。",
                "expected_outcome": self._expected_outcome(_modes("plaintext_mutation_sqli")),
            })
            scenarios.append({
                "scenario_id": "boundary_empty_string",
                "category": "boundary_anomaly",
                "title": f"边界值：{text_key} 置空",
                "payload_mutation": {"set": {text_key: ""}, "remove": []},
                "meta_mutations": [],
                "allow_captured_message_fallback": False,
                "description": f"将字段 {text_key} 置为空字符串。",
                "expected_outcome": self._expected_outcome(_modes("boundary_empty_string")),
            })
            scenarios.append({
                "scenario_id": "boundary_long_string",
                "category": "boundary_anomaly",
                "title": f"边界值：{text_key} 超长字符串",
                "payload_mutation": {"set": {text_key: str(original_text) * 64}, "remove": []},
                "meta_mutations": [],
                "allow_captured_message_fallback": False,
                "description": f"将字段 {text_key} 扩展为超长字符串，测试长度边界。",
                "expected_outcome": self._expected_outcome(_modes("boundary_long_string")),
            })
            scenarios.append({
                "scenario_id": "special_chars_payload",
                "category": "boundary_anomaly",
                "title": f"特殊字符测试：{text_key}",
                "payload_mutation": {"set": {text_key: "!@#￥%…&*()_+-=[]{}|;:'\",.<>/?`~中文🚧"}, "remove": []},
                "meta_mutations": [],
                "allow_captured_message_fallback": False,
                "description": f"向字段 {text_key} 注入特殊字符、中文与 Unicode。",
                "expected_outcome": self._expected_outcome(_modes("special_chars_payload")),
            })
            scenarios.append({
                "scenario_id": "auth_context_variation",
                "category": "auth_context_variation",
                "title": f"身份上下文变体：{text_key}",
                "payload_mutation": {"set": {text_key: "guest_user"}, "remove": []},
                "meta_mutations": [],
                "allow_captured_message_fallback": False,
                "description": f"替换字段 {text_key} 的身份语义值，观察是否可构造新的合法请求。",
                "expected_outcome": self._expected_outcome(_modes("auth_context_variation")),
            })
            scenarios.append({
                "scenario_id": "payload_type_confusion",
                "category": "payload_structure_variation",
                "title": f"类型错配测试：{text_key}",
                "payload_mutation": {"set": {text_key: {"nested": True}}, "remove": []},
                "meta_mutations": [],
                "allow_captured_message_fallback": False,
                "description": f"将字段 {text_key} 由字符串替换为对象，测试类型错配。",
                "expected_outcome": self._expected_outcome(_modes("payload_type_confusion")),
            })

        removable_key = None
        for candidate in ["password", "username", "id"]:
            if candidate in payload:
                removable_key = candidate
                break
        if not removable_key and payload_keys:
            removable_key = payload_keys[0]
        if removable_key:
            scenarios.append({
                "scenario_id": "payload_missing_field",
                "category": "payload_structure_variation",
                "title": f"缺字段测试：移除 {removable_key}",
                "payload_mutation": {"set": {}, "remove": [removable_key]},
                # 只做业务请求字段缺失变异，避免误删运行时加密材料导致本地执行失败。
                "meta_mutations": [],
                # 强制作用到最终发送包，避免被 runtime_params 回退覆盖导致“变异未生效”。
                "request_tamper": {"action": "remove_field", "fields": [removable_key]},
                "allow_captured_message_fallback": False,
                "description": f"移除字段 {removable_key}，检查本地是否还能重建请求。",
                "expected_outcome": self._expected_outcome(_modes("payload_missing_field")),
            })

        scenarios.extend([
            {
                "scenario_id": "crypto_remove_security_field",
                "category": "crypto_protocol_tamper",
                "title": "协议篡改：移除签名/随机字段",
                "payload_mutation": {"set": {}, "remove": []},
                "meta_mutations": [
                    {"op": "remove", "path": "validation.runtime_params.signature"},
                    {"op": "remove", "path": "validation.runtime_params.nonce"},
                ],
                "allow_captured_message_fallback": False,
                "description": "删除 signature/nonce/timestamp/encryptedData/random 中的安全字段。",
                "request_tamper": {"action": "remove_field", "fields": ["signature", "nonce", "timestamp", "encryptedData", "data", "random"]},
                "expected_outcome": self._expected_outcome(_modes("crypto_remove_security_field")),
            },
            {
                "scenario_id": "crypto_stale_timestamp",
                "category": "crypto_protocol_tamper",
                "title": "协议篡改：旧时间戳重放",
                "payload_mutation": {"set": {}, "remove": []},
                "meta_mutations": [{"op": "set", "path": "validation.runtime_params.timestamp", "value": 1}],
                "allow_captured_message_fallback": False,
                "description": "将 timestamp 重写为旧值，模拟重放场景。",
                "request_tamper": {
                    "action": "overwrite_field",
                    "fields": ["timestamp"],
                    "value": 1,
                    "disable_fallback": True,
                    "strict_target_only": True,
                },
                "expected_outcome": self._expected_outcome(_modes("crypto_stale_timestamp")),
            },
            {
                "scenario_id": "crypto_signature_corruption",
                "category": "crypto_protocol_tamper",
                "title": "协议篡改：破坏签名字段",
                "payload_mutation": {"set": {}, "remove": []},
                "meta_mutations": [{"op": "set", "path": "validation.runtime_params.signature", "value": "deadbeefdeadbeef"}],
                "allow_captured_message_fallback": False,
                "description": "将 signature 覆写为明显错误的固定值。",
                "request_tamper": {
                    "action": "overwrite_field",
                    "fields": ["signature"],
                    "value": "deadbeefdeadbeef",
                    "disable_fallback": True,
                    "strict_target_only": True,
                },
                "expected_outcome": self._expected_outcome(_modes("crypto_signature_corruption")),
            },
            {
                "scenario_id": "crypto_ciphertext_truncate",
                "category": "crypto_protocol_tamper",
                "title": "协议篡改：截断密文字段",
                "payload_mutation": {"set": {}, "remove": []},
                "meta_mutations": [],
                "allow_captured_message_fallback": False,
                "description": "对 encryptedData / data / random / password 等字段进行截断。",
                "request_tamper": {
                    "action": "truncate_field",
                    "fields": ["encryptedData", "data", "random", "password"],
                    "length": 12,
                    "strict_fields": True,
                    "disable_fallback": True,
                    "exclude_fields": ["nonce", "timestamp", "sign", "sig", "signature", "token", "mac"],
                },
                "expected_outcome": self._expected_outcome(_modes("crypto_ciphertext_truncate")),
            },
            {
                "scenario_id": "crypto_duplicate_timestamp",
                "category": "crypto_protocol_tamper",
                "title": "协议篡改：重复 timestamp 字段",
                "payload_mutation": {"set": {}, "remove": []},
                "meta_mutations": [],
                "allow_captured_message_fallback": False,
                "description": "在 URL 编码请求中追加重复 timestamp 字段。",
                "request_tamper": {
                    "action": "duplicate_field",
                    "fields": ["timestamp"],
                    "value": "1",
                    "disable_fallback": True,
                    "strict_target_only": True,
                },
                "expected_outcome": self._expected_outcome(_modes("crypto_duplicate_timestamp")),
            },
        ])
        interlayer_signals = self._extract_interlayer_signals(entry)
        self._mark_interlayer_key_scenarios(scenarios, interlayer_signals)
        self._enhance_common_scenarios(scenarios, text_key)
        return scenarios

    def _build_password_prehash_scenarios(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """PasswordPreHash 特例仅保留认证抗性相关场景。"""
        prehash_scenario_modes: dict[str, list[str]] = {
            "prehash_remove_security_field": ["APP_INVALID_INPUT", "APP_MISSING_DATA", "APP_REJECTED", "HTTP_4XX", "HTTP_OK_OTHER", "APP_DECRYPT_FAIL", "NOT_ATTEMPTED"],
            "prehash_stale_timestamp": ["APP_INVALID_INPUT", "APP_MISSING_DATA", "APP_REJECTED", "HTTP_4XX", "HTTP_OK_OTHER", "NOT_ATTEMPTED"],
            "prehash_nonce_reuse": ["APP_INVALID_INPUT", "APP_MISSING_DATA", "APP_REJECTED", "HTTP_4XX", "HTTP_OK_OTHER", "NOT_ATTEMPTED"],
            "prehash_credential_mismatch": ["APP_INVALID_INPUT", "APP_MISSING_DATA", "APP_REJECTED", "HTTP_4XX", "HTTP_OK_OTHER", "APP_DECRYPT_FAIL", "NOT_ATTEMPTED"],
        }

        def _prehash_modes(scenario_id: str) -> list[str]:
            return list(prehash_scenario_modes.get(scenario_id, ["APP_INVALID_INPUT", "APP_REJECTED", "HTTP_4XX", "HTTP_OK_OTHER", "NOT_ATTEMPTED"]))

        hash_field = first_payload_key(payload, ["password", "pwd", "password_hash", "hash", "token"])

        scenarios = [
            {
                "scenario_id": "baseline_replay",
                "category": "baseline_replay",
                "title": "基线重放一致性检查",
                "payload_mutation": {"set": {}, "remove": []},
                "meta_mutations": [],
                "allow_captured_message_fallback": not self.strict_baseline_replay,
                "description": "基线重放，用于观察服务端是否存在重放可接受窗口。",
                "expected_outcome": self._expected_outcome(
                    remote_modes=["APP_SUCCESS"],
                    layer_any_of=[
                        {"protocol": ["HTTP_2XX"], "semantic": ["APP_SUCCESS"]},
                    ],
                ),
            },
            {
                "scenario_id": "prehash_remove_security_field",
                "category": "password_prehash_tamper",
                "title": "认证抗性：移除 nonce/timestamp/signature",
                "payload_mutation": {"set": {}, "remove": []},
                "meta_mutations": [
                    {"op": "remove", "path": "validation.runtime_params.nonce"},
                    {"op": "remove", "path": "validation.runtime_params.timestamp"},
                    {"op": "remove", "path": "validation.runtime_params.signature"},
                ],
                "allow_captured_message_fallback": False,
                "description": "删除认证上下文字段，验证服务端是否强制校验时效与一次性参数。",
                "request_tamper": {"action": "remove_field", "fields": ["nonce", "timestamp", "signature", "sig", "token"]},
                "expected_outcome": self._expected_outcome(_prehash_modes("prehash_remove_security_field")),
            },
            {
                "scenario_id": "prehash_stale_timestamp",
                "category": "password_prehash_tamper",
                "title": "认证抗性：旧时间戳重放",
                "payload_mutation": {"set": {}, "remove": []},
                "meta_mutations": [{"op": "set", "path": "validation.runtime_params.timestamp", "value": 1}],
                "allow_captured_message_fallback": False,
                "description": "强制时间戳回退，观察服务端是否拒绝过期请求。",
                "request_tamper": {"action": "overwrite_field", "fields": ["timestamp", "ts", "time"], "value": 1},
                "expected_outcome": self._expected_outcome(_prehash_modes("prehash_stale_timestamp")),
            },
            {
                "scenario_id": "prehash_nonce_reuse",
                "category": "password_prehash_tamper",
                "title": "认证抗性：重复 nonce",
                "payload_mutation": {"set": {}, "remove": []},
                "meta_mutations": [{"op": "set", "path": "validation.runtime_params.nonce", "value": "REPLAY_NONCE"}],
                "allow_captured_message_fallback": False,
                "description": "固定 nonce 值，模拟重放请求中的 nonce 复用。",
                "request_tamper": {"action": "overwrite_field", "fields": ["nonce", "nonceStr", "random"], "value": "REPLAY_NONCE"},
                "expected_outcome": self._expected_outcome(_prehash_modes("prehash_nonce_reuse")),
            },
        ]

        if hash_field:
            scenarios.append({
                "scenario_id": "prehash_credential_mismatch",
                "category": "password_prehash_tamper",
                "title": f"认证抗性：篡改口令哈希字段 {hash_field}",
                "payload_mutation": {"set": {}, "remove": []},
                "meta_mutations": [],
                "allow_captured_message_fallback": False,
                "description": "覆盖口令哈希字段，验证服务端是否严格绑定用户名与哈希关系。",
                "request_tamper": {"action": "overwrite_field", "fields": [hash_field, "password", "pwd", "password_hash", "hash"], "value": "deadbeef"},
                "expected_outcome": self._expected_outcome(_prehash_modes("prehash_credential_mismatch")),
            })

        self._enhance_prehash_scenarios(scenarios, hash_field)

        return scenarios

    def _apply_special_path_scoring_filter(self, baseline_gaps: list[dict[str, Any]], findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
        """特例路径：豁免 handler 缺失类扣分，但保留认证抗性场景扣分。"""
        waived_gap_codes = {
            "STATUS_NOT_SYNCED",
            "MISSING_PACK_STEP",
            "UNRESOLVED_PACK_REFERENCE",
            "MISSING_INPUT_CONTEXT",
            "MISSING_SIGN_INPUT_RULE",
            "MISSING_RUNTIME_PARAMS",
        }
        waived_finding_ids = {"ASSESSMENT_BASELINE_GAP", "AUTH_SIGNATURE_BYPASS_RISK"}

        filtered_gaps = [gap for gap in baseline_gaps if gap.get("code") not in waived_gap_codes]
        filtered_findings = [f for f in findings if f.get("id") not in waived_finding_ids]

        metadata = {
            "waived_gap_codes": sorted({str(g.get("code")) for g in baseline_gaps if g.get("code") in waived_gap_codes}),
            "waived_finding_ids": sorted({str(f.get("id")) for f in findings if f.get("id") in waived_finding_ids}),
        }
        return filtered_gaps, filtered_findings, metadata

    def _materialize_payload(self, base_payload: dict[str, Any], scenario: dict[str, Any]) -> dict[str, Any]:
        if isinstance(scenario.get("payload"), dict):
            return copy.deepcopy(scenario.get("payload"))
        payload = copy.deepcopy(base_payload)
        # 先移除未填充占位符，避免占位符污染 baseline_replay 的组包结果。
        for key in list(payload.keys()):
            if payload.get(key) == "<Fill Value>":
                payload.pop(key, None)
        mutation = scenario.get("payload_mutation", {}) or {}
        for key in mutation.get("remove", []) or []:
            payload.pop(str(key), None)
        for key, value in (mutation.get("set", {}) or {}).items():
            payload[str(key)] = value
        return payload

    def _request_preview_has_placeholder(self, preview: Optional[dict[str, Any]]) -> bool:
        if not preview:
            return False
        body_text = str(preview.get("body_text") or "")
        if "<Fill Value>" in body_text:
            return True
        body_json = preview.get("body_json")
        if isinstance(body_json, dict):
            for value in body_json.values():
                if isinstance(value, str) and "<Fill Value>" in value:
                    return True
        return False

    def _apply_meta_mutations(self, entry: dict[str, Any], mutations: list[dict[str, Any]]) -> list[str]:
        notes: list[str] = []
        for mutation in mutations or []:
            op = str(mutation.get("op", "")).strip().lower()
            path = str(mutation.get("path", "")).strip()
            if not op or not path:
                continue
            tokens = [part for part in path.split(".") if part]
            if not tokens:
                continue
            parent = entry
            for token in tokens[:-1]:
                if isinstance(parent, dict):
                    if token not in parent or not isinstance(parent[token], (dict, list)):
                        parent[token] = {}
                    parent = parent[token]
                elif isinstance(parent, list) and token.isdigit() and int(token) < len(parent):
                    parent = parent[int(token)]
                else:
                    parent = None
                    break
            if parent is None:
                notes.append(f"meta_mutation 未命中路径: {path}")
                continue

            leaf = tokens[-1]
            if op == "set":
                value = mutation.get("value")
                if isinstance(parent, dict):
                    parent[leaf] = value
                elif isinstance(parent, list) and leaf.isdigit() and int(leaf) < len(parent):
                    parent[int(leaf)] = value
                else:
                    notes.append(f"meta_mutation set 失败: {path}")
            elif op == "remove":
                removed = False
                if isinstance(parent, dict) and leaf in parent:
                    parent.pop(leaf, None)
                    removed = True
                elif isinstance(parent, list) and leaf.isdigit() and int(leaf) < len(parent):
                    parent.pop(int(leaf))
                    removed = True
                if not removed:
                    notes.append(f"meta_mutation remove 未命中: {path}")
            else:
                notes.append(f"meta_mutation 未支持操作: {op}@{path}")
        return notes

    def _is_dynamic_endpoint(self, entry: dict[str, Any]) -> bool:
        """判断端点是否依赖动态/服务端字段。"""
        validation = (entry.get("validation", {}) or {})
        dynamic_meta = (validation.get("dynamic", {}) or {})

        strong_dynamic_fields = {"nonce", "timestamp", "signature", "sign", "token", "rand", "random"}
        weak_dynamic_fields = {"key", "iv", "server_key", "server_iv", "message"}

        observed = (dynamic_meta.get("observed", {}) or {})
        if not observed:
            observed = (validation.get("dynamic_observed", {}) or {})
        observed_fields = {
            str(field).lower()
            for field in ((observed or {}).get("observed_dynamic_fields", []) or [])
            if str(field).strip()
        }
        strong_observed_fields = {
            str(field).lower()
            for field in ((observed or {}).get("strong_dynamic_fields", []) or [])
            if str(field).strip()
        }
        has_server_fetch_observed = bool((observed or {}).get("has_server_intermediate_fetch"))

        hint = (dynamic_meta.get("hint", {}) or {})
        if not hint:
            hint = ((entry.get("meta", {}) or {}).get("dynamic_endpoint_hint", {}) or {})
        hint_fields = {
            str(field).lower()
            for field in ((hint or {}).get("dynamic_fields", []) or [])
            if str(field).strip()
        }
        optional_pack_fields: set[str] = set()
        for step in ((entry.get("meta", {}) or {}).get("execution_flow", []) or []):
            if str(step.get("step_type", "")).lower() != "pack":
                continue
            packing_info = (step.get("runtime_args", {}) or {}).get("packing_info", {}) or {}
            for name in (packing_info.get("optional_fields", []) or []):
                if isinstance(name, str) and name.strip():
                    optional_pack_fields.add(name.strip().lower())
        hint_reasons = {
            str(reason).lower()
            for reason in ((hint or {}).get("reasons", []) or [])
            if str(reason).strip()
        }
        has_server_fetch_hint = bool((hint or {}).get("needs_server_intermediate")) or ("has_server_intermediate_fetch" in hint_reasons)

        # 两段式优先：服务端中间材料 / 强动态字段命中即判定动态。
        if has_server_fetch_observed or has_server_fetch_hint:
            return True
        if strong_observed_fields & strong_dynamic_fields:
            return True
        if (observed_fields & strong_dynamic_fields) and bool((observed or {}).get("observed")):
            return True
        hint_strong_fields = hint_fields & strong_dynamic_fields
        required_hint_strong = hint_strong_fields - optional_pack_fields
        if required_hint_strong:
            return True

        # key/iv/message 这种弱动态字段，只有在 hint 给出动态理由时才视为动态。
        weak_reason_tokens = {
            "has_random_or_timestamp_expression",
        }
        if (hint_fields & weak_dynamic_fields) and (hint_reasons & weak_reason_tokens):
            return True

        runtime_params = ((entry.get("validation", {}) or {}).get("runtime_params", {}) or {})
        # 旧产物兜底：若缺少 hint/observed，则只根据强动态字段兜底判定。
        dynamic_keys = strong_dynamic_fields | {"server_key", "server_iv"}
        if not hint and not observed and any(str(key).lower() in dynamic_keys for key in runtime_params.keys()):
            return True

        execution_flow = ((entry.get("meta", {}) or {}).get("execution_flow", []) or [])
        for step in execution_flow:
            step_type = str(step.get("step_type", "")).lower()
            if step_type.startswith("derive_"):
                target = step_type.replace("derive_", "").strip().lower()
                if target in {"nonce", "timestamp", "token", "signature", "random"}:
                    return True
                if target in {"key", "iv"}:
                    derivation = ((step.get("runtime_args", {}) or {}).get("derivation"))
                    derivation_text = json.dumps(derivation, ensure_ascii=False).lower() if isinstance(derivation, dict) else str(derivation or "").lower()
                    if any(token in derivation_text for token in ["math.random", "date.now", "wordarray.random", "timestamp", "nonce", "server"]):
                        return True
                continue
            if step_type == "sign":
                return True
            if step_type == "pack":
                packing_info = (step.get("runtime_args", {}) or {}).get("packing_info", {}) or {}
                structure = packing_info.get("structure", {}) or {}
                optional_fields = {
                    str(item).lower()
                    for item in (packing_info.get("optional_fields", []) or [])
                    if isinstance(item, str) and str(item).strip()
                }
                for field_name in structure.keys():
                    field_lc = str(field_name).lower()
                    if field_lc in {"timestamp", "signature", "nonce", "token", "sign"} and field_lc not in optional_fields:
                        return True

        # 兼容历史基线：若缺少 dynamic.hint/observed，尝试从 capture trace 与 hints 识别服务端中间材料请求。
        trace = (validation.get("trace", []) or [])
        for item in trace:
            if not isinstance(item, dict) or str(item.get("type")) != "FETCH":
                continue
            fetch_url = str(item.get("url") or "").lower()
            if any(token in fetch_url for token in ["generate_key", "get-signature", "server", "token"]):
                return True

        hints = (((entry.get("meta", {}) or {}).get("hints", []) or []))
        for hint_text in hints:
            text = str(hint_text).lower()
            if "fetch(" in text and any(token in text for token in ["generate_key", "get-signature", "server", "token"]):
                return True
        return False

    def _is_server_dependent_dynamic_endpoint(self, entry: dict[str, Any]) -> bool:
        """仅识别“动态且依赖服务端中间材料”的端点。"""
        if not self._is_dynamic_endpoint(entry):
            return False
        validation = (entry.get("validation", {}) or {})
        dynamic_meta = (validation.get("dynamic", {}) or {})

        observed = (dynamic_meta.get("observed", {}) or {})
        if not observed:
            observed = (validation.get("dynamic_observed", {}) or {})
        if isinstance(observed, dict) and observed:
            return bool((observed or {}).get("has_server_intermediate_fetch"))

        hint = (dynamic_meta.get("hint", {}) or {})
        if not hint:
            hint = ((entry.get("meta", {}) or {}).get("dynamic_endpoint_hint", {}) or {})
        if bool((hint or {}).get("needs_server_intermediate")):
            return True
        return False

    def _build_session_with_captured_context(self, entry: dict[str, Any]) -> Optional[Any]:
        """从阶段3 capture 回填的 cookie 构建 requests 会话，用于会话连续性发送。"""
        if requests is None:
            return None
        session = requests.Session()
        cookies = (((entry.get("validation", {}) or {}).get("session", {}) or {}).get("cookies", []) or [])
        for item in cookies:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            value = str(item.get("value") or "")
            if not name:
                continue
            # 对内网主机名（如 encrypt-labs-main）优先使用 host-only cookie，
            # 避免 requests 因 domain 属性不匹配而不发送 Cookie。
            session.cookies.set(name, value)
        return session

    def _skip_reason_code(self, reason: Optional[str]) -> Optional[str]:
        text = str(reason or "")
        if not text:
            return None
        if "payload 变异未映射到最终请求体" in text or "变异未映射到最终请求体" in text:
            return "MUTATION_NOT_EFFECTIVE"
        if (
            "未找到可篡改目标字段" in text
            or "无法执行协议篡改场景" in text
            or "请求头不支持重复字段动作" in text
            or "当前请求体格式不支持该篡改动作" in text
        ):
            return "UNMUTATABLE"
        return None

    def _fresh_capture_dynamic_entry(self, entry: dict[str, Any]) -> tuple[dict[str, Any], Optional[str]]:
        """动态端点按场景执行 fresh capture，避免复用旧动态参数。"""
        if not self.capture_page_url:
            return copy.deepcopy(entry), "动态端点未配置 capture_page_url，使用当前基线数据继续评估。"
        if not CAPTURE_SCRIPT_PATH.exists():
            return copy.deepcopy(entry), f"动态端点 fresh capture 跳过：未找到脚本 {CAPTURE_SCRIPT_PATH}"

        endpoint_id = str((entry.get("meta", {}) or {}).get("id") or "unknown")
        with tempfile.TemporaryDirectory(prefix="phase5_fresh_capture_") as tmp_dir:
            tmp_path = Path(tmp_dir) / f"baseline_single_{endpoint_id}.json"
            tmp_path.write_text(json.dumps([copy.deepcopy(entry)], ensure_ascii=False, indent=2), encoding="utf-8")

            cmd = [
                sys.executable,
                str(CAPTURE_SCRIPT_PATH),
                "--url",
                self.capture_page_url,
                "--skeleton",
                str(tmp_path),
            ]
            try:
                completed = subprocess.run(cmd, capture_output=True, text=True, timeout=max(45.0, self.timeout * 6))
            except Exception as exc:
                return copy.deepcopy(entry), f"动态端点 fresh capture 执行失败: {exc}"

            if completed.returncode != 0:
                stderr_preview = truncate_text((completed.stderr or completed.stdout or "").strip(), 180)
                return copy.deepcopy(entry), f"动态端点 fresh capture 失败(returncode={completed.returncode}): {stderr_preview}"

            try:
                updated_data = json.loads(tmp_path.read_text(encoding="utf-8"))
            except Exception as exc:
                return copy.deepcopy(entry), f"动态端点 fresh capture 结果解析失败: {exc}"

            if isinstance(updated_data, list) and updated_data:
                refreshed = updated_data[0]
                trace = ((refreshed.get("validation", {}) or {}).get("trace", []) or [])
                if trace:
                    return refreshed, "动态端点场景前 fresh capture 成功，已使用最新运行时参数。"

            return copy.deepcopy(entry), "动态端点 fresh capture 未产出有效 trace，回退使用当前基线数据。"

    async def _capture_single_entry_with_browser(self, browser: Any, entry: dict[str, Any]) -> tuple[dict[str, Any], Optional[str]]:
        """在同一 browser 进程中完成一次端点 fresh capture。"""
        if not self.capture_page_url:
            return copy.deepcopy(entry), "动态端点未配置 capture_page_url，使用当前基线数据继续评估。"

        hook_path = BASE_DIR / "runtime" / "playwright_hook.js"
        if not hook_path.exists():
            return copy.deepcopy(entry), f"动态端点 fresh capture 跳过：未找到 Hook {hook_path}"

        captured_data: list[dict[str, Any]] = []
        endpoint = copy.deepcopy(entry)
        meta = endpoint.get("meta", {}) or {}
        trigger_func = str(meta.get("trigger_function") or "")
        endpoint_url = str(meta.get("url") or "")
        payload = (endpoint.get("request", {}) or {}).get("payload", {}) or {}
        if not trigger_func or not endpoint_url:
            return endpoint, "动态端点 fresh capture 跳过：缺少 trigger_function 或 endpoint_url。"

        context = await browser.new_context()
        page = await context.new_page()
        try:
            hook_script = hook_path.read_text(encoding="utf-8")
            await context.add_init_script(hook_script)

            def _handle_console(msg: Any) -> None:
                text = str(msg.text or "")
                if not text.startswith("[CAPTURE:"):
                    return
                try:
                    parts = text.split(" ", 1)
                    if len(parts) != 2:
                        return
                    raw_type = parts[0].replace("[CAPTURE:", "").replace("]", "")
                    data = json.loads(parts[1])
                    data["type"] = raw_type
                    captured_data.append(data)
                except Exception:
                    return

            page.on("console", _handle_console)
            await page.goto(self.capture_page_url)
            try:
                await page.wait_for_function("typeof window.sendDataAes === 'function'", timeout=3500)
            except Exception:
                pass

            for key, value in payload.items():
                if str(key).startswith("_") or value == "<Fill Value>":
                    continue
                try:
                    locator = page.locator(f"#{key}")
                    if await locator.count() > 0:
                        await locator.fill(str(value))
                    else:
                        locator = page.locator(f"[name='{key}']")
                        if await locator.count() > 0:
                            await locator.fill(str(value))
                except Exception:
                    continue

            await page.evaluate(
                """
                async ({ funcName, targetUrl }) => {
                    if (typeof window[funcName] === 'function') {
                        const res = window[funcName](targetUrl);
                        if (res instanceof Promise) {
                            await res;
                        }
                        return;
                    }
                    const buttons = document.querySelectorAll('button[onclick]');
                    for (const btn of buttons) {
                        const attr = btn.getAttribute('onclick');
                        if (attr && attr.includes(funcName)) {
                            btn.click();
                            return;
                        }
                    }
                }
                """,
                {"funcName": trigger_func, "targetUrl": endpoint_url},
            )
            await page.wait_for_timeout(1800)

            valid_capture: dict[str, Any] = {}
            for cap in reversed(captured_data):
                ctype = str(cap.get("type") or "")
                if ctype.endswith("_OUTPUT") and "ciphertext" not in valid_capture:
                    valid_capture["ciphertext"] = cap.get("ciphertext")
                elif ctype in {"AES", "DES", "RSA", "HMAC"}:
                    for name in ["key", "iv", "message", "mode"]:
                        if name in cap and name not in valid_capture:
                            valid_capture[name] = cap.get(name)

            endpoint.setdefault("validation", {})
            endpoint["validation"].setdefault("dynamic", {})
            endpoint["validation"].setdefault("session", {})
            endpoint["validation"]["trace"] = list(captured_data)
            endpoint["validation"]["runtime_params"] = {k: v for k, v in valid_capture.items() if k != "ciphertext"}
            endpoint["validation"]["dynamic"]["observed"] = build_dynamic_observed(captured_data, valid_capture)
            endpoint["validation"]["session"]["cookies"] = await context.cookies()
            if "ciphertext" in valid_capture:
                endpoint["validation"]["captured_ciphertext"] = valid_capture.get("ciphertext")

            if endpoint["validation"].get("trace"):
                return endpoint, "动态端点场景前 fresh capture 成功（单浏览器并发模式）。"
            return copy.deepcopy(entry), "动态端点 fresh capture 无有效 trace，回退使用当前基线数据。"
        except Exception as exc:
            return copy.deepcopy(entry), f"动态端点 fresh capture 执行失败: {exc}"
        finally:
            await context.close()

    async def _fresh_capture_dynamic_entries_parallel_async(
        self,
        entry: dict[str, Any],
        count: int,
        concurrency: int = 4,
    ) -> list[tuple[dict[str, Any], Optional[str]]]:
        """单浏览器进程内并发执行多场景 fresh capture。"""
        if async_playwright is None:
            return [self._fresh_capture_dynamic_entry(entry) for _ in range(count)]

        results: list[tuple[dict[str, Any], Optional[str]]] = [
            (copy.deepcopy(entry), "动态端点 fresh capture 未执行。") for _ in range(count)
        ]
        sem = asyncio.Semaphore(max(1, int(concurrency)))
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                async def _worker(index: int) -> None:
                    async with sem:
                        results[index] = await self._capture_single_entry_with_browser(browser, entry)

                await asyncio.gather(*[_worker(i) for i in range(count)])
            finally:
                await browser.close()
        return results

    def _fresh_capture_dynamic_entries_parallel(
        self,
        entry: dict[str, Any],
        count: int,
        concurrency: int = 4,
    ) -> list[tuple[dict[str, Any], Optional[str]]]:
        """同步包装：为服务端依赖型动态端点提供场景并发 fresh capture。"""
        if count <= 0:
            return []
        try:
            return asyncio.run(self._fresh_capture_dynamic_entries_parallel_async(entry, count, concurrency=concurrency))
        except Exception:
            return [self._fresh_capture_dynamic_entry(entry) for _ in range(count)]

    def _build_local_gate(self, status: str, skip_reason: Optional[str], local_success: bool, used_capture_preview: bool) -> dict[str, Any]:
        """本地仅做门控分类，不参与预期命中判定。"""
        skip_code = self._skip_reason_code(skip_reason)
        if skip_code == "UNMUTATABLE":
            return {"dimension": "executability", "code": "UNMUTATABLE", "note": "场景无法落地变异，跳过发送"}
        if skip_code == "MUTATION_NOT_EFFECTIVE":
            return {"dimension": "effectiveness", "code": "MUTATION_NOT_EFFECTIVE", "note": "变异未进入最终发送包，跳过发送"}
        if (not local_success) and used_capture_preview and status in {"LOCAL_OK", "REMOTE_SENT"}:
            return {"dimension": "dependency_completeness", "code": "RUNTIME_DEP_MISSING", "note": "本地依赖缺失，已使用 capture 回退继续评估"}
        if status == "REMOTE_SENT":
            return {"dimension": "executability", "code": "SENDABLE", "note": "场景已完成构包并发送"}
        if status == "LOCAL_FAILED":
            return {"dimension": "executability", "code": "LOCAL_EXECUTION_ERROR", "note": "本地执行失败，未发送"}
        if status == "SKIPPED":
            return {"dimension": "executability", "code": "SKIPPED_OTHER", "note": "场景跳过，请查看 skip_reason"}
        return {"dimension": "executability", "code": "LOCAL_OK", "note": "本地构包成功"}

    def _run_scenario(self, entry: dict[str, Any], base_payload: dict[str, Any], scenario: dict[str, Any], baseline_request_preview: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        scenario_entry = copy.deepcopy(entry)
        observations = self._apply_meta_mutations(scenario_entry, scenario.get("meta_mutations", []) or [])
        payload = self._materialize_payload(base_payload, scenario)
        executor = LocalFlowExecutor(scenario_entry)
        strict_baseline = self.strict_baseline_replay and str(scenario.get("scenario_id")) == "baseline_replay"
        allow_captured_fallback = bool(scenario.get("allow_captured_message_fallback")) and (not strict_baseline)
        removed_fields = {
            str(item)
            for item in ((scenario.get("payload_mutation", {}) or {}).get("remove", []) or [])
            if str(item)
        }
        local_result = executor.execute(
            payload,
            allow_captured_message_fallback=allow_captured_fallback,
            removed_fields=removed_fields,
        )
        request_preview = local_result.get("request_preview")
        skip_reason = None
        status = "LOCAL_OK" if local_result.get("success") else "LOCAL_FAILED"
        used_capture_preview = False
        is_dynamic_endpoint = self._is_dynamic_endpoint(entry)
        allow_capture_preview_fallback = is_dynamic_endpoint and bool(self.capture_page_url) and (not strict_baseline)
        if strict_baseline:
            observations.append("strict_baseline_replay: disabled captured-message and capture-preview fallback.")

        # 对仅打包/服务端签名类端点，execution_flow 可能不含 pack，
        # 在本地执行成功但缺少 request_preview 时，允许非严格模式回退到 capture 包。
        if allow_capture_preview_fallback and bool(local_result.get("success")) and (not request_preview or not request_preview.get("send_ready")):
            fallback_preview = self._build_captured_request_preview(scenario_entry)
            if fallback_preview:
                request_preview = fallback_preview
                used_capture_preview = True
                observations.append("本地无可发送请求体，已回退使用 capture trace 中的 FETCH body。")

        # 请求体仍含占位符时，回退 capture 请求体，避免把未填充值直接发往服务端。
        if allow_capture_preview_fallback and self._request_preview_has_placeholder(request_preview):
            fallback_preview = self._build_captured_request_preview(scenario_entry)
            if fallback_preview and fallback_preview.get("send_ready"):
                request_preview = fallback_preview
                used_capture_preview = True
                observations.append("请求体含占位符，已回退使用 capture 请求体。")

        # 动态端点本地失败时，允许基于 capture 请求体继续变异并在线验证。
        if (not local_result.get("success")) and allow_capture_preview_fallback:
            fallback_preview = self._build_captured_request_preview(scenario_entry)
            if fallback_preview and fallback_preview.get("send_ready"):
                request_preview = fallback_preview
                used_capture_preview = True
                status = "LOCAL_OK"
                observations.append("动态端点本地失败：使用 capture 请求体继续在线验证。")

        payload_mutation = scenario.get("payload_mutation", {}) or {}
        has_payload_mutation = bool((payload_mutation.get("set") or {})) or bool((payload_mutation.get("remove") or []))
        has_meta_mutation = bool(scenario.get("meta_mutations") or [])
        has_request_tamper = bool(scenario.get("request_tamper"))

        request_tamper = scenario.get("request_tamper")
        if request_tamper:
            if not local_result.get("success"):
                observations.append("本地明确失败：禁用 capture 包回退，避免污染在线验证。")
            if request_preview and request_preview.get("send_ready"):
                tamper_result = self._apply_request_tamper(request_preview, request_tamper, scenario_entry)
                if tamper_result.get("success"):
                    request_preview = tamper_result.get("request_preview")
                    observations.append(tamper_result.get("reason"))
                    if status != "LOCAL_FAILED":
                        status = "LOCAL_OK"
                else:
                    status = "SKIPPED"
                    skip_reason = tamper_result.get("reason")
                    observations.append(skip_reason)
            else:
                status = "SKIPPED"
                skip_reason = "缺少可用请求体，无法执行协议篡改场景。"
                observations.append(skip_reason)

        # 统一变异有效性门控：有变异意图但最终请求包与参考包相同，判定为 MUTATION_NOT_EFFECTIVE。
        has_mutation_intent = has_payload_mutation or has_meta_mutation or has_request_tamper
        if (
            status != "SKIPPED"
            and scenario.get("scenario_id") != "baseline_replay"
            and has_mutation_intent
            and request_preview
            and baseline_request_preview
            and self._has_materialized_request_body(request_preview)
            and self._has_materialized_request_body(baseline_request_preview)
            and self._request_preview_equal(request_preview, baseline_request_preview)
        ):
            status = "SKIPPED"
            skip_reason = "变异未映射到最终请求体（MUTATION_NOT_EFFECTIVE）。"
            observations.append(skip_reason)

        if local_result.get("limitations"):
            observations.extend(local_result.get("limitations"))
            if status == "SKIPPED" and not skip_reason:
                skip_reason = next((item for item in local_result.get("limitations", []) if item), None)

        remote_result = {"attempted": False, "status_code": None, "elapsed_ms": None, "body_preview": None, "error": None}
        if status == "LOCAL_OK" and request_preview and request_preview.get("send_ready"):
            remote_result = self._send_request(scenario_entry, request_preview, use_session_context=True)
            remote_result["response_layers"] = build_response_layers(remote_result)
            remote_result["response_mode"] = classify_response_mode(remote_result)
            if remote_result.get("attempted") and remote_result.get("status_code") is not None:
                status = "REMOTE_SENT"
            elif remote_result.get("error"):
                observations.append(remote_result["error"])
        else:
            remote_result["response_layers"] = build_response_layers(remote_result)
            remote_result["response_mode"] = classify_response_mode(remote_result)

        if status == "SKIPPED" and not skip_reason:
            skip_reason = next((item for item in observations if item), None)

        expectation = evaluate_scenario_expectation(
            scenario=scenario,
            status=status,
            remote_result=remote_result,
        )

        return {
            "scenario_id": scenario["scenario_id"],
            "category": scenario["category"],
            "title": scenario["title"],
            "description": scenario["description"],
            "status": status,
            "skip_reason": skip_reason,
            "expected_outcome": scenario.get("expected_outcome"),
            "expectation": expectation,
            "payload": payload,
            "local_replay": {
                "success": bool(local_result.get("success")),
                "error": local_result.get("error"),
                "named_outputs": local_result.get("named_outputs", {}),
                "final_output_preview": truncate_text(local_result.get("final_output"), 120),
            },
            "local_gate": self._build_local_gate(status, skip_reason, bool(local_result.get("success")), used_capture_preview),
            "request_preview": request_preview,
            "remote_result": remote_result,
            "observations": observations,
            "interlayer_key_scenario": bool(scenario.get("interlayer_key_scenario")),
            "interlayer_layers": copy.deepcopy(scenario.get("interlayer_layers", [])),
            "diagnostic_tags": [tag for tag in ["INTERLAYER_KEY_SCENARIO" if bool(scenario.get("interlayer_key_scenario")) else ""] if tag],
        }

    def _request_preview_equal(self, left: Optional[dict[str, Any]], right: Optional[dict[str, Any]]) -> bool:
        if not left or not right:
            return False
        if left.get("body_type") != right.get("body_type"):
            return False

        def canonical_body(preview: dict[str, Any]) -> str:
            body_json = preview.get("body_json")
            if isinstance(body_json, dict):
                return json.dumps(body_json, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            body_text = preview.get("body_text")
            if isinstance(body_text, str) and body_text.strip() != "":
                return body_text.strip()
            resolved = preview.get("resolved_fields")
            if isinstance(resolved, dict) and resolved:
                headers = preview.get("headers") if isinstance(preview.get("headers"), dict) else {}
                content_type = str((headers or {}).get("Content-Type") or (headers or {}).get("content-type") or "").lower()
                if "json" in content_type:
                    return json.dumps(resolved, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                return urllib.parse.urlencode(sorted((str(k), "" if v is None else str(v)) for k, v in resolved.items()))
            return ""

        if canonical_body(left) != canonical_body(right):
            return False

        def signature_headers(headers: Any) -> dict[str, str]:
            if not isinstance(headers, dict):
                return {}
            picked = {}
            for k, v in headers.items():
                key_lc = str(k).strip().lower()
                if key_lc in {"x-signature", "signature", "x-sign"}:
                    picked[key_lc] = str(v)
            return picked

        return signature_headers(left.get("headers")) == signature_headers(right.get("headers"))

    def _has_materialized_request_body(self, preview: Optional[dict[str, Any]]) -> bool:
        if not preview:
            return False
        body_json = preview.get("body_json")
        if isinstance(body_json, dict) and len(body_json) > 0:
            return True
        body_text = preview.get("body_text")
        if isinstance(body_text, str) and body_text.strip() != "":
            return True
        return False

    def _build_captured_request_preview(self, entry: dict[str, Any]) -> Optional[dict[str, Any]]:
        trace = entry.get("validation", {}).get("trace", []) or []
        headers = copy.deepcopy(entry.get("request", {}).get("headers", {}) or {})
        for item in reversed(trace):
            if not isinstance(item, dict) or item.get("type") != "FETCH":
                continue
            body = item.get("body")
            if body is None:
                continue
            if isinstance(body, str):
                stripped = body.strip()
                if stripped.startswith("{") and stripped.endswith("}"):
                    try:
                        body_json = json.loads(stripped)
                        return {"body_type": "json", "headers": headers, "resolved_fields": copy.deepcopy(body_json), "missing_fields": [], "body_text": stripped, "body_json": body_json, "send_ready": True}
                    except json.JSONDecodeError:
                        pass
                return {"body_type": "url_search_params" if "=" in stripped else "raw_text", "headers": headers, "resolved_fields": {}, "missing_fields": [], "body_text": stripped, "body_json": None, "send_ready": True}
        return None

    def _extract_identifier_names_from_derivation(self, node: Any) -> set[str]:
        names: set[str] = set()
        if isinstance(node, dict):
            node_type = str(node.get("type") or "")
            if node_type == "identifier":
                name = str(node.get("name") or "").strip()
                if name:
                    names.add(name)
            for key in ["input", "left", "right"]:
                names.update(self._extract_identifier_names_from_derivation(node.get(key)))
            for arg in (node.get("args", []) or []):
                names.update(self._extract_identifier_names_from_derivation(arg))
        elif isinstance(node, list):
            for item in node:
                names.update(self._extract_identifier_names_from_derivation(item))
        return names

    def _collect_pack_lineage_map(self, entry: dict[str, Any], available_fields: set[str]) -> dict[str, set[str]]:
        lineage: dict[str, set[str]] = {}
        execution_flow = ((entry.get("meta", {}) or {}).get("execution_flow", []) or [])
        for step in execution_flow:
            if str(step.get("step_type", "")).lower() != "pack":
                continue
            packing_info = (step.get("runtime_args", {}) or {}).get("packing_info", {}) or {}
            structure = packing_info.get("structure", {}) or {}
            field_sources = packing_info.get("field_sources", {}) or {}
            value_derivations = packing_info.get("value_derivations", {}) or {}
            for field_name, raw_source in structure.items():
                field = str(field_name)
                if field not in available_fields:
                    continue
                refs = lineage.setdefault(field, set())
                source_name = str(raw_source or "").strip()
                if source_name:
                    refs.add(source_name)
                source_meta = field_sources.get(field_name, {}) if isinstance(field_sources, dict) else {}
                if isinstance(source_meta, dict):
                    for key in ["source_name", "bridge_from_output"]:
                        value = str(source_meta.get(key) or "").strip()
                        if value:
                            refs.add(value)
                    refs.update(self._extract_identifier_names_from_derivation(source_meta.get("derivation")))
                if source_name and isinstance(value_derivations, dict):
                    refs.update(self._extract_identifier_names_from_derivation(value_derivations.get(source_name)))
        return lineage

    def _collect_tamper_candidates(
        self,
        preview: dict[str, Any],
        fields: list[str],
        entry: Optional[dict[str, Any]] = None,
        allow_aliases: bool = True,
        allow_fallback: bool = True,
        exclude_fields: Optional[set[str]] = None,
        strict_target_only: bool = False,
    ) -> list[str]:
        available = set()
        body_json = preview.get("body_json")
        body_text = preview.get("body_text")
        if isinstance(body_json, dict):
            available.update(str(key) for key in body_json.keys())
        if isinstance(body_text, str) and "=" in body_text:
            for key, _ in urllib.parse.parse_qsl(body_text, keep_blank_values=True):
                available.add(str(key))
        resolved_fields = preview.get("resolved_fields")
        if isinstance(resolved_fields, dict):
            available.update(str(key) for key in resolved_fields.keys())
        headers = preview.get("headers") if isinstance(preview.get("headers"), dict) else {}
        if isinstance(headers, dict):
            for key in headers.keys():
                key_text = str(key)
                key_lc = key_text.lower()
                available.add(key_text)
                available.add(key_lc)
                if key_lc in {"x-signature", "signature", "x-sign"}:
                    available.update({"signature", "sign", "sig", "x-signature", "x-sign", "mac", "token"})

        excluded = {str(item).lower() for item in (exclude_fields or set()) if str(item).strip()}

        requested_names = set()
        for base in fields:
            base_name = str(base)
            if base_name and base_name.lower() not in excluded:
                requested_names.add(base_name)
            if allow_aliases:
                for alias in TAMPER_FIELD_ALIASES.get(base_name, []):
                    if str(alias).lower() not in excluded:
                        requested_names.add(str(alias))
        requested_names_lc = {str(name).lower() for name in requested_names}
        requested_cipher_like = bool(requested_names_lc & {"encrypteddata", "encrypted", "ciphertext", "cipher", "data", "payload", "random"})
        requested_signature_like = bool(requested_names_lc & {"signature", "sign", "sig", "token", "mac", "hmac", "x-signature", "x-sign"})

        crypto_outputs: set[str] = set()
        sign_outputs: set[str] = set()
        pack_lineage: dict[str, set[str]] = {}
        if entry:
            execution_flow = ((entry.get("meta", {}) or {}).get("execution_flow", []) or [])
            for step in execution_flow:
                step_type = str(step.get("step_type", "")).lower()
                output_var = str(step.get("output_variable") or "").strip()
                if step_type == "encrypt" and output_var:
                    crypto_outputs.add(output_var)
                if step_type == "sign" and output_var:
                    sign_outputs.add(output_var)
            pack_lineage = self._collect_pack_lineage_map(entry, available)

        candidates: list[str] = []
        for base in fields:
            alias_names = TAMPER_FIELD_ALIASES.get(str(base), []) if allow_aliases else []
            for name in [base, *alias_names]:
                if str(name).lower() in excluded:
                    continue
                if name in available and name not in candidates:
                    candidates.append(name)

        if not strict_target_only:
            for field_name, refs in pack_lineage.items():
                if field_name in candidates:
                    continue
                if str(field_name).lower() in excluded:
                    continue
                if refs & requested_names:
                    candidates.append(str(field_name))
                    continue
                # 仅在请求目标本身是密文字段时，才允许 encrypt-output 映射。
                if requested_cipher_like and (refs & crypto_outputs):
                    candidates.append(str(field_name))
                    continue
                if requested_signature_like and (refs & sign_outputs):
                    candidates.append(str(field_name))

        if not candidates and allow_fallback and (not strict_target_only):
            fallback_priority = ["signature", "nonce", "timestamp", "encryptedData", "data", "random"]
            for key in fallback_priority:
                if str(key).lower() in excluded:
                    continue
                if key in available and key not in candidates:
                    candidates.append(key)
        return candidates

    def _rebuild_preview_from_field_map(self, preview: dict[str, Any], field_map: dict[str, Any]) -> dict[str, Any]:
        cloned = copy.deepcopy(preview)
        body_type = str(cloned.get("body_type") or "")
        headers = cloned.get("headers") if isinstance(cloned.get("headers"), dict) else {}
        content_type = str((headers or {}).get("Content-Type") or (headers or {}).get("content-type") or "").lower()
        cloned["resolved_fields"] = copy.deepcopy(field_map)

        if body_type == "json" or "json" in content_type:
            cloned["body_json"] = copy.deepcopy(field_map)
            cloned["body_text"] = json.dumps(field_map, ensure_ascii=False)
            cloned["send_ready"] = True
            return cloned

        if body_type in {"url_search_params", "template", "raw_text", ""}:
            cloned["body_json"] = None
            cloned["body_text"] = urllib.parse.urlencode([(str(k), "" if v is None else str(v)) for k, v in field_map.items()])
            cloned["send_ready"] = True
            return cloned

        return cloned

    def _truncate_field_value(self, value: Any, length: int) -> str:
        text = "" if value is None else str(value)
        target = max(1, int(length))
        # 常规截断策略：保留左侧前 N 位。
        if len(text) > target:
            return text[:target]
        # 当原值已短于 N 时，仍做一次最小缩短，保证变异有效。
        if len(text) <= 1:
            return ""
        return text[:-1]

    def _build_json_body_with_duplicate_field(self, field_map: dict[str, Any], field_name: str, duplicate_value: Any) -> str:
        """构造可重复键的 JSON 原始文本，用于 duplicate_field 场景。"""
        tokens: list[str] = []
        for key, value in field_map.items():
            tokens.append(f"{json.dumps(str(key), ensure_ascii=False)}:{json.dumps(value, ensure_ascii=False)}")
        dup_val = duplicate_value if duplicate_value is not None else field_map.get(field_name, "")
        tokens.append(f"{json.dumps(str(field_name), ensure_ascii=False)}:{json.dumps(dup_val, ensure_ascii=False)}")
        return "{" + ",".join(tokens) + "}"

    def _apply_request_tamper(self, preview: dict[str, Any], tamper: dict[str, Any], entry: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        cloned = copy.deepcopy(preview)
        body_json = cloned.get("body_json")
        body_text = cloned.get("body_text")
        action = tamper.get("action")
        strict_fields = bool(tamper.get("strict_fields", False))
        disable_fallback = bool(tamper.get("disable_fallback", False))
        strict_target_only = bool(tamper.get("strict_target_only", False))
        raw_exclude = tamper.get("exclude_fields", [])
        exclude_fields: set[str] = set()
        if isinstance(raw_exclude, list):
            exclude_fields = {str(item) for item in raw_exclude if str(item).strip()}
        fields = self._collect_tamper_candidates(
            cloned,
            tamper.get("fields", []) or [],
            entry,
            allow_aliases=not strict_fields,
            allow_fallback=not disable_fallback,
            exclude_fields=exclude_fields,
            strict_target_only=strict_target_only,
        )
        replacement = tamper.get("value")
        length = int(tamper.get("length", 12))

        headers_obj = cloned.get("headers") if isinstance(cloned.get("headers"), dict) else {}
        header_name_index = {str(key).lower(): key for key in headers_obj.keys()}

        def _resolve_header_target(field_name: str) -> Optional[str]:
            # 中文注释：签名字段可能放在 Header，需要和 body 字段统一处理。
            low = str(field_name).strip().lower()
            if not low:
                return None
            direct = header_name_index.get(low)
            if direct:
                return direct
            if low in {"signature", "sign", "sig", "mac", "token", "x-signature", "x-sign"}:
                for candidate in ["x-signature", "signature", "x-sign"]:
                    hit = header_name_index.get(candidate)
                    if hit:
                        return hit
            return None

        def _tamper_header(field_name: str) -> Optional[dict[str, Any]]:
            target = _resolve_header_target(field_name)
            if not target:
                return None
            if action == "remove_field":
                headers_obj.pop(target, None)
                cloned["headers"] = headers_obj
                return {"success": True, "request_preview": cloned, "reason": f"已移除请求头 {target}"}
            if action == "overwrite_field":
                headers_obj[target] = str(replacement if replacement is not None else "")
                cloned["headers"] = headers_obj
                return {"success": True, "request_preview": cloned, "reason": f"已覆写请求头 {target}"}
            if action == "truncate_field":
                headers_obj[target] = self._truncate_field_value(headers_obj.get(target), length)
                cloned["headers"] = headers_obj
                return {"success": True, "request_preview": cloned, "reason": f"已截断请求头 {target}"}
            if action == "duplicate_field":
                return {"success": False, "reason": f"请求头不支持重复字段动作（目标: {target}）。"}
            return None

        field_map: dict[str, Any] = {}
        source_mode = "none"
        if isinstance(body_json, dict):
            field_map = copy.deepcopy(body_json)
            source_mode = "json"
        elif isinstance(body_text, str) and "=" in body_text:
            field_map = {k: v for k, v in urllib.parse.parse_qsl(body_text, keep_blank_values=True)}
            source_mode = "urlencoded"
        elif isinstance(cloned.get("resolved_fields"), dict):
            field_map = copy.deepcopy(cloned.get("resolved_fields") or {})
            source_mode = "resolved"

        if field_map:
            for field_name in fields:
                if field_name not in field_map:
                    header_result = _tamper_header(field_name)
                    if header_result is not None:
                        return header_result
                    continue
                if action == "remove_field":
                    field_map.pop(field_name, None)
                    return {"success": True, "request_preview": self._rebuild_preview_from_field_map(cloned, field_map), "reason": f"已移除字段 {field_name}"}
                if action == "overwrite_field":
                    field_map[field_name] = replacement
                    return {"success": True, "request_preview": self._rebuild_preview_from_field_map(cloned, field_map), "reason": f"已覆写字段 {field_name}"}
                if action == "truncate_field":
                    field_map[field_name] = self._truncate_field_value(field_map[field_name], length)
                    return {"success": True, "request_preview": self._rebuild_preview_from_field_map(cloned, field_map), "reason": f"已截断字段 {field_name}"}
                if action == "duplicate_field":
                    if source_mode == "json":
                        cloned["body_json"] = None
                        cloned["body_text"] = self._build_json_body_with_duplicate_field(
                            field_map,
                            field_name,
                            replacement,
                        )
                        cloned["send_ready"] = True
                        return {
                            "success": True,
                            "request_preview": cloned,
                            "reason": f"已在 JSON 原始体追加重复字段 {field_name}",
                        }
                    pairs = urllib.parse.parse_qsl(cloned.get("body_text") or "", keep_blank_values=True)
                    pairs.append((field_name, str(replacement if replacement is not None else field_map.get(field_name, ""))))
                    cloned["body_text"] = urllib.parse.urlencode(pairs)
                    return {"success": True, "request_preview": cloned, "reason": f"已追加重复字段 {field_name}"}
            if source_mode == "json":
                return {"success": False, "reason": f"JSON 请求体中未找到可篡改目标字段（候选: {fields or 'none'}）。"}
            if source_mode in {"urlencoded", "resolved"}:
                return {"success": False, "reason": f"URL 编码请求体中未找到可篡改目标字段（候选: {fields or 'none'}）。"}

        for field_name in fields:
            header_result = _tamper_header(field_name)
            if header_result is not None:
                return header_result

        if isinstance(body_text, str) and "=" in body_text:
            pairs = urllib.parse.parse_qsl(body_text, keep_blank_values=True)
            if not pairs:
                return {"success": False, "reason": "无法解析 URL 编码请求体。"}
            for field_name in fields:
                for index, (key, value) in enumerate(pairs):
                    if key != field_name:
                        continue
                    if action == "remove_field":
                        pairs.pop(index)
                        cloned["body_text"] = urllib.parse.urlencode(pairs)
                        return {"success": True, "request_preview": cloned, "reason": f"已移除字段 {field_name}"}
                    if action == "overwrite_field":
                        pairs[index] = (key, str(replacement))
                        cloned["body_text"] = urllib.parse.urlencode(pairs)
                        return {"success": True, "request_preview": cloned, "reason": f"已覆写字段 {field_name}"}
                    if action == "truncate_field":
                        pairs[index] = (key, self._truncate_field_value(value, length))
                        cloned["body_text"] = urllib.parse.urlencode(pairs)
                        return {"success": True, "request_preview": cloned, "reason": f"已截断字段 {field_name}"}
                    if action == "duplicate_field":
                        pairs.append((key, str(replacement if replacement is not None else value)))
                        cloned["body_text"] = urllib.parse.urlencode(pairs)
                        return {"success": True, "request_preview": cloned, "reason": f"已追加重复字段 {field_name}"}
            return {"success": False, "reason": f"URL 编码请求体中未找到可篡改目标字段（候选: {fields or 'none'}）。"}

        return {"success": False, "reason": "当前请求体格式不支持该篡改动作。"}

    def _send_request(self, entry: dict[str, Any], request_preview: dict[str, Any], use_session_context: bool = True) -> dict[str, Any]:
        if requests is None:
            return {"attempted": False, "status_code": None, "elapsed_ms": None, "body_preview": None, "error": "requests 未安装，无法发送真实请求。"}
        url = request_preview.get("url_override") or entry.get("meta", {}).get("url")
        method = entry.get("meta", {}).get("method", "POST")
        headers = copy.deepcopy(request_preview.get("headers", {}) or {})
        try:
            started = datetime.now(timezone.utc)
            sender = requests
            session = None
            if use_session_context:
                session = self._build_session_with_captured_context(entry)
                if session is not None:
                    sender = session
            if request_preview.get("body_type") == "json" and request_preview.get("body_json") is not None:
                response = sender.request(method, url, headers=headers, json=request_preview["body_json"], timeout=self.timeout)
            else:
                response = sender.request(method, url, headers=headers, data=request_preview.get("body_text"), timeout=self.timeout)
            elapsed = (datetime.now(timezone.utc) - started).total_seconds() * 1000
            if session is not None:
                session.close()
            return {"attempted": True, "status_code": response.status_code, "elapsed_ms": round(elapsed, 2), "body_preview": truncate_text(response.text, 300), "error": None}
        except Exception as exc:
            return {"attempted": True, "status_code": None, "elapsed_ms": None, "body_preview": None, "error": f"真实请求发送失败: {exc}"}

    def _evaluate_session_binding(self, entry: dict[str, Any], scenario_results: list[dict[str, Any]]) -> dict[str, Any]:
        """仅对服务端依赖型动态端点做跨会话重放探测。"""
        if not self._is_server_dependent_dynamic_endpoint(entry):
            return {"applicable": False, "assessed": False, "missing": None, "reason": "not_server_dependent_dynamic"}

        baseline = next((item for item in scenario_results if str(item.get("scenario_id")) == "baseline_replay"), None)
        if not baseline:
            return {"applicable": True, "assessed": False, "missing": None, "reason": "baseline_replay_missing"}

        request_preview = baseline.get("request_preview") or {}
        remote_result = baseline.get("remote_result") or {}
        if not request_preview.get("send_ready"):
            return {"applicable": True, "assessed": False, "missing": None, "reason": "baseline_not_send_ready"}
        if not remote_result.get("attempted"):
            return {"applicable": True, "assessed": False, "missing": None, "reason": "baseline_not_attempted"}

        no_session_result = self._send_request(entry, request_preview, use_session_context=False)
        no_session_result["response_layers"] = build_response_layers(no_session_result)
        no_session_result["response_mode"] = classify_response_mode(no_session_result)

        baseline_mode = str(remote_result.get("response_mode") or "")
        without_session_mode = str(no_session_result.get("response_mode") or "")
        baseline_status = remote_result.get("status_code")
        without_session_status = no_session_result.get("status_code")
        same_status_class = (
            isinstance(baseline_status, int)
            and isinstance(without_session_status, int)
            and (baseline_status // 100) == (without_session_status // 100)
        )

        missing = bool(
            without_session_mode == "APP_SUCCESS"
            or (
                baseline_mode
                and without_session_mode
                and baseline_mode == without_session_mode
                and same_status_class
                and baseline_mode != "APP_REPLAY_REJECT"
            )
        )
        return {
            "applicable": True,
            "assessed": True,
            "missing": missing,
            "baseline_mode": baseline_mode,
            "without_session_mode": without_session_mode,
            "without_session_status": no_session_result.get("status_code"),
            "without_session_body": no_session_result.get("body_preview"),
        }

    def _calculate_security_score(
        self,
        findings: list[dict[str, Any]],
        baseline_gaps: list[dict[str, Any]],
        scenarios: list[dict[str, Any]],
        is_special_path: bool = False,
        interlayer_effectiveness: Optional[dict[str, Any]] = None,
    ) -> tuple[float, dict[str, Any]]:
        base_score = float(self.scoring_profile.get("base_score", 100.0))
        severity_penalties = self.scoring_profile.get("severity_penalties", {}) or {}
        category_multipliers = self.scoring_profile.get("finding_category_multipliers", {}) or {}
        scenario_status_penalties = self.scoring_profile.get("scenario_status_penalties", {}) or {}
        scenario_category_multipliers = self.scoring_profile.get("scenario_category_multipliers", {}) or {}
        expectation_mismatch_penalties = self.scoring_profile.get("expectation_mismatch_penalties", {}) or {}
        baseline_gap_penalty = self.scoring_profile.get("baseline_gap_penalty", {}) or {}
        interlayer_scoring = self.scoring_profile.get("interlayer_scoring", {}) or {}
        state_multipliers = interlayer_scoring.get("state_multipliers", {}) if isinstance(interlayer_scoring, dict) else {}
        endpoint_penalties = interlayer_scoring.get("endpoint_penalties", {}) if isinstance(interlayer_scoring, dict) else {}
        interlayer_state = str((interlayer_effectiveness or {}).get("state") or "no_interlayer")
        interlayer_multiplier = float(state_multipliers.get(interlayer_state, state_multipliers.get("no_interlayer", 1.0)))
        interlayer_endpoint_penalty = float(endpoint_penalties.get(interlayer_state, endpoint_penalties.get("no_interlayer", 0.0)))

        finding_deductions = []
        scenario_deductions = []
        total_findings = 0.0
        total_scenarios = 0.0
        layer_weights = self.scoring_profile.get("layer_score_weights", {}) or {}
        protocol_weight = float(layer_weights.get("protocol", 0.5))
        business_weight = float(layer_weights.get("business", 0.5))
        total_weight = protocol_weight + business_weight if (protocol_weight + business_weight) > 0 else 1.0
        protocol_weight /= total_weight
        business_weight /= total_weight
        layer_deductions = {"protocol": 0.0, "business": 0.0}

        for finding in findings:
            severity = str(finding.get("severity", "info"))
            category = str(finding.get("category", "default"))
            severity_value = float(severity_penalties.get(severity, 0.0))
            category_multiplier = self._lookup_weight(category_multipliers, category, 1.0)
            deduction = round(severity_value * category_multiplier, 2)
            total_findings += deduction
            layer_name = FINDING_LAYER_MAP.get(category, "business")
            layer_deductions[layer_name] += deduction
            finding_deductions.append({
                "finding_id": finding.get("id"),
                "severity": severity,
                "category": category,
                "severity_penalty": severity_value,
                "category_multiplier": category_multiplier,
                "deduction": deduction,
            })

        # 场景扣分新口径：仅由远程预期命中驱动。
        # 门控不可变异场景免罚且不占权重；其余场景预算重分配到成功发起远程请求的场景。
        gate_exempt_scenarios: list[dict[str, Any]] = []
        scored_pool: list[dict[str, Any]] = []
        participants: list[dict[str, Any]] = []
        scenario_budget_total = 0.0

        for scenario in scenarios:
            status = str(scenario.get("status", "LOCAL_OK"))
            category = str(scenario.get("category", "default"))
            skip_code = self._skip_reason_code(scenario.get("skip_reason"))
            expectation = scenario.get("expectation", {}) or {}
            remote_result = scenario.get("remote_result", {}) or {}

            if skip_code in {"UNMUTATABLE", "MUTATION_NOT_EFFECTIVE"}:
                gate_exempt_scenarios.append(scenario)
                scenario_deductions.append({
                    "scenario_id": scenario.get("scenario_id"),
                    "status": status,
                    "category": category,
                    "deduction_reason": skip_code,
                    "deduction": 0.0,
                    "gate_exempt": True,
                })
                continue

            base_mismatch_penalty = float(expectation_mismatch_penalties.get(category, expectation_mismatch_penalties.get("default", 0.0)))
            scenario_budget_total += max(base_mismatch_penalty, 0.0)
            scored_pool.append(scenario)

            
        

        for scenario in scenarios:
            status = str(scenario.get("status", "LOCAL_OK"))
            category = str(scenario.get("category", "default"))
            category_multiplier = self._lookup_weight(scenario_category_multipliers, category, 1.0)
            skip_code = self._skip_reason_code(scenario.get("skip_reason"))
            expectation = scenario.get("expectation", {}) or {}
            remote_result = scenario.get("remote_result", {}) or {}

            if skip_code in {"UNMUTATABLE", "MUTATION_NOT_EFFECTIVE"}:
                continue

            participated = bool(remote_result.get("attempted")) and float(scenario_status_penalties.get(status, scenario_status_penalties.get("default", 0.0))) > 0
            if not participated:
                scenario_deductions.append({
                    "scenario_id": scenario.get("scenario_id"),
                    "status": status,
                    "category": category,
                    "deduction_reason": "NOT_IN_REMOTE_WEIGHT_POOL",
                    "deduction": 0.0,
                    "participated_in_pool": False,
                })
                continue

            mismatch_hit = bool(expectation.get("defined")) and expectation.get("matched") is False
            if mismatch_hit :
                mismatch_penalty = float(expectation_mismatch_penalties.get(category, expectation_mismatch_penalties.get("default", 0.0)))
                weighted_penalty = round(mismatch_penalty * interlayer_multiplier * category_multiplier / scenario_budget_total * 100, 2)
                total_scenarios += weighted_penalty 
                layer_name = SCENARIO_LAYER_MAP.get(category, "business")
                layer_deductions[layer_name] += weighted_penalty
                scenario_deductions.append({
                    "scenario_id": scenario.get("scenario_id"),
                    "status": status,
                    "category": category,
                    "deduction_reason": "EXPECTATION_MISMATCH",
                    "status_penalty": float(scenario_status_penalties.get(status, scenario_status_penalties.get("default", 0.0))),
                    "category_multiplier": category_multiplier,
                    "deduction": weighted_penalty,
                    "interlayer_state": interlayer_state,
                    "interlayer_multiplier": interlayer_multiplier,
                    "actual_remote_mode": expectation.get("actual_remote_mode"),
                    "expected_remote_modes": expectation.get("expected_remote_modes", []),
                    "pool_mode": "equal_share_on_remote_attempted",
                })
            else:
                scenario_deductions.append({
                    "scenario_id": scenario.get("scenario_id"),
                    "status": status,
                    "category": category,
                    "status_penalty": float(scenario_status_penalties.get(status, scenario_status_penalties.get("default", 0.0))),
                    "category_multiplier": self._lookup_weight(scenario_category_multipliers, category, 1.0),
                    "deduction": 0.0,
                    "waived_by_expectation": bool(expectation.get("defined")) and bool(expectation.get("matched")),
                    "actual_remote_mode": expectation.get("actual_remote_mode"),
                    "participated_in_pool": True,
                    "pool_mode": "equal_share_on_remote_attempted",
                    "interlayer_state": interlayer_state,
                    "interlayer_multiplier": interlayer_multiplier,
                })

        if interlayer_endpoint_penalty > 0:
            total_scenarios += interlayer_endpoint_penalty
            layer_deductions["protocol"] += interlayer_endpoint_penalty
            scenario_deductions.append(
                {
                    "scenario_id": "_endpoint_interlayer_state_",
                    "status": "REMOTE_SENT",
                    "category": "crypto_protocol_tamper",
                    "deduction_reason": "INTERLAYER_STATE_ENDPOINT_PENALTY",
                    "deduction": interlayer_endpoint_penalty,
                    "interlayer_state": interlayer_state,
                    "interlayer_multiplier": interlayer_multiplier,
                }
            )

        per_gap = float(baseline_gap_penalty.get("per_gap", 3.0))
        max_total = float(baseline_gap_penalty.get("max_total", 15.0))
        gap_deduction_raw = len(baseline_gaps) * per_gap
        gap_deduction = round(min(gap_deduction_raw, max_total), 2)

        total_deduction = round(total_findings + total_scenarios + gap_deduction, 2)
        score = round(max(base_score - total_deduction, 0.0), 2)
        protocol_gap = round(gap_deduction * protocol_weight, 2)
        business_gap = round(gap_deduction * business_weight, 2)
        protocol_score = round(max(base_score - layer_deductions["protocol"] - protocol_gap, 0.0), 2)
        business_score = round(max(base_score - layer_deductions["business"] - business_gap, 0.0), 2)
        breakdown = {
            "profile": self.scoring_profile_name,
            "base_score": base_score,
            "finding_deductions": finding_deductions,
            "scenario_deductions": scenario_deductions,
            "baseline_gap_penalty": {"gap_count": len(baseline_gaps), "per_gap": per_gap, "max_total": max_total, "deduction": gap_deduction},
            "layer_scores": {
                "weights": {"protocol": protocol_weight, "business": business_weight},
                "deductions": {"protocol": round(layer_deductions["protocol"], 2), "business": round(layer_deductions["business"], 2)},
                "gap_allocation": {"protocol": protocol_gap, "business": business_gap},
                "protocol_score": protocol_score,
                "business_score": business_score,
            },
            "totals": {"findings": round(total_findings, 2), "scenarios": round(total_scenarios, 2), "baseline_gaps": gap_deduction, "deduction": total_deduction, "final_score": score},
            "scenario_policy": {
                "mode": "expectation_hit_remote_pool",
                "pool_participants": len(participants),
                "gate_exempt": len(gate_exempt_scenarios),
                "scored_pool_size": len(scored_pool),
                "budget_total": round(scenario_budget_total, 2),
                "interlayer_state": interlayer_state,
                "interlayer_multiplier": interlayer_multiplier,
                "interlayer_endpoint_penalty": interlayer_endpoint_penalty,
            },
            "interlayer_effectiveness": copy.deepcopy(interlayer_effectiveness or {"state": interlayer_state}),
        }
        return score, breakdown

    def _score_to_risk(self, score: float) -> str:
        thresholds = self.scoring_profile.get("risk_thresholds", {}) or {}
        low = float(thresholds.get("low", 80.0))
        medium = float(thresholds.get("medium", 60.0))
        high = float(thresholds.get("high", 40.0))
        if score >= low:
            return "low"
        if score >= medium:
            return "medium"
        if score >= high:
            return "high"
        return "critical"

    def _build_server_verification(self, remote_execution: dict[str, Any]) -> dict[str, Any]:
        attempted = int(remote_execution.get("attempted", 0) or 0)
        responded = int(remote_execution.get("responded", 0) or 0)
        errors = int(remote_execution.get("errors", 0) or 0)

        if responded > 0:
            return {"status": "VERIFIED_BY_REMOTE_RESPONSE", "verified": True, "warning_level": "none", "reason": f"已收到 {responded} 个远程响应。"}
        if attempted == 0:
            return {"status": "UNVERIFIED_NOT_ATTEMPTED", "verified": False, "warning_level": "low", "reason": "已开启真实请求发送，但无场景成功进入远程发送。"}
        if errors > 0:
            return {"status": "UNVERIFIED_TRANSPORT_ERROR", "verified": False, "warning_level": "low", "reason": "已尝试远程发送，但均因网络/连接错误未收到服务端响应。"}
        return {"status": "UNVERIFIED_NO_RESPONSE", "verified": False, "warning_level": "low", "reason": "已尝试远程发送，但未获得可用服务端响应。"}

    def _assess_entry(self, entry: dict[str, Any], baseline_path: Path, endpoint_map: dict[str, Any]) -> dict[str, Any]:
        meta = entry.get("meta", {})
        validation = entry.get("validation", {})
        request = entry.get("request", {})
        payload = copy.deepcopy(request.get("payload", {}) or {})
        endpoint_url = meta.get("url", "unknown")
        static_endpoint_info = endpoint_map.get(endpoint_url, {}) if isinstance(endpoint_map, dict) else {}
        is_special_path = self._is_password_prehash_path(entry, static_endpoint_info)
        is_dynamic_endpoint = self._is_dynamic_endpoint(entry)
        is_server_dependent_dynamic = self._is_server_dependent_dynamic_endpoint(entry)
        interlayer_signals = self._extract_interlayer_signals(entry)
        baseline_gaps = self._detect_baseline_gaps(entry)
        findings = self._collect_static_findings(entry, baseline_gaps)
        limitations = [gap["reason"] for gap in baseline_gaps]
        scoring_gaps = baseline_gaps
        scoring_findings = findings
        special_path_adjustments: dict[str, Any] = {}

        if is_special_path:
            scenarios = self._build_password_prehash_scenarios(payload)
            scoring_gaps, scoring_findings, special_path_adjustments = self._apply_special_path_scoring_filter(baseline_gaps, findings)
            limitations.append("PasswordPreHash 特例路径：阶段5仅执行认证抗性场景，评分豁免 handler 缺失类罚分。")
            findings.append({
                "id": "PASSWORD_PREHASH_SPECIAL_PATH",
                "title": "PasswordPreHash 特例路径评估",
                "severity": "info",
                "category": "credential_handling",
                "description": "该端点采用前端口令预哈希口径，阶段5使用认证抗性特例场景进行评估。",
                "evidence": endpoint_url,
                "remediation": "优先验证服务端对重放、时间戳、nonce 与口令哈希一致性的校验强度。",
                "cwe_id": None,
            })
        else:
            scenarios = self._build_scenarios(payload, meta, entry)

        # baseline_replay 已统一按“攻击应失败”口径收敛，不再针对单端点放宽成功模式。

        scenario_results: list[dict[str, Any]] = []
        baseline_preview: Optional[dict[str, Any]] = None
        endpoint_level_dynamic_entry = entry
        endpoint_level_capture_note: Optional[str] = None
        scenario_level_dynamic_entries: Optional[list[tuple[dict[str, Any], Optional[str]]]] = None
        capture_enabled = bool(self.capture_page_url)
        if is_dynamic_endpoint and capture_enabled and (not is_server_dependent_dynamic):
            endpoint_level_dynamic_entry, endpoint_level_capture_note = self._fresh_capture_dynamic_entry(entry)
        if is_dynamic_endpoint and capture_enabled and is_server_dependent_dynamic:
            scenario_level_dynamic_entries = self._fresh_capture_dynamic_entries_parallel(
                entry,
                len(scenarios),
                concurrency=max(1, len(scenarios)),
            )
        for idx, scenario in enumerate(scenarios):
            scenario_entry = entry
            capture_note = None
            scenario_reference_preview = baseline_preview
            if is_dynamic_endpoint:
                if is_server_dependent_dynamic:
                    if scenario_level_dynamic_entries and idx < len(scenario_level_dynamic_entries):
                        scenario_entry, capture_note = scenario_level_dynamic_entries[idx]
                    else:
                        scenario_entry, capture_note = self._fresh_capture_dynamic_entry(entry)
                else:
                    scenario_entry = endpoint_level_dynamic_entry
                    capture_note = endpoint_level_capture_note
                # 动态端点以 fresh capture 原包作为变异有效性对照基线。
                scenario_reference_preview = self._build_captured_request_preview(scenario_entry)
            result = self._run_scenario(scenario_entry, payload, scenario, baseline_request_preview=scenario_reference_preview)
            if capture_note:
                observations = result.get("observations") or []
                observations.insert(0, capture_note)
                result["observations"] = observations
            scenario_results.append(result)
            if idx == 0 and scenario.get("scenario_id") == "baseline_replay":
                baseline_preview = result.get("request_preview")

        interlayer_effectiveness = self._summarize_interlayer_effectiveness(interlayer_signals, scenario_results)
        score, score_breakdown = self._calculate_security_score(
            scoring_findings,
            scoring_gaps,
            scenario_results,
            is_special_path=is_special_path,
            interlayer_effectiveness=interlayer_effectiveness,
        )
        session_binding = self._evaluate_session_binding(entry, scenario_results)
        signature_bypass_dynamic = self._detect_signature_bypass_from_scenarios(scenario_results)
        if bool(signature_bypass_dynamic.get("triggered")) and not any(str(item.get("id")) == "AUTH_SIGNATURE_BYPASS_RISK" for item in findings):
            finding = self._make_finding("AUTH_SIGNATURE_BYPASS_RISK", signature_bypass_dynamic.get("evidence") or endpoint_url)
            findings.append(finding)
            scoring_findings = scoring_findings + [finding]
            score, score_breakdown = self._calculate_security_score(
                scoring_findings,
                scoring_gaps,
                scenario_results,
                is_special_path=is_special_path,
                interlayer_effectiveness=interlayer_effectiveness,
            )
        if bool(session_binding.get("assessed")) and bool(session_binding.get("missing")):
            finding = self._make_finding("AUTH_SESSION_BINDING_MISSING", endpoint_url)
            findings.append(finding)
            scoring_findings = scoring_findings + [finding]
            score, score_breakdown = self._calculate_security_score(
                scoring_findings,
                scoring_gaps,
                scenario_results,
                is_special_path=is_special_path,
                interlayer_effectiveness=interlayer_effectiveness,
            )
        if str((interlayer_effectiveness or {}).get("state") or "") == "interlayer_invalid":
            finding = self._make_finding("INTERLAYER_WEAK_EFFECT", endpoint_url)
            findings.append(finding)
            scoring_findings = scoring_findings + [finding]
            score, score_breakdown = self._calculate_security_score(
                scoring_findings,
                scoring_gaps,
                scenario_results,
                is_special_path=is_special_path,
                interlayer_effectiveness=interlayer_effectiveness,
            )
        if is_special_path:
            score_breakdown["special_path"] = {
                "enabled": True,
                "name": "PasswordPreHash",
                "adjustments": special_path_adjustments,
                "note": "特例路径不计 handler 缺失类罚分，但保留认证抗性场景扣分。",
            }
        layer_scores = (score_breakdown.get("layer_scores", {}) or {})
        risk_level = self._score_to_risk(score)
        remote_execution = self._summarize_remote_execution(scenario_results)
        server_verification = self._build_server_verification(remote_execution)
        if not server_verification.get("verified"):
            findings.append(self._make_finding("SERVER_BEHAVIOR_UNVERIFIED", server_verification.get("reason", "unknown")))
        error_portrait = summarize_response_modes(scenario_results)

        return {
            "endpoint_id": meta.get("id", "unknown"),
            "endpoint": endpoint_url,
            "method": meta.get("method", "POST"),
            "trigger_function": meta.get("trigger_function"),
            "status": entry.get("status"),
            "verified": bool(validation.get("verified")),
            "comparison_result": validation.get("comparison_result"),
            "algorithms": meta.get("crypto_algorithms", []),
            "special_path": "PasswordPreHash" if is_special_path else None,
            "baseline_overview": {
                "payload_keys": list(payload.keys()) if isinstance(payload, dict) else [],
                "execution_steps": len(meta.get("execution_flow", [])),
                "runtime_param_keys": sorted((validation.get("runtime_params", {}) or {}).keys()),
                "trace_types": [item.get("type") for item in validation.get("trace", []) if isinstance(item, dict)],
                "source_analysis_file": meta.get("source_analysis_file"),
                "static_trace_calls": static_endpoint_info.get("trace_calls", []),
            },
            "baseline_gaps": baseline_gaps,
            "findings": findings,
            "scenario_results": scenario_results,
            "remote_execution": remote_execution,
            "server_verification": server_verification,
            "error_portrait": error_portrait,
            "interlayer_signals": interlayer_signals,
            "interlayer_effectiveness": interlayer_effectiveness,
            "session_binding": session_binding,
            "limitations": limitations,
            "security_score": round(score, 2),
            "protocol_score": float(layer_scores.get("protocol_score", score)),
            "business_score": float(layer_scores.get("business_score", score)),
            "score_breakdown": score_breakdown,
            "risk_level": risk_level,
            "source_refs": {"baseline_file": str(baseline_path), "static_analysis_file": meta.get("source_analysis_file")},
        }

    def _summarize_remote_execution(self, scenario_results: list[dict[str, Any]]) -> dict[str, Any]:
        summary = {
            "total_scenarios": len(scenario_results),
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
        for scenario in scenario_results:
            remote = scenario.get("remote_result", {}) or {}
            if not remote.get("attempted"):
                summary["not_attempted"] += 1
                continue
            summary["attempted"] += 1
            status_code = remote.get("status_code")
            if status_code is not None:
                summary["responded"] += 1
                key = str(status_code)
                summary["status_code_counts"][key] = summary["status_code_counts"].get(key, 0) + 1
            error = remote.get("error")
            if error:
                summary["errors"] += 1
                normalized_error = re.sub(r"0x[0-9A-Fa-f]+", "0xADDR", str(error))
                summary["error_counts"][normalized_error] = summary["error_counts"].get(normalized_error, 0) + 1
            elapsed_ms = remote.get("elapsed_ms")
            if isinstance(elapsed_ms, (int, float)):
                elapsed_values.append(float(elapsed_ms))
        if elapsed_values:
            ordered = sorted(elapsed_values)
            p95_index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * 0.95)))
            summary["avg_elapsed_ms"] = round(sum(ordered) / len(ordered), 2)
            summary["p95_elapsed_ms"] = round(ordered[p95_index], 2)
        return summary


def build_summary_table(report: dict[str, Any]) -> Table:
    summary = report.get("summary", {})
    scoring = report.get("scoring", {}) or {}
    table = Table(title="安全评估摘要", box=box.ASCII)
    table.add_column("指标", style="cyan")
    table.add_column("值", style="yellow")
    table.add_row("基线总数", str(summary.get("baseline_entries_total", 0)))
    table.add_row("已验证端点数", str(summary.get("verified_entries_total", 0)))
    table.add_row("已评估端点数", str(summary.get("assessed_endpoints", 0)))
    table.add_row("场景总数", str(summary.get("scenario_results_total", 0)))
    table.add_row("发现总数", str(summary.get("findings_total", 0)))
    table.add_row("总体评分", f"{summary.get('overall_score', 0):.2f}/100")
    table.add_row("评分 Profile", str(scoring.get("profile", summary.get("scoring_profile", "default"))))
    return table


def resolve_baseline_path(user_input: Optional[str]) -> Path:
    if user_input:
        path = Path(user_input)
        if not path.exists():
            raise FileNotFoundError(f"未找到基线文件: {path}")
        return path
    latest = latest_matching_file(DEFAULT_BASELINE_DIR, "baseline_skeletons_*.json")
    if not latest:
        raise FileNotFoundError("baseline_samples 中未找到 baseline_skeletons_*.json")
    return latest


def resolve_static_analysis_path(user_input: Optional[str]) -> Optional[Path]:
    if user_input:
        path = Path(user_input)
        if not path.exists():
            raise FileNotFoundError(f"未找到静态分析文件: {path}")
        return path
    return latest_matching_file(DEFAULT_STATIC_ANALYSIS_DIR, "static_analysis_*.json")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="阶段5：端点安全性评估")
    parser.add_argument("--baseline", help="基线 JSON 文件路径（默认读取最新 baseline_skeletons_*.json）")
    parser.add_argument("--static", help="静态分析 JSON 文件路径（可选，默认自动推断）")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="评估结果输出目录")
    parser.add_argument("--output", help="输出文件名（默认 assessment_<report_id>.json）")
    parser.add_argument("--endpoint-id", help="仅评估指定 endpoint_id")
    parser.add_argument("--timeout", type=float, default=10.0, help="真实请求超时时间（秒）")
    parser.add_argument("--capture-page-url", help="动态端点场景前 fresh capture 的页面 URL（建议传 easy.php）")
    parser.add_argument("--scoring-profile", default="default", help="评分 profile 名称")
    parser.add_argument("--scoring-config", default=str(DEFAULT_SCORING_CONFIG), help="评分配置 YAML 路径")
    parser.add_argument("--include-unverified", action="store_true", help="纳入未通过 phase4 的端点进行诊断评估")
    parser.add_argument("--strict-baseline-replay", action="store_true", help="baseline_replay 场景禁用 message/capture 兜底，仅使用结构化重建")
    parser.add_argument("--enhanced-fuzz-mode", action="store_true", help="启用增强模糊模式（不增加场景数，仅提升场景变异强度）")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    baseline_path = resolve_baseline_path(args.baseline)
    static_path = resolve_static_analysis_path(args.static)
    engine = BaselineAssessmentEngine(
        output_dir=Path(args.output_dir),
        timeout=float(args.timeout),
        capture_page_url=args.capture_page_url,
        scoring_profile=str(args.scoring_profile),
        scoring_config_path=Path(args.scoring_config),
        strict_baseline_replay=bool(args.strict_baseline_replay),
        enhanced_fuzz_mode=bool(args.enhanced_fuzz_mode),
    )
    report = engine.assess(
        baseline_path=baseline_path,
        static_analysis_path=static_path,
        endpoint_id=args.endpoint_id,
        include_unverified=bool(args.include_unverified),
    )
    output_path = engine.save_report(report, filename=args.output)
    console.print(build_summary_table(report))
    console.print(f"[green][OK][/green] 评估结果已保存到: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
