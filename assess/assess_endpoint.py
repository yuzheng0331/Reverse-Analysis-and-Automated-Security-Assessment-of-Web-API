#!/usr/bin/env python3
"""
Phase 5: Endpoint Security Assessment
====================================
基于统一基线 JSON 执行安全性评估。
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import json
import random
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from rich import box

try:
    import requests
except ImportError:
    requests = None

from assess.common import latest_matching_file, load_json_file, load_yaml_file, save_json_file, safe_json_dumps, truncate_text, utc_now
from handlers.base import CryptoContext
from handlers.operations import VariableDerivationOperation
from handlers.registry import get_registry

console = Console()
DEFAULT_BASELINE_DIR = BASE_DIR / "baseline_samples"
DEFAULT_STATIC_ANALYSIS_DIR = BASE_DIR / "collect" / "static_analysis"
DEFAULT_OUTPUT_DIR = BASE_DIR / "assessment_results"
DEFAULT_SCORING_CONFIG = BASE_DIR / "configs" / "scoring_profiles.yaml"

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


class LocalFlowExecutor:
    def __init__(self, entry: dict[str, Any]):
        self.entry = copy.deepcopy(entry)
        self.execution_flow = self.entry.get("meta", {}).get("execution_flow", [])
        self.runtime_params = self.entry.get("validation", {}).get("runtime_params", {}) or {}
        self.request_headers = self.entry.get("request", {}).get("headers", {}) or {}
        self.registry = get_registry()

    def execute(self, payload: dict[str, Any], allow_captured_message_fallback: bool = False) -> dict[str, Any]:
        state: dict[str, Any] = {
            "payload": copy.deepcopy(payload),
            "outputs": {},
            "key": self.runtime_params.get("key"),
            "iv": self.runtime_params.get("iv"),
            "public_key": self.runtime_params.get("public_key"),
            "last_output": None,
            "request_preview": None,
            "limitations": [],
            "logs": [],
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

        # 评估阶段优先复用动态捕获阶段已经得到的运行时材料，避免因静态分析里的占位派生表达式再次失败。
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
        if not result.success:
            raise ValueError(result.error)
        if target == "key":
            state["key"] = result.context.key
        elif target == "iv":
            state["iv"] = result.context.iv

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
        if input_source == "missing":
            raise ValueError(f"缺少结构化输入表达式，无法解析: {source_expression or '[empty]'}")
        context = CryptoContext(plaintext=input_value)
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

    def _build_request_preview(self, step: dict[str, Any], payload: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        runtime_args = step.get("runtime_args", {}) or {}
        packing_info = runtime_args.get("packing_info", {}) or {}
        packing_type = packing_info.get("type", "unknown")
        resolved_fields: dict[str, Any] = {}
        missing_fields: list[str] = []
        body_text: Optional[str] = None
        body_json: Optional[dict[str, Any]] = None

        def resolve_value(field_name: str, name: str) -> Any:
            if name in state["outputs"]:
                return state["outputs"][name]
            if name in payload:
                return payload[name]
            if name in self.runtime_params:
                return self.runtime_params[name]
            field_sources = packing_info.get("field_sources", {}) or {}
            field_source = field_sources.get(field_name, {}) if isinstance(field_sources, dict) else {}
            derivations = packing_info.get("value_derivations", {}) or {}
            if isinstance(field_source, dict) and field_source.get("derivation"):
                return self._evaluate_dynamic_derivation(field_source.get("derivation"), payload, state)
            if name in derivations:
                return self._evaluate_dynamic_derivation(derivations[name], payload, state)
            return None

        if packing_type == "json":
            structure = packing_info.get("structure", {}) or {}
            body_json = {}
            for field_name, source_name in structure.items():
                value = resolve_value(str(field_name), str(source_name))
                if value is None:
                    missing_fields.append(f"{field_name} <- {source_name}")
                    continue
                body_json[field_name] = value
                resolved_fields[field_name] = value
            if not missing_fields:
                body_text = json.dumps(body_json, ensure_ascii=False)
        elif packing_type == "url_search_params":
            structure = packing_info.get("structure", {}) or {}
            params: dict[str, Any] = {}
            for field_name, source_name in structure.items():
                value = resolve_value(str(field_name), str(source_name))
                if value is None:
                    missing_fields.append(f"{field_name} <- {source_name}")
                    continue
                params[field_name] = value
                resolved_fields[field_name] = value
            if not missing_fields:
                body_text = urllib.parse.urlencode(params)
        elif packing_type == "template":
            template = str(packing_info.get("template", ""))
            insertions = packing_info.get("insertions", []) or []
            body_text = template
            for insertion in insertions:
                variable = insertion.get("variable")
                value = resolve_value(str(variable), str(variable))
                if value is None:
                    missing_fields.append(str(variable))
                    continue
                body_text = body_text.replace(f"{{{{{variable}}}}}", urllib.parse.quote_plus(str(value)))
                resolved_fields[str(variable)] = value
            if missing_fields:
                body_text = None
        else:
            missing_fields.append(f"不支持的 packing type: {packing_type}")
        return {
            "body_type": packing_type,
            "headers": copy.deepcopy(self.request_headers),
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
        if node_type == "op":
            input_val = self._evaluate_dynamic_derivation(derivation.get("input"), payload, state)
            args = [self._evaluate_dynamic_derivation(arg, payload, state) for arg in derivation.get("args", [])]
            op_name = derivation.get("op")
            if op_name == "JSON.stringify":
                return safe_json_dumps(input_val)
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
            if callee == "Math.random":
                return random.random()
            if callee == "Math.floor":
                expression = derivation.get("expression", "")
                if "Date.now() / 1000" in expression:
                    return int(time.time())
                return int(time.time())
            return derivation.get("expression")
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
            return safe_json_dumps(payload), f"synthetic_json:{expr}"
        if expr.startswith("JSON.stringify(") and expr.endswith(")"):
            inner = expr[len("JSON.stringify(") : -1].strip()
            value, source = self._resolve_expression(inner, payload, state, allow_captured_message_fallback)
            if source == "missing":
                return None, source
            if isinstance(value, (dict, list)):
                return safe_json_dumps(value), f"json_stringify:{source}"
            return safe_json_dumps(value) if not isinstance(value, str) else value, f"json_stringify:{source}"
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
        if allow_captured_message_fallback and self.runtime_params.get("message") is not None:
            return self.runtime_params["message"], "captured_message_fallback"
        return None, "missing"

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
    def __init__(self, output_dir: Path, send_requests: bool = False, timeout: float = 10.0, scoring_profile: str = "default", scoring_config_path: Path = DEFAULT_SCORING_CONFIG):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.send_requests = send_requests
        self.timeout = timeout
        self.scoring_config_path = Path(scoring_config_path)
        self.scoring_profile_name = scoring_profile
        self.scoring_profile = self._load_scoring_profile(self.scoring_config_path, scoring_profile)

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
        normalized.setdefault("scenario_status_penalties", {"LOCAL_FAILED": 2.0, "SKIPPED": 2.0, "LOCAL_OK": 0.0, "REMOTE_SENT": 0.0})
        normalized.setdefault("scenario_category_multipliers", {"default": 1.0})
        normalized.setdefault("baseline_gap_penalty", {"per_gap": 3.0, "max_total": 15.0})
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
            "baseline_gap_penalty": copy.deepcopy(self.scoring_profile.get("baseline_gap_penalty", {})),
        }

    def _lookup_weight(self, mapping: dict[str, Any], key: str, default: float = 1.0) -> float:
        if not isinstance(mapping, dict):
            return float(default)
        if key in mapping:
            return float(mapping[key])
        return float(mapping.get("default", default))

    def assess(self, baseline_path: Path, static_analysis_path: Optional[Path] = None, endpoint_id: Optional[str] = None) -> dict[str, Any]:
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
            if entry.get("validation", {}).get("verified"):
                verified_entries.append(entry)
            else:
                skipped_entries.append({"endpoint_id": current_id, "reason": "validation.verified != true"})
        assessments = []
        gap_summary = []
        scenario_total = 0
        findings_total = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        with Progress() as progress:
            task = progress.add_task("评估端点中...", total=len(verified_entries))
            for entry in verified_entries:
                assessment = self._assess_entry(entry, baseline_path, endpoint_map)
                assessments.append(assessment)
                scenario_total += len(assessment.get("scenario_results", []))
                findings_total += len(assessment.get("findings", []))
                for finding in assessment.get("findings", []):
                    severity = finding.get("severity", "info")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                gap_summary.extend(assessment.get("baseline_gaps", []))
                progress.advance(task)
        overall_score = sum(item.get("security_score", 0.0) for item in assessments) / len(assessments) if assessments else 0.0
        return {
            "report_id": f"ASM-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "generated_at": utc_now(),
            "source": {"baseline_file": str(baseline_path), "static_analysis_file": str(static_analysis_path or "") if static_analysis_path else self._infer_static_path_from_baselines(baseline_data), "send_requests": self.send_requests, "timeout_seconds": self.timeout, "scoring_profile": self.scoring_profile_name, "scoring_config_file": str(self.scoring_config_path)},
            "scoring": self._current_scoring_summary(),
            "summary": {"baseline_entries_total": len(baseline_data), "verified_entries_total": len(verified_entries), "assessed_endpoints": len(assessments), "skipped_entries": len(skipped_entries), "scenario_results_total": scenario_total, "findings_total": findings_total, "by_severity": severity_counts, "overall_score": round(overall_score, 2), "scoring_profile": self.scoring_profile_name},
            "skipped_entries": skipped_entries,
            "baseline_gap_summary": gap_summary,
            "assessments": assessments,
        }

    def save_report(self, report: dict[str, Any], filename: Optional[str] = None) -> Path:
        if not filename:
            filename = f"assessment_{report['report_id']}.json"
        output_path = self.output_dir / filename
        save_json_file(output_path, report)
        console.print(f"[green][OK] 已保存评估结果:[/green] {output_path}")
        return output_path

    def _load_static_analysis(self, baseline_data: list[dict[str, Any]], explicit_path: Optional[Path]) -> Optional[dict[str, Any]]:
        static_path = explicit_path
        if static_path is None:
            inferred = self._infer_static_path_from_baselines(baseline_data)
            if inferred:
                static_path = Path(inferred)
        if not static_path or not static_path.exists():
            return None
        return load_json_file(static_path)

    def _infer_static_path_from_baselines(self, baseline_data: list[dict[str, Any]]) -> Optional[str]:
        for entry in baseline_data:
            source_name = entry.get("meta", {}).get("source_analysis_file")
            if source_name:
                return str(DEFAULT_STATIC_ANALYSIS_DIR / source_name)
        return None

    def _make_finding(self, finding_id: str, evidence: str) -> dict[str, Any]:
        template = FINDING_LIBRARY[finding_id]
        return {"id": finding_id, "title": template["title"], "severity": template["severity"], "category": template["category"], "description": template["description"], "evidence": evidence, "remediation": template["remediation"], "cwe_id": template["cwe_id"]}

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
        available_names = set(payload.keys()) | set(runtime_params.keys()) | {item for item in named_outputs if item}
        for pack_step in pack_steps:
            packing_info = (pack_step.get("runtime_args", {}) or {}).get("packing_info", {}) or {}
            structure = packing_info.get("structure", {}) or {}
            field_sources = packing_info.get("field_sources", {}) or {}
            for field_name, source_name in structure.items():
                if source_name in available_names:
                    continue
                field_source = field_sources.get(field_name, {}) if isinstance(field_sources, dict) else {}
                if isinstance(field_source, dict) and field_source.get("derivation"):
                    continue
                add_gap("UNRESOLVED_PACK_REFERENCE", f"packing_info.structure.{field_name}", f"打包字段引用了未结构化输出变量 '{source_name}'，本地无法稳定重建。", "阶段2-静态分析 与 阶段3-基线生成", "除 output_variable 外，还应输出可直接引用的中间结果名或编码转换步骤。")
        crypto_steps = [step for step in execution_flow if str(step.get("step_type", "")).lower() in {"encrypt", "sign"}]
        for step in crypto_steps:
            if not step.get("context"):
                add_gap("MISSING_INPUT_CONTEXT", "meta.execution_flow[*].context", "加密/签名步骤缺少上下文，无法分析输入来源。", "阶段2-静态分析", "为每个原语 step 输出结构化 input_expression，而不是仅依赖模糊上下文。")
        has_sign_step = any(str(step.get("step_type", "")).lower() == "sign" for step in execution_flow)
        if has_sign_step and runtime_params.get("message") and not any(step.get("input_expression") or step.get("input_derivation") for step in crypto_steps):
            add_gap("MISSING_SIGN_INPUT_RULE", "meta.execution_flow[*].input_expression", "已捕获 message，但缺少结构化签名输入规则，变异后无法本地重新生成签名。", "阶段2-静态分析 与 阶段3-基线生成", "为 sign 步骤输出 input_expression / input_derivation，并记录 dataToSign 的拼接规则。")
        if validation.get("verified") and not runtime_params and meta.get("crypto_algorithms") not in ([], ["PayloadPacking"]):
            add_gap("MISSING_RUNTIME_PARAMS", "validation.runtime_params", "已验证端点却缺少运行时参数，动态 Key/IV/Nonce 场景无法重放。", "阶段4-动态捕获", "在 Hook 中把 key / iv / nonce / timestamp / message 等运行时数据完整回填到 validation.runtime_params。")
        return gaps

    def _collect_static_findings(self, entry: dict[str, Any], baseline_gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        meta = entry.get("meta", {})
        algorithms = [str(item).upper() for item in meta.get("crypto_algorithms", [])]
        execution_flow = meta.get("execution_flow", []) or []
        findings = []
        if "DES" in algorithms:
            findings.append(self._make_finding("CRYPTO_WEAK_DES", meta.get("url", "unknown")))
        for step in execution_flow:
            step_type = str(step.get("step_type", "")).lower()
            args = step.get("runtime_args", {}) or {}
            if step_type == "setkey" and args.get("key"):
                findings.append(self._make_finding("CRYPTO_HARDCODED_KEY", step.get("context", "setkey")))
            if step_type == "setiv" and args.get("iv"):
                findings.append(self._make_finding("CRYPTO_STATIC_IV", step.get("context", "setiv")))
        if any(gap.get("code") == "MISSING_SIGN_INPUT_RULE" for gap in baseline_gaps):
            findings.append(self._make_finding("AUTH_SIGNATURE_BYPASS_RISK", meta.get("url", "unknown")))
        if baseline_gaps:
            findings.append(self._make_finding("ASSESSMENT_BASELINE_GAP", "; ".join(sorted({gap.get('field', 'unknown') for gap in baseline_gaps}))))
        dedup: dict[tuple[str, str], dict[str, Any]] = {}
        for finding in findings:
            dedup[(finding["id"], finding["evidence"])] = finding
        return list(dedup.values())

    def _build_scenarios(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        scenarios = [{"scenario_id": "baseline_replay", "category": "baseline_replay", "title": "基线重放一致性检查", "payload": copy.deepcopy(payload), "allow_captured_message_fallback": True, "description": "使用原始基线 Payload 在本地重建加密与打包流程。"}]
        text_key = first_payload_key(payload, ["username", "password", "id", "query"])
        payload_keys = list(payload.keys())
        if text_key:
            injected = copy.deepcopy(payload); injected[text_key] = f"{injected[text_key]}' OR '1'='1"
            scenarios.append({"scenario_id": "plaintext_mutation_sqli", "category": "plaintext_mutation", "title": f"明文注入测试：{text_key}", "payload": injected, "allow_captured_message_fallback": False, "description": f"对字段 {text_key} 注入常见 SQL 注入载荷。"})
            boundary = copy.deepcopy(payload); boundary[text_key] = ""
            scenarios.append({"scenario_id": "boundary_empty_string", "category": "boundary_anomaly", "title": f"边界值：{text_key} 置空", "payload": boundary, "allow_captured_message_fallback": False, "description": f"将字段 {text_key} 置为空字符串。"})
            long_text = copy.deepcopy(payload); long_text[text_key] = str(long_text[text_key]) * 64
            scenarios.append({"scenario_id": "boundary_long_string", "category": "boundary_anomaly", "title": f"边界值：{text_key} 超长字符串", "payload": long_text, "allow_captured_message_fallback": False, "description": f"将字段 {text_key} 扩展为超长字符串，测试长度边界。"})
            special_chars = copy.deepcopy(payload); special_chars[text_key] = "!@#￥%…&*()_+-=[]{}|;:'\",.<>/?`~中文🚧"
            scenarios.append({"scenario_id": "special_chars_payload", "category": "boundary_anomaly", "title": f"特殊字符测试：{text_key}", "payload": special_chars, "allow_captured_message_fallback": False, "description": f"向字段 {text_key} 注入特殊字符、中文与 Unicode。"})
            auth_payload = copy.deepcopy(payload); auth_payload[text_key] = "guest_user"
            scenarios.append({"scenario_id": "auth_context_variation", "category": "auth_context_variation", "title": f"身份上下文变体：{text_key}", "payload": auth_payload, "allow_captured_message_fallback": False, "description": f"替换字段 {text_key} 的身份语义值，观察是否可构造新的合法请求。"})
            type_confusion = copy.deepcopy(payload); type_confusion[text_key] = {"nested": True}
            scenarios.append({"scenario_id": "payload_type_confusion", "category": "payload_structure_variation", "title": f"类型错配测试：{text_key}", "payload": type_confusion, "allow_captured_message_fallback": False, "description": f"将字段 {text_key} 由字符串替换为对象，测试类型错配。"})
        removable_key = None
        for candidate in ["password", "username", "id"]:
            if candidate in payload:
                removable_key = candidate
                break
        if not removable_key and payload_keys:
            removable_key = payload_keys[0]
        if removable_key:
            missing_field_payload = copy.deepcopy(payload); missing_field_payload.pop(removable_key, None)
            scenarios.append({"scenario_id": "payload_missing_field", "category": "payload_structure_variation", "title": f"缺字段测试：移除 {removable_key}", "payload": missing_field_payload, "allow_captured_message_fallback": False, "description": f"移除字段 {removable_key}，检查本地是否还能重建请求。"})
        base = copy.deepcopy(payload)
        scenarios.extend([
            {"scenario_id": "crypto_remove_security_field", "category": "crypto_protocol_tamper", "title": "协议篡改：移除签名/随机字段", "payload": copy.deepcopy(base), "allow_captured_message_fallback": True, "description": "删除 signature/nonce/timestamp/encryptedData/random 中的安全字段。", "request_tamper": {"action": "remove_field", "fields": ["signature", "nonce", "timestamp", "encryptedData", "data", "random"]}},
            {"scenario_id": "crypto_stale_timestamp", "category": "crypto_protocol_tamper", "title": "协议篡改：旧时间戳重放", "payload": copy.deepcopy(base), "allow_captured_message_fallback": True, "description": "将 timestamp 重写为旧值，模拟重放场景。", "request_tamper": {"action": "overwrite_field", "fields": ["timestamp"], "value": 1}},
            {"scenario_id": "crypto_signature_corruption", "category": "crypto_protocol_tamper", "title": "协议篡改：破坏签名字段", "payload": copy.deepcopy(base), "allow_captured_message_fallback": True, "description": "将 signature 覆写为明显错误的固定值。", "request_tamper": {"action": "overwrite_field", "fields": ["signature"], "value": "deadbeefdeadbeef"}},
            {"scenario_id": "crypto_ciphertext_truncate", "category": "crypto_protocol_tamper", "title": "协议篡改：截断密文字段", "payload": copy.deepcopy(base), "allow_captured_message_fallback": True, "description": "对 encryptedData / data / random / password 等字段进行截断。", "request_tamper": {"action": "truncate_field", "fields": ["encryptedData", "data", "random", "password"], "length": 12}},
            {"scenario_id": "crypto_duplicate_timestamp", "category": "crypto_protocol_tamper", "title": "协议篡改：重复 timestamp 字段", "payload": copy.deepcopy(base), "allow_captured_message_fallback": True, "description": "在 URL 编码请求中追加重复 timestamp 字段。", "request_tamper": {"action": "duplicate_field", "fields": ["timestamp"], "value": "1"}},
        ])
        return scenarios

    def _run_scenario(self, entry: dict[str, Any], scenario: dict[str, Any]) -> dict[str, Any]:
        payload = copy.deepcopy(scenario["payload"])
        executor = LocalFlowExecutor(entry)
        local_result = executor.execute(payload, allow_captured_message_fallback=bool(scenario.get("allow_captured_message_fallback")))
        request_preview = local_result.get("request_preview")
        observations = []
        status = "LOCAL_OK" if local_result.get("success") else "LOCAL_FAILED"
        request_tamper = scenario.get("request_tamper")
        if request_tamper:
            if not request_preview or not request_preview.get("send_ready"):
                request_preview = self._build_captured_request_preview(entry)
                if request_preview:
                    observations.append("本地请求体不可重建，已回退使用 capture trace 中的 FETCH body。")
            if request_preview and request_preview.get("send_ready"):
                tamper_result = self._apply_request_tamper(request_preview, request_tamper)
                if tamper_result.get("success"):
                    request_preview = tamper_result.get("request_preview")
                    observations.append(tamper_result.get("reason"))
                    if status != "LOCAL_FAILED":
                        status = "LOCAL_OK"
                else:
                    status = "SKIPPED"
                    observations.append(tamper_result.get("reason"))
            else:
                status = "SKIPPED"
                observations.append("缺少可用请求体，无法执行协议篡改场景。")
        if local_result.get("limitations"):
            observations.extend(local_result.get("limitations"))
        remote_result = {"attempted": False, "status_code": None, "elapsed_ms": None, "body_preview": None, "error": None}
        if self.send_requests and request_preview and request_preview.get("send_ready"):
            remote_result = self._send_request(entry, request_preview)
            if remote_result.get("attempted") and remote_result.get("status_code") is not None:
                status = "REMOTE_SENT"
            elif remote_result.get("error"):
                observations.append(remote_result["error"])
        return {"scenario_id": scenario["scenario_id"], "category": scenario["category"], "title": scenario["title"], "description": scenario["description"], "status": status, "payload": payload, "local_replay": {"success": bool(local_result.get("success")), "error": local_result.get("error"), "named_outputs": local_result.get("named_outputs", {}), "final_output_preview": truncate_text(local_result.get("final_output"), 120)}, "request_preview": request_preview, "remote_result": remote_result, "observations": observations}

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

    def _apply_request_tamper(self, preview: dict[str, Any], tamper: dict[str, Any]) -> dict[str, Any]:
        cloned = copy.deepcopy(preview)
        body_json = cloned.get("body_json")
        body_text = cloned.get("body_text")
        action = tamper.get("action")
        fields = tamper.get("fields", [])
        replacement = tamper.get("value")
        length = int(tamper.get("length", 12))
        if isinstance(body_json, dict):
            for field_name in fields:
                if field_name not in body_json:
                    continue
                if action == "remove_field":
                    body_json.pop(field_name, None); cloned["body_text"] = json.dumps(body_json, ensure_ascii=False); return {"success": True, "request_preview": cloned, "reason": f"已移除字段 {field_name}"}
                if action == "overwrite_field":
                    body_json[field_name] = replacement; cloned["body_text"] = json.dumps(body_json, ensure_ascii=False); return {"success": True, "request_preview": cloned, "reason": f"已覆写字段 {field_name}"}
                if action == "truncate_field":
                    body_json[field_name] = str(body_json[field_name])[:length]; cloned["body_text"] = json.dumps(body_json, ensure_ascii=False); return {"success": True, "request_preview": cloned, "reason": f"已截断字段 {field_name}"}
                if action == "duplicate_field":
                    return {"success": False, "reason": "JSON 请求体无法自然表达重复字段。"}
            return {"success": False, "reason": "JSON 请求体中未找到可篡改目标字段。"}
        if isinstance(body_text, str) and "=" in body_text:
            pairs = urllib.parse.parse_qsl(body_text, keep_blank_values=True)
            if not pairs:
                return {"success": False, "reason": "无法解析 URL 编码请求体。"}
            for field_name in fields:
                for index, (key, value) in enumerate(pairs):
                    if key != field_name:
                        continue
                    if action == "remove_field":
                        pairs.pop(index); cloned["body_text"] = urllib.parse.urlencode(pairs); return {"success": True, "request_preview": cloned, "reason": f"已移除字段 {field_name}"}
                    if action == "overwrite_field":
                        pairs[index] = (key, str(replacement)); cloned["body_text"] = urllib.parse.urlencode(pairs); return {"success": True, "request_preview": cloned, "reason": f"已覆写字段 {field_name}"}
                    if action == "truncate_field":
                        pairs[index] = (key, str(value)[:length]); cloned["body_text"] = urllib.parse.urlencode(pairs); return {"success": True, "request_preview": cloned, "reason": f"已截断字段 {field_name}"}
                    if action == "duplicate_field":
                        pairs.append((key, str(replacement if replacement is not None else value))); cloned["body_text"] = urllib.parse.urlencode(pairs); return {"success": True, "request_preview": cloned, "reason": f"已追加重复字段 {field_name}"}
            return {"success": False, "reason": "URL 编码请求体中未找到可篡改目标字段。"}
        return {"success": False, "reason": "当前请求体格式不支持该篡改动作。"}

    def _send_request(self, entry: dict[str, Any], request_preview: dict[str, Any]) -> dict[str, Any]:
        if requests is None:
            return {"attempted": False, "status_code": None, "elapsed_ms": None, "body_preview": None, "error": "requests 未安装，无法发送真实请求。"}
        url = entry.get("meta", {}).get("url")
        method = entry.get("meta", {}).get("method", "POST")
        headers = copy.deepcopy(request_preview.get("headers", {}) or {})
        try:
            started = datetime.now(timezone.utc)
            if request_preview.get("body_type") == "json" and request_preview.get("body_json") is not None:
                response = requests.request(method, url, headers=headers, json=request_preview["body_json"], timeout=self.timeout)
            else:
                response = requests.request(method, url, headers=headers, data=request_preview.get("body_text"), timeout=self.timeout)
            elapsed = (datetime.now(timezone.utc) - started).total_seconds() * 1000
            return {"attempted": True, "status_code": response.status_code, "elapsed_ms": round(elapsed, 2), "body_preview": truncate_text(response.text, 300), "error": None}
        except Exception as exc:
            return {"attempted": True, "status_code": None, "elapsed_ms": None, "body_preview": None, "error": f"真实请求发送失败: {exc}"}

    def _calculate_security_score(self, findings: list[dict[str, Any]], baseline_gaps: list[dict[str, Any]], scenarios: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
        base_score = float(self.scoring_profile.get("base_score", 100.0))
        severity_penalties = self.scoring_profile.get("severity_penalties", {}) or {}
        category_multipliers = self.scoring_profile.get("finding_category_multipliers", {}) or {}
        scenario_status_penalties = self.scoring_profile.get("scenario_status_penalties", {}) or {}
        scenario_category_multipliers = self.scoring_profile.get("scenario_category_multipliers", {}) or {}
        baseline_gap_penalty = self.scoring_profile.get("baseline_gap_penalty", {}) or {}

        finding_deductions = []
        scenario_deductions = []
        total_findings = 0.0
        total_scenarios = 0.0

        for finding in findings:
            severity = str(finding.get("severity", "info"))
            category = str(finding.get("category", "default"))
            severity_value = float(severity_penalties.get(severity, 0.0))
            category_multiplier = self._lookup_weight(category_multipliers, category, 1.0)
            deduction = round(severity_value * category_multiplier, 2)
            total_findings += deduction
            finding_deductions.append({
                "finding_id": finding.get("id"),
                "severity": severity,
                "category": category,
                "severity_penalty": severity_value,
                "category_multiplier": category_multiplier,
                "deduction": deduction,
            })

        for scenario in scenarios:
            status = str(scenario.get("status", "LOCAL_OK"))
            category = str(scenario.get("category", "default"))
            status_penalty = float(scenario_status_penalties.get(status, 0.0))
            if status_penalty <= 0:
                continue
            category_multiplier = self._lookup_weight(scenario_category_multipliers, category, 1.0)
            deduction = round(status_penalty * category_multiplier, 2)
            total_scenarios += deduction
            scenario_deductions.append({
                "scenario_id": scenario.get("scenario_id"),
                "status": status,
                "category": category,
                "status_penalty": status_penalty,
                "category_multiplier": category_multiplier,
                "deduction": deduction,
            })

        per_gap = float(baseline_gap_penalty.get("per_gap", 3.0))
        max_total = float(baseline_gap_penalty.get("max_total", 15.0))
        gap_deduction_raw = len(baseline_gaps) * per_gap
        gap_deduction = round(min(gap_deduction_raw, max_total), 2)

        total_deduction = round(total_findings + total_scenarios + gap_deduction, 2)
        score = round(max(base_score - total_deduction, 0.0), 2)
        breakdown = {
            "profile": self.scoring_profile_name,
            "base_score": base_score,
            "finding_deductions": finding_deductions,
            "scenario_deductions": scenario_deductions,
            "baseline_gap_penalty": {"gap_count": len(baseline_gaps), "per_gap": per_gap, "max_total": max_total, "deduction": gap_deduction},
            "totals": {"findings": round(total_findings, 2), "scenarios": round(total_scenarios, 2), "baseline_gaps": gap_deduction, "deduction": total_deduction, "final_score": score},
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

    def _assess_entry(self, entry: dict[str, Any], baseline_path: Path, endpoint_map: dict[str, Any]) -> dict[str, Any]:
        meta = entry.get("meta", {})
        validation = entry.get("validation", {})
        request = entry.get("request", {})
        payload = copy.deepcopy(request.get("payload", {}) or {})
        endpoint_url = meta.get("url", "unknown")
        static_endpoint_info = endpoint_map.get(endpoint_url, {}) if isinstance(endpoint_map, dict) else {}
        baseline_gaps = self._detect_baseline_gaps(entry)
        findings = self._collect_static_findings(entry, baseline_gaps)
        limitations = [gap["reason"] for gap in baseline_gaps]
        scenario_results = [self._run_scenario(entry, scenario) for scenario in self._build_scenarios(payload)]
        score, score_breakdown = self._calculate_security_score(findings, baseline_gaps, scenario_results)
        risk_level = self._score_to_risk(score)
        return {
            "endpoint_id": meta.get("id", "unknown"),
            "endpoint": endpoint_url,
            "method": meta.get("method", "POST"),
            "trigger_function": meta.get("trigger_function"),
            "status": entry.get("status"),
            "verified": bool(validation.get("verified")),
            "comparison_result": validation.get("comparison_result"),
            "algorithms": meta.get("crypto_algorithms", []),
            "baseline_overview": {"payload_keys": list(payload.keys()) if isinstance(payload, dict) else [], "execution_steps": len(meta.get("execution_flow", [])), "runtime_param_keys": sorted((validation.get("runtime_params", {}) or {}).keys()), "trace_types": [item.get("type") for item in validation.get("trace", []) if isinstance(item, dict)], "source_analysis_file": meta.get("source_analysis_file"), "static_trace_calls": static_endpoint_info.get("trace_calls", [])},
            "baseline_gaps": baseline_gaps,
            "findings": findings,
            "scenario_results": scenario_results,
            "limitations": limitations,
            "security_score": round(score, 2),
            "score_breakdown": score_breakdown,
            "risk_level": risk_level,
            "source_refs": {"baseline_file": str(baseline_path), "static_analysis_file": meta.get("source_analysis_file")},
        }


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


def main() -> None:
    parser = argparse.ArgumentParser(description="基于 VERIFIED 基线执行安全性评估")
    parser.add_argument("--baseline", help="基线 JSON 文件路径。默认自动读取 baseline_samples 中最新文件。")
    parser.add_argument("--static-analysis", help="静态分析 JSON 文件路径。默认根据基线 source_analysis_file 自动推断。")
    parser.add_argument("--endpoint-id", help="仅评估指定 endpoint_id。")
    parser.add_argument("--send", action="store_true", help="启用真实请求发送。默认仅做本地重建，不发网。")
    parser.add_argument("--timeout", type=float, default=10.0, help="真实请求发送超时时间，单位秒。")
    parser.add_argument("--scoring-profile", default="default", help="评分 profile 名称，默认: default")
    parser.add_argument("--weights-file", default=str(DEFAULT_SCORING_CONFIG), help=f"评分配置 YAML 路径，默认: {DEFAULT_SCORING_CONFIG}")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_DIR, help=f"输出目录，默认: {DEFAULT_OUTPUT_DIR}")
    args = parser.parse_args()
    baseline_path = resolve_baseline_path(args.baseline)
    static_analysis_path = resolve_static_analysis_path(args.static_analysis)
    console.print(
        f"[bold]基线驱动安全评估[/bold]\n"
        f"基线文件: {baseline_path}\n"
        f"静态分析: {static_analysis_path if static_analysis_path else '未提供'}\n"
        f"真实请求发送: {'开启' if args.send else '关闭'}\n"
        f"评分 Profile: {args.scoring_profile}\n"
        f"评分配置: {args.weights_file}"
    )
    engine = BaselineAssessmentEngine(output_dir=args.output, send_requests=args.send, timeout=args.timeout, scoring_profile=args.scoring_profile, scoring_config_path=Path(args.weights_file))
    report = engine.assess(baseline_path=baseline_path, static_analysis_path=static_analysis_path, endpoint_id=args.endpoint_id)
    engine.save_report(report)
    console.print(build_summary_table(report))


if __name__ == "__main__":
    main()

