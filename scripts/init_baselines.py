import json
import os
import re
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
ANALYSIS_DIR = BASE_DIR / "collect" / "static_analysis"
OUTPUT_DIR = BASE_DIR / "baseline_samples"


def get_latest_analysis_file() -> Path | None:
    """获取最新的静态分析 JSON。"""
    if not ANALYSIS_DIR.exists():
        return None
    files = sorted(ANALYSIS_DIR.glob("static_analysis_*.json"), key=os.path.getmtime)
    return files[-1] if files else None


def extract_source_values(node: Any, keys_set: set[str]) -> None:
    """递归提取 derivation 中可作为 payload 的 source key。"""
    if node is None:
        return
    if isinstance(node, dict):
        if node.get("type") == "source" and isinstance(node.get("value"), str):
            keys_set.add(node["value"])
        for key in ("input", "left", "right"):
            if key in node:
                extract_source_values(node[key], keys_set)
        if isinstance(node.get("args"), list):
            for arg in node["args"]:
                extract_source_values(arg, keys_set)
        return
    if isinstance(node, list):
        for item in node:
            extract_source_values(item, keys_set)


def normalize_packing_info(packing_info: Any) -> dict[str, Any]:
    """归一化 packing_info，补齐 value_derivations。"""
    if not isinstance(packing_info, dict):
        return {}

    normalized = dict(packing_info)
    structure = normalized.get("structure", {}) or {}
    field_sources = normalized.get("field_sources", {}) or {}
    value_derivations = dict(normalized.get("value_derivations", {}) or {})

    for field_name, source_info in field_sources.items():
        if not isinstance(source_info, dict):
            continue
        source_name = source_info.get("source_name")
        if not source_name and isinstance(structure, dict):
            source_name = structure.get(field_name)
        if not isinstance(source_name, str) or not source_name:
            continue

        derivation = source_info.get("derivation")
        if derivation and source_name not in value_derivations:
            value_derivations[source_name] = derivation

    normalized["field_sources"] = field_sources
    normalized["value_derivations"] = value_derivations
    return normalized


def _infer_server_intermediate_fetch_from_context(context_text: str) -> bool:
    """仅把“获取中间材料”的请求识别为 server intermediate fetch。"""
    text = str(context_text or "").lower()
    if "fetch(" not in text:
        return False
    intermediate_tokens = [
        "get-signature",
        "server_generate_key",
        "generate_key",
        "get-key",
        "../",
    ]
    return any(token in text for token in intermediate_tokens)


def _extract_derivation_call_expression(node: Any) -> str:
    if not isinstance(node, dict):
        return ""
    node_type = str(node.get("type") or "")
    if node_type == "call":
        return str(node.get("expression") or node.get("callee") or "")
    for child_key in ["input", "left", "right"]:
        child = node.get(child_key)
        expr = _extract_derivation_call_expression(child)
        if expr:
            return expr
    for arg in node.get("args", []) or []:
        expr = _extract_derivation_call_expression(arg)
        if expr:
            return expr
    return ""


def _derivation_requires_hex(node: Any) -> bool:
    if not isinstance(node, dict):
        return False
    if str(node.get("type") or "") == "op" and str(node.get("op") or "") == "toString":
        args = node.get("args", []) or []
        return any(str(arg) == "CryptoJS.enc.Hex" for arg in args)
    for child_key in ["input", "left", "right"]:
        if _derivation_requires_hex(node.get(child_key)):
            return True
    for arg in node.get("args", []) or []:
        if _derivation_requires_hex(arg):
            return True
    return False


def reconcile_packing_bridges(execution_flow: list[dict[str, Any]]) -> None:
    """为 pack 字段补齐来源桥接，避免 source_name 与输出变量名不一致导致链条断开。"""
    produced_outputs = []
    for step in execution_flow:
        step_type = str(step.get("step_type", "")).lower()
        output_var = step.get("output_variable")
        if step_type in {"encrypt", "sign"} and output_var:
            produced_outputs.append((str(output_var), str(step.get("algorithm", "")).upper(), str(step.get("context", ""))))

    for step in execution_flow:
        if str(step.get("step_type", "")).lower() != "pack":
            continue
        packing_info = (step.get("runtime_args", {}) or {}).get("packing_info", {}) or {}
        field_sources = packing_info.get("field_sources", {}) or {}
        value_derivations = packing_info.get("value_derivations", {}) or {}

        for _, source_meta in field_sources.items():
            if not isinstance(source_meta, dict):
                continue
            source_name = str(source_meta.get("source_name") or "")
            if not source_name:
                continue
            if any(source_name == out_name for out_name, _, _ in produced_outputs):
                continue

            derivation = source_meta.get("derivation")
            if not isinstance(derivation, dict):
                continue
            call_expr = _extract_derivation_call_expression(derivation).lower()
            bridge_transform = "hex" if _derivation_requires_hex(derivation) else None

            candidate = None
            if "des.encrypt" in call_expr:
                for out_name, algo, _ in reversed(produced_outputs):
                    if algo == "DES":
                        candidate = out_name
                        break
            elif "aes.encrypt" in call_expr:
                for out_name, algo, _ in reversed(produced_outputs):
                    if algo == "AES":
                        candidate = out_name
                        break
            elif "jsencrypt.encrypt" in call_expr or "rsaencrypt" in call_expr:
                for out_name, algo, _ in reversed(produced_outputs):
                    if algo == "RSA":
                        candidate = out_name
                        break

            if candidate:
                source_meta["bridge_from_output"] = candidate
                if bridge_transform:
                    source_meta["bridge_transform"] = bridge_transform
                if source_name not in value_derivations:
                    value_derivations[source_name] = {"type": "identifier", "name": candidate}

        packing_info["field_sources"] = field_sources
        packing_info["value_derivations"] = value_derivations
        (step.get("runtime_args", {}) or {})["packing_info"] = packing_info


def normalize_encoding_name(raw_name: Any) -> str | None:
    if raw_name in [None, ""]:
        return None
    text = str(raw_name).strip().lower()
    if not text:
        return None
    if "utf8" in text:
        return "utf-8"
    if "utf16" in text:
        return "utf-16"
    if "base64" in text:
        return "base64"
    if "hex" in text:
        return "hex"
    if "latin1" in text:
        return "latin1"
    return str(raw_name)


def extract_parse_encodings(text: str) -> list[str]:
    if not text:
        return []
    matches = re.findall(r"CryptoJS\.enc\.([A-Za-z0-9_]+)\.parse", str(text))
    normalized = [normalize_encoding_name(item) for item in matches]
    return [item for item in normalized if item]


def extract_tostring_encodings(text: str) -> list[str]:
    if not text:
        return []
    matches = re.findall(r"toString\(\s*CryptoJS\.enc\.([A-Za-z0-9_]+)\s*\)", str(text))
    normalized = [normalize_encoding_name(item) for item in matches]
    return [item for item in normalized if item]


def infer_encoding_runtime_args(detail: dict[str, Any]) -> dict[str, Any]:
    inferred: dict[str, Any] = {}
    input_expr = str(detail.get("input_expression", "") or "")
    output_transform = str(detail.get("output_transform", "") or "")
    context = str(detail.get("context", "") or "")

    parse_from_input = extract_parse_encodings(input_expr)
    parse_from_context = extract_parse_encodings(context)
    to_string_from_transform = extract_tostring_encodings(output_transform)
    to_string_from_context = extract_tostring_encodings(context)

    if parse_from_input:
        inferred["input_encoding"] = parse_from_input[0]
    elif parse_from_context:
        inferred["input_encoding"] = parse_from_context[0]

    if to_string_from_transform:
        inferred["output_encoding"] = to_string_from_transform[-1]
    elif to_string_from_context:
        inferred["output_encoding"] = to_string_from_context[-1]

    key_match = re.search(
        r"CryptoJS\.[A-Za-z0-9_]+\.(?:encrypt|decrypt)\s*\(\s*[^,]+,\s*CryptoJS\.enc\.([A-Za-z0-9_]+)\.parse",
        context,
    )
    if key_match:
        key_encoding = normalize_encoding_name(key_match.group(1))
        if key_encoding:
            inferred["key_encoding"] = key_encoding

    iv_match = re.search(r"\biv\s*:\s*CryptoJS\.enc\.([A-Za-z0-9_]+)\.parse", context)
    if iv_match:
        iv_encoding = normalize_encoding_name(iv_match.group(1))
        if iv_encoding:
            inferred["iv_encoding"] = iv_encoding

    return inferred


def _encoding_from_derivation(derivation: Any) -> str | None:
    if not isinstance(derivation, dict):
        return None
    if str(derivation.get("type") or "") != "call":
        return None
    callee = str(derivation.get("callee") or "")
    if callee not in {"__gen_parse_material", "CryptoJS.enc.Utf8.parse", "CryptoJS.enc.Hex.parse", "CryptoJS.enc.Base64.parse", "CryptoJS.enc.Latin1.parse"}:
        return None
    args = derivation.get("args") or []
    if len(args) < 2:
        return None
    second = args[1]
    if isinstance(second, dict) and str(second.get("type") or "") == "literal":
        return normalize_encoding_name(second.get("value"))
    return normalize_encoding_name(second)


def backfill_crypto_step_encodings(execution_flow: list[dict[str, Any]]) -> None:
    """Propagate derive_key/derive_iv encoding hints into following encrypt/sign steps."""
    last_key_encoding: str | None = None
    last_iv_encoding: str | None = None

    for step in execution_flow:
        step_type = str(step.get("step_type", "")).lower()
        runtime_args = step.setdefault("runtime_args", {})

        if step_type == "derive_key":
            inferred = _encoding_from_derivation(runtime_args.get("derivation"))
            if inferred:
                runtime_args.setdefault("key_encoding", inferred)
                last_key_encoding = inferred
            continue

        if step_type == "derive_iv":
            inferred = _encoding_from_derivation(runtime_args.get("derivation"))
            if inferred:
                runtime_args.setdefault("iv_encoding", inferred)
                last_iv_encoding = inferred
            continue

        if step_type in {"encrypt", "decrypt", "sign", "hash"}:
            if last_key_encoding and runtime_args.get("key_encoding") in [None, ""]:
                runtime_args["key_encoding"] = last_key_encoding
            if last_iv_encoding and runtime_args.get("iv_encoding") in [None, ""]:
                runtime_args["iv_encoding"] = last_iv_encoding


def build_runtime_args_from_detail(detail: dict[str, Any], algorithm: str, op_type: str) -> dict[str, Any]:
    """从 detail 提取 step 的 runtime_args。"""
    runtime_args: dict[str, Any] = {}
    resolved_val = detail.get("resolved_value")

    if op_type == "setkey" and resolved_val:
        if str(algorithm).upper() == "RSA":
            runtime_args["public_key"] = resolved_val
        else:
            runtime_args["key"] = resolved_val
    elif op_type == "setiv" and resolved_val:
        runtime_args["iv"] = resolved_val
    elif op_type == "pack" and "info" in detail:
        runtime_args["packing_info"] = normalize_packing_info(detail.get("info"))
    elif op_type.startswith("derive_") and "derivation" in detail:
        runtime_args["derivation"] = detail.get("derivation")

    if str(op_type).lower() in {"encrypt", "decrypt", "sign", "hash"}:
        for field_name in [
            "mode",
            "padding",
            "input_encoding",
            "output_encoding",
            "key_encoding",
            "iv_encoding",
            "placement",
            "signature_placement",
            "signature_field",
            "signature_header_name",
            "signature_query_param",
            "sign_input_rule",
            "sign_input_parts",
            "sign_input_canonicalization",
        ]:
            if field_name in detail and detail.get(field_name) not in [None, ""]:
                runtime_args[field_name] = detail.get(field_name)
        inferred_encodings = infer_encoding_runtime_args(detail)
        for field_name, field_value in inferred_encodings.items():
            if field_name not in runtime_args and field_value not in [None, ""]:
                runtime_args[field_name] = field_value

    return runtime_args


def forward_detail_fields_to_step(step: dict[str, Any], detail: dict[str, Any]) -> None:
    """透传后续阶段会用到的结构化字段。"""
    for field_name in [
        "output_variable", "input_expression", "input_derivation", "input_source_keys", "output_transform", "target",
        "mode", "padding", "input_encoding", "output_encoding", "key_encoding", "iv_encoding",
        "placement", "signature_placement", "signature_field", "signature_header_name", "signature_query_param",
        "sign_input_rule", "sign_input_parts", "sign_input_canonicalization"
    ]:
        if field_name in detail:
            step[field_name] = detail[field_name]


def collect_inferred_payload_keys(raw_operations: list[dict[str, Any]]) -> list[str]:
    """从 operations/details 中推断 payload 字段集合，并保留首次出现顺序。"""
    inferred_ordered: list[str] = []
    seen: set[str] = set()

    def push_key(value: Any) -> None:
        key = str(value) if value is not None else ""
        if not key or key in seen:
            return
        seen.add(key)
        inferred_ordered.append(key)
    for op_group in raw_operations:
        for detail in op_group.get("details", []) or []:
            if detail.get("operation") == "DataStructure" and isinstance(detail.get("inferred_keys"), list):
                for key in detail["inferred_keys"]:
                    push_key(key)

            if "input_derivation" in detail:
                derived_keys: set[str] = set()
                extract_source_values(detail.get("input_derivation"), derived_keys)
                for key in sorted(derived_keys):
                    push_key(key)

            if detail.get("operation") == "pack" and "info" in detail:
                packing_info = normalize_packing_info(detail.get("info"))
                for deriv in (packing_info.get("value_derivations", {}) or {}).values():
                    derived_keys: set[str] = set()
                    extract_source_values(deriv, derived_keys)
                    for key in sorted(derived_keys):
                        push_key(key)


    # 过滤明显不是业务 payload 的内部变量名
    skip_names = {"jsonData", "formData", "dataToSend", "dataString", "encrypted", "encryptedData", "signature", "nonce", "timestamp", "random", "key", "iv", "publicKey"}
    return [key for key in inferred_ordered if key not in skip_names]


def build_execution_flow(raw_operations: list[dict[str, Any]], default_input_keys: list[str] | None = None) -> list[dict[str, Any]]:
    """从静态分析 operations 生成执行流水线。"""
    execution_flow: list[dict[str, Any]] = []
    for op_group in raw_operations:
        library = op_group.get("library")
        algorithm = op_group.get("algorithm")
        for detail in op_group.get("details", []) or []:
            op_type = detail.get("operation")
            if not op_type or op_type == "DataStructure":
                continue

            step = {
                "step_type": op_type,
                "library": library,
                "algorithm": algorithm,
                "line": detail.get("line"),
                "context": str(detail.get("context", "")).strip(),
                "runtime_args": build_runtime_args_from_detail(detail, str(algorithm), str(op_type)),
            }
            forward_detail_fields_to_step(step, detail)

            if (
                str(op_type).lower() in {"encrypt", "sign"}
                and not step.get("input_source_keys")
                and isinstance(default_input_keys, list)
                and default_input_keys
            ):
                step["input_source_keys"] = list(default_input_keys)

            # 签名步骤若未给出输出变量，补齐默认变量名，避免 pack 阶段引用 signature 时成为悬空引用。
            if str(op_type).lower() == "sign" and not step.get("output_variable"):
                step["output_variable"] = "signature"
            execution_flow.append(step)

    execution_flow.sort(key=lambda x: int(x.get("line") or 0))
    return execution_flow


def build_hints(raw_operations: list[dict[str, Any]]) -> list[str]:
    """提取关键上下文提示，便于人工排障。"""
    hints: list[str] = []
    for op in raw_operations:
        for detail in op.get("details", []) or []:
            line = detail.get("line")
            ctx = str(detail.get("context", "")).strip()
            if line and ctx:
                hints.append(f"Line {line}: {ctx}")
    return hints


def infer_dynamic_endpoint_hint(raw_operations: list[dict[str, Any]], execution_flow: list[dict[str, Any]]) -> dict[str, Any]:
    """基于静态分析结果推断端点是否属于动态参数/服务端中间参数路径。"""
    dynamic_markers = {"key", "iv", "nonce", "timestamp", "signature", "sign", "token"}
    dynamic_fields: set[str] = set()
    reasons: set[str] = set()
    server_intermediate_calls: set[str] = set()

    for step in execution_flow:
        step_type = str(step.get("step_type", "")).lower()
        context_text = str(step.get("context", "")).lower()

        if step_type.startswith("derive_"):
            reasons.add("has_derive_step")
            target = step_type.replace("derive_", "").strip()
            if target:
                dynamic_fields.add(target)

        if step_type == "sign":
            reasons.add("has_sign_step")
            dynamic_fields.add("signature")

        if step_type == "pack":
            packing_info = (step.get("runtime_args", {}) or {}).get("packing_info", {}) or {}
            structure = packing_info.get("structure", {}) or {}
            for field_name in structure.keys():
                if str(field_name) in dynamic_markers:
                    dynamic_fields.add(str(field_name))
                    reasons.add("pack_contains_dynamic_field")

        if any(token in context_text for token in ["date.now", "math.random", "wordarray.random", "nonce", "timestamp"]):
            reasons.add("has_random_or_timestamp_expression")

        if _infer_server_intermediate_fetch_from_context(context_text):
            reasons.add("has_server_intermediate_fetch")
            server_intermediate_calls.add(str(step.get("context", "")).strip())

    for op_group in raw_operations:
        for detail in op_group.get("details", []) or []:
            ctx = str(detail.get("context", "")).strip()
            ctx_lc = ctx.lower()
            if _infer_server_intermediate_fetch_from_context(ctx_lc):
                reasons.add("has_server_intermediate_fetch")
                server_intermediate_calls.add(ctx)

    server_calls = sorted([item for item in server_intermediate_calls if item])
    is_dynamic = bool(dynamic_fields or reasons)
    return {
        "is_dynamic": is_dynamic,
        "needs_server_intermediate": "has_server_intermediate_fetch" in reasons,
        "dynamic_fields": sorted(dynamic_fields),
        "reasons": sorted(reasons),
        "server_intermediate_calls": server_calls,
        "hint_version": "v1",
    }


def generate_skeletons() -> None:
    """基于最新静态分析生成统一基线骨架文件。"""
    static_analysis_file = get_latest_analysis_file()
    if not static_analysis_file:
        print(f"[Error] Static analysis directory or file not found in: {ANALYSIS_DIR}")
        print("Please run the static analysis phase first.")
        return

    print(f"[Info] Loading analysis from: {static_analysis_file.name}")
    try:
        with open(static_analysis_file, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError:
        print(f"[Error] Failed to parse JSON file: {static_analysis_file}")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp_str = static_analysis_file.stem.replace("static_analysis_", "")
    output_path = OUTPUT_DIR / f"baseline_skeletons_{timestamp_str}.json"

    crypto_map = data.get("endpoint_crypto_map", {}) or {}
    endpoints = data.get("endpoints", []) or []
    print(f"[Info] Found {len(endpoints)} endpoints. Generating consolidated baseline file...")

    all_skeletons: list[dict[str, Any]] = []
    used_ids: dict[str, int] = {}

    for endpoint in endpoints:
        url = endpoint.get("url")
        if not url:
            continue

        base_id = url.split("/")[-1].split("?")[0].replace(".php", "") or "endpoint"
        used_ids[base_id] = used_ids.get(base_id, 0) + 1
        endpoint_id = base_id if used_ids[base_id] == 1 else f"{base_id}_{used_ids[base_id]}"

        ep_details = crypto_map.get(url, {}) or {}
        raw_operations = ep_details.get("operations", []) or []
        inferred_payload_keys = collect_inferred_payload_keys(raw_operations)
        execution_flow = build_execution_flow(raw_operations, default_input_keys=inferred_payload_keys)
        reconcile_packing_bridges(execution_flow)
        backfill_crypto_step_encodings(execution_flow)
        dynamic_hint = infer_dynamic_endpoint_hint(raw_operations, execution_flow)
        hints = build_hints(raw_operations)

        if inferred_payload_keys:
            print(f"[Info] [{endpoint_id}] Inferred payload keys: {inferred_payload_keys}")
            initial_payload = {k: "<Fill Value>" for k in inferred_payload_keys}
        else:
            initial_payload = {"_comment": "Fill your payload here"}

        skeleton = {
            "meta": {
                "id": endpoint_id,
                "url": url,
                "method": endpoint.get("method", "POST"),
                "trigger_function": endpoint.get("trigger_function"),
                "crypto_algorithms": ep_details.get("algorithms", []) or [],
                "source_analysis_file": static_analysis_file.name,
                "execution_flow": execution_flow,
                "hints": hints,
            },
            "status": "PENDING_PAYLOAD",
            "request": {
                "payload": initial_payload,
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            },
            "validation": {
                "verified": False,
                "runtime_params": {},
                "trace": [],
                "dynamic": {
                    "hint": dynamic_hint,
                    "observed": {
                        "observed": False,
                        "observed_dynamic_fields": [],
                        "runtime_param_keys": [],
                        "fetch_urls": [],
                        "has_server_intermediate_fetch": False,
                        "capture_types": [],
                        "captured_at": None,
                        "observe_version": "v1",
                    },
                },
                "captured_ciphertext": None,
                "handler_ciphertext": None,
                "comparison_result": None,
            },
        }
        all_skeletons.append(skeleton)

    if not all_skeletons:
        print("[Warn] No endpoints found to generate skeletons.")
        return

    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(all_skeletons, handle, indent=2, ensure_ascii=False)

    print(f"\n[Success] Generated consolidated baseline with {len(all_skeletons)} entries.")
    print(f"File location: {output_path}")
    print("Next Step: populate request.payload (manual/auto), then run capture + verify + assess.")


if __name__ == "__main__":
    generate_skeletons()
