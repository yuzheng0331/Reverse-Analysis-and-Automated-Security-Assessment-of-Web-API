#!/usr/bin/env python3
"""Layer1 自动化生成：按算法条件组合生成基础稳定池。"""

from __future__ import annotations

import argparse
import itertools
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE_DIR))

from scripts.api_lab_builder.common import PruneRecord, append_jsonl, dedupe_key, dump_json, dump_yaml, load_yaml


def _product_dict(matrix: dict[str, list[Any]]) -> list[dict[str, Any]]:
    keys = list(matrix.keys())
    rows = []
    for values in itertools.product(*(matrix[k] for k in keys)):
        rows.append({k: v for k, v in zip(keys, values)})
    return rows


def _make_spec(algorithm: str, base: dict[str, Any], fixed: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "algorithm_stack": algorithm,
        "algo_params": {},
        "material_source": base.get("material_source"),
        "material_dynamicity": dict(base.get("material_dynamicity", {})),
        "validation_hops": fixed.get("validation_hops", "single_hop"),
        "anti_replay": row.get("anti_replay", "none"),
        "interlayers": list(fixed.get("interlayers", [])),
        "risk_tags": list(base.get("risk_tags", [])),
        "template_level": base.get("template_level", "BASELINE"),
    }

    if "session_policy" in base:
        spec["session_policy"] = dict(base["session_policy"])

    if algorithm == "PLAINTEXT_HMAC":
        placement = row.get("signature_placement") or base.get("signature_strategy", {}).get("placement")
        spec["signature_strategy"] = {"placement": placement}

    for key, value in row.items():
        if key in {"anti_replay", "signature_placement"}:
            continue
        spec["algo_params"][key] = value

    return spec


def _materialize_layer1_item(spec: dict[str, Any], cfg: dict[str, Any], seq: int) -> dict[str, Any]:
    item = dict(spec)
    item["algo_params"] = dict(spec.get("algo_params", {}))
    item["material_dynamicity"] = dict(spec.get("material_dynamicity", {}))
    item["risk_tags"] = list(spec.get("risk_tags", []))
    item["interlayers"] = list(spec.get("interlayers", []))
    if "signature_strategy" in spec:
        item["signature_strategy"] = dict(spec.get("signature_strategy", {}))
    if "session_policy" in spec:
        item["session_policy"] = dict(spec.get("session_policy", {}))

    # Layer1 不展开 2.7 路由维度，固定为基础路由，Layer5 再做翻倍展开。
    item["route_variant"] = "PLAIN_ROUTE"
    item["site_group"] = cfg["global"]["fixed_site_group"]
    item["id"] = f"layer1_{seq:05d}"
    return item


def _check_conflicts(spec: dict[str, Any], cfg: dict[str, Any]) -> list[PruneRecord]:
    errors: list[PruneRecord] = []
    spec_id = str(spec.get("id", "<unknown>"))
    algo = str(spec.get("algorithm_stack", ""))
    params = spec.get("algo_params", {}) if isinstance(spec.get("algo_params"), dict) else {}
    dynamic = spec.get("material_dynamicity", {}) if isinstance(spec.get("material_dynamicity"), dict) else {}
    anti_replay = str(spec.get("anti_replay", ""))
    signature_strategy = spec.get("signature_strategy", {}) if isinstance(spec.get("signature_strategy"), dict) else {}
    session_policy = spec.get("session_policy", {}) if isinstance(spec.get("session_policy"), dict) else {}

    # 兼容“原语链命名 + 历史命名”
    is_aes = algo in {"AES", "AES_CBC"}
    is_des = algo in {"DES", "DES_CBC"}
    is_rsa_only = algo == "RSA_ONLY"
    is_plain_hmac = algo == "PLAINTEXT_HMAC"

    # 字段唯一归属：algo_params 只能承载算法参数
    forbidden_param_keys = {
        "anti_replay",
        "material_source",
        "material_dynamicity",
        "signature_strategy",
        "session_policy",
        "signature_placement",
    }
    touched_forbidden = sorted(k for k in params.keys() if k in forbidden_param_keys)
    if touched_forbidden:
        errors.append(
            PruneRecord(
                spec_id,
                "CONFLICT_FIELD_OWNERSHIP_ALGO_PARAMS",
                f"algo_params 出现越权字段: {','.join(touched_forbidden)}",
            )
        )

    # signature_strategy 仅允许 coverage/placement
    invalid_sig_keys = sorted(k for k in signature_strategy.keys() if k not in {"coverage", "placement"})
    if invalid_sig_keys:
        errors.append(
            PruneRecord(
                spec_id,
                "CONFLICT_FIELD_OWNERSHIP_SIGNATURE_STRATEGY",
                f"signature_strategy 非法字段: {','.join(invalid_sig_keys)}",
            )
        )

    if algo not in set(cfg["global"]["algorithm_whitelist"]):
        errors.append(PruneRecord(spec_id, "SCHEMA_ALGO_NOT_ALLOWED", f"算法不在白名单: {algo}"))

    if str(spec.get("route_variant", "")) not in set(cfg["global"]["allowed_route_variants"]):
        errors.append(PruneRecord(spec_id, "SCHEMA_ROUTE_NOT_ALLOWED", "route_variant 不在允许集合"))

    if (is_aes or is_des) and str(params.get("mode", "")) == "":
        errors.append(PruneRecord(spec_id, "CONFLICT_SYMMETRIC_MODE_MISSING", "AES/DES 必须声明 mode"))

    if is_aes or is_des:
        mode = str(params.get("mode", "")).upper()
        if mode in {"CBC", "CFB", "OFB", "CTR"} and str(params.get("iv_policy", "absent")) == "absent":
            errors.append(
                PruneRecord(spec_id, "CONFLICT_SYMMETRIC_IV_ABSENT", "对称算法在该 mode 下要求 iv_policy != absent")
            )

    if is_rsa_only:
        blocked = [k for k in ["mode", "iv_policy", "padding"] if k in params]
        if blocked:
            errors.append(PruneRecord(spec_id, "CONFLICT_RSA_ONLY_SYMMETRIC_PARAMS", f"RSA_ONLY 禁止参数: {','.join(blocked)}"))

    if is_plain_hmac:
        blocked = [k for k in ["key_size", "mode", "iv_policy", "padding"] if k in params]
        if blocked:
            errors.append(
                PruneRecord(spec_id, "CONFLICT_HMAC_SYMMETRIC_PARAMS", f"PLAINTEXT_HMAC 禁止参数: {','.join(blocked)}")
            )

        placement = str(signature_strategy.get("placement", ""))
        if placement not in {"body", "header", "query"}:
            errors.append(PruneRecord(spec_id, "CONFLICT_HMAC_NO_PLACEMENT", "HMAC 需要签名放置位置"))

    def _dyn_missing(name: str) -> bool:
        return str(dynamic.get(name, "absent")) == "absent"

    if anti_replay == "timestamp_only" and _dyn_missing("timestamp"):
        errors.append(PruneRecord(spec_id, "CONFLICT_ANTI_REPLAY_TIMESTAMP_MISSING", "timestamp_only 缺少 timestamp"))

    if anti_replay == "nonce_only" and _dyn_missing("nonce"):
        errors.append(PruneRecord(spec_id, "CONFLICT_ANTI_REPLAY_NONCE_MISSING", "nonce_only 缺少 nonce"))

    if anti_replay == "nonce_timestamp":
        missing = [k for k in ["nonce", "timestamp"] if _dyn_missing(k)]
        if missing:
            errors.append(PruneRecord(spec_id, "CONFLICT_ANTI_REPLAY_NONCE_TIMESTAMP_MISSING", f"依赖缺失: {','.join(missing)}"))

    if anti_replay in {"nonce_timestamp_signature", "nonce_timestamp_signature_session_binding"}:
        missing = [k for k in ["nonce", "timestamp", "signature"] if _dyn_missing(k)]
        placement = str(signature_strategy.get("placement", ""))
        if placement not in {"body", "header", "query"}:
            missing.append("signature_placement")
        if anti_replay == "nonce_timestamp_signature_session_binding" and str(session_policy.get("binding", "")) != "bind_cookie":
            missing.append("session_binding")
        if missing:
            errors.append(PruneRecord(spec_id, "CONFLICT_ANTI_REPLAY_INCOMPLETE", f"依赖缺失: {','.join(missing)}"))

    if str(params.get("padding", "")) == "NoPadding" and not bool(params.get("plaintext_block_aligned", False)):
        errors.append(PruneRecord(spec_id, "CONFLICT_NOPADDING_ALIGNMENT", "NoPadding 需要块对齐"))

    if len(spec.get("interlayers", [])) > int(cfg["constraints"]["max_interlayers"]):
        errors.append(PruneRecord(spec_id, "CONFLICT_INTERLAYERS_OVERFLOW", "夹层层数超过上限"))

    if set(str(tag).upper() for tag in spec.get("risk_tags", [])) & set(
        str(tag).upper() for tag in cfg["constraints"].get("unsupported_markers", [])
    ):
        errors.append(PruneRecord(spec_id, "UNSUPPORTED_COMPLEX_CUSTOM_CRYPTO", "命中不支持复杂样本标记"))

    return errors


def run_layer1_generate(config_path: Path, output_dir: Path | None = None) -> dict[str, Any]:
    cfg = load_yaml(config_path)
    out_cfg = cfg["output"]
    out_root = output_dir or (BASE_DIR / out_cfg["directory"])
    out_root.mkdir(parents=True, exist_ok=True)

    fixed = cfg["layer1"]["fixed"]
    # 兼容新旧命名：优先原语链，兼容历史键
    order = ["AES", "AES_CBC", "DES", "DES_CBC", "RSA_ONLY", "AES_RSA_ENVELOPE", "PLAINTEXT_HMAC"]

    candidates: list[dict[str, Any]] = []
    seq = 1
    for algorithm in order:
        if algorithm not in cfg["layer1"]["algorithms"]:
            continue
        item = cfg["layer1"]["algorithms"][algorithm]
        base = item["base"]
        matrix = item["matrix"]
        for row in _product_dict(matrix):
            spec = _make_spec(algorithm, base, fixed, row)
            candidates.append(_materialize_layer1_item(spec, cfg, seq))
            seq += 1

    prune_records: list[PruneRecord] = []
    passed_conflict: list[dict[str, Any]] = []
    for spec in candidates:
        conflicts = _check_conflicts(spec, cfg)
        if conflicts:
            prune_records.extend(conflicts)
            continue
        passed_conflict.append(spec)

    selected: list[dict[str, Any]] = []
    seen: dict[str, str] = {}
    for spec in passed_conflict:
        key = dedupe_key(spec)
        spec["_dedupe_key"] = key
        if key in seen:
            prune_records.append(
                PruneRecord(spec["id"], "DUPLICATE_SPEC", f"与 {seen[key]} 去重键冲突")
            )
            continue
        seen[key] = spec["id"]
        selected.append(spec)

    reason_counts: dict[str, int] = {}
    for row in prune_records:
        reason_counts[row.reason_code] = reason_counts.get(row.reason_code, 0) + 1

    report = {
        "counts": {
            "generated_candidates": len(candidates),
            "after_conflict_prune": len(passed_conflict),
            "selected": len(selected),
            "pruned": len(prune_records),
        },
        "pruned_reason_counts": reason_counts,
        "gate": {
            "has_selected": len(selected) > 0,
        },
        "notes": {
            "layer": "Layer1",
            "model": "conditional_sum_product_then_prune",
            "execution_order": order,
        },
    }

    dump_yaml(out_root / out_cfg["layer1_pool_yaml"], selected)
    dump_json(out_root / out_cfg["layer1_pool_json"], selected)
    dump_json(out_root / out_cfg["layer1_gate_report"], report)
    append_jsonl(
        out_root / out_cfg["layer1_pruned_reasons"],
        [{"spec_id": r.spec_id, "reason_code": r.reason_code, "message": r.message} for r in prune_records],
    )

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Layer1 自动化生成")
    parser.add_argument("--config", default="configs/api_lab_builder_step0.yaml")
    parser.add_argument("--output-dir", default="")
    args = parser.parse_args()

    config_path = BASE_DIR / args.config
    out_dir = (BASE_DIR / args.output_dir) if args.output_dir else None
    report = run_layer1_generate(config_path, out_dir)

    print("[Layer1] 完成")
    print(report)


if __name__ == "__main__":
    main()


