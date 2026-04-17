#!/usr/bin/env python3
"""Layer1 自动化生成：按算法条件组合生成基础稳定池。"""

from __future__ import annotations

import argparse
import itertools
from pathlib import Path
from typing import Any

from scripts.api_lab_builder.common import PruneRecord, append_jsonl, dedupe_key, dump_json, dump_yaml, load_yaml

BASE_DIR = Path(__file__).resolve().parents[2]


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


def _expand_routes(spec: dict[str, Any], cfg: dict[str, Any], seq: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for route in cfg["global"]["allowed_route_variants"]:
        item = dict(spec)
        item["algo_params"] = dict(spec.get("algo_params", {}))
        item["material_dynamicity"] = dict(spec.get("material_dynamicity", {}))
        item["risk_tags"] = list(spec.get("risk_tags", []))
        if "interlayers" in spec:
            item["interlayers"] = list(spec.get("interlayers", []))
        if "signature_strategy" in spec:
            item["signature_strategy"] = dict(spec.get("signature_strategy", {}))
        if "session_policy" in spec:
            item["session_policy"] = dict(spec.get("session_policy", {}))

        item["route_variant"] = route
        item["site_group"] = cfg["global"]["fixed_site_group"]
        item["id"] = f"layer1_{seq:05d}_{route.lower()}"
        out.append(item)
    return out


def _check_conflicts(spec: dict[str, Any], cfg: dict[str, Any]) -> list[PruneRecord]:
    errors: list[PruneRecord] = []
    spec_id = str(spec.get("id", "<unknown>"))
    algo = str(spec.get("algorithm_stack", ""))
    params = spec.get("algo_params", {}) if isinstance(spec.get("algo_params"), dict) else {}
    dynamic = spec.get("material_dynamicity", {}) if isinstance(spec.get("material_dynamicity"), dict) else {}

    if algo not in set(cfg["global"]["algorithm_whitelist"]):
        errors.append(PruneRecord(spec_id, "SCHEMA_ALGO_NOT_ALLOWED", f"算法不在白名单: {algo}"))

    if str(spec.get("route_variant", "")) not in set(cfg["global"]["allowed_route_variants"]):
        errors.append(PruneRecord(spec_id, "SCHEMA_ROUTE_NOT_ALLOWED", "route_variant 不在允许集合"))

    if algo == "AES_CBC" and str(params.get("iv_policy", "absent")) == "absent":
        errors.append(PruneRecord(spec_id, "CONFLICT_AES_CBC_IV_ABSENT", "AES_CBC 要求 iv_policy != absent"))

    if algo == "RSA_ONLY":
        blocked = [k for k in ["mode", "iv_policy", "padding"] if k in params]
        if blocked:
            errors.append(PruneRecord(spec_id, "CONFLICT_RSA_ONLY_SYMMETRIC_PARAMS", f"RSA_ONLY 禁止参数: {','.join(blocked)}"))

    if algo == "PLAINTEXT_HMAC":
        placement = str(spec.get("signature_strategy", {}).get("placement", ""))
        if placement not in {"body", "header", "query"}:
            errors.append(PruneRecord(spec_id, "CONFLICT_HMAC_NO_PLACEMENT", "HMAC 需要签名放置位置"))

    if str(spec.get("anti_replay", "")) == "nonce_timestamp_signature_session_binding":
        missing = [k for k in ["nonce", "timestamp", "signature"] if str(dynamic.get(k, "absent")) == "absent"]
        if str(spec.get("session_policy", {}).get("binding", "")) != "bind_cookie":
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
    order = ["AES_CBC", "RSA_ONLY", "PLAINTEXT_HMAC"]

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
            expanded = _expand_routes(spec, cfg, seq)
            seq += 1
            candidates.extend(expanded)

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

