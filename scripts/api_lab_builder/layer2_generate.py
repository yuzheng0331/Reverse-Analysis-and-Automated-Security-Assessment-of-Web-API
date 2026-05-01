#!/usr/bin/env python3
"""Layer2 自动化生成：在 Layer1 基础上增量扩展 2.3 + 2.5 + 2.8，并对显式夹层信号补标。"""

from __future__ import annotations

import argparse
import copy
import itertools
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE_DIR))

from scripts.api_lab_builder.common import PruneRecord, append_jsonl, dedupe_key, dump_json, dump_yaml, load_yaml
from scripts.api_lab_builder.layer1_generate import _check_conflicts


TARGET_INTERLAYERS = {"HEADER_SIGN_LAYER", "ENCODING_LAYER"}


def _combo_rows(dimensions: dict[str, list[Any]]) -> list[dict[str, Any]]:
    keys = list(dimensions.keys())
    rows: list[dict[str, Any]] = []
    for values in itertools.product(*(dimensions[k] for k in keys)):
        rows.append({k: v for k, v in zip(keys, values)})
    return rows


def _apply_layer2_row(base: dict[str, Any], row: dict[str, Any], profile_map: dict[str, Any]) -> dict[str, Any]:
    spec = copy.deepcopy(base)
    spec["source_layer1_id"] = str(base.get("id", ""))
    spec["material_source"] = row["material_source"]
    # 以 Layer1 基线动态性为底，避免对 RSA/HMAC 这类无 IV 算法强行注入 iv=static/dynamic。
    merged_dynamicity = dict(base.get("material_dynamicity", {}))
    merged_dynamicity.update(dict(profile_map[row["material_dynamicity_profile"]]))
    algo = str(spec.get("algorithm_stack", ""))
    if algo in {"RSA_ONLY", "PLAINTEXT_HMAC"}:
        merged_dynamicity["iv"] = str(base.get("material_dynamicity", {}).get("iv", "absent"))
    spec["material_dynamicity"] = merged_dynamicity
    spec["packaging"] = {
        "type": row["packaging_type"],
        "field_policy": row["field_policy"],
    }
    spec["transport"] = {
        "content_type": row["content_type"],
        "key_location": row["key_location"],
    }
    # 支持 Layer2 通过维度直接覆写算法参数（如 algo_params.iv_policy）。
    for key, value in row.items():
        if key.startswith("algo_params."):
            param = key.split(".", 1)[1]
            spec.setdefault("algo_params", {})
            # 仅对该算法原本支持的参数做覆写，避免给 RSA/HMAC 注入对称参数。
            if param in spec["algo_params"]:
                spec["algo_params"][param] = value
    if "anti_replay" in row:
        spec["anti_replay"] = row["anti_replay"]
    binding = row.get("session_policy.binding")
    if binding is not None:
        spec.setdefault("session_policy", {})
        spec["session_policy"]["binding"] = binding
    placement = row.get("signature_strategy.placement")
    if placement is not None:
        spec.setdefault("signature_strategy", {})
        spec["signature_strategy"]["placement"] = placement
    elif str(spec.get("anti_replay", "")) in {
        "nonce_timestamp_signature",
        "nonce_timestamp_signature_session_binding",
    }:
        # 签名型 anti_replay 至少给一个可解析默认放置位置，避免被 _check_conflicts 误剪。
        spec.setdefault("signature_strategy", {})
        spec["signature_strategy"].setdefault("placement", "body")
    spec["interlayers"] = _infer_interlayers(spec, row)
    spec["_layer2_values"] = dict(row)
    return spec


def _select_representative_bases(base_specs: list[dict[str, Any]], rep_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    if not rep_cfg.get("enabled", False):
        return base_specs

    per_algorithm = int(rep_cfg.get("per_algorithm", 0))
    if per_algorithm <= 0:
        return base_specs

    prefer_tags = set(rep_cfg.get("prefer_risk_tags", []))
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in base_specs:
        algo = str(item.get("algorithm_stack", "UNKNOWN"))
        grouped.setdefault(algo, []).append(item)

    selected: list[dict[str, Any]] = []
    for algo in sorted(grouped.keys()):
        rows = sorted(grouped[algo], key=lambda x: str(x.get("id", "")))
        if prefer_tags:
            tagged = [r for r in rows if prefer_tags.intersection(set(r.get("risk_tags", [])))]
            fallback = [r for r in rows if r not in tagged]
            ordered = tagged + fallback
        else:
            ordered = rows
        selected.extend(ordered[:per_algorithm])
    return selected


def _infer_interlayers(spec: dict[str, Any], row: dict[str, Any]) -> list[str]:
    """保守推断 Layer2 的显式夹层信号。

    只认“明确额外处理层”的信号，避免把 2.5 防重放或 2.8 打包字段误标成夹层。
    """
    layers: set[str] = set()

    def _norm(value: Any) -> str:
        return str(value).strip().lower()

    sig_place = _norm(row.get("signature_strategy.placement") or spec.get("signature_strategy", {}).get("placement"))
    if sig_place == "header":
        layers.add("HEADER_SIGN_LAYER")

    # 仅对明确的预编码/包裹型编码做标注；常规 urlencoded/json 不视作夹层。
    algo_params = spec.get("algo_params", {}) if isinstance(spec.get("algo_params"), dict) else {}
    encoding_values = {
        _norm(algo_params.get("plaintext_encoding")),
        _norm(algo_params.get("key_encoding")),
        _norm(algo_params.get("iv_encoding")),
    }
    if {"base64-pre-encoded", "base64"} & encoding_values:
        layers.add("ENCODING_LAYER")

    return sorted(layers)


def _row_conflicts(spec: dict[str, Any], row: dict[str, Any], cfg: dict[str, Any]) -> list[PruneRecord]:
    errors: list[PruneRecord] = []
    spec_id = str(spec.get("id", "<unknown>"))
    checks = cfg.get("layer2", {}).get("constraints", {})

    def _as_list(value: Any) -> list[Any]:
        if isinstance(value, list):
            return value
        return [value]

    def _resolve_value(path: str) -> Any:
        if path in row:
            return row[path]
        if path == "material_dynamicity_profile":
            return row.get("material_dynamicity_profile")
        if path == "session_policy.binding":
            session = spec.get("session_policy", {}) if isinstance(spec.get("session_policy"), dict) else {}
            return session.get("binding")
        if path == "signature_strategy.placement":
            sig = spec.get("signature_strategy", {}) if isinstance(spec.get("signature_strategy"), dict) else {}
            return sig.get("placement")
        if path.startswith("algo_params."):
            key = path.split(".", 1)[1]
            params = spec.get("algo_params", {}) if isinstance(spec.get("algo_params"), dict) else {}
            return params.get(key)
        return spec.get(path)

    if checks.get("enforce_content_type_match", True):
        pack = row["packaging_type"]
        ctype = row["content_type"]
        if pack == "json" and ctype != "application/json":
            errors.append(
                PruneRecord(spec_id, "CONFLICT_PACK_CONTENT_TYPE_MISMATCH", "json 打包必须使用 application/json")
            )
        if pack in {"urlencoded", "template"} and ctype == "application/json":
            errors.append(
                PruneRecord(spec_id, "CONFLICT_PACK_CONTENT_TYPE_MISMATCH", "urlencoded/template 不应使用 application/json")
            )

    dependency_rules = cfg.get("field_rules", {}).get("dependency_constraints", [])
    if isinstance(dependency_rules, list):
        for idx, rule in enumerate(dependency_rules, start=1):
            if not isinstance(rule, dict):
                continue
            cond = rule.get("if", {}) if isinstance(rule.get("if"), dict) else {}
            then = rule.get("then", {}) if isinstance(rule.get("then"), dict) else {}
            if not cond or not then:
                continue
            if not all(_resolve_value(key) == val for key, val in cond.items()):
                continue
            for target, allowed in then.items():
                current = _resolve_value(target)
                if target.startswith("algo_params.") and current is None:
                    # 该算法不包含此参数（如 RSA/HMAC 没有 iv_policy），跳过该条依赖判定。
                    continue
                allowed_values = _as_list(allowed)
                if current not in allowed_values:
                    errors.append(
                        PruneRecord(
                            spec_id,
                            "CONFLICT_DEPENDENCY_CONSTRAINT",
                            f"规则#{idx}冲突: {target}={current} 不在允许集合 {allowed_values}",
                        )
                    )
    return errors


def _tuple_keys_for_row(row: dict[str, Any], strength: int) -> set[tuple[tuple[str, Any], ...]]:
    keys = list(row.keys())
    result: set[tuple[tuple[str, Any], ...]] = set()
    for dims in itertools.combinations(keys, strength):
        result.add(tuple((d, row[d]) for d in dims))
    return result


def _greedy_twise_select(candidates: list[dict[str, Any]], strength: int, max_pick: int) -> list[dict[str, Any]]:
    if not candidates:
        return []
    if strength < 2:
        return candidates[:max_pick]

    candidate_tuples = [
        _tuple_keys_for_row(c.get("_layer2_values", {}), strength)
        for c in candidates
    ]
    uncovered: set[tuple[tuple[str, Any], ...]] = set()
    for tuples in candidate_tuples:
        uncovered.update(tuples)

    selected_idx: list[int] = []
    remained = set(range(len(candidates)))

    while uncovered and remained and len(selected_idx) < max_pick:
        best_idx = -1
        best_gain = -1
        for idx in sorted(remained):
            gain = len(candidate_tuples[idx] & uncovered)
            if gain > best_gain:
                best_idx = idx
                best_gain = gain
        if best_idx < 0 or best_gain <= 0:
            break
        selected_idx.append(best_idx)
        remained.remove(best_idx)
        uncovered -= candidate_tuples[best_idx]

    if len(selected_idx) < max_pick:
        for idx in sorted(remained):
            selected_idx.append(idx)
            if len(selected_idx) >= max_pick:
                break

    return [candidates[idx] for idx in selected_idx]


def _ensure_field_value_coverage(
    candidates: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    fields: list[str],
    max_pick: int,
) -> list[dict[str, Any]]:
    if not fields or len(selected) >= max_pick:
        return selected

    def _values_map(rows: list[dict[str, Any]]) -> dict[str, set[Any]]:
        out: dict[str, set[Any]] = {f: set() for f in fields}
        for item in rows:
            row = item.get("_layer2_values", {}) if isinstance(item.get("_layer2_values"), dict) else {}
            for f in fields:
                if f in row:
                    out[f].add(row[f])
        return out

    universe = _values_map(candidates)
    covered = _values_map(selected)
    selected_ids = {id(x) for x in selected}

    while len(selected) < max_pick:
        missing_pairs: set[tuple[str, Any]] = set()
        for f in fields:
            for value in universe.get(f, set()):
                if value not in covered.get(f, set()):
                    missing_pairs.add((f, value))
        if not missing_pairs:
            break

        best: dict[str, Any] | None = None
        best_gain = 0
        for cand in candidates:
            if id(cand) in selected_ids:
                continue
            row = cand.get("_layer2_values", {}) if isinstance(cand.get("_layer2_values"), dict) else {}
            gain = 0
            for pair in missing_pairs:
                f, value = pair
                if row.get(f) == value:
                    gain += 1
            if gain > best_gain:
                best = cand
                best_gain = gain

        if best is None or best_gain <= 0:
            break
        selected.append(best)
        selected_ids.add(id(best))
        row = best.get("_layer2_values", {}) if isinstance(best.get("_layer2_values"), dict) else {}
        for f in fields:
            if f in row:
                covered.setdefault(f, set()).add(row[f])

    return selected


def _ensure_non_hmac_interlayer_coverage(
    base: dict[str, Any],
    candidates: list[dict[str, Any]],
    picked: list[dict[str, Any]],
    max_pick: int,
) -> list[dict[str, Any]]:
    """For non-HMAC bases, keep explicit HEADER/ENCODING coverage when available."""
    if str(base.get("algorithm_stack", "")) == "PLAINTEXT_HMAC":
        return picked

    def _layers(item: dict[str, Any]) -> set[str]:
        raw = item.get("interlayers", []) if isinstance(item.get("interlayers"), list) else []
        return {str(layer) for layer in raw}

    available_targets = {
        layer
        for layer in TARGET_INTERLAYERS
        if any(layer in _layers(item) for item in candidates)
    }
    if not available_targets:
        return picked

    covered_targets = {
        layer
        for layer in TARGET_INTERLAYERS
        if any(layer in _layers(item) for item in picked)
    }
    missing_targets = sorted(available_targets - covered_targets)

    def _inject_target(target: str) -> None:
        # Prefer candidates that also carry the other target to maximize coverage per slot.
        ranked = sorted(
            [item for item in candidates if target in _layers(item)],
            key=lambda item: (
                1 if "ENCODING_LAYER" in _layers(item) else 0,
                1 if "HEADER_SIGN_LAYER" in _layers(item) else 0,
                str(item.get("id", "")),
            ),
            reverse=True,
        )
        if not ranked:
            return
        chosen = ranked[0]
        if chosen in picked:
            return
        if len(picked) < max_pick:
            picked.append(chosen)
            return
        for idx in range(len(picked) - 1, -1, -1):
            if not (_layers(picked[idx]) & TARGET_INTERLAYERS):
                picked[idx] = chosen
                return
        picked[-1] = chosen

    for target in missing_targets:
        _inject_target(target)

    return picked


def _ensure_control_coverage(
    candidates: list[dict[str, Any]],
    picked: list[dict[str, Any]],
    max_pick: int,
) -> list[dict[str, Any]]:
    """Keep at least one untagged row as control sample when candidate space allows."""

    def _has_interlayer(item: dict[str, Any]) -> bool:
        return bool(item.get("interlayers", []) if isinstance(item.get("interlayers"), list) else [])

    if any(not _has_interlayer(item) for item in picked):
        return picked

    untagged_candidates = [item for item in candidates if not _has_interlayer(item)]
    if not untagged_candidates:
        return picked

    control = sorted(untagged_candidates, key=lambda x: str(x.get("id", "")))[0]
    if control in picked:
        return picked

    if len(picked) < max_pick:
        picked.append(control)
        return picked

    # Replace the tail to preserve most greedy-selected rows while injecting one control.
    picked[-1] = control
    return picked


def run_layer2_generate(config_path: Path, output_dir: Path | None = None) -> dict[str, Any]:
    cfg = load_yaml(config_path)
    out_cfg = cfg["output"]
    out_root = output_dir or (BASE_DIR / out_cfg["directory"])
    out_root.mkdir(parents=True, exist_ok=True)

    layer2_cfg = cfg["layer2"]
    source_pool = out_root / str(layer2_cfg.get("source_pool", out_cfg["layer1_pool_yaml"]))
    base_specs = load_yaml(source_pool)
    if not isinstance(base_specs, list):
        raise ValueError("Layer2 source_pool 不是列表")

    base_filter = layer2_cfg.get("base_filter", {})
    filtered_base = [
        item
        for item in base_specs
        if all(item.get(k) == v for k, v in base_filter.items())
    ]
    rep_cfg = layer2_cfg.get("representative_seed", {}) if isinstance(layer2_cfg.get("representative_seed"), dict) else {}
    seeded_base = _select_representative_bases(filtered_base, rep_cfg)

    dimensions = layer2_cfg["dimensions"]
    profile_map = layer2_cfg["profile_map"]
    rows = _combo_rows(dimensions)

    strength = int(layer2_cfg.get("coverage", {}).get("strength", 3))
    max_selected_per_base = int(layer2_cfg.get("coverage", {}).get("max_selected_per_base", 18))
    enforce_fields = layer2_cfg.get("coverage", {}).get("enforce_value_coverage_fields", [])
    if not isinstance(enforce_fields, list):
        enforce_fields = []

    layer1_keys = {dedupe_key(item) for item in base_specs}
    selected_keys = set(layer1_keys)

    generated_candidates = 0
    prune_records: list[PruneRecord] = []
    selected: list[dict[str, Any]] = []
    coverage_before = 0
    coverage_after = 0

    temp_seq = 1
    for base in seeded_base:
        candidates: list[dict[str, Any]] = []

        for row in rows:
            spec = _apply_layer2_row(base, row, profile_map)
            spec["id"] = f"layer2_tmp_{temp_seq:06d}"
            temp_seq += 1
            generated_candidates += 1

            own_conflicts = _row_conflicts(spec, row, cfg)
            if own_conflicts:
                prune_records.extend(own_conflicts)
                continue

            conflicts = _check_conflicts(spec, cfg)
            if conflicts:
                prune_records.extend(conflicts)
                continue

            key = dedupe_key(spec)
            if key in selected_keys:
                prune_records.append(PruneRecord(spec["id"], "DUPLICATE_WITH_LAYER1_OR_SELECTED", "与 layer1 或已选 layer2 去重键冲突"))
                continue

            candidates.append(spec)

        if not candidates:
            continue

        base_universe: set[tuple[tuple[str, Any], ...]] = set()
        for item in candidates:
            base_universe.update(_tuple_keys_for_row(item.get("_layer2_values", {}), strength))
        coverage_before += len(base_universe)

        picked = _greedy_twise_select(candidates, strength, max_selected_per_base)
        picked = _ensure_field_value_coverage(candidates, picked, enforce_fields, max_selected_per_base)
        picked = _ensure_non_hmac_interlayer_coverage(base, candidates, picked, max_selected_per_base)
        picked = _ensure_control_coverage(candidates, picked, max_selected_per_base)
        for item in picked:
            coverage_after += len(_tuple_keys_for_row(item.get("_layer2_values", {}), strength))
            selected_keys.add(dedupe_key(item))
            selected.append(item)

    selected_value_rows = [dict(item.get("_layer2_values", {})) for item in selected]

    for idx, item in enumerate(selected, start=1):
        item["id"] = f"layer2_{idx:05d}"
        item.pop("_layer2_values", None)

    reason_counts: dict[str, int] = {}
    for row in prune_records:
        reason_counts[row.reason_code] = reason_counts.get(row.reason_code, 0) + 1

    report = {
        "counts": {
            "layer1_base": len(base_specs),
            "layer1_base_after_filter": len(filtered_base),
            "layer1_base_after_representative_seed": len(seeded_base),
            "generated_candidates": generated_candidates,
            "selected": len(selected),
            "pruned": len(prune_records),
        },
        "coverage": {
            "strategy": "greedy_max_uncovered_3wise",
            "strength": strength,
            "max_selected_per_base": max_selected_per_base,
            "enforce_value_coverage_fields": enforce_fields,
            "tuples_before_selection": coverage_before,
            "tuples_after_selection_sum": coverage_after,
        },
        "pruned_reason_counts": reason_counts,
        "gate": {"has_selected": len(selected) > 0},
        "notes": {
            "layer": "Layer2",
            "input_source": str(source_pool),
            "increment_dimensions": ["2.3", "2.5", "2.8"],
            "interlayer_tagging": "explicit_signal_only",
        },
    }

    interlayer_counts: dict[str, int] = {}
    for item in selected:
        for layer in item.get("interlayers", []) if isinstance(item.get("interlayers"), list) else []:
            text = str(layer)
            interlayer_counts[text] = interlayer_counts.get(text, 0) + 1
    report["counts"]["interlayer_tagged"] = sum(interlayer_counts.values())
    report["counts"]["interlayer_tagged_unique"] = len(interlayer_counts)
    if interlayer_counts:
        report["interlayer_tag_counts"] = interlayer_counts

    if enforce_fields:
        coverage_matrix: dict[str, dict[str, Any]] = {}
        for field in enforce_fields:
            expected = sorted({str(row.get(field)) for row in rows if field in row})
            actual = sorted({str(row.get(field)) for row in selected_value_rows if field in row})
            missing = sorted(set(expected) - set(actual))
            coverage_matrix[field] = {
                "expected_values": expected,
                "actual_values": actual,
                "missing_values": missing,
                "covered": len(missing) == 0,
            }
        report["coverage"]["value_coverage_matrix"] = coverage_matrix

    dump_yaml(out_root / out_cfg["layer2_pool_yaml"], selected)
    dump_json(out_root / out_cfg["layer2_pool_json"], selected)
    dump_json(out_root / out_cfg["layer2_gate_report"], report)
    append_jsonl(
        out_root / out_cfg["layer2_pruned_reasons"],
        [{"spec_id": r.spec_id, "reason_code": r.reason_code, "message": r.message} for r in prune_records],
    )

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Layer2 自动化生成")
    parser.add_argument("--config", default="configs/api_lab_builder_step0.yaml")
    parser.add_argument("--output-dir", default="")
    args = parser.parse_args()

    config_path = BASE_DIR / args.config
    out_dir = (BASE_DIR / args.output_dir) if args.output_dir else None
    report = run_layer2_generate(config_path, out_dir)

    print("[Layer2] 完成")
    print(report)


if __name__ == "__main__":
    main()















