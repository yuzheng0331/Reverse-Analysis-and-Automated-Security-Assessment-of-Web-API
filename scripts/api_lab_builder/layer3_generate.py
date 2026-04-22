#!/usr/bin/env python3
"""Layer3 自动化生成：基于 Layer2 做可观测复杂度扩展（2.6 + 2.5）。"""

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


def _get_by_path(obj: dict[str, Any], path: str) -> Any:
    """按 a.b 形式取值，缺失返回 None。"""
    current: Any = obj
    for token in str(path).split("."):
        if isinstance(current, dict) and token in current:
            current = current[token]
            continue
        return None
    return current


def _bucket_key(spec: dict[str, Any], keys: list[str]) -> tuple[Any, ...]:
    return tuple(_get_by_path(spec, key) for key in keys)


def _select_bucket_bases(specs: list[dict[str, Any]], bucket_keys: list[str], per_bucket: int) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for item in specs:
        grouped.setdefault(_bucket_key(item, bucket_keys), []).append(item)

    selected: list[dict[str, Any]] = []
    for key in sorted(grouped.keys(), key=lambda x: str(x)):
        rows = sorted(grouped[key], key=lambda x: str(x.get("id", "")))
        selected.extend(rows[: max(1, int(per_bucket))])
    return selected


def _row_tuples(row: dict[str, Any], strength: int) -> set[tuple[tuple[str, Any], ...]]:
    if strength <= 1:
        return {tuple((k, row.get(k)) for k in sorted(row.keys()))}
    dims = list(row.keys())
    result: set[tuple[tuple[str, Any], ...]] = set()
    for combo in itertools.combinations(dims, strength):
        result.add(tuple((name, row.get(name)) for name in combo))
    return result


def _greedy_select(candidates: list[dict[str, Any]], strength: int, max_pick: int) -> list[dict[str, Any]]:
    if not candidates:
        return []
    if max_pick <= 0:
        return []

    candidate_tuples = [_row_tuples(item.get("_layer3_values", {}), strength) for item in candidates]
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


def _ensure_value_coverage(
    candidates: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    fields: list[str],
    max_pick: int,
) -> list[dict[str, Any]]:
    if not fields or len(selected) >= max_pick:
        return selected

    def _collect_values(rows: list[dict[str, Any]]) -> dict[str, set[Any]]:
        out: dict[str, set[Any]] = {name: set() for name in fields}
        for item in rows:
            row = item.get("_layer3_values", {}) if isinstance(item.get("_layer3_values"), dict) else {}
            for name in fields:
                if name in row:
                    out[name].add(row[name])
        return out

    universe = _collect_values(candidates)
    covered = _collect_values(selected)
    selected_ids = {id(item) for item in selected}

    while len(selected) < max_pick:
        missing_pairs: set[tuple[str, Any]] = set()
        for field in fields:
            for value in universe.get(field, set()):
                if value not in covered.get(field, set()):
                    missing_pairs.add((field, value))
        if not missing_pairs:
            break

        best: dict[str, Any] | None = None
        best_gain = 0
        for cand in candidates:
            if id(cand) in selected_ids:
                continue
            row = cand.get("_layer3_values", {}) if isinstance(cand.get("_layer3_values"), dict) else {}
            gain = 0
            for field, value in missing_pairs:
                if row.get(field) == value:
                    gain += 1
            if gain > best_gain:
                best = cand
                best_gain = gain

        if best is None or best_gain <= 0:
            break

        selected.append(best)
        selected_ids.add(id(best))
        row = best.get("_layer3_values", {}) if isinstance(best.get("_layer3_values"), dict) else {}
        for field in fields:
            if field in row:
                covered.setdefault(field, set()).add(row[field])

    return selected


def _make_layer3_candidate(base: dict[str, Any], interlayer: str, seq: int) -> dict[str, Any]:
    spec = copy.deepcopy(base)
    spec["source_layer2_id"] = str(base.get("id", ""))
    spec["id"] = f"layer3_tmp_{seq:06d}"
    spec["interlayers"] = [str(interlayer)]

    session_binding = ""
    if isinstance(spec.get("session_policy"), dict):
        session_binding = str(spec.get("session_policy", {}).get("binding", ""))

    sig_placement = ""
    if isinstance(spec.get("signature_strategy"), dict):
        sig_placement = str(spec.get("signature_strategy", {}).get("placement", ""))

    spec["_layer3_values"] = {
        "interlayer": str(interlayer),
        "anti_replay": str(spec.get("anti_replay", "")),
        "session_policy.binding": session_binding,
        "signature_strategy.placement": sig_placement,
    }
    return spec


def run_layer3_generate(config_path: Path, output_dir: Path | None = None) -> dict[str, Any]:
    cfg = load_yaml(config_path)
    out_cfg = cfg["output"]
    out_root = output_dir or (BASE_DIR / out_cfg["directory"])
    out_root.mkdir(parents=True, exist_ok=True)

    layer3_cfg = cfg.get("layer3", {}) or {}
    source_pool = out_root / str(layer3_cfg.get("source_pool", out_cfg["layer2_pool_yaml"]))
    base_specs = load_yaml(source_pool)
    if not isinstance(base_specs, list):
        raise ValueError("Layer3 source_pool 不是列表")

    bucket_keys = [str(key) for key in (layer3_cfg.get("bucket_keys", []) or [])]
    if not bucket_keys:
        raise ValueError("layer3.bucket_keys 不能为空")
    per_bucket = int(layer3_cfg.get("per_bucket_base_samples", 4))
    selected_bases = _select_bucket_bases(base_specs, bucket_keys, per_bucket)

    dimensions = layer3_cfg.get("dimensions", {}) or {}
    interlayers = [str(item) for item in (dimensions.get("interlayers", []) or [])]
    if not interlayers:
        raise ValueError("layer3.dimensions.interlayers 不能为空")

    constraints = layer3_cfg.get("constraints", {}) or {}
    primary = str(constraints.get("primary_interlayer", interlayers[0]))
    boundaries = {str(item) for item in (constraints.get("boundary_interlayers", []) or [])}
    high_value_anti_replay = {str(item) for item in (constraints.get("high_value_anti_replay", []) or [])}
    max_interlayers_per_base = int(constraints.get("max_interlayers_per_base", 1))

    coverage_cfg = layer3_cfg.get("coverage", {}) or {}
    strength = int(coverage_cfg.get("strength", 2))
    max_selected_per_base = int(coverage_cfg.get("max_selected_per_base", 2))
    enforce_fields = coverage_cfg.get("enforce_value_coverage_fields", []) or []
    if not isinstance(enforce_fields, list):
        enforce_fields = []

    existing_keys = {dedupe_key(item) for item in base_specs}
    selected_keys = set(existing_keys)
    selected: list[dict[str, Any]] = []
    prune_records: list[PruneRecord] = []

    generated_candidates = 0
    tmp_seq = 1

    for base in selected_bases:
        anti_replay = str(base.get("anti_replay", ""))
        allowed_interlayers: list[str] = []

        # 主评分口径优先 HEADER_SIGN_LAYER。
        if primary in interlayers:
            allowed_interlayers.append(primary)

        # 边界夹层只在高价值 anti_replay 上补点。
        if anti_replay in high_value_anti_replay:
            for item in interlayers:
                if item in boundaries and item not in allowed_interlayers:
                    allowed_interlayers.append(item)

        if not allowed_interlayers:
            allowed_interlayers = [interlayers[0]]

        candidates: list[dict[str, Any]] = []
        for interlayer in allowed_interlayers:
            spec = _make_layer3_candidate(base, interlayer, tmp_seq)
            tmp_seq += 1
            generated_candidates += 1

            if len(spec.get("interlayers", [])) > max_interlayers_per_base:
                prune_records.append(
                    PruneRecord(spec["id"], "CONFLICT_LAYER3_INTERLAYERS_OVERFLOW", "Layer3 每个基样本最多 1 个夹层")
                )
                continue

            conflicts = _check_conflicts(spec, cfg)
            if conflicts:
                prune_records.extend(conflicts)
                continue

            key = dedupe_key(spec)
            if key in selected_keys:
                prune_records.append(PruneRecord(spec["id"], "DUPLICATE_WITH_LAYER2_OR_SELECTED", "与 layer2 或已选 layer3 去重键冲突"))
                continue

            candidates.append(spec)

        if not candidates:
            continue

        picked = _greedy_select(candidates, strength=max(2, strength), max_pick=max_selected_per_base)
        picked = _ensure_value_coverage(candidates, picked, enforce_fields, max_selected_per_base)

        for item in picked:
            selected_keys.add(dedupe_key(item))
            selected.append(item)

    selected_rows = [dict(item.get("_layer3_values", {})) for item in selected]
    for idx, item in enumerate(selected, start=1):
        item["id"] = f"layer3_{idx:05d}"
        item.pop("_layer3_values", None)

    reason_counts: dict[str, int] = {}
    for row in prune_records:
        reason_counts[row.reason_code] = reason_counts.get(row.reason_code, 0) + 1

    value_coverage_matrix: dict[str, dict[str, Any]] = {}
    if enforce_fields:
        for field in enforce_fields:
            expected = sorted({str(v) for v in [primary, *boundaries]}) if field == "interlayer" else sorted(
                {str((row.get(field) if isinstance(row, dict) else "")) for row in selected_rows if isinstance(row, dict) and field in row}
            )
            actual = sorted({str((row.get(field) if isinstance(row, dict) else "")) for row in selected_rows if isinstance(row, dict) and field in row})
            missing = sorted(set(expected) - set(actual))
            value_coverage_matrix[field] = {
                "expected_values": expected,
                "actual_values": actual,
                "missing_values": missing,
                "covered": len(missing) == 0,
            }

    report = {
        "counts": {
            "layer2_base": len(base_specs),
            "layer2_base_after_bucket_sampling": len(selected_bases),
            "generated_candidates": generated_candidates,
            "selected": len(selected),
            "pruned": len(prune_records),
        },
        "coverage": {
            "strategy": "bucketed_observable_2wise",
            "strength": max(2, strength),
            "max_selected_per_base": max_selected_per_base,
            "enforce_value_coverage_fields": enforce_fields,
            "value_coverage_matrix": value_coverage_matrix,
        },
        "pruned_reason_counts": reason_counts,
        "gate": {
            "has_selected": len(selected) > 0,
            "bucket_keys": bucket_keys,
            "per_bucket_base_samples": per_bucket,
        },
        "notes": {
            "layer": "Layer3",
            "input_source": str(source_pool),
            "increment_dimensions": ["2.6", "2.5"],
            "primary_interlayer": primary,
            "boundary_interlayers": sorted(boundaries),
        },
    }

    dump_yaml(out_root / out_cfg["layer3_pool_yaml"], selected)
    dump_json(out_root / out_cfg["layer3_pool_json"], selected)
    dump_json(out_root / out_cfg["layer3_gate_report"], report)
    append_jsonl(
        out_root / out_cfg["layer3_pruned_reasons"],
        [{"spec_id": r.spec_id, "reason_code": r.reason_code, "message": r.message} for r in prune_records],
    )

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Layer3 自动化生成")
    parser.add_argument("--config", default="configs/api_lab_builder_step0.yaml")
    parser.add_argument("--output-dir", default="")
    args = parser.parse_args()

    config_path = BASE_DIR / args.config
    out_dir = (BASE_DIR / args.output_dir) if args.output_dir else None
    report = run_layer3_generate(config_path, out_dir)

    print("[Layer3] 完成")
    print(report)


if __name__ == "__main__":
    main()

