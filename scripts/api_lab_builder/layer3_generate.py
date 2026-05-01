#!/usr/bin/env python3
"""Layer3 自动化生成：基于 Layer2 做弱混淆与风险层扩展（2.9）。"""

from __future__ import annotations

import argparse
import copy
import sys
import time
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE_DIR))

from scripts.api_lab_builder.common import PruneRecord, append_jsonl, dedupe_key, dump_json, dump_yaml, load_yaml


DEFAULT_TEMPLATES: list[dict[str, Any]] = [
    {"name": "BASELINE_NO_SHIFT", "template_level": "BASELINE", "risk_tags": []},
    {"name": "WEAK_SHIFT_L1", "template_level": "L1", "risk_tags": ["WEAK_SHIFT_L1"]},
    {"name": "WEAK_SHIFT_L2", "template_level": "L2", "risk_tags": ["WEAK_SHIFT_L2"]},
    {"name": "WEAK_SHIFT_L3", "template_level": "L3", "risk_tags": ["WEAK_SHIFT_L3"]},
]


def _select_representative_bases(base_specs: list[dict[str, Any]], rep_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    if not rep_cfg.get("enabled", False):
        return base_specs

    per_algorithm = int(rep_cfg.get("per_algorithm", 0))
    if per_algorithm <= 0:
        return base_specs

    prefer_tags = {str(tag) for tag in (rep_cfg.get("prefer_risk_tags", []) or [])}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in base_specs:
        algo = str(item.get("algorithm_stack", "UNKNOWN"))
        grouped.setdefault(algo, []).append(item)

    selected: list[dict[str, Any]] = []
    for algo in sorted(grouped.keys()):
        rows = sorted(grouped[algo], key=lambda x: str(x.get("id", "")))
        if prefer_tags:
            tagged = [r for r in rows if prefer_tags.intersection({str(tag) for tag in r.get("risk_tags", []) or []})]
            fallback = [r for r in rows if r not in tagged]
            ordered = tagged + fallback
        else:
            ordered = rows
        selected.extend(ordered[:per_algorithm])
    return selected


def _normalize_templates(raw_templates: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_templates, list) or not raw_templates:
        return copy.deepcopy(DEFAULT_TEMPLATES)

    templates: list[dict[str, Any]] = []
    for idx, item in enumerate(raw_templates, start=1):
        if not isinstance(item, dict):
            continue
        templates.append(
            {
                "name": str(item.get("name") or item.get("template_level") or f"TEMPLATE_{idx}"),
                "template_level": str(item.get("template_level") or item.get("level") or "BASELINE"),
                "risk_tags": [str(tag) for tag in (item.get("risk_tags", []) or []) if str(tag)],
                "note": str(item.get("note") or ""),
            }
        )

    return templates or copy.deepcopy(DEFAULT_TEMPLATES)


def _normalize_weak_options(raw_options: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_options, list):
        return []
    options: list[dict[str, Any]] = []
    for idx, item in enumerate(raw_options, start=1):
        if not isinstance(item, dict):
            continue
        apply_cfg = item.get("apply") if isinstance(item.get("apply"), dict) else {}
        options.append(
            {
                "name": str(item.get("name") or f"WEAK_OPTION_{idx}"),
                "detection_source": str(item.get("detection_source") or "unknown"),
                "detection_signals": [str(sig) for sig in (item.get("detection_signals", []) or []) if str(sig)],
                "apply": copy.deepcopy(apply_cfg),
            }
        )
    return options


def _weak_option_priority_index(option_name: str, priority_names: list[str]) -> int:
    name = str(option_name).strip().upper()
    for idx, candidate in enumerate(priority_names):
        if name == str(candidate).strip().upper():
            return idx
    return len(priority_names)


def _match_weak_option(base: dict[str, Any], option: dict[str, Any]) -> bool:
    apply_cfg = option.get("apply") if isinstance(option.get("apply"), dict) else {}
    algo_values = apply_cfg.get("algorithm_stack")
    if isinstance(algo_values, list) and algo_values:
        algo = str(base.get("algorithm_stack") or "")
        if algo not in {str(x) for x in algo_values}:
            return False
    return True


def _set_nested(spec: dict[str, Any], dotted_path: str, value: Any) -> None:
    parts = [p for p in str(dotted_path).split(".") if p]
    if not parts:
        return
    cursor: dict[str, Any] = spec
    for part in parts[:-1]:
        if not isinstance(cursor.get(part), dict):
            cursor[part] = {}
        cursor = cursor[part]
    cursor[parts[-1]] = value


def _apply_weak_option(spec: dict[str, Any], option: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(spec)
    apply_cfg = option.get("apply") if isinstance(option.get("apply"), dict) else {}
    out["layer3_weak_option"] = str(option.get("name") or "")
    out["layer3_weak_detection_source"] = str(option.get("detection_source") or "")
    out["layer3_weak_detection_signals"] = [
        str(sig) for sig in (option.get("detection_signals", []) or []) if str(sig)
    ]
    out["layer3_role"] = "risk"

    extra_tags = [str(tag) for tag in (apply_cfg.get("append_risk_tags", []) or []) if str(tag)]
    tags = [str(tag) for tag in (out.get("risk_tags") or []) if str(tag)]
    for tag in extra_tags:
        if tag not in tags:
            tags.append(tag)
    out["risk_tags"] = tags

    if isinstance(apply_cfg.get("interlayers"), list):
        out["interlayers"] = [str(x) for x in (apply_cfg.get("interlayers") or []) if str(x)]

    if isinstance(apply_cfg.get("anti_replay"), list) and apply_cfg.get("anti_replay"):
        out["anti_replay"] = str((apply_cfg.get("anti_replay") or [out.get("anti_replay")])[0])

    binding_values = apply_cfg.get("session_policy.binding")
    if isinstance(binding_values, list) and binding_values:
        session_policy = out.get("session_policy") if isinstance(out.get("session_policy"), dict) else {}
        session_policy["binding"] = str(binding_values[0])
        out["session_policy"] = session_policy

    runtime_force = apply_cfg.get("force_runtime_args")
    if isinstance(runtime_force, dict):
        for path, value in runtime_force.items():
            _set_nested(out, f"weak_runtime_args.{path}", value)

    if bool(apply_cfg.get("drop_sign_input_rule")):
        out["weak_mutations"] = out.get("weak_mutations", []) + ["drop_sign_input_rule"]
    return out


def _build_control_mapping(
    selected: list[dict[str, Any]],
    required: bool,
    match_keys: list[str],
) -> tuple[list[dict[str, Any]], list[PruneRecord]]:
    controls = [row for row in selected if str(row.get("layer3_role") or "") == "control"]
    risks = [row for row in selected if str(row.get("layer3_role") or "") == "risk"]

    control_by_source: dict[str, dict[str, Any]] = {}
    for ctrl in controls:
        src = str(ctrl.get("source_layer2_id") or "")
        if src and src not in control_by_source:
            control_by_source[src] = ctrl

    mapping_rows: list[dict[str, Any]] = []
    prune: list[PruneRecord] = []
    for risk in risks:
        weak_id = str(risk.get("id") or "")
        src = str(risk.get("source_layer2_id") or "")
        control = control_by_source.get(src)

        if control is None and controls:
            for candidate in controls:
                hit = True
                for key in match_keys:
                    if candidate.get(key) != risk.get(key):
                        hit = False
                        break
                if hit:
                    control = candidate
                    break

        if control is None:
            if required:
                prune.append(
                    PruneRecord(
                        weak_id or "unknown",
                        "LAYER3_CONTROL_MAPPING_MISSING",
                        "未找到同构 Layer3 control 样本",
                    )
                )
            continue

        mapping_rows.append(
            {
                "weak_id": weak_id,
                "control_id": str(control.get("id") or ""),
                "source_layer2_id": src,
                "source_layer1_id": risk.get("source_layer1_id") or control.get("source_layer1_id"),
                "match_keys": {key: risk.get(key) for key in match_keys},
            }
        )

    return mapping_rows, prune


def _apply_template(base: dict[str, Any], template: dict[str, Any], seq: int) -> dict[str, Any]:
    spec = copy.deepcopy(base)
    spec["source_layer2_id"] = str(base.get("id", ""))
    spec["id"] = f"layer3_{seq:05d}"

    base_tags = [str(tag) for tag in (base.get("risk_tags", []) or []) if str(tag)]
    template_tags = [str(tag) for tag in (template.get("risk_tags", []) or []) if str(tag)]
    combined_tags: list[str] = []
    for tag in base_tags + template_tags:
        if tag not in combined_tags:
            combined_tags.append(tag)

    spec["template_level"] = str(template.get("template_level") or spec.get("template_level") or "BASELINE")
    spec["risk_tags"] = combined_tags
    spec["layer3_template"] = str(template.get("name") or spec["template_level"])
    if template.get("note"):
        spec["layer3_template_note"] = str(template.get("note"))
    if str(template.get("name") or "").upper() in {"BASELINE_NO_SHIFT", "CONTROL_NO_SHIFT"}:
        spec["layer3_role"] = "control"
    else:
        spec["layer3_role"] = "risk"
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

    base_filter = layer3_cfg.get("base_filter", {}) if isinstance(layer3_cfg.get("base_filter"), dict) else {}
    filtered_base = [item for item in base_specs if all(item.get(k) == v for k, v in base_filter.items())]

    rep_cfg = layer3_cfg.get("representative_seed", {}) if isinstance(layer3_cfg.get("representative_seed"), dict) else {}
    seeded_base = _select_representative_bases(filtered_base, rep_cfg)

    templates = _normalize_templates(layer3_cfg.get("templates"))
    if not templates:
        templates = copy.deepcopy(DEFAULT_TEMPLATES)
    weak_options = _normalize_weak_options(layer3_cfg.get("weak_design_options"))
    baseline_template = next(
        (
            t
            for t in templates
            if str(t.get("name") or "").upper() in {"BASELINE_NO_SHIFT", "CONTROL_NO_SHIFT"}
        ),
        templates[0] if templates else {"name": "BASELINE_NO_SHIFT", "template_level": "BASELINE", "risk_tags": []},
    )

    coverage_cfg = layer3_cfg.get("coverage", {}) if isinstance(layer3_cfg.get("coverage"), dict) else {}
    max_selected_per_base = int(coverage_cfg.get("max_selected_per_base", len(templates)))
    if max_selected_per_base <= 0:
        max_selected_per_base = len(templates)
    preferred_weak_options = [
        str(name)
        for name in (coverage_cfg.get("prefer_weak_options") or [
            "L3_SIGN_RULE_MISSING",
            "L3_SESSION_BINDING_MISSING",
            "L3_INTERLAYER_WEAK_EFFECT",
        ])
        if str(name).strip()
    ]
    enforce_fields = coverage_cfg.get("enforce_value_coverage_fields", []) or []
    if not isinstance(enforce_fields, list):
        enforce_fields = []

    constraints_cfg = layer3_cfg.get("constraints", {}) if isinstance(layer3_cfg.get("constraints"), dict) else {}
    max_risk_tags = int(constraints_cfg.get("max_risk_tags", 0)) if isinstance(constraints_cfg.get("max_risk_tags"), int) else 0

    existing_keys = {dedupe_key(item) for item in base_specs}
    selected_keys = set(existing_keys)
    selected: list[dict[str, Any]] = []
    prune_records: list[PruneRecord] = []
    generated_candidates = 0

    for base in seeded_base:
        candidates: list[dict[str, Any]] = []
        for template in templates:
            spec = _apply_template(base, template, len(selected) + len(candidates) + 1)
            generated_candidates += 1

            if max_risk_tags > 0 and len(spec.get("risk_tags", [])) > max_risk_tags:
                prune_records.append(
                    PruneRecord(spec["id"], "CONFLICT_RISK_TAG_OVERFLOW", "risk_tags 数量超过上限")
                )
                continue

            key = dedupe_key(spec)
            is_control_template = str(template.get("name") or "").upper() in {"BASELINE_NO_SHIFT", "CONTROL_NO_SHIFT"}
            if key in selected_keys and not is_control_template:
                prune_records.append(
                    PruneRecord(spec["id"], "DUPLICATE_WITH_LAYER2_OR_SELECTED", "与 layer2 或已选 layer3 去重键冲突")
                )
                continue

            candidates.append(spec)

        # 基于弱设计选项生成“可评估风险样本”。
        base_control = _apply_template(base, baseline_template, len(selected) + len(candidates) + 1)
        for option in weak_options:
            if not _match_weak_option(base, option):
                continue
            weak_spec = _apply_weak_option(base_control, option)
            weak_spec["id"] = f"layer3_{len(selected) + len(candidates) + 1:05d}"
            generated_candidates += 1
            if max_risk_tags > 0 and len(weak_spec.get("risk_tags", [])) > max_risk_tags:
                prune_records.append(
                    PruneRecord(weak_spec["id"], "CONFLICT_RISK_TAG_OVERFLOW", "risk_tags 数量超过上限")
                )
                continue
            candidates.append(weak_spec)

        # 选择优先级：control 基线 > 弱设计风险样本 > 其余模板样本。
        controls = [c for c in candidates if str(c.get("layer3_role") or "") == "control"]
        weak_risks = sorted(
            [c for c in candidates if str(c.get("layer3_weak_option") or "")],
            key=lambda c: _weak_option_priority_index(str(c.get("layer3_weak_option") or ""), preferred_weak_options),
        )
        others = [c for c in candidates if c not in controls and c not in weak_risks]

        picked: list[dict[str, Any]] = []
        if controls:
            picked.append(controls[0])
        for item in weak_risks:
            if len(picked) >= max_selected_per_base:
                break
            if item not in picked:
                picked.append(item)
        for item in others:
            if len(picked) >= max_selected_per_base:
                break
            if item not in picked:
                picked.append(item)

        for item in picked:
            selected_keys.add(dedupe_key(item))
            selected.append(item)

    # 全局兜底：确保每个“可匹配弱设计选项”至少有一个样本进入池。
    matchable_option_names: set[str] = set()
    for option in weak_options:
        option_name = str(option.get("name") or "")
        if not option_name:
            continue
        if any(_match_weak_option(base, option) for base in seeded_base):
            matchable_option_names.add(option_name)

    selected_weak_names = {
        str(row.get("layer3_weak_option") or "")
        for row in selected
        if str(row.get("layer3_weak_option") or "")
    }
    missing_option_names = sorted(matchable_option_names - selected_weak_names)

    for option_name in missing_option_names:
        option = next((row for row in weak_options if str(row.get("name") or "") == option_name), None)
        if option is None:
            continue

        matched_base = next((base for base in seeded_base if _match_weak_option(base, option)), None)
        if matched_base is None:
            continue

        source_id = str(matched_base.get("id") or "")
        existing_control = next(
            (
                row
                for row in selected
                if str(row.get("layer3_role") or "") == "control"
                and str(row.get("source_layer2_id") or "") == source_id
            ),
            None,
        )
        if existing_control is None:
            control_spec = _apply_template(matched_base, baseline_template, len(selected) + 1)
            selected.append(control_spec)
            selected_keys.add(dedupe_key(control_spec))

        weak_base_control = _apply_template(matched_base, baseline_template, len(selected) + 1)
        weak_spec = _apply_weak_option(weak_base_control, option)
        weak_spec["id"] = f"layer3_{len(selected) + 1:05d}"
        if max_risk_tags > 0 and len(weak_spec.get("risk_tags", [])) > max_risk_tags:
            prune_records.append(
                PruneRecord(weak_spec["id"], "CONFLICT_RISK_TAG_OVERFLOW", "risk_tags 数量超过上限")
            )
            continue
        selected.append(weak_spec)
        selected_keys.add(dedupe_key(weak_spec))

    reason_counts: dict[str, int] = {}
    for row in prune_records:
        reason_counts[row.reason_code] = reason_counts.get(row.reason_code, 0) + 1

    template_counts: dict[str, int] = {}
    risk_tag_counts: dict[str, int] = {}
    weak_option_counts: dict[str, int] = {}
    for item in selected:
        template_name = str(item.get("layer3_template") or item.get("template_level") or "UNKNOWN")
        template_counts[template_name] = template_counts.get(template_name, 0) + 1
        weak_name = str(item.get("layer3_weak_option") or "")
        if weak_name:
            weak_option_counts[weak_name] = weak_option_counts.get(weak_name, 0) + 1
        for tag in item.get("risk_tags", []) if isinstance(item.get("risk_tags"), list) else []:
            text = str(tag)
            risk_tag_counts[text] = risk_tag_counts.get(text, 0) + 1

    report = {
        "counts": {
            "layer2_base": len(base_specs),
            "layer2_base_after_filter": len(filtered_base),
            "layer2_base_after_representative_seed": len(seeded_base),
            "generated_candidates": generated_candidates,
            "selected": len(selected),
            "pruned": len(prune_records),
        },
        "coverage": {
            "strategy": "onewise_risk_injection",
            "templates": [str(item.get("name") or item.get("template_level") or "") for item in templates],
            "max_selected_per_base": max_selected_per_base,
            "prefer_weak_options": preferred_weak_options,
            "enforce_value_coverage_fields": enforce_fields,
        },
        "pruned_reason_counts": reason_counts,
        "gate": {
            "has_selected": len(selected) > 0,
            "base_filter": base_filter,
            "representative_seed": rep_cfg,
        },
        "template_counts": template_counts,
        "weak_option_counts": weak_option_counts,
        "risk_tag_counts": risk_tag_counts,
        "notes": {
            "layer": "Layer3",
            "input_source": str(source_pool),
            "increment_dimensions": ["2.9"],
            "mode": "weak_design_risk_layer",
        },
    }

    control_cfg = layer3_cfg.get("control_mapping", {}) if isinstance(layer3_cfg.get("control_mapping"), dict) else {}
    control_required = bool(control_cfg.get("required", False))
    match_keys = control_cfg.get("match_keys", []) if isinstance(control_cfg.get("match_keys"), list) else []
    mapping_rows, mapping_prune = _build_control_mapping(selected, control_required, [str(k) for k in match_keys if str(k)])
    prune_records.extend(mapping_prune)

    weak_rows = [row for row in selected if str(row.get("layer3_weak_option") or "")]
    detectable_rows = [
        row
        for row in weak_rows
        if isinstance(row.get("layer3_weak_detection_signals"), list) and len(row.get("layer3_weak_detection_signals") or []) > 0
    ]
    weak_total = len(weak_rows)
    detectable_ratio = (len(detectable_rows) / weak_total) if weak_total > 0 else 0.0

    gate_cfg = layer3_cfg.get("gate", {}) if isinstance(layer3_cfg.get("gate"), dict) else {}
    detectable_ratio_min = float(gate_cfg.get("detectable_weak_ratio_min", 0.0) or 0.0)

    metrics_cfg = layer3_cfg.get("metrics", {}) if isinstance(layer3_cfg.get("metrics"), dict) else {}
    report["metrics"] = {
        "detect_rate": {
            "enabled": bool((metrics_cfg.get("detect_rate") or {}).get("enabled", True)) if isinstance(metrics_cfg.get("detect_rate"), dict) else True,
            "formula": str((metrics_cfg.get("detect_rate") or {}).get("formula") or "detected_weak_design/total_layer3_weak_design") if isinstance(metrics_cfg.get("detect_rate"), dict) else "detected_weak_design/total_layer3_weak_design",
            "value": round(detectable_ratio, 6),
            "numerator": len(detectable_rows),
            "denominator": weak_total,
        },
        "delta_score": {
            "enabled": bool((metrics_cfg.get("delta_score") or {}).get("enabled", True)) if isinstance(metrics_cfg.get("delta_score"), dict) else True,
            "formula": str((metrics_cfg.get("delta_score") or {}).get("formula") or "score(control_L1L2)-score(layer3_variant)") if isinstance(metrics_cfg.get("delta_score"), dict) else "score(control_L1L2)-score(layer3_variant)",
            "value": None,
            "status": "pending_phase5",
        },
        "isg": {
            "enabled": bool((metrics_cfg.get("isg") or {}).get("enabled", True)) if isinstance(metrics_cfg.get("isg"), dict) else True,
            "formula": str((metrics_cfg.get("isg") or {}).get("formula") or "RejectLikeRate(interlayer)-RejectLikeRate(control)") if isinstance(metrics_cfg.get("isg"), dict) else "RejectLikeRate(interlayer)-RejectLikeRate(control)",
            "reject_like_modes": [str(x) for x in ((metrics_cfg.get("isg") or {}).get("reject_like_modes") or [])] if isinstance(metrics_cfg.get("isg"), dict) else [],
            "value": None,
            "status": "pending_phase5",
        },
    }

    report["control_mapping"] = {
        "enabled": bool(control_cfg.get("enabled", False)),
        "required": control_required,
        "match_keys": [str(k) for k in match_keys if str(k)],
        "pairs": len(mapping_rows),
        "missing_pairs": len(mapping_prune),
    }
    report["gate"].update(
        {
            "weak_selected": weak_total,
            "detectable_weak_selected": len(detectable_rows),
            "detectable_weak_ratio": round(detectable_ratio, 6),
            "detectable_weak_ratio_min": detectable_ratio_min,
            "detectable_weak_ratio_passed": detectable_ratio >= detectable_ratio_min,
            "control_mapping_required": control_required,
            "control_mapping_pairs": len(mapping_rows),
            "control_mapping_passed": (len(mapping_rows) > 0) if control_required else True,
            "required_weak_options": sorted(matchable_option_names),
            "required_weak_options_present": sorted(
                {
                    str(row.get("layer3_weak_option") or "")
                    for row in selected
                    if str(row.get("layer3_weak_option") or "")
                }
                & matchable_option_names
            ),
        }
    )
    report["gate"]["required_weak_options_missing"] = sorted(
        set(report["gate"].get("required_weak_options", [])) - set(report["gate"].get("required_weak_options_present", []))
    )
    report["gate"]["required_weak_options_passed"] = len(report["gate"]["required_weak_options_missing"]) == 0
    report["gate"]["passed"] = (
        report["gate"].get("has_selected", False)
        and report["gate"].get("detectable_weak_ratio_passed", False)
        and report["gate"].get("control_mapping_passed", False)
        and report["gate"].get("required_weak_options_passed", False)
    )

    if enforce_fields:
        coverage_matrix: dict[str, dict[str, Any]] = {}
        for field in enforce_fields:
            expected = sorted({str((template.get(field) if isinstance(template, dict) else "")) for template in templates if field in template})
            actual = sorted({str((row.get(field) if isinstance(row, dict) else "")) for row in selected if isinstance(row, dict) and field in row})
            missing = sorted(set(expected) - set(actual))
            coverage_matrix[field] = {
                "expected_values": expected,
                "actual_values": actual,
                "missing_values": missing,
                "covered": len(missing) == 0,
            }
        report["coverage"]["value_coverage_matrix"] = coverage_matrix

    dump_yaml(out_root / out_cfg["layer3_pool_yaml"], selected)
    dump_json(out_root / out_cfg["layer3_pool_json"], selected)
    dump_json(out_root / out_cfg["layer3_gate_report"], report)
    if out_cfg.get("layer3_control_mapping"):
        dump_json(out_root / str(out_cfg.get("layer3_control_mapping")), mapping_rows)
    append_jsonl(
        out_root / out_cfg["layer3_pruned_reasons"],
        [{"spec_id": r.spec_id, "reason_code": r.reason_code, "message": r.message} for r in prune_records],
    )

    if not report["gate"].get("passed", False):
        raise RuntimeError("Layer3 gate failed: detectable_weak_ratio/control_mapping requirements not met")

    return report


def main() -> None:
    start_time = time.time()

    parser = argparse.ArgumentParser(description="Layer3 自动化生成")
    parser.add_argument("--config", default="configs/api_lab_builder_step0.yaml")
    parser.add_argument("--output-dir", default="")
    args = parser.parse_args()

    config_path = BASE_DIR / args.config
    out_dir = (BASE_DIR / args.output_dir) if args.output_dir else None
    report = run_layer3_generate(config_path, out_dir)

    elapsed = time.time() - start_time
    print("[Layer3] 完成")
    print(f"[Layer3] 执行时长: {elapsed:.2f} 秒")
    print(report)


if __name__ == "__main__":
    main()
