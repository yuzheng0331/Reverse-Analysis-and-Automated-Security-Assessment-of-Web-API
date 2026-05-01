#!/usr/bin/env python3
"""Layer 流程前置门控：配置冻结与结构校验。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE_DIR))

from scripts.api_lab_builder.common import dump_json, dump_yaml, load_yaml


def _validate_config(cfg: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in ["global", "constraints", "layer1", "layer2", "layer3", "output"]:
        if key not in cfg:
            errors.append(f"缺少配置段: {key}")

    global_cfg = cfg.get("global", {})
    for key in ["fixed_site_group", "allowed_route_variants", "algorithm_whitelist"]:
        if key not in global_cfg:
            errors.append(f"global 缺少字段: {key}")

    layer1 = cfg.get("layer1", {})
    if "algorithms" not in layer1:
        errors.append("layer1 缺少 algorithms")
    else:
        for algo, meta in layer1["algorithms"].items():
            if "base" not in meta:
                errors.append(f"layer1.algorithms.{algo} 缺少 base")
            if "matrix" not in meta:
                errors.append(f"layer1.algorithms.{algo} 缺少 matrix")

    layer2 = cfg.get("layer2", {})
    for key in ["source_pool", "dimensions", "profile_map", "coverage"]:
        if key not in layer2:
            errors.append(f"layer2 缺少字段: {key}")

    layer3 = cfg.get("layer3", {})
    for key in ["source_pool", "templates", "constraints", "coverage"]:
        if key not in layer3:
            errors.append(f"layer3 缺少字段: {key}")

    field_rules = cfg.get("field_rules", {}) if isinstance(cfg.get("field_rules"), dict) else {}
    dep_rules = field_rules.get("dependency_constraints", [])
    if dep_rules and not isinstance(dep_rules, list):
        errors.append("field_rules.dependency_constraints 必须为列表")
    if isinstance(dep_rules, list):
        iv_policies = set((field_rules.get("algo_params", {}) or {}).get("iv_policy", []))
        material_sources = set((field_rules.get("material_source", {}) or {}).get("values", []))
        for idx, rule in enumerate(dep_rules, start=1):
            if not isinstance(rule, dict):
                errors.append(f"dependency_constraints[{idx}] 必须为对象")
                continue
            cond = rule.get("if")
            then = rule.get("then")
            if not isinstance(cond, dict) or not cond:
                errors.append(f"dependency_constraints[{idx}].if 必须为非空对象")
                continue
            if not isinstance(then, dict) or not then:
                errors.append(f"dependency_constraints[{idx}].then 必须为非空对象")
                continue
            # 允许两类主驱动条件：动态材料画像或防重放策略。
            if "material_dynamicity_profile" not in cond and "anti_replay" not in cond:
                errors.append(
                    f"dependency_constraints[{idx}].if 必须包含 material_dynamicity_profile 或 anti_replay"
                )
            for key, raw_values in then.items():
                values = raw_values if isinstance(raw_values, list) else [raw_values]
                if key == "material_source":
                    invalid = [v for v in values if v not in material_sources]
                    if invalid:
                        errors.append(f"dependency_constraints[{idx}] material_source 非法值: {invalid}")
                if key == "algo_params.iv_policy":
                    invalid = [v for v in values if v not in iv_policies]
                    if invalid:
                        errors.append(f"dependency_constraints[{idx}] algo_params.iv_policy 非法值: {invalid}")

    blueprint = cfg.get("layer_blueprint", {})
    if isinstance(blueprint, dict):
        for layer_name, layer_meta in blueprint.items():
            if not isinstance(layer_meta, dict):
                errors.append(f"layer_blueprint.{layer_name} 必须为对象")
                continue
            if "active_fields" not in layer_meta:
                errors.append(f"layer_blueprint.{layer_name} 缺少 active_fields")
                continue
            active_fields = layer_meta.get("active_fields", [])
            if not isinstance(active_fields, list):
                errors.append(f"layer_blueprint.{layer_name}.active_fields 必须为列表")
                continue
            frozen_defaults = layer_meta.get("frozen_defaults", {})
            if isinstance(frozen_defaults, dict):
                frozen_keys = set(frozen_defaults.keys())
                conflict = [f for f in active_fields if f in frozen_keys]
                if conflict:
                    errors.append(f"layer_blueprint.{layer_name} active_fields 与 frozen_defaults 冲突: {conflict}")

    output_cfg = cfg.get("output", {})
    for key in [
        "directory",
        "frozen_config",
        "step0_gate_report",
        "layer1_pool_yaml",
        "layer1_gate_report",
        "layer2_pool_yaml",
        "layer2_gate_report",
        "layer3_pool_yaml",
        "layer3_pool_json",
        "layer3_gate_report",
        "layer3_pruned_reasons",
        "layer3_control_mapping",
    ]:
        if key not in output_cfg:
            errors.append(f"output 缺少字段: {key}")

    return errors


def run_step0_freeze(config_path: Path, output_dir: Path | None = None) -> dict[str, Any]:
    cfg = load_yaml(config_path)
    out_cfg = cfg["output"]
    out_root = output_dir or (BASE_DIR / out_cfg["directory"])
    out_root.mkdir(parents=True, exist_ok=True)

    errors = _validate_config(cfg)
    report = {
        "config_path": str(config_path),
        "valid": not errors,
        "errors": errors,
        "frozen": {
            "site_group": cfg.get("global", {}).get("fixed_site_group"),
            "route_variants": cfg.get("global", {}).get("allowed_route_variants", []),
            "algorithm_whitelist": cfg.get("global", {}).get("algorithm_whitelist", []),
            "max_interlayers": cfg.get("constraints", {}).get("max_interlayers"),
        },
    }

    dump_yaml(out_root / out_cfg["frozen_config"], cfg)
    dump_json(out_root / out_cfg["step0_gate_report"], report)

    if errors:
        raise ValueError("Step0 配置校验失败: " + "; ".join(errors))
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Step0 配置冻结")
    parser.add_argument("--config", default="configs/api_lab_builder_step0.yaml")
    parser.add_argument("--output-dir", default="")
    args = parser.parse_args()

    config_path = BASE_DIR / args.config
    out_dir = (BASE_DIR / args.output_dir) if args.output_dir else None
    report = run_step0_freeze(config_path, out_dir)

    print("[Step0-Freeze] 完成")
    print(report)


if __name__ == "__main__":
    main()


