#!/usr/bin/env python3
"""Layer 流程前置门控：配置冻结与结构校验。"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from scripts.api_lab_builder.common import dump_json, dump_yaml, load_yaml

BASE_DIR = Path(__file__).resolve().parents[2]


def _validate_config(cfg: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in ["global", "constraints", "layer1", "output"]:
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

    output_cfg = cfg.get("output", {})
    for key in ["directory", "frozen_config", "step0_gate_report", "layer1_pool_yaml", "layer1_gate_report"]:
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

