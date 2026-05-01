#!/usr/bin/env python3
"""Layer3 抽样写入：将 layer3 样本池写入目标站点。"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE_DIR))

from scripts.api_lab_builder.common import load_yaml
from scripts.api_lab_builder.layer1_write_sample import run_layer_write_sample


def _layer3_gate_precheck(config_path: Path, output_dir: Path | None = None) -> dict[str, Any]:
    cfg = load_yaml(config_path)
    out_cfg = cfg.get("output", {}) if isinstance(cfg.get("output"), dict) else {}
    layer3_cfg = cfg.get("layer3", {}) if isinstance(cfg.get("layer3"), dict) else {}
    out_root = output_dir or (BASE_DIR / str(out_cfg.get("directory", "runtime/api_lab_builder")))

    gate_path = out_root / str(out_cfg.get("layer3_gate_report", "layer3_gate_report.json"))
    mapping_path = out_root / str(out_cfg.get("layer3_control_mapping", "layer3_control_mapping.json"))
    pool_path = out_root / str(out_cfg.get("layer3_pool_yaml", "layer3_pool.yaml"))

    if not pool_path.exists():
        raise FileNotFoundError(f"Layer3 样本池不存在: {pool_path}")
    if not gate_path.exists():
        raise FileNotFoundError(f"Layer3 gate 报告不存在: {gate_path}")
    if not mapping_path.exists():
        raise FileNotFoundError(f"Layer3 control mapping 不存在: {mapping_path}")

    gate = load_yaml(gate_path)
    if not isinstance(gate, dict):
        raise ValueError("Layer3 gate 报告格式非法")

    gate_info = gate.get("gate", {}) if isinstance(gate.get("gate"), dict) else {}
    if not gate_info.get("passed", False):
        raise ValueError("Layer3 gate 未通过，禁止抽样写入")
    if not gate_info.get("detectable_weak_ratio_passed", False):
        raise ValueError("Layer3 detectable_weak_ratio 未达标，禁止抽样写入")
    if bool((layer3_cfg.get("control_mapping") or {}).get("required", False)) and not gate_info.get("control_mapping_passed", False):
        raise ValueError("Layer3 control_mapping 未满足要求，禁止抽样写入")
    return gate


def run_layer3_write_sample(config_path: Path, sample_size_override: int | None = None, output_dir: Path | None = None) -> dict:
    _layer3_gate_precheck(config_path, output_dir)
    return run_layer_write_sample(config_path, "layer3", sample_size_override, output_dir)


def main() -> None:
    start_time = time.time()
    parser = argparse.ArgumentParser(description="Layer3 抽样写入目标站点")
    parser.add_argument("--config", default="configs/api_lab_builder_step0.yaml")
    parser.add_argument("--sample-size", type=int, default=0)
    parser.add_argument("--output-dir", default="")
    args = parser.parse_args()

    config_path = BASE_DIR / args.config
    out_dir = (BASE_DIR / args.output_dir) if args.output_dir else None
    sample_size = args.sample_size if args.sample_size > 0 else None
    manifest = run_layer3_write_sample(config_path, sample_size, out_dir)

    elapsed = time.time() - start_time
    print("[Layer3-Write-Sample] 完成")
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(f"[Layer3-Write-Sample] 执行时长: {elapsed:.2f} 秒")


if __name__ == "__main__":
    main()

