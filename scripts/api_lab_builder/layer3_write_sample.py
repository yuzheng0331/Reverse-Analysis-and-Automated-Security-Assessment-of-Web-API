#!/usr/bin/env python3
"""Layer3 抽样写入：将 layer3 样本池写入目标站点。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE_DIR))

from scripts.api_lab_builder.layer1_write_sample import run_layer_write_sample


def run_layer3_write_sample(config_path: Path, sample_size_override: int | None = None, output_dir: Path | None = None) -> dict:
    return run_layer_write_sample(config_path, "layer3", sample_size_override, output_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description="Layer3 抽样写入目标站点")
    parser.add_argument("--config", default="configs/api_lab_builder_step0.yaml")
    parser.add_argument("--sample-size", type=int, default=0)
    parser.add_argument("--output-dir", default="")
    args = parser.parse_args()

    config_path = BASE_DIR / args.config
    out_dir = (BASE_DIR / args.output_dir) if args.output_dir else None
    sample_size = args.sample_size if args.sample_size > 0 else None
    manifest = run_layer3_write_sample(config_path, sample_size, out_dir)

    print("[Layer3-Write-Sample] 完成")
    print(json.dumps(manifest, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

