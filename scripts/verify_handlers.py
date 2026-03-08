#!/usr/bin/env python3
"""
Verify Handlers against Baseline Skeletons (CLI)
================================================
验证 Handler 逻辑正确性的 CLI 工具。
使用说明:
    python verify_handlers.py [skeleton_file.json] [-i/--interactive]
"""

import sys
import argparse
from pathlib import Path

# 将项目根目录加入 sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# 导入新的 BaselinePipelineRunner
try:
    from handlers.pipeline import BaselinePipelineRunner
except ImportError as e:
    print(f"导入错误: {e}")
    print("请确保在正确的环境中运行，并且 handlers 模块在 Python 路径中。")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="验证本地 Handler 是否与基线（Playwright 捕获）一致。")
    parser.add_argument("skeleton_file", nargs="?", help="基线骨架 JSON 文件路径。默认自动查找 baseline_samples 中最新的文件。")
    parser.add_argument("--interactive", "-i", action="store_true", help="启用交互模式：提示输入缺失的 Payload。")

    args = parser.parse_args()

    skeleton_path = None
    if args.skeleton_file:
        skeleton_path = Path(args.skeleton_file)
    else:
        # 查找最新的 baseline_skeletons_*.json
        samples_dir = BASE_DIR / "baseline_samples"
        if samples_dir.exists():
            files = sorted(samples_dir.glob("baseline_skeletons_*.json"), key=lambda f: f.stat().st_mtime)
            if files:
                skeleton_path = files[-1]

    if not skeleton_path or not skeleton_path.exists():
        print("错误: 未找到基线骨架文件。")
        print("请先通过 'python scripts/generate_test_skeletons.py' 生成，或手动指定路径。")
        sys.exit(1)

    print(f"[*] 使用基线文件: {skeleton_path}")

    try:
        runner = BaselinePipelineRunner(skeleton_path)
        runner.process_all(interactive=args.interactive)
    except Exception as e:
        print(f"[!] 运行时发生错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

