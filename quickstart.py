#!/usr/bin/env python3
"""
快速开始脚本 - 演示完整的静态分析流程
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from collect.static_analyze import StaticAnalyzer
from rich.console import Console

console = Console()


def main():
    console.print("[bold cyan]欢迎使用 Web API 安全分析工具[/bold cyan]\n")

    # 示例URL列表
    examples = [
        "http://encrypt-labs-main/easy.php",
        # 可以添加更多目标URL
    ]

    console.print("[yellow]示例目标:[/yellow]")
    for i, url in enumerate(examples, 1):
        console.print(f"  {i}. {url}")

    console.print("\n[cyan]开始分析第一个目标...[/cyan]\n")

    # 执行静态分析
    analyzer = StaticAnalyzer()
    result = analyzer.analyze(examples[0])

    # 显示摘要
    analyzer.display_summary()

    # 保存结果
    output_path = analyzer.save_results()

    console.print(f"\n[bold green]分析完成！[/bold green]")
    console.print(f"结果文件: {output_path}")

    # 提示下一步
    console.print("\n[bold cyan]下一步:[/bold cyan]")
    console.print("  1. 查看生成的 JSON 文件了解详细分析结果")
    console.print("  2. 运行动态采集: python scripts/capture_baseline.py")
    console.print("  3. 实现 Handler 并验证加密逻辑")
    console.print("  4. 生成安全评估报告")


if __name__ == "__main__":
    main()

