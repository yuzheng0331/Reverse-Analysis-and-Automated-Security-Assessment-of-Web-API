#!/usr/bin/env python3
"""
Handler Registry Inspector
==========================
查看已注册的加密操作和提供者
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# 导入所有操作和提供者以触发注册
from handlers.operations import *
from handlers.providers import *
from handlers.registry import get_registry
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def main():
    """显示注册表信息"""
    registry = get_registry()

    console.print(Panel.fit(
        "[bold]Handler Registry Inspector[/bold]\n查看已注册的组件",
        style="cyan"
    ))

    # 显示操作
    operations = registry.list_operations()
    console.print(f"\n[bold green]已注册加密操作 ({len(operations)}):[/bold green]\n")

    ops_table = Table(show_header=True, header_style="bold cyan")
    ops_table.add_column("#", style="dim", width=4)
    ops_table.add_column("操作名", style="cyan", width=20)
    ops_table.add_column("类型", style="yellow", width=15)

    op_types = {
        "aes": "对称加密",
        "des": "对称加密",
        "rsa": "非对称加密",
        "md5": "哈希",
        "sha": "哈希",
        "hmac": "MAC/签名",
        "base64": "编码",
        "hex": "编码"
    }

    for i, op_name in enumerate(sorted(operations), 1):
        op_type = "未知"
        for key, value in op_types.items():
            if key in op_name.lower():
                op_type = value
                break
        ops_table.add_row(str(i), op_name, op_type)

    console.print(ops_table)

    # 显示提供者
    providers = registry.list_providers()
    console.print(f"\n[bold green]已注册上下文提供者 ({len(providers)}):[/bold green]\n")

    if providers:
        prov_table = Table(show_header=True, header_style="bold cyan")
        prov_table.add_column("#", style="dim", width=4)
        prov_table.add_column("提供者名", style="cyan", width=25)
        prov_table.add_column("描述", style="yellow")

        prov_desc = {
            "static": "静态参数",
            "static_analysis": "从静态分析结果",
            "baseline": "从基线样本",
            "env": "从环境变量",
            "composite": "组合多个提供者"
        }

        for i, prov_name in enumerate(sorted(providers), 1):
            desc = prov_desc.get(prov_name, "自定义提供者")
            prov_table.add_row(str(i), prov_name, desc)

        console.print(prov_table)
    else:
        console.print("[yellow]  (无)[/yellow]")

    # 统计信息
    console.print(f"\n[bold]总计:[/bold]")
    console.print(f"  加密操作: [green]{len(operations)}[/green]")
    console.print(f"  上下文提供者: [green]{len(providers)}[/green]")
    console.print()


if __name__ == "__main__":
    main()

