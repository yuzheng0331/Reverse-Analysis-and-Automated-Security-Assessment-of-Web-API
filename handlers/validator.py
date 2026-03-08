#!/usr/bin/env python3
"""
Validation Layer
================
Handler 输出与基线样本的验证对比
"""

import json
import base64
import binascii
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import unquote

from rich.console import Console
from rich.table import Table

from .base import ValidationResult, HandlerResult

console = Console()


class ValidationLayer:
    """
    验证层
    对比 Handler 输出与基线样本
    """

    def __init__(self, baseline_path: Path):
        self.baseline_path = Path(baseline_path)
        self.baseline_data = self._load_baseline()

        # 验证策略列表（按优先级）
        self.strategies = [
            self._exact_match,
            self._normalize_whitespace,
            self._url_decode_match,
            self._base64_variants,
            self._case_insensitive,
            self._hex_vs_base64
        ]

    def _load_baseline(self) -> Dict:
        """加载基线样本"""
        if not self.baseline_path.exists():
            return {}

        with open(self.baseline_path, encoding="utf-8") as f:
            return json.load(f)

    def validate_simple(self, baseline_value: str, handler_value: Any) -> ValidationResult:
        """
        直接验证给定的基线值和 Handler 输出，不查找文件
        """
        handler_str = str(handler_value)
        strategies_tried = []

        for strategy in self.strategies:
            strategy_name = strategy.__name__
            strategies_tried.append(strategy_name)

            matched, note = strategy(baseline_value, handler_str)
            if matched:
                return ValidationResult(
                    matched=True,
                    baseline_value=baseline_value,
                    handler_value=handler_str,
                    match_strategies_tried=strategies_tried,
                    matched_strategy=strategy_name,
                    notes=[note] if note else []
                )

        return ValidationResult(
            matched=False,
            baseline_value=baseline_value,
            handler_value=handler_str,
            match_strategies_tried=strategies_tried,
            diff=self._compute_diff(baseline_value, handler_str),
            notes=["All matching strategies failed"]
        )

    def validate(
        self,
        endpoint: str,
        handler_result: HandlerResult,
        field_name: str = "encryptedData"
    ) -> ValidationResult:
        """
        验证 Handler 输出

        Args:
            endpoint: 端点名称
            handler_result: Handler 执行结果
            field_name: 要验证的字段名

        Returns:
            ValidationResult
        """
        if not handler_result.success:
            return ValidationResult(
                matched=False,
                diff="Handler execution failed",
                notes=[f"Error: {handler_result.error}"]
            )

        # 从基线中查找对应的请求
        baseline_value = self._find_baseline_value(endpoint, field_name)
        if not baseline_value:
            return ValidationResult(
                matched=False,
                diff="Baseline value not found",
                notes=[f"No baseline data for endpoint: {endpoint}"]
            )

        handler_value = str(handler_result.output)

        # 尝试各种匹配策略
        strategies_tried = []

        for strategy in self.strategies:
            strategy_name = strategy.__name__
            strategies_tried.append(strategy_name)

            matched, note = strategy(baseline_value, handler_value)
            if matched:
                return ValidationResult(
                    matched=True,
                    baseline_value=baseline_value,
                    handler_value=handler_value,
                    match_strategies_tried=strategies_tried,
                    matched_strategy=strategy_name,
                    notes=[note] if note else []
                )

        # 所有策略都失败
        return ValidationResult(
            matched=False,
            baseline_value=baseline_value,
            handler_value=handler_value,
            match_strategies_tried=strategies_tried,
            diff=self._compute_diff(baseline_value, handler_value),
            notes=["All matching strategies failed"]
        )

    def _find_baseline_value(self, endpoint: str, field_name: str) -> Optional[str]:
        """从基线中查找字段值"""
        for request in self.baseline_data.get("requests", []):
            req_url = request.get("request", {}).get("url", "")
            if endpoint in req_url:
                # 尝试从 post_data_parsed 获取
                parsed = request.get("request", {}).get("post_data_parsed", {})
                if field_name in parsed:
                    return parsed[field_name]

                # 尝试从 post_data_json 获取
                json_data = request.get("request", {}).get("post_data_json", {})
                if field_name in json_data:
                    return json_data[field_name]

        return None

    # =========================================================================
    # Matching Strategies
    # =========================================================================

    def _exact_match(self, baseline: str, handler: str) -> tuple[bool, str]:
        """精确匹配"""
        if baseline == handler:
            return True, "Exact match"
        return False, None

    def _normalize_whitespace(self, baseline: str, handler: str) -> tuple[bool, str]:
        """归一化空白字符"""
        b_norm = " ".join(baseline.split())
        h_norm = " ".join(handler.split())
        if b_norm == h_norm:
            return True, "Match after whitespace normalization"
        return False, None

    def _url_decode_match(self, baseline: str, handler: str) -> tuple[bool, str]:
        """URL 解码匹配"""
        try:
            b_decoded = unquote(baseline)
            h_decoded = unquote(handler)
            if b_decoded == h_decoded:
                return True, "Match after URL decoding"
        except:
            pass
        return False, None

    def _base64_variants(self, baseline: str, handler: str) -> tuple[bool, str]:
        """Base64 变体匹配（处理 padding）"""
        # 移除 = 填充后比较
        b_stripped = baseline.rstrip("=")
        h_stripped = handler.rstrip("=")
        if b_stripped == h_stripped:
            return True, "Match after removing base64 padding"

        # 尝试解码后比较
        try:
            b_decoded = base64.b64decode(baseline)
            h_decoded = base64.b64decode(handler)
            if b_decoded == h_decoded:
                return True, "Match after base64 decoding"
        except:
            pass

        return False, None

    def _case_insensitive(self, baseline: str, handler: str) -> tuple[bool, str]:
        """忽略大小写匹配"""
        if baseline.lower() == handler.lower():
            return True, "Case-insensitive match"
        return False, None

    def _hex_vs_base64(self, baseline: str, handler: Any) -> tuple[bool, str]:
        """策略: 尝试 Hex/Base64 互转对比"""
        if not isinstance(baseline, str) or not isinstance(handler, str):
            return False, None
        
        # 尝试 baseline(Hex) == handler(Base64)
        try:
            # 假设 baseline 是 hex
            baseline_bytes = binascii.unhexlify(baseline.strip())
            # 假设 handler 是 base64
            handler_bytes = base64.b64decode(handler.strip())
            if baseline_bytes == handler_bytes:
                return True, "Match: Baseline(Hex) == Handler(Base64)"
        except (binascii.Error, ValueError):
            pass

        # 尝试 baseline(Base64) == handler(Hex)
        try:
            baseline_bytes = base64.b64decode(baseline.strip())
            handler_bytes = binascii.unhexlify(handler.strip())
            if baseline_bytes == handler_bytes:
                return True, "Match: Baseline(Base64) == Handler(Hex)"
        except (binascii.Error, ValueError):
            pass
            
        return False, None

    def _compute_diff(self, baseline: str, handler: str) -> str:
        """计算差异摘要"""
        if len(baseline) != len(handler):
            return f"Length mismatch: baseline={len(baseline)}, handler={len(handler)}"

        # 查找第一个不同的位置
        for i, (b_char, h_char) in enumerate(zip(baseline, handler)):
            if b_char != h_char:
                context_start = max(0, i - 10)
                context_end = min(len(baseline), i + 10)
                return (
                    f"First diff at position {i}:\n"
                    f"  Baseline: ...{baseline[context_start:context_end]}...\n"
                    f"  Handler:  ...{handler[context_start:context_end]}..."
                )

        return "Unknown difference"

    def display_validation_report(self, results: List[tuple[str, ValidationResult]]):
        """显示验证报告"""
        console.print("\n[bold cyan]═══ Validation Report ═══[/bold cyan]\n")

        table = Table(title="Handler Validation Results")
        table.add_column("Endpoint", style="cyan", width=30)
        table.add_column("Status", style="bold", width=10)
        table.add_column("Strategy", style="yellow", width=25)
        table.add_column("Notes", style="dim", max_width=40)

        matched_count = 0

        for endpoint, result in results:
            if result.matched:
                matched_count += 1
                status = "[green]✓ PASS[/green]"
                strategy = result.matched_strategy or "-"
                notes = ", ".join(result.notes) if result.notes else "-"
            else:
                status = "[red]✗ FAIL[/red]"
                strategy = "-"
                notes = result.diff or ", ".join(result.notes)

            table.add_row(endpoint, status, strategy, notes)

        console.print(table)

        # 摘要统计
        total = len(results)
        pass_rate = (matched_count / total * 100) if total > 0 else 0

        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"  Total: {total}")
        console.print(f"  [green]Passed: {matched_count}[/green]")
        console.print(f"  [red]Failed: {total - matched_count}[/red]")
        console.print(f"  Pass Rate: {pass_rate:.1f}%")
