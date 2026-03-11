#!/usr/bin/env python3
"""
Static Analyzer (Phase 1-4: 静态分析阶段)
=========================================
合并 JS 收集、解析、加密检测为一体的静态分析模块。

职责：
1. 收集 HTML/JS 文件（替代原 fetch_js.py）
2. 提取端点信息（onclick、form action、JS 中的 URL）
3. 检测加密模式和库（替代原 parse_js.py）
4. 提取函数定义和调用关系
5. 建立 端点 ↔ 函数 ↔ 加密算法 的映射（替代原 detect_crypto.py 的静态部分）
6. 标记安全弱点

输出：一个完整的 static_analysis.json，供后续动态采集阶段使用

Usage:
    python collect/static_analyze.py --url http://target.com/page.php
    python collect/static_analyze.py --url http://target.com/page.php --output results/
"""

import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich import box

from dotenv import load_dotenv
load_dotenv() # 从 .env 文件加载环境变量
import os

console = Console()


# =============================================================================
# 数据结构
# =============================================================================

@dataclass
class Endpoint:
    """API 端点"""
    url: str
    method: str = "POST"
    source: str = ""  # onclick, form, js_fetch
    trigger_function: str = ""  # 触发该端点的 JS 函数名


@dataclass
class CryptoPattern:
    """加密模式"""
    library: str  # CryptoJS, JSEncrypt, WebCrypto
    algorithm: str  # AES, RSA, MD5
    operation: str  # encrypt, decrypt, sign, hash
    function_name: str  # 所在函数名
    file: str  # 所在文件
    line: int  # 行号
    context: str  # 上下文代码
    weakness: Optional[str] = None  # 安全弱点
    details: list[dict] = field(default_factory=list)  # 详细操作映射: [{operation, line, context}]


@dataclass
class FunctionInfo:
    """函数信息"""
    name: str
    file: str
    line: int
    calls_crypto: list[str] = field(default_factory=list)  # 调用的加密函数
    calls_api: list[str] = field(default_factory=list)  # 调用的 API


@dataclass
class StaticAnalysisResult:
    """完整的静态分析结果"""
    target_url: str
    analyzed_at: str

    # 收集的文件
    collected_files: list[dict] = field(default_factory=list)

    # 发现的端点
    endpoints: list[Endpoint] = field(default_factory=list)

    # 加密模式
    crypto_patterns: list[CryptoPattern] = field(default_factory=list)

    # 函数信息
    functions: list[FunctionInfo] = field(default_factory=list)

    # 核心映射：端点 → 函数 → 加密
    endpoint_crypto_map: dict = field(default_factory=dict)

    # 安全发现
    security_findings: list[dict] = field(default_factory=list)


# =============================================================================
# 静态分析器
# =============================================================================

class StaticAnalyzer:
    """
    一体化静态分析器。

    整合了原 fetch_js + parse_js + detect_crypto 的功能。
    """

    def __init__(self, output_dir: Optional[Path] = None):
        # Ensure defaults are created relative to this script's directory (collect/)
        script_dir = Path(__file__).resolve().parent

        if output_dir is None:
            self.output_dir = script_dir / "static_analysis"
        else:
            # allow callers to override (can be absolute or relative to CWD)
            self.output_dir = Path(output_dir)

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # New directories for collected JS placed under collect/ by default
        self.raw_js_dir = script_dir / "collected_js" / "raw"
        self.normalized_js_dir = script_dir / "collected_js" / "normalized"
        self.raw_js_dir.mkdir(parents=True, exist_ok=True)
        self.normalized_js_dir.mkdir(parents=True, exist_ok=True)

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

        self.result: Optional[StaticAnalysisResult] = None

    def analyze(self, target_url: str) -> StaticAnalysisResult:
        """
        执行完整的静态分析。

        Args:
            target_url: 目标 URL

        Returns:
            StaticAnalysisResult: 完整的分析结果
        """
        console.print(f"[bold cyan]=== 静态分析: {target_url} ===[/bold cyan]\n")

        self.result = StaticAnalysisResult(
            target_url=target_url,
            analyzed_at=datetime.now(timezone.utc).isoformat()
        )

        # Step 1: 获取页面
        console.print("[cyan]1. 获取页面内容...[/cyan]")
        html = self._fetch_page(target_url)
        if not html:
            return self.result

        # Step 2: 提取端点
        console.print("[cyan]2. 提取 API 端点...[/cyan]")
        self._extract_endpoints(html, target_url)

        # Step 3: 收集并分析 JS
        console.print("[cyan]3. 收集并分析 JavaScript...[/cyan]")
        self._collect_and_analyze_js(html, target_url)

        # Step 4: 建立映射关系
        console.print("[cyan]4. 建立端点-加密映射...[/cyan]")
        self._build_crypto_map()

        # Step 5: 安全弱点检测
        console.print("[cyan]5. 检测安全弱点...[/cyan]")
        self._detect_weaknesses()

        return self.result

    def _fetch_page(self, url: str) -> Optional[str]:
        """获取页面 HTML"""
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            console.print(f"  [green][OK][/green] 获取成功: {len(response.content)} bytes")
            return response.text
        except Exception as e:
            console.print(f"  [red][ERROR][/red] 获取失败: {e}")
            return None

    def _extract_endpoints(self, html: str, base_url: str):
        """从 HTML 中提取端点"""
        soup = BeautifulSoup(html, "html.parser")

        # 1. 从 onclick 提取
        for element in soup.find_all(attrs={"onclick": True}):
            onclick = element.get("onclick", "")
            # 匹配 functionName('endpoint.php')
            match = re.search(r"(\w+)\s*\(\s*['\"]([^'\"]+)['\"]", onclick)
            if match:
                func_name, endpoint = match.groups()
                if self._is_api_endpoint(endpoint):
                    self.result.endpoints.append(Endpoint(
                        url=urljoin(base_url, endpoint),
                        source="onclick",
                        trigger_function=func_name
                    ))

        # 2. 从 form action 提取
        for form in soup.find_all("form"):
            action = form.get("action")
            if action and self._is_api_endpoint(action):
                self.result.endpoints.append(Endpoint(
                    url=urljoin(base_url, action),
                    method=form.get("method", "GET").upper(),
                    source="form_action"
                ))

        console.print(f"  [green][OK][/green] 发现 {len(self.result.endpoints)} 个端点")

    def _is_api_endpoint(self, url: str) -> bool:
        """判断是否为 API 端点"""
        if not url or url.startswith("#") or url.startswith("javascript:"):
            return False
        api_indicators = ['.php', '.asp', '.jsp', '/api/', '/v1/', '/encrypt/', '/sign/']
        return any(ind in url.lower() for ind in api_indicators)

    def _collect_and_analyze_js(self, html: str, base_url: str):
        """收集并分析 JS"""
        soup = BeautifulSoup(html, "html.parser")

        # 记录已处理的内容，避免重复
        processed_contents = set()

        for idx, script in enumerate(soup.find_all("script")):
            src = script.get("src")
            content = ""
            filename = ""
            js_url = None

            if src:
                # 外部脚本
                js_url = urljoin(base_url, src)
                content = self._download_js(js_url)
                if not content:
                   continue
                filename = Path(src).name
                if not filename.endswith('.js'):
                    filename = f"script_{idx}.js"
            else:
                # 内联脚本
                content = script.string or ""
                if not content.strip():
                    continue
                filename = f"inline_{idx}.js"

            # 去重
            if content in processed_contents:
                continue
            processed_contents.add(content)

            # Save raw content
            raw_path = self.raw_js_dir / filename
            counter = 1
            while raw_path.exists():
                raw_path = self.raw_js_dir / f"{raw_path.stem}_{counter}{raw_path.suffix}"
                counter += 1

            with open(raw_path, 'w', encoding='utf-8') as f:
                f.write(content)

            # Deobfuscate/Normalize
            console.print(f"  [cyan]Normalize:[/cyan] {filename}")
            normalized_path = self.normalized_js_dir / raw_path.name
            normalized_content = self._run_deobfuscator(raw_path, normalized_path)

            target_path = normalized_path if normalized_content else raw_path
            final_content = normalized_content if normalized_content else content

            # Run AST Detection
            console.print(f"  [cyan]AST Detect:[/cyan] {target_path.name}")
            # Run AST detector on the normalized (deobfuscated/formatted) file so report line numbers map to normalized
            ast_findings = self._run_ast_detector(target_path)

            if ast_findings:
                self._process_ast_findings(ast_findings, final_content, target_path.name)


            self.result.collected_files.append({
                "type": "external" if src else "inline",
                "url": js_url,
                "file_path": str(target_path),
                "size": len(final_content)
            })

        console.print(f"  [green][OK][/green] 分析了 {len(self.result.collected_files)} 个脚本")

    def _run_deobfuscator(self, input_path: Path, output_path: Path) -> Optional[str]:
        """运行 Node.js 解混淆器"""
        # Use path relative to this script file to ensure it's found regardless of CWD
        script_dir = Path(__file__).resolve().parent
        deobfuscator_script = script_dir / "deobfuscator.js"

        if not deobfuscator_script.exists():
            console.print(f"  [red]![/red] Deobfuscator script not found at {deobfuscator_script}")
            return None

        try:
            cmd = [
                "node",
                str(deobfuscator_script),
                "--input", str(input_path.absolute()),
                "--output", str(output_path.absolute()),
                #"--no-formatting"  Optional: remove if you want pretty print
            ]

            # Use shell=True for Windows if node is in PATH but issues arise,
            # generally list args are safer/portable. On Windows with shell=False,
            # ensure 'node' is in path.
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )

            if result.returncode == 0 and output_path.exists():
                return output_path.read_text(encoding='utf-8')
            else:
                console.print(f"  [yellow]![/yellow] Deobfuscator failed for {input_path.name}: {result.stderr}")
                return None
        except Exception as e:
            console.print(f"  [red]![/red] Deobfuscator error: {e}")
            return None

    def _download_js(self, url: str) -> Optional[str]:
        """下载 JS 文件"""
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.text
        except:
            return None

    def _run_ast_detector(self, input_path: Path) -> Optional[dict]:
        """运行 AST 检测脚本"""
        # Use path relative to this script file
        script_dir = Path(__file__).resolve().parent
        detector_script = script_dir / "ast_detect_crypto.js"

        if not detector_script.exists():
             console.print(f"  [red]![/red] AST Detector script not found at {detector_script}")
             return None

        try:
            cmd = [
                "node",
                str(detector_script),
                "--input", str(input_path.absolute())
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            if result.returncode == 0:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    console.print(f"  [yellow]![/yellow] Failed to parse AST detector output: {result.stdout[:100]}...")
                    return None
            else:
                 console.print(f"  [red]![/red] AST detector error: {result.stderr}")
                 return None
        except Exception as e:
            console.print(f"  [red]![/red] Execution error: {e}")
            return None

    def _process_ast_findings(self, ast_result: dict, content: str, filename: str):
        """处理 AST 检测结果并转换为内部结构"""

        # 1. Process Findings (Crypto)
        findings = ast_result.get("findings", [])
        # Aggregate by (function, library, algorithm) to avoid duplicate crypto types within the same function
        agg: dict = {}
        for f in findings:
            lib = f.get("library", "Unknown")
            alg = f.get("algorithm", "Unknown")
            func = f.get("function", "anonymous")
            op = f.get("operation", "Unknown")
            line = f.get("line", 0)
            code = f.get("code", "")
            weakness = f.get("weakness")

            key = (func, lib, alg)
            if key not in agg:
                agg[key] = {
                    "details": [],
                    "weaknesses": set(),
                }

            # Store detail for exact mapping

            # 增强：如果 finding 本身携带了更详细的子步骤 (details)，应当优先使用或合并它们
            # 这些子步骤包含了 resolved_value, inferred_keys 等关键信息
            if details := f.get("details"):
                 if isinstance(details, list) and len(details) > 0:
                    for sub_detail in details:
                        # Use sub_detail values, fallback to parent finding values if missing
                        op_sd = sub_detail.get("operation", op)
                        line_sd = sub_detail.get("line", int(line) if line else 0)

                        detail_entry = {
                            "operation": op_sd,
                            "line": line_sd,
                            "context": sub_detail.get("context", code).strip()
                        }

                        # 透传关键扩展字段
                        # [FIX] Explicitly forward structured input/output metadata
                        if "resolved_value" in sub_detail:
                            detail_entry["resolved_value"] = sub_detail["resolved_value"]
                        if "inferred_keys" in sub_detail:
                            detail_entry["inferred_keys"] = sub_detail["inferred_keys"]
                        if "output_variable" in sub_detail:
                            detail_entry["output_variable"] = sub_detail["output_variable"]
                        if "info" in sub_detail:
                            detail_entry["info"] = sub_detail["info"]
                        if "input_expression" in sub_detail:
                            detail_entry["input_expression"] = sub_detail["input_expression"]
                        if "input_derivation" in sub_detail:
                            detail_entry["input_derivation"] = sub_detail["input_derivation"]
                        if "input_source_keys" in sub_detail:
                            detail_entry["input_source_keys"] = sub_detail["input_source_keys"]
                        if "output_transform" in sub_detail:
                            detail_entry["output_transform"] = sub_detail["output_transform"]
 
                        # Forward derivation logic
                        if "derivation" in sub_detail:
                            detail_entry["derivation"] = sub_detail["derivation"]
                        if "target" in sub_detail:
                            detail_entry["target"] = sub_detail["target"]

                        agg_key_details = agg[key]["details"]
                        agg_key_details.append(detail_entry)
            else:
                # 回退到旧逻辑：仅记录顶层操作
                agg[key]["details"].append({
                    "operation": op,
                    "line": int(line) if line else 0,
                    "context": code
                })

            if weakness:
                agg[key]["weaknesses"].add(weakness)

        # Convert aggregated entries back to CryptoPattern list
        for (func, lib, alg), meta in agg.items():
            # Sort details by line number
            details = sorted(meta["details"], key=lambda x: x["line"])

            # Aggregate operations for high-level summary (deduplicated)
            ops = sorted(list(set(d["operation"] for d in details if d["operation"])))
            if not ops: ops = ["Unknown"]
            op_str = ",".join(ops)

            # Representative line (first occurrence)
            line_num = details[0]["line"] if details else 0

            # Combined context (truncated)
            full_context = "\n---\n".join([d["context"] for d in details if d["context"]])

            weakness_val = next(iter(meta["weaknesses"])) if meta["weaknesses"] else None

            crypto_pattern = CryptoPattern(
                library=lib,
                algorithm=alg,
                operation=op_str,
                function_name=func,
                file=filename,
                line=line_num,
                context=full_context[:300],
                weakness=weakness_val,
                details=details
            )
            self.result.crypto_patterns.append(crypto_pattern)

        # 2. Process Functions (Structure & API Calls)
        functions = ast_result.get("functions", [])
        for func in functions:
            func_info = FunctionInfo(
                name=func.get("name", "anonymous"),
                file=filename,
                line=func.get("line", 0),
                calls_crypto=func.get("crypto_calls", []),
                calls_api=func.get("api_calls", [])
            )
            self.result.functions.append(func_info)

    def _build_crypto_map(self):
        """建立 端点 → 加密 映射"""
        # 从端点的 trigger_function 关联到加密
        for endpoint in self.result.endpoints:
            trigger_func = endpoint.trigger_function
            if not trigger_func:
                continue

            # 找到该函数使用的加密
            # 分类收集：Algorithm Patterns 和 Raw Trace Calls

            algo_patterns = []  # 存 {library, algorithm, operation}
            trace_calls = set() # 存 "CallName"

            # 1. 从 Crypto Patterns 收集（高置信度算法识别）
            unique_patterns = set()
            for pattern in self.result.crypto_patterns:
                if pattern.function_name == trigger_func:
                    key = (pattern.library, pattern.algorithm, pattern.operation)
                    if key not in unique_patterns:
                        unique_patterns.add(key)
                        algo_patterns.append({
                            "library": pattern.library,
                            "algorithm": pattern.algorithm,
                            "operation": pattern.operation,
                            "details": pattern.details # 传递详细的点对点映射
                        })

            # 构建 canonical set，用于后续过滤纯 Call 里的重复项
            # 例如如果我们已经识别了 "CryptoJS.AES.encrypt"，那就不需要在 trace 中再加一次
            canonical_calls = set()
            for p in algo_patterns:
                lib, alg, op = p["library"], p["algorithm"], p["operation"]
                if lib and lib != "N/A" and alg and alg != "N/A" and op:
                    canonical_calls.add(f"{lib}.{alg}.{op}")

            # 2. 从 Function Calls 收集（补充调用痕迹）
            for func in self.result.functions:
                if func.name == trigger_func and func.calls_crypto:
                    for call in func.calls_crypto:
                        # 规范化：去掉可能的前缀
                        normalized = call

                        # 过滤掉已经作为 Pattern 识别过的调用（避免冗余）
                        # 简单的启发式过滤：如果 Trace Call 包含 Algorithm Pattern 里的关键词
                        is_redundant = False
                        for canonical in canonical_calls:
                            # 比如 canonical="CryptoJS.AES.encrypt", normalized="CryptoJS.AES.encrypt"
                            if normalized in canonical:
                                is_redundant = True
                                break

                        if not is_redundant:
                            trace_calls.add(normalized)

            if algo_patterns or trace_calls:
                # 提取纯算法列表用于快速索引
                algorithms = sorted(list(set(
                    p["algorithm"] for p in algo_patterns
                    if p["algorithm"] not in ["N/A", "Unknown"]
                )))

                self.result.endpoint_crypto_map[endpoint.url] = {
                    "trigger_function": trigger_func,
                    "algorithms": algorithms,       # 简表：["AES", "RSA"]
                    "operations": algo_patterns,    # 详表：[{lib:Crypto, alg:AES...}]
                    "trace_calls": sorted(list(trace_calls)) # 痕迹：["someFunc.encrypt"]
                }

        console.print(f"  [green][OK][/green] 建立了 {len(self.result.endpoint_crypto_map)} 个端点映射")

    def _detect_weaknesses(self):
        """检测安全弱点"""
        for pattern in self.result.crypto_patterns:
            if pattern.weakness:
                self.result.security_findings.append({
                    "type": pattern.weakness,
                    "severity": "HIGH",
                    "file": pattern.file,
                    "line": pattern.line,
                    "context": pattern.context,
                    "description": f"检测到 {pattern.weakness} 在 {pattern.file}:{pattern.line}"
                })

            # 弱算法检测
            if pattern.algorithm in ["MD5", "DES", "SHA1"]:
                self.result.security_findings.append({
                    "type": "WEAK_ALGORITHM",
                    "severity": "MEDIUM",
                    "algorithm": pattern.algorithm,
                    "file": pattern.file,
                    "line": pattern.line,
                    "description": f"使用了弱加密算法 {pattern.algorithm}"
                })

        console.print(f"  [green][OK][/green] 发现 {len(self.result.security_findings)} 个安全问题")

    def save_results(self) -> Path:
        """保存分析结果"""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = self.output_dir / f"static_analysis_{timestamp}.json"

        # 转换为可序列化的字典
        data = {
            "target_url": self.result.target_url,
            "analyzed_at": self.result.analyzed_at,
            "summary": {
                "total_files": len(self.result.collected_files),
                "total_endpoints": len(self.result.endpoints),
                "total_crypto_patterns": len(self.result.crypto_patterns),
                "total_functions": len(self.result.functions),
                "total_security_findings": len(self.result.security_findings)
            },
            "collected_files": self.result.collected_files,
            "endpoints": [
                {"url": e.url, "method": e.method, "source": e.source, "trigger_function": e.trigger_function}
                for e in self.result.endpoints
            ],
            "crypto_patterns": [
                {
                    "library": p.library,
                    "algorithm": p.algorithm,
                    "operation": p.operation,
                    "function_name": p.function_name,
                    "file": p.file,
                    "line": p.line,
                    "weakness": p.weakness,
                    "details": p.details
                }
                for p in self.result.crypto_patterns
            ],
            "endpoint_crypto_map": self.result.endpoint_crypto_map,
            "security_findings": self.result.security_findings
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        console.print(f"\n[green][OK] 结果已保存到: {output_path}[/green]")
        return output_path

    def display_summary(self):
        """显示分析摘要"""
        if not self.result:
            return

        # 端点表
        if self.result.endpoints:
            table = Table(title="发现的 API 端点", box=box.ASCII)
            table.add_column("URL", style="cyan")
            table.add_column("触发函数", style="yellow")
            table.add_column("加密类型", style="green")

            for ep in self.result.endpoints:
                crypto_info = self.result.endpoint_crypto_map.get(ep.url, {})
                crypto_str = ", ".join(crypto_info.get("algorithms", [])) or "-"
                table.add_row(ep.url, ep.trigger_function or "-", crypto_str)

            console.print(table)

        # 安全发现
        if self.result.security_findings:
            console.print("\n[bold red]安全发现:[/bold red]")
            for finding in self.result.security_findings:
                console.print(f"  - [{finding['severity']}] {finding['description']}")


# =============================================================================
# CLI
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(description="一体化静态分析工具")
    parser.add_argument("--url", default=os.getenv("TARGET_URL"), help="目标 URL, 默认为靶场URL")
    # If --output is not provided, StaticAnalyzer will create script-relative directory under collect/
    parser.add_argument("--output", type=Path, default=None, help="可选：自定义输出目录 (默认放到 collect/static_analysis)")

    args = parser.parse_args()

    analyzer = StaticAnalyzer(output_dir=args.output)
    analyzer.analyze(args.url)
    analyzer.display_summary()
    analyzer.save_results()


if __name__ == "__main__":
    main()
