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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

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

    # 加密模式定义
    CRYPTO_PATTERNS = {
        # CryptoJS
        "cryptojs_aes_encrypt": {
            "pattern": r"CryptoJS\.AES\.encrypt\s*\(\s*([^,]+),\s*([^,\)]+)",
            "library": "CryptoJS",
            "algorithm": "AES",
            "operation": "encrypt"
        },
        "cryptojs_aes_decrypt": {
            "pattern": r"CryptoJS\.AES\.decrypt\s*\(",
            "library": "CryptoJS",
            "algorithm": "AES",
            "operation": "decrypt"
        },
        "cryptojs_md5": {
            "pattern": r"CryptoJS\.MD5\s*\(",
            "library": "CryptoJS",
            "algorithm": "MD5",
            "operation": "hash"
        },
        "cryptojs_sha256": {
            "pattern": r"CryptoJS\.SHA256\s*\(",
            "library": "CryptoJS",
            "algorithm": "SHA256",
            "operation": "hash"
        },
        "cryptojs_hmac": {
            "pattern": r"CryptoJS\.Hmac(SHA256|SHA1|MD5)\s*\(",
            "library": "CryptoJS",
            "algorithm": "HMAC",
            "operation": "sign"
        },

        # JSEncrypt (RSA)
        "jsencrypt_create": {
            "pattern": r"new\s+JSEncrypt\s*\(",
            "library": "JSEncrypt",
            "algorithm": "RSA",
            "operation": "init"
        },
        "jsencrypt_encrypt": {
            "pattern": r"\.encrypt\s*\([^)]+\)",
            "library": "JSEncrypt",
            "algorithm": "RSA",
            "operation": "encrypt"
        },
        "jsencrypt_setkey": {
            "pattern": r"\.setPublicKey\s*\(\s*['\"`]([^'\"`]+)['\"`]\s*\)",
            "library": "JSEncrypt",
            "algorithm": "RSA",
            "operation": "setkey"
        },

        # DES
        "cryptojs_des": {
            "pattern": r"CryptoJS\.(DES|TripleDES)\.encrypt\s*\(",
            "library": "CryptoJS",
            "algorithm": "DES",
            "operation": "encrypt"
        },

        # 硬编码密钥检测（安全弱点）
        "hardcoded_key": {
            "pattern": r"(key|secret|password)\s*[=:]\s*['\"]([a-zA-Z0-9+/=]{8,})['\"]",
            "library": "N/A",
            "algorithm": "N/A",
            "operation": "hardcoded_secret",
            "weakness": "HARDCODED_KEY"
        },
    }

    # 发送函数模式（用于关联端点和加密）
    SENDER_PATTERNS = [
        r"function\s+(\w+)\s*\([^)]*\)\s*\{[^}]*(?:fetch|axios|ajax|XMLHttpRequest)[^}]*['\"]([^'\"]+\.php)['\"]",
        r"(\w+)\s*[=:]\s*(?:async\s+)?function[^{]*\{[^}]*['\"]([^'\"]+\.php)['\"]",
    ]

    def __init__(self, output_dir: Path = Path("static_analysis")):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
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
        console.print(f"[bold cyan]═══ 静态分析: {target_url} ═══[/bold cyan]\n")

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
            console.print(f"  [green]✓[/green] 获取成功: {len(response.content)} bytes")
            return response.text
        except Exception as e:
            console.print(f"  [red]✗[/red] 获取失败: {e}")
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

        console.print(f"  [green]✓[/green] 发现 {len(self.result.endpoints)} 个端点")

    def _is_api_endpoint(self, url: str) -> bool:
        """判断是否为 API 端点"""
        if not url or url.startswith("#") or url.startswith("javascript:"):
            return False
        api_indicators = ['.php', '.asp', '.jsp', '/api/', '/v1/', '/encrypt/', '/sign/']
        return any(ind in url.lower() for ind in api_indicators)

    def _collect_and_analyze_js(self, html: str, base_url: str):
        """收集并分析 JS"""
        soup = BeautifulSoup(html, "html.parser")

        for idx, script in enumerate(soup.find_all("script")):
            src = script.get("src")

            if src:
                # 外部脚本
                js_url = urljoin(base_url, src)
                content = self._download_js(js_url)
                if content:
                    self._analyze_js_content(content, src, js_url)
                    self.result.collected_files.append({
                        "type": "external",
                        "url": js_url,
                        "size": len(content)
                    })
            else:
                # 内联脚本
                content = script.string or ""
                if content.strip():
                    self._analyze_js_content(content, f"inline_{idx}", None)
                    self.result.collected_files.append({
                        "type": "inline",
                        "index": idx,
                        "size": len(content)
                    })

        console.print(f"  [green]✓[/green] 分析了 {len(self.result.collected_files)} 个脚本")

    def _download_js(self, url: str) -> Optional[str]:
        """下载 JS 文件"""
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.text
        except:
            return None

    def _analyze_js_content(self, content: str, filename: str, url: Optional[str]):
        """分析 JS 内容"""
        lines = content.split("\n")

        # 检测加密模式
        for pattern_name, pattern_info in self.CRYPTO_PATTERNS.items():
            for match in re.finditer(pattern_info["pattern"], content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1

                # 获取上下文
                start_line = max(0, line_num - 2)
                end_line = min(len(lines), line_num + 2)
                context = "\n".join(lines[start_line:end_line])

                # 找到所在函数
                func_name = self._find_enclosing_function(content, match.start())

                crypto_pattern = CryptoPattern(
                    library=pattern_info["library"],
                    algorithm=pattern_info["algorithm"],
                    operation=pattern_info["operation"],
                    function_name=func_name,
                    file=filename,
                    line=line_num,
                    context=context,
                    weakness=pattern_info.get("weakness")
                )
                self.result.crypto_patterns.append(crypto_pattern)

        # 提取函数定义
        func_patterns = [
            r"function\s+(\w+)\s*\(",
            r"(\w+)\s*=\s*function\s*\(",
            r"(\w+)\s*:\s*function\s*\(",
            r"const\s+(\w+)\s*=\s*\([^)]*\)\s*=>",
        ]

        for pattern in func_patterns:
            for match in re.finditer(pattern, content):
                func_name = match.group(1)
                line_num = content[:match.start()].count("\n") + 1

                # 分析函数体
                func_body = self._extract_function_body(content, match.end())

                func_info = FunctionInfo(
                    name=func_name,
                    file=filename,
                    line=line_num,
                    calls_crypto=self._find_crypto_calls(func_body),
                    calls_api=self._find_api_calls(func_body)
                )
                self.result.functions.append(func_info)

    def _find_enclosing_function(self, content: str, position: int) -> str:
        """找到包含指定位置的函数名"""
        # 简化实现：向前搜索最近的 function 声明
        before = content[:position]
        match = re.search(r"function\s+(\w+)\s*\([^)]*\)\s*\{[^}]*$", before)
        if match:
            return match.group(1)

        # 尝试匹配箭头函数
        match = re.search(r"(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>)[^{]*\{[^}]*$", before)
        if match:
            return match.group(1)

        return "anonymous"

    def _extract_function_body(self, content: str, start: int) -> str:
        """提取函数体（简化实现）"""
        # 找到开始的 {
        brace_start = content.find("{", start)
        if brace_start == -1:
            return ""

        # 简单计数配对
        depth = 1
        pos = brace_start + 1
        while pos < len(content) and depth > 0:
            if content[pos] == "{":
                depth += 1
            elif content[pos] == "}":
                depth -= 1
            pos += 1

        return content[brace_start:pos]

    def _find_crypto_calls(self, code: str) -> list[str]:
        """在代码中查找加密调用"""
        calls = []
        patterns = [
            r"CryptoJS\.(AES|DES|MD5|SHA256|HmacSHA256)\.(encrypt|decrypt)",
            r"\.encrypt\s*\(",
            r"\.decrypt\s*\(",
            r"\.sign\s*\(",
        ]
        for pattern in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                match = re.search(pattern, code, re.IGNORECASE)
                calls.append(match.group(0))
        return calls

    def _find_api_calls(self, code: str) -> list[str]:
        """在代码中查找 API 调用"""
        apis = []
        patterns = [
            r"fetch\s*\(\s*['\"]([^'\"]+)['\"]",
            r"axios\.\w+\s*\(\s*['\"]([^'\"]+)['\"]",
            r"\.ajax\s*\(\s*\{[^}]*url\s*:\s*['\"]([^'\"]+)['\"]",
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                apis.append(match.group(1))
        return apis

    def _build_crypto_map(self):
        """建立 端点 → 加密 映射"""
        # 从端点的 trigger_function 关联到加密
        for endpoint in self.result.endpoints:
            trigger_func = endpoint.trigger_function
            if not trigger_func:
                continue

            # 找到该函数使用的加密
            crypto_used = []
            for pattern in self.result.crypto_patterns:
                if pattern.function_name == trigger_func:
                    crypto_used.append({
                        "library": pattern.library,
                        "algorithm": pattern.algorithm,
                        "operation": pattern.operation
                    })

            # 也检查函数信息
            for func in self.result.functions:
                if func.name == trigger_func and func.calls_crypto:
                    for call in func.calls_crypto:
                        crypto_used.append({"call": call})

            if crypto_used:
                self.result.endpoint_crypto_map[endpoint.url] = {
                    "trigger_function": trigger_func,
                    "crypto": crypto_used
                }

        console.print(f"  [green]✓[/green] 建立了 {len(self.result.endpoint_crypto_map)} 个端点映射")

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

        console.print(f"  [green]✓[/green] 发现 {len(self.result.security_findings)} 个安全问题")

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
                    "weakness": p.weakness
                }
                for p in self.result.crypto_patterns
            ],
            "endpoint_crypto_map": self.result.endpoint_crypto_map,
            "security_findings": self.result.security_findings
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        console.print(f"\n[green]✓ 结果已保存到: {output_path}[/green]")
        return output_path

    def display_summary(self):
        """显示分析摘要"""
        if not self.result:
            return

        # 端点表
        if self.result.endpoints:
            table = Table(title="发现的 API 端点")
            table.add_column("URL", style="cyan")
            table.add_column("触发函数", style="yellow")
            table.add_column("加密类型", style="green")

            for ep in self.result.endpoints:
                crypto_info = self.result.endpoint_crypto_map.get(ep.url, {})
                crypto_str = ", ".join(
                    c.get("algorithm", c.get("call", "?"))
                    for c in crypto_info.get("crypto", [])
                ) or "-"
                table.add_row(ep.url, ep.trigger_function or "-", crypto_str)

            console.print(table)

        # 安全发现
        if self.result.security_findings:
            console.print("\n[bold red]安全发现:[/bold red]")
            for finding in self.result.security_findings:
                console.print(f"  • [{finding['severity']}] {finding['description']}")


# =============================================================================
# CLI
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(description="一体化静态分析工具")
    parser.add_argument("--url", required=True, help="目标 URL")
    parser.add_argument("--output", type=Path, default=Path("static_analysis"))

    args = parser.parse_args()

    analyzer = StaticAnalyzer(output_dir=args.output)
    analyzer.analyze(args.url)
    analyzer.display_summary()
    analyzer.save_results()


if __name__ == "__main__":
    main()