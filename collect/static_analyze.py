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
from urllib.parse import urljoin, urlparse

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

    def __init__(
        self,
        output_dir: Optional[Path] = None,
        default_blacklist_enabled: bool = True,
        extra_blacklist_patterns: Optional[list[str]] = None,
    ):
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
        self.default_blacklist_enabled = default_blacklist_enabled
        self.extra_blacklist_patterns = [p.lower() for p in (extra_blacklist_patterns or []) if p]
        # 运行期索引：用于把 JS 事件绑定回填到 form_action 端点
        self._form_bind_index: list[dict] = []
        self._submit_event_bindings: list[dict] = []

    def _default_third_party_patterns(self) -> list[str]:
        """常见第三方库关键字，用于降低噪声。"""
        return [
            "jquery", "jquery-ui", "bootstrap", "chart", "moment", "daterangepicker",
            "tempusdominus", "summernote", "overlay", "adminlte", "select2", "qrcode",
            "sparkline", "jqgrid", "ztree", "vue.min", "react", "angular", "chunk-vendors",
            "vendor", "vendors", "prism", "layer.js", "jsencrypt", "zxcvbn.min", "zxcvbn-async.min",
        ]

    def _is_blacklisted_script(self, script_url: Optional[str], filename: str) -> bool:
        """按 URL/文件名做黑名单过滤。"""
        target = f"{(script_url or '')} {filename}".lower()
        patterns = []
        if self.default_blacklist_enabled:
            patterns.extend(self._default_third_party_patterns())
        patterns.extend(self.extra_blacklist_patterns)
        return any(p and p in target for p in patterns)

    def analyze(
        self,
        target_url: str,
        html_override: Optional[str] = None,
        manual_js_files: Optional[list[Path]] = None,
    ) -> StaticAnalysisResult:
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
        self._form_bind_index = []
        self._submit_event_bindings = []

        # Step 1: 获取页面（或使用离线 HTML）
        if html_override is not None:
            console.print("[cyan]1. 使用离线 HTML 输入...[/cyan]")
            html = html_override
            console.print(f"  [green][OK][/green] 离线 HTML 已加载: {len(html.encode('utf-8'))} bytes")
        else:
            console.print("[cyan]1. 获取页面内容...[/cyan]")
            html = self._fetch_page(target_url)
            if not html:
                return self.result

        # Step 2: 提取端点
        console.print("[cyan]2. 提取 API 端点...[/cyan]")
        self._extract_endpoints(html, target_url)

        # Step 3: 收集并分析 JS
        console.print("[cyan]3. 收集并分析 JavaScript...[/cyan]")
        self._collect_and_analyze_js(html, target_url, manual_js_files=manual_js_files)

        # Step 3.1: 合并 JS 中识别出的端点（如 $.ajax/fetch）
        self._merge_js_discovered_endpoints(target_url)

        # Step 3.2: 将 JS submit 事件绑定映射回 form_action 端点
        self._apply_submit_bindings_to_forms()

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
                onsubmit = form.get("onsubmit", "")
                endpoint_url = urljoin(base_url, action)
                classes = [c for c in (form.get("class") or []) if isinstance(c, str)]
                selectors = ["form"]
                if form.get("id"):
                    selectors.append(f"#{form.get('id')}")
                if form.get("name"):
                    selectors.append(f"form[name=\"{form.get('name')}\"]")
                for cls in classes:
                    selectors.append(f"form.{cls}")

                self.result.endpoints.append(Endpoint(
                    url=endpoint_url,
                    method=form.get("method", "GET").upper(),
                    source="form_action",
                    trigger_function=self._extract_handler_function(onsubmit)
                ))

                self._form_bind_index.append({
                    "url": endpoint_url,
                    "id": form.get("id") or "",
                    "name": form.get("name") or "",
                    "classes": classes,
                    "selectors": selectors,
                })

        console.print(f"  [green][OK][/green] 发现 {len(self.result.endpoints)} 个端点")

    def _extract_handler_function(self, handler_code: str) -> str:
        """从 onsubmit/onclick 这类内联处理器中提取函数名。"""
        if not handler_code:
            return ""
        # 兼容 return check(); / check(); / return foo.bar();
        match = re.search(r"(?:return\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\(", handler_code)
        return match.group(1) if match else ""

    def _is_api_endpoint(self, url: str) -> bool:
        """判断是否为 API 端点（通用规则，避免站点特化）。"""
        if not url:
            return False
        raw = url.strip()
        if not raw:
            return False

        lower = raw.lower()
        if lower.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "blob:")):
            return False

        parsed = urlparse(raw)
        path = (parsed.path or "").strip().lower()
        query = (parsed.query or "").strip()

        # 常见动态端点指示器（补充 .me 以覆盖传统站点路由）
        dynamic_markers = (".php", ".asp", ".aspx", ".jsp", ".do", ".action", ".me", "/api/", "/v1/", "/v2/")
        if any(m in lower for m in dynamic_markers):
            return True

        # 显式排除静态资源（不记录 img/src/css/js/font）
        static_exts = (
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp",
            ".woff", ".woff2", ".ttf", ".otf", ".eot", ".map", ".pdf", ".txt", ".xml"
        )
        if path.endswith(static_exts):
            return False

        # 带 query 的动态路由通常是接口（如 /validateCode?series=1）
        if query and path:
            return True

        # 支持无后缀 REST/登录路由（如 /jsp/login）
        if path and path != "/":
            last_segment = path.rsplit("/", 1)[-1]
            if last_segment and "." not in last_segment:
                return True

        # 兜底：登录/认证类路由关键词（含相对路径 form action）
        auth_markers = ("login", "signin", "auth", "token", "session")
        if path and any(m in path for m in auth_markers):
            return True

        return False

    def _collect_and_analyze_js(self, html: str, base_url: str, manual_js_files: Optional[list[Path]] = None):
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
                   console.print(f"  [yellow]- Skip download failed:[/yellow] idx={idx}, src={src}")
                   continue
                filename = Path(src).name
                if not filename.endswith('.js'):
                    filename = f"script_{idx}.js"

                if self._is_blacklisted_script(js_url, filename):
                    console.print(f"  [yellow]- Skip third-party:[/yellow] {filename}")
                    continue
            else:
                # 内联脚本
                content = script.string or ""
                if not content.strip():
                    continue
                filename = f"inline_{idx}.js"

            self._analyze_single_js_content(
                content=content,
                filename=filename,
                source_type="external" if src else "inline",
                source_url=js_url,
                processed_contents=processed_contents,
            )

        # 手工补充 JS（用于动态加载脚本无法直接从 HTML script 标签获得的场景）
        for js_path in manual_js_files or []:
            try:
                manual_content = js_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                manual_content = js_path.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                console.print(f"  [yellow]![/yellow] 读取手工 JS 失败 {js_path}: {e}")
                continue

            self._analyze_single_js_content(
                content=manual_content,
                filename=js_path.name,
                source_type="manual",
                source_url=str(js_path),
                processed_contents=processed_contents,
            )

        console.print(f"  [green][OK][/green] 分析了 {len(self.result.collected_files)} 个脚本")

    def _analyze_single_js_content(
        self,
        content: str,
        filename: str,
        source_type: str,
        source_url: Optional[str],
        processed_contents: set,
    ):
        """统一处理单个 JS 文本：落盘、格式化、AST 识别、结果登记。"""
        if not content or not content.strip():
            return

        if content in processed_contents:
            console.print(f"  [yellow]- Skip duplicate content:[/yellow] {filename}")
            return
        processed_contents.add(content)

        raw_path = self.raw_js_dir / filename
        counter = 1
        while raw_path.exists():
            raw_path = self.raw_js_dir / f"{raw_path.stem}_{counter}{raw_path.suffix}"
            counter += 1

        with open(raw_path, "w", encoding="utf-8") as f:
            f.write(content)

        console.print(f"  [cyan]Normalize:[/cyan] {filename}")
        normalized_path = self.normalized_js_dir / raw_path.name
        normalized_content = self._run_deobfuscator(raw_path, normalized_path)

        target_path = normalized_path if normalized_content else raw_path
        final_content = normalized_content if normalized_content else content

        console.print(f"  [cyan]AST Detect:[/cyan] {target_path.name}")
        ast_findings = self._run_ast_detector(target_path)
        if ast_findings:
            self._process_ast_findings(ast_findings, final_content, target_path.name)

        # 补充识别：前端口令预哈希链（如 SHA256(SHA256(pwd)+username)）
        self._detect_password_prehash_patterns(final_content, target_path.name)

        # 额外识别 submit 事件绑定（jQuery + 原生 addEventListener）
        self._scan_submit_event_bindings(final_content, target_path.name)

        self.result.collected_files.append({
            "type": source_type,
            "url": source_url,
            "file_path": str(target_path),
            "size": len(final_content)
        })

    def _scan_submit_event_bindings(self, js_content: str, filename: str):
        """识别常见 submit 事件绑定写法，提取 selector 与 handler。"""
        # 兼容 jQuery 别名：$, jQuery, 以及常见短别名（例如 ready(function(e){ e(...) })）
        jq_callee = r"(?:\$|jQuery|[A-Za-z_$][\w$]*)"

        # jQuery: $(selector).submit(handler)
        self._collect_binding_matches(
            js_content,
            filename,
            rf"{jq_callee}\s*\(\s*(?P<selector>[^\)]*?)\s*\)\s*\.submit\s*\(\s*(?P<handler>[^\)]*?)\s*\)",
            "jquery_submit",
        )

        # jQuery: $(selector).on('submit', handler) / .bind('submit', handler)
        self._collect_binding_matches(
            js_content,
            filename,
            rf"{jq_callee}\s*\(\s*(?P<selector>[^\)]*?)\s*\)\s*\.(?:on|bind)\s*\(\s*['\"]submit['\"]\s*,\s*(?P<handler>[^\)]*?)\s*\)",
            "jquery_on_bind",
        )

        # 委托: $(document).on('submit', '#loginform', handler)
        self._collect_binding_matches(
            js_content,
            filename,
            rf"{jq_callee}\s*\(\s*(?:document|['\"]body['\"]|body)\s*\)\s*\.on\s*\(\s*['\"]submit['\"]\s*,\s*(?P<selector>[^,]+?)\s*,\s*(?P<handler>[^\)]*?)\s*\)",
            "jquery_delegate",
        )

        # 原生: document.getElementById(...).addEventListener('submit', handler)
        self._collect_binding_matches(
            js_content,
            filename,
            r"document\.getElementById\s*\(\s*['\"](?P<id>[^'\"]+)['\"]\s*\)\s*\.addEventListener\s*\(\s*['\"]submit['\"]\s*,\s*(?P<handler>[^\)]*?)\s*\)",
            "native_getElementById",
            selector_from_id=True,
        )

        # 原生: document.querySelector('form/#id/...').addEventListener('submit', handler)
        self._collect_binding_matches(
            js_content,
            filename,
            r"document\.querySelector\s*\(\s*(?P<selector>[^\)]*?)\s*\)\s*\.addEventListener\s*\(\s*['\"]submit['\"]\s*,\s*(?P<handler>[^\)]*?)\s*\)",
            "native_querySelector",
        )

        # 原生: element.onsubmit = handler / function(...) {}
        self._collect_binding_matches(
            js_content,
            filename,
            r"(?P<selector>document\.getElementById\s*\(\s*['\"][^'\"]+['\"]\s*\)|document\.querySelector\s*\(\s*[^\)]*\)|[A-Za-z_$][\w$]*)\s*\.onsubmit\s*=\s*(?P<handler>[^;\n]+)",
            "native_onsubmit",
        )

    def _collect_binding_matches(
        self,
        js_content: str,
        filename: str,
        pattern: str,
        bind_type: str,
        selector_from_id: bool = False,
    ):
        """按给定正则收集事件绑定。"""
        for m in re.finditer(pattern, js_content, re.IGNORECASE | re.DOTALL):
            if selector_from_id:
                selector_raw = f"#{(m.group('id') or '').strip()}"
            else:
                selector_raw = (m.groupdict().get("selector") or "").strip()

            handler_raw = (m.groupdict().get("handler") or "").strip()
            if not selector_raw or not handler_raw:
                continue

            selector = self._normalize_selector(selector_raw)
            if not selector:
                continue

            line = js_content.count("\n", 0, m.start()) + 1
            handler = self._normalize_handler_token(handler_raw, filename, line)
            if not handler:
                continue

            self._submit_event_bindings.append({
                "selector": selector,
                "handler": handler,
                "line": line,
                "file": filename,
                "bind_type": bind_type,
            })

    def _normalize_selector(self, selector_raw: str) -> str:
        """将 selector 规范化成可匹配 form 的简化字符串。"""
        s = selector_raw.strip().strip(";,")
        if not s:
            return ""
        if (s.startswith("\"") and s.endswith("\"")) or (s.startswith("'") and s.endswith("'")):
            s = s[1:-1].strip()

        # 支持 document.getElementById("id") / querySelector("...") 形式
        m_id = re.match(r"document\.getElementById\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", s)
        if m_id:
            return f"#{m_id.group(1)}"
        m_qs = re.match(r"document\.querySelector\s*\(\s*(['\"])(.*?)\1\s*\)", s)
        if m_qs:
            s = m_qs.group(2).strip()

        # 只保留与 form 相关的选择器
        if "form" in s or s.startswith("#"):
            return s
        return ""

    def _normalize_handler_token(self, handler_raw: str, filename: str, line: int) -> str:
        """将 handler token 解析为函数名；匿名函数回退为匿名占位。"""
        token = handler_raw.strip().rstrip(";")
        if not token:
            return ""

        # 常见写法: someFunc, obj.someFunc
        ident = re.match(r"^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)$", token)
        if ident:
            return ident.group(1)

        # function(...) { ... } / (...) => ...
        if token.startswith("function") or "=>" in token:
            return f"anonymous@{filename}:{line}"

        return ""

    def _parse_anonymous_handler(self, handler_name: str) -> Optional[tuple[str, int]]:
        """解析 anonymous@file:line 形式的处理器标识。"""
        m = re.match(r"^anonymous@(.+):(\d+)$", handler_name or "")
        if not m:
            return None
        return m.group(1), int(m.group(2))

    def _detect_password_prehash_patterns(self, js_content: str, filename: str):
        """识别常见密码预哈希链，输出 PasswordPreHash 场景详情。"""
        chain_re = re.compile(
            r"CryptoJS\.SHA256\s*\(\s*CryptoJS\.SHA256\s*\(\s*(?P<pwd>[^)]{1,200})\s*\)\s*\+\s*(?P<salt>[^)]{1,200})\s*\)",
            re.IGNORECASE | re.DOTALL,
        )

        for m in chain_re.finditer(js_content):
            pwd_expr = (m.group("pwd") or "").strip()
            salt_expr = (m.group("salt") or "").strip()
            full_expr = m.group(0).strip()
            line = js_content.count("\n", 0, m.start()) + 1

            # 去重：避免同一文件同一行重复追加
            duplicated = any(
                p.file == filename and p.algorithm == "SHA256" and p.line == line
                and any((d.get("scenario") == "PasswordPreHash") for d in (p.details or []))
                for p in self.result.crypto_patterns
            )
            if duplicated:
                continue

            func_name = self._infer_enclosing_function_name(js_content, m.start(), filename, line)
            details = [
                {
                    "operation": "hash",
                    "line": line,
                    "context": f"CryptoJS.SHA256({pwd_expr})",
                    "stage": "inner_hash",
                    "input_expression": pwd_expr,
                },
                {
                    "operation": "hash",
                    "line": line,
                    "context": full_expr,
                    "stage": "outer_hash",
                    "input_expression": f"CryptoJS.SHA256({pwd_expr}) + {salt_expr}",
                    "input_source_keys": ["password", "username"],
                    "scenario": "PasswordPreHash",
                    "info": "前端口令预哈希链",
                },
            ]

            self.result.crypto_patterns.append(CryptoPattern(
                library="CryptoJS",
                algorithm="SHA256",
                operation="hash_chain",
                function_name=func_name,
                file=filename,
                line=line,
                context=full_expr[:300],
                weakness=None,
                details=details,
            ))

    def _infer_enclosing_function_name(self, js_content: str, pos: int, filename: str, line: int) -> str:
        """按位置推断所在函数名；找不到则使用匿名占位。"""
        prefix = js_content[:pos]
        # 支持 function foo(...) 与 foo = function(...)
        candidates: list[tuple[int, str]] = []

        for m in re.finditer(r"function\s+([A-Za-z_$][\w$]*)\s*\(", prefix):
            candidates.append((m.start(), m.group(1)))
        for m in re.finditer(r"([A-Za-z_$][\w$]*)\s*=\s*function\s*\(", prefix):
            candidates.append((m.start(), m.group(1)))

        if candidates:
            candidates.sort(key=lambda x: x[0])
            return candidates[-1][1]
        return f"anonymous@{filename}:{line}"

    def _apply_submit_bindings_to_forms(self):
        """将识别到的 submit 绑定回填到 form_action 端点。"""
        if not self._form_bind_index or not self._submit_event_bindings:
            return

        updated = 0
        for endpoint in self.result.endpoints:
            if endpoint.source != "form_action":
                continue

            form_meta = next((f for f in self._form_bind_index if f["url"] == endpoint.url), None)
            if not form_meta:
                continue

            best = None
            best_score = 0
            for b in self._submit_event_bindings:
                score = self._match_selector_score(b["selector"], form_meta)
                # 委托绑定天然更宽泛，降低一点置信度
                if b.get("bind_type") == "jquery_delegate":
                    score -= 10
                if score > best_score:
                    best_score = score
                    best = b

            # 仅在高置信度时回填；若已有内联 onsubmit 则不覆盖
            if best and best_score >= 50 and not endpoint.trigger_function:
                handler_name = best.get("handler")
                if handler_name:
                    endpoint.trigger_function = str(handler_name)
                    updated += 1

        if updated > 0:
            console.print(f"  [green][OK][/green] 从事件绑定回填了 {updated} 个 form 触发函数")

    def _match_selector_score(self, selector: str, form_meta: dict) -> int:
        """按 selector 与 form 元数据计算匹配分，用于选择最可信的 handler。"""
        s = (selector or "").strip()
        if not s:
            return 0

        form_id = form_meta.get("id") or ""
        form_name = form_meta.get("name") or ""
        form_classes = form_meta.get("classes") or []

        if form_id and f"#{form_id}" in s:
            return 100
        if form_name and f"name=\"{form_name}\"" in s:
            return 90
        for cls in form_classes:
            if f".{cls}" in s:
                return 80
        if s == "form" or s.endswith(" form"):
            return 55
        return 0

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
                encoding="utf-8",
                errors="replace",
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

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )

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
                        if "mode" in sub_detail:
                            detail_entry["mode"] = sub_detail["mode"]
                        if "padding" in sub_detail:
                            detail_entry["padding"] = sub_detail["padding"]
                        if "input_encoding" in sub_detail:
                            detail_entry["input_encoding"] = sub_detail["input_encoding"]
                        if "output_encoding" in sub_detail:
                            detail_entry["output_encoding"] = sub_detail["output_encoding"]
                        if "key_encoding" in sub_detail:
                            detail_entry["key_encoding"] = sub_detail["key_encoding"]
                        if "iv_encoding" in sub_detail:
                            detail_entry["iv_encoding"] = sub_detail["iv_encoding"]
                        if "placement" in sub_detail:
                            detail_entry["placement"] = sub_detail["placement"]
                        if "signature_placement" in sub_detail:
                            detail_entry["signature_placement"] = sub_detail["signature_placement"]
                        if "signature_field" in sub_detail:
                            detail_entry["signature_field"] = sub_detail["signature_field"]
                        if "signature_header_name" in sub_detail:
                            detail_entry["signature_header_name"] = sub_detail["signature_header_name"]
                        if "signature_query_param" in sub_detail:
                            detail_entry["signature_query_param"] = sub_detail["signature_query_param"]
                        if "sign_input_rule" in sub_detail:
                            detail_entry["sign_input_rule"] = sub_detail["sign_input_rule"]
                        if "sign_input_parts" in sub_detail:
                            detail_entry["sign_input_parts"] = sub_detail["sign_input_parts"]
                        if "sign_input_canonicalization" in sub_detail:
                            detail_entry["sign_input_canonicalization"] = sub_detail["sign_input_canonicalization"]
 
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

            anonymous_ref = self._parse_anonymous_handler(trigger_func)

            # 找到该函数使用的加密
            # 分类收集：Algorithm Patterns 和 Raw Trace Calls

            algo_patterns = []  # 存 {library, algorithm, operation}
            trace_calls = set() # 存 "CallName"

            # 1. 从 Crypto Patterns 收集（高置信度算法识别）
            unique_patterns = set()
            for pattern in self.result.crypto_patterns:
                matched = pattern.function_name == trigger_func

                # 匿名 submit 处理器的回填映射：允许按 file+line 邻近匹配
                if not matched and anonymous_ref:
                    anon_file, anon_line = anonymous_ref
                    same_file = (pattern.file == anon_file)
                    near_line = abs((pattern.line or 0) - anon_line) <= 80
                    same_anon = pattern.function_name.startswith("anonymous@")
                    is_prehash = any((d.get("scenario") == "PasswordPreHash") for d in (pattern.details or []))
                    if same_file and (near_line or same_anon or is_prehash):
                        matched = True

                if matched:
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
                matched_func = (func.name == trigger_func)
                if not matched_func and anonymous_ref:
                    anon_file, anon_line = anonymous_ref
                    matched_func = (func.file == anon_file and abs((func.line or 0) - anon_line) <= 80)

                if matched_func and func.calls_crypto:
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

    def _merge_js_discovered_endpoints(self, base_url: str):
        """将函数内识别到的 API 调用补充到 endpoints，覆盖 fetch/axios/$.ajax 等场景。"""
        existing = {(ep.url, ep.method) for ep in self.result.endpoints}
        added = 0

        for func in self.result.functions:
            for api_url in func.calls_api:
                if not api_url or api_url == "unknown":
                    continue
                if not self._looks_like_js_api(api_url):
                    continue
                full_url = urljoin(base_url, api_url)
                key = (full_url, "POST")
                if key in existing:
                    continue

                self.result.endpoints.append(Endpoint(
                    url=full_url,
                    method="POST",
                    source="js_call",
                    trigger_function=func.name
                ))
                existing.add(key)
                added += 1

        if added > 0:
            console.print(f"  [green][OK][/green] 从 JS 调用补充了 {added} 个端点")

    def _looks_like_js_api(self, url: str) -> bool:
        """对 JS 中提取到的 URL 做轻量过滤，避免把配置项字符串误识别为端点。"""
        if not url:
            return False
        url = url.strip()
        if not url or url.startswith("#") or url.startswith("javascript:"):
            return False

        # 统一复用 API 判定逻辑，避免把静态资源当端点
        if self._is_api_endpoint(url):
            return True

        # 至少包含路径分隔，且不像普通单词配置项
        if "/" in url and not re.match(r"^[A-Za-z0-9_.-]+$", url) and not re.search(r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map)(\?|$)", url, re.IGNORECASE):
            return True
        return False

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
    parser.add_argument("--html-file", type=Path, default=None, help="离线 HTML 输入文件（可选）")
    parser.add_argument("--js-file", action="append", type=Path, default=[], help="手工 JS 文件，可重复传入多次")
    parser.add_argument("--js-dir", type=Path, default=None, help="手工 JS 目录（递归读取 *.js）")
    # If --output is not provided, StaticAnalyzer will create script-relative directory under collect/
    parser.add_argument("--output", type=Path, default=None, help="可选：自定义输出目录 (默认放到 collect/static_analysis)")
    parser.add_argument("--no-default-blacklist", action="store_true", help="关闭内置第三方库黑名单")
    parser.add_argument("--blacklist-pattern", action="append", default=[], help="追加黑名单关键字，可重复传入")

    args = parser.parse_args()

    if not args.url and not args.html_file:
        parser.error("必须至少提供 --url 或 --html-file")

    manual_js_files: list[Path] = []
    for p in args.js_file or []:
        if p.exists() and p.is_file() and p.suffix.lower() == ".js":
            manual_js_files.append(p)
        else:
            console.print(f"[yellow]![/yellow] 忽略无效 --js-file: {p}")

    if args.js_dir:
        if args.js_dir.exists() and args.js_dir.is_dir():
            manual_js_files.extend(sorted(args.js_dir.rglob("*.js")))
        else:
            console.print(f"[yellow]![/yellow] 忽略无效 --js-dir: {args.js_dir}")

    html_override = None
    if args.html_file:
        try:
            html_override = args.html_file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            html_override = args.html_file.read_text(encoding="utf-8", errors="ignore")

    analyzer = StaticAnalyzer(
        output_dir=args.output,
        default_blacklist_enabled=not args.no_default_blacklist,
        extra_blacklist_patterns=args.blacklist_pattern,
    )
    analyzer.analyze(args.url or "http://localhost/", html_override=html_override, manual_js_files=manual_js_files)
    analyzer.display_summary()
    analyzer.save_results()


if __name__ == "__main__":
    main()
