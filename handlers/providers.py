#!/usr/bin/env python3
"""
Context Providers
=================
从各种来源提供加密上下文参数
"""

import json
from pathlib import Path
from typing import Dict, Any

from .base import ContextProvider
from .registry import register_provider


@register_provider("static")
class StaticProvider(ContextProvider):
    """
    静态参数提供者
    直接从配置文件提供固定参数
    """

    def __init__(self, params: Dict[str, Any]):
        self.params = params

    def provide(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        return self.params.copy()


@register_provider("static_analysis")
class StaticAnalysisProvider(ContextProvider):
    """
    从静态分析结果提供参数
    """

    def __init__(self, analysis_dir: Path):
        self.analysis_dir = Path(analysis_dir)
        self.analysis_data = self._load_latest()

    def _load_latest(self) -> Dict:
        """加载最新的静态分析结果"""
        files = sorted(self.analysis_dir.glob("static_analysis_*.json"))
        if not files:
            return {}

        with open(files[-1], encoding="utf-8") as f:
            return json.load(f)

    def provide(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """根据端点提供参数"""
        params = {}

        # 从端点映射中查找加密信息
        endpoint_map = self.analysis_data.get("endpoint_crypto_map", {})

        for url, info in endpoint_map.items():
            if endpoint in url:
                crypto_list = info.get("crypto", [])
                if crypto_list:
                    # 提取第一个加密算法信息
                    first_crypto = crypto_list[0]
                    params["algorithm"] = first_crypto.get("algorithm", "")
                    params["library"] = first_crypto.get("library", "")
                break

        return params


@register_provider("baseline")
class BaselineProvider(ContextProvider):
    """
    从基线样本提供参数
    用于提取真实请求中的加密参数
    """

    def __init__(self, baseline_path: Path):
        self.baseline_path = Path(baseline_path)
        self.baseline_data = self._load_baseline()

    def _load_baseline(self) -> Dict:
        """加载基线样本"""
        if not self.baseline_path.exists():
            return {}

        with open(self.baseline_path, encoding="utf-8") as f:
            return json.load(f)

    def provide(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """从基线样本中提取参数"""
        params = {}

        # 查找匹配的请求
        for request in self.baseline_data.get("requests", []):
            req_url = request.get("request", {}).get("url", "")
            if endpoint in req_url:
                # 提取请求数据
                post_data = request.get("request", {}).get("post_data_parsed", {})
                params["baseline_request"] = post_data

                # 提取响应数据
                response = request.get("response", {})
                params["baseline_response"] = response
                break

        return params


@register_provider("env")
class EnvironmentProvider(ContextProvider):
    """
    从环境变量提供参数
    """

    def __init__(self):
        import os
        from dotenv import load_dotenv
        load_dotenv()
        self.env = os.environ

    def provide(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """从环境变量提取参数"""
        params = {}

        # 查找以 CRYPTO_ 开头的环境变量
        for key, value in self.env.items():
            if key.startswith("CRYPTO_"):
                param_name = key[7:].lower()  # 移除 CRYPTO_ 前缀
                params[param_name] = value

        return params


@register_provider("composite")
class CompositeProvider(ContextProvider):
    """
    组合提供者
    按优先级合并多个提供者的结果
    """

    def __init__(self, providers: list[ContextProvider]):
        self.providers = providers

    def provide(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """合并所有提供者的结果"""
        params = {}

        # 按顺序合并（后面的覆盖前面的）
        for provider in self.providers:
            provider_params = provider.provide(endpoint, **kwargs)
            params.update(provider_params)

        return params

