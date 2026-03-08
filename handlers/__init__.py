#!/usr/bin/env python3
"""
Handler Framework
=================
加密 Handler 框架，支持配置驱动的加密流水线。

核心组件:
- CryptoRegistry: 算法原语注册表
- HandlerPipeline: 加密流水线执行器
- ValidationLayer: 基线对比验证层
"""

from .base import (
    CryptoOperation,
    CryptoContext,
    HandlerResult,
    ValidationResult,
)

from .registry import CryptoRegistry
from .pipeline import HandlerPipeline, BaselinePipelineRunner
from .validator import ValidationLayer

__all__ = [
    "CryptoOperation",
    "CryptoContext",
    "HandlerResult",
    "ValidationResult",
    "CryptoRegistry",
    "HandlerPipeline",
    "BaselinePipelineRunner",
    "ValidationLayer"
]

