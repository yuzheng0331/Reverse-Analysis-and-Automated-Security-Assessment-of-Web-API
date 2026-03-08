#!/usr/bin/env python3
"""
Handler Base Classes
====================
定义 Handler 框架的基础数据结构和抽象接口。
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, List
from enum import Enum


class CryptoType(Enum):
    """加密类型枚举"""
    SYMMETRIC = "symmetric"  # AES, DES 等
    ASYMMETRIC = "asymmetric"  # RSA, ECC 等
    HASH = "hash"  # MD5, SHA 等
    MAC = "mac"  # HMAC 等
    ENCODING = "encoding"  # Base64 等
    SIGNATURE = "signature"  # 签名


@dataclass
class CryptoContext:
    """
    加密上下文
    包含执行加密所需的所有参数和状态
    """
    # 输入数据
    plaintext: Any = None

    # 算法参数
    algorithm: str = ""  # AES, RSA, HMAC, etc.
    mode: str = ""  # CBC, ECB, GCM, etc.
    padding: str = "Pkcs7"  # PKCS7, ZeroPadding, etc.

    # 密钥材料
    key: Optional[bytes] = None
    iv: Optional[bytes] = None
    salt: Optional[bytes] = None

    # 编码格式
    input_encoding: str = "utf-8"  # 输入编码
    output_encoding: str = "base64"  # 输出编码 (base64, hex)

    # 额外参数（用于特殊算法）
    extra_params: Dict[str, Any] = field(default_factory=dict)

    # 中间结果存储
    intermediate_results: Dict[str, Any] = field(default_factory=dict)

    # 执行状态
    is_success: bool = False
    error_message: str = ""
    logs: List[str] = field(default_factory=list)

    # 动态参数标记 (Stage 4 Runtime Injection)
    # 记录哪些参数是需要在运行时捕获的 (例如: "key", "iv", "token")
    dynamic_requirements: List[str] = field(default_factory=list)

    def merge_runtime_data(self, runtime_data: Dict[str, Any]):
        """从运行时 Hook 数据中合并参数"""
        for req in self.dynamic_requirements:
            if req in runtime_data:
                # 简单映射(目前只对key和iv字段)，实际可能需要类型转换 (Hex/Base64 -> Bytes)
                val = runtime_data[req]
                if req == "key" and isinstance(val, str):
                    self.key = val.encode('utf-8') # 默认行为，子类可覆盖
                elif req == "iv" and isinstance(val, str):
                    self.iv = val.encode('utf-8')
                # ... 其他字段映射
                self.logs.append(f"Injected runtime parameter: {req}")

    def get(self, key: str, default: Any = None) -> Any:
        """获取参数（支持链式查找）"""
        # 优先从 extra_params 获取
        if key in self.extra_params:
            return self.extra_params[key]
        # 然后从实例属性获取
        return getattr(self, key, default)

    def set_intermediate(self, key: str, value: Any):
        """存储中间结果"""
        self.intermediate_results[key] = value

    def get_intermediate(self, key: str) -> Any:
        """获取中间结果"""
        return self.intermediate_results.get(key, None)


@dataclass
class HandlerResult:
    """
    Handler 执行结果
    """
    success: bool
    output: Any = None  # 加密/解密结果
    error: Optional[str] = None
    context: Optional[CryptoContext] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __bool__(self):
        return self.success


@dataclass
class ValidationResult:
    """
    验证结果
    """
    matched: bool
    baseline_value: str = ""
    handler_value: str = ""
    diff: Optional[str] = None
    match_strategies_tried: List[str] = field(default_factory=list)
    matched_strategy: Optional[str] = None
    notes: List[str] = field(default_factory=list)


class CryptoOperation(ABC):
    """
    加密操作抽象基类
    所有加密原语必须继承此类
    """

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def execute(self, context: CryptoContext) -> HandlerResult:
        """
        执行加密操作

        Args:
            context: 加密上下文

        Returns:
            HandlerResult
        """
        pass

    def validate_context(self, context: CryptoContext) -> tuple[bool, Optional[str]]:
        """
        验证上下文是否满足要求

        Returns:
            (is_valid, error_message)
        """
        return True, None


class ContextProvider(ABC):
    """
    上下文提供者抽象基类
    用于从各种来源获取加密参数
    """

    @abstractmethod
    def provide(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        提供上下文参数

        Args:
            endpoint: 目标端点
            **kwargs: 额外参数

        Returns:
            参数字典
        """
        pass

