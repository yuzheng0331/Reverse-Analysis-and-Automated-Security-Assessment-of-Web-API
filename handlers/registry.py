#!/usr/bin/env python3
"""
Crypto Registry
===============
加密算法原语注册表
"""

from typing import Dict, Type, Optional
from .base import CryptoOperation, ContextProvider


class CryptoRegistry:
    """
    全局加密操作注册表
    管理所有可用的加密原语和上下文提供者
    """

    def __init__(self):
        self._operations: Dict[str, Type[CryptoOperation]] = {}
        self._providers: Dict[str, Type[ContextProvider]] = {}

    def register_operation(self, name: str, operation_class: Type[CryptoOperation]):
        """注册加密操作"""
        self._operations[name] = operation_class

    def register_provider(self, name: str, provider_class: Type[ContextProvider]):
        """注册上下文提供者"""
        self._providers[name] = provider_class

    def get_operation(self, name: str) -> Optional[Type[CryptoOperation]]:
        """获取加密操作类"""
        return self._operations.get(name)

    def get_provider(self, name: str) -> Optional[Type[ContextProvider]]:
        """获取上下文提供者类"""
        return self._providers.get(name)

    def list_operations(self) -> list[str]:
        """列出所有已注册的操作"""
        return list(self._operations.keys())

    def list_providers(self) -> list[str]:
        """列出所有已注册的提供者"""
        return list(self._providers.keys())


# 全局注册表实例
_global_registry = CryptoRegistry()
_imported_operations = False

def get_registry() -> CryptoRegistry:
    """获取全局单例注册表"""
    global _imported_operations
    # print(f"DEBUG: get_registry() called. Registry ID: {id(_global_registry)}")
    if not _imported_operations:
        # Auto-import operations to trigger registration decorators
        try:
             # Just import the module, the decorators will run and register to _global_registry
             import handlers.operations
             _imported_operations = True
        except ImportError as e:
             print(f"DEBUG: Failed to auto-import handlers.operations: {e}")
             # If run as script (e.g. verify_handlers), relative import might fail or circular logic?
             pass
    return _global_registry


def register_operation(name: str):
    """装饰器：注册加密操作"""
    def decorator(cls: Type[CryptoOperation]):
        # print(f"DEBUG: Registering operation '{name}' to Registry ID: {id(_global_registry)}")
        _global_registry.register_operation(name, cls)
        return cls
    return decorator


def register_provider(name: str):
    """装饰器：注册上下文提供者"""
    def decorator(cls: Type[ContextProvider]):
        _global_registry.register_provider(name, cls)
        return cls
    return decorator
