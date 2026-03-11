#!/usr/bin/env python3
"""
assess 通用工具
================
为安全评估与报告生成提供共享的小型辅助函数。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml


def utc_now() -> str:
    """返回当前 UTC 时间字符串。"""
    return datetime.now(timezone.utc).isoformat()


def load_json_file(path: Path) -> Any:
    """读取 JSON 文件。"""
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_json_file(path: Path, data: Any) -> None:
    """保存 JSON 文件。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)


def latest_matching_file(directory: Path, pattern: str) -> Optional[Path]:
    """返回目录中匹配模式的最新文件。"""
    if not directory.exists():
        return None
    files = list(directory.glob(pattern))
    if not files:
        return None
    return max(files, key=lambda item: item.stat().st_mtime)


def truncate_text(value: Any, limit: int = 240) -> str:
    """裁剪过长文本，便于报告展示。"""
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def safe_json_dumps(value: Any) -> str:
    """稳定输出紧凑 JSON 字符串。"""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def load_yaml_file(path: Path) -> Any:
    """读取 YAML 文件。"""
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)
