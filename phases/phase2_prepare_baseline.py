#!/usr/bin/env python3
"""阶段 2：基线骨架生成与 Payload 预填统一入口。"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import TextIO
from common import BASE_DIR, DEFAULT_PASSWORD, DEFAULT_USERNAME, fill_login_payloads, resolve_baseline_path, run_python_script, emit


def run_phase2(username: str, password: str, log_handle: TextIO | None = None) -> Path:
    run_python_script(BASE_DIR / "scripts" / "init_baselines.py", log_handle=log_handle)
    baseline_path = resolve_baseline_path(allow_tmp=False)
    summary = fill_login_payloads(baseline_path, username, password)
    emit(f"[阶段2] 基线文件: {baseline_path}", log_handle)
    emit(f"[阶段2] 已填充 Payload 的记录数: {summary['updated_entries']} / {summary['total_entries']}", log_handle)
    return baseline_path


def main() -> None:
    parser = argparse.ArgumentParser(description="阶段2：生成基线骨架并填入用户名/密码")
    parser.add_argument("--username", default=DEFAULT_USERNAME, help="要写入基线的用户名")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="要写入基线的密码")
    args = parser.parse_args()
    run_phase2(args.username, args.password)


if __name__ == "__main__":
    main()
