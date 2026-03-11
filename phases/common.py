from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Optional, TextIO

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_TARGET_URL = os.getenv("TARGET_URL") or "http://encrypt-labs-main/easy.php"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "123456"


def latest_matching_file(directory: Path, pattern: str, *, allow_tmp: bool = True) -> Optional[Path]:
    if not directory.exists():
        return None
    files = list(directory.glob(pattern))
    if not allow_tmp:
        files = [item for item in files if ".tmp" not in item.name]
    if not files:
        return None
    return max(files, key=lambda item: item.stat().st_mtime)


def resolve_baseline_path(path: str | Path | None = None, *, allow_tmp: bool = False) -> Path:
    if path:
        candidate = Path(path)
        if not candidate.exists():
            raise FileNotFoundError(f"未找到基线文件: {candidate}")
        return candidate
    baseline_dir = BASE_DIR / "baseline_samples"
    latest = latest_matching_file(baseline_dir, "baseline_skeletons_*.json", allow_tmp=allow_tmp)
    if latest:
        return latest
    latest_any = latest_matching_file(baseline_dir, "baseline_skeletons_*.json", allow_tmp=True)
    if latest_any:
        return latest_any
    raise FileNotFoundError("baseline_samples 中未找到 baseline_skeletons_*.json")


def emit(message: str, log_handle: TextIO | None = None) -> None:
    print(message)
    if log_handle:
        log_handle.write(message + "\n")
        log_handle.flush()


def run_python_script(script_path: Path, args: Iterable[str] | None = None, log_handle: TextIO | None = None) -> None:
    command = [sys.executable, str(script_path)] + list(args or [])
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    if not log_handle:
        subprocess.run(command, cwd=BASE_DIR, check=True, env=env)
        return

    process = subprocess.Popen(
        command,
        cwd=BASE_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    assert process.stdout is not None
    for line in process.stdout:
        sys.stdout.write(line)
        log_handle.write(line)
        log_handle.flush()
    process.wait()
    log_handle.flush()
    if process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, command)


def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_json(path: Path, data) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)


def fill_login_payloads(baseline_path: Path, username: str, password: str) -> dict[str, int]:
    data = load_json(baseline_path)
    updated_entries = 0
    created_payloads = 0

    for entry in data:
        request = entry.setdefault("request", {})
        payload = request.get("payload")

        if not isinstance(payload, dict) or not payload:
            request["payload"] = {"username": username, "password": password}
            updated_entries += 1
            created_payloads += 1
            continue

        if "_comment" in payload:
            request["payload"] = {"username": username, "password": password}
            updated_entries += 1
            created_payloads += 1
            continue

        changed = False
        if "username" in payload and payload.get("username") in {"<Fill Value>", "", None}:
            payload["username"] = username
            changed = True
        if "password" in payload and payload.get("password") in {"<Fill Value>", "", None}:
            payload["password"] = password
            changed = True
        if changed:
            updated_entries += 1

    save_json(baseline_path, data)
    return {"updated_entries": updated_entries, "created_payloads": created_payloads, "total_entries": len(data)}


def summarize_verification(baseline_path: Path) -> dict[str, int]:
    data = load_json(baseline_path)
    summary: dict[str, int] = {"total": len(data), "verified": 0}
    for entry in data:
        status = str(entry.get("status", "UNKNOWN"))
        summary[status] = summary.get(status, 0) + 1
        if entry.get("validation", {}).get("verified"):
            summary["verified"] += 1
    return summary

