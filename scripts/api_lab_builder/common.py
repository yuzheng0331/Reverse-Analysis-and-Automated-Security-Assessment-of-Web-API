from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml


@dataclass
class PruneRecord:
    spec_id: str
    reason_code: str
    message: str


def load_yaml(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def dump_yaml(path: Path, data: Any) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        yaml.safe_dump(data, handle, allow_unicode=True, sort_keys=False)


def dump_json(path: Path, data: Any) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)


def append_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def normalize_for_hash(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: normalize_for_hash(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [normalize_for_hash(item) for item in value]
    return value


def dedupe_key(spec: dict[str, Any]) -> str:
    payload = {
        "algorithm_stack": spec.get("algorithm_stack"),
        "algo_params": normalize_for_hash(spec.get("algo_params", {})),
        "material_source": spec.get("material_source"),
        "material_dynamicity": normalize_for_hash(spec.get("material_dynamicity", {})),
        "validation_hops": spec.get("validation_hops"),
        "anti_replay": spec.get("anti_replay"),
        "interlayers": normalize_for_hash(spec.get("interlayers", [])),
        "signature_strategy": normalize_for_hash(spec.get("signature_strategy", {})),
        "session_policy": normalize_for_hash(spec.get("session_policy", {})),
        "packaging": normalize_for_hash(spec.get("packaging", {})),
        "transport": normalize_for_hash(spec.get("transport", {})),
        "route_variant": spec.get("route_variant"),
        "template_level": spec.get("template_level"),
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

