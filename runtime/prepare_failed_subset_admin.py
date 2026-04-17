import json
from pathlib import Path

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API")
in_path = base / "baseline_samples" / "baseline_failed_subset_20260411_150034.json"
out_path = base / "baseline_samples" / "baseline_failed_subset_admin_20260412.json"

with in_path.open("r", encoding="utf-8") as f:
    rows = json.load(f)

updated = 0
missing = 0
for entry in rows:
    payload = ((entry.get("request") or {}).get("payload") or {})
    if not isinstance(payload, dict):
        missing += 1
        continue
    changed = False
    if "username" in payload:
        payload["username"] = "admin"
        changed = True
    if "password" in payload:
        payload["password"] = "123456"
        changed = True
    if changed:
        updated += 1
    else:
        missing += 1

with out_path.open("w", encoding="utf-8") as f:
    json.dump(rows, f, ensure_ascii=False, indent=2)

summary = {
    "input": str(in_path),
    "output": str(out_path),
    "total": len(rows),
    "updated": updated,
    "missing_payload_keys": missing,
}

sum_path = base / "runtime" / "prepare_failed_subset_admin_summary.json"
with sum_path.open("w", encoding="utf-8") as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)

