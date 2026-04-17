import json
from pathlib import Path

from assess.assess_endpoint import LocalFlowExecutor

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API")
baseline_path = base / "baseline_samples" / "baseline_failed_subset_20260411_150034.json"
out_path = base / "runtime" / "tmp_local_replay_match_stats.json"

with baseline_path.open("r", encoding="utf-8") as f:
    data = json.load(f)

rows = []
for entry in data:
    eid = str((entry.get("meta") or {}).get("id") or "")
    payload = ((entry.get("request") or {}).get("payload") or {})
    executor = LocalFlowExecutor(entry)
    result = executor.execute(payload, allow_captured_message_fallback=False)
    named = result.get("named_outputs") or {}
    local_ct = named.get("encryptedData") if isinstance(named, dict) else None
    captured_ct = ((entry.get("validation") or {}).get("runtime_params") or {}).get("encryptedData")
    rows.append(
        {
            "endpoint_id": eid,
            "success": bool(result.get("success")),
            "local_cipher": local_ct,
            "captured_cipher": captured_ct,
            "cipher_match": (local_ct == captured_ct) if (local_ct is not None and captured_ct is not None) else None,
            "error": result.get("error"),
            "request_preview": result.get("request_preview"),
        }
    )

summary = {
    "total": len(rows),
    "success_count": sum(1 for r in rows if r["success"]),
    "cipher_match_count": sum(1 for r in rows if r["cipher_match"] is True),
    "cipher_mismatch_count": sum(1 for r in rows if r["cipher_match"] is False),
    "missing_cipher_count": sum(1 for r in rows if r["cipher_match"] is None),
    "mismatch_examples": [r for r in rows if r["cipher_match"] is False][:8],
}

with out_path.open("w", encoding="utf-8") as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)

