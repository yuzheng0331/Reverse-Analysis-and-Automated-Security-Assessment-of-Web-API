import json
from pathlib import Path

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API")
baseline_path = base / "baseline_samples" / "baseline_failed_subset_20260411_150034.json"
out_path = base / "runtime" / "tmp_missing_runtime_iv.json"

ids = {"layer1_aes_0025", "layer1_aes_0026", "layer1_aes_0027", "layer1_aes_0028"}
with baseline_path.open("r", encoding="utf-8") as f:
    data = json.load(f)

rows = []
for e in data:
    eid = str((e.get("meta") or {}).get("id") or "")
    if eid not in ids:
        continue
    rp = ((e.get("validation") or {}).get("runtime_params") or {})
    trace = ((e.get("validation") or {}).get("trace") or [])
    fetch = next((t for t in reversed(trace) if isinstance(t, dict) and str(t.get("type") or "") == "FETCH"), {})
    rows.append({
        "endpoint_id": eid,
        "runtime_iv": rp.get("iv"),
        "runtime_key": rp.get("key"),
        "fetch_body": fetch.get("body"),
        "fetch_body_form": fetch.get("body_form"),
    })

with out_path.open("w", encoding="utf-8") as f:
    json.dump(rows, f, ensure_ascii=False, indent=2)

