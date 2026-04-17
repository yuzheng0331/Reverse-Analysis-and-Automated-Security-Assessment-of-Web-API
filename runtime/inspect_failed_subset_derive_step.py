import json
from pathlib import Path

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API")
path = base / "baseline_samples" / "baseline_failed_subset_20260411_150034.json"
out = base / "runtime" / "failed_subset_derive_step_sample.json"

with path.open("r", encoding="utf-8") as f:
    data = json.load(f)

samples = []
for entry in data[:5]:
    eid = (entry.get("meta") or {}).get("id")
    flow = ((entry.get("meta") or {}).get("execution_flow") or [])
    derives = [s for s in flow if str(s.get("step_type") or "").lower().startswith("derive_")]
    samples.append({"endpoint_id": eid, "derive_steps": derives})

with out.open("w", encoding="utf-8") as f:
    json.dump(samples, f, ensure_ascii=False, indent=2)

