import json
from collections import Counter
from pathlib import Path

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API")
old_subset_path = base / "baseline_samples" / "baseline_failed_subset_20260411_150034.json"
new_baseline_path = base / "baseline_samples" / "baseline_skeletons_20260411_193048.json"
out_path = base / "runtime" / "encoding_coverage_compare.json"

with old_subset_path.open("r", encoding="utf-8") as f:
    old_subset = json.load(f)
with new_baseline_path.open("r", encoding="utf-8") as f:
    new_baseline = json.load(f)

failed_ids = {str((e.get("meta") or {}).get("id") or "") for e in old_subset}

new_subset = [e for e in new_baseline if str((e.get("meta") or {}).get("id") or "") in failed_ids]

counter = Counter()
for entry in new_subset:
    for step in ((entry.get("meta") or {}).get("execution_flow") or []):
        if str(step.get("step_type") or "").lower() not in {"encrypt", "sign"}:
            continue
        args = step.get("runtime_args") or {}
        for name in ["input_encoding", "output_encoding", "key_encoding", "iv_encoding"]:
            if args.get(name) not in [None, ""]:
                counter[f"present:{name}"] += 1
            else:
                counter[f"missing:{name}"] += 1

out = {
    "failed_id_count": len(failed_ids),
    "new_subset_count": len(new_subset),
    "counts": dict(counter),
}

with out_path.open("w", encoding="utf-8") as f:
    json.dump(out, f, ensure_ascii=False, indent=2)

