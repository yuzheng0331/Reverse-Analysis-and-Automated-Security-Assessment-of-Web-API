import json
from collections import Counter
from pathlib import Path

p = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API\assessment_results\assessment_tmp_replay_strict_encoding_gap_v3.json")
out = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API\runtime\v3_gap_field_counts.json")
with p.open("r", encoding="utf-8") as f:
    d = json.load(f)
fields = Counter(str(g.get("field") or "") for g in (d.get("baseline_gap_summary") or []))
reasons = Counter(str(g.get("reason") or "") for g in (d.get("baseline_gap_summary") or []))
with out.open("w", encoding="utf-8") as f:
    json.dump({"field_counts": dict(fields), "reason_top": reasons.most_common(3)}, f, ensure_ascii=False, indent=2)

