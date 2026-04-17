import json
from collections import Counter
from pathlib import Path

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API")
paths = {
    "v1": base / "assessment_results" / "assessment_tmp_replay_strict_encoding_gap.json",
    "v5": base / "assessment_results" / "assessment_tmp_replay_strict_encoding_gap_v5.json",
}
out = base / "runtime" / "strict_report_compare_v5.json"

def summary(path: Path):
    with path.open("r", encoding="utf-8") as f:
        d = json.load(f)
    gaps = d.get("baseline_gap_summary") or []
    gap_counts = Counter(str(g.get("code") or "") for g in gaps)
    gap_fields = Counter(str(g.get("field") or "") for g in gaps)
    baseline = []
    for a in (d.get("assessments") or []):
        for s in (a.get("scenario_results") or []):
            if str(s.get("scenario_id") or "") == "baseline_replay":
                baseline.append((s.get("expectation") or {}).get("matched"))
    return {
        "findings_total": (d.get("summary") or {}).get("findings_total"),
        "baseline_gap_total": len(gaps),
        "gap_counts": dict(gap_counts),
        "gap_fields": dict(gap_fields),
        "baseline_replay_total": len(baseline),
        "baseline_replay_matched_true": sum(1 for x in baseline if x is True),
        "baseline_replay_matched_false": sum(1 for x in baseline if x is False),
    }

result = {}
for k, p in paths.items():
    result[k] = {"exists": p.exists()}
    if p.exists():
        result[k].update(summary(p))

with out.open("w", encoding="utf-8") as f:
    json.dump(result, f, ensure_ascii=False, indent=2)

