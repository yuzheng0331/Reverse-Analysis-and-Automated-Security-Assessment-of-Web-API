import json
from pathlib import Path
from collections import Counter

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API")
p5 = base / "assessment_results" / "assessment_tmp_replay_strict_encoding_gap_v5.json"
p6 = base / "assessment_results" / "assessment_tmp_replay_strict_encoding_gap_v6.json"
out = base / "runtime" / "tmp_compare_v5_v6.json"

def collect(path):
    with path.open("r", encoding="utf-8") as f:
        d = json.load(f)
    gaps = d.get("baseline_gap_summary") or []
    baseline = []
    for a in (d.get("assessments") or []):
        for s in (a.get("scenario_results") or []):
            if str(s.get("scenario_id") or "") != "baseline_replay":
                continue
            baseline.append({
                "matched": (s.get("expectation") or {}).get("matched"),
                "remote_mode": str((s.get("remote_result") or {}).get("response_mode") or ""),
                "status": str(s.get("status") or ""),
            })
    return {
        "findings_total": (d.get("summary") or {}).get("findings_total"),
        "gap_total": len(gaps),
        "gap_codes": dict(Counter(str(g.get("code") or "") for g in gaps)),
        "matched_true": sum(1 for r in baseline if r["matched"] is True),
        "matched_false": sum(1 for r in baseline if r["matched"] is False),
        "remote_mode": dict(Counter(r["remote_mode"] for r in baseline)),
        "status": dict(Counter(r["status"] for r in baseline)),
    }

out_data = {"v5": collect(p5), "v6": collect(p6)}
with out.open("w", encoding="utf-8") as f:
    json.dump(out_data, f, ensure_ascii=False, indent=2)

