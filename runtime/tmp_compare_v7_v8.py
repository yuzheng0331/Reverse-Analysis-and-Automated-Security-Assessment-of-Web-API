import json
from pathlib import Path
from collections import Counter

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API")
p7 = base / "assessment_results" / "assessment_tmp_replay_strict_encoding_gap_v7.json"
p8 = base / "assessment_results" / "assessment_tmp_replay_strict_encoding_gap_v8.json"
out = base / "runtime" / "tmp_compare_v7_v8.json"

def collect(path: Path):
    with path.open("r", encoding="utf-8") as f:
        d = json.load(f)
    baseline = []
    for a in (d.get("assessments") or []):
        for s in (a.get("scenario_results") or []):
            if str(s.get("scenario_id") or "") != "baseline_replay":
                continue
            baseline.append(
                {
                    "matched": (s.get("expectation") or {}).get("matched"),
                    "mode": str((s.get("remote_result") or {}).get("response_mode") or ""),
                    "status": str(s.get("status") or ""),
                }
            )
    return {
        "matched_true": sum(1 for item in baseline if item["matched"] is True),
        "matched_false": sum(1 for item in baseline if item["matched"] is False),
        "modes": dict(Counter(item["mode"] for item in baseline)),
        "status": dict(Counter(item["status"] for item in baseline)),
        "findings_total": (d.get("summary") or {}).get("findings_total"),
        "gap_total": len(d.get("baseline_gap_summary") or []),
    }

with out.open("w", encoding="utf-8") as f:
    json.dump({"v7": collect(p7), "v8": collect(p8)}, f, ensure_ascii=False, indent=2)

