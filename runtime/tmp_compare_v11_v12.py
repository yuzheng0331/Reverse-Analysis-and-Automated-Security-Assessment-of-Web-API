import json
from collections import Counter
from pathlib import Path

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API")
p11 = base / "assessment_results" / "assessment_tmp_replay_strict_encoding_gap_v11.json"
p12 = base / "assessment_results" / "assessment_tmp_replay_strict_encoding_gap_v12.json"
out = base / "runtime" / "tmp_compare_v11_v12.json"


def collect(path: Path):
    with path.open("r", encoding="utf-8") as f:
        d = json.load(f)
    rows = []
    for a in (d.get("assessments") or []):
        for s in (a.get("scenario_results") or []):
            if str(s.get("scenario_id") or "") != "baseline_replay":
                continue
            rows.append(
                {
                    "matched": (s.get("expectation") or {}).get("matched"),
                    "mode": str((s.get("remote_result") or {}).get("response_mode") or ""),
                    "status": str(s.get("status") or ""),
                }
            )
    return {
        "matched_true": sum(1 for r in rows if r["matched"] is True),
        "matched_false": sum(1 for r in rows if r["matched"] is False),
        "modes": dict(Counter(r["mode"] for r in rows)),
        "status": dict(Counter(r["status"] for r in rows)),
        "findings_total": (d.get("summary") or {}).get("findings_total"),
        "gap_total": len(d.get("baseline_gap_summary") or []),
    }


with out.open("w", encoding="utf-8") as f:
    json.dump({"v11": collect(p11), "v12": collect(p12)}, f, ensure_ascii=False, indent=2)

