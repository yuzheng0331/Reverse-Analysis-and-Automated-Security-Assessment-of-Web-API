import json
from collections import Counter
from pathlib import Path

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API")
report_path = base / "assessment_results" / "assessment_tmp_replay_strict_encoding_gap_v13_admin.json"
out_path = base / "runtime" / "v13_admin_summary.json"

with report_path.open("r", encoding="utf-8") as f:
    report = json.load(f)

rows = []
for a in (report.get("assessments") or []):
    eid = str(a.get("endpoint_id") or "")
    for s in (a.get("scenario_results") or []):
        if str(s.get("scenario_id") or "") != "baseline_replay":
            continue
        rows.append(
            {
                "endpoint_id": eid,
                "matched": (s.get("expectation") or {}).get("matched"),
                "mode": str((s.get("remote_result") or {}).get("response_mode") or ""),
                "status": str(s.get("status") or ""),
            }
        )

summary = {
    "report": str(report_path),
    "assessed": (report.get("summary") or {}).get("assessed_endpoints"),
    "findings_total": (report.get("summary") or {}).get("findings_total"),
    "baseline_gap_total": len(report.get("baseline_gap_summary") or []),
    "baseline_replay_total": len(rows),
    "baseline_replay_matched_true": sum(1 for r in rows if r["matched"] is True),
    "baseline_replay_matched_false": sum(1 for r in rows if r["matched"] is False),
    "baseline_replay_mode_counts": dict(Counter(r["mode"] for r in rows)),
    "baseline_replay_status_counts": dict(Counter(r["status"] for r in rows)),
}

with out_path.open("w", encoding="utf-8") as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)

