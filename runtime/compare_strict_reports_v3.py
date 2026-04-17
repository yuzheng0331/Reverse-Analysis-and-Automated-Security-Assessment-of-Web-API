import json
from collections import Counter
from pathlib import Path

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API")
paths = {
    "v1": base / "assessment_results" / "assessment_tmp_replay_strict_encoding_gap.json",
    "v2": base / "assessment_results" / "assessment_tmp_replay_strict_encoding_gap_v2.json",
    "v3": base / "assessment_results" / "assessment_tmp_replay_strict_encoding_gap_v3.json",
}
out_path = base / "runtime" / "strict_report_compare_v3.json"

def summarize(report):
    summary = report.get("summary") or {}
    gaps = report.get("baseline_gap_summary") or []
    gap_counts = Counter(str(g.get("code") or "UNKNOWN") for g in gaps)
    baseline_rows = []
    for a in (report.get("assessments") or []):
        eid = str(a.get("endpoint_id") or "unknown")
        for s in (a.get("scenario_results") or []):
            if str(s.get("scenario_id") or "") != "baseline_replay":
                continue
            baseline_rows.append({
                "endpoint_id": eid,
                "status": str(s.get("status") or ""),
                "matched": (s.get("expectation") or {}).get("matched"),
                "remote_mode": str((s.get("remote_result") or {}).get("response_mode") or ""),
            })
    fail_rows = [r for r in baseline_rows if r["matched"] is not True]
    return {
        "assessed_endpoints": summary.get("assessed_endpoints"),
        "findings_total": summary.get("findings_total"),
        "baseline_gap_total": len(gaps),
        "gap_counts": dict(gap_counts),
        "baseline_replay_total": len(baseline_rows),
        "baseline_replay_matched_true": sum(1 for r in baseline_rows if r["matched"] is True),
        "baseline_replay_matched_false": sum(1 for r in baseline_rows if r["matched"] is False),
        "baseline_replay_remote_mode_counts": dict(Counter(r["remote_mode"] for r in baseline_rows)),
        "baseline_replay_fail_by_endpoint": dict(Counter(r["endpoint_id"] for r in fail_rows)),
    }

result = {}
for key, path in paths.items():
    if not path.exists():
        result[key] = {"exists": False}
        continue
    with path.open("r", encoding="utf-8") as f:
        report = json.load(f)
    entry = summarize(report)
    entry["exists"] = True
    result[key] = entry

with out_path.open("w", encoding="utf-8") as f:
    json.dump(result, f, ensure_ascii=False, indent=2)

