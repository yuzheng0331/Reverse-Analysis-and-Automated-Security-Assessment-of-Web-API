import json
from collections import Counter
from pathlib import Path

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API")
report_path = base / "assessment_results" / "assessment_tmp_replay_strict_encoding_gap.json"
out_path = base / "runtime" / "strict_review_summary.json"

summary = {
    "report_exists": report_path.exists(),
    "report_size": report_path.stat().st_size if report_path.exists() else None,
}

if report_path.exists():
    with report_path.open("r", encoding="utf-8") as f:
        report = json.load(f)

    assessments = report.get("assessments", []) or []
    gap_summary = report.get("baseline_gap_summary", []) or []

    gap_counts = Counter(str(g.get("code") or "UNKNOWN") for g in gap_summary)

    baseline_rows = []
    for a in assessments:
        endpoint_id = str(a.get("endpoint_id") or "unknown")
        for s in (a.get("scenario_results", []) or []):
            if str(s.get("scenario_id") or "") != "baseline_replay":
                continue
            expectation = s.get("expectation") or {}
            local_gate = s.get("local_gate") or {}
            observations = s.get("observations") or []
            baseline_rows.append(
                {
                    "endpoint_id": endpoint_id,
                    "status": str(s.get("status") or ""),
                    "matched": expectation.get("matched"),
                    "gate_code": str(local_gate.get("code") or ""),
                    "strict_note": any("strict_baseline_replay" in str(item) for item in observations),
                }
            )

    baseline_fail_rows = [
        row
        for row in baseline_rows
        if row.get("matched") is not True or row.get("status") != "REMOTE_SENT" or row.get("gate_code") != "SENDABLE"
    ]
    baseline_fail_by_endpoint = Counter(row.get("endpoint_id") for row in baseline_fail_rows)

    encoding_gaps = [g for g in gap_summary if str(g.get("code") or "") == "MISSING_ENCODING_METADATA"]
    encoding_gap_field_counts = Counter(str(g.get("field") or "") for g in encoding_gaps)

    summary.update(
        {
            "assessed_endpoints": ((report.get("summary") or {}).get("assessed_endpoints")),
            "scenario_total": ((report.get("summary") or {}).get("scenario_results_total")),
            "findings_total": ((report.get("summary") or {}).get("findings_total")),
            "baseline_gap_total": len(gap_summary),
            "gap_counts": dict(gap_counts),
            "baseline_replay_total": len(baseline_rows),
            "baseline_replay_fail_total": len(baseline_fail_rows),
            "baseline_replay_fail_by_endpoint": dict(baseline_fail_by_endpoint),
            "strict_note_covered": sum(1 for row in baseline_rows if row.get("strict_note")),
            "encoding_gap_total": len(encoding_gaps),
            "encoding_gap_field_counts": dict(encoding_gap_field_counts),
        }
    )

with out_path.open("w", encoding="utf-8") as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)

