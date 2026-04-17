import json
from collections import Counter, defaultdict
from pathlib import Path

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API")
report_path = base / "assessment_results" / "assessment_tmp_replay_strict_encoding_gap.json"
out_path = base / "runtime" / "strict_baseline_fail_details.json"

with report_path.open("r", encoding="utf-8") as f:
    report = json.load(f)

status_counter = Counter()
match_counter = Counter()
gate_counter = Counter()
local_error_counter = Counter()
remote_mode_counter = Counter()
examples = []

for a in (report.get("assessments", []) or []):
    endpoint_id = str(a.get("endpoint_id") or "unknown")
    for s in (a.get("scenario_results", []) or []):
        if str(s.get("scenario_id") or "") != "baseline_replay":
            continue
        status = str(s.get("status") or "")
        matched = (s.get("expectation") or {}).get("matched")
        gate_code = str((s.get("local_gate") or {}).get("code") or "")
        local_error = str((s.get("local_replay") or {}).get("error") or "")
        remote_mode = str((s.get("remote_result") or {}).get("response_mode") or "")

        status_counter[status] += 1
        match_counter[str(matched)] += 1
        gate_counter[gate_code] += 1
        if local_error:
            local_error_counter[local_error] += 1
        if remote_mode:
            remote_mode_counter[remote_mode] += 1

        if len(examples) < 10:
            examples.append(
                {
                    "endpoint_id": endpoint_id,
                    "status": status,
                    "matched": matched,
                    "gate_code": gate_code,
                    "local_error": local_error,
                    "remote_mode": remote_mode,
                    "observations": s.get("observations", [])[:5],
                }
            )

out = {
    "baseline_replay_status_counts": dict(status_counter),
    "baseline_replay_match_counts": dict(match_counter),
    "baseline_replay_gate_counts": dict(gate_counter),
    "baseline_replay_remote_mode_counts": dict(remote_mode_counter),
    "baseline_replay_local_error_top10": local_error_counter.most_common(10),
    "examples": examples,
}

with out_path.open("w", encoding="utf-8") as f:
    json.dump(out, f, ensure_ascii=False, indent=2)

