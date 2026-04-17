import json
from pathlib import Path

p = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API\assessment_results\assessment_tmp_replay_strict_encoding_gap_v10.json")
out = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API\runtime\tmp_inspect_v10_one.json")

with p.open("r", encoding="utf-8") as f:
    d = json.load(f)

row = None
for a in d.get("assessments", []):
    if str(a.get("endpoint_id") or "") != "layer1_aes_0009":
        continue
    for s in a.get("scenario_results", []):
        if str(s.get("scenario_id") or "") != "baseline_replay":
            continue
        row = {
            "status": s.get("status"),
            "mode": (s.get("remote_result") or {}).get("response_mode"),
            "body_text": (s.get("request_preview") or {}).get("body_text"),
            "resolved_fields": (s.get("request_preview") or {}).get("resolved_fields"),
            "named_outputs": (s.get("local_replay") or {}).get("named_outputs"),
            "final_output_preview": (s.get("local_replay") or {}).get("final_output_preview"),
            "observations": s.get("observations"),
        }
        break
    break

with out.open("w", encoding="utf-8") as f:
    json.dump(row, f, ensure_ascii=False, indent=2)

