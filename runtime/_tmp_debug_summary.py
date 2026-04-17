import json
from pathlib import Path

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API\runtime")
files = sorted(base.glob("debug_packets_*.json"))

for fp in files:
    endpoint_id = fp.stem.replace("debug_packets_", "")
    if endpoint_id in {"aes", "aes_after_fix"}:
        continue
    data = json.loads(fp.read_text(encoding="utf-8"))
    scenarios = data.get("scenario_packets", [])
    raw_body = ((data.get("raw_packet", {}).get("from_reconstructed_baseline") or {}).get("body_text"))

    remote_sent = sum(
        1 for item in scenarios
        if ((item.get("mutated_packet", {}) or {}).get("scenario_status") == "REMOTE_SENT")
    )
    skipped = sum(
        1 for item in scenarios
        if ((item.get("mutated_packet", {}) or {}).get("scenario_status") == "SKIPPED")
    )
    local_failed = sum(
        1 for item in scenarios
        if ((item.get("mutated_packet", {}) or {}).get("scenario_status") == "LOCAL_FAILED")
    )
    changed = sum(
        1 for item in scenarios
        if (((item.get("mutated_packet", {}).get("request_preview") or {}).get("body_text")) != raw_body)
    )
    mismatch = sum(
        1
        for item in scenarios
        if (
            ((item.get("response_packet", {}).get("expectation") or {}).get("defined"))
            and (((item.get("response_packet", {}).get("expectation") or {}).get("matched")) is False)
        )
    )

    print(
        endpoint_id,
        "scenarios=", len(scenarios),
        "REMOTE_SENT=", remote_sent,
        "SKIPPED=", skipped,
        "LOCAL_FAILED=", local_failed,
        "changed_vs_base=", changed,
        "mismatch=", mismatch,
    )

