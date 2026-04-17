import json
from pathlib import Path

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API\runtime")
for fp in sorted(base.glob("debug_packets_*.json")):
    endpoint_id = fp.stem.replace("debug_packets_", "")
    if endpoint_id in {"aes", "aes_after_fix"}:
        continue

    data = json.loads(fp.read_text(encoding="utf-8"))
    scenarios = data.get("scenario_packets", [])
    raw = ((data.get("raw_packet", {}).get("from_reconstructed_baseline") or {}).get("body_text"))

    remote_sent = sum(
        1 for s in scenarios
        if ((s.get("mutated_packet", {}) or {}).get("scenario_status") == "REMOTE_SENT")
    )
    skipped = sum(
        1 for s in scenarios
        if ((s.get("mutated_packet", {}) or {}).get("scenario_status") == "SKIPPED")
    )
    local_failed = [
        s for s in scenarios
        if ((s.get("mutated_packet", {}) or {}).get("scenario_status") == "LOCAL_FAILED")
    ]
    changed = sum(
        1 for s in scenarios
        if (((s.get("mutated_packet", {}).get("request_preview") or {}).get("body_text")) != raw)
    )
    mismatch = [
        s for s in scenarios
        if (((s.get("response_packet", {}).get("expectation") or {}).get("defined"))
            and (((s.get("response_packet", {}).get("expectation") or {}).get("matched")) is False))
    ]

    print(f"\n[{endpoint_id}] scenarios={len(scenarios)} REMOTE_SENT={remote_sent} SKIPPED={skipped} LOCAL_FAILED={len(local_failed)} changed_vs_base={changed} mismatch={len(mismatch)}")

    if local_failed:
        print("  LOCAL_FAILED:")
        for s in local_failed:
            mp = s.get("mutated_packet", {}) or {}
            print("   -", s.get("scenario_id"), "=>", str(mp.get("local_error"))[:140])

    if mismatch:
        print("  MISMATCH:")
        for s in mismatch:
            rp = ((s.get("response_packet", {}) or {}).get("remote_result") or {})
            exp = ((s.get("response_packet", {}) or {}).get("expectation") or {})
            print("   -", s.get("scenario_id"), "mode=", rp.get("response_mode"), "expected=", exp.get("expected_remote_modes"))

