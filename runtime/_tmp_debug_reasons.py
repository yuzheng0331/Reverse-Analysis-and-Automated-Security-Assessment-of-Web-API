import json
from collections import Counter
from pathlib import Path

base = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API\runtime")
for fp in sorted(base.glob("debug_packets_*.json")):
    endpoint_id = fp.stem.replace("debug_packets_", "")
    if endpoint_id in {"aes", "aes_after_fix"}:
        continue
    data = json.loads(fp.read_text(encoding="utf-8"))
    scenarios = data.get("scenario_packets", [])
    skip_reasons = Counter()
    local_errors = Counter()
    mismatch_ids = []

    for item in scenarios:
        mid = item.get("scenario_id")
        mp = item.get("mutated_packet", {}) or {}
        st = mp.get("scenario_status")
        if st == "SKIPPED":
            skip_reasons[str(mp.get("skip_reason") or "")[:120]] += 1
        if st == "LOCAL_FAILED":
            local_errors[str(mp.get("local_error") or "")[:120]] += 1
        expectation = ((item.get("response_packet", {}) or {}).get("expectation") or {})
        if expectation.get("defined") and expectation.get("matched") is False:
            mismatch_ids.append(mid)

    if skip_reasons or local_errors or mismatch_ids:
        print(f"\n[{endpoint_id}]")
        if mismatch_ids:
            print("  mismatch:", ", ".join(map(str, mismatch_ids)))
        if skip_reasons:
            print("  skipped reasons:")
            for k, v in skip_reasons.items():
                print(f"    - ({v}) {k}")
        if local_errors:
            print("  local failed errors:")
            for k, v in local_errors.items():
                print(f"    - ({v}) {k}")

