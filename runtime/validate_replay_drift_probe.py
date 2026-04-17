import json
from pathlib import Path

import requests

BASE = Path(r"D:\Reverse Analysis and Automated Security Assessment of Web API")
BASELINE = BASE / "baseline_samples" / "baseline_failed_subset_20260411_150034.json"
OUT = BASE / "runtime" / "replay_drift_probe.json"

PROBE_IDS = [
    "layer1_aes_0009",  # decrypt_fail group
    "layer1_aes_0010",
    "layer1_aes_0025",  # missing_data -> fixed-to-decrypt_fail group (with iv field)
    "layer1_aes_0026",
]


def classify_mode(status_code, body_text):
    body = (body_text or "").lower()
    if status_code is None:
        return "NOT_ATTEMPTED"
    if status_code >= 500:
        return "SERVER_5XX"
    if status_code >= 400:
        return "HTTP_4XX"
    if "decrypt" in body or "解密" in (body_text or ""):
        return "APP_DECRYPT_FAIL"
    if "missing" in body or "no data" in body:
        return "APP_MISSING_DATA"
    if '"success":false' in body:
        return "APP_REJECTED"
    if '"success":true' in body:
        return "APP_SUCCESS"
    return "HTTP_OK_OTHER" if 200 <= status_code < 300 else "HTTP_OTHER"


with BASELINE.open("r", encoding="utf-8") as f:
    rows = json.load(f)

entry_map = {str((e.get("meta") or {}).get("id") or ""): e for e in rows}
results = []

for endpoint_id in PROBE_IDS:
    e = entry_map.get(endpoint_id)
    if not e:
        results.append({"endpoint_id": endpoint_id, "error": "entry_not_found"})
        continue

    meta = e.get("meta") or {}
    validation = e.get("validation") or {}
    req_headers = ((e.get("request") or {}).get("headers") or {}).copy()
    trace = validation.get("trace") or []
    fetch_item = next((t for t in reversed(trace) if isinstance(t, dict) and str(t.get("type") or "") == "FETCH"), None)
    if not fetch_item:
        results.append({"endpoint_id": endpoint_id, "error": "fetch_trace_not_found"})
        continue

    url = str(meta.get("url") or "")
    body = fetch_item.get("body")
    if body is None:
        results.append({"endpoint_id": endpoint_id, "error": "fetch_body_missing"})
        continue

    cookies = {}
    for c in (((validation.get("session") or {}).get("cookies") or [])):
        name = str(c.get("name") or "")
        value = str(c.get("value") or "")
        if name:
            cookies[name] = value

    # Variant A: with captured cookies
    status_a = None
    text_a = ""
    err_a = None
    try:
        r = requests.request(str(meta.get("method") or "POST"), url, headers=req_headers, data=body, cookies=cookies or None, timeout=10)
        status_a = r.status_code
        text_a = r.text[:300]
    except Exception as ex:
        err_a = str(ex)

    # Variant B: no cookies
    status_b = None
    text_b = ""
    err_b = None
    try:
        r2 = requests.request(str(meta.get("method") or "POST"), url, headers=req_headers, data=body, timeout=10)
        status_b = r2.status_code
        text_b = r2.text[:300]
    except Exception as ex:
        err_b = str(ex)

    results.append(
        {
            "endpoint_id": endpoint_id,
            "url": url,
            "captured_body": body,
            "captured_body_form_keys": sorted(list((fetch_item.get("body_form") or {}).keys())) if isinstance(fetch_item.get("body_form"), dict) else [],
            "variant_with_cookies": {
                "status_code": status_a,
                "response_mode": classify_mode(status_a, text_a),
                "error": err_a,
                "body_preview": text_a,
            },
            "variant_without_cookies": {
                "status_code": status_b,
                "response_mode": classify_mode(status_b, text_b),
                "error": err_b,
                "body_preview": text_b,
            },
        }
    )

with OUT.open("w", encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

