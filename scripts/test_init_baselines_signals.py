from __future__ import annotations

from scripts.init_baselines import build_runtime_args_from_detail, forward_detail_fields_to_step


def test_build_runtime_args_preserves_sign_signal_fields() -> None:
    detail = {
        "operation": "sign",
        "placement": "header",
        "signature_placement": "header",
        "signature_field": "signature",
        "signature_header_name": "X-Signature",
        "signature_query_param": "sign",
        "sign_input_rule": "nonce + timestamp + payload",
        "sign_input_parts": ["nonce", "timestamp", "payload"],
        "sign_input_canonicalization": ["concat"],
    }

    runtime_args = build_runtime_args_from_detail(detail, "SHA256", "sign")

    assert runtime_args.get("placement") == "header"
    assert runtime_args.get("signature_placement") == "header"
    assert runtime_args.get("signature_field") == "signature"
    assert runtime_args.get("signature_header_name") == "X-Signature"
    assert runtime_args.get("signature_query_param") == "sign"
    assert runtime_args.get("sign_input_rule") == "nonce + timestamp + payload"
    assert runtime_args.get("sign_input_parts") == ["nonce", "timestamp", "payload"]
    assert runtime_args.get("sign_input_canonicalization") == ["concat"]


def test_forward_detail_fields_to_step_preserves_sign_signal_fields() -> None:
    step = {"runtime_args": {}}
    detail = {
        "placement": "body",
        "signature_placement": "body",
        "signature_field": "sign",
        "sign_input_rule": "JSON.stringify(payload)",
        "sign_input_parts": ["username", "password"],
    }

    forward_detail_fields_to_step(step, detail)

    assert step.get("placement") == "body"
    assert step.get("signature_placement") == "body"
    assert step.get("signature_field") == "sign"
    assert step.get("sign_input_rule") == "JSON.stringify(payload)"
    assert step.get("sign_input_parts") == ["username", "password"]

