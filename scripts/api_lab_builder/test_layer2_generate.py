from __future__ import annotations

import json
from pathlib import Path

import yaml

from scripts.api_lab_builder.layer2_generate import run_layer2_generate


def _write_yaml(path: Path, data) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, allow_unicode=True, sort_keys=False)


def test_layer2_generate_marks_explicit_interlayers(tmp_path: Path) -> None:
    out_root = tmp_path / "out"
    out_root.mkdir(parents=True)

    layer1_pool = [
        {
            "id": "layer1_00001",
            "algorithm_stack": "AES",
            "algo_params": {
                "key_size": 128,
                "mode": "CBC",
                "iv_policy": "static",
                "padding": "Pkcs7",
                "plaintext_encoding": "utf8",
                "key_encoding": "hex",
                "iv_encoding": "hex",
            },
            "material_source": "FRONTEND_HARDCODED",
            "material_dynamicity": {"key": "static", "iv": "static", "nonce": "absent", "timestamp": "absent", "signature": "absent"},
            "validation_hops": "single_hop",
            "anti_replay": "none",
            "interlayers": [],
            "risk_tags": ["BASELINE_STABLE"],
            "template_level": "BASELINE",
            "route_variant": "PLAIN_ROUTE",
            "site_group": "SITE_A",
        },
        {
            "id": "layer1_00002",
            "algorithm_stack": "AES",
            "algo_params": {
                "key_size": 128,
                "mode": "CBC",
                "iv_policy": "static",
                "padding": "Pkcs7",
                "plaintext_encoding": "base64-pre-encoded",
                "key_encoding": "hex",
                "iv_encoding": "hex",
            },
            "material_source": "FRONTEND_HARDCODED",
            "material_dynamicity": {"key": "static", "iv": "static", "nonce": "absent", "timestamp": "absent", "signature": "absent"},
            "validation_hops": "single_hop",
            "anti_replay": "none",
            "interlayers": [],
            "risk_tags": ["BASELINE_STABLE"],
            "template_level": "BASELINE",
            "route_variant": "PLAIN_ROUTE",
            "site_group": "SITE_A",
        },
    ]
    _write_yaml(out_root / "layer1_pool.yaml", layer1_pool)

    cfg = {
        "global": {
            "fixed_site_group": "SITE_A",
            "allowed_route_variants": ["PLAIN_ROUTE", "WEAK_OBF_ROUTE"],
            "algorithm_whitelist": ["AES", "DES", "RSA_ONLY", "AES_RSA_ENVELOPE", "PLAINTEXT_HMAC"],
        },
        "constraints": {"max_interlayers": 5, "unsupported_markers": []},
        "field_rules": {"dependency_constraints": []},
        "layer1": {"fixed": {"validation_hops": "single_hop", "interlayers": []}, "algorithms": {}},
        "layer2": {
            "source_pool": "layer1_pool.yaml",
            "base_filter": {"route_variant": "PLAIN_ROUTE"},
            "representative_seed": {"enabled": False},
            "dimensions": {
                "material_source": ["FRONTEND_HARDCODED"],
                "material_dynamicity_profile": ["STATIC_LOCAL"],
                "anti_replay": ["none"],
                "session_policy.binding": ["no_bind"],
                "signature_strategy.placement": ["body", "header"],
                "packaging_type": ["urlencoded"],
                "field_policy": ["normal"],
                "content_type": ["application/x-www-form-urlencoded"],
                "key_location": ["body"],
            },
            "profile_map": {
                "STATIC_LOCAL": {"key": "static", "iv": "static", "nonce": "absent", "timestamp": "absent", "signature": "absent"},
            },
            "coverage": {"strength": 2, "max_selected_per_base": 4},
            "constraints": {"enforce_content_type_match": True},
        },
        "output": {
            "directory": "runtime/test",
            "frozen_config": "step0_frozen_config.yaml",
            "step0_gate_report": "step0_gate_report.json",
            "layer1_pool_yaml": "layer1_pool.yaml",
            "layer1_gate_report": "layer1_gate_report.json",
            "layer2_pool_yaml": "layer2_pool.yaml",
            "layer2_pool_json": "layer2_pool.json",
            "layer2_gate_report": "layer2_gate_report.json",
            "layer2_pruned_reasons": "layer2_pruned_reasons.jsonl",
        },
    }

    cfg_path = tmp_path / "cfg.yaml"
    _write_yaml(cfg_path, cfg)

    report = run_layer2_generate(cfg_path, out_root)

    assert report["counts"]["selected"] > 0
    assert report["counts"].get("interlayer_tagged", 0) > 0
    assert (out_root / "layer2_pool.yaml").exists()
    assert (out_root / "layer2_pool.json").exists()
    assert (out_root / "layer2_gate_report.json").exists()

    with open(out_root / "layer2_pool.json", "r", encoding="utf-8") as handle:
        rows = json.load(handle)

    assert all(str(r["id"]).startswith("layer2_") for r in rows)
    assert all("packaging" in r for r in rows)
    assert any("HEADER_SIGN_LAYER" in (r.get("interlayers") or []) for r in rows)
    assert any("ENCODING_LAYER" in (r.get("interlayers") or []) for r in rows)
    assert any((r.get("interlayers") or []) == [] for r in rows)
    assert any(
        (r.get("algorithm_stack") != "PLAINTEXT_HMAC")
        and ({"HEADER_SIGN_LAYER", "ENCODING_LAYER"} & set(r.get("interlayers") or []))
        for r in rows
    )


def test_layer2_generate_non_hmac_keeps_both_target_interlayers(tmp_path: Path) -> None:
    out_root = tmp_path / "out"
    out_root.mkdir(parents=True)

    layer1_pool = [
        {
            "id": "layer1_00001",
            "algorithm_stack": "AES",
            "algo_params": {
                "key_size": 128,
                "mode": "CBC",
                "iv_policy": "static",
                "padding": "Pkcs7",
                "plaintext_encoding": "utf8",
                "key_encoding": "hex",
                "iv_encoding": "hex",
            },
            "material_source": "FRONTEND_HARDCODED",
            "material_dynamicity": {"key": "static", "iv": "static", "nonce": "absent", "timestamp": "absent", "signature": "absent"},
            "validation_hops": "single_hop",
            "anti_replay": "none",
            "interlayers": [],
            "risk_tags": ["BASELINE_STABLE"],
            "template_level": "BASELINE",
            "route_variant": "PLAIN_ROUTE",
            "site_group": "SITE_A",
        }
    ]
    _write_yaml(out_root / "layer1_pool.yaml", layer1_pool)

    cfg = {
        "global": {
            "fixed_site_group": "SITE_A",
            "allowed_route_variants": ["PLAIN_ROUTE"],
            "algorithm_whitelist": ["AES", "PLAINTEXT_HMAC"],
        },
        "constraints": {"max_interlayers": 5, "unsupported_markers": []},
        "field_rules": {"dependency_constraints": []},
        "layer1": {"fixed": {"validation_hops": "single_hop", "interlayers": []}, "algorithms": {}},
        "layer2": {
            "source_pool": "layer1_pool.yaml",
            "base_filter": {"route_variant": "PLAIN_ROUTE"},
            "representative_seed": {"enabled": False},
            "dimensions": {
                "material_source": ["FRONTEND_HARDCODED"],
                "material_dynamicity_profile": ["STATIC_LOCAL"],
                "anti_replay": ["none"],
                "session_policy.binding": ["no_bind"],
                "signature_strategy.placement": ["body", "header"],
                "algo_params.plaintext_encoding": ["utf8", "base64-pre-encoded"],
                "packaging_type": ["urlencoded"],
                "field_policy": ["normal"],
                "content_type": ["application/x-www-form-urlencoded"],
                "key_location": ["body"],
            },
            "profile_map": {
                "STATIC_LOCAL": {"key": "static", "iv": "static", "nonce": "absent", "timestamp": "absent", "signature": "absent"},
            },
            "coverage": {"strength": 2, "max_selected_per_base": 2},
            "constraints": {"enforce_content_type_match": True},
        },
        "output": {
            "directory": "runtime/test",
            "frozen_config": "step0_frozen_config.yaml",
            "step0_gate_report": "step0_gate_report.json",
            "layer1_pool_yaml": "layer1_pool.yaml",
            "layer1_gate_report": "layer1_gate_report.json",
            "layer2_pool_yaml": "layer2_pool.yaml",
            "layer2_pool_json": "layer2_pool.json",
            "layer2_gate_report": "layer2_gate_report.json",
            "layer2_pruned_reasons": "layer2_pruned_reasons.jsonl",
        },
    }

    cfg_path = tmp_path / "cfg.yaml"
    _write_yaml(cfg_path, cfg)

    run_layer2_generate(cfg_path, out_root)

    rows = json.loads((out_root / "layer2_pool.json").read_text(encoding="utf-8"))
    assert len(rows) == 2
    tagged_layers = {layer for row in rows for layer in (row.get("interlayers") or [])}
    assert "HEADER_SIGN_LAYER" in tagged_layers
    assert "ENCODING_LAYER" in tagged_layers







