from __future__ import annotations

import json
from pathlib import Path

import yaml

from scripts.api_lab_builder.layer2_generate import run_layer2_generate


def _write_yaml(path: Path, data) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, allow_unicode=True, sort_keys=False)


def test_layer2_generate_outputs_parallel_pool(tmp_path: Path) -> None:
    out_root = tmp_path / "out"
    out_root.mkdir(parents=True)

    layer1_pool = [
        {
            "id": "layer1_00001",
            "algorithm_stack": "AES",
            "algo_params": {"key_size": 128, "mode": "CBC", "iv_policy": "static", "padding": "Pkcs7"},
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
            "allowed_route_variants": ["PLAIN_ROUTE", "WEAK_OBF_ROUTE"],
            "algorithm_whitelist": ["AES", "DES", "RSA_ONLY", "AES_RSA_ENVELOPE", "PLAINTEXT_HMAC"],
        },
        "constraints": {"max_interlayers": 5, "unsupported_markers": []},
        "layer1": {"fixed": {"validation_hops": "single_hop", "interlayers": []}, "algorithms": {}},
        "layer2": {
            "source_pool": "layer1_pool.yaml",
            "base_filter": {"route_variant": "PLAIN_ROUTE"},
            "dimensions": {
                "material_source": ["FRONTEND_HARDCODED", "FRONTEND_DERIVED"],
                "material_dynamicity_profile": ["STATIC_LOCAL", "NONCE_TIMESTAMP"],
                "packaging_type": ["urlencoded", "json"],
                "field_policy": ["normal"],
                "content_type": ["application/x-www-form-urlencoded", "application/json"],
                "key_location": ["body"],
            },
            "profile_map": {
                "STATIC_LOCAL": {"key": "static", "iv": "static", "nonce": "absent", "timestamp": "absent", "signature": "absent"},
                "NONCE_TIMESTAMP": {"key": "static", "iv": "static", "nonce": "dynamic", "timestamp": "dynamic", "signature": "absent"},
            },
            "coverage": {"strength": 3, "max_selected_per_base": 6},
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
    assert (out_root / "layer2_pool.yaml").exists()
    assert (out_root / "layer2_pool.json").exists()
    assert (out_root / "layer2_gate_report.json").exists()

    with open(out_root / "layer2_pool.json", "r", encoding="utf-8") as handle:
        rows = json.load(handle)
    assert all(str(r["id"]).startswith("layer2_") for r in rows)
    assert all("packaging" in r for r in rows)

