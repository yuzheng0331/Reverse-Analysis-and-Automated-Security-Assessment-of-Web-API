from __future__ import annotations

import json
from pathlib import Path

import yaml

from scripts.api_lab_builder.layer1_write_sample import run_layer1_write_sample


def _write_yaml(path: Path, data) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, allow_unicode=True, sort_keys=False)


def test_layer1_write_sample_generates_php_js_and_manifest(tmp_path: Path) -> None:
    site_root = tmp_path / "site"
    (site_root / "js").mkdir(parents=True)
    (site_root / "encrypt").mkdir(parents=True)

    (site_root / "easy.php").write_text("<html><body><div>base</div></body></html>", encoding="utf-8")
    (site_root / "js" / "easy.js").write_text("function closeModal(){}", encoding="utf-8")

    out_root = tmp_path / "out"
    out_root.mkdir(parents=True)

    layer1_pool = [
        {
            "id": "layer1_00001",
            "algorithm_stack": "AES_CBC",
            "algo_params": {"key_size": 128, "iv_policy": "static", "padding": "Pkcs7", "mode": "CBC"},
            "material_source": "FRONTEND_HARDCODED",
            "material_dynamicity": {"key": "static", "iv": "static", "nonce": "absent", "timestamp": "absent", "signature": "absent"},
            "validation_hops": "single_hop",
            "anti_replay": "none",
            "interlayers": [],
            "risk_tags": ["BASELINE_STABLE"],
            "route_variant": "PLAIN_ROUTE",
            "site_group": "SITE_A",
            "template_level": "BASELINE",
        },
        {
            "id": "layer1_00002",
            "algorithm_stack": "PLAINTEXT_HMAC",
            "algo_params": {"plaintext_encoding": "utf8"},
            "material_source": "FRONTEND_DERIVED",
            "material_dynamicity": {"key": "dynamic", "iv": "absent", "nonce": "dynamic", "timestamp": "dynamic", "signature": "dynamic"},
            "validation_hops": "single_hop",
            "anti_replay": "nonce_timestamp",
            "interlayers": [],
            "risk_tags": ["BASELINE_STABLE"],
            "route_variant": "PLAIN_ROUTE",
            "site_group": "SITE_A",
            "template_level": "BASELINE",
            "signature_strategy": {"placement": "header"},
        },
    ]

    _write_yaml(out_root / "layer1_pool.yaml", layer1_pool)

    cfg = {
        "global": {
            "fixed_site_group": "SITE_A",
            "allowed_route_variants": ["PLAIN_ROUTE", "WEAK_OBF_ROUTE"],
            "algorithm_whitelist": ["AES_CBC", "RSA_ONLY", "PLAINTEXT_HMAC"],
        },
        "constraints": {"max_interlayers": 5, "unsupported_markers": []},
        "layer1": {"fixed": {"validation_hops": "single_hop", "interlayers": []}, "algorithms": {}},
        "output": {
            "directory": "runtime/test",
            "target_site_root": str(site_root),
            "frozen_config": "step0_frozen_config.yaml",
            "step0_gate_report": "step0_gate_report.json",
            "layer1_pool_yaml": "layer1_pool.yaml",
            "layer1_pool_json": "layer1_pool.json",
            "layer1_gate_report": "layer1_gate_report.json",
            "layer1_pruned_reasons": "layer1_pruned_reasons.jsonl",
        },
        "writer": {
            "layer1": {
                "sample_size_per_algorithm": 1,
                "sample_pool_yaml": "layer1_sample_pool.yaml",
                "sample_gate_report": "layer1_sample_gate_report.json",
                "sample_manifest": "layer1_sample_write_manifest.json",
                "full_manifest": "layer1_full_write_manifest.json",
                "api_name_prefix": "layer1",
                "generated_page_php": "generated_layer1_sample.php",
                "generated_js_file": "generated_layer1_sample.js",
                "templates": {"php": "easy.php", "js": "js/easy.js"},
                "defaults": {
                    "username": "test_user",
                    "password": "test_pass",
                    "success_username": "admin",
                    "success_password": "123456",
                },
            }
        },
    }

    cfg_path = tmp_path / "cfg.yaml"
    _write_yaml(cfg_path, cfg)

    manifest = run_layer1_write_sample(cfg_path, output_dir=out_root)

    assert manifest["sample_count"] == 2
    assert (out_root / "layer1_sample_pool.yaml").exists()
    assert (out_root / "layer1_sample_gate_report.json").exists()
    assert (out_root / "layer1_sample_write_manifest.json").exists()

    assert (site_root / "generated_layer1_sample.php").exists()
    assert (site_root / "js" / "generated_layer1_sample.js").exists()
    assert (site_root / "encrypt" / "generated").exists()

    with open(out_root / "layer1_sample_write_manifest.json", "r", encoding="utf-8") as handle:
        saved = json.load(handle)
    assert saved["sample_count"] == 2

