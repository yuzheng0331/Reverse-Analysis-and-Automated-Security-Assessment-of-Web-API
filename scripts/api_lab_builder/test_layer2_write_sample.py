from __future__ import annotations

import json
from pathlib import Path

import yaml

from scripts.api_lab_builder.layer2_write_sample import run_layer2_write_sample


def _write_yaml(path: Path, data) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, allow_unicode=True, sort_keys=False)


def test_layer2_write_sample_writes_parallel_targets(tmp_path: Path) -> None:
    site_root = tmp_path / "site"
    (site_root / "js").mkdir(parents=True)
    (site_root / "encrypt").mkdir(parents=True)
    (site_root / "easy.php").write_text("<html><body><div>base</div></body></html>", encoding="utf-8")
    (site_root / "js" / "easy.js").write_text("function closeModal(){}", encoding="utf-8")

    out_root = tmp_path / "out"
    out_root.mkdir(parents=True)

    layer2_pool = [
        {
            "id": "layer2_00001",
            "source_layer1_id": "layer1_00001",
            "algorithm_stack": "AES",
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
            "packaging": {"type": "urlencoded", "field_policy": "normal"},
            "transport": {"content_type": "application/x-www-form-urlencoded", "key_location": "body"},
        }
    ]
    _write_yaml(out_root / "layer2_pool.yaml", layer2_pool)

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
            "dimensions": {},
            "profile_map": {},
            "coverage": {"strength": 3, "max_selected_per_base": 6},
        },
        "output": {
            "directory": "runtime/test",
            "target_site_root": str(site_root),
            "frozen_config": "step0_frozen_config.yaml",
            "step0_gate_report": "step0_gate_report.json",
            "layer1_pool_yaml": "layer1_pool.yaml",
            "layer1_gate_report": "layer1_gate_report.json",
            "layer2_pool_yaml": "layer2_pool.yaml",
            "layer2_pool_json": "layer2_pool.json",
            "layer2_gate_report": "layer2_gate_report.json",
            "layer2_pruned_reasons": "layer2_pruned_reasons.jsonl",
        },
        "writer": {
            "layer2": {
                "sample_size_per_algorithm": 3,
                "sample_pool_yaml": "layer2_sample_pool.yaml",
                "sample_gate_report": "layer2_sample_gate_report.json",
                "sample_manifest": "layer2_sample_write_manifest.json",
                "full_manifest": "layer2_full_write_manifest.json",
                "api_name_prefix": "layer2",
                "generated_page_php": "generated_layer2_sample.php",
                "generated_js_file": "generated_layer2_sample.js",
                "templates": {"php": "easy.php", "js": "js/easy.js"},
                "defaults": {"username": "test_user", "password": "test_pass"},
            }
        },
    }

    cfg_path = tmp_path / "cfg.yaml"
    _write_yaml(cfg_path, cfg)

    manifest = run_layer2_write_sample(cfg_path, output_dir=out_root)

    assert manifest["sample_count"] == 1
    assert (site_root / "generated_layer2_sample.php").exists()
    assert (site_root / "js" / "generated_layer2_sample.js").exists()

    php_files = list((site_root / "encrypt" / "generated").glob("layer2_*.php"))
    assert len(php_files) == 1

    with open(out_root / "layer2_sample_write_manifest.json", "r", encoding="utf-8") as handle:
        saved = json.load(handle)
    assert saved["sample_count"] == 1


def test_layer2_write_sample_keeps_control_row(tmp_path: Path) -> None:
    site_root = tmp_path / "site"
    (site_root / "js").mkdir(parents=True)
    (site_root / "encrypt").mkdir(parents=True)
    (site_root / "easy.php").write_text("<html><body><div>base</div></body></html>", encoding="utf-8")
    (site_root / "js" / "easy.js").write_text("function closeModal(){}", encoding="utf-8")

    out_root = tmp_path / "out"
    out_root.mkdir(parents=True)

    layer2_pool = [
        {
            "id": "layer2_00001",
            "algorithm_stack": "AES",
            "algo_params": {"key_size": 128, "iv_policy": "static", "padding": "Pkcs7", "mode": "CBC", "plaintext_encoding": "base64-pre-encoded"},
            "material_source": "FRONTEND_HARDCODED",
            "material_dynamicity": {"key": "static", "iv": "static", "nonce": "absent", "timestamp": "absent", "signature": "absent"},
            "validation_hops": "single_hop",
            "anti_replay": "none",
            "interlayers": ["ENCODING_LAYER", "HEADER_SIGN_LAYER"],
            "risk_tags": ["BASELINE_STABLE"],
            "route_variant": "PLAIN_ROUTE",
            "site_group": "SITE_A",
            "template_level": "BASELINE",
            "packaging": {"type": "urlencoded", "field_policy": "normal"},
            "transport": {"content_type": "application/x-www-form-urlencoded", "key_location": "body"},
        },
        {
            "id": "layer2_00002",
            "algorithm_stack": "AES",
            "algo_params": {"key_size": 128, "iv_policy": "static", "padding": "Pkcs7", "mode": "CBC", "plaintext_encoding": "utf8"},
            "material_source": "FRONTEND_HARDCODED",
            "material_dynamicity": {"key": "static", "iv": "static", "nonce": "absent", "timestamp": "absent", "signature": "absent"},
            "validation_hops": "single_hop",
            "anti_replay": "none",
            "interlayers": [],
            "risk_tags": ["BASELINE_STABLE"],
            "route_variant": "PLAIN_ROUTE",
            "site_group": "SITE_A",
            "template_level": "BASELINE",
            "packaging": {"type": "urlencoded", "field_policy": "normal"},
            "transport": {"content_type": "application/x-www-form-urlencoded", "key_location": "body"},
        },
    ]
    _write_yaml(out_root / "layer2_pool.yaml", layer2_pool)

    cfg = {
        "global": {
            "fixed_site_group": "SITE_A",
            "allowed_route_variants": ["PLAIN_ROUTE", "WEAK_OBF_ROUTE"],
            "algorithm_whitelist": ["AES", "DES", "RSA_ONLY", "AES_RSA_ENVELOPE", "PLAINTEXT_HMAC"],
        },
        "constraints": {"max_interlayers": 5, "unsupported_markers": []},
        "layer1": {"fixed": {"validation_hops": "single_hop", "interlayers": []}, "algorithms": {}},
        "layer2": {"source_pool": "layer1_pool.yaml", "dimensions": {}, "profile_map": {}, "coverage": {"strength": 3, "max_selected_per_base": 6}},
        "output": {
            "directory": "runtime/test",
            "target_site_root": str(site_root),
            "frozen_config": "step0_frozen_config.yaml",
            "step0_gate_report": "step0_gate_report.json",
            "layer1_pool_yaml": "layer1_pool.yaml",
            "layer1_gate_report": "layer1_gate_report.json",
            "layer2_pool_yaml": "layer2_pool.yaml",
            "layer2_pool_json": "layer2_pool.json",
            "layer2_gate_report": "layer2_gate_report.json",
            "layer2_pruned_reasons": "layer2_pruned_reasons.jsonl",
        },
        "writer": {
            "layer2": {
                "sample_size_per_algorithm": 2,
                "sample_pool_yaml": "layer2_sample_pool.yaml",
                "sample_gate_report": "layer2_sample_gate_report.json",
                "sample_manifest": "layer2_sample_write_manifest.json",
                "full_manifest": "layer2_full_write_manifest.json",
                "api_name_prefix": "layer2",
                "generated_page_php": "generated_layer2_sample.php",
                "generated_js_file": "generated_layer2_sample.js",
                "templates": {"php": "easy.php", "js": "js/easy.js"},
                "defaults": {"username": "test_user", "password": "test_pass"},
            }
        },
    }

    cfg_path = tmp_path / "cfg.yaml"
    _write_yaml(cfg_path, cfg)

    manifest = run_layer2_write_sample(cfg_path, output_dir=out_root)
    assert manifest["sample_count"] == 2

    sampled = yaml.safe_load((out_root / "layer2_sample_pool.yaml").read_text(encoding="utf-8"))
    assert any((row.get("interlayers") or []) == [] for row in sampled)
    assert any("ENCODING_LAYER" in (row.get("interlayers") or []) for row in sampled)

