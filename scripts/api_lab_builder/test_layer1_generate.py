from __future__ import annotations

import json
from pathlib import Path

import yaml

from scripts.api_lab_builder.layer1_generate import run_layer1_generate


def _write_yaml(path: Path, data) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, allow_unicode=True, sort_keys=False)


def test_layer1_generate_outputs_pool_and_reports(tmp_path: Path) -> None:
    cfg = {
        "global": {
            "fixed_site_group": "SITE_A",
            "allowed_route_variants": ["PLAIN_ROUTE", "WEAK_OBF_ROUTE"],
            "algorithm_whitelist": ["AES_CBC", "RSA_ONLY", "PLAINTEXT_HMAC"],
        },
        "constraints": {"max_interlayers": 5, "unsupported_markers": []},
        "layer1": {
            "fixed": {"validation_hops": "single_hop", "interlayers": []},
            "algorithms": {
                "AES_CBC": {
                    "base": {
                        "material_source": "FRONTEND_HARDCODED",
                        "material_dynamicity": {
                            "key": "static",
                            "iv": "static",
                            "nonce": "absent",
                            "timestamp": "absent",
                            "signature": "absent",
                        },
                        "risk_tags": ["BASELINE_STABLE"],
                        "template_level": "BASELINE",
                    },
                    "matrix": {
                        "key_size": [128],
                        "mode": ["CBC"],
                        "iv_policy": ["static"],
                        "padding": ["Pkcs7"],
                        "plaintext_encoding": ["utf8"],
                        "key_encoding": ["utf8"],
                        "iv_encoding": ["utf8"],
                        "anti_replay": ["none"],
                    },
                }
            },
        },
        "output": {
            "directory": "runtime/test",
            "frozen_config": "step0_frozen_config.yaml",
            "step0_gate_report": "step0_gate_report.json",
            "layer1_pool_yaml": "layer1_pool.yaml",
            "layer1_pool_json": "layer1_pool.json",
            "layer1_gate_report": "layer1_gate_report.json",
            "layer1_pruned_reasons": "layer1_pruned_reasons.jsonl",
        },
    }

    cfg_path = tmp_path / "cfg.yaml"
    _write_yaml(cfg_path, cfg)

    out_dir = tmp_path / "out"
    report = run_layer1_generate(cfg_path, out_dir)

    assert report["counts"]["selected"] > 0
    assert (out_dir / "layer1_pool.yaml").exists()
    assert (out_dir / "layer1_pool.json").exists()
    assert (out_dir / "layer1_gate_report.json").exists()

    with open(out_dir / "layer1_pool.json", "r", encoding="utf-8") as handle:
        rows = json.load(handle)
    assert all(r["site_group"] == "SITE_A" for r in rows)
    assert set(r["route_variant"] for r in rows) == {"PLAIN_ROUTE"}

