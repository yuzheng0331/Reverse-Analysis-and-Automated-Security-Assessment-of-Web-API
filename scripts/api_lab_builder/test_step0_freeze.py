from __future__ import annotations

from pathlib import Path

from scripts.api_lab_builder.step0_freeze import run_step0_freeze


def test_step0_freeze_validates_and_writes_outputs(tmp_path: Path) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        """
global:
  fixed_site_group: SITE_A
  allowed_route_variants: [PLAIN_ROUTE, WEAK_OBF_ROUTE]
  algorithm_whitelist: [AES_CBC, RSA_ONLY, PLAINTEXT_HMAC]
constraints:
  max_interlayers: 5
layer1:
  algorithms:
    AES_CBC:
      base: {material_source: FRONTEND_HARDCODED}
      matrix: {key_size: [128], anti_replay: [none]}
layer2:
  source_pool: layer1_pool.yaml
  dimensions:
    material_source: [FRONTEND_HARDCODED]
    material_dynamicity_profile: [STATIC_LOCAL]
    packaging_type: [urlencoded]
    field_policy: [normal]
    content_type: [application/x-www-form-urlencoded]
    key_location: [body]
  profile_map:
    STATIC_LOCAL:
      key: static
      iv: static
      nonce: absent
      timestamp: absent
      signature: absent
  coverage:
    strength: 3
    max_selected_per_base: 6
layer3:
  source_pool: layer2_pool.yaml
  templates:
    - name: BASELINE_NO_SHIFT
      template_level: BASELINE
      risk_tags: []
    - name: WEAK_SHIFT_L1
      template_level: L1
      risk_tags: [WEAK_SHIFT_L1]
  constraints:
    max_risk_tags: 5
  coverage:
    strategy: onewise_risk_injection
    max_selected_per_base: 2
field_rules:
  algo_params:
    iv_policy: [absent, static, random, derived, server_fetch]
  material_source:
    values: [FRONTEND_HARDCODED, FRONTEND_DERIVED, SERVER_INTERMEDIATE_FETCH]
  dependency_constraints:
    - if: {material_dynamicity_profile: STATIC_LOCAL}
      then:
        material_source: [FRONTEND_HARDCODED]
        algo_params.iv_policy: [static]
layer_blueprint:
  layer1:
    active_dimensions: [2.1]
    active_fields: [algorithm_stack]
    frozen_defaults: {validation_hops: single_hop}
  layer2:
    active_dimensions: [2.3]
    active_fields: [material_source, material_dynamicity_profile]
    frozen_defaults: {validation_hops: single_hop}
output:
  directory: runtime/test
  frozen_config: frozen.yaml
  step0_gate_report: gate.json
  layer1_pool_yaml: layer1_pool.yaml
  layer1_gate_report: layer1_gate.json
  layer2_pool_yaml: layer2_pool.yaml
  layer2_gate_report: layer2_gate.json
  layer3_pool_yaml: layer3_pool.yaml
  layer3_pool_json: layer3_pool.json
  layer3_gate_report: layer3_gate.json
  layer3_pruned_reasons: layer3_pruned.jsonl
  layer3_control_mapping: layer3_control_mapping.json
""".strip(),
        encoding="utf-8",
    )

    out_dir = tmp_path / "out"
    report = run_step0_freeze(cfg, out_dir)

    assert report["valid"] is True
    assert (out_dir / "frozen.yaml").exists()
    assert (out_dir / "gate.json").exists()


