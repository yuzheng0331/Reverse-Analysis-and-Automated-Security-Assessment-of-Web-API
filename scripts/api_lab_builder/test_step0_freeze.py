from __future__ import annotations

from pathlib import Path

from scripts.api_lab_builder.step0_freeze import run_step0_freeze


def test_step0_freeze_validates_and_writes_outputs(tmp_path: Path) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        """
+global:
+  fixed_site_group: SITE_A
+  allowed_route_variants: [PLAIN_ROUTE, WEAK_OBF_ROUTE]
+  algorithm_whitelist: [AES_CBC, RSA_ONLY, PLAINTEXT_HMAC]
+constraints:
+  max_interlayers: 5
+layer1:
+  algorithms:
+    AES_CBC:
+      base: {material_source: FRONTEND_HARDCODED}
+      matrix: {key_size: [128], anti_replay: [none]}
+output:
+  directory: runtime/test
+  frozen_config: frozen.yaml
+  step0_gate_report: gate.json
+  layer1_pool_yaml: layer1_pool.yaml
+  layer1_gate_report: layer1_gate.json
+""".strip(),
+        encoding="utf-8",
+    )
+
+    out_dir = tmp_path / "out"
+    report = run_step0_freeze(cfg, out_dir)
+
+    assert report["valid"] is True
+    assert (out_dir / "frozen.yaml").exists()
+    assert (out_dir / "gate.json").exists()

