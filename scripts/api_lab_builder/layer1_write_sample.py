#!/usr/bin/env python3
"""Layer1 抽样写入：把样本池转写为可运行的 PHP/JS 代码。"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE_DIR))

from scripts.api_lab_builder.common import dump_json, dump_yaml, load_yaml


def _algo_slug(algorithm: str) -> str:
    mapping = {
        "AES_CBC": "aes",
        "RSA_ONLY": "rsa",
        "PLAINTEXT_HMAC": "hmac",
        "DES_CBC": "des",
        "AES_RSA_ENVELOPE": "aesrsa",
    }
    return mapping.get(algorithm, algorithm.lower())


def _group_by_algorithm(specs: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for spec in specs:
        algo = str(spec.get("algorithm_stack", "UNKNOWN"))
        grouped.setdefault(algo, []).append(spec)
    return grouped


def _derive_materials(spec: dict[str, Any]) -> dict[str, Any]:
    algo = str(spec.get("algorithm_stack", ""))
    anti_replay = str(spec.get("anti_replay", "none"))
    template_level = str(spec.get("template_level", "BASELINE"))
    params = spec.get("algo_params", {}) if isinstance(spec.get("algo_params"), dict) else {}

    key_size = int(params.get("key_size", 128))
    key_len = 16 if key_size <= 128 else 24 if key_size <= 192 else 32
    base_key = ("k" * key_len)
    base_iv = ("i" * 16)

    # 业务上用于 JS 派生的表达式片段
    materials: dict[str, Any] = {
        "algorithm": algo,
        "template_level": template_level,
        "key": base_key,
        "iv": base_iv,
        "nonce": None,
        "timestamp": None,
        "signature": None,
    }

    if anti_replay in {"timestamp_only", "nonce_timestamp", "nonce_timestamp_signature", "nonce_timestamp_signature_session_binding"}:
        materials["timestamp"] = "Math.floor(Date.now()/1000)"
    if anti_replay in {"nonce_only", "nonce_timestamp", "nonce_timestamp_signature", "nonce_timestamp_signature_session_binding"}:
        materials["nonce"] = "Math.random().toString(36).slice(2, 12)"
    if anti_replay in {"nonce_timestamp_signature", "nonce_timestamp_signature_session_binding"} or algo == "PLAINTEXT_HMAC":
        materials["signature"] = "sha256(username + password + (nonce || '') + (timestamp || ''))"

    return materials


def _js_sha256_helper() -> str:
    return (
        "function sha256(input) {\n"
        "  if (window.CryptoJS && CryptoJS.SHA256) {\n"
        "    return CryptoJS.SHA256(input).toString(CryptoJS.enc.Hex);\n"
        "  }\n"
        "  return input;\n"
        "}\n"
    )


def _render_js_function(spec: dict[str, Any], endpoint: str, api_name: str, defaults: dict[str, Any]) -> str:
    materials = _derive_materials(spec)
    algo = str(spec.get("algorithm_stack", ""))

    lines = [
        f"async function {api_name}() {{",
        "  const username = document.getElementById('username')?.value || '" + str(defaults.get("username", "test_user")) + "';",
        "  const password = document.getElementById('password')?.value || '" + str(defaults.get("password", "test_pass")) + "';",
        "  let nonce = null;",
        "  let timestamp = null;",
        "  let signature = null;",
    ]

    if materials.get("nonce"):
        lines.append(f"  nonce = {materials['nonce']};")
    if materials.get("timestamp"):
        lines.append(f"  timestamp = {materials['timestamp']};")
    if materials.get("signature"):
        lines.append("  signature = " + materials["signature"] + ";")

    lines.extend(
        [
            "  const payload = {",
            "    username,",
            "    password,",
            f"    algorithm_stack: '{algo}',",
            f"    anti_replay: '{spec.get('anti_replay', 'none')}',",
            f"    template_level: '{spec.get('template_level', 'BASELINE')}',",
            "    nonce,",
            "    timestamp,",
            "    signature",
            "  };",
            "",
            "  const resp = await fetch('" + endpoint + "', {",
            "    method: 'POST',",
            "    headers: { 'Content-Type': 'application/json; charset=utf-8' },",
            "    body: JSON.stringify(payload)",
            "  });",
            "  const data = await resp.json();",
            "  if (data.success) {",
            "    alert('登录成功');",
            "  } else {",
            "    alert(data.error || '用户名或密码错误');",
            "  }",
            "}",
            "",
        ]
    )

    return "\n".join(lines)


def _render_php_endpoint(api_name: str, defaults: dict[str, Any]) -> str:
    ok_user = str(defaults.get("success_username", "admin"))
    ok_pass = str(defaults.get("success_password", "123456"))
    return (
        "<?php\n"
        "header('Content-Type: application/json; charset=utf-8');\n"
        "$raw = file_get_contents('php://input');\n"
        "$data = json_decode($raw, true);\n"
        "if (!is_array($data)) {\n"
        "  echo json_encode(['success' => false, 'error' => 'invalid json']);\n"
        "  exit;\n"
        "}\n"
        "$username = isset($data['username']) ? (string)$data['username'] : '';\n"
        "$password = isset($data['password']) ? (string)$data['password'] : '';\n"
        "$ok = ($username === '" + ok_user + "' && $password === '" + ok_pass + "');\n"
        "if ($ok) {\n"
        "  echo json_encode(['success' => true, 'api' => '" + api_name + "']);\n"
        "} else {\n"
        "  echo json_encode(['success' => false, 'error' => 'invalid credentials', 'api' => '" + api_name + "']);\n"
        "}\n"
        "?>\n"
    )


def _inject_buttons_into_page(page_html: str, buttons_html: str, generated_js_rel: str) -> str:
    block = (
        "\n<!-- auto-generated layer1 buttons -->\n"
        "<div id=\"generated-layer1-buttons\" style=\"margin:16px auto;max-width:780px;text-align:center;\">\n"
        "  <h3>Layer1 Generated APIs (Sample)</h3>\n"
        f"  {buttons_html}\n"
        "</div>\n"
        f"<script src=\"{generated_js_rel}\"></script>\n"
    )

    # 优先插入到 </body> 前
    if "</body>" in page_html:
        return page_html.replace("</body>", block + "</body>", 1)
    return page_html + block


def run_layer1_write_sample(config_path: Path, sample_size_override: int | None = None, output_dir: Path | None = None) -> dict[str, Any]:
    cfg = load_yaml(config_path)
    out_cfg = cfg["output"]
    writer_cfg = cfg.get("writer", {}).get("layer1", {})

    if not writer_cfg:
        raise ValueError("配置缺少 writer.layer1")

    out_root = output_dir or (BASE_DIR / out_cfg["directory"])
    target_root = Path(out_cfg["target_site_root"])
    sample_size = int(sample_size_override or writer_cfg.get("sample_size_per_algorithm", 5))

    layer1_pool_path = out_root / out_cfg["layer1_pool_yaml"]
    specs = load_yaml(layer1_pool_path)
    if not isinstance(specs, list):
        raise ValueError("layer1_pool 不是列表")

    grouped = _group_by_algorithm(specs)
    sampled: list[dict[str, Any]] = []
    for algo in ["AES_CBC", "RSA_ONLY", "PLAINTEXT_HMAC", "DES_CBC", "AES_RSA_ENVELOPE"]:
        rows = grouped.get(algo, [])
        sampled.extend(rows[:sample_size])

    out_root.mkdir(parents=True, exist_ok=True)
    dump_yaml(out_root / writer_cfg["sample_pool_yaml"], sampled)

    php_template_path = target_root / writer_cfg["templates"]["php"]
    js_template_path = target_root / writer_cfg["templates"]["js"]

    php_template = php_template_path.read_text(encoding="utf-8")
    js_template = js_template_path.read_text(encoding="utf-8")

    php_generated_dir = target_root / "encrypt" / "generated"
    php_generated_dir.mkdir(parents=True, exist_ok=True)

    js_generated_rel = "js/" + writer_cfg["generated_js_file"]
    js_generated_path = target_root / js_generated_rel
    js_generated_path.parent.mkdir(parents=True, exist_ok=True)

    defaults = writer_cfg.get("defaults", {})
    prefix = str(writer_cfg.get("api_name_prefix", "layer1"))

    js_funcs = ["// auto-generated layer1 sample functions", _js_sha256_helper()]
    buttons = []
    endpoints = []

    counters: dict[str, int] = {}
    for spec in sampled:
        algo = str(spec.get("algorithm_stack", "unknown"))
        slug = _algo_slug(algo)
        counters[slug] = counters.get(slug, 0) + 1
        api_name = f"{prefix}_{slug}_{counters[slug]:04d}"
        endpoint_rel = f"encrypt/generated/{api_name}.php"

        php_code = _render_php_endpoint(api_name, defaults)
        (php_generated_dir / f"{api_name}.php").write_text(php_code, encoding="utf-8", newline="\n")

        js_funcs.append(_render_js_function(spec, endpoint_rel, api_name, defaults))
        buttons.append(f"<button onclick=\"{api_name}()\">{api_name}</button>")
        endpoints.append(endpoint_rel)

    js_generated_path.write_text(js_template + "\n\n" + "\n".join(js_funcs) + "\n", encoding="utf-8", newline="\n")

    generated_page_path = target_root / str(writer_cfg["generated_page_php"])
    page_html = _inject_buttons_into_page(php_template, "\n  ".join(buttons), js_generated_rel)
    generated_page_path.write_text(page_html, encoding="utf-8", newline="\n")

    manifest = {
        "sample_count": len(sampled),
        "sample_size_per_algorithm": sample_size,
        "generated_page": str(generated_page_path),
        "generated_js": str(js_generated_path),
        "generated_endpoints": [str(php_generated_dir / Path(ep).name) for ep in endpoints],
        "defaults": defaults,
    }

    dump_json(out_root / writer_cfg["sample_manifest"], manifest)
    dump_json(
        out_root / writer_cfg["sample_gate_report"],
        {
            "layer": "Layer1",
            "sample_ready": len(sampled) > 0,
            "sample_count": len(sampled),
            "target_root": str(target_root),
        },
    )

    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Layer1 抽样写入目标站点")
    parser.add_argument("--config", default="configs/api_lab_builder_step0.yaml")
    parser.add_argument("--sample-size", type=int, default=0)
    parser.add_argument("--output-dir", default="")
    args = parser.parse_args()

    config_path = BASE_DIR / args.config
    out_dir = (BASE_DIR / args.output_dir) if args.output_dir else None
    sample_size = args.sample_size if args.sample_size > 0 else None
    manifest = run_layer1_write_sample(config_path, sample_size, out_dir)

    print("[Layer1-Write-Sample] 完成")
    print(json.dumps(manifest, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

