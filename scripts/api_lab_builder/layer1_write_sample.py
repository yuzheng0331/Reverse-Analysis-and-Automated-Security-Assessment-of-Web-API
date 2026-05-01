#!/usr/bin/env python3
"""Layer1 抽样写入：把样本池转写为前端加密链路等价的 PHP/JS 代码。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE_DIR))

from scripts.api_lab_builder.common import dump_json, dump_yaml, load_yaml

PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRvA7giwinEkaTYllDYCkzujvi
NH+up0XAKXQot8RixKGpB7nr8AdidEvuo+wVCxZwDK3hlcRGrrqt0Gxqwc11btlM
DSj92Mr3xSaJcshZU8kfj325L8DRh9jpruphHBfh955ihvbednGAvOHOrz3Qy3Cb
ocDbsNeCwNpRxwjIdQIDAQAB
-----END PUBLIC KEY-----"""

PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDRvA7giwinEkaTYllDYCkzujviNH+up0XAKXQot8RixKGpB7nr
8AdidEvuo+wVCxZwDK3hlcRGrrqt0Gxqwc11btlMDSj92Mr3xSaJcshZU8kfj325
L8DRh9jpruphHBfh955ihvbednGAvOHOrz3Qy3CbocDbsNeCwNpRxwjIdQIDAQAB
AoGAMek68RylFn025mQFMg90PqcXESHFMN8FrlEvH3F7/rUkc4EvMYKRf1CFsWi5
Cdj1ofyidIibiOaT7kEnS9CK//SmY+1628/eyngOvOR9ADsHN/JRlJ3dHathcBrr
1GENlCB9EmN+Fzhh7vEC2RUPrkkHCYGU2j+9rkzHUCXxLpECQQD5jgm9K7bvsOzM
82v6avdNFAV/9ILdple1xlCfcEuWgnRztxTS6fbVguDCkB95yQq/WT2XzuohUMSG
0uGGemlbAkEA1ya+aG8bRNlEC4yGiROSWZOiFBtiUhMyDGQ4E/FUifNdZSft5jSE
gqUZZYJNchyKSXWtFKyclvJjcnflKxBubwJAT7eexs4bDvA+hK3RtVnMC9Q0eY5a
64ECja9++598leSwXHKEdWeFkOjQ8XXmiBm/lCZmtYLEacYKMWNV5YZe9wJAMYM/
CnWXRu7hE+9Q/ra8VVT+VbY/mDfGqsddiGlfVSfmdGMOAo5PeGlaQNwNypb61BD6
telLWAmMDUm+OXzcjQJBAJGn+vI0JV7OI0m4QpSucn/rJ9pAYJG4HE/MOQcgHog0
AeussmDIlr+wqWr+iJxYfJHc8ikTRSeTgqavruZs2Hg=
-----END RSA PRIVATE KEY-----"""


def _algo_slug(algorithm: str) -> str:
    mapping = {
        "AES": "aes",
        "AES_CBC": "aes",
        "RSA_ONLY": "rsa",
        "PLAINTEXT_HMAC": "hmac",
        "DES": "des",
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


def _require_keys(obj: dict[str, Any], required: list[str], where: str) -> None:
    missing = [key for key in required if key not in obj]
    if missing:
        raise ValueError(f"{where} 缺少字段: {', '.join(missing)}")


def _validate_spec(spec: Any, index: int) -> dict[str, Any]:
    if not isinstance(spec, dict):
        raise ValueError(f"layer1_pool[{index}] 不是对象")
    _require_keys(spec, ["algorithm_stack"], f"layer1_pool[{index}]")
    algo = spec.get("algorithm_stack")
    if not isinstance(algo, str) or not algo.strip():
        raise ValueError(f"layer1_pool[{index}].algorithm_stack 非法")
    params = spec.get("algo_params")
    if params is not None and not isinstance(params, dict):
        raise ValueError(f"layer1_pool[{index}].algo_params 必须为对象")
    return spec


def _aes_key_len(key_size: int) -> int:
    if key_size <= 128:
        return 16
    if key_size <= 192:
        return 24
    return 32


def _seed(text: str, n: int) -> str:
    return (text * ((n // len(text)) + 1))[:n]


def _normalize_material_literal(raw_value: str, encoding: str, byte_len: int) -> str:
    text = str(raw_value or "")
    if byte_len <= 0:
        return text
    if encoding == "hex":
        cleaned = "".join(ch for ch in text if ch.lower() in "0123456789abcdef")
        if len(cleaned) >= 2:
            return _seed(cleaned, byte_len * 2)
        derived = text.encode("utf-8").hex() or "ab"
        return _seed(derived, byte_len * 2)
    return _seed(text or "X", byte_len)


def _profile(spec: dict[str, Any]) -> dict[str, Any]:
    params = spec.get("algo_params", {}) if isinstance(spec.get("algo_params"), dict) else {}
    algo = str(spec.get("algorithm_stack", ""))
    key_size = int(params.get("key_size", 128))
    if algo in {"DES", "DES_CBC"}:
        key_len = 8
    else:
        key_len = _aes_key_len(key_size)
    iv_hex_len = 16 if algo in {"DES", "DES_CBC"} else 32
    iv_utf8_len = 8 if algo in {"DES", "DES_CBC"} else 16
    weak_args = spec.get("weak_runtime_args") if isinstance(spec.get("weak_runtime_args"), dict) else {}
    weak_setkey = weak_args.get("setkey") if isinstance(weak_args.get("setkey"), dict) else {}
    weak_setiv = weak_args.get("setiv") if isinstance(weak_args.get("setiv"), dict) else {}
    weak_key_raw = str(weak_setkey.get("key") or "").strip()
    weak_iv_raw = str(weak_setiv.get("iv") or "").strip()

    key_encoding = str(params.get("key_encoding", "utf8"))
    iv_encoding = str(params.get("iv_encoding", "utf8"))
    key_utf8 = _seed("K", key_len)
    key_hex = _seed("ab", key_len * 2)
    if weak_key_raw:
        if key_encoding == "hex":
            key_hex = _normalize_material_literal(weak_key_raw, "hex", key_len)
        else:
            key_utf8 = _normalize_material_literal(weak_key_raw, "utf8", key_len)

    iv_utf8 = _seed("I", iv_utf8_len)
    iv_hex = _seed("cd", iv_hex_len)
    if weak_iv_raw:
        if iv_encoding == "hex":
            iv_hex = _normalize_material_literal(weak_iv_raw, "hex", iv_utf8_len)
        else:
            iv_utf8 = _normalize_material_literal(weak_iv_raw, "utf8", iv_utf8_len)

    iv_policy = str(params.get("iv_policy", "static"))
    if weak_iv_raw:
        iv_policy = "static"

    return {
        "algo": str(spec.get("algorithm_stack", "")),
        "anti_replay": str(spec.get("anti_replay", "none")),
        "key_size": key_size,
        "key_encoding": key_encoding,
        "iv_encoding": iv_encoding,
        "iv_policy": iv_policy,
        "padding": str(params.get("padding", "Pkcs7")),
        "signature_placement": str(spec.get("signature_strategy", {}).get("placement", "body")),
        "session_binding": str(spec.get("session_policy", {}).get("binding", "bind_cookie")),
        "key_utf8": key_utf8,
        "iv_utf8": iv_utf8,
        "key_hex": key_hex,
        "iv_hex": iv_hex,
        "has_weak_setkey": bool(weak_key_raw),
        "has_weak_setiv": bool(weak_iv_raw),
        "hmac_secret": "be56e057f20f883e",
    }


def _weak_option_slug(spec: dict[str, Any]) -> str:
    option = str(spec.get("layer3_weak_option") or "").strip().upper()
    if not option:
        return ""
    return option.lower()


def _js_helpers() -> str:
    return (
        "function __gen_parse_material(rawValue, encoding) {\n"
        "  if (encoding === 'hex') return CryptoJS.enc.Hex.parse(rawValue);\n"
        "  if (encoding === 'base64') return CryptoJS.enc.Base64.parse(rawValue);\n"
        "  return CryptoJS.enc.Utf8.parse(rawValue);\n"
        "}\n\n"
        "function __gen_nonce() {\n"
        "  return Math.random().toString(36).slice(2, 12);\n"
        "}\n"
    )


def _js_head(api_name: str, defaults: dict[str, Any]) -> list[str]:
    return [
        f"async function {api_name}() {{",
        "  const username = document.getElementById('username')?.value || '" + str(defaults.get("username", "test_user")) + "';",
        "  const password = document.getElementById('password')?.value || '" + str(defaults.get("password", "test_pass")) + "';",
        "  let nonce = null;",
        "  let timestamp = null;",
        "",
    ]


def _js_replay(anti_replay: str) -> list[str]:
    rows: list[str] = []
    nonce_required = {
        "nonce_only",
        "nonce_timestamp",
        "nonce_timestamp_signature",
        "nonce_timestamp_signature_session_binding",
    }
    timestamp_required = {
        "timestamp_only",
        "nonce_timestamp",
        "nonce_timestamp_signature",
        "nonce_timestamp_signature_session_binding",
    }
    if anti_replay in nonce_required:
        rows.append("  nonce = __gen_nonce();")
    if anti_replay in timestamp_required:
        rows.append("  timestamp = Math.floor(Date.now() / 1000);")
    if rows:
        rows.append("")
    return rows


def _render_js_aes(spec: dict[str, Any], endpoint: str, api_name: str, defaults: dict[str, Any]) -> str:
    p = _profile(spec)
    rows = _js_head(api_name, defaults)
    rows.extend(
        [
            "  const formData = { username: username, password: password };",
            "  const jsonData = JSON.stringify(formData);",
            f"  const key = __gen_parse_material('{p['key_hex'] if p['key_encoding'] == 'hex' else p['key_utf8']}', '{p['key_encoding']}');",
            "  let iv = null;",
        ]
    )
    if p["iv_policy"] == "random":
        rows.append("  iv = CryptoJS.lib.WordArray.random(16);")
    elif p["iv_policy"] == "derived":
        rows.extend(
            [
                "  const ivRaw = CryptoJS.SHA256(username).toString(CryptoJS.enc.Hex).slice(0, 32);",
                "  iv = __gen_parse_material(ivRaw, 'hex');",
            ]
        )
    else:
        iv_val = p["iv_hex"] if p["iv_encoding"] == "hex" else p["iv_utf8"]
        rows.append(f"  iv = __gen_parse_material('{iv_val}', '{p['iv_encoding']}');")

    rows.extend(
        [
            "  const encryptedData = CryptoJS.AES.encrypt(jsonData, key, {",
            "    iv: iv,",
            "    mode: CryptoJS.mode.CBC,",
            f"    padding: CryptoJS.pad.{p['padding']}",
            "  }).toString();",
            "",
            "  const requestPayload = { encryptedData: encryptedData };",
        ]
    )
    if p["iv_policy"] != "static":
        rows.append("  requestPayload.iv = iv.toString(CryptoJS.enc.Base64);")

    rows.extend(_js_replay(p["anti_replay"]))
    rows.extend(
        [
            "  if (nonce) requestPayload.nonce = nonce;",
            "  if (timestamp) requestPayload.timestamp = timestamp;",
            "",
            "  const params = new URLSearchParams(requestPayload);",
            f"  const response = await fetch('{endpoint}', {{",
            "    method: 'POST',",
            "    headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' },",
            "    body: params.toString()",
            "  });",
            "  const data = await response.json();",
            "  if (data.success) alert('登录成功'); else alert(data.error || '用户名或密码错误');",
            "}",
            "",
        ]
    )
    return "\n".join(rows)


def _render_js_des(spec: dict[str, Any], endpoint: str, api_name: str, defaults: dict[str, Any]) -> str:
    p = _profile(spec)
    rows = _js_head(api_name, defaults)
    rows.extend(
        [
            "  const formData = { username: username, password: password };",
            "  const jsonData = JSON.stringify(formData);",
            f"  const key = __gen_parse_material('{p['key_hex'] if p['key_encoding'] == 'hex' else p['key_utf8']}', '{p['key_encoding']}');",
            "  let iv = null;",
        ]
    )
    iv_val = p["iv_hex"] if p["iv_encoding"] == "hex" else p["iv_utf8"]
    rows.append(f"  iv = __gen_parse_material('{iv_val}', '{p['iv_encoding']}');")
    rows.extend(
        [
            "  const encryptedData = CryptoJS.DES.encrypt(jsonData, key, {",
            "    iv: iv,",
            "    mode: CryptoJS.mode.CBC,",
            "    padding: CryptoJS.pad.Pkcs7",
            "  }).toString();",
            "",
            "  const requestPayload = { encryptedData: encryptedData };",
        ]
    )
    rows.extend(_js_replay(p["anti_replay"]))
    rows.extend(
        [
            "  if (nonce) requestPayload.nonce = nonce;",
            "  if (timestamp) requestPayload.timestamp = timestamp;",
            "",
            "  const params = new URLSearchParams(requestPayload);",
            f"  const response = await fetch('{endpoint}', {{",
            "    method: 'POST',",
            "    headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' },",
            "    body: params.toString()",
            "  });",
            "  const data = await response.json();",
            "  if (data.success) alert('登录成功'); else alert(data.error || '用户名或密码错误');",
            "}",
            "",
        ]
    )
    return "\n".join(rows)


def _render_js_aes_rsa(spec: dict[str, Any], endpoint: str, api_name: str, defaults: dict[str, Any]) -> str:
    p = _profile(spec)
    rows = _js_head(api_name, defaults)
    rows.extend(_js_replay(p["anti_replay"]))
    aes_key_expr = "CryptoJS.lib.WordArray.random(16)"
    if p.get("has_weak_setkey"):
        key_val = p["key_hex"] if p["key_encoding"] == "hex" else p["key_utf8"]
        aes_key_expr = f"__gen_parse_material('{key_val}', '{p['key_encoding']}')"
    aes_iv_expr = "CryptoJS.lib.WordArray.random(16)"
    if p.get("has_weak_setiv"):
        iv_val = p["iv_hex"] if p["iv_encoding"] == "hex" else p["iv_utf8"]
        aes_iv_expr = f"__gen_parse_material('{iv_val}', '{p['iv_encoding']}')"
    rows.extend(
        [
            "  const formData = { username: username, password: password, nonce: nonce, timestamp: timestamp };",
            "  const jsonData = JSON.stringify(formData);",
            f"  const aesKey = {aes_key_expr};",
            f"  const aesIv = {aes_iv_expr};",
            "  const encryptedData = CryptoJS.AES.encrypt(jsonData, aesKey, {",
            "    iv: aesIv,",
            "    mode: CryptoJS.mode.CBC,",
            f"    padding: CryptoJS.pad.{p['padding']}",
            "  }).toString();",
            "  const encryptor = new JSEncrypt();",
            "  encryptor.setPublicKey(`" + PUBLIC_KEY_PEM + "`);",
            "  const encryptedKey = encryptor.encrypt(CryptoJS.enc.Base64.stringify(aesKey));",
            "  const encryptedIv = encryptor.encrypt(CryptoJS.enc.Base64.stringify(aesIv));",
            "  if (!encryptedKey || !encryptedIv) { alert('RSA 包裹失败'); return; }",
            "  const requestPayload = { encryptedData, encryptedKey, encryptedIv };",
            "  if (nonce) requestPayload.nonce = nonce;",
            "  if (timestamp) requestPayload.timestamp = timestamp;",
            "  const params = new URLSearchParams(requestPayload);",
            f"  const response = await fetch('{endpoint}', {{",
            "    method: 'POST',",
            "    headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' },",
            "    body: params.toString()",
            "  });",
            "  const data = await response.json();",
            "  if (data.success) alert('登录成功'); else alert(data.error || '用户名或密码错误');",
            "}",
            "",
        ]
    )
    return "\n".join(rows)


def _render_js_rsa(spec: dict[str, Any], endpoint: str, api_name: str, defaults: dict[str, Any]) -> str:
    p = _profile(spec)
    rows = _js_head(api_name, defaults)
    rows.extend(_js_replay(p["anti_replay"]))
    rows.extend(
        [
            "  const dataPacket = { username: username, password: password, nonce: nonce, timestamp: timestamp };",
            "  const dataString = JSON.stringify(dataPacket);",
            "  const encryptor = new JSEncrypt();",
            "  encryptor.setPublicKey(`" + PUBLIC_KEY_PEM + "`);",
            "  const encryptedData = encryptor.encrypt(dataString);",
            "  if (!encryptedData) { alert('RSA 加密失败'); return; }",
            "",
            "  const params = new URLSearchParams();",
            "  params.append('data', encryptedData);",
            f"  const response = await fetch('{endpoint}', {{",
            "    method: 'POST',",
            "    headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' },",
            "    body: params.toString()",
            "  });",
            "  const data = await response.json();",
            "  if (data.success) alert('登录成功'); else alert(data.error || '用户名或密码错误');",
            "}",
            "",
        ]
    )
    return "\n".join(rows)


def _render_js_hmac(spec: dict[str, Any], endpoint: str, api_name: str, defaults: dict[str, Any]) -> str:
    p = _profile(spec)
    rows = _js_head(api_name, defaults)
    rows.extend(_js_replay(p["anti_replay"]))
    rows.extend(
        [
            f"  const secretKey = '{p['hmac_secret']}';",
            "  const dataToSign = username + password + (nonce || '') + (timestamp || '');",
            "  const signature = CryptoJS.HmacSHA256(dataToSign, secretKey).toString(CryptoJS.enc.Hex);",
            "  const requestPayload = { username: username, password: password, nonce: nonce, timestamp: timestamp };",
            "  const headers = { 'Content-Type': 'application/json; charset=utf-8' };",
            f"  let requestUrl = '{endpoint}';",
        ]
    )

    if p["signature_placement"] == "header":
        rows.append("  headers['X-Signature'] = signature;")
    elif p["signature_placement"] == "query":
        rows.append("  requestUrl += '?signature=' + encodeURIComponent(signature);")
    else:
        rows.append("  requestPayload.signature = signature;")

    rows.extend(
        [
            "",
            "  const response = await fetch(requestUrl, {",
            "    method: 'POST',",
            "    headers: headers,",
            "    body: JSON.stringify(requestPayload)",
            "  });",
            "  const data = await response.json();",
            "  if (data.success) alert('登录成功'); else alert(data.error || '用户名或密码错误');",
            "}",
            "",
        ]
    )
    return "\n".join(rows)


def _render_js_function(spec: dict[str, Any], endpoint: str, api_name: str, defaults: dict[str, Any]) -> str:
    algo = str(spec.get("algorithm_stack", ""))
    if algo in {"AES", "AES_CBC"}:
        return _render_js_aes(spec, endpoint, api_name, defaults)
    if algo in {"DES", "DES_CBC"}:
        return _render_js_des(spec, endpoint, api_name, defaults)
    if algo == "RSA_ONLY":
        return _render_js_rsa(spec, endpoint, api_name, defaults)
    if algo == "AES_RSA_ENVELOPE":
        return _render_js_aes_rsa(spec, endpoint, api_name, defaults)
    if algo == "PLAINTEXT_HMAC":
        return _render_js_hmac(spec, endpoint, api_name, defaults)
    raise ValueError(f"Layer1 暂不支持写入算法: {algo}")


def _php_common() -> str:
    return (
        "<?php\n"
        "header('Content-Type: application/json; charset=utf-8');\n"
        "require '../../database.php';\n"
        "session_start();\n"
        "function gen_fail($msg){ echo json_encode(['success'=>false,'error'=>$msg]); exit; }\n"
        "function gen_check_user($pdo,$username,$password){\n"
        "  $stmt=$pdo->prepare('SELECT * FROM users WHERE username = :username');\n"
        "  $stmt->execute(['username'=>$username]);\n"
        "  $user=$stmt->fetch(PDO::FETCH_ASSOC);\n"
        "  if(!$user || $user['password']!==md5($password)){ gen_fail('Invalid username or password'); }\n"
        "}\n"
        "function gen_check_replay($antiReplay,$nonce,$timestamp,$sessionBinding='bind_cookie'){\n"
        "  $needNonce=in_array($antiReplay,['nonce_only','nonce_timestamp','nonce_timestamp_signature','nonce_timestamp_signature_session_binding'],true);\n"
        "  $needTs=in_array($antiReplay,['timestamp_only','nonce_timestamp','nonce_timestamp_signature','nonce_timestamp_signature_session_binding'],true);\n"
        "  $needSig=in_array($antiReplay,['nonce_timestamp_signature','nonce_timestamp_signature_session_binding'],true);\n"
        "  $needSessionBind=($antiReplay==='nonce_timestamp_signature_session_binding');\n"
        "  if($needNonce){ if(!$nonce){ gen_fail('Missing nonce'); } }\n"
        "  if($needTs){\n"
        "    if(!$timestamp || !is_numeric($timestamp)){ gen_fail('Missing timestamp'); }\n"
        "    if(abs(time()-intval($timestamp))>600){ gen_fail('Request timeout'); }\n"
        "  }\n"
        "  if($needSig){\n"
        "    $sigHeader=$_SERVER['HTTP_X_SIGNATURE'] ?? $_SERVER['HTTP_SIGNATURE'] ?? $_SERVER['HTTP_X_SIGN'] ?? null;\n"
        "    $sigBody=$_POST['signature'] ?? $_POST['sign'] ?? $_POST['sig'] ?? null;\n"
        "    $sigQuery=$_GET['signature'] ?? $_GET['sign'] ?? $_GET['sig'] ?? null;\n"
        "    $raw=file_get_contents('php://input'); $json=@json_decode($raw,true); $sigJson=(is_array($json)?($json['signature'] ?? $json['sign'] ?? $json['sig'] ?? null):null);\n"
        "    if(!$sigHeader && !$sigBody && !$sigQuery && !$sigJson){ gen_fail('Missing signature'); }\n"
        "  }\n"
        "  if($needSessionBind && $sessionBinding==='bind_cookie'){ if(empty($_COOKIE['PHPSESSID'])){ gen_fail('Missing session binding'); } }\n"
        "}\n"
    )


def _php_aes(spec: dict[str, Any], api_name: str) -> str:
    p = _profile(spec)
    cipher = "AES-128-CBC" if p["key_size"] <= 128 else "AES-192-CBC" if p["key_size"] <= 192 else "AES-256-CBC"
    key_raw = p["key_hex"] if p["key_encoding"] == "hex" else p["key_utf8"]
    key_decode = "hex2bin" if p["key_encoding"] == "hex" else "strval"
    iv_raw = p["iv_hex"] if p["iv_encoding"] == "hex" else p["iv_utf8"]
    iv_decode = "hex2bin" if p["iv_encoding"] == "hex" else "strval"
    iv_part = "$iv=base64_decode($_POST['iv'] ?? '', true); if(!$iv){ gen_fail('Missing IV'); }\n"
    if p["iv_policy"] == "static":
        iv_part = f"$iv={iv_decode}('{iv_raw}');\n"

    padding_mode = str(p.get("padding", "Pkcs7")).strip().lower().replace("-", "").replace("_", "")
    decrypt_part = "$plain=openssl_decrypt($cipherRaw,$cipher,$key,OPENSSL_RAW_DATA,$iv); if($plain===false){ gen_fail('Decrypt failed'); }\n"
    if padding_mode == "zeropadding":
        decrypt_part = (
            "$plain=openssl_decrypt($cipherRaw,$cipher,$key,OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING,$iv); if($plain===false){ gen_fail('Decrypt failed'); }\n"
            + "$plain=rtrim($plain, \"\\0\");\n"
        )
    elif padding_mode == "nopadding":
        decrypt_part = "$plain=openssl_decrypt($cipherRaw,$cipher,$key,OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING,$iv); if($plain===false){ gen_fail('Decrypt failed'); }\n"

    return (
        _php_common()
        + f"$antiReplay='{p['anti_replay']}';\n"
        + f"$cipher='{cipher}';\n"
        + f"$key={key_decode}('{key_raw}');\n"
        + "$encryptedData=$_POST['encryptedData'] ?? null;\n"
        + "$nonce=$_POST['nonce'] ?? null;\n"
        + "$timestamp=$_POST['timestamp'] ?? null;\n"
        + "if(!$encryptedData){ gen_fail('No encrypted data'); }\n"
        + f"$sessionBinding='{p['session_binding']}';\n"
        + "gen_check_replay($antiReplay,$nonce,$timestamp,$sessionBinding);\n"
        + iv_part
        + "$cipherRaw=base64_decode($encryptedData, true); if($cipherRaw===false){ gen_fail('Invalid ciphertext'); }\n"
        + decrypt_part
        + "$data=json_decode($plain,true); if(!is_array($data) || !isset($data['username']) || !isset($data['password'])){ gen_fail('Invalid input'); }\n"
        + "gen_check_user($pdo,strval($data['username']),strval($data['password']));\n"
        + f"echo json_encode(['success'=>true,'api'=>'{api_name}']);\n"
        + "?>\n"
    )


def _php_rsa(spec: dict[str, Any], api_name: str) -> str:
    p = _profile(spec)
    return (
        _php_common()
        + f"$antiReplay='{p['anti_replay']}';\n"
        + "$privateKey = <<<'PRI'\n"
        + PRIVATE_KEY_PEM
        + "\nPRI;\n"
        + "$cipherInput=$_POST['data'] ?? null; if(!$cipherInput){ gen_fail('No data'); }\n"
        + "$cipherRaw=base64_decode($cipherInput,true); if($cipherRaw===false){ gen_fail('Invalid RSA data'); }\n"
        + "if(!openssl_private_decrypt($cipherRaw,$plain,$privateKey)){ gen_fail('RSA decrypt failed'); }\n"
        + "$data=json_decode($plain,true); if(!is_array($data) || !isset($data['username']) || !isset($data['password'])){ gen_fail('Invalid input'); }\n"
        + "$nonce=$data['nonce'] ?? null; $timestamp=$data['timestamp'] ?? null;\n"
        + f"$sessionBinding='{p['session_binding']}';\n"
        + "gen_check_replay($antiReplay,$nonce,$timestamp,$sessionBinding);\n"
        + "gen_check_user($pdo,strval($data['username']),strval($data['password']));\n"
        + f"echo json_encode(['success'=>true,'api'=>'{api_name}']);\n"
        + "?>\n"
    )


def _php_hmac(spec: dict[str, Any], api_name: str) -> str:
    p = _profile(spec)
    sign_get = "$signature=$data['signature'] ?? null;\n"
    if p["signature_placement"] == "header":
        sign_get = "$signature=$_SERVER['HTTP_X_SIGNATURE'] ?? null;\n"
    elif p["signature_placement"] == "query":
        sign_get = "$signature=$_GET['signature'] ?? null;\n"

    return (
        _php_common()
        + f"$antiReplay='{p['anti_replay']}';\n"
        + f"$secretKey='{p['hmac_secret']}';\n"
        + "$data=json_decode(file_get_contents('php://input'), true);\n"
        + "if(!is_array($data) || !isset($data['username']) || !isset($data['password'])){ gen_fail('Missing data'); }\n"
        + sign_get
        + "if(!$signature){ gen_fail('Missing signature'); }\n"
        + "$username=strval($data['username']); $password=strval($data['password']);\n"
        + "$nonce=$data['nonce'] ?? null; $timestamp=$data['timestamp'] ?? null;\n"
        + f"$sessionBinding='{p['session_binding']}';\n"
        + "gen_check_replay($antiReplay,$nonce,$timestamp,$sessionBinding);\n"
        + "$serverSign=hash_hmac('sha256',$username.$password.strval($nonce ?? '').strval($timestamp ?? ''),$secretKey);\n"
        + "if(!hash_equals($serverSign,strval($signature))){ gen_fail('Signature mismatch'); }\n"
        + "gen_check_user($pdo,$username,$password);\n"
        + f"echo json_encode(['success'=>true,'api'=>'{api_name}']);\n"
        + "?>\n"
    )


def _php_des(spec: dict[str, Any], api_name: str) -> str:
    p = _profile(spec)
    key_raw = p["key_hex"] if p["key_encoding"] == "hex" else p["key_utf8"]
    key_decode = "hex2bin" if p["key_encoding"] == "hex" else "strval"
    iv_raw = p["iv_hex"] if p["iv_encoding"] == "hex" else p["iv_utf8"]
    iv_decode = "hex2bin" if p["iv_encoding"] == "hex" else "strval"
    padding_mode = str(p.get("padding", "Pkcs7")).strip().lower().replace("-", "").replace("_", "")
    decrypt_part = "$plain=@openssl_decrypt($cipherRaw,'DES-CBC',$key,OPENSSL_RAW_DATA,$iv); if($plain===false){ gen_fail('Decrypt failed'); }\n"
    if padding_mode == "zeropadding":
        decrypt_part = (
            "$plain=@openssl_decrypt($cipherRaw,'DES-CBC',$key,OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING,$iv); if($plain===false){ gen_fail('Decrypt failed'); }\n"
            + "$plain=rtrim($plain, \"\\0\");\n"
        )
    elif padding_mode == "nopadding":
        decrypt_part = "$plain=@openssl_decrypt($cipherRaw,'DES-CBC',$key,OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING,$iv); if($plain===false){ gen_fail('Decrypt failed'); }\n"
    return (
        _php_common()
        + f"$antiReplay='{p['anti_replay']}';\n"
        + f"$key={key_decode}('{key_raw}');\n"
        + f"$iv={iv_decode}('{iv_raw}');\n"
        + "$methods=array_map('strtolower', openssl_get_cipher_methods()); if(!in_array('des-cbc',$methods)){ gen_fail('DES not supported on server'); }\n"
        + "$encryptedData=$_POST['encryptedData'] ?? null;\n"
        + "$nonce=$_POST['nonce'] ?? null;\n"
        + "$timestamp=$_POST['timestamp'] ?? null;\n"
        + "if(!$encryptedData){ gen_fail('No encrypted data'); }\n"
        + f"$sessionBinding='{p['session_binding']}';\n"
        + "gen_check_replay($antiReplay,$nonce,$timestamp,$sessionBinding);\n"
        + "$cipherRaw=base64_decode($encryptedData, true); if($cipherRaw===false){ gen_fail('Invalid ciphertext'); }\n"
        + decrypt_part
        + "$data=json_decode($plain,true); if(!is_array($data) || !isset($data['username']) || !isset($data['password'])){ gen_fail('Invalid input'); }\n"
        + "gen_check_user($pdo,strval($data['username']),strval($data['password']));\n"
        + f"echo json_encode(['success'=>true,'api'=>'{api_name}']);\n"
        + "?>\n"
    )


def _php_aes_rsa(spec: dict[str, Any], api_name: str) -> str:
    p = _profile(spec)
    cipher = "AES-128-CBC" if p["key_size"] <= 128 else "AES-256-CBC"
    return (
        _php_common()
        + f"$antiReplay='{p['anti_replay']}';\n"
        + "$privateKey = <<<'PRI'\n"
        + PRIVATE_KEY_PEM
        + "\nPRI;\n"
        + "$encryptedData=$_POST['encryptedData'] ?? null;\n"
        + "$encryptedKey=$_POST['encryptedKey'] ?? null;\n"
        + "$encryptedIv=$_POST['encryptedIv'] ?? null;\n"
        + "$nonce=$_POST['nonce'] ?? null;\n"
        + "$timestamp=$_POST['timestamp'] ?? null;\n"
        + "if(!$encryptedData || !$encryptedKey || !$encryptedIv){ gen_fail('Missing encrypted envelope'); }\n"
        + f"$sessionBinding='{p['session_binding']}';\n"
        + "gen_check_replay($antiReplay,$nonce,$timestamp,$sessionBinding);\n"
        + "$keyRaw=base64_decode($encryptedKey,true); $ivRaw=base64_decode($encryptedIv,true);\n"
        + "if($keyRaw===false || $ivRaw===false){ gen_fail('Invalid RSA envelope'); }\n"
        + "if(!openssl_private_decrypt($keyRaw,$aesKeyB64,$privateKey)){ gen_fail('RSA key decrypt failed'); }\n"
        + "if(!openssl_private_decrypt($ivRaw,$aesIvB64,$privateKey)){ gen_fail('RSA iv decrypt failed'); }\n"
        + "$key=base64_decode($aesKeyB64,true); $iv=base64_decode($aesIvB64,true);\n"
        + "if($key===false || $iv===false){ gen_fail('Invalid AES material'); }\n"
        + "$cipherRaw=base64_decode($encryptedData, true); if($cipherRaw===false){ gen_fail('Invalid ciphertext'); }\n"
        + f"$plain=openssl_decrypt($cipherRaw,'{cipher}',$key,OPENSSL_RAW_DATA,$iv); if($plain===false){{ gen_fail('Decrypt failed'); }}\n"
        + "$data=json_decode($plain,true); if(!is_array($data) || !isset($data['username']) || !isset($data['password'])){ gen_fail('Invalid input'); }\n"
        + "gen_check_user($pdo,strval($data['username']),strval($data['password']));\n"
        + f"echo json_encode(['success'=>true,'api'=>'{api_name}']);\n"
        + "?>\n"
    )


def _render_php_endpoint(spec: dict[str, Any], api_name: str) -> str:
    algo = str(spec.get("algorithm_stack", ""))
    if algo in {"AES", "AES_CBC"}:
        return _php_aes(spec, api_name)
    if algo in {"DES", "DES_CBC"}:
        return _php_des(spec, api_name)
    if algo == "RSA_ONLY":
        return _php_rsa(spec, api_name)
    if algo == "AES_RSA_ENVELOPE":
        return _php_aes_rsa(spec, api_name)
    if algo == "PLAINTEXT_HMAC":
        return _php_hmac(spec, api_name)
    raise ValueError(f"Layer1 暂不支持写入算法: {algo}")


def _inject_buttons_into_page(page_html: str, buttons_html: str, generated_js_rel: str) -> str:
    block = (
        "\n<!-- auto-generated layer1 buttons -->\n"
        "<div id=\"generated-layer1-buttons\" style=\"margin:16px auto;max-width:860px;text-align:center;\">\n"
        "  <h3>Layer1 Generated APIs (Sample)</h3>\n"
        f"  {buttons_html}\n"
        "</div>\n"
        f"<script src=\"{generated_js_rel}\"></script>\n"
    )
    if "</body>" in page_html:
        return page_html.replace("</body>", block + "</body>", 1)
    return page_html + block


def run_layer_write_sample(
    config_path: Path,
    layer_name: str,
    sample_size_override: int | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    cfg = load_yaml(config_path)
    out_cfg = cfg["output"]
    writer_cfg = cfg.get("writer", {}).get(layer_name, {})
    if not writer_cfg:
        raise ValueError(f"配置缺少 writer.{layer_name}")

    _require_keys(out_cfg, ["directory", "target_site_root"], "output")
    _require_keys(
        writer_cfg,
        ["sample_pool_yaml", "sample_gate_report", "sample_manifest", "generated_page_php", "generated_js_file", "templates"],
        f"writer.{layer_name}",
    )
    templates = writer_cfg.get("templates")
    if not isinstance(templates, dict):
        raise ValueError(f"writer.{layer_name}.templates 必须为对象")
    _require_keys(templates, ["php", "js"], f"writer.{layer_name}.templates")

    out_root = output_dir or (BASE_DIR / out_cfg["directory"])
    target_root = Path(out_cfg["target_site_root"])
    sample_size = int(sample_size_override or writer_cfg.get("sample_size_per_algorithm", 5))
    if sample_size <= 0:
        raise ValueError("sample_size_per_algorithm 必须大于 0")

    pool_key = f"{layer_name}_pool_yaml"
    if pool_key not in out_cfg:
        raise ValueError(f"output 缺少字段: {pool_key}")
    specs = load_yaml(out_root / out_cfg[pool_key])
    if not isinstance(specs, list):
        raise ValueError("layer1_pool 不是列表")
    specs = [_validate_spec(spec, idx) for idx, spec in enumerate(specs)]

    grouped = _group_by_algorithm(specs)
    sampled: list[dict[str, Any]] = []

    def _layer2_sort_key(row: dict[str, Any]) -> tuple[int, int, int, str]:
        algo = str(row.get("algorithm_stack", ""))
        layers = {str(layer) for layer in (row.get("interlayers", []) or []) if str(layer)}
        is_non_hmac = algo != "PLAINTEXT_HMAC"
        prefer_encoding = 0 if (is_non_hmac and "ENCODING_LAYER" in layers) else 1
        prefer_header = 0 if (is_non_hmac and "HEADER_SIGN_LAYER" in layers) else 1
        prefer_tagged = 0 if layers else 1
        return (prefer_encoding, prefer_header, prefer_tagged, str(row.get("id", "")))

    for algo in ["AES", "AES_CBC", "DES", "DES_CBC", "RSA_ONLY", "AES_RSA_ENVELOPE", "PLAINTEXT_HMAC"]:
        algo_rows = grouped.get(algo, [])
        if layer_name == "layer2":
            algo_rows = sorted(algo_rows, key=_layer2_sort_key)
            chosen = algo_rows[:sample_size]
            if sample_size >= 2:
                has_control = any(not (row.get("interlayers") or []) for row in chosen)
                if not has_control:
                    control_candidate = next((row for row in algo_rows if not (row.get("interlayers") or [])), None)
                    if control_candidate is not None:
                        if len(chosen) < sample_size:
                            chosen.append(control_candidate)
                        elif chosen:
                            chosen[-1] = control_candidate
            sampled.extend(chosen)
            continue
        sampled.extend(algo_rows[:sample_size])

    out_root.mkdir(parents=True, exist_ok=True)
    dump_yaml(out_root / writer_cfg["sample_pool_yaml"], sampled)

    php_template_path = target_root / str(writer_cfg["templates"]["php"])
    js_template_path = target_root / str(writer_cfg["templates"]["js"])
    if not php_template_path.is_file():
        raise ValueError(f"PHP 模板不存在: {php_template_path}")
    if not js_template_path.is_file():
        raise ValueError(f"JS 模板不存在: {js_template_path}")

    php_template = php_template_path.read_text(encoding="utf-8")
    js_template = js_template_path.read_text(encoding="utf-8")

    php_generated_dir = target_root / "encrypt" / "generated"
    php_generated_dir.mkdir(parents=True, exist_ok=True)

    js_generated_rel = "js/" + writer_cfg["generated_js_file"]
    js_generated_path = target_root / js_generated_rel
    js_generated_path.parent.mkdir(parents=True, exist_ok=True)

    defaults = writer_cfg.get("defaults", {})
    prefix = str(writer_cfg.get("api_name_prefix", layer_name))

    js_funcs = [f"// auto-generated {layer_name} sample functions", _js_helpers()]
    buttons: list[str] = []
    endpoints: list[str] = []

    counters: dict[str, int] = {}
    for spec in sampled:
        slug = _algo_slug(str(spec.get("algorithm_stack", "unknown")))
        counters[slug] = counters.get(slug, 0) + 1
        api_name = f"{prefix}_{slug}_{counters[slug]:04d}"
        if layer_name == "layer3":
            weak_slug = _weak_option_slug(spec)
            if weak_slug:
                api_name = f"{api_name}_{weak_slug}"
        endpoint_rel = f"encrypt/generated/{api_name}.php"

        (php_generated_dir / f"{api_name}.php").write_text(_render_php_endpoint(spec, api_name), encoding="utf-8", newline="\n")
        js_funcs.append(_render_js_function(spec, endpoint_rel, api_name, defaults))
        buttons.append(f"<button onclick=\"{api_name}()\">{api_name}</button>")
        endpoints.append(endpoint_rel)

    js_generated_path.write_text(js_template + "\n\n" + "\n".join(js_funcs) + "\n", encoding="utf-8", newline="\n")

    generated_page_path = target_root / str(writer_cfg["generated_page_php"])
    generated_page_path.write_text(
        _inject_buttons_into_page(php_template, "\n  ".join(buttons), js_generated_rel),
        encoding="utf-8",
        newline="\n",
    )

    generated_endpoint_paths = [str(php_generated_dir / Path(ep).name) for ep in endpoints]
    if len(set(generated_endpoint_paths)) != len(generated_endpoint_paths):
        raise ValueError("生成端点存在重名冲突")

    manifest = {
        "sample_count": len(sampled),
        "sample_size_per_algorithm": sample_size,
        "generated_page": str(generated_page_path),
        "generated_js": str(js_generated_path),
        "generated_endpoints": generated_endpoint_paths,
        "defaults": defaults,
    }

    dump_json(out_root / writer_cfg["sample_manifest"], manifest)
    dump_json(
        out_root / writer_cfg["sample_gate_report"],
        {
            "layer": layer_name,
            "sample_ready": len(sampled) > 0,
            "sample_count": len(sampled),
            "target_root": str(target_root),
        },
    )

    return manifest


def run_layer1_write_sample(config_path: Path, sample_size_override: int | None = None, output_dir: Path | None = None) -> dict[str, Any]:
    return run_layer_write_sample(config_path, "layer1", sample_size_override, output_dir)


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
