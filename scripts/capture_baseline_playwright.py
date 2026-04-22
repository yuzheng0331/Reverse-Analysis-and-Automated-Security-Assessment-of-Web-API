#!/usr/bin/env python3
"""
Playwright Baseline Capture
===========================
Automates the browser interaction to trigger API calls and capture real cryptographic parameters (Key, IV) and ciphertexts.
Updates the `baseline_skeletons.json` with verification data.
"""

import json
import asyncio
import argparse
import os
import datetime
from collections import defaultdict
from pathlib import Path
from playwright.async_api import async_playwright
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Project Paths
BASE_DIR = Path(__file__).resolve().parent.parent
HOOK_SCRIPT_PATH = BASE_DIR / "runtime" / "playwright_hook.js"
SKELETONS_DIR = BASE_DIR / "baseline_samples"


def build_dynamic_observed(captured_data, valid_capture):
    dynamic_markers = {"key", "iv", "nonce", "timestamp", "signature", "sign", "token", "message", "rand", "random"}
    strong_dynamic_markers = {"nonce", "timestamp", "signature", "sign", "token", "rand", "random"}
    fetch_urls = []
    observed_fields = set()
    has_server_intermediate_fetch = False
    crypto_types = set()

    for item in captured_data:
        if not isinstance(item, dict):
            continue
        item_type = str(item.get("type") or "")
        if item_type:
            crypto_types.add(item_type)

        if item_type == "FETCH":
            url = str(item.get("url") or "")
            if url:
                fetch_urls.append(url)
                url_lc = url.lower()
                if any(token in url_lc for token in ["server", "signature", "get-signature", "generate_key", "token"]):
                    has_server_intermediate_fetch = True

            body_json = item.get("body_json")
            body_form = item.get("body_form")
            if isinstance(body_json, dict):
                observed_fields.update(str(key) for key in body_json.keys())
            if isinstance(body_form, dict):
                observed_fields.update(str(key) for key in body_form.keys())

    runtime_param_keys = [str(key) for key in valid_capture.keys() if key != "ciphertext"]
    observed_dynamic_fields = sorted({
        key for key in set(runtime_param_keys) | observed_fields
        if key in dynamic_markers
    })

    strong_hits = sorted([field for field in observed_dynamic_fields if field in strong_dynamic_markers])
    return {
        "observed": bool(strong_hits or has_server_intermediate_fetch),
        "observed_dynamic_fields": observed_dynamic_fields,
        "strong_dynamic_fields": strong_hits,
        "runtime_param_keys": sorted(runtime_param_keys),
        "fetch_urls": sorted(set(fetch_urls)),
        "has_server_intermediate_fetch": has_server_intermediate_fetch,
        "capture_types": sorted(crypto_types),
        "captured_at": datetime.datetime.now().isoformat(),
        "observe_version": "v1",
    }


def extract_runtime_fields_from_fetch(captured_data):
    """从最近的 FETCH 请求体提取可复用运行时字段。"""
    extracted = {}
    for item in reversed(captured_data):
        if not isinstance(item, dict) or item.get("type") != "FETCH":
            continue
        body_json = item.get("body_json")
        body_form = item.get("body_form")
        source = body_json if isinstance(body_json, dict) else (body_form if isinstance(body_form, dict) else None)
        if not source:
            continue
        for key, value in source.items():
            if value is None or isinstance(value, (str, int, float, bool)):
                extracted[str(key)] = value
        if extracted:
            return extracted
    return extracted


def extract_last_fetch_headers(captured_data):
    for item in reversed(captured_data):
        if not isinstance(item, dict) or item.get("type") != "FETCH":
            continue
        headers = item.get("headers")
        if isinstance(headers, dict) and headers:
            return {str(k): v for k, v in headers.items()}
    return None


def build_capture_batches(endpoints, algo_batch=True):
    """Build endpoint batches. When algo_batch=True, group by crypto algorithm set."""
    if not algo_batch:
        return [("all", list(endpoints))]

    grouped = defaultdict(list)
    for ep in endpoints:
        meta = ep.get("meta", {}) if isinstance(ep, dict) else {}
        algos = meta.get("crypto_algorithms") if isinstance(meta, dict) else None
        if isinstance(algos, list) and algos:
            key = tuple(sorted(str(a).upper() for a in algos if a is not None))
        elif isinstance(algos, str) and algos.strip():
            key = (algos.strip().upper(),)
        else:
            key = ("UNKNOWN",)
        grouped[key].append(ep)

    ordered_keys = sorted(grouped.keys(), key=lambda item: (item == ("UNKNOWN",), item))
    return [(",".join(key), grouped[key]) for key in ordered_keys]


async def run_capture(target_url, endpoints, skeleton_file, settle_ms=300, nav_timeout_ms=10000, concurrency=4, algo_batch=True):
    """
    Spawns browser, injects hooks, and triggers endpoints.
    """
    print("Starting Playwright capture process...", flush=True)
    async with async_playwright() as p:
        print("Launching browser...", flush=True)
        browser = None
        launch_errors = []

        # 优先使用 bundled Chromium；若在 Windows 被策略拦截（spawn EPERM），
        # 再尝试系统浏览器 channel，避免阶段3直接中断。
        launch_candidates = [
            {"headless": True},
        ]
        if os.name == "nt":
            launch_candidates.extend([
                {"channel": "msedge", "headless": True},
                {"channel": "chrome", "headless": True},
            ])

        for candidate in launch_candidates:
            try:
                browser = await p.chromium.launch(**candidate)
                label = candidate.get("channel", "bundled-chromium")
                print(f"Browser launched via: {label}", flush=True)
                break
            except Exception as exc:
                launch_errors.append(f"{candidate}: {exc}")

        if browser is None:
            print("[ERROR] 浏览器启动失败，阶段3无法继续。", flush=True)
            for item in launch_errors:
                print(f"  - {item}", flush=True)
            print("[HINT] 若提示 spawn EPERM，请检查安全软件/系统策略对 headless_shell 的拦截，或安装 Edge/Chrome 后重试。", flush=True)
            return

        # Load Hook Script
        if not HOOK_SCRIPT_PATH.exists():
             print(f"Error: Hook script not found at {HOOK_SCRIPT_PATH}", flush=True)
             await browser.close()
             return

        print(f"Loading hook script from {HOOK_SCRIPT_PATH}", flush=True)
        with open(HOOK_SCRIPT_PATH, 'r', encoding='utf-8') as f:
            hook_script = f.read()

        updated_count = 0

        async def process_endpoint(ep):
            captured_data = []
            meta = ep.get("meta", {})
            eid = meta.get("id")
            trigger_func = meta.get("trigger_function")
            ep_url = meta.get("url")

            # Skip if no specific API URL or trigger
            if not ep_url or not trigger_func or trigger_func == "anonymous":
                return False

            print(f"\n[+] Testing Endpoint: {eid} (Trigger: {trigger_func})", flush=True)

            context = await browser.new_context()
            page = await context.new_page()
            await context.add_init_script(hook_script)

            def handle_console(msg):
                if msg.text.startswith("[CAPTURE:"):
                    try:
                        parts = msg.text.split(' ', 1)
                        if len(parts) > 1:
                            raw_type_tag = parts[0]
                            raw_type = raw_type_tag.replace("[CAPTURE:", "").replace("]", "")
                            data = json.loads(parts[1])
                            data["type"] = raw_type
                            captured_data.append(data)
                            print(f"    [CAPTURE] Caught {raw_type}: {str(data)[:80]}...", flush=True)
                    except Exception:
                        pass

            page.on("console", handle_console)

            try:
                # 1. Navigate/Reset State
                # print(f"    Navigating to {target_url} ...", flush=True)
                await page.goto(target_url, timeout=max(1000, int(nav_timeout_ms)))
                # Wait for scripts to load. sendDataAes is a good proxy for 'easy.js loaded'
                try:
                    await page.wait_for_function(
                        "typeof window.sendDataAes === 'function'",
                        timeout=min(max(1000, int(nav_timeout_ms)), 3000),
                    )
                except:
                    # print("    [!] Warning: sendDataAes not detected yet (timeout)")
                    pass
                
                # Check hook
                is_hooked = await page.evaluate("() => window._hook_injected === true")
                if not is_hooked:
                    print("    [!] Hook NOT detected after navigation (Wait/Inject issue?)", flush=True)

            except Exception as e:
                print(f"    [-] Navigation failed: {e}", flush=True)
                await context.close()
                return False

            try:
                # 2. Fill Payload
                req_payload = ep.get("request", {}).get("payload", {})
                if req_payload:
                    for key, val in req_payload.items():
                        if key.startswith("_") or val == "<Fill Value>":
                            continue
                        try:
                            # Try ID then Name
                            loc = page.locator(f"#{key}")
                            if await loc.count() > 0:
                                await loc.fill(str(val))
                            else:
                                loc = page.locator(f"[name='{key}']")
                                if await loc.count() > 0:
                                    await loc.fill(str(val))
                        except Exception:
                            pass

                # 3. Trigger Action
                print(f"    Invoking {trigger_func}('{ep_url}')...", flush=True)
                try:
                    result = await page.evaluate(f"""
                    async () => {{
                        const funcName = '{trigger_func}';
                        const targetUrl = '{ep_url}';

                        if (typeof window[funcName] === 'function') {{
                            try {{
                                const res = window[funcName](targetUrl);
                                if (res instanceof Promise) await res;
                                return 'CALLED_DIRECTLY';
                            }} catch(e) {{
                                return 'ERROR: ' + e.toString();
                            }}
                        }}

                        // Fallback: Click button
                        const buttons = document.querySelectorAll('button[onclick]');
                        for (let btn of buttons) {{
                            const attr = btn.getAttribute('onclick');
                            if (attr && attr.includes(funcName)) {{
                                btn.click();
                                return 'CLICKED_BUTTON';
                            }}
                        }}
                        return 'NOT_FOUND';
                    }}
                    """)
                    print(f"    Result: {result}", flush=True)

                    # Wait for network/crypto capture to settle
                    await page.wait_for_timeout(max(0, int(settle_ms)))
                except Exception as e:
                    print(f"    Error invoking: {e}", flush=True)

                # 4. Process Captured Data
                valid_capture = {}

                # 优先提取输出密文
                for cap in reversed(captured_data):
                    ctype = cap.get("type", "")
                    if ctype.endswith("_OUTPUT") and "ciphertext" not in valid_capture:
                        valid_capture["ciphertext"] = cap.get("ciphertext")

                # 第一优先级：AES/DES/HMAC 的 runtime（避免被 RSA message 污染）
                for cap in reversed(captured_data):
                    ctype = cap.get("type", "")
                    if ctype in ["AES", "DES", "HMAC"]:
                        for k in ["key", "iv", "message", "mode"]:
                            if k in cap and k not in valid_capture:
                                valid_capture[k] = cap[k]

                # 第二优先级：仅兜底补充 RSA 的 runtime
                for cap in reversed(captured_data):
                    ctype = cap.get("type", "")
                    if ctype == "RSA":
                        for k in ["key", "iv", "message", "mode"]:
                            if k in cap and k not in valid_capture:
                                valid_capture[k] = cap[k]

                # 5. Update Skeleton in memory
                fetch_runtime_fields = extract_runtime_fields_from_fetch(captured_data)
                if "ciphertext" in valid_capture:
                    ep.setdefault("validation", {})
                    ep["validation"].setdefault("dynamic", {})
                    ep["validation"].setdefault("session", {})
                    ep["validation"]["captured_ciphertext"] = valid_capture["ciphertext"]
                    merged_runtime = {
                        k: v for k, v in valid_capture.items() if k != "ciphertext"
                    }
                    for key, value in fetch_runtime_fields.items():
                        if key not in merged_runtime:
                            merged_runtime[key] = value
                    ep["validation"]["runtime_params"] = merged_runtime
                    fetch_headers = extract_last_fetch_headers(captured_data)
                    if fetch_headers:
                        ep.setdefault("request", {})
                        ep["request"]["headers"] = fetch_headers
                    ep["validation"]["trace"] = list(captured_data) # Store full trace
                    ep["validation"]["dynamic"]["observed"] = build_dynamic_observed(captured_data, valid_capture)
                    ep["validation"]["session"]["cookies"] = await context.cookies()

                    print(f"    [OK] Captured Ciphertext: {str(valid_capture.get('ciphertext'))[:30]}...")
                    if "key" in valid_capture:
                        print(f"    [OK] Captured Key: {valid_capture['key']}")
                    return True

                # 无密文并不等于无价值：服务端签名/仅打包端点仍需保留 FETCH trace。
                fetch_count = sum(1 for item in captured_data if isinstance(item, dict) and item.get("type") == "FETCH")
                if fetch_count > 0:
                    ep.setdefault("validation", {})
                    ep["validation"].setdefault("dynamic", {})
                    ep["validation"].setdefault("session", {})
                    ep["validation"]["trace"] = list(captured_data)
                    if "runtime_params" not in ep["validation"] or not isinstance(ep["validation"]["runtime_params"], dict):
                        ep["validation"]["runtime_params"] = {}
                    for k, v in valid_capture.items():
                        if k != "ciphertext":
                            ep["validation"]["runtime_params"][k] = v
                    for k, v in fetch_runtime_fields.items():
                        if k not in ep["validation"]["runtime_params"]:
                            ep["validation"]["runtime_params"][k] = v
                    fetch_headers = extract_last_fetch_headers(captured_data)
                    if fetch_headers:
                        ep.setdefault("request", {})
                        ep["request"]["headers"] = fetch_headers
                    ep["validation"]["dynamic"]["observed"] = build_dynamic_observed(captured_data, valid_capture)
                    ep["validation"]["session"]["cookies"] = await context.cookies()
                    print(f"    [OK] No ciphertext, but stored trace with {fetch_count} FETCH records.")
                    return True

                print("    [-] Capture empty or missing ciphertext.")
                return False
            finally:
                await context.close()

        capture_batches = build_capture_batches(endpoints, bool(algo_batch))
        sem = asyncio.Semaphore(max(1, int(concurrency)))

        for batch_name, batch_endpoints in capture_batches:
            print(f"\n[batch] {batch_name} | endpoints={len(batch_endpoints)} | concurrency={max(1, int(concurrency))}", flush=True)

            async def run_with_limit(ep):
                async with sem:
                    return await process_endpoint(ep)

            results = await asyncio.gather(*(run_with_limit(ep) for ep in batch_endpoints))
            updated_count += sum(1 for item in results if item)

        await browser.close()

        # Save updates
        if updated_count > 0:
            with open(skeleton_file, 'w', encoding='utf-8') as f:
                json.dump(endpoints, f, indent=2, ensure_ascii=False)
            print(f"\n[success] Updated {updated_count} endpoints in {skeleton_file}")
        else:
            print("\n[-] No endpoints updated.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=os.getenv("TARGET_URL"), required=False, help="Target URL (e.g. http://site/easy.php)")
    parser.add_argument("--skeleton", help="Path to baseline_skeletons.json")
    parser.add_argument("--concurrency", type=int, default=4, help="并发端点数")
    parser.add_argument("--settle-ms", type=int, default=300, help="触发后额外等待毫秒")
    parser.add_argument("--nav-timeout-ms", type=int, default=10000, help="导航超时毫秒")
    parser.add_argument("--algo-batch", dest="algo_batch", action="store_true")
    parser.add_argument("--no-algo-batch", dest="algo_batch", action="store_false")
    parser.set_defaults(algo_batch=True)
    args = parser.parse_args()

    # Find skeleton file if not provided
    skeleton_path = args.skeleton
    if not skeleton_path:
        if SKELETONS_DIR.exists():
            files = sorted(SKELETONS_DIR.glob("baseline_skeletons_*.json"), key=lambda f: f.stat().st_mtime)
            if files:
                skeleton_path = files[-1]

    if not skeleton_path:
        print("No skeleton file found.")
        return

    # Use args.url or env as a fallback base URL, but we mostly rely on endpoints
    fallback_url = args.url or os.getenv("TARGET_URL")
    if not fallback_url:
        print("Error: Target URL not specified.")
        return

    asyncio.run(
        run_capture(
            fallback_url,
            endpoints=json.load(open(skeleton_path, 'r', encoding='utf-8')),
            skeleton_file=skeleton_path,
            settle_ms=max(0, int(args.settle_ms)),
            nav_timeout_ms=max(1000, int(args.nav_timeout_ms)),
            concurrency=max(1, int(args.concurrency)),
            algo_batch=bool(args.algo_batch),
        )
    )

if __name__ == "__main__":
    main()
