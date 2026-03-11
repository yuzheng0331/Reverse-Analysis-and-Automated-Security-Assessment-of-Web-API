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
from pathlib import Path
from playwright.async_api import async_playwright
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Project Paths
BASE_DIR = Path(__file__).resolve().parent.parent
HOOK_SCRIPT_PATH = BASE_DIR / "runtime" / "playwright_hook.js"
SKELETONS_DIR = BASE_DIR / "baseline_samples"


def _expected_capture_type(step):
    algorithm = str(step.get("algorithm", "")).upper()
    step_type = str(step.get("step_type", "")).lower()
    if step_type not in ["encrypt", "sign"]:
        return None
    if algorithm == "AES":
        return "AES_OUTPUT"
    if algorithm == "DES":
        return "DES_OUTPUT"
    if algorithm == "RSA":
        return "RSA_OUTPUT"
    if algorithm in ["HMACSHA256", "HMACSHA256()"]:
        return "HMAC_OUTPUT"
    return None


def _extract_fetch_body_fields(fetch_item):
    if not isinstance(fetch_item, dict):
        return {}
    body_json = fetch_item.get("body_json")
    if isinstance(body_json, dict):
        return body_json
    body_form = fetch_item.get("body_form")
    if isinstance(body_form, dict):
        return body_form
    return {}


def _build_runtime_capture(entry, captured_data):
    runtime_params = {}
    named_outputs = {}
    captured_ciphertext = None
    execution_flow = entry.get("meta", {}).get("execution_flow", []) or []
    endpoint_url = entry.get("meta", {}).get("url", "")

    output_events = [item for item in captured_data if str(item.get("type", "")).endswith("_OUTPUT")]
    used_indices = set()
    crypto_steps = [step for step in execution_flow if str(step.get("step_type", "")).lower() in ["encrypt", "sign"]]

    for step in crypto_steps:
        expected_type = _expected_capture_type(step)
        if not expected_type:
            continue
        selected = None
        selected_index = None
        for idx, item in enumerate(output_events):
            if idx in used_indices:
                continue
            if item.get("type") == expected_type:
                selected = item
                selected_index = idx
                break
        if selected is None:
            continue
        used_indices.add(selected_index)
        output_value = selected.get("ciphertext")
        output_variable = step.get("output_variable")
        if output_variable and output_value is not None:
            named_outputs[output_variable] = output_value
            runtime_params[output_variable] = output_value
        if output_value is not None:
            captured_ciphertext = output_value

    for item in captured_data:
        ctype = item.get("type", "")
        if ctype in ["AES", "DES", "HMAC", "RSA"]:
            for key_name in ["key", "iv", "message", "mode", "public_key"]:
                if key_name in item and item.get(key_name) is not None and key_name not in runtime_params:
                    runtime_params[key_name] = item.get(key_name)
        elif ctype == "RSA_KEY":
            if item.get("public_key"):
                runtime_params.setdefault("public_key", item.get("public_key"))

    matching_fetches = []
    for item in captured_data:
        if item.get("type") != "FETCH":
            continue
        fetch_url = str(item.get("url", ""))
        if endpoint_url and endpoint_url in fetch_url:
            matching_fetches.append(item)
        elif endpoint_url and fetch_url.endswith(endpoint_url.split("/")[-1]):
            matching_fetches.append(item)

    for fetch_item in matching_fetches:
        body_fields = _extract_fetch_body_fields(fetch_item)
        if not body_fields:
            continue
        for step in execution_flow:
            if str(step.get("step_type", "")).lower() != "pack":
                continue
            packing_info = (step.get("runtime_args", {}) or {}).get("packing_info", {}) or {}
            structure = packing_info.get("structure", {}) or {}
            for field_name, source_name in structure.items():
                if field_name in body_fields:
                    runtime_params[field_name] = body_fields[field_name]
                    runtime_params.setdefault(str(source_name), body_fields[field_name])

    if captured_ciphertext is None and named_outputs:
        captured_ciphertext = list(named_outputs.values())[-1]

    return {
        "captured_ciphertext": captured_ciphertext,
        "runtime_params": runtime_params,
        "named_outputs": named_outputs,
        "trace": list(captured_data)
    }


async def run_capture(target_url, endpoints, skeleton_file):
    """
    Spawns browser, injects hooks, and triggers endpoints.
    """
    print("Starting Playwright capture process...", flush=True)
    async with async_playwright() as p:
        print("Launching browser...", flush=True)
        browser = await p.chromium.launch(headless=True) # Set headless=False for debugging
        context = await browser.new_context()
        page = await context.new_page()

        # Load Hook Script
        if not HOOK_SCRIPT_PATH.exists():
             print(f"Error: Hook script not found at {HOOK_SCRIPT_PATH}", flush=True)
             return

        print(f"Loading hook script from {HOOK_SCRIPT_PATH}", flush=True)
        with open(HOOK_SCRIPT_PATH, 'r', encoding='utf-8') as f:
            hook_script = f.read()

        # Add init script once; it persists across navigations in the same context
        await context.add_init_script(hook_script)

        # Global Capture List
        captured_data = []

        def handle_console(msg):
            if msg.text.startswith("[CAPTURE:"):
                try:
                    # extract type from [CAPTURE:TYPE]
                    # msg.text format: "[CAPTURE:AES] {...}"
                    parts = msg.text.split(' ', 1)
                    if len(parts) > 1:
                        raw_type_tag = parts[0] # [CAPTURE:AES]
                        raw_type = raw_type_tag.replace("[CAPTURE:", "").replace("]", "")
                        
                        json_str = parts[1]
                        data = json.loads(json_str)
                        
                        # Inject type back into data for easier processing
                        data["type"] = raw_type
                        
                        captured_data.append(data)
                        print(f"    [CAPTURE] Caught {raw_type}: {str(data)[:80]}...", flush=True)
                except Exception as e:
                    # print(f"    [CAPTURE ERROR] {e}", flush=True)
                    pass

        # Attach listener once
        page.on("console", handle_console)

        updated_count = 0

        for ep in endpoints:
            captured_data.clear() # Reset capture buffer for this test

            meta = ep.get("meta", {})
            eid = meta.get("id")
            trigger_func = meta.get("trigger_function")
            ep_url = meta.get("url")

            # Skip if no specific API URL or trigger
            if not ep_url or not trigger_func or trigger_func == "anonymous":
                continue

            print(f"\n[+] Testing Endpoint: {eid} (Trigger: {trigger_func})", flush=True)
            
            # 1. Navigate/Reset State
            try:
                # print(f"    Navigating to {target_url} ...", flush=True)
                await page.goto(target_url)
                # Wait for scripts to load. sendDataAes is a good proxy for 'easy.js loaded'
                try:
                    await page.wait_for_function("typeof window.sendDataAes === 'function'", timeout=3000)
                except:
                    # print("    [!] Warning: sendDataAes not detected yet (timeout)")
                    pass
                
                # Check hook
                is_hooked = await page.evaluate("() => window._hook_injected === true")
                if not is_hooked:
                    print("    [!] Hook NOT detected after navigation (Wait/Inject issue?)", flush=True)

            except Exception as e:
                print(f"    [-] Navigation failed: {e}", flush=True)
                continue

            # 2. Fill Payload
            req_payload = ep.get("request", {}).get("payload", {})
            if req_payload:
                for key, val in req_payload.items():
                    if key.startswith("_") or val == "<Fill Value>": continue
                    try:
                        # Try ID then Name
                        loc = page.locator(f"#{key}")
                        if await loc.count() > 0:
                            await loc.fill(str(val))
                        else:
                            loc = page.locator(f"[name='{key}']")
                            if await loc.count() > 0:
                                await loc.fill(str(val))
                    except Exception as e:
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

                # Wait for network/crypto
                await page.wait_for_timeout(2000)
            except Exception as e:
                print(f"    Error invoking: {e}", flush=True)

            # 4. Process Captured Data
            capture_summary = _build_runtime_capture(ep, captured_data)
            runtime_params = capture_summary.get("runtime_params", {})
            named_outputs = capture_summary.get("named_outputs", {})
            captured_ciphertext = capture_summary.get("captured_ciphertext")

            # 5. Update Skeleton in memory
            if captured_ciphertext is not None:
                ep.setdefault("validation", {})["captured_ciphertext"] = captured_ciphertext

            if runtime_params:
                existing_runtime = ep.setdefault("validation", {}).get("runtime_params", {}) or {}
                existing_runtime.update(runtime_params)
                ep["validation"]["runtime_params"] = existing_runtime

            if captured_data:
                ep.setdefault("validation", {})["trace"] = list(captured_data)

            if captured_ciphertext is not None or runtime_params or captured_data:
                if captured_ciphertext is not None:
                    print(f"    [OK] Captured Ciphertext: {str(captured_ciphertext)[:30]}...", flush=True)
                if runtime_params:
                    print(f"    [OK] Runtime Params: {sorted(runtime_params.keys())}", flush=True)
                if named_outputs:
                    print(f"    [OK] Output Vars: {sorted(named_outputs.keys())}", flush=True)
                updated_count += 1
            else:
                print("    [-] Capture empty.")

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

    asyncio.run(run_capture(fallback_url, endpoints=json.load(open(skeleton_path, 'r', encoding='utf-8')), skeleton_file=skeleton_path))

if __name__ == "__main__":
    main()
