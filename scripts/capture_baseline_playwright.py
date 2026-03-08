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
import sys
from pathlib import Path
from playwright.async_api import async_playwright
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Project Paths
BASE_DIR = Path(__file__).resolve().parent.parent
HOOK_SCRIPT_PATH = BASE_DIR / "runtime" / "playwright_hook.js"
SKELETONS_DIR = BASE_DIR / "baseline_samples"

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
            valid_capture = {}

            # Prioritize finding the output ciphertext
            # We assume the last relevant OUTPUT log is the one we want
            for cap in reversed(captured_data):
                ctype = cap.get("type", "")
                
                # Check for output types (AES_OUTPUT, RSA_OUTPUT, etc.)
                if ctype.endswith("_OUTPUT") and "ciphertext" not in valid_capture:
                    valid_capture["ciphertext"] = cap.get("ciphertext")
                
                # Check for parameter types (AES, RSA, DES, HMAC)
                elif ctype in ["AES", "DES", "RSA", "HMAC"]:
                    # Capture parameters if not set
                    for k in ["key", "iv", "message", "mode"]:
                        if k in cap and k not in valid_capture:
                            valid_capture[k] = cap[k]

            # 5. Update Skeleton in memory
            if "ciphertext" in valid_capture:
                ep["validation"]["captured_ciphertext"] = valid_capture["ciphertext"]
                ep["validation"]["runtime_params"] = {
                    k: v for k, v in valid_capture.items() if k != "ciphertext"
                }
                ep["validation"]["trace"] = list(captured_data) # Store full trace

                print(f"    [OK] Captured Ciphertext: {str(valid_capture.get('ciphertext'))[:30]}...")
                if "key" in valid_capture:
                    print(f"    [OK] Captured Key: {valid_capture['key']}")
                updated_count += 1
            else:
                print("    [-] Capture empty or missing ciphertext.")

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
