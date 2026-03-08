#!/usr/bin/env python3
"""
Stage 4: Dynamic Analysis & Runtime Hooking
===========================================
Executes Playwright with injected hooks based on Stage 2 analysis.

Functionality:
1. Loads hook configuration from `runtime/hooks_config.json`.
2. Launches browser and navigates to target.
3. Injects JavaScript proxies to intercept function calls and crypto operations.
4. Captures dynamic values (keys, IVs, plaintexts) during execution.
5. Saves captured context to `runtime/captured_context.json`.

Usage:
    python runtime/playwright_hook.py
"""

import json
import os
import sys
import time
from pathlib import Path
from playwright.sync_api import sync_playwright
from rich.console import Console

console = Console()

HOOKS_CONFIG_PATH = Path("runtime/hooks_config.json")
OUTPUT_CONTEXT_PATH = Path("runtime/captured_context.json")

def generate_injection_script(hooks):
    """
    Generates the JavaScript code to be injected into the browser.
    """
    js_code = """
    (function() {
        console.log("[Hook] Initializing runtime hooks...");
        window._captured_data = [];

        function reportCapture(type, target, args, result, timestamp) {
            const entry = {
                type: type,
                target: target,
                args: Array.from(args).map(arg => {
                    try { return JSON.stringify(arg); } catch(e) { return String(arg); }
                }),
                result: (typeof result === 'object') ? JSON.stringify(result) : String(result),
                timestamp: timestamp
            };
            window._captured_data.push(entry);
            console.log(`[Captured] ${target}`, entry);
            // In a real scenario, you might want to expose a binding to send this back immediately
        }

        // Helper to resolve namespace safely
        function resolvePath(path, root) {
            const parts = path.split('.');
            let current = root;
            for (let i = 0; i < parts.length - 1; i++) {
                if (!current[parts[i]]) return null;
                current = current[parts[i]];
            }
            return { parent: current, prop: parts[parts.length - 1] };
        }
    """

    for hook in hooks:
        target = hook.get("target")
        hk_type = hook.get("type")

        js_code += f"""
        // Hooking {target} ({hk_type})
        try {{
            let targetPath = "{target}";
            let resolved = resolvePath(targetPath, window);
            
            // Wait for libraries like CryptoJS to load if necessary
            // For simplicity, we assume immediate availability or valid window property
            // A more robust solution uses Object.defineProperty to hook on creation
            
            if (resolved && resolved.parent && resolved.parent[resolved.prop]) {{
                let original = resolved.parent[resolved.prop];
                resolved.parent[resolved.prop] = function(...args) {{
                    const start = Date.now();
                    const result = original.apply(this, args);
                    reportCapture("{hk_type}", "{target}", args, result, start);
                    return result;
                }};
                console.log("[Hook] Successfully hooked " + targetPath);
            }} else {{
                console.warn("[Hook] Target not found: " + targetPath);
                // Attempt proactive defineProperty hook for global vars
                if (targetPath.indexOf('.') === -1) {{
                    let _val;
                    Object.defineProperty(window, targetPath, {{
                        get: function() {{ return _val; }},
                        set: function(newVal) {{
                            console.log("[Hook] Detected assignment to " + targetPath);
                            if (typeof newVal === 'function') {{
                                _val = function(...args) {{
                                    const start = Date.now();
                                    const result = newVal.apply(this, args);
                                    reportCapture("{hk_type}", "{target}", args, result, start);
                                    return result;
                                }};
                            }} else {{
                                _val = newVal;
                            }}
                        }},
                        configurable: true
                    }});
                }}
            }}
        }} catch (e) {{
            console.error("[Hook] Error hooking {target}: ", e);
        }}
        """

    js_code += "})();"
    return js_code

def main():
    if not HOOKS_CONFIG_PATH.exists():
        console.print(f"[red]Hooks config not found at {HOOKS_CONFIG_PATH}. Run Stage 2 Bridge first.[/red]")
        sys.exit(1)

    try:
        config = json.loads(HOOKS_CONFIG_PATH.read_text(encoding='utf-8'))
    except Exception as e:
        console.print(f"[red]Failed to load hooks config: {e}[/red]")
        sys.exit(1)

    target_url = config.get("target_url")
    hooks = config.get("hooks", [])

    if not target_url:
        console.print("[red]Target URL missing in config.[/red]")
        sys.exit(1)

    console.print(f"[cyan]Target URL:[/cyan] {target_url}")
    console.print(f"[cyan]Injecting {len(hooks)} hooks...[/cyan]")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False) # Headless=False to see what happens
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        # 1. Inject Instrumentation Script
        injection_js = generate_injection_script(hooks)
        page.add_init_script(injection_js)

        # 2. Expose binding to retrieve data
        # We can also rely on reading window._captured_data at the end

        try:
            console.print("[yellow]Navigating to target...[/yellow]")
            page.goto(target_url, wait_until="networkidle")

            # 3. User Interaction Simulation
            # Wait for user input or simulate actions to trigger crypto
            console.print("[green]Page loaded. Waiting for interaction/execution... (15s)[/green]")

            # In a real automated pipeline, you would perform clicks here
            # page.click("#login-button")

            time.sleep(15)

            # 4. Extract Captured Data
            captured_data = page.evaluate("() => window._captured_data")

            console.print(f"[green]Captured {len(captured_data)} events.[/green]")

            # Save relevant contexts
            OUTPUT_CONTEXT_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(OUTPUT_CONTEXT_PATH, 'w', encoding='utf-8') as f:
                json.dump(captured_data, f, indent=2)

            console.print(f"[cyan]Runtime data saved to {OUTPUT_CONTEXT_PATH}[/cyan]")

        except Exception as e:
            console.print(f"[red]Runtime error: {e}[/red]")
        finally:
            browser.close()

if __name__ == "__main__":
    main()

