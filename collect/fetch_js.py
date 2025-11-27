#!/usr/bin/env python3
"""
Phase 2: JavaScript Collector
==============================
Fetches JavaScript files from target web applications for crypto analysis.

This module:
- Fetches the entry HTML page
- Extracts all <script> tags (inline and external)
- Downloads external JS files
- Saves collected JS for AST parsing

Usage:
    python collect/fetch_js.py --url https://example.com --output collected_js/
"""

import argparse
import hashlib
import os
import re
import sys
import importlib
import importlib.util
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Optional: load .env from repo root if python-dotenv is installed (do not require it)
if importlib.util.find_spec("dotenv"):
    _dotenv = importlib.import_module("dotenv")
    try:
        _dotenv.load_dotenv(Path(__file__).parent.parent / ".env")
    except Exception:
        # If loading fails for any reason, continue without failing the script
        pass

# Required third-party imports
try:
    import requests
    from bs4 import BeautifulSoup
    from rich.console import Console
    from rich.progress import Progress
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

console = Console()

# =============================================================================
# Configuration
# =============================================================================

DEFAULT_OUTPUT_DIR = Path(__file__).parent.parent / "collected_js"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# =============================================================================
# JavaScript Collector Class
# =============================================================================


class JSCollector:
    """
    Collects JavaScript files from web applications for security analysis.
    
    Supports:
    - Inline <script> content extraction
    - External script file downloading
    - Source map detection
    - Webpack/bundle detection
    """
    
    def __init__(
        self,
        output_dir: Path = DEFAULT_OUTPUT_DIR,
        timeout: int = 30
    ):
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        
        self.collected_scripts: list[dict] = []
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def fetch_page(self, url: str) -> Optional[str]:
        """
        Fetch the HTML content of a page.
        
        Args:
            url: Target URL
            
        Returns:
            HTML content or None on error
        """
        try:
            console.print(f"[cyan]Fetching:[/cyan] {url}")
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            console.print(f"[green]✓ Fetched:[/green] {len(response.content)} bytes")
            return response.text
        except requests.RequestException as e:
            console.print(f"[red]✗ Failed to fetch {url}:[/red] {e}")
            return None
    
    def extract_scripts(self, html: str, base_url: str) -> list[dict]:
        """
        Extract all script references from HTML.
        
        Args:
            html: HTML content
            base_url: Base URL for resolving relative paths
            
        Returns:
            List of script info dictionaries
        """
        soup = BeautifulSoup(html, "html.parser")
        scripts = []
        
        for idx, script in enumerate(soup.find_all("script")):
            script_info = {
                "index": idx,
                "type": script.get("type", "text/javascript"),
                "async": script.get("async") is not None,
                "defer": script.get("defer") is not None,
            }
            
            src = script.get("src")
            if src:
                # External script
                script_info["source"] = "external"
                script_info["url"] = urljoin(base_url, src)
                script_info["original_src"] = src
            else:
                # Inline script
                script_info["source"] = "inline"
                script_info["content"] = script.string or ""
                script_info["content_hash"] = hashlib.md5(
                    (script.string or "").encode()
                ).hexdigest()[:8]
            
            scripts.append(script_info)
        
        console.print(f"[cyan]Found {len(scripts)} scripts[/cyan]")
        return scripts
    
    def download_script(self, url: str) -> Optional[str]:
        """
        Download a JavaScript file.
        
        Args:
            url: Script URL
            
        Returns:
            Script content or None on error
        """
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            console.print(f"[red]  ✗ Failed to download {url}:[/red] {e}")
            return None
    
    def collect_from_url(self, url: str) -> list[dict]:
        """
        Collect all JavaScript from a URL.
        
        Args:
            url: Target URL
            
        Returns:
            List of collected script information
        """
        html = self.fetch_page(url)
        if not html:
            return []
        
        scripts = self.extract_scripts(html, url)
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Downloading scripts...", total=len(scripts))
            
            for script in scripts:
                if script["source"] == "external":
                    content = self.download_script(script["url"])
                    if content:
                        script["content"] = content
                        script["size_bytes"] = len(content)
                        
                        # Detect potential crypto patterns (quick scan)
                        script["crypto_hints"] = self._quick_crypto_scan(content)
                
                progress.advance(task)
        
        self.collected_scripts.extend(scripts)
        return scripts
    
    def _quick_crypto_scan(self, content: str) -> list[str]:
        """
        Perform a quick scan for crypto-related patterns.
        
        Args:
            content: JavaScript content
            
        Returns:
            List of detected crypto hints
        """
        hints = []
        patterns = {
            "CryptoJS": r"CryptoJS",
            "crypto-js": r"crypto-js",
            "AES": r"\.AES\.|aes[.-]",
            "RSA": r"\.RSA\.|rsa[.-]|RSAKey",
            "MD5": r"\.MD5\(|md5\(",
            "SHA": r"\.SHA\d*\(|sha\d*\(",
            "HMAC": r"\.HMAC|hmac",
            "Base64": r"btoa\(|atob\(|base64",
            "JSEncrypt": r"JSEncrypt",
            "forge": r"node-forge|forge\.pki",
            "WebCrypto": r"crypto\.subtle",
            "sign": r"\.sign\(|createSign",
            "encrypt": r"\.encrypt\(|encryptData",
            "decrypt": r"\.decrypt\(|decryptData",
        }
        
        for name, pattern in patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                hints.append(name)
        
        return hints
    
    def save_collected(self) -> Path:
        """
        Save all collected scripts to the output directory.
        
        Returns:
            Path to the manifest file
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        collection_dir = self.output_dir / f"collection_{timestamp}"
        collection_dir.mkdir(parents=True, exist_ok=True)
        
        manifest = {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "total_scripts": len(self.collected_scripts),
            "scripts": []
        }
        
        for idx, script in enumerate(self.collected_scripts):
            script_entry = {
                "index": idx,
                "source": script["source"],
                "crypto_hints": script.get("crypto_hints", []),
            }
            
            if script["source"] == "external":
                script_entry["url"] = script.get("url")
            
            # Save content to file
            if script.get("content"):
                filename = f"script_{idx:03d}"
                if script["source"] == "external":
                    # Use URL path for filename
                    parsed = urlparse(script.get("url", ""))
                    path_name = parsed.path.split("/")[-1] or "index"
                    filename = f"{idx:03d}_{path_name}"
                else:
                    filename = f"{idx:03d}_inline_{script.get('content_hash', 'unknown')}"
                
                if not filename.endswith(".js"):
                    filename += ".js"
                
                filepath = collection_dir / filename
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(script["content"])
                
                script_entry["saved_as"] = filename
                script_entry["size_bytes"] = len(script["content"])
            
            manifest["scripts"].append(script_entry)
        
        # Save manifest
        manifest_path = collection_dir / "manifest.json"
        import json
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        
        console.print(f"[green]✓ Saved {len(self.collected_scripts)} scripts to:[/green] {collection_dir}")
        return manifest_path
    
    def display_summary(self):
        """Display a summary of collected scripts."""
        from rich.table import Table
        
        if not self.collected_scripts:
            console.print("[yellow]No scripts collected[/yellow]")
            return
        
        table = Table(title="Collected Scripts Summary")
        table.add_column("#", style="dim")
        table.add_column("Source", style="cyan")
        table.add_column("URL/Hash", max_width=40)
        table.add_column("Size", style="green")
        table.add_column("Crypto Hints", style="yellow")
        
        for script in self.collected_scripts:
            source = script["source"]
            identifier = script.get("url", script.get("content_hash", "-"))[:40]
            size = f"{script.get('size_bytes', 0):,}" if script.get("content") else "-"
            hints = ", ".join(script.get("crypto_hints", [])) or "-"
            
            table.add_row(
                str(script["index"]),
                source,
                identifier,
                size,
                hints
            )
        
        console.print(table)


# =============================================================================
# CLI Interface
# =============================================================================


def main():
    """Main entry point for JS collector."""
    parser = argparse.ArgumentParser(
        description="Collect JavaScript files from web applications",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Collect JS from a URL
    python collect/fetch_js.py --url https://example.com
    
    # Collect with custom output directory
    python collect/fetch_js.py --url https://example.com --output ./my_js/
        """
    )
    
    # Make --url optional: if not provided, fall back to environment variables (TARGET_URL or TARGET_API_BASE)
    parser.add_argument(
        "--url",
        required=False,
        help="Target URL to collect JavaScript from (or set TARGET_URL in .env / environment)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)"
    )
    
    args = parser.parse_args()

    # Determine effective URL: CLI arg > environment TARGET_URL > TARGET_API_BASE
    url = args.url or os.environ.get("TARGET_URL") or os.environ.get("TARGET_API_BASE")
    if not url:
        parser.error("No target URL specified. Provide --url or set TARGET_URL in your environment/.env")

    console.print("[bold cyan]═══ JavaScript Collector ═══[/bold cyan]\n")
    
    collector = JSCollector(output_dir=args.output, timeout=args.timeout)
    collector.collect_from_url(url)
    collector.display_summary()
    collector.save_collected()


if __name__ == "__main__":
    main()
