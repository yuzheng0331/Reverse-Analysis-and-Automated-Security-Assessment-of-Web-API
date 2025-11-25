#!/usr/bin/env python3
"""
Phase 1: Baseline Capture Script
=================================
Captures baseline API requests using Playwright or requests library.
Saves captured requests to baseline_samples/ for further analysis.

Usage:
    python scripts/capture_baseline.py --url https://example.com --output baseline_samples/
    python scripts/capture_baseline.py --config configs/api_config.yaml
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import requests
    from rich.console import Console
    from rich.table import Table
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

console = Console()

# =============================================================================
# Configuration
# =============================================================================

DEFAULT_OUTPUT_DIR = Path(__file__).parent.parent / "baseline_samples"
DEFAULT_TIMEOUT = 30  # seconds

# =============================================================================
# Baseline Capture Class
# =============================================================================


class BaselineCapture:
    """
    Captures baseline HTTP requests for API security assessment.
    
    Supports both simple requests and Playwright-based browser automation
    for JavaScript-heavy applications.
    """
    
    def __init__(
        self,
        output_dir: Path = DEFAULT_OUTPUT_DIR,
        timeout: int = DEFAULT_TIMEOUT
    ):
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.captured_requests: list[dict[str, Any]] = []
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def capture_simple(self, url: str, method: str = "GET", **kwargs) -> dict[str, Any]:
        """
        Capture a simple HTTP request using the requests library.
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            **kwargs: Additional arguments passed to requests
            
        Returns:
            Dictionary containing request/response details
        """
        console.print(f"[cyan]Capturing request to:[/cyan] {url}")
        
        try:
            response = requests.request(
                method=method,
                url=url,
                timeout=self.timeout,
                **kwargs
            )
            
            captured = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request": {
                    "method": method,
                    "url": url,
                    "headers": dict(response.request.headers),
                    "body": kwargs.get("data") or kwargs.get("json"),
                },
                "response": {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body_preview": response.text[:1000] if response.text else None,
                    "elapsed_ms": response.elapsed.total_seconds() * 1000,
                },
                "metadata": {
                    "capture_method": "requests",
                    "timeout": self.timeout,
                }
            }
            
            self.captured_requests.append(captured)
            console.print(f"[green]✓ Captured:[/green] {response.status_code} - {len(response.content)} bytes")
            return captured
            
        except requests.RequestException as e:
            console.print(f"[red]✗ Request failed:[/red] {e}")
            return {"error": str(e), "url": url}
    
    async def capture_with_playwright(self, url: str) -> list[dict[str, Any]]:
        """
        Capture requests using Playwright browser automation.
        Useful for JavaScript-heavy applications that make dynamic API calls.
        
        Args:
            url: Target URL to visit
            
        Returns:
            List of captured network requests
        """
        # TODO: Implement Playwright-based capture
        # This is a placeholder for the full implementation
        
        console.print("[yellow]Playwright capture not yet implemented[/yellow]")
        console.print("[dim]TODO: Implement browser-based request capture[/dim]")
        
        # Example implementation structure:
        # from playwright.async_api import async_playwright
        #
        # async with async_playwright() as p:
        #     browser = await p.chromium.launch()
        #     page = await browser.new_page()
        #     
        #     captured = []
        #     
        #     async def handle_request(request):
        #         captured.append({
        #             "url": request.url,
        #             "method": request.method,
        #             "headers": request.headers,
        #             "post_data": request.post_data,
        #         })
        #     
        #     page.on("request", handle_request)
        #     await page.goto(url)
        #     await page.wait_for_load_state("networkidle")
        #     
        #     await browser.close()
        #     return captured
        
        return []
    
    def save_captured(self, filename: Optional[str] = None) -> Path:
        """
        Save captured requests to a JSON file.
        
        Args:
            filename: Output filename (auto-generated if not provided)
            
        Returns:
            Path to the saved file
        """
        if not filename:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"baseline_{timestamp}.json"
        
        output_path = self.output_dir / filename
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "captured_at": datetime.now(timezone.utc).isoformat(),
                    "total_requests": len(self.captured_requests),
                    "requests": self.captured_requests,
                },
                f,
                indent=2,
                ensure_ascii=False
            )
        
        console.print(f"[green]✓ Saved to:[/green] {output_path}")
        return output_path
    
    def display_summary(self):
        """Display a summary table of captured requests."""
        if not self.captured_requests:
            console.print("[yellow]No requests captured[/yellow]")
            return
        
        table = Table(title="Captured Requests Summary")
        table.add_column("URL", style="cyan", max_width=50)
        table.add_column("Method", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Time (ms)", style="blue")
        
        for req in self.captured_requests:
            if "error" in req:
                table.add_row(req.get("url", "?"), "?", "[red]ERROR[/red]", "-")
            else:
                table.add_row(
                    req["request"]["url"][:50],
                    req["request"]["method"],
                    str(req["response"]["status_code"]),
                    f"{req['response']['elapsed_ms']:.0f}"
                )
        
        console.print(table)


# =============================================================================
# CLI Interface
# =============================================================================


def create_sample_baseline():
    """Create a sample baseline file for demonstration."""
    sample_data = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "total_requests": 1,
        "requests": [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request": {
                    "method": "POST",
                    "url": "https://api.example.com/v1/login",
                    "headers": {
                        "Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                        "X-Request-ID": "placeholder-request-id"
                    },
                    "body": {
                        "username": "test_user",
                        "password": "PLACEHOLDER_ENCRYPTED_PASSWORD",
                        "timestamp": "1700000000000",
                        "sign": "PLACEHOLDER_SIGNATURE_HASH"
                    }
                },
                "response": {
                    "status_code": 200,
                    "headers": {
                        "Content-Type": "application/json",
                        "X-Crypto-Version": "AES-256-CBC"
                    },
                    "body_preview": '{"code": 0, "data": {"token": "PLACEHOLDER_JWT_TOKEN"}}',
                    "elapsed_ms": 150.5
                },
                "metadata": {
                    "capture_method": "manual",
                    "notes": "Sample login request with encrypted parameters",
                    "crypto_indicators": [
                        "sign parameter (possible HMAC/MD5)",
                        "encrypted password field",
                        "X-Crypto-Version header"
                    ]
                }
            }
        ]
    }
    
    output_dir = DEFAULT_OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_path = output_dir / "sample_request.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sample_data, f, indent=2, ensure_ascii=False)
    
    console.print(f"[green]✓ Created sample baseline:[/green] {output_path}")
    return output_path


def main():
    """Main entry point for baseline capture script."""
    parser = argparse.ArgumentParser(
        description="Capture baseline API requests for security assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Capture a single URL
    python scripts/capture_baseline.py --url https://api.example.com/endpoint
    
    # Create sample baseline file
    python scripts/capture_baseline.py --create-sample
    
    # Capture with custom output directory
    python scripts/capture_baseline.py --url https://api.example.com --output ./my_baselines/
        """
    )
    
    parser.add_argument(
        "--url",
        help="Target URL to capture"
    )
    parser.add_argument(
        "--method",
        default="GET",
        help="HTTP method (default: GET)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--create-sample",
        action="store_true",
        help="Create a sample baseline file for demonstration"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    
    args = parser.parse_args()
    
    console.print("[bold cyan]═══ Baseline Capture Tool ═══[/bold cyan]\n")
    
    if args.create_sample:
        create_sample_baseline()
        return
    
    if not args.url:
        # Create sample if no URL provided
        console.print("[yellow]No URL provided. Creating sample baseline...[/yellow]\n")
        create_sample_baseline()
        console.print("\n[dim]Use --url to capture a real endpoint[/dim]")
        return
    
    capture = BaselineCapture(output_dir=args.output, timeout=args.timeout)
    capture.capture_simple(args.url, method=args.method)
    capture.display_summary()
    capture.save_captured()


if __name__ == "__main__":
    main()
