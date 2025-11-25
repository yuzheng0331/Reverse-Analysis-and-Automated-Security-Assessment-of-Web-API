#!/usr/bin/env python3
"""
Phase 5: Request Replay Utility
================================
Replays captured API requests with crypto parameters.

This module:
- Replays baseline requests with original parameters
- Re-encrypts/re-signs parameters using detected crypto
- Compares responses for consistency
- Supports batch replay for testing

Usage:
    python replay/replay_request.py --baseline baseline_samples/sample_request.json
    python replay/replay_request.py --url https://api.example.com --method POST --data '{"key":"value"}'
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

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

DEFAULT_BASELINE_DIR = Path(__file__).parent.parent / "baseline_samples"
DEFAULT_OUTPUT_DIR = Path(__file__).parent.parent / "replay_results"
DEFAULT_TIMEOUT = 30


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class ReplayRequest:
    """Definition of a request to replay."""
    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body: Any = None
    timeout: int = DEFAULT_TIMEOUT
    crypto_transform: Optional[str] = None  # Transform to apply


@dataclass
class ReplayResult:
    """Result of a replayed request."""
    request: ReplayRequest
    status_code: int
    response_body: str
    response_headers: dict
    elapsed_ms: float
    success: bool
    error: Optional[str] = None
    comparison: Optional[dict] = None


# =============================================================================
# Crypto Transform Functions (Placeholders)
# =============================================================================


class CryptoTransforms:
    """
    Placeholder crypto transformation functions.
    
    TODO: Implement actual crypto transformations based on detected patterns.
    These should match the crypto implementations found in the target application.
    """
    
    @staticmethod
    def identity(data: Any) -> Any:
        """No transformation - return as-is."""
        return data
    
    @staticmethod
    def update_timestamp(data: dict) -> dict:
        """Update timestamp field to current time."""
        if isinstance(data, dict):
            data = data.copy()
            for key in ["timestamp", "ts", "time", "t"]:
                if key in data:
                    data[key] = str(int(time.time() * 1000))
        return data
    
    @staticmethod
    def regenerate_sign(data: dict, secret: str = "PLACEHOLDER_SECRET") -> dict:
        """
        Regenerate signature field.
        
        TODO: Implement actual signature generation based on detected algorithm.
        This is a placeholder that shows the structure.
        """
        if isinstance(data, dict):
            data = data.copy()
            # Placeholder: Would compute actual signature here
            # Example for HMAC-SHA256:
            # import hmac
            # import hashlib
            # sign_string = "&".join(f"{k}={v}" for k, v in sorted(data.items()) if k != "sign")
            # data["sign"] = hmac.new(secret.encode(), sign_string.encode(), hashlib.sha256).hexdigest()
            
            if "sign" in data:
                data["sign"] = "PLACEHOLDER_REGENERATED_SIGNATURE"
        return data
    
    @staticmethod
    def encrypt_password(data: dict, key: str = "PLACEHOLDER_KEY") -> dict:
        """
        Re-encrypt password field.
        
        TODO: Implement actual encryption based on detected algorithm.
        """
        if isinstance(data, dict):
            data = data.copy()
            if "password" in data:
                # Placeholder: Would encrypt with actual key/algorithm
                data["password"] = "PLACEHOLDER_ENCRYPTED_PASSWORD"
        return data


# Transform registry
TRANSFORMS: dict[str, Callable] = {
    "identity": CryptoTransforms.identity,
    "update_timestamp": CryptoTransforms.update_timestamp,
    "regenerate_sign": CryptoTransforms.regenerate_sign,
    "encrypt_password": CryptoTransforms.encrypt_password,
}


# =============================================================================
# Request Replayer Class
# =============================================================================


class RequestReplayer:
    """
    Replays API requests with optional crypto transformations.
    
    Supports:
    - Single request replay
    - Batch replay from baseline files
    - Response comparison
    - Crypto parameter regeneration
    """
    
    def __init__(
        self,
        output_dir: Path = DEFAULT_OUTPUT_DIR,
        timeout: int = DEFAULT_TIMEOUT
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.session = requests.Session()
        self.results: list[ReplayResult] = []
    
    def replay_single(
        self,
        request: ReplayRequest,
        transform: Optional[str] = None
    ) -> ReplayResult:
        """
        Replay a single request.
        
        Args:
            request: Request to replay
            transform: Name of transform to apply (from TRANSFORMS)
            
        Returns:
            ReplayResult with response details
        """
        console.print(f"[cyan]Replaying:[/cyan] {request.method} {request.url}")
        
        # Apply transform if specified
        body = request.body
        if transform and transform in TRANSFORMS:
            transform_func = TRANSFORMS[transform]
            if isinstance(body, dict):
                body = transform_func(body)
                console.print(f"  [dim]Applied transform: {transform}[/dim]")
        
        try:
            # Prepare request kwargs
            kwargs: dict[str, Any] = {
                "method": request.method,
                "url": request.url,
                "headers": request.headers,
                "timeout": request.timeout or self.timeout,
            }
            
            if body:
                if isinstance(body, dict):
                    kwargs["json"] = body
                else:
                    kwargs["data"] = body
            
            # Execute request
            start_time = time.time()
            response = self.session.request(**kwargs)
            elapsed_ms = (time.time() - start_time) * 1000
            
            result = ReplayResult(
                request=request,
                status_code=response.status_code,
                response_body=response.text[:5000],  # Limit size
                response_headers=dict(response.headers),
                elapsed_ms=elapsed_ms,
                success=response.ok,
            )
            
            console.print(f"  [green]✓ Response:[/green] {response.status_code} ({elapsed_ms:.0f}ms)")
            
        except requests.RequestException as e:
            result = ReplayResult(
                request=request,
                status_code=0,
                response_body="",
                response_headers={},
                elapsed_ms=0,
                success=False,
                error=str(e)
            )
            console.print(f"  [red]✗ Error:[/red] {e}")
        
        self.results.append(result)
        return result
    
    def replay_from_baseline(
        self,
        baseline_path: Path,
        transform: Optional[str] = None
    ) -> list[ReplayResult]:
        """
        Replay all requests from a baseline file.
        
        Args:
            baseline_path: Path to baseline JSON file
            transform: Transform to apply to all requests
            
        Returns:
            List of ReplayResults
        """
        if not baseline_path.exists():
            console.print(f"[red]Baseline file not found:[/red] {baseline_path}")
            return []
        
        with open(baseline_path, encoding="utf-8") as f:
            data = json.load(f)
        
        results = []
        for req_data in data.get("requests", []):
            request_info = req_data.get("request", {})
            
            request = ReplayRequest(
                url=request_info.get("url", ""),
                method=request_info.get("method", "GET"),
                headers=request_info.get("headers", {}),
                body=request_info.get("body"),
            )
            
            if request.url:
                result = self.replay_single(request, transform)
                
                # Compare with original response if available
                original_response = req_data.get("response", {})
                if original_response:
                    result.comparison = self._compare_responses(
                        original_response,
                        {
                            "status_code": result.status_code,
                            "body": result.response_body
                        }
                    )
                
                results.append(result)
        
        return results
    
    def _compare_responses(
        self,
        original: dict,
        replayed: dict
    ) -> dict:
        """Compare original and replayed responses."""
        comparison = {
            "status_match": original.get("status_code") == replayed.get("status_code"),
            "original_status": original.get("status_code"),
            "replayed_status": replayed.get("status_code"),
            "body_similarity": 0.0,
        }
        
        # Simple body comparison (could be enhanced)
        orig_body = str(original.get("body_preview", ""))
        replay_body = str(replayed.get("body", ""))
        
        if orig_body and replay_body:
            # Calculate simple similarity
            orig_set = set(orig_body.split())
            replay_set = set(replay_body.split())
            if orig_set or replay_set:
                comparison["body_similarity"] = len(orig_set & replay_set) / len(orig_set | replay_set)
        
        return comparison
    
    def save_results(self, filename: Optional[str] = None) -> Path:
        """Save replay results to JSON."""
        if not filename:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"replay_results_{timestamp}.json"
        
        output_path = self.output_dir / filename
        
        output_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_requests": len(self.results),
            "successful": sum(1 for r in self.results if r.success),
            "results": []
        }
        
        for result in self.results:
            output_data["results"].append({
                "url": result.request.url,
                "method": result.request.method,
                "status_code": result.status_code,
                "elapsed_ms": result.elapsed_ms,
                "success": result.success,
                "error": result.error,
                "comparison": result.comparison,
                "response_preview": result.response_body[:500] if result.response_body else None
            })
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]✓ Saved results to:[/green] {output_path}")
        return output_path
    
    def display_summary(self):
        """Display replay results summary."""
        if not self.results:
            console.print("[yellow]No replay results[/yellow]")
            return
        
        table = Table(title="Replay Results Summary")
        table.add_column("URL", style="cyan", max_width=40)
        table.add_column("Method", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Time (ms)", style="blue")
        table.add_column("Match", style="magenta")
        
        for result in self.results:
            status_style = "green" if result.success else "red"
            match_status = "-"
            if result.comparison:
                if result.comparison.get("status_match"):
                    match_status = f"[green]✓[/green] ({result.comparison.get('body_similarity', 0):.0%})"
                else:
                    match_status = f"[red]✗[/red]"
            
            table.add_row(
                result.request.url[:40],
                result.request.method,
                f"[{status_style}]{result.status_code}[/{status_style}]",
                f"{result.elapsed_ms:.0f}" if result.elapsed_ms else "-",
                match_status
            )
        
        console.print(table)


# =============================================================================
# CLI Interface
# =============================================================================


def main():
    """Main entry point for request replayer."""
    parser = argparse.ArgumentParser(
        description="Replay API requests with crypto transformations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Replay from baseline file
    python replay/replay_request.py --baseline baseline_samples/sample_request.json
    
    # Replay with timestamp update transform
    python replay/replay_request.py --baseline sample.json --transform update_timestamp
    
    # Single request replay
    python replay/replay_request.py --url https://api.example.com/endpoint --method GET

Available transforms:
    - identity: No transformation
    - update_timestamp: Update timestamp fields
    - regenerate_sign: Regenerate signature (placeholder)
    - encrypt_password: Re-encrypt password (placeholder)
        """
    )
    
    parser.add_argument(
        "--baseline",
        type=Path,
        help="Baseline JSON file to replay"
    )
    parser.add_argument(
        "--url",
        help="URL for single request replay"
    )
    parser.add_argument(
        "--method",
        default="GET",
        help="HTTP method (default: GET)"
    )
    parser.add_argument(
        "--data",
        help="Request body (JSON string)"
    )
    parser.add_argument(
        "--transform",
        choices=list(TRANSFORMS.keys()),
        help="Crypto transform to apply"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})"
    )
    
    args = parser.parse_args()
    
    console.print("[bold cyan]═══ Request Replayer ═══[/bold cyan]\n")
    
    replayer = RequestReplayer(output_dir=args.output)
    
    if args.baseline:
        replayer.replay_from_baseline(args.baseline, args.transform)
    elif args.url:
        body = json.loads(args.data) if args.data else None
        request = ReplayRequest(
            url=args.url,
            method=args.method,
            body=body
        )
        replayer.replay_single(request, args.transform)
    else:
        console.print("[yellow]Specify --baseline or --url to replay requests[/yellow]")
        console.print("[dim]Use --help for more information[/dim]")
        return
    
    replayer.display_summary()
    if replayer.results:
        replayer.save_results()


if __name__ == "__main__":
    main()
