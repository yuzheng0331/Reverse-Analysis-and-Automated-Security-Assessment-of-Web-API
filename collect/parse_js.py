#!/usr/bin/env python3
"""
Phase 3: JavaScript AST Parser
===============================
Parses JavaScript files to extract crypto-related patterns using AST analysis.

This module:
- Parses JavaScript using esprima/acorn-compatible AST
- Identifies crypto function calls
- Extracts encryption parameters and patterns
- Maps API calls to crypto operations

Usage:
    python collect/parse_js.py --input collected_js/ --output analysis_results/
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
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

DEFAULT_INPUT_DIR = Path(__file__).parent.parent / "collected_js"
DEFAULT_OUTPUT_DIR = Path(__file__).parent.parent / "analysis_results"

# =============================================================================
# Crypto Pattern Definitions
# =============================================================================

# Pattern definitions for crypto detection
CRYPTO_PATTERNS = {
    # CryptoJS patterns
    "cryptojs_aes": {
        "pattern": r"CryptoJS\.AES\.(encrypt|decrypt)\s*\(",
        "library": "CryptoJS",
        "algorithm": "AES",
        "description": "CryptoJS AES encryption/decryption"
    },
    "cryptojs_des": {
        "pattern": r"CryptoJS\.(DES|TripleDES)\.(encrypt|decrypt)\s*\(",
        "library": "CryptoJS",
        "algorithm": "DES/3DES",
        "description": "CryptoJS DES/3DES encryption"
    },
    "cryptojs_md5": {
        "pattern": r"CryptoJS\.MD5\s*\(",
        "library": "CryptoJS",
        "algorithm": "MD5",
        "description": "CryptoJS MD5 hash"
    },
    "cryptojs_sha": {
        "pattern": r"CryptoJS\.SHA(1|256|384|512)\s*\(",
        "library": "CryptoJS",
        "algorithm": "SHA",
        "description": "CryptoJS SHA hash"
    },
    "cryptojs_hmac": {
        "pattern": r"CryptoJS\.Hmac(MD5|SHA1|SHA256)\s*\(",
        "library": "CryptoJS",
        "algorithm": "HMAC",
        "description": "CryptoJS HMAC"
    },
    
    # JSEncrypt RSA patterns
    "jsencrypt_rsa": {
        "pattern": r"JSEncrypt\s*\(\)|\.encrypt\s*\(|\.setPublicKey\s*\(",
        "library": "JSEncrypt",
        "algorithm": "RSA",
        "description": "JSEncrypt RSA encryption"
    },
    
    # Web Crypto API
    "webcrypto_subtle": {
        "pattern": r"crypto\.subtle\.(encrypt|decrypt|sign|verify|digest)\s*\(",
        "library": "WebCrypto",
        "algorithm": "various",
        "description": "Web Crypto API"
    },
    
    # Node.js crypto
    "node_crypto": {
        "pattern": r"require\s*\(\s*['\"]crypto['\"]\s*\)|crypto\.createCipher|crypto\.createHash",
        "library": "Node.js crypto",
        "algorithm": "various",
        "description": "Node.js crypto module"
    },
    
    # Base64 encoding
    "base64": {
        "pattern": r"btoa\s*\(|atob\s*\(|\.toString\s*\(\s*['\"]base64['\"]\s*\)",
        "library": "Native",
        "algorithm": "Base64",
        "description": "Base64 encoding/decoding"
    },
    
    # Custom sign functions
    "custom_sign": {
        "pattern": r"(generateSign|createSign|calcSign|getSign|makeSign)\s*\(",
        "library": "Custom",
        "algorithm": "Unknown",
        "description": "Custom signature function"
    },
    
    # API key/secret patterns
    "api_key": {
        "pattern": r"(apiKey|api_key|appKey|app_key|secretKey|secret_key)\s*[=:]\s*['\"]",
        "library": "N/A",
        "algorithm": "N/A",
        "description": "Potential API key/secret"
    },
}


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class CryptoMatch:
    """Represents a detected crypto pattern match."""
    pattern_name: str
    library: str
    algorithm: str
    description: str
    line_number: int
    context: str  # Surrounding code
    confidence: float = 0.0


@dataclass
class ParseResult:
    """Result of parsing a JavaScript file."""
    filepath: str
    file_size: int
    matches: list[CryptoMatch] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    api_calls: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# =============================================================================
# JavaScript Parser Class
# =============================================================================


class JSCryptoParser:
    """
    Parses JavaScript files to detect crypto patterns.
    
    Uses regex-based pattern matching for initial detection.
    TODO: Implement full AST parsing for more accurate analysis.
    """
    
    def __init__(
        self,
        output_dir: Path = DEFAULT_OUTPUT_DIR
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: list[ParseResult] = []
    
    def parse_file(self, filepath: Path) -> ParseResult:
        """
        Parse a JavaScript file for crypto patterns.
        
        Args:
            filepath: Path to the JS file
            
        Returns:
            ParseResult with detected patterns
        """
        result = ParseResult(
            filepath=str(filepath),
            file_size=filepath.stat().st_size
        )
        
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")
            
            # Pattern-based detection
            for pattern_name, pattern_info in CRYPTO_PATTERNS.items():
                for match in re.finditer(pattern_info["pattern"], content, re.IGNORECASE):
                    # Find line number
                    line_number = content[:match.start()].count("\n") + 1
                    
                    # Get context (surrounding lines)
                    start_line = max(0, line_number - 2)
                    end_line = min(len(lines), line_number + 2)
                    context = "\n".join(lines[start_line:end_line])
                    
                    crypto_match = CryptoMatch(
                        pattern_name=pattern_name,
                        library=pattern_info["library"],
                        algorithm=pattern_info["algorithm"],
                        description=pattern_info["description"],
                        line_number=line_number,
                        context=context,
                        confidence=0.8  # High confidence for exact pattern match
                    )
                    result.matches.append(crypto_match)
            
            # Extract function names (simple regex-based)
            result.functions = self._extract_functions(content)
            
            # Extract potential API calls
            result.api_calls = self._extract_api_calls(content)
            
        except Exception as e:
            result.errors.append(str(e))
            console.print(f"[red]Error parsing {filepath}:[/red] {e}")
        
        self.results.append(result)
        return result
    
    def _extract_functions(self, content: str) -> list[str]:
        """Extract function names from JavaScript content."""
        functions = []
        
        # Match various function declaration patterns
        patterns = [
            r"function\s+(\w+)\s*\(",  # function foo()
            r"(\w+)\s*=\s*function\s*\(",  # foo = function()
            r"(\w+)\s*:\s*function\s*\(",  # foo: function()
            r"const\s+(\w+)\s*=\s*\([^)]*\)\s*=>",  # const foo = () =>
            r"(\w+)\s*=\s*\([^)]*\)\s*=>",  # foo = () =>
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                func_name = match.group(1)
                if func_name and func_name not in functions:
                    functions.append(func_name)
        
        return functions[:50]  # Limit to first 50 functions
    
    def _extract_api_calls(self, content: str) -> list[dict]:
        """Extract potential API call patterns."""
        api_calls = []
        
        # Match fetch, axios, XMLHttpRequest patterns
        patterns = [
            (r"fetch\s*\(\s*['\"]([^'\"]+)['\"]", "fetch"),
            (r"axios\.(get|post|put|delete)\s*\(\s*['\"]([^'\"]+)['\"]", "axios"),
            (r"\.ajax\s*\(\s*\{[^}]*url\s*:\s*['\"]([^'\"]+)['\"]", "jQuery.ajax"),
            (r"XMLHttpRequest.*\.open\s*\([^,]*,\s*['\"]([^'\"]+)['\"]", "XHR"),
        ]
        
        for pattern, method in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                url = match.group(1) if method != "axios" else match.group(2)
                api_calls.append({
                    "method": method,
                    "url": url,
                    "line": content[:match.start()].count("\n") + 1
                })
        
        return api_calls[:20]  # Limit results
    
    def parse_directory(self, input_dir: Path) -> list[ParseResult]:
        """
        Parse all JavaScript files in a directory.
        
        Args:
            input_dir: Directory containing JS files
            
        Returns:
            List of ParseResults
        """
        js_files = list(input_dir.rglob("*.js"))
        console.print(f"[cyan]Found {len(js_files)} JavaScript files[/cyan]")
        
        for filepath in js_files:
            console.print(f"  Parsing: {filepath.name}")
            self.parse_file(filepath)
        
        return self.results
    
    def save_results(self, filename: Optional[str] = None) -> Path:
        """
        Save parsing results to JSON.
        
        Args:
            filename: Output filename
            
        Returns:
            Path to saved file
        """
        if not filename:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"parse_results_{timestamp}.json"
        
        output_path = self.output_dir / filename
        
        # Convert dataclasses to dict
        output_data = {
            "parsed_at": datetime.now(timezone.utc).isoformat(),
            "total_files": len(self.results),
            "total_matches": sum(len(r.matches) for r in self.results),
            "results": []
        }
        
        for result in self.results:
            result_dict = {
                "filepath": result.filepath,
                "file_size": result.file_size,
                "matches": [
                    {
                        "pattern_name": m.pattern_name,
                        "library": m.library,
                        "algorithm": m.algorithm,
                        "description": m.description,
                        "line_number": m.line_number,
                        "context": m.context,
                        "confidence": m.confidence
                    }
                    for m in result.matches
                ],
                "functions_count": len(result.functions),
                "api_calls": result.api_calls,
                "errors": result.errors
            }
            output_data["results"].append(result_dict)
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]✓ Saved results to:[/green] {output_path}")
        return output_path
    
    def display_summary(self):
        """Display a summary of parsing results."""
        if not self.results:
            console.print("[yellow]No results to display[/yellow]")
            return
        
        # Summary table
        table = Table(title="Crypto Pattern Detection Summary")
        table.add_column("File", style="cyan", max_width=30)
        table.add_column("Size", style="green")
        table.add_column("Matches", style="yellow")
        table.add_column("Libraries Detected", style="magenta")
        
        for result in self.results:
            filepath = Path(result.filepath).name
            size = f"{result.file_size:,}"
            matches = str(len(result.matches))
            libraries = ", ".join(set(m.library for m in result.matches)) or "-"
            
            table.add_row(filepath, size, matches, libraries)
        
        console.print(table)
        
        # Detailed matches
        all_matches = [m for r in self.results for m in r.matches]
        if all_matches:
            console.print("\n[bold]Detected Crypto Patterns:[/bold]")
            match_table = Table()
            match_table.add_column("Pattern", style="cyan")
            match_table.add_column("Library", style="green")
            match_table.add_column("Algorithm", style="yellow")
            match_table.add_column("Count", style="magenta")
            
            # Group by pattern
            pattern_counts: dict[str, dict] = {}
            for m in all_matches:
                if m.pattern_name not in pattern_counts:
                    pattern_counts[m.pattern_name] = {
                        "library": m.library,
                        "algorithm": m.algorithm,
                        "count": 0
                    }
                pattern_counts[m.pattern_name]["count"] += 1
            
            for pattern, info in sorted(pattern_counts.items(), key=lambda x: -x[1]["count"]):
                match_table.add_row(
                    pattern,
                    info["library"],
                    info["algorithm"],
                    str(info["count"])
                )
            
            console.print(match_table)


# =============================================================================
# CLI Interface
# =============================================================================


def main():
    """Main entry point for JS parser."""
    parser = argparse.ArgumentParser(
        description="Parse JavaScript files for crypto patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Parse a directory of JS files
    python collect/parse_js.py --input collected_js/ --output analysis_results/
    
    # Parse a single file
    python collect/parse_js.py --file script.js
        """
    )
    
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help=f"Input directory containing JS files (default: {DEFAULT_INPUT_DIR})"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--file",
        type=Path,
        help="Parse a single JS file instead of a directory"
    )
    
    args = parser.parse_args()
    
    console.print("[bold cyan]═══ JavaScript Crypto Parser ═══[/bold cyan]\n")
    
    js_parser = JSCryptoParser(output_dir=args.output)
    
    if args.file:
        if not args.file.exists():
            console.print(f"[red]File not found:[/red] {args.file}")
            sys.exit(1)
        js_parser.parse_file(args.file)
    else:
        if not args.input.exists():
            console.print(f"[yellow]Input directory not found:[/yellow] {args.input}")
            console.print("[dim]Run fetch_js.py first to collect JavaScript files[/dim]")
            return
        js_parser.parse_directory(args.input)
    
    js_parser.display_summary()
    js_parser.save_results()


if __name__ == "__main__":
    main()
