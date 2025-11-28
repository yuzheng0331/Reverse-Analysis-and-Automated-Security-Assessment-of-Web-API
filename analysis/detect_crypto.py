#!/usr/bin/env python3
"""
Phase 4: Crypto Detection Engine
=================================
Analyzes collected data to detect and classify cryptographic implementations.

This module:
- Identifies crypto algorithms used in API communications
- Classifies encryption types (symmetric, asymmetric, hash)
- Extracts key/IV patterns and parameter structures
- Maps crypto operations to API endpoints

Usage:
    python analysis/detect_crypto.py --input analysis_results/ --baseline baseline_samples/
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

console = Console()

# =============================================================================
# Configuration
# =============================================================================

DEFAULT_INPUT_DIR = Path(__file__).parent.parent / "analysis_results"
DEFAULT_BASELINE_DIR = Path(__file__).parent.parent / "baseline_samples"
DEFAULT_OUTPUT_DIR = Path(__file__).parent.parent / "crypto_analysis"


# =============================================================================
# Enums and Data Classes
# =============================================================================


class CryptoType(Enum):
    """Types of cryptographic operations."""
    SYMMETRIC = "symmetric"  # AES, DES, etc.
    ASYMMETRIC = "asymmetric"  # RSA, ECC, etc.
    HASH = "hash"  # MD5, SHA, etc.
    MAC = "mac"  # HMAC, etc.
    ENCODING = "encoding"  # Base64, etc.
    UNKNOWN = "unknown"


class SecurityLevel(Enum):
    """Security assessment levels."""
    CRITICAL = "critical"  # Broken/weak crypto
    HIGH = "high"  # Potentially weak
    MEDIUM = "medium"  # Could be improved
    LOW = "low"  # Minor issues
    INFO = "info"  # Informational
    SECURE = "secure"  # Good implementation


@dataclass
class CryptoFinding:
    """Represents a detected crypto implementation."""
    crypto_type: CryptoType
    algorithm: str
    library: str
    security_level: SecurityLevel
    description: str
    location: str  # File/endpoint where found
    details: dict = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class DetectionResult:
    """Result of crypto detection analysis."""
    timestamp: str
    findings: list[CryptoFinding] = field(default_factory=list)
    api_endpoints: list[dict] = field(default_factory=list)
    crypto_map: dict = field(default_factory=dict)  # endpoint -> crypto used


# =============================================================================
# Crypto Detector Class
# =============================================================================


class CryptoDetector:
    """
    Detects and analyzes cryptographic implementations in API traffic.
    
    Combines:
    - JS parsing results (static analysis)
    - Baseline request/response samples (dynamic analysis)
    - Signature database patterns
    """
    
    def __init__(
        self,
        output_dir: Path = DEFAULT_OUTPUT_DIR
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.result = DetectionResult(timestamp=datetime.now(timezone.utc).isoformat())
        
        # Load signature database
        from analysis.signature_db import SignatureDatabase
        self.sig_db = SignatureDatabase()
    
    def analyze_parse_results(self, parse_results_path: Path) -> list[CryptoFinding]:
        """
        Analyze JS parsing results for crypto patterns.
        
        Args:
            parse_results_path: Path to parse_results JSON
            
        Returns:
            List of crypto findings
        """
        findings = []
        
        if not parse_results_path.exists():
            console.print(f"[yellow]Parse results not found:[/yellow] {parse_results_path}")
            return findings
        
        with open(parse_results_path, encoding="utf-8") as f:
            data = json.load(f)
        
        for result in data.get("results", []):
            for match in result.get("matches", []):
                finding = self._analyze_pattern_match(match, result["filepath"])
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _analyze_pattern_match(self, match: dict, filepath: str) -> Optional[CryptoFinding]:
        """Analyze a single pattern match and create a finding."""
        algorithm = match.get("algorithm", "Unknown")
        library = match.get("library", "Unknown")
        
        # Determine crypto type
        crypto_type = CryptoType.UNKNOWN
        if algorithm.upper() in ["AES", "DES", "3DES", "BLOWFISH", "RC4"]:
            crypto_type = CryptoType.SYMMETRIC
        elif algorithm.upper() in ["RSA", "ECC", "ECDSA", "DSA"]:
            crypto_type = CryptoType.ASYMMETRIC
        elif algorithm.upper() in ["MD5", "SHA", "SHA1", "SHA256", "SHA512"]:
            crypto_type = CryptoType.HASH
        elif algorithm.upper() in ["HMAC"]:
            crypto_type = CryptoType.MAC
        elif algorithm.upper() in ["BASE64"]:
            crypto_type = CryptoType.ENCODING
        
        # Assess security level
        security_level = self._assess_security(algorithm, library)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(algorithm, security_level)
        
        return CryptoFinding(
            crypto_type=crypto_type,
            algorithm=algorithm,
            library=library,
            security_level=security_level,
            description=match.get("description", ""),
            location=f"{filepath}:{match.get('line_number', '?')}",
            details={
                "pattern_name": match.get("pattern_name"),
                "confidence": match.get("confidence", 0),
                "context": match.get("context", "")[:200]
            },
            recommendations=recommendations
        )
    
    def _assess_security(self, algorithm: str, library: str) -> SecurityLevel:
        """Assess the security level of a crypto implementation."""
        algo_upper = algorithm.upper()
        
        # Critical: Known broken
        if algo_upper in ["MD5", "SHA1", "DES", "RC4"]:
            return SecurityLevel.CRITICAL
        
        # High: Potentially weak
        if algo_upper in ["3DES"]:
            return SecurityLevel.HIGH
        
        # Medium: Depends on implementation
        if algo_upper in ["AES", "RSA"]:
            return SecurityLevel.MEDIUM
        
        # Encoding is just informational
        if algo_upper in ["BASE64"]:
            return SecurityLevel.INFO
        
        return SecurityLevel.MEDIUM
    
    def _generate_recommendations(
        self,
        algorithm: str,
        security_level: SecurityLevel
    ) -> list[str]:
        """Generate security recommendations."""
        recommendations = []
        algo_upper = algorithm.upper()
        
        if algo_upper == "MD5":
            recommendations.extend([
                "MD5 is cryptographically broken - do not use for security",
                "Replace with SHA-256 or SHA-3 for hashing",
                "Use bcrypt, scrypt, or Argon2 for password hashing"
            ])
        elif algo_upper == "SHA1":
            recommendations.extend([
                "SHA-1 has known collision attacks",
                "Migrate to SHA-256 or SHA-3"
            ])
        elif algo_upper == "DES":
            recommendations.extend([
                "DES uses only 56-bit keys - easily broken",
                "Migrate to AES-256"
            ])
        elif algo_upper == "AES":
            recommendations.extend([
                "Ensure using AES-256 with secure mode (GCM preferred)",
                "Verify IV is randomly generated for each encryption",
                "Check for hardcoded keys in client code"
            ])
        elif algo_upper == "RSA":
            recommendations.extend([
                "Ensure key size is at least 2048 bits",
                "Use OAEP padding, not PKCS#1 v1.5",
                "Check if private key is exposed in client code"
            ])
        
        return recommendations
    
    def analyze_baseline(self, baseline_dir: Path) -> list[dict]:
        """
        Analyze baseline request/response samples.
        
        Args:
            baseline_dir: Directory containing baseline samples
            
        Returns:
            List of API endpoint analysis
        """
        endpoints = []
        
        if not baseline_dir.exists():
            console.print(f"[yellow]Baseline directory not found:[/yellow] {baseline_dir}")
            return endpoints
        
        for sample_file in baseline_dir.glob("*.json"):
            try:
                with open(sample_file, encoding="utf-8") as f:
                    data = json.load(f)
                
                for request in data.get("requests", []):
                    endpoint = self._analyze_request(request)
                    if endpoint:
                        endpoints.append(endpoint)
                        
            except json.JSONDecodeError as e:
                console.print(f"[yellow]Invalid JSON in {sample_file}:[/yellow] {e}")
        
        return endpoints
    
    def _analyze_request(self, request: dict) -> Optional[dict]:
        """Analyze a single request for crypto patterns."""
        req_data = request.get("request", {})
        resp_data = request.get("response", {})
        metadata = request.get("metadata", {})
        
        endpoint = {
            "url": req_data.get("url", ""),
            "method": req_data.get("method", ""),
            "crypto_indicators": [],
            "parameters_analyzed": []
        }
        
        # Check request body for crypto patterns
        body = req_data.get("body", {})
        if isinstance(body, dict):
            for key, value in body.items():
                indicator = self._detect_param_crypto(key, str(value))
                if indicator:
                    endpoint["crypto_indicators"].append(indicator)
                    endpoint["parameters_analyzed"].append(key)
        
        # Check headers for crypto indicators
        headers = req_data.get("headers", {})
        for key, value in headers.items():
            if any(hint in key.lower() for hint in ["crypto", "sign", "token", "auth"]):
                endpoint["crypto_indicators"].append({
                    "type": "header",
                    "name": key,
                    "pattern": "potential_auth_crypto"
                })
        
        # Use metadata hints if available
        if metadata.get("crypto_indicators"):
            for hint in metadata["crypto_indicators"]:
                endpoint["crypto_indicators"].append({
                    "type": "metadata",
                    "description": hint
                })
        
        return endpoint if endpoint["crypto_indicators"] else None
    
    def _detect_param_crypto(self, param_name: str, param_value: str) -> Optional[dict]:
        """Detect crypto patterns in a parameter."""
        patterns = {
            "sign": ("signature", "Potential signature/HMAC"),
            "hash": ("hash", "Potential hash value"),
            "token": ("token", "Potential encrypted token"),
            "encrypted": ("encrypted", "Marked as encrypted"),
            "cipher": ("cipher", "Cipher text"),
        }
        
        # Check param name
        for pattern, (crypto_type, desc) in patterns.items():
            if pattern in param_name.lower():
                return {
                    "type": crypto_type,
                    "param_name": param_name,
                    "description": desc,
                    "value_length": len(param_value)
                }
        
        # Check value patterns (hex, base64, etc.)
        if re.match(r"^[a-fA-F0-9]{32,}$", param_value):
            return {
                "type": "hex_string",
                "param_name": param_name,
                "description": "Hex-encoded value (possible hash or encrypted data)",
                "value_length": len(param_value)
            }
        
        if re.match(r"^[A-Za-z0-9+/=]{20,}$", param_value) and len(param_value) % 4 == 0:
            return {
                "type": "base64",
                "param_name": param_name,
                "description": "Base64-encoded value",
                "value_length": len(param_value)
            }
        
        return None
    
    def run_analysis(
        self,
        parse_results_dir: Path,
        baseline_dir: Path
    ) -> DetectionResult:
        """
        Run full crypto detection analysis.

        Args:
            parse_results_dir: Directory with JS parse results
            baseline_dir: Directory with baseline samples

        Returns:
            Complete detection result
        """
        console.print("[cyan]Starting crypto detection analysis...[/cyan]\n")

        # Analyze JS parsing results
        for result_file in parse_results_dir.glob("parse_results_*.json"):
            console.print(f"  Analyzing: {result_file.name}")
            findings = self.analyze_parse_results(result_file)
            self.result.findings.extend(findings)

        # Analyze baseline samples
        console.print(f"\n  Analyzing baseline samples from: {baseline_dir}")
        endpoints = self.analyze_baseline(baseline_dir)
        self.result.api_endpoints = endpoints

        # Build crypto map
        for endpoint in endpoints:
            url = endpoint.get("url", "unknown")
            if url not in self.result.crypto_map:
                self.result.crypto_map[url] = []
            for indicator in endpoint.get("crypto_indicators", []):
                self.result.crypto_map[url].append(indicator.get("type", "unknown"))

        return self.result

    def save_results(self, filename: Optional[str] = None) -> Path:
        """Save detection results to JSON."""
        if not filename:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"crypto_detection_{timestamp}.json"
        
        output_path = self.output_dir / filename
        
        output_data = {
            "timestamp": self.result.timestamp,
            "summary": {
                "total_findings": len(self.result.findings),
                "total_endpoints": len(self.result.api_endpoints),
                "security_levels": {}
            },
            "findings": [],
            "api_endpoints": self.result.api_endpoints,
            "crypto_map": self.result.crypto_map
        }
        
        # Count by security level
        for finding in self.result.findings:
            level = finding.security_level.value
            output_data["summary"]["security_levels"][level] = \
                output_data["summary"]["security_levels"].get(level, 0) + 1
            
            output_data["findings"].append({
                "crypto_type": finding.crypto_type.value,
                "algorithm": finding.algorithm,
                "library": finding.library,
                "security_level": finding.security_level.value,
                "description": finding.description,
                "location": finding.location,
                "details": finding.details,
                "recommendations": finding.recommendations
            })
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]✓ Saved results to:[/green] {output_path}")
        return output_path
    
    def display_summary(self):
        """Display detection summary."""
        console.print(Panel("[bold]Crypto Detection Summary[/bold]", style="cyan"))
        
        # Findings by security level
        if self.result.findings:
            level_counts: dict[str, int] = {}
            for finding in self.result.findings:
                level = finding.security_level.value
                level_counts[level] = level_counts.get(level, 0) + 1
            
            table = Table(title="Findings by Security Level")
            table.add_column("Level", style="cyan")
            table.add_column("Count", style="yellow")
            
            level_colors = {
                "critical": "red",
                "high": "bright_red",
                "medium": "yellow",
                "low": "bright_yellow",
                "info": "blue",
                "secure": "green"
            }
            
            for level in ["critical", "high", "medium", "low", "info", "secure"]:
                if level in level_counts:
                    color = level_colors.get(level, "white")
                    table.add_row(f"[{color}]{level.upper()}[/{color}]", str(level_counts[level]))
            
            console.print(table)
        else:
            console.print("[yellow]No crypto findings detected[/yellow]")
        
        # API endpoints with crypto
        if self.result.api_endpoints:
            console.print(f"\n[cyan]Analyzed {len(self.result.api_endpoints)} API endpoints with crypto indicators[/cyan]")


# =============================================================================
# CLI Interface
# =============================================================================


def main():
    """Main entry point for crypto detection."""
    parser = argparse.ArgumentParser(
        description="Detect and analyze cryptographic implementations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Run full analysis
    python analysis/detect_crypto.py --input analysis_results/ --baseline baseline_samples/
    
    # Output to custom directory
    python analysis/detect_crypto.py --output my_analysis/
        """
    )
    
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help=f"Input directory with parse results (default: {DEFAULT_INPUT_DIR})"
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE_DIR,
        help=f"Baseline samples directory (default: {DEFAULT_BASELINE_DIR})"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})"
    )
    
    args = parser.parse_args()
    
    console.print("[bold cyan]═══ Crypto Detection Engine ═══[/bold cyan]\n")
    
    detector = CryptoDetector(output_dir=args.output)
    detector.run_analysis(args.input, args.baseline)
    detector.display_summary()
    detector.save_results()


if __name__ == "__main__":
    main()
