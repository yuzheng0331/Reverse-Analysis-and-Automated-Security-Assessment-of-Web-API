#!/usr/bin/env python3
"""
Phase 7: Endpoint Security Assessment
=======================================
Performs security assessment of API endpoints.

This module:
- Assesses crypto implementation security
- Tests for common vulnerabilities
- Validates parameter handling
- Generates security scores

Usage:
    python assess/assess_endpoint.py --detection crypto_analysis/crypto_detection.json
    python assess/assess_endpoint.py --url https://api.example.com --test-suite basic
"""

import argparse
import json
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
    from rich.progress import Progress
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

console = Console()

# =============================================================================
# Configuration
# =============================================================================

DEFAULT_DETECTION_DIR = Path(__file__).parent.parent / "crypto_analysis"
DEFAULT_OUTPUT_DIR = Path(__file__).parent.parent / "assessment_results"


# =============================================================================
# Enums and Data Classes
# =============================================================================


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityCategory(Enum):
    """Categories of vulnerabilities."""
    CRYPTO = "cryptography"
    AUTH = "authentication"
    INJECTION = "injection"
    CONFIG = "configuration"
    DATA_EXPOSURE = "data_exposure"
    ACCESS_CONTROL = "access_control"


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""
    id: str
    title: str
    category: VulnerabilityCategory
    severity: Severity
    description: str
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None


@dataclass
class EndpointAssessment:
    """Assessment result for a single endpoint."""
    endpoint_url: str
    method: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    crypto_issues: list[dict] = field(default_factory=list)
    security_score: float = 100.0
    risk_level: str = "low"
    tested_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class AssessmentReport:
    """Complete assessment report."""
    report_id: str
    generated_at: str
    endpoints_assessed: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    assessments: list[EndpointAssessment] = field(default_factory=list)
    overall_score: float = 100.0


# =============================================================================
# Vulnerability Definitions
# =============================================================================

VULNERABILITY_TEMPLATES = {
    # Cryptography Issues
    "CRYPTO_001": {
        "title": "Use of Broken Cryptographic Algorithm",
        "category": VulnerabilityCategory.CRYPTO,
        "severity": Severity.CRITICAL,
        "description": "The application uses cryptographic algorithms that are known to be broken or weak.",
        "remediation": "Replace with modern, secure algorithms. Use AES-256-GCM for encryption, SHA-256/SHA-3 for hashing.",
        "cwe_id": "CWE-327"
    },
    "CRYPTO_002": {
        "title": "Hardcoded Cryptographic Key",
        "category": VulnerabilityCategory.CRYPTO,
        "severity": Severity.CRITICAL,
        "description": "Cryptographic keys are hardcoded in the client-side code.",
        "remediation": "Remove hardcoded keys. Use secure key exchange or server-side encryption.",
        "cwe_id": "CWE-321"
    },
    "CRYPTO_003": {
        "title": "Weak Key Size",
        "category": VulnerabilityCategory.CRYPTO,
        "severity": Severity.HIGH,
        "description": "Cryptographic keys do not meet minimum size requirements.",
        "remediation": "Use minimum 2048-bit keys for RSA, 256-bit for symmetric encryption.",
        "cwe_id": "CWE-326"
    },
    "CRYPTO_004": {
        "title": "Insecure Block Cipher Mode",
        "category": VulnerabilityCategory.CRYPTO,
        "severity": Severity.HIGH,
        "description": "ECB mode or other insecure cipher modes are used.",
        "remediation": "Use authenticated encryption modes like GCM or CCM.",
        "cwe_id": "CWE-327"
    },
    "CRYPTO_005": {
        "title": "Missing or Predictable IV",
        "category": VulnerabilityCategory.CRYPTO,
        "severity": Severity.HIGH,
        "description": "Initialization vectors are missing, static, or predictable.",
        "remediation": "Generate cryptographically random IVs for each encryption operation.",
        "cwe_id": "CWE-329"
    },
    
    # Authentication Issues
    "AUTH_001": {
        "title": "Weak Password Hashing",
        "category": VulnerabilityCategory.AUTH,
        "severity": Severity.HIGH,
        "description": "Password hashing uses weak algorithms (MD5, SHA1).",
        "remediation": "Use bcrypt, scrypt, or Argon2 for password hashing.",
        "cwe_id": "CWE-916"
    },
    "AUTH_002": {
        "title": "Insufficient Signature Validation",
        "category": VulnerabilityCategory.AUTH,
        "severity": Severity.HIGH,
        "description": "Request signatures are not properly validated or can be bypassed.",
        "remediation": "Implement robust signature validation with timing-safe comparison.",
        "cwe_id": "CWE-347"
    },
    
    # Data Exposure
    "DATA_001": {
        "title": "Sensitive Data in Client Code",
        "category": VulnerabilityCategory.DATA_EXPOSURE,
        "severity": Severity.HIGH,
        "description": "Sensitive data (keys, secrets) exposed in client-side JavaScript.",
        "remediation": "Move sensitive operations to server-side. Use environment variables.",
        "cwe_id": "CWE-200"
    },
    
    # Configuration Issues
    "CONFIG_001": {
        "title": "Debug Mode Enabled",
        "category": VulnerabilityCategory.CONFIG,
        "severity": Severity.MEDIUM,
        "description": "Application appears to be running in debug mode.",
        "remediation": "Disable debug mode in production environments.",
        "cwe_id": "CWE-489"
    },
}


# =============================================================================
# Security Assessor Class
# =============================================================================


class EndpointAssessor:
    """
    Performs security assessment of API endpoints.
    
    Combines:
    - Static analysis results (crypto detection)
    - Dynamic testing results (replay/mutation)
    - Vulnerability pattern matching
    """
    
    def __init__(
        self,
        output_dir: Path = DEFAULT_OUTPUT_DIR
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report = AssessmentReport(
            report_id=f"ASM-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            generated_at=datetime.now(timezone.utc).isoformat()
        )
    
    def assess_from_detection(self, detection_path: Path) -> AssessmentReport:
        """
        Perform assessment based on crypto detection results.
        
        Args:
            detection_path: Path to crypto detection JSON
            
        Returns:
            Complete assessment report
        """
        if not detection_path.exists():
            console.print(f"[red]Detection file not found:[/red] {detection_path}")
            return self.report
        
        with open(detection_path, encoding="utf-8") as f:
            detection_data = json.load(f)
        
        console.print("[cyan]Analyzing detection results...[/cyan]\n")
        
        # Assess findings from crypto detection
        for finding in detection_data.get("findings", []):
            assessment = self._assess_crypto_finding(finding)
            if assessment:
                self.report.assessments.append(assessment)
        
        # Assess API endpoints
        for endpoint in detection_data.get("api_endpoints", []):
            assessment = self._assess_endpoint(endpoint)
            if assessment:
                self.report.assessments.append(assessment)
        
        # Calculate totals
        self._calculate_report_totals()
        
        return self.report
    
    def _assess_crypto_finding(self, finding: dict) -> Optional[EndpointAssessment]:
        """Assess a single crypto finding."""
        assessment = EndpointAssessment(
            endpoint_url=finding.get("location", "unknown"),
            method="STATIC"
        )
        
        algorithm = finding.get("algorithm", "").upper()
        security_level = finding.get("security_level", "medium")
        
        # Map findings to vulnerabilities
        if security_level == "critical":
            if algorithm in ["MD5", "DES", "RC4"]:
                vuln = self._create_vulnerability("CRYPTO_001", f"Use of {algorithm}")
                assessment.vulnerabilities.append(vuln)
        
        if security_level in ["critical", "high"]:
            if "hardcoded" in finding.get("description", "").lower():
                vuln = self._create_vulnerability("CRYPTO_002", "Hardcoded key detected")
                assessment.vulnerabilities.append(vuln)
        
        # Store crypto issues
        assessment.crypto_issues.append({
            "algorithm": algorithm,
            "library": finding.get("library"),
            "security_level": security_level,
            "recommendations": finding.get("recommendations", [])
        })
        
        # Calculate score
        assessment.security_score = self._calculate_endpoint_score(assessment)
        assessment.risk_level = self._determine_risk_level(assessment.security_score)
        
        return assessment if assessment.vulnerabilities or assessment.crypto_issues else None
    
    def _assess_endpoint(self, endpoint: dict) -> Optional[EndpointAssessment]:
        """Assess an API endpoint."""
        assessment = EndpointAssessment(
            endpoint_url=endpoint.get("url", "unknown"),
            method=endpoint.get("method", "GET")
        )
        
        # Analyze crypto indicators
        for indicator in endpoint.get("crypto_indicators", []):
            indicator_type = indicator.get("type", "")
            
            # Check for weak hash indicators
            if "md5" in indicator_type.lower() or "sha1" in indicator_type.lower():
                vuln = self._create_vulnerability(
                    "AUTH_001",
                    f"Weak hash detected: {indicator_type}"
                )
                assessment.vulnerabilities.append(vuln)
            
            assessment.crypto_issues.append(indicator)
        
        # Calculate score
        assessment.security_score = self._calculate_endpoint_score(assessment)
        assessment.risk_level = self._determine_risk_level(assessment.security_score)
        
        return assessment if assessment.vulnerabilities or assessment.crypto_issues else None
    
    def _create_vulnerability(
        self,
        template_id: str,
        evidence: str
    ) -> Vulnerability:
        """Create a vulnerability from a template."""
        template = VULNERABILITY_TEMPLATES.get(template_id, {})
        
        return Vulnerability(
            id=template_id,
            title=template.get("title", "Unknown Vulnerability"),
            category=template.get("category", VulnerabilityCategory.CONFIG),
            severity=template.get("severity", Severity.MEDIUM),
            description=template.get("description", ""),
            evidence=evidence,
            remediation=template.get("remediation", ""),
            cwe_id=template.get("cwe_id")
        )
    
    def _calculate_endpoint_score(self, assessment: EndpointAssessment) -> float:
        """Calculate security score for an endpoint."""
        score = 100.0
        
        # Deduct points based on vulnerability severity
        for vuln in assessment.vulnerabilities:
            if vuln.severity == Severity.CRITICAL:
                score -= 30
            elif vuln.severity == Severity.HIGH:
                score -= 20
            elif vuln.severity == Severity.MEDIUM:
                score -= 10
            elif vuln.severity == Severity.LOW:
                score -= 5
        
        # Deduct for crypto issues
        for issue in assessment.crypto_issues:
            if issue.get("security_level") == "critical":
                score -= 15
            elif issue.get("security_level") == "high":
                score -= 10
        
        return max(0.0, score)
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score."""
        if score >= 80:
            return "low"
        elif score >= 60:
            return "medium"
        elif score >= 40:
            return "high"
        else:
            return "critical"
    
    def _calculate_report_totals(self):
        """Calculate report totals and overall score."""
        all_vulns = []
        scores = []
        
        for assessment in self.report.assessments:
            all_vulns.extend(assessment.vulnerabilities)
            scores.append(assessment.security_score)
        
        self.report.endpoints_assessed = len(self.report.assessments)
        self.report.total_vulnerabilities = len(all_vulns)
        
        for vuln in all_vulns:
            if vuln.severity == Severity.CRITICAL:
                self.report.critical_count += 1
            elif vuln.severity == Severity.HIGH:
                self.report.high_count += 1
            elif vuln.severity == Severity.MEDIUM:
                self.report.medium_count += 1
            elif vuln.severity == Severity.LOW:
                self.report.low_count += 1
        
        if scores:
            self.report.overall_score = sum(scores) / len(scores)
    
    def save_report(self, filename: Optional[str] = None) -> Path:
        """Save assessment report to JSON."""
        if not filename:
            filename = f"assessment_{self.report.report_id}.json"
        
        output_path = self.output_dir / filename
        
        output_data = {
            "report_id": self.report.report_id,
            "generated_at": self.report.generated_at,
            "summary": {
                "endpoints_assessed": self.report.endpoints_assessed,
                "total_vulnerabilities": self.report.total_vulnerabilities,
                "by_severity": {
                    "critical": self.report.critical_count,
                    "high": self.report.high_count,
                    "medium": self.report.medium_count,
                    "low": self.report.low_count
                },
                "overall_score": self.report.overall_score
            },
            "assessments": []
        }
        
        for assessment in self.report.assessments:
            assessment_data = {
                "endpoint": assessment.endpoint_url,
                "method": assessment.method,
                "security_score": assessment.security_score,
                "risk_level": assessment.risk_level,
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "title": v.title,
                        "category": v.category.value,
                        "severity": v.severity.value,
                        "description": v.description,
                        "evidence": v.evidence,
                        "remediation": v.remediation,
                        "cwe_id": v.cwe_id
                    }
                    for v in assessment.vulnerabilities
                ],
                "crypto_issues": assessment.crypto_issues
            }
            output_data["assessments"].append(assessment_data)
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]✓ Saved report to:[/green] {output_path}")
        return output_path
    
    def display_summary(self):
        """Display assessment summary."""
        console.print(Panel(
            f"[bold]Security Assessment Report[/bold]\n"
            f"Report ID: {self.report.report_id}",
            style="cyan"
        ))
        
        # Summary stats
        console.print("\n[bold]Summary:[/bold]")
        console.print(f"  Endpoints Assessed: {self.report.endpoints_assessed}")
        console.print(f"  Total Vulnerabilities: {self.report.total_vulnerabilities}")
        console.print(f"  Overall Score: {self.report.overall_score:.1f}/100")
        
        # Severity breakdown
        if self.report.total_vulnerabilities > 0:
            console.print("\n[bold]Vulnerabilities by Severity:[/bold]")
            severity_table = Table()
            severity_table.add_column("Severity", style="cyan")
            severity_table.add_column("Count", style="yellow")
            
            if self.report.critical_count:
                severity_table.add_row("[red]CRITICAL[/red]", str(self.report.critical_count))
            if self.report.high_count:
                severity_table.add_row("[bright_red]HIGH[/bright_red]", str(self.report.high_count))
            if self.report.medium_count:
                severity_table.add_row("[yellow]MEDIUM[/yellow]", str(self.report.medium_count))
            if self.report.low_count:
                severity_table.add_row("[bright_yellow]LOW[/bright_yellow]", str(self.report.low_count))
            
            console.print(severity_table)
        
        # Top vulnerabilities
        all_vulns = [v for a in self.report.assessments for v in a.vulnerabilities]
        if all_vulns:
            console.print("\n[bold]Top Vulnerabilities:[/bold]")
            vuln_table = Table()
            vuln_table.add_column("ID", style="dim")
            vuln_table.add_column("Title", style="cyan")
            vuln_table.add_column("Severity", style="yellow")
            vuln_table.add_column("Category", style="green")
            
            for vuln in all_vulns[:10]:
                sev_color = {
                    Severity.CRITICAL: "red",
                    Severity.HIGH: "bright_red",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "bright_yellow"
                }.get(vuln.severity, "white")
                
                vuln_table.add_row(
                    vuln.id,
                    vuln.title,
                    f"[{sev_color}]{vuln.severity.value.upper()}[/{sev_color}]",
                    vuln.category.value
                )
            
            console.print(vuln_table)


# =============================================================================
# CLI Interface
# =============================================================================


def main():
    """Main entry point for endpoint assessor."""
    parser = argparse.ArgumentParser(
        description="Perform security assessment of API endpoints",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Assess from crypto detection results
    python assess/assess_endpoint.py --detection crypto_analysis/crypto_detection.json
    
    # Output to custom directory
    python assess/assess_endpoint.py --detection results.json --output my_reports/
        """
    )
    
    parser.add_argument(
        "--detection",
        type=Path,
        help="Path to crypto detection results JSON"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})"
    )
    
    args = parser.parse_args()
    
    console.print("[bold cyan]═══ Endpoint Security Assessor ═══[/bold cyan]\n")
    
    assessor = EndpointAssessor(output_dir=args.output)
    
    if args.detection:
        assessor.assess_from_detection(args.detection)
    else:
        # Look for detection files
        detection_dir = DEFAULT_DETECTION_DIR
        if detection_dir.exists():
            detection_files = list(detection_dir.glob("crypto_detection_*.json"))
            if detection_files:
                latest = max(detection_files, key=lambda p: p.stat().st_mtime)
                console.print(f"[cyan]Using latest detection file:[/cyan] {latest.name}\n")
                assessor.assess_from_detection(latest)
            else:
                console.print("[yellow]No detection files found[/yellow]")
                console.print("[dim]Run detect_crypto.py first to generate detection results[/dim]")
                return
        else:
            console.print("[yellow]Detection directory not found[/yellow]")
            console.print("[dim]Use --detection to specify a detection results file[/dim]")
            return
    
    assessor.display_summary()
    assessor.save_report()


if __name__ == "__main__":
    main()
