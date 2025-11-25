#!/usr/bin/env python3
"""
Phase 8: Report Generator
==========================
Generates comprehensive security assessment reports.

This module:
- Aggregates all assessment results
- Generates HTML/Markdown/JSON reports
- Creates executive summaries
- Provides remediation guidance

Usage:
    python assess/report_gen.py --assessment assessment_results/
    python assess/report_gen.py --format html --output final_report.html
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
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

DEFAULT_ASSESSMENT_DIR = Path(__file__).parent.parent / "assessment_results"
DEFAULT_OUTPUT_DIR = Path(__file__).parent.parent / "reports"


# =============================================================================
# Report Templates
# =============================================================================

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Assessment Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .card h3 {{
            margin: 0 0 10px 0;
            color: #666;
            font-size: 14px;
        }}
        .card .value {{
            font-size: 32px;
            font-weight: bold;
        }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .section {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #f8f9fa;
        }}
        .severity-badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }}
        .severity-critical {{ background: #dc3545; color: white; }}
        .severity-high {{ background: #fd7e14; color: white; }}
        .severity-medium {{ background: #ffc107; color: black; }}
        .severity-low {{ background: #28a745; color: white; }}
        .score-gauge {{
            width: 100%;
            height: 20px;
            background: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
        }}
        .score-fill {{
            height: 100%;
            transition: width 0.5s;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 API Security Assessment Report</h1>
        <p>Report ID: {report_id}</p>
        <p>Generated: {generated_at}</p>
    </div>
    
    <div class="summary-cards">
        <div class="card">
            <h3>Overall Score</h3>
            <div class="value">{overall_score:.0f}/100</div>
            <div class="score-gauge">
                <div class="score-fill" style="width: {overall_score}%; background: {score_color};"></div>
            </div>
        </div>
        <div class="card">
            <h3>Endpoints Assessed</h3>
            <div class="value">{endpoints_assessed}</div>
        </div>
        <div class="card">
            <h3>Critical Issues</h3>
            <div class="value critical">{critical_count}</div>
        </div>
        <div class="card">
            <h3>High Issues</h3>
            <div class="value high">{high_count}</div>
        </div>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>{executive_summary}</p>
    </div>
    
    <div class="section">
        <h2>Vulnerability Details</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Endpoint</th>
                </tr>
            </thead>
            <tbody>
                {vulnerability_rows}
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>Remediation Recommendations</h2>
        {remediation_section}
    </div>
    
    <div class="section">
        <h2>Appendix: Crypto Analysis</h2>
        {crypto_section}
    </div>
</body>
</html>"""

MARKDOWN_TEMPLATE = """# API Security Assessment Report

**Report ID:** {report_id}  
**Generated:** {generated_at}

---

## Executive Summary

{executive_summary}

## Summary Statistics

| Metric | Value |
|--------|-------|
| Overall Score | {overall_score:.0f}/100 |
| Endpoints Assessed | {endpoints_assessed} |
| Total Vulnerabilities | {total_vulnerabilities} |
| Critical | {critical_count} |
| High | {high_count} |
| Medium | {medium_count} |
| Low | {low_count} |

## Vulnerability Details

{vulnerability_table}

## Remediation Recommendations

{remediation_section}

## Crypto Analysis Summary

{crypto_section}

---

*Generated by API Security Assessment Pipeline*
"""


# =============================================================================
# Report Generator Class
# =============================================================================


class ReportGenerator:
    """
    Generates comprehensive security assessment reports.
    
    Supports:
    - HTML reports with visual styling
    - Markdown reports for documentation
    - JSON reports for automation
    - Executive summaries
    """
    
    def __init__(
        self,
        output_dir: Path = DEFAULT_OUTPUT_DIR
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.assessment_data: Optional[dict] = None
    
    def load_assessment(self, assessment_path: Path) -> bool:
        """Load assessment data from JSON file."""
        if not assessment_path.exists():
            console.print(f"[red]Assessment file not found:[/red] {assessment_path}")
            return False
        
        try:
            with open(assessment_path, encoding="utf-8") as f:
                self.assessment_data = json.load(f)
            return True
        except json.JSONDecodeError as e:
            console.print(f"[red]Invalid JSON:[/red] {e}")
            return False
    
    def load_latest_assessment(self, assessment_dir: Path) -> bool:
        """Load the most recent assessment file."""
        if not assessment_dir.exists():
            console.print(f"[yellow]Assessment directory not found:[/yellow] {assessment_dir}")
            return False
        
        files = list(assessment_dir.glob("assessment_*.json"))
        if not files:
            console.print("[yellow]No assessment files found[/yellow]")
            return False
        
        latest = max(files, key=lambda p: p.stat().st_mtime)
        console.print(f"[cyan]Loading:[/cyan] {latest.name}")
        return self.load_assessment(latest)
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary text."""
        if not self.assessment_data:
            return "No assessment data available."
        
        summary = self.assessment_data.get("summary", {})
        total = summary.get("total_vulnerabilities", 0)
        critical = summary.get("by_severity", {}).get("critical", 0)
        high = summary.get("by_severity", {}).get("high", 0)
        score = summary.get("overall_score", 0)
        
        if critical > 0:
            risk_statement = f"The assessment identified **{critical} critical** security issues that require immediate attention."
        elif high > 0:
            risk_statement = f"The assessment identified **{high} high-severity** issues that should be addressed promptly."
        elif total > 0:
            risk_statement = f"The assessment identified **{total}** security findings of varying severity."
        else:
            risk_statement = "No significant security vulnerabilities were identified."
        
        score_statement = ""
        if score >= 80:
            score_statement = "The overall security posture is **good**."
        elif score >= 60:
            score_statement = "The overall security posture is **moderate** and could be improved."
        elif score >= 40:
            score_statement = "The overall security posture is **concerning** and requires attention."
        else:
            score_statement = "The overall security posture is **critical** and requires immediate remediation."
        
        return f"{risk_statement} {score_statement}"
    
    def generate_html(self, filename: Optional[str] = None) -> Path:
        """Generate HTML report."""
        if not self.assessment_data:
            console.print("[red]No assessment data loaded[/red]")
            return Path()
        
        if not filename:
            filename = f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"
        
        output_path = self.output_dir / filename
        
        summary = self.assessment_data.get("summary", {})
        score = summary.get("overall_score", 0)
        
        # Determine score color
        if score >= 80:
            score_color = "#28a745"
        elif score >= 60:
            score_color = "#ffc107"
        elif score >= 40:
            score_color = "#fd7e14"
        else:
            score_color = "#dc3545"
        
        # Generate vulnerability rows
        vuln_rows = []
        for assessment in self.assessment_data.get("assessments", []):
            endpoint = assessment.get("endpoint", "Unknown")
            for vuln in assessment.get("vulnerabilities", []):
                severity = vuln.get("severity", "medium")
                row = f"""
                <tr>
                    <td>{vuln.get('id', '-')}</td>
                    <td>{vuln.get('title', '-')}</td>
                    <td><span class="severity-badge severity-{severity}">{severity.upper()}</span></td>
                    <td>{vuln.get('category', '-')}</td>
                    <td>{endpoint[:50]}</td>
                </tr>
                """
                vuln_rows.append(row)
        
        # Generate remediation section
        remediation_items = []
        seen_ids = set()
        for assessment in self.assessment_data.get("assessments", []):
            for vuln in assessment.get("vulnerabilities", []):
                vid = vuln.get("id")
                if vid not in seen_ids:
                    seen_ids.add(vid)
                    remediation_items.append(f"""
                    <div style="margin-bottom: 15px;">
                        <h4>{vuln.get('id')}: {vuln.get('title')}</h4>
                        <p><strong>Remediation:</strong> {vuln.get('remediation', 'No specific remediation provided.')}</p>
                        {f"<p><strong>CWE:</strong> {vuln.get('cwe_id')}</p>" if vuln.get('cwe_id') else ''}
                    </div>
                    """)
        
        # Generate crypto section
        crypto_items = []
        for assessment in self.assessment_data.get("assessments", []):
            for issue in assessment.get("crypto_issues", []):
                crypto_items.append(f"""
                <li>{issue.get('algorithm', 'Unknown')} ({issue.get('library', 'Unknown library')}) - 
                    Security Level: {issue.get('security_level', 'unknown')}</li>
                """)
        
        html_content = HTML_TEMPLATE.format(
            report_id=self.assessment_data.get("report_id", "Unknown"),
            generated_at=self.assessment_data.get("generated_at", datetime.now(timezone.utc).isoformat()),
            overall_score=score,
            score_color=score_color,
            endpoints_assessed=summary.get("endpoints_assessed", 0),
            critical_count=summary.get("by_severity", {}).get("critical", 0),
            high_count=summary.get("by_severity", {}).get("high", 0),
            executive_summary=self.generate_executive_summary(),
            vulnerability_rows="\n".join(vuln_rows) if vuln_rows else "<tr><td colspan='5'>No vulnerabilities found</td></tr>",
            remediation_section="\n".join(remediation_items) if remediation_items else "<p>No specific remediations required.</p>",
            crypto_section=f"<ul>{''.join(crypto_items)}</ul>" if crypto_items else "<p>No crypto issues detected.</p>"
        )
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        console.print(f"[green]✓ Generated HTML report:[/green] {output_path}")
        return output_path
    
    def generate_markdown(self, filename: Optional[str] = None) -> Path:
        """Generate Markdown report."""
        if not self.assessment_data:
            console.print("[red]No assessment data loaded[/red]")
            return Path()
        
        if not filename:
            filename = f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md"
        
        output_path = self.output_dir / filename
        
        summary = self.assessment_data.get("summary", {})
        
        # Generate vulnerability table
        vuln_lines = ["| ID | Title | Severity | Category |", "|---|---|---|---|"]
        for assessment in self.assessment_data.get("assessments", []):
            for vuln in assessment.get("vulnerabilities", []):
                vuln_lines.append(
                    f"| {vuln.get('id', '-')} | {vuln.get('title', '-')} | "
                    f"{vuln.get('severity', '-').upper()} | {vuln.get('category', '-')} |"
                )
        
        # Generate remediation section
        remediation_lines = []
        seen_ids = set()
        for assessment in self.assessment_data.get("assessments", []):
            for vuln in assessment.get("vulnerabilities", []):
                vid = vuln.get("id")
                if vid not in seen_ids:
                    seen_ids.add(vid)
                    remediation_lines.append(f"### {vid}: {vuln.get('title')}")
                    remediation_lines.append(f"\n**Remediation:** {vuln.get('remediation', 'N/A')}")
                    if vuln.get("cwe_id"):
                        remediation_lines.append(f"\n**CWE:** {vuln.get('cwe_id')}")
                    remediation_lines.append("")
        
        # Generate crypto section
        crypto_lines = []
        for assessment in self.assessment_data.get("assessments", []):
            for issue in assessment.get("crypto_issues", []):
                crypto_lines.append(
                    f"- **{issue.get('algorithm', 'Unknown')}** ({issue.get('library', 'Unknown')}) - "
                    f"Level: {issue.get('security_level', 'unknown')}"
                )
        
        md_content = MARKDOWN_TEMPLATE.format(
            report_id=self.assessment_data.get("report_id", "Unknown"),
            generated_at=self.assessment_data.get("generated_at", datetime.now(timezone.utc).isoformat()),
            executive_summary=self.generate_executive_summary(),
            overall_score=summary.get("overall_score", 0),
            endpoints_assessed=summary.get("endpoints_assessed", 0),
            total_vulnerabilities=summary.get("total_vulnerabilities", 0),
            critical_count=summary.get("by_severity", {}).get("critical", 0),
            high_count=summary.get("by_severity", {}).get("high", 0),
            medium_count=summary.get("by_severity", {}).get("medium", 0),
            low_count=summary.get("by_severity", {}).get("low", 0),
            vulnerability_table="\n".join(vuln_lines),
            remediation_section="\n".join(remediation_lines) if remediation_lines else "No remediations required.",
            crypto_section="\n".join(crypto_lines) if crypto_lines else "No crypto issues detected."
        )
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        
        console.print(f"[green]✓ Generated Markdown report:[/green] {output_path}")
        return output_path
    
    def generate_json(self, filename: Optional[str] = None) -> Path:
        """Generate JSON report (copy with additional metadata)."""
        if not self.assessment_data:
            console.print("[red]No assessment data loaded[/red]")
            return Path()
        
        if not filename:
            filename = f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        
        output_path = self.output_dir / filename
        
        report_data = {
            "report_format": "json",
            "report_version": "1.0",
            "executive_summary": self.generate_executive_summary(),
            **self.assessment_data
        }
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]✓ Generated JSON report:[/green] {output_path}")
        return output_path
    
    def display_preview(self):
        """Display report preview in terminal."""
        if not self.assessment_data:
            console.print("[yellow]No assessment data loaded[/yellow]")
            return
        
        console.print(Panel(
            "[bold]Report Preview[/bold]",
            style="cyan"
        ))
        
        console.print(f"\n[bold]Executive Summary:[/bold]")
        console.print(self.generate_executive_summary().replace("**", ""))
        
        summary = self.assessment_data.get("summary", {})
        console.print(f"\n[bold]Statistics:[/bold]")
        console.print(f"  Score: {summary.get('overall_score', 0):.0f}/100")
        console.print(f"  Endpoints: {summary.get('endpoints_assessed', 0)}")
        console.print(f"  Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")


# =============================================================================
# CLI Interface
# =============================================================================


def main():
    """Main entry point for report generator."""
    parser = argparse.ArgumentParser(
        description="Generate security assessment reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Generate all report formats
    python assess/report_gen.py --assessment assessment_results/
    
    # Generate specific format
    python assess/report_gen.py --format html --output my_report.html
    
    # From specific assessment file
    python assess/report_gen.py --file assessment_ASM-20231201.json --format markdown
        """
    )
    
    parser.add_argument(
        "--assessment",
        type=Path,
        default=DEFAULT_ASSESSMENT_DIR,
        help=f"Assessment results directory (default: {DEFAULT_ASSESSMENT_DIR})"
    )
    parser.add_argument(
        "--file",
        type=Path,
        help="Specific assessment JSON file to use"
    )
    parser.add_argument(
        "--format",
        choices=["html", "markdown", "json", "all"],
        default="all",
        help="Report format (default: all)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})"
    )
    
    args = parser.parse_args()
    
    console.print("[bold cyan]═══ Report Generator ═══[/bold cyan]\n")
    
    generator = ReportGenerator(output_dir=args.output)
    
    # Load assessment data
    if args.file:
        if not generator.load_assessment(args.file):
            return
    else:
        if not generator.load_latest_assessment(args.assessment):
            console.print("[dim]Run assess_endpoint.py first to generate assessment results[/dim]")
            return
    
    generator.display_preview()
    
    # Generate reports
    console.print("\n[cyan]Generating reports...[/cyan]")
    
    if args.format in ["html", "all"]:
        generator.generate_html()
    
    if args.format in ["markdown", "all"]:
        generator.generate_markdown()
    
    if args.format in ["json", "all"]:
        generator.generate_json()
    
    console.print("\n[green]✓ Report generation complete![/green]")


if __name__ == "__main__":
    main()
