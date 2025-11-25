"""
Assess Module
=============
Phase 7-8: Security assessment and report generation.

Modules:
- assess_endpoint: Endpoint security assessment
- report_gen: Report generation (HTML/Markdown/JSON)
"""

from pathlib import Path

# Module version
__version__ = "0.1.0"

# Default paths
ASSESSMENT_RESULTS_DIR = Path(__file__).parent.parent / "assessment_results"
REPORTS_DIR = Path(__file__).parent.parent / "reports"
