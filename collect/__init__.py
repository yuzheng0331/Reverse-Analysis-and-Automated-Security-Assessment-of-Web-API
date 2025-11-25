"""
Collect Module
==============
Phase 2-3: JavaScript collection and parsing for crypto analysis.

Modules:
- fetch_js: Collect JavaScript files from web applications
- parse_js: Parse JavaScript for crypto patterns using AST analysis
"""

from pathlib import Path

# Module version
__version__ = "0.1.0"

# Default paths
COLLECTED_JS_DIR = Path(__file__).parent.parent / "collected_js"
ANALYSIS_RESULTS_DIR = Path(__file__).parent.parent / "analysis_results"
