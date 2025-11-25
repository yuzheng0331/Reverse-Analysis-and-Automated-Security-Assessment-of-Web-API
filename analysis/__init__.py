"""
Analysis Module
===============
Phase 4: Crypto detection and analysis.

Modules:
- detect_crypto: Main crypto detection engine
- signature_db: Database of crypto signatures and patterns
"""

from pathlib import Path

# Module version
__version__ = "0.1.0"

# Default paths
CRYPTO_ANALYSIS_DIR = Path(__file__).parent.parent / "crypto_analysis"
