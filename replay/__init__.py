"""
Replay Module
=============
Phase 5-6: Request replay and parameter mutation.

Modules:
- replay_request: Replay captured requests with crypto transformations
- mutate_params: Generate parameter mutations for security testing
"""

from pathlib import Path

# Module version
__version__ = "0.1.0"

# Default paths
REPLAY_RESULTS_DIR = Path(__file__).parent.parent / "replay_results"
MUTATIONS_DIR = Path(__file__).parent.parent / "mutations"
