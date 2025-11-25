#!/usr/bin/env python3
"""
Phase 6: Parameter Mutation Engine
===================================
Mutates API parameters for security testing.

This module:
- Generates parameter mutations for fuzzing
- Tests crypto parameter boundaries
- Identifies parameter validation weaknesses
- Supports various mutation strategies

Usage:
    python replay/mutate_params.py --baseline baseline_samples/sample_request.json
    python replay/mutate_params.py --params '{"user":"test","id":123}' --strategy all
"""

import argparse
import json
import random
import string
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Generator, Optional

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

DEFAULT_OUTPUT_DIR = Path(__file__).parent.parent / "mutations"


# =============================================================================
# Mutation Strategies
# =============================================================================


class MutationStrategy(Enum):
    """Types of parameter mutations."""
    BOUNDARY = "boundary"  # Boundary value testing
    TYPE_CONFUSION = "type_confusion"  # Type confusion attacks
    INJECTION = "injection"  # SQL/XSS/Command injection
    CRYPTO = "crypto"  # Crypto-specific mutations
    ENCODING = "encoding"  # Encoding variations
    EMPTY_NULL = "empty_null"  # Empty/null values
    OVERFLOW = "overflow"  # Buffer overflow attempts
    FORMAT = "format"  # Format string attacks


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class Mutation:
    """Represents a single parameter mutation."""
    param_name: str
    original_value: Any
    mutated_value: Any
    strategy: MutationStrategy
    description: str
    risk_level: str = "medium"  # low, medium, high


@dataclass
class MutationSet:
    """Set of mutations for a request."""
    original_params: dict
    mutations: list[Mutation] = field(default_factory=list)


# =============================================================================
# Mutation Generator Class
# =============================================================================


class ParameterMutator:
    """
    Generates parameter mutations for security testing.
    
    Supports various mutation strategies targeting:
    - Input validation weaknesses
    - Crypto implementation flaws
    - Injection vulnerabilities
    - Type confusion bugs
    """
    
    def __init__(
        self,
        output_dir: Path = DEFAULT_OUTPUT_DIR
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.mutation_sets: list[MutationSet] = []
    
    def generate_mutations(
        self,
        params: dict,
        strategies: Optional[list[MutationStrategy]] = None
    ) -> MutationSet:
        """
        Generate mutations for a parameter set.
        
        Args:
            params: Original parameters
            strategies: List of strategies to use (all if None)
            
        Returns:
            MutationSet with generated mutations
        """
        if strategies is None:
            strategies = list(MutationStrategy)
        
        mutation_set = MutationSet(original_params=params.copy())
        
        for param_name, param_value in params.items():
            for strategy in strategies:
                mutations = self._generate_for_param(param_name, param_value, strategy)
                mutation_set.mutations.extend(mutations)
        
        self.mutation_sets.append(mutation_set)
        return mutation_set
    
    def _generate_for_param(
        self,
        name: str,
        value: Any,
        strategy: MutationStrategy
    ) -> list[Mutation]:
        """Generate mutations for a single parameter."""
        mutations = []
        
        generators = {
            MutationStrategy.BOUNDARY: self._boundary_mutations,
            MutationStrategy.TYPE_CONFUSION: self._type_confusion_mutations,
            MutationStrategy.INJECTION: self._injection_mutations,
            MutationStrategy.CRYPTO: self._crypto_mutations,
            MutationStrategy.ENCODING: self._encoding_mutations,
            MutationStrategy.EMPTY_NULL: self._empty_null_mutations,
            MutationStrategy.OVERFLOW: self._overflow_mutations,
            MutationStrategy.FORMAT: self._format_mutations,
        }
        
        generator = generators.get(strategy)
        if generator:
            for mutated_value, description, risk in generator(name, value):
                mutations.append(Mutation(
                    param_name=name,
                    original_value=value,
                    mutated_value=mutated_value,
                    strategy=strategy,
                    description=description,
                    risk_level=risk
                ))
        
        return mutations
    
    def _boundary_mutations(
        self,
        name: str,
        value: Any
    ) -> Generator[tuple[Any, str, str], None, None]:
        """Generate boundary value mutations."""
        if isinstance(value, int):
            yield 0, "Integer zero", "low"
            yield -1, "Negative integer", "medium"
            yield 2147483647, "Max 32-bit integer", "medium"
            yield -2147483648, "Min 32-bit integer", "medium"
            yield 9999999999999999, "Very large integer", "high"
        elif isinstance(value, str):
            yield "", "Empty string", "low"
            yield "A" * 1000, "Long string (1000 chars)", "medium"
            yield "A" * 10000, "Very long string (10000 chars)", "high"
        elif isinstance(value, float):
            yield 0.0, "Float zero", "low"
            yield -0.0, "Negative zero", "low"
            yield float("inf"), "Infinity", "medium"
            yield float("-inf"), "Negative infinity", "medium"
    
    def _type_confusion_mutations(
        self,
        name: str,
        value: Any
    ) -> Generator[tuple[Any, str, str], None, None]:
        """Generate type confusion mutations."""
        # Convert to different types
        yield str(value), "Convert to string", "low"
        yield [value], "Wrap in array", "medium"
        yield {"value": value}, "Wrap in object", "medium"
        yield None, "Null value", "medium"
        yield True, "Boolean true", "low"
        yield False, "Boolean false", "low"
        
        if isinstance(value, str):
            try:
                yield int(value), "Parse as integer", "low"
            except (ValueError, TypeError):
                pass
    
    def _injection_mutations(
        self,
        name: str,
        value: Any
    ) -> Generator[tuple[Any, str, str], None, None]:
        """Generate injection attack mutations."""
        base = str(value)
        
        # SQL injection
        yield f"{base}'", "SQL injection - single quote", "high"
        yield f"{base}' OR '1'='1", "SQL injection - OR bypass", "high"
        yield f"{base}; DROP TABLE users--", "SQL injection - destructive", "high"
        
        # XSS
        yield f"<script>alert(1)</script>", "XSS - script tag", "high"
        yield f"{base}<img src=x onerror=alert(1)>", "XSS - img onerror", "high"
        yield f"javascript:alert(1)", "XSS - javascript protocol", "high"
        
        # Command injection
        yield f"{base}; ls", "Command injection - semicolon", "high"
        yield f"{base} | cat /etc/passwd", "Command injection - pipe", "high"
        yield f"{base}`id`", "Command injection - backticks", "high"
        
        # Path traversal
        yield f"../../../etc/passwd", "Path traversal", "high"
        yield f"....//....//etc/passwd", "Path traversal - bypass", "high"
    
    def _crypto_mutations(
        self,
        name: str,
        value: Any
    ) -> Generator[tuple[Any, str, str], None, None]:
        """Generate crypto-specific mutations."""
        val_str = str(value)
        
        # Signature manipulation
        if any(hint in name.lower() for hint in ["sign", "hash", "token", "auth"]):
            yield "", "Empty signature", "high"
            yield "a" * len(val_str), "Replaced signature (same length)", "high"
            yield val_str[:-1], "Truncated signature", "medium"
            yield val_str + "a", "Extended signature", "medium"
            yield val_str[::-1], "Reversed signature", "low"
        
        # Timestamp manipulation
        if any(hint in name.lower() for hint in ["time", "ts", "timestamp", "nonce"]):
            yield "0", "Zero timestamp", "medium"
            yield "9999999999999", "Future timestamp", "medium"
            yield "1", "Epoch timestamp", "medium"
            yield val_str + "000", "Extended timestamp", "low"
        
        # Key/IV manipulation
        if any(hint in name.lower() for hint in ["key", "iv", "secret"]):
            yield "0" * len(val_str), "All zeros", "high"
            yield "f" * len(val_str), "All 0xFF", "high"
    
    def _encoding_mutations(
        self,
        name: str,
        value: Any
    ) -> Generator[tuple[Any, str, str], None, None]:
        """Generate encoding variation mutations."""
        import base64
        import urllib.parse
        
        val_str = str(value)
        
        # URL encoding
        yield urllib.parse.quote(val_str), "URL encoded", "low"
        yield urllib.parse.quote_plus(val_str), "URL encoded (plus)", "low"
        
        # Base64
        yield base64.b64encode(val_str.encode()).decode(), "Base64 encoded", "low"
        
        # Double encoding
        yield urllib.parse.quote(urllib.parse.quote(val_str)), "Double URL encoded", "medium"
        
        # Unicode variations
        yield val_str.replace("a", "а"), "Unicode homograph (Cyrillic a)", "medium"  # noqa: RUF001
    
    def _empty_null_mutations(
        self,
        name: str,
        value: Any
    ) -> Generator[tuple[Any, str, str], None, None]:
        """Generate empty/null value mutations."""
        yield None, "Null", "medium"
        yield "", "Empty string", "low"
        yield [], "Empty array", "medium"
        yield {}, "Empty object", "medium"
        yield "null", "String 'null'", "low"
        yield "undefined", "String 'undefined'", "low"
        yield "\x00", "Null byte", "high"
    
    def _overflow_mutations(
        self,
        name: str,
        value: Any
    ) -> Generator[tuple[Any, str, str], None, None]:
        """Generate overflow mutations."""
        yield "A" * 256, "256 byte string", "medium"
        yield "A" * 1024, "1KB string", "medium"
        yield "A" * 65536, "64KB string", "high"
        yield "%n" * 100, "Format string overflow", "high"
        
        if isinstance(value, int):
            yield 2 ** 31 - 1, "INT32_MAX", "medium"
            yield 2 ** 31, "INT32_MAX + 1", "high"
            yield 2 ** 63 - 1, "INT64_MAX", "medium"
    
    def _format_mutations(
        self,
        name: str,
        value: Any
    ) -> Generator[tuple[Any, str, str], None, None]:
        """Generate format string mutations."""
        yield "%s%s%s%s%s", "Format string - %s", "high"
        yield "%n%n%n%n%n", "Format string - %n", "high"
        yield "%x%x%x%x%x", "Format string - %x", "high"
        yield "{0}{1}{2}", "Python format string", "medium"
        yield "{{7*7}}", "Template injection", "high"
    
    def save_mutations(self, filename: Optional[str] = None) -> Path:
        """Save generated mutations to JSON."""
        if not filename:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"mutations_{timestamp}.json"
        
        output_path = self.output_dir / filename
        
        output_data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_mutation_sets": len(self.mutation_sets),
            "mutation_sets": []
        }
        
        for mutation_set in self.mutation_sets:
            set_data = {
                "original_params": mutation_set.original_params,
                "total_mutations": len(mutation_set.mutations),
                "mutations": [
                    {
                        "param_name": m.param_name,
                        "original_value": str(m.original_value)[:100],
                        "mutated_value": str(m.mutated_value)[:100],
                        "strategy": m.strategy.value,
                        "description": m.description,
                        "risk_level": m.risk_level
                    }
                    for m in mutation_set.mutations
                ]
            }
            output_data["mutation_sets"].append(set_data)
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]✓ Saved mutations to:[/green] {output_path}")
        return output_path
    
    def display_summary(self):
        """Display mutations summary."""
        if not self.mutation_sets:
            console.print("[yellow]No mutations generated[/yellow]")
            return
        
        for idx, mutation_set in enumerate(self.mutation_sets):
            console.print(f"\n[bold]Mutation Set {idx + 1}[/bold]")
            console.print(f"Original params: {list(mutation_set.original_params.keys())}")
            
            # Group by strategy
            by_strategy: dict[str, list[Mutation]] = {}
            for mutation in mutation_set.mutations:
                strategy = mutation.strategy.value
                if strategy not in by_strategy:
                    by_strategy[strategy] = []
                by_strategy[strategy].append(mutation)
            
            table = Table(title=f"Mutations by Strategy ({len(mutation_set.mutations)} total)")
            table.add_column("Strategy", style="cyan")
            table.add_column("Count", style="yellow")
            table.add_column("Risk Levels", style="magenta")
            
            for strategy, mutations in sorted(by_strategy.items()):
                risks = set(m.risk_level for m in mutations)
                table.add_row(strategy, str(len(mutations)), ", ".join(risks))
            
            console.print(table)


# =============================================================================
# CLI Interface
# =============================================================================


def main():
    """Main entry point for parameter mutator."""
    parser = argparse.ArgumentParser(
        description="Generate parameter mutations for security testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Generate mutations from params
    python replay/mutate_params.py --params '{"username":"test","password":"123"}'
    
    # Specific strategies only
    python replay/mutate_params.py --params '{"id":123}' --strategy injection crypto
    
    # From baseline file
    python replay/mutate_params.py --baseline baseline_samples/sample_request.json

Available strategies:
    - boundary: Boundary value testing
    - type_confusion: Type confusion attacks
    - injection: SQL/XSS/Command injection
    - crypto: Crypto-specific mutations
    - encoding: Encoding variations
    - empty_null: Empty/null values
    - overflow: Buffer overflow attempts
    - format: Format string attacks
        """
    )
    
    parser.add_argument(
        "--params",
        help="JSON string of parameters to mutate"
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help="Baseline file to extract params from"
    )
    parser.add_argument(
        "--strategy",
        nargs="+",
        choices=[s.value for s in MutationStrategy],
        help="Strategies to use (default: all)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})"
    )
    
    args = parser.parse_args()
    
    console.print("[bold cyan]═══ Parameter Mutator ═══[/bold cyan]\n")
    
    mutator = ParameterMutator(output_dir=args.output)
    
    # Parse strategies
    strategies = None
    if args.strategy:
        strategies = [MutationStrategy(s) for s in args.strategy]
    
    # Get params to mutate
    params = None
    
    if args.params:
        try:
            params = json.loads(args.params)
        except json.JSONDecodeError as e:
            console.print(f"[red]Invalid JSON params:[/red] {e}")
            return
    elif args.baseline:
        if not args.baseline.exists():
            console.print(f"[red]Baseline not found:[/red] {args.baseline}")
            return
        
        with open(args.baseline, encoding="utf-8") as f:
            data = json.load(f)
        
        # Extract params from first request
        for req in data.get("requests", []):
            body = req.get("request", {}).get("body")
            if isinstance(body, dict):
                params = body
                break
    
    if not params:
        console.print("[yellow]No parameters to mutate[/yellow]")
        console.print("[dim]Use --params or --baseline to provide parameters[/dim]")
        
        # Generate sample output
        sample_params = {
            "username": "test_user",
            "password": "secret123",
            "timestamp": "1700000000",
            "sign": "abc123def456"
        }
        console.print(f"\n[dim]Example: --params '{json.dumps(sample_params)}'[/dim]")
        return
    
    console.print(f"[cyan]Generating mutations for params:[/cyan] {list(params.keys())}\n")
    mutator.generate_mutations(params, strategies)
    mutator.display_summary()
    mutator.save_mutations()


if __name__ == "__main__":
    main()
