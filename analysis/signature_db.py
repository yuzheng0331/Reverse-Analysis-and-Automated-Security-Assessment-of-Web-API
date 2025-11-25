#!/usr/bin/env python3
"""
Phase 4: Crypto Signature Database
===================================
Database of cryptographic signatures, patterns, and fingerprints.

This module provides:
- Known crypto library fingerprints
- Algorithm signature patterns
- Key format recognition
- Weakness indicators

Usage:
    from analysis.signature_db import SignatureDatabase
    db = SignatureDatabase()
    matches = db.match_pattern(code_snippet)
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


# =============================================================================
# Configuration
# =============================================================================

DEFAULT_DB_PATH = Path(__file__).parent.parent / "configs" / "signatures.json"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class CryptoSignature:
    """Definition of a crypto signature pattern."""
    id: str
    name: str
    category: str  # symmetric, asymmetric, hash, encoding
    library: Optional[str]
    patterns: list[str]  # Regex patterns
    indicators: list[str]  # Additional indicators
    weakness_level: str  # critical, high, medium, low, none
    description: str
    references: list[str] = field(default_factory=list)


@dataclass
class SignatureMatch:
    """Result of a signature match."""
    signature_id: str
    signature_name: str
    category: str
    weakness_level: str
    matched_pattern: str
    match_text: str
    position: int
    confidence: float


# =============================================================================
# Default Signatures
# =============================================================================

DEFAULT_SIGNATURES = [
    # =========================================================================
    # Symmetric Encryption
    # =========================================================================
    {
        "id": "SYM_AES_CRYPTOJS",
        "name": "CryptoJS AES",
        "category": "symmetric",
        "library": "CryptoJS",
        "patterns": [
            r"CryptoJS\.AES\.(encrypt|decrypt)",
            r"CryptoJS\.mode\.(CBC|ECB|CTR|CFB|OFB)",
            r"CryptoJS\.pad\.(Pkcs7|ZeroPadding|NoPadding)"
        ],
        "indicators": ["aes", "cryptojs", "encrypt"],
        "weakness_level": "medium",
        "description": "CryptoJS AES encryption - check mode and padding",
        "references": ["https://cryptojs.gitbook.io/docs/"]
    },
    {
        "id": "SYM_AES_ECB",
        "name": "AES ECB Mode (Weak)",
        "category": "symmetric",
        "library": None,
        "patterns": [
            r"mode\s*[=:]\s*['\"]?ECB['\"]?",
            r"CryptoJS\.mode\.ECB",
            r"AES/ECB/",
            r"createCipheriv\s*\([^,]*,\s*['\"]aes[^'\"]*ecb"
        ],
        "indicators": ["ecb", "no iv"],
        "weakness_level": "high",
        "description": "ECB mode reveals patterns in encrypted data",
        "references": ["https://blog.filippo.io/the-ecb-penguin/"]
    },
    {
        "id": "SYM_DES",
        "name": "DES Encryption (Broken)",
        "category": "symmetric",
        "library": None,
        "patterns": [
            r"CryptoJS\.DES\.",
            r"createCipher\s*\(\s*['\"]des['\"]",
            r"DES/",
            r"Crypto\.DES"
        ],
        "indicators": ["des", "56-bit"],
        "weakness_level": "critical",
        "description": "DES is broken - 56-bit key is easily brute-forced",
        "references": []
    },
    {
        "id": "SYM_3DES",
        "name": "Triple DES (Deprecated)",
        "category": "symmetric",
        "library": None,
        "patterns": [
            r"CryptoJS\.TripleDES",
            r"3DES|des-ede3|des3",
            r"createCipher\s*\(\s*['\"]des-ede3"
        ],
        "indicators": ["3des", "tripledes"],
        "weakness_level": "high",
        "description": "3DES is deprecated - migrate to AES",
        "references": []
    },
    {
        "id": "SYM_RC4",
        "name": "RC4 (Broken)",
        "category": "symmetric",
        "library": None,
        "patterns": [
            r"CryptoJS\.RC4",
            r"rc4|arcfour",
            r"createCipher\s*\(\s*['\"]rc4"
        ],
        "indicators": ["rc4", "arcfour"],
        "weakness_level": "critical",
        "description": "RC4 has multiple known vulnerabilities",
        "references": []
    },
    
    # =========================================================================
    # Asymmetric Encryption
    # =========================================================================
    {
        "id": "ASYM_RSA_JSENCRYPT",
        "name": "JSEncrypt RSA",
        "category": "asymmetric",
        "library": "JSEncrypt",
        "patterns": [
            r"new\s+JSEncrypt\s*\(",
            r"\.setPublicKey\s*\(",
            r"\.encrypt\s*\(",
            r"jsencrypt"
        ],
        "indicators": ["rsa", "jsencrypt", "public key"],
        "weakness_level": "medium",
        "description": "JSEncrypt RSA - verify key size >= 2048 bits",
        "references": ["https://travistidwell.com/jsencrypt/"]
    },
    {
        "id": "ASYM_RSA_FORGE",
        "name": "Forge RSA",
        "category": "asymmetric",
        "library": "node-forge",
        "patterns": [
            r"forge\.pki\.rsa",
            r"forge\.pki\.publicKeyFromPem",
            r"publicKey\.encrypt"
        ],
        "indicators": ["forge", "rsa", "pki"],
        "weakness_level": "medium",
        "description": "Node-forge RSA implementation",
        "references": ["https://github.com/digitalbazaar/forge"]
    },
    {
        "id": "ASYM_RSA_SMALL_KEY",
        "name": "RSA Small Key (Weak)",
        "category": "asymmetric",
        "library": None,
        "patterns": [
            r"keySize\s*[=:]\s*(512|768|1024)",
            r"bits\s*[=:]\s*(512|768|1024)",
            r"generateKeyPair\s*\([^)]*\b(512|768|1024)\b"
        ],
        "indicators": ["small key", "weak rsa"],
        "weakness_level": "critical",
        "description": "RSA key size < 2048 bits is insecure",
        "references": []
    },
    
    # =========================================================================
    # Hash Functions
    # =========================================================================
    {
        "id": "HASH_MD5",
        "name": "MD5 Hash (Broken)",
        "category": "hash",
        "library": None,
        "patterns": [
            r"CryptoJS\.MD5\s*\(",
            r"\.md5\s*\(",
            r"createHash\s*\(\s*['\"]md5['\"]",
            r"Crypto\.MD5"
        ],
        "indicators": ["md5"],
        "weakness_level": "critical",
        "description": "MD5 has collision vulnerabilities - not for security",
        "references": []
    },
    {
        "id": "HASH_SHA1",
        "name": "SHA-1 Hash (Deprecated)",
        "category": "hash",
        "library": None,
        "patterns": [
            r"CryptoJS\.SHA1\s*\(",
            r"\.sha1\s*\(",
            r"createHash\s*\(\s*['\"]sha1['\"]"
        ],
        "indicators": ["sha1", "sha-1"],
        "weakness_level": "high",
        "description": "SHA-1 has known collision attacks",
        "references": ["https://shattered.io/"]
    },
    {
        "id": "HASH_SHA256",
        "name": "SHA-256 Hash",
        "category": "hash",
        "library": None,
        "patterns": [
            r"CryptoJS\.SHA256\s*\(",
            r"\.sha256\s*\(",
            r"createHash\s*\(\s*['\"]sha256['\"]"
        ],
        "indicators": ["sha256", "sha-256"],
        "weakness_level": "none",
        "description": "SHA-256 is currently secure",
        "references": []
    },
    
    # =========================================================================
    # MAC Functions
    # =========================================================================
    {
        "id": "MAC_HMAC_MD5",
        "name": "HMAC-MD5 (Weak)",
        "category": "mac",
        "library": None,
        "patterns": [
            r"CryptoJS\.HmacMD5",
            r"createHmac\s*\(\s*['\"]md5['\"]"
        ],
        "indicators": ["hmac", "md5"],
        "weakness_level": "high",
        "description": "HMAC-MD5 inherits MD5 weaknesses",
        "references": []
    },
    {
        "id": "MAC_HMAC_SHA256",
        "name": "HMAC-SHA256",
        "category": "mac",
        "library": None,
        "patterns": [
            r"CryptoJS\.HmacSHA256",
            r"createHmac\s*\(\s*['\"]sha256['\"]"
        ],
        "indicators": ["hmac", "sha256"],
        "weakness_level": "none",
        "description": "HMAC-SHA256 is secure",
        "references": []
    },
    
    # =========================================================================
    # Encoding (Not Encryption!)
    # =========================================================================
    {
        "id": "ENC_BASE64",
        "name": "Base64 Encoding",
        "category": "encoding",
        "library": None,
        "patterns": [
            r"btoa\s*\(",
            r"atob\s*\(",
            r"\.toString\s*\(\s*['\"]base64['\"]",
            r"Buffer\.from\s*\([^)]*,\s*['\"]base64['\"]"
        ],
        "indicators": ["base64", "btoa", "atob"],
        "weakness_level": "none",
        "description": "Base64 is encoding, NOT encryption",
        "references": []
    },
    
    # =========================================================================
    # Hardcoded Secrets (Critical)
    # =========================================================================
    {
        "id": "SECRET_HARDCODED_KEY",
        "name": "Hardcoded Crypto Key",
        "category": "secret",
        "library": None,
        "patterns": [
            r"(key|secret|password)\s*[=:]\s*['\"][a-zA-Z0-9+/=]{16,}['\"]",
            r"(AES|DES|RSA)_KEY\s*=\s*['\"]",
            r"iv\s*[=:]\s*['\"][a-fA-F0-9]{16,}['\"]"
        ],
        "indicators": ["hardcoded", "key", "secret"],
        "weakness_level": "critical",
        "description": "Hardcoded keys in client code can be extracted",
        "references": []
    },
    {
        "id": "SECRET_PRIVATE_KEY",
        "name": "Private Key in Code",
        "category": "secret",
        "library": None,
        "patterns": [
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
            r"privateKey\s*[=:]\s*['\"]"
        ],
        "indicators": ["private key", "rsa private"],
        "weakness_level": "critical",
        "description": "Private keys should never be in client code",
        "references": []
    }
]


# =============================================================================
# Signature Database Class
# =============================================================================


class SignatureDatabase:
    """
    Database of cryptographic signatures for pattern matching.
    
    Supports:
    - Loading signatures from JSON
    - Pattern matching against code
    - Weakness assessment
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        self.signatures: list[CryptoSignature] = []
        self._load_default_signatures()
        
        if db_path and db_path.exists():
            self._load_from_file(db_path)
    
    def _load_default_signatures(self):
        """Load built-in signature definitions."""
        for sig_data in DEFAULT_SIGNATURES:
            self.signatures.append(CryptoSignature(**sig_data))
    
    def _load_from_file(self, filepath: Path):
        """Load additional signatures from a JSON file."""
        try:
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            
            for sig_data in data.get("signatures", []):
                self.signatures.append(CryptoSignature(**sig_data))
                
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Warning: Failed to load signatures from {filepath}: {e}")
    
    def match_pattern(self, code: str) -> list[SignatureMatch]:
        """
        Match code against all signatures in the database.
        
        Args:
            code: Source code to analyze
            
        Returns:
            List of signature matches
        """
        matches = []
        
        for sig in self.signatures:
            for pattern in sig.patterns:
                try:
                    for match in re.finditer(pattern, code, re.IGNORECASE):
                        matches.append(SignatureMatch(
                            signature_id=sig.id,
                            signature_name=sig.name,
                            category=sig.category,
                            weakness_level=sig.weakness_level,
                            matched_pattern=pattern,
                            match_text=match.group(0),
                            position=match.start(),
                            confidence=0.9
                        ))
                except re.error:
                    continue
        
        return matches
    
    def get_signature(self, sig_id: str) -> Optional[CryptoSignature]:
        """Get a signature by ID."""
        for sig in self.signatures:
            if sig.id == sig_id:
                return sig
        return None
    
    def get_signatures_by_category(self, category: str) -> list[CryptoSignature]:
        """Get all signatures in a category."""
        return [s for s in self.signatures if s.category == category]
    
    def get_weak_signatures(self) -> list[CryptoSignature]:
        """Get all signatures with weakness_level != 'none'."""
        return [s for s in self.signatures if s.weakness_level != "none"]
    
    def export_to_json(self, filepath: Path):
        """Export signatures to a JSON file."""
        data = {
            "version": "1.0",
            "signatures": [
                {
                    "id": s.id,
                    "name": s.name,
                    "category": s.category,
                    "library": s.library,
                    "patterns": s.patterns,
                    "indicators": s.indicators,
                    "weakness_level": s.weakness_level,
                    "description": s.description,
                    "references": s.references
                }
                for s in self.signatures
            ]
        }
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    
    def summary(self) -> dict[str, Any]:
        """Get a summary of the signature database."""
        categories: dict[str, int] = {}
        weaknesses: dict[str, int] = {}
        
        for sig in self.signatures:
            categories[sig.category] = categories.get(sig.category, 0) + 1
            weaknesses[sig.weakness_level] = weaknesses.get(sig.weakness_level, 0) + 1
        
        return {
            "total_signatures": len(self.signatures),
            "by_category": categories,
            "by_weakness": weaknesses
        }


# =============================================================================
# CLI Interface
# =============================================================================


def main():
    """Main entry point for signature database CLI."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Crypto Signature Database utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "--export",
        type=Path,
        help="Export signatures to JSON file"
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Display database summary"
    )
    parser.add_argument(
        "--test",
        type=str,
        help="Test pattern matching against provided code snippet"
    )
    
    args = parser.parse_args()
    
    db = SignatureDatabase()
    
    if args.export:
        db.export_to_json(args.export)
        print(f"Exported {len(db.signatures)} signatures to {args.export}")
    
    if args.summary:
        summary = db.summary()
        print(f"\nSignature Database Summary:")
        print(f"  Total signatures: {summary['total_signatures']}")
        print(f"\n  By category:")
        for cat, count in summary["by_category"].items():
            print(f"    {cat}: {count}")
        print(f"\n  By weakness level:")
        for level, count in summary["by_weakness"].items():
            print(f"    {level}: {count}")
    
    if args.test:
        matches = db.match_pattern(args.test)
        if matches:
            print(f"\nFound {len(matches)} matches:")
            for m in matches:
                print(f"  - {m.signature_name} ({m.weakness_level})")
                print(f"    Pattern: {m.matched_pattern}")
                print(f"    Matched: {m.match_text}")
        else:
            print("\nNo crypto patterns detected")


if __name__ == "__main__":
    main()
