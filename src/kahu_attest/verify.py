"""CLI tool to verify attestation v2 bundles.

Usage:
    python -m kahu_attest.verify <bundle.json> <pubkey.pem>
    python -m kahu_attest.verify --check-expiry <bundle.json> <pubkey.pem>
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from kahu_attest.bundle import (
    is_attestation_expired,
    verify_attestation_signature,
    verify_evidence_chain,
)
from kahu_tuning.signing import load_public


def verify_bundle(
    bundle_path: str | Path,
    pubkey_path: str | Path,
    check_expiry: bool = True,
) -> dict:
    """Verify an attestation bundle.

    Returns a result dict with:
    - valid: bool (overall result)
    - signature_valid: bool
    - chain_valid: bool
    - expired: bool | None
    - errors: list[str]
    """
    errors = []
    result = {
        "valid": False,
        "signature_valid": False,
        "chain_valid": False,
        "expired": None,
        "errors": errors,
    }

    # Load bundle
    try:
        bundle_data = Path(bundle_path).read_text(encoding="utf-8")
        bundle = json.loads(bundle_data)
    except (OSError, json.JSONDecodeError) as e:
        errors.append(f"Failed to load bundle: {e}")
        return result

    # Load public key
    try:
        pubkey = load_public(pubkey_path)
    except (OSError, TypeError, ValueError) as e:
        errors.append(f"Failed to load public key: {e}")
        return result

    # Verify signature
    sig_valid = verify_attestation_signature(bundle, pubkey)
    result["signature_valid"] = sig_valid
    if not sig_valid:
        errors.append("Signature verification FAILED")

    # Verify evidence chain
    chain_valid = verify_evidence_chain(bundle)
    result["chain_valid"] = chain_valid
    if not chain_valid:
        errors.append("Evidence chain verification FAILED")

    # Check expiry
    if check_expiry:
        expired = is_attestation_expired(bundle)
        result["expired"] = expired
        if expired:
            errors.append("Attestation has EXPIRED")

    result["valid"] = sig_valid and chain_valid and (not check_expiry or not result["expired"])
    return result


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="kahu-verify",
        description="Verify a Kahu attestation v2 bundle",
    )
    parser.add_argument("bundle", help="Path to attestation bundle JSON file")
    parser.add_argument("pubkey", help="Path to Ed25519 public key PEM file")
    parser.add_argument(
        "--no-expiry-check",
        action="store_true",
        help="Skip expiry check",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output result as JSON",
    )

    args = parser.parse_args(argv)
    result = verify_bundle(args.bundle, args.pubkey, check_expiry=not args.no_expiry_check)

    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        print(f"Bundle:    {args.bundle}")
        print(f"Public key: {args.pubkey}")
        print()
        print(f"Signature: {'VALID' if result['signature_valid'] else 'INVALID'}")
        print(f"Chain:     {'VALID' if result['chain_valid'] else 'INVALID'}")
        if result["expired"] is not None:
            print(f"Expired:   {'YES' if result['expired'] else 'NO'}")
        print()
        if result["valid"]:
            print("RESULT: VERIFIED")
        else:
            print("RESULT: FAILED")
            for err in result["errors"]:
                print(f"  - {err}")

    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
