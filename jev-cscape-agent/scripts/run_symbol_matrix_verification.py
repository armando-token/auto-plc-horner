"""Verification script for Cscape HMI Dynamic Barcode & QR Code Symbol Generator (W072 / Gate G9 / Gate G2)."""

from __future__ import annotations

import json
import os
import sys

# Ensure src/ is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from jev_cscape.hmi.symbol_matrix import verify_symbol_matrix_and_export_evidence


def main() -> int:
    evidence_path = os.path.abspath("artifacts/HMI/symbol_matrix_evidence.json")
    svg_sample_path = os.path.abspath("artifacts/HMI/qr_code_sample.svg")
    print(f"Running Symbol Matrix verification -> {evidence_path}")
    result = verify_symbol_matrix_and_export_evidence(evidence_path, svg_sample_path)
    print(json.dumps(result, indent=2))
    if result["status"] == "success":
        print("\n[SUCCESS] W072 Symbol Matrix & QR Code verification passed cleanly.")
        return 0
    else:
        print(f"\n[FAILED] Verification failed: {result['error_code']}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
