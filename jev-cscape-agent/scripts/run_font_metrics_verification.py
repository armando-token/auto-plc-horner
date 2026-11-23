#!/usr/bin/env python3
"""Verification Runner for Cscape HMI Vector Font Metrics & Multi-Lingual Dictionary (W066).

Generates:
- artifacts/HMI/font_metrics_evidence.json (deterministic 4-state evidence)
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from jev_cscape.hmi.font_metrics import verify_font_metrics_and_export_evidence


def main() -> int:
    evidence_path = PROJECT_ROOT / "artifacts" / "HMI" / "font_metrics_evidence.json"

    print("[*] Executing W066 HMI Font Metrics & Translation verification...")
    result = verify_font_metrics_and_export_evidence(
        output_evidence_path=str(evidence_path),
    )

    print(json.dumps(result, indent=2))

    if result.get("status") == "success":
        print(f"[+] Verification passed. Artifact written to:\n    {evidence_path}")
        return 0
    else:
        print(f"[-] Verification failed: {result.get('details')}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
