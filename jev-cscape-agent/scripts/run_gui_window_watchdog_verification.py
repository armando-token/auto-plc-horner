#!/usr/bin/env python3
"""Verification Runner for Cscape GUI Automated Window Health Watchdog & Geometry Forensics (W063).

Generates:
- artifacts/G3/gui_window_watchdog_evidence.json (deterministic 4-state evidence)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from jev_cscape.automation.gui_window_watchdog import (
    verify_gui_window_watchdog_and_export_evidence,
)


def main() -> int:
    evidence_path = PROJECT_ROOT / "artifacts" / "G3" / "gui_window_watchdog_evidence.json"

    print("[*] Executing W063 GUI Window Watchdog verification...")
    result = verify_gui_window_watchdog_and_export_evidence(
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
