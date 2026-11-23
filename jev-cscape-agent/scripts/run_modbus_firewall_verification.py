"""Standalone CLI Verification Runner for W067 Modbus TCP Security Guard & Packet Firewall."""

from __future__ import annotations

import json
from pathlib import Path
import sys

# Ensure repository root is in sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root / "src") not in sys.path:
    sys.path.insert(0, str(repo_root / "src"))
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from jev_cscape.telemetry.modbus_firewall import verify_modbus_firewall_and_export_evidence


def main() -> int:
    evidence_path = repo_root / "artifacts" / "telemetry" / "modbus_firewall_evidence.json"
    print("[*] Executing W067 Modbus TCP Security Firewall verification...")
    result = verify_modbus_firewall_and_export_evidence(output_evidence_path=str(evidence_path))
    print(json.dumps(result, indent=2))
    if result["status"] == "success":
        print(f"[+] Verification passed. Artifact written to:\n    {evidence_path}")
        return 0
    else:
        print(f"[-] Verification failed: {result['error_code']}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
