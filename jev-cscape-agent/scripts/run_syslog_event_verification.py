#!/usr/bin/env python3
"""Verification Runner for Real-Time SCADA Process Event Logger & Syslog RFC 5424 Serializer (W062).

Generates:
- artifacts/telemetry/scada_events.log (RFC 5424 formatted audit events)
- artifacts/telemetry/syslog_event_evidence.json (deterministic 4-state evidence)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from jev_cscape.telemetry.syslog_event import verify_syslog_event_and_export_evidence


def main() -> int:
    evidence_path = PROJECT_ROOT / "artifacts" / "telemetry" / "syslog_event_evidence.json"
    log_path = PROJECT_ROOT / "artifacts" / "telemetry" / "scada_events.log"

    print("[*] Executing W062 Syslog Event Logger verification...")
    result = verify_syslog_event_and_export_evidence(
        output_evidence_path=str(evidence_path),
        output_log_path=str(log_path),
    )

    print(json.dumps(result, indent=2))

    if result.get("status") == "success":
        print(f"[+] Verification passed. Artifacts written to:\n    {evidence_path}\n    {log_path}")
        return 0
    else:
        print(f"[-] Verification failed: {result.get('details')}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
