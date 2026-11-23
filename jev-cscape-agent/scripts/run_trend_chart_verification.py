"""Standalone CLI Verification Runner for W069 Cscape HMI Historical Trend Chart Vector Rasterizer."""

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

from jev_cscape.hmi.trend_chart import verify_trend_chart_and_export_evidence


def main() -> int:
    evidence_path = repo_root / "artifacts" / "HMI" / "trend_chart_evidence.json"
    svg_path = repo_root / "artifacts" / "HMI" / "trend_chart_sample.svg"
    print("[*] Executing W069 Cscape HMI Trend Chart verification...")
    result = verify_trend_chart_and_export_evidence(
        output_evidence_path=str(evidence_path),
        output_svg_path=str(svg_path),
    )
    print(json.dumps(result, indent=2))
    if result["status"] == "success":
        print(f"[+] Verification passed. Artifacts written to:\n    {evidence_path}\n    {svg_path}")
        return 0
    else:
        print(f"[-] Verification failed: {result['error_code']}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
