"""Verification Runner for Industrial Modbus Protocol Resilience Fuzzer.

Work Package: W055 (Gate G8 / G11)
Executes deterministic attack vectors and 1000 stochastic frame mutations, asserting
zero unhandled exceptions, zero crashes, and exporting artifacts/telemetry/modbus_fuzzer_evidence.json.
"""

import json
import sys
from pathlib import Path

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root / "src"))

from jev_cscape.telemetry.modbus_fuzzer import verify_modbus_fuzzer_and_export_evidence


def main() -> int:
    output_path = repo_root / "artifacts" / "telemetry" / "modbus_fuzzer_evidence.json"
    print(f"[W055] Executing Modbus resilience fuzzer verification...")
    result = verify_modbus_fuzzer_and_export_evidence(str(output_path))
    print(f"[W055] Status: {result.get('status')}")
    print(f"[W055] Details: {result.get('details')}")

    if result.get("status") == "success":
        data = result.get("data", {})
        det = data.get("deterministic_suite", {})
        stoch = data.get("stochastic_campaign", {})
        print(f"[W055] Deterministic Vectors: {det.get('passed_vectors')}/{det.get('total_vectors')} passed ({det.get('pass_rate_percent')}%)")
        print(f"[W055] Stochastic Mutations: {stoch.get('mutations_tested')} tested, {stoch.get('unhandled_crashes')} crashes, throughput {stoch.get('throughput_vectors_per_sec')} vec/sec")
        print(f"[W055] Evidence written to: {output_path}")
        return 0
    else:
        print(f"[W055] ERROR: Fuzzing verification failed: {result.get('error_code')}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
