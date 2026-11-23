#!/usr/bin/env python3
"""Deterministic 9-Stage Verification Runner for Industrial ODVA CIP Safety Over Ethernet-APL Cable Diagnostics & TDR Engine (W325).

Work Package: W325 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [ODVA CIP Safety Over Ethernet-APL Cable TDR Diagnostics Protocol Engine]
Status Contract: Strict 4-State JSON output (success | failed | blocked | inconclusive) & evidence emission.

Standards & Specifications:
- IEEE 802.3cg-2019: 10 Mb/s Single Pair Ethernet (10BASE-T1L Ethernet-APL):
  - Point-to-point trunk (up to 1,000m) and spur (up to 200m) topologies.
  - Characteristic differential impedance Z_0 = 100.0 Ohm (+/- 20 Ohm).
  - Time-Domain Reflectometry (TDR) pulse generation, impedance discontinuity localization.
  - Nominal Velocity of Propagation (NVP) nominal 67.0% of speed of light in vacuum.
- ODVA CIP Networks Library Volume 5: CIP Safety Specification:
  - Dual 16-bit Safety CRCs: CRC-S1 (0x5935) and CRC-S2 (0x755B).
  - Electronic Product ID (EPID) CRC32 ("HORNER-OCS-APL-CABLE-TDR-SIL3").
- Diagnostics & Surveillance (%R2867):
  - 0x0000: DIAG_OK
  - 0xEEC1: DIAG_ERR_CABLE_OPEN_CIRCUIT (Reflection coeff Gamma > +0.700)
  - 0xEEC2: DIAG_ERR_CABLE_SHORT_CIRCUIT (Reflection coeff Gamma < -0.700)
  - 0xEEC3: DIAG_ERR_IMPEDANCE_MISMATCH (|Z - 100.0| > 25.0 Ohm)
  - 0xEEC4: DIAG_ERR_RETURN_LOSS_EXCURSION (Return loss < 14.0 dB)
  - 0xEEC5: DIAG_ERR_DUAL_CRC_SAFETY_FAULT (Dual CRC-S1/S2 mismatch)
  - 0xEEC6: DIAG_ERR_TDR_PULSE_ATTENUATION (Pulse amplitude < min threshold)
- Horner OCS Memory Space:
  - Analog registers %R2860..%R2867
  - Discrete coils %M667..%M668
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Union

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.telemetry.cip_safety_apl_tdr import (
    CIP_SAFETY_APL_TDR_EPID,
    CIP_SAFETY_CRC_INIT,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    COIL_CIP_APL_TDR_ONLINE,
    COIL_CIP_APL_TDR_SAFETY_TRIP,
    DIAG_ERR_CABLE_OPEN_CIRCUIT,
    DIAG_ERR_CABLE_SHORT_CIRCUIT,
    DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
    DIAG_ERR_IMPEDANCE_MISMATCH,
    DIAG_ERR_RETURN_LOSS_EXCURSION,
    DIAG_ERR_TDR_PULSE_ATTENUATION,
    DIAG_OK,
    REG_CIP_APL_TDR_CABLE_LENGTH_M,
    REG_CIP_APL_TDR_DIAGNOSTIC_CODE,
    REG_CIP_APL_TDR_FAULT_DISTANCE_M,
    REG_CIP_APL_TDR_IMPEDANCE_OHM,
    REG_CIP_APL_TDR_PROPAGATION_VEL_PERCENT,
    REG_CIP_APL_TDR_REFLECTION_COEFF,
    REG_CIP_APL_TDR_RETURN_LOSS_DB,
    REG_CIP_APL_TDR_STATUS,
    CableFaultType,
    CIPAPLTDRPacket,
    CIPAPLTDRSafetyEngine,
    DiagnosticCode,
    TDROperatingState,
    compute_crc_s1,
    compute_crc_s2,
    compute_epid_hash,
    create_valid_apl_tdr_packet,
    run_cip_safety_apl_tdr_verification,
    verify_cip_safety_apl_tdr_pure_st,
    verify_dual_crc_s,
)

# ANSI terminal formatting
ESC_RESET = "\033[0m"
ESC_BOLD = "\033[1m"
ESC_DIM = "\033[2m"
ESC_GREEN = "\033[92m"
ESC_RED = "\033[91m"
ESC_YELLOW = "\033[93m"
ESC_CYAN = "\033[96m"


def format_stage_result(
    stage: int | str,
    check: str,
    passed: bool,
    timing_ms: Optional[float] = None,
    details: str = "",
    status: Optional[str] = None,
) -> str:
    """Format single stage verification outcome for terminal display."""
    if status is not None:
        if status == "success":
            badge = f"{ESC_GREEN}[PASS]{ESC_RESET}"
        elif status == "blocked":
            badge = f"{ESC_YELLOW}[BLOCKED]{ESC_RESET}"
        else:
            badge = f"{ESC_RED}[FAIL]{ESC_RESET}"
    else:
        badge = f"{ESC_GREEN}[PASS]{ESC_RESET}" if passed else f"{ESC_RED}[FAIL]{ESC_RESET}"

    timing_str = f" ({timing_ms:.1f}ms)" if timing_ms is not None else ""
    line = f"  Stage {stage:>2}: {badge} {ESC_BOLD}{check}{ESC_RESET}{timing_str}"
    if details:
        line += f"\n            {ESC_DIM}{details}{ESC_RESET}"
    return line


def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution entrypoint."""
    parser = argparse.ArgumentParser(
        description="Deterministic 9-Stage Verification Runner for ODVA CIP Safety Over Ethernet-APL Cable TDR (W325)"
    )
    parser.add_argument(
        "positional_path",
        nargs="?",
        default=None,
        help="Optional positional path for output evidence JSON file",
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="flag_path",
        default=None,
        help="Path to output JSON evidence artifact (default: artifacts/telemetry/cip_safety_apl_tdr_evidence.json)",
    )
    parser.add_argument(
        "--quick",
        "-q",
        action="store_true",
        default=False,
        help="Execute quick verification mode (reduced simulation cycles)",
    )
    parser.add_argument(
        "--work-package",
        "-w",
        default="W325",
        help="Work package ID (default: W325)",
    )
    parser.add_argument(
        "--json",
        "--json-only",
        action="store_true",
        help="Emit raw JSON report only (no ANSI stdout banner)",
    )
    args = parser.parse_args(argv)

    selected_path = args.flag_path or args.positional_path
    if selected_path:
        evidence_path = Path(selected_path).resolve()
    else:
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_apl_tdr_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print("=" * 80)
        print(f"  {ESC_BOLD}JEV Cscape Agent: ODVA CIP Safety Over Ethernet-APL Cable TDR Verification ({args.work_package}){ESC_RESET}")
        print("=" * 80)

    t0 = time.perf_counter()
    try:
        evidence = run_cip_safety_apl_tdr_verification(
            output_path=evidence_path,
            work_package=args.work_package,
            quick=args.quick,
        )
    except Exception as exc:
        print(f"\n[{ESC_RED}{ESC_BOLD}EXCEPTION{ESC_RESET}] Verification suite crashed with unhandled exception:")
        print(f"  {type(exc).__name__}: {exc}")
        print("=" * 80)
        return 1
    elapsed_total_ms = (time.perf_counter() - t0) * 1000.0

    # Ensure evidence file was written
    if not evidence_path.exists() or evidence_path.stat().st_size == 0:
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    if args.json:
        print(json.dumps(evidence, indent=2))
        return 0 if evidence.get("status") == "success" else 1

    stages = evidence.get("data", {}).get("stages", [])
    for stg in stages:
        stage_num = stg.get("stage", "?")
        stage_name = stg.get("name") or stg.get("check", "unnamed_stage")
        passed = stg.get("passed", False)
        timing = stg.get("timing_ms") or stg.get("duration_ms")
        details = stg.get("details", "")
        status = stg.get("status")
        print(format_stage_result(stage_num, stage_name, passed, timing, details, status))

    passed_count = evidence.get("stages_passed", sum(1 for s in stages if s.get("passed", False)))
    total_count = evidence.get("total_stages", len(stages))
    status_str = evidence.get("status", "unknown")

    print("-" * 80)
    status_badge = (
        f"{ESC_GREEN}{ESC_BOLD}{status_str.upper()}{ESC_RESET}"
        if status_str == "success"
        else f"{ESC_RED}{ESC_BOLD}{status_str.upper()}{ESC_RESET}"
    )
    print(f"[*] Outcome: {passed_count}/{total_count} checks passed across {len(stages)} verification stages (in {elapsed_total_ms:.2f} ms).")
    print(f"[*] Status: {status_badge}")
    print(f"[*] Evidence artifact saved: {ESC_CYAN}{evidence_path}{ESC_RESET}")
    print("=" * 80)

    return 0 if status_str == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
