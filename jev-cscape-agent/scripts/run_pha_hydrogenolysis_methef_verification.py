#!/usr/bin/env python3
"""Deterministic 9-Stage Verification Runner for Industrial Catalytic PHA Hydrogenolysis & 2-MeTHF Synthesis (W326).

Work Package: W326 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [CSTR Catalytic PHA Hydrogenolysis & 2-MeTHF Synthesis]
Status Contract: Strict 4-State JSON output (success | failed | blocked | inconclusive) & evidence emission.

Features:
- Continuous Stirred-Tank Reactor (CSTR) ODE continuous model:
  Levulinate / methylsuccinate ester precursor -> 2-MeTHF + coproduct H2O.
- Competitive consecutive/parallel byproduct: 1,4-pentanediol.
- Langmuir-Hinshelwood catalytic kinetics and thermal catalyst sintering deactivation.
- Coupled 6-state continuous ODE solver (RK4).
- Mass conservation residuals < 1e-10.
- Diagnostics & Surveillance (%R2877):
  - 0x0000: DIAG_OK
  - 0xF9C1: DIAG_ERR_THERMAL_RUNAWAY (T > 530 K or dT/dt > 12.0 K/s)
  - 0xF9C2: DIAG_ERR_OVERPRESSURE_QUENCH (P > 50.0 bar)
  - 0xF9C3: DIAG_ERR_CATALYST_SINTERING (Activity < 35.0%)
  - 0xF9C4: DIAG_ERR_PENTANEDIOL_BYPRODUCT_SPIKE (Byproduct yield > 25.0%)
  - 0xF9C5: DIAG_ERR_MASS_BALANCE_DIVERGENCE (Residual > 1e-4)
- Horner OCS Memory Space:
  - Analog registers %R2870..%R2877
  - Discrete coils %M669..%M671
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

from jev_cscape.simulation.pha_hydrogenolysis_methef import (
    COIL_PHA_METH_EMERGENCY_QUENCH,
    COIL_PHA_METH_FEED_PUMP,
    COIL_PHA_METH_REACTOR_ACTIVE,
    DIAG_ERR_CATALYST_SINTERING,
    DIAG_ERR_MASS_BALANCE_DIVERGENCE,
    DIAG_ERR_OVERPRESSURE_QUENCH,
    DIAG_ERR_PENTANEDIOL_BYPRODUCT_SPIKE,
    DIAG_ERR_THERMAL_RUNAWAY,
    DIAG_OK,
    REG_PHA_METH_CATALYST_ACTIVITY,
    REG_PHA_METH_COOLING_DUTY_KW,
    REG_PHA_METH_DIAGNOSTIC_CODE,
    REG_PHA_METH_FEED_FLOW_RATE,
    REG_PHA_METH_PRECURSOR_CONVERSION,
    REG_PHA_METH_REACTOR_PRESSURE,
    REG_PHA_METH_REACTOR_TEMP,
    REG_PHA_METH_SELECTIVITY_PERCENT,
    DiagnosticCode,
    PHAHydrogenolysisMethefConfig,
    PHAHydrogenolysisMethefEngine,
    PHAHydrogenolysisMethefState,
    run_pha_hydrogenolysis_methef_verification,
    verify_pha_hydrogenolysis_methef_pure_st,
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
        description="Deterministic 9-Stage Verification Runner for PHA Hydrogenolysis & 2-MeTHF Synthesis (W326)"
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
        help="Path to output JSON evidence artifact (default: artifacts/simulation/pha_hydrogenolysis_methef_evidence.json)",
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
        default="W326",
        help="Work package ID (default: W326)",
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
        evidence_path = (REPO_ROOT / "artifacts" / "simulation" / "pha_hydrogenolysis_methef_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print("=" * 80)
        print(f"  {ESC_BOLD}JEV Cscape Agent: Industrial PHA Hydrogenolysis & 2-MeTHF Verification ({args.work_package}){ESC_RESET}")
        print("=" * 80)

    t0 = time.perf_counter()
    try:
        evidence = run_pha_hydrogenolysis_methef_verification(
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
