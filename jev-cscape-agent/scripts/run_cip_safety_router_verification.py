#!/usr/bin/env python3
"""Verification Script for Industrial ODVA CIP Safety Router Protocol Engine (Wave W238).

Work Package: W238 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Follows the deterministic 9-stage verification pattern:
  Stage 1: Protocol Architecture & Constants Initialization (Class 0x39, 0x3A, 0x3B, SNN, SCID, 4-node topology, EPI 10ms, watchdog 30ms, jitter 2000us/2500us, diagnostic codes 0xEA01..0xEA06 signed/unsigned 16-bit equality).
  Stage 2: Pure IEC 61131-3 Structured Text POU Validation ('CipSafetyRouterSync' with STParser & SecurityGuard, %R1990..%R1997, %M464..%M465).
  Stage 3: Anti-Ladder Security Guard Interception (rejection of contacts, coils, rungs, networks, mnemonics with LadderForbiddenError).
  Stage 4: Router Multi-Node Configuration & Node Registration (4 nodes: Node 0..3, unique network IDs, EPI surveillance).
  Stage 5: Dual-Channel Parity & Dual CRC-S Checksum Verification (Channel A vs Channel B complement parity, CRC-S1/CRC-S2 deterministic calculation, single-bit corruption detection, 0xEA01 and 0xEA03 detection).
  Stage 6: EPI Watchdog Surveillance & Timeout Fault Injection (exceeding 30ms watchdog timeout without packets trips 0xEA02, %M465 asserted, %M464 de-asserted).
  Stage 7: Excessive Jitter & Node Disconnect Fault Injections (0xEA04 jitter exceeded and 0xEA05 node disconnect, fail-closed state).
  Stage 8: Horner OCS Register Table Synchronization & Operator Reset (%R1990..%R1997, %M464..%M465 bit-exact synchronization under SYSTEM privilege, zero drift across reset).
  Stage 9: Simulation Soak 100 Cycles & Heap Boundedness (deterministic 100-cycle soak, memory bounded, latency bounds).

Generates:
  artifacts/telemetry/cip_safety_router_evidence.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Union

# Ensure repository root and src/ are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.telemetry.cip_safety_router import (
    run_cip_safety_router_verification,
)

# ANSI terminal formatting constants
ESC_RESET = "\033[0m"
ESC_BOLD = "\033[1m"
ESC_DIM = "\033[2m"
ESC_GREEN = "\033[92m"
ESC_RED = "\033[91m"
ESC_YELLOW = "\033[93m"
ESC_CYAN = "\033[96m"


def format_stage_badge(passed: bool, status: Optional[str] = None) -> str:
    """Format strict 4-state contract ANSI badge."""
    norm_status = (status or "").lower()
    if norm_status == "blocked":
        return f"{ESC_YELLOW}{ESC_BOLD}[BLOCKED]{ESC_RESET}"
    if norm_status == "inconclusive":
        return f"{ESC_YELLOW}{ESC_BOLD}[INCONCLUSIVE]{ESC_RESET}"
    if passed or norm_status in ("passed", "pass", "success"):
        return f"{ESC_GREEN}{ESC_BOLD}[PASS]{ESC_RESET}"
    return f"{ESC_RED}{ESC_BOLD}[FAIL]{ESC_RESET}"


def format_stage_result(
    stage: int | str,
    check: str,
    passed: bool,
    timing_ms: Optional[float] = None,
    details: str = "",
    status: Optional[str] = None,
) -> str:
    """Format a single stage line with ANSI colored badge, timing, and description."""
    badge = format_stage_badge(passed, status)
    timing_str = f" ({timing_ms:.2f} ms)" if timing_ms is not None else ""
    line = f"  Stage {stage}: {badge} {check}{timing_str}"
    if details:
        line += f"\n    {ESC_DIM}{details}{ESC_RESET}"
    return line


def main(argv: Optional[List[str]] = None) -> int:
    """Main verification CLI entry point."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="JEV Cscape Agent: Industrial ODVA CIP Safety Router Protocol Engine Verification (W238)"
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
        help="Specified evidence JSON output path",
    )
    parser.add_argument(
        "--work-package",
        dest="work_package",
        default="W238",
        help="Work package identifier (default: W238)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw strict 4-state contract JSON to stdout",
    )
    args = parser.parse_args(argv)

    selected_path = args.flag_path or args.positional_path
    if selected_path:
        evidence_path = Path(selected_path).resolve()
    else:
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_router_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print("=" * 80)
        print(f"  {ESC_BOLD}JEV Cscape Agent: Industrial ODVA CIP Safety Router Verification ({args.work_package}){ESC_RESET}")
        print("=" * 80)

    t_start = time.perf_counter()
    try:
        evidence = run_cip_safety_router_verification(
            output_path=evidence_path,
            work_package=args.work_package,
        )
    except TypeError:
        # Fallback if function takes only output_path
        evidence = run_cip_safety_router_verification(output_path=evidence_path)
    except Exception as exc:
        elapsed_fail = (time.perf_counter() - t_start) * 1000.0
        fail_payload: Dict[str, Any] = {
            "status": "failed",
            "error_code": "VERIFICATION_EXCEPTION",
            "details": f"Verification suite crashed with unhandled exception: {exc}",
            "stages_passed": 0,
            "total_stages": 9,
            "passed_stages": 0,
            "data": {
                "work_package": args.work_package,
                "duration_ms": elapsed_fail,
                "stages": [],
                "tests": [],
            },
        }
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(fail_payload, f, indent=2)

        if args.json:
            print(json.dumps(fail_payload, indent=2))
        else:
            print(f"\n[{ESC_RED}{ESC_BOLD}EXCEPTION{ESC_RESET}] Verification suite crashed with unhandled exception:")
            print(f"  {type(exc).__name__}: {exc}")
            print("=" * 80)
        return 1

    total_elapsed_ms = (time.perf_counter() - t_start) * 1000.0

    # Ensure evidence dictionary has tests alias and total_checks
    if isinstance(evidence, dict) and "data" in evidence:
        stages_list = evidence["data"].get("stages", [])
        if "tests" not in evidence["data"]:
            evidence["data"]["tests"] = stages_list
        if "checks_passed" not in evidence["data"]:
            evidence["data"]["checks_passed"] = sum(1 for s in stages_list if s.get("passed"))
        if "total_checks" not in evidence["data"]:
            evidence["data"]["total_checks"] = len(stages_list)
        # Re-save with complete data
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    if args.json:
        print(json.dumps(evidence, indent=2))
        return 0 if evidence.get("status") == "success" else 1

    valid_states = {"success", "failed", "blocked", "inconclusive"}
    overall_status = evidence.get("status") if isinstance(evidence, dict) else None
    error_code = evidence.get("error_code") if isinstance(evidence, dict) else "INVALID_PAYLOAD"
    details_str = evidence.get("details", "") if isinstance(evidence, dict) else "Evidence is not a dictionary"

    if overall_status not in valid_states:
        print(f"\n[{ESC_RED}{ESC_BOLD}CONTRACT VIOLATION{ESC_RESET}] Invalid status '{overall_status}'. Must be one of {valid_states}.")
        print("=" * 80)
        return 1

    stages_data: List[Dict[str, Any]] = []
    if isinstance(evidence, dict):
        data_dict = evidence.get("data")
        if isinstance(data_dict, dict):
            stages_data = data_dict.get("stages") or data_dict.get("tests") or []

    print("\nDeterministic 9-Stage Protocol Verification Results:")
    for s in stages_data:
        st_num = s.get("stage", "?")
        chk_name = s.get("check") or s.get("name") or s.get("stage_name") or f"Stage_{st_num}"
        passed = bool(s.get("passed"))
        details = s.get("details", "")
        timing = s.get("timing_ms")
        st_stat = s.get("status")
        print(format_stage_result(st_num, chk_name, passed, timing, details, st_stat))

    print("-" * 80)
    print(f"Total Execution Time: {total_elapsed_ms:.2f} ms")
    stages_passed = evidence.get("stages_passed", sum(1 for s in stages_data if s.get("passed")))
    total_stages = evidence.get("total_stages", len(stages_data))
    print(f"Stages Passed: {stages_passed}/{total_stages}")
    print(f"Evidence Artifact: {ESC_CYAN}{evidence_path}{ESC_RESET}")
    print(f"Engineering Contract Status: {overall_status.upper()}")

    if overall_status == "blocked":
        print(f"\n{ESC_YELLOW}{ESC_BOLD}[BLOCKED] Action prevented by safety policy or platform limitation: {error_code}{ESC_RESET}")
        return 2
    elif overall_status == "inconclusive":
        print(f"\n{ESC_YELLOW}{ESC_BOLD}[INCONCLUSIVE] Outcome unverified: {error_code}{ESC_RESET}")
        return 3
    elif overall_status == "success":
        print(f"\n{ESC_GREEN}{ESC_BOLD}[SUCCESS] All 9 CIP Safety Router protocol stages PASSED deterministically.{ESC_RESET}")
        print("=" * 80)
        return 0
    else:
        print(f"\n{ESC_RED}{ESC_BOLD}[FAILED] Verification failed with status '{overall_status}' (error_code: {error_code}).{ESC_RESET}")
        print(f"Details: {details_str}")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(main())
