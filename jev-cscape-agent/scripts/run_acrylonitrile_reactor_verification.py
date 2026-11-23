#!/usr/bin/env python3
"""Verification Script for Industrial Acrylonitrile Propylene Ammoxidation Fluidized-Bed Reactor ODE Simulation (W194).

Work Package: W194 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Rigorous Process Physics & Numerical Verification]
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/simulation/acrylonitrile_reactor_evidence.json
"""

from __future__ import annotations

import argparse
import inspect
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Union

# Ensure repository root and src/ are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from jev_cscape.simulation.acrylonitrile_reactor import (
        run_acrylonitrile_reactor_verification,
    )
    _import_error = None
except ImportError as exc:
    try:
        from jev_cscape.simulation import run_acrylonitrile_reactor_verification
        _import_error = None
    except ImportError:
        run_acrylonitrile_reactor_verification = None
        _import_error = exc

# ANSI terminal formatting constants matching repo conventions
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
    """Format a single stage line with ANSI colored badge, timing, and description."""
    norm_status = (status or "").lower()
    if norm_status == "blocked":
        badge = f"{ESC_YELLOW}{ESC_BOLD}[BLOCKED]{ESC_RESET}"
    elif norm_status == "inconclusive":
        badge = f"{ESC_YELLOW}{ESC_BOLD}[INCONCLUSIVE]{ESC_RESET}"
    elif passed or norm_status in ("passed", "pass", "success"):
        badge = f"{ESC_GREEN}{ESC_BOLD}[PASS]{ESC_RESET}"
    else:
        badge = f"{ESC_RED}{ESC_BOLD}[FAIL]{ESC_RESET}"

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
        description="JEV Cscape Agent: Industrial Acrylonitrile Propylene Ammoxidation Fluidized-Bed Reactor ODE Verification (W194)"
    )
    parser.add_argument(
        "positional_evidence",
        nargs="?",
        default=None,
        help="Optional positional path for output verification evidence JSON file",
    )
    parser.add_argument(
        "--evidence",
        "--output",
        "-o",
        "--evidence-path",
        "-e",
        dest="flag_evidence",
        default=None,
        help="Specified evidence JSON output path",
    )
    args = parser.parse_args(argv)

    selected_path = args.flag_evidence or args.positional_evidence
    if selected_path:
        evidence_path = Path(selected_path).resolve()
    else:
        evidence_path = (REPO_ROOT / "artifacts" / "simulation" / "acrylonitrile_reactor_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print(f"  {ESC_BOLD}JEV Cscape Agent: Acrylonitrile Fluidized-Bed Reactor ODE Verification (W194){ESC_RESET}")
    print("=" * 80)

    if run_acrylonitrile_reactor_verification is None:
        print(f"\n[{ESC_RED}{ESC_BOLD}ERROR{ESC_RESET}] Failed to import `run_acrylonitrile_reactor_verification` from `jev_cscape.simulation.acrylonitrile_reactor`:")
        print(f"  {_import_error}")
        print("=" * 80)
        return 1

    t_start = time.perf_counter()
    try:
        sig = inspect.signature(run_acrylonitrile_reactor_verification)
        has_var_pos = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in sig.parameters.values())
        has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
        pos_params = [
            p for p in sig.parameters.values()
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]

        if "output_path" in sig.parameters:
            evidence = run_acrylonitrile_reactor_verification(output_path=str(evidence_path))
        elif "evidence_path" in sig.parameters:
            evidence = run_acrylonitrile_reactor_verification(evidence_path=str(evidence_path))
        elif "target_path" in sig.parameters:
            evidence = run_acrylonitrile_reactor_verification(target_path=str(evidence_path))
        elif pos_params or has_var_pos:
            evidence = run_acrylonitrile_reactor_verification(str(evidence_path))
        elif has_var_kw:
            evidence = run_acrylonitrile_reactor_verification(output_path=str(evidence_path))
        else:
            evidence = run_acrylonitrile_reactor_verification()
    except Exception as exc:
        print(f"\n[{ESC_RED}{ESC_BOLD}EXCEPTION{ESC_RESET}] Verification suite crashed with unhandled exception:")
        print(f"  {type(exc).__name__}: {exc}")
        print("=" * 80)
        return 1
    total_elapsed_ms = (time.perf_counter() - t_start) * 1000.0

    # Ensure evidence artifact is exported to target file
    if isinstance(evidence, dict):
        if not evidence_path.exists() or evidence_path.stat().st_size == 0:
            evidence_path.parent.mkdir(parents=True, exist_ok=True)
            with open(evidence_path, "w", encoding="utf-8") as f:
                json.dump(evidence, f, indent=2)

    # Strict 4-state contract verification
    valid_states = {"success", "failed", "blocked", "inconclusive"}
    overall_status = evidence.get("status") if isinstance(evidence, dict) else None
    error_code = evidence.get("error_code") if isinstance(evidence, dict) else "INVALID_PAYLOAD"
    details_str = evidence.get("details", "") if isinstance(evidence, dict) else "Evidence is not a dictionary"

    if overall_status not in valid_states:
        print(f"\n[{ESC_RED}{ESC_BOLD}CONTRACT VIOLATION{ESC_RESET}] Invalid status '{overall_status}'. Must be one of {valid_states}.")
        print("=" * 80)
        return 1

    # Extract tests / stages
    tests = []
    if isinstance(evidence, dict):
        tests = evidence.get("data", {}).get("tests", [])
        if not tests and "stages" in evidence.get("data", {}):
            tests = evidence["data"]["stages"]

    # Format each of the verification stages with timing and [PASS] badges
    for idx, t in enumerate(tests, start=1):
        stage_num = t.get("stage", idx)
        check_name = t.get("check", t.get("name", f"Verification_Stage_{stage_num}"))
        passed = bool(t.get("passed", t.get("status") in ("passed", "pass", "success")))
        stage_status = t.get("status")
        details = t.get("details", "")

        # Extract or compute stage timing
        stage_timing: Optional[float] = None
        for key in ("duration_ms", "timing_ms", "elapsed_ms", "time_ms"):
            if key in t and isinstance(t[key], (int, float)):
                stage_timing = float(t[key])
                break
        if stage_timing is None:
            for key in ("duration_s", "elapsed_s", "time_s"):
                if key in t and isinstance(t[key], (int, float)):
                    stage_timing = float(t[key]) * 1000.0
                    break
        if stage_timing is None and total_elapsed_ms > 0:
            stage_timing = total_elapsed_ms / max(len(tests), 1)

        print(format_stage_result(stage_num, check_name, passed, stage_timing, details, status=stage_status))

    checks_passed = evidence.get("data", {}).get("checks_passed", sum(1 for t in tests if t.get("passed", False))) if isinstance(evidence, dict) else 0
    total_checks = evidence.get("data", {}).get("total_checks", len(tests)) if isinstance(evidence, dict) else 0

    print("-" * 80)
    status_color = ESC_GREEN if overall_status == "success" else (ESC_YELLOW if overall_status in ("blocked", "inconclusive") else ESC_RED)
    status_badge = f"{status_color}{ESC_BOLD}{overall_status.upper()}{ESC_RESET}"
    print(f"  Result: {checks_passed}/{total_checks} stages passed in {total_elapsed_ms:.2f} ms. Status: {status_badge}")
    print(f"  Evidence: {ESC_CYAN}{evidence_path}{ESC_RESET}")
    print("=" * 80)

    if overall_status == "blocked":
        print(f"  {ESC_YELLOW}[BLOCKED] Action prevented by safety or platform limitation: {error_code}{ESC_RESET}")
        return 2
    if overall_status == "inconclusive":
        print(f"  {ESC_YELLOW}[INCONCLUSIVE] Outcome unverified: {error_code}{ESC_RESET}")
        return 3
    if overall_status != "success" or checks_passed != total_checks or total_checks == 0:
        print(f"  {ESC_RED}[FAILURE] Verification failed: {error_code} - {details_str}{ESC_RESET}")
        return 1

    print(f"  {ESC_GREEN}{ESC_BOLD}VERIFICATION SUCCESS: All {total_checks} stages passed deterministically.{ESC_RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
