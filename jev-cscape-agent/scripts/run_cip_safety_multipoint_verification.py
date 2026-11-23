#!/usr/bin/env python3
"""Verification Script for Industrial ODVA EtherNet/IP CIP Safety Multi-Point Protocol Engine (W214).

Work Package: W214 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/telemetry/cip_safety_multipoint_evidence.json
"""

from __future__ import annotations

import argparse
import inspect
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional

# Ensure repository root and src/ are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from jev_cscape.telemetry.cip_safety_multipoint import run_cip_safety_multipoint_verification
    _import_error = None
except ImportError as exc:
    try:
        from jev_cscape.telemetry import run_cip_safety_multipoint_verification
        _import_error = None
    except ImportError:
        run_cip_safety_multipoint_verification = None
        _import_error = exc

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
        description="JEV Cscape Agent: Industrial ODVA CIP Safety Multi-Point Verification (W214)"
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
    args = parser.parse_args(argv)

    selected_path = args.flag_path or args.positional_path
    if selected_path:
        evidence_path = Path(selected_path).resolve()
    else:
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_multipoint_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print(f"  {ESC_BOLD}JEV Cscape Agent: Industrial CIP Safety Multi-Point Engine Verification (W214){ESC_RESET}")
    print("=" * 80)

    fn = run_cip_safety_multipoint_verification
    if fn is None:
        try:
            from jev_cscape.telemetry.cip_safety_multipoint import (
                run_cip_safety_multipoint_verification as _resolved_fn,
            )
            fn = _resolved_fn
        except ImportError:
            try:
                from jev_cscape.telemetry import run_cip_safety_multipoint_verification as _resolved_fn
                fn = _resolved_fn
            except ImportError:
                fn = None

    if fn is None:
        print(f"\n[{ESC_RED}{ESC_BOLD}ERROR{ESC_RESET}] Failed to import `run_cip_safety_multipoint_verification` from `jev_cscape.telemetry.cip_safety_multipoint`:")
        print(f"  {_import_error}")
        print("=" * 80)
        return 1

    t_start = time.perf_counter()
    try:
        sig = inspect.signature(fn)
        if "output_path" in sig.parameters:
            evidence = fn(output_path=str(evidence_path))
        elif "evidence_path" in sig.parameters:
            evidence = fn(evidence_path=str(evidence_path))
        elif len(sig.parameters) > 0:
            evidence = fn(str(evidence_path))
        else:
            evidence = fn()
    except Exception as exc:
        print(f"\n[{ESC_RED}{ESC_BOLD}EXCEPTION{ESC_RESET}] Verification suite crashed with unhandled exception:")
        print(f"  {type(exc).__name__}: {exc}")
        print("=" * 80)
        return 1
    total_elapsed_ms = (time.perf_counter() - t_start) * 1000.0

    if hasattr(evidence, "to_dict"):
        evidence = evidence.to_dict()

    if isinstance(evidence, dict):
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

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
    print(f"Evidence Artifact: {evidence_path}")
    print(f"Engineering Contract Status: {overall_status.upper()}")

    if overall_status == "success":
        print(f"\n{ESC_GREEN}{ESC_BOLD}[SUCCESS] All 9 CIP Safety Multi-Point protocol stages PASSED deterministically.{ESC_RESET}")
        print("=" * 80)
        return 0
    else:
        print(f"\n{ESC_RED}{ESC_BOLD}[FAILED] Verification failed with status '{overall_status}' (error_code: {error_code}).{ESC_RESET}")
        print(f"Details: {details_str}")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(main())
