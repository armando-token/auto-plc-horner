#!/usr/bin/env python3
"""Verification Script for Cscape HMI Dynamic Hexagonal Binning Heatmap & Density Scatter SCADA Canvas (W225).

Work Package: W225 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Hexagonal Binning Heatmap & Density Scatter SCADA Canvas]
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/HMI/hexbin_canvas_evidence.json
  artifacts/HMI/hexbin_canvas_sample.svg
"""

from __future__ import annotations

import argparse
import inspect
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

try:
    from jev_cscape.hmi.hexbin_canvas import (
        run_hexbin_canvas_verification,
    )
    _import_error = None
except ImportError as exc:
    try:
        from jev_cscape.hmi import run_hexbin_canvas_verification
        _import_error = None
    except ImportError:
        run_hexbin_canvas_verification = None
        _import_error = exc

# ANSI color escape codes matching repo conventions
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_DIM = "\033[2m"
CLR_GREEN = "\033[92m"
CLR_RED = "\033[91m"
CLR_YELLOW = "\033[93m"
CLR_CYAN = "\033[96m"
CLR_GRAY = "\033[90m"


def format_stage_badge(passed: bool, status: Optional[str] = None) -> str:
    """Format strict 4-state contract ANSI badge."""
    norm_status = (status or "").lower()
    if norm_status == "blocked":
        return f"{CLR_YELLOW}{CLR_BOLD}[BLOCKED]{CLR_RESET}"
    if norm_status == "inconclusive":
        return f"{CLR_YELLOW}{CLR_BOLD}[INCONCLUSIVE]{CLR_RESET}"
    if passed or norm_status in ("passed", "success"):
        return f"{CLR_GREEN}{CLR_BOLD}[PASS]{CLR_RESET}"
    return f"{CLR_RED}{CLR_BOLD}[FAIL]{CLR_RESET}"


def format_stage_result(
    stage_num: int,
    check_name: str,
    passed: bool,
    timing_ms: float = 0.0,
    details: str = "",
    status: Optional[str] = None,
) -> str:
    """Format single stage output row."""
    badge = format_stage_badge(passed, status)
    time_str = f"{CLR_DIM}({timing_ms:6.2f} ms){CLR_RESET}" if timing_ms > 0 else ""
    out = f"  Stage {stage_num:02d}: {badge} {check_name:<50} {time_str}"
    if details:
        out += f"\n            {CLR_GRAY}-> {details}{CLR_RESET}"
    return out


def main() -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(
        description="Run Cscape HMI Dynamic Hexagonal Binning Heatmap & Density Scatter SCADA Canvas Verification (W225)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="artifacts/HMI/hexbin_canvas_evidence.json",
        help="Path to output verification evidence JSON",
    )
    parser.add_argument(
        "--svg",
        "-s",
        type=str,
        default="artifacts/HMI/hexbin_canvas_sample.svg",
        help="Path to output standalone SVG sample",
    )
    parser.add_argument(
        "--work-package",
        type=str,
        default="W225",
        help="Work package identifier (default: W225)",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Emit raw JSON report only (no ANSI stdout banner)",
    )
    args = parser.parse_args()

    evidence_path = Path(args.output)
    svg_path = Path(args.svg)

    # Ensure parent directories exist
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json_only:
        print(f"\n{CLR_CYAN}{'=' * 80}{CLR_RESET}")
        print(f"  {CLR_BOLD}JEV Cscape Agent: Hexagonal Binning Heatmap & Scatter SCADA Canvas Verification (W225){CLR_RESET}")
        print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")

    if run_hexbin_canvas_verification is None:
        if not args.json_only:
            print(f"  {CLR_RED}[FAIL] Unable to import run_hexbin_canvas_verification: {_import_error}{CLR_RESET}")
        failure_payload: Dict[str, Any] = {
            "status": "failed",
            "error_code": "IMPORT_ERROR",
            "details": f"Unable to import run_hexbin_canvas_verification: {_import_error}",
            "data": {
                "work_package": args.work_package,
                "gate": "Gate G9 / G2",
                "component": "Cscape HMI Dynamic Hexagonal Binning Heatmap & Density Scatter SCADA Canvas",
                "checks_passed": 0,
                "total_checks": 9,
                "tests": [],
            },
        }
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(failure_payload, f, indent=2)
        print(json.dumps(failure_payload, indent=2))
        return 1

    t0 = time.perf_counter()
    report = run_hexbin_canvas_verification(
        output_path=evidence_path,
        sample_svg_path=svg_path,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    if args.json_only:
        print(json.dumps(report, indent=2))
        return 0 if report.get("status") == "success" else 1

    tests = report.get("data", {}).get("tests", [])
    checks_passed = report.get("data", {}).get("checks_passed", 0)
    total_checks = report.get("data", {}).get("total_checks", 0)

    for t in tests:
        st_num = t.get("stage", 0)
        st_check = t.get("check", "Unknown_Check")
        st_pass = bool(t.get("passed", False))
        st_details = t.get("details", "")
        print(format_stage_result(st_num, st_check, st_pass, details=st_details))

    print(f"\n{CLR_CYAN}{'-' * 80}{CLR_RESET}")
    status_str = report.get("status", "unknown").upper()
    if status_str == "SUCCESS":
        status_badge = f"{CLR_GREEN}{CLR_BOLD}[SUCCESS]{CLR_RESET}"
    else:
        status_badge = f"{CLR_RED}{CLR_BOLD}[{status_str}]{CLR_RESET}"

    print(f"  Result: {status_badge}  Passed: {checks_passed}/{total_checks} stages ({elapsed_ms:.1f} ms)")
    print(f"  Evidence: {CLR_BOLD}{evidence_path}{CLR_RESET}")
    print(f"  Sample SVG: {CLR_BOLD}{svg_path}{CLR_RESET}")
    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}\n")

    return 0 if report.get("status") == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
