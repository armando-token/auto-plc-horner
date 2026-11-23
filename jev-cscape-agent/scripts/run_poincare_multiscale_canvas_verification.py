#!/usr/bin/env python3
"""Verification Script for Cscape HMI Dynamic Hyperbolic Poincaré Multiscale Radial Asset SCADA Canvas (W264).

Work Package: W264 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Hyperbolic Poincaré Multiscale Radial Asset SCADA Canvas]
Status Contract: Strict 4-State JSON output & evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: Poincare Hyperbolic Metric & Geodesic Arc Geometry
  Stage 2: Pure IEC 61131-3 ST POU Validation with STParser and SecurityGuard
  Stage 3: Anti-Ladder Security Guard Interception
  Stage 4: Mobius Conformal Transformation & Angle Preservation
  Stage 5: WCAG AAA Color Contrast Compliance (>= 18:1 badges, >= 7:1 text)
  Stage 6: Boundary Overflow & Singularity Fault Injections (0x7801, 0x7802, %M526)
  Stage 7: Hyperbolic Panning / Navigation & Focus Translation
  Stage 8: Horner OCS Register Table Synchronization (%R2250..%R2257, %M525..%M526)
  Stage 9: Visual Grounding Fallback & High-Res SVG Export

Exports:
  artifacts/HMI/poincare_multiscale_canvas_evidence.json
  artifacts/HMI/poincare_multiscale_canvas_sample.svg
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
    from jev_cscape.hmi.poincare_multiscale_canvas import (
        run_poincare_multiscale_canvas_verification,
        main as canvas_main,
    )
    _import_error = None
except ImportError as exc:
    try:
        from jev_cscape.hmi import run_poincare_multiscale_canvas_verification
        canvas_main = None
        _import_error = None
    except ImportError:
        run_poincare_multiscale_canvas_verification = None
        canvas_main = None
        _import_error = exc

# ANSI color escape codes matching repo conventions
CLR_RESET  = "\033[0m"
CLR_BOLD   = "\033[1m"
CLR_DIM    = "\033[2m"
CLR_GREEN  = "\033[92m"
CLR_RED    = "\033[91m"
CLR_YELLOW = "\033[93m"
CLR_CYAN   = "\033[96m"
CLR_GRAY   = "\033[90m"


def format_stage_badge(passed: bool, status: Optional[str] = None) -> str:
    """Format strict 4-state contract ANSI badge."""
    norm_status = (status or "").lower()
    if norm_status == "blocked":
        return f"{CLR_YELLOW}{CLR_BOLD}[BLOCKED]{CLR_RESET}"
    if norm_status == "inconclusive":
        return f"{CLR_YELLOW}{CLR_BOLD}[INCONCLUSIVE]{CLR_RESET}"
    if passed or norm_status in ("passed", "pass", "success"):
        return f"{CLR_GREEN}{CLR_BOLD}[PASS]{CLR_RESET}"
    return f"{CLR_RED}{CLR_BOLD}[FAIL]{CLR_RESET}"


def format_stage_result(
    stage_num: Union[int, str],
    check_name: str,
    passed: bool,
    timing_ms: float = 0.0,
    details: str = "",
    status: Optional[str] = None,
) -> str:
    """Format single stage output row."""
    badge = format_stage_badge(passed, status)
    time_str = f"{CLR_DIM}({timing_ms:6.2f} ms){CLR_RESET}" if timing_ms > 0 else ""
    if isinstance(stage_num, int):
        stage_str = f"Stage {stage_num:02d}"
    else:
        stage_str = f"Stage {stage_num}"
    out = f"  {stage_str}: {badge} {check_name:<65} {time_str}"
    if details:
        out += f"\n            {CLR_GRAY}-> {details}{CLR_RESET}"
    return out


def main(argv: Optional[List[str]] = None) -> int:
    """Execute W264 Poincaré Multiscale Canvas verification suite and output report."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Verify Cscape HMI Dynamic Hyperbolic Poincaré Multiscale Radial Asset SCADA Canvas (W264)"
    )
    parser.add_argument(
        "positional_output",
        nargs="?",
        default=None,
        help="Optional positional path to write JSON evidence artifact.",
    )
    parser.add_argument(
        "positional_svg",
        nargs="?",
        default=None,
        help="Optional positional path to write SVG sample artifact.",
    )
    parser.add_argument(
        "--evidence",
        "--output",
        "-o",
        dest="output_path",
        type=str,
        default=None,
        help="Path for generated JSON verification evidence",
    )
    parser.add_argument(
        "--sample-svg",
        "--svg",
        "-s",
        dest="sample_svg_path",
        type=str,
        default=None,
        help="Path for generated sample SVG canvas graphic",
    )
    parser.add_argument(
        "--work-package",
        type=str,
        default="W264",
        help="Work package identifier (default: W264)",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Emit raw JSON report only (no ANSI stdout banner)",
    )

    args = parser.parse_args(argv)

    resolved_evidence = (
        args.output_path
        or args.positional_output
        or str(REPO_ROOT / "artifacts" / "HMI" / "poincare_multiscale_canvas_evidence.json")
    )
    resolved_svg = (
        args.sample_svg_path
        or args.positional_svg
        or str(REPO_ROOT / "artifacts" / "HMI" / "poincare_multiscale_canvas_sample.svg")
    )

    evidence_path = Path(resolved_evidence)
    svg_path = Path(resolved_svg)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json_only:
        print()
        print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")
        print(f"  {CLR_BOLD}JEV CSCAPE AGENT - WAVE W264 POINCARÉ MULTISCALE CANVAS VERIFICATION RUNNER{CLR_RESET}")
        print(f"  {CLR_DIM}Classification: PRODUCTION_READY (Gate G9 / Gate G2 Live GUI){CLR_RESET}")
        print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")
        print()

    if run_poincare_multiscale_canvas_verification is None:
        if not args.json_only:
            print(f"  {CLR_RED}[FAIL] Unable to import run_poincare_multiscale_canvas_verification: {_import_error}{CLR_RESET}")
        failure_payload: Dict[str, Any] = {
            "status": "failed",
            "error_code": "IMPORT_ERROR",
            "details": f"Unable to import run_poincare_multiscale_canvas_verification: {_import_error}",
            "data": {
                "work_package": args.work_package,
                "gate": "Gate G9 / Gate G2",
                "component": "Cscape HMI Dynamic Hyperbolic Poincare Multiscale Radial Asset SCADA Canvas",
                "checks_passed": 0,
                "total_checks": 9,
                "tests": [],
            },
        }
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(failure_payload, f, indent=2)
        return 1

    start_time = time.perf_counter()
    try:
        sig = inspect.signature(run_poincare_multiscale_canvas_verification)
        kwargs: Dict[str, Any] = {}
        if "output_path" in sig.parameters:
            kwargs["output_path"] = str(evidence_path)
        elif "evidence_path" in sig.parameters:
            kwargs["evidence_path"] = str(evidence_path)
        if "sample_svg_path" in sig.parameters:
            kwargs["sample_svg_path"] = str(svg_path)
        elif "svg_path" in sig.parameters:
            kwargs["svg_path"] = str(svg_path)
        elif "svg_output_path" in sig.parameters:
            kwargs["svg_output_path"] = str(svg_path)
        if "work_package" in sig.parameters:
            kwargs["work_package"] = args.work_package

        report = run_poincare_multiscale_canvas_verification(**kwargs)
        elapsed_total_ms = (time.perf_counter() - start_time) * 1000.0
    except Exception as ex:
        elapsed_total_ms = (time.perf_counter() - start_time) * 1000.0
        if not args.json_only:
            print(f"  {CLR_RED}[FAIL] Verification failed with exception: {ex}{CLR_RESET}")
        failure_payload = {
            "status": "failed",
            "error_code": "VERIFICATION_EXCEPTION",
            "details": f"Verification failed with exception: {ex}",
            "data": {
                "work_package": args.work_package,
                "gate": "Gate G9 / Gate G2",
                "component": "Cscape HMI Dynamic Hyperbolic Poincare Multiscale Radial Asset SCADA Canvas",
                "duration_ms": elapsed_total_ms,
                "checks_passed": 0,
                "total_checks": 9,
                "tests": [],
            },
        }
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(failure_payload, f, indent=2)
        return 1

    if args.json_only:
        print(json.dumps(report, indent=2))
        return 0 if report.get("status") == "success" else 1

    # Format output stages
    tests = report.get("data", {}).get("tests", []) if isinstance(report, dict) else []
    total_checks = report.get("data", {}).get("total_checks", len(tests)) if isinstance(report, dict) else len(tests)
    checks_passed = report.get("data", {}).get("checks_passed", 0) if isinstance(report, dict) else 0

    stage_duration_estimate = (elapsed_total_ms / max(len(tests), 1)) if tests else 0.0
    for idx, t in enumerate(tests, start=1):
        stage_num = t.get("stage", idx)
        check_name = t.get("check", f"Stage_{stage_num}")
        passed = t.get("passed", False)
        status = t.get("status", "passed" if passed else "failed")
        details = t.get("details", "")
        timing_ms = t.get("timing_ms", stage_duration_estimate)
        print(format_stage_result(stage_num, check_name, passed, timing_ms, details, status))

    print()
    print(f"{CLR_CYAN}{'-' * 80}{CLR_RESET}")
    overall_status = report.get("status", "unknown") if isinstance(report, dict) else "unknown"
    status_badge = format_stage_badge(overall_status in ("success", "passed"), overall_status)
    evidence_size = evidence_path.stat().st_size if evidence_path.is_file() else 0
    svg_size = svg_path.stat().st_size if svg_path.is_file() else 0

    print(f"  Result: {checks_passed}/{total_checks} stages passed in {elapsed_total_ms:.2f} ms. Status: {status_badge}")
    print(f"  Evidence:   {CLR_CYAN}{evidence_path}{CLR_RESET} ({evidence_size} bytes)")
    print(f"  Sample SVG: {CLR_CYAN}{svg_path}{CLR_RESET} ({svg_size} bytes)")
    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")
    print()

    if overall_status == "blocked":
        print(f"  {CLR_YELLOW}[BLOCKED] Action prevented by safety or platform limitation{CLR_RESET}\n")
        return 0

    if overall_status != "success" or checks_passed < total_checks:
        print(f"  {CLR_RED}{CLR_BOLD}VERIFICATION FAILED: {total_checks - checks_passed} check(s) did not pass.{CLR_RESET}\n")
        return 1

    print(f"  {CLR_GREEN}{CLR_BOLD}VERIFICATION SUCCESS: All {total_checks} stages passed deterministically.{CLR_RESET}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
