#!/usr/bin/env python3
"""Verification Script for Cscape HMI Dynamic Ternary Phase Diagram SCADA Canvas (W243).

Work Package: W243 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Ternary Phase Diagram SCADA Canvas]
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/HMI/ternary_phase_canvas_evidence.json
  artifacts/HMI/ternary_phase_canvas_sample.svg
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
    from jev_cscape.hmi.ternary_phase_canvas import (
        run_ternary_phase_canvas_verification,
    )
    _import_error = None
except ImportError as exc:
    try:
        from jev_cscape.hmi import run_ternary_phase_canvas_verification
        _import_error = None
    except ImportError:
        run_ternary_phase_canvas_verification = None
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
    """Execute W243 Ternary Phase Canvas verification suite and output report."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Verify Cscape HMI Dynamic Ternary Phase Diagram SCADA Canvas (W243)"
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
        dest="svg_path",
        type=str,
        default=None,
        help="Path for generated sample SVG vector visual",
    )
    parser.add_argument(
        "--work-package",
        type=str,
        default="W243",
        help="Work package identifier (default: W243)",
    )
    parser.add_argument(
        "--json",
        "--json-only",
        action="store_true",
        help="Output raw strict 4-state contract JSON to stdout",
    )
    args = parser.parse_args(argv)

    default_evidence = str(REPO_ROOT / "artifacts" / "HMI" / "ternary_phase_canvas_evidence.json")
    default_svg = str(REPO_ROOT / "artifacts" / "HMI" / "ternary_phase_canvas_sample.svg")

    evidence_file_str = args.output_path or args.positional_output or default_evidence
    svg_file_str = args.svg_path or args.positional_svg or default_svg

    evidence_path = Path(evidence_file_str).resolve()
    svg_path = Path(svg_file_str).resolve()

    # Ensure parent directories exist
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print(f"\n{CLR_BOLD}{CLR_CYAN}{'=' * 80}{CLR_RESET}")
        print(f"  {CLR_BOLD}JEV CSCAPE AGENT - WAVE W243 TERNARY PHASE CANVAS VERIFICATION RUNNER{CLR_RESET}")
        print(f"  {CLR_BOLD}Classification: PRODUCTION_READY (Gate G9 / Gate G2 Live GUI){CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN}{'=' * 80}{CLR_RESET}\n")

    if run_ternary_phase_canvas_verification is None:
        fail_payload: Dict[str, Any] = {
            "status": "failed",
            "error_code": "IMPORT_ERROR",
            "details": f"Failed to import run_ternary_phase_canvas_verification: {_import_error}",
            "data": {
                "work_package": args.work_package,
                "gate": "Gate G9 / G2",
                "component": "Cscape HMI Dynamic Ternary Phase Diagram SCADA Canvas",
                "checks_passed": 0,
                "total_checks": 9,
                "tests": [],
            },
        }
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(fail_payload, f, indent=2)

        if args.json:
            print(json.dumps(fail_payload, indent=2))
        else:
            print(f"  {CLR_RED}[FAIL] Import Error: {_import_error}{CLR_RESET}")
        return 1

    start_time = time.perf_counter()
    try:
        sig = inspect.signature(run_ternary_phase_canvas_verification)
        kwargs: Dict[str, Any] = {}
        for p in sig.parameters.values():
            name = p.name
            if name in ("output_path", "evidence_path", "target_evidence_path", "output", "target_path"):
                kwargs[name] = str(evidence_path)
            elif name in ("sample_svg_path", "svg_path", "target_svg_path", "svg_export_path", "svg"):
                kwargs[name] = str(svg_path)
            elif name == "work_package":
                kwargs["work_package"] = args.work_package

        if kwargs:
            report = run_ternary_phase_canvas_verification(**kwargs)
        else:
            try:
                report = run_ternary_phase_canvas_verification(
                    output_path=str(evidence_path),
                    sample_svg_path=str(svg_path),
                )
            except TypeError:
                report = run_ternary_phase_canvas_verification(str(evidence_path), str(svg_path))
        elapsed_total_ms = (time.perf_counter() - start_time) * 1000.0
    except Exception as ex:
        elapsed_total_ms = (time.perf_counter() - start_time) * 1000.0
        fail_payload = {
            "status": "failed",
            "error_code": "VERIFICATION_EXCEPTION",
            "details": f"Verification failed with exception: {ex}",
            "data": {
                "work_package": args.work_package,
                "gate": "Gate G9 / G2",
                "component": "Cscape HMI Dynamic Ternary Phase Diagram SCADA Canvas",
                "duration_ms": elapsed_total_ms,
                "checks_passed": 0,
                "total_checks": 9,
                "tests": [],
            },
        }
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(fail_payload, f, indent=2)

        if args.json:
            print(json.dumps(fail_payload, indent=2))
        else:
            print(f"  {CLR_RED}[FAIL] Verification failed with exception: {ex}{CLR_RESET}")
        return 1

    # Ensure evidence artifact exists on disk
    if isinstance(report, dict):
        if not evidence_path.is_file() or evidence_path.stat().st_size == 0:
            with open(evidence_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if isinstance(report, dict) and report.get("status") == "success" else 1

    # Extract test matrix
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

    print(f"\n{CLR_CYAN}{'-' * 80}{CLR_RESET}")
    overall_status = report.get("status", "unknown") if isinstance(report, dict) else "unknown"
    status_badge = format_stage_badge(overall_status in ("success", "passed"), overall_status)
    print(f"  Result: {checks_passed}/{total_checks} stages passed in {elapsed_total_ms:.2f} ms. Status: {status_badge}")
    print(f"  Evidence:   {CLR_CYAN}{evidence_path}{CLR_RESET} ({evidence_path.stat().st_size if evidence_path.exists() else 0} bytes)")
    print(f"  Sample SVG: {CLR_CYAN}{svg_path}{CLR_RESET} ({svg_path.stat().st_size if svg_path.exists() else 0} bytes)")
    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}\n")

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
