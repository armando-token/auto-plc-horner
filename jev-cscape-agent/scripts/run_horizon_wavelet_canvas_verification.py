#!/usr/bin/env python3
"""Verification Script for Cscape HMI Dynamic Horizon / Multi-Horizon Wavelet Decomposition SCADA Canvas (W195).

Work Package: W195 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Multi-Horizon Wavelet Visualizer & Frequency Decomposition]
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/HMI/horizon_wavelet_canvas_evidence.json
  artifacts/HMI/horizon_wavelet_canvas_sample.svg
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
    from jev_cscape.hmi.horizon_wavelet_canvas import (
        run_horizon_wavelet_canvas_verification,
    )
    _import_error = None
except ImportError as exc:
    try:
        from jev_cscape.hmi import run_horizon_wavelet_canvas_verification
        _import_error = None
    except ImportError:
        run_horizon_wavelet_canvas_verification = None
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
    stage: Union[int, str],
    check: str,
    passed: bool,
    timing_ms: Optional[float] = None,
    details: str = "",
    status: Optional[str] = None,
) -> str:
    """Format a single stage line with ANSI colored badge, timing, and description."""
    badge = format_stage_badge(passed, status)
    if timing_ms is not None:
        timing_str = f"[{timing_ms:.2f}ms]"
    else:
        timing_str = "[--ms]"

    if isinstance(stage, int):
        stage_str = f"Stage {stage:2d}"
    else:
        stage_str = f"Stage {stage}"

    line = f"  {stage_str}: {badge} {timing_str} {check}"
    if details:
        line += f"\n            {CLR_GRAY}-> {details}{CLR_RESET}"
    return line


def main(argv: Optional[List[str]] = None) -> int:
    """Main verification CLI entry point."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Run Cscape HMI Dynamic Horizon / Multi-Horizon Wavelet Decomposition SCADA Canvas (W195) 9-Stage Verification Suite."
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
        "--output",
        "-o",
        "--evidence",
        "--evidence-path",
        "-e",
        dest="output_path",
        type=str,
        default=None,
        help="Path to write JSON evidence artifact.",
    )
    parser.add_argument(
        "--svg",
        "-s",
        "--svg-path",
        dest="svg_path",
        type=str,
        default=None,
        help="Path to write SVG sample artifact.",
    )
    args = parser.parse_args(argv)

    default_evidence = str(REPO_ROOT / "artifacts" / "HMI" / "horizon_wavelet_canvas_evidence.json")
    default_svg = str(REPO_ROOT / "artifacts" / "HMI" / "horizon_wavelet_canvas_sample.svg")

    evidence_file_str = args.output_path or args.positional_output or default_evidence
    svg_file_str = args.svg_path or args.positional_svg or default_svg

    evidence_path = Path(evidence_file_str).resolve()
    svg_path = Path(svg_file_str).resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")
    print(f"  {CLR_BOLD}JEV Cscape Agent: Horizon Wavelet Canvas Verification (W195){CLR_RESET}")
    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")

    if run_horizon_wavelet_canvas_verification is None:
        print(f"  {CLR_RED}[FAIL] Unable to import run_horizon_wavelet_canvas_verification: {_import_error}{CLR_RESET}")
        failure_payload: Dict[str, Any] = {
            "status": "failed",
            "error_code": "IMPORT_ERROR",
            "details": f"Unable to import run_horizon_wavelet_canvas_verification: {_import_error}",
            "data": {
                "work_package": "W195",
                "gate": "Gate G9 / G2",
                "component": "Cscape HMI Dynamic Horizon / Multi-Horizon Wavelet Decomposition SCADA Canvas",
                "checks_passed": 0,
                "total_checks": 9,
                "tests": [],
            },
        }
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(failure_payload, f, indent=2)
        return 1

    call_kwargs: Dict[str, Any] = {}
    start_time = time.perf_counter()
    try:
        sig = inspect.signature(run_horizon_wavelet_canvas_verification)
        for p in sig.parameters.values():
            name = p.name
            if name in ("output_path", "evidence_path", "target_evidence_path", "output", "target_path"):
                call_kwargs[name] = str(evidence_path)
            elif name in ("sample_svg_path", "svg_path", "target_svg_path", "svg_export_path", "svg"):
                call_kwargs[name] = str(svg_path)

        if call_kwargs:
            report = run_horizon_wavelet_canvas_verification(**call_kwargs)
        else:
            try:
                report = run_horizon_wavelet_canvas_verification(
                    output_path=str(evidence_path),
                    sample_svg_path=str(svg_path),
                )
            except TypeError:
                report = run_horizon_wavelet_canvas_verification(str(evidence_path), str(svg_path))
        elapsed_total_ms = (time.perf_counter() - start_time) * 1000.0
    except Exception as ex:
        elapsed_total_ms = (time.perf_counter() - start_time) * 1000.0
        print(f"  {CLR_RED}[FAIL] Verification failed with exception: {ex}{CLR_RESET}")
        failure_payload = {
            "status": "failed",
            "error_code": "VERIFICATION_EXCEPTION",
            "details": f"Verification failed with exception: {ex}",
            "data": {
                "work_package": "W195",
                "gate": "Gate G9 / G2",
                "component": "Cscape HMI Dynamic Horizon / Multi-Horizon Wavelet Decomposition SCADA Canvas",
                "duration_ms": elapsed_total_ms,
                "checks_passed": 0,
                "total_checks": 9,
                "tests": [],
            },
        }
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(failure_payload, f, indent=2)
        return 1

    # Ensure evidence artifact is written to target path
    if isinstance(report, dict):
        if not evidence_path.is_file() or evidence_path.stat().st_size == 0:
            with open(evidence_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

    # Export sample SVG if present in report and not already written
    data = report.get("data", {}) if isinstance(report, dict) else {}
    svg_content = (
        data.get("svg")
        or data.get("svg_content")
        or data.get("svg_sample")
        or (report.get("svg") if isinstance(report, dict) else None)
        or (report.get("svg_content") if isinstance(report, dict) else None)
    )
    if svg_content and (not svg_path.is_file() or svg_path.stat().st_size == 0):
        with open(svg_path, "w", encoding="utf-8") as f:
            f.write(svg_content)

    # Strict 4-state contract verification
    valid_states = {"success", "failed", "blocked", "inconclusive"}
    overall_status = report.get("status") if isinstance(report, dict) else None
    error_code = report.get("error_code") if isinstance(report, dict) else "INVALID_PAYLOAD"
    details_str = report.get("details", "") if isinstance(report, dict) else "Report is not a dictionary"

    if overall_status not in valid_states:
        print(f"\n{CLR_RED}{CLR_BOLD}[CONTRACT VIOLATION]{CLR_RESET} Invalid status '{overall_status}'. Must be one of {valid_states}.")
        print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")
        return 1

    # Extract tests / stages
    tests = data.get("tests", [])
    if not tests and "stages" in data:
        tests = data["stages"]

    # Format console output showing all 9 verification stages with timing and [PASS] badges
    for idx, t in enumerate(tests, start=1):
        stage_num = t.get("stage", idx)
        check_name = t.get("check", t.get("name", f"Verification_Stage_{stage_num}"))
        passed = bool(t.get("passed", t.get("status") in ("passed", "pass", "success")))
        stage_status = t.get("status", None)
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
        if stage_timing is None and elapsed_total_ms > 0:
            stage_timing = elapsed_total_ms / max(len(tests), 1)

        print(format_stage_result(stage_num, check_name, passed, stage_timing, details, status=stage_status))

    passed_count = sum(1 for t in tests if t.get("passed", False) or t.get("status") in ("passed", "pass", "success"))
    total_count = len(tests)

    print(f"{CLR_CYAN}{'-' * 80}{CLR_RESET}")
    print(f"  Total Checks: {passed_count}/{total_count} passing (in {elapsed_total_ms:.2f} ms)")
    print(f"  Evidence:     {evidence_path}")
    print(f"  SVG Sample:   {svg_path}")
    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")

    if overall_status == "blocked":
        print(f"  {CLR_YELLOW}[BLOCKED] Action prevented by safety or platform limitation: {error_code}{CLR_RESET}")
        return 2
    if overall_status == "inconclusive":
        print(f"  {CLR_YELLOW}[INCONCLUSIVE] Outcome unverified: {error_code}{CLR_RESET}")
        return 3
    if overall_status != "success" or passed_count != total_count or total_count < 9:
        print(f"  {CLR_RED}{CLR_BOLD}VERIFICATION FAILED: Verification did not pass (status={overall_status}, passed={passed_count}/{total_count}). {error_code} - {details_str}{CLR_RESET}")
        return 1

    print(f"  {CLR_GREEN}{CLR_BOLD}VERIFICATION SUCCESS: All 9 stages passed deterministically.{CLR_RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
