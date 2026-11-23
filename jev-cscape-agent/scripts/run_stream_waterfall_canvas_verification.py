#!/usr/bin/env python3
"""Verification Script for Cscape HMI Dynamic Stream / Waterfall Multi-Epoch Hydrodynamic Flow SCADA Canvas (W189).

Work Package: W189 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Status Contract: Strict 4-State JSON output & evidence emission.
"""

from __future__ import annotations

import argparse
import inspect
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict

# Ensure repository root and src are on sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root / "src") not in sys.path:
    sys.path.insert(0, str(repo_root / "src"))
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

try:
    from jev_cscape.hmi.stream_waterfall_canvas import (
        run_stream_waterfall_canvas_verification,
    )
except ImportError as e:
    run_stream_waterfall_canvas_verification = None
    _import_error = e

# ANSI color escape codes
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_GREEN = "\033[92m"
CLR_RED = "\033[91m"
CLR_YELLOW = "\033[93m"
CLR_CYAN = "\033[96m"
CLR_GRAY = "\033[90m"


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Run Dynamic Stream / Waterfall Multi-Epoch Hydrodynamic Flow Canvas (W189) 9-Stage Verification Suite."
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
    args = parser.parse_args()

    default_evidence = str(repo_root / "artifacts" / "HMI" / "stream_waterfall_canvas_evidence.json")
    default_svg = str(repo_root / "artifacts" / "HMI" / "stream_waterfall_canvas_sample.svg")

    evidence_file_str = args.output_path or args.positional_output or default_evidence
    svg_file_str = args.svg_path or args.positional_svg or default_svg

    evidence_path = Path(evidence_file_str)
    svg_path = Path(svg_file_str)

    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")
    print(f"  {CLR_BOLD}JEV Cscape Agent: Stream / Waterfall Flow Canvas Verification (W189){CLR_RESET}")
    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")

    if run_stream_waterfall_canvas_verification is None:
        print(f"  {CLR_RED}[FAIL] Unable to import run_stream_waterfall_canvas_verification: {_import_error}{CLR_RESET}")
        failure_payload: Dict[str, Any] = {
            "status": "failed",
            "error_code": "IMPORT_ERROR",
            "details": f"Unable to import run_stream_waterfall_canvas_verification: {_import_error}",
            "data": {
                "work_package": "W189",
                "gate": "Gate G9 / G2",
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
        sig = inspect.signature(run_stream_waterfall_canvas_verification)
        for p in sig.parameters.values():
            name = p.name
            if name in ("output_path", "evidence_path", "target_evidence_path", "output", "target_path"):
                call_kwargs[name] = str(evidence_path)
            elif name in ("sample_svg_path", "svg_path", "target_svg_path", "svg_export_path", "svg"):
                call_kwargs[name] = str(svg_path)

        if call_kwargs:
            report = run_stream_waterfall_canvas_verification(**call_kwargs)
        else:
            report = run_stream_waterfall_canvas_verification(
                output_path=str(evidence_path),
                sample_svg_path=str(svg_path),
            )
        elapsed_total_ms = (time.perf_counter() - start_time) * 1000.0
    except Exception as ex:
        elapsed_total_ms = (time.perf_counter() - start_time) * 1000.0
        print(f"  {CLR_RED}[FAIL] Verification failed with exception: {ex}{CLR_RESET}")
        failure_payload = {
            "status": "failed",
            "error_code": "VERIFICATION_EXCEPTION",
            "details": f"Verification failed with exception: {ex}",
            "data": {
                "work_package": "W189",
                "gate": "Gate G9 / G2",
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
    if not evidence_path.is_file() or evidence_path.stat().st_size == 0:
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    # Pretty print verification stages
    data = report.get("data", {})
    svg_content = data.get("svg") or data.get("svg_content") or data.get("svg_sample")
    if svg_content and (not svg_path.is_file() or svg_path.stat().st_size == 0):
        with open(svg_path, "w", encoding="utf-8") as f:
            f.write(svg_content)
    tests = data.get("tests", [])

    for t in tests:
        stage = t.get("stage", "?")
        check = t.get("check", "Unknown")
        passed = t.get("passed", False)
        details = t.get("details", "")

        # Format timing
        if "duration_ms" in t and t["duration_ms"] is not None:
            timing_str = f"[{t['duration_ms']:.2f}ms]"
        elif "duration" in t and t["duration"] is not None:
            timing_str = f"[{t['duration']}]"
        elif "timing" in t and t["timing"] is not None:
            timing_str = f"[{t['timing']}]"
        elif "duration_s" in t and t["duration_s"] is not None:
            timing_str = f"[{t['duration_s'] * 1000.0:.2f}ms]"
        else:
            per_stage_ms = elapsed_total_ms / max(len(tests), 1)
            timing_str = f"[{per_stage_ms:.2f}ms]"

        status_str = f"{CLR_GREEN}[PASS]{CLR_RESET}" if passed else f"{CLR_RED}[FAIL]{CLR_RESET}"
        if isinstance(stage, int):
            print(f"  Stage {stage:2d}: {status_str} {timing_str} {check}")
        else:
            print(f"  Stage {stage}: {status_str} {timing_str} {check}")

        if details:
            print(f"            {CLR_GRAY}-> {details}{CLR_RESET}")

    passed_count = sum(1 for t in tests if t.get("passed", False))
    total_count = len(tests)

    print(f"{CLR_CYAN}{'-' * 80}{CLR_RESET}")
    print(f"  Total Checks: {passed_count}/{total_count} passing (in {elapsed_total_ms:.2f} ms)")
    print(f"  Evidence:     {evidence_path.resolve()}")
    print(f"  SVG Sample:   {svg_path.resolve()}")
    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")

    status = report.get("status", "unknown")
    if status == "success" and passed_count == total_count and total_count >= 9:
        print(f"  {CLR_GREEN}{CLR_BOLD}VERIFICATION SUCCESS: All 9 stages passed deterministically.{CLR_RESET}")
        return 0
    else:
        print(f"  {CLR_RED}{CLR_BOLD}VERIFICATION FAILED: One or more checks did not pass (status={status}).{CLR_RESET}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
