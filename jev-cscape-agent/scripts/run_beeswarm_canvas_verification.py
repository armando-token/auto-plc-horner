#!/usr/bin/env python3
"""Verification Script for Cscape HMI Dynamic Beeswarm Jitter Scatter SCADA Canvas (W228).

Work Package: W228 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Beeswarm Jitter Scatter SCADA Canvas]
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/HMI/beeswarm_canvas_evidence.json
  artifacts/HMI/beeswarm_canvas_sample.svg
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
    from jev_cscape.hmi.beeswarm_canvas import (
        run_beeswarm_canvas_verification,
    )
    _import_error = None
except ImportError as exc:
    try:
        from jev_cscape.hmi import run_beeswarm_canvas_verification
        _import_error = None
    except ImportError:
        run_beeswarm_canvas_verification = None
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
    if passed:
        return f"{CLR_GREEN}{CLR_BOLD}[PASS]{CLR_RESET}"
    return f"{CLR_RED}{CLR_BOLD}[FAIL]{CLR_RESET}"


def main() -> int:
    """Execute W228 Beeswarm Canvas verification suite and output report."""
    parser = argparse.ArgumentParser(
        description="Verify Cscape HMI Dynamic Beeswarm Jitter Scatter SCADA Canvas (W228)"
    )
    parser.add_argument(
        "--evidence",
        "--output",
        "-o",
        type=str,
        default="artifacts/HMI/beeswarm_canvas_evidence.json",
        help="Path for generated JSON verification evidence",
    )
    parser.add_argument(
        "--svg",
        "-s",
        type=str,
        default="artifacts/HMI/beeswarm_canvas_sample.svg",
        help="Path for generated sample SVG vector visual",
    )
    parser.add_argument(
        "--json",
        "--json-only",
        action="store_true",
        help="Output raw strict 4-state contract JSON to stdout",
    )
    args = parser.parse_args()

    if not args.json:
        print(f"\n{CLR_BOLD}{CLR_CYAN}========================================================================{CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN}  JEV CSCAPE AGENT - WAVE W228 BEESWARM CANVAS VERIFICATION RUNNER     {CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN}  Classification: PRODUCTION_READY (Gate G9 / Gate G2 Live GUI)        {CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN}========================================================================{CLR_RESET}\n")

    if run_beeswarm_canvas_verification is None:
        fail_payload: Dict[str, Any] = {
            "status": "failed",
            "error_code": "IMPORT_ERROR",
            "details": f"Failed to import run_beeswarm_canvas_verification: {_import_error}",
            "data": {"work_package": "W228", "error": str(_import_error)},
        }
        if args.json:
            print(json.dumps(fail_payload, indent=2))
        else:
            print(f"{CLR_RED}Import Error: {_import_error}{CLR_RESET}")
        return 1

    evidence_path = Path(args.evidence)
    svg_path = Path(args.svg)

    # Inspect runner signature to pass supported arguments
    sig = inspect.signature(run_beeswarm_canvas_verification)
    kwargs: Dict[str, Any] = {}
    if "evidence_path" in sig.parameters:
        kwargs["evidence_path"] = evidence_path
    elif "output_path" in sig.parameters:
        kwargs["output_path"] = evidence_path
    if "svg_path" in sig.parameters:
        kwargs["svg_path"] = svg_path
    elif "sample_svg_path" in sig.parameters:
        kwargs["sample_svg_path"] = svg_path

    t0 = time.perf_counter()
    report = run_beeswarm_canvas_verification(**kwargs)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if report.get("status") == "success" else 1

    status = report.get("status", "unknown")
    err_code = report.get("error_code")
    details = report.get("details", "")
    data = report.get("data", {})
    checks = data.get("tests", [])

    print(f"Status Contract: {CLR_BOLD}{status.upper()}{CLR_RESET} (error_code: {err_code})")
    print(f"Details:         {details}")
    print(f"Duration:        {elapsed_ms:.2f} ms\n")
    print(f"{CLR_BOLD}Stage Verification Matrix:{CLR_RESET}")
    print(f"{'#':<3} {'Stage Name':<52} {'Status':<10} {'Details'}")
    print(f"{'-'*3} {'-'*52} {'-'*10} {'-'*40}")

    for idx, c in enumerate(checks, start=1):
        c_num = c.get("stage", idx)
        c_name = c.get("name", f"Stage {c_num}")
        c_passed = bool(c.get("passed", False))
        c_badge = format_stage_badge(c_passed)
        c_det = c.get("details", "")
        print(f"{c_num:<3} {c_name:<52} {c_badge:<19} {CLR_GRAY}{c_det}{CLR_RESET}")

    print(f"\n{CLR_BOLD}Artifacts Emitted:{CLR_RESET}")
    print(f"  - Evidence JSON: {CLR_CYAN}{evidence_path}{CLR_RESET} ({evidence_path.stat().st_size if evidence_path.exists() else 0} bytes)")
    print(f"  - Sample SVG:    {CLR_CYAN}{svg_path}{CLR_RESET} ({svg_path.stat().st_size if svg_path.exists() else 0} bytes)")

    print(f"\n{CLR_BOLD}{CLR_CYAN}========================================================================{CLR_RESET}")
    if status == "success":
        print(f"  {CLR_GREEN}{CLR_BOLD}ALL 9 VERIFICATION STAGES PASSED CLEANLY (Gate G9 / G2 Sealed){CLR_RESET}")
    else:
        print(f"  {CLR_RED}{CLR_BOLD}VERIFICATION FAILED: {err_code} - {details}{CLR_RESET}")
    print(f"{CLR_BOLD}{CLR_CYAN}========================================================================{CLR_RESET}\n")

    return 0 if status == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
