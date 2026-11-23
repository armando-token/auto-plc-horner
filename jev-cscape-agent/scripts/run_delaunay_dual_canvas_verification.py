#!/usr/bin/env python3
"""Deterministic 9-Stage Verification Runner for Cscape HMI Dynamic Spatial Geohash / Delaunay Triangulation Dual Graph SCADA Canvas (W327).

Work Package: W327 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Geohash / Delaunay Triangulation Dual Graph SCADA Canvas]
Status Contract: Strict 4-State JSON output (success | failed | blocked | inconclusive) & evidence emission.

Features:
- Pure Python 2D Delaunay Triangulation & Dual Voronoi Facets Algorithm:
  - Bowyer-Watson incremental Delaunay Triangulation dual graph (O(N log N)).
  - Voronoi polygonal cell generation via analytical Sutherland-Hodgman convex polygon clipping.
  - Morton Z-order curve bit-interleaving and Base32 Geohash spatial hashing.
- Dynamic Spatial Proximity Hazard Collision Detection:
  - Real-time proximity hazard collision alarm when inter-node distance < safety_threshold_m.
  - Asserts discrete coil %M673 and diagnostic code 0x8440 (DIAG_PROXIMITY_HAZARD_COLLISION).
- Vector SCADA Visual Grounding (W3C SVG 1.1):
  - Primal Delaunay edges (cyan/blue) + Dual Voronoi polygons (amber/green transparent fills).
  - High-contrast HUD scorecard (> 18:1 contrast, WCAG 2.1 AAA).
- Horner OCS Memory Space Integration:
  - Registers %R2880..%R2887, coils %M672..%M673.
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

from jev_cscape.hmi.delaunay_dual_canvas import (
    COIL_DELAUNAY_COLLISION_ALARM,
    COIL_DELAUNAY_ONLINE,
    DIAG_DELAUNAY_COORDINATE_OUT_OF_BOUNDS,
    DIAG_DELAUNAY_DEGENERATE_NODES,
    DIAG_OK,
    DIAG_PROXIMITY_HAZARD_COLLISION,
    REG_DELAUNAY_DIAGNOSTIC_CODE,
    REG_DELAUNAY_QUERY_LATENCY_US,
    REG_DELAUNAY_SELECTED_NODE_X,
    REG_DELAUNAY_SELECTED_NODE_Y,
    REG_DELAUNAY_TOPOLOGY_HASH_HI,
    REG_DELAUNAY_TOTAL_NODES,
    REG_DELAUNAY_TRIANGLE_COUNT,
    REG_DELAUNAY_VORONOI_FACETS,
    DelaunayDualCanvasEngine,
    DiagnosticCode,
    generate_delaunay_dual_canvas_svg,
    run_delaunay_dual_canvas_verification,
    verify_delaunay_dual_canvas_pure_st,
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
        description="Deterministic 9-Stage Verification Runner for Delaunay Dual Graph SCADA Canvas (W327)"
    )
    parser.add_argument(
        "positional_output",
        nargs="?",
        default=None,
        help="Optional positional path for output evidence JSON file",
    )
    parser.add_argument(
        "positional_svg",
        nargs="?",
        default=None,
        help="Optional positional path for output sample SVG file",
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="output_path",
        default=None,
        help="Path to output JSON evidence artifact (default: artifacts/HMI/delaunay_dual_canvas_evidence.json)",
    )
    parser.add_argument(
        "--svg",
        "-s",
        dest="svg_output_path",
        default=None,
        help="Path to output sample SVG file (default: artifacts/HMI/delaunay_dual_canvas_sample.svg)",
    )
    parser.add_argument(
        "--quick",
        "-q",
        action="store_true",
        default=False,
        help="Execute quick verification mode",
    )
    parser.add_argument(
        "--work-package",
        "-w",
        default="W327",
        help="Work package ID (default: W327)",
    )
    parser.add_argument(
        "--json",
        "--json-only",
        action="store_true",
        dest="json_mode",
        help="Emit raw JSON report only (no ANSI stdout banner)",
    )
    args = parser.parse_args(argv)

    selected_output = args.output_path or args.positional_output
    if selected_output:
        evidence_path = Path(selected_output).resolve()
    else:
        evidence_path = (REPO_ROOT / "artifacts" / "HMI" / "delaunay_dual_canvas_evidence.json").resolve()

    selected_svg = args.svg_output_path or args.positional_svg
    if selected_svg:
        svg_path = Path(selected_svg).resolve()
    else:
        svg_path = (REPO_ROOT / "artifacts" / "HMI" / "delaunay_dual_canvas_sample.svg").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json_mode:
        print("=" * 80)
        print(f"  {ESC_BOLD}JEV Cscape Agent: Delaunay Dual Graph SCADA Canvas Verification ({args.work_package}){ESC_RESET}")
        print("=" * 80)

    t0 = time.perf_counter()
    try:
        evidence = run_delaunay_dual_canvas_verification(
            output_path=evidence_path,
            sample_svg_path=svg_path,
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

    if args.json_mode:
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
    print(f"[*] Sample SVG saved:         {ESC_CYAN}{svg_path}{ESC_RESET}")
    print("=" * 80)

    return 0 if status_str == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
