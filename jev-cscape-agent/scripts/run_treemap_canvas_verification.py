#!/usr/bin/env python3
"""Verification Script for Cscape HMI Dynamic Treemap Hierarchical Resource & Heat Allocation Canvas (W117).

Work Package: W117 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Status Contract: Strict 4-State JSON output & evidence emission.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
import sys

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root / "src") not in sys.path:
    sys.path.insert(0, str(repo_root / "src"))
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

try:
    from jev_cscape.hmi.treemap_canvas import run_treemap_canvas_verification
except ImportError as e:
    # Allow running when treemap_canvas is not yet available, reporting proper error
    run_treemap_canvas_verification = None
    _import_error = e


def main() -> int:
    evidence_path = repo_root / "artifacts" / "HMI" / "treemap_canvas_evidence.json"
    svg_path = repo_root / "artifacts" / "HMI" / "treemap_canvas_sample.svg"

    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.parent.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("  JEV Cscape Agent: Treemap Canvas Verification (W117)")
    print("=" * 80)

    if run_treemap_canvas_verification is None:
        print(f"[FAIL] Unable to import run_treemap_canvas_verification: {_import_error}")
        return 1

    try:
        sig = inspect.signature(run_treemap_canvas_verification)
        kwargs = {}
        if "evidence_path" in sig.parameters:
            kwargs["evidence_path"] = str(evidence_path)
        if "svg_path" in sig.parameters:
            kwargs["svg_path"] = str(svg_path)
        elif "svg_export_path" in sig.parameters:
            kwargs["svg_export_path"] = str(svg_path)

        if kwargs:
            evidence = run_treemap_canvas_verification(**kwargs)
        else:
            evidence = run_treemap_canvas_verification(str(evidence_path), str(svg_path))
    except TypeError:
        evidence = run_treemap_canvas_verification(str(evidence_path), str(svg_path))

    tests = evidence.get("data", {}).get("tests", [])
    for t in tests:
        st = "PASS" if t.get("passed") else "FAIL"
        print(f"  Stage {t.get('stage')}: [{st}] {t.get('check')}")

    passed_count = evidence.get("data", {}).get("checks_passed", sum(1 for t in tests if t.get("passed")))
    total_count = evidence.get("data", {}).get("total_checks", len(tests))

    print("-" * 80)
    print(f"[*] Outcome: {passed_count}/{total_count} checks passed.")
    print(f"[*] Status: {evidence.get('status')}")
    print(f"[*] Evidence artifact saved: {evidence_path.resolve()}")
    print(f"[*] SVG canvas artifact saved: {svg_path.resolve()}")
    print("=" * 80)

    return 0 if evidence.get("status") == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
