# -*- coding: utf-8 -*-
"""Gate G7 Visual Reopen Screenshot Verification Engine.

Mandate: Automated colorimetric and structural verification of Cscape 10.2 reopen screenshots.
Verifies dimensions (1278x566 client rect) and verifies that the center ROI contains
ladder editor canvas grid and rung wires, fail-closing if occluded by modal dialogs
(e.g., 'About Cscape' #32770 popup).

Status Contract: strictly returns status: success | failed | blocked | inconclusive
Classification: TESTED_MOCK / INTEGRATION [offline/DEV]
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple

from PIL import Image

logger = logging.getLogger("visual_reopen_verifier")

# Default paths and geometry
DEFAULT_RUNS_DIR = Path(__file__).resolve().parent.parent / "artifacts" / "G7" / "campaign_runs"
DEFAULT_EXPECTED_DIMS = (1278, 566)
DEFAULT_CENTER_ROI = (450, 150, 800, 400)  # (x1, y1, x2, y2)

# Colorimetric invariants
COLOR_CANVAS_GRAY = (210, 210, 210)
COLOR_WIRE_BLACK = (0, 0, 0)
HORNER_NAVY_R = (20, 35)
HORNER_NAVY_G = (30, 50)
HORNER_NAVY_B = (75, 105)


@dataclass
class ScreenshotVerificationResult:
    filename: str
    filepath: str
    dimensions: Tuple[int, int]
    dimension_verified: bool
    roi: Tuple[int, int, int, int]
    roi_pixel_count: int
    canvas_gray_pixels: int
    canvas_gray_pct: float
    wire_black_pixels: int
    wire_black_pct: float
    navy_logo_pixels: int
    navy_logo_pct: float
    unique_colors_in_roi: int
    classification: str
    status: str
    failure_reasons: List[str]


def verify_single_screenshot(
    image_path: Path,
    expected_dims: Tuple[int, int] = DEFAULT_EXPECTED_DIMS,
    roi: Tuple[int, int, int, int] = DEFAULT_CENTER_ROI,
    min_canvas_gray_pct: float = 15.0,
    min_wire_black_pixels: int = 100,
    max_navy_logo_pixels: int = 10,
) -> ScreenshotVerificationResult:
    """Verify geometry, ladder canvas presence, and dialog occlusion for a single screenshot."""
    failures: List[str] = []

    if not image_path.exists():
        return ScreenshotVerificationResult(
            filename=image_path.name,
            filepath=str(image_path),
            dimensions=(0, 0),
            dimension_verified=False,
            roi=roi,
            roi_pixel_count=0,
            canvas_gray_pixels=0,
            canvas_gray_pct=0.0,
            wire_black_pixels=0,
            wire_black_pct=0.0,
            navy_logo_pixels=0,
            navy_logo_pct=0.0,
            unique_colors_in_roi=0,
            classification="FILE_NOT_FOUND",
            status="failed",
            failure_reasons=["Screenshot file does not exist on disk."],
        )

    with Image.open(image_path) as im:
        w, h = im.size
        dim_ok = (w, h) == expected_dims
        if not dim_ok:
            failures.append(f"Dimensions mismatch: expected {expected_dims}, actual ({w}, {h})")

        crop = im.crop(roi)
        roi_w = roi[2] - roi[0]
        roi_h = roi[3] - roi[1]
        roi_area = roi_w * roi_h

        colors = crop.getcolors(maxcolors=200000)
        col_map = {c: cnt for cnt, c in colors} if colors else {}

        # 1. Canvas background gray (210, 210, 210)
        canvas_gray = col_map.get(COLOR_CANVAS_GRAY, 0)
        canvas_gray_pct = (canvas_gray / roi_area) * 100.0

        # 2. Black wire / contact / coil pixels (0, 0, 0)
        black_pixels = col_map.get(COLOR_WIRE_BLACK, 0)
        black_pct = (black_pixels / roi_area) * 100.0

        # 3. Horner APG brand navy blue (About dialog logo banner)
        navy_pixels = 0
        for (r, g, b), count in col_map.items():
            if (HORNER_NAVY_R[0] <= r <= HORNER_NAVY_R[1] and
                HORNER_NAVY_G[0] <= g <= HORNER_NAVY_G[1] and
                HORNER_NAVY_B[0] <= b <= HORNER_NAVY_B[1]):
                navy_pixels += count
        navy_pct = (navy_pixels / roi_area) * 100.0

        unique_colors = len(col_map)

        # Classification decision
        is_canvas = (
            canvas_gray_pct >= min_canvas_gray_pct
            and navy_pixels <= max_navy_logo_pixels
            and black_pixels >= min_wire_black_pixels
        )
        is_about_modal = (navy_pixels >= 500) or (canvas_gray_pct < 5.0 and unique_colors > 1500)

        if is_canvas and not is_about_modal:
            classification = "CANVAS_CLEAR"
        elif is_about_modal:
            classification = "ABOUT_DIALOG_OCCLUDED"
            failures.append(
                f"Center ROI occluded by About Cscape dialog (navy logo: {navy_pixels} px, canvas gray: {canvas_gray_pct:.2f}%)"
            )
        else:
            classification = "UNKNOWN_STATE"
            failures.append(
                f"Center ROI did not match ladder canvas or about dialog (canvas gray: {canvas_gray_pct:.2f}%, unique colors: {unique_colors})"
            )

        if not is_canvas:
            if canvas_gray_pct < min_canvas_gray_pct and "occluded" not in " ".join(failures):
                failures.append(f"Canvas gray below threshold ({canvas_gray_pct:.2f}% < {min_canvas_gray_pct}%)")
            if black_pixels < min_wire_black_pixels and "occluded" not in " ".join(failures):
                failures.append(f"Black wire pixels below threshold ({black_pixels} < {min_wire_black_pixels})")
            if navy_pixels > max_navy_logo_pixels and "occluded" not in " ".join(failures):
                failures.append(f"Navy logo pixels detected ({navy_pixels} > {max_navy_logo_pixels})")

        status = "success" if (dim_ok and is_canvas and not failures) else "failed"

        return ScreenshotVerificationResult(
            filename=image_path.name,
            filepath=str(image_path),
            dimensions=(w, h),
            dimension_verified=dim_ok,
            roi=roi,
            roi_pixel_count=roi_area,
            canvas_gray_pixels=canvas_gray,
            canvas_gray_pct=round(canvas_gray_pct, 2),
            wire_black_pixels=black_pixels,
            wire_black_pct=round(black_pct, 2),
            navy_logo_pixels=navy_pixels,
            navy_logo_pct=round(navy_pct, 2),
            unique_colors_in_roi=unique_colors,
            classification=classification,
            status=status,
            failure_reasons=failures,
        )


def verify_all_campaign_screenshots(
    runs_dir: Path = DEFAULT_RUNS_DIR,
    pattern: str = "run_*_reopen.png",
    expected_dims: Tuple[int, int] = DEFAULT_EXPECTED_DIMS,
    roi: Tuple[int, int, int, int] = DEFAULT_CENTER_ROI,
) -> Dict[str, Any]:
    """Audit all campaign reopen screenshots in the designated directory."""
    images = sorted(runs_dir.glob(pattern))
    results: List[ScreenshotVerificationResult] = []

    for img_path in images:
        res = verify_single_screenshot(img_path, expected_dims=expected_dims, roi=roi)
        results.append(res)

    passed_count = sum(1 for r in results if r.status == "success")
    failed_count = sum(1 for r in results if r.status == "failed")
    overall_status = "success" if (results and failed_count == 0) else "failed"

    return {
        "status": overall_status,
        "runs_directory": str(runs_dir),
        "total_evaluated": len(results),
        "runs_passed": passed_count,
        "runs_failed": failed_count,
        "results": [asdict(r) for r in results],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit Cscape Gate G7 reopen screenshots.")
    parser.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS_DIR, help="Path to campaign runs directory")
    parser.add_argument("--json-out", type=Path, default=None, help="Optional output JSON audit deliverable")
    args = parser.parse_args()

    report = verify_all_campaign_screenshots(runs_dir=args.runs_dir)

    print("=" * 80)
    print(f"GATE G7 REOPEN SCREENSHOT VISUAL AUDIT: {report['status'].upper()}")
    print(f"Evaluated: {report['total_evaluated']} | Passed: {report['runs_passed']} | Failed: {report['runs_failed']}")
    print("-" * 80)
    for r in report["results"]:
        status_tag = "[PASS]" if r["status"] == "success" else "[FAIL]"
        print(
            f"{status_tag} {r['filename']:<20} | DimOK={r['dimension_verified']!s:<5} | "
            f"Gray={r['canvas_gray_pct']:>5.2f}% | Navy={r['navy_logo_pct']:>4.2f}% | "
            f"Black={r['wire_black_pct']:>4.2f}% | {r['classification']}"
        )
        if r["failure_reasons"]:
            for f in r["failure_reasons"]:
                print(f"       -> {f}")
    print("=" * 80)

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"JSON audit deliverable written to {args.json_out}")

    return 0 if report["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
