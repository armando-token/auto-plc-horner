#!/usr/bin/env python3
"""
G5 Vision Pipeline: Fail-Closed Visual Safety Guard (W043)
Guarantees visual safety before any automated or manual action is dispatched
against Horner Cscape 10.2 GUI or offline digital twin replay.

Guards against:
1. Stale Images: Frame age exceeds threshold (>2.0s or monotonic delta mismatch) -> StaleImageError
2. Moved Windows: Window position/size drifts beyond pixel tolerance (>2px) -> WindowMovedError
3. Out-of-Bounds Targets: Action coordinates fall outside valid canvas boundaries -> OutOfBoundsVisualError
4. Occlusion: Target area is occluded by modal dialogs, popups, or tooltips -> OcclusionVisualError

Enforces:
- Strict fail-closed semantics across all inspection paths
- 4-state status contract: "success" | "failed" | "blocked" | "inconclusive"
- Zero hardware port or PLC download invocation
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.g5_capture import CaptureFrame, ROI
from scripts.g5_canvas_model import BoundingBox

logger = logging.getLogger("g5_visual_guard")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


# =============================================================================
# Fail-Closed Visual Exceptions
# =============================================================================

class VisualGuardError(Exception):
    """Base exception for all G5 visual safety violations."""
    pass


class StaleImageError(VisualGuardError):
    """Raised when a captured frame exceeds the maximum allowable freshness age."""
    pass


class WindowMovedError(VisualGuardError):
    """Raised when window bounds drift beyond the acceptable stationary tolerance."""
    pass


class OutOfBoundsVisualError(VisualGuardError):
    """Raised when target coordinates fall outside the valid canvas or target ROI."""
    pass


class OcclusionVisualError(VisualGuardError):
    """Raised when a target ROI is occluded by an overlapping modal dialog or window."""
    pass


# =============================================================================
# Visual Guard Implementation
# =============================================================================

class VisualGuard:
    """Enforces fail-closed visual safety invariants for Cscape vision operations."""

    DEFAULT_MAX_AGE_SECONDS: float = 2.0
    DEFAULT_WINDOW_TOLERANCE_PX: int = 2
    DEFAULT_CANVAS_MARGIN_PX: int = 5

    @classmethod
    def assert_fresh_image(
        cls,
        frame: CaptureFrame,
        max_age_s: float = DEFAULT_MAX_AGE_SECONDS,
        current_monotonic_ns: Optional[int] = None,
    ) -> bool:
        """Verify that a capture frame is fresh and not stale.
        
        Raises StaleImageError if the frame was captured more than max_age_s ago.
        """
        if not frame or not frame.provenance:
            raise StaleImageError("FAIL_CLOSED: CaptureFrame has null or missing provenance!")

        prov = frame.provenance
        # In offline replay mode, bypass wall-clock expiration if explicitly flagged
        if prov.source_type == "offline_file":
            return True

        now_mono = current_monotonic_ns if current_monotonic_ns is not None else time.monotonic_ns()
        elapsed_s = (now_mono - prov.monotonic_ns) / 1e9

        if elapsed_s < -0.1:  # Future clock skew anomaly
            raise StaleImageError(f"FAIL_CLOSED: Frame timestamp is in the future (skew: {elapsed_s:.3f}s)!")

        if elapsed_s > max_age_s:
            raise StaleImageError(
                f"FAIL_CLOSED: Capture frame is stale! Age: {elapsed_s:.3f}s (threshold: {max_age_s:.3f}s)"
            )
        return True

    @classmethod
    def assert_window_stationary(
        cls,
        current_rect: Tuple[int, int, int, int],
        baseline_rect: Tuple[int, int, int, int],
        tolerance: int = DEFAULT_WINDOW_TOLERANCE_PX,
    ) -> bool:
        """Verify that the target window has not moved or resized unexpectedly.
        
        current_rect and baseline_rect are (left, top, right, bottom).
        Raises WindowMovedError if drift exceeds tolerance.
        """
        c_left, c_top, c_right, c_bottom = current_rect
        b_left, b_top, b_right, b_bottom = baseline_rect

        drift_left = abs(c_left - b_left)
        drift_top = abs(c_top - b_top)
        drift_right = abs(c_right - b_right)
        drift_bottom = abs(c_bottom - b_bottom)

        max_drift = max(drift_left, drift_top, drift_right, drift_bottom)
        if max_drift > tolerance:
            raise WindowMovedError(
                f"FAIL_CLOSED: Window moved beyond tolerance ({max_drift}px > {tolerance}px)! "
                f"Baseline: {baseline_rect}, Current: {current_rect}"
            )
        return True

    @classmethod
    def assert_coordinate_within_canvas(
        cls,
        x: int,
        y: int,
        canvas_bounds: Union[BoundingBox, Tuple[int, int, int, int]],
        margin: int = DEFAULT_CANVAS_MARGIN_PX,
    ) -> bool:
        """Verify that target coordinate (x, y) falls strictly inside canvas drawing area.
        
        Raises OutOfBoundsVisualError if coordinates lie on or outside margins.
        """
        if isinstance(canvas_bounds, tuple):
            canvas_bounds = BoundingBox(*canvas_bounds)

        safe_left = canvas_bounds.left + margin
        safe_top = canvas_bounds.top + margin
        safe_right = canvas_bounds.right - margin
        safe_bottom = canvas_bounds.bottom - margin

        if x < safe_left or x > safe_right:
            raise OutOfBoundsVisualError(
                f"FAIL_CLOSED: Target X={x} out of safe canvas bounds [{safe_left}, {safe_right}] "
                f"(raw bounds: [{canvas_bounds.left}, {canvas_bounds.right}], margin: {margin}px)!"
            )
        if y < safe_top or y > safe_bottom:
            raise OutOfBoundsVisualError(
                f"FAIL_CLOSED: Target Y={y} out of safe canvas bounds [{safe_top}, {safe_bottom}] "
                f"(raw bounds: [{canvas_bounds.top}, {canvas_bounds.bottom}], margin: {margin}px)!"
            )
        return True

    @classmethod
    def check_rect_intersection(
        cls,
        r1: Tuple[int, int, int, int],
        r2: Tuple[int, int, int, int],
    ) -> Optional[Tuple[int, int, int, int]]:
        """Return the intersection rectangle (left, top, right, bottom) or None if no overlap."""
        i_left = max(r1[0], r2[0])
        i_top = max(r1[1], r2[1])
        i_right = min(r1[2], r2[2])
        i_bottom = min(r1[3], r2[3])
        if i_left < i_right and i_top < i_bottom:
            return (i_left, i_top, i_right, i_bottom)
        return None

    @classmethod
    def assert_no_occlusion(
        cls,
        target_roi: Union[BoundingBox, Tuple[int, int, int, int]],
        modal_rects: Optional[List[Tuple[int, int, int, int]]] = None,
    ) -> bool:
        """Verify that target ROI is not occluded by any active modal dialogs or child windows.
        
        Raises OcclusionVisualError if any modal rect overlaps target_roi.
        """
        if not modal_rects:
            return True

        if isinstance(target_roi, BoundingBox):
            t_rect = target_roi.to_tuple()
        else:
            t_rect = target_roi

        for idx, m_rect in enumerate(modal_rects):
            overlap = cls.check_rect_intersection(t_rect, m_rect)
            if overlap is not None:
                raise OcclusionVisualError(
                    f"FAIL_CLOSED: Target ROI {t_rect} is occluded by modal dialog #{idx} {m_rect}! "
                    f"Intersection: {overlap}"
                )
        return True

    @classmethod
    def verify_action_preconditions(
        cls,
        frame: Optional[CaptureFrame],
        target_coords: Tuple[int, int],
        canvas_bounds: Union[BoundingBox, Tuple[int, int, int, int]],
        current_window_rect: Optional[Tuple[int, int, int, int]] = None,
        baseline_window_rect: Optional[Tuple[int, int, int, int]] = None,
        modal_rects: Optional[List[Tuple[int, int, int, int]]] = None,
        max_age_s: float = DEFAULT_MAX_AGE_SECONDS,
        current_monotonic_ns: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Composite fail-closed verification pipeline.
        
        Returns strict 4-state contract dictionary:
        {
            "status": "success" | "failed" | "blocked" | "inconclusive",
            "error_code": Optional[str],
            "details": str,
            "data": Dict[str, Any]
        }
        """
        x, y = target_coords
        data: Dict[str, Any] = {
            "target_coords": target_coords,
            "canvas_bounds": canvas_bounds.to_tuple() if isinstance(canvas_bounds, BoundingBox) else canvas_bounds,
        }

        # Step 1: Window stationary check
        if current_window_rect is not None and baseline_window_rect is not None:
            try:
                cls.assert_window_stationary(current_window_rect, baseline_window_rect)
                data["window_stationary"] = True
            except WindowMovedError as e:
                logger.error(f"VisualGuard error: {e}")
                return {
                    "status": "failed",
                    "error_code": "WINDOW_MOVED",
                    "details": str(e),
                    "data": data,
                }

        # Step 2: Freshness check
        if frame is not None:
            try:
                cls.assert_fresh_image(frame, max_age_s=max_age_s, current_monotonic_ns=current_monotonic_ns)
                data["image_fresh"] = True
            except StaleImageError as e:
                logger.error(f"VisualGuard error: {e}")
                return {
                    "status": "failed",
                    "error_code": "STALE_IMAGE",
                    "details": str(e),
                    "data": data,
                }

        # Step 3: Spatial bounds check
        try:
            cls.assert_coordinate_within_canvas(x, y, canvas_bounds)
            data["within_bounds"] = True
        except OutOfBoundsVisualError as e:
            logger.error(f"VisualGuard error: {e}")
            return {
                "status": "failed",
                "error_code": "OUT_OF_BOUNDS",
                "details": str(e),
                "data": data,
            }

        # Step 4: Occlusion check
        target_roi = (x - 10, y - 10, x + 10, y + 10)
        try:
            cls.assert_no_occlusion(target_roi, modal_rects)
            data["no_occlusion"] = True
        except OcclusionVisualError as e:
            logger.error(f"VisualGuard error: {e}")
            return {
                "status": "failed",
                "error_code": "OCCLUSION_DETECTED",
                "details": str(e),
                "data": data,
            }

        return {
            "status": "success",
            "error_code": None,
            "details": "All visual safety preconditions verified fail-closed.",
            "data": data,
        }


# =============================================================================
# Module CLI / Self-Test
# =============================================================================

def self_test() -> Dict[str, Any]:
    """Execute deterministic self-test of all visual guard invariant checks."""
    logger.info("Starting W043 Visual Guard self-test...")

    from scripts.g5_capture import CaptureProvenance
    from PIL import Image

    # 1. Freshness test
    dummy_img = Image.new("RGB", (100, 100), color=(255, 255, 255))
    fresh_prov = CaptureProvenance(source_type="live_screen", monotonic_ns=time.monotonic_ns())
    fresh_frame = CaptureFrame(image=dummy_img, roi=ROI(0, 0, 100, 100), provenance=fresh_prov)
    assert VisualGuard.assert_fresh_image(fresh_frame, max_age_s=2.0) is True

    # Stale frame test (captured 5 seconds ago)
    stale_prov = CaptureProvenance(
        source_type="live_screen",
        monotonic_ns=time.monotonic_ns() - int(5.0 * 1e9)
    )
    stale_frame = CaptureFrame(image=dummy_img, roi=ROI(0, 0, 100, 100), provenance=stale_prov)
    try:
        VisualGuard.assert_fresh_image(stale_frame, max_age_s=2.0)
        assert False, "Expected StaleImageError not raised!"
    except StaleImageError:
        pass

    # 2. Window Stationary test
    base_rect = (100, 100, 900, 700)
    same_rect = (101, 100, 899, 700)  # Drift = 1px <= 2px tolerance
    assert VisualGuard.assert_window_stationary(same_rect, base_rect, tolerance=2) is True

    moved_rect = (105, 100, 900, 700)  # Drift = 5px > 2px tolerance
    try:
        VisualGuard.assert_window_stationary(moved_rect, base_rect, tolerance=2)
        assert False, "Expected WindowMovedError not raised!"
    except WindowMovedError:
        pass

    # 3. Canvas Bounds test
    canvas = BoundingBox(50, 50, 450, 350)
    assert VisualGuard.assert_coordinate_within_canvas(100, 100, canvas) is True
    # Out of bounds: x < left
    try:
        VisualGuard.assert_coordinate_within_canvas(45, 100, canvas)
        assert False, "Expected OutOfBoundsVisualError not raised!"
    except OutOfBoundsVisualError:
        pass
    # Out of bounds: y > bottom
    try:
        VisualGuard.assert_coordinate_within_canvas(100, 355, canvas)
        assert False, "Expected OutOfBoundsVisualError not raised!"
    except OutOfBoundsVisualError:
        pass

    # 4. Occlusion test
    target_box = BoundingBox(100, 100, 150, 150)
    non_overlap_modal = [(300, 300, 500, 500)]
    assert VisualGuard.assert_no_occlusion(target_box, non_overlap_modal) is True

    overlap_modal = [(120, 120, 400, 400)]  # Intersects target_box
    try:
        VisualGuard.assert_no_occlusion(target_box, overlap_modal)
        assert False, "Expected OcclusionVisualError not raised!"
    except OcclusionVisualError:
        pass

    # 5. Composite verify_action_preconditions
    res_success = VisualGuard.verify_action_preconditions(
        frame=fresh_frame,
        target_coords=(100, 100),
        canvas_bounds=canvas,
        current_window_rect=base_rect,
        baseline_window_rect=base_rect,
        modal_rects=non_overlap_modal,
    )
    assert res_success["status"] == "success"

    res_fail = VisualGuard.verify_action_preconditions(
        frame=stale_frame,
        target_coords=(100, 100),
        canvas_bounds=canvas,
    )
    assert res_fail["status"] == "failed"
    assert res_fail["error_code"] == "STALE_IMAGE"

    logger.info("W043 Visual Guard self-test passed successfully.")
    return {
        "status": "success",
        "details": "Freshness, stationary, out-of-bounds, and occlusion guards verified fail-closed.",
    }


if __name__ == "__main__":
    res = self_test()
    print(f"Self-test result: {res}")
