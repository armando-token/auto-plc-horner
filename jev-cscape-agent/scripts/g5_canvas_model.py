#!/usr/bin/env python3
"""
G5 Vision Pipeline: Canvas & Grid Geometry Model (W041)
Provides mathematical coordinate transformations, grid snapping, anchor mapping,
and visual landmark detection for Horner Cscape 10.2 Ladder & HMI Screen Editors.

Supports:
1. LadderCanvasModel:
   - Rung grid structure (rung index r, column index c: 0..10)
   - Left and right power rail detection and alignment
   - Cell bounding boxes and center snap coordinates
   - Contact and coil placement targeting

2. HMICanvasModel:
   - Horner OCS virtual screen space (default 320x240 for Micro/X5 series, configurable)
   - Zoom scaling factor Z (100%, 120%, 150%, 200%)
   - Configurable grid snap (8x8, 16x16, or custom step)
   - 9-point anchor system (NW, N, NE, W, CENTER, E, SW, S, SE)
   - Bidirectional coordinate transforms: Virtual <-> Client <-> Screen
   - Spatial boundary validation (fail-closed)

3. CanvasAnchorDetector:
   - Pure-software visual landmark detection via PIL pixel scanning
   - Canvas border and viewport identification
   - Status bar ROI localization
   - Ruler / margin boundary detection

Complies with Horner Cscape FastMCP & Autonomous Agent Directives:
- Fail-closed boundary guards
- Pure software execution without external GUI dependencies
- Deterministic offline replay support
- Zero hardware port access
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import logging
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from PIL import Image

logger = logging.getLogger("g5_canvas_model")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


# =============================================================================
# Anchor Point Definitions
# =============================================================================

class AnchorPoint(str, Enum):
    NW = "NW"         # Top-Left
    N = "N"           # Top-Center
    NE = "NE"         # Top-Right
    W = "W"           # Center-Left
    CENTER = "CENTER" # Bounding Box Center
    E = "E"           # Center-Right
    SW = "SW"         # Bottom-Left
    S = "S"           # Bottom-Center
    SE = "SE"         # Bottom-Right


@dataclass
class BoundingBox:
    """Rectangular bounding box in arbitrary 2D coordinate space."""
    left: int
    top: int
    right: int
    bottom: int

    @property
    def width(self) -> int:
        return max(0, self.right - self.left)

    @property
    def height(self) -> int:
        return max(0, self.bottom - self.top)

    @property
    def center_x(self) -> int:
        return self.left + self.width // 2

    @property
    def center_y(self) -> int:
        return self.top + self.height // 2

    def to_tuple(self) -> Tuple[int, int, int, int]:
        return (self.left, self.top, self.right, self.bottom)

    def contains(self, x: float, y: float) -> bool:
        return self.left <= x <= self.right and self.top <= y <= self.bottom

    def get_anchor(self, anchor: Union[AnchorPoint, str]) -> Tuple[int, int]:
        """Compute pixel coordinate of specified anchor point."""
        if isinstance(anchor, str):
            anchor = AnchorPoint(anchor.upper())

        cx = self.center_x
        cy = self.center_y

        mapping = {
            AnchorPoint.NW: (self.left, self.top),
            AnchorPoint.N: (cx, self.top),
            AnchorPoint.NE: (self.right, self.top),
            AnchorPoint.W: (self.left, cy),
            AnchorPoint.CENTER: (cx, cy),
            AnchorPoint.E: (self.right, cy),
            AnchorPoint.SW: (self.left, self.bottom),
            AnchorPoint.S: (cx, self.bottom),
            AnchorPoint.SE: (self.right, self.bottom),
        }
        return mapping[anchor]

    def all_anchors(self) -> Dict[str, Tuple[int, int]]:
        """Return all 9 anchor points."""
        return {ap.value: self.get_anchor(ap) for ap in AnchorPoint}


# =============================================================================
# Ladder Canvas Model
# =============================================================================

@dataclass
class LadderCanvasModel:
    """Geometric model for Cscape Ladder Editor canvas.
    
    Standard Horner Cscape Ladder canvas contains:
    - Left power rail at fixed horizontal margin (e.g., x=24)
    - Right power rail at right boundary (e.g., column 10 or canvas width - margin)
    - 11 columns per rung (columns 0..9 for contacts/instructions, column 10 for coils)
    - Row/rung height (~60px default)
    """
    canvas_width: int = 800
    canvas_height: int = 600
    origin_x: int = 30       # Left margin to start of column 0 (past left power rail)
    origin_y: int = 20       # Top margin to top of rung 0
    rung_height: int = 60    # Vertical pitch per rung
    col_width: int = 70      # Horizontal pitch per ladder column
    num_cols: int = 11       # Total columns (0..9 contacts, 10 coils)
    left_rail_x: int = 15    # X position of left vertical power rail
    right_rail_x: Optional[int] = None  # X position of right vertical power rail

    def __post_init__(self):
        if self.right_rail_x is None:
            self.right_rail_x = self.origin_x + self.num_cols * self.col_width + 10

    def is_valid_cell(self, rung: int, col: int) -> bool:
        """Validate whether rung and column fall within canvas geometry."""
        if rung < 0 or col < 0 or col >= self.num_cols:
            return False
        max_rungs = max(1, (self.canvas_height - self.origin_y) // self.rung_height)
        return rung < max_rungs

    def get_cell_rect(self, rung: int, col: int) -> BoundingBox:
        """Return BoundingBox in client coordinates for a ladder cell."""
        if not self.is_valid_cell(rung, col):
            raise ValueError(f"Invalid ladder cell (rung={rung}, col={col}) outside bounds!")
        left = self.origin_x + col * self.col_width
        top = self.origin_y + rung * self.rung_height
        right = left + self.col_width
        bottom = top + self.rung_height
        return BoundingBox(left, top, right, bottom)

    def rung_col_to_client(self, rung: int, col: int) -> Tuple[int, int]:
        """Return center (x, y) client coordinate for placing contact or coil."""
        box = self.get_cell_rect(rung, col)
        return (box.center_x, box.center_y)

    def client_to_rung_col(self, cx: int, cy: int) -> Tuple[int, int]:
        """Convert client coordinate (cx, cy) to nearest (rung, col)."""
        rel_x = cx - self.origin_x
        rel_y = cy - self.origin_y
        col = int(rel_x // self.col_width)
        rung = int(rel_y // self.rung_height)
        col = max(0, min(self.num_cols - 1, col))
        rung = max(0, rung)
        return (rung, col)

    def get_coil_target(self, rung: int) -> Tuple[int, int]:
        """Return standard coil placement coordinate (rightmost column)."""
        return self.rung_col_to_client(rung, self.num_cols - 1)

    def get_power_rails(self) -> Dict[str, Any]:
        """Return vertical line segments for power rails."""
        return {
            "left_rail": ((self.left_rail_x, self.origin_y), (self.left_rail_x, self.canvas_height - 10)),
            "right_rail": ((self.right_rail_x, self.origin_y), (self.right_rail_x, self.canvas_height - 10)),
        }


# =============================================================================
# HMI Canvas Model
# =============================================================================

@dataclass
class HMICanvasModel:
    """Geometric model for Cscape HMI (GrEdit) Screen Editor canvas.
    
    Transforms coordinates between:
    - Virtual Screen Space: e.g. 320x240 native OCS LCD screen coordinate space
    - Client Viewport Space: Actual pixels in Cscape Screen Editor window
    - Screen Desktop Space: Absolute Windows desktop pixels
    
    Handles:
    - Zoom scaling (factor Z = zoom_percent / 100.0)
    - Grid snapping (8x8 or 16x16)
    - Viewport panning offset
    - Fail-closed boundary validation
    """
    virtual_width: int = 320
    virtual_height: int = 240
    zoom_percent: int = 100      # e.g., 100, 120, 150, 200
    viewport_offset_x: int = 0   # Client X of virtual (0, 0)
    viewport_offset_y: int = 0   # Client Y of virtual (0, 0)
    grid_size: int = 8           # Grid step in virtual pixels
    client_width: int = 800
    client_height: int = 600

    @property
    def zoom_factor(self) -> float:
        return max(0.1, self.zoom_percent / 100.0)

    @property
    def virtual_bounds(self) -> BoundingBox:
        return BoundingBox(0, 0, self.virtual_width, self.virtual_height)

    @property
    def client_canvas_bounds(self) -> BoundingBox:
        """Client pixel bounding box of the virtual canvas under current zoom & offset."""
        c_left = self.viewport_offset_x
        c_top = self.viewport_offset_y
        c_right = c_left + int(round(self.virtual_width * self.zoom_factor))
        c_bottom = c_top + int(round(self.virtual_height * self.zoom_factor))
        return BoundingBox(c_left, c_top, c_right, c_bottom)

    # -------------------------------------------------------------------------
    # Coordinate Transforms
    # -------------------------------------------------------------------------

    def virtual_to_client(self, vx: float, vy: float) -> Tuple[int, int]:
        """Convert virtual OCS LCD coordinate to client viewport pixel."""
        cx = int(round(self.viewport_offset_x + vx * self.zoom_factor))
        cy = int(round(self.viewport_offset_y + vy * self.zoom_factor))
        return (cx, cy)

    def client_to_virtual(self, cx: int, cy: int) -> Tuple[float, float]:
        """Convert client viewport pixel to virtual OCS LCD coordinate."""
        vx = (cx - self.viewport_offset_x) / self.zoom_factor
        vy = (cy - self.viewport_offset_y) / self.zoom_factor
        return (vx, vy)

    def client_to_screen(self, cx: int, cy: int, client_origin_screen: Tuple[int, int]) -> Tuple[int, int]:
        """Convert client pixel to absolute Windows screen coordinate."""
        sx = client_origin_screen[0] + cx
        sy = client_origin_screen[1] + cy
        return (sx, sy)

    def screen_to_client(self, sx: int, sy: int, client_origin_screen: Tuple[int, int]) -> Tuple[int, int]:
        """Convert Windows screen coordinate to client pixel."""
        cx = sx - client_origin_screen[0]
        cy = sy - client_origin_screen[1]
        return (cx, cy)

    def virtual_to_screen(
        self, vx: float, vy: float, client_origin_screen: Tuple[int, int]
    ) -> Tuple[int, int]:
        """Convert virtual OCS LCD coordinate directly to screen coordinate."""
        cx, cy = self.virtual_to_client(vx, vy)
        return self.client_to_screen(cx, cy, client_origin_screen)

    # -------------------------------------------------------------------------
    # Grid Snapping & Bounding Box Utilities
    # -------------------------------------------------------------------------

    def snap_virtual_to_grid(self, vx: float, vy: float, custom_grid: Optional[int] = None) -> Tuple[int, int]:
        """Snap virtual coordinate to nearest grid intersection."""
        step = custom_grid if custom_grid is not None else self.grid_size
        if step <= 1:
            return (int(round(vx)), int(round(vy)))
        snapped_x = int(round(vx / step) * step)
        snapped_y = int(round(vy / step) * step)
        # Clamp within virtual bounds
        snapped_x = max(0, min(self.virtual_width, snapped_x))
        snapped_y = max(0, min(self.virtual_height, snapped_y))
        return (snapped_x, snapped_y)

    def snap_client_to_grid(self, cx: int, cy: int, custom_grid: Optional[int] = None) -> Tuple[int, int]:
        """Snap client pixel to virtual grid, returning snapped client pixel."""
        vx, vy = self.client_to_virtual(cx, cy)
        snapped_vx, snapped_vy = self.snap_virtual_to_grid(vx, vy, custom_grid)
        return self.virtual_to_client(snapped_vx, snapped_vy)

    def get_object_client_box(
        self, vx: float, vy: float, v_width: float, v_height: float
    ) -> BoundingBox:
        """Compute client bounding box for a virtual object."""
        c_left, c_top = self.virtual_to_client(vx, vy)
        c_right, c_bottom = self.virtual_to_client(vx + v_width, vy + v_height)
        return BoundingBox(c_left, c_top, c_right, c_bottom)

    # -------------------------------------------------------------------------
    # Spatial Boundary Validation (Fail-Closed)
    # -------------------------------------------------------------------------

    def is_valid_virtual(self, vx: float, vy: float, margin: float = 0.0) -> bool:
        """Validate whether virtual coordinate falls strictly inside LCD area."""
        return (
            (0.0 + margin) <= vx <= (self.virtual_width - margin)
            and (0.0 + margin) <= vy <= (self.virtual_height - margin)
        )

    def is_valid_client(self, cx: int, cy: int, margin: int = 2) -> bool:
        """Validate whether client pixel falls inside visible canvas drawing area."""
        bounds = self.client_canvas_bounds
        return (
            (bounds.left + margin) <= cx <= (bounds.right - margin)
            and (bounds.top + margin) <= cy <= (bounds.bottom - margin)
        )

    def validate_action_target(self, cx: int, cy: int, margin: int = 2) -> None:
        """Fail-closed assertion that client coordinate is inside canvas drawing area."""
        if not self.is_valid_client(cx, cy, margin=margin):
            bounds = self.client_canvas_bounds
            raise ValueError(
                f"FAIL_CLOSED: Target ({cx}, {cy}) is outside valid HMI canvas bounds "
                f"[{bounds.left}, {bounds.top}, {bounds.right}, {bounds.bottom}]!"
            )


# =============================================================================
# Canvas Anchor Detector (Visual Landmark Localization)
# =============================================================================

class CanvasAnchorDetector:
    """Locates visual landmarks (canvas boundaries, rulers, status bars, power rails)
    directly from captured image pixels using pure-software algorithms.
    """

    @staticmethod
    def detect_status_bar_roi(image: Image.Image, expected_height: int = 24) -> BoundingBox:
        """Locate standard Windows msctls_statusbar32 at bottom of window image."""
        w, h = image.size
        top = max(0, h - expected_height)
        return BoundingBox(left=0, top=top, right=w, bottom=h)

    @staticmethod
    def detect_canvas_bounds_from_image(
        image: Image.Image,
        min_contrast: int = 15,
        default_fallback: Optional[BoundingBox] = None,
    ) -> BoundingBox:
        """Scan image horizontally and vertically to detect prominent canvas drawing area.
        
        Horner Cscape editors typically place the white/light-gray drawing canvas
        surrounded by darker borders, rulers, or dockable frame backgrounds.
        """
        w, h = image.size
        gray = image.convert("L")
        raw = gray.tobytes()

        # Step 1: Horizontal profile across center horizontal strip
        center_y = h // 2
        row_start = center_y * w
        
        # Scan from left to find left canvas border (transition to light canvas)
        left_edge = 0
        for x in range(10, w // 2):
            lum = raw[row_start + x]
            lum_prev = raw[row_start + x - 1]
            if lum > 180 and abs(int(lum) - int(lum_prev)) >= min_contrast:
                left_edge = x
                break

        # Scan from right to find right canvas border
        right_edge = w
        for x in range(w - 10, w // 2, -1):
            lum = raw[row_start + x]
            lum_next = raw[row_start + x + 1]
            if lum > 180 and abs(int(lum) - int(lum_next)) >= min_contrast:
                right_edge = x + 1
                break

        # Step 2: Vertical profile across center vertical strip
        center_x = (left_edge + right_edge) // 2
        top_edge = 0
        for y in range(10, h // 2):
            lum = raw[y * w + center_x]
            lum_prev = raw[(y - 1) * w + center_x]
            if lum > 180 and abs(int(lum) - int(lum_prev)) >= min_contrast:
                top_edge = y
                break

        bottom_edge = h
        for y in range(h - 25, h // 2, -1):
            lum = raw[y * w + center_x]
            lum_next = raw[(y + 1) * w + center_x]
            if lum > 180 and abs(int(lum) - int(lum_next)) >= min_contrast:
                bottom_edge = y + 1
                break

        # Plausibility check: canvas must span at least 100x100 pixels
        if (right_edge - left_edge) >= 100 and (bottom_edge - top_edge) >= 80:
            return BoundingBox(left_edge, top_edge, right_edge, bottom_edge)

        if default_fallback:
            return default_fallback

        # Conservative default: central 85% of image
        margin_x = int(w * 0.05)
        margin_y = int(h * 0.05)
        return BoundingBox(margin_x, margin_y, w - margin_x, h - margin_y - 24)

    @staticmethod
    def detect_ladder_power_rail(
        image: Image.Image,
        search_roi: Optional[BoundingBox] = None,
        max_search_x: int = 80,
    ) -> int:
        """Detect X position of the left vertical power rail line in Ladder editor.
        
        The power rail appears as a continuous dark vertical line (luminance < 100).
        """
        w, h = image.size
        gray = image.convert("L")
        raw = gray.tobytes()

        roi = search_roi or BoundingBox(0, 0, min(w, max_search_x), h)
        y_start = roi.top + int(roi.height * 0.2)
        y_end = roi.top + int(roi.height * 0.8)
        sample_height = max(1, y_end - y_start)

        best_x = -1
        min_avg_lum = 255.0

        for x in range(roi.left + 5, min(roi.right, w - 1)):
            col_lum_sum = 0
            for y in range(y_start, y_end):
                col_lum_sum += raw[y * w + x]
            avg_lum = col_lum_sum / float(sample_height)
            if avg_lum < min_avg_lum:
                min_avg_lum = avg_lum
                best_x = x

        # If dark line found (avg luminance < 140)
        if best_x >= 0 and min_avg_lum < 140.0:
            return best_x

        # Fallback standard margin
        return 24


# =============================================================================
# Module CLI / Self-Test
# =============================================================================

def self_test() -> Dict[str, Any]:
    """Execute deterministic unit verification for W041 models."""
    logger.info("Starting W041 Canvas Model self-test...")

    # Test 1: BoundingBox & 9-point Anchors
    box = BoundingBox(left=100, top=50, right=200, bottom=150)
    assert box.width == 100
    assert box.height == 100
    assert box.center_x == 150
    assert box.center_y == 100
    assert box.get_anchor(AnchorPoint.NW) == (100, 50)
    assert box.get_anchor(AnchorPoint.CENTER) == (150, 100)
    assert box.get_anchor(AnchorPoint.SE) == (200, 150)
    assert box.get_anchor(AnchorPoint.N) == (150, 50)
    assert box.get_anchor(AnchorPoint.S) == (150, 150)
    assert box.get_anchor(AnchorPoint.W) == (100, 100)
    assert box.get_anchor(AnchorPoint.E) == (200, 100)

    # Test 2: Ladder Canvas Model
    ladder = LadderCanvasModel(canvas_width=800, canvas_height=600)
    assert ladder.is_valid_cell(0, 0)
    assert ladder.is_valid_cell(5, 10)
    assert not ladder.is_valid_cell(-1, 0)
    assert not ladder.is_valid_cell(0, 15)
    c0 = ladder.rung_col_to_client(0, 0)
    c_coil = ladder.get_coil_target(0)
    assert c_coil[0] > c0[0]
    r, c = ladder.client_to_rung_col(c0[0], c0[1])
    assert (r, c) == (0, 0)

    # Test 3: HMI Canvas Model Coordinate Transforms & Zoom
    hmi_100 = HMICanvasModel(virtual_width=320, virtual_height=240, zoom_percent=100, viewport_offset_x=50, viewport_offset_y=40)
    # Virtual (0, 0) -> Client (50, 40)
    assert hmi_100.virtual_to_client(0, 0) == (50, 40)
    # Virtual (320, 240) -> Client (370, 280)
    assert hmi_100.virtual_to_client(320, 240) == (370, 280)
    # Round-trip client -> virtual
    vx, vy = hmi_100.client_to_virtual(210, 160)
    assert abs(vx - 160.0) < 1e-4
    assert abs(vy - 120.0) < 1e-4

    # Zoom 120%
    hmi_120 = HMICanvasModel(virtual_width=320, virtual_height=240, zoom_percent=120, viewport_offset_x=50, viewport_offset_y=40)
    cx_120, cy_120 = hmi_120.virtual_to_client(100, 100)
    assert cx_120 == int(round(50 + 100 * 1.2)) == 170
    assert cy_120 == int(round(40 + 100 * 1.2)) == 160

    # Grid snap
    snapped = hmi_100.snap_virtual_to_grid(23.7, 45.1, custom_grid=8)
    assert snapped == (24, 48)

    # Boundaries & Fail-closed checks
    assert hmi_100.is_valid_virtual(160, 120)
    assert not hmi_100.is_valid_virtual(350, 100)
    assert not hmi_100.is_valid_virtual(-10, 50)

    # Test 4: Visual Landmark Detector Synthetic Image
    test_img = Image.new("RGB", (600, 400), color=(128, 128, 128))
    # Draw white canvas inside
    from PIL import ImageDraw
    draw = ImageDraw.Draw(test_img)
    draw.rectangle([50, 40, 550, 360], fill=(255, 255, 255), outline=(0, 0, 0))
    detected_bounds = CanvasAnchorDetector.detect_canvas_bounds_from_image(test_img)
    assert abs(detected_bounds.left - 50) <= 2
    assert abs(detected_bounds.top - 40) <= 2

    # Draw vertical dark line (power rail) at x=20 inside a ladder strip
    ladder_strip = Image.new("RGB", (200, 300), color=(255, 255, 255))
    draw_ladder = ImageDraw.Draw(ladder_strip)
    draw_ladder.line([(35, 10), (35, 290)], fill=(0, 0, 0), width=3)
    detected_rail = CanvasAnchorDetector.detect_ladder_power_rail(ladder_strip)
    assert abs(detected_rail - 35) <= 1

    logger.info("W041 Canvas Model self-test passed successfully.")
    return {
        "status": "success",
        "details": "Ladder and HMI canvas geometry, anchors, transforms, and landmark detector verified.",
    }


if __name__ == "__main__":
    res = self_test()
    print(f"Self-test result: {res}")
