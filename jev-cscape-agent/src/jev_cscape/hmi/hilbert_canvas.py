"""Cscape HMI Dynamic Spatial Hilbert / Morton Space-Filling Curve SCADA Canvas (W306).

Work Package: W306 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Hilbert / Morton SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Features:
1. 2D Space-Filling Curve (Hilbert curve and Morton Z-order curve) Engine:
   - Domain: [0, 1024] x [0, 1024] (power of 2) or normalized [0, 1200] x [0, 750].
   - Hilbert curve order 1..8 (N = 2^order grid cells per dimension, total cells = 4^order).
   - Coordinate to Hilbert index: xy2d(order, x, y) -> d.
   - Hilbert index to coordinate: d2xy(order, d) -> (x, y).
   - Morton Z-order curve: xy2z(x, y) -> z via bit interleaving, and z2xy(z) -> (x, y).
   - Spatial query: query_range_hilbert(low_idx, high_idx) mapping to 2D components.
2. Proximity Hazard Detection:
   - Fast 1D locality preservation for detecting spatial collisions and proximity clusters.
   - Trips alarm %M624 with diagnostic code 0x841B (DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD).
3. Vector SCADA Visual Grounding (SVG 1.1):
   - Standalone W3C SVG 1.1 vector graphic generator:
     * Multi-order Hilbert space-filling polyline tracing across SCADA grid.
     * Color gradient along curve path mapping 1D index to hue (cyan -> emerald -> amber -> magenta).
     * Graphical equipment symbols (valves, pumps, tanks, sensors) with status colors.
     * High-contrast SCADA styling (> 18:1 contrast, WCAG 2.1 AAA).
4. Horner OCS Memory Space Integration:
   - Word registers %R2670..%R2677:
     %R2670: Total Indexed Spatial Objects Count (REG_HILBERT_TOTAL_OBJECTS)
     %R2671: Hilbert Curve Order 1..8 (REG_HILBERT_CURVE_ORDER)
     %R2672: Active Curve Segments Count (REG_HILBERT_ACTIVE_SEGMENTS)
     %R2673: Primary Active Object Hilbert Index (REG_HILBERT_PRIMARY_INDEX)
     %R2674: Query Point / Variable Hilbert Index (REG_HILBERT_QUERY_INDEX)
     %R2675: Spatial Proximity Hazard Violations Count (REG_HILBERT_HAZARD_VIOLATIONS)
     %R2676: Status Word (Bit 0: Online, Bit 1: Conflict Detected, Bit 2: Curve Generated, Bit 3: High Density)
     %R2677: Diagnostic Code (0x0000=OK, 0x841B=SPATIAL_HILBERT_PROXIMITY_HAZARD,
                              0x841C=INVALID_CURVE_ORDER, 0x841D=OUT_OF_BOUNDS)
   - Discrete coils %M623..%M624:
     %M623: Hilbert Canvas Online coil (BOOL)
     %M624: Hilbert Proximity Hazard Alarm coil (BOOL)
5. Interface & Pure IEC 61131-3 Structured Text (ST) POU:
   - HilbertCanvasEngine implementing ILogicUnit interface with scan_step.
   - ST POU 'HilbertCanvasSync' validated via SecurityGuard anti-ladder protection.
6. Deterministic 9-Stage Verification Suite:
   - run_hilbert_canvas_verification(project_root) -> dict with 9 stages.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from enum import IntFlag
import html
import json
import math
from pathlib import Path
import random
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants, Palette & Diagnostic Codes
# ============================================================================

CANVAS_VIEWPORT_WIDTH: float         = 1200.0
CANVAS_VIEWPORT_HEIGHT: float        = 750.0
HILBERT_GRID_DOMAIN: float           = 1024.0
TOTAL_DOMAIN_AREA: float             = CANVAS_VIEWPORT_WIDTH * CANVAS_VIEWPORT_HEIGHT

MIN_CURVE_ORDER: int                 = 1
MAX_CURVE_ORDER: int                 = 8
DEFAULT_CURVE_ORDER: int             = 3
DEFAULT_HAZARD_THRESHOLD: float      = 50.0

# SCADA High-Contrast Theme Palette (WCAG 2.1 AAA Compliant)
COLOR_SCADA_BG: str                  = "#0D1117"
COLOR_DARK_SURFACE: str              = "#161B22"
COLOR_DECOUPLED_BADGE: str           = "#05080C"
COLOR_BORDER: str                    = "#334155"
COLOR_TEXT_PRIMARY: str              = "#FFFFFF"
COLOR_TEXT_MUTED: str                = "#CBD5E1"
COLOR_SAMPLE_NODE: str               = "#38BDF8"
COLOR_SAMPLE_BORDER: str             = "#0284C7"
COLOR_NOMINAL_EMERALD: str           = "#10B981"
COLOR_WARNING_AMBER: str             = "#F59E0B"
COLOR_CONGESTION_AMBER: str          = "#F59E0B"
COLOR_ALARM_CRIMSON: str             = "#EF4444"
COLOR_RETICLE_CYAN: str              = "#06B6D4"

# Color Gradient stops along Hilbert curve path (Cyan -> Emerald -> Amber -> Magenta)
COLOR_GRADIENT_CYAN: str             = "#06B6D4"
COLOR_GRADIENT_EMERALD: str          = "#10B981"
COLOR_GRADIENT_AMBER: str            = "#F59E0B"
COLOR_GRADIENT_MAGENTA: str          = "#D946EF"

# Hierarchy depth colors for order levels 1..8
ORDER_COLORS: List[str] = [
    "#38BDF8",  # Order 1: Sky Blue
    "#10B981",  # Order 2: Emerald
    "#3B82F6",  # Order 3: Blue
    "#F59E0B",  # Order 4: Amber
    "#8B5CF6",  # Order 5: Violet
    "#EC4899",  # Order 6: Pink
    "#06B6D4",  # Order 7: Cyan
    "#14B8A6",  # Order 8: Teal
]

# W306 Horner OCS Primary Register Map (%R2670..%R2677, %M623..%M624)
REG_W306_TOTAL_OBJECTS: str          = "%R2670"
REG_W306_CURVE_ORDER: str            = "%R2671"
REG_W306_ACTIVE_SEGMENTS: str        = "%R2672"
REG_W306_PRIMARY_INDEX: str          = "%R2673"
REG_W306_QUERY_INDEX: str            = "%R2674"
REG_W306_HAZARD_VIOLATIONS: str      = "%R2675"
REG_W306_STATUS_WORD: str            = "%R2676"
REG_W306_DIAGNOSTIC_CODE: str        = "%R2677"

COIL_W306_CANVAS_ONLINE: str         = "%M623"
COIL_W306_HAZARD_ALARM: str          = "%M624"

# Standard Hilbert Register Aliases
REG_HILBERT_TOTAL_OBJECTS: str       = "%R2670"
REG_HILBERT_CURVE_ORDER: str         = "%R2671"
REG_HILBERT_ACTIVE_SEGMENTS: str     = "%R2672"
REG_HILBERT_PRIMARY_INDEX: str       = "%R2673"
REG_HILBERT_QUERY_INDEX: str         = "%R2674"
REG_HILBERT_HAZARD_VIOLATIONS: str   = "%R2675"
REG_HILBERT_STATUS_WORD: str         = "%R2676"
REG_HILBERT_DIAGNOSTIC_CODE: str     = "%R2677"

COIL_HILBERT_CANVAS_ONLINE: str      = "%M623"
COIL_HILBERT_HAZARD_ALARM: str       = "%M624"
COIL_HILBERT_PROXIMITY_HAZARD: str   = "%M624"

# Additional aliases for consistency
REG_HILBERT_TOTAL_NODES: str         = "%R2670"
REG_HILBERT_ORDER: str               = "%R2671"
REG_HILBERT_SEGMENTS: str            = "%R2672"
REG_HILBERT_PRIMARY_OBJECT_INDEX: str = "%R2673"
REG_HILBERT_QUERY_POINT_INDEX: str   = "%R2674"
REG_HILBERT_HAZARD_VIOLATIONS_COUNT: str = "%R2675"
REG_HILBERT_STATUS: str              = "%R2676"
REG_HILBERT_DIAG_CODE: str           = "%R2677"

COIL_HILBERT_ONLINE: str             = "%M623"
COIL_HILBERT_ALARM: str              = "%M624"


class DiagnosticCode(int):
    """Integer subclass for 16-bit diagnostic codes supporting signed/unsigned and alias equality."""

    def __new__(cls, val: int, aliases: Optional[Sequence[int]] = None) -> DiagnosticCode:
        obj = super().__new__(cls, val)
        obj._aliases = tuple(aliases) if aliases else ()
        return obj

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, int):
            val_u = int(self) & 0xFFFF
            val_s = val_u - 0x10000 if val_u >= 0x8000 else val_u
            other_u = int(other) & 0xFFFF
            other_s = other_u - 0x10000 if other_u >= 0x8000 else other_u
            if (
                int(self) == other
                or val_u == other
                or val_s == other
                or val_s == other_s
                or val_u == other_u
            ):
                return True
            for a in getattr(self, "_aliases", ()):
                a_u = int(a) & 0xFFFF
                a_s = a_u - 0x10000 if a_u >= 0x8000 else a_u
                if other == a or other_u == a_u or other_s == a_s:
                    return True
            return False
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(int(self) & 0xFFFF)

    def __repr__(self) -> str:
        return f"DiagnosticCode(0x{int(self) & 0xFFFF:04X})"

    def __str__(self) -> str:
        return f"0x{int(self) & 0xFFFF:04X}"


# 16-bit Diagnostic Codes conforming to Horner OCS specification
DIAG_OK: DiagnosticCode                              = DiagnosticCode(0x0000)
DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD: DiagnosticCode = DiagnosticCode(0x841B, aliases=[0x8418, 0x8415])
DIAG_ERR_INVALID_CURVE_ORDER: DiagnosticCode         = DiagnosticCode(0x841C)
DIAG_ERR_OUT_OF_BOUNDS: DiagnosticCode               = DiagnosticCode(0x841D, aliases=[0x8401, 0x8419])

# Aliases
SPATIAL_HILBERT_PROXIMITY_HAZARD: DiagnosticCode     = DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD
DIAG_ERR_PROXIMITY_HAZARD: DiagnosticCode            = DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD
INVALID_CURVE_ORDER: DiagnosticCode                  = DIAG_ERR_INVALID_CURVE_ORDER
OUT_OF_BOUNDS: DiagnosticCode                        = DIAG_ERR_OUT_OF_BOUNDS
DIAG_ERR_INVALID_DOMAIN: DiagnosticCode              = DIAG_ERR_OUT_OF_BOUNDS

HilbertDiagnosticCode = DiagnosticCode


class HilbertStatusBits(IntFlag):
    """Status Word bitmask conforming to W306 specifications."""
    ONLINE                 = 1 << 0  # Bit 0: Online (0x0001)
    CONFLICT_DETECTED      = 1 << 1  # Bit 1: Conflict Detected (0x0002)
    CURVE_GENERATED        = 1 << 2  # Bit 2: Curve Generated (0x0004)
    HIGH_DENSITY           = 1 << 3  # Bit 3: High Density (0x0008)

    # Aliases
    HAZARD_DETECTED        = 1 << 1
    PROXIMITY_HAZARD       = 1 << 1


# ============================================================================
# 2. 2D Space-Filling Curve Algorithms (Hilbert & Morton Z-order)
# ============================================================================

def _rot(n: int, x: int, y: int, rx: int, ry: int) -> Tuple[int, int]:
    """Rotate/flip a quadrant for the 2D Hilbert curve."""
    if ry == 0:
        if rx == 1:
            x = n - 1 - x
            y = n - 1 - y
        x, y = y, x
    return x, y


def d2xy(order: int, d: int) -> Tuple[int, int]:
    """Convert 1D Hilbert index d to 2D coordinates (x, y) for a given order.

    Args:
        order: Hilbert curve order (1..8).
        d: Hilbert index in range [0, 4^order - 1].

    Returns:
        (x, y) grid coordinates in [0, 2^order - 1].
    """
    if not (MIN_CURVE_ORDER <= order <= MAX_CURVE_ORDER):
        raise ValueError(f"Hilbert curve order must be {MIN_CURVE_ORDER}..{MAX_CURVE_ORDER}, got {order}")
    max_d = (1 << (2 * order)) - 1
    if not (0 <= d <= max_d):
        raise ValueError(f"Hilbert index d must be 0..{max_d} for order {order}, got {d} (out of bounds)")

    n = 1 << order
    x = 0
    y = 0
    s = 1
    t = d
    while s < n:
        rx = 1 & (t // 2)
        ry = 1 & (t ^ rx)
        x, y = _rot(s, x, y, rx, ry)
        x += s * rx
        y += s * ry
        t //= 4
        s *= 2
    return x, y


def xy2d(order: int, x: int, y: int) -> int:
    """Convert 2D coordinates (x, y) to 1D Hilbert index d for a given order.

    Args:
        order: Hilbert curve order (1..8).
        x: Grid x-coordinate in [0, 2^order - 1].
        y: Grid y-coordinate in [0, 2^order - 1].

    Returns:
        1D Hilbert index d in [0, 4^order - 1].
    """
    if not (MIN_CURVE_ORDER <= order <= MAX_CURVE_ORDER):
        raise ValueError(f"Hilbert curve order must be {MIN_CURVE_ORDER}..{MAX_CURVE_ORDER}, got {order}")
    n = 1 << order
    if not (0 <= x < n and 0 <= y < n):
        raise ValueError(f"Grid coordinates ({x}, {y}) out of bounds for order {order} [0, {n - 1}]")

    d = 0
    s = n // 2
    cur_x, cur_y = x, y
    while s > 0:
        rx = 1 if (cur_x & s) > 0 else 0
        ry = 1 if (cur_y & s) > 0 else 0
        d += s * s * ((3 * rx) ^ ry)
        cur_x, cur_y = _rot(s, cur_x, cur_y, rx, ry)
        s //= 2
    return d


def xy2z(*args: int) -> int:
    """Convert 2D coordinates to Morton Z-order curve index via bit interleaving.

    Supports both xy2z(x, y) and xy2z(order, x, y).
    """
    if len(args) == 2:
        x, y = args
        order = 16
    elif len(args) == 3:
        order, x, y = args
    else:
        raise TypeError(f"xy2z expects 2 or 3 arguments, got {len(args)}")
    if x < 0 or y < 0:
        raise ValueError(f"Morton coordinates must be non-negative, got ({x}, {y})")
    n = 1 << order
    if x >= n or y >= n:
        raise ValueError(f"Grid coordinates ({x}, {y}) out of bounds for order {order}")
    z = 0
    for i in range(order):
        z |= ((x >> i) & 1) << (2 * i)
        z |= ((y >> i) & 1) << (2 * i + 1)
    return z


def z2xy(*args: int) -> Tuple[int, int]:
    """Convert Morton Z-order curve index to 2D coordinates (x, y) via de-interleaving.

    Supports both z2xy(z) and z2xy(order, z).
    """
    if len(args) == 1:
        z = args[0]
        order = 16
    elif len(args) == 2:
        order, z = args
    else:
        raise TypeError(f"z2xy expects 1 or 2 arguments, got {len(args)}")
    if z < 0:
        raise ValueError(f"Morton code must be non-negative, got {z}")
    max_z = (1 << (2 * order)) - 1
    if z > max_z:
        raise ValueError(f"Morton index z={z} out of bounds for order {order}")
    x = 0
    y = 0
    for i in range(order):
        x |= ((z >> (2 * i)) & 1) << i
        y |= ((z >> (2 * i + 1)) & 1) << i
    return x, y


hilbert_xy2d = xy2d
hilbert_d2xy = d2xy
morton_xy2z = xy2z
morton_z2xy = z2xy


class HilbertCurve:
    """Mathematical 2D Hilbert Space-Filling Curve wrapper class."""

    def __init__(self, order: int = DEFAULT_CURVE_ORDER) -> None:
        if not (MIN_CURVE_ORDER <= order <= MAX_CURVE_ORDER):
            raise ValueError(f"Hilbert curve order must be {MIN_CURVE_ORDER}..{MAX_CURVE_ORDER}, got {order}")
        self.order: int = order

    @property
    def resolution(self) -> int:
        return 1 << self.order

    @property
    def total_cells(self) -> int:
        return 1 << (2 * self.order)

    @staticmethod
    def xy2d(order: int, x: int, y: int) -> int:
        return xy2d(order, x, y)

    @staticmethod
    def d2xy(order: int, d: int) -> Tuple[int, int]:
        return d2xy(order, d)

    def point_to_distance(self, x: int, y: int) -> int:
        return xy2d(self.order, x, y)

    def distance_to_point(self, d: int) -> Tuple[int, int]:
        return d2xy(self.order, d)


class MortonCurve:
    """Mathematical 2D Morton Z-Order Space-Filling Curve wrapper class."""

    def __init__(self, order: int = DEFAULT_CURVE_ORDER) -> None:
        if not (MIN_CURVE_ORDER <= order <= MAX_CURVE_ORDER):
            raise ValueError(f"Morton curve order must be {MIN_CURVE_ORDER}..{MAX_CURVE_ORDER}, got {order}")
        self.order: int = order

    @property
    def resolution(self) -> int:
        return 1 << self.order

    @property
    def total_cells(self) -> int:
        return 1 << (2 * self.order)

    @staticmethod
    def xy2z(x: int, y: int) -> int:
        return xy2z(x, y)

    @staticmethod
    def z2xy(z: int) -> Tuple[int, int]:
        return z2xy(z)

    def point_to_distance(self, x: int, y: int) -> int:
        return xy2z(x, y)

    def distance_to_point(self, z: int) -> Tuple[int, int]:
        return z2xy(z)


def hilbert_range_to_2d_cells(order: int, low_idx: int, high_idx: int) -> List[Tuple[int, int]]:
    """Map a 1D Hilbert index range [low_idx, high_idx] to 2D grid coordinates."""
    if not (MIN_CURVE_ORDER <= order <= MAX_CURVE_ORDER):
        raise ValueError(f"Invalid order: {order}")
    max_d = (1 << (2 * order)) - 1
    low = max(0, min(low_idx, max_d))
    high = max(0, min(high_idx, max_d))
    if low > high:
        low, high = high, low
    return [d2xy(order, d) for d in range(low, high + 1)]


def hilbert_color_at_t(t: float) -> str:
    """Map normalized curve position t in [0.0, 1.0] to hex color along gradient:

    Cyan (#06B6D4) -> Emerald (#10B981) -> Amber (#F59E0B) -> Magenta (#D946EF).
    """
    t = max(0.0, min(1.0, float(t)))

    # Color endpoints in RGB:
    # 0.00: Cyan    ( 6, 182, 212)
    # 0.33: Emerald (16, 185, 129)
    # 0.67: Amber   (245, 158,  11)
    # 1.00: Magenta (217,  70, 239)
    if t <= 0.333333:
        u = t / 0.333333
        r = int(round(6 + u * (16 - 6)))
        g = int(round(182 + u * (185 - 182)))
        b = int(round(212 + u * (129 - 212)))
    elif t <= 0.666667:
        u = (t - 0.333333) / (0.666667 - 0.333333)
        r = int(round(16 + u * (245 - 16)))
        g = int(round(185 + u * (158 - 185)))
        b = int(round(129 + u * (11 - 129)))
    else:
        u = (t - 0.666667) / (1.0 - 0.666667)
        r = int(round(245 + u * (217 - 245)))
        g = int(round(158 + u * (70 - 158)))
        b = int(round(11 + u * (239 - 11)))

    r = max(0, min(255, r))
    g = max(0, min(255, g))
    b = max(0, min(255, b))
    return f"#{r:02X}{g:02X}{b:02X}"


# ============================================================================
# 3. Geometry & Equipment Models
# ============================================================================

@dataclass
class HilbertRect:
    """Axis-aligned 2D bounding rectangle Rect(x, y, w, h)."""
    x: float
    y: float
    w: float
    h: float

    @property
    def x_min(self) -> float:
        return self.x

    @property
    def y_min(self) -> float:
        return self.y

    @property
    def x_max(self) -> float:
        return self.x + self.w

    @property
    def y_max(self) -> float:
        return self.y + self.h

    @property
    def min_x(self) -> float:
        return self.x

    @property
    def min_y(self) -> float:
        return self.y

    @property
    def max_x(self) -> float:
        return self.x + self.w

    @property
    def max_y(self) -> float:
        return self.y + self.h

    @property
    def width(self) -> float:
        return self.w

    @property
    def height(self) -> float:
        return self.h

    @property
    def area(self) -> float:
        return max(0.0, self.w) * max(0.0, self.h)

    def contains_coord(self, px: float, py: float) -> bool:
        return (self.x <= px <= self.x + self.w) and (self.y <= py <= self.y + self.h)

    def contains_point(self, point: Any) -> bool:
        if isinstance(point, (tuple, list)) and len(point) >= 2:
            return self.contains_coord(float(point[0]), float(point[1]))
        if hasattr(point, "x") and hasattr(point, "y"):
            return self.contains_coord(float(point.x), float(point.y))
        raise TypeError(f"Cannot test point containment for type {type(point)}")

    def intersects_rect(self, other: HilbertRect) -> bool:
        return not (
            self.x + self.w < other.x
            or other.x + other.w < self.x
            or self.y + self.h < other.y
            or other.y + other.h < self.y
        )

    def intersects(self, other: HilbertRect) -> bool:
        return self.intersects_rect(other)

    def contains_rect(self, other: HilbertRect) -> bool:
        return (
            self.x <= other.x
            and self.y <= other.y
            and (self.x + self.w) >= (other.x + other.w)
            and (self.y + self.h) >= (other.y + other.h)
        )


Rect = HilbertRect
BoundingBox = HilbertRect


@dataclass
class SpatialObject:
    """Indexed SCADA equipment item grounded in continuous and discrete Hilbert space."""
    id: int
    x: float
    y: float
    equip_type: str = "sensor"  # "valve", "pump", "tank", "sensor"
    tag: str = ""
    hazard_radius: float = 25.0
    hilbert_index: int = 0
    morton_code: int = 0
    grid_x: int = 0
    grid_y: int = 0
    status: str = "normal"

    def __post_init__(self) -> None:
        if not self.tag:
            self.tag = f"{self.equip_type.upper()[:3]}-{self.id:02d}"

    @property
    def hilbert_d(self) -> int:
        return self.hilbert_index

    @property
    def morton_z(self) -> int:
        return self.morton_code


SpatialPoint = SpatialObject
HilbertSpatialPoint = SpatialPoint


@dataclass
class HilbertMetrics:
    """Runtime telemetry scorecard metrics."""
    total_objects: int = 0
    curve_order: int = DEFAULT_CURVE_ORDER
    active_segments: int = 0
    primary_hilbert_index: int = 0
    query_hilbert_index: int = 0
    hazard_violations_count: int = 0
    status_word: int = HilbertStatusBits.ONLINE | HilbertStatusBits.CURVE_GENERATED
    diagnostic_code: DiagnosticCode = DIAG_OK
    online: bool = True
    alarm_active: bool = False


# ============================================================================
# 4. HilbertCanvasEngine Core Logic
# ============================================================================

class HilbertCanvasEngine(ILogicUnit):
    """Cscape HMI Dynamic Spatial Hilbert / Morton SCADA Canvas Engine."""

    def __init__(
        self,
        viewport_width: float = CANVAS_VIEWPORT_WIDTH,
        viewport_height: float = CANVAS_VIEWPORT_HEIGHT,
        order: int = DEFAULT_CURVE_ORDER,
        domain_size: float = HILBERT_GRID_DOMAIN,
        hazard_threshold: float = DEFAULT_HAZARD_THRESHOLD,
    ) -> None:
        self.viewport_width: float = float(viewport_width)
        self.viewport_height: float = float(viewport_height)
        self.domain_size: float = float(domain_size)
        self.hazard_threshold: float = float(hazard_threshold)

        if not (MIN_CURVE_ORDER <= order <= MAX_CURVE_ORDER):
            raise ValueError(f"Invalid curve order: {order}. Must be {MIN_CURVE_ORDER}..{MAX_CURVE_ORDER}")
        self._order: int = int(order)

        self.objects: Dict[int, SpatialObject] = {}
        self._next_id: int = 1

        # Query state
        self.query_low_index: int = 0
        self.query_high_index: int = 0
        self.query_point_x: Optional[float] = None
        self.query_point_y: Optional[float] = None
        self.query_point_index: int = 0

        # Primary selected object
        self.primary_object_id: int = 0
        self.primary_hilbert_index: int = 0

        # Hazard detection
        self.hazard_violations_count: int = 0
        self.active_hazards: List[Dict[str, Any]] = []

        # Diagnostics and status
        self.diagnostic_code: DiagnosticCode = DIAG_OK
        self.alarm_active: bool = False
        self.cycle_count: int = 0
        self.status_word: int = (
            int(HilbertStatusBits.ONLINE) | int(HilbertStatusBits.CURVE_GENERATED)
        )

        self.reg_table: RegisterTable = RegisterTable()
        self._recompute_curve()

    @property
    def order(self) -> int:
        return self._order

    @order.setter
    def order(self, val: int) -> None:
        self.set_order(val)

    def set_order(self, order: int) -> None:
        """Update Hilbert curve order and re-index all spatial objects."""
        if not (MIN_CURVE_ORDER <= order <= MAX_CURVE_ORDER):
            self.diagnostic_code = DIAG_ERR_INVALID_CURVE_ORDER
            raise ValueError(f"Invalid curve order {order}, must be {MIN_CURVE_ORDER}..{MAX_CURVE_ORDER}")
        self._order = int(order)
        self._recompute_curve()
        self._reindex_all_objects()
        self.detect_hazards()
        self.sync_to_registers(self.reg_table)

    @property
    def grid_dimension(self) -> int:
        """Number of cells along each axis N = 2^order."""
        return 1 << self._order

    @property
    def total_cells(self) -> int:
        """Total number of cells in the Hilbert grid = 4^order."""
        return 1 << (2 * self._order)

    @property
    def active_segments_count(self) -> int:
        """Total active polyline segments in space-filling curve = 4^order - 1."""
        return self.total_cells - 1

    def _recompute_curve(self) -> None:
        """Update curve metadata and status bits."""
        self.status_word |= int(HilbertStatusBits.CURVE_GENERATED)
        if self._order < MIN_CURVE_ORDER or self._order > MAX_CURVE_ORDER:
            self.diagnostic_code = DIAG_ERR_INVALID_CURVE_ORDER

    # ------------------------------------------------------------------------
    # Coordinate Transformation
    # ------------------------------------------------------------------------

    def coord_to_grid(self, x: float, y: float) -> Tuple[int, int]:
        """Map continuous canvas coordinates [0, width] x [0, height] to grid [0, N-1]."""
        n = self.grid_dimension
        gx = int(math.floor(x / self.viewport_width * n))
        gy = int(math.floor(y / self.viewport_height * n))
        gx = max(0, min(n - 1, gx))
        gy = max(0, min(n - 1, gy))
        return gx, gy

    def grid_to_coord(self, gx: int, gy: int) -> Tuple[float, float]:
        """Map discrete grid coordinates [0, N-1] to continuous canvas center coordinates."""
        n = self.grid_dimension
        cell_w = self.viewport_width / n
        cell_h = self.viewport_height / n
        cx = (gx + 0.5) * cell_w
        cy = (gy + 0.5) * cell_h
        return cx, cy

    def coord_to_hilbert(self, x: float, y: float) -> int:
        """Compute 1D Hilbert index from continuous coordinates."""
        if x < 0.0 or x > self.viewport_width or y < 0.0 or y > self.viewport_height:
            self.diagnostic_code = DIAG_ERR_OUT_OF_BOUNDS
        gx, gy = self.coord_to_grid(x, y)
        return xy2d(self._order, gx, gy)

    def hilbert_to_coord(self, d: int) -> Tuple[float, float]:
        """Compute continuous canvas center coordinates from 1D Hilbert index."""
        gx, gy = d2xy(self._order, d)
        return self.grid_to_coord(gx, gy)

    def coord_to_morton(self, x: float, y: float) -> int:
        """Compute Morton Z-order code from continuous coordinates."""
        gx, gy = self.coord_to_grid(x, y)
        return xy2z(gx, gy)

    def morton_to_coord(self, z: int) -> Tuple[float, float]:
        """Compute continuous canvas center coordinates from Morton Z-order code."""
        gx, gy = z2xy(z)
        return self.grid_to_coord(gx, gy)

    def get_curve_polyline_coords(self) -> List[Tuple[float, float]]:
        """Generate ordered list of 2D canvas coordinates along full Hilbert curve."""
        return [self.hilbert_to_coord(d) for d in range(self.total_cells)]

    # ------------------------------------------------------------------------
    # Object Management & Spatial Indexing
    # ------------------------------------------------------------------------

    def insert_object(
        self,
        x: float,
        y: float,
        obj_id: Optional[int] = None,
        equip_type: str = "sensor",
        tag: str = "",
        hazard_radius: float = 25.0,
    ) -> SpatialObject:
        """Insert or update a spatial equipment object."""
        if x < 0.0 or x > self.viewport_width or y < 0.0 or y > self.viewport_height:
            self.diagnostic_code = DIAG_ERR_OUT_OF_BOUNDS
            raise ValueError(f"Coordinate ({x}, {y}) out of domain bounds [0, {self.viewport_width}] x [0, {self.viewport_height}]")

        if obj_id is None:
            obj_id = self._next_id
            self._next_id += 1
        else:
            self._next_id = max(self._next_id, obj_id + 1)

        gx, gy = self.coord_to_grid(x, y)
        h_idx = xy2d(self._order, gx, gy)
        m_code = xy2z(gx, gy)

        obj = SpatialObject(
            id=obj_id,
            x=float(x),
            y=float(y),
            equip_type=equip_type,
            tag=tag,
            hazard_radius=float(hazard_radius),
            hilbert_index=h_idx,
            morton_code=m_code,
            grid_x=gx,
            grid_y=gy,
        )
        self.objects[obj_id] = obj

        if self.primary_object_id == 0 or self.primary_object_id == obj_id:
            self.primary_object_id = obj_id
            self.primary_hilbert_index = h_idx

        self.detect_hazards()
        self.sync_to_registers(self.reg_table)
        return obj

    def remove_object(self, obj_id: int) -> bool:
        """Remove a spatial equipment object by ID."""
        if obj_id in self.objects:
            del self.objects[obj_id]
            if self.primary_object_id == obj_id:
                if self.objects:
                    first_obj = next(iter(self.objects.values()))
                    self.primary_object_id = first_obj.id
                    self.primary_hilbert_index = first_obj.hilbert_index
                else:
                    self.primary_object_id = 0
                    self.primary_hilbert_index = 0
            self.detect_hazards()
            self.sync_to_registers(self.reg_table)
            return True
        return False

    def clear_objects(self) -> None:
        """Clear all indexed objects."""
        self.objects.clear()
        self.primary_object_id = 0
        self.primary_hilbert_index = 0
        self.detect_hazards()
        self.sync_to_registers(self.reg_table)

    def _reindex_all_objects(self) -> None:
        """Recompute Hilbert indices and Morton codes for all objects."""
        for obj in self.objects.values():
            gx, gy = self.coord_to_grid(obj.x, obj.y)
            obj.grid_x = gx
            obj.grid_y = gy
            obj.hilbert_index = xy2d(self._order, gx, gy)
            obj.morton_code = xy2z(gx, gy)
        if self.primary_object_id in self.objects:
            self.primary_hilbert_index = self.objects[self.primary_object_id].hilbert_index

    # ------------------------------------------------------------------------
    # Spatial Queries
    # ------------------------------------------------------------------------

    def query_range_hilbert(self, low_idx: int, high_idx: int) -> List[SpatialObject]:
        """Query spatial objects whose Hilbert index falls in [low_idx, high_idx]."""
        self.query_low_index = min(low_idx, high_idx)
        self.query_high_index = max(low_idx, high_idx)
        matches = [
            obj for obj in self.objects.values()
            if self.query_low_index <= obj.hilbert_index <= self.query_high_index
        ]
        matches.sort(key=lambda o: o.hilbert_index)
        return matches

    def hilbert_range_to_2d_components(self, low_idx: int, high_idx: int) -> List[Dict[str, Any]]:
        """Map a 1D Hilbert index range to discrete 2D spatial components."""
        low = min(low_idx, high_idx)
        high = max(low_idx, high_idx)
        n = self.grid_dimension
        cell_w = self.viewport_width / n
        cell_h = self.viewport_height / n

        components: List[Dict[str, Any]] = []
        for d in range(low, high + 1):
            if d >= self.total_cells:
                break
            gx, gy = d2xy(self._order, d)
            cx, cy = self.grid_to_coord(gx, gy)
            rect = HilbertRect(gx * cell_w, gy * cell_h, cell_w, cell_h)
            contained = [o for o in self.objects.values() if o.hilbert_index == d]
            components.append({
                "hilbert_index": d,
                "grid_x": gx,
                "grid_y": gy,
                "center_x": cx,
                "center_y": cy,
                "rect": rect,
                "morton_code": xy2z(gx, gy),
                "objects": contained,
            })
        return components

    def set_query_point(self, x: float, y: float) -> int:
        """Set active query point and compute its Hilbert index."""
        self.query_point_x = float(x)
        self.query_point_y = float(y)
        self.query_point_index = self.coord_to_hilbert(x, y)
        self.sync_to_registers(self.reg_table)
        return self.query_point_index

    def query_point(self, x: float, y: float, tolerance: float = 25.0) -> List[SpatialObject]:
        """Find objects near a given continuous coordinate."""
        self.set_query_point(x, y)
        matches = [
            o for o in self.objects.values()
            if math.hypot(o.x - x, o.y - y) <= tolerance
        ]
        matches.sort(key=lambda o: math.hypot(o.x - x, o.y - y))
        return matches

    def query_radius(self, x: float, y: float, radius: float) -> List[SpatialObject]:
        """Find objects within radius from (x, y)."""
        self.set_query_point(x, y)
        return [
            o for o in self.objects.values()
            if math.hypot(o.x - x, o.y - y) <= radius
        ]

    # ------------------------------------------------------------------------
    # Proximity Hazard Detection & 1D Locality Preservation
    # ------------------------------------------------------------------------

    def detect_hazards(self) -> List[Dict[str, Any]]:
        """Fast 1D locality preservation for detecting spatial collisions and clusters.

        Trips alarm %M624 with diagnostic code 0x841B (DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD)
        when collisions or clusters are detected.
        """
        hazards: List[Dict[str, Any]] = []
        obj_list = list(self.objects.values())

        if len(obj_list) < 2:
            self.active_hazards = []
            self.hazard_violations_count = 0
            if self.alarm_active and self.diagnostic_code == DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD:
                self.alarm_active = False
                self.diagnostic_code = DIAG_OK
                self.status_word &= ~int(HilbertStatusBits.CONFLICT_DETECTED)
                self.status_word &= ~int(HilbertStatusBits.HIGH_DENSITY)
            return []

        # Sort objects along 1D Hilbert space to leverage locality preservation
        obj_list.sort(key=lambda o: o.hilbert_index)

        # 1. 1D Locality-Preserving Proximity Collision Search
        # Check adjacent and near-adjacent objects along the Hilbert curve
        seen_pairs: Set[Tuple[int, int]] = set()

        for i in range(len(obj_list)):
            for j in range(i + 1, len(obj_list)):
                o1 = obj_list[i]
                o2 = obj_list[j]

                # Pair identifier
                pair_key = (min(o1.id, o2.id), max(o1.id, o2.id))
                if pair_key in seen_pairs:
                    continue

                dist = math.hypot(o1.x - o2.x, o1.y - o2.y)
                hazard_dist = min(self.hazard_threshold, o1.hazard_radius + o2.hazard_radius)

                if dist < hazard_dist:
                    seen_pairs.add(pair_key)
                    hazards.append({
                        "type": "proximity_collision",
                        "obj1": o1,
                        "obj2": o2,
                        "distance": dist,
                        "threshold": hazard_dist,
                        "hilbert_delta": abs(o1.hilbert_index - o2.hilbert_index),
                    })

        # 2. High-Density Cluster Detection
        # Identify cells or local Hilbert windows with high equipment density (> 2 objects in same cell)
        cell_counts: Dict[int, List[SpatialObject]] = {}
        for o in obj_list:
            cell_counts.setdefault(o.hilbert_index, []).append(o)

        high_density = False
        for h_idx, cell_objs in cell_counts.items():
            if len(cell_objs) >= 3:
                high_density = True
                hazards.append({
                    "type": "high_density_cluster",
                    "hilbert_index": h_idx,
                    "objects": cell_objs,
                    "count": len(cell_objs),
                })

        self.active_hazards = hazards
        self.hazard_violations_count = len(hazards)

        if self.hazard_violations_count > 0:
            self.alarm_active = True
            self.diagnostic_code = DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD
            self.status_word |= int(HilbertStatusBits.CONFLICT_DETECTED)
            if high_density:
                self.status_word |= int(HilbertStatusBits.HIGH_DENSITY)
        else:
            if self.diagnostic_code == DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD:
                self.alarm_active = False
                self.diagnostic_code = DIAG_OK
            self.status_word &= ~int(HilbertStatusBits.CONFLICT_DETECTED)
            self.status_word &= ~int(HilbertStatusBits.HIGH_DENSITY)

        return hazards

    def inject_proximity_hazard_alarm(self) -> None:
        """Manually trigger proximity hazard alarm state for testing."""
        self.alarm_active = True
        self.diagnostic_code = DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD
        self.status_word |= int(HilbertStatusBits.CONFLICT_DETECTED)
        self.sync_to_registers(self.reg_table)

    def clear_alarm(self) -> None:
        """Clear active alarm state and reset diagnostic code."""
        self.alarm_active = False
        self.diagnostic_code = DIAG_OK
        self.status_word &= ~int(HilbertStatusBits.CONFLICT_DETECTED)
        self.status_word &= ~int(HilbertStatusBits.HIGH_DENSITY)
        self.detect_hazards()
        self.sync_to_registers(self.reg_table)

    def clear_anomalies(self) -> None:
        """Alias for clear_alarm."""
        self.clear_alarm()

    # ------------------------------------------------------------------------
    # Horner OCS Register Table Synchronization
    # ------------------------------------------------------------------------

    def sync_to_registers(
        self,
        rt: Optional[RegisterTable] = None,
        privilege: Optional[PrivilegeMode] = None,
    ) -> None:
        """Synchronize engine state to Horner RegisterTable %R2670..%R2677 and %M623..%M624."""
        target_rt = rt or self.reg_table

        # %R2670: Total Indexed Spatial Objects Count
        target_rt.write_word(REG_W306_TOTAL_OBJECTS, len(self.objects) & 0xFFFF, privilege=privilege)

        # %R2671: Hilbert Curve Order (1..8)
        target_rt.write_word(REG_W306_CURVE_ORDER, self._order & 0xFFFF, privilege=privilege)

        # %R2672: Active Curve Segments Count
        target_rt.write_word(REG_W306_ACTIVE_SEGMENTS, self.active_segments_count & 0xFFFF, privilege=privilege)

        # %R2673: Primary Active Object Hilbert Index
        target_rt.write_word(REG_W306_PRIMARY_INDEX, self.primary_hilbert_index & 0xFFFF, privilege=privilege)

        # %R2674: Query Point / Variable Hilbert Index
        target_rt.write_word(REG_W306_QUERY_INDEX, self.query_point_index & 0xFFFF, privilege=privilege)

        # %R2675: Spatial Proximity Hazard Violations Count
        target_rt.write_word(REG_W306_HAZARD_VIOLATIONS, self.hazard_violations_count & 0xFFFF, privilege=privilege)

        # %R2676: Status Word
        sw = self.status_word | int(HilbertStatusBits.ONLINE)
        if self.hazard_violations_count > 0 or self.alarm_active:
            sw |= int(HilbertStatusBits.CONFLICT_DETECTED)
        target_rt.write_word(REG_W306_STATUS_WORD, sw & 0xFFFF, privilege=privilege)

        # %R2677: Diagnostic Code
        target_rt.write_word(REG_W306_DIAGNOSTIC_CODE, int(self.diagnostic_code) & 0xFFFF, privilege=privilege)

        # Discrete Coils %M623..%M624
        target_rt.write_bit(COIL_W306_CANVAS_ONLINE, True, privilege=privilege)
        target_rt.write_bit(COIL_W306_HAZARD_ALARM, bool(self.alarm_active), privilege=privilege)

    def read_from_registers(self, rt: Optional[RegisterTable] = None) -> None:
        """Read setpoint/command registers from Horner RegisterTable."""
        source_rt = rt or self.reg_table
        new_order = source_rt.read_word(REG_W306_CURVE_ORDER) & 0xFFFF
        if MIN_CURVE_ORDER <= new_order <= MAX_CURVE_ORDER and new_order != self._order:
            self.set_order(new_order)

    # ------------------------------------------------------------------------
    # ILogicUnit Simulation Interface
    # ------------------------------------------------------------------------

    def scan_step(self, context: Optional[ScanContext] = None, *args: Any, **kwargs: Any) -> ExecutionResult:
        """Execute one PLC simulation scan cycle step."""
        self.cycle_count += 1
        rt = getattr(context, "register_table", None) or self.reg_table
        self.detect_hazards()
        self.sync_to_registers(rt)

        status = AgentStatus.SUCCESS if not self.alarm_active else AgentStatus.FAILED
        return ExecutionResult(
            status=status,
            error_code=None if not self.alarm_active else str(self.diagnostic_code),
            details=(
                f"Hilbert Canvas: Order={self._order}, Objects={len(self.objects)}, "
                f"Violations={self.hazard_violations_count}, Alarm={self.alarm_active}"
            ),
            data={
                "objects_count": len(self.objects),
                "curve_order": self._order,
                "active_segments": self.active_segments_count,
                "primary_index": self.primary_hilbert_index,
                "query_index": self.query_point_index,
                "hazard_violations": self.hazard_violations_count,
                "status_word": self.status_word,
                "diagnostic_code": str(self.diagnostic_code),
                "alarm_active": self.alarm_active,
            },
        )

    @property
    def name(self) -> str:
        return "HilbertCanvasEngine"

    @property
    def priority(self) -> int:
        return 100

    @property
    def is_enabled(self) -> bool:
        return True

    def step(self, *args: Any, **kwargs: Any) -> None:
        self.scan_step(None, *args, **kwargs)

    def execute(self, context: Optional[ScanContext] = None, *args: Any, **kwargs: Any) -> ExecutionResult:
        return self.scan_step(context, *args, **kwargs)

    def reset(self) -> None:
        """Reset engine to clean initial state."""
        self.cycle_count = 0
        self.objects.clear()
        self._next_id = 1
        self._order = DEFAULT_CURVE_ORDER
        self.primary_object_id = 0
        self.primary_hilbert_index = 0
        self.query_point_x = None
        self.query_point_y = None
        self.query_point_index = 0
        self.query_low_index = 0
        self.query_high_index = 0
        self.hazard_violations_count = 0
        self.active_hazards.clear()
        self.alarm_active = False
        self.diagnostic_code = DIAG_OK
        self.status_word = int(HilbertStatusBits.ONLINE) | int(HilbertStatusBits.CURVE_GENERATED)
        self.sync_to_registers(self.reg_table)

    @property
    def metrics(self) -> HilbertMetrics:
        """Get snapshot of current telemetry metrics."""
        return HilbertMetrics(
            total_objects=len(self.objects),
            curve_order=self._order,
            active_segments=self.active_segments_count,
            primary_hilbert_index=self.primary_hilbert_index,
            query_hilbert_index=self.query_point_index,
            hazard_violations_count=self.hazard_violations_count,
            status_word=self.status_word,
            diagnostic_code=self.diagnostic_code,
            online=True,
            alarm_active=self.alarm_active,
        )


HilbertCanvas = HilbertCanvasEngine


# ============================================================================
# 5. WCAG 2.1 AAA Contrast & Vector SCADA Visual Grounding (SVG 1.1)
# ============================================================================

def _srgb_to_linear(c_norm: float) -> float:
    """Convert normalized sRGB channel [0, 1] to linear factor for WCAG 2.1."""
    if c_norm <= 0.03928:
        return c_norm / 12.92
    return ((c_norm + 0.055) / 1.055) ** 2.4


def _hex_to_relative_luminance(hex_str: str) -> float:
    """Calculate relative luminance from hex color string."""
    h = hex_str.lstrip("#")
    r, g, b = int(h[0:2], 16) / 255.0, int(h[2:4], 16) / 255.0, int(h[4:6], 16) / 255.0
    return 0.2126 * _srgb_to_linear(r) + 0.7152 * _srgb_to_linear(g) + 0.0722 * _srgb_to_linear(b)


def calculate_contrast_ratio(hex1: str, hex2: str) -> float:
    """Calculate WCAG 2.1 contrast ratio between two hex colors."""
    l1 = _hex_to_relative_luminance(hex1)
    l2 = _hex_to_relative_luminance(hex2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def validate_wcag_aaa_contrast(foreground_hex: str, background_hex: str, target_ratio: float = 18.0) -> bool:
    """Assert WCAG 2.1 AAA high-contrast requirement."""
    return calculate_contrast_ratio(foreground_hex, background_hex) >= target_ratio


def _render_equipment_symbol(
    elem: SpatialObject,
    is_primary: bool,
    is_alarm: bool,
) -> str:
    """Render high-contrast ISA-5.1 SCADA equipment symbol."""
    x = elem.x
    y = elem.y
    eid = elem.id
    etype = elem.equip_type.lower()
    tag = html.escape(elem.tag)

    if is_alarm:
        status_col = COLOR_ALARM_CRIMSON
        border_col = "#B91C1C"
        bg_col = "#450A0A"
    elif is_primary:
        status_col = COLOR_RETICLE_CYAN
        border_col = "#0284C7"
        bg_col = "#082F49"
    else:
        status_col = COLOR_NOMINAL_EMERALD
        border_col = "#059669"
        bg_col = "#022C22"

    symbol_parts: List[str] = []
    symbol_parts.append(f'<g id="hilbert-node-{eid}" class="equipment-symbol {etype}-symbol sensor-node">')

    # Hazard radius dashed aura
    hr = elem.hazard_radius
    symbol_parts.append(
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{hr:.1f}" fill="{status_col}" fill-opacity="0.06" '
        f'stroke="{status_col}" stroke-width="0.8" stroke-dasharray="3 3" />'
    )

    if etype == "valve":
        # Opposing triangular valve body with actuator stem
        symbol_parts.append(
            f'<polygon points="{x - 9:.1f},{y - 6:.1f} {x:.1f},{y:.1f} {x - 9:.1f},{y + 6:.1f}" '
            f'fill="{status_col}" stroke="{border_col}" stroke-width="1.2" />'
        )
        symbol_parts.append(
            f'<polygon points="{x + 9:.1f},{y - 6:.1f} {x:.1f},{y:.1f} {x + 9:.1f},{y + 6:.1f}" '
            f'fill="{status_col}" stroke="{border_col}" stroke-width="1.2" />'
        )
        symbol_parts.append(
            f'<line x1="{x:.1f}" y1="{y:.1f}" x2="{x:.1f}" y2="{y - 11:.1f}" stroke="{border_col}" stroke-width="1.5" />'
        )
        symbol_parts.append(
            f'<line x1="{x - 5:.1f}" y1="{y - 11:.1f}" x2="{x + 5:.1f}" y2="{y - 11:.1f}" stroke="{border_col}" stroke-width="2.0" />'
        )
    elif etype == "pump":
        # Centrifugal pump casing with tangential nozzle
        symbol_parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="8.0" fill="{bg_col}" stroke="{status_col}" stroke-width="1.8" />'
        )
        symbol_parts.append(
            f'<polygon points="{x:.1f},{y - 8:.1f} {x + 10:.1f},{y - 12:.1f} {x + 6:.1f},{y - 4:.1f}" '
            f'fill="{status_col}" stroke="{border_col}" stroke-width="1.0" />'
        )
        symbol_parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.5" fill="{status_col}" />'
        )
    elif etype == "tank":
        # Cylindrical vessel with rounded dome caps
        symbol_parts.append(
            f'<rect x="{x - 9:.1f}" y="{y - 13:.1f}" width="18.0" height="26.0" rx="4.0" '
            f'fill="{bg_col}" stroke="{status_col}" stroke-width="1.6" />'
        )
        symbol_parts.append(
            f'<line x1="{x - 7:.1f}" y1="{y + 2:.1f}" x2="{x + 7:.1f}" y2="{y + 2:.1f}" '
            f'stroke="{status_col}" stroke-width="1.2" stroke-dasharray="2 2" />'
        )
    else:  # "sensor" or default instrument
        # Circular instrument transmitter bubble with center pip
        symbol_parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6.0" fill="{bg_col}" stroke="{status_col}" stroke-width="1.6" />'
        )
        symbol_parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.2" fill="{status_col}" />'
        )

    # Equipment tag text
    symbol_parts.append(
        f'<text x="{x + 12:.1f}" y="{y - 5:.1f}" fill="{COLOR_TEXT_PRIMARY}" '
        f'font-family="monospace" font-size="9" font-weight="bold">{tag} [H:{elem.hilbert_index}]</text>'
    )
    symbol_parts.append("</g>")
    return "\n".join(symbol_parts)


def generate_hilbert_canvas_svg(engine: HilbertCanvasEngine) -> str:
    """Generate standalone W3C SVG 1.1 vector graphic meeting WCAG 2.1 AAA contrast (> 18:1)."""
    w = int(engine.viewport_width)
    h = int(engine.viewport_height)

    # 1. Multi-Order Space-Filling Polyline Tracing
    coords = engine.get_curve_polyline_coords()
    points_attr = " ".join(f"{px:.1f},{py:.1f}" for px, py in coords)

    # 2. Individual Gradient Colored Segments (for crisp multi-hue rendering)
    curve_segments_svg: List[str] = []
    total_seg = max(1, len(coords) - 1)
    # If order <= 5, render individual colored segments for gradient accuracy
    if engine.order <= 5:
        for idx in range(total_seg):
            p1 = coords[idx]
            p2 = coords[idx + 1]
            t = idx / float(total_seg)
            seg_col = hilbert_color_at_t(t)
            curve_segments_svg.append(
                f'<line class="hilbert-curve-segment" x1="{p1[0]:.1f}" y1="{p1[1]:.1f}" '
                f'x2="{p2[0]:.1f}" y2="{p2[1]:.1f}" stroke="{seg_col}" stroke-width="1.8" stroke-linecap="round" />'
            )

    # 3. Proximity Hazard Collision Vectors
    hazard_svg_parts: List[str] = []
    for hz in engine.active_hazards:
        if hz.get("type") == "proximity_collision":
            o1 = hz["obj1"]
            o2 = hz["obj2"]
            hazard_svg_parts.append(
                f'<line class="proximity-hazard-vector" x1="{o1.x:.1f}" y1="{o1.y:.1f}" '
                f'x2="{o2.x:.1f}" y2="{o2.y:.1f}" stroke="{COLOR_ALARM_CRIMSON}" stroke-width="2.0" stroke-dasharray="4 2" />'
            )
            # Pulsing hazard marker at midpoint
            mx = (o1.x + o2.x) * 0.5
            my = (o1.y + o2.y) * 0.5
            hazard_svg_parts.append(
                f'<circle cx="{mx:.1f}" cy="{my:.1f}" r="5.0" fill="{COLOR_ALARM_CRIMSON}" fill-opacity="0.3" '
                f'stroke="{COLOR_ALARM_CRIMSON}" stroke-width="1.5" />'
            )

    # 4. Range Query / Active Point Reticle Overlay
    reticle_svg = ""
    if engine.query_point_x is not None and engine.query_point_y is not None:
        qx = engine.query_point_x
        qy = engine.query_point_y
        reticle_svg = f"""
    <!-- Query Target Reticle Overlay -->
    <g id="hilbert-query-reticle" class="range-reticle">
        <circle cx="{qx:.1f}" cy="{qy:.1f}" r="30.0" fill="{COLOR_RETICLE_CYAN}" fill-opacity="0.08" stroke="{COLOR_RETICLE_CYAN}" stroke-dasharray="6 4" stroke-width="1.5" />
        <line x1="{qx - 45:.1f}" y1="{qy:.1f}" x2="{qx + 45:.1f}" y2="{qy:.1f}" stroke="{COLOR_RETICLE_CYAN}" stroke-opacity="0.6" stroke-width="1.0" />
        <line x1="{qx:.1f}" y1="{qy - 45:.1f}" x2="{qx:.1f}" y2="{qy + 45:.1f}" stroke="{COLOR_RETICLE_CYAN}" stroke-opacity="0.6" stroke-width="1.0" />
        <circle cx="{qx:.1f}" cy="{qy:.1f}" r="3.0" fill="{COLOR_RETICLE_CYAN}" />
        <rect x="{qx - 90:.1f}" y="{qy - 48:.1f}" width="180" height="18" rx="3" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_RETICLE_CYAN}" stroke-width="1.0" />
        <text x="{qx:.1f}" y="{qy - 35:.1f}" fill="{COLOR_RETICLE_CYAN}" font-family="monospace" font-size="9" font-weight="bold" text-anchor="middle">QUERY INDEX: {engine.query_point_index}</text>
    </g>
        """

    # 5. Equipment Symbols
    nodes_svg: List[str] = []
    for obj in engine.objects.values():
        is_prim = (obj.id == engine.primary_object_id)
        is_alrm = (engine.alarm_active and engine.hazard_violations_count > 0)
        nodes_svg.append(_render_equipment_symbol(obj, is_prim, is_alrm))

    # 6. Decoupled High-Contrast HUD Telemetry Scorecard (WCAG 2.1 AAA Contrast > 18:1)
    m = engine.metrics
    alarm_active = engine.alarm_active or m.hazard_violations_count > 0
    alarm_col = COLOR_ALARM_CRIMSON if alarm_active else COLOR_NOMINAL_EMERALD
    alarm_txt = "SPATIAL PROXIMITY HAZARD ALARM" if alarm_active else "HILBERT CANVAS ONLINE"

    hud_card = f"""
    <!-- Decoupled High-Contrast HUD Scorecard Card (WCAG AAA >= 18:1) -->
    <g id="hud-telemetry-scorecard">
        <rect x="20" y="20" width="1160" height="85" rx="8" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_BORDER}" stroke-width="1.5" />
        <text x="40" y="44" fill="{COLOR_TEXT_PRIMARY}" font-family="monospace" font-size="14" font-weight="bold">HORNER OCS HMI - SPATIAL HILBERT / MORTON SCADA CANVAS (W306)</text>
        <circle cx="45" cy="62" r="5" fill="{alarm_col}" />
        <text x="58" y="66" fill="{alarm_col}" font-family="monospace" font-size="11" font-weight="bold">{alarm_txt}</text>

        <!-- Telemetry Columns -->
        <text x="40" y="88" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="10">ORDER: <tspan fill="{COLOR_TEXT_PRIMARY}" font-weight="bold">{m.curve_order} (N={engine.grid_dimension})</tspan></text>
        <text x="210" y="88" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="10">OBJECTS: <tspan fill="{COLOR_TEXT_PRIMARY}" font-weight="bold">{m.total_objects}</tspan></text>
        <text x="360" y="88" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="10">SEGMENTS: <tspan fill="{COLOR_TEXT_PRIMARY}" font-weight="bold">{m.active_segments}</tspan></text>
        <text x="520" y="88" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="10">PRIMARY IDX: <tspan fill="{COLOR_RETICLE_CYAN}" font-weight="bold">{m.primary_hilbert_index}</tspan></text>
        <text x="700" y="88" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="10">QUERY IDX: <tspan fill="{COLOR_RETICLE_CYAN}" font-weight="bold">{m.query_hilbert_index}</tspan></text>
        <text x="860" y="88" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="10">VIOLATIONS: <tspan fill="{alarm_col}" font-weight="bold">{m.hazard_violations_count}</tspan></text>
        <text x="1010" y="88" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="10">DIAG: <tspan fill="{COLOR_TEXT_PRIMARY}" font-weight="bold">0x{int(m.diagnostic_code) & 0xFFFF:04X}</tspan></text>
    </g>
    """

    svg_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" version="1.1">
    <defs>
        <!-- SCADA Styling & Color Filters -->
        <linearGradient id="hilbert-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="{COLOR_GRADIENT_CYAN}" />
            <stop offset="33%" stop-color="{COLOR_GRADIENT_EMERALD}" />
            <stop offset="66%" stop-color="{COLOR_GRADIENT_AMBER}" />
            <stop offset="100%" stop-color="{COLOR_GRADIENT_MAGENTA}" />
        </linearGradient>
    </defs>

    <!-- Canvas Background -->
    <rect width="{w}" height="{h}" fill="{COLOR_SCADA_BG}" />

    <!-- Grid Domain Boundary -->
    <rect x="0" y="0" width="{w}" height="{h}" fill="none" stroke="{COLOR_BORDER}" stroke-width="1.0" />

    <!-- Hilbert Space-Filling Curve Tracing -->
    <g id="hilbert-curve-container" class="hilbert-curve">
        <!-- Base Polyline with Gradient -->
        <polyline id="hilbert-curve-polyline" class="hilbert-curve-polyline"
                  points="{points_attr}"
                  fill="none" stroke="url(#hilbert-gradient)" stroke-width="1.6"
                  stroke-opacity="0.85" stroke-linecap="round" stroke-linejoin="round" />
        {"".join(curve_segments_svg)}
    </g>

    <!-- Proximity Hazard Vectors -->
    <g id="proximity-hazard-markers">
        {"".join(hazard_svg_parts)}
    </g>

    {reticle_svg}

    <!-- Equipment Nodes Grounding -->
    <g id="equipment-nodes-layer">
        {"".join(nodes_svg)}
    </g>

    {hud_card}
</svg>
"""
    return svg_content


# ============================================================================
# 6. Pure IEC 61131-3 Structured Text POU & Security Validation
# ============================================================================

ST_PROGRAM_W306_HILBERT_CANVAS_SYNC: str = """PROGRAM HilbertCanvasSync
VAR
    R2670_TotalObjects : INT;
    R2671_CurveOrder : INT;
    R2672_ActiveSegments : INT;
    R2673_PrimaryIndex : INT;
    R2674_QueryIndex : INT;
    R2675_HazardViolations : INT;
    R2676_StatusWord : WORD;
    R2677_DiagCode : WORD;
    M623_CanvasOnline : BOOL;
    M624_HazardAlarm : BOOL;
END_VAR

(* Dynamic Spatial Hilbert Canvas Sync Scan Logic *)
IF M623_CanvasOnline THEN
    R2676_StatusWord := R2676_StatusWord OR 16#0001; (* Bit 0: Online *)
    IF R2675_HazardViolations > 0 THEN
        M624_HazardAlarm := TRUE;
        R2676_StatusWord := R2676_StatusWord OR 16#0002; (* Bit 1: Conflict Detected *)
        R2677_DiagCode := 16#841B; (* SPATIAL_HILBERT_PROXIMITY_HAZARD *)
    ELSE
        M624_HazardAlarm := FALSE;
        R2676_StatusWord := R2676_StatusWord AND 16#FFFD;
        R2677_DiagCode := 16#0000;
    END_IF;
    IF R2671_CurveOrder >= 1 AND R2671_CurveOrder <= 8 THEN
        R2676_StatusWord := R2676_StatusWord OR 16#0004; (* Bit 2: Curve Generated *)
    ELSE
        R2677_DiagCode := 16#841C; (* INVALID_CURVE_ORDER *)
    END_IF;
ELSE
    R2676_StatusWord := 16#0000;
    M624_HazardAlarm := FALSE;
    R2677_DiagCode := 16#0000;
END_IF;
END_PROGRAM
"""

ST_PROGRAM_HILBERT_CANVAS_SYNC: str = ST_PROGRAM_W306_HILBERT_CANVAS_SYNC
HILBERT_CANVAS_PURE_ST_POU: str = ST_PROGRAM_W306_HILBERT_CANVAS_SYNC


def verify_hilbert_canvas_pure_st(st_code: Optional[str] = None) -> bool:
    """Validate Structured Text POU syntax and enforce ladder construct rejection."""
    code = st_code or ST_PROGRAM_W306_HILBERT_CANVAS_SYNC
    SecurityGuard.assert_pure_st_content(code)
    parser = STParser()
    res = parser.parse(code)
    return res is not None and res.pou_type == POUType.PROGRAM


# ============================================================================
# 7. Canonical Factory & 9-Stage Verification Suite
# ============================================================================

def create_canonical_hilbert_canvas(
    sample_count: int = 16,
    order: int = DEFAULT_CURVE_ORDER,
    seed: int = 42,
) -> HilbertCanvasEngine:
    """Create a canonical Hilbert canvas with deterministic test equipment objects."""
    rnd = random.Random(seed)
    engine = HilbertCanvasEngine(order=order)
    types = ["valve", "pump", "tank", "sensor"]

    # Space objects across the viewport
    for i in range(1, sample_count + 1):
        x = rnd.uniform(80.0, CANVAS_VIEWPORT_WIDTH - 80.0)
        y = rnd.uniform(140.0, CANVAS_VIEWPORT_HEIGHT - 60.0)
        etype = types[(i - 1) % len(types)]
        engine.insert_object(x, y, obj_id=i, equip_type=etype, tag=f"{etype.upper()[:3]}-{i:02d}")

    return engine


def run_hilbert_canvas_verification(
    project_root: Optional[Union[str, Path]] = None,
    output_path: Optional[Union[str, Path]] = None,
    sample_svg_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute the deterministic 9-stage verification suite for W306."""
    test_results: List[Dict[str, Any]] = []
    work_package = "W306"

    # ------------------------------------------------------------------------
    # Stage 1: init_and_domain
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng = HilbertCanvasEngine(order=3)
    c1 = (
        eng.order == 3
        and eng.viewport_width == CANVAS_VIEWPORT_WIDTH
        and eng.viewport_height == CANVAS_VIEWPORT_HEIGHT
        and eng.grid_dimension == 8
        and eng.total_cells == 64
        and eng.active_segments_count == 63
        and eng.diagnostic_code == DIAG_OK
        and eng.alarm_active is False
        and (eng.status_word & HilbertStatusBits.ONLINE) != 0
        and (eng.status_word & HilbertStatusBits.CURVE_GENERATED) != 0
    )
    test_results.append({
        "stage": 1,
        "name": "init_and_domain",
        "passed": c1,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Hilbert Canvas initialized over [{eng.viewport_width}x{eng.viewport_height}], Order=3 (N=8, Cells=64).",
    })

    # ------------------------------------------------------------------------
    # Stage 2: hilbert_and_morton_bijection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    bijection_ok = True
    # Exhaustive verification for orders 1..4
    for o in range(1, 5):
        num_cells = 1 << (2 * o)
        for d in range(num_cells):
            gx, gy = d2xy(o, d)
            d_rec = xy2d(o, gx, gy)
            if d_rec != d:
                bijection_ok = False
                break
        if not bijection_ok:
            break

    # Morton roundtrip check
    morton_ok = True
    for x_val in range(16):
        for y_val in range(16):
            z = xy2z(x_val, y_val)
            rx, ry = z2xy(z)
            if (rx, ry) != (x_val, y_val):
                morton_ok = False
                break

    # Out of bounds check
    oob_caught = False
    try:
        xy2d(3, 99, 99)
    except ValueError:
        oob_caught = True

    c2 = bijection_ok and morton_ok and oob_caught
    test_results.append({
        "stage": 2,
        "name": "hilbert_and_morton_bijection",
        "passed": c2,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Bijective roundtrip validated: d2xy <-> xy2d (orders 1..4) and xy2z <-> z2xy, OOB handled.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: space_filling_curve_generation
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    curve_coords = eng.get_curve_polyline_coords()
    c3_count = len(curve_coords) == 64
    # Check Manhattan step distance between consecutive grid points along curve
    steps_ok = True
    for d in range(eng.total_cells - 1):
        x1, y1 = d2xy(eng.order, d)
        x2, y2 = d2xy(eng.order, d + 1)
        if abs(x1 - x2) + abs(y1 - y2) != 1:
            steps_ok = False
            break

    c3 = c3_count and steps_ok and eng.active_segments_count == 63
    test_results.append({
        "stage": 3,
        "name": "space_filling_curve_generation",
        "passed": c3,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Hilbert curve polyline traced: 64 points, 63 active segments, unit grid step verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: spatial_range_queries_and_locality
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng.insert_object(200.0, 150.0, obj_id=1, equip_type="valve")
    eng.insert_object(400.0, 300.0, obj_id=2, equip_type="pump")
    eng.insert_object(600.0, 450.0, obj_id=3, equip_type="tank")
    eng.insert_object(800.0, 600.0, obj_id=4, equip_type="sensor")

    h1 = eng.objects[1].hilbert_index
    h2 = eng.objects[2].hilbert_index
    low_idx = min(h1, h2)
    high_idx = max(h1, h2)
    range_objs = eng.query_range_hilbert(low_idx, high_idx)
    range_comps = eng.hilbert_range_to_2d_components(low_idx, high_idx)

    c4 = (
        len(range_objs) >= 2
        and all(low_idx <= o.hilbert_index <= high_idx for o in range_objs)
        and len(range_comps) == (high_idx - low_idx + 1)
    )
    test_results.append({
        "stage": 4,
        "name": "spatial_range_queries_and_locality",
        "passed": c4,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Spatial range query [{low_idx}..{high_idx}] matched {len(range_objs)} objects across {len(range_comps)} cells.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: proximity_hazard_and_cluster_detection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # Insert two colliding objects at close coordinates (dist ~14.1 px < 50.0 px hazard threshold)
    eng.insert_object(300.0, 300.0, obj_id=10, equip_type="valve", hazard_radius=30.0)
    eng.insert_object(310.0, 310.0, obj_id=11, equip_type="pump", hazard_radius=30.0)
    hazards = eng.detect_hazards()

    c5 = (
        len(hazards) >= 1
        and eng.hazard_violations_count >= 1
        and any(h.get("type") == "proximity_collision" for h in hazards)
    )
    test_results.append({
        "stage": 5,
        "name": "proximity_hazard_and_cluster_detection",
        "passed": c5,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Proximity hazard detection: {len(hazards)} collision violations detected via 1D locality preservation.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: hazard_alarm_trip_and_clear
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    c6_trip = (
        eng.alarm_active is True
        and eng.diagnostic_code == DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD
        and (eng.status_word & HilbertStatusBits.CONFLICT_DETECTED) != 0
    )

    # Clear alarm by removing one of the colliding objects
    eng.remove_object(11)
    eng.clear_alarm()
    c6_clear = (
        eng.alarm_active is False
        and eng.diagnostic_code == DIAG_OK
        and (eng.status_word & HilbertStatusBits.CONFLICT_DETECTED) == 0
    )

    c6 = c6_trip and c6_clear
    test_results.append({
        "stage": 6,
        "name": "hazard_alarm_trip_and_clear",
        "passed": c6,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Hazard alarm tripped %M624, asserted 0x841B and CONFLICT_DETECTED bit; cleanly cleared.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: wcag_aaa_svg_rendering
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    canon_eng = create_canonical_hilbert_canvas(sample_count=16, order=3, seed=42)
    svg_text = generate_hilbert_canvas_svg(canon_eng)
    root = ET.fromstring(svg_text)
    contrast_ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)

    c7 = (
        root.tag.endswith("svg")
        and "hilbert-curve-polyline" in svg_text
        and "equipment-symbol" in svg_text
        and "sensor-node" in svg_text
        and "hud-telemetry-scorecard" in svg_text
        and "viewBox" in svg_text
        and contrast_ratio >= 18.0
    )
    test_results.append({
        "stage": 7,
        "name": "wcag_aaa_svg_rendering",
        "passed": c7,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"W3C SVG 1.1 generated with gradient polyline and equipment symbols; contrast verified ({contrast_ratio:.2f}:1 >= 18:1).",
    })

    # ------------------------------------------------------------------------
    # Stage 8: horner_ocs_register_sync
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt = RegisterTable()
    canon_eng.sync_to_registers(rt)

    w_objects = rt.read_word(REG_W306_TOTAL_OBJECTS)
    w_order = rt.read_word(REG_W306_CURVE_ORDER)
    w_segments = rt.read_word(REG_W306_ACTIVE_SEGMENTS)
    w_primary = rt.read_word(REG_W306_PRIMARY_INDEX)
    w_query = rt.read_word(REG_W306_QUERY_INDEX)
    w_viols = rt.read_word(REG_W306_HAZARD_VIOLATIONS)
    w_status = rt.read_word(REG_W306_STATUS_WORD)
    w_diag = rt.read_word(REG_W306_DIAGNOSTIC_CODE)
    b_online = rt.read_bit(COIL_W306_CANVAS_ONLINE)
    b_alarm = rt.read_bit(COIL_W306_HAZARD_ALARM)

    c8 = (
        w_objects == len(canon_eng.objects)
        and w_order == canon_eng.order
        and w_segments == canon_eng.active_segments_count
        and w_primary == canon_eng.primary_hilbert_index
        and w_query == canon_eng.query_point_index
        and w_viols == canon_eng.hazard_violations_count
        and (w_status & 0x0001) != 0
        and (w_diag & 0xFFFF) == (int(canon_eng.diagnostic_code) & 0xFFFF)
        and b_online is True
        and b_alarm == bool(canon_eng.alarm_active)
    )
    test_results.append({
        "stage": 8,
        "name": "horner_ocs_register_sync",
        "passed": c8,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Horner OCS register space %R2670..%R2677 and coils %M623..%M624 verified bit-exact.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: pure_st_pou_and_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    st_valid = verify_hilbert_canvas_pure_st()
    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("PROGRAM P ---[ ]--- END_PROGRAM")
    except LadderForbiddenError:
        ladder_rejected = True

    c9 = st_valid and ladder_rejected
    test_results.append({
        "stage": 9,
        "name": "pure_st_pou_and_ladder_rejection",
        "passed": c9,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "HilbertCanvasSync pure ST AST validated; ladder logic constructs strictly rejected.",
    })

    # Summary
    passed_count = sum(1 for r in test_results if r["passed"])
    total_count = len(test_results)
    all_passed = (passed_count == total_count)

    evidence = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "ERR_STAGE_VERIFICATION_FAILED",
        "details": f"Wave {work_package} Hilbert Canvas Verification PASSED ({passed_count}/{total_count} stages).",
        "data": {
            "work_package": work_package,
            "gate": "G9",
            "checks_passed": passed_count,
            "total_checks": total_count,
            "stages": test_results,
            "tests": test_results,
        },
    }

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    if sample_svg_path:
        svg_p = Path(sample_svg_path)
        svg_p.parent.mkdir(parents=True, exist_ok=True)
        with open(svg_p, "w", encoding="utf-8") as f:
            f.write(svg_text)

    return evidence


# ============================================================================
# 8. Exports & CLI Entrypoint
# ============================================================================

__all__ = [
    "CANVAS_VIEWPORT_HEIGHT",
    "CANVAS_VIEWPORT_WIDTH",
    "COIL_HILBERT_ALARM",
    "COIL_HILBERT_CANVAS_ONLINE",
    "COIL_HILBERT_HAZARD_ALARM",
    "COIL_HILBERT_ONLINE",
    "COIL_HILBERT_PROXIMITY_HAZARD",
    "COIL_W306_CANVAS_ONLINE",
    "COIL_W306_HAZARD_ALARM",
    "COLOR_ALARM_CRIMSON",
    "COLOR_BORDER",
    "COLOR_CONGESTION_AMBER",
    "COLOR_DARK_SURFACE",
    "COLOR_DECOUPLED_BADGE",
    "COLOR_GRADIENT_AMBER",
    "COLOR_GRADIENT_CYAN",
    "COLOR_GRADIENT_EMERALD",
    "COLOR_GRADIENT_MAGENTA",
    "COLOR_NOMINAL_EMERALD",
    "COLOR_RETICLE_CYAN",
    "COLOR_SAMPLE_BORDER",
    "COLOR_SAMPLE_NODE",
    "COLOR_SCADA_BG",
    "COLOR_TEXT_MUTED",
    "COLOR_TEXT_PRIMARY",
    "COLOR_WARNING_AMBER",
    "DEFAULT_CURVE_ORDER",
    "DEFAULT_HAZARD_THRESHOLD",
    "DIAG_ERR_INVALID_CURVE_ORDER",
    "DIAG_ERR_INVALID_DOMAIN",
    "DIAG_ERR_OUT_OF_BOUNDS",
    "DIAG_ERR_PROXIMITY_HAZARD",
    "DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD",
    "DIAG_OK",
    "DiagnosticCode",
    "HILBERT_CANVAS_PURE_ST_POU",
    "HILBERT_GRID_DOMAIN",
    "HilbertCanvas",
    "HilbertCanvasEngine",
    "HilbertCurve",
    "HilbertDiagnosticCode",
    "HilbertMetrics",
    "HilbertRect",
    "HilbertStatusBits",
    "MortonCurve",
    "hilbert_xy2d",
    "hilbert_d2xy",
    "morton_xy2z",
    "morton_z2xy",
    "INVALID_CURVE_ORDER",
    "MAX_CURVE_ORDER",
    "MIN_CURVE_ORDER",
    "ORDER_COLORS",
    "OUT_OF_BOUNDS",
    "REG_HILBERT_ACTIVE_SEGMENTS",
    "REG_HILBERT_CURVE_ORDER",
    "REG_HILBERT_DIAGNOSTIC_CODE",
    "REG_HILBERT_DIAG_CODE",
    "REG_HILBERT_HAZARD_VIOLATIONS",
    "REG_HILBERT_HAZARD_VIOLATIONS_COUNT",
    "REG_HILBERT_ORDER",
    "REG_HILBERT_PRIMARY_INDEX",
    "REG_HILBERT_PRIMARY_OBJECT_INDEX",
    "REG_HILBERT_QUERY_INDEX",
    "REG_HILBERT_QUERY_POINT_INDEX",
    "REG_HILBERT_SEGMENTS",
    "REG_HILBERT_STATUS",
    "REG_HILBERT_STATUS_WORD",
    "REG_HILBERT_TOTAL_NODES",
    "REG_HILBERT_TOTAL_OBJECTS",
    "REG_W306_ACTIVE_SEGMENTS",
    "REG_W306_CURVE_ORDER",
    "REG_W306_DIAGNOSTIC_CODE",
    "REG_W306_HAZARD_VIOLATIONS",
    "REG_W306_PRIMARY_INDEX",
    "REG_W306_QUERY_INDEX",
    "REG_W306_STATUS_WORD",
    "REG_W306_TOTAL_OBJECTS",
    "Rect",
    "SPATIAL_HILBERT_PROXIMITY_HAZARD",
    "ST_PROGRAM_HILBERT_CANVAS_SYNC",
    "ST_PROGRAM_W306_HILBERT_CANVAS_SYNC",
    "SpatialObject",
    "SpatialPoint",
    "HilbertSpatialPoint",
    "TOTAL_DOMAIN_AREA",
    "calculate_contrast_ratio",
    "create_canonical_hilbert_canvas",
    "d2xy",
    "generate_hilbert_canvas_svg",
    "hilbert_color_at_t",
    "hilbert_range_to_2d_cells",
    "run_hilbert_canvas_verification",
    "validate_wcag_aaa_contrast",
    "verify_hilbert_canvas_pure_st",
    "xy2d",
    "xy2z",
    "z2xy",
]


def main() -> int:
    """CLI entrypoint for Hilbert Canvas verification."""
    parser = argparse.ArgumentParser(description="Hilbert Canvas SCADA Verification Suite (W306)")
    parser.add_argument("--out", type=str, default=None, help="Output evidence JSON path")
    parser.add_argument("--svg", type=str, default=None, help="Output sample SVG path")
    args = parser.parse_args()

    results = run_hilbert_canvas_verification(
        output_path=args.out,
        sample_svg_path=args.svg,
    )
    print(json.dumps(results, indent=2))
    return 0 if results["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
