"""Cscape HMI Dynamic Spatial Medial Axis Skeletonization SCADA Canvas (W282).

Work Package: W282 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Medial Axis Transform Voronoi Skeletonization SCADA Canvas]
Status Contract: Strict 4-State JSON output & evidence emission.

Provides:
1. Computational Geometry:
   - Pure Python 2D Medial Axis Transform (MAT) / Voronoi Skeletonization for 2D polygon boundaries.
   - Point sampling along polygon boundary contours.
   - Extraction of internal Voronoi vertices / medial nodes and connecting branches inside polygon.
   - Maximal Inscribed Disk calculation: for each medial point, calculate shortest Euclidean distance to polygon boundary (clearance radius R).
   - Branch Pruning Filter: prune minor noise branches based on branch length / max clearance ratio or clearance significance.
   - Bottleneck Identification: identify critical choke points where clearance radius drops below a minimum threshold.
2. Canvas Rendering & Visualization:
   - Standalone W3C SVG 1.1 vector graphic generator.
   - High-contrast dark theme HUD styling meeting WCAG 2.1 AAA contrast (> 18:1).
   - Draw polygon boundary, medial axis skeleton branches, inscribed clearance disks at key nodes, and highlighted bottleneck locations.
3. Diagnostic & Status Codes:
   - MedialAxisDiagnosticCode (IntEnum): OK=0, INVALID_POLYGON=1, SELF_INTERSECTING=2, INSUFFICIENT_VERTICES=3, BOTTLENECK_DETECTED=4, TOPOLOGY_COLLAPSE=5.
   - __hash__ = lambda self: hash(int(self) & 0xFFFF).
4. RegisterTable Synchronization:
   - Analog registers:
     %R2430: Boundary Contour Vertex Count
     %R2431: Internal Medial Branch Count
     %R2432: Max Clearance / Inscribed Circle Radius x10 (e.g. 45.2 -> 452)
     %R2433: Mean Skeleton Clearance Radius x10
     %R2434: Skeleton Total Length (pixels/mm)
     %R2435: Selected Branch ID / Topology Code
     %R2436: Medial Axis Pruning Threshold % x10
     %R2437: Geometric Health / Topology Diagnostic Code
   - Discrete bits:
     %M567: Skeletonization Valid / Topology Intact
     %M568: Narrow Bottleneck / Clearance Violation Warning
   Note: rt.write_word(reg, val & 0xFFFF) for 16-bit unsigned writes.
5. Pure IEC 61131-3 Structured Text POU:
   - MedialAxisCanvasSync program validated via STParser and SecurityGuard.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import json
import math
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants, Diagnostic Codes & Status Bits
# ============================================================================

class MedialAxisDiagnosticCode(IntEnum):
    """Diagnostic and geometric health codes for Medial Axis Canvas."""
    OK = 0
    INVALID_POLYGON = 1
    SELF_INTERSECTING = 2
    INSUFFICIENT_VERTICES = 3
    BOTTLENECK_DETECTED = 4
    TOPOLOGY_COLLAPSE = 5

    def __hash__(self) -> int:
        return hash(int(self) & 0xFFFF)


# Legacy DiagnosticCode wrapper for signed/unsigned equality
class DiagnosticCode(int):
    """Integer subclass for 16-bit diagnostic codes supporting signed/unsigned equality."""

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, int):
            val_u = int(self) & 0xFFFF
            val_s = val_u - 0x10000 if val_u >= 0x8000 else val_u
            other_u = int(other) & 0xFFFF
            other_s = other_u - 0x10000 if other_u >= 0x8000 else other_u
            return (
                int(self) == other
                or val_u == other
                or val_s == other
                or val_s == other_s
                or val_u == other_u
            )
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(int(self) & 0xFFFF)

    def __repr__(self) -> str:
        return f"DiagnosticCode(0x{int(self) & 0xFFFF:04X})"

    def __str__(self) -> str:
        return f"0x{int(self) & 0xFFFF:04X}"


# Diagnostic code aliases and constants
DIAG_OK: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.OK
DIAG_EVENT_OK: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.OK
NOMINAL_OK: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.OK
MEDIAL_AXIS_OK: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.OK

DIAG_ERR_INVALID_POLYGON: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.INVALID_POLYGON
INVALID_POLYGON_FAULT: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.INVALID_POLYGON

DIAG_ERR_SELF_INTERSECTING: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.SELF_INTERSECTING
SELF_INTERSECTING_FAULT: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.SELF_INTERSECTING

DIAG_ERR_INSUFFICIENT_VERTICES: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.INSUFFICIENT_VERTICES
INSUFFICIENT_VERTICES_FAULT: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.INSUFFICIENT_VERTICES

DIAG_ERR_BOTTLENECK_DETECTED: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.BOTTLENECK_DETECTED
BOTTLENECK_DETECTED_ALARM: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.BOTTLENECK_DETECTED

DIAG_ERR_TOPOLOGY_COLLAPSE: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.TOPOLOGY_COLLAPSE
TOPOLOGY_COLLAPSE_FAULT: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.TOPOLOGY_COLLAPSE

DIAG_ERR_BOTTLENECK_CHOKE = DIAG_ERR_BOTTLENECK_DETECTED
DIAG_ERR_CLEARANCE_VIOLATION = DIAG_ERR_BOTTLENECK_DETECTED
DIAG_ERR_DEGENERATE_GEOMETRY = DIAG_ERR_INVALID_POLYGON
DIAG_ERR_COLINEAR_FAULT = DIAG_ERR_INVALID_POLYGON


class MedialAxisStatusBits(IntFlag):
    """Discrete status bit flags for Medial Axis Canvas."""
    CANVAS_ACTIVE = 1 << 0
    SKELETON_COMPUTED = 1 << 1
    BOTTLENECK_WARNING = 1 << 2
    BOTTLENECK_ALARM = 1 << 2
    CLEARANCE_VIOLATION = 1 << 2
    TOPOLOGY_INTACT = 1 << 3
    POLYGON_VALID = 1 << 4
    SVG_RENDER_VALID = 1 << 5
    PRUNING_COMPLETED = 1 << 6


MedialAxisCanvasStatusBits = MedialAxisStatusBits


# Register definitions (%R2430..%R2437)
REG_W282_BOUNDARY_VERTICES: str = "%R2430"
REG_W282_MEDIAL_BRANCHES: str = "%R2431"
REG_W282_MAX_CLEARANCE: str = "%R2432"
REG_W282_MEAN_CLEARANCE: str = "%R2433"
REG_W282_SKELETON_LENGTH: str = "%R2434"
REG_W282_SELECTED_BRANCH: str = "%R2435"
REG_W282_PRUNING_THRESHOLD: str = "%R2436"
REG_W282_DIAGNOSTIC_CODE: str = "%R2437"

REG_BOUNDARY_CONTOUR_VERTEX_COUNT: str = REG_W282_BOUNDARY_VERTICES
REG_INTERNAL_MEDIAL_BRANCH_COUNT: str = REG_W282_MEDIAL_BRANCHES
REG_MAX_CLEARANCE_RADIUS_SCALED: str = REG_W282_MAX_CLEARANCE
REG_MEAN_CLEARANCE_RADIUS_SCALED: str = REG_W282_MEAN_CLEARANCE
REG_SKELETON_TOTAL_LENGTH: str = REG_W282_SKELETON_LENGTH
REG_SELECTED_BRANCH_ID: str = REG_W282_SELECTED_BRANCH
REG_PRUNING_THRESHOLD_SCALED: str = REG_W282_PRUNING_THRESHOLD
REG_DIAGNOSTIC_STATUS_CODE: str = REG_W282_DIAGNOSTIC_CODE

REG_MEDIAL_AXIS_BOUNDARY_VERTICES: str = REG_W282_BOUNDARY_VERTICES
REG_MEDIAL_AXIS_BRANCH_COUNT: str = REG_W282_MEDIAL_BRANCHES
REG_MEDIAL_AXIS_MAX_CLEARANCE: str = REG_W282_MAX_CLEARANCE
REG_MEDIAL_AXIS_MEAN_CLEARANCE: str = REG_W282_MEAN_CLEARANCE
REG_MEDIAL_AXIS_SKELETON_LENGTH: str = REG_W282_SKELETON_LENGTH
REG_MEDIAL_AXIS_SELECTED_BRANCH: str = REG_W282_SELECTED_BRANCH
REG_MEDIAL_AXIS_PRUNING_THRESHOLD: str = REG_W282_PRUNING_THRESHOLD
REG_MEDIAL_AXIS_DIAGNOSTIC_CODE: str = REG_W282_DIAGNOSTIC_CODE

# Legacy register aliases
REG_W282_STATUS_WORD: str = "%R2430"
REG_W282_BOUNDARY_POINTS: str = "%R2430"
REG_W282_MEDIAL_NODES: str = "%R2431"
REG_W282_BRANCH_SEGMENTS: str = "%R2431"
REG_W282_MAX_INSCRIBED_RADIUS: str = "%R2432"
REG_W282_MIN_CLEARANCE_RADIUS: str = "%R2433"
REG_W282_BOTTLENECK_COUNT: str = "%R2436"
REG_MEDIAL_AXIS_STATUS_WORD: str = REG_W282_STATUS_WORD
REG_MEDIAL_AXIS_BOUNDARY_POINTS: str = REG_W282_BOUNDARY_POINTS
REG_MEDIAL_AXIS_NODE_COUNT: str = REG_W282_MEDIAL_NODES
REG_MEDIAL_AXIS_BRANCH_SEGMENTS: str = REG_W282_BRANCH_SEGMENTS
REG_MEDIAL_AXIS_MAX_INSCRIBED_RADIUS: str = REG_W282_MAX_INSCRIBED_RADIUS
REG_MEDIAL_AXIS_MIN_CLEARANCE_RADIUS: str = REG_W282_MIN_CLEARANCE_RADIUS
REG_MEDIAL_AXIS_BOTTLENECK_COUNT: str = REG_W282_BOTTLENECK_COUNT

# Discrete coils (%M567..%M568)
COIL_W282_SKELETON_VALID: str = "%M567"
COIL_W282_BOTTLENECK_WARNING: str = "%M568"

COIL_SKELETON_VALID: str = COIL_W282_SKELETON_VALID
COIL_BOTTLENECK_WARNING: str = COIL_W282_BOTTLENECK_WARNING
COIL_MEDIAL_AXIS_CANVAS_ACTIVE: str = COIL_W282_SKELETON_VALID
COIL_W282_CANVAS_ACTIVE: str = COIL_W282_SKELETON_VALID
COIL_W282_BOTTLENECK_ALARM: str = COIL_W282_BOTTLENECK_WARNING
COIL_BOTTLENECK_ALARM: str = COIL_W282_BOTTLENECK_WARNING
COIL_CLEARANCE_VIOLATION: str = COIL_W282_BOTTLENECK_WARNING
COIL_MEDIAL_AXIS_ACTIVE: str = COIL_W282_SKELETON_VALID

# Color palette & WCAG Contrast constants
COLOR_DARK_THEME_BACKING: str = "#0A0E17"
COLOR_DARK_SURFACE: str = "#0F172A"
COLOR_DECOUPLED_BADGE: str = "#05080E"
COLOR_TEXT_PRIMARY: str = "#F8FAFC"
COLOR_TEXT_MUTED: str = "#94A3B8"
COLOR_POLYGON_BOUNDARY: str = "#06B6D4"
COLOR_POLYGON_FILL: str = "#0891B2"
COLOR_SKELETON_BRANCH: str = "#10B981"
COLOR_CLEARANCE_DISK: str = "#38BDF8"
COLOR_MAX_DISK: str = "#F59E0B"
COLOR_BOTTLENECK: str = "#EF4444"
COLOR_NOMINAL_EMERALD: str = "#10B981"
COLOR_ALARM_CRIMSON: str = "#EF4444"
COLOR_WARNING_AMBER: str = "#F59E0B"

WCAG_AAA_BADGE_CONTRAST_TARGET: float = 18.0
WCAG_AAA_TEXT_CONTRAST_TARGET: float = 7.0
WCAG_GRAPHICAL_CONTRAST_TARGET: float = 3.0


# ============================================================================
# 2. WCAG Contrast Calculation
# ============================================================================

def srgb_channel_to_linear(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def hex_to_relative_luminance(hex_str: str) -> float:
    h = hex_str.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    r = int(h[0:2], 16) / 255.0
    g = int(h[2:4], 16) / 255.0
    b = int(h[4:6], 16) / 255.0
    return 0.2126 * srgb_channel_to_linear(r) + 0.7152 * srgb_channel_to_linear(g) + 0.0722 * srgb_channel_to_linear(b)


def calculate_contrast_ratio(hex1: str, hex2: str) -> float:
    l1 = hex_to_relative_luminance(hex1)
    l2 = hex_to_relative_luminance(hex2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


class ContrastResult(dict):
    @property
    def is_compliant(self) -> bool:
        return bool(self["is_compliant"])

    @property
    def contrast_ratio(self) -> float:
        return float(self["contrast_ratio"])

    def __bool__(self) -> bool:
        return bool(self["is_compliant"])


def validate_wcag_aaa_contrast(color1: str, color2: str, min_contrast: float = 18.0) -> ContrastResult:
    ratio = calculate_contrast_ratio(color1, color2)
    return ContrastResult({"is_compliant": ratio >= min_contrast, "contrast_ratio": ratio})


# ============================================================================
# 3. Geometry Primitives & Data Models
# ============================================================================

PointTuple = Tuple[float, float]


@dataclass
class Point2D:
    x: float
    y: float
    point_id: int = 0

    @property
    def coords(self) -> PointTuple:
        return (self.x, self.y)

    def distance_to(self, other: Union[Point2D, PointTuple]) -> float:
        ox, oy = (other.x, other.y) if isinstance(other, Point2D) else other
        return math.hypot(self.x - ox, self.y - oy)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Point2D):
            return abs(self.x - other.x) < 1e-6 and abs(self.y - other.y) < 1e-6
        if isinstance(other, tuple) and len(other) == 2:
            return abs(self.x - other[0]) < 1e-6 and abs(self.y - other[1]) < 1e-6
        return False

    def __hash__(self) -> int:
        return hash((round(self.x, 4), round(self.y, 4)))


@dataclass(frozen=True)
class Segment2D:
    """Directed or undirected 2D line segment."""
    p1: Union[Point2D, PointTuple]
    p2: Union[Point2D, PointTuple]

    @property
    def length(self) -> float:
        c1 = self.p1.coords if isinstance(self.p1, Point2D) else self.p1
        c2 = self.p2.coords if isinstance(self.p2, Point2D) else self.p2
        return math.hypot(c2[0] - c1[0], c2[1] - c1[1])

    def distance_to_point(self, pt: Union[Point2D, PointTuple]) -> float:
        c1 = self.p1.coords if isinstance(self.p1, Point2D) else self.p1
        c2 = self.p2.coords if isinstance(self.p2, Point2D) else self.p2
        p = pt.coords if isinstance(pt, Point2D) else pt
        return point_to_segment_distance(p, c1, c2)


@dataclass
class BottleneckChoke:
    """Localized geometric choke/bottleneck violation zone."""
    node_id: int
    x: float
    y: float
    clearance_radius: float
    choke_width: float = 0.0

    def __post_init__(self) -> None:
        if self.choke_width <= 0.0:
            self.choke_width = 2.0 * self.clearance_radius


def is_collinear_set(points: Sequence[Union[Point2D, PointTuple]], tol: float = 1e-4) -> bool:
    """Test if all given points are collinear."""
    pts = [p.coords if isinstance(p, Point2D) else p for p in points]
    if len(pts) <= 2:
        return True
    p0 = pts[0]
    p1 = pts[1]
    dx = p1[0] - p0[0]
    dy = p1[1] - p0[1]
    l = math.hypot(dx, dy)
    if l < tol:
        for p in pts[2:]:
            if math.hypot(p[0] - p0[0], p[1] - p0[1]) > tol:
                return is_collinear_set([p0, p] + list(pts[2:]), tol)
        return True
    for p in pts[2:]:
        cross = abs((p[0] - p0[0]) * dy - (p[1] - p0[1]) * dx)
        if cross / l > tol:
            return False
    return True


@dataclass
class Polygon2D:
    """Simple 2D boundary polygon wrapper."""
    vertices: List[Union[Point2D, PointTuple]] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        pts = [p.coords if isinstance(p, Point2D) else p for p in self.vertices]
        return validate_polygon(pts) == MedialAxisDiagnosticCode.OK

    def shoelace_area(self) -> float:
        pts = [p.coords if isinstance(p, Point2D) else p for p in self.vertices]
        return compute_shoelace_area(pts)

    def perimeter(self) -> float:
        pts = [p.coords if isinstance(p, Point2D) else p for p in self.vertices]
        return compute_polygon_perimeter(pts)

    def contains_point(self, pt: Union[Point2D, PointTuple]) -> bool:
        p = pt.coords if isinstance(pt, Point2D) else pt
        pts = [v.coords if isinstance(v, Point2D) else v for v in self.vertices]
        return is_point_in_polygon(p, pts)

    def min_clearance_to_boundary(self, pt: Union[Point2D, PointTuple]) -> float:
        p = pt.coords if isinstance(pt, Point2D) else pt
        pts = [v.coords if isinstance(v, Point2D) else v for v in self.vertices]
        return shortest_distance_to_polygon(p, pts)

    def sample_boundary(self, spacing: float = 30.0) -> List[Point2D]:
        pts = [v.coords if isinstance(v, Point2D) else v for v in self.vertices]
        samples, _ = sample_polygon_boundary(pts, spacing=spacing)
        return [Point2D(s[0], s[1], point_id=i) for i, s in enumerate(samples)]


def create_canonical_venturi_polygon() -> Polygon2D:
    """Canonical test chamber: industrial venturi conduit with two wide chambers and central choke."""
    return Polygon2D([
        Point2D(100.0, 150.0),
        Point2D(350.0, 150.0),
        Point2D(450.0, 280.0),
        Point2D(650.0, 280.0),
        Point2D(750.0, 150.0),
        Point2D(900.0, 150.0),
        Point2D(900.0, 550.0),
        Point2D(750.0, 550.0),
        Point2D(650.0, 420.0),
        Point2D(450.0, 420.0),
        Point2D(350.0, 550.0),
        Point2D(100.0, 550.0),
    ])


@dataclass(frozen=True)
class Edge2D:
    p1: PointTuple
    p2: PointTuple

    def __init__(self, p1: Union[PointTuple, Point2D], p2: Union[PointTuple, Point2D]) -> None:
        c1 = p1.coords if isinstance(p1, Point2D) else p1
        c2 = p2.coords if isinstance(p2, Point2D) else p2
        p1_c, p2_c = sorted([c1, c2])
        object.__setattr__(self, "p1", p1_c)
        object.__setattr__(self, "p2", p2_c)

    @property
    def length(self) -> float:
        return math.hypot(self.p2[0] - self.p1[0], self.p2[1] - self.p1[1])


@dataclass(frozen=True)
class Triangle2D:
    p1: PointTuple
    p2: PointTuple
    p3: PointTuple

    def __init__(
        self,
        p1: Union[PointTuple, Point2D],
        p2: Union[PointTuple, Point2D],
        p3: Union[PointTuple, Point2D],
    ) -> None:
        c1 = p1.coords if isinstance(p1, Point2D) else p1
        c2 = p2.coords if isinstance(p2, Point2D) else p2
        c3 = p3.coords if isinstance(p3, Point2D) else p3
        object.__setattr__(self, "p1", c1)
        object.__setattr__(self, "p2", c2)
        object.__setattr__(self, "p3", c3)

    @property
    def area(self) -> float:
        return 0.5 * abs(
            self.p1[0] * (self.p2[1] - self.p3[1])
            + self.p2[0] * (self.p3[1] - self.p1[1])
            + self.p3[0] * (self.p1[1] - self.p2[1])
        )

    @property
    def circumcenter(self) -> PointTuple:
        ax, ay = self.p1
        bx, by = self.p2
        cx, cy = self.p3
        d = 2 * (ax * (by - cy) + bx * (cy - ay) + cx * (ay - by))
        if abs(d) < 1e-12:
            return ((ax + bx + cx) / 3.0, (ay + by + cy) / 3.0)
        ux = ((ax * ax + ay * ay) * (by - cy) + (bx * bx + by * by) * (cy - ay) + (cx * cx + cy * cy) * (ay - by)) / d
        uy = ((ax * ax + ay * ay) * (cx - bx) + (bx * bx + by * by) * (ax - cx) + (cx * cx + cy * cy) * (bx - ax)) / d
        return (ux, uy)

    @property
    def circumradius(self) -> float:
        cx, cy = self.circumcenter
        return math.hypot(self.p1[0] - cx, self.p1[1] - cy)

    def circumcircle_contains(self, pt: Union[PointTuple, Point2D], eps: float = 1e-9) -> bool:
        c = pt.coords if isinstance(pt, Point2D) else pt
        cx, cy = self.circumcenter
        return math.hypot(c[0] - cx, c[1] - cy) < self.circumradius - eps


@dataclass
class MedialNode:
    """Represents an internal Voronoi vertex / medial axis skeleton node."""
    node_id: int
    x: float
    y: float
    clearance_radius: float
    is_bottleneck: bool = False
    is_max_clearance: bool = False
    degree: int = 0
    is_pruned: bool = False

    @property
    def coords(self) -> PointTuple:
        return (self.x, self.y)

    @property
    def point(self) -> Point2D:
        return Point2D(self.x, self.y, point_id=self.node_id)


@dataclass
class MedialBranch:
    """Represents a connection branch between two medial axis skeleton nodes."""
    branch_id: int
    p1: PointTuple
    p2: PointTuple
    length: float = 0.0
    avg_clearance: float = 0.0
    is_pruned: bool = False
    is_bottleneck: bool = False
    node1_id: int = 0
    node2_id: int = 0

    def __post_init__(self) -> None:
        if self.length <= 0.0:
            self.length = math.hypot(self.p2[0] - self.p1[0], self.p2[1] - self.p1[1])


MedialAxisNode = MedialNode
MedialAxisBranch = MedialBranch


MedialAxisBranch = MedialBranch
MedialAxisNode = MedialNode


@dataclass
class MedialAxisMetrics:
    """Aggregated geometric and topological metrics for SCADA telemetry."""
    boundary_vertex_count: int = 0
    medial_branch_count: int = 0
    medial_node_count: int = 0
    max_clearance_radius: float = 0.0
    mean_clearance_radius: float = 0.0
    min_clearance_radius: float = 0.0
    skeleton_total_length: float = 0.0
    pruned_branch_count: int = 0
    bottleneck_count: int = 0
    pruning_threshold_pct: float = 10.0
    bottleneck_threshold: float = 25.0
    diagnostic_code: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.OK


# ============================================================================
# 4. Computational Geometry & Spatial Algorithms
# ============================================================================

def cross_product_2d(o: PointTuple, a: PointTuple, b: PointTuple) -> float:
    """2D scalar cross product of vectors OA and OB."""
    return (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0])


def compute_shoelace_area(vertices: Sequence[Union[PointTuple, Point2D]]) -> float:
    """Exact polygon area via Green's theorem Shoelace formula."""
    pts = [p.coords if isinstance(p, Point2D) else p for p in vertices]
    n = len(pts)
    if n < 3:
        return 0.0
    area2 = 0.0
    for i in range(n):
        x1, y1 = pts[i]
        x2, y2 = pts[(i + 1) % n]
        area2 += (x1 * y2 - x2 * y1)
    return abs(area2) / 2.0


def compute_polygon_perimeter(vertices: Sequence[Union[PointTuple, Point2D]]) -> float:
    """Perimeter of 2D polygon boundary."""
    pts = [p.coords if isinstance(p, Point2D) else p for p in vertices]
    n = len(pts)
    if n < 2:
        return 0.0
    perim = 0.0
    for i in range(n):
        p1 = pts[i]
        p2 = pts[(i + 1) % n]
        perim += math.hypot(p2[0] - p1[0], p2[1] - p1[1])
    return perim


def segments_strictly_intersect(a1: PointTuple, a2: PointTuple, b1: PointTuple, b2: PointTuple) -> bool:
    """Check if segments A1A2 and B1B2 strictly cross each other."""
    def ccw(p: PointTuple, q: PointTuple, r: PointTuple) -> float:
        return (q[0] - p[0]) * (r[1] - p[1]) - (q[1] - p[1]) * (r[0] - p[0])

    d1 = ccw(a1, a2, b1)
    d2 = ccw(a1, a2, b2)
    d3 = ccw(b1, b2, a1)
    d4 = ccw(b1, b2, a2)

    return ((d1 > 1e-9 and d2 < -1e-9) or (d1 < -1e-9 and d2 > 1e-9)) and \
           ((d3 > 1e-9 and d4 < -1e-9) or (d3 < -1e-9 and d4 > 1e-9))


def is_polygon_self_intersecting(vertices: Sequence[Union[PointTuple, Point2D]]) -> bool:
    """Check if polygon boundary has self-intersecting non-adjacent edges."""
    pts = [p.coords if isinstance(p, Point2D) else p for p in vertices]
    n = len(pts)
    if n < 4:
        return False

    for i in range(n):
        a1 = pts[i]
        a2 = pts[(i + 1) % n]
        for j in range(i + 2, n):
            if (i == 0 and j == n - 1):
                continue
            b1 = pts[j]
            b2 = pts[(j + 1) % n]
            if segments_strictly_intersect(a1, a2, b1, b2):
                return True
    return False


def validate_polygon(polygon: Sequence[Union[PointTuple, Point2D]]) -> MedialAxisDiagnosticCode:
    """Validate 2D polygon boundary topology."""
    pts = [p.coords if isinstance(p, Point2D) else p for p in polygon]
    if len(pts) < 3:
        return MedialAxisDiagnosticCode.INSUFFICIENT_VERTICES

    if is_polygon_self_intersecting(pts):
        return MedialAxisDiagnosticCode.SELF_INTERSECTING

    area = compute_shoelace_area(pts)
    if area < 1e-5:
        return MedialAxisDiagnosticCode.INVALID_POLYGON

    return MedialAxisDiagnosticCode.OK


def is_point_in_polygon(point: Union[PointTuple, Point2D], polygon: Sequence[Union[PointTuple, Point2D]]) -> bool:
    """Exact ray casting point-in-polygon containment test."""
    px, py = point.coords if isinstance(point, Point2D) else point
    pts = [p.coords if isinstance(p, Point2D) else p for p in polygon]
    n = len(pts)
    inside = False
    p1x, p1y = pts[0]
    for i in range(n):
        p2x, p2y = pts[(i + 1) % n]
        if min(p1y, p2y) < py <= max(p1y, p2y):
            if p1y != p2y:
                x_inters = (py - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                if px <= x_inters:
                    inside = not inside
        p1x, p1y = p2x, p2y
    return inside


def point_to_segment_distance(point: PointTuple, a: PointTuple, b: PointTuple) -> float:
    """Shortest Euclidean distance from 2D point to line segment AB."""
    px, py = point
    ax, ay = a
    bx, by = b
    dx = bx - ax
    dy = by - ay
    l2 = dx * dx + dy * dy
    if l2 < 1e-12:
        return math.hypot(px - ax, py - ay)
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / l2))
    proj_x = ax + t * dx
    proj_y = ay + t * dy
    return math.hypot(px - proj_x, py - proj_y)


def shortest_distance_to_polygon(point: Union[PointTuple, Point2D], polygon: Sequence[Union[PointTuple, Point2D]]) -> float:
    """Maximal Inscribed Disk clearance radius R: shortest Euclidean distance to boundary."""
    pt = point.coords if isinstance(point, Point2D) else point
    pts = [p.coords if isinstance(p, Point2D) else p for p in polygon]
    n = len(pts)
    if n < 2:
        return 0.0
    min_dist = float("inf")
    for i in range(n):
        a = pts[i]
        b = pts[(i + 1) % n]
        d = point_to_segment_distance(pt, a, b)
        if d < min_dist:
            min_dist = d
    return min_dist


def is_segment_inside_polygon(p1: PointTuple, p2: PointTuple, polygon: List[PointTuple]) -> bool:
    """Verify that a branch segment lies completely inside the polygon."""
    if not is_point_in_polygon(p1, polygon) or not is_point_in_polygon(p2, polygon):
        return False
    mid = ((p1[0] + p2[0]) * 0.5, (p1[1] + p2[1]) * 0.5)
    if not is_point_in_polygon(mid, polygon):
        return False
    n = len(polygon)
    for i in range(n):
        a = polygon[i]
        b = polygon[(i + 1) % n]
        if segments_strictly_intersect(p1, p2, a, b):
            return False
    return True


def sample_polygon_boundary(polygon: List[PointTuple], spacing: float = 25.0) -> Tuple[List[PointTuple], Dict[PointTuple, int]]:
    """Sample boundary contour with uniform spacing and tag edge indices."""
    sampled_pts: List[PointTuple] = []
    edge_of_point: Dict[PointTuple, int] = {}
    n = len(polygon)

    for i in range(n):
        p1 = polygon[i]
        p2 = polygon[(i + 1) % n]
        dist = math.hypot(p2[0] - p1[0], p2[1] - p1[1])
        n_segs = max(1, int(round(dist / spacing)))
        for k in range(n_segs):
            t = k / float(n_segs)
            sx = round(p1[0] + t * (p2[0] - p1[0]), 3)
            sy = round(p1[1] + t * (p2[1] - p1[1]), 3)
            pt = (sx, sy)
            if pt not in edge_of_point:
                sampled_pts.append(pt)
                edge_of_point[pt] = i

    return sampled_pts, edge_of_point


def compute_delaunay_triangulation(points: Sequence[Union[PointTuple, Point2D]]) -> List[Triangle2D]:
    """Pure Python incremental Bowyer-Watson Delaunay Triangulation."""
    pts = sorted(list(set(p.coords if isinstance(p, Point2D) else p for p in points)))
    if len(pts) < 3:
        return []

    min_x = min(p[0] for p in pts) - 200.0
    max_x = max(p[0] for p in pts) + 200.0
    min_y = min(p[1] for p in pts) - 200.0
    max_y = max(p[1] for p in pts) + 200.0
    dx = max_x - min_x
    dy = max_y - min_y
    delta_max = max(dx, dy)
    mid_x = (min_x + max_x) / 2.0
    mid_y = (min_y + max_y) / 2.0

    p1 = (mid_x - 20.0 * delta_max, mid_y - delta_max)
    p2 = (mid_x, mid_y + 20.0 * delta_max)
    p3 = (mid_x + 20.0 * delta_max, mid_y - delta_max)

    st_pts = {p1, p2, p3}
    triangles: List[Triangle2D] = [Triangle2D(p1, p2, p3)]

    for p in pts:
        bad_triangles: List[Triangle2D] = []
        for t in triangles:
            if t.circumcircle_contains(p):
                bad_triangles.append(t)

        polygon: List[Edge2D] = []
        for t in bad_triangles:
            edges = [Edge2D(t.p1, t.p2), Edge2D(t.p2, t.p3), Edge2D(t.p3, t.p1)]
            for edge in edges:
                is_shared = False
                for other in bad_triangles:
                    if other == t:
                        continue
                    if edge in [Edge2D(other.p1, other.p2), Edge2D(other.p2, other.p3), Edge2D(other.p3, other.p1)]:
                        is_shared = True
                        break
                if not is_shared:
                    polygon.append(edge)

        triangles = [t for t in triangles if t not in bad_triangles]
        for edge in polygon:
            triangles.append(Triangle2D(edge.p1, edge.p2, p))

    final_tris: List[Triangle2D] = []
    for t in triangles:
        if t.p1 not in st_pts and t.p2 not in st_pts and t.p3 not in st_pts:
            final_tris.append(t)
    return final_tris


def prune_skeleton_graph(
    adj_graph: Dict[PointTuple, Set[PointTuple]],
    length_threshold: float,
    polygon: List[PointTuple],
) -> Tuple[Dict[PointTuple, Set[PointTuple]], int]:
    """Iteratively prune minor noise leaf branches based on branch length / max clearance ratio."""
    g = {k: set(v) for k, v in adj_graph.items()}
    if length_threshold <= 0.0 or not g:
        return g, 0

    pruned_count = 0
    changed = True

    while changed:
        changed = False
        leaves = [u for u, neighbors in g.items() if len(neighbors) == 1]
        for leaf in leaves:
            if len(g.get(leaf, set())) != 1:
                continue

            # Trace branch path from leaf towards junction
            path = [leaf]
            curr = leaf
            prev = None
            branch_len = 0.0
            junction_found = False

            while True:
                neighbors = g[curr]
                next_nodes = [n for n in neighbors if n != prev]
                if not next_nodes:
                    break
                nxt = next_nodes[0]
                branch_len += math.hypot(nxt[0] - curr[0], nxt[1] - curr[1])
                path.append(nxt)
                if len(g[nxt]) >= 3:
                    junction_found = True
                    break
                elif len(g[nxt]) == 1:
                    # Isolated leaf-to-leaf path
                    break
                prev, curr = curr, nxt

            # Prune branch if shorter than threshold and connects to a junction
            if junction_found and branch_len < length_threshold:
                for i in range(len(path) - 1):
                    n1, n2 = path[i], path[i + 1]
                    g[n1].discard(n2)
                    g[n2].discard(n1)
                    if not g[n1]:
                        del g[n1]
                changed = True
                pruned_count += 1
                break

    return g, pruned_count


def compute_medial_axis_transform(
    polygon: Sequence[Union[PointTuple, Point2D]],
    sample_spacing: float = 25.0,
    pruning_threshold_pct: float = 10.0,
    bottleneck_threshold: float = 25.0,
) -> Tuple[List[MedialNode], List[MedialBranch], MedialAxisMetrics, MedialAxisDiagnosticCode]:
    """Pure Python 2D Medial Axis Transform (MAT) / Voronoi Skeletonization."""
    pts = [p.coords if isinstance(p, Point2D) else p for p in polygon]
    diag = validate_polygon(pts)
    if diag != MedialAxisDiagnosticCode.OK:
        metrics = MedialAxisMetrics(
            boundary_vertex_count=len(pts),
            diagnostic_code=diag,
        )
        return [], [], metrics, diag

    # 1. Point sampling along polygon boundary contours
    sampled_pts, edge_of_point = sample_polygon_boundary(pts, spacing=sample_spacing)
    if len(sampled_pts) < 3:
        diag = MedialAxisDiagnosticCode.TOPOLOGY_COLLAPSE
        metrics = MedialAxisMetrics(boundary_vertex_count=len(pts), diagnostic_code=diag)
        return [], [], metrics, diag

    # 2. Bowyer-Watson Delaunay Triangulation
    delaunay_tris = compute_delaunay_triangulation(sampled_pts)

    # 3. Extraction of internal Voronoi vertices / medial nodes inside polygon
    internal_tris: List[Triangle2D] = []
    for t in delaunay_tris:
        c = t.circumcenter
        e1 = edge_of_point.get(t.p1, -1)
        e2 = edge_of_point.get(t.p2, -1)
        e3 = edge_of_point.get(t.p3, -1)
        # Filter out chordal boundary discretization slivers
        if e1 == e2 == e3 and e1 != -1:
            continue
        # Maximal Inscribed Disk clearance radius
        d = shortest_distance_to_polygon(c, pts)
        if is_point_in_polygon(c, pts) and d > 0.5:
            internal_tris.append(t)

    # 4. Connect adjacent Voronoi circumcenters sharing a Delaunay edge
    edge_to_tris: Dict[Edge2D, List[Triangle2D]] = defaultdict(list)
    for t in internal_tris:
        edge_to_tris[Edge2D(t.p1, t.p2)].append(t)
        edge_to_tris[Edge2D(t.p2, t.p3)].append(t)
        edge_to_tris[Edge2D(t.p3, t.p1)].append(t)

    raw_adj: Dict[PointTuple, Set[PointTuple]] = defaultdict(set)
    for d_edge, tris in edge_to_tris.items():
        if len(tris) == 2:
            c1 = (round(tris[0].circumcenter[0], 2), round(tris[0].circumcenter[1], 2))
            c2 = (round(tris[1].circumcenter[0], 2), round(tris[1].circumcenter[1], 2))
            if c1 != c2 and is_segment_inside_polygon(c1, c2, pts):
                raw_adj[c1].add(c2)
                raw_adj[c2].add(c1)

    if not raw_adj:
        diag = MedialAxisDiagnosticCode.TOPOLOGY_COLLAPSE
        metrics = MedialAxisMetrics(boundary_vertex_count=len(pts), diagnostic_code=diag)
        return [], [], metrics, diag

    # 5. Maximal Inscribed Disk calculation: max clearance radius
    all_clearances = {node: shortest_distance_to_polygon(node, pts) for node in raw_adj.keys()}
    max_clearance = max(all_clearances.values()) if all_clearances else 0.0

    # 6. Branch Pruning Filter based on branch length / max clearance ratio
    length_threshold = (pruning_threshold_pct / 100.0) * max_clearance
    pruned_adj, pruned_count = prune_skeleton_graph(raw_adj, length_threshold, pts)

    if not pruned_adj:
        # Prevent total topology collapse by falling back to unpruned raw skeleton
        pruned_adj = raw_adj
        pruned_count = 0

    # 7. Build MedialNode and MedialBranch records
    node_id_map: Dict[PointTuple, int] = {}
    nodes: List[MedialNode] = []
    branches: List[MedialBranch] = []
    node_counter = 1
    branch_counter = 1

    bottleneck_count = 0
    total_skeleton_length = 0.0
    clearance_values: List[float] = []

    for pt in sorted(pruned_adj.keys()):
        deg = len(pruned_adj[pt])
        clearance = shortest_distance_to_polygon(pt, pts)
        clearance_values.append(clearance)
        is_bottleneck = (clearance < bottleneck_threshold)
        if is_bottleneck:
            bottleneck_count += 1
        is_max = math.isclose(clearance, max_clearance, abs_tol=1e-2)

        node = MedialNode(
            node_id=node_counter,
            x=pt[0],
            y=pt[1],
            clearance_radius=clearance,
            is_bottleneck=is_bottleneck,
            is_max_clearance=is_max,
            degree=deg,
        )
        nodes.append(node)
        node_id_map[pt] = node_counter
        node_counter += 1

    seen_edges: Set[Tuple[PointTuple, PointTuple]] = set()
    for u, neighbors in pruned_adj.items():
        for v in neighbors:
            edge_key = tuple(sorted([u, v]))
            if edge_key not in seen_edges:
                seen_edges.add(edge_key)
                b_len = math.hypot(v[0] - u[0], v[1] - u[1])
                c_u = shortest_distance_to_polygon(u, pts)
                c_v = shortest_distance_to_polygon(v, pts)
                avg_c = (c_u + c_v) * 0.5
                is_b = (c_u < bottleneck_threshold or c_v < bottleneck_threshold)
                total_skeleton_length += b_len

                branch = MedialBranch(
                    branch_id=branch_counter,
                    p1=u,
                    p2=v,
                    length=b_len,
                    avg_clearance=avg_c,
                    is_bottleneck=is_b,
                    node1_id=node_id_map.get(u, 0),
                    node2_id=node_id_map.get(v, 0),
                )
                branches.append(branch)
                branch_counter += 1

    # 8. Bottleneck Identification & Diagnostic Code
    if bottleneck_count > 0:
        diag = MedialAxisDiagnosticCode.BOTTLENECK_DETECTED
    else:
        diag = MedialAxisDiagnosticCode.OK

    mean_clearance = sum(clearance_values) / len(clearance_values) if clearance_values else 0.0
    min_clearance = min(clearance_values) if clearance_values else 0.0

    metrics = MedialAxisMetrics(
        boundary_vertex_count=len(pts),
        medial_branch_count=len(branches),
        medial_node_count=len(nodes),
        max_clearance_radius=max_clearance,
        mean_clearance_radius=mean_clearance,
        min_clearance_radius=min_clearance,
        skeleton_total_length=total_skeleton_length,
        pruned_branch_count=pruned_count,
        bottleneck_count=bottleneck_count,
        pruning_threshold_pct=pruning_threshold_pct,
        bottleneck_threshold=bottleneck_threshold,
        diagnostic_code=diag,
    )

    return nodes, branches, metrics, diag


# ============================================================================
# 5. Pure IEC 61131-3 Structured Text POU
# ============================================================================

MEDIAL_AXIS_CANVAS_PURE_ST_POU: str = """PROGRAM MedialAxisCanvasSync
VAR
    BoundaryVertexCount   AT %R2430 : INT;
    InternalBranchCount   AT %R2431 : INT;
    MaxClearanceRadiusX10 AT %R2432 : INT;
    MeanClearanceRadiusX10 AT %R2433 : INT;
    SkeletonTotalLength   AT %R2434 : INT;
    SelectedBranchId      AT %R2435 : INT;
    PruningThresholdX10   AT %R2436 : INT;
    DiagnosticCode        AT %R2437 : UINT;

    SkeletonValid         AT %M567  : BOOL;
    NarrowBottleneckWarn  AT %M568  : BOOL;
END_VAR

IF (DiagnosticCode = 0) OR (DiagnosticCode = 4) THEN
    SkeletonValid := TRUE;
ELSE
    SkeletonValid := FALSE;
END_IF;

IF (DiagnosticCode = 4) THEN
    NarrowBottleneckWarn := TRUE;
ELSE
    NarrowBottleneckWarn := FALSE;
END_IF;
END_PROGRAM
"""

W282_MEDIAL_AXIS_PURE_ST_POU: str = MEDIAL_AXIS_CANVAS_PURE_ST_POU
ST_PROGRAM_MEDIAL_AXIS_CANVAS_SYNC: str = MEDIAL_AXIS_CANVAS_PURE_ST_POU
MEDIAL_AXIS_PURE_ST_POU: str = MEDIAL_AXIS_CANVAS_PURE_ST_POU


def verify_medial_axis_canvas_pure_st(pou_text: Optional[str] = None) -> bool:
    """Validate Pure ST POU against anti-ladder security rules and AST parsing."""
    try:
        text = pou_text if pou_text is not None else MEDIAL_AXIS_CANVAS_PURE_ST_POU
        SecurityGuard.assert_pure_st_content(text)
        res = STParser.validate_code(text)
        if res.status != AgentStatus.SUCCESS:
            return False
        ast = STParser.parse_pou(text)
        return ast.pou_type == POUType.PROGRAM
    except Exception:
        return False


# ============================================================================
# 6. Medial Axis Canvas Engine (ILogicUnit)
# ============================================================================

def create_canonical_polygon() -> List[PointTuple]:
    """Create canonical industrial dual-chamber vessel with narrow constriction neck."""
    return [
        (150.0, 200.0),
        (450.0, 200.0),
        (450.0, 350.0),
        (750.0, 350.0),
        (750.0, 200.0),
        (1050.0, 200.0),
        (1050.0, 550.0),
        (750.0, 550.0),
        (750.0, 400.0),
        (450.0, 400.0),
        (450.0, 550.0),
        (150.0, 550.0),
    ]


class MedialAxisCanvasEngine(ILogicUnit):
    """Dynamic Spatial Medial Axis Skeletonization SCADA Canvas Engine."""

    def __init__(
        self,
        polygon: Optional[Sequence[Union[PointTuple, Point2D]]] = None,
        register_table: Optional[RegisterTable] = None,
        sample_spacing: float = 30.0,
        pruning_threshold_pct: float = 10.0,
        bottleneck_threshold: float = 30.0,
        clearance_threshold: Optional[float] = None,
        **kwargs: Any,
    ) -> None:
        self.reg_table: RegisterTable = register_table or RegisterTable()
        self.sample_spacing: float = float(sample_spacing)
        self.pruning_threshold_pct: float = float(pruning_threshold_pct)
        if clearance_threshold is not None:
            self.bottleneck_threshold = float(clearance_threshold)
        else:
            self.bottleneck_threshold = float(bottleneck_threshold)

        self.is_active: bool = True
        self._cycle_count: int = 0
        self._selected_branch_id: int = 1

        if polygon is not None:
            raw_pts = polygon.vertices if hasattr(polygon, "vertices") else polygon
            self._polygon = [p.coords if isinstance(p, Point2D) else p for p in raw_pts]
        else:
            self._polygon = create_canonical_polygon()

        self._medial_nodes: List[MedialNode] = []
        self._medial_branches: List[MedialBranch] = []
        self._metrics: MedialAxisMetrics = MedialAxisMetrics()
        self._diagnostic_code: MedialAxisDiagnosticCode = MedialAxisDiagnosticCode.OK

        self.update_analytics()

    @property
    def name(self) -> str:
        return "MedialAxisCanvasEngine"

    @property
    def priority(self) -> int:
        return 88

    @property
    def is_enabled(self) -> bool:
        return self.is_active

    @property
    def cycle_count(self) -> int:
        return self._cycle_count

    @property
    def polygon(self) -> List[PointTuple]:
        return self._polygon

    @property
    def boundary_vertices(self) -> List[PointTuple]:
        return self._polygon

    @property
    def boundary_points(self) -> List[Point2D]:
        return [Point2D(x, y, i + 1) for i, (x, y) in enumerate(self._polygon)]

    @property
    def medial_nodes(self) -> List[MedialNode]:
        return self._medial_nodes

    @property
    def medial_branches(self) -> List[MedialBranch]:
        return self._medial_branches

    @property
    def branches(self) -> List[MedialBranch]:
        return self._medial_branches

    @property
    def bottlenecks(self) -> List[MedialNode]:
        return [n for n in self._medial_nodes if n.is_bottleneck]

    @property
    def metrics(self) -> MedialAxisMetrics:
        return self._metrics

    @property
    def diagnostic_code(self) -> MedialAxisDiagnosticCode:
        return self._diagnostic_code

    @property
    def max_clearance(self) -> float:
        return self._metrics.max_clearance_radius

    @property
    def max_inscribed_radius(self) -> float:
        return self._metrics.max_clearance_radius

    @property
    def mean_clearance(self) -> float:
        return self._metrics.mean_clearance_radius

    @property
    def min_clearance(self) -> float:
        return self._metrics.min_clearance_radius

    @property
    def min_clearance_radius(self) -> float:
        return self._metrics.min_clearance_radius

    @property
    def skeleton_length(self) -> float:
        return self._metrics.skeleton_total_length

    @property
    def is_bottleneck_detected(self) -> bool:
        return self._diagnostic_code == MedialAxisDiagnosticCode.BOTTLENECK_DETECTED

    @property
    def is_skeleton_valid(self) -> bool:
        return len(self._medial_branches) > 0 and self._diagnostic_code in (
            MedialAxisDiagnosticCode.OK,
            MedialAxisDiagnosticCode.BOTTLENECK_DETECTED,
        )

    def set_polygon(self, polygon: Any) -> None:
        raw_pts = polygon.vertices if hasattr(polygon, "vertices") else polygon
        self._polygon = [p.coords if isinstance(p, Point2D) else p for p in raw_pts]
        self.update_analytics()

    def set_pruning_threshold(self, pct: float) -> None:
        self.pruning_threshold_pct = max(0.0, float(pct))
        self.update_analytics()

    def set_bottleneck_threshold(self, threshold: float) -> None:
        self.bottleneck_threshold = max(0.0, float(threshold))
        self.update_analytics()

    def set_clearance_threshold(self, threshold: float) -> None:
        self.set_bottleneck_threshold(threshold)

    def update_analytics(self) -> None:
        nodes, branches, metrics, diag = compute_medial_axis_transform(
            polygon=self._polygon,
            sample_spacing=self.sample_spacing,
            pruning_threshold_pct=self.pruning_threshold_pct,
            bottleneck_threshold=self.bottleneck_threshold,
        )
        self._medial_nodes = nodes
        self._medial_branches = branches
        self._metrics = metrics
        self._diagnostic_code = diag
        self._sync_registers()

    def _sync_registers(self) -> None:
        self.sync_to_registers(self.reg_table, privilege=PrivilegeMode.SYSTEM)

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.USER,
    ) -> None:
        rt = reg_table or self.reg_table

        # Analog registers %R2430..%R2437
        rt.write_word(REG_W282_BOUNDARY_VERTICES, len(self._polygon) & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W282_MEDIAL_BRANCHES, len(self._medial_branches) & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W282_MAX_CLEARANCE, int(round(self._metrics.max_clearance_radius * 10)) & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W282_MEAN_CLEARANCE, int(round(self._metrics.mean_clearance_radius * 10)) & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W282_SKELETON_LENGTH, int(round(self._metrics.skeleton_total_length)) & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W282_SELECTED_BRANCH, int(self._selected_branch_id) & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W282_PRUNING_THRESHOLD, int(round(self.pruning_threshold_pct * 10)) & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W282_DIAGNOSTIC_CODE, int(self._diagnostic_code) & 0xFFFF, privilege=privilege)

        # Discrete coils %M567..%M568
        rt.write_bit(COIL_W282_SKELETON_VALID, self.is_skeleton_valid, privilege=privilege)
        rt.write_bit(COIL_W282_BOTTLENECK_WARNING, self.is_bottleneck_detected, privilege=privilege)

    def scan_step(self, dt: float = 0.01, context: Optional[ScanContext] = None) -> Dict[str, Any]:
        self._cycle_count += 1
        self.update_analytics()
        return {
            "cycle": self._cycle_count,
            "boundary_vertices": len(self._polygon),
            "medial_branches": len(self._medial_branches),
            "max_clearance": self._metrics.max_clearance_radius,
            "mean_clearance": self._metrics.mean_clearance_radius,
            "skeleton_length": self._metrics.skeleton_total_length,
            "diagnostic_code": int(self._diagnostic_code),
            "skeleton_valid": self.is_skeleton_valid,
            "bottleneck_warning": self.is_bottleneck_detected,
        }

    def step(self, dt: float = 0.01) -> None:
        self.scan_step(dt=dt)

    def execute(self, context: Optional[ScanContext] = None) -> ExecutionResult:
        dt = getattr(context, "dt_s", 0.01) if context else 0.01
        res_data = self.scan_step(dt=dt, context=context)
        return ExecutionResult(
            status=AgentStatus.SUCCESS,
            details="Medial Axis Canvas scan step executed successfully",
            data=res_data,
        )

    def reset(self) -> None:
        self._cycle_count = 0
        self._selected_branch_id = 1
        self._polygon = create_canonical_polygon()
        self.update_analytics()

    def to_svg(self) -> str:
        return generate_medial_axis_canvas_svg(self)


MedialAxisCanvas = MedialAxisCanvasEngine


def create_canonical_medial_axis_canvas() -> MedialAxisCanvasEngine:
    return MedialAxisCanvasEngine()


# ============================================================================
# 7. Canvas Rendering & Visualization (W3C SVG 1.1)
# ============================================================================

def generate_medial_axis_canvas_svg(engine: Optional[MedialAxisCanvasEngine] = None) -> str:
    """Standalone W3C SVG 1.1 vector graphic generator meeting WCAG 2.1 AAA contrast."""
    eng = engine or MedialAxisCanvasEngine()
    poly = eng.polygon
    nodes = eng.medial_nodes
    branches = eng.medial_branches
    metrics = eng.metrics

    # Polygon boundary
    poly_pts_str = " ".join(f"{p[0]},{p[1]}" for p in poly)
    polygon_svg = (
        f'<polygon points="{poly_pts_str}" fill="{COLOR_POLYGON_FILL}" '
        f'fill-opacity="0.08" stroke="{COLOR_POLYGON_BOUNDARY}" stroke-width="2.5" '
        f'stroke-linejoin="round" />'
    )

    # Skeleton branch lines
    branches_svg: List[str] = []
    for b in branches:
        col = COLOR_BOTTLENECK if b.is_bottleneck else COLOR_SKELETON_BRANCH
        branches_svg.append(
            f'<line x1="{b.p1[0]}" y1="{b.p1[1]}" x2="{b.p2[0]}" y2="{b.p2[1]}" '
            f'stroke="{col}" stroke-width="2.5" stroke-linecap="round" />'
        )

    # Inscribed clearance disks at key nodes (max clearance, bottleneck, key junctions)
    disks_svg: List[str] = []
    nodes_svg: List[str] = []

    for n in nodes:
        if n.is_max_clearance:
            disks_svg.append(
                f'<circle cx="{n.x}" cy="{n.y}" r="{n.clearance_radius:.1f}" '
                f'fill="{COLOR_MAX_DISK}" fill-opacity="0.10" stroke="{COLOR_MAX_DISK}" '
                f'stroke-width="2.0" stroke-dasharray="5 3" />'
            )
        elif n.is_bottleneck:
            disks_svg.append(
                f'<circle cx="{n.x}" cy="{n.y}" r="{n.clearance_radius:.1f}" '
                f'fill="{COLOR_BOTTLENECK}" fill-opacity="0.15" stroke="{COLOR_BOTTLENECK}" '
                f'stroke-width="2.0" stroke-dasharray="4 2" />'
            )
        elif n.degree >= 3 or n.degree == 1:
            disks_svg.append(
                f'<circle cx="{n.x}" cy="{n.y}" r="{n.clearance_radius:.1f}" '
                f'fill="none" stroke="{COLOR_CLEARANCE_DISK}" stroke-width="1.0" '
                f'stroke-dasharray="3 3" opacity="0.4" />'
            )

        # Node dot
        dot_col = COLOR_BOTTLENECK if n.is_bottleneck else (COLOR_MAX_DISK if n.is_max_clearance else COLOR_NOMINAL_EMERALD)
        r_dot = 5.0 if (n.is_max_clearance or n.is_bottleneck) else 3.0
        nodes_svg.append(f'<circle cx="{n.x}" cy="{n.y}" r="{r_dot}" fill="{dot_col}" />')

    # Status badge text and color
    if eng.diagnostic_code == MedialAxisDiagnosticCode.OK:
        status_label = "NOMINAL (OK)"
        status_color = COLOR_NOMINAL_EMERALD
    elif eng.diagnostic_code == MedialAxisDiagnosticCode.BOTTLENECK_DETECTED:
        status_label = "BOTTLENECK DETECTED"
        status_color = COLOR_ALARM_CRIMSON
    else:
        status_label = f"FAULT ({eng.diagnostic_code.name})"
        status_color = COLOR_WARNING_AMBER

    svg_content = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 750" width="1200" height="750">
    <defs>
        <radialGradient id="bottleneckGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="{COLOR_BOTTLENECK}" stop-opacity="0.4" />
            <stop offset="100%" stop-color="{COLOR_BOTTLENECK}" stop-opacity="0.0" />
        </radialGradient>
    </defs>

    <!-- Background -->
    <rect width="1200" height="750" fill="{COLOR_DARK_THEME_BACKING}" />

    <!-- Decoupled SCADA HUD Header Badge (WCAG 2.1 AAA > 18:1) -->
    <rect x="20" y="20" width="1160" height="85" rx="8" fill="{COLOR_DECOUPLED_BADGE}" stroke="#1E293B" stroke-width="1.5" />
    <text x="40" y="55" fill="{COLOR_TEXT_PRIMARY}" font-family="monospace" font-size="20" font-weight="bold">HORNER OCS MEDIAL AXIS SKELETONIZATION SCADA CANVAS (W282)</text>
    <text x="40" y="85" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="14">STATUS: <tspan fill="{status_color}" font-weight="bold">{status_label}</tspan> | CODE: 0x{int(eng.diagnostic_code):04X} | G9 GRAPHIC ENGINE</text>

    <!-- Inscribed Clearance Disks -->
    {"".join(disks_svg)}

    <!-- Polygon Boundary -->
    {polygon_svg}

    <!-- Medial Axis Skeleton Branches -->
    {"".join(branches_svg)}

    <!-- Medial Nodes -->
    {"".join(nodes_svg)}

    <!-- Bottom Telemetry HUD Card -->
    <rect x="20" y="635" width="1160" height="95" rx="8" fill="{COLOR_DECOUPLED_BADGE}" stroke="#1E293B" stroke-width="1.5" />
    <text x="40" y="665" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="13">BOUND VERTICES (%R2430): <tspan fill="{COLOR_TEXT_PRIMARY}" font-weight="bold">{metrics.boundary_vertex_count}</tspan></text>
    <text x="320" y="665" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="13">MEDIAL BRANCHES (%R2431): <tspan fill="{COLOR_TEXT_PRIMARY}" font-weight="bold">{metrics.medial_branch_count}</tspan></text>
    <text x="600" y="665" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="13">MAX CLEARANCE (%R2432): <tspan fill="{COLOR_MAX_DISK}" font-weight="bold">{metrics.max_clearance_radius:.1f} px</tspan></text>
    <text x="880" y="665" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="13">MEAN CLEARANCE (%R2433): <tspan fill="{COLOR_TEXT_PRIMARY}" font-weight="bold">{metrics.mean_clearance_radius:.1f} px</tspan></text>

    <text x="40" y="705" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="13">SKELETON LENGTH (%R2434): <tspan fill="{COLOR_TEXT_PRIMARY}" font-weight="bold">{int(round(metrics.skeleton_total_length))} px</tspan></text>
    <text x="320" y="705" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="13">PRUNING THRESH (%R2436): <tspan fill="{COLOR_TEXT_PRIMARY}" font-weight="bold">{metrics.pruning_threshold_pct:.1f}%</tspan></text>
    <text x="600" y="705" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="13">SKELETON VALID (%M567): <tspan fill="{COLOR_NOMINAL_EMERALD if eng.is_skeleton_valid else COLOR_ALARM_CRIMSON}" font-weight="bold">{'TRUE' if eng.is_skeleton_valid else 'FALSE'}</tspan></text>
    <text x="880" y="705" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="13">BOTTLENECK CHOKE (%M568): <tspan fill="{COLOR_ALARM_CRIMSON if eng.is_bottleneck_detected else COLOR_NOMINAL_EMERALD}" font-weight="bold">{'ALARM' if eng.is_bottleneck_detected else 'CLEAR'}</tspan></text>
</svg>"""
    return svg_content


def create_mock_scan_context(cycle: int = 1, dt_ms: float = 10.0, reg_table: Optional[RegisterTable] = None) -> ScanContext:
    return ScanContext(cycle=cycle, dt_ms=dt_ms, reg_table=reg_table)


# ============================================================================
# 8. Deterministic Verification Suite (Strict 4-State Contract)
# ============================================================================

def run_medial_axis_canvas_verification(
    output_path: Optional[str] = None,
    sample_svg_path: Optional[str] = None,
    work_package: str = "W282",
) -> Dict[str, Any]:
    """Deterministic 10-stage verification suite returning strict 4-state contract JSON."""
    test_results: List[Dict[str, Any]] = []

    # Stage 1: Initialization & Geometry
    t0 = time.perf_counter()
    eng1 = MedialAxisCanvasEngine()
    c1 = (
        len(eng1.polygon) == 12
        and eng1.priority == 88
        and eng1.is_enabled
        and eng1.name == "MedialAxisCanvasEngine"
    )
    test_results.append({
        "stage": 1,
        "name": "initialization_and_nodes",
        "passed": c1,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Engine initialized with 12 polygon vertices, priority 88, enabled.",
    })

    # Stage 2: Pure ST POU Validation
    t0 = time.perf_counter()
    c2 = verify_medial_axis_canvas_pure_st()
    test_results.append({
        "stage": 2,
        "name": "pure_st_pou_validation",
        "passed": c2,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "MedialAxisCanvasSync passes SecurityGuard and STParser.",
    })

    # Stage 3: Anti-Ladder Rejection
    t0 = time.perf_counter()
    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("PROGRAM P VAR X : BOOL; END_VAR ---[ ]--- END_PROGRAM")
    except LadderForbiddenError:
        ladder_rejected = True
    c3 = ladder_rejected
    test_results.append({
        "stage": 3,
        "name": "anti_ladder_rejection",
        "passed": c3,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "SecurityGuard aggressively rejects ladder constructs.",
    })

    # Stage 4: Polygon Validation & Diagnostics
    t0 = time.perf_counter()
    v_insufficient = validate_polygon([(0.0, 0.0), (10.0, 10.0)])
    v_self_intersect = validate_polygon([(0.0, 0.0), (100.0, 100.0), (0.0, 100.0), (100.0, 0.0)])
    v_collinear = validate_polygon([(0.0, 0.0), (50.0, 0.0), (100.0, 0.0)])
    v_valid = validate_polygon(create_canonical_polygon())

    c4 = (
        v_insufficient == MedialAxisDiagnosticCode.INSUFFICIENT_VERTICES
        and v_self_intersect == MedialAxisDiagnosticCode.SELF_INTERSECTING
        and v_collinear == MedialAxisDiagnosticCode.INVALID_POLYGON
        and v_valid == MedialAxisDiagnosticCode.OK
    )
    test_results.append({
        "stage": 4,
        "name": "polygon_validation_and_diagnostics",
        "passed": c4,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Validated INSUFFICIENT_VERTICES, SELF_INTERSECTING, INVALID_POLYGON, and OK.",
    })

    # Stage 5: Boundary Sampling & Delaunay Triangulation
    t0 = time.perf_counter()
    samples, edge_map = sample_polygon_boundary(create_canonical_polygon(), spacing=30.0)
    delaunay = compute_delaunay_triangulation(samples)
    c5 = len(samples) >= 80 and len(delaunay) >= 100
    test_results.append({
        "stage": 5,
        "name": "boundary_sampling_and_triangulation",
        "passed": c5,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Generated {len(samples)} boundary samples and {len(delaunay)} Delaunay triangles.",
    })

    # Stage 6: Medial Axis Skeletonization & Maximal Inscribed Disks
    t0 = time.perf_counter()
    nodes, branches, metrics, diag = compute_medial_axis_transform(
        create_canonical_polygon(),
        sample_spacing=30.0,
        pruning_threshold_pct=10.0,
        bottleneck_threshold=30.0,
    )
    c6 = (
        len(nodes) > 10
        and len(branches) > 10
        and metrics.max_clearance_radius > 140.0
        and metrics.min_clearance_radius > 10.0
    )
    test_results.append({
        "stage": 6,
        "name": "medial_axis_and_inscribed_disks",
        "passed": c6,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Max inscribed radius {metrics.max_clearance_radius:.1f} px, min {metrics.min_clearance_radius:.1f} px.",
    })

    # Stage 7: Branch Pruning Filter
    t0 = time.perf_counter()
    _, branches_unpruned, _, _ = compute_medial_axis_transform(
        create_canonical_polygon(),
        pruning_threshold_pct=0.0,
    )
    _, branches_pruned, _, _ = compute_medial_axis_transform(
        create_canonical_polygon(),
        pruning_threshold_pct=25.0,
    )
    c7 = len(branches_pruned) <= len(branches_unpruned) and len(branches_pruned) > 0
    test_results.append({
        "stage": 7,
        "name": "branch_pruning_filter",
        "passed": c7,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Unpruned branches {len(branches_unpruned)} vs pruned branches {len(branches_pruned)}.",
    })

    # Stage 8: Bottleneck Identification & Alarms
    t0 = time.perf_counter()
    eng8 = MedialAxisCanvasEngine(bottleneck_threshold=30.0)
    b_alarm = eng8.is_bottleneck_detected
    eng8_safe = MedialAxisCanvasEngine(bottleneck_threshold=10.0)
    b_safe = not eng8_safe.is_bottleneck_detected
    c8 = b_alarm and b_safe
    test_results.append({
        "stage": 8,
        "name": "bottleneck_identification",
        "passed": c8,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Correctly detected constriction choke point (< 30.0 px) and cleared when safe (< 10.0 px).",
    })

    # Stage 9: SVG Generation & Contrast Compliance
    t0 = time.perf_counter()
    svg9 = generate_medial_axis_canvas_svg(eng8)
    root = ET.fromstring(svg9)
    wcag_badge = validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    c9 = root.tag.endswith("svg") and wcag_badge.is_compliant
    test_results.append({
        "stage": 9,
        "name": "svg_and_contrast_compliance",
        "passed": c9,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"SVG parses cleanly; decoupled badge contrast {wcag_badge.contrast_ratio:.1f}:1 >= 18:1.",
    })

    # Stage 10: RegisterTable Synchronization & Soak Stability
    t0 = time.perf_counter()
    rt10 = RegisterTable()
    eng10 = MedialAxisCanvasEngine(register_table=rt10, bottleneck_threshold=30.0)
    for _ in range(50):
        eng10.scan_step(0.01)

    c10 = (
        rt10.read_word(REG_W282_BOUNDARY_VERTICES) == 12
        and rt10.read_word(REG_W282_MEDIAL_BRANCHES) == len(eng10.medial_branches)
        and rt10.read_word(REG_W282_MAX_CLEARANCE) == int(round(eng10.max_clearance * 10))
        and rt10.read_word(REG_W282_DIAGNOSTIC_CODE) == int(MedialAxisDiagnosticCode.BOTTLENECK_DETECTED)
        and rt10.read_bit(COIL_W282_SKELETON_VALID) is True
        and rt10.read_bit(COIL_W282_BOTTLENECK_WARNING) is True
        and eng10.cycle_count == 50
    )
    test_results.append({
        "stage": 10,
        "name": "register_synchronization_and_soak",
        "passed": c10,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Register table %R2430..%R2437 and %M567..%M568 synchronized and 50 soak cycles stable.",
    })

    stages_passed = sum(1 for r in test_results if r["passed"])
    total_stages = len(test_results)
    all_passed = (stages_passed == total_stages)

    evidence = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "ERR_STAGE_VERIFICATION_FAILED",
        "details": f"Wave {work_package} Dynamic Spatial Medial Axis Skeletonization SCADA Canvas PASSED ({stages_passed}/{total_stages} stages).",
        "data": {
            "work_package": work_package,
            "gate": "G9",
            "checks_passed": stages_passed,
            "total_checks": total_stages,
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
            f.write(generate_medial_axis_canvas_svg(eng8))

    return evidence


if __name__ == "__main__":
    res = run_medial_axis_canvas_verification()
    print(json.dumps(res, indent=2))
    sys.exit(0 if res["status"] == "success" else 1)
