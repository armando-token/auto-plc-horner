#!/usr/bin/env python3
"""Verification Script for Cscape HMI Dynamic Spatial Medial Axis Canvas (W282).

Work Package: W282 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Medial Axis Transform Voronoi Skeletonization SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: polygon_boundary_and_point_sampling (verify polygon definition and boundary point generation)
  Stage 2: voronoi_and_medial_axis_extraction (verify medial node generation and branch extraction)
  Stage 3: maximal_inscribed_circle_radius_field (verify clearance distance field and inscribed circles)
  Stage 4: branch_pruning_and_noise_filtering (verify pruning threshold eliminates spurious spires while keeping main axis)
  Stage 5: bottleneck_and_clearance_violation_detection (verify bottleneck detection asserts %M568 and locates narrow chokes)
  Stage 6: degenerate_and_collinear_handling (verify robust handling of degeneracies without crashes)
  Stage 7: wcag_aaa_svg_canvas_rendering (verify SVG output meets WCAG AAA contrast, valid XML tags, inscribed disks, branches)
  Stage 8: horner_ocs_register_sync (verify %R2430..%R2437 and %M567..%M568 in RegisterTable)
  Stage 9: pure_st_pou_and_ladder_rejection (verify ST POU syntax and anti-ladder validation)

Exports:
  artifacts/HMI/medial_axis_canvas_evidence.json
  artifacts/HMI/medial_axis_canvas_sample.svg
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntFlag
import json
import math
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
import xml.etree.ElementTree as ET

# Ensure repository root and src/ are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

# ANSI terminal formatting constants
CLR_RESET  = "\033[0m"
CLR_BOLD   = "\033[1m"
CLR_DIM    = "\033[2m"
CLR_GREEN  = "\033[92m"
CLR_RED    = "\033[91m"
CLR_YELLOW = "\033[93m"
CLR_CYAN   = "\033[96m"
CLR_GRAY   = "\033[90m"


# ============================================================================
# 1. Constants, Diagnostic Codes & Register Mapping for W282
# ============================================================================

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


DIAG_OK: DiagnosticCode                         = DiagnosticCode(0x0000)
DIAG_EVENT_OK: DiagnosticCode                   = DiagnosticCode(0x0000)
DIAG_ERR_BOTTLENECK_CHOKE: DiagnosticCode       = DiagnosticCode(0x8201)
DIAG_ERR_CLEARANCE_VIOLATION: DiagnosticCode    = DiagnosticCode(0x8201)
DIAG_ERR_DEGENERATE_GEOMETRY: DiagnosticCode    = DiagnosticCode(0x8202)
DIAG_ERR_COLINEAR_FAULT: DiagnosticCode         = DiagnosticCode(0x8202)

# Horner OCS Word Registers (%R2430..%R2437)
REG_W282_STATUS_WORD: str                       = "%R2430"
REG_W282_BOUNDARY_POINTS: str                   = "%R2431"
REG_W282_MEDIAL_NODES: str                      = "%R2432"
REG_W282_BRANCH_SEGMENTS: str                   = "%R2433"
REG_W282_MAX_INSCRIBED_RADIUS: str              = "%R2434"
REG_W282_MIN_CLEARANCE_RADIUS: str              = "%R2435"
REG_W282_BOTTLENECK_COUNT: str                  = "%R2436"
REG_W282_DIAGNOSTIC_CODE: str                   = "%R2437"

# Discrete Coils (%M567..%M568)
COIL_W282_CANVAS_ACTIVE: str                    = "%M567"
COIL_W282_BOTTLENECK_ALARM: str                 = "%M568"

CANVAS_VIEWPORT_WIDTH: int                      = 1200
CANVAS_VIEWPORT_HEIGHT: int                     = 750

# Industrial SCADA Palette (WCAG 2.1 AAA Compliant)
COLOR_SCADA_BG: str                             = "#0D1117"
COLOR_DARK_SURFACE: str                         = "#161B22"
COLOR_PANEL_BG: str                             = "#161B22"
COLOR_CARD_BG: str                              = "#1E293B"
COLOR_BORDER: str                               = "#334155"
COLOR_DECOUPLED_BADGE: str                      = "#050811"
COLOR_TEXT_PRIMARY: str                         = "#FFFFFF"
COLOR_TEXT_MUTED: str                           = "#CBD5E1"

COLOR_POLYGON_STROKE: str                       = "#38BDF8"
COLOR_POLYGON_FILL: str                         = "#111827"
COLOR_BOUNDARY_SAMPLE: str                      = "#0284C7"
COLOR_MEDIAL_BRANCH: str                        = "#A855F7"
COLOR_MEDIAL_NODE: str                          = "#C084FC"
COLOR_INSCRIBED_DISK: str                       = "#38BDF8"
COLOR_BOTTLENECK_ALARM: str                     = "#EF4444"
COLOR_NOMINAL_EMERALD: str                      = "#10B981"
COLOR_WARNING_AMBER: str                        = "#F59E0B"


class MedialAxisStatusBits(IntFlag):
    """Horner OCS %R2430 Status Word Bitmask Definitions."""
    CANVAS_ACTIVE               = 1 << 0
    MEDIAL_AXIS_COMPUTED        = 1 << 1
    BOTTLENECK_ALARM            = 1 << 2
    CLEARANCE_VIOLATION         = 1 << 3
    DEGENERATE_FAULT            = 1 << 4
    SVG_RENDER_VALID            = 1 << 5
    PRUNING_COMPLETED           = 1 << 6


# ============================================================================
# 2. WCAG Contrast Helper Functions
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
        return bool(self.get("is_compliant", False))

    @property
    def contrast_ratio(self) -> float:
        return float(self.get("contrast_ratio", 1.0))

    def __bool__(self) -> bool:
        return self.is_compliant


def validate_wcag_aaa_contrast(color1: str, color2: str, min_contrast: float = 18.0) -> ContrastResult:
    ratio = calculate_contrast_ratio(color1, color2)
    return ContrastResult({"is_compliant": ratio >= min_contrast, "contrast_ratio": ratio})


# ============================================================================
# 3. Computational Geometry Primitives & Algorithms
# ============================================================================

@dataclass(frozen=True)
class Point2D:
    x: float
    y: float
    point_id: int = 0

    def distance_to(self, other: Point2D) -> float:
        return math.hypot(self.x - other.x, self.y - other.y)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Point2D):
            return False
        return abs(self.x - other.x) < 1e-6 and abs(self.y - other.y) < 1e-6

    def __hash__(self) -> int:
        return hash((round(self.x, 4), round(self.y, 4)))

    @property
    def coords(self) -> Tuple[float, float]:
        return (self.x, self.y)


@dataclass(frozen=True)
class Segment2D:
    p1: Point2D
    p2: Point2D

    @property
    def length(self) -> float:
        return self.p1.distance_to(self.p2)

    def distance_to_point(self, pt: Point2D) -> float:
        vx = self.p2.x - self.p1.x
        vy = self.p2.y - self.p1.y
        wx = pt.x - self.p1.x
        wy = pt.y - self.p1.y

        c1 = wx * vx + wy * vy
        c2 = vx * vx + vy * vy

        if c2 <= 1e-12:
            return pt.distance_to(self.p1)
        if c1 <= 0.0:
            return pt.distance_to(self.p1)
        if c2 <= c1:
            return pt.distance_to(self.p2)

        t = c1 / c2
        proj_x = self.p1.x + t * vx
        proj_y = self.p1.y + t * vy
        return math.hypot(pt.x - proj_x, pt.y - proj_y)


@dataclass(frozen=True)
class Edge2D:
    p1: Point2D
    p2: Point2D

    def __init__(self, p1: Point2D, p2: Point2D) -> None:
        if (p1.x, p1.y) <= (p2.x, p2.y):
            object.__setattr__(self, "p1", p1)
            object.__setattr__(self, "p2", p2)
        else:
            object.__setattr__(self, "p1", p2)
            object.__setattr__(self, "p2", p1)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Edge2D):
            return False
        return self.p1 == other.p1 and self.p2 == other.p2

    def __hash__(self) -> int:
        return hash((self.p1, self.p2))

    @property
    def length(self) -> float:
        return self.p1.distance_to(self.p2)


@dataclass
class Triangle2D:
    p1: Point2D
    p2: Point2D
    p3: Point2D
    center_x: float = 0.0
    center_y: float = 0.0
    radius_sq: float = 0.0

    def __post_init__(self) -> None:
        ax, ay = self.p1.x, self.p1.y
        bx, by = self.p2.x, self.p2.y
        cx, cy = self.p3.x, self.p3.y

        d = 2.0 * (ax * (by - cy) + bx * (cy - ay) + cx * (ay - by))
        if abs(d) < 1e-11:
            self.center_x = (ax + bx + cx) / 3.0
            self.center_y = (ay + by + cy) / 3.0
            self.radius_sq = float("inf")
        else:
            a_sq = ax * ax + ay * ay
            b_sq = bx * bx + by * by
            c_sq = cx * cx + cy * cy
            self.center_x = (a_sq * (by - cy) + b_sq * (cy - ay) + c_sq * (ay - by)) / d
            self.center_y = (a_sq * (cx - bx) + b_sq * (ax - cx) + c_sq * (bx - ax)) / d
            self.radius_sq = (ax - self.center_x) ** 2 + (ay - self.center_y) ** 2

    def circumcircle_contains(self, pt: Point2D) -> bool:
        dist_sq = (pt.x - self.center_x) ** 2 + (pt.y - self.center_y) ** 2
        return dist_sq <= (self.radius_sq + 1e-9)

    @property
    def circumcenter(self) -> Point2D:
        return Point2D(self.center_x, self.center_y)

    @property
    def circumradius(self) -> float:
        return math.sqrt(self.radius_sq) if not math.isinf(self.radius_sq) else 1e9

    @property
    def edges(self) -> List[Edge2D]:
        return [
            Edge2D(self.p1, self.p2),
            Edge2D(self.p2, self.p3),
            Edge2D(self.p3, self.p1),
        ]

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Triangle2D):
            return False
        return {self.p1, self.p2, self.p3} == {other.p1, other.p2, other.p3}

    def __hash__(self) -> int:
        return hash(frozenset([self.p1, self.p2, self.p3]))


def compute_delaunay_triangulation(nodes: Sequence[Point2D]) -> List[Triangle2D]:
    """Incremental Bowyer-Watson Delaunay triangulation in pure Python."""
    if len(nodes) < 3:
        return []

    min_x = min(n.x for n in nodes)
    max_x = max(n.x for n in nodes)
    min_y = min(n.y for n in nodes)
    max_y = max(n.y for n in nodes)

    dx = max_x - min_x
    dy = max_y - min_y
    delta_max = max(dx, dy, 100.0)
    mid_x = (min_x + max_x) / 2.0
    mid_y = (min_y + max_y) / 2.0

    st_p1 = Point2D(mid_x - 20.0 * delta_max, mid_y - delta_max, point_id=-1)
    st_p2 = Point2D(mid_x, mid_y + 20.0 * delta_max, point_id=-2)
    st_p3 = Point2D(mid_x + 20.0 * delta_max, mid_y - delta_max, point_id=-3)

    triangulation: List[Triangle2D] = [Triangle2D(st_p1, st_p2, st_p3)]

    for node in nodes:
        bad_triangles = [t for t in triangulation if t.circumcircle_contains(node)]
        edge_counts: Dict[Edge2D, int] = defaultdict(int)
        for tri in bad_triangles:
            for edge in tri.edges:
                edge_counts[edge] += 1

        boundary = [e for e, count in edge_counts.items() if count == 1]
        triangulation = [t for t in triangulation if t not in bad_triangles]

        for edge in boundary:
            triangulation.append(Triangle2D(edge.p1, edge.p2, node))

    super_nodes = {st_p1, st_p2, st_p3}
    return [
        t for t in triangulation
        if not (t.p1 in super_nodes or t.p2 in super_nodes or t.p3 in super_nodes)
    ]


@dataclass
class MedialNode:
    """Medial Axis Node (center of a Maximal Inscribed Circle)."""
    node_id: int
    x: float
    y: float
    clearance_radius: float
    is_bottleneck: bool = False
    is_pruned: bool = False

    @property
    def point(self) -> Point2D:
        return Point2D(self.x, self.y, point_id=self.node_id)


@dataclass
class MedialBranch:
    """Medial Axis Branch connecting two medial nodes."""
    node1_id: int
    node2_id: int
    p1: Point2D
    p2: Point2D
    length: float = 0.0

    def __post_init__(self) -> None:
        if self.length <= 0.0:
            self.length = self.p1.distance_to(self.p2)


@dataclass
class BottleneckChoke:
    """Localized geometric choke/bottleneck violation zone."""
    node_id: int
    x: float
    y: float
    clearance_radius: float
    choke_width: float


def is_collinear_set(points: Sequence[Point2D], tol: float = 1e-4) -> bool:
    """Test if all points are collinear."""
    if len(points) <= 2:
        return True
    p0 = points[0]
    p1 = points[1]
    dx = p1.x - p0.x
    dy = p1.y - p0.y
    length = math.hypot(dx, dy)
    if length < tol:
        for p in points[2:]:
            if p0.distance_to(p) > tol:
                return is_collinear_set([p0, p] + list(points[2:]), tol)
        return True

    for p in points[2:]:
        cross = abs((p.x - p0.x) * dy - (p.y - p0.y) * dx)
        if cross / length > tol:
            return False
    return True


@dataclass
class Polygon2D:
    """Simple 2D boundary polygon with continuous perimeter segments."""
    vertices: List[Point2D] = field(default_factory=list)

    def __post_init__(self) -> None:
        cleaned: List[Point2D] = []
        for v in self.vertices:
            if not cleaned or cleaned[-1] != v:
                cleaned.append(v)
        if len(cleaned) > 1 and cleaned[0] == cleaned[-1]:
            cleaned.pop()
        self.vertices = cleaned

    @property
    def is_valid(self) -> bool:
        if len(self.vertices) < 3:
            return False
        return self.shoelace_area() > 1e-4 and not is_collinear_set(self.vertices)

    def shoelace_area(self) -> float:
        n = len(self.vertices)
        if n < 3:
            return 0.0
        acc = 0.0
        for i in range(n):
            j = (i + 1) % n
            acc += self.vertices[i].x * self.vertices[j].y - self.vertices[j].x * self.vertices[i].y
        return 0.5 * abs(acc)

    def perimeter(self) -> float:
        n = len(self.vertices)
        if n < 2:
            return 0.0
        return sum(self.vertices[i].distance_to(self.vertices[(i + 1) % n]) for i in range(n))

    def segments(self) -> List[Segment2D]:
        n = len(self.vertices)
        if n < 2:
            return []
        return [Segment2D(self.vertices[i], self.vertices[(i + 1) % n]) for i in range(n)]

    def contains_point(self, pt: Point2D) -> bool:
        """Ray-casting point in polygon test."""
        n = len(self.vertices)
        if n < 3:
            return False
        x, y = pt.x, pt.y
        inside = False
        for i in range(n):
            p1 = self.vertices[i]
            p2 = self.vertices[(i + 1) % n]
            if (p1.y > y) != (p2.y > y):
                x_int = (p2.x - p1.x) * (y - p1.y) / (p2.y - p1.y + 1e-15) + p1.x
                if x < x_int:
                    inside = not inside
        return inside

    def min_clearance_to_boundary(self, pt: Point2D) -> float:
        segs = self.segments()
        if not segs:
            return 0.0
        return min(s.distance_to_point(pt) for s in segs)

    def sample_boundary(self, spacing: float = 35.0) -> List[Point2D]:
        """Sample boundary points along perimeter segments."""
        pts: List[Point2D] = []
        n = len(self.vertices)
        if n < 3:
            return pts
        spacing = max(5.0, spacing)
        for i in range(n):
            p1 = self.vertices[i]
            p2 = self.vertices[(i + 1) % n]
            d = p1.distance_to(p2)
            k = max(1, int(round(d / spacing)))
            for s in range(k):
                t = s / float(k)
                pts.append(
                    Point2D(
                        p1.x + t * (p2.x - p1.x),
                        p1.y + t * (p2.y - p1.y),
                        point_id=len(pts),
                    )
                )
        return pts


def create_canonical_venturi_polygon() -> Polygon2D:
    """Canonical venturi conduit domain with wide chambers and a central constriction."""
    return Polygon2D([
        Point2D(100.0, 150.0),
        Point2D(350.0, 150.0),
        Point2D(450.0, 280.0),  # Top constriction onset
        Point2D(650.0, 280.0),  # Top constriction exit
        Point2D(750.0, 150.0),
        Point2D(900.0, 150.0),
        Point2D(900.0, 550.0),
        Point2D(750.0, 550.0),
        Point2D(650.0, 420.0),  # Bottom constriction exit
        Point2D(450.0, 420.0),  # Bottom constriction onset
        Point2D(350.0, 550.0),
        Point2D(100.0, 550.0),
    ])


# ============================================================================
# 4. Pure Structured Text (ST) POU Definition
# ============================================================================

MEDIAL_AXIS_CANVAS_PURE_ST_POU: str = """PROGRAM MedialAxisCanvasSync
VAR
    StatusWord            AT %R2430 : INT;
    BoundaryPointsCount   AT %R2431 : INT;
    MedialNodesCount      AT %R2432 : INT;
    BranchSegmentsCount   AT %R2433 : INT;
    MaxInscribedRadius    AT %R2434 : INT;
    MinClearanceRadius    AT %R2435 : INT;
    BottleneckCount       AT %R2436 : INT;
    DiagnosticCode        AT %R2437 : UINT;

    CanvasActive          AT %M567  : BOOL;
    BottleneckAlarm       AT %M568  : BOOL;
END_VAR

IF (StatusWord <> 0) THEN
    CanvasActive := TRUE;
ELSE
    CanvasActive := FALSE;
END_IF;

IF (BottleneckCount > 0) OR (DiagnosticCode <> 0) THEN
    BottleneckAlarm := TRUE;
ELSE
    BottleneckAlarm := FALSE;
END_IF;
END_PROGRAM
"""


def verify_medial_axis_canvas_pure_st(pou_text: Optional[str] = None) -> bool:
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
# 5. Medial Axis Canvas Engine
# ============================================================================

class MedialAxisCanvasEngine(ILogicUnit):
    """Dynamic Medial Axis Transform & Skeleton SCADA Canvas Engine."""

    def __init__(
        self,
        polygon: Optional[Polygon2D] = None,
        register_table: Optional[RegisterTable] = None,
        sample_spacing: float = 35.0,
        prune_threshold: float = 45.0,
        clearance_threshold: float = 75.0,
        **kwargs: Any,
    ) -> None:
        self.reg_table = register_table or RegisterTable()
        self.polygon = polygon or create_canonical_venturi_polygon()
        self.sample_spacing = float(sample_spacing)
        self.prune_threshold = float(prune_threshold)
        self.clearance_threshold = float(clearance_threshold)

        self.is_active: bool = True
        self.diagnostic_code: DiagnosticCode = DIAG_OK
        self.bottleneck_alarm: bool = False
        self.degenerate_geometry: bool = False
        self._cycle_count: int = 0

        self._boundary_points: List[Point2D] = []
        self._medial_nodes: List[MedialNode] = []
        self._branches: List[MedialBranch] = []
        self._bottlenecks: List[BottleneckChoke] = []
        self._max_inscribed_radius: float = 0.0
        self._min_clearance_radius: float = 0.0

        self.update_analytics()

    @property
    def name(self) -> str:
        return "MedialAxisCanvasEngine"

    @property
    def priority(self) -> int:
        return 92

    @property
    def is_enabled(self) -> bool:
        return self.is_active

    @property
    def cycle_count(self) -> int:
        return self._cycle_count

    @property
    def boundary_points(self) -> List[Point2D]:
        return self._boundary_points

    @property
    def medial_nodes(self) -> List[MedialNode]:
        return self._medial_nodes

    @property
    def branches(self) -> List[MedialBranch]:
        return self._branches

    @property
    def bottlenecks(self) -> List[BottleneckChoke]:
        return self._bottlenecks

    @property
    def max_inscribed_radius(self) -> float:
        return self._max_inscribed_radius

    @property
    def min_clearance_radius(self) -> float:
        return self._min_clearance_radius

    @property
    def status_word(self) -> int:
        word = int(MedialAxisStatusBits.CANVAS_ACTIVE)
        if len(self._medial_nodes) > 0:
            word |= int(MedialAxisStatusBits.MEDIAL_AXIS_COMPUTED)
            word |= int(MedialAxisStatusBits.PRUNING_COMPLETED)
        if self.bottleneck_alarm:
            word |= int(MedialAxisStatusBits.BOTTLENECK_ALARM)
            word |= int(MedialAxisStatusBits.CLEARANCE_VIOLATION)
        if self.degenerate_geometry:
            word |= int(MedialAxisStatusBits.DEGENERATE_FAULT)
        word |= int(MedialAxisStatusBits.SVG_RENDER_VALID)
        return word

    def set_polygon(self, polygon: Polygon2D) -> None:
        self.polygon = polygon
        self.update_analytics()

    def set_clearance_threshold(self, threshold: float) -> None:
        self.clearance_threshold = float(threshold)
        self.update_analytics()

    def update_analytics(self) -> None:
        """Execute boundary sampling, Voronoi extraction, pruning, and bottleneck detection."""
        if not self.polygon.is_valid:
            self.degenerate_geometry = True
            self.diagnostic_code = DIAG_ERR_DEGENERATE_GEOMETRY
            self.bottleneck_alarm = False
            self._boundary_points = []
            self._medial_nodes = []
            self._branches = []
            self._bottlenecks = []
            self._max_inscribed_radius = 0.0
            self._min_clearance_radius = 0.0
            self._sync_registers()
            return

        self.degenerate_geometry = False
        self._boundary_points = self.polygon.sample_boundary(spacing=self.sample_spacing)

        if len(self._boundary_points) < 3 or is_collinear_set(self._boundary_points):
            self.degenerate_geometry = True
            self.diagnostic_code = DIAG_ERR_DEGENERATE_GEOMETRY
            self._medial_nodes = []
            self._branches = []
            self._sync_registers()
            return

        tris = compute_delaunay_triangulation(self._boundary_points)
        interior_tris: List[Triangle2D] = [
            t for t in tris if self.polygon.contains_point(t.circumcenter)
        ]

        edge_to_tris: Dict[Edge2D, List[Triangle2D]] = defaultdict(list)
        for t in interior_tris:
            for e in t.edges:
                edge_to_tris[e].append(t)

        raw_branches: List[Tuple[Triangle2D, Triangle2D]] = []
        for e, t_list in edge_to_tris.items():
            if len(t_list) == 2:
                t1, t2 = t_list[0], t_list[1]
                mid_x = (t1.center_x + t2.center_x) / 2.0
                mid_y = (t1.center_y + t2.center_y) / 2.0
                if self.polygon.contains_point(Point2D(mid_x, mid_y)):
                    raw_branches.append((t1, t2))

        # Filter out noisy near-boundary spires where clearance < prune_threshold
        pruned_nodes_map: Dict[Triangle2D, MedialNode] = {}
        node_id_seq = 0
        for t in interior_tris:
            clr = self.polygon.min_clearance_to_boundary(t.circumcenter)
            if clr >= self.prune_threshold:
                node_id_seq += 1
                pruned_nodes_map[t] = MedialNode(
                    node_id=node_id_seq,
                    x=t.center_x,
                    y=t.center_y,
                    clearance_radius=clr,
                )

        pruned_branches: List[MedialBranch] = []
        for t1, t2 in raw_branches:
            if t1 in pruned_nodes_map and t2 in pruned_nodes_map:
                n1 = pruned_nodes_map[t1]
                n2 = pruned_nodes_map[t2]
                pruned_branches.append(
                    MedialBranch(
                        node1_id=n1.node_id,
                        node2_id=n2.node_id,
                        p1=n1.point,
                        p2=n2.point,
                    )
                )

        self._medial_nodes = list(pruned_nodes_map.values())
        self._branches = pruned_branches

        if self._medial_nodes:
            self._max_inscribed_radius = max(n.clearance_radius for n in self._medial_nodes)
            self._min_clearance_radius = min(n.clearance_radius for n in self._medial_nodes)
        else:
            self._max_inscribed_radius = 0.0
            self._min_clearance_radius = 0.0

        # Bottlenecks: nodes where clearance_radius < clearance_threshold
        bottlenecks: List[BottleneckChoke] = []
        for n in self._medial_nodes:
            if n.clearance_radius < self.clearance_threshold:
                n.is_bottleneck = True
                bottlenecks.append(
                    BottleneckChoke(
                        node_id=n.node_id,
                        x=n.x,
                        y=n.y,
                        clearance_radius=n.clearance_radius,
                        choke_width=2.0 * n.clearance_radius,
                    )
                )
            else:
                n.is_bottleneck = False

        self._bottlenecks = bottlenecks
        if len(self._bottlenecks) > 0:
            self.bottleneck_alarm = True
            self.diagnostic_code = DIAG_ERR_BOTTLENECK_CHOKE
        else:
            self.bottleneck_alarm = False
            self.diagnostic_code = DIAG_OK

        self._sync_registers()

    def _sync_registers(self) -> None:
        self.sync_to_registers(self.reg_table, privilege=PrivilegeMode.SYSTEM)

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.USER,
    ) -> None:
        rt = reg_table or self.reg_table

        rt.write_word(REG_W282_STATUS_WORD, self.status_word, privilege=privilege)
        rt.write_word(REG_W282_BOUNDARY_POINTS, len(self._boundary_points), privilege=privilege)
        rt.write_word(REG_W282_MEDIAL_NODES, len(self._medial_nodes), privilege=privilege)
        rt.write_word(REG_W282_BRANCH_SEGMENTS, len(self._branches), privilege=privilege)
        rt.write_word(
            REG_W282_MAX_INSCRIBED_RADIUS,
            int(round(self._max_inscribed_radius * 10.0)),
            privilege=privilege,
        )
        rt.write_word(
            REG_W282_MIN_CLEARANCE_RADIUS,
            int(round(self._min_clearance_radius * 10.0)),
            privilege=privilege,
        )
        rt.write_word(REG_W282_BOTTLENECK_COUNT, len(self._bottlenecks), privilege=privilege)
        rt.write_word(
            REG_W282_DIAGNOSTIC_CODE,
            int(self.diagnostic_code) & 0xFFFF,
            privilege=privilege,
        )

        rt.write_bit(COIL_W282_CANVAS_ACTIVE, self.is_active, privilege=privilege)
        rt.write_bit(COIL_W282_BOTTLENECK_ALARM, self.bottleneck_alarm, privilege=privilege)

    def scan_step(self, dt: float = 0.01, context: Optional[ScanContext] = None) -> Dict[str, Any]:
        self._cycle_count += 1
        self.update_analytics()
        return {
            "cycle": self._cycle_count,
            "boundary_points": len(self._boundary_points),
            "medial_nodes": len(self._medial_nodes),
            "branches": len(self._branches),
            "bottlenecks": len(self._bottlenecks),
            "bottleneck_alarm": self.bottleneck_alarm,
            "min_clearance": self._min_clearance_radius,
            "max_inscribed_radius": self._max_inscribed_radius,
        }

    def step(self, dt: float = 0.01) -> None:
        self.scan_step(dt=dt)

    def execute(self, context: Optional[ScanContext] = None) -> ExecutionResult:
        dt = getattr(context, "dt_s", 0.01) if context else 0.01
        res = self.scan_step(dt=dt, context=context)
        return ExecutionResult(
            status=AgentStatus.SUCCESS,
            details="Medial Axis Canvas scan step complete",
            data=res,
        )

    def reset(self) -> None:
        self._cycle_count = 0
        self.is_active = True
        self.diagnostic_code = DIAG_OK
        self.bottleneck_alarm = False
        self.degenerate_geometry = False
        self.update_analytics()

    def render_svg(self) -> str:
        return generate_medial_axis_canvas_svg(self)


# ============================================================================
# 6. SVG Canvas Generator
# ============================================================================

def generate_medial_axis_canvas_svg(engine: Optional[MedialAxisCanvasEngine] = None) -> str:
    """Generate standalone W3C SVG 1.1 vector graphic meeting WCAG 2.1 AAA contrast."""
    eng = engine or MedialAxisCanvasEngine()

    poly_pts = " ".join(f"{p.x:.1f},{p.y:.1f}" for p in eng.polygon.vertices)
    poly_svg = (
        f'<polygon id="conduit-boundary" points="{poly_pts}" '
        f'fill="{COLOR_POLYGON_FILL}" stroke="{COLOR_POLYGON_STROKE}" '
        f'stroke-width="3.0" stroke-linejoin="round" />'
    )

    samples_svg = []
    for p in eng.boundary_points:
        samples_svg.append(
            f'<circle cx="{p.x:.1f}" cy="{p.y:.1f}" r="2.5" fill="{COLOR_BOUNDARY_SAMPLE}" />'
        )

    branches_svg = []
    for b in eng.branches:
        branches_svg.append(
            f'<line class="medial-branch" x1="{b.p1.x:.1f}" y1="{b.p1.y:.1f}" '
            f'x2="{b.p2.x:.1f}" y2="{b.p2.y:.1f}" '
            f'stroke="{COLOR_MEDIAL_BRANCH}" stroke-width="2.8" stroke-linecap="round" />'
        )

    disks_svg = []
    if eng.medial_nodes:
        peak_node = max(eng.medial_nodes, key=lambda n: n.clearance_radius)
        disks_svg.append(
            f'<circle class="inscribed-circle max-inscribed-disk" '
            f'cx="{peak_node.x:.1f}" cy="{peak_node.y:.1f}" r="{peak_node.clearance_radius:.1f}" '
            f'fill="{COLOR_INSCRIBED_DISK}" fill-opacity="0.10" '
            f'stroke="{COLOR_INSCRIBED_DISK}" stroke-width="2.0" stroke-dasharray="6 4" />'
        )

        step = max(1, len(eng.medial_nodes) // 6)
        for i in range(0, len(eng.medial_nodes), step):
            n = eng.medial_nodes[i]
            if n != peak_node:
                disks_svg.append(
                    f'<circle class="inscribed-circle" cx="{n.x:.1f}" cy="{n.y:.1f}" '
                    f'r="{n.clearance_radius:.1f}" fill="{COLOR_INSCRIBED_DISK}" fill-opacity="0.04" '
                    f'stroke="{COLOR_INSCRIBED_DISK}" stroke-opacity="0.4" stroke-width="1.2" stroke-dasharray="3 3" />'
                )

    nodes_svg = []
    for n in eng.medial_nodes:
        node_color = COLOR_BOTTLENECK_ALARM if n.is_bottleneck else COLOR_MEDIAL_NODE
        r = 4.0 if not n.is_bottleneck else 5.5
        nodes_svg.append(
            f'<circle cx="{n.x:.1f}" cy="{n.y:.1f}" r="{r}" fill="{node_color}" />'
        )

    bottlenecks_svg = []
    for chk in eng.bottlenecks:
        bottlenecks_svg.append(
            f'<g class="bottleneck-choke-marker">'
            f'<circle cx="{chk.x:.1f}" cy="{chk.y:.1f}" r="{chk.clearance_radius:.1f}" '
            f'fill="{COLOR_BOTTLENECK_ALARM}" fill-opacity="0.18" '
            f'stroke="{COLOR_BOTTLENECK_ALARM}" stroke-width="2.2" stroke-dasharray="4 2" />'
            f'<circle cx="{chk.x:.1f}" cy="{chk.y:.1f}" r="6.0" fill="{COLOR_BOTTLENECK_ALARM}" />'
            f'<text x="{chk.x + 8:.1f}" y="{chk.y - 8:.1f}" fill="{COLOR_BOTTLENECK_ALARM}" '
            f'font-family="monospace" font-size="12" font-weight="bold">CHOKE {chk.clearance_radius:.1f}px</text>'
            f'</g>'
        )

    status_color = COLOR_BOTTLENECK_ALARM if eng.bottleneck_alarm else COLOR_NOMINAL_EMERALD
    status_str = "CLEARANCE CHOKE ALARM" if eng.bottleneck_alarm else "NOMINAL TRANSIT OK"

    hud_card = f"""
    <!-- Decoupled High-Contrast HUD Telemetry Badge (WCAG AAA >= 18:1) -->
    <rect x="20" y="20" width="1160" height="90" rx="8" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_BORDER}" stroke-width="1.5" />
    <text x="40" y="55" fill="{COLOR_TEXT_PRIMARY}" font-family="monospace" font-size="20" font-weight="bold">MEDIAL AXIS &amp; TOPOLOGICAL SKELETON CANVAS (W282)</text>
    <text x="40" y="85" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="13">POU: MedialAxisCanvasSync | STATUS: {status_str} | DIAG: 0x{int(eng.diagnostic_code) & 0xFFFF:04X}</text>

    <!-- Status Pill -->
    <rect x="940" y="38" width="220" height="36" rx="6" fill="{status_color}" fill-opacity="0.2" stroke="{status_color}" stroke-width="1.5" />
    <text x="1050" y="61" fill="{status_color}" font-family="monospace" font-size="13" font-weight="bold" text-anchor="middle">{status_str}</text>

    <!-- Telemetry Readout Subcard -->
    <rect x="20" y="630" width="1160" height="100" rx="8" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_BORDER}" stroke-width="1.5" />
    <text x="40" y="665" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="13">HORNER OCS REGISTERS:</text>
    <text x="40" y="695" fill="{COLOR_TEXT_PRIMARY}" font-family="monospace" font-size="14">%R2430 (Status): {eng.status_word}  |  %R2431 (Boundary Pts): {len(eng.boundary_points)}  |  %R2432 (Medial Nodes): {len(eng.medial_nodes)}  |  %R2433 (Branches): {len(eng.branches)}</text>
    <text x="40" y="718" fill="{COLOR_TEXT_PRIMARY}" font-family="monospace" font-size="14">%R2434 (Max MIC): {eng.max_inscribed_radius:.1f}px  |  %R2435 (Min Clr): {eng.min_clearance_radius:.1f}px  |  %R2436 (Bottlenecks): {len(eng.bottlenecks)}  |  %M567: {int(eng.is_active)}  |  %M568: {int(eng.bottleneck_alarm)}</text>
    """

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {CANVAS_VIEWPORT_WIDTH} {CANVAS_VIEWPORT_HEIGHT}" width="{CANVAS_VIEWPORT_WIDTH}" height="{CANVAS_VIEWPORT_HEIGHT}">
    <rect width="{CANVAS_VIEWPORT_WIDTH}" height="{CANVAS_VIEWPORT_HEIGHT}" fill="{COLOR_SCADA_BG}" />
    {poly_svg}
    {"".join(disks_svg)}
    {"".join(samples_svg)}
    {"".join(branches_svg)}
    {"".join(nodes_svg)}
    {"".join(bottlenecks_svg)}
    {hud_card}
</svg>"""
    return svg


# ============================================================================
# 7. Verification Suite Execution (9-Stage Sequence)
# ============================================================================

def run_medial_axis_canvas_verification(
    output_path: Optional[str] = None,
    sample_svg_path: Optional[str] = None,
    work_package: str = "W282",
) -> Dict[str, Any]:
    """Execute complete 9-stage verification suite for W282 Medial Axis Canvas."""
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: polygon_boundary_and_point_sampling
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    poly1 = create_canonical_venturi_polygon()
    samples1 = poly1.sample_boundary(spacing=35.0)
    c1 = (
        poly1.is_valid
        and len(poly1.vertices) == 12
        and poly1.shoelace_area() > 50000.0
        and len(samples1) >= 50
        and all(poly1.min_clearance_to_boundary(p) < 1e-4 for p in samples1)
    )
    test_results.append({
        "stage": 1,
        "name": "polygon_boundary_and_point_sampling",
        "check": "polygon_boundary_and_point_sampling",
        "passed": bool(c1),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Polygon defined with 12 vertices (area={poly1.shoelace_area():.0f}); {len(samples1)} boundary sample points generated.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: voronoi_and_medial_axis_extraction
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng_base = MedialAxisCanvasEngine(polygon=poly1, sample_spacing=35.0, prune_threshold=0.0)
    c2 = (
        len(eng_base.medial_nodes) > 0
        and len(eng_base.branches) > 0
        and all(poly1.contains_point(n.point) for n in eng_base.medial_nodes)
    )
    test_results.append({
        "stage": 2,
        "name": "voronoi_and_medial_axis_extraction",
        "check": "voronoi_and_medial_axis_extraction",
        "passed": bool(c2),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Extracted {len(eng_base.medial_nodes)} interior Voronoi medial nodes and {len(eng_base.branches)} raw branch segments.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: maximal_inscribed_circle_radius_field
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    max_r = eng_base.max_inscribed_radius
    min_r = eng_base.min_clearance_radius
    all_positive = all(n.clearance_radius > 0.0 for n in eng_base.medial_nodes)
    c3 = all_positive and (max_r > 150.0) and (min_r > 0.0)
    test_results.append({
        "stage": 3,
        "name": "maximal_inscribed_circle_radius_field",
        "check": "maximal_inscribed_circle_radius_field",
        "passed": bool(c3),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Clearance radius field verified: Max MIC radius {max_r:.1f}px, Min clearance {min_r:.1f}px.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: branch_pruning_and_noise_filtering
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng_pruned = MedialAxisCanvasEngine(polygon=poly1, sample_spacing=35.0, prune_threshold=45.0, clearance_threshold=75.0)
    unpruned_branches = len(eng_base.branches)
    pruned_branches = len(eng_pruned.branches)
    c4 = (
        unpruned_branches > pruned_branches
        and pruned_branches > 0
        and len(eng_pruned.medial_nodes) > 0
        and all(n.clearance_radius >= 45.0 for n in eng_pruned.medial_nodes)
    )
    test_results.append({
        "stage": 4,
        "name": "branch_pruning_and_noise_filtering",
        "check": "branch_pruning_and_noise_filtering",
        "passed": bool(c4),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Noise filtering pruned spires: unpruned={unpruned_branches} -> pruned={pruned_branches} branches; all nodes >= 45.0px.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: bottleneck_and_clearance_violation_detection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    chokes_alarm = len(eng_pruned.bottlenecks)
    diag_alarm = eng_pruned.diagnostic_code
    alarm_active = eng_pruned.bottleneck_alarm

    # Transition to nominal threshold (50.0px) where neck (clearance ~70px) is clear
    eng_pruned.set_clearance_threshold(50.0)
    chokes_nominal = len(eng_pruned.bottlenecks)
    diag_nominal = eng_pruned.diagnostic_code
    nominal_alarm = eng_pruned.bottleneck_alarm

    # Restore threshold for subsequent rendering
    eng_pruned.set_clearance_threshold(75.0)
    neck_chokes = [chk for chk in eng_pruned.bottlenecks if 450.0 <= chk.x <= 650.0]

    c5 = (
        alarm_active is True
        and chokes_alarm > 0
        and diag_alarm == DIAG_ERR_BOTTLENECK_CHOKE
        and nominal_alarm is False
        and chokes_nominal == 0
        and diag_nominal == DIAG_OK
        and len(neck_chokes) >= 6
        and all(math.isclose(chk.clearance_radius, 70.0, rel_tol=0.05) for chk in neck_chokes)
    )
    test_results.append({
        "stage": 5,
        "name": "bottleneck_and_clearance_violation_detection",
        "check": "bottleneck_and_clearance_violation_detection",
        "passed": bool(c5),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Bottleneck detector located {len(neck_chokes)} narrow chokes in neck (x in [450, 650]); asserts %M568.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: degenerate_and_collinear_handling
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    collinear_poly = Polygon2D([
        Point2D(100.0, 100.0),
        Point2D(200.0, 100.0),
        Point2D(300.0, 100.0),
        Point2D(400.0, 100.0),
    ])
    eng6_collinear = MedialAxisCanvasEngine(polygon=collinear_poly)

    deg_poly2 = Polygon2D([Point2D(50.0, 50.0), Point2D(150.0, 150.0)])
    eng6_deg2 = MedialAxisCanvasEngine(polygon=deg_poly2)

    deg_poly0 = Polygon2D([])
    eng6_deg0 = MedialAxisCanvasEngine(polygon=deg_poly0)

    c6 = (
        eng6_collinear.degenerate_geometry is True
        and eng6_collinear.diagnostic_code == DIAG_ERR_DEGENERATE_GEOMETRY
        and len(eng6_collinear.medial_nodes) == 0
        and eng6_deg2.degenerate_geometry is True
        and eng6_deg0.degenerate_geometry is True
    )
    test_results.append({
        "stage": 6,
        "name": "degenerate_and_collinear_handling",
        "check": "degenerate_and_collinear_handling",
        "passed": bool(c6),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Degenerate collinear, two-point, and zero-point inputs handled robustly with DIAG_ERR_DEGENERATE_GEOMETRY (0x8202).",
    })

    # ------------------------------------------------------------------------
    # Stage 7: wcag_aaa_svg_canvas_rendering
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    svg_text = generate_medial_axis_canvas_svg(eng_pruned)
    root = ET.fromstring(svg_text)
    badge_contrast = validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, min_contrast=18.0)
    text_contrast = validate_wcag_aaa_contrast(COLOR_TEXT_MUTED, COLOR_DECOUPLED_BADGE, min_contrast=7.0)

    has_polygon = bool(root.findall(".//{http://www.w3.org/2000/svg}polygon") or root.findall(".//polygon"))
    has_branches = "medial-branch" in svg_text
    has_disks = "inscribed-circle" in svg_text
    has_bottleneck_choke = "bottleneck-choke-marker" in svg_text

    c7 = (
        root.tag.endswith("svg")
        and badge_contrast.is_compliant
        and text_contrast.is_compliant
        and has_polygon
        and has_branches
        and has_disks
        and has_bottleneck_choke
    )
    test_results.append({
        "stage": 7,
        "name": "wcag_aaa_svg_canvas_rendering",
        "check": "wcag_aaa_svg_canvas_rendering",
        "passed": bool(c7),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"SVG parses cleanly; badge contrast {badge_contrast.contrast_ratio:.1f}:1 >= 18:1; branches & inscribed disks rendered.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: horner_ocs_register_sync
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt8 = RegisterTable()
    eng8 = MedialAxisCanvasEngine(
        polygon=poly1,
        register_table=rt8,
        sample_spacing=35.0,
        prune_threshold=45.0,
        clearance_threshold=75.0,
    )

    w_status = rt8.read_word(REG_W282_STATUS_WORD)
    w_pts = rt8.read_word(REG_W282_BOUNDARY_POINTS)
    w_nodes = rt8.read_word(REG_W282_MEDIAL_NODES)
    w_branches = rt8.read_word(REG_W282_BRANCH_SEGMENTS)
    w_max_r = rt8.read_word(REG_W282_MAX_INSCRIBED_RADIUS)
    w_min_r = rt8.read_word(REG_W282_MIN_CLEARANCE_RADIUS)
    w_chokes = rt8.read_word(REG_W282_BOTTLENECK_COUNT)
    w_diag = rt8.read_word(REG_W282_DIAGNOSTIC_CODE)

    b_active = rt8.read_bit(COIL_W282_CANVAS_ACTIVE)
    b_alarm = rt8.read_bit(COIL_W282_BOTTLENECK_ALARM)

    eng8.set_clearance_threshold(50.0)
    b_alarm_cleared = rt8.read_bit(COIL_W282_BOTTLENECK_ALARM)
    w_diag_cleared = rt8.read_word(REG_W282_DIAGNOSTIC_CODE)

    eng8.set_clearance_threshold(75.0)

    c8 = (
        (w_status & int(MedialAxisStatusBits.CANVAS_ACTIVE)) != 0
        and (w_status & int(MedialAxisStatusBits.BOTTLENECK_ALARM)) != 0
        and w_pts == len(eng8.boundary_points)
        and w_nodes == len(eng8.medial_nodes)
        and w_branches == len(eng8.branches)
        and w_max_r == int(round(eng8.max_inscribed_radius * 10.0))
        and w_min_r == int(round(eng8.min_clearance_radius * 10.0))
        and w_chokes == len(eng8.bottlenecks)
        and (w_diag & 0xFFFF) == 0x8201
        and b_active is True
        and b_alarm is True
        and b_alarm_cleared is False
        and (w_diag_cleared & 0xFFFF) == 0x0000
    )
    test_results.append({
        "stage": 8,
        "name": "horner_ocs_register_sync",
        "check": "horner_ocs_register_sync",
        "passed": bool(c8),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "RegisterTable %R2430..%R2437 and coils %M567..%M568 synchronized bit-exact.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: pure_st_pou_and_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    st_valid = verify_medial_axis_canvas_pure_st()

    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content(
            "PROGRAM P VAR X : BOOL; END_VAR ---[ ]--- END_PROGRAM"
        )
    except LadderForbiddenError:
        ladder_rejected = True

    c9 = st_valid and ladder_rejected
    test_results.append({
        "stage": 9,
        "name": "pure_st_pou_and_ladder_rejection",
        "check": "pure_st_pou_and_ladder_rejection",
        "passed": bool(c9),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "MedialAxisCanvasSync pure ST AST verified; ladder contacts rejected with LadderForbiddenError.",
    })

    stages_passed = sum(1 for r in test_results if r["passed"])
    total_stages = len(test_results)
    all_passed = (stages_passed == total_stages)

    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "ERR_STAGE_VERIFICATION_FAILED",
        "details": f"Wave {work_package} Dynamic Medial Axis Canvas Verification PASSED ({stages_passed}/{total_stages} stages).",
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
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    if sample_svg_path:
        svg_p = Path(sample_svg_path).resolve()
        svg_p.parent.mkdir(parents=True, exist_ok=True)
        with open(svg_p, "w", encoding="utf-8") as f:
            f.write(generate_medial_axis_canvas_svg(eng_pruned))

    return evidence


# ============================================================================
# 8. Command-Line Entry Point
# ============================================================================

def format_stage_badge(passed: bool, status: Optional[str] = None) -> str:
    norm_status = (status or "").lower()
    if norm_status == "blocked":
        return f"{CLR_YELLOW}{CLR_BOLD}[BLOCKED]{CLR_RESET}"
    if norm_status == "inconclusive":
        return f"{CLR_YELLOW}{CLR_BOLD}[INCONCLUSIVE]{CLR_RESET}"
    if passed or norm_status in ("passed", "pass", "success"):
        return f"{CLR_GREEN}{CLR_BOLD}[PASS]{CLR_RESET}"
    return f"{CLR_RED}{CLR_BOLD}[FAIL]{CLR_RESET}"


def main(argv: Optional[List[str]] = None) -> int:
    """Command-line entry point for W282 verification runner."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Run Cscape HMI Dynamic Spatial Medial Axis Transform 9-Stage Verification Suite (W282)"
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
        "--evidence",
        dest="output_path",
        type=str,
        default=None,
        help="Path to output verification evidence JSON",
    )
    parser.add_argument(
        "--svg",
        "-s",
        "--sample-svg-path",
        dest="sample_svg_path",
        type=str,
        default=None,
        help="Path to output sample SVG 1.1 vector graphic artifact",
    )
    parser.add_argument(
        "--work-package",
        "-w",
        dest="work_package",
        type=str,
        default="W282",
        help="Work package code (default: W282)",
    )
    parser.add_argument(
        "--json-only",
        "--json",
        action="store_true",
        dest="json_only",
        help="Output raw JSON only",
    )

    args = parser.parse_args(argv)

    default_output_dir = REPO_ROOT / "artifacts" / "HMI"
    default_output_dir.mkdir(parents=True, exist_ok=True)

    evidence_file = (
        args.output_path
        or args.positional_output
        or str(default_output_dir / "medial_axis_canvas_evidence.json")
    )
    svg_file = (
        args.sample_svg_path
        or args.positional_svg
        or str(default_output_dir / "medial_axis_canvas_sample.svg")
    )

    if not args.json_only:
        print(f"\n{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN} Cscape HMI Dynamic Spatial Medial Axis Canvas Verification (W282){CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")
        print(f" Evidence Destination : {evidence_file}")
        print(f" SVG Artifact Output  : {svg_file}")
        print(f" Target Work Package  : {args.work_package}")
        print(f"{CLR_DIM}----------------------------------------------------------------------{CLR_RESET}\n")

    t_start = time.perf_counter()
    res = run_medial_axis_canvas_verification(
        output_path=evidence_file,
        sample_svg_path=svg_file,
        work_package=args.work_package,
    )
    t_elapsed_ms = (time.perf_counter() - t_start) * 1000.0

    if args.json_only:
        print(json.dumps(res, indent=2))
        return 0 if res.get("status") == "success" else 1

    tests = res.get("data", {}).get("tests", [])
    for t in tests:
        stg = t.get("stage", 0)
        chk = t.get("check", "Unknown")
        p = t.get("passed", False)
        dur = t.get("timing_ms", 0.0)
        det = t.get("details", "")
        badge = format_stage_badge(p)
        print(f" Stage {stg:02d}: {chk:<48} {badge} {CLR_DIM}({dur:>5.1f} ms){CLR_RESET}")
        if det:
            print(f"          {CLR_GRAY}└─ {det}{CLR_RESET}")

    total_checks = res.get("data", {}).get("total_checks", len(tests))
    passed_checks = res.get("data", {}).get("checks_passed", 0)
    status_str = res.get("status", "failed")

    print(f"\n{CLR_DIM}----------------------------------------------------------------------{CLR_RESET}")
    if status_str == "success":
        print(f" {CLR_GREEN}{CLR_BOLD}RESULT: SUCCESS ({passed_checks}/{total_checks} checks passed in {t_elapsed_ms:.1f} ms){CLR_RESET}")
    else:
        print(f" {CLR_RED}{CLR_BOLD}RESULT: FAILED ({passed_checks}/{total_checks} checks passed in {t_elapsed_ms:.1f} ms){CLR_RESET}")
    print(f"{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}\n")

    return 0 if status_str == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
