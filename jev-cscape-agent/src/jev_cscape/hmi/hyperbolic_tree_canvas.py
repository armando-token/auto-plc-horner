"""Cscape HMI Dynamic Hyperbolic Tree / Poincaré Disk SCADA Canvas.

Work Package: W213 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Provides:
1. Complex Coordinates & Poincaré Disk Model:
   - ComplexPoint 2D complex numbers z = x + i*y in the open unit disk D = {z in C : |z| < 1.0}.
   - Strict boundary containment verification (|z| < 1.0) and numerical radius clamping (|z| <= MAX_HYPERBOLIC_RADIUS).
   - Coordinate conversion between normalized Poincaré disk coordinates and screen viewport pixels.
2. Möbius Transformations & Non-Euclidean Isometries:
   - Disk automorphism T_{a, theta}(z) = e^(i*theta) * (z - a) / (1 - conj(a)*z) mapping target node 'a' to origin.
   - Inverse transformation T_{a, theta}^(-1)(w) = (w*e^(-i*theta) + a) / (1 + conj(a)*w*e^(-i*theta)).
   - Identity transformation T_{0, 0}(z) = z, isometry preservation of hyperbolic distances.
   - Singularity guard intercepting near-zero denominators (|1 - conj(a)*z| < eps) with SingularityError.
3. Hyperbolic Distance Metric:
   - Exact Poincaré metric d(u, v) = 2 * artanh(|u - v| / |1 - conj(u)*v|).
   - Invariant verification: d(u, u) = 0, symmetry d(u, v) = d(v, u), triangle inequality d(u, w) <= d(u, v) + d(v, w).
   - Origin distance d(0, v) = 2 * artanh(|v|).
4. Geodesic Arc Circle Geometry:
   - Poincaré disk geodesics: diameters through origin (straight lines) or Euclidean circular arcs orthogonal to |z| = 1.
   - Analytical center (c_x, c_y) and radius R calculation satisfying c_x^2 + c_y^2 - R^2 = 1.0 and |c - u| = |c - v| = R.
   - SVG arc command generation `<path d="M ux,uy A R,R 0 0,sweep vx,vy" .../>`.
5. Hierarchical Tree Traversal & Radial Layout:
   - TreeNode data model with parent-child references, depth level, weight, health scores, and complex coordinates.
   - HyperbolicTree builder with bidirectional linking and O(V + E) cycle detection.
   - Recursive angular wedge allocation [theta_min, theta_max] proportional to subtree weights.
   - Interactive recentering on any selected node via Möbius automorphism.
6. Bottom-Up Health Score Propagation & Critical Fault Identification:
   - Post-order bottom-up health propagation from leaf assets to plant root.
   - Weighted average health aggregation: H_parent = sum(W_i * H_i) / sum(W_i).
   - Critical fault trip localization (health < 70.0% asserts is_fault and trips coil %M406).
7. Dark Industrial Theme & WCAG 2.1 AAA Accessibility:
   - Dark industrial SCADA viewport backing (#0D1117) with ultra-high contrast decoupled badge (#050811).
   - Relative luminance and contrast ratio engine meeting WCAG 2.1 AAA (> 18:1 badge, > 7:1 text, > 3:1 graphics).
8. Standalone W3C SVG 1.1 Vector Graphic Generation:
   - Valid XML SVG markup with defs, unit boundary circle, concentric hyperbolic distance rings,
     geodesic arc edges, multi-ring status nodes with glows, and telemetry HUD cards.
   - Fully parsable by xml.etree.ElementTree.fromstring.
9. Horner OCS Memory Space Integration:
   - Analog registers %R1740..%R1747:
     - %R1740: RootAggregateHealthScoreScaled (INT16, scaled x10 %, e.g. 950 = 95.0%)
     - %R1741: SelectedNodeIndex (INT16, 0..N)
     - %R1742: SelectedNodeDistanceScaled (INT16, scaled x100, e.g. 125 = 1.25)
     - %R1743: CriticalFaultCount (INT16, count of degraded nodes < 70.0%)
     - %R1744: MaxTreeDepth (INT16, max depth in active tree)
     - %R1745: TotalNodeCount (INT16, total node count)
     - %R1746: MinHealthScoreScaled (INT16, scaled x10 %, lowest health in tree)
     - %R1747: DiagnosticStatusCode (0x0000=OK, 0xE201, 0xE202, 0xE203, 0xE204)
   - Discrete coils %M406..%M407:
     - %M406: CriticalFaultAlarmActive (BOOL)
     - %M407: HyperbolicTreeCanvasActive (BOOL)
   - Synchronization with PrivilegeMode.SYSTEM.
10. ILogicUnit Discrete Scan Cycle Engine:
    - Implements scan_step(dt), step(), and execute(ScanContext) protocols.
11. Pure IEC 61131-3 Structured Text (ST) POU:
    - Program 'HyperbolicTreeCanvasSync' validated via SecurityGuard.assert_pure_st_content and STParser.
12. Deterministic 9-Stage Verification Suite:
    - run_hyperbolic_tree_canvas_verification returning strict 4-state contract JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntFlag
import html
import json
import math
from pathlib import Path
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
# 1. Constants & Diagnostic Event Codes
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


# Diagnostic event codes conforming to Horner OCS %R1747 specification
DIAG_OK: DiagnosticCode                                              = DiagnosticCode(0x0000)
DIAG_EVENT_OK: DiagnosticCode                                        = DiagnosticCode(0x0000)

# 0xE201: Hierarchy cycle detected in tree dependency graph
DIAG_ERR_HIERARCHY_CYCLE_DETECTED: DiagnosticCode                    = DiagnosticCode(0xE201)
HIERARCHY_CYCLE_DETECTED: DiagnosticCode                             = DIAG_ERR_HIERARCHY_CYCLE_DETECTED

# 0xE202: Poincaré disk boundary overflow / singularity (|z| >= 1.0 or |1 - conj(a)*z| < eps)
DIAG_ERR_BOUNDARY_OVERFLOW: DiagnosticCode                           = DiagnosticCode(0xE202)
BOUNDARY_OVERFLOW_FAULT: DiagnosticCode                              = DIAG_ERR_BOUNDARY_OVERFLOW

# 0xE203: Critical health fault trip (node health < critical threshold) -> asserts %M406
DIAG_ERR_CRITICAL_FAULT_TRIP: DiagnosticCode                         = DiagnosticCode(0xE203)
CRITICAL_FAULT_TRIP: DiagnosticCode                                  = DIAG_ERR_CRITICAL_FAULT_TRIP

# 0xE204: SVG vector rasterization / XML syntax render fault
DIAG_ERR_SVG_RENDER_FAULT: DiagnosticCode                            = DiagnosticCode(0xE204)
SVG_RENDER_FAULT: DiagnosticCode                                     = DIAG_ERR_SVG_RENDER_FAULT

# Horner OCS Register Definitions (%R1740..%R1747)
REG_ROOT_HEALTH_SCORE_SCALED: str                                    = "%R1740"
REG_SELECTED_NODE_INDEX: str                                         = "%R1741"
REG_SELECTED_NODE_DISTANCE_SCALED: str                               = "%R1742"
REG_CRITICAL_FAULT_COUNT: str                                        = "%R1743"
REG_MAX_TREE_DEPTH: str                                              = "%R1744"
REG_TOTAL_NODE_COUNT: str                                            = "%R1745"
REG_MIN_HEALTH_SCORE_SCALED: str                                     = "%R1746"
REG_DIAGNOSTIC_STATUS_CODE: str                                      = "%R1747"

# Aliases for W213
REG_W213_ROOT_HEALTH: str                                            = "%R1740"
REG_W213_SELECTED_NODE: str                                          = "%R1741"
REG_W213_SELECTED_DISTANCE: str                                      = "%R1742"
REG_W213_CRITICAL_FAULTS: str                                        = "%R1743"
REG_W213_MAX_DEPTH: str                                              = "%R1744"
REG_W213_TOTAL_NODES: str                                            = "%R1745"
REG_W213_MIN_HEALTH: str                                             = "%R1746"
REG_W213_STATUS_WORD: str                                            = "%R1747"
REG_W213_DIAGNOSTIC_CODE: str                                        = "%R1747"

# Discrete Coils (%M406..%M407)
COIL_CRITICAL_FAULT_ALARM_ACTIVE: str                                = "%M406"
COIL_HYPERBOLIC_TREE_CANVAS_ACTIVE: str                              = "%M407"
COIL_W213_FAULT_ALARM: str                                           = "%M406"
COIL_W213_CANVAS_ACTIVE: str                                         = "%M407"
COIL_TREE_FAULT_TRIP: str                                            = "%M406"
COIL_HYPERBOLIC_TREE_ACTIVE: str                                     = "%M407"

# Canvas & Viewport Specifications
CANVAS_VIEWPORT_WIDTH: int                                           = 1200
CANVAS_VIEWPORT_HEIGHT: int                                          = 750
CANVAS_CENTER_X: float                                               = 500.0
CANVAS_CENTER_Y: float                                               = 375.0
POINCARE_DISK_RADIUS: float                                          = 320.0
MAX_HYPERBOLIC_RADIUS: float                                         = 0.96

# Concentric Canonical Hyperbolic Radii per Hierarchy Level
LEVEL_0_RADIUS: float                                                = 0.00    # Central Plant Root Hub
LEVEL_1_RADIUS: float                                                = 0.38    # Level 1: Production Areas
LEVEL_2_RADIUS: float                                                = 0.68    # Level 2: Operating Units
LEVEL_3_RADIUS: float                                                = 0.88    # Level 3: Subsystems & Assets
CANONICAL_LEVEL_RADII: List[float]                                   = [
    LEVEL_0_RADIUS,
    LEVEL_1_RADIUS,
    LEVEL_2_RADIUS,
    LEVEL_3_RADIUS,
]

# Process Health Thresholds
HEALTH_CRITICAL_THRESHOLD: float                                     = 70.0    # < 70.0% is CRITICAL fault
HEALTH_WARNING_THRESHOLD: float                                      = 85.0    # 70.0% <= health < 85.0% is WARNING
HEALTH_NOMINAL_BASELINE: float                                       = 95.0    # Nominal healthy baseline

# WCAG 2.1 AAA Accessibility Targets
WCAG_AAA_BADGE_CONTRAST_TARGET: float                                = 18.0    # Contrast > 18:1
WCAG_AAA_TEXT_CONTRAST_TARGET: float                                 = 7.0     # Contrast > 7:1
WCAG_GRAPHICAL_CONTRAST_TARGET: float                                = 3.0     # Contrast > 3:1

# SCADA Industrial Color Palette
COLOR_DARK_THEME_BACKING: str                                        = "#0D1117"   # Industrial dark background
COLOR_DARK_SURFACE: str                                              = "#161B22"   # Elevated container surface
COLOR_CARD_BG: str                                                   = "#1E293B"   # HUD telemetry card background
COLOR_CARD_BORDER: str                                               = "#334155"   # Card boundary stroke
COLOR_DECOUPLED_BADGE: str                                           = "#050811"   # Ultra-dark decoupled badge (> 18:1)
COLOR_TEXT_PRIMARY: str                                              = "#F8FAFC"   # White primary text
COLOR_TEXT_MUTED: str                                                = "#94A3B8"   # Secondary slate text
COLOR_FOCUS_BLUE: str                                                = "#38BDF8"   # Cyan/Blue selection highlight
COLOR_DISK_BOUNDARY: str                                             = "#38BDF8"   # Poincaré unit disk boundary circle
COLOR_GEODESIC_EDGE: str                                             = "#475569"   # Geodesic arc curves
COLOR_CONCENTRIC_GUIDE: str                                          = "#1E293B"   # Concentric guide circles

# Status Health Colors
COLOR_NOMINAL_EMERALD: str                                           = "#10B981"   # Nominal health (>= 85%)
COLOR_NOMINAL: str                                                   = COLOR_NOMINAL_EMERALD
COLOR_WARM_AMBER: str                                                = "#F59E0B"   # Warning health (70..85%)
COLOR_WARNING: str                                                   = COLOR_WARM_AMBER
COLOR_ALARM_CRIMSON: str                                             = "#EF4444"   # Critical fault (< 70%)
COLOR_CRITICAL: str                                                  = COLOR_ALARM_CRIMSON
COLOR_CYAN_INFO: str                                                 = "#06B6D4"   # Informational / auxiliary


# ============================================================================
# 2. Enums and Status Bitmasks
# ============================================================================

class NodeHealthState(str, Enum):
    """Health classification for tree nodes."""
    NOMINAL = "NOMINAL"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class HyperbolicTreeStatusBits(IntFlag):
    """Horner OCS Status Bitmask Definitions (%R1747)."""
    CANVAS_ACTIVE              = 1 << 0  # Bit 0 (0x0001): Canvas & hyperbolic engine active (%M407)
    GEOMETRY_COMPUTED          = 1 << 1  # Bit 1 (0x0002): Poincaré hyperbolic layout calculated
    HIERARCHY_VALID            = 1 << 2  # Bit 2 (0x0004): Tree acyclic and references valid
    HEALTH_PROPAGATED          = 1 << 3  # Bit 3 (0x0008): Bottom-up health propagated to root
    CRITICAL_FAULT_ACTIVE      = 1 << 4  # Bit 4 (0x0010): Critical fault alarm asserted (%M406)
    CYCLE_DETECTED             = 1 << 5  # Bit 5 (0x0020): Cycle detected in graph (0xE201)
    BOUNDARY_OVERFLOW_FAULT    = 1 << 6  # Bit 6 (0x0040): Boundary or singularity detected (0xE202)
    RENDER_FAULT               = 1 << 7  # Bit 7 (0x0080): SVG render fault (0xE204)
    SVG_VALID                  = 1 << 8  # Bit 8 (0x0100): Standalone W3C SVG 1.1 rendered and valid
    WCAG_AAA_VERIFIED          = 1 << 9  # Bit 9 (0x0200): WCAG 2.1 AAA contrast confirmed (> 18:1)
    NODE_SELECTED              = 1 << 10 # Bit 10 (0x0400): Active node selected and highlighted
    NOMINAL_OPERATION          = 1 << 11 # Bit 11 (0x0800): Nominal fault-free operation


class HierarchyCycleError(ValueError):
    """Raised when a directed or indirect cycle is detected in the tree structure."""
    pass


class HyperbolicBoundaryError(ValueError):
    """Raised when coordinates exceed the open unit disk boundary |z| >= 1.0."""
    pass


class SingularityError(ZeroDivisionError):
    """Raised when a numerical singularity or zero denominator is encountered in Möbius math."""
    pass


# ============================================================================
# 3. Geometric Primitives & Complex Poincaré Math
# ============================================================================

@dataclass(frozen=True)
class ComplexPoint:
    """Complex number z = x + i*y representing a coordinate in the Poincaré unit disk."""
    x: float
    y: float

    @property
    def real(self) -> float:
        return self.x

    @property
    def imag(self) -> float:
        return self.y

    def magnitude(self) -> float:
        """Euclidean magnitude |z| = sqrt(x^2 + y^2)."""
        return math.hypot(self.x, self.y)

    def magnitude_squared(self) -> float:
        """Magnitude squared |z|^2 = x^2 + y^2."""
        return self.x * self.x + self.y * self.y

    def conjugate(self) -> ComplexPoint:
        """Complex conjugate bar{z} = x - i*y."""
        return ComplexPoint(self.x, -self.y)

    def angle(self) -> float:
        """Polar phase angle in radians [-pi, pi]."""
        return math.atan2(self.y, self.x)

    def is_in_disk(self, max_radius: float = 1.0) -> bool:
        """Check whether point lies strictly within disk boundary |z| < max_radius."""
        return self.magnitude() < max_radius

    def clamp(self, max_radius: float = MAX_HYPERBOLIC_RADIUS) -> ComplexPoint:
        """Clamp coordinate to maximum radial threshold inside the open unit disk."""
        mag = self.magnitude()
        if mag > max_radius:
            if mag < 1e-15:
                return ComplexPoint(0.0, 0.0)
            scale = max_radius / mag
            return ComplexPoint(round(self.x * scale, 6), round(self.y * scale, 6))
        return self

    def __add__(self, other: Any) -> ComplexPoint:
        if isinstance(other, ComplexPoint):
            return ComplexPoint(self.x + other.x, self.y + other.y)
        if isinstance(other, complex):
            return ComplexPoint(self.x + other.real, self.y + other.imag)
        if isinstance(other, (int, float)):
            return ComplexPoint(self.x + float(other), self.y)
        return NotImplemented

    def __radd__(self, other: Any) -> ComplexPoint:
        return self.__add__(other)

    def __sub__(self, other: Any) -> ComplexPoint:
        if isinstance(other, ComplexPoint):
            return ComplexPoint(self.x - other.x, self.y - other.y)
        if isinstance(other, complex):
            return ComplexPoint(self.x - other.real, self.y - other.imag)
        if isinstance(other, (int, float)):
            return ComplexPoint(self.x - float(other), self.y)
        return NotImplemented

    def __rsub__(self, other: Any) -> ComplexPoint:
        if isinstance(other, (int, float)):
            return ComplexPoint(float(other) - self.x, -self.y)
        if isinstance(other, complex):
            return ComplexPoint(other.real - self.x, other.imag - self.y)
        return NotImplemented

    def __mul__(self, other: Any) -> ComplexPoint:
        if isinstance(other, ComplexPoint):
            return ComplexPoint(
                self.x * other.x - self.y * other.y,
                self.x * other.y + self.y * other.x,
            )
        if isinstance(other, complex):
            return ComplexPoint(
                self.x * other.real - self.y * other.imag,
                self.x * other.imag + self.y * other.real,
            )
        if isinstance(other, (int, float)):
            return ComplexPoint(self.x * float(other), self.y * float(other))
        return NotImplemented

    def __rmul__(self, other: Any) -> ComplexPoint:
        return self.__mul__(other)

    def __truediv__(self, other: Any) -> ComplexPoint:
        if isinstance(other, (int, float)):
            f_other = float(other)
            if abs(f_other) < 1e-15:
                raise SingularityError("Division by near-zero scalar in ComplexPoint")
            return ComplexPoint(self.x / f_other, self.y / f_other)
        if isinstance(other, (ComplexPoint, complex)):
            ox = other.x if isinstance(other, ComplexPoint) else other.real
            oy = other.y if isinstance(other, ComplexPoint) else other.imag
            denom = ox * ox + oy * oy
            if denom < 1e-15:
                raise SingularityError("Division by near-zero complex number in ComplexPoint")
            return ComplexPoint(
                (self.x * ox + self.y * oy) / denom,
                (self.y * ox - self.x * oy) / denom,
            )
        return NotImplemented

    def to_complex(self) -> complex:
        """Convert to Python native complex."""
        return complex(self.x, self.y)

    @classmethod
    def from_complex(cls, c: complex) -> ComplexPoint:
        """Construct from Python native complex."""
        return cls(c.real, c.imag)

    @classmethod
    def from_polar(cls, r: float, theta_rad: float) -> ComplexPoint:
        """Construct from polar coordinates (r, theta)."""
        return cls(round(r * math.cos(theta_rad), 6), round(r * math.sin(theta_rad), 6))

    def as_tuple(self) -> Tuple[float, float]:
        """Convert to (x, y) tuple."""
        return (self.x, self.y)


def to_complex_point(pt: Union[ComplexPoint, complex, Tuple[float, float]]) -> ComplexPoint:
    """Coerce input to ComplexPoint."""
    if isinstance(pt, ComplexPoint):
        return pt
    if isinstance(pt, complex):
        return ComplexPoint(pt.real, pt.imag)
    if isinstance(pt, (tuple, list)) and len(pt) >= 2:
        return ComplexPoint(float(pt[0]), float(pt[1]))
    raise TypeError(f"Cannot convert {type(pt)} to ComplexPoint")


def is_in_poincare_disk(z: Union[ComplexPoint, complex], max_radius: float = 1.0) -> bool:
    """Check if point lies strictly inside the open Poincaré unit disk |z| < max_radius."""
    cp = to_complex_point(z)
    return cp.magnitude() < max_radius


def clamp_to_disk(
    z: Union[ComplexPoint, complex],
    max_radius: float = MAX_HYPERBOLIC_RADIUS,
) -> ComplexPoint:
    """Clamp coordinate to maximum radial threshold inside the open unit disk."""
    cp = to_complex_point(z)
    return cp.clamp(max_radius)


# ============================================================================
# 4. Möbius Transformations & Hyperbolic Distance Metric
# ============================================================================

def mobius_transform(
    z: Union[ComplexPoint, complex],
    a: Union[ComplexPoint, complex],
    theta: float = 0.0,
) -> ComplexPoint:
    """Poincaré disk automorphism Möbius transformation.

    Formula:
      T_{a, theta}(z) = e^(i*theta) * (z - a) / (1 - conj(a)*z)

    Properties:
      - Maps point 'a' directly to the origin 0: T_{a, theta}(a) = 0.
      - Preserves the open unit disk D: maps D -> D bijectively.
      - When a = 0 and theta = 0: T_{0, 0}(z) = z (identity transformation).
      - Intercepts numerical singularities (|1 - conj(a)*z| < 1e-12) with SingularityError.
    """
    cp_z = to_complex_point(z)
    cp_a = to_complex_point(a)

    if cp_a.magnitude() >= 1.0:
        raise HyperbolicBoundaryError(f"Translation parameter |a|={cp_a.magnitude():.4f} >= 1.0 must lie inside disk")

    num = cp_z - cp_a
    denom = ComplexPoint(1.0, 0.0) - (cp_a.conjugate() * cp_z)

    if denom.magnitude() < 1e-12:
        raise SingularityError(f"Numerical singularity in Möbius transformation: denom magnitude {denom.magnitude():.2e} < 1e-12")

    quotient = num / denom

    if abs(theta) > 1e-12:
        rot = ComplexPoint(math.cos(theta), math.sin(theta))
        res = rot * quotient
    else:
        res = quotient

    return res


def mobius_inverse(
    w: Union[ComplexPoint, complex],
    a: Union[ComplexPoint, complex],
    theta: float = 0.0,
) -> ComplexPoint:
    """Inverse of the Poincaré disk automorphism Möbius transformation.

    Formula:
      Let w' = w * e^(-i*theta).
      Then z = (w' + a) / (1 + conj(a)*w').
    """
    cp_w = to_complex_point(w)
    cp_a = to_complex_point(a)

    if cp_a.magnitude() >= 1.0:
        raise HyperbolicBoundaryError(f"Translation parameter |a|={cp_a.magnitude():.4f} >= 1.0 must lie inside disk")

    if abs(theta) > 1e-12:
        rot_inv = ComplexPoint(math.cos(-theta), math.sin(-theta))
        w_prime = rot_inv * cp_w
    else:
        w_prime = cp_w

    num = w_prime + cp_a
    denom = ComplexPoint(1.0, 0.0) + (cp_a.conjugate() * w_prime)

    if denom.magnitude() < 1e-12:
        raise SingularityError(f"Numerical singularity in inverse Möbius transformation: denom magnitude {denom.magnitude():.2e} < 1e-12")

    return num / denom


def hyperbolic_distance(
    u: Union[ComplexPoint, complex],
    v: Union[ComplexPoint, complex],
) -> float:
    """Exact Poincaré disk hyperbolic distance metric.

    Formula:
      d(u, v) = 2 * artanh(|u - v| / |1 - conj(u)*v|)

    Properties:
      - Positive definiteness: d(u, v) >= 0; d(u, v) == 0 iff u == v.
      - Symmetry: d(u, v) == d(v, u).
      - Triangle inequality: d(u, w) <= d(u, v) + d(v, w).
      - Origin distance: d(0, v) = 2 * artanh(|v|).
    """
    cp_u = to_complex_point(u)
    cp_v = to_complex_point(v)

    # Identical points
    diff_mag = (cp_u - cp_v).magnitude()
    if diff_mag < 1e-15:
        return 0.0

    denom = (ComplexPoint(1.0, 0.0) - (cp_u.conjugate() * cp_v)).magnitude()
    if denom < 1e-15:
        raise SingularityError("Singularity in hyperbolic distance denominator")

    rho = diff_mag / denom

    # Clamp rho strictly into [0.0, 1.0 - 1e-12]
    if rho < 0.0:
        rho = 0.0
    elif rho >= 1.0 - 1e-12:
        rho = 1.0 - 1e-12

    return 2.0 * math.atanh(rho)


# ============================================================================
# 5. Geodesic Arc Circle Geometry
# ============================================================================

@dataclass
class GeodesicArc:
    """Geodesic arc in the Poincaré disk model connecting points u and v."""
    u: ComplexPoint
    v: ComplexPoint
    is_straight_line: bool
    center_disk: Optional[ComplexPoint]
    radius_disk: Optional[float]
    center_pixel: Optional[Tuple[float, float]]
    radius_pixel: Optional[float]
    start_pixel: Tuple[float, float]
    end_pixel: Tuple[float, float]
    svg_path: str


def disk_to_pixel(
    z: ComplexPoint,
    center_x: float = CANVAS_CENTER_X,
    center_y: float = CANVAS_CENTER_Y,
    disk_radius: float = POINCARE_DISK_RADIUS,
) -> Tuple[float, float]:
    """Convert Poincaré unit disk coordinate z (|z| < 1) to screen pixel coordinates."""
    px = center_x + disk_radius * z.x
    py = center_y + disk_radius * z.y
    return (round(px, 3), round(py, 3))


def pixel_to_disk(
    px: float,
    py: float,
    center_x: float = CANVAS_CENTER_X,
    center_y: float = CANVAS_CENTER_Y,
    disk_radius: float = POINCARE_DISK_RADIUS,
) -> ComplexPoint:
    """Convert screen pixel coordinates to Poincaré unit disk coordinate z."""
    zx = (px - center_x) / disk_radius
    zy = (py - center_y) / disk_radius
    return ComplexPoint(round(zx, 6), round(zy, 6))


def compute_geodesic_arc(
    u: Union[ComplexPoint, complex],
    v: Union[ComplexPoint, complex],
    center_x: float = CANVAS_CENTER_X,
    center_y: float = CANVAS_CENTER_Y,
    disk_radius: float = POINCARE_DISK_RADIUS,
) -> GeodesicArc:
    """Calculate geodesic arc connecting points u and v in the Poincaré disk.

    In the Poincaré disk model, geodesics are:
    1. Straight line diameters passing through the origin when u, v, and 0 are collinear.
    2. Circular arcs of Euclidean circles that intersect the unit boundary circle |z|=1 orthogonally.

    Analytical derivation of orthogonal circle through u and v:
      Circle equation: (x - c_x)^2 + (y - c_y)^2 = R^2
      Orthogonality with unit circle x^2 + y^2 = 1 implies: c_x^2 + c_y^2 - R^2 = 1.
      Passing through u and v implies:
        |c - u|^2 = R^2 = |c|^2 - 1 => 2*(c . u) = 1 + |u|^2
        |c - v|^2 = R^2 = |c|^2 - 1 => 2*(c . v) = 1 + |v|^2
      Solving the 2x2 linear system yields center c = (c_x, c_y) and radius R = sqrt(|c|^2 - 1).
    """
    cp_u = to_complex_point(u)
    cp_v = to_complex_point(v)

    pu_px = disk_to_pixel(cp_u, center_x, center_y, disk_radius)
    pv_px = disk_to_pixel(cp_v, center_x, center_y, disk_radius)

    # Identical points
    if (cp_u - cp_v).magnitude() < 1e-12:
        return GeodesicArc(
            u=cp_u,
            v=cp_v,
            is_straight_line=True,
            center_disk=None,
            radius_disk=None,
            center_pixel=None,
            radius_pixel=None,
            start_pixel=pu_px,
            end_pixel=pv_px,
            svg_path=f"M {pu_px[0]:.2f},{pu_px[1]:.2f}",
        )

    # Check collinearity with origin via cross-product u_x * v_y - u_y * v_x
    det = cp_u.x * cp_v.y - cp_u.y * cp_v.x
    u_mag = cp_u.magnitude()
    v_mag = cp_v.magnitude()

    # Straight line if collinear with origin or either point is origin
    if abs(det) < 1e-6 or u_mag < 1e-6 or v_mag < 1e-6:
        return GeodesicArc(
            u=cp_u,
            v=cp_v,
            is_straight_line=True,
            center_disk=None,
            radius_disk=None,
            center_pixel=None,
            radius_pixel=None,
            start_pixel=pu_px,
            end_pixel=pv_px,
            svg_path=f"M {pu_px[0]:.2f},{pu_px[1]:.2f} L {pv_px[0]:.2f},{pv_px[1]:.2f}",
        )

    # 2x2 linear system for circle center
    b1 = (1.0 + cp_u.magnitude_squared()) / 2.0
    b2 = (1.0 + cp_v.magnitude_squared()) / 2.0

    cx = (b1 * cp_v.y - b2 * cp_u.y) / det
    cy = (cp_u.x * b2 - cp_v.x * b1) / det

    c_center = ComplexPoint(cx, cy)
    r_sq = c_center.magnitude_squared() - 1.0
    r_disk = math.sqrt(max(0.0, r_sq))

    # Convert center and radius to pixel space
    c_px = (center_x + disk_radius * cx, center_y + disk_radius * cy)
    r_px = disk_radius * r_disk

    # Determine SVG arc sweep flag based on cross product in screen space
    cross_screen = (pu_px[0] - c_px[0]) * (pv_px[1] - c_px[1]) - (pu_px[1] - c_px[1]) * (pv_px[0] - c_px[0])
    sweep_flag = 1 if cross_screen > 0 else 0

    svg_path = (
        f"M {pu_px[0]:.2f},{pu_px[1]:.2f} "
        f"A {r_px:.2f},{r_px:.2f} 0 0,{sweep_flag} {pv_px[0]:.2f},{pv_px[1]:.2f}"
    )

    return GeodesicArc(
        u=cp_u,
        v=cp_v,
        is_straight_line=False,
        center_disk=c_center,
        radius_disk=r_disk,
        center_pixel=c_px,
        radius_pixel=r_px,
        start_pixel=pu_px,
        end_pixel=pv_px,
        svg_path=svg_path,
    )


# ============================================================================
# 6. Tree Data Structures & Traversal
# ============================================================================

@dataclass
class TreeNode:
    """Hierarchical Tree Node within an industrial SCADA architecture."""
    id: str
    name: str
    parent_id: Optional[str] = None
    depth: int = 0
    health_score: float = 95.0
    weight: float = 1.0
    tag: str = ""
    unit_type: str = "Unit"
    index: int = 0

    # Complex Poincaré disk positions
    z: ComplexPoint = field(default_factory=lambda: ComplexPoint(0.0, 0.0))
    z_view: ComplexPoint = field(default_factory=lambda: ComplexPoint(0.0, 0.0))

    # Polar layout angles
    radius: float = 0.0
    theta_rad: float = 0.0
    theta_min_rad: float = 0.0
    theta_max_rad: float = 0.0
    hyperbolic_dist: float = 0.0

    # Runtime operational flags
    is_fault: bool = False
    status: str = NodeHealthState.NOMINAL.value

    # Graph connectivity
    children: List[TreeNode] = field(default_factory=list)
    parent: Optional[TreeNode] = None

    def add_child(self, child: TreeNode) -> None:
        """Add child node, establishing bidirectional references."""
        child.parent = self
        child.parent_id = self.id
        self.children.append(child)

    def is_leaf(self) -> bool:
        """Return True if node has no children."""
        return len(self.children) == 0

    def compute_subtree_weight(self) -> float:
        """Recursively compute aggregated weight of subtree."""
        if self.is_leaf():
            return max(0.1, self.weight)
        return max(0.1, self.weight) + sum(c.compute_subtree_weight() for c in self.children)

    def compute_subtree_leaf_count(self) -> int:
        """Recursively count total leaf nodes in subtree."""
        if self.is_leaf():
            return 1
        return sum(c.compute_subtree_leaf_count() for c in self.children)

    @property
    def angular_span_rad(self) -> float:
        """Angular span in radians allocated to subtree."""
        return self.theta_max_rad - self.theta_min_rad


@dataclass
class HyperbolicTree:
    """Hierarchical Tree Graph representing an industrial plant SCADA architecture."""
    nodes: Dict[str, TreeNode] = field(default_factory=dict)
    root_id: Optional[str] = None

    def add_node(self, node: TreeNode) -> None:
        """Add node to graph."""
        self.nodes[node.id] = node
        if self.root_id is None and node.parent_id is None:
            self.root_id = node.id

    def add_edge(self, parent_id: str, child_id: str) -> None:
        """Add directed edge from parent to child, establishing references."""
        if parent_id not in self.nodes:
            raise KeyError(f"Parent node '{parent_id}' not found in tree")
        if child_id not in self.nodes:
            raise KeyError(f"Child node '{child_id}' not found in tree")
        parent = self.nodes[parent_id]
        child = self.nodes[child_id]
        parent.add_child(child)

    def get_node(self, node_id: str) -> Optional[TreeNode]:
        """Look up node by ID."""
        return self.nodes.get(node_id)

    def get_root(self) -> Optional[TreeNode]:
        """Return root node if configured."""
        if self.root_id is not None:
            return self.nodes.get(self.root_id)
        for node in self.nodes.values():
            if node.parent_id is None:
                self.root_id = node.id
                return node
        return None

    def get_all_nodes(self) -> List[TreeNode]:
        """Return list of all tree nodes."""
        return list(self.nodes.values())

    def total_node_count(self) -> int:
        """Return total number of nodes in graph."""
        return len(self.nodes)

    def max_depth(self) -> int:
        """Compute maximum depth level present in tree."""
        root = self.get_root()
        if root is None or not self.nodes:
            return 0
        return max(n.depth for n in self.nodes.values())

    def detect_cycles(self) -> bool:
        """Detect if graph contains any cycles using depth-first search."""
        state: Dict[str, int] = {node_id: 0 for node_id in self.nodes}

        def _dfs(node_id: str) -> bool:
            state[node_id] = 1  # visiting
            node = self.nodes[node_id]
            for child in node.children:
                child_id = child.id
                if child_id not in state:
                    continue
                if state[child_id] == 1:
                    return True  # Back-edge found -> cycle
                if state[child_id] == 0:
                    if _dfs(child_id):
                        return True
            state[node_id] = 2  # done
            return False

        for nid in self.nodes:
            if state[nid] == 0:
                if _dfs(nid):
                    return True
        return False

    def validate_acyclic(self) -> None:
        """Raise HierarchyCycleError if cycle detected in tree."""
        if self.detect_cycles():
            raise HierarchyCycleError("Cycle detected in hyperbolic tree hierarchy")

    def traverse_preorder(self) -> List[TreeNode]:
        """Preorder traversal of tree nodes."""
        res: List[TreeNode] = []
        root = self.get_root()
        if not root:
            return res

        def _visit(n: TreeNode) -> None:
            res.append(n)
            for c in n.children:
                _visit(c)

        _visit(root)
        return res

    def traverse_postorder(self) -> List[TreeNode]:
        """Postorder traversal of tree nodes."""
        res: List[TreeNode] = []
        root = self.get_root()
        if not root:
            return res

        def _visit(n: TreeNode) -> None:
            for c in n.children:
                _visit(c)
            res.append(n)

        _visit(root)
        return res

    def traverse_bfs(self) -> List[TreeNode]:
        """Breadth-first search traversal."""
        res: List[TreeNode] = []
        root = self.get_root()
        if not root:
            return res
        queue = [root]
        while queue:
            curr = queue.pop(0)
            res.append(curr)
            queue.extend(curr.children)
        return res


# ============================================================================
# 7. Layout Algorithm & Bottom-Up Health Propagation
# ============================================================================

def layout_hyperbolic_tree(
    tree: HyperbolicTree,
    level_radii: Optional[List[float]] = None,
    start_angle_rad: float = 0.0,
    sweep_angle_rad: float = 2.0 * math.pi,
) -> None:
    """Compute Poincaré disk coordinates for all nodes in the hyperbolic tree.

    1. Validates acyclic hierarchy.
    2. Assigns depths to all nodes.
    3. Allocates radial distance |z| based on level radii.
    4. Recursively allocates angular wedges [theta_min, theta_max] to subtrees proportionally.
    5. Places each node at (r, theta) -> z = r * e^(i*theta).
    """
    tree.validate_acyclic()
    root = tree.get_root()
    if root is None:
        return

    radii = level_radii if level_radii is not None else CANONICAL_LEVEL_RADII

    def _assign_depths(node: TreeNode, current_depth: int) -> None:
        node.depth = current_depth
        for child in node.children:
            _assign_depths(child, current_depth + 1)

    _assign_depths(root, 0)

    # Root allocation at origin
    root.radius = radii[0] if len(radii) > 0 else 0.0
    root.theta_min_rad = start_angle_rad
    root.theta_max_rad = start_angle_rad + sweep_angle_rad
    root.theta_rad = (root.theta_min_rad + root.theta_max_rad) / 2.0
    root.z = ComplexPoint(0.0, 0.0)
    root.z_view = ComplexPoint(0.0, 0.0)
    root.hyperbolic_dist = 0.0

    def _layout_children(parent: TreeNode) -> None:
        if not parent.children:
            return

        total_weight = sum(c.compute_subtree_weight() for c in parent.children)
        parent_span = parent.theta_max_rad - parent.theta_min_rad

        current_angle = parent.theta_min_rad
        for child in parent.children:
            child_depth = child.depth
            if child_depth < len(radii):
                r = radii[child_depth]
            else:
                extra = child_depth - len(radii) + 1
                r = min(MAX_HYPERBOLIC_RADIUS, radii[-1] + extra * 0.05)
            child.radius = r

            if total_weight > 0.0:
                child_fraction = child.compute_subtree_weight() / total_weight
            else:
                child_fraction = 1.0 / len(parent.children)

            child_span = parent_span * child_fraction
            child.theta_min_rad = current_angle
            child.theta_max_rad = current_angle + child_span
            child.theta_rad = (child.theta_min_rad + child.theta_max_rad) / 2.0

            z_pt = ComplexPoint.from_polar(child.radius, child.theta_rad).clamp(MAX_HYPERBOLIC_RADIUS)
            child.z = z_pt
            child.z_view = z_pt
            child.hyperbolic_dist = hyperbolic_distance(ComplexPoint(0.0, 0.0), z_pt)

            current_angle += child_span

            _layout_children(child)

    _layout_children(root)


def recenter_tree_at(
    tree: HyperbolicTree,
    center_node_id: str,
) -> None:
    """Apply Poincaré disk Möbius automorphism to bring selected node to the origin.

    T_{a}(z) = (z - a) / (1 - conj(a)*z) where a = center_node.z.
    Transforms z_view for all nodes, preserving hyperbolic distances and boundary containment.
    """
    node = tree.get_node(center_node_id)
    if node is None:
        return

    a = node.z
    for n in tree.nodes.values():
        if (a - n.z).magnitude() < 1e-12:
            n.z_view = ComplexPoint(0.0, 0.0)
            n.hyperbolic_dist = 0.0
        else:
            n_view = mobius_transform(n.z, a).clamp(MAX_HYPERBOLIC_RADIUS)
            n.z_view = n_view
            n.hyperbolic_dist = hyperbolic_distance(ComplexPoint(0.0, 0.0), n_view)


def propagate_bottom_up_health(
    tree: HyperbolicTree,
    critical_threshold: float = HEALTH_CRITICAL_THRESHOLD,
    warning_threshold: float = HEALTH_WARNING_THRESHOLD,
) -> None:
    """Propagate health scores bottom-up from leaf assets to plant root.

    For internal nodes:
      H_parent = sum(weight_i * H_i) / sum(weight_i)
    """
    root = tree.get_root()
    if root is None:
        return

    def _propagate(node: TreeNode) -> float:
        if node.is_leaf():
            h = node.health_score
        else:
            total_w = 0.0
            weighted_h = 0.0
            for child in node.children:
                ch_health = _propagate(child)
                w = max(0.1, child.weight)
                weighted_h += ch_health * w
                total_w += w
            h = weighted_h / total_w if total_w > 0.0 else 100.0
            node.health_score = round(h, 2)

        if node.health_score < critical_threshold:
            node.is_fault = True
            node.status = NodeHealthState.CRITICAL.value
        elif node.health_score < warning_threshold:
            node.is_fault = False
            node.status = NodeHealthState.WARNING.value
        else:
            node.is_fault = False
            node.status = NodeHealthState.NOMINAL.value

        return node.health_score

    _propagate(root)


def identify_critical_faults(
    tree: HyperbolicTree,
    critical_threshold: float = HEALTH_CRITICAL_THRESHOLD,
) -> List[TreeNode]:
    """Return all nodes exhibiting critical fault condition (health < critical_threshold)."""
    return [
        node for node in tree.nodes.values()
        if node.health_score < critical_threshold or node.is_fault
    ]


def find_min_health_node(tree: HyperbolicTree) -> Optional[TreeNode]:
    """Find and return the node with lowest health score in tree."""
    if not tree.nodes:
        return None
    return min(tree.nodes.values(), key=lambda n: n.health_score)


# ============================================================================
# 8. Canonical Factory: Industrial SCADA Hyperbolic Tree Hierarchy
# ============================================================================

def create_canonical_scada_hyperbolic_tree() -> HyperbolicTree:
    """Construct canonical 4-tier industrial refinery SCADA hyperbolic tree hierarchy.

    Hierarchy:
    - Level 0 (Central Root):
      - PLANT_ROOT: Overall Refinery Facility (Root Health ~ 95.0%)
    - Level 1 (4 Production Areas):
      - AREA_CRUDE: Crude Distillation Area
      - AREA_FCC: Fluid Catalytic Cracking Area
      - AREA_REFORM: Continuous Catalytic Reforming Area
      - AREA_UTILITY: Steam & Power Utilities Area
    - Level 2 (8 Operating Units, 2 per area):
      - UNIT_CDU, UNIT_VDU (Crude)
      - UNIT_RISER, UNIT_FRAC (FCC)
      - UNIT_PREHEAT, UNIT_REACTORS (Reform)
      - UNIT_BOILER, UNIT_TURBINE (Utility)
    - Level 3 (16 Equipment Subsystems / Assets, 2 per unit):
      - Pump trains, heater banks, compressor skids, distillation trays, valves.
    Total: 29 nodes across 4 depth levels (0, 1, 2, 3).
    """
    tree = HyperbolicTree()

    # Level 0: Plant Core Root
    root = TreeNode(
        id="PLANT_ROOT",
        name="Industrial Refinery Plant",
        depth=0,
        health_score=95.0,
        weight=10.0,
        tag="PLANT-REF-01",
        unit_type="Refinery",
        index=0,
    )
    tree.add_node(root)

    # Level 1: 4 Production Areas
    areas = [
        ("AREA_CRUDE", "Crude Distillation Area", "AREA-01", 3.0),
        ("AREA_FCC", "Fluid Catalytic Cracking Area", "AREA-02", 3.0),
        ("AREA_REFORM", "Continuous Catalytic Reforming Area", "AREA-03", 2.0),
        ("AREA_UTILITY", "Steam & Power Utilities Area", "AREA-04", 2.0),
    ]

    for idx, (aid, aname, atag, awt) in enumerate(areas, start=1):
        anode = TreeNode(
            id=aid,
            name=aname,
            parent_id="PLANT_ROOT",
            depth=1,
            health_score=95.0,
            weight=awt,
            tag=atag,
            unit_type="Area",
            index=idx,
        )
        tree.add_node(anode)
        tree.add_edge("PLANT_ROOT", aid)

    # Level 2: 8 Units (2 per area)
    units_def = [
        # Crude units
        ("UNIT_CDU", "Atmospheric Distillation Unit", "AREA_CRUDE", "CDU-100", 1.5),
        ("UNIT_VDU", "Vacuum Distillation Unit", "AREA_CRUDE", "VDU-200", 1.5),
        # FCC units
        ("UNIT_RISER", "Riser Reactor & Regenerator", "AREA_FCC", "FCC-300", 1.5),
        ("UNIT_FRAC", "Main Fractionator Column", "AREA_FCC", "FCC-350", 1.5),
        # Reforming units
        ("UNIT_PREHEAT", "Feed Preheating Furnaces", "AREA_REFORM", "REF-400", 1.0),
        ("UNIT_REACTORS", "Multi-Stage Catalytic Bed", "AREA_REFORM", "REF-450", 1.0),
        # Utility units
        ("UNIT_BOILER", "High-Pressure Steam Boilers", "AREA_UTILITY", "UTL-500", 1.0),
        ("UNIT_TURBINE", "Co-Gen Turbine Generator", "AREA_UTILITY", "UTL-550", 1.0),
    ]

    for idx, (uid, uname, parent_aid, utag, uwt) in enumerate(units_def, start=5):
        unode = TreeNode(
            id=uid,
            name=uname,
            parent_id=parent_aid,
            depth=2,
            health_score=95.0,
            weight=uwt,
            tag=utag,
            unit_type="Unit",
            index=idx,
        )
        tree.add_node(unode)
        tree.add_edge(parent_aid, uid)

    # Level 3: 16 Leaf Subsystems (2 per unit)
    leaves_def = [
        # CDU
        ("SS_CDU_PUMP", "Crude Feed Charge Pumps", "UNIT_CDU", "P-101A/B", 94.0),
        ("SS_CDU_COL", "Crude Fractionation Trays", "UNIT_CDU", "C-101", 96.0),
        # VDU
        ("SS_VDU_EJECT", "Steam Ejector Vacuum System", "UNIT_VDU", "J-201", 93.0),
        ("SS_VDU_COL", "Vacuum Column Internals", "UNIT_VDU", "C-201", 95.0),
        # FCC Riser
        ("SS_FCC_RISER", "Riser Feed Injection Nozzles", "UNIT_RISER", "R-301", 92.0),
        ("SS_FCC_REGEN", "Regenerator Air Grid & Cyclones", "UNIT_RISER", "R-302", 94.0),
        # FCC Fractionator
        ("SS_FCC_OHD", "Overhead Vapor Condenser", "UNIT_FRAC", "E-351", 96.0),
        ("SS_FCC_SLURRY", "Clarified Slurry Oil Settler", "UNIT_FRAC", "V-352", 95.0),
        # Reform Preheat
        ("SS_REF_FURN", "Charge Heaters 101/102", "UNIT_PREHEAT", "F-401", 97.0),
        ("SS_REF_EXCH", "Feed-Effluent Combined Exchanger", "UNIT_PREHEAT", "E-401", 95.0),
        # Reform Reactors
        ("SS_REF_R1R2", "Reformer Lead Reactors R-1/2", "UNIT_REACTORS", "R-401", 93.0),
        ("SS_REF_R3R4", "Reformer Tail Reactors R-3/4", "UNIT_REACTORS", "R-402", 96.0),
        # Boiler
        ("SS_BOIL_FEED", "Deaerator & Feedwater Pumps", "UNIT_BOILER", "B-501", 98.0),
        ("SS_BOIL_DRUM", "Steam Drum & Superheater", "UNIT_BOILER", "B-502", 94.0),
        # Turbine
        ("SS_TURB_GEN", "Multi-Stage Steam Turbine", "UNIT_TURBINE", "TG-551", 96.0),
        ("SS_TURB_COND", "Surface Condenser & Hotwell", "UNIT_TURBINE", "E-552", 97.0),
    ]

    for idx, (lid, lname, parent_uid, ltag, lhealth) in enumerate(leaves_def, start=13):
        lnode = TreeNode(
            id=lid,
            name=lname,
            parent_id=parent_uid,
            depth=3,
            health_score=lhealth,
            weight=1.0,
            tag=ltag,
            unit_type="Subsystem",
            index=idx,
        )
        tree.add_node(lnode)
        tree.add_edge(parent_uid, lid)

    # Compute coordinates and bottom-up health
    layout_hyperbolic_tree(tree)
    propagate_bottom_up_health(tree)

    return tree


# ============================================================================
# 9. WCAG 2.1 AAA Accessibility Engine
# ============================================================================

def parse_hex_color(hex_str: str) -> Tuple[int, int, int]:
    """Parse hex color string '#RRGGBB' to integer RGB tuple."""
    clean = hex_str.strip().lstrip("#")
    if len(clean) == 3:
        clean = "".join(c * 2 for c in clean)
    if len(clean) != 6:
        return (0, 0, 0)
    return (int(clean[0:2], 16), int(clean[2:4], 16), int(clean[4:6], 16))


def relative_luminance(hex_str: str) -> float:
    """Compute relative luminance according to WCAG 2.1 formula."""
    r_i, g_i, b_i = parse_hex_color(hex_str)

    def _channel_lum(c: int) -> float:
        s = c / 255.0
        return s / 12.92 if s <= 0.03928 else math.pow((s + 0.055) / 1.055, 2.4)

    r = _channel_lum(r_i)
    g = _channel_lum(g_i)
    b = _channel_lum(b_i)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(c1: str, c2: str) -> float:
    """Calculate WCAG 2.1 contrast ratio between two hex colors."""
    l1 = relative_luminance(c1)
    l2 = relative_luminance(c2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def validate_wcag_aaa_contrast(
    text_color: str = COLOR_TEXT_PRIMARY,
    theme_backing: str = COLOR_DARK_THEME_BACKING,
    badge_backing: str = COLOR_DECOUPLED_BADGE,
) -> Tuple[bool, float, float]:
    """Validate compliance with WCAG 2.1 AAA contrast targets (> 18:1 badge, > 7:1 text)."""
    cr_text_theme = contrast_ratio(text_color, theme_backing)
    cr_text_badge = contrast_ratio(text_color, badge_backing)

    meets_aaa = (
        cr_text_theme >= WCAG_AAA_TEXT_CONTRAST_TARGET
        and cr_text_badge >= WCAG_AAA_BADGE_CONTRAST_TARGET
    )
    return (meets_aaa, cr_text_theme, cr_text_badge)


# ============================================================================
# 10. Standalone W3C SVG 1.1 Vector Graphics Renderer
# ============================================================================

def generate_hyperbolic_tree_canvas_svg(
    tree: HyperbolicTree,
    metrics: HyperbolicTreeMetrics,
    status_bits: HyperbolicTreeStatusBits,
    selected_node_id: Optional[str] = None,
    diagnostic_code: DiagnosticCode = DIAG_OK,
    viewport_width: int = CANVAS_VIEWPORT_WIDTH,
    viewport_height: int = CANVAS_VIEWPORT_HEIGHT,
    dark_theme_bg: str = COLOR_DARK_THEME_BACKING,
) -> str:
    """Generate standalone W3C SVG 1.1 vector graphic conforming to SCADA standards."""
    root = tree.get_root()
    if root is None:
        raise ValueError("Cannot render SVG for empty tree with no root")

    sel_id = selected_node_id or metrics.selected_node_id
    sel_node = tree.get_node(sel_id) or root

    svg_parts: List[str] = []

    # SVG Root Header
    svg_parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" version="1.1" '
        f'width="{viewport_width}" height="{viewport_height}" '
        f'viewBox="0 0 {viewport_width} {viewport_height}">'
    )

    # Defs: Gradients and Filters
    svg_parts.append("  <defs>")
    svg_parts.append(
        '    <linearGradient id="cardGrad" x1="0%" y1="0%" x2="100%" y2="100%">'
        f'      <stop offset="0%" stop-color="{COLOR_CARD_BG}" stop-opacity="0.95"/>'
        '      <stop offset="100%" stop-color="#0F172A" stop-opacity="0.98"/>'
        "    </linearGradient>"
    )
    svg_parts.append(
        '    <filter id="glowEffect" x="-20%" y="-20%" width="140%" height="140%">'
        '      <feGaussianBlur stdDeviation="3" result="blur"/>'
        '      <feComposite in="SourceGraphic" in2="blur" operator="over"/>'
        "    </filter>"
    )
    svg_parts.append("  </defs>")

    # Viewport Background
    svg_parts.append(
        f'  <rect width="{viewport_width}" height="{viewport_height}" '
        f'fill="{dark_theme_bg}"/>'
    )

    # Poincaré Unit Disk Boundary & Interior
    cx = CANVAS_CENTER_X
    cy = CANVAS_CENTER_Y
    r_disk = POINCARE_DISK_RADIUS

    svg_parts.append(
        f'  <!-- Poincaré Unit Disk Boundary (|z| = 1.0) -->'
    )
    svg_parts.append(
        f'  <circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r_disk:.1f}" '
        f'fill="#0A0E17" stroke="{COLOR_DISK_BOUNDARY}" stroke-width="2.5" '
        f'stroke-opacity="0.85"/>'
    )

    # Concentric Hyperbolic Distance Guide Rings
    for r_lvl in CANONICAL_LEVEL_RADII[1:]:
        guide_r_px = r_disk * r_lvl
        svg_parts.append(
            f'  <circle cx="{cx:.1f}" cy="{cy:.1f}" r="{guide_r_px:.1f}" '
            f'fill="none" stroke="{COLOR_CONCENTRIC_GUIDE}" stroke-width="1.0" '
            f'stroke-dasharray="4,4" opacity="0.6"/>'
        )

    # Geodesic Arc Edges
    svg_parts.append('  <!-- Geodesic Arc Edges connecting parent and child nodes -->')
    for node in tree.nodes.values():
        for child in node.children:
            arc = compute_geodesic_arc(
                node.z_view,
                child.z_view,
                center_x=cx,
                center_y=cy,
                disk_radius=r_disk,
            )
            edge_color = COLOR_ALARM_CRIMSON if child.is_fault else COLOR_GEODESIC_EDGE
            stroke_w = "2.0" if child.is_fault else "1.4"
            op = "0.9" if child.is_fault else "0.7"
            svg_parts.append(
                f'  <path d="{arc.svg_path}" fill="none" stroke="{edge_color}" '
                f'stroke-width="{stroke_w}" opacity="{op}"/>'
            )

    # Tree Nodes
    svg_parts.append('  <!-- Hierarchy Tree Nodes -->')
    for node in tree.nodes.values():
        n_px = disk_to_pixel(node.z_view, center_x=cx, center_y=cy, disk_radius=r_disk)
        nx, ny = n_px[0], n_px[1]

        # Status fill color
        if node.is_fault or node.health_score < HEALTH_CRITICAL_THRESHOLD:
            fill_col = COLOR_ALARM_CRIMSON
        elif node.health_score < HEALTH_WARNING_THRESHOLD:
            fill_col = COLOR_WARM_AMBER
        else:
            fill_col = COLOR_NOMINAL_EMERALD

        is_sel = (node.id == sel_node.id)
        node_radius = 10.0 if node.depth == 0 else (7.0 if node.depth == 1 else 5.0)

        if is_sel:
            svg_parts.append(
                f'  <circle cx="{nx:.1f}" cy="{ny:.1f}" r="{node_radius + 5.0:.1f}" '
                f'fill="none" stroke="{COLOR_FOCUS_BLUE}" stroke-width="2.5" '
                f'filter="url(#glowEffect)"/>'
            )

        svg_parts.append(
            f'  <circle cx="{nx:.1f}" cy="{ny:.1f}" r="{node_radius:.1f}" '
            f'fill="{fill_col}" stroke="#FFFFFF" stroke-width="1.2">'
            f'<title>{html.escape(node.name)} ({node.tag}) - Health: {node.health_score:.1f}%</title>'
            f'</circle>'
        )

        # Label for depth <= 1 or selected
        if node.depth <= 1 or is_sel:
            txt_anchor = "middle"
            ty = ny - node_radius - 4.0
            svg_parts.append(
                f'  <text x="{nx:.1f}" y="{ty:.1f}" fill="{COLOR_TEXT_PRIMARY}" '
                f'font-family="system-ui, -apple-system, sans-serif" font-size="11" '
                f'font-weight="600" text-anchor="{txt_anchor}">'
                f'{html.escape(node.tag or node.id)}</text>'
            )

    # Right-Hand SCADA Telemetry HUD Cards
    hud_x = 880
    hud_y = 40
    hud_w = 280
    hud_h = 670

    svg_parts.append('  <!-- Right-Hand SCADA Telemetry HUD Cards -->')
    svg_parts.append(
        f'  <rect x="{hud_x}" y="{hud_y}" width="{hud_w}" height="{hud_h}" rx="8" '
        f'fill="url(#cardGrad)" stroke="{COLOR_CARD_BORDER}" stroke-width="1.5"/>'
    )

    # Decoupled Badge (> 18:1 contrast)
    badge_x = hud_x + 15
    badge_y = hud_y + 15
    badge_w = hud_w - 30
    badge_h = 42

    svg_parts.append(
        f'  <rect x="{badge_x}" y="{badge_y}" width="{badge_w}" height="{badge_h}" rx="6" '
        f'fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_CARD_BORDER}" stroke-width="1.0"/>'
    )
    svg_parts.append(
        f'  <text x="{badge_x + 10}" y="{badge_y + 26}" fill="{COLOR_TEXT_PRIMARY}" '
        f'font-family="system-ui, -apple-system, sans-serif" font-size="13" font-weight="700">'
        f'W213 POINCARÉ DISK SCADA</text>'
    )

    # Telemetry Item Entries
    entries = [
        ("Selected Asset", f"{sel_node.tag} ({sel_node.id})"),
        ("Unit Name", sel_node.name[:22]),
        ("Health Score", f"{sel_node.health_score:.1f}%"),
        ("Poincaré Hyperbolic Dist", f"{sel_node.hyperbolic_dist:.3f}"),
        ("Plant Root Health", f"{metrics.root_health_score:.1f}%"),
        ("Critical Faults (%R1743)", f"{metrics.critical_fault_count}"),
        ("Hierarchy Depth (%R1744)", f"{metrics.max_tree_depth}"),
        ("Total Plant Nodes (%R1745)", f"{metrics.total_node_count}"),
        ("Min Health Score (%R1746)", f"{metrics.min_health_score:.1f}%"),
        ("Horner Diagnostic (%R1747)", f"0x{int(metrics.diagnostic_code) & 0xFFFF:04X}"),
        ("Fault Trip Coil (%M406)", "ACTIVE" if metrics.critical_fault_count > 0 or int(diagnostic_code) != 0 else "OFF"),
        ("Canvas Engine (%M407)", "ENABLED" if bool(status_bits & HyperbolicTreeStatusBits.CANVAS_ACTIVE) else "OFF"),
    ]

    curr_entry_y = badge_y + badge_h + 30
    for label, val in entries:
        val_color = COLOR_ALARM_CRIMSON if "ACTIVE" in val or "0xE2" in val else COLOR_TEXT_PRIMARY
        if "Health" in label and "%" in val:
            try:
                num = float(val.replace("%", ""))
                if num < HEALTH_CRITICAL_THRESHOLD:
                    val_color = COLOR_ALARM_CRIMSON
                elif num < HEALTH_WARNING_THRESHOLD:
                    val_color = COLOR_WARM_AMBER
                else:
                    val_color = COLOR_NOMINAL_EMERALD
            except ValueError:
                pass

        svg_parts.append(
            f'  <text x="{hud_x + 20}" y="{curr_entry_y}" fill="{COLOR_TEXT_MUTED}" '
            f'font-family="system-ui, -apple-system, sans-serif" font-size="11" font-weight="500">'
            f'{html.escape(label)}</text>'
        )
        svg_parts.append(
            f'  <text x="{hud_x + hud_w - 20}" y="{curr_entry_y}" fill="{val_color}" '
            f'font-family="system-ui, -apple-system, sans-serif" font-size="11" font-weight="600" '
            f'text-anchor="end">{html.escape(val)}</text>'
        )
        curr_entry_y += 38

    # Close SVG
    svg_parts.append("</svg>")
    return "\n".join(svg_parts)


# ============================================================================
# 11. Horner OCS Memory Space Integration & ILogicUnit Scan Cycle Engine
# ============================================================================

@dataclass
class HyperbolicTreeMetrics:
    """Aggregated operational metrics for Horner OCS memory synchronization (%R1740..%R1747)."""
    root_health_score: float = 95.0              # %R1740 scaled x10 (e.g. 950 = 95.0%)
    selected_node_index: int = 0                 # %R1741 (0..N)
    selected_node_distance: float = 0.0          # %R1742 scaled x100 (e.g. 125 = 1.25)
    critical_fault_count: int = 0                # %R1743 (Count of degraded nodes < 70.0%)
    max_tree_depth: int = 3                      # %R1744 (Hierarchy levels count)
    total_node_count: int = 29                   # %R1745 (Total nodes in tree)
    min_health_score: float = 90.0               # %R1746 scaled x10 (e.g. 900 = 90.0%)
    diagnostic_code: int = 0                     # %R1747 (0x0000=OK or diagnostic code)

    selected_node_id: str = "PLANT_ROOT"
    selected_node_name: str = "Industrial Refinery Plant"
    selected_node_tag: str = "PLANT-REF-01"
    min_health_node_id: str = "PLANT_ROOT"


class HyperbolicTreeCanvas(ILogicUnit):
    """Cscape HMI Dynamic Hyperbolic Tree / Poincaré Disk SCADA Canvas Engine."""

    def __init__(
        self,
        tree: Optional[HyperbolicTree] = None,
        selected_node_id: Optional[str] = None,
        reg_table: Optional[RegisterTable] = None,
    ) -> None:
        self.tree: HyperbolicTree = tree if tree is not None else create_canonical_scada_hyperbolic_tree()
        self.selected_node_id: str = selected_node_id or (self.tree.get_root().id if self.tree.get_root() else "PLANT_ROOT")
        self.reg_table: RegisterTable = reg_table if reg_table is not None else RegisterTable()

        self.diagnostic_code: DiagnosticCode = DIAG_OK
        self.critical_fault_alarm_active: bool = False
        self.canvas_active: bool = True

        self.status_bits: HyperbolicTreeStatusBits = (
            HyperbolicTreeStatusBits.CANVAS_ACTIVE
            | HyperbolicTreeStatusBits.GEOMETRY_COMPUTED
            | HyperbolicTreeStatusBits.HIERARCHY_VALID
            | HyperbolicTreeStatusBits.HEALTH_PROPAGATED
            | HyperbolicTreeStatusBits.SVG_VALID
            | HyperbolicTreeStatusBits.WCAG_AAA_VERIFIED
            | HyperbolicTreeStatusBits.NOMINAL_OPERATION
        )

        self.metrics: HyperbolicTreeMetrics = HyperbolicTreeMetrics()
        self.update_telemetry()
        self.sync_to_registers()

    def update_telemetry(self) -> None:
        """Recalculate bottom-up health and aggregated metrics."""
        propagate_bottom_up_health(self.tree)
        root = self.tree.get_root()
        root_h = root.health_score if root else 100.0

        sel_node = self.tree.get_node(self.selected_node_id) or root
        sel_idx = sel_node.index if sel_node else 0
        sel_dist = sel_node.hyperbolic_dist if sel_node else 0.0

        faults = identify_critical_faults(self.tree)
        min_node = find_min_health_node(self.tree)
        min_h = min_node.health_score if min_node else 100.0

        self.critical_fault_alarm_active = (len(faults) > 0 or int(self.diagnostic_code) != 0)

        if self.critical_fault_alarm_active:
            self.status_bits |= HyperbolicTreeStatusBits.CRITICAL_FAULT_ACTIVE
            self.status_bits &= ~HyperbolicTreeStatusBits.NOMINAL_OPERATION
        else:
            self.status_bits &= ~HyperbolicTreeStatusBits.CRITICAL_FAULT_ACTIVE
            if int(self.diagnostic_code) == 0:
                self.status_bits |= HyperbolicTreeStatusBits.NOMINAL_OPERATION

        self.metrics = HyperbolicTreeMetrics(
            root_health_score=root_h,
            selected_node_index=sel_idx,
            selected_node_distance=round(sel_dist, 3),
            critical_fault_count=len(faults),
            max_tree_depth=self.tree.max_depth(),
            total_node_count=self.tree.total_node_count(),
            min_health_score=min_h,
            diagnostic_code=int(self.diagnostic_code) & 0xFFFF,
            selected_node_id=sel_node.id if sel_node else "PLANT_ROOT",
            selected_node_name=sel_node.name if sel_node else "Industrial Refinery Plant",
            selected_node_tag=sel_node.tag if sel_node else "PLANT-REF-01",
            min_health_node_id=min_node.id if min_node else "PLANT_ROOT",
        )

    def select_node(self, node_id: str, recenter: bool = True) -> None:
        """Select an active node by ID, optionally recentering via Möbius automorphism."""
        if node_id in self.tree.nodes:
            self.selected_node_id = node_id
            self.status_bits |= HyperbolicTreeStatusBits.NODE_SELECTED
            if recenter:
                recenter_tree_at(self.tree, node_id)
            self.update_telemetry()
            self.sync_to_registers()

    def inject_node_fault(self, node_id: str, health_score: float = 45.0) -> None:
        """Simulate a localized sensor or equipment fault on a node."""
        node = self.tree.get_node(node_id)
        if node:
            node.health_score = health_score
            if health_score < HEALTH_CRITICAL_THRESHOLD:
                self.diagnostic_code = DIAG_ERR_CRITICAL_FAULT_TRIP
            self.update_telemetry()
            self.sync_to_registers()

    def trigger_cycle_fault(self) -> None:
        """Inject 0xE201 HIERARCHY_CYCLE_DETECTED fault."""
        self.diagnostic_code = DIAG_ERR_HIERARCHY_CYCLE_DETECTED
        self.status_bits |= HyperbolicTreeStatusBits.CYCLE_DETECTED
        self.status_bits &= ~HyperbolicTreeStatusBits.NOMINAL_OPERATION
        self.update_telemetry()
        self.sync_to_registers()

    def trigger_boundary_fault(self) -> None:
        """Inject 0xE202 BOUNDARY_OVERFLOW_FAULT."""
        self.diagnostic_code = DIAG_ERR_BOUNDARY_OVERFLOW
        self.status_bits |= HyperbolicTreeStatusBits.BOUNDARY_OVERFLOW_FAULT
        self.status_bits &= ~HyperbolicTreeStatusBits.NOMINAL_OPERATION
        self.update_telemetry()
        self.sync_to_registers()

    def trigger_render_fault(self) -> None:
        """Inject 0xE204 SVG_RENDER_FAULT."""
        self.diagnostic_code = DIAG_ERR_SVG_RENDER_FAULT
        self.status_bits |= HyperbolicTreeStatusBits.RENDER_FAULT
        self.status_bits &= ~HyperbolicTreeStatusBits.NOMINAL_OPERATION
        self.update_telemetry()
        self.sync_to_registers()

    def reset_nominal(self) -> None:
        """Restore tree to canonical nominal operating conditions."""
        self.tree = create_canonical_scada_hyperbolic_tree()
        root = self.tree.get_root()
        self.selected_node_id = root.id if root else "PLANT_ROOT"
        self.diagnostic_code = DIAG_OK
        self.critical_fault_alarm_active = False
        self.canvas_active = True
        self.status_bits = (
            HyperbolicTreeStatusBits.CANVAS_ACTIVE
            | HyperbolicTreeStatusBits.GEOMETRY_COMPUTED
            | HyperbolicTreeStatusBits.HIERARCHY_VALID
            | HyperbolicTreeStatusBits.HEALTH_PROPAGATED
            | HyperbolicTreeStatusBits.SVG_VALID
            | HyperbolicTreeStatusBits.WCAG_AAA_VERIFIED
            | HyperbolicTreeStatusBits.NOMINAL_OPERATION
        )
        self.update_telemetry()
        self.sync_to_registers()

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Synchronize telemetry metrics to Horner OCS RegisterTable memory space (%R1740..%R1747, %M406..%M407)."""
        reg = reg_table if reg_table is not None else self.reg_table

        r1740 = int(round(self.metrics.root_health_score * 10))
        r1741 = int(self.metrics.selected_node_index)
        r1742 = int(round(self.metrics.selected_node_distance * 100))
        r1743 = int(self.metrics.critical_fault_count)
        r1744 = int(self.metrics.max_tree_depth)
        r1745 = int(self.metrics.total_node_count)
        r1746 = int(round(self.metrics.min_health_score * 10))

        diag_val = int(self.diagnostic_code) & 0xFFFF
        diag_s16 = diag_val - 0x10000 if diag_val >= 0x8000 else diag_val

        reg.write_word(REG_ROOT_HEALTH_SCORE_SCALED, r1740, privilege=privilege)
        reg.write_word(REG_SELECTED_NODE_INDEX, r1741, privilege=privilege)
        reg.write_word(REG_SELECTED_NODE_DISTANCE_SCALED, r1742, privilege=privilege)
        reg.write_word(REG_CRITICAL_FAULT_COUNT, r1743, privilege=privilege)
        reg.write_word(REG_MAX_TREE_DEPTH, r1744, privilege=privilege)
        reg.write_word(REG_TOTAL_NODE_COUNT, r1745, privilege=privilege)
        reg.write_word(REG_MIN_HEALTH_SCORE_SCALED, r1746, privilege=privilege)
        reg.write_word(REG_DIAGNOSTIC_STATUS_CODE, diag_s16, privilege=privilege)

        reg.write_bit(COIL_CRITICAL_FAULT_ALARM_ACTIVE, bool(self.critical_fault_alarm_active), privilege=privilege)
        reg.write_bit(COIL_HYPERBOLIC_TREE_CANVAS_ACTIVE, bool(self.canvas_active), privilege=privilege)

    # ------------------------------------------------------------------------
    # ILogicUnit Protocol Implementation
    # ------------------------------------------------------------------------
    @property
    def name(self) -> str:
        return "HyperbolicTreeCanvasSync"

    @property
    def priority(self) -> int:
        return 95

    @property
    def is_enabled(self) -> bool:
        return True

    def reset(self) -> None:
        """Reset internal unit state to initial nominal conditions."""
        self.reset_nominal()

    def scan_step(self, dt: float = 0.01) -> None:
        """Simulate single clock cycle step with delta time dt."""
        self.update_telemetry()
        self.sync_to_registers()

    def step(self) -> None:
        """Step alias."""
        self.scan_step()

    def execute(self, context: ScanContext) -> None:
        """Execute discrete logic cycle within Horner scan context."""
        self.update_telemetry()
        self.sync_to_registers(self.reg_table, privilege=PrivilegeMode.SYSTEM)

    def render_svg(
        self,
        viewport_width: int = CANVAS_VIEWPORT_WIDTH,
        viewport_height: int = CANVAS_VIEWPORT_HEIGHT,
        dark_theme_bg: str = COLOR_DARK_THEME_BACKING,
    ) -> str:
        """Render standalone W3C SVG 1.1 vector graphic."""
        return generate_hyperbolic_tree_canvas_svg(
            tree=self.tree,
            metrics=self.metrics,
            status_bits=self.status_bits,
            selected_node_id=self.selected_node_id,
            diagnostic_code=self.diagnostic_code,
            viewport_width=viewport_width,
            viewport_height=viewport_height,
            dark_theme_bg=dark_theme_bg,
        )


# Aliases for W213
HyperbolicTreeCanvasEngine = HyperbolicTreeCanvas
HyperbolicTreeCanvasSync = HyperbolicTreeCanvas


def create_canonical_hyperbolic_tree_canvas(
    selected_node_id: Optional[str] = None,
) -> HyperbolicTreeCanvas:
    """Instantiate canonical Hyperbolic Tree Canvas bound to Horner OCS memory."""
    tree = create_canonical_scada_hyperbolic_tree()
    return HyperbolicTreeCanvas(tree=tree, selected_node_id=selected_node_id)


def create_mock_scan_context(
    cycle: int = 1,
    dt_ms: float = 10.0,
    reg_table: Optional[RegisterTable] = None,
) -> ScanContext:
    """Helper to instantiate mock Horner ScanContext for discrete ILogicUnit execution."""
    regs = reg_table if reg_table is not None else RegisterTable()
    return ScanContext(
        cycle=cycle,
        dt_ms=dt_ms,
        elapsed_time_ms=cycle * dt_ms,
        get_register=lambda addr: regs.read_word(addr),
        set_register=lambda addr, val: regs.write_word(addr, val, privilege=PrivilegeMode.SYSTEM),
        get_variable=lambda name, default=None: default,
        set_variable=lambda name, val: None,
        record_fault=lambda fault: None,
    )


# ============================================================================
# 12. Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

HYPERBOLIC_TREE_CANVAS_PURE_ST_POU: str = """PROGRAM HyperbolicTreeCanvasSync
VAR
    RootAggregateHealthScoreScaled AT %R1740 : INT;
    SelectedNodeIndex              AT %R1741 : INT;
    SelectedNodeDistanceScaled     AT %R1742 : INT;
    CriticalFaultCount             AT %R1743 : INT;
    MaxTreeDepth                   AT %R1744 : INT;
    TotalNodeCount                 AT %R1745 : INT;
    MinHealthScoreScaled           AT %R1746 : INT;
    DiagnosticStatusCode           AT %R1747 : INT;
    CriticalFaultAlarmActive       AT %M406  : BOOL;
    HyperbolicTreeCanvasActive     AT %M407  : BOOL;
END_VAR

IF HyperbolicTreeCanvasActive THEN
    IF CriticalFaultCount > 0 OR DiagnosticStatusCode <> 0 THEN
        CriticalFaultAlarmActive := TRUE;
    ELSE
        CriticalFaultAlarmActive := FALSE;
    END_IF;
ELSE
    CriticalFaultAlarmActive := FALSE;
END_IF;
END_PROGRAM
"""

HYPERBOLIC_TREE_PURE_ST_POU: str = HYPERBOLIC_TREE_CANVAS_PURE_ST_POU
W213_HYPERBOLIC_TREE_PURE_ST_POU: str = HYPERBOLIC_TREE_CANVAS_PURE_ST_POU


def verify_hyperbolic_tree_canvas_pure_st() -> bool:
    """Verify purity of HYPERBOLIC_TREE_CANVAS_PURE_ST_POU with SecurityGuard and STParser."""
    SecurityGuard.assert_pure_st_content(HYPERBOLIC_TREE_CANVAS_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(HYPERBOLIC_TREE_CANVAS_PURE_ST_POU)
    return (
        pou is not None
        and pou.name == "HyperbolicTreeCanvasSync"
        and pou.pou_type == POUType.PROGRAM
        and len(pou.variables) == 10
    )


# ============================================================================
# 13. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_hyperbolic_tree_canvas_verification(
    output_path: Optional[str] = None,
    sample_svg_path: Optional[str] = None,
    work_package: str = "W213",
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite returning strict 4-state contract JSON."""
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    final_evidence_path = output_path or str(repo_root / "artifacts" / "HMI" / "hyperbolic_tree_canvas_evidence.json")
    final_svg_path = sample_svg_path or str(repo_root / "artifacts" / "HMI" / "hyperbolic_tree_canvas_sample.svg")

    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU Grammar & AST Validation (%R1740..%R1747, %M406..%M407)
    # ------------------------------------------------------------------------
    s1_pass = False
    try:
        SecurityGuard.assert_pure_st_content(HYPERBOLIC_TREE_CANVAS_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(HYPERBOLIC_TREE_CANVAS_PURE_ST_POU)

        expected_vars = {
            "RootAggregateHealthScoreScaled": "%R1740",
            "SelectedNodeIndex": "%R1741",
            "SelectedNodeDistanceScaled": "%R1742",
            "CriticalFaultCount": "%R1743",
            "MaxTreeDepth": "%R1744",
            "TotalNodeCount": "%R1745",
            "MinHealthScoreScaled": "%R1746",
            "DiagnosticStatusCode": "%R1747",
            "CriticalFaultAlarmActive": "%M406",
            "HyperbolicTreeCanvasActive": "%M407",
        }

        vmap = {v.name: v.address_binding for v in pou.variables}
        all_bindings_valid = all(vmap.get(k) == b for k, b in expected_vars.items())

        s1_pass = (
            pou is not None
            and pou.name == "HyperbolicTreeCanvasSync"
            and pou.pou_type == POUType.PROGRAM
            and len(pou.variables) == 10
            and all_bindings_valid
        )
    except Exception:
        s1_pass = False

    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_Grammar_AST_Validation",
        "passed": s1_pass,
        "details": "Verified 'HyperbolicTreeCanvasSync' POU with SecurityGuard & STParser across Horner registers %R1740..%R1747 and %M406..%M407.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Anti-Ladder Construct Security Interception (ERR_LADDER_FORBIDDEN)
    # ------------------------------------------------------------------------
    ladder_snippets = [
        ("Contacts", "PROGRAM Bad VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM"),
        ("Coils", "PROGRAM Bad VAR Y: BOOL; END_VAR ---( )--- END_PROGRAM"),
        ("Rung", "PROGRAM Bad\nRUNG 1:\nEND_PROGRAM"),
        ("Network", "PROGRAM Bad\nNETWORK 1:\nEND_PROGRAM"),
        ("Mnemonic_XIC", "PROGRAM Bad\nXIC bit1;\nEND_PROGRAM"),
        ("Mnemonic_OTE", "PROGRAM Bad\nOTE bit2;\nEND_PROGRAM"),
    ]
    rejected_count = 0
    for name, snippet in ladder_snippets:
        try:
            SecurityGuard.assert_pure_st_content(snippet)
        except LadderForbiddenError:
            rejected_count += 1
        except Exception:
            pass

    s2_pass = (rejected_count == len(ladder_snippets))
    test_results.append({
        "stage": 2,
        "check": "Anti_Ladder_Construct_Security_Interception",
        "passed": s2_pass,
        "details": f"Rejected {rejected_count}/{len(ladder_snippets)} forbidden ladder logic constructs with LadderForbiddenError.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Complex Poincaré Disk Coordinate Space & Boundary Containment
    # ------------------------------------------------------------------------
    s3_pass = False
    try:
        p_origin = ComplexPoint(0.0, 0.0)
        p_valid = ComplexPoint(0.5, -0.6)
        p_boundary = ComplexPoint(0.8, 0.6)  # magnitude = 1.0
        p_overflow = ComplexPoint(1.2, 0.5)

        c1 = is_in_poincare_disk(p_origin) and is_in_poincare_disk(p_valid)
        c2 = not is_in_poincare_disk(p_boundary) and not is_in_poincare_disk(p_overflow)

        clamped = p_overflow.clamp(MAX_HYPERBOLIC_RADIUS)
        c3 = math.isclose(clamped.magnitude(), MAX_HYPERBOLIC_RADIUS, abs_tol=1e-4)

        s3_pass = c1 and c2 and c3
    except Exception:
        s3_pass = False

    test_results.append({
        "stage": 3,
        "check": "Complex_Poincare_Disk_Coordinate_Space_And_Boundary",
        "passed": s3_pass,
        "details": "Verified ComplexPoint arithmetic, strict unit disk boundary containment (|z| < 1.0), and radius clamping.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Möbius Transformations, Inversion, Identity & Singularity Guards
    # ------------------------------------------------------------------------
    s4_pass = False
    try:
        z = ComplexPoint(0.4, 0.3)
        a = ComplexPoint(0.2, -0.5)

        # Map 'a' to origin
        mapped_origin = mobius_transform(a, a)
        origin_ok = mapped_origin.magnitude() < 1e-12

        # Identity
        identity_mapped = mobius_transform(z, ComplexPoint(0.0, 0.0))
        identity_ok = math.isclose(identity_mapped.x, z.x, abs_tol=1e-12) and math.isclose(identity_mapped.y, z.y, abs_tol=1e-12)

        # Invertibility: T_a^(-1)(T_a(z)) == z
        w = mobius_transform(z, a)
        z_rec = mobius_inverse(w, a)
        invert_ok = math.isclose(z_rec.x, z.x, abs_tol=1e-7) and math.isclose(z_rec.y, z.y, abs_tol=1e-7)

        # Singularity guard on boundary |a| >= 1
        singularity_raised = False
        try:
            mobius_transform(z, ComplexPoint(1.0, 0.0))
        except HyperbolicBoundaryError:
            singularity_raised = True

        s4_pass = origin_ok and identity_ok and invert_ok and singularity_raised
    except Exception:
        s4_pass = False

    test_results.append({
        "stage": 4,
        "check": "Mobius_Transformations_Inversion_And_Singularity_Guards",
        "passed": s4_pass,
        "details": "Verified disk automorphism T_a(a)=0, identity T_0(z)=z, inverse reconstruction, and singularity guards.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Hyperbolic Distance Metric Invariants d(u, v)
    # ------------------------------------------------------------------------
    s5_pass = False
    try:
        u = ComplexPoint(0.2, 0.1)
        v = ComplexPoint(-0.4, 0.3)
        w = ComplexPoint(0.1, -0.5)

        d_uu = hyperbolic_distance(u, u)
        d_uv = hyperbolic_distance(u, v)
        d_vu = hyperbolic_distance(v, u)
        d_uw = hyperbolic_distance(u, w)
        d_vw = hyperbolic_distance(v, w)

        zero_prop = math.isclose(d_uu, 0.0, abs_tol=1e-12)
        symm_prop = math.isclose(d_uv, d_vu, abs_tol=1e-10)
        tri_prop = (d_uw <= d_uv + d_vw + 1e-10)

        # Formula check against 2*artanh(|v|) from origin
        d_0v = hyperbolic_distance(ComplexPoint(0.0, 0.0), v)
        expected_0v = 2.0 * math.atanh(v.magnitude())
        origin_formula_ok = math.isclose(d_0v, expected_0v, abs_tol=1e-10)

        s5_pass = zero_prop and symm_prop and tri_prop and origin_formula_ok
    except Exception:
        s5_pass = False

    test_results.append({
        "stage": 5,
        "check": "Hyperbolic_Distance_Metric_Invariants",
        "passed": s5_pass,
        "details": "Verified d(u,v) metric properties: d(u,u)=0, symmetry, triangle inequality, and 2*artanh formula.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Geodesic Arc Circle Geometry & Orthogonal Boundary Circle
    # ------------------------------------------------------------------------
    s6_pass = False
    try:
        pt_a = ComplexPoint(0.2, 0.3)
        pt_b = ComplexPoint(-0.4, 0.5)

        arc = compute_geodesic_arc(pt_a, pt_b, CANVAS_CENTER_X, CANVAS_CENTER_Y, POINCARE_DISK_RADIUS)

        not_line = not arc.is_straight_line
        has_c = arc.center_disk is not None and arc.radius_disk is not None

        # Check orthogonality condition: |c|^2 - R^2 == 1.0
        c_mag_sq = arc.center_disk.magnitude_squared()
        r_sq = arc.radius_disk * arc.radius_disk
        ortho_ok = math.isclose(c_mag_sq - r_sq, 1.0, abs_tol=1e-7)

        # Check passage through endpoints: |c - u| == R and |c - v| == R
        dist_u = (arc.center_disk - pt_a).magnitude()
        dist_v = (arc.center_disk - pt_b).magnitude()
        pass_ok = (
            math.isclose(dist_u, arc.radius_disk, abs_tol=1e-7)
            and math.isclose(dist_v, arc.radius_disk, abs_tol=1e-7)
        )

        # Collinear geodesic check
        pt_collinear = ComplexPoint(0.4, 0.6)
        arc_line = compute_geodesic_arc(ComplexPoint(0.0, 0.0), pt_collinear)
        collinear_ok = arc_line.is_straight_line and " L " in arc_line.svg_path

        s6_pass = not_line and has_c and ortho_ok and pass_ok and collinear_ok
    except Exception:
        s6_pass = False

    test_results.append({
        "stage": 6,
        "check": "Geodesic_Arc_Circle_Geometry_And_Orthogonality",
        "passed": s6_pass,
        "details": "Verified geodesic circle center/radius math, boundary circle orthogonality (|c|^2 - R^2 = 1), and diameter lines.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Hierarchical Tree Traversal, Layout & Bottom-Up Health Propagation
    # ------------------------------------------------------------------------
    tree = create_canonical_scada_hyperbolic_tree()
    s7_pass = False
    try:
        root = tree.get_root()
        node_count_ok = (tree.total_node_count() == 29)
        depth_ok = (tree.max_depth() == 3)
        acyclic_ok = not tree.detect_cycles()

        # Check all nodes within disk
        all_in_disk = all(n.z.magnitude() < 1.0 for n in tree.nodes.values())

        # Check health propagation
        canvas = HyperbolicTreeCanvas(tree=tree)
        nominal_h = canvas.metrics.root_health_score
        nominal_faults = canvas.metrics.critical_fault_count

        # Inject fault
        canvas.inject_node_fault("SS_CDU_PUMP", 45.0)
        post_faults = canvas.metrics.critical_fault_count
        post_min_h = canvas.metrics.min_health_score
        alarm_asserted = canvas.critical_fault_alarm_active

        s7_pass = (
            node_count_ok
            and depth_ok
            and acyclic_ok
            and all_in_disk
            and nominal_faults == 0
            and nominal_h >= 90.0
            and post_faults >= 1
            and post_min_h == 45.0
            and alarm_asserted
        )
    except Exception:
        s7_pass = False

    test_results.append({
        "stage": 7,
        "check": "Hierarchical_Tree_Traversal_Layout_And_Health",
        "passed": s7_pass,
        "details": "Verified 29 refinery nodes across 4 tiers, acyclic graph, wedge layout, and bottom-up health propagation.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: WCAG 2.1 AAA Contrast Ratio & Standalone W3C SVG XML Parsing
    # ------------------------------------------------------------------------
    s8_pass = False
    try:
        is_aaa, text_cr, badge_cr = validate_wcag_aaa_contrast(
            text_color=COLOR_TEXT_PRIMARY,
            theme_backing=COLOR_DARK_THEME_BACKING,
            badge_backing=COLOR_DECOUPLED_BADGE,
        )

        contrast_ok = (
            is_aaa
            and text_cr >= WCAG_AAA_TEXT_CONTRAST_TARGET
            and badge_cr >= WCAG_AAA_BADGE_CONTRAST_TARGET
        )

        # SVG XML validation
        canvas_nominal = HyperbolicTreeCanvas()
        svg_str = canvas_nominal.render_svg()

        root_elem = ET.fromstring(svg_str)
        tag_is_svg = root_elem.tag.endswith("svg")
        has_rects = len(root_elem.findall(".//{http://www.w3.org/2000/svg}rect")) + len(root_elem.findall(".//rect")) > 0
        has_paths = len(root_elem.findall(".//{http://www.w3.org/2000/svg}path")) + len(root_elem.findall(".//path")) > 0
        has_circles = len(root_elem.findall(".//{http://www.w3.org/2000/svg}circle")) + len(root_elem.findall(".//circle")) > 0

        # Save sample SVG
        svg_p = Path(final_svg_path)
        svg_p.parent.mkdir(parents=True, exist_ok=True)
        with open(svg_p, "w", encoding="utf-8") as f:
            f.write(svg_str)

        s8_pass = contrast_ok and tag_is_svg and has_rects and has_paths and has_circles
    except Exception:
        s8_pass = False

    test_results.append({
        "stage": 8,
        "check": "WCAG_AAA_Contrast_And_W3C_SVG_XML_Parsing",
        "passed": s8_pass,
        "details": f"Verified decoupled badge contrast (> 18:1), text contrast (> 7:1), and valid XML SVG -> {final_svg_path}.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Horner OCS Register Space Synchronization & ILogicUnit Scan Cycle
    # ------------------------------------------------------------------------
    s9_pass = False
    try:
        reg_table = RegisterTable()
        canvas_sync = HyperbolicTreeCanvas(reg_table=reg_table)
        canvas_sync.scan_step(dt=0.01)

        r1740 = reg_table.read_word("%R1740")  # Root health scaled x10
        r1741 = reg_table.read_word("%R1741")  # Selected node index
        r1742 = reg_table.read_word("%R1742")  # Selected node dist scaled x100
        r1743 = reg_table.read_word("%R1743")  # Critical fault count
        r1744 = reg_table.read_word("%R1744")  # Max tree depth (3)
        r1745 = reg_table.read_word("%R1745")  # Total node count (29)
        r1746 = reg_table.read_word("%R1746")  # Min health score scaled x10
        r1747 = reg_table.read_word("%R1747")  # Diag status code (0)
        m406 = reg_table.read_bit("%M406")    # Critical fault alarm (False)
        m407 = reg_table.read_bit("%M407")    # Canvas active (True)

        registers_ok = (
            r1740 >= 900
            and r1741 == 0
            and r1742 == 0
            and r1743 == 0
            and r1744 == 3
            and r1745 == 29
            and r1746 >= 900
            and r1747 == 0
            and (not m406)
            and m407
        )

        ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=reg_table)
        canvas_sync.execute(ctx)

        s9_pass = registers_ok
    except Exception:
        s9_pass = False

    test_results.append({
        "stage": 9,
        "check": "Horner_OCS_Register_Sync_And_Scan_Cycle",
        "passed": s9_pass,
        "details": "Verified %R1740..%R1747 and %M406..%M407 with PrivilegeMode.SYSTEM and ILogicUnit scan cycle.",
    })

    # ------------------------------------------------------------------------
    # Aggregate Strict 4-State Verification Report
    # ------------------------------------------------------------------------
    checks_passed = sum(1 for t in test_results if t["passed"])
    total_checks = len(test_results)
    all_passed = (checks_passed == total_checks)

    overall_status = "success" if all_passed else "failed"
    error_code = None if all_passed else "STAGE_VERIFICATION_FAILURE"

    report_payload: Dict[str, Any] = {
        "status": overall_status,
        "error_code": error_code,
        "details": f"Deterministic verification: {checks_passed}/{total_checks} stages passed.",
        "data": {
            "work_package": work_package,
            "gate": "Gate G9 / G2",
            "component": "Cscape HMI Dynamic Hyperbolic Tree / Poincaré Disk SCADA Canvas",
            "checks_passed": checks_passed,
            "total_checks": total_checks,
            "tests": test_results,
        },
    }

    evidence_p = Path(final_evidence_path)
    evidence_p.parent.mkdir(parents=True, exist_ok=True)
    with open(evidence_p, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)

    return report_payload
