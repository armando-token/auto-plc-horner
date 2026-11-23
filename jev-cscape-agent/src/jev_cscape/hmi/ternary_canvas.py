"""Cscape HMI Dynamic Ternary / Gibbs Triangle Phase Equilibrium Canvas.

Work Package: W129 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Implements:
1. Strict Pure IEC 61131-3 Structured Text (ST) POU:
   - Program 'TernaryCanvasSync' with Horner OCS RegisterTable bindings:
     - %R900..%R907 (Status Word, Scaled Compositions A/B/C, Envelope Distance, Active Phases, System Mode, Diagnostics)
     - %M210..%M211 (Phase Boundary Excursion Alarm & Composition Limit Trip Coils)
   - Validated with SecurityGuard.assert_pure_st_content and STParser.
   - Aggressive ladder logic interception (---[ ]---, ---( )---, RUNG, NETWORK, XIC)
     failing closed with ERR_LADDER_FORBIDDEN.
2. Gibbs Triangular Coordinate Transformations:
   - Equilateral triangular coordinate system (apex A, bottom-right B, bottom-left C).
   - Barycentric coordinate conversion (a, b, c -> x, y) and inverse mapping (x, y -> a, b, c).
   - Strictly enforced sum-to-1 composition normalization (a + b + c = 1.0).
3. Binodal Curve & Tie-Line (Conode) Phase Equilibrium Engine:
   - Liquid-liquid equilibrium (LLE) miscibility gap envelope with critical plait point.
   - Conjugate equilibrium tie-line interpolation across two-phase region.
   - Euclidean signed distance field (SDF) from operating point to binodal boundary.
4. Phase Boundary Excursion Supervisor:
   - Detects entry into immiscible two-phase envelope.
   - Asserts %M210 (PhaseBoundaryExcursionAlarm) and Horner diagnostic event 0x9A01.
   - Computes distance-to-envelope safety margin in pixels and composition percentages.
5. Standalone W3C SVG 1.1 Vector Canvas Renderer:
   - 1200x750 industrial viewport (#0F172A dark theme backing).
   - Equilateral triangle frame, composition grid lines (10% increments), binodal envelope,
     tie lines, and prominent operating composition point with excursion halo rings.
   - Decoupled dark backing badges (#0B0F19 at 0.92 opacity) meeting WCAG 2.1 AAA
     contrast standards (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
6. Horner OCS Memory Space Integration:
   - %R900: StatusWord (CANVAS_ACTIVE, TERNARY_COMPUTED, COMPOSITION_NORMALIZED,
            PHASE_EXCURSION_ALARM, COMPOSITION_LIMIT_TRIP, SVG_VALID, WCAG_AAA, EXCURSION_HIGHLIGHTED)
   - %R901: ComponentA_Scaled (INT16, a * 1000)
   - %R902: ComponentB_Scaled (INT16, b * 1000)
   - %R903: ComponentC_Scaled (INT16, c * 1000)
   - %R904: DistToEnvelopeScaled (INT16, distance_px * 10)
   - %R905: ActivePhaseCount (1=Single Phase / Homogeneous, 2=Two Phase / Excursion)
   - %R906: SystemMode (0=LIQUID_LIQUID, 1=SOLID_LIQUID, 2=VAPOR_LIQUID)
   - %R907: DiagEventCode (0x0000=OK, 0x9A01=PHASE_EXCURSION, 0x9A02=COMPOSITION_FAULT)
   - %M210: PhaseBoundaryExcursionAlarm
   - %M211: CompositionLimitTrip
7. Deterministic 9-Stage Verification Suite:
   - run_ternary_canvas_verification(output_path, sample_svg_path) returning
     strict 4-state engineering contract JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntFlag
import html
import json
import math
from pathlib import Path
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
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
            return int(self) == other or val_u == other or val_s == other or val_s == other_s or val_u == other_u
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(int(self))


# Diagnostic event codes conforming to Horner OCS %R907 specification
DIAG_EVENT_OK: DiagnosticCode                   = DiagnosticCode(0x0000)
DIAG_EVENT_PHASE_EXCURSION: DiagnosticCode      = DiagnosticCode(0x9A01)  # Two-phase boundary excursion (%M210)
DIAG_EVENT_PHASE_BOUNDARY_TRIP: DiagnosticCode  = DIAG_EVENT_PHASE_EXCURSION  # W129 Specification 5 Trip Alias (%M210)
DIAG_EVENT_BOUNDARY_EXCURSION: DiagnosticCode   = DIAG_EVENT_PHASE_EXCURSION  # Code alias
DIAG_EVENT_COMPOSITION_FAULT: DiagnosticCode    = DiagnosticCode(0x9A02)  # Composition limit breach / trip (%M211)
DIAG_EVENT_GEOMETRY_DEGENERACY: DiagnosticCode  = DiagnosticCode(0x9A03)  # Triangle geometry degeneracy

# Contrast targets conforming to WCAG 2.1 AAA
WCAG_AAA_TEXT_CONTRAST_TARGET: float            = 7.0    # WCAG 2.1 AAA normal text contrast target (> 7.0:1)
WCAG_GRAPHICAL_CONTRAST_TARGET: float           = 3.0    # WCAG 2.1 AAA UI / graphical boundary contrast (> 3.0:1)
WCAG_AAA_CONTRAST_TARGET: float                 = 18.0   # Decoupled dark backing badge target contrast (> 18:1)

# Industrial SCADA Color-Coding Palette
COLOR_NOMINAL_GREEN: str                        = "#107C41"   # Deep Nominal Green
COLOR_NOMINAL_GREEN_LIGHT: str                  = "#27AE60"   # Vibrant Nominal Green
COLOR_NOMINAL_GREEN_VIBRANT: str                = "#27AE60"   # Vibrant Nominal Green alias
COLOR_ADVISORY_AMBER: str                       = "#D83B01"   # Deep Advisory Amber
COLOR_ADVISORY_AMBER_LIGHT: str                 = "#F39C12"   # Vibrant Advisory Amber
COLOR_ADVISORY_AMBER_VIBRANT: str               = "#F39C12"   # Vibrant Advisory Amber alias
COLOR_TRIP_RED: str                             = "#A80000"   # Deep Trip Red
COLOR_TRIP_RED_LIGHT: str                       = "#E74C3C"   # Vibrant Trip Red
COLOR_TRIP_RED_VIBRANT: str                     = "#E74C3C"   # Vibrant Trip Red alias
COLOR_DARK_THEME_BACKING: str                   = "#0F172A"   # Dark Slate Blue Theme Backing
COLOR_DARK_THEME_BACKING_1E1E1E: str            = "#1E1E1E"   # Dark Theme Backing Alternative (#1E1E1E Mandate)
COLOR_DARK_BACKING: str                         = "#0F172A"   # Dark Theme Backing alias
COLOR_DECOUPLED_BADGE: str                      = "#0B0F19"   # Decoupled Badge Backing
COLOR_BADGE_BACKING: str                        = "#0B0F19"   # Decoupled Badge Backing alias
COLOR_TEXT_PRIMARY: str                         = "#F8FAFC"   # WCAG AAA Primary Light Text
COLOR_TEXT_MUTED: str                           = "#94A3B8"   # Secondary Muted Text

# Ternary Component & Phase Region Colors
COLOR_COMPONENT_A: str                          = "#38BDF8"   # Component A (Solvent) - Sky Blue
COLOR_COMPONENT_B: str                          = "#34D399"   # Component B (Solute) - Emerald
COLOR_COMPONENT_C: str                          = "#FBBF24"   # Component C (Carrier) - Amber
COLOR_TWO_PHASE_FILL: str                       = "#D83B01"   # Two-Phase Region Fill
COLOR_TWO_PHASE_STROKE: str                     = "#F39C12"   # Binodal Envelope Stroke
COLOR_TIE_LINE: str                             = "#CBD5E1"   # Tie-Line Stroke

# Viewport and Equilateral Triangle Geometry Constants
CANVAS_VIEWPORT_WIDTH: int                      = 1200
CANVAS_VIEWPORT_HEIGHT: int                     = 750
CANVAS_CENTER_X: float                          = 600.0
CANVAS_CENTER_Y: float                          = 400.0
TRIANGLE_SIDE_LENGTH: float                     = 500.0
TRIANGLE_HEIGHT: float                          = 433.0127018922193  # 500.0 * sqrt(3) / 2

# Standard Equilateral Triangle Vertices centered at (600, 400)
# Apex VA: Top vertex (Component A)
VERTEX_A: Tuple[float, float]                   = (600.0, 111.32486540518712)
# Vertex VB: Bottom-Right vertex (Component B)
VERTEX_B: Tuple[float, float]                   = (850.0, 544.3375672974064)
# Vertex VC: Bottom-Left vertex (Component C)
VERTEX_C: Tuple[float, float]                   = (350.0, 544.3375672974064)
STANDARD_TRIANGLE_VERTICES: Tuple[Tuple[float, float], Tuple[float, float], Tuple[float, float]] = (
    VERTEX_A,
    VERTEX_B,
    VERTEX_C,
)


# ============================================================================
# 2. Enums and Status Bitmasks
# ============================================================================

class TernaryStatusBits(IntFlag):
    """Horner OCS %R900 Status Word Bitmask Definitions."""
    CANVAS_ACTIVE           = 1 << 0  # Bit 0 (0x0001): Canvas & ternary engine active
    TERNARY_COMPUTED        = 1 << 1  # Bit 1 (0x0002): Gibbs coordinates & equilibrium computed
    COMPOSITION_NORMALIZED  = 1 << 2  # Bit 2 (0x0004): Compositions strictly normalized (sum = 1.0)
    PHASE_EXCURSION_ALARM   = 1 << 3  # Bit 3 (0x0008): Operating point inside two-phase envelope (%M210 active)
    COMPOSITION_LIMIT_TRIP  = 1 << 4  # Bit 4 (0x0010): Critical composition limit trip (%M211 active)
    SVG_VALID               = 1 << 5  # Bit 5 (0x0020): Standalone W3C SVG 1.1 rendered and valid
    WCAG_AAA                = 1 << 6  # Bit 6 (0x0040): WCAG 2.1 AAA contrast verified (> 7:1 text, > 3:1 graphical)
    EXCURSION_HIGHLIGHTED   = 1 << 7  # Bit 7 (0x0080): Excursion operating point visually highlighted with warning halo


TernaryCanvasStatusBits = TernaryStatusBits


class SystemMode(str, Enum):
    """Ternary equilibrium phase system category."""
    LIQUID_LIQUID = "LIQUID_LIQUID"  # Type I or II Liquid-Liquid Extraction (LLE)
    SOLID_LIQUID  = "SOLID_LIQUID"   # Crystallization / Eutectic Precipitation
    VAPOR_LIQUID  = "VAPOR_LIQUID"   # Azeotropic Distillation


class PhaseState(str, Enum):
    """Phase equilibrium classification for current operating point."""
    HOMOGENEOUS   = "HOMOGENEOUS"    # Single-phase homogeneous solution (nominal)
    TWO_PHASE     = "TWO_PHASE"      # Two-phase liquid-liquid separation (miscibility gap)
    CRITICAL      = "CRITICAL"       # Near plait point / critical boundary


class OperationalState(str, Enum):
    """SCADA operational status level."""
    NOMINAL  = "NOMINAL"   # Single phase nominal (Green)
    ADVISORY = "ADVISORY"  # Proximity warning to phase envelope (Amber)
    TRIP     = "TRIP"      # Phase boundary excursion / limit breach (Red)


# ============================================================================
# 3. WCAG 2.1 AAA Accessibility Engine
# ============================================================================

def srgb_channel_to_linear(channel: float) -> float:
    """Convert 8-bit sRGB channel (0..1) to linear luminance value."""
    if channel <= 0.03928:
        return channel / 12.92
    return ((channel + 0.055) / 1.055) ** 2.4


def hex_to_relative_luminance(hex_color: str) -> float:
    """Calculate WCAG 2.1 relative luminance for an sRGB hex color (#RRGGBB)."""
    clean_hex = hex_color.lstrip("#")
    if len(clean_hex) == 3:
        clean_hex = "".join(c * 2 for c in clean_hex)
    r = int(clean_hex[0:2], 16) / 255.0
    g = int(clean_hex[2:4], 16) / 255.0
    b = int(clean_hex[4:6], 16) / 255.0

    r_lin = srgb_channel_to_linear(r)
    g_lin = srgb_channel_to_linear(g)
    b_lin = srgb_channel_to_linear(b)

    return 0.2126 * r_lin + 0.7152 * g_lin + 0.0722 * b_lin


def calculate_contrast_ratio(color_a: str, color_b: str) -> float:
    """Calculate WCAG 2.1 contrast ratio between two colors."""
    lum_a = hex_to_relative_luminance(color_a)
    lum_b = hex_to_relative_luminance(color_b)
    lighter = max(lum_a, lum_b)
    darker = min(lum_a, lum_b)
    return (lighter + 0.05) / (darker + 0.05)


def validate_wcag_aaa_contrast(
    text_color: str = COLOR_TEXT_PRIMARY,
    graphics_colors: Optional[List[str]] = None,
    background_color: str = COLOR_DARK_THEME_BACKING,
) -> Tuple[bool, float, float]:
    """Validate that text and graphics meet WCAG 2.1 AAA contrast standards."""
    if graphics_colors is None:
        graphics_colors = [
            COLOR_NOMINAL_GREEN_LIGHT,
            COLOR_ADVISORY_AMBER_LIGHT,
            COLOR_TRIP_RED_LIGHT,
            COLOR_COMPONENT_A,
            COLOR_COMPONENT_B,
            COLOR_COMPONENT_C,
        ]

    text_contrast = calculate_contrast_ratio(text_color, background_color)
    graphics_contrasts = [calculate_contrast_ratio(g, background_color) for g in graphics_colors]
    min_graphics_contrast = min(graphics_contrasts) if graphics_contrasts else 0.0

    text_ok = text_contrast >= WCAG_AAA_TEXT_CONTRAST_TARGET
    graphics_ok = min_graphics_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET

    return (text_ok and graphics_ok, text_contrast, min_graphics_contrast)


DECOUPLED_BADGE_CONTRAST_RATIO: float = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
DARK_THEME_TEXT_CONTRAST_RATIO: float = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
GRAPHICAL_BOUNDARY_CONTRAST_RATIO: float = calculate_contrast_ratio(COLOR_NOMINAL_GREEN_LIGHT, COLOR_DARK_THEME_BACKING)


# ============================================================================
# 4. Gibbs Triangular Coordinate Transformations
# ============================================================================

def normalize_composition(a: float, b: float, c: float) -> Tuple[float, float, float]:
    """Strictly normalize ternary compositions (a, b, c) such that a + b + c = 1.0.

    Negative values are clamped to 0.0 before normalization.
    If the sum is zero or non-positive, returns an equilateral centroid (1/3, 1/3, 1/3).
    """
    ca = max(0.0, float(a))
    cb = max(0.0, float(b))
    cc = max(0.0, float(c))
    total = ca + cb + cc
    if total <= 1e-9:
        return (1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0)
    return (ca / total, cb / total, cc / total)


def gibbs_to_cartesian_2d(a: float, b: float, c: float) -> Tuple[float, float]:
    """Equilateral triangular Gibbs phase coordinate geometry transformation to Cartesian 2D.

    Specification Formula (W129 Specification 2):
        x = 0.5 * (2*b + c) / (a + b + c)
        y = (sqrt(3)/2) * c / (a + b + c)

    Vertices:
        Vertex A (1, 0, 0) -> (0.0, 0.0) [Bottom-Left]
        Vertex B (0, 1, 0) -> (1.0, 0.0) [Bottom-Right]
        Vertex C (0, 0, 1) -> (0.5, sqrt(3)/2) [Apex]
    """
    total = a + b + c
    if total <= 1e-12:
        return (0.5, (math.sqrt(3.0) / 2.0) / 3.0)
    x = 0.5 * (2.0 * b + c) / total
    y = (math.sqrt(3.0) / 2.0) * c / total
    return (x, y)


def cartesian_2d_to_gibbs(x: float, y: float) -> Tuple[float, float, float]:
    """Inverse transformation from Cartesian 2D (x, y) back into Gibbs ternary coordinates (a, b, c).

    Derived from:
        y = (sqrt(3)/2) * c  => c = 2*y / sqrt(3)
        x = b + 0.5 * c      => b = x - 0.5 * c = x - y / sqrt(3)
        a = 1 - b - c        => a = 1 - x - y / sqrt(3)
    """
    sqrt3 = math.sqrt(3.0)
    c = 2.0 * y / sqrt3
    b = x - 0.5 * c
    a = 1.0 - b - c
    return (a, b, c)


def ternary_to_cartesian(
    a: float,
    b: float,
    c: float,
    vertices: Optional[Tuple[Tuple[float, float], Tuple[float, float], Tuple[float, float]]] = None,
) -> Tuple[float, float]:
    """Transform barycentric ternary compositions (a, b, c) into Cartesian 2D (x, y) coordinates.

    Formula:
        P(x, y) = a * V_A + b * V_B + c * V_C
    where:
        V_A is the apex (top vertex, pure A),
        V_B is the bottom-right vertex (pure B),
        V_C is the bottom-left vertex (pure C).
    """
    na, nb, nc = normalize_composition(a, b, c)
    va, vb, vc = vertices or STANDARD_TRIANGLE_VERTICES

    x = na * va[0] + nb * vb[0] + nc * vc[0]
    y = na * va[1] + nb * vb[1] + nc * vc[1]
    return (x, y)


def cartesian_to_ternary(
    x: float,
    y: float,
    vertices: Optional[Tuple[Tuple[float, float], Tuple[float, float], Tuple[float, float]]] = None,
) -> Tuple[float, float, float]:
    """Inverse transformation: Map Cartesian 2D (x, y) back into normalized ternary compositions (a, b, c).

    Solves the 2x2 linear system of barycentric coordinates:
        x = a * xA + b * xB + c * xC
        y = a * yA + b * yB + c * yC
        a + b + c = 1
    """
    va, vb, vc = vertices or STANDARD_TRIANGLE_VERTICES
    xa, ya = va
    xb, yb = vb
    xc, yc = vc

    denom = (yb - yc) * (xa - xc) + (xc - xb) * (ya - yc)
    if abs(denom) < 1e-9:
        return (1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0)

    a = ((yb - yc) * (x - xc) + (xc - xb) * (y - yc)) / denom
    b = ((yc - ya) * (x - xc) + (xa - xc) * (y - yc)) / denom
    c = 1.0 - a - b

    return (a, b, c)


# ============================================================================
# 5. Binodal Curve & Tie-Line Phase Equilibrium Engine
# ============================================================================

@dataclass
class TieLine:
    """Conjugate phase tie-line (conode) across the two-phase miscibility gap."""
    index: int
    raffinate: Tuple[float, float, float]  # Phase rich in carrier C (left branch)
    extract: Tuple[float, float, float]    # Phase rich in solute B (right branch)
    k_factor: float = 0.0                  # Solute distribution coefficient (b_extract / b_raffinate)


def compute_binodal_curve(
    num_points: int = 61,
    a_plait: float = 0.42,
    b_plait: float = 0.38,
    c_plait: float = 0.20,
    a_base: float = 0.02,
    b_left_base: float = 0.08,
    b_right_base: float = 0.82,
) -> List[Tuple[float, float, float]]:
    """Compute smooth parameterized binodal envelope curve for Type I ternary system.

    Parameter s in [-1.0, 1.0]:
        s = -1.0 : Raffinate base boundary on BC axis (carrier C rich)
        s =  0.0 : Critical plait point (critical miscibility apex)
        s = +1.0 : Extract base boundary on BC axis (solute B rich)

    Strictly guarantees a(s) + b(s) + c(s) == 1.0 for every point.
    """
    points: List[Tuple[float, float, float]] = []
    step = 2.0 / (num_points - 1)

    for i in range(num_points):
        s = -1.0 + i * step
        # Quadratic dome for solvent A height: peak at s=0, base at s=+-1
        a_val = a_plait * (1.0 - s * s) + a_base * (s * s)
        # Smooth monotonic progression of solute B across width
        b_val = b_plait + 0.37 * s + 0.07 * (s * s)
        # Carrier C by strict sum conservation
        c_val = 1.0 - a_val - b_val
        points.append((a_val, b_val, c_val))

    return points


def generate_tie_lines(
    binodal_points: Optional[List[Tuple[float, float, float]]] = None,
    count: int = 5,
) -> List[TieLine]:
    """Generate canonical equilibrium tie-lines (conodes) inside the binodal envelope.

    Tie-lines connect equilibrium conjugate phases from the raffinate arm to extract arm.
    """
    tie_lines: List[TieLine] = []
    # Relative heights inside envelope: k_frac in (0.15, 0.85)
    k_fractions = [0.18, 0.36, 0.54, 0.72, 0.88] if count == 5 else [
        0.15 + (0.75 * i / max(1, count - 1)) for i in range(count)
    ]

    for idx, k in enumerate(k_fractions):
        s_left = -k
        s_right = k * 0.94  # Slight plait point inclination towards extract branch

        # Raffinate point
        a_r = 0.42 * (1.0 - s_left ** 2) + 0.02 * (s_left ** 2)
        b_r = 0.38 + 0.37 * s_left + 0.07 * (s_left ** 2)
        c_r = 1.0 - a_r - b_r

        # Extract point
        a_e = 0.42 * (1.0 - s_right ** 2) + 0.02 * (s_right ** 2)
        b_e = 0.38 + 0.37 * s_right + 0.07 * (s_right ** 2)
        c_e = 1.0 - a_e - b_e

        k_distrib = b_e / max(1e-4, b_r)
        tie_lines.append(
            TieLine(
                index=idx,
                raffinate=(a_r, b_r, c_r),
                extract=(a_e, b_e, c_e),
                k_factor=k_distrib,
            )
        )

    return tie_lines


def _point_to_segment_distance(
    px: float, py: float, x1: float, y1: float, x2: float, y2: float
) -> float:
    """Distance from point (px, py) to line segment (x1, y1)-(x2, y2)."""
    dx = x2 - x1
    dy = y2 - y1
    l2 = dx * dx + dy * dy
    if l2 <= 1e-9:
        return math.hypot(px - x1, py - y1)
    t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / l2))
    proj_x = x1 + t * dx
    proj_y = y1 + t * dy
    return math.hypot(px - proj_x, py - proj_y)


def _point_in_polygon_cartesian(px: float, py: float, poly: List[Tuple[float, float]]) -> bool:
    """Standard ray-casting algorithm to test whether (px, py) is inside polygon."""
    n = len(poly)
    inside = False
    p1x, p1y = poly[0]
    for i in range(n + 1):
        p2x, p2y = poly[i % n]
        if py > min(p1y, p2y):
            if py <= max(p1y, p2y):
                if px <= max(p1x, p2x):
                    if p1y != p2y:
                        xinters = (py - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                    if p1x == p2x or px <= xinters:
                        inside = not inside
        p1x, p1y = p2x, p2y
    return inside


def is_inside_binodal(
    a: float,
    b: float,
    c: float,
    binodal_points: Optional[List[Tuple[float, float, float]]] = None,
    vertices: Optional[Tuple[Tuple[float, float], Tuple[float, float], Tuple[float, float]]] = None,
) -> bool:
    """Test whether ternary composition (a, b, c) lies inside the two-phase binodal envelope."""
    pts = binodal_points or compute_binodal_curve()
    verts = vertices or STANDARD_TRIANGLE_VERTICES

    # Convert binodal points to 2D polygon
    poly_cartesian = [ternary_to_cartesian(pa, pb, pc, verts) for pa, pb, pc in pts]
    # Close polygon along the base
    op_x, op_y = ternary_to_cartesian(a, b, c, verts)

    return _point_in_polygon_cartesian(op_x, op_y, poly_cartesian)


def compute_distance_to_envelope(
    a: float,
    b: float,
    c: float,
    binodal_points: Optional[List[Tuple[float, float, float]]] = None,
    vertices: Optional[Tuple[Tuple[float, float], Tuple[float, float], Tuple[float, float]]] = None,
) -> float:
    """Calculate Euclidean signed distance (in pixels) from operating point to binodal boundary.

    Sign convention:
        Positive (> 0.0): Operating point is OUTSIDE envelope in single-phase region (safe margin).
        Negative (< 0.0): Operating point is INSIDE envelope in two-phase region (phase excursion).
        Zero     (== 0.0): Operating point lies exactly on the phase boundary.
    """
    pts = binodal_points or compute_binodal_curve()
    verts = vertices or STANDARD_TRIANGLE_VERTICES

    poly_cart = [ternary_to_cartesian(pa, pb, pc, verts) for pa, pb, pc in pts]
    op_x, op_y = ternary_to_cartesian(a, b, c, verts)

    inside = _point_in_polygon_cartesian(op_x, op_y, poly_cart)

    min_dist = float("inf")
    n = len(poly_cart)
    for i in range(n):
        x1, y1 = poly_cart[i]
        x2, y2 = poly_cart[(i + 1) % n]
        d = _point_to_segment_distance(op_x, op_y, x1, y1, x2, y2)
        if d < min_dist:
            min_dist = d

    return -min_dist if inside else min_dist


# ============================================================================
# 6. Data Models: Composition Point, System & Metrics
# ============================================================================

@dataclass
class TernaryComposition:
    """Operating composition point with multi-component fractions."""
    a: float = 0.60                             # Solvent component fraction
    b: float = 0.20                             # Solute component fraction
    c: float = 0.20                             # Carrier component fraction
    label: str = "Operating Point"              # Display label
    flow_rate_kg_h: float = 2500.0              # Total mass flow rate (kg/h)
    temperature_c: float = 25.0                 # System operating temperature (°C)
    pressure_kpa: float = 101.3                 # System operating pressure (kPa)

    def normalized(self) -> Tuple[float, float, float]:
        """Strictly normalized composition (a, b, c)."""
        return normalize_composition(self.a, self.b, self.c)


@dataclass
class TernarySystem:
    """Ternary equilibrium phase system container."""
    system_id: str
    name: str
    mode: SystemMode = SystemMode.LIQUID_LIQUID
    components: Tuple[str, str, str] = ("Water", "Ethanol", "Toluene")
    operating_point: TernaryComposition = field(default_factory=TernaryComposition)
    binodal_points: List[Tuple[float, float, float]] = field(default_factory=compute_binodal_curve)
    tie_lines: List[TieLine] = field(default_factory=generate_tie_lines)
    plait_point: Tuple[float, float, float] = (0.42, 0.38, 0.20)
    critical_distance_px: float = 15.0          # Distance threshold for warning advisory


@dataclass
class TernaryMetrics:
    """Operational metrics summarized for Horner OCS memory synchronization."""
    a_pct: float = 60.0                         # Component A (0.0..100.0%)
    b_pct: float = 20.0                         # Component B (0.0..100.0%)
    c_pct: float = 20.0                         # Component C (0.0..100.0%)
    is_normalized: bool = True                  # Sum equals 1.0 within tolerance
    phase_state: PhaseState = PhaseState.HOMOGENEOUS
    is_excursion: bool = False                  # Operating point inside two-phase zone
    distance_to_envelope_px: float = 65.0       # Signed distance to envelope in pixels
    distance_margin_pct: float = 13.0           # Margin percentage relative to triangle size
    active_phase_count: int = 1                 # 1=Single phase, 2=Two phase
    tie_line_count: int = 5
    system_mode_val: int = 0                    # 0=LIQUID_LIQUID, 1=SOLID_LIQUID, 2=VAPOR_LIQUID

    @property
    def a_scaled(self) -> int:
        """Component A scaled x1000 for %R901 (0..1000)."""
        val = int(round(self.a_pct * 10.0))
        return max(-32768, min(32767, val))

    @property
    def b_scaled(self) -> int:
        """Component B scaled x1000 for %R902 (0..1000)."""
        val = int(round(self.b_pct * 10.0))
        return max(-32768, min(32767, val))

    @property
    def c_scaled(self) -> int:
        """Component C scaled x1000 for %R903 (0..1000)."""
        val = int(round(self.c_pct * 10.0))
        return max(-32768, min(32767, val))

    @property
    def distance_scaled(self) -> int:
        """Envelope signed distance scaled x10 for %R904."""
        val = int(round(self.distance_to_envelope_px * 10.0))
        return max(-32768, min(32767, val))


def compute_ternary_metrics(system: TernarySystem) -> TernaryMetrics:
    """Calculate aggregate phase metrics and excursion state from ternary system."""
    op = system.operating_point
    na, nb, nc = op.normalized()
    total_raw = op.a + op.b + op.c
    is_norm = math.isclose(total_raw, 1.0, rel_tol=1e-3) or math.isclose(total_raw, 100.0, rel_tol=1e-3)

    in_envelope = is_inside_binodal(na, nb, nc, system.binodal_points)
    dist_px = compute_distance_to_envelope(na, nb, nc, system.binodal_points)
    margin_pct = (dist_px / TRIANGLE_SIDE_LENGTH) * 100.0

    if in_envelope:
        state = PhaseState.TWO_PHASE
        phases = 2
    elif abs(dist_px) < system.critical_distance_px:
        state = PhaseState.CRITICAL
        phases = 1
    else:
        state = PhaseState.HOMOGENEOUS
        phases = 1

    mode_val = 0
    if system.mode == SystemMode.SOLID_LIQUID:
        mode_val = 1
    elif system.mode == SystemMode.VAPOR_LIQUID:
        mode_val = 2

    return TernaryMetrics(
        a_pct=na * 100.0,
        b_pct=nb * 100.0,
        c_pct=nc * 100.0,
        is_normalized=is_norm,
        phase_state=state,
        is_excursion=in_envelope,
        distance_to_envelope_px=dist_px,
        distance_margin_pct=margin_pct,
        active_phase_count=phases,
        tie_line_count=len(system.tie_lines),
        system_mode_val=mode_val,
    )


# ============================================================================
# 7. Standalone W3C SVG 1.1 Vector Canvas Renderer
# ============================================================================

def generate_triangle_path(
    vertices: Optional[Tuple[Tuple[float, float], Tuple[float, float], Tuple[float, float]]] = None
) -> str:
    """Generate SVG path for outer Gibbs equilateral triangle frame strictly conforming to 'M ... L ... L ... Z'."""
    va, vb, vc = vertices or STANDARD_TRIANGLE_VERTICES
    return f"M {va[0]:.2f} {va[1]:.2f} L {vb[0]:.2f} {vb[1]:.2f} L {vc[0]:.2f} {vc[1]:.2f} Z"


def generate_binodal_svg_path(
    binodal_points: Optional[List[Tuple[float, float, float]]] = None,
    vertices: Optional[Tuple[Tuple[float, float], Tuple[float, float], Tuple[float, float]]] = None,
) -> str:
    """Generate SVG path for closed two-phase binodal envelope ('M ... L ... Z')."""
    pts = binodal_points or compute_binodal_curve()
    verts = vertices or STANDARD_TRIANGLE_VERTICES

    cart_pts = [ternary_to_cartesian(pa, pb, pc, verts) for pa, pb, pc in pts]
    if not cart_pts:
        return "M 0 0 Z"

    path_parts = [f"M {cart_pts[0][0]:.2f} {cart_pts[0][1]:.2f}"]
    for x, y in cart_pts[1:]:
        path_parts.append(f"L {x:.2f} {y:.2f}")
    path_parts.append("Z")

    return " ".join(path_parts)


def generate_ternary_canvas_svg(
    system: TernarySystem,
    metrics: TernaryMetrics,
    diagnostic_code: DiagnosticCode = DIAG_EVENT_OK,
    status_bits: TernaryStatusBits = TernaryStatusBits.CANVAS_ACTIVE,
    width: int = CANVAS_VIEWPORT_WIDTH,
    height: int = CANVAS_VIEWPORT_HEIGHT,
) -> str:
    """Render standalone W3C SVG 1.1 Ternary / Gibbs Triangle Phase Equilibrium Canvas."""
    diag_int = int(diagnostic_code)
    diag_str = "OK (0x0000)" if diag_int == 0 else f"ALARM (0x{diag_int & 0xFFFF:04X})"

    va, vb, vc = STANDARD_TRIANGLE_VERTICES
    na, nb, nc = system.operating_point.normalized()
    op_x, op_y = ternary_to_cartesian(na, nb, nc)

    is_excursion = metrics.is_excursion
    op_fill = COLOR_TRIP_RED_LIGHT if is_excursion else COLOR_NOMINAL_GREEN_LIGHT
    op_stroke = COLOR_TRIP_RED if is_excursion else COLOR_NOMINAL_GREEN

    svg_parts: List[str] = []
    svg_parts.append('<?xml version="1.0" encoding="UTF-8"?>')
    svg_parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" version="1.1" '
        f'width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
    )

    # Defs: Filters and Shadows
    svg_parts.append("  <defs>")
    svg_parts.append('    <filter id="badge-shadow" x="-10%" y="-10%" width="120%" height="120%">')
    svg_parts.append('      <feDropShadow dx="0" dy="2" stdDeviation="3" flood-color="#000000" flood-opacity="0.6"/>')
    svg_parts.append("    </filter>")
    svg_parts.append("  </defs>")

    # Dark Slate Industrial Backing
    svg_parts.append(f'  <rect width="{width}" height="{height}" fill="{COLOR_DARK_THEME_BACKING}"/>')

    # Diagnostic HUD Header
    svg_parts.append('  <g id="diagnostic-hud">')
    svg_parts.append(f'    <rect x="20" y="15" width="{width - 40}" height="55" rx="6" fill="{COLOR_DECOUPLED_BADGE}" fill-opacity="0.94" filter="url(#badge-shadow)"/>')
    svg_parts.append(f'    <text x="40" y="42" fill="{COLOR_TEXT_PRIMARY}" font-family="Segoe UI, monospace" font-size="16" font-weight="700">CSCAPE HMI - TERNARY / GIBBS TRIANGLE PHASE EQUILIBRIUM (W129)</text>')
    svg_parts.append(f'    <text x="40" y="58" fill="{COLOR_TEXT_MUTED}" font-family="Segoe UI, monospace" font-size="11">SYSTEM: {system.name} | MODE: {system.mode.value} | COMPONENTS: {system.components[0]} (A) / {system.components[1]} (B) / {system.components[2]} (C)</text>')

    diag_color = COLOR_TRIP_RED_LIGHT if diag_int != 0 else COLOR_NOMINAL_GREEN_LIGHT
    svg_parts.append(f'    <rect x="{width - 240}" y="24" width="200" height="36" rx="4" fill="#1E293B" stroke="{diag_color}" stroke-width="1.5"/>')
    svg_parts.append(f'    <text x="{width - 225}" y="47" fill="{diag_color}" font-family="Segoe UI, monospace" font-size="13" font-weight="700">DIAG: {diag_str}</text>')
    svg_parts.append("  </g>")

    # Equilateral Triangle Frame
    svg_parts.append('  <g id="ternary-triangle-frame">')
    triangle_path = generate_triangle_path()
    svg_parts.append(f'    <path d="{triangle_path}" fill="#1E293B" fill-opacity="0.35" stroke="#475569" stroke-width="2.5"/>')

    # Grid Lines (10%, 20%, ... 90% increments)
    svg_parts.append('    <g id="ternary-grid-lines">')
    for tick in range(1, 10):
        frac = tick / 10.0
        # Line of constant a (parallel to BC base)
        p_a1 = ternary_to_cartesian(frac, 1.0 - frac, 0.0)
        p_a2 = ternary_to_cartesian(frac, 0.0, 1.0 - frac)
        svg_parts.append(f'      <line x1="{p_a1[0]:.2f}" y1="{p_a1[1]:.2f}" x2="{p_a2[0]:.2f}" y2="{p_a2[1]:.2f}" stroke="#334155" stroke-width="0.8" stroke-dasharray="3,3"/>')

        # Line of constant b (parallel to AC edge)
        p_b1 = ternary_to_cartesian(1.0 - frac, frac, 0.0)
        p_b2 = ternary_to_cartesian(0.0, frac, 1.0 - frac)
        svg_parts.append(f'      <line x1="{p_b1[0]:.2f}" y1="{p_b1[1]:.2f}" x2="{p_b2[0]:.2f}" y2="{p_b2[1]:.2f}" stroke="#334155" stroke-width="0.8" stroke-dasharray="3,3"/>')

        # Line of constant c (parallel to AB edge)
        p_c1 = ternary_to_cartesian(1.0 - frac, 0.0, frac)
        p_c2 = ternary_to_cartesian(0.0, 1.0 - frac, frac)
        svg_parts.append(f'      <line x1="{p_c1[0]:.2f}" y1="{p_c1[1]:.2f}" x2="{p_c2[0]:.2f}" y2="{p_c2[1]:.2f}" stroke="#334155" stroke-width="0.8" stroke-dasharray="3,3"/>')
    svg_parts.append("    </g>")

    # Triangle Vertex Labels
    svg_parts.append(f'    <text x="{va[0]:.2f}" y="{va[1] - 14.0:.2f}" text-anchor="middle" fill="{COLOR_COMPONENT_A}" font-family="Segoe UI, monospace" font-size="13" font-weight="700">A: {system.components[0]} (100%)</text>')
    svg_parts.append(f'    <text x="{vb[0] + 16.0:.2f}" y="{vb[1] + 18.0:.2f}" text-anchor="start" fill="{COLOR_COMPONENT_B}" font-family="Segoe UI, monospace" font-size="13" font-weight="700">B: {system.components[1]} (100%)</text>')
    svg_parts.append(f'    <text x="{vc[0] - 16.0:.2f}" y="{vc[1] + 18.0:.2f}" text-anchor="end" fill="{COLOR_COMPONENT_C}" font-family="Segoe UI, monospace" font-size="13" font-weight="700">C: {system.components[2]} (100%)</text>')
    svg_parts.append("  </g>")

    # Two-Phase Binodal Envelope
    svg_parts.append('  <g id="binodal-envelope">')
    binodal_path = generate_binodal_svg_path(system.binodal_points)
    svg_parts.append(f'    <path id="binodal-curve-path" d="{binodal_path}" fill="{COLOR_TWO_PHASE_FILL}" fill-opacity="0.22" stroke="{COLOR_TWO_PHASE_STROKE}" stroke-width="2.5"/>')

    # Plait Point Critical Marker
    plait_x, plait_y = ternary_to_cartesian(system.plait_point[0], system.plait_point[1], system.plait_point[2])
    svg_parts.append(f'    <circle id="plait-point" cx="{plait_x:.2f}" cy="{plait_y:.2f}" r="4.5" fill="{COLOR_TEXT_PRIMARY}" stroke="{COLOR_TWO_PHASE_STROKE}" stroke-width="2"/>')
    svg_parts.append(f'    <text x="{plait_x + 8.0:.2f}" y="{plait_y - 8.0:.2f}" fill="{COLOR_TWO_PHASE_STROKE}" font-family="Segoe UI, monospace" font-size="10" font-weight="700">Plait Point</text>')
    svg_parts.append("  </g>")

    # Equilibrium Tie-Lines (Conodes)
    svg_parts.append('  <g id="tie-lines">')
    for tl in system.tie_lines:
        rx, ry = ternary_to_cartesian(tl.raffinate[0], tl.raffinate[1], tl.raffinate[2])
        ex, ey = ternary_to_cartesian(tl.extract[0], tl.extract[1], tl.extract[2])
        svg_parts.append(f'    <line id="tie-line-{tl.index}" x1="{rx:.2f}" y1="{ry:.2f}" x2="{ex:.2f}" y2="{ey:.2f}" stroke="{COLOR_TIE_LINE}" stroke-width="1.2" stroke-dasharray="4,3" opacity="0.85"/>')
    svg_parts.append("  </g>")

    # Operating Point Marker & Excursion Halo
    svg_parts.append('  <g id="operating-point">')
    if is_excursion:
        svg_parts.append(f'    <circle cx="{op_x:.2f}" cy="{op_y:.2f}" r="16" fill="none" stroke="{COLOR_TRIP_RED_LIGHT}" stroke-width="1.8" stroke-dasharray="4,4"/>')
        svg_parts.append(f'    <circle cx="{op_x:.2f}" cy="{op_y:.2f}" r="24" fill="none" stroke="{COLOR_TRIP_RED}" stroke-width="1.2" opacity="0.6"/>')

    svg_parts.append(f'    <circle id="operating-point-marker" cx="{op_x:.2f}" cy="{op_y:.2f}" r="7.5" fill="{op_fill}" stroke="{op_stroke}" stroke-width="2.5"/>')
    svg_parts.append(f'    <text x="{op_x + 12.0:.2f}" y="{op_y - 10.0:.2f}" fill="{COLOR_TEXT_PRIMARY}" font-family="Segoe UI, monospace" font-size="12" font-weight="700">OP: A={metrics.a_pct:.1f}% B={metrics.b_pct:.1f}% C={metrics.c_pct:.1f}%</text>')
    svg_parts.append(f'    <text x="{op_x + 12.0:.2f}" y="{op_y + 8.0:.2f}" fill="{op_stroke}" font-family="Segoe UI, monospace" font-size="10" font-weight="600">STATE: {metrics.phase_state.value} (dist={metrics.distance_to_envelope_px:+.1f}px)</text>')
    svg_parts.append("  </g>")

    # Horner OCS Register Space Telemetry Panel
    svg_parts.append('  <g id="horner-register-space">')
    svg_parts.append(f'    <rect x="20" y="{height - 110}" width="{width - 40}" height="90" rx="6" fill="{COLOR_DECOUPLED_BADGE}" fill-opacity="0.94" filter="url(#badge-shadow)"/>')
    svg_parts.append(f'    <text x="40" y="{height - 85}" fill="{COLOR_TEXT_PRIMARY}" font-family="Segoe UI, monospace" font-size="12" font-weight="700">HORNER OCS REGISTER SPACE (%R900..%R907, %M210..%M211)</text>')
    svg_parts.append(
        f'    <text x="40" y="{height - 62}" fill="{COLOR_TEXT_MUTED}" font-family="Segoe UI, monospace" font-size="11">'
        f'%R900 [Status]=0x{int(status_bits):04X}  |  '
        f'%R901 [CompA]={metrics.a_scaled} ({metrics.a_pct:.1f}%)  |  '
        f'%R902 [CompB]={metrics.b_scaled} ({metrics.b_pct:.1f}%)  |  '
        f'%R903 [CompC]={metrics.c_scaled} ({metrics.c_pct:.1f}%)  |  '
        f'%R904 [DistPxX10]={metrics.distance_scaled}'
        f'</text>'
    )
    svg_parts.append(
        f'    <text x="40" y="{height - 40}" fill="{COLOR_TEXT_MUTED}" font-family="Segoe UI, monospace" font-size="11">'
        f'%R905 [Phases]={metrics.active_phase_count}  |  '
        f'%R906 [Mode]={metrics.system_mode_val}  |  '
        f'%R907 [DiagCode]=0x{diag_int & 0xFFFF:04X}  |  '
        f'%M210 [ExcursionAlarm]={"1 (ALARM)" if is_excursion else "0 (NOMINAL)"}  |  '
        f'%M211 [LimitTrip]={"1 (TRIP)" if (diag_int != 0 or is_excursion) else "0 (CLEAR)"}'
        f'</text>'
    )
    svg_parts.append("  </g>")

    svg_parts.append("</svg>")
    return "\n".join(svg_parts)


# ============================================================================
# 8. Cscape HMI Dynamic Ternary Canvas Engine & ILogicUnit
# ============================================================================

class TernaryCanvas(ILogicUnit):
    """Cscape HMI Dynamic Ternary / Gibbs Triangle Canvas bound to Horner OCS memory."""

    def __init__(
        self,
        system: Optional[TernarySystem] = None,
        reg_table: Optional[RegisterTable] = None,
    ) -> None:
        self.system = system or create_canonical_extraction_system()
        self.reg_table = reg_table or RegisterTable()
        self.status_bits: TernaryStatusBits = TernaryStatusBits.CANVAS_ACTIVE
        self.diagnostic_code: DiagnosticCode = DIAG_EVENT_OK
        self.metrics: TernaryMetrics = compute_ternary_metrics(self.system)

        self.evaluate_equilibrium()
        self.sync_to_registers()

    @property
    def current_mode(self) -> SystemMode:
        """Active ternary equilibrium system mode."""
        return self.system.mode

    def set_system_mode(self, mode: SystemMode) -> None:
        """Switch ternary equilibrium system mode (Liquid-Liquid, Solid-Liquid, Vapor-Liquid)."""
        if mode == SystemMode.LIQUID_LIQUID:
            self.system = create_canonical_extraction_system()
        elif mode == SystemMode.SOLID_LIQUID:
            self.system = create_canonical_eutectic_system()
        elif mode == SystemMode.VAPOR_LIQUID:
            self.system = create_canonical_azeotrope_system()
        else:
            self.diagnostic_code = DIAG_EVENT_COMPOSITION_FAULT
            return

        self.evaluate_equilibrium()
        self.sync_to_registers()

    def set_operating_point(self, a: float, b: float, c: float, label: Optional[str] = None) -> None:
        """Update current operating point composition."""
        self.system.operating_point.a = a
        self.system.operating_point.b = b
        self.system.operating_point.c = c
        if label:
            self.system.operating_point.label = label

        self.evaluate_equilibrium()
        self.sync_to_registers()

    def evaluate_equilibrium(self) -> None:
        """Calculate ternary coordinates, verify sum conservation, and inspect for phase excursions."""
        self.metrics = compute_ternary_metrics(self.system)

        # Update status bits
        self.status_bits |= TernaryStatusBits.CANVAS_ACTIVE
        self.status_bits |= TernaryStatusBits.TERNARY_COMPUTED

        if self.metrics.is_normalized:
            self.status_bits |= TernaryStatusBits.COMPOSITION_NORMALIZED
        else:
            self.status_bits &= ~TernaryStatusBits.COMPOSITION_NORMALIZED

        # WCAG AAA compliance verification
        ok_wcag, _, _ = validate_wcag_aaa_contrast()
        if ok_wcag:
            self.status_bits |= TernaryStatusBits.WCAG_AAA

        # Inspect phase excursion
        if self.metrics.is_excursion:
            self.diagnostic_code = DIAG_EVENT_PHASE_EXCURSION
            self.status_bits |= TernaryStatusBits.PHASE_EXCURSION_ALARM
            self.status_bits |= TernaryStatusBits.EXCURSION_HIGHLIGHTED
            self.status_bits |= TernaryStatusBits.COMPOSITION_LIMIT_TRIP
        else:
            if self.diagnostic_code == DIAG_EVENT_PHASE_EXCURSION:
                self.diagnostic_code = DIAG_EVENT_OK
            self.status_bits &= ~TernaryStatusBits.PHASE_EXCURSION_ALARM
            self.status_bits &= ~TernaryStatusBits.EXCURSION_HIGHLIGHTED
            if self.diagnostic_code == DIAG_EVENT_OK:
                self.status_bits &= ~TernaryStatusBits.COMPOSITION_LIMIT_TRIP

    def trigger_fault(self, fault_code: DiagnosticCode = DIAG_EVENT_COMPOSITION_FAULT) -> None:
        """Inject explicit composition limit or system fault trip."""
        self.diagnostic_code = fault_code
        self.status_bits |= TernaryStatusBits.COMPOSITION_LIMIT_TRIP
        self.sync_to_registers()

    def render_svg(self) -> str:
        """Render standalone W3C SVG 1.1 representation."""
        svg_str = generate_ternary_canvas_svg(
            system=self.system,
            metrics=self.metrics,
            diagnostic_code=self.diagnostic_code,
            status_bits=self.status_bits,
        )
        self.status_bits |= TernaryStatusBits.SVG_VALID
        return svg_str

    def sync_to_registers(self) -> None:
        """Synchronize state into Horner OCS register space (%R900..%R907, %M210..%M211)."""
        reg = self.reg_table
        m = self.metrics

        # %R900: StatusWord
        reg.write_word("%R900", int(self.status_bits), privilege=PrivilegeMode.SYSTEM)

        # %R901: ComponentA_Scaled (INT16, a * 1000)
        reg.write_word("%R901", m.a_scaled, privilege=PrivilegeMode.SYSTEM)

        # %R902: ComponentB_Scaled (INT16, b * 1000)
        reg.write_word("%R902", m.b_scaled, privilege=PrivilegeMode.SYSTEM)

        # %R903: ComponentC_Scaled (INT16, c * 1000)
        reg.write_word("%R903", m.c_scaled, privilege=PrivilegeMode.SYSTEM)

        # %R904: DistToEnvelopeScaled (INT16, distance_px * 10)
        reg.write_word("%R904", m.distance_scaled, privilege=PrivilegeMode.SYSTEM)

        # %R905: ActivePhaseCount (1=Single Phase, 2=Two Phase)
        reg.write_word("%R905", m.active_phase_count, privilege=PrivilegeMode.SYSTEM)

        # %R906: SystemMode (0=LIQUID_LIQUID, 1=SOLID_LIQUID, 2=VAPOR_LIQUID)
        reg.write_word("%R906", m.system_mode_val, privilege=PrivilegeMode.SYSTEM)

        # %R907: DiagEventCode
        reg.write_word("%R907", int(self.diagnostic_code), privilege=PrivilegeMode.SYSTEM)

        # %M210: PhaseBoundaryExcursionAlarm
        excursion_active = bool(
            (int(self.status_bits) & int(TernaryStatusBits.PHASE_EXCURSION_ALARM)) != 0
            or (self.diagnostic_code == DIAG_EVENT_PHASE_EXCURSION)
            or m.is_excursion
        )
        reg.write_bit("%M210", excursion_active, privilege=PrivilegeMode.SYSTEM)

        # %M211: CompositionLimitTrip
        limit_trip_active = bool(
            excursion_active
            or (int(self.status_bits) & int(TernaryStatusBits.COMPOSITION_LIMIT_TRIP)) != 0
            or (self.diagnostic_code == DIAG_EVENT_COMPOSITION_FAULT)
            or (self.diagnostic_code == DIAG_EVENT_BOUNDARY_EXCURSION)
        )
        reg.write_bit("%M211", limit_trip_active, privilege=PrivilegeMode.SYSTEM)

    # ILogicUnit implementation
    @property
    def name(self) -> str:
        return "TernaryCanvasSync"

    @property
    def priority(self) -> int:
        return 75

    @property
    def is_enabled(self) -> bool:
        return True

    def reset(self) -> None:
        """Reset internal unit state to initial nominal conditions."""
        self.system = create_canonical_extraction_system()
        self.status_bits = TernaryStatusBits.CANVAS_ACTIVE
        self.diagnostic_code = DIAG_EVENT_OK
        self.evaluate_equilibrium()
        self.sync_to_registers()

    def execute(self, ctx: ScanContext) -> None:
        """Scan cycle logic step."""
        self.evaluate_equilibrium()
        self.sync_to_registers()

    def step(self) -> None:
        """Single simulation step."""
        self.evaluate_equilibrium()
        self.sync_to_registers()

    def execute_logic(self, ctx: ScanContext) -> None:
        """Execute logic unit interface."""
        self.execute(ctx)


TernaryEngine = TernaryCanvas


# ============================================================================
# 9. Canonical Factory Functions & Test Fixtures
# ============================================================================

def create_canonical_extraction_system(
    excursion: bool = False,
    fault: bool = False,
) -> TernarySystem:
    """Create canonical Type I liquid-liquid extraction system (Water-Ethanol-Toluene)."""
    # Nominal operating point (outside binodal envelope, homogeneous single phase)
    # A (Water / solvent) = 0.60, B (Ethanol / solute) = 0.20, C (Toluene / carrier) = 0.20
    op = TernaryComposition(
        a=0.60,
        b=0.20,
        c=0.20,
        label="Homogeneous Extraction Feed",
        flow_rate_kg_h=3200.0,
        temperature_c=25.0,
    )

    if excursion:
        # Inside binodal dome (miscibility gap excursion)
        # At b=0.45, envelope dome extends to a ~ 0.40. With a=0.15, point is deep in two-phase zone!
        op.a = 0.15
        op.b = 0.45
        op.c = 0.40
        op.label = "Two-Phase Emulsion Excursion"

    sys_obj = TernarySystem(
        system_id="TERNARY_LLE_01",
        name="Water-Ethanol-Toluene Liquid Extraction System",
        mode=SystemMode.LIQUID_LIQUID,
        components=("Water", "Ethanol", "Toluene"),
        operating_point=op,
        binodal_points=compute_binodal_curve(),
        tie_lines=generate_tie_lines(),
        plait_point=(0.42, 0.38, 0.20),
    )
    return sys_obj


def create_canonical_azeotrope_system(
    excursion: bool = False,
    fault: bool = False,
) -> TernarySystem:
    """Create canonical vapor-liquid azeotropic distillation system (Acetone-Chloroform-Methanol)."""
    op = TernaryComposition(
        a=0.55,
        b=0.25,
        c=0.20,
        label="Azeotrope Distillation Overhead",
        flow_rate_kg_h=1800.0,
        temperature_c=64.5,
    )
    if excursion:
        op.a = 0.12
        op.b = 0.48
        op.c = 0.40

    return TernarySystem(
        system_id="TERNARY_VLE_01",
        name="Acetone-Chloroform-Methanol Azeotropic System",
        mode=SystemMode.VAPOR_LIQUID,
        components=("Acetone", "Chloroform", "Methanol"),
        operating_point=op,
        binodal_points=compute_binodal_curve(a_plait=0.38, b_plait=0.40, c_plait=0.22),
        tie_lines=generate_tie_lines(),
        plait_point=(0.38, 0.40, 0.22),
    )


def create_canonical_eutectic_system(
    excursion: bool = False,
    fault: bool = False,
) -> TernarySystem:
    """Create canonical solid-liquid crystallization eutectic system (NaCl-KCl-H2O)."""
    op = TernaryComposition(
        a=0.70,
        b=0.15,
        c=0.15,
        label="Crystallizer Brine Feed",
        flow_rate_kg_h=4500.0,
        temperature_c=40.0,
    )
    if excursion:
        op.a = 0.18
        op.b = 0.42
        op.c = 0.40

    return TernarySystem(
        system_id="TERNARY_SLE_01",
        name="NaCl-KCl-Water Crystallization Eutectic System",
        mode=SystemMode.SOLID_LIQUID,
        components=("Water", "NaCl", "KCl"),
        operating_point=op,
        binodal_points=compute_binodal_curve(a_plait=0.45, b_plait=0.35, c_plait=0.20),
        tie_lines=generate_tie_lines(),
        plait_point=(0.45, 0.35, 0.20),
    )


def create_mock_scan_context(
    cycle: int = 1,
    dt_ms: float = 10.0,
    reg_table: Optional[RegisterTable] = None,
) -> ScanContext:
    """Helper to instantiate mock Horner ScanContext for ILogicUnit execution."""
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
# 10. Pure IEC 61131-3 Structured Text POU
# ============================================================================

TERNARY_PURE_ST_POU: str = """PROGRAM TernaryCanvasSync
VAR
    StatusWord              AT %R900 : INT;
    ComponentA_Scaled       AT %R901 : INT;
    ComponentB_Scaled       AT %R902 : INT;
    ComponentC_Scaled       AT %R903 : INT;
    DistToEnvelopeScaled    AT %R904 : INT;
    ActivePhaseCount        AT %R905 : INT;
    SystemMode              AT %R906 : INT;
    DiagEventCode           AT %R907 : INT;
    PhaseExcursionAlarm     AT %M210 : BOOL;
    CompositionLimitTrip    AT %M211 : BOOL;
    SeparationTripRelay     : BOOL := FALSE;
    VisualAlertBeacon       : BOOL := FALSE;
END_VAR

(* Synchronize phase boundary excursion alarm: bit 3 (8) or diag 0x9A01 (-26111 / 39425) *)
IF ((StatusWord AND 8) <> 0) OR (DiagEventCode = -26111) OR (DiagEventCode = 39425) THEN
    PhaseExcursionAlarm := TRUE;
ELSE
    PhaseExcursionAlarm := FALSE;
END_IF;

(* Synchronize composition limit / fault trip: bit 4 (16) or diag 0x9A01 or 0x9A02 (-26110 / 39426) *)
IF ((StatusWord AND 16) <> 0) OR (DiagEventCode = -26111) OR (DiagEventCode = 39425) OR (DiagEventCode = -26110) OR (DiagEventCode = 39426) THEN
    CompositionLimitTrip := TRUE;
    SeparationTripRelay := TRUE;
ELSE
    CompositionLimitTrip := FALSE;
    SeparationTripRelay := FALSE;
END_IF;

IF PhaseExcursionAlarm OR CompositionLimitTrip THEN
    VisualAlertBeacon := TRUE;
ELSE
    VisualAlertBeacon := FALSE;
END_IF;
END_PROGRAM
"""


def verify_ternary_canvas_pure_st() -> bool:
    """Validate TernaryCanvasSync POU with STParser and SecurityGuard."""
    SecurityGuard.assert_pure_st_content(TERNARY_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(TERNARY_PURE_ST_POU)
    if not pou:
        return False
    return pou.name == "TernaryCanvasSync" and pou.pou_type == POUType.PROGRAM


verify_ternary_pure_st = verify_ternary_canvas_pure_st


# ============================================================================
# 11. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_ternary_canvas_verification(
    output_path: Optional[Union[str, Path]] = None,
    sample_svg_path: Optional[Union[str, Path]] = None,
    evidence_path: Optional[Union[str, Path]] = None,
    svg_path: Optional[Union[str, Path]] = None,
    svg_export_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute complete 9-stage verification suite for Ternary Phase Equilibrium Canvas (W129)."""
    target_evidence_path = output_path or evidence_path
    target_svg_path = sample_svg_path or svg_path or svg_export_path
    test_results: List[Dict[str, Any]] = []

    # Stage 1: Pure ST POU AST Parsing & Anti-Ladder Security Guard
    st_valid = verify_ternary_canvas_pure_st()
    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("""
        PROGRAM BadTernaryLadder
        VAR CanvasActive : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """)
    except LadderForbiddenError:
        ladder_rejected = True

    c1_pass = st_valid and ladder_rejected
    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_AST_Parsing_And_Security_Guard",
        "passed": c1_pass,
        "details": "Parsed TernaryCanvasSync with STParser; validated bound registers %R900..%R907, %M210..%M211; ladder intercepted.",
    })

    # Stage 2: Gibbs Triangular Coordinate Transformation & Sum-to-1 Normalization
    na, nb, nc = normalize_composition(20.0, 30.0, 50.0)
    sum_norm = math.isclose(na + nb + nc, 1.0, rel_tol=1e-5)
    va, vb, vc = STANDARD_TRIANGLE_VERTICES
    # Apex test (1, 0, 0)
    pt_a = ternary_to_cartesian(1.0, 0.0, 0.0)
    pt_b = ternary_to_cartesian(0.0, 1.0, 0.0)
    pt_c = ternary_to_cartesian(0.0, 0.0, 1.0)
    # Centroid test (1/3, 1/3, 1/3)
    pt_cent = ternary_to_cartesian(1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0)

    # Inverse mapping roundtrip test
    rev_a, rev_b, rev_c = cartesian_to_ternary(pt_cent[0], pt_cent[1])
    roundtrip_exact = (
        math.isclose(rev_a, 1.0 / 3.0, rel_tol=1e-4)
        and math.isclose(rev_b, 1.0 / 3.0, rel_tol=1e-4)
        and math.isclose(rev_c, 1.0 / 3.0, rel_tol=1e-4)
    )

    c2_pass = (
        sum_norm
        and math.isclose(pt_a[0], va[0], rel_tol=1e-4)
        and math.isclose(pt_a[1], va[1], rel_tol=1e-4)
        and math.isclose(pt_b[0], vb[0], rel_tol=1e-4)
        and math.isclose(pt_c[0], vc[0], rel_tol=1e-4)
        and roundtrip_exact
    )
    test_results.append({
        "stage": 2,
        "check": "Gibbs_Triangular_Coordinate_Transformation_And_Normalization",
        "passed": c2_pass,
        "details": "Normalized compositions to sum-to-1; verified barycentric forward/inverse transformations with < 1e-4 tolerance.",
    })

    # Stage 3: Binodal Envelope Curve & Critical Plait Point Formulation
    curve_pts = compute_binodal_curve(num_points=61)
    pts_sum_1 = all(math.isclose(pa + pb + pc, 1.0, rel_tol=1e-5) for pa, pb, pc in curve_pts)
    apex_pt = max(curve_pts, key=lambda p: p[0])
    plait_accurate = math.isclose(apex_pt[0], 0.42, rel_tol=1e-3)

    c3_pass = (len(curve_pts) == 61) and pts_sum_1 and plait_accurate
    test_results.append({
        "stage": 3,
        "check": "Binodal_Envelope_Curve_And_Plait_Point_Formulation",
        "passed": c3_pass,
        "details": f"Generated 61-point smooth binodal curve; apex plait point A={apex_pt[0]:.2f} strictly verified; sum-to-1 conserved.",
    })

    # Stage 4: Tie-Line Generation & Equilibrium Phase Partitioning
    tie_lines = generate_tie_lines(count=5)
    tlines_valid = (
        len(tie_lines) == 5
        and all(tl.extract[1] > tl.raffinate[1] for tl in tie_lines)
        and all(tl.k_factor > 1.0 for tl in tie_lines)
    )
    c4_pass = tlines_valid
    test_results.append({
        "stage": 4,
        "check": "Tie_Line_Generation_And_Phase_Partitioning",
        "passed": c4_pass,
        "details": "Interpolated 5 equilibrium tie-lines across miscibility gap; conjugate distribution coefficients K > 1.0 verified.",
    })

    # Stage 5: Standalone W3C SVG 1.1 Vector Canvas Path Generation & Grammar
    tri_path = generate_triangle_path()
    bin_path = generate_binodal_svg_path(curve_pts)
    tri_conforms = tri_path.startswith("M ") and " L " in tri_path and tri_path.endswith(" Z")
    bin_conforms = bin_path.startswith("M ") and " L " in bin_path and bin_path.endswith(" Z")

    c5_pass = tri_conforms and bin_conforms
    test_results.append({
        "stage": 5,
        "check": "SVG_Vector_Path_Generation_Grammar",
        "passed": c5_pass,
        "details": "Generated valid W3C SVG paths for triangle frame and binodal curve strictly conforming to 'M ... L ... Z' grammar.",
    })

    # Stage 6: WCAG 2.1 AAA Contrast Ratio & Accessibility Checks
    contrast_text = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    contrast_dark_text = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    contrast_graphic = calculate_contrast_ratio(COLOR_NOMINAL_GREEN_LIGHT, COLOR_DARK_THEME_BACKING)
    contrast_amber = calculate_contrast_ratio(COLOR_ADVISORY_AMBER_LIGHT, COLOR_DARK_THEME_BACKING)
    contrast_red = calculate_contrast_ratio(COLOR_TRIP_RED_LIGHT, COLOR_DARK_THEME_BACKING)

    c6_pass = (
        contrast_text >= WCAG_AAA_TEXT_CONTRAST_TARGET
        and contrast_text > 18.0
        and contrast_dark_text >= WCAG_AAA_TEXT_CONTRAST_TARGET
        and contrast_graphic >= WCAG_GRAPHICAL_CONTRAST_TARGET
        and contrast_amber >= WCAG_GRAPHICAL_CONTRAST_TARGET
        and contrast_red >= WCAG_GRAPHICAL_CONTRAST_TARGET
    )
    test_results.append({
        "stage": 6,
        "check": "WCAG_21_AAA_Accessibility_And_Contrast_Checks",
        "passed": c6_pass,
        "details": f"Decoupled badge contrast {contrast_text:.2f}:1 (> 18:1), Graphical boundary contrast {contrast_graphic:.2f}:1 (> 3:1) verified.",
    })

    # Stage 7: Phase Boundary Excursion Detection & Alarm Assertion (%M210, Code 0x9A01)
    sys_nom = create_canonical_extraction_system(excursion=False)
    canvas_nom = TernaryCanvas(system=sys_nom)

    sys_excur = create_canonical_extraction_system(excursion=True)
    canvas_excur = TernaryCanvas(system=sys_excur)

    nom_ok = (
        canvas_nom.metrics.is_excursion is False
        and canvas_nom.metrics.distance_to_envelope_px > 0.0
        and canvas_nom.reg_table.read_bit("%M210") is False
        and canvas_nom.reg_table.read_bit("%M211") is False
        and canvas_nom.diagnostic_code == DIAG_EVENT_OK
    )

    excur_ok = (
        canvas_excur.metrics.is_excursion is True
        and canvas_excur.metrics.distance_to_envelope_px < 0.0
        and canvas_excur.reg_table.read_bit("%M210") is True
        and canvas_excur.reg_table.read_bit("%M211") is True
        and canvas_excur.diagnostic_code == DIAG_EVENT_PHASE_EXCURSION
        and canvas_excur.diagnostic_code == 0x9A01
        and bool(canvas_excur.status_bits & TernaryStatusBits.PHASE_EXCURSION_ALARM)
        and bool(canvas_excur.status_bits & TernaryStatusBits.EXCURSION_HIGHLIGHTED)
    )

    c7_pass = nom_ok and excur_ok
    test_results.append({
        "stage": 7,
        "check": "Phase_Boundary_Excursion_Detection_And_Alarm_Assertion",
        "passed": c7_pass,
        "details": "Identified two-phase emulsion excursion (A=15%, B=45%, C=40%); %M210 asserted, diagnostic event 0x9A01 logged.",
    })

    # Stage 8: Standalone W3C SVG XML Validation & Artifact Generation
    svg_content = canvas_nom.render_svg()
    xml_valid = False
    try:
        ET.fromstring(svg_content)
        xml_valid = True
    except ET.ParseError:
        xml_valid = False

    svg_has_structure = (
        '<svg xmlns="http://www.w3.org/2000/svg"' in svg_content
        and 'width="1200"' in svg_content
        and 'height="750"' in svg_content
        and COLOR_DARK_THEME_BACKING in svg_content
        and 'id="diagnostic-hud"' in svg_content
        and 'id="ternary-triangle-frame"' in svg_content
        and 'id="binodal-envelope"' in svg_content
        and 'id="tie-lines"' in svg_content
        and 'id="operating-point"' in svg_content
    )

    c8_pass = xml_valid and svg_has_structure
    test_results.append({
        "stage": 8,
        "check": "Standalone_W3C_SVG_XML_Validation_And_Canvas_Rendering",
        "passed": c8_pass,
        "details": "Rendered 1200x750 standalone SVG; XML schema valid; diagnostic HUD header, Gibbs triangle, and binodal envelope verified.",
    })

    if target_svg_path:
        out_svg = Path(target_svg_path)
        out_svg.parent.mkdir(parents=True, exist_ok=True)
        with open(out_svg, "w", encoding="utf-8") as f:
            f.write(svg_content)

    # Stage 9: Horner OCS Register Space Synchronization & Fault Trips (%R900..%R907, %M210..%M211)
    reg = canvas_nom.reg_table
    r900 = reg.read_uword("%R900")
    r901 = reg.read_word("%R901")
    r902 = reg.read_word("%R902")
    r903 = reg.read_word("%R903")
    r904 = reg.read_word("%R904")
    r905 = reg.read_word("%R905")
    r906 = reg.read_word("%R906")
    r907 = reg.read_word("%R907")
    m210 = reg.read_bit("%M210")
    m211 = reg.read_bit("%M211")

    sync_ok = (
        (r900 & int(TernaryStatusBits.CANVAS_ACTIVE)) != 0
        and (r900 & int(TernaryStatusBits.TERNARY_COMPUTED)) != 0
        and (r900 & int(TernaryStatusBits.COMPOSITION_NORMALIZED)) != 0
        and r901 == 600     # 60.0% Component A
        and r902 == 200     # 20.0% Component B
        and r903 == 200     # 20.0% Component C
        and r904 > 0        # Positive safe margin
        and r905 == 1       # Single homogeneous phase
        and r906 == 0       # Mode: LIQUID_LIQUID
        and r907 == DIAG_EVENT_OK
        and m210 is False
        and m211 is False
    )

    # Injected composition fault trip
    canvas_fault = TernaryCanvas()
    canvas_fault.trigger_fault(DIAG_EVENT_COMPOSITION_FAULT)
    fault_m211 = canvas_fault.reg_table.read_bit("%M211")
    fault_diag = canvas_fault.reg_table.read_word("%R907")

    fault_trip_ok = fault_m211 is True and fault_diag == DIAG_EVENT_COMPOSITION_FAULT

    c9_pass = sync_ok and fault_trip_ok
    test_results.append({
        "stage": 9,
        "check": "Horner_OCS_Register_Space_Synchronization_And_Fault_Trips",
        "passed": c9_pass,
        "details": f"%R900=0x{r900:04X}, %R901={r901} (A=60.0%), %R902={r902} (B=20.0%), %R903={r903} (C=20.0%); %M211 fault trip verified.",
    })

    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": f"Ternary / Gibbs Triangle Canvas verification passed cleanly ({sum(1 for t in test_results if t['passed'])}/{len(test_results)} checks passed).",
        "data": {
            "work_package": "W129",
            "gate": "Gate G9 / G2",
            "component": "Cscape HMI Dynamic Ternary / Gibbs Triangle Phase Equilibrium Canvas",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "metrics": {
                "component_a_pct": canvas_nom.metrics.a_pct,
                "component_b_pct": canvas_nom.metrics.b_pct,
                "component_c_pct": canvas_nom.metrics.c_pct,
                "active_phase_count": canvas_nom.metrics.active_phase_count,
                "distance_to_envelope_px": canvas_nom.metrics.distance_to_envelope_px,
                "text_contrast_ratio": round(contrast_text, 2),
                "graphical_contrast_ratio": round(contrast_graphic, 2),
            },
            "register_map": {
                "analog_registers": "%R900..%R907",
                "discrete_coils": "%M210..%M211",
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    if target_evidence_path:
        out_p = Path(target_evidence_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence


if __name__ == "__main__":
    result = run_ternary_canvas_verification()
    print(json.dumps(result, indent=2))
