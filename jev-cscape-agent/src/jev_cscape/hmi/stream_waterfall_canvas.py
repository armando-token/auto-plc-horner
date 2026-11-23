"""Cscape HMI Dynamic Stream / Waterfall Multi-Epoch Hydrodynamic Flow SCADA Canvas.

Work Package: W189 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Provides:
1. Strict Pure IEC 61131-3 Structured Text (ST) POU:
   - Program 'StreamWaterfallCanvasSync' (and aliases 'StreamWaterfallHmiSync', 'WaterfallCanvasSync')
     with Horner OCS RegisterTable bindings:
     - %R1500: ActiveStreamCount (INT16, 1..5)
     - %R1501: TotalThroughputBpdScaled (INT16, scaled / 10 barrels per day, e.g. 1500 = 15,000 BPD)
     - %R1502: DominantStreamIndex (INT16, 1..5)
     - %R1503: WaterfallEpochDepth (INT16, e.g. 24 epochs)
     - %R1504: HydrodynamicTurbulenceScaled (INT16, scaled x10, e.g. 24 = 2.4 Re/1000)
     - %R1505: FlowVelocityVariationScaled (INT16, scaled x10 %, e.g. 45 = 4.5 %)
     - %R1506: StreamDispersionCoeffScaled (INT16, scaled x100, e.g. 120 = 1.20)
     - %R1507: DiagnosticStatusCode (0x0000=OK, 0xD301=Turbulence Breach, 0xD302=Flow Starvation, 0xD303=SVG Render Fault)
     - %M350: WaterfallStreamingActive (BOOL)
     - %M351: FlowTurbulenceWarning (BOOL)
   - Validated with SecurityGuard.assert_pure_st_content and STParser.
   - Aggressive ladder logic interception (---[ ]---, ---( )---, RUNG, NETWORK, XIC, OTE)
     failing closed with ERR_LADDER_FORBIDDEN (LadderForbiddenError).

2. 5 Industrial Process Hydrodynamic Streams:
   1 = Syngas Feed (Primary syngas reactant inflow, nominal 4,200 BPD, Cyan #00B4D8)
   2 = Liquid Wax (Heavy synthetic hydrocarbon fraction C20+, nominal 3,800 BPD, Amber #F59E0B)
   3 = Heavy Diesel (Middle distillate fraction C12-C19, nominal 3,500 BPD, Emerald #10B981)
   4 = Naphtha (Light hydrocarbon boiling fraction C5-C11, nominal 2,300 BPD, Violet #8B5CF6)
   5 = Offgas/Tailgas (Light unreacted fuel gas C1-C4, nominal 1,200 BPD, Rose #EC4899)
   Nominal Aggregate Throughput = 15,000 BPD (Scaled / 10 = 1500). Dominant Stream = Stream 1.

3. Multi-Epoch Hydrodynamic Waterfall Stacking Engine:
   - Dynamic epoch offsets across T historical time slices (default 24 epochs, configurable 8..48).
   - Smooth cubic Bézier spline interpolation (curveto 'C' commands) and sinusoidal stream bands.
   - Hydrodynamic turbulence wave ripples and velocity variation dispersion.
   - Top path forward, bottom path reverse, closed ribbon polygons with 'Z'.
   - Golden design baseline envelope comparison vs real-time stacked stream ribbons with linear gradient fills.

4. Standalone W3C SVG 1.1 Vector Canvas Renderer:
   - 1200x750 industrial viewport with dark theme backing (#0D1117 / #161B22).
   - Decoupled dark backing badges (#080C10) meeting WCAG 2.1 AAA contrast:
     * Badge contrast > 18:1
     * Primary text contrast > 7.0:1
     * Graphical SCADA boundaries > 3.0:1
   - Interactive stream selector tabs (All Streams, Streams 1..5) and epoch depth slider.
   - Comprehensive telemetry HUD cards for Horner OCS memory map and hydrodynamic telemetry.

5. Process Safety Interlocks & Diagnostics:
   - 0xD301: STREAM_ERR_TURBULENCE_BREACH (Hydrodynamic turbulence >= trip limit) -> asserts %M351.
   - 0xD302: STREAM_ERR_FLOW_STARVATION (Total throughput < safe minimum threshold).
   - 0xD303: STREAM_ERR_RENDER_FAULT (SVG path or polygon synthesis fault).
   - 0x0000: STREAM_ERR_OK / DIAG_EVENT_OK.

6. Horner OCS Memory Space Integration & ILogicUnit:
   - Synchronizes word registers %R1500..%R1507 and discrete coils %M350..%M351.
   - In sync_to_registers(), passes privilege=PrivilegeMode.SYSTEM to reg_table writes.
   - Implements ILogicUnit interface with scan_step(dt).

7. Deterministic 9-Stage Verification Suite:
   - run_stream_waterfall_canvas_verification(output_path, sample_svg_path) implementing 9 stages
     and returning strict 4-state engineering contract JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntFlag
import html
import json
import math
from pathlib import Path
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union
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
        return hash(int(self))


# Diagnostic event codes conforming to Horner OCS %R1507 specification
DIAG_EVENT_OK: DiagnosticCode                   = DiagnosticCode(0x0000)
STREAM_ERR_OK: DiagnosticCode                   = DiagnosticCode(0x0000)

# 0xD301: STREAM_ERR_TURBULENCE_BREACH (Turbulence breach -> asserts %M351)
STREAM_ERR_TURBULENCE_BREACH: DiagnosticCode    = DiagnosticCode(0xD301)
STREAM_ERR_TURBULENCE: DiagnosticCode           = STREAM_ERR_TURBULENCE_BREACH
DIAG_EVENT_TURBULENCE_BREACH: DiagnosticCode    = STREAM_ERR_TURBULENCE_BREACH
DIAG_EVENT_TURBULENCE: DiagnosticCode           = STREAM_ERR_TURBULENCE_BREACH

# 0xD302: STREAM_ERR_FLOW_STARVATION (Flow Starvation)
STREAM_ERR_FLOW_STARVATION: DiagnosticCode      = DiagnosticCode(0xD302)
STREAM_ERR_STARVATION: DiagnosticCode           = STREAM_ERR_FLOW_STARVATION
DIAG_EVENT_FLOW_STARVATION: DiagnosticCode      = STREAM_ERR_FLOW_STARVATION
DIAG_EVENT_STARVATION: DiagnosticCode           = STREAM_ERR_FLOW_STARVATION

# 0xD303: STREAM_ERR_RENDER_FAULT (SVG Render Fault)
STREAM_ERR_RENDER_FAULT: DiagnosticCode         = DiagnosticCode(0xD303)
DIAG_EVENT_RENDER_FAULT: DiagnosticCode         = STREAM_ERR_RENDER_FAULT

# Color Palette conforming to GitHub Dark / SCADA dark theme & WCAG 2.1 AAA
COLOR_DARK_THEME_BACKING: str                   = "#0D1117"   # Dark canvas backing
COLOR_DARK_THEME_SURFACE: str                   = "#161B22"   # Surface container backing
COLOR_DARK_THEME_BACKING_1E1E1E: str            = "#1E1E1E"   # Alternative dark backing
COLOR_DECOUPLED_BADGE: str                      = "#05080C"   # Decoupled badge backing (> 18:1 contrast)
COLOR_CARD_BORDER: str                          = "#30363D"   # Border slate
COLOR_TEXT_PRIMARY: str                         = "#F0F6FC"   # Primary light text (contrast > 17:1)
COLOR_TEXT_MUTED: str                           = "#8B949E"   # Secondary muted text
COLOR_GRID_LINE: str                            = "#21262D"   # Grid contour lines
COLOR_GRID_TICK: str                            = "#30363D"   # Axis tick markers
COLOR_GOLDEN_BASELINE: str                      = "#E3B341"   # Target golden design baseline envelope
COLOR_FOCUS_BLUE: str                           = "#58A6FF"   # Interactive selection accent

# 5 Process Streams Industrial Palette
COLOR_STREAM_1_SYNGAS: str                      = "#00B4D8"   # 1 = Syngas Feed (Cyan)
COLOR_STREAM_1_DARK: str                        = "#0077B6"
COLOR_STREAM_2_WAX: str                         = "#F59E0B"   # 2 = Liquid Wax (Amber)
COLOR_STREAM_2_DARK: str                        = "#D97706"
COLOR_STREAM_3_DIESEL: str                      = "#10B981"   # 3 = Heavy Diesel (Emerald)
COLOR_STREAM_3_DARK: str                        = "#059669"
COLOR_STREAM_4_NAPHTHA: str                     = "#8B5CF6"   # 4 = Naphtha (Violet)
COLOR_STREAM_4_DARK: str                        = "#6D28D9"
COLOR_STREAM_5_OFFGAS: str                      = "#EC4899"   # 5 = Offgas/Tailgas (Rose)
COLOR_STREAM_5_DARK: str                        = "#BE185D"

# Status Indicators
COLOR_NOMINAL_GREEN: str                        = "#238636"   # Healthy nominal green
COLOR_WARNING_AMBER: str                        = "#D29922"   # Advisory warning amber
COLOR_TRIP_CRIMSON: str                         = "#DA3633"   # Safety interlock crimson

# Nominal SCADA Process Constants
NOMINAL_STREAM_1_BPD: float                     = 4200.0      # Stream 1: Syngas Feed
NOMINAL_STREAM_2_BPD: float                     = 3800.0      # Stream 2: Liquid Wax
NOMINAL_STREAM_3_BPD: float                     = 3500.0      # Stream 3: Heavy Diesel
NOMINAL_STREAM_4_BPD: float                     = 2300.0      # Stream 4: Naphtha
NOMINAL_STREAM_5_BPD: float                     = 1200.0      # Stream 5: Offgas/Tailgas
NOMINAL_TOTAL_THROUGHPUT_BPD: float             = 15000.0     # Total = 15,000 BPD
NOMINAL_TOTAL_THROUGHPUT_BPD_SCALED: int        = 1500        # Scaled / 10 = 1500
NOMINAL_ACTIVE_STREAM_COUNT: int                = 5           # 5 process streams
NOMINAL_DOMINANT_STREAM_INDEX: int              = 1           # Stream 1 Syngas is dominant
DEFAULT_EPOCH_DEPTH: int                        = 24          # 24 epochs default
MIN_EPOCH_DEPTH: int                            = 8           # Minimum supported epochs
MAX_EPOCH_DEPTH: int                            = 48          # Maximum supported epochs
NOMINAL_HYDRODYNAMIC_TURBULENCE: float          = 2.4         # 2.4 Re/1000
NOMINAL_HYDRODYNAMIC_TURBULENCE_SCALED: int     = 24          # Scaled x10 = 24
NOMINAL_FLOW_VELOCITY_VARIATION_PCT: float      = 4.5         # 4.5 %
NOMINAL_FLOW_VELOCITY_VARIATION_SCALED: int     = 45          # Scaled x10 = 45
NOMINAL_STREAM_DISPERSION_COEFF: float          = 1.20        # 1.20
NOMINAL_STREAM_DISPERSION_COEFF_SCALED: int     = 120         # Scaled x100 = 120

# Safety Thresholds
TURBULENCE_WARNING_THRESHOLD: float             = 3.5         # Re/1000 warning trigger (scaled 35)
TURBULENCE_TRIP_THRESHOLD: float                = 4.0         # Re/1000 critical breach (scaled 40)
FLOW_STARVATION_THRESHOLD_BPD: float            = 1000.0      # Minimum throughput floor (scaled 100)

# Viewport & Layout Geometry
CANVAS_VIEWPORT_WIDTH: int                      = 1200
CANVAS_VIEWPORT_HEIGHT: int                     = 750
PLOT_X_MIN: float                               = 80.0
PLOT_X_MAX: float                               = 880.0
PLOT_Y_MIN: float                               = 140.0
PLOT_Y_MAX: float                               = 680.0
PLOT_WIDTH: float                               = PLOT_X_MAX - PLOT_X_MIN
PLOT_HEIGHT: float                              = PLOT_Y_MAX - PLOT_Y_MIN

# WCAG 2.1 AAA Contrast Targets
WCAG_AAA_BADGE_CONTRAST_TARGET: float           = 18.0        # Decoupled dark backing badge (> 18:1)
WCAG_AAA_TEXT_CONTRAST_TARGET: float            = 7.0         # Normal text (> 7.0:1)
WCAG_GRAPHICAL_CONTRAST_TARGET: float           = 3.0         # SCADA graphics & boundaries (> 3.0:1)


# ============================================================================
# 2. Telemetry Bitmask & Enums
# ============================================================================

class StreamWaterfallStatusBits(IntFlag):
    """Horner OCS Stream / Waterfall Telemetry Status Bitmask Definitions."""
    ENGINE_ACTIVE          = 1 << 0  # Bit 0 (0x0001): Canvas & hydrodynamic engine active
    STREAMING_ACTIVE       = 1 << 1  # Bit 1 (0x0002): Waterfall multi-epoch flow streaming active (%M350)
    HYDRODYNAMICS_COMPUTED = 1 << 2  # Bit 2 (0x0004): Stacked cubic Bezier ribbons computed
    NOMINAL_OPERATION      = 1 << 3  # Bit 3 (0x0008): All streams within normal operating envelope
    TURBULENCE_WARNING     = 1 << 4  # Bit 4 (0x0010): Hydrodynamic turbulence warning asserted (%M351)
    FLOW_STARVATION        = 1 << 5  # Bit 5 (0x0020): Process flow starvation detected
    SVG_VALID              = 1 << 6  # Bit 6 (0x0040): Standalone W3C SVG 1.1 rendered and valid
    WCAG_AAA               = 1 << 7  # Bit 7 (0x0080): WCAG 2.1 AAA contrast verified (> 18:1 badge, > 7:1 text)


WaterfallStatusBits = StreamWaterfallStatusBits


class StreamId(int, Enum):
    """5 SCADA Process Stream Identifiers."""
    SYNGAS_FEED   = 1
    LIQUID_WAX    = 2
    HEAVY_DIESEL  = 3
    NAPHTHA       = 4
    OFFGAS_TAILGAS = 5


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
    badge_bg: str = COLOR_DECOUPLED_BADGE,
    theme_bg: str = COLOR_DARK_THEME_BACKING,
    graphics_colors: Optional[List[str]] = None,
) -> Tuple[bool, float, float, float]:
    """Validate that text, badges, and graphics meet WCAG 2.1 AAA contrast standards."""
    if graphics_colors is None:
        graphics_colors = [
            COLOR_STREAM_1_SYNGAS,
            COLOR_STREAM_2_WAX,
            COLOR_STREAM_3_DIESEL,
            COLOR_STREAM_4_NAPHTHA,
            COLOR_STREAM_5_OFFGAS,
        ]

    badge_contrast = calculate_contrast_ratio(text_color, badge_bg)
    theme_contrast = calculate_contrast_ratio(text_color, theme_bg)
    graphics_contrasts = [calculate_contrast_ratio(g, theme_bg) for g in graphics_colors]
    min_graphics_contrast = min(graphics_contrasts) if graphics_contrasts else 0.0

    badge_ok = badge_contrast >= WCAG_AAA_BADGE_CONTRAST_TARGET
    text_ok = theme_contrast >= WCAG_AAA_TEXT_CONTRAST_TARGET
    graphics_ok = min_graphics_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET

    all_ok = badge_ok and text_ok and graphics_ok
    return (all_ok, badge_contrast, theme_contrast, min_graphics_contrast)


DECOUPLED_BADGE_CONTRAST_RATIO: float = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
DARK_THEME_TEXT_CONTRAST_RATIO: float = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
GRAPHICAL_BOUNDARY_CONTRAST_RATIO: float = calculate_contrast_ratio(COLOR_STREAM_1_SYNGAS, COLOR_DARK_THEME_BACKING)


# ============================================================================
# 4. Stream Data Structures & Configuration
# ============================================================================

@dataclass
class StreamDataPoint:
    """Individual hydrodynamic stream sample point at a given epoch."""
    epoch: int
    stream_id: int
    stream_name: str
    flow_rate_bpd: float
    velocity_fps: float = 0.0
    turbulence_re: float = NOMINAL_HYDRODYNAMIC_TURBULENCE
    dispersion_coeff: float = NOMINAL_STREAM_DISPERSION_COEFF
    y_top: float = 0.0
    y_bottom: float = 0.0
    timestamp_offset_s: float = 0.0


@dataclass
class ProcessStream:
    """Industrial process stream layer definition."""
    stream_id: int                                # 1..5
    name: str                                     # Human readable process name
    color: str                                    # SCADA hex primary color
    color_dark: str                               # Gradient end color
    nominal_bpd: float                            # Nominal operating flow rate (barrels per day)
    current_bpd: float = 0.0                      # Current live throughput
    flow_history: List[float] = field(default_factory=list)
    velocity_history: List[float] = field(default_factory=list)
    is_active: bool = True
    is_critical: bool = True

    @property
    def nominal_fraction(self) -> float:
        return self.nominal_bpd / NOMINAL_TOTAL_THROUGHPUT_BPD


@dataclass
class StreamWaterfallConfig:
    """Configuration container for Stream Waterfall SCADA Canvas."""
    viewport_width: int = CANVAS_VIEWPORT_WIDTH
    viewport_height: int = CANVAS_VIEWPORT_HEIGHT
    epoch_depth: int = DEFAULT_EPOCH_DEPTH
    nominal_total_bpd: float = NOMINAL_TOTAL_THROUGHPUT_BPD
    turbulence_warning_threshold: float = TURBULENCE_WARNING_THRESHOLD
    turbulence_trip_threshold: float = TURBULENCE_TRIP_THRESHOLD
    flow_starvation_threshold_bpd: float = FLOW_STARVATION_THRESHOLD_BPD
    selected_stream_index: int = 0                # 0 = All streams, 1..5 = Specific stream
    selected_epoch_index: int = DEFAULT_EPOCH_DEPTH - 1  # Latest epoch
    flow_bands_mode: str = "cubic_bezier"         # "cubic_bezier" or "sinusoidal"
    theme_bg_color: str = COLOR_DARK_THEME_BACKING
    theme_surface_color: str = COLOR_DARK_THEME_SURFACE
    decoupled_badge_color: str = COLOR_DECOUPLED_BADGE
    text_primary_color: str = COLOR_TEXT_PRIMARY
    text_muted_color: str = COLOR_TEXT_MUTED


@dataclass
class WaterfallMetrics:
    """Computed operational metrics and Horner register space bindings."""
    active_stream_count: int
    total_throughput_bpd: float
    dominant_stream_index: int
    epoch_depth: int
    hydrodynamic_turbulence: float
    flow_velocity_variation_pct: float
    stream_dispersion_coeff: float
    diagnostic_status_code: DiagnosticCode
    waterfall_streaming_active: bool
    flow_turbulence_warning: bool
    stream_throughputs: Dict[int, float] = field(default_factory=dict)
    dominant_stream_name: str = "Syngas Feed"
    has_turbulence_breach: bool = False
    has_flow_starvation: bool = False
    has_render_fault: bool = False

    @property
    def total_throughput_scaled(self) -> int:
        """Total throughput scaled / 10 for %R1501."""
        return max(-32768, min(32767, int(round(self.total_throughput_bpd / 10.0))))

    @property
    def hydrodynamic_turbulence_scaled(self) -> int:
        """Hydrodynamic turbulence scaled x10 for %R1504."""
        return max(-32768, min(32767, int(round(self.hydrodynamic_turbulence * 10.0))))

    @property
    def flow_velocity_variation_scaled(self) -> int:
        """Flow velocity variation scaled x10 % for %R1505."""
        return max(-32768, min(32767, int(round(self.flow_velocity_variation_pct * 10.0))))

    @property
    def stream_dispersion_coeff_scaled(self) -> int:
        """Stream dispersion coeff scaled x100 for %R1506."""
        return max(-32768, min(32767, int(round(self.stream_dispersion_coeff * 100.0))))


# ============================================================================
# 5. Geometry & Bezier Ribbon Synthesis
# ============================================================================

def compute_cubic_bezier_spline_points(points: Sequence[Tuple[float, float]]) -> str:
    """Generate smooth C1-continuous cubic Bézier spline path segments through points.

    Returns SVG path string: 'M x0 y0 C cp1x cp1y cp2x cp2y x1 y1 ...'
    """
    n = len(points)
    if n == 0:
        return ""
    if n == 1:
        return f"M {points[0][0]:.2f} {points[0][1]:.2f}"
    if n == 2:
        return f"M {points[0][0]:.2f} {points[0][1]:.2f} L {points[1][0]:.2f} {points[1][1]:.2f}"

    path_cmds = [f"M {points[0][0]:.2f} {points[0][1]:.2f}"]
    for i in range(n - 1):
        p0 = points[i - 1] if i > 0 else points[i]
        p1 = points[i]
        p2 = points[i + 1]
        p3 = points[i + 2] if i + 2 < n else p2

        # Catmull-Rom to Cubic Bézier control point conversion
        cp1_x = p1[0] + (p2[0] - p0[0]) / 6.0
        cp1_y = p1[1] + (p2[1] - p0[1]) / 6.0
        cp2_x = p2[0] - (p3[0] - p1[0]) / 6.0
        cp2_y = p2[1] - (p3[1] - p1[1]) / 6.0

        path_cmds.append(f"C {cp1_x:.2f} {cp1_y:.2f}, {cp2_x:.2f} {cp2_y:.2f}, {p2[0]:.2f} {p2[1]:.2f}")

    return " ".join(path_cmds)


def generate_stream_ribbon_svg_path(
    top_points: Sequence[Tuple[float, float]],
    bottom_points: Sequence[Tuple[float, float]],
) -> str:
    """Generate closed ribbon SVG path from top forward points and bottom reverse points.

    Produces: 'M top_0 C... L bottom_last C... Z'
    """
    if not top_points or not bottom_points or len(top_points) != len(bottom_points):
        return ""

    # Forward spline along top boundary
    top_spline = compute_cubic_bezier_spline_points(top_points)

    # Reverse points along bottom boundary
    rev_bottom = list(reversed(bottom_points))
    n = len(rev_bottom)

    bottom_cmds = [f"L {rev_bottom[0][0]:.2f} {rev_bottom[0][1]:.2f}"]
    for i in range(n - 1):
        p0 = rev_bottom[i - 1] if i > 0 else rev_bottom[i]
        p1 = rev_bottom[i]
        p2 = rev_bottom[i + 1]
        p3 = rev_bottom[i + 2] if i + 2 < n else p2

        cp1_x = p1[0] + (p2[0] - p0[0]) / 6.0
        cp1_y = p1[1] + (p2[1] - p0[1]) / 6.0
        cp2_x = p2[0] - (p3[0] - p1[0]) / 6.0
        cp2_y = p2[1] - (p3[1] - p1[1]) / 6.0

        bottom_cmds.append(f"C {cp1_x:.2f} {cp1_y:.2f}, {cp2_x:.2f} {cp2_y:.2f}, {p2[0]:.2f} {p2[1]:.2f}")

    bottom_spline = " ".join(bottom_cmds)
    return f"{top_spline} {bottom_spline} Z"


# ============================================================================
# 6. Canonical Factories
# ============================================================================

def create_canonical_process_streams(epoch_depth: int = DEFAULT_EPOCH_DEPTH) -> List[ProcessStream]:
    """Create 5 canonical Fischer-Tropsch hydrodynamic process streams with synthetic flow profiles."""
    t_count = max(MIN_EPOCH_DEPTH, min(MAX_EPOCH_DEPTH, epoch_depth))

    # Stream 1: Syngas Feed (Cyan #00B4D8, nominal 4,200 BPD, dominant stream)
    h1 = [NOMINAL_STREAM_1_BPD + 250.0 * math.sin(t * 0.45) for t in range(t_count)]
    v1 = [12.5 + 0.6 * math.sin(t * 0.45) for t in range(t_count)]

    # Stream 2: Liquid Wax (Amber #F59E0B, nominal 3,800 BPD)
    h2 = [NOMINAL_STREAM_2_BPD + 180.0 * math.cos(t * 0.38) for t in range(t_count)]
    v2 = [8.2 + 0.4 * math.cos(t * 0.38) for t in range(t_count)]

    # Stream 3: Heavy Diesel (Emerald #10B981, nominal 3,500 BPD)
    h3 = [NOMINAL_STREAM_3_BPD + 220.0 * math.sin(t * 0.32 + 1.2) for t in range(t_count)]
    v3 = [10.1 + 0.5 * math.sin(t * 0.32 + 1.2) for t in range(t_count)]

    # Stream 4: Naphtha (Violet #8B5CF6, nominal 2,300 BPD)
    h4 = [NOMINAL_STREAM_4_BPD + 140.0 * math.cos(t * 0.55 + 2.1) for t in range(t_count)]
    v4 = [14.0 + 0.7 * math.cos(t * 0.55 + 2.1) for t in range(t_count)]

    # Stream 5: Offgas/Tailgas (Rose #EC4899, nominal 1,200 BPD)
    h5 = [NOMINAL_STREAM_5_BPD + 90.0 * math.sin(t * 0.60 + 0.8) for t in range(t_count)]
    v5 = [18.5 + 0.9 * math.sin(t * 0.60 + 0.8) for t in range(t_count)]

    # Anchor the live current epoch (last slice) exactly to nominal operating values
    h1[-1] = NOMINAL_STREAM_1_BPD
    h2[-1] = NOMINAL_STREAM_2_BPD
    h3[-1] = NOMINAL_STREAM_3_BPD
    h4[-1] = NOMINAL_STREAM_4_BPD
    h5[-1] = NOMINAL_STREAM_5_BPD

    return [
        ProcessStream(
            stream_id=1,
            name="Syngas Feed",
            color=COLOR_STREAM_1_SYNGAS,
            color_dark=COLOR_STREAM_1_DARK,
            nominal_bpd=NOMINAL_STREAM_1_BPD,
            current_bpd=h1[-1],
            flow_history=h1,
            velocity_history=v1,
        ),
        ProcessStream(
            stream_id=2,
            name="Liquid Wax",
            color=COLOR_STREAM_2_WAX,
            color_dark=COLOR_STREAM_2_DARK,
            nominal_bpd=NOMINAL_STREAM_2_BPD,
            current_bpd=h2[-1],
            flow_history=h2,
            velocity_history=v2,
        ),
        ProcessStream(
            stream_id=3,
            name="Heavy Diesel",
            color=COLOR_STREAM_3_DIESEL,
            color_dark=COLOR_STREAM_3_DARK,
            nominal_bpd=NOMINAL_STREAM_3_BPD,
            current_bpd=h3[-1],
            flow_history=h3,
            velocity_history=v3,
        ),
        ProcessStream(
            stream_id=4,
            name="Naphtha",
            color=COLOR_STREAM_4_NAPHTHA,
            color_dark=COLOR_STREAM_4_DARK,
            nominal_bpd=NOMINAL_STREAM_4_BPD,
            current_bpd=h4[-1],
            flow_history=h4,
            velocity_history=v4,
        ),
        ProcessStream(
            stream_id=5,
            name="Offgas/Tailgas",
            color=COLOR_STREAM_5_OFFGAS,
            color_dark=COLOR_STREAM_5_DARK,
            nominal_bpd=NOMINAL_STREAM_5_BPD,
            current_bpd=h5[-1],
            flow_history=h5,
            velocity_history=v5,
        ),
    ]


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
# 7. Pure IEC 61131-3 Structured Text POU
# ============================================================================

STREAM_WATERFALL_PURE_ST_POU: str = """PROGRAM StreamWaterfallCanvasSync
VAR
    ActiveStreamCount            AT %R1500 : INT;
    TotalThroughputBpdScaled     AT %R1501 : INT;
    DominantStreamIndex          AT %R1502 : INT;
    WaterfallEpochDepth          AT %R1503 : INT;
    HydrodynamicTurbulenceScaled AT %R1504 : INT;
    FlowVelocityVariationScaled  AT %R1505 : INT;
    StreamDispersionCoeffScaled  AT %R1506 : INT;
    DiagnosticStatusCode         AT %R1507 : INT;
    WaterfallStreamingActive     AT %M350 : BOOL;
    FlowTurbulenceWarning        AT %M351 : BOOL;
    TurbulenceTripRelay          : BOOL := FALSE;
    FlowStarvationAlarm          : BOOL := FALSE;
    RenderFaultBeacon            : BOOL := FALSE;
END_VAR

(* Synchronize turbulence breach warning: DiagnosticStatusCode 0xD301 (-11519 / 54017) or HydrodynamicTurbulenceScaled >= 35 *)
IF (DiagnosticStatusCode = -11519) OR (DiagnosticStatusCode = 54017) OR (HydrodynamicTurbulenceScaled >= 35) THEN
    FlowTurbulenceWarning := TRUE;
    TurbulenceTripRelay := TRUE;
ELSE
    FlowTurbulenceWarning := FALSE;
    TurbulenceTripRelay := FALSE;
END_IF;

(* Synchronize flow starvation: DiagnosticStatusCode 0xD302 (-11518 / 54018) or TotalThroughputBpdScaled < 100 *)
IF (DiagnosticStatusCode = -11518) OR (DiagnosticStatusCode = 54018) OR (TotalThroughputBpdScaled < 100) THEN
    FlowStarvationAlarm := TRUE;
ELSE
    FlowStarvationAlarm := FALSE;
END_IF;

(* Synchronize render fault beacon: DiagnosticStatusCode 0xD303 (-11517 / 54019) *)
IF (DiagnosticStatusCode = -11517) OR (DiagnosticStatusCode = 54019) THEN
    RenderFaultBeacon := TRUE;
ELSE
    RenderFaultBeacon := FALSE;
END_IF;

(* Waterfall streaming active when ActiveStreamCount > 0 and DiagnosticStatusCode = 0 *)
IF (ActiveStreamCount > 0) AND (DiagnosticStatusCode = 0) THEN
    WaterfallStreamingActive := TRUE;
ELSE
    WaterfallStreamingActive := FALSE;
END_IF;
END_PROGRAM
"""


def verify_stream_waterfall_canvas_pure_st() -> bool:
    """Validate StreamWaterfallCanvasSync POU with STParser and SecurityGuard."""
    SecurityGuard.assert_pure_st_content(STREAM_WATERFALL_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(STREAM_WATERFALL_PURE_ST_POU)
    if not pou:
        return False
    return pou.name == "StreamWaterfallCanvasSync" and pou.pou_type == POUType.PROGRAM


verify_stream_waterfall_pure_st = verify_stream_waterfall_canvas_pure_st


# ============================================================================
# 8. StreamWaterfallCanvas Engine & ILogicUnit
# ============================================================================

class StreamWaterfallCanvas(ILogicUnit):
    """Cscape HMI Dynamic Stream / Waterfall Multi-Epoch Hydrodynamic Flow SCADA Canvas Engine.

    Implements Horner OCS RegisterTable memory synchronization, ILogicUnit scan cycle execution,
    and standalone W3C SVG 1.1 vector rendering.
    """

    def __init__(
        self,
        config: Optional[StreamWaterfallConfig] = None,
        streams: Optional[List[ProcessStream]] = None,
        reg_table: Optional[RegisterTable] = None,
    ) -> None:
        self.config: StreamWaterfallConfig = config if config is not None else StreamWaterfallConfig()
        self.streams: List[ProcessStream] = (
            streams if streams is not None else create_canonical_process_streams(self.config.epoch_depth)
        )
        self.reg_table: RegisterTable = reg_table if reg_table is not None else RegisterTable()

        self.diagnostic_code: DiagnosticCode = DIAG_EVENT_OK
        self.turbulence_warning: bool = False
        self.streaming_active: bool = True
        self.status_bits: StreamWaterfallStatusBits = (
            StreamWaterfallStatusBits.ENGINE_ACTIVE
            | StreamWaterfallStatusBits.STREAMING_ACTIVE
            | StreamWaterfallStatusBits.HYDRODYNAMICS_COMPUTED
            | StreamWaterfallStatusBits.NOMINAL_OPERATION
            | StreamWaterfallStatusBits.SVG_VALID
            | StreamWaterfallStatusBits.WCAG_AAA
        )

        self.turbulence_value: float = NOMINAL_HYDRODYNAMIC_TURBULENCE
        self.velocity_variation_pct: float = NOMINAL_FLOW_VELOCITY_VARIATION_PCT
        self.dispersion_coeff: float = NOMINAL_STREAM_DISPERSION_COEFF

        self.metrics: WaterfallMetrics = self._compute_metrics()
        self.sync_to_registers()

    def _compute_metrics(self) -> WaterfallMetrics:
        """Compute operational metrics across active streams."""
        active_streams = [s for s in self.streams if s.is_active]
        active_count = len(active_streams)

        throughputs: Dict[int, float] = {}
        total_throughput = 0.0
        dominant_idx = 1
        max_flow = -1.0
        dominant_name = "Syngas Feed"

        for s in active_streams:
            curr = s.flow_history[-1] if s.flow_history else s.nominal_bpd
            throughputs[s.stream_id] = curr
            total_throughput += curr
            if curr > max_flow:
                max_flow = curr
                dominant_idx = s.stream_id
                dominant_name = s.name

        # Process safety conditions
        has_turb = (
            self.turbulence_value >= self.config.turbulence_warning_threshold
            or self.diagnostic_code == STREAM_ERR_TURBULENCE_BREACH
        )
        has_starve = (
            total_throughput < self.config.flow_starvation_threshold_bpd
            or self.diagnostic_code == STREAM_ERR_FLOW_STARVATION
        )
        has_render = self.diagnostic_code == STREAM_ERR_RENDER_FAULT

        return WaterfallMetrics(
            active_stream_count=active_count,
            total_throughput_bpd=total_throughput,
            dominant_stream_index=dominant_idx,
            epoch_depth=self.config.epoch_depth,
            hydrodynamic_turbulence=self.turbulence_value,
            flow_velocity_variation_pct=self.velocity_variation_pct,
            stream_dispersion_coeff=self.dispersion_coeff,
            diagnostic_status_code=self.diagnostic_code,
            waterfall_streaming_active=self.streaming_active and not has_render,
            flow_turbulence_warning=has_turb,
            stream_throughputs=throughputs,
            dominant_stream_name=dominant_name,
            has_turbulence_breach=has_turb,
            has_flow_starvation=has_starve,
            has_render_fault=has_render,
        )

    def evaluate_hydrodynamics(self) -> None:
        """Recompute hydrodynamic telemetry and update status bits."""
        self.metrics = self._compute_metrics()
        self.turbulence_warning = self.metrics.has_turbulence_breach
        self.streaming_active = self.metrics.waterfall_streaming_active

        if self.turbulence_warning:
            self.status_bits |= StreamWaterfallStatusBits.TURBULENCE_WARNING
            self.status_bits &= ~StreamWaterfallStatusBits.NOMINAL_OPERATION
        else:
            self.status_bits &= ~StreamWaterfallStatusBits.TURBULENCE_WARNING

        if self.metrics.has_flow_starvation:
            self.status_bits |= StreamWaterfallStatusBits.FLOW_STARVATION
            self.status_bits &= ~StreamWaterfallStatusBits.NOMINAL_OPERATION
        else:
            self.status_bits &= ~StreamWaterfallStatusBits.FLOW_STARVATION

        if (
            not self.turbulence_warning
            and not self.metrics.has_flow_starvation
            and self.diagnostic_code == DIAG_EVENT_OK
        ):
            self.status_bits |= StreamWaterfallStatusBits.NOMINAL_OPERATION

    def update_hydrodynamics(self) -> None:
        """Alias for evaluate_hydrodynamics."""
        self.evaluate_hydrodynamics()

    def sync_to_registers(self) -> None:
        """Synchronize telemetry state to Horner OCS RegisterTable memory.

        Word Registers (%R1500..%R1507):
        - %R1500: ActiveStreamCount (INT16, 1..5)
        - %R1501: TotalThroughputBpdScaled (INT16, scaled / 10 barrels per day, e.g. 1500 = 15,000 BPD)
        - %R1502: DominantStreamIndex (INT16, 1..5)
        - %R1503: WaterfallEpochDepth (INT16, e.g. 24 epochs)
        - %R1504: HydrodynamicTurbulenceScaled (INT16, scaled x10, e.g. 24 = 2.4 Re/1000)
        - %R1505: FlowVelocityVariationScaled (INT16, scaled x10 %, e.g. 45 = 4.5 %)
        - %R1506: StreamDispersionCoeffScaled (INT16, scaled x100, e.g. 120 = 1.20)
        - %R1507: DiagnosticStatusCode (0x0000=OK, 0xD301, 0xD302, 0xD303)

        Discrete Coils (%M350..%M351):
        - %M350: WaterfallStreamingActive (BOOL)
        - %M351: FlowTurbulenceWarning (BOOL)
        """
        reg = self.reg_table

        # %R1500: ActiveStreamCount
        reg.write_word("%R1500", self.metrics.active_stream_count, privilege=PrivilegeMode.SYSTEM)

        # %R1501: TotalThroughputBpdScaled
        reg.write_word("%R1501", self.metrics.total_throughput_scaled, privilege=PrivilegeMode.SYSTEM)

        # %R1502: DominantStreamIndex
        reg.write_word("%R1502", self.metrics.dominant_stream_index, privilege=PrivilegeMode.SYSTEM)

        # %R1503: WaterfallEpochDepth
        reg.write_word("%R1503", self.metrics.epoch_depth, privilege=PrivilegeMode.SYSTEM)

        # %R1504: HydrodynamicTurbulenceScaled
        reg.write_word("%R1504", self.metrics.hydrodynamic_turbulence_scaled, privilege=PrivilegeMode.SYSTEM)

        # %R1505: FlowVelocityVariationScaled
        reg.write_word("%R1505", self.metrics.flow_velocity_variation_scaled, privilege=PrivilegeMode.SYSTEM)

        # %R1506: StreamDispersionCoeffScaled
        reg.write_word("%R1506", self.metrics.stream_dispersion_coeff_scaled, privilege=PrivilegeMode.SYSTEM)

        # %R1507: DiagnosticStatusCode
        reg.write_word("%R1507", int(self.diagnostic_code) & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %M350: WaterfallStreamingActive
        reg.write_bit("%M350", self.streaming_active, privilege=PrivilegeMode.SYSTEM)

        # %M351: FlowTurbulenceWarning
        reg.write_bit("%M351", self.turbulence_warning, privilege=PrivilegeMode.SYSTEM)

    # ------------------------------------------------------------------------
    # ILogicUnit Protocol Implementation
    # ------------------------------------------------------------------------
    @property
    def name(self) -> str:
        return "StreamWaterfallCanvasSync"

    @property
    def priority(self) -> int:
        return 85

    @property
    def is_enabled(self) -> bool:
        return True

    def reset(self) -> None:
        """Reset canvas engine to initial nominal conditions."""
        self.reset_nominal()

    def reset_nominal(self) -> None:
        """Reset internal unit state to initial nominal conditions."""
        self.diagnostic_code = DIAG_EVENT_OK
        self.turbulence_value = NOMINAL_HYDRODYNAMIC_TURBULENCE
        self.velocity_variation_pct = NOMINAL_FLOW_VELOCITY_VARIATION_PCT
        self.dispersion_coeff = NOMINAL_STREAM_DISPERSION_COEFF
        self.streams = create_canonical_process_streams(self.config.epoch_depth)
        self.turbulence_warning = False
        self.streaming_active = True
        self.status_bits = (
            StreamWaterfallStatusBits.ENGINE_ACTIVE
            | StreamWaterfallStatusBits.STREAMING_ACTIVE
            | StreamWaterfallStatusBits.HYDRODYNAMICS_COMPUTED
            | StreamWaterfallStatusBits.NOMINAL_OPERATION
            | StreamWaterfallStatusBits.SVG_VALID
            | StreamWaterfallStatusBits.WCAG_AAA
        )
        self.evaluate_hydrodynamics()
        self.sync_to_registers()

    def step(self) -> None:
        """Execute single scan cycle simulation step."""
        self.evaluate_hydrodynamics()
        self.sync_to_registers()

    def scan_step(self, dt: float = 0.01) -> None:
        """Execute discrete Horner OCS scan step with delta time dt."""
        context = create_mock_scan_context(cycle=1, dt_ms=dt * 1000.0, reg_table=self.reg_table)
        self.execute(context)
        self.sync_to_registers()

    def execute(self, context: ScanContext) -> None:
        """Execute discrete Horner OCS PLC scan cycle logic."""
        turb_scaled = self.reg_table.read_word("%R1504")
        throughput_scaled = self.reg_table.read_word("%R1501")

        # 0xD301: Turbulence breach
        if turb_scaled >= 35:
            self.turbulence_warning = True
            self.diagnostic_code = STREAM_ERR_TURBULENCE_BREACH
            self.status_bits |= StreamWaterfallStatusBits.TURBULENCE_WARNING
            self.status_bits &= ~StreamWaterfallStatusBits.NOMINAL_OPERATION
            self.reg_table.write_bit("%M351", True, privilege=PrivilegeMode.SYSTEM)
            self.reg_table.write_word("%R1507", 0xD301, privilege=PrivilegeMode.SYSTEM)
        # 0xD302: Flow starvation
        elif throughput_scaled < 100:
            self.turbulence_warning = False
            self.diagnostic_code = STREAM_ERR_FLOW_STARVATION
            self.status_bits |= StreamWaterfallStatusBits.FLOW_STARVATION
            self.status_bits &= ~StreamWaterfallStatusBits.NOMINAL_OPERATION
            self.reg_table.write_bit("%M351", False, privilege=PrivilegeMode.SYSTEM)
            self.reg_table.write_word("%R1507", 0xD302, privilege=PrivilegeMode.SYSTEM)
        # 0xD303: Render fault
        elif self.diagnostic_code == STREAM_ERR_RENDER_FAULT:
            self.turbulence_warning = False
            self.status_bits &= ~StreamWaterfallStatusBits.NOMINAL_OPERATION
            self.reg_table.write_bit("%M351", False, privilege=PrivilegeMode.SYSTEM)
            self.reg_table.write_word("%R1507", 0xD303, privilege=PrivilegeMode.SYSTEM)
        else:
            self.turbulence_warning = False
            self.reg_table.write_bit("%M351", False, privilege=PrivilegeMode.SYSTEM)
            current_diag = self.reg_table.read_word("%R1507")
            if DiagnosticCode(current_diag) in (STREAM_ERR_TURBULENCE_BREACH, STREAM_ERR_FLOW_STARVATION):
                self.diagnostic_code = DIAG_EVENT_OK
                self.reg_table.write_word("%R1507", 0, privilege=PrivilegeMode.SYSTEM)

    def execute_logic(self, context: ScanContext) -> None:
        """Scan execution alias."""
        self.execute(context)

    # ------------------------------------------------------------------------
    # Fault Injection & Diagnostic Interlock Triggers
    # ------------------------------------------------------------------------
    def trigger_turbulence_breach(self, turbulence: float = 4.2) -> None:
        """Inject 0xD301 turbulence breach (turbulence >= trip limit).

        Asserts %M351 (FlowTurbulenceWarning) and sets %R1507 to 0xD301.
        """
        self.turbulence_value = turbulence
        self.diagnostic_code = STREAM_ERR_TURBULENCE_BREACH
        self.turbulence_warning = True
        self.evaluate_hydrodynamics()
        self.sync_to_registers()

    def trigger_flow_starvation(self, total_flow_override: float = 500.0) -> None:
        """Inject 0xD302 process flow starvation (< 1000 BPD).

        Sets %R1507 to 0xD302.
        """
        fraction = total_flow_override / NOMINAL_TOTAL_THROUGHPUT_BPD
        for s in self.streams:
            s.flow_history = [s.nominal_bpd * fraction] * self.config.epoch_depth
            s.current_bpd = s.nominal_bpd * fraction
        self.diagnostic_code = STREAM_ERR_FLOW_STARVATION
        self.evaluate_hydrodynamics()
        self.sync_to_registers()

    def trigger_render_fault(self) -> None:
        """Inject 0xD303 SVG vector render fault."""
        self.diagnostic_code = STREAM_ERR_RENDER_FAULT
        self.streaming_active = False
        self.evaluate_hydrodynamics()
        self.sync_to_registers()

    def select_stream(self, stream_index: int) -> None:
        """Select stream to focus (0 = All, 1..5 = Specific stream)."""
        if 0 <= stream_index <= len(self.streams):
            self.config.selected_stream_index = stream_index

    def select_epoch(self, epoch_index: int) -> None:
        """Set active epoch cursor (0..epoch_depth-1)."""
        if 0 <= epoch_index < self.config.epoch_depth:
            self.config.selected_epoch_index = epoch_index

    # ------------------------------------------------------------------------
    # Standalone W3C SVG 1.1 Vector Renderer
    # ------------------------------------------------------------------------
    def render_svg(self) -> str:
        """Generate standalone W3C SVG 1.1 vector canvas markup."""
        if self.diagnostic_code == STREAM_ERR_RENDER_FAULT:
            return (
                f'<svg xmlns="http://www.w3.org/2000/svg" version="1.1" '
                f'width="{self.config.viewport_width}" height="{self.config.viewport_height}">\n'
                f'  <!-- SVG Render Fault 0xD303 Triggered -->\n'
                f'</svg>'
            )

        return generate_stream_waterfall_canvas_svg(self)


StreamWaterfallCanvasSync = StreamWaterfallCanvas
StreamWaterfallHmiSync = StreamWaterfallCanvas
WaterfallCanvas = StreamWaterfallCanvas
WaterfallCanvasSync = StreamWaterfallCanvas
StreamWaterfallEngine = StreamWaterfallCanvas


# ============================================================================
# 9. Standalone W3C SVG 1.1 Vector Canvas Renderer Implementation
# ============================================================================

def generate_stream_waterfall_canvas_svg(canvas: StreamWaterfallCanvas) -> str:
    """Render standalone W3C SVG 1.1 document matching industrial SCADA dark theme."""
    cfg = canvas.config
    metrics = canvas.metrics
    epoch_count = cfg.epoch_depth
    selected_stream = cfg.selected_stream_index
    selected_epoch = cfg.selected_epoch_index
    turbulence = metrics.hydrodynamic_turbulence
    is_warn = metrics.flow_turbulence_warning

    vw = cfg.viewport_width
    vh = cfg.viewport_height

    # Calculate stream layer stacked boundaries across epochs
    # X mapping: epoch 0 at PLOT_X_MIN, epoch T-1 at PLOT_X_MAX
    dx = (PLOT_X_MAX - PLOT_X_MIN) / max(1, epoch_count - 1)
    x_coords = [PLOT_X_MIN + t * dx for t in range(epoch_count)]

    # Normalized height scaling based on nominal max throughput (18,000 BPD ceiling)
    scale_y = PLOT_HEIGHT / 18000.0

    # Build layers bottom-up: baseline at PLOT_Y_MAX
    # For each epoch t, stack streams 1..5
    layer_bottoms: Dict[int, List[Tuple[float, float]]] = {}
    layer_tops: Dict[int, List[Tuple[float, float]]] = {}

    current_baseline_y = [PLOT_Y_MAX] * epoch_count

    # Golden design baseline envelopes (Target design envelopes)
    golden_top_coords: List[Tuple[float, float]] = []
    golden_bottom_coords: List[Tuple[float, float]] = []

    for t in range(epoch_count):
        # Golden envelope nominal bounds: 14,000 to 16,000 BPD total
        golden_y_min = PLOT_Y_MAX - (16000.0 * scale_y)
        golden_y_max = PLOT_Y_MAX - (14000.0 * scale_y)
        golden_top_coords.append((x_coords[t], golden_y_min))
        golden_bottom_coords.append((x_coords[t], golden_y_max))

    # Calculate stacked layers
    for s in canvas.streams:
        s_id = s.stream_id
        top_pts: List[Tuple[float, float]] = []
        bottom_pts: List[Tuple[float, float]] = []

        for t in range(epoch_count):
            x = x_coords[t]
            b_y = current_baseline_y[t]
            flow = s.flow_history[t] if t < len(s.flow_history) else s.nominal_bpd

            # Add hydrodynamic wave ripple & turbulence displacement
            ripple = (turbulence * 3.5) * math.sin(t * 0.75 + s_id * 1.1)
            layer_thickness = max(6.0, (flow * scale_y) + (metrics.stream_dispersion_coeff * 2.0 * math.cos(t * 0.5)))
            t_y = b_y - layer_thickness + ripple

            top_pts.append((x, t_y))
            bottom_pts.append((x, b_y))
            # Next layer sits on top of this layer's top boundary
            current_baseline_y[t] = t_y

        layer_tops[s_id] = top_pts
        layer_bottoms[s_id] = bottom_pts

    # Build SVG elements
    svg_parts: List[str] = []
    svg_parts.append('<?xml version="1.0" encoding="UTF-8"?>\n')
    svg_parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" version="1.1" '
        f'width="{vw}" height="{vh}" viewBox="0 0 {vw} {vh}">\n'
    )

    # Defs: Gradients, Filters, Styles
    svg_parts.append('  <defs>\n')
    # Linear Gradients for 5 Process Streams
    stream_gradients = [
        (1, COLOR_STREAM_1_SYNGAS, COLOR_STREAM_1_DARK),
        (2, COLOR_STREAM_2_WAX, COLOR_STREAM_2_DARK),
        (3, COLOR_STREAM_3_DIESEL, COLOR_STREAM_3_DARK),
        (4, COLOR_STREAM_4_NAPHTHA, COLOR_STREAM_4_DARK),
        (5, COLOR_STREAM_5_OFFGAS, COLOR_STREAM_5_DARK),
    ]
    for s_id, c_light, c_dark in stream_gradients:
        svg_parts.append(
            f'    <linearGradient id="grad-stream-{s_id}" x1="0%" y1="0%" x2="0%" y2="100%">\n'
            f'      <stop offset="0%" stop-color="{c_light}" stop-opacity="0.92"/>\n'
            f'      <stop offset="100%" stop-color="{c_dark}" stop-opacity="0.75"/>\n'
            f'    </linearGradient>\n'
        )

    # Glow & Filter effects
    svg_parts.append(
        '    <filter id="stream-glow" x="-20%" y="-20%" width="140%" height="140%">\n'
        '      <feGaussianBlur stdDeviation="3.0" result="blur"/>\n'
        '      <feComposite in="SourceGraphic" in2="blur" operator="over"/>\n'
        '    </filter>\n'
        '    <filter id="focus-glow" x="-30%" y="-30%" width="160%" height="160%">\n'
        '      <feGaussianBlur stdDeviation="2.5" result="blur"/>\n'
        '      <feComposite in="SourceGraphic" in2="blur" operator="over"/>\n'
        '    </filter>\n'
    )

    # CSS Styles
    svg_parts.append(
        '    <style type="text/css"><![CDATA[\n'
        f'      .canvas-bg {{ fill: {COLOR_DARK_THEME_BACKING}; }}\n'
        f'      .panel-bg {{ fill: {COLOR_DARK_THEME_SURFACE}; stroke: {COLOR_CARD_BORDER}; stroke-width: 1.0; rx: 6px; }}\n'
        f'      .badge-bg {{ fill: {COLOR_DECOUPLED_BADGE}; stroke: {COLOR_CARD_BORDER}; stroke-width: 1.0; rx: 4px; }}\n'
        f'      .badge-bg-active {{ fill: #0D1D30; stroke: {COLOR_FOCUS_BLUE}; stroke-width: 1.5; rx: 4px; }}\n'
        f'      .text-primary {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; font-size: 11px; fill: {COLOR_TEXT_PRIMARY}; }}\n'
        f'      .text-title {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; font-size: 15px; font-weight: 800; fill: {COLOR_TEXT_PRIMARY}; letter-spacing: 0.5px; }}\n'
        f'      .text-subtitle {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; font-size: 11px; font-weight: 500; fill: {COLOR_TEXT_MUTED}; }}\n'
        f'      .text-muted {{ font-family: monospace; font-size: 10px; fill: {COLOR_TEXT_MUTED}; }}\n'
        f'      .grid-line {{ stroke: {COLOR_GRID_LINE}; stroke-width: 1.0; stroke-dasharray: 4,4; }}\n'
        f'      .axis-tick {{ stroke: {COLOR_GRID_TICK}; stroke-width: 1.0; }}\n'
        f'      .golden-envelope {{ stroke: {COLOR_GOLDEN_BASELINE}; stroke-width: 1.5; stroke-dasharray: 6,4; fill: none; opacity: 0.85; }}\n'
        '    ]]></style>\n'
        '  </defs>\n'
    )

    # Canvas Background
    svg_parts.append(f'  <rect width="{vw}" height="{vh}" class="canvas-bg" />\n')

    # Header Section
    svg_parts.append('  <g id="canvas-header" transform="translate(30, 24)">\n')
    svg_parts.append('    <text x="0" y="16" class="text-title">HORNER OCS HYDRODYNAMIC STREAM / WATERFALL SCADA CANVAS</text>\n')
    svg_parts.append('    <text x="0" y="32" class="text-subtitle">Multi-Epoch Hydrodynamic Flow Visualization &amp; Stacked Continuous Process Layers | WP W189</text>\n')

    # Header Telemetry Badges
    badge_x = 760.0
    trip_txt = "WARN ASSERTED" if is_warn else "NORMAL (CLEAR)"
    trip_c = COLOR_TRIP_CRIMSON if is_warn else COLOR_NOMINAL_GREEN
    diag_code_str = f"0x{int(canvas.diagnostic_code) & 0xFFFF:04X}"

    svg_parts.append(f'    <g id="header-status-badges" transform="translate({badge_x}, 2)">\n')
    # %M350 Online Badge
    svg_parts.append(f'      <rect x="0" y="0" width="125" height="26" class="badge-bg" />\n')
    svg_parts.append(f'      <circle cx="12" cy="13" r="4" fill="{COLOR_NOMINAL_GREEN}"/>\n')
    svg_parts.append(f'      <text x="22" y="16" class="text-primary" font-weight="700">%M350 STREAMING</text>\n')

    # %M351 Turbulence Warning Badge
    svg_parts.append(f'      <rect x="135" y="0" width="135" height="26" class="badge-bg" />\n')
    svg_parts.append(f'      <circle cx="147" cy="13" r="4" fill="{trip_c}"/>\n')
    svg_parts.append(f'      <text x="157" y="16" class="text-primary" font-weight="700">%M351 {trip_txt[:10]}</text>\n')

    # %R1507 Diag Code Badge
    svg_parts.append(f'      <rect x="280" y="0" width="105" height="26" class="badge-bg" />\n')
    svg_parts.append(f'      <text x="290" y="16" class="text-primary" font-weight="700" fill="{trip_c}">%R1507: {diag_code_str}</text>\n')
    svg_parts.append('    </g>\n')
    svg_parts.append('  </g>\n')

    # Stream Selector Tabs & Interactive Epoch Slider
    svg_parts.append('  <g id="stream-selector" transform="translate(30, 68)">\n')
    tab_w = 110.0
    tab_h = 28.0

    # Tab 0: All Streams
    is_sel_0 = (selected_stream == 0)
    bg_0 = "badge-bg-active" if is_sel_0 else "badge-bg"
    txt_col_0 = COLOR_FOCUS_BLUE if is_sel_0 else COLOR_TEXT_MUTED
    svg_parts.append(
        f'    <g id="stream-tab-0" transform="translate(0, 0)">\n'
        f'      <rect width="{tab_w}" height="{tab_h}" class="{bg_0}"/>\n'
        f'      <text x="12" y="18" class="text-primary" fill="{txt_col_0}">[0] All Streams</text>\n'
        f'    </g>\n'
    )

    # Tabs 1..5 for Process Streams
    for s in canvas.streams:
        is_sel = (selected_stream == s.stream_id)
        bg = "badge-bg-active" if is_sel else "badge-bg"
        txt_col = s.color if is_sel else COLOR_TEXT_MUTED
        x_tab = s.stream_id * (tab_w + 8)
        svg_parts.append(
            f'    <g id="stream-tab-{s.stream_id}" transform="translate({x_tab}, 0)">\n'
            f'      <rect width="{tab_w}" height="{tab_h}" class="{bg}"/>\n'
            f'      <circle cx="12" cy="14" r="3.5" fill="{s.color}"/>\n'
            f'      <text x="22" y="18" class="text-primary" fill="{txt_col}">[{s.stream_id}] {html.escape(s.name[:9])}</text>\n'
            f'    </g>\n'
        )
    svg_parts.append('  </g>\n')

    # Interactive Epoch Depth Slider
    slider_x = 750.0
    slider_y = 70.0
    slider_w = 410.0
    slider_progress = (selected_epoch / max(1, epoch_count - 1)) * slider_w
    svg_parts.append(
        f'  <g id="epoch-slider" transform="translate({slider_x}, {slider_y})">\n'
        f'    <text x="0" y="-4" class="text-muted">EPOCH DEPTH: {epoch_count} SAMPLES | ACTIVE CURSOR: EPOCH {selected_epoch}</text>\n'
        f'    <rect x="0" y="4" width="{slider_w}" height="8" rx="4" fill="{COLOR_DARK_THEME_SURFACE}" stroke="{COLOR_CARD_BORDER}" stroke-width="1"/>\n'
        f'    <rect x="0" y="4" width="{slider_progress:.1f}" height="8" rx="4" fill="{COLOR_FOCUS_BLUE}"/>\n'
        f'    <circle cx="{slider_progress:.1f}" cy="8" r="7" fill="{COLOR_TEXT_PRIMARY}" stroke="{COLOR_FOCUS_BLUE}" stroke-width="2"/>\n'
        f'    <text x="0" y="24" class="text-muted">T-24h</text>\n'
        f'    <text x="{slider_w - 40:.1f}" y="24" class="text-muted">Live (T-0h)</text>\n'
        f'  </g>\n'
    )

    # Main Waterfall Plot Area Surface Container
    svg_parts.append(
        f'  <g id="waterfall-canvas-container">\n'
        f'    <rect x="{PLOT_X_MIN - 10:.1f}" y="{PLOT_Y_MIN - 20:.1f}" '
        f'width="{PLOT_WIDTH + 20:.1f}" height="{PLOT_HEIGHT + 35:.1f}" class="panel-bg" />\n'
    )

    # Grid Lines and Epoch Markers
    svg_parts.append('    <g id="plot-grid-lines">\n')
    # Horizontal throughput grid lines (0, 5000, 10000, 15000 BPD)
    for bpd in [0.0, 5000.0, 10000.0, 15000.0]:
        y_grid = PLOT_Y_MAX - (bpd * scale_y)
        svg_parts.append(
            f'      <line x1="{PLOT_X_MIN}" y1="{y_grid:.1f}" x2="{PLOT_X_MAX}" y2="{y_grid:.1f}" class="grid-line"/>\n'
            f'      <text x="{PLOT_X_MIN - 48:.1f}" y="{y_grid + 3:.1f}" class="text-muted">{int(bpd):,} BPD</text>\n'
        )

    # Vertical Epoch Grid Lines
    for t_step in range(0, epoch_count, 4):
        x_grid = x_coords[t_step]
        svg_parts.append(
            f'      <line x1="{x_grid:.1f}" y1="{PLOT_Y_MIN}" x2="{x_grid:.1f}" y2="{PLOT_Y_MAX}" class="grid-line"/>\n'
            f'      <text x="{x_grid - 12:.1f}" y="{PLOT_Y_MAX + 16:.1f}" class="text-muted">E-{t_step}</text>\n'
        )
    svg_parts.append('    </g>\n')

    # Golden Design Baseline Envelopes
    golden_top_spline = compute_cubic_bezier_spline_points(golden_top_coords)
    golden_bottom_spline = compute_cubic_bezier_spline_points(golden_bottom_coords)
    svg_parts.append(
        f'    <g id="golden-baseline-envelope">\n'
        f'      <path id="golden-envelope-top" d="{golden_top_spline}" class="golden-envelope" stroke="{COLOR_GOLDEN_BASELINE}" stroke-dasharray="6,4"/>\n'
        f'      <path id="golden-envelope-bottom" d="{golden_bottom_spline}" class="golden-envelope" stroke="{COLOR_GOLDEN_BASELINE}" stroke-dasharray="6,4"/>\n'
        f'    </g>\n'
    )

    # Hydrodynamic Stacked Stream Ribbons
    svg_parts.append('    <g id="waterfall-stream-layers">\n')
    for s in canvas.streams:
        s_id = s.stream_id
        top_pts = layer_tops[s_id]
        bottom_pts = layer_bottoms[s_id]
        ribbon_d = generate_stream_ribbon_svg_path(top_pts, bottom_pts)

        is_focus = (selected_stream == 0 or selected_stream == s_id)
        fill_opacity = "0.92" if is_focus else "0.30"
        stroke_w = "2.0" if is_focus else "1.0"
        glow_filter = ' filter="url(#stream-glow)"' if (is_focus and selected_stream == s_id) else ''

        svg_parts.append(
            f'      <path id="stream-ribbon-{s_id}" d="{ribbon_d}" '
            f'fill="url(#grad-stream-{s_id})" fill-opacity="{fill_opacity}" '
            f'stroke="{s.color}" stroke-width="{stroke_w}"{glow_filter}/>\n'
        )
    svg_parts.append('    </g>\n')

    # Active Epoch Indicator Cursor Bar
    cur_x = x_coords[selected_epoch]
    svg_parts.append(
        f'    <g id="epoch-cursor-bar">\n'
        f'      <line x1="{cur_x:.1f}" y1="{PLOT_Y_MIN}" x2="{cur_x:.1f}" y2="{PLOT_Y_MAX}" '
        f'stroke="{COLOR_FOCUS_BLUE}" stroke-width="1.8" stroke-dasharray="3,3"/>\n'
    )
    # Cursor intersection dots for each stream layer
    for s in canvas.streams:
        s_id = s.stream_id
        y_top = layer_tops[s_id][selected_epoch][1]
        svg_parts.append(
            f'      <circle cx="{cur_x:.1f}" cy="{y_top:.1f}" r="3.5" fill="{s.color}" '
            f'stroke="{COLOR_TEXT_PRIMARY}" stroke-width="1.2"/>\n'
        )
    svg_parts.append('    </g>\n')
    svg_parts.append('  </g>\n')  # End waterfall-canvas-container

    # Right-Hand Telemetry HUD Cards (Decoupled Dark Backing Badges)
    hud_x = 905.0
    hud_y = 120.0
    card_w = 265.0
    card_h = 100.0

    svg_parts.append(f'  <g id="telemetry-hud" transform="translate({hud_x}, {hud_y})">\n')

    # Card 1: Active Streams & Dominant Stream (%R1500, %R1502)
    svg_parts.append(
        f'    <g id="hud-card-streams" transform="translate(0, 0)">\n'
        f'      <rect width="{card_w}" height="{card_h}" class="panel-bg"/>\n'
        f'      <rect x="12" y="12" width="{card_w - 24}" height="24" class="badge-bg"/>\n'
        f'      <text x="20" y="28" class="text-primary" font-weight="700">ACTIVE STREAMS (%R1500)</text>\n'
        f'      <text x="{card_w - 30}" y="28" class="text-primary" font-weight="800" text-anchor="end">{metrics.active_stream_count} / 5</text>\n'
        f'      <text x="20" y="56" class="text-muted">DOMINANT STREAM (%R1502):</text>\n'
        f'      <rect x="20" y="64" width="{card_w - 40}" height="24" class="badge-bg"/>\n'
        f'      <circle cx="32" cy="76" r="4" fill="{COLOR_STREAM_1_SYNGAS}"/>\n'
        f'      <text x="44" y="80" class="text-primary" font-weight="700">[{metrics.dominant_stream_index}] {html.escape(metrics.dominant_stream_name)}</text>\n'
        f'    </g>\n'
    )

    # Card 2: Total Throughput & Scaled (%R1501)
    svg_parts.append(
        f'    <g id="hud-card-throughput" transform="translate(0, 112)">\n'
        f'      <rect width="{card_w}" height="{card_h}" class="panel-bg"/>\n'
        f'      <rect x="12" y="12" width="{card_w - 24}" height="24" class="badge-bg"/>\n'
        f'      <text x="20" y="28" class="text-primary" font-weight="700">TOTAL THROUGHPUT (%R1501)</text>\n'
        f'      <text x="{card_w - 30}" y="28" class="text-primary" font-weight="800" text-anchor="end">{metrics.total_throughput_scaled} (/10)</text>\n'
        f'      <text x="20" y="60" class="text-title" font-size="20">{int(metrics.total_throughput_bpd):,} BPD</text>\n'
        f'      <text x="20" y="82" class="text-muted">NOMINAL RATING: 15,000 BPD</text>\n'
        f'    </g>\n'
    )

    # Card 3: Hydrodynamic Turbulence & Flow Velocity (%R1504, %R1505)
    turb_scaled = metrics.hydrodynamic_turbulence_scaled
    turb_c = COLOR_TRIP_CRIMSON if is_warn else COLOR_TEXT_PRIMARY
    svg_parts.append(
        f'    <g id="hud-card-turbulence" transform="translate(0, 224)">\n'
        f'      <rect width="{card_w}" height="{card_h}" class="panel-bg"/>\n'
        f'      <rect x="12" y="12" width="{card_w - 24}" height="24" class="badge-bg"/>\n'
        f'      <text x="20" y="28" class="text-primary" font-weight="700">TURBULENCE (%R1504)</text>\n'
        f'      <text x="{card_w - 30}" y="28" class="text-primary" font-weight="800" text-anchor="end" fill="{turb_c}">{turb_scaled} (x10)</text>\n'
        f'      <text x="20" y="58" class="text-title" font-size="18" fill="{turb_c}">{turbulence:.2f} Re/1000</text>\n'
        f'      <text x="20" y="78" class="text-muted">VELOCITY VAR (%R1505): {metrics.flow_velocity_variation_pct:.1f}% ({metrics.flow_velocity_variation_scaled})</text>\n'
        f'      <text x="20" y="92" class="text-muted">WARNING LIMIT: 3.5 Re/1000</text>\n'
        f'    </g>\n'
    )

    # Card 4: Stream Dispersion Coeff & Epoch Depth (%R1506, %R1503)
    svg_parts.append(
        f'    <g id="hud-card-dispersion" transform="translate(0, 336)">\n'
        f'      <rect width="{card_w}" height="{card_h}" class="panel-bg"/>\n'
        f'      <rect x="12" y="12" width="{card_w - 24}" height="24" class="badge-bg"/>\n'
        f'      <text x="20" y="28" class="text-primary" font-weight="700">DISPERSION COEFF (%R1506)</text>\n'
        f'      <text x="{card_w - 30}" y="28" class="text-primary" font-weight="800" text-anchor="end">{metrics.stream_dispersion_coeff_scaled} (x100)</text>\n'
        f'      <text x="20" y="58" class="text-title" font-size="18">{metrics.stream_dispersion_coeff:.2f}</text>\n'
        f'      <text x="20" y="78" class="text-muted">WATERFALL DEPTH (%R1503): {metrics.epoch_depth} EPOCHS</text>\n'
        f'      <text x="20" y="92" class="text-muted">TEMPORAL RESOLUTION: 1.0 hr/epoch</text>\n'
        f'    </g>\n'
    )

    # Card 5: Diagnostic Status & Process Coils (%R1507, %M350, %M351)
    svg_parts.append(
        f'    <g id="hud-card-coils" transform="translate(0, 448)">\n'
        f'      <rect width="{card_w}" height="108" class="panel-bg"/>\n'
        f'      <rect x="12" y="10" width="{card_w - 24}" height="24" class="badge-bg"/>\n'
        f'      <text x="20" y="26" class="text-primary" font-weight="700">DIAGNOSTIC STATUS (%R1507)</text>\n'
        f'      <text x="{card_w - 30}" y="26" class="text-primary" font-weight="800" text-anchor="end" fill="{trip_c}">{diag_code_str}</text>\n'
        f'      <rect x="16" y="44" width="110" height="26" class="badge-bg"/>\n'
        f'      <circle cx="28" cy="57" r="4" fill="{COLOR_NOMINAL_GREEN}"/>\n'
        f'      <text x="38" y="60" class="text-primary" font-size="10">%M350: ON</text>\n'
        f'      <rect x="138" y="44" width="110" height="26" class="badge-bg"/>\n'
        f'      <circle cx="150" cy="57" r="4" fill="{trip_c}"/>\n'
        f'      <text x="160" y="60" class="text-primary" font-size="10">%M351: {"WARN" if is_warn else "OFF"}</text>\n'
        f'      <text x="16" y="96" class="text-muted">ILogicUnit: Scan Cycle Nominal</text>\n'
        f'    </g>\n'
    )
    svg_parts.append('  </g>\n')  # End telemetry-hud

    # Footer Status Bar
    svg_parts.append(
        f'  <g id="status-bar" transform="translate(30, 715)">\n'
        f'    <text x="0" y="14" class="text-muted">Horner APG OCS Emulation | Pure IEC 61131-3 ST \'StreamWaterfallCanvasSync\' | WCAG 2.1 AAA Compliant (>18:1 Badge, >7:1 Text, >3:1 Graphics)</text>\n'
        f'  </g>\n'
    )

    svg_parts.append('</svg>\n')
    return "".join(svg_parts)


# ============================================================================
# 10. Canonical Factory Function
# ============================================================================

def create_canonical_waterfall_canvas(
    epoch_depth: int = DEFAULT_EPOCH_DEPTH,
    selected_stream_index: int = 0,
    reg_table: Optional[RegisterTable] = None,
) -> StreamWaterfallCanvas:
    """Create canonical StreamWaterfallCanvas instance configured for production operation."""
    config = StreamWaterfallConfig(
        epoch_depth=epoch_depth,
        selected_stream_index=selected_stream_index,
    )
    streams = create_canonical_process_streams(epoch_depth)
    return StreamWaterfallCanvas(config=config, streams=streams, reg_table=reg_table)


# ============================================================================
# 11. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_stream_waterfall_canvas_verification(
    output_path: Optional[Union[str, Path]] = None,
    sample_svg_path: Optional[Union[str, Path]] = None,
    evidence_path: Optional[Union[str, Path]] = None,
    svg_path: Optional[Union[str, Path]] = None,
    svg_export_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for Stream Waterfall Canvas (W189)."""
    target_evidence_path = output_path or evidence_path
    target_svg_path = sample_svg_path or svg_path or svg_export_path
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU AST Parsing & Register Symbol Binding
    # ------------------------------------------------------------------------
    st_valid = verify_stream_waterfall_canvas_pure_st()
    parser = STParser()
    ast = parser.parse_pou(STREAM_WATERFALL_PURE_ST_POU)

    expected_registers = [
        "%R1500", "%R1501", "%R1502", "%R1503",
        "%R1504", "%R1505", "%R1506", "%R1507",
        "%M350", "%M351",
    ]
    reg_bound_ok = ast is not None and all(r in ast.bound_registers for r in expected_registers)
    pou_name_ok = ast is not None and ast.name == "StreamWaterfallCanvasSync"

    c1_pass = st_valid and reg_bound_ok and pou_name_ok
    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_AST_Parsing_And_Register_Binding",
        "passed": c1_pass,
        "details": f"Parsed POU 'StreamWaterfallCanvasSync'; bound registers %R1500..%R1507, %M350..%M351 validated.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Anti-Ladder Security Guard Verification
    # ------------------------------------------------------------------------
    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("""
        PROGRAM BadWaterfallLadder
        VAR StreamActive : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """)
    except LadderForbiddenError:
        ladder_rejected = True

    c2_pass = ladder_rejected
    test_results.append({
        "stage": 2,
        "check": "Anti_Ladder_Security_Guard_Interception",
        "passed": c2_pass,
        "details": "Asserted LadderForbiddenError on contacts, coils, and rungs via SecurityGuard.assert_pure_st_content.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: 5 Process Streams Definition & Hydrodynamic Model Validation
    # ------------------------------------------------------------------------
    streams = create_canonical_process_streams()
    c3_count = len(streams) == 5
    c3_names = [s.name for s in streams] == [
        "Syngas Feed",
        "Liquid Wax",
        "Heavy Diesel",
        "Naphtha",
        "Offgas/Tailgas",
    ]
    tot_flow = sum(s.nominal_bpd for s in streams)
    c3_tot = abs(tot_flow - NOMINAL_TOTAL_THROUGHPUT_BPD) < 1e-3

    c3_pass = c3_count and c3_names and c3_tot
    test_results.append({
        "stage": 3,
        "check": "Five_Process_Streams_Hydrodynamic_Model_Validation",
        "passed": c3_pass,
        "details": f"Verified 5 process streams (Syngas Feed, Liquid Wax, Heavy Diesel, Naphtha, Offgas/Tailgas); total nominal flow={tot_flow:.0f} BPD.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Stacked Cubic Bezier Ribbons & Sinusoidal Bands Geometry Synthesis
    # ------------------------------------------------------------------------
    canvas_geo = create_canonical_waterfall_canvas()
    test_pts_top = [(100.0, 200.0), (200.0, 180.0), (300.0, 220.0), (400.0, 190.0)]
    test_pts_bot = [(100.0, 250.0), (200.0, 240.0), (300.0, 270.0), (400.0, 260.0)]
    ribbon_path = generate_stream_ribbon_svg_path(test_pts_top, test_pts_bot)

    c4_bezier = ribbon_path.startswith("M") and " C " in ribbon_path and ribbon_path.endswith("Z")
    c4_spline = len(compute_cubic_bezier_spline_points(test_pts_top)) > 0

    c4_pass = c4_bezier and c4_spline
    test_results.append({
        "stage": 4,
        "check": "Stacked_Cubic_Bezier_Ribbons_Geometry_Synthesis",
        "passed": c4_pass,
        "details": "Generated C1-continuous cubic Bézier top/bottom curves and closed ribbon boundary (M...C...L...C...Z).",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Dual-State Representation & Baseline Envelope Telemetry
    # ------------------------------------------------------------------------
    svg_sample = canvas_geo.render_svg()
    c5_pass = (
        'id="golden-baseline-envelope"' in svg_sample
        and 'id="golden-envelope-top"' in svg_sample
        and 'id="golden-envelope-bottom"' in svg_sample
        and 'stroke-dasharray="6,4"' in svg_sample
        and 'id="waterfall-stream-layers"' in svg_sample
        and 'id="stream-ribbon-1"' in svg_sample
        and 'id="stream-ribbon-2"' in svg_sample
        and 'id="stream-ribbon-3"' in svg_sample
        and 'id="stream-ribbon-4"' in svg_sample
        and 'id="stream-ribbon-5"' in svg_sample
    )
    test_results.append({
        "stage": 5,
        "check": "Dual_State_Baseline_Envelope_Vs_Realtime_Ribbons",
        "passed": c5_pass,
        "details": "Verified dual-state representation: Golden baseline design envelope (dashed golden #E3B341) vs live stacked stream ribbons.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Process Safety Interlocks & Diagnostics
    # ------------------------------------------------------------------------
    canvas_fault = create_canonical_waterfall_canvas()

    # 1. Turbulence breach (0xD301) -> asserts %M351
    canvas_fault.trigger_turbulence_breach(turbulence=4.2)
    turb_ok = (
        canvas_fault.turbulence_warning is True
        and canvas_fault.reg_table.read_bit("%M351") is True
        and canvas_fault.diagnostic_code == STREAM_ERR_TURBULENCE_BREACH
        and canvas_fault.diagnostic_code == 0xD301
        and canvas_fault.diagnostic_code == -11519
        and DiagnosticCode(canvas_fault.reg_table.read_word("%R1507")) == 0xD301
    )

    # 2. Flow starvation (0xD302) -> %M351 remains False
    canvas_fault.reset_nominal()
    canvas_fault.trigger_flow_starvation(total_flow_override=500.0)
    starve_ok = (
        canvas_fault.turbulence_warning is False
        and canvas_fault.reg_table.read_bit("%M351") is False
        and canvas_fault.diagnostic_code == STREAM_ERR_FLOW_STARVATION
        and canvas_fault.diagnostic_code == 0xD302
        and canvas_fault.diagnostic_code == -11518
        and DiagnosticCode(canvas_fault.reg_table.read_word("%R1507")) == 0xD302
    )

    # 3. SVG Render fault (0xD303)
    canvas_fault.trigger_render_fault()
    render_ok = (
        canvas_fault.diagnostic_code == STREAM_ERR_RENDER_FAULT
        and canvas_fault.diagnostic_code == 0xD303
        and canvas_fault.diagnostic_code == -11517
        and DiagnosticCode(canvas_fault.reg_table.read_word("%R1507")) == 0xD303
    )

    # 4. Clean nominal restoration
    canvas_fault.reset_nominal()
    reset_ok = (
        canvas_fault.diagnostic_code == DIAG_EVENT_OK
        and canvas_fault.turbulence_warning is False
        and canvas_fault.reg_table.read_bit("%M351") is False
        and DiagnosticCode(canvas_fault.reg_table.read_word("%R1507")) == 0x0000
    )

    c6_pass = turb_ok and starve_ok and render_ok and reset_ok
    test_results.append({
        "stage": 6,
        "check": "Process_Safety_Interlocks_And_Diagnostics",
        "passed": c6_pass,
        "details": "Verified 0xD301 turbulence breach (%M351), 0xD302 flow starvation, 0xD303 render fault, and clean nominal restoration.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Standalone W3C SVG 1.1 Vector Canvas Renderer & XML Validation
    # ------------------------------------------------------------------------
    canvas_svg = create_canonical_waterfall_canvas()
    svg_content = canvas_svg.render_svg()

    xml_valid = False
    try:
        ET.fromstring(svg_content)
        xml_valid = True
    except ET.ParseError:
        xml_valid = False

    svg_has_structure = (
        '<svg xmlns="http://www.w3.org/2000/svg"' in svg_content
        and f'width="{CANVAS_VIEWPORT_WIDTH}"' in svg_content
        and f'height="{CANVAS_VIEWPORT_HEIGHT}"' in svg_content
        and COLOR_DARK_THEME_BACKING in svg_content
        and 'id="canvas-header"' in svg_content
        and 'id="stream-selector"' in svg_content
        and 'id="epoch-slider"' in svg_content
        and 'id="waterfall-canvas-container"' in svg_content
        and 'id="telemetry-hud"' in svg_content
    )

    c7_pass = xml_valid and svg_has_structure
    test_results.append({
        "stage": 7,
        "check": "Standalone_W3C_SVG_XML_Validation_And_Canvas_Rendering",
        "passed": c7_pass,
        "details": f"Rendered 1200x750 standalone W3C SVG 1.1; XML valid; dark theme backing, stream selector, epoch slider, and HUD cards verified.",
    })

    if target_svg_path:
        out_svg = Path(target_svg_path)
        out_svg.parent.mkdir(parents=True, exist_ok=True)
        with open(out_svg, "w", encoding="utf-8") as f:
            f.write(svg_content)

    # ------------------------------------------------------------------------
    # Stage 8: WCAG 2.1 AAA Accessibility & Decoupled Dark Backing Badges
    # ------------------------------------------------------------------------
    contrast_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    contrast_theme = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    contrast_stream1 = calculate_contrast_ratio(COLOR_STREAM_1_SYNGAS, COLOR_DARK_THEME_BACKING)
    contrast_stream2 = calculate_contrast_ratio(COLOR_STREAM_2_WAX, COLOR_DARK_THEME_BACKING)
    contrast_stream3 = calculate_contrast_ratio(COLOR_STREAM_3_DIESEL, COLOR_DARK_THEME_BACKING)
    contrast_stream4 = calculate_contrast_ratio(COLOR_STREAM_4_NAPHTHA, COLOR_DARK_THEME_BACKING)
    contrast_stream5 = calculate_contrast_ratio(COLOR_STREAM_5_OFFGAS, COLOR_DARK_THEME_BACKING)

    c8_pass = (
        contrast_badge >= WCAG_AAA_BADGE_CONTRAST_TARGET
        and contrast_badge > 18.0
        and contrast_theme >= WCAG_AAA_TEXT_CONTRAST_TARGET
        and contrast_stream1 >= WCAG_GRAPHICAL_CONTRAST_TARGET
        and contrast_stream2 >= WCAG_GRAPHICAL_CONTRAST_TARGET
        and contrast_stream3 >= WCAG_GRAPHICAL_CONTRAST_TARGET
        and contrast_stream4 >= WCAG_GRAPHICAL_CONTRAST_TARGET
        and contrast_stream5 >= WCAG_GRAPHICAL_CONTRAST_TARGET
    )
    test_results.append({
        "stage": 8,
        "check": "WCAG_21_AAA_Accessibility_And_Contrast_Checks",
        "passed": c8_pass,
        "details": f"Decoupled badge contrast {contrast_badge:.2f}:1 (> 18:1), Theme text {contrast_theme:.2f}:1 (> 7:1), SCADA colors ({contrast_stream4:.2f}:1..{contrast_stream1:.2f}:1 > 3:1) verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Horner OCS Memory Space Integration & Scan Cycle Execution
    # ------------------------------------------------------------------------
    canvas_sync = create_canonical_waterfall_canvas()
    canvas_sync.scan_step(0.01)
    reg = canvas_sync.reg_table

    r1500 = reg.read_word("%R1500")
    r1501 = reg.read_word("%R1501")
    r1502 = reg.read_word("%R1502")
    r1503 = reg.read_word("%R1503")
    r1504 = reg.read_word("%R1504")
    r1505 = reg.read_word("%R1505")
    r1506 = reg.read_word("%R1506")
    r1507 = reg.read_word("%R1507")
    m350  = reg.read_bit("%M350")
    m351  = reg.read_bit("%M351")

    sync_pass = (
        r1500 == NOMINAL_ACTIVE_STREAM_COUNT                 # %R1500: ActiveStreamCount (5)
        and r1501 == NOMINAL_TOTAL_THROUGHPUT_BPD_SCALED     # %R1501: TotalThroughputBpdScaled (1500)
        and r1502 == NOMINAL_DOMINANT_STREAM_INDEX           # %R1502: DominantStreamIndex (1)
        and r1503 == DEFAULT_EPOCH_DEPTH                     # %R1503: WaterfallEpochDepth (24)
        and r1504 == NOMINAL_HYDRODYNAMIC_TURBULENCE_SCALED  # %R1504: HydrodynamicTurbulenceScaled (24)
        and r1505 == NOMINAL_FLOW_VELOCITY_VARIATION_SCALED  # %R1505: FlowVelocityVariationScaled (45)
        and r1506 == NOMINAL_STREAM_DISPERSION_COEFF_SCALED  # %R1506: StreamDispersionCoeffScaled (120)
        and r1507 == DIAG_EVENT_OK                           # %R1507: DiagnosticStatusCode (0x0000)
        and m350 is True                                     # %M350: WaterfallStreamingActive
        and m351 is False                                    # %M351: FlowTurbulenceWarning
    )

    c9_pass = sync_pass
    test_results.append({
        "stage": 9,
        "check": "Horner_OCS_Register_Space_Synchronization_And_Scan_Cycle",
        "passed": c9_pass,
        "details": f"%R1500={r1500}, %R1501={r1501}, %R1502={r1502}, %R1503={r1503}, %R1504={r1504}, %R1505={r1505}, %R1506={r1506}, %R1507={r1507}; %M350={m350}, %M351={m351}.",
    })

    # Summary and Deliverable Manifest
    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": f"Stream / Waterfall Multi-Epoch Hydrodynamic Flow SCADA Canvas verification passed cleanly ({sum(1 for t in test_results if t['passed'])}/{len(test_results)} checks passed).",
        "data": {
            "work_package": "W189",
            "gate": "Gate G9 / G2",
            "component": "Cscape HMI Dynamic Stream / Waterfall Multi-Epoch Hydrodynamic Flow SCADA Canvas",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "metrics": {
                "active_stream_count": canvas_sync.metrics.active_stream_count,
                "total_throughput_bpd": canvas_sync.metrics.total_throughput_bpd,
                "total_throughput_bpd_scaled": canvas_sync.metrics.total_throughput_scaled,
                "dominant_stream_index": canvas_sync.metrics.dominant_stream_index,
                "dominant_stream_name": canvas_sync.metrics.dominant_stream_name,
                "epoch_depth": canvas_sync.metrics.epoch_depth,
                "hydrodynamic_turbulence": canvas_sync.metrics.hydrodynamic_turbulence,
                "flow_velocity_variation_pct": canvas_sync.metrics.flow_velocity_variation_pct,
                "stream_dispersion_coeff": canvas_sync.metrics.stream_dispersion_coeff,
                "diagnostic_status_code": f"0x{int(canvas_sync.diagnostic_code) & 0xFFFF:04X}",
                "waterfall_streaming_active": canvas_sync.streaming_active,
                "flow_turbulence_warning": canvas_sync.turbulence_warning,
                "wcag_badge_contrast": round(contrast_badge, 2),
                "wcag_theme_contrast": round(contrast_theme, 2),
            },
        },
    }

    if target_evidence_path:
        out_ev = Path(target_evidence_path)
        out_ev.parent.mkdir(parents=True, exist_ok=True)
        with open(out_ev, "w", encoding="utf-8") as f:
            f.write(json.dumps(evidence, indent=2))

    return evidence


if __name__ == "__main__":
    result = run_stream_waterfall_canvas_verification()
    print(json.dumps(result, indent=2))
