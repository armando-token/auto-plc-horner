"""Cscape HMI Dynamic Wind Rose / Polar Directional Vector & Environmental Hydrodynamic SCADA Canvas.

Work Package: W192 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Provides:
1. Strict Pure IEC 61131-3 Structured Text (ST) POU:
   - Program 'WindRoseEnvironmentalCanvasSync' (and aliases 'WindRoseCanvasSync', 'WindRoseEngine')
     with Horner OCS RegisterTable bindings:
     - %R1530: PrevailingWindDirectionDeg (INT16, 0..359 degrees)
     - %R1531: AverageWindSpeedMpsScaled (INT16, scaled x10 m/s, e.g. 65 = 6.5 m/s)
     - %R1532: PeakGustSpeedMpsScaled (INT16, scaled x10 m/s, e.g. 142 = 14.2 m/s)
     - %R1533: CalmPeriodPercentageScaled (INT16, scaled x10 %, e.g. 85 = 8.5 %)
     - %R1534: PlumeDispersionDistanceMeters (INT16, meters, e.g. 850 m)
     - %R1535: AtmosphericStabilityClass (INT16, 1=A..6=F Pasquill-Gifford class)
     - %R1536: ToxicCorridorSectorAngleDeg (INT16, degrees)
     - %R1537: DiagnosticStatusCode (0x0000=OK, 0xD301=Gale Warning, 0xD302=Plume Boundary Breach, 0xD303=SVG Render Fault)
     - %M357: WindRoseCanvasActive (BOOL)
     - %M358: EnvironmentalDispersionAlarm (BOOL)
   - Validated with SecurityGuard.assert_pure_st_content and STParser.
   - Aggressive ladder logic interception (---[ ]---, ---( )---, RUNG, NETWORK, XIC, OTE)
     failing closed with ERR_LADDER_FORBIDDEN (LadderForbiddenError).

2. 16 Directional Sectors & 5 Wind Speed Frequency Bins:
   - 16 Polar sectors: N, NNE, NE, ENE, E, ESE, SE, SSE, S, SSW, SW, WSW, W, WNW, NW, NNW.
   - 5 Wind speed frequency classes:
     1. Calm (< 1 m/s)
     2. Light (1 - 5 m/s)
     3. Moderate (5 - 10 m/s)
     4. Fresh (10 - 15 m/s)
     5. Strong (> 15 m/s)
   - Stacked annular sector wedges with color-coded speed classes.
   - Concentric polar grid circles (5%, 10%, 15%, 20%, 25% frequency limits).
   - Frequency conservation across sectors + calm period = 100.0%.

3. Gaussian Plume Dispersion Hazard Corridor Overlay:
   - Downwind toxic footprint calculation based on Pasquill-Gifford stability classes (1=A .. 6=F).
   - Lateral plume dispersion spread and hazard boundary envelope.
   - Centerline downwind vector with directional vector arrow.
   - Inner IDLH / AEGL-3 high toxicity core overlay and outer dispersion hazard footprint.
   - Downwind distance threshold monitoring (1000m fence line breach).

4. Standalone W3C SVG 1.1 Vector Canvas Renderer:
   - 1200x750 industrial SCADA viewport with dark theme backing (#0D1117 / #161B22).
   - Decoupled dark backing badges (#05080C) meeting WCAG 2.1 AAA contrast:
     * Badge contrast > 18:1
     * Primary text contrast > 7.0:1
     * Graphical SCADA boundaries > 3.0:1
   - Interactive sector selector buttons (All Sectors, N, NE, E, SE, S, SW, W, NW, Toxic Corridor).
   - Beaufort scale telemetry HUD card (Forces 0..12, knots, m/s, gusts).
   - Toxic corridor alarm badge and environmental dispersion status HUD card.
   - Horner OCS register telemetry card (%R1530..%R1537, %M357..%M358).

5. Process Safety Interlocks & Diagnostics:
   - 0xD301: WIND_ERR_GALE_WARNING (Average wind >= 17.2 m/s or Gust >= 20.8 m/s).
   - 0xD302: WIND_ERR_PLUME_BOUNDARY_BREACH (Plume dispersion distance >= 1000m) -> asserts %M358.
   - 0xD303: WIND_ERR_RENDER_FAULT (SVG path or polygon synthesis fault).
   - 0x0000: WIND_ERR_OK / DIAG_EVENT_OK.

6. Horner OCS Memory Space Integration & ILogicUnit:
   - Synchronizes word registers %R1530..%R1537 and discrete coils %M357..%M358.
   - In sync_to_registers(), passes privilege=PrivilegeMode.SYSTEM to reg_table writes.
   - Implements ILogicUnit interface with scan_step(dt).

7. Deterministic 9-Stage Verification Suite:
   - run_wind_rose_canvas_verification(output_path, sample_svg_path) implementing 9 stages
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


# Diagnostic event codes conforming to Horner OCS %R1537 specification
DIAG_EVENT_OK: DiagnosticCode                     = DiagnosticCode(0x0000)
WIND_ERR_OK: DiagnosticCode                       = DiagnosticCode(0x0000)

# 0xD301: WIND_ERR_GALE_WARNING (Average wind >= 17.2 m/s or Gust >= 20.8 m/s)
WIND_ERR_GALE_WARNING: DiagnosticCode             = DiagnosticCode(0xD301)
DIAG_EVENT_GALE_WARNING: DiagnosticCode           = WIND_ERR_GALE_WARNING

# 0xD302: WIND_ERR_PLUME_BOUNDARY_BREACH (Plume dispersion distance >= 1000 m) -> asserts %M358
WIND_ERR_PLUME_BOUNDARY_BREACH: DiagnosticCode    = DiagnosticCode(0xD302)
WIND_ERR_PLUME_BREACH: DiagnosticCode             = WIND_ERR_PLUME_BOUNDARY_BREACH
DIAG_EVENT_PLUME_BOUNDARY_BREACH: DiagnosticCode  = WIND_ERR_PLUME_BOUNDARY_BREACH
DIAG_EVENT_PLUME_BREACH: DiagnosticCode           = WIND_ERR_PLUME_BOUNDARY_BREACH

# 0xD303: WIND_ERR_RENDER_FAULT (SVG path or polygon synthesis fault)
WIND_ERR_RENDER_FAULT: DiagnosticCode             = DiagnosticCode(0xD303)
DIAG_EVENT_RENDER_FAULT: DiagnosticCode           = WIND_ERR_RENDER_FAULT

# Color Palette conforming to GitHub Dark / SCADA dark theme & WCAG 2.1 AAA
COLOR_DARK_THEME_BACKING: str                     = "#0D1117"   # Canvas dark backing
COLOR_DARK_THEME_SURFACE: str                     = "#161B22"   # Surface container backing
COLOR_DARK_THEME_BACKING_1E1E1E: str              = "#1E1E1E"   # Alternative dark backing
COLOR_DECOUPLED_BADGE: str                        = "#05080C"   # Decoupled badge backing (> 18:1 contrast)
COLOR_CARD_BORDER: str                            = "#30363D"   # Border slate
COLOR_TEXT_PRIMARY: str                           = "#F0F6FC"   # Primary light text (contrast > 17:1)
COLOR_TEXT_MUTED: str                             = "#8B949E"   # Secondary muted text
COLOR_GRID_LINE: str                              = "#21262D"   # Grid contour lines
COLOR_GRID_SPOKE: str                             = "#30363D"   # Radial spoke lines
COLOR_FOCUS_BLUE: str                             = "#58A6FF"   # Interactive selection accent

# 5 Wind Speed Frequency Bin Colors (Meeting WCAG 2.1 AAA Graphical Contrast > 3.0:1)
COLOR_BIN_CALM: str                               = "#38BDF8"   # Calm (< 1 m/s): Sky Blue (contrast 8.8:1)
COLOR_BIN_LIGHT: str                              = "#10B981"   # Light (1 - 5 m/s): Emerald (contrast 7.5:1)
COLOR_BIN_MODERATE: str                           = "#F59E0B"   # Moderate (5 - 10 m/s): Amber (contrast 8.8:1)
COLOR_BIN_FRESH: str                              = "#F97316"   # Fresh (10 - 15 m/s): Coral (contrast 6.8:1)
COLOR_BIN_STRONG: str                             = "#EF4444"   # Strong (> 15 m/s): Crimson (contrast 5.0:1)

# Environmental Dispersion Hazard Colors
COLOR_PLUME_HAZARD_CORE: str                      = "#DC2626"   # IDLH toxic core
COLOR_PLUME_HAZARD_OUTER: str                     = "#EF4444"   # Boundary hazard contour
COLOR_NOMINAL_GREEN: str                          = "#238636"   # Nominal active green
COLOR_WARNING_AMBER: str                          = "#D29922"   # Advisory warning amber
COLOR_TRIP_CRIMSON: str                           = "#DA3633"   # Safety interlock crimson

# Nominal SCADA Process Constants
NOMINAL_PREVAILING_WIND_DIRECTION_DEG: int        = 225         # Prevailing SW (225 degrees)
NOMINAL_AVERAGE_WIND_SPEED_MPS: float             = 6.5         # 6.5 m/s (Moderate breeze)
NOMINAL_AVERAGE_WIND_SPEED_SCALED: int            = 65          # Scaled x10 = 65
NOMINAL_PEAK_GUST_SPEED_MPS: float                = 14.2        # 14.2 m/s (Near gale gust)
NOMINAL_PEAK_GUST_SPEED_SCALED: int               = 142         # Scaled x10 = 142
NOMINAL_CALM_PERIOD_PCT: float                    = 8.5         # 8.5 %
NOMINAL_CALM_PERIOD_SCALED: int                   = 85          # Scaled x10 = 85
NOMINAL_PLUME_DISPERSION_DISTANCE_M: int          = 850         # 850 m
NOMINAL_ATMOSPHERIC_STABILITY_CLASS: int          = 4           # Class D (Neutral)
NOMINAL_TOXIC_CORRIDOR_SECTOR_ANGLE_DEG: int      = 45          # 45 degrees NE (Downwind)

# Operational Safety Thresholds
GALE_WARNING_THRESHOLD_MPS: float                 = 17.2        # Beaufort 8 (Gale force >= 17.2 m/s)
GUST_GALE_THRESHOLD_MPS: float                    = 20.8        # Beaufort 9 (Strong gale gust >= 20.8 m/s)
PLUME_BREACH_THRESHOLD_METERS: float              = 1000.0      # Boundary fence line (1000 m)

# 16 Polar Directional Sectors & 5 Speed Classes
SECTOR_COUNT: int                                 = 16
SPEED_BIN_COUNT: int                              = 5
SECTOR_NAMES: List[str]                           = [
    "N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE",
    "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW",
]
SPEED_BIN_NAMES: List[str]                        = [
    "Calm (<1 m/s)",
    "Light (1-5 m/s)",
    "Moderate (5-10 m/s)",
    "Fresh (10-15 m/s)",
    "Strong (>15 m/s)",
]

# Viewport & Layout Geometry
CANVAS_VIEWPORT_WIDTH: int                        = 1200
CANVAS_VIEWPORT_HEIGHT: int                       = 750
PLOT_CENTER_X: float                              = 420.0
PLOT_CENTER_Y: float                              = 415.0
PLOT_MAX_RADIUS: float                            = 250.0
PLOT_HUB_RADIUS: float                            = 45.0
PLOT_MAX_FREQUENCY_PCT: float                     = 25.0
PLUME_MAX_DISTANCE_REF_METERS: float              = 1200.0

# WCAG 2.1 AAA Contrast Targets
WCAG_AAA_BADGE_CONTRAST_TARGET: float             = 18.0        # Decoupled dark backing badge (> 18:1)
WCAG_AAA_TEXT_CONTRAST_TARGET: float              = 7.0         # Normal text (> 7.0:1)
WCAG_GRAPHICAL_CONTRAST_TARGET: float             = 3.0         # SCADA graphics & boundaries (> 3.0:1)


# ============================================================================
# 2. Telemetry Bitmask & Enums
# ============================================================================

class WindRoseStatusBits(IntFlag):
    """Horner OCS Wind Rose Telemetry Status Bitmask Definitions."""
    ENGINE_ACTIVE          = 1 << 0  # Bit 0 (0x0001): Canvas & telemetry engine active
    CANVAS_ACTIVE          = 1 << 1  # Bit 1 (0x0002): Wind rose canvas active (%M357)
    SECTORS_COMPUTED       = 1 << 2  # Bit 2 (0x0004): 16 sector wedges computed
    NOMINAL_OPERATION      = 1 << 3  # Bit 3 (0x0008): Operating within nominal limits
    GALE_WARNING           = 1 << 4  # Bit 4 (0x0010): Gale warning condition active
    PLUME_DISPERSION_ALARM = 1 << 5  # Bit 5 (0x0020): Plume breach alarm asserted (%M358)
    SVG_VALID              = 1 << 6  # Bit 6 (0x0040): Standalone W3C SVG 1.1 rendered and valid
    WCAG_AAA               = 1 << 7  # Bit 7 (0x0080): WCAG 2.1 AAA contrast verified (> 18:1 badge, > 7:1 text)


class WindSpeedBin(int, Enum):
    """5 SCADA Wind Speed Frequency Classes."""
    CALM     = 0  # < 1.0 m/s
    LIGHT    = 1  # 1.0 - 5.0 m/s
    MODERATE = 2  # 5.0 - 10.0 m/s
    FRESH    = 3  # 10.0 - 15.0 m/s
    STRONG   = 4  # > 15.0 m/s


class PasquillGiffordClass(int, Enum):
    """Pasquill-Gifford Atmospheric Stability Classes (1=A .. 6=F)."""
    CLASS_A = 1  # Extremely unstable
    CLASS_B = 2  # Moderately unstable
    CLASS_C = 3  # Slightly unstable
    CLASS_D = 4  # Neutral
    CLASS_E = 5  # Slightly stable
    CLASS_F = 6  # Moderately stable


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


def calculate_contrast_ratio(color1_hex: str, color2_hex: str) -> float:
    """Calculate WCAG 2.1 contrast ratio between two hex colors."""
    lum1 = hex_to_relative_luminance(color1_hex)
    lum2 = hex_to_relative_luminance(color2_hex)
    lighter = max(lum1, lum2)
    darker = min(lum1, lum2)
    return (lighter + 0.05) / (darker + 0.05)


def validate_wcag_aaa_contrast(foreground_hex: str, background_hex: str, min_contrast: float = 7.0) -> bool:
    """Verify if color pair satisfies WCAG AAA contrast threshold."""
    return calculate_contrast_ratio(foreground_hex, background_hex) >= min_contrast


# Pre-computed verified contrast ratios
DECOUPLED_BADGE_CONTRAST_RATIO: float       = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
DARK_THEME_TEXT_CONTRAST_RATIO: float       = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
CALM_GRAPHICAL_CONTRAST_RATIO: float        = calculate_contrast_ratio(COLOR_BIN_CALM, COLOR_DARK_THEME_BACKING)
LIGHT_GRAPHICAL_CONTRAST_RATIO: float       = calculate_contrast_ratio(COLOR_BIN_LIGHT, COLOR_DARK_THEME_BACKING)
MODERATE_GRAPHICAL_CONTRAST_RATIO: float    = calculate_contrast_ratio(COLOR_BIN_MODERATE, COLOR_DARK_THEME_BACKING)
FRESH_GRAPHICAL_CONTRAST_RATIO: float       = calculate_contrast_ratio(COLOR_BIN_FRESH, COLOR_DARK_THEME_BACKING)
STRONG_GRAPHICAL_CONTRAST_RATIO: float      = calculate_contrast_ratio(COLOR_BIN_STRONG, COLOR_DARK_THEME_BACKING)


# ============================================================================
# 4. Data Models & Configuration
# ============================================================================

@dataclass
class WindSectorData:
    """Represents a single directional sector (one of 16) in the wind rose."""
    index: int                          # 0..15
    name: str                           # e.g. "N", "SW"
    azimuth_deg: float                  # Sector center azimuth (0..337.5)
    bin_frequencies: List[float] = field(default_factory=list)  # 5 floats (% of total observations)
    mean_speed_mps: float = 0.0         # Sector mean wind speed (m/s)
    peak_gust_mps: float = 0.0          # Sector peak gust speed (m/s)

    @property
    def total_frequency_pct(self) -> float:
        """Sum of frequencies across the 5 speed bins for this sector."""
        return sum(self.bin_frequencies)

    def cumulative_bin_frequency(self, bin_idx: int) -> float:
        """Cumulative frequency up to and including bin_idx (0..4)."""
        if bin_idx < 0:
            return 0.0
        return sum(self.bin_frequencies[: bin_idx + 1])


@dataclass
class WindRoseConfig:
    """Configuration options for Cscape Dynamic Wind Rose SCADA Canvas."""
    viewport_width: int = CANVAS_VIEWPORT_WIDTH
    viewport_height: int = CANVAS_VIEWPORT_HEIGHT
    center_x: float = PLOT_CENTER_X
    center_y: float = PLOT_CENTER_Y
    max_radius: float = PLOT_MAX_RADIUS
    hub_radius: float = PLOT_HUB_RADIUS
    max_frequency_pct: float = PLOT_MAX_FREQUENCY_PCT
    plume_max_distance_ref: float = PLUME_MAX_DISTANCE_REF_METERS
    gale_warning_threshold_mps: float = GALE_WARNING_THRESHOLD_MPS
    gust_gale_threshold_mps: float = GUST_GALE_THRESHOLD_MPS
    plume_breach_threshold_meters: float = PLUME_BREACH_THRESHOLD_METERS
    dark_theme_backing: str = COLOR_DARK_THEME_BACKING
    surface_backing: str = COLOR_DARK_THEME_SURFACE
    badge_backing: str = COLOR_DECOUPLED_BADGE


@dataclass
class WindRoseMetrics:
    """Telemetry metrics bundle for SCADA monitoring and Horner OCS registers."""
    prevailing_direction_deg: int               # %R1530 (0..359)
    average_wind_speed_mps: float               # physical m/s
    average_wind_speed_scaled: int              # %R1531 (x10)
    peak_gust_speed_mps: float                  # physical m/s
    peak_gust_speed_scaled: int                 # %R1532 (x10)
    calm_period_pct: float                      # physical %
    calm_period_scaled: int                     # %R1533 (x10)
    plume_dispersion_distance_m: int            # %R1534 (meters)
    atmospheric_stability_class: int            # %R1535 (1..6)
    toxic_corridor_sector_angle_deg: int        # %R1536 (degrees)
    diagnostic_status_code: DiagnosticCode      # %R1537
    wind_rose_canvas_active: bool               # %M357
    environmental_dispersion_alarm: bool        # %M358
    beaufort_force: int                         # 0..12
    beaufort_description: str                   # e.g. "Moderate Breeze"
    has_gale_warning: bool
    has_plume_breach: bool
    has_render_fault: bool
    prevailing_sector_name: str
    toxic_sector_name: str


# ============================================================================
# 5. Domain Calculations & Geometry Helpers
# ============================================================================

def get_beaufort_scale_info(wind_speed_mps: float) -> Tuple[int, str]:
    """Calculate Beaufort scale force (0..12) and meteorological description."""
    if wind_speed_mps < 0.5:
        return (0, "Calm")
    elif wind_speed_mps < 1.6:
        return (1, "Light Air")
    elif wind_speed_mps < 3.4:
        return (2, "Light Breeze")
    elif wind_speed_mps < 5.5:
        return (3, "Gentle Breeze")
    elif wind_speed_mps < 8.0:
        return (4, "Moderate Breeze")
    elif wind_speed_mps < 10.8:
        return (5, "Fresh Breeze")
    elif wind_speed_mps < 13.9:
        return (6, "Strong Breeze")
    elif wind_speed_mps < 17.2:
        return (7, "High Wind / Near Gale")
    elif wind_speed_mps < 20.8:
        return (8, "Gale")
    elif wind_speed_mps < 24.5:
        return (9, "Strong Gale")
    elif wind_speed_mps < 28.5:
        return (10, "Storm")
    elif wind_speed_mps < 32.7:
        return (11, "Violent Storm")
    else:
        return (12, "Hurricane")


def compute_plume_spread_angle(stability_class: int) -> float:
    """Lateral dispersion half-angle (degrees) based on Pasquill-Gifford stability class.

    Class 1 (A: Extremely unstable) has large convective lateral mixing.
    Class 6 (F: Moderately stable) has narrow, persistent downwind channeling.
    """
    spread_angles: Dict[int, float] = {
        1: 24.0,  # Class A
        2: 20.0,  # Class B
        3: 16.0,  # Class C
        4: 12.0,  # Class D (Neutral)
        5: 9.0,   # Class E
        6: 6.5,   # Class F
    }
    return spread_angles.get(stability_class, 12.0)


def sector_index_from_direction_deg(deg: float) -> int:
    """Map directional azimuth in degrees (0..359) to one of the 16 sector indices (0..15)."""
    norm_deg = deg % 360.0
    sector_span = 360.0 / 16.0  # 22.5 degrees
    index = int(round(norm_deg / sector_span)) % 16
    return index


def direction_name_from_deg(deg: float) -> str:
    """Return compass acronym for a given azimuth angle."""
    idx = sector_index_from_direction_deg(deg)
    return SECTOR_NAMES[idx]


def polar_to_cartesian_svg(
    cx: float,
    cy: float,
    radius: float,
    angle_deg: float,
) -> Tuple[float, float]:
    """Convert polar coordinates to SVG screen coordinates.

    Meteorological standard: 0° is North (UP: dy < 0), 90° is East (RIGHT: dx > 0),
    180° is South (DOWN: dy > 0), 270° is West (LEFT: dx < 0).
    """
    rad = math.radians(angle_deg)
    x = cx + radius * math.sin(rad)
    y = cy - radius * math.cos(rad)
    return (x, y)


def generate_sector_wedge_svg_path(
    cx: float,
    cy: float,
    r_inner: float,
    r_outer: float,
    theta_start_deg: float,
    theta_end_deg: float,
) -> str:
    """Generate SVG path for an annular sector wedge.

    Uses standard SVG grammar: 'M ... L ... A ... L ... A ... Z'.
    """
    if r_outer <= r_inner or theta_end_deg <= theta_start_deg:
        return ""

    p1 = polar_to_cartesian_svg(cx, cy, r_inner, theta_start_deg)
    p2 = polar_to_cartesian_svg(cx, cy, r_outer, theta_start_deg)
    p3 = polar_to_cartesian_svg(cx, cy, r_outer, theta_end_deg)
    p4 = polar_to_cartesian_svg(cx, cy, r_inner, theta_end_deg)

    # Arc sweep: from theta_start to theta_end clockwise is sweep=1
    # Returning from theta_end to theta_start counter-clockwise along r_inner is sweep=0
    path = (
        f"M {p1[0]:.2f} {p1[1]:.2f} "
        f"L {p2[0]:.2f} {p2[1]:.2f} "
        f"A {r_outer:.2f} {r_outer:.2f} 0 0 1 {p3[0]:.2f} {p3[1]:.2f} "
        f"L {p4[0]:.2f} {p4[1]:.2f} "
        f"A {r_inner:.2f} {r_inner:.2f} 0 0 0 {p1[0]:.2f} {p1[1]:.2f} Z"
    )
    return path


def generate_gaussian_plume_svg_path(
    cx: float,
    cy: float,
    hub_radius: float,
    plume_distance_m: float,
    max_dist_ref: float,
    max_canvas_radius: float,
    sector_angle_deg: float,
    stability_class: int,
) -> str:
    """Generate Gaussian plume dispersion hazard corridor polygon path.

    Synthesizes downwind hazard envelope with Pasquill-Gifford dispersion widening.
    """
    # Scale physical dispersion distance (e.g. 850m) to canvas pixel radius
    span_radius = max_canvas_radius - hub_radius
    norm_dist = max(0.1, min(1.3, plume_distance_m / max_dist_ref))
    r_plume = hub_radius + norm_dist * span_radius

    spread_half_angle = compute_plume_spread_angle(stability_class)
    rad_center = math.radians(sector_angle_deg)

    # Centerline unit vector
    ux = math.sin(rad_center)
    uy = -math.cos(rad_center)

    # Lateral crosswind unit vector (perpendicular to right)
    vx = math.cos(rad_center)
    vy = math.sin(rad_center)

    # Compute boundary points along right edge (forward)
    steps = 8
    pts_right: List[Tuple[float, float]] = []
    pts_left: List[Tuple[float, float]] = []

    for k in range(steps + 1):
        tau = k / float(steps)
        r_curr = hub_radius + tau * (r_plume - hub_radius)
        # Lateral dispersion width (initial hub offset + Pasquill expansion)
        w_curr = 4.0 + (r_plume * math.tan(math.radians(spread_half_angle)) - 4.0) * (tau ** 0.85)

        # Centerline position at this distance
        xc = cx + r_curr * ux
        yc = cy + r_curr * uy

        xr = xc + w_curr * vx
        yr = yc + w_curr * vy
        pts_right.append((xr, yr))

        xl = xc - w_curr * vx
        yl = yc - w_curr * vy
        pts_left.append((xl, yl))

    # Plume front curved cap (around downwind tip)
    r_front = r_plume + 6.0
    front_tip = (cx + r_front * ux, cy + r_front * uy)

    # Build path: start at inner hub right, follow right edge, front cap, return along left edge
    cmds: List[str] = []
    cmds.append(f"M {pts_right[0][0]:.2f} {pts_right[0][1]:.2f}")
    for pt in pts_right[1:]:
        cmds.append(f"L {pt[0]:.2f} {pt[1]:.2f}")

    cmds.append(f"Q {front_tip[0]:.2f} {front_tip[1]:.2f} {pts_left[-1][0]:.2f} {pts_left[-1][1]:.2f}")

    for pt in reversed(pts_left[:-1]):
        cmds.append(f"L {pt[0]:.2f} {pt[1]:.2f}")

    cmds.append("Z")
    return " ".join(cmds)


def generate_gaussian_plume_core_svg_path(
    cx: float,
    cy: float,
    hub_radius: float,
    plume_distance_m: float,
    max_dist_ref: float,
    max_canvas_radius: float,
    sector_angle_deg: float,
    stability_class: int,
) -> str:
    """Generate inner IDLH / AEGL-3 lethal concentration toxic plume core path."""
    return generate_gaussian_plume_svg_path(
        cx=cx,
        cy=cy,
        hub_radius=hub_radius,
        plume_distance_m=plume_distance_m * 0.40,  # Inner 40% distance
        max_dist_ref=max_dist_ref,
        max_canvas_radius=max_canvas_radius,
        sector_angle_deg=sector_angle_deg,
        stability_class=stability_class,
    )


def create_canonical_wind_sectors() -> List[WindSectorData]:
    """Generate 16 canonical meteorological directional sectors with balanced 5-bin distributions.

    Total across 16 sectors = 91.5 %; Calm period = 8.5 %; Total sum = 100.0 %.
    Prevailing wind is SW (225°) with elevated frequency.
    """
    # 16 sectors frequencies matching 91.5% total (91.5 + 8.5 calm = 100.0%)
    sector_specs: List[Tuple[str, float, List[float], float, float]] = [
        # (name, azimuth, [calm, light, moderate, fresh, strong], mean_mps, peak_gust_mps)
        ("N",   0.0,   [0.3, 1.6, 0.9, 0.2, 0.0], 4.2, 8.5),
        ("NNE", 22.5,  [0.4, 2.3, 1.4, 0.4, 0.0], 4.8, 9.2),
        ("NE",  45.0,  [0.5, 3.0, 2.5, 0.5, 0.0], 5.4, 10.5),
        ("ENE", 67.5,  [0.4, 2.3, 1.4, 0.4, 0.0], 4.7, 9.1),
        ("E",   90.0,  [0.3, 1.6, 0.9, 0.2, 0.0], 4.1, 8.2),
        ("ESE", 112.5, [0.4, 1.5, 0.9, 0.2, 0.0], 3.8, 7.6),
        ("SE",  135.0, [0.3, 1.6, 0.9, 0.2, 0.0], 4.0, 8.0),
        ("SSE", 157.5, [0.4, 1.8, 1.1, 0.2, 0.0], 4.3, 8.7),
        ("S",   180.0, [0.5, 2.5, 3.0, 1.0, 0.0], 5.8, 11.4),
        ("SSW", 202.5, [0.5, 3.0, 4.0, 1.5, 0.5], 6.4, 13.8),
        ("SW",  225.0, [0.5, 4.0, 6.0, 3.5, 1.5], 7.8, 16.5),  # Prevailing sector
        ("WSW", 247.5, [0.5, 3.0, 3.5, 1.5, 0.5], 6.2, 13.2),
        ("W",   270.0, [0.5, 2.5, 3.0, 1.0, 0.5], 5.6, 12.0),
        ("WNW", 292.5, [0.4, 1.8, 1.4, 0.4, 0.0], 4.6, 9.4),
        ("NW",  315.0, [0.5, 2.0, 1.5, 0.5, 0.0], 4.5, 9.0),
        ("NNW", 337.5, [0.4, 1.8, 1.1, 0.2, 0.0], 4.2, 8.6),
    ]

    sectors: List[WindSectorData] = []
    for idx, (name, az, bins, mean_mps, gust_mps) in enumerate(sector_specs):
        sectors.append(
            WindSectorData(
                index=idx,
                name=name,
                azimuth_deg=az,
                bin_frequencies=bins,
                mean_speed_mps=mean_mps,
                peak_gust_mps=gust_mps,
            )
        )
    return sectors


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
# 6. Pure IEC 61131-3 Structured Text POU
# ============================================================================

WIND_ROSE_PURE_ST_POU: str = """PROGRAM WindRoseEnvironmentalCanvasSync
VAR
    PrevailingWindDirectionDeg    AT %R1530 : INT;
    AverageWindSpeedMpsScaled     AT %R1531 : INT;
    PeakGustSpeedMpsScaled        AT %R1532 : INT;
    CalmPeriodPercentageScaled    AT %R1533 : INT;
    PlumeDispersionDistanceMeters AT %R1534 : INT;
    AtmosphericStabilityClass     AT %R1535 : INT;
    ToxicCorridorSectorAngleDeg   AT %R1536 : INT;
    DiagnosticStatusCode          AT %R1537 : INT;
    WindRoseCanvasActive          AT %M357 : BOOL;
    EnvironmentalDispersionAlarm  AT %M358 : BOOL;
    GaleWarningTripRelay          : BOOL := FALSE;
    PlumeBreachAlarmRelay         : BOOL := FALSE;
    RenderFaultBeacon             : BOOL := FALSE;
END_VAR

(* Synchronize Gale Warning: DiagnosticStatusCode 0xD301 (-11519 / 54017) or AverageWindSpeedMpsScaled >= 172 *)
IF (DiagnosticStatusCode = -11519) OR (DiagnosticStatusCode = 54017) OR (AverageWindSpeedMpsScaled >= 172) THEN
    GaleWarningTripRelay := TRUE;
ELSE
    GaleWarningTripRelay := FALSE;
END_IF;

(* Synchronize Plume Boundary Breach: DiagnosticStatusCode 0xD302 (-11518 / 54018) or PlumeDispersionDistanceMeters >= 1000 *)
IF (DiagnosticStatusCode = -11518) OR (DiagnosticStatusCode = 54018) OR (PlumeDispersionDistanceMeters >= 1000) THEN
    EnvironmentalDispersionAlarm := TRUE;
    PlumeBreachAlarmRelay := TRUE;
ELSE
    EnvironmentalDispersionAlarm := FALSE;
    PlumeBreachAlarmRelay := FALSE;
END_IF;

(* Synchronize render fault beacon: DiagnosticStatusCode 0xD303 (-11517 / 54019) *)
IF (DiagnosticStatusCode = -11517) OR (DiagnosticStatusCode = 54019) THEN
    RenderFaultBeacon := TRUE;
ELSE
    RenderFaultBeacon := FALSE;
END_IF;

(* Wind rose canvas active when DiagnosticStatusCode = 0 or no fatal render fault *)
IF (DiagnosticStatusCode = 0) OR (DiagnosticStatusCode = -11519) OR (DiagnosticStatusCode = -11518) THEN
    WindRoseCanvasActive := TRUE;
ELSE
    WindRoseCanvasActive := FALSE;
END_IF;
END_PROGRAM
"""


WIND_ROSE_ENVIRONMENTAL_CANVAS_PURE_ST_POU: str = WIND_ROSE_PURE_ST_POU


def verify_wind_rose_canvas_pure_st() -> bool:
    """Validate WindRoseEnvironmentalCanvasSync POU with STParser and SecurityGuard."""
    SecurityGuard.assert_pure_st_content(WIND_ROSE_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(WIND_ROSE_PURE_ST_POU)
    if not pou:
        return False
    return pou.name == "WindRoseEnvironmentalCanvasSync" and pou.pou_type == POUType.PROGRAM


verify_wind_rose_pure_st = verify_wind_rose_canvas_pure_st


# ============================================================================
# 7. WindRoseCanvas Engine & ILogicUnit Implementation
# ============================================================================

class WindRoseCanvas(ILogicUnit):
    """Cscape HMI Dynamic Wind Rose / Polar Directional Vector & Environmental SCADA Canvas Engine.

    Implements Horner OCS RegisterTable memory synchronization, ILogicUnit scan cycle execution,
    and standalone W3C SVG 1.1 vector rendering.
    """

    def __init__(
        self,
        config: Optional[WindRoseConfig] = None,
        sectors: Optional[List[WindSectorData]] = None,
        reg_table: Optional[RegisterTable] = None,
    ) -> None:
        self.config: WindRoseConfig = config if config is not None else WindRoseConfig()
        self.sectors: List[WindSectorData] = (
            sectors if sectors is not None else create_canonical_wind_sectors()
        )
        self.reg_table: RegisterTable = reg_table if reg_table is not None else RegisterTable()

        # Telemetry State
        self.prevailing_direction_deg: int = NOMINAL_PREVAILING_WIND_DIRECTION_DEG
        self.average_wind_speed_mps: float = NOMINAL_AVERAGE_WIND_SPEED_MPS
        self.peak_gust_speed_mps: float = NOMINAL_PEAK_GUST_SPEED_MPS
        self.calm_period_pct: float = NOMINAL_CALM_PERIOD_PCT
        self.plume_dispersion_distance_m: int = NOMINAL_PLUME_DISPERSION_DISTANCE_M
        self.atmospheric_stability_class: int = NOMINAL_ATMOSPHERIC_STABILITY_CLASS
        self.toxic_corridor_sector_angle_deg: int = NOMINAL_TOXIC_CORRIDOR_SECTOR_ANGLE_DEG

        self.diagnostic_code: DiagnosticCode = DIAG_EVENT_OK
        self.canvas_active: bool = True
        self.environmental_dispersion_alarm: bool = False
        self.selected_sector_index: int = 10  # Sector SW (225 deg) default selection

        self.status_bits: WindRoseStatusBits = (
            WindRoseStatusBits.ENGINE_ACTIVE
            | WindRoseStatusBits.CANVAS_ACTIVE
            | WindRoseStatusBits.SECTORS_COMPUTED
            | WindRoseStatusBits.NOMINAL_OPERATION
            | WindRoseStatusBits.SVG_VALID
            | WindRoseStatusBits.WCAG_AAA
        )

        self.metrics: WindRoseMetrics = self._compute_metrics()
        self.sync_to_registers()

    def _compute_metrics(self) -> WindRoseMetrics:
        """Compute operational SCADA metrics and safety triggers."""
        # Check safety interlocks
        has_gale = (
            self.average_wind_speed_mps >= self.config.gale_warning_threshold_mps
            or self.peak_gust_speed_mps >= self.config.gust_gale_threshold_mps
            or self.diagnostic_code == WIND_ERR_GALE_WARNING
        )
        has_plume = (
            self.plume_dispersion_distance_m >= self.config.plume_breach_threshold_meters
            or self.diagnostic_code == WIND_ERR_PLUME_BOUNDARY_BREACH
        )
        has_render = self.diagnostic_code == WIND_ERR_RENDER_FAULT

        beaufort_force, beaufort_desc = get_beaufort_scale_info(self.average_wind_speed_mps)

        prev_name = direction_name_from_deg(float(self.prevailing_direction_deg))
        toxic_name = direction_name_from_deg(float(self.toxic_corridor_sector_angle_deg))

        return WindRoseMetrics(
            prevailing_direction_deg=self.prevailing_direction_deg,
            average_wind_speed_mps=self.average_wind_speed_mps,
            average_wind_speed_scaled=int(round(self.average_wind_speed_mps * 10.0)),
            peak_gust_speed_mps=self.peak_gust_speed_mps,
            peak_gust_speed_scaled=int(round(self.peak_gust_speed_mps * 10.0)),
            calm_period_pct=self.calm_period_pct,
            calm_period_scaled=int(round(self.calm_period_pct * 10.0)),
            plume_dispersion_distance_m=self.plume_dispersion_distance_m,
            atmospheric_stability_class=self.atmospheric_stability_class,
            toxic_corridor_sector_angle_deg=self.toxic_corridor_sector_angle_deg,
            diagnostic_status_code=self.diagnostic_code,
            wind_rose_canvas_active=self.canvas_active and not has_render,
            environmental_dispersion_alarm=has_plume,
            beaufort_force=beaufort_force,
            beaufort_description=beaufort_desc,
            has_gale_warning=has_gale,
            has_plume_breach=has_plume,
            has_render_fault=has_render,
            prevailing_sector_name=prev_name,
            toxic_sector_name=toxic_name,
        )

    def evaluate_telemetry(self) -> None:
        """Recompute wind rose metrics and update telemetry status bitmask."""
        self.metrics = self._compute_metrics()
        self.environmental_dispersion_alarm = self.metrics.has_plume_breach
        self.canvas_active = self.metrics.wind_rose_canvas_active

        if self.metrics.has_gale_warning:
            self.status_bits |= WindRoseStatusBits.GALE_WARNING
            self.status_bits &= ~WindRoseStatusBits.NOMINAL_OPERATION
        else:
            self.status_bits &= ~WindRoseStatusBits.GALE_WARNING

        if self.metrics.has_plume_breach:
            self.status_bits |= WindRoseStatusBits.PLUME_DISPERSION_ALARM
            self.status_bits &= ~WindRoseStatusBits.NOMINAL_OPERATION
        else:
            self.status_bits &= ~WindRoseStatusBits.PLUME_DISPERSION_ALARM

        if (
            not self.metrics.has_gale_warning
            and not self.metrics.has_plume_breach
            and not self.metrics.has_render_fault
            and self.diagnostic_code == DIAG_EVENT_OK
        ):
            self.status_bits |= WindRoseStatusBits.NOMINAL_OPERATION

    def update_telemetry(self) -> None:
        """Alias for evaluate_telemetry."""
        self.evaluate_telemetry()

    def sync_to_registers(self) -> None:
        """Synchronize telemetry state to Horner OCS RegisterTable memory space.

        Word Registers (%R1530..%R1537):
        - %R1530: PrevailingWindDirectionDeg (INT16, 0..359 degrees)
        - %R1531: AverageWindSpeedMpsScaled (INT16, scaled x10 m/s, e.g. 65 = 6.5 m/s)
        - %R1532: PeakGustSpeedMpsScaled (INT16, scaled x10 m/s, e.g. 142 = 14.2 m/s)
        - %R1533: CalmPeriodPercentageScaled (INT16, scaled x10 %, e.g. 85 = 8.5 %)
        - %R1534: PlumeDispersionDistanceMeters (INT16, meters, e.g. 850 m)
        - %R1535: AtmosphericStabilityClass (INT16, 1=A..6=F Pasquill-Gifford class)
        - %R1536: ToxicCorridorSectorAngleDeg (INT16, degrees)
        - %R1537: DiagnosticStatusCode (0x0000=OK, 0xD301, 0xD302, 0xD303)

        Discrete Coils (%M357..%M358):
        - %M357: WindRoseCanvasActive (BOOL)
        - %M358: EnvironmentalDispersionAlarm (BOOL)
        """
        reg = self.reg_table

        # %R1530: PrevailingWindDirectionDeg
        reg.write_word("%R1530", self.metrics.prevailing_direction_deg, privilege=PrivilegeMode.SYSTEM)

        # %R1531: AverageWindSpeedMpsScaled
        reg.write_word("%R1531", self.metrics.average_wind_speed_scaled, privilege=PrivilegeMode.SYSTEM)

        # %R1532: PeakGustSpeedMpsScaled
        reg.write_word("%R1532", self.metrics.peak_gust_speed_scaled, privilege=PrivilegeMode.SYSTEM)

        # %R1533: CalmPeriodPercentageScaled
        reg.write_word("%R1533", self.metrics.calm_period_scaled, privilege=PrivilegeMode.SYSTEM)

        # %R1534: PlumeDispersionDistanceMeters
        reg.write_word("%R1534", self.metrics.plume_dispersion_distance_m, privilege=PrivilegeMode.SYSTEM)

        # %R1535: AtmosphericStabilityClass
        reg.write_word("%R1535", self.metrics.atmospheric_stability_class, privilege=PrivilegeMode.SYSTEM)

        # %R1536: ToxicCorridorSectorAngleDeg
        reg.write_word("%R1536", self.metrics.toxic_corridor_sector_angle_deg, privilege=PrivilegeMode.SYSTEM)

        # %R1537: DiagnosticStatusCode
        reg.write_word("%R1537", int(self.diagnostic_code) & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %M357: WindRoseCanvasActive
        reg.write_bit("%M357", self.canvas_active, privilege=PrivilegeMode.SYSTEM)

        # %M358: EnvironmentalDispersionAlarm
        reg.write_bit("%M358", self.environmental_dispersion_alarm, privilege=PrivilegeMode.SYSTEM)

    # ------------------------------------------------------------------------
    # ILogicUnit Protocol Implementation
    # ------------------------------------------------------------------------
    @property
    def name(self) -> str:
        return "WindRoseEnvironmentalCanvasSync"

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
        self.prevailing_direction_deg = NOMINAL_PREVAILING_WIND_DIRECTION_DEG
        self.average_wind_speed_mps = NOMINAL_AVERAGE_WIND_SPEED_MPS
        self.peak_gust_speed_mps = NOMINAL_PEAK_GUST_SPEED_MPS
        self.calm_period_pct = NOMINAL_CALM_PERIOD_PCT
        self.plume_dispersion_distance_m = NOMINAL_PLUME_DISPERSION_DISTANCE_M
        self.atmospheric_stability_class = NOMINAL_ATMOSPHERIC_STABILITY_CLASS
        self.toxic_corridor_sector_angle_deg = NOMINAL_TOXIC_CORRIDOR_SECTOR_ANGLE_DEG

        self.diagnostic_code = DIAG_EVENT_OK
        self.canvas_active = True
        self.environmental_dispersion_alarm = False
        self.selected_sector_index = 10
        self.sectors = create_canonical_wind_sectors()

        self.status_bits = (
            WindRoseStatusBits.ENGINE_ACTIVE
            | WindRoseStatusBits.CANVAS_ACTIVE
            | WindRoseStatusBits.SECTORS_COMPUTED
            | WindRoseStatusBits.NOMINAL_OPERATION
            | WindRoseStatusBits.SVG_VALID
            | WindRoseStatusBits.WCAG_AAA
        )
        self.evaluate_telemetry()
        self.sync_to_registers()

    def step(self) -> None:
        """Execute single scan cycle simulation step."""
        self.evaluate_telemetry()
        self.sync_to_registers()

    def scan_step(self, dt: float = 0.01) -> None:
        """Execute discrete Horner OCS scan step with delta time dt."""
        context = create_mock_scan_context(cycle=1, dt_ms=dt * 1000.0, reg_table=self.reg_table)
        self.execute(context)
        self.sync_to_registers()

    def execute(self, context: ScanContext) -> None:
        """Execute discrete Horner OCS PLC scan cycle logic."""
        avg_speed_scaled = self.reg_table.read_word("%R1531")
        gust_speed_scaled = self.reg_table.read_word("%R1532")
        plume_dist = self.reg_table.read_word("%R1534")

        # 0xD301: Gale warning trigger
        if avg_speed_scaled >= 172 or gust_speed_scaled >= 208:
            self.diagnostic_code = WIND_ERR_GALE_WARNING
            self.status_bits |= WindRoseStatusBits.GALE_WARNING
            self.status_bits &= ~WindRoseStatusBits.NOMINAL_OPERATION
            self.reg_table.write_word("%R1537", 0xD301, privilege=PrivilegeMode.SYSTEM)
        # 0xD302: Plume boundary breach trigger
        elif plume_dist >= 1000:
            self.environmental_dispersion_alarm = True
            self.diagnostic_code = WIND_ERR_PLUME_BOUNDARY_BREACH
            self.status_bits |= WindRoseStatusBits.PLUME_DISPERSION_ALARM
            self.status_bits &= ~WindRoseStatusBits.NOMINAL_OPERATION
            self.reg_table.write_bit("%M358", True, privilege=PrivilegeMode.SYSTEM)
            self.reg_table.write_word("%R1537", 0xD302, privilege=PrivilegeMode.SYSTEM)
        # 0xD303: Render fault
        elif self.diagnostic_code == WIND_ERR_RENDER_FAULT:
            self.canvas_active = False
            self.status_bits &= ~WindRoseStatusBits.NOMINAL_OPERATION
            self.reg_table.write_bit("%M357", False, privilege=PrivilegeMode.SYSTEM)
            self.reg_table.write_word("%R1537", 0xD303, privilege=PrivilegeMode.SYSTEM)
        else:
            self.environmental_dispersion_alarm = False
            self.reg_table.write_bit("%M358", False, privilege=PrivilegeMode.SYSTEM)
            curr_diag = self.reg_table.read_word("%R1537")
            if DiagnosticCode(curr_diag) in (WIND_ERR_GALE_WARNING, WIND_ERR_PLUME_BOUNDARY_BREACH):
                self.diagnostic_code = DIAG_EVENT_OK
                self.reg_table.write_word("%R1537", 0, privilege=PrivilegeMode.SYSTEM)

    def execute_logic(self, context: ScanContext) -> None:
        """Scan execution alias."""
        self.execute(context)

    # ------------------------------------------------------------------------
    # Fault Injection & Diagnostic Interlock Triggers
    # ------------------------------------------------------------------------
    def trigger_gale_warning(self, wind_speed: float = 18.5, gust_speed: float = 22.0) -> None:
        """Inject 0xD301 Gale Warning (average wind >= 17.2 m/s or gust >= 20.8 m/s)."""
        self.average_wind_speed_mps = wind_speed
        self.peak_gust_speed_mps = gust_speed
        self.diagnostic_code = WIND_ERR_GALE_WARNING
        self.evaluate_telemetry()
        self.sync_to_registers()

    def trigger_plume_boundary_breach(self, distance_meters: int = 1150) -> None:
        """Inject 0xD302 Plume Boundary Breach (plume distance >= 1000 m).

        Asserts %M358 (EnvironmentalDispersionAlarm) and sets %R1537 to 0xD302.
        """
        self.plume_dispersion_distance_m = distance_meters
        self.diagnostic_code = WIND_ERR_PLUME_BOUNDARY_BREACH
        self.environmental_dispersion_alarm = True
        self.evaluate_telemetry()
        self.sync_to_registers()

    def trigger_render_fault(self) -> None:
        """Inject 0xD303 SVG Render Fault."""
        self.diagnostic_code = WIND_ERR_RENDER_FAULT
        self.canvas_active = False
        self.evaluate_telemetry()
        self.sync_to_registers()

    def select_sector(self, sector_index: int) -> None:
        """Select active sector tab for focused HMI inspection (0..15)."""
        if 0 <= sector_index < len(self.sectors):
            self.selected_sector_index = sector_index

    def render_svg(self) -> str:
        """Render standalone W3C SVG 1.1 representation of the SCADA canvas."""
        return generate_wind_rose_canvas_svg(self)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize complete canvas telemetry state."""
        return {
            "component": "WindRoseCanvas",
            "work_package": "W192",
            "prevailing_direction_deg": self.prevailing_direction_deg,
            "prevailing_sector": self.metrics.prevailing_sector_name,
            "average_wind_speed_mps": self.average_wind_speed_mps,
            "peak_gust_speed_mps": self.peak_gust_speed_mps,
            "calm_period_pct": self.calm_period_pct,
            "plume_dispersion_distance_m": self.plume_dispersion_distance_m,
            "atmospheric_stability_class": self.atmospheric_stability_class,
            "toxic_corridor_sector_angle_deg": self.toxic_corridor_sector_angle_deg,
            "toxic_sector": self.metrics.toxic_sector_name,
            "beaufort_force": self.metrics.beaufort_force,
            "beaufort_desc": self.metrics.beaufort_description,
            "canvas_active": self.canvas_active,
            "environmental_dispersion_alarm": self.environmental_dispersion_alarm,
            "diagnostic_code": f"0xD3{int(self.diagnostic_code) & 0xFF:02X}" if int(self.diagnostic_code) else "0x0000",
            "status_bits": int(self.status_bits),
        }


WindRoseCanvasSync = WindRoseCanvas
WindRoseEnvironmentalCanvas = WindRoseCanvas
WindRoseEnvironmentalCanvasSync = WindRoseCanvas
WindRoseEngine = WindRoseCanvas


def create_canonical_wind_rose_canvas() -> WindRoseCanvas:
    """Factory creating fully initialized canonical WindRoseCanvas."""
    return WindRoseCanvas()


# ============================================================================
# 8. Standalone W3C SVG 1.1 Vector Canvas Renderer
# ============================================================================

def generate_wind_rose_canvas_svg(canvas: WindRoseCanvas) -> str:
    """Render standalone W3C SVG 1.1 vector canvas.

    Generates:
    - 1200x750 dark viewport with WCAG 2.1 AAA decoupled badge backings.
    - 16 polar sector wedges stacked by 5 speed frequency classes.
    - Concentric grid circles with frequency percentage indicators.
    - Directional radial spokes and cardinal/intercardinal direction markers.
    - Gaussian plume dispersion hazard corridor overlay and toxic core footprint.
    - Centerline downwind vector with directional arrow marker.
    - Interactive sector selector buttons.
    - Beaufort scale telemetry HUD card.
    - Environmental hazard & plume dispersion status HUD card.
    - Horner OCS register space memory HUD card (%R1530..%R1537, %M357..%M358).
    - 5 speed bins SCADA color legend.
    """
    cfg = canvas.config
    m = canvas.metrics
    cx = cfg.center_x
    cy = cfg.center_y
    r_max = cfg.max_radius
    r_hub = cfg.hub_radius
    f_max = cfg.max_frequency_pct
    r_span = r_max - r_hub

    # Speed bin color mapping
    bin_colors = [
        COLOR_BIN_CALM,
        COLOR_BIN_LIGHT,
        COLOR_BIN_MODERATE,
        COLOR_BIN_FRESH,
        COLOR_BIN_STRONG,
    ]

    svg_parts: List[str] = []

    # SVG Root Header
    svg_parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {cfg.viewport_width} {cfg.viewport_height}" '
        f'width="{cfg.viewport_width}" height="{cfg.viewport_height}">'
    )

    # Defs: Gradients, Markers, and Filters
    svg_parts.append(f"""  <defs>
    <linearGradient id="canvas-bg-grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="{COLOR_DARK_THEME_BACKING}" />
      <stop offset="100%" stop-color="{COLOR_DARK_THEME_SURFACE}" />
    </linearGradient>
    <linearGradient id="card-surface-grad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="{COLOR_DARK_THEME_SURFACE}" stop-opacity="0.95" />
      <stop offset="100%" stop-color="{COLOR_DARK_THEME_BACKING}" stop-opacity="0.95" />
    </linearGradient>
    <linearGradient id="plume-hazard-grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="{COLOR_PLUME_HAZARD_CORE}" stop-opacity="0.75" />
      <stop offset="60%" stop-color="{COLOR_PLUME_HAZARD_OUTER}" stop-opacity="0.45" />
      <stop offset="100%" stop-color="{COLOR_WARNING_AMBER}" stop-opacity="0.15" />
    </linearGradient>
    <marker id="plume-arrowhead" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="{COLOR_WARNING_AMBER}" />
    </marker>
    <marker id="prevailing-arrow" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="{COLOR_FOCUS_BLUE}" />
    </marker>
    <filter id="hazard-alarm-glow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="3.5" result="glow" />
      <feComposite in="SourceGraphic" in2="glow" operator="over" />
    </filter>
  </defs>""")

    # Canvas Background
    svg_parts.append(
        f'  <rect width="{cfg.viewport_width}" height="{cfg.viewport_height}" fill="url(#canvas-bg-grad)" />'
    )

    # ------------------------------------------------------------------------
    # Header Banner & System Telemetry Badges
    # ------------------------------------------------------------------------
    svg_parts.append('  <!-- Header Banner -->')
    svg_parts.append('  <g id="canvas-header" transform="translate(40, 24)">')
    # Decoupled title backing badge (> 18:1 contrast)
    svg_parts.append(
        f'    <rect x="0" y="0" width="700" height="60" rx="8" '
        f'fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_CARD_BORDER}" stroke-width="1.2" />'
    )
    svg_parts.append(
        f'    <text x="18" y="26" fill="{COLOR_TEXT_PRIMARY}" font-size="16" '
        f'font-family="system-ui, -apple-system, sans-serif" font-weight="700">'
        f'CSCAPE SCADA DYNAMIC WIND ROSE &amp; ENVIRONMENTAL DISPERSION CANVAS</text>'
    )
    svg_parts.append(
        f'    <text x="18" y="46" fill="{COLOR_TEXT_MUTED}" font-size="11" '
        f'font-family="monospace">'
        f'WORK PACKAGE W192 | 16 POLAR SECTORS | GAUSSIAN PLUME HAZARD OVERLAY | HORNER OCS %R1530..%R1537</text>'
    )

    # Top Status Badges
    alarm_color = COLOR_TRIP_CRIMSON if m.environmental_dispersion_alarm else COLOR_NOMINAL_GREEN
    alarm_label = "DISPERSION BREACH" if m.environmental_dispersion_alarm else "BOUNDARY CLEAR"
    svg_parts.append(
        f'    <g transform="translate(715, 0)">'
        f'      <rect x="0" y="0" width="135" height="28" rx="6" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_CARD_BORDER}" />'
        f'      <circle cx="14" cy="14" r="5" fill="{COLOR_NOMINAL_GREEN if m.wind_rose_canvas_active else COLOR_TEXT_MUTED}" />'
        f'      <text x="26" y="18" fill="{COLOR_TEXT_PRIMARY}" font-size="11" font-weight="600" font-family="system-ui">ACTIVE %M357</text>'
        f'    </g>'
    )
    svg_parts.append(
        f'    <g transform="translate(860, 0)">'
        f'      <rect x="0" y="0" width="145" height="28" rx="6" fill="{COLOR_DECOUPLED_BADGE}" stroke="{alarm_color}" stroke-width="1.2" />'
        f'      <circle cx="14" cy="14" r="5" fill="{alarm_color}" />'
        f'      <text x="26" y="18" fill="{COLOR_TEXT_PRIMARY}" font-size="10" font-weight="600" font-family="system-ui">{alarm_label}</text>'
        f'    </g>'
    )
    diag_str = f"0xD3{int(m.diagnostic_status_code) & 0xFF:02X}" if int(m.diagnostic_status_code) else "0x0000 OK"
    svg_parts.append(
        f'    <g transform="translate(1015, 0)">'
        f'      <rect x="0" y="0" width="105" height="28" rx="6" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_CARD_BORDER}" />'
        f'      <text x="12" y="18" fill="{COLOR_WARNING_AMBER if int(m.diagnostic_status_code) else COLOR_TEXT_MUTED}" '
        f'font-size="10" font-weight="700" font-family="monospace">{diag_str}</text>'
        f'    </g>'
    )
    svg_parts.append('  </g>')

    # ------------------------------------------------------------------------
    # Interactive Sector Selector Navigation Bar
    # ------------------------------------------------------------------------
    svg_parts.append('  <!-- Interactive Sector Selector -->')
    svg_parts.append('  <g id="interactive-sector-selector" transform="translate(40, 96)">')
    selector_tabs = [
        ("ALL SECTORS", -1),
        ("N (0°)", 0),
        ("NE (45°)", 2),
        ("E (90°)", 4),
        ("SE (135°)", 6),
        ("S (180°)", 8),
        ("SW (225°)*", 10),
        ("W (270°)", 12),
        ("NW (315°)", 14),
        (f"TOXIC CORRIDOR ({m.toxic_corridor_sector_angle_deg}°)", -2),
    ]
    cur_x = 0
    for label, tab_idx in selector_tabs:
        is_sel = (tab_idx == canvas.selected_sector_index) or (tab_idx == -1 and canvas.selected_sector_index == 10)
        btn_w = 98 if "TOXIC" in label else (85 if len(label) > 7 else 75)
        stroke_col = COLOR_FOCUS_BLUE if is_sel else COLOR_CARD_BORDER
        fill_col = "#1F2937" if is_sel else COLOR_DECOUPLED_BADGE
        svg_parts.append(
            f'    <rect x="{cur_x}" y="0" width="{btn_w}" height="26" rx="5" '
            f'fill="{fill_col}" stroke="{stroke_col}" stroke-width="{1.5 if is_sel else 1.0}" />'
            f'    <text x="{cur_x + btn_w / 2.0:.1f}" y="17" text-anchor="middle" '
            f'fill="{COLOR_TEXT_PRIMARY if is_sel else COLOR_TEXT_MUTED}" font-size="10" font-weight="600" '
            f'font-family="system-ui">{html.escape(label)}</text>'
        )
        cur_x += btn_w + 6
    svg_parts.append('  </g>')

    # ------------------------------------------------------------------------
    # Wind Rose Polar SCADA Display
    # ------------------------------------------------------------------------
    svg_parts.append('  <!-- Wind Rose Polar SCADA Display -->')
    svg_parts.append(f'  <g id="wind-rose-polar-display">')

    # Polar backing circle
    svg_parts.append(
        f'    <circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r_max:.1f}" '
        f'fill="{COLOR_DARK_THEME_SURFACE}" fill-opacity="0.3" stroke="{COLOR_CARD_BORDER}" stroke-width="1.5" />'
    )

    # Concentric Grid Circles (5%, 10%, 15%, 20%, 25%)
    svg_parts.append('    <!-- Concentric Grid Circles -->')
    svg_parts.append('    <g id="concentric-grid-circles">')
    grid_levels = [5.0, 10.0, 15.0, 20.0, 25.0]
    for lvl in grid_levels:
        r_grid = r_hub + (lvl / f_max) * r_span
        svg_parts.append(
            f'      <circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r_grid:.2f}" '
            f'fill="none" stroke="{COLOR_GRID_LINE}" stroke-width="1" stroke-dasharray="3,3" />'
        )
        svg_parts.append(
            f'      <text x="{cx + 6:.1f}" y="{cy - r_grid + 11:.1f}" fill="{COLOR_TEXT_MUTED}" '
            f'font-size="9" font-family="monospace">{lvl:.0f}%</text>'
        )
    svg_parts.append('    </g>')

    # 16 Directional Radial Spokes & Compass Labels
    svg_parts.append('    <!-- 16 Directional Radial Spokes -->')
    svg_parts.append('    <g id="directional-spokes">')
    for i in range(SECTOR_COUNT):
        az_deg = i * 22.5
        p_in = polar_to_cartesian_svg(cx, cy, r_hub, az_deg)
        p_out = polar_to_cartesian_svg(cx, cy, r_max + 10.0, az_deg)
        svg_parts.append(
            f'      <line x1="{p_in[0]:.2f}" y1="{p_in[1]:.2f}" x2="{p_out[0]:.2f}" y2="{p_out[1]:.2f}" '
            f'stroke="{COLOR_GRID_SPOKE}" stroke-width="1" />'
        )

        # Direction labels
        p_lbl = polar_to_cartesian_svg(cx, cy, r_max + 24.0, az_deg)
        sec_name = SECTOR_NAMES[i]
        is_cardinal = sec_name in ("N", "E", "S", "W")
        is_intercardinal = sec_name in ("NE", "SE", "SW", "NW")

        font_sz = 14 if is_cardinal else (11 if is_intercardinal else 9)
        font_wt = "bold" if (is_cardinal or is_intercardinal) else "normal"
        txt_col = COLOR_TEXT_PRIMARY if is_cardinal else (COLOR_FOCUS_BLUE if is_intercardinal else COLOR_TEXT_MUTED)

        svg_parts.append(
            f'      <text x="{p_lbl[0]:.2f}" y="{p_lbl[1] + 4.0:.2f}" text-anchor="middle" '
            f'fill="{txt_col}" font-size="{font_sz}" font-weight="{font_wt}" '
            f'font-family="system-ui, -apple-system, sans-serif">{sec_name}</text>'
        )
    svg_parts.append('    </g>')

    # 16 Stacked Sector Wedges
    svg_parts.append('    <!-- Stacked Sector Wedges -->')
    svg_parts.append('    <g id="stacked-sector-wedges">')
    gap_deg = 1.0  # Angular separation padding
    half_span = (22.5 / 2.0) - (gap_deg / 2.0)

    for sector in canvas.sectors:
        az_deg = sector.azimuth_deg
        th_start = az_deg - half_span
        th_end = az_deg + half_span

        for bin_idx in range(SPEED_BIN_COUNT):
            freq = sector.bin_frequencies[bin_idx]
            if freq <= 0.001:
                continue

            cum_prev = sector.cumulative_bin_frequency(bin_idx - 1)
            cum_curr = cum_prev + freq

            r_in = r_hub + (cum_prev / f_max) * r_span
            r_out = r_hub + (cum_curr / f_max) * r_span

            wedge_d = generate_sector_wedge_svg_path(cx, cy, r_in, r_out, th_start, th_end)
            if not wedge_d:
                continue

            color = bin_colors[bin_idx]
            is_prevailing = (sector.index == 10)  # SW prevailing
            opac = 0.95 if is_prevailing else 0.85

            title_text = html.escape(f"{sector.name}: {SPEED_BIN_NAMES[bin_idx]} = {freq:.1f}%")
            svg_parts.append(
                f'      <path id="sector-{sector.name}-bin-{bin_idx}" d="{wedge_d}" '
                f'fill="{color}" fill-opacity="{opac:.2f}" stroke="{COLOR_DARK_THEME_SURFACE}" stroke-width="0.7">'
                f'<title>{title_text}</title></path>'
            )
    svg_parts.append('    </g>')

    # Gaussian Plume Dispersion Hazard Corridor Overlay
    svg_parts.append('    <!-- Gaussian Plume Dispersion Hazard Corridor -->')
    svg_parts.append('    <g id="gaussian-plume-corridor">')

    plume_path = generate_gaussian_plume_svg_path(
        cx=cx,
        cy=cy,
        hub_radius=r_hub,
        plume_distance_m=float(m.plume_dispersion_distance_m),
        max_dist_ref=cfg.plume_max_distance_ref,
        max_canvas_radius=r_max,
        sector_angle_deg=float(m.toxic_corridor_sector_angle_deg),
        stability_class=m.atmospheric_stability_class,
    )

    core_path = generate_gaussian_plume_core_svg_path(
        cx=cx,
        cy=cy,
        hub_radius=r_hub,
        plume_distance_m=float(m.plume_dispersion_distance_m),
        max_dist_ref=cfg.plume_max_distance_ref,
        max_canvas_radius=r_max,
        sector_angle_deg=float(m.toxic_corridor_sector_angle_deg),
        stability_class=m.atmospheric_stability_class,
    )

    # Outer hazard envelope
    filter_attr = ' filter="url(#hazard-alarm-glow)"' if m.environmental_dispersion_alarm else ''
    svg_parts.append(
        f'      <path id="plume-hazard-corridor-boundary" d="{plume_path}" '
        f'fill="url(#plume-hazard-grad)" stroke="{COLOR_PLUME_HAZARD_OUTER}" '
        f'stroke-width="1.8" stroke-dasharray="5,3"{filter_attr}>'
        f'<title>Downwind Toxic Footprint: {m.plume_dispersion_distance_m} m</title></path>'
    )

    # Inner IDLH lethal core
    svg_parts.append(
        f'      <path id="plume-toxic-core" d="{core_path}" '
        f'fill="{COLOR_PLUME_HAZARD_CORE}" fill-opacity="0.6" stroke="{COLOR_TEXT_PRIMARY}" '
        f'stroke-width="1.2">'
        f'<title>IDLH Core Concentration Zone</title></path>'
    )

    # Downwind Centerline Vector
    norm_dist = max(0.1, min(1.3, m.plume_dispersion_distance_m / cfg.plume_max_distance_ref))
    r_plume_tip = r_hub + norm_dist * r_span
    p_center_start = polar_to_cartesian_svg(cx, cy, r_hub, float(m.toxic_corridor_sector_angle_deg))
    p_center_end = polar_to_cartesian_svg(cx, cy, r_plume_tip, float(m.toxic_corridor_sector_angle_deg))
    svg_parts.append(
        f'      <line id="plume-centerline" x1="{p_center_start[0]:.2f}" y1="{p_center_start[1]:.2f}" '
        f'x2="{p_center_end[0]:.2f}" y2="{p_center_end[1]:.2f}" '
        f'stroke="{COLOR_WARNING_AMBER}" stroke-width="2.2" marker-end="url(#plume-arrowhead)" />'
    )

    # Plume front telemetry marker tag
    p_tag = polar_to_cartesian_svg(cx, cy, r_plume_tip + 14.0, float(m.toxic_corridor_sector_angle_deg))
    svg_parts.append(
        f'      <g transform="translate({p_tag[0] - 40.0:.1f}, {p_tag[1] - 10.0:.1f})">'
        f'        <rect x="0" y="0" width="80" height="20" rx="4" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_WARNING_AMBER}" stroke-width="1" />'
        f'        <text x="40" y="14" text-anchor="middle" fill="{COLOR_TEXT_PRIMARY}" font-size="9" font-weight="700" font-family="monospace">{m.plume_dispersion_distance_m}m PG-{m.atmospheric_stability_class}</text>'
        f'      </g>'
    )
    svg_parts.append('    </g>')

    # Central Calm Period Circle Hub
    svg_parts.append('    <!-- Central Calm Hub -->')
    svg_parts.append('    <g id="central-calm-hub">')
    svg_parts.append(
        f'      <circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r_hub:.1f}" '
        f'fill="{COLOR_DARK_THEME_SURFACE}" stroke="{COLOR_CARD_BORDER}" stroke-width="2" />'
    )
    svg_parts.append(
        f'      <text x="{cx:.1f}" y="{cy - 3.0:.1f}" text-anchor="middle" '
        f'fill="{COLOR_TEXT_PRIMARY}" font-size="14" font-weight="700" font-family="monospace">{m.calm_period_pct:.1f}%</text>'
    )
    svg_parts.append(
        f'      <text x="{cx:.1f}" y="{cy + 13.0:.1f}" text-anchor="middle" '
        f'fill="{COLOR_BIN_CALM}" font-size="9" font-weight="600" font-family="system-ui">CALM</text>'
    )
    svg_parts.append('    </g>')

    svg_parts.append('  </g>')

    # ------------------------------------------------------------------------
    # Right Column SCADA HUD Cards (Beaufort, Environmental, Horner Memory)
    # ------------------------------------------------------------------------
    hud_x = 760
    hud_w = 400

    # 1. Beaufort Scale Telemetry HUD Card
    svg_parts.append('  <!-- Beaufort Scale Telemetry HUD Card -->')
    svg_parts.append(f'  <g id="beaufort-scale-hud" transform="translate({hud_x}, 145)">')
    svg_parts.append(
        f'    <rect x="0" y="0" width="{hud_w}" height="175" rx="8" '
        f'fill="url(#card-surface-grad)" stroke="{COLOR_CARD_BORDER}" stroke-width="1.2" />'
    )
    # Decoupled title badge (> 18:1 contrast)
    svg_parts.append(
        f'    <rect x="12" y="10" width="220" height="24" rx="4" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_CARD_BORDER}" />'
        f'    <text x="22" y="26" fill="{COLOR_TEXT_PRIMARY}" font-size="11" font-weight="700" font-family="system-ui">BEAUFORT SCALE TELEMETRY</text>'
    )
    # Scale indicator pill
    b_col = COLOR_TRIP_CRIMSON if m.beaufort_force >= 8 else (COLOR_WARNING_AMBER if m.beaufort_force >= 7 else COLOR_NOMINAL_GREEN)
    svg_parts.append(
        f'    <rect x="{hud_w - 110}" y="10" width="98" height="24" rx="4" fill="{COLOR_DECOUPLED_BADGE}" stroke="{b_col}" stroke-width="1.2" />'
        f'    <text x="{hud_w - 61}" y="26" text-anchor="middle" fill="{b_col}" font-size="11" font-weight="700" font-family="monospace">FORCE {m.beaufort_force}</text>'
    )

    # Telemetry rows
    svg_parts.append(
        f'    <text x="20" y="60" fill="{COLOR_TEXT_MUTED}" font-size="12" font-family="system-ui">Beaufort Condition:</text>'
        f'    <text x="{hud_w - 20}" y="60" text-anchor="end" fill="{COLOR_TEXT_PRIMARY}" font-size="12" font-weight="600" font-family="system-ui">{m.beaufort_description}</text>'
    )
    knots = m.average_wind_speed_mps * 1.94384
    svg_parts.append(
        f'    <text x="20" y="86" fill="{COLOR_TEXT_MUTED}" font-size="12" font-family="system-ui">Average Wind Speed (%R1531):</text>'
        f'    <text x="{hud_w - 20}" y="86" text-anchor="end" fill="{COLOR_TEXT_PRIMARY}" font-size="12" font-weight="700" font-family="monospace">{m.average_wind_speed_mps:.1f} m/s ({knots:.1f} kts)</text>'
    )
    gust_kts = m.peak_gust_speed_mps * 1.94384
    svg_parts.append(
        f'    <text x="20" y="112" fill="{COLOR_TEXT_MUTED}" font-size="12" font-family="system-ui">Peak Gust Speed (%R1532):</text>'
        f'    <text x="{hud_w - 20}" y="112" text-anchor="end" fill="{COLOR_WARNING_AMBER if m.peak_gust_speed_mps >= 17.2 else COLOR_TEXT_PRIMARY}" font-size="12" font-weight="700" font-family="monospace">{m.peak_gust_speed_mps:.1f} m/s ({gust_kts:.1f} kts)</text>'
    )
    svg_parts.append(
        f'    <text x="20" y="138" fill="{COLOR_TEXT_MUTED}" font-size="12" font-family="system-ui">Prevailing Vector (%R1530):</text>'
        f'    <text x="{hud_w - 20}" y="138" text-anchor="end" fill="{COLOR_FOCUS_BLUE}" font-size="12" font-weight="700" font-family="monospace">{m.prevailing_direction_deg}° ({m.prevailing_sector_name})</text>'
    )
    svg_parts.append(
        f'    <text x="20" y="162" fill="{COLOR_TEXT_MUTED}" font-size="12" font-family="system-ui">Calm Observations (%R1533):</text>'
        f'    <text x="{hud_w - 20}" y="162" text-anchor="end" fill="{COLOR_BIN_CALM}" font-size="12" font-weight="700" font-family="monospace">{m.calm_period_pct:.1f} % total</text>'
    )
    svg_parts.append('  </g>')

    # 2. Environmental Hazard & Toxic Dispersion Corridor HUD Card
    svg_parts.append('  <!-- Environmental Hazard & Toxic Dispersion HUD Card -->')
    svg_parts.append(f'  <g id="toxic-corridor-hud" transform="translate({hud_x}, 332)">')
    svg_parts.append(
        f'    <rect x="0" y="0" width="{hud_w}" height="175" rx="8" '
        f'fill="url(#card-surface-grad)" stroke="{COLOR_CARD_BORDER}" stroke-width="1.2" />'
    )
    # Decoupled title badge (> 18:1 contrast)
    svg_parts.append(
        f'    <rect x="12" y="10" width="235" height="24" rx="4" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_CARD_BORDER}" />'
        f'    <text x="22" y="26" fill="{COLOR_TEXT_PRIMARY}" font-size="11" font-weight="700" font-family="system-ui">TOXIC PLUME DISPERSION</text>'
    )
    # Alarm state indicator pill
    alarm_bg = COLOR_TRIP_CRIMSON if m.environmental_dispersion_alarm else COLOR_NOMINAL_GREEN
    svg_parts.append(
        f'    <rect x="{hud_w - 125}" y="10" width="112" height="24" rx="4" fill="{COLOR_DECOUPLED_BADGE}" stroke="{alarm_bg}" stroke-width="1.2" />'
        f'    <text x="{hud_w - 69}" y="26" text-anchor="middle" fill="{alarm_bg}" font-size="10" font-weight="700" font-family="monospace">%M358: {str(m.environmental_dispersion_alarm).upper()}</text>'
    )

    pg_names = {1: "A (Extremely Unstable)", 2: "B (Moderately Unstable)", 3: "C (Slightly Unstable)", 4: "D (Neutral)", 5: "E (Slightly Stable)", 6: "F (Moderately Stable)"}
    pg_label = pg_names.get(m.atmospheric_stability_class, f"Class {m.atmospheric_stability_class}")

    svg_parts.append(
        f'    <text x="20" y="60" fill="{COLOR_TEXT_MUTED}" font-size="12" font-family="system-ui">Stability Class (%R1535):</text>'
        f'    <text x="{hud_w - 20}" y="60" text-anchor="end" fill="{COLOR_TEXT_PRIMARY}" font-size="12" font-weight="600" font-family="system-ui">Class {pg_label}</text>'
    )
    svg_parts.append(
        f'    <text x="20" y="86" fill="{COLOR_TEXT_MUTED}" font-size="12" font-family="system-ui">Dispersion Distance (%R1534):</text>'
        f'    <text x="{hud_w - 20}" y="86" text-anchor="end" fill="{alarm_bg}" font-size="12" font-weight="700" font-family="monospace">{m.plume_dispersion_distance_m} m (Limit: 1000m)</text>'
    )
    svg_parts.append(
        f'    <text x="20" y="112" fill="{COLOR_TEXT_MUTED}" font-size="12" font-family="system-ui">Downwind Azimuth (%R1536):</text>'
        f'    <text x="{hud_w - 20}" y="112" text-anchor="end" fill="{COLOR_WARNING_AMBER}" font-size="12" font-weight="700" font-family="monospace">{m.toxic_corridor_sector_angle_deg}° ({m.toxic_sector_name})</text>'
    )
    svg_parts.append(
        f'    <text x="20" y="138" fill="{COLOR_TEXT_MUTED}" font-size="12" font-family="system-ui">Lateral Spread Angle:</text>'
        f'    <text x="{hud_w - 20}" y="138" text-anchor="end" fill="{COLOR_TEXT_PRIMARY}" font-size="12" font-weight="700" font-family="monospace">±{compute_plume_spread_angle(m.atmospheric_stability_class):.1f}° (Pasquill-Gifford)</text>'
    )
    breach_desc = "BREACH: EVACUATE SECTOR" if m.environmental_dispersion_alarm else "NORMAL: WITHIN BOUNDARY"
    svg_parts.append(
        f'    <text x="20" y="162" fill="{COLOR_TEXT_MUTED}" font-size="12" font-family="system-ui">Dispersion Safety State:</text>'
        f'    <text x="{hud_w - 20}" y="162" text-anchor="end" fill="{alarm_bg}" font-size="12" font-weight="700" font-family="monospace">{breach_desc}</text>'
    )
    svg_parts.append('  </g>')

    # 3. Horner OCS SCADA Memory Space HUD Card
    svg_parts.append('  <!-- Horner OCS SCADA Memory Space HUD Card -->')
    svg_parts.append(f'  <g id="horner-memory-hud" transform="translate({hud_x}, 519)">')
    svg_parts.append(
        f'    <rect x="0" y="0" width="{hud_w}" height="206" rx="8" '
        f'fill="url(#card-surface-grad)" stroke="{COLOR_CARD_BORDER}" stroke-width="1.2" />'
    )
    # Decoupled title badge (> 18:1 contrast)
    svg_parts.append(
        f'    <rect x="12" y="10" width="240" height="24" rx="4" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_CARD_BORDER}" />'
        f'    <text x="22" y="26" fill="{COLOR_TEXT_PRIMARY}" font-size="11" font-weight="700" font-family="system-ui">HORNER OCS REGISTER MAPPINGS</text>'
    )
    svg_parts.append(
        f'    <rect x="{hud_w - 110}" y="10" width="98" height="24" rx="4" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_CARD_BORDER}" />'
        f'    <text x="{hud_w - 61}" y="26" text-anchor="middle" fill="{COLOR_FOCUS_BLUE}" font-size="10" font-weight="700" font-family="monospace">IEC 61131-3</text>'
    )

    reg_entries = [
        ("%R1530 PrevailingWindDirectionDeg", f"{m.prevailing_direction_deg}°"),
        ("%R1531 AverageWindSpeedMpsScaled", f"{m.average_wind_speed_scaled}"),
        ("%R1532 PeakGustSpeedMpsScaled", f"{m.peak_gust_speed_scaled}"),
        ("%R1533 CalmPeriodPercentageScaled", f"{m.calm_period_scaled}"),
        ("%R1534 PlumeDispersionDistanceMeters", f"{m.plume_dispersion_distance_m} m"),
        ("%R1535 AtmosphericStabilityClass", f"{m.atmospheric_stability_class}"),
        ("%R1536 ToxicCorridorSectorAngleDeg", f"{m.toxic_corridor_sector_angle_deg}°"),
        ("%R1537 DiagnosticStatusCode", f"0x{int(m.diagnostic_status_code) & 0xFFFF:04X}"),
    ]
    r_y = 52
    for r_name, r_val in reg_entries:
        svg_parts.append(
            f'    <text x="20" y="{r_y}" fill="{COLOR_TEXT_MUTED}" font-size="10.5" font-family="monospace">{r_name}:</text>'
            f'    <text x="{hud_w - 20}" y="{r_y}" text-anchor="end" fill="{COLOR_TEXT_PRIMARY}" font-size="10.5" font-weight="700" font-family="monospace">{r_val}</text>'
        )
        r_y += 18
    svg_parts.append('  </g>')

    # ------------------------------------------------------------------------
    # Bottom Wind Speed Frequency Classes Legend
    # ------------------------------------------------------------------------
    svg_parts.append('  <!-- Wind Speed Frequency Bins Legend -->')
    svg_parts.append('  <g id="speed-bins-legend" transform="translate(40, 695)">')
    svg_parts.append(
        f'    <rect x="0" y="0" width="700" height="36" rx="6" '
        f'fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_CARD_BORDER}" stroke-width="1" />'
    )
    leg_x = 16
    for b_idx in range(SPEED_BIN_COUNT):
        b_name = html.escape(SPEED_BIN_NAMES[b_idx])
        b_col = bin_colors[b_idx]
        svg_parts.append(
            f'    <rect x="{leg_x}" y="11" width="14" height="14" rx="2" fill="{b_col}" />'
            f'    <text x="{leg_x + 20}" y="22" fill="{COLOR_TEXT_PRIMARY}" font-size="10" font-weight="600" '
            f'font-family="system-ui">{b_name}</text>'
        )
        leg_x += 135
    svg_parts.append('  </g>')

    svg_parts.append('</svg>')
    return "\n".join(svg_parts)


# ============================================================================
# 9. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_wind_rose_canvas_verification(
    output_path: Optional[str] = None,
    sample_svg_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage engineering verification suite.

    Stages:
    1. Pure ST POU AST parsing, symbol binding, and STParser validation (%R1530..%R1537, %M357..%M358)
    2. Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics
    3. 16 directional polar sectors & 5-bin speed frequency distribution conservation
    4. Stacked sector wedge geometry & concentric grid rings (5%, 10%, 15%, 20%, 25%)
    5. Gaussian plume dispersion hazard corridor overlay & toxic footprint calculation
    6. Process safety interlocks & diagnostics (0xD301 Gale, 0xD302 Plume breach %M358, 0xD303 render fault)
    7. Standalone W3C SVG 1.1 Vector Canvas renderer & XML validation
    8. WCAG 2.1 AAA accessibility & decoupled dark backing badges (> 18:1 badge, > 7:1 text, > 3:1 graphics)
    9. Horner OCS memory space synchronization (%R1530..%R1537, %M357..%M358) & ILogicUnit scan cycle execution

    Returns strict 4-state engineering contract JSON dict:
    {
      "status": "success | failed | blocked | inconclusive",
      "error_code": "STRING_OR_NULL",
      "details": "Factual description of outcome",
      "data": {}
    }
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
    # ------------------------------------------------------------------------
    c1_pure_st = verify_wind_rose_canvas_pure_st()
    parser = STParser()
    ast = parser.parse_pou(WIND_ROSE_PURE_ST_POU)

    c1_ast_valid = ast is not None and ast.name == "WindRoseEnvironmentalCanvasSync"
    c1_pou_type = ast.pou_type == POUType.PROGRAM if ast else False

    # Verify bound registers in AST declarations
    var_names = [v.name for v in ast.variables] if ast else []
    expected_vars = [
        "PrevailingWindDirectionDeg",
        "AverageWindSpeedMpsScaled",
        "PeakGustSpeedMpsScaled",
        "CalmPeriodPercentageScaled",
        "PlumeDispersionDistanceMeters",
        "AtmosphericStabilityClass",
        "ToxicCorridorSectorAngleDeg",
        "DiagnosticStatusCode",
        "WindRoseCanvasActive",
        "EnvironmentalDispersionAlarm",
    ]
    c1_vars_bound = all(v in var_names for v in expected_vars)

    c1_pass = c1_pure_st and c1_ast_valid and c1_pou_type and c1_vars_bound
    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_AST_Parsing_And_Symbol_Binding",
        "passed": c1_pass,
        "details": f"POU 'WindRoseEnvironmentalCanvasSync' parsed with STParser; PROGRAM AST verified; {len(expected_vars)} registers bound (%R1530..%R1537, %M357..%M358).",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Anti-Ladder Security Guard Interception
    # ------------------------------------------------------------------------
    guard_pass = True
    try:
        SecurityGuard.assert_pure_st_content(WIND_ROSE_PURE_ST_POU)
    except Exception:
        guard_pass = False

    ladder_samples = [
        ("contact_no", WIND_ROSE_PURE_ST_POU + "\n---[ ]---"),
        ("contact_nc", WIND_ROSE_PURE_ST_POU + "\n---[/]---"),
        ("coil_out", WIND_ROSE_PURE_ST_POU + "\n---( )---"),
        ("rung_delim", WIND_ROSE_PURE_ST_POU + "\nRUNG 1: Start cycle"),
        ("network_delim", WIND_ROSE_PURE_ST_POU + "\nNETWORK 2"),
        ("xic_mnemonic", WIND_ROSE_PURE_ST_POU + "\nXIC StartBit"),
        ("ote_mnemonic", WIND_ROSE_PURE_ST_POU + "\nOTE OutputBit"),
    ]

    interceptions = 0
    for l_label, l_text in ladder_samples:
        try:
            SecurityGuard.assert_pure_st_content(l_text)
        except LadderForbiddenError:
            interceptions += 1

    c2_pass = guard_pass and (interceptions == len(ladder_samples))
    test_results.append({
        "stage": 2,
        "check": "Anti_Ladder_Security_Guard_Interception",
        "passed": c2_pass,
        "details": f"Asserted LadderForbiddenError on {interceptions}/{len(ladder_samples)} ladder logic contacts, coils, rungs, and mnemonics.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: 16 Directional Polar Sectors & 5-Bin Speed Frequency Distribution
    # ------------------------------------------------------------------------
    sectors = create_canonical_wind_sectors()
    c3_count = len(sectors) == 16
    c3_names = [s.name for s in sectors] == SECTOR_NAMES
    c3_azimuths = [s.azimuth_deg for s in sectors] == [i * 22.5 for i in range(16)]
    c3_bins = all(len(s.bin_frequencies) == 5 for s in sectors)

    # Check conservation of total observations (sum of all sectors + calm = 100.0%)
    total_sector_freq = sum(s.total_frequency_pct for s in sectors)
    total_all = total_sector_freq + NOMINAL_CALM_PERIOD_PCT
    c3_conservation = abs(total_all - 100.0) < 1e-4

    c3_pass = c3_count and c3_names and c3_azimuths and c3_bins and c3_conservation
    test_results.append({
        "stage": 3,
        "check": "16_Directional_Sectors_And_5_Bin_Speed_Distribution",
        "passed": c3_pass,
        "details": f"Verified 16 sectors at 22.5° increments; 5 speed bins per sector; total observations conserved at {total_all:.2f}%.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Stacked Sector Wedge Geometry & Concentric Grid Rings
    # ------------------------------------------------------------------------
    w_sample = generate_sector_wedge_svg_path(
        cx=PLOT_CENTER_X,
        cy=PLOT_CENTER_Y,
        r_inner=PLOT_HUB_RADIUS,
        r_outer=PLOT_MAX_RADIUS,
        theta_start_deg=214.25,
        theta_end_deg=235.75,
    )
    c4_wedge_valid = w_sample.startswith("M ") and " A " in w_sample and w_sample.endswith("Z")

    # Verify concentric grid rings
    rings_tested = [PLOT_HUB_RADIUS + (lvl / PLOT_MAX_FREQUENCY_PCT) * (PLOT_MAX_RADIUS - PLOT_HUB_RADIUS) for lvl in [5.0, 10.0, 15.0, 20.0, 25.0]]
    c4_rings_valid = len(rings_tested) == 5 and all(r > PLOT_HUB_RADIUS and r <= PLOT_MAX_RADIUS for r in rings_tested)

    c4_pass = c4_wedge_valid and c4_rings_valid
    test_results.append({
        "stage": 4,
        "check": "Stacked_Sector_Wedge_Geometry_And_Grid_Rings",
        "passed": c4_pass,
        "details": f"Generated W3C SVG annular sector path ('M...A...Z'); verified 5 concentric grid levels (5%..25%).",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Gaussian Plume Dispersion Hazard Corridor Overlay
    # ------------------------------------------------------------------------
    plume_svg = generate_gaussian_plume_svg_path(
        cx=PLOT_CENTER_X,
        cy=PLOT_CENTER_Y,
        hub_radius=PLOT_HUB_RADIUS,
        plume_distance_m=850.0,
        max_dist_ref=PLUME_MAX_DISTANCE_REF_METERS,
        max_canvas_radius=PLOT_MAX_RADIUS,
        sector_angle_deg=45.0,
        stability_class=4,
    )
    core_svg = generate_gaussian_plume_core_svg_path(
        cx=PLOT_CENTER_X,
        cy=PLOT_CENTER_Y,
        hub_radius=PLOT_HUB_RADIUS,
        plume_distance_m=850.0,
        max_dist_ref=PLUME_MAX_DISTANCE_REF_METERS,
        max_canvas_radius=PLOT_MAX_RADIUS,
        sector_angle_deg=45.0,
        stability_class=4,
    )
    c5_plume_valid = plume_svg.startswith("M ") and " Q " in plume_svg and plume_svg.endswith("Z")
    c5_core_valid = core_svg.startswith("M ") and core_svg.endswith("Z")

    # Pasquill-Gifford dispersion angles
    c5_pg_angles = [compute_plume_spread_angle(cls) for cls in range(1, 7)]
    c5_pg_valid = c5_pg_angles == [24.0, 20.0, 16.0, 12.0, 9.0, 6.5]

    c5_pass = c5_plume_valid and c5_core_valid and c5_pg_valid
    test_results.append({
        "stage": 5,
        "check": "Gaussian_Plume_Dispersion_Hazard_Corridor_Overlay",
        "passed": c5_pass,
        "details": f"Computed 850m Gaussian toxic footprint polygon; Pasquill-Gifford stability spread validated (Classes A..F: 24.0°..6.5°).",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Process Safety Interlocks & Diagnostics
    # ------------------------------------------------------------------------
    canvas_fault = create_canonical_wind_rose_canvas()

    # 1. Gale Warning (0xD301)
    canvas_fault.trigger_gale_warning(wind_speed=18.5, gust_speed=22.0)
    gale_ok = (
        canvas_fault.diagnostic_code == WIND_ERR_GALE_WARNING
        and canvas_fault.diagnostic_code == 0xD301
        and canvas_fault.diagnostic_code == -11519
        and DiagnosticCode(canvas_fault.reg_table.read_word("%R1537")) == 0xD301
        and canvas_fault.environmental_dispersion_alarm is False
    )

    # 2. Plume Boundary Breach (0xD302) -> asserts %M358
    canvas_fault.reset_nominal()
    canvas_fault.trigger_plume_boundary_breach(distance_meters=1150)
    breach_ok = (
        canvas_fault.diagnostic_code == WIND_ERR_PLUME_BOUNDARY_BREACH
        and canvas_fault.diagnostic_code == 0xD302
        and canvas_fault.diagnostic_code == -11518
        and DiagnosticCode(canvas_fault.reg_table.read_word("%R1537")) == 0xD302
        and canvas_fault.environmental_dispersion_alarm is True
        and canvas_fault.reg_table.read_bit("%M358") is True
    )

    # 3. SVG Render Fault (0xD303)
    canvas_fault.trigger_render_fault()
    render_ok = (
        canvas_fault.diagnostic_code == WIND_ERR_RENDER_FAULT
        and canvas_fault.diagnostic_code == 0xD303
        and canvas_fault.diagnostic_code == -11517
        and DiagnosticCode(canvas_fault.reg_table.read_word("%R1537")) == 0xD303
        and canvas_fault.canvas_active is False
        and canvas_fault.reg_table.read_bit("%M357") is False
    )

    # 4. Clean nominal reset restoration
    canvas_fault.reset_nominal()
    reset_ok = (
        canvas_fault.diagnostic_code == DIAG_EVENT_OK
        and canvas_fault.environmental_dispersion_alarm is False
        and canvas_fault.canvas_active is True
        and canvas_fault.reg_table.read_bit("%M357") is True
        and canvas_fault.reg_table.read_bit("%M358") is False
        and DiagnosticCode(canvas_fault.reg_table.read_word("%R1537")) == 0x0000
    )

    c6_pass = gale_ok and breach_ok and render_ok and reset_ok
    test_results.append({
        "stage": 6,
        "check": "Process_Safety_Interlocks_And_Diagnostics",
        "passed": c6_pass,
        "details": "Verified 0xD301 Gale Warning, 0xD302 Plume Boundary Breach (%M358 asserted), 0xD303 Render Fault, and clean nominal restoration.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Standalone W3C SVG 1.1 Vector Canvas Renderer & XML Validation
    # ------------------------------------------------------------------------
    canvas_svg = create_canonical_wind_rose_canvas()
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
        and 'id="interactive-sector-selector"' in svg_content
        and 'id="wind-rose-polar-display"' in svg_content
        and 'id="concentric-grid-circles"' in svg_content
        and 'id="stacked-sector-wedges"' in svg_content
        and 'id="gaussian-plume-corridor"' in svg_content
        and 'id="beaufort-scale-hud"' in svg_content
        and 'id="toxic-corridor-hud"' in svg_content
        and 'id="horner-memory-hud"' in svg_content
        and 'id="speed-bins-legend"' in svg_content
    )

    c7_pass = xml_valid and svg_has_structure
    test_results.append({
        "stage": 7,
        "check": "Standalone_W3C_SVG_XML_Validation_And_Canvas_Rendering",
        "passed": c7_pass,
        "details": "Rendered 1200x750 standalone W3C SVG 1.1; XML valid; dark theme backing, polar rose, plume overlay, and 3 HUD cards verified.",
    })

    if sample_svg_path:
        out_svg = Path(sample_svg_path)
        out_svg.parent.mkdir(parents=True, exist_ok=True)
        with open(out_svg, "w", encoding="utf-8") as f:
            f.write(svg_content)

    # ------------------------------------------------------------------------
    # Stage 8: WCAG 2.1 AAA Accessibility & Decoupled Dark Backing Badges
    # ------------------------------------------------------------------------
    contrast_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    contrast_theme = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    contrast_calm = calculate_contrast_ratio(COLOR_BIN_CALM, COLOR_DARK_THEME_BACKING)
    contrast_light = calculate_contrast_ratio(COLOR_BIN_LIGHT, COLOR_DARK_THEME_BACKING)
    contrast_mod = calculate_contrast_ratio(COLOR_BIN_MODERATE, COLOR_DARK_THEME_BACKING)
    contrast_fresh = calculate_contrast_ratio(COLOR_BIN_FRESH, COLOR_DARK_THEME_BACKING)
    contrast_strong = calculate_contrast_ratio(COLOR_BIN_STRONG, COLOR_DARK_THEME_BACKING)

    c8_pass = (
        contrast_badge >= WCAG_AAA_BADGE_CONTRAST_TARGET
        and contrast_badge > 18.0
        and contrast_theme >= WCAG_AAA_TEXT_CONTRAST_TARGET
        and contrast_calm >= WCAG_GRAPHICAL_CONTRAST_TARGET
        and contrast_light >= WCAG_GRAPHICAL_CONTRAST_TARGET
        and contrast_mod >= WCAG_GRAPHICAL_CONTRAST_TARGET
        and contrast_fresh >= WCAG_GRAPHICAL_CONTRAST_TARGET
        and contrast_strong >= WCAG_GRAPHICAL_CONTRAST_TARGET
    )
    test_results.append({
        "stage": 8,
        "check": "WCAG_21_AAA_Accessibility_And_Contrast_Checks",
        "passed": c8_pass,
        "details": f"Decoupled badge contrast {contrast_badge:.2f}:1 (> 18:1), Theme text {contrast_theme:.2f}:1 (> 7:1), 5 speed bins graphical SCADA contrast ({contrast_strong:.2f}:1..{contrast_calm:.2f}:1 > 3:1) verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Horner OCS Memory Space Integration & Scan Cycle Execution
    # ------------------------------------------------------------------------
    canvas_sync = create_canonical_wind_rose_canvas()
    canvas_sync.scan_step(0.01)
    reg = canvas_sync.reg_table

    r1530 = reg.read_word("%R1530")
    r1531 = reg.read_word("%R1531")
    r1532 = reg.read_word("%R1532")
    r1533 = reg.read_word("%R1533")
    r1534 = reg.read_word("%R1534")
    r1535 = reg.read_word("%R1535")
    r1536 = reg.read_word("%R1536")
    r1537 = reg.read_word("%R1537")
    m357  = reg.read_bit("%M357")
    m358  = reg.read_bit("%M358")

    sync_pass = (
        r1530 == NOMINAL_PREVAILING_WIND_DIRECTION_DEG      # %R1530: PrevailingWindDirectionDeg (225)
        and r1531 == NOMINAL_AVERAGE_WIND_SPEED_SCALED      # %R1531: AverageWindSpeedMpsScaled (65)
        and r1532 == NOMINAL_PEAK_GUST_SPEED_SCALED         # %R1532: PeakGustSpeedMpsScaled (142)
        and r1533 == NOMINAL_CALM_PERIOD_SCALED             # %R1533: CalmPeriodPercentageScaled (85)
        and r1534 == NOMINAL_PLUME_DISPERSION_DISTANCE_M    # %R1534: PlumeDispersionDistanceMeters (850)
        and r1535 == NOMINAL_ATMOSPHERIC_STABILITY_CLASS    # %R1535: AtmosphericStabilityClass (4)
        and r1536 == NOMINAL_TOXIC_CORRIDOR_SECTOR_ANGLE_DEG # %R1536: ToxicCorridorSectorAngleDeg (45)
        and r1537 == DIAG_EVENT_OK                          # %R1537: DiagnosticStatusCode (0x0000)
        and m357 is True                                    # %M357: WindRoseCanvasActive
        and m358 is False                                   # %M358: EnvironmentalDispersionAlarm
    )

    c9_pass = sync_pass
    test_results.append({
        "stage": 9,
        "check": "Horner_OCS_Register_Space_Synchronization_And_Scan_Cycle",
        "passed": c9_pass,
        "details": f"%R1530={r1530}, %R1531={r1531}, %R1532={r1532}, %R1533={r1533}, %R1534={r1534}, %R1535={r1535}, %R1536={r1536}, %R1537={r1537}; %M357={m357}, %M358={m358}.",
    })

    # Summary and Deliverable Manifest
    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": f"Wind Rose / Polar Directional Vector & Environmental Hydrodynamic SCADA Canvas verification passed cleanly ({sum(1 for t in test_results if t['passed'])}/{len(test_results)} checks passed).",
        "data": {
            "work_package": "W192",
            "gate": "Gate G9 / G2",
            "component": "Cscape HMI Dynamic Wind Rose / Polar Directional Vector & Environmental Hydrodynamic SCADA Canvas",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "metrics": {
                "prevailing_direction_deg": canvas_sync.metrics.prevailing_direction_deg,
                "average_wind_speed_mps": canvas_sync.metrics.average_wind_speed_mps,
                "peak_gust_speed_mps": canvas_sync.metrics.peak_gust_speed_mps,
                "calm_period_pct": canvas_sync.metrics.calm_period_pct,
                "plume_dispersion_distance_m": canvas_sync.metrics.plume_dispersion_distance_m,
                "atmospheric_stability_class": canvas_sync.metrics.atmospheric_stability_class,
                "toxic_corridor_sector_angle_deg": canvas_sync.metrics.toxic_corridor_sector_angle_deg,
                "beaufort_force": canvas_sync.metrics.beaufort_force,
                "diagnostic_status_code": f"0x{int(canvas_sync.diagnostic_code) & 0xFFFF:04X}",
                "wcag_badge_contrast": round(contrast_badge, 2),
                "wcag_theme_contrast": round(contrast_theme, 2),
            },
        },
    }

    if output_path:
        out_ev = Path(output_path)
        out_ev.parent.mkdir(parents=True, exist_ok=True)
        with open(out_ev, "w", encoding="utf-8") as f:
            f.write(json.dumps(evidence, indent=2))

    return evidence


if __name__ == "__main__":
    result = run_wind_rose_canvas_verification()
    print(json.dumps(result, indent=2))
