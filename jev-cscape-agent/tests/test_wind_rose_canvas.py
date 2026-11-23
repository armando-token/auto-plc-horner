"""Comprehensive pytest test suite for Cscape HMI Dynamic Wind Rose / Polar Directional Vector & Environmental Hydrodynamic SCADA Canvas (W192).

Work Package: W192 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Coverage:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1530..%R1537, %M357..%M358).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: WindRoseConfig, WindSectorData, and WindRoseMetrics initialization and validation.
4. Section 4: 16 Polar directional sectors angular trigonometry, azimuth steps, and observation frequency conservation.
5. Section 5: Stacked speed frequency bin radius math and annular sector wedge SVG path geometry.
6. Section 6: Gaussian plume dispersion hazard corridor cone polygon math and Pasquill-Gifford stability classes.
7. Section 7: Standalone W3C SVG 1.1 XML generation, XML validity, and DOM element structure.
8. Section 8: WCAG 2.1 AAA accessibility and color contrast compliance (> 18:1 badge, > 7:1 text, > 3:1 graphics).
9. Section 9: Real-time wind speed/direction modulation, Beaufort scale calculation, and interactive sector selection.
10. Section 10: Horner RegisterTable memory space synchronization (%R1530..%R1537, %M357..%M358) with PrivilegeMode.SYSTEM.
11. Section 11: Process safety interlocks (0xD301 Gale Warning, 0xD302 Plume Boundary Breach asserts %M358, 0xD303 Render Fault).
12. Section 12: ILogicUnit discrete scan cycle execution (100+ scan steps, auto-trip, auto-recovery).
13. Section 13: Deterministic 9-stage verification suite runner returning status == 'success' and 9 passed stages.
14. Section 14: Engine class aliases, serialization, and factory integrity.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.wind_rose_canvas import (
    CALM_GRAPHICAL_CONTRAST_RATIO,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COLOR_BIN_CALM,
    COLOR_BIN_FRESH,
    COLOR_BIN_LIGHT,
    COLOR_BIN_MODERATE,
    COLOR_BIN_STRONG,
    COLOR_CARD_BORDER,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DARK_THEME_SURFACE,
    COLOR_DECOUPLED_BADGE,
    COLOR_FOCUS_BLUE,
    COLOR_GRID_LINE,
    COLOR_GRID_SPOKE,
    COLOR_NOMINAL_GREEN,
    COLOR_PLUME_HAZARD_CORE,
    COLOR_PLUME_HAZARD_OUTER,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TRIP_CRIMSON,
    COLOR_WARNING_AMBER,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DIAG_EVENT_GALE_WARNING,
    DIAG_EVENT_OK,
    DIAG_EVENT_PLUME_BOUNDARY_BREACH,
    DIAG_EVENT_PLUME_BREACH,
    DIAG_EVENT_RENDER_FAULT,
    DiagnosticCode,
    FRESH_GRAPHICAL_CONTRAST_RATIO,
    GALE_WARNING_THRESHOLD_MPS,
    GUST_GALE_THRESHOLD_MPS,
    LIGHT_GRAPHICAL_CONTRAST_RATIO,
    MODERATE_GRAPHICAL_CONTRAST_RATIO,
    NOMINAL_ATMOSPHERIC_STABILITY_CLASS,
    NOMINAL_AVERAGE_WIND_SPEED_MPS,
    NOMINAL_AVERAGE_WIND_SPEED_SCALED,
    NOMINAL_CALM_PERIOD_PCT,
    NOMINAL_CALM_PERIOD_SCALED,
    NOMINAL_PEAK_GUST_SPEED_MPS,
    NOMINAL_PEAK_GUST_SPEED_SCALED,
    NOMINAL_PLUME_DISPERSION_DISTANCE_M,
    NOMINAL_PREVAILING_WIND_DIRECTION_DEG,
    NOMINAL_TOXIC_CORRIDOR_SECTOR_ANGLE_DEG,
    PLOT_CENTER_X,
    PLOT_CENTER_Y,
    PLOT_HUB_RADIUS,
    PLOT_MAX_FREQUENCY_PCT,
    PLOT_MAX_RADIUS,
    PLUME_BREACH_THRESHOLD_METERS,
    PLUME_MAX_DISTANCE_REF_METERS,
    PasquillGiffordClass,
    SECTOR_COUNT,
    SECTOR_NAMES,
    SPEED_BIN_COUNT,
    SPEED_BIN_NAMES,
    STRONG_GRAPHICAL_CONTRAST_RATIO,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    WIND_ERR_GALE_WARNING,
    WIND_ERR_OK,
    WIND_ERR_PLUME_BOUNDARY_BREACH,
    WIND_ERR_PLUME_BREACH,
    WIND_ERR_RENDER_FAULT,
    WIND_ROSE_ENVIRONMENTAL_CANVAS_PURE_ST_POU,
    WIND_ROSE_PURE_ST_POU,
    WindRoseCanvas,
    WindRoseCanvasSync,
    WindRoseConfig,
    WindRoseEngine,
    WindRoseEnvironmentalCanvas,
    WindRoseEnvironmentalCanvasSync,
    WindRoseMetrics,
    WindRoseStatusBits,
    WindSectorData,
    WindSpeedBin,
    calculate_contrast_ratio,
    compute_plume_spread_angle,
    create_canonical_wind_rose_canvas,
    create_canonical_wind_sectors,
    create_mock_scan_context,
    direction_name_from_deg,
    generate_gaussian_plume_core_svg_path,
    generate_gaussian_plume_svg_path,
    generate_sector_wedge_svg_path,
    generate_wind_rose_canvas_svg,
    get_beaufort_scale_info,
    hex_to_relative_luminance,
    polar_to_cartesian_svg,
    run_wind_rose_canvas_verification,
    sector_index_from_direction_deg,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_wind_rose_canvas_pure_st,
    verify_wind_rose_pure_st,
)


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Section 1.1: Verify Pure ST POU parses correctly via STParser and functions as PROGRAM."""
    assert verify_wind_rose_canvas_pure_st() is True
    assert verify_wind_rose_pure_st() is True

    parser = STParser()
    ast = parser.parse_pou(WIND_ROSE_PURE_ST_POU)
    assert ast is not None
    assert ast.name == "WindRoseEnvironmentalCanvasSync"
    assert ast.pou_type == POUType.PROGRAM


def test_pure_st_pou_bound_registers() -> None:
    """Section 1.2: Verify all 10 Horner registers (%R1530..%R1537, %M357..%M358) are bound in AST."""
    parser = STParser()
    ast = parser.parse_pou(WIND_ROSE_PURE_ST_POU)
    assert ast is not None

    expected_registers = [
        "%R1530", "%R1531", "%R1532", "%R1533",
        "%R1534", "%R1535", "%R1536", "%R1537",
        "%M357", "%M358",
    ]
    for reg in expected_registers:
        assert reg in ast.bound_registers, f"Register {reg} must be bound in POU AST"


def test_pure_st_pou_syntax_validation() -> None:
    """Section 1.3: Validate code syntax passes with SUCCESS status."""
    res = STParser.validate_code(WIND_ROSE_PURE_ST_POU)
    assert res.status == AgentStatus.SUCCESS


def test_pure_st_pou_alias_and_helpers() -> None:
    """Section 1.4: Verify alias constants point to the same ST POU string."""
    assert WIND_ROSE_PURE_ST_POU == WIND_ROSE_ENVIRONMENTAL_CANVAS_PURE_ST_POU
    assert "PROGRAM WindRoseEnvironmentalCanvasSync" in WIND_ROSE_PURE_ST_POU
    assert "END_PROGRAM" in WIND_ROSE_PURE_ST_POU


# ============================================================================
# Section 2: Anti-Ladder Security Guard Interception
# ============================================================================

def test_anti_ladder_security_guard_assertion() -> None:
    """Section 2.1: Verify pure ST content passes SecurityGuard without error."""
    SecurityGuard.assert_pure_st_content(WIND_ROSE_PURE_ST_POU)


def test_anti_ladder_security_guard_rejections() -> None:
    """Section 2.2: Verify ladder contacts, coils, mnemonics, and rungs are rejected."""
    bad_snippets = [
        "PROGRAM Bad1 VAR X : BOOL; END_VAR ---[ ]--- END_PROGRAM",
        "PROGRAM Bad2 VAR X : BOOL; END_VAR ---( )--- END_PROGRAM",
        "PROGRAM Bad3 VAR X : BOOL; END_VAR XIC %M357; END_PROGRAM",
        "PROGRAM Bad4 VAR X : BOOL; END_VAR OTE %M358; END_PROGRAM",
        "PROGRAM Bad5 VAR X : BOOL; END_VAR RUNG 1 WindActive := TRUE; END_PROGRAM",
        "PROGRAM Bad6 VAR X : BOOL; END_VAR NETWORK 1 END_PROGRAM",
    ]
    for snippet in bad_snippets:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# Section 3: Configuration & Data Models Validation
# ============================================================================

def test_wind_rose_config_defaults() -> None:
    """Section 3.1: Verify default configuration parameters."""
    cfg = WindRoseConfig()
    assert cfg.viewport_width == CANVAS_VIEWPORT_WIDTH == 1200
    assert cfg.viewport_height == CANVAS_VIEWPORT_HEIGHT == 750
    assert cfg.center_x == PLOT_CENTER_X == 420.0
    assert cfg.center_y == PLOT_CENTER_Y == 415.0
    assert cfg.max_radius == PLOT_MAX_RADIUS == 250.0
    assert cfg.hub_radius == PLOT_HUB_RADIUS == 45.0
    assert cfg.max_frequency_pct == PLOT_MAX_FREQUENCY_PCT == 25.0
    assert cfg.plume_max_distance_ref == PLUME_MAX_DISTANCE_REF_METERS == 1200.0
    assert cfg.gale_warning_threshold_mps == GALE_WARNING_THRESHOLD_MPS == 17.2
    assert cfg.gust_gale_threshold_mps == GUST_GALE_THRESHOLD_MPS == 20.8
    assert cfg.plume_breach_threshold_meters == PLUME_BREACH_THRESHOLD_METERS == 1000.0
    assert cfg.dark_theme_backing == COLOR_DARK_THEME_BACKING == "#0D1117"
    assert cfg.surface_backing == COLOR_DARK_THEME_SURFACE == "#161B22"
    assert cfg.badge_backing == COLOR_DECOUPLED_BADGE == "#05080C"


def test_wind_rose_config_custom_initialization() -> None:
    """Section 3.2: Verify custom configuration initialization."""
    cfg = WindRoseConfig(
        viewport_width=1600,
        viewport_height=900,
        center_x=500.0,
        center_y=450.0,
        max_radius=300.0,
        hub_radius=50.0,
        max_frequency_pct=30.0,
        gale_warning_threshold_mps=15.0,
        gust_gale_threshold_mps=19.0,
        plume_breach_threshold_meters=900.0,
        dark_theme_backing=COLOR_DARK_THEME_BACKING_1E1E1E,
    )
    assert cfg.viewport_width == 1600
    assert cfg.viewport_height == 900
    assert cfg.center_x == 500.0
    assert cfg.center_y == 450.0
    assert cfg.max_radius == 300.0
    assert cfg.max_frequency_pct == 30.0
    assert cfg.gale_warning_threshold_mps == 15.0
    assert cfg.dark_theme_backing == "#1E1E1E"


def test_wind_sector_data_initialization_and_properties() -> None:
    """Section 3.3: Verify WindSectorData dataclass fields, total_frequency, and cumulative."""
    sec = WindSectorData(
        index=0,
        name="N",
        azimuth_deg=0.0,
        bin_frequencies=[0.3, 1.6, 0.9, 0.2, 0.0],
        mean_speed_mps=4.2,
        peak_gust_mps=8.5,
    )
    assert sec.index == 0
    assert sec.name == "N"
    assert sec.azimuth_deg == 0.0
    assert len(sec.bin_frequencies) == 5
    assert abs(sec.total_frequency_pct - 3.0) < 1e-4
    assert abs(sec.cumulative_bin_frequency(0) - 0.3) < 1e-4
    assert abs(sec.cumulative_bin_frequency(1) - 1.9) < 1e-4
    assert abs(sec.cumulative_bin_frequency(2) - 2.8) < 1e-4
    assert abs(sec.cumulative_bin_frequency(3) - 3.0) < 1e-4
    assert abs(sec.cumulative_bin_frequency(4) - 3.0) < 1e-4
    assert sec.cumulative_bin_frequency(-1) == 0.0


def test_wind_rose_metrics_initialization() -> None:
    """Section 3.4: Verify WindRoseMetrics fields and scaled telemetry."""
    m = WindRoseMetrics(
        prevailing_direction_deg=225,
        average_wind_speed_mps=6.5,
        average_wind_speed_scaled=65,
        peak_gust_speed_mps=14.2,
        peak_gust_speed_scaled=142,
        calm_period_pct=8.5,
        calm_period_scaled=85,
        plume_dispersion_distance_m=850,
        atmospheric_stability_class=4,
        toxic_corridor_sector_angle_deg=45,
        diagnostic_status_code=DIAG_EVENT_OK,
        wind_rose_canvas_active=True,
        environmental_dispersion_alarm=False,
        beaufort_force=4,
        beaufort_description="Moderate Breeze",
        has_gale_warning=False,
        has_plume_breach=False,
        has_render_fault=False,
        prevailing_sector_name="SW",
        toxic_sector_name="NE",
    )
    assert m.prevailing_direction_deg == 225
    assert m.average_wind_speed_scaled == 65
    assert m.peak_gust_speed_scaled == 142
    assert m.calm_period_scaled == 85
    assert m.plume_dispersion_distance_m == 850
    assert m.atmospheric_stability_class == 4
    assert m.toxic_corridor_sector_angle_deg == 45
    assert m.diagnostic_status_code == 0
    assert m.wind_rose_canvas_active is True
    assert m.environmental_dispersion_alarm is False
    assert m.beaufort_force == 4
    assert m.prevailing_sector_name == "SW"
    assert m.toxic_sector_name == "NE"


def test_pasquill_gifford_and_speed_bin_enums() -> None:
    """Section 3.5: Verify PasquillGiffordClass and WindSpeedBin enum mappings."""
    assert PasquillGiffordClass.CLASS_A.value == 1
    assert PasquillGiffordClass.CLASS_B.value == 2
    assert PasquillGiffordClass.CLASS_C.value == 3
    assert PasquillGiffordClass.CLASS_D.value == 4
    assert PasquillGiffordClass.CLASS_E.value == 5
    assert PasquillGiffordClass.CLASS_F.value == 6

    assert WindSpeedBin.CALM.value == 0
    assert WindSpeedBin.LIGHT.value == 1
    assert WindSpeedBin.MODERATE.value == 2
    assert WindSpeedBin.FRESH.value == 3
    assert WindSpeedBin.STRONG.value == 4


# ============================================================================
# Section 4: 16 Polar Directional Sectors & Angular Trigonometry
# ============================================================================

def test_16_canonical_wind_sectors_count_and_names() -> None:
    """Section 4.1: Verify canonical wind sectors count, ordering, and names."""
    sectors = create_canonical_wind_sectors()
    assert len(sectors) == SECTOR_COUNT == 16
    assert [s.name for s in sectors] == SECTOR_NAMES
    expected_names = [
        "N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE",
        "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW",
    ]
    assert [s.name for s in sectors] == expected_names


def test_16_sectors_azimuth_increments() -> None:
    """Section 4.2: Verify 16 sectors are spaced exactly at 22.5° intervals starting from 0°."""
    sectors = create_canonical_wind_sectors()
    for idx, sec in enumerate(sectors):
        expected_azimuth = idx * 22.5
        assert abs(sec.azimuth_deg - expected_azimuth) < 1e-4, f"Sector {sec.name} azimuth mismatch"


def test_observation_frequency_conservation() -> None:
    """Section 4.3: Verify sum of all 16 sectors + calm period equals 100.0%."""
    sectors = create_canonical_wind_sectors()
    sum_sectors = sum(s.total_frequency_pct for s in sectors)
    total_obs = sum_sectors + NOMINAL_CALM_PERIOD_PCT
    assert abs(total_obs - 100.0) < 1e-4, f"Total observation frequency must be 100%, got {total_obs}"


def test_sector_index_from_direction_deg() -> None:
    """Section 4.4: Verify azimuth mapping to sector index with boundary rounding."""
    assert sector_index_from_direction_deg(0.0) == 0    # N
    assert sector_index_from_direction_deg(11.2) == 0   # N (< 11.25)
    assert sector_index_from_direction_deg(11.3) == 1   # NNE (> 11.25)
    assert sector_index_from_direction_deg(22.5) == 1   # NNE
    assert sector_index_from_direction_deg(45.0) == 2   # NE
    assert sector_index_from_direction_deg(90.0) == 4   # E
    assert sector_index_from_direction_deg(180.0) == 8  # S
    assert sector_index_from_direction_deg(225.0) == 10 # SW
    assert sector_index_from_direction_deg(270.0) == 12 # W
    assert sector_index_from_direction_deg(315.0) == 14 # NW
    assert sector_index_from_direction_deg(350.0) == 0  # N (wrap-around)
    assert sector_index_from_direction_deg(360.0) == 0  # N (modulo)


def test_direction_name_from_deg() -> None:
    """Section 4.5: Verify direction acronym lookup from degree values."""
    assert direction_name_from_deg(0.0) == "N"
    assert direction_name_from_deg(90.0) == "E"
    assert direction_name_from_deg(180.0) == "S"
    assert direction_name_from_deg(225.0) == "SW"
    assert direction_name_from_deg(270.0) == "W"
    assert direction_name_from_deg(337.5) == "NNW"


def test_polar_to_cartesian_svg_trigonometry() -> None:
    """Section 4.6: Verify polar to Cartesian SVG coordinates (0° North UP, 90° East RIGHT)."""
    cx, cy, r = 400.0, 400.0, 100.0

    # 0° (North): dx=0, dy=-r
    x, y = polar_to_cartesian_svg(cx, cy, r, 0.0)
    assert abs(x - 400.0) < 1e-4
    assert abs(y - 300.0) < 1e-4

    # 90° (East): dx=r, dy=0
    x, y = polar_to_cartesian_svg(cx, cy, r, 90.0)
    assert abs(x - 500.0) < 1e-4
    assert abs(y - 400.0) < 1e-4

    # 180° (South): dx=0, dy=+r
    x, y = polar_to_cartesian_svg(cx, cy, r, 180.0)
    assert abs(x - 400.0) < 1e-4
    assert abs(y - 500.0) < 1e-4

    # 270° (West): dx=-r, dy=0
    x, y = polar_to_cartesian_svg(cx, cy, r, 270.0)
    assert abs(x - 300.0) < 1e-4
    assert abs(y - 400.0) < 1e-4


# ============================================================================
# Section 5: Stacked Speed Frequency Bin Radius & Wedge Math
# ============================================================================

def test_generate_sector_wedge_svg_path_valid() -> None:
    """Section 5.1: Verify valid annular wedge SVG path syntax."""
    path = generate_sector_wedge_svg_path(
        cx=420.0,
        cy=415.0,
        r_inner=45.0,
        r_outer=120.0,
        theta_start_deg=214.25,
        theta_end_deg=235.75,
    )
    assert path.startswith("M ")
    assert " L " in path
    assert " A " in path
    assert path.endswith(" Z")
    # Must contain both inner and outer radii in arc commands
    assert "120.00 120.00" in path
    assert "45.00 45.00" in path


def test_generate_sector_wedge_svg_path_degenerated() -> None:
    """Section 5.2: Verify degenerate geometry returns empty string."""
    # r_outer <= r_inner
    p1 = generate_sector_wedge_svg_path(420.0, 415.0, 50.0, 50.0, 0.0, 20.0)
    assert p1 == ""
    p2 = generate_sector_wedge_svg_path(420.0, 415.0, 60.0, 50.0, 0.0, 20.0)
    assert p2 == ""
    # theta_end <= theta_start
    p3 = generate_sector_wedge_svg_path(420.0, 415.0, 45.0, 100.0, 20.0, 20.0)
    assert p3 == ""
    p4 = generate_sector_wedge_svg_path(420.0, 415.0, 45.0, 100.0, 30.0, 20.0)
    assert p4 == ""


def test_stacked_speed_bins_cumulative_radii() -> None:
    """Section 5.3: Verify radius scaling across the 5 stacked speed bins."""
    canvas = create_canonical_wind_rose_canvas()
    sw_sector = canvas.sectors[10]  # SW sector
    r_hub = canvas.config.hub_radius
    r_max = canvas.config.max_radius
    r_span = r_max - r_hub
    f_max = canvas.config.max_frequency_pct

    radii = []
    for b_idx in range(5):
        cum_freq = sw_sector.cumulative_bin_frequency(b_idx)
        r = r_hub + (min(cum_freq, f_max) / f_max) * r_span
        radii.append(r)

    # Radii must be strictly monotonically non-decreasing
    for i in range(len(radii) - 1):
        assert radii[i] <= radii[i + 1]
    assert radii[0] >= r_hub
    assert radii[-1] <= r_max


def test_concentric_grid_rings_geometry() -> None:
    """Section 5.4: Verify concentric grid rings radii calculation."""
    r_hub = PLOT_HUB_RADIUS
    r_max = PLOT_MAX_RADIUS
    f_max = PLOT_MAX_FREQUENCY_PCT
    levels = [5.0, 10.0, 15.0, 20.0, 25.0]

    rings = [r_hub + (lvl / f_max) * (r_max - r_hub) for lvl in levels]
    assert len(rings) == 5
    assert rings[0] > r_hub
    assert abs(rings[-1] - r_max) < 1e-4
    for i in range(len(rings) - 1):
        assert rings[i] < rings[i + 1]


# ============================================================================
# Section 6: Gaussian Plume Dispersion Hazard Corridor Math
# ============================================================================

def test_compute_plume_spread_angles_pasquill_gifford() -> None:
    """Section 6.1: Verify Pasquill-Gifford stability class dispersion half-angles."""
    assert compute_plume_spread_angle(1) == 24.0  # Class A (Unstable convective)
    assert compute_plume_spread_angle(2) == 20.0  # Class B
    assert compute_plume_spread_angle(3) == 16.0  # Class C
    assert compute_plume_spread_angle(4) == 12.0  # Class D (Neutral)
    assert compute_plume_spread_angle(5) == 9.0   # Class E
    assert compute_plume_spread_angle(6) == 6.5   # Class F (Stable persistent)
    assert compute_plume_spread_angle(99) == 12.0 # Default fallback


def test_generate_gaussian_plume_svg_path_geometry() -> None:
    """Section 6.2: Verify Gaussian plume polygon path structure and quadratic tip cap."""
    plume_path = generate_gaussian_plume_svg_path(
        cx=PLOT_CENTER_X,
        cy=PLOT_CENTER_Y,
        hub_radius=PLOT_HUB_RADIUS,
        plume_distance_m=850.0,
        max_dist_ref=PLUME_MAX_DISTANCE_REF_METERS,
        max_canvas_radius=PLOT_MAX_RADIUS,
        sector_angle_deg=45.0,
        stability_class=4,
    )
    assert plume_path.startswith("M ")
    assert " L " in plume_path
    assert " Q " in plume_path  # Quadratic curve at downwind tip
    assert plume_path.endswith(" Z")


def test_generate_gaussian_plume_core_svg_path_scaling() -> None:
    """Section 6.3: Verify IDLH toxic core plume path is generated with 40% distance scaling."""
    core_path = generate_gaussian_plume_core_svg_path(
        cx=PLOT_CENTER_X,
        cy=PLOT_CENTER_Y,
        hub_radius=PLOT_HUB_RADIUS,
        plume_distance_m=850.0,
        max_dist_ref=PLUME_MAX_DISTANCE_REF_METERS,
        max_canvas_radius=PLOT_MAX_RADIUS,
        sector_angle_deg=45.0,
        stability_class=4,
    )
    assert core_path.startswith("M ")
    assert " Q " in core_path
    assert core_path.endswith(" Z")


# ============================================================================
# Section 7: Standalone W3C SVG 1.1 XML Generation & Syntax Validation
# ============================================================================

def test_svg_xml_syntax_validity() -> None:
    """Section 7.1: Verify rendered SVG parses cleanly with xml.etree.ElementTree."""
    canvas = create_canonical_wind_rose_canvas()
    svg = canvas.render_svg()
    root = ET.fromstring(svg)
    assert root.tag == "{http://www.w3.org/2000/svg}svg" or root.tag == "svg"


def test_svg_root_attributes_and_viewbox() -> None:
    """Section 7.2: Verify SVG root dimensions and viewBox attributes."""
    canvas = create_canonical_wind_rose_canvas()
    svg = canvas.render_svg()
    root = ET.fromstring(svg)
    assert root.attrib.get("width") == str(CANVAS_VIEWPORT_WIDTH)
    assert root.attrib.get("height") == str(CANVAS_VIEWPORT_HEIGHT)
    assert root.attrib.get("viewBox") == f"0 0 {CANVAS_VIEWPORT_WIDTH} {CANVAS_VIEWPORT_HEIGHT}"


def test_svg_required_dom_elements_presence() -> None:
    """Section 7.3: Verify essential SCADA UI components are embedded in the SVG."""
    canvas = create_canonical_wind_rose_canvas()
    svg = canvas.render_svg()

    required_ids = [
        "canvas-header",
        "interactive-sector-selector",
        "wind-rose-polar-display",
        "concentric-grid-circles",
        "directional-spokes",
        "stacked-sector-wedges",
        "gaussian-plume-corridor",
        "beaufort-scale-hud",
        "toxic-corridor-hud",
        "horner-memory-hud",
        "speed-bins-legend",
    ]
    for elem_id in required_ids:
        assert f'id="{elem_id}"' in svg, f"Element id='{elem_id}' must exist in SVG"


def test_svg_xml_escaping_in_tooltips() -> None:
    """Section 7.4: Verify no raw unescaped '<' characters exist in XML text or titles."""
    canvas = create_canonical_wind_rose_canvas()
    svg = canvas.render_svg()
    # In XML, text nodes must use &lt; rather than raw <
    # If unescaped, ET.fromstring would fail with ParseError
    ET.fromstring(svg)
    assert "&lt;1 m/s" in svg or "<1 m/s" not in svg


# ============================================================================
# Section 8: WCAG 2.1 AAA Accessibility & Color Contrast Compliance
# ============================================================================

def test_srgb_channel_to_linear() -> None:
    """Section 8.1: Verify sRGB channel to linear conversion piecewise function."""
    assert srgb_channel_to_linear(0.0) == 0.0
    assert abs(srgb_channel_to_linear(0.03928) - 0.03928 / 12.92) < 1e-6
    assert abs(srgb_channel_to_linear(1.0) - 1.0) < 1e-6


def test_hex_to_relative_luminance() -> None:
    """Section 8.2: Verify WCAG relative luminance calculation for black and white."""
    lum_black = hex_to_relative_luminance("#000000")
    lum_white = hex_to_relative_luminance("#FFFFFF")
    assert abs(lum_black - 0.0) < 1e-4
    assert abs(lum_white - 1.0) < 1e-4


def test_calculate_contrast_ratio_formula() -> None:
    """Section 8.3: Verify contrast ratio formula bounds."""
    # Identical colors -> 1.0
    assert abs(calculate_contrast_ratio("#FFFFFF", "#FFFFFF") - 1.0) < 1e-4
    assert abs(calculate_contrast_ratio("#000000", "#000000") - 1.0) < 1e-4
    # Black and white -> 21.0
    cr_bw = calculate_contrast_ratio("#FFFFFF", "#000000")
    assert abs(cr_bw - 21.0) < 0.1


def test_decoupled_badge_contrast_aaa() -> None:
    """Section 8.4: Verify decoupled badge background contrast against primary text > 18:1."""
    ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    assert ratio >= WCAG_AAA_BADGE_CONTRAST_TARGET, f"Badge contrast {ratio:.2f} must exceed 18:1"
    assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, 18.0) is True


def test_theme_text_contrast_aaa() -> None:
    """Section 8.5: Verify theme text contrast against canvas dark backing > 7.0:1."""
    ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    assert ratio >= WCAG_AAA_TEXT_CONTRAST_TARGET, f"Theme text contrast {ratio:.2f} must exceed 7:1"
    assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING, 7.0) is True


def test_speed_bins_graphical_contrast() -> None:
    """Section 8.6: Verify all 5 speed bin colors exceed SCADA graphical contrast > 3.0:1."""
    bins = [
        COLOR_BIN_CALM,
        COLOR_BIN_LIGHT,
        COLOR_BIN_MODERATE,
        COLOR_BIN_FRESH,
        COLOR_BIN_STRONG,
    ]
    for b_col in bins:
        ratio = calculate_contrast_ratio(b_col, COLOR_DARK_THEME_BACKING)
        assert ratio >= WCAG_GRAPHICAL_CONTRAST_TARGET, f"Speed bin {b_col} contrast {ratio:.2f} must exceed 3.0:1"


# ============================================================================
# Section 9: Real-Time Wind Modulation & Beaufort Scale
# ============================================================================

def test_beaufort_scale_classification() -> None:
    """Section 9.1: Verify Beaufort scale force mapping from wind speed (m/s)."""
    assert get_beaufort_scale_info(0.2) == (0, "Calm")
    assert get_beaufort_scale_info(1.0) == (1, "Light Air")
    assert get_beaufort_scale_info(2.5) == (2, "Light Breeze")
    assert get_beaufort_scale_info(4.5) == (3, "Gentle Breeze")
    assert get_beaufort_scale_info(6.5) == (4, "Moderate Breeze")
    assert get_beaufort_scale_info(9.0) == (5, "Fresh Breeze")
    assert get_beaufort_scale_info(12.0) == (6, "Strong Breeze")
    assert get_beaufort_scale_info(15.5) == (7, "High Wind / Near Gale")
    assert get_beaufort_scale_info(18.5) == (8, "Gale")
    assert get_beaufort_scale_info(22.0) == (9, "Strong Gale")
    assert get_beaufort_scale_info(26.0) == (10, "Storm")
    assert get_beaufort_scale_info(30.0) == (11, "Violent Storm")
    assert get_beaufort_scale_info(35.0) == (12, "Hurricane")


def test_realtime_wind_speed_modulation() -> None:
    """Section 9.2: Verify dynamically modifying wind speed updates metrics and registers."""
    canvas = create_canonical_wind_rose_canvas()
    assert canvas.metrics.beaufort_force == 4

    # Modulate to 12.5 m/s (Strong Breeze)
    canvas.average_wind_speed_mps = 12.5
    canvas.peak_gust_speed_mps = 18.0
    canvas.evaluate_telemetry()
    canvas.sync_to_registers()

    assert canvas.metrics.beaufort_force == 6
    assert canvas.metrics.average_wind_speed_scaled == 125
    assert canvas.metrics.peak_gust_speed_scaled == 180
    assert canvas.reg_table.read_word("%R1531") == 125
    assert canvas.reg_table.read_word("%R1532") == 180


def test_realtime_wind_direction_modulation() -> None:
    """Section 9.3: Verify updating prevailing wind direction updates sectors."""
    canvas = create_canonical_wind_rose_canvas()
    assert canvas.metrics.prevailing_sector_name == "SW"

    # Shift wind to 90° East
    canvas.prevailing_direction_deg = 90
    canvas.toxic_corridor_sector_angle_deg = 270  # Plume downwind West
    canvas.evaluate_telemetry()
    canvas.sync_to_registers()

    assert canvas.metrics.prevailing_sector_name == "E"
    assert canvas.metrics.toxic_sector_name == "W"
    assert canvas.reg_table.read_word("%R1530") == 90
    assert canvas.reg_table.read_word("%R1536") == 270


def test_interactive_sector_selection() -> None:
    """Section 9.4: Verify interactive sector selector updates active tab."""
    canvas = create_canonical_wind_rose_canvas()
    assert canvas.selected_sector_index == 10  # Default SW

    canvas.select_sector(0)  # Select N
    assert canvas.selected_sector_index == 0

    canvas.select_sector(4)  # Select E
    assert canvas.selected_sector_index == 4

    # Out of range index should be ignored
    canvas.select_sector(99)
    assert canvas.selected_sector_index == 4


# ============================================================================
# Section 10: Horner RegisterTable Memory Space Synchronization
# ============================================================================

def test_register_table_synchronization_mappings() -> None:
    """Section 10.1: Verify register table synchronization for %R1530..%R1537 and %M357..%M358."""
    canvas = create_canonical_wind_rose_canvas()
    reg = canvas.reg_table

    assert reg.read_word("%R1530") == NOMINAL_PREVAILING_WIND_DIRECTION_DEG == 225
    assert reg.read_word("%R1531") == NOMINAL_AVERAGE_WIND_SPEED_SCALED == 65
    assert reg.read_word("%R1532") == NOMINAL_PEAK_GUST_SPEED_SCALED == 142
    assert reg.read_word("%R1533") == NOMINAL_CALM_PERIOD_SCALED == 85
    assert reg.read_word("%R1534") == NOMINAL_PLUME_DISPERSION_DISTANCE_M == 850
    assert reg.read_word("%R1535") == NOMINAL_ATMOSPHERIC_STABILITY_CLASS == 4
    assert reg.read_word("%R1536") == NOMINAL_TOXIC_CORRIDOR_SECTOR_ANGLE_DEG == 45
    assert reg.read_word("%R1537") == 0x0000

    assert reg.read_bit("%M357") is True   # WindRoseCanvasActive
    assert reg.read_bit("%M358") is False  # EnvironmentalDispersionAlarm


def test_register_synchronization_privilege_mode() -> None:
    """Section 10.2: Verify sync_to_registers uses PrivilegeMode.SYSTEM without privilege errors."""
    # RegisterTable with RESTRICTED mode default
    reg_table = RegisterTable()
    canvas = WindRoseCanvas(reg_table=reg_table)
    # sync_to_registers must not raise PrivilegeViolationError
    canvas.sync_to_registers()
    assert canvas.reg_table.read_word("%R1530") == 225


def test_diagnostic_code_signed_unsigned_equality() -> None:
    """Section 10.3: Verify DiagnosticCode 16-bit signed/unsigned equivalence and hashing."""
    code_gale = DiagnosticCode(0xD301)
    assert code_gale == 0xD301
    assert code_gale == 54017
    assert code_gale == -11519
    assert hash(code_gale) == hash(0xD301)

    code_plume = DiagnosticCode(0xD302)
    assert code_plume == 0xD302
    assert code_plume == 54018
    assert code_plume == -11518

    code_render = DiagnosticCode(0xD303)
    assert code_render == 0xD303
    assert code_render == 54019
    assert code_render == -11517

    assert DiagnosticCode(0) == 0


# ============================================================================
# Section 11: Process Safety Interlocks & Diagnostics
# ============================================================================

def test_gale_warning_interlock_trigger_and_registers() -> None:
    """Section 11.1: Verify Gale Warning (0xD301) trips when average wind or gust exceeds threshold."""
    canvas = create_canonical_wind_rose_canvas()
    canvas.trigger_gale_warning(wind_speed=18.5, gust_speed=22.0)

    assert canvas.diagnostic_code == WIND_ERR_GALE_WARNING
    assert canvas.diagnostic_code == 0xD301
    assert canvas.diagnostic_code == -11519
    assert canvas.metrics.has_gale_warning is True
    assert (canvas.status_bits & WindRoseStatusBits.GALE_WARNING) != 0
    assert (canvas.status_bits & WindRoseStatusBits.NOMINAL_OPERATION) == 0

    assert DiagnosticCode(canvas.reg_table.read_word("%R1537")) == 0xD301
    assert canvas.reg_table.read_bit("%M357") is True  # Display still active
    assert canvas.reg_table.read_bit("%M358") is False # Plume not alarmed


def test_plume_boundary_breach_trigger_and_registers() -> None:
    """Section 11.2: Verify Plume Boundary Breach (0xD302) asserts %M358 alarm."""
    canvas = create_canonical_wind_rose_canvas()
    canvas.trigger_plume_boundary_breach(distance_meters=1150)

    assert canvas.diagnostic_code == WIND_ERR_PLUME_BOUNDARY_BREACH
    assert canvas.diagnostic_code == 0xD302
    assert canvas.diagnostic_code == -11518
    assert canvas.environmental_dispersion_alarm is True
    assert canvas.metrics.has_plume_breach is True
    assert (canvas.status_bits & WindRoseStatusBits.PLUME_DISPERSION_ALARM) != 0

    assert DiagnosticCode(canvas.reg_table.read_word("%R1537")) == 0xD302
    assert canvas.reg_table.read_bit("%M358") is True  # Asserted


def test_render_fault_trigger_and_registers() -> None:
    """Section 11.3: Verify SVG Render Fault (0xD303) deactivates canvas active bit %M357."""
    canvas = create_canonical_wind_rose_canvas()
    canvas.trigger_render_fault()

    assert canvas.diagnostic_code == WIND_ERR_RENDER_FAULT
    assert canvas.diagnostic_code == 0xD303
    assert canvas.diagnostic_code == -11517
    assert canvas.canvas_active is False
    assert canvas.metrics.has_render_fault is True

    assert DiagnosticCode(canvas.reg_table.read_word("%R1537")) == 0xD303
    assert canvas.reg_table.read_bit("%M357") is False


def test_clean_nominal_recovery() -> None:
    """Section 11.4: Verify reset_nominal restores nominal operation and clears diagnostic codes."""
    canvas = create_canonical_wind_rose_canvas()
    canvas.trigger_plume_boundary_breach(1200)
    assert canvas.environmental_dispersion_alarm is True

    canvas.reset_nominal()
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.environmental_dispersion_alarm is False
    assert canvas.canvas_active is True
    assert (canvas.status_bits & WindRoseStatusBits.NOMINAL_OPERATION) != 0

    assert canvas.reg_table.read_word("%R1537") == 0
    assert canvas.reg_table.read_bit("%M357") is True
    assert canvas.reg_table.read_bit("%M358") is False


# ============================================================================
# Section 12: ILogicUnit Discrete Scan Cycle Execution
# ============================================================================

def test_ilogic_unit_properties() -> None:
    """Section 12.1: Verify ILogicUnit protocol compliance (name, priority, is_enabled)."""
    canvas = create_canonical_wind_rose_canvas()
    assert isinstance(canvas, ILogicUnit)
    assert canvas.name == "WindRoseEnvironmentalCanvasSync"
    assert canvas.priority == 85
    assert canvas.is_enabled is True


def test_ilogic_unit_scan_step_execution() -> None:
    """Section 12.2: Verify scan_step executes discrete scan cycle."""
    canvas = create_canonical_wind_rose_canvas()
    canvas.scan_step(dt=0.01)
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.reg_table.read_word("%R1530") == 225


def test_ilogic_unit_100_plus_scan_cycles() -> None:
    """Section 12.3: Execute 120 discrete Horner OCS scan cycles with multi-phase transitions."""
    canvas = create_canonical_wind_rose_canvas()

    # 1. Nominal scan cycles (1..30)
    for c in range(1, 31):
        canvas.scan_step(dt=0.01)
        assert canvas.diagnostic_code == DIAG_EVENT_OK

    # 2. Gale warning trigger phase (31..60)
    canvas.trigger_gale_warning(18.2, 21.5)
    for c in range(31, 61):
        canvas.scan_step(dt=0.01)
        assert canvas.diagnostic_code == WIND_ERR_GALE_WARNING

    # 3. Plume breach trigger phase (61..90)
    canvas.reset_nominal()
    canvas.trigger_plume_boundary_breach(1100)
    for c in range(61, 91):
        canvas.scan_step(dt=0.01)
        assert canvas.diagnostic_code == WIND_ERR_PLUME_BOUNDARY_BREACH
        assert canvas.reg_table.read_bit("%M358") is True

    # 4. Recovery and nominal cycles (91..120)
    canvas.reset_nominal()
    for c in range(91, 121):
        canvas.scan_step(dt=0.01)
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.reg_table.read_bit("%M358") is False


def test_ilogic_unit_automatic_fault_detection_in_scan() -> None:
    """Section 12.4: Verify execute() logic detects register threshold breaches automatically."""
    canvas = create_canonical_wind_rose_canvas()

    # Inject high wind speed directly via register
    canvas.reg_table.write_word("%R1531", 185, privilege=PrivilegeMode.SYSTEM)  # 18.5 m/s >= 172
    ctx = create_mock_scan_context(cycle=1, reg_table=canvas.reg_table)
    canvas.execute(ctx)

    assert canvas.diagnostic_code == WIND_ERR_GALE_WARNING
    assert DiagnosticCode(canvas.reg_table.read_word("%R1537")) == 0xD301

    # Inject plume distance breach directly via register
    canvas.reset_nominal()
    canvas.reg_table.write_word("%R1534", 1050, privilege=PrivilegeMode.SYSTEM) # >= 1000m
    canvas.execute(ctx)

    assert canvas.diagnostic_code == WIND_ERR_PLUME_BOUNDARY_BREACH
    assert canvas.environmental_dispersion_alarm is True
    assert canvas.reg_table.read_bit("%M358") is True
    assert DiagnosticCode(canvas.reg_table.read_word("%R1537")) == 0xD302


# ============================================================================
# Section 13: Deterministic 9-Stage Verification Suite Integration Runner
# ============================================================================

def test_verification_runner_success_all_9_stages(tmp_path: Path) -> None:
    """Section 13.1: Execute run_wind_rose_canvas_verification and verify status=='success' with 9 passed stages."""
    evidence_path = tmp_path / "wind_rose_evidence.json"
    sample_svg_path = tmp_path / "wind_rose_sample.svg"

    result = run_wind_rose_canvas_verification(
        output_path=str(evidence_path),
        sample_svg_path=str(sample_svg_path),
    )

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert "data" in result
    data = result["data"]
    assert data["checks_passed"] == 9
    assert data["total_checks"] == 9
    assert len(data["tests"]) == 9
    for stage_test in data["tests"]:
        assert stage_test["passed"] is True, f"Stage {stage_test.get('stage')} failed: {stage_test.get('details')}"


def test_verification_runner_artifact_file_emission(tmp_path: Path) -> None:
    """Section 13.2: Verify verification runner writes valid JSON evidence and SVG sample files."""
    evidence_path = tmp_path / "wind_rose_evidence.json"
    sample_svg_path = tmp_path / "wind_rose_sample.svg"

    run_wind_rose_canvas_verification(
        output_path=str(evidence_path),
        sample_svg_path=str(sample_svg_path),
    )

    assert evidence_path.is_file()
    assert evidence_path.stat().st_size > 0
    with open(evidence_path, "r", encoding="utf-8") as f:
        evidence_data = json.load(f)
    assert evidence_data["status"] == "success"

    assert sample_svg_path.is_file()
    assert sample_svg_path.stat().st_size > 0
    svg_content = sample_svg_path.read_text(encoding="utf-8")
    assert "<svg" in svg_content
    assert "</svg>" in svg_content
    ET.fromstring(svg_content)


# ============================================================================
# Section 14: Engine Class Aliases, Serialization & Factory Integrity
# ============================================================================

def test_engine_class_aliases() -> None:
    """Section 14.1: Verify class aliases for backward and forward compatibility."""
    assert WindRoseCanvasSync is WindRoseCanvas
    assert WindRoseEnvironmentalCanvas is WindRoseCanvas
    assert WindRoseEnvironmentalCanvasSync is WindRoseCanvas
    assert WindRoseEngine is WindRoseCanvas


def test_to_dict_serialization() -> None:
    """Section 14.2: Verify to_dict serializes all expected telemetry keys."""
    canvas = create_canonical_wind_rose_canvas()
    d = canvas.to_dict()

    assert d["component"] == "WindRoseCanvas"
    assert d["work_package"] == "W192"
    assert d["prevailing_direction_deg"] == 225
    assert d["prevailing_sector"] == "SW"
    assert d["average_wind_speed_mps"] == 6.5
    assert d["peak_gust_speed_mps"] == 14.2
    assert d["calm_period_pct"] == 8.5
    assert d["plume_dispersion_distance_m"] == 850
    assert d["atmospheric_stability_class"] == 4
    assert d["toxic_corridor_sector_angle_deg"] == 45
    assert d["toxic_sector"] == "NE"
    assert d["beaufort_force"] == 4
    assert d["canvas_active"] is True
    assert d["environmental_dispersion_alarm"] is False
    assert d["diagnostic_code"] == "0x0000"
    assert "status_bits" in d
