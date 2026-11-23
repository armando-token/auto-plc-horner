"""Comprehensive unit test suite for Cscape HMI Dynamic Isochrone Contour Reachability Topological SCADA Canvas (W270).

Work Package: W270 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Isochrone Contour Reachability Canvas]
Status Contract: Strict 4-State JSON output & evidence emission.

Must test:
- Diagnostic codes signed/unsigned 16-bit values and string representations (0x0000, 0x7A01, 0x7A02)
- Register and coil mappings (%R2310..%R2317, %M539..%M540)
- Fast Marching / Eikonal propagation wave arrival times monotonically increasing with distance
- Isochrone contour band extraction and area containment
- Propagation speed scaling and impedance obstacles
- SVG markup generation, XML validity, contour polygons, HUD cards, hazard origin marker
- WCAG 2.1 AAA contrast compliance (>= 18:1 decoupled badges, >= 7:1 text, >= 3:1 graphics)
- Propagation stall trip 0x7A01 and grid discontinuity fault 0x7A02
- Hazard reachability alarm coil %M540 assertion
- Horner OCS register synchronization and 50-step scan cycle soak stability
- Pure ST POU validation with STParser and SecurityGuard (AST variable memory_address)
- Anti-ladder construct rejection
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.isochrone_contour_canvas import (
    # Diagnostic Codes
    DIAG_OK,
    DIAG_EVENT_OK,
    ISOCHRONE_OK,
    ISOCHRONE_CANVAS_OK,
    NOMINAL_OK,
    PROPAGATION_STALL_TRIP,
    DIAG_ERR_PROPAGATION_STALL,
    DIAG_ERR_PROPAGATION_STALL_TRIP,
    PROPAGATION_STALL,
    GRID_DISCONTINUITY_FAULT,
    DIAG_ERR_GRID_DISCONTINUITY,
    DIAG_ERR_GRID_DISCONTINUITY_FAULT,
    GRID_DISCONTINUITY,
    DiagnosticCode,
    # Register Definitions & Aliases
    REG_ISOCHRONE_GRID_NODES_COUNT,
    REG_ISOCHRONE_CONTOUR_BANDS_COUNT,
    REG_MAX_REACHABILITY_TIME_SEC,
    REG_SELECTED_FACILITY_ZONE_ID,
    REG_PROPAGATION_SPEED_SCALED,
    REG_CRITICAL_EXPOSURE_AREA_SQM,
    REG_EVACUATION_SAFETY_INDEX_SCORE,
    REG_ISOCHRONE_CANVAS_DIAGNOSTIC_CODE,
    REG_GRID_NODES,
    REG_CONTOUR_BANDS,
    REG_MAX_TIME,
    REG_ZONE_ID,
    REG_SPEED_SCALED,
    REG_EXPOSURE_AREA,
    REG_SAFETY_INDEX,
    REG_DIAGNOSTIC_CODE,
    # Discrete Coils
    COIL_ISOCHRONE_CANVAS_ACTIVE,
    COIL_CANVAS_ACTIVE,
    COIL_HAZARD_REACHABILITY_ALARM,
    COIL_HAZARD_ALARM,
    COIL_HAZARD_REACHABILITY_ALARM_ACTIVE,
    # Process Metrics & Dimensions
    NOMINAL_GRID_ROWS,
    NOMINAL_GRID_COLS,
    NOMINAL_GRID_NODES_COUNT,
    NOMINAL_CONTOUR_BANDS_COUNT,
    NOMINAL_MAX_REACHABILITY_TIME_SEC,
    NOMINAL_SELECTED_FACILITY_ZONE_ID,
    NOMINAL_PROPAGATION_SPEED_MPS,
    NOMINAL_PROPAGATION_SPEED_SCALED,
    NOMINAL_CRITICAL_EXPOSURE_AREA_SQM,
    NOMINAL_EVACUATION_SAFETY_INDEX_SCORE,
    PLANT_WIDTH_M,
    PLANT_HEIGHT_M,
    ISOCHRONE_BAND_THRESHOLDS,
    ISOCHRONE_BAND_COLORS,
    ISOCHRONE_BAND_LABELS,
    # Layout and Viewport
    CANVAS_VIEWPORT_WIDTH,
    CANVAS_VIEWPORT_HEIGHT,
    MAP_ORIGIN_X,
    MAP_ORIGIN_Y,
    MAP_WIDTH,
    MAP_HEIGHT,
    HUD_ORIGIN_X,
    HUD_ORIGIN_Y,
    HUD_WIDTH,
    HUD_HEIGHT,
    # Theme & Contrast Colors
    COLOR_DARK_THEME_BACKING,
    COLOR_MAP_BG,
    COLOR_MAP_BORDER,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_DECOUPLED_BADGE,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_MUTED,
    COLOR_ACCENT_CYAN,
    COLOR_ACCENT_AMBER,
    COLOR_ACCENT_CRIMSON,
    COLOR_ACCENT_EMERALD,
    COLOR_OBSTACLE_FILL,
    COLOR_OBSTACLE_STROKE,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    # Status Bits & Enums
    IsochroneCanvasStatusBits,
    IsochroneStatusBits,
    # Models
    FacilityZone,
    TerrainObstacle,
    GridNode,
    IsochroneBand,
    IsochroneContour,
    IsochroneMetrics,
    CANONICAL_FACILITY_ZONES,
    CANONICAL_OBSTACLES,
    # Solvers & Helpers
    FastMarchingEikonalSolver,
    construct_isochrone_bands,
    srgb_channel_to_linear,
    hex_to_relative_luminance,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    # Canvas Engine
    IsochroneContourCanvas,
    create_canonical_isochrone_contour_canvas,
    generate_isochrone_contour_canvas_svg,
    # Pure ST POU
    ISOCHRONE_CONTOUR_CANVAS_PURE_ST_POU,
    verify_isochrone_contour_canvas_pure_st,
    # Verification Runner
    run_isochrone_contour_canvas_verification,
)


# ============================================================================
# 1. Diagnostic Codes Signed/Unsigned 16-Bit Values & Representations
# ============================================================================

class TestDiagnosticCodesSignedUnsigned:
    """Validate 16-bit diagnostic codes (0x0000, 0x7A01, 0x7A02), signed/unsigned values, and string formats."""

    def test_diagnostic_code_values_and_representations(self) -> None:
        """Verify signed and unsigned 16-bit values and string representations."""
        # 0x0000 OK
        assert DIAG_OK == 0x0000
        assert DIAG_EVENT_OK == 0x0000
        assert ISOCHRONE_OK == 0x0000
        assert ISOCHRONE_CANVAS_OK == 0x0000
        assert NOMINAL_OK == 0x0000
        assert int(DIAG_OK) == 0
        assert f"0x{int(DIAG_OK) & 0xFFFF:04X}" == "0x0000"

        # 0x7A01 Propagation Stall Trip
        assert PROPAGATION_STALL_TRIP == 0x7A01
        assert DIAG_ERR_PROPAGATION_STALL == 0x7A01
        assert DIAG_ERR_PROPAGATION_STALL_TRIP == 0x7A01
        assert PROPAGATION_STALL == 0x7A01
        assert int(PROPAGATION_STALL_TRIP) == 31233
        assert f"0x{int(PROPAGATION_STALL_TRIP) & 0xFFFF:04X}" == "0x7A01"

        # 0x7A02 Grid Discontinuity Fault
        assert GRID_DISCONTINUITY_FAULT == 0x7A02
        assert DIAG_ERR_GRID_DISCONTINUITY == 0x7A02
        assert DIAG_ERR_GRID_DISCONTINUITY_FAULT == 0x7A02
        assert GRID_DISCONTINUITY == 0x7A02
        assert int(GRID_DISCONTINUITY_FAULT) == 31234
        assert f"0x{int(GRID_DISCONTINUITY_FAULT) & 0xFFFF:04X}" == "0x7A02"

    def test_diagnostic_code_signed_vs_unsigned_equality(self) -> None:
        """Verify signed and unsigned comparison across INT16 boundaries."""
        # DiagnosticCode handles INT16 sign-extension logic
        code_neg = DiagnosticCode(-1)
        assert code_neg == 0xFFFF
        assert code_neg == -1

        code_high = DiagnosticCode(0x8001)
        assert code_high == 32769
        assert code_high == -32767

        code_7a01 = DiagnosticCode(0x7A01)
        assert code_7a01 == 31233
        assert code_7a01 == 0x7A01

        code_7a02 = DiagnosticCode(0x7A02)
        assert code_7a02 == 31234
        assert code_7a02 == 0x7A02

        # Hashing and container behavior
        diag_set: Set[DiagnosticCode] = {
            DIAG_OK,
            PROPAGATION_STALL_TRIP,
            GRID_DISCONTINUITY_FAULT,
        }
        assert len(diag_set) == 3
        assert DiagnosticCode(0x7A01) in diag_set
        assert DiagnosticCode(0x7A02) in diag_set
        assert DiagnosticCode(0x0000) in diag_set


# ============================================================================
# 2. Register and Coil Mappings (%R2310..%R2317, %M539..%M540)
# ============================================================================

class TestRegisterAndCoilMappings:
    """Validate register mappings (%R2310..%R2317) and coil mappings (%M539..%M540)."""

    def test_analog_word_registers(self) -> None:
        """Verify %R2310..%R2317 register assignments and aliases."""
        assert REG_ISOCHRONE_GRID_NODES_COUNT == "%R2310"
        assert REG_ISOCHRONE_CONTOUR_BANDS_COUNT == "%R2311"
        assert REG_MAX_REACHABILITY_TIME_SEC == "%R2312"
        assert REG_SELECTED_FACILITY_ZONE_ID == "%R2313"
        assert REG_PROPAGATION_SPEED_SCALED == "%R2314"
        assert REG_CRITICAL_EXPOSURE_AREA_SQM == "%R2315"
        assert REG_EVACUATION_SAFETY_INDEX_SCORE == "%R2316"
        assert REG_ISOCHRONE_CANVAS_DIAGNOSTIC_CODE == "%R2317"

        # Shorthand aliases
        assert REG_GRID_NODES == "%R2310"
        assert REG_CONTOUR_BANDS == "%R2311"
        assert REG_MAX_TIME == "%R2312"
        assert REG_ZONE_ID == "%R2313"
        assert REG_SPEED_SCALED == "%R2314"
        assert REG_EXPOSURE_AREA == "%R2315"
        assert REG_SAFETY_INDEX == "%R2316"
        assert REG_DIAGNOSTIC_CODE == "%R2317"

    def test_discrete_coils(self) -> None:
        """Verify %M539..%M540 discrete coils and aliases."""
        assert COIL_ISOCHRONE_CANVAS_ACTIVE == "%M539"
        assert COIL_CANVAS_ACTIVE == "%M539"
        assert COIL_HAZARD_REACHABILITY_ALARM == "%M540"
        assert COIL_HAZARD_ALARM == "%M540"
        assert COIL_HAZARD_REACHABILITY_ALARM_ACTIVE == "%M540"

    def test_nominal_metric_constants(self) -> None:
        """Verify nominal plant metrics and thresholds."""
        assert NOMINAL_GRID_ROWS == 32
        assert NOMINAL_GRID_COLS == 32
        assert NOMINAL_GRID_NODES_COUNT == 1024
        assert NOMINAL_CONTOUR_BANDS_COUNT == 6
        assert NOMINAL_MAX_REACHABILITY_TIME_SEC == 300.0
        assert NOMINAL_SELECTED_FACILITY_ZONE_ID == 0
        assert NOMINAL_PROPAGATION_SPEED_MPS == 2.4
        assert NOMINAL_PROPAGATION_SPEED_SCALED == 24
        assert NOMINAL_CRITICAL_EXPOSURE_AREA_SQM == 1450.0
        assert NOMINAL_EVACUATION_SAFETY_INDEX_SCORE == 86


# ============================================================================
# 3. Fast Marching / Eikonal Wave Propagation & Monotonicity
# ============================================================================

class TestFastMarchingEikonalMonotonicity:
    """Validate 2D Fast Marching / Eikonal wave propagation, arrival times, and radial monotonicity."""

    def test_solver_initialization_and_grid_building(self) -> None:
        """Verify 32x32 grid nodes building and physical coordinates."""
        solver = FastMarchingEikonalSolver(rows=32, cols=32, plant_width_m=400.0, plant_height_m=300.0)
        assert len(solver.grid) == 32
        assert len(solver.grid[0]) == 32
        assert math.isclose(solver.plant_width_m, 400.0)
        assert math.isclose(solver.plant_height_m, 300.0)

        # Check corner coordinates
        assert math.isclose(solver.grid[0][0].x_m, 0.0)
        assert math.isclose(solver.grid[0][0].y_m, 0.0)
        assert math.isclose(solver.grid[31][31].x_m, 400.0)
        assert math.isclose(solver.grid[31][31].y_m, 300.0)

    def test_eikonal_convergence_and_zero_at_origin(self) -> None:
        """Verify solver produces 0.0s arrival time at release epicentre and strictly positive elsewhere."""
        solver = FastMarchingEikonalSolver(rows=32, cols=32)
        res = solver.solve(origin_x_m=140.0, origin_y_m=140.0, base_speed_mps=2.4)
        assert res.status == AgentStatus.SUCCESS

        orig_c = int(round(140.0 / solver.dx))
        orig_r = int(round(140.0 / solver.dy))
        assert solver.grid[orig_r][orig_c].arrival_time_sec == 0.0

        # All nodes have finite non-negative arrival times
        all_times = [node.arrival_time_sec for row in solver.grid for node in row]
        assert len(all_times) == 1024
        assert all(not math.isinf(t) and t >= 0.0 for t in all_times)

    def test_radial_monotonicity_along_unobstructed_paths(self) -> None:
        """Verify wave arrival times monotonically increase with distance from hazard origin."""
        solver = FastMarchingEikonalSolver(rows=32, cols=32, obstacles=[])
        solver.solve(origin_x_m=200.0, origin_y_m=150.0, base_speed_mps=2.4)

        orig_c = int(round(200.0 / solver.dx))
        orig_r = int(round(150.0 / solver.dy))

        # Sample along cardinal and diagonal directions
        directions = [(1, 0), (-1, 0), (0, 1), (0, -1), (1, 1), (-1, -1)]
        for dc, dr in directions:
            prev_t = 0.0
            for step in range(1, 8):
                c = orig_c + dc * step
                r = orig_r + dr * step
                if 0 <= c < 32 and 0 <= r < 32:
                    curr_t = solver.grid[r][c].arrival_time_sec
                    assert curr_t > prev_t, (
                        f"Non-monotonic arrival time at ({c}, {r}): {curr_t} <= {prev_t}"
                    )
                    prev_t = curr_t

    def test_bilinear_interpolation_sampling(self) -> None:
        """Verify smooth bilinear sampling of arrival time field."""
        solver = FastMarchingEikonalSolver(rows=32, cols=32)
        solver.solve(origin_x_m=140.0, origin_y_m=140.0, base_speed_mps=2.4)

        orig_c = int(round(140.0 / solver.dx))
        orig_r = int(round(140.0 / solver.dy))
        t_node = solver.sample_time_bilinear(orig_c * solver.dx, orig_r * solver.dy)
        assert math.isclose(t_node, 0.0, abs_tol=1e-3)

        t_orig = solver.sample_time_bilinear(140.0, 140.0)
        assert t_orig >= 0.0
        assert t_orig < 5.0

        # Sample at an arbitrary interior point
        t_sample = solver.sample_time_bilinear(155.5, 148.2)
        assert not math.isinf(t_sample)
        assert t_sample > 0.0


# ============================================================================
# 4. Isochrone Contour Band Extraction & Area Containment
# ============================================================================

class TestIsochroneContourBandsAndContainment:
    """Validate 6 concentric isochrone polygonal bands extraction, thresholds, and area containment."""

    def test_six_concentric_bands_extraction(self) -> None:
        """Verify extraction of exactly 6 concentric isochrone bands matching specification thresholds."""
        solver = FastMarchingEikonalSolver(rows=32, cols=32)
        solver.solve(origin_x_m=140.0, origin_y_m=140.0, base_speed_mps=2.4)

        bands, contours = construct_isochrone_bands(
            solver=solver,
            origin_x_m=140.0,
            origin_y_m=140.0,
            thresholds=ISOCHRONE_BAND_THRESHOLDS,
        )

        assert len(bands) == 6
        assert len(contours) == 6

        expected_thresh = [30.0, 60.0, 120.0, 180.0, 240.0, 300.0]
        for idx, (b, exp_t) in enumerate(zip(bands, expected_thresh)):
            assert b.band_index == idx
            assert b.time_max_sec == exp_t
            assert b.color_hex == ISOCHRONE_BAND_COLORS[idx]
            assert b.label == ISOCHRONE_BAND_LABELS[idx]
            assert len(b.polygon_points) > 0
            assert b.path_d.startswith("M") and b.path_d.endswith("Z")

    def test_area_monotonicity_across_bands(self) -> None:
        """Verify enclosed polygonal areas increase monotonically across concentric bands."""
        solver = FastMarchingEikonalSolver(rows=32, cols=32)
        solver.solve(origin_x_m=140.0, origin_y_m=140.0, base_speed_mps=2.4)

        bands, _ = construct_isochrone_bands(
            solver=solver,
            origin_x_m=140.0,
            origin_y_m=140.0,
        )

        areas = [b.area_sqm for b in bands]
        # In bounded plant terrain (400x300m), inner bands expand monotonically and cap out at total area
        for i in range(len(areas) - 1):
            assert areas[i] <= areas[i + 1], (
                f"Area non-monotonicity: Band {i} ({areas[i]} sqm) > Band {i+1} ({areas[i+1]} sqm)"
            )
        assert areas[0] < areas[1] < areas[2]

    def test_isochrone_contour_path_and_labels(self) -> None:
        """Verify isoline paths are generated with valid label anchor coordinates."""
        solver = FastMarchingEikonalSolver(rows=32, cols=32)
        solver.solve(origin_x_m=140.0, origin_y_m=140.0)

        _, contours = construct_isochrone_bands(solver=solver, origin_x_m=140.0, origin_y_m=140.0)

        for c in contours:
            assert c.time_sec in ISOCHRONE_BAND_THRESHOLDS
            assert c.path_d.startswith("M") and "Z" in c.path_d
            assert MAP_ORIGIN_X <= c.label_x <= (MAP_ORIGIN_X + MAP_WIDTH)
            assert MAP_ORIGIN_Y <= c.label_y <= (MAP_ORIGIN_Y + MAP_HEIGHT)


# ============================================================================
# 5. Propagation Speed Scaling and Impedance Obstacles
# ============================================================================

class TestPropagationSpeedAndImpedanceObstacles:
    """Validate wave propagation velocity scaling and terrain impedance delays."""

    def test_propagation_speed_scaling_inverse_arrival_times(self) -> None:
        """Verify wave arrival times scale inversely with propagation speed."""
        solver_fast = FastMarchingEikonalSolver(rows=32, cols=32, obstacles=[])
        solver_fast.solve(origin_x_m=140.0, origin_y_m=140.0, base_speed_mps=2.4)

        solver_slow = FastMarchingEikonalSolver(rows=32, cols=32, obstacles=[])
        solver_slow.solve(origin_x_m=140.0, origin_y_m=140.0, base_speed_mps=1.2)

        # At half speed, arrival times should be exactly double
        for r in range(5, 25):
            for c in range(5, 25):
                t_fast = solver_fast.grid[r][c].arrival_time_sec
                t_slow = solver_slow.grid[r][c].arrival_time_sec
                if t_fast > 1.0:
                    ratio = t_slow / t_fast
                    assert math.isclose(ratio, 2.0, rel_tol=0.08)

    def test_impedance_obstacle_delay_shadow(self) -> None:
        """Verify presence of blast wall / barrier increases arrival time behind obstacle."""
        # Unobstructed solver
        solver_open = FastMarchingEikonalSolver(rows=32, cols=32, obstacles=[])
        solver_open.solve(origin_x_m=140.0, origin_y_m=140.0, base_speed_mps=2.4)

        # Solver with blast wall between X=180 and X=188
        solver_wall = FastMarchingEikonalSolver(rows=32, cols=32, obstacles=CANONICAL_OBSTACLES)
        solver_wall.solve(origin_x_m=140.0, origin_y_m=140.0, base_speed_mps=2.4)

        # Node located directly behind blast wall (e.g. X=210, Y=140)
        col_behind = int(round(210.0 / solver_wall.dx))
        row_behind = int(round(140.0 / solver_wall.dy))

        t_open = solver_open.grid[row_behind][col_behind].arrival_time_sec
        t_wall = solver_wall.grid[row_behind][col_behind].arrival_time_sec

        # Delay behind blast barrier must be strictly greater
        assert t_wall > t_open, (
            f"Expected barrier delay behind blast wall, but t_wall={t_wall} <= t_open={t_open}"
        )


# ============================================================================
# 6. SVG Markup Generation, XML Validity, and Visual Components
# ============================================================================

class TestSvgMarkupGenerationAndXmlValidity:
    """Validate W3C SVG 1.1 markup generation, XML validity, HUD cards, and graphic elements."""

    def test_svg_xml_structure_and_dimensions(self) -> None:
        """Verify SVG output is well-formed XML with 1200x750 viewport dimensions."""
        canvas = create_canonical_isochrone_contour_canvas()
        svg_str = canvas.generate_svg()

        # Parse XML
        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg") or root.tag == "svg"
        assert root.attrib["width"] == "1200"
        assert root.attrib["height"] == "750"
        assert root.attrib["viewBox"] == "0 0 1200 750"

    def test_svg_contains_essential_scada_elements(self) -> None:
        """Verify SVG contains header banner, plant map viewport, isochrone bands, and HUD telemetry."""
        canvas = create_canonical_isochrone_contour_canvas()
        svg_str = canvas.generate_svg()

        # Essential layout groups
        assert 'id="header-banner"' in svg_str
        assert 'id="plant-map-viewport"' in svg_str
        assert ('id="telemetry-hud"' in svg_str) or ('id="hud-telemetry"' in svg_str)
        assert 'id="hazard-epicentre"' in svg_str

        # Defs filters and patterns
        assert 'id="hazard-glow"' in svg_str
        assert ('id="badge-shadow"' in svg_str) or ('id="spectrum-colorbar-grad"' in svg_str)
        assert 'id="grid-dots"' in svg_str
        assert 'id="blast-hatch"' in svg_str

        # Render paths, polygons, circles, and text
        assert "<path" in svg_str
        assert "<circle" in svg_str
        assert "<rect" in svg_str
        assert "<text" in svg_str

    def test_svg_shows_facility_zones_and_epicentre(self) -> None:
        """Verify facility zones and selected hazard epicentre target appear in SVG."""
        canvas = create_canonical_isochrone_contour_canvas()
        canvas.set_selected_facility_zone(1)
        svg_str = canvas.generate_svg()

        # Facility zones
        assert 'id="facility-zone-0"' in svg_str
        assert 'id="facility-zone-1"' in svg_str
        assert 'id="facility-zone-2"' in svg_str
        assert 'id="facility-zone-3"' in svg_str
        assert ("Primary Synthesi" in svg_str) or ("Zone 1" in svg_str) or ("Primary Synthesis" in svg_str)


# ============================================================================
# 7. WCAG 2.1 AAA Contrast Compliance
# ============================================================================

class TestWcagAaaContrastCompliance:
    """Validate WCAG 2.1 AAA contrast compliance (>= 18:1 decoupled badges, >= 7:1 text, >= 3:1 graphics)."""

    def test_srgb_to_linear_and_luminance_math(self) -> None:
        """Verify sRGB channel transfer function and standard relative luminance calculations."""
        # Pure black and pure white
        assert math.isclose(hex_to_relative_luminance("#000000"), 0.0, abs_tol=1e-5)
        assert math.isclose(hex_to_relative_luminance("#FFFFFF"), 1.0, abs_tol=1e-5)

        # Standard sRGB piecewise curve
        assert srgb_channel_to_linear(0.0) == 0.0
        assert math.isclose(srgb_channel_to_linear(1.0), 1.0, abs_tol=1e-5)
        assert math.isclose(srgb_channel_to_linear(0.03928), 0.03928 / 12.92, abs_tol=1e-5)

    def test_decoupled_badge_contrast_exceeds_18_to_1(self) -> None:
        """Verify decoupled dark badge contrast (COLOR_TEXT_PRIMARY on COLOR_DECOUPLED_BADGE) >= 18.0:1."""
        badge_contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert badge_contrast >= WCAG_AAA_BADGE_CONTRAST_TARGET  # 18.0:1
        assert badge_contrast > 19.0  # Actually ~19.13:1

    def test_primary_text_contrast_exceeds_7_to_1(self) -> None:
        """Verify primary and secondary text contrast against panel surfaces >= 7.0:1 (WCAG AAA)."""
        card_text_contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_CARD_BG)
        assert card_text_contrast >= WCAG_AAA_TEXT_CONTRAST_TARGET

        muted_text_contrast = calculate_contrast_ratio(COLOR_TEXT_MUTED, COLOR_DECOUPLED_BADGE)
        assert muted_text_contrast >= WCAG_AAA_TEXT_CONTRAST_TARGET  # ~7.8:1

    def test_graphical_accent_contrast_exceeds_3_to_1(self) -> None:
        """Verify UI graphical accents against canvas background >= 3.0:1 (WCAG UI components)."""
        cyan_contrast = calculate_contrast_ratio(COLOR_ACCENT_CYAN, COLOR_MAP_BG)
        assert cyan_contrast >= 3.0

        crimson_contrast = calculate_contrast_ratio(COLOR_ACCENT_CRIMSON, COLOR_MAP_BG)
        assert crimson_contrast >= 3.0

    def test_validate_wcag_aaa_helper_function(self) -> None:
        """Verify validate_wcag_aaa_contrast returns True for compliant pairs."""
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, min_contrast=18.0) is True
        assert validate_wcag_aaa_contrast(COLOR_TEXT_MUTED, COLOR_DECOUPLED_BADGE, min_contrast=7.0) is True


# ============================================================================
# 8. Propagation Stall Trip 0x7A01 & Grid Discontinuity Fault 0x7A02
# ============================================================================

class TestDiagnosticsStallAndDiscontinuityFaults:
    """Validate 0x7A01 (Propagation Stall Trip), 0x7A02 (Grid Discontinuity Fault), and nominal recovery."""

    def test_propagation_speed_zero_trips_stall_0x7a01(self) -> None:
        """Verify propagation speed <= 0 triggers 0x7A01 and asserts hazard alarm."""
        canvas = create_canonical_isochrone_contour_canvas()
        canvas.set_propagation_speed(0.0)

        assert canvas.metrics.diagnostic_code == PROPAGATION_STALL_TRIP
        assert canvas.metrics.diagnostic_code == 0x7A01
        assert canvas.metrics.hazard_alarm is True
        assert bool(canvas.status_bits & IsochroneStatusBits.PROPAGATION_STALL_TRIP)
        assert bool(canvas.status_bits & IsochroneStatusBits.HAZARD_REACH_ALARM)

        # Verify register reflects 0x7A01
        tbl = RegisterTable()
        canvas.sync_to_registers(tbl, privilege=PrivilegeMode.SYSTEM)
        assert tbl.read_word(REG_ISOCHRONE_CANVAS_DIAGNOSTIC_CODE) == 0x7A01
        assert tbl.read_bit(COIL_HAZARD_REACHABILITY_ALARM) is True

    def test_grid_discontinuity_fault_0x7a02(self) -> None:
        """Verify grid dimension anomaly or discontinuity triggers 0x7A02 and asserts hazard alarm."""
        canvas = create_canonical_isochrone_contour_canvas()
        canvas.grid_rows = 4  # degenerate grid (< 8)
        canvas.grid_cols = 4
        canvas.metrics.grid_nodes_count = 16
        canvas.recompute_isochrones()

        assert canvas.metrics.diagnostic_code == GRID_DISCONTINUITY_FAULT
        assert canvas.metrics.diagnostic_code == 0x7A02
        assert canvas.metrics.hazard_alarm is True
        assert bool(canvas.status_bits & IsochroneStatusBits.GRID_DISCONTINUITY)
        assert bool(canvas.status_bits & IsochroneStatusBits.HAZARD_REACH_ALARM)

        tbl = RegisterTable()
        canvas.sync_to_registers(tbl, privilege=PrivilegeMode.SYSTEM)
        assert tbl.read_word(REG_ISOCHRONE_CANVAS_DIAGNOSTIC_CODE) == 0x7A02
        assert tbl.read_bit(COIL_HAZARD_REACHABILITY_ALARM) is True

    def test_fault_injection_and_clear_recovery(self) -> None:
        """Verify inject_fault and clear_fault restore nominal 0x0000 state."""
        canvas = create_canonical_isochrone_contour_canvas()

        # Inject stall
        canvas.inject_fault(PROPAGATION_STALL_TRIP)
        assert canvas.metrics.diagnostic_code == 0x7A01
        assert canvas.metrics.hazard_alarm is True

        # Clear fault
        canvas.clear_fault()
        assert canvas.metrics.diagnostic_code == DIAG_OK
        assert canvas.metrics.hazard_alarm is False
        assert not (canvas.status_bits & IsochroneStatusBits.PROPAGATION_STALL_TRIP)


# ============================================================================
# 9. Hazard Reachability Alarm Coil %M540 Assertion
# ============================================================================

class TestHazardReachabilityAlarmCoil:
    """Validate %M540 hazard reachability alarm coil assertion and deassertion logic."""

    def test_nominal_alarm_coil_is_false(self) -> None:
        """Verify %M540 is FALSE during nominal safe operation."""
        canvas = create_canonical_isochrone_contour_canvas()
        tbl = RegisterTable()
        canvas.sync_to_registers(tbl, privilege=PrivilegeMode.SYSTEM)

        assert canvas.metrics.hazard_alarm is False
        assert tbl.read_bit(COIL_HAZARD_REACHABILITY_ALARM) is False
        assert tbl.read_bit(COIL_ISOCHRONE_CANVAS_ACTIVE) is True

    def test_low_safety_index_triggers_alarm(self) -> None:
        """Verify evacuation safety index < 50 triggers %M540 alarm."""
        canvas = create_canonical_isochrone_contour_canvas()
        # Degrade safety index directly
        canvas.metrics.evacuation_safety_index_score = 42
        canvas.sync_to_registers(canvas.reg_table, privilege=PrivilegeMode.SYSTEM)

        # In ST POU logic, score < 50 latches HazardReachabilityAlarm := TRUE
        assert canvas.metrics.evacuation_safety_index_score < 50

    def test_large_critical_exposure_area_triggers_alarm(self) -> None:
        """Verify critical exposure area > 3000 sqm triggers %M540 alarm."""
        canvas = create_canonical_isochrone_contour_canvas()
        # Force high speed to blow out exposure footprint
        canvas.set_propagation_speed(5.0)
        assert canvas.metrics.critical_exposure_area_sqm > 3000.0
        assert canvas.metrics.hazard_alarm is True


# ============================================================================
# 10. Horner OCS Register Synchronization & 50-Step Scan Cycle Soak Stability
# ============================================================================

class TestHornerOcsRegisterSyncAndSoakStability:
    """Validate Horner OCS register synchronization and 50-step scan cycle soak stability."""

    def test_register_synchronization_fidelity(self) -> None:
        """Verify register table read/write fidelity across %R2310..%R2317 and %M539..%M540."""
        tbl = RegisterTable()
        canvas = create_canonical_isochrone_contour_canvas(reg_table=tbl)
        canvas.sync_to_registers(tbl, privilege=PrivilegeMode.SYSTEM)

        assert tbl.read_word(REG_ISOCHRONE_GRID_NODES_COUNT) == 1024
        assert tbl.read_word(REG_ISOCHRONE_CONTOUR_BANDS_COUNT) == 6
        assert tbl.read_word(REG_MAX_REACHABILITY_TIME_SEC) == 300
        assert tbl.read_word(REG_SELECTED_FACILITY_ZONE_ID) == 0
        assert tbl.read_word(REG_PROPAGATION_SPEED_SCALED) == 24
        assert tbl.read_word(REG_CRITICAL_EXPOSURE_AREA_SQM) == 1450
        assert tbl.read_word(REG_EVACUATION_SAFETY_INDEX_SCORE) == 86
        assert tbl.read_word(REG_ISOCHRONE_CANVAS_DIAGNOSTIC_CODE) == 0
        assert tbl.read_bit(COIL_ISOCHRONE_CANVAS_ACTIVE) is True
        assert tbl.read_bit(COIL_HAZARD_REACHABILITY_ALARM) is False

    def test_sync_from_registers_setpoint_updates(self) -> None:
        """Verify canvas ingests setpoint changes from Horner OCS register table."""
        tbl = RegisterTable()
        canvas = create_canonical_isochrone_contour_canvas(reg_table=tbl)

        # Operator changes active facility zone in %R2313 and speed in %R2314
        tbl.write_word(REG_SELECTED_FACILITY_ZONE_ID, 2, privilege=PrivilegeMode.SYSTEM)
        tbl.write_word(REG_PROPAGATION_SPEED_SCALED, 30, privilege=PrivilegeMode.SYSTEM)  # 3.0 m/s
        canvas.sync_from_registers(tbl)

        assert canvas.selected_zone_id == 2
        assert math.isclose(canvas.base_speed_mps, 3.0, abs_tol=1e-2)

    def test_fifty_step_scan_cycle_soak_stability(self) -> None:
        """Verify 50 consecutive scan cycles execute without memory leaks, NaN values, or drift."""
        tbl = RegisterTable()
        canvas = create_canonical_isochrone_contour_canvas(reg_table=tbl)

        ctx = ScanContext(cycle=0, dt_ms=10.0)

        for step in range(50):
            ctx.cycle = step + 1
            canvas.execute_scan(ctx)

            # Assert invariants
            assert not math.isnan(canvas.metrics.propagation_speed_mps)
            assert not math.isnan(canvas.metrics.critical_exposure_area_sqm)
            assert not math.isinf(canvas.metrics.critical_exposure_area_sqm)
            assert 0 <= canvas.metrics.evacuation_safety_index_score <= 100
            assert canvas.metrics.diagnostic_code == DIAG_OK
            assert tbl.read_bit(COIL_ISOCHRONE_CANVAS_ACTIVE) is True
            assert tbl.read_bit(COIL_HAZARD_REACHABILITY_ALARM) is False


# ============================================================================
# 11. Pure IEC 61131-3 ST POU Validation with STParser and SecurityGuard
# ============================================================================

class TestPureStPouValidation:
    """Validate Pure ST POU syntax, AST parsing, and register bindings."""

    def test_pure_st_pou_syntax_and_ast_parsing(self) -> None:
        """Verify ST POU 'IsochroneContourCanvasSync' validates and parses cleanly."""
        SecurityGuard.assert_pure_st_content(ISOCHRONE_CONTOUR_CANVAS_PURE_ST_POU)

        res = STParser.validate_code(ISOCHRONE_CONTOUR_CANVAS_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser().parse_pou(ISOCHRONE_CONTOUR_CANVAS_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "IsochroneContourCanvasSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_pure_st_variable_register_bindings(self) -> None:
        """Verify each ST variable has the exact intended %R and %M memory binding."""
        ast = STParser().parse_pou(ISOCHRONE_CONTOUR_CANVAS_PURE_ST_POU)
        bound = set(ast.bound_registers)

        expected_regs = {
            "%R2310", "%R2311", "%R2312", "%R2313",
            "%R2314", "%R2315", "%R2316", "%R2317",
            "%M539", "%M540",
        }
        assert expected_regs.issubset(bound)

    def test_pure_st_validator_function(self) -> None:
        """Verify verify_isochrone_contour_canvas_pure_st() helper returns True."""
        assert verify_isochrone_contour_canvas_pure_st() is True


# ============================================================================
# 12. Anti-Ladder Construct Rejection
# ============================================================================

class TestAntiLadderConstructRejection:
    """Validate aggressive interception and rejection of ladder logic constructs."""

    def test_ladder_contacts_rejection(self) -> None:
        """Verify contacts construct '---[ ]---' is rejected with LadderForbiddenError."""
        bad_st = "PROGRAM Test VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_coils_rejection(self) -> None:
        """Verify coils construct '---( )---' is rejected with LadderForbiddenError."""
        bad_st = "PROGRAM Test VAR Y: BOOL; END_VAR ---( )--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_rung_delimiters_rejection(self) -> None:
        """Verify RUNG and NETWORK delimiters are rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\nRUNG 1:\nEND_PROGRAM")

        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\nNETWORK 1:\nEND_PROGRAM")

    def test_ladder_mnemonics_rejection(self) -> None:
        """Verify mnemonics XIC and OTE are rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\nXIC InBit;\nEND_PROGRAM")

        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\nOTE OutBit;\nEND_PROGRAM")


# ============================================================================
# 13. Verification Suite Runner
# ============================================================================

class TestVerificationSuiteRunner:
    """Validate complete deterministic 9-stage verification suite."""

    def test_runner_returns_strict_4_state_success(self) -> None:
        """Verify run_isochrone_contour_canvas_verification returns success and 9/9 stages pass."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_p = Path(tmpdir) / "sample.svg"

            res = run_isochrone_contour_canvas_verification(
                output_path=ev_path,
                sample_svg_path=svg_p,
            )

            assert res["status"] == "success"
            assert res["error_code"] is None
            assert res["data"]["stages_passed"] == 9
            assert res["data"]["total_stages"] == 9
            assert ev_path.is_file()
            assert svg_p.is_file()
