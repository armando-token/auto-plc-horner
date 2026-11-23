"""Comprehensive pytest test suite for Cscape HMI Dynamic Contour Surface Heatmap SCADA Canvas (W246).

Work Package: Wave W246 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Contour Surface Heatmap Canvas]

Covers 110+ Deterministic Unit Tests across 14 Test Classes (including all 12 specified classes):
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit equality, hashing, enums, register names, coil addresses.
2. TestSensorGridMatrix: 8x8 matrix initialization, cell coordinates, peak/min value extraction, gradient calculations.
3. TestMarchingSquaresInterpolation: Isocline threshold crossing, contour segment generation, non-empty polygon paths.
4. TestCanvasGeometryAndLayout: 1200x750 viewport, bounds containment, cell spacing, non-negative dimensions.
5. TestHotspotAlarmCondition: Gradient > 45 °C/m or peak > 650 °C trips %M484 alarm, recovery reset.
6. TestSVGGenerationAndXMLSyntax: Standalone W3C SVG 1.1 generation, ElementTree XML validation, <path>, <polygon>, <rect> tags.
7. TestWCAG21AAAContrastAndVisualLegibility: WCAG 2.1 AAA relative luminance, contrast formulas, badge contrast > 18:1, text > 7:1.
8. TestHornerOCSSynchronizationAndRegisters: %R2070..%R2077 and %M483..%M484 bit-exact synchronization, PrivilegeMode.SYSTEM.
9. TestPureSTAndSecurity: STParser & SecurityGuard verification of ContourSurfaceCanvasSync POU.
10. TestAntiLadderRejection: Rejection of 6+ ladder constructs (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError.
11. TestILogicUnitCompliance: scan_step, step, execute, reset, 100-cycle soak stability.
12. TestVerificationRunnerAndContract: Deterministic 9-stage runner export and strict 4-state contract validation.
13. TestThermalColorScaleAndPalette: High-contrast 6-level thermal scale, temperature to level mapping, temperature to color mapping.
14. TestSafetyDiagnosticsAndInterlocks: 0x0000 nominal, 0xF801 (<3x3), 0xF802 (<2 levels), 0xF803 (min==max), 0xF804 (overflow), recovery.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Tuple
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.contour_surface_canvas import (
    ALARM_GRADIENT_THRESHOLD_C_M,
    ALARM_PEAK_TEMP_THRESHOLD_C,
    CANONICAL_LEVEL_THRESHOLDS,
    CANVAS_BOUNDS_HEIGHT,
    CANVAS_BOUNDS_WIDTH,
    CANVAS_BOUNDS_X,
    CANVAS_BOUNDS_Y,
    CANVAS_MAX_X,
    CANVAS_MAX_Y,
    CANVAS_MIN_X,
    CANVAS_MIN_Y,
    CANVAS_OVERFLOW,
    CANVAS_OVERFLOW_FAULT,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COIL_ALARM_ACTIVE,
    COIL_CANVAS_ACTIVE,
    COIL_CONTOUR_ACTIVE,
    COIL_CONTOUR_CANVAS_ACTIVE,
    COIL_CONTOUR_SURFACE_ACTIVE,
    COIL_GRADIENT_ALARM,
    COIL_HOTSPOT_ALARM,
    COIL_HOTSPOT_GRADIENT_ALARM,
    COIL_SURFACE_ACTIVE,
    COLOR_ACCENT_AMBER,
    COLOR_ACCENT_CRIMSON,
    COLOR_ACCENT_CYAN,
    COLOR_ACCENT_EMERALD,
    COLOR_CANVAS_BG,
    COLOR_DARK_THEME_BACKING,
    COLOR_DECOUPLED_BADGE,
    COLOR_PANEL_BG,
    COLOR_PANEL_BORDER,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    CONTOUR_OK,
    CONTOUR_PALETTE_6,
    CONTOUR_SURFACE_CANVAS_PURE_ST_POU,
    CONTOUR_SURFACE_CANVAS_SYNC_PURE_ST_POU,
    CONTOUR_SURFACE_OK,
    CanvasGeometry,
    CanvasOverflowError,
    ContourLineSegment,
    ContourPath,
    ContourSurfaceCanvas,
    ContourSurfaceCanvasDiagnosticCode,
    ContourSurfaceCanvasEngine,
    ContourSurfaceCanvasError,
    ContourSurfaceCanvasStatusBits,
    ContourSurfaceCanvasSync,
    ContourSurfaceDiagnosticCode,
    ContourSurfaceMetrics,
    ContourSurfaceStatusBits,
    DEGENERATE_RANGE,
    DEGENERATE_RANGE_FAULT,
    DIAG_CONTOUR_OK,
    DIAG_ERR_CANVAS_OVERFLOW,
    DIAG_ERR_DEGENERATE_RANGE,
    DIAG_ERR_GRID_DIMENSION_INVALID,
    DIAG_ERR_GRID_INVALID,
    DIAG_ERR_INSUFFICIENT_LEVELS,
    DIAG_EVENT_OK,
    DIAG_OK,
    DegenerateRangeError,
    DiagnosticCode,
    GRID_COLS,
    GRID_DIMENSION_INVALID,
    GRID_DIMENSION_INVALID_FAULT,
    GRID_INVALID,
    GRID_ROWS,
    GRADIENT_ALARM_THRESHOLD_MAGNITUDE,
    GridDimensionInvalidError,
    GridInvalidError,
    HEATMAP_HEIGHT,
    HEATMAP_ORIGIN_X,
    HEATMAP_ORIGIN_Y,
    HEATMAP_WIDTH,
    HUD_HEIGHT,
    HUD_ORIGIN_X,
    HUD_ORIGIN_Y,
    HUD_WIDTH,
    INSUFFICIENT_LEVELS,
    INSUFFICIENT_LEVELS_FAULT,
    InsufficientLevelsError,
    IsolinePath,
    LineSegment,
    MarchingSquaresInterpolator,
    NOMINAL_CONTOUR_LEVEL_COUNT,
    NOMINAL_CONTOUR_LEVELS_COUNT,
    NOMINAL_DIAGNOSTIC_CODE,
    NOMINAL_GRID_DIMENSION_X,
    NOMINAL_GRID_DIMENSION_Y,
    NOMINAL_HOTSPOT_COL,
    NOMINAL_HOTSPOT_INDEX,
    NOMINAL_HOTSPOT_ROW,
    NOMINAL_MAX_GRADIENT_C_M,
    NOMINAL_MIN_TEMPERATURE_C,
    NOMINAL_MIN_VALUE,
    NOMINAL_MIN_VALUE_SCALED,
    NOMINAL_OK,
    NOMINAL_PEAK_TEMPERATURE_C,
    NOMINAL_PEAK_VALUE,
    NOMINAL_PEAK_VALUE_SCALED,
    NOMINAL_SELECTED_CELL_INDEX,
    PEAK_ALARM_THRESHOLD_C,
    PHYSICAL_DX_M,
    PHYSICAL_DY_M,
    PHYSICAL_SPACING_DX,
    PHYSICAL_SPACING_DY,
    PLOT_HEIGHT,
    PLOT_ORIGIN_X,
    PLOT_ORIGIN_Y,
    PLOT_WIDTH,
    Point2D,
    REG_CELL_INDEX,
    REG_CONTOUR_LEVELS,
    REG_CONTOUR_LEVEL_COUNT,
    REG_CONTOUR_LEVELS_COUNT,
    REG_DIAG_CODE,
    REG_DIAGNOSTIC_CODE,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_GRID_COLS,
    REG_GRID_DIM_X,
    REG_GRID_DIM_Y,
    REG_GRID_DIMENSION,
    REG_GRID_DIMENSION_X,
    REG_GRID_DIMENSION_Y,
    REG_GRID_ROWS,
    REG_HOTSPOT_INDEX,
    REG_HOTSPOT_NODE_INDEX,
    REG_MAX_GRAD_SCALED,
    REG_MAX_GRADIENT_SCALED,
    REG_MEAN_GRADIENT_MAGNITUDE_SCALED,
    REG_MEAN_GRADIENT_SCALED,
    REG_MIN_TEMP_SCALED,
    REG_MIN_TEMPERATURE_SCALED,
    REG_MIN_VALUE_SCALED,
    REG_PEAK_TEMP_SCALED,
    REG_PEAK_TEMPERATURE_SCALED,
    REG_PEAK_VALUE_SCALED,
    REG_SELECTED_CELL_INDEX,
    REG_SELECTED_INDEX,
    ScalarMesh2D,
    SensorCell,
    SensorGrid,
    SensorGridMatrix,
    THERMAL_COLOR_SCALE,
    TOTAL_SENSOR_NODES,
    ThermalLevel,
    W246_CONTOUR_SURFACE_PURE_ST_POU,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    build_canonical_sensor_mesh,
    calculate_contrast_ratio,
    chain_line_segments,
    compute_canonical_sensor_grid,
    create_canonical_contour_surface_canvas,
    format_polyline_path_data,
    generate_contour_surface_canvas_svg,
    is_point_within_canvas,
    marching_squares_extract_isoclines,
    marching_squares_extract_isolines,
    relative_luminance,
    run_contour_surface_canvas_verification,
    srgb_channel_to_linear,
    temperature_to_color,
    temperature_to_level_index,
    validate_canvas_bounds,
    validate_wcag_aaa_contrast,
    verify_contour_surface_canvas_pure_st,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate DiagnosticCode signed/unsigned 16-bit equality, hashing, enums, registers, and coils."""

    def test_diagnostic_code_signed_unsigned_equality_ok(self) -> None:
        diag = DiagnosticCode(0x0000)
        assert diag == 0
        assert diag == 0x0000
        assert diag == DIAG_EVENT_OK
        assert diag == DIAG_OK
        assert diag == CONTOUR_OK
        assert diag == CONTOUR_SURFACE_OK
        assert diag == DIAG_CONTOUR_OK
        assert diag == NOMINAL_OK

    def test_diagnostic_code_signed_unsigned_equality_0xf801(self) -> None:
        diag = DiagnosticCode(0xF801)
        assert diag == 0xF801
        assert diag == -2047  # 0xF801 as signed int16
        assert diag == DIAG_ERR_GRID_DIMENSION_INVALID
        assert diag == GRID_DIMENSION_INVALID
        assert diag == GRID_DIMENSION_INVALID_FAULT
        assert diag == DIAG_ERR_GRID_INVALID
        assert diag == GRID_INVALID

    def test_diagnostic_code_signed_unsigned_equality_0xf802(self) -> None:
        diag = DiagnosticCode(0xF802)
        assert diag == 0xF802
        assert diag == -2046  # 0xF802 as signed int16
        assert diag == DIAG_ERR_INSUFFICIENT_LEVELS
        assert diag == INSUFFICIENT_LEVELS
        assert diag == INSUFFICIENT_LEVELS_FAULT

    def test_diagnostic_code_signed_unsigned_equality_0xf803(self) -> None:
        diag = DiagnosticCode(0xF803)
        assert diag == 0xF803
        assert diag == -2045  # 0xF803 as signed int16
        assert diag == DIAG_ERR_DEGENERATE_RANGE
        assert diag == DEGENERATE_RANGE
        assert diag == DEGENERATE_RANGE_FAULT

    def test_diagnostic_code_signed_unsigned_equality_0xf804(self) -> None:
        diag = DiagnosticCode(0xF804)
        assert diag == 0xF804
        assert diag == -2044  # 0xF804 as signed int16
        assert diag == DIAG_ERR_CANVAS_OVERFLOW
        assert diag == CANVAS_OVERFLOW
        assert diag == CANVAS_OVERFLOW_FAULT

    def test_diagnostic_code_hashing(self) -> None:
        d1 = DiagnosticCode(0xF801)
        d2 = DiagnosticCode(0xF801)
        assert hash(d1) == hash(d2)
        diag_map = {d1: "grid_invalid"}
        assert diag_map[d2] == "grid_invalid"

    def test_diagnostic_code_non_int_comparison(self) -> None:
        diag = DiagnosticCode(0xF801)
        assert diag != "0xF801"
        assert diag is not None

    def test_diagnostic_code_subclass_int(self) -> None:
        c = DiagnosticCode(0xF801)
        assert isinstance(c, int)
        assert (c + 1) == 0xF802
        assert (int(c) & 0xFFFF) == 0xF801

    def test_thermal_level_enum_values(self) -> None:
        assert ThermalLevel.LEVEL_0_CYAN == 0
        assert ThermalLevel.LEVEL_1_EMERALD == 1
        assert ThermalLevel.LEVEL_2_LIME == 2
        assert ThermalLevel.LEVEL_3_YELLOW == 3
        assert ThermalLevel.LEVEL_4_ORANGE == 4
        assert ThermalLevel.LEVEL_5_CRIMSON == 5

    def test_status_bits_values(self) -> None:
        assert ContourSurfaceStatusBits.NOMINAL_OPERATION == 1
        assert ContourSurfaceStatusBits.CANVAS_ACTIVE == 2
        assert ContourSurfaceStatusBits.HOTSPOT_GRADIENT_ALARM == 4
        assert ContourSurfaceStatusBits.SURFACE_EVALUATED == 8
        assert ContourSurfaceStatusBits.ISOCLINES_EXTRACTED == 16
        assert ContourSurfaceStatusBits.GRID_DIMENSION_FAULT == 32
        assert ContourSurfaceStatusBits.INSUFFICIENT_LEVELS_FAULT == 64
        assert ContourSurfaceStatusBits.DEGENERATE_RANGE_FAULT == 128
        assert ContourSurfaceStatusBits.CANVAS_OVERFLOW_FAULT == 256
        assert ContourSurfaceStatusBits.SVG_VALID == 512
        assert ContourSurfaceStatusBits.WCAG_AAA_VERIFIED == 1024
        assert ContourSurfaceCanvasStatusBits == ContourSurfaceStatusBits

    def test_status_bits_bitwise_operations(self) -> None:
        bits = ContourSurfaceStatusBits.CANVAS_ACTIVE | ContourSurfaceStatusBits.ISOCLINES_EXTRACTED
        assert bits & ContourSurfaceStatusBits.CANVAS_ACTIVE
        assert bits & ContourSurfaceStatusBits.ISOCLINES_EXTRACTED
        assert not (bits & ContourSurfaceStatusBits.HOTSPOT_GRADIENT_ALARM)

    def test_register_names_and_aliases(self) -> None:
        assert REG_GRID_DIMENSION_X == "%R2070"
        assert REG_GRID_DIMENSION_Y == "%R2071"
        assert REG_CONTOUR_LEVELS_COUNT == "%R2072"
        assert REG_PEAK_VALUE_SCALED == "%R2073"
        assert REG_MIN_VALUE_SCALED == "%R2074"
        assert REG_MEAN_GRADIENT_MAGNITUDE_SCALED == "%R2075"
        assert REG_SELECTED_CELL_INDEX == "%R2076"
        assert REG_DIAGNOSTIC_CODE == "%R2077"

        assert REG_GRID_COLS == REG_GRID_DIMENSION_X
        assert REG_GRID_ROWS == REG_GRID_DIMENSION_Y
        assert REG_CONTOUR_LEVELS == REG_CONTOUR_LEVELS_COUNT
        assert REG_PEAK_TEMP_SCALED == REG_PEAK_VALUE_SCALED
        assert REG_MIN_TEMP_SCALED == REG_MIN_VALUE_SCALED
        assert REG_MAX_GRAD_SCALED == REG_MEAN_GRADIENT_MAGNITUDE_SCALED
        assert REG_HOTSPOT_INDEX == REG_SELECTED_CELL_INDEX
        assert REG_DIAGNOSTIC_STATUS_CODE == REG_DIAGNOSTIC_CODE

    def test_coil_names_and_aliases(self) -> None:
        assert COIL_CONTOUR_CANVAS_ACTIVE == "%M483"
        assert COIL_HOTSPOT_GRADIENT_ALARM == "%M484"
        assert COIL_CANVAS_ACTIVE == COIL_CONTOUR_CANVAS_ACTIVE
        assert COIL_CONTOUR_ACTIVE == COIL_CONTOUR_CANVAS_ACTIVE
        assert COIL_CONTOUR_SURFACE_ACTIVE == COIL_CONTOUR_CANVAS_ACTIVE
        assert COIL_SURFACE_ACTIVE == COIL_CONTOUR_CANVAS_ACTIVE
        assert COIL_HOTSPOT_ALARM == COIL_HOTSPOT_GRADIENT_ALARM
        assert COIL_GRADIENT_ALARM == COIL_HOTSPOT_GRADIENT_ALARM
        assert COIL_ALARM_ACTIVE == COIL_HOTSPOT_GRADIENT_ALARM

    def test_color_constants_and_palette(self) -> None:
        assert COLOR_CANVAS_BG == "#0B0F19"
        assert COLOR_PANEL_BG == "#161B22"
        assert COLOR_PANEL_BORDER == "#21262D"
        assert COLOR_DECOUPLED_BADGE == "#050811"
        assert COLOR_TEXT_PRIMARY == "#F8FAFC" or COLOR_TEXT_PRIMARY == "#FFFFFF"
        assert len(CONTOUR_PALETTE_6) == 6


# ============================================================================
# 2. TestSensorGridMatrix
# ============================================================================

class TestSensorGridMatrix:
    """Validate 8x8 sensor matrix initialization, cell coordinates, peak/min value extraction, gradient calculations."""

    def test_canonical_mesh_dimensions(self) -> None:
        mesh = build_canonical_sensor_mesh()
        assert mesh.cols == 8
        assert mesh.rows == 8
        assert len(mesh.values) == 8
        assert all(len(row) == 8 for row in mesh.values)

    def test_sensor_grid_matrix_alias(self) -> None:
        assert SensorGridMatrix is ScalarMesh2D
        assert SensorGrid is ScalarMesh2D

    def test_canonical_mesh_extrema(self) -> None:
        mesh = build_canonical_sensor_mesh()
        min_v = min(min(r) for r in mesh.values)
        max_v = max(max(r) for r in mesh.values)
        assert abs(min_v - 350.0) < 1.0
        assert abs(max_v - 625.0) < 1.0
        assert mesh.min_temperature == min_v
        assert mesh.peak_temperature == max_v

    def test_canonical_mesh_peak_location(self) -> None:
        mesh = build_canonical_sensor_mesh()
        assert mesh.values[3][3] == 625.0
        r, c, peak = mesh.find_hotspot()
        assert r == 3
        assert c == 3
        assert peak == 625.0
        assert mesh.peak_coordinates == (3, 3)

    def test_cell_temperature_retrieval_and_mutation(self) -> None:
        mesh = build_canonical_sensor_mesh()
        assert mesh.get_cell(0, 0) == mesh.values[0][0]
        mesh.set_cell(2, 2, 450.5)
        assert mesh.get_cell(2, 2) == 450.5
        assert mesh.values[2][2] == 450.5

    def test_physical_cell_coordinates_mapping(self) -> None:
        mesh = build_canonical_sensor_mesh()
        coord = mesh.get_cell_coord(3, 4)
        assert abs(coord[0] - 4 * mesh.dx_meters) < 1e-6
        assert abs(coord[1] - 3 * mesh.dy_meters) < 1e-6

    def test_bilinear_interpolation_at_grid_nodes(self) -> None:
        mesh = build_canonical_sensor_mesh()
        for j in range(8):
            for i in range(8):
                sampled = mesh.sample_bilinear(float(i), float(j))
                assert abs(sampled - mesh.values[j][i]) < 1e-5

    def test_bilinear_interpolation_midpoint(self) -> None:
        mesh = build_canonical_sensor_mesh()
        mid = mesh.sample_bilinear(3.5, 3.5)
        assert 350.0 < mid < 625.0
        avg_corner = (mesh.values[3][3] + mesh.values[3][4] + mesh.values[4][3] + mesh.values[4][4]) / 4.0
        assert abs(mid - avg_corner) < 1e-5

    def test_bilinear_interpolation_clamping(self) -> None:
        mesh = build_canonical_sensor_mesh()
        val_edge = mesh.sample_bilinear(0.0, 0.0)
        val_outside = mesh.sample_bilinear(-10.0, -10.0)
        assert abs(val_edge - val_outside) < 1e-5

    def test_gradient_magnitude_calculation(self) -> None:
        mesh = build_canonical_sensor_mesh()
        grad_mat, max_g = mesh.compute_gradients()
        assert len(grad_mat) == 8
        assert len(grad_mat[0]) == 8
        assert max_g > 0.0
        assert abs(max_g - mesh.max_gradient) < 1e-6

    def test_validate_finite_returns_true(self) -> None:
        mesh = build_canonical_sensor_mesh()
        assert mesh.validate_finite() is True

    def test_compute_canonical_sensor_grid_matches_build_canonical(self) -> None:
        grid = compute_canonical_sensor_grid()
        assert grid.cols == 8
        assert grid.rows == 8
        assert grid.peak_temperature == 625.0

    def test_invalid_mesh_dimensions_raises(self) -> None:
        with pytest.raises(GridDimensionInvalidError):
            build_canonical_sensor_mesh(cols=2, rows=8)
        with pytest.raises(GridDimensionInvalidError):
            build_canonical_sensor_mesh(cols=8, rows=2)

    def test_degenerate_range_mesh_raises(self) -> None:
        with pytest.raises(DegenerateRangeError):
            build_canonical_sensor_mesh(min_temp=500.0, peak_temp=500.0)


# ============================================================================
# 3. TestMarchingSquaresInterpolation
# ============================================================================

class TestMarchingSquaresInterpolation:
    """Validate isocline threshold crossing, contour segment generation, and non-empty polygon paths."""

    def test_canonical_isoline_count(self) -> None:
        mesh = build_canonical_sensor_mesh()
        isolines = marching_squares_extract_isolines(mesh)
        assert len(isolines) == 5

    def test_isoline_thresholds_match_specification(self) -> None:
        mesh = build_canonical_sensor_mesh()
        isolines = marching_squares_extract_isolines(mesh)
        thresholds = [iso.threshold_c for iso in isolines]
        assert thresholds == CANONICAL_LEVEL_THRESHOLDS

    def test_contour_segments_generation_non_empty(self) -> None:
        mesh = build_canonical_sensor_mesh()
        isolines = marching_squares_extract_isolines(mesh)
        for iso in isolines:
            assert len(iso.segments) > 0
            assert len(iso.path_d) > 0
            assert iso.path_d.startswith("M ")

    def test_contour_line_segment_length_positive(self) -> None:
        p1 = Point2D(10.0, 20.0)
        p2 = Point2D(30.0, 50.0)
        seg = ContourLineSegment(p1, p2, 450.0)
        assert seg.p1 == p1
        assert seg.p2 == p2
        assert seg.isovalue == 450.0
        assert seg.length() > 0.0

    def test_chain_line_segments_empty(self) -> None:
        assert chain_line_segments([]) == []

    def test_chain_line_segments_connected(self) -> None:
        p1 = Point2D(0.0, 0.0)
        p2 = Point2D(1.0, 1.0)
        p3 = Point2D(2.0, 2.0)
        segs = [ContourLineSegment(p1, p2, 100.0), ContourLineSegment(p2, p3, 100.0)]
        polys = chain_line_segments(segs)
        assert len(polys) == 1
        assert len(polys[0]) == 3

    def test_format_polyline_path_data(self) -> None:
        poly = [[Point2D(10.0, 20.0), Point2D(30.0, 40.0)]]
        d = format_polyline_path_data(poly)
        assert d == "M 10.00 20.00 L 30.00 40.00"

    def test_format_polyline_closed_loop(self) -> None:
        poly = [[Point2D(0.0, 0.0), Point2D(10.0, 0.0), Point2D(10.0, 10.0), Point2D(0.0, 0.0)]]
        d = format_polyline_path_data(poly)
        assert d.endswith("Z")

    def test_marching_squares_extract_isoclines_wrapper(self) -> None:
        mesh = build_canonical_sensor_mesh()
        contours = marching_squares_extract_isoclines(mesh)
        assert len(contours) == 5
        assert isinstance(contours[0], IsolinePath)
        assert contours[0].isovalue == 400.0

    def test_marching_squares_interpolator_class(self) -> None:
        mesh = build_canonical_sensor_mesh()
        interp = MarchingSquaresInterpolator(mesh)
        contours = interp.extract_isoclines()
        assert len(contours) == 5

    def test_insufficient_levels_raises(self) -> None:
        mesh = build_canonical_sensor_mesh()
        with pytest.raises(InsufficientLevelsError):
            marching_squares_extract_isolines(mesh, thresholds=[450.0])

    def test_isoline_path_threshold_attribute(self) -> None:
        mesh = build_canonical_sensor_mesh()
        isolines = marching_squares_extract_isolines(mesh)
        for iso in isolines:
            assert iso.isovalue == iso.threshold_c


# ============================================================================
# 4. TestCanvasGeometryAndLayout
# ============================================================================

class TestCanvasGeometryAndLayout:
    """Validate 1200x750 viewport, bounds containment, cell spacing, non-negative dimensions."""

    def test_viewport_geometry_dimensions(self) -> None:
        assert CANVAS_VIEWPORT_WIDTH == 1200
        assert CANVAS_VIEWPORT_HEIGHT == 750

    def test_canvas_bounds_constants(self) -> None:
        assert CANVAS_BOUNDS_X == 20.0
        assert CANVAS_BOUNDS_Y == 86.0
        assert CANVAS_BOUNDS_WIDTH == 1160.0
        assert CANVAS_BOUNDS_HEIGHT == 644.0
        assert CANVAS_MIN_X == 20.0
        assert CANVAS_MAX_X == 1180.0
        assert CANVAS_MIN_Y == 86.0
        assert CANVAS_MAX_Y == 730.0

    def test_canvas_bounds_containment_in_viewport(self) -> None:
        assert CANVAS_MIN_X >= 0.0
        assert CANVAS_MIN_Y >= 0.0
        assert CANVAS_MAX_X <= CANVAS_VIEWPORT_WIDTH
        assert CANVAS_MAX_Y <= CANVAS_VIEWPORT_HEIGHT

    def test_heatmap_plot_dimensions_strictly_positive(self) -> None:
        assert HEATMAP_WIDTH > 0.0
        assert HEATMAP_HEIGHT > 0.0
        assert (HEATMAP_ORIGIN_X + HEATMAP_WIDTH) <= CANVAS_MAX_X
        assert (HEATMAP_ORIGIN_Y + HEATMAP_HEIGHT) <= CANVAS_MAX_Y

    def test_hud_card_dimensions_strictly_positive(self) -> None:
        assert HUD_WIDTH > 0.0
        assert HUD_HEIGHT > 0.0
        assert (HUD_ORIGIN_X + HUD_WIDTH) <= CANVAS_MAX_X
        assert (HUD_ORIGIN_Y + HUD_HEIGHT) <= CANVAS_MAX_Y

    def test_is_point_within_canvas_interior(self) -> None:
        assert is_point_within_canvas(100.0, 200.0) is True
        assert is_point_within_canvas(CANVAS_MIN_X, CANVAS_MIN_Y) is True
        assert is_point_within_canvas(CANVAS_MAX_X, CANVAS_MAX_Y) is True

    def test_is_point_within_canvas_outside(self) -> None:
        assert is_point_within_canvas(10.0, 200.0) is False
        assert is_point_within_canvas(100.0, 80.0) is False
        assert is_point_within_canvas(1200.0, 200.0) is False
        assert is_point_within_canvas(100.0, 750.0) is False

    def test_validate_canvas_bounds_raises_on_overflow(self) -> None:
        with pytest.raises(CanvasOverflowError):
            validate_canvas_bounds(15.0, 200.0)
        with pytest.raises(CanvasOverflowError):
            validate_canvas_bounds(100.0, 740.0)

    def test_canvas_geometry_class(self) -> None:
        geom = CanvasGeometry()
        assert geom.viewport_width == 1200
        assert geom.viewport_height == 750
        assert geom.contains_point(600.0, 375.0) is True
        assert geom.contains_point(-5.0, 100.0) is False

    def test_cell_spacing_positive(self) -> None:
        cell_w = HEATMAP_WIDTH / 7.0
        cell_h = HEATMAP_HEIGHT / 7.0
        assert cell_w > 0.0
        assert cell_h > 0.0


# ============================================================================
# 5. TestHotspotAlarmCondition
# ============================================================================

class TestHotspotAlarmCondition:
    """Validate gradient > 45 °C/m or peak > 650 °C trips %M484 alarm, recovery reset."""

    def test_nominal_alarm_inactive(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        assert canvas.hotspot_gradient_alarm is False
        assert canvas.reg_table.read_bit(COIL_HOTSPOT_GRADIENT_ALARM) is False

    def test_canonical_mesh_gradient_magnitude(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        assert 20.0 <= canvas.mean_gradient_magnitude <= 35.0
        assert canvas.mean_gradient_magnitude < GRADIENT_ALARM_THRESHOLD_MAGNITUDE

    def test_steep_gradient_triggers_alarm(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.trigger_steep_gradient(50.0)
        assert canvas.hotspot_gradient_alarm is True
        assert canvas.reg_table.read_bit(COIL_HOTSPOT_GRADIENT_ALARM) is True
        assert bool(canvas.status_bits & ContourSurfaceStatusBits.HOTSPOT_GRADIENT_ALARM) is True

    def test_runaway_peak_triggers_alarm(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.trigger_hotspot_overheat(680.0)
        assert canvas.hotspot_gradient_alarm is True
        assert canvas.reg_table.read_bit(COIL_HOTSPOT_GRADIENT_ALARM) is True
        assert bool(canvas.status_bits & ContourSurfaceStatusBits.HOTSPOT_GRADIENT_ALARM) is True

    def test_alarm_recovery_to_nominal(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.trigger_hotspot_overheat(700.0)
        assert canvas.hotspot_gradient_alarm is True
        assert canvas.reg_table.read_bit(COIL_HOTSPOT_GRADIENT_ALARM) is True

        canvas.reset_nominal()
        assert canvas.hotspot_gradient_alarm is False
        assert canvas.reg_table.read_bit(COIL_HOTSPOT_GRADIENT_ALARM) is False
        assert canvas.diagnostic_code == DIAG_EVENT_OK

    def test_alarm_threshold_constants(self) -> None:
        assert GRADIENT_ALARM_THRESHOLD_MAGNITUDE == 45.0
        assert PEAK_ALARM_THRESHOLD_C == 650.0
        assert ALARM_GRADIENT_THRESHOLD_C_M == 45.0
        assert ALARM_PEAK_TEMP_THRESHOLD_C == 650.0

    def test_scan_step_preserves_alarm_evaluation(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.trigger_hotspot_overheat(675.0)
        canvas.scan_step()
        assert canvas.hotspot_gradient_alarm is True
        assert canvas.reg_table.read_bit(COIL_HOTSPOT_GRADIENT_ALARM) is True

    def test_both_peak_and_gradient_high(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.trigger_hotspot_overheat(690.0)
        canvas.trigger_steep_gradient(55.0)
        assert canvas.hotspot_gradient_alarm is True
        assert canvas.reg_table.read_bit(COIL_HOTSPOT_GRADIENT_ALARM) is True

    def test_trigger_methods_update_scaled_registers(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.trigger_hotspot_overheat(660.0)
        assert canvas.reg_table.read_word(REG_PEAK_VALUE_SCALED) == 6600

    def test_reset_method_clears_alarm(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.trigger_steep_gradient(48.0)
        assert canvas.hotspot_gradient_alarm is True
        canvas.reset()
        assert canvas.hotspot_gradient_alarm is False


# ============================================================================
# 6. TestSVGGenerationAndXMLSyntax
# ============================================================================

class TestSVGGenerationAndXMLSyntax:
    """Validate standalone W3C SVG 1.1 generation, ElementTree XML validation, <path>, <polygon>, <rect> tags."""

    def test_render_svg_valid_xml(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        svg_xml = canvas.render_svg()
        root = ET.fromstring(svg_xml)
        assert root.tag.endswith("svg") or root.tag == "svg"

    def test_render_svg_dimensions(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        svg_xml = canvas.render_svg()
        root = ET.fromstring(svg_xml)
        assert root.attrib.get("width") == "1200"
        assert root.attrib.get("height") == "750"
        assert root.attrib.get("viewBox") == "0 0 1200 750"

    def test_render_svg_contains_required_elements(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        svg_xml = canvas.render_svg()
        root = ET.fromstring(svg_xml)
        paths = root.findall(".//{http://www.w3.org/2000/svg}path") or root.findall(".//path")
        lines = root.findall(".//{http://www.w3.org/2000/svg}line") or root.findall(".//line")
        circles = root.findall(".//{http://www.w3.org/2000/svg}circle") or root.findall(".//circle")
        rects = root.findall(".//{http://www.w3.org/2000/svg}rect") or root.findall(".//rect")

        assert len(paths) >= 1
        assert len(lines) >= 10
        assert len(circles) >= 64
        assert len(rects) >= 10

    def test_render_svg_contains_hud_and_legend(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        svg_xml = canvas.render_svg()
        assert "SCADA PROCESS TELEMETRY HUD" in svg_xml
        assert "PEAK TEMP" in svg_xml or "Peak Temp" in svg_xml or "%R2073" in svg_xml
        assert "WCAG 2.1 AAA" in svg_xml

    def test_standalone_generator_function(self) -> None:
        svg_str = generate_contour_surface_canvas_svg()
        assert svg_str.startswith("<svg") or "<svg" in svg_str
        root = ET.fromstring(svg_str)
        assert root is not None

    def test_svg_contains_defs_and_gradient(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        svg_xml = canvas.render_svg()
        assert "<defs>" in svg_xml
        assert "</defs>" in svg_xml


# ============================================================================
# 7. TestWCAG21AAAContrastAndVisualLegibility
# ============================================================================

class TestWCAG21AAAContrastAndVisualLegibility:
    """Validate WCAG 2.1 AAA relative luminance, contrast formulas, badge contrast > 18:1, text > 7:1."""

    def test_srgb_channel_to_linear(self) -> None:
        assert srgb_channel_to_linear(0) == 0.0
        assert abs(srgb_channel_to_linear(255) - 1.0) < 1e-4
        assert 0.0 < srgb_channel_to_linear(128) < 1.0

    def test_relative_luminance_black_white(self) -> None:
        lum_black = relative_luminance("#000000")
        lum_white = relative_luminance("#FFFFFF")
        assert abs(lum_black - 0.0) < 1e-5
        assert abs(lum_white - 1.0) < 1e-5

    def test_calculate_contrast_ratio_black_white(self) -> None:
        ratio = calculate_contrast_ratio("#FFFFFF", "#000000")
        assert abs(ratio - 21.0) < 1e-3

    def test_contrast_ratio_symmetry(self) -> None:
        cr1 = calculate_contrast_ratio("#FFFFFF", "#050811")
        cr2 = calculate_contrast_ratio("#050811", "#FFFFFF")
        assert abs(cr1 - cr2) < 1e-6

    def test_contrast_ratio_identity(self) -> None:
        assert abs(calculate_contrast_ratio("#161B22", "#161B22") - 1.0) < 1e-6

    def test_wcag_aaa_badge_contrast_exceeds_18_to_1(self) -> None:
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert ratio >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert ratio > 18.0

    def test_wcag_aaa_text_contrast_exceeds_7_to_1(self) -> None:
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_CANVAS_BG)
        assert ratio >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert ratio > 7.0

    def test_validate_wcag_aaa_contrast_helper(self) -> None:
        is_compliant, text_cr, badge_cr = validate_wcag_aaa_contrast()
        assert is_compliant is True
        assert badge_cr >= 18.0
        assert text_cr >= 7.0

    def test_wcag_targets_constants_values(self) -> None:
        assert WCAG_AAA_BADGE_CONTRAST_TARGET == 18.0
        assert WCAG_AAA_TEXT_CONTRAST_TARGET == 7.0

    def test_relative_luminance_monotonicity(self) -> None:
        assert relative_luminance("#111111") < relative_luminance("#888888") < relative_luminance("#EEEEEE")


# ============================================================================
# 8. TestHornerOCSSynchronizationAndRegisters
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Validate %R2070..%R2077 and %M483..%M484 bit-exact synchronization, PrivilegeMode.SYSTEM."""

    def test_initial_synchronization(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        rt = canvas.reg_table

        assert (rt.read_word(REG_GRID_DIMENSION_X) & 0xFFFF) == 8
        assert (rt.read_word(REG_GRID_DIMENSION_Y) & 0xFFFF) == 8
        assert (rt.read_word(REG_CONTOUR_LEVELS_COUNT) & 0xFFFF) == 6
        assert (rt.read_word(REG_PEAK_VALUE_SCALED) & 0xFFFF) == 6250
        assert (rt.read_word(REG_MIN_VALUE_SCALED) & 0xFFFF) == 3500
        assert (rt.read_word(REG_MEAN_GRADIENT_MAGNITUDE_SCALED) & 0xFFFF) == 2842
        assert (rt.read_word(REG_SELECTED_CELL_INDEX) & 0xFFFF) == 27
        assert (rt.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

        assert rt.read_bit(COIL_CONTOUR_CANVAS_ACTIVE) is True
        assert rt.read_bit(COIL_HOTSPOT_GRADIENT_ALARM) is False

    def test_select_cell_mutation(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.select_cell(4, 5)
        assert canvas.selected_cell_index == 37
        assert (canvas.reg_table.read_word(REG_SELECTED_CELL_INDEX) & 0xFFFF) == 37

    def test_set_cell_value_mutation(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.set_cell_value(3, 3, 640.0)
        assert canvas.mesh.values[3][3] == 640.0
        assert canvas.peak_value_c == 640.0
        assert (canvas.reg_table.read_word(REG_PEAK_VALUE_SCALED) & 0xFFFF) == 6400

    def test_sync_from_registers(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.reg_table.write_bit(COIL_CONTOUR_CANVAS_ACTIVE, False, privilege=PrivilegeMode.SYSTEM)
        canvas.sync_from_registers(canvas.reg_table)
        assert canvas.contour_canvas_active is False

    def test_privilege_mode_system_enforced(self) -> None:
        rt = RegisterTable()
        canvas = ContourSurfaceCanvas(reg_table=rt)
        canvas.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert (rt.read_word(REG_GRID_DIMENSION_X) & 0xFFFF) == 8

    def test_all_8_registers_bound(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        regs = [
            REG_GRID_DIMENSION_X,
            REG_GRID_DIMENSION_Y,
            REG_CONTOUR_LEVELS_COUNT,
            REG_PEAK_VALUE_SCALED,
            REG_MIN_VALUE_SCALED,
            REG_MEAN_GRADIENT_MAGNITUDE_SCALED,
            REG_SELECTED_CELL_INDEX,
            REG_DIAGNOSTIC_CODE,
        ]
        for reg in regs:
            val = canvas.reg_table.read_word(reg)
            assert isinstance(val, int)

    def test_coils_bit_exact(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        assert canvas.reg_table.read_bit(COIL_CONTOUR_CANVAS_ACTIVE) is True
        assert canvas.reg_table.read_bit(COIL_HOTSPOT_GRADIENT_ALARM) is False


# ============================================================================
# 9. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure IEC 61131-3 Structured Text (ST) POU grammar, bindings, and SecurityGuard."""

    def test_pure_st_content_passes_security_guard(self) -> None:
        SecurityGuard.assert_pure_st_content(CONTOUR_SURFACE_CANVAS_PURE_ST_POU)

    def test_pure_st_ast_structure(self) -> None:
        parser = STParser()
        pou = parser.parse_pou(CONTOUR_SURFACE_CANVAS_PURE_ST_POU)
        assert pou.name == "ContourSurfaceCanvasSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_pure_st_variable_bindings(self) -> None:
        parser = STParser()
        pou = parser.parse_pou(CONTOUR_SURFACE_CANVAS_PURE_ST_POU)
        var_names = {v.name: v.address_binding for v in pou.variables}
        assert var_names.get("GridDimensionX") == "%R2070"
        assert var_names.get("GridDimensionY") == "%R2071"
        assert var_names.get("ContourLevelsCount") == "%R2072"
        assert var_names.get("PeakValueScaled") == "%R2073"
        assert var_names.get("MinValueScaled") == "%R2074"
        assert var_names.get("MeanGradientMagnitudeScaled") == "%R2075"
        assert var_names.get("SelectedCellIndex") == "%R2076"
        assert var_names.get("DiagnosticCode") == "%R2077"
        assert var_names.get("ContourCanvasActive") == "%M483"
        assert var_names.get("HotspotGradientAlarm") == "%M484"

    def test_verify_helper_returns_true(self) -> None:
        assert verify_contour_surface_canvas_pure_st() is True

    def test_st_parser_validate_syntax(self) -> None:
        parser = STParser()
        result = parser.validate_code(CONTOUR_SURFACE_CANVAS_PURE_ST_POU)
        assert result.status == AgentStatus.SUCCESS

    def test_w246_pure_st_alias_match(self) -> None:
        assert W246_CONTOUR_SURFACE_PURE_ST_POU == CONTOUR_SURFACE_CANVAS_PURE_ST_POU
        assert CONTOUR_SURFACE_CANVAS_SYNC_PURE_ST_POU == CONTOUR_SURFACE_CANVAS_PURE_ST_POU


# ============================================================================
# 10. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Validate rejection of 6+ ladder constructs with LadderForbiddenError."""

    @pytest.mark.parametrize(
        "bad_snippet",
        [
            "---[ ]---",
            "---( )---",
            "---(L)---",
            "---(U)---",
            "RUNG 1: XIC %M483",
            "NETWORK 1: LD %R2070",
            "XIC StartExtraction",
            "OTE CoilHotspotAlarm",
            "PROGRAM Bad VAR x: BOOL; END_VAR ---[ / ]--- END_PROGRAM",
        ],
    )
    def test_forbidden_ladder_constructs_rejected(self, bad_snippet: str) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_snippet)


# ============================================================================
# 11. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate scan_step, step, execute, reset, 100-cycle soak stability."""

    def test_ilogicunit_interface_implementation(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        assert isinstance(canvas, ILogicUnit)

    def test_ilogicunit_properties(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        assert canvas.name == "ContourSurfaceCanvas"
        assert canvas.priority == 10
        assert canvas.is_enabled is True

    def test_ilogicunit_enable_toggle(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.is_enabled = False
        assert canvas.is_enabled is False
        canvas.is_enabled = True
        assert canvas.is_enabled is True

    def test_scan_step_and_step_execution(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.scan_step(dt=0.01)
        assert canvas.peak_value_scaled == 6250
        canvas.step()
        assert canvas.peak_value_scaled == 6250

    def test_execute_scan_context(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        ctx = ScanContext(cycle=1, dt_ms=10.0)
        canvas.execute(ctx)
        assert (canvas.reg_table.read_word(REG_GRID_DIMENSION_X) & 0xFFFF) == 8

    def test_reset_method(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.trigger_hotspot_overheat(680.0)
        assert canvas.hotspot_gradient_alarm is True
        canvas.reset()
        assert canvas.hotspot_gradient_alarm is False
        assert canvas.peak_value_c == NOMINAL_PEAK_VALUE

    def test_100_cycle_soak_stability(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        ctx = ScanContext(cycle=1, dt_ms=10.0)
        for i in range(100):
            ctx.cycle = i + 1
            canvas.execute(ctx)

        assert canvas.peak_value_scaled == 6250
        assert canvas.mean_gradient_magnitude_scaled == 2842
        assert not math.isnan(canvas.mean_gradient_magnitude)
        assert not math.isnan(canvas.peak_value_c)
        assert canvas.diagnostic_code == DIAG_EVENT_OK


# ============================================================================
# 12. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate deterministic 9-stage runner export and strict 4-state contract validation."""

    def test_verification_runner_returns_strict_4_state_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"

            res = run_contour_surface_canvas_verification(
                evidence_path=ev_path,
                sample_svg_path=svg_path,
            )

            assert isinstance(res, dict)
            assert res["status"] in ("success", "failed", "blocked", "inconclusive")
            assert res["status"] == "success"
            assert res["error_code"] is None
            assert "Deterministic verification" in res["details"]
            assert ev_path.exists()
            assert svg_path.exists()

    def test_runner_stages_count_is_9(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            res = run_contour_surface_canvas_verification(
                evidence_path=Path(tmpdir) / "ev.json",
                sample_svg_path=Path(tmpdir) / "s.svg",
            )
            data = res["data"]
            assert data["total_checks"] == 9
            assert data["checks_passed"] == 9
            assert len(data["tests"]) == 9

    def test_runner_all_stages_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            res = run_contour_surface_canvas_verification(
                evidence_path=Path(tmpdir) / "ev.json",
                sample_svg_path=Path(tmpdir) / "s.svg",
            )
            for t in res["data"]["tests"]:
                assert t["passed"] is True
                assert t["timing_ms"] >= 0.0

    def test_runner_data_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            res = run_contour_surface_canvas_verification(
                evidence_path=Path(tmpdir) / "ev.json",
                sample_svg_path=Path(tmpdir) / "s.svg",
            )
            data = res["data"]
            assert data["work_package"] == "W246"
            assert data["gate"] == "Gate G9 / G2"
            assert "Contour Surface Heatmap" in data["component"]

    def test_runner_evidence_file_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "ev.json"
            svg_path = Path(tmpdir) / "s.svg"
            run_contour_surface_canvas_verification(evidence_path=ev_path, sample_svg_path=svg_path)
            with open(ev_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert "metrics" in loaded["data"]

    def test_runner_svg_sample_valid_xml(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "ev.json"
            svg_path = Path(tmpdir) / "s.svg"
            run_contour_surface_canvas_verification(evidence_path=ev_path, sample_svg_path=svg_path)
            content = svg_path.read_text(encoding="utf-8")
            root = ET.fromstring(content)
            assert root.attrib.get("width") == "1200"


# ============================================================================
# 13. TestThermalColorScaleAndPalette
# ============================================================================

class TestThermalColorScaleAndPalette:
    """Validate 6-level thermal colormap and temperature mapping functions."""

    def test_thermal_color_scale_values(self) -> None:
        assert len(THERMAL_COLOR_SCALE) == 6
        assert THERMAL_COLOR_SCALE[0] == "#06B6D4"  # Cyan
        assert THERMAL_COLOR_SCALE[1] == "#10B981"  # Emerald
        assert THERMAL_COLOR_SCALE[2] == "#84CC16"  # Lime
        assert THERMAL_COLOR_SCALE[3] == "#EAB308"  # Yellow
        assert THERMAL_COLOR_SCALE[4] == "#F97316"  # Orange
        assert THERMAL_COLOR_SCALE[5] == "#EF4444"  # Crimson

    def test_temperature_to_level_mapping(self) -> None:
        assert temperature_to_level_index(380.0) == 0
        assert temperature_to_level_index(420.0) == 1
        assert temperature_to_level_index(480.0) == 2
        assert temperature_to_level_index(530.0) == 3
        assert temperature_to_level_index(580.0) == 4
        assert temperature_to_level_index(620.0) == 5

    def test_temperature_to_color_mapping(self) -> None:
        assert temperature_to_color(380.0) == "#06B6D4"
        assert temperature_to_color(620.0) == "#EF4444"


# ============================================================================
# 14. TestSafetyDiagnosticsAndInterlocks
# ============================================================================

class TestSafetyDiagnosticsAndInterlocks:
    """Validate safety diagnostics 0x0000, 0xF801..0xF804 and latching/recovery."""

    def test_diagnostic_nominal_ok(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.diagnostic_code == 0x0000

    def test_diagnostic_0xf801_grid_dimension_invalid(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.trigger_grid_dimension_invalid()
        assert canvas.diagnostic_code == DIAG_ERR_GRID_DIMENSION_INVALID
        assert canvas.diagnostic_code == 0xF801
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF801
        assert canvas.contour_canvas_active is False

    def test_diagnostic_0xf802_insufficient_levels(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.trigger_insufficient_levels()
        assert canvas.diagnostic_code == DIAG_ERR_INSUFFICIENT_LEVELS
        assert canvas.diagnostic_code == 0xF802
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF802

    def test_diagnostic_0xf803_degenerate_range(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.trigger_degenerate_range()
        assert canvas.diagnostic_code == DIAG_ERR_DEGENERATE_RANGE
        assert canvas.diagnostic_code == 0xF803
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF803

    def test_diagnostic_0xf804_canvas_overflow(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.trigger_canvas_overflow()
        assert canvas.diagnostic_code == DIAG_ERR_CANVAS_OVERFLOW
        assert canvas.diagnostic_code == 0xF804
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF804

    def test_nominal_reset_clears_all_faults(self) -> None:
        canvas = create_canonical_contour_surface_canvas()
        canvas.trigger_grid_dimension_invalid()
        assert canvas.diagnostic_code == 0xF801
        canvas.reset_nominal()
        assert canvas.diagnostic_code == 0x0000
        assert canvas.contour_canvas_active is True
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
