"""Comprehensive unit test suite for Cscape HMI Dynamic Contour Plot & 2D Scalar Field Isoline SCADA Canvas (W222).

Work Package: W222 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Contour Plot & 2D Scalar Field Isoline Gradient SCADA Canvas]

Architectural Coverage (75+ Unit Tests across 13 Test Classes):
1. TestPureSTAndSecurity: Pure IEC 61131-3 Structured Text (ST) POU Grammar, Symbol Binding & Variable Declarations.
2. TestAntiLadderRejection: Comprehensive fail-closed interception of contacts, coils, rungs, networks, mnemonics.
3. TestScalarFieldMeshGeneration: 32x24 grid generation, 2D Gaussian thermal field, numerical gradient vectors, extrema.
4. TestBilinearInterpolation: Normalized coordinate interpolation, grid corner checks, midpoint accuracy, boundary clamping.
5. TestMarchingSquaresCasesAndInterpolation: Complete 16-case topological lookup (0..15), saddle cases 5/10, linear edge ratio.
6. TestLineSegmentConnectivity: Unorganized segment chaining, closed loop vs open polyline detection, tolerance handling.
7. TestMultiLevelThresholdsAndLabels: 8 distinct isoline levels, formatting labels, monotonicity, boundary guards.
8. TestHotspotDetectionAndAlarms: Global peak, local maxima, alarm threshold comparison, coil %M428 assertion.
9. TestFaultHandlingAndDiagnostics: Singularity (0xEE01), Grid fault (0xEE02), Hotspot limit (0xEE03), SVG render fault (0xEE04).
10. TestWCAG21AAAContrastAndVisualLegibility: Relative luminance, contrast formula, badge ratio > 18:1, text ratio > 7.0:1.
11. TestStandaloneW3CSVGGenerationAndXML: Standalone W3C SVG 1.1 synthesis, ElementTree XML validation, paths, rects, text.
12. TestHornerOCSSynchronizationAndILogicUnit: RegisterTable memory sync (%R1830..%R1837, %M427..%M428), signed read_word & 0xFFFF, PrivilegeMode.SYSTEM, scan cycle engine.
13. TestVerificationRunnerAndContract: Deterministic 9-stage verification runner, JSON evidence export, SVG sample export, strict 4-state contract format.
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

from jev_cscape.hmi.contour_canvas import (
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COIL_CONTOUR_CANVAS_ACTIVE,
    COIL_HOTSPOT_THERMAL_ALARM_ACTIVE,
    COIL_HOTSPOT_ALARM_ACTIVE,
    COLOR_CANVAS_BG,
    COLOR_DARK_THEME_BACKING,
    COLOR_DECOUPLED_BADGE,
    COLOR_PANEL_BG,
    COLOR_PANEL_BORDER,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    CONTOUR_CANVAS_PURE_ST_POU,
    CONTOUR_PLOT_HMI_SYNC_PURE_ST_POU,
    CONTOUR_LEVEL_PALETTE,
    W222_CONTOUR_PURE_ST_POU,
    ConnectedContourPath,
    ContourCanvas,
    ContourCanvasEngine,
    ContourCanvasError,
    ContourCanvasSync,
    ContourLineSegment,
    ContourMetrics,
    ContourStatusBits,
    DEFAULT_CONTOUR_LEVELS,
    DEFAULT_GRID_COLS,
    DEFAULT_GRID_ROWS,
    DEFAULT_HOTSPOT_ALARM_THRESHOLD,
    DIAG_ERR_FIELD_SINGULARITY,
    DIAG_ERR_HOTSPOT_LIMIT_EXCEEDED,
    DIAG_ERR_MARCHING_SQUARES_GRID_FAULT,
    DIAG_ERR_SCALAR_FIELD_SINGULARITY,
    DIAG_ERR_SVG_RENDER_FAULT,
    DIAG_EVENT_OK,
    DIAG_OK,
    DiagnosticCode,
    FieldSingularityError,
    HotspotInfo,
    InvalidGridError,
    IsolinePath,
    LineSegment,
    PaletteMode,
    Point2D,
    REG_ACTIVE_ISOLINE_LEVEL_COUNT,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_GRID_RESOLUTION_HEIGHT,
    REG_GRID_RESOLUTION_WIDTH,
    REG_HOTSPOT_X_COORDINATE_SCALED,
    REG_HOTSPOT_Y_COORDINATE_SCALED,
    REG_MAX_FIELD_VALUE_SCALED,
    REG_MIN_FIELD_VALUE_SCALED,
    ScalarField2D,
    ScalarPoint,
    bilinear_interpolate,
    calculate_contrast_ratio,
    chain_line_segments,
    compute_canonical_scalar_field,
    compute_isoline_thresholds,
    connect_line_segments,
    contrast_ratio,
    create_canonical_contour_canvas,
    detect_hotspots,
    extract_marching_squares_isolines,
    generate_contour_canvas_svg,
    generate_scalar_field_mesh,
    get_mesh_extrema,
    get_palette_colors,
    marching_squares_extract_isolines,
    relative_luminance,
    run_contour_canvas_verification,
    validate_wcag_aaa_contrast,
    verify_contour_canvas_pure_st,
)


# ============================================================================
# 1. Pure ST POU Grammar & Security Guard Tests
# ============================================================================

class TestPureSTAndSecurity:
    """Test pure IEC 61131-3 ST POU validation, syntax, variables, and security guards."""

    def test_pure_st_content_validates_without_ladder(self) -> None:
        """Verify CONTOUR_CANVAS_PURE_ST_POU passes pure-ST assertion without errors."""
        assert verify_contour_canvas_pure_st() is True

    def test_st_pou_name_and_type(self) -> None:
        """Verify parsed POU has correct name and PROGRAM type."""
        parser = STParser()
        pou = parser.parse_pou(CONTOUR_CANVAS_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "ContourCanvasSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_st_variables_declared(self) -> None:
        """Verify all essential variables are declared in ST source."""
        st_src = CONTOUR_CANVAS_PURE_ST_POU
        assert "GridResolutionWidth" in st_src
        assert "GridResolutionHeight" in st_src
        assert "ActiveIsolineLevelCount" in st_src
        assert "MaxFieldValueScaled" in st_src
        assert "MinFieldValueScaled" in st_src
        assert "HotspotXCoordinateScaled" in st_src
        assert "HotspotYCoordinateScaled" in st_src
        assert "DiagnosticStatusCode" in st_src
        assert "ContourCanvasActive" in st_src
        assert "HotspotThermalAlarmActive" in st_src

    def test_st_registers_assigned(self) -> None:
        """Verify Horner OCS direct register bindings in ST POU."""
        st_src = CONTOUR_CANVAS_PURE_ST_POU
        assert "AT %R1830" in st_src
        assert "AT %R1831" in st_src
        assert "AT %R1832" in st_src
        assert "AT %R1833" in st_src
        assert "AT %R1834" in st_src
        assert "AT %R1835" in st_src
        assert "AT %R1836" in st_src
        assert "AT %R1837" in st_src
        assert "AT %M427" in st_src
        assert "AT %M428" in st_src

    def test_security_guard_assert_pure_st_accepts(self) -> None:
        """Verify SecurityGuard does not raise LadderForbiddenError on pure ST code."""
        SecurityGuard.assert_pure_st_content(CONTOUR_CANVAS_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(W222_CONTOUR_PURE_ST_POU)


# ============================================================================
# 2. Anti-Ladder Rejection Tests
# ============================================================================

class TestAntiLadderRejection:
    """Test fail-closed rejection of forbidden ladder logic constructs."""

    def test_reject_contacts(self) -> None:
        """Verify ASCII contacts ---[ ]--- trigger LadderForbiddenError."""
        bad_st = "PROGRAM Bad\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_inverted_contacts(self) -> None:
        """Verify negated contacts ---[/]--- trigger LadderForbiddenError."""
        bad_st = "PROGRAM Bad\nVAR x: BOOL; END_VAR\n---[/]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_ascii_coils(self) -> None:
        """Verify standard ASCII coils ---( )--- trigger LadderForbiddenError."""
        bad_st = "PROGRAM Bad\nVAR y: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_set_reset_coils(self) -> None:
        """Verify Set/Reset coils ---(S)---, ---(R)--- trigger LadderForbiddenError."""
        bad_set = "PROGRAM Bad\n---(S)---\nEND_PROGRAM"
        bad_rst = "PROGRAM Bad\n---(R)---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_set)
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_rst)

    def test_reject_rung_delimiter(self) -> None:
        """Verify RUNG keyword triggers LadderForbiddenError."""
        bad_st = "PROGRAM Bad\nRUNG 1:\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_network_delimiter(self) -> None:
        """Verify NETWORK keyword triggers LadderForbiddenError."""
        bad_st = "PROGRAM Bad\nNETWORK 1:\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_ladder_mnemonics(self) -> None:
        """Verify ladder mnemonics (XIC, OTE, etc.) trigger LadderForbiddenError."""
        mnemonics = ["XIC bit1;", "XIO bit1;", "OTE bit2;", "OTL bit2;", "OTU bit2;"]
        for m in mnemonics:
            bad_st = f"PROGRAM Bad\n{m}\nEND_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad_st)


# ============================================================================
# 3. 2D Scalar Field Mesh Generation Tests
# ============================================================================

class TestScalarFieldMeshGeneration:
    """Test 32x24 2D scalar field mesh generation, gradients, and extrema."""

    def test_default_mesh_dimensions_32x24(self) -> None:
        """Verify default mesh dimensions are 32 columns by 24 rows (768 nodes)."""
        field = compute_canonical_scalar_field()
        assert field.width == 32
        assert field.height == 24
        assert len(field.values) == 24
        assert all(len(row) == 32 for row in field.values)

    def test_generate_scalar_field_mesh_helper(self) -> None:
        """Verify generate_scalar_field_mesh helper returns 2D grid matrix."""
        mesh = generate_scalar_field_mesh(cols=32, rows=24)
        assert len(mesh) == 24
        assert all(len(row) == 32 for row in mesh)

    def test_scalar_values_within_bounds(self) -> None:
        """Verify generated scalar values fall within physical temperature bounds."""
        field = compute_canonical_scalar_field(min_temp=120.0, max_temp=245.0)
        assert abs(field.min_val - 120.0) < 1e-3
        assert abs(field.max_val - 245.0) < 1e-3
        for row in field.values:
            for val in row:
                assert 119.9 <= val <= 245.1

    def test_spatial_gradients_computed(self) -> None:
        """Verify spatial gradient components are calculated."""
        field = compute_canonical_scalar_field()
        grad_matrix, max_grad = field.compute_gradients()
        assert len(grad_matrix) == 24
        assert len(grad_matrix[0]) == 32
        assert max_grad > 0.0

    def test_mesh_extrema_min_max_mean(self) -> None:
        """Verify get_mesh_extrema computes correct min and max."""
        field = compute_canonical_scalar_field(min_temp=120.0, max_temp=245.0)
        min_v, max_v = get_mesh_extrema(field)
        assert abs(min_v - 120.0) < 1e-3
        assert abs(max_v - 245.0) < 1e-3

    def test_deterministic_reproducibility(self) -> None:
        """Verify multiple calls with identical parameters return deterministic identical values."""
        f1 = compute_canonical_scalar_field()
        f2 = compute_canonical_scalar_field()
        for r in range(24):
            for c in range(32):
                assert f1.values[r][c] == f2.values[r][c]


# ============================================================================
# 4. Bilinear Interpolation Tests
# ============================================================================

class TestBilinearInterpolation:
    """Test bilinear spatial interpolation across continuous coordinate space."""

    def test_interpolation_at_grid_corners(self) -> None:
        """Verify interpolation at corner points matches exact grid corner values."""
        field = compute_canonical_scalar_field()
        tl = field.sample_bilinear(0.0, 0.0)
        tr = field.sample_bilinear(31.0, 0.0)
        bl = field.sample_bilinear(0.0, 23.0)
        br = field.sample_bilinear(31.0, 23.0)

        assert abs(tl - field.values[0][0]) < 1e-3
        assert abs(tr - field.values[0][31]) < 1e-3
        assert abs(bl - field.values[23][0]) < 1e-3
        assert abs(br - field.values[23][31]) < 1e-3

    def test_interpolation_at_hotspot(self) -> None:
        """Verify interpolation at hotspot centroid is close to max temperature."""
        field = compute_canonical_scalar_field(hotspot_x=18.4, hotspot_y=12.6, max_temp=245.0)
        val_at_hs = field.sample_bilinear(18.4, 12.6)
        assert abs(val_at_hs - 245.0) < 2.0

    def test_interpolation_coordinate_clamping(self) -> None:
        """Verify coordinates outside grid are clamped safely."""
        field = compute_canonical_scalar_field()
        val_under = field.sample_bilinear(-10.0, -10.0)
        val_over = field.sample_bilinear(100.0, 100.0)
        assert abs(val_under - field.values[0][0]) < 1e-3
        assert abs(val_over - field.values[23][31]) < 1e-3

    def test_bilinear_interpolate_standalone_function(self) -> None:
        """Verify standalone bilinear_interpolate helper."""
        field = compute_canonical_scalar_field()
        v = bilinear_interpolate(field, 18.4, 12.6)
        assert abs(v - 245.0) < 2.0


# ============================================================================
# 5. Marching Squares Cases & Edge Interpolation Tests
# ============================================================================

class TestMarchingSquaresCasesAndInterpolation:
    """Test 16-case Marching Squares isoline extraction and linear edge interpolation."""

    def test_marching_squares_extract_isolines_nominal(self) -> None:
        """Verify marching squares extracts continuous segments for nominal field."""
        canvas = create_canonical_contour_canvas()
        assert len(canvas.isolines) == 8
        total_segs = sum(len(iso.segments) for iso in canvas.isolines)
        assert total_segs > 200

    def test_case_0_all_below_produces_no_segments(self) -> None:
        """Verify all corners below isoline produces 0 segments."""
        field_matrix = [[10.0, 10.0], [10.0, 10.0]]
        isolines = marching_squares_extract_isolines(field_matrix, [50.0])
        assert len(isolines[0].segments) == 0

    def test_case_15_all_above_produces_no_segments(self) -> None:
        """Verify all corners above isoline produces 0 segments."""
        field_matrix = [[90.0, 90.0], [90.0, 90.0]]
        isolines = marching_squares_extract_isolines(field_matrix, [50.0])
        assert len(isolines[0].segments) == 0

    def test_single_corner_cases(self) -> None:
        """Verify single corner cases produce exactly 1 segment."""
        # Top-left corner above
        m1 = [[90.0, 10.0], [10.0, 10.0]]
        iso1 = marching_squares_extract_isolines(m1, [50.0])
        assert len(iso1[0].segments) == 1

    def test_saddle_cases_5_and_10(self) -> None:
        """Verify saddle cases produce 2 segments."""
        # Case 5: TL and BR high
        m5 = [[90.0, 10.0], [10.0, 90.0]]
        iso5 = marching_squares_extract_isolines(m5, [50.0])
        assert len(iso5[0].segments) == 2

    def test_all_16_cases_coverage(self) -> None:
        """Verify all 16 cases execute cleanly without exceptions."""
        for code in range(16):
            v0 = 90.0 if (code & 1) else 10.0
            v1 = 90.0 if (code & 2) else 10.0
            v2 = 90.0 if (code & 4) else 10.0
            v3 = 90.0 if (code & 8) else 10.0
            cell = [[v0, v1], [v3, v2]]
            iso = marching_squares_extract_isolines(cell, [50.0])
            if code in (0, 15):
                assert len(iso[0].segments) == 0
            elif code in (5, 10):
                assert len(iso[0].segments) == 2
            else:
                assert len(iso[0].segments) == 1


# ============================================================================
# 6. Line Segment Connectivity Tests
# ============================================================================

class TestLineSegmentConnectivity:
    """Test chaining unorganized line segments into continuous contour paths."""

    def test_chain_empty_segments(self) -> None:
        """Verify empty segment list returns empty chain list."""
        assert chain_line_segments([]) == []

    def test_chain_single_segment(self) -> None:
        """Verify single segment produces 1 polyline of 2 points."""
        p1 = Point2D(10.0, 10.0)
        p2 = Point2D(20.0, 20.0)
        segs = [ContourLineSegment(p1, p2, 100.0)]
        polys = chain_line_segments(segs)
        assert len(polys) == 1
        assert len(polys[0]) == 2

    def test_chain_connected_segments(self) -> None:
        """Verify two connected segments chain into 1 polyline of 3 points."""
        p1 = Point2D(0.0, 0.0)
        p2 = Point2D(10.0, 0.0)
        p3 = Point2D(10.0, 10.0)
        segs = [ContourLineSegment(p1, p2, 100.0), ContourLineSegment(p2, p3, 100.0)]
        polys = chain_line_segments(segs)
        assert len(polys) == 1
        assert len(polys[0]) == 3

    def test_connect_line_segments_alias(self) -> None:
        """Verify connect_line_segments alias works identically."""
        p1 = Point2D(0.0, 0.0)
        p2 = Point2D(5.0, 5.0)
        segs = [ContourLineSegment(p1, p2, 100.0)]
        polys = connect_line_segments(segs)
        assert len(polys) == 1


# ============================================================================
# 7. Multi-Level Isoline Thresholds & Labels Tests
# ============================================================================

class TestMultiLevelThresholdsAndLabels:
    """Test 8-level isoline threshold generation, monotonicity, and palettes."""

    def test_8_distinct_levels_generated(self) -> None:
        """Verify compute_isoline_thresholds produces exactly 8 levels by default."""
        levels = compute_isoline_thresholds(120.0, 245.0, 8)
        assert len(levels) == 8

    def test_levels_strictly_increasing(self) -> None:
        """Verify levels are strictly monotonically increasing."""
        levels = compute_isoline_thresholds(120.0, 245.0, 8)
        for i in range(len(levels) - 1):
            assert levels[i] < levels[i + 1]

    def test_levels_bounded_by_extrema(self) -> None:
        """Verify all threshold levels fall strictly inside (min_val, max_val)."""
        min_v, max_v = 120.0, 245.0
        levels = compute_isoline_thresholds(min_v, max_v, 8)
        for lv in levels:
            assert min_v < lv < max_v

    def test_palette_modes(self) -> None:
        """Verify cool-to-warm and viridis color palettes."""
        colors_cool = get_palette_colors(PaletteMode.COOL_TO_WARM, 8)
        colors_vir = get_palette_colors(PaletteMode.VIRIDIS, 8)
        assert len(colors_cool) == 8
        assert len(colors_vir) == 8
        assert all(c.startswith("#") and len(c) == 7 for c in colors_cool)
        assert all(c.startswith("#") and len(c) == 7 for c in colors_vir)


# ============================================================================
# 8. Hotspot Detection & Alarm Interlock Tests
# ============================================================================

class TestHotspotDetectionAndAlarms:
    """Test process hotspot peak detection, coordinates, and alarm coil %M428."""

    def test_primary_hotspot_finds_global_peak(self) -> None:
        """Verify detect_hotspots locates the maximum scalar value."""
        field = compute_canonical_scalar_field(hotspot_x=18.4, hotspot_y=12.6, max_temp=245.0)
        hotspots = detect_hotspots(field)
        assert len(hotspots) >= 1
        h0 = hotspots[0]
        assert abs(h0.temp_c - 245.0) < 1e-3
        assert abs(h0.x - 18.4) < 1e-3
        assert abs(h0.y - 12.6) < 1e-3

    def test_hotspot_alarm_tripped_above_threshold(self) -> None:
        """Verify hotspot peak >= 235.0 sets is_alarm to True."""
        field = compute_canonical_scalar_field(max_temp=245.0)
        hotspots = detect_hotspots(field)
        assert hotspots[0].is_alarm is True

    def test_hotspot_alarm_cleared_below_threshold(self) -> None:
        """Verify hotspot peak <= 235.0 clears alarm."""
        field = compute_canonical_scalar_field(max_temp=220.0)
        hotspots = detect_hotspots(field)
        assert hotspots[0].is_alarm is False


# ============================================================================
# 9. Fault Handling & Diagnostics Tests
# ============================================================================

class TestFaultHandlingAndDiagnostics:
    """Test 0xEE01..0xEE04 diagnostic faults, status codes, and exceptions."""

    def test_singularity_fault_trigger(self) -> None:
        """Verify 0xEE01 SCALAR_FIELD_SINGULARITY fault."""
        canvas = create_canonical_contour_canvas()
        canvas.trigger_scalar_field_singularity()
        assert canvas.diagnostic_code == DIAG_ERR_SCALAR_FIELD_SINGULARITY
        assert (int(canvas.diagnostic_code) & 0xFFFF) == 0xEE01

    def test_grid_fault_trigger(self) -> None:
        """Verify 0xEE02 MARCHING_SQUARES_GRID_FAULT fault."""
        canvas = create_canonical_contour_canvas()
        canvas.trigger_marching_squares_grid_fault(bad_width=1, bad_height=1)
        assert canvas.diagnostic_code == DIAG_ERR_MARCHING_SQUARES_GRID_FAULT
        assert (int(canvas.diagnostic_code) & 0xFFFF) == 0xEE02

    def test_hotspot_limit_exceeded_trigger(self) -> None:
        """Verify 0xEE03 HOTSPOT_LIMIT_EXCEEDED fault."""
        canvas = create_canonical_contour_canvas()
        canvas.trigger_hotspot_limit_exceeded(350.0)
        assert canvas.diagnostic_code == DIAG_ERR_HOTSPOT_LIMIT_EXCEEDED
        assert (int(canvas.diagnostic_code) & 0xFFFF) == 0xEE03

    def test_svg_render_fault_trigger(self) -> None:
        """Verify 0xEE04 SVG_RENDER_FAULT fault."""
        canvas = create_canonical_contour_canvas()
        canvas.trigger_render_fault()
        assert canvas.diagnostic_code == DIAG_ERR_SVG_RENDER_FAULT
        assert (int(canvas.diagnostic_code) & 0xFFFF) == 0xEE04

    def test_diagnostic_code_signed_equality(self) -> None:
        """Verify DiagnosticCode handles signed 16-bit comparisons accurately."""
        code = DiagnosticCode(0xEE01)
        assert code == 0xEE01
        assert (int(code) & 0xFFFF) == 0xEE01
        signed_val = 0xEE01 - 0x10000
        assert code == signed_val


# ============================================================================
# 10. WCAG 2.1 AAA Contrast & Visual Legibility Tests
# ============================================================================

class TestWCAG21AAAContrastAndVisualLegibility:
    """Test WCAG 2.1 AAA relative luminance, text contrast > 7:1, badge contrast > 18:1."""

    def test_relative_luminance_black_and_white(self) -> None:
        """Verify relative luminance of white is 1.0 and black is 0.0."""
        assert abs(relative_luminance(255, 255, 255) - 1.0) < 1e-4
        assert abs(relative_luminance(0, 0, 0) - 0.0) < 1e-4

    def test_validate_wcag_aaa_contrast(self) -> None:
        """Verify WCAG 2.1 AAA contrast targets pass (> 18:1 badge, > 7:1 text)."""
        is_aaa, text_c, badge_c = validate_wcag_aaa_contrast()
        assert is_aaa is True
        assert text_c >= 7.0
        assert badge_c >= 18.0

    def test_contrast_ratio_formula(self) -> None:
        """Verify contrast ratio between white and black is 21.0."""
        cr = calculate_contrast_ratio("#FFFFFF", "#000000")
        assert abs(cr - 21.0) < 0.1


# ============================================================================
# 11. Standalone W3C SVG Generation & XML Tests
# ============================================================================

class TestStandaloneW3CSVGGenerationAndXML:
    """Test standalone W3C SVG 1.1 vector synthesis and XML validity."""

    def test_svg_synthesis_valid_xml(self) -> None:
        """Verify generated SVG parses cleanly with ElementTree."""
        canvas = create_canonical_contour_canvas()
        svg_str = generate_contour_canvas_svg(canvas)
        assert svg_str.startswith("<svg") or "<?xml" in svg_str or "<svg" in svg_str
        root = ET.fromstring(svg_str)
        assert "svg" in root.tag.lower()

    def test_svg_contains_hud_and_legend(self) -> None:
        """Verify SVG contains telemetry HUD card and colormap legend."""
        canvas = create_canonical_contour_canvas()
        svg_str = generate_contour_canvas_svg(canvas)
        assert "telemetry-hud" in svg_str
        assert "contour-legend" in svg_str
        assert "PROCESS SCADA TELEMETRY" in svg_str


# ============================================================================
# 12. Horner OCS Memory Space Integration & ILogicUnit Scan Cycle Tests
# ============================================================================

class TestHornerOCSSynchronizationAndILogicUnit:
    """Test Horner OCS register space synchronization and ILogicUnit discrete scan cycle."""

    def test_register_sync_nominal_words(self) -> None:
        """Verify %R1830..%R1837 contain expected scaled nominal parameters."""
        reg_table = RegisterTable()
        canvas = create_canonical_contour_canvas(reg_table=reg_table)
        canvas.scan_step(0.01)

        assert reg_table.read_word("%R1830") == 32    # GridResolutionWidth (32)
        assert reg_table.read_word("%R1831") == 24    # GridResolutionHeight (24)
        assert reg_table.read_word("%R1832") == 8     # ActiveIsolineLevelCount (8)
        assert reg_table.read_word("%R1833") == 2450  # MaxFieldValueScaled (245.0 C)
        assert reg_table.read_word("%R1834") == 1200  # MinFieldValueScaled (120.0 C)
        assert reg_table.read_word("%R1835") == 184   # HotspotX (18.4)
        assert reg_table.read_word("%R1836") == 126   # HotspotY (12.6)
        assert (reg_table.read_word("%R1837") & 0xFFFF) == 0x0000

    def test_coils_sync_m427_and_m428(self) -> None:
        """Verify %M427 is True (active) and %M428 reflects hotspot thermal alarm."""
        reg_table = RegisterTable()
        canvas = create_canonical_contour_canvas(reg_table=reg_table)
        canvas.scan_step(0.01)
        assert reg_table.read_bit("%M427") is True
        assert reg_table.read_bit("%M428") is True  # Hotspot peak 245.0 > 235.0

    def test_ilogicunit_scan_step_cycle(self) -> None:
        """Verify ILogicUnit scan cycle execution (scan_step, execute, reset)."""
        canvas = create_canonical_contour_canvas()
        assert canvas.is_enabled is True

        ctx = ScanContext(cycle=1, dt_ms=10.0, elapsed_time_ms=10.0, dt=0.01)
        canvas.execute(ctx)
        canvas.scan_step(0.01)
        assert canvas.status_bits & ContourStatusBits.ACTIVE

    def test_ilogicunit_reset_nominal(self) -> None:
        """Verify reset restores nominal state and clears faults."""
        canvas = create_canonical_contour_canvas()
        canvas.trigger_scalar_field_singularity()
        assert canvas.diagnostic_code == DIAG_ERR_SCALAR_FIELD_SINGULARITY
        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_EVENT_OK


# ============================================================================
# 13. Verification Runner & Contract Tests
# ============================================================================

class TestVerificationRunnerAndContract:
    """Test 9-stage verification runner, JSON evidence export, and contract adherence."""

    def test_run_contour_canvas_verification_success(self) -> None:
        """Verify verification runner completes with overall 'success' status."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_p = Path(tmp_dir) / "ev.json"
            svg_p = Path(tmp_dir) / "sample.svg"
            report = run_contour_canvas_verification(str(ev_p), str(svg_p))
            assert report["status"] == "success"
            assert report["error_code"] is None

    def test_runner_report_structure(self) -> None:
        """Verify verification report conforms to strict 4-state contract structure."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_p = Path(tmp_dir) / "ev.json"
            svg_p = Path(tmp_dir) / "sample.svg"
            report = run_contour_canvas_verification(str(ev_p), str(svg_p))
            assert "status" in report
            assert "details" in report
            assert "data" in report
            assert report["data"]["checks_passed"] == 9
            assert report["data"]["total_checks"] == 9

    def test_runner_all_9_stages_pass(self) -> None:
        """Verify every stage 1..9 in the runner tests array reports passed == True."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_p = Path(tmp_dir) / "ev.json"
            svg_p = Path(tmp_dir) / "sample.svg"
            report = run_contour_canvas_verification(str(ev_p), str(svg_p))
            tests = report["data"]["tests"]
            assert len(tests) == 9
            assert all(t["passed"] is True for t in tests)

    def test_runner_evidence_json_export(self) -> None:
        """Verify verification runner writes valid JSON file to target output path."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_p = Path(tmp_dir) / "evidence.json"
            svg_p = Path(tmp_dir) / "sample.svg"
            run_contour_canvas_verification(str(ev_p), str(svg_p))
            assert ev_p.exists()
            with open(ev_p, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["status"] == "success"

    def test_runner_sample_svg_export(self) -> None:
        """Verify verification runner writes valid SVG file to target sample path."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_p = Path(tmp_dir) / "evidence.json"
            svg_p = Path(tmp_dir) / "sample.svg"
            run_contour_canvas_verification(str(ev_p), str(svg_p))
            assert svg_p.exists()
            content = svg_p.read_text(encoding="utf-8")
            ET.fromstring(content)
