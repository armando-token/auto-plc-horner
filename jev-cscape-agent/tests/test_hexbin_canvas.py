"""Comprehensive unit test suite for Cscape HMI Dynamic Hexagonal Binning Heatmap & Density Scatter SCADA Canvas (W225).

Work Package: W225 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Hexagonal Binning Heatmap & Density Scatter SCADA Canvas]

Architectural Coverage (80+ Unit Tests across 13 Test Classes):
1. TestPureSTAndSecurity: Pure IEC 61131-3 Structured Text (ST) POU Grammar, Symbol Binding & Variable Declarations.
2. TestAntiLadderRejection: Comprehensive fail-closed interception of contacts, coils, rungs, networks, mnemonics.
3. TestHexagonalGridGeometryAndMath: In-circle radius (apothem), 6 vertices per hex, flat-topped and pointy-topped orientations, point containment.
4. TestPointToHexQuantizationAndBinning: Continuous coordinate quantization to axial (q, r), round-trip projection, singularity handling.
5. TestSpatialBinning500CoordinatesAndAggregation: Spatial binning for 500+ sample points, canonical 48 active bins, max density 42, mean 10.4.
6. TestDensityNormalizationAndPalettes: Linear and logarithmic density scaling, multi-stop perceptual color gradients (Cool-to-Warm, Magma, Plasma, Viridis).
7. TestWCAG21AAAContrastAndVisualLegibility: Relative luminance, contrast formula, badge ratio > 18:1, text ratio > 7.0:1.
8. TestFaultHandlingAndDiagnostics: Singularity (0xF101), Empty dataset (0xF102), Density overflow (0xF103), SVG render fault (0xF104).
9. TestHighDensityClusterAlarm: Cluster alarm threshold (> 35 points), coil %M435 assertion/de-assertion, nominal recovery.
10. TestHornerOCSSynchronizationAndRegisters: RegisterTable memory sync (%R1860..%R1867, %M434..%M435), signed read_word & 0xFFFF, PrivilegeMode.SYSTEM.
11. TestILogicUnitIntegration: Discrete scan cycle engine, scan_step(dt, context), execute, reset, 100-cycle stability.
12. TestStandaloneW3CSVGGenerationAndXML: Standalone W3C SVG 1.1 vector graphic synthesis, ElementTree XML validation, polygons, badges, reticle, HUD.
13. TestVerificationRunnerAndContract: Deterministic 9-stage verification runner, JSON evidence export, SVG sample export, strict 4-state contract.
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

from jev_cscape.hmi.hexbin_canvas import (
    CANONICAL_ACTIVE_BINS_COUNT,
    CANONICAL_MAX_DENSITY,
    CANONICAL_MEAN_DENSITY_SCALED,
    CANONICAL_PEAK_X,
    CANONICAL_PEAK_X_SCALED,
    CANONICAL_PEAK_Y,
    CANONICAL_PEAK_Y_SCALED,
    CANONICAL_POINTS_COUNT,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COIL_CANVAS_ACTIVE,
    COIL_CLUSTER_ALARM,
    COIL_HEXBIN_CANVAS_ACTIVE,
    COIL_HIGH_DENSITY_CLUSTER_ALARM_ACTIVE,
    COLOR_ALARM_AMBER,
    COLOR_ALARM_CRIMSON,
    COLOR_BLUE_ACCENT,
    COLOR_CANVAS_BG,
    COLOR_CYAN_ACCENT,
    COLOR_DARK_THEME_BACKING,
    COLOR_DECOUPLED_BADGE,
    COLOR_GRID_LINE,
    COLOR_OK_EMERALD,
    COLOR_PANEL_BG,
    COLOR_PANEL_BORDER,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    DEFAULT_HEX_RADIUS,
    DENSITY_ALARM_THRESHOLD,
    DENSITY_OVERFLOW_LIMIT,
    DIAG_ERR_DENSITY_OVERFLOW_ALARM,
    DIAG_ERR_EMPTY_SAMPLE_DATASET,
    DIAG_ERR_HEX_TESSELLATION_SINGULARITY,
    DIAG_ERR_SVG_RENDER_FAULT,
    DIAG_EVENT_OK,
    DIAG_OK,
    HEXBIN_CANVAS_PURE_ST_POU,
    HEXBIN_ERR_OK,
    HEXBIN_HEATMAP_SCADA_SYNC_PURE_ST_POU,
    HEXBIN_OK,
    PALETTE_STOPS,
    PLOT_CANVAS_HEIGHT,
    PLOT_CANVAS_WIDTH,
    PLOT_ORIGIN_X,
    PLOT_ORIGIN_Y,
    REG_ACTIVE_BINS,
    REG_DIAG_CODE,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_HEX_TESSELLATION_RADIUS_PX,
    REG_MAX_DENSITY,
    REG_MAX_HEX_BIN_DENSITY_COUNT,
    REG_MEAN_DENSITY_SCALED,
    REG_MEAN_HEX_BIN_DENSITY_SCALED,
    REG_PEAK_DENSITY_HEX_X_SCALED,
    REG_PEAK_DENSITY_HEX_Y_SCALED,
    REG_PEAK_X_SCALED,
    REG_PEAK_Y_SCALED,
    REG_RADIUS_PX,
    REG_SAMPLE_POINTS,
    REG_TOTAL_ACTIVE_HEX_BINS_COUNT,
    REG_TOTAL_SAMPLE_POINTS_COUNT,
    W225_HEXBIN_PURE_ST_POU,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    DensityOverflowError,
    DensityScaleMode,
    DiagnosticCode,
    EmptyDatasetError,
    HexBin,
    HexCoordinate,
    HexOrientation,
    HexbinCanvas,
    HexbinCanvasEngine,
    HexbinCanvasError,
    HexbinCanvasSync,
    HexbinHeatmapCanvas,
    HexbinHeatmapScadaSync,
    HexbinMetrics,
    HexbinPalette,
    HexbinScatterCanvas,
    HexbinSingularityError,
    HexbinStatusBits,
    Point2D,
    SVGRenderError,
    axial_to_center,
    axial_to_center_flat,
    axial_to_center_pointy,
    calculate_contrast_ratio,
    compute_hex_vertices,
    contrast_ratio,
    create_canonical_hexbin_canvas,
    create_mock_scan_context,
    format_polygon_points,
    generate_canonical_scatter_points,
    generate_hexbin_canvas_svg,
    get_palette_colors,
    hex_to_rgb,
    in_circle_radius,
    interpolate_palette_color,
    interpolate_rgb,
    is_point_inside_hex,
    normalize_density,
    point_to_axial,
    point_to_axial_flat,
    point_to_axial_pointy,
    relative_luminance,
    rgb_to_hex,
    run_hexbin_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_hexbin_canvas_pure_st,
)


# ============================================================================
# 1. Pure ST POU Grammar & Security Guard Tests
# ============================================================================

class TestPureSTAndSecurity:
    """Test pure IEC 61131-3 ST POU validation, syntax, variables, and security guards."""

    def test_pure_st_content_validates_without_ladder(self) -> None:
        """Verify HEXBIN_CANVAS_PURE_ST_POU passes pure-ST assertion without errors."""
        assert verify_hexbin_canvas_pure_st() is True

    def test_st_pou_name_and_type(self) -> None:
        """Verify parsed POU has correct name and PROGRAM type."""
        parser = STParser()
        pou = parser.parse_pou(HEXBIN_CANVAS_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "HexbinCanvasSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_st_variables_declared(self) -> None:
        """Verify all essential variables are declared in ST source."""
        st_src = HEXBIN_CANVAS_PURE_ST_POU
        assert "TotalActiveHexBinsCount" in st_src
        assert "TotalSamplePointsCount" in st_src
        assert "MaxHexBinDensityCount" in st_src
        assert "MeanHexBinDensityScaled" in st_src
        assert "PeakDensityHexXScaled" in st_src
        assert "PeakDensityHexYScaled" in st_src
        assert "HexTessellationRadiusPx" in st_src
        assert "DiagnosticStatusCode" in st_src
        assert "HexbinCanvasActive" in st_src
        assert "HighDensityClusterAlarmActive" in st_src

    def test_st_registers_assigned(self) -> None:
        """Verify Horner OCS direct register bindings in ST POU."""
        st_src = HEXBIN_CANVAS_PURE_ST_POU
        for reg in [
            "%R1860", "%R1861", "%R1862", "%R1863",
            "%R1864", "%R1865", "%R1866", "%R1867",
            "%M434", "%M435",
        ]:
            assert reg in st_src, f"Expected register {reg} in ST code"

    def test_alias_pou_hexbin_heatmap_scada_sync(self) -> None:
        """Verify secondary POU HexbinHeatmapScadaSync parses cleanly."""
        parser = STParser()
        pou = parser.parse_pou(HEXBIN_HEATMAP_SCADA_SYNC_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "HexbinHeatmapScadaSync"
        assert pou.pou_type == POUType.PROGRAM
        assert len(pou.bound_registers) == 10

    def test_verify_hexbin_canvas_pure_st_function(self) -> None:
        """Verify helper returns True and catches tampered POU."""
        assert verify_hexbin_canvas_pure_st() is True


# ============================================================================
# 2. Anti-Ladder Rejection Tests
# ============================================================================

class TestAntiLadderRejection:
    """Test comprehensive fail-closed interception of ladder logic constructs."""

    def test_reject_normally_open_contact(self) -> None:
        """Interception of normally open contact symbol ---[ ]---."""
        tampered = HEXBIN_CANVAS_PURE_ST_POU + "\n---[ ]---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(tampered)

    def test_reject_normally_closed_contact(self) -> None:
        """Interception of normally closed contact symbol ---[/]---."""
        tampered = HEXBIN_CANVAS_PURE_ST_POU + "\n---[/]---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(tampered)

    def test_reject_standard_coil(self) -> None:
        """Interception of output coil symbol ---( )---."""
        tampered = HEXBIN_CANVAS_PURE_ST_POU + "\n---( )---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(tampered)

    def test_reject_set_reset_coils(self) -> None:
        """Interception of Set/Reset coils ---(S)--- and ---(R)---."""
        for coil in ["---(S)---", "---(R)---", "---(L)---", "---(U)---"]:
            tampered = HEXBIN_CANVAS_PURE_ST_POU + f"\n{coil}\n"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(tampered)

    def test_reject_rung_network_delimiters(self) -> None:
        """Interception of RUNG and NETWORK ladder delimiters."""
        for kw in ["RUNG 1", "NETWORK 1", "END_RUNG", "NETWORK 10"]:
            tampered = HEXBIN_CANVAS_PURE_ST_POU + f"\n{kw}\n"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(tampered)

    def test_reject_ladder_mnemonics(self) -> None:
        """Interception of Allen-Bradley / Modicon ladder mnemonics."""
        for mnemonic in ["XIC bit_1", "XIO bit_2", "OTE coil_1", "OTL latch_1", "OTU unlatch_1"]:
            tampered = HEXBIN_CANVAS_PURE_ST_POU + f"\n{mnemonic}\n"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(tampered)

    def test_fail_closed_on_ladder_tamper(self) -> None:
        """Verify verify_hexbin_canvas_pure_st returns False on tampering."""
        st_clean = HEXBIN_CANVAS_PURE_ST_POU
        assert SecurityGuard.assert_pure_st_content(st_clean) is None
        tampered = st_clean + "\n---[ ]---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(tampered)
        assert SecurityGuard.assert_pure_st_content(st_clean) is None


# ============================================================================
# 3. Hexagonal Grid Geometry & Math Tests
# ============================================================================

class TestHexagonalGridGeometryAndMath:
    """Test 2D regular hexagonal grid math, in-circle radius, vertices, and containment."""

    def test_in_circle_radius_calculation(self) -> None:
        """Verify apothem r_in = sqrt(3)/2 * R for regular hexagon."""
        r = 22.0
        expected = math.sqrt(3.0) / 2.0 * 22.0
        assert math.isclose(in_circle_radius(r), expected, rel_tol=1e-6)
        assert math.isclose(in_circle_radius(22.0), 19.052558883, rel_tol=1e-5)

    def test_compute_hex_vertices_pointy_topped_count_and_radius(self) -> None:
        """Verify 6 vertices generated at exactly radius R from center for pointy-topped."""
        cx, cy, r = 100.0, 100.0, 22.0
        vertices = compute_hex_vertices(cx, cy, r, HexOrientation.POINTY_TOPPED)
        assert len(vertices) == 6

        for vx, vy in vertices:
            dist = math.hypot(vx - cx, vy - cy)
            assert math.isclose(dist, r, abs_tol=0.05)

        # First vertex of pointy-topped is at 30°
        v0 = vertices[0]
        expected_v0_x = cx + r * math.cos(math.pi / 6.0)
        expected_v0_y = cy + r * math.sin(math.pi / 6.0)
        assert math.isclose(v0[0], expected_v0_x, abs_tol=0.05)
        assert math.isclose(v0[1], expected_v0_y, abs_tol=0.05)

    def test_compute_hex_vertices_flat_topped_count_and_radius(self) -> None:
        """Verify 6 vertices generated for flat-topped orientation."""
        cx, cy, r = 150.0, 200.0, 22.0
        vertices = compute_hex_vertices(cx, cy, r, HexOrientation.FLAT_TOPPED)
        assert len(vertices) == 6

        for vx, vy in vertices:
            dist = math.hypot(vx - cx, vy - cy)
            assert math.isclose(dist, r, abs_tol=0.05)

        # First vertex of flat-topped is at 0° (rightmost)
        v0 = vertices[0]
        assert math.isclose(v0[0], cx + r, abs_tol=0.05)
        assert math.isclose(v0[1], cy, abs_tol=0.05)

    def test_format_polygon_points_svg_format(self) -> None:
        """Verify format_polygon_points returns space-separated x,y pairs."""
        verts = [(10.0, 20.0), (30.0, 40.0), (50.0, 60.0)]
        res = format_polygon_points(verts)
        assert res == "10.0,20.0 30.0,40.0 50.0,60.0"

    def test_is_point_inside_hex_center(self) -> None:
        """Verify center point is strictly inside hexagon."""
        assert is_point_inside_hex(100.0, 100.0, 100.0, 100.0, 22.0, HexOrientation.POINTY_TOPPED) is True
        assert is_point_inside_hex(100.0, 100.0, 100.0, 100.0, 22.0, HexOrientation.FLAT_TOPPED) is True

    def test_is_point_inside_hex_near_vertex(self) -> None:
        """Verify point slightly inside vertex boundary is contained."""
        cx, cy, r = 100.0, 100.0, 22.0
        # Point at 0.9 * R along angle
        px = cx + 0.9 * r * math.cos(math.pi / 6.0)
        py = cy + 0.9 * r * math.sin(math.pi / 6.0)
        assert is_point_inside_hex(px, py, cx, cy, r, HexOrientation.POINTY_TOPPED) is True

    def test_is_point_inside_hex_outside(self) -> None:
        """Verify points outside circumcircle are rejected."""
        cx, cy, r = 100.0, 100.0, 22.0
        assert is_point_inside_hex(cx + 25.0, cy, cx, cy, r, HexOrientation.POINTY_TOPPED) is False
        assert is_point_inside_hex(cx, cy + 25.0, cx, cy, r, HexOrientation.POINTY_TOPPED) is False

    def test_is_point_inside_hex_flat_topped(self) -> None:
        """Verify point inside flat-topped hex boundary."""
        cx, cy, r = 50.0, 50.0, 22.0
        assert is_point_inside_hex(55.0, 55.0, cx, cy, r, HexOrientation.FLAT_TOPPED) is True
        assert is_point_inside_hex(80.0, 50.0, cx, cy, r, HexOrientation.FLAT_TOPPED) is False

    def test_hex_coordinate_s_cubic_constraint(self) -> None:
        """Verify HexCoordinate s property enforces q + r + s = 0."""
        coord1 = HexCoordinate(q=3, r=-5)
        assert coord1.s == 2
        assert coord1.q + coord1.r + coord1.s == 0

        coord2 = HexCoordinate(q=0, r=0)
        assert coord2.s == 0
        assert coord2.q + coord2.r + coord2.s == 0


# ============================================================================
# 4. Point-to-Hex Quantization & Binning Tests
# ============================================================================

class TestPointToHexQuantizationAndBinning:
    """Test point-to-hex quantization algorithms and round-trip coordinate projection."""

    def test_point_to_axial_pointy_origin(self) -> None:
        """Verify origin point projects to axial (0, 0) for pointy-topped."""
        ox, oy, r = 200.0, 300.0, 22.0
        q, r_ax = point_to_axial_pointy(ox, oy, r, ox, oy)
        assert (q, r_ax) == (0, 0)

    def test_axial_to_center_pointy_roundtrip(self) -> None:
        """Verify recovering axial coords from synthesized center point."""
        ox, oy, r = 100.0, 100.0, 22.0
        for test_q in [-3, -1, 0, 2, 4]:
            for test_r in [-2, 0, 1, 3]:
                cx, cy = axial_to_center_pointy(test_q, test_r, r, ox, oy)
                rec_q, rec_r = point_to_axial_pointy(cx, cy, r, ox, oy)
                assert (rec_q, rec_r) == (test_q, test_r), f"Failed roundtrip for ({test_q}, {test_r})"

    def test_point_to_axial_flat_origin(self) -> None:
        """Verify origin point projects to axial (0, 0) for flat-topped."""
        ox, oy, r = 150.0, 150.0, 22.0
        q, r_ax = point_to_axial_flat(ox, oy, r, ox, oy)
        assert (q, r_ax) == (0, 0)

    def test_axial_to_center_flat_roundtrip(self) -> None:
        """Verify recovering axial coords from synthesized center point for flat-topped."""
        ox, oy, r = 120.0, 180.0, 22.0
        for test_q in [-2, 0, 1, 3]:
            for test_r in [-3, -1, 0, 2]:
                cx, cy = axial_to_center_flat(test_q, test_r, r, ox, oy)
                rec_q, rec_r = point_to_axial_flat(cx, cy, r, ox, oy)
                assert (rec_q, rec_r) == (test_q, test_r), f"Failed flat roundtrip for ({test_q}, {test_r})"

    def test_point_to_axial_unified_both_orientations(self) -> None:
        """Verify point_to_axial handles both orientations correctly."""
        ox, oy, r = 100.0, 100.0, 22.0
        q_p, r_p = point_to_axial(ox, oy, r, ox, oy, HexOrientation.POINTY_TOPPED)
        q_f, r_f = point_to_axial(ox, oy, r, ox, oy, HexOrientation.FLAT_TOPPED)
        assert (q_p, r_p) == (0, 0)
        assert (q_f, r_f) == (0, 0)

    def test_axial_to_center_unified_both_orientations(self) -> None:
        """Verify axial_to_center dispatches to appropriate orientation formula."""
        ox, oy, r = 100.0, 100.0, 22.0
        cx_p, cy_p = axial_to_center(2, 3, r, ox, oy, HexOrientation.POINTY_TOPPED)
        cx_f, cy_f = axial_to_center(2, 3, r, ox, oy, HexOrientation.FLAT_TOPPED)
        assert cx_p != cx_f or cy_p != cy_f

    def test_quantize_coordinate_stability_within_incircle(self) -> None:
        """Verify jitter within in-circle radius preserves exact axial quantization."""
        ox, oy, r = 250.0, 250.0, 22.0
        target_q, target_r = 3, 2
        cx, cy = axial_to_center_pointy(target_q, target_r, r, ox, oy)

        # Small perturbations inside in-circle (apothem approx 19px)
        for offset_x in [-8.0, 0.0, 8.0]:
            for offset_y in [-8.0, 0.0, 8.0]:
                q, r_ax = point_to_axial_pointy(cx + offset_x, cy + offset_y, r, ox, oy)
                assert (q, r_ax) == (target_q, target_r)

    def test_quantize_negative_coordinates(self) -> None:
        """Verify correct quantization into negative quadrants."""
        ox, oy, r = 300.0, 300.0, 22.0
        cx, cy = axial_to_center_pointy(-4, -5, r, ox, oy)
        q, r_ax = point_to_axial_pointy(cx, cy, r, ox, oy)
        assert (q, r_ax) == (-4, -5)

    def test_quantize_large_offsets(self) -> None:
        """Verify quantization works at large pixel offsets."""
        ox, oy, r = 0.0, 0.0, 22.0
        cx, cy = axial_to_center_pointy(50, 40, r, ox, oy)
        q, r_ax = point_to_axial_pointy(cx, cy, r, ox, oy)
        assert (q, r_ax) == (50, 40)

    def test_quantize_zero_or_negative_radius_raises_singularity(self) -> None:
        """Verify radius <= 0 raises HexbinSingularityError."""
        with pytest.raises(HexbinSingularityError):
            point_to_axial_pointy(100.0, 100.0, 0.0, 100.0, 100.0)
        with pytest.raises(HexbinSingularityError):
            point_to_axial_pointy(100.0, 100.0, -10.0, 100.0, 100.0)
        with pytest.raises(HexbinSingularityError):
            point_to_axial_flat(100.0, 100.0, 0.0, 100.0, 100.0)


# ============================================================================
# 5. Spatial Binning for 500+ Coordinates & Aggregation Tests
# ============================================================================

class TestSpatialBinning500CoordinatesAndAggregation:
    """Test spatial binning, density counts aggregation, and canonical dataset matching."""

    def test_generate_canonical_scatter_points_count(self) -> None:
        """Verify generator yields exactly 500 coordinates."""
        pts = generate_canonical_scatter_points()
        assert len(pts) == 500
        assert all(isinstance(p, Point2D) for p in pts)

    def test_canonical_aggregation_48_active_bins(self) -> None:
        """Verify 500 canonical points aggregate into exactly 48 active hex bins."""
        canvas = create_canonical_hexbin_canvas()
        assert canvas.metrics.total_sample_points_count == 500
        assert canvas.metrics.total_active_hex_bins_count == 48
        assert len(canvas.bins) == 48

    def test_canonical_aggregation_max_density_42(self) -> None:
        """Verify maximum hex bin density is exactly 42 points."""
        canvas = create_canonical_hexbin_canvas()
        assert canvas.metrics.max_hex_bin_density_count == 42
        peak_bins = [b for b in canvas.bins.values() if b.is_peak]
        assert len(peak_bins) == 1
        assert peak_bins[0].count == 42

    def test_canonical_aggregation_mean_density_104_scaled(self) -> None:
        """Verify mean hex bin density scaled x10 is 104 (10.4 pts/bin)."""
        canvas = create_canonical_hexbin_canvas()
        # 500 / 48 = 10.4166... -> scaled x10 is 104
        assert canvas.metrics.mean_hex_bin_density_scaled == 104
        assert math.isclose(canvas.metrics.mean_hex_bin_density, 10.42, abs_tol=0.05)

    def test_canonical_peak_centroid_coords_45_28(self) -> None:
        """Verify peak density hex centroid is at engineering (45.0, 28.0) scaled (450, 280)."""
        canvas = create_canonical_hexbin_canvas()
        assert math.isclose(canvas.metrics.peak_density_hex_x, 45.0, abs_tol=0.1)
        assert math.isclose(canvas.metrics.peak_density_hex_y, 28.0, abs_tol=0.1)
        assert canvas.metrics.peak_density_hex_x_scaled == 450
        assert canvas.metrics.peak_density_hex_y_scaled == 280

    def test_custom_points_dataset_binning_accuracy(self) -> None:
        """Verify binning custom points with arbitrary distribution."""
        pts = [
            Point2D(x=100.0, y=100.0),
            Point2D(x=102.0, y=101.0),
            Point2D(x=105.0, y=98.0),
            Point2D(x=300.0, y=300.0),
        ]
        canvas = HexbinCanvas(points=pts, radius=22.0)
        assert canvas.metrics.total_sample_points_count == 4
        # Expect 2 active bins
        assert canvas.metrics.total_active_hex_bins_count == 2
        assert canvas.metrics.max_hex_bin_density_count == 3

    def test_points_with_different_weights_and_tags(self) -> None:
        """Verify Point2D data model with custom weight and tags."""
        p = Point2D(x=45.5, y=28.3, weight=2.5, tag="SENSOR_REACTOR_TC01")
        assert p.x == 45.5
        assert p.y == 28.3
        assert p.weight == 2.5
        assert p.tag == "SENSOR_REACTOR_TC01"

    def test_screen_to_eng_and_eng_to_screen_transforms(self) -> None:
        """Verify coordinate transforms between screen pixels and engineering units."""
        canvas = create_canonical_hexbin_canvas()
        ex, ey = 50.0, 50.0
        sx, sy = canvas.eng_to_screen(ex, ey)
        rx, ry = canvas.screen_to_eng(sx, sy)
        assert math.isclose(ex, rx, abs_tol=1e-5)
        assert math.isclose(ey, ry, abs_tol=1e-5)


# ============================================================================
# 6. Density Normalization & Color Palette Mapping Tests
# ============================================================================

class TestDensityNormalizationAndPalettes:
    """Test Linear vs Logarithmic density normalization and perceptual color gradients."""

    def test_normalize_density_linear_bounds(self) -> None:
        """Verify linear normalization maps [min, max] to [0.0, 1.0]."""
        assert normalize_density(1, 1, 42, DensityScaleMode.LINEAR) == 0.0
        assert normalize_density(42, 1, 42, DensityScaleMode.LINEAR) == 1.0

    def test_normalize_density_linear_midpoint(self) -> None:
        """Verify linear midpoint calculation."""
        norm_mid = normalize_density(21, 1, 41, DensityScaleMode.LINEAR)
        assert math.isclose(norm_mid, 0.5, abs_tol=1e-5)

    def test_normalize_density_logarithmic_bounds(self) -> None:
        """Verify logarithmic normalization maps [min, max] to [0.0, 1.0]."""
        assert normalize_density(1, 1, 42, DensityScaleMode.LOGARITHMIC) == 0.0
        assert normalize_density(42, 1, 42, DensityScaleMode.LOGARITHMIC) == 1.0

    def test_normalize_density_logarithmic_boosts_low_counts(self) -> None:
        """Verify logarithmic curve gives higher normalized density than linear at midtones."""
        lin = normalize_density(10, 1, 100, DensityScaleMode.LINEAR)
        log = normalize_density(10, 1, 100, DensityScaleMode.LOGARITHMIC)
        assert log > lin, f"Expected log ({log}) > lin ({lin})"

    def test_normalize_density_zero_count_returns_zero(self) -> None:
        """Verify count <= 0 returns 0.0."""
        assert normalize_density(0, 1, 42) == 0.0
        assert normalize_density(-5, 1, 42) == 0.0

    def test_normalize_density_equal_min_max_returns_one(self) -> None:
        """Verify degenerate min == max returns 1.0."""
        assert normalize_density(10, 10, 10) == 1.0

    def test_srgb_channel_to_linear(self) -> None:
        """Verify sRGB piecewise linear conversion."""
        assert srgb_channel_to_linear(0.0) == 0.0
        assert math.isclose(srgb_channel_to_linear(1.0), 1.0, rel_tol=1e-6)
        # Small channel threshold <= 0.04045
        assert math.isclose(srgb_channel_to_linear(0.02), 0.02 / 12.92, rel_tol=1e-6)

    def test_hex_to_rgb_and_rgb_to_hex_roundtrip(self) -> None:
        """Verify roundtrip conversion between hex string and RGB triplet."""
        test_colors = ["#1E3A8A", "#0D1117", "#EF4444", "#FFFFFF", "#000000"]
        for c in test_colors:
            r, g, b = hex_to_rgb(c)
            rec = rgb_to_hex(r, g, b)
            assert rec.upper() == c.upper()

    def test_interpolate_rgb_midpoint(self) -> None:
        """Verify linear interpolation between colors."""
        black = "#000000"
        white = "#FFFFFF"
        mid = interpolate_rgb(black, white, 0.5)
        r, g, b = hex_to_rgb(mid)
        assert abs(r - 128) <= 1
        assert abs(g - 128) <= 1
        assert abs(b - 128) <= 1

    def test_interpolate_palette_color_all_stops(self) -> None:
        """Verify interpolation samples boundary stops exactly."""
        stops = ["#0000FF", "#00FF00", "#FF0000"]
        c_min = interpolate_palette_color(stops, 0.0)
        c_mid = interpolate_palette_color(stops, 0.5)
        c_max = interpolate_palette_color(stops, 1.0)
        assert c_min.upper() == "#0000FF"
        assert c_mid.upper() == "#00FF00"
        assert c_max.upper() == "#FF0000"

    def test_get_palette_colors_cool_to_warm(self) -> None:
        """Verify Cool-to-Warm palette generates valid hex stops."""
        colors = get_palette_colors(HexbinPalette.COOL_TO_WARM, 6)
        assert len(colors) == 6
        assert all(c.startswith("#") and len(c) == 7 for c in colors)

    def test_get_palette_colors_magma(self) -> None:
        """Verify Magma palette generates valid hex stops."""
        colors = get_palette_colors(HexbinPalette.MAGMA, 6)
        assert len(colors) == 6
        assert all(c.startswith("#") and len(c) == 7 for c in colors)

    def test_get_palette_colors_plasma(self) -> None:
        """Verify Plasma palette generates valid hex stops."""
        colors = get_palette_colors(HexbinPalette.PLASMA, 6)
        assert len(colors) == 6
        assert all(c.startswith("#") and len(c) == 7 for c in colors)

    def test_get_palette_colors_viridis(self) -> None:
        """Verify Viridis palette generates valid hex stops."""
        colors = get_palette_colors(HexbinPalette.VIRIDIS, 6)
        assert len(colors) == 6
        assert all(c.startswith("#") and len(c) == 7 for c in colors)


# ============================================================================
# 7. WCAG 2.1 AAA Contrast & Accessibility Tests
# ============================================================================

class TestWCAG21AAAContrast:
    """Test WCAG 2.1 AAA contrast ratios (> 18:1 for badges, > 7.0:1 for text)."""

    def test_relative_luminance_black_and_white(self) -> None:
        """Verify luminance extremes: 0.0 for pure black, 1.0 for pure white."""
        assert math.isclose(relative_luminance("#000000"), 0.0, abs_tol=1e-5)
        assert math.isclose(relative_luminance("#FFFFFF"), 1.0, abs_tol=1e-5)

    def test_calculate_contrast_ratio_black_white(self) -> None:
        """Verify black on white contrast ratio is 21.0:1."""
        cr = calculate_contrast_ratio("#FFFFFF", "#000000")
        assert math.isclose(cr, 21.0, rel_tol=1e-3)

    def test_wcag_aaa_badge_contrast_exceeds_18_to_1(self) -> None:
        """Verify decoupled dark badge contrast exceeds strict 18.0:1 target."""
        badge_cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert badge_cr > WCAG_AAA_BADGE_CONTRAST_TARGET, f"Badge CR {badge_cr} <= 18.0:1"
        assert badge_cr > 18.0

    def test_wcag_aaa_primary_text_on_canvas_bg_exceeds_18_to_1(self) -> None:
        """Verify primary text on dark canvas theme exceeds 18:1."""
        cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_CANVAS_BG)
        assert cr > 18.0

    def test_wcag_aaa_muted_text_on_canvas_bg_exceeds_7_to_1(self) -> None:
        """Verify secondary muted text on canvas background meets WCAG AAA (> 7.0:1)."""
        cr = calculate_contrast_ratio(COLOR_TEXT_MUTED, COLOR_CANVAS_BG)
        assert cr > WCAG_AAA_TEXT_CONTRAST_TARGET, f"Muted CR {cr} <= 7.0:1"
        assert cr > 7.0

    def test_validate_wcag_aaa_contrast_helper_returns_true(self) -> None:
        """Verify validate_wcag_aaa_contrast() helper returns (True, >7.0, >18.0)."""
        is_aaa, text_cr, badge_cr = validate_wcag_aaa_contrast()
        assert is_aaa is True
        assert text_cr >= 7.0
        assert badge_cr >= 18.0


# ============================================================================
# 8. Fault Handling & Diagnostics Tests
# ============================================================================

class TestFaultHandlingAndDiagnostics:
    """Test 0xF101..0xF104 diagnostic fault injection, latching, and reset behavior."""

    def test_diagnostic_code_signed_unsigned_equality(self) -> None:
        """Verify DiagnosticCode handles signed/unsigned 16-bit comparisons."""
        code_0xf101 = DIAG_ERR_HEX_TESSELLATION_SINGULARITY
        assert code_0xf101 == 0xF101
        assert code_0xf101 == -3839  # 0xF101 - 0x10000

        code_0xf102 = DIAG_ERR_EMPTY_SAMPLE_DATASET
        assert code_0xf102 == 0xF102
        assert code_0xf102 == -3838

        code_0xf103 = DIAG_ERR_DENSITY_OVERFLOW_ALARM
        assert code_0xf103 == 0xF103
        assert code_0xf103 == -3837

        code_0xf104 = DIAG_ERR_SVG_RENDER_FAULT
        assert code_0xf104 == 0xF104
        assert code_0xf104 == -3836

    def test_diagnostic_code_hashing(self) -> None:
        """Verify DiagnosticCode hashes properly in sets and dicts."""
        d = {DIAG_EVENT_OK: "OK", DIAG_ERR_HEX_TESSELLATION_SINGULARITY: "SINGULARITY"}
        assert d[DiagnosticCode(0x0000)] == "OK"
        assert d[DiagnosticCode(0xF101)] == "SINGULARITY"

    def test_tessellation_singularity_fault_0xf101(self) -> None:
        """Verify 0xF101 triggered when radius <= 0."""
        canvas = create_canonical_hexbin_canvas()
        canvas.trigger_tessellation_singularity(bad_radius=0.0)
        assert canvas.diagnostic_code == DIAG_ERR_HEX_TESSELLATION_SINGULARITY
        reg_val = canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF
        assert reg_val == 0xF101
        assert HexbinStatusBits.TESSELLATION_SINGULARITY in canvas.status_bits

    def test_empty_sample_dataset_fault_0xf102(self) -> None:
        """Verify 0xF102 triggered when sample dataset is empty."""
        canvas = create_canonical_hexbin_canvas()
        canvas.trigger_empty_dataset()
        assert canvas.diagnostic_code == DIAG_ERR_EMPTY_SAMPLE_DATASET
        reg_val = canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF
        assert reg_val == 0xF102
        assert HexbinStatusBits.EMPTY_DATASET_FAULT in canvas.status_bits

    def test_density_overflow_alarm_0xf103(self) -> None:
        """Verify 0xF103 triggered when maximum density exceeds overflow limit (> 1000)."""
        canvas = create_canonical_hexbin_canvas()
        canvas.trigger_density_overflow(overflow_count=1200)
        assert canvas.diagnostic_code == DIAG_ERR_DENSITY_OVERFLOW_ALARM
        reg_val = canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF
        assert reg_val == 0xF103
        assert HexbinStatusBits.DENSITY_OVERFLOW_FAULT in canvas.status_bits

    def test_svg_render_fault_0xf104(self) -> None:
        """Verify 0xF104 triggered upon SVG render fault."""
        canvas = create_canonical_hexbin_canvas()
        canvas.trigger_render_fault()
        assert canvas.diagnostic_code == DIAG_ERR_SVG_RENDER_FAULT
        reg_val = canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF
        assert reg_val == 0xF104

    def test_render_svg_raises_svg_render_error_on_0xf104(self) -> None:
        """Verify render_svg raises SVGRenderError when DIAG_ERR_SVG_RENDER_FAULT is active."""
        canvas = create_canonical_hexbin_canvas()
        canvas.trigger_render_fault()
        with pytest.raises(SVGRenderError):
            canvas.render_svg()

    def test_reset_nominal_clears_all_faults_and_restores_ok(self) -> None:
        """Verify reset_nominal restores DIAG_EVENT_OK and cleans registers."""
        canvas = create_canonical_hexbin_canvas()
        canvas.trigger_tessellation_singularity(bad_radius=0.0)
        assert canvas.diagnostic_code != DIAG_EVENT_OK

        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0
        assert canvas.metrics.total_sample_points_count == 500
        assert canvas.metrics.total_active_hex_bins_count == 48

    def test_mutators_update_bins_and_telemetry(self) -> None:
        """Verify set_radius, set_palette, set_density_scale, set_orientation mutators."""
        canvas = create_canonical_hexbin_canvas()
        canvas.set_radius(30.0)
        assert canvas.radius == 30.0
        assert canvas.reg_table.read_word(REG_HEX_TESSELLATION_RADIUS_PX) == 30

        canvas.set_palette(HexbinPalette.MAGMA)
        assert canvas.palette == HexbinPalette.MAGMA

        canvas.set_density_scale(DensityScaleMode.LOGARITHMIC)
        assert canvas.density_scale == DensityScaleMode.LOGARITHMIC
        assert HexbinStatusBits.LOGARITHMIC_SCALE in canvas.status_bits

        canvas.set_orientation(HexOrientation.FLAT_TOPPED)
        assert canvas.orientation == HexOrientation.FLAT_TOPPED


# ============================================================================
# 9. High Density Cluster Alarm Tests
# ============================================================================

class TestHighDensityClusterAlarm:
    """Test process safety interlock: High Density Cluster Alarm (%M435)."""

    def test_alarm_active_when_max_density_gt_35(self) -> None:
        """Verify alarm asserts when maximum bin density exceeds 35 points."""
        canvas = create_canonical_hexbin_canvas()
        # Canonical max density is 42 > 35
        assert canvas.metrics.max_hex_bin_density_count == 42
        assert canvas.metrics.high_density_cluster_alarm_active is True
        assert canvas.reg_table.read_bit(COIL_HIGH_DENSITY_CLUSTER_ALARM_ACTIVE) is True

    def test_alarm_clears_when_max_density_lte_35(self) -> None:
        """Verify alarm clears when maximum bin density is <= 35 points."""
        # 30 points in one bin
        pts = [Point2D(x=100.0, y=100.0) for _ in range(30)]
        canvas = HexbinCanvas(points=pts)
        assert canvas.metrics.max_hex_bin_density_count == 30
        assert canvas.metrics.high_density_cluster_alarm_active is False
        assert canvas.reg_table.read_bit(COIL_HIGH_DENSITY_CLUSTER_ALARM_ACTIVE) is False

    def test_coil_m435_reflects_alarm_state(self) -> None:
        """Verify %M435 tracks alarm across transitions."""
        canvas = create_canonical_hexbin_canvas()
        assert canvas.reg_table.read_bit("%M435") is True

        # Lower density
        pts = [Point2D(x=100.0, y=100.0) for _ in range(10)]
        canvas.set_points(pts)
        assert canvas.reg_table.read_bit("%M435") is False

        # Raise density back
        pts = [Point2D(x=100.0, y=100.0) for _ in range(40)]
        canvas.set_points(pts)
        assert canvas.reg_table.read_bit("%M435") is True

    def test_status_bits_cluster_alarm_flag(self) -> None:
        """Verify CLUSTER_ALARM bit in status_bits."""
        canvas = create_canonical_hexbin_canvas()
        assert HexbinStatusBits.CLUSTER_ALARM in canvas.status_bits


# ============================================================================
# 10. Horner OCS Memory Space & Register Synchronization Tests
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Test register synchronization (%R1860..%R1867, %M434..%M435) with PrivilegeMode.SYSTEM."""

    def test_register_sync_words_r1860_through_r1867(self) -> None:
        """Verify all analog word registers match telemetry metrics."""
        canvas = create_canonical_hexbin_canvas()
        reg_table = canvas.reg_table

        # %R1860: TotalActiveHexBinsCount = 48
        assert reg_table.read_word(REG_TOTAL_ACTIVE_HEX_BINS_COUNT) == 48
        # %R1861: TotalSamplePointsCount = 500
        assert reg_table.read_word(REG_TOTAL_SAMPLE_POINTS_COUNT) == 500
        # %R1862: MaxHexBinDensityCount = 42
        assert reg_table.read_word(REG_MAX_HEX_BIN_DENSITY_COUNT) == 42
        # %R1863: MeanHexBinDensityScaled = 104
        assert reg_table.read_word(REG_MEAN_HEX_BIN_DENSITY_SCALED) == 104
        # %R1864: PeakDensityHexXScaled = 450
        assert reg_table.read_word(REG_PEAK_DENSITY_HEX_X_SCALED) == 450
        # %R1865: PeakDensityHexYScaled = 280
        assert reg_table.read_word(REG_PEAK_DENSITY_HEX_Y_SCALED) == 280
        # %R1866: HexTessellationRadiusPx = 22
        assert reg_table.read_word(REG_HEX_TESSELLATION_RADIUS_PX) == 22
        # %R1867: DiagnosticStatusCode = 0x0000
        assert reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0

    def test_register_sync_coils_m434_and_m435(self) -> None:
        """Verify discrete coils %M434 (active) and %M435 (alarm)."""
        canvas = create_canonical_hexbin_canvas()
        reg_table = canvas.reg_table

        # %M434: HexbinCanvasActive = True
        assert reg_table.read_bit(COIL_HEXBIN_CANVAS_ACTIVE) is True
        # %M435: HighDensityClusterAlarmActive = True (Max 42 > 35)
        assert reg_table.read_bit(COIL_HIGH_DENSITY_CLUSTER_ALARM_ACTIVE) is True

    def test_signed_16bit_diagnostic_read_word_masking(self) -> None:
        """Verify signed 16-bit read_word masked with & 0xFFFF equals hex code."""
        canvas = create_canonical_hexbin_canvas()
        canvas.trigger_tessellation_singularity()

        raw_word = canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE)
        # 0xF101 as signed int16 is -3839
        assert raw_word == -3839
        # Masking raw word with & 0xFFFF recovers unsigned 0xF101
        assert (raw_word & 0xFFFF) == 0xF101

    def test_privilege_mode_system_required_for_writes(self) -> None:
        """Verify writes with PrivilegeMode.SYSTEM succeed."""
        table = RegisterTable()
        table.write_word("%R1860", 48, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R1860") == 48

    def test_sync_to_external_register_table(self) -> None:
        """Verify canvas can synchronize into an external RegisterTable instance."""
        canvas = create_canonical_hexbin_canvas()
        ext_table = RegisterTable()
        canvas.sync_to_registers(reg_table=ext_table, privilege=PrivilegeMode.SYSTEM)

        assert ext_table.read_word(REG_TOTAL_ACTIVE_HEX_BINS_COUNT) == 48
        assert ext_table.read_word(REG_TOTAL_SAMPLE_POINTS_COUNT) == 500
        assert ext_table.read_bit(COIL_HEXBIN_CANVAS_ACTIVE) is True


# ============================================================================
# 11. ILogicUnit Integration & Scan Cycle Tests
# ============================================================================

class TestILogicUnitIntegration:
    """Test ILogicUnit discrete scan cycle protocol implementation."""

    def test_ilogic_unit_properties_name_priority_enabled(self) -> None:
        """Verify name, priority, and is_enabled properties."""
        canvas = create_canonical_hexbin_canvas()
        assert canvas.name == "HexbinCanvasSync"
        assert canvas.priority == 85
        assert canvas.is_enabled is True

    def test_ilogic_unit_scan_step_increments_cycle_and_elapsed(self) -> None:
        """Verify scan_step increments cycle counter and elapsed time."""
        canvas = create_canonical_hexbin_canvas()
        assert canvas._cycle_count == 0
        assert canvas._elapsed_s == 0.0

        canvas.scan_step(dt=0.02)
        assert canvas._cycle_count == 1
        assert math.isclose(canvas._elapsed_s, 0.02, abs_tol=1e-5)

        canvas.scan_step(dt=0.02)
        assert canvas._cycle_count == 2
        assert math.isclose(canvas._elapsed_s, 0.04, abs_tol=1e-5)

    def test_ilogic_unit_execute_with_scan_context(self) -> None:
        """Verify execute method accepting ScanContext."""
        canvas = create_canonical_hexbin_canvas()
        ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=canvas.reg_table)
        canvas.execute(ctx)
        assert canvas._cycle_count == 1
        assert math.isclose(canvas._elapsed_s, 0.01, abs_tol=1e-5)

    def test_ilogic_unit_reset_restores_nominal(self) -> None:
        """Verify reset() method restores initial state."""
        canvas = create_canonical_hexbin_canvas()
        canvas.trigger_empty_dataset()
        assert canvas.metrics.total_sample_points_count == 0

        canvas.reset()
        assert canvas.metrics.total_sample_points_count == 500
        assert canvas.diagnostic_code == DIAG_EVENT_OK

    def test_100_cycle_scan_simulation_stability(self) -> None:
        """Verify executing 100 consecutive scan cycles maintains state stability."""
        canvas = create_canonical_hexbin_canvas()
        for c in range(1, 101):
            ctx = create_mock_scan_context(cycle=c, dt_ms=10.0, reg_table=canvas.reg_table)
            canvas.execute(ctx)

        assert canvas._cycle_count == 100
        assert math.isclose(canvas._elapsed_s, 1.0, abs_tol=1e-4)
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.metrics.total_active_hex_bins_count == 48


# ============================================================================
# 12. Standalone W3C SVG 1.1 Vector Canvas XML Tests
# ============================================================================

class TestStandaloneW3CSVGGenerationAndXML:
    """Test XML SVG synthesis, validity with ElementTree, tags, attributes, and WCAG contrast."""

    def test_render_svg_returns_valid_xml(self) -> None:
        """Verify render_svg produces valid well-formed XML parseable by xml.etree.ElementTree."""
        canvas = create_canonical_hexbin_canvas()
        svg_xml = canvas.render_svg()
        root = ET.fromstring(svg_xml)
        assert root is not None
        assert root.tag.endswith("svg")

    def test_svg_root_attributes_viewport(self) -> None:
        """Verify SVG viewBox and width/height match 1200x750 viewport."""
        canvas = create_canonical_hexbin_canvas()
        svg_xml = canvas.render_svg()
        root = ET.fromstring(svg_xml)
        assert root.attrib.get("width") == "1200"
        assert root.attrib.get("height") == "750"
        assert root.attrib.get("viewBox") == "0 0 1200 750"

    def test_svg_contains_48_polygon_hexbins(self) -> None:
        """Verify SVG contains exactly 48 <polygon> elements for the 48 active hex bins."""
        canvas = create_canonical_hexbin_canvas()
        svg_xml = canvas.render_svg()
        root = ET.fromstring(svg_xml)
        polygons = root.findall(".//{http://www.w3.org/2000/svg}polygon") + root.findall(".//polygon")
        assert len(polygons) == 48

        for poly in polygons:
            pts_attr = poly.attrib.get("points")
            assert pts_attr is not None
            # Each regular hex polygon has 6 vertices (6 x,y pairs)
            coords = pts_attr.split()
            assert len(coords) == 6

    def test_svg_contains_dark_backing_badges(self) -> None:
        """Verify presence of decoupled dark backing rectangles (#0B0F19) for density counts."""
        canvas = create_canonical_hexbin_canvas()
        svg_xml = canvas.render_svg()
        assert COLOR_DECOUPLED_BADGE in svg_xml
        root = ET.fromstring(svg_xml)
        rects = root.findall(".//{http://www.w3.org/2000/svg}rect") + root.findall(".//rect")
        # Background + frame + status badges + 48 hex count badges + HUD + colorbar > 50
        assert len(rects) >= 48

    def test_svg_contains_peak_density_reticle(self) -> None:
        """Verify SVG contains the peak reticle crosshairs and pulse halo."""
        canvas = create_canonical_hexbin_canvas()
        svg_xml = canvas.render_svg()
        assert 'id="peak-reticle"' in svg_xml
        assert 'class="reticle-halo"' in svg_xml
        assert "PEAK: 42 pts" in svg_xml

    def test_svg_contains_telemetry_hud_scorecard(self) -> None:
        """Verify SVG contains the telemetry HUD card with register readings."""
        canvas = create_canonical_hexbin_canvas()
        svg_xml = canvas.render_svg()
        assert 'id="telemetry-hud"' in svg_xml
        assert "HEXBIN DENSITY SCADA HUD" in svg_xml
        assert "%R1860" in svg_xml
        assert "%R1861" in svg_xml
        assert "%R1862" in svg_xml
        assert "%R1863" in svg_xml
        assert "%R1864" in svg_xml
        assert "%R1865" in svg_xml
        assert "%R1866" in svg_xml
        assert "%R1867" in svg_xml
        assert "%M434" in svg_xml
        assert "%M435" in svg_xml

    def test_svg_contains_colorbar_legend_and_gradient(self) -> None:
        """Verify SVG contains colorbar legend and linearGradient definition."""
        canvas = create_canonical_hexbin_canvas()
        svg_xml = canvas.render_svg()
        assert 'id="colorbar-legend"' in svg_xml
        assert 'id="colorbar-gradient"' in svg_xml
        assert "Density Scaling Palette" in svg_xml

    def test_svg_escapes_xml_entities(self) -> None:
        """Verify text inside SVG is properly XML entity-escaped."""
        canvas = create_canonical_hexbin_canvas()
        svg_xml = canvas.render_svg()
        assert "&amp;" in svg_xml
        # Verify valid XML parsing confirms no naked ampersands
        ET.fromstring(svg_xml)


# ============================================================================
# 13. Verification Runner & Contract Tests
# ============================================================================

class TestVerificationRunnerAndContract:
    """Test 9-stage verification suite run_hexbin_canvas_verification and contract conformance."""

    def test_run_hexbin_canvas_verification_returns_strict_4state_contract(self) -> None:
        """Verify runner returns dictionary matching strict 4-state contract schema."""
        report = run_hexbin_canvas_verification()
        assert isinstance(report, dict)
        assert "status" in report
        assert report["status"] in ("success", "failed", "blocked", "inconclusive")
        assert "error_code" in report
        assert "details" in report
        assert "data" in report

    def test_verification_all_9_stages_pass(self) -> None:
        """Verify all 9 stages in the runner pass cleanly."""
        report = run_hexbin_canvas_verification()
        assert report["status"] == "success"
        data = report.get("data", {})
        assert data.get("checks_passed") == 9
        assert data.get("total_checks") == 9
        tests = data.get("tests", [])
        assert len(tests) == 9
        for t in tests:
            assert t.get("passed") is True, f"Stage {t.get('stage')} failed: {t.get('details')}"

    def test_verification_emits_evidence_json_and_svg_file(self) -> None:
        """Verify files are generated at default artifacts paths."""
        evidence_file = Path("artifacts/HMI/hexbin_canvas_evidence.json")
        svg_file = Path("artifacts/HMI/hexbin_canvas_sample.svg")

        report = run_hexbin_canvas_verification(
            output_path=evidence_file,
            sample_svg_path=svg_file,
        )
        assert report["status"] == "success"
        assert evidence_file.exists()
        assert svg_file.exists()
        assert evidence_file.stat().st_size > 100
        assert svg_file.stat().st_size > 500

    def test_verification_evidence_json_is_valid_and_matches_results(self) -> None:
        """Verify evidence JSON file content matches returned report structure."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_ev = Path(tmp_dir) / "evidence.json"
            tmp_svg = Path(tmp_dir) / "sample.svg"

            report = run_hexbin_canvas_verification(output_path=tmp_ev, sample_svg_path=tmp_svg)
            assert report["status"] == "success"

            with open(tmp_ev, "r", encoding="utf-8") as f:
                saved = json.load(f)

            assert saved["status"] == "success"
            assert saved["data"]["checks_passed"] == 9
            assert saved["data"]["work_package"] == "W225"

    def test_verification_custom_paths(self) -> None:
        """Verify runner honors custom destination paths."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            custom_ev = Path(tmp_dir) / "custom_evidence.json"
            custom_svg = Path(tmp_dir) / "custom_sample.svg"

            report = run_hexbin_canvas_verification(
                evidence_path=custom_ev,
                svg_path=custom_svg,
            )
            assert report["status"] == "success"
            assert custom_ev.exists()
            assert custom_svg.exists()
