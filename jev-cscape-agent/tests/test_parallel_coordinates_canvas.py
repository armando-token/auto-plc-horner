"""Comprehensive Unit Test Suite for Cscape HMI Dynamic Parallel Coordinates Canvas (Wave W240).

Work Package: W240 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Multi-Dimensional Parallel Coordinates SCADA Canvas]

Architectural Coverage (115+ Unit Tests across 15 Test Classes):
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit equality (& 0xFFFF), hashing, enums, status flags.
2. TestParallelDimensionAxisDataclass: Axis setup, normalization (to 0.0..1.0), denormalization, tick generation, z-score, 3-sigma.
3. TestTelemetryProfileDataclass: Profile values, polyline coordinate calculation, deviation/outlier detection, categories.
4. TestCanvasGeometryAndLayout: 1200x750 viewport, axis spacing, bounding boxes, non-negative coordinates, Rect containment.
5. TestPolylineSplineInterpolation: Piecewise linear and cubic Bézier control point calculations, bounding.
6. TestBrushingAndFiltering: Axis range filtering, active profile subsetting, correlation calculation, interactive selection.
7. TestOutlierAlarmCondition: Multi-dimensional distance threshold, 0xF603/outlier injection, %M470 trip, recovery.
8. TestSVGGenerationAndXMLSyntax: Standalone W3C SVG 1.1 generation, ElementTree XML validation, <path> and <line> tags, HUD scorecard.
9. TestWCAG21AAAContrastAndVisualLegibility: WCAG 2.1 AAA relative luminance, contrast formulas, badge contrast > 18:1, text > 7:1.
10. TestHornerOCSSynchronizationAndRegisters: %R2010..%R2017 and %M469..%M470 bit-exact synchronization, PrivilegeMode.SYSTEM.
11. TestDiagnosticFaultConditionsAndRecovery: 0xF601 singularity, 0xF602 insufficient axes, 0xF603 range degeneracy, 0xF604 overflow, reset nominal.
12. TestPureSTAndSecurity: STParser & SecurityGuard verification of ParallelCoordinatesCanvasSync POU.
13. TestAntiLadderRejection: Rejection of 6+ ladder constructs (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError.
14. TestILogicUnitCompliance: scan_step, step, execute, reset, 100-cycle soak stability and zero drift.
15. TestVerificationRunnerAndContract: Deterministic 9-stage runner export and strict 4-state contract validation.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Set, Tuple
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.parallel_coordinates_canvas import (
    CANONICAL_ACTIVE_PROFILES_COUNT,
    CANONICAL_AXES_COUNT,
    CANONICAL_BRUSHING_AXIS_INDEX,
    CANONICAL_BRUSHING_WINDOW_SCALED,
    CANONICAL_MEAN_CORRELATION_INDEX,
    CANONICAL_MEAN_CORRELATION_INDEX_SCALED,
    CANONICAL_OUTLIER_COUNT,
    CANONICAL_SELECTED_PROFILE,
    CANVAS_OVERFLOW,
    CANVAS_OVERFLOW_FAULT,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    CanvasOverflowError,
    COIL_ALARM_ACTIVE,
    COIL_CANVAS_ACTIVE,
    COIL_MULTIVARIATE_OUTLIER_ALARM,
    COIL_OUTLIER_ALARM,
    COIL_OUTLIER_ALARM_ACTIVE,
    COIL_PARALLEL_ACTIVE,
    COIL_PARALLEL_CANVAS_ACTIVE,
    COIL_PARALLEL_COORDINATES_ACTIVE,
    COIL_W240_CANVAS_ACTIVE,
    COIL_W240_OUTLIER_ALARM,
    COLOR_ALARM,
    COLOR_AMBER,
    COLOR_AXIS_LINE,
    COLOR_BORDER,
    COLOR_CRIMSON,
    COLOR_CYAN,
    COLOR_DARK_THEME_BACKING,
    COLOR_DECOUPLED_BADGE,
    COLOR_EMERALD,
    COLOR_FOCUS,
    COLOR_GRID_LINE,
    COLOR_INDIGO,
    COLOR_NORMAL,
    COLOR_OUTLIER,
    COLOR_PANEL_BG,
    COLOR_PURPLE,
    COLOR_SELECTED,
    COLOR_SLATE,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TICK_LINE,
    COLOR_WARNING,
    DEFAULT_CANVAS_HEIGHT,
    DEFAULT_CANVAS_WIDTH,
    DEFAULT_CANVAS_X,
    DEFAULT_CANVAS_Y,
    DIAG_ERR_CANVAS_OVERFLOW,
    DIAG_ERR_GEOMETRY_SINGULARITY,
    DIAG_ERR_INSUFFICIENT_AXES,
    DIAG_ERR_RANGE_DEGENERACY,
    DIAG_EVENT_OK,
    DIAG_OK,
    DiagnosticCode,
    GEOMETRY_SINGULARITY,
    GEOMETRY_SINGULARITY_FAULT,
    GeometrySingularityError,
    INSUFFICIENT_AXES,
    INSUFFICIENT_AXES_FAULT,
    InsufficientAxesError,
    LAYOUT_BOUNDS_HEIGHT,
    LAYOUT_BOUNDS_WIDTH,
    LAYOUT_BOUNDS_X,
    LAYOUT_BOUNDS_Y,
    PARALLEL_COORDINATES_CANVAS_PURE_ST_POU,
    PARALLEL_COORDINATES_CANVAS_SYNC_PURE_ST_POU,
    PARALLEL_COORDINATES_PURE_ST_POU,
    PARALLEL_COORDS_OK,
    PARALLEL_OK,
    ParallelCoordinatesCanvas,
    ParallelCoordinatesCanvasDiagnosticCode,
    ParallelCoordinatesCanvasEngine,
    ParallelCoordinatesCanvasStatusBits,
    ParallelCoordinatesCanvasSync,
    ParallelCoordinatesDiagnosticCode,
    ParallelDiagnosticCode,
    ParallelCoordinatesEngine,
    ParallelCoordinatesError,
    ParallelCoordinatesMetrics,
    ParallelCoordinatesStatusBits,
    ParallelDiagnosticCode,
    ParallelDimensionAxis,
    ParallelStatusBits,
    ProfileCategory,
    RANGE_DEGENERACY,
    RANGE_DEGENERACY_FAULT,
    RangeDegeneracyError,
    Rect,
    REG_ACTIVE_AXES_COUNT,
    REG_ACTIVE_PROFILE_INDEX,
    REG_ACTIVE_PROFILES_COUNT,
    REG_BRUSH_AXIS,
    REG_BRUSH_WINDOW_SCALED,
    REG_BRUSHING_AXIS_INDEX,
    REG_BRUSHING_WINDOW_SCALED,
    REG_CORRELATION_INDEX_SCALED,
    REG_DIAG_CODE,
    REG_DIAGNOSTIC_CODE,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_MEAN_CORRELATION_INDEX_SCALED,
    REG_OUTLIER_COUNT,
    REG_OUTLIER_PROFILES_COUNT,
    REG_PARALLEL_AXES_COUNT,
    REG_SELECTED_PROFILE_INDEX,
    REG_TOTAL_AXES_COUNT,
    REG_TOTAL_PROFILES_COUNT,
    REG_W240_ACTIVE_PROFILES,
    REG_W240_BRUSH_AXIS,
    REG_W240_BRUSH_WINDOW,
    REG_W240_CORRELATION_INDEX,
    REG_W240_DIAG_CODE,
    REG_W240_OUTLIER_COUNT,
    REG_W240_PARALLEL_AXES,
    REG_W240_SELECTED_PROFILE,
    SIGMA_OUTLIER_THRESHOLD,
    TelemetryProfile,
    W240_PARALLEL_COORDINATES_PURE_ST_POU,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    build_cubic_bezier_path,
    build_piecewise_linear_path,
    calculate_contrast_ratio,
    calculate_mean_correlation_index,
    create_canonical_parallel_axes,
    create_canonical_parallel_coordinates_canvas,
    create_canonical_telemetry_profiles,
    generate_parallel_coordinates_canvas_svg,
    layout_parallel_axes,
    relative_luminance,
    run_parallel_coordinates_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_parallel_coordinates_canvas_pure_st,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate 16-bit diagnostic codes, signed/unsigned equality, register maps, coils, and enums."""

    def test_diagnostic_code_signed_unsigned_equality(self) -> None:
        """DiagnosticCode must equate both signed (-4095) and unsigned (0xF001) representations."""
        code_pos = DiagnosticCode(0x0000)
        assert code_pos == 0
        assert code_pos == 0x0000

        code_f601 = DiagnosticCode(0xF601)
        assert code_f601 == 0xF601
        assert code_f601 == (0xF601 - 0x10000)  # -2559 signed 16-bit
        assert code_f601 == -2559

        code_f602 = DiagnosticCode(0xF602)
        assert code_f602 == 0xF602
        assert code_f602 == (0xF602 - 0x10000)  # -2558

        code_f603 = DiagnosticCode(0xF603)
        assert code_f603 == 0xF603
        assert code_f603 == (0xF603 - 0x10000)  # -2557

        code_f604 = DiagnosticCode(0xF604)
        assert code_f604 == 0xF604
        assert code_f604 == (0xF604 - 0x10000)  # -2556

    def test_diagnostic_code_hashing_in_collections(self) -> None:
        """DiagnosticCode must hash consistently based on 16-bit unsigned masking."""
        code1 = DiagnosticCode(0xF601)
        code2 = DiagnosticCode(0xF601 - 0x10000)
        s = {code1}
        assert code2 in s
        d = {code1: "SINGULARITY"}
        assert d[code2] == "SINGULARITY"

    def test_diagnostic_code_constants_and_aliases(self) -> None:
        """Verify diagnostic code constants match specific hexadecimal values."""
        assert DIAG_EVENT_OK == 0x0000
        assert DIAG_OK == DIAG_EVENT_OK
        assert PARALLEL_COORDS_OK == DIAG_EVENT_OK
        assert PARALLEL_OK == DIAG_EVENT_OK

        assert DIAG_ERR_GEOMETRY_SINGULARITY == 0xF601
        assert GEOMETRY_SINGULARITY == DIAG_ERR_GEOMETRY_SINGULARITY
        assert GEOMETRY_SINGULARITY_FAULT == DIAG_ERR_GEOMETRY_SINGULARITY

        assert DIAG_ERR_INSUFFICIENT_AXES == 0xF602
        assert INSUFFICIENT_AXES == DIAG_ERR_INSUFFICIENT_AXES
        assert INSUFFICIENT_AXES_FAULT == DIAG_ERR_INSUFFICIENT_AXES

        assert DIAG_ERR_RANGE_DEGENERACY == 0xF603
        assert RANGE_DEGENERACY == DIAG_ERR_RANGE_DEGENERACY
        assert RANGE_DEGENERACY_FAULT == DIAG_ERR_RANGE_DEGENERACY

        assert DIAG_ERR_CANVAS_OVERFLOW == 0xF604
        assert CANVAS_OVERFLOW == DIAG_ERR_CANVAS_OVERFLOW
        assert CANVAS_OVERFLOW_FAULT == DIAG_ERR_CANVAS_OVERFLOW

    def test_diagnostic_code_class_aliases(self) -> None:
        """Verify class aliases point to DiagnosticCode."""
        assert ParallelCoordinatesDiagnosticCode is DiagnosticCode
        assert ParallelCoordinatesCanvasDiagnosticCode is DiagnosticCode
        assert ParallelDiagnosticCode is DiagnosticCode

    def test_profile_category_enum(self) -> None:
        """ProfileCategory enum must define expected classification members."""
        assert ProfileCategory.NORMAL.value == "NORMAL"
        assert ProfileCategory.WARNING.value == "WARNING"
        assert ProfileCategory.OUTLIER.value == "OUTLIER"
        assert ProfileCategory.SELECTED.value == "SELECTED"

    def test_status_bits_enum_flags(self) -> None:
        """ParallelCoordinatesStatusBits IntFlag members must occupy distinct binary bit positions."""
        assert ParallelCoordinatesStatusBits.NOMINAL_OPERATION == 1 << 0
        assert ParallelCoordinatesStatusBits.CANVAS_ACTIVE == 1 << 1
        assert ParallelCoordinatesStatusBits.OUTLIER_ALARM_ACTIVE == 1 << 2
        assert ParallelCoordinatesStatusBits.BRUSHING_ACTIVE == 1 << 3
        assert ParallelCoordinatesStatusBits.GEOMETRY_SINGULARITY_FAULT == 1 << 4
        assert ParallelCoordinatesStatusBits.INSUFFICIENT_AXES_FAULT == 1 << 5
        assert ParallelCoordinatesStatusBits.RANGE_DEGENERACY_FAULT == 1 << 6
        assert ParallelCoordinatesStatusBits.CANVAS_OVERFLOW_FAULT == 1 << 7
        assert ParallelCoordinatesStatusBits.SPLINE_COMPUTED == 1 << 8
        assert ParallelCoordinatesStatusBits.SVG_VALID == 1 << 9
        assert ParallelCoordinatesStatusBits.WCAG_AAA_VERIFIED == 1 << 10

    def test_status_bits_aliases(self) -> None:
        """Verify aliases for ParallelCoordinatesStatusBits."""
        assert ParallelStatusBits is ParallelCoordinatesStatusBits
        assert ParallelCoordinatesCanvasStatusBits is ParallelCoordinatesStatusBits

    def test_horner_word_registers_addresses(self) -> None:
        """Verify Horner OCS register strings %R2010..%R2017."""
        assert REG_PARALLEL_AXES_COUNT == "%R2010"
        assert REG_ACTIVE_PROFILES_COUNT == "%R2011"
        assert REG_OUTLIER_PROFILES_COUNT == "%R2012"
        assert REG_SELECTED_PROFILE_INDEX == "%R2013"
        assert REG_MEAN_CORRELATION_INDEX_SCALED == "%R2014"
        assert REG_BRUSHING_AXIS_INDEX == "%R2015"
        assert REG_BRUSHING_WINDOW_SCALED == "%R2016"
        assert REG_DIAGNOSTIC_CODE == "%R2017"

    def test_register_aliases_equivalence(self) -> None:
        """Verify all register aliases resolve to their exact canonical address."""
        assert REG_TOTAL_AXES_COUNT == "%R2010"
        assert REG_ACTIVE_AXES_COUNT == "%R2010"
        assert REG_TOTAL_PROFILES_COUNT == "%R2011"
        assert REG_OUTLIER_COUNT == "%R2012"
        assert REG_ACTIVE_PROFILE_INDEX == "%R2013"
        assert REG_CORRELATION_INDEX_SCALED == "%R2014"
        assert REG_BRUSH_AXIS == "%R2015"
        assert REG_BRUSH_WINDOW_SCALED == "%R2016"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2017"
        assert REG_DIAG_CODE == "%R2017"

    def test_wave_w240_register_aliases(self) -> None:
        """Verify wave-specific W240 aliases resolve properly."""
        assert REG_W240_PARALLEL_AXES == "%R2010"
        assert REG_W240_ACTIVE_PROFILES == "%R2011"
        assert REG_W240_OUTLIER_COUNT == "%R2012"
        assert REG_W240_SELECTED_PROFILE == "%R2013"
        assert REG_W240_CORRELATION_INDEX == "%R2014"
        assert REG_W240_BRUSH_AXIS == "%R2015"
        assert REG_W240_BRUSH_WINDOW == "%R2016"
        assert REG_W240_DIAG_CODE == "%R2017"

    def test_discrete_coils_addresses_and_aliases(self) -> None:
        """Verify discrete coils %M469 and %M470."""
        assert COIL_PARALLEL_COORDINATES_ACTIVE == "%M469"
        assert COIL_MULTIVARIATE_OUTLIER_ALARM == "%M470"

        assert COIL_PARALLEL_ACTIVE == "%M469"
        assert COIL_CANVAS_ACTIVE == "%M469"
        assert COIL_W240_CANVAS_ACTIVE == "%M469"

        assert COIL_OUTLIER_ALARM == "%M470"
        assert COIL_OUTLIER_ALARM_ACTIVE == "%M470"
        assert COIL_ALARM_ACTIVE == "%M470"
        assert COIL_W240_OUTLIER_ALARM == "%M470"

    def test_viewport_and_layout_constants(self) -> None:
        """Verify 1200x750 viewport and default layout coordinates."""
        assert CANVAS_VIEWPORT_WIDTH == 1200
        assert CANVAS_VIEWPORT_HEIGHT == 750
        assert DEFAULT_CANVAS_X == 20.0
        assert DEFAULT_CANVAS_Y == 86.0
        assert DEFAULT_CANVAS_WIDTH == 1160.0
        assert DEFAULT_CANVAS_HEIGHT == 644.0
        assert LAYOUT_BOUNDS_X == DEFAULT_CANVAS_X
        assert LAYOUT_BOUNDS_Y == DEFAULT_CANVAS_Y
        assert LAYOUT_BOUNDS_WIDTH == DEFAULT_CANVAS_WIDTH
        assert LAYOUT_BOUNDS_HEIGHT == DEFAULT_CANVAS_HEIGHT

    def test_palette_and_theme_constants(self) -> None:
        """Verify colors for dark theme and status indicators."""
        assert COLOR_DARK_THEME_BACKING == "#0B0F19"
        assert COLOR_PANEL_BG == "#161B22"
        assert COLOR_BORDER == "#21262D"
        assert COLOR_DECOUPLED_BADGE == "#050811"
        assert COLOR_EMERALD == "#10B981"
        assert COLOR_AMBER == "#F59E0B"
        assert COLOR_CRIMSON == "#EF4444"
        assert COLOR_CYAN == "#06B6D4"
        assert COLOR_NORMAL == COLOR_EMERALD
        assert COLOR_WARNING == COLOR_AMBER
        assert COLOR_OUTLIER == COLOR_CRIMSON
        assert COLOR_ALARM == COLOR_CRIMSON
        assert COLOR_SELECTED == COLOR_CYAN
        assert COLOR_FOCUS == COLOR_CYAN

    def test_wcag_and_operational_targets(self) -> None:
        """Verify accessibility targets and 3-sigma threshold."""
        assert WCAG_AAA_BADGE_CONTRAST_TARGET == 18.0
        assert WCAG_AAA_TEXT_CONTRAST_TARGET == 7.0
        assert WCAG_GRAPHICAL_CONTRAST_TARGET == 3.0
        assert SIGMA_OUTLIER_THRESHOLD == 3.0
        assert CANONICAL_AXES_COUNT == 6
        assert CANONICAL_ACTIVE_PROFILES_COUNT == 8
        assert CANONICAL_MEAN_CORRELATION_INDEX_SCALED == 7850


# ============================================================================
# 2. TestParallelDimensionAxisDataclass
# ============================================================================

class TestParallelDimensionAxisDataclass:
    """Test axis initialization, normalization, denormalization, tick generation, and z-score."""

    def test_axis_initialization_and_tag_generation(self) -> None:
        """Axis dataclass must automatically generate tag if not supplied."""
        ax = ParallelDimensionAxis(
            index=0,
            name="Bed Temperature",
            unit="°C",
            min_val=300.0,
            max_val=400.0,
            nominal_ref=350.0,
            sigma=5.0,
        )
        assert ax.index == 0
        assert ax.name == "Bed Temperature"
        assert ax.unit == "°C"
        assert ax.tag == "AXIS_0_BED_TEMPERATURE"
        assert ax.span == 100.0

    def test_axis_span_calculation(self) -> None:
        """Span is max_val - min_val."""
        ax = ParallelDimensionAxis(1, "Press", "bar", 0.8, 2.0, 1.2, 0.05)
        assert math.isclose(ax.span, 1.2, rel_tol=1e-6)

    def test_axis_normalization_nominal(self) -> None:
        """Value at nominal_ref normalizes correctly."""
        ax = ParallelDimensionAxis(0, "Temp", "°C", 300.0, 400.0, 350.0, 5.0)
        assert math.isclose(ax.normalize(350.0), 0.5, rel_tol=1e-6)
        assert math.isclose(ax.normalize(300.0), 0.0, rel_tol=1e-6)
        assert math.isclose(ax.normalize(400.0), 1.0, rel_tol=1e-6)

    def test_axis_normalization_intermediate_values(self) -> None:
        """Intermediate values normalize linearly."""
        ax = ParallelDimensionAxis(2, "Conv", "%", 90.0, 100.0, 98.5, 0.4)
        assert math.isclose(ax.normalize(95.0), 0.5, rel_tol=1e-6)
        assert math.isclose(ax.normalize(92.5), 0.25, rel_tol=1e-6)
        assert math.isclose(ax.normalize(97.5), 0.75, rel_tol=1e-6)

    def test_axis_denormalize_roundtrip(self) -> None:
        """denormalize(normalize(val)) == val within floating tolerance."""
        ax = ParallelDimensionAxis(3, "Sel", "%", 85.0, 100.0, 95.2, 0.6)
        for v in [85.0, 88.3, 95.2, 99.1, 100.0]:
            norm = ax.normalize(v)
            assert math.isclose(ax.denormalize(norm), v, rel_tol=1e-6)

    def test_axis_val_to_y_screen_mapping(self) -> None:
        """Max value is at top (y_top) and min value is at bottom (y_bottom)."""
        ax = ParallelDimensionAxis(
            0, "Temp", "°C", 300.0, 400.0, 350.0, 5.0,
            x_pos=100.0, y_top=150.0, y_bottom=630.0
        )
        assert math.isclose(ax.val_to_y(300.0), 630.0, rel_tol=1e-6)  # Min at bottom
        assert math.isclose(ax.val_to_y(400.0), 150.0, rel_tol=1e-6)  # Max at top
        assert math.isclose(ax.val_to_y(350.0), 390.0, rel_tol=1e-6)  # Midpoint

    def test_axis_y_to_val_inverse_mapping(self) -> None:
        """y_to_val must invert val_to_y accurately."""
        ax = ParallelDimensionAxis(
            0, "Temp", "°C", 300.0, 400.0, 350.0, 5.0,
            x_pos=100.0, y_top=150.0, y_bottom=630.0
        )
        for v in [300.0, 325.0, 350.0, 375.0, 400.0]:
            y = ax.val_to_y(v)
            assert math.isclose(ax.y_to_val(y), v, rel_tol=1e-6)

    def test_axis_z_score_calculation(self) -> None:
        """z_score = (val - nominal_ref) / sigma."""
        ax = ParallelDimensionAxis(0, "Temp", "°C", 300.0, 400.0, 350.0, 5.0)
        assert math.isclose(ax.z_score(350.0), 0.0, rel_tol=1e-6)
        assert math.isclose(ax.z_score(355.0), 1.0, rel_tol=1e-6)
        assert math.isclose(ax.z_score(340.0), -2.0, rel_tol=1e-6)
        assert math.isclose(ax.z_score(365.0), 3.0, rel_tol=1e-6)
        assert math.isclose(ax.z_score(370.0), 4.0, rel_tol=1e-6)

    def test_axis_is_outlier_3_sigma_rule(self) -> None:
        """is_outlier returns True if |z_score| > 3.0."""
        ax = ParallelDimensionAxis(0, "Temp", "°C", 300.0, 400.0, 350.0, 5.0)
        assert ax.is_outlier(350.0) is False
        assert ax.is_outlier(364.9) is False
        assert ax.is_outlier(365.1) is True
        assert ax.is_outlier(334.9) is True

    def test_axis_zero_span_safety(self) -> None:
        """Zero span returns 0.5 without ZeroDivisionError."""
        ax = ParallelDimensionAxis(0, "Degenerate", "unit", 100.0, 100.0, 100.0, 0.0)
        assert ax.normalize(100.0) == 0.5
        assert ax.z_score(100.0) == 0.0

    def test_canonical_axes_factory(self) -> None:
        """create_canonical_parallel_axes must instantiate all 6 process axes."""
        axes = create_canonical_parallel_axes()
        assert len(axes) == 6
        names = [a.name for a in axes]
        assert "Bed Temperature" in names
        assert "Operating Pressure" in names
        assert "Oxime Conversion" in names
        assert "Caprolactam Selectivity" in names
        assert "Superficial Velocity" in names
        assert "Vibration Level" in names


# ============================================================================
# 3. TestTelemetryProfileDataclass
# ============================================================================

class TestTelemetryProfileDataclass:
    """Test telemetry profile properties, screen coordinates, and outlier evaluation."""

    def test_profile_initialization_defaults(self) -> None:
        """TelemetryProfile initializes with expected defaults."""
        prof = TelemetryProfile(
            id=0,
            name="Stream A",
            values=[350.0, 1.20, 98.8, 95.5, 0.45, 1.50],
        )
        assert prof.id == 0
        assert prof.name == "Stream A"
        assert len(prof.values) == 6
        assert prof.category == ProfileCategory.NORMAL
        assert prof.color == COLOR_EMERALD
        assert prof.is_outlier is False
        assert prof.in_brush_window is True

    def test_profile_get_point_on_axis(self) -> None:
        """get_point returns tuple (ax.x_pos, ax.val_to_y(val))."""
        ax = ParallelDimensionAxis(
            0, "Temp", "°C", 300.0, 400.0, 350.0, 5.0,
            x_pos=200.0, y_top=150.0, y_bottom=630.0
        )
        prof = TelemetryProfile(0, "Test", [350.0])
        px, py = prof.get_point(0, ax)
        assert px == 200.0
        assert math.isclose(py, 390.0, rel_tol=1e-6)

    def test_profile_update_outlier_status_nominal(self) -> None:
        """Nominal profile values result in NORMAL category and emerald color."""
        axes = create_canonical_parallel_axes()
        prof = TelemetryProfile(0, "Nominal", [350.0, 1.20, 98.5, 95.2, 0.45, 1.50])
        prof.update_outlier_status(axes)
        assert prof.is_outlier is False
        assert prof.category == ProfileCategory.NORMAL
        assert prof.color == COLOR_EMERALD
        assert prof.max_z_score <= 2.0

    def test_profile_update_outlier_status_warning(self) -> None:
        """2.0 < z <= 3.0 results in WARNING category and amber color."""
        axes = create_canonical_parallel_axes()
        # Temperature 362.0 -> z = (362 - 350) / 5 = 2.4 (Warning)
        prof = TelemetryProfile(1, "Warning", [362.0, 1.20, 98.5, 95.2, 0.45, 1.50])
        prof.update_outlier_status(axes)
        assert prof.is_outlier is False
        assert prof.category == ProfileCategory.WARNING
        assert prof.color == COLOR_AMBER
        assert 2.0 < prof.max_z_score <= 3.0

    def test_profile_update_outlier_status_outlier(self) -> None:
        """z > 3.0 results in OUTLIER category, crimson color, and is_outlier=True."""
        axes = create_canonical_parallel_axes()
        # Vibration 9.5 mm/s -> z = (9.5 - 1.5) / 0.3 = 26.67 sigma (Critical outlier)
        prof = TelemetryProfile(2, "Outlier", [350.0, 1.20, 98.5, 95.2, 0.45, 9.50])
        prof.update_outlier_status(axes)
        assert prof.is_outlier is True
        assert prof.category == ProfileCategory.OUTLIER
        assert prof.color == COLOR_CRIMSON
        assert prof.max_z_score > 3.0

    def test_canonical_profiles_factory_count_and_types(self) -> None:
        """create_canonical_telemetry_profiles returns 8 profiles with 6 values each."""
        profs = create_canonical_telemetry_profiles()
        assert len(profs) == 8
        for p in profs:
            assert isinstance(p, TelemetryProfile)
            assert len(p.values) == 6
            assert p.is_outlier is False


# ============================================================================
# 4. TestCanvasGeometryAndLayout
# ============================================================================

class TestCanvasGeometryAndLayout:
    """Validate 1200x750 viewport, bounds, spacing, and Rect containment methods."""

    def test_rect_properties(self) -> None:
        """Rect right, bottom, and area calculations."""
        r = Rect(10.0, 20.0, 100.0, 200.0)
        assert r.right == 110.0
        assert r.bottom == 220.0
        assert r.area == 20000.0

    def test_rect_contains_point(self) -> None:
        """contains_point handles interior and border points."""
        r = Rect(10.0, 20.0, 100.0, 200.0)
        assert r.contains_point(50.0, 100.0) is True
        assert r.contains_point(10.0, 20.0) is True
        assert r.contains_point(110.0, 220.0) is True
        assert r.contains_point(5.0, 100.0) is False
        assert r.contains_point(50.0, 230.0) is False

    def test_rect_contains_rect(self) -> None:
        """contains_rect checks complete geometric containment."""
        r1 = Rect(0.0, 0.0, 1000.0, 1000.0)
        r2 = Rect(50.0, 50.0, 200.0, 200.0)
        r3 = Rect(50.0, 50.0, 1200.0, 200.0)
        assert r1.contains_rect(r2) is True
        assert r1.contains_rect(r3) is False

    def test_layout_parallel_axes_positions(self) -> None:
        """Axes must be laid out with non-negative coordinates evenly spaced."""
        axes = create_canonical_parallel_axes()
        bounds = Rect(20.0, 86.0, 1160.0, 644.0)
        layout_parallel_axes(axes, bounds)

        for i, ax in enumerate(axes):
            assert ax.x_pos >= bounds.x
            assert ax.x_pos <= bounds.right
            assert ax.y_top == bounds.y + 48.0
            assert ax.y_bottom == bounds.bottom - 44.0
            if i > 0:
                assert ax.x_pos > axes[i - 1].x_pos

        # Check even spacing
        dx0 = axes[1].x_pos - axes[0].x_pos
        for i in range(len(axes) - 1):
            dx = axes[i + 1].x_pos - axes[i].x_pos
            assert math.isclose(dx, dx0, rel_tol=1e-4)

    def test_layout_geometry_singularity_raises_error(self) -> None:
        """Non-positive bounds width or height raises GeometrySingularityError."""
        axes = create_canonical_parallel_axes()
        with pytest.raises(GeometrySingularityError):
            layout_parallel_axes(axes, Rect(0.0, 0.0, 0.0, 500.0))
        with pytest.raises(GeometrySingularityError):
            layout_parallel_axes(axes, Rect(0.0, 0.0, 500.0, -10.0))

    def test_layout_insufficient_axes_raises_error(self) -> None:
        """Fewer than 3 axes raises InsufficientAxesError."""
        axes = create_canonical_parallel_axes()[:2]
        bounds = Rect(20.0, 86.0, 1160.0, 644.0)
        with pytest.raises(InsufficientAxesError):
            layout_parallel_axes(axes, bounds)

    def test_layout_range_degeneracy_raises_error(self) -> None:
        """Axis min >= max raises RangeDegeneracyError."""
        axes = create_canonical_parallel_axes()
        axes[0].max_val = axes[0].min_val
        bounds = Rect(20.0, 86.0, 1160.0, 644.0)
        with pytest.raises(RangeDegeneracyError):
            layout_parallel_axes(axes, bounds)


# ============================================================================
# 5. TestPolylineSplineInterpolation
# ============================================================================

class TestPolylineSplineInterpolation:
    """Test piecewise linear and cubic Bézier SVG path generation."""

    def test_piecewise_linear_empty_and_single_point(self) -> None:
        """Piecewise linear path handles 0 and 1 point gracefully."""
        assert build_piecewise_linear_path([]) == ""
        assert build_piecewise_linear_path([(10.0, 20.0)]) == "M 10.00,20.00"

    def test_piecewise_linear_multi_points(self) -> None:
        """Piecewise linear path produces M and L commands."""
        pts = [(10.0, 20.0), (30.0, 40.0), (50.0, 60.0)]
        path = build_piecewise_linear_path(pts)
        assert path.startswith("M 10.00,20.00")
        assert "L 30.00,40.00" in path
        assert "L 50.00,60.00" in path

    def test_cubic_bezier_empty_and_single_point(self) -> None:
        """Cubic Bézier path handles 0 and 1 point gracefully."""
        assert build_cubic_bezier_path([]) == ""
        assert build_cubic_bezier_path([(10.0, 20.0)]) == "M 10.00,20.00"

    def test_cubic_bezier_two_points_control_points(self) -> None:
        """Cubic Bézier S-curve control points are positioned at midpoint X with horizontal tangents."""
        p0 = (100.0, 200.0)
        p1 = (300.0, 400.0)
        path = build_cubic_bezier_path([p0, p1])
        # Expected: M 100.00,200.00 C 200.00,200.00 200.00,400.00 300.00,400.00
        assert "M 100.00,200.00" in path
        assert "C 200.00,200.00 200.00,400.00 300.00,400.00" in path

    def test_cubic_bezier_multi_point_segments(self) -> None:
        """Cubic Bézier path has N-1 C segments for N points."""
        pts = [(100.0, 200.0), (200.0, 300.0), (300.0, 250.0), (400.0, 500.0)]
        path = build_cubic_bezier_path(pts)
        c_count = path.count(" C ")
        assert c_count == 3


# ============================================================================
# 6. TestBrushingAndFiltering
# ============================================================================

class TestBrushingAndFiltering:
    """Test interactive profile selection, brushing axis, and Pearson correlation."""

    def test_canonical_mean_correlation_index(self) -> None:
        """calculate_mean_correlation_index returns 0.7850 for nominal canonical dataset."""
        axes = create_canonical_parallel_axes()
        profs = create_canonical_telemetry_profiles()
        corr = calculate_mean_correlation_index(profs, axes)
        assert math.isclose(corr, CANONICAL_MEAN_CORRELATION_INDEX, rel_tol=1e-4)

    def test_mean_correlation_insufficient_axes(self) -> None:
        """Fewer than 2 axes returns default correlation index."""
        profs = create_canonical_telemetry_profiles()
        assert calculate_mean_correlation_index(profs, []) == CANONICAL_MEAN_CORRELATION_INDEX

    def test_mean_correlation_insufficient_profiles(self) -> None:
        """Fewer than 2 profiles returns default correlation index."""
        axes = create_canonical_parallel_axes()
        assert calculate_mean_correlation_index([], axes) == CANONICAL_MEAN_CORRELATION_INDEX

    def test_select_profile_valid_and_invalid(self) -> None:
        """select_profile updates index and rejects out-of-range values."""
        canvas = create_canonical_parallel_coordinates_canvas()
        assert canvas.select_profile(3) is True
        assert canvas.selected_profile_index == 3
        assert canvas.metrics.selected_profile_index == 3
        assert canvas.select_profile(99) is False
        assert canvas.selected_profile_index == 3

    def test_set_brushing_valid_and_invalid(self) -> None:
        """set_brushing updates axis and window width."""
        canvas = create_canonical_parallel_coordinates_canvas()
        assert canvas.set_brushing(2, window_scaled=150) is True
        assert canvas.brushing_axis_index == 2
        assert canvas.brushing_window_scaled == 150
        assert canvas.set_brushing(-1) is False
        assert canvas.set_brushing(10) is False


# ============================================================================
# 7. TestOutlierAlarmCondition
# ============================================================================

class TestOutlierAlarmCondition:
    """Test multi-dimensional distance evaluation, outlier injection, and %M470 trip."""

    def test_nominal_baseline_has_zero_outliers(self) -> None:
        """Nominal profiles have 0 outliers and %M470 is False."""
        canvas = create_canonical_parallel_coordinates_canvas()
        assert canvas.metrics.outlier_profiles_count == 0
        assert canvas.metrics.outlier_alarm_active is False
        assert canvas.reg_table.read_bit(COIL_MULTIVARIATE_OUTLIER_ALARM) is False
        assert canvas.reg_table.read_word(REG_OUTLIER_PROFILES_COUNT) == 0

    def test_outlier_injection_trips_alarm_coil_m470(self) -> None:
        """Injecting 3-sigma outlier asserts %M470 and increments OutlierProfilesCount."""
        canvas = create_canonical_parallel_coordinates_canvas()
        # Vibration 9.5 mm/s on stream 0 trips 3-sigma outlier
        canvas.trigger_outlier(profile_index=0, axis_index=5, outlier_value=9.5)

        assert canvas.metrics.outlier_profiles_count >= 1
        assert canvas.metrics.outlier_alarm_active is True
        assert canvas.reg_table.read_bit(COIL_MULTIVARIATE_OUTLIER_ALARM) is True
        assert canvas.reg_table.read_word(REG_OUTLIER_PROFILES_COUNT) >= 1
        assert (canvas.status_bits & ParallelCoordinatesStatusBits.OUTLIER_ALARM_ACTIVE) != 0

    def test_outlier_recovery_resets_alarm(self) -> None:
        """reset_nominal clears outliers and de-asserts %M470."""
        canvas = create_canonical_parallel_coordinates_canvas()
        canvas.trigger_outlier(profile_index=0, axis_index=5, outlier_value=9.5)
        assert canvas.metrics.outlier_alarm_active is True

        canvas.reset_nominal()
        assert canvas.metrics.outlier_profiles_count == 0
        assert canvas.metrics.outlier_alarm_active is False
        assert canvas.reg_table.read_bit(COIL_MULTIVARIATE_OUTLIER_ALARM) is False
        assert canvas.reg_table.read_word(REG_OUTLIER_PROFILES_COUNT) == 0


# ============================================================================
# 8. TestSVGGenerationAndXMLSyntax
# ============================================================================

class TestSVGGenerationAndXMLSyntax:
    """Test standalone W3C SVG 1.1 generation, ElementTree XML validation, <path> and <line> tags."""

    def test_svg_is_valid_xml(self) -> None:
        """render_svg produces well-formed XML parseable by ElementTree."""
        canvas = create_canonical_parallel_coordinates_canvas()
        svg_xml = canvas.render_svg()
        root = ET.fromstring(svg_xml)
        assert root.tag.endswith("svg")

    def test_svg_viewport_dimensions(self) -> None:
        """SVG root element has width 1200, height 750, and valid viewBox."""
        canvas = create_canonical_parallel_coordinates_canvas()
        svg_xml = canvas.render_svg()
        root = ET.fromstring(svg_xml)
        assert root.attrib.get("width") == "1200"
        assert root.attrib.get("height") == "750"
        assert root.attrib.get("viewBox") == "0 0 1200 750"

    def test_svg_contains_paths_and_lines(self) -> None:
        """SVG must contain polylines (<path>) and vertical axes (<line>)."""
        canvas = create_canonical_parallel_coordinates_canvas()
        svg_xml = canvas.render_svg()
        root = ET.fromstring(svg_xml)
        paths = root.findall(".//{http://www.w3.org/2000/svg}path") or root.findall(".//path")
        lines = root.findall(".//{http://www.w3.org/2000/svg}line") or root.findall(".//line")
        assert len(paths) >= 8  # 8 profile polylines
        assert len(lines) >= 6  # 6 vertical axis lines

    def test_svg_contains_decoupled_badge(self) -> None:
        """SVG must contain decoupled badge rect with #050811 backing."""
        canvas = create_canonical_parallel_coordinates_canvas()
        svg_xml = canvas.render_svg()
        assert COLOR_DECOUPLED_BADGE in svg_xml

    def test_svg_render_spline_toggle(self) -> None:
        """SVG can render with Bézier splines or piecewise linear paths."""
        canvas = create_canonical_parallel_coordinates_canvas()
        svg_spline = canvas.render_svg(render_spline=True)
        svg_linear = canvas.render_svg(render_spline=False)

        root_spline = ET.fromstring(svg_spline)
        root_linear = ET.fromstring(svg_linear)

        paths_spline = [p.attrib.get("d", "") for p in root_spline.findall(".//{http://www.w3.org/2000/svg}path") or root_spline.findall(".//path")]
        paths_linear = [p.attrib.get("d", "") for p in root_linear.findall(".//{http://www.w3.org/2000/svg}path") or root_linear.findall(".//path")]

        # Spline paths have cubic Bézier 'C' commands
        assert any(" C " in d for d in paths_spline)
        # Linear paths do not have cubic Bézier 'C' commands in their path d attribute
        assert not any(" C " in d for d in paths_linear)
        assert any(" L " in d for d in paths_linear)


# ============================================================================
# 9. TestWCAG21AAAContrastAndVisualLegibility
# ============================================================================

class TestWCAG21AAAContrastAndVisualLegibility:
    """Test WCAG 2.1 AAA relative luminance, contrast formulas, badge contrast > 18:1, text > 7:1."""

    def test_srgb_channel_to_linear(self) -> None:
        """Test photometric linear conversion."""
        assert srgb_channel_to_linear(0) == 0.0
        assert math.isclose(srgb_channel_to_linear(255), 1.0, rel_tol=1e-5)
        # Low value linear branch
        assert srgb_channel_to_linear(5) == (5 / 255.0) / 12.92

    def test_relative_luminance_extremes(self) -> None:
        """Pure black is 0.0 and pure white is 1.0."""
        assert math.isclose(relative_luminance("#000000"), 0.0, abs_tol=1e-6)
        assert math.isclose(relative_luminance("#FFFFFF"), 1.0, abs_tol=1e-6)

    def test_relative_luminance_invalid_fallback(self) -> None:
        """Invalid color string returns 0.0."""
        assert relative_luminance("invalid") == 0.0

    def test_contrast_ratio_black_and_white(self) -> None:
        """White on black has exact 21:1 contrast ratio."""
        cr = calculate_contrast_ratio("#FFFFFF", "#000000")
        assert math.isclose(cr, 21.0, rel_tol=1e-4)

    def test_contrast_ratio_symmetry(self) -> None:
        """Contrast ratio is commutative."""
        cr1 = calculate_contrast_ratio("#10B981", "#0B0F19")
        cr2 = calculate_contrast_ratio("#0B0F19", "#10B981")
        assert math.isclose(cr1, cr2, rel_tol=1e-6)

    def test_decoupled_badge_contrast_exceeds_18_to_1(self) -> None:
        """White text on decoupled badge backing #050811 must exceed 18:1."""
        cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert cr >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert cr > 18.0

    def test_primary_text_on_panel_exceeds_7_to_1(self) -> None:
        """White text on panel bg #161B22 must exceed 7.0:1."""
        cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_PANEL_BG)
        assert cr >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert cr > 7.0

    def test_validate_wcag_aaa_contrast_helper(self) -> None:
        """validate_wcag_aaa_contrast returns compliance and ratios."""
        ok, text_cr, badge_cr = validate_wcag_aaa_contrast()
        assert ok is True
        assert badge_cr >= 18.0
        assert text_cr >= 7.0


# ============================================================================
# 10. TestHornerOCSSynchronizationAndRegisters
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Validate %R2010..%R2017 and %M469..%M470 bit-exact synchronization, PrivilegeMode.SYSTEM."""

    def test_nominal_registers_synchronization(self) -> None:
        """Registers %R2010..%R2017 match nominal values bit-for-bit."""
        reg_table = RegisterTable()
        canvas = ParallelCoordinatesCanvas(reg_table=reg_table)
        canvas.scan_step()

        assert reg_table.read_word(REG_PARALLEL_AXES_COUNT) == 6
        assert reg_table.read_word(REG_ACTIVE_PROFILES_COUNT) == 8
        assert reg_table.read_word(REG_OUTLIER_PROFILES_COUNT) == 0
        assert reg_table.read_word(REG_SELECTED_PROFILE_INDEX) == 0
        assert reg_table.read_word(REG_MEAN_CORRELATION_INDEX_SCALED) == 7850
        assert reg_table.read_word(REG_BRUSHING_AXIS_INDEX) == 0
        assert reg_table.read_word(REG_BRUSHING_WINDOW_SCALED) == 116
        assert (reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

        assert reg_table.read_bit(COIL_PARALLEL_COORDINATES_ACTIVE) is True
        assert reg_table.read_bit(COIL_MULTIVARIATE_OUTLIER_ALARM) is False

    def test_sync_from_registers_updates_selected_profile(self) -> None:
        """Writing %R2013 from external controller updates selected profile."""
        reg_table = RegisterTable()
        canvas = ParallelCoordinatesCanvas(reg_table=reg_table)

        reg_table.write_word(REG_SELECTED_PROFILE_INDEX, 4, privilege=PrivilegeMode.SYSTEM)
        canvas.sync_from_registers()
        assert canvas.selected_profile_index == 4
        assert canvas.metrics.selected_profile_index == 4

    def test_sync_from_registers_updates_brushing_axis(self) -> None:
        """Writing %R2015 from external controller updates brushing axis."""
        reg_table = RegisterTable()
        canvas = ParallelCoordinatesCanvas(reg_table=reg_table)

        reg_table.write_word(REG_BRUSHING_AXIS_INDEX, 3, privilege=PrivilegeMode.SYSTEM)
        canvas.sync_from_registers()
        assert canvas.brushing_axis_index == 3
        assert canvas.metrics.brushing_axis_index == 3


# ============================================================================
# 11. TestDiagnosticFaultConditionsAndRecovery
# ============================================================================

class TestDiagnosticFaultConditionsAndRecovery:
    """Test 0xF601, 0xF602, 0xF603, 0xF604 diagnostic fault injection and recovery."""

    def test_geometry_singularity_fault_0xf601(self) -> None:
        """Zero canvas dimensions asserts 0xF601 and deactivates canvas."""
        canvas = create_canonical_parallel_coordinates_canvas()
        canvas.trigger_geometry_singularity()
        assert canvas.diagnostic_code == 0xF601
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF601
        assert canvas.canvas_active is False
        assert canvas.reg_table.read_bit(COIL_PARALLEL_COORDINATES_ACTIVE) is False
        assert (canvas.status_bits & ParallelCoordinatesStatusBits.GEOMETRY_SINGULARITY_FAULT) != 0

    def test_insufficient_axes_fault_0xf602(self) -> None:
        """Fewer than 3 axes asserts 0xF602 and deactivates canvas."""
        canvas = create_canonical_parallel_coordinates_canvas()
        canvas.trigger_insufficient_axes()
        assert canvas.diagnostic_code == 0xF602
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF602
        assert canvas.canvas_active is False
        assert (canvas.status_bits & ParallelCoordinatesStatusBits.INSUFFICIENT_AXES_FAULT) != 0

    def test_range_degeneracy_fault_0xf603(self) -> None:
        """Axis min == max asserts 0xF603 and deactivates canvas."""
        canvas = create_canonical_parallel_coordinates_canvas()
        canvas.trigger_range_degeneracy()
        assert canvas.diagnostic_code == 0xF603
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF603
        assert canvas.canvas_active is False
        assert (canvas.status_bits & ParallelCoordinatesStatusBits.RANGE_DEGENERACY_FAULT) != 0

    def test_canvas_overflow_fault_0xf604(self) -> None:
        """Extreme vertex exceeding bounds asserts 0xF604 and deactivates canvas."""
        canvas = create_canonical_parallel_coordinates_canvas()
        canvas.trigger_canvas_overflow()
        assert canvas.diagnostic_code == 0xF604
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF604
        assert canvas.canvas_active is False
        assert (canvas.status_bits & ParallelCoordinatesStatusBits.CANVAS_OVERFLOW_FAULT) != 0

    def test_reset_nominal_restores_clean_state(self) -> None:
        """reset_nominal recovers from any fault to clean 0x0000 nominal state."""
        canvas = create_canonical_parallel_coordinates_canvas()
        canvas.trigger_range_degeneracy()
        assert canvas.diagnostic_code != 0x0000

        canvas.reset_nominal()
        assert canvas.diagnostic_code == 0x0000
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
        assert canvas.canvas_active is True
        assert canvas.reg_table.read_bit(COIL_PARALLEL_COORDINATES_ACTIVE) is True
        assert (canvas.status_bits & ParallelCoordinatesStatusBits.NOMINAL_OPERATION) != 0


# ============================================================================
# 12. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate Pure IEC 61131-3 Structured Text POU grammar and AST bindings."""

    def test_st_pou_string_constant(self) -> None:
        """PARALLEL_COORDINATES_CANVAS_SYNC_PURE_ST_POU is non-empty and well-formed."""
        assert isinstance(PARALLEL_COORDINATES_CANVAS_SYNC_PURE_ST_POU, str)
        assert len(PARALLEL_COORDINATES_CANVAS_SYNC_PURE_ST_POU) > 100
        assert "PROGRAM ParallelCoordinatesCanvasSync" in PARALLEL_COORDINATES_CANVAS_SYNC_PURE_ST_POU

    def test_st_pou_security_guard_pure_st(self) -> None:
        """SecurityGuard asserts pure ST without raising error."""
        SecurityGuard.assert_pure_st_content(PARALLEL_COORDINATES_CANVAS_SYNC_PURE_ST_POU)

    def test_st_pou_parser_program_name(self) -> None:
        """STParser parses POU as PROGRAM named ParallelCoordinatesCanvasSync."""
        parser = STParser()
        pou = parser.parse_pou(PARALLEL_COORDINATES_CANVAS_SYNC_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "ParallelCoordinatesCanvasSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_st_pou_parser_variables_count(self) -> None:
        """POU has exactly 10 memory-bound variables."""
        parser = STParser()
        pou = parser.parse_pou(PARALLEL_COORDINATES_CANVAS_SYNC_PURE_ST_POU)
        assert len(pou.variables) == 10

    def test_st_pou_parser_variable_bindings(self) -> None:
        """Verify each variable is bound to the exact specified register or coil."""
        parser = STParser()
        pou = parser.parse_pou(PARALLEL_COORDINATES_CANVAS_SYNC_PURE_ST_POU)
        vmap = {v.name: v.address_binding for v in pou.variables}

        assert vmap["ParallelAxesCount"] == "%R2010"
        assert vmap["ActiveProfilesCount"] == "%R2011"
        assert vmap["OutlierProfilesCount"] == "%R2012"
        assert vmap["SelectedProfileIndex"] == "%R2013"
        assert vmap["MeanCorrelationIndexScaled"] == "%R2014"
        assert vmap["BrushingAxisIndex"] == "%R2015"
        assert vmap["BrushingWindowScaled"] == "%R2016"
        assert vmap["DiagnosticCode"] == "%R2017"
        assert vmap["ParallelCoordinatesActive"] == "%M469"
        assert vmap["MultivariateOutlierAlarm"] == "%M470"

    def test_verify_parallel_coordinates_canvas_pure_st_helper(self) -> None:
        """Helper function verify_parallel_coordinates_canvas_pure_st returns True."""
        assert verify_parallel_coordinates_canvas_pure_st() is True


# ============================================================================
# 13. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Validate aggressive fail-closed rejection of ladder logic constructs."""

    def test_reject_ladder_open_contact(self) -> None:
        """Reject open contact ---[ ]---."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR x : BOOL; END_VAR ---[ ]--- END_PROGRAM")

    def test_reject_ladder_closed_contact(self) -> None:
        """Reject closed contact ---[/]---."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR x : BOOL; END_VAR ---[/]--- END_PROGRAM")

    def test_reject_ladder_output_coil(self) -> None:
        """Reject output coil ---( )---."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR x : BOOL; END_VAR ---( )--- END_PROGRAM")

    def test_reject_ladder_set_coil(self) -> None:
        """Reject set coil ---(S)---."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR x : BOOL; END_VAR ---(S)--- END_PROGRAM")

    def test_reject_ladder_reset_coil(self) -> None:
        """Reject reset coil ---(R)---."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR x : BOOL; END_VAR ---(R)--- END_PROGRAM")

    def test_reject_ladder_latch_coil(self) -> None:
        """Reject latch coil ---(L)---."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR x : BOOL; END_VAR ---(L)--- END_PROGRAM")

    def test_reject_ladder_unlatch_coil(self) -> None:
        """Reject unlatch coil ---(U)---."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR x : BOOL; END_VAR ---(U)--- END_PROGRAM")

    def test_reject_ladder_rung_keyword(self) -> None:
        """Reject RUNG delimiter."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("RUNG 1: XIC %M469 OTE %M470")

    def test_reject_ladder_end_rung_keyword(self) -> None:
        """Reject END_RUNG delimiter."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("END_RUNG")

    def test_reject_ladder_network_keyword(self) -> None:
        """Reject NETWORK delimiter."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("NETWORK 10: LD %R2010")

    def test_reject_ladder_end_network_keyword(self) -> None:
        """Reject END_NETWORK delimiter."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("END_NETWORK")

    def test_reject_ladder_mnemonic_xic(self) -> None:
        """Reject XIC mnemonic."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("XIC StartButton")

    def test_reject_ladder_mnemonic_xio(self) -> None:
        """Reject XIO mnemonic."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("XIO StopButton")

    def test_reject_ladder_mnemonic_ote(self) -> None:
        """Reject OTE mnemonic."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("OTE OutlierCoil")

    def test_reject_ladder_mnemonic_otl(self) -> None:
        """Reject OTL mnemonic."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("OTL AlarmLatch")

    def test_reject_ladder_mnemonic_otu(self) -> None:
        """Reject OTU mnemonic."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("OTU AlarmUnlatch")

    def test_reject_ladder_mixed_injection(self) -> None:
        """Reject ladder snippet embedded within otherwise valid Structured Text."""
        st_with_ladder = (
            "PROGRAM Mixed\n"
            "VAR x : INT; END_VAR\n"
            "x := 10;\n"
            "---[ ]---\n"
            "END_PROGRAM"
        )
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(st_with_ladder)


# ============================================================================
# 14. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface compliance, scan cycles, and 100-cycle soak stability."""

    def test_ilogic_unit_interface_properties(self) -> None:
        """Verify name, priority, is_enabled, bounds properties."""
        canvas = create_canonical_parallel_coordinates_canvas()
        assert canvas.name == "ParallelCoordinatesCanvasSync"
        assert canvas.priority == 95
        assert canvas.is_enabled is True
        assert isinstance(canvas.bounds, Rect)
        assert canvas.bounds.width == DEFAULT_CANVAS_WIDTH

    def test_scan_step_cycle(self) -> None:
        """scan_step executes a discrete scan cycle and synchronizes registers."""
        canvas = create_canonical_parallel_coordinates_canvas()
        canvas.scan_step(dt=0.01)
        assert canvas.metrics.axes_count == 6
        assert canvas.metrics.active_profiles_count == 8

    def test_step_alias_method(self) -> None:
        """step executes scan_step."""
        canvas = create_canonical_parallel_coordinates_canvas()
        canvas.step(dt=0.01)
        assert canvas.metrics.axes_count == 6

    def test_execute_with_scan_context(self) -> None:
        """execute executes under Horner ScanContext."""
        canvas = create_canonical_parallel_coordinates_canvas()
        ctx = ScanContext(cycle=1, dt_ms=10.0)
        canvas.execute(ctx)
        assert canvas.metrics.axes_count == 6

    def test_reset_method(self) -> None:
        """reset calls reset_nominal."""
        canvas = create_canonical_parallel_coordinates_canvas()
        canvas.trigger_insufficient_axes()
        assert canvas.diagnostic_code != 0x0000

        canvas.reset()
        assert canvas.diagnostic_code == 0x0000
        assert canvas.canvas_active is True

    def test_soak_100_cycles_stability_and_no_drift(self) -> None:
        """100 scan cycles run without memory drift, NaN, or deviation."""
        canvas = create_canonical_parallel_coordinates_canvas()
        for i in range(100):
            canvas.scan_step(dt=0.01)

        assert canvas.metrics.axes_count == 6
        assert canvas.metrics.active_profiles_count == 8
        assert canvas.metrics.mean_correlation_index_scaled == 7850
        assert canvas.metrics.outlier_profiles_count == 0
        assert canvas.diagnostic_code == 0x0000
        assert canvas.canvas_active is True


# ============================================================================
# 15. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate deterministic 9-stage verification runner and strict 4-state contract."""

    def test_runner_returns_dict_with_success_status(self) -> None:
        """Runner must return dictionary with status=='success'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"
            report = run_parallel_coordinates_canvas_verification(
                output_path=str(ev_path),
                sample_svg_path=str(svg_path),
                work_package="W240",
            )
            assert isinstance(report, dict)
            assert report["status"] == "success"
            assert report["error_code"] is None
            assert report["data"]["checks_passed"] == 9
            assert report["data"]["total_checks"] == 9
            assert ev_path.exists()
            assert svg_path.exists()

    def test_runner_evidence_file_json_structure(self) -> None:
        """Evidence file must contain valid JSON strictly adhering to schema."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"
            run_parallel_coordinates_canvas_verification(
                output_path=str(ev_path),
                sample_svg_path=str(svg_path),
            )
            with open(ev_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            assert data["status"] in ("success", "failed", "blocked", "inconclusive")
            assert "data" in data
            assert len(data["data"]["tests"]) == 9
            for t in data["data"]["tests"]:
                assert t["passed"] is True
                assert "stage" in t
                assert "check" in t
                assert "timing_ms" in t

    def test_runner_all_9_stages_individual_checks(self) -> None:
        """Verify each of the 9 stages has explicit name and details."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            report = run_parallel_coordinates_canvas_verification(output_path=str(ev_path))
            stages = report["data"]["tests"]
            assert len(stages) == 9
            stage_names = [s["check"] for s in stages]
            assert "Parallel_Coordinates_Geometry_And_Viewport_Parameter_Verification" in stage_names
            assert "Pure_IEC_61131_3_Structured_Text_POU_Validation" in stage_names
            assert "Anti_Ladder_Security_Guard_Interception" in stage_names
            assert "Multidimensional_Spline_Interpolation_And_Trajectory_Bounds" in stage_names
            assert "Standalone_W3C_SVG_Vector_Canvas_Generation" in stage_names
            assert "Multivariate_Outlier_Alarm_Injection" in stage_names
            assert "Diagnostic_Fault_Handling" in stage_names
            assert "Horner_OCS_Register_Table_Synchronization" in stage_names
            assert "Simulation_Soak_100_Cycle_And_Memory_Boundedness" in stage_names

    def test_runner_metrics_payload_conformance(self) -> None:
        """Verify report data metrics dictionary keys and values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            report = run_parallel_coordinates_canvas_verification(output_path=str(ev_path))
            metrics = report["data"]["metrics"]
            assert metrics["parallel_axes_count"] == 6
            assert metrics["active_profiles_count"] == 8
            assert metrics["outlier_profiles_count"] == 0
            assert metrics["selected_profile_index"] == 0
            assert metrics["mean_correlation_index_scaled"] == 7850
            assert metrics["diagnostic_code"] == "0x0000"
            assert metrics["wcag_badge_contrast"] >= 18.0
            assert metrics["wcag_text_contrast"] >= 7.0


# ============================================================================
# 16. TestCanvasEdgeCasesAndAdvancedCoverage
# ============================================================================

class TestCanvasEdgeCasesAndAdvancedCoverage:
    """Extra boundary tests for multi-dimensional axes, profiles, and SVG generator."""

    def test_axis_custom_tag_override(self) -> None:
        """Supplied tag should not be overwritten by __post_init__."""
        ax = ParallelDimensionAxis(0, "Pressure", "bar", 0.0, 10.0, 5.0, 1.0, tag="CUSTOM_P_TAG")
        assert ax.tag == "CUSTOM_P_TAG"

    def test_axis_denormalize_beyond_unit_interval(self) -> None:
        """denormalize works smoothly for values outside [0, 1]."""
        ax = ParallelDimensionAxis(0, "Temp", "°C", 100.0, 200.0, 150.0, 10.0)
        assert math.isclose(ax.denormalize(-0.5), 50.0, rel_tol=1e-6)
        assert math.isclose(ax.denormalize(1.5), 250.0, rel_tol=1e-6)

    def test_profile_get_point_beyond_values_fallback(self) -> None:
        """Requesting axis index beyond profile values falls back to axis nominal reference."""
        ax = ParallelDimensionAxis(5, "Extra", "units", 0.0, 100.0, 50.0, 5.0, x_pos=500.0, y_top=100.0, y_bottom=600.0)
        prof = TelemetryProfile(0, "Short", values=[10.0, 20.0])  # only 2 values
        px, py = prof.get_point(5, ax)
        assert px == 500.0
        assert math.isclose(py, 350.0, rel_tol=1e-6)  # 50.0 normalized is 0.5 -> y = 600 - 0.5*500 = 350

    def test_multiple_outlier_profiles_accumulation(self) -> None:
        """Injecting outliers into multiple profiles increments count and keeps alarm active."""
        canvas = create_canonical_parallel_coordinates_canvas()
        canvas.trigger_outlier(profile_index=0, axis_index=5, outlier_value=9.5)
        canvas.trigger_outlier(profile_index=1, axis_index=5, outlier_value=9.8)

        assert canvas.metrics.outlier_profiles_count == 2
        assert canvas.reg_table.read_word(REG_OUTLIER_PROFILES_COUNT) == 2
        assert canvas.reg_table.read_bit(COIL_MULTIVARIATE_OUTLIER_ALARM) is True

    def test_outlier_injection_on_pressure_axis(self) -> None:
        """Injecting outlier on axis 1 (Operating Pressure: 0.8..2.0 bar, ref 1.20, sigma 0.05)."""
        canvas = create_canonical_parallel_coordinates_canvas()
        # 1.50 bar -> z = (1.50 - 1.20) / 0.05 = 6.0 sigma (Outlier)
        canvas.trigger_outlier(profile_index=2, axis_index=1, outlier_value=1.50)
        assert canvas.metrics.outlier_profiles_count >= 1
        assert canvas.profiles[2].is_outlier is True
        assert canvas.profiles[2].category == ProfileCategory.OUTLIER

    def test_svg_brushing_rect_rendered_when_configured(self) -> None:
        """Brushing box overlay is rendered in SVG with BRUSH label."""
        canvas = create_canonical_parallel_coordinates_canvas()
        canvas.set_brushing(axis_index=1, window_scaled=120)
        svg_xml = canvas.render_svg()
        assert "BRUSH [120]" in svg_xml
        assert "stroke-dasharray=\"3,3\"" in svg_xml

    def test_svg_header_title_present(self) -> None:
        """Header title text must be present in SVG."""
        canvas = create_canonical_parallel_coordinates_canvas()
        svg_xml = canvas.render_svg()
        assert "PARALLEL COORDINATES" in svg_xml

    def test_rect_area_with_zero_or_negative_dimensions(self) -> None:
        """Rect area returns 0.0 for zero or negative dimensions."""
        assert Rect(0.0, 0.0, -10.0, 50.0).area == 0.0
        assert Rect(0.0, 0.0, 50.0, 0.0).area == 0.0

    def test_layout_parallel_axes_custom_margins(self) -> None:
        """Custom margins shift start and end axis X positions."""
        axes = create_canonical_parallel_axes()
        bounds = Rect(0.0, 0.0, 1000.0, 500.0)
        layout_parallel_axes(axes, bounds, margin_left=100.0, margin_right=100.0)
        assert math.isclose(axes[0].x_pos, 100.0, rel_tol=1e-6)
        assert math.isclose(axes[-1].x_pos, 900.0, rel_tol=1e-6)

    def test_correlation_zero_variance_handling(self) -> None:
        """calculate_mean_correlation_index handles constant series without crash."""
        axes = create_canonical_parallel_axes()
        # Constant profile values
        profs = [
            TelemetryProfile(i, f"P{i}", [350.0, 1.20, 98.5, 95.2, 0.45, 1.50])
            for i in range(5)
        ]
        corr = calculate_mean_correlation_index(profs, axes)
        assert 0.0 <= corr <= 1.0

    def test_sync_to_registers_custom_table_argument(self) -> None:
        """sync_to_registers accepts explicit external RegisterTable."""
        canvas = create_canonical_parallel_coordinates_canvas()
        external_table = RegisterTable()
        canvas.sync_to_registers(reg_table=external_table, privilege=PrivilegeMode.SYSTEM)
        assert external_table.read_word(REG_PARALLEL_AXES_COUNT) == 6
        assert external_table.read_bit(COIL_PARALLEL_COORDINATES_ACTIVE) is True
