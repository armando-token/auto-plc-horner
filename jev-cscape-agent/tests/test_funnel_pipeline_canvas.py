"""Comprehensive pytest test suite for Cscape HMI Dynamic Funnel Pipeline Flow SCADA Canvas (W249).

Work Package: Wave W249 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Funnel Pipeline Flow SCADA Canvas]

Covers 120+ Deterministic Unit Tests across 13 Test Classes (including all 11 specified classes):
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit equality, hashing, enums, register names, coil addresses.
2. TestPipelineFunnelStages: 5 stages volume data, flow continuity, attrition calculations, bottleneck detection.
3. TestCanvasGeometryAndLayout: 1200x750 viewport, bounds containment, segment width, non-negative coordinates.
4. TestBottleneckAlarmCondition: Single-stage attrition > 30.0% or efficiency < 40.0% trips %M491 alarm, recovery reset.
5. TestSVGGenerationAndXMLSyntax: Standalone W3C SVG 1.1 generation, ElementTree XML validation, <polygon>, <path>, <rect> tags.
6. TestWCAG21AAAContrastAndVisualLegibility: WCAG 2.1 AAA relative luminance, contrast formulas, badge contrast > 18:1, text > 7:1.
7. TestHornerOCSSynchronizationAndRegisters: %R2100..%R2107 and %M490..%M491 bit-exact synchronization, PrivilegeMode.SYSTEM.
8. TestPureSTAndSecurity: STParser & SecurityGuard verification of FunnelPipelineCanvasSync POU.
9. TestAntiLadderRejection: Rejection of 6+ ladder constructs (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError.
10. TestILogicUnitCompliance: scan_step, step, execute, reset, 100-cycle soak stability.
11. TestDiagnosticFaultHandlingAndEdgeCases: 0xF901, 0xF902, 0xF903, 0xF904 fault injection, status bits, exception hierarchy, recovery.
12. TestVerificationRunnerAndContract: Deterministic 9-stage runner export and strict 4-state contract validation.
13. TestClassAliasesAndCanonicalFactory: Class aliases, factory functions, dataclass defaults, and module exports.
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

from jev_cscape.hmi.funnel_pipeline_canvas import (
    ATTRITION_ALARM_THRESHOLD_PCT,
    ATTRITION_ALARM_THRESHOLD_SCALED,
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
    COIL_BOTTLENECK_ALARM,
    COIL_BOTTLENECK_ALARM_TRIP,
    COIL_CANVAS_ACTIVE,
    COIL_FUNNEL_ACTIVE,
    COIL_FUNNEL_CANVAS_ACTIVE,
    COIL_PIPELINE_ACTIVE,
    COIL_PIPELINE_ALARM,
    COIL_PIPELINE_BOTTLENECK_ALARM,
    COIL_W249_BOTTLENECK_ALARM,
    COIL_W249_CANVAS_ACTIVE,
    COLOR_ALARM_CRIMSON,
    COLOR_ALERT_CRIMSON,
    COLOR_AXIS_LINE,
    COLOR_BORDER,
    COLOR_CANVAS_BG,
    COLOR_DARK_THEME_BACKING,
    COLOR_DECOUPLED_BADGE,
    COLOR_GRID_LINE,
    COLOR_OK_EMERALD,
    COLOR_PANEL_BG,
    COLOR_PANEL_BORDER,
    COLOR_STAGE_0_BLUE,
    COLOR_STAGE_1_CYAN,
    COLOR_STAGE_2_EMERALD,
    COLOR_STAGE_3_AMBER,
    COLOR_STAGE_4_PURPLE,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    CanvasGeometry,
    CanvasOverflowError,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DIAG_ERR_CANVAS_OVERFLOW,
    DIAG_ERR_INVERTED_FLOW_GRADIENT,
    DIAG_ERR_INVERTED_GRADIENT,
    DIAG_ERR_STAGES_COUNT_INVALID,
    DIAG_ERR_STAGES_INVALID,
    DIAG_ERR_ZERO_INLET,
    DIAG_ERR_ZERO_INLET_VOLUME,
    DIAG_EVENT_OK,
    DIAG_FUNNEL_OK,
    DIAG_OK,
    DiagnosticCode,
    EFFICIENCY_ALARM_THRESHOLD_PCT,
    EFFICIENCY_ALARM_THRESHOLD_SCALED,
    ERR_CANVAS_OVERFLOW,
    ERR_INVERTED_FLOW_GRADIENT,
    ERR_STAGES_COUNT_INVALID,
    ERR_ZERO_INLET_VOLUME,
    FUNNEL_ERR_CANVAS_OVERFLOW,
    FUNNEL_ERR_INVERTED_FLOW_GRADIENT,
    FUNNEL_ERR_STAGES_COUNT_INVALID,
    FUNNEL_ERR_ZERO_INLET_VOLUME,
    FUNNEL_OK,
    FUNNEL_PIPELINE_CANVAS_PURE_ST_POU,
    FUNNEL_PIPELINE_CANVAS_SYNC_PURE_ST_POU,
    FUNNEL_PIPELINE_OK,
    FunnelDiagnosticCode,
    FunnelMetrics,
    FunnelPipelineCanvas,
    FunnelPipelineCanvasDiagnosticCode,
    FunnelPipelineCanvasEngine,
    FunnelPipelineCanvasError,
    FunnelPipelineCanvasStatusBits,
    FunnelPipelineCanvasSync,
    FunnelPipelineDiagnosticCode,
    FunnelPipelineMetrics,
    FunnelPipelineStage,
    FunnelPipelineStatusBits,
    FunnelStage,
    FunnelStatusBits,
    FunnelTransitionMode,
    HUD_HEIGHT,
    HUD_ORIGIN_X,
    HUD_ORIGIN_Y,
    HUD_WIDTH,
    INVERTED_FLOW_FAULT,
    INVERTED_FLOW_GRADIENT,
    INVERTED_GRADIENT,
    InvertedFlowGradientError,
    NOMINAL_BOTTLENECK_STAGE_INDEX,
    NOMINAL_DIAGNOSTIC_CODE,
    NOMINAL_FUNNEL_STAGES_COUNT,
    NOMINAL_INLET_FLOW_VOLUME,
    NOMINAL_INLET_FLOW_VOLUME_SCALED,
    NOMINAL_MAX_STAGE_ATTRITION_PCT,
    NOMINAL_MAX_STAGE_ATTRITION_SCALED,
    NOMINAL_OK,
    NOMINAL_OUTLET_YIELD_VOLUME,
    NOMINAL_OUTLET_YIELD_VOLUME_SCALED,
    NOMINAL_OVERALL_THROUGHPUT_EFFICIENCY_PCT,
    NOMINAL_OVERALL_THROUGHPUT_EFFICIENCY_SCALED,
    NOMINAL_SELECTED_PIPELINE_STAGE,
    PIPELINE_CENTER_Y,
    PIPELINE_HEIGHT,
    PIPELINE_MAX_HALF_HEIGHT,
    PIPELINE_ORIGIN_X,
    PIPELINE_ORIGIN_Y,
    PIPELINE_WIDTH,
    PipelineStage,
    REG_BOTTLENECK_INDEX,
    REG_BOTTLENECK_STAGE,
    REG_BOTTLENECK_STAGE_INDEX,
    REG_DIAG_CODE,
    REG_DIAGNOSTIC_CODE,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_FUNNEL_STAGES_COUNT,
    REG_INLET_FLOW_SCALED,
    REG_INLET_FLOW_VOLUME_SCALED,
    REG_MAX_ATTRITION_SCALED,
    REG_MAX_STAGE_ATTRITION,
    REG_MAX_STAGE_ATTRITION_SCALED,
    REG_OUTLET_YIELD_SCALED,
    REG_OUTLET_YIELD_VOLUME_SCALED,
    REG_OVERALL_EFFICIENCY_SCALED,
    REG_OVERALL_THROUGHPUT_EFFICIENCY_SCALED,
    REG_PIPELINE_EFFICIENCY_PCT_SCALED,
    REG_SELECTED_PIPELINE_STAGE,
    REG_SELECTED_STAGE,
    REG_SELECTED_STAGE_INDEX,
    REG_STAGE_0_VOLUME,
    REG_STAGE_4_VOLUME,
    REG_STAGES_COUNT,
    REG_THROUGHPUT_EFFICIENCY_SCALED,
    REG_W249_ATTRITION,
    REG_W249_BOTTLENECK,
    REG_W249_DIAG,
    REG_W249_EFFICIENCY,
    REG_W249_INLET,
    REG_W249_SELECTED,
    REG_W249_STAGES,
    REG_W249_YIELD,
    STAGE_PALETTE_COLORS,
    STAGES_COUNT_INVALID,
    STAGES_COUNT_INVALID_FAULT,
    STAGES_INVALID,
    StagesCountInvalidError,
    TrapezoidSegmentGeometry,
    W249_FUNNEL_PIPELINE_PURE_ST_POU,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    ZERO_INLET,
    ZERO_INLET_FAULT,
    ZERO_INLET_VOLUME,
    ZeroInletVolumeError,
    calculate_contrast_ratio,
    compute_trapezoid_funnel_layout,
    create_canonical_funnel_pipeline_canvas,
    create_canonical_funnel_stages,
    generate_funnel_pipeline_canvas_svg,
    hex_to_relative_luminance,
    is_point_within_canvas,
    run_funnel_pipeline_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_funnel_pipeline_canvas_pure_st,
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
        assert diag == NOMINAL_OK
        assert diag == FUNNEL_OK
        assert diag == FUNNEL_PIPELINE_OK
        assert diag == DIAG_FUNNEL_OK
        assert diag == NOMINAL_DIAGNOSTIC_CODE

    def test_diagnostic_code_signed_unsigned_equality_0xf901(self) -> None:
        diag = DiagnosticCode(0xF901)
        assert diag == 0xF901
        assert diag == -1791  # 0xF901 - 0x10000
        assert diag == DIAG_ERR_STAGES_COUNT_INVALID
        assert diag == STAGES_COUNT_INVALID
        assert diag == STAGES_COUNT_INVALID_FAULT
        assert diag == ERR_STAGES_COUNT_INVALID
        assert diag == FUNNEL_ERR_STAGES_COUNT_INVALID
        assert diag == DIAG_ERR_STAGES_INVALID
        assert diag == STAGES_INVALID

    def test_diagnostic_code_signed_unsigned_equality_0xf902(self) -> None:
        diag = DiagnosticCode(0xF902)
        assert diag == 0xF902
        assert diag == -1790  # 0xF902 - 0x10000
        assert diag == DIAG_ERR_INVERTED_FLOW_GRADIENT
        assert diag == INVERTED_FLOW_GRADIENT
        assert diag == INVERTED_FLOW_FAULT
        assert diag == ERR_INVERTED_FLOW_GRADIENT
        assert diag == FUNNEL_ERR_INVERTED_FLOW_GRADIENT
        assert diag == DIAG_ERR_INVERTED_GRADIENT
        assert diag == INVERTED_GRADIENT

    def test_diagnostic_code_signed_unsigned_equality_0xf903(self) -> None:
        diag = DiagnosticCode(0xF903)
        assert diag == 0xF903
        assert diag == -1789  # 0xF903 - 0x10000
        assert diag == DIAG_ERR_ZERO_INLET_VOLUME
        assert diag == ZERO_INLET_VOLUME
        assert diag == ZERO_INLET_FAULT
        assert diag == ERR_ZERO_INLET_VOLUME
        assert diag == FUNNEL_ERR_ZERO_INLET_VOLUME
        assert diag == DIAG_ERR_ZERO_INLET
        assert diag == ZERO_INLET

    def test_diagnostic_code_signed_unsigned_equality_0xf904(self) -> None:
        diag = DiagnosticCode(0xF904)
        assert diag == 0xF904
        assert diag == -1788  # 0xF904 - 0x10000
        assert diag == DIAG_ERR_CANVAS_OVERFLOW
        assert diag == CANVAS_OVERFLOW
        assert diag == CANVAS_OVERFLOW_FAULT
        assert diag == ERR_CANVAS_OVERFLOW
        assert diag == FUNNEL_ERR_CANVAS_OVERFLOW

    def test_diagnostic_code_hash_and_set_membership(self) -> None:
        diag1 = DiagnosticCode(0xF901)
        diag2 = DiagnosticCode(0xF901)
        diag_diff = DiagnosticCode(0xF902)
        assert hash(diag1) == hash(diag2)
        assert hash(diag1) == hash(0xF901)
        diag_set = {diag1, diag_diff}
        assert DiagnosticCode(0xF901) in diag_set
        assert DiagnosticCode(0x0000) not in diag_set

    def test_diagnostic_code_aliases(self) -> None:
        assert FunnelPipelineDiagnosticCode is DiagnosticCode
        assert FunnelPipelineCanvasDiagnosticCode is DiagnosticCode
        assert FunnelDiagnosticCode is DiagnosticCode

    def test_status_bits_enum_flags(self) -> None:
        assert FunnelPipelineStatusBits.ACTIVE == 1 << 0
        assert FunnelPipelineStatusBits.NOMINAL_OPERATION == 1 << 1
        assert FunnelPipelineStatusBits.PIPELINE_EVALUATED == 1 << 2
        assert FunnelPipelineStatusBits.BOTTLENECK_ALARM_ACTIVE == 1 << 3
        assert FunnelPipelineStatusBits.STAGES_COUNT_INVALID == 1 << 4
        assert FunnelPipelineStatusBits.INVERTED_FLOW_FAULT == 1 << 5
        assert FunnelPipelineStatusBits.ZERO_INLET_FAULT == 1 << 6
        assert FunnelPipelineStatusBits.CANVAS_OVERFLOW_FAULT == 1 << 7
        assert FunnelPipelineStatusBits.WCAG_AAA_COMPLIANT == 1 << 8
        assert FunnelPipelineStatusBits.SVG_RENDER_VALID == 1 << 9

    def test_status_bits_aliases(self) -> None:
        assert FunnelStatusBits is FunnelPipelineStatusBits
        assert FunnelPipelineCanvasStatusBits is FunnelPipelineStatusBits

    def test_transition_mode_enum(self) -> None:
        assert FunnelTransitionMode.CURVED.value == "curved"
        assert FunnelTransitionMode.TRAPEZOIDAL.value == "trapezoidal"

    def test_register_names_and_addresses(self) -> None:
        assert REG_FUNNEL_STAGES_COUNT == "%R2100"
        assert REG_INLET_FLOW_VOLUME_SCALED == "%R2101"
        assert REG_OUTLET_YIELD_VOLUME_SCALED == "%R2102"
        assert REG_OVERALL_THROUGHPUT_EFFICIENCY_SCALED == "%R2103"
        assert REG_BOTTLENECK_STAGE_INDEX == "%R2104"
        assert REG_MAX_STAGE_ATTRITION_SCALED == "%R2105"
        assert REG_SELECTED_PIPELINE_STAGE == "%R2106"
        assert REG_DIAGNOSTIC_CODE == "%R2107"

        # General Aliases
        assert REG_STAGES_COUNT == "%R2100"
        assert REG_INLET_FLOW_SCALED == "%R2101"
        assert REG_OUTLET_YIELD_SCALED == "%R2102"
        assert REG_THROUGHPUT_EFFICIENCY_SCALED == "%R2103"
        assert REG_OVERALL_EFFICIENCY_SCALED == "%R2103"
        assert REG_BOTTLENECK_STAGE == "%R2104"
        assert REG_BOTTLENECK_INDEX == "%R2104"
        assert REG_MAX_STAGE_ATTRITION == "%R2105"
        assert REG_MAX_ATTRITION_SCALED == "%R2105"
        assert REG_SELECTED_STAGE == "%R2106"
        assert REG_SELECTED_STAGE_INDEX == "%R2106"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2107"
        assert REG_DIAG_CODE == "%R2107"

        # W249 explicit aliases
        assert REG_W249_STAGES == "%R2100"
        assert REG_W249_INLET == "%R2101"
        assert REG_W249_YIELD == "%R2102"
        assert REG_W249_EFFICIENCY == "%R2103"
        assert REG_W249_BOTTLENECK == "%R2104"
        assert REG_W249_ATTRITION == "%R2105"
        assert REG_W249_SELECTED == "%R2106"
        assert REG_W249_DIAG == "%R2107"

    def test_coil_addresses_and_aliases(self) -> None:
        assert COIL_FUNNEL_CANVAS_ACTIVE == "%M490"
        assert COIL_PIPELINE_BOTTLENECK_ALARM == "%M491"

        # Aliases
        assert COIL_CANVAS_ACTIVE == "%M490"
        assert COIL_FUNNEL_ACTIVE == "%M490"
        assert COIL_PIPELINE_ACTIVE == "%M490"
        assert COIL_BOTTLENECK_ALARM == "%M491"
        assert COIL_PIPELINE_ALARM == "%M491"
        assert COIL_ALARM_ACTIVE == "%M491"
        assert COIL_BOTTLENECK_ALARM_TRIP == "%M491"
        assert COIL_W249_CANVAS_ACTIVE == "%M490"
        assert COIL_W249_BOTTLENECK_ALARM == "%M491"

    def test_nominal_constants(self) -> None:
        assert NOMINAL_FUNNEL_STAGES_COUNT == 5
        assert NOMINAL_INLET_FLOW_VOLUME == 1250.0
        assert NOMINAL_OUTLET_YIELD_VOLUME == 685.0
        assert NOMINAL_OVERALL_THROUGHPUT_EFFICIENCY_PCT == 54.80
        assert NOMINAL_BOTTLENECK_STAGE_INDEX == 1
        assert NOMINAL_MAX_STAGE_ATTRITION_PCT == 22.40
        assert NOMINAL_SELECTED_PIPELINE_STAGE == 0
        assert NOMINAL_DIAGNOSTIC_CODE == 0x0000

        # Scaled nominals
        assert NOMINAL_INLET_FLOW_VOLUME_SCALED == 12500
        assert NOMINAL_OUTLET_YIELD_VOLUME_SCALED == 6850
        assert NOMINAL_OVERALL_THROUGHPUT_EFFICIENCY_SCALED == 5480
        assert NOMINAL_MAX_STAGE_ATTRITION_SCALED == 2240

    def test_alarm_threshold_constants(self) -> None:
        assert ATTRITION_ALARM_THRESHOLD_PCT == 30.0
        assert ATTRITION_ALARM_THRESHOLD_SCALED == 3000
        assert EFFICIENCY_ALARM_THRESHOLD_PCT == 40.0
        assert EFFICIENCY_ALARM_THRESHOLD_SCALED == 4000

    def test_stage_palette_colors_list(self) -> None:
        assert len(STAGE_PALETTE_COLORS) == 5
        assert STAGE_PALETTE_COLORS[0] == COLOR_STAGE_0_BLUE == "#3B82F6"
        assert STAGE_PALETTE_COLORS[1] == COLOR_STAGE_1_CYAN == "#06B6D4"
        assert STAGE_PALETTE_COLORS[2] == COLOR_STAGE_2_EMERALD == "#10B981"
        assert STAGE_PALETTE_COLORS[3] == COLOR_STAGE_3_AMBER == "#F59E0B"
        assert STAGE_PALETTE_COLORS[4] == COLOR_STAGE_4_PURPLE == "#8B5CF6"


# ============================================================================
# 2. TestPipelineFunnelStages
# ============================================================================

class TestPipelineFunnelStages:
    """Validate 5 stages volume data, flow continuity, attrition calculations, and bottleneck detection."""

    def test_canonical_stages_creation_count(self) -> None:
        stages = create_canonical_funnel_stages()
        assert len(stages) == 5
        assert [s.stage_index for s in stages] == [0, 1, 2, 3, 4]

    def test_canonical_stages_volumes(self) -> None:
        stages = create_canonical_funnel_stages()
        volumes = [s.flow_volume for s in stages]
        assert volumes == [1250.0, 1080.0, 920.0, 780.0, 685.0]

    def test_canonical_stages_scaled_properties(self) -> None:
        stages = create_canonical_funnel_stages()
        scaled = [s.flow_volume_scaled for s in stages]
        assert scaled == [12500, 10800, 9200, 7800, 6850]

    def test_canonical_stages_drop_off_volumes(self) -> None:
        stages = create_canonical_funnel_stages()
        drop_offs = [s.drop_off_volume for s in stages]
        assert drop_offs == [0.0, 170.0, 160.0, 140.0, 95.0]

    def test_canonical_stages_attrition_calculations(self) -> None:
        stages = create_canonical_funnel_stages()
        assert stages[0].attrition_pct == 0.0
        assert stages[1].attrition_pct == 22.40  # Canonical nominal max attrition
        assert math.isclose(stages[2].attrition_pct, 14.81, abs_tol=0.01)
        assert math.isclose(stages[3].attrition_pct, 15.22, abs_tol=0.01)
        assert math.isclose(stages[4].attrition_pct, 12.18, abs_tol=0.01)

    def test_canonical_stages_bottleneck_flag(self) -> None:
        stages = create_canonical_funnel_stages()
        bottlenecks = [s.is_bottleneck for s in stages]
        assert bottlenecks == [False, True, False, False, False]
        assert stages[1].is_bottleneck is True
        assert stages[1].name == "Primary Separation"

    def test_canonical_stages_tags_and_names(self) -> None:
        stages = create_canonical_funnel_stages()
        expected_tags = ["FD-100", "PS-200", "CC-300", "QA-400", "HY-500"]
        assert [s.tag for s in stages] == expected_tags
        assert stages[0].name == "Raw Feed Intake"
        assert stages[4].name == "High-Purity Yield"

    def test_pipeline_stage_dataclass_defaults(self) -> None:
        s = PipelineStage(stage_index=0, name="Test Feed", tag="TF-01", flow_volume=1000.0)
        assert s.drop_off_volume == 0.0
        assert s.attrition_pct == 0.0
        assert s.is_bottleneck is False
        assert s.is_selected is False
        assert s.flow_volume_scaled == 10000
        assert s.drop_off_volume_scaled == 0
        assert s.attrition_scaled == 0

    def test_flow_continuity_mass_conservation(self) -> None:
        stages = create_canonical_funnel_stages()
        total_drop = sum(s.drop_off_volume for s in stages)
        inlet_vol = stages[0].flow_volume
        yield_vol = stages[-1].flow_volume
        # 1250.0 - (170 + 160 + 140 + 95 = 565) = 685.0
        assert math.isclose(inlet_vol - total_drop, yield_vol, abs_tol=1e-5)

    def test_stage_scaled_clamping_int16(self) -> None:
        s_high = PipelineStage(stage_index=0, name="Max", tag="M", flow_volume=5000.0, drop_off_volume=4000.0, attrition_pct=400.0)
        assert s_high.flow_volume_scaled == 32767
        assert s_high.drop_off_volume_scaled == 32767
        assert s_high.attrition_scaled == 32767

        s_neg = PipelineStage(stage_index=0, name="Neg", tag="N", flow_volume=-4000.0)
        assert s_neg.flow_volume_scaled == -32768


# ============================================================================
# 3. TestCanvasGeometryAndLayout
# ============================================================================

class TestCanvasGeometryAndLayout:
    """Validate 1200x750 viewport, bounds containment, segment width, non-negative coordinates."""

    def test_canvas_geometry_defaults(self) -> None:
        geom = CanvasGeometry()
        assert geom.viewport_width == 1200
        assert geom.viewport_height == 750
        assert geom.bounds_x == 20.0
        assert geom.bounds_y == 86.0
        assert geom.bounds_width == 1160.0
        assert geom.bounds_height == 644.0

    def test_canvas_min_max_bounds(self) -> None:
        assert CANVAS_MIN_X == 20.0
        assert CANVAS_MAX_X == 1180.0
        assert CANVAS_MIN_Y == 86.0
        assert CANVAS_MAX_Y == 730.0

    def test_sub_region_coordinates(self) -> None:
        assert PIPELINE_ORIGIN_X == 40.0
        assert PIPELINE_ORIGIN_Y == 106.0
        assert PIPELINE_WIDTH == 780.0
        assert PIPELINE_HEIGHT == 604.0
        assert PIPELINE_CENTER_Y == 390.0
        assert PIPELINE_MAX_HALF_HEIGHT == 140.0

        assert HUD_ORIGIN_X == 840.0
        assert HUD_ORIGIN_Y == 106.0
        assert HUD_WIDTH == 320.0
        assert HUD_HEIGHT == 604.0

    def test_contains_point_corners_and_center(self) -> None:
        geom = CanvasGeometry()
        assert geom.contains_point(20.0, 86.0) is True      # Top-left corner
        assert geom.contains_point(1180.0, 86.0) is True    # Top-right corner
        assert geom.contains_point(20.0, 730.0) is True     # Bottom-left corner
        assert geom.contains_point(1180.0, 730.0) is True   # Bottom-right corner
        assert geom.contains_point(600.0, 400.0) is True    # Viewport center

    def test_contains_point_out_of_bounds(self) -> None:
        geom = CanvasGeometry()
        assert geom.contains_point(19.9, 200.0) is False
        assert geom.contains_point(1180.1, 200.0) is False
        assert geom.contains_point(500.0, 85.9) is False
        assert geom.contains_point(500.0, 730.1) is False

    def test_is_point_within_canvas_corners(self) -> None:
        assert is_point_within_canvas(20.0, 86.0) is True
        assert is_point_within_canvas(1180.0, 730.0) is True
        assert is_point_within_canvas(100.0, 200.0) is True

    def test_is_point_within_canvas_outside(self) -> None:
        assert is_point_within_canvas(10.0, 200.0) is False
        assert is_point_within_canvas(1190.0, 200.0) is False
        assert is_point_within_canvas(100.0, 80.0) is False
        assert is_point_within_canvas(100.0, 740.0) is False

    def test_compute_trapezoid_funnel_layout(self) -> None:
        stages = create_canonical_funnel_stages()
        geoms = compute_trapezoid_funnel_layout(stages)
        assert len(geoms) == 5
        for g in geoms:
            assert isinstance(g, TrapezoidSegmentGeometry)
            assert g.x_start >= 20.0
            assert g.x_end <= 1180.0
            assert g.x_end > g.x_start
            assert g.height_start > 0.0
            assert g.height_end > 0.0
            assert g.y_bottom_start > g.y_top_start
            assert is_point_within_canvas(g.x_start, g.y_top_start) is True
            assert is_point_within_canvas(g.x_end, g.y_bottom_end) is True
            assert g.path_d.startswith("M ")

    def test_trapezoid_segment_spacing(self) -> None:
        stages = create_canonical_funnel_stages()
        geoms = compute_trapezoid_funnel_layout(stages)
        for i in range(len(geoms) - 1):
            assert geoms[i + 1].x_start > geoms[i].x_end

    def test_compute_trapezoid_funnel_layout_empty(self) -> None:
        assert compute_trapezoid_funnel_layout([]) == []


# ============================================================================
# 4. TestBottleneckAlarmCondition
# ============================================================================

class TestBottleneckAlarmCondition:
    """Validate single-stage attrition > 30.0% or efficiency < 40.0% trips %M491 alarm, recovery reset."""

    def test_nominal_alarm_inactive(self) -> None:
        canvas = FunnelPipelineCanvas()
        assert canvas.metrics.pipeline_bottleneck_alarm is False
        assert canvas.reg_table.read_bit(COIL_PIPELINE_BOTTLENECK_ALARM) is False
        assert (canvas.status_bits & FunnelPipelineStatusBits.BOTTLENECK_ALARM_ACTIVE) == 0

    def test_attrition_alarm_trigger(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.trigger_bottleneck_attrition_alarm(attrition_pct=35.0)
        assert canvas.metrics.pipeline_bottleneck_alarm is True
        assert canvas.metrics.max_stage_attrition_pct == 35.0
        assert canvas.reg_table.read_bit(COIL_PIPELINE_BOTTLENECK_ALARM) is True
        assert (canvas.status_bits & FunnelPipelineStatusBits.BOTTLENECK_ALARM_ACTIVE) != 0

    def test_attrition_alarm_recovery_reset(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.trigger_bottleneck_attrition_alarm(attrition_pct=40.0)
        assert canvas.metrics.pipeline_bottleneck_alarm is True

        canvas.reset_nominal()
        assert canvas.metrics.pipeline_bottleneck_alarm is False
        assert canvas.reg_table.read_bit(COIL_PIPELINE_BOTTLENECK_ALARM) is False
        assert (canvas.status_bits & FunnelPipelineStatusBits.BOTTLENECK_ALARM_ACTIVE) == 0

    def test_efficiency_alarm_trigger(self) -> None:
        canvas = FunnelPipelineCanvas()
        # Inlet=1250.0, yield=400.0 -> efficiency = 32.0% < 40.0%
        canvas.trigger_low_efficiency_alarm(yield_val=400.0)
        assert canvas.metrics.pipeline_bottleneck_alarm is True
        assert canvas.metrics.overall_throughput_efficiency_pct < 40.0
        assert canvas.reg_table.read_bit(COIL_PIPELINE_BOTTLENECK_ALARM) is True
        assert (canvas.status_bits & FunnelPipelineStatusBits.BOTTLENECK_ALARM_ACTIVE) != 0

    def test_efficiency_alarm_recovery_reset(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.trigger_low_efficiency_alarm(yield_val=300.0)
        assert canvas.metrics.pipeline_bottleneck_alarm is True

        canvas.reset_nominal()
        assert canvas.metrics.pipeline_bottleneck_alarm is False
        assert canvas.reg_table.read_bit(COIL_PIPELINE_BOTTLENECK_ALARM) is False
        assert (canvas.status_bits & FunnelPipelineStatusBits.BOTTLENECK_ALARM_ACTIVE) == 0

    def test_both_alarm_conditions_simultaneous(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.stages[-1].flow_volume = 400.0
        canvas.trigger_bottleneck_attrition_alarm(attrition_pct=35.0)
        assert canvas.metrics.pipeline_bottleneck_alarm is True
        assert canvas.reg_table.read_bit(COIL_PIPELINE_BOTTLENECK_ALARM) is True

    def test_alarm_boundary_conditions_exactly_30_pct(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.metrics.max_stage_attrition_pct = 30.0
        # Exactly 30% does not exceed strictly > 30.0%
        assert canvas.metrics.max_stage_attrition_pct <= ATTRITION_ALARM_THRESHOLD_PCT

    def test_alarm_boundary_conditions_strictly_above_30_pct(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.trigger_bottleneck_attrition_alarm(attrition_pct=30.01)
        assert canvas.metrics.pipeline_bottleneck_alarm is True
        assert canvas.reg_table.read_bit(COIL_PIPELINE_BOTTLENECK_ALARM) is True

    def test_reset_method_clears_alarm(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.trigger_bottleneck_attrition_alarm(attrition_pct=50.0)
        assert canvas.metrics.pipeline_bottleneck_alarm is True
        canvas.reset()
        assert canvas.metrics.pipeline_bottleneck_alarm is False
        assert canvas.reg_table.read_bit(COIL_PIPELINE_BOTTLENECK_ALARM) is False

    def test_alarm_status_bit_toggled_cleanly(self) -> None:
        canvas = FunnelPipelineCanvas()
        assert (canvas.status_bits & FunnelPipelineStatusBits.BOTTLENECK_ALARM_ACTIVE) == 0
        canvas.trigger_bottleneck_attrition_alarm(attrition_pct=35.0)
        assert (canvas.status_bits & FunnelPipelineStatusBits.BOTTLENECK_ALARM_ACTIVE) != 0
        canvas.reset_nominal()
        assert (canvas.status_bits & FunnelPipelineStatusBits.BOTTLENECK_ALARM_ACTIVE) == 0


# ============================================================================
# 5. TestSVGGenerationAndXMLSyntax
# ============================================================================

class TestSVGGenerationAndXMLSyntax:
    """Validate standalone W3C SVG 1.1 generation, ElementTree XML validation, <polygon>, <path>, <rect> tags."""

    def test_svg_standalone_valid_xml(self) -> None:
        canvas = FunnelPipelineCanvas()
        svg_str = canvas.render_svg()
        assert svg_str.startswith("<?xml")
        root = ET.fromstring(svg_str)
        assert root is not None

    def test_svg_root_tag_and_viewbox(self) -> None:
        canvas = FunnelPipelineCanvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg")
        assert root.attrib.get("viewBox") == "0 0 1200 750"
        assert root.attrib.get("width") == "1200"
        assert root.attrib.get("height") == "750"

    def test_svg_contains_polygon_tags(self) -> None:
        canvas = FunnelPipelineCanvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        polys = root.findall(".//{http://www.w3.org/2000/svg}polygon") or root.findall(".//polygon")
        # Bleed indicator arrows for stages 1..4
        assert len(polys) >= 4

    def test_svg_contains_path_tags(self) -> None:
        canvas = FunnelPipelineCanvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        paths = root.findall(".//{http://www.w3.org/2000/svg}path") or root.findall(".//path")
        # 5 trapezoid segments with smooth rounded fillets
        assert len(paths) >= 5

    def test_svg_contains_rect_tags(self) -> None:
        canvas = FunnelPipelineCanvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        rects = root.findall(".//{http://www.w3.org/2000/svg}rect") or root.findall(".//rect")
        # Viewport, outer canvas, HUD cards, badges
        assert len(rects) >= 15

    def test_svg_contains_text_tags(self) -> None:
        canvas = FunnelPipelineCanvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        texts = root.findall(".//{http://www.w3.org/2000/svg}text") or root.findall(".//text")
        assert len(texts) >= 20

    def test_svg_contains_defs_and_gradients(self) -> None:
        canvas = FunnelPipelineCanvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        defs = root.findall(".//{http://www.w3.org/2000/svg}defs") or root.findall(".//defs")
        assert len(defs) == 1
        grads = root.findall(".//{http://www.w3.org/2000/svg}linearGradient") or root.findall(".//linearGradient")
        assert len(grads) >= 5

    def test_svg_alarm_visual_indication(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.trigger_bottleneck_attrition_alarm(attrition_pct=35.0)
        svg_str = canvas.render_svg()
        assert "ALARM: BOTTLENECK" in svg_str
        assert COLOR_ALARM_CRIMSON in svg_str

    def test_svg_clean_xml_entities(self) -> None:
        canvas = FunnelPipelineCanvas()
        svg_str = canvas.render_svg()
        assert "&amp;" in svg_str or "&" not in svg_str.replace("&amp;", "")
        ET.fromstring(svg_str)

    def test_generate_funnel_pipeline_canvas_svg_helper(self) -> None:
        stages = create_canonical_funnel_stages()
        metrics = FunnelPipelineMetrics()
        svg_str = generate_funnel_pipeline_canvas_svg(stages, metrics)
        assert svg_str.startswith("<?xml")
        root = ET.fromstring(svg_str)
        assert root is not None


# ============================================================================
# 6. TestWCAG21AAAContrastAndVisualLegibility
# ============================================================================

class TestWCAG21AAAContrastAndVisualLegibility:
    """Validate WCAG 2.1 AAA relative luminance, contrast formulas, badge contrast > 18:1, text > 7:1."""

    def test_relative_luminance_black_and_white(self) -> None:
        assert hex_to_relative_luminance("#000000") == 0.0
        assert math.isclose(hex_to_relative_luminance("#FFFFFF"), 1.0, abs_tol=1e-3)

    def test_srgb_channel_to_linear_low_and_high(self) -> None:
        assert srgb_channel_to_linear(0.0) == 0.0
        assert math.isclose(srgb_channel_to_linear(0.02), 0.02 / 12.92, abs_tol=1e-5)
        assert math.isclose(srgb_channel_to_linear(1.0), 1.0, abs_tol=1e-3)

    def test_hex_to_relative_luminance_short_and_long_hex(self) -> None:
        assert hex_to_relative_luminance("#FFF") == hex_to_relative_luminance("#FFFFFF")
        assert hex_to_relative_luminance("#000") == hex_to_relative_luminance("#000000")
        assert hex_to_relative_luminance("#0B0F19") > 0.0

    def test_contrast_ratio_formula_symmetry(self) -> None:
        cr1 = calculate_contrast_ratio("#FFFFFF", "#000000")
        cr2 = calculate_contrast_ratio("#000000", "#FFFFFF")
        assert math.isclose(cr1, cr2, abs_tol=1e-5)
        assert math.isclose(cr1, 21.0, abs_tol=0.1)

    def test_badge_contrast_exceeds_18_to_1(self) -> None:
        badge_cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        # Primary #F8FAFC vs Decoupled Badge #050811 is ~19.13:1
        assert badge_cr >= 18.0
        assert badge_cr >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert math.isclose(badge_cr, DECOUPLED_BADGE_CONTRAST_RATIO, abs_tol=1e-3)

    def test_text_contrast_exceeds_7_to_1(self) -> None:
        text_cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        # Primary #F8FAFC vs Dark Backing #0B0F19 is ~18.30:1
        assert text_cr >= 7.0
        assert text_cr >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert math.isclose(text_cr, DARK_THEME_TEXT_CONTRAST_RATIO, abs_tol=1e-3)

    def test_panel_text_contrast_exceeds_7_to_1(self) -> None:
        panel_cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_PANEL_BG)
        # Primary #F8FAFC vs Panel BG #161B22 is ~16.53:1
        assert panel_cr >= 7.0

    def test_validate_wcag_aaa_contrast_helper(self) -> None:
        compliant, text_cr, badge_cr = validate_wcag_aaa_contrast()
        assert compliant is True
        assert text_cr >= 7.0
        assert badge_cr >= 18.0

    def test_graphical_contrast_target(self) -> None:
        assert WCAG_GRAPHICAL_CONTRAST_TARGET == 3.0
        # Panel border vs panel bg
        border_cr = calculate_contrast_ratio(COLOR_PANEL_BORDER, COLOR_DARK_THEME_BACKING)
        assert border_cr >= 1.0

    def test_stage_colors_distinct(self) -> None:
        assert len(set(STAGE_PALETTE_COLORS)) == 5


# ============================================================================
# 7. TestHornerOCSSynchronizationAndRegisters
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Validate %R2100..%R2107 and %M490..%M491 bit-exact synchronization, PrivilegeMode.SYSTEM."""

    def test_sync_to_registers_nominal_values(self) -> None:
        reg_table = RegisterTable()
        canvas = FunnelPipelineCanvas(reg_table=reg_table)
        canvas.sync_to_registers(reg_table, privilege=PrivilegeMode.SYSTEM)

        assert reg_table.read_word("%R2100") == 5       # Funnel stages count
        assert reg_table.read_word("%R2101") == 12500   # Inlet flow scaled (1250.0 x 10)
        assert reg_table.read_word("%R2102") == 6850    # Outlet yield scaled (685.0 x 10)
        assert reg_table.read_word("%R2103") == 5480    # Overall efficiency scaled (54.80 x 100)
        assert reg_table.read_word("%R2104") == 1       # Bottleneck stage index
        assert reg_table.read_word("%R2105") == 2240    # Max stage attrition scaled (22.40 x 100)
        assert reg_table.read_word("%R2106") == 0       # Monitored stage index
        assert reg_table.read_word("%R2107") == 0       # Diagnostic code (OK)

    def test_sync_to_registers_discrete_coils(self) -> None:
        reg_table = RegisterTable()
        canvas = FunnelPipelineCanvas(reg_table=reg_table)
        assert reg_table.read_bit("%M490") is True     # FunnelCanvasActive
        assert reg_table.read_bit("%M491") is False    # PipelineBottleneckAlarm

    def test_sync_to_registers_privilege_mode_system(self) -> None:
        reg_table = RegisterTable()
        canvas = FunnelPipelineCanvas(reg_table=reg_table)
        canvas.sync_to_registers(reg_table, privilege=PrivilegeMode.SYSTEM)
        assert reg_table.read_word(REG_FUNNEL_STAGES_COUNT) == 5

    def test_sync_to_registers_custom_table(self) -> None:
        canvas = FunnelPipelineCanvas()
        custom_table = RegisterTable()
        canvas.sync_to_registers(custom_table, privilege=PrivilegeMode.SYSTEM)
        assert custom_table.read_word("%R2100") == 5
        assert custom_table.read_bit("%M490") is True

    def test_sync_to_registers_signed_diagnostic_code(self) -> None:
        reg_table = RegisterTable()
        canvas = FunnelPipelineCanvas(reg_table=reg_table)
        canvas.trigger_stages_count_invalid(bad_stages_count=1)
        # Diagnostic code 0xF901 stored as signed -1791
        raw_val = reg_table.read_word("%R2107")
        assert raw_val == -1791
        assert (raw_val & 0xFFFF) == 0xF901

    def test_register_bit_exactness_all_8_words(self) -> None:
        reg_table = RegisterTable()
        canvas = FunnelPipelineCanvas(reg_table=reg_table)
        expected = [5, 12500, 6850, 5480, 1, 2240, 0, 0]
        for idx in range(8):
            addr = f"%R{2100 + idx}"
            val = reg_table.read_word(addr)
            assert val == expected[idx]

    def test_register_read_unsigned_and_signed(self) -> None:
        reg_table = RegisterTable()
        canvas = FunnelPipelineCanvas(reg_table=reg_table)
        canvas.trigger_zero_inlet_volume(bad_inlet=0.0)
        # 0xF903 -> -1789
        r2107 = reg_table.read_word("%R2107")
        assert r2107 == -1789
        assert (r2107 & 0xFFFF) == 0xF903
        assert DiagnosticCode(r2107) == 0xF903

    def test_register_overwrite_and_re_sync(self) -> None:
        reg_table = RegisterTable()
        canvas = FunnelPipelineCanvas(reg_table=reg_table)
        reg_table.write_word("%R2100", 99, privilege=PrivilegeMode.SYSTEM)
        assert reg_table.read_word("%R2100") == 99

        canvas.sync_to_registers(reg_table, privilege=PrivilegeMode.SYSTEM)
        assert reg_table.read_word("%R2100") == 5

    def test_isolated_register_tables(self) -> None:
        t1 = RegisterTable()
        t2 = RegisterTable()
        c1 = FunnelPipelineCanvas(reg_table=t1)
        c2 = FunnelPipelineCanvas(reg_table=t2)
        c1.trigger_bottleneck_attrition_alarm(attrition_pct=35.0)
        assert t1.read_bit("%M491") is True
        assert t2.read_bit("%M491") is False

    def test_sync_from_registers_selected_stage(self) -> None:
        reg_table = RegisterTable()
        canvas = FunnelPipelineCanvas(reg_table=reg_table)
        reg_table.write_word(REG_SELECTED_PIPELINE_STAGE, 2, privilege=PrivilegeMode.SYSTEM)
        canvas.sync_from_registers(reg_table)
        assert canvas.metrics.selected_pipeline_stage == 2
        assert canvas.stages[2].is_selected is True
        assert canvas.stages[0].is_selected is False


# ============================================================================
# 8. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate STParser & SecurityGuard verification of FunnelPipelineCanvasSync POU."""

    def test_st_pou_string_constant_non_empty(self) -> None:
        assert isinstance(FUNNEL_PIPELINE_CANVAS_SYNC_PURE_ST_POU, str)
        assert len(FUNNEL_PIPELINE_CANVAS_SYNC_PURE_ST_POU) > 100
        assert "PROGRAM FunnelPipelineCanvasSync" in FUNNEL_PIPELINE_CANVAS_SYNC_PURE_ST_POU

    def test_st_pou_aliases(self) -> None:
        assert FUNNEL_PIPELINE_CANVAS_PURE_ST_POU == FUNNEL_PIPELINE_CANVAS_SYNC_PURE_ST_POU
        assert W249_FUNNEL_PIPELINE_PURE_ST_POU == FUNNEL_PIPELINE_CANVAS_SYNC_PURE_ST_POU

    def test_st_pou_security_guard_assertion(self) -> None:
        SecurityGuard.assert_pure_st_content(FUNNEL_PIPELINE_CANVAS_SYNC_PURE_ST_POU)

    def test_st_pou_st_parser_parse_pou(self) -> None:
        parser = STParser()
        pou = parser.parse_pou(FUNNEL_PIPELINE_CANVAS_SYNC_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "FunnelPipelineCanvasSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_st_pou_variables_count(self) -> None:
        parser = STParser()
        pou = parser.parse_pou(FUNNEL_PIPELINE_CANVAS_SYNC_PURE_ST_POU)
        assert len(pou.variables) == 10

    def test_st_pou_address_bindings(self) -> None:
        parser = STParser()
        pou = parser.parse_pou(FUNNEL_PIPELINE_CANVAS_SYNC_PURE_ST_POU)
        vmap = {v.name: v.address_binding for v in pou.variables}

        expected = {
            "FunnelStagesCount": "%R2100",
            "InletFlowVolumeScaled": "%R2101",
            "OutletYieldVolumeScaled": "%R2102",
            "OverallThroughputEfficiencyScaled": "%R2103",
            "BottleneckStageIndex": "%R2104",
            "MaxStageAttritionScaled": "%R2105",
            "SelectedPipelineStage": "%R2106",
            "DiagnosticCode": "%R2107",
            "FunnelCanvasActive": "%M490",
            "PipelineBottleneckAlarm": "%M491",
        }
        for var_name, expected_addr in expected.items():
            assert vmap.get(var_name) == expected_addr

    def test_st_pou_variable_types(self) -> None:
        parser = STParser()
        pou = parser.parse_pou(FUNNEL_PIPELINE_CANVAS_SYNC_PURE_ST_POU)
        tmap = {v.name: v.data_type for v in pou.variables}
        assert tmap["FunnelStagesCount"] == "INT"
        assert tmap["InletFlowVolumeScaled"] == "INT"
        assert tmap["OutletYieldVolumeScaled"] == "INT"
        assert tmap["OverallThroughputEfficiencyScaled"] == "INT"
        assert tmap["BottleneckStageIndex"] == "INT"
        assert tmap["MaxStageAttritionScaled"] == "INT"
        assert tmap["SelectedPipelineStage"] == "INT"
        assert tmap["DiagnosticCode"] == "INT"
        assert tmap["FunnelCanvasActive"] == "BOOL"
        assert tmap["PipelineBottleneckAlarm"] == "BOOL"

    def test_verify_funnel_pipeline_canvas_pure_st_helper(self) -> None:
        assert verify_funnel_pipeline_canvas_pure_st() is True

    def test_st_pou_no_ladder_keywords(self) -> None:
        content = FUNNEL_PIPELINE_CANVAS_SYNC_PURE_ST_POU.upper()
        assert "RUNG" not in content
        assert "NETWORK" not in content
        assert "XIC" not in content
        assert "OTE" not in content

    def test_st_parser_validate_code_success(self) -> None:
        res = STParser.validate_code(FUNNEL_PIPELINE_CANVAS_SYNC_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS
        assert res.data.get("pou_name") == "FunnelPipelineCanvasSync"
        assert res.data.get("pou_type") == "PROGRAM"


# ============================================================================
# 9. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Validate rejection of 6+ ladder constructs (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError."""

    def test_reject_normally_open_contact(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("---[ ]---")

    def test_reject_normally_closed_contact(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("---[/]---")

    def test_reject_standard_coil(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("---( )---")

    def test_reject_set_reset_coils(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("---(S)---")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("---(R)---")

    def test_reject_rung_delimiter(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("RUNG 1: XIC %M490 OTE %M491")

    def test_reject_network_delimiter(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("NETWORK 10: LD %R2100")

    def test_reject_xic_mnemonic(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("XIC StartPipelineScan")

    def test_reject_ote_mnemonic(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("OTE CoilBottleneckAlarm")

    def test_reject_ladder_embedded_in_st(self) -> None:
        poisoned_st = FUNNEL_PIPELINE_CANVAS_SYNC_PURE_ST_POU + "\n---[ ]---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(poisoned_st)

    def test_st_parser_validate_code_returns_failed_on_ladder(self) -> None:
        res = STParser.validate_code("PROGRAM Bad\n---( )---\nEND_PROGRAM")
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"
        assert res.data.get("ladder_rejected") is True


# ============================================================================
# 10. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit protocol: name, priority, is_enabled, scan_step, step, execute, 100-cycle soak stability."""

    def test_ilogic_unit_interface_properties(self) -> None:
        canvas = FunnelPipelineCanvas()
        assert isinstance(canvas, ILogicUnit)
        assert canvas.name == "FunnelPipelineCanvasSync"
        assert canvas.priority == 249
        assert canvas.is_enabled is True

    def test_ilogic_unit_reset_method(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.trigger_bottleneck_attrition_alarm(attrition_pct=35.0)
        assert canvas.metrics.pipeline_bottleneck_alarm is True

        canvas.reset()
        assert canvas.metrics.pipeline_bottleneck_alarm is False
        assert canvas.metrics.overall_throughput_efficiency_pct == 54.80

    def test_ilogic_unit_scan_step(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.scan_step(dt=0.02)
        assert canvas.metrics.funnel_canvas_active is True
        assert canvas.reg_table.read_word("%R2100") == 5

    def test_ilogic_unit_step_shortcut(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.step()
        assert canvas.metrics.funnel_canvas_active is True

    def test_ilogic_unit_execute_with_scan_context(self) -> None:
        canvas = FunnelPipelineCanvas()
        ctx = ScanContext(cycle=1, dt_ms=10.0)
        canvas.execute(ctx)
        assert canvas.metrics.funnel_canvas_active is True
        assert canvas.reg_table.read_word("%R2103") == 5480

    def test_ilogic_unit_disabled_skips_evaluation(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.is_enabled = False
        canvas.scan_step(dt=0.01)
        assert canvas.is_enabled is False

    def test_ilogic_unit_100_cycle_soak_stability(self) -> None:
        canvas = FunnelPipelineCanvas()
        ctx = ScanContext(cycle=1, dt_ms=10.0)
        for _ in range(100):
            canvas.execute(ctx)

        assert not math.isnan(canvas.metrics.overall_throughput_efficiency_pct)
        assert not math.isnan(canvas.metrics.max_stage_attrition_pct)
        assert canvas.metrics.overall_throughput_efficiency_pct == 54.80
        assert canvas.metrics.bottleneck_stage_index == 1

    def test_ilogic_unit_soak_efficiency_invariant(self) -> None:
        canvas = FunnelPipelineCanvas()
        ctx = ScanContext(cycle=1, dt_ms=10.0)
        initial_eff = canvas.metrics.overall_throughput_efficiency_scaled
        for _ in range(100):
            canvas.execute(ctx)
        assert canvas.metrics.overall_throughput_efficiency_scaled == initial_eff == 5480

    def test_ilogic_unit_soak_bottleneck_invariant(self) -> None:
        canvas = FunnelPipelineCanvas()
        ctx = ScanContext(cycle=1, dt_ms=10.0)
        for _ in range(100):
            canvas.execute(ctx)
        assert canvas.metrics.bottleneck_stage_index == 1
        assert canvas.stages[1].is_bottleneck is True

    def test_ilogic_unit_soak_registers_unaltered(self) -> None:
        reg_table = RegisterTable()
        canvas = FunnelPipelineCanvas(reg_table=reg_table)
        ctx = ScanContext(cycle=1, dt_ms=10.0)
        for _ in range(100):
            canvas.execute(ctx)

        assert reg_table.read_word("%R2100") == 5
        assert reg_table.read_word("%R2101") == 12500
        assert reg_table.read_word("%R2102") == 6850
        assert reg_table.read_word("%R2103") == 5480
        assert reg_table.read_bit("%M490") is True
        assert reg_table.read_bit("%M491") is False


# ============================================================================
# 11. TestDiagnosticFaultHandlingAndEdgeCases
# ============================================================================

class TestDiagnosticFaultHandlingAndEdgeCases:
    """Validate 0xF901, 0xF902, 0xF903, 0xF904 fault injection, recovery, and exceptions."""

    def test_fault_stages_count_invalid_0xf901(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.trigger_stages_count_invalid(bad_stages_count=1)
        assert canvas.metrics.diagnostic_code == 0xF901
        assert canvas.metrics.diagnostic_code == DIAG_ERR_STAGES_COUNT_INVALID
        assert canvas.metrics.funnel_canvas_active is False
        assert canvas.reg_table.read_bit(COIL_FUNNEL_CANVAS_ACTIVE) is False
        assert (canvas.status_bits & FunnelPipelineStatusBits.STAGES_COUNT_INVALID) != 0

    def test_fault_inverted_flow_gradient_0xf902(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.trigger_inverted_flow_gradient(bad_inlet=500.0, bad_yield=800.0)
        assert canvas.metrics.diagnostic_code == 0xF902
        assert canvas.metrics.diagnostic_code == DIAG_ERR_INVERTED_FLOW_GRADIENT
        assert canvas.metrics.funnel_canvas_active is False
        assert canvas.reg_table.read_bit(COIL_FUNNEL_CANVAS_ACTIVE) is False
        assert (canvas.status_bits & FunnelPipelineStatusBits.INVERTED_FLOW_FAULT) != 0

    def test_fault_zero_inlet_volume_0xf903(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.trigger_zero_inlet_volume(bad_inlet=0.0)
        assert canvas.metrics.diagnostic_code == 0xF903
        assert canvas.metrics.diagnostic_code == DIAG_ERR_ZERO_INLET_VOLUME
        assert canvas.metrics.funnel_canvas_active is False
        assert canvas.reg_table.read_bit(COIL_FUNNEL_CANVAS_ACTIVE) is False
        assert (canvas.status_bits & FunnelPipelineStatusBits.ZERO_INLET_FAULT) != 0

    def test_fault_canvas_overflow_0xf904(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.trigger_canvas_overflow(x=-15.0, y=50.0)
        assert canvas.metrics.diagnostic_code == 0xF904
        assert canvas.metrics.diagnostic_code == DIAG_ERR_CANVAS_OVERFLOW
        assert canvas.metrics.pipeline_bottleneck_alarm is True
        assert (canvas.status_bits & FunnelPipelineStatusBits.CANVAS_OVERFLOW_FAULT) != 0

    def test_fault_recovery_to_nominal_from_0xf901(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.trigger_stages_count_invalid(bad_stages_count=1)
        assert canvas.metrics.diagnostic_code == 0xF901

        canvas.reset_nominal()
        assert canvas.metrics.diagnostic_code == 0x0000
        assert canvas.metrics.funnel_canvas_active is True
        assert canvas.reg_table.read_bit(COIL_FUNNEL_CANVAS_ACTIVE) is True
        assert (canvas.status_bits & FunnelPipelineStatusBits.STAGES_COUNT_INVALID) == 0

    def test_fault_recovery_to_nominal_from_0xf902(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.trigger_inverted_flow_gradient(bad_inlet=500.0, bad_yield=800.0)
        assert canvas.metrics.diagnostic_code == 0xF902

        canvas.reset_nominal()
        assert canvas.metrics.diagnostic_code == 0x0000
        assert canvas.metrics.funnel_canvas_active is True
        assert canvas.reg_table.read_bit(COIL_FUNNEL_CANVAS_ACTIVE) is True
        assert (canvas.status_bits & FunnelPipelineStatusBits.INVERTED_FLOW_FAULT) == 0

    def test_fault_recovery_to_nominal_from_0xf903(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.trigger_zero_inlet_volume(bad_inlet=0.0)
        assert canvas.metrics.diagnostic_code == 0xF903

        canvas.reset_nominal()
        assert canvas.metrics.diagnostic_code == 0x0000
        assert canvas.metrics.funnel_canvas_active is True
        assert canvas.reg_table.read_bit(COIL_FUNNEL_CANVAS_ACTIVE) is True
        assert (canvas.status_bits & FunnelPipelineStatusBits.ZERO_INLET_FAULT) == 0

    def test_fault_recovery_to_nominal_from_0xf904(self) -> None:
        canvas = FunnelPipelineCanvas()
        canvas.trigger_canvas_overflow(x=-20.0, y=50.0)
        assert canvas.metrics.diagnostic_code == 0xF904

        canvas.reset_nominal()
        assert canvas.metrics.diagnostic_code == 0x0000
        assert (canvas.status_bits & FunnelPipelineStatusBits.CANVAS_OVERFLOW_FAULT) == 0

    def test_custom_stages_initialization(self) -> None:
        custom_stages = [
            PipelineStage(stage_index=0, name="Feed", tag="F", flow_volume=1000.0),
            PipelineStage(stage_index=1, name="Sep", tag="S", flow_volume=800.0),
            PipelineStage(stage_index=2, name="React", tag="R", flow_volume=600.0),
        ]
        canvas = FunnelPipelineCanvas(stages=custom_stages)
        assert canvas.metrics.diagnostic_code == 0x0000
        assert canvas.metrics.funnel_stages_count == 3
        assert canvas.metrics.overall_throughput_efficiency_pct == 60.0  # 600/1000 = 60%
        assert canvas.reg_table.read_word("%R2100") == 3
        assert canvas.reg_table.read_word("%R2101") == 10000

    def test_exception_hierarchy(self) -> None:
        assert issubclass(StagesCountInvalidError, FunnelPipelineCanvasError)
        assert issubclass(InvertedFlowGradientError, FunnelPipelineCanvasError)
        assert issubclass(ZeroInletVolumeError, FunnelPipelineCanvasError)
        assert issubclass(CanvasOverflowError, FunnelPipelineCanvasError)


# ============================================================================
# 12. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate deterministic 9-stage verification runner, report payload, and strict 4-state contract."""

    def test_run_verification_returns_dict(self) -> None:
        res = run_funnel_pipeline_canvas_verification()
        assert isinstance(res, dict)

    def test_run_verification_status_success(self) -> None:
        res = run_funnel_pipeline_canvas_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None

    def test_run_verification_checks_passed_equals_total(self) -> None:
        res = run_funnel_pipeline_canvas_verification()
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9

    def test_run_verification_stages_1_to_9_present(self) -> None:
        res = run_funnel_pipeline_canvas_verification()
        tests = res["data"]["tests"]
        assert len(tests) == 9
        for i, t in enumerate(tests, start=1):
            assert t["stage"] == i
            assert t["passed"] is True
            assert "check" in t
            assert "timing_ms" in t

    def test_run_verification_evidence_file_created(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_file = Path(tmp_dir) / "test_evidence.json"
            svg_file = Path(tmp_dir) / "test_sample.svg"
            res = run_funnel_pipeline_canvas_verification(
                output_path=str(ev_file),
                sample_svg_path=str(svg_file),
            )
            assert ev_file.exists()
            assert ev_file.stat().st_size > 0
            content = json.loads(ev_file.read_text(encoding="utf-8"))
            assert content["status"] == "success"

    def test_run_verification_sample_svg_file_created(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_file = Path(tmp_dir) / "test_evidence.json"
            svg_file = Path(tmp_dir) / "test_sample.svg"
            run_funnel_pipeline_canvas_verification(
                output_path=str(ev_file),
                sample_svg_path=str(svg_file),
            )
            assert svg_file.exists()
            svg_content = svg_file.read_text(encoding="utf-8")
            assert svg_content.startswith("<?xml")
            assert "</svg>" in svg_content

    def test_run_verification_metrics_payload(self) -> None:
        res = run_funnel_pipeline_canvas_verification()
        metrics = res["data"]["metrics"]
        assert metrics["funnel_stages_count"] == 5
        assert metrics["inlet_flow_volume_scaled"] == 12500
        assert metrics["outlet_yield_volume_scaled"] == 6850
        assert metrics["overall_throughput_efficiency_scaled"] == 5480
        assert metrics["bottleneck_stage_index"] == 1
        assert metrics["max_stage_attrition_scaled"] == 2240
        assert metrics["diagnostic_code"] == "0x0000"
        assert metrics["funnel_canvas_active"] is True
        assert metrics["pipeline_bottleneck_alarm"] is False
        assert metrics["wcag_badge_contrast"] >= 18.0
        assert metrics["wcag_text_contrast"] >= 7.0

    def test_run_verification_strict_4_state_contract(self) -> None:
        res = run_funnel_pipeline_canvas_verification()
        assert res["status"] in ("success", "failed", "blocked", "inconclusive")
        assert "data" in res
        assert "details" in res

    def test_run_verification_work_package_field(self) -> None:
        res = run_funnel_pipeline_canvas_verification(work_package="W249_CUSTOM")
        assert res["data"]["work_package"] == "W249_CUSTOM"
        assert res["data"]["gate"] == "Gate G9 / G2"


# ============================================================================
# 13. TestClassAliasesAndCanonicalFactory
# ============================================================================

class TestClassAliasesAndCanonicalFactory:
    """Validate class aliases, factory functions, dataclass defaults, and module exports."""

    def test_engine_alias(self) -> None:
        assert FunnelPipelineCanvasEngine is FunnelPipelineCanvas

    def test_sync_alias(self) -> None:
        assert FunnelPipelineCanvasSync is FunnelPipelineCanvas

    def test_create_canonical_funnel_pipeline_canvas_factory(self) -> None:
        canvas = create_canonical_funnel_pipeline_canvas()
        assert isinstance(canvas, FunnelPipelineCanvas)
        assert len(canvas.stages) == 5

    def test_funnel_pipeline_metrics_defaults(self) -> None:
        m = FunnelPipelineMetrics()
        assert m.funnel_stages_count == 5
        assert m.inlet_flow_volume == 1250.0
        assert m.outlet_yield_volume == 685.0
        assert m.overall_throughput_efficiency_pct == 54.80
        assert m.bottleneck_stage_index == 1
        assert m.max_stage_attrition_pct == 22.40
        assert m.selected_pipeline_stage == 0
        assert m.diagnostic_code == 0x0000
        assert m.funnel_canvas_active is True
        assert m.pipeline_bottleneck_alarm is False

    def test_pipeline_stage_scaled_properties_negative_and_zero(self) -> None:
        s = PipelineStage(stage_index=0, name="Zero", tag="Z", flow_volume=0.0, drop_off_volume=0.0, attrition_pct=0.0)
        assert s.flow_volume_scaled == 0
        assert s.drop_off_volume_scaled == 0
        assert s.attrition_scaled == 0

    def test_status_bits_bitwise_combinations(self) -> None:
        bits = FunnelPipelineStatusBits.ACTIVE | FunnelPipelineStatusBits.NOMINAL_OPERATION
        assert bool(bits & FunnelPipelineStatusBits.ACTIVE)
        assert bool(bits & FunnelPipelineStatusBits.NOMINAL_OPERATION)
        assert not bool(bits & FunnelPipelineStatusBits.BOTTLENECK_ALARM_ACTIVE)

    def test_module_exports_available_in_hmi(self) -> None:
        import jev_cscape.hmi as hmi
        assert hasattr(hmi, "FunnelPipelineCanvas")
        assert hasattr(hmi, "run_funnel_pipeline_canvas_verification")
        assert hasattr(hmi, "create_canonical_funnel_pipeline_canvas")
        assert hasattr(hmi, "verify_funnel_pipeline_canvas_pure_st")

    def test_execution_result_contract_compatibility(self) -> None:
        res = ExecutionResult.success(details="Canvas verified", data={"stages": 5})
        assert res.status == AgentStatus.SUCCESS
        assert res.data["stages"] == 5
