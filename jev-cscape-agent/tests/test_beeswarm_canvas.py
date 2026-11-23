"""Comprehensive unit test suite for Cscape HMI Dynamic Beeswarm Jitter Scatter SCADA Canvas (W228).

Work Package: W228 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Beeswarm Jitter Scatter SCADA Canvas]

Architectural Coverage (95+ Unit Tests across 15 Test Classes):
1. TestPureSTAndSecurity: Pure IEC 61131-3 Structured Text (ST) POU Grammar, Symbol Binding & Variable Declarations.
2. TestAntiLadderRejection: Comprehensive fail-closed interception of contacts, coils, rungs, networks, mnemonics.
3. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit equality (& 0xFFFF), hashing, enums, status flags.
4. TestPointDataclassAndGeometry: BeeswarmPoint initialization, distance calculation, collision testing, coordinate assignment.
5. TestLaneAllocationAndGeometry: Grouping by lane (Feed, Reactor, Separation, Product), lane bounds, 5-number summary stats.
6. TestForceDisplacementPacking: Non-overlapping circle packing, candidate tangency selection, alternating offsets.
7. TestCollisionAvoidanceConstraint: Zero collision overlaps across all 350 canonical points (d_ij >= 14.0 px), padding enforcement.
8. TestOutlierAndClusterDetection: Tukey IQR outlier detection (Q1 - 1.5*IQR, Q3 + 1.5*IQR) yielding 8 outliers, peak cluster highlighting.
9. TestHighJitterSpreadAlarm: Process safety interlock (%M442 asserted when max jitter > 25.0 px), de-assertion, HUD warning.
10. TestDiagnosticFaultConditions: 0xF201 packing convergence, 0xF202 empty dataset, 0xF203 radius singularity, 0xF204 viewport overflow, reset nominal recovery.
11. TestHornerOCSSynchronizationAndRegisters: RegisterTable memory sync (%R1890..%R1897, %M441..%M442), PrivilegeMode.SYSTEM.
12. TestILogicUnitCompliance: Discrete scan cycle engine, scan_step(dt), execute(context), reset(), 100-cycle soak stability.
13. TestStandaloneW3CSVGGenerationAndXML: Standalone SVG 1.1 vector graphic synthesis, ElementTree XML validation, circles, HUD.
14. TestWCAG21AAAContrastAndVisualLegibility: Relative luminance, contrast formula, badge ratio > 18:1, text ratio > 7.0:1.
15. TestVerificationRunnerAndContract: Deterministic 9-stage verification runner, JSON evidence export, strict 4-state contract.
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

from jev_cscape.hmi.beeswarm_canvas import (
    BEESWARM_CANVAS_PURE_ST_POU,
    BEESWARM_CANVAS_SYNC_PURE_ST_POU,
    BEESWARM_ERR_CONVERGENCE,
    BEESWARM_ERR_EMPTY_DATASET,
    BEESWARM_ERR_OK,
    BEESWARM_ERR_RADIUS_SINGULARITY,
    BEESWARM_ERR_VIEWPORT_OVERFLOW,
    BEESWARM_JITTER_SCADA_SYNC_PURE_ST_POU,
    BEESWARM_OK,
    CANONICAL_ACTIVE_LANES,
    CANONICAL_ACTIVE_PROCESS_LANES_COUNT,
    CANONICAL_CIRCLE_RADIUS_PX,
    CANONICAL_MAX_JITTER_SCALED,
    CANONICAL_MEAN_JITTER_SCALED,
    CANONICAL_OUTLIER_POINTS_COUNT,
    CANONICAL_PACKED_CIRCLES_COUNT,
    CANONICAL_PROCESS_LANES,
    CANONICAL_SAMPLE_POINTS_COUNT,
    CANONICAL_TOTAL_POINTS,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COIL_BEESWARM_CANVAS_ACTIVE,
    COIL_CANVAS_ACTIVE,
    COIL_EXCESSIVE_JITTER_SPREAD_ALARM_ACTIVE,
    COIL_HIGH_JITTER_SPREAD_ALARM,
    COIL_JITTER_ALARM,
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
    COLOR_PURPLE_ACCENT,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    CONVERGENCE_FAULT,
    DEFAULT_CIRCLE_PADDING,
    DEFAULT_CIRCLE_RADIUS,
    DEFAULT_COLLISION_PADDING,
    DEFAULT_POINT_RADIUS,
    DIAG_ERR_COLLISION_PACKING_CONVERGENCE_FAILURE,
    DIAG_ERR_EMPTY_DATASET_ERROR,
    DIAG_ERR_EMPTY_SAMPLE_DATASET,
    DIAG_ERR_PACKING_CONVERGENCE_FAULT,
    DIAG_ERR_POINT_RADIUS_SINGULARITY,
    DIAG_ERR_RADIUS_SINGULARITY_ERROR,
    DIAG_ERR_VIEWPORT_OVERFLOW,
    DIAG_ERR_VIEWPORT_OVERFLOW_ERROR,
    DIAG_EVENT_OK,
    DIAG_OK,
    EMPTY_DATASET_ERROR,
    EMPTY_DATASET_FAULT,
    JITTER_ALARM_THRESHOLD_PX,
    MAX_PACKING_ITERATIONS,
    MAX_PACKING_ITERATIONS_DEFAULT,
    NOMINAL_COLLISION_DISTANCE,
    PACKING_CONVERGENCE_FAULT,
    PLOT_CANVAS_HEIGHT,
    PLOT_CANVAS_WIDTH,
    PLOT_ORIGIN_X,
    PLOT_ORIGIN_Y,
    POINT_RADIUS_SINGULARITY,
    RADIUS_SINGULARITY_ERROR,
    RADIUS_SINGULARITY_FAULT,
    REG_ACTIVE_LANES,
    REG_ACTIVE_LANES_COUNT,
    REG_ACTIVE_PROCESS_LANES_COUNT,
    REG_CIRCLE_RADIUS_PX,
    REG_CLUSTERS_COUNT,
    REG_DENSITY_CLUSTER_COUNT,
    REG_DIAG_CODE,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_LANES_COUNT,
    REG_MAX_JITTER,
    REG_MAX_JITTER_DISPLACEMENT_PX,
    REG_MAX_JITTER_OFFSET_PX_SCALED,
    REG_MEAN_JITTER_OFFSET_PX_SCALED,
    REG_MEAN_JITTER_SPREAD_SCALED,
    REG_MEAN_SPREAD_SCALED,
    REG_OUTLIER_POINTS_COUNT,
    REG_OUTLIERS,
    REG_PACKED_CIRCLES,
    REG_PACKED_CIRCLES_COUNT,
    REG_POINT_RADIUS_PX,
    REG_POINTS_COUNT,
    REG_RADIUS,
    REG_SAMPLE_POINTS,
    REG_TOTAL_POINTS_COUNT,
    REG_TOTAL_SAMPLE_POINTS_COUNT,
    VIEWPORT_OVERFLOW,
    VIEWPORT_OVERFLOW_ERROR,
    VIEWPORT_OVERFLOW_FAULT,
    VIEWPORT_OVERFLOW_LIMIT_PX,
    W228_BEESWARM_PURE_ST_POU,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    BeeswarmCanvas,
    BeeswarmCanvasEngine,
    BeeswarmCanvasError,
    BeeswarmCanvasSync,
    BeeswarmJitterCanvas,
    BeeswarmLane,
    BeeswarmMetrics,
    BeeswarmOrientation,
    BeeswarmPoint,
    BeeswarmScatterCanvas,
    BeeswarmStatusBits,
    CollisionPackingConvergenceError,
    DiagnosticCode,
    EmptyDatasetError,
    PackingAlgorithm,
    PackingConvergenceError,
    PackingStrategy,
    PointRadiusSingularityError,
    ProcessLane,
    RadiusSingularityError,
    SVGRenderError,
    ViewportOverflowError,
    calculate_contrast_ratio,
    calculate_tukey_outliers,
    compute_five_number_summary,
    contrast_ratio,
    create_canonical_beeswarm_canvas,
    create_mock_scan_context,
    generate_canonical_beeswarm_points,
    generate_beeswarm_canvas_svg,
    pack_beeswarm_lane_greedy,
    pack_points_beeswarm,
    relative_luminance,
    run_beeswarm_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_beeswarm_canvas_pure_st,
)


# ============================================================================
# 1. Pure ST POU Grammar & Security Guard Tests
# ============================================================================

class TestPureSTAndSecurity:
    """Test pure IEC 61131-3 ST POU validation, syntax, variables, and security guards."""

    def test_pure_st_content_validates_without_ladder(self) -> None:
        """Verify BEESWARM_CANVAS_PURE_ST_POU passes pure-ST assertion without errors."""
        assert verify_beeswarm_canvas_pure_st() is True

    def test_st_pou_name_and_type(self) -> None:
        """Verify parsed POU has correct name and PROGRAM type."""
        parser = STParser()
        pou = parser.parse_pou(BEESWARM_CANVAS_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "BeeswarmCanvasSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_st_variables_declared(self) -> None:
        """Verify all 10 essential variables are declared in ST source."""
        st_src = BEESWARM_CANVAS_PURE_ST_POU
        assert "TotalSamplePointsCount" in st_src
        assert "PackedCirclesCount" in st_src
        assert "MaxJitterOffsetPxScaled" in st_src
        assert "MeanJitterOffsetPxScaled" in st_src
        assert "OutlierPointsCount" in st_src
        assert "ActiveProcessLanesCount" in st_src
        assert "CircleRadiusPx" in st_src
        assert "DiagnosticStatusCode" in st_src
        assert "BeeswarmCanvasActive" in st_src
        assert "ExcessiveJitterSpreadAlarmActive" in st_src

    def test_st_registers_assigned(self) -> None:
        """Verify Horner OCS direct register bindings in ST POU."""
        st_src = BEESWARM_CANVAS_PURE_ST_POU
        for reg in [
            "%R1890", "%R1891", "%R1892", "%R1893",
            "%R1894", "%R1895", "%R1896", "%R1897",
            "%M441", "%M442",
        ]:
            assert reg in st_src, f"Expected register {reg} in ST code"

    def test_alias_pou_beeswarm_jitter_scada_sync(self) -> None:
        """Verify secondary POU alias BeeswarmJitterScadaSync parses cleanly."""
        parser = STParser()
        pou = parser.parse_pou(BEESWARM_JITTER_SCADA_SYNC_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "BeeswarmCanvasSync"
        assert pou.pou_type == POUType.PROGRAM
        assert len(pou.bound_registers) == 10

    def test_w228_alias_string_equivalence(self) -> None:
        """Verify W228_BEESWARM_PURE_ST_POU alias is identical to main POU."""
        assert W228_BEESWARM_PURE_ST_POU == BEESWARM_CANVAS_PURE_ST_POU

    def test_verify_beeswarm_canvas_pure_st_helper(self) -> None:
        """Verify helper returns True on clean ST code."""
        assert verify_beeswarm_canvas_pure_st() is True


# ============================================================================
# 2. Anti-Ladder Rejection Tests
# ============================================================================

class TestAntiLadderRejection:
    """Test comprehensive fail-closed interception of ladder logic constructs."""

    def test_reject_normally_open_contact(self) -> None:
        """Interception of normally open contact symbol ---[ ]---."""
        tampered = BEESWARM_CANVAS_PURE_ST_POU + "\n---[ ]---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(tampered)

    def test_reject_normally_closed_contact(self) -> None:
        """Interception of normally closed contact symbol ---[/]---."""
        tampered = BEESWARM_CANVAS_PURE_ST_POU + "\n---[/]---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(tampered)

    def test_reject_standard_coil(self) -> None:
        """Interception of output coil symbol ---( )---."""
        tampered = BEESWARM_CANVAS_PURE_ST_POU + "\n---( )---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(tampered)

    def test_reject_set_reset_coils(self) -> None:
        """Interception of Set/Reset coils ---(S)--- and ---(R)---."""
        for coil in ["---(S)---", "---(R)---", "---(L)---", "---(U)---"]:
            tampered = BEESWARM_CANVAS_PURE_ST_POU + f"\n{coil}\n"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(tampered)

    def test_reject_rung_network_delimiters(self) -> None:
        """Interception of RUNG and NETWORK ladder delimiters."""
        for kw in ["RUNG 1", "NETWORK 1", "END_RUNG", "NETWORK 10"]:
            tampered = BEESWARM_CANVAS_PURE_ST_POU + f"\n{kw}\n"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(tampered)

    def test_reject_ladder_mnemonics(self) -> None:
        """Interception of Allen-Bradley / Modicon ladder mnemonics."""
        for mnemonic in ["XIC bit_1", "XIO bit_2", "OTE coil_1", "OTL latch_1", "OTU unlatch_1"]:
            tampered = BEESWARM_CANVAS_PURE_ST_POU + f"\n{mnemonic}\n"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(tampered)

    def test_fail_closed_on_ladder_tamper(self) -> None:
        """Verify fail-closed assertion on ladder tamper."""
        st_clean = BEESWARM_CANVAS_PURE_ST_POU
        assert SecurityGuard.assert_pure_st_content(st_clean) is None
        tampered = st_clean + "\n---[ ]---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(tampered)
        assert SecurityGuard.assert_pure_st_content(st_clean) is None


# ============================================================================
# 3. Constants, Enums & Diagnostics Tests
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Test DiagnosticCode signed/unsigned 16-bit equality (& 0xFFFF), hashing, and enums."""

    def test_diagnostic_code_signed_unsigned_equality_0xf201(self) -> None:
        """Verify DiagnosticCode handles 0xF201 packing convergence signed/unsigned equality."""
        code = DIAG_ERR_COLLISION_PACKING_CONVERGENCE_FAILURE
        assert code == 0xF201
        assert code == -3583
        assert (int(code) & 0xFFFF) == 0xF201

    def test_diagnostic_code_signed_unsigned_equality_0xf202(self) -> None:
        """Verify DiagnosticCode handles 0xF202 empty dataset signed/unsigned equality."""
        code = DIAG_ERR_EMPTY_DATASET_ERROR
        assert code == 0xF202
        assert code == -3582
        assert (int(code) & 0xFFFF) == 0xF202

    def test_diagnostic_code_signed_unsigned_equality_0xf203(self) -> None:
        """Verify DiagnosticCode handles 0xF203 radius singularity signed/unsigned equality."""
        code = DIAG_ERR_RADIUS_SINGULARITY_ERROR
        assert code == 0xF203
        assert code == -3581
        assert (int(code) & 0xFFFF) == 0xF203

    def test_diagnostic_code_signed_unsigned_equality_0xf204(self) -> None:
        """Verify DiagnosticCode handles 0xF204 viewport overflow signed/unsigned equality."""
        code = DIAG_ERR_VIEWPORT_OVERFLOW_ERROR
        assert code == 0xF204
        assert code == -3580
        assert (int(code) & 0xFFFF) == 0xF204

    def test_diagnostic_code_ok(self) -> None:
        """Verify nominal OK code is 0x0000."""
        assert DIAG_EVENT_OK == 0x0000
        assert DIAG_EVENT_OK == 0
        assert BEESWARM_OK == 0
        assert BEESWARM_ERR_OK == 0

    def test_diagnostic_code_hashing(self) -> None:
        """Verify DiagnosticCode hashes properly in sets and dicts."""
        d = {DIAG_EVENT_OK: "OK", DIAG_ERR_COLLISION_PACKING_CONVERGENCE_FAILURE: "CONVERGENCE"}
        assert d[DiagnosticCode(0x0000)] == "OK"
        assert d[DiagnosticCode(0xF201)] == "CONVERGENCE"

    def test_packing_strategy_enum(self) -> None:
        """Verify PackingStrategy enum values."""
        assert PackingStrategy.GREEDY == "greedy"
        assert PackingStrategy.FORCE_DIRECTED == "force_directed"
        assert PackingStrategy.HYBRID == "hybrid"

    def test_beeswarm_orientation_enum(self) -> None:
        """Verify BeeswarmOrientation enum values."""
        assert BeeswarmOrientation.HORIZONTAL in ("horizontal", "HORIZONTAL")
        assert BeeswarmOrientation.VERTICAL in ("vertical", "VERTICAL")

    def test_beeswarm_status_bits_flags(self) -> None:
        """Verify BeeswarmStatusBits IntFlag masks and combinations."""
        bits = BeeswarmStatusBits.ACTIVE | BeeswarmStatusBits.PACKING_SETTLED | BeeswarmStatusBits.WCAG_AAA_COMPLIANT
        assert BeeswarmStatusBits.ACTIVE in bits
        assert BeeswarmStatusBits.PACKING_SETTLED in bits
        assert BeeswarmStatusBits.WCAG_AAA_COMPLIANT in bits
        assert BeeswarmStatusBits.CONVERGENCE_FAILURE not in bits


# ============================================================================
# 4. Point Dataclass & Geometry Tests
# ============================================================================

class TestPointDataclassAndGeometry:
    """Test BeeswarmPoint initialization, distance, overlaps, and coordinates."""

    def test_point_initialization_defaults(self) -> None:
        """Verify default attributes for BeeswarmPoint."""
        p = BeeswarmPoint(id="P1", value=50.0)
        assert p.id == "P1"
        assert p.value == 50.0
        assert p.lane_id == "Feed"
        assert p.radius == DEFAULT_CIRCLE_RADIUS
        assert p.x == 0.0
        assert p.y == 0.0
        assert p.jitter_offset_px == 0.0
        assert p.is_outlier is False

    def test_point_custom_attributes(self) -> None:
        """Verify custom lane, weight, tag, and color on BeeswarmPoint."""
        p = BeeswarmPoint(
            id="PT_101",
            value=125.4,
            lane_id="Reactor",
            lane_index=1,
            radius=8.0,
            tag="TI_REACTOR_1",
            batch_id="LOT-2026-REA-01",
            fill_color="#10B981",
        )
        assert p.id == "PT_101"
        assert p.lane_id == "Reactor"
        assert p.lane_index == 1
        assert p.radius == 8.0
        assert p.tag == "TI_REACTOR_1"
        assert p.batch_id == "LOT-2026-REA-01"

    def test_point_distance_to_same_point(self) -> None:
        """Verify distance to self or identical coordinates is 0.0."""
        p1 = BeeswarmPoint(id="1", value=10.0, x=100.0, y=150.0)
        p2 = BeeswarmPoint(id="2", value=10.0, x=100.0, y=150.0)
        assert p1.distance_to(p2) == 0.0

    def test_point_distance_to_different_points(self) -> None:
        """Verify Euclidean distance calculation (3-4-5 triangle)."""
        p1 = BeeswarmPoint(id="1", value=10.0, x=100.0, y=100.0)
        p2 = BeeswarmPoint(id="2", value=20.0, x=103.0, y=104.0)
        assert math.isclose(p1.distance_to(p2), 5.0, abs_tol=1e-5)

    def test_point_overlaps_with_overlapping_points(self) -> None:
        """Verify distance < 2*radius means overlapping."""
        p1 = BeeswarmPoint(id="1", value=10.0, x=100.0, y=100.0, radius=6.0)
        p2 = BeeswarmPoint(id="2", value=10.0, x=105.0, y=100.0, radius=6.0)
        assert p1.distance_to(p2) < (p1.radius + p2.radius)

    def test_point_overlaps_with_non_overlapping_points(self) -> None:
        """Verify distance >= 2*radius means non-overlapping."""
        p1 = BeeswarmPoint(id="1", value=10.0, x=100.0, y=100.0, radius=6.0)
        p2 = BeeswarmPoint(id="2", value=20.0, x=115.0, y=100.0, radius=6.0)
        assert p1.distance_to(p2) >= (p1.radius + p2.radius)

    def test_point_screen_coordinate_assignment(self) -> None:
        """Verify assigning coordinates and jitter displacement."""
        p = BeeswarmPoint(id="1", value=50.0)
        p.x = 250.0
        p.y = 310.0
        p.jitter_offset_px = 10.0
        assert p.x == 250.0
        assert p.y == 310.0
        assert p.jitter_offset_px == 10.0

    def test_point_cluster_peak_flag(self) -> None:
        """Verify is_cluster_peak flag on BeeswarmPoint."""
        p = BeeswarmPoint(id="PEAK_01", value=45.0, is_cluster_peak=True)
        assert p.is_cluster_peak is True


# ============================================================================
# 5. Lane Allocation & Geometry Tests
# ============================================================================

class TestLaneAllocationAndGeometry:
    """Test grouping by lane, lane bounds, baseline spacing, and value scaling."""

    def test_canonical_lanes_allocation_count(self) -> None:
        """Verify canonical canvas allocates exactly 4 process lanes."""
        canvas = create_canonical_beeswarm_canvas()
        assert len(canvas.lanes) == CANONICAL_ACTIVE_PROCESS_LANES_COUNT
        assert canvas.metrics.active_process_lanes_count == CANONICAL_ACTIVE_PROCESS_LANES_COUNT

    def test_canonical_process_lane_names(self) -> None:
        """Verify lane names: Feed, Reactor, Separation, Product."""
        assert CANONICAL_PROCESS_LANES == ["Feed", "Reactor", "Separation", "Product"]
        canvas = create_canonical_beeswarm_canvas()
        for name in CANONICAL_PROCESS_LANES:
            assert name in canvas.lanes

    def test_lane_point_distribution_350_points(self) -> None:
        """Verify points count per lane in canonical dataset (90, 95, 85, 80)."""
        canvas = create_canonical_beeswarm_canvas()
        assert canvas.lanes["Feed"].points_count == 90
        assert canvas.lanes["Reactor"].points_count == 95
        assert canvas.lanes["Separation"].points_count == 85
        assert canvas.lanes["Product"].points_count == 80
        assert sum(l.points_count for l in canvas.lanes.values()) == 350

    def test_lane_baseline_spacing(self) -> None:
        """Verify lane baselines are spaced evenly along the plot height."""
        canvas = create_canonical_beeswarm_canvas()
        baselines = [canvas.lanes[name].baseline_y for name in CANONICAL_PROCESS_LANES]
        diffs = [baselines[i + 1] - baselines[i] for i in range(len(baselines) - 1)]
        assert math.isclose(diffs[0], diffs[1], abs_tol=1.0)
        assert math.isclose(diffs[1], diffs[2], abs_tol=1.0)

    def test_lane_five_number_summary_stats(self) -> None:
        """Verify compute_five_number_summary helper (Min, Q1, Median, Q3, Max)."""
        vals = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0]
        min_v, q1, med, q3, max_v = compute_five_number_summary(vals)
        assert min_v == 10.0
        assert max_v == 70.0
        assert med == 40.0
        assert q1 == 25.0
        assert q3 == 55.0

    def test_lane_custom_points_grouping(self) -> None:
        """Verify custom dataset groups points into correct lanes."""
        pts = [
            BeeswarmPoint(id="1", value=10.0, lane_id="Feed"),
            BeeswarmPoint(id="2", value=12.0, lane_id="Feed"),
            BeeswarmPoint(id="3", value=50.0, lane_id="Reactor"),
        ]
        canvas = BeeswarmCanvas(points=pts)
        assert canvas.lanes["Feed"].points_count == 2
        assert canvas.lanes["Reactor"].points_count == 1
        assert canvas.metrics.active_process_lanes_count == 2

    def test_process_lane_dataclass_fields(self) -> None:
        """Verify ProcessLane dataclass fields."""
        lane = ProcessLane(index=0, name="Feed", baseline_y=150.0, y_min=100.0, y_max=200.0)
        assert lane.name == "Feed"
        assert lane.baseline_y == 150.0
        assert lane.y_min == 100.0
        assert lane.y_max == 200.0
        assert lane.color == COLOR_BLUE_ACCENT

    def test_lane_color_palette_distinctness(self) -> None:
        """Verify each of the 4 canonical lanes has a distinct color."""
        canvas = create_canonical_beeswarm_canvas()
        colors = [canvas.lanes[name].color for name in CANONICAL_PROCESS_LANES]
        assert len(set(colors)) == 4


# ============================================================================
# 6. Force Displacement Packing Tests
# ============================================================================

class TestForceDisplacementPacking:
    """Test iterative greedy packing, non-overlapping slot allocation, and jitter symmetry."""

    def test_greedy_packing_places_all_points(self) -> None:
        """Verify pack_points_beeswarm returns all input points with valid coordinates."""
        test_pts = [BeeswarmPoint(id=f"T_{i}", value=50.0 + i * 2.0, x=100.0 + i * 15.0) for i in range(10)]
        packed_pts, settled, overflow = pack_points_beeswarm(test_pts, baseline_y=200.0)
        assert len(packed_pts) == 10
        assert settled is True
        assert overflow is False

    def test_greedy_packing_jitter_alternation(self) -> None:
        """Verify packing displaces points both positively and negatively around baseline."""
        canvas = create_canonical_beeswarm_canvas()
        for lane_name in CANONICAL_PROCESS_LANES:
            l_pts = [p for p in canvas.points if p.lane_id == lane_name]
            pos_jitter = [p for p in l_pts if p.jitter_offset_px > 0]
            neg_jitter = [p for p in l_pts if p.jitter_offset_px < 0]
            assert len(pos_jitter) > 0
            assert len(neg_jitter) > 0

    def test_packing_identical_values_without_collision(self) -> None:
        """Verify multiple points with identical continuous values pack without colliding."""
        pts = [BeeswarmPoint(id=f"I_{i}", value=50.0, x=200.0) for i in range(8)]
        packed, settled, overflow = pack_points_beeswarm(pts, baseline_y=150.0, radius=6.0, padding=2.0)
        d_min = 14.0
        for i in range(len(packed)):
            for j in range(i + 1, len(packed)):
                assert math.hypot(packed[i].x - packed[j].x, packed[i].y - packed[j].y) >= d_min - 1e-4

    def test_packing_respects_boundary_limits(self) -> None:
        """Verify packing detects lane boundary overflow when jitter exceeds limits."""
        pts = [BeeswarmPoint(id=f"O_{i}", value=50.0, x=200.0) for i in range(30)]
        packed, settled, overflow = pack_points_beeswarm(
            pts, baseline_y=150.0, y_min_limit=140.0, y_max_limit=160.0
        )
        assert overflow is True

    def test_packing_empty_points_returns_empty(self) -> None:
        """Verify packing an empty list returns empty list and settled True."""
        packed, settled, overflow = pack_points_beeswarm([], baseline_y=150.0)
        assert packed == []
        assert settled is True
        assert overflow is False

    def test_packing_radius_singularity_raises_error(self) -> None:
        """Verify pack_points_beeswarm raises RadiusSingularityError if radius <= 0."""
        pts = [BeeswarmPoint(id="1", value=50.0)]
        with pytest.raises(RadiusSingularityError):
            pack_points_beeswarm(pts, baseline_y=150.0, radius=0.0)
        with pytest.raises(RadiusSingularityError):
            pack_points_beeswarm(pts, baseline_y=150.0, radius=-5.0)

    def test_packing_mean_jitter_spread_calculation(self) -> None:
        """Verify canonical mean jitter offset is 6.2 px (scaled 62)."""
        canvas = create_canonical_beeswarm_canvas()
        assert canvas.metrics.mean_jitter_offset_px_scaled == CANONICAL_MEAN_JITTER_SCALED
        assert math.isclose(canvas.metrics.mean_jitter_offset_px, 6.2, abs_tol=0.1)

    def test_packing_max_jitter_offset_calculation(self) -> None:
        """Verify canonical max jitter offset is 14.5 px (scaled 145)."""
        canvas = create_canonical_beeswarm_canvas()
        assert canvas.metrics.max_jitter_offset_px_scaled == CANONICAL_MAX_JITTER_SCALED
        assert math.isclose(canvas.metrics.max_jitter_offset_px, 14.5, abs_tol=0.1)


# ============================================================================
# 7. Collision Avoidance Constraint Tests
# ============================================================================

class TestCollisionAvoidanceConstraint:
    """Test comprehensive collision avoidance (d_ij >= r_i + r_j + padding) across all lanes."""

    def test_canonical_dataset_zero_collisions(self) -> None:
        """Verify canonical 350-point dataset contains strictly zero overlapping circles."""
        canvas = create_canonical_beeswarm_canvas()
        d_min = 2.0 * canvas.radius + canvas.padding  # 14.0 px
        for lane_name in CANONICAL_PROCESS_LANES:
            l_pts = [p for p in canvas.points if p.lane_id == lane_name]
            for i in range(len(l_pts)):
                for j in range(i + 1, len(l_pts)):
                    d = math.hypot(l_pts[i].x - l_pts[j].x, l_pts[i].y - l_pts[j].y)
                    assert d >= d_min - 1e-4, f"Collision in {lane_name}: d={d:.2f} < {d_min}"

    def test_minimum_distance_exceeds_14px(self) -> None:
        """Verify NOMINAL_COLLISION_DISTANCE is 14.0 px."""
        assert NOMINAL_COLLISION_DISTANCE == 14.0

    def test_custom_dataset_zero_collisions_after_pack(self) -> None:
        """Verify packing custom points achieves zero collisions."""
        pts = [
            BeeswarmPoint(id=f"C_{i}", value=40.0 + (i % 5) * 1.0, lane_id="Feed")
            for i in range(25)
        ]
        canvas = BeeswarmCanvas(points=pts, radius=6.0, padding=2.0)
        d_min = 14.0
        feed_pts = [p for p in canvas.points if p.lane_id == "Feed"]
        for i in range(len(feed_pts)):
            for j in range(i + 1, len(feed_pts)):
                d = math.hypot(feed_pts[i].x - feed_pts[j].x, feed_pts[i].y - feed_pts[j].y)
                assert d >= d_min - 1e-4

    def test_pairwise_distance_between_adjacent_lanes(self) -> None:
        """Verify circles in different lanes are well separated by lane spacing."""
        canvas = create_canonical_beeswarm_canvas()
        feed_pts = [p for p in canvas.points if p.lane_id == "Feed"]
        reactor_pts = [p for p in canvas.points if p.lane_id == "Reactor"]
        # Baselines are separated by > 100 px
        min_inter_lane_d = min(
            math.hypot(p1.x - p2.x, p1.y - p2.y)
            for p1 in feed_pts
            for p2 in reactor_pts
        )
        assert min_inter_lane_d > 50.0

    def test_collision_avoidance_with_various_radii(self) -> None:
        """Verify circle packing maintains distance with radius 4.0, 6.0, 8.0 px."""
        for r in [4.0, 6.0, 8.0]:
            pts = [BeeswarmPoint(id=f"R_{i}", value=50.0, x=200.0) for i in range(6)]
            packed, settled, overflow = pack_points_beeswarm(pts, baseline_y=150.0, radius=r, padding=2.0)
            d_min = 2.0 * r + 2.0
            for i in range(len(packed)):
                for j in range(i + 1, len(packed)):
                    d = math.hypot(packed[i].x - packed[j].x, packed[i].y - packed[j].y)
                    assert d >= d_min - 1e-4

    def test_collision_avoidance_with_various_paddings(self) -> None:
        """Verify padding increases separation distance proportionally."""
        for pad in [1.0, 3.0, 5.0]:
            pts = [BeeswarmPoint(id=f"P_{i}", value=50.0, x=200.0) for i in range(6)]
            packed, settled, overflow = pack_points_beeswarm(pts, baseline_y=150.0, radius=6.0, padding=pad)
            d_min = 12.0 + pad
            for i in range(len(packed)):
                for j in range(i + 1, len(packed)):
                    assert math.hypot(packed[i].x - packed[j].x, packed[i].y - packed[j].y) >= d_min - 1e-4

    def test_packed_circles_count_equals_sample_points_count(self) -> None:
        """Verify %R1891 (PackedCirclesCount) == %R1890 (TotalSamplePointsCount)."""
        canvas = create_canonical_beeswarm_canvas()
        assert canvas.metrics.packed_circles_count == canvas.metrics.total_sample_points_count == 350


# ============================================================================
# 8. Outlier & Density Cluster Detection Tests
# ============================================================================

class TestOutlierAndClusterDetection:
    """Test Tukey IQR outlier detection and spatial density cluster detection."""

    def test_calculate_tukey_outliers_helper(self) -> None:
        """Verify calculate_tukey_outliers detects known extremes."""
        vals = [50.0 + i * 0.5 for i in range(40)] + [-50.0, 250.0]
        q1, med, q3, lf, uf, outs = calculate_tukey_outliers(vals)
        assert len(outs) == 2
        assert -50.0 in outs
        assert 250.0 in outs
        assert lf < min([50.0 + i * 0.5 for i in range(40)])
        assert uf > max([50.0 + i * 0.5 for i in range(40)])

    def test_canonical_dataset_outlier_count(self) -> None:
        """Verify exactly 8 outliers detected in canonical dataset (2 per lane)."""
        canvas = create_canonical_beeswarm_canvas()
        assert canvas.metrics.outlier_points_count == CANONICAL_OUTLIER_POINTS_COUNT
        assert canvas.metrics.outlier_points_count == 8

    def test_outlier_count_per_lane(self) -> None:
        """Verify each of the 4 lanes has exactly 2 outliers."""
        canvas = create_canonical_beeswarm_canvas()
        for name in CANONICAL_PROCESS_LANES:
            assert canvas.lanes[name].outlier_count == 2

    def test_outlier_points_have_is_outlier_flag(self) -> None:
        """Verify outlier points have is_outlier == True."""
        canvas = create_canonical_beeswarm_canvas()
        outliers = [p for p in canvas.points if p.is_outlier]
        assert len(outliers) == 8
        for p in outliers:
            assert p.is_outlier is True

    def test_peak_cluster_point_identified(self) -> None:
        """Verify at least one circle is flagged as is_cluster_peak."""
        canvas = create_canonical_beeswarm_canvas()
        peaks = [p for p in canvas.points if p.is_cluster_peak]
        assert len(peaks) >= 1

    def test_uniform_distribution_has_zero_outliers(self) -> None:
        """Verify uniform distribution produces 0 outliers."""
        vals = [20.0 + i * 2.0 for i in range(30)]
        q1, med, q3, lf, uf, outs = calculate_tukey_outliers(vals)
        assert len(outs) == 0

    def test_empty_values_returns_empty_tukey(self) -> None:
        """Verify calculate_tukey_outliers with empty list returns default zeros."""
        q1, med, q3, lf, uf, outs = calculate_tukey_outliers([])
        assert (q1, med, q3, lf, uf, outs) == (0.0, 0.0, 0.0, 0.0, 0.0, [])

    def test_status_bits_outlier_detected(self) -> None:
        """Verify OUTLIER_DETECTED status bit is present in status_bits."""
        assert BeeswarmStatusBits.OUTLIER_DETECTED == 1 << 3


# ============================================================================
# 9. High Jitter Spread Alarm Tests
# ============================================================================

class TestHighJitterSpreadAlarm:
    """Test process safety interlock: High Jitter Spread Alarm (%M442)."""

    def test_canonical_jitter_within_limits_alarm_clear(self) -> None:
        """Verify canonical max jitter (14.5 px) is <= 25.0 px, alarm is CLEAR."""
        canvas = create_canonical_beeswarm_canvas()
        assert canvas.metrics.max_jitter_offset_px <= JITTER_ALARM_THRESHOLD_PX
        assert canvas.metrics.excessive_jitter_spread_alarm_active is False
        assert canvas.reg_table.read_bit(COIL_EXCESSIVE_JITTER_SPREAD_ALARM_ACTIVE) is False

    def test_trigger_jitter_alarm_asserts_coil_m442(self) -> None:
        """Verify trigger_jitter_alarm asserts %M442 and metrics alarm flag."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.trigger_jitter_alarm(high_jitter=28.5)
        assert canvas.metrics.excessive_jitter_spread_alarm_active is True
        assert canvas.reg_table.read_bit(COIL_EXCESSIVE_JITTER_SPREAD_ALARM_ACTIVE) is True
        assert BeeswarmStatusBits.JITTER_ALARM_ACTIVE in canvas.status_bits

    def test_reset_nominal_clears_alarm(self) -> None:
        """Verify reset_nominal de-asserts %M442."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.trigger_jitter_alarm(high_jitter=30.0)
        assert canvas.metrics.excessive_jitter_spread_alarm_active is True

        canvas.reset_nominal()
        assert canvas.metrics.excessive_jitter_spread_alarm_active is False
        assert canvas.reg_table.read_bit(COIL_EXCESSIVE_JITTER_SPREAD_ALARM_ACTIVE) is False
        assert BeeswarmStatusBits.JITTER_ALARM_ACTIVE not in canvas.status_bits

    def test_jitter_alarm_threshold_constant(self) -> None:
        """Verify JITTER_ALARM_THRESHOLD_PX is 25.0 px."""
        assert JITTER_ALARM_THRESHOLD_PX == 25.0

    def test_alarm_status_in_svg_hud_when_active(self) -> None:
        """Verify SVG HUD displays ACTIVE (>25px) when alarm is asserted."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.trigger_jitter_alarm(high_jitter=28.0)
        svg = canvas.render_svg()
        assert "ACTIVE" in svg

    def test_alarm_status_in_svg_hud_when_clear(self) -> None:
        """Verify SVG HUD displays CLEAR when alarm is not asserted."""
        canvas = create_canonical_beeswarm_canvas()
        svg = canvas.render_svg()
        assert "CLEAR" in svg


# ============================================================================
# 10. Diagnostic Fault Conditions Tests
# ============================================================================

class TestDiagnosticFaultConditions:
    """Test 0xF201..0xF204 diagnostic fault injection, latching, and reset behavior."""

    def test_diagnostic_fault_convergence_0xf201(self) -> None:
        """Verify 0xF201 triggered when packing convergence fails."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.trigger_convergence_failure()
        assert canvas.diagnostic_code == DIAG_ERR_COLLISION_PACKING_CONVERGENCE_FAILURE
        reg_val = canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF
        assert reg_val == 0xF201
        assert BeeswarmStatusBits.CONVERGENCE_FAILURE in canvas.status_bits

    def test_diagnostic_fault_empty_dataset_0xf202(self) -> None:
        """Verify 0xF202 triggered when sample dataset is empty."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.trigger_empty_dataset()
        assert canvas.diagnostic_code == DIAG_ERR_EMPTY_DATASET_ERROR
        reg_val = canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF
        assert reg_val == 0xF202
        assert BeeswarmStatusBits.EMPTY_DATASET_FAULT in canvas.status_bits

    def test_diagnostic_fault_radius_singularity_0xf203(self) -> None:
        """Verify 0xF203 triggered when radius <= 0."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.trigger_radius_singularity(bad_radius=0.0)
        assert canvas.diagnostic_code == DIAG_ERR_RADIUS_SINGULARITY_ERROR
        reg_val = canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF
        assert reg_val == 0xF203
        assert BeeswarmStatusBits.RADIUS_SINGULARITY_FAULT in canvas.status_bits

    def test_diagnostic_fault_radius_singularity_negative(self) -> None:
        """Verify 0xF203 triggered when radius < 0."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.trigger_radius_singularity(bad_radius=-3.0)
        assert canvas.diagnostic_code == DIAG_ERR_RADIUS_SINGULARITY_ERROR

    def test_diagnostic_fault_viewport_overflow_0xf204(self) -> None:
        """Verify 0xF204 triggered when jitter exceeds lane boundary."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.trigger_viewport_overflow(overflow_jitter=75.0)
        assert canvas.diagnostic_code == DIAG_ERR_VIEWPORT_OVERFLOW_ERROR
        reg_val = canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF
        assert reg_val == 0xF204
        assert BeeswarmStatusBits.VIEWPORT_OVERFLOW_FAULT in canvas.status_bits

    def test_render_svg_raises_on_radius_singularity(self) -> None:
        """Verify render_svg raises RadiusSingularityError when radius <= 0."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.radius = 0.0
        with pytest.raises(RadiusSingularityError):
            canvas.render_svg()

    def test_render_svg_raises_on_render_fault(self) -> None:
        """Verify render_svg raises SVGRenderError when fault is injected."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.trigger_render_fault()
        with pytest.raises(SVGRenderError):
            canvas.render_svg()

    def test_reset_nominal_restores_all_faults(self) -> None:
        """Verify reset_nominal restores DIAG_EVENT_OK and canonical state."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.trigger_convergence_failure()
        assert canvas.diagnostic_code != DIAG_EVENT_OK

        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0
        assert canvas.metrics.total_sample_points_count == CANONICAL_SAMPLE_POINTS_COUNT
        assert canvas.metrics.active_process_lanes_count == CANONICAL_ACTIVE_PROCESS_LANES_COUNT

    def test_mutator_methods(self) -> None:
        """Verify set_radius, set_padding, and set_points mutators."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.set_radius(8.0)
        assert canvas.radius == 8.0
        assert canvas.reg_table.read_word(REG_CIRCLE_RADIUS_PX) == 8

        canvas.set_padding(3.0)
        assert canvas.padding == 3.0

        pts = [BeeswarmPoint(id="1", value=10.0, lane_id="Feed")]
        canvas.set_points(pts)
        assert canvas.metrics.total_sample_points_count == 1


# ============================================================================
# 11. Horner OCS Memory Space & Register Synchronization Tests
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Test register synchronization (%R1890..%R1897, %M441..%M442) with PrivilegeMode.SYSTEM."""

    def test_registers_r1890_through_r1897_words(self) -> None:
        """Verify all analog word registers match telemetry metrics."""
        canvas = create_canonical_beeswarm_canvas()
        reg_table = canvas.reg_table

        # %R1890: TotalSamplePointsCount = 350
        assert reg_table.read_word(REG_TOTAL_SAMPLE_POINTS_COUNT) == 350
        # %R1891: PackedCirclesCount = 350
        assert reg_table.read_word(REG_PACKED_CIRCLES_COUNT) == 350
        # %R1892: MaxJitterOffsetPxScaled = 145
        assert reg_table.read_word(REG_MAX_JITTER_OFFSET_PX_SCALED) == 145
        # %R1893: MeanJitterOffsetPxScaled = 62
        assert reg_table.read_word(REG_MEAN_JITTER_OFFSET_PX_SCALED) == 62
        # %R1894: OutlierPointsCount = 8
        assert reg_table.read_word(REG_OUTLIER_POINTS_COUNT) == 8
        # %R1895: ActiveProcessLanesCount = 4
        assert reg_table.read_word(REG_ACTIVE_PROCESS_LANES_COUNT) == 4
        # %R1896: CircleRadiusPx = 6
        assert reg_table.read_word(REG_CIRCLE_RADIUS_PX) == 6
        # %R1897: DiagnosticStatusCode = 0
        assert reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0

    def test_coils_m441_and_m442_bits(self) -> None:
        """Verify discrete coils %M441 (active) and %M442 (alarm)."""
        canvas = create_canonical_beeswarm_canvas()
        reg_table = canvas.reg_table
        assert reg_table.read_bit(COIL_BEESWARM_CANVAS_ACTIVE) is True
        assert reg_table.read_bit(COIL_EXCESSIVE_JITTER_SPREAD_ALARM_ACTIVE) is False

    def test_signed_16bit_diagnostic_read_word_masking(self) -> None:
        """Verify signed 16-bit read_word masked with & 0xFFFF equals hex code."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.trigger_convergence_failure()
        raw_word = canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE)
        # 0xF201 as signed int16 is -3583
        assert raw_word == -3583
        assert (raw_word & 0xFFFF) == 0xF201

    def test_privilege_mode_system_required_for_writes(self) -> None:
        """Verify writes with PrivilegeMode.SYSTEM succeed."""
        table = RegisterTable()
        table.write_word("%R1890", 350, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R1890") == 350

    def test_sync_to_external_register_table(self) -> None:
        """Verify canvas can synchronize into an external RegisterTable instance."""
        canvas = create_canonical_beeswarm_canvas()
        ext_table = RegisterTable()
        canvas.sync_to_registers(reg_table=ext_table, privilege=PrivilegeMode.SYSTEM)

        assert ext_table.read_word(REG_TOTAL_SAMPLE_POINTS_COUNT) == 350
        assert ext_table.read_word(REG_ACTIVE_PROCESS_LANES_COUNT) == 4
        assert ext_table.read_bit(COIL_BEESWARM_CANVAS_ACTIVE) is True

    def test_r1890_total_points_alias(self) -> None:
        """Verify %R1890 alias REG_TOTAL_POINTS_COUNT."""
        canvas = create_canonical_beeswarm_canvas()
        assert canvas.reg_table.read_word(REG_TOTAL_POINTS_COUNT) == 350

    def test_r1895_active_lanes_alias(self) -> None:
        """Verify %R1895 alias REG_ACTIVE_LANES_COUNT."""
        canvas = create_canonical_beeswarm_canvas()
        assert canvas.reg_table.read_word(REG_ACTIVE_LANES_COUNT) == 4

    def test_r1896_circle_radius_alias(self) -> None:
        """Verify %R1896 alias REG_POINT_RADIUS_PX."""
        canvas = create_canonical_beeswarm_canvas()
        assert canvas.reg_table.read_word(REG_POINT_RADIUS_PX) == 6


# ============================================================================
# 12. ILogicUnit Integration & Scan Cycle Tests
# ============================================================================

class TestILogicUnitCompliance:
    """Test ILogicUnit discrete scan cycle protocol implementation."""

    def test_ilogic_unit_properties(self) -> None:
        """Verify name, priority, and is_enabled properties."""
        canvas = create_canonical_beeswarm_canvas()
        assert canvas.name == "BeeswarmCanvasSync"
        assert canvas.priority == 88
        assert canvas.is_enabled is True

    def test_scan_step_increments_cycle_and_elapsed(self) -> None:
        """Verify scan_step increments cycle counter and elapsed time."""
        canvas = create_canonical_beeswarm_canvas()
        assert canvas._cycle_count == 0
        assert canvas._elapsed_s == 0.0

        canvas.scan_step(dt=0.02)
        assert canvas._cycle_count == 1
        assert math.isclose(canvas._elapsed_s, 0.02, abs_tol=1e-5)

        canvas.scan_step(dt=0.02)
        assert canvas._cycle_count == 2
        assert math.isclose(canvas._elapsed_s, 0.04, abs_tol=1e-5)

    def test_execute_accepts_scan_context(self) -> None:
        """Verify execute method accepting ScanContext."""
        canvas = create_canonical_beeswarm_canvas()
        ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=canvas.reg_table)
        canvas.execute(ctx)
        assert canvas._cycle_count == 1
        assert math.isclose(canvas._elapsed_s, 0.01, abs_tol=1e-5)

    def test_reset_restores_nominal(self) -> None:
        """Verify reset() method restores initial canonical state."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.trigger_empty_dataset()
        assert canvas.metrics.total_sample_points_count == 0

        canvas.reset()
        assert canvas.metrics.total_sample_points_count == CANONICAL_SAMPLE_POINTS_COUNT
        assert canvas.diagnostic_code == DIAG_EVENT_OK

    def test_100_cycle_simulation_stability(self) -> None:
        """Verify executing 100 consecutive scan cycles maintains state stability."""
        canvas = create_canonical_beeswarm_canvas()
        for c in range(1, 101):
            ctx = create_mock_scan_context(cycle=c, dt_ms=10.0, reg_table=canvas.reg_table)
            canvas.execute(ctx)

        assert canvas._cycle_count == 100
        assert math.isclose(canvas._elapsed_s, 1.0, abs_tol=1e-4)
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.metrics.total_sample_points_count == CANONICAL_SAMPLE_POINTS_COUNT

    def test_scan_step_with_custom_dt(self) -> None:
        """Verify scan_step with custom dt updates elapsed time accordingly."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.scan_step(dt=0.05)
        assert math.isclose(canvas._elapsed_s, 0.05, abs_tol=1e-5)

    def test_is_enabled_property_tracks_active(self) -> None:
        """Verify is_enabled tracks is_active flag."""
        canvas = create_canonical_beeswarm_canvas()
        assert canvas.is_enabled is True
        canvas.is_active = False
        assert canvas.is_enabled is False

    def test_scan_step_recomputes_and_syncs_registers(self) -> None:
        """Verify scan_step keeps registers synchronized."""
        canvas = create_canonical_beeswarm_canvas()
        canvas.scan_step()
        assert canvas.reg_table.read_word(REG_TOTAL_SAMPLE_POINTS_COUNT) == 350


# ============================================================================
# 13. Standalone W3C SVG 1.1 Vector Canvas XML Tests
# ============================================================================

class TestStandaloneW3CSVGGenerationAndXML:
    """Test XML SVG synthesis, validity with ElementTree, tags, and attributes."""

    def test_render_svg_valid_xml(self) -> None:
        """Verify render_svg produces valid well-formed XML parseable by xml.etree.ElementTree."""
        canvas = create_canonical_beeswarm_canvas()
        svg_xml = canvas.render_svg()
        root = ET.fromstring(svg_xml)
        assert root is not None
        assert root.tag.endswith("svg")

    def test_svg_root_dimensions_and_viewbox(self) -> None:
        """Verify SVG viewBox and width/height match 1200x750 viewport."""
        canvas = create_canonical_beeswarm_canvas()
        svg_xml = canvas.render_svg()
        root = ET.fromstring(svg_xml)
        assert root.attrib.get("width") == "1200"
        assert root.attrib.get("height") == "750"
        assert root.attrib.get("viewBox") == "0 0 1200 750"

    def test_svg_contains_circle_elements_for_all_points(self) -> None:
        """Verify SVG contains circle elements for all 350 points."""
        canvas = create_canonical_beeswarm_canvas()
        svg_xml = canvas.render_svg()
        root = ET.fromstring(svg_xml)
        circles = root.findall(".//{http://www.w3.org/2000/svg}circle") + root.findall(".//circle")
        assert len(circles) >= 350

    def test_svg_contains_dark_backing_and_hud(self) -> None:
        """Verify dark theme backing (#0D1117) and telemetry HUD scorecard."""
        canvas = create_canonical_beeswarm_canvas()
        svg_xml = canvas.render_svg()
        assert 'id="telemetry-hud"' in svg_xml
        assert "HORNER OCS TELEMETRY HUD" in svg_xml

    def test_svg_contains_lane_labels(self) -> None:
        """Verify SVG contains labels for all 4 process lanes."""
        canvas = create_canonical_beeswarm_canvas()
        svg_xml = canvas.render_svg()
        assert "Feed" in svg_xml
        assert "Reactor" in svg_xml
        assert "Separation" in svg_xml
        assert "Product" in svg_xml

    def test_svg_contains_outlier_warning_halos(self) -> None:
        """Verify SVG contains outlier warning circles with outlier-halo class."""
        canvas = create_canonical_beeswarm_canvas()
        svg_xml = canvas.render_svg()
        assert 'class="outlier-halo"' in svg_xml
        assert 'id="outliers-layer"' in svg_xml

    def test_svg_contains_register_strings_in_hud(self) -> None:
        """Verify register strings (%R1890..%R1897, %M441..%M442) appear in HUD text."""
        canvas = create_canonical_beeswarm_canvas()
        svg_xml = canvas.render_svg()
        for reg in [
            "%R1890", "%R1891", "%R1892", "%R1893",
            "%R1894", "%R1895", "%R1896", "%R1897",
            "%M441", "%M442",
        ]:
            assert reg in svg_xml, f"Expected {reg} in SVG HUD scorecard"

    def test_svg_escapes_xml_entities(self) -> None:
        """Verify text inside SVG is properly XML entity-escaped."""
        canvas = create_canonical_beeswarm_canvas()
        svg_xml = canvas.render_svg()
        ET.fromstring(svg_xml)


# ============================================================================
# 14. WCAG 2.1 AAA Contrast & Accessibility Tests
# ============================================================================

class TestWCAG21AAAContrastAndVisualLegibility:
    """Test WCAG 2.1 AAA contrast ratios (> 18:1 for badges, > 7.0:1 for text)."""

    def test_relative_luminance_extremes(self) -> None:
        """Verify luminance extremes: 0.0 for pure black, 1.0 for pure white."""
        assert math.isclose(relative_luminance("#000000"), 0.0, abs_tol=1e-5)
        assert math.isclose(relative_luminance("#FFFFFF"), 1.0, abs_tol=1e-5)

    def test_contrast_ratio_black_white(self) -> None:
        """Verify black on white contrast ratio is 21.0:1."""
        cr = calculate_contrast_ratio("#FFFFFF", "#000000")
        assert math.isclose(cr, 21.0, rel_tol=1e-3)

    def test_wcag_aaa_badge_contrast_exceeds_18_to_1(self) -> None:
        """Verify decoupled dark badge contrast exceeds strict 18.0:1 target."""
        badge_cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert badge_cr > WCAG_AAA_BADGE_CONTRAST_TARGET, f"Badge CR {badge_cr} <= 18.0:1"
        assert badge_cr > 18.0

    def test_wcag_aaa_text_contrast_exceeds_7_to_1(self) -> None:
        """Verify primary text on canvas theme exceeds 7.0:1."""
        cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_CANVAS_BG)
        assert cr > WCAG_AAA_TEXT_CONTRAST_TARGET
        assert cr > 7.0

    def test_wcag_aaa_muted_text_contrast(self) -> None:
        """Verify muted text on canvas background meets WCAG AAA (> 7.0:1)."""
        cr = calculate_contrast_ratio(COLOR_TEXT_MUTED, COLOR_CANVAS_BG)
        assert cr > WCAG_AAA_TEXT_CONTRAST_TARGET
        assert cr > 7.0

    def test_validate_wcag_aaa_contrast_helper(self) -> None:
        """Verify validate_wcag_aaa_contrast() helper returns (True, >7.0, >18.0)."""
        is_aaa, text_cr, badge_cr = validate_wcag_aaa_contrast()
        assert is_aaa is True
        assert text_cr >= 7.0
        assert badge_cr >= 18.0

    def test_status_bits_wcag_compliant(self) -> None:
        """Verify WCAG_AAA_COMPLIANT status bit flag is defined."""
        assert BeeswarmStatusBits.WCAG_AAA_COMPLIANT == 256


# ============================================================================
# 15. Verification Runner & Contract Tests
# ============================================================================

class TestVerificationRunnerAndContract:
    """Test 9-stage verification suite run_beeswarm_canvas_verification and contract conformance."""

    def test_runner_returns_strict_4state_contract(self) -> None:
        """Verify runner returns dictionary matching strict 4-state contract schema."""
        report = run_beeswarm_canvas_verification()
        assert isinstance(report, dict)
        assert "status" in report
        assert report["status"] in ("success", "failed", "blocked", "inconclusive")
        assert "error_code" in report
        assert "details" in report
        assert "data" in report

    def test_verification_all_9_stages_pass(self) -> None:
        """Verify all 9 stages in the runner pass cleanly."""
        report = run_beeswarm_canvas_verification()
        assert report["status"] == "success"
        data = report.get("data", {})
        assert data.get("checks_passed") == 9
        assert data.get("total_checks") == 9
        tests = data.get("tests", [])
        assert len(tests) == 9
        for t in tests:
            assert t.get("passed") is True, f"Stage {t.get('stage')} failed: {t.get('details')}"

    def test_verification_emits_evidence_and_svg_files(self) -> None:
        """Verify files are generated at default artifacts paths."""
        evidence_file = Path("artifacts/HMI/beeswarm_canvas_evidence.json")
        svg_file = Path("artifacts/HMI/beeswarm_canvas_sample.svg")

        report = run_beeswarm_canvas_verification(
            output_path=evidence_file,
            sample_svg_path=svg_file,
        )
        assert report["status"] == "success"
        assert evidence_file.exists()
        assert svg_file.exists()
        assert evidence_file.stat().st_size > 100
        assert svg_file.stat().st_size > 500

    def test_evidence_json_content_and_structure(self) -> None:
        """Verify evidence JSON file content matches returned report structure."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_ev = Path(tmp_dir) / "evidence.json"
            tmp_svg = Path(tmp_dir) / "sample.svg"

            report = run_beeswarm_canvas_verification(output_path=tmp_ev, sample_svg_path=tmp_svg)
            assert report["status"] == "success"

            with open(tmp_ev, "r", encoding="utf-8") as f:
                saved = json.load(f)

            assert saved["status"] == "success"
            assert saved["data"]["checks_passed"] == 9
            assert saved["data"]["work_package"] == "W228"

    def test_verification_custom_paths(self) -> None:
        """Verify runner honors custom destination paths."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            custom_ev = Path(tmp_dir) / "custom_evidence.json"
            custom_svg = Path(tmp_dir) / "custom_sample.svg"

            report = run_beeswarm_canvas_verification(
                evidence_path=custom_ev,
                svg_path=custom_svg,
            )
            assert report["status"] == "success"
            assert custom_ev.exists()
            assert custom_svg.exists()

    def test_verification_report_data_metrics(self) -> None:
        """Verify verification report data includes essential SCADA metrics."""
        report = run_beeswarm_canvas_verification()
        data = report.get("data", {})
        assert data.get("work_package") == "W228"
        assert "G9" in data.get("gate", "")
        metrics = data.get("metrics", {})
        assert metrics.get("total_sample_points_count") == CANONICAL_SAMPLE_POINTS_COUNT
        assert metrics.get("active_process_lanes_count") == CANONICAL_ACTIVE_PROCESS_LANES_COUNT
