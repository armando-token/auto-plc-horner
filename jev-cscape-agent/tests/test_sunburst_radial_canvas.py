"""Comprehensive unit test suite for Cscape HMI Dynamic Sunburst Hierarchical Radial Partition SCADA Canvas (W231).

Work Package: W231 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Sunburst Hierarchical Radial Partition SCADA Canvas]

Architectural Coverage (110+ Unit Tests across 13 Test Classes):
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit equality (& 0xFFFF), hashing, enums, status flags.
2. TestNodeDataclassAndHierarchyTree: SunburstRadialNode initialization, properties, health state computation, tree indexing and traversal.
3. TestRadialArcGeometryAndPolarMapping: Polar-to-Cartesian coordinate mapping, annular arc synthesis, layout geometry boundaries.
4. TestWeightConservationAndAngleBounding: Angular weight conservation (2*pi coverage), child angle containment, non-overlapping sectors.
5. TestHealthAggregationAndCriticalAlarm: Bottom-up health score aggregation, warning node detection, critical fault alarm (%M449).
6. TestSVGGenerationAndXMLSyntax: Standalone W3C SVG 1.1 vector graphic generation, ElementTree XML validation, filter defs, HUD card.
7. TestWCAG21AAAContrastAndVisualLegibility: WCAG 2.1 AAA relative luminance, contrast formulas, badge contrast > 18:1, text > 7:1.
8. TestDiagnosticFaultConditionsAndRecovery: 0xF301 singularity, 0xF302 empty tree, 0xF303 weight mismatch, 0xF304 canvas overflow, reset nominal.
9. TestHornerOCSSynchronizationAndRegisters: RegisterTable memory sync (%R1920..%R1927, %M448..%M449), PrivilegeMode.SYSTEM enforcement.
10. TestPureSTAndSecurity: Pure IEC 61131-3 Structured Text (ST) POU grammar, symbol bindings, AST validation.
11. TestAntiLadderRejection: Comprehensive fail-closed interception of contacts, coils, rungs, networks, mnemonics.
12. TestILogicUnitCompliance: Discrete cyclic scan engine (scan_step, step, execute, reset), 100-cycle soak stability.
13. TestVerificationRunnerAndContract: Deterministic 9-stage verification runner, JSON evidence export, strict 4-state engineering contract.
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

from jev_cscape.hmi.sunburst_radial_canvas import (
    CANONICAL_CRITICAL_ALARMS,
    CANONICAL_MAX_DEPTH,
    CANONICAL_OUTER_RADIUS_PX,
    CANONICAL_OVERALL_HEALTH_PCT,
    CANONICAL_OVERALL_HEALTH_SCALED,
    CANONICAL_TOTAL_SECTORS,
    CANONICAL_WARNING_NODES,
    CANVAS_CENTER_X,
    CANVAS_CENTER_Y,
    CANVAS_OVERFLOW_FAULT,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    CENTER_X,
    CENTER_Y,
    COIL_CANVAS_ACTIVE,
    COIL_CRITICAL_ALARM,
    COIL_CRITICAL_NODE_ALARM_ACTIVE,
    COIL_HEALTH_CRITICAL_ALARM,
    COIL_PLANT_HEALTH_CRITICAL_ALARM_ACTIVE,
    COIL_RADIAL_CANVAS_ACTIVE,
    COIL_SUNBURST_CANVAS_ACTIVE,
    COIL_SUNBURST_RADIAL_CANVAS_ACTIVE,
    COIL_W231_ALARM_ACTIVE,
    COIL_W231_CANVAS_ACTIVE,
    COIL_W231_CRITICAL_ALARM,
    COLOR_AMBER,
    COLOR_BORDER,
    COLOR_CRITICAL,
    COLOR_DARK_THEME_BACKING,
    COLOR_DECOUPLED_BADGE,
    COLOR_EMERALD,
    COLOR_FOCUS_CYAN,
    COLOR_GRID_LINE,
    COLOR_INACTIVE,
    COLOR_NORMAL,
    COLOR_PANEL_BG,
    COLOR_RUBY,
    COLOR_SLATE,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_WARNING,
    DIAG_ERR_EMPTY_HIERARCHY_TREE_ERROR,
    DIAG_ERR_EMPTY_TREE,
    DIAG_ERR_GEOMETRY_SINGULARITY,
    DIAG_ERR_HIERARCHICAL_WEIGHT_SUM_MISMATCH,
    DIAG_ERR_RADIAL_GEOMETRY_SINGULARITY,
    DIAG_ERR_RENDER_CANVAS_OVERFLOW,
    DIAG_EVENT_OK,
    DIAG_OK,
    DiagnosticCode,
    EMPTY_HIERARCHY_TREE_ERROR,
    EMPTY_TREE_FAULT,
    EmptyHierarchyTreeError,
    GEOMETRY_SINGULARITY_FAULT,
    HEALTH_COLORS,
    HEALTH_CRITICAL_THRESHOLD,
    HEALTH_WARNING_THRESHOLD,
    HIERARCHICAL_WEIGHT_SUM_MISMATCH,
    HealthState,
    HierarchicalWeightSumMismatchError,
    INNER_RADIUS_PX,
    MAX_CANVAS_RADIUS_PX,
    NodeHealthState,
    OUTER_RADIUS_PX,
    PLANT_HEALTH_ALARM_THRESHOLD_PCT,
    RADIAL_GEOMETRY_SINGULARITY,
    RADIAL_SINGULARITY_FAULT,
    REG_ACTIVE_SECTOR_INDEX,
    REG_CRITICAL_ALARMS_COUNT,
    REG_CRITICAL_NODE_ALARM_COUNT,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_DIAG_CODE,
    REG_HIERARCHY_TIER_DEPTH,
    REG_MAX_DEPTH_TIERS,
    REG_MAX_HIERARCHY_DEPTH_TIERS,
    REG_MIN_HEALTH_SCORE_SCALED,
    REG_OUTER_RADIUS_PX,
    REG_OUTER_RING_RADIUS_PX,
    REG_OVERALL_HEALTH_SCALED,
    REG_PLANT_OVERALL_HEALTH_INDEX_PCT_SCALED,
    REG_ROOT_AGGREGATE_HEALTH_SCALED,
    REG_SELECTED_SECTOR_HEALTH_SCALED,
    REG_SELECTED_SECTOR_INDEX,
    REG_TOTAL_HIERARCHY_NODES_COUNT,
    REG_TOTAL_NODES_COUNT,
    REG_TOTAL_SECTOR_COUNT,
    REG_W231_CRITICAL_ALARMS,
    REG_W231_CRITICAL_COUNT,
    REG_W231_DIAGNOSTIC_CODE,
    REG_W231_DIAG_CODE,
    REG_W231_HEALTH_SCALED,
    REG_W231_MAX_DEPTH,
    REG_W231_MIN_HEALTH,
    REG_W231_OUTER_RADIUS,
    REG_W231_ROOT_HEALTH,
    REG_W231_SELECTED_HEALTH,
    REG_W231_SELECTED_INDEX,
    REG_W231_SELECTED_SECTOR,
    REG_W231_TIER_DEPTH,
    REG_W231_TOTAL_NODES,
    REG_W231_TOTAL_SECTORS,
    REG_W231_WARNING_COUNT,
    REG_WARNING_NODES_COUNT,
    REG_WARNING_NODE_COUNT,
    RENDER_CANVAS_OVERFLOW,
    RadialGeometrySingularityError,
    RadialSector,
    RadialSectorNode,
    RadialStatusBits,
    RenderCanvasOverflowError,
    SUNBURST_OK,
    SUNBURST_RADIAL_CANVAS_PURE_ST_POU,
    SUNBURST_RADIAL_CANVAS_SYNC_PURE_ST_POU,
    SUNBURST_RADIAL_OK,
    SUNBURST_RADIAL_PURE_ST_POU,
    SVGRenderError,
    SunburstDiagnosticCode,
    SunburstMetrics,
    SunburstRadialCanvas,
    SunburstRadialCanvasEngine,
    SunburstRadialCanvasSync,
    SunburstRadialDiagnosticCode,
    SunburstRadialError,
    SunburstRadialHeatmapCanvas,
    SunburstRadialMetrics,
    SunburstRadialNode,
    SunburstRadialStatusBits,
    SunburstRadialTree,
    SunburstSector,
    TierLevel,
    W231_SUNBURST_RADIAL_PURE_ST_POU,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    WEIGHT_MISMATCH_FAULT,
    contrast_ratio,
    create_canonical_sunburst_radial_canvas,
    create_canonical_sunburst_radial_tree,
    create_canonical_sunburst_tree,
    create_mock_scan_context,
    format_annular_sector_arc,
    generate_annular_sector_path,
    generate_sector_path_for_node,
    generate_sunburst_canvas_svg,
    generate_sunburst_radial_canvas_svg,
    layout_sunburst_radial_tree,
    polar_to_cartesian,
    relative_luminance,
    run_sunburst_radial_canvas_verification,
    validate_wcag_aaa_contrast,
    verify_sunburst_radial_canvas_pure_st,
)


# ============================================================================
# Section 1: Constants, Enums, and Diagnostic Codes
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate 16-bit diagnostic codes, signed/unsigned masking, enums, registers, and coils."""

    def test_diagnostic_code_ok_equality(self) -> None:
        """DIAG_EVENT_OK is 0x0000 and equals 0 integer."""
        assert DIAG_EVENT_OK == 0
        assert DIAG_EVENT_OK == 0x0000
        assert DIAG_OK == DIAG_EVENT_OK
        assert SUNBURST_RADIAL_OK == DIAG_EVENT_OK
        assert SUNBURST_OK == DIAG_EVENT_OK
        assert int(DIAG_EVENT_OK) == 0

    @pytest.mark.parametrize(
        "code_const,uint_val,sint_val",
        [
            (DIAG_ERR_RADIAL_GEOMETRY_SINGULARITY, 0xF301, 0xF301 - 0x10000),
            (DIAG_ERR_EMPTY_HIERARCHY_TREE_ERROR, 0xF302, 0xF302 - 0x10000),
            (DIAG_ERR_HIERARCHICAL_WEIGHT_SUM_MISMATCH, 0xF303, 0xF303 - 0x10000),
            (DIAG_ERR_RENDER_CANVAS_OVERFLOW, 0xF304, 0xF304 - 0x10000),
        ],
    )
    def test_diagnostic_code_signed_unsigned_equality(
        self, code_const: DiagnosticCode, uint_val: int, sint_val: int
    ) -> None:
        """DiagnosticCode supports unsigned uint16 and signed int16 equality via & 0xFFFF."""
        assert code_const == uint_val
        assert code_const == sint_val
        assert (code_const & 0xFFFF) == uint_val
        assert int(code_const) == uint_val

    def test_diagnostic_code_hash_and_uniqueness(self) -> None:
        """DiagnosticCode hashes conform to 16-bit integer masking and ensure set uniqueness."""
        codes = {
            DIAG_EVENT_OK,
            DIAG_ERR_RADIAL_GEOMETRY_SINGULARITY,
            DIAG_ERR_EMPTY_HIERARCHY_TREE_ERROR,
            DIAG_ERR_HIERARCHICAL_WEIGHT_SUM_MISMATCH,
            DIAG_ERR_RENDER_CANVAS_OVERFLOW,
        }
        assert len(codes) == 5
        assert hash(DiagnosticCode(0xF301)) == hash(0xF301)

    def test_diagnostic_code_aliases(self) -> None:
        """Aliases for diagnostic codes point to canonical constants."""
        assert RADIAL_GEOMETRY_SINGULARITY == DIAG_ERR_RADIAL_GEOMETRY_SINGULARITY
        assert RADIAL_SINGULARITY_FAULT == DIAG_ERR_RADIAL_GEOMETRY_SINGULARITY
        assert DIAG_ERR_GEOMETRY_SINGULARITY == DIAG_ERR_RADIAL_GEOMETRY_SINGULARITY
        assert GEOMETRY_SINGULARITY_FAULT == DIAG_ERR_RADIAL_GEOMETRY_SINGULARITY

        assert EMPTY_HIERARCHY_TREE_ERROR == DIAG_ERR_EMPTY_HIERARCHY_TREE_ERROR
        assert EMPTY_TREE_FAULT == DIAG_ERR_EMPTY_HIERARCHY_TREE_ERROR
        assert DIAG_ERR_EMPTY_TREE == DIAG_ERR_EMPTY_HIERARCHY_TREE_ERROR

        assert HIERARCHICAL_WEIGHT_SUM_MISMATCH == DIAG_ERR_HIERARCHICAL_WEIGHT_SUM_MISMATCH
        assert WEIGHT_MISMATCH_FAULT == DIAG_ERR_HIERARCHICAL_WEIGHT_SUM_MISMATCH

        assert RENDER_CANVAS_OVERFLOW == DIAG_ERR_RENDER_CANVAS_OVERFLOW
        assert CANVAS_OVERFLOW_FAULT == DIAG_ERR_RENDER_CANVAS_OVERFLOW

        assert SunburstRadialDiagnosticCode is DiagnosticCode
        assert SunburstDiagnosticCode is DiagnosticCode

    def test_horner_word_registers_constants(self) -> None:
        """Horner OCS word registers span %R1920..%R1927 with expected string bindings."""
        assert REG_TOTAL_HIERARCHY_NODES_COUNT == "%R1920"
        assert REG_PLANT_OVERALL_HEALTH_INDEX_PCT_SCALED == "%R1921"
        assert REG_CRITICAL_NODE_ALARM_COUNT == "%R1922"
        assert REG_WARNING_NODE_COUNT == "%R1923"
        assert REG_MAX_HIERARCHY_DEPTH_TIERS == "%R1924"
        assert REG_SELECTED_SECTOR_INDEX == "%R1925"
        assert REG_OUTER_RING_RADIUS_PX == "%R1926"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R1927"

    def test_horner_register_aliases(self) -> None:
        """Horner register aliases match canonical register addresses."""
        assert REG_TOTAL_NODES_COUNT == "%R1920"
        assert REG_TOTAL_SECTOR_COUNT == "%R1920"
        assert REG_W231_TOTAL_NODES == "%R1920"
        assert REG_W231_TOTAL_SECTORS == "%R1920"

        assert REG_OVERALL_HEALTH_SCALED == "%R1921"
        assert REG_ROOT_AGGREGATE_HEALTH_SCALED == "%R1921"
        assert REG_W231_HEALTH_SCALED == "%R1921"
        assert REG_W231_ROOT_HEALTH == "%R1921"

        assert REG_CRITICAL_ALARMS_COUNT == "%R1922"
        assert REG_W231_CRITICAL_COUNT == "%R1922"
        assert REG_W231_CRITICAL_ALARMS == "%R1922"

        assert REG_WARNING_NODES_COUNT == "%R1923"
        assert REG_W231_WARNING_COUNT == "%R1923"

        assert REG_MAX_DEPTH_TIERS == "%R1924"
        assert REG_HIERARCHY_TIER_DEPTH == "%R1924"
        assert REG_W231_MAX_DEPTH == "%R1924"
        assert REG_W231_TIER_DEPTH == "%R1924"

        assert REG_ACTIVE_SECTOR_INDEX == "%R1925"
        assert REG_W231_SELECTED_SECTOR == "%R1925"
        assert REG_W231_SELECTED_INDEX == "%R1925"

        assert REG_OUTER_RADIUS_PX == "%R1926"
        assert REG_W231_OUTER_RADIUS == "%R1926"

        assert REG_DIAG_CODE == "%R1927"
        assert REG_W231_DIAGNOSTIC_CODE == "%R1927"
        assert REG_W231_DIAG_CODE == "%R1927"

    def test_horner_discrete_coils_constants(self) -> None:
        """Horner OCS discrete coils bind to %M448 and %M449 with aliases."""
        assert COIL_SUNBURST_CANVAS_ACTIVE == "%M448"
        assert COIL_PLANT_HEALTH_CRITICAL_ALARM_ACTIVE == "%M449"

        assert COIL_CANVAS_ACTIVE == "%M448"
        assert COIL_RADIAL_CANVAS_ACTIVE == "%M448"
        assert COIL_SUNBURST_RADIAL_CANVAS_ACTIVE == "%M448"
        assert COIL_W231_CANVAS_ACTIVE == "%M448"

        assert COIL_CRITICAL_ALARM == "%M449"
        assert COIL_HEALTH_CRITICAL_ALARM == "%M449"
        assert COIL_CRITICAL_NODE_ALARM_ACTIVE == "%M449"
        assert COIL_W231_ALARM_ACTIVE == "%M449"
        assert COIL_W231_CRITICAL_ALARM == "%M449"

    def test_tier_level_enum_values(self) -> None:
        """TierLevel enum spans 5 concentric tiers from ROOT_PLANT (0) to INSTRUMENTATION_SAFETY (4)."""
        assert TierLevel.ROOT_PLANT.value == 0
        assert TierLevel.PROCESS_AREA.value == 1
        assert TierLevel.UNIT_OPERATION.value == 2
        assert TierLevel.EQUIPMENT_SUBSYSTEM.value == 3
        assert TierLevel.INSTRUMENTATION_SAFETY.value == 4
        assert len(TierLevel) == 5

    def test_health_state_enum_and_colors(self) -> None:
        """HealthState enum and HEALTH_COLORS map correctly to industrial palette."""
        assert HealthState.NORMAL.value == "NORMAL"
        assert HealthState.WARNING.value == "WARNING"
        assert HealthState.CRITICAL.value == "CRITICAL"
        assert HealthState.INACTIVE.value == "INACTIVE"
        assert NodeHealthState is HealthState

        assert HEALTH_COLORS[HealthState.NORMAL] == COLOR_NORMAL
        assert HEALTH_COLORS[HealthState.WARNING] == COLOR_WARNING
        assert HEALTH_COLORS[HealthState.CRITICAL] == COLOR_CRITICAL
        assert HEALTH_COLORS[HealthState.INACTIVE] == COLOR_INACTIVE

        assert COLOR_NORMAL == "#10B981"
        assert COLOR_WARNING == "#F59E0B"
        assert COLOR_CRITICAL == "#EF4444"
        assert COLOR_INACTIVE == "#6B7280"

        assert COLOR_EMERALD == COLOR_NORMAL
        assert COLOR_AMBER == COLOR_WARNING
        assert COLOR_RUBY == COLOR_CRITICAL
        assert COLOR_SLATE == COLOR_INACTIVE

    def test_sunburst_radial_status_bits_values(self) -> None:
        """SunburstRadialStatusBits bitmask defines discrete bit flags."""
        assert SunburstRadialStatusBits.CANVAS_ACTIVE.value == 0x0001
        assert SunburstRadialStatusBits.HIERARCHY_VALID.value == 0x0002
        assert SunburstRadialStatusBits.GEOMETRY_COMPUTED.value == 0x0004
        assert SunburstRadialStatusBits.CRITICAL_ALARM_ACTIVE.value == 0x0008
        assert SunburstRadialStatusBits.WARNING_ACTIVE.value == 0x0010
        assert SunburstRadialStatusBits.RADIAL_SINGULARITY_FAULT.value == 0x0020
        assert SunburstRadialStatusBits.EMPTY_TREE_FAULT.value == 0x0040
        assert SunburstRadialStatusBits.WEIGHT_MISMATCH_FAULT.value == 0x0080
        assert SunburstRadialStatusBits.CANVAS_OVERFLOW_FAULT.value == 0x0100
        assert SunburstRadialStatusBits.WCAG_AAA_VERIFIED.value == 0x0200
        assert SunburstRadialStatusBits.SVG_RENDER_VALID.value == 0x0400
        assert SunburstRadialStatusBits.NOMINAL_OPERATION.value == 0x0800
        assert RadialStatusBits is SunburstRadialStatusBits

    def test_canvas_geometry_constants(self) -> None:
        """Canvas viewport and radial geometry constants match specification."""
        assert CANVAS_VIEWPORT_WIDTH == 1200
        assert CANVAS_VIEWPORT_HEIGHT == 750
        assert CENTER_X == 500.0
        assert CENTER_Y == 375.0
        assert CANVAS_CENTER_X == CENTER_X
        assert CANVAS_CENTER_Y == CENTER_Y
        assert INNER_RADIUS_PX == 60.0
        assert OUTER_RADIUS_PX == 320.0
        assert MAX_CANVAS_RADIUS_PX == 375.0

    def test_canonical_dimensions_and_thresholds(self) -> None:
        """Canonical dimensions and health thresholds are correctly configured."""
        assert CANONICAL_TOTAL_SECTORS == 61
        assert CANONICAL_MAX_DEPTH == 5
        assert CANONICAL_OVERALL_HEALTH_SCALED == 9850
        assert CANONICAL_OVERALL_HEALTH_PCT == 98.50
        assert CANONICAL_CRITICAL_ALARMS == 0
        assert CANONICAL_WARNING_NODES == 2
        assert CANONICAL_OUTER_RADIUS_PX == 320

        assert HEALTH_CRITICAL_THRESHOLD == 70.0
        assert HEALTH_WARNING_THRESHOLD == 85.0
        assert PLANT_HEALTH_ALARM_THRESHOLD_PCT == 80.0

    def test_dark_theme_colors(self) -> None:
        """Dark theme palette conforms to industrial SCADA aesthetic."""
        assert COLOR_DARK_THEME_BACKING == "#0B0F19"
        assert COLOR_PANEL_BG == "#161B22"
        assert COLOR_BORDER == "#21262D"
        assert COLOR_DECOUPLED_BADGE == "#050811"
        assert COLOR_TEXT_PRIMARY == "#FFFFFF"
        assert COLOR_TEXT_MUTED == "#8B949E"
        assert COLOR_FOCUS_CYAN == "#38BDF8"
        assert COLOR_GRID_LINE == "#1F2937"

    def test_wcag_targets_constants(self) -> None:
        """WCAG 2.1 AAA target constants match accessibility thresholds."""
        assert WCAG_AAA_BADGE_CONTRAST_TARGET == 18.0
        assert WCAG_AAA_TEXT_CONTRAST_TARGET == 7.0
        assert WCAG_GRAPHICAL_CONTRAST_TARGET == 3.0


# ============================================================================
# Section 2: Node Dataclass & Hierarchy Tree Structure
# ============================================================================

class TestNodeDataclassAndHierarchyTree:
    """Validate SunburstRadialNode, tree containers, depth calculations, and traversals."""

    def test_node_initialization_and_properties(self) -> None:
        """SunburstRadialNode initializes with default and provided properties."""
        node = SunburstRadialNode(
            id="NODE_TEST",
            index=10,
            name="Test Equipment Node",
            tier=2,
            parent_id="PARENT_TEST",
            health_score=92.5,
            weight=2.0,
            r_inner=100.0,
            r_outer=180.0,
            theta_start_rad=0.0,
            theta_end_rad=math.pi / 2,
        )
        assert node.node_id == "NODE_TEST"
        assert node.index == 10
        assert node.name == "Test Equipment Node"
        assert node.tier == 2
        assert node.parent_id == "PARENT_TEST"
        assert math.isclose(node.angular_span_rad, math.pi / 2, rel_tol=1e-5)
        assert math.isclose(node.angular_span_deg, 90.0, rel_tol=1e-5)
        assert node.is_leaf is True
        assert node.health_state == HealthState.NORMAL
        assert node.color == COLOR_NORMAL

    def test_node_aliases(self) -> None:
        """RadialSectorNode, RadialSector, and SunburstSector are aliases of SunburstRadialNode."""
        assert RadialSectorNode is SunburstRadialNode
        assert RadialSector is SunburstRadialNode
        assert SunburstSector is SunburstRadialNode

    def test_node_health_state_transitions(self) -> None:
        """Node correctly evaluates HealthState based on health_score and is_active flag."""
        node = SunburstRadialNode(id="N1", index=1, name="N1", tier=1, health_score=95.0)
        assert node.health_state == HealthState.NORMAL

        node.health_score = 84.9
        assert node.health_state == HealthState.WARNING
        assert node.color == COLOR_WARNING

        node.health_score = 69.9
        assert node.health_state == HealthState.CRITICAL
        assert node.color == COLOR_CRITICAL

        node.is_active = False
        assert node.health_state == HealthState.INACTIVE
        assert node.color == COLOR_INACTIVE

    def test_node_get_all_nodes_and_leaves(self) -> None:
        """get_all_nodes() and get_leaves() recursively traverse descendant hierarchy."""
        root = SunburstRadialNode(id="ROOT", index=0, name="Root", tier=0)
        c1 = SunburstRadialNode(id="C1", index=1, name="C1", tier=1, parent_id="ROOT")
        c2 = SunburstRadialNode(id="C2", index=2, name="C2", tier=1, parent_id="ROOT")
        gc1 = SunburstRadialNode(id="GC1", index=3, name="GC1", tier=2, parent_id="C1")
        c1.children.append(gc1)
        root.children.extend([c1, c2])

        all_nodes = root.get_all_nodes()
        assert len(all_nodes) == 4
        assert [n.id for n in all_nodes] == ["ROOT", "C1", "GC1", "C2"]

        leaves = root.get_leaves()
        assert len(leaves) == 2
        assert [l.id for l in leaves] == ["GC1", "C2"]

    def test_node_max_depth_calculation(self) -> None:
        """max_depth() correctly computes maximum tree depth from current node."""
        root = SunburstRadialNode(id="ROOT", index=0, name="Root", tier=0)
        assert root.max_depth() == 1

        c1 = SunburstRadialNode(id="C1", index=1, name="C1", tier=1, parent_id="ROOT")
        gc1 = SunburstRadialNode(id="GC1", index=2, name="GC1", tier=2, parent_id="C1")
        c1.children.append(gc1)
        root.children.append(c1)
        assert root.max_depth() == 3

    def test_canonical_tree_total_node_population(self) -> None:
        """Canonical hierarchy tree contains exactly 61 nodes."""
        tree = create_canonical_sunburst_radial_tree()
        assert tree.total_nodes == 61
        assert len(tree.get_all_nodes()) == 61

    def test_canonical_tree_tier_distribution(self) -> None:
        """Canonical hierarchy spans 5 tiers: Tier 0 (1), Tier 1 (4), Tier 2 (8), Tier 3 (16), Tier 4 (32)."""
        tree = create_canonical_sunburst_radial_tree()
        tier_counts: Dict[int, int] = {i: 0 for i in range(5)}
        for node in tree.get_all_nodes():
            tier_counts[node.tier] += 1

        assert tier_counts[0] == 1
        assert tier_counts[1] == 4
        assert tier_counts[2] == 8
        assert tier_counts[3] == 16
        assert tier_counts[4] == 32
        assert tree.max_depth == 5

    def test_canonical_tree_leaf_count(self) -> None:
        """Canonical hierarchy tree contains exactly 32 leaf instrumentation/safety nodes."""
        tree = create_canonical_sunburst_radial_tree()
        leaves = tree.get_leaves()
        assert len(leaves) == 32
        assert all(l.tier == 4 for l in leaves)

    def test_tree_indexing_by_id_and_index(self) -> None:
        """SunburstRadialTree get_node and get_node_by_index return valid nodes across 0..60."""
        tree = create_canonical_sunburst_radial_tree()
        root = tree.get_node("ROOT_PLANT")
        assert root is not None
        assert root.index == 0

        for i in range(61):
            node = tree.get_node_by_index(i)
            assert node is not None
            assert node.index == i

        assert tree.get_node("NON_EXISTENT") is None
        assert tree.get_node_by_index(999) is None

    def test_tree_traverse_bfs(self) -> None:
        """traverse_bfs() traverses tree in breadth-first level order starting with root."""
        tree = create_canonical_sunburst_radial_tree()
        bfs_nodes = tree.traverse_bfs()
        assert len(bfs_nodes) == 61
        assert bfs_nodes[0].id == "ROOT_PLANT"
        tiers = [n.tier for n in bfs_nodes]
        assert tiers[0:1] == [0]
        assert tiers[1:5] == [1, 1, 1, 1]
        assert tiers[5:13] == [2] * 8
        assert tiers[13:29] == [3] * 16
        assert tiers[29:61] == [4] * 32

    def test_tree_traverse_dfs_postorder(self) -> None:
        """traverse_dfs_postorder() visits all children before their parent, ending with root."""
        tree = create_canonical_sunburst_radial_tree()
        dfs_nodes = tree.traverse_dfs_postorder()
        assert len(dfs_nodes) == 61
        assert dfs_nodes[-1].id == "ROOT_PLANT"

    def test_empty_tree_container_behavior(self) -> None:
        """SunburstRadialTree with no root handles operations gracefully."""
        tree = SunburstRadialTree(root=None)
        assert tree.total_nodes == 0
        assert tree.max_depth == 0
        assert tree.get_all_nodes() == []
        assert tree.get_leaves() == []
        assert tree.traverse_bfs() == []
        assert tree.traverse_dfs_postorder() == []
        h, c, w = tree.recompute_overall_health()
        assert h == 0.0 and c == 0 and w == 0


# ============================================================================
# Section 3: Radial Arc Geometry & Polar Coordinate Mapping
# ============================================================================

class TestRadialArcGeometryAndPolarMapping:
    """Validate polar-to-Cartesian conversion, SVG annular arc paths, and radius tiers."""

    def test_polar_to_cartesian_cardinal_points(self) -> None:
        """polar_to_cartesian correctly maps cardinal directions from (500, 375)."""
        cx, cy, r = 500.0, 375.0, 100.0
        # theta = 0 (Right, East)
        x0, y0 = polar_to_cartesian(cx, cy, r, 0.0)
        assert math.isclose(x0, 600.0, abs_tol=1e-4)
        assert math.isclose(y0, 375.0, abs_tol=1e-4)

        # theta = pi/2 (Down, South in SVG coordinates)
        x1, y1 = polar_to_cartesian(cx, cy, r, math.pi / 2)
        assert math.isclose(x1, 500.0, abs_tol=1e-4)
        assert math.isclose(y1, 475.0, abs_tol=1e-4)

        # theta = pi (Left, West)
        x2, y2 = polar_to_cartesian(cx, cy, r, math.pi)
        assert math.isclose(x2, 400.0, abs_tol=1e-4)
        assert math.isclose(y2, 375.0, abs_tol=1e-4)

        # theta = 3*pi/2 (Up, North)
        x3, y3 = polar_to_cartesian(cx, cy, r, 3.0 * math.pi / 2)
        assert math.isclose(x3, 500.0, abs_tol=1e-4)
        assert math.isclose(y3, 275.0, abs_tol=1e-4)

    def test_generate_annular_sector_path_format(self) -> None:
        """generate_annular_sector_path produces valid SVG path syntax 'M ... A ... L ... A ... Z'."""
        path_str = generate_annular_sector_path(
            r_inner=60.0,
            r_outer=125.0,
            theta_start=0.0,
            theta_end=math.pi / 2,
            cx=500.0,
            cy=375.0,
        )
        assert path_str.startswith("M ")
        assert " A " in path_str
        assert " L " in path_str
        assert path_str.endswith(" Z")
        assert format_annular_sector_arc(60.0, 125.0, 0.0, math.pi / 2, 500.0, 375.0) == path_str

    def test_annular_sector_path_large_arc_flag(self) -> None:
        """large_arc flag is 0 for span <= pi and 1 for span > pi."""
        path_small = generate_annular_sector_path(60.0, 125.0, 0.0, math.pi / 2)
        assert " 0 0 1 " in path_small or " 0 0 0 " in path_small

        path_large = generate_annular_sector_path(60.0, 125.0, 0.0, 3.0 * math.pi / 2)
        assert " 0 1 1 " in path_large

    def test_annular_sector_path_invalid_radii_raises(self) -> None:
        """Invalid radii (r_inner >= r_outer or r_inner < 0) raises RadialGeometrySingularityError."""
        with pytest.raises(RadialGeometrySingularityError):
            generate_annular_sector_path(r_inner=100.0, r_outer=50.0, theta_start=0.0, theta_end=1.0)
        with pytest.raises(RadialGeometrySingularityError):
            generate_annular_sector_path(r_inner=100.0, r_outer=100.0, theta_start=0.0, theta_end=1.0)
        with pytest.raises(RadialGeometrySingularityError):
            generate_annular_sector_path(r_inner=-10.0, r_outer=50.0, theta_start=0.0, theta_end=1.0)

    def test_annular_sector_path_invalid_angles_raises(self) -> None:
        """Invalid angles (theta_end <= theta_start) raises RadialGeometrySingularityError."""
        with pytest.raises(RadialGeometrySingularityError):
            generate_annular_sector_path(r_inner=50.0, r_outer=100.0, theta_start=2.0, theta_end=1.0)
        with pytest.raises(RadialGeometrySingularityError):
            generate_annular_sector_path(r_inner=50.0, r_outer=100.0, theta_start=1.0, theta_end=1.0)

    def test_generate_sector_path_for_node_tier0_disc(self) -> None:
        """generate_sector_path_for_node for Tier 0 root node returns full circular disc path."""
        tree = create_canonical_sunburst_radial_tree()
        root = tree.root
        assert root is not None
        disc_path = generate_sector_path_for_node(root)
        assert disc_path.startswith("M ")
        assert " 0 1 1 " in disc_path
        assert disc_path.endswith(" Z")

    def test_generate_sector_path_for_node_tiers_1_to_4(self) -> None:
        """generate_sector_path_for_node for Tiers 1..4 returns annular arc paths."""
        tree = create_canonical_sunburst_radial_tree()
        for node in tree.get_all_nodes():
            if node.tier > 0:
                p = generate_sector_path_for_node(node)
                assert p.startswith("M ")
                assert " A " in p
                assert " L " in p
                assert p.endswith(" Z")

    def test_layout_radial_boundaries_per_tier(self) -> None:
        """Concentric tiers have deterministic radii across 5 tiers: 0..60, 60..125, 125..190, 190..255, 255..320."""
        tree = create_canonical_sunburst_radial_tree()
        root = tree.root
        assert root is not None
        assert root.r_inner == 0.0
        assert root.r_outer == 60.0

        for n in tree.get_all_nodes():
            if n.tier == 1:
                assert math.isclose(n.r_inner, 60.0, abs_tol=1e-4)
                assert math.isclose(n.r_outer, 125.0, abs_tol=1e-4)
            elif n.tier == 2:
                assert math.isclose(n.r_inner, 125.0, abs_tol=1e-4)
                assert math.isclose(n.r_outer, 190.0, abs_tol=1e-4)
            elif n.tier == 3:
                assert math.isclose(n.r_inner, 190.0, abs_tol=1e-4)
                assert math.isclose(n.r_outer, 255.0, abs_tol=1e-4)
            elif n.tier == 4:
                assert math.isclose(n.r_inner, 255.0, abs_tol=1e-4)
                assert math.isclose(n.r_outer, 320.0, abs_tol=1e-4)

    def test_layout_custom_start_angle(self) -> None:
        """layout_sunburst_radial_tree with custom start angle offsets all angles uniformly."""
        tree = create_canonical_sunburst_radial_tree()
        layout_sunburst_radial_tree(tree, start_angle_rad=math.pi / 4)
        root = tree.root
        assert root is not None
        assert math.isclose(root.theta_start_rad, math.pi / 4, abs_tol=1e-4)
        assert math.isclose(root.theta_end_rad, math.pi / 4 + 2.0 * math.pi, abs_tol=1e-4)
        assert math.isclose(root.children[0].theta_start_rad, math.pi / 4, abs_tol=1e-4)

    def test_layout_canvas_overflow_raises(self) -> None:
        """layout_sunburst_radial_tree raises RenderCanvasOverflowError when r_out > 375 px (0xF304)."""
        tree = create_canonical_sunburst_radial_tree()
        with pytest.raises(RenderCanvasOverflowError):
            layout_sunburst_radial_tree(tree, r_in=60.0, r_out=380.0)

    def test_layout_empty_tree_raises(self) -> None:
        """layout_sunburst_radial_tree raises EmptyHierarchyTreeError when tree has no nodes (0xF302)."""
        empty_tree = SunburstRadialTree(root=None)
        with pytest.raises(EmptyHierarchyTreeError):
            layout_sunburst_radial_tree(empty_tree)

    def test_layout_singularity_radii_raises(self) -> None:
        """layout_sunburst_radial_tree raises RadialGeometrySingularityError when r_in >= r_out (0xF301)."""
        tree = create_canonical_sunburst_radial_tree()
        with pytest.raises(RadialGeometrySingularityError):
            layout_sunburst_radial_tree(tree, r_in=320.0, r_out=60.0)
        with pytest.raises(RadialGeometrySingularityError):
            layout_sunburst_radial_tree(tree, r_in=200.0, r_out=200.0)


# ============================================================================
# Section 4: Weight Conservation & Child Angle Bounding
# ============================================================================

class TestWeightConservationAndAngleBounding:
    """Validate 2*pi angular coverage, tier-wise weight conservation, and child sector containment."""

    def test_tier1_angle_conservation(self) -> None:
        """Tier 1 process areas angular spans sum exactly to 2*pi radians (360 degrees)."""
        tree = create_canonical_sunburst_radial_tree()
        areas = [n for n in tree.get_all_nodes() if n.tier == 1]
        assert len(areas) == 4
        total_span = sum(a.angular_span_rad for a in areas)
        assert math.isclose(total_span, 2.0 * math.pi, rel_tol=1e-5)

    def test_tier2_angle_conservation(self) -> None:
        """Tier 2 unit operations angular spans sum exactly to 2*pi radians."""
        tree = create_canonical_sunburst_radial_tree()
        uops = [n for n in tree.get_all_nodes() if n.tier == 2]
        assert len(uops) == 8
        total_span = sum(u.angular_span_rad for u in uops)
        assert math.isclose(total_span, 2.0 * math.pi, rel_tol=1e-5)

    def test_tier3_angle_conservation(self) -> None:
        """Tier 3 equipment subsystems angular spans sum exactly to 2*pi radians."""
        tree = create_canonical_sunburst_radial_tree()
        eqs = [n for n in tree.get_all_nodes() if n.tier == 3]
        assert len(eqs) == 16
        total_span = sum(e.angular_span_rad for e in eqs)
        assert math.isclose(total_span, 2.0 * math.pi, rel_tol=1e-5)

    def test_tier4_angle_conservation(self) -> None:
        """Tier 4 instrumentation/safety nodes angular spans sum exactly to 2*pi radians."""
        tree = create_canonical_sunburst_radial_tree()
        insts = [n for n in tree.get_all_nodes() if n.tier == 4]
        assert len(insts) == 32
        total_span = sum(i.angular_span_rad for i in insts)
        assert math.isclose(total_span, 2.0 * math.pi, rel_tol=1e-5)

    def test_parent_child_angle_containment(self) -> None:
        """Every child sector's [theta_start, theta_end] is strictly contained in parent's span."""
        tree = create_canonical_sunburst_radial_tree()
        for node in tree.get_all_nodes():
            for child in node.children:
                assert child.theta_start_rad >= node.theta_start_rad - 1e-6
                assert child.theta_end_rad <= node.theta_end_rad + 1e-6
                assert child.theta_end_rad > child.theta_start_rad

    def test_sibling_sectors_non_overlapping_and_contiguous(self) -> None:
        """Sibling sectors are strictly contiguous without overlap: child[i+1].start == child[i].end."""
        tree = create_canonical_sunburst_radial_tree()
        for node in tree.get_all_nodes():
            if len(node.children) > 1:
                for i in range(len(node.children) - 1):
                    c_curr = node.children[i]
                    c_next = node.children[i + 1]
                    assert math.isclose(c_curr.theta_end_rad, c_next.theta_start_rad, abs_tol=1e-6)

    def test_equal_weight_partition_symmetry(self) -> None:
        """In canonical tree, 4 process areas with weight=1.0 partition 2*pi into exactly pi/2 (90 deg)."""
        tree = create_canonical_sunburst_radial_tree()
        areas = [n for n in tree.get_all_nodes() if n.tier == 1]
        for a in areas:
            assert math.isclose(a.angular_span_rad, math.pi / 2, abs_tol=1e-5)
            assert math.isclose(a.angular_span_deg, 90.0, abs_tol=1e-5)

    def test_non_uniform_weight_proportionality(self) -> None:
        """Non-uniform child weights result in proportional angle partition."""
        root = SunburstRadialNode(id="ROOT", index=0, name="Root", tier=0)
        c1 = SunburstRadialNode(id="C1", index=1, name="C1", tier=1, parent_id="ROOT", weight=1.0)
        c2 = SunburstRadialNode(id="C2", index=2, name="C2", tier=1, parent_id="ROOT", weight=3.0)
        root.children = [c1, c2]
        tree = SunburstRadialTree(root=root)
        layout_sunburst_radial_tree(tree)

        assert math.isclose(c1.angular_span_rad, math.pi / 2, abs_tol=1e-5)
        assert math.isclose(c2.angular_span_rad, 3.0 * math.pi / 2, abs_tol=1e-5)

    def test_zero_or_negative_weight_raises(self) -> None:
        """Zero or negative child total weight raises RadialGeometrySingularityError (0xF301)."""
        root = SunburstRadialNode(id="ROOT", index=0, name="Root", tier=0)
        c1 = SunburstRadialNode(id="C1", index=1, name="C1", tier=1, parent_id="ROOT", weight=0.0)
        root.children = [c1]
        tree = SunburstRadialTree(root=root)
        with pytest.raises(RadialGeometrySingularityError):
            layout_sunburst_radial_tree(tree)

    def test_negative_parent_angle_span_raises(self) -> None:
        """Invalid child angle span or negative weights raise RadialGeometrySingularityError (0xF301)."""
        root = SunburstRadialNode(id="ROOT", index=0, name="Root", tier=0)
        c1 = SunburstRadialNode(id="C1", index=1, name="C1", tier=1, parent_id="ROOT", weight=-1.0)
        c2 = SunburstRadialNode(id="C2", index=2, name="C2", tier=1, parent_id="ROOT", weight=2.0)
        root.children = [c1, c2]
        tree = SunburstRadialTree(root=root)
        with pytest.raises(RadialGeometrySingularityError):
            layout_sunburst_radial_tree(tree)
        with pytest.raises(RadialGeometrySingularityError):
            generate_annular_sector_path(60.0, 120.0, 5.0, 2.0)


# ============================================================================
# Section 5: Health Aggregation & Critical Node Alarms
# ============================================================================

class TestHealthAggregationAndCriticalAlarm:
    """Validate bottom-up health calculation, warning node detection, and %M449 critical alarm trip."""

    def test_canonical_health_aggregation_metrics(self) -> None:
        """Canonical tree health averages exactly 98.50% (scaled 9850), 2 warnings, 0 critical."""
        tree = create_canonical_sunburst_radial_tree()
        mean_health, crit_count, warn_count = tree.recompute_overall_health()
        assert mean_health == 98.50
        assert crit_count == 0
        assert warn_count == 2

    def test_canonical_warning_nodes_identification(self) -> None:
        """Canonical hierarchy contains exactly 2 warning nodes: 59 and 60 (75.00%)."""
        tree = create_canonical_sunburst_radial_tree()
        warn_nodes = [n for n in tree.get_all_nodes() if n.health_state == HealthState.WARNING]
        assert len(warn_nodes) == 2
        assert {n.index for n in warn_nodes} == {59, 60}
        assert all(n.health_score == 75.00 for n in warn_nodes)

    def test_nominal_canvas_critical_alarm_deasserted(self) -> None:
        """In canonical nominal state, %M449 is False and critical alarm bit is not set."""
        canvas = create_canonical_sunburst_radial_canvas()
        assert canvas.metrics.critical_alarm_active is False
        assert canvas.metrics.critical_node_count == 0
        assert canvas.reg_table.read_bit(COIL_PLANT_HEALTH_CRITICAL_ALARM_ACTIVE) is False
        assert not bool(canvas.status_bits & SunburstRadialStatusBits.CRITICAL_ALARM_ACTIVE)

    def test_trigger_critical_alarm_equipment_failure(self) -> None:
        """trigger_critical_alarm sets node health < 70% and trips %M449."""
        canvas = create_canonical_sunburst_radial_canvas()
        canvas.trigger_critical_alarm(bad_health=50.0)

        assert canvas.metrics.critical_node_count >= 1
        assert canvas.metrics.critical_alarm_active is True
        assert canvas.reg_table.read_bit(COIL_PLANT_HEALTH_CRITICAL_ALARM_ACTIVE) is True
        assert bool(canvas.status_bits & SunburstRadialStatusBits.CRITICAL_ALARM_ACTIVE)

    def test_critical_alarm_overall_health_threshold(self) -> None:
        """If mean health drops below 80.0%, %M449 trips even if no single node is marked CRITICAL."""
        canvas = create_canonical_sunburst_radial_canvas()
        for n in canvas.tree.get_all_nodes():
            n.health_score = 78.0
        canvas.update_telemetry()
        canvas.sync_to_registers()

        assert canvas.metrics.overall_health_pct < PLANT_HEALTH_ALARM_THRESHOLD_PCT
        assert canvas.metrics.critical_alarm_active is True
        assert canvas.reg_table.read_bit(COIL_PLANT_HEALTH_CRITICAL_ALARM_ACTIVE) is True

    def test_reset_nominal_clears_critical_alarm(self) -> None:
        """reset_nominal clears critical alarm, restoring %M449 to False and health to 98.50%."""
        canvas = create_canonical_sunburst_radial_canvas()
        canvas.trigger_critical_alarm(bad_health=40.0)
        assert canvas.reg_table.read_bit(COIL_PLANT_HEALTH_CRITICAL_ALARM_ACTIVE) is True

        canvas.reset_nominal()
        assert canvas.metrics.critical_alarm_active is False
        assert canvas.metrics.critical_node_count == 0
        assert canvas.metrics.overall_health_pct == 98.50
        assert canvas.reg_table.read_bit(COIL_PLANT_HEALTH_CRITICAL_ALARM_ACTIVE) is False

    def test_status_bits_warning_detection(self) -> None:
        """SunburstRadialStatusBits WARNING_ACTIVE bit is asserted when warning nodes exist."""
        canvas = create_canonical_sunburst_radial_canvas()
        assert bool(canvas.status_bits & SunburstRadialStatusBits.WARNING_ACTIVE) is True

        for n in canvas.tree.get_all_nodes():
            n.health_score = 99.0
        canvas.update_telemetry()
        assert bool(canvas.status_bits & SunburstRadialStatusBits.WARNING_ACTIVE) is False

    def test_inactive_node_does_not_trip_critical_alarm(self) -> None:
        """Inactive node (is_active=False) has INACTIVE state, does not count as CRITICAL."""
        tree = create_canonical_sunburst_radial_tree()
        node = tree.get_node_by_index(10)
        assert node is not None
        node.is_active = False
        assert node.health_state == HealthState.INACTIVE
        assert node.color == COLOR_INACTIVE


# ============================================================================
# Section 6: Standalone W3C SVG 1.1 Vector Graphic Generation
# ============================================================================

class TestSVGGenerationAndXMLSyntax:
    """Validate standalone W3C SVG 1.1 generation, valid XML syntax, element tags, and HUD."""

    def test_svg_generation_valid_xml_syntax(self) -> None:
        """generate_sunburst_radial_canvas_svg produces valid XML parseable by ElementTree."""
        canvas = create_canonical_sunburst_radial_canvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg") or root.tag == "svg"

    def test_svg_viewport_dimensions(self) -> None:
        """SVG root element has width 1200, height 750, and viewBox '0 0 1200 750'."""
        canvas = create_canonical_sunburst_radial_canvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        assert root.attrib.get("width") == "1200"
        assert root.attrib.get("height") == "750"
        assert root.attrib.get("viewBox") == "0 0 1200 750"

    def test_svg_defs_and_glow_filters(self) -> None:
        """SVG contains <defs> section with focus-glow and alarm-glow filter elements."""
        canvas = create_canonical_sunburst_radial_canvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        defs = root.find(".//{http://www.w3.org/2000/svg}defs")
        if defs is None:
            defs = root.find(".//defs")
        assert defs is not None
        filter_elements = defs.findall(".//{http://www.w3.org/2000/svg}filter")
        if not filter_elements:
            filter_elements = defs.findall(".//filter")
        filter_ids = [f.attrib.get("id") for f in filter_elements]
        assert "focus-glow" in filter_ids
        assert "alarm-glow" in filter_ids

    def test_svg_dark_theme_background_rect(self) -> None:
        """SVG contains dark theme background rect with fill COLOR_DARK_THEME_BACKING (#0B0F19)."""
        canvas = create_canonical_sunburst_radial_canvas()
        svg_str = canvas.render_svg()
        assert f'fill="{COLOR_DARK_THEME_BACKING}"' in svg_str

    def test_svg_header_banner_content(self) -> None:
        """SVG header banner includes complex name, wave W231, and sector count."""
        canvas = create_canonical_sunburst_radial_canvas()
        svg_str = canvas.render_svg()
        assert "CSCAPE SCADA // SUNBURST HIERARCHICAL RADIAL PARTITION" in svg_str
        assert "WAVE W231" in svg_str
        assert "61 SECTORS" in svg_str

    def test_svg_concentric_guide_rings(self) -> None:
        """SVG contains concentric guide rings group with 5 reference circles."""
        canvas = create_canonical_sunburst_radial_canvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        guides_group = None
        for g in root.findall(".//{http://www.w3.org/2000/svg}g") or root.findall(".//g"):
            if g.attrib.get("id") == "concentric_guide_rings":
                guides_group = g
                break
        assert guides_group is not None
        circles = guides_group.findall(".//{http://www.w3.org/2000/svg}circle") or guides_group.findall(".//circle")
        assert len(circles) == 5

    def test_svg_sunburst_sectors_path_count(self) -> None:
        """SVG sunburst_sectors group contains exactly 61 sector path elements."""
        canvas = create_canonical_sunburst_radial_canvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        sectors_group = None
        for g in root.findall(".//{http://www.w3.org/2000/svg}g") or root.findall(".//g"):
            if g.attrib.get("id") == "sunburst_sectors":
                sectors_group = g
                break
        assert sectors_group is not None
        paths = sectors_group.findall(".//{http://www.w3.org/2000/svg}path") or sectors_group.findall(".//path")
        assert len(paths) == 61

    def test_svg_active_sector_highlighting(self) -> None:
        """Selected sector path features focus-cyan stroke and focus-glow filter."""
        canvas = create_canonical_sunburst_radial_canvas(selected_sector_index=5)
        svg_str = canvas.render_svg()
        assert 'id="sector_5"' in svg_str
        assert f'stroke="{COLOR_FOCUS_CYAN}"' in svg_str
        assert 'filter="url(#focus-glow)"' in svg_str

    def test_svg_interactive_telemetry_hud_panel(self) -> None:
        """SVG contains interactive SCADA telemetry HUD panel with stats scorecard."""
        canvas = create_canonical_sunburst_radial_canvas()
        svg_str = canvas.render_svg()
        assert 'id="interactive_telemetry_hud"' in svg_str
        assert "PLANT STATS SCORECARD" in svg_str
        assert "TOTAL SECTORS (%R1920)" in svg_str
        assert "MAX DEPTH TIERS (%R1924)" in svg_str
        assert "OVERALL HEALTH (%R1921)" in svg_str
        assert "CRITICAL NODES (%R1922)" in svg_str
        assert "WARNING NODES (%R1923)" in svg_str
        assert "ACTIVE SECTOR FOCUS" in svg_str

    def test_svg_sector_title_tooltips(self) -> None:
        """Each sector path includes a <title> element with name, tag, tier, and health score."""
        canvas = create_canonical_sunburst_radial_canvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        titles = root.findall(".//{http://www.w3.org/2000/svg}title") or root.findall(".//title")
        assert len(titles) >= 61
        assert any("PLANT-ROOT" in t.text for t in titles if t.text)

    def test_generate_sunburst_canvas_svg_alias(self) -> None:
        """generate_sunburst_canvas_svg is an alias of generate_sunburst_radial_canvas_svg."""
        assert generate_sunburst_canvas_svg is generate_sunburst_radial_canvas_svg


# ============================================================================
# Section 7: WCAG 2.1 AAA Accessibility & Contrast Verification
# ============================================================================

class TestWCAG21AAAContrastAndVisualLegibility:
    """Validate relative luminance, contrast formula, text contrast > 7.0:1, badge > 18.0:1."""

    def test_relative_luminance_extremes(self) -> None:
        """relative_luminance computes 0.0 for black and 1.0 for white."""
        assert math.isclose(relative_luminance("#000000"), 0.0, abs_tol=1e-4)
        assert math.isclose(relative_luminance("#FFFFFF"), 1.0, abs_tol=1e-4)

    def test_relative_luminance_short_hex_and_invalid(self) -> None:
        """relative_luminance handles 3-digit shorthand hex and returns 0.0 on malformed hex."""
        assert math.isclose(relative_luminance("#FFF"), 1.0, abs_tol=1e-4)
        assert math.isclose(relative_luminance("#000"), 0.0, abs_tol=1e-4)
        assert relative_luminance("invalid") == 0.0
        assert relative_luminance("#12") == 0.0

    def test_contrast_ratio_symmetry(self) -> None:
        """contrast_ratio is symmetric regardless of parameter order."""
        c1, c2 = "#F0F6FC", "#0B0F19"
        assert math.isclose(contrast_ratio(c1, c2), contrast_ratio(c2, c1), abs_tol=1e-4)

    def test_text_primary_contrast_exceeds_wcag_aaa(self) -> None:
        """COLOR_TEXT_PRIMARY (#F0F6FC) against dark backing (#0B0F19) exceeds 7.0:1 text target."""
        cr = contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert cr >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert cr > 18.0

    def test_decoupled_badge_contrast_exceeds_wcag_aaa(self) -> None:
        """COLOR_TEXT_PRIMARY against COLOR_DECOUPLED_BADGE exceeds 18.0:1 badge target."""
        cr = contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert cr >= WCAG_AAA_BADGE_CONTRAST_TARGET

    def test_graphical_element_contrast_exceeds_target(self) -> None:
        """Status colors (emerald, amber, ruby) against dark backing exceed 3.0:1 graphical target."""
        assert contrast_ratio(COLOR_NORMAL, COLOR_DARK_THEME_BACKING) >= WCAG_GRAPHICAL_CONTRAST_TARGET
        assert contrast_ratio(COLOR_WARNING, COLOR_DARK_THEME_BACKING) >= WCAG_GRAPHICAL_CONTRAST_TARGET
        assert contrast_ratio(COLOR_CRITICAL, COLOR_DARK_THEME_BACKING) >= WCAG_GRAPHICAL_CONTRAST_TARGET

    def test_validate_wcag_aaa_contrast_helper_success(self) -> None:
        """validate_wcag_aaa_contrast returns (True, text_cr, badge_cr) on canonical theme."""
        is_aaa, text_cr, badge_cr = validate_wcag_aaa_contrast()
        assert is_aaa is True
        assert text_cr >= 7.0
        assert badge_cr >= 18.0

    def test_validate_wcag_aaa_contrast_helper_failure(self) -> None:
        """validate_wcag_aaa_contrast returns False when low contrast colors are supplied."""
        is_aaa, text_cr, badge_cr = validate_wcag_aaa_contrast(
            text_color="#1A202C",
            theme_backing="#0B0F19",
            badge_backing="#0B0F19",
        )
        assert is_aaa is False


# ============================================================================
# Section 8: Diagnostic Fault Conditions & Nominal Recovery
# ============================================================================

class TestDiagnosticFaultConditionsAndRecovery:
    """Validate 0xF301, 0xF302, 0xF303, 0xF304 fault handling, exceptions, and nominal recovery."""

    def test_fault_0xf301_radial_geometry_singularity(self) -> None:
        """trigger_radial_singularity sets 0xF301, de-asserts canvas_active, sets status bit."""
        canvas = create_canonical_sunburst_radial_canvas()
        canvas.trigger_radial_singularity()

        assert canvas.diagnostic_code == DIAG_ERR_RADIAL_GEOMETRY_SINGULARITY
        assert canvas.diagnostic_code == 0xF301
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xF301
        assert canvas.canvas_active is False
        assert canvas.reg_table.read_bit(COIL_SUNBURST_CANVAS_ACTIVE) is False
        assert bool(canvas.status_bits & SunburstRadialStatusBits.RADIAL_SINGULARITY_FAULT)

    def test_fault_0xf302_empty_hierarchy_tree(self) -> None:
        """trigger_empty_tree sets 0xF302, de-asserts canvas_active, sets status bit."""
        canvas = create_canonical_sunburst_radial_canvas()
        canvas.trigger_empty_tree()

        assert canvas.diagnostic_code == DIAG_ERR_EMPTY_HIERARCHY_TREE_ERROR
        assert canvas.diagnostic_code == 0xF302
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xF302
        assert canvas.canvas_active is False
        assert bool(canvas.status_bits & SunburstRadialStatusBits.EMPTY_TREE_FAULT)

    def test_fault_0xf303_hierarchical_weight_sum_mismatch(self) -> None:
        """trigger_weight_mismatch sets 0xF303, de-asserts canvas_active, sets status bit."""
        canvas = create_canonical_sunburst_radial_canvas()
        canvas.trigger_weight_mismatch()

        assert canvas.diagnostic_code == DIAG_ERR_HIERARCHICAL_WEIGHT_SUM_MISMATCH
        assert canvas.diagnostic_code == 0xF303
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xF303
        assert canvas.canvas_active is False
        assert bool(canvas.status_bits & SunburstRadialStatusBits.WEIGHT_MISMATCH_FAULT)

    def test_fault_0xf304_render_canvas_overflow(self) -> None:
        """trigger_canvas_overflow sets 0xF304, de-asserts canvas_active, sets status bit."""
        canvas = create_canonical_sunburst_radial_canvas()
        canvas.trigger_canvas_overflow()

        assert canvas.diagnostic_code == DIAG_ERR_RENDER_CANVAS_OVERFLOW
        assert canvas.diagnostic_code == 0xF304
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xF304
        assert canvas.canvas_active is False
        assert bool(canvas.status_bits & SunburstRadialStatusBits.CANVAS_OVERFLOW_FAULT)

    def test_nominal_recovery_after_faults(self) -> None:
        """reset_nominal recovers canvas to 0x0000, canvas_active=True, clears fault status bits."""
        canvas = create_canonical_sunburst_radial_canvas()
        canvas.trigger_radial_singularity()
        assert canvas.canvas_active is False

        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0x0000
        assert canvas.canvas_active is True
        assert canvas.reg_table.read_bit(COIL_SUNBURST_CANVAS_ACTIVE) is True
        assert bool(canvas.status_bits & SunburstRadialStatusBits.NOMINAL_OPERATION)
        assert not bool(canvas.status_bits & SunburstRadialStatusBits.RADIAL_SINGULARITY_FAULT)

    def test_custom_exception_hierarchy_inheritance(self) -> None:
        """All domain exceptions inherit from SunburstRadialError."""
        assert issubclass(RadialGeometrySingularityError, SunburstRadialError)
        assert issubclass(EmptyHierarchyTreeError, SunburstRadialError)
        assert issubclass(HierarchicalWeightSumMismatchError, SunburstRadialError)
        assert issubclass(RenderCanvasOverflowError, SunburstRadialError)
        assert issubclass(SVGRenderError, SunburstRadialError)

    def test_sequential_fault_injection_and_resets(self) -> None:
        """Sequential injection of all 4 faults with interleaved nominal resets."""
        canvas = create_canonical_sunburst_radial_canvas()
        fault_methods = [
            (canvas.trigger_radial_singularity, 0xF301),
            (canvas.trigger_empty_tree, 0xF302),
            (canvas.trigger_weight_mismatch, 0xF303),
            (canvas.trigger_canvas_overflow, 0xF304),
        ]
        for trigger_fn, expected_code in fault_methods:
            trigger_fn()
            assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == expected_code
            canvas.reset_nominal()
            assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0x0000


# ============================================================================
# Section 9: Horner OCS Memory Space & Register Synchronization
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Validate RegisterTable synchronization (%R1920..%R1927, %M448..%M449), privilege, and setpoints."""

    def test_nominal_registers_bit_exact_sync(self) -> None:
        """In nominal canonical state, registers %R1920..%R1927 and %M448..%M449 match specification."""
        reg_table = RegisterTable()
        canvas = SunburstRadialCanvas(reg_table=reg_table)
        canvas.sync_to_registers(privilege=PrivilegeMode.SYSTEM)

        assert reg_table.read_word(REG_TOTAL_HIERARCHY_NODES_COUNT) == 61
        assert reg_table.read_word(REG_PLANT_OVERALL_HEALTH_INDEX_PCT_SCALED) == 9850
        assert reg_table.read_word(REG_CRITICAL_NODE_ALARM_COUNT) == 0
        assert reg_table.read_word(REG_WARNING_NODE_COUNT) == 2
        assert reg_table.read_word(REG_MAX_HIERARCHY_DEPTH_TIERS) == 5
        assert reg_table.read_word(REG_SELECTED_SECTOR_INDEX) == 0
        assert reg_table.read_word(REG_OUTER_RING_RADIUS_PX) == 320
        assert reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0

        assert reg_table.read_bit(COIL_SUNBURST_CANVAS_ACTIVE) is True
        assert reg_table.read_bit(COIL_PLANT_HEALTH_CRITICAL_ALARM_ACTIVE) is False

    @pytest.mark.parametrize(
        "reg_addr,expected_val",
        [
            ("%R1920", 61),
            ("%R1921", 9850),
            ("%R1922", 0),
            ("%R1923", 2),
            ("%R1924", 5),
            ("%R1925", 0),
            ("%R1926", 320),
            ("%R1927", 0),
        ],
    )
    def test_individual_word_registers(self, reg_addr: str, expected_val: int) -> None:
        """Each word register in %R1920..%R1927 correctly stores its expected nominal value."""
        reg_table = RegisterTable()
        canvas = SunburstRadialCanvas(reg_table=reg_table)
        canvas.sync_to_registers(privilege=PrivilegeMode.SYSTEM)
        assert reg_table.read_word(reg_addr) == expected_val

    def test_signed_int16_register_packing(self) -> None:
        """Diagnostic code 0xF301 is stored as signed INT16 (-3327) and unmasks to 0xF301."""
        reg_table = RegisterTable()
        canvas = SunburstRadialCanvas(reg_table=reg_table)
        canvas.trigger_radial_singularity()

        raw_val = reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE)
        assert raw_val == 0xF301 - 0x10000
        assert (raw_val & 0xFFFF) == 0xF301

    def test_select_sector_by_index_syncs_registers(self) -> None:
        """select_sector_by_index updates selected sector index in register %R1925."""
        canvas = create_canonical_sunburst_radial_canvas()
        canvas.select_sector_by_index(15)

        assert canvas.selected_sector_index == 15
        assert canvas.reg_table.read_word(REG_SELECTED_SECTOR_INDEX) == 15
        assert canvas.metrics.selected_node_id == "EQ_ALK_COL_COND"

    def test_sync_from_registers_reads_setpoint(self) -> None:
        """sync_from_registers updates active sector index from external write to %R1925."""
        canvas = create_canonical_sunburst_radial_canvas()
        canvas.reg_table.write_word(REG_SELECTED_SECTOR_INDEX, 25, privilege=PrivilegeMode.SYSTEM)
        canvas.sync_from_registers()

        assert canvas.selected_sector_index == 25
        assert canvas.metrics.selected_node_id == "EQ_DIS_ACE_COND"

    def test_privilege_mode_system_write(self) -> None:
        """Writes to register table succeed under PrivilegeMode.SYSTEM."""
        reg_table = RegisterTable()
        canvas = SunburstRadialCanvas(reg_table=reg_table)
        canvas.sync_to_registers(reg_table=reg_table, privilege=PrivilegeMode.SYSTEM)
        assert reg_table.read_word(REG_TOTAL_HIERARCHY_NODES_COUNT) == 61

    def test_metrics_dataclass_properties(self) -> None:
        """SunburstRadialMetrics dataclass holds comprehensive telemetry."""
        metrics = SunburstRadialMetrics(
            total_nodes_count=61,
            overall_health_pct=98.50,
            overall_health_pct_scaled=9850,
            critical_node_count=0,
            warning_node_count=2,
            max_depth_tiers=5,
            selected_sector_index=3,
        )
        assert metrics.total_nodes_count == 61
        assert metrics.overall_health_pct == 98.50
        assert metrics.max_depth_tiers == 5
        assert SunburstMetrics is SunburstRadialMetrics


# ============================================================================
# Section 10: Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure ST syntax, STParser AST parsing, variable count, and symbol bindings."""

    def test_pure_st_pou_name_and_type(self) -> None:
        """SecurityGuard asserts pure ST and STParser parses PROGRAM POU named SunburstRadialCanvasSync."""
        SecurityGuard.assert_pure_st_content(SUNBURST_RADIAL_CANVAS_SYNC_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(SUNBURST_RADIAL_CANVAS_SYNC_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "SunburstRadialCanvasSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_pure_st_variables_count_and_types(self) -> None:
        """ST POU declares exactly 10 variables: 8 INT analog registers and 2 BOOL discrete coils."""
        parser = STParser()
        pou = parser.parse_pou(SUNBURST_RADIAL_CANVAS_SYNC_PURE_ST_POU)
        assert pou is not None
        assert len(pou.variables) == 10
        int_vars = [v for v in pou.variables if v.data_type == "INT"]
        bool_vars = [v for v in pou.variables if v.data_type == "BOOL"]
        assert len(int_vars) == 8
        assert len(bool_vars) == 2

    def test_pure_st_register_address_bindings(self) -> None:
        """Variables in ST POU are directly bound to %R1920..%R1927 and %M448..%M449."""
        parser = STParser()
        pou = parser.parse_pou(SUNBURST_RADIAL_CANVAS_SYNC_PURE_ST_POU)
        assert pou is not None
        expected_bindings = {
            "TotalHierarchyNodesCount": "%R1920",
            "PlantOverallHealthIndexPctScaled": "%R1921",
            "CriticalNodeAlarmCount": "%R1922",
            "WarningNodeCount": "%R1923",
            "MaxHierarchyDepthTiers": "%R1924",
            "SelectedSectorIndex": "%R1925",
            "OuterRingRadiusPx": "%R1926",
            "DiagnosticStatusCode": "%R1927",
            "SunburstCanvasActive": "%M448",
            "PlantHealthCriticalAlarmActive": "%M449",
        }
        vmap = {v.name: v.address_binding for v in pou.variables}
        for name, addr in expected_bindings.items():
            assert vmap.get(name) == addr

    def test_pure_st_pou_string_aliases(self) -> None:
        """Aliases SUNBURST_RADIAL_CANVAS_PURE_ST_POU and W231_SUNBURST_RADIAL_PURE_ST_POU match."""
        assert SUNBURST_RADIAL_CANVAS_PURE_ST_POU == SUNBURST_RADIAL_CANVAS_SYNC_PURE_ST_POU
        assert W231_SUNBURST_RADIAL_PURE_ST_POU == SUNBURST_RADIAL_CANVAS_SYNC_PURE_ST_POU
        assert SUNBURST_RADIAL_PURE_ST_POU == SUNBURST_RADIAL_CANVAS_SYNC_PURE_ST_POU

    def test_verify_sunburst_radial_canvas_pure_st_helper(self) -> None:
        """verify_sunburst_radial_canvas_pure_st returns True deterministically."""
        assert verify_sunburst_radial_canvas_pure_st() is True

    def test_pure_st_logic_body(self) -> None:
        """ST code body implements interlocking logic for CriticalNodeAlarmCount and scaled health."""
        assert "IF SunburstCanvasActive THEN" in SUNBURST_RADIAL_CANVAS_SYNC_PURE_ST_POU
        assert "CriticalNodeAlarmCount > 0 OR PlantOverallHealthIndexPctScaled < 8000" in SUNBURST_RADIAL_CANVAS_SYNC_PURE_ST_POU
        assert "PlantHealthCriticalAlarmActive := TRUE;" in SUNBURST_RADIAL_CANVAS_SYNC_PURE_ST_POU


# ============================================================================
# Section 11: Anti-Ladder Security Guard Interception
# ============================================================================

class TestAntiLadderRejection:
    """Validate fail-closed interception of ladder logic contacts, coils, rungs, and mnemonics."""

    @pytest.mark.parametrize(
        "ladder_snippet",
        [
            "---[ ]---",
            "---[/]---",
            "---( )---",
            "---(L)---",
            "---(U)---",
            "RUNG 1: XIC Sensor OTE Coil",
            "NETWORK 10: LD %R1920",
            "XIC StartButton",
            "XIO StopButton",
            "OTE CoilPump",
            "OTL AlarmLatch",
            "OTU AlarmUnlatch",
        ],
    )
    def test_reject_ladder_constructs(self, ladder_snippet: str) -> None:
        """SecurityGuard rejects ladder logic constructs raising LadderForbiddenError."""
        bad_st = f"PROGRAM Bad\n{ladder_snippet}\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_normally_open_contact_direct(self) -> None:
        """SecurityGuard rejects normally-open contact construct ---[ ]---."""
        bad_st = SUNBURST_RADIAL_CANVAS_SYNC_PURE_ST_POU + "\n---[ ]---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_normally_closed_contact_direct(self) -> None:
        """SecurityGuard rejects normally-closed contact construct ---[/]---."""
        bad_st = SUNBURST_RADIAL_CANVAS_SYNC_PURE_ST_POU + "\n---[/]---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_ladder_coil_direct(self) -> None:
        """SecurityGuard rejects ladder coil construct ---( )---."""
        bad_st = SUNBURST_RADIAL_CANVAS_SYNC_PURE_ST_POU + "\n---( )---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)


# ============================================================================
# Section 12: ILogicUnit Compliance & Simulation Soak
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface, execution priority, scan cycle step, and soak stability."""

    def test_ilogicunit_inheritance(self) -> None:
        """SunburstRadialCanvas implements abstract ILogicUnit protocol."""
        canvas = create_canonical_sunburst_radial_canvas()
        assert isinstance(canvas, ILogicUnit)
        assert SunburstRadialCanvasEngine is SunburstRadialCanvas
        assert SunburstRadialCanvasSync is SunburstRadialCanvas
        assert SunburstRadialHeatmapCanvas is SunburstRadialCanvas

    def test_name_property(self) -> None:
        """ILogicUnit name returns 'SunburstRadialCanvasSync'."""
        canvas = create_canonical_sunburst_radial_canvas()
        assert canvas.name == "SunburstRadialCanvasSync"

    def test_priority_property(self) -> None:
        """ILogicUnit priority returns 95."""
        canvas = create_canonical_sunburst_radial_canvas()
        assert canvas.priority == 95

    def test_is_enabled_property(self) -> None:
        """ILogicUnit is_enabled tracks canvas_active state."""
        canvas = create_canonical_sunburst_radial_canvas()
        assert canvas.is_enabled is True
        canvas.canvas_active = False
        assert canvas.is_enabled is False

    def test_scan_step_execution(self) -> None:
        """scan_step executes discrete single clock cycle without exceptions."""
        canvas = create_canonical_sunburst_radial_canvas()
        canvas.scan_step(dt=0.01)
        assert canvas.metrics.total_nodes_count == 61
        assert canvas.metrics.overall_health_pct_scaled == 9850

    def test_step_alias(self) -> None:
        """step() alias invokes scan_step()."""
        canvas = create_canonical_sunburst_radial_canvas()
        canvas.step()
        assert canvas.metrics.total_nodes_count == 61

    def test_execute_with_scan_context(self) -> None:
        """execute(context) evaluates logic cycle inside Horner ScanContext."""
        reg_table = RegisterTable()
        canvas = SunburstRadialCanvas(reg_table=reg_table)
        ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=reg_table)
        canvas.execute(ctx)
        assert reg_table.read_word(REG_TOTAL_HIERARCHY_NODES_COUNT) == 61

    def test_reset_method(self) -> None:
        """reset() restores canonical state."""
        canvas = create_canonical_sunburst_radial_canvas()
        canvas.trigger_radial_singularity()
        assert canvas.canvas_active is False
        canvas.reset()
        assert canvas.canvas_active is True
        assert canvas.diagnostic_code == DIAG_EVENT_OK

    def test_soak_100_cycles_stability(self) -> None:
        """100 sequential scan cycles exhibit zero memory drift and steady health metrics."""
        canvas = create_canonical_sunburst_radial_canvas()
        init_nodes = len(canvas.sectors)
        init_health = canvas.metrics.overall_health_pct_scaled

        for _ in range(100):
            canvas.scan_step(dt=0.01)

        assert len(canvas.sectors) == init_nodes == 61
        assert canvas.metrics.overall_health_pct_scaled == init_health == 9850
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.reg_table.read_bit(COIL_SUNBURST_CANVAS_ACTIVE) is True
        assert canvas.reg_table.read_bit(COIL_PLANT_HEALTH_CRITICAL_ALARM_ACTIVE) is False


# ============================================================================
# Section 13: Deterministic Verification Runner & Strict 4-State Contract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate 9-stage verification runner and strict 4-state engineering contract JSON output."""

    def test_run_verification_returns_success_contract(self) -> None:
        """run_sunburst_radial_canvas_verification returns strict 4-state contract with status 'success'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"

            res = run_sunburst_radial_canvas_verification(
                output_path=ev_path,
                sample_svg_path=svg_path,
                work_package="W231",
            )

            assert isinstance(res, dict)
            assert res["status"] == "success"
            assert res["error_code"] is None
            assert "Deterministic verification" in res["details"]
            assert res["data"]["checks_passed"] == 9
            assert res["data"]["total_checks"] == 9
            assert len(res["data"]["tests"]) == 9
            assert all(t["passed"] for t in res["data"]["tests"])

    def test_verification_evidence_file_written(self) -> None:
        """Evidence JSON file is written and contains valid data payload."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"

            run_sunburst_radial_canvas_verification(
                output_path=ev_path,
                sample_svg_path=svg_path,
            )

            assert ev_path.exists()
            with open(ev_path, "r", encoding="utf-8") as f:
                saved = json.load(f)
            assert saved["status"] == "success"
            assert saved["data"]["metrics"]["total_hierarchy_nodes_count"] == 61
            assert saved["data"]["metrics"]["plant_overall_health_index_pct_scaled"] == 9850

    def test_verification_sample_svg_file_written(self) -> None:
        """Sample SVG file is written and contains parseable XML."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"

            run_sunburst_radial_canvas_verification(
                output_path=ev_path,
                sample_svg_path=svg_path,
            )

            assert svg_path.exists()
            content = svg_path.read_text(encoding="utf-8")
            assert content.startswith("<?xml")
            root = ET.fromstring(content)
            assert root.tag.endswith("svg") or root.tag == "svg"

    def test_verification_contract_valid_statuses(self) -> None:
        """Contract status strictly belongs to 4-state set: success | failed | blocked | inconclusive."""
        valid_statuses = {"success", "failed", "blocked", "inconclusive"}
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"
            res = run_sunburst_radial_canvas_verification(ev_path, svg_path)
            assert res["status"] in valid_statuses
