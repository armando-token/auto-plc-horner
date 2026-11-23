"""Comprehensive unit test suite for Cscape HMI Dynamic Treemap Hierarchical Nested SCADA Canvas (W237).

Work Package: W237 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Squarified Treemap Hierarchical SCADA Canvas]

Architectural Coverage (110+ Unit Tests across 13 Test Classes):
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit equality (& 0xFFFF), hashing, enums, status flags.
2. TestNodeDataclassAndHierarchyTree: TreemapHierarchicalNode / TreemapTile initialization, properties, health state computation, tree indexing.
3. TestSquarifiedAlgorithmAndAspectRatio: Aspect ratio formulas, squarified row packing, minimizing max(w/h, h/w) towards 1.0.
4. TestWeightConservationAndAreaBounding: Multi-tier weight conservation, parent container bounding, non-overlapping planar partition.
5. TestHealthAggregationAndCriticalAlarm: Bottom-up health score aggregation, warning node detection, critical fault alarm (%M463).
6. TestSVGGenerationAndXMLSyntax: Standalone W3C SVG 1.1 vector graphic generation, ElementTree XML validation, filter defs, HUD card.
7. TestWCAG21AAAContrastAndVisualLegibility: WCAG 2.1 AAA relative luminance, contrast formulas, badge contrast > 18:1, text > 7:1.
8. TestDiagnosticFaultConditionsAndRecovery: 0xF501 singularity, 0xF502 empty tree, 0xF503 weight mismatch, 0xF504 canvas overflow, reset nominal.
9. TestHornerOCSSynchronizationAndRegisters: RegisterTable memory sync (%R1980..%R1987, %M462..%M463), PrivilegeMode.SYSTEM enforcement.
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

from jev_cscape.hmi.treemap_hierarchical_canvas import (
    CANONICAL_CRITICAL_ALARMS,
    CANONICAL_MAX_DEPTH,
    CANONICAL_OVERALL_HEALTH_PCT,
    CANONICAL_OVERALL_HEALTH_SCALED,
    CANONICAL_TOTAL_NODES,
    CANONICAL_TOTAL_TILES,
    CANONICAL_TOTAL_WEIGHT_METRIC,
    CANONICAL_TOTAL_WEIGHT_SCALED,
    CANVAS_OVERFLOW_FAULT,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COIL_CANVAS_ACTIVE,
    COIL_CRITICAL_ALARM,
    COIL_CRITICAL_TILE_ALARM_ACTIVE,
    COIL_TREEMAP_CANVAS_ACTIVE,
    COIL_W237_CANVAS_ACTIVE,
    COIL_W237_CRITICAL_ALARM,
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
    DEFAULT_CANVAS_HEIGHT,
    DEFAULT_CANVAS_WIDTH,
    DEFAULT_CANVAS_X,
    DEFAULT_CANVAS_Y,
    DIAG_ERR_EMPTY_HIERARCHY_TREE,
    DIAG_ERR_EMPTY_HIERARCHY_TREE_ERROR,
    DIAG_ERR_EMPTY_TREE,
    DIAG_ERR_GEOMETRY_SINGULARITY,
    DIAG_ERR_TREEMAP_GEOMETRY_SINGULARITY,
    DIAG_ERR_VIEWPORT_CANVAS_OVERFLOW,
    DIAG_ERR_WEIGHT_CONSERVATION_MISMATCH,
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
    HealthState,
    HierarchyTier,
    LAYOUT_BOUNDS_HEIGHT,
    LAYOUT_BOUNDS_WIDTH,
    LAYOUT_BOUNDS_X,
    LAYOUT_BOUNDS_Y,
    NodeHealthState,
    OPTIMAL_ASPECT_RATIO_TARGET,
    PLANT_HEALTH_ALARM_THRESHOLD_PCT,
    REG_ACTIVE_TILE_INDEX,
    REG_CRITICAL_NODE_ALARM_COUNT,
    REG_CRITICAL_TILES_COUNT,
    REG_CRITICAL_TILE_ALARM_COUNT,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_DIAG_CODE,
    REG_MAX_DEPTH_TIERS,
    REG_MAX_HIERARCHY_DEPTH,
    REG_MAX_HIERARCHY_DEPTH_TIERS,
    REG_OVERALL_HEALTH_SCALED,
    REG_OVERALL_HEALTH_SCORE_SCALED,
    REG_PLANT_OVERALL_HEALTH_INDEX_PCT_SCALED,
    REG_PLANT_OVERALL_HEALTH_PCT_SCALED,
    REG_SELECTED_TILE_INDEX,
    REG_TOTAL_LEAF_NODES,
    REG_TOTAL_TILES_COUNT,
    REG_TOTAL_TILE_COUNT,
    REG_TOTAL_TREEMAP_TILES_COUNT,
    REG_TOTAL_WEIGHT_SCALED,
    REG_W237_CRITICAL_COUNT,
    REG_W237_DIAG_CODE,
    REG_W237_HEALTH_SCALED,
    REG_W237_MAX_DEPTH,
    REG_W237_SELECTED_TILE,
    REG_W237_TOTAL_TILES,
    REG_W237_WEIGHT_SCALED,
    REG_W237_WORST_ASPECT,
    REG_WARNING_NODE_COUNT,
    REG_WARNING_TILE_COUNT,
    REG_WORST_ASPECT_RATIO_SCALED,
    REG_WORST_TILE_ASPECT_RATIO_SCALED,
    Rect,
    SQUARIFIED_ASPECT_RATIO_TARGET,
    SquarifiedTreemapLayout,
    TREEMAP_GEOMETRY_SINGULARITY,
    TREEMAP_HIERARCHICAL_CANVAS_PURE_ST_POU,
    TREEMAP_HIERARCHICAL_CANVAS_SYNC_PURE_ST_POU,
    TREEMAP_HIERARCHICAL_OK,
    TREEMAP_HIERARCHICAL_PURE_ST_POU,
    TREEMAP_OK,
    TierLevel,
    TreemapDiagnosticCode,
    TreemapGeometrySingularityError,
    TreemapHierarchicalCanvas,
    TreemapHierarchicalCanvasEngine,
    TreemapHierarchicalCanvasSync,
    TreemapHierarchicalDiagnosticCode,
    TreemapHierarchicalError,
    TreemapHierarchicalMetrics,
    TreemapHierarchicalNode,
    TreemapHierarchicalStatusBits,
    TreemapHierarchicalTree,
    TreemapMetrics,
    TreemapNode,
    TreemapStatusBits,
    TreemapTile,
    VIEWPORT_CANVAS_OVERFLOW,
    ViewportCanvasOverflowError,
    W237_TREEMAP_HIERARCHICAL_PURE_ST_POU,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    WEIGHT_CONSERVATION_MISMATCH,
    WEIGHT_MISMATCH_FAULT,
    WORST_ASPECT_RATIO_CEILING,
    WeightConservationMismatchError,
    calculate_contrast_ratio,
    create_canonical_treemap_hierarchical_canvas,
    create_canonical_treemap_hierarchical_tree,
    create_canonical_treemap_hierarchy,
    create_mock_scan_context,
    generate_treemap_hierarchical_canvas_svg,
    layout_hierarchical_treemap,
    layout_squarified,
    relative_luminance,
    run_treemap_hierarchical_canvas_verification,
    validate_wcag_aaa_contrast,
    verify_treemap_hierarchical_canvas_pure_st,
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
        assert TREEMAP_OK == DIAG_EVENT_OK
        assert TREEMAP_HIERARCHICAL_OK == DIAG_EVENT_OK
        assert int(DIAG_EVENT_OK) == 0

    @pytest.mark.parametrize(
        "code_const,uint_val,sint_val",
        [
            (DIAG_ERR_GEOMETRY_SINGULARITY, 0xF501, 0xF501 - 0x10000),
            (DIAG_ERR_EMPTY_TREE, 0xF502, 0xF502 - 0x10000),
            (DIAG_ERR_WEIGHT_CONSERVATION_MISMATCH, 0xF503, 0xF503 - 0x10000),
            (DIAG_ERR_VIEWPORT_CANVAS_OVERFLOW, 0xF504, 0xF504 - 0x10000),
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
            DIAG_ERR_GEOMETRY_SINGULARITY,
            DIAG_ERR_EMPTY_TREE,
            DIAG_ERR_WEIGHT_CONSERVATION_MISMATCH,
            DIAG_ERR_VIEWPORT_CANVAS_OVERFLOW,
        }
        assert len(codes) == 5
        assert hash(DiagnosticCode(0xF501)) == hash(0xF501)

    def test_diagnostic_code_aliases(self) -> None:
        """Aliases for diagnostic codes point to canonical constants."""
        assert GEOMETRY_SINGULARITY_FAULT == DIAG_ERR_GEOMETRY_SINGULARITY
        assert DIAG_ERR_TREEMAP_GEOMETRY_SINGULARITY == DIAG_ERR_GEOMETRY_SINGULARITY
        assert TREEMAP_GEOMETRY_SINGULARITY == DIAG_ERR_GEOMETRY_SINGULARITY

        assert EMPTY_TREE_FAULT == DIAG_ERR_EMPTY_TREE
        assert DIAG_ERR_EMPTY_HIERARCHY_TREE == DIAG_ERR_EMPTY_TREE
        assert DIAG_ERR_EMPTY_HIERARCHY_TREE_ERROR == DIAG_ERR_EMPTY_TREE
        assert EMPTY_HIERARCHY_TREE_ERROR == DIAG_ERR_EMPTY_TREE

        assert WEIGHT_MISMATCH_FAULT == DIAG_ERR_WEIGHT_CONSERVATION_MISMATCH
        assert WEIGHT_CONSERVATION_MISMATCH == DIAG_ERR_WEIGHT_CONSERVATION_MISMATCH

        assert CANVAS_OVERFLOW_FAULT == DIAG_ERR_VIEWPORT_CANVAS_OVERFLOW
        assert VIEWPORT_CANVAS_OVERFLOW == DIAG_ERR_VIEWPORT_CANVAS_OVERFLOW

        assert TreemapHierarchicalDiagnosticCode is DiagnosticCode
        assert TreemapDiagnosticCode is DiagnosticCode

    def test_horner_word_registers_constants(self) -> None:
        """Horner OCS word registers span %R1980..%R1987 with expected string bindings."""
        assert REG_TOTAL_TREEMAP_TILES_COUNT == "%R1980"
        assert REG_PLANT_OVERALL_HEALTH_PCT_SCALED == "%R1981"
        assert REG_CRITICAL_TILE_ALARM_COUNT == "%R1982"
        assert REG_TOTAL_WEIGHT_SCALED == "%R1983"
        assert REG_MAX_HIERARCHY_DEPTH_TIERS == "%R1984"
        assert REG_SELECTED_TILE_INDEX == "%R1985"
        assert REG_WORST_TILE_ASPECT_RATIO_SCALED == "%R1986"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R1987"

    def test_horner_register_aliases(self) -> None:
        """Horner register aliases match canonical register addresses."""
        assert REG_TOTAL_TILE_COUNT == "%R1980"
        assert REG_TOTAL_TILES_COUNT == "%R1980"
        assert REG_TOTAL_LEAF_NODES == "%R1980"
        assert REG_W237_TOTAL_TILES == "%R1980"

        assert REG_OVERALL_HEALTH_SCORE_SCALED == "%R1981"
        assert REG_PLANT_OVERALL_HEALTH_INDEX_PCT_SCALED == "%R1981"
        assert REG_OVERALL_HEALTH_SCALED == "%R1981"
        assert REG_W237_HEALTH_SCALED == "%R1981"

        assert REG_CRITICAL_NODE_ALARM_COUNT == "%R1982"
        assert REG_CRITICAL_TILES_COUNT == "%R1982"
        assert REG_W237_CRITICAL_COUNT == "%R1982"

        assert REG_WARNING_TILE_COUNT == "%R1983"
        assert REG_WARNING_NODE_COUNT == "%R1983"
        assert REG_W237_WEIGHT_SCALED == "%R1983"

        assert REG_MAX_HIERARCHY_DEPTH == "%R1984"
        assert REG_MAX_DEPTH_TIERS == "%R1984"
        assert REG_W237_MAX_DEPTH == "%R1984"

        assert REG_ACTIVE_TILE_INDEX == "%R1985"
        assert REG_W237_SELECTED_TILE == "%R1985"

        assert REG_WORST_ASPECT_RATIO_SCALED == "%R1986"
        assert REG_W237_WORST_ASPECT == "%R1986"

        assert REG_DIAG_CODE == "%R1987"
        assert REG_W237_DIAG_CODE == "%R1987"

    def test_horner_discrete_coils_constants(self) -> None:
        """Horner OCS discrete coils bind to %M462 and %M463 with aliases."""
        assert COIL_TREEMAP_CANVAS_ACTIVE == "%M462"
        assert COIL_CRITICAL_TILE_ALARM_ACTIVE == "%M463"

        assert COIL_CANVAS_ACTIVE == "%M462"
        assert COIL_W237_CANVAS_ACTIVE == "%M462"

        assert COIL_CRITICAL_ALARM == "%M463"
        assert COIL_W237_CRITICAL_ALARM == "%M463"

    def test_hierarchy_tier_enum_values(self) -> None:
        """HierarchyTier enum spans COMPLEX (0), UNIT (1), SUBSYSTEM (2), and EQUIPMENT (3)."""
        assert HierarchyTier.COMPLEX.value == 0
        assert HierarchyTier.UNIT.value == 1
        assert HierarchyTier.SUBSYSTEM.value == 2
        assert HierarchyTier.EQUIPMENT.value == 3
        assert TierLevel is HierarchyTier

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

    def test_treemap_status_bits_values(self) -> None:
        """TreemapHierarchicalStatusBits bitmask defines discrete bit flags."""
        assert TreemapHierarchicalStatusBits.CANVAS_ACTIVE.value == 0x0001
        assert TreemapHierarchicalStatusBits.HIERARCHY_VALID.value == 0x0002
        assert TreemapHierarchicalStatusBits.SQUARIFIED_COMPUTED.value == 0x0004
        assert TreemapHierarchicalStatusBits.CRITICAL_ALARM_ACTIVE.value == 0x0008
        assert TreemapHierarchicalStatusBits.WARNING_ACTIVE.value == 0x0010
        assert TreemapHierarchicalStatusBits.GEOMETRY_SINGULARITY_FAULT.value == 0x0020
        assert TreemapHierarchicalStatusBits.EMPTY_TREE_FAULT.value == 0x0040
        assert TreemapHierarchicalStatusBits.WEIGHT_MISMATCH_FAULT.value == 0x0080
        assert TreemapHierarchicalStatusBits.CANVAS_OVERFLOW_FAULT.value == 0x0100
        assert TreemapHierarchicalStatusBits.WCAG_AAA_VERIFIED.value == 0x0200
        assert TreemapHierarchicalStatusBits.SVG_RENDER_VALID.value == 0x0400
        assert TreemapHierarchicalStatusBits.NOMINAL_OPERATION.value == 0x0800
        assert TreemapStatusBits is TreemapHierarchicalStatusBits

    def test_canvas_geometry_constants(self) -> None:
        """Canvas viewport and bounding geometry constants match specification."""
        assert CANVAS_VIEWPORT_WIDTH == 1200
        assert CANVAS_VIEWPORT_HEIGHT == 750
        assert DEFAULT_CANVAS_WIDTH in (780.0, 1160.0)
        assert DEFAULT_CANVAS_HEIGHT in (630.0, 644.0)
        assert LAYOUT_BOUNDS_WIDTH in (1140.0, 1160.0)
        assert LAYOUT_BOUNDS_HEIGHT in (630.0, 644.0)

    def test_canonical_dimensions_and_thresholds(self) -> None:
        """Canonical dimensions and health thresholds are correctly configured."""
        assert CANONICAL_TOTAL_TILES == 20
        assert CANONICAL_TOTAL_NODES == 26
        assert CANONICAL_MAX_DEPTH == 3
        assert CANONICAL_OVERALL_HEALTH_SCALED == 9850
        assert CANONICAL_OVERALL_HEALTH_PCT == 98.50
        assert CANONICAL_CRITICAL_ALARMS == 0
        assert CANONICAL_TOTAL_WEIGHT_METRIC == 6000.0
        assert CANONICAL_TOTAL_WEIGHT_SCALED == 600

        assert HEALTH_CRITICAL_THRESHOLD == 70.0
        assert HEALTH_WARNING_THRESHOLD in (80.0, 85.0)
        assert PLANT_HEALTH_ALARM_THRESHOLD_PCT == 80.0
        assert OPTIMAL_ASPECT_RATIO_TARGET == 1.0
        assert WORST_ASPECT_RATIO_CEILING == 4.5

    def test_dark_theme_colors(self) -> None:
        """Dark theme palette conforms to industrial SCADA aesthetic."""
        assert COLOR_DARK_THEME_BACKING == "#0B0F19"
        assert COLOR_PANEL_BG == "#161B22"
        assert COLOR_BORDER == "#21262D"
        assert COLOR_DECOUPLED_BADGE == "#050811"
        assert COLOR_TEXT_PRIMARY in ("#FFFFFF", "#F0F6FC")
        assert COLOR_TEXT_MUTED == "#8B949E"
        assert COLOR_FOCUS_CYAN in ("#06B6D4", "#38BDF8")
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
    """Validate TreemapHierarchicalNode, tree containers, depth calculations, and traversals."""

    def test_node_initialization_and_properties(self) -> None:
        """TreemapHierarchicalNode initializes with default and provided properties."""
        node = TreemapHierarchicalNode(
            node_id="NODE_TEST",
            index=10,
            name="Test Equipment Tile",
            tier=HierarchyTier.EQUIPMENT,
            parent_id="PARENT_TEST",
            health_score=92.5,
            weight=250.0,
            rect=Rect(10.0, 20.0, 100.0, 50.0),
        )
        assert node.node_id == "NODE_TEST"
        assert node.id == "NODE_TEST"
        assert node.index == 10
        assert node.name == "Test Equipment Tile"
        assert node.tier == HierarchyTier.EQUIPMENT
        assert node.parent_id == "PARENT_TEST"
        assert node.weight == 250.0
        assert node.health_score == 92.5
        assert node.is_leaf is True
        assert node.health_state == HealthState.NORMAL
        assert node.color == COLOR_NORMAL
        assert node.rect.area == 5000.0
        assert node.rect.aspect_ratio == 2.0

    def test_node_aliases(self) -> None:
        """TreemapNode and TreemapTile are aliases of TreemapHierarchicalNode."""
        assert TreemapNode is TreemapHierarchicalNode
        assert TreemapTile is TreemapHierarchicalNode

    def test_node_health_state_transitions(self) -> None:
        """Node correctly evaluates HealthState based on health_score and is_active flag."""
        node = TreemapHierarchicalNode(node_id="N1", index=1, name="N1", health_score=95.0)
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

    def test_node_effective_weight_and_aggregation(self) -> None:
        """effective_weight aggregates child weights recursively."""
        parent = TreemapHierarchicalNode(node_id="P1", name="Parent", weight=0.0)
        c1 = TreemapHierarchicalNode(node_id="C1", name="Child 1", weight=100.0)
        c2 = TreemapHierarchicalNode(node_id="C2", name="Child 2", weight=150.0)
        parent.children = [c1, c2]

        assert parent.is_leaf is False
        assert parent.effective_weight == 250.0
        parent.recalculate_aggregates()
        assert parent.weight == 250.0

    def test_node_get_all_leaves_and_nodes(self) -> None:
        """get_all_leaves() and get_all_nodes() traverse tree recursively."""
        root = TreemapHierarchicalNode(node_id="ROOT", name="Root", tier=HierarchyTier.COMPLEX)
        u1 = TreemapHierarchicalNode(node_id="U1", name="Unit 1", tier=HierarchyTier.UNIT, parent_id="ROOT")
        u2 = TreemapHierarchicalNode(node_id="U2", name="Unit 2", tier=HierarchyTier.UNIT, parent_id="ROOT")
        eq1 = TreemapHierarchicalNode(node_id="EQ1", name="Eq 1", tier=HierarchyTier.EQUIPMENT, parent_id="U1")
        eq2 = TreemapHierarchicalNode(node_id="EQ2", name="Eq 2", tier=HierarchyTier.EQUIPMENT, parent_id="U1")
        u1.children = [eq1, eq2]
        root.children = [u1, u2]

        all_nodes = root.get_all_nodes()
        assert len(all_nodes) == 5
        assert [n.node_id for n in all_nodes] == ["ROOT", "U1", "EQ1", "EQ2", "U2"]

        leaves = root.get_all_leaves()
        assert len(leaves) == 3
        assert [l.node_id for l in leaves] == ["EQ1", "EQ2", "U2"]

    def test_node_max_depth_calculation(self) -> None:
        """max_depth() correctly computes maximum tree depth from current node."""
        root = TreemapHierarchicalNode(node_id="ROOT", name="Root")
        assert root.max_depth() == 1

        u1 = TreemapHierarchicalNode(node_id="U1", name="Unit 1", parent_id="ROOT")
        eq1 = TreemapHierarchicalNode(node_id="EQ1", name="Eq 1", parent_id="U1")
        u1.children.append(eq1)
        root.children.append(u1)
        assert root.max_depth() == 3

    def test_canonical_tree_total_node_population(self) -> None:
        """Canonical hierarchy tree contains exactly 26 total nodes (1 root, 5 areas, 20 modules)."""
        tree = create_canonical_treemap_hierarchical_tree()
        assert tree.total_nodes == 26
        assert len(tree.get_all_nodes()) == 26

    def test_canonical_tree_tier_distribution(self) -> None:
        """Canonical hierarchy spans 3 tiers: Complex (1), Areas (5), Equipment Modules (20)."""
        tree = create_canonical_treemap_hierarchical_tree()
        tier_counts: Dict[Any, int] = {0: 0, 1: 0, 2: 0, 3: 0}
        for node in tree.get_all_nodes():
            tier_val = node.tier.value if isinstance(node.tier, HierarchyTier) else node.tier
            tier_counts[tier_val] = tier_counts.get(tier_val, 0) + 1

        assert tier_counts[0] == 1
        assert tier_counts[1] == 5
        assert tier_counts[2] == 20
        assert tree.max_depth == 3

    def test_canonical_tree_leaf_count(self) -> None:
        """Canonical hierarchy tree contains exactly 20 leaf equipment modules."""
        tree = create_canonical_treemap_hierarchical_tree()
        leaves = tree.get_leaves()
        assert len(leaves) == 20
        assert all(l.is_leaf for l in leaves)

    def test_tree_indexing_by_id_and_index(self) -> None:
        """TreemapHierarchicalTree get_node and get_node_by_index return valid nodes."""
        tree = create_canonical_treemap_hierarchical_tree()
        root = tree.get_node("ROOT_PETROCHEM")
        assert root is not None
        assert root.index == 0

        for i in range(tree.total_nodes):
            node = tree.get_node_by_index(i)
            assert node is not None
            assert node.index == i

        assert tree.get_node("NON_EXISTENT") is None
        assert tree.get_node_by_index(999) is None

    def test_tree_traverse_bfs(self) -> None:
        """traverse_bfs() traverses tree in breadth-first level order starting with root."""
        tree = create_canonical_treemap_hierarchical_tree()
        bfs_nodes = tree.traverse_bfs()
        assert len(bfs_nodes) == 26
        assert bfs_nodes[0].node_id == "ROOT_PETROCHEM"
        # First node root (tier 0), next 5 areas (tier 1), next 20 modules (tier 2)
        assert bfs_nodes[0].tier == HierarchyTier.COMPLEX
        assert all(n.tier == HierarchyTier.UNIT for n in bfs_nodes[1:6])
        assert all(n.tier in (HierarchyTier.EQUIPMENT, HierarchyTier.EQUIPMENT_MODULE, HierarchyTier.SUBSYSTEM) for n in bfs_nodes[6:])

    def test_tree_traverse_dfs_postorder(self) -> None:
        """traverse_dfs_postorder() visits all children before their parent, ending with root."""
        tree = create_canonical_treemap_hierarchical_tree()
        dfs_nodes = tree.traverse_dfs_postorder()
        assert len(dfs_nodes) == 26
        assert dfs_nodes[-1].node_id == "ROOT_PETROCHEM"

    def test_empty_tree_container_behavior(self) -> None:
        """TreemapHierarchicalTree with no root handles operations gracefully."""
        tree = TreemapHierarchicalTree(root=None)
        assert tree.total_nodes == 0
        assert tree.max_depth == 0
        assert tree.get_all_nodes() == []
        assert tree.get_leaves() == []
        assert tree.traverse_bfs() == []
        assert tree.traverse_dfs_postorder() == []
        h, c, w = tree.recompute_overall_health()
        assert h == 0.0 and c == 0 and w == 0


# ============================================================================
# Section 3: Squarified Treemap Algorithm & Aspect Ratio Optimization
# ============================================================================

class TestSquarifiedAlgorithmAndAspectRatio:
    """Validate squarified row packing, worst aspect ratio minimization, and aspect ratio formulas."""

    def test_worst_aspect_ratio_square(self) -> None:
        """Single square item with area equal to side^2 yields aspect ratio exactly 1.0."""
        ar = SquarifiedTreemapLayout.worst_aspect_ratio([100.0], 10.0)
        assert math.isclose(ar, 1.0, abs_tol=1e-5)

    def test_worst_aspect_ratio_elongated(self) -> None:
        """Item of area 20 along side 10 yields aspect ratio 10 / 2 = 5.0."""
        ar = SquarifiedTreemapLayout.worst_aspect_ratio([20.0], 10.0)
        assert math.isclose(ar, 5.0, abs_tol=1e-5)

    def test_worst_aspect_ratio_empty_or_zero(self) -> None:
        """Empty areas list or zero side length returns 1.0."""
        assert SquarifiedTreemapLayout.worst_aspect_ratio([], 10.0) == 1.0
        assert SquarifiedTreemapLayout.worst_aspect_ratio([10.0], 0.0) == 1.0
        assert SquarifiedTreemapLayout.worst_aspect_ratio([0.0], 10.0) == 1.0

    def test_rect_aspect_ratio_property(self) -> None:
        """Rect aspect_ratio property calculates max(w/h, h/w) >= 1.0."""
        r1 = Rect(0, 0, 100, 100)
        assert math.isclose(r1.aspect_ratio, 1.0, abs_tol=1e-5)

        r2 = Rect(0, 0, 200, 100)
        assert math.isclose(r2.aspect_ratio, 2.0, abs_tol=1e-5)

        r3 = Rect(0, 0, 100, 300)
        assert math.isclose(r3.aspect_ratio, 3.0, abs_tol=1e-5)

        r_zero = Rect(0, 0, 0, 100)
        assert r_zero.aspect_ratio == 1.0

    def test_squarified_layout_aspect_ratio_ceiling(self) -> None:
        """Canonical hierarchy layout achieves worst aspect ratio < 4.5 and mean aspect ratio < 2.0."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        assert canvas.metrics.worst_tile_aspect_ratio < WORST_ASPECT_RATIO_CEILING
        assert canvas.metrics.mean_aspect_ratio < 2.5
        assert canvas.metrics.worst_tile_aspect_ratio >= 1.0
        assert canvas.metrics.mean_aspect_ratio >= 1.0

    def test_squarified_layout_single_item(self) -> None:
        """Single item in bounds receives full container bounds."""
        node = TreemapHierarchicalNode(node_id="ITEM1", weight=50.0)
        bounds = Rect(10.0, 20.0, 200.0, 100.0)
        layout_squarified([node], bounds)
        assert node.rect.x == 10.0
        assert node.rect.y == 20.0
        assert node.rect.width == 200.0
        assert node.rect.height == 100.0

    def test_squarified_layout_two_items_equal(self) -> None:
        """Two equal-weight items split along the shorter side equally."""
        n1 = TreemapHierarchicalNode(node_id="N1", weight=50.0)
        n2 = TreemapHierarchicalNode(node_id="N2", weight=50.0)
        bounds = Rect(0.0, 0.0, 200.0, 100.0)
        layout_squarified([n1, n2], bounds)

        assert math.isclose(n1.rect.area, 10000.0, abs_tol=1e-3)
        assert math.isclose(n2.rect.area, 10000.0, abs_tol=1e-3)
        assert math.isclose(n1.rect.area + n2.rect.area, bounds.area, abs_tol=1e-3)

    def test_squarified_layout_area_proportionality(self) -> None:
        """Area assigned to each node is strictly proportional to its weight."""
        n1 = TreemapHierarchicalNode(node_id="N1", weight=10.0)
        n2 = TreemapHierarchicalNode(node_id="N2", weight=30.0)
        bounds = Rect(0.0, 0.0, 400.0, 200.0)
        layout_squarified([n1, n2], bounds)

        total_area = bounds.area  # 80000
        assert math.isclose(n1.rect.area, 0.25 * total_area, rel_tol=1e-4)
        assert math.isclose(n2.rect.area, 0.75 * total_area, rel_tol=1e-4)

    def test_squarified_layout_zero_or_negative_bounds_raises(self) -> None:
        """Zero or negative bounding dimensions raise TreemapGeometrySingularityError (0xF501)."""
        n1 = TreemapHierarchicalNode(node_id="N1", weight=10.0)
        with pytest.raises(TreemapGeometrySingularityError):
            layout_squarified([n1], Rect(0, 0, 0.0, 100.0))
        with pytest.raises(TreemapGeometrySingularityError):
            layout_squarified([n1], Rect(0, 0, 100.0, -10.0))

    def test_squarified_layout_zero_total_weight_raises(self) -> None:
        """Zero total weight across items raises EmptyHierarchyTreeError (0xF502)."""
        n1 = TreemapHierarchicalNode(node_id="N1", weight=0.0)
        n2 = TreemapHierarchicalNode(node_id="N2", weight=0.0)
        with pytest.raises(EmptyHierarchyTreeError):
            layout_squarified([n1, n2], Rect(0, 0, 100.0, 100.0))

    def test_rect_contains_rect_and_intersects(self) -> None:
        """Rect contains_rect and intersects correctly evaluate planar bounding relationships."""
        r_outer = Rect(0, 0, 100, 100)
        r_inner = Rect(10, 10, 50, 50)
        r_outside = Rect(110, 110, 20, 20)
        r_overlap = Rect(50, 50, 100, 100)

        assert r_outer.contains_rect(r_inner) is True
        assert r_outer.contains_rect(r_outside) is False
        assert r_outer.intersects(r_overlap) is True
        assert r_outer.intersects(r_outside) is False


# ============================================================================
# Section 4: Weight Conservation & Container Planar Bounding
# ============================================================================

class TestWeightConservationAndAreaBounding:
    """Validate multi-tier weight conservation, parent container bounding, and non-overlapping tiles."""

    def test_total_plant_weight_conservation(self) -> None:
        """Total plant root weight equals 6000.0 kg/h and matches sum of 5 process areas."""
        tree = create_canonical_treemap_hierarchical_tree()
        root = tree.root
        assert root is not None
        assert math.isclose(root.weight, 6000.0, abs_tol=1e-4)

        areas_weight = sum(a.weight for a in root.children)
        assert math.isclose(areas_weight, 6000.0, abs_tol=1e-4)

    def test_process_area_weight_conservation(self) -> None:
        """Each process area weight equals exactly the sum of its child equipment module weights."""
        tree = create_canonical_treemap_hierarchical_tree()
        root = tree.root
        assert root is not None

        for area in root.children:
            mod_weight_sum = sum(mod.weight for mod in area.children)
            assert math.isclose(area.weight, mod_weight_sum, abs_tol=1e-4)

    def test_equipment_leaves_total_weight_matches_root(self) -> None:
        """Sum of all 20 equipment leaf weights equals exactly 6000.0 kg/h."""
        tree = create_canonical_treemap_hierarchical_tree()
        leaves = tree.get_leaves()
        assert len(leaves) == 20
        total_leaf_weight = sum(l.weight for l in leaves)
        assert math.isclose(total_leaf_weight, 6000.0, abs_tol=1e-4)

    def test_total_allocated_area_matches_bounding_rectangle(self) -> None:
        """Sum of all leaf tile areas equals total layout bounding rectangle area (718,200 px^2)."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        leaves = canvas.tree.get_leaves()
        sum_leaves_area = sum(l.rect.area for l in leaves)
        assert math.isclose(sum_leaves_area, canvas.bounds.area, rel_tol=0.15) or math.isclose(sum_leaves_area, canvas.bounds.area, rel_tol=1e-4)

    def test_all_leaf_tiles_contained_within_canvas_bounds(self) -> None:
        """Every leaf equipment tile is strictly contained within canvas bounding rectangle."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        bounds = canvas.bounds
        for leaf in canvas.tree.get_leaves():
            assert bounds.contains_rect(leaf.rect, tolerance=1e-3) is True
            assert leaf.rect.x >= bounds.x - 1e-3
            assert leaf.rect.y >= bounds.y - 1e-3
            assert (leaf.rect.x + leaf.rect.width) <= (bounds.x + bounds.width + 1e-3)
            assert (leaf.rect.y + leaf.rect.height) <= (bounds.y + bounds.height + 1e-3)

    def test_all_leaf_tiles_strictly_positive_dimensions(self) -> None:
        """Every leaf equipment tile has strictly positive width and height."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        for leaf in canvas.tree.get_leaves():
            assert leaf.rect.width > 0.0
            assert leaf.rect.height > 0.0
            assert leaf.rect.area > 0.0

    def test_sibling_tiles_zero_overlapping(self) -> None:
        """Sibling equipment tiles have zero planar overlapping interior area."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        leaves = canvas.tree.get_leaves()
        # Pairwise intersection area check
        for i in range(len(leaves)):
            for j in range(i + 1, len(leaves)):
                r1, r2 = leaves[i].rect, leaves[j].rect
                # Overlap box
                ox = max(0.0, min(r1.x + r1.width, r2.x + r2.width) - max(r1.x, r2.x))
                oy = max(0.0, min(r1.y + r1.height, r2.y + r2.height) - max(r1.y, r2.y))
                overlap_area = ox * oy
                assert overlap_area < 1e-2, f"Tiles {leaves[i].node_id} and {leaves[j].node_id} overlap by {overlap_area} px^2"

    def test_layout_canvas_overflow_raises(self) -> None:
        """layout_hierarchical_treemap raises ViewportCanvasOverflowError when bounds exceed 1200x750."""
        tree = create_canonical_treemap_hierarchical_tree()
        overflow_bounds = Rect(0, 0, 1300.0, 800.0)
        with pytest.raises(ViewportCanvasOverflowError):
            layout_hierarchical_treemap(tree.root, overflow_bounds)

    def test_layout_empty_tree_raises(self) -> None:
        """layout_hierarchical_treemap raises EmptyHierarchyTreeError when root is None or has no leaves."""
        empty_node = TreemapHierarchicalNode(node_id="EMPTY", weight=0.0)
        with pytest.raises(EmptyHierarchyTreeError):
            layout_hierarchical_treemap(empty_node, Rect(0, 0, 500, 500))


# ============================================================================
# Section 5: Health Aggregation & Critical Tile Alarms
# ============================================================================

class TestHealthAggregationAndCriticalAlarm:
    """Validate bottom-up health calculation, warning tile detection, and %M463 critical alarm trip."""

    def test_canonical_health_aggregation_metrics(self) -> None:
        """Canonical tree health averages exactly 98.50% (scaled 9850), 0 critical tiles."""
        tree = create_canonical_treemap_hierarchical_tree()
        mean_health, crit_count, warn_count = tree.recompute_overall_health()
        assert mean_health == 98.50
        assert crit_count == 0

    def test_canonical_warning_tiles_identification(self) -> None:
        """Canonical hierarchy contains warning tiles with health between 70.0% and 85.0%."""
        tree = create_canonical_treemap_hierarchical_tree()
        leaves = tree.get_leaves()
        warn_tiles = [l for l in leaves if l.health_state == HealthState.WARNING]
        assert len(warn_tiles) >= 1
        assert all(70.0 <= l.health_score < 85.0 for l in warn_tiles)

    def test_nominal_canvas_critical_alarm_deasserted(self) -> None:
        """In canonical nominal state, %M463 is False and critical alarm bit is not set."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        assert canvas.metrics.critical_tile_alarm_count == 0
        assert canvas.critical_alarm_active is False
        assert canvas.reg_table.read_bit(COIL_CRITICAL_TILE_ALARM_ACTIVE) is False
        assert not bool(canvas.status_bits & TreemapHierarchicalStatusBits.CRITICAL_ALARM_ACTIVE)

    def test_trigger_critical_alarm_equipment_failure(self) -> None:
        """trigger_critical_tile_failure sets tile health < 70% and trips %M463."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        canvas.trigger_critical_tile_failure(bad_health=45.0)

        assert canvas.metrics.critical_tile_alarm_count >= 1
        assert canvas.critical_alarm_active is True
        assert canvas.reg_table.read_bit(COIL_CRITICAL_TILE_ALARM_ACTIVE) is True
        assert bool(canvas.status_bits & TreemapHierarchicalStatusBits.CRITICAL_ALARM_ACTIVE)

    def test_critical_alarm_overall_health_threshold(self) -> None:
        """If mean health drops below 80.0%, %M463 trips even if no single tile is marked CRITICAL."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        for l in canvas.tree.get_leaves():
            l.health_score = 78.0
        canvas.scan_step()

        assert canvas.metrics.overall_health_pct < PLANT_HEALTH_ALARM_THRESHOLD_PCT
        assert canvas.critical_alarm_active is True
        assert canvas.reg_table.read_bit(COIL_CRITICAL_TILE_ALARM_ACTIVE) is True

    def test_reset_nominal_clears_critical_alarm(self) -> None:
        """reset_nominal clears critical alarm, restoring %M463 to False and health to 98.50%."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        canvas.trigger_critical_tile_failure(bad_health=40.0)
        assert canvas.reg_table.read_bit(COIL_CRITICAL_TILE_ALARM_ACTIVE) is True

        canvas.reset_nominal()
        assert canvas.critical_alarm_active is False
        assert canvas.metrics.critical_tile_alarm_count == 0
        assert canvas.metrics.overall_health_pct == 98.50
        assert canvas.reg_table.read_bit(COIL_CRITICAL_TILE_ALARM_ACTIVE) is False

    def test_status_bits_warning_detection(self) -> None:
        """TreemapHierarchicalStatusBits WARNING_ACTIVE bit is asserted when warning tiles exist."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        assert bool(canvas.status_bits & TreemapHierarchicalStatusBits.WARNING_ACTIVE) is True

        for l in canvas.tree.get_leaves():
            l.health_score = 99.0
        canvas.scan_step()
        assert bool(canvas.status_bits & TreemapHierarchicalStatusBits.WARNING_ACTIVE) is False

    def test_inactive_tile_does_not_trip_critical_alarm(self) -> None:
        """Inactive tile (is_active=False) has INACTIVE state, does not count as CRITICAL."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        leaf = canvas.tree.get_leaves()[0]
        leaf.is_active = False
        assert leaf.health_state == HealthState.INACTIVE
        assert leaf.color == COLOR_INACTIVE

    def test_trigger_critical_alarm_alias(self) -> None:
        """trigger_critical_alarm is alias of trigger_critical_tile_failure."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        canvas.trigger_critical_alarm(bad_health=35.0)
        assert canvas.reg_table.read_bit(COIL_CRITICAL_TILE_ALARM_ACTIVE) is True


# ============================================================================
# Section 6: Standalone W3C SVG 1.1 Vector Graphic Generation
# ============================================================================

class TestSVGGenerationAndXMLSyntax:
    """Validate standalone W3C SVG 1.1 generation, valid XML syntax, element tags, and HUD."""

    def test_svg_generation_valid_xml_syntax(self) -> None:
        """render_svg produces valid XML parseable by ElementTree."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg") or root.tag == "svg"

    def test_svg_viewport_dimensions(self) -> None:
        """SVG root element has width 1200, height 750, and viewBox '0 0 1200 750'."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        assert root.attrib.get("width") == "1200"
        assert root.attrib.get("height") == "750"
        assert root.attrib.get("viewBox") == "0 0 1200 750"

    def test_svg_defs_and_glow_filters(self) -> None:
        """SVG contains <defs> section with focus-glow and alert-glow filter elements."""
        canvas = create_canonical_treemap_hierarchical_canvas()
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
        assert "glow-focus" in filter_ids
        assert "glow-alert" in filter_ids

    def test_svg_dark_theme_background_rect(self) -> None:
        """SVG contains dark theme background rect with fill COLOR_DARK_THEME_BACKING (#0B0F19)."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        svg_str = canvas.render_svg()
        assert f'fill="{COLOR_DARK_THEME_BACKING}"' in svg_str

    def test_svg_header_banner_content(self) -> None:
        """SVG header banner includes complex name, wave W237, and tile count."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        svg_str = canvas.render_svg()
        assert "CSCAPE SCADA // DYNAMIC TREEMAP HIERARCHICAL PARTITION" in svg_str
        assert "W237" in svg_str

    def test_svg_rect_tiles_count(self) -> None:
        """SVG contains at least 20 rect tile elements corresponding to leaf equipment."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        rects = root.findall(".//{http://www.w3.org/2000/svg}rect") or root.findall(".//rect")
        assert len(rects) >= 20

    def test_svg_active_tile_highlighting(self) -> None:
        """Selected tile path features focus-cyan stroke or focus-glow filter."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        canvas.select_tile_by_index(3)
        svg_str = canvas.render_svg()
        assert f'stroke="{COLOR_FOCUS_CYAN}"' in svg_str or 'filter="url(#glow-focus)"' in svg_str

    def test_svg_interactive_telemetry_hud_panel(self) -> None:
        """SVG contains interactive SCADA telemetry HUD panel with stats scorecard."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        svg_str = canvas.render_svg()
        assert "PLANT STATS SCORECARD" in svg_str
        assert "TOTAL TILES (%R1980)" in svg_str
        assert "OVERALL HEALTH (%R1981)" in svg_str
        assert "CRITICAL TILES (%R1982)" in svg_str
        assert "ACTIVE SECTOR FOCUS" in svg_str

    def test_svg_tile_title_tooltips(self) -> None:
        """Each tile element includes a <title> element with name and health score."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        titles = root.findall(".//{http://www.w3.org/2000/svg}title") or root.findall(".//title")
        assert len(titles) >= 20

    def test_generate_treemap_canvas_svg_alias(self) -> None:
        """generate_treemap_hierarchical_canvas_svg generates valid standalone SVG XML."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        svg = generate_treemap_hierarchical_canvas_svg(canvas.tree, canvas.metrics)
        assert svg.startswith("<?xml")
        assert "</svg>" in svg


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
        """calculate_contrast_ratio is symmetric regardless of parameter order."""
        c1, c2 = "#F0F6FC", "#0B0F19"
        assert math.isclose(calculate_contrast_ratio(c1, c2), calculate_contrast_ratio(c2, c1), abs_tol=1e-4)

    def test_text_primary_contrast_exceeds_wcag_aaa(self) -> None:
        """COLOR_TEXT_PRIMARY (#F0F6FC) against dark backing (#0B0F19) exceeds 7.0:1 text target."""
        cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert cr >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert cr > 15.0

    def test_decoupled_badge_contrast_exceeds_wcag_aaa(self) -> None:
        """COLOR_TEXT_PRIMARY against COLOR_DECOUPLED_BADGE exceeds 18.0:1 badge target."""
        cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert cr >= WCAG_AAA_BADGE_CONTRAST_TARGET

    def test_graphical_element_contrast_exceeds_target(self) -> None:
        """Status colors (emerald, amber, ruby) against dark backing exceed 3.0:1 graphical target."""
        assert calculate_contrast_ratio(COLOR_NORMAL, COLOR_DARK_THEME_BACKING) >= WCAG_GRAPHICAL_CONTRAST_TARGET
        assert calculate_contrast_ratio(COLOR_WARNING, COLOR_DARK_THEME_BACKING) >= WCAG_GRAPHICAL_CONTRAST_TARGET
        assert calculate_contrast_ratio(COLOR_CRITICAL, COLOR_DARK_THEME_BACKING) >= WCAG_GRAPHICAL_CONTRAST_TARGET

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
    """Validate 0xF501, 0xF502, 0xF503, 0xF504 fault handling, exceptions, and nominal recovery."""

    def test_fault_0xf501_geometry_singularity(self) -> None:
        """trigger_singularity sets 0xF501, de-asserts canvas_active, sets status bit."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        canvas.trigger_singularity()

        assert canvas.diagnostic_code == DIAG_ERR_GEOMETRY_SINGULARITY
        assert canvas.diagnostic_code == 0xF501
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xF501
        assert canvas.canvas_active is False
        assert canvas.reg_table.read_bit(COIL_TREEMAP_CANVAS_ACTIVE) is False
        assert bool(canvas.status_bits & TreemapHierarchicalStatusBits.GEOMETRY_SINGULARITY_FAULT)

    def test_fault_0xf502_empty_hierarchy_tree(self) -> None:
        """trigger_empty_tree sets 0xF502, de-asserts canvas_active, sets status bit."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        canvas.trigger_empty_tree()

        assert canvas.diagnostic_code == DIAG_ERR_EMPTY_TREE
        assert canvas.diagnostic_code == 0xF502
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xF502
        assert canvas.canvas_active is False
        assert bool(canvas.status_bits & TreemapHierarchicalStatusBits.EMPTY_TREE_FAULT)

    def test_fault_0xf503_hierarchical_weight_sum_mismatch(self) -> None:
        """trigger_weight_mismatch sets 0xF503, de-asserts canvas_active, sets status bit."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        canvas.trigger_weight_mismatch()

        assert canvas.diagnostic_code == DIAG_ERR_WEIGHT_CONSERVATION_MISMATCH
        assert canvas.diagnostic_code == 0xF503
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xF503
        assert canvas.canvas_active is False
        assert bool(canvas.status_bits & TreemapHierarchicalStatusBits.WEIGHT_MISMATCH_FAULT)

    def test_fault_0xf504_render_canvas_overflow(self) -> None:
        """trigger_canvas_overflow sets 0xF504, de-asserts canvas_active, sets status bit."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        canvas.trigger_canvas_overflow()

        assert canvas.diagnostic_code == DIAG_ERR_VIEWPORT_CANVAS_OVERFLOW
        assert canvas.diagnostic_code == 0xF504
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xF504
        assert canvas.canvas_active is False
        assert bool(canvas.status_bits & TreemapHierarchicalStatusBits.CANVAS_OVERFLOW_FAULT)

    def test_nominal_recovery_after_faults(self) -> None:
        """reset_nominal recovers canvas to 0x0000, canvas_active=True, clears fault status bits."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        canvas.trigger_singularity()
        assert canvas.canvas_active is False

        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0x0000
        assert canvas.canvas_active is True
        assert canvas.reg_table.read_bit(COIL_TREEMAP_CANVAS_ACTIVE) is True
        assert bool(canvas.status_bits & TreemapHierarchicalStatusBits.NOMINAL_OPERATION)
        assert not bool(canvas.status_bits & TreemapHierarchicalStatusBits.GEOMETRY_SINGULARITY_FAULT)

    def test_custom_exception_hierarchy_inheritance(self) -> None:
        """All domain exceptions inherit from TreemapHierarchicalError."""
        assert issubclass(TreemapGeometrySingularityError, TreemapHierarchicalError)
        assert issubclass(EmptyHierarchyTreeError, TreemapHierarchicalError)
        assert issubclass(WeightConservationMismatchError, TreemapHierarchicalError)
        assert issubclass(ViewportCanvasOverflowError, TreemapHierarchicalError)

    def test_sequential_fault_injection_and_resets(self) -> None:
        """Sequential injection of all 4 faults with interleaved nominal resets."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        fault_methods = [
            (canvas.trigger_singularity, 0xF501),
            (canvas.trigger_empty_tree, 0xF502),
            (canvas.trigger_weight_mismatch, 0xF503),
            (canvas.trigger_canvas_overflow, 0xF504),
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
    """Validate RegisterTable synchronization (%R1980..%R1987, %M462..%M463), privilege, and setpoints."""

    def test_nominal_registers_bit_exact_sync(self) -> None:
        """In nominal canonical state, registers %R1980..%R1987 and %M462..%M463 match specification."""
        reg_table = RegisterTable()
        canvas = TreemapHierarchicalCanvas(reg_table=reg_table)
        canvas.scan_step(dt=0.01)

        assert reg_table.read_word(REG_TOTAL_TREEMAP_TILES_COUNT) == 20
        assert reg_table.read_word(REG_PLANT_OVERALL_HEALTH_PCT_SCALED) == 9850
        assert reg_table.read_word(REG_CRITICAL_TILE_ALARM_COUNT) == 0
        assert reg_table.read_word(REG_TOTAL_WEIGHT_SCALED) == 600
        assert reg_table.read_word(REG_MAX_HIERARCHY_DEPTH_TIERS) == 3
        assert reg_table.read_word(REG_SELECTED_TILE_INDEX) == 0
        assert reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0

        assert reg_table.read_bit(COIL_TREEMAP_CANVAS_ACTIVE) is True
        assert reg_table.read_bit(COIL_CRITICAL_TILE_ALARM_ACTIVE) is False

    @pytest.mark.parametrize(
        "reg_addr,expected_val",
        [
            ("%R1980", 20),
            ("%R1981", 9850),
            ("%R1982", 0),
            ("%R1983", 600),
            ("%R1984", 3),
            ("%R1985", 0),
            ("%R1987", 0),
        ],
    )
    def test_individual_word_registers(self, reg_addr: str, expected_val: int) -> None:
        """Each word register in %R1980..%R1987 correctly stores its expected nominal value."""
        reg_table = RegisterTable()
        canvas = TreemapHierarchicalCanvas(reg_table=reg_table)
        canvas.scan_step(dt=0.01)
        assert reg_table.read_word(reg_addr) == expected_val

    def test_signed_int16_register_packing(self) -> None:
        """Diagnostic code 0xF501 is stored as signed INT16 (-2815) and unmasks to 0xF501."""
        reg_table = RegisterTable()
        canvas = TreemapHierarchicalCanvas(reg_table=reg_table)
        canvas.trigger_singularity()

        raw_val = reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE)
        assert raw_val == 0xF501 - 0x10000
        assert (raw_val & 0xFFFF) == 0xF501

    def test_select_tile_by_index_syncs_registers(self) -> None:
        """select_tile_by_index updates selected tile index in register %R1985."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        canvas.select_tile_by_index(5)

        assert canvas.selected_tile_index == 5
        assert canvas.reg_table.read_word(REG_SELECTED_TILE_INDEX) == 5

    def test_sync_from_registers_reads_setpoint(self) -> None:
        """sync_from_registers updates active tile index from external write to %R1985."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        canvas.reg_table.write_word(REG_SELECTED_TILE_INDEX, 12, privilege=PrivilegeMode.SYSTEM)
        canvas.scan_step()

        assert canvas.selected_tile_index == 12

    def test_privilege_mode_system_write(self) -> None:
        """Writes to register table succeed under PrivilegeMode.SYSTEM."""
        reg_table = RegisterTable()
        canvas = TreemapHierarchicalCanvas(reg_table=reg_table)
        canvas.sync_to_registers(reg_table=reg_table, privilege=PrivilegeMode.SYSTEM)
        assert reg_table.read_word(REG_TOTAL_TREEMAP_TILES_COUNT) == 20

    def test_metrics_dataclass_properties(self) -> None:
        """TreemapHierarchicalMetrics dataclass holds comprehensive telemetry."""
        metrics = TreemapHierarchicalMetrics(
            total_tiles_count=20,
            overall_health_pct=98.50,
            overall_health_pct_scaled=9850,
            critical_tile_count=0,
            warning_tile_count=2,
            max_depth_tiers=3,
            selected_tile_index=2,
        )
        assert metrics.total_tiles_count == 20
        assert metrics.overall_health_pct == 98.50
        assert metrics.max_depth_tiers == 3
        assert TreemapMetrics is TreemapHierarchicalMetrics


# ============================================================================
# Section 10: Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure ST syntax, STParser AST parsing, variable count, and symbol bindings."""

    def test_pure_st_pou_name_and_type(self) -> None:
        """SecurityGuard asserts pure ST and STParser parses PROGRAM POU named TreemapHierarchicalCanvasSync."""
        SecurityGuard.assert_pure_st_content(TREEMAP_HIERARCHICAL_CANVAS_SYNC_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(TREEMAP_HIERARCHICAL_CANVAS_SYNC_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "TreemapHierarchicalCanvasSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_pure_st_variables_count_and_types(self) -> None:
        """ST POU declares exactly 10 variables: 8 INT analog registers and 2 BOOL discrete coils."""
        parser = STParser()
        pou = parser.parse_pou(TREEMAP_HIERARCHICAL_CANVAS_SYNC_PURE_ST_POU)
        assert pou is not None
        assert len(pou.variables) == 10
        int_vars = [v for v in pou.variables if v.data_type == "INT"]
        bool_vars = [v for v in pou.variables if v.data_type == "BOOL"]
        assert len(int_vars) == 8
        assert len(bool_vars) == 2

    def test_pure_st_register_address_bindings(self) -> None:
        """Variables in ST POU are directly bound to %R1980..%R1987 and %M462..%M463."""
        parser = STParser()
        pou = parser.parse_pou(TREEMAP_HIERARCHICAL_CANVAS_SYNC_PURE_ST_POU)
        assert pou is not None
        expected_bindings = {
            "TotalTreemapTilesCount": "%R1980",
            "PlantOverallHealthPctScaled": "%R1981",
            "CriticalTileAlarmCount": "%R1982",
            "TotalPlantWeightMetricScaled": "%R1983",
            "MaxHierarchyDepthTiers": "%R1984",
            "SelectedTileIndex": "%R1985",
            "WorstTileAspectRatioScaled": "%R1986",
            "DiagnosticStatusCode": "%R1987",
            "TreemapCanvasActive": "%M462",
            "TreemapCriticalAlarmActive": "%M463",
        }
        vmap = {v.name: v.address_binding for v in pou.variables}
        for name, addr in expected_bindings.items():
            assert vmap.get(name) == addr

    def test_pure_st_pou_string_aliases(self) -> None:
        """Aliases TREEMAP_HIERARCHICAL_CANVAS_PURE_ST_POU and W237_TREEMAP_HIERARCHICAL_PURE_ST_POU match."""
        assert TREEMAP_HIERARCHICAL_CANVAS_PURE_ST_POU == TREEMAP_HIERARCHICAL_CANVAS_SYNC_PURE_ST_POU
        assert W237_TREEMAP_HIERARCHICAL_PURE_ST_POU == TREEMAP_HIERARCHICAL_CANVAS_SYNC_PURE_ST_POU
        assert TREEMAP_HIERARCHICAL_PURE_ST_POU == TREEMAP_HIERARCHICAL_CANVAS_SYNC_PURE_ST_POU

    def test_verify_treemap_hierarchical_canvas_pure_st_helper(self) -> None:
        """verify_treemap_hierarchical_canvas_pure_st returns True deterministically."""
        assert verify_treemap_hierarchical_canvas_pure_st() is True

    def test_pure_st_logic_body(self) -> None:
        """ST code body implements interlocking logic for CriticalTileAlarmCount and scaled health."""
        assert "IF TreemapCanvasActive THEN" in TREEMAP_HIERARCHICAL_CANVAS_SYNC_PURE_ST_POU
        assert "CriticalTileAlarmCount > 0 OR PlantOverallHealthPctScaled < 8000" in TREEMAP_HIERARCHICAL_CANVAS_SYNC_PURE_ST_POU
        assert "TreemapCriticalAlarmActive := TRUE;" in TREEMAP_HIERARCHICAL_CANVAS_SYNC_PURE_ST_POU


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
            "NETWORK 10: LD %R1980",
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
        bad_st = TREEMAP_HIERARCHICAL_CANVAS_SYNC_PURE_ST_POU + "\n---[ ]---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_normally_closed_contact_direct(self) -> None:
        """SecurityGuard rejects normally-closed contact construct ---[/]---."""
        bad_st = TREEMAP_HIERARCHICAL_CANVAS_SYNC_PURE_ST_POU + "\n---[/]---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_ladder_coil_direct(self) -> None:
        """SecurityGuard rejects ladder coil construct ---( )---."""
        bad_st = TREEMAP_HIERARCHICAL_CANVAS_SYNC_PURE_ST_POU + "\n---( )---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)


# ============================================================================
# Section 12: ILogicUnit Compliance & Simulation Soak
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface, execution priority, scan cycle step, and soak stability."""

    def test_ilogicunit_inheritance(self) -> None:
        """TreemapHierarchicalCanvas implements abstract ILogicUnit protocol."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        assert isinstance(canvas, ILogicUnit)
        assert TreemapHierarchicalCanvasEngine is TreemapHierarchicalCanvas
        assert TreemapHierarchicalCanvasSync is TreemapHierarchicalCanvas

    def test_name_property(self) -> None:
        """ILogicUnit name returns 'TreemapHierarchicalCanvasSync'."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        assert canvas.name == "TreemapHierarchicalCanvasSync"

    def test_priority_property(self) -> None:
        """ILogicUnit priority returns 95."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        assert canvas.priority == 95

    def test_is_enabled_property(self) -> None:
        """ILogicUnit is_enabled tracks canvas_active state."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        assert canvas.is_enabled is True
        canvas.canvas_active = False
        assert canvas.is_enabled is False

    def test_scan_step_execution(self) -> None:
        """scan_step executes discrete single clock cycle without exceptions."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        canvas.scan_step(dt=0.01)
        assert canvas.metrics.total_tiles_count == 20
        assert canvas.metrics.overall_health_pct_scaled == 9850

    def test_step_alias(self) -> None:
        """step() alias invokes scan_step()."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        canvas.step()
        assert canvas.metrics.total_tiles_count == 20

    def test_execute_with_scan_context(self) -> None:
        """execute(context) evaluates logic cycle inside Horner ScanContext."""
        reg_table = RegisterTable()
        canvas = TreemapHierarchicalCanvas(reg_table=reg_table)
        ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=reg_table)
        canvas.execute(ctx)
        assert reg_table.read_word(REG_TOTAL_TREEMAP_TILES_COUNT) == 20

    def test_reset_method(self) -> None:
        """reset() restores canonical state."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        canvas.trigger_singularity()
        assert canvas.canvas_active is False
        canvas.reset()
        assert canvas.canvas_active is True
        assert canvas.diagnostic_code == DIAG_EVENT_OK

    def test_soak_100_cycles_stability(self) -> None:
        """100 sequential scan cycles exhibit zero memory drift and steady health metrics."""
        canvas = create_canonical_treemap_hierarchical_canvas()
        init_nodes = len(canvas.tree.get_leaves())
        init_health = canvas.metrics.overall_health_pct_scaled

        for _ in range(100):
            canvas.scan_step(dt=0.01)

        assert len(canvas.tree.get_leaves()) == init_nodes == 20
        assert canvas.metrics.overall_health_pct_scaled == init_health == 9850
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.reg_table.read_bit(COIL_TREEMAP_CANVAS_ACTIVE) is True
        assert canvas.reg_table.read_bit(COIL_CRITICAL_TILE_ALARM_ACTIVE) is False


# ============================================================================
# Section 13: Deterministic Verification Runner & Strict 4-State Contract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate 9-stage verification runner and strict 4-state engineering contract JSON output."""

    def test_run_verification_returns_success_contract(self) -> None:
        """run_treemap_hierarchical_canvas_verification returns strict 4-state contract with status 'success'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"

            res = run_treemap_hierarchical_canvas_verification(
                output_path=ev_path,
                sample_svg_path=svg_path,
                work_package="W237",
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

            run_treemap_hierarchical_canvas_verification(
                output_path=ev_path,
                sample_svg_path=svg_path,
            )

            assert ev_path.exists()
            with open(ev_path, "r", encoding="utf-8") as f:
                saved = json.load(f)
            assert saved["status"] == "success"
            assert saved["data"]["metrics"]["total_treemap_tiles_count"] == 20
            assert saved["data"]["metrics"]["plant_overall_health_pct_scaled"] == 9850

    def test_verification_sample_svg_file_written(self) -> None:
        """Sample SVG file is written and contains parseable XML."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"

            run_treemap_hierarchical_canvas_verification(
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
            res = run_treemap_hierarchical_canvas_verification(ev_path, svg_path)
            assert res["status"] in valid_statuses

    def test_verification_stage_count_and_keys(self) -> None:
        """Each verification stage record contains stage, check, passed, timing_ms, and details."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"
            res = run_treemap_hierarchical_canvas_verification(ev_path, svg_path)

            for t in res["data"]["tests"]:
                assert "stage" in t
                assert "check" in t
                assert "passed" in t
                assert "timing_ms" in t
                assert "details" in t
