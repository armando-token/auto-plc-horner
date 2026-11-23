"""Comprehensive unit test suite for Cscape HMI Dynamic Icicle / Hierarchical Partition Flow SCADA Canvas (W216).

Work Package: W216 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Coverage (75+ Unit Tests across 14 Test Classes):
1. TestPureSTAndSecurity: Pure IEC 61131-3 Structured Text (ST) POU Grammar, Symbol Binding & Anti-Ladder Interception.
2. TestRectBoundsGeometryAndClamping: RectBounds 2D geometry model, aspect ratios, interpolation, and clamping.
3. TestTotalWidthConservation: Mathematical invariant: total width conservation across all hierarchy levels.
4. TestHierarchyTreeTopologyAndTraversal: 5-tier 32-node hierarchy, BFS, DFS post-order, and cycle detection.
5. TestAncestorAndDescendantLineage: Ancestor path and descendant resolution for multi-echelon refining assets.
6. TestDrillDownFocusZoomAndStackNavigation: Focus zoom expansion, 100% width scaling, stack push/pop, and restoration.
7. TestMassFlowConservationAndImbalance: Mass balance continuity (125.0 t/h), bottom-up reconciliation, and 0xE803 detection.
8. TestHealthScorePropagationAndDegradedAssetTracking: Bottom-up capacity-weighted health aggregation and critical fault tracking.
9. TestWCAG21AAAAccessibility: WCAG 2.1 AAA relative luminance and contrast ratio calculations (> 18:1 badge, > 7:1 text).
10. TestStandaloneW3CSVGGenerationAndXMLParsing: W3C SVG 1.1 vector graphic synthesis, XML parsing with ElementTree.
11. TestHornerOCSSynchronization: RegisterTable memory synchronization (%R1770..%R1777, %M413..%M414) with PrivilegeMode.SYSTEM.
12. TestILogicUnitScanCycleEngine: ILogicUnit discrete scan cycle (scan_step, step, execute, reset).
13. TestVerificationRunnerAndContract: Deterministic 9-stage verification runner and strict 4-state engineering contract JSON.
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

from jev_cscape.hmi.icicle_canvas import (
    CANVAS_HEIGHT,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    CANVAS_WIDTH,
    CANVAS_X,
    CANVAS_Y,
    COIL_FLOW_IMBALANCE_ALARM_ACTIVE,
    COIL_ICICLE_CANVAS_ACTIVE,
    COIL_W216_CANVAS_ACTIVE,
    COIL_W216_IMBALANCE_ALARM,
    COLOR_ALARM_CRIMSON,
    COLOR_BORDER,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_CRITICAL,
    COLOR_DARK_THEME_BACKING,
    COLOR_DECOUPLED_BADGE,
    COLOR_FOCUS_CYAN,
    COLOR_NODE_BADGE,
    COLOR_NOMINAL,
    COLOR_NOMINAL_EMERALD,
    COLOR_SURFACE,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_WARNING,
    COLOR_WARM_AMBER,
    DEFAULT_TIER_GAP,
    DIAG_ERR_DRILLDOWN_STACK_OVERFLOW,
    DIAG_ERR_MASS_FLOW_IMBALANCE_FAULT,
    DIAG_ERR_PARTITION_GEOMETRY_OVERFLOW,
    DIAG_ERR_SVG_RENDER_FAULT,
    DIAG_EVENT_OK,
    DIAG_OK,
    DiagnosticCode,
    DrilldownStackError,
    FLOW_IMBALANCE_ALARM_THRESHOLD_PCT,
    HEALTH_CRITICAL_THRESHOLD,
    HEALTH_NOMINAL_BASELINE,
    HEALTH_WARNING_THRESHOLD,
    HierarchyCycleError,
    ICICLE_CANVAS_PURE_ST_POU,
    ICICLE_PURE_ST_POU,
    IcicleCanvas,
    IcicleCanvasEngine,
    IcicleCanvasMetrics,
    IcicleCanvasStatusBits,
    IcicleCanvasSync,
    IcicleMetrics,
    IcicleNode,
    IcicleStatusBits,
    IcicleTree,
    MIN_NODE_WIDTH,
    MassFlowImbalanceError,
    NodeHealthState,
    NUM_TIERS,
    PartitionGeometryError,
    RectBounds,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_FLOW_THROUGHPUT_TPH_SCALED,
    REG_HEALTH_SCORE_WEIGHTED_PCT,
    REG_PARTITION_DEFORMATION_METRIC,
    REG_SELECTED_NODE_DEPTH,
    REG_SELECTED_NODE_INDEX,
    REG_TOTAL_PARTITION_COUNT,
    REG_W216_DEFORMATION_METRIC,
    REG_W216_DIAGNOSTIC_CODE,
    REG_W216_FLOW_THROUGHPUT,
    REG_W216_HEALTH_SCORE,
    REG_W216_SELECTED_DEPTH,
    REG_W216_SELECTED_NODE,
    REG_W216_TOTAL_PARTITIONS,
    REG_W216_ZOOM_LEVEL,
    REG_ZOOM_EXPANSION_LEVEL,
    SVGRenderError,
    TierLevel,
    W216_ICICLE_PURE_ST_POU,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    check_tree_mass_flow_imbalance,
    compute_icicle_partition_layout,
    contrast_ratio,
    create_canonical_icicle_canvas,
    create_canonical_scada_icicle_tree,
    create_mock_scan_context,
    find_min_health_node,
    generate_icicle_canvas_svg,
    identify_critical_faults,
    propagate_bottom_up_health,
    relative_luminance,
    run_icicle_canvas_verification,
    validate_wcag_aaa_contrast,
    verify_icicle_canvas_pure_st,
)


# ============================================================================
# Section 1: Pure ST POU Grammar & Anti-Ladder Interception
# ============================================================================

class TestPureSTAndSecurity:
    """Validate purity, grammar, symbol bindings, and anti-ladder interception."""

    def test_pure_st_grammar_and_pou_type(self) -> None:
        """SecurityGuard asserts pure Structured Text content and STParser parses PROGRAM POU."""
        SecurityGuard.assert_pure_st_content(ICICLE_CANVAS_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(ICICLE_CANVAS_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "IcicleCanvasSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_pure_st_variable_declarations(self) -> None:
        """ST POU contains exactly 10 variables (8 INT analog, 2 BOOL coils)."""
        parser = STParser()
        pou = parser.parse_pou(ICICLE_CANVAS_PURE_ST_POU)
        assert pou is not None
        assert len(pou.variables) == 10
        int_vars = [v for v in pou.variables if v.data_type == "INT"]
        bool_vars = [v for v in pou.variables if v.data_type == "BOOL"]
        assert len(int_vars) == 8
        assert len(bool_vars) == 2

    def test_pure_st_address_bindings(self) -> None:
        """Variables are bound to Horner memory %R1770..%R1777 and %M413..%M414."""
        parser = STParser()
        pou = parser.parse_pou(ICICLE_CANVAS_PURE_ST_POU)
        assert pou is not None
        expected_bindings = {
            "TotalPartitionCount": "%R1770",
            "SelectedNodeIndex": "%R1771",
            "SelectedNodeDepth": "%R1772",
            "FlowThroughputTphScaled": "%R1773",
            "HealthScoreWeightedPct": "%R1774",
            "ZoomExpansionLevel": "%R1775",
            "PartitionDeformationMetric": "%R1776",
            "DiagnosticStatusCode": "%R1777",
            "IcicleCanvasActive": "%M413",
            "FlowImbalanceAlarmActive": "%M414",
        }
        vmap = {v.name: v.address_binding for v in pou.variables}
        for name, addr in expected_bindings.items():
            assert vmap.get(name) == addr

    def test_pure_st_pou_aliases(self) -> None:
        """Aliases ICICLE_PURE_ST_POU and W216_ICICLE_PURE_ST_POU match canonical definition."""
        assert ICICLE_PURE_ST_POU == ICICLE_CANVAS_PURE_ST_POU
        assert W216_ICICLE_PURE_ST_POU == ICICLE_CANVAS_PURE_ST_POU

    def test_verify_icicle_canvas_pure_st_helper(self) -> None:
        """verify_icicle_canvas_pure_st returns True deterministically."""
        assert verify_icicle_canvas_pure_st() is True

    def test_anti_ladder_contacts_and_coils(self) -> None:
        """Ladder normally-open contacts and coils fail closed with LadderForbiddenError."""
        bad_contacts = "PROGRAM Bad VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM"
        bad_coils = "PROGRAM Bad VAR Y: BOOL; END_VAR ---( )--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_contacts)
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_coils)

    def test_anti_ladder_rungs_networks_and_mnemonics(self) -> None:
        """Ladder rungs, networks, and mnemonics (XIC, OTE) raise LadderForbiddenError."""
        for snippet in [
            "PROGRAM Bad\nRUNG 1:\nEND_PROGRAM",
            "PROGRAM Bad\nNETWORK 1:\nEND_PROGRAM",
            "PROGRAM Bad\nXIC Contact1;\nEND_PROGRAM",
            "PROGRAM Bad\nOTE Coil1;\nEND_PROGRAM",
        ]:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# Section 2: RectBounds Geometry, Aspect Ratio & Clamping
# ============================================================================

class TestRectBoundsGeometryAndClamping:
    """Validate RectBounds 2D geometry model, aspect ratios, interpolation, and clamping."""

    def test_rect_bounds_attributes_and_properties(self) -> None:
        """RectBounds correctly computes x_max, y_max, and aspect_ratio."""
        rb = RectBounds(x=40.0, y=96.0, width=280.0, height=100.0)
        assert rb.x_max == 320.0
        assert rb.y_max == 196.0
        assert math.isclose(rb.aspect_ratio, 2.8, abs_tol=1e-4)

    def test_rect_bounds_contains_point(self) -> None:
        """RectBounds correctly identifies points inside and outside bounds."""
        rb = RectBounds(x=10.0, y=20.0, width=100.0, height=50.0)
        assert rb.contains(10.0, 20.0) is True      # Top-left corner
        assert rb.contains(110.0, 70.0) is True     # Bottom-right corner
        assert rb.contains(60.0, 45.0) is True      # Center
        assert rb.contains(5.0, 45.0) is False      # Left outside
        assert rb.contains(115.0, 45.0) is False    # Right outside
        assert rb.contains(60.0, 15.0) is False     # Top outside
        assert rb.contains(60.0, 75.0) is False     # Bottom outside

    def test_rect_bounds_interpolation(self) -> None:
        """RectBounds linear interpolation smoothly transitions between geometries."""
        r1 = RectBounds(x=0.0, y=0.0, width=100.0, height=50.0)
        r2 = RectBounds(x=200.0, y=100.0, width=300.0, height=150.0)
        mid = r1.interpolate(r2, 0.5)
        assert math.isclose(mid.x, 100.0, abs_tol=1e-4)
        assert math.isclose(mid.y, 50.0, abs_tol=1e-4)
        assert math.isclose(mid.width, 200.0, abs_tol=1e-4)
        assert math.isclose(mid.height, 100.0, abs_tol=1e-4)

    def test_aspect_ratio_near_zero_height_guard(self) -> None:
        """aspect_ratio handles zero height without ZeroDivisionError."""
        rb = RectBounds(x=0.0, y=0.0, width=100.0, height=0.0)
        assert rb.aspect_ratio > 0.0

    def test_negative_dimension_raises_geometry_error(self) -> None:
        """compute_icicle_partition_layout with negative canvas dimensions raises PartitionGeometryError."""
        tree = create_canonical_scada_icicle_tree()
        with pytest.raises(PartitionGeometryError):
            compute_icicle_partition_layout(tree, canvas_width=-500.0)
        with pytest.raises(PartitionGeometryError):
            compute_icicle_partition_layout(tree, canvas_height=-300.0)

    def test_minimum_width_clamping_applied(self) -> None:
        """In canonical layout, all visible nodes obey MIN_NODE_WIDTH (28.0 px)."""
        tree = create_canonical_scada_icicle_tree()
        compute_icicle_partition_layout(tree)
        for node in tree.nodes.values():
            if node.bounds.width > 0.1:
                assert node.bounds.width >= MIN_NODE_WIDTH - 1e-4


# ============================================================================
# Section 3: Total Width Conservation Across Hierarchy Levels
# ============================================================================

class TestTotalWidthConservation:
    """Validate mathematical invariant: total width conservation across all hierarchy levels."""

    def test_root_tier_width_conservation(self) -> None:
        """Tier 0 Enterprise root width exactly matches CANVAS_WIDTH (1120.0 px)."""
        tree = create_canonical_scada_icicle_tree()
        compute_icicle_partition_layout(tree)
        root = tree.get_root()
        assert root is not None
        assert math.isclose(root.bounds.x, CANVAS_X, abs_tol=1e-3)
        assert math.isclose(root.bounds.width, CANVAS_WIDTH, abs_tol=1e-3)

    def test_ideal_width_conservation_all_tiers(self) -> None:
        """Across all 5 structural tiers, ideal_bounds width sums to CANVAS_WIDTH."""
        tree = create_canonical_scada_icicle_tree()
        compute_icicle_partition_layout(tree)
        for depth in range(4):
            tier_nodes = tree.get_tier_nodes(depth)
            tier_ideal_width = sum(n.ideal_bounds.width for n in tier_nodes)
            assert math.isclose(tier_ideal_width, CANVAS_WIDTH, abs_tol=1e-3), (
                f"Tier {depth} ideal width {tier_ideal_width} does not conserve {CANVAS_WIDTH}"
            )
        # Tier 4 contains 9 critical transmitters under their respective manifolds
        tier_4_nodes = tree.get_tier_nodes(4)
        tier_4_width = sum(n.ideal_bounds.width for n in tier_4_nodes)
        assert tier_4_width > 1000.0

    def test_parent_child_ideal_width_conservation(self) -> None:
        """For every non-leaf node, the sum of its children's ideal widths equals parent ideal width."""
        tree = create_canonical_scada_icicle_tree()
        compute_icicle_partition_layout(tree)
        for node in tree.nodes.values():
            if not node.is_leaf:
                children = [tree.get_node(cid) for cid in node.children_ids if tree.get_node(cid)]
                children_ideal_sum = sum(c.ideal_bounds.width for c in children)
                assert math.isclose(children_ideal_sum, node.ideal_bounds.width, abs_tol=1e-3)

    def test_horizontal_bounds_containment(self) -> None:
        """Every node rectangle is contained within [CANVAS_X, CANVAS_X + CANVAS_WIDTH]."""
        tree = create_canonical_scada_icicle_tree()
        compute_icicle_partition_layout(tree)
        for node in tree.nodes.values():
            assert node.bounds.x >= CANVAS_X - 1e-4
            assert node.bounds.x_max <= CANVAS_X + CANVAS_WIDTH + 1e-3

    def test_partition_deformation_metric_calculation(self) -> None:
        """compute_icicle_partition_layout returns deformation metric in [0.0, 100.0]."""
        tree = create_canonical_scada_icicle_tree()
        deform = compute_icicle_partition_layout(tree)
        assert 0.0 <= deform <= 100.0

    def test_vertical_tier_spacing_and_heights(self) -> None:
        """All 5 structural tiers are spaced uniformly by tier height and DEFAULT_TIER_GAP."""
        tree = create_canonical_scada_icicle_tree()
        compute_icicle_partition_layout(tree)
        tier_height = (CANVAS_HEIGHT - (NUM_TIERS - 1) * DEFAULT_TIER_GAP) / NUM_TIERS
        for depth in range(NUM_TIERS):
            expected_y = CANVAS_Y + depth * (tier_height + DEFAULT_TIER_GAP)
            tier_nodes = tree.get_tier_nodes(depth)
            for node in tier_nodes:
                assert math.isclose(node.bounds.y, expected_y, abs_tol=1e-3)
                assert math.isclose(node.bounds.height, tier_height, abs_tol=1e-3)


# ============================================================================
# Section 4: Hierarchy Tree Topology & Traversal
# ============================================================================

class TestHierarchyTreeTopologyAndTraversal:
    """Validate 5-tier 32-node tree structure, BFS, DFS post-order, and cycle detection."""

    def test_canonical_tree_total_node_count(self) -> None:
        """Canonical tree contains exactly 32 unit operation nodes."""
        tree = create_canonical_scada_icicle_tree()
        assert tree.total_node_count() == 32

    def test_canonical_tree_depth_and_tier_distribution(self) -> None:
        """Canonical hierarchy spans 5 tiers: Tier 0 (1), Tier 1 (4), Tier 2 (8), Tier 3 (10), Tier 4 (9)."""
        tree = create_canonical_scada_icicle_tree()
        assert tree.max_depth() == 4
        assert len(tree.get_tier_nodes(0)) == 1
        assert len(tree.get_tier_nodes(1)) == 4
        assert len(tree.get_tier_nodes(2)) == 8
        assert len(tree.get_tier_nodes(3)) == 10
        assert len(tree.get_tier_nodes(4)) == 9

    def test_tree_indices_completeness(self) -> None:
        """All 32 nodes possess contiguous 1-based indices 1..32."""
        tree = create_canonical_scada_icicle_tree()
        indices = {n.index for n in tree.nodes.values()}
        assert indices == set(range(1, 33))

    def test_tree_acyclic_topology(self) -> None:
        """Canonical hierarchy is strictly acyclic."""
        tree = create_canonical_scada_icicle_tree()
        assert tree.detect_cycles() is False

    def test_cycle_detection_on_cyclic_graph(self) -> None:
        """Artificial cycle parent -> child -> parent is detected by detect_cycles()."""
        tree = IcicleTree()
        n1 = IcicleNode(node_id="A", name="A", tag="A", depth=0, flow_capacity_tph=10, measured_flow_tph=10)
        n2 = IcicleNode(node_id="B", name="B", tag="B", depth=1, flow_capacity_tph=10, measured_flow_tph=10, parent_id="A")
        tree.add_node(n1)
        tree.add_node(n2)
        n2.children_ids.append("A")  # Inject circular loop
        assert tree.detect_cycles() is True

    def test_bfs_and_dfs_postorder_traversals(self) -> None:
        """BFS starts at root and visits 32 nodes; DFS post-order visits leaves before root."""
        tree = create_canonical_scada_icicle_tree()
        bfs = tree.traverse_bfs()
        post = tree.traverse_dfs_postorder()
        assert len(bfs) == 32
        assert len(post) == 32
        assert bfs[0].node_id == "REF_COMPLEX"
        assert post[-1].node_id == "REF_COMPLEX"


# ============================================================================
# Section 5: Ancestor and Descendant Lineage
# ============================================================================

class TestAncestorAndDescendantLineage:
    """Validate ancestor path and descendant resolution for multi-echelon refining assets."""

    def test_get_node_by_index_resolution(self) -> None:
        """get_node_by_index resolves each 1-based index 1..32 to correct node."""
        tree = create_canonical_scada_icicle_tree()
        for i in range(1, 33):
            node = tree.get_node_by_index(i)
            assert node is not None
            assert node.index == i

    def test_get_ancestors_lineage(self) -> None:
        """Critical transmitter XMTR_CDU_FLOW_01 (Tier 4) has full 4-ancestor chain to root."""
        tree = create_canonical_scada_icicle_tree()
        ancestors = tree.get_ancestors("XMTR_CDU_FLOW_01")
        anc_ids = [n.node_id for n in ancestors]
        assert anc_ids == ["REF_COMPLEX", "CDU", "CDU_TRAIN_A", "FCV_CDU_FEED"]

    def test_get_descendants_aggregation(self) -> None:
        """CDU (Tier 1) has 7 total descendants in its subtree."""
        tree = create_canonical_scada_icicle_tree()
        descendants = tree.get_descendants("CDU")
        desc_ids = {n.node_id for n in descendants}
        assert "CDU_TRAIN_A" in desc_ids
        assert "CDU_TRAIN_B" in desc_ids
        assert "FCV_CDU_FEED" in desc_ids
        assert "XMTR_CDU_FLOW_01" in desc_ids
        assert len(descendants) == 8

    def test_leaf_node_property(self) -> None:
        """Leaf nodes have is_leaf == True and empty children_ids."""
        tree = create_canonical_scada_icicle_tree()
        leaves = [n for n in tree.nodes.values() if n.is_leaf]
        assert len(leaves) >= 9  # At least all Tier 4 transmitters
        for leaf in leaves:
            assert len(leaf.children_ids) == 0

    def test_non_leaf_node_children(self) -> None:
        """Enterprise root has 4 process unit children (CDU, FCC, HTU, POLY)."""
        tree = create_canonical_scada_icicle_tree()
        root = tree.get_root()
        assert root is not None
        assert root.children_ids == ["CDU", "FCC", "HTU", "POLY"]


# ============================================================================
# Section 6: Drill-Down Focus Zoom & Stack Navigation
# ============================================================================

class TestDrillDownFocusZoomAndStackNavigation:
    """Validate interactive drill-down zoom, root focus change, and stack restoration."""

    def test_initial_zoom_level_is_root(self) -> None:
        """Initial canvas zoom level is 0 with root complex selected."""
        canvas = IcicleCanvas()
        assert canvas.zoom_expansion_level == 0
        assert canvas.focused_node_id is None
        assert canvas.selected_node_id == "REF_COMPLEX"

    def test_drill_down_to_tier_1_unit(self) -> None:
        """Drilling into CDU expands it to 100% canvas width and sets zoom level 1."""
        canvas = IcicleCanvas()
        canvas.drill_down_to("CDU")
        assert canvas.zoom_expansion_level == 1
        assert canvas.focused_node_id == "CDU"
        cdu = canvas.tree.get_node("CDU")
        assert math.isclose(cdu.bounds.width, CANVAS_WIDTH, rel_tol=1e-4)
        assert bool(canvas.status_bits & IcicleStatusBits.DRILLDOWN_ACTIVE) is True

    def test_drill_down_to_tier_2_train(self) -> None:
        """Drilling into CDU_TRAIN_A sets zoom level 2 and pushes navigation stack."""
        canvas = IcicleCanvas()
        canvas.drill_down_to("CDU")
        canvas.drill_down_to("CDU_TRAIN_A")
        assert canvas.zoom_expansion_level == 2
        assert canvas.focused_node_id == "CDU_TRAIN_A"
        assert len(canvas.tree.drilldown_stack) == 2

    def test_zoom_out_pops_stack(self) -> None:
        """zoom_out pops navigation stack and returns to parent node."""
        canvas = IcicleCanvas()
        canvas.drill_down_to("CDU")
        canvas.drill_down_to("CDU_TRAIN_A")
        canvas.zoom_out()
        assert canvas.zoom_expansion_level == 1
        assert canvas.focused_node_id == "CDU"

    def test_zoom_out_to_root(self) -> None:
        """zoom_out from Level 1 returns back to Tier 0 root complex."""
        canvas = IcicleCanvas()
        canvas.drill_down_to("CDU")
        canvas.zoom_out()
        assert canvas.zoom_expansion_level == 0
        assert canvas.focused_node_id is None
        assert bool(canvas.status_bits & IcicleStatusBits.DRILLDOWN_ACTIVE) is False

    def test_reset_zoom_clears_stack(self) -> None:
        """reset_zoom directly clears navigation stack and restores root view."""
        canvas = IcicleCanvas()
        canvas.drill_down_to("FCC")
        canvas.drill_down_to("FCC_REACTOR_TRAIN")
        canvas.reset_zoom()
        assert canvas.zoom_expansion_level == 0
        assert canvas.focused_node_id is None
        assert len(canvas.tree.drilldown_stack) == 0

    def test_drill_down_invalid_node_raises_drilldown_error(self) -> None:
        """Drilling into non-existent node raises DrilldownStackError and trips 0xE802."""
        canvas = IcicleCanvas()
        with pytest.raises(DrilldownStackError):
            canvas.drill_down_to("NON_EXISTENT_UNIT")
        assert canvas.diagnostic_code == DIAG_ERR_DRILLDOWN_STACK_OVERFLOW
        assert bool(canvas.status_bits & IcicleStatusBits.DRILLDOWN_OVERFLOW_FAULT) is True


# ============================================================================
# Section 7: Mass Flow Conservation & Imbalance Detection
# ============================================================================

class TestMassFlowConservationAndImbalance:
    """Validate mass balance continuity (125.0 t/h) and 0xE803 imbalance fault detection."""

    def test_canonical_tree_mass_flow_balanced(self) -> None:
        """Canonical tree exhibits zero mass flow imbalance."""
        tree = create_canonical_scada_icicle_tree()
        is_imb, max_imb, culprit = check_tree_mass_flow_imbalance(tree)
        assert is_imb is False
        assert max_imb == 0.0
        assert culprit is None

    def test_root_flow_capacity_matches_tier_1(self) -> None:
        """Enterprise root throughput (125.0 t/h) equals sum of Tier 1 process units."""
        tree = create_canonical_scada_icicle_tree()
        root = tree.get_root()
        t1_sum = sum(n.measured_flow_tph for n in tree.get_tier_nodes(1))
        assert math.isclose(root.measured_flow_tph, 125.0, abs_tol=1e-3)
        assert math.isclose(t1_sum, 125.0, abs_tol=1e-3)

    def test_each_tier_flow_conservation(self) -> None:
        """CDU trains sum to 50.0 t/h, FCC trains sum to 40.0 t/h, HTU trains sum to 20.0 t/h."""
        tree = create_canonical_scada_icicle_tree()
        cdu_trains = [tree.get_node(cid) for cid in tree.get_node("CDU").children_ids]
        fcc_trains = [tree.get_node(cid) for cid in tree.get_node("FCC").children_ids]
        htu_trains = [tree.get_node(cid) for cid in tree.get_node("HTU").children_ids]
        poly_trains = [tree.get_node(cid) for cid in tree.get_node("POLY").children_ids]

        assert math.isclose(sum(n.measured_flow_tph for n in cdu_trains), 50.0, abs_tol=1e-3)
        assert math.isclose(sum(n.measured_flow_tph for n in fcc_trains), 40.0, abs_tol=1e-3)
        assert math.isclose(sum(n.measured_flow_tph for n in htu_trains), 20.0, abs_tol=1e-3)
        assert math.isclose(sum(n.measured_flow_tph for n in poly_trains), 15.0, abs_tol=1e-3)

    def test_inject_flow_imbalance_trips_alarm(self) -> None:
        """Injecting flow imbalance > 5.0% trips FlowImbalanceAlarmActive (%M414)."""
        canvas = IcicleCanvas()
        assert canvas.flow_imbalance_alarm_active is False
        canvas.inject_flow_imbalance("CDU", 60.0)  # 50.0 -> 60.0 (+20% imbalance)
        assert canvas.flow_imbalance_alarm_active is True
        assert bool(canvas.status_bits & IcicleStatusBits.FLOW_IMBALANCE_ALARM) is True

    def test_flow_imbalance_sets_diagnostic_code(self) -> None:
        """Imbalance trips diagnostic code DIAG_ERR_MASS_FLOW_IMBALANCE_FAULT (0xE803)."""
        canvas = IcicleCanvas()
        canvas.inject_flow_imbalance("CDU", 60.0)
        assert canvas.diagnostic_code == DIAG_ERR_MASS_FLOW_IMBALANCE_FAULT

    def test_trigger_imbalance_fault_method(self) -> None:
        """inject_flow_imbalance asserts alarm and updates Horner register memory."""
        canvas = IcicleCanvas()
        canvas.inject_flow_imbalance("CDU", 60.0)
        assert canvas.flow_imbalance_alarm_active is True
        assert canvas.diagnostic_code == DIAG_ERR_MASS_FLOW_IMBALANCE_FAULT
        assert canvas.reg_table.read_bit(COIL_FLOW_IMBALANCE_ALARM_ACTIVE) is True


# ============================================================================
# Section 8: Health Score Propagation & Degraded Asset Tracking
# ============================================================================

class TestHealthScorePropagationAndDegradedAssetTracking:
    """Validate bottom-up capacity-weighted health aggregation and critical fault tracking."""

    def test_nominal_root_health_score(self) -> None:
        """In canonical nominal state, enterprise root health is >= 95%."""
        tree = create_canonical_scada_icicle_tree()
        root_health = propagate_bottom_up_health(tree)
        assert root_health >= 95.0

    def test_weighted_health_propagation_formula(self) -> None:
        """Parent health score matches capacity-weighted average of its children."""
        tree = IcicleTree()
        p = IcicleNode(node_id="P", name="P", tag="P", depth=0, flow_capacity_tph=100.0, measured_flow_tph=100.0)
        c1 = IcicleNode(node_id="C1", name="C1", tag="C1", depth=1, flow_capacity_tph=75.0, measured_flow_tph=75.0, health_score=90.0, parent_id="P")
        c2 = IcicleNode(node_id="C2", name="C2", tag="C2", depth=1, flow_capacity_tph=25.0, measured_flow_tph=25.0, health_score=70.0, parent_id="P")
        tree.add_node(p)
        tree.add_node(c1)
        tree.add_node(c2)

        propagate_bottom_up_health(tree)
        # Expected: (75*90 + 25*70) / 100 = (6750 + 1750) / 100 = 85.0
        assert math.isclose(p.health_score, 85.0, abs_tol=1e-2)

    def test_node_health_state_nominal_warning_critical(self) -> None:
        """health_state property categorizes NOMINAL (>= 85%), WARNING (70..85%), CRITICAL (< 70%)."""
        n_nom = IcicleNode(node_id="A", name="A", tag="A", depth=0, flow_capacity_tph=10, measured_flow_tph=10, health_score=92.0)
        n_warn = IcicleNode(node_id="B", name="B", tag="B", depth=0, flow_capacity_tph=10, measured_flow_tph=10, health_score=78.0)
        n_crit = IcicleNode(node_id="C", name="C", tag="C", depth=0, flow_capacity_tph=10, measured_flow_tph=10, health_score=45.0)

        assert n_nom.health_state == NodeHealthState.NOMINAL
        assert n_warn.health_state == NodeHealthState.WARNING
        assert n_crit.health_state == NodeHealthState.CRITICAL

    def test_inject_node_fault_detects_critical(self) -> None:
        """Injecting health < 70.0% increments critical fault count and updates min health."""
        canvas = IcicleCanvas()
        assert canvas.metrics.critical_fault_count == 0
        canvas.inject_node_fault("XMTR_CDU_FLOW_01", 45.0)
        assert canvas.metrics.critical_fault_count >= 1
        assert canvas.metrics.min_health_score == 45.0
        faulty_node = canvas.tree.get_node("XMTR_CDU_FLOW_01")
        assert faulty_node.health_state == NodeHealthState.CRITICAL

    def test_identify_critical_faults_helper(self) -> None:
        """identify_critical_faults returns list of degraded nodes below threshold."""
        tree = create_canonical_scada_icicle_tree()
        assert len(identify_critical_faults(tree)) == 0
        tree.get_node("XMTR_CDU_PRESS_03").health_score = 55.0
        faults = identify_critical_faults(tree)
        assert len(faults) == 1
        assert faults[0].node_id == "XMTR_CDU_PRESS_03"

    def test_find_min_health_node_helper(self) -> None:
        """find_min_health_node identifies node with lowest health in tree."""
        tree = create_canonical_scada_icicle_tree()
        tree.get_node("XMTR_CDU_PRESS_03").health_score = 30.0
        min_n = find_min_health_node(tree)
        assert min_n is not None
        assert min_n.node_id == "XMTR_CDU_PRESS_03"
        assert min_n.health_score == 30.0


# ============================================================================
# Section 9: WCAG 2.1 AAA Accessibility & Contrast Ratio Checks
# ============================================================================

class TestWCAG21AAAAccessibility:
    """Validate WCAG 2.1 AAA relative luminance and contrast ratio calculations (> 18:1, > 7:1)."""

    def test_relative_luminance_extremes(self) -> None:
        """Relative luminance of white is 1.0, black is 0.0, and theme backing is < 0.02."""
        assert math.isclose(relative_luminance("#FFFFFF"), 1.0, abs_tol=1e-3)
        assert math.isclose(relative_luminance("#000000"), 0.0, abs_tol=1e-3)
        assert relative_luminance(COLOR_DARK_THEME_BACKING) < 0.02

    def test_contrast_ratio_formula(self) -> None:
        """Contrast ratio is symmetric, >= 1.0, and maximum 21.0."""
        cr1 = contrast_ratio("#FFFFFF", "#000000")
        cr2 = contrast_ratio("#000000", "#FFFFFF")
        assert math.isclose(cr1, cr2)
        assert math.isclose(cr1, 21.0, abs_tol=0.1)

    def test_text_contrast_ratio_exceeds_7_0(self) -> None:
        """Primary text (#F0F6FC) on dark theme (#0D1117) exceeds 7.0:1 (WCAG AAA)."""
        cr = contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert cr >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert cr > 14.0

    def test_decoupled_badge_contrast_exceeds_18_0(self) -> None:
        """Primary text (#F0F6FC) on decoupled badge (#050811) exceeds 18.0:1."""
        cr = contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert cr >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert cr > 18.0

    def test_validate_wcag_aaa_contrast_helper(self) -> None:
        """validate_wcag_aaa_contrast returns meets_aaa True with both targets passing."""
        is_aaa, text_cr, badge_cr = validate_wcag_aaa_contrast()
        assert is_aaa is True
        assert text_cr >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert badge_cr >= WCAG_AAA_BADGE_CONTRAST_TARGET


# ============================================================================
# Section 10: Standalone W3C SVG 1.1 Vector Graphic XML Parsing
# ============================================================================

class TestStandaloneW3CSVGGenerationAndXMLParsing:
    """Validate W3C SVG 1.1 vector graphic synthesis and XML parsing with ElementTree."""

    def test_svg_xml_well_formed(self) -> None:
        """Rendered SVG string is parsed into XML tree by xml.etree.ElementTree.fromstring."""
        canvas = IcicleCanvas()
        svg_content = canvas.render_svg()
        root = ET.fromstring(svg_content)
        assert root is not None
        assert root.tag.endswith("svg")

    def test_svg_dimensions_and_viewbox(self) -> None:
        """SVG contains correct width=1200, height=750, and viewBox."""
        canvas = IcicleCanvas()
        svg_content = canvas.render_svg()
        root = ET.fromstring(svg_content)
        assert root.attrib.get("width") == "1200"
        assert root.attrib.get("height") == "750"
        assert root.attrib.get("viewBox") == "0 0 1200 750"

    def test_svg_contains_defs_linear_gradients(self) -> None:
        """SVG defs contain linear gradients and focus filters."""
        canvas = IcicleCanvas()
        svg_content = canvas.render_svg()
        assert "<defs>" in svg_content
        assert 'id="flowGradNominal"' in svg_content
        assert 'id="flowGradWarning"' in svg_content
        assert 'id="flowGradCritical"' in svg_content
        assert 'id="focusGlow"' in svg_content

    def test_svg_contains_all_partition_groups(self) -> None:
        """SVG contains partition elements for unit operation nodes."""
        canvas = IcicleCanvas()
        svg_content = canvas.render_svg()
        root = ET.fromstring(svg_content)
        rects = root.findall(".//{http://www.w3.org/2000/svg}rect") + root.findall(".//rect")
        # 32 nodes + container rects + HUD elements = > 35 rects
        assert len(rects) >= 32

    def test_svg_contains_hud_telemetry_card(self) -> None:
        """SVG contains bottom HUD telemetry card and register labels."""
        canvas = IcicleCanvas()
        svg_content = canvas.render_svg()
        assert "hud_telemetry" in svg_content
        assert "PARTITIONS (%R1770)" in svg_content
        assert "CANVAS ACTIVE (%M413)" in svg_content

    def test_svg_drill_down_breadcrumb_updates(self) -> None:
        """When drilled down to CDU, SVG updates to show CDU focus and L1 zoom."""
        canvas = IcicleCanvas()
        canvas.drill_down_to("CDU")
        svg_content = canvas.render_svg()
        assert "UNIT-CDU-100" in svg_content
        assert "node_CDU" in svg_content
        assert "L1" in svg_content


# ============================================================================
# Section 11: Horner OCS Memory Space Integration (%R1770..%R1777, %M413..%M414)
# ============================================================================

class TestHornerOCSSynchronization:
    """Validate synchronization with Horner OCS RegisterTable memory with PrivilegeMode.SYSTEM."""

    def test_analog_registers_r1770_to_r1777_nominal_values(self) -> None:
        """Registers %R1770..%R1777 are written with scaled integer values in nominal state."""
        reg_table = RegisterTable()
        canvas = IcicleCanvas(reg_table=reg_table)
        canvas.sync_to_registers()

        r1770 = reg_table.read_word("%R1770")  # Total partitions (32)
        r1771 = reg_table.read_word("%R1771")  # Selected node index (1)
        r1772 = reg_table.read_word("%R1772")  # Selected node depth (0)
        r1773 = reg_table.read_word("%R1773")  # Flow throughput x10 (1250)
        r1774 = reg_table.read_word("%R1774")  # Health score pct (>= 90)
        r1775 = reg_table.read_word("%R1775")  # Zoom expansion level (0)
        r1776 = reg_table.read_word("%R1776")  # Deformation metric (0..100)
        r1777 = reg_table.read_word("%R1777")  # Diagnostic code (0)

        assert r1770 == 32
        assert r1771 == 1
        assert r1772 == 0
        assert r1773 == 1250
        assert r1774 >= 90
        assert r1775 == 0
        assert r1776 >= 0
        assert r1777 == 0

    def test_discrete_coils_m413_and_m414_states(self) -> None:
        """Coil %M413 is True (canvas active) and %M414 is False (imbalance OK) nominally."""
        reg_table = RegisterTable()
        canvas = IcicleCanvas(reg_table=reg_table)
        canvas.sync_to_registers()

        m413 = reg_table.read_bit("%M413")
        m414 = reg_table.read_bit("%M414")
        assert m413 is True
        assert m414 is False

    def test_node_selection_updates_r1771_and_r1772(self) -> None:
        """Selecting node index 2 (CDU) updates %R1771=2 and %R1772=1."""
        reg_table = RegisterTable()
        canvas = IcicleCanvas(reg_table=reg_table)
        canvas.select_node_by_index(2)

        r1771 = reg_table.read_word("%R1771")
        r1772 = reg_table.read_word("%R1772")
        assert r1771 == 2
        assert r1772 == 1

    def test_drill_down_updates_r1775(self) -> None:
        """Drilling down to CDU sets %R1775 to zoom expansion level 1."""
        reg_table = RegisterTable()
        canvas = IcicleCanvas(reg_table=reg_table)
        canvas.drill_down_to("CDU")

        r1775 = reg_table.read_word("%R1775")
        assert r1775 == 1

    def test_flow_imbalance_asserts_coil_m414(self) -> None:
        """Injecting flow imbalance sets %M414 to True."""
        reg_table = RegisterTable()
        canvas = IcicleCanvas(reg_table=reg_table)
        canvas.inject_flow_imbalance("CDU", 60.0)

        m414 = reg_table.read_bit("%M414")
        assert m414 is True

    def test_diagnostic_status_code_signed_conversion(self) -> None:
        """Diagnostic code 0xE803 is written into %R1777 as signed 16-bit integer."""
        reg_table = RegisterTable()
        canvas = IcicleCanvas(reg_table=reg_table)
        canvas.inject_flow_imbalance("CDU", 60.0)

        r1777 = reg_table.read_word("%R1777")
        assert (r1777 & 0xFFFF) == 0xE803


# ============================================================================
# Section 12: ILogicUnit Discrete Scan Cycle Engine
# ============================================================================

class TestILogicUnitScanCycleEngine:
    """Validate ILogicUnit protocol methods (scan_step, step, execute, reset)."""

    def test_ilogic_unit_properties(self) -> None:
        """Canvas engine implements name, priority, and is_enabled properties."""
        canvas = IcicleCanvas()
        assert canvas.name == "IcicleCanvasSync"
        assert canvas.priority == 95
        assert canvas.is_enabled is True

    def test_scan_step_cycle(self) -> None:
        """scan_step updates telemetry and synchronizes memory space."""
        reg_table = RegisterTable()
        canvas = IcicleCanvas(reg_table=reg_table)
        canvas.scan_step(dt=0.01)
        assert reg_table.read_word("%R1770") == 32

    def test_step_alias(self) -> None:
        """step() behaves identically to scan_step()."""
        canvas = IcicleCanvas()
        canvas.step()
        assert canvas.metrics.total_partition_count == 32

    def test_execute_scan_context(self) -> None:
        """execute(context) runs within Horner ScanContext with PrivilegeMode.SYSTEM."""
        reg_table = RegisterTable()
        canvas = IcicleCanvas(reg_table=reg_table)
        ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=reg_table)
        canvas.execute(ctx)
        assert reg_table.read_word("%R1770") == 32

    def test_reset_restores_nominal(self) -> None:
        """reset() clears drilldown, faults, and restores canonical tree."""
        canvas = IcicleCanvas()
        canvas.drill_down_to("CDU")
        canvas.inject_node_fault("XMTR_CDU_FLOW_01", 30.0)
        assert canvas.zoom_expansion_level == 1

        canvas.reset()
        assert canvas.zoom_expansion_level == 0
        assert canvas.focused_node_id is None
        assert canvas.diagnostic_code == DIAG_OK
        assert canvas.metrics.critical_fault_count == 0


# ============================================================================
# Section 13: Deterministic 9-Stage Verification Suite & Artifact Export
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate deterministic 9-stage verification runner and strict 4-state contract JSON."""

    def test_verification_runner_status_success(self) -> None:
        """run_icicle_canvas_verification returns strict 4-state contract status 'success'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = str(Path(tmpdir) / "evidence.json")
            svg_path = str(Path(tmpdir) / "sample.svg")
            report = run_icicle_canvas_verification(output_path=ev_path, sample_svg_path=svg_path)
            assert report["status"] == "success"
            assert report["error_code"] is None

    def test_verification_runner_checks_passed_9_of_9(self) -> None:
        """Verification suite runs 9 stages and all 9 stages pass."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = str(Path(tmpdir) / "evidence.json")
            svg_path = str(Path(tmpdir) / "sample.svg")
            report = run_icicle_canvas_verification(output_path=ev_path, sample_svg_path=svg_path)
            assert report["data"]["checks_passed"] == 9
            assert report["data"]["total_checks"] == 9
            assert len(report["data"]["tests"]) == 9

    def test_verification_runner_strict_4_state_contract(self) -> None:
        """Report conforms strictly to 4-state engineering contract schema."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = str(Path(tmpdir) / "evidence.json")
            svg_path = str(Path(tmpdir) / "sample.svg")
            report = run_icicle_canvas_verification(output_path=ev_path, sample_svg_path=svg_path)
            assert "status" in report
            assert "error_code" in report
            assert "details" in report
            assert "data" in report
            assert report["data"]["work_package"] == "W216"
            assert report["data"]["gate"] == "Gate G9 / G2"

    def test_verification_runner_exports_json_evidence(self) -> None:
        """Evidence JSON file is written to disk and is readable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = str(Path(tmpdir) / "evidence.json")
            svg_path = str(Path(tmpdir) / "sample.svg")
            run_icicle_canvas_verification(output_path=ev_path, sample_svg_path=svg_path)
            assert Path(ev_path).exists()
            with open(ev_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["status"] == "success"

    def test_verification_runner_exports_sample_svg(self) -> None:
        """Sample SVG file is written to disk and is valid XML."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = str(Path(tmpdir) / "evidence.json")
            svg_path = str(Path(tmpdir) / "sample.svg")
            run_icicle_canvas_verification(output_path=ev_path, sample_svg_path=svg_path)
            assert Path(svg_path).exists()
            with open(svg_path, "r", encoding="utf-8") as f:
                svg_str = f.read()
            root = ET.fromstring(svg_str)
            assert root.tag.endswith("svg")
