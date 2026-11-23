"""Comprehensive unit test suite for Cscape HMI Dynamic Radial Tree & Hierarchical Dependency Graph SCADA Canvas (W207).

Work Package: W207 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Coverage (50+ Unit Tests across 12 Sections):
1. Section 1: Pure IEC 61131-3 Structured Text (ST) POU Grammar, Symbol Binding & STParser Validation (%R1680..%R1687, %M392..%M393).
2. Section 2: SecurityGuard Anti-Ladder Construct Interception (LadderForbiddenError on contacts, coils, rungs, mnemonics).
3. Section 3: Node Hierarchy Structures, TreeNode Modeling, Parent-Child Bidirectional References & Tree Builder.
4. Section 4: Cycle Detection in Dependency Graphs (DFS Invariant, Self-Loop, Multi-Hop Cycle, HierarchyCycleError).
5. Section 5: Polar-to-Cartesian Coordinate Math & Reversibility Primitives.
6. Section 6: Radial Tree Concentric Layout & Subtree Angular Interval Spacing Conservation.
7. Section 7: Radial Cubic Bezier Curve Synthesis, Endpoint Continuity, Smoothness & Tangent Orientation.
8. Section 8: Bottom-Up Health Score Propagation, Weighted Aggregation & Critical Fault Identification.
9. Section 9: WCAG 2.1 AAA Accessibility Contrast Ratio Checks (> 18:1 Decoupled Badge, > 7:1 Text, > 3:1 Graphics).
10. Section 10: Standalone W3C SVG 1.1 Vector Graphic XML Validation via xml.etree.ElementTree.fromstring.
11. Section 11: Horner OCS Memory Synchronization (%R1680..%R1687, %M392..%M393) with PrivilegeMode.SYSTEM & ILogicUnit Scan Cycle.
12. Section 12: Deterministic 9-Stage Verification Runner run_radial_tree_canvas_verification & JSON/SVG Artifact Export.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.radial_tree_canvas import (
    CANONICAL_LEVEL_RADII,
    CANVAS_CENTER_X,
    CANVAS_CENTER_Y,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COIL_CRITICAL_FAULT_ALARM_ACTIVE,
    COIL_RADIAL_TREE_ACTIVE,
    COIL_RADIAL_TREE_CANVAS_ACTIVE,
    COIL_TREE_FAULT_TRIP,
    COIL_W207_CANVAS_ACTIVE,
    COIL_W207_FAULT_ALARM,
    COLOR_ALARM_CRIMSON,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_CRITICAL,
    COLOR_DARK_SURFACE,
    COLOR_DARK_THEME_BACKING,
    COLOR_DECOUPLED_BADGE,
    COLOR_FOCUS_BLUE,
    COLOR_NOMINAL,
    COLOR_NOMINAL_EMERALD,
    COLOR_RING_GUIDE,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TREE_EDGE,
    COLOR_WARNING,
    COLOR_WARM_AMBER,
    DIAG_ERR_ANGULAR_OVERLAP,
    DIAG_ERR_CRITICAL_FAULT_TRIP,
    DIAG_ERR_HIERARCHY_CYCLE_DETECTED,
    DIAG_ERR_SVG_RENDER_FAULT,
    DIAG_EVENT_OK,
    DIAG_OK,
    DiagnosticCode,
    HEALTH_CRITICAL_THRESHOLD,
    HEALTH_NOMINAL_BASELINE,
    HEALTH_WARNING_THRESHOLD,
    HierarchyCycleError,
    LEVEL_0_RADIUS,
    LEVEL_1_RADIUS,
    LEVEL_2_RADIUS,
    LEVEL_3_RADIUS,
    NodeHealthState,
    Point2D,
    RADIAL_TREE_CANVAS_PURE_ST_POU,
    RADIAL_TREE_PURE_ST_POU,
    REG_CRITICAL_FAULT_COUNT,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_MAX_TREE_DEPTH,
    REG_MIN_HEALTH_SCORE_SCALED,
    REG_ROOT_HEALTH_SCORE_SCALED,
    REG_SELECTED_NODE_HEALTH_SCALED,
    REG_SELECTED_NODE_INDEX,
    REG_TOTAL_NODE_COUNT,
    REG_W207_CRITICAL_FAULTS,
    REG_W207_DIAGNOSTIC_CODE,
    REG_W207_MAX_DEPTH,
    REG_W207_MIN_HEALTH,
    REG_W207_ROOT_HEALTH,
    REG_W207_SELECTED_HEALTH,
    REG_W207_SELECTED_NODE,
    REG_W207_STATUS_WORD,
    REG_W207_TOTAL_NODES,
    RadialTree,
    RadialTreeCanvas,
    RadialTreeCanvasEngine,
    RadialTreeCanvasSync,
    RadialTreeMetrics,
    RadialTreeStatusBits,
    TreeNode,
    W207_RADIAL_TREE_PURE_ST_POU,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    calculate_contrast_ratio,
    cartesian_to_polar,
    compute_cubic_bezier_points,
    create_canonical_radial_tree_canvas,
    create_canonical_scada_radial_tree,
    create_mock_scan_context,
    eval_cubic_bezier,
    find_min_health_node,
    format_cubic_bezier_svg_path,
    generate_radial_tree_canvas_svg,
    hex_to_relative_luminance,
    identify_critical_faults,
    layout_radial_tree,
    normalize_angle_rad,
    polar_to_cartesian,
    propagate_bottom_up_health,
    run_radial_tree_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_radial_tree_canvas_pure_st,
)


# ============================================================================
# Section 1: Pure ST POU Grammar & AST Validation
# ============================================================================

class TestSection1PureSTPOU:
    """Verify IEC 61131-3 Pure Structured Text program integrity and symbol bindings."""

    def test_pure_st_pou_security_guard_assertion(self) -> None:
        """Assert pure ST content passes SecurityGuard without raising exceptions."""
        SecurityGuard.assert_pure_st_content(RADIAL_TREE_CANVAS_PURE_ST_POU)

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify STParser parses program RadialTreeCanvasSync as PROGRAM POUType."""
        parser = STParser()
        pou = parser.parse_pou(RADIAL_TREE_CANVAS_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "RadialTreeCanvasSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_pure_st_variable_bindings(self) -> None:
        """Verify all 10 memory bindings (%R1680..%R1687, %M392..%M393) exist."""
        parser = STParser()
        pou = parser.parse_pou(RADIAL_TREE_CANVAS_PURE_ST_POU)
        assert pou is not None

        expected_bindings = {
            "RootAggregateHealthScoreScaled": "%R1680",
            "SelectedNodeIndex": "%R1681",
            "SelectedNodeHealthScoreScaled": "%R1682",
            "CriticalFaultCount": "%R1683",
            "MaxTreeDepth": "%R1684",
            "TotalNodeCount": "%R1685",
            "MinHealthScoreScaled": "%R1686",
            "DiagnosticStatusCode": "%R1687",
            "CriticalFaultAlarmActive": "%M392",
            "RadialTreeCanvasActive": "%M393",
        }

        vmap = {v.name: v.address_binding for v in pou.variables}
        for var_name, expected_addr in expected_bindings.items():
            assert var_name in vmap, f"Variable {var_name} missing from ST POU"
            assert vmap[var_name] == expected_addr, f"{var_name} mapped to {vmap[var_name]}, expected {expected_addr}"

    def test_pure_st_pou_helper_function(self) -> None:
        """Verify verify_radial_tree_canvas_pure_st helper returns True."""
        assert verify_radial_tree_canvas_pure_st() is True

    def test_pure_st_pou_aliases(self) -> None:
        """Verify POU string aliases match RADIAL_TREE_CANVAS_PURE_ST_POU."""
        assert RADIAL_TREE_PURE_ST_POU == RADIAL_TREE_CANVAS_PURE_ST_POU
        assert W207_RADIAL_TREE_PURE_ST_POU == RADIAL_TREE_CANVAS_PURE_ST_POU


# ============================================================================
# Section 2: SecurityGuard Anti-Ladder Construct Interception
# ============================================================================

class TestSection2AntiLadderInterception:
    """Verify security enforcement rejects forbidden ladder logic constructs."""

    def test_anti_ladder_contacts_interception(self) -> None:
        """Assert ladder normally open contacts raise LadderForbiddenError."""
        bad_code = "PROGRAM Bad VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_coils_interception(self) -> None:
        """Assert ladder coils raise LadderForbiddenError."""
        bad_code = "PROGRAM Bad VAR Y: BOOL; END_VAR ---( )--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rung_delimiters(self) -> None:
        """Assert RUNG delimiters raise LadderForbiddenError."""
        bad_code = "PROGRAM Bad\nRUNG 1:\nX := TRUE;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_network_delimiters(self) -> None:
        """Assert NETWORK delimiters raise LadderForbiddenError."""
        bad_code = "PROGRAM Bad\nNETWORK 1:\nX := FALSE;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_mnemonic_xic(self) -> None:
        """Assert XIC mnemonic raises LadderForbiddenError."""
        bad_code = "PROGRAM Bad\nXIC bit_in;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_mnemonic_ote(self) -> None:
        """Assert OTE mnemonic raises LadderForbiddenError."""
        bad_code = "PROGRAM Bad\nOTE coil_out;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_mixed_content_rejection(self) -> None:
        """Assert ladder construct embedded in Structured Text statements fails."""
        bad_code = "PROGRAM P VAR A : INT; END_VAR A := A + 1; ---( )--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)


# ============================================================================
# Section 3: Node Hierarchy Structures & Tree Builder
# ============================================================================

class TestSection3NodeHierarchyStructures:
    """Verify TreeNode and RadialTree instantiation, linking, and graph queries."""

    def test_tree_node_defaults(self) -> None:
        """Verify default attributes of a freshly created TreeNode."""
        node = TreeNode(id="N1", name="Node 1")
        assert node.id == "N1"
        assert node.name == "Node 1"
        assert node.depth == 0
        assert node.health_score == 100.0
        assert node.weight == 1.0
        assert node.is_fault is False
        assert node.status == "NOMINAL"
        assert node.children == []
        assert node.parent is None
        assert node.is_leaf() is True

    def test_tree_node_add_child_bidirectional(self) -> None:
        """Verify add_child establishes parent and child mutual references."""
        parent = TreeNode(id="P", name="Parent")
        child = TreeNode(id="C", name="Child")
        parent.add_child(child)

        assert child in parent.children
        assert "C" in parent.children_ids
        assert child.parent is parent
        assert child.parent_id == "P"
        assert child.depth == parent.depth + 1
        assert parent.is_leaf() is False
        assert child.is_leaf() is True

    def test_tree_node_remove_child(self) -> None:
        """Verify remove_child detaches child from parent's collection."""
        parent = TreeNode(id="P", name="Parent")
        child = TreeNode(id="C", name="Child")
        parent.add_child(child)
        assert len(parent.children) == 1

        parent.remove_child("C")
        assert len(parent.children) == 0
        assert "C" not in parent.children_ids

    def test_tree_node_get_leaves(self) -> None:
        """Verify get_leaves returns all terminal nodes in the subtree."""
        root = TreeNode(id="R", name="Root")
        c1 = TreeNode(id="C1", name="Child 1")
        c2 = TreeNode(id="C2", name="Child 2")
        g1 = TreeNode(id="G1", name="Grandchild 1")
        g2 = TreeNode(id="G2", name="Grandchild 2")

        root.add_child(c1)
        root.add_child(c2)
        c1.add_child(g1)
        c1.add_child(g2)

        leaves = root.get_leaves()
        leaf_ids = {l.id for l in leaves}
        assert leaf_ids == {"G1", "G2", "C2"}

    def test_tree_node_get_descendants(self) -> None:
        """Verify get_descendants returns all descendants excluding self."""
        root = TreeNode(id="R", name="Root")
        c1 = TreeNode(id="C1", name="Child 1")
        g1 = TreeNode(id="G1", name="Grandchild 1")
        root.add_child(c1)
        c1.add_child(g1)

        desc = root.get_descendants()
        assert len(desc) == 2
        assert {d.id for d in desc} == {"C1", "G1"}

    def test_tree_builder_missing_parent_key_error(self) -> None:
        """Verify add_edge raises KeyError when parent does not exist."""
        tree = RadialTree()
        tree.add_node(TreeNode(id="C", name="Child"))
        with pytest.raises(KeyError):
            tree.add_edge("NON_EXISTENT_PARENT", "C")

    def test_tree_builder_missing_child_key_error(self) -> None:
        """Verify add_edge raises KeyError when child does not exist."""
        tree = RadialTree()
        tree.add_node(TreeNode(id="P", name="Parent"))
        with pytest.raises(KeyError):
            tree.add_edge("P", "NON_EXISTENT_CHILD")

    def test_canonical_tree_total_node_count_and_depth(self) -> None:
        """Verify canonical SCADA tree has exactly 29 nodes and 3 depth levels."""
        tree = create_canonical_scada_radial_tree()
        assert tree.total_node_count() == 29
        assert tree.max_depth() == 3
        root = tree.get_root()
        assert root is not None
        assert root.id == "PLANT_ROOT"
        assert len(root.children) == 4


# ============================================================================
# Section 4: Cycle Detection & Acyclic Graph Invariants
# ============================================================================

class TestSection4CycleDetection:
    """Verify graph cycle detection algorithm and exception handling."""

    def test_acyclic_tree_passes_cycle_detection(self) -> None:
        """Assert canonical tree contains zero cycles."""
        tree = create_canonical_scada_radial_tree()
        assert tree.detect_cycles() is False

    def test_cycle_detection_direct_loop(self) -> None:
        """Assert direct 2-node cycle (A -> B -> A) is detected."""
        tree = RadialTree()
        na = TreeNode(id="A", name="Node A")
        nb = TreeNode(id="B", name="Node B")
        tree.add_node(na)
        tree.add_node(nb)
        tree.add_edge("A", "B")
        tree.add_edge("B", "A")

        assert tree.detect_cycles() is True

    def test_cycle_detection_self_loop(self) -> None:
        """Assert self-loop (A -> A) is detected."""
        tree = RadialTree()
        na = TreeNode(id="A", name="Node A")
        tree.add_node(na)
        tree.add_edge("A", "A")

        assert tree.detect_cycles() is True

    def test_cycle_detection_multi_hop_cycle(self) -> None:
        """Assert multi-hop cycle (A -> B -> C -> D -> B) is detected."""
        tree = RadialTree()
        for nid in ["A", "B", "C", "D"]:
            tree.add_node(TreeNode(id=nid, name=f"Node {nid}"))
        tree.add_edge("A", "B")
        tree.add_edge("B", "C")
        tree.add_edge("C", "D")
        tree.add_edge("D", "B")  # back-edge to B

        assert tree.detect_cycles() is True

    def test_validate_acyclic_raises_hierarchy_cycle_error(self) -> None:
        """Assert validate_acyclic raises HierarchyCycleError on cyclic graph."""
        tree = RadialTree()
        tree.add_node(TreeNode(id="X", name="X"))
        tree.add_node(TreeNode(id="Y", name="Y"))
        tree.add_edge("X", "Y")
        tree.add_edge("Y", "X")

        with pytest.raises(HierarchyCycleError, match="Cycle detected"):
            tree.validate_acyclic()


# ============================================================================
# Section 5: Polar-to-Cartesian Coordinate Math & Conversions
# ============================================================================

class TestSection5PolarCartesianMath:
    """Verify trigonometric coordinate transformations and reversibility."""

    def test_polar_to_cartesian_center(self) -> None:
        """Verify radius 0.0 returns center (CANVAS_CENTER_X, CANVAS_CENTER_Y)."""
        pt = polar_to_cartesian(0.0, 1.234)
        assert math.isclose(pt.x, CANVAS_CENTER_X, abs_tol=1e-3)
        assert math.isclose(pt.y, CANVAS_CENTER_Y, abs_tol=1e-3)

    def test_polar_to_cartesian_cardinal_angles(self) -> None:
        """Verify 0, pi/2, pi, 3pi/2 yield exact Cartesian offsets."""
        r = 100.0
        p0 = polar_to_cartesian(r, 0.0)
        assert math.isclose(p0.x, CANVAS_CENTER_X + r, abs_tol=1e-3)
        assert math.isclose(p0.y, CANVAS_CENTER_Y, abs_tol=1e-3)

        p_pi_2 = polar_to_cartesian(r, math.pi / 2.0)
        assert math.isclose(p_pi_2.x, CANVAS_CENTER_X, abs_tol=1e-3)
        assert math.isclose(p_pi_2.y, CANVAS_CENTER_Y + r, abs_tol=1e-3)

        p_pi = polar_to_cartesian(r, math.pi)
        assert math.isclose(p_pi.x, CANVAS_CENTER_X - r, abs_tol=1e-3)
        assert math.isclose(p_pi.y, CANVAS_CENTER_Y, abs_tol=1e-3)

    def test_cartesian_to_polar_reversibility(self) -> None:
        """Verify polar -> cartesian -> polar round-trip preserves (r, theta)."""
        test_cases = [
            (50.0, 0.5),
            (150.0, 2.1),
            (250.0, 4.3),
            (310.0, 5.8),
        ]
        for r_orig, theta_orig in test_cases:
            pt = polar_to_cartesian(r_orig, theta_orig)
            r_rec, theta_rec = cartesian_to_polar(pt)
            assert math.isclose(r_orig, r_rec, abs_tol=1e-2)
            assert math.isclose(theta_orig, theta_rec, abs_tol=1e-3)

    def test_normalize_angle_rad(self) -> None:
        """Verify normalize_angle_rad confines angles to [0, 2*pi)."""
        two_pi = 2.0 * math.pi
        assert math.isclose(normalize_angle_rad(0.0), 0.0, abs_tol=1e-5)
        assert math.isclose(normalize_angle_rad(two_pi), 0.0, abs_tol=1e-5)
        assert math.isclose(normalize_angle_rad(3.0 * two_pi + 1.0), 1.0, abs_tol=1e-5)
        assert math.isclose(normalize_angle_rad(-1.0), two_pi - 1.0, abs_tol=1e-5)

    def test_point2d_distance_and_tuple(self) -> None:
        """Verify Point2D distance calculation and tuple representation."""
        p1 = Point2D(0.0, 0.0)
        p2 = Point2D(3.0, 4.0)
        assert math.isclose(p1.distance_to(p2), 5.0, abs_tol=1e-5)
        assert p2.as_tuple() == (3.0, 4.0)


# ============================================================================
# Section 6: Radial Tree Concentric Layout & Angular Spacing
# ============================================================================

class TestSection6RadialTreeLayout:
    """Verify radial tree layout algorithm and angular span conservation."""

    def test_concentric_radial_levels(self) -> None:
        """Verify each node's radius corresponds to its depth level."""
        tree = create_canonical_scada_radial_tree()
        for node in tree.nodes.values():
            expected_r = CANONICAL_LEVEL_RADII[node.depth]
            assert math.isclose(node.radius, expected_r, abs_tol=1e-3), (
                f"Node {node.id} at depth {node.depth} has r={node.radius}, expected {expected_r}"
            )

    def test_root_placed_at_canvas_center(self) -> None:
        """Verify root node is positioned exactly at center coordinates."""
        tree = create_canonical_scada_radial_tree()
        root = tree.get_root()
        assert root is not None
        assert math.isclose(root.x, CANVAS_CENTER_X, abs_tol=1e-2)
        assert math.isclose(root.y, CANVAS_CENTER_Y, abs_tol=1e-2)

    def test_angular_span_conservation_at_root(self) -> None:
        """Verify children of root partition exact 2*pi radians without overlap."""
        tree = create_canonical_scada_radial_tree()
        root = tree.get_root()
        assert root is not None

        child_spans = [c.angular_span_rad for c in root.children]
        total_span = sum(child_spans)
        assert math.isclose(total_span, 2.0 * math.pi, abs_tol=1e-4)

    def test_angular_span_conservation_hierarchical(self) -> None:
        """Verify each internal node's children partition its allocated angular span."""
        tree = create_canonical_scada_radial_tree()
        for node in tree.nodes.values():
            if not node.is_leaf():
                children_sum = sum(c.angular_span_rad for c in node.children)
                assert math.isclose(children_sum, node.angular_span_rad, abs_tol=1e-4), (
                    f"Node {node.id} children span sum {children_sum} != parent span {node.angular_span_rad}"
                )

    def test_proportional_angular_allocation_by_weight(self) -> None:
        """Verify subtrees with equal leaf counts receive equal angular spans."""
        tree = create_canonical_scada_radial_tree()
        area_crude = tree.get_node("AREA_CRUDE")
        area_fcc = tree.get_node("AREA_FCC")
        assert area_crude is not None and area_fcc is not None
        # In canonical tree, crude and fcc areas have identical weight (3.0) and 4 leaves each
        assert math.isclose(area_crude.angular_span_rad, area_fcc.angular_span_rad, abs_tol=1e-4)

    def test_nodes_positioned_within_allocated_interval(self) -> None:
        """Verify every node's theta_rad is exactly at midpoint of its [theta_min, theta_max]."""
        tree = create_canonical_scada_radial_tree()
        for node in tree.nodes.values():
            mid = (node.theta_min_rad + node.theta_max_rad) / 2.0
            assert math.isclose(node.theta_rad, mid, abs_tol=1e-4)


# ============================================================================
# Section 7: Radial Cubic Bezier Curve Synthesis
# ============================================================================

class TestSection7CubicBezierCurves:
    """Verify cubic Bezier curve synthesis, control points, and evaluation."""

    def test_cubic_bezier_endpoints(self) -> None:
        """Verify B(0) == P0 and B(1) == P3."""
        p0 = Point2D(CANVAS_CENTER_X, CANVAS_CENTER_Y)
        p3 = Point2D(700.0, 375.0)
        pts = compute_cubic_bezier_points(
            p0=p0, p3=p3, r0=0.0, r3=200.0,
            theta0=0.0, theta3=0.0,
            center_x=CANVAS_CENTER_X, center_y=CANVAS_CENTER_Y,
        )

        b0 = eval_cubic_bezier(pts[0], pts[1], pts[2], pts[3], 0.0)
        b1 = eval_cubic_bezier(pts[0], pts[1], pts[2], pts[3], 1.0)

        assert math.isclose(b0.x, p0.x, abs_tol=1e-3)
        assert math.isclose(b0.y, p0.y, abs_tol=1e-3)
        assert math.isclose(b1.x, p3.x, abs_tol=1e-3)
        assert math.isclose(b1.y, p3.y, abs_tol=1e-3)

    def test_cubic_bezier_midpoint_continuity(self) -> None:
        """Verify B(0.5) lies smoothly between endpoints."""
        p0 = Point2D(500.0, 375.0)
        p3 = Point2D(700.0, 375.0)
        pts = compute_cubic_bezier_points(
            p0=p0, p3=p3, r0=100.0, r3=200.0,
            theta0=0.0, theta3=0.0,
            center_x=500.0, center_y=375.0,
        )

        b_mid = eval_cubic_bezier(pts[0], pts[1], pts[2], pts[3], 0.5)
        assert 500.0 < b_mid.x < 700.0
        assert math.isclose(b_mid.y, 375.0, abs_tol=1e-2)

    def test_cubic_bezier_root_parent_tangent_direction(self) -> None:
        """Verify when parent is root (r0=0), control points project along child direction."""
        p0 = Point2D(CANVAS_CENTER_X, CANVAS_CENTER_Y)
        child_angle = math.pi / 4.0
        p3 = polar_to_cartesian(110.0, child_angle)
        pts = compute_cubic_bezier_points(
            p0=p0, p3=p3, r0=0.0, r3=110.0,
            theta0=0.0, theta3=child_angle,
            center_x=CANVAS_CENTER_X, center_y=CANVAS_CENTER_Y,
        )

        # Control points P1 and P2 should have angle close to child_angle
        _, theta_p1 = cartesian_to_polar(pts[1])
        _, theta_p2 = cartesian_to_polar(pts[2])
        assert math.isclose(theta_p1, child_angle, abs_tol=1e-3)
        assert math.isclose(theta_p2, child_angle, abs_tol=1e-3)

    def test_format_cubic_bezier_svg_path(self) -> None:
        """Verify format_cubic_bezier_svg_path produces valid SVG syntax."""
        p0 = Point2D(10.0, 20.0)
        p1 = Point2D(30.0, 40.0)
        p2 = Point2D(50.0, 60.0)
        p3 = Point2D(70.0, 80.0)
        cmd = format_cubic_bezier_svg_path(p0, p1, p2, p3)
        assert cmd == "M 10.00,20.00 C 30.00,40.00 50.00,60.00 70.00,80.00"

    def test_eval_cubic_bezier_parameter_clamping(self) -> None:
        """Verify values of t outside [0, 1] clamp to endpoints."""
        p0 = Point2D(0.0, 0.0)
        p3 = Point2D(100.0, 100.0)
        pts = (p0, Point2D(30.0, 30.0), Point2D(70.0, 70.0), p3)

        b_under = eval_cubic_bezier(pts[0], pts[1], pts[2], pts[3], -0.5)
        b_over = eval_cubic_bezier(pts[0], pts[1], pts[2], pts[3], 1.5)

        assert math.isclose(b_under.x, p0.x, abs_tol=1e-3)
        assert math.isclose(b_over.x, p3.x, abs_tol=1e-3)


# ============================================================================
# Section 8: Bottom-Up Health Score Propagation & Fault Identification
# ============================================================================

class TestSection8HealthPropagation:
    """Verify bottom-up health score aggregation, fault thresholds, and critical trips."""

    def test_propagate_health_leaves_remain_invariant(self) -> None:
        """Verify leaf health scores are preserved during bottom-up propagation."""
        tree = create_canonical_scada_radial_tree()
        leaves = tree.get_root().get_leaves()
        orig_scores = {l.id: l.health_score for l in leaves}

        propagate_bottom_up_health(tree)
        for l in leaves:
            assert math.isclose(l.health_score, orig_scores[l.id], abs_tol=1e-3)

    def test_propagate_health_parent_weighted_average(self) -> None:
        """Verify internal node health equals weighted average of children."""
        tree = RadialTree()
        parent = TreeNode(id="P", name="Parent")
        c1 = TreeNode(id="C1", name="Child 1", health_score=80.0, weight=2.0)
        c2 = TreeNode(id="C2", name="Child 2", health_score=90.0, weight=3.0)
        tree.add_node(parent)
        tree.add_node(c1)
        tree.add_node(c2)
        tree.add_edge("P", "C1")
        tree.add_edge("P", "C2")

        propagate_bottom_up_health(tree)
        expected = (80.0 * 2.0 + 90.0 * 3.0) / (2.0 + 3.0)  # 86.0
        assert math.isclose(parent.health_score, expected, abs_tol=1e-2)

    def test_status_nominal_classification(self) -> None:
        """Verify health >= 85.0% results in NOMINAL status and is_fault=False."""
        node = TreeNode(id="N", name="N", health_score=92.0)
        tree = RadialTree()
        tree.add_node(node)
        propagate_bottom_up_health(tree)
        assert node.status == NodeHealthState.NOMINAL.value
        assert node.is_fault is False

    def test_status_warning_classification(self) -> None:
        """Verify 70.0% <= health < 85.0% results in WARNING status and is_fault=False."""
        node = TreeNode(id="N", name="N", health_score=78.5)
        tree = RadialTree()
        tree.add_node(node)
        propagate_bottom_up_health(tree)
        assert node.status == NodeHealthState.WARNING.value
        assert node.is_fault is False

    def test_status_critical_classification(self) -> None:
        """Verify health < 70.0% results in CRITICAL status and is_fault=True."""
        node = TreeNode(id="N", name="N", health_score=55.0)
        tree = RadialTree()
        tree.add_node(node)
        propagate_bottom_up_health(tree)
        assert node.status == NodeHealthState.CRITICAL.value
        assert node.is_fault is True

    def test_identify_critical_faults(self) -> None:
        """Verify identify_critical_faults accurately returns degraded nodes."""
        tree = create_canonical_scada_radial_tree()
        assert len(identify_critical_faults(tree)) == 0

        # Inject faults on two leaf nodes
        tree.get_node("SS_CDU_PUMP").health_score = 45.0
        tree.get_node("SS_FCC_RISER").health_score = 62.0
        propagate_bottom_up_health(tree)

        faults = identify_critical_faults(tree)
        fault_ids = {f.id for f in faults}
        assert "SS_CDU_PUMP" in fault_ids
        assert "SS_FCC_RISER" in fault_ids

    def test_find_min_health_node(self) -> None:
        """Verify find_min_health_node locates node with lowest health score."""
        tree = create_canonical_scada_radial_tree()
        tree.get_node("SS_BOIL_DRUM").health_score = 35.0
        propagate_bottom_up_health(tree)

        min_node = find_min_health_node(tree)
        assert min_node is not None
        assert min_node.id == "SS_BOIL_DRUM"
        assert min_node.health_score == 35.0


# ============================================================================
# Section 9: WCAG 2.1 AAA Accessibility Contrast Checks
# ============================================================================

class TestSection9WCAG21AAAContrast:
    """Verify WCAG 2.1 AAA contrast calculations and accessibility compliance."""

    def test_wcag_aaa_contrast_validation_function(self) -> None:
        """Verify validate_wcag_aaa_contrast confirms AAA compliance."""
        is_valid, text_cr, badge_cr = validate_wcag_aaa_contrast(
            text_color=COLOR_TEXT_PRIMARY,
            theme_backing=COLOR_DARK_THEME_BACKING,
            badge_backing=COLOR_DECOUPLED_BADGE,
        )
        assert is_valid is True
        assert text_cr >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert badge_cr >= WCAG_AAA_BADGE_CONTRAST_TARGET

    def test_decoupled_badge_contrast_exceeds_18_to_1(self) -> None:
        """Assert decoupled badge contrast ratio strictly exceeds 18.0:1."""
        badge_cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert badge_cr > 18.0, f"Decoupled badge contrast {badge_cr}:1 does not exceed 18:1"

    def test_primary_text_contrast_exceeds_7_to_1(self) -> None:
        """Assert white primary text on dark background strictly exceeds 7.0:1."""
        text_cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert text_cr > 7.0, f"Primary text contrast {text_cr}:1 does not exceed 7:1"

    def test_graphical_status_palette_contrast_exceeds_3_to_1(self) -> None:
        """Assert status palette colors (emerald, amber, crimson) exceed 3.0:1 graphics threshold."""
        for color_name, hex_val in [
            ("Emerald", COLOR_NOMINAL_EMERALD),
            ("Amber", COLOR_WARM_AMBER),
            ("Crimson", COLOR_ALARM_CRIMSON),
            ("Focus Blue", COLOR_FOCUS_BLUE),
        ]:
            cr = calculate_contrast_ratio(hex_val, COLOR_DARK_THEME_BACKING)
            assert cr >= WCAG_GRAPHICAL_CONTRAST_TARGET, (
                f"{color_name} ({hex_val}) contrast {cr}:1 below 3.0:1 graphical target"
            )

    def test_relative_luminance_extremes(self) -> None:
        """Verify relative luminance for pure black and pure white."""
        assert math.isclose(hex_to_relative_luminance("#000000"), 0.0, abs_tol=1e-4)
        assert math.isclose(hex_to_relative_luminance("#FFFFFF"), 1.0, abs_tol=1e-4)


# ============================================================================
# Section 10: Standalone W3C SVG 1.1 Vector Graphics & XML Parsing
# ============================================================================

class TestSection10W3CSVGGeneration:
    """Verify SVG generation, W3C standards compliance, and XML parsing."""

    def test_svg_well_formed_xml_parsing(self) -> None:
        """Assert SVG generated from canonical canvas parses with ET.fromstring without errors."""
        canvas = RadialTreeCanvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        assert root is not None
        assert root.tag.endswith("svg")

    def test_svg_root_viewport_attributes(self) -> None:
        """Verify SVG root element contains correct width, height, and viewBox."""
        canvas = RadialTreeCanvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        assert root.attrib["width"] == str(CANVAS_VIEWPORT_WIDTH)
        assert root.attrib["height"] == str(CANVAS_VIEWPORT_HEIGHT)
        assert root.attrib["viewBox"] == f"0 0 {CANVAS_VIEWPORT_WIDTH} {CANVAS_VIEWPORT_HEIGHT}"

    def test_svg_defs_and_gradients(self) -> None:
        """Verify SVG contains defs section with cardGrad gradient and glowEffect filter."""
        canvas = RadialTreeCanvas()
        svg_str = canvas.render_svg()
        assert "<defs>" in svg_str
        assert 'id="cardGrad"' in svg_str
        assert 'id="glowEffect"' in svg_str

    def test_svg_concentric_guide_rings(self) -> None:
        """Verify SVG contains guide rings group with dashed circle markup."""
        canvas = RadialTreeCanvas()
        svg_str = canvas.render_svg()
        assert 'class="guide-rings"' in svg_str
        assert 'stroke-dasharray="4,4"' in svg_str

    def test_svg_cubic_bezier_edges(self) -> None:
        """Verify SVG contains cubic Bezier path elements for hierarchy connections."""
        canvas = RadialTreeCanvas()
        svg_str = canvas.render_svg()
        assert 'class="tree-edges"' in svg_str
        assert 'd="M ' in svg_str
        assert ' C ' in svg_str

    def test_svg_hud_telemetry_card_and_badge(self) -> None:
        """Verify SVG contains HUD telemetry card and WCAG > 18:1 decoupled badge."""
        canvas = RadialTreeCanvas()
        svg_str = canvas.render_svg()
        assert 'class="hud-telemetry"' in svg_str
        assert "RADIAL TREE SCADA" in svg_str
        assert "ROOT HEALTH:" in svg_str
        assert COLOR_DECOUPLED_BADGE in svg_str


# ============================================================================
# Section 11: Horner OCS Registers & ILogicUnit Scan Cycle
# ============================================================================

class TestSection11HornerOCSRegistersAndScanCycle:
    """Verify Horner OCS register synchronization and ILogicUnit scan cycle execution."""

    def test_register_sync_nominal_baseline(self) -> None:
        """Verify registers %R1680..%R1687 and coils %M392..%M393 in nominal operation."""
        reg_table = RegisterTable()
        canvas = RadialTreeCanvas(reg_table=reg_table)
        canvas.scan_step(dt=0.01)

        r1680 = reg_table.read_word(REG_ROOT_HEALTH_SCORE_SCALED)
        r1681 = reg_table.read_word(REG_SELECTED_NODE_INDEX)
        r1682 = reg_table.read_word(REG_SELECTED_NODE_HEALTH_SCALED)
        r1683 = reg_table.read_word(REG_CRITICAL_FAULT_COUNT)
        r1684 = reg_table.read_word(REG_MAX_TREE_DEPTH)
        r1685 = reg_table.read_word(REG_TOTAL_NODE_COUNT)
        r1686 = reg_table.read_word(REG_MIN_HEALTH_SCORE_SCALED)
        r1687 = reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE)
        m392 = reg_table.read_bit(COIL_CRITICAL_FAULT_ALARM_ACTIVE)
        m393 = reg_table.read_bit(COIL_RADIAL_TREE_CANVAS_ACTIVE)

        assert r1680 >= 900  # >= 90.0%
        assert r1681 == 0    # root index
        assert r1682 >= 900
        assert r1683 == 0    # zero critical faults
        assert r1684 == 3    # 3 depth levels
        assert r1685 == 29   # 29 nodes
        assert r1686 >= 900  # min health >= 90.0%
        assert r1687 == 0    # DIAG_OK
        assert m392 is False # no fault alarm
        assert m393 is True  # canvas active

    def test_fault_injection_register_trip(self) -> None:
        """Verify injecting critical fault asserts coil %M392 and updates %R1683."""
        reg_table = RegisterTable()
        canvas = RadialTreeCanvas(reg_table=reg_table)

        canvas.inject_node_fault("SS_CDU_PUMP", 35.0)
        canvas.scan_step(dt=0.01)

        r1683 = reg_table.read_word(REG_CRITICAL_FAULT_COUNT)
        r1686 = reg_table.read_word(REG_MIN_HEALTH_SCORE_SCALED)
        m392 = reg_table.read_bit(COIL_CRITICAL_FAULT_ALARM_ACTIVE)

        assert r1683 >= 1
        assert r1686 == 350  # 35.0% scaled x10
        assert m392 is True

    def test_node_selection_updates_registers(self) -> None:
        """Verify select_node updates %R1681 and %R1682."""
        reg_table = RegisterTable()
        canvas = RadialTreeCanvas(reg_table=reg_table)

        canvas.select_node("AREA_FCC")
        canvas.scan_step(dt=0.01)

        node = canvas.tree.get_node("AREA_FCC")
        r1681 = reg_table.read_word(REG_SELECTED_NODE_INDEX)
        r1682 = reg_table.read_word(REG_SELECTED_NODE_HEALTH_SCALED)

        assert r1681 == node.index
        assert r1682 == int(round(node.health_score * 10))

    def test_ilogic_unit_interface_properties(self) -> None:
        """Verify ILogicUnit interface attributes."""
        canvas = RadialTreeCanvas()
        assert canvas.name == "RadialTreeCanvasSync"
        assert canvas.priority == 95
        assert canvas.is_enabled is True

    def test_ilogic_unit_reset_lifecycle(self) -> None:
        """Verify reset restores nominal baseline after fault injection."""
        reg_table = RegisterTable()
        canvas = RadialTreeCanvas(reg_table=reg_table)

        canvas.inject_node_fault("SS_CDU_COL", 20.0)
        assert reg_table.read_bit(COIL_CRITICAL_FAULT_ALARM_ACTIVE) is True

        canvas.reset()
        assert reg_table.read_bit(COIL_CRITICAL_FAULT_ALARM_ACTIVE) is False
        assert canvas.metrics.critical_fault_count == 0

    def test_scan_context_execution(self) -> None:
        """Verify execute method integrates cleanly with ScanContext."""
        reg_table = RegisterTable()
        canvas = RadialTreeCanvas(reg_table=reg_table)
        ctx = create_mock_scan_context(cycle=5, dt_ms=20.0, reg_table=reg_table)
        canvas.execute(ctx)
        assert reg_table.read_bit(COIL_RADIAL_TREE_CANVAS_ACTIVE) is True

    def test_diagnostic_code_signed_equality(self) -> None:
        """Verify DiagnosticCode handles 16-bit signed/unsigned equivalence."""
        code = DiagnosticCode(0xE201)
        # 0xE201 = 57857 unsigned, -7679 signed
        assert code == 0xE201
        assert code == 57857
        assert code == -7679


# ============================================================================
# Section 12: Deterministic 9-Stage Verification Runner
# ============================================================================

class TestSection12VerificationRunner:
    """Verify 9-stage verification suite deterministic execution and artifact emission."""

    def test_run_radial_tree_canvas_verification_success(self) -> None:
        """Verify run_radial_tree_canvas_verification returns success status."""
        report = run_radial_tree_canvas_verification(work_package="W207")
        assert report["status"] == "success"
        assert report["error_code"] is None
        assert report["data"]["checks_passed"] == 9
        assert report["data"]["total_checks"] == 9
        assert len(report["data"]["tests"]) == 9

    def test_verification_evidence_json_export(self) -> None:
        """Verify verification runner produces valid evidence JSON file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"

            report = run_radial_tree_canvas_verification(
                output_path=str(ev_path),
                sample_svg_path=str(svg_path),
            )
            assert report["status"] == "success"
            assert ev_path.exists()

            with open(ev_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["status"] == "success"
            assert data["data"]["checks_passed"] == 9

    def test_verification_sample_svg_export(self) -> None:
        """Verify verification runner produces well-formed sample SVG."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"

            run_radial_tree_canvas_verification(
                output_path=str(ev_path),
                sample_svg_path=str(svg_path),
            )
            assert svg_path.exists()

            with open(svg_path, "r", encoding="utf-8") as f:
                content = f.read()
            root = ET.fromstring(content)
            assert root.tag.endswith("svg")

    def test_factory_canvas_helpers(self) -> None:
        """Verify create_canonical_radial_tree_canvas factory function."""
        canvas = create_canonical_radial_tree_canvas(selected_node_id="AREA_CRUDE")
        assert canvas.selected_node_id == "AREA_CRUDE"
        assert canvas.metrics.selected_node_id == "AREA_CRUDE"
        assert canvas.metrics.total_node_count == 29
