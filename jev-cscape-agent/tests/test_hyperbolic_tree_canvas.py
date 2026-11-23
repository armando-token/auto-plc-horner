"""Comprehensive unit test suite for Cscape HMI Dynamic Hyperbolic Tree / Poincaré Disk SCADA Canvas (W213).

Work Package: W213 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Coverage (70+ Unit Tests across 13 Sections):
1. Section 1: Pure IEC 61131-3 Structured Text (ST) POU Grammar, Symbol Binding & STParser Validation (%R1740..%R1747, %M406..%M407).
2. Section 2: SecurityGuard Anti-Ladder Construct Interception (LadderForbiddenError on contacts, coils, rungs, mnemonics).
3. Section 3: ComplexPoint Coordinate Arithmetic, Boundary Containment (|z| < 1.0), and Radius Clamping.
4. Section 4: Möbius Transformations T_{a, theta}(z), Inverse Transformations, Identity, and Singularity Guards.
5. Section 5: Poincaré Disk Hyperbolic Distance Metric d(u, v) = 2 * artanh(|u - v| / |1 - conj(u)*v|) & Metric Invariants.
6. Section 6: Geodesic Arc Circle Geometry, Orthogonality Condition (|c|^2 - R^2 = 1), Center/Radius Math & SVG Path Synthesis.
7. Section 7: Hierarchical Tree Modeling, TreeNode Attributes, Subtree Weights, Traversals & Cycle Detection.
8. Section 8: Poincaré Radial Layout, Depth Assignment, Angular Allocation & Interactive Möbius Recentering.
9. Section 9: Bottom-Up Health Score Propagation, Weighted Aggregation & Critical Fault Identification.
10. Section 10: WCAG 2.1 AAA Accessibility Contrast Ratio Checks (> 18:1 Decoupled Badge, > 7:1 Text, > 3:1 Graphics).
11. Section 11: Standalone W3C SVG 1.1 Vector Graphic XML Validation via xml.etree.ElementTree.fromstring.
12. Section 12: Horner OCS Memory Synchronization (%R1740..%R1747, %M406..%M407) with PrivilegeMode.SYSTEM & ILogicUnit Scan Cycle.
13. Section 13: Deterministic 9-Stage Verification Runner run_hyperbolic_tree_canvas_verification & Artifact Export.
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

from jev_cscape.hmi.hyperbolic_tree_canvas import (
    BOUNDARY_OVERFLOW_FAULT,
    CANONICAL_LEVEL_RADII,
    CANVAS_CENTER_X,
    CANVAS_CENTER_Y,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COIL_CRITICAL_FAULT_ALARM_ACTIVE,
    COIL_HYPERBOLIC_TREE_ACTIVE,
    COIL_HYPERBOLIC_TREE_CANVAS_ACTIVE,
    COIL_TREE_FAULT_TRIP,
    COIL_W213_CANVAS_ACTIVE,
    COIL_W213_FAULT_ALARM,
    COLOR_ALARM_CRIMSON,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_CONCENTRIC_GUIDE,
    COLOR_CRITICAL,
    COLOR_DARK_SURFACE,
    COLOR_DARK_THEME_BACKING,
    COLOR_DECOUPLED_BADGE,
    COLOR_DISK_BOUNDARY,
    COLOR_FOCUS_BLUE,
    COLOR_GEODESIC_EDGE,
    COLOR_NOMINAL,
    COLOR_NOMINAL_EMERALD,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_WARNING,
    COLOR_WARM_AMBER,
    ComplexPoint,
    DIAG_ERR_BOUNDARY_OVERFLOW,
    DIAG_ERR_CRITICAL_FAULT_TRIP,
    DIAG_ERR_HIERARCHY_CYCLE_DETECTED,
    DIAG_ERR_SVG_RENDER_FAULT,
    DIAG_EVENT_OK,
    DIAG_OK,
    DiagnosticCode,
    GeodesicArc,
    HEALTH_CRITICAL_THRESHOLD,
    HEALTH_NOMINAL_BASELINE,
    HEALTH_WARNING_THRESHOLD,
    HIERARCHY_CYCLE_DETECTED,
    HYPERBOLIC_TREE_CANVAS_PURE_ST_POU,
    HYPERBOLIC_TREE_PURE_ST_POU,
    HierarchyCycleError,
    HyperbolicBoundaryError,
    HyperbolicTree,
    HyperbolicTreeCanvas,
    HyperbolicTreeCanvasEngine,
    HyperbolicTreeCanvasSync,
    HyperbolicTreeMetrics,
    HyperbolicTreeStatusBits,
    MAX_HYPERBOLIC_RADIUS,
    NodeHealthState,
    POINCARE_DISK_RADIUS,
    REG_CRITICAL_FAULT_COUNT,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_MAX_TREE_DEPTH,
    REG_MIN_HEALTH_SCORE_SCALED,
    REG_ROOT_HEALTH_SCORE_SCALED,
    REG_SELECTED_NODE_DISTANCE_SCALED,
    REG_SELECTED_NODE_INDEX,
    REG_TOTAL_NODE_COUNT,
    REG_W213_CRITICAL_FAULTS,
    REG_W213_DIAGNOSTIC_CODE,
    REG_W213_MAX_DEPTH,
    REG_W213_MIN_HEALTH,
    REG_W213_ROOT_HEALTH,
    REG_W213_SELECTED_DISTANCE,
    REG_W213_SELECTED_NODE,
    REG_W213_STATUS_WORD,
    REG_W213_TOTAL_NODES,
    SVG_RENDER_FAULT,
    SingularityError,
    TreeNode,
    W213_HYPERBOLIC_TREE_PURE_ST_POU,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    clamp_to_disk,
    compute_geodesic_arc,
    contrast_ratio,
    create_canonical_hyperbolic_tree_canvas,
    create_canonical_scada_hyperbolic_tree,
    disk_to_pixel,
    find_min_health_node,
    generate_hyperbolic_tree_canvas_svg,
    hyperbolic_distance,
    identify_critical_faults,
    is_in_poincare_disk,
    layout_hyperbolic_tree,
    mobius_inverse,
    mobius_transform,
    pixel_to_disk,
    propagate_bottom_up_health,
    recenter_tree_at,
    relative_luminance,
    run_hyperbolic_tree_canvas_verification,
    to_complex_point,
    validate_wcag_aaa_contrast,
    verify_hyperbolic_tree_canvas_pure_st,
)


# ============================================================================
# Section 1: Pure ST POU Grammar & AST Validation (%R1740..%R1747, %M406..%M407)
# ============================================================================

class TestSection1PureStGrammarAndAst:
    """Validate Pure IEC 61131-3 Structured Text POU syntax and symbol bindings."""

    def test_st_pou_passes_security_guard_purity(self) -> None:
        """Ensure ST POU passes SecurityGuard pure ST inspection without exceptions."""
        SecurityGuard.assert_pure_st_content(HYPERBOLIC_TREE_CANVAS_PURE_ST_POU)

    def test_st_pou_ast_parsing_program_type(self) -> None:
        """Parse ST POU with STParser and verify AST metadata."""
        parser = STParser()
        pou = parser.parse_pou(HYPERBOLIC_TREE_CANVAS_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "HyperbolicTreeCanvasSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_st_pou_variable_count_and_types(self) -> None:
        """Confirm exactly 10 declared variables with INT and BOOL data types."""
        parser = STParser()
        pou = parser.parse_pou(HYPERBOLIC_TREE_CANVAS_PURE_ST_POU)
        assert len(pou.variables) == 10
        int_vars = [v for v in pou.variables if v.data_type == "INT"]
        bool_vars = [v for v in pou.variables if v.data_type == "BOOL"]
        assert len(int_vars) == 8
        assert len(bool_vars) == 2

    def test_st_pou_register_address_bindings(self) -> None:
        """Validate all 8 analog variables bind to %R1740..%R1747."""
        parser = STParser()
        pou = parser.parse_pou(HYPERBOLIC_TREE_CANVAS_PURE_ST_POU)
        vmap = {v.name: v.address_binding for v in pou.variables}
        expected_regs = {
            "RootAggregateHealthScoreScaled": "%R1740",
            "SelectedNodeIndex": "%R1741",
            "SelectedNodeDistanceScaled": "%R1742",
            "CriticalFaultCount": "%R1743",
            "MaxTreeDepth": "%R1744",
            "TotalNodeCount": "%R1745",
            "MinHealthScoreScaled": "%R1746",
            "DiagnosticStatusCode": "%R1747",
        }
        for name, expected_addr in expected_regs.items():
            assert vmap.get(name) == expected_addr

    def test_st_pou_discrete_coils_bindings(self) -> None:
        """Validate discrete coils bind to %M406 and %M407."""
        parser = STParser()
        pou = parser.parse_pou(HYPERBOLIC_TREE_CANVAS_PURE_ST_POU)
        vmap = {v.name: v.address_binding for v in pou.variables}
        assert vmap.get("CriticalFaultAlarmActive") == "%M406"
        assert vmap.get("HyperbolicTreeCanvasActive") == "%M407"

    def test_verify_hyperbolic_tree_canvas_pure_st_helper(self) -> None:
        """Verify helper function returns True."""
        assert verify_hyperbolic_tree_canvas_pure_st() is True

    def test_st_pou_aliases_identity(self) -> None:
        """Ensure backward compatibility aliases match primary POU string."""
        assert HYPERBOLIC_TREE_PURE_ST_POU == HYPERBOLIC_TREE_CANVAS_PURE_ST_POU
        assert W213_HYPERBOLIC_TREE_PURE_ST_POU == HYPERBOLIC_TREE_CANVAS_PURE_ST_POU


# ============================================================================
# Section 2: SecurityGuard Anti-Ladder Construct Interception
# ============================================================================

class TestSection2AntiLadderConstructInterception:
    """Verify fail-closed interception of forbidden ladder logic artifacts."""

    def test_ladder_normally_open_contact_rejected(self) -> None:
        bad_st = "PROGRAM Test VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_normally_closed_contact_rejected(self) -> None:
        bad_st = "PROGRAM Test VAR X: BOOL; END_VAR ---[/]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_standard_coil_rejected(self) -> None:
        bad_st = "PROGRAM Test VAR Y: BOOL; END_VAR ---( )--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_set_coil_rejected(self) -> None:
        bad_st = "PROGRAM Test VAR Y: BOOL; END_VAR ---(S)--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_reset_coil_rejected(self) -> None:
        bad_st = "PROGRAM Test VAR Y: BOOL; END_VAR ---(R)--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_rung_keyword_rejected(self) -> None:
        bad_st = "PROGRAM Test\nRUNG 1:\nX := 1;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_network_keyword_rejected(self) -> None:
        bad_st = "PROGRAM Test\nNETWORK 1:\nY := 0;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_mnemonic_xic_rejected(self) -> None:
        bad_st = "PROGRAM Test\nXIC bit_in;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_mnemonic_ote_rejected(self) -> None:
        bad_st = "PROGRAM Test\nOTE bit_out;\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)


# ============================================================================
# Section 3: ComplexPoint Coordinates & Poincaré Disk Boundary
# ============================================================================

class TestSection3ComplexCoordinatesAndBoundary:
    """Test ComplexPoint arithmetic, boundary containment (|z| < 1), and clamping."""

    def test_complex_point_basic_arithmetic(self) -> None:
        p1 = ComplexPoint(1.5, 2.5)
        p2 = ComplexPoint(0.5, -1.0)
        p_add = p1 + p2
        assert math.isclose(p_add.x, 2.0)
        assert math.isclose(p_add.y, 1.5)

        p_sub = p1 - p2
        assert math.isclose(p_sub.x, 1.0)
        assert math.isclose(p_sub.y, 3.5)

        p_mul = p1 * 2.0
        assert math.isclose(p_mul.x, 3.0)
        assert math.isclose(p_mul.y, 5.0)

    def test_complex_multiplication_complex(self) -> None:
        # (1 + 2i) * (3 + 4i) = 3 - 8 + (4 + 6)i = -5 + 10i
        p1 = ComplexPoint(1.0, 2.0)
        p2 = ComplexPoint(3.0, 4.0)
        prod = p1 * p2
        assert math.isclose(prod.x, -5.0)
        assert math.isclose(prod.y, 10.0)

    def test_complex_division_complex(self) -> None:
        # (-5 + 10i) / (3 + 4i) = (1 + 2i)
        p1 = ComplexPoint(-5.0, 10.0)
        p2 = ComplexPoint(3.0, 4.0)
        quot = p1 / p2
        assert math.isclose(quot.x, 1.0)
        assert math.isclose(quot.y, 2.0)

    def test_complex_division_by_zero_singularity(self) -> None:
        p = ComplexPoint(1.0, 1.0)
        with pytest.raises(SingularityError):
            _ = p / 0.0
        with pytest.raises(SingularityError):
            _ = p / ComplexPoint(0.0, 0.0)

    def test_complex_point_magnitude_and_conjugate(self) -> None:
        p = ComplexPoint(3.0, 4.0)
        assert math.isclose(p.magnitude(), 5.0)
        assert math.isclose(p.magnitude_squared(), 25.0)
        conj = p.conjugate()
        assert conj.x == 3.0
        assert conj.y == -4.0

    def test_complex_point_angle_and_polar(self) -> None:
        p = ComplexPoint.from_polar(2.0, math.pi / 4.0)
        assert math.isclose(p.magnitude(), 2.0, abs_tol=1e-5)
        assert math.isclose(p.angle(), math.pi / 4.0, abs_tol=1e-5)

    def test_is_in_poincare_disk_boundary(self) -> None:
        assert is_in_poincare_disk(ComplexPoint(0.0, 0.0)) is True
        assert is_in_poincare_disk(ComplexPoint(0.6, 0.7)) is True  # 0.36 + 0.49 = 0.85 < 1
        assert is_in_poincare_disk(ComplexPoint(0.8, 0.6)) is False  # 0.64 + 0.36 = 1.0
        assert is_in_poincare_disk(ComplexPoint(1.1, 0.0)) is False

    def test_radius_clamping_behavior(self) -> None:
        p_in = ComplexPoint(0.5, 0.5)
        clamped_in = clamp_to_disk(p_in, max_radius=MAX_HYPERBOLIC_RADIUS)
        assert math.isclose(clamped_in.x, 0.5)
        assert math.isclose(clamped_in.y, 0.5)

        p_out = ComplexPoint(1.5, 2.0)  # mag = 2.5
        clamped_out = clamp_to_disk(p_out, max_radius=MAX_HYPERBOLIC_RADIUS)
        assert math.isclose(clamped_out.magnitude(), MAX_HYPERBOLIC_RADIUS, abs_tol=1e-4)
        assert math.isclose(clamped_out.angle(), p_out.angle(), abs_tol=1e-4)

    def test_disk_pixel_roundtrip(self) -> None:
        z_orig = ComplexPoint(0.4, -0.5)
        px = disk_to_pixel(z_orig, CANVAS_CENTER_X, CANVAS_CENTER_Y, POINCARE_DISK_RADIUS)
        z_back = pixel_to_disk(px[0], px[1], CANVAS_CENTER_X, CANVAS_CENTER_Y, POINCARE_DISK_RADIUS)
        assert math.isclose(z_back.x, z_orig.x, abs_tol=1e-4)
        assert math.isclose(z_back.y, z_orig.y, abs_tol=1e-4)


# ============================================================================
# Section 4: Möbius Transformations & Singularity Guards
# ============================================================================

class TestSection4MobiusTransformations:
    """Test Poincaré disk automorphism Möbius transformations and singularities."""

    def test_mobius_identity_when_a_zero(self) -> None:
        z = ComplexPoint(0.3, -0.4)
        res = mobius_transform(z, ComplexPoint(0.0, 0.0))
        assert math.isclose(res.x, z.x, abs_tol=1e-10)
        assert math.isclose(res.y, z.y, abs_tol=1e-10)

    def test_mobius_maps_a_to_origin(self) -> None:
        a = ComplexPoint(0.45, -0.35)
        res = mobius_transform(a, a)
        assert math.isclose(res.magnitude(), 0.0, abs_tol=1e-12)

    def test_mobius_preserves_unit_disk_boundary(self) -> None:
        a = ComplexPoint(0.5, 0.2)
        test_points = [
            ComplexPoint(0.1, 0.2),
            ComplexPoint(-0.4, 0.3),
            ComplexPoint(0.7, -0.5),
            ComplexPoint(0.0, 0.0),
        ]
        for pt in test_points:
            w = mobius_transform(pt, a)
            assert is_in_poincare_disk(w) is True

    def test_mobius_inverse_reconstructs_original(self) -> None:
        z = ComplexPoint(0.2, 0.6)
        a = ComplexPoint(-0.3, 0.4)
        w = mobius_transform(z, a)
        z_rec = mobius_inverse(w, a)
        assert math.isclose(z_rec.x, z.x, abs_tol=1e-7)
        assert math.isclose(z_rec.y, z.y, abs_tol=1e-7)

    def test_mobius_with_rotation_angle(self) -> None:
        z = ComplexPoint(0.4, 0.0)
        a = ComplexPoint(0.0, 0.0)
        theta = math.pi / 2.0
        w = mobius_transform(z, a, theta=theta)
        # 0.4 rotated by 90 deg -> (0.0, 0.4)
        assert math.isclose(w.x, 0.0, abs_tol=1e-7)
        assert math.isclose(w.y, 0.4, abs_tol=1e-7)

        # Inverse with rotation
        z_rec = mobius_inverse(w, a, theta=theta)
        assert math.isclose(z_rec.x, z.x, abs_tol=1e-7)
        assert math.isclose(z_rec.y, z.y, abs_tol=1e-7)

    def test_mobius_boundary_guard_raises_error(self) -> None:
        z = ComplexPoint(0.2, 0.3)
        # Translation parameter |a| >= 1 must be blocked
        with pytest.raises(HyperbolicBoundaryError):
            mobius_transform(z, ComplexPoint(1.0, 0.0))
        with pytest.raises(HyperbolicBoundaryError):
            mobius_inverse(z, ComplexPoint(0.8, 0.8))


# ============================================================================
# Section 5: Poincaré Hyperbolic Distance Metric
# ============================================================================

class TestSection5HyperbolicDistanceMetric:
    """Test Poincaré distance metric d(u, v) = 2 * artanh(|u - v| / |1 - conj(u)*v|)."""

    def test_distance_to_self_is_zero(self) -> None:
        pt = ComplexPoint(0.3, 0.4)
        assert math.isclose(hyperbolic_distance(pt, pt), 0.0, abs_tol=1e-12)

    def test_distance_symmetry(self) -> None:
        u = ComplexPoint(0.2, -0.3)
        v = ComplexPoint(-0.5, 0.4)
        d_uv = hyperbolic_distance(u, v)
        d_vu = hyperbolic_distance(v, u)
        assert math.isclose(d_uv, d_vu, abs_tol=1e-10)

    def test_distance_from_origin_matches_formula(self) -> None:
        origin = ComplexPoint(0.0, 0.0)
        r = 0.6
        v = ComplexPoint(r, 0.0)
        d = hyperbolic_distance(origin, v)
        # d(0, v) = 2 * artanh(|v|)
        expected = 2.0 * math.atanh(r)
        assert math.isclose(d, expected, abs_tol=1e-10)

    def test_distance_triangle_inequality(self) -> None:
        u = ComplexPoint(0.1, 0.2)
        v = ComplexPoint(-0.3, 0.5)
        w = ComplexPoint(0.4, -0.4)
        d_uv = hyperbolic_distance(u, v)
        d_vw = hyperbolic_distance(v, w)
        d_uw = hyperbolic_distance(u, w)
        assert d_uw <= d_uv + d_vw + 1e-10

    def test_distance_isometry_invariance_under_mobius(self) -> None:
        u = ComplexPoint(0.2, 0.1)
        v = ComplexPoint(-0.3, 0.4)
        a = ComplexPoint(0.1, -0.3)

        d_before = hyperbolic_distance(u, v)
        u_prime = mobius_transform(u, a)
        v_prime = mobius_transform(v, a)
        d_after = hyperbolic_distance(u_prime, v_prime)

        assert math.isclose(d_before, d_after, abs_tol=1e-7)

    def test_distance_asymptotic_growth_near_boundary(self) -> None:
        origin = ComplexPoint(0.0, 0.0)
        d1 = hyperbolic_distance(origin, ComplexPoint(0.5, 0.0))
        d2 = hyperbolic_distance(origin, ComplexPoint(0.9, 0.0))
        d3 = hyperbolic_distance(origin, ComplexPoint(0.99, 0.0))
        assert d1 < d2 < d3
        assert d3 > 5.0  # As r -> 1, distance diverges to infinity


# ============================================================================
# Section 6: Geodesic Arc Circle Geometry
# ============================================================================

class TestSection6GeodesicArcGeometry:
    """Test Poincaré geodesic arcs orthogonal to unit boundary circle."""

    def test_geodesic_origin_diameter_is_straight_line(self) -> None:
        u = ComplexPoint(0.0, 0.0)
        v = ComplexPoint(0.5, 0.5)
        arc = compute_geodesic_arc(u, v)
        assert arc.is_straight_line is True
        assert " L " in arc.svg_path

    def test_geodesic_collinear_with_origin_is_straight_line(self) -> None:
        u = ComplexPoint(0.2, 0.3)
        v = ComplexPoint(0.4, 0.6)  # collinear: 0.2*0.6 - 0.3*0.4 = 0
        arc = compute_geodesic_arc(u, v)
        assert arc.is_straight_line is True
        assert " L " in arc.svg_path

    def test_geodesic_orthogonal_circle_center_and_radius(self) -> None:
        u = ComplexPoint(0.2, 0.3)
        v = ComplexPoint(-0.4, 0.5)
        arc = compute_geodesic_arc(u, v)
        assert arc.is_straight_line is False
        assert arc.center_disk is not None
        assert arc.radius_disk is not None

        # Check orthogonality: |c|^2 - R^2 = 1.0
        c_mag_sq = arc.center_disk.magnitude_squared()
        r_sq = arc.radius_disk * arc.radius_disk
        assert math.isclose(c_mag_sq - r_sq, 1.0, abs_tol=1e-7)

        # Check circle passes through u and v
        dist_u = (arc.center_disk - u).magnitude()
        dist_v = (arc.center_disk - v).magnitude()
        assert math.isclose(dist_u, arc.radius_disk, abs_tol=1e-7)
        assert math.isclose(dist_v, arc.radius_disk, abs_tol=1e-7)

    def test_geodesic_svg_path_format(self) -> None:
        u = ComplexPoint(0.1, 0.4)
        v = ComplexPoint(0.6, -0.2)
        arc = compute_geodesic_arc(u, v)
        assert arc.svg_path.startswith("M ")
        assert " A " in arc.svg_path

    def test_geodesic_identical_points(self) -> None:
        u = ComplexPoint(0.3, 0.3)
        arc = compute_geodesic_arc(u, u)
        assert arc.is_straight_line is True
        assert arc.start_pixel == arc.end_pixel


# ============================================================================
# Section 7: Hierarchical Tree Modeling & Traversals
# ============================================================================

class TestSection7HierarchyTreeModeling:
    """Test HyperbolicTree data structure, parent-child links, and cycle detection."""

    def test_tree_node_creation_and_attributes(self) -> None:
        node = TreeNode(id="NODE1", name="Crude Distillation Unit", depth=2, health_score=94.5)
        assert node.id == "NODE1"
        assert node.depth == 2
        assert node.health_score == 94.5
        assert node.is_leaf() is True

    def test_tree_node_children_and_parent_links(self) -> None:
        parent = TreeNode(id="PARENT", name="Area Parent")
        child = TreeNode(id="CHILD", name="Unit Child")
        parent.add_child(child)
        assert len(parent.children) == 1
        assert child.parent is parent
        assert child.parent_id == "PARENT"
        assert parent.is_leaf() is False
        assert child.is_leaf() is True

    def test_tree_add_node_and_edge(self) -> None:
        tree = HyperbolicTree()
        n1 = TreeNode(id="N1", name="Root")
        n2 = TreeNode(id="N2", name="Area")
        tree.add_node(n1)
        tree.add_node(n2)
        tree.add_edge("N1", "N2")
        assert tree.total_node_count() == 2
        assert tree.get_root() is n1
        assert len(n1.children) == 1

    def test_tree_missing_parent_edge_raises(self) -> None:
        tree = HyperbolicTree()
        tree.add_node(TreeNode(id="N1", name="N1"))
        with pytest.raises(KeyError):
            tree.add_edge("NONEXISTENT", "N1")

    def test_tree_traversals(self) -> None:
        tree = HyperbolicTree()
        root = TreeNode(id="R", name="Root")
        c1 = TreeNode(id="C1", name="C1")
        c2 = TreeNode(id="C2", name="C2")
        tree.add_node(root)
        tree.add_node(c1)
        tree.add_node(c2)
        tree.add_edge("R", "C1")
        tree.add_edge("R", "C2")

        pre = [n.id for n in tree.traverse_preorder()]
        assert pre == ["R", "C1", "C2"]

        post = [n.id for n in tree.traverse_postorder()]
        assert post == ["C1", "C2", "R"]

        bfs = [n.id for n in tree.traverse_bfs()]
        assert bfs == ["R", "C1", "C2"]

    def test_cycle_detection_self_loop(self) -> None:
        tree = HyperbolicTree()
        n = TreeNode(id="A", name="A")
        tree.add_node(n)
        tree.add_edge("A", "A")
        assert tree.detect_cycles() is True
        with pytest.raises(HierarchyCycleError):
            tree.validate_acyclic()

    def test_cycle_detection_multi_hop_loop(self) -> None:
        tree = HyperbolicTree()
        n1 = TreeNode(id="A", name="A")
        n2 = TreeNode(id="B", name="B")
        n3 = TreeNode(id="C", name="C")
        tree.add_node(n1)
        tree.add_node(n2)
        tree.add_node(n3)
        tree.add_edge("A", "B")
        tree.add_edge("B", "C")
        tree.add_edge("C", "A")
        assert tree.detect_cycles() is True
        with pytest.raises(HierarchyCycleError):
            tree.validate_acyclic()


# ============================================================================
# Section 8: Radial Layout & Möbius Recentering
# ============================================================================

class TestSection8RadialLayoutAndRecentering:
    """Test Poincaré layout algorithm and interactive recentering."""

    def test_canonical_tree_creation(self) -> None:
        tree = create_canonical_scada_hyperbolic_tree()
        assert tree.total_node_count() == 29
        assert tree.max_depth() == 3
        assert tree.get_root().id == "PLANT_ROOT"

    def test_layout_places_root_at_origin(self) -> None:
        tree = create_canonical_scada_hyperbolic_tree()
        root = tree.get_root()
        assert math.isclose(root.z.magnitude(), 0.0, abs_tol=1e-10)
        assert math.isclose(root.z_view.magnitude(), 0.0, abs_tol=1e-10)

    def test_layout_all_nodes_strictly_in_disk(self) -> None:
        tree = create_canonical_scada_hyperbolic_tree()
        for node in tree.nodes.values():
            assert is_in_poincare_disk(node.z) is True
            assert node.z.magnitude() <= MAX_HYPERBOLIC_RADIUS

    def test_recenter_tree_brings_node_to_origin(self) -> None:
        tree = create_canonical_scada_hyperbolic_tree()
        target_id = "AREA_CRUDE"
        recenter_tree_at(tree, target_id)
        target = tree.get_node(target_id)
        assert math.isclose(target.z_view.magnitude(), 0.0, abs_tol=1e-10)
        assert math.isclose(target.hyperbolic_dist, 0.0, abs_tol=1e-10)

        # All other nodes must remain strictly inside disk
        for node in tree.nodes.values():
            assert is_in_poincare_disk(node.z_view) is True


# ============================================================================
# Section 9: Bottom-Up Health Score Propagation & Fault Trips
# ============================================================================

class TestSection9BottomUpHealthAndFaults:
    """Test health score aggregation, degraded asset tracking, and alarms."""

    def test_canonical_nominal_health_scores(self) -> None:
        tree = create_canonical_scada_hyperbolic_tree()
        root = tree.get_root()
        assert root.health_score >= 94.0
        assert len(identify_critical_faults(tree)) == 0

    def test_leaf_fault_propagation_to_root(self) -> None:
        tree = create_canonical_scada_hyperbolic_tree()
        root = tree.get_root()
        orig_health = root.health_score

        # Inject severe fault on a leaf subsystem
        leaf = tree.get_node("SS_CDU_PUMP")
        leaf.health_score = 30.0
        propagate_bottom_up_health(tree)

        assert leaf.is_fault is True
        assert leaf.status == NodeHealthState.CRITICAL.value
        assert root.health_score < orig_health

        faults = identify_critical_faults(tree)
        assert len(faults) >= 1
        assert any(f.id == "SS_CDU_PUMP" for f in faults)

    def test_find_min_health_node(self) -> None:
        tree = create_canonical_scada_hyperbolic_tree()
        min_node_initial = find_min_health_node(tree)
        assert min_node_initial is not None

        # Inject lowest score
        target = tree.get_node("SS_FCC_RISER")
        target.health_score = 25.0
        propagate_bottom_up_health(tree)

        min_node = find_min_health_node(tree)
        assert min_node.id == "SS_FCC_RISER"
        assert min_node.health_score == 25.0


# ============================================================================
# Section 10: WCAG 2.1 AAA Accessibility Contrast Ratio
# ============================================================================

class TestSection10WcagAccessibilityContrast:
    """Test WCAG 2.1 relative luminance and AAA contrast ratio compliance."""

    def test_relative_luminance_extremes(self) -> None:
        lum_white = relative_luminance("#FFFFFF")
        lum_black = relative_luminance("#000000")
        assert math.isclose(lum_white, 1.0, abs_tol=1e-4)
        assert math.isclose(lum_black, 0.0, abs_tol=1e-4)

    def test_contrast_ratio_formula(self) -> None:
        cr = contrast_ratio("#FFFFFF", "#000000")
        assert math.isclose(cr, 21.0, abs_tol=1e-2)

    def test_decoupled_badge_contrast_exceeds_18_to_1(self) -> None:
        cr_badge = contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert cr_badge > WCAG_AAA_BADGE_CONTRAST_TARGET  # > 18:1

    def test_primary_text_contrast_exceeds_7_to_1(self) -> None:
        cr_text = contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert cr_text > WCAG_AAA_TEXT_CONTRAST_TARGET  # > 7:1

    def test_validate_wcag_aaa_contrast_helper(self) -> None:
        is_aaa, text_cr, badge_cr = validate_wcag_aaa_contrast()
        assert is_aaa is True
        assert text_cr > 7.0
        assert badge_cr > 18.0


# ============================================================================
# Section 11: Standalone W3C SVG 1.1 Vector Graphic XML Validation
# ============================================================================

class TestSection11SvgXmlValidation:
    """Validate standalone SVG vector graphic generation and XML parsing."""

    def test_svg_xml_well_formed_et_fromstring(self) -> None:
        canvas = create_canonical_hyperbolic_tree_canvas()
        svg_str = canvas.render_svg()
        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg")
        assert root.attrib.get("width") == str(CANVAS_VIEWPORT_WIDTH)
        assert root.attrib.get("height") == str(CANVAS_VIEWPORT_HEIGHT)

    def test_svg_contains_boundary_circle_and_guides(self) -> None:
        canvas = create_canonical_hyperbolic_tree_canvas()
        svg_str = canvas.render_svg()
        assert f'r="{POINCARE_DISK_RADIUS:.1f}"' in svg_str
        assert "Poincaré Unit Disk Boundary" in svg_str

    def test_svg_contains_geodesic_arc_paths(self) -> None:
        canvas = create_canonical_hyperbolic_tree_canvas()
        svg_str = canvas.render_svg()
        assert "<path d=" in svg_str

    def test_svg_contains_telemetry_hud_entries(self) -> None:
        canvas = create_canonical_hyperbolic_tree_canvas()
        svg_str = canvas.render_svg()
        assert "W213 POINCARÉ DISK SCADA" in svg_str
        assert "Plant Root Health" in svg_str
        assert "Horner Diagnostic (%R1747)" in svg_str

    def test_empty_tree_svg_render_raises_value_error(self) -> None:
        empty_tree = HyperbolicTree()
        metrics = HyperbolicTreeMetrics()
        with pytest.raises(ValueError):
            generate_hyperbolic_tree_canvas_svg(
                tree=empty_tree,
                metrics=metrics,
                status_bits=HyperbolicTreeStatusBits.CANVAS_ACTIVE,
            )


# ============================================================================
# Section 12: Horner OCS Register Sync & ILogicUnit Scan Cycle
# ============================================================================

class TestSection12HornerOcsRegisterSyncAndScanCycle:
    """Test Horner RegisterTable synchronization (%R1740..%R1747, %M406..%M407) and ILogicUnit."""

    def test_register_sync_nominal_registers(self) -> None:
        reg_table = RegisterTable()
        canvas = HyperbolicTreeCanvas(reg_table=reg_table)
        canvas.sync_to_registers(privilege=PrivilegeMode.SYSTEM)

        r1740 = reg_table.read_word("%R1740")
        r1741 = reg_table.read_word("%R1741")
        r1742 = reg_table.read_word("%R1742")
        r1743 = reg_table.read_word("%R1743")
        r1744 = reg_table.read_word("%R1744")
        r1745 = reg_table.read_word("%R1745")
        r1746 = reg_table.read_word("%R1746")
        r1747 = reg_table.read_word("%R1747")
        m406 = reg_table.read_bit("%M406")
        m407 = reg_table.read_bit("%M407")

        assert r1740 >= 900
        assert r1741 == 0
        assert r1742 == 0
        assert r1743 == 0
        assert r1744 == 3
        assert r1745 == 29
        assert r1746 >= 900
        assert r1747 == 0
        assert m406 is False
        assert m407 is True

    def test_select_node_updates_registers(self) -> None:
        reg_table = RegisterTable()
        canvas = HyperbolicTreeCanvas(reg_table=reg_table)
        canvas.select_node("AREA_CRUDE", recenter=True)

        r1741 = reg_table.read_word("%R1741")
        assert r1741 == 1  # Index of AREA_CRUDE
        assert canvas.selected_node_id == "AREA_CRUDE"

    def test_fault_injection_trips_coil_m406(self) -> None:
        reg_table = RegisterTable()
        canvas = HyperbolicTreeCanvas(reg_table=reg_table)
        canvas.inject_node_fault("SS_CDU_PUMP", health_score=45.0)

        r1743 = reg_table.read_word("%R1743")
        r1746 = reg_table.read_word("%R1746")
        r1747 = reg_table.read_word("%R1747")
        m406 = reg_table.read_bit("%M406")

        assert r1743 >= 1
        assert r1746 == 450
        assert (r1747 & 0xFFFF) == (int(DIAG_ERR_CRITICAL_FAULT_TRIP) & 0xFFFF)
        assert m406 is True

    def test_diagnostic_fault_triggers(self) -> None:
        canvas = HyperbolicTreeCanvas()

        canvas.trigger_cycle_fault()
        assert canvas.diagnostic_code == DIAG_ERR_HIERARCHY_CYCLE_DETECTED
        assert bool(canvas.status_bits & HyperbolicTreeStatusBits.CYCLE_DETECTED)

        canvas.trigger_boundary_fault()
        assert canvas.diagnostic_code == DIAG_ERR_BOUNDARY_OVERFLOW
        assert bool(canvas.status_bits & HyperbolicTreeStatusBits.BOUNDARY_OVERFLOW_FAULT)

        canvas.trigger_render_fault()
        assert canvas.diagnostic_code == DIAG_ERR_SVG_RENDER_FAULT
        assert bool(canvas.status_bits & HyperbolicTreeStatusBits.RENDER_FAULT)

    def test_ilogic_unit_interface(self) -> None:
        canvas = HyperbolicTreeCanvas()
        assert canvas.name == "HyperbolicTreeCanvasSync"
        assert canvas.priority == 95
        assert canvas.is_enabled is True

        # Scan step and step
        canvas.scan_step(dt=0.02)
        canvas.step()

        # Context execute
        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=lambda a: canvas.reg_table.read_word(a),
            set_register=lambda a, v: canvas.reg_table.write_word(a, v, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda n, d=None: d,
            set_variable=lambda n, v: None,
            record_fault=lambda f: None,
        )
        canvas.execute(ctx)

    def test_ilogic_unit_reset_nominal(self) -> None:
        canvas = HyperbolicTreeCanvas()
        canvas.inject_node_fault("SS_CDU_PUMP", 30.0)
        assert canvas.critical_fault_alarm_active is True

        canvas.reset()
        assert canvas.critical_fault_alarm_active is False
        assert canvas.diagnostic_code == DIAG_OK


# ============================================================================
# Section 13: Deterministic 9-Stage Verification Runner
# ============================================================================

class TestSection13VerificationRunner:
    """Test run_hyperbolic_tree_canvas_verification determinism and evidence generation."""

    def test_runner_returns_success_and_all_9_stages_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"

            res = run_hyperbolic_tree_canvas_verification(
                output_path=str(ev_path),
                sample_svg_path=str(svg_path),
                work_package="W213",
            )

            assert res["status"] == "success"
            assert res["error_code"] is None
            data = res["data"]
            assert data["checks_passed"] == 9
            assert data["total_checks"] == 9
            assert len(data["tests"]) == 9

            for t in data["tests"]:
                assert t["passed"] is True

            # Verify files were created
            assert ev_path.exists()
            assert svg_path.exists()

            # Verify evidence file is valid JSON
            with open(ev_path, "r", encoding="utf-8") as f:
                evidence = json.load(f)
            assert evidence["status"] == "success"

            # Verify sample SVG is valid XML
            with open(svg_path, "r", encoding="utf-8") as f:
                svg_content = f.read()
            root_el = ET.fromstring(svg_content)
            assert root_el.tag.endswith("svg")
