"""Comprehensive Unit Test Suite for Cscape HMI Dynamic Spatial K-D Tree SCADA Canvas (W294).

Work Package: W294 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial K-D Tree SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Covers:
1. Constants, viewport dimensions, color palettes, status bits, and diagnostic codes (0x8411..0x8415)
2. KdRect geometry, area, boundary containment, and KdPoint / KdNode tree structures
3. K-D tree dynamic node insertion, alternating orthogonal axis splitting (x at depth 0, 2; y at depth 1, 3)
4. Domain bounds validation [0, 1200] x [0, 750] and degenerate NaN/Inf coordinate rejection
5. Tree depth tracking (0..12), count calculation, and median-split balanced reconstruction
6. Branch-and-bound nearest-neighbor (1-NN) search precision vs analytical ground truth
7. Branch-and-bound k-nearest-neighbors (k-NN) range search, distance monotonicity, and brute-force equivalence
8. Spatial proximity hazard detection, violation counting, and alarm assertion (%M596 / 0x8415)
9. W3C SVG 1.1 vector graphic generation, valid XML parsing, and WCAG 2.1 AAA contrast (> 18:1)
10. Horner OCS register space synchronization (%R2550..%R2557, %M595..%M596) and privilege levels
11. Pure IEC 61131-3 Structured Text validation & anti-ladder rejection
12. ILogicUnit interface compliance (scan_step, step, execute, reset, multi-cycle soak)
13. Deterministic 9-stage verification runner execution and artifact export
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.kdtree_canvas import (
    CANVAS_VIEWPORT_WIDTH,
    CANVAS_VIEWPORT_HEIGHT,
    TOTAL_DOMAIN_AREA,
    DEFAULT_MAX_DEPTH,
    DEFAULT_HAZARD_THRESHOLD,
    COLOR_SCADA_BG,
    COLOR_DARK_SURFACE,
    COLOR_DECOUPLED_BADGE,
    COLOR_BORDER,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_MUTED,
    COLOR_SAMPLE_NODE,
    COLOR_SAMPLE_BORDER,
    COLOR_NOMINAL_EMERALD,
    COLOR_WARNING_AMBER,
    COLOR_ALARM_CRIMSON,
    COLOR_RETICLE_CYAN,
    COLOR_PARTITION_X,
    COLOR_PARTITION_Y,
    COLOR_CONNECTOR_VECTOR,
    DEPTH_COLORS,
    REG_KDTREE_TOTAL_NODES,
    REG_KDTREE_SUBDIVISION_DEPTH,
    REG_KDTREE_QUERY_TARGET_ID,
    REG_KDTREE_NEAREST_NODE_ID,
    REG_KDTREE_NEAREST_DISTANCE_SCALED,
    REG_KDTREE_HAZARD_THRESHOLD_SCALED,
    REG_KDTREE_HAZARD_VIOLATIONS_COUNT,
    REG_KDTREE_DIAGNOSTIC_CODE,
    COIL_KDTREE_INDEXING_ONLINE,
    COIL_KDTREE_PROXIMITY_HAZARD_ALARM,
    REG_W294_TOTAL_NODES,
    REG_W294_SUBDIVISION_DEPTH,
    REG_W294_QUERY_TARGET_ID,
    REG_W294_NEAREST_NODE_ID,
    REG_W294_NEAREST_DISTANCE_SCALED,
    REG_W294_HAZARD_THRESHOLD_SCALED,
    REG_W294_HAZARD_VIOLATIONS_COUNT,
    REG_W294_DIAGNOSTIC_CODE,
    COIL_W294_INDEXING_ONLINE,
    COIL_W294_PROXIMITY_HAZARD_ALARM,
    REG_KDTREE_NODE_COUNT,
    REG_KDTREE_DEPTH,
    REG_KDTREE_MAX_DEPTH,
    REG_KDTREE_TARGET_ID,
    REG_KDTREE_NEAREST_ID,
    REG_KDTREE_NEAREST_DIST,
    REG_KDTREE_HAZARD_THRESHOLD,
    REG_KDTREE_VIOLATIONS_COUNT,
    COIL_KDTREE_CANVAS_ACTIVE,
    COIL_KDTREE_HAZARD_ALARM,
    DiagnosticCode,
    KdtreeDiagnosticCode,
    KdDiagnosticCode,
    DIAG_OK,
    DIAG_ERR_INVALID_DOMAIN,
    DIAG_ERR_EMPTY_TREE,
    DIAG_ERR_INVALID_K_NEIGHBORS,
    DIAG_ERR_DEGENERATE_COORDINATES,
    DIAG_ERR_PROXIMITY_HAZARD_ALARM,
    DIAG_ERR_OUT_OF_BOUNDS,
    DIAG_ERR_DEGENERATE_NODE_COORDS,
    DIAG_ERR_HAZARD_ALARM,
    KdtreeStatusBits,
    KdStatusBits,
    KdPoint,
    KdNodePoint,
    SpatialPoint,
    KdRect,
    BoundingBox,
    KdBounds,
    KdNode,
    KdtreeMetrics,
    KdMetrics,
    KdtreeCanvasEngine,
    KdtreeCanvas,
    ST_PROGRAM_KDTREE_CANVAS_SYNC,
    KDTREE_CANVAS_PURE_ST_POU,
    KdtreeCanvasSync,
    verify_kdtree_canvas_pure_st,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    generate_kdtree_canvas_svg,
    create_canonical_kdtree_canvas,
    run_kdtree_canvas_verification,
)


class TestKdtreeConstantsAndDiagnostics:
    """Test suite for W294 constants, dimensions, palettes, and diagnostic codes."""

    def test_viewport_and_domain_constants(self) -> None:
        """Verify canvas dimensions and domain area."""
        assert CANVAS_VIEWPORT_WIDTH == 1200.0
        assert CANVAS_VIEWPORT_HEIGHT == 750.0
        assert TOTAL_DOMAIN_AREA == 1200.0 * 750.0
        assert DEFAULT_MAX_DEPTH == 12
        assert DEFAULT_HAZARD_THRESHOLD == 30.0

    def test_palette_and_theme_constants(self) -> None:
        """Verify high-contrast SCADA theme color definitions."""
        assert COLOR_SCADA_BG == "#0D1117"
        assert COLOR_DARK_SURFACE == "#161B22"
        assert COLOR_DECOUPLED_BADGE == "#05080C"
        assert COLOR_BORDER == "#334155"
        assert COLOR_TEXT_PRIMARY == "#FFFFFF"
        assert COLOR_TEXT_MUTED == "#CBD5E1"
        assert COLOR_SAMPLE_NODE == "#38BDF8"
        assert COLOR_SAMPLE_BORDER == "#0284C7"
        assert COLOR_NOMINAL_EMERALD == "#10B981"
        assert COLOR_WARNING_AMBER == "#F59E0B"
        assert COLOR_ALARM_CRIMSON == "#EF4444"
        assert COLOR_RETICLE_CYAN == "#06B6D4"
        assert COLOR_PARTITION_X == "#38BDF8"
        assert COLOR_PARTITION_Y == "#10B981"
        assert COLOR_CONNECTOR_VECTOR == "#F59E0B"

    def test_depth_colors_length_and_format(self) -> None:
        """Verify depth colors provide entries for levels 0 to 12."""
        assert len(DEPTH_COLORS) == 13
        for c in DEPTH_COLORS:
            assert c.startswith("#")
            assert len(c) == 7

    def test_register_mappings_and_aliases(self) -> None:
        """Verify primary Horner OCS register addresses and work package aliases."""
        assert REG_KDTREE_TOTAL_NODES == "%R2550"
        assert REG_KDTREE_SUBDIVISION_DEPTH == "%R2551"
        assert REG_KDTREE_QUERY_TARGET_ID == "%R2552"
        assert REG_KDTREE_NEAREST_NODE_ID == "%R2553"
        assert REG_KDTREE_NEAREST_DISTANCE_SCALED == "%R2554"
        assert REG_KDTREE_HAZARD_THRESHOLD_SCALED == "%R2555"
        assert REG_KDTREE_HAZARD_VIOLATIONS_COUNT == "%R2556"
        assert REG_KDTREE_DIAGNOSTIC_CODE == "%R2557"
        assert COIL_KDTREE_INDEXING_ONLINE == "%M595"
        assert COIL_KDTREE_PROXIMITY_HAZARD_ALARM == "%M596"

        assert REG_W294_TOTAL_NODES == "%R2550"
        assert REG_W294_SUBDIVISION_DEPTH == "%R2551"
        assert REG_W294_QUERY_TARGET_ID == "%R2552"
        assert REG_W294_NEAREST_NODE_ID == "%R2553"
        assert REG_W294_NEAREST_DISTANCE_SCALED == "%R2554"
        assert REG_W294_HAZARD_THRESHOLD_SCALED == "%R2555"
        assert REG_W294_HAZARD_VIOLATIONS_COUNT == "%R2556"
        assert REG_W294_DIAGNOSTIC_CODE == "%R2557"
        assert COIL_W294_INDEXING_ONLINE == "%M595"
        assert COIL_W294_PROXIMITY_HAZARD_ALARM == "%M596"

        # Compatibility aliases
        assert REG_KDTREE_NODE_COUNT == "%R2550"
        assert REG_KDTREE_DEPTH == "%R2551"
        assert REG_KDTREE_MAX_DEPTH == "%R2551"
        assert REG_KDTREE_TARGET_ID == "%R2552"
        assert REG_KDTREE_NEAREST_ID == "%R2553"
        assert REG_KDTREE_NEAREST_DIST == "%R2554"
        assert REG_KDTREE_HAZARD_THRESHOLD == "%R2555"
        assert REG_KDTREE_VIOLATIONS_COUNT == "%R2556"
        assert COIL_KDTREE_CANVAS_ACTIVE == "%M595"
        assert COIL_KDTREE_HAZARD_ALARM == "%M596"

    def test_diagnostic_code_values_and_equality(self) -> None:
        """Verify 16-bit diagnostic codes and signed/unsigned equality."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_INVALID_DOMAIN == 0x8411
        assert DIAG_ERR_EMPTY_TREE == 0x8412
        assert DIAG_ERR_INVALID_K_NEIGHBORS == 0x8413
        assert DIAG_ERR_DEGENERATE_COORDINATES == 0x8414
        assert DIAG_ERR_PROXIMITY_HAZARD_ALARM == 0x8415

        # Compatibility aliases
        assert DIAG_ERR_OUT_OF_BOUNDS == 0x8411
        assert DIAG_ERR_DEGENERATE_NODE_COORDS == 0x8414
        assert DIAG_ERR_HAZARD_ALARM == 0x8415

        # String and repr representations
        assert repr(DIAG_ERR_PROXIMITY_HAZARD_ALARM) == "DiagnosticCode(0x8415)"
        assert str(DIAG_ERR_PROXIMITY_HAZARD_ALARM) == "0x8415"
        assert repr(DIAG_OK) == "DiagnosticCode(0x0000)"
        assert str(DIAG_OK) == "0x0000"

        # Signed 16-bit negative equivalence check
        val_signed = 0x8415 - 0x10000
        assert DIAG_ERR_PROXIMITY_HAZARD_ALARM == val_signed

    def test_status_bits(self) -> None:
        """Verify status flag bitmask."""
        b = KdtreeStatusBits.INDEXING_ONLINE | KdtreeStatusBits.SVG_RENDER_VALID
        assert KdtreeStatusBits.INDEXING_ONLINE in b
        assert KdtreeStatusBits.PROXIMITY_HAZARD_ALARM not in b
        assert KdStatusBits == KdtreeStatusBits


class TestKdGeometryAndStructures:
    """Test suite for KdRect, KdPoint, KdNode, and metrics containers."""

    def test_kd_rect_geometry(self) -> None:
        """Verify axis-aligned bounding rectangle calculations and containment."""
        rect = KdRect(100.0, 50.0, 400.0, 350.0)
        assert rect.width == 300.0
        assert rect.height == 300.0
        assert rect.area == 90000.0
        assert rect.center_x == 250.0
        assert rect.center_y == 200.0

        assert rect.contains_coord(200.0, 200.0) is True
        assert rect.contains_coord(50.0, 200.0) is False
        assert rect.contains_coord(100.0, 50.0) is True  # Inclusive boundary
        assert rect.contains_coord(400.0, 350.0) is True

        p1 = KdPoint(x=250.0, y=150.0, id=10)
        p2 = KdPoint(x=550.0, y=150.0, id=20)
        assert rect.contains_point(p1) is True
        assert rect.contains_point(p2) is False
        assert rect.contains_point((200.0, 200.0)) is True
        assert rect.contains_point(200.0, 200.0) is True
        assert rect.contains_point("invalid") is False

    def test_degenerate_rect_rejection(self) -> None:
        """Verify that inverted/degenerate bounding boxes raise ValueError."""
        with pytest.raises(ValueError):
            KdRect(x_min=400.0, y_min=50.0, x_max=100.0, y_max=350.0)
        with pytest.raises(ValueError):
            KdRect(x_min=100.0, y_min=400.0, x_max=300.0, y_max=50.0)

    def test_kd_point_properties(self) -> None:
        """Verify KdPoint initialization, tag formatting, and data payload."""
        pt = KdPoint(x=120.0, y=240.0, id=7, tag="INST-007", status="normal", data={"value": 42.5})
        assert pt.x == 120.0
        assert pt.y == 240.0
        assert pt.id == 7
        assert pt.tag == "INST-007"
        assert pt.status == "normal"
        assert pt.value == 42.5

        # Aliases
        assert KdNodePoint is KdPoint
        assert SpatialPoint is KdPoint

    def test_kd_node_tree_operations(self) -> None:
        """Verify KdNode subtree traversal, point collection, and depth calculation."""
        p_root = KdPoint(x=600.0, y=375.0, id=1)
        p_left = KdPoint(x=300.0, y=200.0, id=2)
        p_right = KdPoint(x=900.0, y=500.0, id=3)

        n_left = KdNode(point=p_left, axis=1, depth=1)
        n_right = KdNode(point=p_right, axis=1, depth=1)
        n_root = KdNode(point=p_root, axis=0, depth=0, left=n_left, right=n_right)

        assert n_root.is_leaf() is False
        assert n_left.is_leaf() is True
        assert n_right.is_leaf() is True
        assert n_root.count() == 3
        assert n_root.get_max_depth() == 1

        all_points = n_root.get_all_points()
        assert len(all_points) == 3
        assert {p.id for p in all_points} == {1, 2, 3}

    def test_kdtree_metrics_scaling(self) -> None:
        """Verify KdtreeMetrics properties and 16-bit integer fixed-point scaling."""
        m = KdtreeMetrics(
            total_nodes=10,
            subdivision_depth=4,
            query_target_id=999,
            nearest_node_id=3,
            nearest_distance=15.46,
            hazard_threshold=30.0,
            hazard_violations_count=2,
            diagnostic_code=DIAG_OK,
            indexing_online=True,
            proximity_hazard_alarm=False,
        )
        assert m.nearest_distance_scaled == 155  # 15.46 * 10 rounded
        assert m.hazard_threshold_scaled == 300  # 30.0 * 10
        assert KdMetrics is KdtreeMetrics

        # Edge case: no nearest neighbor
        m_empty = KdtreeMetrics(nearest_node_id=0, nearest_distance=float("inf"))
        assert m_empty.nearest_distance_scaled == 0


class TestKdtreeInsertionAndPartitioning:
    """Test suite for alternating orthogonal axis partitioning and insertion."""

    def test_alternating_axis_splitting(self) -> None:
        """Verify orthogonal axis split: x-split at depth 0, 2; y-split at depth 1, 3."""
        eng = KdtreeCanvasEngine(max_depth=12)

        # Level 0 (Root)
        assert eng.insert_point(600.0, 375.0, node_id=1) is True
        assert eng.root is not None
        assert eng.root.axis == 0
        assert eng.root.depth == 0

        # Level 1 (Left & Right children split on y)
        assert eng.insert_point(300.0, 200.0, node_id=2) is True  # x < 600 -> left
        assert eng.insert_point(900.0, 500.0, node_id=3) is True  # x >= 600 -> right
        assert eng.root.left is not None
        assert eng.root.left.axis == 1
        assert eng.root.left.depth == 1
        assert eng.root.right is not None
        assert eng.root.right.axis == 1
        assert eng.root.right.depth == 1

        # Level 2 (Grandchildren split on x)
        assert eng.insert_point(200.0, 100.0, node_id=4) is True  # y < 200 -> left.left
        assert eng.insert_point(400.0, 300.0, node_id=5) is True  # y >= 200 -> left.right
        assert eng.root.left.left is not None
        assert eng.root.left.left.axis == 0
        assert eng.root.left.left.depth == 2
        assert eng.root.left.right is not None
        assert eng.root.left.right.axis == 0
        assert eng.root.left.right.depth == 2

        # Level 3 (Great-grandchildren split on y)
        assert eng.insert_point(150.0, 50.0, node_id=6) is True  # x < 200 -> left.left.left
        assert eng.root.left.left.left is not None
        assert eng.root.left.left.left.axis == 1
        assert eng.root.left.left.left.depth == 3

    def test_subdivision_bounds_containment(self) -> None:
        """Verify that child node bounding boxes strictly partition the parent domain."""
        eng = KdtreeCanvasEngine()
        eng.insert_point(600.0, 375.0, node_id=1)
        eng.insert_point(300.0, 200.0, node_id=2)
        eng.insert_point(900.0, 500.0, node_id=3)
        eng.insert_point(200.0, 100.0, node_id=4)
        eng.insert_point(400.0, 300.0, node_id=5)

        root = eng.root
        assert root is not None
        assert root.bounds == KdRect(0.0, 0.0, 1200.0, 750.0)
        assert root.left.bounds == KdRect(0.0, 0.0, 600.0, 750.0)
        assert root.right.bounds == KdRect(600.0, 0.0, 1200.0, 750.0)
        assert root.left.left.bounds == KdRect(0.0, 0.0, 600.0, 200.0)
        assert root.left.right.bounds == KdRect(0.0, 200.0, 600.0, 750.0)

    def test_invalid_domain_rejection(self) -> None:
        """Verify coordinates outside bounding domain [0, 1200] x [0, 750] are rejected."""
        eng = KdtreeCanvasEngine()
        assert eng.insert_point(-10.0, 100.0) is False
        assert eng.diagnostic_code == DIAG_ERR_INVALID_DOMAIN

        assert eng.insert_point(1250.0, 100.0) is False
        assert eng.diagnostic_code == DIAG_ERR_INVALID_DOMAIN

        assert eng.insert_point(100.0, -5.0) is False
        assert eng.diagnostic_code == DIAG_ERR_INVALID_DOMAIN

        assert eng.insert_point(100.0, 800.0) is False
        assert eng.diagnostic_code == DIAG_ERR_INVALID_DOMAIN

    def test_degenerate_coords_rejection(self) -> None:
        """Verify NaN and Inf coordinate rejection asserting 0x8414."""
        eng = KdtreeCanvasEngine()
        assert eng.insert_point(float("nan"), 100.0) is False
        assert eng.diagnostic_code == DIAG_ERR_DEGENERATE_COORDINATES

        assert eng.insert_point(100.0, float("nan")) is False
        assert eng.diagnostic_code == DIAG_ERR_DEGENERATE_COORDINATES

        assert eng.insert_point(float("inf"), 100.0) is False
        assert eng.diagnostic_code == DIAG_ERR_DEGENERATE_COORDINATES

        assert eng.insert_point(100.0, float("-inf")) is False
        assert eng.diagnostic_code == DIAG_ERR_DEGENERATE_COORDINATES

    def test_batch_insertion(self) -> None:
        """Verify batch coordinate insertion function."""
        eng = KdtreeCanvasEngine()
        coords = [(100.0, 100.0), (200.0, 200.0), (300.0, 300.0), (-50.0, 50.0)]
        count = eng.insert_points(coords)
        assert count == 3
        assert eng.total_nodes == 3

    def test_rebalance_median_split(self) -> None:
        """Verify tree rebalancing produces optimal depth distribution."""
        eng = KdtreeCanvasEngine()
        # Insert linear degenerately skewed points
        for i in range(1, 16):
            eng.insert_point(50.0 + i * 20.0, 50.0 + i * 20.0, node_id=i)

        skewed_depth = eng.current_depth
        assert skewed_depth >= 10

        eng.rebalance()
        assert eng.root is not None
        assert eng.root.count() == 15
        # Balanced tree of 15 nodes has max depth <= 4
        assert eng.current_depth <= 4


class TestNearestNeighborSearch:
    """Test suite for 1-NN and k-NN branch-and-bound search precision."""

    def test_empty_tree_search(self) -> None:
        """Verify search on empty tree asserts 0x8412."""
        eng = KdtreeCanvasEngine()
        nn_node, nn_dist = eng.find_nearest(500.0, 300.0)
        assert nn_node is None
        assert math.isinf(nn_dist)
        assert eng.diagnostic_code == DIAG_ERR_EMPTY_TREE

        knn = eng.find_k_nearest(500.0, 300.0, k=3)
        assert knn == []
        assert eng.diagnostic_code == DIAG_ERR_EMPTY_TREE

    def test_degenerate_query_search(self) -> None:
        """Verify search with NaN/Inf query point asserts 0x8414."""
        eng = KdtreeCanvasEngine()
        eng.insert_point(100.0, 100.0, node_id=1)

        nn_node, nn_dist = eng.find_nearest(float("nan"), 100.0)
        assert nn_node is None
        assert math.isinf(nn_dist)
        assert eng.diagnostic_code == DIAG_ERR_DEGENERATE_COORDINATES

        knn = eng.find_k_nearest(100.0, float("inf"), k=3)
        assert knn == []
        assert eng.diagnostic_code == DIAG_ERR_DEGENERATE_COORDINATES

    def test_invalid_k_parameter(self) -> None:
        """Verify k-NN search with k <= 0 asserts 0x8413."""
        eng = KdtreeCanvasEngine()
        eng.insert_point(100.0, 100.0, node_id=1)

        res_zero = eng.find_k_nearest(100.0, 100.0, k=0)
        assert res_zero == []
        assert eng.diagnostic_code == DIAG_ERR_INVALID_K_NEIGHBORS

        res_neg = eng.find_k_nearest(100.0, 100.0, k=-2)
        assert res_neg == []
        assert eng.diagnostic_code == DIAG_ERR_INVALID_K_NEIGHBORS

    def test_1_nn_branch_and_bound_precision(self) -> None:
        """Verify 1-NN branch-and-bound search matches analytical ground truth."""
        eng = KdtreeCanvasEngine(hazard_threshold=20.0)
        # Cluster of distinct instruments
        points = [
            (600.0, 375.0, 1),
            (300.0, 200.0, 2),
            (900.0, 500.0, 3),
            (200.0, 100.0, 4),
            (400.0, 300.0, 5),
        ]
        for x, y, nid in points:
            eng.insert_point(x, y, node_id=nid)

        # Query at (450.0, 350.0)
        # Distances:
        # Pt 1 (600, 375): hypot(150, 25) = 152.069
        # Pt 2 (300, 200): hypot(150, 150) = 212.132
        # Pt 3 (900, 500): hypot(450, 150) = 474.341
        # Pt 4 (200, 100): hypot(250, 250) = 353.553
        # Pt 5 (400, 300): hypot(50, 50) = 70.7106 -> Nearest
        qx, qy = 450.0, 350.0
        nn_node, nn_dist = eng.find_nearest(qx, qy)
        expected_dist = math.hypot(50.0, 50.0)

        assert nn_node is not None
        assert nn_node.id == 5
        assert abs(nn_dist - expected_dist) < 1e-6
        assert eng.nearest_node_id == 5
        assert eng.query_target_x == 450.0
        assert eng.query_target_y == 350.0

    def test_k_nn_search_monotonicity_and_ground_truth(self) -> None:
        """Verify k-NN search returns items strictly ordered by distance and matches brute force."""
        eng = KdtreeCanvasEngine(hazard_threshold=20.0)
        points = [
            (600.0, 375.0, 1),
            (300.0, 200.0, 2),
            (900.0, 500.0, 3),
            (200.0, 100.0, 4),
            (400.0, 300.0, 5),
        ]
        for x, y, nid in points:
            eng.insert_point(x, y, node_id=nid)

        qx, qy = 450.0, 350.0
        knn = eng.find_k_nearest(qx, qy, k=3)

        assert len(knn) == 3
        # Check strict monotonic distance ordering
        assert knn[0][1] <= knn[1][1] <= knn[2][1]
        assert [p.id for p, _ in knn] == [5, 1, 2]

        # Brute force validation for all points
        all_knn = eng.find_k_nearest(qx, qy, k=10)
        assert len(all_knn) == 5
        brute_force = sorted(
            [(p, math.hypot(p.x - qx, p.y - qy)) for p in eng.points],
            key=lambda t: t[1],
        )
        for i in range(5):
            assert all_knn[i][0].id == brute_force[i][0].id
            assert abs(all_knn[i][1] - brute_force[i][1]) < 1e-6


class TestProximityHazardAndAlarms:
    """Test suite for spatial proximity hazard detection and %M596 assertion."""

    def test_hazard_detection_on_point_insertion(self) -> None:
        """Verify insertion of point within hazard distance trips %M596 and 0x8415."""
        eng = KdtreeCanvasEngine(hazard_threshold=30.0)
        eng.insert_point(200.0, 200.0, node_id=1)
        assert eng.alarm_active is False
        assert eng.diagnostic_code == DIAG_OK
        assert eng.hazard_violations_count == 0

        # Insert second point at distance 10.0 px ( < 30.0 px)
        eng.insert_point(200.0, 210.0, node_id=2)
        assert eng.alarm_active is True
        assert eng.diagnostic_code == DIAG_ERR_PROXIMITY_HAZARD_ALARM
        assert eng.hazard_violations_count == 1
        assert eng.points[0].status == "alarm"
        assert eng.points[1].status == "alarm"

    def test_hazard_detection_on_query(self) -> None:
        """Verify query point within hazard threshold trips alarm."""
        eng = KdtreeCanvasEngine(hazard_threshold=30.0)
        eng.insert_point(400.0, 300.0, node_id=1)

        # Query at (405.0, 305.0) -> dist = ~7.07 px < 30.0 px
        node, dist = eng.find_nearest(405.0, 305.0)
        assert node is not None
        assert dist < 30.0
        assert eng.alarm_active is True
        assert eng.diagnostic_code == DIAG_ERR_PROXIMITY_HAZARD_ALARM

    def test_alarm_injection_and_clearing(self) -> None:
        """Verify manual alarm assertion and clear anomaly workflow."""
        eng = KdtreeCanvasEngine()
        eng.inject_proximity_hazard_alarm()
        assert eng.alarm_active is True
        assert eng.diagnostic_code == DIAG_ERR_PROXIMITY_HAZARD_ALARM

        # Verify registers reflect alarm
        rt = RegisterTable()
        eng.sync_to_registers(rt)
        assert rt.read_bit(COIL_KDTREE_PROXIMITY_HAZARD_ALARM) is True
        assert (rt.read_word(REG_KDTREE_DIAGNOSTIC_CODE) & 0xFFFF) == 0x8415

        # Clear alarm
        eng.clear_anomalies()
        assert eng.alarm_active is False
        assert eng.diagnostic_code == DIAG_OK
        eng.sync_to_registers(rt)
        assert rt.read_bit(COIL_KDTREE_PROXIMITY_HAZARD_ALARM) is False
        assert (rt.read_word(REG_KDTREE_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000


class TestSvgGenerationAndWcagContrast:
    """Test suite for SVG 1.1 vector graphics and WCAG 2.1 AAA contrast."""

    def test_wcag_aaa_contrast_ratio(self) -> None:
        """Verify text-to-badge contrast exceeds WCAG 2.1 AAA threshold (> 18:1)."""
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert ratio >= 18.0
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, 18.0) is True

    def test_svg_xml_validity_and_elements(self) -> None:
        """Verify SVG 1.1 output is valid XML and contains required visual elements."""
        eng = create_canonical_kdtree_canvas(sample_count=20, seed=42)
        eng.find_k_nearest(600.0, 375.0, k=3)
        svg_text = generate_kdtree_canvas_svg(eng)

        root = ET.fromstring(svg_text)
        assert root.tag.endswith("svg")
        assert root.attrib["viewBox"] == "0 0 1200 750"
        assert root.attrib["width"] == "1200"
        assert root.attrib["height"] == "750"

        assert "kd-partition-line" in svg_text
        assert "sensor-node" in svg_text
        assert "query-target-crosshair" in svg_text
        assert "nearest-vector" in svg_text
        assert "hud-telemetry-scorecard" in svg_text
        assert "DYNAMIC SPATIAL K-D TREE SCADA CANVAS" in svg_text


class TestHornerOcsRegisterSync:
    """Test suite for Horner OCS memory synchronization."""

    def test_bit_exact_register_sync(self) -> None:
        """Verify registers %R2550..%R2557 and coils %M595..%M596."""
        eng = KdtreeCanvasEngine(max_depth=12, hazard_threshold=30.0)
        eng.insert_point(200.0, 150.0, node_id=101)
        eng.insert_point(400.0, 250.0, node_id=102)
        eng.find_nearest(210.0, 150.0)

        rt = RegisterTable()
        eng.sync_to_registers(rt)

        assert rt.read_word(REG_KDTREE_TOTAL_NODES) == 2
        assert rt.read_word(REG_KDTREE_SUBDIVISION_DEPTH) == eng.current_depth
        assert rt.read_word(REG_KDTREE_QUERY_TARGET_ID) == eng.query_target_id
        assert rt.read_word(REG_KDTREE_NEAREST_NODE_ID) == 101
        assert rt.read_word(REG_KDTREE_NEAREST_DISTANCE_SCALED) == 100  # 10.0 * 10
        assert rt.read_word(REG_KDTREE_HAZARD_THRESHOLD_SCALED) == 300  # 30.0 * 10
        assert rt.read_bit(COIL_KDTREE_INDEXING_ONLINE) is True

    def test_privilege_modes_access(self) -> None:
        """Verify sync_to_registers functions under both USER and SYSTEM privilege modes."""
        eng = KdtreeCanvasEngine()
        eng.insert_point(200.0, 150.0, node_id=101)

        rt = RegisterTable()
        eng.sync_to_registers(rt, privilege=PrivilegeMode.USER)
        assert rt.read_word(REG_KDTREE_TOTAL_NODES) == 1

        eng.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_word(REG_KDTREE_TOTAL_NODES) == 1


class TestPureSTAndSecurityRejection:
    """Test suite for pure Structured Text and anti-ladder security guards."""

    def test_pure_st_pou_syntax_validation(self) -> None:
        """Verify ST_PROGRAM_KDTREE_CANVAS_SYNC compiles under pure ST parser."""
        assert verify_kdtree_canvas_pure_st() is True
        res = STParser.validate_code(ST_PROGRAM_KDTREE_CANVAS_SYNC)
        assert res.status == AgentStatus.SUCCESS
        ast = STParser.parse_pou(ST_PROGRAM_KDTREE_CANVAS_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "KdtreeCanvasSync"

    def test_ladder_contacts_rejection(self) -> None:
        """Verify strict rejection of ladder logic contacts ---[ ]---."""
        bad_st = "PROGRAM P VAR b : BOOL; END_VAR ---[ ]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_coils_rejection(self) -> None:
        """Verify strict rejection of ladder logic coils ---( )---."""
        bad_st = "PROGRAM P VAR b : BOOL; END_VAR ---( )--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_rung_delimiters_rejection(self) -> None:
        """Verify strict rejection of ladder rung delimiters RUNG."""
        bad_st = "PROGRAM P VAR b : BOOL; END_VAR RUNG 1: A := B; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_mnemonics_rejection(self) -> None:
        """Verify strict rejection of ladder mnemonics XIC and OTE."""
        bad_st = "PROGRAM P VAR b : BOOL; END_VAR XIC b; OTE c; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)


class TestILogicUnitCompliance:
    """Test suite for ILogicUnit scan cycle execution."""

    def test_ilogic_unit_properties_and_step(self) -> None:
        """Verify ILogicUnit interface compliance."""
        eng = KdtreeCanvasEngine()
        assert isinstance(eng, ILogicUnit)
        assert eng.name == "KdtreeCanvasEngine"
        assert eng.priority == 100
        assert eng.is_enabled is True

        res = eng.scan_step()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert eng.cycle_count == 1

        eng.step()
        assert eng.cycle_count == 2

        eng.execute()
        assert eng.cycle_count == 3

    def test_reset(self) -> None:
        """Verify reset clears points and restores default tree."""
        eng = KdtreeCanvasEngine()
        eng.insert_point(100.0, 100.0, node_id=1)
        eng.scan_step()
        assert len(eng.points) == 1
        assert eng.cycle_count == 1

        eng.reset()
        assert len(eng.points) == 0
        assert eng.cycle_count == 0
        assert eng.root is None
        assert eng.current_depth == 0

    def test_simulation_scan_cycle_soak(self) -> None:
        """Verify scan cycle soak stability over 50 consecutive cycles."""
        eng = KdtreeCanvasEngine()
        eng.insert_point(150.0, 150.0, node_id=1)
        rt = RegisterTable()
        for c in range(1, 51):
            ctx = ScanContext(cycle=c, dt_ms=10.0, register_table=rt)
            eng.execute(ctx)
            assert eng.cycle_count == c
            assert rt.read_bit(COIL_KDTREE_INDEXING_ONLINE) is True


class TestDeterministicVerificationRunner:
    """Test suite for run_kdtree_canvas_verification."""

    def test_9_stage_verification_runner_success(self, tmp_path: Path) -> None:
        """Verify that all 9 stages pass deterministically and export evidence."""
        out_json = str(tmp_path / "w294_kdtree_evidence.json")
        out_svg = str(tmp_path / "w294_kdtree_sample.svg")

        res = run_kdtree_canvas_verification(
            output_path=out_json,
            sample_svg_path=out_svg,
            work_package="W294",
        )

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["stages"]) == 9

        # Verify output files exist and are valid
        assert Path(out_json).exists()
        assert Path(out_svg).exists()

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"

        with open(out_svg, "r", encoding="utf-8") as f:
            svg_content = f.read()
        root = ET.fromstring(svg_content)
        assert root.tag.endswith("svg")
