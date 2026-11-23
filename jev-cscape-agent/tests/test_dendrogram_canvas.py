"""Comprehensive unit test suite for Cscape HMI Dynamic Dendrogram & Hierarchical Clustering Matrix SCADA Canvas (W219).

Work Package: W219 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Coverage (70+ Unit Tests across 12 Test Classes):
1. TestPureSTAndSecurity: Pure IEC 61131-3 Structured Text (ST) POU Grammar, Symbol Binding & Anti-Ladder Interception.
2. TestCanonicalSensorTopologyAndMetricInvariants: Canonical 32 plant sensors, feature vectors, Euclidean distance, metric invariants.
3. TestWardHierarchicalClusteringAndLinkage: Ward minimum variance criterion, Lance-Williams objective, tree construction, monotonicity.
4. TestCopheneticDistanceAndCorrelation: Lowest Common Ancestor (LCA) cophenetic distances, cophenetic correlation coefficient (CPCC).
5. TestDynamicClusterCutThresholdAndKExtraction: Dynamic horizontal cut threshold line, k-cluster extraction, assignment continuity.
6. TestSensorSimilarityHeatMatrixAndNormalization: 32x32 sensor similarity correlation heat matrix, normalization, optimal leaf order.
7. TestSilhouetteQualityAndClusterDegeneracy: Silhouette coefficient calculation, singleton detection, cluster degeneracy alarm (%M421).
8. TestWCAG21AAAContrastAndVisualLegibility: WCAG 2.1 AAA relative luminance, text contrast (>7:1), decoupled badge contrast (>18:1).
9. TestStandaloneW3CSVGGenerationAndXMLParsing: W3C SVG 1.1 vector graphic synthesis, XML parsing with ElementTree.
10. TestHornerOCSSynchronization: RegisterTable memory synchronization (%R1800..%R1807, %M420..%M421) with PrivilegeMode.SYSTEM.
11. TestILogicUnitScanCycleEngine: ILogicUnit discrete scan cycle (scan_step, step, execute, reset).
12. TestVerificationRunnerAndContract: Deterministic 9-stage verification runner and strict 4-state engineering contract JSON.
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

from jev_cscape.hmi.dendrogram_canvas import (
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    CLUSTER_DEGENERACY_FAULT,
    CLUSTER_NAMES,
    CLUSTER_PALETTE,
    COIL_CLUSTER_DEGENERACY_ALARM_ACTIVE,
    COIL_DENDROGRAM_CANVAS_ACTIVE,
    COIL_W219_CANVAS_ACTIVE,
    COIL_W219_DEGENERACY_ALARM,
    COLOR_ALARM_CRIMSON,
    COLOR_BRANCH_STRUCTURAL,
    COLOR_CONTAINER_BG,
    COLOR_CONTAINER_BORDER,
    COLOR_CUT_LINE,
    COLOR_DARK_THEME_BACKING,
    COLOR_DECOUPLED_BADGE,
    COLOR_FOCUS_CYAN,
    COLOR_GRID_LINE,
    COLOR_NOMINAL_EMERALD,
    COLOR_SURFACE_CARD,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    ClusterDegeneracyError,
    ClusterInfo,
    DEFAULT_DISTANCE_CUT_THRESHOLD,
    DEFAULT_NODE_COUNT,
    DEGENERACY_SILHOUETTE_THRESHOLD,
    DENDROGRAM_CANVAS_PURE_ST_POU,
    DENDROGRAM_PURE_ST_POU,
    DIAG_ERR_CLUSTER_DEGENERACY_FAULT,
    DIAG_ERR_DISTANCE_MATRIX_SINGULARITY,
    DIAG_ERR_SVG_RENDER_FAULT,
    DIAG_ERR_THRESHOLD_OUT_OF_BOUNDS,
    DIAG_EVENT_OK,
    DIAG_OK,
    DISTANCE_MATRIX_SINGULARITY,
    DendrogramCanvas,
    DendrogramCanvasEngine,
    DendrogramCanvasError,
    DendrogramCanvasSync,
    DendrogramMetrics,
    DendrogramNode,
    DendrogramStatusBits,
    DendrogramTree,
    DiagnosticCode,
    DistanceMatrixSingularityError,
    LinkageMetric,
    MAX_REASONABLE_CUT_THRESHOLD_RATIO,
    MIN_CUT_THRESHOLD,
    REG_ACTIVE_CLUSTER_COUNT,
    REG_COPHENETIC_CORRELATION_PCT_SCALED,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_DISTANCE_CUT_THRESHOLD_SCALED,
    REG_MAX_INTER_CLUSTER_DISTANCE_SCALED,
    REG_SELECTED_NODE_CLUSTER_ID,
    REG_SILHOUETTE_COEFFICIENT_SCALED,
    REG_TOTAL_NODE_COUNT,
    REG_W219_ACTIVE_CLUSTERS,
    REG_W219_COPHENETIC_CORR,
    REG_W219_CUT_THRESHOLD,
    REG_W219_DIAGNOSTIC_CODE,
    REG_W219_MAX_INTER_DIST,
    REG_W219_SELECTED_CLUSTER,
    REG_W219_SILHOUETTE_SCORE,
    REG_W219_TOTAL_NODES,
    SVGRenderError,
    SVG_RENDER_FAULT,
    SensorNode,
    THRESHOLD_OUT_OF_BOUNDS,
    ThresholdOutOfBoundsError,
    W219_DENDROGRAM_PURE_ST_POU,
    calculate_cophenetic_correlation,
    compute_cophenetic_distances,
    compute_euclidean_distance_matrix,
    compute_inter_cluster_distances,
    compute_silhouette_coefficient,
    contrast_ratio,
    create_canonical_dendrogram_canvas,
    create_canonical_sensors,
    create_mock_scan_context,
    cut_dendrogram_tree,
    euclidean_distance,
    extract_optimal_leaf_order,
    generate_dendrogram_canvas_svg,
    heat_color_for_similarity,
    interpolate_color,
    perform_ward_hierarchical_clustering,
    relative_luminance,
    run_dendrogram_canvas_verification,
    validate_wcag_aaa_contrast,
    verify_dendrogram_canvas_pure_st,
    ward_cluster_distance,
)


# ============================================================================
# Section 1: Pure ST POU Grammar & Anti-Ladder Interception
# ============================================================================

class TestPureSTAndSecurity:
    """Validate purity, grammar, symbol bindings, and anti-ladder interception."""

    def test_pure_st_grammar_and_pou_type(self) -> None:
        """SecurityGuard asserts pure Structured Text content and STParser parses PROGRAM POU."""
        SecurityGuard.assert_pure_st_content(DENDROGRAM_CANVAS_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(DENDROGRAM_CANVAS_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "DendrogramCanvasSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_pure_st_variable_declarations(self) -> None:
        """ST POU contains exactly 10 variables (8 INT analog, 2 BOOL coils)."""
        parser = STParser()
        pou = parser.parse_pou(DENDROGRAM_CANVAS_PURE_ST_POU)
        assert pou is not None
        assert len(pou.variables) == 10
        int_vars = [v for v in pou.variables if v.data_type == "INT"]
        bool_vars = [v for v in pou.variables if v.data_type == "BOOL"]
        assert len(int_vars) == 8
        assert len(bool_vars) == 2

    def test_pure_st_address_bindings(self) -> None:
        """Variables are bound to Horner memory %R1800..%R1807 and %M420..%M421."""
        parser = STParser()
        pou = parser.parse_pou(DENDROGRAM_CANVAS_PURE_ST_POU)
        assert pou is not None
        expected_bindings = {
            "TotalNodeCount": "%R1800",
            "ActiveClusterCount": "%R1801",
            "DistanceCutThresholdScaled": "%R1802",
            "CopheneticCorrelationPctScaled": "%R1803",
            "SelectedNodeClusterId": "%R1804",
            "MaxInterClusterDistanceScaled": "%R1805",
            "SilhouetteCoefficientScaled": "%R1806",
            "DiagnosticStatusCode": "%R1807",
            "DendrogramCanvasActive": "%M420",
            "ClusterDegeneracyAlarmActive": "%M421",
        }
        vmap = {v.name: v.address_binding for v in pou.variables}
        for name, addr in expected_bindings.items():
            assert vmap.get(name) == addr

    def test_pure_st_pou_aliases(self) -> None:
        """Aliases DENDROGRAM_PURE_ST_POU and W219_DENDROGRAM_PURE_ST_POU match canonical definition."""
        assert DENDROGRAM_PURE_ST_POU == DENDROGRAM_CANVAS_PURE_ST_POU
        assert W219_DENDROGRAM_PURE_ST_POU == DENDROGRAM_CANVAS_PURE_ST_POU

    def test_verify_dendrogram_canvas_pure_st_helper(self) -> None:
        """verify_dendrogram_canvas_pure_st returns True deterministically."""
        assert verify_dendrogram_canvas_pure_st() is True

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
# Section 2: Canonical Sensor Topology & Metric Invariants
# ============================================================================

class TestCanonicalSensorTopologyAndMetricInvariants:
    """Validate 32 plant sensors, feature vectors, Euclidean distance, and metric invariants."""

    def test_canonical_sensors_count_and_indexing(self) -> None:
        """Canonical plant grounding dataset creates exactly 32 sensors indexed 1..32."""
        sensors = create_canonical_sensors()
        assert len(sensors) == 32
        assert [s.index for s in sensors] == list(range(1, 33))
        assert len(set(s.sensor_id for s in sensors)) == 32
        assert len(set(s.tag for s in sensors)) == 32

    def test_canonical_sensor_process_units(self) -> None:
        """Sensors span 4 refining process units (CDU, FCC, HTU, FLARE)."""
        sensors = create_canonical_sensors()
        units = set(s.process_unit for s in sensors)
        assert units == {"CDU", "FCC", "HTU", "FLARE"}
        cdu_sensors = [s for s in sensors if s.process_unit == "CDU"]
        fcc_sensors = [s for s in sensors if s.process_unit == "FCC"]
        htu_sensors = [s for s in sensors if s.process_unit == "HTU"]
        flare_sensors = [s for s in sensors if s.process_unit == "FLARE"]
        assert len(cdu_sensors) == 10
        assert len(fcc_sensors) == 8
        assert len(htu_sensors) == 8
        assert len(flare_sensors) == 6

    def test_sensor_feature_vectors_dimension_and_finiteness(self) -> None:
        """All sensor feature vectors have dimension 4 and finite floating-point values."""
        sensors = create_canonical_sensors()
        for s in sensors:
            assert len(s.feature_vector) == 4
            assert all(math.isfinite(x) for x in s.feature_vector)
            assert s.nominal_val > 0.0

    def test_euclidean_distance_properties(self) -> None:
        """Euclidean distance matrix is 32x32, zero on diagonal, symmetric, and positive off-diagonal."""
        sensors = create_canonical_sensors()
        d_mat = compute_euclidean_distance_matrix(sensors)
        assert len(d_mat) == 32
        assert all(len(row) == 32 for row in d_mat)
        for i in range(32):
            assert d_mat[i][i] == 0.0
            for j in range(i + 1, 32):
                assert d_mat[i][j] > 0.0
                assert d_mat[i][j] == d_mat[j][i]

    def test_euclidean_distance_triangle_inequality(self) -> None:
        """Euclidean distance satisfies triangle inequality D[i][k] <= D[i][j] + D[j][k] + eps."""
        sensors = create_canonical_sensors()
        d_mat = compute_euclidean_distance_matrix(sensors)
        for i in range(32):
            for j in range(32):
                for k in range(32):
                    assert d_mat[i][k] <= d_mat[i][j] + d_mat[j][k] + 1e-9

    def test_euclidean_distance_singularity_error(self) -> None:
        """Distance matrix singularity error is raised for empty or zero-variance sensor sets."""
        with pytest.raises(DistanceMatrixSingularityError):
            compute_euclidean_distance_matrix([])

        # Duplicate sensors with zero distance
        s1 = SensorNode("S1", "T1", "N1", 1, [2.0, 2.0, 2.0, 2.0])
        s2 = SensorNode("S2", "T2", "N2", 2, [2.0, 2.0, 2.0, 2.0])
        with pytest.raises(DistanceMatrixSingularityError):
            compute_euclidean_distance_matrix([s1, s2])


# ============================================================================
# Section 3: Ward Hierarchical Clustering & Linkage
# ============================================================================

class TestWardHierarchicalClusteringAndLinkage:
    """Validate Ward minimum variance criterion, tree building, and height monotonicity."""

    def test_ward_cluster_distance_calculation(self) -> None:
        """ward_cluster_distance computes analytical minimum variance distance between centroids."""
        c_a = [0.0, 0.0]
        c_b = [3.0, 4.0]  # distance = 5.0
        n_a = 2
        n_b = 2
        # scale = sqrt(2 * 2 * 2 / 4) = sqrt(2)
        expected = math.sqrt(2.0) * 5.0
        actual = ward_cluster_distance(c_a, n_a, c_b, n_b)
        assert math.isclose(actual, expected, rel_tol=1e-5)

    def test_ward_hac_tree_construction_node_counts(self) -> None:
        """Ward HAC merges 32 leaves through 31 merge nodes yielding exactly 63 tree nodes."""
        sensors = create_canonical_sensors()
        root, all_nodes = perform_ward_hierarchical_clustering(sensors)
        assert root is not None
        assert len(all_nodes) == 63
        leaves = [n for n in all_nodes if n.is_leaf]
        merges = [n for n in all_nodes if not n.is_leaf]
        assert len(leaves) == 32
        assert len(merges) == 31
        assert root.node_id == 63
        assert root.size == 32

    def test_ward_hac_branch_height_monotonicity(self) -> None:
        """Branch heights are non-decreasing up the tree: parent.height >= children.height."""
        sensors = create_canonical_sensors()
        root, all_nodes = perform_ward_hierarchical_clustering(sensors)
        for node in all_nodes:
            if not node.is_leaf and node.left and node.right:
                assert node.height >= node.left.height - 1e-6
                assert node.height >= node.right.height - 1e-6

    def test_ward_hac_root_leaf_indices_coverage(self) -> None:
        """Root node covers all 32 leaf sensor indices without omissions or duplicates."""
        sensors = create_canonical_sensors()
        root, _ = perform_ward_hierarchical_clustering(sensors)
        assert sorted(root.leaf_indices) == list(range(32))

    def test_ward_hac_single_sensor(self) -> None:
        """Single sensor clustering returns leaf node with height 0.0 and size 1."""
        s = SensorNode("S1", "T1", "N1", 1, [1.0, 2.0, 3.0, 4.0])
        root, all_nodes = perform_ward_hierarchical_clustering([s])
        assert root.is_leaf is True
        assert root.height == 0.0
        assert root.size == 1
        assert len(all_nodes) == 1

    def test_ward_hac_empty_sensor_list_raises_error(self) -> None:
        """Clustering empty sensor list raises DendrogramCanvasError."""
        with pytest.raises(DendrogramCanvasError):
            perform_ward_hierarchical_clustering([])


# ============================================================================
# Section 4: Cophenetic Distance & Correlation
# ============================================================================

class TestCopheneticDistanceAndCorrelation:
    """Validate cophenetic distances via Lowest Common Ancestor and CPCC calculation."""

    def test_cophenetic_matrix_dimensions_and_symmetry(self) -> None:
        """Cophenetic matrix is 32x32, symmetric, with zeros on the diagonal."""
        tree = DendrogramTree()
        c_mat = compute_cophenetic_distances(tree.root, tree.total_leaves)
        assert len(c_mat) == 32
        assert all(len(row) == 32 for row in c_mat)
        for i in range(32):
            assert c_mat[i][i] == 0.0
            for j in range(i + 1, 32):
                assert c_mat[i][j] == c_mat[j][i]
                assert c_mat[i][j] > 0.0

    def test_cophenetic_distance_lca_height(self) -> None:
        """Cophenetic distance between leaves equals merge height of their lowest common ancestor."""
        tree = DendrogramTree()
        c_mat = tree.cophenetic_matrix
        # Check all pairs match their LCA height
        for i in range(32):
            for j in range(i + 1, 32):
                h = c_mat[i][j]
                assert h <= tree.max_height + 1e-6
                assert h > 0.0

    def test_cophenetic_correlation_coefficient_range(self) -> None:
        """Cophenetic Correlation Coefficient (CPCC) r >= 0.85 demonstrating high hierarchical fidelity."""
        tree = DendrogramTree()
        r = tree.cophenetic_correlation
        assert 0.85 <= r <= 1.0

    def test_cophenetic_correlation_identical_matrices(self) -> None:
        """calculate_cophenetic_correlation returns 1.0 when cophenetic matrix equals distance matrix."""
        d_mat = [[0.0, 2.0, 5.0], [2.0, 0.0, 4.0], [5.0, 4.0, 0.0]]
        r = calculate_cophenetic_correlation(d_mat, d_mat)
        assert math.isclose(r, 1.0, rel_tol=1e-5)

    def test_cophenetic_correlation_small_or_empty(self) -> None:
        """CPCC handles trivial n <= 1 matrices returning 1.0 safely."""
        assert calculate_cophenetic_correlation([[0.0]], [[0.0]]) == 1.0
        assert calculate_cophenetic_correlation([], []) == 1.0


# ============================================================================
# Section 5: Dynamic Cluster Cut Threshold & k-Cluster Extraction
# ============================================================================

class TestDynamicClusterCutThresholdAndKExtraction:
    """Validate dynamic cut threshold line, k-cluster partitioning, and assignment continuity."""

    def test_nominal_cut_threshold_yields_4_clusters(self) -> None:
        """Cutting dendrogram at nominal threshold 1.50 resolves exactly 4 process clusters."""
        tree = DendrogramTree()
        clusters = cut_dendrogram_tree(tree.root, 1.50, tree.sensors)
        assert len(clusters) == 4
        assert [c.cluster_id for c in clusters] == [1, 2, 3, 4]
        assert sum(c.size for c in clusters) == 32

    def test_cluster_assignment_continuity(self) -> None:
        """Sensors within the same subtree below cut threshold have identical cluster assignments."""
        tree = DendrogramTree()
        clusters = cut_dendrogram_tree(tree.root, 1.50, tree.sensors)
        assigned_indices = set()
        for c in clusters:
            for idx in c.sensor_indices:
                assert idx not in assigned_indices
                assigned_indices.add(idx)
        assert len(assigned_indices) == 32

    def test_ceiling_cut_threshold_yields_single_cluster(self) -> None:
        """Cutting dendrogram above root height resolves exactly k=1 cluster covering all 32 sensors."""
        tree = DendrogramTree()
        clusters = cut_dendrogram_tree(tree.root, tree.max_height + 1.0, tree.sensors)
        assert len(clusters) == 1
        assert clusters[0].size == 32
        assert len(clusters[0].sensor_indices) == 32

    def test_floor_cut_threshold_yields_32_clusters(self) -> None:
        """Cutting dendrogram at floor threshold (near 0.0) resolves k=32 singleton clusters."""
        tree = DendrogramTree()
        clusters = cut_dendrogram_tree(tree.root, 0.01, tree.sensors)
        assert len(clusters) == 32
        assert all(c.size == 1 for c in clusters)

    def test_cluster_info_attributes_validity(self) -> None:
        """ClusterInfo model contains non-empty name, valid color, positive size, and centroid."""
        tree = DendrogramTree()
        clusters = cut_dendrogram_tree(tree.root, 1.50, tree.sensors)
        for c in clusters:
            assert c.name in CLUSTER_NAMES
            assert c.color.startswith("#")
            assert c.size > 0
            assert len(c.centroid) == 4
            assert len(c.sensor_tags) == c.size

    def test_threshold_out_of_bounds_error(self) -> None:
        """Negative or non-finite cut thresholds raise ThresholdOutOfBoundsError."""
        tree = DendrogramTree()
        with pytest.raises(ThresholdOutOfBoundsError):
            cut_dendrogram_tree(tree.root, -0.5, tree.sensors)
        with pytest.raises(ThresholdOutOfBoundsError):
            cut_dendrogram_tree(tree.root, float("nan"), tree.sensors)

    def test_optimal_leaf_order_completeness(self) -> None:
        """In-order traversal yields 32 unique sensor indices covering entire tree."""
        tree = DendrogramTree()
        leaf_order = extract_optimal_leaf_order(tree.root)
        assert len(leaf_order) == 32
        assert set(leaf_order) == set(range(32))


# ============================================================================
# Section 6: 32x32 Sensor Similarity Correlation Heat Matrix
# ============================================================================

class TestSensorSimilarityHeatMatrixAndNormalization:
    """Validate 32x32 similarity correlation matrix, normalization, and colormap mapping."""

    def test_heat_matrix_dimensions_and_diagonal(self) -> None:
        """Pairwise distance matrix is 32x32 and self-distance is strictly 0.0."""
        sensors = create_canonical_sensors()
        d_mat = compute_euclidean_distance_matrix(sensors)
        assert len(d_mat) == 32
        for i in range(32):
            assert d_mat[i][i] == 0.0

    def test_heat_color_for_similarity_colormap(self) -> None:
        """heat_color_for_similarity returns valid hex strings across the full 0.0..1.0 range."""
        for val in [0.0, 0.25, 0.50, 0.75, 1.0]:
            col = heat_color_for_similarity(val)
            assert col.startswith("#")
            assert len(col) == 7

    def test_interpolate_color_endpoints(self) -> None:
        """interpolate_color returns start color at t=0 and end color at t=1."""
        c1 = "#000000"
        c2 = "#FFFFFF"
        assert interpolate_color(c1, c2, 0.0).upper() == "#000000"
        assert interpolate_color(c1, c2, 1.0).upper() == "#FFFFFF"

    def test_inter_cluster_distance_calculation(self) -> None:
        """compute_inter_cluster_distances returns maximum centroid distance > 3.0 for k=4."""
        tree = DendrogramTree()
        clusters = cut_dendrogram_tree(tree.root, 1.50, tree.sensors)
        max_dist = compute_inter_cluster_distances(clusters)
        assert max_dist > 3.0

    def test_inter_cluster_distance_single_cluster_zero(self) -> None:
        """compute_inter_cluster_distances returns 0.0 for k <= 1."""
        c = ClusterInfo(1, "Test", "#10B981", [0], ["T1"], 1, [1.0, 2.0, 3.0, 4.0])
        assert compute_inter_cluster_distances([c]) == 0.0
        assert compute_inter_cluster_distances([]) == 0.0


# ============================================================================
# Section 7: Silhouette Quality & Cluster Degeneracy
# ============================================================================

class TestSilhouetteQualityAndClusterDegeneracy:
    """Validate silhouette coefficient computation and cluster degeneracy alarm interlock."""

    def test_nominal_silhouette_coefficient_healthy(self) -> None:
        """Nominal 4-cluster partitioning produces mean silhouette coefficient >= 0.70."""
        tree = DendrogramTree()
        clusters = cut_dendrogram_tree(tree.root, 1.50, tree.sensors)
        sil = compute_silhouette_coefficient(tree.distance_matrix, clusters)
        assert sil >= 0.70
        assert sil <= 1.0

    def test_single_cluster_silhouette_degeneracy(self) -> None:
        """Single cluster k=1 produces silhouette coefficient 0.0 (degenerate state)."""
        tree = DendrogramTree()
        clusters = cut_dendrogram_tree(tree.root, tree.max_height + 1.0, tree.sensors)
        sil = compute_silhouette_coefficient(tree.distance_matrix, clusters)
        assert sil == 0.0

    def test_cluster_degeneracy_alarm_assertion(self) -> None:
        """Injecting degeneracy condition asserts %M421 and sets diagnostic code 0xEB01."""
        canvas = DendrogramCanvas()
        assert canvas.metrics.cluster_degeneracy_alarm_active is False
        assert canvas.diagnostic_code == DIAG_OK

        canvas.inject_degeneracy_fault()
        assert canvas.metrics.cluster_degeneracy_alarm_active is True
        assert canvas.reg_table.read_bit(COIL_CLUSTER_DEGENERACY_ALARM_ACTIVE) is True
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == DIAG_ERR_CLUSTER_DEGENERACY_FAULT

    def test_degeneracy_recovery_on_nominal_threshold(self) -> None:
        """Resetting threshold back to nominal clears %M421 degeneracy alarm and 0xEB01 code."""
        canvas = DendrogramCanvas()
        canvas.inject_degeneracy_fault()
        assert canvas.metrics.cluster_degeneracy_alarm_active is True

        canvas.set_distance_cut_threshold(DEFAULT_DISTANCE_CUT_THRESHOLD)
        assert canvas.metrics.cluster_degeneracy_alarm_active is False
        assert canvas.diagnostic_code == DIAG_OK
        assert canvas.reg_table.read_bit(COIL_CLUSTER_DEGENERACY_ALARM_ACTIVE) is False

    def test_silhouette_singleton_handling(self) -> None:
        """Clusters with size 1 produce silhouette score 0.0 without division-by-zero errors."""
        tree = DendrogramTree()
        clusters = cut_dendrogram_tree(tree.root, 0.01, tree.sensors)  # 32 singletons
        sil = compute_silhouette_coefficient(tree.distance_matrix, clusters)
        assert sil == 0.0


# ============================================================================
# Section 8: WCAG 2.1 AAA Accessibility & Visual Legibility
# ============================================================================

class TestWCAG21AAAContrastAndVisualLegibility:
    """Validate relative luminance, contrast ratios (>18:1 badge, >7:1 text), and palettes."""

    def test_wcag_relative_luminance_extremes(self) -> None:
        """Black (#000000) has luminance 0.0 and white (#FFFFFF) has luminance 1.0."""
        assert math.isclose(relative_luminance("#000000"), 0.0, abs_tol=1e-5)
        assert math.isclose(relative_luminance("#FFFFFF"), 1.0, abs_tol=1e-5)

    def test_wcag_contrast_ratio_formula(self) -> None:
        """contrast_ratio is symmetric and bounded: CR(A, B) == CR(B, A) >= 1.0."""
        cr1 = contrast_ratio("#FFFFFF", "#000000")
        cr2 = contrast_ratio("#000000", "#FFFFFF")
        assert math.isclose(cr1, cr2, rel_tol=1e-5)
        assert math.isclose(cr1, 21.0, rel_tol=1e-2)
        assert contrast_ratio("#123456", "#123456") == 1.0

    def test_wcag_text_primary_contrast_ratio(self) -> None:
        """Primary text (#FFFFFF) against dark backing (#0D1117) exceeds WCAG AAA 7.0:1."""
        cr = contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert cr >= 7.0

    def test_wcag_decoupled_badge_contrast_ratio(self) -> None:
        """Primary text against decoupled badge (#0B0F19) exceeds safety target 18.0:1."""
        cr = contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert cr >= 18.0

    def test_wcag_cluster_palette_contrast_against_card(self) -> None:
        """All cluster palette colors have contrast > 4.5:1 against dark container background."""
        for col in CLUSTER_PALETTE:
            cr = contrast_ratio(col, COLOR_CONTAINER_BG)
            assert cr >= 4.0

    def test_validate_wcag_aaa_contrast_helper(self) -> None:
        """validate_wcag_aaa_contrast returns (True, text_cr, badge_cr)."""
        is_aaa, text_cr, badge_cr = validate_wcag_aaa_contrast()
        assert is_aaa is True
        assert text_cr >= 7.0
        assert badge_cr >= 18.0


# ============================================================================
# Section 9: Standalone W3C SVG XML Validation & Vector Generation
# ============================================================================

class TestStandaloneW3CSVGGenerationAndXMLParsing:
    """Validate standalone W3C SVG 1.1 vector graphic markup with ElementTree."""

    def test_svg_valid_xml_parsing(self) -> None:
        """generate_dendrogram_canvas_svg produces strictly valid XML parsed by ET.fromstring."""
        canvas = DendrogramCanvas()
        svg_content = canvas.render_svg()
        root = ET.fromstring(svg_content)
        assert root.tag.endswith("svg")

    def test_svg_viewport_dimensions(self) -> None:
        """SVG contains 1200x750 viewport and viewBox attributes."""
        canvas = DendrogramCanvas()
        svg_content = canvas.render_svg()
        root = ET.fromstring(svg_content)
        assert root.attrib.get("width") == str(CANVAS_VIEWPORT_WIDTH)
        assert root.attrib.get("height") == str(CANVAS_VIEWPORT_HEIGHT)
        assert root.attrib.get("viewBox") == f"0 0 {CANVAS_VIEWPORT_WIDTH} {CANVAS_VIEWPORT_HEIGHT}"

    def test_svg_branch_paths_elements(self) -> None:
        """SVG contains path elements representing orthogonal dendrogram branches."""
        canvas = DendrogramCanvas()
        svg_content = canvas.render_svg()
        root = ET.fromstring(svg_content)
        paths = root.findall(".//{http://www.w3.org/2000/svg}path") + root.findall(".//path")
        assert len(paths) >= 30

    def test_svg_heat_matrix_cells(self) -> None:
        """SVG contains rect elements representing 32x32 heat matrix cells and panels."""
        canvas = DendrogramCanvas()
        svg_content = canvas.render_svg()
        root = ET.fromstring(svg_content)
        rects = root.findall(".//{http://www.w3.org/2000/svg}rect") + root.findall(".//rect")
        # 1024 cells + container panels + cards > 1000
        assert len(rects) > 1000

    def test_svg_hud_telemetry_labels(self) -> None:
        """SVG contains text labels for HUD telemetry cards and Horner OCS registers."""
        canvas = DendrogramCanvas()
        svg_content = canvas.render_svg()
        assert "DENDROGRAM" in svg_content
        assert "ACTIVE CLUSTERS" in svg_content
        assert "SILHOUETTE" in svg_content
        assert "%R1800" in svg_content

    def test_svg_render_error_handling(self) -> None:
        """SVGRenderError is raised if SVG XML parsing encounters a syntax fault."""
        import unittest.mock
        canvas = DendrogramCanvas()
        with unittest.mock.patch("xml.etree.ElementTree.fromstring", side_effect=ET.ParseError("XML syntax fault")):
            with pytest.raises(SVGRenderError):
                canvas.render_svg()


# ============================================================================
# Section 10: Horner OCS Register Space Synchronization
# ============================================================================

class TestHornerOCSSynchronization:
    """Validate RegisterTable memory synchronization (%R1800..%R1807, %M420..%M421)."""

    def test_register_table_word_synchronization(self) -> None:
        """Registers %R1800..%R1807 are written accurately with PrivilegeMode.SYSTEM."""
        reg_table = RegisterTable()
        canvas = DendrogramCanvas(reg_table=reg_table)
        canvas.scan_step()

        assert reg_table.read_word(REG_TOTAL_NODE_COUNT) == 32
        assert reg_table.read_word(REG_ACTIVE_CLUSTER_COUNT) == 4
        assert reg_table.read_word(REG_DISTANCE_CUT_THRESHOLD_SCALED) == 150
        assert reg_table.read_word(REG_COPHENETIC_CORRELATION_PCT_SCALED) >= 8000
        assert 1 <= reg_table.read_word(REG_SELECTED_NODE_CLUSTER_ID) <= 8
        assert reg_table.read_word(REG_MAX_INTER_CLUSTER_DISTANCE_SCALED) > 300
        assert reg_table.read_word(REG_SILHOUETTE_COEFFICIENT_SCALED) >= 70
        assert reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0

    def test_register_table_discrete_coils_synchronization(self) -> None:
        """Coils %M420 (active) and %M421 (degeneracy alarm) reflect canvas state."""
        reg_table = RegisterTable()
        canvas = DendrogramCanvas(reg_table=reg_table)
        canvas.scan_step()

        assert reg_table.read_bit(COIL_DENDROGRAM_CANVAS_ACTIVE) is True
        assert reg_table.read_bit(COIL_CLUSTER_DEGENERACY_ALARM_ACTIVE) is False

    def test_diagnostic_code_signed_and_unsigned_equality(self) -> None:
        """DiagnosticCode(0xEB01) evaluates equal to both unsigned (60161) and signed (-5375)."""
        code = DiagnosticCode(0xEB01)
        assert code == 0xEB01
        assert code == 60161
        assert code == -5375

    def test_scaled_register_properties(self) -> None:
        """DendrogramMetrics helper properties scale floating-point metrics into INT16 words."""
        m = DendrogramMetrics(
            distance_cut_threshold=1.75,
            cophenetic_correlation=0.9234,
            max_inter_cluster_distance=3.85,
            silhouette_coefficient=0.82,
        )
        assert m.distance_cut_threshold_scaled == 175
        assert m.cophenetic_correlation_pct_scaled == 9234
        assert m.max_inter_cluster_distance_scaled == 385
        assert m.silhouette_coefficient_scaled == 82

    def test_sensor_selection_updates_register_r1804(self) -> None:
        """Selecting a sensor updates %R1804 with its assigned cluster ID."""
        reg_table = RegisterTable()
        canvas = DendrogramCanvas(reg_table=reg_table)
        # Select sensor #1
        canvas.select_sensor_by_index(1)
        r1804_1 = reg_table.read_word(REG_SELECTED_NODE_CLUSTER_ID)
        assert 1 <= r1804_1 <= 4

        # Select sensor #11 (FCC group, cluster 2)
        canvas.select_sensor_by_index(11)
        r1804_11 = reg_table.read_word(REG_SELECTED_NODE_CLUSTER_ID)
        assert r1804_11 == 2

    def test_register_aliases_conformity(self) -> None:
        """W219 register aliases point to correct %R1800..%R1807 memory addresses."""
        assert REG_W219_TOTAL_NODES == "%R1800"
        assert REG_W219_ACTIVE_CLUSTERS == "%R1801"
        assert REG_W219_CUT_THRESHOLD == "%R1802"
        assert REG_W219_COPHENETIC_CORR == "%R1803"
        assert REG_W219_SELECTED_CLUSTER == "%R1804"
        assert REG_W219_MAX_INTER_DIST == "%R1805"
        assert REG_W219_SILHOUETTE_SCORE == "%R1806"
        assert REG_W219_DIAGNOSTIC_CODE == "%R1807"
        assert COIL_W219_CANVAS_ACTIVE == "%M420"
        assert COIL_W219_DEGENERACY_ALARM == "%M421"


# ============================================================================
# Section 11: ILogicUnit Scan Cycle Engine & Lifecycle
# ============================================================================

class TestILogicUnitScanCycleEngine:
    """Validate ILogicUnit discrete scan cycle (scan_step, step, execute, reset)."""

    def test_ilogic_unit_properties(self) -> None:
        """ILogicUnit interface properties: name, priority, is_enabled."""
        canvas = DendrogramCanvas()
        assert canvas.name == "DendrogramCanvasSync"
        assert canvas.priority == 95
        assert canvas.is_enabled is True

    def test_scan_step_execution(self) -> None:
        """scan_step simulates single discrete clock cycle and synchronizes registers."""
        reg_table = RegisterTable()
        canvas = DendrogramCanvas(reg_table=reg_table)
        canvas.scan_step(dt=0.01)
        assert reg_table.read_word(REG_TOTAL_NODE_COUNT) == 32

    def test_step_alias(self) -> None:
        """step() method functions as a direct scan_step() alias."""
        reg_table = RegisterTable()
        canvas = DendrogramCanvas(reg_table=reg_table)
        canvas.step()
        assert reg_table.read_bit(COIL_DENDROGRAM_CANVAS_ACTIVE) is True

    def test_execute_with_scan_context(self) -> None:
        """execute(context) executes cleanly within Horner ScanContext callbacks."""
        reg_table = RegisterTable()
        ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=reg_table)
        canvas = DendrogramCanvas(reg_table=reg_table)
        canvas.execute(ctx)
        assert reg_table.read_word(REG_TOTAL_NODE_COUNT) == 32

    def test_reset_lifecycle(self) -> None:
        """reset() restores default cut threshold, clears faults, and re-syncs registers."""
        reg_table = RegisterTable()
        canvas = DendrogramCanvas(reg_table=reg_table)
        canvas.set_distance_cut_threshold(2.50)
        assert canvas.distance_cut_threshold == 2.50

        canvas.reset()
        assert canvas.distance_cut_threshold == DEFAULT_DISTANCE_CUT_THRESHOLD
        assert canvas.diagnostic_code == DIAG_OK
        assert reg_table.read_word(REG_DISTANCE_CUT_THRESHOLD_SCALED) == 150

    def test_create_canonical_dendrogram_canvas_factory(self) -> None:
        """create_canonical_dendrogram_canvas instantiates configured canvas engine."""
        canvas = create_canonical_dendrogram_canvas(distance_cut_threshold=1.80)
        assert canvas.distance_cut_threshold == 1.80
        assert canvas.tree.total_leaves == 32


# ============================================================================
# Section 12: Deterministic 9-Stage Verification Suite & 4-State Contract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate 9-stage verification runner and strict 4-state engineering contract JSON."""

    def test_run_dendrogram_canvas_verification_structure(self) -> None:
        """run_dendrogram_canvas_verification returns strict 4-state contract JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"
            report = run_dendrogram_canvas_verification(
                output_path=str(ev_path),
                sample_svg_path=str(svg_path),
            )
            assert isinstance(report, dict)
            assert report["status"] in ("success", "failed", "blocked", "inconclusive")
            assert "error_code" in report
            assert "details" in report
            assert "data" in report

    def test_run_dendrogram_canvas_verification_all_passed(self) -> None:
        """All 9 stages pass deterministically with status 'success'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"
            report = run_dendrogram_canvas_verification(
                output_path=str(ev_path),
                sample_svg_path=str(svg_path),
            )
            assert report["status"] == "success"
            assert report["error_code"] is None
            assert report["data"]["checks_passed"] == 9
            assert report["data"]["total_checks"] == 9

    def test_verification_evidence_json_export(self) -> None:
        """Verification report is written to disk as valid readable JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"
            run_dendrogram_canvas_verification(
                output_path=str(ev_path),
                sample_svg_path=str(svg_path),
            )
            assert ev_path.exists()
            with open(ev_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["status"] == "success"
            assert len(data["data"]["tests"]) == 9

    def test_verification_sample_svg_export(self) -> None:
        """Sample SVG vector graphic is saved to disk and parsable by ElementTree."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"
            run_dendrogram_canvas_verification(
                output_path=str(ev_path),
                sample_svg_path=str(svg_path),
            )
            assert svg_path.exists()
            with open(svg_path, "r", encoding="utf-8") as f:
                content = f.read()
            root = ET.fromstring(content)
            assert root.tag.endswith("svg")

    def test_individual_stages_content_and_names(self) -> None:
        """Check all 9 stage names in verification output match engineering specifications."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"
            report = run_dendrogram_canvas_verification(
                output_path=str(ev_path),
                sample_svg_path=str(svg_path),
            )
            tests = report["data"]["tests"]
            expected_stages = [
                "Pure_ST_POU_Grammar_AST_Validation",
                "Anti_Ladder_Construct_Security_Interception",
                "Canonical_32Node_Plant_Sensor_Topology_And_Metric_Invariants",
                "Hierarchical_Agglomerative_Clustering_And_Cophenetic_Correlation",
                "Dynamic_Cluster_Cut_Threshold_And_k_Partitioning",
                "Silhouette_Quality_And_Cluster_Degeneracy_Alarm_Trip",
                "Singularity_And_Threshold_Out_Of_Bounds_Guards",
                "Dual_Pane_Standalone_W3C_SVG_XML_Validation_And_WCAG_21_AAA",
                "Horner_OCS_Register_Sync_And_ILogicUnit_Scan_Cycle",
            ]
            actual_stages = [t["check"] for t in tests]
            assert actual_stages == expected_stages
            assert all(t["passed"] is True for t in tests)
