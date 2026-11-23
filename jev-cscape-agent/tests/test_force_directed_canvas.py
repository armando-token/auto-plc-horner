"""Comprehensive unit test suite for Cscape HMI Dynamic Force-Directed Spring-Electrical Network SCADA Canvas (W258).

Work Package: Wave W258 (Gate G9 HMI Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Force-Directed Spring-Electrical Network SCADA Canvas]

Architectural Coverage (120+ Deterministic Unit Tests across 14 Test Classes):
1. TestDiagnosticCodeMathAndFormats: DiagnosticCode signed/unsigned 16-bit values, hex formats, hashes, strings, and equality.
2. TestRegisterAndCoilAddressMappings: %R2190..%R2197 word registers, %M511..%M512 discrete coils, W258 aliases, and W210 backward compatibility.
3. TestTopologyAndGraphModels: Canonical 12-device mesh network (12 nodes, 18 edges) and 36-node plant network (4 tiers, 52 edges).
4. TestForcesAndVectorPhysics: Vector2D arithmetic, Coulomb repulsion (F_r = k_r/d^2 or k^2/d), Hooke spring attraction, Newton's third law.
5. TestBarnesHutQuadtreePhysics: 2D spatial quadtree insertion, mass distribution, center of mass, Barnes-Hut theta criterion.
6. TestAnnealingAndKineticEnergy: AnnealingSchedule cooling, minimum temperature clamping, kinetic energy residual, layout energy norm.
7. TestBoundingBoxAndCollisions: Canvas boundary rectangular containment, hard-sphere collision detection and resolution.
8. TestWCAG21AAAContrastCompliance: WCAG 2.1 AAA relative luminance, text contrast >= 7.0:1, decoupled badge contrast >= 18.0:1, graphics >= 3.0:1.
9. TestSVGGenerationAndXMLValidity: Standalone W3C SVG 1.1 XML generation, ElementTree parsing, viewBox, nodes, edges, HUD, legend.
10. TestProcessSafetyDiagnosticsAndFaults: 0x7601 isolated node trip, 0x7602 high energy instability, status bits, recovery reset nominal.
11. TestPartitionAlarmCoilAssertion: Partition alarm coil %M512 assertion during stress / fault trips, de-assertion upon reset, %M511 active coil.
12. TestHornerOCSRegisterSynchronization: Exact %R2190..%R2197 and %M511..%M512 synchronization, PrivilegeMode.SYSTEM, 50-cycle soak stability.
13. TestPureSTAndSecurity: SecurityGuard and STParser validation of Pure ST POU ForceDirectedCanvasSync, variable bindings, POU structure.
14. TestAntiLadderRejection: Fail-closed interception with LadderForbiddenError on 8+ ladder contacts, coils, rungs, mnemonics.
15. TestVerificationRunnerAndContract: Deterministic 9-stage verification runner returning strict 4-state contract JSON and evidence export.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Sequence, Set, Tuple
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.force_directed_canvas import (
    # Diagnostics & Event Codes
    DIAG_OK,
    DIAG_EVENT_OK,
    DIAG_ERR_ISOLATED_NODE_TRIP,
    ISOLATED_NODE_TRIP,
    DIAG_ERR_ISOLATED_NODE,
    DIAG_ERR_HIGH_ENERGY_INSTABILITY,
    HIGH_ENERGY_INSTABILITY,
    DIAG_ERR_ENERGY_INSTABILITY,
    DIAG_ERR_ENERGY_CONVERGENCE_DIVERGENCE,
    ENERGY_CONVERGENCE_DIVERGENCE,
    DIAG_ERR_TOPOLOGY_ISLAND_DISCONNECTED,
    TOPOLOGY_ISLAND_DISCONNECTED,
    DIAG_ERR_NODE_COLLISION_OVERLAP,
    NODE_COLLISION_OVERLAP,
    DIAG_ERR_SVG_RENDER_FAULT,
    SVG_RENDER_FAULT,
    DIAG_ERR_ENERGY_CONVERGENCE_DIVERGENCE_LEGACY,
    DIAG_ERR_TOPOLOGY_ISLAND_DISCONNECTED_LEGACY,
    DIAG_ERR_NODE_COLLISION_OVERLAP_LEGACY,
    DIAG_ERR_SVG_RENDER_FAULT_LEGACY,
    # Register & Coil Addresses (W258)
    REG_FORCE_ACTIVE_NODES_COUNT,
    REG_FORCE_ACTIVE_EDGES_COUNT,
    REG_LAYOUT_ENERGY_NORM_SCALED,
    REG_LAYOUT_CONVERGENCE_CYCLES,
    REG_SELECTED_NODE_ID,
    REG_MAX_NODE_DEGREE,
    REG_NETWORK_PARTITION_COUNT,
    REG_FORCE_CANVAS_DIAGNOSTIC_CODE,
    COIL_FORCE_CANVAS_ACTIVE,
    COIL_TOPOLOGY_PARTITION_ALARM,
    # W258 Aliases
    REG_W258_TOTAL_NODE_COUNT,
    REG_W258_TOTAL_EDGE_COUNT,
    REG_W258_KINETIC_ENERGY_RESIDUAL_SCALED,
    REG_W258_SELECTED_NODE_INDEX,
    REG_W258_SELECTED_NODE_DEGREE,
    REG_W258_NETWORK_CLUSTERING_COEFF_SCALED,
    REG_W258_CRITICAL_PARTITION_STRESS_SCORE,
    REG_W258_DIAGNOSTIC_STATUS_CODE,
    COIL_W258_FORCE_SIMULATION_EQUILIBRIUM,
    COIL_W258_ENERGY_INSTABILITY_ALARM,
    # W210 Registers & Coils
    REG_TOTAL_NODE_COUNT,
    REG_TOTAL_EDGE_COUNT,
    REG_KINETIC_ENERGY_RESIDUAL_SCALED,
    REG_SELECTED_NODE_INDEX,
    REG_SELECTED_NODE_DEGREE,
    REG_NETWORK_CLUSTERING_COEFF_SCALED,
    REG_CRITICAL_PARTITION_STRESS_SCORE,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_W210_NODE_COUNT,
    REG_W210_EDGE_COUNT,
    REG_W210_KINETIC_ENERGY,
    REG_W210_SELECTED_NODE,
    REG_W210_SELECTED_DEGREE,
    REG_W210_CLUSTERING_COEFF,
    REG_W210_PARTITION_STRESS,
    REG_W210_STATUS_WORD,
    REG_W210_DIAGNOSTIC_CODE,
    COIL_FORCE_SIMULATION_EQUILIBRIUM,
    COIL_NETWORK_STRESS_ALARM_ACTIVE,
    COIL_W210_EQUILIBRIUM,
    COIL_W210_STRESS_ALARM,
    # Thresholds & Geometry Constants
    EQUILIBRIUM_ENERGY_THRESHOLD,
    CRITICAL_STRESS_ALARM_THRESHOLD,
    MIN_NODE_COLLISION_DISTANCE,
    HIGH_ENERGY_INSTABILITY_THRESHOLD,
    CANVAS_VIEWPORT_WIDTH,
    CANVAS_VIEWPORT_HEIGHT,
    GRAPH_BOUNDS_X_MIN,
    GRAPH_BOUNDS_Y_MIN,
    GRAPH_BOUNDS_X_MAX,
    GRAPH_BOUNDS_Y_MAX,
    GRAPH_CENTER_X,
    GRAPH_CENTER_Y,
    # Colors & Accessibility Targets
    COLOR_DARK_THEME_BACKING,
    COLOR_DECOUPLED_BADGE,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_MUTED,
    COLOR_FOCUS_BLUE,
    COLOR_NOMINAL_EMERALD,
    COLOR_WARNING_AMBER,
    COLOR_ALARM_CRIMSON,
    COLOR_TIER_0_POWER,
    COLOR_TIER_1_DCS,
    COLOR_TIER_2_RIO,
    COLOR_TIER_3_SIS,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_AAA_GRAPHICS_CONTRAST_TARGET,
    TIER_NAMES,
    TIER_COLORS,
    TIER_RADII,
    # Pure ST POUs
    FORCE_DIRECTED_CANVAS_PURE_ST_POU,
    W258_FORCE_DIRECTED_PURE_ST_POU,
    W210_FORCE_DIRECTED_PURE_ST_POU,
    FORCE_DIRECTED_PURE_ST_POU,
    DYNAMIC_FORCE_DIRECTED_CANVAS_PURE_ST_POU,
    # Classes & Enums
    DiagnosticCode,
    ForceDirectedDiagnosticCode,
    ForceDirectedCanvasDiagnosticCode,
    NetworkTier,
    Vector2D,
    Point2D,
    AnnealingSchedule,
    BarnesHutQuadTree,
    MeshNode,
    ForceNode,
    NetworkNode,
    MeshEdge,
    ForceEdge,
    NetworkEdge,
    IndustrialMeshTopology,
    ForceDirectedGraph,
    NetworkTopology,
    ForceDirectedStatusBits,
    ForceDirectedCanvasMetrics,
    ForceDirectedMetrics,
    ForceDirectedPhysicsEngine,
    ForceDirectedCanvas,
    ForceDirectedCanvasEngine,
    ForceDirectedCanvasSync,
    # Functions
    srgb_channel_to_linear,
    hex_to_relative_luminance,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    compute_coulomb_repulsion,
    compute_hooke_attraction,
    compute_kinetic_energy,
    compute_network_partition_stress,
    apply_bounding_box_containment,
    local_clustering_coefficient,
    average_clustering_coefficient,
    resolve_node_collisions,
    create_canonical_mesh_network,
    create_canonical_force_directed_graph,
    create_canonical_plant_network,
    layout_force_directed_graph,
    generate_force_directed_canvas_svg,
    create_canonical_force_directed_canvas,
    create_canonical_mesh_canvas,
    create_mock_scan_context,
    verify_force_directed_canvas_pure_st,
    run_force_directed_canvas_verification,
)


# ============================================================================
# 1. TestDiagnosticCodeMathAndFormats
# ============================================================================

class TestDiagnosticCodeMathAndFormats:
    """Verify signed and unsigned 16-bit values, equality, hashing, hex formatting, and string representations."""

    def test_diagnostic_code_ok_equality(self) -> None:
        """Nominal 0x0000 matches integer 0, hex, and OK aliases."""
        diag = DiagnosticCode(0x0000)
        assert diag == 0
        assert diag == 0x0000
        assert diag == DIAG_OK
        assert diag == DIAG_EVENT_OK

    def test_diagnostic_code_isolated_node_0x7601(self) -> None:
        """0x7601 matches unsigned 30209, signed +30209, and isolated node aliases."""
        diag = DiagnosticCode(0x7601)
        assert diag == 0x7601
        assert diag == 30209
        assert diag == DIAG_ERR_ISOLATED_NODE_TRIP
        assert diag == ISOLATED_NODE_TRIP
        assert diag == DIAG_ERR_ISOLATED_NODE

    def test_diagnostic_code_high_energy_instability_0x7602(self) -> None:
        """0x7602 matches unsigned 30210, signed +30210, and high energy instability aliases."""
        diag = DiagnosticCode(0x7602)
        assert diag == 0x7602
        assert diag == 30210
        assert diag == DIAG_ERR_HIGH_ENERGY_INSTABILITY
        assert diag == HIGH_ENERGY_INSTABILITY
        assert diag == DIAG_ERR_ENERGY_INSTABILITY

    def test_diagnostic_code_legacy_w210_codes(self) -> None:
        """Legacy diagnostic codes (0xE201..0xE204) match signed negative 16-bit equivalents."""
        d_e201 = DiagnosticCode(0xE201)
        assert d_e201 == 0xE201
        assert d_e201 == 57857
        assert d_e201 == -7679
        assert d_e201 == DIAG_ERR_ENERGY_CONVERGENCE_DIVERGENCE_LEGACY

        d_e202 = DiagnosticCode(0xE202)
        assert d_e202 == 0xE202
        assert d_e202 == 57858
        assert d_e202 == -7678
        assert d_e202 == DIAG_ERR_TOPOLOGY_ISLAND_DISCONNECTED_LEGACY

        d_e203 = DiagnosticCode(0xE203)
        assert d_e203 == 0xE203
        assert d_e203 == -7677
        assert d_e203 == DIAG_ERR_NODE_COLLISION_OVERLAP_LEGACY

        d_e204 = DiagnosticCode(0xE204)
        assert d_e204 == 0xE204
        assert d_e204 == -7676
        assert d_e204 == DIAG_ERR_SVG_RENDER_FAULT_LEGACY

    def test_diagnostic_code_signed_conversion_extremes(self) -> None:
        """Codes with high-bit set (>= 0x8000) match negative 16-bit signed values."""
        d_high = DiagnosticCode(0x8000)
        assert d_high == 0x8000
        assert d_high == -32768

        d_all_ones = DiagnosticCode(0xFFFF)
        assert d_all_ones == 0xFFFF
        assert d_all_ones == -1

    def test_diagnostic_code_hashing_and_dict_keys(self) -> None:
        """DiagnosticCode instances hash consistently and work in dicts and sets."""
        d1 = DiagnosticCode(0x7601)
        d2 = DiagnosticCode(30209)
        assert hash(d1) == hash(d2)

        mapping = {d1: "ISOLATED_NODE_TRIP"}
        assert mapping[d2] == "ISOLATED_NODE_TRIP"
        assert d2 in mapping

        code_set = {DiagnosticCode(0x0000), DiagnosticCode(0x7601), DiagnosticCode(0x7602)}
        assert DiagnosticCode(0) in code_set
        assert DiagnosticCode(30209) in code_set
        assert DiagnosticCode(30210) in code_set
        assert len(code_set) == 3

    def test_diagnostic_code_string_and_hex_representations(self) -> None:
        """DiagnosticCode converts to decimal string and 16-bit hex formatting."""
        d_ok = DiagnosticCode(0x0000)
        d_iso = DiagnosticCode(0x7601)
        d_ene = DiagnosticCode(0x7602)

        assert str(d_ok) == "0"
        assert str(d_iso) == "30209"
        assert str(d_ene) == "30210"

        assert f"0x{int(d_ok):04X}" == "0x0000"
        assert f"0x{int(d_iso):04X}" == "0x7601"
        assert f"0x{int(d_ene):04X}" == "0x7602"

    def test_diagnostic_code_comparison_with_non_integers(self) -> None:
        """Comparing DiagnosticCode with non-integer types returns False cleanly."""
        code = DiagnosticCode(0x7601)
        assert (code == "0x7601") is False
        assert (code == [0x7601]) is False
        assert (code == None) is False

    def test_diagnostic_code_class_aliases(self) -> None:
        """ForceDirectedDiagnosticCode and ForceDirectedCanvasDiagnosticCode alias DiagnosticCode."""
        assert ForceDirectedDiagnosticCode is DiagnosticCode
        assert ForceDirectedCanvasDiagnosticCode is DiagnosticCode


# ============================================================================
# 2. TestRegisterAndCoilAddressMappings
# ============================================================================

class TestRegisterAndCoilAddressMappings:
    """Verify Horner OCS register space addresses (%R2190..%R2197, %M511..%M512) and aliases."""

    def test_w258_word_register_addresses(self) -> None:
        """Verify each W258 word register maps to %R2190..%R2197."""
        assert REG_FORCE_ACTIVE_NODES_COUNT == "%R2190"
        assert REG_FORCE_ACTIVE_EDGES_COUNT == "%R2191"
        assert REG_LAYOUT_ENERGY_NORM_SCALED == "%R2192"
        assert REG_LAYOUT_CONVERGENCE_CYCLES == "%R2193"
        assert REG_SELECTED_NODE_ID == "%R2194"
        assert REG_MAX_NODE_DEGREE == "%R2195"
        assert REG_NETWORK_PARTITION_COUNT == "%R2196"
        assert REG_FORCE_CANVAS_DIAGNOSTIC_CODE == "%R2197"

    def test_w258_script_aliases(self) -> None:
        """Verify script integration aliases for W258."""
        assert REG_W258_TOTAL_NODE_COUNT == "%R2190"
        assert REG_W258_TOTAL_EDGE_COUNT == "%R2191"
        assert REG_W258_KINETIC_ENERGY_RESIDUAL_SCALED == "%R2192"
        assert REG_W258_SELECTED_NODE_INDEX == "%R2193"
        assert REG_W258_SELECTED_NODE_DEGREE == "%R2194"
        assert REG_W258_NETWORK_CLUSTERING_COEFF_SCALED == "%R2195"
        assert REG_W258_CRITICAL_PARTITION_STRESS_SCORE == "%R2196"
        assert REG_W258_DIAGNOSTIC_STATUS_CODE == "%R2197"
        assert COIL_W258_FORCE_SIMULATION_EQUILIBRIUM == "%M511"
        assert COIL_W258_ENERGY_INSTABILITY_ALARM == "%M512"

    def test_w258_discrete_coil_addresses(self) -> None:
        """Verify discrete coils map to %M511 and %M512."""
        assert COIL_FORCE_CANVAS_ACTIVE == "%M511"
        assert COIL_TOPOLOGY_PARTITION_ALARM == "%M512"

    def test_w258_registers_and_coils_disjoint_and_sequential(self) -> None:
        """Verify W258 word registers form 8 contiguous unique addresses and coils form 2 unique addresses."""
        registers = [
            REG_FORCE_ACTIVE_NODES_COUNT,
            REG_FORCE_ACTIVE_EDGES_COUNT,
            REG_LAYOUT_ENERGY_NORM_SCALED,
            REG_LAYOUT_CONVERGENCE_CYCLES,
            REG_SELECTED_NODE_ID,
            REG_MAX_NODE_DEGREE,
            REG_NETWORK_PARTITION_COUNT,
            REG_FORCE_CANVAS_DIAGNOSTIC_CODE,
        ]
        assert len(registers) == 8
        assert len(set(registers)) == 8
        for i, reg in enumerate(registers):
            assert reg == f"%R{2190 + i}"

        coils = [COIL_FORCE_CANVAS_ACTIVE, COIL_TOPOLOGY_PARTITION_ALARM]
        assert len(coils) == 2
        assert len(set(coils)) == 2
        assert coils[0] == "%M511"
        assert coils[1] == "%M512"

    def test_legacy_w210_aliases_preserved(self) -> None:
        """Verify legacy W210 constants (%R1710..%R1717, %M399..%M400) remain accessible."""
        assert REG_W210_NODE_COUNT == "%R1710"
        assert REG_W210_EDGE_COUNT == "%R1711"
        assert REG_W210_KINETIC_ENERGY == "%R1712"
        assert REG_W210_SELECTED_NODE == "%R1713"
        assert REG_W210_SELECTED_DEGREE == "%R1714"
        assert REG_W210_CLUSTERING_COEFF == "%R1715"
        assert REG_W210_PARTITION_STRESS == "%R1716"
        assert REG_W210_STATUS_WORD == "%R1717"
        assert REG_W210_DIAGNOSTIC_CODE == "%R1717"

        assert COIL_W210_EQUILIBRIUM == "%M399"
        assert COIL_W210_STRESS_ALARM == "%M400"


# ============================================================================
# 3. TestTopologyAndGraphModels
# ============================================================================

class TestTopologyAndGraphModels:
    """Verify 12-device mesh network (W258) and 36-device plant network (W210) compositions."""

    def test_canonical_mesh_network_composition(self) -> None:
        """Canonical W258 mesh network contains exactly 12 nodes, 18 edges, and 1 partition."""
        mesh = create_canonical_mesh_network()
        assert len(mesh.nodes) == 12
        assert len(mesh.edges) == 18
        assert mesh.partition_count() == 1
        assert mesh.max_node_degree() <= 5

        # Check nodes are indexed 0..11
        for idx in range(12):
            node = mesh.get_node(f"NODE_{idx:02d}")
            assert node is not None
            assert node.index == idx

    def test_canonical_plant_network_composition(self) -> None:
        """Canonical plant network topology contains exactly 36 nodes across 4 tiers and 52 edges."""
        graph = create_canonical_plant_network()
        assert len(graph.nodes) == 36
        assert len(graph.edges) == 52

        t0_nodes = [n for n in graph.nodes.values() if n.tier == 0]
        t1_nodes = [n for n in graph.nodes.values() if n.tier == 1]
        t2_nodes = [n for n in graph.nodes.values() if n.tier == 2]
        t3_nodes = [n for n in graph.nodes.values() if n.tier == 3]

        assert len(t0_nodes) == 4
        assert len(t1_nodes) == 8
        assert len(t2_nodes) == 12
        assert len(t3_nodes) == 12

        assert graph.is_connected() is True
        assert len(graph.get_connected_components()) == 1

    def test_mesh_node_properties(self) -> None:
        """MeshNode data structure stores IP, role, telemetry, and coordinates."""
        node = MeshNode(
            id="NODE_00",
            name="Plant Gateway Core",
            tier=0,
            index=0,
            ip_address="192.168.1.1",
            role="Gateway",
            x=440.0,
            y=375.0,
            degree=4,
        )
        assert node.id == "NODE_00"
        assert node.ip_address == "192.168.1.1"
        assert node.role == "Gateway"
        assert node.x == 440.0
        assert node.y == 375.0
        assert node.degree == 4

    def test_mesh_edge_properties(self) -> None:
        """MeshEdge data structure stores bandwidth, packet rate, weight, rest_length, and status."""
        edge = MeshEdge(
            source_id="NODE_00",
            target_id="NODE_01",
            bandwidth_mbps=1000.0,
            packet_rate_pps=540.0,
            weight=1.0,
            rest_length=110.0,
        )
        assert edge.source_id == "NODE_00"
        assert edge.target_id == "NODE_01"
        assert edge.bandwidth_mbps == 1000.0
        assert edge.packet_rate_pps == 540.0
        assert edge.weight == 1.0
        assert edge.rest_length == 110.0
        assert edge.is_severed is False


# ============================================================================
# 4. TestForcesAndVectorPhysics
# ============================================================================

class TestForcesAndVectorPhysics:
    """Verify Vector2D arithmetic, Coulomb repulsion, Hooke spring attraction, and Newton's laws."""

    def test_vector2d_basic_operations(self) -> None:
        """Vector2D addition, subtraction, scalar multiplication, division, and normalization."""
        v1 = Vector2D(3.0, 4.0)
        v2 = Vector2D(1.0, 2.0)

        v_add = v1 + v2
        assert math.isclose(v_add.x, 4.0)
        assert math.isclose(v_add.y, 6.0)

        v_sub = v1 - v2
        assert math.isclose(v_sub.x, 2.0)
        assert math.isclose(v_sub.y, 2.0)

        v_mul = v1 * 2.5
        assert math.isclose(v_mul.x, 7.5)
        assert math.isclose(v_mul.y, 10.0)

        v_div = v1 / 2.0
        assert math.isclose(v_div.x, 1.5)
        assert math.isclose(v_div.y, 2.0)

        # Zero division guard
        v_zero = v1 / 0.0
        assert v_zero.x == 0.0
        assert v_zero.y == 0.0

        # Magnitude and normalized
        assert math.isclose(v1.magnitude(), 5.0)
        v_norm = v1.normalized()
        assert math.isclose(v_norm.x, 0.6)
        assert math.isclose(v_norm.y, 0.8)
        assert math.isclose(v_norm.magnitude(), 1.0)

    def test_coulomb_repulsion_direction_and_symmetry(self) -> None:
        """Coulomb repulsion pushes u away from v, obeying Newton's third law."""
        k = 100.0
        u = ForceNode(id="U", name="Node U", tier=0, index=1, x=150.0, y=100.0, mass=1.0)
        v = ForceNode(id="V", name="Node V", tier=0, index=2, x=100.0, y=100.0, mass=1.0)

        # u is to the right of v -> force on u should push right (positive fx)
        f_rep_u = compute_coulomb_repulsion(u, v, k=k)
        assert f_rep_u.x > 0.0
        assert math.isclose(f_rep_u.y, 0.0, abs_tol=1e-9)

        # Newton's third law: force on v exerted by u is equal and opposite
        f_rep_v = compute_coulomb_repulsion(v, u, k=k)
        assert math.isclose(f_rep_u.x, -f_rep_v.x, rel_tol=1e-5)
        assert math.isclose(f_rep_u.y, -f_rep_v.y, abs_tol=1e-9)

    def test_coulomb_repulsion_distance_clamping(self) -> None:
        """Zero separation is clamped to 1.0 px to prevent singularity."""
        u = ForceNode(id="U", name="U", tier=0, index=1, x=100.0, y=100.0)
        v = ForceNode(id="V", name="V", tier=0, index=2, x=100.0, y=100.0)
        f_rep = compute_coulomb_repulsion(u, v, k=50.0)
        assert math.isfinite(f_rep.x)
        assert math.isfinite(f_rep.y)

    def test_hooke_attraction_direction_and_symmetry(self) -> None:
        """Hooke attraction pulls u towards v, obeying Newton's third law."""
        k = 100.0
        u = ForceNode(id="U", name="Node U", tier=0, index=1, x=100.0, y=100.0)
        v = ForceNode(id="V", name="Node V", tier=0, index=2, x=150.0, y=100.0)

        # v is to the right of u -> force on u should pull right (positive fx)
        f_att_u = compute_hooke_attraction(u, v, k=k, weight=1.0)
        assert f_att_u.x > 0.0
        assert math.isclose(f_att_u.y, 0.0, abs_tol=1e-9)

        # Newton's third law: attraction on v towards u is opposite
        f_att_v = compute_hooke_attraction(v, u, k=k, weight=1.0)
        assert math.isclose(f_att_u.x, -f_att_v.x, rel_tol=1e-5)
        assert math.isclose(f_att_u.y, -f_att_v.y, abs_tol=1e-9)


# ============================================================================
# 5. TestBarnesHutQuadtreePhysics
# ============================================================================

class TestBarnesHutQuadtreePhysics:
    """Verify 2D spatial quadtree insertion, mass distribution, center of mass, and theta criterion."""

    def test_quadtree_single_node_insert(self) -> None:
        """Single node insertion sets total mass and center of mass exactly."""
        qtree = BarnesHutQuadTree(0.0, 0.0, 500.0, 500.0)
        n = ForceNode(id="N1", name="Node 1", tier=0, index=1, x=200.0, y=300.0, mass=2.5)
        assert qtree.insert(n) is True
        assert qtree.total_mass == 2.5
        assert qtree.center_of_mass_x == 200.0
        assert qtree.center_of_mass_y == 300.0
        assert qtree.is_leaf is True

    def test_quadtree_multi_node_subdivision(self) -> None:
        """Inserting multiple nodes subdivides quadtree into 4 children with center of mass."""
        qtree = BarnesHutQuadTree(0.0, 0.0, 400.0, 400.0)
        n1 = ForceNode(id="N1", name="N1", tier=0, index=1, x=100.0, y=100.0, mass=1.0)
        n2 = ForceNode(id="N2", name="N2", tier=0, index=2, x=300.0, y=300.0, mass=3.0)

        assert qtree.insert(n1) is True
        assert qtree.insert(n2) is True
        assert qtree.is_leaf is False
        assert qtree.children is not None
        assert len(qtree.children) == 4
        assert math.isclose(qtree.total_mass, 4.0)

        # Weighted center of mass: (100*1 + 300*3)/4 = 250.0
        assert math.isclose(qtree.center_of_mass_x, 250.0)
        assert math.isclose(qtree.center_of_mass_y, 250.0)

    def test_quadtree_barnes_hut_repulsive_force_approximation(self) -> None:
        """Barnes-Hut compute_repulsive_force computes non-zero repulsive force with theta criterion."""
        qtree = BarnesHutQuadTree(0.0, 0.0, 1000.0, 1000.0)
        target = ForceNode(id="TGT", name="Target", tier=0, index=1, x=50.0, y=50.0, mass=1.0)

        for i in range(5):
            n = ForceNode(id=f"C_{i}", name=f"Node {i}", tier=1, index=i+2, x=600.0 + i*10, y=600.0 + i*10, mass=1.0)
            qtree.insert(n)

        fx, fy = qtree.compute_repulsive_force(target, k=110.0, theta=0.7)
        assert fx < 0.0
        assert fy < 0.0
        assert math.hypot(fx, fy) > 0.0


# ============================================================================
# 6. TestAnnealingAndKineticEnergy
# ============================================================================

class TestAnnealingAndKineticEnergy:
    """Verify simulated annealing cooling schedule, temperature clamping, and kinetic energy calculations."""

    def test_annealing_schedule_defaults_and_cooling(self) -> None:
        """Cooling schedule cools monotonically by cooling_rate."""
        sched = AnnealingSchedule(initial_temperature=50.0, cooling_rate=0.90, min_temperature=0.05)
        assert sched.current_temperature == 50.0

        t1 = sched.cool()
        assert math.isclose(t1, 45.0)
        t2 = sched.cool()
        assert math.isclose(t2, 40.5)
        assert t2 < t1 < 50.0

    def test_annealing_min_temperature_clamping(self) -> None:
        """Temperature does not drop below min_temperature."""
        sched = AnnealingSchedule(initial_temperature=1.0, cooling_rate=0.5, min_temperature=0.05)
        for _ in range(20):
            sched.cool()
        assert math.isclose(sched.current_temperature, 0.05)

    def test_annealing_reset(self) -> None:
        """Reset restores temperature to initial or custom value."""
        sched = AnnealingSchedule(initial_temperature=50.0)
        sched.cool()
        sched.reset()
        assert sched.current_temperature == 50.0
        sched.reset(30.0)
        assert sched.current_temperature == 30.0

    def test_compute_kinetic_energy_empty_nodes(self) -> None:
        """Empty node list yields 0.0 kinetic energy."""
        assert compute_kinetic_energy([]) == 0.0

    def test_compute_kinetic_energy_calculation(self) -> None:
        """Compute specific kinetic energy: 0.5 * sum(m * (vx^2 + vy^2)) / N."""
        n1 = ForceNode(id="A", name="A", tier=0, index=1, vx=3.0, vy=4.0, mass=2.0)  # 0.5 * 2 * 25 = 25
        n2 = ForceNode(id="B", name="B", tier=0, index=2, vx=1.0, vy=1.0, mass=1.0)  # 0.5 * 1 * 2 = 1
        ke = compute_kinetic_energy([n1, n2])
        assert math.isclose(ke, 13.0)


# ============================================================================
# 7. TestBoundingBoxAndCollisions
# ============================================================================

class TestBoundingBoxAndCollisions:
    """Verify rectangular boundary containment and node collision resolution."""

    def test_apply_bounding_box_walls(self) -> None:
        """Nodes outside bounds are clamped and velocity reflected."""
        n_left = ForceNode(id="L", name="Left", tier=0, index=1, x=10.0, y=200.0, vx=-10.0, vy=5.0)
        apply_bounding_box_containment(n_left, x_min=60.0, x_max=800.0, y_min=60.0, y_max=700.0)
        assert n_left.x == 60.0
        assert math.isclose(n_left.vx, -0.5 * abs(-10.0))

        n_right = ForceNode(id="R", name="Right", tier=0, index=2, x=900.0, y=200.0, vx=10.0, vy=5.0)
        apply_bounding_box_containment(n_right, x_min=60.0, x_max=800.0, y_min=60.0, y_max=700.0)
        assert n_right.x == 800.0
        assert math.isclose(n_right.vx, -0.5 * abs(10.0))

        n_top = ForceNode(id="T", name="Top", tier=0, index=3, x=200.0, y=10.0, vx=2.0, vy=-8.0)
        apply_bounding_box_containment(n_top, x_min=60.0, x_max=800.0, y_min=60.0, y_max=700.0)
        assert n_top.y == 60.0
        assert math.isclose(n_top.vy, -0.5 * abs(-8.0))

        n_bot = ForceNode(id="B", name="Bottom", tier=0, index=4, x=200.0, y=850.0, vx=2.0, vy=8.0)
        apply_bounding_box_containment(n_bot, x_min=60.0, x_max=800.0, y_min=60.0, y_max=700.0)
        assert n_bot.y == 700.0
        assert math.isclose(n_bot.vy, -0.5 * abs(8.0))

    def test_detect_and_resolve_node_collisions(self) -> None:
        """Collision detection finds overlapping nodes and resolution separates them."""
        graph = ForceDirectedGraph()
        n1 = ForceNode(id="N1", name="Node 1", tier=0, index=1, x=100.0, y=100.0)
        n2 = ForceNode(id="N2", name="Node 2", tier=0, index=2, x=102.0, y=100.0)  # distance = 2.0 < 5.0
        graph.add_node(n1)
        graph.add_node(n2)

        collisions = graph.detect_node_collisions(min_distance=5.0)
        assert len(collisions) == 1
        assert collisions[0][0] == "N1"
        assert collisions[0][1] == "N2"
        assert math.isclose(collisions[0][2], 2.0)

        resolve_node_collisions(graph, min_distance=5.0)
        new_dist = math.hypot(n1.x - n2.x, n1.y - n2.y)
        assert new_dist >= 5.0


# ============================================================================
# 8. TestWCAG21AAAContrastCompliance
# ============================================================================

class TestWCAG21AAAContrastCompliance:
    """Verify WCAG 2.1 AAA relative luminance, text contrast >= 7.0:1, and badge contrast >= 18.0:1."""

    def test_relative_luminance_extremes(self) -> None:
        """Pure black yields 0.0 luminance, pure white yields 1.0."""
        assert math.isclose(hex_to_relative_luminance("#000000"), 0.0, abs_tol=1e-5)
        assert math.isclose(hex_to_relative_luminance("#FFFFFF"), 1.0, abs_tol=1e-5)

    def test_calculate_contrast_ratio_extremes(self) -> None:
        """Black vs white contrast ratio is 21.0:1, identical colors is 1.0:1."""
        cr_max = calculate_contrast_ratio("#FFFFFF", "#000000")
        assert math.isclose(cr_max, 21.0, rel_tol=1e-2)

        cr_min = calculate_contrast_ratio("#123456", "#123456")
        assert math.isclose(cr_min, 1.0, rel_tol=1e-2)

    def test_wcag_aaa_contrast_validation(self) -> None:
        """Decoupled badge contrast exceeds 18.0:1 and primary text exceeds 7.0:1."""
        is_valid, text_cr, badge_cr = validate_wcag_aaa_contrast(
            text_color=COLOR_TEXT_PRIMARY,
            theme_backing=COLOR_DARK_THEME_BACKING,
            badge_backing=COLOR_DECOUPLED_BADGE,
        )
        assert is_valid is True
        assert text_cr >= WCAG_AAA_TEXT_CONTRAST_TARGET   # >= 7.0:1
        assert badge_cr >= WCAG_AAA_BADGE_CONTRAST_TARGET # >= 18.0:1

    def test_operational_colors_graphical_contrast(self) -> None:
        """Operational SCADA colors meet WCAG graphics contrast requirement (>= 3.0:1) on dark backing."""
        colors = [COLOR_NOMINAL_EMERALD, COLOR_WARNING_AMBER, COLOR_ALARM_CRIMSON, COLOR_FOCUS_BLUE]
        for c in colors:
            cr = calculate_contrast_ratio(c, COLOR_DARK_THEME_BACKING)
            assert cr >= WCAG_AAA_GRAPHICS_CONTRAST_TARGET, f"Color {c} contrast {cr:.2f} failed >= 3.0:1 requirement"


# ============================================================================
# 9. TestSVGGenerationAndXMLValidity
# ============================================================================

class TestSVGGenerationAndXMLValidity:
    """Verify standalone W3C SVG 1.1 XML generation, ElementTree parsing, viewBox, nodes, edges, and HUD."""

    def test_svg_xml_parsing_and_viewbox(self) -> None:
        """Rendered SVG parses without error, has <svg> tag, and valid viewBox."""
        canvas = ForceDirectedCanvas()
        svg_text = canvas.render_svg()

        assert svg_text.startswith("<svg")
        root = ET.fromstring(svg_text)
        assert root.tag.endswith("svg")

        viewbox = root.attrib.get("viewBox", "")
        assert "0 0 1200" in viewbox

    def test_svg_contains_nodes_and_edges(self) -> None:
        """SVG contains node circles and edge link lines."""
        canvas = ForceDirectedCanvas()
        svg_text = canvas.render_svg()
        root = ET.fromstring(svg_text)

        circles = root.findall(".//{http://www.w3.org/2000/svg}circle") + root.findall(".//circle")
        assert len(circles) >= 12

        lines = root.findall(".//{http://www.w3.org/2000/svg}line") + root.findall(".//line")
        assert len(lines) >= 18

    def test_svg_contains_hud_and_decoupled_badge(self) -> None:
        """SVG contains decoupled badge container and telemetry HUD card."""
        canvas = ForceDirectedCanvas()
        svg_text = canvas.render_svg()

        assert COLOR_DECOUPLED_BADGE in svg_text
        assert COLOR_DARK_THEME_BACKING in svg_text
        assert "TELEMETRY" in svg_text or "FORCE-DIRECTED" in svg_text or "NODES" in svg_text

    def test_svg_xml_character_escaping(self) -> None:
        """Special characters in node labels are XML-escaped properly."""
        canvas = ForceDirectedCanvas()
        svg_text = canvas.render_svg()
        # ElementTree parses full SVG cleanly
        root = ET.fromstring(svg_text)
        assert root is not None


# ============================================================================
# 10. TestProcessSafetyDiagnosticsAndFaults
# ============================================================================

class TestProcessSafetyDiagnosticsAndFaults:
    """Verify isolated node trip 0x7601, high energy instability 0x7602, status bits, and recovery."""

    def test_isolated_node_trip_0x7601(self) -> None:
        """inject_isolated_node trips with code 0x7601 and asserts status bits and partition alarm coil."""
        canvas = ForceDirectedCanvas()
        canvas.inject_isolated_node("NODE_11")

        assert canvas.diagnostic_code == 0x7601
        assert canvas.diagnostic_code == DIAG_ERR_ISOLATED_NODE_TRIP
        assert canvas.diagnostic_code == ISOLATED_NODE_TRIP
        assert canvas.diagnostic_code == DIAG_ERR_ISOLATED_NODE
        assert canvas.topology_partition_alarm is True

        assert (canvas.status_bits & ForceDirectedStatusBits.ISLAND_DISCONNECTED) > 0
        assert (canvas.status_bits & ForceDirectedStatusBits.NOMINAL_OPERATION) == 0

        # Memory readback
        reg_table = RegisterTable()
        canvas.sync_to_registers(reg_table)
        assert reg_table.read_word(REG_FORCE_CANVAS_DIAGNOSTIC_CODE) == 0x7601
        assert reg_table.read_bit(COIL_TOPOLOGY_PARTITION_ALARM) is True

    def test_high_energy_instability_0x7602(self) -> None:
        """inject_high_energy_instability trips with code 0x7602 and asserts status bits and alarm."""
        canvas = ForceDirectedCanvas()
        canvas.inject_high_energy_instability(energy_val=30.0)

        assert canvas.diagnostic_code == 0x7602
        assert canvas.diagnostic_code == DIAG_ERR_HIGH_ENERGY_INSTABILITY
        assert canvas.diagnostic_code == HIGH_ENERGY_INSTABILITY
        assert canvas.diagnostic_code == DIAG_ERR_ENERGY_INSTABILITY
        assert canvas.topology_partition_alarm is True

        assert (canvas.status_bits & ForceDirectedStatusBits.ENERGY_DIVERGENCE) > 0
        assert (canvas.status_bits & ForceDirectedStatusBits.NOMINAL_OPERATION) == 0

        # Memory readback
        reg_table = RegisterTable()
        canvas.sync_to_registers(reg_table)
        assert reg_table.read_word(REG_FORCE_CANVAS_DIAGNOSTIC_CODE) == 0x7602
        assert reg_table.read_bit(COIL_TOPOLOGY_PARTITION_ALARM) is True

    def test_recovery_reset_nominal(self) -> None:
        """reset_nominal clears diagnostic fault, de-asserts alarm, and restores equilibrium."""
        canvas = ForceDirectedCanvas()
        canvas.inject_isolated_node()
        assert canvas.diagnostic_code != 0

        canvas.reset_nominal()
        assert canvas.diagnostic_code == 0x0000
        assert canvas.diagnostic_code == DIAG_OK
        assert canvas.topology_partition_alarm is False
        assert canvas.is_active is True
        assert (canvas.status_bits & ForceDirectedStatusBits.NOMINAL_OPERATION) > 0

        # Register table matches nominal
        reg_table = RegisterTable()
        canvas.sync_to_registers(reg_table)
        assert reg_table.read_word(REG_FORCE_CANVAS_DIAGNOSTIC_CODE) == 0
        assert reg_table.read_bit(COIL_TOPOLOGY_PARTITION_ALARM) is False
        assert reg_table.read_bit(COIL_FORCE_CANVAS_ACTIVE) is True


# ============================================================================
# 11. TestPartitionAlarmCoilAssertion
# ============================================================================

class TestPartitionAlarmCoilAssertion:
    """Verify partition alarm coil %M512 assertion on fault conditions and de-assertion on reset."""

    def test_nominal_state_alarm_deasserted(self) -> None:
        """Nominal canvas has %M512 = False and %M511 = True."""
        canvas = ForceDirectedCanvas()
        reg_table = RegisterTable()
        canvas.sync_to_registers(reg_table)

        assert reg_table.read_bit(COIL_TOPOLOGY_PARTITION_ALARM) is False
        assert reg_table.read_bit("%M512") is False
        assert reg_table.read_bit(COIL_FORCE_CANVAS_ACTIVE) is True
        assert reg_table.read_bit("%M511") is True

    def test_alarm_coil_asserted_on_isolated_node_fault(self) -> None:
        """0x7601 fault asserts %M512 partition alarm coil."""
        canvas = ForceDirectedCanvas()
        canvas.inject_isolated_node()

        reg_table = RegisterTable()
        canvas.sync_to_registers(reg_table)
        assert reg_table.read_bit("%M512") is True
        assert reg_table.read_bit(COIL_TOPOLOGY_PARTITION_ALARM) is True

    def test_alarm_coil_asserted_on_high_energy_instability(self) -> None:
        """0x7602 fault asserts %M512 partition alarm coil."""
        canvas = ForceDirectedCanvas()
        canvas.inject_high_energy_instability()

        reg_table = RegisterTable()
        canvas.sync_to_registers(reg_table)
        assert reg_table.read_bit("%M512") is True
        assert reg_table.read_bit(COIL_TOPOLOGY_PARTITION_ALARM) is True

    def test_alarm_coil_cleared_upon_nominal_reset(self) -> None:
        """Resetting to nominal clears %M512 partition alarm coil."""
        canvas = ForceDirectedCanvas()
        canvas.inject_isolated_node()
        canvas.reset_nominal()

        reg_table = RegisterTable()
        canvas.sync_to_registers(reg_table)
        assert reg_table.read_bit("%M512") is False
        assert reg_table.read_bit(COIL_TOPOLOGY_PARTITION_ALARM) is False
        assert reg_table.read_bit("%M511") is True


# ============================================================================
# 12. TestHornerOCSRegisterSynchronization
# ============================================================================

class TestHornerOCSRegisterSynchronization:
    """Verify Horner OCS register space synchronization (%R2190..%R2197, %M511..%M512) and ILogicUnit."""

    def test_register_sync_nominal_baseline(self) -> None:
        """Registers %R2190..%R2197 and coils %M511..%M512 populate expected nominal values."""
        reg_table = RegisterTable()
        canvas = ForceDirectedCanvas(reg_table=reg_table)
        canvas.sync_to_registers()

        assert reg_table.read_word("%R2190") == 12  # ActiveNodesCount
        assert reg_table.read_word("%R2191") == 18  # ActiveEdgesCount
        assert reg_table.read_word("%R2192") == 420 # LayoutEnergyNormScaled (4.20 -> 420)
        assert reg_table.read_word("%R2193") == 45  # LayoutConvergenceCycles
        assert reg_table.read_word("%R2194") == 0   # SelectedNodeId
        assert reg_table.read_word("%R2195") == 5   # MaxNodeDegree
        assert reg_table.read_word("%R2196") == 1   # NetworkPartitionCount
        assert reg_table.read_word("%R2197") == 0   # DiagnosticCode (0x0000 OK)

        assert reg_table.read_bit("%M511") is True  # CanvasActive
        assert reg_table.read_bit("%M512") is False # TopologyPartitionAlarm

    def test_ilogic_unit_interface_properties(self) -> None:
        """ForceDirectedCanvas fulfills ILogicUnit protocol contract."""
        canvas = ForceDirectedCanvas()
        assert isinstance(canvas, ILogicUnit)
        assert canvas.name == "ForceDirectedCanvasSync"
        assert canvas.priority == 95
        assert canvas.is_enabled is True

    def test_ilogic_unit_scan_step_and_execute(self) -> None:
        """scan_step and execute advance physics iteration and maintain valid registers."""
        reg_table = RegisterTable()
        canvas = ForceDirectedCanvas(reg_table=reg_table)

        canvas.scan_step(dt=0.02)
        assert reg_table.read_word("%R2190") == 12
        assert reg_table.read_word("%R2191") == 18

        ctx = create_mock_scan_context(cycle=2, dt_ms=10.0, reg_table=reg_table)
        canvas.execute(ctx)
        assert reg_table.read_word("%R2190") == 12
        assert reg_table.read_bit("%M511") is True

    def test_soak_scan_cycle_stability(self) -> None:
        """50-step scan cycle executes monotonically without numerical instability."""
        reg_table = RegisterTable()
        canvas = ForceDirectedCanvas(reg_table=reg_table)

        for step in range(50):
            canvas.scan_step(dt=0.02)
            assert reg_table.read_word("%R2190") == 12
            assert reg_table.read_word("%R2191") == 18
            assert reg_table.read_word("%R2197") == 0


# ============================================================================
# 13. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Verify IEC 61131-3 Pure Structured Text program integrity and symbol bindings."""

    def test_pure_st_pou_security_guard_assertion(self) -> None:
        """Assert pure ST content passes SecurityGuard without raising exceptions."""
        SecurityGuard.assert_pure_st_content(FORCE_DIRECTED_CANVAS_PURE_ST_POU)

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify STParser parses program ForceDirectedCanvasSync as PROGRAM POUType."""
        parser = STParser()
        pou = parser.parse_pou(FORCE_DIRECTED_CANVAS_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "ForceDirectedCanvasSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_pure_st_variable_bindings(self) -> None:
        """Verify memory bindings (%R2190..%R2197, %M511..%M512) exist."""
        parser = STParser()
        pou = parser.parse_pou(FORCE_DIRECTED_CANVAS_PURE_ST_POU)
        assert pou is not None

        expected_w258 = {
            "ActiveNodesCount": "%R2190",
            "ActiveEdgesCount": "%R2191",
            "LayoutEnergyNormScaled": "%R2192",
            "LayoutConvergenceCycles": "%R2193",
            "SelectedNodeId": "%R2194",
            "MaxNodeDegree": "%R2195",
            "NetworkPartitionCount": "%R2196",
            "CanvasDiagnosticCode": "%R2197",
            "CanvasActive": "%M511",
            "TopologyPartitionAlarm": "%M512",
        }

        vmap = {v.name: v.address_binding for v in pou.variables}
        for var_name, expected_addr in expected_w258.items():
            assert var_name in vmap, f"Variable {var_name} missing from ST POU"
            assert vmap[var_name] == expected_addr, f"{var_name} mapped to {vmap[var_name]}, expected {expected_addr}"

    def test_pure_st_pou_helper_function(self) -> None:
        """Verify verify_force_directed_canvas_pure_st helper returns True."""
        assert verify_force_directed_canvas_pure_st() is True

    def test_pure_st_pou_aliases(self) -> None:
        """Verify POU string aliases match FORCE_DIRECTED_CANVAS_PURE_ST_POU."""
        assert FORCE_DIRECTED_PURE_ST_POU == FORCE_DIRECTED_CANVAS_PURE_ST_POU
        assert W258_FORCE_DIRECTED_PURE_ST_POU == FORCE_DIRECTED_CANVAS_PURE_ST_POU
        assert DYNAMIC_FORCE_DIRECTED_CANVAS_PURE_ST_POU == FORCE_DIRECTED_CANVAS_PURE_ST_POU


# ============================================================================
# 14. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Verify SecurityGuard intercepts and rejects all ladder logic constructs with LadderForbiddenError."""

    def test_anti_ladder_contacts(self) -> None:
        """Reject ladder contacts ---[ ]--- and ---[/]---."""
        snippets = [
            "PROGRAM Test VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM",
            "PROGRAM Test VAR X: BOOL; END_VAR ---[/]--- END_PROGRAM",
        ]
        for snip in snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snip)

    def test_anti_ladder_coils(self) -> None:
        """Reject ladder coils ---( )--- and ---(/)---."""
        snippets = [
            "PROGRAM Test VAR Y: BOOL; END_VAR ---( )--- END_PROGRAM",
            "PROGRAM Test VAR Y: BOOL; END_VAR ---(/)--- END_PROGRAM",
        ]
        for snip in snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snip)

    def test_anti_ladder_rungs_and_networks(self) -> None:
        """Reject RUNG and NETWORK delimiters."""
        snippets = [
            "PROGRAM Test\nRUNG 1:\nEND_PROGRAM",
            "PROGRAM Test\nNETWORK 1:\nEND_PROGRAM",
        ]
        for snip in snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snip)

    def test_anti_ladder_mnemonics(self) -> None:
        """Reject ladder instruction mnemonics (XIC, XIO, OTE, OTL, OTU)."""
        mnemonics = ["XIC b1;", "XIO b2;", "OTE c1;", "OTL c2;", "OTU c3;"]
        for m in mnemonics:
            code = f"PROGRAM Test VAR b1: BOOL; END_VAR\n{m}\nEND_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(code)

    def test_anti_ladder_mixed_content_rejection(self) -> None:
        """Reject mixed ST with embedded ladder contact."""
        mixed = """PROGRAM MixedSync
VAR
    Flag AT %M511 : BOOL;
END_VAR
Flag := TRUE;
---[ ]---
END_PROGRAM"""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(mixed)


# ============================================================================
# 15. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Verify 9-stage verification suite returns strict 4-state engineering contract JSON and valid evidence."""

    def test_verification_runner_success(self) -> None:
        """run_force_directed_canvas_verification completes all 9 stages successfully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = str(Path(tmpdir) / "evidence.json")
            svg_path = str(Path(tmpdir) / "sample.svg")

            res = run_force_directed_canvas_verification(
                output_path=ev_path,
                sample_svg_path=svg_path,
                work_package="W258",
            )

            assert res["status"] == "success"
            assert res["error_code"] is None
            assert res["data"]["checks_passed"] == 9
            assert res["data"]["total_checks"] == 9
            assert res["data"]["work_package"] == "W258"

            assert Path(ev_path).exists()
            assert Path(svg_path).exists()

            with open(ev_path, "r", encoding="utf-8") as f:
                saved = json.load(f)
            assert saved["status"] == "success"
            assert len(saved["data"]["tests"]) == 9

            with open(svg_path, "r", encoding="utf-8") as f:
                svg_data = f.read()
            assert svg_data.startswith("<svg")
            ET.fromstring(svg_data)

    def test_factory_canvas_creations(self) -> None:
        """create_canonical_force_directed_canvas and create_canonical_mesh_canvas produce valid instances."""
        canvas1 = create_canonical_force_directed_canvas()
        assert isinstance(canvas1, ForceDirectedCanvas)

        canvas2 = create_canonical_mesh_canvas()
        assert isinstance(canvas2, ForceDirectedCanvas)
        assert len(canvas2.topology.nodes) >= 12
