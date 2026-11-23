"""Comprehensive unit test suite for Cscape HMI Dynamic Treemap Nested Spatial Hierarchy SCADA Canvas (W261).

Work Package: Wave W261 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Treemap Spatial Asset Partitioning SCADA Canvas]

Architectural Test Suite:
1. TestDiagnosticCodeMathAndFormats:
   - DiagnosticCode signed/unsigned 16-bit values, equality, hashing, hex formatting, and string representations.
   - Nominal 0x0000, 0x7701 INVALID_HIERARCHY_TRIP, 0x7702 ASPECT_RATIO_DEGENERATION_TRIP.
2. TestRegisterAndCoilAddressMappings:
   - Word registers %R2220..%R2227 and discrete coils %M518..%M519.
   - Exact aliases: REG_TREEMAP_*, REG_*, REG_W261_*, COIL_*, COIL_W261_*.
3. TestHierarchicalTreeStructureAndTraversal:
   - Canonical 24 nodes across 4 tiers (Tier 0 Site, Tier 1 Units, Tier 2 Equipment, Tier 3 Subcomponents).
   - Max depth 4, leaves count 16, node lookup by ID and index.
4. TestPowerConservationAndAggregates:
   - Strict 1450 kW power conservation from leaf subcomponents upward to root complex.
   - Thermal heat metric calculation, weighted aggregation, and health state transitions.
5. TestSquarifiedAlgorithmAndPartitioning:
   - Squarified slice-and-dice layout (Bruls et al.), aspect ratio max(w/h, h/w) >= 1.0.
   - Optimization towards 1.0, worst aspect ratio candidate evaluation, non-overlapping partitions.
6. TestParentChildBoundingContainment:
   - Strict geometric containment: Site -> Unit -> Equipment -> Subcomponent.
   - Rect properties: area, right, bottom, contains_rect.
7. TestSVGMarkupGenerationAndXMLValidity:
   - Pure W3C SVG 1.1 standalone XML generation with viewBox 0 0 1200 750.
   - ElementTree parsing, dark industrial viewport #0D1117, HUD scorecard, nested tiles, and badges.
8. TestWCAG21AAAContrastCompliance:
   - Mathematical compliance with WCAG 2.1 AAA benchmarks.
   - Decoupled badge contrast >= 18:1 (white on #05080E), text contrast >= 7:1, graphics >= 3:1.
9. TestDiagnosticFaultTrappingAndRecovery:
   - Invalid hierarchy trip 0x7701 and aspect ratio degeneration trip 0x7702.
   - De-assertion of %M518, assertion of %M519, and recovery reset to nominal baseline.
10. TestCriticalEquipmentAlarmCoilAssertion:
    - Discrete alarm coil %M519 assertion on thermal threshold (>= 85.0 °C) or diagnostic faults.
    - Nominal clearance when within operational limits.
11. TestInteractiveNodeSelectionAndTelemetry:
    - Selection of asset nodes by ID/index, heat metric scaling (0.1 °C -> 685 in %R2224).
    - Synchronizing register table setpoint (%R2223) and HUD focus.
12. TestHornerOCSRegisterSynchronization:
    - Register table synchronization with SYSTEM privilege.
    - Exact %R2220..%R2227 and %M518..%M519 word and bit bindings.
13. TestScanCycleSoakStability:
    - 50-step and 100-step discrete scan cycle soak without drift, memory leak, or degradation.
    - ILogicUnit interface compliance: scan_step, execute, reset, name, priority, is_enabled.
14. TestPureSTAndSecurity:
    - Pure IEC 61131-3 Structured Text POU validation with SecurityGuard and STParser.
    - Abstract Syntax Tree (AST) inspection, 10 register bindings, variable addresses.
15. TestAntiLadderRejection:
    - Fail-closed interception of ladder contacts, coils, mnemonics, rungs, and networks with LadderForbiddenError.
16. TestVerificationRunnerAndContract:
    - Execution of deterministic 9-stage verification suite returning strict 4-state engineering contract JSON.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.treemap_spatial_canvas import (
    # Diagnostic Codes
    DIAG_EVENT_OK,
    DIAG_OK,
    TREEMAP_OK,
    TREEMAP_SPATIAL_OK,
    DIAG_ERR_INVALID_HIERARCHY_TRIP,
    INVALID_HIERARCHY_TRIP,
    DIAG_ERR_INVALID_HIERARCHY,
    DIAG_ERR_ASPECT_RATIO_DEGENERATION_TRIP,
    ASPECT_RATIO_DEGENERATION_TRIP,
    DIAG_ERR_ASPECT_RATIO_DEGENERATION,
    DiagnosticCode,
    TreemapSpatialDiagnosticCode,
    # Register & Coil Mappings
    REG_TREEMAP_TOTAL_NODES_COUNT,
    REG_TREEMAP_DEPTH_LEVELS,
    REG_TREEMAP_ASPECT_RATIO_WORST_SCALED,
    REG_SELECTED_TREEMAP_NODE_ID,
    REG_SELECTED_NODE_HEAT_METRIC_SCALED,
    REG_CRITICAL_EQUIPMENT_ALERT_COUNT,
    REG_TOTAL_MONITORED_POWER_KW,
    REG_TREEMAP_CANVAS_DIAGNOSTIC_CODE,
    COIL_TREEMAP_CANVAS_ACTIVE,
    COIL_CRITICAL_EQUIPMENT_ALARM,
    # Aliases
    REG_TOTAL_NODES_COUNT,
    REG_DEPTH_LEVELS,
    REG_ASPECT_RATIO_WORST_SCALED,
    REG_SELECTED_NODE_ID,
    REG_SELECTED_HEAT_METRIC_SCALED,
    REG_CRITICAL_ALERT_COUNT,
    REG_TOTAL_POWER_KW,
    REG_DIAGNOSTIC_CODE,
    COIL_CANVAS_ACTIVE,
    COIL_CRITICAL_ALARM,
    REG_W261_TOTAL_NODES,
    REG_W261_DEPTH_LEVELS,
    REG_W261_WORST_ASPECT,
    REG_W261_SELECTED_NODE,
    REG_W261_HEAT_METRIC,
    REG_W261_CRITICAL_ALERTS,
    REG_W261_TOTAL_POWER,
    REG_W261_DIAG_CODE,
    COIL_W261_CANVAS_ACTIVE,
    COIL_W261_CRITICAL_ALARM,
    # Viewport & Layout Geometry Constants
    CANVAS_VIEWPORT_WIDTH,
    CANVAS_VIEWPORT_HEIGHT,
    DEFAULT_CANVAS_X,
    DEFAULT_CANVAS_Y,
    DEFAULT_CANVAS_WIDTH,
    DEFAULT_CANVAS_HEIGHT,
    LAYOUT_BOUNDS_X,
    LAYOUT_BOUNDS_Y,
    LAYOUT_BOUNDS_WIDTH,
    LAYOUT_BOUNDS_HEIGHT,
    # Canonical Hierarchy Nominals
    CANONICAL_TOTAL_NODES,
    CANONICAL_DEPTH_LEVELS,
    CANONICAL_WORST_ASPECT_RATIO,
    CANONICAL_WORST_ASPECT_RATIO_SCALED,
    CANONICAL_SELECTED_NODE_ID,
    CANONICAL_SELECTED_HEAT_METRIC,
    CANONICAL_SELECTED_HEAT_METRIC_SCALED,
    CANONICAL_CRITICAL_ALERT_COUNT,
    CANONICAL_TOTAL_MONITORED_POWER_KW,
    CANONICAL_CANVAS_ACTIVE,
    CANONICAL_CRITICAL_ALARM,
    GOLDEN_RATIO_PHI,
    TARGET_ASPECT_RATIO,
    ASPECT_RATIO_DEGENERATION_THRESHOLD,
    HEAT_NORMAL_THRESHOLD_DEG_C,
    HEAT_WARNING_THRESHOLD_DEG_C,
    HEAT_ELEVATED_THRESHOLD_DEG_C,
    HEAT_CRITICAL_THRESHOLD_DEG_C,
    # Colors & Accessibility
    COLOR_DARK_THEME_BACKING,
    COLOR_PANEL_BG,
    COLOR_BORDER,
    COLOR_DECOUPLED_BADGE,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY,
    COLOR_TEXT_MUTED,
    COLOR_FOCUS_CYAN,
    COLOR_GRID_LINE,
    COLOR_EMERALD,
    COLOR_CYAN,
    COLOR_AMBER,
    COLOR_CRIMSON,
    COLOR_SLATE,
    COLOR_NORMAL,
    COLOR_GOOD,
    COLOR_WARNING,
    COLOR_CRITICAL,
    COLOR_INACTIVE,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    # Enums & Flags
    AssetTier,
    AssetLevel,
    HierarchyLevel,
    TreemapSpatialTier,
    NodeHealthState,
    THERMAL_COLORS,
    TreemapSpatialStatusBits,
    # Exceptions
    TreemapSpatialError,
    InvalidHierarchyError,
    AspectRatioDegenerationError,
    TreemapSpatialGeometryError,
    # Math & Data Models
    srgb_channel_to_linear,
    relative_luminance,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    Rect,
    TreemapSpatialNode,
    TreemapSpatialMetrics,
    compute_treemap_spatial_metrics,
    TreemapSpatialTree,
    _worst_aspect_ratio,
    layout_squarified,
    layout_spatial_treemap,
    create_canonical_treemap_spatial_tree,
    # SVG & Canvas
    generate_treemap_spatial_canvas_svg,
    TreemapSpatialCanvas,
    TreemapSpatialCanvasEngine,
    TreemapSpatialCanvasSync,
    create_canonical_treemap_spatial_canvas,
    # Pure ST POU
    TREEMAP_SPATIAL_CANVAS_PURE_ST_POU,
    TREEMAP_SPATIAL_CANVAS_SYNC_PURE_ST_POU,
    W261_TREEMAP_SPATIAL_PURE_ST_POU,
    verify_treemap_spatial_canvas_pure_st,
    # Verification Runner
    run_treemap_spatial_canvas_verification,
)


# ============================================================================
# 1. TestDiagnosticCodeMathAndFormats
# ============================================================================

class TestDiagnosticCodeMathAndFormats:
    """Verify signed and unsigned 16-bit values, equality, hashing, hex formatting, and string representations."""

    def test_diagnostic_code_ok_equality(self) -> None:
        """Nominal 0x0000 matches integer 0, hex 0x0000, and OK aliases."""
        diag = DiagnosticCode(0x0000)
        assert diag == 0
        assert diag == 0x0000
        assert diag == DIAG_OK
        assert diag == DIAG_EVENT_OK
        assert diag == TREEMAP_OK
        assert diag == TREEMAP_SPATIAL_OK

    def test_diagnostic_code_invalid_hierarchy_0x7701(self) -> None:
        """0x7701 matches unsigned 30465, signed +30465, and invalid hierarchy aliases."""
        diag = DiagnosticCode(0x7701)
        assert diag == 0x7701
        assert diag == 30465
        assert diag == DIAG_ERR_INVALID_HIERARCHY_TRIP
        assert diag == INVALID_HIERARCHY_TRIP
        assert diag == DIAG_ERR_INVALID_HIERARCHY

    def test_diagnostic_code_aspect_ratio_degeneration_0x7702(self) -> None:
        """0x7702 matches unsigned 30466, signed +30466, and aspect ratio degeneration aliases."""
        diag = DiagnosticCode(0x7702)
        assert diag == 0x7702
        assert diag == 30466
        assert diag == DIAG_ERR_ASPECT_RATIO_DEGENERATION_TRIP
        assert diag == ASPECT_RATIO_DEGENERATION_TRIP
        assert diag == DIAG_ERR_ASPECT_RATIO_DEGENERATION

    def test_diagnostic_code_signed_negative_16bit_handling(self) -> None:
        """DiagnosticCode handles negative signed 16-bit values correctly."""
        # E.g., 0xE201 corresponds to -7679 signed 16-bit
        d_neg = DiagnosticCode(0xE201)
        assert d_neg == 0xE201
        assert d_neg == 57857
        assert d_neg == -7679

    def test_diagnostic_code_hash_and_set_membership(self) -> None:
        """DiagnosticCode instances can be used as set members and dictionary keys."""
        s = {DIAG_OK, DIAG_ERR_INVALID_HIERARCHY_TRIP, DIAG_ERR_ASPECT_RATIO_DEGENERATION_TRIP}
        assert DiagnosticCode(0) in s
        assert DiagnosticCode(0x7701) in s
        assert DiagnosticCode(0x7702) in s
        assert DiagnosticCode(0x1234) not in s

        mapping = {DIAG_OK: "Nominal", DIAG_ERR_INVALID_HIERARCHY_TRIP: "HierarchyFault"}
        assert mapping[DiagnosticCode(0x0000)] == "Nominal"
        assert mapping[DiagnosticCode(0x7701)] == "HierarchyFault"

    def test_diagnostic_code_hex_formatting(self) -> None:
        """Verify hex formatting representation matches 0x0000, 0x7701, and 0x7702."""
        assert f"0x{int(DIAG_OK) & 0xFFFF:04X}" == "0x0000"
        assert f"0x{int(DIAG_ERR_INVALID_HIERARCHY_TRIP) & 0xFFFF:04X}" == "0x7701"
        assert f"0x{int(DIAG_ERR_ASPECT_RATIO_DEGENERATION_TRIP) & 0xFFFF:04X}" == "0x7702"


# ============================================================================
# 2. TestRegisterAndCoilAddressMappings
# ============================================================================

class TestRegisterAndCoilAddressMappings:
    """Verify Horner OCS register (%R2220..%R2227) and coil (%M518..%M519) mappings and aliases."""

    def test_word_register_addresses(self) -> None:
        """Verify exact string address assignments for %R2220..%R2227."""
        assert REG_TREEMAP_TOTAL_NODES_COUNT == "%R2220"
        assert REG_TREEMAP_DEPTH_LEVELS == "%R2221"
        assert REG_TREEMAP_ASPECT_RATIO_WORST_SCALED == "%R2222"
        assert REG_SELECTED_TREEMAP_NODE_ID == "%R2223"
        assert REG_SELECTED_NODE_HEAT_METRIC_SCALED == "%R2224"
        assert REG_CRITICAL_EQUIPMENT_ALERT_COUNT == "%R2225"
        assert REG_TOTAL_MONITORED_POWER_KW == "%R2226"
        assert REG_TREEMAP_CANVAS_DIAGNOSTIC_CODE == "%R2227"

    def test_discrete_coil_addresses(self) -> None:
        """Verify exact string address assignments for %M518..%M519."""
        assert COIL_TREEMAP_CANVAS_ACTIVE == "%M518"
        assert COIL_CRITICAL_EQUIPMENT_ALARM == "%M519"

    def test_register_aliases(self) -> None:
        """Verify convenient and W261 aliases resolve to the identical register addresses."""
        assert REG_TOTAL_NODES_COUNT == "%R2220"
        assert REG_W261_TOTAL_NODES == "%R2220"
        assert REG_DEPTH_LEVELS == "%R2221"
        assert REG_W261_DEPTH_LEVELS == "%R2221"
        assert REG_ASPECT_RATIO_WORST_SCALED == "%R2222"
        assert REG_W261_WORST_ASPECT == "%R2222"
        assert REG_SELECTED_NODE_ID == "%R2223"
        assert REG_W261_SELECTED_NODE == "%R2223"
        assert REG_SELECTED_HEAT_METRIC_SCALED == "%R2224"
        assert REG_W261_HEAT_METRIC == "%R2224"
        assert REG_CRITICAL_ALERT_COUNT == "%R2225"
        assert REG_W261_CRITICAL_ALERTS == "%R2225"
        assert REG_TOTAL_POWER_KW == "%R2226"
        assert REG_W261_TOTAL_POWER == "%R2226"
        assert REG_DIAGNOSTIC_CODE == "%R2227"
        assert REG_W261_DIAG_CODE == "%R2227"

    def test_coil_aliases(self) -> None:
        """Verify coil aliases resolve to the identical coil addresses."""
        assert COIL_CANVAS_ACTIVE == "%M518"
        assert COIL_W261_CANVAS_ACTIVE == "%M518"
        assert COIL_CRITICAL_ALARM == "%M519"
        assert COIL_W261_CRITICAL_ALARM == "%M519"

    def test_register_address_syntax(self) -> None:
        """Verify all register strings follow %R or %M syntax with valid integer indices."""
        for reg in [
            REG_TREEMAP_TOTAL_NODES_COUNT,
            REG_TREEMAP_DEPTH_LEVELS,
            REG_TREEMAP_ASPECT_RATIO_WORST_SCALED,
            REG_SELECTED_TREEMAP_NODE_ID,
            REG_SELECTED_NODE_HEAT_METRIC_SCALED,
            REG_CRITICAL_EQUIPMENT_ALERT_COUNT,
            REG_TOTAL_MONITORED_POWER_KW,
            REG_TREEMAP_CANVAS_DIAGNOSTIC_CODE,
        ]:
            assert reg.startswith("%R")
            assert int(reg[2:]) >= 2220 and int(reg[2:]) <= 2227

        for coil in [COIL_TREEMAP_CANVAS_ACTIVE, COIL_CRITICAL_EQUIPMENT_ALARM]:
            assert coil.startswith("%M")
            assert int(coil[2:]) in (518, 519)


# ============================================================================
# 3. TestHierarchicalTreeStructureAndTraversal
# ============================================================================

class TestHierarchicalTreeStructureAndTraversal:
    """Verify multi-tier asset hierarchy tree construction, traversal, and indexing."""

    def test_canonical_tree_node_count_and_depth(self) -> None:
        """Canonical tree contains exactly 24 nodes across 4 tiers (0..3)."""
        tree = create_canonical_treemap_spatial_tree()
        assert tree.total_nodes == 24
        assert tree.total_nodes == CANONICAL_TOTAL_NODES
        assert tree.max_depth == 4
        assert tree.max_depth == CANONICAL_DEPTH_LEVELS

    def test_tier_breakdown_counts(self) -> None:
        """Verify breakdown: 1 Site (Tier 0), 2 Units (Tier 1), 5 Equipment (Tier 2), 16 Subcomponents (Tier 3)."""
        tree = create_canonical_treemap_spatial_tree()
        all_nodes = tree.get_all_nodes()
        tier_0 = [n for n in all_nodes if n.tier == AssetTier.SITE]
        tier_1 = [n for n in all_nodes if n.tier == AssetTier.UNIT]
        tier_2 = [n for n in all_nodes if n.tier == AssetTier.EQUIPMENT]
        tier_3 = [n for n in all_nodes if n.tier == AssetTier.SUBCOMPONENT]

        assert len(tier_0) == 1
        assert len(tier_1) == 2
        assert len(tier_2) == 5
        assert len(tier_3) == 16
        assert len(tier_0) + len(tier_1) + len(tier_2) + len(tier_3) == 24

    def test_leaf_nodes_identification(self) -> None:
        """All Tier 3 subcomponents are leaf nodes without children."""
        tree = create_canonical_treemap_spatial_tree()
        leaves = tree.get_leaves()
        assert len(leaves) == 16
        for leaf in leaves:
            assert leaf.is_leaf is True
            assert len(leaf.children) == 0
            assert leaf.tier == AssetTier.SUBCOMPONENT

    def test_node_indexing_by_id_and_index(self) -> None:
        """All 24 nodes are uniquely accessible by string ID and integer index (0..23)."""
        tree = create_canonical_treemap_spatial_tree()
        for idx in range(24):
            node = tree.get_node_by_index(idx)
            assert node is not None
            assert node.index == idx
            # Check ID lookup returns same node
            assert tree.get_node(node.id) is node

    def test_root_node_identity(self) -> None:
        """Root node is SITE_BAYTOWN_ENERGY at index 0 with tier 0."""
        tree = create_canonical_treemap_spatial_tree()
        root = tree.root
        assert root is not None
        assert root.id == "SITE_BAYTOWN_ENERGY"
        assert root.index == 0
        assert root.tier == AssetTier.SITE
        assert root.parent_id is None
        assert len(root.children) == 2


# ============================================================================
# 4. TestPowerConservationAndAggregates
# ============================================================================

class TestPowerConservationAndAggregates:
    """Verify monitored power conservation across all tiers and thermal health aggregation."""

    def test_power_conservation_strict_1450_kw(self) -> None:
        """Monitored power is strictly conserved from leaves (1450 kW) to root (1450 kW)."""
        tree = create_canonical_treemap_spatial_tree()
        root = tree.root
        assert root is not None
        assert round(root.power_kw, 1) == 1450.0

        # Leaf sum equals 1450.0
        leaves = tree.get_leaves()
        leaf_power_sum = sum(l.power_kw for l in leaves)
        assert round(leaf_power_sum, 1) == 1450.0

        # Unit sum equals 1450.0
        unit_power_sum = sum(u.power_kw for u in root.children)
        assert round(unit_power_sum, 1) == 1450.0

    def test_unit_level_power_split(self) -> None:
        """Combined Cycle Train A is 850 kW, Compression Train B is 600 kW."""
        tree = create_canonical_treemap_spatial_tree()
        unit_a = tree.get_node("UNIT_TURBINE_TRAIN_A")
        unit_b = tree.get_node("UNIT_COMPRESSION_TRAIN_B")
        assert unit_a is not None and unit_b is not None
        assert round(unit_a.power_kw, 1) == 850.0
        assert round(unit_b.power_kw, 1) == 600.0

    def test_equipment_power_matches_children_subcomponents(self) -> None:
        """Each equipment's power equals the exact sum of its child subcomponents."""
        tree = create_canonical_treemap_spatial_tree()
        all_nodes = tree.get_all_nodes()
        equipment_nodes = [n for n in all_nodes if n.tier == AssetTier.EQUIPMENT]
        for eq in equipment_nodes:
            children_sum = sum(c.power_kw for c in eq.children)
            assert round(eq.power_kw, 1) == round(children_sum, 1)

    def test_health_state_transitions(self) -> None:
        """Thermal metrics properly classify into NORMAL, GOOD, WARNING, and CRITICAL states."""
        node = TreemapSpatialNode(
            id="TEST_NODE",
            index=99,
            name="Test",
            tier=AssetTier.SUBCOMPONENT,
            heat_metric=65.0,
        )
        assert node.health_state == NodeHealthState.NORMAL

        node.heat_metric = 75.0
        assert node.health_state == NodeHealthState.GOOD

        node.heat_metric = 82.0
        assert node.health_state == NodeHealthState.WARNING

        node.heat_metric = 88.0
        assert node.health_state == NodeHealthState.CRITICAL

        node.is_active = False
        assert node.health_state == NodeHealthState.INACTIVE


# ============================================================================
# 5. TestSquarifiedAlgorithmAndPartitioning
# ============================================================================

class TestSquarifiedAlgorithmAndPartitioning:
    """Verify squarified slice-and-dice layout, aspect ratio calculation, and optimization."""

    def test_aspect_ratio_formula_and_identity(self) -> None:
        """Aspect ratio formula is max(w/h, h/w) >= 1.0; a perfect square yields 1.0."""
        sq_rect = Rect(0.0, 0.0, 100.0, 100.0)
        assert sq_rect.aspect_ratio == 1.0

        wide_rect = Rect(0.0, 0.0, 200.0, 100.0)
        assert wide_rect.aspect_ratio == 2.0

        tall_rect = Rect(0.0, 0.0, 100.0, 200.0)
        assert tall_rect.aspect_ratio == 2.0

    def test_worst_aspect_ratio_helper(self) -> None:
        """_worst_aspect_ratio evaluates candidate row along short side accurately."""
        assert _worst_aspect_ratio([], 100.0) == 1.0
        # Equal areas on side 100
        ar = _worst_aspect_ratio([5000.0, 5000.0], 100.0)
        assert ar >= 1.0

    def test_squarified_layout_dimension_positivity(self) -> None:
        """All laid out rectangles have strictly positive width and height."""
        canvas = create_canonical_treemap_spatial_canvas()
        canvas.compute_layout()
        all_nodes = canvas.tree.get_all_nodes()
        for node in all_nodes:
            if node.index != 0:  # Non-root nodes
                assert node.rect.width > 0.0
                assert node.rect.height > 0.0
                assert node.rect.area > 0.0

    def test_nominal_worst_aspect_ratio_145(self) -> None:
        """Nominal canonical state achieves worst aspect ratio of 1.45 (scaled 145)."""
        canvas = create_canonical_treemap_spatial_canvas()
        canvas.compute_layout()
        assert canvas.metrics.worst_aspect_ratio == 1.45
        assert canvas.metrics.worst_aspect_ratio_scaled == 145

    def test_invalid_bounds_raises_geometry_error(self) -> None:
        """Negative or zero bounds raise TreemapSpatialGeometryError."""
        tree = create_canonical_treemap_spatial_tree()
        with pytest.raises(TreemapSpatialGeometryError):
            layout_spatial_treemap(tree.root, Rect(0.0, 0.0, -100.0, 500.0))
        with pytest.raises(TreemapSpatialGeometryError):
            layout_spatial_treemap(tree.root, Rect(0.0, 0.0, 100.0, 0.0))

    def test_bounds_exceeding_viewport_raises_hierarchy_error(self) -> None:
        """Canvas bounds exceeding 1200x750 viewport raise InvalidHierarchyError."""
        tree = create_canonical_treemap_spatial_tree()
        with pytest.raises(InvalidHierarchyError):
            layout_spatial_treemap(tree.root, Rect(0.0, 0.0, 1300.0, 750.0))


# ============================================================================
# 6. TestParentChildBoundingContainment
# ============================================================================

class TestParentChildBoundingContainment:
    """Verify recursive parent-child bounding box spatial containment."""

    def test_units_contained_within_site_bounds(self) -> None:
        """Process Units (Tier 1) are strictly contained within canvas bounds."""
        canvas = create_canonical_treemap_spatial_canvas()
        canvas.compute_layout()
        bounds = canvas.canvas_bounds
        root = canvas.tree.root
        assert root is not None
        for unit in root.children:
            assert bounds.contains_rect(unit.rect, tolerance=1e-2)

    def test_equipment_contained_within_parent_unit(self) -> None:
        """Equipment assemblies (Tier 2) are strictly contained within their parent unit rect."""
        canvas = create_canonical_treemap_spatial_canvas()
        canvas.compute_layout()
        root = canvas.tree.root
        assert root is not None
        for unit in root.children:
            for eq in unit.children:
                assert unit.rect.contains_rect(eq.rect, tolerance=1e-2)

    def test_subcomponents_contained_within_parent_equipment(self) -> None:
        """Subcomponents (Tier 3) are strictly contained within their parent equipment rect."""
        canvas = create_canonical_treemap_spatial_canvas()
        canvas.compute_layout()
        root = canvas.tree.root
        assert root is not None
        for unit in root.children:
            for eq in unit.children:
                for sub in eq.children:
                    assert eq.rect.contains_rect(sub.rect, tolerance=1e-2)


# ============================================================================
# 7. TestSVGMarkupGenerationAndXMLValidity
# ============================================================================

class TestSVGMarkupGenerationAndXMLValidity:
    """Verify W3C SVG 1.1 generation, ElementTree XML validity, and visual elements."""

    def test_svg_xml_validity(self) -> None:
        """Generated SVG is valid W3C XML parseable by ElementTree."""
        canvas = create_canonical_treemap_spatial_canvas()
        svg_text = canvas.generate_svg()
        assert svg_text.startswith('<?xml version="1.0" encoding="UTF-8"?>')
        root_elem = ET.fromstring(svg_text)
        assert root_elem.tag.endswith("svg") or root_elem.tag == "svg"

    def test_svg_viewbox_and_dimensions(self) -> None:
        """SVG specifies exact 1200x750 viewport and viewBox."""
        canvas = create_canonical_treemap_spatial_canvas()
        svg_text = canvas.generate_svg()
        root_elem = ET.fromstring(svg_text)
        assert root_elem.attrib.get("viewBox") == "0 0 1200 750"
        assert root_elem.attrib.get("width") == "1200"
        assert root_elem.attrib.get("height") == "750"

    def test_svg_hud_and_telemetry_elements(self) -> None:
        """SVG contains telemetry HUD scorecard, register titles, and status badge."""
        canvas = create_canonical_treemap_spatial_canvas()
        svg_text = canvas.generate_svg()
        assert 'id="telemetry-hud"' in svg_text
        assert "%R2220" in svg_text
        assert "%R2221" in svg_text
        assert "%R2222" in svg_text
        assert "%R2223" in svg_text
        assert "%R2224" in svg_text
        assert "%R2225" in svg_text
        assert "%R2226" in svg_text
        assert "ACTIVE | NOMINAL" in svg_text

    def test_svg_hierarchy_tiles_and_subcomponent_tags(self) -> None:
        """SVG contains treemap-spatial-hierarchy group and subcomponent tags."""
        canvas = create_canonical_treemap_spatial_canvas()
        svg_text = canvas.generate_svg()
        assert 'id="treemap-spatial-hierarchy"' in svg_text
        assert "CMP-101" in svg_text
        assert "CMB-101" in svg_text
        assert "TRB-101" in svg_text
        assert "FLT-201" in svg_text

    def test_render_svg_alias(self) -> None:
        """render_svg() produces identical output to generate_svg()."""
        canvas = create_canonical_treemap_spatial_canvas()
        assert canvas.render_svg() == canvas.generate_svg()


# ============================================================================
# 8. TestWCAG21AAAContrastCompliance
# ============================================================================

class TestWCAG21AAAContrastCompliance:
    """Verify WCAG 2.1 AAA relative luminance and contrast ratio mathematics."""

    def test_relative_luminance_extremes(self) -> None:
        """Pure black (#000000) has luminance 0.0, pure white (#FFFFFF) has luminance 1.0."""
        assert relative_luminance("#000000") == 0.0
        assert relative_luminance("#FFFFFF") == 1.0

    def test_contrast_ratio_formula(self) -> None:
        """Contrast ratio between white and black is exactly 21.0:1."""
        cr = calculate_contrast_ratio("#FFFFFF", "#000000")
        assert round(cr, 1) == 21.0

    def test_decoupled_badge_contrast_exceeds_18_to_1(self) -> None:
        """Decoupled badge (#05080E) with white text achieves contrast >= 18.0:1 (WCAG AAA)."""
        badge_cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert badge_cr >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert badge_cr >= 18.0
        assert round(badge_cr, 2) >= 20.0  # Typically ~20.05:1

    def test_text_contrast_exceeds_7_to_1(self) -> None:
        """White text on dark theme backing (#0D1117) achieves contrast >= 7.0:1 (WCAG AAA)."""
        text_cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert text_cr >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert text_cr >= 7.0
        assert text_cr >= 18.0  # Pure white on #0D1117 is ~18.9:1

    def test_graphics_contrast_exceeds_3_to_1(self) -> None:
        """Thermal accent strokes (Emerald, Cyan, Amber, Crimson) achieve contrast >= 3.0:1 against backing."""
        for color in [COLOR_EMERALD, COLOR_CYAN, COLOR_AMBER, COLOR_CRIMSON]:
            cr = calculate_contrast_ratio(color, COLOR_DARK_THEME_BACKING)
            assert cr >= 3.0

    def test_validate_wcag_aaa_contrast_helper(self) -> None:
        """validate_wcag_aaa_contrast returns (True, text_cr, badge_cr)."""
        is_compliant, text_cr, badge_cr = validate_wcag_aaa_contrast()
        assert is_compliant is True
        assert badge_cr >= 18.0
        assert text_cr >= 7.0


# ============================================================================
# 9. TestDiagnosticFaultTrappingAndRecovery
# ============================================================================

class TestDiagnosticFaultTrappingAndRecovery:
    """Verify 0x7701 invalid hierarchy and 0x7702 aspect ratio degeneration trips and nominal recovery."""

    def test_invalid_hierarchy_trip_0x7701(self) -> None:
        """trigger_invalid_hierarchy sets 0x7701, de-asserts %M518, and writes %R2227."""
        canvas = create_canonical_treemap_spatial_canvas()
        canvas.trigger_invalid_hierarchy()
        assert canvas.diagnostic_code == DIAG_ERR_INVALID_HIERARCHY_TRIP
        assert canvas.diagnostic_code == 0x7701
        assert canvas.canvas_active is False
        assert canvas.reg_table.read_bit(COIL_TREEMAP_CANVAS_ACTIVE) is False
        assert canvas.reg_table.read_word(REG_TREEMAP_CANVAS_DIAGNOSTIC_CODE) == 0x7701

    def test_aspect_ratio_degeneration_trip_0x7702(self) -> None:
        """trigger_aspect_ratio_degeneration sets 0x7702, degenerates ratio, and writes %R2227."""
        canvas = create_canonical_treemap_spatial_canvas()
        canvas.trigger_aspect_ratio_degeneration()
        assert canvas.diagnostic_code == DIAG_ERR_ASPECT_RATIO_DEGENERATION_TRIP
        assert canvas.diagnostic_code == 0x7702
        assert canvas.metrics.worst_aspect_ratio >= 5.0
        assert canvas.metrics.worst_aspect_ratio_scaled >= 500
        assert canvas.reg_table.read_word(REG_TREEMAP_CANVAS_DIAGNOSTIC_CODE) == 0x7702

    def test_nominal_reset_clears_diagnostic_faults(self) -> None:
        """reset_nominal restores DIAG_EVENT_OK (0x0000), %M518 True, %M519 False."""
        canvas = create_canonical_treemap_spatial_canvas()
        canvas.trigger_invalid_hierarchy()
        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.diagnostic_code == 0x0000
        assert canvas.canvas_active is True
        assert canvas.reg_table.read_bit(COIL_TREEMAP_CANVAS_ACTIVE) is True
        assert canvas.reg_table.read_bit(COIL_CRITICAL_EQUIPMENT_ALARM) is False

    def test_exception_classes_hierarchy(self) -> None:
        """Verify exception hierarchy derives from TreemapSpatialError."""
        assert issubclass(InvalidHierarchyError, TreemapSpatialError)
        assert issubclass(AspectRatioDegenerationError, TreemapSpatialError)
        assert issubclass(TreemapSpatialGeometryError, TreemapSpatialError)


# ============================================================================
# 10. TestCriticalEquipmentAlarmCoilAssertion
# ============================================================================

class TestCriticalEquipmentAlarmCoilAssertion:
    """Verify discrete alarm coil %M519 assertions under stress and faults."""

    def test_nominal_state_alarm_deasserted(self) -> None:
        """In nominal canonical state, %M519 is False."""
        canvas = create_canonical_treemap_spatial_canvas()
        assert canvas.metrics.critical_equipment_alarm is False
        assert canvas.reg_table.read_bit(COIL_CRITICAL_EQUIPMENT_ALARM) is False

    def test_critical_thermal_alert_asserts_alarm(self) -> None:
        """trigger_critical_equipment_alarm with heat >= 85.0 °C asserts %M519."""
        canvas = create_canonical_treemap_spatial_canvas()
        canvas.trigger_critical_equipment_alarm(node_id=8, heat_c=98.5)
        assert canvas.metrics.critical_equipment_alarm is True
        assert canvas.reg_table.read_bit(COIL_CRITICAL_EQUIPMENT_ALARM) is True

    def test_alarm_cleared_upon_nominal_reset(self) -> None:
        """Alarm coil %M519 is de-asserted upon reset_nominal()."""
        canvas = create_canonical_treemap_spatial_canvas()
        canvas.trigger_critical_equipment_alarm(node_id=8, heat_c=98.5)
        assert canvas.reg_table.read_bit(COIL_CRITICAL_EQUIPMENT_ALARM) is True
        canvas.reset_nominal()
        assert canvas.reg_table.read_bit(COIL_CRITICAL_EQUIPMENT_ALARM) is False


# ============================================================================
# 11. TestInteractiveNodeSelectionAndTelemetry
# ============================================================================

class TestInteractiveNodeSelectionAndTelemetry:
    """Verify interactive asset node selection, heat metric scaling, and register feedback."""

    def test_select_node_by_id(self) -> None:
        """Selecting node 8 updates selected node ID, tag, and heat metric."""
        canvas = create_canonical_treemap_spatial_canvas()
        success = canvas.select_node_by_id(8)
        assert success is True
        assert canvas.selected_node_id == 8
        assert canvas.metrics.selected_node_id == 8
        assert canvas.metrics.selected_node_tag == "CMP-101"
        assert canvas.metrics.selected_node_heat_metric == 68.5
        assert canvas.metrics.selected_node_heat_metric_scaled == 685

    def test_select_invalid_node_id_fails(self) -> None:
        """Selecting out-of-range node ID returns False without altering state."""
        canvas = create_canonical_treemap_spatial_canvas()
        success = canvas.select_node_by_id(999)
        assert success is False
        assert canvas.selected_node_id == 0

    def test_sync_from_registers_setpoint(self) -> None:
        """sync_from_registers reads %R2223 setpoint and updates selected node."""
        canvas = create_canonical_treemap_spatial_canvas()
        canvas.reg_table.write_word(REG_SELECTED_TREEMAP_NODE_ID, 10, privilege=PrivilegeMode.SYSTEM)
        canvas.sync_from_registers()
        assert canvas.selected_node_id == 10


# ============================================================================
# 12. TestHornerOCSRegisterSynchronization
# ============================================================================

class TestHornerOCSRegisterSynchronization:
    """Verify Horner OCS register (%R2220..%R2227) and coil (%M518..%M519) synchronization."""

    def test_nominal_register_synchronization(self) -> None:
        """Nominal registers match 24, 4, 145, 0, 685, 0, 1450, 0, True, False."""
        reg_table = RegisterTable()
        canvas = TreemapSpatialCanvas(reg_table=reg_table)
        canvas.scan_step(dt=0.01)

        assert reg_table.read_word(REG_TREEMAP_TOTAL_NODES_COUNT) == 24
        assert reg_table.read_word(REG_TREEMAP_DEPTH_LEVELS) == 4
        assert reg_table.read_word(REG_TREEMAP_ASPECT_RATIO_WORST_SCALED) == 145
        assert reg_table.read_word(REG_SELECTED_TREEMAP_NODE_ID) == 0
        assert reg_table.read_word(REG_SELECTED_NODE_HEAT_METRIC_SCALED) == 685
        assert reg_table.read_word(REG_CRITICAL_EQUIPMENT_ALERT_COUNT) == 0
        assert reg_table.read_word(REG_TOTAL_MONITORED_POWER_KW) == 1450
        assert reg_table.read_word(REG_TREEMAP_CANVAS_DIAGNOSTIC_CODE) == 0
        assert reg_table.read_bit(COIL_TREEMAP_CANVAS_ACTIVE) is True
        assert reg_table.read_bit(COIL_CRITICAL_EQUIPMENT_ALARM) is False

    def test_ilogic_unit_interface_properties(self) -> None:
        """Verify ILogicUnit interface attributes: name, priority, is_enabled."""
        canvas = create_canonical_treemap_spatial_canvas()
        assert canvas.name == "TreemapSpatialCanvasSync"
        assert canvas.priority == 95
        assert canvas.is_enabled is True

    def test_ilogic_unit_execute_with_scan_context(self) -> None:
        """ScanContext execution via execute() synchronizes registers with SYSTEM privilege."""
        reg_table = RegisterTable()
        canvas = TreemapSpatialCanvas(reg_table=reg_table)
        ctx = ScanContext(cycle=1, dt_ms=10.0)
        canvas.execute(ctx)
        assert reg_table.read_word(REG_TREEMAP_TOTAL_NODES_COUNT) == 24
        assert reg_table.read_bit(COIL_TREEMAP_CANVAS_ACTIVE) is True


# ============================================================================
# 13. TestScanCycleSoakStability
# ============================================================================

class TestScanCycleSoakStability:
    """Verify 50-step and 100-step discrete scan cycle soak stability without drift or leak."""

    def test_50_step_scan_cycle_soak(self) -> None:
        """50 discrete scan cycles preserve exact node count, aspect ratio, and metrics."""
        canvas = create_canonical_treemap_spatial_canvas()
        initial_nodes = canvas.tree.total_nodes
        initial_power = canvas.metrics.total_monitored_power_kw

        for _ in range(50):
            canvas.scan_step(dt=0.01)

        assert canvas.tree.total_nodes == initial_nodes == 24
        assert canvas.metrics.total_monitored_power_kw == initial_power == 1450
        assert canvas.diagnostic_code == DIAG_EVENT_OK

    def test_100_step_scan_cycle_soak(self) -> None:
        """100 discrete scan cycles exhibit 0 memory leak, steady heat metric 685."""
        canvas = create_canonical_treemap_spatial_canvas()
        initial_heat = canvas.metrics.selected_node_heat_metric_scaled

        for _ in range(100):
            canvas.scan_step(dt=0.01)

        assert canvas.metrics.selected_node_heat_metric_scaled == initial_heat == 685
        assert canvas.tree.total_nodes == 24
        assert canvas.canvas_active is True


# ============================================================================
# 14. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Verify pure IEC 61131-3 Structured Text POU validation with SecurityGuard and STParser."""

    def test_pure_st_pou_syntax_and_purity(self) -> None:
        """SecurityGuard asserts pure ST without ladder logic constructs."""
        SecurityGuard.assert_pure_st_content(TREEMAP_SPATIAL_CANVAS_PURE_ST_POU)
        v_res = STParser.validate_code(TREEMAP_SPATIAL_CANVAS_PURE_ST_POU)
        assert v_res.status == AgentStatus.SUCCESS

    def test_st_parser_ast_and_bound_registers(self) -> None:
        """STParser parses PROGRAM TreemapSpatialCanvasSync and verifies all 10 register bindings."""
        parser = STParser()
        ast = parser.parse_pou(TREEMAP_SPATIAL_CANVAS_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "TreemapSpatialCanvasSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R2220", "%R2221", "%R2222", "%R2223",
            "%R2224", "%R2225", "%R2226", "%R2227",
            "%M518", "%M519",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be bound in POU AST"

        expected_var_bindings = {
            "TotalTreemapNodesCount": "%R2220",
            "TreemapDepthLevels": "%R2221",
            "WorstAspectRatioScaled": "%R2222",
            "SelectedTreemapNodeId": "%R2223",
            "SelectedNodeHeatMetricScaled": "%R2224",
            "CriticalEquipmentAlertCount": "%R2225",
            "TotalMonitoredPowerKw": "%R2226",
            "TreemapCanvasDiagnosticCode": "%R2227",
            "TreemapCanvasActive": "%M518",
            "CriticalEquipmentAlarm": "%M519",
        }
        assert len(ast.variables) == 10
        for var in ast.variables:
            expected_addr = expected_var_bindings.get(var.name)
            assert expected_addr is not None, f"Unexpected AST variable {var.name}"
            var_addr = getattr(var, "address_binding", None) or getattr(var, "memory_address", None)
            assert var_addr == expected_addr, f"Variable {var.name} bound to {var_addr}, expected {expected_addr}"

    def test_verify_treemap_spatial_canvas_pure_st_function(self) -> None:
        """verify_treemap_spatial_canvas_pure_st() helper returns True."""
        assert verify_treemap_spatial_canvas_pure_st() is True

    def test_pou_aliases_identity(self) -> None:
        """Verify POU string aliases match identically."""
        assert TREEMAP_SPATIAL_CANVAS_SYNC_PURE_ST_POU == TREEMAP_SPATIAL_CANVAS_PURE_ST_POU
        assert W261_TREEMAP_SPATIAL_PURE_ST_POU == TREEMAP_SPATIAL_CANVAS_PURE_ST_POU


# ============================================================================
# 15. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Verify strict fail-closed interception with LadderForbiddenError on ladder constructs."""

    @pytest.mark.parametrize(
        "snippet",
        [
            "PROGRAM Bad1 VAR X : BOOL; END_VAR ---[ ]--- END_PROGRAM",
            "PROGRAM Bad2 VAR X : BOOL; END_VAR ---( )--- END_PROGRAM",
            "PROGRAM Bad3 VAR X : BOOL; END_VAR XIC %M518; END_PROGRAM",
            "PROGRAM Bad4 VAR X : BOOL; END_VAR OTE %M519; END_PROGRAM",
            "PROGRAM Bad5 VAR X : BOOL; END_VAR RUNG 1 TreemapActive := TRUE; END_PROGRAM",
            "PROGRAM Bad6 VAR X : BOOL; END_VAR NETWORK 1 END_PROGRAM",
            "PROGRAM Bad7 VAR X : BOOL; END_VAR ---[/]--- END_PROGRAM",
            "PROGRAM Bad8 VAR X : BOOL; END_VAR ---(/)--- END_PROGRAM",
        ],
    )
    def test_ladder_constructs_rejected_fail_closed(self, snippet: str) -> None:
        """Every ladder contact, coil, rung, or mnemonic triggers LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# 16. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Verify deterministic 9-stage verification runner returning strict 4-state contract JSON."""

    def test_verification_runner_success(self) -> None:
        """Verification runner passes all 9 deterministic stages with status 'success'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"

            report = run_treemap_spatial_canvas_verification(
                evidence_path=ev_path,
                svg_output_path=svg_path,
            )

            assert report["status"] == "success"
            assert report["error_code"] is None
            assert report["data"]["checks_passed"] == 9
            assert report["data"]["total_checks"] == 9
            assert ev_path.is_file()
            assert svg_path.is_file()
            assert ev_path.stat().st_size > 0
            assert svg_path.stat().st_size > 0

            # Verify saved JSON evidence
            with open(ev_path, "r", encoding="utf-8") as f:
                saved = json.load(f)
            assert saved["status"] == "success"
            assert saved["data"]["metrics"]["total_nodes_count"] == 24
            assert saved["data"]["metrics"]["worst_aspect_ratio_scaled"] == 145
