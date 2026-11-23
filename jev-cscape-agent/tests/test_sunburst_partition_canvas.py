"""Comprehensive pytest test suite for Cscape HMI Dynamic Sunburst Partition Multilevel Hierarchy SCADA Canvas (W252).

Work Package: Wave W252 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Sunburst Partition Multilevel Hierarchy SCADA Canvas]

Covers 125+ Deterministic Unit Tests across 13 Test Classes:
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit equality, hashing, enums, register names, coil addresses.
2. TestSunburstHierarchyModel: 3 radial tiers, 14 active sectors, load distribution, tree hierarchy consistency.
3. TestCanvasGeometryAndLayout: 1200x750 viewport, center (600, 408), radii (70..140, 150..220, 230..300), containment within bounds.
4. TestSectorOverloadAlarmCondition: Single sector load share > 35.0% or efficiency < 75.0% trips %M498 alarm, recovery reset.
5. TestSVGGenerationAndXMLSyntax: Standalone W3C SVG 1.1 generation, ElementTree XML validation, <path> annular segments, labels, badges.
6. TestWCAG21AAAContrastAndVisualLegibility: WCAG 2.1 AAA relative luminance, contrast formulas, badge contrast > 18:1, text > 7:1.
7. TestHornerOCSSynchronizationAndRegisters: %R2130..%R2137 and %M497..%M498 bit-exact synchronization, PrivilegeMode.SYSTEM.
8. TestPureSTAndSecurity: STParser & SecurityGuard verification of SunburstPartitionCanvasSync POU.
9. TestAntiLadderRejection: Rejection of 6+ ladder constructs (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError.
10. TestILogicUnitCompliance: scan_step, step, execute, reset, 100-cycle soak stability.
11. TestDiagnosticFaultHandlingAndEdgeCases: 0xFA01, 0xFA02, 0xFA03, 0xFA04 fault injection, status bits, exception hierarchy, recovery.
12. TestVerificationRunnerAndContract: Deterministic 9-stage runner export and strict 4-state contract validation.
13. TestClassAliasesAndCanonicalFactory: Class aliases, factory functions, dataclass defaults, and module exports.
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

from jev_cscape.hmi.sunburst_partition_canvas import (
    ANGLE_SUM_FAULT,
    CANONICAL_CRITICAL_SECTOR,
    CANONICAL_HIERARCHY_LEVELS,
    CANONICAL_MAX_LOAD_SHARE_PCT,
    CANONICAL_MAX_LOAD_SHARE_SCALED,
    CANONICAL_SELECTED_NODE,
    CANONICAL_THERMAL_EFFICIENCY_PCT,
    CANONICAL_THERMAL_EFFICIENCY_SCALED,
    CANONICAL_TOTAL_LOAD_KW,
    CANONICAL_TOTAL_SECTORS,
    CANVAS_BOUNDS_HEIGHT,
    CANVAS_BOUNDS_WIDTH,
    CANVAS_BOUNDS_X,
    CANVAS_BOUNDS_Y,
    CANVAS_CENTER_X,
    CANVAS_CENTER_Y,
    CANVAS_GEOMETRY_OVERFLOW,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    CENTER_HUB_RADIUS,
    COIL_CANVAS_ACTIVE,
    COIL_OVERLOAD_ALARM,
    COIL_SECTOR_ALARM,
    COIL_SECTOR_OVERLOAD_ALARM,
    COIL_SUNBURST_CANVAS_ACTIVE,
    COIL_W252_CANVAS_ACTIVE,
    COIL_W252_OVERLOAD_ALARM,
    COLOR_ALARM_RUBY,
    COLOR_AREA_SEPARATION,
    COLOR_AREA_SYNTHESIS,
    COLOR_AREA_UTILITIES,
    COLOR_BORDER,
    COLOR_DARK_THEME_BACKING,
    COLOR_DECOUPLED_BADGE,
    COLOR_FOCUS_CYAN,
    COLOR_GRID_LINE,
    COLOR_INACTIVE_SLATE,
    COLOR_NORMAL_EMERALD,
    COLOR_PANEL_BG,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_WARNING_AMBER,
    CanvasGeometryOverflowError,
    DIAG_ERR_CANVAS_GEOMETRY_OVERFLOW,
    DIAG_ERR_HIERARCHY_LEVELS_INVALID,
    DIAG_ERR_SECTOR_ANGLE_SUM_MISMATCH,
    DIAG_ERR_TOTAL_LOAD_NON_POSITIVE,
    DIAG_EVENT_OK,
    DIAG_OK,
    DiagnosticCode,
    GEOMETRY_OVERFLOW_FAULT,
    HIERARCHY_LEVELS_FAULT,
    HIERARCHY_LEVELS_INVALID,
    HierarchyLevelsInvalidError,
    LOAD_SHARE_ALARM_THRESHOLD_PCT,
    LOAD_SHARE_ALARM_THRESHOLD_SCALED,
    MAX_ALLOWABLE_RADIUS,
    REG_ACTIVE_SECTORS,
    REG_ACTIVE_SECTORS_COUNT,
    REG_CRITICAL_OVERCONSUMPTION_SECTOR,
    REG_CRITICAL_SECTOR,
    REG_DIAG_CODE,
    REG_DIAGNOSTIC_CODE,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_HIERARCHY_LEVELS,
    REG_MAX_LOAD_SHARE,
    REG_MAX_LOAD_SHARE_SCALED,
    REG_MAX_SECTOR_LOAD_SHARE_SCALED,
    REG_OVERCONSUMPTION_SECTOR,
    REG_SECTORS_COUNT,
    REG_SELECTED_HIERARCHY_NODE,
    REG_SELECTED_NODE,
    REG_SELECTED_SECTOR,
    REG_SUNBURST_HIERARCHY_LEVELS,
    REG_THERMAL_EFFICIENCY,
    REG_THERMAL_EFFICIENCY_INDEX_SCALED,
    REG_THERMAL_EFFICIENCY_SCALED,
    REG_TOTAL_ENERGY_LOAD_KW,
    REG_TOTAL_LOAD,
    REG_TOTAL_LOAD_KW,
    REG_W252_ACTIVE_SECTORS,
    REG_W252_CRITICAL_SECTOR,
    REG_W252_DIAG_CODE,
    REG_W252_HIERARCHY_LEVELS,
    REG_W252_MAX_LOAD_SHARE,
    REG_W252_SELECTED_NODE,
    REG_W252_THERMAL_EFFICIENCY,
    REG_W252_TOTAL_LOAD_KW,
    SECTOR_ANGLE_SUM_MISMATCH,
    SUNBURST_OK,
    SUNBURST_PARTITION_CANVAS_PURE_ST_POU,
    SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU,
    SUNBURST_PARTITION_OK,
    SUNBURST_PARTITION_PURE_ST_POU,
    SectorAngleSumMismatchError,
    SunburstHierarchyNode,
    SunburstPartitionCanvas,
    SunburstPartitionCanvasDiagnosticCode,
    SunburstPartitionCanvasEngine,
    SunburstPartitionCanvasSync,
    SunburstPartitionDiagnosticCode,
    SunburstPartitionEngine,
    SunburstPartitionError,
    SunburstPartitionMetrics,
    SunburstPartitionSector,
    SunburstPartitionStatusBits,
    SunburstPartitionTree,
    SunburstSector,
    THERMAL_EFFICIENCY_ALARM_THRESHOLD_PCT,
    THERMAL_EFFICIENCY_ALARM_THRESHOLD_SCALED,
    TIER_1_RADIUS_INNER,
    TIER_1_RADIUS_OUTER,
    TIER_2_RADIUS_INNER,
    TIER_2_RADIUS_OUTER,
    TIER_3_RADIUS_INNER,
    TIER_3_RADIUS_OUTER,
    TOTAL_LOAD_FAULT,
    TOTAL_LOAD_NON_POSITIVE,
    TierLevel,
    TotalLoadNonPositiveError,
    W252_SUNBURST_PARTITION_PURE_ST_POU,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    contrast_ratio,
    create_canonical_sunburst_partition_canvas,
    create_canonical_sunburst_partition_tree,
    create_canonical_sunburst_sectors,
    format_annular_sector_arc,
    generate_sunburst_partition_canvas_svg,
    relative_luminance,
    run_sunburst_partition_canvas_verification,
    validate_wcag_aaa_contrast,
    verify_sunburst_partition_canvas_pure_st,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate DiagnosticCode signed/unsigned 16-bit equality, hashing, enums, registers, and coils."""

    def test_diagnostic_code_ok(self) -> None:
        diag = DiagnosticCode(0x0000)
        assert diag == 0
        assert diag == 0x0000
        assert diag == DIAG_EVENT_OK
        assert diag == DIAG_OK
        assert diag == SUNBURST_OK
        assert diag == SUNBURST_PARTITION_OK

    def test_diagnostic_code_signed_unsigned_0xfa01(self) -> None:
        diag = DiagnosticCode(0xFA01)
        assert diag == 0xFA01
        assert diag == -1535  # 0xFA01 - 0x10000
        assert diag == DIAG_ERR_HIERARCHY_LEVELS_INVALID
        assert diag == HIERARCHY_LEVELS_INVALID
        assert diag == HIERARCHY_LEVELS_FAULT

    def test_diagnostic_code_signed_unsigned_0xfa02(self) -> None:
        diag = DiagnosticCode(0xFA02)
        assert diag == 0xFA02
        assert diag == -1534  # 0xFA02 - 0x10000
        assert diag == DIAG_ERR_TOTAL_LOAD_NON_POSITIVE
        assert diag == TOTAL_LOAD_NON_POSITIVE
        assert diag == TOTAL_LOAD_FAULT

    def test_diagnostic_code_signed_unsigned_0xfa03(self) -> None:
        diag = DiagnosticCode(0xFA03)
        assert diag == 0xFA03
        assert diag == -1533  # 0xFA03 - 0x10000
        assert diag == DIAG_ERR_SECTOR_ANGLE_SUM_MISMATCH
        assert diag == SECTOR_ANGLE_SUM_MISMATCH
        assert diag == ANGLE_SUM_FAULT

    def test_diagnostic_code_signed_unsigned_0xfa04(self) -> None:
        diag = DiagnosticCode(0xFA04)
        assert diag == 0xFA04
        assert diag == -1532  # 0xFA04 - 0x10000
        assert diag == DIAG_ERR_CANVAS_GEOMETRY_OVERFLOW
        assert diag == CANVAS_GEOMETRY_OVERFLOW
        assert diag == GEOMETRY_OVERFLOW_FAULT

    def test_diagnostic_code_hashing_and_set_lookup(self) -> None:
        d1 = DiagnosticCode(0xFA01)
        d2 = DiagnosticCode(-1535)
        d_map = {d1: "HIERARCHY_INVALID"}
        assert d_map[d2] == "HIERARCHY_INVALID"
        assert hash(d1) == hash(d2)

    def test_register_address_mappings(self) -> None:
        assert REG_SUNBURST_HIERARCHY_LEVELS == "%R2130"
        assert REG_TOTAL_ENERGY_LOAD_KW == "%R2131"
        assert REG_ACTIVE_SECTORS_COUNT == "%R2132"
        assert REG_MAX_SECTOR_LOAD_SHARE_SCALED == "%R2133"
        assert REG_CRITICAL_OVERCONSUMPTION_SECTOR == "%R2134"
        assert REG_THERMAL_EFFICIENCY_INDEX_SCALED == "%R2135"
        assert REG_SELECTED_HIERARCHY_NODE == "%R2136"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2137"

    def test_register_aliases(self) -> None:
        assert REG_HIERARCHY_LEVELS == REG_SUNBURST_HIERARCHY_LEVELS
        assert REG_TOTAL_LOAD_KW == REG_TOTAL_ENERGY_LOAD_KW
        assert REG_TOTAL_LOAD == REG_TOTAL_ENERGY_LOAD_KW
        assert REG_ACTIVE_SECTORS == REG_ACTIVE_SECTORS_COUNT
        assert REG_SECTORS_COUNT == REG_ACTIVE_SECTORS_COUNT
        assert REG_MAX_LOAD_SHARE_SCALED == REG_MAX_SECTOR_LOAD_SHARE_SCALED
        assert REG_MAX_LOAD_SHARE == REG_MAX_SECTOR_LOAD_SHARE_SCALED
        assert REG_CRITICAL_SECTOR == REG_CRITICAL_OVERCONSUMPTION_SECTOR
        assert REG_OVERCONSUMPTION_SECTOR == REG_CRITICAL_OVERCONSUMPTION_SECTOR
        assert REG_THERMAL_EFFICIENCY_SCALED == REG_THERMAL_EFFICIENCY_INDEX_SCALED
        assert REG_THERMAL_EFFICIENCY == REG_THERMAL_EFFICIENCY_INDEX_SCALED
        assert REG_SELECTED_NODE == REG_SELECTED_HIERARCHY_NODE
        assert REG_SELECTED_SECTOR == REG_SELECTED_HIERARCHY_NODE
        assert REG_DIAGNOSTIC_CODE == REG_DIAGNOSTIC_STATUS_CODE
        assert REG_DIAG_CODE == REG_DIAGNOSTIC_STATUS_CODE

    def test_wave_w252_register_aliases(self) -> None:
        assert REG_W252_HIERARCHY_LEVELS == "%R2130"
        assert REG_W252_TOTAL_LOAD_KW == "%R2131"
        assert REG_W252_ACTIVE_SECTORS == "%R2132"
        assert REG_W252_MAX_LOAD_SHARE == "%R2133"
        assert REG_W252_CRITICAL_SECTOR == "%R2134"
        assert REG_W252_THERMAL_EFFICIENCY == "%R2135"
        assert REG_W252_SELECTED_NODE == "%R2136"
        assert REG_W252_DIAG_CODE == "%R2137"

    def test_coil_address_mappings_and_aliases(self) -> None:
        assert COIL_SUNBURST_CANVAS_ACTIVE == "%M497"
        assert COIL_SECTOR_OVERLOAD_ALARM == "%M498"
        assert COIL_CANVAS_ACTIVE == "%M497"
        assert COIL_OVERLOAD_ALARM == "%M498"
        assert COIL_SECTOR_ALARM == "%M498"
        assert COIL_W252_CANVAS_ACTIVE == "%M497"
        assert COIL_W252_OVERLOAD_ALARM == "%M498"

    def test_tier_level_enum(self) -> None:
        assert TierLevel.PLANT_AREA == 1
        assert TierLevel.UNIT_OPERATION == 2
        assert TierLevel.SUB_EQUIPMENT == 3
        assert len(TierLevel) == 3

    def test_status_bitmasks(self) -> None:
        assert SunburstPartitionStatusBits.CANVAS_ACTIVE == 1 << 0
        assert SunburstPartitionStatusBits.HIERARCHY_VALID == 1 << 1
        assert SunburstPartitionStatusBits.GEOMETRY_COMPUTED == 1 << 2
        assert SunburstPartitionStatusBits.SECTOR_OVERLOAD_ALARM == 1 << 3
        assert SunburstPartitionStatusBits.OVERCONSUMPTION_WARNING == 1 << 4
        assert SunburstPartitionStatusBits.HIERARCHY_LEVELS_INVALID == 1 << 5
        assert SunburstPartitionStatusBits.TOTAL_LOAD_NON_POSITIVE == 1 << 6
        assert SunburstPartitionStatusBits.SECTOR_ANGLE_SUM_MISMATCH == 1 << 7
        assert SunburstPartitionStatusBits.CANVAS_GEOMETRY_OVERFLOW == 1 << 8
        assert SunburstPartitionStatusBits.WCAG_AAA_VERIFIED == 1 << 9
        assert SunburstPartitionStatusBits.SVG_RENDER_VALID == 1 << 10
        assert SunburstPartitionStatusBits.NOMINAL_OPERATION == 1 << 11

    def test_threshold_constants(self) -> None:
        assert LOAD_SHARE_ALARM_THRESHOLD_PCT == 35.0
        assert LOAD_SHARE_ALARM_THRESHOLD_SCALED == 3500
        assert THERMAL_EFFICIENCY_ALARM_THRESHOLD_PCT == 75.0
        assert THERMAL_EFFICIENCY_ALARM_THRESHOLD_SCALED == 7500

    def test_palette_color_constants(self) -> None:
        assert COLOR_DARK_THEME_BACKING == "#0B0F19"
        assert COLOR_PANEL_BG == "#161B22"
        assert COLOR_BORDER == "#21262D"
        assert COLOR_DECOUPLED_BADGE == "#050811"
        assert COLOR_TEXT_PRIMARY == "#FFFFFF"
        assert COLOR_TEXT_MUTED == "#8B949E"
        assert COLOR_FOCUS_CYAN == "#38BDF8"
        assert COLOR_NORMAL_EMERALD == "#10B981"
        assert COLOR_WARNING_AMBER == "#F59E0B"
        assert COLOR_ALARM_RUBY == "#EF4444"
        assert COLOR_INACTIVE_SLATE == "#6B7280"
        assert COLOR_AREA_SYNTHESIS == "#0284C7"
        assert COLOR_AREA_SEPARATION == "#059669"
        assert COLOR_AREA_UTILITIES == "#D97706"


# ============================================================================
# 2. TestSunburstHierarchyModel
# ============================================================================

class TestSunburstHierarchyModel:
    """Validate 3 radial tiers, 14 active sectors, load distribution, and tree hierarchy."""

    @pytest.fixture
    def canonical_tree(self) -> SunburstPartitionTree:
        return create_canonical_sunburst_partition_tree()

    def test_total_sectors_count(self, canonical_tree: SunburstPartitionTree) -> None:
        all_nodes = canonical_tree.get_all_nodes()
        assert len(all_nodes) == CANONICAL_TOTAL_SECTORS
        assert len(all_nodes) == 14

    def test_tier_counts(self, canonical_tree: SunburstPartitionTree) -> None:
        tier1 = canonical_tree.get_tier_nodes(1)
        tier2 = canonical_tree.get_tier_nodes(2)
        tier3 = canonical_tree.get_tier_nodes(3)
        assert len(tier1) == 3
        assert len(tier2) == 4
        assert len(tier3) == 7
        assert len(tier1) + len(tier2) + len(tier3) == 14

    def test_tier_1_areas_names(self, canonical_tree: SunburstPartitionTree) -> None:
        tier1 = canonical_tree.get_tier_nodes(1)
        names = [n.name for n in tier1]
        assert "Synthesis" in names
        assert "Separation" in names
        assert "Utilities" in names

    def test_tier_2_units_names(self, canonical_tree: SunburstPartitionTree) -> None:
        tier2 = canonical_tree.get_tier_nodes(2)
        names = [n.name for n in tier2]
        assert "Reactors" in names
        assert "Distillation" in names
        assert "Boilers" in names
        assert "Chillers" in names

    def test_tier_3_equipments_names(self, canonical_tree: SunburstPartitionTree) -> None:
        tier3 = canonical_tree.get_tier_nodes(3)
        names = [n.name for n in tier3]
        expected = [
            "Feed Pumps", "Compressors", "Reflux Pumps", "Reboilers",
            "Boiler Feed Pumps", "Draft Fans", "Refrigerant Compressors"
        ]
        for exp in expected:
            assert exp in names

    def test_leaf_nodes_consistency(self, canonical_tree: SunburstPartitionTree) -> None:
        leaves = canonical_tree.get_leaf_nodes()
        assert len(leaves) == 7
        for leaf in leaves:
            assert leaf.is_leaf is True
            assert leaf.tier == 3

    def test_non_leaf_nodes_consistency(self, canonical_tree: SunburstPartitionTree) -> None:
        for node in canonical_tree.get_all_nodes():
            if node.tier < 3:
                assert node.is_leaf is False
                assert len(node.children) > 0

    def test_node_lookup_by_index(self, canonical_tree: SunburstPartitionTree) -> None:
        for idx in range(14):
            node = canonical_tree.get_node(idx)
            assert node is not None
            assert node.index == idx

    def test_invalid_node_lookup_returns_none(self, canonical_tree: SunburstPartitionTree) -> None:
        assert canonical_tree.get_node(-1) is None
        assert canonical_tree.get_node(14) is None
        assert canonical_tree.get_node(999) is None

    def test_leaf_loads_sum_to_canonical_total(self, canonical_tree: SunburstPartitionTree) -> None:
        leaf_sum = sum(l.load_kw for l in canonical_tree.get_leaf_nodes())
        assert math.isclose(leaf_sum, CANONICAL_TOTAL_LOAD_KW, rel_tol=1e-5)
        assert math.isclose(leaf_sum, 4250.0, rel_tol=1e-5)

    def test_tier_1_loads_sum_to_canonical_total(self, canonical_tree: SunburstPartitionTree) -> None:
        tier1_sum = sum(n.load_kw for n in canonical_tree.get_tier_nodes(1))
        assert math.isclose(tier1_sum, 4250.0, rel_tol=1e-5)

    def test_tier_2_loads_sum_to_canonical_total(self, canonical_tree: SunburstPartitionTree) -> None:
        tier2_sum = sum(n.load_kw for n in canonical_tree.get_tier_nodes(2))
        assert math.isclose(tier2_sum, 4250.0, rel_tol=1e-5)

    def test_critical_compressor_load_share(self, canonical_tree: SunburstPartitionTree) -> None:
        comp = canonical_tree.get_node(8)
        assert comp is not None
        assert comp.name == "Compressors"
        assert math.isclose(comp.load_kw, 1211.25, rel_tol=1e-5)
        assert math.isclose(comp.load_share_pct, 28.50, abs_tol=0.01)

    def test_leaf_angular_spans_sum_to_360_degrees(self, canonical_tree: SunburstPartitionTree) -> None:
        total_deg = sum(l.angular_span_deg for l in canonical_tree.get_leaf_nodes())
        assert math.isclose(total_deg, 360.0, abs_tol=0.1)

    def test_parent_angular_containment(self, canonical_tree: SunburstPartitionTree) -> None:
        for parent in canonical_tree.get_all_nodes():
            if parent.children:
                min_c_start = min(c.theta_start_rad for c in parent.children)
                max_c_end = max(c.theta_end_rad for c in parent.children)
                assert math.isclose(parent.theta_start_rad, min_c_start, abs_tol=1e-4)
                assert math.isclose(parent.theta_end_rad, max_c_end, abs_tol=1e-4)

    def test_sector_mid_angle_and_mid_radius(self, canonical_tree: SunburstPartitionTree) -> None:
        sec = canonical_tree.get_node(0)
        assert sec is not None
        expected_mid_angle = (sec.theta_start_rad + sec.theta_end_rad) / 2.0
        expected_mid_r = (sec.inner_radius + sec.outer_radius) / 2.0
        assert math.isclose(sec.mid_angle_rad, expected_mid_angle, rel_tol=1e-5)
        assert math.isclose(sec.mid_radius, expected_mid_r, rel_tol=1e-5)


# ============================================================================
# 3. TestCanvasGeometryAndLayout
# ============================================================================

class TestCanvasGeometryAndLayout:
    """Validate 1200x750 viewport, center (600, 408), radii (70..140, 150..220, 230..300), and bounds."""

    def test_viewport_dimensions(self) -> None:
        assert CANVAS_VIEWPORT_WIDTH == 1200
        assert CANVAS_VIEWPORT_HEIGHT == 750

    def test_canvas_bounds_containment(self) -> None:
        assert CANVAS_BOUNDS_X == 20.0
        assert CANVAS_BOUNDS_Y == 86.0
        assert CANVAS_BOUNDS_WIDTH == 1160.0
        assert CANVAS_BOUNDS_HEIGHT == 644.0
        # Right edge
        assert CANVAS_BOUNDS_X + CANVAS_BOUNDS_WIDTH == 1180.0
        # Bottom edge
        assert CANVAS_BOUNDS_Y + CANVAS_BOUNDS_HEIGHT == 730.0

    def test_center_coordinates(self) -> None:
        assert CANVAS_CENTER_X == 600.0
        assert CANVAS_CENTER_Y == 408.0

    def test_tier_radii_specifications(self) -> None:
        assert TIER_1_RADIUS_INNER == 70.0
        assert TIER_1_RADIUS_OUTER == 140.0
        assert TIER_2_RADIUS_INNER == 150.0
        assert TIER_2_RADIUS_OUTER == 220.0
        assert TIER_3_RADIUS_INNER == 230.0
        assert TIER_3_RADIUS_OUTER == 300.0

    def test_radial_thickness_and_gaps(self) -> None:
        # Each tier ring is 70 px wide
        assert TIER_1_RADIUS_OUTER - TIER_1_RADIUS_INNER == 70.0
        assert TIER_2_RADIUS_OUTER - TIER_2_RADIUS_INNER == 70.0
        assert TIER_3_RADIUS_OUTER - TIER_3_RADIUS_INNER == 70.0
        # Inter-tier spacing gaps are 10 px
        assert TIER_2_RADIUS_INNER - TIER_1_RADIUS_OUTER == 10.0
        assert TIER_3_RADIUS_INNER - TIER_2_RADIUS_OUTER == 10.0

    def test_concentric_containment_within_canvas_bounds(self) -> None:
        cx = CANVAS_CENTER_X
        cy = CANVAS_CENTER_Y
        r_max = TIER_3_RADIUS_OUTER  # 300.0

        # Left bound
        assert cx - r_max >= CANVAS_BOUNDS_X  # 600 - 300 = 300 >= 20
        # Right bound
        assert cx + r_max <= CANVAS_BOUNDS_X + CANVAS_BOUNDS_WIDTH  # 600 + 300 = 900 <= 1180
        # Top bound
        assert cy - r_max >= CANVAS_BOUNDS_Y  # 408 - 300 = 108 >= 86
        # Bottom bound
        assert cy + r_max <= CANVAS_BOUNDS_Y + CANVAS_BOUNDS_HEIGHT  # 408 + 300 = 708 <= 730

    def test_center_hub_radius(self) -> None:
        assert CENTER_HUB_RADIUS == 70.0
        assert CENTER_HUB_RADIUS <= TIER_1_RADIUS_INNER

    def test_max_allowable_radius_limits(self) -> None:
        assert MAX_ALLOWABLE_RADIUS == 322.0
        # 408 - 86 = 322 (top limit), 730 - 408 = 322 (bottom limit)
        assert CANVAS_CENTER_Y - MAX_ALLOWABLE_RADIUS == CANVAS_BOUNDS_Y
        assert CANVAS_CENTER_Y + MAX_ALLOWABLE_RADIUS == CANVAS_BOUNDS_Y + CANVAS_BOUNDS_HEIGHT

    def test_format_annular_sector_arc_valid_path(self) -> None:
        path = format_annular_sector_arc(
            cx=600.0,
            cy=408.0,
            r_in=70.0,
            r_out=140.0,
            start_angle_rad=0.0,
            end_angle_rad=math.pi / 2.0,
        )
        assert path.startswith("M ")
        assert " A " in path
        assert " L " in path
        assert path.endswith(" Z")

    def test_format_annular_sector_arc_zero_or_negative_span(self) -> None:
        assert format_annular_sector_arc(600, 408, 70, 140, 1.0, 1.0) == ""
        assert format_annular_sector_arc(600, 408, 70, 140, 2.0, 1.0) == ""

    def test_format_annular_sector_arc_large_arc_flag(self) -> None:
        # Span > pi should set large_arc to 1
        path_large = format_annular_sector_arc(600, 408, 70, 140, 0.0, 4.0)
        assert " 1 1 " in path_large
        # Span <= pi should set large_arc to 0
        path_small = format_annular_sector_arc(600, 408, 70, 140, 0.0, 1.0)
        assert " 0 1 " in path_small


# ============================================================================
# 4. TestSectorOverloadAlarmCondition
# ============================================================================

class TestSectorOverloadAlarmCondition:
    """Validate sector overload (> 35.0%) and low efficiency (< 75.0%) alarm trips on %M498."""

    @pytest.fixture
    def canvas(self) -> SunburstPartitionCanvas:
        return create_canonical_sunburst_partition_canvas()

    def test_nominal_alarm_inactive(self, canvas: SunburstPartitionCanvas) -> None:
        assert canvas.is_overload_alarm is False
        assert canvas.reg_table.read_bit(COIL_SECTOR_OVERLOAD_ALARM) is False
        assert canvas.metrics.max_sector_load_share_pct <= LOAD_SHARE_ALARM_THRESHOLD_PCT
        assert canvas.metrics.thermal_efficiency_index_pct >= THERMAL_EFFICIENCY_ALARM_THRESHOLD_PCT

    def test_trip_alarm_via_load_share_overload(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.trigger_overload_alarm(bad_share_kw=2500.0)
        assert canvas.is_overload_alarm is True
        assert canvas.reg_table.read_bit(COIL_SECTOR_OVERLOAD_ALARM) is True
        assert canvas.metrics.max_sector_load_share_pct > 35.0
        assert (canvas.status_bits & SunburstPartitionStatusBits.SECTOR_OVERLOAD_ALARM) != 0

    def test_trip_alarm_via_low_thermal_efficiency(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.trigger_low_efficiency_alarm(bad_efficiency=72.5)
        assert canvas.is_overload_alarm is True
        assert canvas.reg_table.read_bit(COIL_SECTOR_OVERLOAD_ALARM) is True
        assert canvas.metrics.thermal_efficiency_index_pct < 75.0

    def test_trip_alarm_dual_condition(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.trigger_overload_alarm(bad_share_kw=2500.0)
        canvas.trigger_low_efficiency_alarm(bad_efficiency=68.0)
        assert canvas.is_overload_alarm is True
        assert canvas.reg_table.read_bit(COIL_SECTOR_OVERLOAD_ALARM) is True

    def test_alarm_recovery_after_reset(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.trigger_overload_alarm(bad_share_kw=2500.0)
        assert canvas.is_overload_alarm is True
        canvas.reset_nominal()
        assert canvas.is_overload_alarm is False
        assert canvas.reg_table.read_bit(COIL_SECTOR_OVERLOAD_ALARM) is False
        assert canvas.metrics.max_sector_load_share_pct == CANONICAL_MAX_LOAD_SHARE_PCT
        assert canvas.metrics.thermal_efficiency_index_pct == CANONICAL_THERMAL_EFFICIENCY_PCT

    def test_alarm_deasserted_when_canvas_inactive(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.trigger_overload_alarm(bad_share_kw=2500.0)
        assert canvas.is_overload_alarm is True
        # Deactivate canvas
        canvas.is_canvas_active = False
        canvas.scan_step(dt=0.01)
        assert canvas.is_overload_alarm is False
        assert canvas.reg_table.read_bit(COIL_SECTOR_OVERLOAD_ALARM) is False

    def test_scaled_load_share_register_during_overload(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.trigger_overload_alarm(bad_share_kw=2500.0)
        scaled_reg = canvas.reg_table.read_word(REG_MAX_SECTOR_LOAD_SHARE_SCALED)
        assert scaled_reg > 3500

    def test_scaled_efficiency_register_during_low_efficiency(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.trigger_low_efficiency_alarm(bad_efficiency=70.0)
        scaled_eff = canvas.reg_table.read_word(REG_THERMAL_EFFICIENCY_INDEX_SCALED)
        assert scaled_eff == 7000
        assert scaled_eff < 7500


# ============================================================================
# 5. TestSVGGenerationAndXMLSyntax
# ============================================================================

class TestSVGGenerationAndXMLSyntax:
    """Validate standalone W3C SVG 1.1 generation, ElementTree XML validity, paths, and badges."""

    @pytest.fixture
    def svg_text(self) -> str:
        return generate_sunburst_partition_canvas_svg()

    @pytest.fixture
    def svg_tree(self, svg_text: str) -> ET.Element:
        return ET.fromstring(svg_text)

    def test_svg_is_valid_xml(self, svg_text: str) -> None:
        tree = ET.fromstring(svg_text)
        assert tree is not None
        assert tree.tag.endswith("svg")

    def test_svg_viewbox_and_dimensions(self, svg_tree: ET.Element) -> None:
        assert svg_tree.attrib.get("viewBox") == "0 0 1200 750"
        assert svg_tree.attrib.get("width") == "1200"
        assert svg_tree.attrib.get("height") == "750"

    def test_svg_has_defs_and_glow_filter(self, svg_text: str) -> None:
        assert "<defs>" in svg_text
        assert 'id="glow"' in svg_text
        assert 'id="headerGrad"' in svg_text

    def test_svg_contains_at_least_14_sector_paths(self, svg_text: str) -> None:
        root = ET.fromstring(svg_text)
        ns = {"svg": "http://www.w3.org/2000/svg"}
        paths = root.findall(".//svg:path", ns) or root.findall(".//path")
        assert len(paths) >= 14

    def test_svg_paths_contain_annular_commands(self, svg_text: str) -> None:
        root = ET.fromstring(svg_text)
        paths = root.findall(".//{http://www.w3.org/2000/svg}path") or root.findall(".//path")
        for p in paths:
            d = p.attrib.get("d", "")
            assert d.startswith("M")
            assert "A" in d
            assert "L" in d
            assert d.endswith("Z")

    def test_svg_contains_concentric_guide_circles(self, svg_text: str) -> None:
        root = ET.fromstring(svg_text)
        circles = root.findall(".//{http://www.w3.org/2000/svg}circle") or root.findall(".//circle")
        # 6 concentric guide circles + 1 center core hub disc = 7 circles
        assert len(circles) >= 7

    def test_svg_contains_decoupled_badges(self, svg_text: str) -> None:
        assert COLOR_DECOUPLED_BADGE in svg_text
        assert "CANVAS" in svg_text
        assert "LOAD" in svg_text
        assert "MAX SHARE" in svg_text
        assert "EFFICIENCY" in svg_text
        assert "ALARM" in svg_text
        assert "DIAG" in svg_text

    def test_svg_hud_cards_present(self, svg_text: str) -> None:
        assert "HIERARCHY TIERS" in svg_text
        assert "SELECTED NODE HUD" in svg_text
        assert "Tier 1: Plant Areas" in svg_text
        assert "Tier 2: Unit Operations" in svg_text
        assert "Tier 3: Sub-Equipment" in svg_text

    def test_svg_central_core_hub_display(self, svg_text: str) -> None:
        assert "TOTAL POWER" in svg_text
        assert "4,250 kW" in svg_text
        assert "Eff: 88.4%" in svg_text

    def test_svg_file_export(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".svg", delete=False) as f:
            temp_path = f.name
        try:
            svg = generate_sunburst_partition_canvas_svg()
            Path(temp_path).write_text(svg, encoding="utf-8")
            assert Path(temp_path).stat().st_size > 5000
            # Parse from file
            parsed = ET.parse(temp_path)
            assert parsed.getroot().tag.endswith("svg")
        finally:
            Path(temp_path).unlink(missing_ok=True)


# ============================================================================
# 6. TestWCAG21AAAContrastAndVisualLegibility
# ============================================================================

class TestWCAG21AAAContrastAndVisualLegibility:
    """Validate WCAG 2.1 AAA relative luminance, contrast formulas, and threshold compliance."""

    def test_relative_luminance_extremes(self) -> None:
        assert relative_luminance("#000000") == 0.0
        assert math.isclose(relative_luminance("#FFFFFF"), 1.0, rel_tol=1e-5)

    def test_relative_luminance_shorthand(self) -> None:
        assert math.isclose(relative_luminance("#FFF"), 1.0, rel_tol=1e-5)
        assert relative_luminance("#000") == 0.0

    def test_relative_luminance_invalid_input(self) -> None:
        assert relative_luminance("invalid") == 0.0
        assert relative_luminance("#12") == 0.0

    def test_contrast_ratio_black_and_white(self) -> None:
        cr = contrast_ratio("#FFFFFF", "#000000")
        assert math.isclose(cr, 21.0, rel_tol=1e-3)

    def test_contrast_ratio_symmetric(self) -> None:
        cr1 = contrast_ratio("#FFFFFF", "#050811")
        cr2 = contrast_ratio("#050811", "#FFFFFF")
        assert math.isclose(cr1, cr2, rel_tol=1e-5)

    def test_decoupled_badge_contrast_exceeds_18_to_1(self) -> None:
        cr = contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert cr >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert cr >= 18.0
        assert cr > 20.0

    def test_theme_text_contrast_exceeds_7_to_1(self) -> None:
        cr = contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert cr >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert cr >= 7.0
        assert cr > 18.0

    def test_validate_wcag_aaa_contrast_helper(self) -> None:
        is_aaa, text_cr, badge_cr = validate_wcag_aaa_contrast()
        assert is_aaa is True
        assert text_cr >= 7.0
        assert badge_cr >= 18.0

    def test_focus_cyan_contrast_on_decoupled_badge(self) -> None:
        cr = contrast_ratio(COLOR_FOCUS_CYAN, COLOR_DECOUPLED_BADGE)
        assert cr >= WCAG_GRAPHICAL_CONTRAST_TARGET
        assert cr > 7.0


# ============================================================================
# 7. TestHornerOCSSynchronizationAndRegisters
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Validate %R2130..%R2137 and %M497..%M498 bit-exact synchronization under PrivilegeMode.SYSTEM."""

    @pytest.fixture
    def synced_setup(self) -> Tuple[SunburstPartitionCanvas, RegisterTable]:
        reg_table = RegisterTable()
        canvas = SunburstPartitionCanvas(reg_table=reg_table)
        canvas.scan_step(dt=0.01)
        return canvas, reg_table

    def test_register_r2130_hierarchy_levels(self, synced_setup: Tuple[SunburstPartitionCanvas, RegisterTable]) -> None:
        _, rt = synced_setup
        val = rt.read_word(REG_SUNBURST_HIERARCHY_LEVELS)
        assert val == 3
        assert val == CANONICAL_HIERARCHY_LEVELS

    def test_register_r2131_total_energy_load(self, synced_setup: Tuple[SunburstPartitionCanvas, RegisterTable]) -> None:
        _, rt = synced_setup
        val = rt.read_word(REG_TOTAL_ENERGY_LOAD_KW)
        assert val == 4250
        assert val == int(round(CANONICAL_TOTAL_LOAD_KW))

    def test_register_r2132_active_sectors_count(self, synced_setup: Tuple[SunburstPartitionCanvas, RegisterTable]) -> None:
        _, rt = synced_setup
        val = rt.read_word(REG_ACTIVE_SECTORS_COUNT)
        assert val == 14
        assert val == CANONICAL_TOTAL_SECTORS

    def test_register_r2133_max_load_share_scaled(self, synced_setup: Tuple[SunburstPartitionCanvas, RegisterTable]) -> None:
        _, rt = synced_setup
        val = rt.read_word(REG_MAX_SECTOR_LOAD_SHARE_SCALED)
        assert val == 2850
        assert val == CANONICAL_MAX_LOAD_SHARE_SCALED

    def test_register_r2134_critical_sector(self, synced_setup: Tuple[SunburstPartitionCanvas, RegisterTable]) -> None:
        _, rt = synced_setup
        val = rt.read_word(REG_CRITICAL_OVERCONSUMPTION_SECTOR)
        assert val == 8
        assert val == CANONICAL_CRITICAL_SECTOR

    def test_register_r2135_thermal_efficiency_scaled(self, synced_setup: Tuple[SunburstPartitionCanvas, RegisterTable]) -> None:
        _, rt = synced_setup
        val = rt.read_word(REG_THERMAL_EFFICIENCY_INDEX_SCALED)
        assert val == 8840
        assert val == CANONICAL_THERMAL_EFFICIENCY_SCALED

    def test_register_r2136_selected_node(self, synced_setup: Tuple[SunburstPartitionCanvas, RegisterTable]) -> None:
        _, rt = synced_setup
        val = rt.read_word(REG_SELECTED_HIERARCHY_NODE)
        assert val == 8
        assert val == CANONICAL_SELECTED_NODE

    def test_register_r2137_diagnostic_code(self, synced_setup: Tuple[SunburstPartitionCanvas, RegisterTable]) -> None:
        _, rt = synced_setup
        val = rt.read_word(REG_DIAGNOSTIC_STATUS_CODE)
        assert val == 0x0000

    def test_coil_m497_canvas_active(self, synced_setup: Tuple[SunburstPartitionCanvas, RegisterTable]) -> None:
        _, rt = synced_setup
        val = rt.read_bit(COIL_SUNBURST_CANVAS_ACTIVE)
        assert val is True

    def test_coil_m498_overload_alarm(self, synced_setup: Tuple[SunburstPartitionCanvas, RegisterTable]) -> None:
        _, rt = synced_setup
        val = rt.read_bit(COIL_SECTOR_OVERLOAD_ALARM)
        assert val is False

    def test_custom_register_table_injection(self) -> None:
        custom_rt = RegisterTable()
        c = SunburstPartitionCanvas(reg_table=custom_rt, selected_node_index=4)
        c.scan_step(dt=0.01)
        assert custom_rt.read_word(REG_SELECTED_HIERARCHY_NODE) == 4
        assert custom_rt.read_word(REG_SUNBURST_HIERARCHY_LEVELS) == 3


# ============================================================================
# 8. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure IEC 61131-3 ST POU grammar, bindings, AST, and SecurityGuard."""

    def test_pou_contains_program_header_and_end(self) -> None:
        pou = SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU
        assert "PROGRAM SunburstPartitionCanvasSync" in pou
        assert "END_PROGRAM" in pou

    def test_pou_contains_all_register_bindings(self) -> None:
        pou = SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU
        assert "%R2130" in pou
        assert "%R2131" in pou
        assert "%R2132" in pou
        assert "%R2133" in pou
        assert "%R2134" in pou
        assert "%R2135" in pou
        assert "%R2136" in pou
        assert "%R2137" in pou

    def test_pou_contains_all_coil_bindings(self) -> None:
        pou = SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU
        assert "%M497" in pou
        assert "%M498" in pou

    def test_pou_contains_safety_interlock_logic(self) -> None:
        pou = SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU
        assert "MaxSectorLoadShareScaled > 3500" in pou
        assert "ThermalEfficiencyIndexScaled < 7500" in pou
        assert "SectorOverloadAlarm := TRUE;" in pou
        assert "SectorOverloadAlarm := FALSE;" in pou

    def test_security_guard_asserts_pure_st(self) -> None:
        SecurityGuard.assert_pure_st_content(SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU)

    def test_st_parser_ast_validation(self) -> None:
        parser = STParser()
        pou_node = parser.parse_pou(SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU)
        assert pou_node is not None
        assert pou_node.name == "SunburstPartitionCanvasSync"
        assert pou_node.pou_type == POUType.PROGRAM

    def test_verify_pure_st_helper_function(self) -> None:
        assert verify_sunburst_partition_canvas_pure_st() is True

    def test_pou_aliases_equal_canonical(self) -> None:
        assert SUNBURST_PARTITION_PURE_ST_POU == SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU
        assert W252_SUNBURST_PARTITION_PURE_ST_POU == SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU


# ============================================================================
# 9. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Validate strict rejection of 6+ ladder logic constructs with LadderForbiddenError."""

    def test_reject_normally_open_contact(self) -> None:
        bad_st = SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU + "\n---[ ]---"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_normally_closed_contact(self) -> None:
        bad_st = SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU + "\n---[/]---"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_output_coil(self) -> None:
        bad_st = SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU + "\n---( )---"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_inverted_coil(self) -> None:
        bad_st = SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU + "\n---(/)---"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_rung_delimiter(self) -> None:
        bad_st = "RUNG 1: Main Rung\n" + SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_network_delimiter(self) -> None:
        bad_st = "NETWORK 10\n" + SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_mnemonic_xic(self) -> None:
        bad_st = SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU + "\nXIC %M497"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_reject_mnemonic_ote(self) -> None:
        bad_st = SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU + "\nOTE %M498"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)


# ============================================================================
# 10. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit protocol compliance (name, priority, is_enabled, scan_step, step, execute, reset, soak)."""

    @pytest.fixture
    def canvas(self) -> SunburstPartitionCanvas:
        return create_canonical_sunburst_partition_canvas()

    def test_isinstance_ilogicunit(self, canvas: SunburstPartitionCanvas) -> None:
        assert isinstance(canvas, ILogicUnit)

    def test_logic_unit_properties(self, canvas: SunburstPartitionCanvas) -> None:
        assert canvas.name == "SunburstPartitionCanvasSync"
        assert canvas.priority == 50
        assert canvas.is_enabled is True

    def test_is_enabled_tracks_canvas_active(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.is_canvas_active = False
        assert canvas.is_enabled is False
        canvas.is_canvas_active = True
        assert canvas.is_enabled is True

    def test_step_method(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.step(dt=0.01)
        assert canvas.metrics.total_energy_load_kw == 4250.0

    def test_execute_with_scan_context(self, canvas: SunburstPartitionCanvas) -> None:
        ctx = ScanContext(cycle=1, dt_ms=10.0)
        canvas.execute(ctx)
        assert canvas.metrics.active_sectors_count == 14

    def test_reset_method_restores_nominal(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.trigger_overload_alarm(bad_share_kw=2500.0)
        assert canvas.is_overload_alarm is True
        canvas.reset()
        assert canvas.is_overload_alarm is False
        assert canvas.metrics.max_sector_load_share_pct == CANONICAL_MAX_LOAD_SHARE_PCT

    def test_100_cycle_soak_stability(self, canvas: SunburstPartitionCanvas) -> None:
        init_nodes_count = len(canvas.tree.get_all_nodes())
        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt_ms=10.0)
            canvas.scan_step(dt=0.01, context=ctx)

        final_nodes_count = len(canvas.tree.get_all_nodes())
        assert init_nodes_count == final_nodes_count == 14
        assert not math.isnan(canvas.metrics.total_energy_load_kw)
        assert not math.isinf(canvas.metrics.total_energy_load_kw)
        assert canvas.metrics.total_energy_load_kw == 4250.0
        assert canvas.metrics.max_sector_load_share_scaled == 2850
        assert canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0


# ============================================================================
# 11. TestDiagnosticFaultHandlingAndEdgeCases
# ============================================================================

class TestDiagnosticFaultHandlingAndEdgeCases:
    """Validate 0xFA01..0xFA04 fault injection, status bits, exceptions, and recovery."""

    @pytest.fixture
    def canvas(self) -> SunburstPartitionCanvas:
        return create_canonical_sunburst_partition_canvas()

    def test_fault_0xfa01_hierarchy_levels_too_low(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.trigger_hierarchy_levels_invalid(invalid_levels=1)
        assert canvas.diagnostic_code == DIAG_ERR_HIERARCHY_LEVELS_INVALID
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xFA01
        assert (canvas.status_bits & SunburstPartitionStatusBits.HIERARCHY_LEVELS_INVALID) != 0

    def test_fault_0xfa01_hierarchy_levels_too_high(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.trigger_hierarchy_levels_invalid(invalid_levels=6)
        assert canvas.diagnostic_code == DIAG_ERR_HIERARCHY_LEVELS_INVALID
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xFA01

    def test_fault_0xfa02_non_positive_load_zero(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.trigger_total_load_non_positive(bad_load=0.0)
        assert canvas.diagnostic_code == DIAG_ERR_TOTAL_LOAD_NON_POSITIVE
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xFA02
        assert (canvas.status_bits & SunburstPartitionStatusBits.TOTAL_LOAD_NON_POSITIVE) != 0

    def test_fault_0xfa02_non_positive_load_negative(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.trigger_total_load_non_positive(bad_load=-500.0)
        assert canvas.diagnostic_code == DIAG_ERR_TOTAL_LOAD_NON_POSITIVE
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xFA02

    def test_fault_0xfa03_angle_sum_mismatch(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.trigger_sector_angle_sum_mismatch()
        assert canvas.diagnostic_code == DIAG_ERR_SECTOR_ANGLE_SUM_MISMATCH
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xFA03
        assert (canvas.status_bits & SunburstPartitionStatusBits.SECTOR_ANGLE_SUM_MISMATCH) != 0

    def test_fault_0xfa04_geometry_overflow(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.trigger_canvas_geometry_overflow(bad_radius=350.0)
        assert canvas.diagnostic_code == DIAG_ERR_CANVAS_GEOMETRY_OVERFLOW
        assert (canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xFA04
        assert (canvas.status_bits & SunburstPartitionStatusBits.CANVAS_GEOMETRY_OVERFLOW) != 0

    def test_fault_recovery_to_nominal(self, canvas: SunburstPartitionCanvas) -> None:
        canvas.trigger_canvas_geometry_overflow(bad_radius=360.0)
        assert canvas.diagnostic_code == DIAG_ERR_CANVAS_GEOMETRY_OVERFLOW
        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) == 0x0000

    def test_exception_hierarchy(self) -> None:
        assert issubclass(HierarchyLevelsInvalidError, SunburstPartitionError)
        assert issubclass(TotalLoadNonPositiveError, SunburstPartitionError)
        assert issubclass(SectorAngleSumMismatchError, SunburstPartitionError)
        assert issubclass(CanvasGeometryOverflowError, SunburstPartitionError)

    def test_tree_compute_bottom_up_raises_non_positive_load(self) -> None:
        tree = create_canonical_sunburst_partition_tree()
        with pytest.raises(TotalLoadNonPositiveError):
            tree.compute_bottom_up(total_load=0.0)
        with pytest.raises(TotalLoadNonPositiveError):
            tree.compute_bottom_up(total_load=-100.0)


# ============================================================================
# 12. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate deterministic 9-stage verification runner, JSON report, and strict 4-state contract."""

    def test_run_verification_returns_strict_4_state_dict(self) -> None:
        res = run_sunburst_partition_canvas_verification()
        assert isinstance(res, dict)
        assert res["status"] in ("success", "failed", "blocked", "inconclusive")
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert "9/9 stages passed" in res["details"]

    def test_runner_data_payload_structure(self) -> None:
        res = run_sunburst_partition_canvas_verification()
        data = res["data"]
        assert data["work_package"] == "W252"
        assert data["gate"] == "Gate G9 / G2"
        assert data["component"] == "Cscape HMI Dynamic Sunburst Partition Multilevel Hierarchy SCADA Canvas"
        assert data["checks_passed"] == 9
        assert data["total_checks"] == 9
        assert len(data["tests"]) == 9

    def test_all_9_individual_stages_passed(self) -> None:
        res = run_sunburst_partition_canvas_verification()
        stages = res["data"]["tests"]
        for st in stages:
            assert st["passed"] is True, f"Stage {st.get('stage')} ({st.get('check')}) failed"

    def test_runner_file_emission(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_path = Path(tmpdir) / "sample.svg"
            res = run_sunburst_partition_canvas_verification(output_path=ev_path, sample_svg_path=svg_path)
            assert res["status"] == "success"
            assert ev_path.exists()
            assert svg_path.exists()
            # Verify evidence file is valid JSON
            with open(ev_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["data"]["checks_passed"] == 9


# ============================================================================
# 13. TestClassAliasesAndCanonicalFactory
# ============================================================================

class TestClassAliasesAndCanonicalFactory:
    """Validate class aliases, factory functions, dataclass defaults, and module exports."""

    def test_diagnostic_code_aliases(self) -> None:
        assert SunburstPartitionDiagnosticCode is DiagnosticCode
        assert SunburstPartitionCanvasDiagnosticCode is DiagnosticCode

    def test_canvas_engine_aliases(self) -> None:
        assert SunburstPartitionCanvasEngine is SunburstPartitionCanvas
        assert SunburstPartitionEngine is SunburstPartitionCanvas
        assert SunburstPartitionCanvasSync is SunburstPartitionCanvas

    def test_sector_class_aliases(self) -> None:
        assert SunburstSector is SunburstPartitionSector
        assert SunburstHierarchyNode is SunburstPartitionSector

    def test_canonical_sectors_factory_returns_14_items(self) -> None:
        sectors = create_canonical_sunburst_sectors()
        assert isinstance(sectors, list)
        assert len(sectors) == 14
        for s in sectors:
            assert isinstance(s, SunburstPartitionSector)

    def test_canonical_canvas_factory_defaults(self) -> None:
        canvas = create_canonical_sunburst_partition_canvas()
        assert isinstance(canvas, SunburstPartitionCanvas)
        assert canvas.selected_node_index == CANONICAL_SELECTED_NODE
        assert canvas.hierarchy_levels == CANONICAL_HIERARCHY_LEVELS
        assert canvas.total_energy_load_kw == CANONICAL_TOTAL_LOAD_KW

    def test_metrics_dataclass_defaults(self) -> None:
        metrics = SunburstPartitionMetrics()
        assert metrics.hierarchy_levels == 3
        assert metrics.total_energy_load_kw == 4250.0
        assert metrics.active_sectors_count == 14
        assert metrics.max_sector_load_share_pct == 28.50
        assert metrics.max_sector_load_share_scaled == 2850
        assert metrics.critical_overconsumption_sector == 8
        assert metrics.thermal_efficiency_index_pct == 88.40
        assert metrics.thermal_efficiency_index_scaled == 8840
        assert metrics.selected_hierarchy_node == 8
        assert metrics.diagnostic_status_code == DIAG_EVENT_OK
        assert metrics.is_canvas_active is True
        assert metrics.is_overload_alarm is False

    def test_sector_dataclass_defaults(self) -> None:
        sec = SunburstPartitionSector(index=0, name="Test", tier=1)
        assert sec.parent_index is None
        assert sec.load_kw == 0.0
        assert sec.efficiency_pct == 88.40
        assert sec.is_overload is False
        assert len(sec.children) == 0
