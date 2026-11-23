"""Comprehensive pytest test suite for Cscape HMI Dynamic Sunburst & Hierarchical Multi-Level Radial Ring Partitioning Canvas (W174).

Work Package: W174 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1350..%R1357, %M315..%M316).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Hierarchical Multi-Level Radial Ring Partition Geometry:
   - Level 0 (Central Core): Overall Plant Refinery Energy & KPI Health (Radius 0..80px).
   - Level 1 (Inner Annular Ring): 4 Production Blocks (Crude/Distillation, Conversion FCC/HCU, Reforming/Isom, Alkylation/Treating) (Radius 90..190px).
   - Level 2 (Outer Annular Ring): 16 Equipment Subsystems (Compressors, Furnaces, Heat Exchangers, Columns, Reactors) (Radius 200..300px).
4. Section 4: Proportional angular partition summing to 360 degrees (2*pi) & Polar-to-Cartesian annular arc path math.
5. Section 5: Standalone W3C SVG 1.1 XML generation, dark theme backing, breadcrumbs, core hub, and HUD card.
6. Section 6: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
7. Section 7: Process safety trips (0xC701 hierarchy sum fault tripping %M315, 0xC702 polar bounds fault, 0xC703 render fault).
8. Section 8: Horner OCS register space synchronization (%R1350..%R1357, %M315..%M316) with PrivilegeMode.SYSTEM.
9. Section 9: Deterministic 9-stage verification suite integration test.
10. Section 10: DiagnosticCode signed/unsigned 16-bit math and edge cases.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.sunburst_canvas import (
    CANVAS_CENTER_X,
    CANVAS_CENTER_Y,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COLOR_ALERT_HALO,
    COLOR_AMBER,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_CRIMSON,
    COLOR_CYAN,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DECOUPLED_BADGE,
    COLOR_EMERALD,
    COLOR_EMERALD_GREEN,
    COLOR_FOCUS_BLUE,
    COLOR_FOCUS_OUTLINE,
    COLOR_INDIGO,
    COLOR_PURPLE,
    COLOR_SKY_BLUE,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    DEFAULT_ANGULAR_GAP_DEG,
    DepthLevel,
    DIAG_EVENT_HIERARCHY_SUM_FAULT,
    DIAG_EVENT_OK,
    DIAG_EVENT_POLAR_BOUNDS_FAULT,
    DIAG_EVENT_RENDER_FAULT,
    DiagnosticCode,
    HIERARCHICAL_PARTITION_PURE_ST_POU,
    HierarchicalPartitionHmiSync,
    LEVEL0_R_INNER,
    LEVEL0_R_OUTER,
    LEVEL1_R_INNER,
    LEVEL1_R_OUTER,
    LEVEL2_R_INNER,
    LEVEL2_R_OUTER,
    RADIAL_RING_PARTITIONING_PURE_ST_POU,
    RadialRingPartitioningHmiSync,
    SUNBURST_CANVAS_PURE_ST_POU,
    SUNBURST_CORE_RADIUS,
    SUNBURST_ERR_HIERARCHY_SUM_FAULT,
    SUNBURST_ERR_OK,
    SUNBURST_ERR_POLAR_BOUNDS_FAULT,
    SUNBURST_ERR_RENDER_FAULT,
    SUNBURST_HIERARCHY_CANVAS_PURE_ST_POU,
    SUNBURST_MAX_RADIUS,
    SUNBURST_ROOT_RADIUS,
    SunburstCanvas,
    SunburstCanvasEngine,
    SunburstCanvasStatusBits,
    SunburstCanvasSync,
    SunburstHierarchyCanvasSync,
    SunburstMetrics,
    SunburstNode,
    SunburstSector,
    SunburstStatusBits,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    calculate_contrast_ratio,
    compute_sunburst_metrics,
    create_canonical_refinery_sunburst,
    create_canonical_sunburst_canvas,
    create_canonical_sunburst_nodes,
    create_canonical_sunburst_sectors,
    create_canonical_sunburst_tree,
    create_mock_scan_context,
    generate_annular_arc_path,
    generate_annular_sector_path,
    generate_sunburst_canvas_svg,
    hex_to_relative_luminance,
    layout_sunburst_diagram,
    polar_to_cartesian,
    run_sunburst_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_hierarchical_partition_pure_st,
    verify_radial_ring_partitioning_pure_st,
    verify_sunburst_canvas_pure_st,
    verify_sunburst_hierarchy_pure_st,
    verify_sunburst_pure_st,
)


# ============================================================================
# Section 1: Pure ST POU Grammar & Variable AST Validation
# ============================================================================

class TestPureSTValidation:
    """Validate compliance with IEC 61131-3 Pure Structured Text standards (%R1350..%R1357, %M315..%M316)."""

    def test_pure_st_pou_syntax_and_ast_parsing(self):
        """Verify SunburstHierarchyCanvasSync parses without error and matches expected %R1350..%R1357, %M315..%M316 bindings."""
        SecurityGuard.assert_pure_st_content(SUNBURST_HIERARCHY_CANVAS_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(SUNBURST_HIERARCHY_CANVAS_PURE_ST_POU)

        assert pou is not None
        assert pou.name == "SunburstHierarchyCanvasSync"
        assert pou.pou_type == POUType.PROGRAM
        assert len(pou.variables) == 10

        expected_bindings = {
            "TotalEnergyEfficiencyScoreScaled": "%R1350",
            "SelectedDepthLevel": "%R1351",
            "SelectedSectorIndex": "%R1352",
            "Level1PrimaryUnitScoreScaled": "%R1353",
            "Level2SubsystemScoreScaled": "%R1354",
            "MaxHierarchyDeviationScaled": "%R1355",
            "ActiveSectorsCount": "%R1356",
            "DiagnosticStatusCode": "%R1357",
            "SunburstHierarchyTrip": "%M315",
            "SunburstCanvasActive": "%M316",
        }

        var_dict = {v.name: v.address_binding for v in pou.variables}
        for name, addr in expected_bindings.items():
            assert name in var_dict, f"Missing variable binding: {name}"
            assert var_dict[name] == addr, f"Binding mismatch for {name}: {var_dict[name]} != {addr}"

        # Verify data types
        type_dict = {v.name: v.data_type for v in pou.variables}
        for name in [
            "TotalEnergyEfficiencyScoreScaled", "SelectedDepthLevel", "SelectedSectorIndex",
            "Level1PrimaryUnitScoreScaled", "Level2SubsystemScoreScaled",
            "MaxHierarchyDeviationScaled", "ActiveSectorsCount", "DiagnosticStatusCode",
        ]:
            assert type_dict[name] == "INT", f"Expected INT for {name}, got {type_dict[name]}"

        for name in ["SunburstHierarchyTrip", "SunburstCanvasActive"]:
            assert type_dict[name] == "BOOL", f"Expected BOOL for {name}, got {type_dict[name]}"

    def test_radial_ring_partitioning_alias_pou(self):
        """Verify RadialRingPartitioningHmiSync alias POU parses cleanly."""
        SecurityGuard.assert_pure_st_content(RADIAL_RING_PARTITIONING_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(RADIAL_RING_PARTITIONING_PURE_ST_POU)

        assert pou is not None
        assert pou.name == "RadialRingPartitioningHmiSync"
        assert pou.pou_type == POUType.PROGRAM

        expected_bindings = {
            "TotalEnergyEfficiencyScoreScaled": "%R1350",
            "SelectedDepthLevel": "%R1351",
            "SelectedSectorIndex": "%R1352",
            "Level1PrimaryUnitScoreScaled": "%R1353",
            "Level2SubsystemScoreScaled": "%R1354",
            "MaxHierarchyDeviationScaled": "%R1355",
            "ActiveSectorsCount": "%R1356",
            "DiagnosticStatusCode": "%R1357",
            "SunburstHierarchyTrip": "%M315",
            "SunburstCanvasActive": "%M316",
        }
        var_dict = {v.name: v.address_binding for v in pou.variables}
        for name, addr in expected_bindings.items():
            assert name in var_dict
            assert var_dict[name] == addr

    def test_helper_verification_functions(self):
        """Verify verification helper functions return True."""
        assert verify_sunburst_hierarchy_pure_st() is True
        assert verify_radial_ring_partitioning_pure_st() is True
        assert verify_sunburst_canvas_pure_st() is True
        assert verify_hierarchical_partition_pure_st() is True
        assert verify_sunburst_pure_st() is True


# ============================================================================
# Section 2: Anti-Ladder Construct Security Interception
# ============================================================================

class TestLadderConstructInterception:
    """Verify security guard intercepts forbidden ladder logic constructs."""

    @pytest.mark.parametrize(
        "label,snippet",
        [
            ("Contacts", "PROGRAM BadSunburstContacts\nVAR Active : BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"),
            ("Coils", "PROGRAM BadSunburstCoils\nVAR Trip : BOOL; END_VAR\n---( )---\nEND_PROGRAM"),
            ("Rung", "PROGRAM BadSunburstRung\nRUNG 1:\n    Active := TRUE;\nEND_PROGRAM"),
            ("Network", "PROGRAM BadSunburstNetwork\nNETWORK 1:\n    Active := TRUE;\nEND_PROGRAM"),
            ("XIC", "PROGRAM BadSunburstMnemonicXIC\nVAR Reg : INT; END_VAR\nXIC %M316;\nEND_PROGRAM"),
            ("OTE", "PROGRAM BadSunburstMnemonicOTE\nVAR Reg : INT; END_VAR\nOTE %M315;\nEND_PROGRAM"),
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden(self, label: str, snippet: str):
        """Verify that forbidden ladder logic constructs fail closed with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# Section 3: Hierarchical Multi-Level Radial Ring Partition Geometry
# ============================================================================

class TestHierarchicalMultiLevelGeometry:
    """Verify 3 concentric circular annular levels (Core -> 4 Blocks -> 16 Subsystems)."""

    def test_three_concentric_circular_annular_levels(self):
        """Verify canonical tree topology: Level 0 Core, Level 1 4 Blocks, Level 2 16 Subsystems."""
        root = create_canonical_refinery_sunburst()

        # Level 0 (Central Core): Overall Plant Refinery Energy & KPI Health (Radius 0..80px)
        assert root.level == 0
        assert root.id == "PLANT_CORE"
        assert math.isclose(root.value, 1000.0, rel_tol=1e-5)
        assert root.r_inner == LEVEL0_R_INNER == 0.0
        assert root.r_outer == LEVEL0_R_OUTER == SUNBURST_CORE_RADIUS == 80.0

        # Level 1 (Inner Annular Ring): 4 Production Blocks (Radius 90..190px)
        assert len(root.children) == 4
        expected_blocks = [
            ("BLK_CRUDE", "Crude / Distillation", 350.0, COLOR_SKY_BLUE),
            ("BLK_CONVERSION", "Conversion FCC / HCU", 300.0, COLOR_EMERALD_GREEN),
            ("BLK_REFORMING", "Reforming / Isomerization", 200.0, COLOR_INDIGO),
            ("BLK_ALKYLATION", "Alkylation / Treating", 150.0, COLOR_AMBER),
        ]
        block_sum = 0.0
        for idx, (bid, bname, bval, bcolor) in enumerate(expected_blocks):
            b = root.children[idx]
            assert b.id == bid
            assert b.name == bname
            assert math.isclose(b.value, bval, rel_tol=1e-5)
            assert b.color == bcolor
            assert b.level == 1
            assert b.parent_id == "PLANT_CORE"
            assert b.r_inner == LEVEL1_R_INNER == 90.0
            assert b.r_outer == LEVEL1_R_OUTER == 190.0
            block_sum += b.value

        assert math.isclose(block_sum, root.value, rel_tol=1e-5)

        # Level 2 (Outer Annular Ring): 16 Equipment Subsystems (Radius 200..300px)
        total_subsystems = 0
        equipment_types_found = set()
        for b in root.children:
            assert len(b.children) == 4
            sub_sum = sum(s.value for s in b.children)
            assert math.isclose(sub_sum, b.value, rel_tol=1e-5)
            for s in b.children:
                assert s.level == 2
                assert s.parent_id == b.id
                assert s.r_inner == LEVEL2_R_INNER == 200.0
                assert s.r_outer == LEVEL2_R_OUTER == SUNBURST_MAX_RADIUS == 300.0
                equipment_types_found.add(s.equipment_type)
            total_subsystems += len(b.children)

        assert total_subsystems == 16

        # Check required equipment types: Compressors, Furnaces, Heat Exchangers, Columns, Reactors
        required_types = {"Compressors", "Furnaces", "Heat Exchangers", "Columns", "Reactors"}
        assert required_types.issubset(equipment_types_found)

        # Check concentric radial gaps: 80 to 90 (10px gap), 190 to 200 (10px gap)
        assert math.isclose(LEVEL1_R_INNER - LEVEL0_R_OUTER, 10.0, abs_tol=1e-3)
        assert math.isclose(LEVEL2_R_INNER - LEVEL1_R_OUTER, 10.0, abs_tol=1e-3)

        # Total node count across tree = 1 + 4 + 16 = 21 nodes
        all_nodes = root.get_all_nodes()
        assert len(all_nodes) == 21

        # Leaf count = 16 subsystems, leaf sum = 1000.0
        leaves = root.get_leaves()
        assert len(leaves) == 16
        assert math.isclose(sum(l.value for l in leaves), 1000.0, rel_tol=1e-5)


# ============================================================================
# Section 4: Proportional Angular Partition & Polar Arc Path Math
# ============================================================================

class TestAngularPartitionAndPolarMath:
    """Verify proportional angular partition summing to 360 deg and polar-to-Cartesian arc math."""

    def test_angular_weight_partition_sums_to_360_deg(self):
        """Verify angular weight partitions sum to exactly 360 deg (2*pi rad) across all tiers."""
        root = create_canonical_refinery_sunburst()
        layout_sunburst_diagram(root)

        # Core: 360 deg (2*pi rad)
        assert math.isclose(root.angular_span_deg, 360.0, rel_tol=1e-5)
        assert math.isclose(root.angular_span_rad, 2.0 * math.pi, rel_tol=1e-5)

        # Level 1 Blocks: 4 Blocks sum to 360 deg (2*pi rad)
        l1_sum_deg = sum(b.angular_span_deg for b in root.children)
        l1_sum_rad = sum(b.angular_span_rad for b in root.children)
        assert math.isclose(l1_sum_deg, 360.0, rel_tol=1e-4)
        assert math.isclose(l1_sum_rad, 2.0 * math.pi, rel_tol=1e-4)

        # Proportions: CDU=35%, FCC=30%, CCR=20%, ALK=15%
        assert math.isclose(root.children[0].angular_span_deg, 126.0, rel_tol=1e-3)
        assert math.isclose(root.children[1].angular_span_deg, 108.0, rel_tol=1e-3)
        assert math.isclose(root.children[2].angular_span_deg, 72.0, rel_tol=1e-3)
        assert math.isclose(root.children[3].angular_span_deg, 54.0, rel_tol=1e-3)

        # Level 2 Subsystems: 16 Subsystems sum to 360 deg (2*pi rad)
        all_subs = [s for b in root.children for s in b.children]
        assert len(all_subs) == 16
        l2_sum_deg = sum(s.angular_span_deg for s in all_subs)
        l2_sum_rad = sum(s.angular_span_rad for s in all_subs)
        assert math.isclose(l2_sum_deg, 360.0, rel_tol=1e-4)
        assert math.isclose(l2_sum_rad, 2.0 * math.pi, rel_tol=1e-4)

        # Subsystems within each block conserve parent block's angular span
        for b in root.children:
            sub_span_deg = sum(s.angular_span_deg for s in b.children)
            assert math.isclose(sub_span_deg, b.angular_span_deg, rel_tol=1e-4)

    def test_polar_to_cartesian_projection(self):
        """Verify polar_to_cartesian projects correctly at cardinal angles."""
        cx = CANVAS_CENTER_X  # 460.0
        cy = CANVAS_CENTER_Y  # 385.0
        r = 100.0

        x0, y0 = polar_to_cartesian(cx, cy, r, 0.0)
        assert math.isclose(x0, cx + r, abs_tol=1e-3)
        assert math.isclose(y0, cy, abs_tol=1e-3)

        x_pi2, y_pi2 = polar_to_cartesian(cx, cy, r, math.pi / 2.0)
        assert math.isclose(x_pi2, cx, abs_tol=1e-3)
        assert math.isclose(y_pi2, cy + r, abs_tol=1e-3)

        x_pi, y_pi = polar_to_cartesian(cx, cy, r, math.pi)
        assert math.isclose(x_pi, cx - r, abs_tol=1e-3)
        assert math.isclose(y_pi, cy, abs_tol=1e-3)

        x_3pi2, y_3pi2 = polar_to_cartesian(cx, cy, r, 3.0 * math.pi / 2.0)
        assert math.isclose(x_3pi2, cx, abs_tol=1e-3)
        assert math.isclose(y_3pi2, cy - r, abs_tol=1e-3)

    def test_annular_sector_path_grammar(self):
        """Verify annular sector path string strictly matches 'M ... A ... L ... A ... Z' grammar."""
        path_d = generate_annular_sector_path(
            r_inner=LEVEL1_R_INNER,
            r_outer=LEVEL1_R_OUTER,
            theta_start=0.0,
            theta_end=math.pi / 2.0,
            cx=CANVAS_CENTER_X,
            cy=CANVAS_CENTER_Y,
            gap_deg=DEFAULT_ANGULAR_GAP_DEG,
        )

        assert path_d.startswith("M ")
        assert " A " in path_d
        assert " L " in path_d
        assert path_d.endswith(" Z")
        parts = path_d.split()
        assert parts[0] == "M"
        assert parts.count("A") == 2
        assert parts.count("L") == 1
        assert parts[-1] == "Z"


# ============================================================================
# Section 5: Standalone W3C SVG 1.1 Vector Canvas Renderer
# ============================================================================

class TestSVGCanvasRendering:
    """Verify standalone W3C SVG 1.1 XML generation, styling, breadcrumbs, and HUD card."""

    def test_svg_generation_and_xml_parsing(self):
        """Verify rendered SVG parses cleanly with xml.etree.ElementTree."""
        canvas = create_canonical_sunburst_canvas()
        svg_content = canvas.render_svg()

        assert svg_content.startswith('<?xml version="1.0" encoding="UTF-8"?>')
        root = ET.fromstring(svg_content)
        assert root.tag.endswith("svg")
        assert root.attrib.get("width") == str(CANVAS_VIEWPORT_WIDTH)
        assert root.attrib.get("height") == str(CANVAS_VIEWPORT_HEIGHT)

    def test_svg_contains_all_structural_components(self):
        """Verify SVG contains all essential groups, rings, breadcrumbs, and HUD card components."""
        canvas = create_canonical_sunburst_canvas()
        svg_content = canvas.render_svg()

        assert 'id="canvas-header"' in svg_content
        assert 'id="radial-breadcrumb-tracker"' in svg_content
        assert 'id="sunburst-diagram"' in svg_content
        assert 'id="concentric-annular-sectors"' in svg_content
        assert 'id="center-root-metric-hub"' in svg_content
        assert 'id="hierarchical-telemetry-card"' in svg_content
        assert 'id="diagnostic-hud"' in svg_content
        assert 'id="register-space-hud"' in svg_content

    def test_all_sectors_rendered_in_svg(self):
        """Verify all 4 Blocks and 16 Subsystems are present as SVG path elements."""
        canvas = create_canonical_sunburst_canvas()
        svg_content = canvas.render_svg()

        # Check Level 1 Block paths
        assert 'id="sector-BLK_CRUDE"' in svg_content
        assert 'id="sector-BLK_CONVERSION"' in svg_content
        assert 'id="sector-BLK_REFORMING"' in svg_content
        assert 'id="sector-BLK_ALKYLATION"' in svg_content

        # Check sample Level 2 Subsystem paths
        assert 'id="sector-SS_ATM_COL"' in svg_content
        assert 'id="sector-SS_CRUDE_FURN"' in svg_content
        assert 'id="sector-SS_FCC_RX"' in svg_content
        assert 'id="sector-SS_CCR_RX"' in svg_content
        assert 'id="sector-SS_ALKY_RX"' in svg_content

    def test_selected_sector_highlight_and_breadcrumbs(self):
        """Verify selecting a sector highlights it and updates breadcrumb hierarchy."""
        canvas = create_canonical_sunburst_canvas(selected_sector=0)
        svg_content = canvas.render_svg()

        assert 'class="sector-selected"' in svg_content
        assert 'L0: Plant Core' in svg_content
        assert 'L1: Crude / Distillation' in svg_content
        assert 'L2: Atmospheric Crude Column' in svg_content
        assert 'SELECTED SECTOR [INDEX 0]' in svg_content


# ============================================================================
# Section 6: WCAG 2.1 AAA Contrast Checks
# ============================================================================

class TestWCAGContrastCompliance:
    """Verify contrast ratios for SCADA display meet WCAG 2.1 AAA specifications."""

    def test_decoupled_badge_contrast_ratio(self):
        """Verify decoupled badge contrast ratio exceeds 18:1."""
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert ratio >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert ratio > 18.0

    def test_dark_theme_text_contrast_ratio(self):
        """Verify primary text on dark theme backing exceeds 7.0:1 AAA target."""
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert ratio >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert ratio > 7.0

    def test_scada_graphical_contrast_ratios(self):
        """Verify SCADA graphical colors on dark backing exceed 3.0:1 target."""
        for color, name in [
            (COLOR_EMERALD_GREEN, "Emerald"),
            (COLOR_CYAN, "Cyan"),
            (COLOR_SKY_BLUE, "Sky Blue"),
            (COLOR_INDIGO, "Indigo"),
            (COLOR_AMBER, "Amber"),
            (COLOR_CRIMSON, "Crimson"),
        ]:
            ratio = calculate_contrast_ratio(color, COLOR_DARK_THEME_BACKING)
            assert ratio >= WCAG_GRAPHICAL_CONTRAST_TARGET, f"{name} contrast {ratio:.2f} < 3.0"

    def test_validate_wcag_aaa_contrast_helper(self):
        """Verify validate_wcag_aaa_contrast helper returns True and valid ratios."""
        ok, text_cr, badge_cr = validate_wcag_aaa_contrast()
        assert ok is True
        assert text_cr >= 7.0
        assert badge_cr >= 18.0


# ============================================================================
# Section 7: Process Safety Trips & Diagnostics
# ============================================================================

class TestProcessSafetyTrips:
    """Verify process safety trips (0xC701, 0xC702, 0xC703) and coil assertion (%M315, %M316)."""

    def test_nominal_operational_state(self):
        """Verify nominal canvas state has no safety trips and status code 0x0000."""
        canvas = create_canonical_sunburst_canvas()
        assert canvas.safety_trip is False
        assert canvas.sunburst_hierarchy_trip is False
        assert canvas.diagnostic_code == SUNBURST_ERR_OK
        assert canvas.diagnostic_code == 0x0000
        assert canvas.reg_table.read_bit("%M315") is False
        assert canvas.reg_table.read_bit("%M316") is True
        assert canvas.reg_table.read_word("%R1357") == 0

    def test_hierarchy_sum_fault_0xc701(self):
        """Verify hierarchy sum mismatch triggers 0xC701 and asserts %M315."""
        canvas = create_canonical_sunburst_canvas()
        canvas.trigger_hierarchy_sum_fault(parent_id="BLK_CRUDE", mismatch_pct=10.0)

        assert canvas.safety_trip is True
        assert canvas.sunburst_hierarchy_trip is True
        assert canvas.reg_table.read_bit("%M315") is True
        assert canvas.diagnostic_code == SUNBURST_ERR_HIERARCHY_SUM_FAULT
        assert canvas.diagnostic_code == 0xC701
        assert canvas.diagnostic_code == -14591

        # Register check: signed 16-bit representation
        diag_reg = canvas.reg_table.read_word("%R1357")
        assert diag_reg == -14591
        assert DiagnosticCode(diag_reg) == 0xC701
        assert bool(canvas.status_bits & SunburstStatusBits.HIERARCHY_SUM_TRIP)

    def test_polar_bounds_fault_0xc702(self):
        """Verify polar bounds fault triggers 0xC702."""
        canvas = create_canonical_sunburst_canvas()
        canvas.trigger_polar_bounds_fault(node_id="SS_ATM_COL")

        assert canvas.diagnostic_code == SUNBURST_ERR_POLAR_BOUNDS_FAULT
        assert canvas.diagnostic_code == 0xC702
        assert canvas.diagnostic_code == -14590

        diag_reg = canvas.reg_table.read_word("%R1357")
        assert diag_reg == -14590
        assert DiagnosticCode(diag_reg) == 0xC702
        assert bool(canvas.status_bits & SunburstStatusBits.POLAR_BOUNDS_FAULT)

    def test_render_fault_0xc703(self):
        """Verify render fault latches 0xC703 into %R1357."""
        canvas = create_canonical_sunburst_canvas()
        canvas.trigger_render_fault()

        assert canvas.diagnostic_code == SUNBURST_ERR_RENDER_FAULT
        assert canvas.diagnostic_code == 0xC703
        assert canvas.diagnostic_code == -14589
        assert canvas.reg_table.read_word("%R1357") == -14589

    def test_reset_nominal_restores_clean_state(self):
        """Verify reset_nominal cleanly restores nominal operational state."""
        canvas = create_canonical_sunburst_canvas()
        canvas.trigger_hierarchy_sum_fault()
        assert canvas.safety_trip is True

        canvas.reset_nominal()
        assert canvas.safety_trip is False
        assert canvas.sunburst_hierarchy_trip is False
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.reg_table.read_bit("%M315") is False
        assert canvas.reg_table.read_word("%R1357") == 0


# ============================================================================
# Section 8: Horner OCS Register Space Synchronization & Scan Cycle
# ============================================================================

class TestHornerRegisterSynchronization:
    """Verify memory synchronization for %R1350..%R1357 and %M315..%M316."""

    def test_initial_register_bindings_values(self):
        """Verify initial register values match W174 specification."""
        canvas = create_canonical_sunburst_canvas(selected_sector=0, selected_depth=2)
        reg = canvas.reg_table

        # %R1350: TotalEnergyEfficiencyScoreScaled (89.5% -> 895)
        assert reg.read_word("%R1350") == 895
        # %R1351: SelectedDepthLevel (2)
        assert reg.read_word("%R1351") == 2
        # %R1352: SelectedSectorIndex (0)
        assert reg.read_word("%R1352") == 0
        # %R1353: Level1PrimaryUnitScoreScaled (92.0% -> 920)
        assert reg.read_word("%R1353") == 920
        # %R1354: Level2SubsystemScoreScaled (86.5% -> 865)
        assert reg.read_word("%R1354") == 865
        # %R1355: MaxHierarchyDeviationScaled (5.5% -> 55)
        assert reg.read_word("%R1355") == 55
        # %R1356: ActiveSectorsCount (16)
        assert reg.read_word("%R1356") == 16
        # %R1357: DiagnosticStatusCode (0)
        assert reg.read_word("%R1357") == 0
        # %M315: SunburstHierarchyTrip (False)
        assert reg.read_bit("%M315") is False
        # %M316: SunburstCanvasActive (True)
        assert reg.read_bit("%M316") is True

    def test_privilege_mode_system_on_writes(self):
        """Verify writes are performed with PrivilegeMode.SYSTEM without raising permission errors."""
        reg_table = RegisterTable()
        canvas = SunburstCanvas(reg_table=reg_table)
        canvas.sync_to_registers()

        assert reg_table.read_word("%R1350") == 895
        assert reg_table.read_bit("%M316") is True

    def test_ilogicunit_protocol_compliance(self):
        """Verify ILogicUnit contract properties and methods."""
        canvas = create_canonical_sunburst_canvas()
        assert isinstance(canvas, ILogicUnit)
        assert canvas.name == "SunburstHierarchyCanvasSync"
        assert canvas.priority == 94
        assert canvas.is_enabled is True

    def test_scan_step_execution(self):
        """Verify scan_step(dt) recalculates telemetry and syncs memory."""
        canvas = create_canonical_sunburst_canvas()
        canvas.scan_step(dt=0.01)

        assert canvas.reg_table.read_word("%R1350") == 895
        assert canvas.reg_table.read_word("%R1356") == 16

    def test_discrete_scan_cycle_interlock_trip(self):
        """Verify execute(context) latches trip and writes coils according to %M316 state."""
        canvas = create_canonical_sunburst_canvas()
        ctx = create_mock_scan_context(cycle=1, reg_table=canvas.reg_table)

        # 1. Nominal scan
        canvas.execute(ctx)
        assert canvas.reg_table.read_bit("%M315") is False

        # 2. Hierarchy sum fault
        canvas.trigger_hierarchy_sum_fault()
        canvas.execute(ctx)
        assert canvas.reg_table.read_bit("%M315") is True
        assert canvas.reg_table.read_word("%R1357") == -14591

        # 3. Canvas inactive (%M316=False) forces %M315=False
        canvas.reg_table.write_bit("%M316", False, privilege=PrivilegeMode.SYSTEM)
        canvas.execute(ctx)
        assert canvas.reg_table.read_bit("%M315") is False


# ============================================================================
# Section 9: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestVerificationSuiteIntegration:
    """Verify 9-stage verification suite produces deterministic contract JSON and SVG deliverable."""

    def test_complete_9_stage_verification_suite(self, tmp_path: Path):
        """Verify run_sunburst_canvas_verification runs all 9 stages cleanly."""
        ev_file = tmp_path / "sunburst_evidence.json"
        svg_file = tmp_path / "sunburst_sample.svg"

        result = run_sunburst_canvas_verification(
            output_path=str(ev_file),
            sample_svg_path=str(svg_file),
        )

        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["checks_passed"] == 9
        assert result["data"]["total_checks"] == 9
        assert len(result["data"]["tests"]) == 9

        # Verify deliverables were written
        assert ev_file.exists()
        assert svg_file.exists()
        assert ev_file.stat().st_size > 0
        assert svg_file.stat().st_size > 0

        # Verify JSON content
        with open(ev_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["status"] == "success"
            assert data["data"]["work_package"] == "W174"
            assert data["data"]["gate"] == "Gate G9 / G2"
            assert data["data"]["metrics"]["sector_count_total"] == 21
            assert data["data"]["metrics"]["active_hierarchy_levels"] == 3
            assert data["data"]["metrics"]["root_throughput_scaled"] == 10000
            assert data["data"]["metrics"]["top_consumer_sector_index"] == 1
            assert data["data"]["register_map"]["analog_registers"] == "%R1350..%R1357"
            assert data["data"]["register_map"]["discrete_coils"] == "%M315..%M316"


# ============================================================================
# Section 10: DiagnosticCode, Math & Edge Cases
# ============================================================================

class TestDiagnosticCodeAndEdgeCases:
    """Verify DiagnosticCode signed/unsigned 16-bit equality and helper branches."""

    def test_diagnostic_code_signed_unsigned_equality(self):
        """Verify 16-bit signed vs unsigned equality for DiagnosticCode."""
        code = DiagnosticCode(0xC701)
        assert code == 0xC701
        assert code == 50945
        assert code == -14591
        assert int(code) == 50945
        assert hash(code) == hash(50945)

        code_b = DiagnosticCode(0xC702)
        assert code_b == -14590
        assert code_b == 50946

        code_c = DiagnosticCode(0xC703)
        assert code_c == -14589
        assert code_c == 50947

    def test_srgb_and_hex_luminance_math(self):
        """Verify sRGB channel linear conversion and hex luminance."""
        assert abs(srgb_channel_to_linear(0.02) - (0.02 / 12.92)) < 1e-6
        assert abs(srgb_channel_to_linear(0.5) - (((0.5 + 0.055) / 1.055) ** 2.4)) < 1e-6

        # 3-char vs 6-char hex
        lum3 = hex_to_relative_luminance("#FFF")
        lum6 = hex_to_relative_luminance("#FFFFFF")
        assert abs(lum3 - lum6) < 1e-4

    def test_interactive_selection_and_drilldown(self):
        """Verify interactive sector selection and zoom drill-down state machine."""
        canvas = create_canonical_sunburst_canvas(selected_sector=0)
        assert canvas.selected_sector_index == 0
        assert canvas.current_drill_tier == 2

        # Select sector 1 (Crude Preflash Furnace)
        assert canvas.select_sector(1) is True
        assert canvas.selected_sector_index == 1
        assert canvas.active_focus_node_id == "SS_CRUDE_FURN"
        assert canvas.reg_table.read_word("%R1352") == 1

        # Drill down to level 1
        assert canvas.drill_down(1) is True
        assert canvas.selected_depth_level == 1

        # Zoom in
        assert canvas.zoom_in("SS_FCC_RX") is True
        assert canvas.active_focus_node_id == "SS_FCC_RX"

        # Zoom out
        assert canvas.zoom_out() is True

        # Reset zoom
        assert canvas.reset_zoom() is True
        assert canvas.selected_sector_index == 0
        assert canvas.selected_depth_level == 0

    def test_aliases_and_factory_functions(self):
        """Verify class aliases and factory functions instantiate properly."""
        c1 = SunburstHierarchyCanvasSync()
        c2 = RadialRingPartitioningHmiSync()
        c3 = SunburstCanvasSync()
        c4 = SunburstCanvasEngine()
        assert isinstance(c1, SunburstCanvas)
        assert isinstance(c2, SunburstCanvas)
        assert isinstance(c3, SunburstCanvas)
        assert isinstance(c4, SunburstCanvas)

        sectors = create_canonical_sunburst_sectors()
        assert len(sectors) == 21
        nodes = create_canonical_sunburst_nodes()
        assert len(nodes) == 21
