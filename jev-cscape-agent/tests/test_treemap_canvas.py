"""Unit tests for Cscape HMI Dynamic Squarified Treemap Canvas (W117).

Work Package: W117 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.treemap_canvas import (
    DIAG_EVENT_ALLOCATION_IMBALANCE,
    DIAG_EVENT_LAYOUT_DEGENERACY,
    DIAG_EVENT_OK,
    DIAG_EVENT_RESOURCE_OVERLOAD,
    HierarchyLevel,
    OPTIMAL_ASPECT_RATIO_CEILING,
    Rect,
    THERMAL_STRESS_ALARM_THRESHOLD_DEG_C,
    TREEMAP_CANVAS_PURE_ST_POU,
    TreemapCanvas,
    TreemapCanvasStatusBits,
    TreemapMetrics,
    TreemapNode,
    TreemapStatusBits,
    WCAG_AAA_CONTRAST_TARGET,
    calculate_contrast_ratio,
    compute_treemap_metrics,
    create_canonical_petrochemical_plant,
    generate_treemap_canvas_svg,
    layout_hierarchical_treemap,
    layout_squarified,
    run_treemap_canvas_verification,
    thermal_to_hex_color,
    verify_treemap_canvas_pure_st,
    verify_treemap_pure_st,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Pure ST POU AST Validation and Anti-Ladder Check
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Stage 1: Verify Pure ST POU AST parsing, absence of ladder constructs, and Horner register bindings."""
    assert verify_treemap_canvas_pure_st() is True
    assert verify_treemap_pure_st() is True

    # SecurityGuard assertion
    SecurityGuard.assert_pure_st_content(TREEMAP_CANVAS_PURE_ST_POU)

    # Syntax validation via STParser
    res = STParser.validate_code(TREEMAP_CANVAS_PURE_ST_POU)
    assert res.status == AgentStatus.SUCCESS

    # AST structure and bound registers verification
    parser = STParser()
    ast = parser.parse_pou(TREEMAP_CANVAS_PURE_ST_POU)
    assert ast is not None
    assert ast.name == "TreemapCanvasSync"
    assert ast.pou_type == POUType.PROGRAM

    expected_registers = [
        "%R780", "%R781", "%R782", "%R783",
        "%R784", "%R785", "%R786", "%R787",
        "%M182", "%M183",
    ]
    for reg in expected_registers:
        assert reg in ast.bound_registers, f"Register {reg} must be bound in POU AST"


def test_anti_ladder_security_guard_rejection() -> None:
    """Stage 1b: Verify strict fail-closed rejection of ladder contacts, coils, and mnemonics."""
    bad_snippets = [
        "PROGRAM Bad1 VAR X : BOOL; END_VAR ---[ ]--- END_PROGRAM",
        "PROGRAM Bad2 VAR X : BOOL; END_VAR ---( )--- END_PROGRAM",
        "PROGRAM Bad3 VAR X : BOOL; END_VAR XIC %M182; END_PROGRAM",
        "PROGRAM Bad4 VAR X : BOOL; END_VAR RUNG 1 TreemapActive := TRUE; END_PROGRAM",
        "PROGRAM Bad5 VAR X : BOOL; END_VAR NETWORK 1 END_PROGRAM",
    ]
    for snip in bad_snippets:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snip)


# ============================================================================
# 2. Hierarchical Resource Tree Construction & Aggregation
# ============================================================================

def test_hierarchical_plant_tree_construction_and_aggregation() -> None:
    """Stage 2: Verify 4-level plant hierarchy and exact upward resource aggregation."""
    plant = create_canonical_petrochemical_plant(overload=True)
    assert plant.level == HierarchyLevel.PLANT
    assert plant.max_depth() == 4
    assert len(plant.children) == 4

    leaves = plant.get_leaves()
    assert len(leaves) == 16

    # Verify exact conservation of resource sums across hierarchy
    sum_leaves = sum(lf.resource_kw for lf in leaves)
    sum_units = sum(u.resource_kw for u in plant.children)
    assert sum_leaves == pytest.approx(1640.0, abs=1e-4)
    assert sum_units == pytest.approx(1640.0, abs=1e-4)
    assert plant.resource_kw == pytest.approx(1640.0, abs=1e-4)

    # Subsystem counts
    subsystems: List[TreemapNode] = []
    for u in plant.children:
        subsystems.extend(u.children)
    assert len(subsystems) == 8


# ============================================================================
# 3. Squarified Treemap Layout & Aspect Ratio Optimization
# ============================================================================

def test_squarified_treemap_aspect_ratio_optimization() -> None:
    """Stage 3: Verify Bruls et al. squarified layout aspect ratio optimization towards 1.0."""
    plant = create_canonical_petrochemical_plant(overload=True)
    canvas_bounds = Rect(20.0, 86.0, 1160.0, 650.0)
    layout_hierarchical_treemap(plant, canvas_bounds)

    leaves = plant.get_leaves()
    for lf in leaves:
        assert lf.rect.width > 0.0, f"Node {lf.id} width must be positive"
        assert lf.rect.height > 0.0, f"Node {lf.id} height must be positive"
        assert lf.rect.aspect_ratio >= 1.0, f"Aspect ratio must be >= 1.0"

    aspect_ratios = [lf.rect.aspect_ratio for lf in leaves]
    mean_aspect = sum(aspect_ratios) / len(aspect_ratios)
    assert mean_aspect <= OPTIMAL_ASPECT_RATIO_CEILING
    assert max(aspect_ratios) < 6.5


# ============================================================================
# 4. Multi-Level Nested Bounding Box Containment & Padding
# ============================================================================

def test_nested_bounding_box_containment() -> None:
    """Stage 4: Verify strict containment of children within parent bounding rectangles."""
    plant = create_canonical_petrochemical_plant(overload=True)
    canvas_bounds = Rect(20.0, 86.0, 1160.0, 650.0)
    layout_hierarchical_treemap(plant, canvas_bounds)

    for unit in plant.children:
        assert canvas_bounds.contains_rect(unit.rect), f"Unit {unit.id} must be inside canvas"
        for sub in unit.children:
            assert unit.rect.contains_rect(sub.rect), f"Subsystem {sub.id} must be inside Unit {unit.id}"
            for eq in sub.children:
                assert sub.rect.contains_rect(eq.rect), f"Equipment {eq.id} must be inside Subsystem {sub.id}"


# ============================================================================
# 5. Thermal Stress & Power Color Grading Palette
# ============================================================================

def test_thermal_color_grading_palette() -> None:
    """Stage 5: Verify continuous thermal colormap generation across temperature zones."""
    c_cold = thermal_to_hex_color(20.0)
    c_nom = thermal_to_hex_color(50.0)
    c_warm = thermal_to_hex_color(75.0)
    c_crit = thermal_to_hex_color(98.5)

    for col in [c_cold, c_nom, c_warm, c_crit]:
        assert col.startswith("#")
        assert len(col) == 7

    # Distinct progressive colors
    assert c_cold != c_crit
    assert c_nom != c_crit


# ============================================================================
# 6. Overload Anomaly Detection & Outline Pulsing
# ============================================================================

def test_overload_anomaly_detection() -> None:
    """Stage 6: Verify identification of overloaded nodes and alarm activation."""
    # Test plant with overload
    plant_overload = create_canonical_petrochemical_plant(overload=True)
    m_overload = compute_treemap_metrics(plant_overload)
    assert m_overload.has_overload is True
    assert m_overload.max_thermal_stress_deg_c == pytest.approx(98.5, abs=0.1)

    # Test plant without overload
    plant_nominal = create_canonical_petrochemical_plant(overload=False)
    m_nominal = compute_treemap_metrics(plant_nominal)
    assert m_nominal.has_overload is False
    assert m_nominal.max_thermal_stress_deg_c < THERMAL_STRESS_ALARM_THRESHOLD_DEG_C


# ============================================================================
# 7. Standalone W3C SVG 1.1 Vector Canvas Generation & Layout Invariants
# ============================================================================

def test_standalone_svg_generation_and_xml_validity() -> None:
    """Stage 7: Verify standalone W3C SVG 1.1 XML parsing, HUD banner, and dark backdrop."""
    canvas = TreemapCanvas()
    svg = canvas.render_svg()

    # XML validation
    root_el = ET.fromstring(svg)
    assert root_el.tag.endswith("svg")
    assert root_el.attrib["width"] == "1200"
    assert root_el.attrib["height"] == "750"

    # Layout structure
    assert "#0F172A" in svg
    assert "#0B0F19" in svg
    assert 'id="diagnostic-hud"' in svg
    assert 'id="treemap-canvas"' in svg
    assert 'id="anomaly-glow"' in svg
    assert "F-101" in svg
    assert "K-301" in svg


# ============================================================================
# 8. WCAG 2.1 AAA Accessibility & Decoupled Backing Badges
# ============================================================================

def test_wcag_aaa_contrast_ratio() -> None:
    """Stage 8: Verify decoupled dark backing badges ensure WCAG 2.1 AAA contrast (> 18:1)."""
    contrast = calculate_contrast_ratio("#F8FAFC", "#0B0F19")
    assert contrast >= WCAG_AAA_CONTRAST_TARGET
    assert contrast > 18.0

    canvas = TreemapCanvas()
    assert (canvas.status_bits & TreemapStatusBits.WCAG_AAA) != 0


# ============================================================================
# 9. Horner OCS Memory Space Synchronization & Diagnostic Trips
# ============================================================================

def test_horner_ocs_register_synchronization_and_diagnostic_trips() -> None:
    """Stage 9: Verify register table bindings (%R780..%R787, %M182..%M183) and trip logic."""
    canvas = TreemapCanvas()
    reg = canvas.reg_table

    # %R780: TreemapStatusWord
    status_word = reg.read_uword("%R780")
    assert (status_word & int(TreemapStatusBits.CANVAS_ACTIVE)) != 0
    assert (status_word & int(TreemapStatusBits.TREEMAP_COMPUTED)) != 0
    assert (status_word & int(TreemapStatusBits.SQUARIFIED_OPTIMAL)) != 0
    assert (status_word & int(TreemapStatusBits.RESOURCE_OVERLOAD_ALARM)) != 0
    assert (status_word & int(TreemapStatusBits.SVG_VALID)) != 0
    assert (status_word & int(TreemapStatusBits.WCAG_AAA)) != 0

    # %R781: TotalLeafNodesCount
    assert reg.read_word("%R781") == 16

    # %R782: TotalResourceUsageKw (scaled x10)
    assert reg.read_word("%R782") == 16400

    # %R783: MeanAspectRatioScaled (scaled x100)
    assert reg.read_word("%R783") > 100

    # %R784: PeakNodeResourcePct (scaled x10)
    assert reg.read_word("%R784") > 100

    # %R785: MaxThermalStressDegC (scaled x10)
    assert reg.read_word("%R785") == 985

    # %R786: TreemapLevelsCount
    assert reg.read_word("%R786") == 4

    # %R787: DiagnosticEventCode
    assert reg.read_word("%R787") == DIAG_EVENT_RESOURCE_OVERLOAD

    # %M182: ResourceOverloadAlarm
    assert reg.read_bit("%M182") is True

    # Test allocation imbalance trip injection
    canvas.diagnostic_code = DIAG_EVENT_ALLOCATION_IMBALANCE
    canvas.status_bits |= TreemapStatusBits.ALLOCATION_IMBALANCE_TRIP
    canvas._sync_registers()
    assert reg.read_bit("%M183") is True
    assert reg.read_word("%R787") == DIAG_EVENT_ALLOCATION_IMBALANCE

    # Reset
    canvas.reset()
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert reg.read_bit("%M182") is False


# ============================================================================
# 10. Complete 9-Stage Verification Suite Runner and 4-State Contract
# ============================================================================

def test_full_treemap_canvas_verification_runner(tmp_path: Path) -> None:
    """Stage 10: Verify full 9-stage verification runner returning strict 4-state contract."""
    evidence_file = str(tmp_path / "treemap_evidence.json")
    svg_file = str(tmp_path / "treemap_sample.svg")

    result = run_treemap_canvas_verification(evidence_path=evidence_file, svg_path=svg_file)

    # Strict 4-State Contract
    assert result["status"] == "success"
    assert result["error_code"] is None
    assert "verified cleanly" in result["details"]

    data = result["data"]
    assert data["work_package"] == "W117"
    assert data["gate"] == "Gate G9 / G2"
    assert data["checks_passed"] == 9
    assert data["total_checks"] == 9
    assert len(data["tests"]) == 9
    assert all(t["passed"] for t in data["tests"])

    reg_map = data["register_map"]
    assert reg_map["analog_registers"] == "%R780..%R787"
    assert reg_map["discrete_coils"] == "%M182..%M183"

    assert Path(evidence_file).is_file()
    assert Path(svg_file).is_file()

    with open(evidence_file, "r", encoding="utf-8") as f:
        saved_json = json.load(f)
    assert saved_json["status"] == "success"
    assert saved_json["data"]["checks_passed"] == 9
