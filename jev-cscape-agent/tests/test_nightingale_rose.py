"""Unit tests for Cscape HMI Dynamic Nightingale Rose / Polar Area Canvas (W126).

Work Package: W126 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.nightingale_rose import (
    ANOMALY_TRIP_CAPACITY_PCT,
    CANVAS_CENTER_X,
    CANVAS_CENTER_Y,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COLOR_ADVISORY_AMBER,
    COLOR_ADVISORY_AMBER_LIGHT,
    COLOR_DARK_THEME_BACKING,
    COLOR_DECOUPLED_BADGE,
    COLOR_NOMINAL_GREEN,
    COLOR_NOMINAL_GREEN_LIGHT,
    COLOR_SHIFT_DAY,
    COLOR_SHIFT_DAY_LIGHT,
    COLOR_SHIFT_NIGHT,
    COLOR_SHIFT_NIGHT_LIGHT,
    COLOR_SHIFT_SWING,
    COLOR_SHIFT_SWING_LIGHT,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TRIP_RED,
    COLOR_TRIP_RED_LIGHT,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DEFAULT_ANGULAR_GAP_DEG,
    DIAG_EVENT_GEOMETRY_DEGENERACY,
    DIAG_EVENT_OK,
    DIAG_EVENT_PEAK_ANOMALY,
    DIAG_EVENT_PROFILE_FAULT,
    DIAG_EVENT_PROFILE_LIMIT_BREACH,
    DIAG_EVENT_SEASONALITY_FAULT,
    GRAPHICAL_BOUNDARY_CONTRAST_RATIO,
    NIGHTINGALE_ROSE_PURE_ST_POU,
    NightingaleRoseCanvas,
    NightingaleRoseEngine,
    NightingaleRoseStatusBits,
    NOMINAL_CAPACITY_LIMIT_PCT,
    OperationalState,
    PEAK_ANOMALY_THRESHOLD,
    ProfileMode,
    RoseMetrics,
    ROSE_MAX_RADIUS,
    ROSE_HUB_RADIUS,
    RoseProfile,
    RoseStatusBits,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    calculate_contrast_ratio,
    compute_polar_area_radius,
    compute_rose_metrics,
    create_canonical_batch_profile,
    create_canonical_diurnal_profile,
    create_canonical_seasonal_profile,
    create_mock_scan_context,
    generate_nightingale_rose_svg,
    generate_rose_annular_sector_path,
    generate_rose_petal_path,
    layout_rose_diagram,
    polar_to_cartesian,
    run_nightingale_rose_verification,
    validate_wcag_aaa_contrast,
    verify_nightingale_pure_st,
    verify_nightingale_rose_pure_st,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Section 1: Verify Pure ST POU AST parsing, symbol binding, and Horner register bindings (%R870..%R877, %M203..%M204)."""
    assert verify_nightingale_rose_pure_st() is True
    assert verify_nightingale_pure_st() is True

    # SecurityGuard assertion against ladder logic
    SecurityGuard.assert_pure_st_content(NIGHTINGALE_ROSE_PURE_ST_POU)

    # Syntax validation via STParser
    res = STParser.validate_code(NIGHTINGALE_ROSE_PURE_ST_POU)
    assert res.status == AgentStatus.SUCCESS

    # AST structure and bound registers verification
    parser = STParser()
    ast = parser.parse_pou(NIGHTINGALE_ROSE_PURE_ST_POU)
    assert ast is not None
    assert ast.name == "NightingaleRoseSync"
    assert ast.pou_type == POUType.PROGRAM

    expected_registers = [
        "%R870", "%R871", "%R872", "%R873",
        "%R874", "%R875", "%R876", "%R877",
        "%M203", "%M204",
    ]
    for reg in expected_registers:
        assert reg in ast.bound_registers, f"Register {reg} must be bound in POU AST"


# ============================================================================
# 2. Section 2: Anti-Ladder Security Guard Assertion
# ============================================================================

def test_anti_ladder_security_guard_rejection() -> None:
    """Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, and rungs."""
    bad_snippets = [
        "PROGRAM Bad1 VAR X : BOOL; END_VAR ---[ ]--- END_PROGRAM",
        "PROGRAM Bad2 VAR X : BOOL; END_VAR ---( )--- END_PROGRAM",
        "PROGRAM Bad3 VAR X : BOOL; END_VAR XIC %M203; END_PROGRAM",
        "PROGRAM Bad4 VAR X : BOOL; END_VAR OTE %M204; END_PROGRAM",
        "PROGRAM Bad5 VAR X : BOOL; END_VAR RUNG 1 RoseActive := TRUE; END_PROGRAM",
        "PROGRAM Bad6 VAR X : BOOL; END_VAR NETWORK 1 END_PROGRAM",
    ]
    for snip in bad_snippets:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snip)


# ============================================================================
# 3. Section 3: Polar Area Radius Formulation (r ~ sqrt(val)) & Area Proportionality
# ============================================================================

def test_polar_area_radius_formulation_and_area_proportionality() -> None:
    """Section 3: Verify Florence Nightingale polar area formulation r ~ sqrt(val) ensuring area proportionality."""
    max_radius = 300.0
    max_val = 100.0

    # Test baseline values
    val_1 = 25.0
    val_2 = 100.0
    r_1 = compute_polar_area_radius(val_1, max_value=max_val, max_radius=max_radius)
    r_2 = compute_polar_area_radius(val_2, max_value=max_val, max_radius=max_radius)

    # With r ~ sqrt(val), r2 / r1 should be sqrt(100 / 25) = sqrt(4) = 2.0
    assert math.isclose(r_1, 150.0, rel_tol=1e-5)
    assert math.isclose(r_2, 300.0, rel_tol=1e-5)
    assert math.isclose(r_2 / r_1, 2.0, rel_tol=1e-5)

    # In a circular sector of angle delta_theta, Area = 0.5 * delta_theta * r^2.
    # Therefore Area_2 / Area_1 = (r_2 / r_1)^2 = 4.0 = val_2 / val_1.
    area_ratio = (r_2 ** 2) / (r_1 ** 2)
    val_ratio = val_2 / val_1
    assert math.isclose(area_ratio, val_ratio, rel_tol=1e-5), "Sector area must be strictly proportional to value"

    # Test 9x value increase yields 3x radius increase and exactly 9x area
    val_a = 10.0
    val_b = 90.0
    r_a = compute_polar_area_radius(val_a, max_value=max_val, max_radius=max_radius)
    r_b = compute_polar_area_radius(val_b, max_value=max_val, max_radius=max_radius)
    assert math.isclose(r_b / r_a, 3.0, rel_tol=1e-5)
    assert math.isclose((r_b ** 2) / (r_a ** 2), 9.0, rel_tol=1e-5)

    # Test boundary and edge cases
    assert compute_polar_area_radius(0.0, max_value=max_val, max_radius=max_radius) == 0.0
    assert compute_polar_area_radius(-5.0, max_value=max_val, max_radius=max_radius) == 0.0
    assert compute_polar_area_radius(max_val, max_value=max_val, max_radius=max_radius) == max_radius
    assert compute_polar_area_radius(150.0, max_value=max_val, max_radius=max_radius) == max_radius

    # Polar-to-Cartesian checks at cardinal angles
    cx, cy = 600.0, 375.0
    r = 100.0
    p_0 = polar_to_cartesian(cx, cy, r, 0.0)
    p_pi2 = polar_to_cartesian(cx, cy, r, math.pi / 2.0)
    p_pi = polar_to_cartesian(cx, cy, r, math.pi)

    assert math.isclose(p_0[0], cx + r, rel_tol=1e-4)
    assert math.isclose(p_0[1], cy, abs_tol=1e-4)
    assert math.isclose(p_pi2[0], cx, abs_tol=1e-4)
    assert math.isclose(p_pi2[1], cy + r, rel_tol=1e-4)
    assert math.isclose(p_pi[0], cx - r, rel_tol=1e-4)
    assert math.isclose(p_pi[1], cy, abs_tol=1e-4)

    # Angular sweep partitioning check: sum of sector spans = 2*pi
    profile = create_canonical_diurnal_profile()
    layout_rose_diagram(profile)
    total_span = sum(s.angular_span_rad for s in profile.sectors)
    assert math.isclose(total_span, 2.0 * math.pi, rel_tol=1e-4)
    assert len(profile.sectors) == 24


# ============================================================================
# 4. Section 4: SVG Arc Sector Path Generation ('M ... L ... A ... Z') & XML Validity
# ============================================================================

def test_svg_arc_sector_path_generation_and_xml_validity() -> None:
    """Section 4: SVG arc sector path generation strictly adhering to 'M ... L ... A ... Z' grammar and XML validity."""
    cx, cy = 600.0, 375.0
    r = 200.0
    theta0 = 0.0
    theta1 = math.pi / 6.0  # 30 deg

    path_d = generate_rose_petal_path(
        center_x=cx,
        center_y=cy,
        radius=r,
        theta_start_rad=theta0,
        theta_end_rad=theta1,
    )

    # Assert exact grammar ('M ... L ... A ... Z')
    assert path_d.startswith("M ")
    assert " L " in path_d
    assert " A " in path_d
    assert path_d.endswith(" Z")
    assert path_d.count(" M ") == 0
    assert path_d.count(" A ") == 1
    assert path_d.count(" L ") == 1

    # Test annular sector path helper
    annular_path = generate_rose_annular_sector_path(
        center_x=cx,
        center_y=cy,
        r_inner=50.0,
        r_outer=150.0,
        theta_start_rad=0.0,
        theta_end_rad=math.pi / 4.0,
    )
    assert annular_path.startswith("M ")
    assert " L " in annular_path
    assert " A " in annular_path
    assert annular_path.endswith(" Z")
    assert annular_path.count(" A ") == 2

    # Render complete SVG and validate XML schema
    canvas = NightingaleRoseCanvas()
    svg_content = canvas.render_svg()

    parsed_tree = ET.fromstring(svg_content)
    assert parsed_tree.tag == "{http://www.w3.org/2000/svg}svg"
    assert parsed_tree.attrib["width"] == "1200"
    assert parsed_tree.attrib["height"] == "750"

    # Structure checks
    assert COLOR_DARK_THEME_BACKING in svg_content
    assert 'id="diagnostic-hud"' in svg_content
    assert 'id="nightingale-rose-petals"' in svg_content
    assert 'id="polar-grid-rings"' in svg_content
    assert 'id="sector-labels"' in svg_content
    assert 'HORNER OCS REGISTER SPACE' in svg_content


# ============================================================================
# 5. Section 5: WCAG 2.1 AAA Contrast Ratio Checks (> 7.0:1 Text, > 3.0:1 Graphical)
# ============================================================================

def test_wcag_21_aaa_contrast_ratio_checks() -> None:
    """Section 5: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge)."""
    # Palette definition checks
    assert COLOR_NOMINAL_GREEN == "#107C41"
    assert COLOR_NOMINAL_GREEN_LIGHT == "#27AE60"
    assert COLOR_ADVISORY_AMBER == "#D83B01"
    assert COLOR_ADVISORY_AMBER_LIGHT == "#F39C12"
    assert COLOR_TRIP_RED == "#A80000"
    assert COLOR_TRIP_RED_LIGHT == "#E74C3C"
    assert COLOR_DARK_THEME_BACKING == "#0F172A"
    assert COLOR_DECOUPLED_BADGE == "#0B0F19"
    assert COLOR_TEXT_PRIMARY == "#F8FAFC"

    # Contrast ratios
    contrast_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    contrast_dark_text = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    contrast_graphic = calculate_contrast_ratio(COLOR_NOMINAL_GREEN_LIGHT, COLOR_DARK_THEME_BACKING)
    contrast_amber = calculate_contrast_ratio(COLOR_ADVISORY_AMBER_LIGHT, COLOR_DARK_THEME_BACKING)
    contrast_red = calculate_contrast_ratio(COLOR_TRIP_RED_LIGHT, COLOR_DARK_THEME_BACKING)
    contrast_night = calculate_contrast_ratio(COLOR_SHIFT_NIGHT_LIGHT, COLOR_DARK_THEME_BACKING)
    contrast_day = calculate_contrast_ratio(COLOR_SHIFT_DAY_LIGHT, COLOR_DARK_THEME_BACKING)
    contrast_swing = calculate_contrast_ratio(COLOR_SHIFT_SWING_LIGHT, COLOR_DARK_THEME_BACKING)

    # Assert WCAG 2.1 AAA targets
    assert contrast_badge >= WCAG_AAA_TEXT_CONTRAST_TARGET
    assert contrast_badge > 18.0  # Decoupled badge > 18:1
    assert contrast_dark_text >= WCAG_AAA_TEXT_CONTRAST_TARGET
    assert contrast_graphic >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_amber >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_red >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_night >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_day >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert contrast_swing >= WCAG_GRAPHICAL_CONTRAST_TARGET

    # validate_wcag_aaa_contrast function
    ok, t_cr, g_cr = validate_wcag_aaa_contrast()
    assert ok is True
    assert t_cr >= 7.0
    assert g_cr >= 3.0


# ============================================================================
# 6. Section 6: Cyclic Operational Profile State Machine & Peak Anomaly Detection
# ============================================================================

def test_cyclic_profile_state_machine_and_peak_anomaly_detection() -> None:
    """Section 6: Cyclic operational profile state machine (Diurnal/Seasonal/Batch) and peak anomaly detection (%M203, code 0x9701)."""
    # 1. State machine transitions
    canvas = NightingaleRoseCanvas()
    assert canvas.current_mode == ProfileMode.DIURNAL
    assert len(canvas.profile.sectors) == 24
    assert canvas.profile.sectors[0].sector_id == "H00"
    assert canvas.profile.sectors[23].sector_id == "H23"

    # Switch to Seasonal (12 months)
    canvas.set_profile_mode(ProfileMode.SEASONAL)
    assert canvas.current_mode == ProfileMode.SEASONAL
    assert len(canvas.profile.sectors) == 12
    assert canvas.profile.sectors[0].sector_id == "JAN"
    assert canvas.profile.sectors[11].sector_id == "DEC"

    # Switch to Batch (8 stages)
    canvas.set_profile_mode(ProfileMode.BATCH)
    assert canvas.current_mode == ProfileMode.BATCH
    assert len(canvas.profile.sectors) == 8
    assert canvas.profile.sectors[0].sector_id == "P1_FILL"
    assert canvas.profile.sectors[7].sector_id == "P8_CIP"

    # Switch back to Diurnal
    canvas.set_profile_mode(ProfileMode.DIURNAL)
    assert canvas.current_mode == ProfileMode.DIURNAL
    assert len(canvas.profile.sectors) == 24

    # 2. Nominal baseline (no anomaly)
    assert canvas.reg_table.read_bit("%M203") is False
    assert canvas.reg_table.read_bit("%M204") is False
    assert canvas.diagnostic_code == DIAG_EVENT_OK

    # 3. Peak anomaly detection (%M203, code 0x9701)
    profile_anom = create_canonical_diurnal_profile(anomaly=True)
    canvas_anom = NightingaleRoseCanvas(profile=profile_anom)

    assert canvas_anom.metrics.has_anomaly is True
    assert canvas_anom.metrics.anomaly_sector_id == "H14"
    assert canvas_anom.reg_table.read_bit("%M203") is True
    assert canvas_anom.reg_table.read_bit("%M204") is True
    assert canvas_anom.diagnostic_code == DIAG_EVENT_PEAK_ANOMALY
    assert canvas_anom.diagnostic_code == 0x9701
    assert bool(canvas_anom.status_bits & RoseStatusBits.PEAK_ANOMALY_ALARM) is True
    assert bool(canvas_anom.status_bits & RoseStatusBits.ANOMALY_HIGHLIGHTED) is True
    assert bool(canvas_anom.status_bits & RoseStatusBits.PROFILE_LIMIT_TRIP) is True

    # Check operational state of the anomalous sector
    sec14 = canvas_anom.profile.get_sector("H14")
    assert sec14 is not None
    assert sec14.operational_state == OperationalState.TRIP
    assert sec14.resolve_color() == COLOR_TRIP_RED_LIGHT
    assert sec14.resolve_stroke_color() == COLOR_TRIP_RED


# ============================================================================
# 7. Section 7: Horner OCS Register Space Synchronization (%R870..%R877, %M203..%M204)
# ============================================================================

def test_horner_ocs_register_space_synchronization() -> None:
    """Section 7: Horner OCS register space synchronization (%R870..%R877, %M203..%M204) and scan cycle execution."""
    canvas = NightingaleRoseCanvas()
    reg = canvas.reg_table

    r870 = reg.read_uword("%R870")
    r871 = reg.read_word("%R871")
    r872 = reg.read_word("%R872")
    r873 = reg.read_word("%R873")
    r874 = reg.read_word("%R874")
    r875 = reg.read_word("%R875")
    r876 = reg.read_word("%R876")
    r877 = reg.read_word("%R877")
    m203 = reg.read_bit("%M203")
    m204 = reg.read_bit("%M204")

    # Status word bit checks
    assert bool(r870 & int(RoseStatusBits.CANVAS_ACTIVE)) is True
    assert bool(r870 & int(RoseStatusBits.ROSE_COMPUTED)) is True
    assert bool(r870 & int(RoseStatusBits.PROFILE_CONSERVED)) is True
    assert bool(r870 & int(RoseStatusBits.WCAG_AAA)) is True

    # Register values
    assert r871 == 24      # 24 sectors in Diurnal mode
    assert r872 == 2       # 2 series: power, thermal
    assert r873 == 14125   # 1412.5 MW total scaled x10
    assert r874 == 810     # Peak sector 81.0 MW scaled x10
    assert r875 == 14      # Peak sector hour 14
    assert r876 == 0       # Mode: 0=DIURNAL
    assert r877 == DIAG_EVENT_OK
    assert m203 is False
    assert m204 is False

    # ILogicUnit interface & Scan cycle execution
    assert canvas.name == "NightingaleRoseSync"
    assert canvas.priority == 75
    assert canvas.is_enabled is True

    ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=reg)
    canvas.execute(ctx)
    canvas.step()
    canvas.execute_logic(ctx)

    # Injected profile fault test (%M204 trip)
    profile_fault = create_canonical_diurnal_profile(fault=True)
    canvas_fault = NightingaleRoseCanvas(profile=profile_fault)
    canvas_fault.diagnostic_code = DIAG_EVENT_PROFILE_FAULT
    canvas_fault.sync_to_registers()

    assert canvas_fault.reg_table.read_bit("%M204") is True
    assert canvas_fault.reg_table.read_word("%R877") == DIAG_EVENT_PROFILE_FAULT

    # Reset test
    canvas_fault.reset()
    assert canvas_fault.current_mode == ProfileMode.DIURNAL
    assert canvas_fault.diagnostic_code == DIAG_EVENT_OK
    assert canvas_fault.reg_table.read_bit("%M204") is False


# ============================================================================
# 8. Section 8: 9-Stage Verification Suite Integration Test
# ============================================================================

def test_run_nightingale_rose_verification_suite(tmp_path: Path) -> None:
    """Section 8: 9-stage verification suite integration test writing evidence JSON and SVG."""
    evidence_file = tmp_path / "nightingale_rose_evidence.json"
    svg_file = tmp_path / "nightingale_rose_sample.svg"

    result = run_nightingale_rose_verification(
        output_path=evidence_file,
        sample_svg_path=svg_file,
    )

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert result["data"]["checks_passed"] == 9
    assert result["data"]["total_checks"] == 9
    assert len(result["data"]["tests"]) == 9
    assert evidence_file.exists()
    assert svg_file.exists()

    # Verify JSON content structure
    with open(evidence_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["status"] == "success"
    assert data["data"]["work_package"] == "W126"
    assert data["data"]["gate"] == "Gate G9 / G2"
    assert data["data"]["register_map"]["analog_registers"] == "%R870..%R877"
    assert data["data"]["register_map"]["discrete_coils"] == "%M203..%M204"

    # Verify SVG file XML validity
    svg_tree = ET.parse(svg_file)
    root = svg_tree.getroot()
    assert root.attrib["width"] == "1200"
    assert root.attrib["height"] == "750"
