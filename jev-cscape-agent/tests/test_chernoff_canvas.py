"""Comprehensive pytest test suite for Cscape HMI Dynamic Chernoff Faces / Multi-Parameter Glyph Condition Canvas (W138).

Work Package: W138 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment (following tests/test_marimekko_canvas.py):
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R990..%R997, %M231..%M232).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Chernoff parametric facial feature geometry (ellipse radii, eye aspect ratio, eyebrow angle, nose span, mouth curvature Bezier).
4. Section 4: Standalone W3C SVG 1.1 XML generation, multi-glyph 4-unit grid layout, and path grammar.
5. Section 5: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
6. Section 6: Process safety trips (distress trip 0xA301, out of bounds 0xA302) and Horner coil assertion (%M231, %M232).
7. Section 7: Horner OCS register space synchronization (%R990..%R997, %M231..%M232).
8. Section 8: 9-stage verification suite integration test writing evidence JSON and sample SVG.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import re
import pytest
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.chernoff_canvas import (
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    CHERNOFF_ERR_DISTRESS,
    CHERNOFF_ERR_GLYPH_RENDER_FAULT,
    CHERNOFF_ERR_MACHINE_DISTRESS,
    CHERNOFF_ERR_PARAMETER_OUT_OF_BOUNDS,
    CHERNOFF_ERR_PROCESS_DISTRESS,
    CHERNOFF_PURE_ST_POU,
    COLOR_ADVISORY_AMBER,
    COLOR_ADVISORY_AMBER_DARK,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DECOUPLED_BADGE,
    COLOR_DISTRESS_RED,
    COLOR_DISTRESS_RED_DARK,
    COLOR_FOCUS_OUTLINE,
    COLOR_NOMINAL_GREEN,
    COLOR_NOMINAL_GREEN_DARK,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DIAG_EVENT_DISTRESS,
    DIAG_EVENT_GLYPH_RENDER_FAULT,
    DIAG_EVENT_MACHINE_DISTRESS,
    DIAG_EVENT_OK,
    DIAG_EVENT_PARAM_OUT_OF_BOUNDS,
    DIAG_EVENT_PARAMETER_OUT_OF_BOUNDS,
    DIAG_EVENT_RENDER_FAULT,
    GRAPHICAL_BOUNDARY_CONTRAST_RATIO,
    HEALTH_DISTRESS_LIMIT_PCT,
    HEALTH_DISTRESS_SCALED,
    MOUTH_DISTRESS_LIMIT_PCT,
    MOUTH_DISTRESS_SCALED,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    ChernoffCanvas,
    ChernoffCanvasStatusBits,
    ChernoffCanvasSync,
    ChernoffEngine,
    ChernoffHmiSync,
    ChernoffParametricFace,
    ChernoffStatusBits,
    DiagnosticCode,
    EquipmentGlyph,
    calculate_contrast_ratio,
    create_canonical_chernoff_canvas,
    create_canonical_equipment_glyphs,
    create_canonical_glyphs,
    create_mock_scan_context,
    generate_chernoff_canvas_svg,
    hex_to_relative_luminance,
    run_chernoff_canvas_verification,
    srgb_channel_to_linear,
    validate_glyph_parameters,
    validate_wcag_aaa_contrast,
    verify_chernoff_canvas_pure_st,
    verify_chernoff_pure_st,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Verify Pure ST POU AST parsing, symbol binding, and Horner register bindings (%R990..%R997, %M231..%M232)."""
    assert verify_chernoff_canvas_pure_st() is True
    assert verify_chernoff_pure_st() is True

    # Validate with SecurityGuard directly
    SecurityGuard.assert_pure_st_content(CHERNOFF_PURE_ST_POU)

    # Parse with STParser
    parser = STParser()
    ast = parser.parse_pou(CHERNOFF_PURE_ST_POU)

    assert ast is not None
    assert ast.name == "ChernoffCanvasSync"
    assert ast.pou_type == POUType.PROGRAM

    # Verify bound registers in AST (%R990..%R997, %M231..%M232)
    expected_registers = {
        "%R990", "%R991", "%R992", "%R993",
        "%R994", "%R995", "%R996", "%R997",
        "%M231", "%M232",
    }
    ast_registers = set(ast.bound_registers)
    for reg in expected_registers:
        assert reg in ast_registers, f"Expected register {reg} not found in parsed AST bound registers."

    # Verify variable names and types
    var_dict = {v.name: v for v in ast.variables}
    assert "FaceSizeScaled" in var_dict
    assert var_dict["FaceSizeScaled"].data_type == "INT"
    assert var_dict["FaceSizeScaled"].address_binding == "%R990"

    assert "MouthCurvatureScaled" in var_dict
    assert var_dict["MouthCurvatureScaled"].data_type == "INT"
    assert var_dict["MouthCurvatureScaled"].address_binding == "%R991"

    assert "EyeEccentricityScaled" in var_dict
    assert var_dict["EyeEccentricityScaled"].data_type == "INT"
    assert var_dict["EyeEccentricityScaled"].address_binding == "%R992"

    assert "EyebrowSlantScaled" in var_dict
    assert var_dict["EyebrowSlantScaled"].data_type == "INT"
    assert var_dict["EyebrowSlantScaled"].address_binding == "%R993"

    assert "NoseLengthScaled" in var_dict
    assert var_dict["NoseLengthScaled"].data_type == "INT"
    assert var_dict["NoseLengthScaled"].address_binding == "%R994"

    assert "OverallHealthIndexScaled" in var_dict
    assert var_dict["OverallHealthIndexScaled"].data_type == "INT"
    assert var_dict["OverallHealthIndexScaled"].address_binding == "%R995"

    assert "ActiveUnitGlyphIndex" in var_dict
    assert var_dict["ActiveUnitGlyphIndex"].data_type == "INT"
    assert var_dict["ActiveUnitGlyphIndex"].address_binding == "%R996"

    assert "DiagnosticStatusCode" in var_dict
    assert var_dict["DiagnosticStatusCode"].data_type == "INT"
    assert var_dict["DiagnosticStatusCode"].address_binding == "%R997"

    assert "MachineDistressTrip" in var_dict
    assert var_dict["MachineDistressTrip"].data_type == "BOOL"
    assert var_dict["MachineDistressTrip"].address_binding == "%M231"

    assert "ChernoffGlyphActive" in var_dict
    assert var_dict["ChernoffGlyphActive"].data_type == "BOOL"
    assert var_dict["ChernoffGlyphActive"].address_binding == "%M232"

    # Validate source code
    val_res = STParser.validate_code(CHERNOFF_PURE_ST_POU)
    assert val_res.status == AgentStatus.SUCCESS


# ============================================================================
# Section 2: Anti-Ladder Security Guard Asserting LadderForbiddenError
# ============================================================================

def test_ladder_construct_rejection() -> None:
    """Verify aggressive rejection of ladder logic contacts, coils, rungs, mnemonics with LadderForbiddenError."""
    forbidden_snippets = [
        "PROGRAM BadFace VAR Active : BOOL; END_VAR ---[ ]--- END_PROGRAM",
        "PROGRAM BadFace VAR Active : BOOL; END_VAR ---[/]--- END_PROGRAM",
        "PROGRAM BadFace VAR Active : BOOL; END_VAR ---( )--- END_PROGRAM",
        "PROGRAM BadFace VAR Active : BOOL; END_VAR ---(S)--- END_PROGRAM",
        "PROGRAM BadFace VAR Active : BOOL; END_VAR ---(R)--- END_PROGRAM",
        "PROGRAM BadFace RUNG 1: XIC %M232 OTE %M231; END_RUNG END_PROGRAM",
        "PROGRAM BadFace NETWORK 1: LD %M232 ST %M231; END_PROGRAM",
    ]

    for snippet in forbidden_snippets:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

        val_res = STParser.validate_code(snippet)
        assert val_res.status == AgentStatus.FAILED
        assert val_res.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# Section 3: Chernoff Parametric Facial Feature Geometry
# ============================================================================

def test_chernoff_parametric_facial_geometry() -> None:
    """Verify Herman Chernoff parametric facial geometry (ellipse radii, eye aspect ratio, eyebrow angle, nose span, mouth curvature Bezier)."""
    glyph = EquipmentGlyph(
        unit_id=0,
        name="Unit 1 Test",
        equipment_type="Test Unit",
        load_pct=75.0,
        variance_pct=40.0,
        gradient_pct=70.0,
        vibration_pct=60.0,
        health_pct=85.0,
    )

    face = glyph.compute_geometry(cx=200.0, cy=200.0)

    # 1. Head shape / ellipse radii (Rx, Ry) mapped to equipment load
    expected_rx = 48.0 + 0.75 * 24.0  # 66.0
    expected_ry = 64.0 + 0.75 * 28.0  # 85.0
    assert math.isclose(face.rx, expected_rx, rel_tol=1e-3)
    assert math.isclose(face.ry, expected_ry, rel_tol=1e-3)

    # 2. Eye eccentricity & aspect ratio mapped to sensor variance
    expected_eye_rx = 8.5 + 0.40 * 5.5  # 10.7
    expected_eye_ry = 11.5 - 0.40 * 5.0  # 9.5
    assert math.isclose(face.eye_rx, expected_eye_rx, rel_tol=1e-3)
    assert math.isclose(face.eye_ry, expected_eye_ry, rel_tol=1e-3)
    assert face.left_eye_cx < 200.0 < face.right_eye_cx
    assert face.left_eye_cy == face.right_eye_cy

    # 3. Eyebrow slant & angle mapped to rate-of-change / temperature gradient
    # Positive gradient furrows brow (inner end lower, outer end higher)
    assert face.left_brow_p1[1] > face.left_brow_p2[1]
    assert face.right_brow_p1[1] > face.right_brow_p2[1]

    # 4. Nose vertical length & width span mapped to vibration / pressure
    expected_nose_len = 16.0 + 0.60 * 18.0  # 26.8
    assert math.isclose(face.nose_p2[1] - face.nose_p1[1], expected_nose_len, rel_tol=1e-3)
    assert math.isclose(face.nose_p3[1] - face.nose_p1[1], expected_nose_len, rel_tol=1e-3)

    # 5. Mouth curvature Bezier curve 'M x1 y1 Q xc yc x2 y2' (frown < 500 < smile)
    assert "M " in face.mouth_path_d
    assert " Q " in face.mouth_path_d

    # Test smile (health > 50% -> control point pulled downward yc > y1)
    assert face.mouth_pc[1] > face.mouth_p1[1]

    # Test neutral (health = 50% -> control point on horizontal line yc == y1)
    glyph_neutral = EquipmentGlyph(unit_id=0, name="Neutral", equipment_type="Test", health_pct=50.0)
    face_neutral = glyph_neutral.compute_geometry(200.0, 200.0)
    assert math.isclose(face_neutral.mouth_pc[1], face_neutral.mouth_p1[1], abs_tol=1e-3)

    # Test frown (health < 50% -> control point pulled upward yc < y1)
    glyph_frown = EquipmentGlyph(unit_id=0, name="Frown", equipment_type="Test", health_pct=15.0)
    face_frown = glyph_frown.compute_geometry(200.0, 200.0)
    assert face_frown.mouth_pc[1] < face_frown.mouth_p1[1]


# ============================================================================
# Section 4: Standalone W3C SVG 1.1 XML Generation, 4-Unit Grid & Path Grammar
# ============================================================================

def test_multi_glyph_array_topology() -> None:
    """Verify array of 4 canonical industrial equipment units in multi-glyph grid."""
    glyphs = create_canonical_equipment_glyphs()
    assert len(glyphs) == 4

    expected_names = [
        "Unit 1 Reactor",
        "Unit 2 Turbine",
        "Unit 3 Boiler",
        "Unit 4 Feed Pump",
    ]
    for i, g in enumerate(glyphs):
        assert g.unit_id == i
        assert g.name == expected_names[i]
        assert 0.0 <= g.load_pct <= 100.0
        assert 0.0 <= g.variance_pct <= 100.0
        assert 0.0 <= g.gradient_pct <= 100.0
        assert 0.0 <= g.vibration_pct <= 100.0
        assert 0.0 <= g.health_pct <= 100.0

    # Unit 3 Boiler is advisory in canonical setup
    assert glyphs[0].condition_status == "NOMINAL"
    assert glyphs[1].condition_status == "NOMINAL"
    assert glyphs[2].condition_status == "ADVISORY"
    assert glyphs[3].condition_status == "NOMINAL"


def test_standalone_w3c_svg_canvas_rendering_and_path_grammar(tmp_path: Path) -> None:
    """Verify standalone W3C SVG 1.1 rendering, XML well-formedness, 4-unit grid layout, and path grammar."""
    canvas = create_canonical_chernoff_canvas()
    svg_code = canvas.render_svg()

    # XML well-formedness
    root = ET.fromstring(svg_code)
    assert root.tag.endswith("svg")
    assert root.attrib.get("width") == str(CANVAS_VIEWPORT_WIDTH)
    assert root.attrib.get("height") == str(CANVAS_VIEWPORT_HEIGHT)

    # Structural components
    assert 'id="canvas-backdrop"' in svg_code
    assert COLOR_DARK_THEME_BACKING in svg_code
    assert 'id="diagnostic-hud"' in svg_code
    assert 'id="chernoff-glyph-grid"' in svg_code
    assert 'id="equipment-card-unit-0"' in svg_code
    assert 'id="equipment-card-unit-1"' in svg_code
    assert 'id="equipment-card-unit-2"' in svg_code
    assert 'id="equipment-card-unit-3"' in svg_code
    assert 'id="active-unit-focus"' in svg_code
    assert 'id="register-space-hud"' in svg_code

    # Quadratic Bezier mouth curve format: 'M x1 y1 Q xc yc x2 y2'
    assert 'd="M ' in svg_code
    assert ' Q ' in svg_code

    # Path grammar verification via regex
    bezier_regex = re.compile(r'd="M\s+[\d.-]+\s+[\d.-]+\s+Q\s+[\d.-]+\s+[\d.-]+\s+[\d.-]+\s+[\d.-]+"')
    assert bezier_regex.search(svg_code) is not None

    # Alternative dark theme (#1E1E1E)
    svg_1e1e1e = canvas.render_svg(dark_theme_bg=COLOR_DARK_THEME_BACKING_1E1E1E)
    assert COLOR_DARK_THEME_BACKING_1E1E1E in svg_1e1e1e

    # SVG export to file
    out_svg = tmp_path / "test_chernoff.svg"
    with open(out_svg, "w", encoding="utf-8") as f:
        f.write(svg_code)
    assert out_svg.exists()
    assert out_svg.stat().st_size > 5000


# ============================================================================
# Section 5: WCAG 2.1 AAA Contrast Ratio Checks (> 7.0:1 text, > 3.0:1 graphics, > 18:1 badge)
# ============================================================================

def test_wcag_21_aaa_contrast_metrics() -> None:
    """Verify WCAG 2.1 AAA contrast guidelines (> 7.0:1 text, > 3.0:1 graphics, > 18:1 badge)."""
    # 1. Decoupled dark backing badge contrast (> 18:1)
    badge_contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    assert badge_contrast >= WCAG_AAA_BADGE_CONTRAST_TARGET
    assert badge_contrast > 18.0

    # 2. Primary text on canvas backdrop (> 7.0:1)
    text_canvas_contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    assert text_canvas_contrast >= WCAG_AAA_TEXT_CONTRAST_TARGET
    assert text_canvas_contrast > 7.0

    # 3. Muted text on badge (> 7.0:1)
    muted_badge_contrast = calculate_contrast_ratio(COLOR_TEXT_MUTED, COLOR_DECOUPLED_BADGE)
    assert muted_badge_contrast >= WCAG_AAA_TEXT_CONTRAST_TARGET

    # 4. SCADA condition colors on canvas backdrop (> 3.0:1)
    green_contrast = calculate_contrast_ratio(COLOR_NOMINAL_GREEN, COLOR_DARK_THEME_BACKING)
    amber_contrast = calculate_contrast_ratio(COLOR_ADVISORY_AMBER, COLOR_DARK_THEME_BACKING)
    red_contrast = calculate_contrast_ratio(COLOR_DISTRESS_RED, COLOR_DARK_THEME_BACKING)

    assert green_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert amber_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert red_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET

    # Overall validation function
    ok, t_c, g_c = validate_wcag_aaa_contrast()
    assert ok is True
    assert t_c > 7.0
    assert g_c > 3.0


# ============================================================================
# Section 6: Process Safety Trips & Horner Coil Assertion (%M231, %M232)
# ============================================================================

def test_process_distress_trip_0xa301() -> None:
    """Verify 0xA301 machine distress trip asserts %M231 when mouth curvature < 20% or health < 30%."""
    canvas = create_canonical_chernoff_canvas()

    # Nominal check
    assert canvas.machine_distress_trip is False
    assert canvas.reg_table.read_bit("%M231") is False
    assert canvas.diagnostic_code == DIAG_EVENT_OK

    # 1. Trigger distress via mouth curvature < 20%
    canvas.trigger_machine_distress(unit_idx=0, mouth_curvature=15.0, health=75.0)
    assert canvas.machine_distress_trip is True
    assert canvas.reg_table.read_bit("%M231") is True
    assert canvas.diagnostic_code == CHERNOFF_ERR_MACHINE_DISTRESS
    assert canvas.diagnostic_code == 0xA301
    assert canvas.diagnostic_code == -23807  # Signed 16-bit match
    assert bool(canvas.status_bits & ChernoffStatusBits.MACHINE_DISTRESS_TRIP)

    # 2. Trigger distress via overall health < 30%
    canvas.reset_nominal()
    assert canvas.machine_distress_trip is False
    canvas.trigger_machine_distress(unit_idx=1, mouth_curvature=70.0, health=25.0)
    assert canvas.machine_distress_trip is True
    assert canvas.reg_table.read_bit("%M231") is True
    assert canvas.diagnostic_code == 0xA301


def test_parameter_out_of_bounds_trip_0xa302() -> None:
    """Verify 0xA302 parameter out-of-bounds trip and 0xA303 glyph render fault."""
    canvas = create_canonical_chernoff_canvas()

    # 1. Trigger parameter out of bounds (0xA302)
    canvas.trigger_parameter_out_of_bounds(unit_idx=0, param_name="load_pct", val=125.0)
    assert canvas.diagnostic_code == CHERNOFF_ERR_PARAMETER_OUT_OF_BOUNDS
    assert canvas.diagnostic_code == 0xA302
    assert canvas.diagnostic_code == -23806
    assert bool(canvas.status_bits & ChernoffStatusBits.PARAM_OUT_OF_BOUNDS)

    # 2. Trigger render fault (0xA303)
    canvas.reset_nominal()
    canvas.trigger_render_fault()
    assert canvas.diagnostic_code == CHERNOFF_ERR_GLYPH_RENDER_FAULT
    assert canvas.diagnostic_code == 0xA303
    assert canvas.diagnostic_code == -23805


def test_nominal_reset_clears_trips() -> None:
    """Verify nominal reset restores clean operating state and deasserts %M231."""
    canvas = create_canonical_chernoff_canvas()
    canvas.trigger_machine_distress(unit_idx=0, mouth_curvature=10.0, health=20.0)
    assert canvas.machine_distress_trip is True

    canvas.reset_nominal()
    assert canvas.machine_distress_trip is False
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.reg_table.read_bit("%M231") is False
    assert canvas.reg_table.read_bit("%M232") is True


# ============================================================================
# Section 7: Horner OCS Register Space Synchronization (%R990..%R997, %M231..%M232)
# ============================================================================

def test_horner_ocs_register_space_synchronization() -> None:
    """Verify full Horner OCS memory map bindings (%R990..%R997, %M231..%M232) and scan cycle execution."""
    canvas = create_canonical_chernoff_canvas(active_index=0)
    ctx = create_mock_scan_context(reg_table=canvas.reg_table)

    canvas.execute(ctx)
    canvas.step()

    reg = canvas.reg_table
    assert reg.read_word("%R990") == 750   # 75.0% Load (Face Size)
    assert reg.read_word("%R991") == 885   # 88.5% Mouth Curvature
    assert reg.read_word("%R992") == 400   # 40.0% Variance (Eye Eccentricity)
    assert reg.read_word("%R993") == 450   # 45.0% Gradient (Eyebrow Slant)
    assert reg.read_word("%R994") == 350   # 35.0% Vibration (Nose Length)
    assert reg.read_word("%R995") == 885   # 88.5% Overall Health
    assert reg.read_word("%R996") == 0     # Active Unit 0
    assert reg.read_word("%R997") == 0     # 0x0000 OK
    assert reg.read_bit("%M231") is False  # Machine distress trip inactive
    assert reg.read_bit("%M232") is True   # Chernoff glyph active


def test_active_unit_focus_switching() -> None:
    """Verify switching active unit glyph index updates registers %R990..%R996."""
    canvas = create_canonical_chernoff_canvas(active_index=0)

    # Unit 0 active
    assert canvas.active_unit_index == 0
    assert canvas.reg_table.read_word("%R996") == 0
    assert canvas.reg_table.read_word("%R990") == 750  # Unit 1 load 75.0%

    # Switch to Unit 1
    canvas.set_active_unit(1)
    assert canvas.active_unit_index == 1
    assert canvas.reg_table.read_word("%R996") == 1
    assert canvas.reg_table.read_word("%R990") == 600  # Unit 2 load 60.0%

    # Switch to Unit 2
    canvas.set_active_unit(2)
    assert canvas.active_unit_index == 2
    assert canvas.reg_table.read_word("%R996") == 2
    assert canvas.reg_table.read_word("%R990") == 850  # Unit 3 load 85.0%

    # Switch to Unit 3
    canvas.set_active_unit(3)
    assert canvas.active_unit_index == 3
    assert canvas.reg_table.read_word("%R996") == 3
    assert canvas.reg_table.read_word("%R990") == 400  # Unit 4 load 40.0%


def test_logic_unit_scan_lifecycle() -> None:
    """Verify ILogicUnit interface properties and scan lifecycle methods."""
    canvas = create_canonical_chernoff_canvas()
    assert canvas.name == "ChernoffCanvasSync"
    assert canvas.priority == 82
    assert canvas.is_enabled is True

    canvas.step()
    ctx = create_mock_scan_context(reg_table=canvas.reg_table)
    canvas.execute_logic(ctx)
    canvas.reset()
    assert canvas.diagnostic_code == DIAG_EVENT_OK


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration Test
# ============================================================================

def test_deterministic_9_stage_verification_suite(tmp_path: Path) -> None:
    """Verify run_chernoff_canvas_verification executes cleanly across all 9 stages writing evidence JSON and SVG."""
    ev_path = tmp_path / "chernoff_evidence.json"
    svg_path = tmp_path / "chernoff_sample.svg"

    res = run_chernoff_canvas_verification(
        output_path=ev_path,
        sample_svg_path=svg_path,
    )

    assert res["status"] == "success"
    assert res["error_code"] is None
    assert res["data"]["checks_passed"] == 9
    assert res["data"]["total_checks"] == 9
    assert len(res["data"]["tests"]) == 9
    assert all(t["passed"] for t in res["data"]["tests"])

    # Verify evidence file written to disk
    assert ev_path.exists()
    assert ev_path.stat().st_size > 0
    with open(ev_path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["status"] == "success"
    assert loaded["data"]["work_package"] == "W138"

    # Verify sample SVG written to disk and valid
    assert svg_path.exists()
    assert svg_path.stat().st_size > 0
    with open(svg_path, "r", encoding="utf-8") as f:
        svg_content = f.read()
    root = ET.fromstring(svg_content)
    assert root.tag.endswith("svg")
