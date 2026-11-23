"""Comprehensive pytest test suite for Cscape HMI Dynamic UpSet Matrix Multi-Set Interlocking Canvas (W141).

Work Package: W141 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment (following tests/test_chernoff_canvas.py):
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1020..%R1027, %M238..%M239).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: UpSet matrix set intersection calculation, combination enumeration, and cardinality ranking.
4. Section 4: Standalone W3C SVG 1.1 XML generation, connected dot matrix layout, and bar charts.
5. Section 5: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
6. Section 6: Process safety trips (cascade trip 0xA601, cardinality excursion 0xA602) and Horner coil assertion (%M238, %M239).
7. Section 7: Horner OCS register space synchronization (%R1020..%R1027, %M238..%M239).
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
from jev_cscape.hmi.upset_canvas import (
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    CARDINALITY_EXCURSION_LIMIT,
    CASCADE_DEGREE_LIMIT,
    CASCADE_SEVERITY_LIMIT_PCT,
    CASCADE_SEVERITY_LIMIT_SCALED,
    COLOR_ADVISORY_AMBER,
    COLOR_ADVISORY_AMBER_DARK,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_CONNECTING_LINE,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DECOUPLED_BADGE,
    COLOR_DISTRESS_RED,
    COLOR_DISTRESS_RED_DARK,
    COLOR_FOCUS_OUTLINE,
    COLOR_INTERSECTION_BAR,
    COLOR_INTERSECTION_DOT,
    COLOR_INTERSECTION_DOT_INACTIVE,
    COLOR_NOMINAL_GREEN,
    COLOR_NOMINAL_GREEN_DARK,
    COLOR_SET_BAR,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TRIP_RED,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DIAG_EVENT_CARDINALITY_EXCURSION,
    DIAG_EVENT_CASCADE_TRIP,
    DIAG_EVENT_OK,
    DIAG_EVENT_RENDER_FAULT,
    GRAPHICAL_BOUNDARY_CONTRAST_RATIO,
    UPSET_ERR_CARDINALITY_EXCURSION,
    UPSET_ERR_CASCADE_TRIP,
    UPSET_ERR_RENDER_FAULT,
    UPSET_PURE_ST_POU,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    DiagnosticCode,
    IncidentRecord,
    PrimarySet,
    SetIntersection,
    UpSetCanvas,
    UpSetCanvasStatusBits,
    UpSetCanvasSync,
    UpSetEngine,
    UpSetHmiSync,
    UpSetStatusBits,
    calculate_contrast_ratio,
    compute_set_intersections,
    create_canonical_incidents,
    create_canonical_intersections,
    create_canonical_primary_sets,
    create_canonical_upset_canvas,
    create_mock_scan_context,
    enumerate_combinations,
    filter_intersections,
    generate_upset_canvas_svg,
    generate_upset_matrix_svg,
    hex_to_relative_luminance,
    rank_intersections_by_cardinality,
    rank_intersections_by_degree,
    run_upset_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_upset_canvas_pure_st,
    verify_upset_pure_st,
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
    """Verify Pure ST POU AST parsing, symbol binding, and Horner register bindings (%R1020..%R1027, %M238..%M239)."""
    assert verify_upset_canvas_pure_st() is True
    assert verify_upset_pure_st() is True

    # Validate with SecurityGuard directly
    SecurityGuard.assert_pure_st_content(UPSET_PURE_ST_POU)

    # Parse with STParser
    parser = STParser()
    ast = parser.parse_pou(UPSET_PURE_ST_POU)

    assert ast is not None
    assert ast.name == "UpSetCanvasSync"
    assert ast.pou_type == POUType.PROGRAM

    # Verify bound registers in AST (%R1020..%R1027, %M238..%M239)
    expected_registers = {
        "%R1020", "%R1021", "%R1022", "%R1023",
        "%R1024", "%R1025", "%R1026", "%R1027",
        "%M238", "%M239",
    }
    ast_registers = set(ast.bound_registers)
    for reg in expected_registers:
        assert reg in ast_registers, f"Expected register {reg} not found in parsed AST bound registers."

    # Verify variable names and types
    var_dict = {v.name: v for v in ast.variables}
    assert "TotalActiveSets" in var_dict
    assert var_dict["TotalActiveSets"].data_type == "INT"
    assert var_dict["TotalActiveSets"].address_binding == "%R1020"

    assert "ActiveIntersectionCardinality" in var_dict
    assert var_dict["ActiveIntersectionCardinality"].data_type == "INT"
    assert var_dict["ActiveIntersectionCardinality"].address_binding == "%R1021"

    assert "TotalCombinations" in var_dict
    assert var_dict["TotalCombinations"].data_type == "INT"
    assert var_dict["TotalCombinations"].address_binding == "%R1022"

    assert "ActiveIntersectionDegree" in var_dict
    assert var_dict["ActiveIntersectionDegree"].data_type == "INT"
    assert var_dict["ActiveIntersectionDegree"].address_binding == "%R1023"

    assert "TotalIncidentCount" in var_dict
    assert var_dict["TotalIncidentCount"].data_type == "INT"
    assert var_dict["TotalIncidentCount"].address_binding == "%R1024"

    assert "OverallSeverityIndexScaled" in var_dict
    assert var_dict["OverallSeverityIndexScaled"].data_type == "INT"
    assert var_dict["OverallSeverityIndexScaled"].address_binding == "%R1025"

    assert "ActiveCombinationIndex" in var_dict
    assert var_dict["ActiveCombinationIndex"].data_type == "INT"
    assert var_dict["ActiveCombinationIndex"].address_binding == "%R1026"

    assert "DiagnosticStatusCode" in var_dict
    assert var_dict["DiagnosticStatusCode"].data_type == "INT"
    assert var_dict["DiagnosticStatusCode"].address_binding == "%R1027"

    assert "AlarmCascadeTrip" in var_dict
    assert var_dict["AlarmCascadeTrip"].data_type == "BOOL"
    assert var_dict["AlarmCascadeTrip"].address_binding == "%M238"

    assert "UpSetCanvasActive" in var_dict
    assert var_dict["UpSetCanvasActive"].data_type == "BOOL"
    assert var_dict["UpSetCanvasActive"].address_binding == "%M239"

    # Validate source code
    val_res = STParser.validate_code(UPSET_PURE_ST_POU)
    assert val_res.status == AgentStatus.SUCCESS


# ============================================================================
# Section 2: Anti-Ladder Security Guard Asserting LadderForbiddenError
# ============================================================================

def test_ladder_construct_rejection() -> None:
    """Verify aggressive rejection of ladder logic contacts, coils, rungs, mnemonics with LadderForbiddenError."""
    forbidden_snippets = [
        "PROGRAM BadUpSet VAR Active : BOOL; END_VAR ---[ ]--- END_PROGRAM",
        "PROGRAM BadUpSet VAR Active : BOOL; END_VAR ---[/]--- END_PROGRAM",
        "PROGRAM BadUpSet VAR Active : BOOL; END_VAR ---( )--- END_PROGRAM",
        "PROGRAM BadUpSet VAR Active : BOOL; END_VAR ---(S)--- END_PROGRAM",
        "PROGRAM BadUpSet VAR Active : BOOL; END_VAR ---(R)--- END_PROGRAM",
        "PROGRAM BadUpSet RUNG 1: XIC %M239 OTE %M238; END_RUNG END_PROGRAM",
        "PROGRAM BadUpSet NETWORK 1: LD %M239 ST %M238; END_PROGRAM",
    ]

    for snippet in forbidden_snippets:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)

        val_res = STParser.validate_code(snippet)
        assert val_res.status == AgentStatus.FAILED
        assert val_res.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# Section 3: UpSet Matrix Set Intersection Calculation, Combination Enumeration & Ranking
# ============================================================================

def test_upset_primary_sets_topology() -> None:
    """Verify primary industrial interlocking sets (5 sets) topology and properties."""
    primary_sets = create_canonical_primary_sets()
    assert len(primary_sets) == 5

    expected_names = [
        "Emergency Stop",
        "Over-Pressure",
        "Over-Temperature",
        "Vibration Trip",
        "Gas Leak",
    ]
    for i, p_set in enumerate(primary_sets):
        assert p_set.set_id == i
        assert p_set.name == expected_names[i]
        assert p_set.size > 0
        assert p_set.color.startswith("#")


def test_upset_set_intersection_calculation() -> None:
    """Verify UpSet multi-set intersection calculation, degree computation, bitmasks, and severities."""
    sets = create_canonical_primary_sets()
    incidents = create_canonical_incidents()

    intersections = compute_set_intersections(sets, incidents)
    assert len(intersections) == 8

    # Verify each intersection has valid properties
    for comb in intersections:
        assert comb.combination_id >= 0
        assert len(comb.set_ids) >= 1
        assert comb.cardinality > 0
        assert comb.degree == len(comb.set_ids)
        expected_bitmask = sum(1 << sid for sid in comb.set_ids)
        assert comb.bitmask == expected_bitmask
        assert 0.0 <= comb.severity_pct <= 100.0

    # Test combination with degree 3 is cascade trip
    comb_deg3 = [c for c in intersections if c.degree == 3]
    assert len(comb_deg3) == 1
    assert comb_deg3[0].is_cascade is True
    assert set(comb_deg3[0].set_ids) == {0, 1, 2}
    assert comb_deg3[0].severity_pct >= 80.0


def test_upset_combination_enumeration_and_filtering() -> None:
    """Verify combination enumeration and threshold filtering."""
    sets = create_canonical_primary_sets()
    incidents = create_canonical_incidents()

    all_combs = enumerate_combinations(sets, incidents)
    assert len(all_combs) == 8

    # Filter by min cardinality >= 30
    filtered_card = filter_intersections(all_combs, min_cardinality=30)
    assert all(c.cardinality >= 30 for c in filtered_card)
    assert len(filtered_card) < len(all_combs)

    # Filter by min degree >= 2 (multi-set combinations only)
    filtered_deg = filter_intersections(all_combs, min_degree=2)
    assert all(c.degree >= 2 for c in filtered_deg)
    assert len(filtered_deg) == 4  # [1,2], [0,1,2], [1,3], [0,4]


def test_cardinality_and_degree_ranking() -> None:
    """Verify descending and ascending sorting by cardinality and degree."""
    combs = create_canonical_intersections()

    # Rank by cardinality descending
    ranked_card = rank_intersections_by_cardinality(combs, descending=True)
    for i in range(len(ranked_card) - 1):
        assert ranked_card[i].cardinality >= ranked_card[i + 1].cardinality
    assert ranked_card[0].cardinality == 55
    assert ranked_card[-1].cardinality == 12

    # Rank by cardinality ascending
    ranked_card_asc = rank_intersections_by_cardinality(combs, descending=False)
    assert ranked_card_asc[0].cardinality == 12
    assert ranked_card_asc[-1].cardinality == 55

    # Rank by degree descending
    ranked_deg = rank_intersections_by_degree(combs, descending=True)
    for i in range(len(ranked_deg) - 1):
        assert ranked_deg[i].degree >= ranked_deg[i + 1].degree
    assert ranked_deg[0].degree == 3


# ============================================================================
# Section 4: Standalone W3C SVG 1.1 XML Generation, Connected Dot Matrix & Bar Charts
# ============================================================================

def test_standalone_w3c_svg_canvas_rendering_and_connected_dot_matrix(tmp_path: Path) -> None:
    """Verify standalone W3C SVG 1.1 rendering, XML well-formedness, connected dot matrix, and bar charts."""
    canvas = create_canonical_upset_canvas()
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
    assert 'id="upset-matrix-grid"' in svg_code
    assert 'id="set-size-bars"' in svg_code
    assert 'id="intersection-bars"' in svg_code
    assert 'id="connected-dot-matrix"' in svg_code
    assert 'id="active-combination-focus"' in svg_code
    assert 'id="register-space-hud"' in svg_code

    # Connected dot matrix layout verification:
    # 1. Connecting line spans (<line id="conn-line-col-...")
    assert 'id="conn-line-col-0"' in svg_code
    assert 'id="conn-line-col-3"' in svg_code  # Degree 3 connecting line
    assert 'stroke-linecap="round"' in svg_code

    # 2. Active dot circles (<circle id="dot-active-...")
    assert 'id="dot-active-0-1"' in svg_code
    assert 'id="dot-active-0-2"' in svg_code

    # 3. Inactive dot circles (<circle id="dot-inactive-...")
    assert 'id="dot-inactive-0-0"' in svg_code
    assert 'id="dot-inactive-0-3"' in svg_code

    # Bar chart verification
    assert 'id="card-bar-col-0"' in svg_code
    assert 'id="card-bar-col-1"' in svg_code

    # Alternative dark theme (#1E1E1E)
    svg_1e1e1e = canvas.render_svg(dark_theme_bg=COLOR_DARK_THEME_BACKING_1E1E1E)
    assert COLOR_DARK_THEME_BACKING_1E1E1E in svg_1e1e1e

    # SVG export to file
    out_svg = tmp_path / "test_upset.svg"
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
    focus_contrast = calculate_contrast_ratio(COLOR_FOCUS_OUTLINE, COLOR_DARK_THEME_BACKING)

    assert green_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert amber_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert red_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert focus_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET

    # Overall validation function
    ok, t_c, g_c = validate_wcag_aaa_contrast()
    assert ok is True
    assert t_c > 7.0
    assert g_c > 3.0


# ============================================================================
# Section 6: Process Safety Trips & Horner Coil Assertion (%M238, %M239)
# ============================================================================

def test_cascade_trip_0xa601() -> None:
    """Verify 0xA601 multi-set interlocking cascade trip asserts %M238 when degree >= 3 or severity >= 80%."""
    canvas = create_canonical_upset_canvas()

    # Nominal check
    assert canvas.alarm_cascade_trip is False
    assert canvas.reg_table.read_bit("%M238") is False
    assert canvas.diagnostic_code == DIAG_EVENT_OK

    # 1. Trigger cascade trip via explicit call
    canvas.trigger_cascade_trip(combination_idx=3, severity=90.0)
    assert canvas.alarm_cascade_trip is True
    assert canvas.reg_table.read_bit("%M238") is True
    assert canvas.diagnostic_code == UPSET_ERR_CASCADE_TRIP
    assert canvas.diagnostic_code == 0xA601
    assert canvas.diagnostic_code == -23039  # Signed 16-bit match
    assert bool(canvas.status_bits & UpSetStatusBits.CASCADE_TRIP)

    # 2. Trigger cascade trip via focusing combination with degree 3
    canvas.reset_nominal()
    assert canvas.alarm_cascade_trip is False
    canvas.set_active_combination(3)  # Combination 3 has degree 3 and severity 90%
    assert canvas.alarm_cascade_trip is True
    assert canvas.reg_table.read_bit("%M238") is True
    assert canvas.diagnostic_code == UPSET_ERR_CASCADE_TRIP


def test_cardinality_excursion_trip_0xa602() -> None:
    """Verify 0xA602 cardinality excursion trip and 0xA603 render fault."""
    canvas = create_canonical_upset_canvas()

    # 1. Trigger cardinality excursion (0xA602)
    canvas.trigger_cardinality_excursion(cardinality_val=150)
    assert canvas.diagnostic_code == UPSET_ERR_CARDINALITY_EXCURSION
    assert canvas.diagnostic_code == 0xA602
    assert canvas.diagnostic_code == -23038
    assert canvas.reg_table.read_bit("%M238") is True
    assert bool(canvas.status_bits & UpSetStatusBits.CARDINALITY_EXCURSION)

    # 2. Trigger render fault (0xA603)
    canvas.reset_nominal()
    canvas.trigger_render_fault()
    assert canvas.diagnostic_code == UPSET_ERR_RENDER_FAULT
    assert canvas.diagnostic_code == 0xA603
    assert canvas.diagnostic_code == -23037


def test_nominal_reset_clears_trips() -> None:
    """Verify nominal reset restores clean operating state and deasserts %M238."""
    canvas = create_canonical_upset_canvas()
    canvas.trigger_cascade_trip(combination_idx=3, severity=95.0)
    assert canvas.alarm_cascade_trip is True

    canvas.reset_nominal()
    assert canvas.alarm_cascade_trip is False
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.reg_table.read_bit("%M238") is False
    assert canvas.reg_table.read_bit("%M239") is True


# ============================================================================
# Section 7: Horner OCS Register Space Synchronization (%R1020..%R1027, %M238..%M239)
# ============================================================================

def test_horner_ocs_register_space_synchronization() -> None:
    """Verify full Horner OCS memory map bindings (%R1020..%R1027, %M238..%M239) and scan cycle execution."""
    canvas = create_canonical_upset_canvas(active_index=0)
    ctx = create_mock_scan_context(reg_table=canvas.reg_table)

    canvas.execute(ctx)
    canvas.step()

    reg = canvas.reg_table
    assert reg.read_word("%R1020") == 5    # 5 Primary Sets
    assert reg.read_word("%R1021") == 55   # 55 Cardinality (Combination 0)
    assert reg.read_word("%R1022") == 8    # 8 Total Combinations
    assert reg.read_word("%R1023") == 2    # Degree 2 (Sets 1 and 2)
    assert reg.read_word("%R1024") == 240  # 240 Total Incidents across combinations
    assert reg.read_word("%R1025") == 650  # 65.0% Overall Severity Index Scaled x10
    assert reg.read_word("%R1026") == 0    # Active Combination 0
    assert reg.read_word("%R1027") == 0    # 0x0000 OK
    assert reg.read_bit("%M238") is False  # Alarm cascade trip inactive
    assert reg.read_bit("%M239") is True   # UpSet canvas active


def test_active_combination_focus_switching() -> None:
    """Verify switching active combination index updates registers %R1020..%R1026."""
    canvas = create_canonical_upset_canvas(active_index=0)

    # Combination 0 active
    assert canvas.active_combination_index == 0
    assert canvas.reg_table.read_word("%R1026") == 0
    assert canvas.reg_table.read_word("%R1021") == 55  # Cardinality 55
    assert canvas.reg_table.read_word("%R1023") == 2   # Degree 2

    # Switch to Combination 1 (Set 1 only, cardinality 45, degree 1)
    canvas.set_active_combination(1)
    assert canvas.active_combination_index == 1
    assert canvas.reg_table.read_word("%R1026") == 1
    assert canvas.reg_table.read_word("%R1021") == 45
    assert canvas.reg_table.read_word("%R1023") == 1

    # Switch to Combination 3 (Sets 0, 1, 2: cardinality 25, degree 3)
    canvas.set_active_combination(3)
    assert canvas.active_combination_index == 3
    assert canvas.reg_table.read_word("%R1026") == 3
    assert canvas.reg_table.read_word("%R1021") == 25
    assert canvas.reg_table.read_word("%R1023") == 3

    # Switch to Combination 7 (Sets 0, 4: cardinality 12, degree 2)
    canvas.set_active_combination(7)
    assert canvas.active_combination_index == 7
    assert canvas.reg_table.read_word("%R1026") == 7
    assert canvas.reg_table.read_word("%R1021") == 12
    assert canvas.reg_table.read_word("%R1023") == 2


def test_logic_unit_scan_lifecycle() -> None:
    """Verify ILogicUnit interface properties and scan lifecycle methods."""
    canvas = create_canonical_upset_canvas()
    assert canvas.name == "UpSetCanvasSync"
    assert canvas.priority == 84
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
    """Verify run_upset_canvas_verification executes cleanly across all 9 stages writing evidence JSON and SVG."""
    ev_path = tmp_path / "upset_evidence.json"
    svg_path = tmp_path / "upset_sample.svg"

    res = run_upset_canvas_verification(
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
    assert loaded["data"]["work_package"] == "W141"

    # Verify sample SVG written to disk and valid
    assert svg_path.exists()
    assert svg_path.stat().st_size > 0
    with open(svg_path, "r", encoding="utf-8") as f:
        svg_content = f.read()
    root = ET.fromstring(svg_content)
    assert root.tag.endswith("svg")


# ============================================================================
# Supplementary Edge Cases, Diagnostic Code & Branch Coverage Tests
# ============================================================================

def test_diagnostic_code_edge_cases() -> None:
    """Verify DiagnosticCode comparisons, hashing, signed 16-bit handling, and non-int comparisons."""
    code = DiagnosticCode(0xA601)
    assert code == 0xA601
    assert code == -23039
    assert code == 42497
    assert code != 0x0000
    assert code != "invalid_type"
    assert isinstance(hash(code), int)

    ok_code = DiagnosticCode(0x0000)
    assert ok_code == 0
    assert ok_code != 0xA601


def test_color_and_wcag_math_branches() -> None:
    """Verify sRGB channel linear conversion, 3-char hex expansion, and relative luminance math."""
    # Low channel value <= 0.03928
    assert srgb_channel_to_linear(0.01) == 0.01 / 12.92
    assert srgb_channel_to_linear(0.5) > 0.0

    # 3-char hex string
    lum_white_short = hex_to_relative_luminance("#FFF")
    lum_white_long = hex_to_relative_luminance("#FFFFFF")
    assert math.isclose(lum_white_short, lum_white_long, abs_tol=1e-5)


def test_upset_empty_and_error_branches() -> None:
    """Verify empty set inputs, value errors, and fallback branches."""
    # Empty primary sets in intersection computation
    assert compute_set_intersections([], []) == []

    # Incident with no matching active sets
    sets = create_canonical_primary_sets()
    inc_empty = [IncidentRecord(incident_id="EMPTY", active_sets=[999])]
    assert compute_set_intersections(sets, inc_empty) == []

    # SVG generation with empty lists raises ValueError
    with pytest.raises(ValueError, match="Cannot render UpSet canvas with empty sets"):
        generate_upset_canvas_svg(primary_sets=[], intersections=[])

    # UpSetCanvas with empty intersections
    empty_canvas = UpSetCanvas(primary_sets=sets, intersections=[])
    assert empty_canvas.active_combination.cardinality == 0
    assert empty_canvas.active_combination.degree == 0

    # UpSetCanvas evaluate_dynamics with active combination trip
    comb_large = SetIntersection(combination_id=0, set_ids=[0], cardinality=150)
    canvas_large = UpSetCanvas(primary_sets=sets, intersections=[comb_large])
    assert canvas_large.cardinality_excursion is True
    assert canvas_large.alarm_cascade_trip is True
    assert canvas_large.diagnostic_code == UPSET_ERR_CARDINALITY_EXCURSION


def test_upset_aliases_and_verification_kwargs(tmp_path: Path) -> None:
    """Verify module-level aliases and verification suite keyword arguments."""
    assert UpSetCanvasSync is UpSetCanvas
    assert UpSetHmiSync is UpSetCanvas
    assert UpSetEngine is UpSetCanvas
    assert UpSetCanvasStatusBits is UpSetStatusBits
    assert generate_upset_matrix_svg is generate_upset_canvas_svg

    ev_path = tmp_path / "kwargs_evidence.json"
    svg_path = tmp_path / "kwargs_sample.svg"
    res = run_upset_canvas_verification(
        evidence_path=ev_path,
        svg_path=svg_path,
    )
    assert res["status"] == "success"
    assert ev_path.exists()
    assert svg_path.exists()

