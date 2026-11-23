"""Comprehensive pytest test suite for Cscape HMI Dynamic Flame 3D Contour & Combustion Thermal Intensity SCADA Canvas (W180).

Work Package: W180 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1410..%R1417, %M329..%M330).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: 8x8 sensor matrix, thermal elevation interpolation, and contour level extraction.
4. Section 4: Smooth Bézier splines, radial gradient shading, flame elongation.
5. Section 5: Standalone W3C SVG 1.1 XML generation, contours, burner icons, and HUD card.
6. Section 6: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
7. Section 7: Process safety trips (0xCD01 flameout trip, 0xCD02 asymmetry impingement) and Horner coil assertion (%M329, %M330).
8. Section 8: Horner OCS register space synchronization (%R1410..%R1417, %M329..%M330) with PrivilegeMode.SYSTEM.
9. Section 9: 9-stage verification suite integration test writing evidence JSON and sample SVG.
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

from jev_cscape.hmi.flame_contour_canvas import (
    ACTIVE_BURNERS_COUNT_NOMINAL,
    ALERT_GRAPHICAL_CONTRAST_RATIO,
    AMBER_GRAPHICAL_CONTRAST_RATIO,
    BURNER_SYMMETRY_IMPINGEMENT_THRESHOLD_PCT,
    BURNER_SYMMETRY_INDEX_NOMINAL_PCT,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COLOR_ALERT_CRIMSON,
    COLOR_AMBER,
    COLOR_BURNER_THROAT,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_CYAN,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DECOUPLED_BADGE,
    COLOR_DEEP_BLUE_CORE,
    COLOR_FOCUS_BLUE,
    COLOR_GOLDEN_DESIGN,
    COLOR_INCANDESCENT_PEAK,
    COLOR_ORANGE_1400,
    COLOR_REFRACTORY_WALL,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COMBUSTION_EFFICIENCY_NOMINAL_PCT,
    COMBUSTION_FLAME_PURE_ST_POU,
    CYAN_GRAPHICAL_CONTRAST_RATIO,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DIAG_EVENT_ASYMMETRY_IMPINGEMENT,
    DIAG_EVENT_FLAME_EXTINCTION_FLAMEOUT,
    DIAG_EVENT_OK,
    DIAG_EVENT_RENDER_FAULT,
    FIREBOX_GRAPHIC_HEIGHT,
    FIREBOX_GRAPHIC_WIDTH,
    FIREBOX_LENGTH_M,
    FIREBOX_ORIGIN_X,
    FIREBOX_ORIGIN_Y,
    FIREBOX_WIDTH_M,
    FLAME_CONTOUR_PURE_ST_POU,
    FLAME_ERR_ASYMMETRY_IMPINGEMENT,
    FLAME_ERR_FLAME_EXTINCTION_FLAMEOUT,
    FLAME_ERR_FLAMEOUT,
    FLAME_ERR_IMPINGEMENT,
    FLAME_ERR_OK,
    FLAME_ERR_RENDER_FAULT,
    FLAME_EXTINCTION_TEMP_THRESHOLD_C,
    FLAME_LENGTH_NOMINAL_M,
    FLAME_PURE_ST_POU,
    FLAME_STABILITY_INDEX_NOMINAL_PCT,
    FLAME_STABILITY_TRIP_THRESHOLD_PCT,
    ISOTHERM_LEVELS_C,
    MESH_COLS,
    MESH_ROWS,
    PEAK_FLAME_TEMP_MIN_SAFE_C,
    PEAK_FLAME_TEMP_NOMINAL_C,
    PEAK_GRAPHICAL_CONTRAST_RATIO,
    SELECTED_BURNER_INDEX_NOMINAL,
    TOTAL_SENSOR_NODES,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    BezierSplineMode,
    BurnerNode,
    CombustionFlameThermalHmiSync,
    ContourLineSegment,
    DiagnosticCode,
    FlameContourCanvas,
    FlameContourEngine,
    FlameContourMetrics,
    FlameContourStatusBits,
    FlameContourThermalCanvas,
    FlameContourThermalCanvasSync,
    FlameStatusBits,
    FlameThermalIntensityCanvas,
    IsothermContour,
    ThermalSensorNode,
    build_isotherm_contours,
    calculate_contrast_ratio,
    compute_flame_temperature_field,
    create_canonical_burner_bank,
    create_canonical_flame_canvas,
    create_canonical_flame_contour_canvas,
    extract_marching_squares_segments,
    generate_flame_contour_canvas_svg,
    generate_smooth_bezier_spline_path,
    hex_to_relative_luminance,
    run_flame_contour_canvas_verification,
    srgb_channel_to_linear,
    synthesize_isotherm_bezier_envelope,
    validate_wcag_aaa_contrast,
    verify_flame_contour_pure_st,
)


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestPureSTValidation:
    """Validate compliance with IEC 61131-3 Pure Structured Text standards (%R1410..%R1417, %M329..%M330)."""

    def test_pure_st_pou_ast_parsing_and_symbol_binding(self) -> None:
        """Stage 1 Check: Verify FlameContourThermalCanvasSync POU conforms to IEC 61131-3 grammar (%R1410..%R1417, %M329..%M330)."""
        SecurityGuard.assert_pure_st_content(FLAME_CONTOUR_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(FLAME_CONTOUR_PURE_ST_POU)

        assert pou is not None
        assert pou.name == "FlameContourThermalCanvasSync"
        assert pou.pou_type == POUType.PROGRAM
        assert len(pou.variables) == 10

        expected_bindings = {
            "PeakFlameTempCelsiusScaled": "%R1410",
            "ActiveBurnersCount": "%R1411",
            "SelectedBurnerIndex": "%R1412",
            "FlameStabilityIndexScaled": "%R1413",
            "BurnerSymmetryScoreScaled": "%R1414",
            "FlameLengthMetersScaled": "%R1415",
            "CombustionEfficiencyScoreScaled": "%R1416",
            "DiagnosticStatusCode": "%R1417",
            "FlameoutTrip": "%M329",
            "FlameCanvasActive": "%M330",
        }

        var_dict = {v.name: v.address_binding for v in pou.variables}
        for name, addr in expected_bindings.items():
            assert name in var_dict, f"Missing variable binding: {name}"
            assert var_dict[name] == addr, f"Binding mismatch for {name}: {var_dict[name]} != {addr}"

        type_dict = {v.name: v.data_type for v in pou.variables}
        for name in [
            "PeakFlameTempCelsiusScaled", "ActiveBurnersCount", "SelectedBurnerIndex",
            "FlameStabilityIndexScaled", "BurnerSymmetryScoreScaled", "FlameLengthMetersScaled",
            "CombustionEfficiencyScoreScaled", "DiagnosticStatusCode",
        ]:
            assert type_dict[name] == "INT", f"Expected INT for {name}, got {type_dict[name]}"

        for name in ["FlameoutTrip", "FlameCanvasActive"]:
            assert type_dict[name] == "BOOL", f"Expected BOOL for {name}, got {type_dict[name]}"

    def test_combustion_flame_alias_pou(self) -> None:
        """Verify CombustionFlameThermalHmiSync alias POU parses cleanly with STParser."""
        SecurityGuard.assert_pure_st_content(COMBUSTION_FLAME_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(COMBUSTION_FLAME_PURE_ST_POU)

        assert pou is not None
        assert pou.name == "CombustionFlameThermalHmiSync"
        assert pou.pou_type == POUType.PROGRAM
        assert len(pou.variables) == 10

        expected_bindings = {
            "PeakFlameTempCelsiusScaled": "%R1410",
            "ActiveBurnersCount": "%R1411",
            "SelectedBurnerIndex": "%R1412",
            "FlameStabilityIndexScaled": "%R1413",
            "BurnerSymmetryScoreScaled": "%R1414",
            "FlameLengthMetersScaled": "%R1415",
            "CombustionEfficiencyScoreScaled": "%R1416",
            "DiagnosticStatusCode": "%R1417",
            "FlameoutTrip": "%M329",
            "FlameCanvasActive": "%M330",
        }
        var_dict = {v.name: v.address_binding for v in pou.variables}
        for name, addr in expected_bindings.items():
            assert name in var_dict
            assert var_dict[name] == addr

    def test_helper_verification_functions(self) -> None:
        """Verify Pure ST helper verification function returns True."""
        assert verify_flame_contour_pure_st() is True


# ============================================================================
# Section 2: Anti-Ladder Security Guard Interception
# ============================================================================

class TestLadderConstructInterception:
    """Verify security guard intercepts forbidden ladder logic constructs."""

    @pytest.mark.parametrize(
        "label,snippet",
        [
            ("Contacts", "PROGRAM BadFlameContacts\nVAR Active : BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"),
            ("Coils", "PROGRAM BadFlameCoils\nVAR Trip : BOOL; END_VAR\n---( )---\nEND_PROGRAM"),
            ("ContactsSlash", "PROGRAM BadFlameContactsSlash\nVAR Active : BOOL; END_VAR\n---[/]---\nEND_PROGRAM"),
            ("Rung", "PROGRAM BadFlameRung\nRUNG 1:\n    Active := TRUE;\nEND_PROGRAM"),
            ("Network", "PROGRAM BadFlameNetwork\nNETWORK 1:\n    Active := TRUE;\nEND_PROGRAM"),
            ("XIC", "PROGRAM BadFlameMnemonicXIC\nVAR Reg : INT; END_VAR\nXIC %M330;\nEND_PROGRAM"),
            ("OTE", "PROGRAM BadFlameMnemonicOTE\nVAR Reg : INT; END_VAR\nOTE %M329;\nEND_PROGRAM"),
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden(self, label: str, snippet: str) -> None:
        """Verify that forbidden ladder logic constructs fail closed with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# Section 3: 8x8 Sensor Matrix, Thermal Elevation Interpolation & Contour Level Extraction
# ============================================================================

class TestSensorMatrixAndThermalInterpolation:
    """Verify 8x8 sensor matrix, thermal elevation interpolation, and contour level extraction."""

    def test_8x8_sensor_mesh_dimensions_and_topology(self) -> None:
        """Verify 8x8 sensor matrix (64 nodes) conforms to furnace radiant chamber dimensions."""
        mesh = compute_flame_temperature_field()
        assert len(mesh) == MESH_ROWS
        assert all(len(row) == MESH_COLS for row in mesh)
        total_nodes = sum(len(row) for row in mesh)
        assert total_nodes == TOTAL_SENSOR_NODES
        assert total_nodes == 64

        for j in range(MESH_ROWS):
            for i in range(MESH_COLS):
                node = mesh[j][i]
                assert 0.0 <= node.x_m <= FIREBOX_LENGTH_M
                assert -FIREBOX_WIDTH_M / 2.0 <= node.y_m <= FIREBOX_WIDTH_M / 2.0
                assert node.i == i
                assert node.j == j

    def test_thermal_elevation_bounds_and_hotspot_core(self) -> None:
        """Verify thermal elevation field bounds and incandescent core hotspot."""
        mesh = compute_flame_temperature_field(peak_temp_c=PEAK_FLAME_TEMP_NOMINAL_C)
        max_t = max(node.temp_c for row in mesh for node in row)
        min_t = min(node.temp_c for row in mesh for node in row)

        assert 1500.0 <= max_t <= 1600.0
        assert 350.0 <= min_t <= 600.0

        # Peak hotspot nodes >= 1400.0 °C located near axial core
        hotspot_nodes = [node for row in mesh for node in row if node.temp_c >= 1400.0]
        assert len(hotspot_nodes) > 0

    def test_spatial_temperature_gradients(self) -> None:
        """Verify spatial temperature gradients across the 8x8 thermal field."""
        mesh = compute_flame_temperature_field()
        max_grad = max(node.grad_mag for row in mesh for node in row)
        assert max_grad > 50.0

    def test_marching_squares_isothermal_segment_extraction(self) -> None:
        """Verify 16-case Marching Squares contour segment extraction at predefined isotherms."""
        mesh = compute_flame_temperature_field(peak_temp_c=PEAK_FLAME_TEMP_NOMINAL_C)
        segs_800 = extract_marching_squares_segments(mesh, 800.0, 0.0, 0.0, 500.0, 300.0)
        assert isinstance(segs_800, list)
        assert len(segs_800) > 0
        for seg in segs_800:
            assert seg.iso_temp == 800.0
            assert isinstance(seg.x1, float)
            assert isinstance(seg.y1, float)
            assert isinstance(seg.x2, float)
            assert isinstance(seg.y2, float)

    def test_isotherm_levels_structure(self) -> None:
        """Verify the 5 canonical isothermal contour levels (°C)."""
        assert ISOTHERM_LEVELS_C == [800.0, 1000.0, 1200.0, 1400.0, 1600.0]


# ============================================================================
# Section 4: Smooth Bézier Splines, Radial Gradient Shading & Flame Elongation
# ============================================================================

class TestBezierSplinesAndFlameElongation:
    """Verify smooth Bézier splines, radial gradient shading, and flame elongation."""

    def test_smooth_cubic_and_open_bezier_splines(self) -> None:
        """Verify Catmull-Rom tangent-based cubic Bézier spline path generation."""
        pts = [(100.0, 100.0), (200.0, 80.0), (300.0, 120.0), (250.0, 180.0), (120.0, 160.0)]
        path_closed = generate_smooth_bezier_spline_path(pts, is_closed=True)
        assert path_closed.startswith("M ")
        assert " C " in path_closed
        assert path_closed.endswith(" Z") or path_closed.endswith("Z")

        path_open = generate_smooth_bezier_spline_path(pts, is_closed=False)
        assert path_open.startswith("M ")
        assert " C " in path_open
        assert not path_open.endswith("Z")

    def test_build_all_5_isotherm_contours(self) -> None:
        """Verify all 5 isothermal contours produce valid closed Bézier splines."""
        canvas = create_canonical_flame_contour_canvas()
        contours = canvas.contours
        assert len(contours) == 5

        temps = [c.iso_temp_c for c in contours]
        assert temps == [800.0, 1000.0, 1200.0, 1400.0, 1600.0]

        for c in contours:
            assert c.path_d.startswith("M")
            assert " C " in c.path_d
            assert c.path_d.endswith("Z")
            assert c.color_hex in (
                COLOR_DEEP_BLUE_CORE,
                COLOR_CYAN,
                COLOR_AMBER,
                COLOR_ORANGE_1400,
                COLOR_INCANDESCENT_PEAK,
            )

    def test_radial_gradient_shading_in_svg(self) -> None:
        """Verify radial gradient shading and glow filters are defined and referenced."""
        canvas = create_canonical_flame_contour_canvas()
        svg = canvas.render_svg()

        assert 'id="flame-thermal-gradient"' in svg
        assert '<radialGradient' in svg
        assert COLOR_INCANDESCENT_PEAK in svg
        assert COLOR_AMBER in svg
        assert COLOR_CYAN in svg
        assert COLOR_DEEP_BLUE_CORE in svg
        assert 'filter="url(#flame-glow)"' in svg

    def test_flame_elongation_metrics_and_factor(self) -> None:
        """Verify flame elongation control, length calculation, and clamping."""
        canvas = create_canonical_flame_contour_canvas()
        assert canvas.metrics.flame_length_m == FLAME_LENGTH_NOMINAL_M
        assert canvas.metrics.flame_length_scaled == 420

        # Change elongation factor
        canvas.set_flame_elongation(1.5)
        assert canvas.elongation_factor == 1.5

        # Check clamping bounds
        canvas.set_flame_elongation(0.2)
        assert canvas.elongation_factor == 0.5
        canvas.set_flame_elongation(3.5)
        assert canvas.elongation_factor == 2.0


# ============================================================================
# Section 5: Standalone W3C SVG 1.1 XML Generation, Contours, Burner Icons & HUD Card
# ============================================================================

class TestSVGCanvasRendering:
    """Verify standalone W3C SVG 1.1 XML generation, contours, burner icons, and HUD card."""

    def test_svg_generation_and_xml_parsing(self) -> None:
        """Verify SVG output is well-formed XML and conforms to W3C SVG 1.1 specifications."""
        canvas = create_canonical_flame_contour_canvas()
        svg_str = canvas.render_svg()

        assert svg_str.startswith('<?xml version="1.0" encoding="UTF-8"?>')
        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg")
        assert root.attrib["width"] == str(CANVAS_VIEWPORT_WIDTH)
        assert root.attrib["height"] == str(CANVAS_VIEWPORT_HEIGHT)

    def test_svg_contains_all_structural_components(self) -> None:
        """Verify SVG contains all essential groups, firebox, contours, burners, and HUD."""
        canvas = create_canonical_flame_contour_canvas()
        svg_str = canvas.render_svg()

        assert 'id="canvas-header"' in svg_str
        assert 'id="combustion-firebox"' in svg_str
        assert 'id="burner-throat"' in svg_str
        assert 'id="pseudo-3d-wireframe"' in svg_str
        assert 'id="golden-design-flame"' in svg_str
        assert 'id="live-combustion-flame"' in svg_str
        assert 'id="isothermal-contours"' in svg_str
        assert 'id="sensor-nodes-matrix"' in svg_str
        assert 'id="hotspot-reticle"' in svg_str
        assert 'id="burner-selector"' in svg_str
        assert 'id="flame-elongation-slider"' in svg_str
        assert 'id="telemetry-hud"' in svg_str

    def test_dual_state_representation(self) -> None:
        """Verify dual-state representation: golden design flame contour vs live combustion profile."""
        canvas = create_canonical_flame_contour_canvas()
        svg_str = canvas.render_svg()

        assert 'id="golden-design-flame"' in svg_str
        assert 'id="live-combustion-flame"' in svg_str
        assert COLOR_GOLDEN_DESIGN in svg_str
        assert 'stroke-dasharray="6,4"' in svg_str
        assert 'filter="url(#flame-glow)"' in svg_str

    def test_interactive_burner_selection(self) -> None:
        """Verify interactive burner selection updates selected index and HUD card."""
        canvas = create_canonical_flame_contour_canvas()
        canvas.select_burner(3)
        assert canvas.selected_burner_index == 3
        assert canvas.reg_table.read_word("%R1412") == 3

        svg_str = canvas.render_svg()
        assert "BURNER 3" in svg_str or "B3" in svg_str


# ============================================================================
# Section 6: WCAG 2.1 AAA Accessibility & Contrast Targets
# ============================================================================

class TestWCAGContrastCompliance:
    """Verify contrast ratios meet WCAG 2.1 AAA specifications (> 7:1 text, > 3:1 graphical, > 18:1 badge)."""

    def test_decoupled_badge_contrast_ratio(self) -> None:
        """Verify decoupled badge contrast ratio exceeds 18:1."""
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert ratio >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert ratio > 18.0

    def test_dark_theme_text_contrast_ratio(self) -> None:
        """Verify primary text on dark theme backing exceeds 7.0:1 AAA target."""
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert ratio >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert ratio > 7.0

    def test_scada_graphical_contrast_ratios(self) -> None:
        """Verify SCADA graphical colors on dark backing exceed 3.0:1 target."""
        for color, name in [
            (COLOR_CYAN, "Cyan 1000C"),
            (COLOR_AMBER, "Amber 1200C"),
            (COLOR_INCANDESCENT_PEAK, "Incandescent Peak 1600C"),
            (COLOR_ALERT_CRIMSON, "Alert Crimson"),
        ]:
            ratio = calculate_contrast_ratio(color, COLOR_DARK_THEME_BACKING)
            assert ratio >= WCAG_GRAPHICAL_CONTRAST_TARGET, f"{name} contrast {ratio:.2f} < 3.0"

    def test_validate_wcag_aaa_contrast_helper(self) -> None:
        """Verify validate_wcag_aaa_contrast helper returns True."""
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, min_contrast=18.0) is True
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING, min_contrast=7.0) is True


# ============================================================================
# Section 7: Process Safety Trips & Diagnostics
# ============================================================================

class TestProcessSafetyTrips:
    """Verify process safety trips (0xCD01, 0xCD02, 0xCD03) and coil assertion (%M329, %M330)."""

    def test_nominal_operational_state(self) -> None:
        """Verify nominal canvas state has no safety trips and status code 0x0000."""
        canvas = create_canonical_flame_contour_canvas()
        assert canvas.flameout_trip is False
        assert canvas.reg_table.read_bit("%M329") is False
        assert canvas.reg_table.read_bit("%M330") is True
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.diagnostic_code == 0x0000
        assert canvas.reg_table.read_word("%R1417") == 0

    def test_flameout_trip_0xcd01(self) -> None:
        """Verify 0xCD01 trip when flameout occurs, asserting coil %M329."""
        canvas = create_canonical_flame_contour_canvas()
        canvas.trigger_flameout_trip()

        assert canvas.flameout_trip is True
        assert canvas.reg_table.read_bit("%M329") is True
        assert canvas.diagnostic_code == FLAME_ERR_FLAME_EXTINCTION_FLAMEOUT
        assert canvas.diagnostic_code == 0xCD01
        assert canvas.diagnostic_code == -13055
        assert (DiagnosticCode(canvas.reg_table.read_word("%R1417")) == 0xCD01)
        assert bool(canvas.status_bits & FlameContourStatusBits.FLAMEOUT_TRIP)

        # Verify alert badge rendered in SVG
        svg_trip = canvas.render_svg()
        assert 'FLAMEOUT TRIP' in svg_trip or '0xCD01' in svg_trip

    def test_asymmetry_impingement_0xcd02(self) -> None:
        """Verify 0xCD02 trip when burner asymmetry causes flame impingement hazard."""
        canvas = create_canonical_flame_contour_canvas()
        canvas.trigger_asymmetry_impingement()

        assert canvas.diagnostic_code == FLAME_ERR_ASYMMETRY_IMPINGEMENT
        assert canvas.diagnostic_code == 0xCD02
        assert canvas.diagnostic_code == -13054
        assert (DiagnosticCode(canvas.reg_table.read_word("%R1417")) == 0xCD02)
        assert canvas.metrics.burner_symmetry_score_pct < BURNER_SYMMETRY_IMPINGEMENT_THRESHOLD_PCT
        assert bool(canvas.status_bits & FlameContourStatusBits.ASYMMETRY_WARNING)

    def test_render_fault_0xcd03(self) -> None:
        """Verify 0xCD03 render fault condition latches diagnostic into %R1417."""
        canvas = create_canonical_flame_contour_canvas()
        canvas.trigger_render_fault()

        assert canvas.diagnostic_code == FLAME_ERR_RENDER_FAULT
        assert canvas.diagnostic_code == 0xCD03
        assert canvas.diagnostic_code == -13053
        assert (DiagnosticCode(canvas.reg_table.read_word("%R1417")) == 0xCD03)
        assert bool(canvas.status_bits & FlameContourStatusBits.RENDER_FAULT)

    def test_reset_nominal_restores_clean_state(self) -> None:
        """Verify reset_nominal cleanly restores nominal operational state and clears trips."""
        canvas = create_canonical_flame_contour_canvas()
        canvas.trigger_flameout_trip()
        assert canvas.flameout_trip is True

        canvas.reset_nominal()
        assert canvas.flameout_trip is False
        assert canvas.reg_table.read_bit("%M329") is False
        assert canvas.reg_table.read_bit("%M330") is True
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.reg_table.read_word("%R1417") == 0


# ============================================================================
# Section 8: Horner OCS Register Space Synchronization & Scan Cycle
# ============================================================================

class TestHornerRegisterSynchronization:
    """Verify memory synchronization for %R1410..%R1417 and %M329..%M330 with PrivilegeMode.SYSTEM."""

    def test_initial_register_bindings_values(self) -> None:
        """Verify initial register values match W180 specification."""
        canvas = create_canonical_flame_contour_canvas()
        canvas.scan_step(0.01)

        reg = canvas.reg_table
        # %R1410: PeakFlameTempCelsiusScaled (nominal 1550 = 1550 C)
        assert reg.read_word("%R1410") == 1550
        # %R1411: ActiveBurnersCount (8)
        assert reg.read_word("%R1411") == 8
        # %R1412: SelectedBurnerIndex (0)
        assert reg.read_word("%R1412") == 0
        # %R1413: FlameStabilityIndexScaled (965)
        assert reg.read_word("%R1413") == 965
        # %R1414: BurnerSymmetryScoreScaled (920)
        assert reg.read_word("%R1414") == 920
        # %R1415: FlameLengthMetersScaled (420)
        assert reg.read_word("%R1415") == 420
        # %R1416: CombustionEfficiencyScoreScaled (948)
        assert reg.read_word("%R1416") == 948
        # %R1417: DiagnosticStatusCode (0)
        assert reg.read_word("%R1417") == 0
        # %M329: FlameoutTrip (False)
        assert reg.read_bit("%M329") is False
        # %M330: FlameCanvasActive (True)
        assert reg.read_bit("%M330") is True

    def test_privilege_mode_system_on_writes(self) -> None:
        """Verify writes are performed with PrivilegeMode.SYSTEM without raising permission errors."""
        reg_table = RegisterTable()
        canvas = FlameContourThermalCanvas(reg_table=reg_table)
        canvas.sync_to_registers()

        assert reg_table.read_word("%R1410") == 1550
        assert reg_table.read_bit("%M330") is True

    def test_ilogicunit_protocol_compliance(self) -> None:
        """Verify ILogicUnit contract properties and methods."""
        canvas = create_canonical_flame_contour_canvas()
        assert isinstance(canvas, ILogicUnit)
        assert canvas.name == "FlameContourThermalCanvasSync"
        assert canvas.priority == 88
        assert canvas.is_enabled is True

    def test_discrete_scan_cycle_execution(self) -> None:
        """Verify discrete scan cycle updates registers cleanly."""
        canvas = create_canonical_flame_contour_canvas()
        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=lambda a: 0,
            set_register=lambda a, v: None,
            get_variable=lambda n, d=None: d,
            set_variable=lambda n, v: None,
            record_fault=lambda f: None,
        )

        canvas.execute(ctx)
        assert canvas.reg_table.read_bit("%M330") is True

        canvas.step()
        canvas.execute_logic(ctx)
        canvas.reset()
        assert canvas.diagnostic_code == DIAG_EVENT_OK


# ============================================================================
# Section 9: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestVerificationSuiteIntegration:
    """Verify 9-stage verification suite produces deterministic contract JSON and SVG deliverable."""

    def test_complete_9_stage_verification_suite(self, tmp_path: Path) -> None:
        """Verify run_flame_contour_canvas_verification runs all 9 stages cleanly."""
        ev_file = tmp_path / "flame_contour_evidence.json"
        svg_file = tmp_path / "flame_contour_sample.svg"

        result = run_flame_contour_canvas_verification(
            output_path=str(ev_file),
            sample_svg_path=str(svg_file),
        )

        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["checks_passed"] == 9
        assert result["data"]["total_checks"] == 9
        assert len(result["data"]["tests"]) == 9

        # Verify all 9 stages passed
        for t in result["data"]["tests"]:
            assert t["passed"] is True, f"Failed stage {t['stage']}: {t['check']}"

        # Verify deliverables were written
        assert ev_file.exists()
        assert svg_file.exists()
        assert ev_file.stat().st_size > 0
        assert svg_file.stat().st_size > 0

        # Verify JSON content
        with open(ev_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["status"] == "success"
            assert data["data"]["work_package"] == "W180"
            assert data["data"]["gate"] == "Gate G9 / G2"
            assert data["data"]["metrics"]["active_burners_count"] == 8
            assert data["data"]["metrics"]["peak_flame_temp_c"] == 1550.0
            assert data["data"]["metrics"]["flame_length_m"] == 4.20


# ============================================================================
# Section 10: DiagnosticCode, Math & Edge Cases
# ============================================================================

class TestDiagnosticCodeAndEdgeCases:
    """Verify DiagnosticCode signed/unsigned 16-bit equality and helper branches."""

    def test_diagnostic_code_signed_unsigned_equality(self) -> None:
        """Verify 16-bit signed vs unsigned equality for DiagnosticCode."""
        code_flame = DiagnosticCode(0xCD01)
        assert code_flame == 0xCD01
        assert code_flame == 52481
        assert code_flame == -13055
        assert int(code_flame) == 52481
        assert hash(code_flame) == hash(52481)
        assert code_flame != "not_an_int"
        assert code_flame != 0x0000

        code_asym = DiagnosticCode(0xCD02)
        assert code_asym == 0xCD02
        assert code_asym == 52482
        assert code_asym == -13054

        code_rend = DiagnosticCode(0xCD03)
        assert code_rend == 0xCD03
        assert code_rend == 52483
        assert code_rend == -13053

        code_ok = DiagnosticCode(0x0000)
        assert code_ok == 0
        assert code_ok == 0x0000

    def test_srgb_and_hex_luminance_math(self) -> None:
        """Verify sRGB channel linear conversion and hex luminance."""
        assert abs(srgb_channel_to_linear(0.02) - (0.02 / 12.92)) < 1e-6
        assert abs(srgb_channel_to_linear(0.5) - (((0.5 + 0.055) / 1.055) ** 2.4)) < 1e-6

        # 3-char vs 6-char hex
        lum3 = hex_to_relative_luminance("#FFF")
        lum6 = hex_to_relative_luminance("#FFFFFF")
        assert abs(lum3 - lum6) < 1e-4

        lum_blk3 = hex_to_relative_luminance("#000")
        lum_blk6 = hex_to_relative_luminance("#000000")
        assert abs(lum_blk3 - lum_blk6) < 1e-4

    def test_aliases_and_factory_functions(self) -> None:
        """Verify class aliases and factory functions instantiate properly."""
        c1 = FlameContourThermalCanvasSync()
        c2 = CombustionFlameThermalHmiSync()
        c3 = FlameContourEngine()
        c4 = FlameThermalIntensityCanvas()
        c5 = create_canonical_flame_contour_canvas()
        c6 = create_canonical_flame_canvas()

        for c in (c1, c2, c3, c4, c5, c6):
            assert isinstance(c, FlameContourThermalCanvas)
            assert isinstance(c, FlameContourCanvas)

        burners = create_canonical_burner_bank()
        assert len(burners) == 8
