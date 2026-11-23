"""Comprehensive pytest test suite for Cscape HMI Dynamic Trellis / Small Multiples Canvas (W171).

Work Package: W171 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Alignment:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1320..%R1327, %M308..%M309).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: 6 canonical refinery process units and 2x3 matrix grid layout geometry.
4. Section 4: Synchronized micro-spark distributions (Golden baseline cyan envelope vs Real-time emerald trajectory).
5. Section 5: Standalone W3C SVG 1.1 XML generation, pulsing operating point markers, and HUD card.
6. Section 6: WCAG 2.1 AAA contrast ratio checks (> 7.0:1 text, > 3.0:1 graphical, > 18:1 badge).
7. Section 7: Process safety trips (0xC401 envelope breach, 0xC402 aspect ratio, 0xC403 render fault) and coil assertion (%M308, %M309).
8. Section 8: Horner OCS register space synchronization (%R1320..%R1327, %M308..%M309) with PrivilegeMode.SYSTEM.
9. Section 9: ILogicUnit discrete scan cycle execution and scan_step(dt).
10. Section 10: 9-stage verification suite integration test writing evidence JSON and sample SVG.
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

from jev_cscape.hmi.trellis_canvas import (
    CANONICAL_PANEL_COUNT,
    CANONICAL_STREAM_COUNT,
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
    COLOR_FOCUS_BLUE,
    COLOR_GRID_AXIS,
    COLOR_GRID_TICK,
    COLOR_INDIGO,
    COLOR_PURPLE,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DEFAULT_GRID_COLS,
    DEFAULT_GRID_ROWS,
    DEFAULT_PANELS_COUNT,
    DIAG_EVENT_ASPECT_RATIO_FAULT,
    DIAG_EVENT_ENVELOPE_BREACH,
    DIAG_EVENT_OK,
    DIAG_EVENT_PANEL_ENVELOPE_BREACH,
    DIAG_EVENT_RENDER_FAULT,
    DiagnosticCode,
    FleetDistributionCanvas,
    FleetDistributionCanvasSync,
    GRID_DEFAULT_COLS,
    GRID_DEFAULT_ROWS,
    HUD_CARD_HEIGHT,
    HUD_CARD_WIDTH,
    HUD_CARD_X,
    HUD_CARD_Y,
    PANEL_GAP_X,
    PANEL_GAP_Y,
    PANEL_HEIGHT,
    PANEL_WIDTH,
    PanelAlarmState,
    ProcessFleetStatusBits,
    ProcessFleetTrellisCanvas,
    ProcessFleetTrellisCanvasSync,
    PROCESS_FLEET_TRELLIS_PURE_ST_POU,
    ProcessPanel,
    SparkPoint,
    TRELLIS_CANVAS_PURE_ST_POU,
    TRELLIS_ERR_ASPECT_FAULT,
    TRELLIS_ERR_ASPECT_RATIO_FAULT,
    TRELLIS_ERR_ENVELOPE_BREACH,
    TRELLIS_ERR_ENVELOPE_VIOLATION,
    TRELLIS_ERR_OK,
    TRELLIS_ERR_PANEL_ENVELOPE_BREACH,
    TRELLIS_ERR_RENDER_FAULT,
    TRELLIS_GRID_HEIGHT,
    TRELLIS_GRID_WIDTH,
    TRELLIS_GRID_X,
    TRELLIS_GRID_Y,
    TRELLIS_PURE_ST_POU,
    TRELLIS_SMALL_MULTIPLES_PURE_ST_POU,
    TrellisCanvas,
    TrellisCanvasEngine,
    TrellisCanvasStatusBits,
    TrellisCanvasSync,
    TrellisMetrics,
    TrellisSmallMultiplesCanvas,
    TrellisSmallMultiplesSync,
    TrellisStatusBits,
    calculate_contrast_ratio,
    compute_trellis_grid_layout,
    compute_trellis_metrics,
    create_canonical_trellis_canvas,
    create_canonical_trellis_panels,
    create_mock_scan_context,
    generate_trellis_canvas_svg,
    hex_to_relative_luminance,
    map_hour_to_panel_x,
    map_value_to_panel_y,
    run_trellis_canvas_verification,
    validate_wcag_aaa_contrast,
    verify_process_fleet_trellis_pure_st,
    verify_trellis_pure_st,
    verify_trellis_small_multiples_pure_st,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
)


# ============================================================================
# Section 1: Pure ST POU Grammar & Variable AST Validation
# ============================================================================

class TestPureSTValidation:
    """Validate compliance with IEC 61131-3 Pure Structured Text standards."""

    def test_pure_st_pou_syntax_and_ast_parsing(self):
        """Verify TrellisSmallMultiplesSync parses without error and matches expected bindings."""
        SecurityGuard.assert_pure_st_content(TRELLIS_CANVAS_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(TRELLIS_CANVAS_PURE_ST_POU)

        assert pou is not None
        assert pou.name == "TrellisSmallMultiplesSync"
        assert pou.pou_type == POUType.PROGRAM
        assert len(pou.variables) == 10

        expected_bindings = {
            "FleetHealthScorePct": "%R1320",
            "ActivePanelsCount": "%R1321",
            "SelectedPanelIndex": "%R1322",
            "Panel1MetricScaled": "%R1323",
            "Panel2MetricScaled": "%R1324",
            "Panel3MetricScaled": "%R1325",
            "MaxPanelDeviationPct": "%R1326",
            "DiagnosticStatusCode": "%R1327",
            "TrellisEnvelopeTrip": "%M308",
            "TrellisCanvasActive": "%M309",
        }

        var_dict = {v.name: v.address_binding for v in pou.variables}
        for name, addr in expected_bindings.items():
            assert name in var_dict, f"Missing variable binding: {name}"
            assert var_dict[name] == addr, f"Binding mismatch for {name}: {var_dict[name]} != {addr}"

    def test_process_fleet_trellis_alias_pou(self):
        """Verify ProcessFleetTrellisCanvasSync alias POU parses cleanly."""
        SecurityGuard.assert_pure_st_content(PROCESS_FLEET_TRELLIS_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(PROCESS_FLEET_TRELLIS_PURE_ST_POU)

        assert pou is not None
        assert pou.name == "ProcessFleetTrellisCanvasSync"
        assert pou.pou_type == POUType.PROGRAM
        assert len(pou.variables) == 10

    def test_helper_verification_functions(self):
        """Verify verification helper functions return True."""
        assert verify_trellis_small_multiples_pure_st() is True
        assert verify_process_fleet_trellis_pure_st() is True
        assert verify_trellis_pure_st() is True


# ============================================================================
# Section 2: Anti-Ladder Construct Security Interception
# ============================================================================

class TestLadderConstructInterception:
    """Verify security guard intercepts forbidden ladder logic constructs."""

    @pytest.mark.parametrize(
        "label,snippet",
        [
            ("Contacts", "PROGRAM Bad\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"),
            ("Coils", "PROGRAM Bad\nVAR y: BOOL; END_VAR\n---( )---\nEND_PROGRAM"),
            ("Rung", "PROGRAM Bad\nRUNG 1:\nEND_PROGRAM"),
            ("Network", "PROGRAM Bad\nNETWORK 1:\nEND_PROGRAM"),
            ("XIC", "PROGRAM Bad\nXIC B3:0/0;\nEND_PROGRAM"),
            ("OTE", "PROGRAM Bad\nOTE B3:0/1;\nEND_PROGRAM"),
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden(self, label: str, snippet: str):
        """Verify that forbidden ladder logic constructs fail closed with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# Section 3: 6 Canonical Refinery Process Units & Trellis Grid Layout
# ============================================================================

class TestCanonicalRefineryUnitsAndGrid:
    """Verify 6 refinery process units and 2x3 matrix grid layout geometry."""

    def test_canonical_units_count_and_tags(self):
        """Verify 6 canonical refinery process units have correct specifications."""
        panels = create_canonical_trellis_panels()
        assert len(panels) == 6

        expected_units = [
            ("CDU", "CDU-101", "Crude Distillation Unit (CDU)", "°C", 365.0, 3650, "%R1323"),
            ("VDU", "VDU-201", "Vacuum Distillation Unit (VDU)", "°C", 512.0, 5120, "%R1324"),
            ("FCC", "FCC-301", "Fluid Catalytic Cracking (FCC)", "kPa", 120.0, 1200, "%R1325"),
            ("HCU", "HCU-401", "Hydrocracker Unit (HCU)", "bar", 160.0, 1600, None),
            ("CCR", "CCR-501", "Continuous Catalytic Reformer (CCR)", "RON", 100.84, 1008, None),
            ("HID", "HID-601", "Hydroisomerization Dewaxing (HID)", "°C", 320.0, 3200, None),
        ]

        for idx, (code, tag, name, unit, curr_val, scaled, reg_addr) in enumerate(expected_units):
            p = panels[idx]
            assert p.unit_code == code
            assert p.tag == tag
            assert p.name == name
            assert p.unit == unit
            assert math.isclose(p.current_val, curr_val, abs_tol=1e-2)
            assert p.register_addr == reg_addr
            assert p.scaled_metric == scaled

    def test_trellis_grid_layout_2x3_geometry(self):
        """Verify 2x3 matrix grid coordinate bounds and geometry."""
        panels = create_canonical_trellis_panels()
        success = compute_trellis_grid_layout(panels, rows=2, cols=3)
        assert success is True

        # Check rows and cols
        for i, p in enumerate(panels):
            assert p.grid_row == i // 3
            assert p.grid_col == i % 3
            assert p.bounding_w == PANEL_WIDTH
            assert p.bounding_h == PANEL_HEIGHT

        # Row 0 vs Row 1 Y coordinates
        assert panels[0].bounding_y == panels[1].bounding_y == panels[2].bounding_y
        assert panels[3].bounding_y == panels[4].bounding_y == panels[5].bounding_y
        assert panels[3].bounding_y > panels[0].bounding_y

        # Col 0, 1, 2 X coordinates
        assert panels[0].bounding_x == panels[3].bounding_x
        assert panels[1].bounding_x == panels[4].bounding_x
        assert panels[2].bounding_x == panels[5].bounding_x
        assert panels[0].bounding_x < panels[1].bounding_x < panels[2].bounding_x

    def test_aspect_ratio_fault_on_invalid_grid(self):
        """Verify compute_trellis_grid_layout fails on invalid dimensions."""
        panels = create_canonical_trellis_panels()
        # Invalid row count
        assert compute_trellis_grid_layout(panels, rows=0, cols=3) is False
        # Invalid col count
        assert compute_trellis_grid_layout(panels, rows=2, cols=0) is False
        # Negative width or height
        assert compute_trellis_grid_layout(panels, panel_w=-10.0) is False
        assert compute_trellis_grid_layout(panels, panel_h=-10.0) is False
        # Insufficient cells for panels
        assert compute_trellis_grid_layout(panels, rows=1, cols=2) is False

    def test_screen_mapping_projection(self):
        """Verify map_value_to_panel_y correctly maps within min and max range."""
        cy = 100.0
        ch = 200.0
        min_v = 300.0
        max_v = 400.0

        # min_val maps to bottom
        assert math.isclose(map_value_to_panel_y(min_v, min_v, max_v, cy, ch), cy + ch)
        # max_val maps to top
        assert math.isclose(map_value_to_panel_y(max_v, min_v, max_v, cy, ch), cy)
        # midpoint maps to middle
        assert math.isclose(map_value_to_panel_y(350.0, min_v, max_v, cy, ch), cy + 100.0)


# ============================================================================
# Section 4: Micro-Spark Distribution Synthesis
# ============================================================================

class TestMicroSparkSynthesis:
    """Verify micro-spark distribution synthesis and safe operating envelope bounds."""

    def test_24h_history_profiles(self):
        """Verify each panel contains at least 24 historical stability points."""
        panels = create_canonical_trellis_panels()
        for p in panels:
            assert len(p.history_24h) >= 24
            assert p.stability_index_pct > 90.0
            # All historical points within display min and max range
            for h in p.history_24h:
                assert p.min_range <= h <= p.max_range

    def test_safe_operating_envelope_bounds(self):
        """Verify safe operating envelope bounds for each unit."""
        panels = create_canonical_trellis_panels()
        for p in panels:
            assert p.min_range < p.safe_min < p.target_val < p.safe_max < p.max_range
            assert p.is_operating_point_in_envelope is True
            if p.unit_code == "CCR":
                assert p.state == PanelAlarmState.WARNING
            else:
                assert p.state == PanelAlarmState.NORMAL

    def test_max_panel_deviation_calculation(self):
        """Verify CCR panel produces exactly 4.2% maximum deviation."""
        panels = create_canonical_trellis_panels()
        ccr = panels[4]
        assert ccr.unit_code == "CCR"
        assert math.isclose(ccr.deviation_pct, 4.2, abs_tol=1e-2)

        metrics = compute_trellis_metrics(panels)
        assert math.isclose(metrics.max_panel_deviation_pct, 4.2, abs_tol=1e-2)
        assert metrics.max_panel_deviation_scaled == 42


# ============================================================================
# Section 5: Standalone W3C SVG 1.1 Generation & XML Validation
# ============================================================================

class TestSVGCanvasRendering:
    """Verify W3C SVG 1.1 vector graphics generation, accessibility, and XML structure."""

    def test_svg_generation_and_xml_parsing(self):
        """Verify rendered SVG parses cleanly with xml.etree.ElementTree."""
        canvas = create_canonical_trellis_canvas()
        svg_content = canvas.render_svg()

        assert svg_content.startswith('<?xml version="1.0" encoding="UTF-8"?>')
        root = ET.fromstring(svg_content)
        assert root.tag.endswith("svg")
        assert root.attrib.get("width") == str(CANVAS_VIEWPORT_WIDTH)
        assert root.attrib.get("height") == str(CANVAS_VIEWPORT_HEIGHT)

    def test_svg_contains_all_panels_and_hud(self):
        """Verify SVG contains all 6 panels, micro-sparks, and HUD card components."""
        canvas = create_canonical_trellis_canvas()
        svg_content = canvas.render_svg()

        # Check essential group tags
        assert 'id="canvas-header"' in svg_content
        assert 'id="trellis-diagram"' in svg_content
        assert 'id="trellis-grid"' in svg_content
        for i in range(6):
            assert f'id="trellis-panel-{i}"' in svg_content
            assert f'id="panel-{i}-baseline-envelope"' in svg_content
            assert f'id="panel-{i}-trajectory"' in svg_content
            assert f'id="panel-{i}-footer"' in svg_content

        assert 'id="trellis-hud-card"' in svg_content
        assert 'id="fleet-health-summary-box"' in svg_content
        assert 'id="scaled-metrics-breakdown"' in svg_content
        assert 'id="diagnostics-safety-card"' in svg_content

    def test_selected_panel_focus_highlight(self):
        """Verify selecting a panel applies focus class and glow filter."""
        canvas = create_canonical_trellis_canvas(selected_panel_index=2)
        svg_content = canvas.render_svg()

        assert 'panel-card-selected' in svg_content
        assert 'filter="url(#focus-glow)"' in svg_content
        assert 'FOCUSED UNIT [2] TELEMETRY' in svg_content


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

    def test_scada_graphical_contrast_ratios(self):
        """Verify SCADA graphical colors on dark backing exceed 3.0:1 target."""
        for color, name in [
            (COLOR_EMERALD, "Emerald"),
            (COLOR_CYAN, "Cyan"),
            (COLOR_AMBER, "Amber"),
            (COLOR_CRIMSON, "Crimson"),
        ]:
            ratio = calculate_contrast_ratio(color, COLOR_DARK_THEME_BACKING)
            assert ratio >= WCAG_GRAPHICAL_CONTRAST_TARGET, f"{name} contrast {ratio:.2f} < 3.0"


# ============================================================================
# Section 7: Process Safety Interlocks & Diagnostics
# ============================================================================

class TestProcessSafetyInterlocks:
    """Verify process safety interlocks (0xC401, 0xC402, 0xC403) and coil assertion (%M308)."""

    def test_nominal_state_clear(self):
        """Verify nominal canvas state has no safety trips and status code 0x0000."""
        canvas = create_canonical_trellis_canvas()
        assert canvas.envelope_trip is False
        assert canvas.diagnostic_code == TRELLIS_ERR_OK
        assert canvas.reg_table.read_bit("%M308") is False
        assert canvas.reg_table.read_bit("%M309") is True
        assert canvas.reg_table.read_word("%R1327") == 0

    def test_envelope_breach_trip_0xc401(self):
        """Verify operating point breach outside safe bounds triggers 0xC401 and asserts %M308."""
        canvas = create_canonical_trellis_canvas()
        # Trigger breach on panel 0 (CDU) with 425.0 °C (safe max is 380.0 °C)
        canvas.trigger_envelope_breach(panel_index=0, injected_val=425.0)

        assert canvas.envelope_trip is True
        assert canvas.reg_table.read_bit("%M308") is True
        assert canvas.diagnostic_code == TRELLIS_ERR_PANEL_ENVELOPE_BREACH
        assert canvas.diagnostic_code == 0xC401
        assert canvas.diagnostic_code == -15359

        # Register check: signed 16-bit representation
        diag_reg = canvas.reg_table.read_word("%R1327")
        assert diag_reg == -15359
        assert DiagnosticCode(diag_reg) == 0xC401
        assert bool(canvas.status_bits & TrellisStatusBits.PANEL_ENVELOPE_BREACH_TRIP)

    def test_aspect_ratio_fault_0xc402(self):
        """Verify aspect ratio fault latches 0xC402 into %R1327."""
        canvas = create_canonical_trellis_canvas()
        canvas.trigger_aspect_ratio_fault()

        assert canvas.diagnostic_code == TRELLIS_ERR_ASPECT_RATIO_FAULT
        assert canvas.diagnostic_code == 0xC402
        assert canvas.diagnostic_code == -15358
        assert canvas.reg_table.read_word("%R1327") == -15358
        assert bool(canvas.status_bits & TrellisStatusBits.ASPECT_RATIO_FAULT)

    def test_render_fault_0xc403(self):
        """Verify render fault latches 0xC403 into %R1327."""
        canvas = create_canonical_trellis_canvas()
        canvas.trigger_render_fault()

        assert canvas.diagnostic_code == TRELLIS_ERR_RENDER_FAULT
        assert canvas.diagnostic_code == 0xC403
        assert canvas.diagnostic_code == -15357
        assert canvas.reg_table.read_word("%R1327") == -15357
        assert bool(canvas.status_bits & TrellisStatusBits.RENDER_FAULT)

    def test_reset_nominal_restores_clean_state(self):
        """Verify reset_nominal cleanly restores nominal operational state."""
        canvas = create_canonical_trellis_canvas()
        canvas.trigger_envelope_breach(panel_index=1, injected_val=580.0)
        assert canvas.envelope_trip is True

        canvas.reset_nominal()
        assert canvas.envelope_trip is False
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.reg_table.read_bit("%M308") is False
        assert canvas.reg_table.read_word("%R1327") == 0


# ============================================================================
# Section 8: Horner OCS Register Space Synchronization
# ============================================================================

class TestHornerRegisterSynchronization:
    """Verify memory synchronization for %R1320..%R1327 and %M308..%M309."""

    def test_initial_register_bindings_values(self):
        """Verify initial register values match specification."""
        canvas = create_canonical_trellis_canvas()
        reg = canvas.reg_table

        # %R1320: FleetHealthScorePct (96.2% -> 962)
        assert reg.read_word("%R1320") == 962
        # %R1321: ActivePanelsCount (6)
        assert reg.read_word("%R1321") == 6
        # %R1322: SelectedPanelIndex (0)
        assert reg.read_word("%R1322") == 0
        # %R1323: Panel1MetricScaled (365.0 -> 3650)
        assert reg.read_word("%R1323") == 3650
        # %R1324: Panel2MetricScaled (512.0 -> 5120)
        assert reg.read_word("%R1324") == 5120
        # %R1325: Panel3MetricScaled (120.0 -> 1200)
        assert reg.read_word("%R1325") == 1200
        # %R1326: MaxPanelDeviationPct (4.2% -> 42)
        assert reg.read_word("%R1326") == 42
        # %R1327: DiagnosticStatusCode (0x0000 -> 0)
        assert reg.read_word("%R1327") == 0
        # %M308: TrellisEnvelopeTrip (False)
        assert reg.read_bit("%M308") is False
        # %M309: TrellisCanvasActive (True)
        assert reg.read_bit("%M309") is True

    def test_privilege_mode_system_on_writes(self):
        """Verify writes are performed with PrivilegeMode.SYSTEM without raising permission errors."""
        reg_table = RegisterTable()
        canvas = TrellisCanvas(reg_table=reg_table)
        canvas.sync_to_registers()

        assert reg_table.read_word("%R1320") == 962
        assert reg_table.read_bit("%M309") is True


# ============================================================================
# Section 9: ILogicUnit Protocol & Scan Cycle Execution
# ============================================================================

class TestLogicUnitScanCycle:
    """Verify ILogicUnit protocol compliance and scan_step / execute_scan execution."""

    def test_ilogicunit_interface_properties(self):
        """Verify ILogicUnit contract properties and methods."""
        canvas = create_canonical_trellis_canvas()
        assert isinstance(canvas, ILogicUnit)
        assert canvas.name == "TrellisSmallMultiplesSync"
        assert canvas.priority == 91
        assert canvas.is_enabled is True

    def test_scan_step_execution(self):
        """Verify scan_step(dt) recalculates telemetry and syncs memory."""
        canvas = create_canonical_trellis_canvas()
        canvas.panels[0].current_val = 370.0  # Still in safe envelope [340..380]
        canvas.scan_step(dt=0.01)

        assert canvas.reg_table.read_word("%R1323") == 3700

    def test_discrete_scan_cycle_interlock_trip(self):
        """Verify execute(context) latches trip and writes coils according to %M309 state."""
        canvas = create_canonical_trellis_canvas()
        ctx = create_mock_scan_context(cycle=1, reg_table=canvas.reg_table)

        # 1. Nominal scan
        canvas.execute(ctx)
        assert canvas.reg_table.read_bit("%M308") is False

        # 2. Exceed envelope on panel 2 (FCC: safe envelope [105..135], inject 145.0)
        canvas.panels[2].current_val = 145.0
        canvas.execute(ctx)
        assert canvas.reg_table.read_bit("%M308") is True
        assert canvas.reg_table.read_word("%R1327") == -15359

        # 3. Canvas inactive (%M309=False) forces %M308=False
        canvas.reg_table.write_bit("%M309", False, privilege=PrivilegeMode.SYSTEM)
        canvas.execute(ctx)
        assert canvas.reg_table.read_bit("%M308") is False


# ============================================================================
# Section 10: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestVerificationSuiteIntegration:
    """Verify 9-stage verification suite produces deterministic contract JSON and SVG deliverable."""

    def test_complete_9_stage_verification_suite(self, tmp_path: Path):
        """Verify run_trellis_canvas_verification runs all 9 stages cleanly."""
        ev_file = tmp_path / "trellis_evidence.json"
        svg_file = tmp_path / "trellis_sample.svg"

        result = run_trellis_canvas_verification(
            output_path=str(ev_file),
            sample_svg_path=str(svg_file),
        )

        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["checks_passed"] == 9
        assert result["data"]["total_checks"] == 9
        assert len(result["data"]["tests"]) == 9

        # Verify files were created
        assert ev_file.exists()
        assert svg_file.exists()
        assert ev_file.stat().st_size > 0
        assert svg_file.stat().st_size > 0

        # Verify JSON content
        with open(ev_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["status"] == "success"
            assert data["data"]["work_package"] == "W171"
            assert data["data"]["gate"] == "Gate G9 / G2"
            assert data["data"]["metrics"]["num_panels"] == 6
            assert data["data"]["metrics"]["fleet_health_score_scaled"] == 962
            assert data["data"]["metrics"]["max_panel_deviation_scaled"] == 42
