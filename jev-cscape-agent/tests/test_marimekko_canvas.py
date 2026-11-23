"""Unit test suite for Cscape HMI Dynamic Marimekko / Mosaic Allocation Canvas (W135).

Work Package: W135 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.marimekko_canvas import (
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COLOR_AMBER,
    COLOR_CORAL,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DECOUPLED_BADGE,
    COLOR_INDUSTRIAL_BLUE,
    COLOR_NOMINAL_GREEN,
    COLOR_NOMINAL_GREEN_LIGHT,
    COLOR_TEAL,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TRIP_RED,
    COLOR_TRIP_RED_LIGHT,
    COLOR_VIOLET,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DIAG_EVENT_ALLOCATION_IMBALANCE,
    DIAG_EVENT_CAPACITY_OVERRUN,
    DIAG_EVENT_NORMALIZATION_FAULT,
    DIAG_EVENT_OK,
    GRAPHICAL_BOUNDARY_CONTRAST_RATIO,
    IMBALANCE_LOWER_LIMIT_PCT,
    IMBALANCE_UPPER_LIMIT_PCT,
    MARIMEKKO_ERR_ALLOCATION_IMBALANCE,
    MARIMEKKO_ERR_CAPACITY_OVERRUN,
    MARIMEKKO_ERR_NORMALIZATION_FAULT,
    MARIMEKKO_PURE_ST_POU,
    PLOT_HEIGHT,
    PLOT_ORIGIN_X,
    PLOT_ORIGIN_Y,
    PLOT_WIDTH,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    DiagnosticCode,
    MarimekkoCanvas,
    MarimekkoCanvasStatusBits,
    MarimekkoCanvasSync,
    MarimekkoColumn,
    MarimekkoEngine,
    MarimekkoHmiSync,
    MarimekkoMatrix,
    MarimekkoMetrics,
    MarimekkoSegment,
    MarimekkoStatusBits,
    MarimekkoSystem,
    calculate_contrast_ratio,
    compute_cell_areas,
    compute_column_widths,
    compute_marimekko_metrics,
    compute_segment_heights,
    create_canonical_marimekko_canvas,
    create_canonical_marimekko_columns,
    create_canonical_marimekko_matrix,
    create_canonical_marimekko_system,
    create_mock_scan_context,
    generate_marimekko_canvas_svg,
    hex_to_relative_luminance,
    normalize_matrix,
    run_marimekko_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_marimekko_canvas_pure_st,
    verify_marimekko_pure_st,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding & Ladder Interception
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Verify Pure ST POU AST parsing, symbol binding, and Horner register bindings."""
    assert verify_marimekko_canvas_pure_st() is True
    assert verify_marimekko_pure_st() is True

    # Validate with SecurityGuard directly
    SecurityGuard.assert_pure_st_content(MARIMEKKO_PURE_ST_POU)

    # Validate AST structure with STParser
    parser = STParser()
    pou = parser.parse_pou(MARIMEKKO_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "MarimekkoCanvasSync"
    assert pou.pou_type == POUType.PROGRAM

    # Verify bound registers
    var_bindings = {v.name: v.address_binding for v in pou.variables if v.address_binding}
    assert var_bindings["Category1WidthScaled"] == "%R960"
    assert var_bindings["Category2WidthScaled"] == "%R961"
    assert var_bindings["Category3WidthScaled"] == "%R962"
    assert var_bindings["Segment1HeightScaled"] == "%R963"
    assert var_bindings["Segment2HeightScaled"] == "%R964"
    assert var_bindings["TotalAreaAllocationScaled"] == "%R965"
    assert var_bindings["ActiveColumnIndex"] == "%R966"
    assert var_bindings["DiagnosticStatusCode"] == "%R967"
    assert var_bindings["AllocationImbalanceTrip"] == "%M224"
    assert var_bindings["MarimekkoNormalized"] == "%M225"


def test_ladder_construct_rejection() -> None:
    """Ensure ladder logic contacts, coils, and mnemonics fail closed with LadderForbiddenError."""
    ladder_samples = [
        "PROGRAM Bad\nVAR X: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM",
        "PROGRAM Bad\nVAR X: BOOL; END_VAR\n---( )---\nEND_PROGRAM",
        "PROGRAM Bad\nVAR X: BOOL; END_VAR\nRUNG 1\nEND_PROGRAM",
        "PROGRAM Bad\nVAR X: BOOL; END_VAR\nNETWORK 1\nEND_PROGRAM",
        "PROGRAM Bad\nVAR X: BOOL; END_VAR\nXIC Bit1\nEND_PROGRAM",
        "PROGRAM Bad\nVAR X: BOOL; END_VAR\nOTE Coil1\nEND_PROGRAM",
    ]
    for sample in ladder_samples:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(sample)


# ============================================================================
# Section 2: Marimekko / Mosaic Matrix Geometry & Proportionality
# ============================================================================

def test_mosaic_geometry_proportionality() -> None:
    """Verify 2D variable-width and variable-height tiled partition geometry."""
    matrix = create_canonical_marimekko_matrix(active_index=0)
    assert len(matrix.columns) == 3

    col1, col2, col3 = matrix.columns
    # Column width w_j proportional to category total budget: 450, 350, 200 out of 1000
    assert math.isclose(col1.width_pct, 45.0, abs_tol=1e-5)
    assert math.isclose(col2.width_pct, 35.0, abs_tol=1e-5)
    assert math.isclose(col3.width_pct, 20.0, abs_tol=1e-5)

    # Segment heights within column j: 270/450=60%, 180/450=40%
    assert math.isclose(col1.segments[0].height_pct, 60.0, abs_tol=1e-5)
    assert math.isclose(col1.segments[1].height_pct, 40.0, abs_tol=1e-5)

    # Cell area A_ij = w_j * h_ij strictly proportional to individual resource consumption
    assert math.isclose(col1.segments[0].area_pct, 27.0, abs_tol=1e-5)
    assert math.isclose(col1.segments[1].area_pct, 18.0, abs_tol=1e-5)
    assert math.isclose(col2.segments[0].area_pct, 17.5, abs_tol=1e-5)
    assert math.isclose(col2.segments[1].area_pct, 17.5, abs_tol=1e-5)
    assert math.isclose(col3.segments[0].area_pct, 14.0, abs_tol=1e-5)
    assert math.isclose(col3.segments[1].area_pct, 6.0, abs_tol=1e-5)

    # Area conservation sum
    total_area = sum(seg.area_pct for c in matrix.columns for seg in c.segments)
    assert math.isclose(total_area, 100.0, abs_tol=1e-5)


def test_cumulative_coordinates() -> None:
    """Verify cumulative X start offsets across categories."""
    matrix = create_canonical_marimekko_matrix()
    col1, col2, col3 = matrix.columns
    assert math.isclose(col1.x_offset_pct, 0.0, abs_tol=1e-5)
    assert math.isclose(col2.x_offset_pct, 45.0, abs_tol=1e-5)
    assert math.isclose(col3.x_offset_pct, 80.0, abs_tol=1e-5)


# ============================================================================
# Section 3: Strict Normalization
# ============================================================================

def test_strict_normalization_engine() -> None:
    """Test normalization with arbitrary unnormalized raw values."""
    raw_cols = [
        MarimekkoColumn(category_id=0, name="Alpha", total_value=250.0),
        MarimekkoColumn(category_id=1, name="Beta", total_value=750.0),
    ]
    raw_cols[0].segments = [
        MarimekkoSegment(1, "A1", 100.0, COLOR_INDUSTRIAL_BLUE),
        MarimekkoSegment(2, "A2", 150.0, COLOR_TEAL),
    ]
    raw_cols[1].segments = [
        MarimekkoSegment(1, "B1", 300.0, COLOR_AMBER),
        MarimekkoSegment(2, "B2", 450.0, COLOR_CORAL),
    ]

    matrix = normalize_matrix(raw_cols)
    assert math.isclose(sum(c.width_pct for c in matrix.columns), 100.0, abs_tol=1e-5)
    assert math.isclose(sum(s.height_pct for s in matrix.columns[0].segments), 100.0, abs_tol=1e-5)
    assert math.isclose(sum(s.height_pct for s in matrix.columns[1].segments), 100.0, abs_tol=1e-5)
    assert matrix.is_normalized is True


# ============================================================================
# Section 4: Process Safety Interlocks & Diagnostic Codes
# ============================================================================

def test_allocation_imbalance_interlock_upper_limit() -> None:
    """Verify 0xA001 trips %M224 when single category exceeds 80%."""
    canvas = create_canonical_marimekko_canvas()
    assert canvas.reg_table.read_bit("%M224") is False
    assert canvas.diagnostic_code == DIAG_EVENT_OK

    canvas.trigger_allocation_imbalance(category_idx=0, dominant_pct=85.0)
    assert canvas.allocation_imbalance_trip is True
    assert canvas.reg_table.read_bit("%M224") is True
    assert canvas.diagnostic_code == MARIMEKKO_ERR_ALLOCATION_IMBALANCE
    assert canvas.diagnostic_code == 0xA001
    assert bool(canvas.status_bits & MarimekkoStatusBits.ALLOCATION_IMBALANCE_TRIP)


def test_allocation_imbalance_interlock_zero_allocation() -> None:
    """Verify 0xA001 trips %M224 when single category has zero allocation."""
    canvas = create_canonical_marimekko_canvas()
    canvas.set_category_width(2, 0.0)
    assert canvas.allocation_imbalance_trip is True
    assert canvas.reg_table.read_bit("%M224") is True
    assert canvas.diagnostic_code == MARIMEKKO_ERR_ALLOCATION_IMBALANCE


def test_normalization_fault_interlock() -> None:
    """Verify 0xA002 clears %M225 when sum of column widths != 100%."""
    canvas = create_canonical_marimekko_canvas()
    assert canvas.marimekko_normalized is True
    assert canvas.reg_table.read_bit("%M225") is True

    canvas.trigger_normalization_fault(unnormalized_sum=92.0)
    assert canvas.marimekko_normalized is False
    assert canvas.reg_table.read_bit("%M225") is False
    assert canvas.diagnostic_code == MARIMEKKO_ERR_NORMALIZATION_FAULT
    assert canvas.diagnostic_code == 0xA002
    assert not bool(canvas.status_bits & MarimekkoStatusBits.MARIMEKKO_NORMALIZED)


def test_capacity_overrun_interlock() -> None:
    """Verify 0xA003 triggers when total resource demand exceeds 100%."""
    canvas = create_canonical_marimekko_canvas()
    canvas.trigger_capacity_overrun(overrun_pct=115.0)
    assert canvas.diagnostic_code == MARIMEKKO_ERR_CAPACITY_OVERRUN
    assert canvas.diagnostic_code == 0xA003
    assert bool(canvas.status_bits & MarimekkoStatusBits.CAPACITY_OVERRUN_ALARM)


def test_nominal_reset() -> None:
    """Verify nominal reset restores clean operating state."""
    canvas = create_canonical_marimekko_canvas()
    canvas.trigger_allocation_imbalance(0, 90.0)
    assert canvas.allocation_imbalance_trip is True

    canvas.reset_nominal()
    assert canvas.allocation_imbalance_trip is False
    assert canvas.marimekko_normalized is True
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.reg_table.read_bit("%M224") is False
    assert canvas.reg_table.read_bit("%M225") is True


# ============================================================================
# Section 5: Standalone W3C SVG 1.1 Vector Canvas Renderer
# ============================================================================

def test_svg_rendering_xml_validity() -> None:
    """Verify SVG renderer produces well-formed W3C XML."""
    canvas = create_canonical_marimekko_canvas()
    svg = canvas.render_svg()

    # XML Parser validation
    root = ET.fromstring(svg)
    assert root.tag == "{http://www.w3.org/2000/svg}svg"
    assert root.attrib["width"] == str(CANVAS_VIEWPORT_WIDTH)
    assert root.attrib["height"] == str(CANVAS_VIEWPORT_HEIGHT)


def test_svg_visual_elements_presence() -> None:
    """Verify SVG contains all required structural groups and theme colors."""
    canvas = create_canonical_marimekko_canvas()
    svg = canvas.render_svg()

    assert COLOR_DARK_THEME_BACKING in svg
    assert 'id="diagnostic-hud"' in svg
    assert 'id="mosaic-matrix"' in svg
    assert 'id="axis-x-cumulative"' in svg
    assert 'id="axis-y-cumulative"' in svg
    assert 'id="marimekko-columns"' in svg
    assert 'id="register-space-hud"' in svg
    assert 'id="active-column-focus"' in svg
    assert 'id="anomaly-alarm-indicator"' in svg

    # Color palette elements present
    assert COLOR_INDUSTRIAL_BLUE in svg
    assert COLOR_TEAL in svg
    assert COLOR_AMBER in svg
    assert COLOR_CORAL in svg
    assert COLOR_VIOLET in svg


# ============================================================================
# Section 6: WCAG 2.1 AAA Contrast & Accessibility
# ============================================================================

def test_wcag_aaa_contrast_metrics() -> None:
    """Verify WCAG 2.1 AAA contrast targets for text, graphics, and badges."""
    badge_contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    theme_contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    blue_contrast = calculate_contrast_ratio(COLOR_INDUSTRIAL_BLUE, COLOR_DARK_THEME_BACKING)
    amber_contrast = calculate_contrast_ratio(COLOR_AMBER, COLOR_DARK_THEME_BACKING)

    # Badge contrast target > 18:1
    assert badge_contrast >= WCAG_AAA_BADGE_CONTRAST_TARGET
    assert badge_contrast > 18.0

    # Normal text contrast target > 7.0:1
    assert theme_contrast >= WCAG_AAA_TEXT_CONTRAST_TARGET

    # Graphical contrast target > 3.0:1
    assert blue_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET
    assert amber_contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET

    ok, t_c, g_c = validate_wcag_aaa_contrast()
    assert ok is True
    assert t_c >= 7.0
    assert g_c >= 3.0


# ============================================================================
# Section 7: Active Column Focus & Index Switching
# ============================================================================

def test_active_column_switching() -> None:
    """Verify active column switching updates focus, registers, and metrics."""
    canvas = create_canonical_marimekko_canvas(active_index=0)
    assert canvas.active_column_index == 0
    assert canvas.metrics.segment1_height_scaled == 600
    assert canvas.metrics.segment2_height_scaled == 400

    canvas.set_active_column(1)
    assert canvas.active_column_index == 1
    assert canvas.metrics.segment1_height_scaled == 500
    assert canvas.metrics.segment2_height_scaled == 500
    assert canvas.reg_table.read_word("%R966") == 1
    assert canvas.reg_table.read_word("%R963") == 500
    assert canvas.reg_table.read_word("%R964") == 500

    canvas.set_active_column(2)
    assert canvas.active_column_index == 2
    assert canvas.metrics.segment1_height_scaled == 700
    assert canvas.metrics.segment2_height_scaled == 300
    assert canvas.reg_table.read_word("%R966") == 2
    assert canvas.reg_table.read_word("%R963") == 700
    assert canvas.reg_table.read_word("%R964") == 300


# ============================================================================
# Section 8: Horner OCS Register Space & Scan Cycle Execution
# ============================================================================

def test_horner_ocs_register_synchronization() -> None:
    """Verify full Horner OCS memory map bindings (%R960..%R967, %M224..%M225)."""
    canvas = create_canonical_marimekko_canvas(active_index=0)
    ctx = create_mock_scan_context(reg_table=canvas.reg_table)
    canvas.execute(ctx)

    reg = canvas.reg_table
    assert reg.read_word("%R960") == 450      # 45.0% Category 1
    assert reg.read_word("%R961") == 350      # 35.0% Category 2
    assert reg.read_word("%R962") == 200      # 20.0% Category 3
    assert reg.read_word("%R963") == 600      # 60.0% Segment 1
    assert reg.read_word("%R964") == 400      # 40.0% Segment 2
    assert reg.read_word("%R965") == 1000     # 100.0% Total Area
    assert reg.read_word("%R966") == 0        # Active Column Index
    assert reg.read_word("%R967") == DIAG_EVENT_OK
    assert reg.read_bit("%M224") is False     # AllocationImbalanceTrip
    assert reg.read_bit("%M225") is True      # MarimekkoNormalized


def test_logic_unit_scan_lifecycle() -> None:
    """Verify ILogicUnit interface properties and scan lifecycle methods."""
    canvas = create_canonical_marimekko_canvas()
    assert canvas.name == "MarimekkoCanvasSync"
    assert canvas.priority == 79
    assert canvas.is_enabled is True

    canvas.step()
    ctx = create_mock_scan_context(reg_table=canvas.reg_table)
    canvas.execute_logic(ctx)
    canvas.reset()
    assert canvas.diagnostic_code == DIAG_EVENT_OK


# ============================================================================
# Section 9: Deterministic 9-Stage Verification Suite Runner
# ============================================================================

def test_deterministic_9_stage_verification_suite(tmp_path: Path) -> None:
    """Verify run_marimekko_canvas_verification executes cleanly across all 9 stages."""
    evidence_path = tmp_path / "test_evidence.json"
    svg_path = tmp_path / "test_canvas.svg"

    result = run_marimekko_canvas_verification(
        output_path=evidence_path,
        sample_svg_path=svg_path,
    )

    assert result["status"] == "success"
    assert result["error_code"] is None
    data = result["data"]
    assert data["checks_passed"] == 9
    assert data["total_checks"] == 9
    assert len(data["tests"]) == 9
    assert all(t["passed"] for t in data["tests"])

    # Verify generated artifacts
    assert evidence_path.exists()
    assert svg_path.exists()
    assert evidence_path.stat().st_size > 0
    assert svg_path.stat().st_size > 0
