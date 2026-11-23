"""Unit and integration tests for Cscape HMI Vector Gauge & Polar Compass Dial.

Work Package: W075 (Gate G9 / G2)
Verifies:
- 270-degree radial gauge deflection angle mapping (-225.0° to +45.0°)
- 360-degree polar compass azimuth angle mapping (0.0° to 360.0°)
- Threshold classification: Normal, Warning, Danger status bits
- Peak hold tracking and reset handshake
- W3C SVG vector rendering and well-formed XML structure
- Pure ST POU AST parsing and Horner OCS register bindings (%R360..%R367, %M84..%M85)
- Hard fail-closed rejection of forbidden ladder logic constructs
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.vector_gauge import (
    CompassPointMode,
    DialMode,
    VECTOR_GAUGE_ST_CODE,
    VectorDialConfig,
    VectorGaugeEngine,
)
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import RegisterTable


def test_radial_gauge_angle_synthesis() -> None:
    """Verify radial gauge angle sweep (-2250 to +450, representing -225.0° to +45.0°)."""
    engine = VectorGaugeEngine()

    # 0%
    engine.update(0)
    assert engine.needle_deflection_angle == -2250

    # 50%
    engine.update(5000)
    assert engine.needle_deflection_angle == -900

    # 100%
    engine.update(10000)
    assert engine.needle_deflection_angle == 450


def test_polar_compass_azimuth_angle_synthesis() -> None:
    """Verify polar compass azimuth mapping (0..3600, representing 0.0° to 360.0°)."""
    cfg = VectorDialConfig(mode=DialMode.POLAR_COMPASS)
    engine = VectorGaugeEngine(cfg)

    # 0% -> 0.0° (North)
    engine.update(0)
    assert engine.needle_deflection_angle == 0

    # 25% -> 90.0° (East)
    engine.update(2500)
    assert engine.needle_deflection_angle == 900

    # 50% -> 180.0° (South)
    engine.update(5000)
    assert engine.needle_deflection_angle == 1800

    # 75% -> 270.0° (West)
    engine.update(7500)
    assert engine.needle_deflection_angle == 2700


def test_threshold_bands_status_bits() -> None:
    """Verify multi-band threshold status bits (Normal, Warning, Danger)."""
    engine = VectorGaugeEngine()

    # Normal band: 50.00% < 70.00%
    engine.update(5000)
    assert engine.status_word & 0x0002 != 0  # Normal Band
    assert engine.status_word & 0x0004 == 0
    assert engine.status_word & 0x0008 == 0

    # Warning band: 75.00% (70.00% <= PV < 85.00%)
    engine.update(7500)
    assert engine.status_word & 0x0004 != 0  # Warning Band
    assert engine.status_word & 0x0008 == 0

    # Danger band: 90.00% >= 85.00%
    engine.update(9000)
    assert engine.status_word & 0x0008 != 0  # Danger Band


def test_peak_hold_and_reset_handshake() -> None:
    """Verify peak hold monotonically latches max value and clears on reset pulse."""
    engine = VectorGaugeEngine()
    engine.update(4000)
    assert engine.peak_hold_value == 4000

    engine.update(8000)
    assert engine.peak_hold_value == 8000

    engine.update(2000)
    assert engine.peak_hold_value == 8000  # Remains held at peak

    # Reset handshake
    engine.reset_peak_hold = True
    engine.update(2000)
    assert engine.peak_hold_value == 2000
    assert engine.reset_peak_hold is False
    assert engine.status_word & 0x0040 != 0  # Reset Ack bit


def test_svg_vector_rendering_valid_xml() -> None:
    """Verify standalone SVG export produces valid W3C XML for both modes."""
    # 1. Radial Gauge
    engine_gauge = VectorGaugeEngine()
    engine_gauge.update(6500)
    svg_gauge = engine_gauge.render_svg()
    root_g = ET.fromstring(svg_gauge)
    assert root_g.tag.endswith("svg")
    assert "viewBox" in root_g.attrib

    # 2. Polar Compass
    cfg_comp = VectorDialConfig(mode=DialMode.POLAR_COMPASS)
    engine_comp = VectorGaugeEngine(cfg_comp)
    engine_comp.update(4500)
    svg_comp = engine_comp.render_svg()
    root_c = ET.fromstring(svg_comp)
    assert root_c.tag.endswith("svg")
    assert "viewBox" in root_c.attrib


def test_w075_st_pou_ast_parsing_and_bindings() -> None:
    """Verify IEC 61131-3 Pure ST POU syntax and register bindings."""
    val = STParser.validate_code(VECTOR_GAUGE_ST_CODE)
    assert val.status == AgentStatus.SUCCESS
    assert val.error_code is None

    ast = STParser.parse_pou(VECTOR_GAUGE_ST_CODE)
    assert ast.name == "VectorGaugeRasterizerSync"
    assert ast.pou_type == POUType.PROGRAM
    expected_bindings = {
        "%R360", "%R361", "%R362", "%R363", "%R364", "%R365", "%R366", "%R367",
        "%M84", "%M85"
    }
    assert set(ast.bound_registers) == expected_bindings
    assert ast.statements_count > 0


@pytest.mark.parametrize(
    "ladder_artifact",
    [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(S)---",
        "---(R)---",
        "RUNG 1",
        "END_RUNG",
        "NETWORK 10",
        "XIC EnableEngine",
        "XIO ResetPeakHold",
        "OTE StatusWord",
        "OTL DeflectionAngle",
        "OTU PeakHoldVal",
    ],
)
def test_w075_forbidden_ladder_constructs_rejected(ladder_artifact: str) -> None:
    """Verify ladder logic tokens are strictly rejected with ERR_LADDER_FORBIDDEN."""
    bad_code = f"{VECTOR_GAUGE_ST_CODE}\n{ladder_artifact}\n"
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_code)
    res = STParser.validate_code(bad_code)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "ERR_LADDER_FORBIDDEN"
    assert res.data["ladder_rejected"] is True


def test_register_table_sync() -> None:
    """Verify synchronization between VectorGaugeEngine and Horner RegisterTable."""
    table = RegisterTable()
    engine = VectorGaugeEngine()

    table.write_register("%R361", 7200)  # 72.00%
    table.write_register("%M84", True)
    table.write_register("%M85", False)

    engine.sync_from_registers(table)
    assert engine.input_pv_scaled == 7200
    assert engine.needle_deflection_angle == -306  # -225.0 + 0.72*270 = -30.6° (-306)
    assert engine.status_word & 0x0004 != 0        # Warning band

    engine.sync_to_registers(table)
    assert table.read_register("%R360") == engine.status_word
    assert table.read_register("%R362") == engine.needle_deflection_angle
    assert table.read_register("%R367") == engine.peak_hold_value
