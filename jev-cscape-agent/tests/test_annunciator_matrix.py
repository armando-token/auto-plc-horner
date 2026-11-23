"""Unit and integration tests for Cscape HMI Dynamic Annunciator Matrix & Alarm Panel Rasterizer.

Work Package: W081 (Gate G9 / G2)
Classification: PRODUCTION_READY
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.annunciator_matrix import (
    ANNUNCIATOR_ST_CODE,
    AlarmPriority,
    AnnunciatorMatrixEngine,
    AnnunciatorPanelConfig,
    AnnunciatorSVGGenerator,
    AnnunciatorState,
    AnnunciatorTile,
    LampFlashMode,
    validate_pure_st,
    wrap_label,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import RegisterTable


# ============================================================================
# 1. Typography & Label Wrapping Tests
# ============================================================================

def test_wrap_label_two_lines() -> None:
    """Verify word-boundary auto-wrapping across two lines."""
    text = "FEED PUMP BEARING HIGH TEMP"
    lines = wrap_label(text, max_chars_per_line=20, max_lines=2)
    assert len(lines) == 2
    assert lines[0] == "FEED PUMP BEARING"
    assert lines[1] == "HIGH TEMP"


def test_wrap_label_short_and_empty() -> None:
    """Verify short text remains single line and empty returns empty list."""
    assert wrap_label("SHORT", max_chars_per_line=20, max_lines=2) == ["SHORT"]
    assert wrap_label("", max_chars_per_line=20, max_lines=2) == []
    assert wrap_label("   ", max_chars_per_line=20, max_lines=2) == []


def test_wrap_label_long_truncation() -> None:
    """Verify exceeding maximum lines adds ellipsis truncation."""
    text = "VERY LONG PROCESS ALARM DESCRIPTION THAT EXCEEDS MULTIPLE LINES IN THE MATRIX"
    lines = wrap_label(text, max_chars_per_line=18, max_lines=2)
    assert len(lines) == 2
    assert lines[1].endswith("...")


# ============================================================================
# 2. ISA-18.1 Sequence State Machine Tests
# ============================================================================

def test_sequence_m_manual_reset_ringback() -> None:
    """Verify ISA-18.1 Sequence M: Trip -> Fast Flash -> Ack -> Steady -> Clear -> Slow Flash (Ringback) -> Reset -> Normal."""
    engine = AnnunciatorMatrixEngine(sequence_mode="M")
    tile_idx = 0

    # 1. Normal state
    assert engine.tiles[tile_idx].state == AnnunciatorState.NORMAL
    assert engine.tiles[tile_idx].lamp_mode == LampFlashMode.OFF
    assert not engine.horn_active

    # 2. Process Trip -> Fast Flash + Horn
    engine.trip_alarm(tile_idx, status_line="TRIP 92.4 °C")
    assert engine.tiles[tile_idx].state == AnnunciatorState.UNACKNOWLEDGED
    assert engine.tiles[tile_idx].lamp_mode == LampFlashMode.FAST_FLASH
    assert engine.horn_active
    assert engine.first_out_latched
    assert engine.first_out_index == tile_idx

    # 3. Operator Ack (%M98) -> Steady + Horn Silenced
    engine.operator_ack()
    assert engine.tiles[tile_idx].state == AnnunciatorState.ACKNOWLEDGED
    assert engine.tiles[tile_idx].lamp_mode == LampFlashMode.STEADY
    assert not engine.horn_active

    # 4. Process Returns to Normal -> Ringback (Slow Flash)
    engine.clear_alarm(tile_idx)
    assert engine.tiles[tile_idx].state == AnnunciatorState.RETURNED_UNACKNOWLEDGED
    assert engine.tiles[tile_idx].lamp_mode == LampFlashMode.SLOW_FLASH

    # 5. Operator Silence / Reset (%M99) -> Normal + Lamp Off
    engine.operator_silence_reset()
    assert engine.tiles[tile_idx].state == AnnunciatorState.NORMAL
    assert engine.tiles[tile_idx].lamp_mode == LampFlashMode.OFF
    assert not engine.first_out_latched


def test_sequence_a_automatic_reset() -> None:
    """Verify ISA-18.1 Sequence A: Trip -> Ack -> Clear -> Auto Reset to Normal."""
    engine = AnnunciatorMatrixEngine(sequence_mode="A")
    tile_idx = 2

    engine.trip_alarm(tile_idx)
    assert engine.tiles[tile_idx].state == AnnunciatorState.UNACKNOWLEDGED

    engine.operator_ack()
    assert engine.tiles[tile_idx].state == AnnunciatorState.ACKNOWLEDGED

    engine.clear_alarm(tile_idx)
    assert engine.tiles[tile_idx].state == AnnunciatorState.NORMAL
    assert engine.tiles[tile_idx].lamp_mode == LampFlashMode.OFF


def test_first_out_alarm_capture() -> None:
    """Verify first-out alarm is latched to the initial event in a cascade trip chain."""
    engine = AnnunciatorMatrixEngine(sequence_mode="M")

    # Trip initial alarm
    engine.trip_alarm(3)
    assert engine.first_out_index == 3
    assert engine.tiles[3].is_first_out

    # Subsequent trips in cascade must NOT overwrite first-out
    engine.trip_alarm(0)
    engine.trip_alarm(5)
    assert engine.first_out_index == 3
    assert not engine.tiles[0].is_first_out
    assert not engine.tiles[5].is_first_out


def test_operator_silence_horn() -> None:
    """Verify pressing silence when horn is sounding silences horn without clearing unacknowledged alarms."""
    engine = AnnunciatorMatrixEngine(sequence_mode="M")
    engine.trip_alarm(1)
    assert engine.horn_active

    engine.operator_silence_reset()
    assert not engine.horn_active
    assert engine.tiles[1].state == AnnunciatorState.SILENCED


# ============================================================================
# 3. SVG Generation & XML Well-Formedness
# ============================================================================

def test_svg_rendering_12_tiles() -> None:
    """Verify SVG generation renders 12-tile grid and parses cleanly in ElementTree."""
    engine = AnnunciatorMatrixEngine()
    engine.trip_alarm(0)
    engine.operator_ack()
    engine.trip_alarm(1)

    svg_content = engine.render_svg()
    assert "<svg" in svg_content
    assert "</svg>" in svg_content

    # XML validation
    root = ET.fromstring(svg_content)
    assert root.tag.endswith("svg")
    assert root.attrib["viewBox"] == "0 0 800 480"

    # Verify tile group elements
    grid_elem = root.find(".//*[@id='annunciator-grid']")
    assert grid_elem is not None
    tiles = [e for e in grid_elem if e.attrib.get("id", "").startswith("tile-")]
    assert len(tiles) == 12

    # Verify redundant glyphs
    assert "◆" in svg_content
    assert "★" in svg_content  # First out marker


def test_lamp_test_mode_rendering() -> None:
    """Verify lamp test mode renders all tiles active and lit."""
    engine = AnnunciatorMatrixEngine()
    engine.operator_lamp_test(True)
    assert engine.lamp_test_active

    svg = engine.render_svg()
    assert 'id="btn-TEST"' in svg
    assert "LAMP TEST" in svg


# ============================================================================
# 4. Horner OCS Register Space Synchronization
# ============================================================================

def test_horner_register_table_sync() -> None:
    """Verify Horner OCS register mapping (%R420..%R427, %M98..%M99)."""
    table = RegisterTable()
    engine = AnnunciatorMatrixEngine(register_table=table)

    # Initial normal state
    engine.sync_to_register_table(table)
    assert table.read_register("%R420") & 0x0001 != 0  # Active
    assert table.read_register("%R421") == 0          # 0 active
    assert table.read_register("%R422") == 0          # 0 unack
    assert table.read_register("%R423") == -1         # No first-out

    # Trip alarms
    engine.trip_alarm(0)
    engine.trip_alarm(4)
    engine.sync_to_register_table(table)

    r420 = table.read_register("%R420")
    assert r420 & 0x0002 != 0  # Any Unack
    assert r420 & 0x0004 != 0  # Horn Active
    assert r420 & 0x0008 != 0  # First-Out Latched
    assert table.read_register("%R421") == 2
    assert table.read_register("%R422") == 2
    assert table.read_register("%R423") == 0

    # Operator ACK via %M98
    table.write_register("%M98", True)
    engine.sync_from_register_table(table)
    engine.sync_to_register_table(table)

    assert table.read_register("%M98") is False  # Self-cleared
    assert not engine.horn_active
    assert table.read_register("%R422") == 0     # 0 unack
    assert table.read_register("%R421") == 2     # Still 2 active (acknowledged)

    # Verify bitfields for Tile 0 (Ack = 2) and Tile 4 (Ack = 2)
    r425 = table.read_register("%R425")  # Tiles 0..3
    assert r425 & 0x03 == 2              # Tile 0 is code 2 (Ack)
    r426 = table.read_register("%R426")  # Tiles 4..7
    assert r426 & 0x03 == 2              # Tile 4 is code 2 (Ack)


# ============================================================================
# 5. Pure ST POU & Forbidden Ladder Logic Rejection Guard
# ============================================================================

def test_annunciator_st_pou_ast_parsing() -> None:
    """Verify IEC 61131-3 Pure ST POU syntax and register bindings."""
    val = validate_pure_st()
    assert val.status == AgentStatus.SUCCESS
    assert val.error_code is None

    ast = STParser.parse_pou(ANNUNCIATOR_ST_CODE)
    assert ast.name == "W081_AnnunciatorEngine"
    assert ast.pou_type == POUType.PROGRAM
    expected_bindings = {
        "%R420", "%R421", "%R422", "%R423", "%R424", "%R425", "%R426", "%R427",
        "%M98", "%M99",
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
        "XIC PbAck",
        "XIO PbSilenceReset",
        "OTE StatusWord",
        "OTL FirstOutLatched",
        "OTU HornActive",
    ],
)
def test_annunciator_forbidden_ladder_constructs_rejected(ladder_artifact: str) -> None:
    """Verify ladder logic tokens are strictly rejected with ERR_LADDER_FORBIDDEN."""
    bad_code = f"{ANNUNCIATOR_ST_CODE}\n{ladder_artifact}\n"
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_code)
    res = STParser.validate_code(bad_code)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "ERR_LADDER_FORBIDDEN"
    assert res.data["ladder_rejected"] is True
