"""Unit and integration tests for Cscape HMI Interactive Data Table & Grid Rasterizer.

Work Package: W078 (Gate G9 / G2)
Verifies:
- Viewport window virtualization & pagination bounds clamping
- Multi-column data sorting (ascending and descending)
- Active row selection & visual accent highlight
- WCAG 2.1 AAA status badge pill rendering and redundant glyphs
- Standalone W3C SVG 1.1 well-formed XML generation
- Horner OCS register space synchronization (%R390..%R397, %M91..%M92)
- Pure ST POU AST parsing and variable binding extraction
- Hard fail-closed rejection of forbidden ladder logic constructs
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.data_table import (
    ColumnAlignment,
    ColumnDef,
    DATA_TABLE_ST_CODE,
    DataTableConfig,
    DataTableEngine,
    SortDirection,
    StatusSeverity,
    TableRow,
)
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import RegisterTable


def _create_sample_rows(count: int = 25) -> list[TableRow]:
    rows: list[TableRow] = []
    severities = [StatusSeverity.NORMAL, StatusSeverity.WARNING, StatusSeverity.ALARM]
    for i in range(count):
        rows.append(
            TableRow(
                id=i + 1,
                timestamp=f"2026-10-03 12:{i:02d}:00",
                tag=f"TT_{100 + i}",
                value=50.0 + (i * 2.5),
                units="°C",
                status=severities[i % 3],
                action="VIEW",
            )
        )
    return rows


def test_virtual_window_and_clamping() -> None:
    """Verify virtual scroll window clamps start row to [0..N - page_size]."""
    engine = DataTableEngine()
    engine.load_rows(_create_sample_rows(25))

    # Requested start row within valid range
    engine.update(start_row=5)
    assert engine.start_row == 5
    assert engine.status_word & 0x0010 != 0  # Virtual scroll active

    # Requested start row beyond max start (25 - 10 = 15)
    engine.update(start_row=20)
    assert engine.start_row == 15
    assert engine.status_word & 0x0008 != 0  # Row overrun warning

    # Negative start row
    engine.update(start_row=-5)
    assert engine.start_row == 0
    assert engine.status_word & 0x0008 != 0  # Row overrun warning


def test_multi_column_sorting() -> None:
    """Verify sorting buffer ascending and descending by column index."""
    engine = DataTableEngine()
    engine.load_rows(_create_sample_rows(15))

    # Sort by ID descending
    engine.sort_data(col_index=0, direction=SortDirection.DESCENDING)
    assert engine.rows[0].id == 15
    assert engine.rows[-1].id == 1
    assert engine.status_word & 0x0020 != 0  # Reverse sort bit

    # Sort by Tag ascending
    engine.sort_data(col_index=2, direction=SortDirection.ASCENDING)
    assert engine.rows[0].tag <= engine.rows[1].tag
    assert engine.status_word & 0x0020 == 0


def test_row_selection_and_status_bits() -> None:
    """Verify selected row validation and status word bitmask."""
    engine = DataTableEngine()
    engine.load_rows(_create_sample_rows(20))

    # Valid selection
    engine.update(start_row=0, selected_row=3)
    assert engine.selected_row_idx == 3
    assert engine.status_word & 0x0004 != 0  # Selected valid

    # Invalid selection (-1 or >= total_rows)
    engine.update(start_row=0, selected_row=-1)
    assert engine.selected_row_idx == -1
    assert engine.status_word & 0x0004 == 0

    engine.update(start_row=0, selected_row=50)
    assert engine.selected_row_idx == -1
    assert engine.status_word & 0x0004 == 0


def test_standalone_svg_rendering_and_xml_validity() -> None:
    """Verify SVG generation produces well-formed W3C XML with AAA contrast badges."""
    engine = DataTableEngine()
    engine.load_rows(_create_sample_rows(20))
    engine.update(start_row=2, selected_row=4)

    svg_content = engine.render_svg()
    assert len(svg_content) > 500

    # Parse XML
    root = ET.fromstring(svg_content)
    assert root.tag.endswith("svg")
    assert "viewBox" in root.attrib

    # Check for accessibility roles and labels
    assert 'role="grid"' in svg_content
    assert 'role="status"' in svg_content

    # Check for WCAG AAA hardened status badge colors
    assert "#064E3B" in svg_content  # Normal BG
    assert "#A7F3D0" in svg_content  # Normal text (7.58:1)
    assert "#78350F" in svg_content  # Warning BG
    assert "#FDE68A" in svg_content  # Warning text (7.28:1)
    assert "#7F1D1D" in svg_content  # Alarm BG
    assert "#FEE2E2" in svg_content  # Alarm text (8.20:1)

    # Check for 4px left accent border on selected row
    assert "#38BDF8" in svg_content


def test_register_table_synchronization() -> None:
    """Verify bidirectional synchronization with Horner OCS RegisterTable."""
    engine = DataTableEngine()
    engine.load_rows(_create_sample_rows(30))
    table = RegisterTable()

    table.write_register("%R392", 8)   # Start row 8
    table.write_register("%R394", 12)  # Selected row 12
    table.write_register("%R395", 3)   # Sort col 3 (Value)
    table.write_register("%R396", 1)   # Sort dir 1 (Desc)
    table.write_register("%M91", True)
    table.write_register("%M92", True)  # Trigger sort

    engine.sync_from_register_table(table)
    assert engine.start_row == 8
    assert engine.selected_row_idx == 12
    assert engine.sort_col_idx == 3
    assert engine.sort_dir == SortDirection.DESCENDING

    engine.sync_to_register_table(table)
    assert table.read_register("%R390") & 0x0001 != 0  # Active
    assert table.read_register("%R391") == 30          # Total rows
    assert table.read_register("%R392") == 8
    assert table.read_register("%R394") == 12


def test_data_table_st_pou_ast_parsing_and_bindings() -> None:
    """Verify IEC 61131-3 Pure ST POU syntax and register bindings."""
    val = STParser.validate_code(DATA_TABLE_ST_CODE)
    assert val.status == AgentStatus.SUCCESS
    assert val.error_code is None

    ast = STParser.parse_pou(DATA_TABLE_ST_CODE)
    assert ast.name == "DataTableGridRasterizerSync"
    assert ast.pou_type == POUType.PROGRAM
    expected_bindings = {
        "%R390", "%R391", "%R392", "%R393", "%R394", "%R395", "%R396", "%R397",
        "%M91", "%M92"
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
        "XIO TriggerSortRefresh",
        "OTE StatusWord",
        "OTL VirtualScroll",
        "OTU RowOverrun",
    ],
)
def test_data_table_forbidden_ladder_constructs_rejected(ladder_artifact: str) -> None:
    """Verify ladder logic tokens are strictly rejected with ERR_LADDER_FORBIDDEN."""
    bad_code = f"{DATA_TABLE_ST_CODE}\n{ladder_artifact}\n"
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_code)
    res = STParser.validate_code(bad_code)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "ERR_LADDER_FORBIDDEN"
    assert res.data["ladder_rejected"] is True
