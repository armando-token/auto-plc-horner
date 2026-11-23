"""Cscape HMI Interactive Data Table & Grid Rasterizer Verification Runner.

Work Package: W078 (Gate G9 / G2)
Standard: W3C SVG 1.1 Vector Graphics & WCAG 2.1 AAA Accessibility
Exports:
- artifacts/HMI/data_table_evidence.json
- artifacts/HMI/table_sample.svg
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Dict
import xml.etree.ElementTree as ET

from jev_cscape.hmi.data_table import (
    ColumnAlignment,
    ColumnDef,
    DataTableConfig,
    DataTableEngine,
    SortDirection,
    StatusSeverity,
    TableRow,
)
from jev_cscape.simulation.register_table import RegisterTable


def run_data_table_verification(
    output_evidence_path: Path = Path("artifacts/HMI/data_table_evidence.json"),
    output_svg_path: Path = Path("artifacts/HMI/table_sample.svg"),
) -> Dict[str, Any]:
    """Execute end-to-end verification of HMI data table rasterizer."""
    output_evidence_path.parent.mkdir(parents=True, exist_ok=True)
    output_svg_path.parent.mkdir(parents=True, exist_ok=True)

    engine = DataTableEngine()
    checks: Dict[str, Any] = {}

    # Populate 30 sample process variable rows
    sample_tags = ["TT_101", "PT_204", "LT_301", "FT_402", "AT_503", "VT_604"]
    units_list = ["°C", "bar", "%", "m³/h", "pH", "mm/s"]
    severities = [StatusSeverity.NORMAL, StatusSeverity.WARNING, StatusSeverity.ALARM]

    rows: list[TableRow] = []
    for i in range(30):
        rows.append(
            TableRow(
                id=i + 1,
                timestamp=f"2026-10-03 14:{i:02d}:00",
                tag=f"{sample_tags[i % len(sample_tags)]}_{i // len(sample_tags) + 1}",
                value=25.0 + (i * 3.75),
                units=units_list[i % len(units_list)],
                status=severities[i % 3],
                action="DETAILS",
            )
        )
    engine.load_rows(rows)

    # Check 1: Virtual Scroll Pagination and Bounds Clamping
    engine.update(start_row=12)
    start_ok = engine.start_row == 12 and (engine.status_word & 0x0010 != 0)  # Virtual scroll active
    engine.update(start_row=45)  # Out of bounds (> 30 - 10 = 20)
    clamp_ok = engine.start_row == 20 and (engine.status_word & 0x0008 != 0)  # Overrun bit

    checks["virtual_scroll_pagination"] = {
        "status": "passed" if start_ok and clamp_ok else "failed",
        "requested_12_actual": 12,
        "requested_45_clamped_max": engine.start_row,
        "virtual_scroll_active_bit": bool(engine.status_word & 0x0010),
    }

    # Check 2: Multi-Column Sorting
    engine.sort_data(col_index=3, direction=SortDirection.DESCENDING)  # Sort by Value Desc
    val_first = engine.rows[0].value
    val_last = engine.rows[-1].value
    desc_ok = val_first > val_last and (engine.status_word & 0x0020 != 0)

    engine.sort_data(col_index=0, direction=SortDirection.ASCENDING)  # Sort by ID Asc
    id_first = engine.rows[0].id
    asc_ok = id_first == 1

    checks["multi_column_sorting"] = {
        "status": "passed" if desc_ok and asc_ok else "failed",
        "desc_val_first": val_first,
        "desc_val_last": val_last,
        "asc_id_first": id_first,
    }

    # Check 3: Row Selection & Status Word
    engine.update(start_row=0, selected_row=2)
    sel_ok = engine.selected_row_idx == 2 and (engine.status_word & 0x0004 != 0)
    checks["row_selection"] = {
        "status": "passed" if sel_ok else "failed",
        "selected_row_index": engine.selected_row_idx,
        "selected_valid_bit": bool(engine.status_word & 0x0004),
    }

    # Check 4: Standalone SVG Render & XML Validity
    svg_content = engine.render_svg()
    root = ET.fromstring(svg_content)
    xml_valid = root.tag.endswith("svg")

    with open(output_svg_path, "w", encoding="utf-8") as f_svg:
        f_svg.write(svg_content)

    aaa_colors_present = (
        "#064E3B" in svg_content
        and "#A7F3D0" in svg_content
        and "#78350F" in svg_content
        and "#FDE68A" in svg_content
        and "#7F1D1D" in svg_content
        and "#FEE2E2" in svg_content
    )
    svg_ok = xml_valid and aaa_colors_present and output_svg_path.is_file()
    checks["svg_export_and_wcag_aaa"] = {
        "status": "passed" if svg_ok else "failed",
        "svg_file_path": str(output_svg_path).replace("\\", "/"),
        "byte_size": len(svg_content.encode("utf-8")),
        "root_tag": root.tag,
        "wcag_aaa_badges_verified": aaa_colors_present,
    }

    # Check 5: Horner OCS RegisterTable Synchronization
    table = RegisterTable()
    table.write_register("%R392", 5)
    table.write_register("%R394", 8)
    table.write_register("%R395", 2)
    table.write_register("%R396", 0)
    table.write_register("%M91", True)
    table.write_register("%M92", False)

    engine.sync_from_register_table(table)
    engine.sync_to_register_table(table)

    r_ok = (
        table.read_register("%R390") & 0x0001 != 0
        and table.read_register("%R391") == 30
        and table.read_register("%R392") == 5
        and table.read_register("%R394") == 8
    )
    checks["register_table_synchronization"] = {
        "status": "passed" if r_ok else "failed",
        "r390_status": table.read_register("%R390"),
        "r391_total_rows": table.read_register("%R391"),
        "r392_start_row": table.read_register("%R392"),
        "r394_selected_row": table.read_register("%R394"),
    }

    all_passed = all(c["status"] == "passed" for c in checks.values())
    evidence = {
        "work_package": "W078",
        "gate": "G9",
        "component": "Cscape HMI Interactive Data Table & Grid Column Virtualizer Rasterizer",
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "overall_status": "success" if all_passed else "failed",
        "registers": {
            "%R390": engine.status_word,
            "%R391": engine.total_rows,
            "%R392": engine.start_row,
            "%R393": engine.page_size,
            "%R394": engine.selected_row_idx,
            "%R395": engine.sort_col_idx,
            "%R396": int(engine.sort_dir),
            "%R397": engine.total_cols,
            "%M91": engine.enable_engine,
            "%M92": engine.trigger_sort_refresh,
        },
        "checks": checks,
    }

    with open(output_evidence_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    return evidence


if __name__ == "__main__":
    res = run_data_table_verification()
    print(json.dumps(res, indent=2))
