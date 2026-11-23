"""Cscape HMI Dynamic Annunciator Matrix & Alarm Panel Rasterizer Verification Runner.

Work Package: W081 (Gate G9 HMI Graphics / Gate G2 UI Engine)
Standard: ISA-18.1 / ISA-18.2 Annunciator Sequences, W3C SVG 1.1 Vector Graphics & WCAG 2.1 AAA Contrast
Exports:
- artifacts/HMI/annunciator_matrix_evidence.json
- artifacts/HMI/annunciator_sample.svg
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Dict
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.annunciator_matrix import (
    ANNUNCIATOR_ST_CODE,
    AlarmPriority,
    AnnunciatorMatrixEngine,
    AnnunciatorPanelConfig,
    AnnunciatorState,
    AnnunciatorTile,
    LampFlashMode,
    validate_pure_st,
    wrap_label,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.simulation.register_table import RegisterTable


def run_annunciator_matrix_verification(
    output_evidence_path: Path = Path("artifacts/HMI/annunciator_matrix_evidence.json"),
    output_svg_path: Path = Path("artifacts/HMI/annunciator_sample.svg"),
) -> Dict[str, Any]:
    """Execute end-to-end verification of HMI annunciator matrix rasterizer."""
    output_evidence_path.parent.mkdir(parents=True, exist_ok=True)
    output_svg_path.parent.mkdir(parents=True, exist_ok=True)

    engine = AnnunciatorMatrixEngine(sequence_mode="M")
    checks: Dict[str, Any] = {}

    # Check 1: ISA-18.1 Sequence M State Machine & Flashing
    engine.trip_alarm(0, status_line="92.4 °C | TRIP")
    trip_ok = (
        engine.tiles[0].state == AnnunciatorState.UNACKNOWLEDGED
        and engine.tiles[0].lamp_mode == LampFlashMode.FAST_FLASH
        and engine.horn_active
        and engine.first_out_latched
        and engine.first_out_index == 0
    )

    engine.operator_ack()
    ack_ok = (
        engine.tiles[0].state == AnnunciatorState.ACKNOWLEDGED
        and engine.tiles[0].lamp_mode == LampFlashMode.STEADY
        and not engine.horn_active
    )

    engine.clear_alarm(0)
    clear_ok = (
        engine.tiles[0].state == AnnunciatorState.RETURNED_UNACKNOWLEDGED
        and engine.tiles[0].lamp_mode == LampFlashMode.SLOW_FLASH
    )

    engine.operator_silence_reset()
    reset_ok = (
        engine.tiles[0].state == AnnunciatorState.NORMAL
        and engine.tiles[0].lamp_mode == LampFlashMode.OFF
        and not engine.first_out_latched
    )

    checks["isa181_sequence_m_lifecycle"] = {
        "status": "passed" if trip_ok and ack_ok and clear_ok and reset_ok else "failed",
        "trip_fast_flash": trip_ok,
        "operator_ack_steady": ack_ok,
        "clear_ringback_slow_flash": clear_ok,
        "silence_reset_normal": reset_ok,
    }

    # Check 2: First-Out Alarm Capture across Cascade Trips
    engine_fo = AnnunciatorMatrixEngine(sequence_mode="M")
    engine_fo.trip_alarm(4)  # Initial trip
    engine_fo.trip_alarm(1)  # Cascade trips
    engine_fo.trip_alarm(7)

    fo_ok = (
        engine_fo.first_out_index == 4
        and engine_fo.tiles[4].is_first_out
        and not engine_fo.tiles[1].is_first_out
        and not engine_fo.tiles[7].is_first_out
    )
    checks["first_out_cascade_capture"] = {
        "status": "passed" if fo_ok else "failed",
        "latched_first_out_index": engine_fo.first_out_index,
        "expected_first_out_index": 4,
        "non_initial_first_out_flag": engine_fo.tiles[1].is_first_out,
    }

    # Check 3: Multi-Line Word-Boundary Typography Wrapping
    w_lines = wrap_label("FEED PUMP BEARING HIGH TEMP", max_chars_per_line=20, max_lines=2)
    wrap_ok = len(w_lines) == 2 and w_lines[0] == "FEED PUMP BEARING" and w_lines[1] == "HIGH TEMP"
    checks["typography_word_wrap"] = {
        "status": "passed" if wrap_ok else "failed",
        "line_count": len(w_lines),
        "lines": w_lines,
    }

    # Check 4: Standalone W3C SVG 1.1 Generation & XML Validity
    # Trip a realistic alarm pattern
    engine_svg = AnnunciatorMatrixEngine(sequence_mode="M")
    engine_svg.trip_alarm(0, status_line="92.4 °C | TRIP")
    engine_svg.trip_alarm(1, status_line="18.2 PSI | TRIP")
    engine_svg.operator_ack()
    engine_svg.trip_alarm(2, status_line="94.2 % | HIGH")

    svg_content = engine_svg.render_svg()
    with open(output_svg_path, "w", encoding="utf-8") as f:
        f.write(svg_content)

    root = ET.fromstring(svg_content)
    svg_ok = (
        root.tag.endswith("svg")
        and root.attrib.get("viewBox") == "0 0 800 480"
        and "◆" in svg_content
        and "★" in svg_content
        and "FEED PUMP BEARING" in svg_content
    )
    checks["svg_rendering_and_xml_validity"] = {
        "status": "passed" if svg_ok else "failed",
        "svg_bytes": len(svg_content.encode("utf-8")),
        "root_tag": root.tag,
        "viewbox": root.attrib.get("viewBox"),
        "redundant_glyphs_present": bool("◆" in svg_content and "★" in svg_content),
    }

    # Check 5: Horner OCS Register Space Synchronization
    table = RegisterTable()
    engine_reg = AnnunciatorMatrixEngine(register_table=table)
    engine_reg.trip_alarm(0)
    engine_reg.trip_alarm(4)
    engine_reg.sync_to_register_table(table)

    r420 = table.read_register("%R420")
    r421 = table.read_register("%R421")
    r422 = table.read_register("%R422")
    r423 = table.read_register("%R423")
    r425 = table.read_register("%R425")
    r426 = table.read_register("%R426")

    reg_ok = (
        (r420 & 0x0001 != 0)  # Active
        and (r420 & 0x0002 != 0)  # Unack
        and (r420 & 0x0004 != 0)  # Horn
        and (r420 & 0x0008 != 0)  # First-Out
        and r421 == 2
        and r422 == 2
        and r423 == 0
        and (r425 & 0x03 == 1)  # Tile 0 Unack (code 1)
        and (r426 & 0x03 == 1)  # Tile 4 Unack (code 1)
    )
    checks["horner_register_table_sync"] = {
        "status": "passed" if reg_ok else "failed",
        "status_word_hex": hex(r420),
        "total_active_count": r421,
        "unack_count": r422,
        "first_out_tile_idx": r423,
        "tile0_state_code": r425 & 0x03,
        "tile4_state_code": r426 & 0x03,
    }

    # Check 6: Pure ST POU Validation & AST Verification
    val = validate_pure_st()
    ast = STParser.parse_pou(ANNUNCIATOR_ST_CODE)
    st_ok = (
        val.status == AgentStatus.SUCCESS
        and ast.name == "W081_AnnunciatorEngine"
        and ast.pou_type == POUType.PROGRAM
        and len(ast.bound_registers) == 10
    )
    checks["pure_st_ast_validation"] = {
        "status": "passed" if st_ok else "failed",
        "pou_name": ast.name,
        "pou_type": ast.pou_type.value,
        "bound_registers_count": len(ast.bound_registers),
        "statements_count": ast.statements_count,
    }

    all_passed = all(c["status"] == "passed" for c in checks.values())

    evidence = {
        "work_package": "W081",
        "title": "Cscape HMI Dynamic Multi-State Graphic Annunciator Matrix & Alarm Panel Rasterizer",
        "gates": ["G9", "G2"],
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "overall_status": "success" if all_passed else "failed",
        "checks": checks,
        "specification": {
            "matrix_layout": "4 columns x 3 rows (12 annunciator tiles)",
            "viewbox": "800x480",
            "tile_dimensions": "178px x 100px",
            "contrast_standard": "WCAG 2.1 AAA",
            "sequence_standards": ["ISA-18.1 Sequence M", "ISA-18.1 Sequence A"],
        },
    }

    with open(output_evidence_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    return evidence


if __name__ == "__main__":
    ev = run_annunciator_matrix_verification()
    print(json.dumps(ev, indent=2))
