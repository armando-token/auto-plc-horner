"""Cscape HMI Vector Gauge & Polar Compass Dial Verification Runner.

Work Package: W075 (Gate G9 / G2)
Standard: W3C SVG 1.1 Vector Graphics & WCAG 2.1 AAA Contrast
Exports:
- artifacts/HMI/vector_gauge_evidence.json
- artifacts/HMI/gauge_sample.svg
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Dict
import xml.etree.ElementTree as ET

from jev_cscape.hmi.vector_gauge import (
    CompassPointMode,
    DialMode,
    VectorDialConfig,
    VectorGaugeEngine,
)


def run_vector_gauge_verification(
    output_evidence_path: Path = Path("artifacts/HMI/vector_gauge_evidence.json"),
    output_svg_path: Path = Path("artifacts/HMI/gauge_sample.svg"),
) -> Dict[str, Any]:
    """Execute end-to-end verification of vector gauge and polar compass rasterizer."""
    output_evidence_path.parent.mkdir(parents=True, exist_ok=True)
    output_svg_path.parent.mkdir(parents=True, exist_ok=True)
    engine = VectorGaugeEngine()
    checks: Dict[str, Any] = {}

    # Check 1: Radial Gauge Deflection Angle Mapping (-225° to +45°)
    engine.update(0)
    a_0 = engine.needle_deflection_angle / 10.0
    engine.update(5000)
    a_50 = engine.needle_deflection_angle / 10.0
    engine.update(10000)
    a_100 = engine.needle_deflection_angle / 10.0
    checks["radial_deflection_mapping"] = {
        "status": "passed" if a_0 == -225.0 and a_50 == -90.0 and a_100 == 45.0 else "failed",
        "angle_at_0_pct": a_0,
        "angle_at_50_pct": a_50,
        "angle_at_100_pct": a_100,
    }

    # Check 2: Polar Compass Azimuth Mapping (0° to 360°)
    cfg_comp = VectorDialConfig(mode=DialMode.POLAR_COMPASS)
    comp_engine = VectorGaugeEngine(cfg_comp)
    comp_engine.update(2500)
    a_east = comp_engine.needle_deflection_angle / 10.0
    comp_engine.update(5000)
    a_south = comp_engine.needle_deflection_angle / 10.0
    checks["polar_azimuth_mapping"] = {
        "status": "passed" if a_east == 90.0 and a_south == 180.0 else "failed",
        "angle_at_east_25pct": a_east,
        "angle_at_south_50pct": a_south,
    }

    # Check 3: Multi-Band Threshold Classification
    engine.update(5000)
    normal_ok = (engine.status_word & 0x0002) != 0
    engine.update(7500)
    warning_ok = (engine.status_word & 0x0004) != 0
    engine.update(9200)
    danger_ok = (engine.status_word & 0x0008) != 0
    checks["multi_band_classification"] = {
        "status": "passed" if normal_ok and warning_ok and danger_ok else "failed",
        "normal_band_detected": normal_ok,
        "warning_band_detected": warning_ok,
        "danger_band_detected": danger_ok,
    }

    # Check 4: Peak Hold and Reset Handshake
    engine_peak = VectorGaugeEngine()
    engine_peak.update(4000)
    engine_peak.update(8500)
    engine_peak.update(3000)
    peak_held = engine_peak.peak_hold_value == 8500
    engine_peak.reset_peak_hold = True
    engine_peak.update(3000)
    peak_reset = engine_peak.peak_hold_value == 3000 and (engine_peak.status_word & 0x0040 != 0)
    checks["peak_hold_and_reset"] = {
        "status": "passed" if peak_held and peak_reset else "failed",
        "peak_held_at_85pct": peak_held,
        "peak_cleared_on_handshake": peak_reset,
    }

    # Check 5: Render and Validate SVG Sample
    engine.update(7420)  # 74.20% (Warning band, BAR units)
    svg_content = engine.render_svg()
    root = ET.fromstring(svg_content)
    xml_valid = root.tag.endswith("svg")
    with open(output_svg_path, "w", encoding="utf-8") as f_svg:
        f_svg.write(svg_content)
    checks["svg_export_and_xml_validity"] = {
        "status": "passed" if xml_valid and output_svg_path.is_file() else "failed",
        "svg_file_path": str(output_svg_path).replace("\\", "/"),
        "byte_size": len(svg_content.encode("utf-8")),
        "root_tag": root.tag,
    }

    all_passed = all(c["status"] == "passed" for c in checks.values())
    evidence = {
        "work_package": "W075",
        "gate": "G9",
        "component": "Cscape HMI Dynamic Vector Gauge & Polar Compass Dial",
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "overall_status": "success" if all_passed else "failed",
        "registers": {
            "%R360": engine.status_word,
            "%R361": engine.input_pv_scaled,
            "%R362": engine.needle_deflection_angle,
            "%R363": engine.gauge_low_range_eu,
            "%R364": engine.gauge_high_range_eu,
            "%R365": engine.warning_threshold,
            "%R366": engine.danger_threshold,
            "%R367": engine.peak_hold_value,
            "%M84": engine.enable_engine,
            "%M85": engine.reset_peak_hold,
        },
        "checks": checks,
    }

    with open(output_evidence_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    return evidence


if __name__ == "__main__":
    res = run_vector_gauge_verification()
    print(json.dumps(res, indent=2))
