"""Unit tests for Cscape HMI Historical Trend Chart Vector Rasterizer & Multi-Pen Spline Plotter (W069).

Tests:
1. Telemetry sample validation and OPC UA quality filtering.
2. Contiguous run partitioning across missing/null data dropouts.
3. Catmull-Rom spline path synthesis and cubic Bezier control points.
4. Linear fallback interpolation for short 2-point runs.
5. Dual Y-axis coordinate projections (Pen 1 primary vs Pen 2 secondary).
6. SVG document generation with viewport clipPath and background cards.
7. WCAG 2.1 contrast compliance of pen colors against dark slate background.
8. Horner OCS register synchronization (%R300..%R307, %M70..%M71).
9. Momentary buffer reset handshake coil %M71 clearing ring buffer.
10. Pure ST boundary enforcement: rejection of forbidden ladder logic constructs.
11. Canonical verification runner and SVG artifact export.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.font_metrics import compute_contrast_ratio
from jev_cscape.hmi.trend_chart import (
    DualAxisTrendRasterizer,
    TelemetrySample,
    TrendPenConfig,
    TrendStatusFlag,
    verify_trend_chart_and_export_evidence,
)
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


def test_telemetry_sample_validation() -> None:
    """Verify is_valid flag checks for None, NaN, and OPC UA quality bits."""
    valid_sample = TelemetrySample(timestamp_s=10.0, value=45.2, quality_word=0x00C0)
    assert valid_sample.is_valid is True

    none_sample = TelemetrySample(timestamp_s=10.0, value=None, quality_word=0x00C0)
    assert none_sample.is_valid is False

    nan_sample = TelemetrySample(timestamp_s=10.0, value=float("nan"), quality_word=0x00C0)
    assert nan_sample.is_valid is False

    bad_quality_sample = TelemetrySample(timestamp_s=10.0, value=45.2, quality_word=0x0000)
    assert bad_quality_sample.is_valid is False


def test_contiguous_run_partitioning() -> None:
    """Verify samples with gaps or bad quality are split into separate render runs."""
    rasterizer = DualAxisTrendRasterizer()
    samples = [
        TelemetrySample(1.0, 10.0),
        TelemetrySample(2.0, 12.0),
        TelemetrySample(3.0, None),  # Dropout
        TelemetrySample(4.0, 15.0),
        TelemetrySample(5.0, 18.0),
        TelemetrySample(12.0, 20.0),  # Time jump > 3.0s
        TelemetrySample(13.0, 22.0),
    ]
    runs = rasterizer.partition_contiguous_runs(samples, max_gap_s=3.0)
    assert len(runs) == 3
    assert len(runs[0]) == 2
    assert len(runs[1]) == 2
    assert len(runs[2]) == 2


def test_spline_path_generation() -> None:
    """Verify Catmull-Rom produces valid SVG cubic Bezier curve commands."""
    rasterizer = DualAxisTrendRasterizer()
    pts = [(100.0, 200.0), (150.0, 180.0), (200.0, 220.0), (250.0, 190.0)]
    d = rasterizer.generate_spline_path(pts, interpolation="catmull_rom")
    assert d.startswith("M 100.0,200.0")
    assert "C " in d

    # 2 points fallback
    d2 = rasterizer.generate_spline_path(pts[:2], interpolation="catmull_rom")
    assert d2 == "M 100.0,200.0 L 150.0,180.0"

    # Linear mode
    d_lin = rasterizer.generate_spline_path(pts, interpolation="linear")
    assert "C " not in d_lin
    assert "L " in d_lin


def test_dual_axis_coordinate_projections() -> None:
    """Verify Pen 1 (0..100) and Pen 2 (0..10) map correctly to plot rect."""
    rasterizer = DualAxisTrendRasterizer(x=0, y=0, width=500, height=300)
    px, py, pw, ph = rasterizer.plot_rect

    # Min value should map to bottom of plot: py + ph
    x1_min, y1_min = rasterizer.project_point(0.0, 0.0, 0.0, 60.0, 0.0, 100.0)
    assert x1_min == px
    assert y1_min == py + ph

    # Max value should map to top of plot: py
    x1_max, y1_max = rasterizer.project_point(60.0, 100.0, 0.0, 60.0, 0.0, 100.0)
    assert x1_max == px + pw
    assert y1_max == py

    # Pen 2 mid value (5.0 on 0..10) should map to vertical center
    x2_mid, y2_mid = rasterizer.project_point(30.0, 5.0, 0.0, 60.0, 0.0, 10.0)
    assert abs(y2_mid - (py + ph / 2.0)) < 1.0


def test_svg_rendering_and_contrast() -> None:
    """Verify SVG markup and contrast ratios for dark theme."""
    rasterizer = DualAxisTrendRasterizer()
    pen1 = TrendPenConfig("LEVEL", "%", 0.0, 100.0, "#00E5FF")
    pen2 = TrendPenConfig("PRESS", "bar", 0.0, 10.0, "#FFB300")

    rasterizer.add_sample(10.0, 50.0, 5.0)
    rasterizer.add_sample(20.0, 60.0, 6.0)

    svg = rasterizer.render_svg(pen1, pen2, t_now=20.0)
    assert "<svg" in svg
    assert "</svg>" in svg
    assert "clipPath" in svg
    assert "#00E5FF" in svg
    assert "#FFB300" in svg

    # Contrast against plot canvas background #1E293B
    ratio_cyan = compute_contrast_ratio("#00E5FF", "#1E293B")
    assert ratio_cyan > 7.0  # WCAG AAA compliant

    ratio_amber = compute_contrast_ratio("#FFB300", "#1E293B")
    assert ratio_amber > 7.0  # WCAG AAA compliant


def test_horner_register_sync() -> None:
    """Verify %R300..%R307 and %M70..%M71 synchronization."""
    regs = RegisterTable()
    rasterizer = DualAxisTrendRasterizer()

    rasterizer.add_sample(1.0, 75.25, 4.8)
    regs.write_bit("%M70", True, privilege=PrivilegeMode.SYSTEM)
    regs.write_word("%R304", 120, privilege=PrivilegeMode.SYSTEM)
    regs.write_word("%R305", 4, privilege=PrivilegeMode.SYSTEM)
    regs.write_word("%R306", 100, privilege=PrivilegeMode.SYSTEM)

    rasterizer.solve(regs)

    assert regs.read_word("%R300") & TrendStatusFlag.ACTIVE
    assert regs.read_word("%R300") & TrendStatusFlag.DUAL_PEN_ENABLED
    assert regs.read_word("%R301") == 1
    assert regs.read_word("%R302") == 7525  # 75.25% * 100
    assert regs.read_word("%R303") == 4800  # 4.80 bar * 1000
    assert regs.read_word("%R304") == 120
    assert regs.read_word("%R305") == 4


def test_buffer_reset_handshake() -> None:
    """Verify %M71 resets buffer and self-clears."""
    regs = RegisterTable()
    rasterizer = DualAxisTrendRasterizer()
    rasterizer.add_sample(1.0, 10.0, 2.0)
    rasterizer.add_sample(2.0, 20.0, 3.0)

    regs.write_bit("%M70", True, privilege=PrivilegeMode.SYSTEM)
    regs.write_bit("%M71", True, privilege=PrivilegeMode.SYSTEM)
    rasterizer.solve(regs)

    assert len(rasterizer.pen1_buffer) == 0
    assert regs.read_bit("%M71") is False  # Self-cleared
    assert regs.read_word("%R301") == 0


def test_pure_st_boundary_enforcement() -> None:
    """Verify IEC 61131-3 Pure ST boundary rejects ladder constructs."""
    valid_st = (
        "PROGRAM TrendRasterizerSync\n"
        "VAR\n"
        "    TrendStatusWord AT %R300 : WORD;\n"
        "    SampleCount AT %R301 : INT;\n"
        "    Pen1LatestPV AT %R302 : INT;\n"
        "    Pen2LatestPV AT %R303 : INT;\n"
        "    TimeSpanSec AT %R304 : INT;\n"
        "    GridDivisions AT %R305 : INT;\n"
        "    SampleIntervalMs AT %R306 : INT;\n"
        "    FrameCounter AT %R307 : UINT;\n"
        "    EnableEngine AT %M70 : BOOL;\n"
        "    ResetBuffer AT %M71 : BOOL;\n"
        "END_VAR\n"
        "IF EnableEngine THEN\n"
        "    TrendStatusWord := %R300;\n"
        "END_IF;\n"
        "END_PROGRAM"
    )
    SecurityGuard.assert_pure_st_content(valid_st)
    ast = STParser.parse_pou(valid_st)
    assert ast.name == "TrendRasterizerSync"
    assert ast.pou_type == POUType.PROGRAM
    expected_regs = {"%R300", "%R301", "%R302", "%R303", "%R304", "%R305", "%R306", "%R307", "%M70", "%M71"}
    assert expected_regs.issubset(set(ast.bound_registers))

    ladder_samples = [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(S)---",
        "---(R)---",
        "RUNG 1",
        "END_RUNG",
        "NETWORK 10",
        "XIC EnableEngine",
        "OTE ResetBuffer",
    ]
    for sample in ladder_samples:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(f"{valid_st}\n{sample}")


def test_verification_runner_and_artifact(tmp_path: Path) -> None:
    """Verify canonical verification runner and artifact exports."""
    evidence_file = tmp_path / "trend_chart_evidence.json"
    svg_file = tmp_path / "trend_chart_sample.svg"

    result = verify_trend_chart_and_export_evidence(
        output_evidence_path=str(evidence_file),
        output_svg_path=str(svg_file),
    )

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert result["data"]["tests_run"] == result["data"]["tests_passed"]
    assert evidence_file.exists()
    assert svg_file.exists()

    with open(evidence_file, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["status"] == "success"
    assert "svg_artifact" in loaded["data"]
