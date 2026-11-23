"""Unit tests for Cscape HMI Dynamic Cartesian Heatmap & Thermal Dispersion Matrix Rasterizer.

Work Package: W090 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY
"""

import math
import pytest
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.hmi.cartesian_heatmap import (
    CartesianHeatmapRasterizer,
    ContourLineSegment,
    HeatmapColormap,
    HeatmapNode,
    HeatmapStatusBits,
    HEATMAP_PURE_ST_POU,
    relative_luminance,
    wcag_contrast_ratio,
    interpolate_palette,
    PALETTE_TURBO,
    PALETTE_THERMAL_IRON,
    PALETTE_VIRIDIS,
    run_heatmap_verification,
)


class TestCartesianHeatmapPureST:
    """Tests for IEC 61131-3 Pure ST compliance and anti-ladder security."""

    def test_pure_st_security_guard(self) -> None:
        """Verify Pure ST POU passes security guard assertion."""
        SecurityGuard.assert_pure_st_content(HEATMAP_PURE_ST_POU)

    def test_ladder_constructs_rejected(self) -> None:
        """Verify ladder contacts, coils, and rungs trigger LadderForbiddenError."""
        ladder_snippets = [
            HEATMAP_PURE_ST_POU + "\n---[ ]---",
            HEATMAP_PURE_ST_POU + "\n---( )---",
            HEATMAP_PURE_ST_POU + "\nRUNG 1",
            HEATMAP_PURE_ST_POU + "\nNETWORK 1",
            HEATMAP_PURE_ST_POU + "\nOTE MyCoil",
        ]
        for snip in ladder_snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snip)

    def test_st_parser_validation_and_ast(self) -> None:
        """Verify ST parser validates syntax and extracts AST properly."""
        val = STParser.validate_code(HEATMAP_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(HEATMAP_PURE_ST_POU)
        assert ast.name == "CartesianHeatmapRasterizerSync"
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = ["%R510", "%R511", "%R512", "%R513", "%R514", "%R515", "%R516", "%R517"]
        for reg in expected_regs:
            assert reg in ast.bound_registers
        expected_coils = ["%M119", "%M120"]
        for coil in expected_coils:
            assert coil in ast.bound_registers


class TestCartesianHeatmapGeometryAndInterpolation:
    """Tests for 16x8 mesh geometry, node updates, and bilinear spatial interpolation."""

    def test_mesh_initialization(self) -> None:
        """Verify 16x8 mesh has exactly 128 nodes with valid coordinates."""
        raster = CartesianHeatmapRasterizer()
        assert len(raster.nodes) == 8
        for row in raster.nodes:
            assert len(row) == 16

        assert raster.dx_m == pytest.approx(4.0 / 15.0)
        assert raster.dy_m == pytest.approx(2.0 / 7.0)

        # Check corner coordinates
        assert raster.nodes[0][0].x_m == 0.0
        assert raster.nodes[0][0].y_m == 0.0
        assert raster.nodes[7][15].x_m == pytest.approx(4.0)
        assert raster.nodes[7][15].y_m == pytest.approx(2.0)

    def test_bilinear_exact_at_corners(self) -> None:
        """Verify bilinear interpolation matches exact node values at grid intersections."""
        raster = CartesianHeatmapRasterizer()
        raster.set_node_temperature(4, 3, 543.21)
        x = raster.nodes[3][4].x_m
        y = raster.nodes[3][4].y_m
        sampled = raster.sample_bilinear(x, y)
        assert sampled == pytest.approx(543.21, rel=1e-4)

    def test_bilinear_centroid_interpolation(self) -> None:
        """Verify bilinear interpolation at cell center equals 4-corner mean."""
        raster = CartesianHeatmapRasterizer()
        t00 = raster.get_node_temperature(2, 2)
        t10 = raster.get_node_temperature(3, 2)
        t01 = raster.get_node_temperature(2, 3)
        t11 = raster.get_node_temperature(3, 3)
        mid_x = (raster.nodes[2][2].x_m + raster.nodes[2][3].x_m) * 0.5
        mid_y = (raster.nodes[2][2].y_m + raster.nodes[3][2].y_m) * 0.5
        sampled = raster.sample_bilinear(mid_x, mid_y)
        expected = 0.25 * (t00 + t10 + t01 + t11)
        assert sampled == pytest.approx(expected, rel=1e-3)


class TestThermalGradientsAndStress:
    """Tests for 2D spatial gradients and thermal stress trip."""

    def test_interior_central_difference(self) -> None:
        """Verify central difference gradient calculation in interior mesh."""
        raster = CartesianHeatmapRasterizer()
        raster.update_gradients()
        stats = raster.get_temperature_statistics()
        assert stats["max_gradient"] > 0.0

        # Create known synthetic linear gradient along X: T = 100 * x
        for j in range(raster.ROWS):
            for i in range(raster.COLS):
                raster.set_node_temperature(i, j, 100.0 * raster.nodes[j][i].x_m)
        raster.update_gradients()

        # Interior node (8, 4) should have grad_x = 100.0, grad_y = 0.0
        node = raster.nodes[4][8]
        assert node.grad_x == pytest.approx(100.0, rel=1e-3)
        assert node.grad_y == pytest.approx(0.0, abs=1e-4)
        assert node.grad_mag == pytest.approx(100.0, rel=1e-3)

    def test_high_gradient_stress_warning(self) -> None:
        """Verify warning flag engaged when gradient exceeds 150.0 °C/m."""
        raster = CartesianHeatmapRasterizer()
        # Set steep temperature jump
        raster.set_node_temperature(5, 3, 200.0)
        raster.set_node_temperature(6, 3, 900.0)
        raster.update_gradients()
        stats = raster.get_temperature_statistics()
        assert stats["max_gradient"] >= 150.0
        assert raster.gradient_warning


class TestColormapsAndAccessibility:
    """Tests for color palettes and WCAG 2.1 AAA contrast compliance."""

    def test_colormap_palettes_interpolation(self) -> None:
        """Verify RGB output across all supported palettes."""
        for palette in [PALETTE_TURBO, PALETTE_THERMAL_IRON, PALETTE_VIRIDIS]:
            for norm in [0.0, 0.25, 0.5, 0.75, 1.0]:
                r, g, b = interpolate_palette(palette, norm)
                assert 0 <= r <= 255
                assert 0 <= g <= 255
                assert 0 <= b <= 255

    def test_wcag_aaa_contrast_ratio(self) -> None:
        """Verify decoupled dark badge background satisfies > 7:1 AAA contrast."""
        bg_lum = relative_luminance(11, 15, 25)    # #0B0F19
        fg_lum = relative_luminance(248, 250, 252) # #F8FAFC
        contrast = wcag_contrast_ratio(fg_lum, bg_lum)
        assert contrast >= 18.0, f"Contrast {contrast} < 18.0:1"


class TestMarchingSquaresIsolines:
    """Tests for 16-case Marching Squares contour segment generation."""

    def test_contour_extraction(self) -> None:
        """Verify extraction of isothermal segments for multi-level thresholds."""
        raster = CartesianHeatmapRasterizer()
        iso_levels = [400.0, 600.0, 800.0]
        segments = raster.extract_marching_squares_contours(
            iso_levels, 40.0, 90.0, 60.0, 60.0
        )
        assert len(segments) > 0
        for seg in segments:
            assert isinstance(seg, ContourLineSegment)
            assert seg.iso_temp in iso_levels
            assert seg.x1 >= 40.0
            assert seg.y1 >= 90.0


class TestReticleAndHornerRegisters:
    """Tests for hotspot targeting reticle and Horner OCS register space."""

    def test_hotspot_peak_detection_and_reticle(self) -> None:
        """Verify peak node detection and runaway alarm trip."""
        reg_table = RegisterTable()
        raster = CartesianHeatmapRasterizer(register_table=reg_table)
        raster.set_node_temperature(12, 5, 950.0)
        raster.update_gradients()
        raster.sync_registers()

        stats = raster.get_temperature_statistics()
        assert stats["hotspot_i"] == 12
        assert stats["hotspot_j"] == 5
        assert stats["t_max"] == 950.0
        assert raster.hotspot_alarm

        r510 = reg_table.read_word("%R510")
        assert bool(r510 & HeatmapStatusBits.HOT_SPOT_ALARM)
        assert reg_table.read_word("%R511") == 9500
        assert reg_table.read_word("%R515") == 12
        assert reg_table.read_word("%R516") == 5

    def test_colormap_cycle_coil(self) -> None:
        """Verify coil %M120 advances the active colormap."""
        reg_table = RegisterTable()
        raster = CartesianHeatmapRasterizer(register_table=reg_table)
        assert raster.colormap == HeatmapColormap.TURBO

        reg_table.write_bit("%M120", True, privilege=PrivilegeMode.SYSTEM)
        raster.sync_registers()

        assert raster.colormap == HeatmapColormap.THERMAL_IRON
        assert not reg_table.read_bit("%M120")
        assert reg_table.read_word("%R517") == 1

    def test_svg_rendering_structure(self) -> None:
        """Verify generated SVG is valid XML and contains all essential graphic elements."""
        raster = CartesianHeatmapRasterizer()
        svg_str = raster.generate_svg()
        # Parse XML
        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg")
        assert root.attrib["width"] == "1200"
        assert root.attrib["height"] == "750"

        # Check groups
        group_ids = [elem.attrib.get("id") for elem in root.iter() if elem.tag.endswith("g") and "id" in elem.attrib]
        assert "header_hud" in group_ids
        assert "heatmap_matrix" in group_ids
        assert "isothermal_contours" in group_ids
        assert "hotspot_reticle" in group_ids
        assert "colorbar_legend" in group_ids
        assert "scorecard_hud" in group_ids


class TestHeatmapVerificationRunner:
    """Tests for the end-to-end 9-stage verification runner."""

    def test_run_verification(self, tmp_path) -> None:
        """Verify the full 9-stage verification function passes and writes artifacts."""
        out_evidence = tmp_path / "heatmap_evidence.json"
        out_svg = tmp_path / "heatmap_sample.svg"
        res = run_heatmap_verification(str(out_evidence), str(out_svg))
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert out_evidence.exists()
        assert out_svg.exists()
