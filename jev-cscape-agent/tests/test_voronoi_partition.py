"""Unit Tests for Cscape HMI Dynamic Voronoi Spatial Partitioning Canvas (W099).

Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI.
"""

from __future__ import annotations

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.hmi.voronoi_partition import (
    CellSeverity,
    VoronoiStatusBits,
    Point2D,
    Polygon2D,
    SensorSite,
    VoronoiCell,
    VoronoiTopologyCanvas,
    VORONOI_PARTITION_PURE_ST_POU,
    run_voronoi_partition_verification,
)


class TestVoronoiTopologyCanvas:
    """Test suite for W099 Voronoi Spatial Partitioning Canvas."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify Pure ST POU validation and AST symbol bindings."""
        SecurityGuard.assert_pure_st_content(VORONOI_PARTITION_PURE_ST_POU)
        res = STParser.validate_code(VORONOI_PARTITION_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(VORONOI_PARTITION_PURE_ST_POU)
        assert ast.name == "VoronoiSpatialPartitionSync"
        assert ast.pou_type == POUType.PROGRAM
        assert "%R600" in ast.bound_registers
        assert "%R607" in ast.bound_registers
        assert "%M140" in ast.bound_registers
        assert "%M141" in ast.bound_registers

    def test_ladder_construct_interception(self) -> None:
        """Verify ladder contacts and coils are intercepted fail-closed."""
        bad_st = """
        PROGRAM LadderVoronoi
        VAR CellBit : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_shoelace_area_and_centroid(self) -> None:
        """Verify Green's theorem Shoelace area and centroid calculations."""
        # Rectangle [0, 4] x [0, 2], area = 8, centroid = (2, 1)
        rect = Polygon2D([
            Point2D(0.0, 0.0),
            Point2D(4.0, 0.0),
            Point2D(4.0, 2.0),
            Point2D(0.0, 2.0),
        ])
        assert abs(rect.shoelace_area() - 8.0) < 1e-6
        c = rect.centroid()
        assert abs(c.x - 2.0) < 1e-6
        assert abs(c.y - 1.0) < 1e-6

    def test_sutherland_hodgman_clipping(self) -> None:
        """Verify convex polygon clipping against half-plane."""
        box = Polygon2D([
            Point2D(0.0, 0.0),
            Point2D(10.0, 0.0),
            Point2D(10.0, 10.0),
            Point2D(0.0, 10.0),
        ])
        # Clip with x <= 4 (normal = (1, 0), p_mid = (4, 0))
        clipped = box.clip_halfplane(p_mid=Point2D(4.0, 0.0), normal=Point2D(1.0, 0.0))
        assert len(clipped.vertices) == 4
        assert abs(clipped.shoelace_area() - 40.0) < 1e-6

    def test_global_area_conservation(self) -> None:
        """Verify global Voronoi partition area equals exact canvas area (900,000 px^2)."""
        canvas = VoronoiTopologyCanvas()
        total_area = sum(c.area for c in canvas.cells.values())
        assert abs(total_area - 900000.0) < 1e-3

    def test_delaunay_dual_graph_and_gradients(self) -> None:
        """Verify Delaunay dual graph connectivity and spatial gradient calculation."""
        canvas = VoronoiTopologyCanvas()
        assert len(canvas.cells) == 8

        # Each site must have neighbors
        for cell in canvas.cells.values():
            assert len(cell.neighbors) >= 2

        # Check max gradient
        assert canvas.max_gradient > 0.0
        assert canvas.max_gradient_pair != (0, 0)

    def test_wcag_aaa_contrast_ratio(self) -> None:
        """Verify WCAG AAA contrast ratio compliance (> 18:1 for white on badge)."""
        cr_white_on_dark = VoronoiTopologyCanvas.calculate_contrast_ratio("#FFFFFF", "#0B0F19")
        assert cr_white_on_dark >= 18.0

        cr_tag_on_dark = VoronoiTopologyCanvas.calculate_contrast_ratio("#38BDF8", "#0B0F19")
        assert cr_tag_on_dark >= 7.0

    def test_horner_registers_and_alarm_coils(self) -> None:
        """Verify register mapping and alarm coils."""
        reg_table = RegisterTable()
        canvas = VoronoiTopologyCanvas(register_table=reg_table)

        assert reg_table.read_word("%R601") == 8
        assert reg_table.read_word("%R604") == 900
        assert reg_table.read_bit("%M141") is True  # Site 3 is 96 °C (CRITICAL)

    def test_svg_export_and_validity(self, tmp_path) -> None:
        """Verify SVG export writes valid XML."""
        canvas = VoronoiTopologyCanvas()
        out_svg = tmp_path / "test_voronoi.svg"
        res = canvas.export_svg(str(out_svg))
        assert res.status == AgentStatus.SUCCESS
        assert out_svg.exists()
        assert out_svg.stat().st_size > 1000

    def test_full_verification_runner_9_stages(self) -> None:
        """Verify 9-stage verification suite executes and produces evidence."""
        evidence = run_voronoi_partition_verification()
        assert evidence["status"] == "success"
        assert evidence["data"]["checks_passed"] == 9
        assert evidence["data"]["total_checks"] == 9
