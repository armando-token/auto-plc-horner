"""Unit Tests for Cscape HMI Parallel Coordinate Trajectory Plotter (W093).

Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI.
"""

from __future__ import annotations

import math
import pytest
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.hmi.parallel_coordinate_plotter import (
    AnomalySeverity,
    ParallelPlotterStatusBits,
    ParallelAxisConfig,
    ParallelCoordinatePlotter,
    DEFAULT_AXES,
    PARALLEL_PLOTTER_PURE_ST_POU,
    compute_contrast_ratio,
    run_parallel_plotter_verification,
)


class TestParallelCoordinatePlotter:
    """Test suite for W093 Parallel Coordinate Plotter component."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify Pure ST POU validation and AST symbol bindings."""
        SecurityGuard.assert_pure_st_content(PARALLEL_PLOTTER_PURE_ST_POU)
        res = STParser.validate_code(PARALLEL_PLOTTER_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(PARALLEL_PLOTTER_PURE_ST_POU)
        assert ast.name == "ParallelCoordinatePlotterSync"
        assert ast.pou_type == POUType.PROGRAM
        assert "%R540" in ast.bound_registers
        assert "%R547" in ast.bound_registers
        assert "%M126" in ast.bound_registers
        assert "%M127" in ast.bound_registers

    def test_ladder_construct_interception(self) -> None:
        """Verify ladder contacts and coils are intercepted fail-closed."""
        bad_st = """
        PROGRAM LadderPlotter
        VAR Coil1 : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_affine_normalization_and_screen_mapping(self) -> None:
        """Test physical to normalized [0, 1] and SVG Y coordinate mapping."""
        plotter = ParallelCoordinatePlotter()

        # Temp: [0..500], screen Y [120..620], height = 500
        assert plotter.normalize_value(0, 0.0) == 0.0
        assert plotter.normalize_value(0, 500.0) == 1.0
        assert plotter.normalize_value(0, 250.0) == 0.5

        assert plotter.map_to_screen_y(0, 0.0) == 620.0
        assert plotter.map_to_screen_y(0, 500.0) == 120.0
        assert plotter.map_to_screen_y(0, 250.0) == 370.0

    def test_golden_corridor_polygon_ribbon(self) -> None:
        """Test closed polygon ribbon coordinates across 8 axes."""
        plotter = ParallelCoordinatePlotter()
        poly_str = plotter.generate_corridor_polygon_points()
        pts = poly_str.split()

        # 8 upper points + 8 lower points = 16 points
        assert len(pts) == 16
        # First point X should match first axis X
        assert pts[0].startswith(f"{plotter.axes[0].x_pos:.1f}")
        # Last point X should also match first axis X (closing ribbon loop)
        assert pts[-1].startswith(f"{plotter.axes[0].x_pos:.1f}")

    def test_orthogonal_cubic_bezier_tangents(self) -> None:
        """Test orthogonal cubic Bézier spline with horizontal tangents."""
        plotter = ParallelCoordinatePlotter()
        vals = [300.0, 22.0, 55.0, 500.0, 3.0, 25.0, 900.0, 100.0]
        path = plotter.generate_cubic_bezier_path(vals)

        assert path.startswith("M 120.00")
        assert path.count(" C ") == 7

        # Extract first Bézier command: C c1_x,c1_y c2_x,c2_y p2_x,p2_y
        parts = path.split(" C ")
        c_chunk = parts[1].split()[0:3]
        c1 = [float(x) for x in c_chunk[0].split(",")]
        c2 = [float(x) for x in c_chunk[1].split(",")]
        p2 = [float(x) for x in c_chunk[2].split(",")]

        # In horizontal entry/exit tangents: c1_y == p1_y, c2_y == p2_y
        p1_y = plotter.map_to_screen_y(0, vals[0])
        assert abs(c1[1] - p1_y) < 1e-2
        assert abs(c2[1] - p2[1]) < 1e-2

    def test_anomaly_metrics_l1_l2_chebyshev(self) -> None:
        """Test Manhattan, Euclidean, and Chebyshev distance metrics."""
        plotter = ParallelCoordinatePlotter()

        # In-corridor sample
        nom = [310.0, 22.0, 55.0, 515.0, 3.25, 25.0, 890.0, 115.0]
        m_in = plotter.evaluate_anomaly(nom)
        assert m_in.severity == AnomalySeverity.NORMAL
        assert m_in.d_chebyshev == 0.0
        assert m_in.d_manhattan == 0.0
        assert m_in.d_euclidean == 0.0
        assert m_in.status_code == 0

        # Warning excursion on single axis (Temp = 349 °C, corridor [280..340], span=60 -> d=9/60=0.15)
        warn_vals = list(nom)
        warn_vals[0] = 349.0
        m_warn = plotter.evaluate_anomaly(warn_vals)
        assert m_warn.severity == AnomalySeverity.WARNING
        assert abs(m_warn.d_chebyshev - 0.15) < 1e-3
        assert m_warn.status_code == 1

        # Critical alarm excursion (Pressure = 30 bar, corridor [18..26], span=8 -> d=4/8=0.50)
        alarm_vals = list(nom)
        alarm_vals[1] = 30.0
        m_alarm = plotter.evaluate_anomaly(alarm_vals)
        assert m_alarm.severity == AnomalySeverity.CRITICAL
        assert abs(m_alarm.d_chebyshev - 0.50) < 1e-3
        assert m_alarm.worst_axis_index == 1
        assert m_alarm.status_code == 2

    def test_parametric_corridor_crossing_root_finding(self) -> None:
        """Test bisection root finding for exact corridor crossing parameter t*."""
        plotter = ParallelCoordinatePlotter()

        # Axis 0 (Temp): corridor [280..340]. Start inside at 310, end outside at 380.
        t_star = plotter.find_corridor_crossing(0, 310.0, 380.0, is_upper=True)
        assert t_star is not None
        assert 0.0 < t_star < 1.0

        # No crossing when both are inside (Temp=300 on axis 0, Press=22 on axis 1)
        t_none = plotter.find_corridor_crossing(0, 300.0, 22.0, is_upper=True)
        assert t_none is None

    def test_wcag_2_1_aaa_accessibility_contrast(self) -> None:
        """Test WCAG AAA contrast ratio calculation for decoupled backing badges."""
        contrast = compute_contrast_ratio("#F8FAFC", "#0B0F19")
        assert contrast >= 18.0  # Vastly exceeds 7.0:1 AAA standard

    def test_svg_generation_and_xml_validity(self, tmp_path) -> None:
        """Test standalone W3C SVG 1.1 generation and XML well-formedness."""
        plotter = ParallelCoordinatePlotter()
        plotter.ingest_sample([310.0, 22.0, 55.0, 515.0, 3.25, 25.0, 890.0, 115.0])

        svg_content = plotter.render_svg()
        root = ET.fromstring(svg_content)
        assert root.tag.endswith("svg")
        assert root.attrib["width"] == "1200"
        assert root.attrib["height"] == "750"

        # Check export to file
        svg_file = tmp_path / "plotter.svg"
        plotter.export_svg(str(svg_file))
        assert svg_file.exists()
        assert svg_file.stat().st_size > 2000

    def test_horner_ocs_register_synchronization(self) -> None:
        """Test Horner registers %R540..%R547 and coils %M126..%M127."""
        reg_table = RegisterTable()
        plotter = ParallelCoordinatePlotter(register_table=reg_table)

        # Alarm excursion on Pressure (axis 1)
        vals = [310.0, 30.0, 55.0, 515.0, 3.25, 25.0, 890.0, 115.0]
        plotter.ingest_sample(vals)

        assert reg_table.read_word("%R540") == 1  # Worst axis index (Pressure)
        assert reg_table.read_word("%R541") == 500  # D_inf = 0.50 * 1000
        assert reg_table.read_word("%R546") == 2    # Status code Critical (2)

        r547 = reg_table.read_word("%R547")
        assert bool(r547 & ParallelPlotterStatusBits.ACTIVE)
        assert bool(r547 & ParallelPlotterStatusBits.ALARM_ACTIVE)
        assert bool(r547 & ParallelPlotterStatusBits.EXTREME_EXCURSION)
        assert reg_table.read_bit("%M126") is True
        assert reg_table.read_bit("%M127") is True

    def test_run_verification_runner_end_to_end(self, tmp_path) -> None:
        """Test end-to-end 9-stage verification runner function."""
        ev_file = tmp_path / "plotter_evidence.json"
        svg_file = tmp_path / "plotter_sample.svg"

        res = run_parallel_plotter_verification(
            evidence_path=str(ev_file),
            svg_output_path=str(svg_file),
        )

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert ev_file.exists()
        assert svg_file.exists()
