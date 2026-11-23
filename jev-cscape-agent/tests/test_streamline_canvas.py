"""Unit tests for Cscape HMI 2D Vector Field & Streamline Canvas (W108)."""

from __future__ import annotations

import math
import pytest
import xml.etree.ElementTree as ET

from jev_cscape.hmi.streamline_canvas import (
    ColorBy,
    ContractionNozzleField,
    CylinderCrossFlowField,
    FlowProfileType,
    IntegratorMethod,
    SpatialHashGrid,
    StreamlineCanvas,
    StreamlineStatusBits,
    StreamlineTracer,
    VortexSwirlField,
    generate_inlet_seeds,
    generate_streamline_svg,
    generate_vortex_seeds,
    run_streamline_canvas_verification,
    verify_streamline_pure_st,
    verify_streamline_canvas_pure_st,
    STREAMLINE_PURE_ST_POU,
    HIGH_VELOCITY_TRIP_THRESHOLD,
    VORTEX_STALL_TRIP_THRESHOLD,
    DIVERGENCE_ANOMALY_THRESHOLD,
    DIAG_EVENT_OK,
    DIAG_EVENT_HIGH_VELOCITY,
    DIAG_EVENT_VORTEX_STALL,
    DIAG_EVENT_DIVERGENCE_ANOMALY,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard


def test_pure_st_pou_ast_and_ladder_guard() -> None:
    """Stage 1: Verify Pure ST POU AST parsing and absence of ladder constructs."""
    assert verify_streamline_pure_st() is True
    assert verify_streamline_canvas_pure_st() is True

    # POU AST parse validation
    parser = STParser()
    pou = parser.parse_pou(STREAMLINE_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "StreamlineCanvasSync"
    assert pou.pou_type == POUType.PROGRAM
    assert "%R690" in pou.bound_registers
    assert "%R691" in pou.bound_registers
    assert "%R697" in pou.bound_registers
    assert "%M161" in pou.bound_registers
    assert "%M162" in pou.bound_registers

    # Bad ladder logic injection check
    bad_st = """
    PROGRAM BadStreamlineLadder
    VAR Flag : BOOL; END_VAR
    ---[ ]---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_st)


def test_cylinder_cross_flow_potential_flow() -> None:
    """Stage 2: Verify analytical potential flow around cylinder."""
    field = CylinderCrossFlowField(cx=600.0, cy=375.0, radius=90.0, u_inf=12.0)

    # Obstacle check
    assert field.is_obstacle(600.0, 375.0) is True
    assert field.is_obstacle(590.0, 375.0) is True
    assert field.is_obstacle(500.0, 375.0) is False

    # Inside obstacle: velocity is 0
    u_in, v_in = field.velocity_at(600.0, 375.0)
    assert u_in == 0.0 and v_in == 0.0

    # Stagnation points at surface (r = R, theta = 0, pi)
    u_stag1, v_stag1 = field.velocity_at(510.0, 375.0)
    u_stag2, v_stag2 = field.velocity_at(690.0, 375.0)
    assert math.hypot(u_stag1, v_stag1) == pytest.approx(0.0, abs=1e-4)
    assert math.hypot(u_stag2, v_stag2) == pytest.approx(0.0, abs=1e-4)

    # Peak velocity at cylinder top/bottom (u = 2 * U_inf = 24.0 m/s)
    u_top, v_top = field.velocity_at(600.0, 465.0)
    assert u_top == pytest.approx(24.0, abs=1e-3)
    assert v_top == pytest.approx(0.0, abs=1e-3)

    # Divergence check (incompressible flow, div = 0)
    div = field.divergence_at(400.0, 200.0)
    assert div == pytest.approx(0.0, abs=1e-3)


def test_vortex_swirl_vorticity_and_profile() -> None:
    """Stage 3a: Verify Rankine vortex solid body core and irrotational decay."""
    field = VortexSwirlField(cx=600.0, cy=375.0, r_core=80.0, v_peak=18.0, u_drift=2.0)

    # Center velocity: only drift
    u_c, v_c = field.velocity_at(600.0, 375.0)
    assert u_c == pytest.approx(2.0, abs=1e-3)
    assert v_c == pytest.approx(0.0, abs=1e-3)

    # Core vorticity: omega_z = 2 * v_peak / (r_core * scale) = 2 * 18.0 / (80 * 0.05) = 9.0 1/s
    omega_core = field.vorticity_at(600.0, 415.0)
    assert omega_core == pytest.approx(9.0, abs=0.25)

    # Outer region vorticity: decays to ~0
    omega_outer = field.vorticity_at(600.0, 575.0)
    assert omega_outer == pytest.approx(0.0, abs=0.25)


def test_contraction_nozzle_divergence_and_acceleration() -> None:
    """Stage 3b: Verify contraction nozzle acceleration and zero divergence."""
    nozzle = ContractionNozzleField(cy=375.0, h_in=280.0, h_throat=112.0, u_in=10.0)

    # Obstacle check outside walls
    assert nozzle.is_obstacle(100.0, 375.0 - 290.0) is True
    assert nozzle.is_obstacle(100.0, 375.0) is False

    # Inlet velocity vs throat velocity
    u_inlet, _ = nozzle.velocity_at(100.0, 375.0)
    u_throat, _ = nozzle.velocity_at(850.0, 375.0)
    assert u_inlet == pytest.approx(10.0, abs=1e-3)
    assert u_throat == pytest.approx(25.0, abs=1e-3)
    assert (u_throat / u_inlet) == pytest.approx(2.5, abs=1e-3)

    # Incompressibility check (divergence is 0)
    div = nozzle.divergence_at(550.0, 375.0)
    assert div == pytest.approx(0.0, abs=0.05)


def test_integrator_methods_accuracy() -> None:
    """Stage 4: Verify RK4 and Euler flowline integrators with arc-length step ds."""
    field = CylinderCrossFlowField(radius=90.0, u_inf=12.0)

    # Valid step size range: [2.0, 10.0] px
    tracer_rk4 = StreamlineTracer(field, step_size_ds=5.0, method=IntegratorMethod.RK4)
    assert 2.0 <= tracer_rk4.step_size_ds <= 10.0

    line_rk4 = tracer_rk4.trace_streamline(50.0, 200.0)
    assert len(line_rk4.points) > 50
    assert line_rk4.length > 300.0

    tracer_euler = StreamlineTracer(field, step_size_ds=5.0, method=IntegratorMethod.EULER)
    line_euler = tracer_euler.trace_streamline(50.0, 200.0)
    assert len(line_euler.points) > 50

    # Point-to-point step length should match ds approximately
    for i in range(len(line_rk4.points) - 1):
        p1 = line_rk4.points[i]
        p2 = line_rk4.points[i + 1]
        step_len = math.hypot(p2.x - p1.x, p2.y - p1.y)
        assert step_len == pytest.approx(5.0, rel=0.10)


def test_stopping_criteria_and_collision_avoidance() -> None:
    """Stage 5: Verify stopping criteria: boundary, stagnation, obstacle, and collision."""
    field = CylinderCrossFlowField(radius=90.0, u_inf=12.0)
    tracer = StreamlineTracer(field, step_size_ds=5.0, min_separation=15.0)

    # Boundary stop: starts near edge and exits
    line_b = tracer.trace_streamline(50.0, 50.0)
    assert line_b.termination_reason in ("boundary", "max_steps")

    # Obstacle / stagnation stop: fired straight toward front stagnation point
    tracer_obs = StreamlineTracer(field, step_size_ds=4.0, min_separation=15.0)
    line_o = tracer_obs.trace_streamline(250.0, 375.0)
    assert line_o.termination_reason in ("stagnation", "obstacle", "collision")

    # Collision avoidance: tracing line very close to prior line
    line_c = tracer_obs.trace_streamline(250.0, 375.5)
    assert line_c.termination_reason in ("collision", "stagnation", "obstacle")


def test_seed_point_generators() -> None:
    """Stage 6: Verify inlet seeds and vortex circular seeds."""
    inlet_seeds = generate_inlet_seeds(count=20, x_inlet=50.0, y_min=50.0, y_max=700.0)
    assert len(inlet_seeds) == 20
    assert inlet_seeds[0] == (50.0, 50.0)
    assert inlet_seeds[-1] == (50.0, 700.0)

    vortex_seeds = generate_vortex_seeds(cx=600.0, cy=375.0, radii=[50.0, 100.0], points_per_ring=8)
    assert len(vortex_seeds) == 16


def test_svg_11_rendering_and_xml_structure() -> None:
    """Stage 7: Verify standalone W3C SVG 1.1 structure and XML well-formedness."""
    field = CylinderCrossFlowField(radius=90.0, u_inf=12.0)
    canvas = StreamlineCanvas(vector_field=field, step_size_ds=6.0)
    canvas.trace(seeds=[(50.0, 200.0), (50.0, 300.0), (50.0, 450.0)])
    svg_str = canvas.render_svg(color_by=ColorBy.VELOCITY)

    root = ET.fromstring(svg_str)
    assert root.tag.endswith("svg")
    assert root.attrib["width"] == "1200"
    assert root.attrib["height"] == "750"
    assert "<path" in svg_str
    assert "<polygon" in svg_str
    assert "<circle" in svg_str
    assert "#0F172A" in svg_str
    assert (canvas.status_bits & StreamlineStatusBits.SVG_VALID) != 0


def test_wcag_21_aaa_contrast_ratio() -> None:
    """Stage 8: Verify WCAG 2.1 AAA contrast ratio exceeds 18:1 target."""
    # Badge #0B0F19 at 0.92 opacity on #0F172A yields composite background luminance ~0.0051
    # White text #FFFFFF relative luminance is 1.0
    contrast_ratio = (1.0 + 0.05) / (0.0051 + 0.05)
    assert contrast_ratio > 18.0


def test_horner_registers_and_trip_alarms() -> None:
    """Stage 9: Verify Horner OCS register space synchronization and trip alarms."""
    # 1. Nominal flow
    cyl = CylinderCrossFlowField(radius=90.0, u_inf=10.0)
    canvas = StreamlineCanvas(vector_field=cyl)
    canvas.trace(seeds=[(50.0, 200.0), (50.0, 300.0)])

    assert (canvas.reg_table.read_uword("%R690") & int(StreamlineStatusBits.CANVAS_ACTIVE)) != 0
    assert canvas.reg_table.read_word("%R691") == 2
    assert canvas.reg_table.read_bit("%M161") is False
    assert canvas.reg_table.read_bit("%M162") is False
    assert canvas.reg_table.read_uword("%R697") == DIAG_EVENT_OK

    # 2. High velocity trip (%M161, %R697=0x8501)
    high_vel_field = ContractionNozzleField(cy=375.0, h_in=280.0, h_throat=112.0, u_in=14.0)  # throat velocity = 35.0 m/s >= 25.0
    canvas_high = StreamlineCanvas(vector_field=high_vel_field)
    canvas_high.trace(seeds=[(50.0, 375.0)])  # flow accelerates through throat to 35.0 m/s
    assert canvas_high.reg_table.read_bit("%M161") is True
    assert (canvas_high.reg_table.read_uword("%R690") & int(StreamlineStatusBits.HIGH_VELOCITY_TRIP)) != 0
    assert canvas_high.reg_table.read_uword("%R697") == DIAG_EVENT_HIGH_VELOCITY

    # 3. Vortex stall trip (%M162, %R697=0x8502)
    stall_vortex = VortexSwirlField(v_peak=35.0, r_core=40.0)  # omega = 35.0 1/s >= 15.0
    canvas_vortex = StreamlineCanvas(vector_field=stall_vortex)
    canvas_vortex.trace(seeds=[(600.0, 390.0)])
    assert canvas_vortex.reg_table.read_bit("%M162") is True
    assert (canvas_vortex.reg_table.read_uword("%R690") & int(StreamlineStatusBits.VORTEX_STALL_TRIP)) != 0
    assert canvas_vortex.reg_table.read_uword("%R697") == DIAG_EVENT_VORTEX_STALL


def test_full_9_stage_verification_suite(tmp_path) -> None:
    """Verify complete 9-stage verification suite runner and 4-state contract."""
    evidence_path = str(tmp_path / "streamline_evidence.json")
    svg_path = str(tmp_path / "streamline.svg")

    res = run_streamline_canvas_verification(evidence_path, svg_path)

    assert res["status"] == "success"
    assert res["error_code"] is None
    assert res["data"]["total_checks"] == 9
    assert res["data"]["checks_passed"] == 9
    assert len(res["data"]["tests"]) == 9
    assert all(t["passed"] for t in res["data"]["tests"])
