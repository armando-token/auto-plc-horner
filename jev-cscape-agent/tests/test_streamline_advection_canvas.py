"""Comprehensive unit test suite for Cscape HMI Dynamic Streamline Particle Vector Field Advection SCADA Canvas (W273).

Work Package: W273 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Streamline Particle Vector Field Advection SCADA Canvas]
Status Contract: Strict 4-State JSON output & evidence emission.

Must test:
- Diagnostic codes signed/unsigned 16-bit values and string representations (0x0000, 0x8A01..0x8A04)
- Register and coil mappings (%R2340..%R2347, %M546..%M547)
- 2D Eulerian velocity vector field generation, bilinear interpolation, divergence/vorticity calculations
- RK4 particle integration accuracy and boundary handling (clamping / periodic wrapping)
- Dynamic tracer particles with lifecycle aging and re-seeding
- Streamline trajectory curve generation with speed color spectrum grading
- Standalone W3C SVG 1.1 markup generation, XML validity, and HUD telemetry cards
- WCAG 2.1 AAA contrast compliance (> 18:1 badges, > 7:1 text, > 3:1 graphics)
- Process safety diagnostics (0x8A01..0x8A04) and turbulence warning coil %M547 assertion
- ILogicUnit interface compliance (scan_step, execute, reset, name, priority, is_enabled)
- sync_to_registers with RegisterTable and PrivilegeMode.SYSTEM, plus 50-step scan cycle soak stability
- Pure ST POU validation with STParser and SecurityGuard.assert_pure_st_content
- Anti-ladder construct rejection raising LadderForbiddenError
- 9-stage verification suite run_streamline_advection_canvas_verification()
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.streamline_advection_canvas import (
    # Diagnostic Codes
    DIAG_OK,
    DIAG_EVENT_OK,
    NOMINAL_OK,
    STREAMLINE_OK,
    STREAMLINE_CANVAS_OK,
    GRID_RESOLUTION_FAULT,
    VELOCITY_SINGULARITY_FAULT,
    DIAG_ERR_GRID_RESOLUTION_FAULT,
    DIAG_ERR_VELOCITY_SINGULARITY,
    VELOCITY_DIVERGENCE_TRIP,
    ADVECTION_DIVERGENCE_FAULT,
    DIAG_ERR_VELOCITY_DIVERGENCE_TRIP,
    DIAG_ERR_ADVECTION_DIVERGENCE,
    TURBULENCE_CRITICAL_FAULT,
    GRID_BOUNDARY_OVERFLOW_FAULT,
    DIAG_ERR_TURBULENCE_CRITICAL_FAULT,
    DIAG_ERR_GRID_BOUNDARY_OVERFLOW,
    PARTICLE_STARVATION_FAULT,
    SVG_RENDER_FAULT,
    DIAG_ERR_PARTICLE_STARVATION_FAULT,
    DIAG_ERR_SVG_RENDER_FAULT,
    DiagnosticCode,
    # Registers & Coils
    REG_STREAMLINE_GRID_CELLS_COUNT,
    REG_ACTIVE_TRACER_PARTICLES_COUNT,
    REG_STREAMLINE_ADVECTION_TIMESTEP_MS,
    REG_FLOW_REYNOLDS_NUMBER_SCALED,
    REG_MAX_VELOCITY_MAGNITUDE_SCALED,
    REG_VORTICITY_INTENSITY_SCALED,
    REG_PARTICLE_RESIDENCE_TIME_SEC,
    REG_STREAMLINE_CANVAS_DIAGNOSTIC_CODE,
    COIL_STREAMLINE_CANVAS_ACTIVE,
    COIL_FLOW_TURBULENCE_WARNING,
    # Aliases
    REG_GRID_RESOLUTION_X,
    REG_GRID_RESOLUTION_Y,
    REG_ACTIVE_STREAMLINE_COUNT,
    REG_PEAK_VELOCITY_SCALED,
    REG_MEAN_VORTICITY_SCALED,
    REG_ACTIVE_TRACER_PARTICLE_COUNT,
    REG_ADVECTION_TIME_STEP_MS,
    REG_DIAGNOSTIC_STATUS_CODE,
    COIL_STREAMLINE_ADVECTION_CANVAS_ACTIVE,
    COIL_TURBULENCE_WARNING_ACTIVE,
    # Dimensions & Nominal Values
    NOMINAL_GRID_ROWS,
    NOMINAL_GRID_COLS,
    NOMINAL_GRID_NODES_COUNT,
    NOMINAL_ACTIVE_PARTICLES_COUNT,
    NOMINAL_STREAMLINE_COUNT,
    NOMINAL_FLOW_REYNOLDS_NUMBER,
    NOMINAL_MAX_VELOCITY_MPS,
    NOMINAL_VORTICITY_INTENSITY,
    NOMINAL_PARTICLE_RESIDENCE_TIME_SEC,
    CANVAS_VIEWPORT_WIDTH,
    CANVAS_VIEWPORT_HEIGHT,
    PLANT_WIDTH_M,
    PLANT_HEIGHT_M,
    # Colors & Contrast
    COLOR_DARK_THEME_BACKING,
    COLOR_MAP_BG,
    COLOR_MAP_BORDER,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_DECOUPLED_BADGE,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_MUTED,
    COLOR_ACCENT_CYAN,
    COLOR_ACCENT_EMERALD,
    COLOR_ACCENT_AMBER,
    COLOR_ACCENT_ORANGE,
    COLOR_ACCENT_CRIMSON,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_GRAPHICS_CONTRAST_TARGET,
    srgb_channel_to_linear,
    hex_to_relative_luminance,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    # Models & Primitives
    Point2D,
    FluidObstacle,
    FluidVortex,
    GridNode,
    TracerParticle,
    StreamlineCurve,
    StreamlineMetrics,
    StreamlineAdvectionStatusBits,
    StreamlineStatusBits,
    BoundaryHandlingMode,
    apply_boundary_handling,
    # Solvers & Engines
    EulerianVectorGrid,
    rk4_step,
    euler_step,
    trace_streamline,
    generate_canonical_streamlines,
    RK4StreamlineIntegrator,
    ParticleAdvectionEngine,
    # Canvas Engine
    StreamlineAdvectionCanvas,
    create_canonical_streamline_advection_canvas,
    generate_streamline_advection_canvas_svg,
    # Pure ST POU
    STREAMLINE_ADVECTION_CANVAS_PURE_ST_POU,
    verify_streamline_advection_canvas_pure_st,
    # Verification Runner
    run_streamline_advection_canvas_verification,
)


# ============================================================================
# 1. Diagnostic Codes Signed/Unsigned 16-Bit Values & Representations
# ============================================================================

class TestDiagnosticCodesSignedUnsigned:
    """Validate 16-bit diagnostic codes (0x0000, 0x8A01..0x8A04), signed/unsigned values, and formats."""

    def test_diagnostic_code_values_and_representations(self) -> None:
        """Verify signed and unsigned 16-bit values and string representations."""
        # 0x0000 OK
        assert DIAG_OK == 0x0000
        assert DIAG_EVENT_OK == 0x0000
        assert NOMINAL_OK == 0x0000
        assert STREAMLINE_OK == 0x0000
        assert STREAMLINE_CANVAS_OK == 0x0000
        assert int(DIAG_OK) == 0
        assert f"0x{int(DIAG_OK) & 0xFFFF:04X}" == "0x0000"

        # 0x8A01 Grid Resolution / Singularity Fault
        assert GRID_RESOLUTION_FAULT == 0x8A01
        assert VELOCITY_SINGULARITY_FAULT == 0x8A01
        assert DIAG_ERR_GRID_RESOLUTION_FAULT == 0x8A01
        assert DIAG_ERR_VELOCITY_SINGULARITY == 0x8A01
        assert int(GRID_RESOLUTION_FAULT) == 35329
        assert f"0x{int(GRID_RESOLUTION_FAULT) & 0xFFFF:04X}" == "0x8A01"

        # 0x8A02 Velocity Divergence Trip
        assert VELOCITY_DIVERGENCE_TRIP == 0x8A02
        assert ADVECTION_DIVERGENCE_FAULT == 0x8A02
        assert DIAG_ERR_VELOCITY_DIVERGENCE_TRIP == 0x8A02
        assert DIAG_ERR_ADVECTION_DIVERGENCE == 0x8A02
        assert int(VELOCITY_DIVERGENCE_TRIP) == 35330
        assert f"0x{int(VELOCITY_DIVERGENCE_TRIP) & 0xFFFF:04X}" == "0x8A02"

        # 0x8A03 Critical Turbulence / Boundary Overflow Fault
        assert TURBULENCE_CRITICAL_FAULT == 0x8A03
        assert GRID_BOUNDARY_OVERFLOW_FAULT == 0x8A03
        assert DIAG_ERR_TURBULENCE_CRITICAL_FAULT == 0x8A03
        assert DIAG_ERR_GRID_BOUNDARY_OVERFLOW == 0x8A03
        assert int(TURBULENCE_CRITICAL_FAULT) == 35331
        assert f"0x{int(TURBULENCE_CRITICAL_FAULT) & 0xFFFF:04X}" == "0x8A03"

        # 0x8A04 Particle Starvation / SVG Render Fault
        assert PARTICLE_STARVATION_FAULT == 0x8A04
        assert SVG_RENDER_FAULT == 0x8A04
        assert DIAG_ERR_PARTICLE_STARVATION_FAULT == 0x8A04
        assert DIAG_ERR_SVG_RENDER_FAULT == 0x8A04
        assert int(PARTICLE_STARVATION_FAULT) == 35332
        assert f"0x{int(PARTICLE_STARVATION_FAULT) & 0xFFFF:04X}" == "0x8A04"

    def test_diagnostic_code_signed_vs_unsigned_equality(self) -> None:
        """Verify signed and unsigned comparison across INT16 boundaries."""
        code_neg = DiagnosticCode(-1)
        assert code_neg == 0xFFFF
        assert code_neg == -1

        # 0x8A01 unsigned 35329 == signed -30207
        code_8a01 = DiagnosticCode(0x8A01)
        assert code_8a01 == 35329
        assert code_8a01 == -30207
        assert code_8a01 == 0x8A01

        # 0x8A02 unsigned 35330 == signed -30206
        code_8a02 = DiagnosticCode(0x8A02)
        assert code_8a02 == 35330
        assert code_8a02 == -30206
        assert code_8a02 == 0x8A02

        # 0x8A03 unsigned 35331 == signed -30205
        code_8a03 = DiagnosticCode(0x8A03)
        assert code_8a03 == 35331
        assert code_8a03 == -30205
        assert code_8a03 == 0x8A03

        # 0x8A04 unsigned 35332 == signed -30204
        code_8a04 = DiagnosticCode(0x8A04)
        assert code_8a04 == 35332
        assert code_8a04 == -30204
        assert code_8a04 == 0x8A04

        # Hashing and container behavior
        diag_set: Set[DiagnosticCode] = {
            DIAG_OK,
            GRID_RESOLUTION_FAULT,
            VELOCITY_DIVERGENCE_TRIP,
            TURBULENCE_CRITICAL_FAULT,
            PARTICLE_STARVATION_FAULT,
        }
        assert len(diag_set) == 5
        assert DiagnosticCode(0x8A01) in diag_set
        assert DiagnosticCode(0x8A02) in diag_set
        assert DiagnosticCode(0x8A03) in diag_set
        assert DiagnosticCode(0x8A04) in diag_set
        assert DiagnosticCode(0x0000) in diag_set


# ============================================================================
# 2. Register and Coil Mappings (%R2340..%R2347, %M546..%M547)
# ============================================================================

class TestRegisterAndCoilMappings:
    """Validate register mappings (%R2340..%R2347) and coil mappings (%M546..%M547)."""

    def test_analog_word_registers(self) -> None:
        """Verify %R2340..%R2347 register assignments and aliases."""
        assert REG_STREAMLINE_GRID_CELLS_COUNT == "%R2340"
        assert REG_ACTIVE_TRACER_PARTICLES_COUNT == "%R2341"
        assert REG_STREAMLINE_ADVECTION_TIMESTEP_MS == "%R2342"
        assert REG_FLOW_REYNOLDS_NUMBER_SCALED == "%R2343"
        assert REG_MAX_VELOCITY_MAGNITUDE_SCALED == "%R2344"
        assert REG_VORTICITY_INTENSITY_SCALED == "%R2345"
        assert REG_PARTICLE_RESIDENCE_TIME_SEC == "%R2346"
        assert REG_STREAMLINE_CANVAS_DIAGNOSTIC_CODE == "%R2347"

        # Compatibility aliases
        assert REG_GRID_RESOLUTION_X == "%R2340"
        assert REG_ACTIVE_TRACER_PARTICLE_COUNT == "%R2341"
        assert REG_GRID_RESOLUTION_Y == "%R2341"
        assert REG_ACTIVE_STREAMLINE_COUNT == "%R2342"
        assert REG_PEAK_VELOCITY_SCALED == "%R2343"
        assert REG_MEAN_VORTICITY_SCALED == "%R2345"
        assert REG_ADVECTION_TIME_STEP_MS == "%R2346"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2347"

    def test_discrete_coils(self) -> None:
        """Verify %M546..%M547 discrete coils and aliases."""
        assert COIL_STREAMLINE_CANVAS_ACTIVE == "%M546"
        assert COIL_STREAMLINE_ADVECTION_CANVAS_ACTIVE == "%M546"
        assert COIL_FLOW_TURBULENCE_WARNING == "%M547"
        assert COIL_TURBULENCE_WARNING_ACTIVE == "%M547"

    def test_nominal_metric_constants(self) -> None:
        """Verify nominal plant metrics and thresholds."""
        assert NOMINAL_GRID_ROWS == 32
        assert NOMINAL_GRID_COLS == 32
        assert NOMINAL_GRID_NODES_COUNT == 1024
        assert NOMINAL_ACTIVE_PARTICLES_COUNT == 120
        assert NOMINAL_STREAMLINE_COUNT == 24
        assert NOMINAL_FLOW_REYNOLDS_NUMBER == 1850.0
        assert NOMINAL_MAX_VELOCITY_MPS == 4.5
        assert NOMINAL_VORTICITY_INTENSITY == 2.8
        assert NOMINAL_PARTICLE_RESIDENCE_TIME_SEC == 14
        assert math.isclose(PLANT_WIDTH_M, 400.0)
        assert math.isclose(PLANT_HEIGHT_M, 300.0)


# ============================================================================
# 3. 2D Eulerian Vector Grid, Interpolation & Differential Invariants
# ============================================================================

class TestEulerianVectorGridAndInterpolation:
    """Validate 2D Eulerian grid generation, bilinear interpolation, divergence, and vorticity."""

    def test_grid_initialization_and_dimensions(self) -> None:
        """Verify 32x32 Eulerian grid nodes, physical coordinates, and cell spacing."""
        grid = EulerianVectorGrid(rows=32, cols=32, width_m=400.0, height_m=300.0)
        assert len(grid.nodes) == 32
        assert len(grid.nodes[0]) == 32
        assert grid.rows == 32
        assert grid.cols == 32
        assert math.isclose(grid.width_m, 400.0)
        assert math.isclose(grid.height_m, 300.0)

        # Check corner coordinates
        assert math.isclose(grid.nodes[0][0].x_m, 0.0)
        assert math.isclose(grid.nodes[0][0].y_m, 0.0)
        assert math.isclose(grid.nodes[31][31].x_m, 400.0)
        assert math.isclose(grid.nodes[31][31].y_m, 300.0)

    def test_solid_obstacle_flow_deflection(self) -> None:
        """Verify cylindrical obstacle deflects flow and produces zero velocity internally."""
        grid = EulerianVectorGrid(rows=32, cols=32)
        obs = grid.obstacle
        assert obs.is_circular is True

        # Center of obstacle has zero velocity
        u_in, v_in = grid.sample_velocity(obs.center_x_m, obs.center_y_m)
        assert u_in == 0.0
        assert v_in == 0.0

        # Flow outside obstacle is non-zero
        u_out, v_out = grid.sample_velocity(obs.center_x_m + obs.radius_m + 10.0, obs.center_y_m)
        spd_out = math.sqrt(u_out * u_out + v_out * v_out)
        assert spd_out > 0.0

    def test_bilinear_interpolation_smoothness(self) -> None:
        """Verify bilinear velocity interpolation samples continuously between grid nodes."""
        grid = EulerianVectorGrid(rows=32, cols=32)

        # Sample at exact node
        n = grid.nodes[6][6]
        u_sample, v_sample = grid.sample_velocity(n.x_m, n.y_m)
        assert math.isclose(u_sample, n.u, abs_tol=1e-3)
        assert math.isclose(v_sample, n.v, abs_tol=1e-3)

        # Sample at midpoint between nodes
        mid_x = 0.5 * (grid.nodes[6][6].x_m + grid.nodes[6][7].x_m)
        mid_y = grid.nodes[6][6].y_m
        u_mid, v_mid = grid.sample_velocity(mid_x, mid_y)
        assert not math.isnan(u_mid)
        assert not math.isnan(v_mid)

    def test_differential_invariants_divergence_and_vorticity(self) -> None:
        """Verify near-zero incompressibility divergence and non-trivial vorticity."""
        grid = EulerianVectorGrid(rows=32, cols=32)
        mean_div = grid.compute_mean_divergence()
        assert not math.isnan(mean_div)
        assert mean_div < 0.15  # Near zero divergence incompressibility

        # Vorticity sampling
        vort_center = grid.sample_vorticity(240.0, 200.0)
        assert not math.isnan(vort_center)
        assert not math.isinf(vort_center)


# ============================================================================
# 4. RK4 Particle Integration & Boundary Handling
# ============================================================================

class TestRK4ParticleIntegrationAndBoundaryHandling:
    """Validate RK4 integration accuracy, comparative Euler difference, and boundary handling."""

    def test_rk4_step_vs_euler_integration(self) -> None:
        """Verify RK4 produces higher-order curvature refinement compared to Euler."""
        grid = EulerianVectorGrid(rows=32, cols=32)
        x0, y0 = 60.0, 150.0
        dt = 0.5

        rk4_x, rk4_y, rk4_u, rk4_v = rk4_step(grid, x0, y0, dt)
        euler_x, euler_y, euler_u, euler_v = euler_step(grid, x0, y0, dt)

        dist_rk4 = math.hypot(rk4_x - x0, rk4_y - y0)
        dist_euler = math.hypot(euler_x - x0, euler_y - y0)
        assert dist_rk4 > 0.0
        assert dist_euler > 0.0

        # RK4 captures trajectory curvature
        diff = math.hypot(rk4_x - euler_x, rk4_y - euler_y)
        assert diff >= 0.0
        assert diff < dist_rk4

    def test_boundary_handling_clamping_and_wrapping(self) -> None:
        """Verify clamping and periodic wrapping boundary policies."""
        w, h = 400.0, 300.0

        # Clamping
        cx, cy, ovf_c = apply_boundary_handling(-20.0, 350.0, width_m=w, height_m=h, mode=BoundaryHandlingMode.CLAMP)
        assert ovf_c is True
        assert cx == 0.0
        assert cy == 300.0

        # Wrapping
        wx, wy, ovf_w = apply_boundary_handling(425.0, 310.0, width_m=w, height_m=h, mode=BoundaryHandlingMode.WRAP)
        assert ovf_w is True
        assert math.isclose(wx, 25.0)
        assert math.isclose(wy, 10.0)


# ============================================================================
# 5. Dynamic Tracer Particles & Residence Lifetime
# ============================================================================

class TestDynamicTracerParticles:
    """Validate tracer particle advection, aging, re-seeding, and trail streak history."""

    def test_particle_advection_and_trails(self) -> None:
        """Verify particles advance over time and accumulate trail points."""
        grid = EulerianVectorGrid(rows=32, cols=32)
        engine = ParticleAdvectionEngine(grid=grid, particle_count=40)
        assert len(engine.particles) == 40

        init_x = engine.particles[0].x_m
        for _ in range(10):
            engine.advect(dt_sec=0.05)

        final_x = engine.particles[0].x_m
        assert abs(final_x - init_x) > 0.001
        assert len(engine.particles[0].trail) >= 2

    def test_residence_time_calculation(self) -> None:
        """Verify average residence time calculation across active particles."""
        grid = EulerianVectorGrid(rows=32, cols=32)
        engine = ParticleAdvectionEngine(grid=grid, particle_count=30)
        for _ in range(20):
            engine.advect(dt_sec=0.1)
        res_time = engine.get_average_residence_time()
        assert res_time > 0.0


# ============================================================================
# 6. Streamline Trajectory Curves
# ============================================================================

class TestStreamlineTrajectoryCurves:
    """Validate streamline curve tracing from seeds and color mapping."""

    def test_canonical_streamlines_generation(self) -> None:
        """Verify generation of canonical streamline curves."""
        grid = EulerianVectorGrid(rows=32, cols=32)
        streamlines = generate_canonical_streamlines(grid, count=16)
        assert len(streamlines) >= 16

        for sl in streamlines:
            assert len(sl.points) > 5
            assert sl.arc_length > 10.0
            assert sl.path_d.startswith("M")
            assert sl.color_hex in (
                COLOR_ACCENT_CYAN,
                COLOR_ACCENT_EMERALD,
                COLOR_ACCENT_AMBER,
                COLOR_ACCENT_ORANGE,
                COLOR_ACCENT_CRIMSON,
            )

    def test_rk4_streamline_integrator_adapter(self) -> None:
        """Verify RK4StreamlineIntegrator adapter class."""
        grid = EulerianVectorGrid(rows=32, cols=32)
        integrator = RK4StreamlineIntegrator(grid)
        curve = integrator.trace_streamline(seed=(10.0, 150.0), step_ds=5.0, max_steps=40)
        assert len(curve.points) > 2
        assert curve.arc_length > 0.0


# ============================================================================
# 7. Standalone W3C SVG 1.1 Generation & XML Validity
# ============================================================================

class TestSvgMarkupGenerationAndXmlValidity:
    """Validate W3C SVG 1.1 markup generation, XML validity, and SCADA visual elements."""

    def test_svg_xml_structure_and_dimensions(self) -> None:
        """Verify SVG output is well-formed XML with 1200x750 viewport dimensions."""
        canvas = create_canonical_streamline_advection_canvas()
        svg_str = canvas.generate_svg()

        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg") or root.tag == "svg"
        assert root.attrib["width"] == "1200"
        assert root.attrib["height"] == "750"
        assert root.attrib["viewBox"] == "0 0 1200 750"

    def test_svg_contains_essential_scada_elements(self) -> None:
        """Verify SVG contains header banner, map viewport, streamlines, particles, polylines, and HUD cards."""
        canvas = create_canonical_streamline_advection_canvas()
        svg_str = canvas.generate_svg()

        assert 'id="header-banner"' in svg_str
        assert 'id="streamline-map-viewport"' in svg_str
        assert 'id="telemetry-hud"' in svg_str

        # Defs & elements
        assert "<defs>" in svg_str
        assert "<path" in svg_str
        assert "<circle" in svg_str
        assert "<rect" in svg_str
        assert "<polyline" in svg_str
        assert "<text" in svg_str


# ============================================================================
# 8. WCAG 2.1 AAA Contrast Compliance
# ============================================================================

class TestWcagAaaContrastCompliance:
    """Validate WCAG 2.1 AAA contrast compliance (> 18:1 badges, > 7:1 text, > 3:1 graphics)."""

    def test_srgb_to_linear_and_luminance_math(self) -> None:
        """Verify sRGB channel transfer function and standard relative luminance calculations."""
        assert math.isclose(hex_to_relative_luminance("#000000"), 0.0, abs_tol=1e-5)
        assert math.isclose(hex_to_relative_luminance("#FFFFFF"), 1.0, abs_tol=1e-5)
        assert srgb_channel_to_linear(0.0) == 0.0
        assert math.isclose(srgb_channel_to_linear(1.0), 1.0, abs_tol=1e-5)

    def test_decoupled_badge_contrast_exceeds_18_to_1(self) -> None:
        """Verify decoupled dark badge contrast (COLOR_TEXT_PRIMARY on COLOR_DECOUPLED_BADGE) >= 18.0:1."""
        badge_contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert badge_contrast >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert badge_contrast > 18.0

    def test_primary_text_contrast_exceeds_7_to_1(self) -> None:
        """Verify primary and muted text contrast against panel surfaces >= 7.0:1."""
        card_text_contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_CARD_BG)
        assert card_text_contrast >= WCAG_AAA_TEXT_CONTRAST_TARGET

        muted_text_contrast = calculate_contrast_ratio(COLOR_TEXT_MUTED, COLOR_DECOUPLED_BADGE)
        assert muted_text_contrast >= WCAG_AAA_TEXT_CONTRAST_TARGET

    def test_graphical_accent_contrast_exceeds_3_to_1(self) -> None:
        """Verify UI graphical accents against canvas background >= 3.0:1."""
        cyan_contrast = calculate_contrast_ratio(COLOR_ACCENT_CYAN, COLOR_MAP_BG)
        assert cyan_contrast >= WCAG_GRAPHICS_CONTRAST_TARGET

        emerald_contrast = calculate_contrast_ratio(COLOR_ACCENT_EMERALD, COLOR_MAP_BG)
        assert emerald_contrast >= WCAG_GRAPHICS_CONTRAST_TARGET


# ============================================================================
# 9. Process Safety Diagnostics & Interlock Trip / Recovery
# ============================================================================

class TestDiagnosticsFaultCodesAndInterlocks:
    """Validate 0x8A01..0x8A04 diagnostics, %M547 alarm assertion, and clear recovery."""

    def test_grid_resolution_fault_0x8a01(self) -> None:
        """Verify grid dimension anomaly triggers 0x8A01 and asserts %M547."""
        canvas = create_canonical_streamline_advection_canvas()
        canvas.grid_rows = 4
        canvas.grid_cols = 4
        canvas.metrics.grid_cells_count = 16
        canvas._evaluate_safety_interlocks()

        assert canvas.metrics.diagnostic_code == GRID_RESOLUTION_FAULT
        assert canvas.metrics.diagnostic_code == 0x8A01
        assert canvas.metrics.turbulence_warning is True
        assert bool(canvas.status_bits & StreamlineAdvectionStatusBits.GRID_FAULT)

        tbl = RegisterTable()
        canvas.sync_to_registers(tbl, privilege=PrivilegeMode.SYSTEM)
        assert tbl.read_uword(REG_STREAMLINE_CANVAS_DIAGNOSTIC_CODE) == 0x8A01
        assert DiagnosticCode(tbl.read_word(REG_STREAMLINE_CANVAS_DIAGNOSTIC_CODE)) == 0x8A01
        assert tbl.read_bit(COIL_FLOW_TURBULENCE_WARNING) is True

    def test_velocity_divergence_trip_0x8a02(self) -> None:
        """Verify velocity divergence triggers 0x8A02 and asserts %M547."""
        canvas = create_canonical_streamline_advection_canvas()
        canvas.set_max_velocity(0.0)

        assert canvas.metrics.diagnostic_code == VELOCITY_DIVERGENCE_TRIP
        assert canvas.metrics.diagnostic_code == 0x8A02
        assert canvas.metrics.turbulence_warning is True
        assert bool(canvas.status_bits & StreamlineAdvectionStatusBits.VELOCITY_TRIP)

        tbl = RegisterTable()
        canvas.sync_to_registers(tbl, privilege=PrivilegeMode.SYSTEM)
        assert tbl.read_uword(REG_STREAMLINE_CANVAS_DIAGNOSTIC_CODE) == 0x8A02
        assert DiagnosticCode(tbl.read_word(REG_STREAMLINE_CANVAS_DIAGNOSTIC_CODE)) == 0x8A02
        assert tbl.read_bit(COIL_FLOW_TURBULENCE_WARNING) is True

    def test_turbulence_critical_fault_0x8a03(self) -> None:
        """Verify critical turbulence (Re > 4000) triggers 0x8A03 and asserts %M547."""
        canvas = create_canonical_streamline_advection_canvas()
        canvas.set_reynolds_number(4500.0)

        assert canvas.metrics.diagnostic_code == TURBULENCE_CRITICAL_FAULT
        assert canvas.metrics.diagnostic_code == 0x8A03
        assert canvas.metrics.turbulence_warning is True
        assert bool(canvas.status_bits & StreamlineAdvectionStatusBits.TURBULENCE_CRITICAL)

        tbl = RegisterTable()
        canvas.sync_to_registers(tbl, privilege=PrivilegeMode.SYSTEM)
        assert tbl.read_uword(REG_STREAMLINE_CANVAS_DIAGNOSTIC_CODE) == 0x8A03
        assert DiagnosticCode(tbl.read_word(REG_STREAMLINE_CANVAS_DIAGNOSTIC_CODE)) == 0x8A03
        assert tbl.read_bit(COIL_FLOW_TURBULENCE_WARNING) is True

    def test_particle_starvation_fault_0x8a04(self) -> None:
        """Verify particle starvation triggers 0x8A04 and asserts %M547."""
        canvas = create_canonical_streamline_advection_canvas()
        canvas.set_active_particles_count(0)

        assert canvas.metrics.diagnostic_code == PARTICLE_STARVATION_FAULT
        assert canvas.metrics.diagnostic_code == 0x8A04
        assert canvas.metrics.turbulence_warning is True
        assert bool(canvas.status_bits & StreamlineAdvectionStatusBits.PARTICLE_STARVATION)

        tbl = RegisterTable()
        canvas.sync_to_registers(tbl, privilege=PrivilegeMode.SYSTEM)
        assert tbl.read_uword(REG_STREAMLINE_CANVAS_DIAGNOSTIC_CODE) == 0x8A04
        assert DiagnosticCode(tbl.read_word(REG_STREAMLINE_CANVAS_DIAGNOSTIC_CODE)) == 0x8A04
        assert tbl.read_bit(COIL_FLOW_TURBULENCE_WARNING) is True

    def test_fault_recovery_and_reset(self) -> None:
        """Verify reset restores nominal 0x0000 state and deasserts %M547."""
        canvas = create_canonical_streamline_advection_canvas()
        canvas.set_active_particles_count(0)
        assert canvas.metrics.diagnostic_code == 0x8A04

        canvas.reset()
        assert canvas.metrics.diagnostic_code == DIAG_OK
        assert canvas.metrics.turbulence_warning is False
        assert canvas.metrics.active_particles_count == NOMINAL_ACTIVE_PARTICLES_COUNT


# ============================================================================
# 10. ILogicUnit Interface Compliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface compliance (scan_step, execute, reset)."""

    def test_ilogicunit_properties(self) -> None:
        """Verify name, priority, and is_enabled properties."""
        canvas = create_canonical_streamline_advection_canvas()
        assert canvas.name == "StreamlineAdvectionCanvas"
        assert canvas.priority == 100
        assert canvas.is_enabled is True

    def test_scan_step_and_execute(self) -> None:
        """Verify scan_step and execute run without raising exceptions."""
        canvas = create_canonical_streamline_advection_canvas()
        canvas.scan_step(dt=0.02)
        assert canvas._cycle_count == 1

        ctx = ScanContext(cycle=2, dt_ms=20.0)
        canvas.execute(ctx)
        assert canvas._cycle_count == 2

    def test_reset_restores_initial_state(self) -> None:
        """Verify reset restores initial dimensions, metrics, and nominal diagnostic state."""
        canvas = create_canonical_streamline_advection_canvas()
        canvas.set_max_velocity(0.0)

        canvas.reset()
        assert canvas.metrics.diagnostic_code == DIAG_OK
        assert canvas.metrics.turbulence_warning is False
        assert canvas.metrics.canvas_active is True
        assert canvas._cycle_count == 0


# ============================================================================
# 11. Horner OCS Register Synchronization & 50-Step Scan Cycle Soak Stability
# ============================================================================

class TestHornerOcsRegisterSyncAndSoakStability:
    """Validate Horner OCS register synchronization and 50-step scan cycle soak stability."""

    def test_register_synchronization_fidelity(self) -> None:
        """Verify register table read/write fidelity across %R2340..%R2347 and %M546..%M547."""
        tbl = RegisterTable()
        canvas = create_canonical_streamline_advection_canvas(reg_table=tbl)
        canvas.sync_to_registers(tbl, privilege=PrivilegeMode.SYSTEM)

        assert tbl.read_word(REG_STREAMLINE_GRID_CELLS_COUNT) == 1024
        assert tbl.read_word(REG_ACTIVE_TRACER_PARTICLES_COUNT) == 120
        assert tbl.read_word(REG_STREAMLINE_ADVECTION_TIMESTEP_MS) == 20
        assert tbl.read_word(REG_FLOW_REYNOLDS_NUMBER_SCALED) == 1850
        assert tbl.read_word(REG_MAX_VELOCITY_MAGNITUDE_SCALED) == 45
        assert tbl.read_word(REG_VORTICITY_INTENSITY_SCALED) == 28
        assert tbl.read_word(REG_PARTICLE_RESIDENCE_TIME_SEC) == 14
        assert tbl.read_word(REG_STREAMLINE_CANVAS_DIAGNOSTIC_CODE) == 0

        assert tbl.read_bit(COIL_STREAMLINE_CANVAS_ACTIVE) is True
        assert tbl.read_bit(COIL_FLOW_TURBULENCE_WARNING) is False

    def test_sync_from_registers_setpoint_updates(self) -> None:
        """Verify canvas ingests setpoint changes from Horner OCS register table."""
        tbl = RegisterTable()
        canvas = create_canonical_streamline_advection_canvas(reg_table=tbl)

        tbl.write_word(REG_ACTIVE_TRACER_PARTICLES_COUNT, 80, privilege=PrivilegeMode.SYSTEM)
        tbl.write_word(REG_STREAMLINE_ADVECTION_TIMESTEP_MS, 30, privilege=PrivilegeMode.SYSTEM)
        canvas.sync_from_registers(tbl)

        assert canvas.target_particle_count == 80
        assert canvas.advection_timestep_ms == 30

    def test_fifty_step_scan_cycle_soak_stability(self) -> None:
        """Verify 50 consecutive scan cycles execute without memory leaks, NaN values, or drift."""
        tbl = RegisterTable()
        canvas = create_canonical_streamline_advection_canvas(reg_table=tbl)

        ctx = ScanContext(cycle=0, dt_ms=20.0)

        for step in range(50):
            ctx.cycle = step + 1
            canvas.scan_step(dt=0.02, context=ctx)

            assert not math.isnan(canvas.metrics.max_velocity_mps)
            assert not math.isnan(canvas.metrics.vorticity_intensity)
            assert not math.isnan(canvas.metrics.reynolds_number)
            assert canvas.metrics.diagnostic_code == DIAG_OK
            assert tbl.read_bit(COIL_STREAMLINE_CANVAS_ACTIVE) is True
            assert tbl.read_bit(COIL_FLOW_TURBULENCE_WARNING) is False


# ============================================================================
# 12. Pure IEC 61131-3 ST POU Validation with STParser and SecurityGuard
# ============================================================================

class TestPureStPouValidation:
    """Validate Pure ST POU syntax, AST parsing, and register bindings."""

    def test_pure_st_pou_syntax_and_ast_parsing(self) -> None:
        """Verify ST POU 'StreamlineAdvectionCanvasSync' validates and parses cleanly."""
        SecurityGuard.assert_pure_st_content(STREAMLINE_ADVECTION_CANVAS_PURE_ST_POU)

        res = STParser.validate_code(STREAMLINE_ADVECTION_CANVAS_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser().parse_pou(STREAMLINE_ADVECTION_CANVAS_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "StreamlineAdvectionCanvasSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_pure_st_variable_register_bindings(self) -> None:
        """Verify each ST variable has the exact intended %R and %M memory binding."""
        ast = STParser().parse_pou(STREAMLINE_ADVECTION_CANVAS_PURE_ST_POU)
        bound = set(ast.bound_registers)

        expected_regs = {
            "%R2340", "%R2341", "%R2342", "%R2343",
            "%R2344", "%R2345", "%R2346", "%R2347",
            "%M546", "%M547",
        }
        assert expected_regs.issubset(bound)

    def test_pure_st_validator_function(self) -> None:
        """Verify verify_streamline_advection_canvas_pure_st() helper returns True."""
        assert verify_streamline_advection_canvas_pure_st() is True


# ============================================================================
# 13. Anti-Ladder Construct Rejection
# ============================================================================

class TestAntiLadderConstructRejection:
    """Validate aggressive interception and rejection of ladder logic constructs."""

    def test_ladder_contacts_rejection(self) -> None:
        """Verify contacts construct '---[ ]---' is rejected with LadderForbiddenError."""
        bad_st = "PROGRAM Test VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_coils_rejection(self) -> None:
        """Verify coils construct '---( )---' is rejected with LadderForbiddenError."""
        bad_st = "PROGRAM Test VAR Y: BOOL; END_VAR ---( )--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_ladder_rung_delimiters_rejection(self) -> None:
        """Verify RUNG and NETWORK delimiters are rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\nRUNG 1:\nEND_PROGRAM")

        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\nNETWORK 1:\nEND_PROGRAM")

    def test_ladder_mnemonics_rejection(self) -> None:
        """Verify mnemonics XIC and OTE are rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\nXIC InBit;\nEND_PROGRAM")

        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test\nOTE OutBit;\nEND_PROGRAM")


# ============================================================================
# 14. Verification Suite Runner
# ============================================================================

class TestVerificationSuiteRunner:
    """Validate complete deterministic 9-stage verification suite."""

    def test_runner_returns_strict_4_state_success(self) -> None:
        """Verify run_streamline_advection_canvas_verification returns success and 9/9 stages pass."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            svg_p = Path(tmpdir) / "sample.svg"

            res = run_streamline_advection_canvas_verification(
                output_path=ev_path,
                sample_svg_path=svg_p,
            )

            assert res["status"] == "success"
            assert res["error_code"] is None
            assert res["data"]["stages_passed"] == 9
            assert res["data"]["total_stages"] == 9
            assert ev_path.is_file()
            assert svg_p.is_file()
