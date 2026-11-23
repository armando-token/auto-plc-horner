"""Unit Tests for Three-Phase Separator Hydrodynamics ODE Solver (W092).

Gate G7 Advanced Process Dynamics / Gate G4 Simulation.
"""

from __future__ import annotations

import math
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.three_phase_separator import (
    ThreePhaseSeparatorConfig,
    ThreePhaseSeparatorSimulator,
    SeparatorStatusBits,
    THREE_PHASE_SEPARATOR_PURE_ST_POU,
    run_three_phase_separator_verification,
)


class TestThreePhaseSeparator:
    """Test suite for W092 Three-Phase Separator Simulator."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Test ST POU validation and AST symbol bindings."""
        SecurityGuard.assert_pure_st_content(THREE_PHASE_SEPARATOR_PURE_ST_POU)
        res = STParser.validate_code(THREE_PHASE_SEPARATOR_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(THREE_PHASE_SEPARATOR_PURE_ST_POU)
        assert ast.name == "W092_ThreePhaseSeparator"
        assert ast.pou_type == POUType.PROGRAM
        assert "%R530" in ast.bound_registers
        assert "%R537" in ast.bound_registers
        assert "%M123" in ast.bound_registers
        assert "%M125" in ast.bound_registers

    def test_ladder_construct_interception(self) -> None:
        """Verify ladder contacts and coils are intercepted fail-closed."""
        bad_st = """
        PROGRAM LadderTest
        VAR Contact : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_vessel_geometry_functions(self) -> None:
        """Test horizontal cylindrical chord width, segment area, and volume."""
        cfg = ThreePhaseSeparatorConfig(vessel_diameter_m=2.4, vessel_length_m=6.0)
        sim = ThreePhaseSeparatorSimulator(config=cfg)

        # Bottom and top limits
        assert sim.chord_width(0.0) == 0.05
        assert sim.cross_sectional_area(0.0) == 0.0
        assert sim.liquid_volume(0.0) == 0.0

        # Mid-level (h = R = 1.2 m): chord width should be D = 2.4 m
        w_mid = sim.chord_width(1.2)
        assert abs(w_mid - 2.4) < 1e-4

        # Half cylinder area should be pi * R^2 / 2
        area_mid = sim.cross_sectional_area(1.2)
        expected_half_area = 0.5 * math.pi * (1.2 ** 2)
        assert abs(area_mid - expected_half_area) < 1e-4

        # Full vessel liquid volume
        v_full = sim.liquid_volume(2.4)
        assert abs(v_full - sim.total_volume) < 1e-3

    def test_stokes_droplet_velocities(self) -> None:
        """Test Stokes water settling and oil rising velocities."""
        sim = ThreePhaseSeparatorSimulator()
        v_settle = sim.stokes_water_settling_velocity()
        v_rise = sim.stokes_oil_rising_velocity()

        # Water settling in oil (100 um droplet, 15 cP) ~ 6.72e-5 m/s
        assert 5.0e-5 <= v_settle <= 8.0e-5
        # Oil rising in water (150 um droplet, 1.0 cP) ~ 2.27e-3 m/s
        assert 1.5e-3 <= v_rise <= 3.0e-3

    def test_emulsion_pad_coalescence_kinetics(self) -> None:
        """Test surfactant hindrance and demulsifier acceleration."""
        sim = ThreePhaseSeparatorSimulator()

        k0, psi0 = sim.emulsion_coalescence_kinetics(c_demuls_ppm=0.0)
        k_dosed, psi_dosed = sim.emulsion_coalescence_kinetics(c_demuls_ppm=35.0)

        # Baseline hindrance factor Psi > 1.0
        assert psi0 > 2.5
        # Dosed hindrance factor decreases towards 1.0
        assert psi_dosed < psi0
        # Coalescence rate increases significantly with demulsifier
        assert k_dosed > 1.8 * k0

    def test_francis_overflow_weir(self) -> None:
        """Test Francis overflow weir discharge calculation."""
        sim = ThreePhaseSeparatorSimulator()

        # No flow below weir crest
        assert sim.francis_weir_flow(h_total_m=1.19) == 0.0
        # Positive discharge above crest
        q1 = sim.francis_weir_flow(h_total_m=1.25)
        q2 = sim.francis_weir_flow(h_total_m=1.35)
        assert q1 > 0.0
        assert q2 > q1

    def test_wire_mesh_demister_performance(self) -> None:
        """Test demister pad efficiency >= 99.8% and dP calculation."""
        sim = ThreePhaseSeparatorSimulator()
        res = sim.demister_performance(gas_flow_kg_s=3.5, p_pa=800000.0)

        assert res["eta_demist"] >= 0.998
        assert res["dp_mbar"] > 0.0
        assert res["flooding_ratio"] < 1.0

    def test_coupled_ode_mass_conservation(self) -> None:
        """Test exact mass conservation residual < 1e-10 kg/s."""
        sim = ThreePhaseSeparatorSimulator()
        y = [sim.h_w, sim.h_pad, sim.h_o, sim.p_gas_pa]
        dydt, flows = sim.evaluate_derivatives(y, sim.demulsifier_ppm)

        cons = sim.check_mass_conservation(dydt, flows, sim.p_gas_pa)
        assert cons["is_conserved"] is True
        assert cons["residual_kg_s"] < 1e-10

    def test_rk4_simulation_stepping(self) -> None:
        """Test dynamic simulation stepping over multiple scan cycles."""
        reg_table = RegisterTable()
        sim = ThreePhaseSeparatorSimulator(register_table=reg_table)

        initial_time = sim.time_s
        for _ in range(10):
            step_data = sim.step(dt=0.1)
            assert step_data["conservation"]["is_conserved"] is True

        assert abs(sim.time_s - (initial_time + 1.0)) < 1e-4
        assert reg_table.read_bit("%M125") is True

    def test_high_high_emulsion_alarm_actuation(self) -> None:
        """Test HH emulsion pad alarm trip and register bit assertion."""
        reg_table = RegisterTable()
        sim = ThreePhaseSeparatorSimulator(register_table=reg_table)

        # Baseline normal pad: 80 mm
        sim.h_pad = 0.08
        sim.step(dt=0.1)
        assert not reg_table.read_bit("%M123")
        assert not (reg_table.read_word("%R537") & SeparatorStatusBits.PAD_ALARM_HH)

        # Exceed HH threshold: 280 mm >= 250 mm
        sim.h_pad = 0.28
        sim.step(dt=0.1)
        assert reg_table.read_bit("%M123") is True
        assert bool(reg_table.read_word("%R537") & SeparatorStatusBits.PAD_ALARM_HH)

    def test_horner_ocs_register_scaling(self) -> None:
        """Test Horner analog registers %R530..%R536 scaling."""
        reg_table = RegisterTable()
        sim = ThreePhaseSeparatorSimulator(register_table=reg_table)

        sim.h_w = 0.650
        sim.h_pad = 0.120
        sim.h_o = 0.700
        sim.p_gas_pa = 825000.0
        sim.sync_registers(weir_flow_l_min=1250.0, demister_dp_mbar=1.4)

        assert reg_table.read_word("%R530") == 650
        assert reg_table.read_word("%R531") == 120
        assert reg_table.read_word("%R532") == 700
        assert reg_table.read_word("%R533") == 825
        assert reg_table.read_word("%R535") == 14  # 1.4 mbar * 10
        assert reg_table.read_word("%R536") == 1250

    def test_run_verification_runner_end_to_end(self, tmp_path) -> None:
        """Test the end-to-end 9-stage verification runner function."""
        ev_file = tmp_path / "separator_evidence.json"
        res = run_three_phase_separator_verification(evidence_path=str(ev_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert ev_file.exists()
