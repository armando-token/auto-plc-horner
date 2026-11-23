"""Unit Tests for Tube Bundle Acoustic Resonance & Vortex Shedding Simulation (W098).

Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation.
"""

from __future__ import annotations

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.acoustic_resonance import (
    AcousticResonanceStatusBits,
    TubeBundleAcousticConfig,
    AcousticResonanceState,
    TubeBundleAcousticSimulator,
    ACOUSTIC_RESONANCE_PURE_ST_POU,
    run_acoustic_resonance_verification,
)


class TestTubeBundleAcousticSimulation:
    """Test suite for W098 Tube Bundle Acoustic Resonance ODE Engine."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify Pure ST POU validation and AST symbol bindings."""
        SecurityGuard.assert_pure_st_content(ACOUSTIC_RESONANCE_PURE_ST_POU)
        res = STParser.validate_code(ACOUSTIC_RESONANCE_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(ACOUSTIC_RESONANCE_PURE_ST_POU)
        assert ast.name == "AcousticResonanceMonitorSync"
        assert ast.pou_type == POUType.PROGRAM
        assert "%R590" in ast.bound_registers
        assert "%R597" in ast.bound_registers
        assert "%M137" in ast.bound_registers
        assert "%M139" in ast.bound_registers

    def test_ladder_construct_interception(self) -> None:
        """Verify ladder contacts and coils are intercepted fail-closed."""
        bad_st = """
        PROGRAM LadderResonance
        VAR ResBit : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_blevins_porosity_correction(self) -> None:
        """Verify effective speed of sound and acoustic natural frequency."""
        cfg = TubeBundleAcousticConfig(
            bundle_solidity=0.30,
            speed_of_sound_m_s=340.0,
            shell_width_m=0.60,
        )
        sim = TubeBundleAcousticSimulator(config=cfg)

        assert sim.c_eff < 340.0
        assert round(sim.c_eff, 1) == 298.2
        assert round(sim.f_a0, 1) == 248.5

    def test_vortex_shedding_strouhal_frequency(self) -> None:
        """Verify interstitial gap velocity and vortex shedding frequency."""
        cfg = TubeBundleAcousticConfig(
            transverse_pitch_m=0.0381,
            tube_outer_diameter_m=0.0254,
            strouhal_number=0.28,
        )
        sim = TubeBundleAcousticSimulator(config=cfg)

        # Gap velocity multiplier = 0.0381 / (0.0381 - 0.0254) = 3.0
        u_gap = sim.get_gap_velocity(10.0)
        assert abs(u_gap - 30.0) < 1e-4

        f_s = sim.get_vortex_frequency(10.0)
        # f_s = 0.28 * 30.0 / 0.0254 = 330.7 Hz
        assert abs(f_s - 330.7) < 0.2

    def test_lock_in_window_detection(self) -> None:
        """Verify detection of acoustic resonance lock-in condition."""
        reg_table = RegisterTable()
        sim = TubeBundleAcousticSimulator(register_table=reg_table)

        # At flow velocity = 7.5 m/s, f_s ~ 248 Hz ~ f_a0 -> locked in
        sim.step(dt=0.001, flow_velocity=7.5, baffle_deployed=False)
        assert sim.state.is_locked_in is True
        assert reg_table.read_bit("%M137") is True

        # At flow velocity = 15.0 m/s, f_s ~ 496 Hz >> f_a0 -> not locked in
        sim.step(dt=0.001, flow_velocity=15.0, baffle_deployed=False)
        assert sim.state.is_locked_in is False
        assert reg_table.read_bit("%M137") is False

    def test_anti_vibration_baffle_suppression(self) -> None:
        """Verify baffle deployment doubles frequency and suppresses resonance."""
        reg_table = RegisterTable()
        sim = TubeBundleAcousticSimulator(register_table=reg_table)

        # Lock-in state with elevated acoustic perturbation
        sim.state.p_ac = 500.0
        sim.state.w = 1000.0
        sim.step(dt=0.001, flow_velocity=7.5, baffle_deployed=False)
        assert sim.state.f_a == sim.f_a0
        assert sim.state.is_locked_in is True

        # Deploy baffle
        sim.step(dt=0.001, flow_velocity=7.5, baffle_deployed=True)
        assert sim.state.f_a == 2.0 * sim.f_a0
        assert sim.state.is_locked_in is False
        assert reg_table.read_bit("%M138") is True

        # Over successive steps, pressure should decay
        for _ in range(100):
            sim.step(dt=0.001, flow_velocity=7.5, baffle_deployed=True)

        assert abs(sim.state.p_ac) < 100.0

    def test_structural_alarm_limit_tripping(self) -> None:
        """Verify deflection and pressure alarm limits trip discrete coil %M139."""
        reg_table = RegisterTable()
        sim = TubeBundleAcousticSimulator(register_table=reg_table)

        # Deflection threshold trip
        sim.state.x = 0.0026  # 2.6 mm > 2.5 mm limit
        sim.step(dt=0.0001, flow_velocity=7.5, baffle_deployed=False)
        assert reg_table.read_bit("%M139") is True

        # Acoustic pressure threshold trip
        sim.state.x = 0.0001
        sim.state.p_ac = 1600.0  # 1600 Pa > 1500 Pa limit
        sim.step(dt=0.0001, flow_velocity=7.5, baffle_deployed=False)
        assert reg_table.read_bit("%M139") is True

    def test_invalid_timestep_handling(self) -> None:
        """Verify rejection of zero or negative timesteps."""
        sim = TubeBundleAcousticSimulator()
        res = sim.step(dt=0.0, flow_velocity=5.0)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_INVALID_TIMESTEP"

    def test_full_verification_runner_9_stages(self) -> None:
        """Verify 9-stage verification suite executes and produces evidence."""
        evidence = run_acoustic_resonance_verification()
        assert evidence["status"] == "success"
        assert evidence["data"]["checks_passed"] == 9
        assert evidence["data"]["total_checks"] == 9
