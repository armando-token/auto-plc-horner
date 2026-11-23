"""Unit tests for Industrial Spray Drying Tower & Atomizer Droplet Evaporation Dynamics ODE Simulation (W107).

Work Package: W107 (Gate G7 Advanced Process Dynamics / Gate G4 Simulation)
Classification: PRODUCTION_READY

Covers:
1. Pure ST POU AST parsing and anti-ladder check (verify_spray_dryer_pure_st).
2. Droplet size distribution calculations (Rosin-Rammler and Sauter mean diameter d32).
3. Phase I constant rate evaporation (d^2 law).
4. Phase II falling rate crust formation and diffusion limitation.
5. Droplet kinematic vertical settling and drag velocity.
6. RK4 coupled 6-state ODE integration.
7. Alarm trips: inlet air over-temp (%M158), exhaust condensation sticky trip (%M159), filter dp trip (%M160).
8. Horner OCS register space synchronization (%R680..%R687, %M158..%M160).
9. Anti-ladder security guard rejection (LadderForbiddenError).
"""

from __future__ import annotations

import math
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.spray_dryer import (
    SPRAY_DRYER_PURE_ST_POU,
    SprayDryerConfig,
    SprayDryerDiagnosticCode,
    SprayDryerSimulationEngine,
    SprayDryerState,
    SprayDryerStatusBits,
    calculate_d_char_from_sauter_mean,
    calculate_sauter_mean_diameter,
    compute_drag_coefficient,
    compute_relative_humidity,
    compute_water_saturation_pressure,
    compute_water_vapor_pressure,
    compute_wet_bulb_temperature,
    rosin_rammler_cdf,
    rosin_rammler_pdf,
    run_spray_dryer_verification,
    verify_spray_dryer_pure_st,
)


# ============================================================================
# 1. Pure ST POU AST Parsing & Anti-Ladder Check
# ============================================================================

class TestSprayDryerPureST:
    """Tests for IEC 61131-3 Pure ST POU validation and anti-ladder security guard."""

    def test_verify_spray_dryer_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_spray_dryer_pure_st() is True

    def test_st_parser_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST name, PROGRAM type, and mapped Horner registers."""
        val = STParser.validate_code(SPRAY_DRYER_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(SPRAY_DRYER_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "SprayDryerSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R680", "%R681", "%R682", "%R683",
            "%R684", "%R685", "%R686", "%R687",
            "%M158", "%M159", "%M160",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_anti_ladder_security_guard_rejection(self) -> None:
        """Requirement 9: Verify ladder contacts, coils, and rungs trigger LadderForbiddenError."""
        ladder_snippets = [
            SPRAY_DRYER_PURE_ST_POU + "\n---[ ]---",
            SPRAY_DRYER_PURE_ST_POU + "\n---( )---",
            SPRAY_DRYER_PURE_ST_POU + "\nRUNG 1",
            SPRAY_DRYER_PURE_ST_POU + "\nNETWORK 1",
            SPRAY_DRYER_PURE_ST_POU + "\nOTE HeaterTripped",
            SPRAY_DRYER_PURE_ST_POU + "\nXIC InletAirOverTempTrip",
        ]
        for snippet in ladder_snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# 2. Droplet Size Distribution (Rosin-Rammler & Sauter Mean Diameter d32)
# ============================================================================

class TestDropletDistribution:
    """Tests for Rosin-Rammler distribution and Sauter mean diameter calculations."""

    def test_rosin_rammler_cdf_properties(self) -> None:
        """Requirement 2: Verify Rosin-Rammler CDF bounds, monotonicity, and characteristic scale."""
        d_char = 70.0e-6
        q = 2.5

        assert rosin_rammler_cdf(0.0, d_char, q) == 0.0
        assert rosin_rammler_cdf(-10.0e-6, d_char, q) == 0.0

        # At dp = d_char, F(d_char) = 1 - 1/e = 0.63212
        f_char = rosin_rammler_cdf(d_char, d_char, q)
        assert f_char == pytest.approx(1.0 - (1.0 / math.e), abs=1e-4)

        # Monotonicity check
        diameters = [15e-6, 30e-6, 50e-6, 70e-6, 100e-6, 150e-6]
        cdfs = [rosin_rammler_cdf(d, d_char, q) for d in diameters]
        for i in range(len(cdfs) - 1):
            assert cdfs[i] < cdfs[i + 1]

        # Convergence to 1.0 at large diameter
        assert rosin_rammler_cdf(500.0e-6, d_char, q) > 0.999

    def test_rosin_rammler_pdf_integral(self) -> None:
        """Requirement 2: Verify Rosin-Rammler PDF integrates numerically to unity."""
        d_char = 70.0e-6
        q = 2.5
        step = 1.0e-6
        bins = [i * step for i in range(1, 300)]
        integral = sum(rosin_rammler_pdf(dp, d_char, q) * step for dp in bins)
        assert integral == pytest.approx(1.0, abs=0.02)

    def test_sauter_mean_diameter_calculations(self) -> None:
        """Requirement 2: Verify Sauter mean diameter d32 analytical formula and roundtrip."""
        q = 2.5
        d_char = calculate_d_char_from_sauter_mean(65.0e-6, q)

        d32 = calculate_sauter_mean_diameter(d_char, q)
        assert d32 == pytest.approx(65.0e-6, abs=1e-6)

        # Invert d32 back to d_char
        d_char_rec = calculate_d_char_from_sauter_mean(d32, q)
        assert d_char_rec == pytest.approx(d_char, rel=1e-9)

        # Engine configured Sauter mean matches target
        engine = SprayDryerSimulationEngine()
        assert engine.compute_sauter_mean_diameter() * 1e6 == pytest.approx(65.0, abs=0.5)


# ============================================================================
# 3. Phase I Constant Rate Evaporation (d^2 Law)
# ============================================================================

class TestPhase1Evaporation:
    """Tests for Phase I constant-rate evaporation and classical d^2 law."""

    def test_phase1_d2_law_linear_shrinkage(self) -> None:
        """Requirement 3: Verify Phase I droplet diameter squared decreases linearly (d^2 law)."""
        sim = SprayDryerSimulationEngine()
        dp0_sq = sim.state.d_p ** 2

        sim.advance_time(duration_s=0.02, dt=0.005)
        dp1_sq = sim.state.d_p ** 2
        delta_sq1 = dp0_sq - dp1_sq

        sim.advance_time(duration_s=0.02, dt=0.005)
        dp2_sq = sim.state.d_p ** 2
        delta_sq2 = dp1_sq - dp2_sq

        # In Phase I: diameter shrinks
        assert dp2_sq < dp1_sq < dp0_sq
        assert delta_sq1 > 0.0
        assert delta_sq2 > 0.0

        # Under the d^2 law, delta_sq1 ~= delta_sq2 within tight tolerance
        assert abs(delta_sq1 - delta_sq2) / delta_sq1 < 0.05
        assert sim.state.evap_phase == 1

    def test_phase1_wet_bulb_buffering(self) -> None:
        """Requirement 3: Verify droplet temperature in Phase I is buffered near wet-bulb temperature."""
        sim = SprayDryerSimulationEngine()
        sim.advance_time(duration_s=0.05, dt=0.01)

        td_c = sim.state.t_d_c
        twb_c = sim.state.t_wb_c

        # Wet bulb temperature is typically 45 - 55 °C for 200 °C inlet air
        assert 35.0 <= twb_c <= 60.0
        assert 20.0 <= td_c <= 65.0
        # Moisture content drops from initial feed
        assert sim.state.x_d < sim.cfg.feed_moisture_dry_basis


# ============================================================================
# 4. Phase II Falling Rate Crust Formation & Diffusion Limitation
# ============================================================================

class TestPhase2CrustFormation:
    """Tests for Phase II crust formation, diameter locking, and diffusion limitation."""

    def test_phase2_crust_formation_locks_diameter(self) -> None:
        """Requirement 4: Verify crust formation locks droplet outer diameter once X_d < X_crit."""
        sim = SprayDryerSimulationEngine()
        # Advance until moisture falls below X_crit (0.15 kg/kg)
        sim.advance_time(duration_s=0.50, dt=0.01)

        assert sim.state.crust_formed is True
        assert sim.state.evap_phase == 2
        assert sim.state.x_d < sim.cfg.x_crit

        dp_crust = sim.state.d_p

        # Advance further into falling rate regime
        sim.advance_time(duration_s=0.30, dt=0.01)

        # Diameter must remain constant (rigid porous crust)
        assert sim.state.d_p == pytest.approx(dp_crust, abs=1e-12)

    def test_phase2_particle_heating_towards_exhaust(self) -> None:
        """Requirement 4: Verify particle core warms up once falling rate diffusion limits cooling."""
        sim = SprayDryerSimulationEngine()
        # In Phase I
        sim.advance_time(duration_s=0.05, dt=0.01)
        td_phase1 = sim.state.t_d_c

        # In Phase II
        sim.advance_time(duration_s=0.75, dt=0.01)
        td_phase2 = sim.state.t_d_c

        # In Phase II, reduced evaporation causes droplet to warm up towards gas temperature
        assert td_phase2 > td_phase1 + 30.0
        assert td_phase2 > 65.0


# ============================================================================
# 5. Droplet Kinematics & Vertical Settling
# ============================================================================

class TestDropletKinematics:
    """Tests for Schiller-Naumann drag coefficient, 1D vertical motion, and settling velocity."""

    def test_schiller_naumann_drag_regimes(self) -> None:
        """Requirement 5: Verify drag coefficient in Stokes, intermediate, and Newton regimes."""
        # Stokes regime Re < 0.1
        cd_stokes = compute_drag_coefficient(0.01)
        assert cd_stokes == pytest.approx(24.0 / 0.01, rel=0.05)

        # Intermediate regime 0.1 <= Re < 1000
        cd_inter = compute_drag_coefficient(10.0)
        assert 1.0 < cd_inter < 10.0

        # Newton plateau Re >= 1000
        cd_newton = compute_drag_coefficient(2000.0)
        assert cd_newton == 0.44

    def test_vertical_settling_trajectory(self) -> None:
        """Requirement 5: Verify vertical position and velocity kinematics down the drying tower."""
        sim = SprayDryerSimulationEngine()
        sim.advance_time(duration_s=1.0, dt=0.01)

        # z must increase downwards
        assert 0.5 < sim.state.z < sim.cfg.tower_height_m
        # v_z must be positive (downward settling)
        assert 0.5 < sim.state.v_z < 2.5


# ============================================================================
# 6. Coupled 6-State ODE RK4 Solver Integration
# ============================================================================

class TestCoupledODEIntegration:
    """Tests for 4th-order Runge-Kutta numerical integration of 6-state coupled ODE system."""

    def test_rk4_coupled_6state_ode_solution(self) -> None:
        """Requirement 6: Verify 6-state ODE [dp, X_d, T_d, z, v_z, Y_g] integration stability."""
        sim = SprayDryerSimulationEngine()
        res = sim.advance_time(duration_s=1.5, dt=0.01)

        assert res.status == AgentStatus.SUCCESS
        st = sim.state

        # All 6 dynamic states finite and bounded
        assert st.d_p > 0.0
        assert not math.isnan(st.d_p)
        assert st.x_d >= sim.cfg.x_eq
        assert not math.isnan(st.x_d)
        assert st.t_d > 273.15
        assert not math.isnan(st.t_d)
        assert st.z > 0.0
        assert not math.isnan(st.z)
        assert st.v_z > 0.0
        assert not math.isnan(st.v_z)
        assert st.y_g > sim.cfg.inlet_air_humidity
        assert not math.isnan(st.y_g)

    def test_gas_phase_psychrometric_cooling(self) -> None:
        """Requirement 6: Verify gas phase temperature drops due to evaporative latent heat absorption."""
        sim = SprayDryerSimulationEngine()
        sim.advance_time(duration_s=1.5, dt=0.01)

        # Gas temperature should decrease from inlet 200 °C
        assert 50.0 < sim.state.t_g_c < sim.cfg.inlet_air_temp_c
        # Humidity should increase
        assert sim.state.y_g > sim.cfg.inlet_air_humidity
        # Evaporation rate should be positive
        assert sim.state.evaporation_rate_kg_h > 10.0


# ============================================================================
# 7. Alarm Trips & Safety Interlocks
# ============================================================================

class TestAlarmTrips:
    """Tests for inlet air over-temp, exhaust condensation, and baghouse DP alarm trips."""

    def test_inlet_air_overtemp_trip(self) -> None:
        """Requirement 7: Verify inlet air over-temp trip (%M158, 0x8401) on T_inlet >= 220 °C."""
        sim = SprayDryerSimulationEngine()
        assert sim.reg_table.read_bit("%M158") is False

        # Inject high inlet air temperature fault (225 °C >= 220 °C)
        sim.trigger_inlet_overtemp(225.0)

        assert sim.state.inlet_temp_trip is True
        assert sim.reg_table.read_bit("%M158") is True
        assert sim.reg_table.read_uword("%R687") == SprayDryerDiagnosticCode.ERR_INLET_AIR_OVERTEMP
        assert bool(sim.reg_table.read_word("%R680") & SprayDryerStatusBits.HIGH_INLET_TEMP_ALARM)

        # Reset to normal
        sim.trigger_inlet_overtemp(200.0)
        assert sim.state.inlet_temp_trip is False
        assert sim.reg_table.read_bit("%M158") is False

    def test_exhaust_condensation_sticky_trip(self) -> None:
        """Requirement 7: Verify exhaust condensation sticky trip (%M159, 0x8402) on RH >= 65.0%."""
        sim = SprayDryerSimulationEngine()
        assert sim.reg_table.read_bit("%M159") is False

        # Inject condensation fault
        sim.trigger_exhaust_condensation(temp_c=48.0, forced_humidity=0.065)

        assert sim.state.condensation_trip is True
        assert sim.reg_table.read_bit("%M159") is True
        assert sim.reg_table.read_uword("%R687") == SprayDryerDiagnosticCode.ERR_EXHAUST_CONDENSATION
        assert bool(sim.reg_table.read_word("%R680") & SprayDryerStatusBits.CONDENSATION_STICKY_TRIP)

    def test_baghouse_filter_dp_trip(self) -> None:
        """Requirement 7: Verify baghouse filter high DP trip (%M160, 0x8403) on Delta_P >= 2.50 kPa."""
        sim = SprayDryerSimulationEngine()
        assert sim.reg_table.read_bit("%M160") is False

        # Inject filter clogging fault
        sim.trigger_filter_clog(dp_kpa=2.80)

        assert sim.state.filter_dp_trip is True
        assert sim.reg_table.read_bit("%M160") is True
        assert sim.reg_table.read_uword("%R687") == SprayDryerDiagnosticCode.ERR_BAGHOUSE_FILTER_DP
        assert bool(sim.reg_table.read_word("%R680") & SprayDryerStatusBits.FILTER_DP_TRIP)


# ============================================================================
# 8. Horner OCS Register Space Synchronization
# ============================================================================

class TestHornerOCSSync:
    """Tests for Horner APG OCS register table synchronization (%R680..%R687, %M158..%M160)."""

    def test_register_space_synchronization(self) -> None:
        """Requirement 8: Verify %R680..%R687 analog registers and %M158..%M160 discrete coils."""
        sim = SprayDryerSimulationEngine()
        sim.advance_time(duration_s=0.5, dt=0.01)

        r680 = sim.reg_table.read_uword("%R680")
        r681 = sim.reg_table.read_word("%R681")
        r682 = sim.reg_table.read_word("%R682")
        r683 = sim.reg_table.read_word("%R683")
        r684 = sim.reg_table.read_word("%R684")
        r685 = sim.reg_table.read_word("%R685")
        r686 = sim.reg_table.read_word("%R686")
        r687 = sim.reg_table.read_uword("%R687")

        # %R680: Status Word
        assert (r680 & int(SprayDryerStatusBits.RUNNING)) != 0
        assert (r680 & int(SprayDryerStatusBits.ATOMIZER_ACTIVE)) != 0

        # %R681: Droplet mean diameter scaled x10 um
        assert 100 <= r681 <= 1500

        # %R682: Droplet moisture scaled x10 wt%
        assert r682 > 0

        # %R683: Exhaust air temperature scaled x10 °C
        assert 500 <= r683 <= 2200

        # %R684: Exhaust RH scaled x10 %RH
        assert 0 <= r684 <= 1000

        # %R685: Evaporation rate scaled x10 kg/h
        assert r685 >= 0

        # %R686: Powder production rate scaled x10 kg/h
        assert r686 > 0

        # %R687: Diagnostic code (0x0000 = OK)
        assert r687 == SprayDryerDiagnosticCode.OK

        # Discrete coils normal state
        assert sim.reg_table.read_bit("%M158") is False
        assert sim.reg_table.read_bit("%M159") is False
        assert sim.reg_table.read_bit("%M160") is False


# ============================================================================
# 9. Verification Runner Suite
# ============================================================================

class TestVerificationRunner:
    """Tests for the deterministic 9-stage verification runner function."""

    def test_run_spray_dryer_verification(self, tmp_path: Path) -> None:
        """Verify run_spray_dryer_verification executes 9/9 stages and writes evidence artifact."""
        evidence_file = tmp_path / "spray_dryer_evidence.json"
        res = run_spray_dryer_verification(str(evidence_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert evidence_file.exists()
