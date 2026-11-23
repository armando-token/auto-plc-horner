"""Unit and Integration Tests for Anaerobic Digester & Biogas Methanogenesis ODE Simulation.

Work Package: W122 (Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Pure IEC 61131-3 ST POU AST parsing, symbol binding, and STParser validation (%R830..%R837, %M193..%M195).
2. Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, and rungs.
3. Monod and Andrews kinetic rate equations and VFA inhibition behavior.
4. Mesophilic temperature sensitivity and Henry's law gas-liquid partition.
5. Coupled 6-state ODE RK4 integration stability and COD/carbon mass conservation.
6. Process safety trips (sour digester 0x9301, overpressure 0x9302, auto-flare %M195, washout alarm 0x9303).
7. Horner OCS register space synchronization (%R830..%R837, %M193..%M195).
8. End-to-end 9-stage verification suite integration test writing evidence JSON.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.anaerobic_digester import (
    AD_PURE_ST_POU,
    ADConfig,
    ADDiagnosticCode,
    ADSimulator,
    ADState,
    ADStatusBits,
    ANAEROBIC_DIGESTER_PURE_ST_POU,
    AnaerobicDigesterConfig,
    AnaerobicDigesterDiagnosticCode,
    AnaerobicDigesterEngine,
    AnaerobicDigesterModel,
    AnaerobicDigesterSimulator,
    AnaerobicDigesterState,
    AnaerobicDigesterStatusBits,
    DIGESTER_PURE_ST_POU,
    DigesterConfig,
    DigesterDiagnosticCode,
    DigesterSimulator,
    DigesterState,
    DigesterStatusBits,
    run_anaerobic_digester_verification,
    verify_anaerobic_digester_pure_st,
)


# ============================================================================
# 1. Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestAnaerobicDigesterPureST:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings."""

    def test_verify_anaerobic_digester_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_anaerobic_digester_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers."""
        SecurityGuard.assert_pure_st_content(ANAEROBIC_DIGESTER_PURE_ST_POU)
        val = STParser.validate_code(ANAEROBIC_DIGESTER_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(ANAEROBIC_DIGESTER_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "AnaerobicDigesterSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R830", "%R831", "%R832", "%R833",
            "%R834", "%R835", "%R836", "%R837",
            "%M193", "%M194", "%M195",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_pure_st_pou_alias_equivalence(self) -> None:
        """Requirement 1: Verify POU aliases are identical and parse equivalently."""
        assert DIGESTER_PURE_ST_POU == ANAEROBIC_DIGESTER_PURE_ST_POU
        assert AD_PURE_ST_POU == ANAEROBIC_DIGESTER_PURE_ST_POU

        ast_alias = STParser.parse_pou(DIGESTER_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "AnaerobicDigesterSync"

    def test_pure_st_pou_internal_variables_and_control_logic(self) -> None:
        """Requirement 1: Verify internal boolean variables and interlock IF-branches."""
        ast = STParser.parse_pou(ANAEROBIC_DIGESTER_PURE_ST_POU)
        assert ast is not None
        var_names = [v.name for v in ast.variables]
        assert "FeedPumpInhibitCmd" in var_names
        assert "EmergencyPressureReliefCmd" in var_names
        assert "FlareIgnitionActive" in var_names
        assert "AcidificationTrip" in var_names
        assert "BiogasOverpressureTrip" in var_names
        assert "AutoFlareCmd" in var_names


# ============================================================================
# 2. Anti-Ladder Security Guard Rejection
# ============================================================================

class TestAntiLadderSecurityGuard:
    """Tests for SecurityGuard fail-closed rejection of ladder logic constructs."""

    @pytest.mark.parametrize(
        "ladder_snippet",
        [
            "---[ ]---",
            "---[/]---",
            "---( )---",
            "---(S)---",
            "---(R)---",
            "RUNG 1",
            "END_RUNG",
            "NETWORK 1",
            "XIC FeedPumpRunning",
            "XIO SourDigesterTrip",
            "OTE AutoFlareCmd",
            "OTL AcidificationAlarm",
            "OTU OverpressureRelief",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: Verify all ladder constructs raise LadderForbiddenError."""
        bad_code = f"{ANAEROBIC_DIGESTER_PURE_ST_POU}\n{ladder_snippet}\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

        val = STParser.validate_code(bad_code)
        assert val.status == AgentStatus.FAILED
        assert val.error_code == "ERR_LADDER_FORBIDDEN"
        assert val.data.get("ladder_rejected") is True


# ============================================================================
# 3. Monod and Andrews Kinetic Rate Equations & VFA Inhibition Behavior
# ============================================================================

class TestBiologicalReactionKinetics:
    """Tests for Monod substrate uptake kinetics, Andrews VFA inhibition, and pH buffering."""

    def test_monod_substrate_uptake_monotonicity_and_saturation(self) -> None:
        """Requirement 3: Verify Monod rate equation increases monotonically and saturates."""
        sim = AnaerobicDigesterSimulator()

        # Zero substrate produces zero rate
        r_0 = sim.compute_monod_substrate_uptake(s_su_g_m3=0.0)
        assert r_0 == 0.0

        # Monotonic uptake rates across concentration span
        r_100 = sim.compute_monod_substrate_uptake(s_su_g_m3=100.0)
        r_500 = sim.compute_monod_substrate_uptake(s_su_g_m3=500.0)
        r_2000 = sim.compute_monod_substrate_uptake(s_su_g_m3=2000.0)
        r_20000 = sim.compute_monod_substrate_uptake(s_su_g_m3=20000.0)

        assert 0.0 < r_100 < r_500 < r_2000 < r_20000

        # At S = K_s (500 g COD/m3), rate should be exactly half of maximum capacity
        r_max_theoretical = sim.config.k_m_su * sim.config.x_su_eff
        assert r_500 == pytest.approx(0.5 * r_max_theoretical, rel=1e-3)

        # Asymptotic approach toward theoretical maximum
        assert r_20000 == pytest.approx(r_max_theoretical, rel=0.05)

    def test_andrews_vfa_inhibition_peak_and_sour_drop(self) -> None:
        """Requirement 3: Verify Andrews inhibition bell-curve behavior with peak at S* = sqrt(K_s * K_i)."""
        sim = AnaerobicDigesterSimulator()

        # Analytical optimum for Andrews equation: S* = sqrt(K_s * K_i)
        k_s = sim.config.k_s_vfa    # 150.0 mg/L
        k_i = sim.config.k_i_vfa    # 3500.0 mg/L
        s_opt = math.sqrt(k_s * k_i)  # ~724.57 mg/L

        mu_low, _, _, _ = sim.compute_andrews_methanogen_rate(s_vfa_g_m3=150.0)
        mu_peak, _, _, _ = sim.compute_andrews_methanogen_rate(s_vfa_g_m3=s_opt)
        mu_mid, _, _, _ = sim.compute_andrews_methanogen_rate(s_vfa_g_m3=2000.0)
        mu_inhibited, ph_sour, _, i_ph_sour = sim.compute_andrews_methanogen_rate(s_vfa_g_m3=4500.0)

        # Growth rate at peak must exceed low VFA and high VFA rates
        assert mu_peak > mu_low > 0.0
        assert mu_peak > mu_mid > mu_inhibited

        # At sour digester threshold (4500 mg/L VFA), severe inhibition occurs
        assert mu_inhibited < 0.5 * mu_peak
        assert ph_sour < 6.50
        assert i_ph_sour < 0.50

    def test_ph_buffer_calculation_and_inhibition_curve(self) -> None:
        """Requirement 3: Verify pH buffer calculation and sigmoidal methanogen inhibition."""
        sim = AnaerobicDigesterSimulator()

        # At zero VFA, pH is baseline
        assert sim.compute_ph(0.0) == pytest.approx(sim.config.ph_base, abs=1e-3)

        # Nominal VFA (350 mg/L) maintains healthy buffered neutral pH (~7.18)
        ph_nom = sim.compute_ph(350.0)
        assert 7.0 <= ph_nom <= 7.3

        # At 4000 mg/L VFA, pH drops below critical 6.50
        ph_acid = sim.compute_ph(4000.0)
        assert ph_acid < 6.50

        # pH inhibition curve characteristics
        i_ph_72 = sim.compute_ph_inhibition(7.20)
        i_ph_65 = sim.compute_ph_inhibition(6.50)
        i_ph_60 = sim.compute_ph_inhibition(6.00)

        assert i_ph_72 > 0.95
        assert i_ph_65 == pytest.approx(0.50, rel=1e-2)
        assert i_ph_60 < 0.05
        assert i_ph_72 > i_ph_65 > i_ph_60 > 0.0


# ============================================================================
# 4. Mesophilic Temperature Sensitivity & Henry's Law Gas-Liquid Partition
# ============================================================================

class TestTemperatureAndHenrysLawPartition:
    """Tests for mesophilic temperature sensitivity and Henry's law two-film gas transfer."""

    def test_mesophilic_cardinal_temperature_curve(self) -> None:
        """Requirement 4: Verify temperature correction factor f(T) peak at 37 °C and mesophilic span."""
        sim = AnaerobicDigesterSimulator()

        # Optimum at 37 °C
        f_opt = sim.compute_temperature_factor(37.0)
        assert f_opt == pytest.approx(1.0, abs=1e-5)

        # Active mesophilic band (35 - 38 °C) retains >= 70% kinetic capacity
        f_35 = sim.compute_temperature_factor(35.0)
        f_38 = sim.compute_temperature_factor(38.0)
        assert f_35 >= 0.70
        assert f_38 >= 0.70

        # Outside mesophilic envelope activity collapses
        f_cold = sim.compute_temperature_factor(20.0)
        f_hot = sim.compute_temperature_factor(50.0)
        assert f_cold < 0.01
        assert f_hot < 0.01

        # Extreme bounds cutoff
        assert sim.compute_temperature_factor(10.0) == 0.0
        assert sim.compute_temperature_factor(55.0) == 0.0

    def test_henrys_law_gas_liquid_mass_transfer_driving_force(self) -> None:
        """Requirement 4: Verify Henry's law two-film mass transfer rates and biogas composition."""
        sim = AnaerobicDigesterSimulator()

        # Under elevated dissolved gas levels, transfer rates into headspace are positive
        r_t_ch4, r_t_co2, n_ch4, n_co2, y_ch4, y_co2 = sim.compute_henry_mass_transfer(
            s_ch4_g_m3=20.0, s_co2_g_m3=300.0, p_gas_mbar=25.0
        )
        assert r_t_ch4 > 0.0
        assert r_t_co2 > 0.0
        assert n_ch4 > 0.0
        assert n_co2 > 0.0
        assert 0.50 <= y_ch4 <= 0.80
        assert y_ch4 + y_co2 == pytest.approx(1.0, rel=1e-5)

        # Under sub-saturation levels, transfer rates clamp to zero (no reverse stripping)
        r_t_ch4_zero, _, _, _, _, _ = sim.compute_henry_mass_transfer(
            s_ch4_g_m3=1.0, s_co2_g_m3=300.0, p_gas_mbar=25.0
        )
        assert r_t_ch4_zero == 0.0

    def test_gas_draw_off_and_relief_conductances(self) -> None:
        """Requirement 4: Verify offgas regulator, emergency auto-flare, and high-pressure relief conductances."""
        sim = AnaerobicDigesterSimulator()

        # Below 20 mbar setpoint: no gas draw-off
        n_sub, flare_sub, relief_sub = sim.compute_gas_draw_off(p_gas_mbar=15.0)
        assert n_sub == 0.0
        assert flare_sub == 0.0
        assert relief_sub == 0.0

        # Normal operating pressure (25 mbar): process utilization draw active, flare and relief zero
        n_nom, flare_nom, relief_nom = sim.compute_gas_draw_off(p_gas_mbar=25.0)
        expected_util = sim.config.k_valve * (25.0 - sim.config.p_setpoint_mbar)
        assert n_nom == pytest.approx(expected_util, rel=1e-5)
        assert flare_nom == 0.0
        assert relief_nom == 0.0

        # Auto-flare active (40 mbar > 35 mbar): flare conductance engaged
        n_flare, flare_active, relief_active = sim.compute_gas_draw_off(p_gas_mbar=40.0)
        expected_flare = sim.config.k_flare * (40.0 - sim.config.p_flare_mbar)
        assert flare_active == pytest.approx(expected_flare, rel=1e-5)
        assert flare_active > 0.0
        assert relief_active == 0.0
        assert n_flare > n_nom

        # Overpressure relief active (55 mbar > 50 mbar): safety relief engaged
        n_trip, flare_trip, relief_trip = sim.compute_gas_draw_off(p_gas_mbar=55.0)
        expected_relief = sim.config.k_relief * (55.0 - sim.config.p_trip_mbar)
        assert relief_trip == pytest.approx(expected_relief, rel=1e-5)
        assert relief_trip > 0.0
        assert flare_trip > 0.0


# ============================================================================
# 5. Coupled 6-State ODE RK4 Integration Stability & COD/Carbon Mass Conservation
# ============================================================================

class TestCoupled6StateODEIntegration:
    """Tests for coupled 6-state RK4 solver numerical stability and stoichiometric carbon balance."""

    def test_coupled_6state_rk4_solution_stability(self) -> None:
        """Requirement 5: Verify all 6 states remain bounded, positive, and physically realistic."""
        sim = AnaerobicDigesterSimulator()
        res = sim.advance_time(duration_s=2.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        st = sim.state

        # Check bounds of all 6 states
        assert 0.0 < st.s_su_g_m3 < sim.config.s_su_in_g_m3
        assert 0.0 < st.s_vfa_g_m3 < 5000.0
        assert 0.0 < st.x_ac_g_m3 < 5000.0
        assert 0.0 < st.s_co2_g_m3 < 1000.0
        assert 0.0 < st.s_ch4_g_m3 < 100.0
        assert 0.0 < st.p_gas_mbar < 100.0
        assert 6.0 <= st.ph <= 8.0

    def test_analytical_carbon_mass_conservation_residual(self) -> None:
        """Requirement 5: Verify analytical stoichiometric carbon mass conservation residual < 1e-10 g C/s."""
        sim = AnaerobicDigesterSimulator()
        sim.advance_time(duration_s=1.0, dt=0.05)

        residual = sim.state.mass_balance_residual_g_s
        assert residual < 1e-10, f"Carbon conservation residual {residual:.3e} exceeds 1e-10 g C/s"

    def test_ode_derivatives_deterministic_and_finite(self) -> None:
        """Requirement 5: Verify time derivatives dy/dt are finite and non-NaN across all 6 states."""
        sim = AnaerobicDigesterSimulator()
        y_test = [1200.0, 350.0, 1800.0, 250.0, 15.0, 24.5]
        dy = sim.ode_derivatives(0.0, y_test)

        assert len(dy) == 6
        for i, val in enumerate(dy):
            assert not math.isnan(val), f"Derivative dy[{i}] is NaN"
            assert not math.isinf(val), f"Derivative dy[{i}] is Inf"

    def test_invalid_timestep_fail_closed(self) -> None:
        """Requirement 5: Verify non-positive duration or timestep fails closed."""
        sim = AnaerobicDigesterSimulator()

        res_zero = sim.advance_time(duration_s=0.0)
        assert res_zero.status == AgentStatus.FAILED
        assert res_zero.error_code == "INVALID_TIMESTEP"

        res_neg = sim.advance_time(duration_s=1.0, dt=-0.05)
        assert res_neg.status == AgentStatus.FAILED
        assert res_neg.error_code == "INVALID_TIMESTEP"

    def test_feed_pump_off_dilution_halt(self) -> None:
        """Requirement 5: Verify feed pump off halts dilution while maintaining carbon balance."""
        sim = AnaerobicDigesterSimulator()
        sim.state.feed_pump_on = False

        res = sim.advance_time(duration_s=1.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert sim.state.carbon_in_g_s == 0.0
        assert sim.state.mass_balance_residual_g_s < 1e-10


# ============================================================================
# 6. Process Safety Trips & Diagnostics
# ============================================================================

class TestProcessSafetyTrips:
    """Tests for %M193 (0x9301), %M194 (0x9302), %M195 flare, and washout alarm (0x9303)."""

    def test_sour_digester_acidification_trip_by_vfa(self) -> None:
        """Requirement 6: Verify sour digester acidification trip (%M193, 0x9301) triggered by VFA > 4000 mg/L."""
        reg_table = RegisterTable()
        sim = AnaerobicDigesterSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M193") is False

        # Incur high VFA acidification trip
        sim.state.s_vfa_g_m3 = 4500.0
        sim.state.ph = sim.compute_ph(4500.0)
        sim._sync_registers()

        assert sim.state.acidification_trip is True
        assert reg_table.read_bit("%M193") is True
        assert (reg_table.read_word("%R837") & 0xFFFF) == int(AnaerobicDigesterDiagnosticCode.SOUR_DIGESTER_ACIDIFICATION_TRIP)
        assert bool(reg_table.read_word("%R830") & int(AnaerobicDigesterStatusBits.SOUR_DIGESTER_TRIP)) is True
        assert sim.state.methanogenesis_healthy is False

    def test_sour_digester_acidification_trip_by_low_ph(self) -> None:
        """Requirement 6: Verify acidification trip (%M193, 0x9301) triggered by pH < 6.50."""
        reg_table = RegisterTable()
        sim = AnaerobicDigesterSimulator(register_table=reg_table)

        # Incur low pH trip with moderate VFA
        sim.state.s_vfa_g_m3 = 3000.0
        sim.state.ph = 6.40
        sim._sync_registers()

        assert sim.state.acidification_trip is True
        assert reg_table.read_bit("%M193") is True
        assert (reg_table.read_word("%R837") & 0xFFFF) == int(AnaerobicDigesterDiagnosticCode.SOUR_DIGESTER_ACIDIFICATION_TRIP)

    def test_biogas_overpressure_trip_and_code(self) -> None:
        """Requirement 6: Verify biogas overpressure trip (%M194, 0x9302) triggered by P_gas > 50.0 mbar."""
        reg_table = RegisterTable()
        sim = AnaerobicDigesterSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M194") is False

        # Incur overpressure trip: 55.0 mbar > 50.0 mbar threshold
        sim.state.p_gas_mbar = 55.0
        sim._sync_registers()

        assert sim.state.overpressure_trip is True
        assert reg_table.read_bit("%M194") is True
        assert (reg_table.read_word("%R837") & 0xFFFF) == int(AnaerobicDigesterDiagnosticCode.BIOGAS_OVERPRESSURE_TRIP)
        assert bool(reg_table.read_word("%R830") & int(AnaerobicDigesterStatusBits.OVERPRESSURE_TRIP)) is True

    def test_auto_flare_command_interlock(self) -> None:
        """Requirement 6: Verify auto-flare command (%M195) active above 35.0 mbar without overpressure trip."""
        reg_table = RegisterTable()
        sim = AnaerobicDigesterSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M195") is False

        # Intermediate pressure: 38.0 mbar (> 35.0 flare trigger, < 50.0 trip)
        sim.state.p_gas_mbar = 38.0
        sim._sync_registers()

        assert sim.state.auto_flare_cmd is True
        assert reg_table.read_bit("%M195") is True
        assert sim.state.overpressure_trip is False
        assert reg_table.read_bit("%M194") is False
        assert bool(reg_table.read_word("%R830") & int(AnaerobicDigesterStatusBits.FLARE_ACTIVE)) is True

    def test_biomass_washout_alarm_and_code(self) -> None:
        """Requirement 6: Verify biomass washout alarm (0x9303) when methanogen biomass < 250 g COD/m3."""
        reg_table = RegisterTable()
        sim = AnaerobicDigesterSimulator(register_table=reg_table)

        # Washout condition
        sim.state.x_ac_g_m3 = 180.0
        sim._sync_registers()

        assert sim.state.biomass_washout_alarm is True
        assert (reg_table.read_word("%R837") & 0xFFFF) == int(AnaerobicDigesterDiagnosticCode.BIOMASS_WASHOUT_ALARM)
        assert bool(reg_table.read_word("%R830") & int(AnaerobicDigesterStatusBits.WASHOUT_ALARM)) is True

    def test_diagnostic_code_priority_hierarchy(self) -> None:
        """Requirement 6: Verify diagnostic event code priority: Overpressure (0x9302) > Sour (0x9301) > Washout (0x9303)."""
        reg_table = RegisterTable()
        sim = AnaerobicDigesterSimulator(register_table=reg_table)

        # Trigger all 3 fault conditions simultaneously
        sim.state.p_gas_mbar = 55.0       # Overpressure (0x9302)
        sim.state.s_vfa_g_m3 = 4500.0     # Acidification (0x9301)
        sim.state.ph = 6.40
        sim.state.x_ac_g_m3 = 150.0       # Washout (0x9303)
        sim._sync_registers()

        # Highest priority: Overpressure (0x9302)
        assert (reg_table.read_word("%R837") & 0xFFFF) == int(AnaerobicDigesterDiagnosticCode.BIOGAS_OVERPRESSURE_TRIP)

        # Clear overpressure -> Acidification (0x9301) takes precedence
        sim.state.p_gas_mbar = 25.0
        sim._sync_registers()
        assert (reg_table.read_word("%R837") & 0xFFFF) == int(AnaerobicDigesterDiagnosticCode.SOUR_DIGESTER_ACIDIFICATION_TRIP)

        # Clear acidification -> Washout (0x9303) takes precedence
        sim.state.s_vfa_g_m3 = 350.0
        sim.state.ph = 7.18
        sim._sync_registers()
        assert (reg_table.read_word("%R837") & 0xFFFF) == int(AnaerobicDigesterDiagnosticCode.BIOMASS_WASHOUT_ALARM)

        # Clear washout -> Normal OK (0x0000)
        sim.state.x_ac_g_m3 = 1800.0
        sim._sync_registers()
        assert (reg_table.read_word("%R837") & 0xFFFF) == int(AnaerobicDigesterDiagnosticCode.OK)


# ============================================================================
# 7. Horner OCS Register Space Synchronization
# ============================================================================

class TestHornerOCSSync:
    """Tests for Horner APG OCS register space mapping (%R830..%R837, %M193..%M195)."""

    def test_register_space_synchronization_nominal(self) -> None:
        """Requirement 7: Verify %R830..%R837 analog registers and %M193..%M195 discrete coils."""
        reg_table = RegisterTable()
        sim = AnaerobicDigesterSimulator(register_table=reg_table)
        sim.advance_time(duration_s=0.5, dt=0.05)

        r830 = reg_table.read_uword("%R830")
        r831 = reg_table.read_word("%R831")
        r832 = reg_table.read_word("%R832")
        r833 = reg_table.read_word("%R833")
        r834 = reg_table.read_word("%R834")
        r835 = reg_table.read_word("%R835")
        r836 = reg_table.read_word("%R836")
        r837 = reg_table.read_uword("%R837")

        # %R830 Status Word
        assert (r830 & int(AnaerobicDigesterStatusBits.RUNNING)) != 0
        assert (r830 & int(AnaerobicDigesterStatusBits.FEED_PUMP_ON)) != 0
        assert (r830 & int(AnaerobicDigesterStatusBits.HEATING_ACTIVE)) != 0
        assert (r830 & int(AnaerobicDigesterStatusBits.METHANOGENESIS_HEALTHY)) != 0
        assert (r830 & int(AnaerobicDigesterStatusBits.SOUR_DIGESTER_TRIP)) == 0
        assert (r830 & int(AnaerobicDigesterStatusBits.OVERPRESSURE_TRIP)) == 0

        # %R831: Substrate COD mg/L (> 0)
        assert r831 > 0

        # %R832: VFA concentration mg/L (> 0)
        assert r832 > 0

        # %R833: Biomass concentration mg/L (> 0)
        assert r833 > 0

        # %R834: Biogas pressure scaled x10 mbar (> 0)
        assert r834 > 0

        # %R835: Methane percentage scaled x10 % (500 to 800 for 50.0% to 80.0%)
        assert 500 <= r835 <= 800

        # %R836: Digester pH scaled x100 (650 to 800 for 6.50 to 8.00)
        assert 650 <= r836 <= 800

        # %R837: Diagnostic event code OK (0x0000)
        assert r837 == int(AnaerobicDigesterDiagnosticCode.OK)

        # Discrete Coils normal
        assert reg_table.read_bit("%M193") is False
        assert reg_table.read_bit("%M194") is False
        assert reg_table.read_bit("%M195") is False

    def test_register_exact_scaling_precision(self) -> None:
        """Requirement 7: Verify exact scaled analog register mapping."""
        reg_table = RegisterTable()
        sim = AnaerobicDigesterSimulator(register_table=reg_table)

        sim.state.s_su_g_m3 = 1520.0
        sim.state.s_vfa_g_m3 = 412.0
        sim.state.x_ac_g_m3 = 1945.0
        sim.state.p_gas_mbar = 28.4
        sim.state.biogas_ch4_pct = 66.8
        sim.state.ph = 7.15
        sim._sync_registers()

        assert reg_table.read_word("%R831") == 1520
        assert reg_table.read_word("%R832") == 412
        assert reg_table.read_word("%R833") == 1945
        assert reg_table.read_word("%R834") == 284
        assert reg_table.read_word("%R835") == 668
        assert reg_table.read_word("%R836") == 715

    def test_compatibility_class_aliases(self) -> None:
        """Requirement 7: Verify model, engine, config, and state aliases instantiate consistently."""
        sim1 = DigesterSimulator()
        sim2 = ADSimulator()
        sim3 = AnaerobicDigesterEngine()
        sim4 = AnaerobicDigesterModel()

        assert isinstance(sim1, AnaerobicDigesterSimulator)
        assert isinstance(sim2, AnaerobicDigesterSimulator)
        assert isinstance(sim3, AnaerobicDigesterSimulator)
        assert isinstance(sim4, AnaerobicDigesterSimulator)

        cfg = ADConfig()
        assert isinstance(cfg, AnaerobicDigesterConfig)
        st = ADState()
        assert isinstance(st, AnaerobicDigesterState)


# ============================================================================
# 8. End-to-End 9-Stage Verification Suite Integration Test
# ============================================================================

class TestAnaerobicDigesterVerificationRunner:
    """Tests for the deterministic 9-stage verification runner function."""

    def test_run_anaerobic_digester_verification_9_stages(self, tmp_path: Path) -> None:
        """Requirement 8: Verify run_anaerobic_digester_verification executes all 9 stages cleanly."""
        evidence_file = tmp_path / "anaerobic_digester_evidence.json"
        res = run_anaerobic_digester_verification(str(evidence_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert res["data"]["work_package"] == "W122"
        assert evidence_file.exists()

        # Check evidence file JSON structure
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert len(data["data"]["tests"]) == 9
        for t in data["data"]["tests"]:
            assert t["passed"] is True
            assert "stage" in t
            assert "check" in t
            assert "details" in t
