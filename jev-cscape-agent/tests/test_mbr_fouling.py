"""Unit and Integration Tests for Industrial Membrane Bioreactor (MBR) Fouling Dynamics ODE Simulation.

Work Package: W125 (Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R860..%R867, %M200..%M202).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs.
3. Section 3: Darcy's law flux calculations, viscosity temperature scaling, and resistance aggregation.
4. Section 4: Dynamic cake deposition vs. aeration scour shear detachment balance.
5. Section 5: Coupled ODE RK4 integration stability and flux/mass balance conservation.
6. Section 6: Process safety trips (high TMP 0x9601, critical fouling 0x9602, aeration loss 0x9603, backwash %M202).
7. Section 7: Horner OCS register space synchronization (%R860..%R867, %M200..%M202).
8. Section 8: 9-stage verification suite integration test writing evidence JSON.
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
from jev_cscape.simulation.mbr_fouling import (
    MBR_FOULING_PURE_ST_POU,
    MBR_PURE_ST_POU,
    MbrConfig,
    MbrDiagnosticCode,
    MbrFoulingConfig,
    MbrFoulingDiagnosticCode,
    MbrFoulingEngine,
    MbrFoulingModel,
    MbrFoulingSimulator,
    MbrFoulingState,
    MbrFoulingStatusBits,
    MbrSimulator,
    MbrState,
    MbrStatusBits,
    run_mbr_fouling_verification,
    verify_mbr_fouling_pure_st,
)


# ============================================================================
# 1. Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestMbrFoulingPureST:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings."""

    def test_verify_mbr_fouling_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_mbr_fouling_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers."""
        SecurityGuard.assert_pure_st_content(MBR_FOULING_PURE_ST_POU)
        val = STParser.validate_code(MBR_FOULING_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(MBR_FOULING_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "MbrFoulingDynamicsSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R860", "%R861", "%R862", "%R863",
            "%R864", "%R865", "%R866", "%R867",
            "%M200", "%M201", "%M202",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_pure_st_pou_alias_equivalence(self) -> None:
        """Requirement 1: Verify POU aliases are identical and parse equivalently."""
        assert MBR_PURE_ST_POU == MBR_FOULING_PURE_ST_POU

        ast_alias = STParser.parse_pou(MBR_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "MbrFoulingDynamicsSync"

    def test_pure_st_pou_internal_variables_and_control_logic(self) -> None:
        """Requirement 1: Verify internal boolean variables and interlock IF-branches."""
        ast = STParser.parse_pou(MBR_FOULING_PURE_ST_POU)
        assert ast is not None
        var_names = [v.name for v in ast.variables]
        assert "PermeatePumpPermissive" in var_names
        assert "EmergencyScourBlowerBoost" in var_names
        assert "BackwashValveOpen" in var_names

        stmts = "\n".join(ast.raw_statements)
        assert "IF CriticalTrip THEN" in stmts
        assert "IF HighTmpAlarm THEN" in stmts
        assert "IF AutoBackwashCmd THEN" in stmts


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
            "XIC PermeatePumpPermissive",
            "XIO CriticalTrip",
            "OTE AutoBackwashCmd",
            "OTL HighTmpAlarm",
            "OTU BackwashValveOpen",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: Verify all ladder constructs raise LadderForbiddenError."""
        bad_code = f"{MBR_FOULING_PURE_ST_POU}\n{ladder_snippet}\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

        val = STParser.validate_code(bad_code)
        assert val.status == AgentStatus.FAILED
        assert val.error_code == "ERR_LADDER_FORBIDDEN"
        assert val.data.get("ladder_rejected") is True


# ============================================================================
# 3. Darcy's Law Flux Calculations, Viscosity Temperature Scaling & Resistance Aggregation
# ============================================================================

class TestDarcyLawAndResistanceAggregation:
    """Tests for Darcy's law filtration, Vogel water viscosity temperature scaling, and Resistance-in-Series."""

    def test_vogel_dynamic_water_viscosity_temperature_scaling(self) -> None:
        """Requirement 3: Verify dynamic water viscosity decreases monotonically with temperature."""
        sim = MbrFoulingSimulator()
        mu_10 = sim.compute_water_viscosity(10.0)
        mu_15 = sim.compute_water_viscosity(15.0)
        mu_20 = sim.compute_water_viscosity(20.0)
        mu_25 = sim.compute_water_viscosity(25.0)
        mu_30 = sim.compute_water_viscosity(30.0)
        mu_40 = sim.compute_water_viscosity(40.0)

        # Monotonic decrease across temperature envelope
        assert mu_10 > mu_15 > mu_20 > mu_25 > mu_30 > mu_40

        # Physical accuracy validation against standard water tables
        assert math.isclose(mu_20, 1.002e-3, rel_tol=0.05)
        assert math.isclose(mu_25, 0.890e-3, rel_tol=0.05)
        assert math.isclose(mu_10, 1.307e-3, rel_tol=0.05)

        # Default configuration temperature fallback
        mu_default = sim.compute_water_viscosity()
        assert mu_default == pytest.approx(mu_20, rel=1e-6)

    def test_resistance_in_series_aggregation(self) -> None:
        """Requirement 3: Verify Resistance-in-Series (RIS) aggregation R_tot = R_m + R_c + R_p."""
        sim = MbrFoulingSimulator()

        # Clean membrane: zero cake and pore fouling
        r_tot_clean, tmp_clean, _ = sim.compute_darcy_tmp_and_flux(
            j_flux_lmh=25.0, r_cake_m_inv=0.0, r_pore_m_inv=0.0, temp_c=20.0
        )
        assert r_tot_clean == pytest.approx(sim.config.r_m)
        assert r_tot_clean == 1.0e12

        # Fouled membrane: intermediate cake and pore fouling
        r_tot_fouled, tmp_fouled, _ = sim.compute_darcy_tmp_and_flux(
            j_flux_lmh=25.0, r_cake_m_inv=1.5e12, r_pore_m_inv=0.3e12, temp_c=20.0
        )
        assert r_tot_fouled == pytest.approx(1.0e12 + 1.5e12 + 0.3e12)
        assert r_tot_fouled == pytest.approx(2.8e12)
        assert tmp_fouled > tmp_clean

        # Clamping of negative fouling resistances to zero
        r_tot_clamped, _, _ = sim.compute_darcy_tmp_and_flux(
            j_flux_lmh=25.0, r_cake_m_inv=-5.0e11, r_pore_m_inv=-1.0e11, temp_c=20.0
        )
        assert r_tot_clamped == pytest.approx(sim.config.r_m)

    def test_darcys_law_flux_and_tmp_linear_scaling(self) -> None:
        """Requirement 3: Verify Darcy's law linear scaling with flux and total resistance."""
        sim = MbrFoulingSimulator()

        # Base filtration condition
        _, tmp_20, _ = sim.compute_darcy_tmp_and_flux(
            j_flux_lmh=20.0, r_cake_m_inv=1.0e12, r_pore_m_inv=0.2e12, temp_c=20.0
        )
        # Double flux: TMP should double exactly
        _, tmp_40, _ = sim.compute_darcy_tmp_and_flux(
            j_flux_lmh=40.0, r_cake_m_inv=1.0e12, r_pore_m_inv=0.2e12, temp_c=20.0
        )
        assert tmp_40 == pytest.approx(2.0 * tmp_20, rel=1e-4)

        # Zero flux produces zero TMP
        _, tmp_zero, _ = sim.compute_darcy_tmp_and_flux(
            j_flux_lmh=0.0, r_cake_m_inv=1.0e12, r_pore_m_inv=0.2e12, temp_c=20.0
        )
        assert tmp_zero == 0.0

    def test_darcy_equilibrium_flux_inverse_consistency(self) -> None:
        """Requirement 3: Verify inverse flux and equilibrium TMP consistency."""
        sim = MbrFoulingSimulator()
        j_test = 30.0  # LMH
        r_tot, tmp_eq, mu = sim.compute_darcy_tmp_and_flux(
            j_flux_lmh=j_test, r_cake_m_inv=1.2e12, r_pore_m_inv=0.25e12, temp_c=20.0
        )

        # Inverse calculation: J = (TMP * 1000) / (mu * R_tot) * 3.6e6
        j_calc = (tmp_eq * 1000.0) / (mu * r_tot) * 3.6e6
        assert j_calc == pytest.approx(j_test, rel=1e-5)


# ============================================================================
# 4. Dynamic Cake Deposition vs. Aeration Scour Shear Detachment Balance
# ============================================================================

class TestDynamicCakeDepositionAndAirScour:
    """Tests for cake layer deposition kinetics, cross-flow air scour detachment, and pore blocking."""

    def test_cake_deposition_rate_scaling_with_mlss_and_flux(self) -> None:
        """Requirement 4: Verify cake deposition rate scales linearly with MLSS and permeate flux."""
        sim = MbrFoulingSimulator()

        # Baseline deposition rate
        r_dep_base, _ = sim.compute_cake_kinetics(j_flux_lmh=25.0, r_cake_m_inv=1.0e12, c_mlss_g_l=8.0)
        assert r_dep_base > 0.0

        # Double MLSS concentration -> double deposition rate
        r_dep_2xmlss, _ = sim.compute_cake_kinetics(j_flux_lmh=25.0, r_cake_m_inv=1.0e12, c_mlss_g_l=16.0)
        assert r_dep_2xmlss == pytest.approx(2.0 * r_dep_base, rel=1e-4)

        # Double flux -> double deposition rate
        r_dep_2xflux, _ = sim.compute_cake_kinetics(j_flux_lmh=50.0, r_cake_m_inv=1.0e12, c_mlss_g_l=8.0)
        assert r_dep_2xflux == pytest.approx(2.0 * r_dep_base, rel=1e-4)

        # Zero flux -> zero deposition rate
        r_dep_zero, _ = sim.compute_cake_kinetics(j_flux_lmh=0.0, r_cake_m_inv=1.0e12, c_mlss_g_l=8.0)
        assert r_dep_zero == 0.0

    def test_aeration_scour_shear_detachment_and_backwash_enhancement(self) -> None:
        """Requirement 4: Verify air scour shear detachment and backwash enhanced removal."""
        sim = MbrFoulingSimulator()

        # Normal aeration shear detachment
        _, r_detach_normal = sim.compute_cake_kinetics(
            j_flux_lmh=25.0, r_cake_m_inv=1.0e12, c_mlss_g_l=8.0, is_backwashing=False
        )
        assert r_detach_normal > 0.0

        # Double cake resistance -> double detachment rate
        _, r_detach_2xrc = sim.compute_cake_kinetics(
            j_flux_lmh=25.0, r_cake_m_inv=2.0e12, c_mlss_g_l=8.0, is_backwashing=False
        )
        assert r_detach_2xrc == pytest.approx(2.0 * r_detach_normal, rel=1e-4)

        # Enhanced detachment during automated backwash / relaxation
        _, r_detach_bw = sim.compute_cake_kinetics(
            j_flux_lmh=0.0, r_cake_m_inv=1.0e12, c_mlss_g_l=8.0, is_backwashing=True
        )
        # Backwash rate constant (0.050) is 10x higher than normal air scour (0.005)
        assert r_detach_bw > r_detach_normal
        expected_bw = (sim.config.k_detach + sim.config.k_backwash) * 1.0e12
        assert r_detach_bw == pytest.approx(expected_bw, rel=1e-4)

    def test_cake_fouling_dynamic_equilibrium_point(self) -> None:
        """Requirement 4: Verify dynamic equilibrium where deposition equals detachment: r_dep == r_detach."""
        sim = MbrFoulingSimulator()
        j_flux = 25.0  # LMH
        c_mlss = 8.0   # g/L

        # Analytical steady-state cake resistance:
        # alpha_cake * C_mlss * (J / 3.6e6) = k_detach * (Q_air / Q_air_nom) * R_c,eq
        j_si = j_flux / 3.6e6
        r_c_eq = (sim.config.alpha_cake * c_mlss * j_si) / sim.config.k_detach

        r_dep, r_detach = sim.compute_cake_kinetics(j_flux, r_c_eq, c_mlss, is_backwashing=False)
        assert r_dep == pytest.approx(r_detach, rel=1e-4)

        # Sub-equilibrium (growth regime)
        r_dep_sub, r_detach_sub = sim.compute_cake_kinetics(j_flux, 0.5 * r_c_eq, c_mlss, is_backwashing=False)
        assert r_dep_sub > r_detach_sub

        # Super-equilibrium (detachment regime)
        r_dep_super, r_detach_super = sim.compute_cake_kinetics(j_flux, 1.5 * r_c_eq, c_mlss, is_backwashing=False)
        assert r_dep_super < r_detach_super

    def test_irreversible_pore_blocking_asymptote_and_smp_fraction(self) -> None:
        """Requirement 4: Verify irreversible pore blocking asymptotic approach to R_p,max."""
        sim = MbrFoulingSimulator()

        r_low = sim.compute_pore_blocking_rate(j_flux_lmh=25.0, r_pore_m_inv=0.2e12, c_mlss_g_l=8.0)
        r_mid = sim.compute_pore_blocking_rate(j_flux_lmh=25.0, r_pore_m_inv=1.0e12, c_mlss_g_l=8.0)
        r_near_sat = sim.compute_pore_blocking_rate(j_flux_lmh=25.0, r_pore_m_inv=1.45e12, c_mlss_g_l=8.0)
        r_sat = sim.compute_pore_blocking_rate(j_flux_lmh=25.0, r_pore_m_inv=1.5e12, c_mlss_g_l=8.0)

        assert r_low > r_mid > r_near_sat > 0.0
        assert math.isclose(r_sat, 0.0, abs_tol=1e-12)

        # Beyond saturation, rate remains clamped to zero
        r_beyond = sim.compute_pore_blocking_rate(j_flux_lmh=25.0, r_pore_m_inv=1.8e12, c_mlss_g_l=8.0)
        assert r_beyond == 0.0

        # Zero flux produces zero pore blocking
        assert sim.compute_pore_blocking_rate(0.0, 0.2e12, 8.0) == 0.0

    def test_aeration_mass_transfer_kla_and_do_respiration(self) -> None:
        """Requirement 4: Verify kLa oxygen mass transfer and biomass respiration OUR dynamics."""
        sim = MbrFoulingSimulator()

        kla, our, do_sat, d_do_dt = sim.compute_aeration_and_respiration(do_mg_l=2.5, c_mlss_g_l=8.0)
        assert kla > 0.0
        assert our > 0.0
        assert do_sat > 2.5

        # Aeration loss: blower turned off
        sim.state.air_scour_on = False
        kla_off, our_off, _, d_do_dt_off = sim.compute_aeration_and_respiration(do_mg_l=2.5, c_mlss_g_l=8.0)
        assert kla_off == 0.0
        assert our_off == pytest.approx(our, rel=1e-4)
        assert d_do_dt_off < 0.0  # Oxygen depletion under endogenous respiration


# ============================================================================
# 5. Coupled ODE RK4 Integration Stability & Flux/Mass Balance Conservation
# ============================================================================

class TestCoupledMbrODEIntegration:
    """Tests for coupled 6-state RK4 solver stability, derivatives, and mass conservation."""

    def test_coupled_6state_rk4_solution_stability(self) -> None:
        """Requirement 5: Verify all 6 states remain bounded, positive, and physically realistic."""
        sim = MbrFoulingSimulator()
        res = sim.advance_time(duration_s=2.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        st = sim.state

        # Check bounds of all 6 states
        assert 0.0 < st.j_flux_lmh <= 50.0
        assert 0.0 < st.r_cake_m_inv < 1.0e13
        assert 0.0 <= st.r_pore_m_inv <= sim.config.r_p_max
        assert 0.0 < st.tmp_kpa < 100.0
        assert 0.0 < st.c_mlss_g_l < 30.0
        assert 0.0 < st.do_mg_l < 15.0
        assert st.time_s == pytest.approx(2.0, rel=1e-3)

    def test_analytical_solids_mass_conservation_residual(self) -> None:
        """Requirement 5: Verify analytical solids mass conservation residual < 1e-10 kg/s."""
        sim = MbrFoulingSimulator()
        sim.advance_time(duration_s=1.5, dt=0.05)

        residual = sim.state.mass_balance_residual_kg_s
        assert residual < 1e-10, f"Solids conservation residual {residual:.3e} exceeds 1e-10 kg/s"

    def test_ode_derivatives_deterministic_and_finite(self) -> None:
        """Requirement 5: Verify time derivatives dy/dt are finite and non-NaN across all 6 states."""
        sim = MbrFoulingSimulator()
        y_test = [25.0, 1.0e12, 0.2e12, 20.0, 8.0, 2.5]
        dy = sim.ode_derivatives(0.0, y_test)

        assert len(dy) == 6
        for i, val in enumerate(dy):
            assert not math.isnan(val), f"Derivative dy[{i}] is NaN"
            assert not math.isinf(val), f"Derivative dy[{i}] is Inf"

    def test_invalid_timestep_fail_closed(self) -> None:
        """Requirement 5: Verify non-positive duration or timestep fails closed with INVALID_TIMESTEP."""
        sim = MbrFoulingSimulator()

        res_zero = sim.advance_time(duration_s=0.0)
        assert res_zero.status == AgentStatus.FAILED
        assert res_zero.error_code == "INVALID_TIMESTEP"

        res_neg = sim.advance_time(duration_s=1.0, dt=-0.05)
        assert res_neg.status == AgentStatus.FAILED
        assert res_neg.error_code == "INVALID_TIMESTEP"

        res_neg_dur = sim.advance_time(duration_s=-2.0)
        assert res_neg_dur.status == AgentStatus.FAILED
        assert res_neg_dur.error_code == "INVALID_TIMESTEP"

    def test_permeate_pump_off_flux_decay(self) -> None:
        """Requirement 5: Verify permeate pump off causes flux decay toward zero with mass balance intact."""
        sim = MbrFoulingSimulator()
        sim.state.permeate_pump_on = False

        res = sim.advance_time(duration_s=2.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert sim.state.j_flux_lmh < 5.0  # Decays toward 0
        assert sim.state.mass_balance_residual_kg_s < 1e-10

    def test_ode_derivatives_during_backwash_relaxation(self) -> None:
        """Requirement 5: Verify ODE target flux is zero during backwash relaxation."""
        sim = MbrFoulingSimulator()
        sim.state.auto_backwash_cmd = True
        dy = sim.ode_derivatives(0.0, [25.0, 1.0e12, 0.2e12, 20.0, 8.0, 2.5])
        assert dy[0] < 0.0  # Decays toward zero setpoint


# ============================================================================
# 6. Process Safety Trips & Diagnostics
# ============================================================================

class TestMbrProcessSafetyTrips:
    """Tests for %M200 (0x9601), %M201 (0x9602, 0x9603), %M202 backwash, and diagnostic hierarchy."""

    def test_high_tmp_warning_alarm_and_code(self) -> None:
        """Requirement 6: Verify High TMP warning alarm (%M200, 0x9601) when TMP > 45.0 kPa."""
        reg_table = RegisterTable()
        sim = MbrFoulingSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M200") is False

        # Set TMP into alarm region (> 45 kPa, < 60 kPa)
        sim.state.tmp_kpa = 48.0
        sim._sync_registers()

        assert sim.state.high_tmp_alarm is True
        assert sim.state.critical_trip is False
        assert reg_table.read_bit("%M200") is True
        assert reg_table.read_bit("%M201") is False
        assert (reg_table.read_word("%R867") & 0xFFFF) == int(MbrFoulingDiagnosticCode.HIGH_TMP_ALARM)
        assert bool(reg_table.read_word("%R860") & int(MbrFoulingStatusBits.HIGH_TMP_ALARM)) is True
        assert sim.state.permeate_pump_on is True  # Warning alarm does not disable pump

    def test_critical_fouling_trip_by_tmp(self) -> None:
        """Requirement 6: Verify Critical fouling trip (%M201, 0x9602) when TMP > 60.0 kPa."""
        reg_table = RegisterTable()
        sim = MbrFoulingSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M201") is False

        # Set TMP above 60.0 kPa critical trip
        sim.state.tmp_kpa = 62.0
        sim._sync_registers()

        assert sim.state.critical_fouling_trip is True
        assert sim.state.critical_trip is True
        assert sim.state.permeate_pump_on is False  # Permissive disabled
        assert reg_table.read_bit("%M201") is True
        assert (reg_table.read_word("%R867") & 0xFFFF) == int(MbrFoulingDiagnosticCode.CRITICAL_FOULING_TRIP)
        assert bool(reg_table.read_word("%R860") & int(MbrFoulingStatusBits.CRITICAL_FOULING_TRIP)) is True

    def test_critical_fouling_trip_by_cake_resistance(self) -> None:
        """Requirement 6: Verify Critical fouling trip (%M201, 0x9602) when Rc > 4.0e12 m^-1."""
        reg_table = RegisterTable()
        sim = MbrFoulingSimulator(register_table=reg_table)

        # Set cake resistance beyond critical threshold
        sim.state.r_cake_m_inv = 4.2e12
        sim._sync_registers()

        assert sim.state.critical_fouling_trip is True
        assert sim.state.critical_trip is True
        assert reg_table.read_bit("%M201") is True
        assert (reg_table.read_word("%R867") & 0xFFFF) == int(MbrFoulingDiagnosticCode.CRITICAL_FOULING_TRIP)

    def test_aeration_loss_trip_and_code(self) -> None:
        """Requirement 6: Verify Aeration loss respiration trip (%M201, 0x9603) when DO < 0.50 mg/L."""
        reg_table = RegisterTable()
        sim = MbrFoulingSimulator(register_table=reg_table)

        # Set dissolved oxygen below 0.50 mg/L threshold
        sim.state.do_mg_l = 0.40
        sim._sync_registers()

        assert sim.state.aeration_loss_trip is True
        assert sim.state.critical_trip is True
        assert sim.state.permeate_pump_on is False
        assert reg_table.read_bit("%M201") is True
        assert (reg_table.read_word("%R867") & 0xFFFF) == int(MbrFoulingDiagnosticCode.AERATION_LOSS_TRIP)
        assert bool(reg_table.read_word("%R860") & int(MbrFoulingStatusBits.AERATION_LOSS_TRIP)) is True

    def test_automated_backwash_command_and_bit(self) -> None:
        """Requirement 6: Verify Automated backwash / relaxation command (%M202) when TMP > 35.0 kPa."""
        reg_table = RegisterTable()
        sim = MbrFoulingSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M202") is False

        # Set TMP above 35.0 kPa backwash trigger (below 45 kPa alarm)
        sim.state.tmp_kpa = 36.0
        sim._sync_registers()

        assert sim.state.auto_backwash_cmd is True
        assert reg_table.read_bit("%M202") is True
        assert bool(reg_table.read_word("%R860") & int(MbrFoulingStatusBits.BACKWASH_ACTIVE)) is True
        assert sim.state.high_tmp_alarm is False
        assert sim.state.critical_trip is False

    def test_diagnostic_code_priority_hierarchy(self) -> None:
        """Requirement 6: Verify diagnostic priority: Critical Fouling (0x9602) > Aeration Loss (0x9603) > High TMP (0x9601) > OK (0x0000)."""
        reg_table = RegisterTable()
        sim = MbrFoulingSimulator(register_table=reg_table)

        # Trigger all 3 conditions simultaneously: Critical TMP, Low DO, High TMP
        sim.state.tmp_kpa = 65.0       # Triggers 0x9602 and 0x9601
        sim.state.do_mg_l = 0.30       # Triggers 0x9603
        sim._sync_registers()

        # Highest priority: Critical Fouling Trip (0x9602)
        assert (reg_table.read_word("%R867") & 0xFFFF) == int(MbrFoulingDiagnosticCode.CRITICAL_FOULING_TRIP)

        # Clear critical TMP -> Aeration Loss Trip (0x9603) takes precedence
        sim.state.tmp_kpa = 48.0       # Still in High TMP alarm zone
        sim._sync_registers()
        assert (reg_table.read_word("%R867") & 0xFFFF) == int(MbrFoulingDiagnosticCode.AERATION_LOSS_TRIP)

        # Clear aeration loss -> High TMP Warning Alarm (0x9601) takes precedence
        sim.state.do_mg_l = 2.50       # Healthy DO
        sim._sync_registers()
        assert (reg_table.read_word("%R867") & 0xFFFF) == int(MbrFoulingDiagnosticCode.HIGH_TMP_ALARM)

        # Clear high TMP -> Normal OK (0x0000)
        sim.state.tmp_kpa = 20.0       # Nominal TMP
        sim._sync_registers()
        assert (reg_table.read_word("%R867") & 0xFFFF) == int(MbrFoulingDiagnosticCode.OK)


# ============================================================================
# 7. Horner OCS Register Space Synchronization
# ============================================================================

class TestHornerOCSSync:
    """Tests for Horner APG OCS register space mapping (%R860..%R867, %M200..%M202)."""

    def test_register_space_synchronization_nominal(self) -> None:
        """Requirement 7: Verify %R860..%R867 analog registers and %M200..%M202 discrete coils."""
        reg_table = RegisterTable()
        sim = MbrFoulingSimulator(register_table=reg_table)
        sim.advance_time(duration_s=0.5, dt=0.05)

        r860 = reg_table.read_uword("%R860")
        r861 = reg_table.read_word("%R861")
        r862 = reg_table.read_word("%R862")
        r863 = reg_table.read_word("%R863")
        r864 = reg_table.read_word("%R864")
        r865 = reg_table.read_word("%R865")
        r866 = reg_table.read_word("%R866")
        r867 = reg_table.read_uword("%R867")

        # %R860 Status Word
        assert (r860 & int(MbrFoulingStatusBits.RUNNING)) != 0
        assert (r860 & int(MbrFoulingStatusBits.PERMEATE_PUMP_ON)) != 0
        assert (r860 & int(MbrFoulingStatusBits.AIR_SCOUR_ON)) != 0
        assert (r860 & int(MbrFoulingStatusBits.FILTRATION_HEALTHY)) != 0
        assert (r860 & int(MbrFoulingStatusBits.HIGH_TMP_ALARM)) == 0
        assert (r860 & int(MbrFoulingStatusBits.CRITICAL_FOULING_TRIP)) == 0
        assert (r860 & int(MbrFoulingStatusBits.AERATION_LOSS_TRIP)) == 0

        # %R861: Permeate flux scaled x10 LMH (> 0)
        assert r861 > 0

        # %R862: TMP scaled x10 kPa (> 0)
        assert r862 > 0

        # %R863: Cake resistance scaled x1e-10 m^-1 (> 0)
        assert r863 > 0

        # %R864: Pore resistance scaled x1e-10 m^-1 (>= 0)
        assert r864 >= 0

        # %R865: MLSS scaled x10 g/L (> 0)
        assert r865 > 0

        # %R866: DO scaled x100 mg/L (> 0)
        assert r866 > 0

        # %R867: Diagnostic event code OK (0x0000)
        assert r867 == int(MbrFoulingDiagnosticCode.OK)

        # Discrete Coils normal
        assert reg_table.read_bit("%M200") is False
        assert reg_table.read_bit("%M201") is False
        assert reg_table.read_bit("%M202") is False

    def test_register_exact_scaling_precision(self) -> None:
        """Requirement 7: Verify exact scaled analog register mapping."""
        reg_table = RegisterTable()
        sim = MbrFoulingSimulator(register_table=reg_table)

        sim.state.j_flux_lmh = 27.4
        sim.state.tmp_kpa = 22.8
        sim.state.r_cake_m_inv = 1.35e12
        sim.state.r_pore_m_inv = 0.28e12
        sim.state.c_mlss_g_l = 8.6
        sim.state.do_mg_l = 2.45
        sim._sync_registers()

        assert reg_table.read_word("%R861") == 274   # 27.4 * 10
        assert reg_table.read_word("%R862") == 228   # 22.8 * 10
        assert reg_table.read_word("%R863") == 135   # 1.35e12 / 1e10
        assert reg_table.read_word("%R864") == 28    # 0.28e12 / 1e10
        assert reg_table.read_word("%R865") == 86    # 8.6 * 10
        assert reg_table.read_word("%R866") == 245   # 2.45 * 100

    def test_compatibility_class_aliases(self) -> None:
        """Requirement 7: Verify model, engine, config, and state aliases instantiate consistently."""
        sim1 = MbrSimulator()
        sim2 = MbrFoulingEngine()
        sim3 = MbrFoulingModel()

        assert isinstance(sim1, MbrFoulingSimulator)
        assert isinstance(sim2, MbrFoulingSimulator)
        assert isinstance(sim3, MbrFoulingSimulator)

        cfg = MbrConfig()
        assert isinstance(cfg, MbrFoulingConfig)
        st = MbrState()
        assert isinstance(st, MbrFoulingState)

        assert MbrStatusBits is MbrFoulingStatusBits
        assert MbrDiagnosticCode is MbrFoulingDiagnosticCode

    def test_state_property_getters_and_setters(self) -> None:
        """Requirement 7: Verify convenience property getters and setters on MbrFoulingState."""
        st = MbrFoulingState()
        st.j = 31.5
        assert st.j == 31.5
        assert st.j_flux_lmh == 31.5

        st.rc = 1.8e12
        assert st.rc == 1.8e12
        assert st.r_cake_m_inv == 1.8e12

        st.rp = 0.4e12
        assert st.rp == 0.4e12
        assert st.r_pore_m_inv == 0.4e12

        st.tmp = 26.5
        assert st.tmp == 26.5
        assert st.tmp_kpa == 26.5

        st.c_mlss = 9.2
        assert st.c_mlss == 9.2
        assert st.c_mlss_g_l == 9.2

        st.do = 3.1
        assert st.do == 3.1
        assert st.do_mg_l == 3.1


# ============================================================================
# 8. End-to-End 9-Stage Verification Suite Integration Test
# ============================================================================

class TestMbrFoulingVerificationRunner:
    """Tests for the deterministic 9-stage verification runner function."""

    def test_run_mbr_fouling_verification_9_stages(self, tmp_path: Path) -> None:
        """Requirement 8: Verify run_mbr_fouling_verification executes all 9 stages cleanly."""
        evidence_file = tmp_path / "mbr_fouling_evidence.json"
        res = run_mbr_fouling_verification(output_path=str(evidence_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert res["data"]["work_package"] == "W125"
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

    def test_run_mbr_fouling_verification_evidence_path_parameter(self, tmp_path: Path) -> None:
        """Requirement 8: Verify run_mbr_fouling_verification accepts evidence_path parameter."""
        evidence_file = tmp_path / "mbr_fouling_alt_evidence.json"
        res = run_mbr_fouling_verification(evidence_path=str(evidence_file))

        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert evidence_file.exists()
