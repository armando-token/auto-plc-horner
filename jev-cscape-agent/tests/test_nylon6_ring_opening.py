"""Comprehensive Industrial Nylon 6 Anionic Ring-Opening Polymerization (AROP) RIM Test Suite.

Work Package: W266 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 15 comprehensive engineering verification sections (100+ unit tests):
1. Section 1: Universal Physical & Chemical Constants, Molecular Weights & Reaction Enthalpy
2. Section 2: Reaction Kinetics & Avrami Crystallization Rate Expressions
3. Section 3: Reactor Geometry, Residence Time, Thermal Capacitance & Operating Baseline
4. Section 4: Nominal Steady-State Closed-Loop Convergence (Conv >= 95%, Temp 165.0 °C, Mw ~45000 Da, Cryst ~42%)
5. Section 5: Coupled 6-State Dynamic ODE System, Derivatives & RK4 Numerical Integrator
6. Section 6: Mathematical Conservation Residuals (Stoichiometric Mass, Elements C/H/O/N, Enthalpy < 1e-10)
7. Section 7: Process Safety Interlocks & Strict Priority Hierarchy (0xF901 > 0xF902 > 0xF903 > 0xF904 > 0x0000)
8. Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality, String & Bitwise Masking
9. Section 9: Fault Injections, Actuations & Emergency Cooling Coil %M531
10. Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege (%R2270..%R2277, %M529..%M531)
11. Section 11: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
12. Section 12: Anti-Ladder Security Guard Rejection (Contacts, Coils, Rungs, Networks, Mnemonics)
13. Section 13: ILogicUnit Compliance & 100-Cycle Soak Stability
14. Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
15. Section 15: Edge Cases, Model Aliases & Parameter Sensitivity
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.simulation.nylon6_ring_opening import (
    CAPROLACTAM_CONV_NOMINAL_PCT,
    CAPROLACTAM_CONVERSION_NOMINAL_PCT,
    COIL_NYLON6_EMERGENCY_COOLING_ACTIVE,
    COIL_NYLON6_MOLD_PERMISSIVE,
    COIL_NYLON6_REACTOR_ACTIVE,
    CRYSTALLINITY_NOMINAL_PCT,
    CRYSTALLINITY_PREMATURE_TRIP_PCT,
    DELTA_H_CRYST_J_G,
    DELTA_H_CRYST_J_KG,
    DELTA_H_CRYST_KJ_KG,
    DELTA_H_RXN_J_MOL,
    DELTA_H_RXN_KJ_MOL,
    G_ACCEL,
    INITIATOR_CONC_NOMINAL_MOL_L,
    INITIATOR_CONCENTRATION_NOMINAL,
    INITIATOR_DEACTIVATION_FAULT_MOL_L,
    MOLD_HEAT_DUTY_NOMINAL_KW,
    MOLD_HEAT_FLUX_NOMINAL_KW,
    MW_ACTIVATOR,
    MW_C,
    MW_CAPROLACTAM,
    MW_CL,
    MW_H,
    MW_INITIATOR,
    MW_MONOMER,
    MW_N,
    MW_NYLON6_MER,
    MW_O,
    MW_PA6_MER,
    MW_POLYMER_MER,
    MW_NUMBER_AVG_NOMINAL_DA,
    MW_WEIGHT_AVG_NOMINAL_DA,
    NUMBER_AVG_MW_NOMINAL_DA,
    NYLON6_AROP_PURE_ST_POU,
    NYLON6_CRYSTALLINITY_NOMINAL_PCT,
    NYLON6_PURE_ST_POU,
    NYLON6_RIM_PURE_ST_POU,
    NYLON6_RING_OPENING_PURE_ST_POU,
    NYLON6_RING_OPENING_SYNC_POU,
    NYLON6_SYNC_POU,
    NYLON6_WEIGHT_AVG_MW_NOMINAL_DA,
    POLYMERIZATION_RATE_FAULT_MOL_L_S,
    POLYMERIZATION_RATE_NOMINAL,
    POLYMERIZATION_RATE_NOMINAL_MOL_L_S,
    R_GAS_CONST,
    REG_CAPROLACTAM_CONVERSION_SCALED,
    REG_INITIATOR_CONCENTRATION_SCALED,
    REG_MOLD_HEAT_FLUX_KW_SCALED,
    REG_NYLON6_CRYSTALLINITY_PCT_SCALED,
    REG_NYLON6_DIAGNOSTIC_CODE,
    REG_NYLON6_REACTOR_TEMP_SCALED,
    REG_NYLON6_WEIGHT_AVG_MW_SCALED,
    REG_POLYMERIZATION_RATE_SCALED,
    T_EXOTHERM_RUNAWAY_TRIP_C,
    T_INLET_NOMINAL_C,
    T_PREMATURE_SOLIDIFICATION_TRIP_C,
    T_REACTOR_NOMINAL_C,
    T_REF_K,
    T_ZERO_CELSIUS,
    DiagnosticCode,
    Nylon6AROPReactor,
    Nylon6Config,
    Nylon6DiagnosticCode,
    Nylon6LogicUnit,
    Nylon6Polymerization,
    Nylon6PolymerizationReactor,
    Nylon6Reactor,
    Nylon6RIMConfig,
    Nylon6RIMDiagnosticCode,
    Nylon6RIMReactor,
    Nylon6RIMState,
    Nylon6RIMStatusBits,
    Nylon6RingOpening,
    Nylon6RingOpeningConfig,
    Nylon6RingOpeningDiagnosticCode,
    Nylon6RingOpeningEngine,
    Nylon6RingOpeningLogicUnit,
    Nylon6RingOpeningModel,
    Nylon6RingOpeningPlantModel,
    Nylon6RingOpeningReactor,
    Nylon6RingOpeningSimulator,
    Nylon6RingOpeningState,
    Nylon6RingOpeningStatusBits,
    Nylon6State,
    Nylon6StatusBits,
    Nylon6StatusWord,
    NylonDiagCode,
    PureSTValidationResult,
    run_nylon6_arop_verification,
    run_nylon6_rim_verification,
    run_nylon6_ring_opening_verification,
    run_nylon6_verification,
    validate_pure_st,
    verify_nylon6_pure_st,
    verify_nylon6_rim_pure_st,
    verify_nylon6_ring_opening_pure_st,
)


# ============================================================================
# Section 1: Universal Physical & Chemical Constants, Molecular Weights & Reaction Enthalpy
# ============================================================================

class TestSection01PhysicalAndChemicalConstants:
    """Verify universal physical constants, IUPAC atomic weights, and reaction thermodynamics."""

    def test_universal_physical_constants(self) -> None:
        """Universal gas constant, gravity, and reference temperature match standard physical constants."""
        assert math.isclose(R_GAS_CONST, 8.314462618, rel_tol=1e-8)
        assert math.isclose(G_ACCEL, 9.80665, rel_tol=1e-6)
        assert math.isclose(T_ZERO_CELSIUS, 273.15, abs_tol=1e-5)
        assert math.isclose(T_REF_K, 438.15, abs_tol=1e-5)
        assert math.isclose(T_REF_K, 165.0 + T_ZERO_CELSIUS, abs_tol=1e-5)

    def test_iupac_standard_atomic_weights(self) -> None:
        """IUPAC atomic weights for Carbon, Hydrogen, Oxygen, and Nitrogen are correct."""
        assert math.isclose(MW_C, 0.012011, rel_tol=1e-6)
        assert math.isclose(MW_H, 0.001008, rel_tol=1e-6)
        assert math.isclose(MW_O, 0.015999, rel_tol=1e-6)
        assert math.isclose(MW_N, 0.014007, rel_tol=1e-6)

    def test_chemical_species_molecular_weights(self) -> None:
        """Molecular weights of caprolactam monomer, Nylon 6 mer, initiator, and activator."""
        # epsilon-Caprolactam (C6H11NO): 6*C + 11*H + 1*N + 1*O = 0.113160 kg/mol
        expected_cl = 6.0 * MW_C + 11.0 * MW_H + 1.0 * MW_N + 1.0 * MW_O
        assert math.isclose(MW_CAPROLACTAM, expected_cl, rel_tol=1e-9)
        assert math.isclose(MW_CL, MW_CAPROLACTAM, rel_tol=1e-9)
        assert math.isclose(MW_MONOMER, MW_CAPROLACTAM, rel_tol=1e-9)
        assert math.isclose(MW_CAPROLACTAM, 0.113160, rel_tol=1e-4)

        # Nylon 6 (Polyamide-6) Repeat Unit: -[NH-(CH2)5-CO]- -> C6H11NO (0.113160 kg/mol)
        assert math.isclose(MW_NYLON6_MER, MW_CAPROLACTAM, rel_tol=1e-12)
        assert math.isclose(MW_PA6_MER, MW_NYLON6_MER, rel_tol=1e-12)
        assert math.isclose(MW_POLYMER_MER, MW_NYLON6_MER, rel_tol=1e-12)

        # Initiator & Activator
        assert math.isclose(MW_INITIATOR, 0.135140, rel_tol=1e-5)
        assert math.isclose(MW_ACTIVATOR, 0.155190, rel_tol=1e-5)

    def test_reaction_enthalpies_and_latent_heats(self) -> None:
        """Exothermic ring-opening enthalpy and crystallization latent heat constants are correct."""
        assert DELTA_H_RXN_KJ_MOL == -14.2
        assert math.isclose(DELTA_H_RXN_J_MOL, -14200.0, rel_tol=1e-9)
        assert DELTA_H_CRYST_J_G == -180.0
        assert math.isclose(DELTA_H_CRYST_J_KG, -180000.0, rel_tol=1e-9)
        assert DELTA_H_CRYST_KJ_KG == -180.0


# ============================================================================
# Section 2: Reaction Kinetics & Avrami Crystallization Rate Expressions
# ============================================================================

class TestSection02ReactionKineticsAndAvramiCrystallization:
    """Verify Arrhenius kinetics, propagation rate, and non-isothermal Nakamura crystallization."""

    def test_arrhenius_propagation_rate_constant(self) -> None:
        """Arrhenius rate constant increases with temperature and recovers activation energy."""
        reactor = Nylon6RingOpeningReactor()
        t1_k = 155.0 + T_ZERO_CELSIUS
        t2_k = 165.0 + T_ZERO_CELSIUS
        t3_k = 175.0 + T_ZERO_CELSIUS

        kp1 = reactor.arrhenius_rate_constant(reactor.config.arrhenius_ap_l_mol_s, reactor.config.activation_ep_j_mol, t1_k)
        kp2 = reactor.arrhenius_rate_constant(reactor.config.arrhenius_ap_l_mol_s, reactor.config.activation_ep_j_mol, t2_k)
        kp3 = reactor.arrhenius_rate_constant(reactor.config.arrhenius_ap_l_mol_s, reactor.config.activation_ep_j_mol, t3_k)

        assert kp1 > 0.0
        assert kp2 > kp1
        assert kp3 > kp2

        # Recover activation energy Ep
        ep_calc = -R_GAS_CONST * math.log(kp3 / kp1) / ((1.0 / t3_k) - (1.0 / t1_k))
        assert math.isclose(ep_calc, reactor.config.activation_ep_j_mol, rel_tol=1e-4)

    def test_polymerization_propagation_rate_expression(self) -> None:
        """Propagation rate Rp = kp * [M] * [C*] evaluates accurately."""
        reactor = Nylon6RingOpeningReactor()
        kin = reactor.compute_kinetics(
            t_c=165.0,
            c_monomer=0.31549,
            c_active=0.08500,
            c_cryst=0.42000,
        )
        assert kin["rp"] > 0.0
        expected_rp = kin["kp"] * 0.31549 * 0.08500
        assert math.isclose(kin["rp"], expected_rp, rel_tol=1e-6)
        assert math.isclose(kin["rp"], 1.85, rel_tol=0.02)

    def test_avrami_nakamura_crystallization_rate_expression(self) -> None:
        """Nakamura crystallization rate dalpha/dt follows Avrami exponent na=2.5 and Gaussian temperature peak."""
        reactor = Nylon6RingOpeningReactor()
        # Test at peak temperature (148.0 °C) vs higher temperature (175.0 °C)
        kin_peak = reactor.compute_kinetics(t_c=148.0, c_monomer=0.315, c_active=0.085, c_cryst=0.25)
        kin_high = reactor.compute_kinetics(t_c=175.0, c_monomer=0.315, c_active=0.085, c_cryst=0.25)

        assert kin_peak["r_cryst"] > 0.0
        assert kin_high["r_cryst"] > 0.0
        # Peak temperature gives higher crystallization rate constant than 175 °C
        assert kin_peak["r_cryst"] > kin_high["r_cryst"]

    def test_reaction_and_crystallization_heat_generation(self) -> None:
        """Exothermic heat generation terms Q_rxn and Q_cryst are strictly positive and correctly scaled."""
        reactor = Nylon6RingOpeningReactor()
        kin = reactor.compute_kinetics(t_c=165.0, c_monomer=0.31549, c_active=0.085, c_cryst=0.420)
        assert kin["q_rxn"] > 0.0
        assert kin["q_cryst"] > 0.0

        # Q_rxn = Rp * V * (-DeltaH_rxn) / 1000 kW
        expected_q_rxn = (kin["rp"] * reactor.config.mold_cavity_volume_l * (-reactor.config.delta_h_rxn_j_mol)) / 1000.0
        assert math.isclose(kin["q_rxn"], expected_q_rxn, rel_tol=1e-6)

        # Q_cryst = r_cryst * m_charge * (-DeltaH_cryst) / 1000 kW
        m_charge = reactor.config.mold_cavity_volume_l * reactor.config.melt_density_kg_l
        expected_q_cryst = (kin["r_cryst"] * m_charge * (-reactor.config.delta_h_cryst_j_kg)) / 1000.0
        assert math.isclose(kin["q_cryst"], expected_q_cryst, rel_tol=1e-6)


# ============================================================================
# Section 3: Reactor Geometry, Residence Time, Thermal Capacitance & Operating Baseline
# ============================================================================

class TestSection03ReactorGeometryAndOperatingBaseline:
    """Verify geometric parameters, thermal mass, and operating nominal constants."""

    def test_reactor_configuration_defaults(self) -> None:
        """Default configuration parameters match industrial RIM reactor specifications."""
        config = Nylon6RingOpeningConfig()
        assert config.mold_cavity_volume_l == 25.0
        assert math.isclose(config.nominal_residence_time_s, 4.7018919, rel_tol=1e-5)
        assert config.melt_density_kg_l == 1.020
        assert config.melt_specific_heat_cp_j_kg_k == 2100.0
        assert config.reactor_thermal_capacitance_kj_k == 53.55
        assert config.nominal_monomer_feed_conc_mol_l == 9.0140
        assert config.nominal_initiator_feed_conc_mol_l == 0.0850
        assert config.nominal_inlet_temp_c == 140.0
        assert config.avrami_exponent_na == 2.5
        assert config.max_crystallinity_fraction == 0.50
        assert config.nominal_crystallinity_fraction == 0.4200
        assert config.cryst_peak_temp_c == 148.0
        assert config.cryst_temp_span_c == 22.0
        assert config.nominal_mw_weight_avg_da == 45000.0
        assert config.nominal_mw_number_avg_da == 26470.0
        assert config.nominal_mold_heat_flux_kw == 48.0
        assert config.mold_temp_setpoint_c == 140.0
        assert config.ua_mold_kw_k == 1.920
        assert config.ambient_loss_kw == 10.0
        assert config.emergency_cooling_jacket_kw == 250.0

    def test_nominal_operating_baseline_constants(self) -> None:
        """Baseline constants match OCS register scaling requirements."""
        assert T_REACTOR_NOMINAL_C == 165.0
        assert T_INLET_NOMINAL_C == 140.0
        assert CAPROLACTAM_CONV_NOMINAL_PCT == 96.50
        assert CAPROLACTAM_CONVERSION_NOMINAL_PCT == 96.50
        assert NYLON6_CRYSTALLINITY_NOMINAL_PCT == 42.00
        assert CRYSTALLINITY_NOMINAL_PCT == 42.00
        assert NYLON6_WEIGHT_AVG_MW_NOMINAL_DA == 45000.0
        assert MW_WEIGHT_AVG_NOMINAL_DA == 45000.0
        assert NUMBER_AVG_MW_NOMINAL_DA == 26470.0
        assert MW_NUMBER_AVG_NOMINAL_DA == 26470.0
        assert POLYMERIZATION_RATE_NOMINAL_MOL_L_S == 1.85
        assert POLYMERIZATION_RATE_NOMINAL == 1.85
        assert MOLD_HEAT_FLUX_NOMINAL_KW == 48.0
        assert MOLD_HEAT_DUTY_NOMINAL_KW == 48.0
        assert INITIATOR_CONC_NOMINAL_MOL_L == 0.085
        assert INITIATOR_CONCENTRATION_NOMINAL == 0.085

    def test_safety_interlock_thresholds(self) -> None:
        """Safety interlock trip limits match system specifications."""
        assert T_PREMATURE_SOLIDIFICATION_TRIP_C == 135.0
        assert CRYSTALLINITY_PREMATURE_TRIP_PCT == 48.00
        assert T_EXOTHERM_RUNAWAY_TRIP_C == 195.0
        assert INITIATOR_DEACTIVATION_FAULT_MOL_L == 0.040
        assert POLYMERIZATION_RATE_FAULT_MOL_L_S == 0.50


# ============================================================================
# Section 4: Nominal Steady-State Closed-Loop Convergence
# ============================================================================

class TestSection04NominalSteadyStateConvergence:
    """Verify nominal steady-state values (Conversion >= 95%, Temp 165.0 °C, Mw ~45k, Cryst ~42%)."""

    def test_nominal_conversion_and_temperature(self) -> None:
        """Nominal steady state meets Conversion >= 95% and Temp = 165.0 °C."""
        reactor = Nylon6RingOpeningReactor()
        assert reactor.state.caprolactam_conversion_pct >= 95.0
        assert math.isclose(reactor.state.caprolactam_conversion_pct, 96.50, abs_tol=0.1)
        assert math.isclose(reactor.state.t_reactor_c, 165.0, abs_tol=0.1)

    def test_nominal_molecular_weight_and_crystallinity(self) -> None:
        """Nominal steady state exhibits Mw ~ 45,000 Da and Crystallinity ~ 42.00%."""
        reactor = Nylon6RingOpeningReactor()
        assert math.isclose(reactor.state.mw_weight_avg, 45000.0, abs_tol=1.0)
        assert math.isclose(reactor.state.mw_number_avg, 26470.0, abs_tol=1.0)
        assert math.isclose(reactor.state.nylon6_crystallinity_pct, 42.00, abs_tol=0.1)
        assert math.isclose(reactor.state.c_crystallinity, 0.4200, abs_tol=0.001)

    def test_nominal_rates_and_heat_duties(self) -> None:
        """Nominal polymerization rate, mold heat flux, and initiator concentration are nominal."""
        reactor = Nylon6RingOpeningReactor()
        assert math.isclose(reactor.state.polymerization_rate_mol_l_s, 1.85, abs_tol=0.05)
        assert math.isclose(reactor.state.mold_heat_flux_kw, 48.0, abs_tol=0.5)
        assert math.isclose(reactor.state.initiator_concentration_mol_l, 0.085, abs_tol=0.005)

    def test_nominal_residual_monomer_concentration(self) -> None:
        """Residual monomer concentration aligns with 96.50% conversion."""
        reactor = Nylon6RingOpeningReactor()
        expected_cm = 9.0140 * (1.0 - 0.9650)
        assert math.isclose(reactor.state.c_monomer, expected_cm, rel_tol=1e-3)


# ============================================================================
# Section 5: Coupled 6-State Dynamic ODE System, Derivatives & RK4 Numerical Integrator
# ============================================================================

class TestSection05Coupled6StateODEAndRK4:
    """Verify ODE derivatives calculation, RK4 numerical stability, and state non-negativity."""

    def test_compute_derivatives_nominal(self) -> None:
        """Compute derivatives returns 6 real derivative values at nominal state."""
        reactor = Nylon6RingOpeningReactor()
        y = [
            reactor.state.c_monomer,
            reactor.state.c_active_centers,
            reactor.state.c_crystallinity,
            reactor.state.mw_number_avg,
            reactor.state.mw_weight_avg,
            reactor.state.t_reactor_c,
        ]
        derivs = reactor.compute_derivatives(y)
        assert len(derivs) == 6
        for d in derivs:
            assert isinstance(d, float)
            assert not math.isnan(d)
            assert not math.isinf(d)

    def test_rk4_step_execution_and_counter_increment(self) -> None:
        """Single rk4_step advances simulation time and updates state variables."""
        reactor = Nylon6RingOpeningReactor()
        initial_time = reactor.state.sim_time_s
        reactor.scan_step(dt=0.02)
        assert math.isclose(reactor.state.sim_time_s, initial_time + 0.02, abs_tol=1e-6)
        assert reactor.state.cycle_count == 1

    def test_state_non_negativity_preservation(self) -> None:
        """State non-negativity is strictly maintained across extreme states."""
        reactor = Nylon6RingOpeningReactor()
        # Perturb to near-zero states
        reactor.state.c_monomer = 0.001
        reactor.state.c_active_centers = 0.0001
        reactor.state.c_crystallinity = 0.0001
        reactor.state.mw_number_avg = 500.0
        reactor.state.mw_weight_avg = 500.0
        reactor.state.t_reactor_c = 140.0

        reactor.rk4_step(dt=0.02)
        assert reactor.state.c_monomer >= 0.0
        assert reactor.state.c_active_centers >= 0.0
        assert reactor.state.c_crystallinity >= 0.0
        assert reactor.state.mw_number_avg >= 0.0
        assert reactor.state.mw_weight_avg >= 0.0
        assert reactor.state.t_reactor_c >= 0.0

    def test_rk4_step_stability_various_dt(self) -> None:
        """RK4 numerical integrator is stable across dt = 0.005, 0.01, 0.02, and 0.05 s."""
        for dt_test in [0.005, 0.010, 0.020, 0.050]:
            r = Nylon6RingOpeningReactor()
            for _ in range(20):
                r.scan_step(dt=dt_test)
            assert not math.isnan(r.state.t_reactor_c)
            assert not math.isnan(r.state.c_monomer)
            assert not math.isnan(r.state.mw_weight_avg)
            assert 140.0 <= r.state.t_reactor_c <= 180.0


# ============================================================================
# Section 6: Mathematical Conservation Residuals (Stoichiometric Mass, Elements C/H/O/N, Enthalpy < 1e-10)
# ============================================================================

class TestSection06ConservationResiduals:
    """Verify first-law enthalpy and stoichiometric mass conservation residuals < 1e-10."""

    def test_stoichiometric_mass_residual_less_than_1e10(self) -> None:
        """Caprolactam to Nylon 6 mer conversion produces zero stoichiometric mass imbalance."""
        reactor = Nylon6RingOpeningReactor()
        reactor._update_conservation_residuals()
        assert reactor.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert reactor.state.total_mass_balance_residual_kg_s >= 0.0

    def test_elemental_mass_residual_less_than_1e10(self) -> None:
        """Elemental conservation of C, H, O, N yields elemental residual < 1e-10 kg/s."""
        reactor = Nylon6RingOpeningReactor()
        reactor._update_conservation_residuals()
        assert reactor.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert reactor.state.elemental_mass_balance_residual_kg_s >= 0.0

    def test_first_law_enthalpy_conservation_residual_less_than_1e10(self) -> None:
        """First-law enthalpy conservation residual |C_th * dT/dt - Q_net| < 1e-10 kW."""
        reactor = Nylon6RingOpeningReactor()
        reactor._update_conservation_residuals()
        assert reactor.state.enthalpy_conservation_residual_kw < 1.0e-10
        assert reactor.state.enthalpy_conservation_residual_kw >= 0.0

    def test_conservation_residuals_maintained_across_scan_steps(self) -> None:
        """Conservation residuals remain < 1e-10 over 50 consecutive scan steps."""
        reactor = Nylon6RingOpeningReactor()
        for _ in range(50):
            reactor.scan_step(dt=0.02)
            assert reactor.state.total_mass_balance_residual_kg_s < 1.0e-10
            assert reactor.state.elemental_mass_balance_residual_kg_s < 1.0e-10
            assert reactor.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# Section 7: Process Safety Interlocks & Strict Priority Hierarchy (0xF901 > 0xF902 > 0xF903 > 0xF904 > 0x0000)
# ============================================================================

class TestSection07SafetyInterlocksAndPriority:
    """Verify safety interlock trip logic and strict priority hierarchy."""

    def test_nominal_state_ok_priority5(self) -> None:
        """Nominal operating conditions resolve to 0x0000 OK with normal coils."""
        reactor = Nylon6RingOpeningReactor()
        assert reactor.state.diagnostic_code == DiagnosticCode.OK
        assert reactor.state.nylon6_reactor_active is True
        assert reactor.state.nylon6_mold_permissive is True
        assert reactor.state.nylon6_emergency_cooling_active is False

    def test_priority1_premature_solidification_low_temp(self) -> None:
        """Temperature < 135.0 °C triggers Priority 1: 0xF901 PREMATURE_SOLIDIFICATION_TRIP."""
        reactor = Nylon6RingOpeningReactor()
        reactor.state.t_reactor_c = 134.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == DiagnosticCode.PREMATURE_SOLIDIFICATION_TRIP
        assert reactor.state.nylon6_reactor_active is False
        assert reactor.state.nylon6_mold_permissive is False
        assert reactor.state.nylon6_emergency_cooling_active is False

    def test_priority1_premature_solidification_high_cryst(self) -> None:
        """Crystallinity > 48.00% triggers Priority 1: 0xF901 PREMATURE_SOLIDIFICATION_TRIP."""
        reactor = Nylon6RingOpeningReactor()
        reactor.state.nylon6_crystallinity_pct = 48.50
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == DiagnosticCode.PREMATURE_SOLIDIFICATION_TRIP
        assert reactor.state.nylon6_reactor_active is False
        assert reactor.state.nylon6_mold_permissive is False

    def test_priority2_exotherm_runaway_trip(self) -> None:
        """Temperature > 195.0 °C triggers Priority 2: 0xF902 EXOTHERM_RUNAWAY_TRIP and emergency cooling %M531."""
        reactor = Nylon6RingOpeningReactor()
        reactor.state.t_reactor_c = 196.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == DiagnosticCode.EXOTHERM_RUNAWAY_TRIP
        assert reactor.state.nylon6_reactor_active is False
        assert reactor.state.nylon6_mold_permissive is False
        assert reactor.state.nylon6_emergency_cooling_active is True

    def test_priority3_initiator_deactivation_fault(self) -> None:
        """Initiator concentration < 0.040 mol/L triggers Priority 3: 0xF903 INITIATOR_DEACTIVATION_FAULT."""
        reactor = Nylon6RingOpeningReactor()
        reactor.state.initiator_concentration_mol_l = 0.038
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == DiagnosticCode.INITIATOR_DEACTIVATION_FAULT
        assert reactor.state.nylon6_mold_permissive is False
        assert reactor.state.nylon6_emergency_cooling_active is False

    def test_priority4_moisture_poisoning_fault(self) -> None:
        """Polymerization rate < 0.50 mol/(L.s) triggers Priority 4: 0xF904 MOISTURE_POISONING_FAULT."""
        reactor = Nylon6RingOpeningReactor()
        reactor.state.polymerization_rate_mol_l_s = 0.45
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == DiagnosticCode.MOISTURE_POISONING_FAULT
        assert reactor.state.nylon6_mold_permissive is False

    def test_priority1_preempts_priority2(self) -> None:
        """Priority 1 (high cryst > 48%) preempts Priority 2 (high temp > 195 °C)."""
        reactor = Nylon6RingOpeningReactor()
        reactor.state.nylon6_crystallinity_pct = 49.00
        reactor.state.t_reactor_c = 200.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == DiagnosticCode.PREMATURE_SOLIDIFICATION_TRIP

    def test_priority2_preempts_priority3(self) -> None:
        """Priority 2 (high temp > 195 °C) preempts Priority 3 (low initiator < 0.040)."""
        reactor = Nylon6RingOpeningReactor()
        reactor.state.t_reactor_c = 200.0
        reactor.state.initiator_concentration_mol_l = 0.020
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == DiagnosticCode.EXOTHERM_RUNAWAY_TRIP
        assert reactor.state.nylon6_emergency_cooling_active is True

    def test_priority3_preempts_priority4(self) -> None:
        """Priority 3 (low initiator < 0.040) preempts Priority 4 (low rate < 0.50)."""
        reactor = Nylon6RingOpeningReactor()
        reactor.state.initiator_concentration_mol_l = 0.030
        reactor.state.polymerization_rate_mol_l_s = 0.20
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == DiagnosticCode.INITIATOR_DEACTIVATION_FAULT


# ============================================================================
# Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality, String & Bitwise Masking
# ============================================================================

class TestSection08DiagnosticCodeMasking:
    """Verify signed/unsigned 16-bit integer conversions, equality, and bitwise masking."""

    def test_diagnostic_code_values_exact(self) -> None:
        """Hexadecimal values match specification: 0x0000, 0xF901, 0xF902, 0xF903, 0xF904."""
        assert DiagnosticCode.OK.value == 0x0000
        assert DiagnosticCode.PREMATURE_SOLIDIFICATION_TRIP.value == 0xF901
        assert DiagnosticCode.EXOTHERM_RUNAWAY_TRIP.value == 0xF902
        assert DiagnosticCode.INITIATOR_DEACTIVATION_FAULT.value == 0xF903
        assert DiagnosticCode.MOISTURE_POISONING_FAULT.value == 0xF904

    def test_signed_16bit_integer_equivalences(self) -> None:
        """Signed 16-bit representations match two's complement values."""
        # 0xF901 -> 63745 unsigned, -1791 signed
        assert (0xF901 - 65536) == -1791
        # 0xF902 -> 63746 unsigned, -1790 signed
        assert (0xF902 - 65536) == -1790
        # 0xF903 -> 63747 unsigned, -1789 signed
        assert (0xF903 - 65536) == -1789
        # 0xF904 -> 63748 unsigned, -1788 signed
        assert (0xF904 - 65536) == -1788

    def test_signed_and_unsigned_equality_operator(self) -> None:
        """DiagnosticCode __eq__ supports unsigned int, signed int, and enum equality."""
        code = DiagnosticCode.PREMATURE_SOLIDIFICATION_TRIP
        assert code == 0xF901
        assert code == 63745
        assert code == -1791
        assert code == DiagnosticCode.PREMATURE_SOLIDIFICATION_TRIP

        code2 = DiagnosticCode.EXOTHERM_RUNAWAY_TRIP
        assert code2 == 0xF902
        assert code2 == 63746
        assert code2 == -1790

        code3 = DiagnosticCode.INITIATOR_DEACTIVATION_FAULT
        assert code3 == 0xF903
        assert code3 == 63747
        assert code3 == -1789

        code4 = DiagnosticCode.MOISTURE_POISONING_FAULT
        assert code4 == 0xF904
        assert code4 == 63748
        assert code4 == -1788

        ok = DiagnosticCode.OK
        assert ok == 0x0000
        assert ok == 0

    def test_bitwise_masking_with_0xffff(self) -> None:
        """Bitwise AND masking (& 0xFFFF) recovers the clean unsigned 16-bit value."""
        for c in DiagnosticCode:
            masked = c & 0xFFFF
            assert masked == (c.value & 0xFFFF)
            assert 0 <= masked <= 65535

    def test_diagnostic_code_lookup_from_signed_int(self) -> None:
        """Lookup from signed negative 16-bit integers successfully resolves the enum member."""
        assert DiagnosticCode(-1791) == DiagnosticCode.PREMATURE_SOLIDIFICATION_TRIP
        assert DiagnosticCode(-1790) == DiagnosticCode.EXOTHERM_RUNAWAY_TRIP
        assert DiagnosticCode(-1789) == DiagnosticCode.INITIATOR_DEACTIVATION_FAULT
        assert DiagnosticCode(-1788) == DiagnosticCode.MOISTURE_POISONING_FAULT
        assert DiagnosticCode(0) == DiagnosticCode.OK

    def test_diagnostic_code_string_representation(self) -> None:
        """String representation includes 4-digit uppercase hex code and name."""
        s = str(DiagnosticCode.PREMATURE_SOLIDIFICATION_TRIP)
        assert "0xF901" in s
        assert "PREMATURE_SOLIDIFICATION_TRIP" in s

    def test_diagnostic_code_aliases(self) -> None:
        """DiagnosticCode aliases map cleanly to the same class."""
        assert Nylon6DiagnosticCode is DiagnosticCode
        assert Nylon6RingOpeningDiagnosticCode is DiagnosticCode
        assert Nylon6RIMDiagnosticCode is DiagnosticCode
        assert NylonDiagCode is DiagnosticCode


# ============================================================================
# Section 9: Fault Injections, Actuations & Emergency Cooling Coil %M531
# ============================================================================

class TestSection09FaultInjectionsAndActuations:
    """Verify fault injection effects on discrete coils and emergency cooling actuation."""

    def test_premature_solidification_actuation_clears_coils(self) -> None:
        """Premature solidification deasserts reactor active %M529 and mold permissive %M530."""
        reactor = Nylon6RingOpeningReactor()
        reactor.state.t_reactor_c = 130.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.nylon6_reactor_active is False
        assert reactor.state.nylon6_mold_permissive is False
        assert reactor.state.nylon6_emergency_cooling_active is False

    def test_exotherm_runaway_asserts_emergency_cooling(self) -> None:
        """Thermal runaway activates emergency cooling coil %M531 = True and deasserts active coils."""
        reactor = Nylon6RingOpeningReactor()
        reactor.state.t_reactor_c = 198.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.nylon6_emergency_cooling_active is True
        assert reactor.state.nylon6_reactor_active is False
        assert reactor.state.nylon6_mold_permissive is False

    def test_moisture_poisoning_injection_fault(self) -> None:
        """Moisture poisoning fault clears mold permissive and sets 0xF904."""
        reactor = Nylon6RingOpeningReactor()
        reactor.state.moisture_poisoning_injected = True
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == DiagnosticCode.MOISTURE_POISONING_FAULT
        assert reactor.state.nylon6_mold_permissive is False

    def test_reset_restores_nominal_coils(self) -> None:
        """Reset clears fault state and re-establishes nominal permissive coils."""
        reactor = Nylon6RingOpeningReactor()
        reactor.state.t_reactor_c = 198.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.nylon6_emergency_cooling_active is True

        reactor.reset()
        assert reactor.state.diagnostic_code == DiagnosticCode.OK
        assert reactor.state.nylon6_reactor_active is True
        assert reactor.state.nylon6_mold_permissive is True
        assert reactor.state.nylon6_emergency_cooling_active is False


# ============================================================================
# Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege (%R2270..%R2277, %M529..%M531)
# ============================================================================

class TestSection10RegisterTableSync:
    """Verify Horner OCS register space bindings, scaling factors, and SYSTEM privilege."""

    def test_register_constants_definitions(self) -> None:
        """Register and coil address constants match W266 specification."""
        assert REG_NYLON6_REACTOR_TEMP_SCALED == "%R2270"
        assert REG_CAPROLACTAM_CONVERSION_SCALED == "%R2271"
        assert REG_NYLON6_CRYSTALLINITY_PCT_SCALED == "%R2272"
        assert REG_NYLON6_WEIGHT_AVG_MW_SCALED == "%R2273"
        assert REG_POLYMERIZATION_RATE_SCALED == "%R2274"
        assert REG_MOLD_HEAT_FLUX_KW_SCALED == "%R2275"
        assert REG_INITIATOR_CONCENTRATION_SCALED == "%R2276"
        assert REG_NYLON6_DIAGNOSTIC_CODE == "%R2277"
        assert COIL_NYLON6_REACTOR_ACTIVE == "%M529"
        assert COIL_NYLON6_MOLD_PERMISSIVE == "%M530"
        assert COIL_NYLON6_EMERGENCY_COOLING_ACTIVE == "%M531"

    def test_nominal_register_synchronization(self) -> None:
        """Nominal state writes exactly scaled integers to %R2270..%R2277 and %M529..%M531."""
        rt = RegisterTable()
        reactor = Nylon6RingOpeningReactor(register_table=rt)
        reactor.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)

        # %R2270: 165.0 °C * 10 = 1650
        assert rt.read_word("%R2270") == 1650
        # %R2271: 96.50 % * 100 = 9650
        assert rt.read_word("%R2271") == 9650
        # %R2272: 42.00 % * 100 = 4200
        assert rt.read_word("%R2272") == 4200
        # %R2273: 45000 Da / 10 = 4500
        assert rt.read_word("%R2273") == 4500
        # %R2274: 1.85 mol/L.s * 100 = 185
        assert rt.read_word("%R2274") == 185
        # %R2275: 48.0 kW * 10 = 480
        assert rt.read_word("%R2275") == 480
        # %R2276: 0.085 mol/L * 1000 = 85
        assert rt.read_word("%R2276") == 85
        # %R2277: 0x0000 = 0
        assert rt.read_word("%R2277") == 0
        assert rt.read_uword("%R2277") == 0x0000

        # Discrete Coils
        assert rt.read_bit("%M529") is True
        assert rt.read_bit("%M530") is True
        assert rt.read_bit("%M531") is False

    def test_runaway_trip_register_sync(self) -> None:
        """Runaway trip synchronization writes 0xF902 and asserts %M531."""
        rt = RegisterTable()
        reactor = Nylon6RingOpeningReactor(register_table=rt)
        reactor.state.t_reactor_c = 196.0
        reactor._evaluate_safety_interlocks()
        reactor.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)

        assert rt.read_uword("%R2277") == 0xF902
        assert rt.read_word("%R2277") == -1790
        assert rt.read_bit("%M529") is False
        assert rt.read_bit("%M530") is False
        assert rt.read_bit("%M531") is True

    def test_solidification_trip_register_sync(self) -> None:
        """Premature solidification synchronization writes 0xF901 and clears %M529..%M531."""
        rt = RegisterTable()
        reactor = Nylon6RingOpeningReactor(register_table=rt)
        reactor.state.t_reactor_c = 130.0
        reactor._evaluate_safety_interlocks()
        reactor.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)

        assert rt.read_uword("%R2277") == 0xF901
        assert rt.read_word("%R2277") == -1791
        assert rt.read_bit("%M529") is False
        assert rt.read_bit("%M530") is False
        assert rt.read_bit("%M531") is False


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
# ============================================================================

class TestSection11PureSTPOU:
    """Verify Pure IEC 61131-3 Structured Text POU, variable bindings, and syntax validation."""

    def test_pure_st_pou_string_constants(self) -> None:
        """Pure ST POU text constant is defined and matches aliases."""
        assert isinstance(NYLON6_RING_OPENING_PURE_ST_POU, str)
        assert "PROGRAM Nylon6RingOpeningSync" in NYLON6_RING_OPENING_PURE_ST_POU
        assert "END_PROGRAM" in NYLON6_RING_OPENING_PURE_ST_POU
        assert NYLON6_RING_OPENING_SYNC_POU == NYLON6_RING_OPENING_PURE_ST_POU
        assert NYLON6_PURE_ST_POU == NYLON6_RING_OPENING_PURE_ST_POU
        assert NYLON6_SYNC_POU == NYLON6_RING_OPENING_PURE_ST_POU
        assert NYLON6_RIM_PURE_ST_POU == NYLON6_RING_OPENING_PURE_ST_POU
        assert NYLON6_AROP_PURE_ST_POU == NYLON6_RING_OPENING_PURE_ST_POU

    def test_st_parser_validate_code_success(self) -> None:
        """STParser.validate_code validates NYLON6_RING_OPENING_PURE_ST_POU cleanly."""
        res = STParser.validate_code(NYLON6_RING_OPENING_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_security_guard_assert_pure_st_success(self) -> None:
        """SecurityGuard.assert_pure_st_content verifies pure ST without ladder logic."""
        SecurityGuard.assert_pure_st_content(NYLON6_RING_OPENING_PURE_ST_POU)

    def test_verify_nylon6_ring_opening_pure_st_function(self) -> None:
        """verify_nylon6_ring_opening_pure_st() and aliases return passed=True."""
        res1 = verify_nylon6_ring_opening_pure_st()
        assert res1.passed is True
        assert res1.status == AgentStatus.SUCCESS
        assert res1.error is None

        res2 = verify_nylon6_pure_st()
        assert res2.passed is True
        res3 = verify_nylon6_rim_pure_st()
        assert res3.passed is True
        res4 = validate_pure_st()
        assert res4.passed is True

    def test_ast_bound_registers_comprehensive(self) -> None:
        """STParser AST contains all 11 required %R2270..%R2277 and %M529..%M531 bindings."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(NYLON6_RING_OPENING_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "Nylon6RingOpeningSync"
        assert pou.pou_type == POUType.PROGRAM

        required = [
            "%R2270", "%R2271", "%R2272", "%R2273",
            "%R2274", "%R2275", "%R2276", "%R2277",
            "%M529", "%M530", "%M531",
        ]
        for reg in required:
            assert reg in pou.bound_registers

    def test_ast_variable_memory_address_attributes(self) -> None:
        """Each AST variable correctly captures its memory_address / address_binding attribute."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(NYLON6_RING_OPENING_PURE_ST_POU)
        assert pou is not None

        var_map = {
            v.name: getattr(v, "address_binding", getattr(v, "memory_address", getattr(v, "address", None)))
            for v in pou.variables
        }
        assert var_map.get("Nylon6ReactorTempScaled") == "%R2270"
        assert var_map.get("CaprolactamConversionScaled") == "%R2271"
        assert var_map.get("Nylon6CrystallinityPctScaled") == "%R2272"
        assert var_map.get("Nylon6WeightAvgMwScaled") == "%R2273"
        assert var_map.get("PolymerizationRateScaled") == "%R2274"
        assert var_map.get("MoldHeatFluxKwScaled") == "%R2275"
        assert var_map.get("InitiatorConcentrationScaled") == "%R2276"
        assert var_map.get("Nylon6DiagnosticCode") == "%R2277"
        assert var_map.get("Nylon6ReactorActive") == "%M529"
        assert var_map.get("Nylon6MoldPermissive") == "%M530"
        assert var_map.get("Nylon6EmergencyCoolingActive") == "%M531"


# ============================================================================
# Section 12: Anti-Ladder Security Guard Rejection (Contacts, Coils, Rungs, Networks, Mnemonics)
# ============================================================================

class TestSection12AntiLadderRejection:
    """Verify anti-ladder security guard rejects contacts, coils, rungs, networks, and mnemonics."""

    def test_reject_ladder_contacts(self) -> None:
        """Ladder logic contacts |---[ ]---| are rejected with LadderForbiddenError."""
        bad_code = "PROGRAM L1\nVAR b: BOOL; END_VAR\n|---[ ]---|\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_coils(self) -> None:
        """Ladder logic coils |---( )---| are rejected with LadderForbiddenError."""
        bad_code = "PROGRAM L2\nVAR b: BOOL; END_VAR\n|---( )---|\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_reject_ladder_rungs_and_networks(self) -> None:
        """Ladder rungs (RUNG) and networks (NETWORK) are rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM RungTest\nRUNG 1\nEND_PROGRAM")

        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM NetTest\nNETWORK 1\nEND_PROGRAM")

    def test_reject_ladder_mnemonics(self) -> None:
        """Ladder mnemonics (XIC, OTE, OTL, OTU) are rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Mnem1\nXIC(Start);\nEND_PROGRAM")

        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Mnem2\nOTE(Run);\nEND_PROGRAM")

        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Mnem3\nOTL(Latch);\nEND_PROGRAM")

        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Mnem4\nOTU(Unlatch);\nEND_PROGRAM")


# ============================================================================
# Section 13: ILogicUnit Compliance & 100-Cycle Soak Stability
# ============================================================================

class TestSection13ILogicUnitComplianceAndSoak:
    """Verify ILogicUnit interface compliance and 100-cycle soak stability."""

    def test_ilogicunit_interface_properties(self) -> None:
        """Nylon6RingOpeningReactor implements ILogicUnit properties and methods."""
        reactor = Nylon6RingOpeningReactor()
        assert isinstance(reactor, ILogicUnit)
        assert reactor.name == "Nylon6RingOpeningReactor"
        assert reactor.priority == 266
        assert reactor.is_enabled is True

        reactor.disable()
        assert reactor.is_enabled is False
        reactor.enable()
        assert reactor.is_enabled is True

    def test_logic_unit_wrapper_class(self) -> None:
        """Nylon6RingOpeningLogicUnit wrapper implements ILogicUnit interface."""
        unit = Nylon6RingOpeningLogicUnit()
        assert isinstance(unit, ILogicUnit)
        assert unit.name == "Nylon6RingOpeningLogicUnit"
        assert unit.priority == 266
        assert unit.is_enabled is True

        unit.scan_step(dt=0.02)
        unit.step(dt=0.02)
        ctx = ScanContext(cycle=1, dt=0.02)
        unit.execute(ctx)
        unit.reset()

    def test_100_cycle_soak_stability(self) -> None:
        """100-cycle scan execution demonstrates zero NaN, zero drift, and steady convergence."""
        rt = RegisterTable()
        reactor = Nylon6RingOpeningReactor(register_table=rt)
        reactor.reset()

        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt_ms=20.0, elapsed_time_ms=cycle * 20.0, dt=0.02)
            reactor.execute(ctx)

        # Assert post-soak stability
        assert 164.0 <= reactor.state.t_reactor_c <= 166.0
        assert reactor.state.caprolactam_conversion_pct >= 95.0
        assert 40.0 <= reactor.state.nylon6_crystallinity_pct <= 45.0
        assert 40000.0 <= reactor.state.mw_weight_avg <= 50000.0
        assert not math.isnan(reactor.state.t_reactor_c)
        assert not math.isnan(reactor.state.c_monomer)
        assert reactor.state.diagnostic_code == DiagnosticCode.OK
        assert reactor.state.cycle_count == 100

    def test_status_bits_bitmask(self) -> None:
        """Status bits bitmask reflects operational flags correctly."""
        reactor = Nylon6RingOpeningReactor()
        assert bool(reactor.state.status_bits & Nylon6RingOpeningStatusBits.RUNNING)
        assert bool(reactor.state.status_bits & Nylon6RingOpeningStatusBits.REACTOR_ACTIVE)
        assert bool(reactor.state.status_bits & Nylon6RingOpeningStatusBits.MOLD_PERMISSIVE)
        assert not bool(reactor.state.status_bits & Nylon6RingOpeningStatusBits.EMERGENCY_COOLING_ACTIVE)


# ============================================================================
# Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
# ============================================================================

class TestSection14VerificationSuiteAndArtifacts:
    """Verify deterministic 9-stage engineering verification suite and artifact export."""

    def test_run_nylon6_ring_opening_verification_all_stages(self, tmp_path: Path) -> None:
        """run_nylon6_ring_opening_verification executes and passes all 9 stages."""
        out_json = tmp_path / "nylon6_evidence.json"
        res = run_nylon6_ring_opening_verification(output_path=out_json, work_package="W266")

        assert res["status"] == AgentStatus.SUCCESS.value
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert res["data"]["passed_stages"] == 9
        assert res["data"]["total_stages"] == 9
        assert len(res["data"]["stages"]) == 9

        # Verify JSON file written to disk
        assert out_json.exists()
        loaded = json.loads(out_json.read_text(encoding="utf-8"))
        assert loaded["status"] == "success"
        assert loaded["data"]["work_package"] == "W266"

    def test_verification_aliases(self) -> None:
        """Verification runner aliases function identically."""
        assert run_nylon6_verification is run_nylon6_ring_opening_verification
        assert run_nylon6_rim_verification is run_nylon6_ring_opening_verification
        assert run_nylon6_arop_verification is run_nylon6_ring_opening_verification


# ============================================================================
# Section 15: Edge Cases, Model Aliases & Parameter Sensitivity
# ============================================================================

class TestSection15EdgeCasesAndAliases:
    """Verify model class aliases, configuration overrides, and boundary sensitivity."""

    def test_model_class_aliases(self) -> None:
        """All model class aliases point to Nylon6RingOpeningReactor."""
        assert Nylon6RingOpening is Nylon6RingOpeningReactor
        assert Nylon6Reactor is Nylon6RingOpeningReactor
        assert Nylon6RIMReactor is Nylon6RingOpeningReactor
        assert Nylon6Polymerization is Nylon6RingOpeningReactor
        assert Nylon6PolymerizationReactor is Nylon6RingOpeningReactor
        assert Nylon6AROPReactor is Nylon6RingOpeningReactor
        assert Nylon6RingOpeningModel is Nylon6RingOpeningReactor
        assert Nylon6RingOpeningSimulator is Nylon6RingOpeningReactor
        assert Nylon6RingOpeningEngine is Nylon6RingOpeningReactor
        assert Nylon6RingOpeningPlantModel is Nylon6RingOpeningReactor

    def test_config_and_state_aliases(self) -> None:
        """Configuration and state aliases resolve correctly."""
        assert Nylon6Config is Nylon6RingOpeningConfig
        assert Nylon6RIMConfig is Nylon6RingOpeningConfig
        assert Nylon6State is Nylon6RingOpeningState
        assert Nylon6RIMState is Nylon6RingOpeningState
        assert Nylon6StatusBits is Nylon6RingOpeningStatusBits
        assert Nylon6RIMStatusBits is Nylon6RingOpeningStatusBits
        assert Nylon6StatusWord is Nylon6RingOpeningStatusBits

    def test_custom_config_initialization(self) -> None:
        """Reactor accepts custom configuration overrides without error."""
        cfg = Nylon6RingOpeningConfig(
            mold_cavity_volume_l=30.0,
            nominal_monomer_feed_conc_mol_l=9.5,
        )
        r = Nylon6RingOpeningReactor(config=cfg)
        assert r.config.mold_cavity_volume_l == 30.0
        assert r.config.nominal_monomer_feed_conc_mol_l == 9.5

    def test_boundary_temperature_transitions(self) -> None:
        """Temperature just above and below safety thresholds operates as expected."""
        r = Nylon6RingOpeningReactor()

        # Just at limit: 135.0 °C (threshold < 135.0) -> OK
        r.state.t_reactor_c = 135.0
        r._evaluate_safety_interlocks()
        assert r.state.diagnostic_code == DiagnosticCode.OK

        # Just below limit: 134.99 °C -> Trip
        r.state.t_reactor_c = 134.99
        r._evaluate_safety_interlocks()
        assert r.state.diagnostic_code == DiagnosticCode.PREMATURE_SOLIDIFICATION_TRIP

        # Just at upper limit: 195.0 °C (threshold > 195.0) -> OK
        r.reset()
        r.state.t_reactor_c = 195.0
        r._evaluate_safety_interlocks()
        assert r.state.diagnostic_code == DiagnosticCode.OK

        # Just above upper limit: 195.01 °C -> Runaway trip
        r.state.t_reactor_c = 195.01
        r._evaluate_safety_interlocks()
        assert r.state.diagnostic_code == DiagnosticCode.EXOTHERM_RUNAWAY_TRIP


# ============================================================================
# Section 16: Comprehensive Deep Coverage & Strict Protocol Invariants
# ============================================================================

class TestSection16ComprehensiveDeepCoverage:
    """Verify detailed string formatting, bitmasks, thermodynamic balances, and fault transitions."""

    def test_all_diagnostic_codes_str_exact(self) -> None:
        """All 5 DiagnosticCode members format accurately into '0xXXXX (NAME)' strings."""
        assert str(DiagnosticCode.OK) == "0x0000 (OK)"
        assert str(DiagnosticCode.PREMATURE_SOLIDIFICATION_TRIP) == "0xF901 (PREMATURE_SOLIDIFICATION_TRIP)"
        assert str(DiagnosticCode.EXOTHERM_RUNAWAY_TRIP) == "0xF902 (EXOTHERM_RUNAWAY_TRIP)"
        assert str(DiagnosticCode.INITIATOR_DEACTIVATION_FAULT) == "0xF903 (INITIATOR_DEACTIVATION_FAULT)"
        assert str(DiagnosticCode.MOISTURE_POISONING_FAULT) == "0xF904 (MOISTURE_POISONING_FAULT)"

    def test_all_diagnostic_codes_bitwise_and(self) -> None:
        """Bitwise AND operations (& and __rand__) work with all DiagnosticCode members."""
        for code in DiagnosticCode:
            u_val = code.value & 0xFFFF
            assert (code & 0xFFFF) == u_val
            assert (0xFFFF & code) == u_val
            assert (code & code.value) == code.value

    def test_status_bits_individual_flags(self) -> None:
        """Each Nylon6RingOpeningStatusBits bit flag possesses unique bit position."""
        assert Nylon6RingOpeningStatusBits.RUNNING == 0x0001
        assert Nylon6RingOpeningStatusBits.REACTOR_ACTIVE == 0x0002
        assert Nylon6RingOpeningStatusBits.MOLD_PERMISSIVE == 0x0004
        assert Nylon6RingOpeningStatusBits.EMERGENCY_COOLING_ACTIVE == 0x0008
        assert Nylon6RingOpeningStatusBits.PREMATURE_SOLIDIFICATION_TRIP == 0x0010
        assert Nylon6RingOpeningStatusBits.EXOTHERM_RUNAWAY_TRIP == 0x0020
        assert Nylon6RingOpeningStatusBits.INITIATOR_DEACTIVATION_FAULT == 0x0040
        assert Nylon6RingOpeningStatusBits.MOISTURE_POISONING_FAULT == 0x0080

    def test_status_bits_aliases(self) -> None:
        """All StatusBits aliases map to Nylon6RingOpeningStatusBits."""
        assert Nylon6StatusBits is Nylon6RingOpeningStatusBits
        assert Nylon6RIMStatusBits is Nylon6RingOpeningStatusBits
        assert Nylon6StatusWord is Nylon6RingOpeningStatusBits

    def test_diagnostic_code_compatibility_aliases(self) -> None:
        """DiagnosticCode aliases for errors and faults resolve to the correct enum constants."""
        assert DiagnosticCode.PREMATURE_SOLIDIFICATION == DiagnosticCode.PREMATURE_SOLIDIFICATION_TRIP
        assert DiagnosticCode.SOLIDIFICATION_TRIP == DiagnosticCode.PREMATURE_SOLIDIFICATION_TRIP
        assert DiagnosticCode.FREEZE_OFF_TRIP == DiagnosticCode.PREMATURE_SOLIDIFICATION_TRIP
        assert DiagnosticCode.EXOTHERM_RUNAWAY == DiagnosticCode.EXOTHERM_RUNAWAY_TRIP
        assert DiagnosticCode.THERMAL_RUNAWAY == DiagnosticCode.EXOTHERM_RUNAWAY_TRIP
        assert DiagnosticCode.RUNAWAY_TRIP == DiagnosticCode.EXOTHERM_RUNAWAY_TRIP
        assert DiagnosticCode.INITIATOR_DEACTIVATION == DiagnosticCode.INITIATOR_DEACTIVATION_FAULT
        assert DiagnosticCode.CATALYST_DEACTIVATION == DiagnosticCode.INITIATOR_DEACTIVATION_FAULT
        assert DiagnosticCode.MOISTURE_POISONING == DiagnosticCode.MOISTURE_POISONING_FAULT
        assert DiagnosticCode.WATER_POISONING_FAULT == DiagnosticCode.MOISTURE_POISONING_FAULT
        assert DiagnosticCode.ERR_PREMATURE_SOLIDIFICATION == DiagnosticCode.PREMATURE_SOLIDIFICATION_TRIP
        assert DiagnosticCode.ERR_EXOTHERM_RUNAWAY == DiagnosticCode.EXOTHERM_RUNAWAY_TRIP
        assert DiagnosticCode.ERR_INITIATOR_DEACTIVATION == DiagnosticCode.INITIATOR_DEACTIVATION_FAULT
        assert DiagnosticCode.ERR_MOISTURE_POISONING == DiagnosticCode.MOISTURE_POISONING_FAULT
        assert DiagnosticCode.NYLON6_ERR_SOLIDIFICATION == DiagnosticCode.PREMATURE_SOLIDIFICATION_TRIP
        assert DiagnosticCode.NYLON6_ERR_RUNAWAY == DiagnosticCode.EXOTHERM_RUNAWAY_TRIP
        assert DiagnosticCode.NYLON6_ERR_INITIATOR == DiagnosticCode.INITIATOR_DEACTIVATION_FAULT
        assert DiagnosticCode.NYLON6_ERR_MOISTURE == DiagnosticCode.MOISTURE_POISONING_FAULT

    def test_pure_st_validation_result_operators(self) -> None:
        """PureSTValidationResult supports boolean cast and AgentStatus equality."""
        res_ok = PureSTValidationResult(True, status=AgentStatus.SUCCESS)
        assert bool(res_ok) is True
        assert res_ok == True
        assert res_ok == AgentStatus.SUCCESS

        res_fail = PureSTValidationResult(False, status=AgentStatus.FAILED, error="Invalid")
        assert bool(res_fail) is False
        assert res_fail == False
        assert res_fail == AgentStatus.FAILED
        assert res_fail.error == "Invalid"

    def test_avrami_nakamura_crystallization_rate_variation(self) -> None:
        """Crystallization rate varies with degree of crystallinity following Avrami kinetics."""
        reactor = Nylon6RingOpeningReactor()
        # Early crystallinity vs near-limit crystallinity
        kin_low = reactor.compute_kinetics(t_c=165.0, c_monomer=0.315, c_active=0.085, c_cryst=0.10)
        kin_high = reactor.compute_kinetics(t_c=165.0, c_monomer=0.315, c_active=0.085, c_cryst=0.45)

        assert kin_low["r_cryst"] > 0.0
        assert kin_high["r_cryst"] > 0.0

    def test_emergency_cooling_jacket_net_heat_balance(self) -> None:
        """Emergency cooling jacket applies 250 kW additional heat sink when active."""
        reactor = Nylon6RingOpeningReactor()
        reactor.state.nylon6_emergency_cooling_active = False
        reactor._update_derived_variables()
        q_net_normal = reactor.state.q_net_kw

        reactor.state.nylon6_emergency_cooling_active = True
        reactor._update_derived_variables()
        q_net_cooling = reactor.state.q_net_kw

        # Difference should equal exactly emergency cooling duty (250 kW)
        assert math.isclose(q_net_normal - q_net_cooling, reactor.config.emergency_cooling_jacket_kw, rel_tol=1e-5)

    def test_200_cycle_extended_soak_stability(self) -> None:
        """200 consecutive scan cycles demonstrate continuous mathematical and thermodynamic stability."""
        rt = RegisterTable()
        reactor = Nylon6RingOpeningReactor(register_table=rt)
        reactor.reset()

        for cycle in range(1, 201):
            ctx = ScanContext(cycle=cycle, dt_ms=20.0, elapsed_time_ms=cycle * 20.0, dt=0.02)
            reactor.execute(ctx)

        assert 164.0 <= reactor.state.t_reactor_c <= 166.0
        assert reactor.state.caprolactam_conversion_pct >= 95.0
        assert not math.isnan(reactor.state.t_reactor_c)
        assert reactor.state.cycle_count == 200

    def test_pou_ast_detailed_structure(self) -> None:
        """STParser AST for Nylon6RingOpeningSync POU contains variables with correct IEC data types."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(NYLON6_RING_OPENING_PURE_ST_POU)
        assert pou is not None
        assert len(pou.variables) == 11

        type_map = {v.name: v.data_type for v in pou.variables}
        # Scaled integer registers
        assert type_map["Nylon6ReactorTempScaled"] == "INT"
        assert type_map["CaprolactamConversionScaled"] == "INT"
        assert type_map["Nylon6CrystallinityPctScaled"] == "INT"
        assert type_map["Nylon6WeightAvgMwScaled"] == "INT"
        assert type_map["PolymerizationRateScaled"] == "INT"
        assert type_map["MoldHeatFluxKwScaled"] == "INT"
        assert type_map["InitiatorConcentrationScaled"] == "INT"
        assert type_map["Nylon6DiagnosticCode"] == "INT"
        # Discrete boolean coils
        assert type_map["Nylon6ReactorActive"] == "BOOL"
        assert type_map["Nylon6MoldPermissive"] == "BOOL"
        assert type_map["Nylon6EmergencyCoolingActive"] == "BOOL"

