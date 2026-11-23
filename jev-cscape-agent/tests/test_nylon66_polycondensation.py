"""Comprehensive Industrial Polyamide-6,6 (Nylon 6,6) Continuous Polycondensation Test Suite.

Work Package: W257 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 15 comprehensive engineering verification sections (115+ unit tests):
1. Section 1: Universal Physical & Chemical Constants, Molecular Weights & Reaction Enthalpies
2. Section 2: Reaction Kinetics, Rate Constants & Arrhenius Temperature Dependence
3. Section 3: Reactor Geometry, Residence Time, Thermal Capacitance & Operating Baseline
4. Section 4: Nominal Steady-State Closed-Loop Convergence (Conversion >= 90.0%, Temp 220.0 °C, Pressure 18.0 bar)
5. Section 5: Coupled 6-State Dynamic ODE System, Derivatives & RK4 Numerical Integrator
6. Section 6: Mathematical Conservation Residuals (Stoichiometric Mass, Elements C/H/O/N, Enthalpy < 1e-10)
7. Section 7: Process Safety Interlocks & Strict Priority Hierarchy (0xF601 > 0xF602 > 0xF603 > 0xF604 > 0x0000)
8. Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality, String & Bitwise Masking
9. Section 9: Pre-Alarm Logic (%M509) & Emergency Autoclave Vent Actuation (%M510)
10. Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege (%R2180..%R2187, %M508..%M510)
11. Section 11: Pure IEC 61131-3 Structured Text POU & Variable Bindings
12. Section 12: Anti-Ladder Security Guard Rejection (Contacts, Coils, Rungs, Networks, Mnemonics)
13. Section 13: ILogicUnit Scan Cycle Execution, Reset Dynamics & 100-Cycle Soak Stability
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

from jev_cscape.simulation.nylon66_polycondensation import (
    AMIDE_CONV_NOMINAL_PCT,
    AMIDE_CONVERSION_NOMINAL_PCT,
    COIL_EMERGENCY_AUTOCLAVE_VENT_OPEN,
    COIL_NYLON_REACTOR_ACTIVE,
    COIL_SALT_RATIO_PRE_ALARM,
    DELTA_H_RXN_J_MOL,
    DELTA_H_RXN_KJ_MOL,
    DELTA_H_VAP_STEAM_J_KG,
    DELTA_H_VAP_STEAM_KJ_KG,
    DELTA_H_VAP_WATER_J_MOL,
    DP_NOMINAL,
    G_ACCEL,
    HEATING_DUTY_NOMINAL_KW,
    MELT_VISCOSITY_NOMINAL,
    MELT_VISCOSITY_NOMINAL_PA_S,
    MW_ADA,
    MW_ADIPIC_ACID,
    MW_AH_SALT,
    MW_C,
    MW_H,
    MW_H2O,
    MW_HEXAMETHYLENEDIAMINE,
    MW_HMDA,
    MW_N,
    MW_NYLON_MER,
    MW_NYLON_SALT,
    MW_NYLON66_MER,
    MW_O,
    MW_PREPOLYMER,
    MW_WATER,
    NUMBER_AVG_DP_NOMINAL,
    NYLON_POLYCONDENSATION_PURE_ST_POU,
    NYLON_POLYCONDENSATION_SYNC_POU,
    NYLON_PURE_ST_POU,
    NYLON_SYNC_POU,
    NYLON66_POLYCONDENSATION_PURE_ST_POU,
    NYLON66_POLYCONDENSATION_SYNC_POU,
    NYLON66_PURE_ST_POU,
    NYLON66_SYNC_POU,
    P_OVERPRESSURE_TRIP_BAR,
    P_REACTOR_NOMINAL_BAR,
    R_GAS_CONST,
    REG_AMIDE_CONVERSION_SCALED,
    REG_MELT_VISCOSITY_SCALED,
    REG_NUMBER_AVG_DP_SCALED,
    REG_NYLON_DIAGNOSTIC_CODE,
    REG_NYLON_REACTOR_PRESSURE_SCALED,
    REG_NYLON_REACTOR_TEMP_SCALED,
    REG_SALT_STOICHIOMETRIC_RATIO_SCALED,
    REG_STEAM_BLEED_RATE_SCALED,
    SALT_RATIO_IMBALANCE_HIGH,
    SALT_RATIO_IMBALANCE_LOW,
    SALT_RATIO_NOMINAL,
    SALT_RATIO_PRE_ALARM_HIGH,
    SALT_RATIO_PRE_ALARM_LOW,
    SALT_STOICHIOMETRIC_RATIO_NOMINAL,
    STEAM_BLEED_FAULT_LOW_KG_H,
    STEAM_BLEED_RATE_NOMINAL_KG_H,
    T_INLET_NOMINAL_C,
    T_OVERTEMP_GELATION_TRIP_C,
    T_REACTOR_NOMINAL_C,
    T_REF_K,
    T_ZERO_CELSIUS,
    DiagnosticCode,
    Nylon66Config,
    Nylon66DiagnosticCode,
    Nylon66Polycondensation,
    Nylon66PolycondensationConfig,
    Nylon66PolycondensationDiagnosticCode,
    Nylon66PolycondensationEngine,
    Nylon66PolycondensationLogicUnit,
    Nylon66PolycondensationModel,
    Nylon66PolycondensationPlantModel,
    Nylon66PolycondensationReactor,
    Nylon66PolycondensationSimulator,
    Nylon66PolycondensationState,
    Nylon66PolycondensationStatusBits,
    Nylon66Reactor,
    Nylon66State,
    Nylon66StatusBits,
    NylonConfig,
    NylonDiagCode,
    NylonDiagnosticCode,
    NylonLogicUnit,
    NylonPolycondensation,
    NylonPolycondensationConfig,
    NylonPolycondensationReactor,
    NylonPolycondensationState,
    NylonPolycondensationStatusBits,
    NylonReactorState,
    NylonState,
    NylonStatusBits,
    NylonStatusWord,
    PureSTValidationResult,
    run_nylon_polycondensation_verification,
    run_nylon66_polycondensation_verification,
    run_nylon66_verification,
    validate_pure_st,
    verify_nylon_polycondensation_pure_st,
    verify_nylon66_polycondensation_pure_st,
    verify_nylon66_pure_st,
)


# ============================================================================
# Section 1: Universal Physical & Chemical Constants, Molecular Weights & Reaction Enthalpies
# ============================================================================

class TestSection01PhysicalAndChemicalConstants:
    """Verify universal physical constants, IUPAC atomic weights, and reaction thermodynamics."""

    def test_universal_physical_constants(self) -> None:
        """Universal gas constant, gravity, and reference temperature match standard physical constants."""
        assert math.isclose(R_GAS_CONST, 8.314462618, rel_tol=1e-8)
        assert math.isclose(G_ACCEL, 9.80665, rel_tol=1e-6)
        assert math.isclose(T_ZERO_CELSIUS, 273.15, abs_tol=1e-5)
        assert math.isclose(T_REF_K, 493.15, abs_tol=1e-5)
        assert math.isclose(T_REF_K, 220.0 + T_ZERO_CELSIUS, abs_tol=1e-5)

    def test_iupac_standard_atomic_weights(self) -> None:
        """IUPAC atomic weights for Carbon, Hydrogen, Oxygen, and Nitrogen are correct."""
        assert math.isclose(MW_C, 0.012011, rel_tol=1e-6)
        assert math.isclose(MW_H, 0.001008, rel_tol=1e-6)
        assert math.isclose(MW_O, 0.015999, rel_tol=1e-6)
        assert math.isclose(MW_N, 0.014007, rel_tol=1e-6)

    def test_chemical_species_molecular_weights(self) -> None:
        """Molecular weights of ADA, HMDA, AH salt, Nylon 6,6 mer, and Water are accurate."""
        # Adipic Acid (ADA): C6H10O4 -> 6*12.011 + 10*1.008 + 4*15.999 = 146.142 g/mol
        expected_ada = 6.0 * MW_C + 10.0 * MW_H + 4.0 * MW_O
        assert math.isclose(MW_ADA, expected_ada, rel_tol=1e-9)
        assert math.isclose(MW_ADIPIC_ACID, MW_ADA, rel_tol=1e-9)
        assert math.isclose(MW_ADA, 0.146142, rel_tol=1e-4)

        # Hexamethylenediamine (HMDA): C6H16N2 -> 6*12.011 + 16*1.008 + 2*14.007 = 116.208 g/mol
        expected_hmda = 6.0 * MW_C + 16.0 * MW_H + 2.0 * MW_N
        assert math.isclose(MW_HMDA, expected_hmda, rel_tol=1e-9)
        assert math.isclose(MW_HEXAMETHYLENEDIAMINE, MW_HMDA, rel_tol=1e-9)
        assert math.isclose(MW_HMDA, 0.116208, rel_tol=1e-4)

        # Water: H2O -> 2*1.008 + 15.999 = 18.015 g/mol
        expected_water = 2.0 * MW_H + 1.0 * MW_O
        assert math.isclose(MW_WATER, expected_water, rel_tol=1e-9)
        assert math.isclose(MW_H2O, MW_WATER, rel_tol=1e-9)

        # Nylon 6,6 Repeat Unit (Prepolymer Mer): C12H22N2O2
        expected_nylon = 12.0 * MW_C + 22.0 * MW_H + 2.0 * MW_N + 2.0 * MW_O
        assert math.isclose(MW_PREPOLYMER, expected_nylon, rel_tol=1e-9)
        assert math.isclose(MW_NYLON66_MER, MW_PREPOLYMER, rel_tol=1e-9)
        assert math.isclose(MW_NYLON_MER, MW_PREPOLYMER, rel_tol=1e-9)

        # AH Salt: C12H26N2O4 = ADA + HMDA
        assert math.isclose(MW_AH_SALT, MW_ADA + MW_HMDA, rel_tol=1e-9)
        assert math.isclose(MW_NYLON_SALT, MW_AH_SALT, rel_tol=1e-9)

    def test_stoichiometric_condensation_mass_balance(self) -> None:
        """Reaction mass balance is exact: ADA + HMDA == Nylon66_mer + 2 H2O."""
        reactants_mass = MW_ADA + MW_HMDA
        products_mass = MW_PREPOLYMER + 2.0 * MW_WATER
        assert abs(reactants_mass - products_mass) < 1e-12

    def test_reaction_enthalpies_and_latent_heats(self) -> None:
        """Reaction enthalpy and latent heat of vaporization match specified values."""
        assert math.isclose(DELTA_H_RXN_KJ_MOL, -26.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H_RXN_J_MOL, -26000.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H_VAP_STEAM_KJ_KG, 1910.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H_VAP_STEAM_J_KG, 1910000.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H_VAP_WATER_J_MOL, 1910000.0 * MW_WATER, rel_tol=1e-6)


# ============================================================================
# Section 2: Reaction Kinetics, Rate Constants & Arrhenius Temperature Dependence
# ============================================================================

class TestSection02ReactionKineticsAndArrhenius:
    """Verify forward and reverse reaction kinetics, Arrhenius temperature dependence, and activation energies."""

    def test_arrhenius_monotonic_temperature_dependence(self) -> None:
        """Rate constants increase monotonically with increasing temperature."""
        sim = Nylon66PolycondensationReactor()
        t_low_k = 200.0 + T_ZERO_CELSIUS
        t_nom_k = 220.0 + T_ZERO_CELSIUS
        t_high_k = 240.0 + T_ZERO_CELSIUS

        kf_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a_f, sim.config.activation_e_f_j_mol, t_low_k)
        kf_nom = sim.arrhenius_rate_constant(sim.config.arrhenius_a_f, sim.config.activation_e_f_j_mol, t_nom_k)
        kf_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a_f, sim.config.activation_e_f_j_mol, t_high_k)

        assert 0.0 < kf_low < kf_nom < kf_high

        kr_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a_r, sim.config.activation_e_r_j_mol, t_low_k)
        kr_nom = sim.arrhenius_rate_constant(sim.config.arrhenius_a_r, sim.config.activation_e_r_j_mol, t_nom_k)
        kr_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a_r, sim.config.activation_e_r_j_mol, t_high_k)

        assert 0.0 < kr_low < kr_nom < kr_high

    def test_forward_activation_energy_reconstruction(self) -> None:
        """Arrhenius equation allows exact mathematical reconstruction of forward activation energy Ea_f."""
        sim = Nylon66PolycondensationReactor()
        t1_k = 210.0 + T_ZERO_CELSIUS
        t2_k = 230.0 + T_ZERO_CELSIUS

        k1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a_f, sim.config.activation_e_f_j_mol, t1_k)
        k2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a_f, sim.config.activation_e_f_j_mol, t2_k)

        # Ea = -R * ln(k2/k1) / (1/T2 - 1/T1)
        recovered_ea = -R_GAS_CONST * math.log(k2 / k1) / ((1.0 / t2_k) - (1.0 / t1_k))
        assert math.isclose(recovered_ea, sim.config.activation_e_f_j_mol, rel_tol=1e-4)
        assert math.isclose(recovered_ea, 68000.0, rel_tol=1e-4)

    def test_reverse_activation_energy_reconstruction(self) -> None:
        """Arrhenius equation allows exact mathematical reconstruction of reverse activation energy Ea_r."""
        sim = Nylon66PolycondensationReactor()
        t1_k = 210.0 + T_ZERO_CELSIUS
        t2_k = 230.0 + T_ZERO_CELSIUS

        k1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a_r, sim.config.activation_e_r_j_mol, t1_k)
        k2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a_r, sim.config.activation_e_r_j_mol, t2_k)

        recovered_ea = -R_GAS_CONST * math.log(k2 / k1) / ((1.0 / t2_k) - (1.0 / t1_k))
        assert math.isclose(recovered_ea, sim.config.activation_e_r_j_mol, rel_tol=1e-4)
        assert math.isclose(recovered_ea, 94000.0, rel_tol=1e-4)

    def test_compute_kinetics_nominal_rates_and_thermal_duty(self) -> None:
        """compute_kinetics produces positive forward, reverse, and net rates, and exothermic thermal duty."""
        sim = Nylon66PolycondensationReactor()
        kin = sim.compute_kinetics(
            t_reactor_k=220.0 + T_ZERO_CELSIUS,
            c_ada=0.153775,
            c_hmda=0.153775,
            c_prep=1.896565,
            c_water=0.450000,
        )

        assert kin["r_f"] > 0.0
        assert kin["r_r"] > 0.0
        assert kin["r_net"] > 0.0
        assert kin["r_f"] > kin["r_r"]  # Forward rate exceeds reverse rate at steady-state
        assert kin["r_net_tot"] > 0.0
        assert kin["q_rxn_kw"] > 0.0    # Exothermic amidation delivers positive heat generation
        assert math.isclose(kin["q_rxn_kw"], 164.369, rel_tol=0.01)

    def test_kinetics_zero_when_inactive(self) -> None:
        """Reaction rates are zero when nylon_reactor_active is False."""
        sim = Nylon66PolycondensationReactor()
        sim.state.nylon_reactor_active = False
        kin = sim.compute_kinetics(
            t_reactor_k=220.0 + T_ZERO_CELSIUS,
            c_ada=0.153775,
            c_hmda=0.153775,
            c_prep=1.896565,
            c_water=0.450000,
        )
        assert kin["r_f"] == 0.0
        assert kin["r_r"] == 0.0
        assert kin["r_net"] == 0.0
        assert kin["q_rxn_kw"] == 0.0


# ============================================================================
# Section 3: Reactor Geometry, Sizing, Thermal Capacitance & Operating Baseline
# ============================================================================

class TestSection03ReactorGeometryAndParameters:
    """Verify continuous autoclave geometry, residence time, thermal capacitance, and baseline configuration."""

    def test_default_configuration_geometry(self) -> None:
        """Default configuration parameters reflect industrial 12 m3 autoclave with 1.0 hour residence time."""
        cfg = Nylon66PolycondensationConfig()
        assert cfg.reactor_volume_m3 == 12.0
        assert cfg.nominal_residence_time_s == 3600.0
        assert cfg.melt_density_kg_m3 == 1080.0
        assert cfg.melt_specific_heat_cp_j_kg_k == 2450.0

    def test_thermal_capacitance_consistency(self) -> None:
        """Vessel + melt thermal capacitance matches mass times specific heat product."""
        cfg = Nylon66PolycondensationConfig()
        # V * rho * Cp = 12 m3 * 1080 kg/m3 * 2.45 kJ/(kg*K) = 31,752 kJ/K
        expected_cth = (cfg.reactor_volume_m3 * cfg.melt_density_kg_m3 * cfg.melt_specific_heat_cp_j_kg_k) / 1000.0
        assert math.isclose(cfg.reactor_thermal_capacitance_kj_k, expected_cth, rel_tol=1e-5)

    def test_nominal_feed_stream_rates(self) -> None:
        """Feed stream rates are configured for equimolar AH salt polycondensation."""
        cfg = Nylon66PolycondensationConfig()
        assert math.isclose(cfg.nominal_ada_feed_rate_mol_s, 6.834468, rel_tol=1e-5)
        assert math.isclose(cfg.nominal_hmda_feed_rate_mol_s, 6.834468, rel_tol=1e-5)
        assert math.isclose(cfg.nominal_ada_feed_rate_mol_s / cfg.nominal_hmda_feed_rate_mol_s, 1.0, rel_tol=1e-5)
        assert cfg.nominal_inlet_temp_c == 185.0

    def test_safety_interlock_threshold_constants(self) -> None:
        """Safety interlock thresholds match official design specifications."""
        assert T_OVERTEMP_GELATION_TRIP_C == 245.0
        assert P_OVERPRESSURE_TRIP_BAR == 22.00
        assert SALT_RATIO_IMBALANCE_LOW == 0.980
        assert SALT_RATIO_IMBALANCE_HIGH == 1.020
        assert STEAM_BLEED_FAULT_LOW_KG_H == 500.0
        assert SALT_RATIO_PRE_ALARM_LOW == 0.990
        assert SALT_RATIO_PRE_ALARM_HIGH == 1.010


# ============================================================================
# Section 4: Nominal Steady-State Closed-Loop Convergence
# ============================================================================

class TestSection04SteadyStateConvergence:
    """Verify nominal steady-state convergence: Conversion >= 90.0%, Temp 220.0 °C, Pressure 18.0 bar."""

    def test_nominal_steady_state_temperatures_and_pressures(self) -> None:
        """Nominal reactor temperature is 220.0 °C and autoclave pressure is 18.00 bar."""
        sim = Nylon66PolycondensationReactor()
        assert math.isclose(sim.state.t_reactor_c, 220.0, abs_tol=0.1)
        assert math.isclose(sim.state.p_reactor_bar, 18.00, abs_tol=0.05)

    def test_nominal_conversion_and_degree_of_polymerization(self) -> None:
        """Amide conversion >= 90.0% (nominal 92.50%) and number-average DP is ~13.3."""
        sim = Nylon66PolycondensationReactor()
        assert sim.state.amide_conversion_pct >= 90.0
        assert math.isclose(sim.state.amide_conversion_pct, 92.50, abs_tol=0.1)
        assert math.isclose(sim.state.number_avg_dp, 13.3, abs_tol=0.1)

    def test_nominal_steam_bleed_and_melt_viscosity(self) -> None:
        """Nominal steam bleed rate is 820 kg/h, salt ratio is 1.000, and melt viscosity is 45.0 Pa.s."""
        sim = Nylon66PolycondensationReactor()
        assert math.isclose(sim.state.steam_bleed_rate_kg_h, 820.0, abs_tol=5.0)
        assert math.isclose(sim.state.salt_stoichiometric_ratio, 1.000, abs_tol=0.005)
        assert math.isclose(sim.state.melt_viscosity_pa_s, 45.0, abs_tol=1.0)
        assert math.isclose(sim.state.heating_duty_kw, 685.0, abs_tol=1.0)

    def test_nominal_coils_and_diagnostic_state(self) -> None:
        """Nominal state asserts %M508, clears %M509, %M510, and sets diagnostic code to OK."""
        sim = Nylon66PolycondensationReactor()
        assert sim.state.nylon_reactor_active is True
        assert sim.state.salt_ratio_pre_alarm is False
        assert sim.state.emergency_autoclave_vent_open is False
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_property_aliases_on_state(self) -> None:
        """State provides standard property getters and setters for compatibility."""
        st = Nylon66PolycondensationState()
        assert st.conversion_pct == st.amide_conversion_pct
        st.conversion_pct = 94.0
        assert st.amide_conversion_pct == 94.0

        assert st.dp_n == st.number_avg_dp
        st.dp_n = 15.0
        assert st.number_avg_dp == 15.0

        assert st.salt_ratio == st.salt_stoichiometric_ratio
        st.salt_ratio = 1.005
        assert st.salt_stoichiometric_ratio == 1.005

        assert st.melt_viscosity == st.melt_viscosity_pa_s
        st.melt_viscosity = 48.0
        assert st.melt_viscosity_pa_s == 48.0

        assert st.reactor_active == st.nylon_reactor_active
        st.reactor_active = False
        assert st.nylon_reactor_active is False

        assert st.vent_open == st.emergency_autoclave_vent_open
        st.vent_open = True
        assert st.emergency_autoclave_vent_open is True


# ============================================================================
# Section 5: Coupled 6-State Dynamic ODE System, Derivatives & RK4 Integrator
# ============================================================================

class TestSection05DynamicODESystem:
    """Verify coupled 6-state ODE derivative evaluation, RK4 integration, and non-negativity."""

    def test_compute_derivatives_returns_six_valid_rates(self) -> None:
        """compute_derivatives evaluates dy/dt for all 6 physical states without NaN/Inf."""
        sim = Nylon66PolycondensationReactor()
        y = [0.153775, 0.153775, 1.896565, 0.45, 0.615102, 220.0]
        dy = sim.compute_derivatives(0.0, y)
        assert len(dy) == 6
        for d in dy:
            assert isinstance(d, float)
            assert not math.isnan(d)
            assert not math.isinf(d)

    def test_steady_state_derivatives_near_zero(self) -> None:
        """At nominal steady-state conditions, state derivatives are virtually zero (< 1e-4)."""
        sim = Nylon66PolycondensationReactor()
        y = [
            sim.state.c_ada,
            sim.state.c_hmda,
            sim.state.c_prepolymer,
            sim.state.c_water,
            sim.state.c_endgroups,
            sim.state.t_reactor_c,
        ]
        dy = sim.compute_derivatives(0.0, y)
        # Derivatives for concentrations in mol/(L*s) and temperature in °C/s
        assert abs(dy[0]) < 1e-4
        assert abs(dy[1]) < 1e-4
        assert abs(dy[5]) < 1e-3

    def test_scan_step_advances_clock_and_cycles(self) -> None:
        """scan_step advances sim_time_s by dt and increments cycle_count."""
        sim = Nylon66PolycondensationReactor()
        t0 = sim.state.sim_time_s
        c0 = sim.state.cycle_count
        sim.scan_step(dt=0.02)
        assert math.isclose(sim.state.sim_time_s, t0 + 0.02, rel_tol=1e-6)
        assert sim.state.cycle_count == c0 + 1

    def test_step_method_advances_clock_and_cycles(self) -> None:
        """step() advances clock and increments cycle_count."""
        sim = Nylon66PolycondensationReactor()
        t0 = sim.state.sim_time_s
        sim.step(dt=0.02)
        assert math.isclose(sim.state.sim_time_s, t0 + 0.02, rel_tol=1e-6)
        assert sim.state.cycle_count == 1

    def test_non_negativity_enforcement(self) -> None:
        """RK4 solver enforces strict non-negativity (C >= 0.0) on all chemical species."""
        sim = Nylon66PolycondensationReactor()
        # Set negative concentrations to test non-negative clamping
        sim.state.c_ada = -0.5
        sim.state.c_hmda = -1.0
        sim.state.c_prepolymer = -2.0
        sim.state.c_water = -0.1
        sim.state.c_endgroups = -0.2
        sim.rk4_step(dt=0.02)

        assert sim.state.c_ada >= 0.0
        assert sim.state.c_hmda >= 0.0
        assert sim.state.c_prepolymer >= 0.0
        assert sim.state.c_water >= 0.0
        assert sim.state.c_endgroups >= 0.0


# ============================================================================
# Section 6: Mathematical Conservation Residuals (< 1e-10)
# ============================================================================

class TestSection06ConservationLaws:
    """Verify strict stoichiometric mass, elemental (C/H/O/N), and enthalpy conservation residuals (< 1e-10)."""

    def test_stoichiometric_mass_balance_residual(self) -> None:
        """Stoichiometric mass balance residual is strictly < 1e-10 kg/s."""
        sim = Nylon66PolycondensationReactor()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1e-10
        assert sim.state.total_mass_balance_residual_kg_s >= 0.0

    def test_elemental_mass_balance_residual(self) -> None:
        """Elemental mass balance residual across C, H, O, N is strictly < 1e-10 kg/s."""
        sim = Nylon66PolycondensationReactor()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10
        assert sim.state.elemental_mass_balance_residual_kg_s >= 0.0

    def test_first_law_enthalpy_conservation_residual(self) -> None:
        """First-law energy conservation residual is strictly < 1e-10 kW."""
        sim = Nylon66PolycondensationReactor()
        sim._update_conservation_residuals()
        assert sim.state.enthalpy_conservation_residual_kw < 1e-10
        assert sim.state.enthalpy_conservation_residual_kw >= 0.0

    def test_conservation_residuals_maintained_over_steps(self) -> None:
        """Conservation residuals remain below 1e-10 threshold across multiple dynamic simulation steps."""
        sim = Nylon66PolycondensationReactor()
        for _ in range(20):
            sim.rk4_step(dt=0.02)
            assert sim.state.total_mass_balance_residual_kg_s < 1e-10
            assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10
            assert sim.state.enthalpy_conservation_residual_kw < 1e-10


# ============================================================================
# Section 7: Process Safety Interlocks & Strict Priority Hierarchy
# ============================================================================

class TestSection07SafetyInterlocksAndPriority:
    """Verify process safety trips, interlocks, and strict priority hierarchy (0xF601 > 0xF602 > 0xF603 > 0xF604 > 0x0000)."""

    def test_priority_1_overtemp_gelation_trip(self) -> None:
        """Temperature > 245.0 °C asserts 0xF601 OVERTEMP_GELATION_TRIP, opens vent %M510, clears %M508."""
        sim = Nylon66PolycondensationReactor()
        sim.state.t_reactor_c = 248.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERTEMP_GELATION_TRIP
        assert sim.state.emergency_autoclave_vent_open is True
        assert sim.state.nylon_reactor_active is False

    def test_priority_2_overpressure_trip(self) -> None:
        """Pressure > 22.00 bar asserts 0xF602 OVERPRESSURE_TRIP, opens vent %M510, clears %M508."""
        sim = Nylon66PolycondensationReactor()
        sim.state.p_reactor_bar = 23.50
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERPRESSURE_TRIP
        assert sim.state.emergency_autoclave_vent_open is True
        assert sim.state.nylon_reactor_active is False

    def test_priority_3_stoichiometric_imbalance_fault_low(self) -> None:
        """Salt stoichiometric ratio < 0.980 asserts 0xF603, activates pre-alarm %M509, keeps vent closed."""
        sim = Nylon66PolycondensationReactor()
        sim.state.salt_stoichiometric_ratio = 0.965
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.STOICHIOMETRIC_IMBALANCE_FAULT
        assert sim.state.salt_ratio_pre_alarm is True
        assert sim.state.emergency_autoclave_vent_open is False

    def test_priority_3_stoichiometric_imbalance_fault_high(self) -> None:
        """Salt stoichiometric ratio > 1.020 asserts 0xF603 and activates pre-alarm %M509."""
        sim = Nylon66PolycondensationReactor()
        sim.state.salt_stoichiometric_ratio = 1.035
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.STOICHIOMETRIC_IMBALANCE_FAULT
        assert sim.state.salt_ratio_pre_alarm is True

    def test_priority_4_condenser_pressure_fault(self) -> None:
        """Steam bleed rate < 500.0 kg/h asserts 0xF604 CONDENSER_PRESSURE_FAULT when active."""
        sim = Nylon66PolycondensationReactor()
        sim.state.steam_bleed_rate_kg_h = 420.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.CONDENSER_PRESSURE_FAULT
        assert sim.state.emergency_autoclave_vent_open is False

    def test_priority_1_overrides_priority_2_3_4(self) -> None:
        """Overtemp (P1) overrides simultaneous overpressure (P2), imbalance (P3), and condenser fault (P4)."""
        sim = Nylon66PolycondensationReactor()
        sim.state.t_reactor_c = 250.0                # P1
        sim.state.p_reactor_bar = 24.0               # P2
        sim.state.salt_stoichiometric_ratio = 0.95   # P3
        sim.state.steam_bleed_rate_kg_h = 300.0      # P4
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERTEMP_GELATION_TRIP
        assert sim.state.emergency_autoclave_vent_open is True
        assert sim.state.nylon_reactor_active is False

    def test_priority_2_overrides_priority_3_4(self) -> None:
        """Overpressure (P2) overrides simultaneous stoichiometric imbalance (P3) and condenser fault (P4)."""
        sim = Nylon66PolycondensationReactor()
        sim.state.t_reactor_c = 220.0                # Normal
        sim.state.p_reactor_bar = 23.50              # P2
        sim.state.salt_stoichiometric_ratio = 0.95   # P3
        sim.state.steam_bleed_rate_kg_h = 300.0      # P4
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERPRESSURE_TRIP
        assert sim.state.emergency_autoclave_vent_open is True
        assert sim.state.nylon_reactor_active is False

    def test_priority_3_overrides_priority_4(self) -> None:
        """Stoichiometric imbalance (P3) overrides simultaneous condenser fault (P4)."""
        sim = Nylon66PolycondensationReactor()
        sim.state.t_reactor_c = 220.0                # Normal
        sim.state.p_reactor_bar = 18.00              # Normal
        sim.state.salt_stoichiometric_ratio = 0.96   # P3
        sim.state.steam_bleed_rate_kg_h = 350.0      # P4
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.STOICHIOMETRIC_IMBALANCE_FAULT
        assert sim.state.emergency_autoclave_vent_open is False

    def test_heating_duty_cut_off_on_emergency_vent(self) -> None:
        """Jacket heating duty is completely isolated (0 kW) when emergency autoclave vent is open."""
        sim = Nylon66PolycondensationReactor()
        sim.state.t_reactor_c = 250.0
        sim._evaluate_safety_interlocks()
        sim._update_derived_variables()
        assert sim.state.heating_duty_kw == 0.0
        assert sim.state.q_jacket_kw == 0.0


# ============================================================================
# Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality, String & Bitwise Masking
# ============================================================================

class TestSection08DiagnosticCodeMasking:
    """Verify DiagnosticCode signed/unsigned 16-bit values, integer equality, bitwise masking, and string formatting."""

    def test_diagnostic_code_hexadecimal_values(self) -> None:
        """Diagnostic codes have correct hexadecimal values."""
        assert DiagnosticCode.OK.value == 0x0000
        assert DiagnosticCode.OVERTEMP_GELATION_TRIP.value == 0xF601
        assert DiagnosticCode.OVERPRESSURE_TRIP.value == 0xF602
        assert DiagnosticCode.STOICHIOMETRIC_IMBALANCE_FAULT.value == 0xF603
        assert DiagnosticCode.CONDENSER_PRESSURE_FAULT.value == 0xF604

    def test_unsigned_integer_equality(self) -> None:
        """DiagnosticCode compares equal to unsigned integer literals."""
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.OVERTEMP_GELATION_TRIP == 0xF601
        assert DiagnosticCode.OVERPRESSURE_TRIP == 0xF602
        assert DiagnosticCode.STOICHIOMETRIC_IMBALANCE_FAULT == 0xF603
        assert DiagnosticCode.CONDENSER_PRESSURE_FAULT == 0xF604

    def test_signed_integer_equality(self) -> None:
        """DiagnosticCode compares equal to signed 16-bit integer values."""
        # 0xF601 - 0x10000 = -2559
        assert DiagnosticCode.OVERTEMP_GELATION_TRIP == -2559
        # 0xF602 - 0x10000 = -2558
        assert DiagnosticCode.OVERPRESSURE_TRIP == -2558
        # 0xF603 - 0x10000 = -2557
        assert DiagnosticCode.STOICHIOMETRIC_IMBALANCE_FAULT == -2557
        # 0xF604 - 0x10000 = -2556
        assert DiagnosticCode.CONDENSER_PRESSURE_FAULT == -2556

    def test_bitwise_masking_with_0xffff(self) -> None:
        """Bitwise AND with 0xFFFF yields unsigned 16-bit word."""
        assert (DiagnosticCode.OVERTEMP_GELATION_TRIP & 0xFFFF) == 0xF601
        assert (0xFFFF & DiagnosticCode.OVERTEMP_GELATION_TRIP) == 0xF601
        assert (DiagnosticCode.OVERPRESSURE_TRIP & 0xFFFF) == 0xF602
        assert (DiagnosticCode.STOICHIOMETRIC_IMBALANCE_FAULT & 0xFFFF) == 0xF603
        assert (DiagnosticCode.CONDENSER_PRESSURE_FAULT & 0xFFFF) == 0xF604

    def test_diagnostic_code_signed_lookup(self) -> None:
        """DiagnosticCode constructor accepts signed 16-bit integers transparently."""
        assert DiagnosticCode(-2559) == DiagnosticCode.OVERTEMP_GELATION_TRIP
        assert DiagnosticCode(-2558) == DiagnosticCode.OVERPRESSURE_TRIP
        assert DiagnosticCode(-2557) == DiagnosticCode.STOICHIOMETRIC_IMBALANCE_FAULT
        assert DiagnosticCode(-2556) == DiagnosticCode.CONDENSER_PRESSURE_FAULT

    def test_string_and_repr_representations(self) -> None:
        """DiagnosticCode str and repr contain hexadecimal code and name."""
        code = DiagnosticCode.OVERTEMP_GELATION_TRIP
        assert "0xF601" in str(code)
        assert "OVERTEMP_GELATION_TRIP" in repr(code)
        assert code.name == "OVERTEMP_GELATION_TRIP"

    def test_diagnostic_code_aliases(self) -> None:
        """Diagnostic code aliases resolve to the same underlying enum class."""
        assert Nylon66PolycondensationDiagnosticCode is DiagnosticCode
        assert Nylon66DiagnosticCode is DiagnosticCode
        assert NylonDiagnosticCode is DiagnosticCode
        assert NylonDiagCode is DiagnosticCode

    def test_status_bits_bitmask(self) -> None:
        """Status bits support bitwise operations and match defined bit flags."""
        bits = Nylon66PolycondensationStatusBits.RUNNING | Nylon66PolycondensationStatusBits.OVERTEMP_GELATION_TRIP
        assert bool(bits & Nylon66PolycondensationStatusBits.RUNNING) is True
        assert bool(bits & Nylon66PolycondensationStatusBits.OVERTEMP_GELATION_TRIP) is True
        assert bool(bits & Nylon66PolycondensationStatusBits.OVERPRESSURE_TRIP) is False


# ============================================================================
# Section 9: Pre-Alarm Logic (%M509) & Emergency Autoclave Vent Actuation (%M510)
# ============================================================================

class TestSection09PreAlarmAndVentActuation:
    """Verify pre-alarm %M509 and emergency autoclave vent valve %M510 behavior."""

    def test_pre_alarm_low_threshold_activation(self) -> None:
        """Pre-alarm %M509 activates when salt ratio is between 0.980 and 0.990 while diag is OK."""
        sim = Nylon66PolycondensationReactor()
        sim.state.salt_stoichiometric_ratio = 0.985
        sim._evaluate_safety_interlocks()
        assert sim.state.salt_ratio_pre_alarm is True
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_pre_alarm_high_threshold_activation(self) -> None:
        """Pre-alarm %M509 activates when salt ratio is between 1.010 and 1.020 while diag is OK."""
        sim = Nylon66PolycondensationReactor()
        sim.state.salt_stoichiometric_ratio = 1.015
        sim._evaluate_safety_interlocks()
        assert sim.state.salt_ratio_pre_alarm is True
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_pre_alarm_cleared_in_nominal_band(self) -> None:
        """Pre-alarm %M509 is False when salt ratio is within nominal [0.990, 1.010] band."""
        sim = Nylon66PolycondensationReactor()
        sim.state.salt_stoichiometric_ratio = 1.000
        sim._evaluate_safety_interlocks()
        assert sim.state.salt_ratio_pre_alarm is False

    def test_emergency_vent_valve_depressurizes_vessel(self) -> None:
        """Opening emergency vent valve decreases vessel pressure over simulation steps."""
        sim = Nylon66PolycondensationReactor()
        sim.state.t_reactor_c = 250.0  # triggers 0xF601 and opens vent
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_autoclave_vent_open is True

        p_initial = sim.state.p_reactor_bar
        for _ in range(5):
            sim.rk4_step(dt=0.02)
        assert sim.state.p_reactor_bar < p_initial


# ============================================================================
# Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege (%R2180..%R2187, %M508..%M510)
# ============================================================================

class TestSection10RegisterTableSync:
    """Verify register table mapping and synchronization to %R2180..%R2187 and %M508..%M510."""

    def test_register_channel_constant_definitions(self) -> None:
        """Register and coil addresses match Horner OCS hardware mapping."""
        assert REG_NYLON_REACTOR_TEMP_SCALED == "%R2180"
        assert REG_NYLON_REACTOR_PRESSURE_SCALED == "%R2181"
        assert REG_AMIDE_CONVERSION_SCALED == "%R2182"
        assert REG_NUMBER_AVG_DP_SCALED == "%R2183"
        assert REG_STEAM_BLEED_RATE_SCALED == "%R2184"
        assert REG_SALT_STOICHIOMETRIC_RATIO_SCALED == "%R2185"
        assert REG_MELT_VISCOSITY_SCALED == "%R2186"
        assert REG_NYLON_DIAGNOSTIC_CODE == "%R2187"
        assert COIL_NYLON_REACTOR_ACTIVE == "%M508"
        assert COIL_SALT_RATIO_PRE_ALARM == "%M509"
        assert COIL_EMERGENCY_AUTOCLAVE_VENT_OPEN == "%M510"

    def test_nominal_register_table_synchronization(self) -> None:
        """Nominal state synchronizes exactly to %R2180..%R2187 and %M508..%M510."""
        table = RegisterTable()
        sim = Nylon66PolycondensationReactor(register_table=table)
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        assert table.read_word("%R2180") == 2200   # 220.0 °C * 10
        assert table.read_word("%R2181") == 1800   # 18.00 bar * 100
        assert table.read_word("%R2182") == 9250   # 92.50 % * 100
        assert table.read_word("%R2183") == 133    # 13.3 DP * 10
        assert table.read_word("%R2184") == 820    # 820 kg/h
        assert table.read_word("%R2185") == 1000   # 1.000 ratio * 1000
        assert table.read_word("%R2186") == 450    # 45.0 Pa.s * 10
        assert table.read_uword("%R2187") == 0x0000# OK
        assert table.read_bit("%M508") is True     # Active
        assert table.read_bit("%M509") is False    # Pre-alarm inactive
        assert table.read_bit("%M510") is False    # Emergency vent closed

    def test_fault_register_synchronization_signed_and_unsigned(self) -> None:
        """Trip condition synchronizes signed 16-bit fault value into %R2187 and asserts %M510."""
        table = RegisterTable()
        sim = Nylon66PolycondensationReactor(register_table=table)
        sim.state.t_reactor_c = 250.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        assert table.read_uword("%R2187") == 0xF601
        assert table.read_word("%R2187") == -2559
        assert table.read_bit("%M508") is False
        assert table.read_bit("%M510") is True

    def test_system_privilege_mode_enforcement(self) -> None:
        """sync_to_registers succeeds when table requires system privilege."""
        table = RegisterTable()
        table.privilege_mode = PrivilegeMode.USER
        sim = Nylon66PolycondensationReactor()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R2180") == 2200


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text POU & Variable Bindings
# ============================================================================

class TestSection11PureSTPOU:
    """Verify Pure IEC 61131-3 Structured Text POU, variable bindings, and syntax validation."""

    def test_st_pou_constant_definition(self) -> None:
        """NYLON66_POLYCONDENSATION_PURE_ST_POU is non-empty and contains PROGRAM Nylon66PolycondensationSync."""
        assert isinstance(NYLON66_POLYCONDENSATION_PURE_ST_POU, str)
        assert "PROGRAM Nylon66PolycondensationSync" in NYLON66_POLYCONDENSATION_PURE_ST_POU
        assert "END_PROGRAM" in NYLON66_POLYCONDENSATION_PURE_ST_POU

    def test_st_pou_aliases(self) -> None:
        """POU string constants are properly aliased."""
        assert NYLON66_PURE_ST_POU == NYLON66_POLYCONDENSATION_PURE_ST_POU
        assert NYLON66_SYNC_POU == NYLON66_POLYCONDENSATION_PURE_ST_POU
        assert NYLON_PURE_ST_POU == NYLON66_POLYCONDENSATION_PURE_ST_POU
        assert NYLON_SYNC_POU == NYLON66_POLYCONDENSATION_PURE_ST_POU

    def test_security_guard_assert_pure_st(self) -> None:
        """SecurityGuard passes pure ST POU without raising LadderForbiddenError."""
        SecurityGuard.assert_pure_st_content(NYLON66_POLYCONDENSATION_PURE_ST_POU)

    def test_st_parser_validation(self) -> None:
        """STParser validates POU syntax with AgentStatus.SUCCESS."""
        res = STParser.validate_code(NYLON66_POLYCONDENSATION_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_st_parser_pou_structure_and_bindings(self) -> None:
        """STParser parses POU structure and verifies all 11 register/coil bindings."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(NYLON66_POLYCONDENSATION_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "Nylon66PolycondensationSync"
        assert pou.pou_type == POUType.PROGRAM

        expected_bindings = [
            "%R2180", "%R2181", "%R2182", "%R2183",
            "%R2184", "%R2185", "%R2186", "%R2187",
            "%M508", "%M509", "%M510",
        ]
        for reg in expected_bindings:
            assert reg in pou.bound_registers

    def test_verify_nylon66_polycondensation_pure_st_function(self) -> None:
        """verify_nylon66_polycondensation_pure_st returns True and AgentStatus.SUCCESS."""
        val = verify_nylon66_polycondensation_pure_st()
        assert bool(val) is True
        assert val == AgentStatus.SUCCESS
        assert verify_nylon66_pure_st() == AgentStatus.SUCCESS
        assert verify_nylon_polycondensation_pure_st() == AgentStatus.SUCCESS
        assert validate_pure_st() == AgentStatus.SUCCESS


# ============================================================================
# Section 12: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection12AntiLadderRejection:
    """Verify anti-ladder security guard rejects contacts, coils, rungs, networks, and mnemonics."""

    def test_anti_ladder_contacts_rejection(self) -> None:
        """Ladder logic contacts |---[ ]---| are rejected with LadderForbiddenError."""
        bad_code = "PROGRAM L1\nVAR b: BOOL; END_VAR\n|---[ ]---|\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_coils_rejection(self) -> None:
        """Ladder logic coils |---( )---| are rejected with LadderForbiddenError."""
        bad_code = "PROGRAM L2\nVAR b: BOOL; END_VAR\n|---( )---|\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rungs_rejection(self) -> None:
        """Ladder RUNG keywords are rejected with LadderForbiddenError."""
        bad_code = "PROGRAM L3\nRUNG 1\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_networks_rejection(self) -> None:
        """Ladder NETWORK keywords are rejected with LadderForbiddenError."""
        bad_code = "PROGRAM L4\nNETWORK 1\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_mnemonics_rejection(self) -> None:
        """Ladder mnemonics (XIC, OTE) are rejected with LadderForbiddenError."""
        bad_code = "PROGRAM L5\nXIC(Start) OTE(Run);\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)


# ============================================================================
# Section 13: ILogicUnit Scan Cycle Execution, Reset Dynamics & 100-Cycle Soak Stability
# ============================================================================

class TestSection13ILogicUnitProtocol:
    """Verify ILogicUnit protocol compliance, reset behavior, and 100-cycle soak stability."""

    def test_ilogicunit_inheritance(self) -> None:
        """Nylon66PolycondensationReactor implements ILogicUnit interface."""
        sim = Nylon66PolycondensationReactor()
        assert isinstance(sim, ILogicUnit)
        assert sim.name == "Nylon66PolycondensationReactor"
        assert sim.priority == 257
        assert sim.is_enabled is True

    def test_enable_disable(self) -> None:
        """enable() and disable() toggle is_enabled property."""
        sim = Nylon66PolycondensationReactor()
        sim.disable()
        assert sim.is_enabled is False
        sim.enable()
        assert sim.is_enabled is True

    def test_scan_step_with_context(self) -> None:
        """scan_step executes properly with ScanContext."""
        sim = Nylon66PolycondensationReactor()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        sim.scan_step(dt=0.02, context=ctx)
        assert sim.state.cycle_count == 1

    def test_execute_method(self) -> None:
        """execute(context) executes scan cycle."""
        sim = Nylon66PolycondensationReactor()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        sim.execute(ctx)
        assert sim.state.cycle_count == 1

    def test_reset_method(self) -> None:
        """reset() restores initial steady-state conditions and clears fault states."""
        sim = Nylon66PolycondensationReactor()
        sim.state.t_reactor_c = 250.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERTEMP_GELATION_TRIP

        sim.reset()
        assert math.isclose(sim.state.t_reactor_c, 220.0, abs_tol=0.1)
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.nylon_reactor_active is True
        assert sim.state.emergency_autoclave_vent_open is False

    def test_logic_unit_wrapper(self) -> None:
        """Nylon66PolycondensationLogicUnit implements ILogicUnit and delegates to simulator."""
        unit = Nylon66PolycondensationLogicUnit()
        assert isinstance(unit, ILogicUnit)
        assert unit.name == "Nylon66PolycondensationLogicUnit"
        assert unit.priority == 257
        assert unit.is_enabled is True

        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        unit.execute(ctx)
        assert unit.simulator.state.cycle_count == 1

        unit.reset()
        assert unit.simulator.state.diagnostic_code == DiagnosticCode.OK

    def test_100_cycle_soak_stability(self) -> None:
        """100-cycle soak simulation maintains bounded state without numerical drift or NaNs."""
        sim = Nylon66PolycondensationReactor()
        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt_ms=20.0, elapsed_time_ms=cycle * 20.0, dt=0.02)
            sim.execute(ctx)

        # Verification bounds
        assert 219.0 <= sim.state.t_reactor_c <= 221.0
        assert sim.state.amide_conversion_pct >= 90.0
        assert 17.50 <= sim.state.p_reactor_bar <= 18.50
        assert not math.isnan(sim.state.t_reactor_c)
        assert not math.isnan(sim.state.c_ada)
        assert not math.isnan(sim.state.c_prepolymer)
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.nylon_reactor_active is True

    def test_class_aliases(self) -> None:
        """Class aliases map to the standard implementation classes."""
        assert Nylon66Polycondensation is Nylon66PolycondensationReactor
        assert Nylon66Reactor is Nylon66PolycondensationReactor
        assert NylonPolycondensationReactor is Nylon66PolycondensationReactor
        assert NylonPolycondensation is Nylon66PolycondensationReactor
        assert Nylon66PolycondensationModel is Nylon66PolycondensationReactor
        assert Nylon66PolycondensationSimulator is Nylon66PolycondensationReactor
        assert Nylon66PolycondensationEngine is Nylon66PolycondensationReactor
        assert Nylon66PolycondensationPlantModel is Nylon66PolycondensationReactor
        assert NylonLogicUnit is Nylon66PolycondensationLogicUnit


# ============================================================================
# Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
# ============================================================================

class TestSection14Deterministic9StageVerification:
    """Verify run_nylon66_polycondensation_verification execution, evidence structure, and artifact generation."""

    def test_verification_suite_success(self) -> None:
        """run_nylon66_polycondensation_verification returns AgentStatus.SUCCESS and all 9 stages pass."""
        res = run_nylon66_polycondensation_verification()
        assert res["status"] == AgentStatus.SUCCESS.value
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert res["data"]["work_package"] == "W257"
        assert res["data"]["module"] == "jev_cscape.simulation.nylon66_polycondensation"

    def test_verification_evidence_json_generation(self, tmp_path: Path) -> None:
        """run_nylon66_polycondensation_verification writes valid JSON artifact to output_path."""
        target_json = tmp_path / "nylon66_polycondensation_evidence.json"
        res = run_nylon66_polycondensation_verification(output_path=target_json)

        assert target_json.exists()
        with open(target_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9
        assert len(data["data"]["stages"]) == 9

    def test_verification_function_aliases(self) -> None:
        """run_nylon66_verification and run_nylon_polycondensation_verification aliases work."""
        res1 = run_nylon66_verification()
        assert res1["status"] == "success"
        res2 = run_nylon_polycondensation_verification()
        assert res2["status"] == "success"

    def test_verification_with_evidence_path(self, tmp_path: Path) -> None:
        """run_nylon66_polycondensation_verification works with evidence_path argument."""
        target_json = tmp_path / "evidence_alt.json"
        res = run_nylon66_polycondensation_verification(evidence_path=target_json)
        assert res["status"] == "success"
        assert target_json.exists()


# ============================================================================
# Section 15: Edge Cases, Model Aliases & Parameter Sensitivity
# ============================================================================

class TestSection15EdgeCasesAndSensitivity:
    """Verify PureSTValidationResult semantics, custom configurations, and parameter sensitivities."""

    def test_pure_st_validation_result_semantics(self) -> None:
        """PureSTValidationResult supports boolean conversion and AgentStatus comparisons."""
        val_pass = PureSTValidationResult(True, status=AgentStatus.SUCCESS)
        assert bool(val_pass) is True
        assert val_pass == AgentStatus.SUCCESS
        assert val_pass == True

        val_fail = PureSTValidationResult(False, status=AgentStatus.FAILED, error="Syntax error")
        assert bool(val_fail) is False
        assert val_fail == AgentStatus.FAILED
        assert val_fail == False
        assert val_fail.error == "Syntax error"

    def test_diagnostic_code_edge_cases(self) -> None:
        """DiagnosticCode unknown lookups, hashing, and non-integer comparisons."""
        assert DiagnosticCode._missing_(999999) is None
        assert hash(DiagnosticCode.OVERTEMP_GELATION_TRIP) == hash(0xF601)
        assert (DiagnosticCode.OVERTEMP_GELATION_TRIP == "0xF601") is False
        assert (DiagnosticCode.OVERTEMP_GELATION_TRIP == None) is False

    def test_custom_config_override(self) -> None:
        """Custom reactor configuration parameters can be passed to Nylon66PolycondensationReactor."""
        custom_cfg = Nylon66PolycondensationConfig(
            reactor_volume_m3=20.0,
            jacket_heating_power_kw=750.0,
        )
        sim = Nylon66PolycondensationReactor(config=custom_cfg)
        assert sim.config.reactor_volume_m3 == 20.0
        assert sim.config.jacket_heating_power_kw == 750.0

    def test_disabled_reactor_skips_scan_step(self) -> None:
        """Disabled reactor does not advance cycle_count during scan_step."""
        sim = Nylon66PolycondensationReactor()
        sim.disable()
        c0 = sim.state.cycle_count
        sim.scan_step(dt=0.02)
        assert sim.state.cycle_count == c0


# ============================================================================
# Section 16: Comprehensive Diagnostics, Bitmasks, Thermodynamics & Transitions
# ============================================================================

class TestSection16ComprehensiveDeepCoverage:
    """Verify detailed string formatting, bitmasks, thermodynamic balances, Carothers DP, and fault transitions."""

    def test_all_diagnostic_codes_str_exact(self) -> None:
        """All 5 DiagnosticCode members format accurately into '0xXXXX (NAME)' strings."""
        assert str(DiagnosticCode.OK) == "0x0000 (OK)"
        assert str(DiagnosticCode.OVERTEMP_GELATION_TRIP) == "0xF601 (OVERTEMP_GELATION_TRIP)"
        assert str(DiagnosticCode.OVERPRESSURE_TRIP) == "0xF602 (OVERPRESSURE_TRIP)"
        assert str(DiagnosticCode.STOICHIOMETRIC_IMBALANCE_FAULT) == "0xF603 (STOICHIOMETRIC_IMBALANCE_FAULT)"
        assert str(DiagnosticCode.CONDENSER_PRESSURE_FAULT) == "0xF604 (CONDENSER_PRESSURE_FAULT)"

    def test_all_diagnostic_codes_bitwise_and(self) -> None:
        """Bitwise AND operations (& and __rand__) work with all DiagnosticCode members."""
        for code in DiagnosticCode:
            u_val = code.value & 0xFFFF
            assert (code & 0xFFFF) == u_val
            assert (0xFFFF & code) == u_val
            assert (code & code.value) == code.value

    def test_status_bits_individual_flags(self) -> None:
        """Each Nylon66PolycondensationStatusBits bit flag possesses unique bit position."""
        assert Nylon66PolycondensationStatusBits.RUNNING == 0x0001
        assert Nylon66PolycondensationStatusBits.NYLON_REACTOR_ACTIVE == 0x0002
        assert Nylon66PolycondensationStatusBits.SALT_RATIO_PRE_ALARM == 0x0004
        assert Nylon66PolycondensationStatusBits.EMERGENCY_VENT_OPEN == 0x0008
        assert Nylon66PolycondensationStatusBits.OVERTEMP_GELATION_TRIP == 0x0010
        assert Nylon66PolycondensationStatusBits.OVERPRESSURE_TRIP == 0x0020
        assert Nylon66PolycondensationStatusBits.STOICHIOMETRIC_IMBALANCE_FAULT == 0x0040
        assert Nylon66PolycondensationStatusBits.CONDENSER_PRESSURE_FAULT == 0x0080

    def test_status_bits_aliases(self) -> None:
        """All StatusBits aliases map to Nylon66PolycondensationStatusBits."""
        assert NylonStatusBits is Nylon66PolycondensationStatusBits
        assert Nylon66StatusBits is Nylon66PolycondensationStatusBits
        assert NylonPolycondensationStatusBits is Nylon66PolycondensationStatusBits
        assert NylonStatusWord is Nylon66PolycondensationStatusBits

    def test_diagnostic_code_compatibility_aliases(self) -> None:
        """DiagnosticCode aliases for errors and faults resolve to the correct enum constants."""
        assert DiagnosticCode.OVERTEMP_GELATION == DiagnosticCode.OVERTEMP_GELATION_TRIP
        assert DiagnosticCode.OVER_TEMPERATURE_TRIP == DiagnosticCode.OVERTEMP_GELATION_TRIP
        assert DiagnosticCode.THERMAL_RUNAWAY == DiagnosticCode.OVERTEMP_GELATION_TRIP
        assert DiagnosticCode.OVERPRESSURE == DiagnosticCode.OVERPRESSURE_TRIP
        assert DiagnosticCode.PRESSURE_SURGE_TRIP == DiagnosticCode.OVERPRESSURE_TRIP
        assert DiagnosticCode.STOICHIOMETRIC_IMBALANCE == DiagnosticCode.STOICHIOMETRIC_IMBALANCE_FAULT
        assert DiagnosticCode.SALT_IMBALANCE_FAULT == DiagnosticCode.STOICHIOMETRIC_IMBALANCE_FAULT
        assert DiagnosticCode.CONDENSER_FAULT == DiagnosticCode.CONDENSER_PRESSURE_FAULT
        assert DiagnosticCode.STEAM_BLEED_FAULT == DiagnosticCode.CONDENSER_PRESSURE_FAULT
        assert DiagnosticCode.ERR_OVERTEMP_GELATION == DiagnosticCode.OVERTEMP_GELATION_TRIP
        assert DiagnosticCode.ERR_OVERPRESSURE == DiagnosticCode.OVERPRESSURE_TRIP
        assert DiagnosticCode.ERR_STOICHIOMETRIC_IMBALANCE == DiagnosticCode.STOICHIOMETRIC_IMBALANCE_FAULT
        assert DiagnosticCode.ERR_CONDENSER_PRESSURE == DiagnosticCode.CONDENSER_PRESSURE_FAULT

    def test_carothers_equation_progression(self) -> None:
        """Carothers relation DP_n = (1+r)/(1+r-2*r*p) produces expected values at r = 1.000."""
        r = 1.000
        # p = 0.50 -> DP = 2/(2 - 2*0.5) = 2.0
        dp_50 = (1.0 + r) / (1.0 + r - 2.0 * r * 0.50)
        assert math.isclose(dp_50, 2.0, rel_tol=1e-5)

        # p = 0.80 -> DP = 2/(2 - 2*0.8) = 5.0
        dp_80 = (1.0 + r) / (1.0 + r - 2.0 * r * 0.80)
        assert math.isclose(dp_80, 5.0, rel_tol=1e-5)

        # p = 0.90 -> DP = 2/(2 - 2*0.9) = 10.0
        dp_90 = (1.0 + r) / (1.0 + r - 2.0 * r * 0.90)
        assert math.isclose(dp_90, 10.0, rel_tol=1e-5)

        # p = 0.925 -> DP = 2/(2 - 2*0.925) = 13.333
        dp_925 = (1.0 + r) / (1.0 + r - 2.0 * r * 0.925)
        assert math.isclose(dp_925, 13.333333, rel_tol=1e-4)

    def test_melt_viscosity_temperature_dependence(self) -> None:
        """Melt viscosity decreases as temperature rises at fixed DP."""
        sim = Nylon66PolycondensationReactor()
        sim.state.t_reactor_c = 210.0
        sim._update_derived_variables()
        visc_low_temp = sim.state.melt_viscosity_pa_s

        sim.state.t_reactor_c = 230.0
        sim._update_derived_variables()
        visc_high_temp = sim.state.melt_viscosity_pa_s

        assert visc_low_temp > visc_high_temp > 0.0

    def test_priority_hierarchy_bidirectional_transitions(self) -> None:
        """Sequential fault escalation and clearing traverses strict priority hierarchy."""
        sim = Nylon66PolycondensationReactor()
        sim.reset()
        assert sim.state.diagnostic_code == DiagnosticCode.OK

        # 1. Escalation to Condenser Fault (P4)
        sim.state.steam_bleed_rate_kg_h = 400.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.CONDENSER_PRESSURE_FAULT

        # 2. Escalation to Stoichiometric Imbalance (P3)
        sim.state.salt_stoichiometric_ratio = 0.970
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.STOICHIOMETRIC_IMBALANCE_FAULT

        # 3. Escalation to Overpressure (P2)
        sim.state.p_reactor_bar = 23.00
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERPRESSURE_TRIP
        assert sim.state.emergency_autoclave_vent_open is True

        # 4. Escalation to Overtemp Gelation (P1)
        sim.state.t_reactor_c = 250.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERTEMP_GELATION_TRIP

        # 5. Clear P1 -> Falls back to P2
        sim.state.t_reactor_c = 220.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERPRESSURE_TRIP

        # 6. Clear P2 -> Falls back to P3
        sim.state.p_reactor_bar = 18.00
        sim.state.emergency_autoclave_vent_open = False
        sim.state.nylon_reactor_active = True
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.STOICHIOMETRIC_IMBALANCE_FAULT

        # 7. Clear P3 -> Falls back to P4
        sim.state.salt_stoichiometric_ratio = 1.000
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.CONDENSER_PRESSURE_FAULT

        # 8. Clear P4 -> Returns to OK (P5)
        sim.state.steam_bleed_rate_kg_h = 820.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_emergency_vent_thermal_cooling_effect(self) -> None:
        """Emergency vent valve opening generates positive cooling duty (q_vent_kw > 0)."""
        sim = Nylon66PolycondensationReactor()
        sim.state.t_reactor_c = 250.0
        sim.state.emergency_autoclave_vent_open = True
        dy = sim.compute_derivatives(0.0, [
            sim.state.c_ada,
            sim.state.c_hmda,
            sim.state.c_prepolymer,
            sim.state.c_water,
            sim.state.c_endgroups,
            sim.state.t_reactor_c,
        ])
        assert sim.state.q_vent_kw > 0.0
        # Cooling causes negative dT/dt
        assert dy[5] < 0.0

    def test_reset_fully_restores_clean_state(self) -> None:
        """Reset clears all fault coils, restores sim_time_s and cycle_count to zero, and resets code to OK."""
        sim = Nylon66PolycondensationReactor()
        sim.state.t_reactor_c = 260.0
        sim.state.p_reactor_bar = 25.0
        sim.state.sim_time_s = 500.0
        sim.state.cycle_count = 25000
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code != DiagnosticCode.OK

        sim.reset()
        assert sim.state.sim_time_s == 0.0
        assert sim.state.cycle_count == 0
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.nylon_reactor_active is True
        assert sim.state.emergency_autoclave_vent_open is False
        assert sim.state.salt_ratio_pre_alarm is False
        assert math.isclose(sim.state.t_reactor_c, 220.0, abs_tol=0.1)
        assert math.isclose(sim.state.p_reactor_bar, 18.00, abs_tol=0.05)

    def test_soak_state_conservation_laws_after_100_cycles(self) -> None:
        """Conservation laws (mass, elements, enthalpy) remain < 1e-10 throughout 100 soak scan cycles."""
        sim = Nylon66PolycondensationReactor()
        for c in range(1, 101):
            ctx = ScanContext(cycle=c, dt_ms=20.0, elapsed_time_ms=c * 20.0, dt=0.02)
            sim.execute(ctx)
            assert sim.state.total_mass_balance_residual_kg_s < 1e-10
            assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10
            assert sim.state.enthalpy_conservation_residual_kw < 1e-10

    def test_individual_word_registers_write_read(self) -> None:
        """All individual registers %R2180 through %R2186 can be written and read accurately."""
        table = RegisterTable()
        sim = Nylon66PolycondensationReactor(register_table=table)
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        assert table.read_word("%R2180") == 2200
        assert table.read_word("%R2181") == 1800
        assert table.read_word("%R2182") == 9250
        assert table.read_word("%R2183") == 133
        assert table.read_word("%R2184") == 820
        assert table.read_word("%R2185") == 1000
        assert table.read_word("%R2186") == 450

    def test_individual_coils_write_read(self) -> None:
        """Discrete coils %M508, %M509, %M510 can be read and reflect active state."""
        table = RegisterTable()
        sim = Nylon66PolycondensationReactor(register_table=table)
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        assert table.read_bit("%M508") is True
        assert table.read_bit("%M509") is False
        assert table.read_bit("%M510") is False

    def test_reaction_rate_constants_at_multiple_temperatures(self) -> None:
        """Forward and reverse rate constants evaluated at 200, 210, 220, 230, 240 °C are strictly monotonic."""
        sim = Nylon66PolycondensationReactor()
        temps_c = [200.0, 210.0, 220.0, 230.0, 240.0]
        kf_vals = [sim.arrhenius_rate_constant(sim.config.arrhenius_a_f, sim.config.activation_e_f_j_mol, tc + T_ZERO_CELSIUS) for tc in temps_c]
        kr_vals = [sim.arrhenius_rate_constant(sim.config.arrhenius_a_r, sim.config.activation_e_r_j_mol, tc + T_ZERO_CELSIUS) for tc in temps_c]

        for i in range(len(temps_c) - 1):
            assert kf_vals[i] < kf_vals[i + 1]
            assert kr_vals[i] < kr_vals[i + 1]

    def test_reaction_enthalpy_exothermicity(self) -> None:
        """Polycondensation reaction is exothermic (Delta H < 0) delivering heat to the melt."""
        assert DELTA_H_RXN_J_MOL < 0.0
        assert DELTA_H_RXN_KJ_MOL == -26.0

    def test_number_average_dp_with_stoichiometric_imbalance(self) -> None:
        """Stoichiometric imbalance (r != 1.000) limits maximum Carothers degree of polymerization."""
        sim = Nylon66PolycondensationReactor()
        sim.state.salt_stoichiometric_ratio = 0.900  # 10% deficiency
        sim._update_derived_variables()
        dp_imbalanced = sim.state.number_avg_dp

        sim.state.salt_stoichiometric_ratio = 1.000  # equimolar
        sim._update_derived_variables()
        dp_equimolar = sim.state.number_avg_dp

        assert dp_imbalanced < dp_equimolar

    def test_nominal_species_concentrations_consistency(self) -> None:
        """State contains non-zero residual concentrations for ADA, HMDA, Prepolymer, Water, and Endgroups."""
        sim = Nylon66PolycondensationReactor()
        assert sim.state.c_ada > 0.0
        assert sim.state.c_hmda > 0.0
        assert sim.state.c_prepolymer > 0.0
        assert sim.state.c_water > 0.0
        assert sim.state.c_endgroups > 0.0

    def test_rk4_step_finite_states_under_temperature_perturbation(self) -> None:
        """Perturbing reactor temperature to 215 °C or 225 °C converges stably without diverging."""
        sim = Nylon66PolycondensationReactor()
        sim.state.t_reactor_c = 215.0
        for _ in range(50):
            sim.rk4_step(dt=0.02)
        assert 215.0 < sim.state.t_reactor_c < 221.0
        assert not math.isnan(sim.state.t_reactor_c)

    def test_residence_time_space_velocity_consistency(self) -> None:
        """Liquid volumetric space flow matches reactor volume divided by residence time."""
        cfg = Nylon66PolycondensationConfig()
        v_l = cfg.reactor_volume_m3 * 1000.0
        f_vol = v_l / cfg.nominal_residence_time_s
        assert math.isclose(f_vol, 12000.0 / 3600.0, rel_tol=1e-6)

    def test_run_verification_runner_all_9_stage_names(self) -> None:
        """Verification suite produces exactly 9 uniquely named verification stages."""
        res = run_nylon66_polycondensation_verification()
        stages = res["data"]["stages"]
        assert len(stages) == 9
        names = [s["name"] for s in stages]
        assert len(set(names)) == 9
