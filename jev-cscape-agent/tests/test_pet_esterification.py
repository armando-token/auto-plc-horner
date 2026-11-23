"""Comprehensive Industrial Polyethylene Terephthalate (PET) Continuous Precursor Esterification Test Suite.

Work Package: W254 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 14 comprehensive engineering verification sections (110+ unit tests):
1. Section 1: Universal Physical Constants, IUPAC Atomic Weights & Species Molecular Weights
2. Section 2: Reaction Enthalpies, Heats of Reaction & Stoichiometric Mass Conservation
3. Section 3: Arrhenius Reaction Kinetics, Activation Energies & Temperature Dependence
4. Section 4: Reactor Geometry, Sizing, Thermal Capacitance & Operating Baseline
5. Section 5: Nominal Steady-State Closed-Loop Convergence, Conversion & Yield Targets
6. Section 6: Coupled 6-State Dynamic ODE System & High-Order RK4 Numerical Integrator
7. Section 7: Mathematical Conservation Residuals (Stoichiometric Mass, Elements C/H/O, Enthalpy < 1e-10)
8. Section 8: Process Safety Interlocks & Strict Diagnostic Priority Hierarchy (0xF501..0xF504)
9. Section 9: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality & String Representations
10. Section 10: Pre-Alarm Logic (%M502) & Emergency Depressurization Valve Actuation (%M503)
11. Section 11: Horner OCS Memory Space Integration & SYSTEM Privilege (%R2150..%R2157, %M501..%M503)
12. Section 12: Pure IEC 61131-3 Structured Text POU & Anti-Ladder Security Guard
13. Section 13: ILogicUnit Scan Cycle Execution, Reset Dynamics & 100-Cycle Soak Stability
14. Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
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

from jev_cscape.simulation.pet_esterification import (
    BHET_YIELD_NOMINAL_PCT,
    COIL_EG_RATIO_PRE_ALARM,
    COIL_EMERGENCY_DEPRESSURE_VALVE_OPEN,
    COIL_PET_REACTOR_ACTIVE,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    DELTA_H_VAP_WATER_J_MOL,
    DELTA_H_VAP_WATER_KJ_KG,
    EG_RATIO_DEPLETION_FAULT,
    EG_RATIO_PRE_ALARM_HIGH,
    EG_RATIO_PRE_ALARM_LOW,
    EG_TO_PTA_RATIO_NOMINAL,
    G_ACCEL,
    HEATING_DUTY_NOMINAL_KW,
    MW_BHET,
    MW_C,
    MW_DEG,
    MW_DIETHYLENE_GLYCOL,
    MW_DIMER,
    MW_EG,
    MW_ETHYLENE_GLYCOL,
    MW_H,
    MW_H2O,
    MW_O,
    MW_PTA,
    MW_WATER,
    P_OVERPRESSURE_TRIP_BAR,
    P_REACTOR_NOMINAL_BAR,
    PET_ESTER_PURE_ST_POU,
    PET_ESTER_SYNC_POU,
    PET_ESTERIFICATION_PURE_ST_POU,
    PET_ESTERIFICATION_REACTOR_PURE_ST_POU,
    PET_ESTERIFICATION_SYNC_POU,
    PTA_CONV_NOMINAL_PCT,
    PTA_CONVERSION_NOMINAL_PCT,
    R_GAS_CONST,
    REG_BHET_YIELD_SCALED,
    REG_EG_TO_PTA_MOLAR_RATIO_SCALED,
    REG_HEATING_DUTY_SCALED,
    REG_PET_DIAGNOSTIC_CODE,
    REG_PET_REACTOR_PRESSURE_SCALED,
    REG_PET_REACTOR_TEMP_SCALED,
    REG_PTA_CONVERSION_SCALED,
    REG_WATER_VAPOR_RATE_SCALED,
    T_INLET_NOMINAL_C,
    T_OVERTEMP_RUNAWAY_TRIP_C,
    T_REACTOR_NOMINAL_C,
    T_REF_K,
    T_ZERO_CELSIUS,
    WATER_VAPOR_CONDENSER_FAULT_KG_H,
    WATER_VAPOR_RATE_NOMINAL_KG_H,
    DiagnosticCode,
    PetConfig,
    PetDiagCode,
    PetDiagnosticCode,
    PetEsterification,
    PetEsterificationConfig,
    PetEsterificationDiagCode,
    PetEsterificationDiagnosticCode,
    PetEsterificationEngine,
    PetEsterificationLogicUnit,
    PetEsterificationModel,
    PetEsterificationParameters,
    PetEsterificationReactor,
    PetEsterificationReactorConfig,
    PetEsterificationReactorLogicUnit,
    PetEsterificationReactorState,
    PetEsterificationSimulator,
    PetEsterificationState,
    PetEsterificationStatusBits,
    PetEsterificationStatusWord,
    PetLogicUnit,
    PetState,
    PetStatusBits,
    PetStatusWord,
    PureSTValidationResult,
    StatusBits,
    run_pet_ester_verification,
    run_pet_esterification_reactor_verification,
    run_pet_esterification_verification,
    validate_pure_st,
    verify_pet_ester_pure_st,
    verify_pet_esterification_pure_st,
    verify_pet_esterification_reactor_pure_st,
)


# ============================================================================
# Section 1: Universal Physical Constants, IUPAC Atomic Weights & Species Molecular Weights
# ============================================================================

class TestSection01PhysicalConstants:
    """Verify IUPAC atomic weights, universal physical constants, and species molecular weights."""

    def test_universal_gas_constant(self) -> None:
        """Universal gas constant must match CODATA 2018 value: 8.314462618 J/(mol*K)."""
        assert math.isclose(R_GAS_CONST, 8.314462618, rel_tol=1e-9)

    def test_standard_gravity_acceleration(self) -> None:
        """Standard gravitational acceleration must equal 9.80665 m/s^2."""
        assert math.isclose(G_ACCEL, 9.80665, abs_tol=1e-6)

    def test_absolute_zero_celsius(self) -> None:
        """Absolute zero reference must be 273.15 K."""
        assert math.isclose(T_ZERO_CELSIUS, 273.15, abs_tol=1e-6)

    def test_reactor_reference_temperature(self) -> None:
        """Reference temperature must correspond to 240.0 °C (513.15 K)."""
        assert math.isclose(T_REF_K, 240.0 + 273.15, abs_tol=1e-6)

    def test_iupac_elemental_weights(self) -> None:
        """Elemental masses for Carbon, Hydrogen, and Oxygen must match IUPAC standards."""
        assert math.isclose(MW_C, 0.012011, rel_tol=1e-6)
        assert math.isclose(MW_H, 0.001008, rel_tol=1e-6)
        assert math.isclose(MW_O, 0.015999, rel_tol=1e-6)

    def test_pta_molecular_weight(self) -> None:
        """PTA (Purified Terephthalic Acid, C8H6O4) molar mass must equal 8*C + 6*H + 4*O."""
        expected = 8.0 * MW_C + 6.0 * MW_H + 4.0 * MW_O
        assert math.isclose(MW_PTA, expected, rel_tol=1e-9)
        assert 0.1661 < MW_PTA < 0.1662  # ~166.13 g/mol

    def test_ethylene_glycol_molecular_weight(self) -> None:
        """Ethylene Glycol (EG, C2H6O2) molar mass must equal 2*C + 6*H + 2*O."""
        expected = 2.0 * MW_C + 6.0 * MW_H + 2.0 * MW_O
        assert math.isclose(MW_EG, expected, rel_tol=1e-9)
        assert math.isclose(MW_ETHYLENE_GLYCOL, expected, rel_tol=1e-9)
        assert 0.0620 < MW_EG < 0.0621  # ~62.07 g/mol

    def test_bhet_molecular_weight(self) -> None:
        """BHET (Bis(2-hydroxyethyl) terephthalate, C12H14O6) molar mass must equal 12*C + 14*H + 6*O."""
        expected = 12.0 * MW_C + 14.0 * MW_H + 6.0 * MW_O
        assert math.isclose(MW_BHET, expected, rel_tol=1e-9)
        assert 0.2542 < MW_BHET < 0.2543  # ~254.24 g/mol

    def test_water_molecular_weight(self) -> None:
        """Water (H2O) molar mass must equal 2*H + O."""
        expected = 2.0 * MW_H + 1.0 * MW_O
        assert math.isclose(MW_WATER, expected, rel_tol=1e-9)
        assert math.isclose(MW_H2O, expected, rel_tol=1e-9)
        assert 0.0180 < MW_WATER < 0.0181  # ~18.015 g/mol

    def test_deg_molecular_weight(self) -> None:
        """Diethylene Glycol (DEG, C4H10O3) molar mass must equal 4*C + 10*H + 3*O."""
        expected = 4.0 * MW_C + 10.0 * MW_H + 3.0 * MW_O
        assert math.isclose(MW_DEG, expected, rel_tol=1e-9)
        assert math.isclose(MW_DIETHYLENE_GLYCOL, expected, rel_tol=1e-9)
        assert 0.1061 < MW_DEG < 0.1062  # ~106.12 g/mol

    def test_dimer_molecular_weight(self) -> None:
        """Dimer Oligomer (C22H22O10) molar mass must equal 2*BHET - EG."""
        expected = 2.0 * MW_BHET - MW_EG
        assert math.isclose(MW_DIMER, expected, rel_tol=1e-9)
        assert 0.4464 < MW_DIMER < 0.4465  # ~446.41 g/mol


# ============================================================================
# Section 2: Reaction Enthalpies, Heats of Reaction & Stoichiometric Mass Conservation
# ============================================================================

class TestSection02ReactionEnthalpies:
    """Verify thermochemical heats of reaction and stoichiometric conservation."""

    def test_reaction_1_enthalpy(self) -> None:
        """Primary esterification is endothermic: Delta H1 = +20.0 kJ/mol (+20,000 J/mol)."""
        assert DELTA_H1_KJ_MOL == 20.0
        assert DELTA_H1_J_MOL == 20000.0

    def test_reaction_2_enthalpy(self) -> None:
        """Side etherification to DEG is exothermic: Delta H2 = -24.0 kJ/mol (-24,000 J/mol)."""
        assert DELTA_H2_KJ_MOL == -24.0
        assert DELTA_H2_J_MOL == -24000.0

    def test_reaction_3_enthalpy(self) -> None:
        """Secondary dimerization is endothermic: Delta H3 = +12.0 kJ/mol (+12,000 J/mol)."""
        assert DELTA_H3_KJ_MOL == 12.0
        assert DELTA_H3_J_MOL == 12000.0

    def test_water_vaporization_latent_heat(self) -> None:
        """Water vaporization latent heat at 240 °C (2.8 bar) is ~1766 kJ/kg (~31.8 kJ/mol)."""
        assert DELTA_H_VAP_WATER_KJ_KG == 1766.0
        expected_j_mol = 1766.0 * MW_WATER * 1000.0
        assert math.isclose(DELTA_H_VAP_WATER_J_MOL, expected_j_mol, rel_tol=1e-6)

    def test_reaction_1_stoichiometric_mass_balance(self) -> None:
        """Reaction 1: PTA + 2 EG -> BHET + 2 H2O has strict stoichiometric mass conservation."""
        reactants = MW_PTA + 2.0 * MW_EG
        products = MW_BHET + 2.0 * MW_WATER
        assert math.isclose(reactants, products, abs_tol=1e-12)

    def test_reaction_2_stoichiometric_mass_balance(self) -> None:
        """Reaction 2: 2 EG -> DEG + H2O has strict stoichiometric mass conservation."""
        reactants = 2.0 * MW_EG
        products = MW_DEG + MW_WATER
        assert math.isclose(reactants, products, abs_tol=1e-12)

    def test_reaction_3_stoichiometric_mass_balance(self) -> None:
        """Reaction 3: 2 BHET -> Dimer + EG has strict stoichiometric mass conservation."""
        reactants = 2.0 * MW_BHET
        products = MW_DIMER + MW_EG
        assert math.isclose(reactants, products, abs_tol=1e-12)


# ============================================================================
# Section 3: Arrhenius Reaction Kinetics, Activation Energies & Temperature Dependence
# ============================================================================

class TestSection03ArrheniusKinetics:
    """Verify Arrhenius kinetics, activation energies, and temperature responsiveness."""

    def test_arrhenius_monotonic_increase(self) -> None:
        """Rate constants k1, k2, k3 must increase monotonically with temperature."""
        sim = PetEsterificationReactor()
        t_low_k = 220.0 + T_ZERO_CELSIUS
        t_nom_k = 240.0 + T_ZERO_CELSIUS
        t_high_k = 260.0 + T_ZERO_CELSIUS

        k1_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_low_k)
        k1_nom = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_nom_k)
        k1_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_high_k)

        assert k1_high > k1_nom > k1_low > 0.0

        k2_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t_low_k)
        k2_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t_high_k)
        assert k2_high > k2_low > 0.0

        k3_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a3, sim.config.activation_e3_j_mol, t_low_k)
        k3_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a3, sim.config.activation_e3_j_mol, t_high_k)
        assert k3_high > k3_low > 0.0

    def test_activation_energy_recovery(self) -> None:
        """Arrhenius two-point slope must exactly recover configured activation energy."""
        sim = PetEsterificationReactor()
        t1_k = 230.0 + T_ZERO_CELSIUS
        t2_k = 250.0 + T_ZERO_CELSIUS

        k1_t1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t1_k)
        k1_t2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t2_k)

        ea_recovered = -R_GAS_CONST * math.log(k1_t2 / k1_t1) / ((1.0 / t2_k) - (1.0 / t1_k))
        assert math.isclose(ea_recovered, sim.config.activation_e1_j_mol, rel_tol=1e-5)

    def test_kinetics_computation_structure(self) -> None:
        """compute_kinetics must return rate constants, reaction rates, and thermal duties."""
        sim = PetEsterificationReactor()
        kin = sim.compute_kinetics(T_REF_K, 0.166, 1.825, 4.64)
        for key in ["k1", "k2", "k3", "r1", "r2", "r3", "r1_tot", "r2_tot", "r3_tot", "q1_kw", "q2_kw", "q3_kw", "q_total_kw"]:
            assert key in kin
            assert not math.isnan(kin[key])
            assert not math.isinf(kin[key])

    def test_kinetics_disabled_when_reactor_inactive(self) -> None:
        """Reaction rates must drop to zero when reactor is inactive or valve open."""
        sim = PetEsterificationReactor()
        sim.state.pet_reactor_active = False
        kin = sim.compute_kinetics(T_REF_K, 0.166, 1.825, 4.64)
        assert kin["r1"] == 0.0
        assert kin["r2"] == 0.0
        assert kin["r3"] == 0.0
        assert kin["q_total_kw"] == 0.0

    def test_arrhenius_low_temperature_clamping(self) -> None:
        """Safe temperature clamping prevents division by zero or negative temperature."""
        sim = PetEsterificationReactor()
        k_clamp = sim.arrhenius_rate_constant(1.0e6, 50000.0, -10.0)
        assert k_clamp > 0.0
        assert not math.isnan(k_clamp)


# ============================================================================
# Section 4: Reactor Geometry, Sizing, Thermal Capacitance & Operating Baseline
# ============================================================================

class TestSection04ReactorGeometry:
    """Verify reactor volume, thermal capacitance, and baseline operating parameters."""

    def test_reactor_configuration_defaults(self) -> None:
        """Default configuration parameters match industrial PET precursor esterification CSTR."""
        cfg = PetEsterificationConfig()
        assert cfg.reactor_volume_m3 == 15.0
        assert cfg.nominal_residence_time_s == 5000.0
        assert cfg.melt_density_kg_m3 == 1180.0
        assert cfg.melt_specific_heat_cp_j_kg_k == 2300.0
        # V * rho * Cp = 15 * 1180 * 2.3 = 40,710 kJ/K
        expected_c_th = cfg.reactor_volume_m3 * cfg.melt_density_kg_m3 * (cfg.melt_specific_heat_cp_j_kg_k / 1000.0)
        assert math.isclose(cfg.reactor_thermal_capacitance_kj_k, expected_c_th, rel_tol=1e-5)

    def test_feed_stream_baseline(self) -> None:
        """Nominal PTA feed rate is 14.7801 mol/s (8840 kg/h) with 1.35 EG:PTA ratio."""
        cfg = PetEsterificationConfig()
        assert math.isclose(cfg.nominal_pta_feed_rate_mol_s, 14.7801, rel_tol=1e-4)
        assert cfg.nominal_eg_to_pta_ratio == 1.35
        assert cfg.nominal_inlet_temp_c == 200.0

    def test_baseline_threshold_constants(self) -> None:
        """Operating baseline constants match Horner APG OCS register scaling."""
        assert T_REACTOR_NOMINAL_C == 240.0
        assert P_REACTOR_NOMINAL_BAR == 2.80
        assert PTA_CONV_NOMINAL_PCT == 96.50
        assert PTA_CONVERSION_NOMINAL_PCT == 96.50
        assert BHET_YIELD_NOMINAL_PCT == 94.20
        assert WATER_VAPOR_RATE_NOMINAL_KG_H == 1850.0
        assert EG_TO_PTA_RATIO_NOMINAL == 1.35
        assert HEATING_DUTY_NOMINAL_KW == 450.0

    def test_interlock_threshold_constants(self) -> None:
        """Safety interlock thresholds match specifications."""
        assert T_OVERTEMP_RUNAWAY_TRIP_C == 265.0
        assert P_OVERPRESSURE_TRIP_BAR == 3.80
        assert EG_RATIO_DEPLETION_FAULT == 1.15
        assert WATER_VAPOR_CONDENSER_FAULT_KG_H == 1200.0
        assert EG_RATIO_PRE_ALARM_LOW == 1.25
        assert EG_RATIO_PRE_ALARM_HIGH == 1.60


# ============================================================================
# Section 5: Nominal Steady-State Closed-Loop Convergence, Conversion & Yield Targets
# ============================================================================

class TestSection05SteadyStateConvergence:
    """Verify nominal steady-state convergence: Conversion >= 95.0%, Yield >= 90.0%, Temp 240.0 °C, Pressure 2.80 bar."""

    def test_nominal_steady_state_temperature_and_pressure(self) -> None:
        """Nominal reactor temperature is 240.0 °C and pressure is 2.80 bar."""
        sim = PetEsterificationReactor()
        assert math.isclose(sim.state.t_reactor_c, 240.0, abs_tol=0.1)
        assert math.isclose(sim.state.p_reactor_bar, 2.80, abs_tol=0.05)

    def test_nominal_conversion_and_yield_targets(self) -> None:
        """Nominal PTA conversion >= 95.0% and BHET yield >= 90.0%."""
        sim = PetEsterificationReactor()
        assert sim.state.pta_conversion_pct >= 95.0
        assert sim.state.bhet_yield_pct >= 90.0
        assert math.isclose(sim.state.pta_conversion_pct, 96.50, abs_tol=0.5)
        assert math.isclose(sim.state.bhet_yield_pct, 94.20, abs_tol=0.5)

    def test_nominal_water_vapor_rate_and_heating_duty(self) -> None:
        """Nominal water vapor overhead rate is ~1850 kg/h and jacket heating is 450 kW."""
        sim = PetEsterificationReactor()
        assert math.isclose(sim.state.water_vapor_rate_kg_h, 1850.0, abs_tol=10.0)
        assert math.isclose(sim.state.heating_duty_kw, 450.0, abs_tol=1.0)
        assert math.isclose(sim.state.eg_to_pta_molar_ratio, 1.35, abs_tol=0.01)

    def test_nominal_coils_and_diagnostic_state(self) -> None:
        """Nominal steady-state operation asserts %M501, clears %M502, %M503, and diag code OK."""
        sim = PetEsterificationReactor()
        assert sim.state.pet_reactor_active is True
        assert sim.state.eg_ratio_pre_alarm is False
        assert sim.state.emergency_depressure_valve_open is False
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_c_deg_property_and_setter(self) -> None:
        """State provides c_deg alias property and setter for c_diethylene_glycol."""
        st = PetEsterificationState()
        assert st.c_deg == st.c_diethylene_glycol
        st.c_deg = 0.125
        assert st.c_diethylene_glycol == 0.125
        assert st.c_deg == 0.125


# ============================================================================
# Section 6: Coupled 6-State Dynamic ODE System & High-Order RK4 Numerical Integrator
# ============================================================================

class TestSection06DynamicODESystem:
    """Verify coupled 6-state ODE derivative evaluation, RK4 integration, and non-negativity."""

    def test_compute_derivatives_state_vector(self) -> None:
        """compute_derivatives evaluates dy/dt for all 6 states."""
        sim = PetEsterificationReactor()
        y = [0.166, 1.825, 4.64, 0.42, 0.085, 240.0]
        dy = sim.compute_derivatives(0.0, y)
        assert len(dy) == 6
        for d in dy:
            assert isinstance(d, float)
            assert not math.isnan(d)
            assert not math.isinf(d)

    def test_rk4_step_advances_simulation_clock(self) -> None:
        """rk4_step advances sim_time_s by dt and increments cycle_count."""
        sim = PetEsterificationReactor()
        t0 = sim.state.sim_time_s
        c0 = sim.state.cycle_count
        sim.rk4_step(dt=0.02)
        assert math.isclose(sim.state.sim_time_s, t0 + 0.02, rel_tol=1e-6)
        assert sim.state.cycle_count == c0 + 1

    def test_rk4_step_alias(self) -> None:
        """step() is a valid alias for rk4_step()."""
        sim = PetEsterificationReactor()
        t0 = sim.state.sim_time_s
        sim.step(dt=0.02)
        assert math.isclose(sim.state.sim_time_s, t0 + 0.02, rel_tol=1e-6)

    def test_non_negativity_and_physical_clamping(self) -> None:
        """RK4 solver enforces non-negativity (C >= 0.0) and temperature bounds [50.0, 350.0]."""
        sim = PetEsterificationReactor()
        # Set negative concentrations to test clamping
        sim.state.c_pta = -0.5
        sim.state.c_eg = -1.0
        sim.state.c_bhet = -2.0
        sim.state.c_water = -0.1
        sim.state.c_diethylene_glycol = -0.05
        sim.state.t_reactor_c = 10.0
        sim.rk4_step(dt=0.02)

        assert sim.state.c_pta >= 0.0
        assert sim.state.c_eg >= 0.0
        assert sim.state.c_bhet >= 0.0
        assert sim.state.c_water >= 0.0
        assert sim.state.c_diethylene_glycol >= 0.0
        assert sim.state.t_reactor_c >= 50.0

    def test_feed_inflow_stopped_when_inactive(self) -> None:
        """Feed inflow to derivatives drops to zero when reactor is inactive."""
        sim = PetEsterificationReactor()
        sim.state.pet_reactor_active = False
        y = [0.166, 1.825, 4.64, 0.42, 0.085, 240.0]
        dy = sim.compute_derivatives(0.0, y)
        # Without inflow, PTA derivative should be purely negative (outflow)
        assert dy[0] < 0.0


# ============================================================================
# Section 7: Mathematical Conservation Residuals (Mass, Elements C/H/O, Enthalpy < 1e-10)
# ============================================================================

class TestSection07ConservationLaws:
    """Verify strict stoichiometric mass, elemental (C, H, O), and first-law enthalpy residuals < 1e-10."""

    def test_stoichiometric_mass_balance_residual(self) -> None:
        """Stoichiometric mass balance residual must be strictly < 1e-10 kg/s."""
        sim = PetEsterificationReactor()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_mass_balance_residual(self) -> None:
        """Elemental mass balance residual (C, H, O) must be strictly < 1e-10 kg/s."""
        sim = PetEsterificationReactor()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_enthalpy_conservation_residual(self) -> None:
        """First-law enthalpy conservation residual must be strictly < 1e-10 kW."""
        sim = PetEsterificationReactor()
        sim._update_conservation_residuals()
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_conservation_residuals_over_multiple_steps(self) -> None:
        """Conservation residuals remain < 1e-10 over consecutive dynamic RK4 steps."""
        sim = PetEsterificationReactor()
        for _ in range(10):
            sim.rk4_step(dt=0.02)
            assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
            assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
            assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# Section 8: Process Safety Interlocks & Strict Diagnostic Priority Hierarchy (0xF501..0xF504)
# ============================================================================

class TestSection08SafetyInterlocks:
    """Verify safety trips, emergency relief, and strict priority hierarchy."""

    def test_priority_1_overtemp_runaway_trip(self) -> None:
        """Priority 1: T_reactor > 265.0 °C sets 0xF501, opens %M503, clears %M501."""
        sim = PetEsterificationReactor()
        sim.state.t_reactor_c = 268.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERTEMP_RUNAWAY
        assert sim.state.emergency_depressure_valve_open is True
        assert sim.state.pet_reactor_active is False

    def test_priority_2_overpressure_trip(self) -> None:
        """Priority 2: P_reactor > 3.80 bar sets 0xF503, opens %M503, clears %M501."""
        sim = PetEsterificationReactor()
        sim.state.p_reactor_bar = 4.10
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERPRESSURE_TRIP
        assert sim.state.emergency_depressure_valve_open is True
        assert sim.state.pet_reactor_active is False

    def test_priority_3_eg_depletion_fault(self) -> None:
        """Priority 3: EG:PTA ratio < 1.15 sets 0xF502 EG_DEPLETION_FAULT."""
        sim = PetEsterificationReactor()
        sim.state.eg_to_pta_molar_ratio = 1.10
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.EG_DEPLETION_FAULT
        assert sim.state.emergency_depressure_valve_open is False

    def test_priority_4_condenser_fault(self) -> None:
        """Priority 4: Water vapor rate < 1200.0 kg/h sets 0xF504 CONDENSER_FAULT."""
        sim = PetEsterificationReactor()
        sim.state.water_vapor_rate_kg_h = 1050.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.CONDENSER_FAULT
        assert sim.state.emergency_depressure_valve_open is False

    def test_priority_1_overrides_priority_2_3_4(self) -> None:
        """Overtemp (P1) overrides simultaneous overpressure (P2), EG depletion (P3), and condenser (P4)."""
        sim = PetEsterificationReactor()
        sim.state.t_reactor_c = 270.0               # P1
        sim.state.p_reactor_bar = 4.50              # P2
        sim.state.eg_to_pta_molar_ratio = 1.05       # P3
        sim.state.water_vapor_rate_kg_h = 800.0     # P4
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERTEMP_RUNAWAY
        assert sim.state.emergency_depressure_valve_open is True

    def test_priority_2_overrides_priority_3_4(self) -> None:
        """Overpressure (P2) overrides simultaneous EG depletion (P3) and condenser fault (P4)."""
        sim = PetEsterificationReactor()
        sim.state.t_reactor_c = 240.0               # Normal
        sim.state.p_reactor_bar = 4.00              # P2
        sim.state.eg_to_pta_molar_ratio = 1.05       # P3
        sim.state.water_vapor_rate_kg_h = 800.0     # P4
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERPRESSURE_TRIP
        assert sim.state.emergency_depressure_valve_open is True

    def test_priority_3_overrides_priority_4(self) -> None:
        """EG depletion (P3) overrides simultaneous condenser fault (P4)."""
        sim = PetEsterificationReactor()
        sim.state.t_reactor_c = 240.0               # Normal
        sim.state.p_reactor_bar = 2.80              # Normal
        sim.state.eg_to_pta_molar_ratio = 1.10       # P3
        sim.state.water_vapor_rate_kg_h = 950.0     # P4
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.EG_DEPLETION_FAULT

    def test_heating_duty_cut_off_on_emergency_trip(self) -> None:
        """Jacket heating duty is cut off (0 kW) whenever emergency valve is opened."""
        sim = PetEsterificationReactor()
        sim.state.t_reactor_c = 270.0
        sim._evaluate_safety_interlocks()
        sim._update_derived_variables()
        assert sim.state.heating_duty_kw == 0.0
        assert sim.state.q_jacket_kw == 0.0


# ============================================================================
# Section 9: DiagnosticCode Signed/Unsigned Integer Equality & Bitwise Masking
# ============================================================================

class TestSection09DiagnosticCodeMasking:
    """Verify DiagnosticCode signed/unsigned 16-bit values, integer equality, and masking."""

    def test_diagnostic_code_hex_values(self) -> None:
        """Diagnostic codes have correct hexadecimal values."""
        assert DiagnosticCode.OK.value == 0x0000
        assert DiagnosticCode.OVERTEMP_RUNAWAY.value == 0xF501
        assert DiagnosticCode.EG_DEPLETION_FAULT.value == 0xF502
        assert DiagnosticCode.OVERPRESSURE_TRIP.value == 0xF503
        assert DiagnosticCode.CONDENSER_FAULT.value == 0xF504

    def test_unsigned_integer_equality(self) -> None:
        """DiagnosticCode compares equal to unsigned integer literals."""
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.OVERTEMP_RUNAWAY == 0xF501
        assert DiagnosticCode.EG_DEPLETION_FAULT == 0xF502
        assert DiagnosticCode.OVERPRESSURE_TRIP == 0xF503
        assert DiagnosticCode.CONDENSER_FAULT == 0xF504

    def test_signed_integer_equality(self) -> None:
        """DiagnosticCode compares equal to signed 16-bit integer values."""
        # 0xF501 - 0x10000 = -2815
        assert DiagnosticCode.OVERTEMP_RUNAWAY == -2815
        # 0xF502 - 0x10000 = -2814
        assert DiagnosticCode.EG_DEPLETION_FAULT == -2814
        # 0xF503 - 0x10000 = -2813
        assert DiagnosticCode.OVERPRESSURE_TRIP == -2813
        # 0xF504 - 0x10000 = -2812
        assert DiagnosticCode.CONDENSER_FAULT == -2812

    def test_bitwise_masking_with_0xffff(self) -> None:
        """Bitwise AND with 0xFFFF yields unsigned 16-bit word."""
        assert (DiagnosticCode.OVERTEMP_RUNAWAY & 0xFFFF) == 0xF501
        assert (0xFFFF & DiagnosticCode.OVERTEMP_RUNAWAY) == 0xF501
        assert (DiagnosticCode.EG_DEPLETION_FAULT & 0xFFFF) == 0xF502
        assert (DiagnosticCode.OVERPRESSURE_TRIP & 0xFFFF) == 0xF503
        assert (DiagnosticCode.CONDENSER_FAULT & 0xFFFF) == 0xF504

    def test_diagnostic_code_missing_signed_lookup(self) -> None:
        """DiagnosticCode lookup accepts signed 16-bit integer."""
        assert DiagnosticCode(-2815) == DiagnosticCode.OVERTEMP_RUNAWAY
        assert DiagnosticCode(-2814) == DiagnosticCode.EG_DEPLETION_FAULT
        assert DiagnosticCode(-2813) == DiagnosticCode.OVERPRESSURE_TRIP
        assert DiagnosticCode(-2812) == DiagnosticCode.CONDENSER_FAULT

    def test_string_and_repr_representations(self) -> None:
        """DiagnosticCode string, repr, and name representations."""
        code = DiagnosticCode.OVERTEMP_RUNAWAY
        assert "OVERTEMP_RUNAWAY" in repr(code)
        assert code.name == "OVERTEMP_RUNAWAY"
        assert code.value == 0xF501

    def test_diagnostic_code_aliases(self) -> None:
        """DiagnosticCode aliases resolve to the same enum class."""
        assert PetEsterificationDiagnosticCode is DiagnosticCode
        assert PetEsterificationDiagCode is DiagnosticCode
        assert PetDiagnosticCode is DiagnosticCode
        assert PetDiagCode is DiagnosticCode

    def test_status_bits_bitmask(self) -> None:
        """Status bits support bitwise operators and flags."""
        bits = PetEsterificationStatusBits.RUNNING | PetEsterificationStatusBits.PET_REACTOR_ACTIVE
        assert PetEsterificationStatusBits.RUNNING in bits
        assert PetEsterificationStatusBits.PET_REACTOR_ACTIVE in bits
        assert PetEsterificationStatusBits.OVERTEMP_RUNAWAY not in bits


# ============================================================================
# Section 10: Pre-Alarm Logic (%M502) & Emergency Depressurization Valve (%M503)
# ============================================================================

class TestSection10PreAlarmAndDepressure:
    """Verify EG:PTA ratio pre-alarm (%M502) and emergency relief valve (%M503) dynamics."""

    def test_pre_alarm_triggered_on_low_ratio(self) -> None:
        """%M502 triggers when EG:PTA ratio is below 1.25."""
        sim = PetEsterificationReactor()
        sim.state.eg_to_pta_molar_ratio = 1.20
        sim._evaluate_safety_interlocks()
        assert sim.state.eg_ratio_pre_alarm is True
        # If ratio >= 1.15, diagnostic code remains OK (pre-alarm only)
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_pre_alarm_triggered_on_high_ratio(self) -> None:
        """%M502 triggers when EG:PTA ratio exceeds 1.60."""
        sim = PetEsterificationReactor()
        sim.state.eg_to_pta_molar_ratio = 1.65
        sim._evaluate_safety_interlocks()
        assert sim.state.eg_ratio_pre_alarm is True
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_pre_alarm_cleared_in_safe_band(self) -> None:
        """%M502 is cleared when EG:PTA ratio is between 1.25 and 1.60."""
        sim = PetEsterificationReactor()
        sim.state.eg_to_pta_molar_ratio = 1.35
        sim._evaluate_safety_interlocks()
        assert sim.state.eg_ratio_pre_alarm is False

    def test_emergency_depressure_valve_drops_reactor_pressure(self) -> None:
        """Opening emergency depressurization valve vents reactor pressure to 1.05 bar."""
        sim = PetEsterificationReactor()
        sim.state.emergency_depressure_valve_open = True
        sim.rk4_step(dt=0.02)
        assert sim.state.emergency_depressure_valve_open is True
        assert math.isclose(sim.state.p_reactor_bar, 1.05, abs_tol=0.01)

    def test_emergency_relief_cooling_active_during_depressure(self) -> None:
        """q_depressure_kw is active when emergency valve is open."""
        sim = PetEsterificationReactor()
        sim.state.emergency_depressure_valve_open = True
        sim.compute_derivatives(0.0, [0.166, 1.825, 4.64, 0.42, 0.085, 250.0])
        assert sim.state.q_depressure_kw > 0.0


# ============================================================================
# Section 11: Horner OCS Memory Space Integration & SYSTEM Privilege (%R2150..%R2157, %M501..%M503)
# ============================================================================

class TestSection11RegisterTableSync:
    """Verify memory mapping and register synchronization to %R2150..%R2157 and %M501..%M503."""

    def test_register_constants_definitions(self) -> None:
        """Register and coil addresses match Horner OCS hardware mapping."""
        assert REG_PET_REACTOR_TEMP_SCALED == "%R2150"
        assert REG_PET_REACTOR_PRESSURE_SCALED == "%R2151"
        assert REG_PTA_CONVERSION_SCALED == "%R2152"
        assert REG_BHET_YIELD_SCALED == "%R2153"
        assert REG_WATER_VAPOR_RATE_SCALED == "%R2154"
        assert REG_EG_TO_PTA_MOLAR_RATIO_SCALED == "%R2155"
        assert REG_HEATING_DUTY_SCALED == "%R2156"
        assert REG_PET_DIAGNOSTIC_CODE == "%R2157"
        assert COIL_PET_REACTOR_ACTIVE == "%M501"
        assert COIL_EG_RATIO_PRE_ALARM == "%M502"
        assert COIL_EMERGENCY_DEPRESSURE_VALVE_OPEN == "%M503"

    def test_nominal_register_table_synchronization(self) -> None:
        """Nominal state synchronizes exactly to %R2150..%R2157 and %M501..%M503."""
        table = RegisterTable()
        sim = PetEsterificationReactor(register_table=table)
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        assert table.read_word("%R2150") == 2400  # 240.0 °C * 10
        assert table.read_word("%R2151") == 280   # 2.80 bar * 100
        assert table.read_word("%R2152") == 9650  # 96.50 % * 100
        assert table.read_word("%R2153") == 9420  # 94.20 % * 100
        assert table.read_word("%R2154") == 1850  # 1850 kg/h
        assert table.read_word("%R2155") == 135   # 1.35 * 100
        assert table.read_word("%R2156") == 450   # 450 kW
        assert table.read_uword("%R2157") == 0x0000 # OK
        assert table.read_bit("%M501") is True    # Active
        assert table.read_bit("%M502") is False   # Pre-alarm inactive
        assert table.read_bit("%M503") is False   # Depressure closed

    def test_trip_register_synchronization(self) -> None:
        """Over-temp trip synchronizes signed 0xF501 into %R2157, clears %M501, sets %M503."""
        table = RegisterTable()
        sim = PetEsterificationReactor(register_table=table)
        sim.state.t_reactor_c = 268.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        assert table.read_uword("%R2157") == 0xF501
        assert table.read_word("%R2157") == -2815
        assert table.read_bit("%M501") is False
        assert table.read_bit("%M503") is True

    def test_system_privilege_mode_in_sync(self) -> None:
        """sync_to_registers writes using SYSTEM privilege."""
        table = RegisterTable()
        table.privilege_mode = PrivilegeMode.USER
        sim = PetEsterificationReactor()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R2150") == 2400


# ============================================================================
# Section 12: Pure IEC 61131-3 Structured Text POU & Anti-Ladder Security Guard
# ============================================================================

class TestSection12PureSTPOU:
    """Verify Pure IEC 61131-3 Structured Text POU, variable bindings, and anti-ladder interception."""

    def test_st_pou_constant_definition(self) -> None:
        """PET_ESTERIFICATION_PURE_ST_POU is non-empty and contains PROGRAM PetEsterificationSync."""
        assert isinstance(PET_ESTERIFICATION_PURE_ST_POU, str)
        assert "PROGRAM PetEsterificationSync" in PET_ESTERIFICATION_PURE_ST_POU
        assert "END_PROGRAM" in PET_ESTERIFICATION_PURE_ST_POU

    def test_st_pou_aliases(self) -> None:
        """POU string constants are aliased properly."""
        assert PET_ESTERIFICATION_SYNC_POU == PET_ESTERIFICATION_PURE_ST_POU
        assert PET_ESTERIFICATION_REACTOR_PURE_ST_POU == PET_ESTERIFICATION_PURE_ST_POU
        assert PET_ESTER_PURE_ST_POU == PET_ESTERIFICATION_PURE_ST_POU
        assert PET_ESTER_SYNC_POU == PET_ESTERIFICATION_PURE_ST_POU

    def test_security_guard_assert_pure_st(self) -> None:
        """SecurityGuard passes pure ST POU without raising LadderForbiddenError."""
        SecurityGuard.assert_pure_st_content(PET_ESTERIFICATION_PURE_ST_POU)

    def test_st_parser_validation(self) -> None:
        """STParser validates POU syntax with AgentStatus.SUCCESS."""
        res = STParser.validate_code(PET_ESTERIFICATION_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_st_parser_pou_structure_and_bindings(self) -> None:
        """STParser parses POU structure and verifies all 11 register/coil bindings."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(PET_ESTERIFICATION_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "PetEsterificationSync"
        assert pou.pou_type == POUType.PROGRAM

        expected_bindings = [
            "%R2150", "%R2151", "%R2152", "%R2153",
            "%R2154", "%R2155", "%R2156", "%R2157",
            "%M501", "%M502", "%M503",
        ]
        for reg in expected_bindings:
            assert reg in pou.bound_registers

    def test_verify_pet_esterification_pure_st_function(self) -> None:
        """verify_pet_esterification_pure_st returns True and AgentStatus.SUCCESS."""
        val = verify_pet_esterification_pure_st()
        assert bool(val) is True
        assert val == AgentStatus.SUCCESS
        assert verify_pet_esterification_reactor_pure_st() == AgentStatus.SUCCESS
        assert verify_pet_ester_pure_st() == AgentStatus.SUCCESS
        assert validate_pure_st() == AgentStatus.SUCCESS

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
        """PetEsterificationReactor implements ILogicUnit interface."""
        sim = PetEsterificationReactor()
        assert isinstance(sim, ILogicUnit)
        assert sim.name == "PetEsterificationReactor"
        assert sim.priority == 254
        assert sim.is_enabled is True

    def test_enable_disable(self) -> None:
        """enable() and disable() toggle is_enabled property."""
        sim = PetEsterificationReactor()
        sim.disable()
        assert sim.is_enabled is False
        sim.enable()
        assert sim.is_enabled is True

    def test_scan_step_with_context(self) -> None:
        """scan_step executes properly with ScanContext."""
        sim = PetEsterificationReactor()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        sim.scan_step(dt=0.02, context=ctx)
        assert sim.state.cycle_count == 1

    def test_execute_method(self) -> None:
        """execute(context) executes scan cycle."""
        sim = PetEsterificationReactor()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        sim.execute(ctx)
        assert sim.state.cycle_count == 1

    def test_reset_method(self) -> None:
        """reset() restores initial steady-state conditions and clears fault states."""
        sim = PetEsterificationReactor()
        sim.state.t_reactor_c = 275.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OVERTEMP_RUNAWAY

        sim.reset()
        assert math.isclose(sim.state.t_reactor_c, 240.0, abs_tol=0.1)
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.pet_reactor_active is True
        assert sim.state.emergency_depressure_valve_open is False

    def test_logic_unit_adapter_wrapper(self) -> None:
        """PetEsterificationLogicUnit wraps reactor and complies with ILogicUnit."""
        unit = PetEsterificationLogicUnit()
        assert isinstance(unit, ILogicUnit)
        assert unit.name == "PetEsterificationReactor"
        assert unit.priority == 254
        assert unit.is_enabled is True

        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        unit.execute(ctx)
        assert unit.state.cycle_count == 1

        unit.reset()
        assert unit.state.diagnostic_code == DiagnosticCode.OK

    def test_100_cycle_soak_stability(self) -> None:
        """100-cycle soak simulation maintains bounded state without numerical drift or NaNs."""
        sim = PetEsterificationReactor()
        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt_ms=20.0, elapsed_time_ms=cycle * 20.0, dt=0.02)
            sim.execute(ctx)

        # Verification bounds
        assert 238.0 <= sim.state.t_reactor_c <= 242.0
        assert sim.state.pta_conversion_pct >= 95.0
        assert sim.state.bhet_yield_pct >= 90.0
        assert 2.70 <= sim.state.p_reactor_bar <= 2.90
        assert not math.isnan(sim.state.t_reactor_c)
        assert not math.isnan(sim.state.c_pta)
        assert not math.isnan(sim.state.c_bhet)
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.pet_reactor_active is True

    def test_class_aliases(self) -> None:
        """Model, Simulator, Engine, and LogicUnit class aliases point to standard classes."""
        assert PetEsterification is PetEsterificationReactor
        assert PetEsterificationModel is PetEsterificationReactor
        assert PetEsterificationSimulator is PetEsterificationReactor
        assert PetEsterificationEngine is PetEsterificationReactor
        assert PetEsterificationReactorLogicUnit is PetEsterificationLogicUnit
        assert PetLogicUnit is PetEsterificationLogicUnit


# ============================================================================
# Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
# ============================================================================

class TestSection14Deterministic9StageVerification:
    """Verify run_pet_esterification_verification execution, evidence structure, and artifact generation."""

    def test_verification_suite_success(self) -> None:
        """run_pet_esterification_verification returns AgentStatus.SUCCESS and all 9 stages pass."""
        res = run_pet_esterification_verification()
        assert res["status"] == AgentStatus.SUCCESS.value
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert res["data"]["work_package"] == "W254"
        assert res["data"]["module"] == "jev_cscape.simulation.pet_esterification"

    def test_verification_evidence_json_generation(self, tmp_path: Path) -> None:
        """run_pet_esterification_verification writes valid JSON artifact to output_path."""
        target_json = tmp_path / "pet_esterification_evidence.json"
        res = run_pet_esterification_verification(output_path=target_json)

        assert target_json.exists()
        with open(target_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9
        assert len(data["data"]["stages"]) == 9

    def test_verification_function_aliases(self) -> None:
        """run_pet_esterification_reactor_verification and run_pet_ester_verification aliases work."""
        res1 = run_pet_esterification_reactor_verification()
        assert res1["status"] == "success"
        res2 = run_pet_ester_verification()
        assert res2["status"] == "success"

    def test_verification_with_evidence_path(self, tmp_path: Path) -> None:
        """run_pet_esterification_verification works with evidence_path argument."""
        target_json = tmp_path / "evidence_alt.json"
        res = run_pet_esterification_verification(evidence_path=target_json)
        assert res["status"] == "success"
        assert target_json.exists()


# ============================================================================
# Section 15: PureSTValidationResult, LogicUnit Delegation & Edge Cases
# ============================================================================

class TestSection15EdgeCasesAndDelegation:
    """Verify PureSTValidationResult behaviors, logic unit property delegations, and edge cases."""

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
        # Unknown lookup returns None
        assert DiagnosticCode._missing_(999999) is None
        # Hash value consistency
        assert hash(DiagnosticCode.OVERTEMP_RUNAWAY) == hash(0xF501)
        # Comparison with string or None returns False without error
        assert (DiagnosticCode.OVERTEMP_RUNAWAY == "0xF501") is False
        assert (DiagnosticCode.OVERTEMP_RUNAWAY == None) is False

    def test_logic_unit_delegated_properties(self) -> None:
        """PetEsterificationLogicUnit delegates config, registers, state, and sync_to_registers."""
        unit = PetEsterificationLogicUnit()
        assert isinstance(unit.config, PetEsterificationConfig)
        assert isinstance(unit.registers, RegisterTable)
        assert isinstance(unit.state, PetEsterificationState)

        # scan_step delegation
        ctx = ScanContext(cycle=2, dt_ms=20.0, elapsed_time_ms=40.0, dt=0.02)
        unit.scan_step(dt=0.02, context=ctx)
        assert unit.state.cycle_count == 1

        # sync_to_registers delegation
        table = RegisterTable()
        unit.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R2150") == 2400

    def test_custom_config_override(self) -> None:
        """Custom reactor configuration parameters can be passed to PetEsterificationReactor."""
        custom_cfg = PetEsterificationConfig(
            reactor_volume_m3=20.0,
            jacket_heating_power_kw=500.0,
        )
        sim = PetEsterificationReactor(config=custom_cfg)
        assert sim.config.reactor_volume_m3 == 20.0
        assert sim.config.jacket_heating_power_kw == 500.0

    def test_subcooling_pressure_reduction(self) -> None:
        """Operating below nominal temperature reduces reactor vapor pressure."""
        sim = PetEsterificationReactor()
        sim.state.t_reactor_c = 220.0
        sim.rk4_step(dt=0.02)
        assert sim.state.p_reactor_bar < P_REACTOR_NOMINAL_BAR

    def test_zero_feed_conversion_and_yield(self) -> None:
        """When feed rate is zero, conversion and yield are zeroed."""
        zero_cfg = PetEsterificationConfig(nominal_pta_feed_rate_mol_s=0.0)
        sim = PetEsterificationReactor(config=zero_cfg)
        sim._update_derived_variables()
        assert sim.state.pta_conversion_pct == 0.0
        assert sim.state.bhet_yield_pct == 0.0

    def test_logic_unit_execute_and_enable_toggle(self) -> None:
        """PetEsterificationLogicUnit execute, enable, and disable work correctly."""
        unit = PetEsterificationLogicUnit()
        unit.disable()
        assert unit.is_enabled is False
        unit.enable()
        assert unit.is_enabled is True

        ctx = ScanContext(cycle=5, dt_ms=20.0, elapsed_time_ms=100.0, dt=0.02)
        unit.execute(ctx)
        assert unit.state.cycle_count == 1


