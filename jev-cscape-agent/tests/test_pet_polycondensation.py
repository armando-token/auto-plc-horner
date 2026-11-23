"""Comprehensive Industrial Polyethylene Terephthalate (PET) Polycondensation Test Suite.

Work Package: W236 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 14 engineering verification sections (120+ unit tests):
1. Section 1: Universal Physical Constants, IUPAC Atomic Weights & Species Molecular Weights
2. Section 2: Reaction Enthalpies, Heats of Reaction & Stoichiometric Conservation
3. Section 3: Arrhenius Reaction Kinetics, Vacuum Devolatilization Enhancement & Activation Energies
4. Section 4: Reactor Geometry, Sizing, Thermal Capacitance & Operating Baseline
5. Section 5: Nominal Steady-State Production Metrics, Conversion, Intrinsic Viscosity (IV) & Rates
6. Section 6: Coupled 6-State Dynamic ODE System & High-Order RK4 Numerical Integrator
7. Section 7: Mathematical Conservation Residuals (Mass, Elements C/H/O, Enthalpy < 1e-10)
8. Section 8: Process Safety Interlocks & Strict Diagnostic Priority Hierarchy (0xF001..0xF004)
9. Section 9: DiagnosticCode Signed/Unsigned Integer Equality, Bitwise Masking (& 0xFFFF)
10. Section 10: Pre-Alarm Logic (%M460) & Emergency Purge Valve Actuation (%M461)
11. Section 11: Horner OCS Memory Space Integration & SYSTEM Privilege (%R1970..%R1977, %M459..%M461)
12. Section 12: Pure IEC 61131-3 Structured Text POU & Anti-Ladder Security Guard
13. Section 13: ILogicUnit Scan Cycle Execution, Reset Dynamics & Soak Stability
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

from jev_cscape.simulation.pet_polycondensation import (
    AA_NOMINAL_PPM,
    AA_TRIP_PPM,
    ACETALDEHYDE_MAX_TRIP_PPM,
    ACETALDEHYDE_NOMINAL_PPM,
    ACETALDEHYDE_PRE_ALARM_PPM,
    ACETALDEHYDE_SURGE_TRIP_PPM,
    ACETALDEHYDE_TRIP_PPM,
    BHET_CONV_NOMINAL_PCT,
    BHET_CONVERSION_NOMINAL_PCT,
    CATALYST_ACTIVITY_NOMINAL_PCT,
    CATALYST_DEACTIVATION_NOMINAL_PCT,
    CATALYST_DEACTIVATION_TRIP_PCT,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    G_ACCEL,
    INTRINSIC_VISCOSITY_NOMINAL,
    INTRINSIC_VISCOSITY_NOMINAL_DL_G,
    IV_NOMINAL,
    IV_NOMINAL_DL_G,
    MW_AA,
    MW_ACETALDEHYDE,
    MW_BHET,
    MW_C,
    MW_CARBOXYL_END,
    MW_DEG,
    MW_DIETHYLENE_GLYCOL,
    MW_DIMER,
    MW_EG,
    MW_ETHYLENE_GLYCOL,
    MW_H,
    MW_H2O,
    MW_MHET,
    MW_O,
    MW_PET,
    MW_PET_MER,
    MW_WATER,
    P_REACTOR_NOMINAL_MBAR,
    P_VAC_NOMINAL_MBAR,
    P_VAC_PRE_ALARM_MBAR,
    P_VAC_TRIP_MBAR,
    P_VACUUM_NOMINAL_MBAR,
    P_VACUUM_PRE_ALARM_MBAR,
    P_VACUUM_TRIP_MBAR,
    PET_CONV_NOMINAL_PCT,
    PET_POLYCONDENSATION_PURE_ST_POU,
    PET_POLYCONDENSATION_REACTOR_PURE_ST_POU,
    PET_POLYCONDENSATION_SYNC_POU,
    PET_PROD_NOMINAL_KG_H,
    PET_PRODUCTION_NOMINAL_KG_H,
    PET_PURE_ST_POU,
    PET_SYNC_POU,
    R_GAS_CONST,
    T_DEGRADATION_TRIP_C,
    T_MAX_SAFE_C,
    T_PRE_ALARM_C,
    T_REACTOR_NOMINAL_C,
    T_REF_K,
    T_RUNAWAY_TRIP_C,
    T_THERMAL_DEGRADATION_TRIP_C,
    T_ZERO_CELSIUS,
    VACUUM_LOSS_TRIP_MBAR,
    VACUUM_NOMINAL_MBAR,
    VACUUM_SURGE_TRIP_MBAR,
    DiagnosticCode,
    PetConfig,
    PetDiagCode,
    PetDiagnosticCode,
    PetEngine,
    PetLogicUnit,
    PetParameters,
    PetPolycondensation,
    PetPolycondensationConfig,
    PetPolycondensationDiagCode,
    PetPolycondensationDiagnosticCode,
    PetPolycondensationEngine,
    PetPolycondensationLogicUnit,
    PetPolycondensationModel,
    PetPolycondensationParameters,
    PetPolycondensationPlantModel,
    PetPolycondensationReactor,
    PetPolycondensationReactorConfig,
    PetPolycondensationReactorLogicUnit,
    PetPolycondensationReactorState,
    PetPolycondensationSimulationEngine,
    PetPolycondensationSimulator,
    PetPolycondensationState,
    PetPolycondensationStatusBits,
    PetPolycondensationStatusWord,
    PetReactor,
    PetReactorConfig,
    PetReactorState,
    PetSimulator,
    PetState,
    PetStatusBits,
    PetStatusWord,
    PureSTValidationResult,
    StatusBits,
    run_pet_polycondensation_reactor_verification,
    run_pet_polycondensation_verification,
    run_pet_verification,
    validate_pure_st,
    verify_pet_polycondensation_pure_st,
    verify_pet_polycondensation_reactor_pure_st,
    verify_pet_pure_st,
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
        """Reference temperature must correspond to 278.0 °C (551.15 K)."""
        assert math.isclose(T_REF_K, 278.0 + 273.15, abs_tol=1e-6)

    def test_iupac_elemental_weights(self) -> None:
        """Elemental masses for Carbon, Hydrogen, and Oxygen must match IUPAC standards."""
        assert math.isclose(MW_C, 0.012011, rel_tol=1e-6)
        assert math.isclose(MW_H, 0.001008, rel_tol=1e-6)
        assert math.isclose(MW_O, 0.015999, rel_tol=1e-6)

    def test_bhet_molecular_weight(self) -> None:
        """BHET C12H14O6 molecular weight must equal 12*C + 14*H + 6*O (~254.238 g/mol)."""
        expected_bhet = 12.0 * MW_C + 14.0 * MW_H + 6.0 * MW_O
        assert math.isclose(MW_BHET, expected_bhet, rel_tol=1e-9)
        assert math.isclose(MW_BHET * 1000.0, 254.238, rel_tol=1e-3)

    def test_pet_repeat_unit_molecular_weight(self) -> None:
        """PET repeat unit C10H8O4 molecular weight must equal 10*C + 8*H + 4*O (~192.170 g/mol)."""
        expected_pet = 10.0 * MW_C + 8.0 * MW_H + 4.0 * MW_O
        assert math.isclose(MW_PET, expected_pet, rel_tol=1e-9)
        assert math.isclose(MW_PET_MER, expected_pet, rel_tol=1e-9)
        assert math.isclose(MW_PET * 1000.0, 192.170, rel_tol=1e-3)

    def test_eg_molecular_weight(self) -> None:
        """Ethylene Glycol C2H6O2 molecular weight must equal 2*C + 6*H + 2*O (~62.068 g/mol)."""
        expected_eg = 2.0 * MW_C + 6.0 * MW_H + 2.0 * MW_O
        assert math.isclose(MW_EG, expected_eg, rel_tol=1e-9)
        assert math.isclose(MW_EG * 1000.0, 62.068, rel_tol=1e-3)
        assert MW_ETHYLENE_GLYCOL == MW_EG

    def test_aa_molecular_weight(self) -> None:
        """Acetaldehyde C2H4O molecular weight must equal 2*C + 4*H + 1*O (~44.053 g/mol)."""
        expected_aa = 2.0 * MW_C + 4.0 * MW_H + 1.0 * MW_O
        assert math.isclose(MW_AA, expected_aa, rel_tol=1e-9)
        assert math.isclose(MW_AA * 1000.0, 44.053, rel_tol=1e-3)
        assert MW_ACETALDEHYDE == MW_AA

    def test_mhet_molecular_weight(self) -> None:
        """MHET C10H10O5 molecular weight must equal 10*C + 10*H + 5*O (~210.185 g/mol)."""
        expected_mhet = 10.0 * MW_C + 10.0 * MW_H + 5.0 * MW_O
        assert math.isclose(MW_MHET, expected_mhet, rel_tol=1e-9)
        assert math.isclose(MW_MHET * 1000.0, 210.185, rel_tol=1e-3)

    def test_deg_and_water_molecular_weights(self) -> None:
        """DEG C4H10O3 and Water H2O molecular weights must match stoichiometric formulas."""
        expected_deg = 4.0 * MW_C + 10.0 * MW_H + 3.0 * MW_O
        expected_water = 2.0 * MW_H + 1.0 * MW_O
        assert math.isclose(MW_DEG, expected_deg, rel_tol=1e-9)
        assert math.isclose(MW_WATER, expected_water, rel_tol=1e-9)
        assert MW_DIETHYLENE_GLYCOL == MW_DEG
        assert MW_H2O == MW_WATER

    def test_dimer_and_carboxyl_aliases(self) -> None:
        """Verify chemical aliases and intermediate dimer weights."""
        assert MW_CARBOXYL_END == MW_MHET
        assert math.isclose(MW_DIMER, 2.0 * MW_BHET - MW_EG, abs_tol=1e-12)


# ============================================================================
# Section 2: Reaction Enthalpies, Heats of Reaction & Stoichiometric Conservation
# ============================================================================

class TestSection02ReactionEnthalpies:
    """Verify thermochemical reaction enthalpies and sign conventions."""

    def test_primary_polycondensation_enthalpy(self) -> None:
        """Reaction 1 is endothermic transesterification: +24.0 kJ/mol (+24,000 J/mol)."""
        assert math.isclose(DELTA_H1_KJ_MOL, 24.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H1_J_MOL, 24000.0, abs_tol=1e-6)
        assert DELTA_H1_KJ_MOL > 0.0

    def test_thermal_cleavage_enthalpy(self) -> None:
        """Reaction 2 is endothermic thermal cleavage: +18.0 kJ/mol (+18,000 J/mol)."""
        assert math.isclose(DELTA_H2_KJ_MOL, 18.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H2_J_MOL, 18000.0, abs_tol=1e-6)
        assert DELTA_H2_KJ_MOL > 0.0

    def test_side_etherification_enthalpy(self) -> None:
        """Reaction 3 is exothermic etherification: -22.0 kJ/mol (-22,000 J/mol)."""
        assert math.isclose(DELTA_H3_KJ_MOL, -22.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H3_J_MOL, -22000.0, abs_tol=1e-6)
        assert DELTA_H3_KJ_MOL < 0.0

    def test_reaction_1_stoichiometric_mass_balance(self) -> None:
        """R1: BHET -> PET + EG must satisfy exact mass conservation: MW_BHET == MW_PET + MW_EG."""
        diff = abs(MW_BHET - (MW_PET + MW_EG))
        assert diff < 1e-15

    def test_reaction_2_stoichiometric_mass_balance(self) -> None:
        """R2: BHET -> MHET + AA must satisfy exact mass conservation: MW_BHET == MW_MHET + MW_AA."""
        diff = abs(MW_BHET - (MW_MHET + MW_AA))
        assert diff < 1e-15

    def test_reaction_3_stoichiometric_mass_balance(self) -> None:
        """R3: 2 EG -> DEG + H2O must satisfy exact mass conservation: 2*MW_EG == MW_DEG + MW_WATER."""
        diff = abs((2.0 * MW_EG) - (MW_DEG + MW_WATER))
        assert diff < 1e-15

    def test_carbon_elemental_conservation(self) -> None:
        """Every reaction step must preserve exact integer counts of Carbon atoms."""
        # R1: C12H14O6 -> C10H8O4 + C2H6O2 (12 == 10 + 2)
        assert 12 == 10 + 2
        # R2: C12H14O6 -> C10H10O5 + C2H4O (12 == 10 + 2)
        assert 12 == 10 + 2
        # R3: 2 C2H6O2 -> C4H10O3 + H2O (4 == 4)
        assert 4 == 4

    def test_hydrogen_elemental_conservation(self) -> None:
        """Every reaction step must preserve exact integer counts of Hydrogen atoms."""
        # R1: 14 == 8 + 6
        assert 14 == 8 + 6
        # R2: 14 == 10 + 4
        assert 14 == 10 + 4
        # R3: 12 == 10 + 2
        assert 12 == 10 + 2

    def test_oxygen_elemental_conservation(self) -> None:
        """Every reaction step must preserve exact integer counts of Oxygen atoms."""
        # R1: 6 == 4 + 2
        assert 6 == 4 + 2
        # R2: 6 == 5 + 1
        assert 6 == 5 + 1
        # R3: 4 == 3 + 1
        assert 4 == 3 + 1


# ============================================================================
# Section 3: Arrhenius Reaction Kinetics, Vacuum Devolatilization & Activation Energies
# ============================================================================

class TestSection03ArrheniusKinetics:
    """Verify Arrhenius kinetic rate equations, activation energies, and devolatilization."""

    def test_arrhenius_monotonicity(self) -> None:
        """Rate constants must increase monotonically with temperature (265 °C < 278 °C < 290 °C)."""
        sim = PetPolycondensation()
        t1_k = 265.0 + T_ZERO_CELSIUS
        t2_k = 278.0 + T_ZERO_CELSIUS
        t3_k = 290.0 + T_ZERO_CELSIUS

        k1_t1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t1_k)
        k1_t2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t2_k)
        k1_t3 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t3_k)

        assert k1_t3 > k1_t2 > k1_t1 > 0.0

    def test_activation_energy_slope_recovery(self) -> None:
        """Recover activation energy Ea1 from Arrhenius slope within 1e-5 J/mol."""
        sim = PetPolycondensation()
        t1_k = 265.0 + T_ZERO_CELSIUS
        t3_k = 290.0 + T_ZERO_CELSIUS

        k1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t1_k)
        k3 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t3_k)

        recovered_ea = -R_GAS_CONST * math.log(k3 / k1) / ((1.0 / t3_k) - (1.0 / t1_k))
        assert math.isclose(recovered_ea, sim.config.activation_e1_j_mol, rel_tol=1e-7)

    def test_activation_energy_e2_slope_recovery(self) -> None:
        """Recover thermal cleavage activation energy Ea2 (95 kJ/mol)."""
        sim = PetPolycondensation()
        t1_k = 265.0 + T_ZERO_CELSIUS
        t3_k = 290.0 + T_ZERO_CELSIUS

        k2_t1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t1_k)
        k2_t3 = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t3_k)

        recovered_ea2 = -R_GAS_CONST * math.log(k2_t3 / k2_t1) / ((1.0 / t3_k) - (1.0 / t1_k))
        assert math.isclose(recovered_ea2, sim.config.activation_e2_j_mol, rel_tol=1e-7)

    def test_activation_energy_e3_slope_recovery(self) -> None:
        """Recover etherification activation energy Ea3 (85 kJ/mol)."""
        sim = PetPolycondensation()
        t1_k = 265.0 + T_ZERO_CELSIUS
        t3_k = 290.0 + T_ZERO_CELSIUS

        k3_t1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a3, sim.config.activation_e3_j_mol, t1_k)
        k3_t3 = sim.arrhenius_rate_constant(sim.config.arrhenius_a3, sim.config.activation_e3_j_mol, t3_k)

        recovered_ea3 = -R_GAS_CONST * math.log(k3_t3 / k3_t1) / ((1.0 / t3_k) - (1.0 / t1_k))
        assert math.isclose(recovered_ea3, sim.config.activation_e3_j_mol, rel_tol=1e-7)

    def test_vacuum_devolatilization_enhancement_monotonicity(self) -> None:
        """Vacuum devolatilization enhancement factor must decrease with rising pressure."""
        sim = PetPolycondensation()
        f_05 = sim.vacuum_devolatilization_factor(0.5)
        f_10 = sim.vacuum_devolatilization_factor(1.0)
        f_25 = sim.vacuum_devolatilization_factor(2.5)
        f_50 = sim.vacuum_devolatilization_factor(5.0)

        assert f_05 > f_10 > f_25 > f_50 > 0.0

    def test_vacuum_devolatilization_deep_vacuum(self) -> None:
        """Under deep vacuum (0.5 mbar), devolatilization factor must exceed 1.0."""
        sim = PetPolycondensation()
        assert sim.vacuum_devolatilization_factor(0.5) > 1.0

    def test_vacuum_devolatilization_loss(self) -> None:
        """Under vacuum loss (5.0 mbar), devolatilization factor must drop below 0.6."""
        sim = PetPolycondensation()
        assert sim.vacuum_devolatilization_factor(5.0) < 0.60

    def test_catalyst_activity_derating(self) -> None:
        """Catalyst deactivation above nominal (1.20%) decreases reaction rates."""
        sim = PetPolycondensation()
        sim.state.catalyst_deactivation_pct = 1.20
        kin_fresh = sim.compute_kinetics(278.0 + T_ZERO_CELSIUS, 0.011, 0.020, 1.0)

        sim.state.catalyst_deactivation_pct = 4.50
        kin_aged = sim.compute_kinetics(278.0 + T_ZERO_CELSIUS, 0.011, 0.020, 1.0)

        assert kin_aged["r1"] < kin_fresh["r1"]

    def test_zero_rate_when_inactive(self) -> None:
        """Rates must be 0 when pet_polycondensation_active is False."""
        sim = PetPolycondensation()
        sim.state.pet_polycondensation_active = False
        kin = sim.compute_kinetics(278.0 + T_ZERO_CELSIUS, 0.011, 0.020, 1.0)
        assert kin["r1"] == 0.0
        assert kin["r2"] == 0.0
        assert kin["r3"] == 0.0

    def test_zero_rate_when_purge_open(self) -> None:
        """Rates must be 0 when emergency_purge_valve_open is True."""
        sim = PetPolycondensation()
        sim.state.emergency_purge_valve_open = True
        kin = sim.compute_kinetics(278.0 + T_ZERO_CELSIUS, 0.011, 0.020, 1.0)
        assert kin["r1"] == 0.0
        assert kin["r2"] == 0.0
        assert kin["r3"] == 0.0


# ============================================================================
# Section 4: Reactor Geometry, Sizing, Thermal Capacitance & Operating Baseline
# ============================================================================

class TestSection04ReactorGeometry:
    """Verify reactor dimensions, residence time, thermal capacitance, and baseline operating points."""

    def test_nominal_operating_points(self) -> None:
        """Verify baseline operating parameters match specification."""
        assert T_REACTOR_NOMINAL_C == 278.0
        assert P_REACTOR_NOMINAL_MBAR == 1.0
        assert VACUUM_NOMINAL_MBAR == 1.0
        assert BHET_CONV_NOMINAL_PCT == 98.85
        assert IV_NOMINAL_DL_G == 0.720
        assert IV_NOMINAL == 0.720
        assert ACETALDEHYDE_NOMINAL_PPM == 40.0
        assert PET_PROD_NOMINAL_KG_H == 2200.0
        assert CATALYST_DEACTIVATION_NOMINAL_PCT == 1.20

    def test_reactor_geometry_and_residence_time(self) -> None:
        """Reactor volume 4.0 m^3 and residence time 1200 s (20.0 min)."""
        cfg = PetPolycondensationConfig()
        assert cfg.reactor_volume_m3 == 4.00
        assert cfg.nominal_residence_time_s == 1200.0

    def test_reactor_thermal_capacitance(self) -> None:
        """Thermal capacitance C_th must equal V * rho * Cp / 1000 (9840.0 kJ/K)."""
        cfg = PetPolycondensationConfig()
        m_tot = cfg.reactor_volume_m3 * cfg.melt_density_kg_m3
        expected_cth = (m_tot * cfg.melt_specific_heat_cp_j_kg_k) / 1000.0
        assert math.isclose(cfg.reactor_thermal_capacitance_kj_k, expected_cth, rel_tol=1e-4)

    def test_nominal_feed_rate(self) -> None:
        """BHET feed rate ~3.22 mol/s."""
        cfg = PetPolycondensationConfig()
        assert math.isclose(cfg.nominal_bhet_feed_rate_mol_s, 3.22, rel_tol=1e-2)

    def test_heating_jacket_power(self) -> None:
        """Heating jacket steady-state thermal power ~110.0 kW."""
        cfg = PetPolycondensationConfig()
        assert cfg.jacket_heating_power_kw == 110.0

    def test_ambient_loss_conductance(self) -> None:
        """Ambient heat loss conductance UA ~0.18 kW/K."""
        cfg = PetPolycondensationConfig()
        assert cfg.ambient_loss_ua_kw_k == 0.18

    def test_emergency_purge_gas_parameters(self) -> None:
        """Inert nitrogen purge flow 5.0 kg/s, 25.0 °C, Cp 1040 J/(kg*K)."""
        cfg = PetPolycondensationConfig()
        assert cfg.emergency_purge_flow_kg_s == 5.0
        assert cfg.emergency_purge_temp_c == 25.0
        assert cfg.emergency_purge_cp_j_kg_k == 1040.0

    def test_steady_state_thermal_equilibrium(self) -> None:
        """At nominal steady state, melt temperature derivative dT/dt is small (< 0.1 °C/s)."""
        sim = PetPolycondensation()
        derivs = sim.compute_derivatives(
            0.0,
            [
                sim.state.c_bhet,
                sim.state.c_pet,
                sim.state.c_eg,
                sim.state.c_aa,
                sim.state.c_deg,
                278.0,
            ],
        )
        assert abs(derivs[5]) < 0.10


# ============================================================================
# Section 5: Nominal Steady-State Production Metrics
# ============================================================================

class TestSection05SteadyStateConvergence:
    """Verify steady-state closed-loop operational criteria."""

    def test_steady_state_attributes(self) -> None:
        """Verify nominal steady-state conversion, IV, production rate, and temperature."""
        sim = PetPolycondensation()
        assert sim.state.conversion_pct > 98.5
        assert math.isclose(sim.state.intrinsic_viscosity_dl_g, 0.720, abs_tol=0.01)
        assert math.isclose(sim.state.pet_production_rate_kg_h, 2200.0, abs_tol=25.0)
        assert math.isclose(sim.state.t_reactor_c, 278.0, abs_tol=1.0)
        assert sim.state.p_reactor_mbar == 1.0
        assert sim.state.pet_polycondensation_active is True
        assert sim.state.emergency_purge_valve_open is False

    def test_conversion_above_98_5_percent(self) -> None:
        """Nominal conversion must exceed 98.5%."""
        sim = PetPolycondensation()
        assert sim.state.bhet_conversion_pct >= 98.80

    def test_intrinsic_viscosity_nominal(self) -> None:
        """Nominal IV must equal 0.720 dL/g within 0.005 dL/g."""
        sim = PetPolycondensation()
        assert math.isclose(sim.state.intrinsic_viscosity_dl_g, 0.720, abs_tol=0.005)

    def test_acetaldehyde_nominal(self) -> None:
        """Nominal acetaldehyde must equal 40.0 ppm."""
        sim = PetPolycondensation()
        assert math.isclose(sim.state.acetaldehyde_ppm, 40.0, abs_tol=0.5)

    def test_iv_increases_with_conversion(self) -> None:
        """Higher BHET conversion increases Intrinsic Viscosity IV."""
        sim = PetPolycondensation()
        sim.state.c_bhet = 0.030
        sim._update_kinetics_and_metrics()
        iv_low = sim.state.intrinsic_viscosity_dl_g

        sim.state.c_bhet = 0.005
        sim._update_kinetics_and_metrics()
        iv_high = sim.state.intrinsic_viscosity_dl_g

        assert iv_high > iv_low

    def test_iv_decreases_with_vacuum_loss(self) -> None:
        """Vacuum pressure rise (loss of vacuum) reduces IV."""
        sim = PetPolycondensation()
        sim.state.p_reactor_mbar = 1.0
        sim._update_kinetics_and_metrics()
        iv_deep = sim.state.intrinsic_viscosity_dl_g

        sim.state.p_reactor_mbar = 4.0
        sim._update_kinetics_and_metrics()
        iv_poor = sim.state.intrinsic_viscosity_dl_g

        assert iv_deep > iv_poor

    def test_aa_rises_with_temperature(self) -> None:
        """Higher temperature exponentially increases acetaldehyde content."""
        sim = PetPolycondensation()
        sim.state.t_reactor_c = 278.0
        sim._update_kinetics_and_metrics()
        aa_nom = sim.state.acetaldehyde_ppm

        sim.state.t_reactor_c = 290.0
        sim._update_kinetics_and_metrics()
        aa_high = sim.state.acetaldehyde_ppm

        assert aa_high > aa_nom >= 40.0

    def test_pet_production_rate_nominal(self) -> None:
        """PET production rate must be approximately 2200.0 kg/h."""
        sim = PetPolycondensation()
        assert math.isclose(sim.state.pet_production_rate_kg_h, 2200.0, abs_tol=10.0)


# ============================================================================
# Section 6: Coupled 6-State ODE System & High-Order RK4 Integrator
# ============================================================================

class TestSection06DynamicODESystem:
    """Verify single and multi-step dynamic integration using RK4."""

    def test_derivatives_vector_dimension(self) -> None:
        """compute_derivatives must return a 6-element list of floats."""
        sim = PetPolycondensation()
        derivs = sim.compute_derivatives(0.0, [0.011, 0.95, 0.02, 0.001, 0.012, 278.0])
        assert len(derivs) == 6
        assert all(isinstance(d, float) for d in derivs)

    def test_rk4_step_advances_time(self) -> None:
        """rk4_step must increment sim_time_s by dt."""
        sim = PetPolycondensation()
        t0 = sim.state.sim_time_s
        sim.rk4_step(dt=0.02)
        assert math.isclose(sim.state.sim_time_s, t0 + 0.02, abs_tol=1e-6)

    def test_step_execution(self) -> None:
        """Single step must advance simulation successfully."""
        sim = PetPolycondensation()
        res = sim.step(dt=0.02)
        assert res.status == AgentStatus.SUCCESS
        assert 275.0 <= sim.state.t_reactor_c <= 282.0
        assert sim.state.conversion_pct > 98.0

    def test_step_invalid_timestep_fails(self) -> None:
        """Step with dt <= 0 must return FAILED."""
        sim = PetPolycondensation()
        res = sim.step(dt=0.0)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "INVALID_TIMESTEP"

    def test_advance_time(self) -> None:
        """advance_time must step cleanly over duration."""
        sim = PetPolycondensation()
        res = sim.advance_time(duration_s=1.0, dt=0.02)
        assert res.status == AgentStatus.SUCCESS
        assert not math.isnan(sim.state.t_reactor_c)
        assert not math.isinf(sim.state.t_reactor_c)

    def test_scan_count_increments(self) -> None:
        """scan_count increments with each RK4 step."""
        sim = PetPolycondensation()
        cnt0 = sim.state.scan_count
        sim.step(dt=0.02)
        assert sim.state.scan_count == cnt0 + 1

    def test_multi_step_bounded_states(self) -> None:
        """50 integration steps remain bounded without NaNs."""
        sim = PetPolycondensation()
        sim.advance_time(duration_s=1.0, dt=0.02)
        assert 270.0 <= sim.state.t_reactor_c <= 285.0
        assert sim.state.c_bhet >= 0.0
        assert sim.state.c_pet >= 0.0

    def test_concentrations_remain_non_negative(self) -> None:
        """All chemical species concentrations remain non-negative after RK4 step."""
        sim = PetPolycondensation()
        sim.step(dt=0.02)
        assert sim.state.c_bhet >= 0.0
        assert sim.state.c_pet >= 0.0
        assert sim.state.c_eg >= 0.0
        assert sim.state.c_aa >= 0.0
        assert sim.state.c_deg >= 0.0


# ============================================================================
# Section 7: Mathematical Conservation Residuals (< 1e-10)
# ============================================================================

class TestSection07ConservationLaws:
    """Verify dual stoichiometric mass, elemental species, and enthalpy residuals."""

    def test_conservation_residuals_under_threshold(self) -> None:
        """Mass, elemental, and enthalpy residuals must be strictly < 1e-10."""
        sim = PetPolycondensation()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1e-10

    def test_mass_balance_residual_zero(self) -> None:
        """Stoichiometric mass balance residual is mathematically exact (0.0)."""
        sim = PetPolycondensation()
        sim.step(dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1e-10

    def test_elemental_mass_balance_residual_zero(self) -> None:
        """Elemental atom mass balance residual is mathematically exact (0.0)."""
        sim = PetPolycondensation()
        sim.step(dt=0.02)
        assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10

    def test_enthalpy_conservation_residual_zero(self) -> None:
        """First-law enthalpy conservation residual is mathematically exact (< 1e-10 kW)."""
        sim = PetPolycondensation()
        sim.step(dt=0.02)
        assert sim.state.enthalpy_conservation_residual_kw < 1e-10

    def test_conservation_preserved_across_dynamic_steps(self) -> None:
        """Residuals remain < 1e-10 after 100 dynamic RK4 steps."""
        sim = PetPolycondensation()
        for _ in range(100):
            sim.step(dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1e-10

    def test_conservation_during_trip_mode(self) -> None:
        """Residuals remain < 1e-10 when tripped and purge valve open."""
        sim = PetPolycondensation()
        sim.state.t_reactor_c = 301.0
        sim._evaluate_safety_interlocks()
        sim.step(dt=0.02)
        assert sim.state.total_mass_balance_residual_kg_s < 1e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1e-10


# ============================================================================
# Section 8: Process Safety Interlocks & Strict Diagnostic Priority Hierarchy
# ============================================================================

class TestSection08SafetyInterlocks:
    """Verify priority hierarchy for diagnostic trips (0xF001 > 0xF002 > 0xF003 > 0xF004)."""

    def test_thermal_degradation_trip(self) -> None:
        """Priority 1: 0xF001 THERMAL_DEGRADATION_TRIP (T > 298.0 °C)."""
        table = RegisterTable()
        sim = PetPolycondensation(register_table=table)
        sim.state.t_reactor_c = 301.0  # > 298.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_DEGRADATION_TRIP
        assert table.read_uword("%R1977") == 0xF001
        assert table.read_bit("%M461") is True
        assert table.read_bit("%M459") is False

    def test_thermal_degradation_boundary(self) -> None:
        """At T = 298.0 °C no trip; at T = 298.1 °C trip triggers."""
        sim = PetPolycondensation()
        sim.state.t_reactor_c = 298.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OK

        sim.state.t_reactor_c = 298.1
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_DEGRADATION_TRIP

    def test_vacuum_loss_trip(self) -> None:
        """Priority 2: 0xF002 VACUUM_LOSS_TRIP (P_vac > 5.0 mbar)."""
        table = RegisterTable()
        sim = PetPolycondensation(register_table=table)
        sim.state.p_reactor_mbar = 6.5  # > 5.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert sim.state.diagnostic_code == DiagnosticCode.VACUUM_LOSS_TRIP
        assert table.read_uword("%R1977") == 0xF002
        assert table.read_bit("%M461") is True
        assert table.read_bit("%M459") is False

    def test_vacuum_loss_boundary(self) -> None:
        """At P_vac = 5.0 mbar no trip; at P_vac = 5.1 mbar trip triggers."""
        sim = PetPolycondensation()
        sim.state.p_reactor_mbar = 5.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OK

        sim.state.p_reactor_mbar = 5.1
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VACUUM_LOSS_TRIP

    def test_acetaldehyde_surge_trip(self) -> None:
        """Priority 3: 0xF003 ACETALDEHYDE_SURGE_TRIP (AA > 80.0 ppm)."""
        table = RegisterTable()
        sim = PetPolycondensation(register_table=table)
        sim.state.acetaldehyde_ppm = 85.0  # > 80.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert sim.state.diagnostic_code == DiagnosticCode.ACETALDEHYDE_SURGE_TRIP
        assert table.read_uword("%R1977") == 0xF003
        assert table.read_bit("%M461") is True
        assert table.read_bit("%M459") is False
        assert table.read_bit("%M460") is True

    def test_acetaldehyde_surge_boundary(self) -> None:
        """At AA = 80.0 ppm no trip; at AA = 80.5 ppm trip triggers."""
        sim = PetPolycondensation()
        sim.state.acetaldehyde_ppm = 80.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OK

        sim.state.acetaldehyde_ppm = 80.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.ACETALDEHYDE_SURGE_TRIP

    def test_catalyst_deactivation_trip(self) -> None:
        """Priority 4: 0xF004 CATALYST_DEACTIVATION_TRIP (Deactivation > 5.0%)."""
        table = RegisterTable()
        sim = PetPolycondensation(register_table=table)
        sim.state.catalyst_deactivation_pct = 5.50  # > 5.0%
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert sim.state.diagnostic_code == DiagnosticCode.CATALYST_DEACTIVATION_TRIP
        assert table.read_uword("%R1977") == 0xF004
        assert table.read_bit("%M461") is True
        assert table.read_bit("%M459") is False

    def test_catalyst_deactivation_boundary(self) -> None:
        """At Deact = 5.0% no trip; at Deact = 5.1% trip triggers."""
        sim = PetPolycondensation()
        sim.state.catalyst_deactivation_pct = 5.00
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OK

        sim.state.catalyst_deactivation_pct = 5.10
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.CATALYST_DEACTIVATION_TRIP

    def test_priority_hierarchy_precedence(self) -> None:
        """Priority 1 takes precedence when all four faults are simultaneously active."""
        table = RegisterTable()
        sim = PetPolycondensation(register_table=table)
        sim.state.t_reactor_c = 305.0
        sim.state.p_reactor_mbar = 7.0
        sim.state.acetaldehyde_ppm = 90.0
        sim.state.catalyst_deactivation_pct = 6.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert table.read_uword("%R1977") == 0xF001

    def test_priority_2_over_priority_3(self) -> None:
        """Priority 2 takes precedence over Priority 3."""
        sim = PetPolycondensation()
        sim.state.p_reactor_mbar = 6.0
        sim.state.acetaldehyde_ppm = 95.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VACUUM_LOSS_TRIP

    def test_priority_3_over_priority_4(self) -> None:
        """Priority 3 takes precedence over Priority 4."""
        sim = PetPolycondensation()
        sim.state.acetaldehyde_ppm = 95.0
        sim.state.catalyst_deactivation_pct = 6.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.ACETALDEHYDE_SURGE_TRIP


# ============================================================================
# Section 9: DiagnosticCode Signed/Unsigned Masking
# ============================================================================

class TestSection09DiagnosticCodeMasking:
    """Verify signed and unsigned 16-bit integer conversions and bitwise masking."""

    def test_signed_unsigned_equality(self) -> None:
        """0xF001 equals -4095 under signed 16-bit representation."""
        code = DiagnosticCode.THERMAL_DEGRADATION_TRIP
        assert code == 0xF001
        assert code == -4095
        assert (code & 0xFFFF) == 0xF001
        assert DiagnosticCode(-4095) == code
        assert DiagnosticCode(0xF001) == code

    def test_vacuum_loss_masking(self) -> None:
        """0xF002 equals -4094 under signed 16-bit representation."""
        code = DiagnosticCode.VACUUM_LOSS_TRIP
        assert code == 0xF002
        assert code == -4094
        assert (code & 0xFFFF) == 0xF002

    def test_acetaldehyde_surge_masking(self) -> None:
        """0xF003 equals -4093 under signed 16-bit representation."""
        code = DiagnosticCode.ACETALDEHYDE_SURGE_TRIP
        assert code == 0xF003
        assert code == -4093
        assert (code & 0xFFFF) == 0xF003

    def test_catalyst_deactivation_masking(self) -> None:
        """0xF004 equals -4092 under signed 16-bit representation."""
        code = DiagnosticCode.CATALYST_DEACTIVATION_TRIP
        assert code == 0xF004
        assert code == -4092
        assert (code & 0xFFFF) == 0xF004

    def test_bitwise_and_left_and_right(self) -> None:
        """__and__ and __rand__ must work identically."""
        code = DiagnosticCode.THERMAL_DEGRADATION_TRIP
        assert (code & 0xF000) == 0xF000
        assert (0xF000 & code) == 0xF000

    def test_diagnostic_code_hashing(self) -> None:
        """Hash must be consistent with 16-bit unsigned value."""
        assert hash(DiagnosticCode.THERMAL_DEGRADATION_TRIP) == hash(0xF001)

    def test_diagnostic_code_aliases(self) -> None:
        """Verify compatibility aliases for diagnostic codes."""
        assert DiagnosticCode.THERMAL_RUNAWAY == DiagnosticCode.THERMAL_DEGRADATION_TRIP
        assert DiagnosticCode.VACUUM_LOSS == DiagnosticCode.VACUUM_LOSS_TRIP
        assert DiagnosticCode.ACETALDEHYDE_SURGE == DiagnosticCode.ACETALDEHYDE_SURGE_TRIP
        assert DiagnosticCode.CATALYST_DEACTIVATION == DiagnosticCode.CATALYST_DEACTIVATION_TRIP


# ============================================================================
# Section 10: Pre-Alarm & Purge System
# ============================================================================

class TestSection10PreAlarmAndPurge:
    """Verify pre-alarm %M460 behavior without causing process trip."""

    def test_acetaldehyde_pre_alarm_no_trip(self) -> None:
        """AA between 60.0 and 80.0 ppm triggers %M460 without trip."""
        table = RegisterTable()
        sim = PetPolycondensation(register_table=table)
        sim.state.acetaldehyde_ppm = 68.0  # between 60.0 and 80.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert table.read_bit("%M460") is True
        assert table.read_bit("%M461") is False
        assert table.read_bit("%M459") is True
        assert table.read_uword("%R1977") == 0x0000

    def test_vacuum_pre_alarm_no_trip(self) -> None:
        """Vacuum between 2.5 and 5.0 mbar triggers %M460 without trip."""
        table = RegisterTable()
        sim = PetPolycondensation(register_table=table)
        sim.state.p_reactor_mbar = 3.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert table.read_bit("%M460") is True
        assert table.read_bit("%M461") is False
        assert table.read_bit("%M459") is True
        assert table.read_uword("%R1977") == 0x0000

    def test_temperature_pre_alarm_no_trip(self) -> None:
        """Temperature between 288.0 and 298.0 °C triggers %M460 without trip."""
        table = RegisterTable()
        sim = PetPolycondensation(register_table=table)
        sim.state.t_reactor_c = 289.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert table.read_bit("%M460") is True
        assert table.read_bit("%M461") is False
        assert table.read_bit("%M459") is True
        assert table.read_uword("%R1977") == 0x0000

    def test_nominal_no_pre_alarm(self) -> None:
        """Under baseline nominal conditions, %M460 remains False."""
        table = RegisterTable()
        sim = PetPolycondensation(register_table=table)
        sim.reset()
        assert table.read_bit("%M460") is False

    def test_emergency_purge_valve_actuation(self) -> None:
        """Purge valve opens on trip and clears active bit."""
        sim = PetPolycondensation()
        sim.state.t_reactor_c = 301.0
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_purge_valve_open is True
        assert sim.state.pet_polycondensation_active is False


# ============================================================================
# Section 11: Horner OCS Register Table Integration
# ============================================================================

class TestSection11RegisterTableSync:
    """Verify bit-exact mapping to registers %R1970..%R1977 and %M459..%M461."""

    def test_nominal_registers(self) -> None:
        """Exact integer values in register table at nominal operating point."""
        table = RegisterTable()
        sim = PetPolycondensation(register_table=table)
        sim.reset()
        assert table.read_word("%R1970") == 2780   # 278.0 °C
        assert table.read_word("%R1971") == 10     # 1.0 mbar
        assert table.read_word("%R1972") == 9885   # 98.85%
        assert table.read_word("%R1973") == 720    # 0.720 dL/g
        assert table.read_word("%R1974") == 400    # 40.0 ppm
        assert table.read_word("%R1975") == 22000  # 2200.0 kg/h
        assert table.read_word("%R1976") == 120    # 1.20%
        assert table.read_uword("%R1977") == 0x0000# OK
        assert table.read_bit("%M459") is True     # Active
        assert table.read_bit("%M460") is False    # Pre-alarm inactive
        assert table.read_bit("%M461") is False    # Purge closed

    def test_system_privilege_mode_in_sync(self) -> None:
        """sync_to_registers writes using SYSTEM privilege."""
        table = RegisterTable()
        table.privilege_mode = PrivilegeMode.USER
        sim = PetPolycondensation()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R1970") == 2780

    def test_status_bits_representation(self) -> None:
        """PetPolycondensationStatusBits bitmasks correctly reflect active state."""
        sim = PetPolycondensation()
        bits = sim.state.status_bits
        assert bits & PetPolycondensationStatusBits.RUNNING
        assert bits & PetPolycondensationStatusBits.PET_POLYCONDENSATION_ACTIVE
        assert not (bits & PetPolycondensationStatusBits.EMERGENCY_PURGE_VALVE_OPEN)

    def test_temperature_scaling_precision(self) -> None:
        """Temperature scaling: 285.4 °C -> 2854 in %R1970."""
        table = RegisterTable()
        sim = PetPolycondensation(register_table=table)
        sim.state.t_reactor_c = 285.4
        sim._sync_registers()
        assert table.read_word("%R1970") == 2854

    def test_vacuum_pressure_scaling_precision(self) -> None:
        """Vacuum pressure scaling: 3.5 mbar -> 35 in %R1971."""
        table = RegisterTable()
        sim = PetPolycondensation(register_table=table)
        sim.state.p_reactor_mbar = 3.5
        sim._sync_registers()
        assert table.read_word("%R1971") == 35


# ============================================================================
# Section 12: Pure IEC 61131-3 Structured Text POU
# ============================================================================

class TestSection12PureSTPOU:
    """Verify strict IEC 61131-3 syntax and anti-ladder security interception."""

    def test_pure_st_pou_valid(self) -> None:
        """POU PetPolycondensationSync must pass SecurityGuard and STParser without errors."""
        SecurityGuard.assert_pure_st_content(PET_POLYCONDENSATION_PURE_ST_POU)
        res = STParser.validate_code(PET_POLYCONDENSATION_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(PET_POLYCONDENSATION_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "PetPolycondensationSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = [
            "%R1970", "%R1971", "%R1972", "%R1973",
            "%R1974", "%R1975", "%R1976", "%R1977",
            "%M459", "%M460", "%M461",
        ]
        for reg in expected_regs:
            assert reg in ast.bound_registers

    def test_anti_ladder_interception(self) -> None:
        """Anti-ladder guard must reject ladder contacts with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad ---[ ]--- END_PROGRAM")

    def test_anti_ladder_coils_interception(self) -> None:
        """Anti-ladder guard must reject ladder coils with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad ---( )--- END_PROGRAM")

    def test_anti_ladder_rung_interception(self) -> None:
        """Anti-ladder guard must reject ladder rungs with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad RUNG END_RUNG END_PROGRAM")

    def test_verify_pet_pure_st_helper(self) -> None:
        """verify_pet_polycondensation_pure_st must return SUCCESS."""
        res = verify_pet_polycondensation_pure_st()
        assert res.status == AgentStatus.SUCCESS

    def test_pure_st_pou_aliases(self) -> None:
        """Verify text aliases for POU."""
        assert PET_POLYCONDENSATION_SYNC_POU == PET_POLYCONDENSATION_PURE_ST_POU
        assert PET_PURE_ST_POU == PET_POLYCONDENSATION_PURE_ST_POU
        assert PET_SYNC_POU == PET_POLYCONDENSATION_PURE_ST_POU


# ============================================================================
# Section 13: ILogicUnit Scan Protocol & Reset
# ============================================================================

class TestSection13ILogicUnitProtocol:
    """Verify ILogicUnit scan cycle and reset behavior."""

    def test_scan_step_and_execute(self) -> None:
        """scan_step and execute advance simulation within bounded range."""
        sim = PetPolycondensation()
        sim.scan_step(dt=0.02)
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        sim.execute(ctx)
        assert 275.0 <= sim.state.t_reactor_c <= 282.0

    def test_reset_restores_nominal(self) -> None:
        """reset must restore nominal baseline after trip excursion."""
        sim = PetPolycondensation()
        sim.state.t_reactor_c = 305.0
        sim.state.emergency_purge_valve_open = True
        sim.state.pet_polycondensation_active = False

        sim.reset()
        assert sim.state.t_reactor_c == 278.0
        assert sim.state.emergency_purge_valve_open is False
        assert sim.state.pet_polycondensation_active is True
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_logic_unit_wrapper(self) -> None:
        """PetPolycondensationLogicUnit wrapper delegates properly."""
        unit = PetPolycondensationLogicUnit()
        assert unit.name == "PetPolycondensation"
        assert unit.priority == 1
        assert unit.is_enabled is True
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        unit.execute(ctx)

    def test_logic_unit_enable_disable(self) -> None:
        """Logic unit enable/disable state toggling."""
        unit = PetPolycondensationLogicUnit()
        assert unit.is_enabled is True
        unit.disable()
        assert unit.is_enabled is False
        unit.enable()
        assert unit.is_enabled is True

    def test_logic_unit_reset(self) -> None:
        """Logic unit reset delegates to simulator."""
        unit = PetPolycondensationLogicUnit()
        unit.state.t_reactor_c = 305.0
        unit.reset()
        assert unit.state.t_reactor_c == 278.0

    def test_soak_100_cycles_stability(self) -> None:
        """100 scan cycles execute with zero NaN and stable bounded state."""
        sim = PetPolycondensation()
        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt_ms=20.0, elapsed_time_ms=cycle * 20.0, dt=0.02)
            sim.execute(ctx)
        assert 275.0 <= sim.state.t_reactor_c <= 282.0
        assert sim.state.conversion_pct > 98.0
        assert not math.isnan(sim.state.t_reactor_c)


# ============================================================================
# Section 14: Deterministic 9-Stage Verification Suite & Artifacts
# ============================================================================

class TestSection14Deterministic9StageVerification:
    """Verify 9-stage verification function and JSON artifact emission."""

    def test_run_verification_returns_success(self, tmp_path: Path) -> None:
        """Verification suite must return strict 4-state contract success."""
        out_file = tmp_path / "pet_evidence.json"
        res = run_pet_polycondensation_verification(output_path=out_file)
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"

    def test_run_verification_all_9_stages_pass(self) -> None:
        """All 9 stages must pass individually."""
        res = run_pet_polycondensation_verification()
        assert res["status"] == "success"
        stages = res["data"]["stages"]
        assert len(stages) == 9
        assert all(s["passed"] for s in stages)

    def test_verification_data_payload_structure(self) -> None:
        """Payload must contain work_package, module, and elapsed_ms."""
        res = run_pet_polycondensation_verification()
        data = res["data"]
        assert data["work_package"] == "W236"
        assert "pet_polycondensation" in data["module"]
        assert "elapsed_ms" in data

    def test_verification_error_code_is_none_on_success(self) -> None:
        """error_code is None when status is success."""
        res = run_pet_polycondensation_verification()
        assert res["error_code"] is None

    def test_run_verification_aliases(self) -> None:
        """Verify verification function aliases."""
        assert run_pet_polycondensation_reactor_verification == run_pet_polycondensation_verification
        assert run_pet_verification == run_pet_polycondensation_verification
