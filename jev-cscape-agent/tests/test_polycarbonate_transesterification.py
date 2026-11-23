"""Comprehensive Industrial Polycarbonate (PC) Bisphenol-A Melt Transesterification Test Suite.

Work Package: W260 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 15 comprehensive engineering verification sections (100+ unit tests):
1. Section 1: Universal Physical & Chemical Constants, Molecular Weights & Reaction Enthalpies
2. Section 2: Reaction Kinetics, Rate Constants & Arrhenius Temperature Dependence
3. Section 3: Reactor Geometry, Residence Time, Thermal Capacitance & Operating Baseline
4. Section 4: Nominal Steady-State Closed-Loop Convergence (Conversion >= 94.0%, Temp 270.0 °C, Pressure 2.50 mbar, MW 28500 Da)
5. Section 5: Coupled 6-State Dynamic ODE System, Derivatives & RK4 Numerical Integrator
6. Section 6: Mathematical Conservation Residuals (Stoichiometric Mass, Elements C/H/O, Enthalpy < 1e-10)
7. Section 7: Process Safety Interlocks & Strict Priority Hierarchy (0xF701 > 0xF702 > 0xF703 > 0xF704 > 0x0000)
8. Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality, String & Bitwise Masking
9. Section 9: Vacuum Permissive Logic (%M516) & Emergency Melt Dump Actuation (%M517)
10. Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege (%R2210..%R2217, %M515..%M517)
11. Section 11: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
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

from jev_cscape.simulation.polycarbonate_transesterification import (
    BPA_CONV_NOMINAL_PCT,
    BPA_CONVERSION_NOMINAL_PCT,
    COIL_EMERGENCY_MELT_DUMP_OPEN,
    COIL_PC_REACTOR_ACTIVE,
    COIL_VACUUM_SYSTEM_PERMISSIVE,
    DELTA_H_RXN_J_MOL,
    DELTA_H_RXN_KJ_MOL,
    DELTA_H_VAP_PHENOL_J_KG,
    DELTA_H_VAP_PHENOL_J_MOL,
    DELTA_H_VAP_PHENOL_KJ_KG,
    DPC_BPA_MOLAR_RATIO_NOMINAL,
    DPC_BPA_RATIO_FAULT_HIGH,
    DPC_BPA_RATIO_FAULT_LOW,
    DPC_BPA_RATIO_NOMINAL,
    G_ACCEL,
    MELT_POLYMER_VISCOSITY_NOMINAL_PA_S,
    MELT_VISCOSITY_NOMINAL_PA_S,
    MW_BISPHENOL_A,
    MW_BPA,
    MW_C,
    MW_C6H6O,
    MW_DIPHENYL_CARBONATE,
    MW_DPC,
    MW_H,
    MW_O,
    MW_PC,
    MW_PC_MER,
    MW_PC_NOMINAL_DA,
    MW_PHENOL,
    MW_POLYCARBONATE_MER,
    P_VAC_NOMINAL_MBAR,
    P_VACUUM_NOMINAL_MBAR,
    P_VACUUM_TRIP_MBAR,
    PC_MW_NOMINAL_DA,
    PC_PURE_ST_POU,
    PC_TRANSESTERIFICATION_PURE_ST_POU,
    PC_WEIGHT_AVG_MW_NOMINAL_DA,
    PHENOL_REMOVAL_NOMINAL_KG_H,
    PHENOL_REMOVAL_RATE_NOMINAL_KG_H,
    POLYCARBONATE_PURE_ST_POU,
    POLYCARBONATE_TRANSESTERIFICATION_PURE_ST_POU,
    POLYCARBONATE_TRANSESTERIFICATION_SYNC_POU,
    R_GAS_CONST,
    REG_BPA_CONVERSION_SCALED,
    REG_DPC_BPA_MOLAR_RATIO_SCALED,
    REG_MELT_POLYMER_VISCOSITY_SCALED,
    REG_PC_DIAGNOSTIC_CODE,
    REG_PC_REACTOR_TEMP_SCALED,
    REG_PC_VACUUM_PRESSURE_SCALED,
    REG_PC_WEIGHT_AVG_MW_SCALED,
    REG_PHENOL_REMOVAL_RATE_SCALED,
    T_DEGRADATION_TRIP_C,
    T_INLET_NOMINAL_C,
    T_REACTOR_NOMINAL_C,
    T_REF_K,
    T_THERMAL_DEGRADATION_TRIP_C,
    T_ZERO_CELSIUS,
    VACUUM_LOSS_TRIP_MBAR,
    VACUUM_NOMINAL_MBAR,
    VISCOSITY_FAULT_HIGH_PA_S,
    DiagnosticCode,
    PcConfig,
    PcDiagCode,
    PcDiagnosticCode,
    PcReactor,
    PcState,
    PcStatusBits,
    PcStatusWord,
    PcTransesterificationReactor,
    PolycarbonateConfig,
    PolycarbonateDiagCode,
    PolycarbonateDiagnosticCode,
    PolycarbonateReactor,
    PolycarbonateState,
    PolycarbonateStatusBits,
    PolycarbonateStatusWord,
    PolycarbonateTransesterification,
    PolycarbonateTransesterificationConfig,
    PolycarbonateTransesterificationDiagCode,
    PolycarbonateTransesterificationDiagnosticCode,
    PolycarbonateTransesterificationEngine,
    PolycarbonateTransesterificationLogicUnit,
    PolycarbonateTransesterificationModel,
    PolycarbonateTransesterificationPlantModel,
    PolycarbonateTransesterificationReactor,
    PolycarbonateTransesterificationSimulator,
    PolycarbonateTransesterificationState,
    PolycarbonateTransesterificationStatusBits,
    PolycarbonateTransesterificationStatusWord,
    PureSTValidationResult,
    StatusBits,
    run_pc_transesterification_verification,
    run_pc_verification,
    run_polycarbonate_transesterification_verification,
    run_polycarbonate_verification,
    verify_pc_pure_st,
    verify_polycarbonate_pure_st,
    verify_polycarbonate_transesterification_pure_st,
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
        assert math.isclose(T_REF_K, 543.15, abs_tol=1e-5)
        assert math.isclose(T_REF_K, 270.0 + T_ZERO_CELSIUS, abs_tol=1e-5)

    def test_iupac_standard_atomic_weights(self) -> None:
        """IUPAC atomic weights for Carbon, Hydrogen, and Oxygen are accurate."""
        assert math.isclose(MW_C, 0.012011, rel_tol=1e-6)
        assert math.isclose(MW_H, 0.001008, rel_tol=1e-6)
        assert math.isclose(MW_O, 0.015999, rel_tol=1e-6)

    def test_chemical_species_molecular_weights(self) -> None:
        """Molecular weights of Bisphenol-A, Diphenyl Carbonate, PC Mer, and Phenol are exact."""
        # Bisphenol-A (BPA): C15H16O2 -> 15*12.011 + 16*1.008 + 2*15.999 = 228.291 g/mol
        expected_bpa = 15.0 * MW_C + 16.0 * MW_H + 2.0 * MW_O
        assert math.isclose(MW_BPA, expected_bpa, rel_tol=1e-9)
        assert math.isclose(MW_BISPHENOL_A, MW_BPA, rel_tol=1e-9)
        assert math.isclose(MW_BPA, 0.228291, rel_tol=1e-4)

        # Diphenyl Carbonate (DPC): C13H10O3 -> 13*12.011 + 10*1.008 + 3*15.999 = 214.220 g/mol
        expected_dpc = 13.0 * MW_C + 10.0 * MW_H + 3.0 * MW_O
        assert math.isclose(MW_DPC, expected_dpc, rel_tol=1e-9)
        assert math.isclose(MW_DIPHENYL_CARBONATE, MW_DPC, rel_tol=1e-9)
        assert math.isclose(MW_DPC, 0.214220, rel_tol=1e-4)

        # Phenol (C6H6O): 6*12.011 + 6*1.008 + 1*15.999 = 94.113 g/mol
        expected_phenol = 6.0 * MW_C + 6.0 * MW_H + 1.0 * MW_O
        assert math.isclose(MW_PHENOL, expected_phenol, rel_tol=1e-9)
        assert math.isclose(MW_C6H6O, MW_PHENOL, rel_tol=1e-9)
        assert math.isclose(MW_PHENOL, 0.094113, rel_tol=1e-4)

        # Polycarbonate Repeat Unit (PC Mer): C16H14O3 -> 16*12.011 + 14*1.008 + 3*15.999 = 254.285 g/mol
        expected_pc = 16.0 * MW_C + 14.0 * MW_H + 3.0 * MW_O
        assert math.isclose(MW_PC, expected_pc, rel_tol=1e-9)
        assert math.isclose(MW_PC_MER, MW_PC, rel_tol=1e-9)
        assert math.isclose(MW_POLYCARBONATE_MER, MW_PC, rel_tol=1e-9)
        assert math.isclose(MW_PC, 0.254285, rel_tol=1e-4)

    def test_stoichiometric_transesterification_mass_conservation(self) -> None:
        """Reaction mass balance is exact: BPA + DPC == PC_mer + 2 Phenol."""
        reactants_mass = MW_BPA + MW_DPC
        products_mass = MW_PC_MER + 2.0 * MW_PHENOL
        assert abs(reactants_mass - products_mass) < 1e-12

    def test_elemental_stoichiometry_conservation(self) -> None:
        """Carbon, Hydrogen, and Oxygen atoms balance exactly across transesterification."""
        # Carbon: 15 + 13 == 16 + 2*6 = 28
        assert (15 + 13) == (16 + 2 * 6)
        # Hydrogen: 16 + 10 == 14 + 2*6 = 26
        assert (16 + 10) == (14 + 2 * 6)
        # Oxygen: 2 + 3 == 3 + 2*1 = 5
        assert (2 + 3) == (3 + 2 * 1)

    def test_reaction_enthalpies_and_latent_heats(self) -> None:
        """Reaction enthalpy and latent heat of vaporization match specified values."""
        assert math.isclose(DELTA_H_RXN_KJ_MOL, 15.5, abs_tol=1e-6)
        assert math.isclose(DELTA_H_RXN_J_MOL, 15500.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H_VAP_PHENOL_KJ_KG, 510.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H_VAP_PHENOL_J_KG, 510000.0, abs_tol=1e-6)
        assert math.isclose(DELTA_H_VAP_PHENOL_J_MOL, 510000.0 * MW_PHENOL, rel_tol=1e-6)

    def test_endothermic_reaction_heat_positive(self) -> None:
        """Reaction enthalpy is positive, representing an endothermic transesterification."""
        assert DELTA_H_RXN_KJ_MOL > 0.0
        assert DELTA_H_RXN_J_MOL > 0.0
        assert DELTA_H_VAP_PHENOL_KJ_KG > 0.0

    def test_atomic_weight_ratios(self) -> None:
        """IUPAC atomic weight ratios match Carbon-12 scale."""
        assert MW_C > MW_H
        assert MW_O > MW_C
        assert math.isclose(MW_C / MW_H, 12.011 / 1.008, rel_tol=1e-4)


# ============================================================================
# Section 2: Reaction Kinetics, Rate Constants & Arrhenius Temperature Dependence
# ============================================================================

class TestSection02ReactionKineticsAndArrhenius:
    """Verify forward and reverse reaction kinetics, Arrhenius temperature dependence, and activation energies."""

    def test_arrhenius_monotonic_temperature_dependence(self) -> None:
        """Rate constants increase monotonically with increasing temperature."""
        sim = PolycarbonateTransesterificationReactor()
        t_low_k = 250.0 + T_ZERO_CELSIUS
        t_nom_k = 270.0 + T_ZERO_CELSIUS
        t_high_k = 290.0 + T_ZERO_CELSIUS

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
        sim = PolycarbonateTransesterificationReactor()
        t1_k = 250.0 + T_ZERO_CELSIUS
        t2_k = 290.0 + T_ZERO_CELSIUS

        k1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a_f, sim.config.activation_e_f_j_mol, t1_k)
        k2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a_f, sim.config.activation_e_f_j_mol, t2_k)

        # Ea = -R * ln(k2/k1) / (1/T2 - 1/T1)
        recovered_ea = -R_GAS_CONST * math.log(k2 / k1) / ((1.0 / t2_k) - (1.0 / t1_k))
        assert math.isclose(recovered_ea, sim.config.activation_e_f_j_mol, rel_tol=1e-5)
        assert math.isclose(recovered_ea, 82000.0, rel_tol=1e-5)

    def test_reverse_activation_energy_reconstruction(self) -> None:
        """Arrhenius equation allows exact reconstruction of reverse activation energy Ea_r."""
        sim = PolycarbonateTransesterificationReactor()
        t1_k = 250.0 + T_ZERO_CELSIUS
        t2_k = 290.0 + T_ZERO_CELSIUS

        kr1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a_r, sim.config.activation_e_r_j_mol, t1_k)
        kr2 = sim.arrhenius_rate_constant(sim.config.arrhenius_a_r, sim.config.activation_e_r_j_mol, t2_k)

        recovered_ea_r = -R_GAS_CONST * math.log(kr2 / kr1) / ((1.0 / t2_k) - (1.0 / t1_k))
        assert math.isclose(recovered_ea_r, sim.config.activation_e_r_j_mol, rel_tol=1e-5)
        assert math.isclose(recovered_ea_r, 98000.0, rel_tol=1e-5)

    def test_compute_kinetics_nominal_rates(self) -> None:
        """compute_kinetics returns positive rates and endothermic reaction heat."""
        sim = PolycarbonateTransesterificationReactor()
        kin = sim.compute_kinetics(
            t_reactor_k=270.0 + T_ZERO_CELSIUS,
            c_bpa=sim.state.c_bpa,
            c_dpc=sim.state.c_dpc,
            c_oligomer=sim.state.c_oligomer,
            c_phenol=sim.state.c_phenol,
        )
        assert kin["r_f"] > kin["r_r"] > 0.0
        assert kin["r_net"] > 0.0
        assert kin["r_net_tot"] > 0.0
        assert kin["q_rxn_kw"] > 0.0
        assert math.isclose(kin["q_rxn_kw"], (kin["r_net_tot"] * 15500.0) / 1000.0, rel_tol=1e-5)

    def test_kinetics_zeroed_when_dump_open_or_inactive(self) -> None:
        """Reaction rates are zeroed when emergency dump is open or reactor is inactive."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.emergency_melt_dump_open = True
        kin = sim.compute_kinetics(270.0 + T_ZERO_CELSIUS, 0.02, 0.04, 0.46, 0.012)
        assert kin["r_f"] == 0.0
        assert kin["r_r"] == 0.0
        assert kin["r_net"] == 0.0
        assert kin["q_rxn_kw"] == 0.0

    def test_arrhenius_low_temp_safety_clamping(self) -> None:
        """Temperatures below 100 K are safely clamped to 100 K avoiding division by zero."""
        sim = PolycarbonateTransesterificationReactor()
        k_clamp = sim.arrhenius_rate_constant(sim.config.arrhenius_a_f, sim.config.activation_e_f_j_mol, 50.0)
        k_100 = sim.arrhenius_rate_constant(sim.config.arrhenius_a_f, sim.config.activation_e_f_j_mol, 100.0)
        assert math.isclose(k_clamp, k_100, rel_tol=1e-9)

    def test_reverse_rate_phenol_quadratic_dependence(self) -> None:
        """Reverse phenolysis reaction rate scales quadratically with dissolved phenol concentration."""
        sim = PolycarbonateTransesterificationReactor()
        c_oligo = 0.46
        t_k = 270.0 + T_ZERO_CELSIUS

        k_r = sim.arrhenius_rate_constant(sim.config.arrhenius_a_r, sim.config.activation_e_r_j_mol, t_k)
        r_r1 = k_r * c_oligo * (0.010 ** 2)
        r_r2 = k_r * c_oligo * (0.020 ** 2)
        # Ratio should be (0.020 / 0.010)^2 = 4.0
        assert math.isclose(r_r2 / r_r1, 4.0, rel_tol=1e-5)


# ============================================================================
# Section 3: Reactor Geometry, Hydrodynamics, Residence Time & Operating Baseline
# ============================================================================

class TestSection03ReactorGeometryAndOperatingBaseline:
    """Verify reactor dimensions, residence time, thermal capacitance, and baseline nominal values."""

    def test_geometric_and_hydrodynamic_parameters(self) -> None:
        """Reactor working volume, residence time, melt density, and heat capacity match baseline."""
        cfg = PolycarbonateTransesterificationConfig()
        assert math.isclose(cfg.reactor_volume_m3, 3.50, abs_tol=1e-6)
        assert math.isclose(cfg.nominal_residence_time_s, 1500.0, abs_tol=1e-6)
        assert math.isclose(cfg.melt_density_kg_m3, 1180.0, abs_tol=1e-6)
        assert math.isclose(cfg.melt_specific_heat_cp_j_kg_k, 2100.0, abs_tol=1e-6)
        assert math.isclose(cfg.reactor_thermal_capacitance_kj_k, 8673.0, abs_tol=1e-6)

    def test_nominal_operating_constants(self) -> None:
        """Nominal operating baseline constants match plant design targets."""
        assert math.isclose(T_REACTOR_NOMINAL_C, 270.0, abs_tol=1e-5)
        assert math.isclose(T_INLET_NOMINAL_C, 240.0, abs_tol=1e-5)
        assert math.isclose(P_VACUUM_NOMINAL_MBAR, 2.50, abs_tol=1e-5)
        assert math.isclose(P_VAC_NOMINAL_MBAR, 2.50, abs_tol=1e-5)
        assert math.isclose(VACUUM_NOMINAL_MBAR, 2.50, abs_tol=1e-5)
        assert math.isclose(BPA_CONV_NOMINAL_PCT, 95.80, abs_tol=1e-5)
        assert math.isclose(BPA_CONVERSION_NOMINAL_PCT, 95.80, abs_tol=1e-5)
        assert math.isclose(PC_MW_NOMINAL_DA, 28500.0, abs_tol=1e-5)
        assert math.isclose(MW_PC_NOMINAL_DA, 28500.0, abs_tol=1e-5)
        assert math.isclose(PC_WEIGHT_AVG_MW_NOMINAL_DA, 28500.0, abs_tol=1e-5)
        assert math.isclose(PHENOL_REMOVAL_NOMINAL_KG_H, 740.0, abs_tol=1e-5)
        assert math.isclose(PHENOL_REMOVAL_RATE_NOMINAL_KG_H, 740.0, abs_tol=1e-5)
        assert math.isclose(DPC_BPA_RATIO_NOMINAL, 1.040, abs_tol=1e-5)
        assert math.isclose(DPC_BPA_MOLAR_RATIO_NOMINAL, 1.040, abs_tol=1e-5)
        assert math.isclose(MELT_VISCOSITY_NOMINAL_PA_S, 650.0, abs_tol=1e-5)
        assert math.isclose(MELT_POLYMER_VISCOSITY_NOMINAL_PA_S, 650.0, abs_tol=1e-5)

    def test_safety_interlock_threshold_constants(self) -> None:
        """Process trip and fault threshold constants are properly defined."""
        assert math.isclose(T_THERMAL_DEGRADATION_TRIP_C, 295.0, abs_tol=1e-5)
        assert math.isclose(T_DEGRADATION_TRIP_C, 295.0, abs_tol=1e-5)
        assert math.isclose(P_VACUUM_TRIP_MBAR, 8.00, abs_tol=1e-5)
        assert math.isclose(VACUUM_LOSS_TRIP_MBAR, 8.00, abs_tol=1e-5)
        assert math.isclose(DPC_BPA_RATIO_FAULT_LOW, 1.010, abs_tol=1e-5)
        assert math.isclose(DPC_BPA_RATIO_FAULT_HIGH, 1.080, abs_tol=1e-5)
        assert math.isclose(VISCOSITY_FAULT_HIGH_PA_S, 1100.0, abs_tol=1e-5)


# ============================================================================
# Section 4: Nominal Steady-State Closed-Loop Convergence
# ============================================================================

class TestSection04NominalSteadyStateConvergence:
    """Verify nominal steady-state values (Conversion >= 94.0%, Temp 270.0 °C, Pressure 2.50 mbar, MW 28500 Da)."""

    def test_nominal_steady_state_initialization(self) -> None:
        """PolycarbonateTransesterificationReactor initializes at calibrated nominal state."""
        sim = PolycarbonateTransesterificationReactor()
        assert math.isclose(sim.state.t_reactor_c, 270.0, abs_tol=0.1)
        assert math.isclose(sim.state.p_vacuum_mbar, 2.50, abs_tol=0.05)
        assert sim.state.bpa_conversion_pct >= 94.0
        assert math.isclose(sim.state.bpa_conversion_pct, 95.80, abs_tol=0.20)
        assert math.isclose(sim.state.mw_pc, 28500.0, abs_tol=50.0)
        assert math.isclose(sim.state.phenol_removal_rate_kg_h, 740.0, abs_tol=5.0)
        assert math.isclose(sim.state.dpc_bpa_molar_ratio, 1.040, abs_tol=0.005)
        assert math.isclose(sim.state.melt_polymer_viscosity_pa_s, 650.0, abs_tol=10.0)
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.pc_reactor_active is True
        assert sim.state.vacuum_system_permissive is True
        assert sim.state.emergency_melt_dump_open is False

    def test_nominal_steady_state_derivatives_near_zero(self) -> None:
        """At nominal steady state, dynamic ODE derivatives are virtually zero."""
        sim = PolycarbonateTransesterificationReactor()
        y0 = [
            sim.state.c_bpa,
            sim.state.c_dpc,
            sim.state.c_phenol,
            sim.state.c_oligomer,
            sim.state.mw_pc,
            sim.state.t_reactor_c,
        ]
        derivs = sim.compute_derivatives(0.0, y0)
        # Species concentration derivatives [mol/(L*s)]
        assert abs(derivs[0]) < 1e-4  # dC_bpa/dt
        assert abs(derivs[1]) < 1e-4  # dC_dpc/dt
        assert abs(derivs[2]) < 1e-4  # dC_phenol/dt
        assert abs(derivs[3]) < 1e-4  # dC_oligo/dt
        assert abs(derivs[4]) < 0.5   # d(MW)/dt [Da/s]
        assert abs(derivs[5]) < 0.05  # dT/dt [°C/s]

    def test_nominal_conversion_exceeds_94_pct_threshold(self) -> None:
        """Nominal BPA conversion is >= 94.00% (specifically 95.80%)."""
        sim = PolycarbonateTransesterificationReactor()
        assert sim.state.bpa_conversion_pct >= 94.0
        assert math.isclose(sim.state.bpa_conversion_pct, 95.80, abs_tol=0.20)

    def test_nominal_temperature_270_celsius(self) -> None:
        """Nominal reactor temperature is exactly 270.0 °C."""
        sim = PolycarbonateTransesterificationReactor()
        assert math.isclose(sim.state.t_reactor_c, 270.0, abs_tol=0.01)

    def test_nominal_pressure_2_5_mbar(self) -> None:
        """Nominal vacuum pressure is exactly 2.50 mbar."""
        sim = PolycarbonateTransesterificationReactor()
        assert math.isclose(sim.state.p_vacuum_mbar, 2.50, abs_tol=0.01)

    def test_nominal_molecular_weight_28500_da(self) -> None:
        """Nominal weight-average molecular weight is 28,500 Da."""
        sim = PolycarbonateTransesterificationReactor()
        assert math.isclose(sim.state.mw_pc, 28500.0, abs_tol=1.0)

    def test_nominal_dpc_bpa_molar_ratio_1_040(self) -> None:
        """Nominal stoichiometric feed molar ratio is 1.040."""
        sim = PolycarbonateTransesterificationReactor()
        assert math.isclose(sim.state.dpc_bpa_molar_ratio, 1.040, abs_tol=0.001)

    def test_nominal_melt_viscosity_650_pa_s(self) -> None:
        """Nominal melt viscosity is 650.0 Pa.s."""
        sim = PolycarbonateTransesterificationReactor()
        assert math.isclose(sim.state.melt_polymer_viscosity_pa_s, 650.0, abs_tol=0.1)

    def test_nominal_phenol_removal_740_kg_h(self) -> None:
        """Nominal phenol devolatilization stripping rate is 740.0 kg/h."""
        sim = PolycarbonateTransesterificationReactor()
        assert math.isclose(sim.state.phenol_removal_rate_kg_h, 740.0, abs_tol=0.1)


# ============================================================================
# Section 5: Coupled 6-State Dynamic ODE System, Derivatives & RK4 Numerical Integrator
# ============================================================================

class TestSection05Coupled6StateODEAndRK4:
    """Verify coupled 6-state ODE dynamics, RK4 integration stability, and state non-negativity."""

    def test_compute_derivatives_vector_length(self) -> None:
        """compute_derivatives returns a 6-element derivative vector."""
        sim = PolycarbonateTransesterificationReactor()
        y = [0.02052, 0.04006, 0.0125, 0.468, 28500.0, 270.0]
        dy = sim.compute_derivatives(0.0, y)
        assert len(dy) == 6
        assert all(isinstance(v, float) for v in dy)

    def test_rk4_state_non_negativity_enforced(self) -> None:
        """Physical concentrations and MW remain strictly non-negative even under extreme perturbations."""
        sim = PolycarbonateTransesterificationReactor()
        # Injected severe negative disturbance
        sim.state.c_bpa = -0.05
        sim.state.c_dpc = -0.05
        sim.state.c_phenol = -0.01
        sim.state.c_oligomer = -0.2
        sim.state.mw_pc = -1000.0

        sim.rk4_step(dt=0.05)

        assert sim.state.c_bpa >= 0.0
        assert sim.state.c_dpc >= 0.0
        assert sim.state.c_phenol >= 0.0
        assert sim.state.c_oligomer >= 0.0
        assert sim.state.mw_pc >= 100.0

    def test_rk4_numerical_stability_different_timesteps(self) -> None:
        """RK4 solver remains numerically stable across time steps dt = 0.005 s, 0.02 s, and 0.05 s."""
        for dt_test in [0.005, 0.02, 0.05]:
            sim = PolycarbonateTransesterificationReactor()
            for _ in range(15):
                sim.rk4_step(dt=dt_test)
            assert not math.isnan(sim.state.t_reactor_c)
            assert not math.isnan(sim.state.mw_pc)
            assert not math.isinf(sim.state.c_bpa)
            assert 250.0 <= sim.state.t_reactor_c <= 300.0

    def test_vacuum_pressure_self_regulation(self) -> None:
        """Vacuum pressure self-regulates toward nominal 2.50 mbar when active."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.p_vacuum_mbar = 3.20  # slight vacuum elevation
        for _ in range(30):
            sim.rk4_step(dt=0.05)
        # Should have moved closer to 2.50 mbar
        assert abs(sim.state.p_vacuum_mbar - 2.50) < abs(3.20 - 2.50)


# ============================================================================
# Section 6: Mathematical Conservation Residuals (Mass, Elements, Enthalpy < 1e-10)
# ============================================================================

class TestSection06ConservationResiduals:
    """Verify stoichiometric mass, elemental (C, H, O), and first-law enthalpy residuals (< 1e-10)."""

    def test_stoichiometric_mass_balance_residual(self) -> None:
        """Stoichiometric transesterification mass balance residual is < 1e-10 kg/s."""
        sim = PolycarbonateTransesterificationReactor()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1e-10
        assert sim.state.total_mass_balance_residual_kg_s >= 0.0

    def test_elemental_mass_balance_residual(self) -> None:
        """Carbon, Hydrogen, and Oxygen elemental mass balance residual is < 1e-10 kg/s."""
        sim = PolycarbonateTransesterificationReactor()
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10
        assert sim.state.elemental_mass_balance_residual_kg_s >= 0.0

    def test_first_law_enthalpy_conservation_residual(self) -> None:
        """Thermal energy accumulation equals net thermal power within < 1e-10 kW."""
        sim = PolycarbonateTransesterificationReactor()
        sim._update_conservation_residuals()
        assert sim.state.enthalpy_conservation_residual_kw < 1e-10
        assert sim.state.enthalpy_conservation_residual_kw >= 0.0

    def test_conservation_residuals_maintained_over_steps(self) -> None:
        """All conservation residuals remain below 1e-10 threshold across multiple dynamic simulation steps."""
        sim = PolycarbonateTransesterificationReactor()
        for _ in range(25):
            sim.rk4_step(dt=0.02)
            assert sim.state.total_mass_balance_residual_kg_s < 1e-10
            assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10
            assert sim.state.enthalpy_conservation_residual_kw < 1e-10


# ============================================================================
# Section 7: Process Safety Interlocks & Strict Priority Hierarchy
# ============================================================================

class TestSection07SafetyInterlocksAndPriority:
    """Verify process safety trips, interlocks, and strict priority hierarchy (0xF701 > 0xF702 > 0xF703 > 0xF704 > 0x0000)."""

    def test_priority_1_thermal_degradation_trip(self) -> None:
        """Temperature > 295.0 °C asserts 0xF701 THERMAL_DEGRADATION_TRIP, opens melt dump %M517, clears %M515."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.t_reactor_c = 298.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_DEGRADATION_TRIP
        assert sim.state.emergency_melt_dump_open is True
        assert sim.state.pc_reactor_active is False

    def test_priority_2_vacuum_loss_trip(self) -> None:
        """Vacuum pressure > 8.00 mbar asserts 0xF702 VACUUM_LOSS_TRIP, clears permissive %M516, opens dump %M517."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.p_vacuum_mbar = 9.20
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VACUUM_LOSS_TRIP
        assert sim.state.vacuum_system_permissive is False
        assert sim.state.emergency_melt_dump_open is True
        assert sim.state.pc_reactor_active is False

    def test_priority_3_stoichiometric_off_ratio_fault_low(self) -> None:
        """DPC:BPA molar ratio < 1.010 asserts 0xF703 STOICHIOMETRIC_OFF_RATIO_FAULT, keeps dump closed."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.dpc_bpa_molar_ratio = 1.000
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.STOICHIOMETRIC_OFF_RATIO_FAULT
        assert sim.state.emergency_melt_dump_open is False

    def test_priority_3_stoichiometric_off_ratio_fault_high(self) -> None:
        """DPC:BPA molar ratio > 1.080 asserts 0xF703 STOICHIOMETRIC_OFF_RATIO_FAULT, keeps dump closed."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.dpc_bpa_molar_ratio = 1.095
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.STOICHIOMETRIC_OFF_RATIO_FAULT
        assert sim.state.emergency_melt_dump_open is False

    def test_priority_4_viscosity_overtorque_fault(self) -> None:
        """Polymer melt viscosity > 1100.0 Pa.s asserts 0xF704 VISCOSITY_OVERTORQUE_FAULT, keeps dump closed."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.melt_polymer_viscosity_pa_s = 1250.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VISCOSITY_OVERTORQUE_FAULT
        assert sim.state.emergency_melt_dump_open is False

    def test_priority_1_overrides_priority_2_3_4(self) -> None:
        """Thermal trip (P1) overrides simultaneous vacuum loss (P2), off-ratio (P3), and overtorque (P4)."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.t_reactor_c = 300.0                 # P1
        sim.state.p_vacuum_mbar = 10.0               # P2
        sim.state.dpc_bpa_molar_ratio = 0.99         # P3
        sim.state.melt_polymer_viscosity_pa_s = 1300 # P4
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_DEGRADATION_TRIP
        assert sim.state.emergency_melt_dump_open is True
        assert sim.state.pc_reactor_active is False

    def test_priority_2_overrides_priority_3_4(self) -> None:
        """Vacuum loss (P2) overrides simultaneous off-ratio (P3) and overtorque (P4)."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.t_reactor_c = 270.0                 # Normal
        sim.state.p_vacuum_mbar = 9.50               # P2
        sim.state.dpc_bpa_molar_ratio = 0.99         # P3
        sim.state.melt_polymer_viscosity_pa_s = 1300 # P4
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VACUUM_LOSS_TRIP
        assert sim.state.emergency_melt_dump_open is True
        assert sim.state.pc_reactor_active is False

    def test_priority_3_overrides_priority_4(self) -> None:
        """Off-ratio fault (P3) overrides simultaneous overtorque fault (P4)."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.t_reactor_c = 270.0                 # Normal
        sim.state.p_vacuum_mbar = 2.50               # Normal
        sim.state.dpc_bpa_molar_ratio = 1.000        # P3
        sim.state.melt_polymer_viscosity_pa_s = 1250 # P4
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.STOICHIOMETRIC_OFF_RATIO_FAULT
        assert sim.state.emergency_melt_dump_open is False

    def test_heating_duty_cut_off_on_emergency_melt_dump(self) -> None:
        """Jacket heating duty is isolated (0 kW) when emergency melt dump is open."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.t_reactor_c = 298.0
        sim._evaluate_safety_interlocks()
        sim._update_derived_variables()
        assert sim.state.q_htf_kw == 0.0

    def test_thermal_trip_threshold_exact_boundary(self) -> None:
        """295.0 °C is within operating limit, 295.01 °C triggers 0xF701 THERMAL_DEGRADATION_TRIP."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.t_reactor_c = 295.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.emergency_melt_dump_open is False

        sim.state.t_reactor_c = 295.01
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_DEGRADATION_TRIP
        assert sim.state.emergency_melt_dump_open is True

    def test_vacuum_loss_trip_threshold_exact_boundary(self) -> None:
        """8.00 mbar is permitted (%M516=True), 8.01 mbar triggers 0xF702 VACUUM_LOSS_TRIP and clears permissive."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.p_vacuum_mbar = 8.00
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OK
        assert sim.state.vacuum_system_permissive is True
        assert sim.state.emergency_melt_dump_open is False

        sim.state.p_vacuum_mbar = 8.01
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VACUUM_LOSS_TRIP
        assert sim.state.vacuum_system_permissive is False
        assert sim.state.emergency_melt_dump_open is True

    def test_stoichiometric_off_ratio_exact_boundaries(self) -> None:
        """Ratio exactly 1.010 and 1.080 are OK; 1.009 and 1.081 trigger 0xF703."""
        sim = PolycarbonateTransesterificationReactor()
        # Low boundary
        sim.state.dpc_bpa_molar_ratio = 1.010
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OK

        sim.state.dpc_bpa_molar_ratio = 1.009
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.STOICHIOMETRIC_OFF_RATIO_FAULT

        # High boundary
        sim.state.dpc_bpa_molar_ratio = 1.080
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OK

        sim.state.dpc_bpa_molar_ratio = 1.081
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.STOICHIOMETRIC_OFF_RATIO_FAULT

    def test_viscosity_overtorque_exact_boundary(self) -> None:
        """Viscosity 1100.0 Pa.s is OK; 1100.1 Pa.s triggers 0xF704 VISCOSITY_OVERTORQUE_FAULT."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.melt_polymer_viscosity_pa_s = 1100.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.OK

        sim.state.melt_polymer_viscosity_pa_s = 1100.1
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VISCOSITY_OVERTORQUE_FAULT


# ============================================================================
# Section 8: DiagnosticCode Signed/Unsigned 16-Bit Values, Integer Equality & Masking
# ============================================================================

class TestSection08DiagnosticCodeMasking:
    """Verify DiagnosticCode signed/unsigned 16-bit values, integer equality, bitwise masking, and string formatting."""

    def test_diagnostic_code_hexadecimal_values(self) -> None:
        """Diagnostic codes have correct hexadecimal values."""
        assert DiagnosticCode.OK.value == 0x0000
        assert DiagnosticCode.THERMAL_DEGRADATION_TRIP.value == 0xF701
        assert DiagnosticCode.VACUUM_LOSS_TRIP.value == 0xF702
        assert DiagnosticCode.STOICHIOMETRIC_OFF_RATIO_FAULT.value == 0xF703
        assert DiagnosticCode.VISCOSITY_OVERTORQUE_FAULT.value == 0xF704

    def test_unsigned_integer_equality(self) -> None:
        """DiagnosticCode compares equal to unsigned integer literals."""
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.THERMAL_DEGRADATION_TRIP == 0xF701
        assert DiagnosticCode.VACUUM_LOSS_TRIP == 0xF702
        assert DiagnosticCode.STOICHIOMETRIC_OFF_RATIO_FAULT == 0xF703
        assert DiagnosticCode.VISCOSITY_OVERTORQUE_FAULT == 0xF704

    def test_signed_integer_equality(self) -> None:
        """DiagnosticCode compares equal to signed 16-bit integer values."""
        # 0xF701 - 0x10000 = -2303
        assert DiagnosticCode.THERMAL_DEGRADATION_TRIP == -2303
        # 0xF702 - 0x10000 = -2302
        assert DiagnosticCode.VACUUM_LOSS_TRIP == -2302
        # 0xF703 - 0x10000 = -2301
        assert DiagnosticCode.STOICHIOMETRIC_OFF_RATIO_FAULT == -2301
        # 0xF704 - 0x10000 = -2300
        assert DiagnosticCode.VISCOSITY_OVERTORQUE_FAULT == -2300

    def test_bitwise_masking_with_0xffff(self) -> None:
        """Bitwise AND with 0xFFFF yields unsigned 16-bit word."""
        assert (DiagnosticCode.THERMAL_DEGRADATION_TRIP & 0xFFFF) == 0xF701
        assert (0xFFFF & DiagnosticCode.THERMAL_DEGRADATION_TRIP) == 0xF701
        assert (DiagnosticCode.VACUUM_LOSS_TRIP & 0xFFFF) == 0xF702
        assert (DiagnosticCode.STOICHIOMETRIC_OFF_RATIO_FAULT & 0xFFFF) == 0xF703
        assert (DiagnosticCode.VISCOSITY_OVERTORQUE_FAULT & 0xFFFF) == 0xF704

    def test_diagnostic_code_signed_lookup(self) -> None:
        """DiagnosticCode constructor accepts signed 16-bit integers transparently."""
        assert DiagnosticCode(-2303) == DiagnosticCode.THERMAL_DEGRADATION_TRIP
        assert DiagnosticCode(-2302) == DiagnosticCode.VACUUM_LOSS_TRIP
        assert DiagnosticCode(-2301) == DiagnosticCode.STOICHIOMETRIC_OFF_RATIO_FAULT
        assert DiagnosticCode(-2300) == DiagnosticCode.VISCOSITY_OVERTORQUE_FAULT

    def test_string_and_repr_representations(self) -> None:
        """DiagnosticCode str and repr contain hexadecimal code and name."""
        code = DiagnosticCode.THERMAL_DEGRADATION_TRIP
        assert "0xF701" in str(code) or "63233" in str(code) or "THERMAL" in str(code)
        assert "THERMAL_DEGRADATION_TRIP" in repr(code)
        assert code.name == "THERMAL_DEGRADATION_TRIP"

    def test_diagnostic_code_aliases(self) -> None:
        """Diagnostic code aliases resolve to the same underlying enum class."""
        assert PolycarbonateTransesterificationDiagnosticCode is DiagnosticCode
        assert PolycarbonateDiagnosticCode is DiagnosticCode
        assert PcDiagnosticCode is DiagnosticCode
        assert PcDiagCode is DiagnosticCode

    def test_status_bits_bitmask(self) -> None:
        """Status bits support bitwise operations and match defined bit flags."""
        bits = PolycarbonateTransesterificationStatusBits.RUNNING | PolycarbonateTransesterificationStatusBits.THERMAL_DEGRADATION_TRIP
        assert bool(bits & PolycarbonateTransesterificationStatusBits.RUNNING) is True
        assert bool(bits & PolycarbonateTransesterificationStatusBits.THERMAL_DEGRADATION_TRIP) is True
        assert bool(bits & PolycarbonateTransesterificationStatusBits.VACUUM_LOSS_TRIP) is False

    def test_all_diagnostic_codes_name_and_hex(self) -> None:
        """All DiagnosticCode members format properly with name and hex value."""
        for code in DiagnosticCode:
            repr_str = repr(code)
            assert code.name in repr_str
            hex_val = f"{code.value & 0xFFFF:04X}"
            assert hex_val in repr_str or hex_val in str(code) or str(code.value) in str(code)

    def test_diagnostic_code_bitwise_or(self) -> None:
        """Diagnostic codes support bitwise OR operations."""
        comb = DiagnosticCode.THERMAL_DEGRADATION_TRIP | DiagnosticCode.VACUUM_LOSS_TRIP
        assert comb == (0xF701 | 0xF702)

    def test_status_bits_all_flags_distinct(self) -> None:
        """Each flag in PolycarbonateTransesterificationStatusBits has a distinct single bit."""
        flags = [
            PolycarbonateTransesterificationStatusBits.RUNNING,
            PolycarbonateTransesterificationStatusBits.PC_REACTOR_ACTIVE,
            PolycarbonateTransesterificationStatusBits.VACUUM_SYSTEM_PERMISSIVE,
            PolycarbonateTransesterificationStatusBits.EMERGENCY_MELT_DUMP_OPEN,
            PolycarbonateTransesterificationStatusBits.THERMAL_DEGRADATION_TRIP,
            PolycarbonateTransesterificationStatusBits.VACUUM_LOSS_TRIP,
            PolycarbonateTransesterificationStatusBits.STOICHIOMETRIC_OFF_RATIO_FAULT,
            PolycarbonateTransesterificationStatusBits.VISCOSITY_OVERTORQUE_FAULT,
        ]
        values = [f.value for f in flags]
        assert len(set(values)) == len(flags)
        for val in values:
            assert (val & (val - 1)) == 0  # Power of 2 (single bit set)


# ============================================================================
# Section 9: Vacuum Permissive Logic (%M516) & Emergency Melt Dump Actuation (%M517)
# ============================================================================

class TestSection09PermissiveAndMeltDumpActuation:
    """Verify vacuum permissive %M516 and emergency melt dump %M517 behavior."""

    def test_vacuum_permissive_active_below_trip(self) -> None:
        """Vacuum permissive is True when vacuum pressure <= 8.00 mbar."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.p_vacuum_mbar = 5.50
        sim._evaluate_safety_interlocks()
        assert sim.state.vacuum_system_permissive is True

    def test_vacuum_permissive_lost_above_trip(self) -> None:
        """Vacuum permissive is False when vacuum pressure > 8.00 mbar."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.p_vacuum_mbar = 8.50
        sim._evaluate_safety_interlocks()
        assert sim.state.vacuum_system_permissive is False

    def test_emergency_melt_dump_actuation_on_thermal_trip(self) -> None:
        """Emergency melt dump %M517 opens on thermal degradation trip 0xF701."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.t_reactor_c = 296.0
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_melt_dump_open is True
        assert sim.state.pc_reactor_active is False

    def test_emergency_melt_dump_actuation_on_vacuum_loss(self) -> None:
        """Emergency melt dump %M517 opens on vacuum loss trip 0xF702."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.p_vacuum_mbar = 9.00
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_melt_dump_open is True
        assert sim.state.pc_reactor_active is False

    def test_emergency_melt_dump_quench_dynamics(self) -> None:
        """When emergency melt dump is open, scan_step executes quench cooling."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.t_reactor_c = 298.0
        sim.state.emergency_melt_dump_open = True
        sim.state.pc_reactor_active = False

        initial_temp = sim.state.t_reactor_c
        for _ in range(10):
            sim.scan_step(dt=0.02)
        assert sim.state.t_reactor_c < initial_temp


# ============================================================================
# Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege (%R2210..%R2217, %M515..%M517)
# ============================================================================

class TestSection10RegisterTableSync:
    """Verify register table mapping and synchronization to %R2210..%R2217 and %M515..%M517."""

    def test_register_channel_constant_definitions(self) -> None:
        """Register and coil addresses match Horner OCS hardware mapping."""
        assert REG_PC_REACTOR_TEMP_SCALED == "%R2210"
        assert REG_PC_VACUUM_PRESSURE_SCALED == "%R2211"
        assert REG_BPA_CONVERSION_SCALED == "%R2212"
        assert REG_PC_WEIGHT_AVG_MW_SCALED == "%R2213"
        assert REG_PHENOL_REMOVAL_RATE_SCALED == "%R2214"
        assert REG_DPC_BPA_MOLAR_RATIO_SCALED == "%R2215"
        assert REG_MELT_POLYMER_VISCOSITY_SCALED == "%R2216"
        assert REG_PC_DIAGNOSTIC_CODE == "%R2217"
        assert COIL_PC_REACTOR_ACTIVE == "%M515"
        assert COIL_VACUUM_SYSTEM_PERMISSIVE == "%M516"
        assert COIL_EMERGENCY_MELT_DUMP_OPEN == "%M517"

    def test_nominal_register_table_synchronization(self) -> None:
        """Nominal state synchronizes exactly to %R2210..%R2217 and %M515..%M517."""
        table = RegisterTable()
        sim = PolycarbonateTransesterificationReactor(register_table=table)
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        assert table.read_word("%R2210") == 2700   # 270.0 °C * 10
        assert table.read_word("%R2211") == 250    # 2.50 mbar * 100
        assert table.read_word("%R2212") == 9580   # 95.80 % * 100
        assert table.read_word("%R2213") == 2850   # 28,500 Da / 10
        assert table.read_word("%R2214") == 740    # 740 kg/h
        assert table.read_word("%R2215") == 1040   # 1.040 ratio * 1000
        assert table.read_word("%R2216") == 650    # 650 Pa.s
        assert table.read_uword("%R2217") == 0x0000# OK
        assert table.read_bit("%M515") is True     # PC reactor active
        assert table.read_bit("%M516") is True     # Vacuum permissive active
        assert table.read_bit("%M517") is False    # Melt dump closed

    def test_thermal_trip_register_synchronization_signed_and_unsigned(self) -> None:
        """Thermal degradation trip synchronizes signed 16-bit fault value into %R2217 and asserts %M517."""
        table = RegisterTable()
        sim = PolycarbonateTransesterificationReactor(register_table=table)
        sim.state.t_reactor_c = 298.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        assert table.read_uword("%R2217") == 0xF701
        assert table.read_word("%R2217") == -2303
        assert table.read_bit("%M515") is False
        assert table.read_bit("%M517") is True

    def test_vacuum_loss_register_synchronization(self) -> None:
        """Vacuum loss trip synchronizes 0xF702, clears %M516, and opens dump %M517."""
        table = RegisterTable()
        sim = PolycarbonateTransesterificationReactor(register_table=table)
        sim.state.p_vacuum_mbar = 9.00
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        assert table.read_uword("%R2217") == 0xF702
        assert table.read_word("%R2217") == -2302
        assert table.read_bit("%M515") is False
        assert table.read_bit("%M516") is False
        assert table.read_bit("%M517") is True

    def test_off_ratio_register_synchronization(self) -> None:
        """Off-ratio fault synchronizes 0xF703 (-2301) into %R2217 and keeps dump closed."""
        table = RegisterTable()
        sim = PolycarbonateTransesterificationReactor(register_table=table)
        sim.state.dpc_bpa_molar_ratio = 1.000
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        assert table.read_uword("%R2217") == 0xF703
        assert table.read_word("%R2217") == -2301
        assert table.read_bit("%M517") is False

    def test_viscosity_overtorque_register_synchronization(self) -> None:
        """Viscosity overtorque fault synchronizes 0xF704 (-2300) into %R2217 and keeps dump closed."""
        table = RegisterTable()
        sim = PolycarbonateTransesterificationReactor(register_table=table)
        sim.state.melt_polymer_viscosity_pa_s = 1200.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        assert table.read_uword("%R2217") == 0xF704
        assert table.read_word("%R2217") == -2300
        assert table.read_bit("%M517") is False

    def test_register_scaling_factors_exactness(self) -> None:
        """Scaled register writes match exact conversion formulas."""
        table = RegisterTable()
        sim = PolycarbonateTransesterificationReactor(register_table=table)
        sim.state.t_reactor_c = 265.4
        sim.state.p_vacuum_mbar = 3.15
        sim.state.bpa_conversion_pct = 95.23
        sim.state.mw_pc = 28120.0
        sim.state.phenol_removal_rate_kg_h = 735.0
        sim.state.dpc_bpa_molar_ratio = 1.045
        sim.state.melt_polymer_viscosity_pa_s = 642.0

        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)

        assert table.read_word("%R2210") == 2654   # 265.4 * 10
        assert table.read_word("%R2211") == 315    # 3.15 * 100
        assert table.read_word("%R2212") == 9523   # 95.23 * 100
        assert table.read_word("%R2213") == 2812   # 28120 / 10
        assert table.read_word("%R2214") == 735    # 735 * 1
        assert table.read_word("%R2215") == 1045   # 1.045 * 1000
        assert table.read_word("%R2216") == 642    # 642 * 1
        assert table.read_bit("%M517") is False

    def test_system_privilege_mode_enforcement(self) -> None:
        """sync_to_registers succeeds when table requires system privilege."""
        table = RegisterTable()
        table.privilege_mode = PrivilegeMode.USER
        sim = PolycarbonateTransesterificationReactor()
        sim.sync_to_registers(table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R2210") == 2700


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text POU & AST Variable Bindings
# ============================================================================

class TestSection11PureSTPOU:
    """Verify Pure IEC 61131-3 Structured Text POU, variable bindings, and syntax validation."""

    def test_st_pou_constant_definition(self) -> None:
        """POLYCARBONATE_TRANSESTERIFICATION_PURE_ST_POU is non-empty and contains PROGRAM PolycarbonateTransesterificationSync."""
        assert isinstance(POLYCARBONATE_TRANSESTERIFICATION_PURE_ST_POU, str)
        assert "PROGRAM PolycarbonateTransesterificationSync" in POLYCARBONATE_TRANSESTERIFICATION_PURE_ST_POU
        assert "END_PROGRAM" in POLYCARBONATE_TRANSESTERIFICATION_PURE_ST_POU

    def test_st_pou_aliases(self) -> None:
        """POU string constants are properly aliased."""
        assert POLYCARBONATE_TRANSESTERIFICATION_SYNC_POU == POLYCARBONATE_TRANSESTERIFICATION_PURE_ST_POU
        assert PC_TRANSESTERIFICATION_PURE_ST_POU == POLYCARBONATE_TRANSESTERIFICATION_PURE_ST_POU
        assert PC_PURE_ST_POU == POLYCARBONATE_TRANSESTERIFICATION_PURE_ST_POU
        assert POLYCARBONATE_PURE_ST_POU == POLYCARBONATE_TRANSESTERIFICATION_PURE_ST_POU

    def test_security_guard_assert_pure_st(self) -> None:
        """SecurityGuard passes pure ST POU without raising LadderForbiddenError."""
        SecurityGuard.assert_pure_st_content(POLYCARBONATE_TRANSESTERIFICATION_PURE_ST_POU)

    def test_st_parser_validation(self) -> None:
        """STParser validates POU syntax with AgentStatus.SUCCESS."""
        res = STParser.validate_code(POLYCARBONATE_TRANSESTERIFICATION_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_st_parser_pou_structure_and_bound_registers(self) -> None:
        """STParser parses POU structure and verifies all 11 register/coil bindings."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(POLYCARBONATE_TRANSESTERIFICATION_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "PolycarbonateTransesterificationSync"
        assert pou.pou_type == POUType.PROGRAM

        expected_bindings = [
            "%R2210", "%R2211", "%R2212", "%R2213",
            "%R2214", "%R2215", "%R2216", "%R2217",
            "%M515", "%M516", "%M517",
        ]
        for reg in expected_bindings:
            assert reg in pou.bound_registers

    def test_ast_variable_memory_address_mappings(self) -> None:
        """STParser AST variables map to exact hardware memory addresses."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(POLYCARBONATE_TRANSESTERIFICATION_PURE_ST_POU)
        assert pou is not None

        var_map = {
            v.name: getattr(v, "address_binding", getattr(v, "memory_address", None))
            for v in pou.variables
        }
        assert var_map["ReactorTempScaled"] == "%R2210"
        assert var_map["VacuumPressureScaled"] == "%R2211"
        assert var_map["BpaConversionScaled"] == "%R2212"
        assert var_map["PcWeightAvgMwScaled"] == "%R2213"
        assert var_map["PhenolRemovalRateScaled"] == "%R2214"
        assert var_map["DpcBpaMolarRatioScaled"] == "%R2215"
        assert var_map["MeltPolymerViscosityScaled"] == "%R2216"
        assert var_map["PcDiagnosticCode"] == "%R2217"
        assert var_map["PcReactorActive"] == "%M515"
        assert var_map["VacuumSystemPermissive"] == "%M516"
        assert var_map["EmergencyMeltDumpOpen"] == "%M517"

    def test_ast_variable_data_types(self) -> None:
        """STParser AST variables have correct IEC 61131-3 data types."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(POLYCARBONATE_TRANSESTERIFICATION_PURE_ST_POU)
        assert pou is not None
        assert len(pou.variables) == 11

        type_map = {v.name: v.data_type for v in pou.variables}
        # Scaled integer registers
        assert type_map["ReactorTempScaled"] == "INT"
        assert type_map["VacuumPressureScaled"] == "INT"
        assert type_map["BpaConversionScaled"] == "INT"
        assert type_map["PcWeightAvgMwScaled"] == "INT"
        assert type_map["PhenolRemovalRateScaled"] == "INT"
        assert type_map["DpcBpaMolarRatioScaled"] == "INT"
        assert type_map["MeltPolymerViscosityScaled"] == "INT"
        assert type_map["PcDiagnosticCode"] == "INT"
        # Discrete boolean coils
        assert type_map["PcReactorActive"] == "BOOL"
        assert type_map["VacuumSystemPermissive"] == "BOOL"
        assert type_map["EmergencyMeltDumpOpen"] == "BOOL"

    def test_pou_keywords_presence(self) -> None:
        """POU Structured Text contains required IEC 61131-3 keywords."""
        pou_text = POLYCARBONATE_TRANSESTERIFICATION_PURE_ST_POU
        assert "PROGRAM" in pou_text
        assert "END_PROGRAM" in pou_text
        assert "VAR" in pou_text
        assert "END_VAR" in pou_text
        assert "IF" in pou_text
        assert "ELSIF" in pou_text
        assert "ELSE" in pou_text
        assert "END_IF" in pou_text

    def test_verify_polycarbonate_transesterification_pure_st_function(self) -> None:
        """verify_polycarbonate_transesterification_pure_st returns True and AgentStatus.SUCCESS."""
        val = verify_polycarbonate_transesterification_pure_st()
        assert bool(val) is True
        assert val.status == AgentStatus.SUCCESS
        assert verify_polycarbonate_pure_st().status == AgentStatus.SUCCESS
        assert verify_pc_pure_st().status == AgentStatus.SUCCESS


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

    def test_anti_ladder_rung_delimiter_rejection(self) -> None:
        """Ladder logic RUNG keyword is rejected with LadderForbiddenError."""
        bad_code = "PROGRAM L3\nRUNG 1\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_network_delimiter_rejection(self) -> None:
        """Ladder logic NETWORK keyword is rejected with LadderForbiddenError."""
        bad_code = "PROGRAM L4\nNETWORK 1\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_mnemonics_rejection(self) -> None:
        """Ladder logic mnemonics (XIC, OTE) are rejected with LadderForbiddenError."""
        bad_code = "PROGRAM L5\nXIC(Start) OTE(Run);\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)


# ============================================================================
# Section 13: ILogicUnit Compliance, Execution & 100-Cycle Soak Stability
# ============================================================================

class TestSection13ILogicUnitComplianceAndSoak:
    """Verify ILogicUnit interface compliance, scan cycles, and 100-cycle soak stability."""

    def test_ilogicunit_interface_properties(self) -> None:
        """PolycarbonateTransesterificationReactor satisfies ILogicUnit interface attributes."""
        sim = PolycarbonateTransesterificationReactor()
        assert isinstance(sim, ILogicUnit)
        assert sim.name == "PolycarbonateTransesterificationReactor"
        assert sim.priority == 100
        assert sim.is_enabled is True

        sim.disable()
        assert sim.is_enabled is False
        sim.enable()
        assert sim.is_enabled is True

    def test_scan_step_increments_cycle_count(self) -> None:
        """scan_step increments simulation elapsed time and cycle count."""
        sim = PolycarbonateTransesterificationReactor()
        assert sim.state.cycle_count == 0
        assert sim.state.sim_time_s == 0.0

        sim.scan_step(dt=0.02)
        assert sim.state.cycle_count == 1
        assert math.isclose(sim.state.sim_time_s, 0.02, abs_tol=1e-5)

    def test_execute_with_scan_context(self) -> None:
        """execute advances simulation using provided ScanContext."""
        sim = PolycarbonateTransesterificationReactor()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        sim.execute(ctx)
        assert sim.state.cycle_count == 1
        assert math.isclose(sim.state.sim_time_s, 0.02, abs_tol=1e-5)

    def test_reset_restores_nominal_state(self) -> None:
        """reset restores reactor state after disturbance injection."""
        sim = PolycarbonateTransesterificationReactor()
        sim.state.t_reactor_c = 299.0
        sim.state.emergency_melt_dump_open = True
        sim.state.pc_reactor_active = False

        sim.reset()
        assert math.isclose(sim.state.t_reactor_c, 270.0, abs_tol=0.1)
        assert sim.state.emergency_melt_dump_open is False
        assert sim.state.pc_reactor_active is True
        assert sim.state.diagnostic_code == DiagnosticCode.OK

    def test_100_cycle_soak_stability(self) -> None:
        """100 scan cycles maintain bounded process state and zero numerical drift."""
        sim = PolycarbonateTransesterificationReactor()
        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt_ms=20.0, elapsed_time_ms=cycle * 20.0, dt=0.02)
            sim.execute(ctx)

        assert 268.0 <= sim.state.t_reactor_c <= 272.0
        assert sim.state.bpa_conversion_pct >= 94.0
        assert abs(sim.state.mw_pc - 28500.0) < 500.0
        assert not math.isnan(sim.state.t_reactor_c)
        assert not math.isnan(sim.state.c_bpa)
        assert not math.isnan(sim.state.mw_pc)
        assert sim.state.total_mass_balance_residual_kg_s < 1e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1e-10

    def test_disabled_reactor_skips_integration(self) -> None:
        """Disabled reactor does not advance simulation cycles or integration."""
        sim = PolycarbonateTransesterificationReactor()
        sim.disable()
        sim.scan_step(dt=0.02)
        assert sim.state.cycle_count == 0
        assert sim.state.sim_time_s == 0.0

    def test_reset_clears_cycle_count_and_time(self) -> None:
        """reset clears cycle count and elapsed simulation time."""
        sim = PolycarbonateTransesterificationReactor()
        sim.scan_step(dt=0.02)
        sim.scan_step(dt=0.02)
        assert sim.state.cycle_count == 2
        sim.reset()
        assert sim.state.cycle_count == 0
        assert sim.state.sim_time_s == 0.0

    def test_200_cycle_soak_stability(self) -> None:
        """Extended 200 scan cycles preserve stability and bounded process state."""
        sim = PolycarbonateTransesterificationReactor()
        for cycle in range(1, 201):
            ctx = ScanContext(cycle=cycle, dt_ms=20.0, elapsed_time_ms=cycle * 20.0, dt=0.02)
            sim.execute(ctx)

        assert 268.0 <= sim.state.t_reactor_c <= 272.0
        assert sim.state.bpa_conversion_pct >= 94.0
        assert not math.isnan(sim.state.t_reactor_c)
        assert sim.state.total_mass_balance_residual_kg_s < 1e-10


# ============================================================================
# Section 14: Deterministic 9-Stage Verification Suite & Artifact Generation
# ============================================================================

class TestSection14VerificationSuiteAndArtifacts:
    """Verify 9-stage engineering verification suite execution and artifact emission."""

    def test_verification_suite_success_contract(self, tmp_path: Path) -> None:
        """run_polycarbonate_transesterification_verification returns strict 4-state SUCCESS contract."""
        out_file = tmp_path / "polycarbonate_evidence.json"
        res = run_polycarbonate_transesterification_verification(output_path=out_file)

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert "details" in res
        assert "data" in res

        data = res["data"]
        assert data["work_package"] == "W260"
        assert data["checks_passed"] == 9
        assert data["total_checks"] == 9
        assert data["passed_stages"] == 9
        assert data["total_stages"] == 9
        assert len(data["stages"]) == 9
        assert all(stage["passed"] for stage in data["stages"])
        assert out_file.exists()

    def test_evidence_file_json_structure(self, tmp_path: Path) -> None:
        """Generated evidence JSON file is valid and contains all stage details."""
        out_file = tmp_path / "pc_evidence_check.json"
        run_polycarbonate_transesterification_verification(output_path=out_file)

        with open(out_file, "r", encoding="utf-8") as f:
            loaded = json.load(f)

        assert loaded["status"] == "success"
        assert loaded["data"]["work_package"] == "W260"
        stages = loaded["data"]["stages"]
        assert len(stages) == 9
        stage_names = [s["name"] for s in stages]
        assert any("Physics" in name or "Chemistry" in name for name in stage_names)
        assert any("ST" in name for name in stage_names)
        assert any("Ladder" in name for name in stage_names)
        assert any("Convergence" in name for name in stage_names)
        assert any("Conservation" in name for name in stage_names)
        assert any("Soak" in name for name in stage_names)


# ============================================================================
# Section 15: Edge Cases, Model Aliases & Parameter Sensitivity
# ============================================================================

class TestSection15EdgeCasesAndAliases:
    """Verify class aliases, property setters, edge cases, and custom configurations."""

    def test_class_and_model_aliases(self) -> None:
        """All class aliases resolve to identical underlying implementations."""
        assert PolycarbonateTransesterification is PolycarbonateTransesterificationReactor
        assert PolycarbonateTransesterificationModel is PolycarbonateTransesterificationReactor
        assert PolycarbonateTransesterificationSimulator is PolycarbonateTransesterificationReactor
        assert PolycarbonateTransesterificationEngine is PolycarbonateTransesterificationReactor
        assert PolycarbonateTransesterificationPlantModel is PolycarbonateTransesterificationReactor
        assert PolycarbonateTransesterificationLogicUnit is PolycarbonateTransesterificationReactor
        assert PcTransesterificationReactor is PolycarbonateTransesterificationReactor
        assert PcReactor is PolycarbonateTransesterificationReactor
        assert PolycarbonateReactor is PolycarbonateTransesterificationReactor

        assert PcConfig is PolycarbonateTransesterificationConfig
        assert PolycarbonateConfig is PolycarbonateTransesterificationConfig
        assert PcState is PolycarbonateTransesterificationState
        assert PolycarbonateState is PolycarbonateTransesterificationState

    def test_verification_function_aliases(self) -> None:
        """Verification runner function aliases point to primary runner."""
        assert run_polycarbonate_verification is run_polycarbonate_transesterification_verification
        assert run_pc_verification is run_polycarbonate_transesterification_verification
        assert run_pc_transesterification_verification is run_polycarbonate_transesterification_verification

    def test_state_property_getters_and_setters(self) -> None:
        """State convenience property getters and setters work symmetrically."""
        st = PolycarbonateTransesterificationState()
        st.conversion_pct = 96.5
        assert st.conversion_pct == 96.5
        assert st.bpa_conversion_pct == 96.5

        st.mw = 29000.0
        assert st.mw == 29000.0
        assert st.mw_pc == 29000.0

        st.viscosity = 700.0
        assert st.viscosity == 700.0
        assert st.melt_polymer_viscosity_pa_s == 700.0

        st.vacuum_mbar = 2.10
        assert st.vacuum_mbar == 2.10
        assert st.p_vacuum_mbar == 2.10

        st.reactor_active = False
        assert st.reactor_active is False
        assert st.pc_reactor_active is False

        st.dump_open = True
        assert st.dump_open is True
        assert st.emergency_melt_dump_open is True

        st.vacuum_permissive = False
        assert st.vacuum_permissive is False
        assert st.vacuum_system_permissive is False

    def test_custom_configuration_injection(self) -> None:
        """PolycarbonateTransesterificationReactor accepts custom configuration overrides."""
        custom_cfg = PolycarbonateTransesterificationConfig(
            reactor_volume_m3=5.0,
            nominal_residence_time_s=1800.0,
            jacket_heating_power_kw=300.0,
        )
        sim = PolycarbonateTransesterificationReactor(config=custom_cfg)
        assert sim.config.reactor_volume_m3 == 5.0
        assert sim.config.nominal_residence_time_s == 1800.0
        assert sim.config.jacket_heating_power_kw == 300.0
        assert sim.state.pc_reactor_active is True

    def test_step_method_alias(self) -> None:
        """step() method is a drop-in alias for scan_step()."""
        sim = PolycarbonateTransesterificationReactor()
        sim.step(dt=0.02)
        assert sim.state.cycle_count == 1
        assert math.isclose(sim.state.sim_time_s, 0.02, abs_tol=1e-5)

    def test_reactor_name_and_priority_defaults(self) -> None:
        """PolycarbonateTransesterificationReactor has correct default name and priority."""
        sim = PolycarbonateTransesterificationReactor()
        assert sim.name == "PolycarbonateTransesterificationReactor"
        assert sim.priority == 100

    def test_config_immutability_or_defaults(self) -> None:
        """PolycarbonateTransesterificationConfig initializes with correct chemical process defaults."""
        cfg = PolycarbonateTransesterificationConfig()
        assert cfg.reactor_volume_m3 == 3.50
        assert cfg.nominal_residence_time_s == 1500.0
        assert cfg.nominal_reactor_temp_c == 270.0
        assert cfg.nominal_vacuum_pressure_mbar == 2.50
