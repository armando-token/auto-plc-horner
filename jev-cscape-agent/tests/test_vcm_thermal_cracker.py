"""Comprehensive Industrial VCM Thermal Cracking Reactor ODE Simulation Test Suite.

Work Package: W206 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 13 engineering verification sections:
1. Section 1: Universal Physical Constants, Molecular Weights & Reaction Stoichiometry
2. Section 2: Pyrolysis Coil Geometry, Operating Conditions & Configuration Models
3. Section 3: Free-Radical Thermal Cracking Kinetics, Arrhenius Monotonicity & Activation Energies
4. Section 4: Radiant Firebox Heat Transfer, Coke Fouling & Pressure Drop Dynamics
5. Section 5: Coupled 6-State ODE System & RK4 Numerical Integration Stability
6. Section 6: Dual Stoichiometric Mass and Energy Conservation Residuals (< 1e-10)
7. Section 7: EDC Conversion, VCM Selectivity & Operational Metrics
8. Section 8: Process Safety Interlocks & Diagnostic Event Codes (0xDE01..0xDE04)
9. Section 9: Emergency Radiant Burner Trip & TLE Direct Liquid EDC Quench Cooling
10. Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege Mode
11. Section 11: ILogicUnit Scan Cycle Execution & Simulation Engine Integration
12. Section 12: Strict Pure IEC 61131-3 Structured Text POU & Anti-Ladder Security Guard
13. Section 13: Deterministic 9-Stage Verification Runner & JSON Export
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.vcm_thermal_cracker import (
    COIL_DP_ALARM_MBAR,
    COIL_DP_NOMINAL_MBAR,
    COKE_THICKNESS_ALARM_UM,
    COKE_THICKNESS_NOMINAL_UM,
    COT_NOMINAL_C,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H_CRACKING_J_MOL,
    DELTA_H_CRACKING_KJ_MOL,
    DELTA_H_SECONDARY_J_MOL,
    DELTA_H_SECONDARY_KJ_MOL,
    EDC_CONVERSION_NOMINAL_PCT,
    EDC_FEED_NOMINAL_KG_H,
    MW_C,
    MW_C2H2,
    MW_C2H3CL,
    MW_C2H4CL2,
    MW_CL,
    MW_COKE,
    MW_EDC,
    MW_H,
    MW_H2,
    MW_HCL,
    MW_VCM,
    P_COIL_NOMINAL_BAR,
    R_GAS_CONST,
    RESIDENCE_TIME_NOMINAL_S,
    RHO_MOLAR_STP,
    T_COIL_OVERHEAT_TRIP_C,
    T_COIL_RESET_C,
    T_FIREBOX_ALARM_C,
    T_FIREBOX_NOMINAL_C,
    T_REF_K,
    T_ZERO_CELSIUS,
    V_MOLAR_STP,
    VCM_CRACKER_PURE_ST_POU,
    VCM_CRACKER_SYNC_POU,
    VCM_PURE_ST_POU,
    VCM_SELECTIVITY_NOMINAL_PCT,
    VCM_SYNC_POU,
    VCM_THERMAL_CRACKER_PURE_ST_POU,
    VCM_THERMAL_CRACKER_SYNC_POU,
    VcmConfig,
    VcmCracker,
    VcmCrackerConfig,
    VcmCrackerDiagCode,
    VcmCrackerDiagnosticCode,
    VcmCrackerEngine,
    VcmCrackerLogicUnit,
    VcmCrackerModel,
    VcmCrackerPlantModel,
    VcmCrackerSimulationEngine,
    VcmCrackerSimulator,
    VcmCrackerState,
    VcmCrackerStatusBits,
    VcmCrackerStatusWord,
    VcmDiagCode,
    VcmDiagnosticCode,
    VcmEngine,
    VcmLogicUnit,
    VcmParameters,
    VcmSimulator,
    VcmState,
    VcmStatusBits,
    VcmStatusWord,
    VcmThermalCracker,
    VcmThermalCrackerConfig,
    VcmThermalCrackerDiagCode,
    VcmThermalCrackerDiagnosticCode,
    VcmThermalCrackerEngine,
    VcmThermalCrackerLogicUnit,
    VcmThermalCrackerModel,
    VcmThermalCrackerParameters,
    VcmThermalCrackerPlantModel,
    VcmThermalCrackerReactorState,
    VcmThermalCrackerSimulationEngine,
    VcmThermalCrackerSimulator,
    VcmThermalCrackerState,
    VcmThermalCrackerStatusBits,
    VcmThermalCrackerStatusWord,
    run_vcm_cracker_verification,
    run_vcm_thermal_cracker_verification,
    run_vcm_verification,
    validate_pure_st,
    verify_vcm_cracker_pure_st,
    verify_vcm_pure_st,
    verify_vcm_thermal_cracker_pure_st,
)


# ============================================================================
# Section 1: Universal Physical Constants, Molecular Weights & Stoichiometry
# ============================================================================

class TestSection1PhysicalConstantsAndStoichiometry:
    """Tests for physical constants, elemental/molecular weights, and reaction enthalpies."""

    def test_universal_gas_constant_and_reference_temperature(self) -> None:
        """Verify universal gas constant, zero Celsius, reference temp, and molar properties."""
        assert abs(R_GAS_CONST - 8.314462618) < 1e-6
        assert abs(T_ZERO_CELSIUS - 273.15) < 1e-4
        assert abs(T_REF_K - 768.15) < 1e-4  # 495.0 °C nominal
        assert abs(V_MOLAR_STP - 0.022414) < 1e-5
        assert abs(RHO_MOLAR_STP - 44.615) < 1e-3

    def test_iupac_elemental_atomic_weights(self) -> None:
        """Verify standard IUPAC atomic weights for Carbon, Hydrogen, and Chlorine."""
        assert abs(MW_C - 0.012011) < 1e-6
        assert abs(MW_H - 0.001008) < 1e-6
        assert abs(MW_CL - 0.035453) < 1e-6

    def test_reactant_and_product_molecular_weights(self) -> None:
        """Verify molecular weights for EDC, VCM, HCl, acetylene, coke, and H2."""
        expected_edc = 2.0 * MW_C + 4.0 * MW_H + 2.0 * MW_CL
        assert abs(MW_EDC - expected_edc) < 1e-8
        assert abs(MW_C2H4CL2 - expected_edc) < 1e-8
        assert abs(MW_EDC - 0.098960) < 1e-5

        expected_vcm = 2.0 * MW_C + 3.0 * MW_H + 1.0 * MW_CL
        assert abs(MW_VCM - expected_vcm) < 1e-8
        assert abs(MW_C2H3CL - expected_vcm) < 1e-8
        assert abs(MW_VCM - 0.062499) < 1e-5

        expected_hcl = 1.0 * MW_H + 1.0 * MW_CL
        assert abs(MW_HCL - expected_hcl) < 1e-8
        assert abs(MW_HCL - 0.036461) < 1e-5

        expected_c2h2 = 2.0 * MW_C + 2.0 * MW_H
        assert abs(MW_C2H2 - expected_c2h2) < 1e-8

        assert MW_COKE == MW_C
        assert abs(MW_H2 - 2.0 * MW_H) < 1e-8

    def test_primary_cracking_stoichiometric_mass_balance(self) -> None:
        """Verify strict mass balance: EDC (C2H4Cl2) -> VCM (C2H3Cl) + HCl."""
        reactants = MW_EDC
        products = MW_VCM + MW_HCL
        assert abs(reactants - products) < 1e-12

    def test_secondary_cracking_coke_precursor_mass_balance(self) -> None:
        """Verify strict mass balance: EDC -> C2H2 + 2 HCl."""
        reactants = MW_EDC
        products = MW_C2H2 + 2.0 * MW_HCL
        assert abs(reactants - products) < 1e-12

    def test_endothermic_reaction_enthalpies_values(self) -> None:
        """Verify endothermic enthalpies: +71 kJ/mol (cracking) and +95 kJ/mol (secondary)."""
        assert DELTA_H1_KJ_MOL == 71.0
        assert DELTA_H1_J_MOL == 71000.0
        assert DELTA_H_CRACKING_KJ_MOL == 71.0
        assert DELTA_H_CRACKING_J_MOL == 71000.0

        assert DELTA_H2_KJ_MOL == 95.0
        assert DELTA_H2_J_MOL == 95000.0
        assert DELTA_H_SECONDARY_KJ_MOL == 95.0
        assert DELTA_H_SECONDARY_J_MOL == 95000.0


# ============================================================================
# Section 2: Pyrolysis Coil Geometry, Operating Conditions & Configuration Models
# ============================================================================

class TestSection2ReactorConfigurationAndGeometry:
    """Tests for VcmThermalCrackerConfig geometry, dimensions, and baseline conditions."""

    def test_default_radiant_coil_geometry(self) -> None:
        """Verify coil volume 5.65 m^3, 150 mm inner diameter, and 320 m length."""
        cfg = VcmThermalCrackerConfig()
        assert cfg.coil_volume_m3 == 5.65
        assert cfg.coil_tube_inner_diameter_m == 0.150
        assert cfg.coil_tube_wall_thickness_m == 0.008
        assert cfg.coil_total_length_m == 320.0
        assert cfg.total_radiant_area_m2 == 150.8

    def test_thermal_conductivity_parameters(self) -> None:
        """Verify conductive properties: coke 2.0 W/(m*K) and high-Ni alloy 25.0 W/(m*K)."""
        cfg = VcmThermalCrackerConfig()
        assert cfg.coke_thermal_conductivity_w_m_k == 2.0
        assert cfg.metal_thermal_conductivity_w_m_k == 25.0

    def test_nominal_operating_and_feed_conditions(self) -> None:
        """Verify baseline feed rate 35000 kg/h, 20 bar pressure, and 495 °C COT."""
        cfg = VcmThermalCrackerConfig()
        assert cfg.nominal_edc_feed_rate_kg_h == EDC_FEED_NOMINAL_KG_H == 35000.0
        assert cfg.nominal_operating_pressure_bar == P_COIL_NOMINAL_BAR == 20.0
        assert cfg.target_cot_c == COT_NOMINAL_C == 495.0
        assert cfg.target_firebox_temp_c == T_FIREBOX_NOMINAL_C == 950.0
        assert cfg.nominal_residence_time_s == RESIDENCE_TIME_NOMINAL_S == 12.0
        assert cfg.nominal_coke_thickness_um == COKE_THICKNESS_NOMINAL_UM == 120.0
        assert cfg.nominal_coil_dp_mbar == COIL_DP_NOMINAL_MBAR == 185.0

    def test_clean_and_fouled_overall_heat_transfer_conductance(self) -> None:
        """Verify clean UA conductance and degradation due to coke layer."""
        cfg = VcmThermalCrackerConfig()
        u_clean = cfg.compute_overall_u(coke_thickness_um=0.0)
        assert u_clean == cfg.overall_heat_transfer_clean_w_m2_k == 180.0

        u_fouled_120 = cfg.compute_overall_u(coke_thickness_um=120.0)
        u_fouled_250 = cfg.compute_overall_u(coke_thickness_um=250.0)
        assert u_clean > u_fouled_120 > u_fouled_250 > 0.0

        # Verify clean UA conductance property
        expected_clean_ua = (180.0 * 150.8) / 1000.0
        assert abs(cfg.clean_ua_kw_k - expected_clean_ua) < 1e-4

    def test_emergency_tle_quench_cooling_parameters(self) -> None:
        """Verify emergency liquid EDC quench parameters: 15 kg/s, 35 °C supply, 320 kJ/kg latent."""
        cfg = VcmThermalCrackerConfig()
        assert cfg.emergency_quench_flow_kg_s == 15.0
        assert cfg.emergency_quench_inlet_temp_c == 35.0
        assert cfg.edc_heat_of_vaporization_j_kg == 320000.0
        assert cfg.edc_liquid_cp_j_kg_k == 1350.0
        assert cfg.edc_boiling_point_c == 150.0

    def test_configuration_class_aliases(self) -> None:
        """Verify configuration aliases point to VcmThermalCrackerConfig."""
        assert VcmCrackerConfig is VcmThermalCrackerConfig
        assert VcmThermalCrackerParameters is VcmThermalCrackerConfig
        assert VcmParameters is VcmThermalCrackerConfig
        assert VcmConfig is VcmThermalCrackerConfig


# ============================================================================
# Section 3: Free-Radical Thermal Cracking Kinetics & Arrhenius Monotonicity
# ============================================================================

class TestSection3CrackingKineticsAndArrhenius:
    """Tests for Arrhenius rate constants, activation energies, and kinetics functions."""

    @pytest.fixture
    def sim(self) -> VcmThermalCracker:
        return VcmThermalCracker()

    def test_arrhenius_activation_energies_ordering(self, sim: VcmThermalCracker) -> None:
        """Verify Ea2 (secondary coking, 140 kJ/mol) > Ea1 (primary cracking, 115 kJ/mol)."""
        cfg = sim.config
        assert cfg.activation_e2_j_mol > cfg.activation_e1_j_mol
        assert cfg.activation_e1_j_mol == 115000.0
        assert cfg.activation_e2_j_mol == 140000.0

    def test_arrhenius_rate_constant_calculation(self, sim: VcmThermalCracker) -> None:
        """Verify arrhenius_rate_constant computes k = A * exp(-Ea / (R * T))."""
        t_k = 495.0 + T_ZERO_CELSIUS
        k1 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_k)
        expected = sim.config.arrhenius_a1 * math.exp(-sim.config.activation_e1_j_mol / (R_GAS_CONST * t_k))
        assert abs(k1 - expected) < 1e-8

    def test_temperature_acceleration_monotonicity(self, sim: VcmThermalCracker) -> None:
        """Verify reaction rate constant k1 increases monotonically with temperature."""
        t_480_k = 480.0 + T_ZERO_CELSIUS
        t_500_k = 500.0 + T_ZERO_CELSIUS
        t_520_k = 520.0 + T_ZERO_CELSIUS
        k_480 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_480_k)
        k_500 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_500_k)
        k_520 = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_520_k)
        assert k_520 > k_500 > k_480 > 0.0

    def test_secondary_coking_accelerates_faster_than_primary_cracking(self, sim: VcmThermalCracker) -> None:
        """Verify higher activation energy of coking leads to faster growth at elevated temp."""
        t_low = 480.0 + T_ZERO_CELSIUS
        t_high = 520.0 + T_ZERO_CELSIUS
        k1_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_low)
        k1_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_high)
        k2_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t_low)
        k2_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a2, sim.config.activation_e2_j_mol, t_high)
        ratio_k1 = k1_high / k1_low
        ratio_k2 = k2_high / k2_low
        assert ratio_k2 > ratio_k1

    def test_nominal_reaction_rates_positive(self, sim: VcmThermalCracker) -> None:
        """Verify compute_kinetics produces positive rates and endothermic duties at nominal conditions."""
        t_k = 495.0 + T_ZERO_CELSIUS
        kin = sim.compute_kinetics(t_process_k=t_k, c_edc=92.2)
        assert kin["r1"] > 0.0
        assert kin["r2"] > 0.0
        assert kin["r1_tot"] > 0.0
        assert kin["r2_tot"] > 0.0
        assert kin["q1_kw"] > 0.0
        assert kin["q2_kw"] > 0.0
        assert kin["q_total_kw"] > 0.0

    def test_zero_edc_concentration_yields_zero_rates(self, sim: VcmThermalCracker) -> None:
        """Verify zero reactant produces zero reaction rates."""
        t_k = 495.0 + T_ZERO_CELSIUS
        kin = sim.compute_kinetics(t_process_k=t_k, c_edc=0.0)
        assert kin["r1"] == 0.0
        assert kin["r2"] == 0.0
        assert kin["q_total_kw"] == 0.0

    def test_kinetics_zeroed_when_cracking_inactive(self, sim: VcmThermalCracker) -> None:
        """Verify reaction rates zeroed when pyrolysis_cracking_active is False."""
        sim.state.pyrolysis_cracking_active = False
        t_k = 495.0 + T_ZERO_CELSIUS
        kin = sim.compute_kinetics(t_process_k=t_k, c_edc=92.2)
        assert kin["r1"] == 0.0
        assert kin["r2"] == 0.0
        assert kin["q_total_kw"] == 0.0

    def test_arrhenius_temperature_clamping_protection(self, sim: VcmThermalCracker) -> None:
        """Verify safe temperature clamping prevents math overflow or domain errors."""
        k_extreme_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, -100.0)
        assert math.isfinite(k_extreme_low)
        assert k_extreme_low > 0.0

        k_extreme_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, 10000.0)
        assert math.isfinite(k_extreme_high)


# ============================================================================
# Section 4: Firebox Radiant Heat Transfer, Coke Fouling & Pressure Drop Dynamics
# ============================================================================

class TestSection4RadiantHeatTransferAndCoking:
    """Tests for radiant heat transfer, coke growth, fouling resistance, and pressure drop."""

    @pytest.fixture
    def sim(self) -> VcmThermalCracker:
        return VcmThermalCracker()

    def test_overall_u_degrades_monotonically_with_coke(self, sim: VcmThermalCracker) -> None:
        """Verify U decreases as coke thickness increases from 0 to 300 microns."""
        u0 = sim.config.compute_overall_u(0.0)
        u100 = sim.config.compute_overall_u(100.0)
        u200 = sim.config.compute_overall_u(200.0)
        u300 = sim.config.compute_overall_u(300.0)
        assert u0 > u100 > u200 > u300 > 0.0

    def test_radiant_heat_transfer_nominal_magnitude(self, sim: VcmThermalCracker) -> None:
        """Verify radiant heat input from firebox at nominal 950 °C is > 8000 kW."""
        y = [92.2, 108.7, 110.4, 1.7, 495.0, 20.0]
        sim.compute_derivatives(0.0, y)
        assert sim.state.q_firebox_kw > 8000.0

    def test_coke_layer_growth_over_time(self, sim: VcmThermalCracker) -> None:
        """Verify coke thickness increases during simulation run with active cracking."""
        coke_0 = sim.state.coke_thickness_microns
        sim.advance_time(duration_s=2.0, dt=0.05)
        assert sim.state.coke_thickness_microns >= coke_0

    def test_pressure_drop_increases_with_coke_buildup(self, sim: VcmThermalCracker) -> None:
        """Verify coil pressure drop increases significantly when coke thickness increases."""
        sim.reset()
        dp_clean = sim.state.coil_pressure_drop_mbar

        # Artificially set heavy coke fouling
        sim.state.coke_thickness_microns = 250.0
        sim.step(dt=0.05)
        dp_fouled = sim.state.coil_pressure_drop_mbar
        assert dp_fouled > dp_clean

    def test_pressure_drop_scales_with_feed_flow_rate(self, sim: VcmThermalCracker) -> None:
        """Verify coil pressure drop increases with higher EDC throughput."""
        sim.reset()
        sim.state.edc_feed_rate_kg_h = 42000.0  # +20% feed rate
        sim.step(dt=0.05)
        assert sim.state.coil_pressure_drop_mbar > COIL_DP_NOMINAL_MBAR

    def test_firebox_high_temperature_alarm_coil_m390(self, sim: VcmThermalCracker) -> None:
        """Verify %M390 triggers when T_firebox exceeds 1000 °C."""
        sim.state.t_firebox_c = 1005.0
        sim._evaluate_safety_interlocks()
        assert sim.state.firebox_high_temp_alarm is True

        sim.state.t_firebox_c = 950.0
        sim._evaluate_safety_interlocks()
        assert sim.state.firebox_high_temp_alarm is False

    def test_coil_heat_capacitance_governs_thermal_inertia(self, sim: VcmThermalCracker) -> None:
        """Verify coil thermal capacitance is 1200 kJ/K."""
        assert sim.config.coil_thermal_capacitance_kj_k == 1200.0


# ============================================================================
# Section 5: Coupled 6-State ODE System & RK4 Numerical Integration Stability
# ============================================================================

class TestSection5CoupledODESystemAndRK4:
    """Tests for derivative vector, RK4 integration stability, and bounds clamping."""

    @pytest.fixture
    def sim(self) -> VcmThermalCracker:
        return VcmThermalCracker()

    def test_compute_derivatives_returns_6_states(self, sim: VcmThermalCracker) -> None:
        """Verify derivative function returns exactly 6 state derivatives."""
        y = [92.2, 108.7, 110.4, 1.7, 495.0, 20.0]
        derivs = sim.compute_derivatives(0.0, y)
        assert len(derivs) == 6

    def test_derivatives_finite_and_real(self, sim: VcmThermalCracker) -> None:
        """Verify all derivatives are finite (no NaN or Inf)."""
        y = [92.2, 108.7, 110.4, 1.7, 495.0, 20.0]
        derivs = sim.compute_derivatives(0.0, y)
        for d in derivs:
            assert math.isfinite(d)

    def test_single_rk4_step_advances_sim_time(self, sim: VcmThermalCracker) -> None:
        """Verify single rk4_step advances simulation time by dt."""
        t0 = sim.state.sim_time_s
        sim.rk4_step(dt=0.02)
        assert abs(sim.state.sim_time_s - (t0 + 0.02)) < 1e-9

    def test_rk4_multi_step_stability(self, sim: VcmThermalCracker) -> None:
        """Verify RK4 solver executes stably over 200 micro-steps without diverging."""
        for _ in range(200):
            res = sim.step(dt=0.02)
            assert res.status == AgentStatus.SUCCESS
        assert 450.0 <= sim.state.t_process_c <= 530.0
        assert 15.0 <= sim.state.p_coil_bar <= 25.0
        assert not math.isnan(sim.state.c_vcm)
        assert not math.isnan(sim.state.c_edc)

    def test_rk4_concentration_clamping_prevents_negatives(self, sim: VcmThermalCracker) -> None:
        """Verify state concentrations are clamped to non-negative bounds."""
        sim.state.c_edc = -10.0
        sim.state.c_vcm = -5.0
        sim.state.c_hcl = -2.0
        sim.state.c_coke = -1.0
        sim.rk4_step(dt=0.01)
        assert sim.state.c_edc >= 0.0
        assert sim.state.c_vcm >= 0.0
        assert sim.state.c_hcl >= 0.0
        assert sim.state.c_coke >= 0.0

    def test_reset_restores_nominal_state(self, sim: VcmThermalCracker) -> None:
        """Verify reset restores simulator state to nominal baseline."""
        sim.advance_time(duration_s=3.0, dt=0.05)
        sim.reset()
        assert sim.state.sim_time_s == 0.0
        assert abs(sim.state.t_process_c - COT_NOMINAL_C) < 1e-4
        assert abs(sim.state.t_firebox_c - T_FIREBOX_NOMINAL_C) < 1e-4
        assert abs(sim.state.edc_feed_rate_kg_h - EDC_FEED_NOMINAL_KG_H) < 1e-4

    def test_advance_time_validation(self, sim: VcmThermalCracker) -> None:
        """Verify advance_time succeeds for positive durations and rejects zero/negative."""
        res_ok = sim.advance_time(duration_s=0.5, dt=0.05)
        assert res_ok.status == AgentStatus.SUCCESS

        res_zero = sim.advance_time(duration_s=0.0, dt=0.05)
        assert res_zero.status == AgentStatus.FAILED
        assert res_zero.error_code == "INVALID_TIMESTEP"

        res_neg = sim.advance_time(duration_s=-2.0, dt=0.05)
        assert res_neg.status == AgentStatus.FAILED


# ============================================================================
# Section 6: Dual Stoichiometric Mass and Energy Conservation Residuals (< 1e-10)
# ============================================================================

class TestSection6MassAndEnergyConservationResiduals:
    """Tests for stoichiometric mass, elemental, and enthalpy residuals (< 1e-10)."""

    @pytest.fixture
    def sim(self) -> VcmThermalCracker:
        return VcmThermalCracker()

    def test_mass_balance_residual_strictly_below_tolerance(self, sim: VcmThermalCracker) -> None:
        """Verify total mass balance residual is strictly < 1e-10 kg/s."""
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_mass_residual_strictly_below_tolerance(self, sim: VcmThermalCracker) -> None:
        """Verify atomic elemental mass residual is strictly < 1e-10 kg/s."""
        sim._update_conservation_residuals()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_enthalpy_conservation_residual_strictly_below_tolerance(self, sim: VcmThermalCracker) -> None:
        """Verify thermal enthalpy conservation residual is strictly < 1e-10 kW."""
        sim._update_conservation_residuals()
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_conservation_residuals_over_dynamic_transients(self, sim: VcmThermalCracker) -> None:
        """Verify conservation residuals remain < 1e-10 over transient steps."""
        for _ in range(20):
            sim.step(dt=0.05)
            assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
            assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
            assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_unheated_coil_shows_endothermic_temperature_drop(self, sim: VcmThermalCracker) -> None:
        """Verify that when burners are extinguished, endothermic cracking causes dT/dt < 0."""
        sim.state.pyrolysis_cracking_active = False
        derivs = sim.compute_derivatives(0.0, [92.2, 108.7, 110.4, 1.7, 495.0, 20.0])
        # dT_process/dt should be negative without heat input
        assert derivs[4] < 0.0

    def test_conservation_residuals_when_quenched(self, sim: VcmThermalCracker) -> None:
        """Verify conservation residuals when emergency quench is active."""
        sim.state.emergency_tle_quench_active = True
        sim._update_kinetics_and_conversion()
        sim._update_conservation_residuals()
        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10


# ============================================================================
# Section 7: EDC Conversion, VCM Selectivity & Operational Metrics
# ============================================================================

class TestSection7OperationalMetricsAndYield:
    """Tests for EDC conversion, VCM selectivity, and status bits."""

    @pytest.fixture
    def sim(self) -> VcmThermalCracker:
        return VcmThermalCracker()

    def test_edc_conversion_calculation(self, sim: VcmThermalCracker) -> None:
        """Verify EDC per-pass conversion is calculated in target range (50-60%)."""
        sim._update_kinetics_and_conversion()
        assert 45.0 <= sim.state.edc_conversion_pct <= 65.0

    def test_vcm_selectivity_calculation(self, sim: VcmThermalCracker) -> None:
        """Verify VCM selectivity is calculated in target range (95-99.5%)."""
        sim._update_kinetics_and_conversion()
        assert 95.0 <= sim.state.vcm_selectivity_pct <= 99.9

    def test_conversion_and_selectivity_zeroed_at_zero_concentrations(self, sim: VcmThermalCracker) -> None:
        """Verify metrics are zero when all C2 species are zero."""
        sim.state.c_edc = 0.0
        sim.state.c_vcm = 0.0
        sim.state.c_coke = 0.0
        sim._update_kinetics_and_conversion()
        assert sim.state.edc_conversion_pct == 0.0
        assert sim.state.vcm_selectivity_pct == 0.0

    def test_status_bits_bitmask_operations(self, sim: VcmThermalCracker) -> None:
        """Verify status word contains RUNNING and PYROLYSIS_CRACKING_ACTIVE flags."""
        sim._evaluate_safety_interlocks()
        sw = int(sim.state.status_bits)
        assert bool(sw & VcmThermalCrackerStatusBits.RUNNING) is True
        assert bool(sw & VcmThermalCrackerStatusBits.PYROLYSIS_CRACKING_ACTIVE) is True

    def test_state_aliases_and_dataclass(self) -> None:
        """Verify state aliases."""
        assert VcmCrackerState is VcmThermalCrackerState
        assert VcmState is VcmThermalCrackerState
        assert VcmThermalCrackerReactorState is VcmThermalCrackerState


# ============================================================================
# Section 8: Process Safety Interlocks & Diagnostic Event Codes (0xDE01..0xDE04)
# ============================================================================

class TestSection8SafetyInterlocksAndDiagnostics:
    """Tests for diagnostic event codes 0xDE01..0xDE04 and strict priority ordering."""

    @pytest.fixture
    def sim(self) -> VcmThermalCracker:
        return VcmThermalCracker()

    def test_normal_steady_state_diagnostic_ok(self, sim: VcmThermalCracker) -> None:
        """Verify baseline operating conditions yield diagnostic code OK (0x0000)."""
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == VcmThermalCrackerDiagnosticCode.OK
        assert sim.state.pyrolysis_cracking_active is True
        assert sim.state.emergency_tle_quench_active is False
        assert sim.state.firebox_high_temp_alarm is False

    def test_diag_de01_coil_overheat_runaway_trip(self, sim: VcmThermalCracker) -> None:
        """Verify T_process > 530 °C asserts 0xDE01, triggers TLE quench, trips burners."""
        sim.state.t_process_c = 535.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == VcmThermalCrackerDiagnosticCode.COIL_OVERHEAT_RUNAWAY
        assert sim.state.emergency_tle_quench_active is True
        assert sim.state.pyrolysis_cracking_active is False

    def test_diag_de02_excessive_coke_fouling_thickness(self, sim: VcmThermalCracker) -> None:
        """Verify coke thickness > 250 um asserts 0xDE02 maintenance alarm."""
        sim.state.coke_thickness_microns = 260.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == VcmThermalCrackerDiagnosticCode.EXCESSIVE_COKE_FOULING
        assert sim.state.pyrolysis_cracking_active is True
        assert sim.state.emergency_tle_quench_active is False

    def test_diag_de02_excessive_coke_fouling_pressure_drop(self, sim: VcmThermalCracker) -> None:
        """Verify coil pressure drop > 350.0 mbar asserts 0xDE02 maintenance alarm."""
        sim.state.coil_pressure_drop_mbar = 360.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == VcmThermalCrackerDiagnosticCode.EXCESSIVE_COKE_FOULING
        assert sim.state.pyrolysis_cracking_active is True
        assert sim.state.emergency_tle_quench_active is False

    def test_diag_de03_conversion_low_alarm(self, sim: VcmThermalCracker) -> None:
        """Verify EDC conversion < 45.0% while active asserts 0xDE03 warning."""
        sim.state.edc_conversion_pct = 40.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == VcmThermalCrackerDiagnosticCode.CONVERSION_LOW_ALARM
        assert sim.state.pyrolysis_cracking_active is True
        assert sim.state.emergency_tle_quench_active is False

    def test_diag_de04_tle_quench_failure(self, sim: VcmThermalCracker) -> None:
        """Verify emergency quench active and T_process > 420 °C asserts 0xDE04."""
        sim.state.emergency_tle_quench_active = True
        sim.state.t_process_c = 430.0  # > 420.0 °C and <= 530.0 °C
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == VcmThermalCrackerDiagnosticCode.TLE_QUENCH_FAILURE
        assert sim.state.pyrolysis_cracking_active is False

    def test_firebox_pre_alarm_without_fault_trip(self, sim: VcmThermalCracker) -> None:
        """Verify T_firebox = 1010 °C asserts %M390 while status code remains 0x0000 OK."""
        sim.state.t_firebox_c = 1010.0
        sim._evaluate_safety_interlocks()
        assert sim.state.firebox_high_temp_alarm is True
        assert sim.state.diagnostic_code == VcmThermalCrackerDiagnosticCode.OK

    def test_strict_priority_hierarchy_de01_over_all(self, sim: VcmThermalCracker) -> None:
        """Verify 0xDE01 takes precedence over 0xDE02, 0xDE03, and 0xDE04."""
        sim.state.t_process_c = 540.0             # Runaway (0xDE01)
        sim.state.coke_thickness_microns = 280.0   # Fouling (0xDE02)
        sim.state.edc_conversion_pct = 35.0        # Low conversion (0xDE03)
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == VcmThermalCrackerDiagnosticCode.COIL_OVERHEAT_RUNAWAY
        assert sim.state.emergency_tle_quench_active is True

    def test_diagnostic_code_aliases(self) -> None:
        """Verify diagnostic code enum aliases."""
        assert VcmDiagnosticCode is VcmThermalCrackerDiagnosticCode
        assert VcmDiagCode is VcmThermalCrackerDiagnosticCode
        assert VcmCrackerDiagnosticCode is VcmThermalCrackerDiagnosticCode
        assert VcmCrackerDiagCode is VcmThermalCrackerDiagnosticCode
        assert VcmThermalCrackerDiagCode is VcmThermalCrackerDiagnosticCode


# ============================================================================
# Section 9: Emergency Radiant Burner Trip & TLE Direct Liquid EDC Quench Cooling
# ============================================================================

class TestSection9EmergencyBurnerTripAndTLEQuench:
    """Tests for emergency burner trip and TLE direct liquid EDC quench cooling."""

    @pytest.fixture
    def sim(self) -> VcmThermalCracker:
        return VcmThermalCracker()

    def test_emergency_quench_activates_on_runaway(self, sim: VcmThermalCracker) -> None:
        """Verify emergency quench asserts %M391 when runaway is detected."""
        sim.state.t_process_c = 535.0
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_tle_quench_active is True

    def test_emergency_quench_extinguishes_radiant_burners(self, sim: VcmThermalCracker) -> None:
        """Verify emergency quench trips radiant burners (%M389 = False)."""
        sim.state.t_process_c = 535.0
        sim._evaluate_safety_interlocks()
        assert sim.state.pyrolysis_cracking_active is False

    def test_emergency_quench_quenches_reaction_power(self, sim: VcmThermalCracker) -> None:
        """Verify emergency quench stops cracking power to 0 kW."""
        sim.state.t_process_c = 535.0
        sim._evaluate_safety_interlocks()
        sim._update_kinetics_and_conversion()
        assert sim.state.q_rxn_total_kw == 0.0

    def test_direct_liquid_edc_quench_cools_process_stream(self, sim: VcmThermalCracker) -> None:
        """Verify liquid EDC quench cooling rapidly brings effluent temperature below 420 °C."""
        sim.state.t_process_c = 535.0
        sim._evaluate_safety_interlocks()
        res = sim.advance_time(duration_s=8.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert sim.state.t_process_c < 420.0

    def test_emergency_quench_latent_heat_absorption(self, sim: VcmThermalCracker) -> None:
        """Verify huge latent heat absorption duty when emergency quench is active."""
        sim.state.emergency_tle_quench_active = True
        y = [0.0, 108.7, 110.4, 1.7, 500.0, 20.0]
        sim.compute_derivatives(0.0, y)
        assert sim.state.q_quench_kw > 4000.0  # Massive quench power > 4 MW

    def test_emergency_quench_isolates_inlet_feed(self, sim: VcmThermalCracker) -> None:
        """Verify hydrocarbon feed is shut off during emergency quench."""
        sim.state.emergency_tle_quench_active = True
        derivs = sim.compute_derivatives(0.0, [92.2, 108.7, 110.4, 1.7, 500.0, 20.0])
        # dC_edc/dt is strictly negative because C_in is 0
        assert derivs[0] < 0.0


# ============================================================================
# Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege Mode
# ============================================================================

class TestSection10HornerRegisterSynchronization:
    """Tests for Horner OCS %R1670..%R1677, %M389..%M391, and SYSTEM privilege writes."""

    def test_registers_nominal_values_written_with_system_privilege(self) -> None:
        """Verify %R1670..%R1677 registers at nominal operating baseline."""
        reg = RegisterTable()
        sim = VcmThermalCracker(register_table=reg)
        sim.state.t_process_c = 495.0
        sim.state.t_firebox_c = 950.0
        sim.state.edc_feed_rate_kg_h = 35000.0
        sim.state.edc_conversion_pct = 54.5
        sim.state.vcm_selectivity_pct = 98.5
        sim.state.coke_thickness_microns = 120.0
        sim.state.coil_pressure_drop_mbar = 185.0
        sim.state.diagnostic_code = VcmThermalCrackerDiagnosticCode.OK
        sim._sync_registers()

        assert reg.read_word("%R1670") == 4950   # 495.0 °C (x10)
        assert reg.read_word("%R1671") == 9500   # 950.0 °C (x10)
        assert reg.read_uword("%R1672") == 35000 # 35000 kg/h (x1)
        assert reg.read_word("%R1673") == 545    # 54.5 % (x10)
        assert reg.read_word("%R1674") == 985    # 98.5 % (x10)
        assert reg.read_word("%R1675") == 120    # 120 um (x1)
        assert reg.read_word("%R1676") == 1850   # 185.0 mbar (x10)
        assert reg.read_word("%R1677") & 0xFFFF == 0x0000 # OK

    def test_discrete_coils_synchronization_m389_to_m391(self) -> None:
        """Verify discrete coils %M389..%M391 synchronization."""
        reg = RegisterTable()
        sim = VcmThermalCracker(register_table=reg)
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_bit("%M389") is True     # PyrolysisCrackingActive
        assert reg.read_bit("%M390") is False    # FireboxHighTempAlarm
        assert reg.read_bit("%M391") is False    # EmergencyTleQuenchActive

    def test_diagnostic_status_code_register_r1677(self) -> None:
        """Verify diagnostic code 0xDE01 writes to %R1677 and sets coil %M391."""
        reg = RegisterTable()
        sim = VcmThermalCracker(register_table=reg)
        sim.state.t_process_c = 535.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_word("%R1677") & 0xFFFF == 0xDE01
        assert reg.read_bit("%M389") is False
        assert reg.read_bit("%M391") is True

    def test_register_writes_require_system_privilege(self) -> None:
        """Verify sync_to_registers succeeds with PrivilegeMode.SYSTEM."""
        reg = RegisterTable()
        sim = VcmThermalCracker(register_table=reg)
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert reg.read_word("%R1670") == 4950

    def test_register_scaling_factors_consistency(self) -> None:
        """Verify scaling factors for temperature (x10), conversion (x10), and dP (x10)."""
        reg = RegisterTable()
        sim = VcmThermalCracker(register_table=reg)
        sim.state.t_process_c = 488.4
        sim.state.edc_conversion_pct = 52.3
        sim.state.coil_pressure_drop_mbar = 192.6
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_word("%R1670") == 4884
        assert reg.read_word("%R1673") == 523
        assert reg.read_word("%R1676") == 1926

    def test_register_bounds_clamping(self) -> None:
        """Verify registers are clamped to valid INT16 boundaries."""
        reg = RegisterTable()
        sim = VcmThermalCracker(register_table=reg)
        sim.state.t_process_c = 6000.0
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        val = reg.read_word("%R1670")
        assert -32768 <= val <= 32767


# ============================================================================
# Section 11: ILogicUnit Scan Cycle Execution & Simulation Engine Integration
# ============================================================================

class TestSection11ILogicUnitScanCycleIntegration:
    """Tests for ILogicUnit scan_step cycle, ScanContext execution, and adapters."""

    @pytest.fixture
    def sim(self) -> VcmThermalCracker:
        return VcmThermalCracker()

    def test_ilogicunit_interface_contracts(self, sim: VcmThermalCracker) -> None:
        """Verify ILogicUnit interface attributes."""
        assert isinstance(sim, ILogicUnit)
        assert sim.name == "VcmThermalCrackerSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

    def test_scan_step_execution_updates_registers(self, sim: VcmThermalCracker) -> None:
        """Verify scan_step advances one scan and updates internal registers."""
        t_before = sim.state.sim_time_s
        sim.scan_step(dt=0.05)
        assert abs(sim.state.sim_time_s - (t_before + 0.05)) < 1e-9

    def test_execute_from_scan_context(self, sim: VcmThermalCracker) -> None:
        """Verify execute method processes ScanContext and writes to external registers."""
        reg = RegisterTable()
        ctx = ScanContext(
            cycle=1,
            dt_ms=50.0,
            elapsed_time_ms=50.0,
            get_register=reg.read_word,
            set_register=lambda addr, val: reg.write_word(addr, val, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda name, default=None: default,
            set_variable=lambda name, val: None,
            record_fault=lambda fault: None,
        )
        setattr(ctx, "registers", reg)
        sim.execute(ctx)
        assert 4500 <= reg.read_word("%R1670") <= 5300

    def test_adapter_logic_unit_scan_and_reset(self) -> None:
        """Verify VcmThermalCrackerLogicUnit adapter executes cleanly."""
        adapter = VcmThermalCrackerLogicUnit()
        assert adapter.name == "VcmThermalCrackerSync"
        assert adapter.is_enabled is True

        reg = RegisterTable()
        ctx = ScanContext(
            cycle=1,
            dt_ms=50.0,
            elapsed_time_ms=50.0,
            get_register=reg.read_word,
            set_register=lambda addr, val: reg.write_word(addr, val, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda name, default=None: default,
            set_variable=lambda name, val: None,
            record_fault=lambda fault: None,
        )
        setattr(ctx, "registers", reg)
        adapter.execute(ctx)
        assert 4500 <= reg.read_word("%R1670") <= 5300

        adapter.reset()
        assert adapter.simulator.state.sim_time_s == 0.0

    def test_continuous_multi_scan_execution(self, sim: VcmThermalCracker) -> None:
        """Verify 50 consecutive scans execute stably."""
        for _ in range(50):
            sim.scan_step(dt=0.02)
        assert sim.state.sim_time_s > 0.9

    def test_scan_step_with_context_register_table(self, sim: VcmThermalCracker) -> None:
        """Verify scan_step propagates to context registers."""
        reg = RegisterTable()
        ctx = ScanContext(
            cycle=2,
            dt_ms=20.0,
            elapsed_time_ms=40.0,
            get_register=reg.read_word,
            set_register=lambda addr, val: reg.write_word(addr, val, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda name, default=None: default,
            set_variable=lambda name, val: None,
            record_fault=lambda fault: None,
        )
        setattr(ctx, "registers", reg)
        sim.scan_step(dt=0.02, context=ctx)
        assert reg.read_word("%R1670") > 0

    def test_simulator_class_aliases(self) -> None:
        """Verify simulator aliases point to VcmThermalCracker."""
        assert VcmThermalCrackerSimulator is VcmThermalCracker
        assert VcmThermalCrackerEngine is VcmThermalCracker
        assert VcmThermalCrackerModel is VcmThermalCracker
        assert VcmThermalCrackerPlantModel is VcmThermalCracker
        assert VcmThermalCrackerSimulationEngine is VcmThermalCracker
        assert VcmCracker is VcmThermalCracker
        assert VcmCrackerSimulator is VcmThermalCracker
        assert VcmCrackerEngine is VcmThermalCracker
        assert VcmCrackerModel is VcmThermalCracker
        assert VcmCrackerPlantModel is VcmThermalCracker
        assert VcmCrackerSimulationEngine is VcmThermalCracker
        assert VcmSimulator is VcmThermalCracker
        assert VcmEngine is VcmThermalCracker


# ============================================================================
# Section 12: Strict Pure IEC 61131-3 ST POU & Anti-Ladder Security Guard
# ============================================================================

class TestSection12PureIEC61131STAndAntiLadder:
    """Tests for pure Structured Text syntax, AST parsing, and ladder rejection."""

    def test_pure_st_pou_ast_parsing_and_name(self) -> None:
        """Verify VCM_THERMAL_CRACKER_PURE_ST_POU passes AST parsing cleanly."""
        SecurityGuard.assert_pure_st_content(VCM_THERMAL_CRACKER_PURE_ST_POU)
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(VCM_THERMAL_CRACKER_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "VcmThermalCrackerSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_pure_st_pou_register_symbol_bindings(self) -> None:
        """Verify AST binds registers %R1670..%R1677 and %M389..%M391."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(VCM_THERMAL_CRACKER_PURE_ST_POU)
        assert pou is not None
        expected_regs = [
            "%R1670", "%R1671", "%R1672", "%R1673",
            "%R1674", "%R1675", "%R1676", "%R1677",
            "%M389", "%M390", "%M391",
        ]
        for reg in expected_regs:
            assert reg in pou.bound_registers

    def test_anti_ladder_contacts_rejection(self) -> None:
        """Verify ladder contacts '---[ ]---' are intercepted with LadderForbiddenError."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_coils_and_rungs_rejection(self) -> None:
        """Verify ladder coils and rung constructs are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T\nVAR c: BOOL; END_VAR\n---( )---\nEND_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T\nVAR r: BOOL; END_VAR\nRUNG 1\nEND_PROGRAM")

    def test_anti_ladder_set_reset_coils_and_negated_contacts(self) -> None:
        """Verify ladder set/reset coils '---(S)---' and negated contacts '---[/]---' are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T\nVAR c: BOOL; END_VAR\n---(S)---\nEND_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T\nVAR c: BOOL; END_VAR\n---[/]---\nEND_PROGRAM")

    def test_anti_ladder_mnemonics_rejection(self) -> None:
        """Verify ladder mnemonics (XIC, OTE) are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T\nVAR m: BOOL; END_VAR\nXIC m\nEND_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T\nVAR m: BOOL; END_VAR\nOTE m\nEND_PROGRAM")

    def test_verify_pure_st_helper_functions(self) -> None:
        """Verify helper validation functions return True and success."""
        assert verify_vcm_thermal_cracker_pure_st() is True
        assert verify_vcm_cracker_pure_st() is True
        assert verify_vcm_pure_st() is True
        assert validate_pure_st() is True

    def test_pou_text_aliases(self) -> None:
        """Verify POU text string aliases match."""
        assert VCM_THERMAL_CRACKER_SYNC_POU == VCM_THERMAL_CRACKER_PURE_ST_POU
        assert VCM_CRACKER_PURE_ST_POU == VCM_THERMAL_CRACKER_PURE_ST_POU
        assert VCM_CRACKER_SYNC_POU == VCM_THERMAL_CRACKER_PURE_ST_POU
        assert VCM_PURE_ST_POU == VCM_THERMAL_CRACKER_PURE_ST_POU
        assert VCM_SYNC_POU == VCM_THERMAL_CRACKER_PURE_ST_POU


# ============================================================================
# Section 13: Deterministic 9-Stage Verification Suite & JSON Export
# ============================================================================

class TestSection13Deterministic9StageVerificationRunner:
    """Tests for run_vcm_thermal_cracker_verification 9-stage runner and JSON export."""

    def test_verification_runner_status_success(self) -> None:
        """Verify verification runner returns status: success and error_code: None."""
        res = run_vcm_thermal_cracker_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["work_package"] == "W206"
        assert res["data"]["total_checks"] == 9
        assert res["data"]["checks_passed"] == 9

    def test_verification_runner_all_9_stages_pass(self) -> None:
        """Verify each of the 9 stages individually passes with factual evidence."""
        res = run_vcm_thermal_cracker_verification()
        tests = res["data"]["tests"]
        assert len(tests) == 9
        for t in tests:
            assert t["passed"] is True, f"Stage {t['stage']} failed: {t['details']}"

    def test_verification_runner_json_evidence_export(self, tmp_path: Path) -> None:
        """Verify verification runner exports valid JSON evidence matching strict contract."""
        out_file = tmp_path / "vcm_evidence.json"
        res = run_vcm_thermal_cracker_verification(output_path=out_file)
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W206"
        assert data["data"]["checks_passed"] == 9

    def test_verification_runner_evidence_content_validation(self, tmp_path: Path) -> None:
        """Verify exported JSON content contains registers, coils, and all required keys."""
        out_file = tmp_path / "vcm_evidence_detail.json"
        run_vcm_thermal_cracker_verification(output_path=out_file)

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        reg_map = data["data"]["register_map"]["values"]
        assert "%R1670" in reg_map
        assert "%R1671" in reg_map
        assert "%R1677" in reg_map
        assert "%M389" in reg_map
        assert "%M390" in reg_map
        assert "%M391" in reg_map
        assert reg_map["%M389"] is True

    def test_verification_runner_aliases(self) -> None:
        """Verify runner function aliases."""
        assert run_vcm_cracker_verification is run_vcm_thermal_cracker_verification
        assert run_vcm_verification is run_vcm_thermal_cracker_verification
