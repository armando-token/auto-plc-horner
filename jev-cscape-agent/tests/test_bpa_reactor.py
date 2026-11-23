"""Comprehensive Industrial Bisphenol A (BPA) Packed-Bed Cation-Exchange Reactor Test Suite.

Work Package: W209 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 13 engineering verification sections:
1. Section 1: Universal Physical Constants, Molecular Weights & Thermodynamic Enthalpies
2. Section 2: Packed-Bed Reactor Configuration, Geometry & Baseline Operating Parameters
3. Section 3: Sulfonated Resin Condensation, Side Isomerization & 3-MPA Promoter Kinetics
4. Section 4: Langmuir-Hinshelwood / Hougen-Watson (LHHW) Water Inhibition Kinetics
5. Section 5: Emergency Cold Phenol Recirculating Quench Cooling Dynamics
6. Section 6: Coupled 6-State ODE Vector & High-Order RK4 Numerical Integration
7. Section 7: Stoichiometric Mass, Elemental Species & Enthalpy Conservation Residuals (< 1e-10)
8. Section 8: Packed-Bed Fluid Dynamics & Ergun Equation Resin Fouling Pressure Drop
9. Section 9: Process Safety Interlocks & Diagnostics in Strict Priority Hierarchy (0xE101..0xE104)
10. Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege Mode (%R1700..%R1707, %M396..%M398)
11. Section 11: Strict Pure IEC 61131-3 Structured Text POU & Anti-Ladder Security Guard
12. Section 12: ILogicUnit Scan Cycle Execution & Simulation Engine Integration
13. Section 13: Deterministic 9-Stage Verification Suite & Runner Integration
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
from jev_cscape.simulation.bpa_reactor import (
    ACETONE_CONV_NOMINAL_PCT,
    ACETONE_FEED_RATE_NOMINAL_KG_H,
    BED_INLET_TEMP_NOMINAL_C,
    BED_OUTLET_TEMP_NOMINAL_C,
    BPA_PURE_ST_POU,
    BPA_REACTOR_PURE_ST_POU,
    BPA_REACTOR_SYNC_POU,
    BPA_SELECTIVITY_NOMINAL_PCT,
    BPA_SYNC_POU,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    EXOTHERM_DELTA_T_ALARM_C,
    G_ACCEL,
    HIGH_DP_TRIP_MBAR,
    LOW_ACTIVITY_TRIP_PCT,
    LOW_CONVERSION_TRIP_PCT,
    MW_ACETONE,
    MW_BPA,
    MW_BYPRODUCTS,
    MW_C,
    MW_H,
    MW_O,
    MW_OP_BPA,
    MW_PHENOL,
    MW_WATER,
    PHENOL_ACETONE_RATIO_NOMINAL,
    QUENCH_SHUTOFF_TEMP_C,
    REACTOR_PRESSURE_NOMINAL_BAR,
    RESIN_ACTIVITY_NOMINAL_PCT,
    RESIN_BED_DP_NOMINAL_MBAR,
    RUNAWAY_TRIP_DELTA_T_C,
    RUNAWAY_TRIP_TEMP_C,
    R_GAS_CONST,
    T_REF_K,
    T_ZERO_CELSIUS,
    WATER_DEACTIVATION_CONC_MOL_M3,
    BpaConfig,
    BpaDiagCode,
    BpaDiagnosticCode,
    BpaLogicUnit,
    BpaParameters,
    BpaReactor,
    BpaReactorConfig,
    BpaReactorDiagCode,
    BpaReactorDiagnosticCode,
    BpaReactorEngine,
    BpaReactorLogicUnit,
    BpaReactorModel,
    BpaReactorParameters,
    BpaReactorPlantModel,
    BpaReactorSimulationEngine,
    BpaReactorSimulator,
    BpaReactorState,
    BpaReactorStatusBits,
    BpaReactorStatusWord,
    BpaSimulator,
    BpaState,
    BpaStatusBits,
    BpaStatusWord,
    run_bpa_reactor_verification,
    run_bpa_verification,
    validate_pure_st,
    verify_bpa_pure_st,
    verify_bpa_reactor_pure_st,
)
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# Section 1: Universal Physical Constants, Molecular Weights & Enthalpies
# ============================================================================

class TestSection1ConstantsAndThermodynamics:
    """Tests for physical constants, atomic/molecular weights, and reaction enthalpies."""

    def test_universal_physical_constants(self) -> None:
        """Verify universal gas constant, standard gravity, and temperature conversions."""
        assert abs(R_GAS_CONST - 8.314462618) < 1e-6
        assert abs(G_ACCEL - 9.80665) < 1e-4
        assert abs(T_ZERO_CELSIUS - 273.15) < 1e-4
        assert abs(T_REF_K - 348.15) < 1e-4

    def test_elemental_atomic_weights(self) -> None:
        """Verify standard IUPAC atomic weights for Carbon, Hydrogen, and Oxygen."""
        assert abs(MW_C - 0.012011) < 1e-6
        assert abs(MW_H - 0.001008) < 1e-6
        assert abs(MW_O - 0.015999) < 1e-6

    def test_species_molecular_weights(self) -> None:
        """Verify stoichiometry and molecular weights for Phenol, Acetone, BPA, and Water."""
        assert abs(MW_PHENOL - 0.094113) < 1e-5
        assert abs(MW_ACETONE - 0.058080) < 1e-5
        assert abs(MW_BPA - 0.228291) < 1e-5
        assert abs(MW_WATER - 0.018015) < 1e-5
        assert abs(MW_OP_BPA - MW_BPA) < 1e-8
        assert abs(MW_BYPRODUCTS - MW_BPA) < 1e-8

    def test_reaction_mass_stoichiometry_exactness(self) -> None:
        """Verify 2 Phenol + 1 Acetone = 1 BPA + 1 H2O exact mass closure."""
        reactants = 2.0 * MW_PHENOL + MW_ACETONE
        products = MW_BPA + MW_WATER
        assert abs(reactants - products) < 1e-12

    def test_reaction_enthalpies(self) -> None:
        """Verify standard reaction enthalpies for reactions 1, 2, and 3."""
        assert DELTA_H1_KJ_MOL == -105.0
        assert DELTA_H1_J_MOL == -105000.0
        assert DELTA_H2_KJ_MOL == -98.0
        assert DELTA_H2_J_MOL == -98000.0
        assert DELTA_H3_KJ_MOL == -45.0
        assert DELTA_H3_J_MOL == -45000.0


# ============================================================================
# Section 2: Packed-Bed Reactor Configuration & Baseline Parameters
# ============================================================================

class TestSection2ReactorConfiguration:
    """Tests for reactor geometric, hydrodynamic, and operating baseline configuration."""

    def test_geometric_properties(self) -> None:
        """Verify column dimensions, cross section, and volume calculations."""
        cfg = BpaConfig()
        assert cfg.reactor_diameter_m == 2.2
        assert cfg.bed_height_m == 4.0
        expected_area = 0.25 * math.pi * (2.2 ** 2)
        assert abs(cfg.bed_cross_section_m2 - expected_area) < 1e-4
        assert abs(cfg.bed_volume_m3 - (expected_area * 4.0)) < 1e-4

    def test_catalytic_bed_properties(self) -> None:
        """Verify resin bead diameter, void fraction, and thermal capacitance."""
        cfg = BpaConfig()
        assert cfg.particle_diameter_m == 0.0008
        assert cfg.bed_voidage_fraction == 0.38
        assert cfg.catalyst_bulk_density_kg_m3 == 780.0
        assert cfg.bed_heat_capacity_j_k == 3.5e6

    def test_nominal_operating_baseline_parameters(self) -> None:
        """Verify baseline operating feed, ratios, temperatures, and conversions."""
        cfg = BpaConfig()
        assert cfg.nominal_bed_inlet_temp_c == BED_INLET_TEMP_NOMINAL_C == 70.0
        assert cfg.nominal_bed_outlet_temp_c == BED_OUTLET_TEMP_NOMINAL_C == 75.0
        assert cfg.nominal_acetone_feed_kg_h == ACETONE_FEED_RATE_NOMINAL_KG_H == 2400.0
        assert cfg.nominal_phenol_acetone_ratio == PHENOL_ACETONE_RATIO_NOMINAL == 10.0
        assert ACETONE_CONV_NOMINAL_PCT == 98.5
        assert BPA_SELECTIVITY_NOMINAL_PCT == 95.2
        assert RESIN_BED_DP_NOMINAL_MBAR == 45.0
        assert RESIN_ACTIVITY_NOMINAL_PCT == 92.0
        assert REACTOR_PRESSURE_NOMINAL_BAR == 4.5

    def test_safety_interlock_thresholds(self) -> None:
        """Verify safety limit parameters."""
        assert EXOTHERM_DELTA_T_ALARM_C == 25.0
        assert RUNAWAY_TRIP_TEMP_C == 95.0
        assert RUNAWAY_TRIP_DELTA_T_C == 28.0
        assert QUENCH_SHUTOFF_TEMP_C == 78.0
        assert HIGH_DP_TRIP_MBAR == 80.0
        assert LOW_CONVERSION_TRIP_PCT == 85.0
        assert LOW_ACTIVITY_TRIP_PCT == 70.0
        assert WATER_DEACTIVATION_CONC_MOL_M3 == 1500.0


# ============================================================================
# Section 3: Reaction Kinetics & Promoter Acceleration
# ============================================================================

class TestSection3ReactionKinetics:
    """Tests for condensation, side isomerization, and 3-MPA promoter kinetics."""

    def test_activation_energies_ordering(self) -> None:
        """Verify activation energies ordering: main condensation < side isomerization < oligomerization."""
        cfg = BpaConfig()
        assert cfg.activation_energy_1_j_mol < cfg.activation_energy_2_j_mol
        assert cfg.activation_energy_2_j_mol < cfg.activation_energy_3_j_mol

    def test_reaction_rates_positive_at_baseline(self) -> None:
        """Verify reaction rates are strictly non-negative at normal conditions."""
        sim = BpaReactor()
        rates = sim.compute_reaction_rates(7875.0, 14.7, 919.7, 966.1, 46.4, 348.15)
        assert rates["r1_mol_s"] > 0.0
        assert rates["r2_mol_s"] > 0.0
        assert rates["r3_mol_s"] > 0.0
        assert rates["q_rxn_kw"] > 0.0

    def test_arrhenius_temperature_acceleration(self) -> None:
        """Verify rates accelerate with increasing temperature."""
        sim = BpaReactor()
        rates_75c = sim.compute_reaction_rates(7875.0, 14.7, 919.7, 966.1, 46.4, 348.15)
        rates_85c = sim.compute_reaction_rates(7875.0, 14.7, 919.7, 966.1, 46.4, 358.15)
        assert rates_85c["r1_mol_s"] > rates_75c["r1_mol_s"]
        assert rates_85c["r2_mol_s"] > rates_75c["r2_mol_s"]
        assert rates_85c["q_rxn_kw"] > rates_75c["q_rxn_kw"]

    def test_3_mpa_promoter_effect(self) -> None:
        """Verify 3-mercaptopropionic acid promoter accelerates main condensation."""
        sim = BpaReactor()
        assert sim.config.promoter_acceleration_factor == 3.5


# ============================================================================
# Section 4: Water Inhibition Kinetics (LHHW Model)
# ============================================================================

class TestSection4WaterInhibitionKinetics:
    """Tests for competitive adsorption of byproduct water on -SO3H sites."""

    def test_water_inhibition_rate_reduction(self) -> None:
        """Verify water accumulation sharply reduces the reaction rate."""
        sim = BpaReactor()
        rates_dry = sim.compute_reaction_rates(7875.0, 14.7, 919.7, 50.0, 46.4, 348.15)
        rates_wet = sim.compute_reaction_rates(7875.0, 14.7, 919.7, 1200.0, 46.4, 348.15)
        assert rates_dry["r1_mol_s"] > 5.0 * rates_wet["r1_mol_s"]

    def test_inhibition_denominator_growth(self) -> None:
        """Verify LHHW denominator increases with water concentration."""
        sim = BpaReactor()
        rates_low = sim.compute_reaction_rates(7875.0, 14.7, 919.7, 200.0, 46.4, 348.15)
        rates_high = sim.compute_reaction_rates(7875.0, 14.7, 919.7, 1000.0, 46.4, 348.15)
        assert rates_high["inhibition_factor"] > rates_low["inhibition_factor"]


# ============================================================================
# Section 5: Emergency Cold Phenol Quench Cooling
# ============================================================================

class TestSection5QuenchDynamics:
    """Tests for emergency cold recirculating phenol quench cooling."""

    def test_quench_inactive_at_nominal_temperature(self) -> None:
        """Verify quench is off during nominal conditions."""
        sim = BpaReactor()
        assert sim.state.emergency_cold_phenol_quench_active is False
        assert sim.state.q_quench_kw == 0.0

    def test_quench_activates_on_thermal_runaway(self) -> None:
        """Verify quench activates when bed temperature exceeds 95.0 °C."""
        sim = BpaReactor()
        sim.state.bed_outlet_temp_celsius = 96.0
        sim.state.t_bed = 96.0 + T_ZERO_CELSIUS
        sim._evaluate_safety_interlocks()
        assert sim.state.emergency_cold_phenol_quench_active is True
        assert sim.state.diagnostic_code == BpaDiagnosticCode.THERMAL_RUNAWAY_TRIP

    def test_emergency_quench_cooling_duty(self) -> None:
        """Verify significant cooling duty is generated by cold quench."""
        sim = BpaReactor()
        sim.state.bed_outlet_temp_celsius = 98.0
        sim.state.t_bed = 98.0 + T_ZERO_CELSIUS
        sim._evaluate_safety_interlocks()
        sim._update_kinetics_and_conversion()
        assert sim.state.q_quench_kw > 1000.0

    def test_quench_arrests_thermal_runaway(self) -> None:
        """Verify advancing time with quench cooling suppresses exotherm."""
        sim = BpaReactor()
        sim.state.bed_outlet_temp_celsius = 98.0
        sim.state.t_bed = 98.0 + T_ZERO_CELSIUS
        sim._evaluate_safety_interlocks()
        res = sim.advance_time(duration_s=15.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert sim.state.bed_outlet_temp_celsius < 95.0


# ============================================================================
# Section 6: Coupled 6-State ODE System & RK4 Numerical Integration
# ============================================================================

class TestSection6RK4Integration:
    """Tests for 6-state ODE derivative evaluation and RK4 integrator."""

    def test_derivative_vector_length_and_finiteness(self) -> None:
        """Verify 6 finite derivatives returned by compute_derivatives."""
        sim = BpaReactor()
        y = [
            sim.state.c_phenol,
            sim.state.c_acetone,
            sim.state.c_bpa,
            sim.state.c_water,
            sim.state.c_byproducts,
            sim.state.t_bed,
        ]
        derivs = sim.compute_derivatives(0.0, y)
        assert len(derivs) == 6
        for d in derivs:
            assert not math.isnan(d) and not math.isinf(d)

    def test_rk4_single_step_advancement(self) -> None:
        """Verify single RK4 step updates state variables within bounds."""
        sim = BpaReactor()
        t0 = sim.state.sim_time_s
        sc0 = sim.state.scan_count
        sim.rk4_step(dt=0.05)
        assert abs(sim.state.sim_time_s - (t0 + 0.05)) < 1e-6
        assert sim.state.scan_count == sc0 + 1
        assert sim.state.c_phenol > 0.0
        assert sim.state.c_bpa > 0.0

    def test_rk4_multi_step_stability_and_convergence(self) -> None:
        """Verify ODE system remains stable and convergent over 100 steps."""
        sim = BpaReactor()
        res = sim.advance_time(duration_s=5.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert 65.0 <= sim.state.bed_outlet_temp_celsius <= 85.0
        assert sim.state.c_phenol > 4000.0
        assert sim.state.c_bpa > 500.0

    def test_reset_functionality(self) -> None:
        """Verify reset restores baseline state."""
        sim = BpaReactor()
        sim.state.c_bpa = 10.0
        sim.state.bed_outlet_temp_celsius = 99.0
        sim.reset()
        assert abs(sim.state.bed_outlet_temp_celsius - 75.0) < 1e-4
        assert sim.state.c_bpa > 800.0
        assert sim.state.diagnostic_code == BpaDiagnosticCode.OK


# ============================================================================
# Section 7: Stoichiometric Mass & Enthalpy Conservation Residuals (< 1e-10)
# ============================================================================

class TestSection7ConservationResiduals:
    """Tests for strict mass, elemental, and thermal enthalpy conservation."""

    def test_total_mass_balance_residual_under_1e10(self) -> None:
        """Verify total stoichiometric mass residual is strictly < 1e-10 kg/s."""
        sim = BpaReactor()
        assert sim.state.total_mass_balance_residual_kg_s < 1e-10

    def test_elemental_mass_balance_residual_under_1e10(self) -> None:
        """Verify elemental atomic species residual is strictly < 1e-10 kg/s."""
        sim = BpaReactor()
        assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10

    def test_enthalpy_conservation_residual_under_1e10(self) -> None:
        """Verify thermal enthalpy residual is strictly < 1e-10 kW."""
        sim = BpaReactor()
        assert sim.state.enthalpy_conservation_residual_kw < 1e-10

    def test_conservation_residuals_maintained_during_rk4_integration(self) -> None:
        """Verify conservation residuals remain < 1e-10 throughout dynamic simulation."""
        sim = BpaReactor()
        for _ in range(50):
            sim.step(dt=0.05)
            assert sim.state.total_mass_balance_residual_kg_s < 1e-10
            assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10
            assert sim.state.enthalpy_conservation_residual_kw < 1e-10


# ============================================================================
# Section 8: Packed-Bed Fluid Dynamics & Ergun Pressure Drop
# ============================================================================

class TestSection8FluidDynamicsAndPressureDrop:
    """Tests for Ergun equation pressure drop and resin fouling detection."""

    def test_nominal_pressure_drop(self) -> None:
        """Verify nominal pressure drop is ~ 45.0 mbar."""
        sim = BpaReactor()
        assert abs(sim.state.resin_bed_pressure_drop_mbar - 45.0) < 1.0

    def test_resin_fouling_elevates_pressure_drop(self) -> None:
        """Verify bed fouling multiplier elevates pressure drop beyond 80 mbar."""
        sim = BpaReactor()
        sim.state.resin_fouling_factor = 2.0
        sim._update_kinetics_and_conversion()
        assert sim.state.resin_bed_pressure_drop_mbar >= 85.0


# ============================================================================
# Section 9: Process Safety Interlocks & Diagnostics (0xE101..0xE104)
# ============================================================================

class TestSection9SafetyInterlocks:
    """Tests for safety interlocks, exotherm alarm, and strict priority hierarchy."""

    def test_nominal_healthy_diagnostic_code(self) -> None:
        """Verify diagnostic code is 0x0000 (OK) at baseline conditions."""
        sim = BpaReactor()
        assert sim.state.diagnostic_code == BpaDiagnosticCode.OK
        assert sim.state.resin_bed_exotherm_alarm is False
        assert sim.state.emergency_cold_phenol_quench_active is False

    def test_resin_bed_exotherm_alarm_on_delta_t_over_25c(self) -> None:
        """Verify %M397 asserts when Delta_T > 25.0 °C."""
        sim = BpaReactor()
        sim.state.bed_inlet_temp_celsius = 65.0
        sim.state.bed_outlet_temp_celsius = 92.0  # Delta_T = 27.0 °C > 25.0 °C
        sim._evaluate_safety_interlocks()
        assert sim.state.resin_bed_exotherm_alarm is True

    def test_priority_1_thermal_runaway_trip(self) -> None:
        """Verify 0xE101 on high bed temperature and cold quench activation."""
        sim = BpaReactor()
        sim.state.bed_outlet_temp_celsius = 96.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BpaDiagnosticCode.THERMAL_RUNAWAY_TRIP
        assert sim.state.emergency_cold_phenol_quench_active is True
        assert sim.state.resin_bed_exotherm_alarm is True

    def test_priority_2_resin_fouling_high_dp(self) -> None:
        """Verify 0xE102 when pressure drop exceeds 80.0 mbar."""
        sim = BpaReactor()
        sim.state.resin_bed_pressure_drop_mbar = 85.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BpaDiagnosticCode.RESIN_FOULING_HIGH_DP

    def test_priority_3_acetone_conversion_low(self) -> None:
        """Verify 0xE103 when acetone conversion drops below 85.0%."""
        sim = BpaReactor()
        sim.state.acetone_conversion_pct = 82.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BpaDiagnosticCode.ACETONE_CONVERSION_LOW

    def test_priority_4_water_accumulation_deactivation(self) -> None:
        """Verify 0xE104 when sulfonic acid activity drops below 70.0%."""
        sim = BpaReactor()
        sim.state.resin_sulfonic_acid_activity_pct = 65.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BpaDiagnosticCode.WATER_ACCUMULATION_DEACTIVATION

    def test_strict_priority_hierarchy_ordering(self) -> None:
        """Verify strict priority ordering: 0xE101 > 0xE102 > 0xE103 > 0xE104 > 0x0000."""
        sim = BpaReactor()
        # All alarms asserted simultaneously
        sim.state.bed_outlet_temp_celsius = 98.0                  # 0xE101
        sim.state.resin_bed_pressure_drop_mbar = 88.0             # 0xE102
        sim.state.acetone_conversion_pct = 78.0                   # 0xE103
        sim.state.resin_sulfonic_acid_activity_pct = 60.0         # 0xE104
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BpaDiagnosticCode.THERMAL_RUNAWAY_TRIP

        # Clear 0xE101 -> 0xE102 takes precedence
        sim.state.bed_outlet_temp_celsius = 75.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BpaDiagnosticCode.RESIN_FOULING_HIGH_DP

        # Clear 0xE102 -> 0xE103 takes precedence
        sim.state.resin_bed_pressure_drop_mbar = 45.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BpaDiagnosticCode.ACETONE_CONVERSION_LOW

        # Clear 0xE103 -> 0xE104 takes precedence
        sim.state.acetone_conversion_pct = 98.5
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BpaDiagnosticCode.WATER_ACCUMULATION_DEACTIVATION

        # Clear 0xE104 -> 0x0000 (OK)
        sim.state.resin_sulfonic_acid_activity_pct = 92.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == BpaDiagnosticCode.OK


# ============================================================================
# Section 10: Horner OCS Memory Space Integration (%R1700..%R1707, %M396..%M398)
# ============================================================================

class TestSection10HornerMemorySpace:
    """Tests for register table mapping, scaling factors, and SYSTEM privilege write."""

    def test_register_table_write_with_system_privilege(self) -> None:
        """Verify simulator successfully writes to Horner RegisterTable with SYSTEM privilege."""
        reg = RegisterTable()
        sim = BpaReactor(register_table=reg)
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_word("%R1700") == 750
        assert reg.read_word("%R1701") == 2400
        assert reg.read_word("%R1702") == 100
        assert reg.read_word("%R1703") == 985
        assert reg.read_word("%R1704") == 952
        assert reg.read_word("%R1705") == 450
        assert reg.read_word("%R1706") == 920
        assert reg.read_uword("%R1707") == 0x0000
        assert reg.read_bit("%M396") is True
        assert reg.read_bit("%M397") is False
        assert reg.read_bit("%M398") is False

    def test_discrete_coils_under_trip(self) -> None:
        """Verify coils under thermal runaway trip."""
        reg = RegisterTable()
        sim = BpaReactor(register_table=reg)
        sim.state.bed_outlet_temp_celsius = 98.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_bit("%M397") is True
        assert reg.read_bit("%M398") is True
        assert reg.read_uword("%R1707") == 0xE101


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text & Anti-Ladder Security Guard
# ============================================================================

class TestSection11PureSTAndSecurityGuard:
    """Tests for pure Structured Text compliance, AST parsing, and ladder rejection."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify BPA POU parses into valid AST PROGRAM structure."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(BPA_REACTOR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "BpaReactorSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_pure_st_pou_register_symbol_bindings(self) -> None:
        """Verify all Horner %R and %M registers are bound in ST POU."""
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(BPA_REACTOR_PURE_ST_POU)
        assert ast is not None
        expected_regs = [
            "%R1700", "%R1701", "%R1702", "%R1703",
            "%R1704", "%R1705", "%R1706", "%R1707",
            "%M396", "%M397", "%M398",
        ]
        for r in expected_regs:
            assert r in ast.bound_registers

    def test_anti_ladder_security_guard_normal_content(self) -> None:
        """Verify SecurityGuard accepts pure Structured Text without ladder constructs."""
        SecurityGuard.assert_pure_st_content(BPA_REACTOR_PURE_ST_POU)

    def test_anti_ladder_rejection_contact(self) -> None:
        """Verify SecurityGuard raises LadderForbiddenError on ladder contacts."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_coil(self) -> None:
        """Verify SecurityGuard raises LadderForbiddenError on ladder coils."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_rung(self) -> None:
        """Verify SecurityGuard raises LadderForbiddenError on RUNG keywords."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\nRUNG 1\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_anti_ladder_rejection_mnemonics(self) -> None:
        """Verify SecurityGuard raises LadderForbiddenError on ladder mnemonics."""
        bad_code = "PROGRAM Bad\nVAR x: BOOL; END_VAR\nXIC BedOutletTempScaled\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_helper_verification_functions(self) -> None:
        """Verify helper validation functions return True / SUCCESS."""
        assert verify_bpa_reactor_pure_st() is True
        assert verify_bpa_pure_st() is True
        res = validate_pure_st()
        assert res.status == AgentStatus.SUCCESS

    def test_pou_string_constants_aliases(self) -> None:
        """Verify all POU aliases match the canonical POU string."""
        assert BPA_REACTOR_PURE_ST_POU == BPA_REACTOR_SYNC_POU == BPA_PURE_ST_POU == BPA_SYNC_POU


# ============================================================================
# Section 12: ILogicUnit Scan Cycle Execution & Simulation Engine
# ============================================================================

class TestSection12ILogicUnitIntegration:
    """Tests for ILogicUnit interface, scan_step, and adapter logic unit."""

    def test_ilogic_unit_properties(self) -> None:
        """Verify BpaReactor exposes required ILogicUnit properties."""
        sim = BpaReactor()
        assert sim.name == "BpaReactorSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

    def test_scan_step_execution(self) -> None:
        """Verify scan_step executes and syncs registers."""
        sim = BpaReactor()
        reg = RegisterTable()
        ctx = ScanContext(cycle=1, dt_ms=50.0)
        ctx.registers = reg
        sim.scan_step(dt=0.05, context=ctx)
        assert 700 <= reg.read_word("%R1700") <= 850

    def test_adapter_logic_unit(self) -> None:
        """Verify BpaReactorLogicUnit adapter integrates seamlessly."""
        unit = BpaReactorLogicUnit()
        assert unit.name == "BpaReactorSync"
        assert unit.priority == 100
        assert unit.is_enabled is True
        reg = RegisterTable()
        ctx = ScanContext(cycle=1, dt_ms=50.0)
        ctx.registers = reg
        unit.execute(ctx)
        assert 700 <= reg.read_word("%R1700") <= 850

    def test_continuous_scan_cycles(self) -> None:
        """Verify continuous 100-cycle scan execution without instability."""
        sim = BpaReactor()
        for c in range(100):
            sim.scan_step(dt=0.05)
        assert sim.state.scan_count == 100
        assert 65.0 <= sim.state.bed_outlet_temp_celsius <= 85.0


# ============================================================================
# Section 13: Deterministic 9-Stage Verification Suite & Runner Integration
# ============================================================================

class TestSection13VerificationSuite:
    """Tests for run_bpa_reactor_verification runner and JSON output."""

    def test_run_bpa_reactor_verification_deterministic_pass(self) -> None:
        """Verify 9-stage verification suite passes all checks deterministically."""
        res = run_bpa_reactor_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["total_checks"] == 9
        assert res["data"]["checks_passed"] == 9

    def test_verification_stage_names(self) -> None:
        """Verify all 9 stage check names are correctly reported."""
        res = run_bpa_reactor_verification()
        stages = [t["stage"] for t in res["data"]["tests"]]
        assert stages == list(range(1, 10))

    def test_verification_json_export(self, tmp_path: Path) -> None:
        """Verify JSON export creates valid artifact on disk."""
        out_file = tmp_path / "bpa_verification_results.json"
        res = run_bpa_reactor_verification(output_path=out_file)
        assert out_file.exists()
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9

    def test_verification_aliases(self) -> None:
        """Verify run_bpa_verification alias works identically."""
        res = run_bpa_verification()
        assert res["status"] == "success"

    def test_class_aliases(self) -> None:
        """Verify class aliases point to canonical classes."""
        assert BpaReactorSimulator is BpaReactor
        assert BpaSimulator is BpaReactor
        assert BpaReactorEngine is BpaReactor
        assert BpaReactorModel is BpaReactor
        assert BpaReactorPlantModel is BpaReactor
        assert BpaReactorSimulationEngine is BpaReactor
        assert BpaLogicUnit is BpaReactorLogicUnit
        assert BpaReactorConfig is BpaConfig
        assert BpaParameters is BpaConfig
        assert BpaReactorParameters is BpaConfig
        assert BpaReactorState is BpaState
        assert BpaDiagCode is BpaDiagnosticCode
        assert BpaReactorDiagnosticCode is BpaDiagnosticCode
        assert BpaReactorDiagCode is BpaDiagnosticCode
        assert BpaStatusWord is BpaStatusBits
        assert BpaReactorStatusBits is BpaStatusBits
        assert BpaReactorStatusWord is BpaStatusBits
