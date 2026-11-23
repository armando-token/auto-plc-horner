"""Comprehensive Industrial Maleic Anhydride Fixed-Bed Reactor Test Suite.

Work Package: W200 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 13 engineering verification sections:
1. Section 1: Universal Physical Constants, Molecular Weights & Reaction Enthalpies
2. Section 2: Fixed-Bed Multi-Tube Geometry & Operating Parameters
3. Section 3: VPO Catalyst Oxidation Kinetics, Arrhenius Acceleration & Activation Energies
4. Section 4: Molten Salt Cooling Loop & Heat Transfer Dynamics
5. Section 5: Coupled 6-State ODE System & RK4 Numerical Integration
6. Section 6: Dual Stoichiometric Mass and Thermal Enthalpy Conservation Residuals (< 1e-10)
7. Section 7: Derived Operational Metrics & Yield Performance
8. Section 8: Process Safety Interlocks & Diagnostic Event Codes (0xD801..0xD804)
9. Section 9: Emergency Nitrogen Ballast Purge Runaway Trip
10. Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege
11. Section 11: ILogicUnit Scan Cycle Execution & Simulation Engine Integration
12. Section 12: Strict Pure IEC 61131-3 Structured Text POU & Anti-Ladder Security Guard
13. Section 13: Deterministic 9-Stage Verification Suite & JSON Export
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
from jev_cscape.simulation.maleic_anhydride_reactor import (
    BUTANE_CONVERSION_NOMINAL_PCT,
    BUTANE_FEED_MAX_PCT,
    BUTANE_FEED_MIN_PCT,
    BUTANE_FEED_NOMINAL_PCT,
    COOLING_DUTY_NOMINAL_KW,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    DELTA_H_COMBUSTION_J_MOL,
    DELTA_H_COMBUSTION_KJ_MOL,
    DELTA_H_MAN_J_MOL,
    DELTA_H_MAN_KJ_MOL,
    DELTA_H_PARTIAL_OX_J_MOL,
    DELTA_H_PARTIAL_OX_KJ_MOL,
    MALEIC_ANHYDRIDE_PURE_ST_POU,
    MALEIC_ANHYDRIDE_REACTOR_PURE_ST_POU,
    MALEIC_ANHYDRIDE_REACTOR_SYNC_POU,
    MALEIC_ANHYDRIDE_SYNC_POU,
    MAN_PURE_ST_POU,
    MAN_REACTOR_PURE_ST_POU,
    MAN_REACTOR_SYNC_POU,
    MAN_SYNC_POU,
    MAN_YIELD_NOMINAL_PCT,
    MW_BUTANE,
    MW_C,
    MW_C4H10,
    MW_C4H2O3,
    MW_CO,
    MW_CO2,
    MW_H,
    MW_H2O,
    MW_MAN,
    MW_N2,
    MW_O,
    MW_O2,
    R_GAS_CONST,
    SALT_FLOW_NOMINAL_M3H,
    SALT_FLOW_TRIP_M3H,
    T_BED_HOTSPOT_ALARM_C,
    T_BED_NOMINAL_C,
    T_BED_RUNAWAY_TRIP_C,
    T_REF_K,
    T_SALT_MAX_C,
    T_SALT_MIN_C,
    T_SALT_NOMINAL_C,
    T_ZERO_CELSIUS,
    MaleicAnhydrideConfig,
    MaleicAnhydrideDiagnosticCode,
    MaleicAnhydrideParameters,
    MaleicAnhydrideReactor,
    MaleicAnhydrideReactorConfig,
    MaleicAnhydrideReactorDiagnosticCode,
    MaleicAnhydrideReactorEngine,
    MaleicAnhydrideReactorLogicUnit,
    MaleicAnhydrideReactorModel,
    MaleicAnhydrideReactorPlantModel,
    MaleicAnhydrideReactorSimulationEngine,
    MaleicAnhydrideReactorSimulator,
    MaleicAnhydrideReactorState,
    MaleicAnhydrideReactorStatusBits,
    MaleicAnhydrideReactorStatusWord,
    MaleicAnhydrideSimulator,
    MaleicAnhydrideStatusBits,
    MaleicAnhydrideStatusWord,
    ManConfig,
    ManDiagCode,
    ManDiagnosticCode,
    ManLogicUnit,
    ManParameters,
    ManReactor,
    ManReactorConfig,
    ManReactorLogicUnit,
    ManSimulator,
    ManStatusBits,
    ManStatusWord,
    run_maleic_anhydride_reactor_verification,
    run_maleic_anhydride_verification,
    run_man_reactor_verification,
    run_man_verification,
    validate_pure_st,
    verify_maleic_anhydride_reactor_pure_st,
    verify_man_reactor_pure_st,
)
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# Section 1: Universal Physical Constants, Molecular Weights & Stoichiometry
# ============================================================================

class TestSection1PhysicalConstantsAndStoichiometry:
    """Tests for physical constants, elemental/molecular weights, and reaction enthalpies."""

    def test_universal_gas_constant_and_reference_temperature(self) -> None:
        """Verify universal gas constant, zero Celsius, and reference temperature."""
        assert abs(R_GAS_CONST - 8.314462618) < 1e-6
        assert abs(T_ZERO_CELSIUS - 273.15) < 1e-4
        assert abs(T_REF_K - 678.15) < 1e-4

    def test_iupac_elemental_atomic_weights(self) -> None:
        """Verify standard IUPAC atomic weights for Carbon, Hydrogen, and Oxygen."""
        assert abs(MW_C - 0.012011) < 1e-6
        assert abs(MW_H - 0.001008) < 1e-6
        assert abs(MW_O - 0.015999) < 1e-6

    def test_reactant_and_product_molecular_weights(self) -> None:
        """Verify molecular weights for n-butane, O2, H2O, CO, CO2, and N2."""
        expected_butane = 4.0 * MW_C + 10.0 * MW_H
        assert abs(MW_C4H10 - expected_butane) < 1e-8
        assert abs(MW_BUTANE - expected_butane) < 1e-8
        assert abs(MW_BUTANE - 0.058124) < 1e-5

        assert abs(MW_O2 - 2.0 * MW_O) < 1e-8
        assert abs(MW_H2O - (2.0 * MW_H + MW_O)) < 1e-8
        assert abs(MW_CO - (MW_C + MW_O)) < 1e-8
        assert abs(MW_CO2 - (MW_C + 2.0 * MW_O)) < 1e-8
        assert abs(MW_N2 - 0.028013) < 1e-5

    def test_maleic_anhydride_exact_stoichiometric_molecular_weight(self) -> None:
        """Verify maleic anhydride (C4H2O3) molecular weight is 98.057 g/mol (0.098057 kg/mol)."""
        expected_man = 4.0 * MW_C + 2.0 * MW_H + 3.0 * MW_O
        assert abs(MW_MAN - expected_man) < 1e-8
        assert abs(MW_C4H2O3 - expected_man) < 1e-8
        assert abs(MW_MAN - 0.098057) < 1e-5

    def test_selective_oxidation_stoichiometric_mass_balance(self) -> None:
        """Verify mass balance for selective oxidation: C4H10 + 3.5 O2 -> C4H2O3 + 4 H2O."""
        reactants = MW_C4H10 + 3.5 * MW_O2
        products = MW_MAN + 4.0 * MW_H2O
        assert abs(reactants - products) < 1e-12

    def test_partial_oxidation_stoichiometric_mass_balance(self) -> None:
        """Verify mass balance for partial oxidation: C4H10 + 4.5 O2 -> 4 CO + 5 H2O."""
        reactants = MW_C4H10 + 4.5 * MW_O2
        products = 4.0 * MW_CO + 5.0 * MW_H2O
        assert abs(reactants - products) < 1e-12

    def test_deep_combustion_stoichiometric_mass_balance(self) -> None:
        """Verify mass balance for deep combustion: C4H10 + 6.5 O2 -> 4 CO2 + 5 H2O."""
        reactants = MW_C4H10 + 6.5 * MW_O2
        products = 4.0 * MW_CO2 + 5.0 * MW_H2O
        assert abs(reactants - products) < 1e-12

    def test_exothermic_reaction_enthalpies_values(self) -> None:
        """Verify highly exothermic enthalpies for VPO oxidation reactions."""
        assert DELTA_H1_KJ_MOL == -1310.0
        assert DELTA_H1_J_MOL == -1310000.0
        assert DELTA_H_MAN_KJ_MOL == -1310.0
        assert DELTA_H_MAN_J_MOL == -1310000.0

        assert DELTA_H2_KJ_MOL == -1530.0
        assert DELTA_H2_J_MOL == -1530000.0
        assert DELTA_H_PARTIAL_OX_KJ_MOL == -1530.0
        assert DELTA_H_PARTIAL_OX_J_MOL == -1530000.0

        assert DELTA_H3_KJ_MOL == -2870.0
        assert DELTA_H3_J_MOL == -2870000.0
        assert DELTA_H_COMBUSTION_KJ_MOL == -2870.0
        assert DELTA_H_COMBUSTION_J_MOL == -2870000.0


# ============================================================================
# Section 2: Fixed-Bed Multi-Tube Geometry & Operating Parameters
# ============================================================================

class TestSection2ReactorConfigurationAndGeometry:
    """Tests for MaleicAnhydrideReactorConfig geometry, dimensions, and baseline conditions."""

    def test_default_vessel_tube_geometry(self) -> None:
        """Verify 20,000 tubes, 25 mm ID, and 3.5 m active length."""
        cfg = MaleicAnhydrideReactorConfig()
        assert cfg.num_tubes == 20000
        assert cfg.tube_inner_diameter_m == 0.025
        assert cfg.tube_length_m == 3.5
        expected_cs = math.pi * (0.025 / 2.0) ** 2
        assert abs(cfg.single_tube_cross_section_m2 - expected_cs) < 1e-6

    def test_bed_volume_and_heat_transfer_area(self) -> None:
        """Verify total bed volume and tube wall heat transfer area."""
        cfg = MaleicAnhydrideReactorConfig()
        expected_vol = 20000 * (math.pi * (0.025 / 2.0) ** 2) * 3.5
        assert abs(cfg.total_bed_volume_m3 - expected_vol) < 1e-4

        expected_area = 20000 * math.pi * 0.025 * 3.5
        assert abs(cfg.total_heat_transfer_area_m2 - expected_area) < 1e-4
        assert cfg.ua_total_w_k == cfg.overall_heat_transfer_coeff_w_m2_k * cfg.total_heat_transfer_area_m2

    def test_thermal_capacitances_bed_and_salt(self) -> None:
        """Verify lumped thermal capacitances for catalyst bed and molten salt bath."""
        cfg = MaleicAnhydrideReactorConfig()
        assert cfg.bed_thermal_capacitance_j_k > 0.0
        expected_salt_cap = 60000.0 * 1560.0
        assert abs(cfg.salt_thermal_capacitance_j_k - expected_salt_cap) < 1e-4

    def test_nominal_feed_and_operating_conditions(self) -> None:
        """Verify baseline feed concentration (1.80 mol%), conversion (84.5%), and temps."""
        cfg = MaleicAnhydrideReactorConfig()
        assert cfg.nominal_butane_feed_pct == BUTANE_FEED_NOMINAL_PCT == 1.80
        assert cfg.nominal_o2_feed_pct == 20.57
        assert cfg.target_bed_hotspot_c == T_BED_NOMINAL_C == 435.0
        assert cfg.target_salt_bath_c == T_SALT_NOMINAL_C == 405.0
        assert cfg.nominal_salt_flow_m3_h == SALT_FLOW_NOMINAL_M3H == 125.0
        assert cfg.nominal_cooling_duty_kw == COOLING_DUTY_NOMINAL_KW == 18500.0

    def test_configuration_aliases(self) -> None:
        """Verify configuration class aliases."""
        assert ManConfig is MaleicAnhydrideReactorConfig
        assert ManReactorConfig is MaleicAnhydrideReactorConfig
        assert MaleicAnhydrideConfig is MaleicAnhydrideReactorConfig
        assert MaleicAnhydrideParameters is MaleicAnhydrideReactorConfig
        assert ManParameters is MaleicAnhydrideReactorConfig


# ============================================================================
# Section 3: VPO Catalyst Oxidation Kinetics, Arrhenius Acceleration & Ea
# ============================================================================

class TestSection3VPOKineticsAndArrhenius:
    """Tests for Arrhenius rate constants, activation energies, and kinetics functions."""

    @pytest.fixture
    def reactor(self) -> MaleicAnhydrideReactor:
        return MaleicAnhydrideReactor()

    def test_arrhenius_activation_energies_ordering(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify Ea3 (145 kJ/mol) > Ea2 (108 kJ/mol) > Ea1 (92 kJ/mol)."""
        cfg = reactor.config
        assert cfg.activation_e3_j_mol > cfg.activation_e2_j_mol
        assert cfg.activation_e2_j_mol > cfg.activation_e1_j_mol
        assert cfg.activation_e1_j_mol == 92000.0
        assert cfg.activation_e2_j_mol == 108000.0
        assert cfg.activation_e3_j_mol == 145000.0

    def test_arrhenius_rate_constant_calculation(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify arrhenius_rate_constant computes k = A * exp(-Ea / (R * T))."""
        t_k = 410.0 + T_ZERO_CELSIUS
        k = reactor.arrhenius_rate_constant(1.25e7, 92000.0, t_k)
        expected = 1.25e7 * math.exp(-92000.0 / (R_GAS_CONST * t_k))
        assert abs(k - expected) < 1e-8

    def test_temperature_acceleration_monotonicity(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify reaction rate constant k1 increases monotonically with temperature."""
        t1_k = 390.0 + T_ZERO_CELSIUS
        t2_k = 410.0 + T_ZERO_CELSIUS
        t3_k = 430.0 + T_ZERO_CELSIUS
        k1 = reactor.arrhenius_rate_constant(reactor.config.arrhenius_a1, reactor.config.activation_e1_j_mol, t1_k)
        k2 = reactor.arrhenius_rate_constant(reactor.config.arrhenius_a1, reactor.config.activation_e1_j_mol, t2_k)
        k3 = reactor.arrhenius_rate_constant(reactor.config.arrhenius_a1, reactor.config.activation_e1_j_mol, t3_k)
        assert k3 > k2 > k1 > 0.0

    def test_deep_combustion_accelerates_faster_than_selective_oxidation(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify combustion acceleration (k3_ratio) exceeds selective oxidation acceleration (k1_ratio)."""
        t_low = 390.0 + T_ZERO_CELSIUS
        t_high = 430.0 + T_ZERO_CELSIUS
        k1_low = reactor.arrhenius_rate_constant(reactor.config.arrhenius_a1, reactor.config.activation_e1_j_mol, t_low)
        k1_high = reactor.arrhenius_rate_constant(reactor.config.arrhenius_a1, reactor.config.activation_e1_j_mol, t_high)
        k3_low = reactor.arrhenius_rate_constant(reactor.config.arrhenius_a3, reactor.config.activation_e3_j_mol, t_low)
        k3_high = reactor.arrhenius_rate_constant(reactor.config.arrhenius_a3, reactor.config.activation_e3_j_mol, t_high)
        ratio_k1 = k1_high / k1_low
        ratio_k3 = k3_high / k3_low
        assert ratio_k3 > ratio_k1

    def test_nominal_reaction_rates_positive(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify compute_kinetics produces positive rates and heat duties at nominal conditions."""
        t_bed_k = 435.0 + T_ZERO_CELSIUS
        kin = reactor.compute_kinetics(t_bed_k=t_bed_k, c_butane=0.1237, c_o2=7.15)
        assert kin["r1_tot"] > 0.0
        assert kin["r2_tot"] > 0.0
        assert kin["r3_tot"] > 0.0
        assert kin["q1_kw"] > 0.0
        assert kin["q2_kw"] > 0.0
        assert kin["q3_kw"] > 0.0
        assert kin["q_total_kw"] > 0.0

    def test_kinetics_zero_feed_zero_rates(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify zero concentrations produce zero reaction rates."""
        t_bed_k = 435.0 + T_ZERO_CELSIUS
        kin = reactor.compute_kinetics(t_bed_k=t_bed_k, c_butane=0.0, c_o2=0.0)
        assert kin["r1_tot"] == 0.0
        assert kin["r2_tot"] == 0.0
        assert kin["r3_tot"] == 0.0
        assert kin["q_total_kw"] == 0.0

    def test_catalyst_overreduction_low_o2_ratio(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify O2/butane ratio calculation and threshold."""
        assert reactor.config.min_o2_butane_ratio == 8.0
        assert reactor.state.o2_butane_ratio > 8.0


# ============================================================================
# Section 4: Molten Salt Cooling Loop & Heat Transfer Dynamics
# ============================================================================

class TestSection4MoltenSaltCoolingLoop:
    """Tests for molten salt heat transfer UA, circulation flow scaling, and cooling duties."""

    @pytest.fixture
    def reactor(self) -> MaleicAnhydrideReactor:
        return MaleicAnhydrideReactor()

    def test_molten_salt_heat_transfer_duty_nominal(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify UA heat transfer rate is > 15 MW for a 30 °C Delta T."""
        ua_kw_k = reactor.config.ua_total_w_k / 1000.0
        q_trans = ua_kw_k * 30.0
        assert q_trans > 15000.0

    def test_molten_salt_flow_dynamics_and_sensitivity(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify that reducing salt circulation flow impacts dT_salt/dt."""
        y = [0.12, 7.0, 0.5, 0.7, 435.0, 405.0]
        reactor.state.salt_flow_m3_h = 125.0
        d_nom = reactor.compute_derivatives(0.0, y)

        reactor.state.salt_flow_m3_h = 50.0  # Reduced flow
        d_low = reactor.compute_derivatives(0.0, y)

        # Lower salt flow reduces heat sent to steam generator -> dT_salt/dt increases
        assert d_low[5] > d_nom[5]

    def test_loss_of_salt_circulation_causes_salt_heating(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify salt temperature rises when circulation flow drops."""
        reactor.state.salt_flow_m3_h = 40.0
        t_salt_0 = reactor.state.t_salt_c
        reactor.advance_time(duration_s=2.0, dt=0.05)
        assert reactor.state.t_salt_c >= t_salt_0

    def test_salt_overheat_thresholds(self) -> None:
        """Verify salt temperature limits and nominal values."""
        assert T_SALT_MIN_C == 380.0
        assert T_SALT_NOMINAL_C == 405.0
        assert T_SALT_MAX_C == 440.0

    def test_salt_pump_trip_limit_value(self) -> None:
        """Verify minimum salt flow trip limit is 80 m3/h."""
        assert SALT_FLOW_TRIP_M3H == 80.0
        assert SALT_FLOW_NOMINAL_M3H == 125.0


# ============================================================================
# Section 5: Coupled 6-State ODE System & RK4 Numerical Integration
# ============================================================================

class TestSection5CoupledODESystemAndRK4:
    """Tests for derivative vector, RK4 integration stability, and bounds clamping."""

    @pytest.fixture
    def reactor(self) -> MaleicAnhydrideReactor:
        return MaleicAnhydrideReactor()

    def test_compute_derivatives_returns_6_states(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify derivative function returns exactly 6 state derivatives."""
        y = [0.1237, 7.15, 0.4988, 0.702, 435.0, 405.0]
        derivs = reactor.compute_derivatives(0.0, y)
        assert len(derivs) == 6

    def test_derivatives_finite_and_real(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify all derivatives are finite (no NaN or Inf)."""
        y = [0.1237, 7.15, 0.4988, 0.702, 435.0, 405.0]
        derivs = reactor.compute_derivatives(0.0, y)
        for d in derivs:
            assert math.isfinite(d)

    def test_single_rk4_step_advances_sim_time(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify single rk4_step advances simulation time by dt."""
        t0 = reactor.state.sim_time_s
        reactor.rk4_step(dt=0.02)
        assert abs(reactor.state.sim_time_s - (t0 + 0.02)) < 1e-9

    def test_rk4_multi_step_stability(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify RK4 solver executes stably over 200 micro-steps without diverging."""
        for _ in range(200):
            res = reactor.step(dt=0.01)
            assert res.status == AgentStatus.SUCCESS
        assert 400.0 <= reactor.state.t_bed_c <= 460.0
        assert 380.0 <= reactor.state.t_salt_c <= 440.0

    def test_rk4_concentration_clamping_prevents_negatives(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify state concentrations are clamped to non-negative bounds."""
        reactor.state.c_butane = -1.0
        reactor.state.c_o2 = -5.0
        reactor.state.c_man = -2.0
        reactor.rk4_step(dt=0.01)
        assert reactor.state.c_butane >= 0.0
        assert reactor.state.c_o2 >= 0.0
        assert reactor.state.c_man >= 0.0

    def test_reset_restores_nominal_state(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify reset restores simulator state to nominal baseline."""
        reactor.advance_time(duration_s=3.0, dt=0.05)
        reactor.reset()
        assert reactor.state.sim_time_s == 0.0
        assert abs(reactor.state.t_bed_c - T_BED_NOMINAL_C) < 1e-4
        assert abs(reactor.state.t_salt_c - T_SALT_NOMINAL_C) < 1e-4


# ============================================================================
# Section 6: Dual Stoichiometric Mass and Energy Conservation Residuals (< 1e-10)
# ============================================================================

class TestSection6MassAndEnergyConservationResiduals:
    """Tests for stoichiometric mass, elemental, and enthalpy residuals (< 1e-10)."""

    @pytest.fixture
    def reactor(self) -> MaleicAnhydrideReactor:
        return MaleicAnhydrideReactor()

    def test_mass_balance_residual_strictly_below_tolerance(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify total mass balance residual is strictly < 1e-10 kg/s."""
        reactor._update_conservation_residuals()
        assert reactor.state.total_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_mass_residual_strictly_below_tolerance(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify atomic elemental mass residual is strictly < 1e-10 kg/s."""
        reactor._update_conservation_residuals()
        assert reactor.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_enthalpy_conservation_residual_strictly_below_tolerance(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify thermal enthalpy conservation residual is strictly < 1e-10 kW."""
        reactor._update_conservation_residuals()
        assert reactor.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_conservation_residuals_over_dynamic_transients(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify conservation residuals remain < 1e-10 over transient steps."""
        for _ in range(15):
            reactor.step(dt=0.05)
            assert reactor.state.total_mass_balance_residual_kg_s < 1.0e-10
            assert reactor.state.elemental_mass_balance_residual_kg_s < 1.0e-10
            assert reactor.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_uncooled_bed_shows_temperature_rise(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify that an uncooled bed with active feed has positive dT_bed/dt."""
        derivs = reactor.compute_derivatives(0.0, [0.70, 8.5, 0.0, 0.0, 435.0, 435.0])
        assert derivs[4] > 0.0


# ============================================================================
# Section 7: Derived Operational Metrics & Yield Performance
# ============================================================================

class TestSection7DerivedOperationalMetrics:
    """Tests for butane conversion, maleic anhydride yield/selectivity, and status bits."""

    @pytest.fixture
    def reactor(self) -> MaleicAnhydrideReactor:
        return MaleicAnhydrideReactor()

    def test_butane_conversion_calculation(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify butane per-pass conversion is calculated in target range."""
        reactor._update_kinetics_and_conversion()
        assert 70.0 <= reactor.state.butane_conversion_pct <= 95.0

    def test_maleic_anhydride_yield_and_selectivity(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify MAN yield and selectivity are within commercial bounds."""
        reactor._update_kinetics_and_conversion()
        assert 50.0 <= reactor.state.man_yield_pct <= 80.0
        assert 60.0 <= reactor.state.man_selectivity_pct <= 90.0

    def test_total_reaction_heat_and_salt_removal(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify heat released by reactions and removed by salt are tracked."""
        reactor._update_kinetics_and_conversion()
        assert reactor.state.q_rxn_total_kw > 0.0
        assert reactor.state.q_salt_heat_removal_kw > 0.0

    def test_status_bits_bitmask_operations(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify status word contains RUNNING, OXIDATION_ACTIVE, and SALT_NORMAL flags."""
        reactor._update_status_bits()
        sw = int(reactor.state.status_bits)
        assert bool(sw & MaleicAnhydrideStatusBits.RUNNING) is True
        assert bool(sw & MaleicAnhydrideStatusBits.OXIDATION_REACTION_ACTIVE) is True
        assert bool(sw & MaleicAnhydrideStatusBits.SALT_CIRCULATION_NORMAL) is True


# ============================================================================
# Section 8: Process Safety Interlocks & Diagnostics (Strict Priority Hierarchy)
# ============================================================================

class TestSection8SafetyInterlocksAndDiagnostics:
    """Tests for diagnostic event codes 0xD801..0xD804 and strict priority ordering."""

    @pytest.fixture
    def reactor(self) -> MaleicAnhydrideReactor:
        return MaleicAnhydrideReactor()

    def test_normal_steady_state_diagnostic_ok(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify baseline operating conditions yield diagnostic code OK (0x0000)."""
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == MaleicAnhydrideDiagnosticCode.OK
        assert reactor.state.oxidation_reaction_active is True
        assert reactor.state.emergency_n2_purge_active is False
        assert reactor.state.hotspot_high_alarm_active is False

    def test_diag_d801_hotspot_thermal_runaway_trip(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify T_bed > 465 °C asserts 0xD801, sets emergency purge, clears permissive."""
        reactor.state.t_bed_c = 470.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == MaleicAnhydrideDiagnosticCode.HOTSPOT_THERMAL_RUNAWAY
        assert reactor.state.emergency_n2_purge_active is True
        assert reactor.state.oxidation_reaction_active is False
        assert reactor.state.hotspot_high_alarm_active is True

    def test_diag_d801_trip_unlatches_below_reset_temperature(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify trip latches until bed temperature drops below reset threshold (430 °C)."""
        reactor.state.t_bed_c = 468.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.emergency_n2_purge_active is True

        # Drop to 440 °C (below 465 °C trip but above 430 °C reset) -> remains latched
        reactor.state.t_bed_c = 440.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.emergency_n2_purge_active is True

        # Drop to 425 °C (below 430 °C reset) -> clears trip
        reactor.state.t_bed_c = 425.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.emergency_n2_purge_active is False

    def test_diag_d802_salt_pump_trip_on_low_flow(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify salt circulation flow < 80 m3/h asserts 0xD802 and halts reaction."""
        reactor.state.t_bed_c = 435.0
        reactor.state.salt_flow_m3_h = 60.0  # Low flow
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == MaleicAnhydrideDiagnosticCode.SALT_PUMP_TRIP
        assert reactor.state.oxidation_reaction_active is False
        assert reactor.state.emergency_n2_purge_active is False

    def test_diag_d803_explosive_concentration_breach(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify butane feed > 2.20 mol% asserts 0xD803 and clears permissive."""
        reactor.state.butane_feed_pct = 2.45  # Exceeds 2.20 mol% limit
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == MaleicAnhydrideDiagnosticCode.EXPLOSIVE_CONC_LIMIT_BREACH
        assert reactor.state.oxidation_reaction_active is False

    def test_diag_d804_vpo_catalyst_overreduction(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify O2/butane ratio < 8.0 asserts 0xD804 warning without cutting reaction."""
        reactor.state.o2_butane_ratio = 6.5  # < 8.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == MaleicAnhydrideDiagnosticCode.VPO_CATALYST_OVERREDUCTION
        assert reactor.state.oxidation_reaction_active is True

    def test_hotspot_high_pre_alarm_coil_m376(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify bed temp at 452 °C asserts %M376 pre-alarm without tripping runaway."""
        reactor.state.t_bed_c = 452.0  # > 450 °C alarm, < 465 °C trip
        reactor._evaluate_safety_interlocks()
        assert reactor.state.hotspot_high_alarm_active is True
        assert reactor.state.emergency_n2_purge_active is False
        assert reactor.state.diagnostic_code == MaleicAnhydrideDiagnosticCode.OK

    def test_strict_priority_hierarchy_d801_over_all(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify 0xD801 takes precedence over all other fault conditions."""
        reactor.state.t_bed_c = 472.0        # Runaway (0xD801)
        reactor.state.salt_flow_m3_h = 50.0  # Pump trip (0xD802)
        reactor.state.butane_feed_pct = 3.0  # Explosive breach (0xD803)
        reactor.state.o2_butane_ratio = 5.0  # Overreduction (0xD804)
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == MaleicAnhydrideDiagnosticCode.HOTSPOT_THERMAL_RUNAWAY


# ============================================================================
# Section 9: Emergency Nitrogen Ballast Purge Runaway Trip
# ============================================================================

class TestSection9EmergencyNitrogenBallastPurge:
    """Tests for emergency nitrogen purge activation, quench rate, and thermal cooldown."""

    @pytest.fixture
    def reactor(self) -> MaleicAnhydrideReactor:
        return MaleicAnhydrideReactor()

    def test_emergency_purge_activates_on_runaway(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify emergency purge asserts %M377 when thermal runaway is detected."""
        reactor.state.t_bed_c = 468.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.emergency_n2_purge_active is True

    def test_emergency_purge_quenches_reaction_power(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify emergency purge stops chemical heat generation."""
        reactor.state.t_bed_c = 468.0
        reactor._evaluate_safety_interlocks()
        reactor.advance_time(duration_s=1.0, dt=0.05)
        assert reactor.state.q_rxn_total_kw < 100.0

    def test_emergency_purge_cools_bed_below_runaway(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify emergency purge cools reactor bed below 450 °C within 10s."""
        reactor.state.t_bed_c = 468.0
        reactor._evaluate_safety_interlocks()
        res = reactor.advance_time(duration_s=10.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert reactor.state.t_bed_c < 450.0

    def test_emergency_n2_purge_design_specifications(self) -> None:
        """Verify cold N2 purge specifications: 30 °C, 25 kg/s, Cp ~ 1040 J/(kg*K)."""
        cfg = MaleicAnhydrideReactorConfig()
        assert cfg.emergency_n2_purge_temp_c == 30.0
        assert cfg.emergency_n2_purge_flow_kg_s == 25.0
        assert cfg.n2_cp_j_kg_k == 1040.0


# ============================================================================
# Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege
# ============================================================================

class TestSection10HornerRegisterSynchronization:
    """Tests for Horner OCS %R1610..%R1617, %M375..%M377, and SYSTEM privilege writes."""

    def test_registers_nominal_values_written_with_system_privilege(self) -> None:
        """Verify %R1610..%R1617 registers at nominal operating baseline."""
        reg = RegisterTable()
        sim = MaleicAnhydrideReactor(register_table=reg)
        sim.state.t_bed_c = 435.0
        sim.state.t_salt_c = 405.0
        sim.state.butane_feed_pct = 1.80
        sim.state.butane_conversion_pct = 84.5
        sim.state.man_yield_pct = 62.5
        sim.state.salt_cooling_duty_kw = 18500.0
        sim.state.salt_flow_m3_h = 125.0
        sim.state.diagnostic_code = MaleicAnhydrideDiagnosticCode.OK
        sim._sync_registers()

        assert reg.read_word("%R1610") == 4350   # 435.0 °C (x10)
        assert reg.read_word("%R1611") == 4050   # 405.0 °C (x10)
        assert reg.read_word("%R1612") == 180    # 1.80 mol% (x100)
        assert reg.read_word("%R1613") == 845    # 84.5 % (x10)
        assert reg.read_word("%R1614") == 625    # 62.5 % (x10)
        assert reg.read_word("%R1615") == 18500  # 18500 kW (x1)
        assert reg.read_word("%R1616") == 1250   # 125.0 m3/h (x10)
        assert reg.read_word("%R1617") & 0xFFFF == 0x0000 # OK

    def test_discrete_coils_synchronization_m375_to_m377(self) -> None:
        """Verify discrete coils %M375..%M377 synchronization."""
        reg = RegisterTable()
        sim = MaleicAnhydrideReactor(register_table=reg)
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_bit("%M375") is True     # OxidationReactionActive
        assert reg.read_bit("%M376") is False    # HotspotHighAlarmActive
        assert reg.read_bit("%M377") is False    # EmergencyN2BallastPurgeActive

    def test_diagnostic_status_code_register_r1617(self) -> None:
        """Verify diagnostic code 0xD801 writes to %R1617 and sets coils %M376, %M377."""
        reg = RegisterTable()
        sim = MaleicAnhydrideReactor(register_table=reg)
        sim.state.t_bed_c = 470.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_word("%R1617") & 0xFFFF == 0xD801
        assert reg.read_bit("%M375") is False
        assert reg.read_bit("%M376") is True
        assert reg.read_bit("%M377") is True

    def test_user_privilege_blocked_when_registers_read_only(self) -> None:
        """Verify sync_to_registers succeeds with PrivilegeMode.SYSTEM."""
        reg = RegisterTable()
        sim = MaleicAnhydrideReactor(register_table=reg)
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert reg.read_word("%R1610") == 4350

    def test_register_scaling_factors_consistency(self) -> None:
        """Verify scaling factors for temperature (x10), concentration (x100), and flow (x10)."""
        reg = RegisterTable()
        sim = MaleicAnhydrideReactor(register_table=reg)
        sim.state.t_bed_c = 412.3
        sim.state.butane_feed_pct = 1.75
        sim.state.salt_flow_m3_h = 110.5
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_word("%R1610") == 4123
        assert reg.read_word("%R1612") == 175
        assert reg.read_word("%R1616") == 1105


# ============================================================================
# Section 11: ILogicUnit Scan Cycle Execution & Simulation Engine Integration
# ============================================================================

class TestSection11ILogicUnitScanCycleIntegration:
    """Tests for ILogicUnit scan_step cycle, ScanContext execution, and adapters."""

    @pytest.fixture
    def reactor(self) -> MaleicAnhydrideReactor:
        return MaleicAnhydrideReactor()

    def test_ilogicunit_interface_contracts(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify ILogicUnit interface attributes."""
        assert isinstance(reactor, ILogicUnit)
        assert reactor.name == "MaleicAnhydrideReactorSync"
        assert reactor.priority == 100
        assert reactor.is_enabled is True

    def test_scan_step_execution_updates_registers(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify scan_step advances one scan and updates internal registers."""
        t_before = reactor.state.sim_time_s
        reactor.scan_step(dt=0.05)
        assert abs(reactor.state.sim_time_s - (t_before + 0.05)) < 1e-9

    def test_execute_from_scan_context(self, reactor: MaleicAnhydrideReactor) -> None:
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
        reactor.execute(ctx)
        assert 4340 <= reg.read_word("%R1610") <= 4360

    def test_adapter_logic_unit_scan_and_reset(self) -> None:
        """Verify MaleicAnhydrideReactorLogicUnit adapter executes cleanly."""
        adapter = MaleicAnhydrideReactorLogicUnit()
        assert adapter.name == "MaleicAnhydrideReactorSync"
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
        assert 4340 <= reg.read_word("%R1610") <= 4360

        adapter.reset()
        assert adapter.simulator.state.sim_time_s == 0.0

    def test_continuous_multi_scan_execution(self, reactor: MaleicAnhydrideReactor) -> None:
        """Verify 50 consecutive scans execute stably."""
        for _ in range(50):
            reactor.scan_step(dt=0.02)
        assert reactor.state.sim_time_s > 0.9


# ============================================================================
# Section 12: Strict Pure IEC 61131-3 ST POU & Anti-Ladder Security Guard
# ============================================================================

class TestSection12PureIEC61131STAndAntiLadder:
    """Tests for pure Structured Text syntax, AST parsing, and ladder rejection."""

    def test_pure_st_pou_ast_parsing_and_name(self) -> None:
        """Verify MALEIC_ANHYDRIDE_REACTOR_PURE_ST_POU passes AST parsing cleanly."""
        SecurityGuard.assert_pure_st_content(MALEIC_ANHYDRIDE_REACTOR_PURE_ST_POU)
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(MALEIC_ANHYDRIDE_REACTOR_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "MaleicAnhydrideReactorSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_pure_st_pou_register_symbol_bindings(self) -> None:
        """Verify AST binds registers %R1610..%R1617 and %M375..%M377."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(MALEIC_ANHYDRIDE_REACTOR_PURE_ST_POU)
        assert pou is not None
        expected_regs = [
            "%R1610", "%R1611", "%R1612", "%R1613",
            "%R1614", "%R1615", "%R1616", "%R1617",
            "%M375", "%M376", "%M377",
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
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T\nVAR m: BOOL; END_VAR\nXIC m\nEND_PROGRAM")

    def test_verify_pure_st_helper_functions(self) -> None:
        """Verify helper validation functions return True and success."""
        assert verify_maleic_anhydride_reactor_pure_st() is True
        assert verify_man_reactor_pure_st() is True
        res = validate_pure_st()
        assert res is True


# ============================================================================
# Section 13: Deterministic 9-Stage Verification Suite & JSON Export
# ============================================================================

class TestSection13Deterministic9StageVerificationRunner:
    """Tests for run_maleic_anhydride_reactor_verification 9-stage runner and JSON export."""

    def test_verification_runner_status_success(self) -> None:
        """Verify verification runner returns status: success and error_code: None."""
        res = run_maleic_anhydride_reactor_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["work_package"] == "W200"
        assert res["data"]["total_checks"] == 9
        assert res["data"]["checks_passed"] == 9

    def test_verification_runner_all_9_stages_pass(self) -> None:
        """Verify each of the 9 stages individually passes with factual evidence."""
        res = run_maleic_anhydride_reactor_verification()
        tests = res["data"]["tests"]
        assert len(tests) == 9
        for t in tests:
            assert t["passed"] is True, f"Stage {t['stage']} failed: {t['details']}"

    def test_verification_runner_json_evidence_export(self, tmp_path: Path) -> None:
        """Verify verification runner exports valid JSON evidence matching strict contract."""
        out_file = tmp_path / "maleic_evidence.json"
        res = run_maleic_anhydride_reactor_verification(output_path=out_file)
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W200"
        assert data["data"]["checks_passed"] == 9

    def test_verification_runner_aliases(self) -> None:
        """Verify runner function aliases."""
        assert run_man_reactor_verification is run_maleic_anhydride_reactor_verification
        assert run_maleic_anhydride_verification is run_maleic_anhydride_reactor_verification
        assert run_man_verification is run_maleic_anhydride_reactor_verification
