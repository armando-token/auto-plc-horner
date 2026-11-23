"""Comprehensive Industrial Phthalic Anhydride Fixed-Bed Reactor Test Suite.

Work Package: W203 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 13 engineering verification sections:
1. Section 1: Universal Physical Constants, Molecular Weights & Reaction Enthalpies
2. Section 2: Fixed-Bed Multi-Tube Geometry & Operating Parameters
3. Section 3: V2O5-TiO2 Catalyst Oxidation Kinetics, Arrhenius Acceleration & Activation Energies
4. Section 4: Molten Salt Cooling Loop & Heat Transfer Dynamics
5. Section 5: Coupled 6-State ODE System & RK4 Numerical Integration
6. Section 6: Dual Stoichiometric Mass and Thermal Enthalpy Conservation Residuals (< 1e-10)
7. Section 7: Derived Operational Metrics & Yield Performance
8. Section 8: Process Safety Interlocks & Diagnostic Event Codes (0xDB01..0xDB04)
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
from jev_cscape.simulation.phthalic_anhydride_reactor import (
    COOLING_DUTY_NOMINAL_KW,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    DELTA_H_COMBUSTION_J_MOL,
    DELTA_H_COMBUSTION_KJ_MOL,
    DELTA_H_PAN_J_MOL,
    DELTA_H_PAN_KJ_MOL,
    DELTA_H_PARTIAL_OX_J_MOL,
    DELTA_H_PARTIAL_OX_KJ_MOL,
    MW_C,
    MW_C8H10,
    MW_C8H4O3,
    MW_CO,
    MW_CO2,
    MW_H,
    MW_H2O,
    MW_N,
    MW_N2,
    MW_O,
    MW_O2,
    MW_OXYLENE,
    MW_PAN,
    OXYLENE_CONVERSION_NOMINAL_PCT,
    OXYLENE_LOADING_MAX_G_NM3,
    OXYLENE_LOADING_MIN_G_NM3,
    OXYLENE_LOADING_NOMINAL_G_NM3,
    PAN_PURE_ST_POU,
    PAN_REACTOR_PURE_ST_POU,
    PAN_REACTOR_SYNC_POU,
    PAN_SYNC_POU,
    PAN_YIELD_NOMINAL_PCT,
    PHTHALIC_ANHYDRIDE_PURE_ST_POU,
    PHTHALIC_ANHYDRIDE_REACTOR_PURE_ST_POU,
    PHTHALIC_ANHYDRIDE_REACTOR_SYNC_POU,
    PHTHALIC_ANHYDRIDE_SYNC_POU,
    PHTHALIC_PURE_ST_POU,
    PHTHALIC_REACTOR_PURE_ST_POU,
    PHTHALIC_REACTOR_SYNC_POU,
    PHTHALIC_SYNC_POU,
    R_GAS_CONST,
    RHO_MOLAR_STP,
    SALT_FLOW_NOMINAL_M3H,
    SALT_FLOW_TRIP_M3H,
    T_BED_HOTSPOT_ALARM_C,
    T_BED_NOMINAL_C,
    T_BED_RUNAWAY_RESET_C,
    T_BED_RUNAWAY_TRIP_C,
    T_REF_K,
    T_SALT_MAX_C,
    T_SALT_MIN_C,
    T_SALT_NOMINAL_C,
    T_ZERO_CELSIUS,
    V_MOLAR_STP,
    PanConfig,
    PanDiagCode,
    PanDiagnosticCode,
    PanLogicUnit,
    PanParameters,
    PanReactor,
    PanReactorConfig,
    PanReactorLogicUnit,
    PanReactorState,
    PanSimulator,
    PanState,
    PanStatusBits,
    PanStatusWord,
    PhthalicAnhydrideConfig,
    PhthalicAnhydrideDiagnosticCode,
    PhthalicAnhydrideParameters,
    PhthalicAnhydrideReactor,
    PhthalicAnhydrideReactorConfig,
    PhthalicAnhydrideReactorDiagnosticCode,
    PhthalicAnhydrideReactorEngine,
    PhthalicAnhydrideReactorLogicUnit,
    PhthalicAnhydrideReactorModel,
    PhthalicAnhydrideReactorPlantModel,
    PhthalicAnhydrideReactorSimulationEngine,
    PhthalicAnhydrideReactorSimulator,
    PhthalicAnhydrideReactorState,
    PhthalicAnhydrideReactorStatusBits,
    PhthalicAnhydrideReactorStatusWord,
    PhthalicAnhydrideSimulator,
    PhthalicAnhydrideState,
    PhthalicAnhydrideStatusBits,
    PhthalicAnhydrideStatusWord,
    PhthalicConfig,
    PhthalicDiagCode,
    PhthalicDiagnosticCode,
    PhthalicLogicUnit,
    PhthalicParameters,
    PhthalicReactor,
    PhthalicReactorConfig,
    PhthalicReactorLogicUnit,
    PhthalicReactorState,
    PhthalicSimulator,
    PhthalicState,
    PhthalicStatusBits,
    PhthalicStatusWord,
    run_pan_reactor_verification,
    run_pan_verification,
    run_phthalic_anhydride_reactor_verification,
    run_phthalic_anhydride_verification,
    run_phthalic_reactor_verification,
    run_phthalic_verification,
    validate_pure_st,
    verify_pan_reactor_pure_st,
    verify_phthalic_anhydride_reactor_pure_st,
    verify_phthalic_pure_st,
    verify_phthalic_reactor_pure_st,
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
        assert abs(T_REF_K - 698.15) < 1e-4
        assert abs(V_MOLAR_STP - 0.022414) < 1e-5
        assert abs(RHO_MOLAR_STP - 44.615) < 1e-3

    def test_iupac_elemental_atomic_weights(self) -> None:
        """Verify standard IUPAC atomic weights for Carbon, Hydrogen, Oxygen, and Nitrogen."""
        assert abs(MW_C - 0.012011) < 1e-6
        assert abs(MW_H - 0.001008) < 1e-6
        assert abs(MW_O - 0.015999) < 1e-6
        assert abs(MW_N - 0.014007) < 1e-6

    def test_reactant_and_product_molecular_weights(self) -> None:
        """Verify molecular weights for o-xylene, O2, H2O, CO, CO2, and N2."""
        expected_oxylene = 8.0 * MW_C + 10.0 * MW_H
        assert abs(MW_C8H10 - expected_oxylene) < 1e-8
        assert abs(MW_OXYLENE - expected_oxylene) < 1e-8
        assert abs(MW_OXYLENE - 0.106168) < 1e-5

        assert abs(MW_O2 - 2.0 * MW_O) < 1e-8
        assert abs(MW_H2O - (2.0 * MW_H + MW_O)) < 1e-8
        assert abs(MW_CO - (MW_C + MW_O)) < 1e-8
        assert abs(MW_CO2 - (MW_C + 2.0 * MW_O)) < 1e-8
        assert abs(MW_N2 - 0.028013) < 1e-5

    def test_phthalic_anhydride_exact_stoichiometric_molecular_weight(self) -> None:
        """Verify phthalic anhydride (C8H4O3) molecular weight is 148.117 g/mol (0.148117 kg/mol)."""
        expected_pan = 8.0 * MW_C + 4.0 * MW_H + 3.0 * MW_O
        assert abs(MW_PAN - expected_pan) < 1e-8
        assert abs(MW_C8H4O3 - expected_pan) < 1e-8
        assert abs(MW_PAN - 0.148117) < 1e-5

    def test_selective_oxidation_stoichiometric_mass_balance(self) -> None:
        """Verify mass balance for selective oxidation: C8H10 + 3 O2 -> C8H4O3 + 3 H2O."""
        reactants = MW_C8H10 + 3.0 * MW_O2
        products = MW_PAN + 3.0 * MW_H2O
        assert abs(reactants - products) < 1e-12

    def test_partial_oxidation_stoichiometric_mass_balance(self) -> None:
        """Verify mass balance for partial oxidation: C8H10 + 6.5 O2 -> 8 CO + 5 H2O."""
        reactants = MW_C8H10 + 6.5 * MW_O2
        products = 8.0 * MW_CO + 5.0 * MW_H2O
        assert abs(reactants - products) < 1e-12

    def test_deep_combustion_stoichiometric_mass_balance(self) -> None:
        """Verify mass balance for deep combustion: C8H10 + 10.5 O2 -> 8 CO2 + 5 H2O."""
        reactants = MW_C8H10 + 10.5 * MW_O2
        products = 8.0 * MW_CO2 + 5.0 * MW_H2O
        assert abs(reactants - products) < 1e-12

    def test_exothermic_reaction_enthalpies_values(self) -> None:
        """Verify highly exothermic enthalpies for V2O5-TiO2 oxidation reactions."""
        assert DELTA_H1_KJ_MOL == -1110.0
        assert DELTA_H1_J_MOL == -1110000.0
        assert DELTA_H_PAN_KJ_MOL == -1110.0
        assert DELTA_H_PAN_J_MOL == -1110000.0

        assert DELTA_H2_KJ_MOL == -2340.0
        assert DELTA_H2_J_MOL == -2340000.0
        assert DELTA_H_PARTIAL_OX_KJ_MOL == -2340.0
        assert DELTA_H_PARTIAL_OX_J_MOL == -2340000.0

        assert DELTA_H3_KJ_MOL == -4560.0
        assert DELTA_H3_J_MOL == -4560000.0
        assert DELTA_H_COMBUSTION_KJ_MOL == -4560.0
        assert DELTA_H_COMBUSTION_J_MOL == -4560000.0


# ============================================================================
# Section 2: Fixed-Bed Multi-Tube Geometry & Operating Parameters
# ============================================================================

class TestSection2ReactorConfigurationAndGeometry:
    """Tests for PhthalicAnhydrideReactorConfig geometry, dimensions, and baseline conditions."""

    def test_default_vessel_tube_geometry(self) -> None:
        """Verify 25,000 tubes, 25 mm ID, and 3.5 m active length."""
        cfg = PhthalicAnhydrideReactorConfig()
        assert cfg.num_tubes == 25000
        assert cfg.tube_inner_diameter_m == 0.025
        assert cfg.tube_length_m == 3.5
        expected_cs = math.pi * (0.025 / 2.0) ** 2
        assert abs(cfg.single_tube_cross_section_m2 - expected_cs) < 1e-6

    def test_bed_volume_and_heat_transfer_area(self) -> None:
        """Verify total bed volume and tube wall heat transfer area."""
        cfg = PhthalicAnhydrideReactorConfig()
        expected_vol = 25000 * (math.pi * (0.025 / 2.0) ** 2) * 3.5
        assert abs(cfg.total_bed_volume_m3 - expected_vol) < 1e-4

        expected_area = 25000 * math.pi * 0.025 * 3.5
        assert abs(cfg.total_heat_transfer_area_m2 - expected_area) < 1e-4
        assert cfg.ua_total_w_k == 430000.0

    def test_thermal_capacitances_bed_and_salt(self) -> None:
        """Verify lumped thermal capacitances for catalyst bed and molten salt bath."""
        cfg = PhthalicAnhydrideReactorConfig()
        assert cfg.bed_thermal_capacitance_j_k > 0.0
        expected_salt_cap = 75000.0 * 1560.0
        assert abs(cfg.salt_thermal_capacitance_j_k - expected_salt_cap) < 1e-4

    def test_nominal_feed_and_operating_conditions(self) -> None:
        """Verify baseline feed loading (60.0 g/Nm3), conversion (99.5%), and temps."""
        cfg = PhthalicAnhydrideReactorConfig()
        assert cfg.nominal_oxylene_loading_g_nm3 == OXYLENE_LOADING_NOMINAL_G_NM3 == 60.0
        assert cfg.nominal_o2_feed_pct == 20.68
        assert cfg.target_bed_hotspot_c == T_BED_NOMINAL_C == 425.0
        assert cfg.target_salt_bath_c == T_SALT_NOMINAL_C == 375.0
        assert cfg.nominal_salt_flow_m3_h == SALT_FLOW_NOMINAL_M3H == 145.0
        assert cfg.nominal_cooling_duty_kw == COOLING_DUTY_NOMINAL_KW == 21500.0

    def test_configuration_aliases(self) -> None:
        """Verify configuration class aliases."""
        assert PanConfig is PhthalicAnhydrideReactorConfig
        assert PanReactorConfig is PhthalicAnhydrideReactorConfig
        assert PhthalicAnhydrideConfig is PhthalicAnhydrideReactorConfig
        assert PhthalicAnhydrideParameters is PhthalicAnhydrideReactorConfig
        assert PanParameters is PhthalicAnhydrideReactorConfig
        assert PhthalicConfig is PhthalicAnhydrideReactorConfig
        assert PhthalicParameters is PhthalicAnhydrideReactorConfig

    def test_residence_time_and_bed_void_fraction(self) -> None:
        """Verify catalyst bed void fraction and residence time."""
        cfg = PhthalicAnhydrideReactorConfig()
        assert cfg.catalyst_bed_void_fraction == 0.40
        assert cfg.catalyst_bulk_density_kg_m3 == 1000.0
        assert cfg.residence_time_s == 2.0


# ============================================================================
# Section 3: V2O5-TiO2 Catalyst Oxidation Kinetics, Arrhenius Acceleration & Ea
# ============================================================================

class TestSection3V2O5TiO2KineticsAndArrhenius:
    """Tests for Arrhenius rate constants, activation energies, and kinetics functions."""

    @pytest.fixture
    def reactor(self) -> PhthalicAnhydrideReactor:
        return PhthalicAnhydrideReactor()

    def test_arrhenius_activation_energies_ordering(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify Ea3 (145 kJ/mol) > Ea2 (110 kJ/mol) > Ea1 (95 kJ/mol)."""
        cfg = reactor.config
        assert cfg.activation_e3_j_mol > cfg.activation_e2_j_mol
        assert cfg.activation_e2_j_mol > cfg.activation_e1_j_mol
        assert cfg.activation_e1_j_mol == 95000.0
        assert cfg.activation_e2_j_mol == 110000.0
        assert cfg.activation_e3_j_mol == 145000.0

    def test_arrhenius_rate_constant_calculation(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify arrhenius_rate_constant computes k = A * exp(-Ea / (R * T))."""
        t_k = 425.0 + T_ZERO_CELSIUS
        k = reactor.arrhenius_rate_constant(1.12e9, 95000.0, t_k)
        expected = 1.12e9 * math.exp(-95000.0 / (R_GAS_CONST * t_k))
        assert abs(k - expected) < 1e-8

    def test_temperature_acceleration_monotonicity(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify reaction rate constant k1 increases monotonically with temperature."""
        t1_k = 360.0 + T_ZERO_CELSIUS
        t2_k = 390.0 + T_ZERO_CELSIUS
        t3_k = 425.0 + T_ZERO_CELSIUS
        k1 = reactor.arrhenius_rate_constant(reactor.config.arrhenius_a1, reactor.config.activation_e1_j_mol, t1_k)
        k2 = reactor.arrhenius_rate_constant(reactor.config.arrhenius_a1, reactor.config.activation_e1_j_mol, t2_k)
        k3 = reactor.arrhenius_rate_constant(reactor.config.arrhenius_a1, reactor.config.activation_e1_j_mol, t3_k)
        assert k3 > k2 > k1 > 0.0

    def test_deep_combustion_accelerates_faster_than_selective_oxidation(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify combustion acceleration (k3_ratio) exceeds selective oxidation acceleration (k1_ratio)."""
        t_low = 360.0 + T_ZERO_CELSIUS
        t_high = 425.0 + T_ZERO_CELSIUS
        k1_low = reactor.arrhenius_rate_constant(reactor.config.arrhenius_a1, reactor.config.activation_e1_j_mol, t_low)
        k1_high = reactor.arrhenius_rate_constant(reactor.config.arrhenius_a1, reactor.config.activation_e1_j_mol, t_high)
        k3_low = reactor.arrhenius_rate_constant(reactor.config.arrhenius_a3, reactor.config.activation_e3_j_mol, t_low)
        k3_high = reactor.arrhenius_rate_constant(reactor.config.arrhenius_a3, reactor.config.activation_e3_j_mol, t_high)
        ratio_k1 = k1_high / k1_low
        ratio_k3 = k3_high / k3_low
        assert ratio_k3 > ratio_k1

    def test_nominal_reaction_rates_positive(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify compute_kinetics produces positive rates and heat duties at nominal conditions."""
        t_bed_k = 425.0 + T_ZERO_CELSIUS
        kin = reactor.compute_kinetics(t_bed_k=t_bed_k, c_oxylene=0.002445, c_o2=6.45)
        assert kin["r1_tot"] > 0.0
        assert kin["r2_tot"] > 0.0
        assert kin["r3_tot"] > 0.0
        assert kin["q1_kw"] > 0.0
        assert kin["q2_kw"] > 0.0
        assert kin["q3_kw"] > 0.0
        assert kin["q_total_kw"] > 0.0

    def test_kinetics_zero_feed_zero_rates(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify zero concentrations produce zero reaction rates."""
        t_bed_k = 425.0 + T_ZERO_CELSIUS
        kin = reactor.compute_kinetics(t_bed_k=t_bed_k, c_oxylene=0.0, c_o2=0.0)
        assert kin["r1_tot"] == 0.0
        assert kin["r2_tot"] == 0.0
        assert kin["r3_tot"] == 0.0
        assert kin["q_total_kw"] == 0.0

    def test_oxygen_redox_saturation_behavior(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify oxygen redox saturation factor f_o2 increases and asymptotes at high O2."""
        t_bed_k = 425.0 + T_ZERO_CELSIUS
        kin1 = reactor.compute_kinetics(t_bed_k=t_bed_k, c_oxylene=0.01, c_o2=1.0)
        kin2 = reactor.compute_kinetics(t_bed_k=t_bed_k, c_oxylene=0.01, c_o2=6.0)
        kin3 = reactor.compute_kinetics(t_bed_k=t_bed_k, c_oxylene=0.01, c_o2=12.0)
        assert kin3["r1"] > kin2["r1"] > kin1["r1"]
        # Rate doubling from 6 to 12 is less than from 1 to 6
        assert (kin3["r1"] / kin2["r1"]) < (kin2["r1"] / kin1["r1"])

    def test_kinetics_inactive_when_reaction_disabled(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify reaction rates are zero when oxidation_reaction_active is False."""
        reactor.state.oxidation_reaction_active = False
        t_bed_k = 425.0 + T_ZERO_CELSIUS
        kin = reactor.compute_kinetics(t_bed_k=t_bed_k, c_oxylene=0.0024, c_o2=6.45)
        assert kin["r1_tot"] == 0.0
        assert kin["q_total_kw"] == 0.0


# ============================================================================
# Section 4: Molten Salt Cooling Loop & Heat Transfer Dynamics
# ============================================================================

class TestSection4MoltenSaltCoolingLoop:
    """Tests for molten salt heat transfer UA, circulation flow scaling, and cooling duties."""

    @pytest.fixture
    def reactor(self) -> PhthalicAnhydrideReactor:
        return PhthalicAnhydrideReactor()

    def test_molten_salt_heat_transfer_duty_nominal(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify UA heat transfer rate is >= 20 MW for a 50 °C Delta T."""
        ua_kw_k = reactor.config.ua_total_w_k / 1000.0
        q_trans = ua_kw_k * 50.0
        assert q_trans >= 20000.0

    def test_molten_salt_flow_dynamics_and_sensitivity(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify that reducing salt circulation flow impacts dT_salt/dt."""
        y = [0.002, 6.5, 0.4, 0.7, 425.0, 375.0]
        reactor.state.salt_flow_m3_h = 145.0
        d_nom = reactor.compute_derivatives(0.0, y)

        reactor.state.salt_flow_m3_h = 60.0  # Reduced flow
        d_low = reactor.compute_derivatives(0.0, y)

        # Lower salt flow reduces heat sent to steam generator -> dT_salt/dt increases
        assert d_low[5] > d_nom[5]

    def test_loss_of_salt_circulation_causes_salt_heating(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify salt temperature rises when circulation flow drops."""
        reactor.state.salt_flow_m3_h = 40.0
        t_salt_0 = reactor.state.t_salt_c
        reactor.advance_time(duration_s=2.0, dt=0.05)
        assert reactor.state.t_salt_c >= t_salt_0

    def test_salt_overheat_thresholds(self) -> None:
        """Verify salt temperature limits and nominal values."""
        assert T_SALT_MIN_C == 350.0
        assert T_SALT_NOMINAL_C == 375.0
        assert T_SALT_MAX_C == 390.0

    def test_salt_pump_trip_limit_value(self) -> None:
        """Verify minimum salt flow trip limit is 95 m3/h."""
        assert SALT_FLOW_TRIP_M3H == 95.0
        assert SALT_FLOW_NOMINAL_M3H == 145.0

    def test_salt_inventory_and_thermal_capacity(self) -> None:
        """Verify salt bath inventory is 75,000 kg with Cp=1560 J/(kg*K)."""
        cfg = PhthalicAnhydrideReactorConfig()
        assert cfg.salt_bath_inventory_kg == 75000.0
        assert cfg.salt_cp_j_kg_k == 1560.0
        assert cfg.salt_thermal_capacitance_j_k == 75000.0 * 1560.0


# ============================================================================
# Section 5: Coupled 6-State ODE System & RK4 Numerical Integration
# ============================================================================

class TestSection5CoupledODESystemAndRK4:
    """Tests for derivative vector, RK4 integration stability, and bounds clamping."""

    @pytest.fixture
    def reactor(self) -> PhthalicAnhydrideReactor:
        return PhthalicAnhydrideReactor()

    def test_compute_derivatives_returns_6_states(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify derivative function returns exactly 6 state derivatives."""
        y = [0.002445, 6.45, 0.3985, 0.704, 425.0, 375.0]
        derivs = reactor.compute_derivatives(0.0, y)
        assert len(derivs) == 6

    def test_derivatives_finite_and_real(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify all derivatives are finite (no NaN or Inf)."""
        y = [0.002445, 6.45, 0.3985, 0.704, 425.0, 375.0]
        derivs = reactor.compute_derivatives(0.0, y)
        for d in derivs:
            assert math.isfinite(d)

    def test_single_rk4_step_advances_sim_time(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify single rk4_step advances simulation time by dt."""
        t0 = reactor.state.sim_time_s
        reactor.rk4_step(dt=0.02)
        assert abs(reactor.state.sim_time_s - (t0 + 0.02)) < 1e-9

    def test_rk4_multi_step_stability(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify RK4 solver executes stably over 200 micro-steps without diverging."""
        for _ in range(200):
            res = reactor.step(dt=0.01)
            assert res.status == AgentStatus.SUCCESS
        assert 380.0 <= reactor.state.t_bed_c <= 460.0
        assert 350.0 <= reactor.state.t_salt_c <= 420.0

    def test_rk4_concentration_clamping_prevents_negatives(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify state concentrations are clamped to non-negative bounds."""
        reactor.state.c_oxylene = -1.0
        reactor.state.c_o2 = -5.0
        reactor.state.c_pan = -2.0
        reactor.rk4_step(dt=0.01)
        assert reactor.state.c_oxylene >= 0.0
        assert reactor.state.c_o2 >= 0.0
        assert reactor.state.c_pan >= 0.0

    def test_reset_restores_nominal_state(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify reset restores simulator state to nominal baseline."""
        reactor.advance_time(duration_s=3.0, dt=0.05)
        reactor.reset()
        assert reactor.state.sim_time_s == 0.0
        assert abs(reactor.state.t_bed_c - T_BED_NOMINAL_C) < 1e-4
        assert abs(reactor.state.t_salt_c - T_SALT_NOMINAL_C) < 1e-4

    def test_advance_time_positive_duration_validation(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify advance_time succeeds for positive durations."""
        res = reactor.advance_time(duration_s=0.5, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None

    def test_advance_time_negative_or_zero_returns_error(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify advance_time fails for negative or zero duration."""
        res_zero = reactor.advance_time(duration_s=0.0, dt=0.05)
        assert res_zero.status == AgentStatus.FAILED
        assert res_zero.error_code == "INVALID_TIMESTEP"

        res_neg = reactor.advance_time(duration_s=-1.0, dt=0.05)
        assert res_neg.status == AgentStatus.FAILED


# ============================================================================
# Section 6: Dual Stoichiometric Mass and Energy Conservation Residuals (< 1e-10)
# ============================================================================

class TestSection6MassAndEnergyConservationResiduals:
    """Tests for stoichiometric mass, elemental, and enthalpy residuals (< 1e-10)."""

    @pytest.fixture
    def reactor(self) -> PhthalicAnhydrideReactor:
        return PhthalicAnhydrideReactor()

    def test_mass_balance_residual_strictly_below_tolerance(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify total mass balance residual is strictly < 1e-10 kg/s."""
        reactor._update_conservation_residuals()
        assert reactor.state.total_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_mass_residual_strictly_below_tolerance(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify atomic elemental mass residual is strictly < 1e-10 kg/s."""
        reactor._update_conservation_residuals()
        assert reactor.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_enthalpy_conservation_residual_strictly_below_tolerance(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify thermal enthalpy conservation residual is strictly < 1e-10 kW."""
        reactor._update_conservation_residuals()
        assert reactor.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_conservation_residuals_over_dynamic_transients(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify conservation residuals remain < 1e-10 over transient steps."""
        for _ in range(15):
            reactor.step(dt=0.05)
            assert reactor.state.total_mass_balance_residual_kg_s < 1.0e-10
            assert reactor.state.elemental_mass_balance_residual_kg_s < 1.0e-10
            assert reactor.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_uncooled_bed_shows_temperature_rise(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify that an uncooled bed with active feed has positive dT_bed/dt."""
        derivs = reactor.compute_derivatives(0.0, [0.48, 7.9, 0.0, 0.0, 425.0, 425.0])
        assert derivs[4] > 0.0

    def test_conservation_residual_zero_rates(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify conservation residuals when reaction is inactive."""
        reactor.state.oxidation_reaction_active = False
        reactor._update_kinetics_and_conversion()
        reactor._update_conservation_residuals()
        assert reactor.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert reactor.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# Section 7: Derived Operational Metrics & Yield Performance
# ============================================================================

class TestSection7DerivedOperationalMetrics:
    """Tests for oxylene conversion, phthalic anhydride yield/selectivity, and status bits."""

    @pytest.fixture
    def reactor(self) -> PhthalicAnhydrideReactor:
        return PhthalicAnhydrideReactor()

    def test_oxylene_conversion_calculation(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify o-xylene per-pass conversion is calculated in target range."""
        reactor._update_kinetics_and_conversion()
        assert 80.0 <= reactor.state.oxylene_conversion_pct <= 100.0

    def test_phthalic_anhydride_yield_and_selectivity(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify PAN yield and selectivity are within commercial bounds."""
        reactor._update_kinetics_and_conversion()
        assert 70.0 <= reactor.state.pan_yield_pct <= 95.0
        assert 70.0 <= reactor.state.pan_selectivity_pct <= 95.0

    def test_total_reaction_heat_and_salt_removal(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify heat released by reactions and removed by salt are tracked."""
        reactor._update_kinetics_and_conversion()
        assert reactor.state.q_rxn_total_kw > 0.0
        assert reactor.state.salt_heat_removal_kw > 0.0

    def test_status_bits_bitmask_operations(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify status word contains RUNNING, OXIDATION_ACTIVE, and SALT_NORMAL flags."""
        reactor._update_status_bits()
        sw = int(reactor.state.status_bits)
        assert bool(sw & PhthalicAnhydrideStatusBits.RUNNING) is True
        assert bool(sw & PhthalicAnhydrideStatusBits.OXIDATION_REACTION_ACTIVE) is True
        assert bool(sw & PhthalicAnhydrideStatusBits.SALT_CIRCULATION_NORMAL) is True

    def test_state_property_getters_and_setters(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify state property getters and setters for compatibility."""
        st = reactor.state
        st.t_bed = 430.5
        assert st.t_bed_c == 430.5
        assert st.bed_hotspot_temp_celsius == 430.5

        st.t_salt = 378.2
        assert st.t_salt_c == 378.2
        assert st.molten_salt_bath_temp_celsius == 378.2

        st.oxylene_feed_loading_g_nm3 = 65.0
        assert st.oxylene_loading_g_nm3 == 65.0

        st.molten_salt_heat_removal_kw = 22000.0
        assert st.salt_heat_removal_kw == 22000.0

        st.salt_circulation_flow_m3_h = 150.0
        assert st.salt_flow_m3_h == 150.0

        st.status_word = int(PhthalicAnhydrideStatusBits.RUNNING)
        assert st.status_bits == PhthalicAnhydrideStatusBits.RUNNING


# ============================================================================
# Section 8: Process Safety Interlocks & Diagnostics (Strict Priority Hierarchy)
# ============================================================================

class TestSection8SafetyInterlocksAndDiagnostics:
    """Tests for diagnostic event codes 0xDB01..0xDB04 and strict priority ordering."""

    @pytest.fixture
    def reactor(self) -> PhthalicAnhydrideReactor:
        return PhthalicAnhydrideReactor()

    def test_normal_steady_state_diagnostic_ok(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify baseline operating conditions yield diagnostic code OK (0x0000)."""
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == PhthalicAnhydrideDiagnosticCode.OK
        assert reactor.state.oxidation_reaction_active is True
        assert reactor.state.emergency_n2_purge_active is False
        assert reactor.state.hotspot_high_alarm_active is False

    def test_diag_db01_hotspot_runaway_risk_trip(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify T_bed > 455 °C asserts 0xDB01, sets emergency purge, clears permissive."""
        reactor.state.t_bed_c = 460.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == PhthalicAnhydrideDiagnosticCode.HOTSPOT_RUNAWAY_RISK
        assert reactor.state.emergency_n2_purge_active is True
        assert reactor.state.oxidation_reaction_active is False
        assert reactor.state.hotspot_high_alarm_active is True

    def test_diag_db01_trip_unlatches_below_reset_temperature(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify trip latches until bed temperature drops below reset threshold (420 °C)."""
        reactor.state.t_bed_c = 458.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.emergency_n2_purge_active is True

        # Drop to 435 °C (below 455 °C trip but above 420 °C reset) -> remains latched
        reactor.state.t_bed_c = 435.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.emergency_n2_purge_active is True

        # Drop to 415 °C (below 420 °C reset) -> clears trip
        reactor.state.t_bed_c = 415.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.emergency_n2_purge_active is False

    def test_diag_db02_salt_pump_failure_on_low_flow(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify salt circulation flow < 95 m3/h asserts 0xDB02 and halts reaction."""
        reactor.state.t_bed_c = 425.0
        reactor.state.salt_flow_m3_h = 75.0  # Low flow
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == PhthalicAnhydrideDiagnosticCode.SALT_PUMP_FAILURE
        assert reactor.state.oxidation_reaction_active is False
        assert reactor.state.emergency_n2_purge_active is False

    def test_diag_db03_explosive_limit_breach_high(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify o-xylene feed loading > 85 g/Nm3 asserts 0xDB03 and clears permissive."""
        reactor.state.oxylene_loading_g_nm3 = 90.0  # Exceeds 85 g/Nm3 limit
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == PhthalicAnhydrideDiagnosticCode.EXPLOSIVE_LIMIT_BREACH
        assert reactor.state.oxidation_reaction_active is False

    def test_diag_db03_explosive_limit_breach_low(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify o-xylene feed loading < 20 g/Nm3 asserts 0xDB03 and clears permissive."""
        reactor.state.oxylene_loading_g_nm3 = 15.0  # Below 20 g/Nm3 limit
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == PhthalicAnhydrideDiagnosticCode.EXPLOSIVE_LIMIT_BREACH
        assert reactor.state.oxidation_reaction_active is False

    def test_diag_db04_catalyst_overheating_warning(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify 440 < T_bed <= 455 °C asserts 0xDB04 warning without cutting reaction."""
        reactor.state.t_bed_c = 445.0  # between 440 and 455
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == PhthalicAnhydrideDiagnosticCode.CATALYST_OVERHEATING
        assert reactor.state.oxidation_reaction_active is True
        assert reactor.state.hotspot_high_alarm_active is True

    def test_hotspot_high_pre_alarm_coil_m383(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify bed temp at 442 °C asserts %M383 pre-alarm."""
        reactor.state.t_bed_c = 442.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.hotspot_high_alarm_active is True
        assert reactor.state.emergency_n2_purge_active is False
        assert reactor.state.diagnostic_code == PhthalicAnhydrideDiagnosticCode.CATALYST_OVERHEATING

    def test_strict_priority_hierarchy_db01_over_all(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify 0xDB01 takes precedence over all other fault conditions."""
        reactor.state.t_bed_c = 462.0        # Runaway (0xDB01)
        reactor.state.salt_flow_m3_h = 60.0  # Pump failure (0xDB02)
        reactor.state.oxylene_loading_g_nm3 = 95.0 # Explosive breach (0xDB03)
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == PhthalicAnhydrideDiagnosticCode.HOTSPOT_RUNAWAY_RISK


# ============================================================================
# Section 9: Emergency Nitrogen Ballast Purge Runaway Trip
# ============================================================================

class TestSection9EmergencyNitrogenBallastPurge:
    """Tests for emergency nitrogen purge activation, quench rate, and thermal cooldown."""

    @pytest.fixture
    def reactor(self) -> PhthalicAnhydrideReactor:
        return PhthalicAnhydrideReactor()

    def test_emergency_purge_activates_on_runaway(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify emergency purge asserts %M384 when thermal runaway is detected."""
        reactor.state.t_bed_c = 460.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.emergency_n2_purge_active is True

    def test_emergency_purge_quenches_reaction_power(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify emergency purge stops chemical heat generation."""
        reactor.state.t_bed_c = 460.0
        reactor._evaluate_safety_interlocks()
        reactor.advance_time(duration_s=1.0, dt=0.05)
        assert reactor.state.q_rxn_total_kw < 100.0

    def test_emergency_purge_cools_bed_below_runaway(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify emergency purge cools reactor bed below 440 °C within 15s."""
        reactor.state.t_bed_c = 460.0
        reactor._evaluate_safety_interlocks()
        res = reactor.advance_time(duration_s=15.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert reactor.state.t_bed_c < 440.0

    def test_emergency_n2_purge_design_specifications(self) -> None:
        """Verify cold N2 purge specifications: 25 °C, 50 kg/s, Cp ~ 1040 J/(kg*K)."""
        cfg = PhthalicAnhydrideReactorConfig()
        assert cfg.emergency_n2_purge_temp_c == 25.0
        assert cfg.emergency_n2_purge_flow_kg_s == 50.0
        assert cfg.n2_cp_j_kg_k == 1040.0

    def test_emergency_purge_isolates_hydrocarbon_feed(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify derivatives with emergency purge active have zero reactant inlet concentrations."""
        reactor.state.emergency_n2_purge_active = True
        derivs = reactor.compute_derivatives(0.0, [0.002, 6.5, 0.4, 0.7, 450.0, 375.0])
        assert derivs[0] <= 0.0


# ============================================================================
# Section 10: Horner OCS Memory Space Integration & SYSTEM Privilege
# ============================================================================

class TestSection10HornerRegisterSynchronization:
    """Tests for Horner OCS %R1640..%R1647, %M382..%M384, and SYSTEM privilege writes."""

    def test_registers_nominal_values_written_with_system_privilege(self) -> None:
        """Verify %R1640..%R1647 registers at nominal operating baseline."""
        reg = RegisterTable()
        sim = PhthalicAnhydrideReactor(register_table=reg)
        sim.state.t_bed_c = 425.0
        sim.state.t_salt_c = 375.0
        sim.state.oxylene_loading_g_nm3 = 60.0
        sim.state.oxylene_conversion_pct = 99.5
        sim.state.pan_yield_pct = 81.5
        sim.state.salt_heat_removal_kw = 21500.0
        sim.state.salt_flow_m3_h = 145.0
        sim.state.diagnostic_code = PhthalicAnhydrideDiagnosticCode.OK
        sim._sync_registers()

        assert reg.read_word("%R1640") == 4250   # 425.0 °C (x10)
        assert reg.read_word("%R1641") == 3750   # 375.0 °C (x10)
        assert reg.read_word("%R1642") == 600    # 60.0 g/Nm3 (x10)
        assert reg.read_word("%R1643") == 995    # 99.5 % (x10)
        assert reg.read_word("%R1644") == 815    # 81.5 % (x10)
        assert reg.read_word("%R1645") == 21500  # 21500 kW (x1)
        assert reg.read_word("%R1646") == 1450   # 145.0 m3/h (x10)
        assert reg.read_word("%R1647") & 0xFFFF == 0x0000 # OK

    def test_discrete_coils_synchronization_m382_to_m384(self) -> None:
        """Verify discrete coils %M382..%M384 synchronization."""
        reg = RegisterTable()
        sim = PhthalicAnhydrideReactor(register_table=reg)
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_bit("%M382") is True     # OxidationReactionActive
        assert reg.read_bit("%M383") is False    # HotspotHighAlarmActive
        assert reg.read_bit("%M384") is False    # EmergencyN2PurgeActive

    def test_diagnostic_status_code_register_r1647(self) -> None:
        """Verify diagnostic code 0xDB01 writes to %R1647 and sets coils %M383, %M384."""
        reg = RegisterTable()
        sim = PhthalicAnhydrideReactor(register_table=reg)
        sim.state.t_bed_c = 460.0
        sim._evaluate_safety_interlocks()
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_word("%R1647") & 0xFFFF == 0xDB01
        assert reg.read_bit("%M382") is False
        assert reg.read_bit("%M383") is True
        assert reg.read_bit("%M384") is True

    def test_register_writes_require_system_privilege(self) -> None:
        """Verify sync_to_registers succeeds with PrivilegeMode.SYSTEM."""
        reg = RegisterTable()
        sim = PhthalicAnhydrideReactor(register_table=reg)
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        assert reg.read_word("%R1640") == 4250

    def test_register_scaling_factors_consistency(self) -> None:
        """Verify scaling factors for temperature (x10), loading (x10), and flow (x10)."""
        reg = RegisterTable()
        sim = PhthalicAnhydrideReactor(register_table=reg)
        sim.state.t_bed_c = 412.3
        sim.state.oxylene_loading_g_nm3 = 62.5
        sim.state.salt_flow_m3_h = 135.2
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

        assert reg.read_word("%R1640") == 4123
        assert reg.read_word("%R1642") == 625
        assert reg.read_word("%R1646") == 1352

    def test_register_bounds_clamping(self) -> None:
        """Verify registers are clamped to valid INT16 boundaries."""
        reg = RegisterTable()
        sim = PhthalicAnhydrideReactor(register_table=reg)
        sim.state.t_bed_c = 5000.0
        sim.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)
        val = reg.read_word("%R1640")
        assert -32768 <= val <= 32767


# ============================================================================
# Section 11: ILogicUnit Scan Cycle Execution & Simulation Engine Integration
# ============================================================================

class TestSection11ILogicUnitScanCycleIntegration:
    """Tests for ILogicUnit scan_step cycle, ScanContext execution, and adapters."""

    @pytest.fixture
    def reactor(self) -> PhthalicAnhydrideReactor:
        return PhthalicAnhydrideReactor()

    def test_ilogicunit_interface_contracts(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify ILogicUnit interface attributes."""
        assert isinstance(reactor, ILogicUnit)
        assert reactor.name == "PhthalicAnhydrideReactorSync"
        assert reactor.priority == 100
        assert reactor.is_enabled is True

    def test_scan_step_execution_updates_registers(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify scan_step advances one scan and updates internal registers."""
        t_before = reactor.state.sim_time_s
        reactor.scan_step(dt=0.05)
        assert abs(reactor.state.sim_time_s - (t_before + 0.05)) < 1e-9

    def test_execute_from_scan_context(self, reactor: PhthalicAnhydrideReactor) -> None:
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
        assert 4200 <= reg.read_word("%R1640") <= 4300

    def test_adapter_logic_unit_scan_and_reset(self) -> None:
        """Verify PhthalicAnhydrideReactorLogicUnit adapter executes cleanly."""
        adapter = PhthalicAnhydrideReactorLogicUnit()
        assert adapter.name == "PhthalicAnhydrideReactorSync"
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
        assert 4200 <= reg.read_word("%R1640") <= 4300

        adapter.reset()
        assert adapter.simulator.state.sim_time_s == 0.0

    def test_continuous_multi_scan_execution(self, reactor: PhthalicAnhydrideReactor) -> None:
        """Verify 50 consecutive scans execute stably."""
        for _ in range(50):
            reactor.scan_step(dt=0.02)
        assert reactor.state.sim_time_s > 0.9

    def test_scan_step_with_context_register_table(self, reactor: PhthalicAnhydrideReactor) -> None:
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
        reactor.scan_step(dt=0.02, context=ctx)
        assert reg.read_word("%R1640") > 0


# ============================================================================
# Section 12: Strict Pure IEC 61131-3 ST POU & Anti-Ladder Security Guard
# ============================================================================

class TestSection12PureIEC61131STAndAntiLadder:
    """Tests for pure Structured Text syntax, AST parsing, and ladder rejection."""

    def test_pure_st_pou_ast_parsing_and_name(self) -> None:
        """Verify PHTHALIC_ANHYDRIDE_REACTOR_PURE_ST_POU passes AST parsing cleanly."""
        SecurityGuard.assert_pure_st_content(PHTHALIC_ANHYDRIDE_REACTOR_PURE_ST_POU)
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(PHTHALIC_ANHYDRIDE_REACTOR_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "PhthalicAnhydrideReactorSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_pure_st_pou_register_symbol_bindings(self) -> None:
        """Verify AST binds registers %R1640..%R1647 and %M382..%M384."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(PHTHALIC_ANHYDRIDE_REACTOR_PURE_ST_POU)
        assert pou is not None
        expected_regs = [
            "%R1640", "%R1641", "%R1642", "%R1643",
            "%R1644", "%R1645", "%R1646", "%R1647",
            "%M382", "%M383", "%M384",
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

    def test_anti_ladder_mnemonics_rejection(self) -> None:
        """Verify ladder mnemonics (XIC, OTE) are rejected."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T\nVAR m: BOOL; END_VAR\nXIC m\nEND_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM T\nVAR m: BOOL; END_VAR\nOTE m\nEND_PROGRAM")

    def test_verify_pure_st_helper_functions(self) -> None:
        """Verify helper validation functions return True and success."""
        assert verify_phthalic_anhydride_reactor_pure_st() is True
        assert verify_pan_reactor_pure_st() is True
        assert verify_phthalic_pure_st() is True
        assert verify_phthalic_reactor_pure_st() is True
        res = validate_pure_st()
        assert res is True


# ============================================================================
# Section 13: Deterministic 9-Stage Verification Suite & JSON Export
# ============================================================================

class TestSection13Deterministic9StageVerificationRunner:
    """Tests for run_phthalic_anhydride_reactor_verification 9-stage runner and JSON export."""

    def test_verification_runner_status_success(self) -> None:
        """Verify verification runner returns status: success and error_code: None."""
        res = run_phthalic_anhydride_reactor_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["work_package"] == "W203"
        assert res["data"]["total_checks"] == 9
        assert res["data"]["checks_passed"] == 9

    def test_verification_runner_all_9_stages_pass(self) -> None:
        """Verify each of the 9 stages individually passes with factual evidence."""
        res = run_phthalic_anhydride_reactor_verification()
        tests = res["data"]["tests"]
        assert len(tests) == 9
        for t in tests:
            assert t["passed"] is True, f"Stage {t['stage']} failed: {t['details']}"

    def test_verification_runner_json_evidence_export(self, tmp_path: Path) -> None:
        """Verify verification runner exports valid JSON evidence matching strict contract."""
        out_file = tmp_path / "phthalic_evidence.json"
        res = run_phthalic_anhydride_reactor_verification(output_path=out_file)
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W203"
        assert data["data"]["checks_passed"] == 9

    def test_verification_runner_evidence_content_validation(self, tmp_path: Path) -> None:
        """Verify exported JSON content contains registers, coils, and all required keys."""
        out_file = tmp_path / "phthalic_evidence_detail.json"
        run_phthalic_anhydride_reactor_verification(output_path=out_file)

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        reg_map = data["data"]["register_map"]["values"]
        assert "%R1640" in reg_map
        assert "%R1647" in reg_map
        assert "%M382" in reg_map
        assert "%M384" in reg_map
        assert reg_map["%M382"] is True

    def test_verification_runner_aliases(self) -> None:
        """Verify runner function aliases."""
        assert run_pan_reactor_verification is run_phthalic_anhydride_reactor_verification
        assert run_phthalic_anhydride_verification is run_phthalic_anhydride_reactor_verification
        assert run_pan_verification is run_phthalic_anhydride_reactor_verification
        assert run_phthalic_reactor_verification is run_phthalic_anhydride_reactor_verification
        assert run_phthalic_verification is run_phthalic_anhydride_reactor_verification
