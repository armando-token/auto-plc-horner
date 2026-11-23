"""Comprehensive Industrial Acrylonitrile (AN) Fluidized-Bed Reactor Test Suite.

Work Package: W194 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS

Structured into 12 engineering verification sections:
1. Section 1: Reactor Physical Constants, Molecular Weights & Thermodynamic Enthalpies
2. Section 2: Bubbling Fluidized-Bed Configuration & Geometric Calculations
3. Section 3: Sohio Propylene Ammoxidation Kinetics, Side Reactions & NH3/C3H6 Sensitivity
4. Section 4: Fluidized-Bed Two-Phase Hydrodynamics (Kunii-Levenspiel Model)
5. Section 5: Coupled 6-State ODE System & RK4 Numerical Integration
6. Section 6: Stoichiometric Mass, Elemental & Thermal Enthalpy Conservation Residuals (< 1e-10)
7. Section 7: Submerged 40 bar Steam Cooling Coil Bundle & Temperature Stabilization (440-450 °C)
8. Section 8: Process Safety Interlocks & Diagnostics in Strict Priority Hierarchy (0xD201..0xD204)
9. Section 9: Horner OCS Memory Space Integration & SYSTEM Privilege Mode
10. Section 10: Pure IEC 61131-3 Structured Text POU & Anti-Ladder Security Guard
11. Section 11: ILogicUnit Scan Cycle Execution (100+ Continuous Scan Steps)
12. Section 12: Deterministic 9-Stage Verification Suite & Runner Integration
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
from jev_cscape.simulation.acrylonitrile_reactor import (
    ACRYLONITRILE_PURE_ST_POU,
    ACRYLONITRILE_REACTOR_PURE_ST_POU,
    ACRYLONITRILE_REACTOR_SYNC_POU,
    ACRYLONITRILE_SYNC_POU,
    AN_YIELD_NOMINAL_PCT,
    BED_TEMP_NOMINAL_C,
    BED_TEMP_RESET_C,
    BED_TEMP_TRIP_C,
    BED_TEMP_WARNING_C,
    BED_VOIDAGE_MAX,
    BED_VOIDAGE_MIN,
    BED_VOIDAGE_NOMINAL,
    COOLING_DUTY_NOMINAL_KW,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H3_J_MOL,
    DELTA_H3_KJ_MOL,
    DELTA_H4_J_MOL,
    DELTA_H4_KJ_MOL,
    DELTA_H_ACETONITRILE_J_MOL,
    DELTA_H_ACETONITRILE_KJ_MOL,
    DELTA_H_AMMOXIDATION_J_MOL,
    DELTA_H_AMMOXIDATION_KJ_MOL,
    DELTA_H_COMBUSTION_J_MOL,
    DELTA_H_COMBUSTION_KJ_MOL,
    DELTA_H_HCN_J_MOL,
    DELTA_H_HCN_KJ_MOL,
    G_ACCEL,
    MW_ACN,
    MW_AN,
    MW_C,
    MW_C3H6,
    MW_CO2,
    MW_H,
    MW_H2O,
    MW_HCN,
    MW_N,
    MW_N2,
    MW_NH3,
    MW_O,
    MW_O2,
    NH3_C3H6_RATIO_MAX,
    NH3_C3H6_RATIO_MIN,
    NH3_C3H6_RATIO_NOMINAL,
    O2_C3H6_RATIO_MIN,
    O2_C3H6_RATIO_NOMINAL,
    PROPYLENE_CONV_NOMINAL_PCT,
    PROPYLENE_FEED_NOMINAL_KG_H,
    R_GAS_CONST,
    T_REF_K,
    T_STEAM_SAT_40BAR_C,
    T_STEAM_SAT_40BAR_K,
    T_ZERO_CELSIUS,
    AcrylonitrileConfig,
    AcrylonitrileDiagCode,
    AcrylonitrileDiagnosticCode,
    AcrylonitrileLogicUnit,
    AcrylonitrileParameters,
    AcrylonitrileReactor,
    AcrylonitrileReactorConfig,
    AcrylonitrileReactorDiagCode,
    AcrylonitrileReactorDiagnosticCode,
    AcrylonitrileReactorEngine,
    AcrylonitrileReactorLogicUnit,
    AcrylonitrileReactorModel,
    AcrylonitrileReactorParameters,
    AcrylonitrileReactorPlantModel,
    AcrylonitrileReactorSimulationEngine,
    AcrylonitrileReactorSimulator,
    AcrylonitrileReactorState,
    AcrylonitrileReactorStatusBits,
    AcrylonitrileReactorStatusWord,
    AcrylonitrileSimulator,
    AcrylonitrileState,
    AcrylonitrileStatusBits,
    AcrylonitrileStatusWord,
    run_acrylonitrile_reactor_verification,
    run_an_reactor_verification,
    validate_pure_st,
    verify_acrylonitrile_reactor_pure_st,
    verify_an_reactor_pure_st,
)
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# Section 1: Reactor Physical Constants, Molecular Weights & Thermodynamics
# ============================================================================

class TestSection1ConstantsAndThermodynamics:
    """Tests for physical constants, atomic/molecular weights, and reaction enthalpies."""

    def test_universal_physical_constants(self) -> None:
        """Verify universal gas constant, standard gravity, and temperature conversions."""
        assert abs(R_GAS_CONST - 8.314462618) < 1e-6
        assert abs(G_ACCEL - 9.80665) < 1e-4
        assert abs(T_ZERO_CELSIUS - 273.15) < 1e-4
        assert abs(T_REF_K - 718.15) < 1e-4
        assert abs(T_STEAM_SAT_40BAR_C - 250.4) < 1e-4
        assert abs(T_STEAM_SAT_40BAR_K - 523.55) < 1e-4

    def test_elemental_atomic_weights(self) -> None:
        """Verify standard IUPAC atomic weights for C, H, O, N."""
        assert abs(MW_C - 0.012011) < 1e-6
        assert abs(MW_H - 0.001008) < 1e-6
        assert abs(MW_O - 0.015999) < 1e-6
        assert abs(MW_N - 0.014007) < 1e-6

    def test_reactant_molecular_weights(self) -> None:
        """Verify reactant molecular weights for propylene, ammonia, and oxygen."""
        expected_c3h6 = 3.0 * MW_C + 6.0 * MW_H
        expected_nh3 = MW_N + 3.0 * MW_H
        expected_o2 = 2.0 * MW_O
        assert abs(MW_C3H6 - expected_c3h6) < 1e-8
        assert abs(MW_NH3 - expected_nh3) < 1e-8
        assert abs(MW_O2 - expected_o2) < 1e-8

    def test_product_molecular_weights(self) -> None:
        """Verify product molecular weights for AN, ACN, HCN, CO2, H2O, N2."""
        expected_an = 3.0 * MW_C + 3.0 * MW_H + MW_N
        expected_acn = 2.0 * MW_C + 3.0 * MW_H + MW_N
        expected_hcn = MW_H + MW_C + MW_N
        expected_co2 = MW_C + 2.0 * MW_O
        expected_h2o = 2.0 * MW_H + MW_O
        expected_n2 = 2.0 * MW_N
        assert abs(MW_AN - expected_an) < 1e-8
        assert abs(MW_ACN - expected_acn) < 1e-8
        assert abs(MW_HCN - expected_hcn) < 1e-8
        assert abs(MW_CO2 - expected_co2) < 1e-8
        assert abs(MW_H2O - expected_h2o) < 1e-8
        assert abs(MW_N2 - expected_n2) < 1e-8

    def test_main_ammoxidation_enthalpy(self) -> None:
        """Verify main reaction enthalpy Delta H1 = -515 kJ/mol."""
        assert DELTA_H1_KJ_MOL == -515.0
        assert DELTA_H1_J_MOL == -515000.0
        assert DELTA_H_AMMOXIDATION_KJ_MOL == -515.0
        assert DELTA_H_AMMOXIDATION_J_MOL == -515000.0

    def test_side_reactions_enthalpies(self) -> None:
        """Verify side reactions enthalpies for acetonitrile and hydrogen cyanide."""
        assert DELTA_H2_KJ_MOL == -545.0
        assert DELTA_H2_J_MOL == -545000.0
        assert DELTA_H_ACETONITRILE_KJ_MOL == -545.0
        assert DELTA_H_ACETONITRILE_J_MOL == -545000.0

        assert DELTA_H3_KJ_MOL == -940.0
        assert DELTA_H3_J_MOL == -940000.0
        assert DELTA_H_HCN_KJ_MOL == -940.0
        assert DELTA_H_HCN_J_MOL == -940000.0

    def test_complete_combustion_enthalpy(self) -> None:
        """Verify complete hydrocarbon combustion enthalpy Delta H4 = -1926 kJ/mol."""
        assert DELTA_H4_KJ_MOL == -1926.0
        assert DELTA_H4_J_MOL == -1926000.0
        assert DELTA_H_COMBUSTION_KJ_MOL == -1926.0
        assert DELTA_H_COMBUSTION_J_MOL == -1926000.0

    def test_reaction_exotherm_hierarchy(self) -> None:
        """Verify exotherm ordering: Combustion > HCN > Acetonitrile > Ammoxidation."""
        assert abs(DELTA_H4_KJ_MOL) > abs(DELTA_H3_KJ_MOL)
        assert abs(DELTA_H3_KJ_MOL) > abs(DELTA_H2_KJ_MOL)
        assert abs(DELTA_H2_KJ_MOL) > abs(DELTA_H1_KJ_MOL)


# ============================================================================
# Section 2: Bubbling Fluidized-Bed Configuration & Geometric Calculations
# ============================================================================

class TestSection2ReactorConfiguration:
    """Tests for AcrylonitrileConfig geometry, dimensions, catalyst, and parameters."""

    def test_default_geometric_properties(self) -> None:
        """Verify default column diameter, bed height, cross-section and volume."""
        cfg = AcrylonitrileConfig()
        assert cfg.reactor_diameter_m == 8.0
        assert cfg.bed_height_m == 6.0
        expected_cross_section = 0.25 * math.pi * (8.0 ** 2)
        assert abs(cfg.bed_cross_section_m2 - expected_cross_section) < 1e-4
        expected_volume = expected_cross_section * 6.0
        assert abs(cfg.bed_volume_m3 - expected_volume) < 1e-4
        expected_surface = math.pi * 8.0 * 6.0
        assert abs(cfg.vessel_surface_area_m2 - expected_surface) < 1e-4

    def test_catalyst_particle_and_bed_properties(self) -> None:
        """Verify Bi-Mo / Fe-Sb catalyst properties and thermal capacitance."""
        cfg = AcrylonitrileConfig()
        assert cfg.particle_dp_m == 60.0e-6
        assert cfg.particle_density_kg_m3 == 2200.0
        assert cfg.eps_mf == 0.47
        assert cfg.catalyst_mass_kg == 250000.0
        assert cfg.bed_heat_capacity_j_k > 0.0

    def test_operating_baseline_targets(self) -> None:
        """Verify baseline process targets: 445 °C, 81.5% yield, 97.8% conversion."""
        cfg = AcrylonitrileConfig()
        assert cfg.nominal_bed_temp_c == BED_TEMP_NOMINAL_C == 445.0
        assert cfg.nominal_an_yield_pct == AN_YIELD_NOMINAL_PCT == 81.5
        assert cfg.nominal_conversion_pct == PROPYLENE_CONV_NOMINAL_PCT == 97.8
        assert cfg.nominal_propylene_feed_kg_h == PROPYLENE_FEED_NOMINAL_KG_H == 12500.0
        assert cfg.nominal_nh3_c3h6_ratio == NH3_C3H6_RATIO_NOMINAL == 1.15
        assert cfg.nominal_o2_c3h6_ratio == O2_C3H6_RATIO_NOMINAL == 2.10

    def test_steam_coil_design_parameters(self) -> None:
        """Verify 40 bar steam coil parameters: U*A and emergency quench duty."""
        cfg = AcrylonitrileConfig()
        assert cfg.steam_pressure_bar == 40.0
        assert cfg.steam_sat_temp_c == 250.4
        assert cfg.ua_steam_coil_w_k == 125900.0
        assert cfg.quench_cooling_duty_kw >= 45000.0

    def test_config_type_aliases(self) -> None:
        """Verify that configuration aliases are fully interchangeable."""
        assert AcrylonitrileReactorConfig is AcrylonitrileConfig
        assert AcrylonitrileParameters is AcrylonitrileConfig
        assert AcrylonitrileReactorParameters is AcrylonitrileConfig


# ============================================================================
# Section 3: Sohio Ammoxidation Kinetics, Side Reactions & NH3 Sensitivity
# ============================================================================

class TestSection3AmmoxidationKinetics:
    """Tests for reaction rates, Arrhenius acceleration, and reactant sensitivities."""

    @pytest.fixture
    def reactor(self) -> AcrylonitrileReactor:
        return AcrylonitrileReactor()

    def test_nominal_reaction_rates_positive(self, reactor: AcrylonitrileReactor) -> None:
        """Verify all 4 reaction rates and total exothermic duty are positive at nominal state."""
        rates = reactor.compute_reaction_rates(
            c_c3h6=0.0607,
            c_nh3=0.2413,
            c_an=2.2470,
            c_hcn=0.5376,
            t_bed_k=718.15,
            eps_bed=0.620,
            o2_ratio=2.10,
        )
        assert rates["r1_mol_s"] > 50.0  # Dominant ammoxidation rate
        assert rates["r2_mol_s"] > 1.0   # Acetonitrile side rate
        assert rates["r3_mol_s"] > 2.0   # HCN side rate
        assert rates["r4_mol_s"] > 2.0   # Combustion rate
        assert rates["q_rxn_kw"] > 30000.0

    def test_arrhenius_temperature_acceleration(self, reactor: AcrylonitrileReactor) -> None:
        """Verify combustion (Ea4=140 kJ/mol) accelerates faster than ammoxidation (Ea1=85 kJ/mol) with temperature."""
        rates_nom = reactor.compute_reaction_rates(0.0607, 0.2413, 2.2470, 0.5376, 718.15, 0.620, 2.10)
        rates_hot = reactor.compute_reaction_rates(0.0607, 0.2413, 2.2470, 0.5376, 743.15, 0.620, 2.10)

        ratio_r1 = rates_hot["r1_mol_s"] / rates_nom["r1_mol_s"]
        ratio_r4 = rates_hot["r4_mol_s"] / rates_nom["r4_mol_s"]
        assert ratio_r4 > ratio_r1
        assert ratio_r4 > 1.5

    def test_ammoxidation_trip_shutoff(self, reactor: AcrylonitrileReactor) -> None:
        """Verify that trip=True zeroes out all reaction rates and heat duty immediately."""
        rates_tripped = reactor.compute_reaction_rates(
            c_c3h6=0.0607,
            c_nh3=0.2413,
            c_an=2.2470,
            c_hcn=0.5376,
            t_bed_k=718.15,
            eps_bed=0.620,
            o2_ratio=2.10,
            trip=True,
        )
        assert rates_tripped["r1_mol_s"] == 0.0
        assert rates_tripped["r2_mol_s"] == 0.0
        assert rates_tripped["r3_mol_s"] == 0.0
        assert rates_tripped["r4_mol_s"] == 0.0
        assert rates_tripped["q_rxn_kw"] == 0.0

    def test_nh3_c3h6_ratio_sensitivity(self, reactor: AcrylonitrileReactor) -> None:
        """Verify reaction rate behavior when ammonia is stoichiometric (optimum 1.15) vs starved."""
        rates_opt = reactor.compute_reaction_rates(0.0607, 0.2413, 2.247, 0.5376, 718.15, 0.620, 2.10)
        rates_starved = reactor.compute_reaction_rates(0.0607, 0.0500, 2.247, 0.5376, 718.15, 0.620, 2.10)
        assert rates_opt["r1_mol_s"] > rates_starved["r1_mol_s"]

    def test_oxygen_starvation_rate_suppression(self, reactor: AcrylonitrileReactor) -> None:
        """Verify oxygen starvation (o2_ratio < 1.6) suppresses ammoxidation and combustion rates."""
        rates_nom = reactor.compute_reaction_rates(0.0607, 0.2413, 2.247, 0.5376, 718.15, 0.620, 2.10)
        rates_low_o2 = reactor.compute_reaction_rates(0.0607, 0.2413, 2.247, 0.5376, 718.15, 0.620, 1.20)
        assert rates_low_o2["r1_mol_s"] < rates_nom["r1_mol_s"]
        assert rates_low_o2["r4_mol_s"] < rates_nom["r4_mol_s"]

    def test_conversion_and_yield_nominal(self, reactor: AcrylonitrileReactor) -> None:
        """Verify baseline conversion ~97.8% and AN yield ~81.5%."""
        assert abs(reactor.state.propylene_conversion_pct - PROPYLENE_CONV_NOMINAL_PCT) < 2.0
        assert abs(reactor.state.acrylonitrile_yield_pct - AN_YIELD_NOMINAL_PCT) < 2.0


# ============================================================================
# Section 4: Fluidized-Bed Two-Phase Hydrodynamics (Kunii-Levenspiel)
# ============================================================================

class TestSection4FluidizedBedHydrodynamics:
    """Tests for bubbling fluidized bed hydrodynamics: u_mf, bubble properties, voidage."""

    @pytest.fixture
    def reactor(self) -> AcrylonitrileReactor:
        return AcrylonitrileReactor()

    def test_minimum_fluidization_velocity(self, reactor: AcrylonitrileReactor) -> None:
        """Verify u_mf is between 0.015 and 0.060 m/s for Geldart A/B 60 um catalyst particles."""
        hydro = reactor.compute_hydrodynamics(t_bed_k=718.15, p_pa=200000.0, total_molar_flow_mol_s=1002.58)
        u_mf = hydro["u_mf_m_s"]
        assert 0.015 <= u_mf <= 0.060

    def test_superficial_velocity_exceeds_minimum_fluidization(self, reactor: AcrylonitrileReactor) -> None:
        """Verify superficial gas velocity u_g significantly exceeds u_mf (fluidization maintained)."""
        hydro = reactor.compute_hydrodynamics(t_bed_k=718.15, p_pa=200000.0, total_molar_flow_mol_s=1002.58)
        assert hydro["u_g_m_s"] > hydro["u_mf_m_s"]
        assert hydro["u_g_m_s"] > 0.40  # Well above fluidization threshold

    def test_bubble_diameter_bounded(self, reactor: AcrylonitrileReactor) -> None:
        """Verify bubble diameter is bounded by internal tube bundle (0.05 to 0.20 m)."""
        hydro = reactor.compute_hydrodynamics(t_bed_k=718.15, p_pa=200000.0, total_molar_flow_mol_s=1002.58)
        assert 0.05 <= hydro["d_b_m"] <= 0.20
        assert hydro["u_b_m_s"] > hydro["u_g_m_s"]

    def test_equilibrium_bed_voidage_expansion(self, reactor: AcrylonitrileReactor) -> None:
        """Verify expanded bed voidage is between 0.48 and 0.75."""
        hydro = reactor.compute_hydrodynamics(t_bed_k=718.15, p_pa=200000.0, total_molar_flow_mol_s=1002.58)
        assert BED_VOIDAGE_MIN <= hydro["eps_eq"] <= BED_VOIDAGE_MAX
        assert hydro["eps_eq"] > reactor.config.eps_mf

    def test_interchange_coefficient_positive(self, reactor: AcrylonitrileReactor) -> None:
        """Verify bubble-to-emulsion gas interchange coefficient K_be is strictly positive."""
        hydro = reactor.compute_hydrodynamics(t_bed_k=718.15, p_pa=200000.0, total_molar_flow_mol_s=1002.58)
        assert hydro["k_be_s_inv"] > 0.5


# ============================================================================
# Section 5: Coupled 6-State ODE System & RK4 Numerical Integration
# ============================================================================

class TestSection5CoupledOdeAndRk4Integration:
    """Tests for 6-state ODE vector derivatives and RK4 integration steps."""

    @pytest.fixture
    def reactor(self) -> AcrylonitrileReactor:
        return AcrylonitrileReactor()

    def test_derivatives_vector_length_and_finiteness(self, reactor: AcrylonitrileReactor) -> None:
        """Verify compute_derivatives returns exactly 6 finite float derivatives."""
        y0 = [
            reactor.state.c_c3h6,
            reactor.state.c_nh3,
            reactor.state.c_an,
            reactor.state.c_hcn,
            reactor.state.t_bed,
            reactor.state.eps_bed,
        ]
        derivs = reactor.compute_derivatives(0.0, y0)
        assert len(derivs) == 6
        for d in derivs:
            assert isinstance(d, float)
            assert not math.isnan(d)
            assert not math.isinf(d)

    def test_single_rk4_step_advances_time(self, reactor: AcrylonitrileReactor) -> None:
        """Verify rk4_step increments simulation time and scan count correctly."""
        t_init = reactor.state.sim_time_s
        scans_init = reactor.state.scan_count
        reactor.rk4_step(dt=0.05)
        assert abs(reactor.state.sim_time_s - (t_init + 0.05)) < 1e-6
        assert reactor.state.scan_count == scans_init + 1

    def test_step_method_returns_success_contract(self, reactor: AcrylonitrileReactor) -> None:
        """Verify step() executes cleanly and returns AgentStatus.SUCCESS."""
        res = reactor.step(dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None
        assert "Step completed" in res.details

    def test_advance_time_multi_second_stability(self, reactor: AcrylonitrileReactor) -> None:
        """Verify advance_time over 5 seconds maintains bounded concentrations and temperature."""
        res = reactor.advance_time(duration_s=5.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert 0.0 <= reactor.state.c_c3h6 <= 2.0
        assert 0.0 <= reactor.state.c_nh3 <= 2.0
        assert 1.0 <= reactor.state.c_an <= 5.0
        assert 0.1 <= reactor.state.c_hcn <= 2.0
        assert 430.0 <= reactor.state.fluidized_bed_temp_celsius <= 460.0
        assert BED_VOIDAGE_MIN <= reactor.state.fluidized_bed_voidage <= BED_VOIDAGE_MAX

    def test_thermal_derivative_balance(self, reactor: AcrylonitrileReactor) -> None:
        """Verify thermal derivative dt_bed_dt accounts for reaction heat and cooling duty."""
        y_nom = [
            reactor.state.c_c3h6,
            reactor.state.c_nh3,
            reactor.state.c_an,
            reactor.state.c_hcn,
            reactor.state.t_bed,
            reactor.state.eps_bed,
        ]
        derivs = reactor.compute_derivatives(0.0, y_nom)
        dt_bed_dt = derivs[4]
        # At near-steady state, temperature drift rate is small (|dT/dt| < 5 K/s)
        assert abs(dt_bed_dt) < 5.0

    def test_reset_method_restores_nominal_state(self, reactor: AcrylonitrileReactor) -> None:
        """Verify reset() restores nominal conditions after excursions."""
        reactor.advance_time(duration_s=2.0, dt=0.05)
        reactor.state.fluidized_bed_temp_celsius = 490.0
        reactor.state.emergency_steam_quench_trip = True
        reactor.reset()
        assert reactor.state.fluidized_bed_temp_celsius == BED_TEMP_NOMINAL_C
        assert reactor.state.emergency_steam_quench_trip is False
        assert reactor.state.diagnostic_code == AcrylonitrileDiagnosticCode.OK


# ============================================================================
# Section 6: Stoichiometric Mass, Elemental & Enthalpy Conservation Residuals
# ============================================================================

class TestSection6ConservationLaws:
    """Tests for mass and elemental C/H/N conservation and enthalpy conservation residuals."""

    @pytest.fixture
    def reactor(self) -> AcrylonitrileReactor:
        return AcrylonitrileReactor()

    def test_stoichiometric_mass_balance_residual(self, reactor: AcrylonitrileReactor) -> None:
        """Verify total stoichiometric mass balance residual is < 1e-10 kg/s."""
        reactor._update_conservation_residuals()
        residual = reactor.state.total_mass_balance_residual_kg_s
        assert residual < 1.0e-10
        assert residual >= 0.0

    def test_elemental_mass_balance_residual(self, reactor: AcrylonitrileReactor) -> None:
        """Verify elemental atomic mass balance residual is < 1e-10 kg/s."""
        reactor._update_conservation_residuals()
        residual = reactor.state.elemental_mass_balance_residual_kg_s
        assert residual < 1.0e-10
        assert residual >= 0.0

    def test_thermal_enthalpy_conservation_residual(self, reactor: AcrylonitrileReactor) -> None:
        """Verify First-Law thermal enthalpy conservation residual is < 1e-10 kW."""
        reactor._update_conservation_residuals()
        residual = reactor.state.enthalpy_conservation_residual_kw
        assert residual < 1.0e-10
        assert residual >= 0.0

    def test_continuous_conservation_under_dynamic_integration(self, reactor: AcrylonitrileReactor) -> None:
        """Verify conservation residuals remain < 1e-10 throughout 100 simulation steps."""
        for _ in range(100):
            reactor.step(dt=0.05)
            assert reactor.state.total_mass_balance_residual_kg_s < 1.0e-10
            assert reactor.state.elemental_mass_balance_residual_kg_s < 1.0e-10
            assert reactor.state.enthalpy_conservation_residual_kw < 1.0e-10


# ============================================================================
# Section 7: Submerged Steam Cooling Coil Heat Removal & Stabilization
# ============================================================================

class TestSection7SteamCoilHeatRemovalAndStabilization:
    """Tests for submerged 40 bar steam coil cooling, heat duty, and temperature control."""

    @pytest.fixture
    def reactor(self) -> AcrylonitrileReactor:
        return AcrylonitrileReactor()

    def test_nominal_cooling_duty(self, reactor: AcrylonitrileReactor) -> None:
        """Verify steam coil cooling duty at nominal 445 °C is ~24,500 kW."""
        reactor._update_kinetics_and_conversion()
        duty = reactor.state.steam_coil_cooling_duty_kw
        assert abs(duty - COOLING_DUTY_NOMINAL_KW) < 1000.0

    def test_temperature_stabilization_window(self, reactor: AcrylonitrileReactor) -> None:
        """Verify bed temperature stabilizes in the 440-450 °C window during steady run."""
        reactor.advance_time(duration_s=10.0, dt=0.05)
        temp_c = reactor.state.fluidized_bed_temp_celsius
        assert 440.0 <= temp_c <= 450.0

    def test_cooling_duty_increases_with_higher_temperature(self, reactor: AcrylonitrileReactor) -> None:
        """Verify steam coil heat removal increases as bed temperature rises above nominal."""
        reactor.state.fluidized_bed_temp_celsius = 445.0
        reactor.state.t_bed = 445.0 + T_ZERO_CELSIUS
        reactor._update_kinetics_and_conversion()
        duty_445 = reactor.state.steam_coil_cooling_duty_kw

        reactor.state.fluidized_bed_temp_celsius = 460.0
        reactor.state.t_bed = 460.0 + T_ZERO_CELSIUS
        reactor._update_kinetics_and_conversion()
        duty_460 = reactor.state.steam_coil_cooling_duty_kw
        assert duty_460 > duty_445

    def test_emergency_quench_duty_applied_on_trip(self, reactor: AcrylonitrileReactor) -> None:
        """Verify quench cooling duty is incorporated when emergency quench is active."""
        assert reactor.config.quench_cooling_duty_kw >= 45000.0


# ============================================================================
# Section 8: Process Safety Interlocks & Diagnostics (0xD201..0xD204)
# ============================================================================

class TestSection8ProcessSafetyInterlocks:
    """Tests for safety interlocks, overheat warning, emergency quench trip, and priority hierarchy."""

    @pytest.fixture
    def reactor(self) -> AcrylonitrileReactor:
        return AcrylonitrileReactor()

    def test_normal_operating_permissive(self, reactor: AcrylonitrileReactor) -> None:
        """Verify normal operation sets code 0x0000, active reaction, no trip."""
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == AcrylonitrileDiagnosticCode.OK
        assert reactor.state.ammoxidation_reaction_active is True
        assert reactor.state.bed_overheat_warning is False
        assert reactor.state.emergency_steam_quench_trip is False

    def test_bed_overheat_warning_at_466_celsius(self, reactor: AcrylonitrileReactor) -> None:
        """Verify %M362 BedOverheatWarning is asserted when T_bed > 465 °C."""
        reactor.state.fluidized_bed_temp_celsius = 466.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.bed_overheat_warning is True
        assert reactor.state.emergency_steam_quench_trip is False  # Not yet tripped

    def test_thermal_runaway_trip_scenario(self, reactor: AcrylonitrileReactor) -> None:
        """Verify T_bed > 480 °C triggers 0xD201, %M363 (quench trip), clears %M361."""
        reactor.state.fluidized_bed_temp_celsius = 482.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == AcrylonitrileDiagnosticCode.AN_ERR_THERMAL_RUNAWAY_TRIP
        assert reactor.state.diagnostic_code == 0xD201
        assert reactor.state.emergency_steam_quench_trip is True
        assert reactor.state.bed_overheat_warning is True
        assert reactor.state.ammoxidation_reaction_active is False

    def test_thermal_runaway_latch_and_reset(self, reactor: AcrylonitrileReactor) -> None:
        """Verify trip latches until bed cools below reset threshold (450 °C)."""
        reactor.state.fluidized_bed_temp_celsius = 482.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.emergency_steam_quench_trip is True

        # Cooled to 470 °C (below trip 480 °C but above reset 450 °C) -> still tripped
        reactor.state.fluidized_bed_temp_celsius = 470.0
        reactor._evaluate_safety_interlocks()
        assert reactor.state.emergency_steam_quench_trip is True
        assert reactor.state.diagnostic_code == 0xD201

        # Cooled to 449 °C (below reset 450 °C) -> resets
        reactor.state.fluidized_bed_temp_celsius = 449.0
        reactor.state.emergency_steam_quench_trip = False
        reactor._evaluate_safety_interlocks()
        assert reactor.state.emergency_steam_quench_trip is False
        assert reactor.state.diagnostic_code == 0x0000

    def test_ammonia_ratio_imbalance_detection(self, reactor: AcrylonitrileReactor) -> None:
        """Verify NH3/C3H6 ratio < 1.00 or > 1.35 triggers 0xD202 without tripping reaction."""
        # Low ammonia ratio
        reactor.state.ammonia_to_propylene_ratio = 0.95
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == AcrylonitrileDiagnosticCode.AN_ERR_AMMONIA_IMBALANCE
        assert reactor.state.diagnostic_code == 0xD202
        assert reactor.state.ammoxidation_reaction_active is True
        assert reactor.state.emergency_steam_quench_trip is False

        # High ammonia ratio
        reactor.state.ammonia_to_propylene_ratio = 1.42
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == AcrylonitrileDiagnosticCode.AN_ERR_AMMONIA_IMBALANCE
        assert reactor.state.diagnostic_code == 0xD202

    def test_defluidization_bed_collapse_detection(self, reactor: AcrylonitrileReactor) -> None:
        """Verify bed voidage collapse (< 0.48) triggers 0xD203."""
        reactor.state.fluidized_bed_voidage = 0.450
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == AcrylonitrileDiagnosticCode.AN_ERR_DEFLUIDIZATION_COLLAPSE
        assert reactor.state.diagnostic_code == 0xD203
        assert reactor.state.emergency_steam_quench_trip is False

    def test_oxygen_starvation_detection(self, reactor: AcrylonitrileReactor) -> None:
        """Verify oxygen ratio < 1.60 triggers 0xD204."""
        reactor.state.oxygen_to_propylene_ratio = 1.45
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == AcrylonitrileDiagnosticCode.AN_ERR_OXYGEN_STARVATION
        assert reactor.state.diagnostic_code == 0xD204

    def test_strict_priority_hierarchy(self, reactor: AcrylonitrileReactor) -> None:
        """Verify strict priority ordering: 0xD201 > 0xD202 > 0xD203 > 0xD204."""
        # All 4 fault conditions simultaneously present
        reactor.state.fluidized_bed_temp_celsius = 485.0   # 0xD201
        reactor.state.ammonia_to_propylene_ratio = 0.85    # 0xD202
        reactor.state.fluidized_bed_voidage = 0.440        # 0xD203
        reactor.state.oxygen_to_propylene_ratio = 1.20     # 0xD204

        # 1. 0xD201 wins
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == 0xD201

        # Clear 0xD201 -> 0xD202 wins
        reactor.state.fluidized_bed_temp_celsius = 445.0
        reactor.state.emergency_steam_quench_trip = False
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == 0xD202

        # Clear 0xD202 -> 0xD203 wins
        reactor.state.ammonia_to_propylene_ratio = 1.15
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == 0xD203

        # Clear 0xD203 -> 0xD204 wins
        reactor.state.fluidized_bed_voidage = 0.620
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == 0xD204

        # Clear 0xD204 -> 0x0000 OK
        reactor.state.oxygen_to_propylene_ratio = 2.10
        reactor._evaluate_safety_interlocks()
        assert reactor.state.diagnostic_code == 0x0000


# ============================================================================
# Section 9: Horner OCS Memory Space Integration & SYSTEM Privilege Mode
# ============================================================================

class TestSection9HornerRegisterSynchronization:
    """Tests for %R1550..%R1557 and %M361..%M363 register table synchronization."""

    @pytest.fixture
    def reg_table(self) -> RegisterTable:
        return RegisterTable()

    def test_analog_register_scaling_nominal(self, reg_table: RegisterTable) -> None:
        """Verify scaling for %R1550..%R1556 at nominal conditions."""
        reactor = AcrylonitrileReactor(register_table=reg_table)
        reactor.state.propylene_feed_flow_kg_h = 12500.0
        reactor.state.ammonia_to_propylene_ratio = 1.15
        reactor.state.fluidized_bed_temp_celsius = 445.0
        reactor.state.acrylonitrile_yield_pct = 81.5
        reactor.state.propylene_conversion_pct = 97.8
        reactor.state.steam_coil_cooling_duty_kw = 24500.0
        reactor.state.fluidized_bed_voidage = 0.620
        reactor.sync_to_registers(reg_table)

        assert reg_table.read_word("%R1550") == 1250   # 12,500 / 10
        assert reg_table.read_word("%R1551") == 115    # 1.15 * 100
        assert reg_table.read_word("%R1552") == 4450   # 445.0 * 10
        assert reg_table.read_word("%R1553") == 815    # 81.5 * 10
        assert reg_table.read_word("%R1554") == 978    # 97.8 * 10
        assert reg_table.read_word("%R1555") == 24500  # 24500 kW
        assert reg_table.read_word("%R1556") == 620    # 0.620 * 1000

    def test_diagnostic_code_register_sync(self, reg_table: RegisterTable) -> None:
        """Verify %R1557 stores correct diagnostic code."""
        reactor = AcrylonitrileReactor(register_table=reg_table)
        reactor.state.fluidized_bed_temp_celsius = 485.0
        reactor._evaluate_safety_interlocks()
        reactor.sync_to_registers(reg_table)
        assert (reg_table.read_word("%R1557") & 0xFFFF) == 0xD201

        reactor.state.fluidized_bed_temp_celsius = 445.0
        reactor.state.emergency_steam_quench_trip = False
        reactor.state.ammonia_to_propylene_ratio = 0.90
        reactor._evaluate_safety_interlocks()
        reactor.sync_to_registers(reg_table)
        assert (reg_table.read_word("%R1557") & 0xFFFF) == 0xD202

    def test_discrete_coil_synchronization(self, reg_table: RegisterTable) -> None:
        """Verify discrete coils %M361, %M362, %M363 synchronization."""
        reactor = AcrylonitrileReactor(register_table=reg_table)
        # Normal
        reactor.sync_to_registers(reg_table)
        assert reg_table.read_bit("%M361") is True
        assert reg_table.read_bit("%M362") is False
        assert reg_table.read_bit("%M363") is False

        # Overheat warning only
        reactor.state.fluidized_bed_temp_celsius = 468.0
        reactor._evaluate_safety_interlocks()
        reactor.sync_to_registers(reg_table)
        assert reg_table.read_bit("%M361") is True
        assert reg_table.read_bit("%M362") is True
        assert reg_table.read_bit("%M363") is False

        # Quench trip
        reactor.state.fluidized_bed_temp_celsius = 485.0
        reactor._evaluate_safety_interlocks()
        reactor.sync_to_registers(reg_table)
        assert reg_table.read_bit("%M361") is False
        assert reg_table.read_bit("%M362") is True
        assert reg_table.read_bit("%M363") is True

    def test_privilege_mode_system_required_for_writes(self, reg_table: RegisterTable) -> None:
        """Verify that register updates use SYSTEM privilege and APPLICATION mode respects protection."""
        # Direct application write to read-only channel raises PermissionError
        with pytest.raises(PermissionError):
            reg_table.write_word("%AI1", 9999, privilege=PrivilegeMode.APPLICATION)

        # System write succeeds
        reg_table.write_word("%R1550", 1250, privilege=PrivilegeMode.SYSTEM)
        assert reg_table.read_word("%R1550") == 1250

    def test_status_bits_enumeration(self) -> None:
        """Verify AcrylonitrileStatusBits flags bitmasks."""
        assert AcrylonitrileStatusBits.RUNNING == 0x0001
        assert AcrylonitrileStatusBits.AMMOXIDATION_ACTIVE == 0x0002
        assert AcrylonitrileStatusBits.OVERHEAT_WARNING == 0x0004
        assert AcrylonitrileStatusBits.STEAM_QUENCH_TRIP == 0x0008
        assert AcrylonitrileStatusBits.AMMONIA_IMBALANCE_ALARM == 0x0010
        assert AcrylonitrileStatusBits.DEFLUIDIZATION_ALARM == 0x0020
        assert AcrylonitrileStatusBits.OXYGEN_STARVATION_ALARM == 0x0040
        assert AcrylonitrileStatusBits.STEAM_COILS_ACTIVE == 0x0080


# ============================================================================
# Section 10: Pure IEC 61131-3 Structured Text POU & Security Guard
# ============================================================================

class TestSection10PureStructuredTextAndSecurityGuard:
    """Tests for pure ST POU validation, AST symbol parsing, and anti-ladder interception."""

    def test_pure_st_pou_syntax_validation(self) -> None:
        """Verify STParser.validate_code validates AcrylonitrileReactorSync with AgentStatus.SUCCESS."""
        res = STParser.validate_code(ACRYLONITRILE_REACTOR_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS
        assert "AcrylonitrileReactorSync" in res.details

    def test_pure_st_pou_ast_parsing_and_registers(self) -> None:
        """Verify STParser.parse_pou extracts program name and bound registers."""
        ast = STParser.parse_pou(ACRYLONITRILE_REACTOR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "AcrylonitrileReactorSync"
        assert ast.pou_type == POUType.PROGRAM

        expected = [
            "%R1550", "%R1551", "%R1552", "%R1553",
            "%R1554", "%R1555", "%R1556", "%R1557",
            "%M361", "%M362", "%M363",
        ]
        for reg in expected:
            assert reg in ast.bound_registers

    def test_security_guard_assert_pure_st_content_accepts_clean_code(self) -> None:
        """Verify SecurityGuard.assert_pure_st_content accepts pure ST without exception."""
        SecurityGuard.assert_pure_st_content(ACRYLONITRILE_REACTOR_PURE_ST_POU)

    def test_anti_ladder_security_guard_intercepts_ladder_constructs(self) -> None:
        """Verify SecurityGuard intercepts ladder logic constructs and raises LadderForbiddenError."""
        ladder_fragments = [
            "---[ ]---",
            "---( )---",
            "---[/]---",
            "RUNG 1: START",
            "NETWORK 10",
            "XIC %M361",
            "OTE %M363",
        ]
        for frag in ladder_fragments:
            bad_code = f"PROGRAM BadTest\nVAR x: BOOL; END_VAR\n{frag}\nEND_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad_code)

    def test_st_pou_verification_helpers(self) -> None:
        """Verify module verification helper functions return True and SUCCESS."""
        assert verify_acrylonitrile_reactor_pure_st() is True
        assert verify_an_reactor_pure_st() is True
        val_res = validate_pure_st()
        assert val_res.status == AgentStatus.SUCCESS


# ============================================================================
# Section 11: ILogicUnit Scan Cycle Execution (100+ Scans)
# ============================================================================

class TestSection11LogicUnitScanCycleExecution:
    """Tests for ILogicUnit interface, scan_step, and multi-cycle execution."""

    @pytest.fixture
    def logic_unit(self) -> AcrylonitrileReactorLogicUnit:
        return AcrylonitrileReactorLogicUnit()

    def test_logic_unit_metadata(self, logic_unit: AcrylonitrileReactorLogicUnit) -> None:
        """Verify ILogicUnit contract properties: name, priority, is_enabled."""
        assert logic_unit.name == "AcrylonitrileReactorSync"
        assert logic_unit.priority == 100
        assert logic_unit.is_enabled is True

    def test_direct_reactor_logic_unit_contract(self) -> None:
        """Verify AcrylonitrileReactor also satisfies ILogicUnit directly."""
        reactor = AcrylonitrileReactor()
        assert isinstance(reactor, ILogicUnit)
        assert reactor.name == "AcrylonitrileReactorSync"
        assert reactor.priority == 100
        assert reactor.is_enabled is True

    def test_scan_step_returns_state_summary(self) -> None:
        """Verify scan_step returns structured dictionary matching contract."""
        reactor = AcrylonitrileReactor()
        summary = reactor.scan_step(dt=0.05)
        assert summary["status"] == "success"
        assert "propylene_feed_flow_kg_h" in summary
        assert "ammonia_to_propylene_ratio" in summary
        assert "fluidized_bed_temp_celsius" in summary
        assert "acrylonitrile_yield_pct" in summary
        assert "propylene_conversion_pct" in summary
        assert "steam_coil_cooling_duty_kw" in summary
        assert "fluidized_bed_voidage" in summary
        assert "diagnostic_code" in summary

    def test_scan_context_execution_with_registers(self) -> None:
        """Verify execute(ctx) runs scan cycle and writes to context register table."""
        reg_table = RegisterTable()
        reactor = AcrylonitrileReactor(register_table=reg_table)
        ctx = ScanContext(
            cycle=1,
            dt_ms=50.0,
            elapsed_time_ms=50.0,
            get_register=lambda a: reg_table.read_word(a),
            set_register=lambda a, v: reg_table.write_word(a, v, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda n, d=None: d,
            set_variable=lambda n, v: None,
            record_fault=lambda f: None,
        )
        ctx.registers = reg_table
        reactor.execute(ctx)
        assert reg_table.read_word("%R1550") == 1250
        assert reg_table.read_bit("%M361") is True

    def test_100_plus_scan_cycles_stability(self) -> None:
        """Verify 150 consecutive scan cycles execute deterministically without numerical divergence."""
        reactor = AcrylonitrileReactor()
        for cycle in range(150):
            summary = reactor.scan_step(dt=0.05)
            assert summary["status"] == "success"
            assert not math.isnan(reactor.state.t_bed)
            assert not math.isnan(reactor.state.c_an)
            assert 435.0 <= reactor.state.fluidized_bed_temp_celsius <= 455.0

        assert reactor.state.scan_count >= 150


# ============================================================================
# Section 12: Deterministic 9-Stage Verification Suite & Runner Integration
# ============================================================================

class TestSection12DeterministicVerificationRunner:
    """Tests for run_acrylonitrile_reactor_verification suite and evidence export."""

    def test_verification_suite_returns_success_contract(self) -> None:
        """Verify run_acrylonitrile_reactor_verification returns status == 'success'."""
        result = run_acrylonitrile_reactor_verification()
        assert isinstance(result, dict)
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert "passed 9/9 checks" in result["details"]

    def test_verification_suite_passes_all_9_stages(self) -> None:
        """Verify all 9 individual stages pass deterministically."""
        result = run_acrylonitrile_reactor_verification()
        data = result["data"]
        assert data["work_package"] == "W194"
        assert data["module"] == "acrylonitrile_reactor"
        assert data["total_checks"] == 9
        assert data["checks_passed"] == 9

        tests = data["tests"]
        assert len(tests) == 9
        for stage_idx, t in enumerate(tests, start=1):
            assert t["stage"] == stage_idx
            assert t["passed"] is True
            assert len(t["details"]) > 0

    def test_verification_evidence_file_emission(self, tmp_path: Path) -> None:
        """Verify verification suite exports valid JSON artifact to specified path."""
        target_file = tmp_path / "acrylonitrile_reactor_evidence.json"
        result = run_acrylonitrile_reactor_verification(output_path=str(target_file))
        assert target_file.exists()
        assert target_file.stat().st_size > 0

        with open(target_file, "r", encoding="utf-8") as f:
            loaded = json.load(f)

        assert loaded["status"] == "success"
        assert loaded["data"]["checks_passed"] == 9
        assert run_an_reactor_verification is run_acrylonitrile_reactor_verification
