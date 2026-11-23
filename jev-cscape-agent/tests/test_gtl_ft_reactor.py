"""Unit and Integration Tests for Industrial Gas-to-Liquids (GTL) Slurry Bubble Column Fischer-Tropsch Reactor ODE Simulation.

Work Package: W188 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Reactor configuration, geometry, and universal physical/chemical constants.
2. Section 2: SBCR three-phase hydrodynamics: gas holdup, superficial velocity, bubble diameter, liquid recirculation.
3. Section 3: Gas-liquid mass transfer rates (kLa_H2, kLa_CO) and Henry's law solubilities.
4. Section 4: Anderson-Schulz-Flory (ASF) polymerization distribution math and chain growth alpha factor.
5. Section 5: Coupled 6-state ODE vector derivatives and RK4 integration steps.
6. Section 6: Dual stoichiometric mass (< 1e-10) and enthalpy (< 1e-10) conservation residuals.
7. Section 7: Cooling jacket heat transfer, boiling water steam generation, and thermal runaway trip (> 245 °C).
8. Section 8: H2/CO ratio imbalance detection (ratio < 1.70 or > 2.30), catalyst deactivation (a_cat < 0.70), and gas holdup anomalies.
9. Section 9: Pure ST POU 'GtlFtSlurryReactorSync' AST parsing, symbol binding, and anti-ladder security guard.
10. Section 10: Horner OCS register space synchronization (%R1490..%R1497, %M347..%M349) with PrivilegeMode.SYSTEM, and ILogicUnit scan cycle (100+ steps).
11. Section 11: Deterministic 9-stage verification suite integration test returning strict 4-state contract JSON.
12. Section 12: Edge cases, bounds clamping, and status word bitmask consistency.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext, SimulationEngine
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.gtl_ft_reactor import (
    ASF_ALPHA_MAX,
    ASF_ALPHA_MIN,
    ASF_ALPHA_NOMINAL,
    CATALYST_ACTIVITY_ALARM_THRESHOLD,
    CATALYST_ACTIVITY_NOMINAL,
    CO_CONVERSION_NOMINAL_PCT,
    DELTA_H_FT_J_MOL,
    DELTA_H_FT_KJ_MOL,
    DELTA_H_RXN_CO_J_MOL,
    DELTA_H_RXN_CO_KJ_MOL,
    DELTA_H_RXN_J_MOL,
    DELTA_H_RXN_KJ_MOL,
    FT_REACTOR_PURE_ST_POU,
    FT_REACTOR_SYNC_POU,
    GAS_HOLDUP_MAX,
    GAS_HOLDUP_MIN,
    GAS_HOLDUP_NOMINAL,
    GTL_FT_REACTOR_DYNAMICS_SYNC_POU,
    GTL_FT_REACTOR_PURE_ST_POU,
    GTL_FT_REACTOR_SYNC_POU,
    GTL_FT_SLURRY_REACTOR_PURE_ST_POU,
    GTL_FT_SLURRY_REACTOR_SYNC_POU,
    G_ACCEL,
    INTERNAL_COOLING_DUTY_NOMINAL_KW,
    MW_C28H58,
    MW_CARBON,
    MW_CH4,
    MW_CO,
    MW_H2,
    MW_H2O,
    MW_HEAVY_WAX,
    MW_WAX_AVG,
    REACTOR_PRESSURE_MAX_BAR,
    REACTOR_PRESSURE_MIN_BAR,
    REACTOR_PRESSURE_NOMINAL_BAR,
    REACTOR_TEMP_NOMINAL_C,
    REACTOR_TEMP_TRIP_C,
    REACTOR_TEMP_WARNING_C,
    R_GAS_CONST,
    SBCR_FT_REACTOR_PURE_ST_POU,
    SBCR_FT_REACTOR_SYNC_POU,
    SUPERFICIAL_GAS_VELOCITY_MAX_MPS,
    SUPERFICIAL_GAS_VELOCITY_MIN_MPS,
    SUPERFICIAL_GAS_VELOCITY_NOMINAL_MPS,
    SYNGAS_H2_CO_RATIO_MAX,
    SYNGAS_H2_CO_RATIO_MIN,
    SYNGAS_H2_CO_RATIO_NOMINAL,
    T_REF_K,
    T_ZERO_CELSIUS,
    FtReactorConfig,
    FtReactorDiagCode,
    FtReactorDiagnosticCode,
    FtReactorEngine,
    FtReactorLogicUnit,
    FtReactorModel,
    FtReactorParameters,
    FtReactorSimulator,
    FtReactorState,
    FtReactorStatusBits,
    FtReactorStatusWord,
    GtlFtReactorConfig,
    GtlFtReactorDiagCode,
    GtlFtReactorDiagnosticCode,
    GtlFtReactorEngine,
    GtlFtReactorLogicUnit,
    GtlFtReactorModel,
    GtlFtReactorParameters,
    GtlFtReactorSimulationEngine,
    GtlFtReactorSimulator,
    GtlFtReactorState,
    GtlFtReactorStatusBits,
    GtlFtReactorStatusWord,
    GtlFtSlurryReactor,
    GtlFtSlurryReactorConfig,
    GtlFtSlurryReactorDiagCode,
    GtlFtSlurryReactorDiagnosticCode,
    GtlFtSlurryReactorEngine,
    GtlFtSlurryReactorLogicUnit,
    GtlFtSlurryReactorModel,
    GtlFtSlurryReactorParameters,
    GtlFtSlurryReactorPlantModel,
    GtlFtSlurryReactorSimulationEngine,
    GtlFtSlurryReactorSimulator,
    GtlFtSlurryReactorState,
    GtlFtSlurryReactorStatusBits,
    GtlFtSlurryReactorStatusWord,
    SbcrFtReactorConfig,
    SbcrFtReactorDiagCode,
    SbcrFtReactorDiagnosticCode,
    SbcrFtReactorEngine,
    SbcrFtReactorLogicUnit,
    SbcrFtReactorModel,
    SbcrFtReactorParameters,
    SbcrFtReactorSimulator,
    SbcrFtReactorState,
    SbcrFtReactorStatusBits,
    SbcrFtReactorStatusWord,
    run_ft_reactor_verification,
    run_gtl_ft_reactor_verification,
    run_gtl_ft_slurry_reactor_verification,
    run_sbcr_ft_reactor_verification,
    validate_pure_st,
    verify_gtl_ft_reactor_pure_st,
    verify_gtl_ft_slurry_reactor_pure_st,
    verify_sbcr_ft_reactor_pure_st,
)


# ============================================================================
# 1. Section 1: Reactor Configuration, Physical & Chemical Constants
# ============================================================================

class TestSection1ReactorConfigAndConstants:
    """Tests for physical constants, molecular weights, reaction enthalpies, and SBCR configuration."""

    def test_physical_and_thermodynamic_constants(self) -> None:
        """Verify universal physical constants."""
        assert abs(R_GAS_CONST - 8.314462618) < 1e-6
        assert abs(G_ACCEL - 9.80665) < 1e-4
        assert abs(T_ZERO_CELSIUS - 273.15) < 1e-4
        assert abs(T_REF_K - 298.15) < 1e-4

    def test_molecular_weight_constants(self) -> None:
        """Verify molecular weights for syngas, water, and Fischer-Tropsch wax products."""
        assert abs(MW_H2 - 0.00201588) < 1e-6
        assert abs(MW_CO - 0.028010) < 1e-5
        assert abs(MW_H2O - 0.01801528) < 1e-5
        assert abs(MW_CARBON - 0.012011) < 1e-5
        assert abs(MW_CH4 - 0.016043) < 1e-5
        assert abs(MW_WAX_AVG - 0.394800) < 1e-5
        assert MW_C28H58 == MW_WAX_AVG
        assert MW_HEAVY_WAX == MW_WAX_AVG

    def test_reaction_enthalpy_constants(self) -> None:
        """Verify high exothermicity FT reaction heat: Delta H_rxn = -165 kJ/mol CO."""
        assert DELTA_H_FT_KJ_MOL == -165.0
        assert DELTA_H_FT_J_MOL == -165000.0
        assert DELTA_H_RXN_CO_KJ_MOL == -165.0
        assert DELTA_H_RXN_CO_J_MOL == -165000.0
        assert DELTA_H_RXN_KJ_MOL == -165.0
        assert DELTA_H_RXN_J_MOL == -165000.0

    def test_nominal_operating_limits(self) -> None:
        """Verify operating limits, warning/trip temperatures, and pressures."""
        assert SYNGAS_H2_CO_RATIO_NOMINAL == 2.05
        assert SYNGAS_H2_CO_RATIO_MIN == 1.70
        assert SYNGAS_H2_CO_RATIO_MAX == 2.30

        assert REACTOR_TEMP_NOMINAL_C == 225.0
        assert REACTOR_TEMP_WARNING_C == 235.0
        assert REACTOR_TEMP_TRIP_C == 245.0

        assert REACTOR_PRESSURE_NOMINAL_BAR == 25.0
        assert REACTOR_PRESSURE_MIN_BAR == 18.0
        assert REACTOR_PRESSURE_MAX_BAR == 32.0

        assert CO_CONVERSION_NOMINAL_PCT == 68.5
        assert ASF_ALPHA_NOMINAL == 0.915
        assert ASF_ALPHA_MIN == 0.880
        assert ASF_ALPHA_MAX == 0.940

        assert INTERNAL_COOLING_DUTY_NOMINAL_KW == 18500.0
        assert SUPERFICIAL_GAS_VELOCITY_NOMINAL_MPS == 0.18
        assert SUPERFICIAL_GAS_VELOCITY_MIN_MPS == 0.05
        assert SUPERFICIAL_GAS_VELOCITY_MAX_MPS == 0.35

        assert GAS_HOLDUP_NOMINAL == 0.28
        assert GAS_HOLDUP_MIN == 0.12
        assert GAS_HOLDUP_MAX == 0.38

        assert CATALYST_ACTIVITY_NOMINAL == 1.00
        assert CATALYST_ACTIVITY_ALARM_THRESHOLD == 0.70

    def test_reactor_config_defaults_and_geometry(self) -> None:
        """Verify SBCR column geometric properties and alias compatibility."""
        config = GtlFtReactorConfig()
        assert config.column_diameter_m == 6.0
        assert config.active_height_m == 30.0

        expected_area = 0.25 * math.pi * (6.0 ** 2)
        assert abs(config.column_cross_sectional_area_m2 - expected_area) < 1e-6
        assert abs(config.total_column_volume_m3 - (expected_area * 30.0)) < 1e-6
        assert abs(config.wall_surface_area_m2 - (math.pi * 6.0 * 30.0)) < 1e-6

        # Check aliases
        assert GtlFtSlurryReactorConfig is GtlFtReactorConfig
        assert GtlFtReactorParameters is GtlFtReactorConfig
        assert SbcrFtReactorConfig is GtlFtReactorConfig
        assert FtReactorConfig is GtlFtReactorConfig


# ============================================================================
# 2. Section 2: SBCR Three-Phase Hydrodynamics
# ============================================================================

class TestSection2SBCRThreePhaseHydrodynamics:
    """Tests for SBCR three-phase hydrodynamics: gas holdup, superficial velocity, bubble dynamics."""

    def test_gas_holdup_calculation_zuber_findlay(self) -> None:
        """Verify Zuber-Findlay drift flux gas holdup formulation."""
        sim = GtlFtSlurryReactor()
        # Nominal: Ug = 0.18 m/s, P = 25.0 bar, T = 498.15 K
        hydro = sim.compute_hydrodynamics(u_g=0.18, p_bar=25.0, t_k=498.15)
        eps_g = hydro["epsilon_g"]

        # Expected: Ug / (1.15 * Ug + 0.45) = 0.18 / (1.15*0.18 + 0.45) = 0.18 / 0.657 = ~0.274
        assert 0.25 <= eps_g <= 0.30

    def test_three_phase_holdup_conservation(self) -> None:
        """Verify gas, liquid, and solid volume fractions sum to 1.0."""
        sim = GtlFtSlurryReactor()
        hydro = sim.compute_hydrodynamics(u_g=0.18, p_bar=25.0, t_k=498.15, eps_s=0.10)
        total_holdup = hydro["epsilon_g"] + hydro["epsilon_l"] + hydro["epsilon_s"]
        assert abs(total_holdup - 1.0) < 1e-9

    def test_superficial_velocity_variation_and_bounds(self) -> None:
        """Verify gas holdup increases monotonically with superficial velocity."""
        sim = GtlFtSlurryReactor()
        h_low = sim.compute_hydrodynamics(u_g=0.08, p_bar=25.0, t_k=498.15)
        h_mid = sim.compute_hydrodynamics(u_g=0.18, p_bar=25.0, t_k=498.15)
        h_high = sim.compute_hydrodynamics(u_g=0.30, p_bar=25.0, t_k=498.15)

        assert h_low["epsilon_g"] < h_mid["epsilon_g"] < h_high["epsilon_g"]
        assert h_low["epsilon_l"] > h_mid["epsilon_l"] > h_high["epsilon_l"]

    def test_bubble_dynamics_and_slip_velocity(self) -> None:
        """Verify drift flux parameters C0 and V_slip are configured correctly."""
        config = GtlFtReactorConfig()
        assert config.zuber_c0 == 1.15
        assert config.v_slip_bubble_m_s == 0.45

    def test_liquid_recirculation_and_slurry_loading(self) -> None:
        """Verify slurry density and catalyst loading parameters."""
        config = GtlFtReactorConfig()
        assert config.catalyst_particle_density_kg_m3 == 2400.0
        assert config.liquid_wax_density_kg_m3 == 750.0
        assert config.solid_holdup_epsilon_s == 0.10
        assert config.slurry_specific_heat_j_kg_k == 2200.0


# ============================================================================
# 3. Section 3: Gas-Liquid Mass Transfer Rates
# ============================================================================

class TestSection3GasLiquidMassTransferRates:
    """Tests for volumetric mass transfer rates (kLa_CO, kLa_H2) and Henry's law solubilities."""

    def test_kla_co_and_kla_h2_rates(self) -> None:
        """Verify nominal kLa rates are within expected SBCR physical range."""
        sim = GtlFtSlurryReactor()
        hydro = sim.compute_hydrodynamics(u_g=0.18, p_bar=25.0, t_k=498.15)
        assert 0.025 <= hydro["kla_co"] <= 0.040
        assert 0.035 <= hydro["kla_h2"] <= 0.055

    def test_h2_diffusivity_ratio_scaling(self) -> None:
        """Verify kLa_H2 is strictly higher than kLa_CO due to higher molecular diffusivity."""
        sim = GtlFtSlurryReactor()
        hydro = sim.compute_hydrodynamics(u_g=0.18, p_bar=25.0, t_k=498.15)
        ratio = hydro["kla_h2"] / hydro["kla_co"]
        assert abs(ratio - sim.config.diffusivity_ratio_h2_co) < 1e-6
        assert ratio == 1.35

    def test_kla_pressure_and_velocity_dependence(self) -> None:
        """Verify mass transfer coefficient increases with pressure and gas velocity."""
        sim = GtlFtSlurryReactor()
        h1 = sim.compute_hydrodynamics(u_g=0.15, p_bar=20.0, t_k=498.15)
        h2 = sim.compute_hydrodynamics(u_g=0.22, p_bar=28.0, t_k=498.15)
        assert h2["kla_co"] > h1["kla_co"]
        assert h2["kla_h2"] > h1["kla_h2"]

    def test_henrys_law_saturation_concentrations(self) -> None:
        """Verify Henry's law saturation concentrations in molten wax."""
        sim = GtlFtSlurryReactor()
        hydro = sim.compute_hydrodynamics(u_g=0.18, p_bar=25.0, t_k=498.15)
        # Check positive saturation values
        assert hydro["c_h2_sat"] > 40.0
        assert hydro["c_co_sat"] > 15.0
        assert hydro["p_h2_bar"] > hydro["p_co_bar"]  # Since H2/CO ratio is ~2.05

    def test_syngas_dissolution_driving_forces(self) -> None:
        """Verify gas-liquid driving force (C_sat - C_liquid) is positive under nominal operation."""
        sim = GtlFtSlurryReactor()
        hydro = sim.compute_hydrodynamics(u_g=0.18, p_bar=25.0, t_k=498.15)
        c_h2_drive = hydro["c_h2_sat"] - sim.state.c_h2
        c_co_drive = hydro["c_co_sat"] - sim.state.c_co
        assert c_h2_drive > 0.0
        assert c_co_drive > 0.0


# ============================================================================
# 4. Section 4: Anderson-Schulz-Flory (ASF) Polymerization Distribution
# ============================================================================

class TestSection4AndersonSchulzFloryPolymerization:
    """Tests for Anderson-Schulz-Flory (ASF) distribution math and alpha chain growth factor."""

    def test_asf_distribution_fractions_sum_to_one(self) -> None:
        """Verify sum of product weight fractions sums identically to 1.0."""
        sim = GtlFtSlurryReactor()
        for alpha in [0.88, 0.90, 0.915, 0.93, 0.94]:
            asf = sim.compute_asf_distribution(alpha)
            total = (
                asf["w_methane"]
                + asf["w_c2_c4"]
                + asf["w_naphtha"]
                + asf["w_diesel"]
                + asf["w_wax"]
            )
            assert abs(total - 1.0) < 1e-12

    def test_asf_alpha_chain_growth_sensitivity(self) -> None:
        """Verify heavy wax (C20+) selectivity increases monotonically with alpha."""
        sim = GtlFtSlurryReactor()
        asf_low = sim.compute_asf_distribution(0.880)
        asf_mid = sim.compute_asf_distribution(0.915)
        asf_high = sim.compute_asf_distribution(0.940)

        assert asf_low["w_wax"] < asf_mid["w_wax"] < asf_high["w_wax"]
        # Nominal wax selectivity is ~48 wt%
        assert 0.45 <= asf_mid["w_wax"] <= 0.55

    def test_asf_methane_selectivity_inversely_related(self) -> None:
        """Verify methane (C1) selectivity decreases monotonically as alpha increases."""
        sim = GtlFtSlurryReactor()
        asf_low = sim.compute_asf_distribution(0.880)
        asf_mid = sim.compute_asf_distribution(0.915)
        asf_high = sim.compute_asf_distribution(0.940)

        assert asf_low["w_methane"] > asf_mid["w_methane"] > asf_high["w_methane"]
        # C1 weight fraction: (1 - alpha)^2 = (1 - 0.915)^2 = 0.085^2 = 0.007225 (~0.72%)
        assert abs(asf_mid["w_methane"] - 0.007225) < 1e-4

    def test_asf_average_carbon_number_formula(self) -> None:
        """Verify n_avg = 1 / (1 - alpha)."""
        sim = GtlFtSlurryReactor()
        asf = sim.compute_asf_distribution(0.915)
        expected_n = 1.0 / (1.0 - 0.915)  # 1 / 0.085 = 11.7647
        assert abs(asf["n_avg"] - expected_n) < 1e-6

    def test_asf_stoichiometric_usage_ratio_formula(self) -> None:
        """Verify stoichiometric usage ratio U_R = 2 + (1 - alpha)."""
        sim = GtlFtSlurryReactor()
        asf = sim.compute_asf_distribution(0.915)
        expected_ur = 2.0 + (1.0 - 0.915)  # 2.085
        assert abs(asf["stoichiometric_h2_co_ratio"] - expected_ur) < 1e-6


# ============================================================================
# 5. Section 5: Coupled 6-State ODE System & RK4 Solver
# ============================================================================

class TestSection5CoupledSixStateODEAndRK4Solver:
    """Tests for coupled 6-state ODE vector derivatives and Runge-Kutta 4th order numerical integration."""

    def test_compute_derivatives_finite_values(self) -> None:
        """Verify derivatives vector contains 6 finite float values."""
        sim = GtlFtSlurryReactor()
        y = [
            sim.state.c_h2,
            sim.state.c_co,
            sim.state.c_wax,
            sim.state.c_h2o,
            sim.state.t_r,
            sim.state.a_cat,
        ]
        derivs = sim.compute_derivatives(0.0, y)
        assert len(derivs) == 6
        for d in derivs:
            assert not math.isnan(d)
            assert not math.isinf(d)

    def test_single_rk4_step_execution(self) -> None:
        """Verify single rk4_step advances simulation time and updates state."""
        sim = GtlFtSlurryReactor()
        t0 = sim.state.sim_time_s
        cnt0 = sim.state.scan_count
        sim.rk4_step(dt=0.05)
        assert abs(sim.state.sim_time_s - (t0 + 0.05)) < 1e-6
        assert sim.state.scan_count == cnt0 + 1

    def test_advance_time_multi_step_trajectory(self) -> None:
        """Verify advance_time runs multiple RK4 steps smoothly."""
        sim = GtlFtSlurryReactor()
        res = sim.advance_time(duration_s=2.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert abs(sim.state.sim_time_s - 2.0) < 1e-5
        assert sim.state.scan_count == 40

    def test_rk4_numerical_stability_different_time_steps(self) -> None:
        """Verify numerical stability across varying integration step sizes dt."""
        for dt_step in [0.01, 0.05, 0.10]:
            sim = GtlFtSlurryReactor()
            res = sim.advance_time(duration_s=1.0, dt=dt_step)
            assert res.status == AgentStatus.SUCCESS
            assert not math.isnan(sim.state.t_r)
            assert not math.isnan(sim.state.c_wax)
            assert 220.0 <= sim.state.reactor_temperature_celsius <= 230.0

    def test_simulator_reset_functionality(self) -> None:
        """Verify reset restores default initial state and counters."""
        sim = GtlFtSlurryReactor()
        sim.advance_time(duration_s=3.0, dt=0.05)
        assert sim.state.sim_time_s > 0.0
        assert sim.state.scan_count > 0

        sim.reset()
        assert sim.state.sim_time_s == 0.0
        assert sim.state.scan_count == 0
        assert abs(sim.state.reactor_temperature_celsius - REACTOR_TEMP_NOMINAL_C) < 1e-4


# ============================================================================
# 6. Section 6: Stoichiometric Mass & Enthalpy Conservation Residuals
# ============================================================================

class TestSection6StoichiometricConservationResiduals:
    """Tests for total mass, elemental carbon/hydrogen, and first-law enthalpy conservation residuals (< 1e-10)."""

    def test_total_mass_balance_residual_strictly_bounded(self) -> None:
        """Verify total mass balance residual is < 1e-10 kg/s."""
        sim = GtlFtSlurryReactor()
        sim.step(dt=0.05)
        assert sim.state.total_mass_balance_residual_kg_s < 1e-10

    def test_elemental_carbon_hydrogen_residual_strictly_bounded(self) -> None:
        """Verify elemental C/H conservation residual is < 1e-10 kg/s."""
        sim = GtlFtSlurryReactor()
        sim.step(dt=0.05)
        assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10

    def test_enthalpy_conservation_residual_strictly_bounded(self) -> None:
        """Verify enthalpy conservation residual is < 1e-10 kW."""
        sim = GtlFtSlurryReactor()
        sim.step(dt=0.05)
        assert sim.state.enthalpy_conservation_residual_kw < 1e-10

    def test_conservation_residuals_maintained_during_long_run(self) -> None:
        """Verify all conservation residuals remain < 1e-10 across 100 simulation cycles."""
        sim = GtlFtSlurryReactor()
        for _ in range(100):
            sim.step(dt=0.05)
            assert sim.state.total_mass_balance_residual_kg_s < 1e-10
            assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10
            assert sim.state.enthalpy_conservation_residual_kw < 1e-10

    def test_conservation_under_different_kinetics(self) -> None:
        """Verify conservation holds under varied kinetics and alpha values."""
        sim = GtlFtSlurryReactor()
        sim.state.asf_alpha = 0.935
        sim.state.c_h2 = 50.0
        sim.state.c_co = 20.0
        sim.step(dt=0.05)
        assert sim.state.total_mass_balance_residual_kg_s < 1e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1e-10


# ============================================================================
# 7. Section 7: Cooling Jacket Heat Transfer & Thermal Runaway Trip
# ============================================================================

class TestSection7CoolingJacketAndThermalRunawayTrip:
    """Tests for cooling tube heat transfer, exotherm warnings, and thermal runaway trip (> 245 °C)."""

    def test_cooling_tube_heat_removal_nominal(self) -> None:
        """Verify internal cooling duty at nominal operating point (~18,500 kW)."""
        sim = GtlFtSlurryReactor()
        # Nominal: T_r = 225 °C, T_cool = 210.15 °C -> Delta T = 14.85 K
        # Q_cool = 500 W/(m2*K) * 2500 m2 * 14.85 K = 18,562,500 W = ~18,562 kW
        assert 18000.0 <= sim.state.internal_cooling_duty_kw <= 19000.0

    def test_temperature_stabilization_closed_loop(self) -> None:
        """Verify closed-loop thermal stability near nominal 225 °C."""
        sim = GtlFtSlurryReactor()
        sim.advance_time(duration_s=5.0, dt=0.05)
        assert 223.0 <= sim.state.reactor_temperature_celsius <= 227.0
        assert sim.state.ft_reaction_active is True
        assert sim.state.emergency_quench_cooling_active is False

    def test_exotherm_high_temp_warning_at_235c(self) -> None:
        """Verify T_r > 235 °C sets %M348 ExothermHighTempWarning without tripping reaction."""
        sim = GtlFtSlurryReactor()
        sim.state.reactor_temperature_celsius = 238.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.exotherm_high_temp_warning is True
        assert sim.state.ft_reaction_active is True
        assert sim.state.emergency_quench_cooling_active is False
        assert sim.state.diagnostic_code == GtlFtReactorDiagnosticCode.OK
        assert sim.registers.read_bit("%M348") is True
        assert sim.registers.read_bit("%M347") is True
        assert sim.registers.read_bit("%M349") is False

    def test_thermal_runaway_trip_at_245c(self) -> None:
        """Verify T_r > 245 °C triggers 0xD201, asserts %M349, and clears %M347."""
        sim = GtlFtSlurryReactor()
        sim.state.reactor_temperature_celsius = 246.5
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == GtlFtReactorDiagnosticCode.FT_ERR_THERMAL_RUNAWAY_TRIP
        assert sim.state.diagnostic_code == 0xD201
        assert sim.state.emergency_quench_cooling_active is True
        assert sim.state.ft_reaction_active is False
        assert sim.state.exotherm_high_temp_warning is True
        assert sim.registers.read_bit("%M349") is True
        assert sim.registers.read_bit("%M347") is False
        assert (sim.registers.read_word("%R1497") & 0xFFFF) == 0xD201

    def test_emergency_quench_cooling_activation(self) -> None:
        """Verify derivatives when quench is active apply emergency cooling duty and zero reaction rate."""
        sim = GtlFtSlurryReactor()
        sim.state.emergency_quench_cooling_active = True
        sim.state.ft_reaction_active = False

        y = [sim.state.c_h2, sim.state.c_co, sim.state.c_wax, sim.state.c_h2o, 520.0, 1.0]
        derivs = sim.compute_derivatives(0.0, y)
        dt_r_dt = derivs[4]

        # Quench should cause rapid temperature drop (negative derivative)
        assert dt_r_dt < 0.0


# ============================================================================
# 8. Section 8: H2/CO Ratio Imbalance, Catalyst Deactivation & Holdup Anomaly
# ============================================================================

class TestSection8ImbalanceAndCatalystDeactivation:
    """Tests for H2/CO ratio imbalance, catalyst deactivation, and gas holdup anomalies."""

    def test_h2_co_ratio_imbalance_low_detection(self) -> None:
        """Verify syngas H2/CO ratio < 1.70 triggers 0xD202 while reaction remains active."""
        sim = GtlFtSlurryReactor()
        sim.state.syngas_h2_co_ratio = 1.55
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == GtlFtReactorDiagnosticCode.FT_ERR_H2_CO_RATIO_IMBALANCE
        assert sim.state.diagnostic_code == 0xD202
        assert sim.state.ft_reaction_active is True
        assert (sim.registers.read_word("%R1497") & 0xFFFF) == 0xD202

    def test_h2_co_ratio_imbalance_high_detection(self) -> None:
        """Verify syngas H2/CO ratio > 2.30 triggers 0xD202."""
        sim = GtlFtSlurryReactor()
        sim.state.syngas_h2_co_ratio = 2.45
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == GtlFtReactorDiagnosticCode.FT_ERR_H2_CO_RATIO_IMBALANCE
        assert sim.state.diagnostic_code == 0xD202
        assert sim.state.ft_reaction_active is True

    def test_catalyst_deactivation_alarm_at_070(self) -> None:
        """Verify catalyst activity a_cat < 0.70 triggers 0xD203."""
        sim = GtlFtSlurryReactor()
        sim.state.a_cat = 0.65
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == GtlFtReactorDiagnosticCode.FT_ERR_CATALYST_DEACTIVATION_ALARM
        assert sim.state.diagnostic_code == 0xD203
        assert sim.state.ft_reaction_active is True
        assert (sim.registers.read_word("%R1497") & 0xFFFF) == 0xD203

    def test_catalyst_poisoning_and_sintering_decay_rate(self) -> None:
        """Verify catalyst deactivation derivative da_cat/dt is strictly negative and temperature dependent."""
        sim = GtlFtSlurryReactor()
        # At 225 °C (498.15 K)
        y_nom = [sim.state.c_h2, sim.state.c_co, sim.state.c_wax, sim.state.c_h2o, 498.15, 1.0]
        derivs_nom = sim.compute_derivatives(0.0, y_nom)
        da_nom = derivs_nom[5]

        # At 240 °C (513.15 K)
        y_hot = [sim.state.c_h2, sim.state.c_co, sim.state.c_wax, sim.state.c_h2o, 513.15, 1.0]
        derivs_hot = sim.compute_derivatives(0.0, y_hot)
        da_hot = derivs_hot[5]

        assert da_nom < 0.0
        assert da_hot < 0.0
        assert abs(da_hot) > abs(da_nom)  # Faster decay at higher temperature

    def test_gas_holdup_anomaly_detection_0xd204(self) -> None:
        """Verify superficial gas velocity outside [0.05, 0.35] triggers 0xD204."""
        sim = GtlFtSlurryReactor()
        sim.state.superficial_gas_velocity_m_s = 0.40
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.diagnostic_code == GtlFtReactorDiagnosticCode.FT_ERR_GAS_HOLDUP_ANOMALY
        assert sim.state.diagnostic_code == 0xD204
        assert sim.state.ft_reaction_active is True
        assert (sim.registers.read_word("%R1497") & 0xFFFF) == 0xD204


# ============================================================================
# 9. Section 9: Pure ST POU Syntax & Anti-Ladder Security Guard
# ============================================================================

class TestSection9PureSTSyntaxAndAntiLadderGuard:
    """Tests for IEC 61131-3 Pure ST syntax validation, AST parsing, and anti-ladder security guard."""

    def test_pou_gtl_ft_slurry_reactor_sync_syntax(self) -> None:
        """Verify GTL FT Slurry Reactor ST POU is valid pure Structured Text."""
        SecurityGuard.assert_pure_st_content(GTL_FT_SLURRY_REACTOR_PURE_ST_POU)
        val = STParser.validate_code(GTL_FT_SLURRY_REACTOR_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(GTL_FT_SLURRY_REACTOR_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "GtlFtSlurryReactorSync"
        assert ast.pou_type == POUType.PROGRAM

    def test_pou_symbol_bindings_all_registers(self) -> None:
        """Verify all Horner OCS registers (%R1490..%R1497, %M347..%M349) are bound in AST."""
        ast = STParser.parse_pou(GTL_FT_SLURRY_REACTOR_PURE_ST_POU)
        assert ast is not None
        expected_regs = [
            "%R1490", "%R1491", "%R1492", "%R1493",
            "%R1494", "%R1495", "%R1496", "%R1497",
            "%M347", "%M348", "%M349",
        ]
        for reg in expected_regs:
            assert reg in ast.bound_registers, f"Register {reg} not bound in ST AST"

    def test_verify_pure_st_helper_functions(self) -> None:
        """Verify helper validation functions return True and AgentStatus.SUCCESS."""
        assert verify_gtl_ft_slurry_reactor_pure_st() is True
        assert verify_gtl_ft_reactor_pure_st() is True
        assert verify_sbcr_ft_reactor_pure_st() is True

        res = validate_pure_st()
        assert res.status == AgentStatus.SUCCESS

    def test_anti_ladder_contacts_and_coils_interception(self) -> None:
        """Verify contacts and coils in ST raise LadderForbiddenError and return ERR_LADDER_FORBIDDEN."""
        bad_fragments = ["---[ ]---", "---[/]---", "---( )---", "---(S)---", "---(R)---"]
        for frag in bad_fragments:
            code = f"PROGRAM BadContacts\nVAR b: BOOL; END_VAR\n{frag}\nEND_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(code)
            val = STParser.validate_code(code)
            assert val.status == AgentStatus.FAILED
            assert val.error_code == "ERR_LADDER_FORBIDDEN"

    def test_anti_ladder_rungs_and_mnemonics_interception(self) -> None:
        """Verify rungs and mnemonics (RUNG, XIC, OTE) raise LadderForbiddenError."""
        bad_fragments = [
            "RUNG 1",
            "END_RUNG",
            "NETWORK 1",
            "XIC FtReactionActive",
            "OTE EmergencyQuenchCoolingActive",
        ]
        for frag in bad_fragments:
            code = f"PROGRAM BadMnemonics\nVAR b: BOOL; END_VAR\n{frag}\nEND_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(code)
            val = STParser.validate_code(code)
            assert val.status == AgentStatus.FAILED
            assert val.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# 10. Section 10: Horner RegisterTable Sync & Scan Cycle Execution
# ============================================================================

class TestSection10HornerRegisterTableSyncAndScanCycle:
    """Tests for Horner RegisterTable synchronization (%R1490..%R1497, %M347..%M349) and ILogicUnit scan cycle."""

    def test_register_table_synchronization_scaled_analog(self) -> None:
        """Verify scaling and bit-packing of analog registers %R1490..%R1497."""
        table = RegisterTable()
        sim = GtlFtSlurryReactor(register_table=table)

        sim.state.syngas_h2_co_ratio = 2.05
        sim.state.reactor_temperature_celsius = 225.0
        sim.state.reactor_pressure_bar = 25.0
        sim.state.co_conversion_pct = 68.5
        sim.state.asf_alpha = 0.915
        sim.state.internal_cooling_duty_kw = 18500.0
        sim.state.superficial_gas_velocity_m_s = 0.18
        sim.state.diagnostic_code = GtlFtReactorDiagnosticCode.OK

        sim.sync_to_registers(table)

        assert table.read_word("%R1490") == 205    # 2.05 * 100
        assert table.read_word("%R1491") == 2250   # 225.0 * 10
        assert table.read_word("%R1492") == 250    # 25.0 * 10
        assert table.read_word("%R1493") == 685    # 68.5 * 10
        assert table.read_word("%R1494") == 915    # 0.915 * 1000
        assert table.read_word("%R1495") == 18500  # 18500
        assert table.read_word("%R1496") == 18     # 0.18 * 100
        assert table.read_word("%R1497") == 0x0000

    def test_register_table_synchronization_discrete_coils(self) -> None:
        """Verify discrete coils %M347, %M348, %M349 reflect simulator state."""
        table = RegisterTable()
        sim = GtlFtSlurryReactor(register_table=table)

        sim.state.ft_reaction_active = True
        sim.state.exotherm_high_temp_warning = False
        sim.state.emergency_quench_cooling_active = False
        sim.sync_to_registers(table)

        assert table.read_bit("%M347") is True
        assert table.read_bit("%M348") is False
        assert table.read_bit("%M349") is False

    def test_privilege_mode_system_enforcement(self) -> None:
        """Verify sync_to_registers passes PrivilegeMode.SYSTEM successfully."""
        table = RegisterTable()
        sim = GtlFtSlurryReactor(register_table=table)
        # Should execute without PermissionError
        sim.sync_to_registers(table)

    def test_ilogic_unit_interface_properties(self) -> None:
        """Verify ILogicUnit standard contract properties."""
        sim = GtlFtSlurryReactor()
        assert isinstance(sim, ILogicUnit)
        assert sim.name == "GtlFtSlurryReactorSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

    def test_ilogic_unit_scan_step_100_cycles(self) -> None:
        """Verify scan_step executes 100+ cycles stably and returns status dictionary."""
        sim = GtlFtSlurryReactor()
        for i in range(100):
            res_dict = sim.scan_step(dt=0.05)
            assert res_dict["status"] == "success"
            assert "reactor_temperature_celsius" in res_dict
            assert "co_conversion_pct" in res_dict
            assert "asf_alpha" in res_dict

        assert sim.state.scan_count >= 100

    def test_adapter_logic_unit_scan_context_execution(self) -> None:
        """Verify GtlFtSlurryReactorLogicUnit adapter executes within Horner ScanContext."""
        table = RegisterTable()
        unit = GtlFtSlurryReactorLogicUnit(register_table=table)
        ctx = ScanContext(
            cycle=1,
            dt_ms=50.0,
            elapsed_time_ms=50.0,
            get_register=lambda a: table.read_word(a),
            set_register=lambda a, v: table.write_word(a, v, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda n, d=None: d,
            set_variable=lambda n, v: None,
            record_fault=lambda f: None,
        )
        ctx.registers = table
        unit.execute(ctx)

        # Registers should be written
        assert table.read_word("%R1490") == 205
        assert table.read_bit("%M347") is True


# ============================================================================
# 11. Section 11: Verification Runner & 9 Stages
# ============================================================================

class TestSection11VerificationRunnerNineStages:
    """Tests for run_gtl_ft_reactor_verification 9-stage verification suite."""

    def test_run_gtl_ft_reactor_verification_full_success(self) -> None:
        """Verify run_gtl_ft_reactor_verification passes all 9 stages deterministically."""
        result = run_gtl_ft_reactor_verification()
        assert isinstance(result, dict)
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["total_checks"] == 9
        assert result["data"]["checks_passed"] == 9
        assert len(result["data"]["tests"]) == 9
        for test in result["data"]["tests"]:
            assert test["passed"] is True

    def test_run_gtl_ft_reactor_verification_exports_evidence_json(self, tmp_path: Path) -> None:
        """Verify verification suite exports valid JSON file at target path."""
        target_json = tmp_path / "gtl_evidence.json"
        result = run_gtl_ft_reactor_verification(output_path=str(target_json))
        assert target_json.exists()
        assert target_json.stat().st_size > 0

        with open(target_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9

    def test_strict_four_state_contract_conformance(self) -> None:
        """Verify strict 4-state contract format: status, error_code, details, data."""
        result = run_gtl_ft_reactor_verification()
        assert result["status"] in {"success", "failed", "blocked", "inconclusive"}
        assert "error_code" in result
        assert "details" in result
        assert "data" in result
        assert isinstance(result["data"], dict)


# ============================================================================
# 12. Section 12: Edge Cases, Bounds Clamping & Status Word Consistency
# ============================================================================

class TestSection12EdgeCasesAndRobustness:
    """Tests for boundary limits, state clamping, and status word bitmask flags."""

    def test_extreme_superficial_gas_velocity_handling(self) -> None:
        """Verify extreme superficial gas velocity is safely bounded."""
        sim = GtlFtSlurryReactor()
        h_zero = sim.compute_hydrodynamics(u_g=0.001, p_bar=25.0, t_k=498.15)
        assert h_zero["epsilon_g"] >= 0.01  # Clamped to lower bound

        h_huge = sim.compute_hydrodynamics(u_g=5.0, p_bar=25.0, t_k=498.15)
        assert h_huge["epsilon_g"] <= 0.60  # Clamped to upper bound

    def test_zero_and_negative_concentration_clamping(self) -> None:
        """Verify zero and negative concentrations in compute_reaction_rates do not fail."""
        sim = GtlFtSlurryReactor()
        rxn = sim.compute_reaction_rates(c_h2=-5.0, c_co=-2.0, t_r_k=498.15, a_cat=-0.1)
        assert rxn["r_ft_mol_m3_s"] == 0.0
        assert rxn["q_rxn_w"] == 0.0

    def test_extreme_temperature_bounds(self) -> None:
        """Verify temperature derivative stays bounded under extreme temperature inputs."""
        sim = GtlFtSlurryReactor()
        y_extreme = [40.0, 15.0, 1800.0, 50.0, 950.0, 1.0]  # 950 K
        derivs = sim.compute_derivatives(0.0, y_extreme)
        assert not math.isnan(derivs[4])
        assert not math.isinf(derivs[4])

    def test_status_word_bitmask_consistency(self) -> None:
        """Verify status word bitmask matches state flags."""
        sim = GtlFtSlurryReactor()
        sim.state.reactor_temperature_celsius = 248.0
        sim._evaluate_safety_interlocks()

        sw = sim.state.status_word
        assert (sw & GtlFtReactorStatusBits.RUNNING) != 0
        assert (sw & GtlFtReactorStatusBits.EXOTHERM_HIGH_TEMP_WARNING) != 0
        assert (sw & GtlFtReactorStatusBits.EMERGENCY_QUENCH_ACTIVE) != 0
