"""Unit and Integration Tests for Industrial Molten Salt Thermal Energy Storage (TES) Thermocline ODE Simulation.

Work Package: W143 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1040..%R1047, %M242..%M244).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Solar salt thermophysical property correlations (density, specific heat, viscosity, freezing point).
4. Section 4: Schumann packed-bed thermocline heat transfer kinetics and two-phase model.
5. Section 5: Thermocline profile metrics: center height % and thickness m.
6. Section 6: Stored thermal energy (MWh) and State of Charge (SOC %) accuracy.
7. Section 7: Coupled 6-state ODE RK4 integration stability and dual mass and thermal enthalpy conservation residuals (< 1e-10).
8. Section 8: Process safety trips (0xA801, 0xA802, 0xA803, 0xA804) and Horner coil assertion (%M242, %M243, %M244).
9. Section 9: Horner OCS register space synchronization (%R1040..%R1047, %M242..%M244).
10. Section 10: 9-stage verification suite integration test writing evidence JSON.
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
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.molten_salt_tes import (
    MOLTEN_SALT_PURE_ST_POU,
    MOLTEN_SALT_SYNC_POU,
    MOLTEN_SALT_TES_DYNAMICS_SYNC_POU,
    MOLTEN_SALT_TES_PURE_ST_POU,
    MOLTEN_SALT_TES_SYNC_POU,
    SOLAR_SALT_FREEZING_TEMP_C,
    SOLAR_SALT_FREEZING_TRIP_C,
    SOLAR_SALT_MAX_SAFE_TEMP_C,
    TES_PURE_ST_POU,
    TES_THERMOCLINE_SYNC_POU,
    THERMAL_STORAGE_THERMOCLINE_PURE_ST_POU,
    THERMAL_STORAGE_THERMOCLINE_SYNC_POU,
    MoltenSaltConfig,
    MoltenSaltDiagCode,
    MoltenSaltDiagnosticCode,
    MoltenSaltModel,
    MoltenSaltParameters,
    MoltenSaltSimulator,
    MoltenSaltState,
    MoltenSaltStatusBits,
    MoltenSaltStatusWord,
    MoltenSaltTESConfig,
    MoltenSaltTESDiagnosticCode,
    MoltenSaltTESEngine,
    MoltenSaltTESModel,
    MoltenSaltTESPlantModel,
    MoltenSaltTESSimulationEngine,
    MoltenSaltTESSimulator,
    MoltenSaltTESState,
    MoltenSaltTESStatusBits,
    MoltenSaltTESStatusWord,
    MoltenSaltTesConfig,
    MoltenSaltTesDiagnosticCode,
    MoltenSaltTesEngine,
    MoltenSaltTesModel,
    MoltenSaltTesPlantModel,
    MoltenSaltTesSimulationEngine,
    MoltenSaltTesSimulator,
    MoltenSaltTesState,
    MoltenSaltTesStatusBits,
    MoltenSaltTesStatusWord,
    TesConfig,
    TesDiagnosticCode,
    TesSimulator,
    TesState,
    TesStatusBits,
    TesStatusWord,
    ThermalStorageDiagnosticCode,
    ThermalStorageThermoclineSimulator,
    ThermoclineConfig,
    ThermoclineDiagnosticCode,
    ThermoclineSimulator,
    ThermoclineState,
    run_molten_salt_tes_verification,
    run_molten_salt_verification,
    run_tes_thermocline_verification,
    run_tes_verification,
    run_thermocline_verification,
    verify_molten_salt_pure_st,
    verify_molten_salt_tes_pure_st,
    verify_tes_pure_st,
    verify_thermal_storage_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1040..%R1047, %M242..%M244)."""

    def test_verify_molten_salt_tes_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_molten_salt_tes_pure_st() is True
        assert verify_molten_salt_pure_st() is True
        assert verify_tes_pure_st() is True
        assert verify_thermal_storage_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1040..%R1047, %M242..%M244)."""
        SecurityGuard.assert_pure_st_content(MOLTEN_SALT_TES_PURE_ST_POU)
        val = STParser.validate_code(MOLTEN_SALT_TES_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(MOLTEN_SALT_TES_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "MoltenSaltTesSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1040", "%R1041", "%R1042", "%R1043",
            "%R1044", "%R1045", "%R1046", "%R1047",
            "%M242", "%M243", "%M244",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_pure_st_pou_aliases(self) -> None:
        """Requirement 1: Verify MoltenSaltTesSync aliases parse cleanly."""
        for pou_text in [
            MOLTEN_SALT_PURE_ST_POU,
            MOLTEN_SALT_TES_SYNC_POU,
            MOLTEN_SALT_SYNC_POU,
            TES_PURE_ST_POU,
            TES_THERMOCLINE_SYNC_POU,
            MOLTEN_SALT_TES_DYNAMICS_SYNC_POU,
        ]:
            SecurityGuard.assert_pure_st_content(pou_text)
            ast = STParser.parse_pou(pou_text)
            assert ast is not None
            assert ast.pou_type == POUType.PROGRAM
            for reg in [
                "%R1040", "%R1041", "%R1042", "%R1043",
                "%R1044", "%R1045", "%R1046", "%R1047",
                "%M242", "%M243", "%M244",
            ]:
                assert reg in ast.bound_registers

    def test_thermal_storage_thermocline_alias(self) -> None:
        """Requirement 1: Verify ThermalStorageThermoclineSync alias AST parsing."""
        SecurityGuard.assert_pure_st_content(THERMAL_STORAGE_THERMOCLINE_SYNC_POU)
        ast = STParser.parse_pou(THERMAL_STORAGE_THERMOCLINE_SYNC_POU)
        assert ast is not None
        assert ast.name == "ThermalStorageThermoclineSync"
        assert ast.pou_type == POUType.PROGRAM
        assert "%R1040" in ast.bound_registers
        assert "%M242" in ast.bound_registers


# ============================================================================
# 2. Section 2: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection2AntiLadderSecurityGuard:
    """Tests for interception and rejection of ladder logic constructs with ERR_LADDER_FORBIDDEN."""

    @pytest.mark.parametrize(
        "ladder_snippet",
        [
            "---[ ]---",
            "---[/]---",
            "---( )---",
            "---(S)---",
            "---(R)---",
            "RUNG 1",
            "END_RUNG",
            "NETWORK 1",
            "XIC SaltPumpPermissive",
            "XIO SaltFreezingTrip",
            "OTE ThermoclineDegradationAlarm",
            "OTL TraceHeatersActive",
            "OTU ChargingPumpRunning",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 1: All ladder constructs must trigger LadderForbiddenError."""
        invalid_st = f"""
        PROGRAM BadLadderTes
        VAR
            TestVar : BOOL;
        END_VAR
        {ladder_snippet}
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(invalid_st)


# ============================================================================
# 3. Section 3: Solar Salt Thermophysical Property Correlations
# ============================================================================

class TestSection3SolarSaltThermophysicalProperties:
    """Tests for temperature-dependent physical properties of 60% NaNO3 + 40% KNO3 Solar Salt."""

    def test_freezing_point_and_thermal_margin(self) -> None:
        """Requirement 2: Verify solidus freezing temperature and safety trip thresholds."""
        assert SOLAR_SALT_FREEZING_TEMP_C == 221.0
        assert SOLAR_SALT_FREEZING_TRIP_C == 238.0
        assert SOLAR_SALT_MAX_SAFE_TEMP_C == 590.0

    def test_density_correlation(self) -> None:
        """Requirement 2: rho(T) = 2090.0 - 0.636*T kg/m^3."""
        rho_290 = MoltenSaltTesSimulator.density(290.0)
        rho_565 = MoltenSaltTesSimulator.density(565.0)

        assert abs(rho_290 - 1905.56) < 1e-4
        assert abs(rho_565 - 1730.66) < 1e-4
        assert rho_290 > rho_565  # Buoyancy stabilizes top-hot stratification

    def test_heat_capacity_correlation(self) -> None:
        """Requirement 2: Cp(T) = 1443.0 + 0.172*T J/(kg*K)."""
        cp_290 = MoltenSaltTesSimulator.heat_capacity(290.0)
        cp_565 = MoltenSaltTesSimulator.heat_capacity(565.0)

        assert abs(cp_290 - 1492.88) < 1e-4
        assert abs(cp_565 - 1540.18) < 1e-4
        assert cp_565 > cp_290

    def test_dynamic_viscosity_correlation(self) -> None:
        """Requirement 2: mu(T) in mPa*s decreases monotonically with temperature."""
        mu_290 = MoltenSaltTesSimulator.viscosity_mpa_s(290.0)
        mu_400 = MoltenSaltTesSimulator.viscosity_mpa_s(400.0)
        mu_565 = MoltenSaltTesSimulator.viscosity_mpa_s(565.0)

        assert mu_290 > mu_400 > mu_565 > 0.0
        assert abs(mu_290 - 3.502) < 0.1
        assert abs(mu_565 - 1.145) < 0.1

    def test_thermal_conductivity_correlation(self) -> None:
        """Requirement 2: k_f(T) = 0.443 + 1.9e-4*T W/(m*K)."""
        kf_290 = MoltenSaltTesSimulator.thermal_conductivity(290.0)
        kf_565 = MoltenSaltTesSimulator.thermal_conductivity(565.0)

        assert abs(kf_290 - (0.443 + 1.9e-4 * 290.0)) < 1e-6
        assert abs(kf_565 - (0.443 + 1.9e-4 * 565.0)) < 1e-6


# ============================================================================
# 4. Section 4: Schumann Two-Phase Packed-Bed Model & Heat Transfer Kinetics
# ============================================================================

class TestSection4SchumannPackedBedModel:
    """Tests for Schumann fluid-solid non-thermal equilibrium model and kinetics."""

    def test_packed_bed_parameters(self) -> None:
        """Requirement 2: Packed bed void fraction and solid quartzite filler properties."""
        cfg = MoltenSaltTesConfig()
        assert cfg.bed_porosity == 0.22
        assert cfg.solid_density_kg_m3 == 2500.0
        assert cfg.filler_particle_diameter_m == 0.03
        assert cfg.solid_thermal_conductivity_w_m_k == 5.5

    def test_schumann_heat_transfer_coefficients(self) -> None:
        """Requirement 2: Wakao-Kaguei fluid-solid HTC h_fs and volumetric HTC h_v."""
        sim = MoltenSaltTesSimulator()
        h_fs, h_v = sim.schumann_heat_transfer_coeff(
            temp_c=427.5,
            mass_flow_kg_s=120.0,
            area_m2=sim.config.tank_cross_section_area_m2,
            particle_diam_m=0.03,
            porosity=0.22,
        )
        assert h_fs > 50.0
        assert h_v > 10000.0


# ============================================================================
# 5. Section 5: Thermocline Profile Calculation
# ============================================================================

class TestSection5ThermoclineProfile:
    """Tests for vertical thermal stratification, thermocline center height %, and thickness m."""

    def test_nominal_thermocline_center_and_thickness(self) -> None:
        """Requirement 2: Nominal center height 50.0% (%R1042=500) and thickness 2.15 m (%R1043=215)."""
        sim = MoltenSaltTesSimulator()
        center_pct, thickness_m = sim.compute_thermocline_profile()

        assert abs(center_pct - 50.0) < 1.0
        assert abs(thickness_m - 2.15) < 0.1
        assert sim.state.t_top_c > sim.state.t_mid_c > sim.state.t_bot_c

    def test_thermocline_degradation_alarm_assertion(self) -> None:
        """Requirement 4: Thermocline thickness > 40% height (5.6 m) triggers 0xA802 (%M244)."""
        sim = MoltenSaltTesSimulator()
        # Flatten temperature profile to simulate thermocline degradation
        sim.state.t_mid_high_c = 440.0
        sim.state.t_mid_low_c = 415.0
        center_pct, thickness_m = sim.compute_thermocline_profile()

        assert thickness_m > 5.6  # > 40% of 14.0 m
        sim._evaluate_safety_interlocks()
        assert sim.state.thermocline_degradation_alarm is True
        assert sim.state.diagnostic_code == MoltenSaltTesDiagnosticCode.TES_ERR_THERMOCLINE_DEGRADATION


# ============================================================================
# 6. Section 6: Stored Thermal Energy & State of Charge
# ============================================================================

class TestSection6StoredEnergyAndStateOfCharge:
    """Tests for stored thermal energy [MWh] and State of Charge (SOC) [%]."""

    def test_nominal_stored_energy_and_soc(self) -> None:
        """Requirement 2: Nominal stored energy 450.0 MWh (%R1045=4500) and SOC 78.5% (%R1046=785)."""
        sim = MoltenSaltTesSimulator()
        e_stored, soc_pct = sim.compute_stored_energy_and_soc()

        assert abs(e_stored - 450.0) < 1.0
        assert abs(soc_pct - 78.5) < 1.0
        assert sim.config.nominal_thermal_capacity_mwh > 500.0


# ============================================================================
# 7. Section 7: Coupled 6-State ODE System & RK4 Solver
# ============================================================================

class TestSection7CoupledODESystemAndRK4Solver:
    """Tests for 6-state ODE integration stability and dual stoichiometric conservation residuals (< 1e-10)."""

    def test_rk4_integration_stability(self) -> None:
        """Requirement 3: RK4 dynamic integration over 2.0s maintains finite, stable temperatures."""
        sim = MoltenSaltTesSimulator()
        res = sim.advance_time(duration_s=2.0, dt=0.1)

        assert res.status == AgentStatus.SUCCESS
        assert not math.isnan(sim.state.t_top_c)
        assert not math.isnan(sim.state.t_bot_c)
        assert not math.isnan(sim.state.stored_thermal_energy_mwh)
        assert sim.state.t_top_c > sim.state.t_bot_c

    def test_dual_stoichiometric_conservation_residuals(self) -> None:
        """Requirement 3: Total mass residual < 1e-10 kg/s and first-law enthalpy residual < 1e-10 kW."""
        sim = MoltenSaltTesSimulator()
        sim.advance_time(duration_s=1.0, dt=0.1)

        assert sim.state.total_mass_balance_residual_kg_s < 1e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1e-10

    def test_invalid_timestep_fail_closed(self) -> None:
        """Requirement 3: Non-positive duration or dt fails closed."""
        sim = MoltenSaltTesSimulator()
        res = sim.advance_time(duration_s=-1.0, dt=0.1)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "INVALID_TIMESTEP"


# ============================================================================
# 8. Section 8: Process Safety Interlocks & Diagnostics
# ============================================================================

class TestSection8ProcessSafetyInterlocks:
    """Tests for process safety trips (0xA801, 0xA802, 0xA803, 0xA804) and priority hierarchy."""

    def test_freezing_trip_0xa801(self) -> None:
        """Requirement 4: Salt temp < 238 °C asserts %M243 (SaltFreezingTrip) and clears %M242."""
        sim = MoltenSaltTesSimulator()
        sim.state.t_bot_c = 230.0  # < 238.0 °C
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.salt_freezing_trip is True
        assert sim.state.salt_pump_permissive is False
        assert sim.state.diagnostic_code == MoltenSaltTesDiagnosticCode.TES_ERR_FREEZING_TRIP
        assert sim.reg_table.read_bit("%M243") is True
        assert sim.reg_table.read_bit("%M242") is False
        assert (sim.reg_table.read_word("%R1047") & 0xFFFF) == 0xA801

    def test_overtemp_trip_0xa804(self) -> None:
        """Requirement 4: Salt temp > 590 °C sets 0xA804 and clears %M242."""
        sim = MoltenSaltTesSimulator()
        sim.state.t_top_c = 595.0  # > 590.0 °C
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.salt_pump_permissive is False
        assert sim.state.overtemp_trip is True
        assert sim.state.diagnostic_code == MoltenSaltTesDiagnosticCode.TES_ERR_OVERTEMP
        assert sim.reg_table.read_bit("%M242") is False
        assert (sim.reg_table.read_word("%R1047") & 0xFFFF) == 0xA804

    def test_tank_overfill_trip_0xa803(self) -> None:
        """Requirement 4: Tank level > 98% sets 0xA803 and clears %M242."""
        sim = MoltenSaltTesSimulator()
        sim.state.tank_level_pct = 99.0  # > 98.0%
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.salt_pump_permissive is False
        assert sim.state.tank_overfill_trip is True
        assert sim.state.diagnostic_code == MoltenSaltTesDiagnosticCode.TES_ERR_TANK_OVERFILL
        assert sim.reg_table.read_bit("%M242") is False
        assert (sim.reg_table.read_word("%R1047") & 0xFFFF) == 0xA803

    def test_thermocline_degradation_alarm_0xa802(self) -> None:
        """Requirement 4: Thermocline thickness > 40% height sets 0xA802 and asserts %M244."""
        sim = MoltenSaltTesSimulator()
        sim.state.thermocline_thickness_m = 6.2  # > 5.6 m
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.thermocline_degradation_alarm is True
        assert sim.state.salt_pump_permissive is True
        assert sim.state.diagnostic_code == MoltenSaltTesDiagnosticCode.TES_ERR_THERMOCLINE_DEGRADATION
        assert sim.reg_table.read_bit("%M244") is True
        assert (sim.reg_table.read_word("%R1047") & 0xFFFF) == 0xA802

    def test_safety_trip_priority_hierarchy(self) -> None:
        """Requirement 4: Freezing (0xA801) > Overtemp (0xA804) > Overfill (0xA803) > Degradation (0xA802)."""
        sim = MoltenSaltTesSimulator()

        # All four conditions active
        sim.state.t_bot_c = 230.0                # 0xA801
        sim.state.t_top_c = 595.0                # 0xA804
        sim.state.tank_level_pct = 99.0          # 0xA803
        sim.state.thermocline_thickness_m = 6.2  # 0xA802

        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == 0xA801

        # Clear freezing -> next is overtemp 0xA804
        sim.state.t_bot_c = 290.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == 0xA804

        # Clear overtemp -> next is overfill 0xA803
        sim.state.t_top_c = 565.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == 0xA803

        # Clear overfill -> next is degradation 0xA802
        sim.state.tank_level_pct = 90.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == 0xA802


# ============================================================================
# 9. Section 9: Horner OCS Register Space Synchronization (%R1040..%R1047, %M242..%M244)
# ============================================================================

class TestSection9HornerOCSSync:
    """Tests for Horner OCS memory register bindings (%R1040..%R1047, %M242..%M244) and class compatibility aliases."""

    def test_nominal_register_sync(self) -> None:
        """Requirement 5: Verify analog registers %R1040..%R1047 and discrete coils %M242..%M244."""
        sim = MoltenSaltTesSimulator()
        reg = sim.reg_table

        # %R1040: TopHotSaltTempCelsius (scaled x10 C, e.g. 5650 = 565.0 C)
        assert reg.read_word("%R1040") == 5650

        # %R1041: BottomColdSaltTempCelsius (scaled x10 C, e.g. 2900 = 290.0 C)
        assert reg.read_word("%R1041") == 2900

        # %R1042: ThermoclineCenterHeightPct (scaled x10 %, e.g. 500 = 50.0%)
        assert reg.read_word("%R1042") == 500

        # %R1043: ThermoclineThicknessMeters (scaled x100 m, e.g. 215 = 2.15 m)
        assert reg.read_word("%R1043") == 215

        # %R1044: SaltMassFlowRateKgs (scaled x10 kg/s, e.g. 1200 = 120.0 kg/s)
        assert reg.read_word("%R1044") == 1200

        # %R1045: StoredThermalEnergyMwh (scaled x10 MWh, e.g. 4500 = 450.0 MWh)
        assert reg.read_word("%R1045") == 4500

        # %R1046: StateOfChargePct (scaled x10 %, e.g. 785 = 78.5%)
        assert reg.read_word("%R1046") == 785

        # %R1047: DiagnosticStatusCode (0x0000 = OK)
        assert (reg.read_word("%R1047") & 0xFFFF) == 0x0000

        # %M242: SaltPumpPermissive (BOOL)
        assert reg.read_bit("%M242") is True

        # %M243: SaltFreezingTrip (BOOL)
        assert reg.read_bit("%M243") is False

        # %M244: ThermoclineDegradationAlarm (BOOL)
        assert reg.read_bit("%M244") is False

    def test_class_compatibility_aliases(self) -> None:
        """Requirement 5: Verify all required class and module aliases exist."""
        assert MoltenSaltTESSimulator is MoltenSaltTesSimulator
        assert MoltenSaltSimulator is MoltenSaltTesSimulator
        assert TesSimulator is MoltenSaltTesSimulator
        assert ThermoclineSimulator is MoltenSaltTesSimulator
        assert ThermalStorageThermoclineSimulator is MoltenSaltTesSimulator
        assert MoltenSaltTesEngine is MoltenSaltTesSimulator
        assert MoltenSaltTESEngine is MoltenSaltTesSimulator
        assert MoltenSaltTesPlantModel is MoltenSaltTesSimulator
        assert MoltenSaltTESPlantModel is MoltenSaltTesSimulator
        assert MoltenSaltTesSimulationEngine is MoltenSaltTesSimulator
        assert MoltenSaltTESSimulationEngine is MoltenSaltTesSimulator
        assert MoltenSaltTesModel is MoltenSaltTesSimulator
        assert MoltenSaltTESModel is MoltenSaltTesSimulator
        assert MoltenSaltModel is MoltenSaltTesSimulator

        assert MoltenSaltTESConfig is MoltenSaltTesConfig
        assert MoltenSaltConfig is MoltenSaltTesConfig
        assert TesConfig is MoltenSaltTesConfig
        assert ThermoclineConfig is MoltenSaltTesConfig
        assert MoltenSaltParameters is MoltenSaltTesConfig

        assert MoltenSaltTESState is MoltenSaltTesState
        assert MoltenSaltState is MoltenSaltTesState
        assert TesState is MoltenSaltTesState
        assert ThermoclineState is MoltenSaltTesState

        assert MoltenSaltTESStatusBits is MoltenSaltTesStatusBits
        assert MoltenSaltStatusBits is MoltenSaltTesStatusBits
        assert TesStatusBits is MoltenSaltTesStatusBits
        assert MoltenSaltTesStatusWord is MoltenSaltTesStatusBits
        assert MoltenSaltTESStatusWord is MoltenSaltTesStatusBits
        assert MoltenSaltStatusWord is MoltenSaltTesStatusBits
        assert TesStatusWord is MoltenSaltTesStatusBits

        assert MoltenSaltTESDiagnosticCode is MoltenSaltTesDiagnosticCode
        assert MoltenSaltDiagnosticCode is MoltenSaltTesDiagnosticCode
        assert TesDiagnosticCode is MoltenSaltTesDiagnosticCode
        assert MoltenSaltDiagCode is MoltenSaltTesDiagnosticCode
        assert ThermalStorageDiagnosticCode is MoltenSaltTesDiagnosticCode
        assert ThermoclineDiagnosticCode is MoltenSaltTesDiagnosticCode


# ============================================================================
# 10. Section 10: 9-Stage Verification Suite Integration Test & Evidence JSON
# ============================================================================

class TestSection10MoltenSaltVerificationRunner:
    """Tests for run_molten_salt_tes_verification function and evidence artifact generation."""

    def test_run_molten_salt_tes_verification_suite_all_9_stages(self, tmp_path: Path) -> None:
        """Requirement 6: Execute full 9-stage verification suite and assert strict success."""
        out_file = str(tmp_path / "w143_molten_salt_tes_evidence.json")
        res = run_molten_salt_tes_verification(output_path=out_file)

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert "Industrial Molten Salt Thermal Energy Storage (TES) Thermocline ODE Simulation verified cleanly (9/9 checks passed)" in res["details"]

        data = res["data"]
        assert data["work_package"] == "W143"
        assert data["gate"] == "Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation"
        assert data["checks_passed"] == 9
        assert data["total_checks"] == 9

        tests = data["tests"]
        assert len(tests) == 9
        for t in tests:
            assert t["passed"] is True, f"Stage {t['stage']} ({t['check']}) failed: {t['details']}"

        # Verify evidence JSON file written to disk
        evidence_file = Path(out_file)
        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            saved_data = json.load(f)
        assert saved_data["status"] == "success"
        assert saved_data["data"]["checks_passed"] == 9

    def test_run_molten_salt_tes_verification_evidence_path_parameter(self, tmp_path: Path) -> None:
        """Requirement 6: Test evidence_path compatibility alias parameter."""
        ev_file = tmp_path / "tes_alias_evidence.json"
        res = run_molten_salt_tes_verification(evidence_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()

    def test_run_molten_salt_verification_function_alias(self, tmp_path: Path) -> None:
        """Requirement 6: Test run_molten_salt_verification function alias."""
        ev_file = tmp_path / "salt_func_alias_evidence.json"
        res = run_molten_salt_verification(output_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()

    def test_run_tes_thermocline_verification_alias(self, tmp_path: Path) -> None:
        """Requirement 6: Test run_tes_thermocline_verification function alias."""
        ev_file = tmp_path / "tes_thermocline_evidence.json"
        res = run_tes_thermocline_verification(output_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()

    def test_run_tes_verification_alias(self, tmp_path: Path) -> None:
        """Requirement 6: Test run_tes_verification function alias."""
        ev_file = tmp_path / "tes_evidence.json"
        res = run_tes_verification(output_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()

    def test_run_thermocline_verification_alias(self, tmp_path: Path) -> None:
        """Requirement 6: Test run_thermocline_verification function alias."""
        ev_file = tmp_path / "thermocline_evidence.json"
        res = run_thermocline_verification(output_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()
