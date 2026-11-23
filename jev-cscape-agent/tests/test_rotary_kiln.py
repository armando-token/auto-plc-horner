"""Unit and Integration Tests for Industrial Rotary Kiln Clinkerization Thermal Reaction Kinetics & Bed Dynamics ODE Simulation.

Work Package: W137 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R980..%R987, %M228..%M230).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Calcination endothermic kinetics, Bogue mineralogy, and alite/belite formation.
4. Section 4: Saeman bed dynamics, rotation speed RPM scaling, and drive torque calculations.
5. Section 5: Coupled ODE RK4 integration stability and dual mass and calcium/silicon elemental conservation residuals (< 1e-10).
6. Section 6: Process safety trips (0xA201, 0xA202, 0xA203, 0xA204) and Horner coil assertion (%M228, %M229, %M230).
7. Section 7: Horner OCS register space synchronization (%R980..%R987, %M228..%M230).
8. Section 8: 9-stage verification suite integration test writing evidence JSON.
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
from jev_cscape.simulation.rotary_kiln import (
    KILN_PURE_ST_POU,
    KILN_SYNC_POU,
    ROTARY_KILN_BED_DYNAMICS_SYNC_POU,
    ROTARY_KILN_CLINKERIZATION_PURE_ST_POU,
    ROTARY_KILN_CLINKERIZATION_SYNC_POU,
    ROTARY_KILN_CLINKER_SYNC_POU,
    ROTARY_KILN_PURE_ST_POU,
    ROTARY_KILN_ST_POU,
    ROTARY_KILN_SYNC_POU,
    KilnConfig,
    KilnDiagnosticCode,
    KilnModel,
    KilnParameters,
    KilnPlantModel,
    KilnSimulator,
    KilnState,
    KilnStatusBits,
    KilnStatusWord,
    RotaryKilnClinkerizationConfig,
    RotaryKilnClinkerizationDiagnosticCode,
    RotaryKilnClinkerizationSimulator,
    RotaryKilnClinkerizationState,
    RotaryKilnClinkerizationStatusBits,
    RotaryKilnClinkerizationStatusWord,
    RotaryKilnConfig,
    RotaryKilnDiagnosticCode,
    RotaryKilnEngine,
    RotaryKilnModel,
    RotaryKilnParameters,
    RotaryKilnPlantModel,
    RotaryKilnSimulationEngine,
    RotaryKilnSimulator,
    RotaryKilnState,
    RotaryKilnStatusBits,
    RotaryKilnStatusWord,
    run_rotary_kiln_clinkerization_verification,
    run_rotary_kiln_verification,
    validate_pure_st,
    verify_rotary_kiln_clinkerization_pure_st,
    verify_rotary_kiln_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R980..%R987, %M228..%M230)."""

    def test_verify_rotary_kiln_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_rotary_kiln_pure_st() is True
        assert verify_rotary_kiln_clinkerization_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R980..%R987, %M228..%M230)."""
        SecurityGuard.assert_pure_st_content(ROTARY_KILN_PURE_ST_POU)
        val = STParser.validate_code(ROTARY_KILN_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(ROTARY_KILN_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "RotaryKilnClinkerSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R980", "%R981", "%R982", "%R983",
            "%R984", "%R985", "%R986", "%R987",
            "%M228", "%M229", "%M230",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_pure_st_pou_bed_dynamics_alias_ast(self) -> None:
        """Requirement 1: Verify RotaryKilnBedDynamicsSync alias parses cleanly."""
        SecurityGuard.assert_pure_st_content(ROTARY_KILN_BED_DYNAMICS_SYNC_POU)
        ast = STParser.parse_pou(ROTARY_KILN_BED_DYNAMICS_SYNC_POU)
        assert ast is not None
        assert ast.name == "RotaryKilnBedDynamicsSync"
        assert ast.pou_type == POUType.PROGRAM
        for reg in ["%R980", "%R981", "%R982", "%R983", "%R984", "%R985", "%R986", "%R987", "%M228", "%M229", "%M230"]:
            assert reg in ast.bound_registers

    def test_pure_st_pou_clinker_sync_alias_ast(self) -> None:
        """Requirement 1: Verify ROTARY_KILN_CLINKER_SYNC_POU alias parses cleanly."""
        SecurityGuard.assert_pure_st_content(ROTARY_KILN_CLINKER_SYNC_POU)
        ast = STParser.parse_pou(ROTARY_KILN_CLINKER_SYNC_POU)
        assert ast is not None
        assert ast.name == "RotaryKilnClinkerSync"
        assert ast.pou_type == POUType.PROGRAM
        for reg in ["%R980", "%R981", "%R982", "%R983", "%R984", "%R985", "%R986", "%R987", "%M228", "%M229", "%M230"]:
            assert reg in ast.bound_registers

    def test_pure_st_pou_alias_equivalence(self) -> None:
        """Requirement 1: Verify POU aliases are defined and consistent."""
        assert ROTARY_KILN_PURE_ST_POU == ROTARY_KILN_CLINKERIZATION_PURE_ST_POU
        assert ROTARY_KILN_SYNC_POU == ROTARY_KILN_CLINKERIZATION_PURE_ST_POU
        assert ROTARY_KILN_CLINKER_SYNC_POU == ROTARY_KILN_CLINKERIZATION_PURE_ST_POU
        assert ROTARY_KILN_CLINKERIZATION_SYNC_POU == ROTARY_KILN_CLINKERIZATION_PURE_ST_POU
        assert KILN_PURE_ST_POU == ROTARY_KILN_CLINKERIZATION_PURE_ST_POU
        assert KILN_SYNC_POU == ROTARY_KILN_CLINKERIZATION_PURE_ST_POU

    def test_pure_st_pou_internal_variables_and_control_logic(self) -> None:
        """Requirement 1: Verify internal boolean variables and interlock IF-branches."""
        ast = STParser.parse_pou(ROTARY_KILN_PURE_ST_POU)
        assert ast is not None
        var_names = [v.name for v in ast.variables]
        assert "ClinkerCoolerPermissive" in var_names
        assert "InducedDraftFanRunning" in var_names
        assert "FuelGasBurnerEnabled" in var_names
        assert "SecondaryAirTempOk" in var_names
        assert "NoxEmissionInterlock" in var_names

        stmts = "\n".join(ast.raw_statements)
        assert "IF (BurningZoneTempCelsius > 15500) OR (Shell_Temp_Est > 4200) THEN" in stmts
        assert "DiagnosticStatusCode := 16#A201;" in stmts
        assert "ELSIF FreeLimeContentPct > 200 THEN" in stmts
        assert "DiagnosticStatusCode := 16#A202;" in stmts
        assert "ELSIF KilnDriveTorqueKnm > 1200 THEN" in stmts
        assert "DiagnosticStatusCode := 16#A203;" in stmts
        assert "ELSIF (BurningZoneTempCelsius < 11000) AND (FuelFiringRateKgh > 500) THEN" in stmts
        assert "DiagnosticStatusCode := 16#A204;" in stmts


# ============================================================================
# 2. Section 2: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection2AntiLadderSecurityGuard:
    """Tests for SecurityGuard fail-closed rejection of ladder logic constructs."""

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
            "XIC KilnDrivePermissive",
            "XIO ShellHotSpotTrip",
            "OTE LowBeliteAliteAlarm",
            "OTL ClinkerCoolerPermissive",
            "OTU InducedDraftFanRunning",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: Verify all ladder constructs raise LadderForbiddenError."""
        bad_code = f"{ROTARY_KILN_PURE_ST_POU}\n{ladder_snippet}\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

        val = STParser.validate_code(bad_code)
        assert val.status == AgentStatus.FAILED
        assert val.error_code == "ERR_LADDER_FORBIDDEN"
        assert val.data.get("ladder_rejected") is True


# ============================================================================
# 3. Section 3: Calcination Endothermic Kinetics, Bogue Mineralogy & Alite/Belite
# ============================================================================

class TestSection3CalcinationKineticsAndBogueMineralogy:
    """Tests for endothermic calcination kinetics, Bogue mineralogy, and alite/belite sintering formation."""

    def test_calcination_enthalpy_and_arrhenius_kinetics(self) -> None:
        """Requirement 3: Verify endothermic enthalpy (1.78e6 J/kg) and Arrhenius temperature scaling."""
        sim = RotaryKilnSimulator()
        cfg = sim.config

        assert math.isclose(cfg.delta_h_calc_j_kg, 1.78e6, rel_tol=1e-3)
        assert cfg.activation_energy_j_mol == 175000.0

        # Below 600 °C, reaction rate is negligible
        r_500 = sim.compute_calcination_rate(500.0)
        assert r_500 == 0.0

        # Reaction rate increases monotonically across calcination range
        r_700 = sim.compute_calcination_rate(700.0)
        r_850 = sim.compute_calcination_rate(850.0)
        r_950 = sim.compute_calcination_rate(950.0)

        assert 0.0 <= r_700 < r_850 < r_950
        assert r_950 > 0.01, f"Rate at 950 C ({r_950:.3f}) must exceed 0.01 s^-1"

    def test_bogue_mineralogy_nominal_clinker(self) -> None:
        """Requirement 3: Verify standard Bogue mineralogy calculation (C3S, C2S, C3A, C4AF)."""
        sim = RotaryKilnSimulator()
        bogue = sim.compute_bogue_mineralogy(
            cao=65.5,
            sio2=21.2,
            al2o3=5.2,
            fe2o3=3.2,
            free_lime=1.0,
        )

        assert 55.0 <= bogue["c3s"] <= 68.0, f"C3S Alite {bogue['c3s']}% outside expected band 55..68%"
        assert 12.0 <= bogue["c2s"] <= 25.0, f"C2S Belite {bogue['c2s']}% outside expected band 12..25%"
        assert 6.0 <= bogue["c3a"] <= 12.0, f"C3A Aluminate {bogue['c3a']}% outside expected band 6..12%"
        assert 6.0 <= bogue["c4af"] <= 14.0, f"C4AF Ferrite {bogue['c4af']}% outside expected band 6..14%"
        assert math.isclose(bogue["free_lime"], 1.0, abs_tol=0.1)

        total_mineral_wt = bogue["c3s"] + bogue["c2s"] + bogue["c3a"] + bogue["c4af"] + bogue["free_lime"]
        assert total_mineral_wt >= 95.0, f"Mineral sum {total_mineral_wt}% must account for >95% clinker weight"

    def test_bogue_lime_saturation_factor(self) -> None:
        """Requirement 3: Verify Lime Saturation Factor (LSF) and its impact on C3S/C2S balance."""
        sim = RotaryKilnSimulator()

        # High lime clinker -> high C3S, low C2S
        bogue_high_lime = sim.compute_bogue_mineralogy(cao=67.0, sio2=21.0, al2o3=5.0, fe2o3=3.0, free_lime=1.0)
        # Low lime clinker -> lower C3S, higher C2S
        bogue_low_lime = sim.compute_bogue_mineralogy(cao=64.0, sio2=21.0, al2o3=5.0, fe2o3=3.0, free_lime=1.0)

        assert bogue_high_lime["lsf"] > bogue_low_lime["lsf"]
        assert bogue_high_lime["c3s"] > bogue_low_lime["c3s"]
        assert bogue_high_lime["c2s"] < bogue_low_lime["c2s"]

    def test_alite_belite_sintering_transformation_temperature_dependency(self) -> None:
        """Requirement 3: Verify Alite (C3S) sintering requires burning zone liquid melt (T >= 1300 C)."""
        sim = RotaryKilnSimulator()
        assert sim.config.t_sinter_onset_c == 1300.0

        # Sub-sintering temperature (e.g. 1150 °C) has suppressed Alite formation
        y_cold = [1150.0, 850.0, 95.0, 50.0, 20.0]
        derivs_cold = sim._derivatives(y_cold)
        # Sintering temperature (e.g. 1450 °C) has active Alite formation
        y_hot = [1450.0, 900.0, 98.5, 50.0, 20.0]
        derivs_hot = sim._derivatives(y_hot)

        assert derivs_hot[3] > derivs_cold[3], "Alite derivative must be significantly higher at 1450 C than at 1150 C"

    def test_free_lime_consumption(self) -> None:
        """Requirement 3: Free lime is constrained and properly reported in state telemetry."""
        sim = RotaryKilnSimulator()
        assert 0.5 <= sim.state.free_lime_pct <= 2.5
        assert sim.state.lime_saturation_factor > 0.90

    def test_calcination_endothermic_heat_absorption(self) -> None:
        """Requirement 3: Verify calcination heat load proportional to feed rate and CaCO3 content."""
        sim = RotaryKilnSimulator()
        cfg = sim.config

        # 36 t/h (10.0 kg/s) feed with 77% CaCO3
        caco3_mass_flow = cfg.feed_rate_kg_s * cfg.caco3_feed_frac
        calc_heat_load_w = caco3_mass_flow * cfg.delta_h_calc_j_kg

        # Calcination heat demand is ~13.7 MW for 36 t/h meal (+1780 kJ/kg CaCO3)
        assert 10.0e6 <= calc_heat_load_w <= 20.0e6


# ============================================================================
# 4. Section 4: Saeman Bed Dynamics, RPM Scaling & Drive Torque
# ============================================================================

class TestSection4SaemanBedDynamicsAndDriveTorque:
    """Tests for Saeman granular bed transport velocity, rotation speed scaling, and drive motor torque."""

    def test_saeman_axial_velocity_and_residence_time(self) -> None:
        """Requirement 4: Verify Saeman axial velocity and solids residence time (10..90 min)."""
        sim = RotaryKilnSimulator()
        v_s = sim.compute_saeman_velocity(rpm=3.5)

        assert 0.010 <= v_s <= 0.120, f"Saeman velocity {v_s:.4f} m/s outside expected range 0.01..0.12 m/s"
        assert 10.0 <= sim.state.bed_residence_time_min <= 90.0
        assert math.isclose(sim.state.bed_velocity_m_s, v_s, rel_tol=1e-5)

    def test_saeman_velocity_rpm_proportionality(self) -> None:
        """Requirement 4: Verify linear velocity scaling with rotation speed RPM (v_s ~ omega)."""
        sim = RotaryKilnSimulator()
        v_1 = sim.compute_saeman_velocity(rpm=1.5)
        v_2 = sim.compute_saeman_velocity(rpm=3.0)
        v_3 = sim.compute_saeman_velocity(rpm=4.5)

        assert math.isclose(v_2 / v_1, 2.0, rel_tol=1e-3)
        assert math.isclose(v_3 / v_1, 3.0, rel_tol=1e-3)

    def test_drive_torque_components_and_power(self) -> None:
        """Requirement 4: Verify drive motor torque in nominal range (80..95 kN*m) and power (25..45 kW)."""
        sim = RotaryKilnSimulator()
        t_knm, p_kw = sim.compute_drive_torque(rpm=3.5)

        assert 80.0 <= t_knm <= 95.0, f"Drive torque {t_knm:.1f} kN*m outside band 80..95 kN*m"
        assert 25.0 <= p_kw <= 45.0, f"Drive power {p_kw:.1f} kW outside band 25..45 kW"
        assert math.isclose(sim.state.drive_torque_knm, t_knm, rel_tol=1e-5)
        assert math.isclose(sim.state.drive_power_kw, p_kw, rel_tol=1e-5)

    def test_drive_torque_rpm_and_bed_loading_scaling(self) -> None:
        """Requirement 4: Verify torque increases with bed mass inventory and power scales with RPM."""
        sim = RotaryKilnSimulator()
        t_light, _ = sim.compute_drive_torque(rpm=3.5, bed_mass_kg=50000.0)
        t_heavy, _ = sim.compute_drive_torque(rpm=3.5, bed_mass_kg=120000.0)

        assert t_heavy > t_light, "Heavier solids bed loading must demand higher lifting torque"

        _, p_low_rpm = sim.compute_drive_torque(rpm=2.0)
        _, p_high_rpm = sim.compute_drive_torque(rpm=4.0)
        assert p_high_rpm > p_low_rpm, "Mechanical power must increase with RPM"

    def test_bed_mass_inventory_scaling(self) -> None:
        """Requirement 4: Verify bed loading mass (~88.6 tonnes) matches 10% fill fraction."""
        sim = RotaryKilnSimulator()
        assert 70000.0 <= sim.state.bed_mass_kg <= 120000.0
        assert math.isclose(sim.state.bed_mass_kg, 88555.0, rel_tol=0.05)


# ============================================================================
# 5. Section 5: Coupled ODE RK4 Integration Stability & Conservation Residuals
# ============================================================================

class TestSection5CoupledODEAndRK4Solver:
    """Tests for coupled ODE RK4 integration stability and dual stoichiometric conservation residuals (< 1e-10)."""

    def test_rk4_advance_time_stability(self) -> None:
        """Requirement 5: Verify RK4 numerical integration produces smooth, stable trajectories."""
        sim = RotaryKilnSimulator()
        res = sim.advance_time(duration_s=3.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS

        st = sim.state
        assert 1350.0 <= st.t_burning_zone_c <= 1550.0
        assert 800.0 <= st.t_calcination_zone_c <= 1000.0
        assert 90.0 <= st.calcination_conversion_pct <= 100.0
        assert 50.0 <= st.alite_c3s_pct <= 70.0
        assert 10.0 <= st.belite_c2s_pct <= 30.0
        assert st.clinker_discharge_kg_s > 0.0

    def test_dual_mass_and_elemental_conservation_residuals(self) -> None:
        """Requirement 5: Verify dual mass and elemental Ca/Si conservation residuals < 1e-10 kg/s."""
        sim = RotaryKilnSimulator()
        sim.advance_time(duration_s=2.0, dt=0.05)

        total_res = sim.state.total_mass_balance_residual_kg_s
        ca_res = sim.state.elemental_ca_residual_kg_s
        si_res = sim.state.elemental_si_residual_kg_s

        assert total_res < 1e-10, f"Total mass balance residual {total_res:.3e} exceeds 1e-10"
        assert ca_res < 1e-10, f"Elemental Ca residual {ca_res:.3e} exceeds 1e-10"
        assert si_res < 1e-10, f"Elemental Si residual {si_res:.3e} exceeds 1e-10"

    def test_invalid_timestep_fail_closed(self) -> None:
        """Requirement 5: Verify negative or zero duration or dt fails closed."""
        sim = RotaryKilnSimulator()
        res_zero = sim.advance_time(duration_s=0.0, dt=0.05)
        assert res_zero.status == AgentStatus.FAILED
        assert res_zero.error_code == "INVALID_TIMESTEP"

        res_neg = sim.advance_time(duration_s=1.0, dt=-0.05)
        assert res_neg.status == AgentStatus.FAILED
        assert res_neg.error_code == "INVALID_TIMESTEP"

    def test_drive_motor_disabled_decay(self) -> None:
        """Requirement 5: Verify kiln transitions to shutdown decay mode when permissive is cleared."""
        sim = RotaryKilnSimulator()
        sim.state.kiln_drive_permissive = False
        initial_tbz = sim.state.t_burning_zone_c

        sim.advance_time(duration_s=2.0, dt=0.05)
        assert sim.state.t_burning_zone_c <= initial_tbz

    def test_step_function_compatibility(self) -> None:
        """Requirement 5: Verify W080 step() legacy wrapper functions correctly."""
        sim = RotaryKilnSimulator()
        sim.step(dt=0.5)
        assert sim.simulation_time_s > 0.0
        assert len(sim.T_s) == sim.N
        assert len(sim.T_g) == sim.N


# ============================================================================
# 6. Section 6: Process Safety Trips & Horner Coil Assertion (%M228..%M230)
# ============================================================================

class TestSection6ProcessSafetyInterlocks:
    """Tests for process safety trips (0xA201, 0xA202, 0xA203, 0xA204) and Horner coils (%M228, %M229, %M230)."""

    def test_burning_zone_overtemp_trip_0xa201(self) -> None:
        """Requirement 6: Burning zone temp > 1550 C asserts %M229, clears %M228, sets code 0xA201."""
        sim = RotaryKilnSimulator()
        sim.state.t_burning_zone_c = 1580.0  # > 1550.0 C
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.reg_table.read_bit("%M229") is True
        assert sim.reg_table.read_bit("%M228") is False
        assert (sim.reg_table.read_word("%R987") & 0xFFFF) == int(RotaryKilnDiagnosticCode.KILN_ERR_BURNING_ZONE_OVERTEMP)

    def test_low_alite_clinker_quality_alarm_0xa202(self) -> None:
        """Requirement 6: Alite (C3S) < 50.0% asserts %M230 and flags 0xA202."""
        sim = RotaryKilnSimulator()
        sim.state.alite_c3s_pct = 45.0  # < 50.0%
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.reg_table.read_bit("%M230") is True
        assert (sim.reg_table.read_word("%R987") & 0xFFFF) == int(RotaryKilnDiagnosticCode.KILN_ERR_LOW_ALITE_FORMATION)

    def test_drive_overtorque_trip_0xa203(self) -> None:
        """Requirement 6: Drive motor torque > 180.0 kN*m clears %M228 and flags 0xA203."""
        sim = RotaryKilnSimulator()
        sim.state.drive_torque_knm = 195.0  # > 180.0 kN*m
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.reg_table.read_bit("%M228") is False
        assert (sim.reg_table.read_word("%R987") & 0xFFFF) == int(RotaryKilnDiagnosticCode.KILN_ERR_DRIVE_OVERTORQUE)

    def test_incomplete_calcination_trip_0xa204(self) -> None:
        """Requirement 6: Calcination conversion < 85.0% flags 0xA204."""
        sim = RotaryKilnSimulator()
        sim.state.calcination_conversion_pct = 78.0  # < 85.0%
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert (sim.reg_table.read_word("%R987") & 0xFFFF) == int(RotaryKilnDiagnosticCode.KILN_ERR_INCOMPLETE_CALCINATION)

    def test_diagnostic_code_priority_hierarchy(self) -> None:
        """Requirement 6: Priority hierarchy: Overtemp (0xA201) > Drive Torque (0xA203) > Incomplete Calc (0xA204) > Low Alite (0xA202)."""
        sim = RotaryKilnSimulator()
        sim.state.t_burning_zone_c = 1580.0          # 0xA201
        sim.state.drive_torque_knm = 195.0           # 0xA203
        sim.state.calcination_conversion_pct = 78.0  # 0xA204
        sim.state.alite_c3s_pct = 45.0               # 0xA202
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        # Highest priority (0xA201) must take precedence
        assert (sim.reg_table.read_word("%R987") & 0xFFFF) == int(RotaryKilnDiagnosticCode.KILN_ERR_BURNING_ZONE_OVERTEMP)


# ============================================================================
# 7. Section 7: Horner OCS Register Space Synchronization (%R980..%R987, %M228..%M230)
# ============================================================================

class TestSection7HornerOCSSync:
    """Tests for Horner OCS memory register bindings (%R980..%R987, %M228..%M230) and class compatibility aliases."""

    def test_nominal_register_sync(self) -> None:
        """Requirement 7: Verify analog registers %R980..%R987 and discrete coils %M228..%M230."""
        sim = RotaryKilnSimulator()
        sim.advance_time(duration_s=0.5, dt=0.05)
        reg = sim.reg_table

        # %R980: BurningZoneTempCelsius (INT16, scaled x10 C, e.g. 14500 = 1450.0 C)
        assert 14000 <= reg.read_word("%R980") <= 15000

        # %R981: CalcinationZoneTempCelsius (INT16, scaled x10 C, e.g. 9200 = 920.0 C)
        assert 8800 <= reg.read_word("%R981") <= 9600

        # %R982: KilnDriveTorqueKnm (INT16, scaled x10 kN*m, e.g. 850 = 85.0 kN*m)
        assert 800 <= reg.read_word("%R982") <= 900

        # %R983: KilnRotationSpeedRpm (INT16, scaled x100 RPM, e.g. 350 = 3.50 RPM)
        assert reg.read_word("%R983") == 350

        # %R984: ClinkerAliteContentPct (INT16, scaled x10 %, e.g. 625 = 62.5%)
        assert 600 <= reg.read_word("%R984") <= 650

        # %R985: FreeLimeContentPct (INT16, scaled x100 %, e.g. 120 = 1.20%)
        assert 100 <= reg.read_word("%R985") <= 150

        # %R986: FuelFiringRateKgh (INT16, scaled x10 kg/h, e.g. 4500 = 450.0 kg/h)
        assert reg.read_word("%R986") == 4500

        # %R987: DiagnosticStatusCode (0x0000 = OK)
        assert (reg.read_word("%R987") & 0xFFFF) == 0x0000

        # %M228: KilnDrivePermissive (BOOL)
        assert reg.read_bit("%M228") is True

        # %M229: HotSpotRefractoryTrip (BOOL)
        assert reg.read_bit("%M229") is False

        # %M230: HighFreeLimeAlarm (BOOL)
        assert reg.read_bit("%M230") is False

    def test_class_compatibility_aliases(self) -> None:
        """Requirement 7: Verify all required class and module aliases exist."""
        assert RotaryKilnClinkerizationSimulator is RotaryKilnSimulator
        assert KilnSimulator is RotaryKilnSimulator
        assert RotaryKilnEngine is RotaryKilnSimulator
        assert RotaryKilnSimulationEngine is RotaryKilnSimulator
        assert RotaryKilnModel is RotaryKilnSimulator
        assert RotaryKilnPlantModel is RotaryKilnSimulator
        assert KilnModel is RotaryKilnSimulator
        assert KilnPlantModel is RotaryKilnSimulator

        assert RotaryKilnClinkerizationConfig is RotaryKilnConfig
        assert KilnConfig is RotaryKilnConfig
        assert RotaryKilnParameters is RotaryKilnConfig
        assert KilnParameters is RotaryKilnConfig

        assert RotaryKilnClinkerizationState is RotaryKilnState
        assert KilnState is RotaryKilnState

        assert RotaryKilnClinkerizationStatusBits is RotaryKilnStatusBits
        assert KilnStatusBits is RotaryKilnStatusBits
        assert RotaryKilnStatusWord is RotaryKilnStatusBits
        assert RotaryKilnClinkerizationStatusWord is RotaryKilnStatusBits
        assert KilnStatusWord is RotaryKilnStatusBits

        assert RotaryKilnClinkerizationDiagnosticCode is RotaryKilnDiagnosticCode
        assert KilnDiagnosticCode is RotaryKilnDiagnosticCode


# ============================================================================
# 8. Section 8: 9-Stage Verification Suite Integration Test & Evidence JSON
# ============================================================================

class TestSection8RotaryKilnVerificationRunner:
    """Tests for run_rotary_kiln_verification function and evidence artifact generation."""

    def test_run_rotary_kiln_verification_suite_all_9_stages(self, tmp_path: Path) -> None:
        """Requirement 8: Execute full 9-stage verification suite and assert strict success."""
        out_file = str(tmp_path / "w137_rotary_kiln_verification_evidence.json")
        res = run_rotary_kiln_verification(output_path=out_file)

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert "Industrial Rotary Kiln Clinkerization Thermal Reaction Kinetics & Bed Dynamics ODE Simulation verified cleanly (9/9 checks passed)" in res["details"]

        data = res["data"]
        assert data["work_package"] == "W137"
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

    def test_run_rotary_kiln_verification_evidence_path_parameter(self, tmp_path: Path) -> None:
        """Requirement 8: Test evidence_path compatibility alias parameter."""
        ev_file = tmp_path / "kiln_alias_evidence.json"
        res = run_rotary_kiln_verification(evidence_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()

    def test_run_rotary_kiln_clinkerization_verification_function_alias(self, tmp_path: Path) -> None:
        """Requirement 8: Test run_rotary_kiln_clinkerization_verification function alias."""
        ev_file = tmp_path / "kiln_func_alias_evidence.json"
        res = run_rotary_kiln_clinkerization_verification(output_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()
