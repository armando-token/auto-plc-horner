"""Unit and Integration Tests for Industrial Supercritical CO2 Brayton Power Cycle & Compressor Dynamics ODE Simulation.

Work Package: W140 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1010..%R1017, %M235..%M237).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Near-critical CO2 real-gas equations of state, density rise, and compressibility Z factor.
4. Section 4: Closed-loop Brayton cycle heat transfer, turbine/compressor power, and thermal efficiency.
5. Section 5: Coupled ODE RK4 integration stability and dual mass and enthalpy conservation residuals (< 1e-10).
6. Section 6: Process safety trips (0xA501, 0xA502, 0xA503, 0xA504) and Horner coil assertion (%M235, %M236, %M237).
7. Section 7: Horner OCS register space synchronization (%R1010..%R1017, %M235..%M237).
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
from jev_cscape.simulation.supercritical_co2 import (
    SCO2_BRAYTON_DYNAMICS_SYNC_POU,
    SUPERCRITICAL_BRAYTON_SYNC_POU,
    SUPERCRITICAL_CO2_BRAYTON_PURE_ST_POU,
    SUPERCRITICAL_CO2_BRAYTON_SYNC_POU,
    SUPERCRITICAL_CO2_PURE_ST_POU,
    SUPERCRITICAL_CO2_SYNC_POU,
    SupercriticalBraytonConfig,
    SupercriticalBraytonDiagnosticCode,
    SupercriticalBraytonPlantModel,
    SupercriticalBraytonSimulator,
    SupercriticalBraytonState,
    SupercriticalBraytonStatusBits,
    SupercriticalBraytonStatusWord,
    SupercriticalCO2BraytonConfig,
    SupercriticalCO2BraytonDiagnosticCode,
    SupercriticalCO2BraytonSimulator,
    SupercriticalCO2BraytonState,
    SupercriticalCO2BraytonStatusBits,
    SupercriticalCO2Config,
    SupercriticalCO2DiagnosticCode,
    SupercriticalCO2Engine,
    SupercriticalCO2Model,
    SupercriticalCO2PlantModel,
    SupercriticalCO2SimulationEngine,
    SupercriticalCO2Simulator,
    SupercriticalCO2State,
    SupercriticalCO2StatusBits,
    SupercriticalCO2StatusWord,
    SupercriticalCo2Config,
    SupercriticalCo2DiagnosticCode,
    SupercriticalCo2Model,
    SupercriticalCo2SimulationEngine,
    SupercriticalCo2Simulator,
    SupercriticalCo2State,
    SupercriticalCo2StatusBits,
    SupercriticalDiagCode,
    SupercriticalParameters,
    SupercriticalStatusBits,
    run_brayton_cycle_verification,
    run_supercritical_co2_brayton_verification,
    run_supercritical_co2_verification,
    verify_supercritical_co2_brayton_pure_st,
    verify_supercritical_co2_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1010..%R1017, %M235..%M237)."""

    def test_verify_supercritical_co2_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_supercritical_co2_pure_st() is True
        assert verify_supercritical_co2_brayton_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1010..%R1017, %M235..%M237)."""
        SecurityGuard.assert_pure_st_content(SUPERCRITICAL_CO2_PURE_ST_POU)
        val = STParser.validate_code(SUPERCRITICAL_CO2_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(SUPERCRITICAL_CO2_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "SupercriticalCO2BraytonSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1010", "%R1011", "%R1012", "%R1013",
            "%R1014", "%R1015", "%R1016", "%R1017",
            "%M235", "%M236", "%M237",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_pure_st_pou_brayton_alias_ast(self) -> None:
        """Requirement 1: Verify SupercriticalCO2BraytonSync aliases parse cleanly."""
        for pou_text in [
            SUPERCRITICAL_CO2_BRAYTON_PURE_ST_POU,
            SUPERCRITICAL_CO2_BRAYTON_SYNC_POU,
            SUPERCRITICAL_BRAYTON_SYNC_POU,
            SUPERCRITICAL_CO2_SYNC_POU,
        ]:
            SecurityGuard.assert_pure_st_content(pou_text)
            ast = STParser.parse_pou(pou_text)
            assert ast is not None
            assert ast.name == "SupercriticalCO2BraytonSync"
            assert ast.pou_type == POUType.PROGRAM
            for reg in [
                "%R1010", "%R1011", "%R1012", "%R1013",
                "%R1014", "%R1015", "%R1016", "%R1017",
                "%M235", "%M236", "%M237",
            ]:
                assert reg in ast.bound_registers

    def test_pure_st_pou_alias_equivalence(self) -> None:
        """Requirement 1: Verify POU aliases are defined and consistent."""
        assert SUPERCRITICAL_CO2_PURE_ST_POU == SUPERCRITICAL_CO2_BRAYTON_PURE_ST_POU
        assert SUPERCRITICAL_CO2_PURE_ST_POU == SUPERCRITICAL_CO2_BRAYTON_SYNC_POU
        assert SUPERCRITICAL_CO2_PURE_ST_POU == SUPERCRITICAL_BRAYTON_SYNC_POU
        assert SUPERCRITICAL_CO2_PURE_ST_POU == SUPERCRITICAL_CO2_SYNC_POU

    def test_pure_st_pou_internal_variables_and_control_logic(self) -> None:
        """Requirement 1: Verify internal boolean variables and interlock IF-branches."""
        ast = STParser.parse_pou(SUPERCRITICAL_CO2_PURE_ST_POU)
        assert ast is not None
        var_names = [v.name for v in ast.variables]
        assert "CoolingWaterPermissive" in var_names
        assert "GeneratorBreakerClosed" in var_names
        assert "RecuperatorBypassValve" in var_names
        assert "LubricationOilPressureOk" in var_names
        assert "InventoryControlPermissive" in var_names

        stmts = "\n".join(ast.raw_statements)
        assert "IF TurbineInletTempCelsius > 6500 THEN" in stmts
        assert "DiagnosticStatusCode := 16#A501;" in stmts
        assert "ELSIF CompressorDischargePressureBar > 2500 THEN" in stmts
        assert "DiagnosticStatusCode := 16#A503;" in stmts
        assert "ELSIF (CompressorInletDensityKgM3 < 500) OR (MassFlowRateKgS < 50) THEN" in stmts
        assert "DiagnosticStatusCode := 16#A502;" in stmts
        assert "ELSIF (ThermalEfficiencyPct < 200) AND (NetTurbinePowerKw > 1000) THEN" in stmts
        assert "DiagnosticStatusCode := 16#A504;" in stmts


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
            "XIC BraytonCyclePermissive",
            "XIO TurbineOvertempTrip",
            "OTE CompressorSurgeTrip",
            "OTL CoolingWaterPermissive",
            "OTU GeneratorBreakerClosed",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: Verify all ladder constructs raise LadderForbiddenError."""
        bad_code = f"{SUPERCRITICAL_CO2_PURE_ST_POU}\n{ladder_snippet}\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

        val = STParser.validate_code(bad_code)
        assert val.status == AgentStatus.FAILED
        assert val.error_code == "ERR_LADDER_FORBIDDEN"
        assert val.data.get("ladder_rejected") is True


# ============================================================================
# 3. Section 3: Near-Critical CO2 Real-Gas Equations of State & Compressibility
# ============================================================================

class TestSection3NearCriticalCO2EOSAndCompressibility:
    """Tests for near-critical CO2 real-gas equations of state, steep density rise, and Z factor."""

    def test_critical_constants_and_peng_robinson_eos(self) -> None:
        """Requirement 3: Verify CO2 critical parameters (Tc=304.13K, Pc=7.377MPa) and PR-EOS."""
        sim = SupercriticalCO2BraytonSimulator()
        cfg = sim.config

        assert math.isclose(cfg.tc_k, 304.13, abs_tol=0.01)
        assert math.isclose(cfg.pc_pa, 7.3773e6, rel_tol=1e-3)
        assert math.isclose(cfg.omega, 0.22394, abs_tol=1e-3)
        assert math.isclose(cfg.mw_kg_mol, 0.04401, abs_tol=1e-4)

    def test_steep_density_rise_near_critical_point(self) -> None:
        """Requirement 3: Verify dramatic density rise (> 2.5x) near critical point (P=7.8 MPa, T=305 K vs 330 K)."""
        sim = SupercriticalCO2BraytonSimulator()

        # Near-critical temperature (305.15 K / 32.0 °C, just 1.0 K above Tc): liquid-like dense phase
        rho_near = sim.peng_robinson_density(7.8e6, 305.15)
        # Warmer temperature (330.15 K / 57.0 °C): gas-like dense phase
        rho_warm = sim.peng_robinson_density(7.8e6, 330.15)

        assert rho_near >= 500.0, f"Near-critical density {rho_near:.1f} kg/m3 must exceed 500 kg/m3"
        assert rho_warm < 250.0, f"Warm density {rho_warm:.1f} kg/m3 must be below 250 kg/m3"

        density_ratio = rho_near / rho_warm
        assert density_ratio > 2.5, f"Density rise ratio {density_ratio:.2f} must exceed 2.5x"

    def test_compressibility_z_factor_drop_near_critical_point(self) -> None:
        """Requirement 3: Verify compressibility factor Z drops into [0.20, 0.45] near critical point."""
        sim = SupercriticalCO2BraytonSimulator()

        # Near-critical condition (7.8 MPa, 305.15 K)
        z_near = sim.peng_robinson_compressibility_z(7.8e6, 305.15)
        assert 0.20 <= z_near <= 0.45, f"Compressibility factor Z={z_near:.3f} must be in [0.20, 0.45]"

        # High-temperature low-pressure gas behavior (Z approaches ~1.0)
        z_hot = sim.peng_robinson_compressibility_z(1.0e6, 600.0)
        assert 0.95 <= z_hot <= 1.05, f"High temperature low pressure Z={z_hot:.3f} must approach 1.0"

        # High-temperature turbine inlet conditions (20 MPa, 823.15 K / 550 °C)
        z_tit = sim.peng_robinson_compressibility_z(20.0e6, 823.15)
        assert 0.90 <= z_tit <= 1.20, f"Turbine inlet Z={z_tit:.3f} expected near ideal"

    def test_real_gas_density_monotonicity_pressure_and_temperature(self) -> None:
        """Requirement 3: Verify thermodynamic monotonicity: d(rho)/dP > 0 and d(rho)/dT < 0."""
        sim = SupercriticalCO2BraytonSimulator()

        # Pressure monotonicity: rho(25 MPa) > rho(20 MPa) > rho(10 MPa) at 400 K
        rho_p10 = sim.peng_robinson_density(10.0e6, 400.0)
        rho_p20 = sim.peng_robinson_density(20.0e6, 400.0)
        rho_p25 = sim.peng_robinson_density(25.0e6, 400.0)
        assert rho_p25 > rho_p20 > rho_p10

        # Temperature monotonicity: rho(310 K) > rho(350 K) > rho(400 K) at 20 MPa
        rho_t310 = sim.peng_robinson_density(20.0e6, 310.0)
        rho_t350 = sim.peng_robinson_density(20.0e6, 350.0)
        rho_t400 = sim.peng_robinson_density(20.0e6, 400.0)
        assert rho_t310 > rho_t350 > rho_t400

    def test_peng_robinson_density_correlation_wrapper(self) -> None:
        """Requirement 3: Verify peng_robinson_density_correlation accepts MPa directly."""
        sim = SupercriticalCO2BraytonSimulator()
        rho_mpa = sim.peng_robinson_density_correlation(20.0, 310.0)
        rho_pa = sim.peng_robinson_density(20.0e6, 310.0)
        assert math.isclose(rho_mpa, rho_pa, rel_tol=1e-9)

        # Chrastil solubility compatibility wrapper
        c_sat = sim.chrastil_solubility(rho_mpa, 310.0)
        assert c_sat >= 0.0
        assert sim.chrastil_solubility(0.0, 310.0) == 0.0


# ============================================================================
# 4. Section 4: Closed-Loop Brayton Cycle Power, Heat Transfer & Efficiency
# ============================================================================

class TestSection4ClosedLoopBraytonCycleThermodynamics:
    """Tests for Brayton cycle turbine/compressor power, recuperator heat transfer, and thermal efficiency."""

    def test_compressor_power_reduction_due_to_near_critical_density(self) -> None:
        """Requirement 4: Verify compressor power is dramatically lower than turbine power (W_comp/W_turb < 0.40)."""
        sim = SupercriticalCO2BraytonSimulator()
        th = sim.compute_cycle_thermodynamics(
            p_high_mpa=20.0,
            p_low_mpa=7.8,
            t_tit_k=823.15,
            t_cin_k=305.15,
            mass_flow_kg_s=25.0,
        )

        w_comp = th["w_comp_kw"]
        w_turb = th["w_turb_kw"]
        ratio = w_comp / w_turb

        assert w_comp > 0.0
        assert w_turb > 10000.0
        assert ratio < 0.40, f"Compressor to turbine work ratio {ratio:.3f} must be < 0.40 due to dense sCO2"

    def test_turbine_power_expansion_and_enthalpy_drop(self) -> None:
        """Requirement 4: Verify multi-megawatt turbine power output (W_turb >= 10,000 kW)."""
        sim = SupercriticalCO2BraytonSimulator()
        th = sim.compute_cycle_thermodynamics(
            p_high_mpa=20.0,
            p_low_mpa=7.8,
            t_tit_k=823.15,
            t_cin_k=305.15,
            mass_flow_kg_s=25.0,
        )

        assert th["w_turb_kw"] >= 10000.0, f"Turbine power {th['w_turb_kw']} kW must exceed 10 MW"
        assert th["w_net_kw"] >= 8000.0, f"Net power {th['w_net_kw']} kW must exceed 8 MW"

    def test_recuperator_heat_transfer_effectiveness(self) -> None:
        """Requirement 4: Verify internal recuperation duty preheats high-pressure cold fluid."""
        sim = SupercriticalCO2BraytonSimulator()
        th = sim.compute_cycle_thermodynamics(
            p_high_mpa=20.0,
            p_low_mpa=7.8,
            t_tit_k=823.15,
            t_cin_k=305.15,
            mass_flow_kg_s=25.0,
        )

        recup_duty = th["recuperator_duty_kw"]
        assert recup_duty >= 5000.0, f"Recuperator duty {recup_duty:.1f} kW must exceed 5 MW"

    def test_cycle_thermal_efficiency_first_law_balance(self) -> None:
        """Requirement 4: Verify thermal efficiency in [35.0%, 52.0%] and exact 1st Law closure (Q_in - Q_out == W_net)."""
        sim = SupercriticalCO2BraytonSimulator()
        th = sim.compute_cycle_thermodynamics(
            p_high_mpa=20.0,
            p_low_mpa=7.8,
            t_tit_k=823.15,
            t_cin_k=305.15,
            mass_flow_kg_s=25.0,
        )

        eta_th = th["eta_th_pct"]
        assert 35.0 <= eta_th <= 52.0, f"Cycle thermal efficiency {eta_th:.1f}% outside nominal band [35%, 52%]"

        # 1st Law of Thermodynamics energy balance: Q_in - Q_out == W_net identically
        q_in = th["q_in_kw"]
        q_out = th["q_out_kw"]
        w_net = th["w_net_kw"]
        first_law_error = abs((q_in - q_out) - w_net)
        assert first_law_error < 1e-9, f"First law residual {first_law_error:.3e} kW must be zero"

    def test_mass_flow_rate_power_scaling(self) -> None:
        """Requirement 4: Verify mechanical power and heat duties scale linearly with mass flow rate."""
        sim = SupercriticalCO2BraytonSimulator()
        th_10 = sim.compute_cycle_thermodynamics(20.0, 7.8, 823.15, 305.15, mass_flow_kg_s=10.0)
        th_20 = sim.compute_cycle_thermodynamics(20.0, 7.8, 823.15, 305.15, mass_flow_kg_s=20.0)

        assert math.isclose(th_20["w_net_kw"] / th_10["w_net_kw"], 2.0, rel_tol=1e-3)
        assert math.isclose(th_20["w_turb_kw"] / th_10["w_turb_kw"], 2.0, rel_tol=1e-3)


# ============================================================================
# 5. Section 5: Coupled ODE RK4 Integration Stability & Conservation Residuals
# ============================================================================

class TestSection5CoupledODEAndRK4Solver:
    """Tests for coupled ODE RK4 integration stability and dual mass and enthalpy conservation residuals (< 1e-10)."""

    def test_coupled_ode_rk4_integration_stability(self) -> None:
        """Requirement 5: Verify RK4 numerical integration produces smooth, stable trajectories."""
        sim = SupercriticalCO2BraytonSimulator()
        res = sim.advance_time(duration_s=2.0, dt=0.01)
        assert res.status == AgentStatus.SUCCESS

        st = sim.state
        assert not math.isnan(st.t_turbine_in_c)
        assert not math.isnan(st.p_high_bar)
        assert not math.isnan(st.p_low_bar)
        assert not math.isnan(st.net_power_kw)
        assert not math.isnan(st.thermal_efficiency_pct)

        assert 500.0 <= st.t_turbine_in_c <= 600.0
        assert 180.0 <= st.p_high_bar <= 220.0
        assert 70.0 <= st.p_low_bar <= 85.0
        assert st.net_power_kw > 1000.0
        assert 35.0 <= st.thermal_efficiency_pct <= 52.0

    def test_dual_mass_and_enthalpy_conservation_residuals(self) -> None:
        """Requirement 5: Verify dual mass balance and enthalpy conservation residuals < 1e-10."""
        sim = SupercriticalCO2BraytonSimulator()
        sim.advance_time(duration_s=1.0, dt=0.01)

        mass_res = sim.state.total_mass_balance_residual_kg_s
        enth_res = sim.state.enthalpy_conservation_residual_w

        assert mass_res < 1e-10, f"Mass balance residual {mass_res:.3e} kg/s must be < 1e-10"
        assert enth_res < 1e-10, f"Enthalpy residual {enth_res:.3e} W must be < 1e-10"

    def test_invalid_timestep_fail_closed(self) -> None:
        """Requirement 5: Verify negative or zero duration or dt fails closed."""
        sim = SupercriticalCO2BraytonSimulator()
        res_zero = sim.advance_time(duration_s=0.0, dt=0.01)
        assert res_zero.status == AgentStatus.FAILED
        assert res_zero.error_code == "INVALID_TIMESTEP"

        res_neg = sim.advance_time(duration_s=1.0, dt=-0.01)
        assert res_neg.status == AgentStatus.FAILED
        assert res_neg.error_code == "INVALID_TIMESTEP"

    def test_permissive_disabled_coastdown_decay(self) -> None:
        """Requirement 5: Verify cycle transitions to coastdown/decay when permissive is cleared."""
        sim = SupercriticalCO2BraytonSimulator()
        sim.state.brayton_cycle_permissive = False
        initial_power = sim.state.net_power_kw

        sim.advance_time(duration_s=1.0, dt=0.01)
        assert sim.state.net_power_kw < initial_power

    def test_advance_time_and_step_compatibility(self) -> None:
        """Requirement 5: Verify step() compatibility wrapper advances time identically."""
        sim = SupercriticalCO2BraytonSimulator()
        sim.step(dt=0.05)
        assert math.isclose(sim.state.time_s, 0.05, abs_tol=1e-5)


# ============================================================================
# 6. Section 6: Process Safety Trips & Horner Coil Assertion (%M235..%M237)
# ============================================================================

class TestSection6ProcessSafetyInterlocks:
    """Tests for process safety trips (0xA501, 0xA502, 0xA503, 0xA504) and Horner coils (%M235, %M236, %M237)."""

    def test_turbine_overtemp_trip_0xa501(self) -> None:
        """Requirement 6: Turbine inlet temp > 650.0 C asserts %M236, clears %M235, sets 0xA501."""
        sim = SupercriticalCO2BraytonSimulator()
        sim.state.t_turbine_in_c = 670.0  # > 650.0 C
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.reg_table.read_bit("%M236") is True
        assert sim.reg_table.read_bit("%M235") is False
        assert (sim.reg_table.read_word("%R1017") & 0xFFFF) == int(SupercriticalCO2BraytonDiagnosticCode.ERR_TURBINE_OVERTEMP)

    def test_compressor_surge_trip_0xa502(self) -> None:
        """Requirement 6: Compressor inlet density < 500 kg/m3 asserts %M237, clears %M235, sets 0xA502."""
        sim = SupercriticalCO2BraytonSimulator()
        sim.state.rho_compressor_in = 450.0  # < 500.0 kg/m^3
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.reg_table.read_bit("%M237") is True
        assert sim.reg_table.read_bit("%M235") is False
        assert (sim.reg_table.read_word("%R1017") & 0xFFFF) == int(SupercriticalCO2BraytonDiagnosticCode.ERR_COMPRESSOR_SURGE)

    def test_cycle_overpressure_trip_0xa503(self) -> None:
        """Requirement 6: High-side pressure > 25.0 MPa (250 bar) clears %M235 and sets 0xA503."""
        sim = SupercriticalCO2BraytonSimulator()
        sim.state.p_high_mpa = 26.5  # > 25.0 MPa
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.reg_table.read_bit("%M235") is False
        assert (sim.reg_table.read_word("%R1017") & 0xFFFF) == int(SupercriticalCO2BraytonDiagnosticCode.ERR_CYCLE_OVERPRESSURE)

    def test_thermal_efficiency_collapse_trip_0xa504(self) -> None:
        """Requirement 6: Thermal efficiency < 20.0% flags 0xA504."""
        sim = SupercriticalCO2BraytonSimulator()
        sim.state.thermal_efficiency_pct = 15.0  # < 20.0%
        sim.state.net_power_kw = 5000.0         # Generating power
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert (sim.reg_table.read_word("%R1017") & 0xFFFF) == int(SupercriticalCO2BraytonDiagnosticCode.ERR_EFFICIENCY_COLLAPSE)

    def test_safety_trip_priority_hierarchy(self) -> None:
        """Requirement 6: Priority hierarchy: Overtemp (0xA501) > Overpressure (0xA503) > Surge (0xA502) > Efficiency (0xA504)."""
        sim = SupercriticalCO2BraytonSimulator()

        # All four faults active simultaneously
        sim.state.t_turbine_in_c = 670.0        # 0xA501
        sim.state.p_high_mpa = 26.5             # 0xA503
        sim.state.rho_compressor_in = 450.0     # 0xA502
        sim.state.thermal_efficiency_pct = 15.0 # 0xA504
        sim.state.net_power_kw = 5000.0

        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        # Top priority: 0xA501
        assert (sim.reg_table.read_word("%R1017") & 0xFFFF) == int(SupercriticalCO2BraytonDiagnosticCode.ERR_TURBINE_OVERTEMP)

        # Clear Overtemp -> Next priority is 0xA503
        sim.state.t_turbine_in_c = 550.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert (sim.reg_table.read_word("%R1017") & 0xFFFF) == int(SupercriticalCO2BraytonDiagnosticCode.ERR_CYCLE_OVERPRESSURE)

        # Clear Overpressure -> Next priority is 0xA502
        sim.state.p_high_mpa = 20.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert (sim.reg_table.read_word("%R1017") & 0xFFFF) == int(SupercriticalCO2BraytonDiagnosticCode.ERR_COMPRESSOR_SURGE)

        # Clear Surge -> Next priority is 0xA504
        sim.state.rho_compressor_in = 620.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert (sim.reg_table.read_word("%R1017") & 0xFFFF) == int(SupercriticalCO2BraytonDiagnosticCode.ERR_EFFICIENCY_COLLAPSE)


# ============================================================================
# 7. Section 7: Horner OCS Register Space Synchronization (%R1010..%R1017, %M235..%M237)
# ============================================================================

class TestSection7HornerOCSSync:
    """Tests for Horner OCS memory register bindings (%R1010..%R1017, %M235..%M237) and class compatibility aliases."""

    def test_nominal_register_sync(self) -> None:
        """Requirement 7: Verify analog registers %R1010..%R1017 and discrete coils %M235..%M237."""
        sim = SupercriticalCO2BraytonSimulator()
        sim.advance_time(duration_s=0.5, dt=0.01)
        reg = sim.reg_table

        # %R1010: TurbineInletTempCelsius (INT16, scaled x10 C, e.g. 5500 = 550.0 C)
        assert reg.read_word("%R1010") == 5500

        # %R1011: CompressorDischargePressureBar (INT16, scaled x10 bar, e.g. 2000 = 200.0 bar)
        assert reg.read_word("%R1011") == 2000

        # %R1012: CompressorInletDensityKgM3 (INT16, scaled x1 kg/m^3, e.g. 540 kg/m^3)
        assert reg.read_word("%R1012") >= 500

        # %R1013: NetTurbinePowerKw (INT16, scaled x1 kW)
        assert reg.read_word("%R1013") >= 5000

        # %R1014: CompressorPowerKw (INT16, scaled x1 kW)
        assert reg.read_word("%R1014") >= 1000

        # %R1015: ThermalEfficiencyPct (INT16, scaled x10 %, e.g. 425 = 42.5%)
        assert 350 <= reg.read_word("%R1015") <= 520

        # %R1016: MassFlowRateKgS (INT16, scaled x10 kg/s, e.g. 250 = 25.0 kg/s)
        assert reg.read_word("%R1016") == 250

        # %R1017: DiagnosticStatusCode (0x0000 = OK)
        assert (reg.read_word("%R1017") & 0xFFFF) == 0x0000

        # %M235: BraytonCyclePermissive (BOOL)
        assert reg.read_bit("%M235") is True

        # %M236: TurbineOvertempTrip (BOOL)
        assert reg.read_bit("%M236") is False

        # %M237: CompressorSurgeTrip (BOOL)
        assert reg.read_bit("%M237") is False

    def test_class_compatibility_aliases(self) -> None:
        """Requirement 7: Verify all required class and module aliases exist."""
        assert SupercriticalCO2BraytonSimulator is SupercriticalCO2Simulator
        assert SupercriticalBraytonSimulator is SupercriticalCO2Simulator
        assert SupercriticalCO2Engine is SupercriticalCO2Simulator
        assert SupercriticalCO2PlantModel is SupercriticalCO2Simulator
        assert SupercriticalBraytonPlantModel is SupercriticalCO2Simulator
        assert SupercriticalCO2SimulationEngine is SupercriticalCO2Simulator
        assert SupercriticalCo2SimulationEngine is SupercriticalCO2Simulator
        assert SupercriticalCo2Simulator is SupercriticalCO2Simulator
        assert SupercriticalCo2Model is SupercriticalCO2Simulator
        assert SupercriticalCO2Model is SupercriticalCO2Simulator

        assert SupercriticalCO2BraytonConfig is SupercriticalCO2Config
        assert SupercriticalBraytonConfig is SupercriticalCO2Config
        assert SupercriticalCo2Config is SupercriticalCO2Config
        assert SupercriticalParameters is SupercriticalCO2Config

        assert SupercriticalCO2BraytonState is SupercriticalCO2State
        assert SupercriticalBraytonState is SupercriticalCO2State
        assert SupercriticalCo2State is SupercriticalCO2State

        assert SupercriticalCO2BraytonStatusBits is SupercriticalCO2StatusBits
        assert SupercriticalBraytonStatusBits is SupercriticalCO2StatusBits
        assert SupercriticalStatusBits is SupercriticalCO2StatusBits
        assert SupercriticalCo2StatusBits is SupercriticalCO2StatusBits
        assert SupercriticalBraytonStatusWord is SupercriticalCO2StatusBits
        assert SupercriticalCO2StatusWord is SupercriticalCO2StatusBits

        assert SupercriticalCO2BraytonDiagnosticCode is SupercriticalCO2DiagnosticCode
        assert SupercriticalBraytonDiagnosticCode is SupercriticalCO2DiagnosticCode
        assert SupercriticalDiagCode is SupercriticalCO2DiagnosticCode
        assert SupercriticalCo2DiagnosticCode is SupercriticalCO2DiagnosticCode


# ============================================================================
# 8. Section 8: 9-Stage Verification Suite Integration Test & Evidence JSON
# ============================================================================

class TestSection8SupercriticalVerificationRunner:
    """Tests for run_supercritical_co2_verification function and evidence artifact generation."""

    def test_run_supercritical_co2_verification_suite_all_9_stages(self, tmp_path: Path) -> None:
        """Requirement 8: Execute full 9-stage verification suite and assert strict success."""
        out_file = str(tmp_path / "w140_supercritical_co2_evidence.json")
        res = run_supercritical_co2_verification(output_path=out_file)

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert "Industrial Supercritical CO2 Brayton Power Cycle & Compressor Dynamics ODE Simulation verified cleanly (9/9 checks passed)" in res["details"]

        data = res["data"]
        assert data["work_package"] == "W140"
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

    def test_run_supercritical_co2_verification_evidence_path_parameter(self, tmp_path: Path) -> None:
        """Requirement 8: Test evidence_path compatibility alias parameter."""
        ev_file = tmp_path / "sco2_alias_evidence.json"
        res = run_supercritical_co2_verification(evidence_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()

    def test_run_supercritical_co2_brayton_verification_function_alias(self, tmp_path: Path) -> None:
        """Requirement 8: Test run_supercritical_co2_brayton_verification function alias."""
        ev_file = tmp_path / "brayton_func_alias_evidence.json"
        res = run_supercritical_co2_brayton_verification(output_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()

    def test_run_brayton_cycle_verification_alias(self, tmp_path: Path) -> None:
        """Requirement 8: Test run_brayton_cycle_verification function alias."""
        ev_file = tmp_path / "brayton_cycle_evidence.json"
        res = run_brayton_cycle_verification(output_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()
