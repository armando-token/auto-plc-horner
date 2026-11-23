"""Unit and Integration Tests for Industrial Fluid Catalytic Cracking (FCC) Riser Simulation.

Work Package: W164 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1250..%R1257, %M291..%M293).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Gas-solid riser hydrodynamics, slip factor (psi = 1.2..2.0), superficial velocities (u_g = 15..25 m/s), voidage.
4. Section 4: 4-lump cracking reaction kinetics, endothermic enthalpy absorption (+480 kJ/kg), Arrhenius monotonicity.
5. Section 5: Coupled 6-state ODE RK4 integration stability and dual stoichiometric conservation residuals (< 1e-10).
6. Section 6: Process safety trips (0xBD01, 0xBD02, 0xBD03, 0xBD04), priority hierarchy, and Horner coil assertions (%M291..%M293).
7. Section 7: Horner OCS register space synchronization (%R1250..%R1257, %M291..%M293) with PrivilegeMode.SYSTEM.
8. Section 8: ILogicUnit scan cycle execution, dynamic disturbance response, and closed-loop settling stability.
9. Section 9: 9-stage verification suite integration test writing evidence JSON with strict 4-state contract.
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
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.fcc_riser import (
    DELTA_H_CRACK_J_KG,
    DELTA_H_CRACK_KJ_KG,
    DELTA_H_CRACKING_J_KG,
    DELTA_H_CRACKING_KJ_KG,
    FCC_RISER_DISENGAGER_PURE_ST_POU,
    FCC_RISER_DISENGAGER_SYNC_POU,
    FCC_RISER_DYNAMICS_SYNC_POU,
    FCC_RISER_PURE_ST_POU,
    FCC_RISER_SYNC_POU,
    FLUID_CATALYTIC_CRACKING_RISER_DISENGAGER_PURE_ST_POU,
    FLUID_CATALYTIC_CRACKING_RISER_DISENGAGER_SYNC_POU,
    FLUID_CATALYTIC_CRACKING_RISER_PURE_ST_POU,
    FLUID_CATALYTIC_CRACKING_RISER_SYNC_POU,
    FccRiserConfig,
    FccRiserDiagCode,
    FccRiserDiagnosticCode,
    FccRiserDisengagerConfig,
    FccRiserDisengagerDiagnosticCode,
    FccRiserDisengagerEngine,
    FccRiserDisengagerParameters,
    FccRiserDisengagerSimulator,
    FccRiserDisengagerState,
    FccRiserDisengagerStatusBits,
    FccRiserDisengagerStatusWord,
    FccRiserEngine,
    FccRiserLogicUnit,
    FccRiserModel,
    FccRiserParameters,
    FccRiserPlantModel,
    FccRiserSimulationEngine,
    FccRiserSimulator,
    FccRiserState,
    FccRiserStatusBits,
    FccRiserStatusWord,
    FluidCatalyticCrackingRiserConfig,
    FluidCatalyticCrackingRiserDiagnosticCode,
    FluidCatalyticCrackingRiserDisengagerConfig,
    FluidCatalyticCrackingRiserDisengagerDiagnosticCode,
    FluidCatalyticCrackingRiserDisengagerSimulator,
    FluidCatalyticCrackingRiserDisengagerState,
    FluidCatalyticCrackingRiserEngine,
    FluidCatalyticCrackingRiserSimulator,
    FluidCatalyticCrackingRiserState,
    FluidCatalyticCrackingRiserStatusBits,
    MW_CARBON,
    MW_COKE,
    MW_DRYGAS,
    MW_FEED,
    MW_GAS,
    MW_GASOIL,
    MW_GASOLINE,
    MW_LIGHT_GAS,
    MW_LPG,
    MW_OIL,
    MW_STEAM,
    MW_VGO,
    R_GAS_CONST,
    T_REF_K,
    T_ZERO_CELSIUS,
    run_fcc_riser_disengager_verification,
    run_fcc_riser_verification,
    run_fluid_catalytic_cracking_riser_disengager_verification,
    run_fluid_catalytic_cracking_riser_verification,
    run_riser_verification,
    verify_fcc_riser_disengager_pure_st,
    verify_fcc_riser_pure_st,
    verify_fluid_catalytic_cracking_riser_disengager_pure_st,
    verify_fluid_catalytic_cracking_riser_pure_st,
)


# ============================================================================
# 1. Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestSection1PureSTPouASTAndSymbolBinding:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings (%R1250..%R1257, %M291..%M293)."""

    def test_verify_fcc_riser_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_fcc_riser_pure_st() is True
        assert verify_fluid_catalytic_cracking_riser_pure_st() is True
        assert verify_fcc_riser_disengager_pure_st() is True
        assert verify_fluid_catalytic_cracking_riser_disengager_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers (%R1250..%R1257, %M291..%M293)."""
        SecurityGuard.assert_pure_st_content(FCC_RISER_DISENGAGER_PURE_ST_POU)
        val = STParser.validate_code(FCC_RISER_DISENGAGER_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(FCC_RISER_DISENGAGER_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "FccRiserDisengagerSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R1250", "%R1251", "%R1252", "%R1253",
            "%R1254", "%R1255", "%R1256", "%R1257",
            "%M291", "%M292", "%M293",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} missing from FccRiserDisengagerSync AST bindings"

    def test_pure_st_pou_aliases(self) -> None:
        """Requirement 1: Validate FluidCatalyticCrackingRiserSync alias POU AST."""
        ast_alias = STParser.parse_pou(FLUID_CATALYTIC_CRACKING_RISER_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "FluidCatalyticCrackingRiserSync"
        assert ast_alias.pou_type == POUType.PROGRAM
        expected_registers = [
            "%R1250", "%R1251", "%R1252", "%R1253",
            "%R1254", "%R1255", "%R1256", "%R1257",
            "%M291", "%M292", "%M293",
        ]
        for reg in expected_registers:
            assert reg in ast_alias.bound_registers, (
                f"Register {reg} missing from FluidCatalyticCrackingRiserSync AST bindings"
            )

    def test_pure_st_pou_disengager_alias(self) -> None:
        """Requirement 1: Validate FluidCatalyticCrackingRiserDisengagerSync alias POU AST."""
        ast_alias = STParser.parse_pou(FLUID_CATALYTIC_CRACKING_RISER_DISENGAGER_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "FluidCatalyticCrackingRiserDisengagerSync"
        assert ast_alias.pou_type == POUType.PROGRAM


# ============================================================================
# 2. Section 2: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection2AntiLadderSecurityGuard:
    """Tests for rejection of ladder logic contacts, coils, rungs, and mnemonics with ERR_LADDER_FORBIDDEN."""

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
            "XIC FccRiserPermissive",
            "XIO RiserThermalTrip",
            "OTE CycloneDiplegFloodedAlarm",
            "OTL RiserThermalTrip",
            "OTU FccRiserPermissive",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: Enforce pure ST by aggressively rejecting ladder constructs."""
        bad_code = f"""
        PROGRAM BadFccLadder
        VAR
            Permissive AT %M291 : BOOL;
        END_VAR
        {ladder_snippet}
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

        val = STParser.validate_code(bad_code)
        assert val.status == AgentStatus.FAILED
        assert val.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# 3. Section 3: Gas-Solid Riser Hydrodynamics & Slip Flow Mechanics
# ============================================================================

class TestSection3GasSolidRiserHydrodynamics:
    """Tests for gas-solid riser hydrodynamics, slip factor (1.2..2.0), superficial velocities (15..25 m/s), voidage."""

    def test_gas_solid_slip_factor_and_velocities(self) -> None:
        """Requirement 3: Verify gas superficial velocity, solid velocity, slip factor, and slip velocity."""
        sim = FccRiserSimulator()
        hydro = sim.compute_hydrodynamics(
            p_bar=2.5,
            temp_k=512.0 + T_ZERO_CELSIUS,
            oil_flow_kg_s=60.0,
            steam_flow_kg_s=3.0,
            cat_to_oil=6.5,
        )

        assert 15.0 <= hydro["u_gas_m_s"] <= 25.0
        assert 1.20 <= hydro["slip_ratio"] <= 2.00
        assert 8.0 <= hydro["u_solid_m_s"] <= 20.0
        assert hydro["u_gas_m_s"] > hydro["u_solid_m_s"]
        assert hydro["u_slip_m_s"] == pytest.approx(hydro["u_gas_m_s"] - hydro["u_solid_m_s"], abs=1e-6)

    def test_particle_and_gas_voidage(self) -> None:
        """Requirement 3: Verify gas voidage eps_g and solid volume fraction eps_s sum to unity."""
        sim = FccRiserSimulator()
        hydro = sim.compute_hydrodynamics(
            p_bar=2.5,
            temp_k=512.0 + T_ZERO_CELSIUS,
            oil_flow_kg_s=60.0,
            steam_flow_kg_s=3.0,
            cat_to_oil=6.5,
        )

        eps_g = hydro["voidage"]
        eps_s = hydro["solid_fraction"]

        assert 0.95 <= eps_g <= 0.999
        assert 0.005 <= eps_s <= 0.05
        assert abs((eps_g + eps_s) - 1.0) < 1.0e-12

    def test_residence_times_and_holdup(self) -> None:
        """Requirement 3: Verify gas and solid residence times and catalyst holdup in riser column."""
        sim = FccRiserSimulator()
        hydro = sim.compute_hydrodynamics(
            p_bar=2.5,
            temp_k=512.0 + T_ZERO_CELSIUS,
            oil_flow_kg_s=60.0,
            steam_flow_kg_s=3.0,
            cat_to_oil=6.5,
        )

        assert 1.0 <= hydro["residence_time_gas_s"] <= 3.0
        assert 1.5 <= hydro["residence_time_solid_s"] <= 4.0
        assert hydro["residence_time_solid_s"] > hydro["residence_time_gas_s"]
        assert 400.0 <= hydro["catalyst_holdup_kg"] <= 2500.0


# ============================================================================
# 4. Section 4: 4-Lump Catalytic Cracking Reaction Kinetics & Thermodynamics
# ============================================================================

class TestSection4FourLumpCrackingReactionKinetics:
    """Tests for 4-lump cracking reaction kinetics, endothermic enthalpy absorption (+480 kJ/kg), and Arrhenius monotonicity."""

    def test_reaction_enthalpies_values(self) -> None:
        """Requirement 4: Verify exact specified cracking reaction enthalpy (+480 kJ/kg feed)."""
        assert DELTA_H_CRACK_J_KG == 480000.0
        assert DELTA_H_CRACK_KJ_KG == 480.0
        assert DELTA_H_CRACKING_J_KG == 480000.0
        assert DELTA_H_CRACKING_KJ_KG == 480.0

    def test_arrhenius_monotonicity(self) -> None:
        """Requirement 4: Verify Arrhenius rate constants increase monotonically with temperature."""
        sim = FccRiserSimulator()
        rx_500 = sim.compute_reaction_rates(500.0 + T_ZERO_CELSIUS, 0.25, 0.485, 0.85)
        rx_520 = sim.compute_reaction_rates(520.0 + T_ZERO_CELSIUS, 0.25, 0.485, 0.85)
        rx_540 = sim.compute_reaction_rates(540.0 + T_ZERO_CELSIUS, 0.25, 0.485, 0.85)

        assert rx_500["k1"] < rx_520["k1"] < rx_540["k1"]
        assert rx_500["k2"] < rx_520["k2"] < rx_540["k2"]
        assert rx_500["k3"] < rx_520["k3"] < rx_540["k3"]
        assert rx_500["k4"] < rx_520["k4"] < rx_540["k4"]

    def test_endothermic_heat_absorption(self) -> None:
        """Requirement 4: Verify net endothermic heat absorption and axial temperature drop."""
        sim = FccRiserSimulator()
        derivs = sim.compute_derivatives(
            0.0,
            [sim.state.t_riser_out_c, sim.state.y_gasoil, sim.state.y_gasoline,
             sim.state.y_lpg, sim.state.y_drygas, sim.state.c_coke_wt],
        )
        assert len(derivs) == 6
        assert sim.state.endothermic_reaction_heat_kw > 15000.0
        assert 20.0 <= sim.state.axial_temperature_drop_c <= 35.0

    def test_coke_yield_and_catalyst_deactivation(self) -> None:
        """Requirement 4: Verify coke accumulation and activity deactivation factor phi."""
        sim = FccRiserSimulator()
        rx_clean = sim.compute_reaction_rates(520.0 + T_ZERO_CELSIUS, 0.25, 0.485, 0.20)
        rx_coked = sim.compute_reaction_rates(520.0 + T_ZERO_CELSIUS, 0.25, 0.485, 1.50)

        assert 0.10 <= rx_clean["phi"] <= 1.00
        assert 0.10 <= rx_coked["phi"] <= 1.00
        assert rx_clean["phi"] > rx_coked["phi"]  # higher coke content decreases catalyst activity


# ============================================================================
# 5. Section 5: Coupled ODE RK4 Integration & Conservation Residuals
# ============================================================================

class TestSection5CoupledODEIntegrationAndConservationResiduals:
    """Tests for coupled 6-state ODE RK4 integration stability and dual elemental mass and thermal enthalpy residuals (< 1e-10)."""

    def test_rk4_solver_stability_and_states(self) -> None:
        """Requirement 5: Verify RK4 integration steps remain stable and bounded within physical limits."""
        sim = FccRiserSimulator()
        for _ in range(100):
            res = sim.step(dt=0.05)
            assert res.status == AgentStatus.SUCCESS

        assert 500.0 <= sim.state.t_riser_out_c <= 530.0
        assert 0.15 <= sim.state.y_gasoil <= 0.35
        assert 0.40 <= sim.state.y_gasoline <= 0.55
        assert 0.15 <= sim.state.y_lpg <= 0.25
        assert 0.02 <= sim.state.y_drygas <= 0.08
        assert 0.50 <= sim.state.c_coke_wt <= 1.20
        assert 65.0 <= sim.state.conversion_pct <= 85.0
        assert 40.0 <= sim.state.gasoline_yield_pct <= 55.0
        assert not math.isnan(sim.state.t_riser_out_c)
        assert not math.isnan(sim.state.gasoline_yield_pct)

    def test_dual_stoichiometric_conservation_residuals(self) -> None:
        """Requirement 5: Verify dual elemental mass and thermal enthalpy residuals < 1e-10."""
        sim = FccRiserSimulator()
        sim.advance_time(duration_s=2.0, dt=0.05)

        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_derivative_computations_finite(self) -> None:
        """Requirement 5: Verify compute_derivatives produces 6 finite derivatives."""
        sim = FccRiserSimulator()
        derivs = sim.compute_derivatives(
            0.0,
            [sim.state.t_riser_out_c, sim.state.y_gasoil, sim.state.y_gasoline,
             sim.state.y_lpg, sim.state.y_drygas, sim.state.c_coke_wt],
        )
        assert len(derivs) == 6
        for d in derivs:
            assert not math.isnan(d)
            assert not math.isinf(d)


# ============================================================================
# 6. Section 6: Process Safety Trips & Priority Hierarchy
# ============================================================================

class TestSection6ProcessSafetyInterlocksAndTrips:
    """Tests for safety trips (0xBD01..0xBD04), priority hierarchy, and Horner coil assertions (%M291..%M293)."""

    def test_trip_0xbd01_riser_thermal_collapse(self) -> None:
        """Requirement 6: Verify 0xBD01 trip on riser temp < 490 C -> asserts %M292, clears %M291."""
        reg = RegisterTable()
        sim = FccRiserSimulator(register_table=reg)

        sim.state.t_riser_out_c = 485.0  # < 490 C
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1257") & 0xFFFF == 0xBD01
        assert reg.read_bit("%M292") is True
        assert reg.read_bit("%M291") is False

    def test_fault_0xbd02_disengager_high_dp(self) -> None:
        """Requirement 6: Verify 0xBD02 on disengager dP > 1.5 bar -> asserts %M293."""
        reg = RegisterTable()
        sim = FccRiserSimulator(register_table=reg)

        sim.state.t_riser_out_c = 512.0
        sim.state.disengager_differential_pressure_bar = 1.65  # > 1.5 bar
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1257") & 0xFFFF == 0xBD02
        assert reg.read_bit("%M293") is True
        assert reg.read_bit("%M291") is True
        assert reg.read_bit("%M292") is False

    def test_fault_0xbd03_feed_slip_choking(self) -> None:
        """Requirement 6: Verify 0xBD03 on gas-solid slip factor > 3.5 -> asserts %M292, clears %M291."""
        reg = RegisterTable()
        sim = FccRiserSimulator(register_table=reg)

        sim.state.t_riser_out_c = 512.0
        sim.state.disengager_differential_pressure_bar = 0.35
        sim.state.slip_ratio = 3.8  # > 3.5
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1257") & 0xFFFF == 0xBD03
        assert reg.read_bit("%M292") is True
        assert reg.read_bit("%M291") is False

    def test_fault_0xbd04_high_coke_deposition(self) -> None:
        """Requirement 6: Verify 0xBD04 on catalyst coke content > 1.5 wt%."""
        reg = RegisterTable()
        sim = FccRiserSimulator(register_table=reg)

        sim.state.t_riser_out_c = 512.0
        sim.state.disengager_differential_pressure_bar = 0.35
        sim.state.slip_ratio = 1.45
        sim.state.c_coke_wt = 1.65  # > 1.5 wt%
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1257") & 0xFFFF == 0xBD04
        assert reg.read_bit("%M291") is True
        assert reg.read_bit("%M292") is False

    def test_priority_hierarchy(self) -> None:
        """Requirement 6: Verify 0xBD01 (thermal collapse) dominates all other faults."""
        reg = RegisterTable()
        sim = FccRiserSimulator(register_table=reg)

        sim.state.t_riser_out_c = 480.0  # 0xBD01
        sim.state.disengager_differential_pressure_bar = 1.8  # 0xBD02
        sim.state.slip_ratio = 4.0  # 0xBD03
        sim.state.c_coke_wt = 2.0  # 0xBD04
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1257") & 0xFFFF == 0xBD01
        assert reg.read_bit("%M292") is True
        assert reg.read_bit("%M291") is False
        assert reg.read_bit("%M293") is True


# ============================================================================
# 7. Section 7: Horner OCS Memory Space Integration
# ============================================================================

class TestSection7HornerOCSMemorySpaceIntegration:
    """Tests for Horner OCS memory space bindings (%R1250..%R1257, %M291..%M293) with PrivilegeMode.SYSTEM."""

    def test_register_space_synchronization(self) -> None:
        """Requirement 7: Verify analog register values and discrete coil states with PrivilegeMode.SYSTEM."""
        reg = RegisterTable()
        sim = FccRiserSimulator(register_table=reg)

        sim.state.t_riser_inlet_c = 540.0
        sim.state.t_riser_out_c = 512.0
        sim.state.disengager_pressure_bar = 2.5
        sim.state.catalyst_to_oil_ratio = 6.5
        sim.state.y_gasoline = 0.485
        sim.state.y_lpg = 0.195
        sim.state.c_coke_wt = 0.85
        sim.state.disengager_differential_pressure_bar = 0.35
        sim.state.slip_ratio = 1.45

        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert reg.read_word("%R1250") == 5400
        assert reg.read_word("%R1251") == 5120
        assert reg.read_word("%R1252") == 25
        assert reg.read_word("%R1253") == 65
        assert reg.read_word("%R1254") == 485
        assert reg.read_word("%R1255") == 195
        assert reg.read_word("%R1256") == 85
        assert reg.read_word("%R1257") & 0xFFFF == 0x0000
        assert reg.read_bit("%M291") is True
        assert reg.read_bit("%M292") is False
        assert reg.read_bit("%M293") is False

    def test_system_privilege_enforced_for_internal_writes(self) -> None:
        """Requirement 7: Ensure writes use PrivilegeMode.SYSTEM without throwing privilege errors."""
        reg = RegisterTable()
        sim = FccRiserSimulator(register_table=reg)
        # sync_to_registers explicitly uses PrivilegeMode.SYSTEM
        sim.sync_to_registers(reg)
        assert reg.read_word("%R1250") == 5400


# ============================================================================
# 8. Section 8: ILogicUnit Compliance & Dynamic Disturbance Response
# ============================================================================

class TestSection8ILogicUnitAndDisturbanceResponse:
    """Tests for ILogicUnit interface, scan_step, transient disturbance response, and settling stability."""

    def test_ilogicunit_interface_and_scan_step(self) -> None:
        """Requirement 8: Verify ILogicUnit protocol compliance and scan_step return dictionary."""
        sim = FccRiserSimulator()
        assert sim.name == "FccRiserDisengagerSync"
        assert sim.priority == 100
        assert sim.is_enabled is True

        res = sim.scan_step(dt_s=0.05)
        assert "status" in res
        assert "t_riser_out_c" in res
        assert "y_gasoline" in res
        assert "fcc_riser_permissive" in res
        assert res["fcc_riser_permissive"] is True

    def test_fcc_riser_logic_unit_adapter(self) -> None:
        """Requirement 8: Verify FccRiserLogicUnit adapter couples correctly into ScanContext."""
        reg = RegisterTable()
        sim = FccRiserSimulator(register_table=reg)
        unit = FccRiserLogicUnit(simulator=sim)
        ctx = ScanContext(
            cycle=1,
            dt_ms=50.0,
            elapsed_time_ms=50.0,
            get_register=lambda addr: reg.read_word(addr),
            set_register=lambda addr, val: reg.write_word(addr, val, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda name, default=None: default,
            set_variable=lambda name, val: None,
            record_fault=lambda fault: None,
        )
        ctx.registers = reg

        unit.execute(ctx)
        assert reg.read_word("%R1250") == 5400
        assert reg.read_word("%R1251") == 5120
        assert reg.read_bit("%M291") is True

        unit.reset()
        assert unit.simulator.state.time_s == 0.0

    def test_inlet_temp_disturbance_settling(self) -> None:
        """Requirement 8: Verify closed-loop settling response to +3 °C inlet temperature disturbance."""
        sim = FccRiserSimulator()
        sim.state.t_riser_inlet_c = 543.0  # +3 C inlet disturbance
        res = sim.advance_time(duration_s=8.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        assert 508.0 <= sim.state.t_riser_out_c <= 525.0
        assert 65.0 <= sim.state.conversion_pct <= 85.0
        assert sim.state.fcc_riser_permissive is True
        assert not math.isnan(sim.state.t_riser_out_c)


# ============================================================================
# 9. Section 9: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestSection9VerificationSuiteIntegration:
    """Tests for run_fcc_riser_verification execution and 4-state contract validation."""

    def test_run_fcc_riser_verification_returns_strict_4_state_success(self, tmp_path: Path) -> None:
        """Requirement 9: Execute verification suite, write evidence JSON, assert success contract."""
        out_file = tmp_path / "fcc_riser_evidence.json"
        evidence = run_fcc_riser_verification(str(out_file))

        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert evidence["data"]["work_package"] == "W164"
        assert evidence["data"]["checks_passed"] == 9
        assert evidence["data"]["total_checks"] == 9
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9

    def test_verification_suite_aliases(self) -> None:
        """Requirement 9: Verify alias functions execute cleanly."""
        res = run_fluid_catalytic_cracking_riser_verification()
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9

        res2 = run_riser_verification()
        assert res2["status"] == "success"
        assert res2["data"]["checks_passed"] == 9

        res3 = run_fcc_riser_disengager_verification()
        assert res3["status"] == "success"
        assert res3["data"]["checks_passed"] == 9

        res4 = run_fluid_catalytic_cracking_riser_disengager_verification()
        assert res4["status"] == "success"
        assert res4["data"]["checks_passed"] == 9
