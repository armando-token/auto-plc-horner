"""Unit and Integration Tests for Industrial Multi-Stage Reverse Osmosis (RO) Desalination ODE Simulation.

Work Package: W131 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R920..%R927, %M214..%M216).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Kedem-Katchalsky flux, temperature scaling, Van 't Hoff osmotic pressure, solution-diffusion transport.
4. Section 4: Film theory concentration polarization dynamics and Sherwood correlation.
5. Section 5: Multi-stage membrane element mass balances (2:1 array ratio, 75%-85% recovery, > 99% rejection).
6. Section 6: Coupled 6-state ODE RK4 integration stability and dual stoichiometric conservation residuals.
7. Section 7: Process safety trips (burst 0x9C01, fouling 0x9C02, salinity 0x9C03, flush 0x9C04).
8. Section 8: Horner OCS register space synchronization (%R920..%R927, %M214..%M216).
9. Section 9: Complete 9-stage verification suite integration test and evidence JSON export.
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
from jev_cscape.simulation.reverse_osmosis import (
    REVERSE_OSMOSIS_PLANT_SYNC_POU,
    REVERSE_OSMOSIS_PURE_ST_POU,
    REVERSE_OSMOSIS_SYNC_POU,
    RO_PURE_ST_POU,
    RO_SYNC_POU,
    ReverseOsmosisConfig,
    ReverseOsmosisDiagnosticCode,
    ReverseOsmosisEngine,
    ReverseOsmosisModel,
    ReverseOsmosisParameters,
    ReverseOsmosisPlantModel,
    ReverseOsmosisSimulationEngine,
    ReverseOsmosisSimulator,
    ReverseOsmosisState,
    ReverseOsmosisStatusBits,
    ReverseOsmosisStatusWord,
    ROConfig,
    RODiagnosticCode,
    ROSimulator,
    ROState,
    ROStatusBits,
    RoConfig,
    RoDiagnosticCode,
    RoSimulator,
    RoState,
    RoStatusBits,
    RoStatusWord,
    run_reverse_osmosis_verification,
    verify_reverse_osmosis_pure_st,
)


# ============================================================================
# 1. Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestReverseOsmosisPureST:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings."""

    def test_verify_reverse_osmosis_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_reverse_osmosis_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers."""
        SecurityGuard.assert_pure_st_content(REVERSE_OSMOSIS_PURE_ST_POU)
        val = STParser.validate_code(REVERSE_OSMOSIS_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(REVERSE_OSMOSIS_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "ReverseOsmosisDynamicsSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R920", "%R921", "%R922", "%R923",
            "%R924", "%R925", "%R926", "%R927",
            "%M214", "%M215", "%M216",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_pure_st_pou_plant_alias_ast(self) -> None:
        """Requirement 1: Verify ReverseOsmosisPlantSync alias parses cleanly."""
        SecurityGuard.assert_pure_st_content(REVERSE_OSMOSIS_PLANT_SYNC_POU)
        ast = STParser.parse_pou(REVERSE_OSMOSIS_PLANT_SYNC_POU)
        assert ast is not None
        assert ast.name == "ReverseOsmosisPlantSync"
        assert ast.pou_type == POUType.PROGRAM
        for reg in ["%R920", "%R921", "%R922", "%R923", "%R924", "%R925", "%R926", "%R927", "%M214", "%M215", "%M216"]:
            assert reg in ast.bound_registers

    def test_pure_st_pou_alias_equivalence(self) -> None:
        """Requirement 1: Verify POU aliases are defined and consistent."""
        assert RO_PURE_ST_POU == REVERSE_OSMOSIS_PURE_ST_POU
        assert RO_SYNC_POU == REVERSE_OSMOSIS_PURE_ST_POU
        assert REVERSE_OSMOSIS_SYNC_POU == REVERSE_OSMOSIS_PLANT_SYNC_POU

    def test_pure_st_pou_internal_variables_and_control_logic(self) -> None:
        """Requirement 1: Verify internal boolean variables and interlock IF-branches."""
        ast = STParser.parse_pou(REVERSE_OSMOSIS_PURE_ST_POU)
        assert ast is not None
        var_names = [v.name for v in ast.variables]
        assert "HighPressureBurstTrip" in var_names
        assert "FlushValveCommand" in var_names
        assert "PermeateDivertValve" in var_names
        assert "HighPressurePumpPermissive" in var_names
        assert "CriticalMembraneFoulingTrip" in var_names
        assert "AutomatedFlushCycleActive" in var_names

        stmts = "\n".join(ast.raw_statements)
        assert "IF FeedPressureScaled > 75000 THEN" in stmts
        assert "IF CriticalMembraneFoulingTrip THEN" in stmts
        assert "IF AutomatedFlushCycleActive THEN" in stmts
        assert "IF PermeateTdsPpm > 500 THEN" in stmts


# ============================================================================
# 2. Anti-Ladder Security Guard Rejection
# ============================================================================

class TestAntiLadderSecurityGuard:
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
            "XIC HighPressurePumpPermissive",
            "XIO CriticalMembraneFoulingTrip",
            "OTE AutomatedFlushCycleActive",
            "OTL HighPressureBurstTrip",
            "OTU FlushValveCommand",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: Verify all ladder constructs raise LadderForbiddenError."""
        bad_code = f"{REVERSE_OSMOSIS_PURE_ST_POU}\n{ladder_snippet}\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

        val = STParser.validate_code(bad_code)
        assert val.status == AgentStatus.FAILED
        assert val.error_code == "ERR_LADDER_FORBIDDEN"
        assert val.data.get("ladder_rejected") is True


# ============================================================================
# 3. Kedem-Katchalsky & Solution-Diffusion Membrane Transport Hydrodynamics
# ============================================================================

class TestKedemKatchalskyAndSolutionDiffusion:
    """Tests for Darcy/Kedem-Katchalsky water flux, Van 't Hoff osmotic pressure, and solute flux."""

    def test_vogel_dynamic_water_viscosity(self) -> None:
        """Requirement 3: Verify dynamic water viscosity decreases monotonically with temperature."""
        sim = ReverseOsmosisSimulator()
        mu_15 = sim.compute_water_viscosity(15.0)
        mu_25 = sim.compute_water_viscosity(25.0)
        mu_35 = sim.compute_water_viscosity(35.0)

        assert mu_15 > mu_25 > mu_35
        assert math.isclose(mu_25, 0.890e-3, rel_tol=0.05)

    def test_van_thoff_osmotic_pressure_scaling(self) -> None:
        """Requirement 3: Verify van 't Hoff equation Pi = 2 * phi * (C / M) * R * T."""
        sim = ReverseOsmosisSimulator()
        pi_10k = sim.compute_osmotic_pressure(10000.0, temp_c=25.0)
        pi_20k = sim.compute_osmotic_pressure(20000.0, temp_c=25.0)
        pi_32k = sim.compute_osmotic_pressure(32000.0, temp_c=25.0)
        pi_64k = sim.compute_osmotic_pressure(64000.0, temp_c=25.0)

        # Linear with solute concentration
        assert math.isclose(pi_20k, 2.0 * pi_10k, rel_tol=1e-3)
        assert math.isclose(pi_64k, 2.0 * pi_32k, rel_tol=1e-3)
        assert math.isclose(pi_32k, 2497.5, rel_tol=0.02)

        # Proportional to absolute temperature
        pi_25c = sim.compute_osmotic_pressure(32000.0, temp_c=25.0)
        pi_35c = sim.compute_osmotic_pressure(32000.0, temp_c=35.0)
        t_ratio = (273.15 + 35.0) / (273.15 + 25.0)
        assert math.isclose(pi_35c, pi_25c * t_ratio, rel_tol=1e-3)

    def test_pure_water_flux_temperature_correction(self) -> None:
        """Requirement 3: Verify pure water flux J_w increases with temperature due to lower viscosity."""
        sim = ReverseOsmosisSimulator()
        jw_15, ndp_15, _, _ = sim.compute_pure_water_flux(5500.0, 32000.0, 240.0, 1.18, temp_c=15.0)
        jw_25, ndp_25, _, _ = sim.compute_pure_water_flux(5500.0, 32000.0, 240.0, 1.18, temp_c=25.0)
        jw_35, ndp_35, _, _ = sim.compute_pure_water_flux(5500.0, 32000.0, 240.0, 1.18, temp_c=35.0)

        assert jw_15 < jw_25 < jw_35
        assert math.isclose(jw_25, 20.0, rel_tol=0.05)
        assert math.isclose(ndp_25, 235.0, rel_tol=0.05)

    def test_solution_diffusion_solute_transport(self) -> None:
        """Requirement 3: Verify solute transport J_s = B_s * (C_m - C_p) and permeate TDS."""
        sim = ReverseOsmosisSimulator()
        cp, cm, js = sim.compute_solute_transport(j_w_lmh=20.0, c_bulk_ppm=32000.0, gamma=1.18)

        assert cm > 32000.0  # Wall concentration is polarized
        assert cp < 500.0    # Product permeate is potable (< 500 ppm)
        assert math.isclose(cp, 240.0, rel_tol=0.05)
        assert js > 0.0

    def test_solute_rejection_improves_with_flux(self) -> None:
        """Requirement 3: Higher flux dilutes salt passage in solution-diffusion model."""
        sim = ReverseOsmosisSimulator()
        cp_low_j, _, _ = sim.compute_solute_transport(j_w_lmh=10.0, c_bulk_ppm=32000.0, gamma=1.18)
        cp_high_j, _, _ = sim.compute_solute_transport(j_w_lmh=30.0, c_bulk_ppm=32000.0, gamma=1.18)

        assert cp_low_j > cp_high_j, "Higher water flux must produce lower permeate salt concentration"


# ============================================================================
# 4. Film Theory Concentration Polarization Dynamics
# ============================================================================

class TestFilmTheoryConcentrationPolarization:
    """Tests for Gamma = exp(J_w / k_mtc) and Sherwood correlation."""

    def test_polarization_factor_increases_with_flux(self) -> None:
        """Requirement 4: Verify Gamma increases exponentially with flux."""
        sim = ReverseOsmosisSimulator()
        g_10, k_10, _, _ = sim.compute_polarization_factor(10.0)
        g_20, k_20, _, _ = sim.compute_polarization_factor(20.0)
        g_30, k_30, _, _ = sim.compute_polarization_factor(30.0)

        assert 1.0 < g_10 < g_20 < g_30
        assert math.isclose(g_20, 1.18, rel_tol=0.05)
        assert k_10 == k_20 == k_30  # Mass transfer coeff is independent of flux

    def test_polarization_factor_increases_at_lower_crossflow_velocity(self) -> None:
        """Requirement 4: Verify lower turbulence/velocity increases boundary layer polarization."""
        sim = ReverseOsmosisSimulator()
        g_fast, _, re_fast, _ = sim.compute_polarization_factor(20.0, crossflow_vel_m_s=0.35)
        g_nom, _, re_nom, _ = sim.compute_polarization_factor(20.0, crossflow_vel_m_s=0.20)
        g_slow, _, re_slow, _ = sim.compute_polarization_factor(20.0, crossflow_vel_m_s=0.10)

        assert re_fast > re_nom > re_slow
        assert g_fast < g_nom < g_slow

    def test_sherwood_reynolds_schmidt_numbers(self) -> None:
        """Requirement 4: Verify Re and Sc numbers are within physical ranges for RO spacer channels."""
        sim = ReverseOsmosisSimulator()
        _, k_mtc, re, sc = sim.compute_polarization_factor(20.0)

        assert 50.0 <= re <= 500.0
        assert 300.0 <= sc <= 1000.0
        assert 50.0 <= k_mtc <= 200.0


# ============================================================================
# 5. Multi-Stage Membrane Element Mass Balances (Two-Stage Array)
# ============================================================================

class TestMultiStageMembraneBalances:
    """Tests for 2:1 vessel array ratio, Stage 1 feeding Stage 2, recovery, and rejection."""

    def test_nominal_two_stage_mass_balance(self) -> None:
        """Requirement 5: Verify nominal operation matches specification: 1520 L/h perm, 480 L/h conc."""
        sim = ReverseOsmosisSimulator()
        mb = sim.compute_two_stage_mass_balance(p_feed_kpa=5500.0, c_feed_ppm=32000.0)

        assert math.isclose(mb["q_perm"], 1520.0, rel_tol=0.02)
        assert math.isclose(mb["q_conc"], 480.0, rel_tol=0.02)
        assert math.isclose(mb["q_perm"] + mb["q_conc"], 2000.0, rel_tol=1e-5)
        assert math.isclose(mb["recovery"], 0.760, rel_tol=0.02)
        assert math.isclose(mb["rejection"], 0.9925, rel_tol=0.01)
        assert math.isclose(mb["c_perm"], 240.0, rel_tol=0.05)

    def test_two_stage_interstage_feed_continuity(self) -> None:
        """Requirement 5: Verify Stage 1 concentrate feeds Stage 2 directly."""
        sim = ReverseOsmosisSimulator()
        mb = sim.compute_two_stage_mass_balance(p_feed_kpa=5500.0, c_feed_ppm=32000.0)

        assert math.isclose(mb["q_c1"], mb["q_p2"] + mb["q_conc"], rel_tol=1e-5)
        assert mb["c_c1"] > 32000.0  # Stage 1 brine is concentrated
        assert mb["c_conc"] > mb["c_c1"]  # Stage 2 brine is even more concentrated

    def test_2_to_1_array_area_distribution(self) -> None:
        """Requirement 5: Verify 2:1 vessel ratio area split."""
        cfg = ReverseOsmosisConfig(membrane_area_total_m2=76.0, vessel_ratio_stage1=2, vessel_ratio_stage2=1)
        assert math.isclose(cfg.membrane_area_stage1_m2, 50.6667, rel_tol=1e-3)
        assert math.isclose(cfg.membrane_area_stage2_m2, 25.3333, rel_tol=1e-3)
        assert math.isclose(cfg.membrane_area_stage1_m2 + cfg.membrane_area_stage2_m2, 76.0, rel_tol=1e-5)


# ============================================================================
# 6. Coupled 6-State ODE System & High-Order RK4 Solver
# ============================================================================

class TestCoupledODEAndRK4Solver:
    """Tests for 6-state ODE integration stability and dual mass conservation."""

    def test_rk4_solution_stability(self) -> None:
        """Requirement 6: Verify 6-state RK4 integrator advances stably with positive states."""
        sim = ReverseOsmosisSimulator()
        res = sim.advance_time(duration_s=2.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS

        st = sim.state
        assert st.time_s >= 2.0
        assert 5000.0 <= st.p_feed_kpa <= 6000.0
        assert 30000.0 <= st.c_feed_ppm <= 34000.0
        assert 15.0 <= st.j_w_lmh <= 25.0
        assert 150.0 <= st.c_perm_ppm <= 350.0
        assert 1.10 <= st.gamma_polarization <= 1.30
        assert st.r_fouling_m_inv >= 0.0

    def test_dual_stoichiometric_conservation_residuals(self) -> None:
        """Requirement 6: Verify volumetric flow residual < 1e-10 m3/s and solute mass residual < 1e-10 kg/s."""
        sim = ReverseOsmosisSimulator()
        sim.advance_time(duration_s=1.0, dt=0.05)

        assert sim.state.volumetric_flow_residual_m3_s < 1e-10
        assert sim.state.solute_mass_balance_residual_kg_s < 1e-10

    def test_invalid_timestep_fail_closed(self) -> None:
        """Requirement 6: Verify negative or zero dt fails closed."""
        sim = ReverseOsmosisSimulator()
        res_zero = sim.advance_time(duration_s=0.0, dt=0.05)
        assert res_zero.status == AgentStatus.FAILED
        assert res_zero.error_code == "INVALID_TIMESTEP"

        res_neg = sim.advance_time(duration_s=1.0, dt=-0.05)
        assert res_neg.status == AgentStatus.FAILED
        assert res_neg.error_code == "INVALID_TIMESTEP"

    def test_pump_off_flux_decay(self) -> None:
        """Requirement 6: Verify flux decays to zero when pump permissive is disabled."""
        sim = ReverseOsmosisSimulator()
        sim.state.hp_pump_permissive = False
        sim.advance_time(duration_s=3.0, dt=0.05)

        assert sim.state.p_feed_kpa < 100.0
        assert sim.state.j_w_lmh < 1.0


# ============================================================================
# 7. Process Safety Interlocks & Diagnostics
# ============================================================================

class TestProcessSafetyInterlocks:
    """Tests for burst trip (0x9C01), fouling trip (0x9C02), salinity alarm (0x9C03), and flush cmd (0x9C04)."""

    def test_high_pressure_burst_trip_clears_m214(self) -> None:
        """Requirement 7: P_feed > 7500 kPa clears %M214 and sets code 0x9C01."""
        sim = ReverseOsmosisSimulator()
        sim.state.p_feed_kpa = 7600.0
        sim._sync_registers()

        assert sim.reg_table.read_bit("%M214") is False
        assert sim.state.hp_pump_permissive is False
        assert (sim.reg_table.read_word("%R927") & 0xFFFF) == int(ReverseOsmosisDiagnosticCode.RO_ERR_HIGH_PRESSURE_BURST)

    def test_critical_fouling_trip_by_ndp_asserts_m215(self) -> None:
        """Requirement 7: NDP > 3500 kPa asserts %M215 and sets code 0x9C02."""
        sim = ReverseOsmosisSimulator()
        sim.state.ndp_kpa = 3600.0
        sim._sync_registers()

        assert sim.reg_table.read_bit("%M215") is True
        assert sim.state.critical_fouling_trip is True
        assert (sim.reg_table.read_word("%R927") & 0xFFFF) == int(ReverseOsmosisDiagnosticCode.RO_ERR_CRITICAL_FOULING)

    def test_critical_fouling_trip_by_polarization_factor(self) -> None:
        """Requirement 7: Gamma > 1.35 asserts %M215 and sets code 0x9C02."""
        sim = ReverseOsmosisSimulator()
        sim.state.gamma_polarization = 1.38
        sim._sync_registers()

        assert sim.reg_table.read_bit("%M215") is True
        assert (sim.reg_table.read_word("%R927") & 0xFFFF) == int(ReverseOsmosisDiagnosticCode.RO_ERR_CRITICAL_FOULING)

    def test_permeate_salinity_excursion_code(self) -> None:
        """Requirement 7: Permeate TDS > 500 ppm triggers 0x9C03."""
        sim = ReverseOsmosisSimulator()
        sim.state.c_perm_ppm = 550.0
        sim._sync_registers()

        assert sim.state.salinity_excursion_alarm is True
        assert (sim.reg_table.read_word("%R927") & 0xFFFF) == int(ReverseOsmosisDiagnosticCode.RO_ERR_PERMEATE_SALINITY_EXCURSION)

    def test_automated_flush_cycle_active_asserts_m216(self) -> None:
        """Requirement 7: %M216 asserted during automated flush cycle and code 0x9C04."""
        sim = ReverseOsmosisSimulator()
        sim.state.flush_cycle_active = True
        sim._sync_registers()

        assert sim.reg_table.read_bit("%M216") is True
        assert (sim.reg_table.read_word("%R927") & 0xFFFF) == int(ReverseOsmosisDiagnosticCode.RO_CMD_FLUSH_ACTIVE)

    def test_diagnostic_code_priority_hierarchy(self) -> None:
        """Requirement 7: Burst (0x9C01) > Fouling (0x9C02) > Salinity (0x9C03) > Flush (0x9C04)."""
        sim = ReverseOsmosisSimulator()
        sim.state.p_feed_kpa = 7600.0  # Burst
        sim.state.ndp_kpa = 3600.0     # Fouling
        sim.state.c_perm_ppm = 600.0   # Salinity
        sim.state.flush_cycle_active = True
        sim._sync_registers()

        # Burst must take highest precedence
        assert (sim.reg_table.read_word("%R927") & 0xFFFF) == int(ReverseOsmosisDiagnosticCode.RO_ERR_HIGH_PRESSURE_BURST)


# ============================================================================
# 8. Horner OCS Memory Space Integration (%R920..%R927, %M214..%M216)
# ============================================================================

class TestHornerOCSSync:
    """Tests for exact scaling and bit registers in RegisterTable."""

    def test_nominal_register_sync(self) -> None:
        """Requirement 8: Check exact scaled registers at nominal state."""
        sim = ReverseOsmosisSimulator()
        sim._sync_registers()
        reg = sim.reg_table

        # %R920: FeedPressureScaled (5500.0 kPa * 10 = 55000)
        assert reg.read_uword("%R920") == 55000

        # %R921: PermeateFlowScaled (1520.0 L/h * 10 = 15200)
        assert math.isclose(reg.read_word("%R921"), 15200, rel_tol=0.02)

        # %R922: ConcentrateFlowScaled (480.0 L/h * 10 = 4800)
        assert math.isclose(reg.read_word("%R922"), 4800, rel_tol=0.02)

        # %R923: FeedTdsPpm (32000)
        assert reg.read_word("%R923") == 32000

        # %R924: PermeateTdsPpm (240)
        assert math.isclose(reg.read_word("%R924"), 240, abs_tol=10)

        # %R925: PolarizationFactorScaled (1.18 * 100 = 118)
        assert reg.read_word("%R925") == 118

        # %R926: NetDrivingPressureScaled (235.0 kPa * 10 = 2350)
        assert math.isclose(reg.read_word("%R926"), 2350, abs_tol=20)

        # %R927: DiagnosticEventCode (0x0000)
        assert reg.read_word("%R927") == 0x0000

        # %M214: HighPressurePumpPermissive (True)
        assert reg.read_bit("%M214") is True

        # %M215: CriticalMembraneFoulingTrip (False)
        assert reg.read_bit("%M215") is False

        # %M216: AutomatedFlushCycleActive (False)
        assert reg.read_bit("%M216") is False

    def test_class_compatibility_aliases(self) -> None:
        """Requirement 8: Verify all required class and module aliases exist."""
        assert ROSimulator is ReverseOsmosisSimulator
        assert RoSimulator is ReverseOsmosisSimulator
        assert ReverseOsmosisSimulationEngine is ReverseOsmosisSimulator
        assert ReverseOsmosisModel is ReverseOsmosisSimulator
        assert ReverseOsmosisEngine is ReverseOsmosisSimulator
        assert ReverseOsmosisPlantModel is ReverseOsmosisSimulator

        assert ROConfig is ReverseOsmosisConfig
        assert RoConfig is ReverseOsmosisConfig
        assert ReverseOsmosisParameters is ReverseOsmosisConfig

        assert ROState is ReverseOsmosisState
        assert RoState is ReverseOsmosisState

        assert ROStatusBits is ReverseOsmosisStatusBits
        assert RoStatusBits is ReverseOsmosisStatusBits
        assert ReverseOsmosisStatusWord is ReverseOsmosisStatusBits
        assert RoStatusWord is ReverseOsmosisStatusBits

        assert RODiagnosticCode is ReverseOsmosisDiagnosticCode
        assert RoDiagnosticCode is ReverseOsmosisDiagnosticCode


# ============================================================================
# 9. Complete 9-Stage Verification Suite Integration Test
# ============================================================================

class TestReverseOsmosisVerificationRunner:
    """Tests for run_reverse_osmosis_verification function and evidence artifact generation."""

    def test_run_reverse_osmosis_verification_all_9_stages(self, tmp_path: Path) -> None:
        """Requirement 9: Execute full 9-stage verification suite and assert strict success."""
        evidence_file = tmp_path / "w131_ro_verification_evidence.json"
        result = run_reverse_osmosis_verification(output_path=str(evidence_file))

        assert result["status"] == "success"
        assert result["error_code"] is None
        assert "Industrial Multi-Stage Reverse Osmosis (RO) Desalination ODE Simulation verified cleanly (9/9 checks passed)" in result["details"]

        data = result["data"]
        assert data["work_package"] == "W131"
        assert data["gate"] == "Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation"
        assert data["checks_passed"] == 9
        assert data["total_checks"] == 9

        tests = data["tests"]
        assert len(tests) == 9
        for t in tests:
            assert t["passed"] is True, f"Stage {t['stage']} ({t['check']}) failed: {t['details']}"

        # Verify evidence file on disk
        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            saved_data = json.load(f)
        assert saved_data["status"] == "success"
        assert saved_data["data"]["checks_passed"] == 9

    def test_run_reverse_osmosis_verification_evidence_path_parameter(self, tmp_path: Path) -> None:
        """Requirement 9: Test evidence_path compatibility alias parameter."""
        ev_file = tmp_path / "ro_alias_evidence.json"
        res = run_reverse_osmosis_verification(evidence_path=str(ev_file))
        assert res["status"] == "success"
        assert ev_file.exists()
