"""Unit and Integration Tests for Industrial Hydrocyclone Desanding & Separation Dynamics ODE Simulation.

Work Package: W128 (Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R890..%R897, %M207..%M209).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs.
3. Section 3: Rietema swirl vortex velocity, Stokes centrifugal force, and cut-size d50 calculation.
4. Section 4: Underflow/overflow splitting ratio, solids concentration, and roping boundary detection.
5. Section 5: Coupled ODE RK4 integration stability and solids/liquid mass balance conservation.
6. Section 6: Process safety trips (roping 0x9901, overpressure 0x9902, blockage 0x9903, apex flush %M209).
7. Section 7: Horner OCS register space synchronization (%R890..%R897, %M207..%M209).
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
from jev_cscape.simulation.hydrocyclone import (
    HYDROCYCLONE_PURE_ST_POU,
    HYDROCYCLONE_SYNC_POU,
    HydrocycloneConfig,
    HydrocycloneDiagnosticCode,
    HydrocycloneEngine,
    HydrocycloneModel,
    HydrocycloneParameters,
    HydrocycloneSimulationEngine,
    HydrocycloneSimulator,
    HydrocycloneState,
    HydrocycloneStatusBits,
    HydrocycloneStatusWord,
    run_hydrocyclone_verification,
    verify_hydrocyclone_pure_st,
)


# ============================================================================
# 1. Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

class TestHydrocyclonePureST:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings."""

    def test_verify_hydrocyclone_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_hydrocyclone_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers."""
        SecurityGuard.assert_pure_st_content(HYDROCYCLONE_PURE_ST_POU)
        val = STParser.validate_code(HYDROCYCLONE_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(HYDROCYCLONE_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "HydrocycloneSeparationSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R890", "%R891", "%R892", "%R893",
            "%R894", "%R895", "%R896", "%R897",
            "%M207", "%M208", "%M209",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_pure_st_pou_alias_equivalence(self) -> None:
        """Requirement 1: Verify POU aliases parse equivalently and bind registers."""
        ast_alias = STParser.parse_pou(HYDROCYCLONE_SYNC_POU)
        assert ast_alias is not None
        assert ast_alias.name == "HydrocycloneSync"
        assert "%R890" in ast_alias.bound_registers
        assert "%M207" in ast_alias.bound_registers

    def test_pure_st_pou_internal_variables_and_control_logic(self) -> None:
        """Requirement 1: Verify internal boolean variables and interlock IF-branches."""
        ast = STParser.parse_pou(HYDROCYCLONE_PURE_ST_POU)
        assert ast is not None
        var_names = [v.name for v in ast.variables]
        assert "FeedPumpPermissive" in var_names
        assert "ApexFlushValveOpen" in var_names
        assert "VortexStabilizerEngaged" in var_names

        stmts = "\n".join(ast.raw_statements)
        assert "IF CriticalTrip THEN" in stmts
        assert "IF RopingAlarm THEN" in stmts
        assert "IF ApexFlushCmd THEN" in stmts


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
            "XIC FeedPumpPermissive",
            "XIO CriticalTrip",
            "OTE ApexFlushCmd",
            "OTL RopingAlarm",
            "OTU ApexFlushValveOpen",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: Verify all ladder constructs raise LadderForbiddenError."""
        bad_code = f"{HYDROCYCLONE_PURE_ST_POU}\n{ladder_snippet}\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

        val = STParser.validate_code(bad_code)
        assert val.status == AgentStatus.FAILED
        assert val.error_code == "ERR_LADDER_FORBIDDEN"
        assert val.data.get("ladder_rejected") is True


# ============================================================================
# 3. Rietema Swirl Vortex Velocity, Stokes Centrifugal Force & Cut-Size d50
# ============================================================================

class TestRietemaSwirlAndStokesDynamics:
    """Tests for Rietema swirl tangential velocity profile, centrifugal field, and Stokes cut-size."""

    def test_linear_inlet_velocity_scaling(self) -> None:
        """Requirement 3: Verify linear inlet velocity v_i = Q_in / A_in scaling."""
        sim = HydrocycloneSimulator()
        v_nom = sim.compute_inlet_velocity(0.015)
        v_double = sim.compute_inlet_velocity(0.030)
        v_zero = sim.compute_inlet_velocity(0.0)

        assert v_nom > 0.0
        assert math.isclose(v_double, 2.0 * v_nom, rel_tol=1e-4)
        assert v_zero == 0.0

        # Physical accuracy: for D_i = 40 mm and Q = 0.015 m3/s, v_i ~ 11.94 m/s
        area = (math.pi / 4.0) * (sim.config.d_i_m ** 2)
        expected_v = 0.015 / area
        assert math.isclose(v_nom, expected_v, rel_tol=1e-4)

    def test_tangential_swirl_vortex_velocity_profile(self) -> None:
        """Requirement 3: Verify free vortex velocity v_t(r) increases towards inner core."""
        sim = HydrocycloneSimulator()
        r_outer = sim.config.d_c_m / 2.0       # 0.10 m (outer wall)
        r_mid = sim.config.d_c_m / 3.0         # 0.067 m
        r_inner = sim.config.d_o_m / 2.0       # 0.035 m (vortex finder lip)

        v_outer = sim.compute_tangential_velocity_profile(r_outer)
        v_mid = sim.compute_tangential_velocity_profile(r_mid)
        v_inner = sim.compute_tangential_velocity_profile(r_inner)

        # Free vortex acceleration towards center: v_outer < v_mid < v_inner
        assert v_outer > 0.0
        assert v_outer < v_mid < v_inner

        # Analytical power-law consistency: v_t(r) / v_t0 = (R_c / r)^n
        v_i = sim.compute_inlet_velocity()
        v_t0 = sim.config.vortex_alpha * v_i
        expected_mid = v_t0 * ((r_outer / r_mid) ** sim.config.vortex_swirl_n)
        assert math.isclose(v_mid, expected_mid, rel_tol=1e-4)

    def test_centrifugal_acceleration_and_g_force_field(self) -> None:
        """Requirement 3: Verify centrifugal acceleration a_c = v_t^2 / r and G-force field."""
        sim = HydrocycloneSimulator()
        a_c, g_force = sim.compute_centrifugal_field()

        assert a_c > 100.0  # Centrifugal acceleration exceeds 100 m/s^2
        assert g_force > 10.0  # Centrifugal field > 10 Gs
        assert math.isclose(g_force, a_c / 9.80665, rel_tol=1e-4)

        # Doubling feed flow quadruples centrifugal acceleration
        a_c_2x, g_2x = sim.compute_centrifugal_field(q_in_m3_s=2.0 * sim.config.q_in_nom_m3_s)
        assert math.isclose(a_c_2x, 4.0 * a_c, rel_tol=1e-3)
        assert math.isclose(g_2x, 4.0 * g_force, rel_tol=1e-3)

    def test_stokes_centrifugal_force_and_radial_migration(self) -> None:
        """Requirement 3: Verify Stokes centrifugal force F_c ~ d_p^3 and migration velocity v_r ~ d_p^2."""
        sim = HydrocycloneSimulator()
        dp_40 = 40.0e-6
        dp_80 = 80.0e-6

        f_c_40, v_r_40 = sim.compute_stokes_force_and_migration(dp_40)
        f_c_80, v_r_80 = sim.compute_stokes_force_and_migration(dp_80)

        assert f_c_40 > 0.0
        assert v_r_40 > 0.0

        # Centrifugal force scales with volume (d_p^3): doubling diameter -> 8x force
        assert math.isclose(f_c_80, 8.0 * f_c_40, rel_tol=1e-3)

        # Stokes radial settling velocity scales with d_p^2: doubling diameter -> 4x velocity
        assert math.isclose(v_r_80, 4.0 * v_r_40, rel_tol=1e-3)

    def test_rietema_cut_size_d50_scaling_laws(self) -> None:
        """Requirement 3: Verify Rietema cut-size d50 scaling with feed flow, viscosity, and density difference."""
        sim = HydrocycloneSimulator()
        d50_base = sim.compute_cut_size_d50(0.015)
        d50_2x_flow = sim.compute_cut_size_d50(0.030)

        # Higher feed flow yields stronger centrifugal field, hence finer cut-size
        assert d50_2x_flow < d50_base
        # Inverse square-root scaling with Q: d50(2*Q) = d50(Q) / sqrt(2)
        assert math.isclose(d50_2x_flow, d50_base / math.sqrt(2.0), rel_tol=1e-3)

        # Operating range realism: d50 should be between 10 and 50 um for desander
        assert 10.0 <= d50_base <= 50.0

    def test_euler_pressure_drop_quadratic_scaling(self) -> None:
        """Requirement 3: Verify pressure drop scales quadratically with flow rate: Delta_P ~ Q^2."""
        sim = HydrocycloneSimulator()
        dp_1 = sim.compute_pressure_drop(0.015)
        dp_2 = sim.compute_pressure_drop(0.030)

        assert dp_1 > 0.0
        assert math.isclose(dp_2, 4.0 * dp_1, rel_tol=1e-3)


# ============================================================================
# 4. Underflow/Overflow Splitting Ratio, Solids Concentration & Roping
# ============================================================================

class TestFlowSplittingAndRopingDetection:
    """Tests for liquid split ratio, Lynch reduced efficiency curve, and underflow roping detection."""

    def test_liquid_split_ratio_geometry_scaling(self) -> None:
        """Requirement 4: Verify liquid split ratio R_f scales with apex/vortex finder diameter ratio."""
        sim = HydrocycloneSimulator()
        rf_nom = sim.compute_split_ratio(d_u_m=0.03, d_o_m=0.07)
        rf_large_apex = sim.compute_split_ratio(d_u_m=0.04, d_o_m=0.07)
        rf_small_apex = sim.compute_split_ratio(d_u_m=0.02, d_o_m=0.07)

        assert 0.05 <= rf_nom <= 0.20  # Industrial hydrocyclone underflow split 5-20%
        assert rf_large_apex > rf_nom > rf_small_apex

    def test_lynch_solids_partition_curve(self) -> None:
        """Requirement 4: Verify Lynch classification partition curve and recovery bounds."""
        sim = HydrocycloneSimulator()
        rf = sim.compute_split_ratio()
        d50 = 25.0  # um

        # Coarse particles (d_p >> d50) -> high recovery approaching 100%
        es_coarse = sim.compute_separation_efficiency(d_p_m=100.0e-6, d50_um=d50, split_ratio=rf)
        assert es_coarse > 0.95

        # Cut-size particles (d_p == d50) -> reduced efficiency E_c = 0.50
        es_cut = sim.compute_separation_efficiency(d_p_m=25.0e-6, d50_um=d50, split_ratio=rf)
        expected_cut = rf + (1.0 - rf) * 0.50
        assert math.isclose(es_cut, expected_cut, rel_tol=1e-4)

        # Ultra-fine particles (d_p << d50) -> bypass recovery approaching liquid split R_f
        es_fine = sim.compute_separation_efficiency(d_p_m=2.0e-6, d50_um=d50, split_ratio=rf)
        assert math.isclose(es_fine, rf, rel_tol=0.05)
        assert es_fine >= rf

    def test_underflow_solids_concentration_concentration_factor(self) -> None:
        """Requirement 4: Verify underflow concentration factor C_s,u / C_s,in > 1.0."""
        sim = HydrocycloneSimulator()
        rf = sim.compute_split_ratio()
        d50 = sim.compute_cut_size_d50()
        es = sim.compute_separation_efficiency(sim.config.d_p_feed_m, d50, rf)

        bal = sim.compute_mass_balance(
            q_in_m3_s=0.015,
            c_in_g_l=100.0,
            split_ratio=rf,
            efficiency=es,
        )

        assert bal["c_u_g_l"] > 100.0  # Underflow is concentrated
        assert bal["c_o_g_l"] < 100.0  # Overflow is clarified
        assert bal["c_u_g_l"] > bal["c_o_g_l"]

    def test_roping_boundary_transition_and_spray_collapse(self) -> None:
        """Requirement 4: Verify transition from spray umbrella to roping discharge when C_u >= 600 g/L."""
        sim = HydrocycloneSimulator()

        # Below roping boundary: healthy spray discharge
        is_rope_low, phi_low = sim.evaluate_roping_condition(450.0)
        assert is_rope_low is False
        assert phi_low < 0.50

        # At roping threshold: roping triggered
        is_rope_crit, phi_crit = sim.evaluate_roping_condition(600.0)
        assert is_rope_crit is True

        # Above roping threshold
        is_rope_high, phi_high = sim.evaluate_roping_condition(700.0)
        assert is_rope_high is True
        assert phi_high > phi_low

    def test_apex_flush_valve_dilution_mitigation(self) -> None:
        """Requirement 4: Verify apex flush command clears solids accumulation and mitigates roping."""
        sim = HydrocycloneSimulator()
        sim.state.c_underflow_g_l = 650.0
        sim.state.apex_flush_cmd = True
        sim._evaluate_safety_interlocks()

        assert sim.state.apex_flush_active is True


# ============================================================================
# 5. Coupled ODE RK4 Integration Stability & Dual Mass Conservation
# ============================================================================

class TestCoupledHydrocycloneODEIntegration:
    """Tests for coupled 6-state RK4 solver stability, derivatives, and mass conservation."""

    def test_coupled_6state_rk4_solution_stability(self) -> None:
        """Requirement 5: Verify all 6 states remain bounded, positive, and physically realistic."""
        sim = HydrocycloneSimulator()
        res = sim.advance_time(duration_s=2.0, dt=0.05)

        assert res.status == AgentStatus.SUCCESS
        st = sim.state

        # Check bounds of all 6 states
        assert 0.0 < st.q_in_m3_s <= 0.050
        assert 0.0 < st.p_in_kpa < 1000.0
        assert 1.0 < st.d50_um < 100.0
        assert 0.0 < st.c_underflow_g_l < 1000.0
        assert 0.0 < st.c_overflow_g_l < 200.0
        assert st.m_solids_cyc_kg >= 0.0
        assert st.time_s == pytest.approx(2.0, rel=1e-3)

    def test_dual_solids_and_liquid_mass_conservation_residuals(self) -> None:
        """Requirement 5: Verify both solids mass residual and liquid volume residual < 1e-10."""
        sim = HydrocycloneSimulator()
        sim.advance_time(duration_s=1.5, dt=0.05)

        res_solids = sim.state.solids_mass_balance_residual_kg_s
        res_liquid = sim.state.liquid_vol_balance_residual_m3_s

        assert res_solids < 1e-10, f"Solids residual {res_solids:.3e} kg/s exceeds 1e-10"
        assert res_liquid < 1e-10, f"Liquid residual {res_liquid:.3e} m3/s exceeds 1e-10"

    def test_ode_derivatives_deterministic_and_finite(self) -> None:
        """Requirement 5: Verify time derivatives dy/dt are finite and non-NaN across all 6 states."""
        sim = HydrocycloneSimulator()
        y_test = [0.015, 188.0, 25.0, 480.0, 18.0, 1.2]
        dy = sim.ode_derivatives(0.0, y_test)

        assert len(dy) == 6
        for i, val in enumerate(dy):
            assert not math.isnan(val), f"Derivative dy[{i}] is NaN"
            assert not math.isinf(val), f"Derivative dy[{i}] is Inf"

    def test_invalid_timestep_fail_closed(self) -> None:
        """Requirement 5: Verify non-positive duration or timestep fails closed with INVALID_TIMESTEP."""
        sim = HydrocycloneSimulator()

        res_zero = sim.advance_time(duration_s=0.0)
        assert res_zero.status == AgentStatus.FAILED
        assert res_zero.error_code == "INVALID_TIMESTEP"

        res_neg = sim.advance_time(duration_s=1.0, dt=-0.05)
        assert res_neg.status == AgentStatus.FAILED
        assert res_neg.error_code == "INVALID_TIMESTEP"

        res_neg_dur = sim.advance_time(duration_s=-2.0)
        assert res_neg_dur.status == AgentStatus.FAILED
        assert res_neg_dur.error_code == "INVALID_TIMESTEP"

    def test_feed_pump_off_flow_decay(self) -> None:
        """Requirement 5: Verify feed pump off causes flow decay toward zero with mass balance intact."""
        sim = HydrocycloneSimulator()
        sim.state.feed_pump_on = False

        res = sim.advance_time(duration_s=2.0, dt=0.05)
        assert res.status == AgentStatus.SUCCESS
        assert sim.state.q_in_m3_s < 0.005  # Decays toward 0
        assert sim.state.solids_mass_balance_residual_kg_s < 1e-10
        assert sim.state.liquid_vol_balance_residual_m3_s < 1e-10


# ============================================================================
# 6. Process Safety Trips & Diagnostics
# ============================================================================

class TestHydrocycloneProcessSafetyTrips:
    """Tests for %M207 (0x9901), %M208 (0x9902, 0x9903), %M209 flush, and diagnostic hierarchy."""

    def test_roping_warning_alarm_and_code(self) -> None:
        """Requirement 6: Verify Roping warning alarm (%M207, 0x9901) when C_u >= 600.0 g/L."""
        reg_table = RegisterTable()
        sim = HydrocycloneSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M207") is False

        # Set underflow concentration into roping region
        sim.state.c_underflow_g_l = 620.0
        sim._update_hydrodynamics_from_state()
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.roping_detected is True
        assert sim.state.roping_alarm is True
        assert sim.state.spray_discharge_ok is False
        assert sim.state.critical_trip is False
        assert reg_table.read_bit("%M207") is True
        assert reg_table.read_bit("%M208") is False
        assert (reg_table.read_word("%R897") & 0xFFFF) == int(HydrocycloneDiagnosticCode.ROPING_WARNING)
        assert bool(reg_table.read_word("%R890") & int(HydrocycloneStatusBits.ROPING_WARNING)) is True
        assert sim.state.feed_pump_on is True  # Warning alone does not trip feed pump

    def test_overpressure_trip_and_pump_permissive(self) -> None:
        """Requirement 6: Verify Overpressure trip (%M208, 0x9902) when P_in >= 350.0 kPa."""
        reg_table = RegisterTable()
        sim = HydrocycloneSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M208") is False

        # Set inlet pressure above 350.0 kPa trip limit
        sim.state.p_in_kpa = 365.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.overpressure_trip is True
        assert sim.state.critical_trip is True
        assert sim.state.feed_pump_on is False  # Permissive disabled
        assert reg_table.read_bit("%M208") is True
        assert (reg_table.read_word("%R897") & 0xFFFF) == int(HydrocycloneDiagnosticCode.OVERPRESSURE_TRIP)
        assert bool(reg_table.read_word("%R890") & int(HydrocycloneStatusBits.OVERPRESSURE_TRIP)) is True

    def test_apex_blockage_trip_and_code(self) -> None:
        """Requirement 6: Verify Apex blockage trip (%M208, 0x9903) when Q_u < threshold."""
        reg_table = RegisterTable()
        sim = HydrocycloneSimulator(register_table=reg_table)

        # Trigger apex blockage
        sim.state.q_in_m3_s = 0.015
        sim.state.q_underflow_m3_s = 0.0001  # Below 0.0003 m3/s threshold
        sim.state.apex_blocked = True
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.apex_blockage_trip is True
        assert sim.state.critical_trip is True
        assert sim.state.feed_pump_on is False
        assert reg_table.read_bit("%M208") is True
        assert (reg_table.read_word("%R897") & 0xFFFF) == int(HydrocycloneDiagnosticCode.APEX_BLOCKAGE_TRIP)
        assert bool(reg_table.read_word("%R890") & int(HydrocycloneStatusBits.APEX_BLOCKAGE_TRIP)) is True

    def test_apex_flush_command_and_coil(self) -> None:
        """Requirement 6: Verify Apex flush command (%M209) active when commanded."""
        reg_table = RegisterTable()
        sim = HydrocycloneSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M209") is False

        sim.state.apex_flush_cmd = True
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert sim.state.apex_flush_active is True
        assert reg_table.read_bit("%M209") is True
        assert bool(reg_table.read_word("%R890") & int(HydrocycloneStatusBits.APEX_FLUSH_ACTIVE)) is True

    def test_diagnostic_code_priority_hierarchy(self) -> None:
        """Requirement 6: Priority: Blockage (0x9903) > Overpressure (0x9902) > Roping (0x9901) > OK (0x0000)."""
        reg_table = RegisterTable()
        sim = HydrocycloneSimulator(register_table=reg_table)

        # Trigger roping, overpressure, and blockage simultaneously
        sim.state.c_underflow_g_l = 650.0  # Triggers 0x9901
        sim.state.p_in_kpa = 380.0         # Triggers 0x9902
        sim.state.apex_blocked = True      # Triggers 0x9903
        sim._update_hydrodynamics_from_state()
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        # Highest priority: Blockage (0x9903)
        assert (reg_table.read_word("%R897") & 0xFFFF) == int(HydrocycloneDiagnosticCode.APEX_BLOCKAGE_TRIP)

        # Clear blockage -> Overpressure (0x9902) takes precedence
        sim.state.apex_blocked = False
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert (reg_table.read_word("%R897") & 0xFFFF) == int(HydrocycloneDiagnosticCode.OVERPRESSURE_TRIP)

        # Clear overpressure -> Roping Warning (0x9901) takes precedence
        sim.state.p_in_kpa = 200.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert (reg_table.read_word("%R897") & 0xFFFF) == int(HydrocycloneDiagnosticCode.ROPING_WARNING)

        # Clear roping -> OK (0x0000)
        sim.state.c_underflow_g_l = 450.0
        sim._update_hydrodynamics_from_state()
        sim._evaluate_safety_interlocks()
        sim._sync_registers()
        assert (reg_table.read_word("%R897") & 0xFFFF) == int(HydrocycloneDiagnosticCode.OK)


# ============================================================================
# 7. Horner OCS Register Space Synchronization
# ============================================================================

class TestHornerOCSSync:
    """Tests for Horner APG OCS register space mapping (%R890..%R897, %M207..%M209)."""

    def test_register_space_synchronization_nominal(self) -> None:
        """Requirement 7: Verify %R890..%R897 analog registers and %M207..%M209 discrete coils."""
        reg_table = RegisterTable()
        sim = HydrocycloneSimulator(register_table=reg_table)
        sim.advance_time(duration_s=0.5, dt=0.05)

        r890 = reg_table.read_uword("%R890")
        r891 = reg_table.read_word("%R891")
        r892 = reg_table.read_word("%R892")
        r893 = reg_table.read_word("%R893")
        r894 = reg_table.read_word("%R894")
        r895 = reg_table.read_word("%R895")
        r896 = reg_table.read_word("%R896")
        r897 = reg_table.read_uword("%R897")

        # %R890 Status Word
        assert (r890 & int(HydrocycloneStatusBits.RUNNING)) != 0
        assert (r890 & int(HydrocycloneStatusBits.FEED_PUMP_ON)) != 0
        assert (r890 & int(HydrocycloneStatusBits.SPRAY_DISCHARGE_OK)) != 0
        assert (r890 & int(HydrocycloneStatusBits.SEPARATION_HEALTHY)) != 0
        assert (r890 & int(HydrocycloneStatusBits.ROPING_WARNING)) == 0
        assert (r890 & int(HydrocycloneStatusBits.OVERPRESSURE_TRIP)) == 0
        assert (r890 & int(HydrocycloneStatusBits.APEX_BLOCKAGE_TRIP)) == 0

        # %R891: Feed flow scaled x10 m3/h (> 0)
        assert r891 > 0

        # %R892: Inlet pressure scaled x10 kPa (> 0)
        assert r892 > 0

        # %R893: Cut size scaled x10 um (> 0)
        assert r893 > 0

        # %R894: Underflow concentration scaled x10 g/L (> 0)
        assert r894 > 0

        # %R895: Overflow concentration scaled x10 g/L (> 0)
        assert r895 > 0

        # %R896: Split ratio scaled x100 % (> 0)
        assert r896 > 0

        # %R897: Diagnostic event code OK (0x0000)
        assert r897 == int(HydrocycloneDiagnosticCode.OK)

        # Discrete Coils normal
        assert reg_table.read_bit("%M207") is False
        assert reg_table.read_bit("%M208") is False
        assert reg_table.read_bit("%M209") is False

    def test_register_exact_scaling_precision(self) -> None:
        """Requirement 7: Verify exact scaled analog register mapping."""
        reg_table = RegisterTable()
        sim = HydrocycloneSimulator(register_table=reg_table)

        # Set specific known states
        sim.state.q_in_m3_s = 0.0150        # 0.0150 * 3600 = 54.0 m3/h -> 540
        sim.state.p_in_kpa = 188.7          # 188.7 * 10 = 1887
        sim.state.d50_um = 25.6             # 25.6 * 10 = 256
        sim.state.c_underflow_g_l = 480.0   # 480.0 * 10 = 4800
        sim.state.c_overflow_g_l = 18.0     # 18.0 * 10 = 180
        sim.state.split_ratio = 0.1020      # 10.20 % * 100 = 1020
        sim._sync_registers()

        assert reg_table.read_word("%R891") == 540
        assert reg_table.read_word("%R892") == 1887
        assert reg_table.read_word("%R893") == 256
        assert reg_table.read_word("%R894") == 4800
        assert reg_table.read_word("%R895") == 180
        assert reg_table.read_word("%R896") == 1020

    def test_compatibility_class_aliases(self) -> None:
        """Requirement 7: Verify model, engine, config, and state aliases instantiate consistently."""
        sim1 = HydrocycloneSimulator()
        sim2 = HydrocycloneSimulationEngine()
        sim3 = HydrocycloneModel()
        sim4 = HydrocycloneEngine()

        assert isinstance(sim1, HydrocycloneSimulator)
        assert isinstance(sim2, HydrocycloneSimulator)
        assert isinstance(sim3, HydrocycloneSimulator)
        assert isinstance(sim4, HydrocycloneSimulator)

        cfg1 = HydrocycloneConfig()
        cfg2 = HydrocycloneParameters()
        assert isinstance(cfg1, HydrocycloneConfig)
        assert isinstance(cfg2, HydrocycloneConfig)

        st = HydrocycloneState()
        assert isinstance(st, HydrocycloneState)

        assert HydrocycloneStatusWord is HydrocycloneStatusBits
        assert HydrocycloneDiagnosticCode is HydrocycloneDiagnosticCode

    def test_state_property_getters_and_setters(self) -> None:
        """Requirement 7: Verify convenience property getters and setters on HydrocycloneState."""
        st = HydrocycloneState()
        st.q_in = 0.020
        assert st.q_in == 0.020
        assert st.q_in_m3_s == 0.020

        st.p_in = 220.0
        assert st.p_in == 220.0
        assert st.p_in_kpa == 220.0

        st.d50 = 22.5
        assert st.d50 == 22.5
        assert st.d50_um == 22.5

        st.c_underflow = 510.0
        assert st.c_underflow == 510.0
        assert st.c_underflow_g_l == 510.0

        st.c_overflow = 12.0
        assert st.c_overflow == 12.0
        assert st.c_overflow_g_l == 12.0

        st.split_ratio_val = 0.115
        assert st.split_ratio_val == 0.115
        assert st.split_ratio == 0.115


# ============================================================================
# 8. End-to-End 9-Stage Verification Suite Integration Test
# ============================================================================

class TestHydrocycloneVerificationRunner:
    """Tests for the deterministic 9-stage verification runner function."""

    def test_run_hydrocyclone_verification_9_stages(self, tmp_path: Path) -> None:
        """Requirement 8: Verify run_hydrocyclone_verification executes all 9 stages cleanly."""
        evidence_file = tmp_path / "hydrocyclone_evidence.json"
        res = run_hydrocyclone_verification(output_path=str(evidence_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert res["data"]["work_package"] == "W128"
        assert evidence_file.exists()

        # Check evidence file JSON structure
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert len(data["data"]["tests"]) == 9
        for t in data["data"]["tests"]:
            assert t["passed"] is True
            assert "stage" in t
            assert "check" in t
            assert "details" in t

    def test_run_hydrocyclone_verification_evidence_path_parameter(self, tmp_path: Path) -> None:
        """Requirement 8: Verify run_hydrocyclone_verification accepts evidence_path parameter."""
        evidence_file = tmp_path / "hydrocyclone_alt_evidence.json"
        res = run_hydrocyclone_verification(evidence_path=str(evidence_file))

        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert evidence_file.exists()
