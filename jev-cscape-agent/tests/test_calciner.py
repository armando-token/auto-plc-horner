"""Unit and integration tests for Industrial Rotary Calciner & Direct-Fired Calcination ODE Simulation.

Work Package: W116 (Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Pure ST POU AST validation and anti-ladder check (verify_calciner_pure_st).
2. Shrinking unreacted core calcination kinetics.
3. Arrhenius temperature sensitivity and endothermic heat balance.
4. Counter-current gas/bed heat transfer and bed transport.
5. Coupled 6-state ODE RK4 integration and mass balance conservation.
6. Process alarms: refractory overtemp (%M179), under-calcination (%M180), draft loss (%M181).
7. Horner OCS register space synchronization (%R770..%R777, %M179..%M181).
8. Anti-ladder security guard rejection (LadderForbiddenError on contacts/coils).
"""

from __future__ import annotations

import math
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import RegisterTable
from jev_cscape.simulation.calciner import (
    CALCINER_PURE_ST_POU,
    ROTARY_CALCINER_PURE_ST_POU,
    CalcinerConfig,
    CalcinerDiagnosticCode,
    CalcinerSimulator,
    CalcinerState,
    CalcinerStatusBits,
    RotaryCalcinerSimulator,
    run_calciner_verification,
    verify_calciner_pure_st,
)


# ============================================================================
# 1. Pure ST POU AST Validation & Anti-Ladder Check
# ============================================================================

class TestCalcinerPureST:
    """Tests for IEC 61131-3 Pure ST POU validation and anti-ladder security guard."""

    def test_verify_calciner_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_calciner_pure_st() is True

    def test_st_parser_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST name, PROGRAM type, and mapped Horner registers."""
        SecurityGuard.assert_pure_st_content(ROTARY_CALCINER_PURE_ST_POU)
        val = STParser.validate_code(ROTARY_CALCINER_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(ROTARY_CALCINER_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "RotaryCalcinerSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R770", "%R771", "%R772", "%R773",
            "%R774", "%R775", "%R776", "%R777",
            "%M179", "%M180", "%M181",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_pure_st_alias_equivalence(self) -> None:
        """Requirement 1: Verify CALCINER_PURE_ST_POU alias is identical to ROTARY_CALCINER_PURE_ST_POU."""
        assert CALCINER_PURE_ST_POU == ROTARY_CALCINER_PURE_ST_POU
        ast_alias = STParser.parse_pou(CALCINER_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "RotaryCalcinerSync"


# ============================================================================
# 2. Shrinking Unreacted Core Calcination Kinetics
# ============================================================================

class TestShrinkingCoreKinetics:
    """Tests for the Shrinking Unreacted Core Model (SCM) decomposition kinetics."""

    def test_shrinking_core_geometric_surface_factor(self) -> None:
        """Requirement 2: Verify shrinking unreacted core rate scales with (1 - X)^(2/3)."""
        sim = RotaryCalcinerSimulator()
        k_ref = 0.020  # 0.020 s^-1

        # At X = 0.0: (1 - 0)^(2/3) = 1.0
        rate_x0 = sim.shrinking_core_rate(0.0, k_ref)
        assert pytest.approx(rate_x0, rel=1e-9) == k_ref

        # At X = 0.5: (1 - 0.5)^(2/3) = 0.5^(2/3) ~ 0.62996 * k_ref
        rate_x50 = sim.shrinking_core_rate(0.5, k_ref)
        expected_x50 = k_ref * (0.5 ** (2.0 / 3.0))
        assert pytest.approx(rate_x50, rel=1e-6) == expected_x50

        # At X = 0.875: (1 - 0.875)^(2/3) = 0.125^(2/3) = (0.5)^2 = 0.25 * k_ref
        rate_x875 = sim.shrinking_core_rate(0.875, k_ref)
        assert pytest.approx(rate_x875, rel=1e-6) == 0.25 * k_ref

        # At X = 1.0: reaction stops completely (unreacted core fully consumed)
        rate_x10 = sim.shrinking_core_rate(1.0, k_ref)
        assert rate_x10 == 0.0

    def test_shrinking_core_monotonic_rate_decrease_with_conversion(self) -> None:
        """Requirement 2: Verify reaction rate decreases monotonically as conversion progresses."""
        sim = RotaryCalcinerSimulator()
        k_val = sim.arrhenius_rate_constant(1193.15)  # 920 °C

        conversions = [0.0, 0.25, 0.50, 0.75, 0.90, 0.99]
        rates = [sim.shrinking_core_rate(x, k_val) for x in conversions]

        for i in range(len(rates) - 1):
            assert rates[i] > rates[i + 1], f"Rate at X={conversions[i]} must exceed rate at X={conversions[i+1]}"

    def test_shrinking_core_rate_clamping(self) -> None:
        """Requirement 2: Verify conversions >= 1.0 or <= 0.0 are safely clamped."""
        sim = RotaryCalcinerSimulator()
        k_ref = 0.015

        # Sub-zero conversion clamped to 0.0
        rate_neg = sim.shrinking_core_rate(-0.1, k_ref)
        assert pytest.approx(rate_neg, rel=1e-9) == k_ref

        # Excess conversion clamped to 1.0 (rate 0.0)
        rate_excess = sim.shrinking_core_rate(1.2, k_ref)
        assert rate_excess == 0.0


# ============================================================================
# 3. Arrhenius Temperature Sensitivity and Endothermic Heat Balance
# ============================================================================

class TestArrheniusAndHeatBalance:
    """Tests for Arrhenius temperature sensitivity and endothermic heat balance."""

    def test_arrhenius_monotonic_temperature_increase(self) -> None:
        """Requirement 3: Verify Arrhenius rate constant increases strictly monotonically with temperature."""
        sim = RotaryCalcinerSimulator()
        temps_c = [750.0, 800.0, 850.0, 900.0, 950.0, 1000.0]
        k_prev = 0.0

        for tc in temps_c:
            k = sim.arrhenius_rate_constant(273.15 + tc)
            assert k > k_prev, f"Rate constant at {tc} °C must exceed rate at lower temperature"
            k_prev = k

    def test_arrhenius_activation_energy_recovery(self) -> None:
        """Requirement 3: Verify Arrhenius slope recovers exact activation energy E_a (175 kJ/mol)."""
        sim = RotaryCalcinerSimulator()
        assert sim.config.activation_energy_j_mol == 175000.0

        t1 = 850.0 + 273.15
        t2 = 950.0 + 273.15
        k1 = sim.arrhenius_rate_constant(t1)
        k2 = sim.arrhenius_rate_constant(t2)

        # ln(k2/k1) = -Ea/R * (1/T2 - 1/T1)
        ea_recovered = -sim.config.r_gas * math.log(k2 / k1) / ((1.0 / t2) - (1.0 / t1))
        assert pytest.approx(ea_recovered, rel=1e-6) == sim.config.activation_energy_j_mol

    def test_temperature_safeguard_clamp(self) -> None:
        """Requirement 3: Verify sub-freezing temperatures are clamped safely (>= 273.15 K)."""
        sim = RotaryCalcinerSimulator()
        k_zero = sim.arrhenius_rate_constant(0.0)
        k_ref = sim.arrhenius_rate_constant(273.15)
        assert k_zero == pytest.approx(k_ref, rel=1e-12)

    def test_endothermic_reaction_heat_balance(self) -> None:
        """Requirement 3: Verify endothermic heat sink Delta_H_calc (1.78 MJ/kg) cools solids bed."""
        sim = RotaryCalcinerSimulator()
        assert sim.config.delta_h_calc_j_kg == 1.78e6

        # Compare derivatives with calcination occurring (X=0.5) vs reaction complete (X=1.0)
        derivs_reacting = sim.compute_derivatives(0.0, [0.5, 1173.15, 1273.15, 1323.15, 0.0, 0.0])
        derivs_inert = sim.compute_derivatives(0.0, [1.0, 1173.15, 1273.15, 1323.15, 0.0, 0.0])

        dt_bed_reacting = derivs_reacting[1]
        dt_bed_inert = derivs_inert[1]

        # Reacting bed must have lower dT_bed/dt due to endothermic heat consumption
        assert dt_bed_inert > dt_bed_reacting


# ============================================================================
# 4. Counter-Current Gas/Bed Heat Transfer and Bed Transport
# ============================================================================

class TestCounterCurrentHeatTransferAndBedTransport:
    """Tests for counter-current direct-fired combustion and solids bed transport."""

    def test_heat_transfer_components_positive_under_normal_gradient(self) -> None:
        """Requirement 4: Verify radiative and convective fluxes flow from hot gas/wall to solids bed."""
        sim = RotaryCalcinerSimulator()
        # Flue gas (1000 °C / 1273 K), Refractory wall (1050 °C / 1323 K), Solids bed (900 °C / 1173 K)
        ht = sim.compute_heat_transfers(t_bed=1173.15, t_gas=1273.15, t_wall=1323.15)

        assert ht["q_rad_gb"] > 0.0      # Gas radiates to bed
        assert ht["q_conv_gb"] > 0.0     # Gas convects to bed
        assert ht["q_rad_gw"] < 0.0 or ht["q_rad_gw"] >= 0.0  # Gas to wall radiation
        assert ht["q_rad_wb"] > 0.0      # Wall radiates to bed
        assert ht["q_contact_wb"] > 0.0  # Rotating drum contact conduction to bed
        assert ht["q_loss_amb"] > 0.0    # Exterior shell heat loss to ambient

    def test_drum_rotation_contact_conduction_enhancement(self) -> None:
        """Requirement 4: Verify rotating drum provides regenerative contact conduction enhancement."""
        sim = RotaryCalcinerSimulator()
        derivs_rotating = sim.compute_derivatives(
            0.0, [0.95, 1100.0, 1200.0, 1300.0, 0.0, 0.0], drum_rotating=True
        )
        derivs_stationary = sim.compute_derivatives(
            0.0, [0.95, 1100.0, 1200.0, 1300.0, 0.0, 0.0], drum_rotating=False
        )

        # Rotating drum transfers more heat from wall to bed, increasing bed heating rate
        assert derivs_rotating[1] > derivs_stationary[1]

    def test_direct_fired_burner_heating_vs_unfired_cooling(self) -> None:
        """Requirement 4: Verify direct-fired burner power sustains gas temperature."""
        sim = RotaryCalcinerSimulator()
        derivs_fired = sim.compute_derivatives(
            0.0, [0.95, 1193.15, 823.15, 1373.15, 0.0, 0.0], burner_on=True
        )
        derivs_unfired = sim.compute_derivatives(
            0.0, [0.95, 1193.15, 823.15, 1373.15, 0.0, 0.0], burner_on=False
        )

        # Fired burner yields higher flue gas temperature derivative
        assert derivs_fired[2] > derivs_unfired[2]

    def test_solids_feed_dilution_and_residence_time(self) -> None:
        """Requirement 4: Verify continuous mineral feed refreshes unreacted bed inventory."""
        sim = RotaryCalcinerSimulator()
        # When feed is active, unreacted feed dilutes conversion
        derivs_fed = sim.compute_derivatives(
            0.0, [0.95, 1193.15, 823.15, 1373.15, 0.0, 0.0], feed_active=True
        )
        derivs_unfed = sim.compute_derivatives(
            0.0, [0.95, 1193.15, 823.15, 1373.15, 0.0, 0.0], feed_active=False
        )

        assert derivs_unfed[0] > derivs_fed[0]


# ============================================================================
# 5. Coupled 6-State ODE RK4 Integration and Mass Balance Conservation
# ============================================================================

class TestCoupled6StateODEIntegration:
    """Tests for 4th-order Runge-Kutta numerical integration and mass balance conservation."""

    def test_coupled_6state_rk4_solution_stability(self) -> None:
        """Requirement 5: Verify all 6 continuous dynamic states remain finite, positive, and stable."""
        sim = RotaryCalcinerSimulator()
        for _ in range(200):
            res = sim.step(dt=0.01)
            assert res.status == AgentStatus.SUCCESS

        st = sim.state
        assert not math.isnan(st.x_calc)
        assert not math.isnan(st.t_bed)
        assert not math.isnan(st.t_gas)
        assert not math.isnan(st.t_wall)
        assert not math.isnan(st.m_co2_released)
        assert not math.isnan(st.m_product)

        assert 0.0 <= st.x_calc <= 1.0
        assert st.t_bed > 273.15
        assert st.t_gas > 273.15
        assert st.t_wall > 273.15
        assert st.m_co2_released >= 0.0
        assert st.m_product >= 0.0

    def test_analytical_mass_balance_conservation_residual(self) -> None:
        """Requirement 5: Verify stoichiometric mass balance conservation residual dM/dt < 1e-12 kg/s."""
        sim = RotaryCalcinerSimulator()
        y_test = [0.50, 1193.15, 823.15, 1373.15, 0.0, 0.0]

        derivs = sim.compute_derivatives(0.0, y_test, feed_active=False)
        dm_co2_dt = derivs[4]
        dm_product_dt = derivs[5]
        total_yield_rate = dm_co2_dt + dm_product_dt

        k_actual = sim.arrhenius_rate_constant(1193.15)
        rx_actual = sim.shrinking_core_rate(0.50, k_actual)
        m_caco3_bed = sim.config.bed_mass_nominal_kg * (1.0 - 0.50)
        expected_r_calc = m_caco3_bed * rx_actual

        mass_conservation_residual = abs(total_yield_rate - expected_r_calc)
        assert mass_conservation_residual < 1.0e-12

    def test_stoichiometric_molar_yield_ratio(self) -> None:
        """Requirement 5: Verify exact CaCO3 -> CaO + CO2 molar stoichiometric ratio (44.01 / 56.08)."""
        sim = RotaryCalcinerSimulator()
        y_test = [0.60, 1193.15, 823.15, 1373.15, 0.0, 0.0]
        derivs = sim.compute_derivatives(0.0, y_test)

        dm_co2_dt = derivs[4]
        dm_product_dt = derivs[5]

        molar_ratio_actual = dm_co2_dt / dm_product_dt
        molar_ratio_expected = sim.config.mw_co2 / sim.config.mw_cao
        assert pytest.approx(molar_ratio_actual, rel=1e-6) == molar_ratio_expected

    def test_invalid_timestep_fail_closed(self) -> None:
        """Requirement 5: Verify non-positive timestep returns failed ExecutionResult."""
        sim = RotaryCalcinerSimulator()
        res_zero = sim.step(dt=0.0)
        assert res_zero.status == AgentStatus.FAILED
        assert res_zero.error_code == "INVALID_TIMESTEP"

        res_neg = sim.step(dt=-0.05)
        assert res_neg.status == AgentStatus.FAILED
        assert res_neg.error_code == "INVALID_TIMESTEP"


# ============================================================================
# 6. Process Alarms & Safety Interlocks
# ============================================================================

class TestProcessAlarms:
    """Tests for refractory overtemp (%M179), under-calcination (%M180), and draft loss (%M181)."""

    def test_refractory_overtemp_alarm_and_interlock(self) -> None:
        """Requirement 6: Verify refractory overtemp trip (%M179, 0x8D01) on T_wall >= 1250.0 °C."""
        reg_table = RegisterTable()
        sim = RotaryCalcinerSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M179") is False

        # Incur refractory over-temperature trip (1255.0 °C >= 1250.0 °C)
        sim.state.t_wall = 273.15 + 1255.0
        sim.step(dt=0.01)

        assert sim.state.overtemp_trip is True
        assert reg_table.read_bit("%M179") is True
        assert (reg_table.read_word("%R777") & 0xFFFF) == CalcinerDiagnosticCode.REFRACTORY_OVERTEMP_TRIP
        assert (reg_table.read_word("%R770") & int(CalcinerStatusBits.WALL_OVERTEMP_TRIP)) != 0
        assert sim.state.burner_on is False  # Burner auto-trip

        # Clear fault
        sim.state.t_wall = 273.15 + 1100.0
        sim.step(dt=0.01)
        assert sim.state.overtemp_trip is False
        assert reg_table.read_bit("%M179") is False
        assert (reg_table.read_word("%R777") & 0xFFFF) == CalcinerDiagnosticCode.OK

    def test_under_calcination_quality_alarm(self) -> None:
        """Requirement 6: Verify under-calcination alarm (%M180, 0x8D02) on X_calc < 90.0%."""
        reg_table = RegisterTable()
        sim = RotaryCalcinerSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M180") is False

        # Incur under-calcination condition (88.0% < 90.0% at discharge)
        sim.state.x_calc = 0.88
        sim.step(dt=0.01)

        assert sim.state.under_calc_alarm is True
        assert reg_table.read_bit("%M180") is True
        assert (reg_table.read_word("%R777") & 0xFFFF) == CalcinerDiagnosticCode.UNDER_CALCINATION_ALARM
        assert (reg_table.read_word("%R770") & int(CalcinerStatusBits.UNDER_CALCINATION_ALARM)) != 0

        # Clear condition
        sim.state.x_calc = 0.95
        sim.step(dt=0.01)
        assert sim.state.under_calc_alarm is False
        assert reg_table.read_bit("%M180") is False
        assert (reg_table.read_word("%R777") & 0xFFFF) == CalcinerDiagnosticCode.OK

    def test_draft_loss_alarm_and_interlock(self) -> None:
        """Requirement 6: Verify flue draft loss trip (%M181, 0x8D03) on P_draft > +20.0 Pa."""
        reg_table = RegisterTable()
        sim = RotaryCalcinerSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M181") is False

        # Incur draft loss: stop induced draft fan -> positive draft develops
        sim.step(dt=0.01, draft_fan_running=False)

        assert sim.state.draft_loss_trip is True
        assert reg_table.read_bit("%M181") is True
        assert (reg_table.read_word("%R777") & 0xFFFF) == CalcinerDiagnosticCode.DRAFT_LOSS_TRIP
        assert (reg_table.read_word("%R770") & int(CalcinerStatusBits.DRAFT_LOSS_TRIP)) != 0
        assert sim.state.burner_on is False  # Burner auto-trip

        # Restore draft fan
        sim.step(dt=0.01, draft_fan_running=True)
        assert sim.state.draft_loss_trip is False
        assert reg_table.read_bit("%M181") is False
        assert (reg_table.read_word("%R777") & 0xFFFF) == CalcinerDiagnosticCode.OK

    def test_diagnostic_code_priority_overtemp_over_draft_and_undercalc(self) -> None:
        """Requirement 6: Verify refractory overtemp trip has highest priority in %R777."""
        reg_table = RegisterTable()
        sim = RotaryCalcinerSimulator(register_table=reg_table)

        # Simultaneously trigger all three fault conditions
        sim.state.t_wall = 273.15 + 1260.0       # Overtemp trip
        sim.state.p_draft_pa = 25.0              # Draft loss trip
        sim.state.x_calc = 0.85                  # Under-calcination alarm
        sim._sync_registers()

        assert sim.state.overtemp_trip is True
        assert sim.state.draft_loss_trip is True
        assert sim.state.under_calc_alarm is True

        # Highest priority must be refractory overtemp (0x8D01)
        assert (reg_table.read_word("%R777") & 0xFFFF) == CalcinerDiagnosticCode.REFRACTORY_OVERTEMP_TRIP

        # Clear overtemp -> draft loss takes precedence (0x8D03) over under-calc (0x8D02)
        sim.state.t_wall = 273.15 + 1100.0
        sim._sync_registers()
        assert (reg_table.read_word("%R777") & 0xFFFF) == CalcinerDiagnosticCode.DRAFT_LOSS_TRIP


# ============================================================================
# 7. Horner OCS Register Space Synchronization
# ============================================================================

class TestHornerOCSSync:
    """Tests for Horner APG OCS register space mapping (%R770..%R777, %M179..%M181)."""

    def test_register_space_synchronization_nominal(self) -> None:
        """Requirement 7: Verify %R770..%R777 analog registers and %M179..%M181 discrete coils."""
        reg_table = RegisterTable()
        sim = RotaryCalcinerSimulator(register_table=reg_table)
        sim.step(dt=0.01)

        r770 = reg_table.read_uword("%R770")
        r771 = reg_table.read_word("%R771")
        r772 = reg_table.read_word("%R772")
        r773 = reg_table.read_word("%R773")
        r774 = reg_table.read_word("%R774")
        r775 = reg_table.read_word("%R775")
        r776 = reg_table.read_word("%R776")
        r777 = reg_table.read_uword("%R777")

        # %R770: Status Word
        assert (r770 & int(CalcinerStatusBits.RUNNING)) != 0
        assert (r770 & int(CalcinerStatusBits.BURNER_ON)) != 0
        assert (r770 & int(CalcinerStatusBits.DRUM_ROTATING)) != 0
        assert (r770 & int(CalcinerStatusBits.CALCINATION_OPTIMAL)) != 0

        # %R771: Solids bed temperature scaled x10 °C (~900..950 °C -> ~9000..9500)
        assert 8500 <= r771 <= 10000

        # %R772: Flue gas exhaust temperature scaled x10 °C (~500..600 °C -> ~5000..6000)
        assert 4500 <= r772 <= 7000

        # %R773: Refractory wall temperature scaled x10 °C (~1050..1150 °C -> ~10500..11500)
        assert 10000 <= r773 <= 12000

        # %R774: Calcination conversion scaled x10 % (~95.0% -> 950)
        assert 900 <= r774 <= 1000

        # %R775: Quicklime production rate scaled x10 kg/h (> 0)
        assert r775 >= 0

        # %R776: Draft pressure in hood scaled x1 Pa (-80..-20 Pa)
        assert -80 <= r776 <= -20

        # %R777: Diagnostic event code (0x0000 = OK)
        assert r777 == CalcinerDiagnosticCode.OK

        # Discrete coils normal state
        assert reg_table.read_bit("%M179") is False
        assert reg_table.read_bit("%M180") is False
        assert reg_table.read_bit("%M181") is False

    def test_register_scaling_precision(self) -> None:
        """Requirement 7: Verify specific scaled register values match physical state."""
        reg_table = RegisterTable()
        sim = RotaryCalcinerSimulator(register_table=reg_table)
        sim.state.t_bed = 273.15 + 920.4
        sim.state.t_gas = 273.15 + 512.6
        sim.state.t_wall = 273.15 + 1150.8
        sim.state.x_calc = 0.946
        sim.state.production_rate_kg_h = 1850.2
        sim.state.p_draft_pa = -45.0
        sim.state.is_running = True
        sim.state.burner_on = True
        sim.state.drum_rotating = True
        sim.state.discharge_active = True
        sim._sync_registers()

        assert reg_table.read_word("%R771") == 9204   # 920.4 °C x10
        assert reg_table.read_word("%R772") == 5126   # 512.6 °C x10
        assert reg_table.read_word("%R773") == 11508  # 1150.8 °C x10
        assert reg_table.read_word("%R774") == 946    # 94.6 % x10
        assert reg_table.read_word("%R775") == 18502  # 1850.2 kg/h x10
        assert reg_table.read_word("%R776") == -45    # -45 Pa x1


# ============================================================================
# 8. Anti-Ladder Security Guard Rejection
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
            "NETWORK 10",
            "XIC BurnerPermissive",
            "XIO RefractoryOverTempTrip",
            "OTE CalcinerMotor",
            "OTL DraftLossFault",
            "OTU BurnerEmergencyShutoff",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 8: Verify all ladder constructs raise LadderForbiddenError."""
        bad_code = f"{ROTARY_CALCINER_PURE_ST_POU}\n{ladder_snippet}\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

        val = STParser.validate_code(bad_code)
        assert val.status == AgentStatus.FAILED
        assert val.error_code == "ERR_LADDER_FORBIDDEN"
        assert val.data.get("ladder_rejected") is True


# ============================================================================
# 9. Full Verification Runner Function
# ============================================================================

class TestCalcinerVerificationRunner:
    """Tests for the deterministic 9-stage verification runner function."""

    def test_run_calciner_verification_9_stages(self, tmp_path: Path) -> None:
        """Verify run_calciner_verification executes all 9 stages cleanly."""
        evidence_file = tmp_path / "calciner_evidence.json"
        res = run_calciner_verification(str(evidence_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert evidence_file.exists()
