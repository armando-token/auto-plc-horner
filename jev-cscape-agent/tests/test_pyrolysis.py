"""Unit and integration tests for Industrial Biomass Pyrolysis & Fast Thermal Decomposition ODE Simulation.

Work Package: W113 (Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Pure ST POU AST validation and anti-ladder check (verify_pyrolysis_pure_st).
2. Shafizadeh 3-component kinetic rate calculations.
3. Temperature dependence and Arrhenius rate constants.
4. Quench condenser heat balance and bio-oil recovery.
5. Coupled 6-state ODE RK4 integration and mass balance conservation.
6. Process alarms: overtemp (%M172), overpressure (%M173), quench fault (%M174).
7. Horner OCS register space synchronization (%R740..%R747, %M172..%M174).
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
from jev_cscape.simulation.pyrolysis import (
    BIOMASS_PYROLYSIS_PURE_ST_POU,
    PYROLYSIS_PURE_ST_POU,
    PyrolysisConfig,
    PyrolysisDiagnosticCode,
    PyrolysisSimulator,
    PyrolysisState,
    PyrolysisStatusBits,
    run_pyrolysis_verification,
    verify_pyrolysis_pure_st,
)


# ============================================================================
# 1. Pure ST POU AST Validation & Anti-Ladder Check
# ============================================================================

class TestPyrolysisPureST:
    """Tests for IEC 61131-3 Pure ST POU validation and anti-ladder security guard."""

    def test_verify_pyrolysis_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_pyrolysis_pure_st() is True

    def test_st_parser_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST name, PROGRAM type, and mapped Horner registers."""
        SecurityGuard.assert_pure_st_content(BIOMASS_PYROLYSIS_PURE_ST_POU)
        val = STParser.validate_code(BIOMASS_PYROLYSIS_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(BIOMASS_PYROLYSIS_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "BiomassPyrolysisSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R740", "%R741", "%R742", "%R743",
            "%R744", "%R745", "%R746", "%R747",
            "%M172", "%M173", "%M174",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_pure_st_alias_equivalence(self) -> None:
        """Requirement 1: Verify PYROLYSIS_PURE_ST_POU alias is identical to BIOMASS_PYROLYSIS_PURE_ST_POU."""
        assert PYROLYSIS_PURE_ST_POU == BIOMASS_PYROLYSIS_PURE_ST_POU
        ast_alias = STParser.parse_pou(PYROLYSIS_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "BiomassPyrolysisSync"


# ============================================================================
# 2. Shafizadeh 3-Component Kinetic Rate Calculations
# ============================================================================

class TestShafizadehKinetics:
    """Tests for Shafizadeh 3-component parallel kinetic rate calculations."""

    def test_shafizadeh_rate_calculation_decomposition(self) -> None:
        """Requirement 2: Verify Shafizadeh 3-pathway rates (bio-oil, syngas, char)."""
        sim = PyrolysisSimulator()
        m_bio = 10.0  # 10 kg
        t_rx = 773.15  # 500 °C

        ro, rg, rc, r_total = sim.shafizadeh_kinetic_rates(t_rx, m_bio)

        # All 3 pathways must produce strictly positive mass generation rates
        assert ro > 0.0
        assert rg > 0.0
        assert rc > 0.0

        # Sum of individual rates must equal total decomposition rate
        assert pytest.approx(ro + rg + rc, rel=1e-12) == r_total

    def test_shafizadeh_bio_oil_selectivity_dominant_at_fast_pyrolysis_temp(self) -> None:
        """Requirement 2: Verify fast pyrolysis temperature (500 °C) favors bio-oil selectivity (> 60%)."""
        sim = PyrolysisSimulator()
        ko, kg, kc = sim.arrhenius_rates(773.15)  # 500 °C

        k_total = ko + kg + kc
        oil_selectivity = ko / k_total
        gas_selectivity = kg / k_total
        char_selectivity = kc / k_total

        # Fast pyrolysis criterion: bio-oil selectivity between 60% and 75%
        assert 0.60 <= oil_selectivity <= 0.75
        assert gas_selectivity > 0.10
        assert char_selectivity > 0.10
        assert pytest.approx(oil_selectivity + gas_selectivity + char_selectivity, rel=1e-12) == 1.0

    def test_shafizadeh_rates_scale_linearly_with_biomass_mass(self) -> None:
        """Requirement 2: Verify reaction rates scale first-order with biomass mass inventory."""
        sim = PyrolysisSimulator()
        t_k = 773.15
        ro_10, rg_10, rc_10, rt_10 = sim.shafizadeh_kinetic_rates(t_k, 10.0)
        ro_20, rg_20, rc_20, rt_20 = sim.shafizadeh_kinetic_rates(t_k, 20.0)

        assert ro_20 == pytest.approx(2.0 * ro_10, rel=1e-9)
        assert rg_20 == pytest.approx(2.0 * rg_10, rel=1e-9)
        assert rc_20 == pytest.approx(2.0 * rc_10, rel=1e-9)
        assert rt_20 == pytest.approx(2.0 * rt_10, rel=1e-9)

    def test_zero_or_negative_biomass_yields_zero_rates(self) -> None:
        """Requirement 2: Verify zero or non-physical negative biomass returns zero reaction rates."""
        sim = PyrolysisSimulator()
        ro, rg, rc, rt = sim.shafizadeh_kinetic_rates(773.15, 0.0)
        assert ro == 0.0 and rg == 0.0 and rc == 0.0 and rt == 0.0

        ro_neg, rg_neg, rc_neg, rt_neg = sim.shafizadeh_kinetic_rates(773.15, -5.0)
        assert ro_neg == 0.0 and rg_neg == 0.0 and rc_neg == 0.0 and rt_neg == 0.0


# ============================================================================
# 3. Temperature Dependence and Arrhenius Rate Constants
# ============================================================================

class TestArrheniusTemperatureDependence:
    """Tests for Arrhenius rate constants and thermal sensitivity across operating regimes."""

    def test_arrhenius_monotonic_increase_with_temperature(self) -> None:
        """Requirement 3: Verify all 3 rate constants increase strictly monotonically with temperature."""
        sim = PyrolysisSimulator()
        temps = [673.15, 723.15, 773.15, 823.15, 873.15]  # 400, 450, 500, 550, 600 °C

        ko_prev, kg_prev, kc_prev = 0.0, 0.0, 0.0
        for t_k in temps:
            ko, kg, kc = sim.arrhenius_rates(t_k)
            assert ko > ko_prev
            assert kg > kg_prev
            assert kc > kc_prev
            ko_prev, kg_prev, kc_prev = ko, kg, kc

    def test_bio_oil_activation_energy_sensitivity(self) -> None:
        """Requirement 3: Verify bio-oil pathway has higher activation energy (140 kJ/mol vs 125 kJ/mol)."""
        sim = PyrolysisSimulator()
        cfg = sim.config
        assert cfg.ea_oil > cfg.ea_gas
        assert cfg.ea_oil > cfg.ea_char

        # Due to higher activation energy, k_oil/k_gas ratio must increase with temperature
        ko_450, kg_450, _ = sim.arrhenius_rates(723.15)
        ko_550, kg_550, _ = sim.arrhenius_rates(823.15)

        ratio_450 = ko_450 / kg_450
        ratio_550 = ko_550 / kg_550
        assert ratio_550 > ratio_450

    def test_low_temperature_slow_kinetics(self) -> None:
        """Requirement 3: Verify low temperature (e.g. 300 °C / 573.15 K) results in negligible fast cracking."""
        sim = PyrolysisSimulator()
        ko_cold, kg_cold, kc_cold = sim.arrhenius_rates(573.15)  # 300 °C
        ko_nom, _, _ = sim.arrhenius_rates(773.15)              # 500 °C

        assert ko_cold < 0.01 * ko_nom
        assert ko_cold < 1e-3

    def test_temperature_safeguard_clamp(self) -> None:
        """Requirement 3: Verify negative or sub-freezing temperatures are clamped safely (>= 273.15 K)."""
        sim = PyrolysisSimulator()
        ko_0, kg_0, kc_0 = sim.arrhenius_rates(0.0)
        ko_ref, kg_ref, kc_ref = sim.arrhenius_rates(273.15)

        assert ko_0 == pytest.approx(ko_ref, rel=1e-12)
        assert kg_0 == pytest.approx(kg_ref, rel=1e-12)
        assert kc_0 == pytest.approx(kc_ref, rel=1e-12)


# ============================================================================
# 4. Quench Condenser Heat Balance and Bio-Oil Recovery
# ============================================================================

class TestQuenchCondenserAndBioOilRecovery:
    """Tests for quench condenser heat balance, condensation efficiency, and cooling dynamics."""

    def test_nominal_quench_temperature_and_cooling(self) -> None:
        """Requirement 4: Verify nominal quench temperature remains below 40 °C target."""
        sim = PyrolysisSimulator()
        for _ in range(100):
            res = sim.step(dt=0.01, condenser_active=True)
            assert res.status == AgentStatus.SUCCESS

        t_quench_c = sim.state.t_quench - 273.15
        assert t_quench_c < 40.0
        assert t_quench_c >= 15.0  # Coolant is 15 °C

    def test_nominal_bio_oil_recovery_fraction(self) -> None:
        """Requirement 4: Verify nominal bio-oil condensation recovery efficiency is >= 95%."""
        sim = PyrolysisSimulator()
        assert sim.config.eta_cond_nominal >= 0.95
        assert sim.config.eta_cond_nominal <= 1.0

    def test_quench_cooling_loss_elevates_quench_temperature(self) -> None:
        """Requirement 4: Verify disabling condenser cooling circuit causes quench temperature to rise."""
        sim = PyrolysisSimulator()
        # Normal step
        for _ in range(50):
            sim.step(dt=0.01, condenser_active=True)

        t_q_initial = sim.state.t_quench

        # Step with condenser inactive (loss of coolant flow)
        for _ in range(100):
            sim.step(dt=0.01, condenser_active=False)

        assert sim.state.t_quench > t_q_initial

    def test_quench_sensible_and_latent_enthalpy_balance(self) -> None:
        """Requirement 4: Verify sensible vapor cooling and latent condensation terms are positive."""
        sim = PyrolysisSimulator()
        ko, _, _ = sim.arrhenius_rates(sim.state.t_reactor)
        r_oil = ko * sim.state.m_biomass
        dt_vap = max(0.0, sim.state.t_reactor - sim.state.t_quench)
        q_sensible = r_oil * sim.config.cp_vapor_j_kg_k * dt_vap
        q_latent = r_oil * sim.config.delta_h_cond_j_kg

        assert q_sensible > 0.0
        assert q_latent > 0.0
        assert sim.config.delta_h_cond_j_kg > 1.0e6  # > 1 MJ/kg latent heat


# ============================================================================
# 5. Coupled 6-State ODE RK4 Integration and Mass Balance Conservation
# ============================================================================

class TestCoupled6StateODEIntegration:
    """Tests for 4th-order Runge-Kutta numerical integration and mass balance conservation."""

    def test_coupled_6state_rk4_solution_stability(self) -> None:
        """Requirement 5: Verify all 6 continuous dynamic states remain finite, positive, and stable."""
        sim = PyrolysisSimulator()
        for _ in range(150):
            res = sim.step(dt=0.01, feeder_active=True, fluidizing_active=True)
            assert res.status == AgentStatus.SUCCESS

        st = sim.state
        assert not math.isnan(st.m_biomass)
        assert not math.isnan(st.m_char)
        assert not math.isnan(st.m_bio_oil)
        assert not math.isnan(st.m_syngas)
        assert not math.isnan(st.t_reactor)
        assert not math.isnan(st.p_reactor)

        assert st.m_biomass >= 0.0
        assert st.m_char >= 0.0
        assert st.m_bio_oil >= 0.0
        assert st.m_syngas >= 0.0
        assert st.t_reactor > 273.15
        assert st.p_reactor > 0.0

    def test_analytical_mass_balance_conservation_residual(self) -> None:
        """Requirement 5: Verify mass conservation residual d(M_total)/dt < 1e-12 in closed system."""
        sim = PyrolysisSimulator()
        y_test = [8.0, 2.0, 3.0, 1.5, 773.15, 1050.0]

        # Derivatives with no external feed and no char discharge (pure closed reactor decomposition)
        derivs = sim.compute_derivatives(
            t=0.0,
            y=y_test,
            feeder_active=False,
            char_discharge_active=False,
        )

        dm_bio_dt = derivs[0]
        dm_char_dt = derivs[1]
        dm_oil_dt = derivs[2]
        dm_gas_dt = derivs[3]

        total_dm_dt = dm_bio_dt + dm_char_dt + dm_oil_dt + dm_gas_dt
        assert abs(total_dm_dt) < 1.0e-12

    def test_rk4_cumulative_mass_conservation_over_time(self) -> None:
        """Requirement 5: Verify total system mass matches initial + fed biomass over 200 RK4 steps."""
        sim = PyrolysisSimulator()
        initial_inventory = sim.state.m_biomass
        feed_rate_kg_s = sim.config.feed_rate_kg_h / 3600.0
        dt = 0.01
        steps = 200

        for _ in range(steps):
            res = sim.step(dt=dt, feeder_active=True, char_discharge_active=False)
            assert res.status == AgentStatus.SUCCESS

        total_fed = steps * dt * feed_rate_kg_s
        expected_total_mass = initial_inventory + total_fed
        actual_total_mass = (
            sim.state.m_biomass
            + sim.state.m_char
            + sim.state.m_bio_oil
            + sim.state.m_syngas
        )

        mass_error = abs(actual_total_mass - expected_total_mass)
        assert mass_error < 0.001  # Conserved to within 1 gram (< 0.01%)

    def test_invalid_timestep_fail_closed(self) -> None:
        """Requirement 5: Verify non-positive timestep returns failed ExecutionResult."""
        sim = PyrolysisSimulator()
        res_zero = sim.step(dt=0.0)
        assert res_zero.status == AgentStatus.FAILED
        assert res_zero.error_code == "ERR_INVALID_TIMESTEP"

        res_neg = sim.step(dt=-0.05)
        assert res_neg.status == AgentStatus.FAILED
        assert res_neg.error_code == "ERR_INVALID_TIMESTEP"


# ============================================================================
# 6. Process Alarms & Safety Interlocks
# ============================================================================

class TestProcessAlarms:
    """Tests for overtemp (%M172), overpressure (%M173), and quench fault (%M174)."""

    def test_reactor_overtemp_alarm_and_interlock(self) -> None:
        """Requirement 6: Verify overtemp trip (%M172, 0x8A01) on T_reactor >= 680.0 °C."""
        reg_table = RegisterTable()
        sim = PyrolysisSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M172") is False

        # Inject overtemperature condition (685.0 °C >= 680.0 °C)
        sim.state.t_reactor = 273.15 + 685.0
        sim._sync_registers()

        assert sim.state.overtemp_trip is True
        assert reg_table.read_bit("%M172") is True
        assert (reg_table.read_word("%R747") & 0xFFFF) == PyrolysisDiagnosticCode.REACTOR_OVERTEMP_TRIP
        assert (reg_table.read_word("%R740") & int(PyrolysisStatusBits.OVERTEMP_TRIP)) != 0

        # Clear fault
        sim.state.t_reactor = 273.15 + 500.0
        sim._sync_registers()
        assert sim.state.overtemp_trip is False
        assert reg_table.read_bit("%M172") is False
        assert (reg_table.read_word("%R747") & 0xFFFF) == PyrolysisDiagnosticCode.OK

    def test_reactor_overpressure_alarm_and_interlock(self) -> None:
        """Requirement 6: Verify overpressure trip (%M173, 0x8A02) on P_reactor >= 1800.0 mbar."""
        reg_table = RegisterTable()
        sim = PyrolysisSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M173") is False

        # Inject overpressure condition (1850 mbar >= 1800 mbar)
        sim.state.p_reactor = 1850.0
        sim._sync_registers()

        assert sim.state.overpressure_trip is True
        assert reg_table.read_bit("%M173") is True
        assert (reg_table.read_word("%R747") & 0xFFFF) == PyrolysisDiagnosticCode.REACTOR_OVERPRESSURE_TRIP
        assert (reg_table.read_word("%R740") & int(PyrolysisStatusBits.OVERPRESSURE_TRIP)) != 0

        # Clear fault
        sim.state.p_reactor = 1050.0
        sim._sync_registers()
        assert sim.state.overpressure_trip is False
        assert reg_table.read_bit("%M173") is False
        assert (reg_table.read_word("%R747") & 0xFFFF) == PyrolysisDiagnosticCode.OK

    def test_quench_condenser_fault_alarm(self) -> None:
        """Requirement 6: Verify quench fault alarm (%M174, 0x8A03) on T_quench >= 55.0 °C."""
        reg_table = RegisterTable()
        sim = PyrolysisSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M174") is False

        # Inject quench cooling fault (60.0 °C >= 55.0 °C)
        sim.state.t_quench = 273.15 + 60.0
        sim._sync_registers()

        assert sim.state.quench_fault_alarm is True
        assert reg_table.read_bit("%M174") is True
        assert (reg_table.read_word("%R747") & 0xFFFF) == PyrolysisDiagnosticCode.QUENCH_COOLING_FAULT_ALARM
        assert (reg_table.read_word("%R740") & int(PyrolysisStatusBits.QUENCH_HIGH_ALARM)) != 0

        # Clear fault
        sim.state.t_quench = 273.15 + 32.0
        sim._sync_registers()
        assert sim.state.quench_fault_alarm is False
        assert reg_table.read_bit("%M174") is False
        assert (reg_table.read_word("%R747") & 0xFFFF) == PyrolysisDiagnosticCode.OK

    def test_diagnostic_code_priority_overtemp_over_quench(self) -> None:
        """Requirement 6: Verify overtemp trip has highest priority in %R747 diagnostic code."""
        reg_table = RegisterTable()
        sim = PyrolysisSimulator(register_table=reg_table)

        # Simultaneously trigger overtemp and quench fault
        sim.state.t_reactor = 273.15 + 700.0  # Overtemp
        sim.state.t_quench = 273.15 + 65.0    # Quench fault
        sim._sync_registers()

        assert sim.state.overtemp_trip is True
        assert sim.state.quench_fault_alarm is True
        # Highest priority must be overtemp (0x8A01)
        assert (reg_table.read_word("%R747") & 0xFFFF) == PyrolysisDiagnosticCode.REACTOR_OVERTEMP_TRIP


# ============================================================================
# 7. Horner OCS Register Space Synchronization
# ============================================================================

class TestHornerOCSSync:
    """Tests for Horner APG OCS register space mapping (%R740..%R747, %M172..%M174)."""

    def test_register_space_synchronization(self) -> None:
        """Requirement 7: Verify %R740..%R747 analog registers and %M172..%M174 discrete coils."""
        reg_table = RegisterTable()
        sim = PyrolysisSimulator(register_table=reg_table)
        sim.step(dt=0.01)

        r740 = reg_table.read_uword("%R740")
        r741 = reg_table.read_word("%R741")
        r742 = reg_table.read_word("%R742")
        r743 = reg_table.read_word("%R743")
        r744 = reg_table.read_word("%R744")
        r745 = reg_table.read_word("%R745")
        r746 = reg_table.read_word("%R746")
        r747 = reg_table.read_uword("%R747")

        # %R740: Status Word
        assert (r740 & int(PyrolysisStatusBits.RUNNING)) != 0
        assert (r740 & int(PyrolysisStatusBits.FEEDER_ACTIVE)) != 0
        assert (r740 & int(PyrolysisStatusBits.FLUIDIZING_OK)) != 0
        assert (r740 & int(PyrolysisStatusBits.CONDENSER_OK)) != 0

        # %R741: Reactor temperature scaled x10 °C (~500.0 °C -> ~5000)
        assert 4500 <= r741 <= 5500

        # %R742: Reactor pressure scaled x1 mbar (~1050 mbar)
        assert 900 <= r742 <= 1200

        # %R743: Bio-oil production rate scaled x10 kg/h
        assert r743 >= 0

        # %R744: Syngas volumetric flow rate scaled x10 Nm3/h
        assert r744 >= 0

        # %R745: Bio-char accumulation scaled x10 kg
        assert r745 >= 0

        # %R746: Quench temperature scaled x10 °C (~30..35 °C -> 300..350)
        assert 200 <= r746 <= 400

        # %R747: Diagnostic event code (0x0000 = OK)
        assert r747 == PyrolysisDiagnosticCode.OK

        # Discrete coils normal state
        assert reg_table.read_bit("%M172") is False
        assert reg_table.read_bit("%M173") is False
        assert reg_table.read_bit("%M174") is False

    def test_register_scaling_precision(self) -> None:
        """Requirement 7: Verify specific scaled register values match physical state."""
        reg_table = RegisterTable()
        sim = PyrolysisSimulator(register_table=reg_table)
        sim.state.t_reactor = 273.15 + 502.4
        sim.state.p_reactor = 1045.0
        sim.state.bio_oil_rate_kg_h = 24.5
        sim.state.syngas_flow_nm3_h = 5.2
        sim.state.m_char = 3.8
        sim.state.t_quench = 273.15 + 32.1
        sim.state.is_running = True
        sim._sync_registers()

        assert reg_table.read_word("%R741") == 5024   # 502.4 °C x10
        assert reg_table.read_word("%R742") == 1045   # 1045 mbar x1
        assert reg_table.read_word("%R743") == 245    # 24.5 kg/h x10
        assert reg_table.read_word("%R744") == 52     # 5.2 Nm^3/h x10
        assert reg_table.read_word("%R745") == 38     # 3.8 kg x10
        assert reg_table.read_word("%R746") == 321    # 32.1 °C x10


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
            "XIC FeederPermissive",
            "XIO ReactorOverTempTrip",
            "OTE BiomassFeederMotor",
            "OTL BioOilCoolingFault",
            "OTU EmergencyPurgeValve",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 8: Verify all ladder constructs raise LadderForbiddenError."""
        bad_code = f"{BIOMASS_PYROLYSIS_PURE_ST_POU}\n{ladder_snippet}\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

        val = STParser.validate_code(bad_code)
        assert val.status == AgentStatus.FAILED
        assert val.error_code == "ERR_LADDER_FORBIDDEN"
        assert val.data.get("ladder_rejected") is True


# ============================================================================
# 9. Full Verification Runner Function
# ============================================================================

class TestPyrolysisVerificationRunner:
    """Tests for the deterministic 9-stage verification runner function."""

    def test_run_pyrolysis_verification_9_stages(self, tmp_path: Path) -> None:
        """Verify run_pyrolysis_verification executes all 9 stages cleanly."""
        evidence_file = tmp_path / "pyrolysis_evidence.json"
        res = run_pyrolysis_verification(str(evidence_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert evidence_file.exists()
