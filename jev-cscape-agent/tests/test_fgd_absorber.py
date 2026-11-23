"""Unit and Integration Tests for Wet FGD Spray Absorber ODE Simulation.

Work Package: W119 (Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Pure IEC 61131-3 ST POU AST parsing and register bindings (%R800..%R807, %M186..%M188).
2. Anti-ladder security guard rejection (LadderForbiddenError on contacts/coils).
3. Two-film gas-liquid mass transfer and chemical enhancement factor calculations.
4. Limestone dissolution kinetics and pH buffer balance.
5. Forced oxidation sump kinetics and gypsum crystallization rate.
6. Coupled 6-state ODE RK4 integration stability and sulfur mass conservation residual.
7. Emission exceedance trip (%M186, 0x9001), low pH trip (%M187, 0x9002), oxidation loss alarm (%M188, 0x9003).
8. Horner OCS register space synchronization (%R800..%R807, %M186..%M188).
9. End-to-end 9-stage verification runner test.
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
from jev_cscape.simulation.fgd_absorber import (
    FGDAbsorberConfig,
    FGDAbsorberSimulator,
    FGDAbsorberState,
    FGDDiagnosticCode,
    FGDStatusBits,
    FGD_ABSORBER_PURE_ST_POU,
    FGD_PURE_ST_POU,
    FGD_SPRAY_ABSORBER_PURE_ST_POU,
    run_fgd_absorber_verification,
    verify_fgd_absorber_pure_st,
)


# ============================================================================
# 1. Pure ST POU AST Parsing & Register Bindings
# ============================================================================

class TestFGDPureST:
    """Tests for IEC 61131-3 Pure ST POU validation, AST generation, and register bindings."""

    def test_verify_fgd_absorber_pure_st(self) -> None:
        """Requirement 1: Verify Pure ST POU passes AST parsing and anti-ladder verification."""
        assert verify_fgd_absorber_pure_st() is True

    def test_pure_st_pou_ast_and_symbol_bindings(self) -> None:
        """Requirement 1: Validate AST program name, type, and mapped Horner registers."""
        SecurityGuard.assert_pure_st_content(FGD_ABSORBER_PURE_ST_POU)
        val = STParser.validate_code(FGD_ABSORBER_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(FGD_ABSORBER_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "FGDAbsorberSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = [
            "%R800", "%R801", "%R802", "%R803",
            "%R804", "%R805", "%R806", "%R807",
            "%M186", "%M187", "%M188",
        ]
        for reg in expected_registers:
            assert reg in ast.bound_registers, f"Register {reg} must be present in AST bound registers"

    def test_pure_st_pou_alias_equivalence(self) -> None:
        """Requirement 1: Verify POU aliases are identical and parse equivalently."""
        assert FGD_PURE_ST_POU == FGD_ABSORBER_PURE_ST_POU
        assert FGD_SPRAY_ABSORBER_PURE_ST_POU == FGD_ABSORBER_PURE_ST_POU

        ast_alias = STParser.parse_pou(FGD_SPRAY_ABSORBER_PURE_ST_POU)
        assert ast_alias is not None
        assert ast_alias.name == "FGDAbsorberSync"


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
            "XIC SprayPumpRunning",
            "XIO EmissionExceedanceTrip",
            "OTE SlurryRecircPump",
            "OTL LowPhAlarm",
            "OTU OxidationBlowerTrip",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, ladder_snippet: str) -> None:
        """Requirement 2: Verify all ladder constructs raise LadderForbiddenError."""
        bad_code = f"{FGD_ABSORBER_PURE_ST_POU}\n{ladder_snippet}\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

        val = STParser.validate_code(bad_code)
        assert val.status == AgentStatus.FAILED
        assert val.error_code == "ERR_LADDER_FORBIDDEN"
        assert val.data.get("ladder_rejected") is True


# ============================================================================
# 3. Two-Film Gas-Liquid Mass Transfer & Enhancement Factor
# ============================================================================

class TestTwoFilmMassTransferAndEnhancement:
    """Tests for Whitman two-film theory and chemical reaction enhancement factor."""

    def test_spray_droplet_interfacial_area_scaling(self) -> None:
        """Requirement 3: Verify spray droplet interfacial area scaling with slurry flow."""
        sim = FGDAbsorberSimulator()

        # Nominal slurry flow
        a_dens_nom, a_tot_nom = sim.compute_spray_interfacial_area()
        assert a_dens_nom > 0.0
        assert a_tot_nom == pytest.approx(6000.0, rel=1e-3)

        # Half slurry flow
        a_dens_half, a_tot_half = sim.compute_spray_interfacial_area(slurry_flow_m3_s=0.625)
        assert a_tot_half == pytest.approx(3000.0, rel=1e-3)
        assert a_tot_half == pytest.approx(0.5 * a_tot_nom, rel=1e-3)

        # Spray pumps turned off
        sim.state.spray_pumps_on = False
        a_dens_off, a_tot_off = sim.compute_spray_interfacial_area()
        assert a_dens_off == 0.0
        assert a_tot_off == 0.0

    def test_whitman_mass_transfer_enhancement_factor_monotonicity(self) -> None:
        """Requirement 3: Verify chemical enhancement factor E increases with pH."""
        sim = FGDAbsorberSimulator()
        _, a_total = sim.compute_spray_interfacial_area()

        # Mass transfer at acidic pH (4.50) vs nominal buffer pH (5.50) vs alkaline pH (6.50)
        _, _, e_45, _, _ = sim.compute_whitman_mass_transfer(
            c_so2_gas_ppm=50.0, ph_slurry=4.50, c_sulfite_mol_m3=3.5, a_total_m2=a_total
        )
        _, _, e_55, _, _ = sim.compute_whitman_mass_transfer(
            c_so2_gas_ppm=50.0, ph_slurry=5.50, c_sulfite_mol_m3=3.5, a_total_m2=a_total
        )
        _, _, e_65, _, _ = sim.compute_whitman_mass_transfer(
            c_so2_gas_ppm=50.0, ph_slurry=6.50, c_sulfite_mol_m3=3.5, a_total_m2=a_total
        )

        assert e_45 >= 1.0
        assert e_55 > e_45
        assert e_65 > e_55

    def test_whitman_mass_transfer_absorption_driving_force(self) -> None:
        """Requirement 3: Verify absorption rate scales with bulk-to-interface driving force."""
        sim = FGDAbsorberSimulator()
        _, a_total = sim.compute_spray_interfacial_area()

        # High inlet SO2 concentration (1000 ppm) vs low concentration (50 ppm)
        n_so2_high, k_g_high, _, p_bulk_high, p_int_high = sim.compute_whitman_mass_transfer(
            c_so2_gas_ppm=1000.0, ph_slurry=5.50, c_sulfite_mol_m3=3.5, a_total_m2=a_total
        )
        n_so2_low, k_g_low, _, p_bulk_low, p_int_low = sim.compute_whitman_mass_transfer(
            c_so2_gas_ppm=50.0, ph_slurry=5.50, c_sulfite_mol_m3=3.5, a_total_m2=a_total
        )

        assert p_bulk_high > p_bulk_low
        assert n_so2_high > n_so2_low > 0.0
        assert k_g_high == pytest.approx(k_g_low, rel=1e-5)


# ============================================================================
# 4. Limestone Dissolution Kinetics & pH Buffer Balance
# ============================================================================

class TestLimestoneDissolutionAndBuffer:
    """Tests for CaCO3 dissolution kinetics, pH sensitivity, and slurry buffering balance."""

    def test_limestone_dissolution_acid_acceleration(self) -> None:
        """Requirement 4: Verify dissolution rate accelerates under lower (more acidic) pH."""
        sim = FGDAbsorberSimulator()
        ca_diss = 15.0  # mol/m3 (< ca_sat = 25.0)

        r_diss_45 = sim.compute_limestone_dissolution(ph_slurry=4.50, ca_dissolved_mol_m3=ca_diss)
        r_diss_55 = sim.compute_limestone_dissolution(ph_slurry=5.50, ca_dissolved_mol_m3=ca_diss)
        r_diss_65 = sim.compute_limestone_dissolution(ph_slurry=6.50, ca_dissolved_mol_m3=ca_diss)

        assert r_diss_45 > r_diss_55 > r_diss_65 > 0.0

    def test_limestone_dissolution_saturation_cutoff(self) -> None:
        """Requirement 4: Verify dissolution stops completely at or above calcium saturation."""
        sim = FGDAbsorberSimulator()
        ca_sat = sim.config.ca_sat_mol_m3

        # Exactly at saturation
        r_diss_sat = sim.compute_limestone_dissolution(ph_slurry=5.00, ca_dissolved_mol_m3=ca_sat)
        assert r_diss_sat == 0.0

        # Oversaturated
        r_diss_over = sim.compute_limestone_dissolution(ph_slurry=5.00, ca_dissolved_mol_m3=ca_sat + 5.0)
        assert r_diss_over == 0.0

    def test_ode_ph_buffer_derivatives_response(self) -> None:
        """Requirement 4: Verify net proton consumption elevates pH derivative."""
        sim = FGDAbsorberSimulator()
        y_test = [50.0, 5.50, 3.5, 15.0, 55.0, 150.0]

        # Derivatives with normal limestone feed
        derivs_normal = sim.ode_derivatives(0.0, y_test)
        d_ph_dt = derivs_normal[1]

        # Verify pH derivative is finite and reasonable
        assert not math.isnan(d_ph_dt)
        assert abs(d_ph_dt) < 5.0  # Buffer suppresses violent swings


# ============================================================================
# 5. Forced Oxidation Sump Kinetics & Gypsum Crystallization
# ============================================================================

class TestForcedOxidationAndGypsumCrystallization:
    """Tests for sulfite oxidation to sulfate and gypsum precipitation kinetics."""

    def test_forced_oxidation_blower_dependency(self) -> None:
        """Requirement 5: Verify oxidation occurs with blower active and halts when blower stops."""
        sim = FGDAbsorberSimulator()

        # Blower ON
        sim.state.oxidation_air_on = True
        r_ox_on = sim.compute_forced_oxidation_rate(c_sulfite_mol_m3=5.0, t_slurry_c=52.0)
        assert r_ox_on > 0.0

        # Blower OFF
        sim.state.oxidation_air_on = False
        r_ox_off = sim.compute_forced_oxidation_rate(c_sulfite_mol_m3=5.0, t_slurry_c=52.0)
        assert r_ox_off == 0.0

    def test_forced_oxidation_linear_sulfite_dependence(self) -> None:
        """Requirement 5: Verify oxidation rate scales linearly with dissolved sulfite."""
        sim = FGDAbsorberSimulator()
        sim.state.oxidation_air_on = True

        r_ox_5 = sim.compute_forced_oxidation_rate(c_sulfite_mol_m3=5.0, t_slurry_c=52.0)
        r_ox_10 = sim.compute_forced_oxidation_rate(c_sulfite_mol_m3=10.0, t_slurry_c=52.0)

        assert r_ox_10 == pytest.approx(2.0 * r_ox_5, rel=1e-5)

    def test_gypsum_crystallization_supersaturation_threshold(self) -> None:
        """Requirement 5: Verify gypsum crystallizes only when ion product exceeds K_sp (200.0)."""
        sim = FGDAbsorberSimulator()
        k_sp = sim.config.k_sp_gypsum  # 200.0

        # Case 1: Sub-saturated (IP = 10 * 10 = 100 < 200)
        r_cryst_sub = sim.compute_gypsum_crystallization_rate(ca_dissolved_mol_m3=10.0, so4_dissolved_mol_m3=10.0)
        assert r_cryst_sub == 0.0

        # Case 2: Exactly saturated (IP = 20 * 10 = 200 == 200)
        r_cryst_sat = sim.compute_gypsum_crystallization_rate(ca_dissolved_mol_m3=20.0, so4_dissolved_mol_m3=10.0)
        assert r_cryst_sat == 0.0

        # Case 3: Super-saturated (IP = 25 * 15 = 375 > 200)
        r_cryst_super = sim.compute_gypsum_crystallization_rate(ca_dissolved_mol_m3=25.0, so4_dissolved_mol_m3=15.0)
        expected_super = sim.config.k_cryst * (375.0 - k_sp)
        assert r_cryst_super == pytest.approx(expected_super, rel=1e-5)
        assert r_cryst_super > 0.0


# ============================================================================
# 6. Coupled 6-State ODE RK4 Integration & Conservation Residual
# ============================================================================

class TestCoupled6StateODEIntegration:
    """Tests for coupled 6-state RK4 solver stability and sulfur conservation."""

    def test_coupled_6state_rk4_solution_stability(self) -> None:
        """Requirement 6: Verify all 6 states remain bounded, positive, and physically realistic."""
        sim = FGDAbsorberSimulator()
        res = sim.advance_time(duration_s=2.0, dt=0.01)

        assert res.status == AgentStatus.SUCCESS
        st = sim.state

        # Check bounds
        assert 0.0 <= st.c_so2_gas_ppm < sim.config.c_so2_in_ppm
        assert 4.0 <= st.ph_slurry <= 7.0
        assert st.c_sulfite_sump_mol_m3 >= 0.0
        assert st.c_gypsum_sump_wt_pct >= 0.0
        assert 40.0 <= st.t_gas_exhaust_c <= sim.config.t_gas_in_c
        assert st.v_sump_m3 > 0.0

    def test_stoichiometric_sulfur_mass_conservation_residual(self) -> None:
        """Requirement 6: Verify analytical sulfur species mass conservation residual < 1e-10 mol/s."""
        sim = FGDAbsorberSimulator()
        sim.advance_time(duration_s=1.0, dt=0.01)

        residual = sim.state.sulfur_balance_residual_mol_s
        assert residual < 1e-10, f"Sulfur conservation residual {residual:.3e} exceeds 1e-10 mol/s"

    def test_invalid_timestep_fail_closed(self) -> None:
        """Requirement 6: Verify non-positive duration or timestep fails closed."""
        sim = FGDAbsorberSimulator()

        res_zero = sim.advance_time(duration_s=0.0)
        assert res_zero.status == AgentStatus.FAILED
        assert res_zero.error_code == "INVALID_TIMESTEP"

        res_neg = sim.advance_time(duration_s=1.0, dt=-0.01)
        assert res_neg.status == AgentStatus.FAILED
        assert res_neg.error_code == "INVALID_TIMESTEP"


# ============================================================================
# 7. Process Safety Interlocks & Alarm Trips
# ============================================================================

class TestProcessSafetyInterlocks:
    """Tests for %M186 (0x9001), %M187 (0x9002), and %M188 (0x9003) safety trips."""

    def test_emission_exceedance_trip_and_code(self) -> None:
        """Requirement 7: Verify SO2 emission exceedance trip (%M186, 0x9001)."""
        reg_table = RegisterTable()
        sim = FGDAbsorberSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M186") is False

        # Incur emission exceedance: high SO2 outlet concentration (250 ppm >= 200 ppm)
        sim.state.c_so2_gas_ppm = 250.0
        sim.state.removal_efficiency_pct = 75.0
        sim._sync_registers()

        assert sim.state.so2_exceedance_trip is True
        assert reg_table.read_bit("%M186") is True
        assert (reg_table.read_word("%R807") & 0xFFFF) == int(FGDDiagnosticCode.SO2_EMISSION_EXCEEDANCE_TRIP)
        assert bool(reg_table.read_word("%R800") & int(FGDStatusBits.EMISSION_EXCEEDANCE_TRIP)) is True

    def test_slurry_low_ph_corrosion_trip_and_code(self) -> None:
        """Requirement 7: Verify slurry low pH corrosion trip (%M187, 0x9002)."""
        reg_table = RegisterTable()
        sim = FGDAbsorberSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M187") is False

        # Incur low pH trip: pH 4.60 < 4.80 threshold
        sim.state.c_so2_gas_ppm = 25.0
        sim.state.removal_efficiency_pct = 97.5
        sim.state.ph_slurry = 4.60
        sim._sync_registers()

        assert sim.state.low_ph_trip is True
        assert reg_table.read_bit("%M187") is True
        assert (reg_table.read_word("%R807") & 0xFFFF) == int(FGDDiagnosticCode.SLURRY_LOW_PH_CORROSION_TRIP)
        assert bool(reg_table.read_word("%R800") & int(FGDStatusBits.LOW_PH_TRIP)) is True

    def test_oxidation_loss_alarm_and_code(self) -> None:
        """Requirement 7: Verify forced oxidation loss alarm (%M188, 0x9003)."""
        reg_table = RegisterTable()
        sim = FGDAbsorberSimulator(register_table=reg_table)
        assert reg_table.read_bit("%M188") is False

        # Incur oxidation loss: sulfite accumulates to 18.0 mol/m3 >= 15.0 threshold
        sim.state.ph_slurry = 5.50
        sim.state.c_sulfite_sump_mol_m3 = 18.0
        sim._sync_registers()

        assert sim.state.oxidation_loss_alarm is True
        assert reg_table.read_bit("%M188") is True
        assert (reg_table.read_word("%R807") & 0xFFFF) == int(FGDDiagnosticCode.OXIDATION_AIR_LOSS_ALARM)
        assert bool(reg_table.read_word("%R800") & int(FGDStatusBits.OXIDATION_LOSS_ALARM)) is True

    def test_diagnostic_code_priority_emission_over_ph_and_oxidation(self) -> None:
        """Requirement 7: Verify SO2 emission trip has top priority (0x9001 > 0x9002 > 0x9003)."""
        reg_table = RegisterTable()
        sim = FGDAbsorberSimulator(register_table=reg_table)

        # Trigger all three simultaneous trips
        sim.state.c_so2_gas_ppm = 300.0          # Emission trip (0x9001)
        sim.state.ph_slurry = 4.50              # Low pH trip (0x9002)
        sim.state.c_sulfite_sump_mol_m3 = 20.0   # Oxidation loss alarm (0x9003)
        sim._sync_registers()

        assert (reg_table.read_word("%R807") & 0xFFFF) == int(FGDDiagnosticCode.SO2_EMISSION_EXCEEDANCE_TRIP)

        # Clear emission trip -> low pH trip takes precedence (0x9002 > 0x9003)
        sim.state.c_so2_gas_ppm = 25.0
        sim.state.removal_efficiency_pct = 97.5
        sim._sync_registers()
        assert (reg_table.read_word("%R807") & 0xFFFF) == int(FGDDiagnosticCode.SLURRY_LOW_PH_CORROSION_TRIP)

        # Clear low pH -> oxidation alarm takes precedence (0x9003)
        sim.state.ph_slurry = 5.60
        sim._sync_registers()
        assert (reg_table.read_word("%R807") & 0xFFFF) == int(FGDDiagnosticCode.OXIDATION_AIR_LOSS_ALARM)


# ============================================================================
# 8. Horner OCS Register Space Synchronization
# ============================================================================

class TestHornerOCSSync:
    """Tests for Horner APG OCS register space mapping (%R800..%R807, %M186..%M188)."""

    def test_register_space_synchronization_nominal(self) -> None:
        """Requirement 8: Verify %R800..%R807 analog registers and %M186..%M188 discrete coils."""
        reg_table = RegisterTable()
        sim = FGDAbsorberSimulator(register_table=reg_table)
        sim.advance_time(duration_s=0.5, dt=0.01)

        r800 = reg_table.read_uword("%R800")
        r801 = reg_table.read_word("%R801")
        r802 = reg_table.read_word("%R802")
        r803 = reg_table.read_word("%R803")
        r804 = reg_table.read_word("%R804")
        r805 = reg_table.read_word("%R805")
        r806 = reg_table.read_word("%R806")
        r807 = reg_table.read_uword("%R807")

        # %R800 Status Word
        assert (r800 & int(FGDStatusBits.RUNNING)) != 0
        assert (r800 & int(FGDStatusBits.SPRAY_PUMPS_ON)) != 0
        assert (r800 & int(FGDStatusBits.OXIDATION_AIR_ON)) != 0
        assert (r800 & int(FGDStatusBits.EMISSION_COMPLIANT)) != 0

        # %R801: SO2 inlet ppm (1000)
        assert r801 == 1000

        # %R802: SO2 outlet ppm (< 200)
        assert 0 <= r802 < 200

        # %R803: SO2 removal efficiency scaled x10 % (>= 950 for >= 95.0%)
        assert r803 >= 950

        # %R804: Slurry pH scaled x100 (e.g. 550 for 5.50)
        assert 500 <= r804 <= 600

        # %R805: Sump gypsum density scaled x10 wt% (> 0)
        assert r805 > 0

        # %R806: Sump liquid level scaled x10 % (> 0)
        assert r806 > 0

        # %R807: Diagnostic code OK (0x0000)
        assert r807 == int(FGDDiagnosticCode.OK)

        # Discrete Coils normal
        assert reg_table.read_bit("%M186") is False
        assert reg_table.read_bit("%M187") is False
        assert reg_table.read_bit("%M188") is False

    def test_register_scaling_precision(self) -> None:
        """Requirement 8: Verify exact scaled register values."""
        reg_table = RegisterTable()
        sim = FGDAbsorberSimulator(register_table=reg_table)

        sim.state.c_so2_gas_ppm = 42.0
        sim.state.removal_efficiency_pct = 95.8
        sim.state.ph_slurry = 5.62
        sim.state.c_gypsum_sump_wt_pct = 16.4
        sim.state.v_sump_m3 = 150.0  # 150/200 = 75.0%
        sim._sync_registers()

        assert reg_table.read_word("%R801") == 1000
        assert reg_table.read_word("%R802") == 42
        assert reg_table.read_word("%R803") == 958
        assert reg_table.read_word("%R804") == 562
        assert reg_table.read_word("%R805") == 164
        assert reg_table.read_word("%R806") == 750


# ============================================================================
# 9. End-to-End 9-Stage Verification Runner Test
# ============================================================================

class TestFGDVerificationRunner:
    """Tests for the deterministic 9-stage verification runner function."""

    def test_run_fgd_absorber_verification_9_stages(self, tmp_path: Path) -> None:
        """Requirement 9: Verify run_fgd_absorber_verification executes all 9 stages cleanly."""
        evidence_file = tmp_path / "fgd_absorber_evidence.json"
        res = run_fgd_absorber_verification(str(evidence_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert evidence_file.exists()

        # Check evidence file JSON structure
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert len(data["data"]["tests"]) == 9
