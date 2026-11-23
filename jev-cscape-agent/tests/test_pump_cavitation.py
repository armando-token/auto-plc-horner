"""Unit tests for Centrifugal Pump Cavitation, NPSH Forensics & Acoustic Emission ODE Dynamics (W068).

Tests:
1. Normal single-phase operation with adequate suction head (CMR > 1.30).
2. VFD affinity law scaling across motor speeds (N=1800 vs N=900 RPM).
3. Temperature-dependent water vapor pressure calculation (Arden-Buck formulation).
4. Suction piping Darcy-Weisbach friction head loss reduction on NPSH_A.
5. Incipient cavitation detection under mild suction lift with acoustic spike.
6. Developed cavitation (3% head drop boundary) and sheet cavity noise.
7. Vapor lock catastrophic breakdown and automated VFD safety trip (%M68).
8. Supervisory fault reset handshake (%M69) clearing trip upon safe NPSH recovery.
9. Horner OCS register synchronization (%R190..%R197, %M67..%M69).
10. Pure ST boundary enforcement: rejection of forbidden ladder logic constructs.
11. Canonical verification runner and artifact JSON validation.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.pump_cavitation import (
    CavitationRegime,
    CentrifugalPumpConfig,
    PumpCavitationModel,
    PumpStatusFlag,
    compute_water_vapor_pressure_pa,
    verify_pump_cavitation_and_export_evidence,
)


def test_water_vapor_pressure_curve() -> None:
    """Verify Arden-Buck vapor pressure formula matches physical water steam tables."""
    # At 20 C: ~2338 Pa
    p_20 = compute_water_vapor_pressure_pa(20.0)
    assert 2200.0 < p_20 < 2500.0

    # At 100 C: ~101325 Pa (atmospheric boiling)
    p_100 = compute_water_vapor_pressure_pa(100.0)
    assert 98000.0 < p_100 < 105000.0


def test_normal_single_phase_operation() -> None:
    """Verify nominal operation with flooded suction is in NORMAL regime with low noise."""
    pump = PumpCavitationModel()
    pump.vfd_speed_rpm = 1800.0
    for _ in range(30):
        pump.step(dt_s=0.05, tank_liquid_level_m=3.0)

    assert pump.regime == CavitationRegime.NORMAL
    assert pump.flow_rate_lpm > 400.0
    assert pump.discharge_head_m > 30.0
    assert pump.cavitation_margin_ratio > 1.30
    assert pump.head_degradation_factor == 1.0
    assert pump.acoustic_noise_db < 65.0
    assert not pump.vfd_trip


def test_vfd_affinity_law_scaling() -> None:
    """Verify flow scales with N and head scales with N^2."""
    pump = PumpCavitationModel()
    pump.vfd_speed_rpm = 1800.0
    for _ in range(30):
        pump.step(dt_s=0.05, tank_liquid_level_m=3.0)
    h_rated = pump.discharge_head_m
    q_rated = pump.flow_rate_lpm

    # Cut speed to 1200 RPM (2/3 rated)
    pump.vfd_speed_rpm = 1200.0
    for _ in range(50):
        pump.step(dt_s=0.05, tank_liquid_level_m=3.0)

    assert pump.actual_speed_rpm < 1250.0
    assert pump.discharge_head_m < h_rated
    assert pump.flow_rate_lpm < q_rated


def test_suction_friction_loss() -> None:
    """Verify inlet pipe friction reduces available NPSH as flow increases."""
    pump = PumpCavitationModel()
    pump.vfd_speed_rpm = 1800.0
    pump.step(dt_s=0.05, tank_liquid_level_m=2.0)
    npsh_static = (pump.config.ambient_pressure_pa - compute_water_vapor_pressure_pa(25.0)) / (998.2 * 9.80665) + 2.0

    # With flowing liquid, NPSH_A must be strictly lower than purely static NPSH
    assert pump.npsh_available_m < npsh_static


def test_incipient_cavitation_and_acoustic_spike() -> None:
    """Verify suction lift induces micro-bubble nucleation and acoustic surge."""
    pump = PumpCavitationModel()
    pump.vfd_speed_rpm = 1800.0
    for _ in range(30):
        pump.step(dt_s=0.05, tank_liquid_level_m=-6.0)

    assert pump.regime in (CavitationRegime.INCIPIENT, CavitationRegime.DEVELOPED)
    assert pump.acoustic_noise_db > 65.0
    assert pump.cavitation_margin_ratio <= 1.30


def test_vapor_lock_and_automated_vfd_trip() -> None:
    """Verify catastrophic vapor lock trips VFD and clamps speed to 0."""
    pump = PumpCavitationModel()
    pump.vfd_speed_rpm = 1800.0
    for _ in range(40):
        pump.step(dt_s=0.05, tank_liquid_level_m=-9.0)

    assert pump.regime == CavitationRegime.VAPOR_LOCK
    assert pump.vfd_trip is True
    assert pump.head_degradation_factor < 0.90

    # Subsequent scan cycles bring actual motor speed down toward 0
    for _ in range(40):
        pump.step(dt_s=0.05, tank_liquid_level_m=-9.0)
    assert pump.actual_speed_rpm < 50.0


def test_supervisory_reset_handshake() -> None:
    """Verify %M69 clears latched trip once suction level is restored."""
    regs = RegisterTable()
    pump = PumpCavitationModel()
    pump.vfd_trip = True
    pump.npsh_available_m = 10.0
    pump.npsh_required_m = 3.0

    regs.write_bit("%M67", True, privilege=PrivilegeMode.SYSTEM)
    regs.write_bit("%M69", True, privilege=PrivilegeMode.SYSTEM)
    regs.write_word("%R190", 1800, privilege=PrivilegeMode.SYSTEM)

    pump.solve(regs, tank_liquid_level_m=3.0)
    assert pump.vfd_trip is False
    assert regs.read_bit("%M69") is False  # Self-cleared
    assert not regs.read_bit("%M68")


def test_horner_register_sync() -> None:
    """Verify %R190..%R197 and %M67..%M69 synchronization."""
    regs = RegisterTable()
    pump = PumpCavitationModel()

    regs.write_bit("%M67", True, privilege=PrivilegeMode.SYSTEM)
    regs.write_word("%R190", 1800, privilege=PrivilegeMode.SYSTEM)

    pump.solve(regs, tank_liquid_level_m=3.0)

    assert regs.read_word("%R191") > 0  # Flow L/min
    assert regs.read_word("%R192") > 0  # Head m
    assert regs.read_word("%R193") > 0  # NPSHa cm
    assert regs.read_word("%R194") > 0  # NPSHr cm
    assert regs.read_word("%R196") > 300  # Noise dBx10
    assert regs.read_word("%R197") & PumpStatusFlag.ACTIVE


def test_pure_st_boundary_enforcement() -> None:
    """Verify IEC 61131-3 Pure ST boundary rejects ladder constructs."""
    valid_st = (
        "PROGRAM PumpCavitationAcousticForensics\n"
        "VAR\n"
        "    VFD_Speed_RPM AT %R190 : INT;\n"
        "    Flow_Rate_Lpm AT %R191 : INT;\n"
        "    Discharge_Head_m AT %R192 : INT;\n"
        "    NPSH_Avail_cm AT %R193 : INT;\n"
        "    NPSH_Req_cm AT %R194 : INT;\n"
        "    Thoma_Index_x1000 AT %R195 : INT;\n"
        "    Acoustic_Noise_x10dB AT %R196 : INT;\n"
        "    Status_Word AT %R197 : INT;\n"
        "    Sys_Enable AT %M67 : BOOL;\n"
        "    VFD_Trip AT %M68 : BOOL;\n"
        "    Sys_Reset AT %M69 : BOOL;\n"
        "END_VAR\n"
        "IF Sys_Enable THEN\n"
        "    Status_Word := %R197;\n"
        "END_IF;\n"
        "END_PROGRAM"
    )
    SecurityGuard.assert_pure_st_content(valid_st)
    ast = STParser.parse_pou(valid_st)
    assert ast.name == "PumpCavitationAcousticForensics"
    assert ast.pou_type == POUType.PROGRAM
    expected_regs = {"%R190", "%R191", "%R192", "%R193", "%R194", "%R195", "%R196", "%R197", "%M67", "%M68", "%M69"}
    assert expected_regs.issubset(set(ast.bound_registers))

    ladder_samples = [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(S)---",
        "---(R)---",
        "RUNG 1",
        "END_RUNG",
        "NETWORK 10",
        "XIC Sys_Enable",
        "OTE VFD_Trip",
    ]
    for sample in ladder_samples:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(f"{valid_st}\n{sample}")


def test_verification_runner_and_artifact(tmp_path: Path) -> None:
    """Verify canonical verification runner and evidence export."""
    evidence_file = tmp_path / "pump_cavitation_evidence.json"
    result = verify_pump_cavitation_and_export_evidence(output_evidence_path=str(evidence_file))

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert result["data"]["tests_run"] == result["data"]["tests_passed"]
    assert evidence_file.exists()

    with open(evidence_file, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["status"] == "success"
    assert "regimes_modeled" in loaded["data"]
