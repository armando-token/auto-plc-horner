"""Unit tests for Multi-Tank Pneumatic Pressure Regulation & Compressible Gas ODE Solver (W065).

Tests:
1. Ideal gas mass balance and pressure derivative calculation dP/dt.
2. Unchoked orifice mass flow rate under subsonic pressure differentials.
3. Choked orifice mass flow rate under supersonic pressure ratios (P_down / P_up <= 0.528).
4. Sonic critical pressure ratio continuity at the boundary.
5. Reservoir charging cycle: pressure rises toward supply pressure.
6. Vent discharging cycle: pressure discharges toward ambient atmospheric pressure.
7. Karnopp friction stiction breakaway threshold: position holds until breakaway force is exceeded.
8. Valve actuator stroke limits [0.0, 1.0] and mechanical endstop clamping.
9. Relief valve solenoid activation (%M61) triggering rapid depressurization.
10. Horner OCS register synchronization (%R180..%R187, %M60..%M62).
11. Pure ST boundary enforcement: rejection of illegal ladder logic constructs.
12. Complete end-to-end verification runner and artifact JSON validation.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.pneumatic_system import (
    CRITICAL_RATIO,
    GAMMA,
    P_AMBIENT_PA,
    R_AIR,
    T_NOMINAL_K,
    KarnoppStictionActuator,
    MultiTankPneumaticPlant,
    PneumaticStatusFlag,
    PneumaticSystemLogicUnit,
    compute_orifice_mass_flow,
    pressure_rate_ode,
    verify_pneumatic_system_and_export_evidence,
)


def test_pressure_rate_ode() -> None:
    """Verify compressible gas ODE dP/dt = (gamma * R * T / V) * (m_in - m_out)."""
    vol = 0.050
    m_in = 0.030
    m_out = 0.010
    dp_dt = pressure_rate_ode(P_AMBIENT_PA, m_in, m_out, vol)
    expected = (GAMMA * R_AIR * T_NOMINAL_K / vol) * (m_in - m_out)
    assert abs(dp_dt - expected) < 1e-6
    assert dp_dt > 0.0

    # Equal in and out gives zero derivative
    assert pressure_rate_ode(P_AMBIENT_PA, 0.02, 0.02, vol) == 0.0


def test_orifice_subsonic_unchoked_flow() -> None:
    """Verify subsonic mass flow calculation where P_down / P_up > r_crit."""
    p_up = 800000.0
    p_down = 600000.0  # ratio = 0.75 > 0.528
    area = 0.0001
    m_dot, is_choked = compute_orifice_mass_flow(p_up, p_down, area)
    assert is_choked is False
    assert m_dot > 0.0

    # Reverse flow (p_up <= p_down) yields 0
    m_zero, _ = compute_orifice_mass_flow(500000.0, 600000.0, area)
    assert m_zero == 0.0


def test_orifice_supersonic_choked_flow() -> None:
    """Verify sonic mass flow calculation where P_down / P_up <= r_crit."""
    p_up = 800000.0
    p_down = P_AMBIENT_PA  # ratio ~ 0.126 <= 0.528
    area = 0.0001
    m_dot, is_choked = compute_orifice_mass_flow(p_up, p_down, area)
    assert is_choked is True
    assert m_dot > 0.0

    # Under choked conditions, reducing downstream pressure further does not increase mass flow
    m_dot_vacuum, is_choked_vac = compute_orifice_mass_flow(p_up, 1000.0, area)
    assert is_choked_vac is True
    assert abs(m_dot_vacuum - m_dot) < 1e-9


def test_sonic_boundary_continuity() -> None:
    """Verify C0 continuity across critical pressure ratio boundary."""
    p_up = 800000.0
    p_crit_down = p_up * CRITICAL_RATIO
    area = 0.0001
    m_sub, _ = compute_orifice_mass_flow(p_up, p_crit_down + 0.1, area)
    m_choked, _ = compute_orifice_mass_flow(p_up, p_crit_down - 0.1, area)
    assert abs(m_sub - m_choked) / m_choked < 0.005


def test_karnopp_stiction_breakaway() -> None:
    """Verify valve actuator holds position in stiction regime until breakaway force is exceeded."""
    actuator = KarnoppStictionActuator()
    assert actuator.position == 0.0
    assert actuator.stiction_active is True

    # Minor command under breakaway threshold
    pos, stiction = actuator.step(command_pos=0.010, dt_s=0.010)
    assert pos == 0.0
    assert stiction is True

    # Strong command breaking away
    for _ in range(50):
        pos, stiction = actuator.step(command_pos=0.75, dt_s=0.010)
    assert pos > 0.10


def test_actuator_stroke_limits() -> None:
    """Verify valve actuator clamps strictly to [0.0, 1.0]."""
    actuator = KarnoppStictionActuator()

    # Saturate high
    for _ in range(100):
        pos_high, _ = actuator.step(command_pos=2.0, dt_s=0.010)
    assert pos_high <= 1.0
    assert pos_high >= (1.0 - actuator.stiction_deadband - 1e-4)

    # Saturate low
    for _ in range(100):
        pos_low, _ = actuator.step(command_pos=-1.0, dt_s=0.010)
    assert pos_low >= 0.0
    assert pos_low <= (actuator.stiction_deadband + 1e-4)


def test_reservoir_charging_cycle() -> None:
    """Verify pneumatic reservoir charging cycle asymptotically approaches supply."""
    plant = MultiTankPneumaticPlant(p_supply_pa=800000.0)
    p_init = plant.p1_pa
    assert p_init == P_AMBIENT_PA

    for _ in range(250):
        plant.step(valve1_cmd=1.0, exhaust_valve_cmd=0.0, dt_s=0.010)

    assert plant.p1_pa > p_init + 250000.0
    assert plant.p1_pa <= plant.p_supply_pa


def test_relief_solenoid_depressurization() -> None:
    """Verify emergency relief dump valve rapidly vents reservoir."""
    plant = MultiTankPneumaticPlant()
    # Charge first
    for _ in range(150):
        plant.step(valve1_cmd=1.0, dt_s=0.010)
    charged_p = plant.p1_pa
    assert charged_p > P_AMBIENT_PA + 100000.0

    # Dump
    for _ in range(250):
        plant.step(valve1_cmd=0.0, relief_open=True, dt_s=0.010)
    assert plant.p1_pa < charged_p - 100000.0


def test_horner_register_sync() -> None:
    """Verify %R180..%R187 and %M60..%M62 register synchronization."""
    regs = RegisterTable()
    unit = PneumaticSystemLogicUnit(register_table=regs)

    ctx = ScanContext(
        cycle=1,
        dt_ms=10.0,
        elapsed_time_ms=10.0,
        get_register=lambda addr: regs.read_register(addr),
        set_register=lambda addr, val: regs.write_register(addr, val, privilege=PrivilegeMode.SYSTEM),
        get_variable=lambda name, default=None: default,
        set_variable=lambda name, val: None,
        record_fault=lambda fault: None,
    )

    # Command valve 50%
    regs.write_word("%R183", 16000, privilege=PrivilegeMode.SYSTEM)
    unit.execute(ctx)

    # %R180 (Supply), %R181 (P1), %R184 (Feedback), %R187 (Status)
    assert regs.read_word("%R180") > 0
    assert regs.read_word("%R181") > 0
    assert regs.read_word("%R187") & PneumaticStatusFlag.ACTIVE


def test_coil_disable_and_reset_handshake() -> None:
    """Verify %M60 enable coil and %M62 self-clearing reset coil."""
    regs = RegisterTable()
    unit = PneumaticSystemLogicUnit(register_table=regs)

    unit.solve(regs)
    assert regs.read_word("%R187") != 0

    # Disable system via %M60
    regs.write_bit("%M60", False, privilege=PrivilegeMode.SYSTEM)
    unit.solve(regs)
    assert regs.read_word("%R187") == 0

    # Re-enable and reset via %M62
    regs.write_bit("%M60", True, privilege=PrivilegeMode.SYSTEM)
    regs.write_bit("%M62", True, privilege=PrivilegeMode.SYSTEM)
    unit.solve(regs)

    assert regs.read_bit("%M62") is False  # Self-cleared
    assert regs.read_word("%R187") & PneumaticStatusFlag.ACTIVE


def test_pure_st_boundary_enforcement() -> None:
    """Verify IEC 61131-3 Pure ST boundary rejects ladder constructs."""
    valid_st = (
        "PROGRAM PneumaticPressureRegulator\n"
        "VAR\n"
        "    P_Supply : INT;\n"
        "    P_Tank : INT;\n"
        "END_VAR\n"
        "P_Supply := %R180;\n"
        "P_Tank := %R181;\n"
        "END_PROGRAM"
    )
    SecurityGuard.assert_pure_st_content(valid_st)

    ladder_samples = [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(S)---",
        "---(R)---",
        "RUNG 1",
        "END_RUNG",
        "NETWORK 5",
        "XIC StartCmd",
        "OTE RunCoil",
    ]
    for sample in ladder_samples:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(f"{valid_st}\n{sample}")


def test_verification_runner_and_artifact(tmp_path: Path) -> None:
    """Verify end-to-end canonical verification runner and evidence generation."""
    evidence_file = tmp_path / "pneumatic_system_evidence.json"
    result = verify_pneumatic_system_and_export_evidence(output_evidence_path=str(evidence_file))

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert result["data"]["tests_run"] == result["data"]["tests_passed"]
    assert evidence_file.exists()

    with open(evidence_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["status"] == "success"
    assert "thermodynamic_constants" in data["data"]
