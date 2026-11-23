"""Unit tests for IEC 61131-3 Sequential Function Chart (SFC) Execution Engine (W060).

Tests:
1. Basic step model and initial state activation.
2. Action qualifier semantics: N, S, R, L, D, P.
3. Selection Divergence (OR branch) priority arbitration.
4. Selection Convergence (OR join).
5. Simultaneous Divergence (AND fork) concurrent step activation.
6. Simultaneous Convergence (AND join) synchronization bar requiring all incoming steps active.
7. Strict Pure ST AST enforcement: rejection of ladder constructs (---[ ]---, RUNG, XIC).
8. Horner OCS register synchronization (%R250..%R253, %M51..%M53).
9. ILogicUnit scan cycle execution, ScanContext integration, and reset behavior.
10. Canonical verification runner and artifact JSON generation.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.iec.sfc_engine import (
    ActionQualifier,
    SFCAction,
    SFCEngine,
    SFCStep,
    SFCTransition,
    verify_sfc_engine_and_export_evidence,
)


def test_sfc_initial_step_and_step_bounds() -> None:
    """Verify initial step is activated on creation and step IDs are strictly 1..16."""
    s1 = SFCStep(step_id=1, name="START", is_initial=True)
    assert s1.active is True
    assert s1.active_time_s == 0.0

    s2 = SFCStep(step_id=2, name="PROCESS", is_initial=False)
    assert s2.active is False

    with pytest.raises(ValueError):
        SFCStep(step_id=0, name="INVALID_ZERO")

    with pytest.raises(ValueError):
        SFCStep(step_id=17, name="INVALID_OVERFLOW")


def test_action_qualifiers_n_s_r() -> None:
    """Verify Non-stored (N), Set (S), and Reset (R) action qualifiers."""
    reg = RegisterTable()
    engine = SFCEngine(register_table=reg, dt_s=0.010)

    # Custom simple chart for qualifier testing
    engine.steps.clear()
    engine.transitions.clear()

    # Step 1: Set a latch coil (%M20)
    s1 = SFCStep(
        step_id=1,
        name="STEP_SET",
        is_initial=True,
        actions=[SFCAction(action_id="SET_LATCH", qualifier=ActionQualifier.S, target_address="%M20")],
    )

    # Step 2: Non-stored output (%M21)
    s2 = SFCStep(
        step_id=2,
        name="STEP_NON_STORED",
        actions=[SFCAction(action_id="NON_STORED", qualifier=ActionQualifier.N, target_address="%M21")],
    )

    # Step 3: Reset the latch coil (%M20)
    s3 = SFCStep(
        step_id=3,
        name="STEP_RESET",
        actions=[SFCAction(action_id="RESET_LATCH", qualifier=ActionQualifier.R, target_address="%M20")],
    )

    engine.add_step(s1)
    engine.add_step(s2)
    engine.add_step(s3)

    t1 = SFCTransition(
        transition_id="T1", from_step_ids=[1], to_step_ids=[2],
        condition_fn=lambda r, t: bool(r.read_bit("%M1")),
    )
    t2 = SFCTransition(
        transition_id="T2", from_step_ids=[2], to_step_ids=[3],
        condition_fn=lambda r, t: bool(r.read_bit("%M2")),
    )
    engine.add_transition(t1)
    engine.add_transition(t2)

    # Step 1: S action activates %M20
    engine.step(0.010)
    assert reg.read_bit("%M20") is True
    assert reg.read_bit("%M21") is False

    # Transition to Step 2: S action remains latched high, N action activates %M21
    reg.write_bit("%M1", True, privilege=PrivilegeMode.SYSTEM)
    engine.step(0.010)
    assert engine.steps[2].active is True
    assert reg.read_bit("%M20") is True   # S action remains True even when Step 1 deactivates!
    assert reg.read_bit("%M21") is True   # N action active

    # Transition to Step 3: N action turns off, R action clears %M20
    reg.write_bit("%M2", True, privilege=PrivilegeMode.SYSTEM)
    engine.step(0.010)
    assert engine.steps[3].active is True
    assert reg.read_bit("%M21") is False  # N action deactivated!
    assert reg.read_bit("%M20") is False  # R action cleared the stored latch!


def test_action_qualifiers_time_limited_and_delayed() -> None:
    """Verify Time-Limited (L) and Time-Delayed (D) actions."""
    reg = RegisterTable()
    engine = SFCEngine(register_table=reg, dt_s=0.010)
    engine.steps.clear()
    engine.transitions.clear()

    # Step 1: L action (duration 0.05s) and D action (delay 0.03s)
    s1 = SFCStep(
        step_id=1,
        name="STEP_TIMED",
        is_initial=True,
        actions=[
            SFCAction(action_id="ACT_L", qualifier=ActionQualifier.L, target_address="%M22", duration_s=0.050),
            SFCAction(action_id="ACT_D", qualifier=ActionQualifier.D, target_address="%M23", duration_s=0.030),
        ],
    )
    engine.add_step(s1)

    # t = 0.010s: L is ON, D is OFF
    engine.step(0.010)
    assert reg.read_bit("%M22") is True
    assert reg.read_bit("%M23") is False

    # t = 0.035s (after 3 more steps): L is ON, D turns ON
    for _ in range(3):
        engine.step(0.010)
    assert reg.read_bit("%M22") is True
    assert reg.read_bit("%M23") is True

    # t = 0.065s (after 3 more steps): L turns OFF (exceeded 0.050s), D remains ON
    for _ in range(3):
        engine.step(0.010)
    assert reg.read_bit("%M22") is False
    assert reg.read_bit("%M23") is True


def test_action_qualifier_pulse() -> None:
    """Verify Pulse (P) action qualifier fires for exactly one scan cycle."""
    reg = RegisterTable()
    engine = SFCEngine(register_table=reg, dt_s=0.010)
    engine.steps.clear()
    engine.transitions.clear()

    s1 = SFCStep(
        step_id=1,
        name="STEP_PULSE",
        is_initial=True,
        actions=[SFCAction(action_id="ACT_P", qualifier=ActionQualifier.P, target_address="%M24")],
    )
    engine.add_step(s1)

    # First cycle: pulse active
    engine.step(0.010)
    assert reg.read_bit("%M24") is True

    # Second cycle: pulse expired
    engine.step(0.010)
    assert reg.read_bit("%M24") is False


def test_selection_divergence_priority() -> None:
    """Verify OR-branch priority arbitration when multiple conditions are true."""
    reg = RegisterTable()
    engine = SFCEngine(register_table=reg, dt_s=0.010)
    engine.steps.clear()
    engine.transitions.clear()

    s1 = SFCStep(step_id=1, name="BRANCH_ORIGIN", is_initial=True)
    s2 = SFCStep(step_id=2, name="HIGH_PRIO_TARGET")
    s3 = SFCStep(step_id=3, name="LOW_PRIO_TARGET")

    engine.add_step(s1)
    engine.add_step(s2)
    engine.add_step(s3)

    # Both conditions are True simultaneously, but T_high has priority 1 < 2
    t_high = SFCTransition(
        transition_id="T_HIGH", from_step_ids=[1], to_step_ids=[2],
        priority=1, condition_fn=lambda r, t: True,
    )
    t_low = SFCTransition(
        transition_id="T_LOW", from_step_ids=[1], to_step_ids=[3],
        priority=2, condition_fn=lambda r, t: True,
    )
    engine.add_transition(t_high)
    engine.add_transition(t_low)

    engine.step(0.010)
    # High priority branch must be taken; low priority must not be taken
    assert engine.steps[2].active is True
    assert engine.steps[3].active is False


def test_simultaneous_divergence_and_convergence() -> None:
    """Verify AND fork and AND join synchronization bar."""
    reg = RegisterTable()
    engine = SFCEngine(register_table=reg, dt_s=0.010)

    # Test the default batch chart:
    # Step 1 -> Step 2 -> [Step 3, Step 4] -> Step 5 -> Step 1
    # 1. Trigger Step 1 -> Step 2
    reg.write_bit("%M40", True, privilege=PrivilegeMode.SYSTEM)
    engine.step(0.010)
    assert engine.steps[2].active is True

    # 2. Trigger AND-fork: Step 2 -> [Step 3, Step 4]
    reg.write_word("%AI1", 16000, privilege=PrivilegeMode.SYSTEM)
    engine.step(0.010)
    assert engine.steps[2].active is False
    assert engine.steps[3].active is True
    assert engine.steps[4].active is True

    # 3. AND-join synchronization bar:
    # If Step 3 or 4 is inactive, transition T3 must not fire even if condition is True!
    # Artificially deactivate Step 4
    engine.steps[4].active = False
    reg.write_word("%AI3", 16000, privilege=PrivilegeMode.SYSTEM)
    engine.step(0.010)
    # Step 5 must NOT activate because Step 4 was not active!
    assert engine.steps[5].active is False

    # Restore Step 4 active
    engine.steps[4].active = True
    engine.step(0.010)
    # Now both 3 and 4 were active, so AND-join fires!
    assert engine.steps[3].active is False
    assert engine.steps[4].active is False
    assert engine.steps[5].active is True


def test_ladder_construct_interception() -> None:
    """Verify strict Pure ST enforcement: Ladder syntax is intercepted immediately."""
    # Forbidden contact --[ ]--
    with pytest.raises(LadderForbiddenError):
        SFCAction(action_id="BAD1", body_st="IF ---[ ]--- THEN x := 1; END_IF;")

    # Forbidden coil --( )--
    with pytest.raises(LadderForbiddenError):
        SFCAction(action_id="BAD2", body_st="---( )---;")

    # Forbidden RUNG delimiter
    with pytest.raises(LadderForbiddenError):
        SFCAction(action_id="BAD3", body_st="RUNG 1: x := 10;")

    # Forbidden ladder mnemonic XIC
    with pytest.raises(LadderForbiddenError):
        SFCTransition(
            transition_id="BAD_T", from_step_ids=[1], to_step_ids=[2],
            condition_code="XIC(Tag1);",
        )


def test_horner_register_synchronization() -> None:
    """Verify %R250..%R253 telemetry words and %M51..%M53 control coils."""
    reg = RegisterTable()
    engine = SFCEngine(register_table=reg, dt_s=0.010)

    # Initial step active: ID = 1
    engine.step(0.010)
    assert reg.read_word("%R250") == 1
    assert reg.read_word("%R251") == 1

    # Manual advance via %M52
    reg.write_bit("%M52", True, privilege=PrivilegeMode.SYSTEM)
    engine.step(0.010)
    assert engine.steps[2].active is True
    assert reg.read_word("%R251") == 2
    # %M52 should be self-cleared
    assert reg.read_bit("%M52") is False

    # Reset trigger via %M53
    reg.write_bit("%M53", True, privilege=PrivilegeMode.SYSTEM)
    engine.step(0.010)
    assert engine.steps[1].active is True
    assert reg.read_word("%R251") == 1


def test_ilogicunit_interface() -> None:
    """Verify compliance with ILogicUnit protocol."""
    engine = SFCEngine()
    assert engine.name == "SFCEngineLogicUnit"
    assert engine.priority == 30
    assert engine.is_enabled is True

    ctx = ScanContext(
        cycle=1,
        dt_ms=10.0,
        elapsed_time_ms=10.0,
        get_register=lambda addr: 0,
        set_register=lambda addr, val: None,
        get_variable=lambda name, default=None: default,
        set_variable=lambda name, val: None,
        record_fault=lambda fault: None,
    )
    engine.execute(ctx)
    assert engine.virtual_time_s > 0.0

    engine.reset()
    assert engine.virtual_time_s == 0.0


def test_verify_sfc_engine_evidence(tmp_path: Path) -> None:
    """Verify canonical evidence generation function."""
    out_evidence = tmp_path / "sfc_engine_evidence.json"
    result = verify_sfc_engine_and_export_evidence(str(out_evidence))
    assert result["status"] == "success"
    assert result["error_code"] is None
    assert out_evidence.exists()

    with open(out_evidence, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["data"]["work_package"] == "W060"
    assert loaded["data"]["gate"] == "G4"
    assert loaded["data"]["topology_verified"]["and_fork_verified"] is True
    assert loaded["data"]["topology_verified"]["and_join_verified"] is True
