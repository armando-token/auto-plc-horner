"""Tests for ANSI/ISA-88 Batch Phase Engine & Recipe Sequencer.

Work Package: W057 (Gate G4 Simulation / Gate G9 Control Logic)
"""

import json
from pathlib import Path
import pytest

from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.batch_phase_engine import (
    BatchFaultCode,
    BatchPhaseEngine,
    BatchRecipe,
    BatchRecipePhase,
    ISA88Command,
    ISA88State,
    RecipeStepConfig,
    verify_batch_phase_engine_and_export_evidence,
)


def test_batch_phase_engine_initial_idle_state():
    """Verify initial quiescent state is IDLE and registers are properly cleared."""
    reg_table = RegisterTable()
    engine = BatchPhaseEngine(register_table=reg_table)

    assert engine.state == ISA88State.IDLE
    assert engine.current_step_index == 0
    assert engine.fault_code == BatchFaultCode.NONE

    # Initial register synchronization
    engine.step(0.010)
    assert reg_table.read_word("%R230") == int(ISA88State.IDLE)
    assert reg_table.read_word("%R231") == 0
    assert reg_table.read_bit("%M40") is True  # IDLE bit


def test_batch_phase_engine_start_command_lifecycle():
    """Verify START command transitions from IDLE to RUNNING."""
    engine = BatchPhaseEngine()
    ok, msg = engine.send_command(ISA88Command.START)

    assert ok is True
    assert engine.state == ISA88State.RUNNING

    # Cannot START again while RUNNING
    ok_again, msg_again = engine.send_command(ISA88Command.START)
    assert ok_again is False


def test_batch_phase_engine_pause_and_resume():
    """Verify PAUSE -> PAUSING -> PAUSED -> RESUME -> RESUMING -> RUNNING."""
    engine = BatchPhaseEngine()
    engine.send_command(ISA88Command.START)
    assert engine.state == ISA88State.RUNNING

    # Pause
    ok, _ = engine.send_command(ISA88Command.PAUSE)
    assert ok is True
    assert engine.state == ISA88State.PAUSING

    for _ in range(25):
        engine.step(0.010)
    assert engine.state == ISA88State.PAUSED

    # Resume
    ok_res, _ = engine.send_command(ISA88Command.RESUME)
    assert ok_res is True
    assert engine.state == ISA88State.RESUMING

    for _ in range(25):
        engine.step(0.010)
    assert engine.state == ISA88State.RUNNING


def test_batch_phase_engine_hold_and_restart():
    """Verify HOLD -> HOLDING -> HELD -> RESTART -> RESTARTING -> RUNNING."""
    engine = BatchPhaseEngine()
    engine.send_command(ISA88Command.START)

    # Hold
    ok, _ = engine.send_command(ISA88Command.HOLD)
    assert ok is True
    assert engine.state == ISA88State.HOLDING

    for _ in range(15):
        engine.step(0.010)
    assert engine.state == ISA88State.HELD
    assert engine.current_inflow_cmd == 0.0
    assert engine.current_heater_cmd == 0.0

    # Restart
    ok_rst, _ = engine.send_command(ISA88Command.RESTART)
    assert ok_rst is True
    assert engine.state == ISA88State.RESTARTING

    for _ in range(25):
        engine.step(0.010)
    assert engine.state == ISA88State.RUNNING


def test_batch_phase_engine_abort_preemption_and_reset():
    """Verify ABORT pre-empts active states and transitions to ABORTED with RESET to IDLE."""
    engine = BatchPhaseEngine()
    engine.send_command(ISA88Command.START)

    # Abort
    ok_abort, _ = engine.send_command(ISA88Command.ABORT)
    assert ok_abort is True
    assert engine.state == ISA88State.ABORTING

    for _ in range(10):
        engine.step(0.010)
    assert engine.state == ISA88State.ABORTED

    # Reset
    ok_reset, _ = engine.send_command(ISA88Command.RESET)
    assert ok_reset is True
    assert engine.state == ISA88State.IDLE


def test_batch_phase_engine_interlock_high_level():
    """Verify high level trip (>1.9m) trips engine to HOLDING with HIGH_LEVEL_TRIP fault."""
    reg_table = RegisterTable()
    engine = BatchPhaseEngine(register_table=reg_table)
    engine.send_command(ISA88Command.START)
    assert engine.state == ISA88State.RUNNING

    # Inject high level: 31000 counts = 1.9375m
    reg_table.write_word("%AI1", 31000, privilege=PrivilegeMode.SYSTEM)
    engine.step(0.010)

    assert engine.fault_code == BatchFaultCode.HIGH_LEVEL_TRIP
    assert engine.state == ISA88State.HOLDING


def test_batch_phase_engine_interlock_high_temp():
    """Verify high temperature trip (>85C) trips engine to HOLDING."""
    reg_table = RegisterTable()
    engine = BatchPhaseEngine(register_table=reg_table)
    engine.send_command(ISA88Command.START)

    # Inject high temp: 28000 counts = 87.5 C
    reg_table.write_word("%AI3", 28000, privilege=PrivilegeMode.SYSTEM)
    engine.step(0.010)

    assert engine.fault_code == BatchFaultCode.HIGH_TEMP_TRIP
    assert engine.state == ISA88State.HOLDING


def test_batch_phase_engine_recipe_phase_progression():
    """Verify timed recipe step advances to next phase upon target duration elapsed."""
    short_recipe = BatchRecipe(
        recipe_id=999,
        name="Test Short Recipe",
        steps=[
            RecipeStepConfig(phase=BatchRecipePhase.PRE_FILL, name="S1", target_duration_s=0.05),
            RecipeStepConfig(phase=BatchRecipePhase.FILL, name="S2", target_duration_s=0.05),
        ],
    )
    reg_table = RegisterTable()
    engine = BatchPhaseEngine(register_table=reg_table, recipe=short_recipe)

    engine.send_command(ISA88Command.START)
    assert engine.current_step_index == 0

    # Step 60ms (exceeds 50ms)
    for _ in range(6):
        engine.step(0.010)
    assert engine.current_step_index == 1

    # Step another 60ms
    for _ in range(6):
        engine.step(0.010)
    # Both steps done -> COMPLETE
    assert engine.state == ISA88State.COMPLETE
    assert reg_table.read_bit("%M42") is True


def test_verify_and_export_evidence(tmp_path: Path):
    """Verify canonical verification runner creates evidence JSON with status success."""
    out_file = tmp_path / "batch_phase_evidence.json"
    result = verify_batch_phase_engine_and_export_evidence(str(out_file))

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert out_file.exists()

    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["status"] == "success"
    assert data["data"]["work_package"] == "W057"
    assert data["data"]["gate"] == "G4"
    assert data["data"]["isa88_state_model"]["total_states"] == 13
