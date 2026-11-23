"""Unit tests for Chemical Reactor pH Neutralization Titration ODE (W071 / Gate G7 / Gate G4)."""

from __future__ import annotations

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.ph_neutralization import (
    CSTRNeutralizationPlant,
    PHNeutralizationController,
    W071_PURE_ST_POU,
    compute_buffer_capacity,
    compute_process_gain,
    solve_ph_analytical,
)
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Physics & Analytical Quadratic Solvers
# ============================================================================

def test_ph_analytical_equivalence_neutral():
    """Verify analytical solver at exact equivalence point gives pH 7.000."""
    ph = solve_ph_analytical(0.0)
    assert abs(ph - 7.0) < 1.0e-7


def test_ph_analytical_acidic_and_basic_branches():
    """Verify analytical solver across strong acidic and basic regimes."""
    # Acidic: 0.01 M HCl -> pH 2.0
    ph_acid = solve_ph_analytical(-0.01)
    assert abs(ph_acid - 2.0) < 1.0e-4

    # Basic: 0.01 M NaOH -> pH 12.0
    ph_base = solve_ph_analytical(0.01)
    assert abs(ph_base - 12.0) < 1.0e-4


def test_buffer_capacity_and_process_gain_ratio():
    """Verify buffer capacity is minimal at pH 7 and process gain is massive."""
    beta_ph7 = compute_buffer_capacity(7.0)
    beta_ph2 = compute_buffer_capacity(2.0)
    gain_ph7 = compute_process_gain(7.0)
    gain_ph2 = compute_process_gain(2.0)

    assert beta_ph7 < beta_ph2
    assert gain_ph7 > gain_ph2
    assert (gain_ph7 / gain_ph2) > 10000.0


# ============================================================================
# 2. CSTR Plant Dynamic ODE & Controller Tests
# ============================================================================

def test_cstr_plant_step_volume_and_mixing():
    """Verify CSTR plant advances volume and mixing lag without divergence."""
    plant = CSTRNeutralizationPlant()
    res1 = plant.step(dt_s=0.1, acid_inflow_l_min=10.0, base_dosing_l_h=0.0)
    assert res1["volume_l"] > 0
    assert res1["ph_bulk"] <= 3.0

    # Add strong base dosing
    res2 = plant.step(dt_s=0.1, acid_inflow_l_min=10.0, base_dosing_l_h=120.0)
    assert res2["ph_bulk"] > res1["ph_bulk"]


def test_ph_neutralization_controller_closed_loop():
    """Verify closed-loop controller drives pH from acidic toward neutral setpoint."""
    controller = PHNeutralizationController()
    controller.registers.write_word("%R320", 250, privilege=PrivilegeMode.SYSTEM)  # 2.50 pH
    controller.registers.write_word("%R321", 700, privilege=PrivilegeMode.SYSTEM)  # 7.00 pH setpoint

    for _ in range(120):
        step = controller.scan_step(dt_s=0.5)

    assert step["ph_meas"] > 4.5
    assert controller.registers.read_word("%R322") >= 0


def test_ph_neutralization_alarm_latching_and_reset():
    """Verify acidic alarm latches when pH < 5.0 and clears with %M76 handshake."""
    controller = PHNeutralizationController()
    # Force low pH
    controller.registers.write_word("%R320", 300, privilege=PrivilegeMode.SYSTEM)
    controller.scan_step(dt_s=0.1)
    assert controller.acidic_alarm_latched is True
    assert (controller.registers.read_word("%R327") & 0x0002) != 0

    # Trigger reset
    controller.registers.write_bit("%M76", True, privilege=PrivilegeMode.SYSTEM)
    controller.scan_step(dt_s=0.1)
    assert controller.registers.read_bit("%M76") is False


# ============================================================================
# 3. Pure ST POU & Forbidden Ladder Tests
# ============================================================================

def test_w071_st_pou_ast_parsing_and_bindings():
    """Verify IEC 61131-3 Pure ST AST parsing and bound registers."""
    val = STParser.validate_code(W071_PURE_ST_POU)
    assert val.status == AgentStatus.SUCCESS
    ast = STParser.parse_pou(W071_PURE_ST_POU)
    assert ast.name == "W071_pHNeutralizationTitration"
    assert ast.pou_type == POUType.PROGRAM
    expected_bindings = {"%R320", "%R321", "%R322", "%R323", "%R324", "%R325", "%R326", "%R327", "%M74", "%M75", "%M76"}
    assert set(ast.bound_registers) == expected_bindings


@pytest.mark.parametrize(
    "ladder_artifact",
    [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(S)---",
        "---(R)---",
        "RUNG 10",
        "END_RUNG",
        "NETWORK 1",
        "XIC Enable_Neutralization",
        "XIO Auto_Dosing_Mode",
        "OTE Base_Dosing_Pump_Cmd",
        "OTL Acidic_Alarm_Latched",
        "OTU Alkaline_Alarm_Latched",
    ],
)
def test_w071_forbidden_ladder_constructs_rejected(ladder_artifact: str):
    """Verify ladder logic tokens are strictly rejected with ERR_LADDER_FORBIDDEN."""
    tainted = f"{W071_PURE_ST_POU}\n{ladder_artifact}"
    val = STParser.validate_code(tainted)
    assert val.status == AgentStatus.FAILED
    assert val.error_code == "ERR_LADDER_FORBIDDEN"
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(tainted)
