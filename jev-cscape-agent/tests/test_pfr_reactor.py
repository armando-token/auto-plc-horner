"""Unit and integration tests for Tubular Catalytic Plug-Flow Reactor (PFR) ODE.

Work Package: W077 (Gate G7 / G4)
Verifies:
- First-principles Arrhenius reaction rate and temperature sensitivity
- Axially discretized dynamic step execution (C_A and T profiles)
- Hot-spot peak formation and axial coordinate identification
- Emergency coolant flood override mode and hotspot quenching
- Thermal runaway alarm latching and reset handshake (%M90)
- Mass and energy balance conservation residuals (< 1e-10)
- Horner OCS register space synchronization (%R380..%R387, %M88..%M90)
- Pure ST POU AST parsing and variable binding extraction
- Hard fail-closed rejection of forbidden ladder logic constructs
"""

from __future__ import annotations

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.pfr_reactor import (
    PFR_REACTOR_ST_CODE,
    PFRConfig,
    TubularPFRSimulator,
)
from jev_cscape.simulation.register_table import RegisterTable


def test_pfr_reaction_rate_kinetics() -> None:
    """Verify Arrhenius reaction rate calculation and exponential temperature scaling."""
    sim = TubularPFRSimulator()
    r_cold = sim.compute_reaction_rate(c_a=20.0, t_k=300.0)
    r_hot = sim.compute_reaction_rate(c_a=20.0, t_k=400.0)
    assert r_cold > 0.0
    assert r_hot > r_cold * 100.0  # Exponential increase with temperature

    # Zero reactant -> zero rate
    assert sim.compute_reaction_rate(c_a=0.0, t_k=400.0) == 0.0


def test_pfr_dynamic_step_and_hotspot() -> None:
    """Verify dynamic step execution, conversion, and hot-spot localization."""
    sim = TubularPFRSimulator()
    res = sim.step(dt_s=0.05)
    assert res["conversion_pct"] >= 0.0
    assert res["t_max_c"] >= sim.cfg.t_inlet_c - 10.0
    assert 0.0 <= res["z_hot_pct"] <= 100.0
    assert res["conservation"]["mass_conserved"] is True
    assert res["conservation"]["energy_conserved"] is True


def test_conservation_residuals_down_to_1e10() -> None:
    """Verify mass and energy balance conservation residuals strictly satisfy < 1e-10."""
    sim = TubularPFRSimulator()
    for _ in range(10):
        res = sim.step(dt_s=0.02)
        assert res["conservation"]["mass_residual"] < 1.0e-10
        assert res["conservation"]["energy_residual"] < 1.0e-10


def test_emergency_coolant_flood_quench() -> None:
    """Verify emergency coolant flood overrides jacket and quenches hot-spot."""
    sim = TubularPFRSimulator()
    # Run a few steps
    for _ in range(5):
        sim.step(dt_s=0.05)
    t_normal = sim.t_max_c

    # Trigger emergency coolant flood
    sim.emergency_coolant_override = True
    for _ in range(15):
        sim.step(dt_s=0.05)

    assert sim.coolant_flood_active is True
    assert sim.status_word & 0x0010 != 0  # Flood bit
    assert sim.t_max_c < t_normal  # Temperature successfully quenched


def test_thermal_runaway_latch_and_reset() -> None:
    """Verify runaway alarm latching when T_max >= 200°C and reset handshake."""
    sim = TubularPFRSimulator()
    # Force high core temperature to simulate runaway condition
    sim.temperature_k = [480.0] * sim.N  # ~206.85 °C
    sim.step(dt_s=0.05)

    assert sim.thermal_runaway_latched is True
    assert sim.status_word & 0x0004 != 0  # Runaway alarm bit

    # Reset handshake
    sim.temperature_k = [380.0] * sim.N  # Back to normal range
    sim.reset_alarms = True
    sim.step(dt_s=0.05)
    assert sim.thermal_runaway_latched is False
    assert sim.reset_alarms is False


def test_register_table_synchronization() -> None:
    """Verify bidirectional synchronization with Horner OCS RegisterTable."""
    sim = TubularPFRSimulator()
    table = RegisterTable()

    table.write_register("%R380", 2500)  # 25.00 mol/m3
    table.write_register("%R385", 1150)  # 115.0 °C
    table.write_register("%M88", True)
    table.write_register("%M89", False)
    table.write_register("%M90", False)

    sim.sync_from_register_table(table)
    assert sim.inlet_c_a == 25.0
    assert abs(sim.coolant_t_k - (115.0 + 273.15)) < 1e-4

    for _ in range(30):
        sim.step(dt_s=0.05)
    sim.sync_to_register_table(table)

    assert table.read_register("%R380") == 2500
    assert table.read_register("%R383") > 0
    assert table.read_register("%R387") & 0x0001 != 0  # Normal status bit


def test_pfr_st_pou_ast_parsing_and_bindings() -> None:
    """Verify IEC 61131-3 Pure ST POU syntax and register bindings."""
    val = STParser.validate_code(PFR_REACTOR_ST_CODE)
    assert val.status == AgentStatus.SUCCESS
    assert val.error_code is None

    ast = STParser.parse_pou(PFR_REACTOR_ST_CODE)
    assert ast.name == "W077_TubularPlugFlowReactor"
    assert ast.pou_type == POUType.PROGRAM
    expected_bindings = {
        "%R380", "%R381", "%R382", "%R383", "%R384", "%R385", "%R386", "%R387",
        "%M88", "%M89", "%M90"
    }
    assert set(ast.bound_registers) == expected_bindings
    assert ast.statements_count > 0


@pytest.mark.parametrize(
    "ladder_artifact",
    [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(S)---",
        "---(R)---",
        "RUNG 1",
        "END_RUNG",
        "NETWORK 10",
        "XIC Enable_PFR_Loop",
        "XIO Emergency_Coolant_Override",
        "OTE Reactor_Status_Word",
        "OTL Thermal_Runaway_Latched",
        "OTU Hot_Spot_Warning_Latched",
    ],
)
def test_pfr_forbidden_ladder_constructs_rejected(ladder_artifact: str) -> None:
    """Verify ladder logic tokens are strictly rejected with ERR_LADDER_FORBIDDEN."""
    bad_code = f"{PFR_REACTOR_ST_CODE}\n{ladder_artifact}\n"
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_code)
    res = STParser.validate_code(bad_code)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "ERR_LADDER_FORBIDDEN"
    assert res.data["ladder_rejected"] is True
