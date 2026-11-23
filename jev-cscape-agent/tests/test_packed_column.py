"""Unit and integration tests for Packed Absorption Column ODE and Hydraulics.

Work Package: W074 (Gate G7 / G4)
Verifies:
- Whitman Two-Film mass transfer and van 't Hoff temperature dependency
- Sherwood-Leva GPDC flooding hydraulics and pressure drop correlations
- Dynamic ODE material balances and solute gas scrubbing efficiency
- Alarm latching: Incipient Flooding, Flooding Alarm, Low Efficiency, High DeltaP
- Pure ST POU AST parsing and Horner OCS register bindings (%R350..%R357, %M81..%M83)
- Fail-closed security guard rejection of forbidden ladder logic constructs
"""

from __future__ import annotations

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.packed_column import (
    PACKED_COLUMN_ST_CODE,
    PackedAbsorptionColumn,
    PackedAbsorptionConfig,
    PackedColumnSupervisor,
)
from jev_cscape.simulation.register_table import RegisterTable


def test_two_film_and_vant_hoff() -> None:
    """Verify temperature-dependent Henry's slope and Two-Film overall coefficient."""
    col = PackedAbsorptionColumn()
    # At 25 °C reference, m should equal m_0 (0.80)
    m_25 = col.compute_henry_m(25.0)
    assert abs(m_25 - 0.80) < 1e-3

    # At 50 °C (323.15 K), exothermic dissolution means solubility decreases and m increases
    m_50 = col.compute_henry_m(50.0)
    assert m_50 > m_25

    # Overall mass transfer coefficient K_OG*a
    k_og_a = col.compute_k_og_a(25.0)
    assert k_og_a > 0.0
    # Resistance in series: 1/K_OG*a = 1/k_G*a + m/k_L*a
    expected_k_og_a = 1.0 / (1.0 / col.cfg.k_g_a + 0.80 / col.cfg.k_l_a)
    assert abs(k_og_a - expected_k_og_a) < 1e-4


def test_gpdc_hydraulics_and_flooding() -> None:
    """Verify Sherwood-Leva GPDC flooding hydraulics and pressure drop."""
    col = PackedAbsorptionColumn()
    # Nominal flows: L = 120 L/min (0.002 m3/s), G = 850 m3/h (0.236 m3/s)
    l_vol = 120.0 / 60000.0
    g_vol = 850.0 / 3600.0

    hyd = col.compute_hydraulics(l_vol, g_vol)
    assert 0.0 < hyd["pct_flooding"] < 100.0
    assert hyd["dp_total_mbar"] > 0.0
    assert hyd["u_flood_m_s"] > hyd["u_g_m_s"]


def test_packed_column_closed_loop_scrubbing() -> None:
    """Verify closed-loop continuous scrubbing simulation achieves >90% removal."""
    sup = PackedColumnSupervisor()
    sup.solute_gas_inflow = 5000  # 500.0 ppm
    sup.gas_flow_rate = 8500      # 850.0 m3/h

    # Run for 20 steps (2 seconds)
    res = {}
    for _ in range(20):
        res = sup.step(dt_s=0.1)

    assert res["status"] == "success"
    assert res["efficiency_pct"] >= 90.0
    assert res["outlet_ppm"] <= 50.0
    assert sup.column_status_word & 0x0001 != 0  # Normal status bit


def test_low_solvent_causes_low_efficiency_alarm() -> None:
    """Verify that cutting solvent flow causes low efficiency alarm to latch."""
    sup = PackedColumnSupervisor()
    sup.auto_liquid_opt = False
    sup.liquid_solvent_inflow = 150  # 15.0 L/min starved liquid
    sup.solute_gas_inflow = 5000     # 500.0 ppm

    for _ in range(30):
        sup.step(dt_s=0.1)

    assert sup.low_efficiency_alarm_latched is True
    assert sup.column_status_word & 0x0008 != 0  # Bit 3: Low Efficiency
    assert sup.column_status_word & 0x0080 != 0  # Bit 7: Alarm Latched


def test_excessive_gas_flow_causes_flooding_alarm() -> None:
    """Verify excessive gas flow causes flooding alarm to latch."""
    sup = PackedColumnSupervisor()
    sup.gas_flow_rate = 14000  # 1400 m3/h high gas velocity

    sup.step(dt_s=0.1)
    assert sup.flooding_alarm_latched is True
    assert sup.column_status_word & 0x0004 != 0  # Bit 2: Flooding Alarm
    assert sup.column_status_word & 0x0080 != 0  # Bit 7: Alarm Latched


def test_alarm_reset_handshake() -> None:
    """Verify alarm reset handshake clears latched alarms once process normalizes."""
    sup = PackedColumnSupervisor()
    sup.auto_liquid_opt = False
    sup.liquid_solvent_inflow = 150
    for _ in range(20):
        sup.step(dt_s=0.1)
    assert sup.low_efficiency_alarm_latched is True

    # Return to normal operating conditions
    sup.auto_liquid_opt = True
    sup.liquid_solvent_inflow = 1200
    for _ in range(20):
        sup.step(dt_s=0.1)

    # Set reset handshake
    sup.reset_alarms = True
    sup.step(dt_s=0.1)
    assert sup.reset_alarms is False
    assert sup.low_efficiency_alarm_latched is False
    assert sup.column_status_word & 0x0001 != 0  # Restored to Normal


def test_w074_st_pou_ast_parsing_and_bindings() -> None:
    """Verify IEC 61131-3 Pure ST POU syntax and register bindings."""
    val = STParser.validate_code(PACKED_COLUMN_ST_CODE)
    assert val.status == AgentStatus.SUCCESS
    assert val.error_code is None

    ast = STParser.parse_pou(PACKED_COLUMN_ST_CODE)
    assert ast.name == "W074_PackedAbsorptionColumn"
    assert ast.pou_type == POUType.PROGRAM
    expected_bindings = {
        "%R350", "%R351", "%R352", "%R353", "%R354", "%R355", "%R356", "%R357",
        "%M81", "%M82", "%M83"
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
        "RUNG 10",
        "END_RUNG",
        "NETWORK 1",
        "XIC Enable_Simulation",
        "XIO Auto_Liquid_Optimization",
        "OTE Liquid_Solvent_Inflow",
        "OTL Flooding_Alarm_Latched",
        "OTU Low_Efficiency_Alarm_Latched",
    ],
)
def test_w074_forbidden_ladder_constructs_rejected(ladder_artifact: str) -> None:
    """Verify ladder logic tokens are strictly rejected with ERR_LADDER_FORBIDDEN."""
    bad_code = f"{PACKED_COLUMN_ST_CODE}\n{ladder_artifact}\n"
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_code)
    res = STParser.validate_code(bad_code)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "ERR_LADDER_FORBIDDEN"
    assert res.data["ladder_rejected"] is True


def test_register_table_sync() -> None:
    """Verify synchronization between PackedColumnSupervisor and Horner RegisterTable."""
    table = RegisterTable()
    sup = PackedColumnSupervisor()

    table.write_register("%R350", 6000)  # 600.0 ppm
    table.write_register("%R354", 9000)  # 900.0 m3/h
    table.write_register("%M81", True)
    table.write_register("%M82", True)

    sup.sync_from_registers(table)
    assert sup.solute_gas_inflow == 6000
    assert sup.gas_flow_rate == 9000

    sup.step(dt_s=0.1)
    sup.sync_to_registers(table)

    assert table.read_register("%R351") == sup.solute_gas_outlet
    assert table.read_register("%R352") == sup.solute_removal_eff
    assert table.read_register("%R357") == sup.column_status_word
