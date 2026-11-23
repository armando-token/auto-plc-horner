"""Comprehensive Unit and Integration Test Suite for Ethernet POWERLINK Managing Node (MN) Engine.

Work Package: W148 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Architectural Alignment (following tests/test_sercos3_ring.py and tests/test_ethercat_slave.py):
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1090..%R1097, %M254..%M255).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Managing Node NMT State Machine progression (0..6) and invalid jump rejection.
4. Section 4: Start of Cycle (SoC) telegram serialization, deserialization, and CRC32 integrity.
5. Section 5: Isochronous PReq / PRes cyclic exchange and Controlled Node simulation.
6. Section 6: Controlled Node loss-of-life detection (3 consecutive missed PRes) -> 0xAD01 and %M255 trip.
7. Section 7: Sub-microsecond SoC clock jitter surveillance (< 100 ns) and excursion interlock (0xAD02).
8. Section 8: Asynchronous period (SoA / ASnd) slot management and overrun interlock (0xAD03).
9. Section 9: Managing Node fault (0xAD04), master permissive lockout (%M254), and operator safety recovery.
10. Section 10: Horner OCS register space synchronization (%R1090..%R1097, %M254..%M255).
11. Section 11: 9-Stage Verification Suite integration test emitting strict 4-state contract JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import time
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.powerlink_mn import (
    ETHERNET_POWERLINK_SYNC_POU,
    POWERLINK_BROADCAST_NODE_ID,
    POWERLINK_DEFAULT_ASYNC_SLOT_TIME_US,
    POWERLINK_DEFAULT_CYCLE_TIME_US,
    POWERLINK_ETHERTYPE,
    POWERLINK_JITTER_THRESHOLD_NS,
    POWERLINK_MANAGING_NODE_SYNC_POU,
    POWERLINK_MAX_CN_NODES,
    POWERLINK_MAX_MISSED_PRES_TRIP,
    POWERLINK_MN_NODE_ID,
    POWERLINK_MN_SYNC_POU,
    POWERLINK_PURE_ST_POU,
    POWERLINK_SPEED_BPS,
    PURE_ST_POU,
    PowerlinkASndTelegram,
    PowerlinkAsyncService,
    PowerlinkCNState,
    PowerlinkControlledNode,
    PowerlinkDiagnosticCode,
    PowerlinkManagingNodeEngine,
    PowerlinkManagingNodeState,
    PowerlinkMessageType,
    PowerlinkPReqTelegram,
    PowerlinkPResTelegram,
    PowerlinkSoATelegram,
    PowerlinkSoCTelegram,
    run_powerlink_mn_verification,
    scale_pv_to_int16,
    verify_powerlink_mn_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provides a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def powerlink_mn_engine(register_table: RegisterTable) -> PowerlinkManagingNodeEngine:
    """Provides a fresh PowerlinkManagingNodeEngine with 4 configured Controlled Nodes."""
    engine = PowerlinkManagingNodeEngine(
        reg_table=register_table,
        cycle_time_us=POWERLINK_DEFAULT_CYCLE_TIME_US,
        async_slot_time_us=POWERLINK_DEFAULT_ASYNC_SLOT_TIME_US,
    )
    for i in range(1, 5):
        engine.configure_controlled_node(
            PowerlinkControlledNode(node_id=i, node_name=f"ServoDrive_CN_{i}")
        )
    return engine


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Structured Text POUs and AST symbol binding."""

    def test_verify_powerlink_mn_pure_st_function(self) -> None:
        """Verify helper validation function passes cleanly."""
        assert verify_powerlink_mn_pure_st() is True

    def test_pure_st_powerlink_mn_sync_ast_parsing(self) -> None:
        """Parse POWERLINK_MN_SYNC_POU and assert AST attributes and register bindings."""
        SecurityGuard.assert_pure_st_content(POWERLINK_MN_SYNC_POU)
        res = STParser.validate_code(POWERLINK_MN_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(POWERLINK_MN_SYNC_POU)
        assert ast is not None
        assert ast.name == "PowerlinkMnSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1090", "%R1091", "%R1092", "%R1093",
            "%R1094", "%R1095", "%R1096", "%R1097",
            "%M254", "%M255",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

        var_names = {v.name for v in ast.variables}
        expected_vars = {
            "ManagingNodeState",
            "ActiveControlledNodeCount",
            "CycleTimeMicroseconds",
            "SocJitterNanoseconds",
            "PollRequestCounter",
            "PollResponseCounter",
            "AsynchronousSlotTimeMicroseconds",
            "DiagnosticStatusCode",
            "PowerlinkMnPermissive",
            "ControlledNodeLossTrip",
        }
        assert expected_vars.issubset(var_names)

    def test_pure_st_ethernet_powerlink_sync_alias_ast_parsing(self) -> None:
        """Parse ETHERNET_POWERLINK_SYNC_POU and assert AST attributes."""
        SecurityGuard.assert_pure_st_content(ETHERNET_POWERLINK_SYNC_POU)
        res = STParser.validate_code(ETHERNET_POWERLINK_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(ETHERNET_POWERLINK_SYNC_POU)
        assert ast is not None
        assert ast.name == "EthernetPowerlinkSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1090", "%R1091", "%R1092", "%R1093",
            "%R1094", "%R1095", "%R1096", "%R1097",
            "%M254", "%M255",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_pou_aliases_consistency(self) -> None:
        """Verify backwards compatibility aliases point to the correct POU definitions."""
        assert POWERLINK_PURE_ST_POU == POWERLINK_MN_SYNC_POU
        assert PURE_ST_POU == POWERLINK_MN_SYNC_POU
        assert POWERLINK_MANAGING_NODE_SYNC_POU == ETHERNET_POWERLINK_SYNC_POU


# ============================================================================
# Section 2: Anti-Ladder Logic Security Interception
# ============================================================================

class TestSection2AntiLadderGuards:
    """Tests for interception and rejection of ladder logic constructs."""

    @pytest.mark.parametrize(
        "bad_code, expected_reason",
        [
            ("PROGRAM BadContact\nVAR X: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM", "ladder contact"),
            ("PROGRAM BadNegContact\nVAR X: BOOL; END_VAR\n---[/]---\nEND_PROGRAM", "ladder negative contact"),
            ("PROGRAM BadCoil\nVAR X: BOOL; END_VAR\n---( )---\nEND_PROGRAM", "ladder coil"),
            ("PROGRAM BadRung\nVAR X: BOOL; END_VAR\nRUNG 1\nEND_PROGRAM", "rung keyword"),
            ("PROGRAM BadMnemonic\nVAR X: BOOL; END_VAR\nXIC %M254\nOTE %M255\nEND_PROGRAM", "ladder mnemonic"),
        ],
    )
    def test_security_guard_rejects_ladder_syntax(self, bad_code: str, expected_reason: str) -> None:
        """Asserts SecurityGuard raises LadderForbiddenError for ladder logic elements."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_st_parser_returns_failed_on_ladder_logic(self) -> None:
        """Asserts STParser.validate_code returns FAILED with ERR_LADDER_FORBIDDEN."""
        ladder_snippet = "PROGRAM Illegal\nVAR S: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM"
        res = STParser.validate_code(ladder_snippet)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"
        assert res.data.get("ladder_rejected") is True


# ============================================================================
# Section 3: Managing Node NMT State Machine Progression & Transition Safety
# ============================================================================

class TestSection3NMTStateMachine:
    """Tests for Managing Node NMT state transitions per EPSG DS 301."""

    def test_initial_nmt_state(self, powerlink_mn_engine: PowerlinkManagingNodeEngine) -> None:
        """Asserts engine starts in NMT_GS_INITIALISATION."""
        assert powerlink_mn_engine.state == PowerlinkManagingNodeState.NMT_GS_INITIALISATION
        assert powerlink_mn_engine.reg_table.read_word("%R1090") == 0

    def test_sequential_forward_progression(self, powerlink_mn_engine: PowerlinkManagingNodeEngine) -> None:
        """Traverses sequential NMT transitions: 0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6."""
        sequence = [
            PowerlinkManagingNodeState.NMT_GS_RESET_APP,
            PowerlinkManagingNodeState.NMT_MS_NOT_ACTIVE,
            PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_1,
            PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2,
            PowerlinkManagingNodeState.NMT_MS_READY_TO_OPERATE,
            PowerlinkManagingNodeState.NMT_MS_OPERATIONAL,
        ]
        for target in sequence:
            ok, msg = powerlink_mn_engine.request_state_transition(target)
            assert ok is True, f"Failed transitioning to {target.name}: {msg}"
            assert powerlink_mn_engine.state == target
            assert powerlink_mn_engine.reg_table.read_word("%R1090") == int(target)

        # Operational state assertions
        assert powerlink_mn_engine.state == PowerlinkManagingNodeState.NMT_MS_OPERATIONAL
        assert powerlink_mn_engine.permissive_coil is True
        assert powerlink_mn_engine.reg_table.read_bit("%M254") is True

    def test_illegal_direct_jumps_rejected(self, powerlink_mn_engine: PowerlinkManagingNodeEngine) -> None:
        """Asserts non-sequential jumps are rejected without state alteration."""
        # Illegal jump from INITIALISATION (0) to OPERATIONAL (6)
        ok, msg = powerlink_mn_engine.request_state_transition(PowerlinkManagingNodeState.NMT_MS_OPERATIONAL)
        assert ok is False
        assert "Illegal state transition" in msg
        assert powerlink_mn_engine.state == PowerlinkManagingNodeState.NMT_GS_INITIALISATION

        # Illegal jump from INITIALISATION (0) to PRE_OPERATIONAL_2 (4)
        ok2, _ = powerlink_mn_engine.request_state_transition(PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2)
        assert ok2 is False
        assert powerlink_mn_engine.state == PowerlinkManagingNodeState.NMT_GS_INITIALISATION

    def test_cannot_enter_operational_with_zero_active_cns(self, register_table: RegisterTable) -> None:
        """Asserts transition to OPERATIONAL is rejected if active CN count is 0."""
        empty_engine = PowerlinkManagingNodeEngine(reg_table=register_table)
        # Advance to READY_TO_OPERATE
        empty_engine.request_state_transition(PowerlinkManagingNodeState.NMT_GS_RESET_APP)
        empty_engine.request_state_transition(PowerlinkManagingNodeState.NMT_MS_NOT_ACTIVE)
        empty_engine.request_state_transition(PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_1)
        empty_engine.request_state_transition(PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2)
        empty_engine.request_state_transition(PowerlinkManagingNodeState.NMT_MS_READY_TO_OPERATE)

        # Attempt OPERATIONAL with no CNs
        ok, msg = empty_engine.request_state_transition(PowerlinkManagingNodeState.NMT_MS_OPERATIONAL)
        assert ok is False
        assert "zero active Controlled Nodes" in msg


# ============================================================================
# Section 4: Start of Cycle (SoC) Generation, Frame Codec, and Timestamp Integrity
# ============================================================================

class TestSection4SoCCodec:
    """Tests for SoC broadcast telegram generation, serialization, and CRC32 verification."""

    def test_soc_serialization_and_deserialization(self, powerlink_mn_engine: PowerlinkManagingNodeEngine) -> None:
        """Serializes and deserializes SoC telegram, verifying exact field preservation."""
        soc = powerlink_mn_engine.generate_soc_telegram()
        raw_bytes = soc.serialize()

        assert len(raw_bytes) == 38  # 17B eth hdr + 17B body + 4B CRC32
        deser = PowerlinkSoCTelegram.deserialize(raw_bytes)

        assert deser.ethertype == POWERLINK_ETHERTYPE
        assert deser.message_type == PowerlinkMessageType.SOC
        assert deser.dst_node_id == POWERLINK_BROADCAST_NODE_ID
        assert deser.src_node_id == POWERLINK_MN_NODE_ID
        assert deser.net_time_ns > 0

    def test_soc_corrupted_crc_rejected(self, powerlink_mn_engine: PowerlinkManagingNodeEngine) -> None:
        """Asserts deserializer detects and rejects CRC32 corruption."""
        soc = powerlink_mn_engine.generate_soc_telegram()
        raw = soc.serialize()
        corrupted = raw[:-1] + bytes([raw[-1] ^ 0xFF])

        with pytest.raises(ValueError, match="CRC32 mismatch"):
            PowerlinkSoCTelegram.deserialize(corrupted)


# ============================================================================
# Section 5: Isochronous PReq / PRes Cyclic Exchange & Controlled Node Tracking
# ============================================================================

class TestSection5IsochronousExchange:
    """Tests for real-time cyclic polling across configured Controlled Nodes."""

    def test_preq_pres_cyclic_exchange(self, powerlink_mn_engine: PowerlinkManagingNodeEngine) -> None:
        """Executes 5 motion cycles, asserting PReq and PRes increments and register updates."""
        # Advance engine to OPERATIONAL
        for state in [
            PowerlinkManagingNodeState.NMT_GS_RESET_APP,
            PowerlinkManagingNodeState.NMT_MS_NOT_ACTIVE,
            PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_1,
            PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2,
            PowerlinkManagingNodeState.NMT_MS_READY_TO_OPERATE,
            PowerlinkManagingNodeState.NMT_MS_OPERATIONAL,
        ]:
            powerlink_mn_engine.request_state_transition(state)

        initial_preq = powerlink_mn_engine.preq_counter
        initial_pres = powerlink_mn_engine.pres_counter

        for _ in range(5):
            res = powerlink_mn_engine.execute_cycle(simulated_jitter_ns=20)
            assert res["polled_nodes"] == 4
            assert res["responded_nodes"] == 4

        # 4 CNs * 5 cycles = 20 telegrams exchanged
        assert powerlink_mn_engine.preq_counter == initial_preq + 20
        assert powerlink_mn_engine.pres_counter == initial_pres + 20
        assert powerlink_mn_engine.reg_table.read_word("%R1094") == (powerlink_mn_engine.preq_counter & 0xFFFF)
        assert powerlink_mn_engine.reg_table.read_word("%R1095") == (powerlink_mn_engine.pres_counter & 0xFFFF)
        assert powerlink_mn_engine.reg_table.read_word("%R1091") == 4
        assert powerlink_mn_engine.reg_table.read_bit("%M254") is True


# ============================================================================
# Section 6: Controlled Node Timeout Detection & Loss-of-Life 3-Strike Rule (0xAD01)
# ============================================================================

class TestSection6CNTimeoutTrip:
    """Tests for Controlled Node loss-of-life detection on 3 consecutive missed PRes."""

    def test_loss_of_life_3_strike_trip(self, powerlink_mn_engine: PowerlinkManagingNodeEngine) -> None:
        """Induces missed responses on CN 3 and verifies 3-strike trip behavior."""
        for state in [
            PowerlinkManagingNodeState.NMT_GS_RESET_APP,
            PowerlinkManagingNodeState.NMT_MS_NOT_ACTIVE,
            PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_1,
            PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2,
            PowerlinkManagingNodeState.NMT_MS_READY_TO_OPERATE,
            PowerlinkManagingNodeState.NMT_MS_OPERATIONAL,
        ]:
            powerlink_mn_engine.request_state_transition(state)

        cn3 = powerlink_mn_engine.controlled_nodes[3]
        cn3.simulate_miss_response = True

        # Strike 1: missed 1st response (no trip)
        powerlink_mn_engine.execute_cycle()
        assert cn3.consecutive_missed_pres == 1
        assert powerlink_mn_engine.loss_trip_coil is False
        assert powerlink_mn_engine.reg_table.read_bit("%M255") is False

        # Strike 2: missed 2nd response (no trip)
        powerlink_mn_engine.execute_cycle()
        assert cn3.consecutive_missed_pres == 2
        assert powerlink_mn_engine.loss_trip_coil is False

        # Strike 3: missed 3rd response (TRIP!)
        powerlink_mn_engine.execute_cycle()
        assert cn3.consecutive_missed_pres == 3
        assert cn3.is_timed_out is True
        assert powerlink_mn_engine.loss_trip_coil is True
        assert powerlink_mn_engine.reg_table.read_bit("%M255") is True
        assert powerlink_mn_engine.diagnostic_code == PowerlinkDiagnosticCode.POWERLINK_ERR_CN_TIMEOUT
        assert powerlink_mn_engine.reg_table.read_uword("%R1097") == 0xAD01
        assert powerlink_mn_engine.active_cn_count == 3
        assert powerlink_mn_engine.reg_table.read_word("%R1091") == 3
        assert powerlink_mn_engine.reg_table.read_bit("%M254") is False


# ============================================================================
# Section 7: Sub-Microsecond SoC Clock Jitter Surveillance (< 100 ns) (0xAD02)
# ============================================================================

class TestSection7SoCJitterSurveillance:
    """Tests for clock jitter measurement and 0xAD02 excursion detection."""

    def test_jitter_excursion_and_recovery(self, powerlink_mn_engine: PowerlinkManagingNodeEngine) -> None:
        """Simulates jitter > 100 ns, asserts 0xAD02 trip, and validates restoration."""
        for state in [
            PowerlinkManagingNodeState.NMT_GS_RESET_APP,
            PowerlinkManagingNodeState.NMT_MS_NOT_ACTIVE,
            PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_1,
            PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2,
            PowerlinkManagingNodeState.NMT_MS_READY_TO_OPERATE,
            PowerlinkManagingNodeState.NMT_MS_OPERATIONAL,
        ]:
            powerlink_mn_engine.request_state_transition(state)

        # Nominal cycle: 20 ns jitter (< 100 ns)
        powerlink_mn_engine.execute_cycle(simulated_jitter_ns=20)
        assert powerlink_mn_engine.diagnostic_code == PowerlinkDiagnosticCode.OK
        assert powerlink_mn_engine.reg_table.read_word("%R1093") == 20

        # Excursion cycle: 125 ns jitter (> 100 ns threshold)
        powerlink_mn_engine.execute_cycle(simulated_jitter_ns=125)
        assert powerlink_mn_engine.diagnostic_code == PowerlinkDiagnosticCode.POWERLINK_ERR_SOC_JITTER_EXCESS
        assert powerlink_mn_engine.reg_table.read_uword("%R1097") == 0xAD02
        assert powerlink_mn_engine.reg_table.read_word("%R1093") == 125

        # Restored cycle: 30 ns jitter (< 100 ns)
        powerlink_mn_engine.execute_cycle(simulated_jitter_ns=30)
        assert powerlink_mn_engine.diagnostic_code == PowerlinkDiagnosticCode.OK
        assert powerlink_mn_engine.reg_table.read_uword("%R1097") == 0x0000
        assert powerlink_mn_engine.reg_table.read_word("%R1093") == 30


# ============================================================================
# Section 8: Asynchronous Slot Time Management & Overrun Interlock (0xAD03)
# ============================================================================

class TestSection8AsyncOverrun:
    """Tests for asynchronous phase slot management and 0xAD03 overrun surveillance."""

    def test_async_slot_overrun_detection(self, powerlink_mn_engine: PowerlinkManagingNodeEngine) -> None:
        """Verifies asynchronous payload exceeding allocated slot triggers 0xAD03."""
        for state in [
            PowerlinkManagingNodeState.NMT_GS_RESET_APP,
            PowerlinkManagingNodeState.NMT_MS_NOT_ACTIVE,
            PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_1,
            PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2,
            PowerlinkManagingNodeState.NMT_MS_READY_TO_OPERATE,
            PowerlinkManagingNodeState.NMT_MS_OPERATIONAL,
        ]:
            powerlink_mn_engine.request_state_transition(state)

        # Normal async: 50 us <= 100 us allocated
        powerlink_mn_engine.execute_cycle(simulated_jitter_ns=20, simulate_async_time_us=50)
        assert powerlink_mn_engine.diagnostic_code == PowerlinkDiagnosticCode.OK
        assert powerlink_mn_engine.reg_table.read_word("%R1096") == 100

        # Overrun async: 150 us > 100 us allocated
        powerlink_mn_engine.execute_cycle(simulated_jitter_ns=20, simulate_async_time_us=150)
        assert powerlink_mn_engine.diagnostic_code == PowerlinkDiagnosticCode.POWERLINK_ERR_ASYNC_OVERRUN
        assert powerlink_mn_engine.reg_table.read_uword("%R1097") == 0xAD03

        # Restored normal async: 40 us
        powerlink_mn_engine.execute_cycle(simulated_jitter_ns=20, simulate_async_time_us=40)
        assert powerlink_mn_engine.diagnostic_code == PowerlinkDiagnosticCode.OK
        assert powerlink_mn_engine.reg_table.read_uword("%R1097") == 0x0000


# ============================================================================
# Section 9: Managing Node Fault (0xAD04), Master Permissive Lockout, & Recovery
# ============================================================================

class TestSection9ManagingNodeFault:
    """Tests for MN fault trip, permissive lockout, and clean operator safety reset."""

    def test_mn_fault_trip_and_recovery(self, powerlink_mn_engine: PowerlinkManagingNodeEngine) -> None:
        """Asserts trigger_managing_node_fault drops %M254 and reset_safety restores healthy state."""
        for state in [
            PowerlinkManagingNodeState.NMT_GS_RESET_APP,
            PowerlinkManagingNodeState.NMT_MS_NOT_ACTIVE,
            PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_1,
            PowerlinkManagingNodeState.NMT_MS_PRE_OPERATIONAL_2,
            PowerlinkManagingNodeState.NMT_MS_READY_TO_OPERATE,
            PowerlinkManagingNodeState.NMT_MS_OPERATIONAL,
        ]:
            powerlink_mn_engine.request_state_transition(state)

        assert powerlink_mn_engine.permissive_coil is True
        assert powerlink_mn_engine.reg_table.read_bit("%M254") is True

        # Trigger Managing Node Fault (0xAD04)
        powerlink_mn_engine.trigger_managing_node_fault()
        assert powerlink_mn_engine.diagnostic_code == PowerlinkDiagnosticCode.POWERLINK_ERR_MANAGING_NODE_FAULT
        assert powerlink_mn_engine.permissive_coil is False
        assert powerlink_mn_engine.reg_table.read_bit("%M254") is False
        assert powerlink_mn_engine.reg_table.read_uword("%R1097") == 0xAD04

        # Reset safety handshake
        powerlink_mn_engine.reset_safety()
        assert powerlink_mn_engine.diagnostic_code == PowerlinkDiagnosticCode.OK
        assert powerlink_mn_engine.permissive_coil is True
        assert powerlink_mn_engine.reg_table.read_bit("%M254") is True
        assert powerlink_mn_engine.reg_table.read_uword("%R1097") == 0x0000


# ============================================================================
# Section 10: Horner OCS Register Space Synchronization
# ============================================================================

class TestSection10RegisterSync:
    """Tests for complete register table mapping verification (%R1090..%R1097, %M254..%M255)."""

    def test_scaling_utility(self) -> None:
        """Verifies scale_pv_to_int16 clamps to 16-bit range."""
        assert scale_pv_to_int16(10.5, 10.0) == 105
        assert scale_pv_to_int16(5000.0, 10.0) == 32767
        assert scale_pv_to_int16(-5000.0, 10.0) == -32768

    def test_full_register_map_integrity(self, powerlink_mn_engine: PowerlinkManagingNodeEngine) -> None:
        """Asserts each Horner mapped register reflects internal engine state."""
        rt = powerlink_mn_engine.reg_table

        assert rt.read_word("%R1090") == int(powerlink_mn_engine.state)
        assert rt.read_word("%R1091") == powerlink_mn_engine.active_cn_count
        assert rt.read_word("%R1092") == powerlink_mn_engine.cycle_time_us
        assert rt.read_word("%R1093") == powerlink_mn_engine.soc_jitter_ns
        assert rt.read_word("%R1094") == (powerlink_mn_engine.preq_counter & 0xFFFF)
        assert rt.read_word("%R1095") == (powerlink_mn_engine.pres_counter & 0xFFFF)
        assert rt.read_word("%R1096") == powerlink_mn_engine.async_slot_time_us
        assert rt.read_uword("%R1097") == int(powerlink_mn_engine.diagnostic_code)
        assert rt.read_bit("%M254") == powerlink_mn_engine.permissive_coil
        assert rt.read_bit("%M255") == powerlink_mn_engine.loss_trip_coil


# ============================================================================
# Section 11: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestSection11VerificationSuite:
    """Tests for run_powerlink_mn_verification output and evidence file emission."""

    def test_run_powerlink_mn_verification_success(self, tmp_path: Path) -> None:
        """Runs the 9-stage verification suite and verifies strict 4-state contract JSON."""
        evidence_file = tmp_path / "powerlink_mn_evidence.json"
        res = run_powerlink_mn_verification(output_path=evidence_file)

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["tests"]) == 9

        # Ensure all individual stages passed
        for stage_test in res["data"]["tests"]:
            assert stage_test["passed"] is True

        # Verify evidence file written and valid
        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W148"
