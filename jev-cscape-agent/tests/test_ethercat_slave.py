"""Unit Test Suite for Industrial EtherCAT SubDevice (Slave) Protocol Engine & CoE / SyncManager Supervisor.

Work Package: W139 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1000..%R1007, %M233..%M234).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: AL State Machine state transitions (Init -> PreOp -> SafeOp -> Op) and illegal transition rejection.
4. Section 4: SyncManager channels (SM0..SM3) and CoE Object Directory read/write access.
5. Section 5: Distributed Clocks (DC) Sync0 sub-microsecond synchronization and jitter tracking (< 100 ns).
6. Section 6: Process safety trips (0xA401, 0xA402, 0xA403, 0xA404) and Horner coil assertion (%M233, %M234).
7. Section 7: Horner OCS register space synchronization (%R1000..%R1007, %M233..%M234).
8. Section 8: 9-stage verification suite integration test writing evidence JSON.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest
import struct
import time
from typing import Any, Dict

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.ethercat_slave import (
    DC_JITTER_THRESHOLD_NS,
    DC_SYNC0_DEFAULT_CYCLE_NS,
    ETHERCAT_DC_JITTER_THRESHOLD_NS,
    ETHERCAT_FRAME_ETHERTYPE,
    ETHERCAT_PRODUCT_CODE_W139,
    ETHERCAT_PURE_ST_POU,
    ETHERCAT_REVISION_W139,
    ETHERCAT_SERIAL_DEFAULT,
    ETHERCAT_SLAVE_PURE_ST_POU,
    ETHERCAT_SLAVE_STATE_MACHINE_PURE_ST_POU,
    ETHERCAT_SLAVE_SYNC_PURE_ST_POU,
    ETHERCAT_VENDOR_ID_HORNER,
    FMMU0_LOGICAL_ADDR,
    FMMU1_LOGICAL_ADDR,
    MAILBOX_BUFFER_SIZE,
    PROCESS_DATA_SIZE,
    SM0_MAILBOX_OUT_ADDR,
    SM1_MAILBOX_IN_ADDR,
    SM2_RXPDO_ADDR,
    SM3_TXPDO_ADDR,
    SYNC0_CYCLE_TIME_NS,
    ALStateTransitionError,
    CoEService,
    CoESDOAbortError,
    DistributedClocksJitterError,
    EMCYFrame,
    ESMState,
    EtherCATALStatusCode,
    EtherCATCommand,
    EtherCATDatagram,
    EtherCATFrame,
    EtherCATSlaveAdapter,
    EtherCATSlaveDiagnosticCode,
    EtherCATSlaveEngine,
    EtherCATSlaveError,
    EtherCATSlaveStatusBits,
    EtherCATSubDeviceAdapter,
    FMMUChannel,
    FMMUType,
    MailboxEnvelope,
    MailboxType,
    ProcessDataWKCError,
    SDOAbortCode,
    SDOCommand,
    SDOFrame,
    SyncManagerChannel,
    SyncManagerConfigError,
    compute_dc_jitter,
    run_ethercat_slave_verification,
    scale_process_input_to_int16,
    scale_pv_to_int16,
    verify_ethercat_slave_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provides a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def ethercat_slave(register_table: RegisterTable) -> EtherCATSlaveEngine:
    """Provides a fresh EtherCATSlaveEngine initialized with register table."""
    return EtherCATSlaveEngine(register_table=register_table)


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
# ============================================================================


class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Pure ST POU compliance, AST verification, and register bindings (%R1000..%R1007, %M233..%M234)."""

    def test_verify_ethercat_slave_pure_st_function(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_ethercat_slave_pure_st() is True

    def test_pure_st_slave_sync_pou_ast_parsing(self) -> None:
        """Parse ETHERCAT_SLAVE_SYNC_PURE_ST_POU (EtherCatSlaveSync) and assert AST attributes."""
        SecurityGuard.assert_pure_st_content(ETHERCAT_SLAVE_SYNC_PURE_ST_POU)
        res = STParser.validate_code(ETHERCAT_SLAVE_SYNC_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        parser = STParser()
        ast = parser.parse_pou(ETHERCAT_SLAVE_SYNC_PURE_ST_POU)
        assert ast is not None
        assert ast.name in ("EtherCatSlaveSync", "EtherCATSlaveSync")
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1000", "%R1001", "%R1002", "%R1003",
            "%R1004", "%R1005", "%R1006", "%R1007",
            "%M233", "%M234",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

        var_names = {v.name for v in ast.variables}
        expected_vars = {
            "AlStatusStateWord",
            "AlStatusCode",
            "SyncManagerCycleCounter",
            "RxPdoProcessDataScaled",
            "TxPdoProcessDataScaled",
            "DcSyncErrorNs",
            "CoeObjectDirectoryCounter",
            "DiagnosticStatusCode",
            "EtherCatOperationalActive",
            "EtherCatWatchdogTrip",
        }
        assert expected_vars.issubset(var_names)

    def test_pure_st_state_machine_pou_ast_parsing(self) -> None:
        """Parse ETHERCAT_SLAVE_STATE_MACHINE_PURE_ST_POU and assert AST attributes."""
        SecurityGuard.assert_pure_st_content(ETHERCAT_SLAVE_STATE_MACHINE_PURE_ST_POU)
        res = STParser.validate_code(ETHERCAT_SLAVE_STATE_MACHINE_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        parser = STParser()
        ast = parser.parse_pou(ETHERCAT_SLAVE_STATE_MACHINE_PURE_ST_POU)
        assert ast is not None
        assert ast.name in ("EtherCatSlaveSync", "EtherCatSubDeviceSync", "EtherCATSlaveStateMachine")
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1000", "%R1001", "%R1002", "%R1003",
            "%R1004", "%R1005", "%R1006", "%R1007",
            "%M233", "%M234",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

        var_names = {v.name for v in ast.variables}
        assert "EtherCatOperationalActive" in var_names
        assert "EtherCatWatchdogTrip" in var_names
        assert "DiagnosticStatusCode" in var_names

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify pure ST POUs pass SecurityGuard pure ST assertion cleanly."""
        SecurityGuard.assert_pure_st_content(ETHERCAT_SLAVE_SYNC_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(ETHERCAT_SLAVE_STATE_MACHINE_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(ETHERCAT_SLAVE_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(ETHERCAT_PURE_ST_POU)


# ============================================================================
# Section 2: Anti-Ladder Security Guard Asserting LadderForbiddenError
# ============================================================================


class TestSection2AntiLadderSecurity:
    """Tests for SecurityGuard strict rejection of ladder logic constructs."""

    @pytest.mark.parametrize(
        "sample",
        [
            "PROGRAM BadContacts\nVAR Flag: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM",
            "PROGRAM BadNegative\nVAR Flag: BOOL; END_VAR\n---[/]---\nEND_PROGRAM",
            "PROGRAM BadRung\nVAR Flag: BOOL; END_VAR\nRUNG 1: XIC %M233 OTE %M234 END_RUNG\nEND_PROGRAM",
            "PROGRAM BadCoil\nVAR Out: BOOL; END_VAR\n---(S)---\nEND_PROGRAM",
            "PROGRAM BadReset\nVAR Out: BOOL; END_VAR\n---(R)---\nEND_PROGRAM",
            "PROGRAM BadMnemonic\nVAR Out: BOOL; END_VAR\nXIO %M233\nEND_PROGRAM",
            "PROGRAM BadLatch\nVAR Out: BOOL; END_VAR\nOTL %M234\nEND_PROGRAM",
            "PROGRAM BadUnlatch\nVAR Out: BOOL; END_VAR\nOTU %M234\nEND_PROGRAM",
            "PROGRAM BadNetwork\nVAR X: BOOL; END_VAR\nNETWORK 1\nEND_PROGRAM",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, sample: str) -> None:
        """Verify embedded ladder constructs raise LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(sample)

        res = STParser.validate_code(sample)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# Section 3: AL State Machine State Transitions & Illegal Rejection
# ============================================================================


class TestSection3ALStateMachine:
    """Tests for EtherCAT State Machine (ESM) transitions and AL status codes."""

    def test_sequential_transitions_init_to_op(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify sequential transitions Init -> PreOp -> SafeOp -> Op."""
        slave = ethercat_slave
        assert slave.esm_state == ESMState.INIT

        ok, code = slave.request_state_transition(ESMState.PREOP)
        assert ok is True
        assert code == EtherCATALStatusCode.NO_ERROR
        assert slave.esm_state == ESMState.PREOP

        ok, code = slave.request_state_transition(ESMState.SAFEOP)
        assert ok is True
        assert code == EtherCATALStatusCode.NO_ERROR
        assert slave.esm_state == ESMState.SAFEOP

        ok, code = slave.request_state_transition(ESMState.OP)
        assert ok is True
        assert code == EtherCATALStatusCode.NO_ERROR
        assert slave.esm_state == ESMState.OP

    def test_valid_backward_transitions(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify backward transitions (Op -> SafeOp, Op -> PreOp, Op -> Init) always succeed."""
        slave = ethercat_slave
        slave.request_state_transition(ESMState.PREOP)
        slave.request_state_transition(ESMState.SAFEOP)
        slave.request_state_transition(ESMState.OP)
        assert slave.esm_state == ESMState.OP

        # Op -> SafeOp
        ok, code = slave.request_state_transition(ESMState.SAFEOP)
        assert ok is True
        assert code == EtherCATALStatusCode.NO_ERROR
        assert slave.esm_state == ESMState.SAFEOP

        # SafeOp -> PreOp
        ok, code = slave.request_state_transition(ESMState.PREOP)
        assert ok is True
        assert code == EtherCATALStatusCode.NO_ERROR
        assert slave.esm_state == ESMState.PREOP

        # PreOp -> Init
        ok, code = slave.request_state_transition(ESMState.INIT)
        assert ok is True
        assert code == EtherCATALStatusCode.NO_ERROR
        assert slave.esm_state == ESMState.INIT

    def test_same_state_request_noop(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify requesting the current state returns True immediately."""
        slave = ethercat_slave
        ok, code = slave.request_state_transition(ESMState.INIT)
        assert ok is True
        assert code == EtherCATALStatusCode.NO_ERROR

    def test_illegal_skip_transitions_rejection(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify illegal skip transitions are rejected with INVALID_STATE_CHANGE."""
        slave = ethercat_slave

        # Init -> Op is illegal
        ok, code = slave.request_state_transition(ESMState.OP)
        assert ok is False
        assert code == EtherCATALStatusCode.INVALID_STATE_CHANGE
        assert slave.esm_state == ESMState.INIT

        # Init -> SafeOp is illegal (must go through PreOp)
        ok, code = slave.request_state_transition(ESMState.SAFEOP)
        assert ok is False
        assert code == EtherCATALStatusCode.INVALID_STATE_CHANGE
        assert slave.esm_state == ESMState.INIT

        # PreOp -> Op is illegal (must go through SafeOp)
        slave.request_state_transition(ESMState.PREOP)
        ok, code = slave.request_state_transition(ESMState.OP)
        assert ok is False
        assert code == EtherCATALStatusCode.INVALID_STATE_CHANGE
        assert slave.esm_state == ESMState.PREOP

    def test_bootstrap_state_rejection(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify requesting BOOT state is rejected with BOOTSTRAP_NOT_SUPPORTED."""
        slave = ethercat_slave
        ok, code = slave.request_state_transition(ESMState.BOOT)
        assert ok is False
        assert code == EtherCATALStatusCode.BOOTSTRAP_NOT_SUPPORTED

    def test_unknown_state_rejection(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify requesting undefined state is rejected with UNKNOWN_STATE."""
        slave = ethercat_slave
        ok, code = slave.request_state_transition(99)  # type: ignore[arg-type]
        assert ok is False
        assert code == EtherCATALStatusCode.UNKNOWN_STATE

    def test_esm_status_word_bitmask_flags(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify %R1000 and %R1001 reflect ESM state transitions accurately."""
        slave = ethercat_slave
        rt = slave.reg_table

        # PreOp
        slave.request_state_transition(ESMState.PREOP)
        r1000 = rt.read_uword("%R1000")
        r1001 = rt.read_uword("%R1001")
        assert bool(r1000 & EtherCATSlaveStatusBits.ESM_PRE_OP) is True
        assert (r1000 & 0x0F) == ESMState.PREOP
        assert r1001 == EtherCATALStatusCode.NO_ERROR

        # SafeOp
        slave.request_state_transition(ESMState.SAFEOP)
        r1000 = rt.read_uword("%R1000")
        assert bool(r1000 & EtherCATSlaveStatusBits.ESM_SAFE_OP) is True
        assert (r1000 & 0x0F) == ESMState.SAFEOP
        assert rt.read_uword("%R1001") == EtherCATALStatusCode.NO_ERROR

        # Op
        slave.request_state_transition(ESMState.OP)
        r1000 = rt.read_uword("%R1000")
        assert bool(r1000 & EtherCATSlaveStatusBits.ESM_OPERATIONAL) is True
        assert (r1000 & 0x0F) == ESMState.OP
        assert rt.read_uword("%R1001") == EtherCATALStatusCode.NO_ERROR


# ============================================================================
# Section 4: SyncManager Channels (SM0..SM3) & CoE Object Directory
# ============================================================================


class TestSection4SyncManagerAndCoE:
    """Tests for SyncManager channels SM0..SM3 and CAN application protocol over EtherCAT SDO services."""

    def test_sync_manager_channels_configuration(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify SM0..SM3 channel addresses, lengths, control bytes, and directions."""
        slave = ethercat_slave

        sm0 = slave.read_sync_manager(0)
        assert sm0.physical_start_address == SM0_MAILBOX_OUT_ADDR  # 0x1000
        assert sm0.length == MAILBOX_BUFFER_SIZE                   # 128B
        assert sm0.is_enabled is True
        assert sm0.is_write is True

        sm1 = slave.read_sync_manager(1)
        assert sm1.physical_start_address == SM1_MAILBOX_IN_ADDR   # 0x1080
        assert sm1.length == MAILBOX_BUFFER_SIZE                   # 128B
        assert sm1.is_enabled is True
        assert sm1.is_read is True

        sm2 = slave.read_sync_manager(2)
        assert sm2.physical_start_address == SM2_RXPDO_ADDR        # 0x1100
        assert sm2.length == PROCESS_DATA_SIZE                     # 8B
        assert sm2.is_enabled is True
        assert sm2.is_write is True

        sm3 = slave.read_sync_manager(3)
        assert sm3.physical_start_address == SM3_TXPDO_ADDR        # 0x1140
        assert sm3.length == PROCESS_DATA_SIZE                     # 8B
        assert sm3.is_enabled is True
        assert sm3.is_read is True

    def test_sync_manager_serialization_roundtrip(self) -> None:
        """Verify SyncManager channel packing and unpacking roundtrip."""
        sm = SyncManagerChannel(
            index=2,
            physical_start_address=0x1100,
            length=8,
            control=0x64,
            status=0x08,
            activate=0x01,
            pdi_control=0x00,
        )
        raw = sm.serialize()
        assert len(raw) == 8
        deserialized = SyncManagerChannel.deserialize(index=2, raw=raw)
        assert deserialized.physical_start_address == 0x1100
        assert deserialized.length == 8
        assert deserialized.control == 0x64
        assert deserialized.is_full is True
        assert deserialized.is_enabled is True

    def test_sync_manager_invalid_channel_raises(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify accessing undefined SyncManager channel raises SyncManagerConfigError."""
        with pytest.raises(SyncManagerConfigError):
            ethercat_slave.read_sync_manager(7)

    def test_coe_sdo_upload_identity_objects(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify reading Identity Object 0x1018 and standard objects."""
        slave = ethercat_slave

        # Device Type 0x1000:00 -> 0x00020191 (CiA 401)
        resp_dev = slave.read_sdo(0x1000, 0x00)
        assert resp_dev.command == SDOCommand.UPLOAD_EXPEDITED_4B
        assert struct.unpack("<I", resp_dev.data[:4])[0] == 0x00020191

        # Vendor ID 0x1018:01 -> Horner APG 0x00000059
        resp_vendor = slave.read_sdo(0x1018, 0x01)
        assert resp_vendor.command == SDOCommand.UPLOAD_EXPEDITED_4B
        vendor_id = struct.unpack("<I", resp_vendor.data[:4])[0]
        assert vendor_id == ETHERCAT_VENDOR_ID_HORNER

        # Product Code 0x1018:02 -> 0x00000139
        resp_prod = slave.read_sdo(0x1018, 0x02)
        assert struct.unpack("<I", resp_prod.data[:4])[0] == ETHERCAT_PRODUCT_CODE_W139

        # Revision 0x1018:03 -> 0x00010001
        resp_rev = slave.read_sdo(0x1018, 0x03)
        assert struct.unpack("<I", resp_rev.data[:4])[0] == ETHERCAT_REVISION_W139

        # Serial 0x1018:04 -> 0x00139001
        resp_ser = slave.read_sdo(0x1018, 0x04)
        assert struct.unpack("<I", resp_ser.data[:4])[0] == ETHERCAT_SERIAL_DEFAULT

    def test_coe_sdo_download_and_register_update(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify SDO download writes object 0x6000:01 and updates Horner register %R1003."""
        slave = ethercat_slave
        resp = slave.write_sdo(0x6000, 0x01, 0x55AA)
        assert resp.command == SDOCommand.DOWNLOAD_RESPONSE
        assert slave.reg_table.read_word("%R1003") == 0x55AA

        resp2 = slave.write_sdo(0x6000, 0x02, 0x33CC)
        assert resp2.command == SDOCommand.DOWNLOAD_RESPONSE
        assert slave.od[(0x6000, 0x02)].value == 0x33CC

    def test_coe_sdo_abort_traps(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify SDO abort codes for non-existent objects, subindices, and read-only access."""
        slave = ethercat_slave

        # Object does not exist
        resp = slave.read_sdo(0x8888, 0x00)
        assert resp.command == SDOCommand.ABORT_TRANSFER
        abort_code = struct.unpack("<I", resp.data[:4])[0]
        assert abort_code == SDOAbortCode.OBJECT_NOT_EXIST

        # Subindex does not exist
        resp_sub = slave.read_sdo(0x1018, 0x99)
        assert resp_sub.command == SDOCommand.ABORT_TRANSFER
        abort_sub = struct.unpack("<I", resp_sub.data[:4])[0]
        assert abort_sub == SDOAbortCode.SUBINDEX_NOT_EXIST

        # Write to read-only object
        req_ro = SDOFrame(command=SDOCommand.DOWNLOAD_EXPEDITED_4B, index=0x1018, subindex=0x01, data=b"\x00" * 4)
        resp_ro = slave.handle_sdo_request(req_ro)
        assert resp_ro.command == SDOCommand.ABORT_TRANSFER
        abort_ro = struct.unpack("<I", resp_ro.data[:4])[0]
        assert abort_ro == SDOAbortCode.UNSUPPORTED_ACCESS

    def test_emcy_message_framing_and_sm1_buffering(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify Emergency message framing and placement in SM1 RAM buffer."""
        slave = ethercat_slave
        dg = slave.emit_emcy(error_code=0x8210, error_register=0x11, error_data=b"\x01\x02\x03\x04\x05")
        assert dg.cmd == EtherCATCommand.FPRD
        assert dg.wkc == 1
        assert slave.sync_managers[1].is_full is True

    def test_mailbox_envelope_serialization_roundtrip(self) -> None:
        """Verify MailboxEnvelope serialization and deserialization."""
        env = MailboxEnvelope(
            length=8,
            address=0x1000,
            channel=0,
            priority=0,
            mbx_type=MailboxType.COE,
            counter=2,
            payload=b"\x12\x34\x56\x78\x9A\xBC\xDE\xF0",
        )
        raw = env.serialize()
        deserialized = MailboxEnvelope.deserialize(raw)
        assert deserialized.length == 8
        assert deserialized.address == 0x1000
        assert deserialized.mbx_type == MailboxType.COE
        assert deserialized.counter == 2
        assert deserialized.payload == env.payload


# ============================================================================
# Section 5: Distributed Clocks (DC) Sync0 Sub-Microsecond Synchronization
# ============================================================================


class TestSection5DistributedClocks:
    """Tests for Distributed Clocks (DC) Sync0 sub-microsecond synchronization and jitter tracking (< 100 ns)."""

    def test_timing_constants(self) -> None:
        """Verify DC jitter threshold and nominal Sync0 cycle constants."""
        assert DC_JITTER_THRESHOLD_NS == 100
        assert ETHERCAT_DC_JITTER_THRESHOLD_NS == 100
        assert DC_SYNC0_DEFAULT_CYCLE_NS == 1_000_000
        assert SYNC0_CYCLE_TIME_NS == 1_000_000

    def test_dc_system_time_sync(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify DC system time calculation with propagation delay compensation."""
        slave = ethercat_slave
        sys_time = slave.sync_dc_system_time(master_time_ns=10_000_000_000, propagation_delay_ns=150)
        assert sys_time == 10_000_000_150
        assert slave.dc_enabled is True
        slave.sync_to_registers()
        status = slave.reg_table.read_uword("%R1000")
        assert bool(status & EtherCATSlaveStatusBits.DC_SYNC_LOCKED) is True

    def test_sync0_cyclic_event_generation(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify Sync0 next event calculation on 1 ms boundary."""
        slave = ethercat_slave
        slave.dc_system_time_ns = 5_432_100_000
        ev = slave.generate_sync0_event(cycle_time_ns=1_000_000)
        assert ev["cycle_time_ns"] == 1_000_000
        assert ev["next_sync0_timestamp_ns"] == 5_433_000_000

    def test_dc_jitter_within_100ns_threshold(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify clock jitter < 100 ns asserts JITTER_OK and does not trip safety."""
        slave = ethercat_slave
        jitter, ok = slave.evaluate_dc_jitter(
            arrival_timestamp_ns=10_000_000_045,
            expected_timestamp_ns=10_000_000_000,
        )
        assert jitter == 45
        assert ok is True
        assert slave.reg_table.read_word("%R1005") == 45

        status = slave.reg_table.read_uword("%R1000")
        assert bool(status & EtherCATSlaveStatusBits.JITTER_OK) is True
        assert bool(status & EtherCATSlaveStatusBits.JITTER_WARNING) is False
        assert slave.is_safety_tripped is False

    def test_dc_jitter_breach_100ns_threshold_trips(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify clock jitter >= 100 ns asserts JITTER_WARNING and triggers safety trip 0xA403."""
        slave = ethercat_slave
        jitter, ok = slave.evaluate_dc_jitter(
            arrival_timestamp_ns=10_000_000_125,
            expected_timestamp_ns=10_000_000_000,
        )
        assert jitter == 125
        assert ok is False
        assert slave.reg_table.read_word("%R1005") == 125

        status = slave.reg_table.read_uword("%R1000")
        assert bool(status & EtherCATSlaveStatusBits.JITTER_WARNING) is True
        assert slave.is_safety_tripped is True
        assert slave.reg_table.read_uword("%R1007") == 0xA403
        assert slave.reg_table.read_bit("%M234") is True
        assert slave.reg_table.read_bit("%M233") is False

    def test_dc_jitter_tracking_history_and_statistics(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify jitter tracking across multiple cycles and helper function."""
        slave = ethercat_slave
        expected_base = 20_000_000_000
        delays = [15, 30, 45, 20, 60]

        for i, d in enumerate(delays):
            exp = expected_base + (i * 1_000_000)
            arr = exp + d
            j = compute_dc_jitter(arr, exp)
            assert j == d
            slave.evaluate_dc_jitter(arr, exp)

        assert len(slave.jitter_history) == 5
        assert min(slave.jitter_history) == 15
        assert max(slave.jitter_history) == 60
        assert math.isclose(sum(slave.jitter_history) / len(slave.jitter_history), 34.0)


# ============================================================================
# Section 6: Process Safety Trips (0xA401..0xA404) & Horner Coils (%M233, %M234)
# ============================================================================


class TestSection6ProcessSafetyTrips:
    """Tests for safety trips 0xA401..0xA404 asserting %M233/%M234 and diagnostic codes."""

    def test_diagnostic_code_values(self) -> None:
        """Verify diagnostic enumeration values and aliases match Work Package W139 specification."""
        assert int(EtherCATSlaveDiagnosticCode.OK) == 0x0000
        assert int(EtherCATSlaveDiagnosticCode.ECAT_ERR_SM_WATCHDOG) == 0xA401
        assert int(EtherCATSlaveDiagnosticCode.ECAT_ERR_INVALID_TRANSITION) == 0xA402
        assert int(EtherCATSlaveDiagnosticCode.ECAT_ERR_DC_SYNC_LOSS) == 0xA403
        assert int(EtherCATSlaveDiagnosticCode.ECAT_ERR_SDO_ABORT) == 0xA404

        # Aliases
        assert int(EtherCATSlaveDiagnosticCode.ECAT_ERR_SM_WATCHDOG_TRIP) == 0xA401
        assert int(EtherCATSlaveDiagnosticCode.ECAT_ERR_INVALID_TRANSITION_TRIP) == 0xA402
        assert int(EtherCATSlaveDiagnosticCode.ECAT_ERR_DC_JITTER_EXCESSIVE) == 0xA403
        assert int(EtherCATSlaveDiagnosticCode.ECAT_ERR_DC_JITTER_TRIP) == 0xA403
        assert int(EtherCATSlaveDiagnosticCode.ECAT_ERR_COE_SDO_ABORT) == 0xA404
        assert int(EtherCATSlaveDiagnosticCode.ECAT_ERR_SDO_ABORT_TRIP) == 0xA404

    def test_trip_0xa401_sync_manager_watchdog(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """0xA401 SyncManager watchdog trip clears %M233, asserts %M234, and sets %R1007."""
        slave = ethercat_slave
        slave.request_state_transition(ESMState.PREOP)
        slave.request_state_transition(ESMState.SAFEOP)
        slave.request_state_transition(ESMState.OP)
        assert slave.reg_table.read_bit("%M233") is True
        assert slave.reg_table.read_bit("%M234") is False

        slave.trigger_safety_trip(EtherCATSlaveDiagnosticCode.ECAT_ERR_SM_WATCHDOG)
        assert slave.reg_table.read_bit("%M234") is True
        assert slave.reg_table.read_bit("%M233") is False
        assert slave.reg_table.read_uword("%R1007") == 0xA401
        assert slave.watchdog_tripped is True

        status = slave.reg_table.read_uword("%R1000")
        assert bool(status & EtherCATSlaveStatusBits.WATCHDOG_TRIP) is True
        assert bool(status & EtherCATSlaveStatusBits.SAFETY_TRIP) is True

    def test_trip_0xa402_invalid_transition(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """0xA402 Invalid transition trip asserts %M234 and sets %R1007."""
        slave = ethercat_slave
        slave.trigger_safety_trip(EtherCATSlaveDiagnosticCode.ECAT_ERR_INVALID_TRANSITION)
        assert slave.reg_table.read_bit("%M234") is True
        assert slave.reg_table.read_bit("%M233") is False
        assert slave.reg_table.read_uword("%R1007") == 0xA402
        assert slave.is_safety_tripped is True

    def test_trip_0xa403_dc_sync_loss(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """0xA403 DC sync loss trip asserts %M234 and sets %R1007."""
        slave = ethercat_slave
        slave.trigger_safety_trip(EtherCATSlaveDiagnosticCode.ECAT_ERR_DC_SYNC_LOSS)
        assert slave.reg_table.read_bit("%M234") is True
        assert slave.reg_table.read_bit("%M233") is False
        assert slave.reg_table.read_uword("%R1007") == 0xA403

    def test_trip_0xa404_coe_sdo_abort(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """0xA404 CoE SDO abort fault asserts %M234 and sets %R1007."""
        slave = ethercat_slave
        slave.trigger_safety_trip(EtherCATSlaveDiagnosticCode.ECAT_ERR_SDO_ABORT)
        assert slave.reg_table.read_bit("%M234") is True
        assert slave.reg_table.read_bit("%M233") is False
        assert slave.reg_table.read_uword("%R1007") == 0xA404

    def test_reset_safety_and_fault_recovery(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify reset_safety clears alarms and restores healthy coils %M233=True, %M234=False."""
        slave = ethercat_slave
        slave.request_state_transition(ESMState.PREOP)
        slave.request_state_transition(ESMState.SAFEOP)
        slave.request_state_transition(ESMState.OP)
        assert slave.reg_table.read_bit("%M233") is True
        assert slave.reg_table.read_bit("%M234") is False

        slave.trigger_safety_trip(EtherCATSlaveDiagnosticCode.ECAT_ERR_SM_WATCHDOG)
        assert slave.reg_table.read_bit("%M234") is True
        assert slave.reg_table.read_bit("%M233") is False

        slave.reset_safety()
        slave.request_state_transition(ESMState.SAFEOP)
        slave.request_state_transition(ESMState.OP)
        assert slave.diagnostic_code == EtherCATSlaveDiagnosticCode.OK
        assert slave.reg_table.read_uword("%R1007") == 0x0000
        assert slave.reg_table.read_bit("%M233") is True
        assert slave.reg_table.read_bit("%M234") is False
        assert slave.is_safety_tripped is False

        # Verify alias reset_fault() works identically
        slave.trigger_safety_trip(EtherCATSlaveDiagnosticCode.ECAT_ERR_DC_SYNC_LOSS)
        slave.reset_fault()
        slave.request_state_transition(ESMState.SAFEOP)
        slave.request_state_transition(ESMState.OP)
        assert slave.reg_table.read_bit("%M233") is True
        assert slave.reg_table.read_bit("%M234") is False


# ============================================================================
# Section 7: Horner OCS Register Space Synchronization (%R1000..%R1007)
# ============================================================================


class TestSection7HornerOCSMemoryIntegration:
    """Tests for Horner OCS register space synchronization (%R1000..%R1007, %M233..%M234)."""

    def test_cyclic_register_sync_in_op_state(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify registers %R1000..%R1007 after a healthy scan cycle in OP state."""
        slave = ethercat_slave
        slave.request_state_transition(ESMState.PREOP)
        slave.request_state_transition(ESMState.SAFEOP)
        slave.request_state_transition(ESMState.OP)

        res = slave.step_scan_cycle(rx_word0=1234, rx_word1=5678)
        assert res["esm_state"] == "OP"
        assert res["cycle"] == 1

        rt = slave.reg_table
        r1000 = rt.read_uword("%R1000")
        r1001 = rt.read_uword("%R1001")
        r1002 = rt.read_uword("%R1002")
        r1003 = rt.read_word("%R1003")
        r1004 = rt.read_word("%R1004")
        r1005 = rt.read_word("%R1005")
        r1006 = rt.read_uword("%R1006")
        r1007 = rt.read_uword("%R1007")
        m233 = rt.read_bit("%M233")
        m234 = rt.read_bit("%M234")

        assert bool(r1000 & EtherCATSlaveStatusBits.SLAVE_ACTIVE) is True
        assert bool(r1000 & EtherCATSlaveStatusBits.ESM_OPERATIONAL) is True
        assert (r1000 & 0x0F) == ESMState.OP
        assert r1001 == EtherCATALStatusCode.NO_ERROR
        assert r1002 == 1
        assert r1003 == 1234
        assert r1004 == 1234
        assert r1007 == 0x0000
        assert m233 is True
        assert m234 is False

    def test_engineering_unit_scaling_helper(self) -> None:
        """Verify scale_pv_to_int16 scaling and clamping to INT16 boundaries."""
        assert scale_pv_to_int16(125.4, scale_factor=10.0) == 1254
        assert scale_pv_to_int16(-45.2, scale_factor=10.0) == -452
        assert scale_pv_to_int16(5000.0, scale_factor=10.0) == 32767   # Clamped max
        assert scale_pv_to_int16(-5000.0, scale_factor=10.0) == -32768  # Clamped min
        assert scale_process_input_to_int16(20.0) == 200

    def test_fmmu_cyclic_lrw_process_data_exchange(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify cyclic LRW datagram yields WKC increment +3 and updates %R1003..%R1004."""
        slave = ethercat_slave
        slave.request_state_transition(ESMState.PREOP)
        slave.request_state_transition(ESMState.SAFEOP)
        slave.request_state_transition(ESMState.OP)

        slave.reg_table.write_word("%R1005", 0x7777, privilege=PrivilegeMode.SYSTEM)

        # Construct LRW datagram covering FMMU0 (0x00010000) and FMMU1 (0x00010008)
        lrw_data = struct.pack("<HH4x8x", 0x1111, 0x2222)
        dg = EtherCATDatagram(
            cmd=EtherCATCommand.LRW,
            index=1,
            address=0x00010000,
            data=lrw_data,
            wkc=0,
        )
        resp = slave.process_datagram(dg)
        assert resp.wkc == 3
        assert slave.reg_table.read_word("%R1003") == 0x1111
        assert slave.reg_table.read_word("%R1004") == 0x1111  # Mirrored to TxPDO in OP state
        assert slave.od[(0x6000, 0x02)].value == 0x2222

    def test_slave_disable_state(self, ethercat_slave: EtherCATSlaveEngine) -> None:
        """Verify clearing %M233 clears OPERATIONAL_ACTIVE in %R1000."""
        slave = ethercat_slave
        slave.request_state_transition(ESMState.PREOP)
        slave.request_state_transition(ESMState.SAFEOP)
        slave.request_state_transition(ESMState.OP)
        assert bool(slave.reg_table.read_uword("%R1000") & EtherCATSlaveStatusBits.OPERATIONAL_ACTIVE) is True

        slave.reg_table.write_bit("%M233", False, privilege=PrivilegeMode.SYSTEM)
        slave.sync_to_registers()
        assert bool(slave.reg_table.read_uword("%R1000") & EtherCATSlaveStatusBits.OPERATIONAL_ACTIVE) is False


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration & Evidence Persistence
# ============================================================================


class TestSection8VerificationSuiteIntegration:
    """Tests for the complete 9-stage verification suite and evidence persistence."""

    def test_run_ethercat_slave_verification_success(self) -> None:
        """Verify the 9-stage verification returns a clean SUCCESS status."""
        result = run_ethercat_slave_verification()
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["checks_passed"] == 9
        assert result["data"]["total_checks"] == 9
        assert len(result["data"]["tests"]) == 9
        for t in result["data"]["tests"]:
            assert t["passed"] is True

    def test_run_ethercat_slave_verification_writes_evidence(self, tmp_path: Path) -> None:
        """Verify verification writes valid JSON evidence matching contract schema."""
        evidence_file = tmp_path / "ethercat_slave_evidence.json"
        result = run_ethercat_slave_verification(evidence_path=str(evidence_file))

        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W139"
        assert data["data"]["gate"] == "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation"
        assert "Industrial EtherCAT SubDevice" in data["data"]["component"]
        assert data["data"]["checks_passed"] == 9
        assert len(data["data"]["tests"]) == 9
        assert data["data"]["register_map"]["%R1000"] == "AlStatusStateWord"
        assert data["data"]["register_map"]["status_word"] == "%R1000"
        assert data["data"]["register_map"]["state_word"] == "%R1001"
        assert data["data"]["register_map"]["cycle_counter"] == "%R1002"
        assert data["data"]["register_map"]["rx_pdo_0"] == "%R1003"
        assert data["data"]["register_map"]["tx_pdo_0"] == "%R1004"
        assert data["data"]["register_map"]["dc_jitter_ns"] == "%R1005"
        assert data["data"]["register_map"]["diagnostic_status_code"] == "%R1007"
        assert data["data"]["register_map"]["slave_active"] == "%M233"
        assert data["data"]["register_map"]["safety_trip"] == "%M234"

    def test_evidence_metrics_schema(self) -> None:
        """Verify evidence metrics dictionary has all expected fields."""
        result = run_ethercat_slave_verification()
        metrics = result["data"]["metrics"]
        assert metrics["dc_jitter_threshold_ns"] == 100
        assert metrics["sync0_cycle_ns"] == 1_000_000
        assert metrics["sync_manager_channels"] == 4
        assert metrics["sm0_mailbox_out_address"] == 0x1000
        assert metrics["sm1_mailbox_in_address"] == 0x1080
        assert metrics["sm2_rx_pdo_address"] == 0x1100
        assert metrics["sm3_tx_pdo_address"] == 0x1140
