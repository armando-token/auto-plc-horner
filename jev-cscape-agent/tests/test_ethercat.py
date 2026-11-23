"""Unit tests for Industrial EtherCAT SubDevice Protocol Telemetry Adapter.

Work Package: W088 (Gate G8 Telemetry Protocols & Scaling Bridge / Gate G4 Simulation)
Classification: PRODUCTION_READY
"""

import struct
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.ethercat import (
    ESMState,
    EtherCATALStatusCode,
    EtherCATCommand,
    EtherCATDatagram,
    EtherCATFrame,
    EtherCATStatusBits,
    EtherCATSubDeviceAdapter,
    ETHERCAT_PURE_ST_POU,
    FMMUChannel,
    FMMUType,
    MailboxEnvelope,
    MailboxType,
    SDOAbortCode,
    SDOCommand,
    SDOFrame,
    SyncManagerChannel,
    run_ethercat_verification,
)


class TestEtherCATPureST:
    """Tests for IEC 61131-3 Pure ST POU compliance and anti-ladder security."""

    def test_pure_st_security_guard(self) -> None:
        """Verify Pure ST POU passes security guard assertion."""
        SecurityGuard.assert_pure_st_content(ETHERCAT_PURE_ST_POU)

    def test_ladder_constructs_rejected(self) -> None:
        """Verify ladder contacts, coils, and rungs trigger LadderForbiddenError."""
        ladder_snippets = [
            ETHERCAT_PURE_ST_POU + "\n---[ ]---",
            ETHERCAT_PURE_ST_POU + "\n---( )---",
            ETHERCAT_PURE_ST_POU + "\nRUNG 1",
            ETHERCAT_PURE_ST_POU + "\nNETWORK 1",
            ETHERCAT_PURE_ST_POU + "\nXIC MyBit",
        ]
        for snip in ladder_snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snip)

    def test_st_parser_validation_and_ast(self) -> None:
        """Verify ST parser validates syntax and extracts AST properly."""
        val = STParser.validate_code(ETHERCAT_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(ETHERCAT_PURE_ST_POU)
        assert ast.name == "EtherCATSubDeviceAdapter"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {"%R490", "%R491", "%R492", "%R493", "%R494", "%R495", "%M114", "%M115"}
        for reg in expected_regs:
            assert reg in ast.bound_registers


class TestEtherCATDatagramsAndFrames:
    """Tests for frame serialization, datagram codecs, and WKC."""

    def test_datagram_serialization_deserialization(self) -> None:
        """Verify EtherCAT datagram packing and unpacking roundtrip."""
        dg = EtherCATDatagram(
            cmd=EtherCATCommand.FPWR,
            index=1,
            address=0x10001000,
            data=b"\x01\x02\x03\x04",
            wkc=0,
        )
        raw = dg.serialize()
        unpacked = EtherCATDatagram.deserialize(raw)
        assert unpacked.cmd == EtherCATCommand.FPWR
        assert unpacked.index == 1
        assert unpacked.address == 0x10001000
        assert unpacked.data == b"\x01\x02\x03\x04"
        assert unpacked.wkc == 0

    def test_ethercat_frame_packing(self) -> None:
        """Verify complete Ethernet II encapsulation with EtherType 0x88A4."""
        dg = EtherCATDatagram(
            cmd=EtherCATCommand.BRD,
            index=2,
            address=0x00000000,
            data=b"\x00\x00",
            wkc=1,
        )
        frame = EtherCATFrame(datagrams=[dg])
        raw_frame = frame.serialize()
        assert len(raw_frame) >= 14 + 2 + 10 + 2 + 2
        assert raw_frame[12:14] == b"\x88\xA4"  # EtherType 0x88A4


class TestEtherCATESMStateMachine:
    """Tests for EtherCAT State Machine transitions and AL status codes."""

    def test_valid_sequential_transitions(self) -> None:
        """Verify sequential transitions Init -> PreOp -> SafeOp -> Op."""
        adapter = EtherCATSubDeviceAdapter()
        assert adapter.esm_state == ESMState.INIT

        ok, code = adapter.request_state_transition(ESMState.PREOP)
        assert ok and code == EtherCATALStatusCode.NO_ERROR
        assert adapter.esm_state == ESMState.PREOP

        ok, code = adapter.request_state_transition(ESMState.SAFEOP)
        assert ok and code == EtherCATALStatusCode.NO_ERROR
        assert adapter.esm_state == ESMState.SAFEOP

        ok, code = adapter.request_state_transition(ESMState.OP)
        assert ok and code == EtherCATALStatusCode.NO_ERROR
        assert adapter.esm_state == ESMState.OP

    def test_illegal_skip_transitions(self) -> None:
        """Verify illegal transitions are rejected with INVALID_STATE_CHANGE."""
        adapter = EtherCATSubDeviceAdapter()
        # Init -> Op is illegal
        ok, code = adapter.request_state_transition(ESMState.OP)
        assert not ok
        assert code == EtherCATALStatusCode.INVALID_STATE_CHANGE
        assert adapter.esm_state == ESMState.INIT

        # PreOp -> Op is illegal
        adapter.request_state_transition(ESMState.PREOP)
        ok, code = adapter.request_state_transition(ESMState.OP)
        assert not ok
        assert code == EtherCATALStatusCode.INVALID_STATE_CHANGE

    def test_bootstrap_unsupported_rejection(self) -> None:
        """Verify requesting BOOT state is rejected with BOOTSTRAP_NOT_SUPPORTED."""
        adapter = EtherCATSubDeviceAdapter()
        ok, code = adapter.request_state_transition(ESMState.BOOT)
        assert not ok
        assert code == EtherCATALStatusCode.BOOTSTRAP_NOT_SUPPORTED


class TestEtherCATCoESDO:
    """Tests for CAN application protocol over EtherCAT SDO services."""

    def test_sdo_upload_horner_vendor_id(self) -> None:
        """Verify reading Identity Object 0x1018:01 returns Vendor ID 0x00000059."""
        adapter = EtherCATSubDeviceAdapter()
        req = SDOFrame(command=SDOCommand.UPLOAD_REQUEST, index=0x1018, subindex=0x01)
        resp = adapter.handle_sdo_request(req)
        assert resp.command == SDOCommand.UPLOAD_EXPEDITED_4B
        assert resp.index == 0x1018
        assert resp.subindex == 0x01
        vendor_id = struct.unpack("<I", resp.data[:4])[0]
        assert vendor_id == 0x00000059  # Horner APG Vendor ID

    def test_sdo_download_and_register_update(self) -> None:
        """Verify SDO download writes object 0x6000:01 and updates %R492."""
        reg_table = RegisterTable()
        adapter = EtherCATSubDeviceAdapter(register_table=reg_table)
        req = SDOFrame(
            command=SDOCommand.DOWNLOAD_EXPEDITED_2B,
            index=0x6000,
            subindex=0x01,
            data=struct.pack("<H2x", 0x4321),
        )
        resp = adapter.handle_sdo_request(req)
        assert resp.command == SDOCommand.DOWNLOAD_RESPONSE
        assert reg_table.read_word("%R492") == 0x4321

    def test_sdo_abort_non_existent_object(self) -> None:
        """Verify accessing undefined object returns SDO Abort 0x06020000."""
        adapter = EtherCATSubDeviceAdapter()
        req = SDOFrame(command=SDOCommand.UPLOAD_REQUEST, index=0x8888, subindex=0x00)
        resp = adapter.handle_sdo_request(req)
        assert resp.command == SDOCommand.ABORT_TRANSFER
        abort_code = struct.unpack("<I", resp.data[:4])[0]
        assert abort_code == SDOAbortCode.OBJECT_NOT_EXIST

    def test_emcy_message_generation(self) -> None:
        """Verify emergency message is generated and placed in SM1 RAM."""
        adapter = EtherCATSubDeviceAdapter()
        dg = adapter.emit_emcy(error_code=0x8210, error_register=0x11)
        assert dg.cmd == EtherCATCommand.FPRD
        assert dg.wkc == 1
        assert adapter.sync_managers[1].is_full


class TestEtherCATFMMUProcessData:
    """Tests for FMMU logical mapping and cyclic process data exchange."""

    def test_cyclic_lrw_exchange_wkc_increment(self) -> None:
        """Verify combined LRW datagram yields WKC increment +3."""
        reg_table = RegisterTable()
        adapter = EtherCATSubDeviceAdapter(register_table=reg_table)
        adapter.request_state_transition(ESMState.PREOP)
        adapter.request_state_transition(ESMState.SAFEOP)
        adapter.request_state_transition(ESMState.OP)

        reg_table.write_word("%R494", 0x1111, privilege=PrivilegeMode.SYSTEM)
        reg_table.write_word("%R495", 0x2222, privilege=PrivilegeMode.SYSTEM)

        # LRW write 0x3333, 0x4444 to FMMU0, read from FMMU1
        lrw_data = struct.pack("<HH4x8x", 0x3333, 0x4444)
        dg = EtherCATDatagram(
            cmd=EtherCATCommand.LRW,
            index=10,
            address=0x00010000,
            data=lrw_data,
            wkc=0,
        )
        resp = adapter.process_datagram(dg)
        assert resp.wkc == 3
        assert reg_table.read_word("%R492") == 0x3333
        assert reg_table.read_word("%R493") == 0x4444

        # Verify TxPDO was copied into output data
        tx_w1, tx_w2 = struct.unpack("<HH", resp.data[8:12])
        assert tx_w1 == 0x1111
        assert tx_w2 == 0x2222


class TestEtherCATDistributedClocks:
    """Tests for Distributed Clocks (DC) jitter surveillance."""

    def test_dc_jitter_within_threshold(self) -> None:
        """Verify clock jitter < 1000 ns asserts JITTER_OK."""
        adapter = EtherCATSubDeviceAdapter()
        jitter, ok = adapter.evaluate_dc_jitter(10_000_000_250, 10_000_000_000)
        assert jitter == 250
        assert ok
        status = adapter.registers.read_word("%R490")
        assert status & EtherCATStatusBits.JITTER_OK
        assert not (status & EtherCATStatusBits.JITTER_WARNING)

    def test_dc_jitter_breach_threshold(self) -> None:
        """Verify clock jitter >= 1000 ns asserts JITTER_WARNING."""
        adapter = EtherCATSubDeviceAdapter()
        jitter, ok = adapter.evaluate_dc_jitter(10_000_001_500, 10_000_000_000)
        assert jitter == 1500
        assert not ok
        status = adapter.registers.read_word("%R490")
        assert status & EtherCATStatusBits.JITTER_WARNING
        assert adapter.alarm_latched


class TestEtherCATRegisterSyncAndReset:
    """Tests for Horner register synchronization and fault reset handshake."""

    def test_engine_disable_state(self) -> None:
        """Verify clearing %M114 zeroes %R490."""
        reg_table = RegisterTable()
        adapter = EtherCATSubDeviceAdapter(register_table=reg_table)
        reg_table.write_bit("%M114", False, privilege=PrivilegeMode.SYSTEM)
        adapter.sync_to_registers()
        assert reg_table.read_word("%R490") == 0

    def test_fault_reset_handshake(self) -> None:
        """Verify pulsing %M115 clears latched fault and auto-clears coil."""
        reg_table = RegisterTable()
        adapter = EtherCATSubDeviceAdapter(register_table=reg_table)

        # Trigger alarm
        adapter.evaluate_dc_jitter(10_000_002_000, 10_000_000_000)
        assert reg_table.read_word("%R490") & EtherCATStatusBits.JITTER_WARNING

        # Pulse reset coil %M115
        reg_table.write_bit("%M115", True, privilege=PrivilegeMode.SYSTEM)
        adapter.sync_to_registers()

        assert not reg_table.read_bit("%M115")
        assert not (reg_table.read_word("%R490") & EtherCATStatusBits.JITTER_WARNING)


class TestEtherCATVerificationRunner:
    """Tests for full 9-stage verification runner."""

    def test_verification_runner_passes(self, tmp_path) -> None:
        """Verify run_ethercat_verification passes all 9 stages."""
        ev_file = tmp_path / "ethercat_evidence.json"
        evidence = run_ethercat_verification(str(ev_file))
        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert evidence["data"]["checks_passed"] == 9
        assert evidence["data"]["total_checks"] == 9
        assert ev_file.exists()
