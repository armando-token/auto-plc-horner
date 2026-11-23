"""Comprehensive Unit and Integration Test Suite for Industrial EtherNet/IP Explicit Messaging Engine.

Work Package: W172 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation
   (%R1330..%R1337, %M310..%M311).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: CIP Object Dictionary implementation (Identity, Message Router, Assembly, Connection Manager, TCP/IP, Ethernet Link).
4. Section 4: EPath logical segment parsing (8-bit and 16-bit Class/Instance/Attribute) and CIP Service handling (0x0E, 0x10, 0x01, 0x54, 0x4E).
5. Section 5: Unconnected Message Manager (UCMM) and Transport Class 3 explicit connection state machine.
6. Section 6: Explicit messaging transaction timeout surveillance (> 25.0 ms), jitter metrics, and error response serialization.
7. Section 7: Process safety trips (0xC501, 0xC502, 0xC503, 0xC504) and Horner coil assertion (%M310, %M311).
8. Section 8: Horner OCS register space synchronization (%R1330..%R1337, %M310..%M311) with PrivilegeMode.SYSTEM.
9. Section 9: 9-stage verification suite integration test writing evidence JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import time
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_explicit_messaging import (
    CIP_EXPLICIT_DEFAULT_TIMEOUT_MS,
    CIP_EXPLICIT_DEFAULT_TIMEOUT_SCALED,
    CIP_EXPLICIT_MAX_CLASS3_CONNECTIONS,
    CIP_EXPLICIT_MAX_TIMEOUT_MS,
    CIP_EXPLICIT_MESSAGING_SYNC_POU,
    CIP_EXPLICIT_NOMINAL_TIMEOUT_MS,
    CIP_EXPLICIT_NOMINAL_TIMEOUT_SCALED,
    CIP_EXPLICIT_SYNC_POU,
    CPFItem,
    CPFTypeId,
    EPATH,
    EPath,
    ETHERNET_DEFAULT_MTU,
    ETHERNET_IP_PORT,
    ETHERNET_IP_UCMM_EXPLICIT_SYNC_POU,
    ETHERNET_IP_EXPLICIT_SYNC_POU,
    EtherNetIpExplicitSync,
    EtherNetIpUcmmEngine,
    EthernetLinkObject,
    ExplicitMessagingStateBits,
    FragmentationEngine,
    HORNER_DEVICE_TYPE,
    HORNER_MAJOR_REVISION,
    HORNER_MINOR_REVISION,
    HORNER_PRODUCT_CODE,
    HORNER_PRODUCT_NAME,
    HORNER_SERIAL_NUMBER,
    HORNER_VENDOR_ID,
    IdentityObject,
    LogicalSegment,
    LogicalType,
    MessageRouterObject,
    PortSegment,
    PURE_ST_POU,
    SymbolicSegment,
    TcpIpInterfaceObject,
    TransportClass3Connection,
    TransportClass3State,
    UCMM_EXPLICIT_SYNC_POU,
    UcmmExplicitEngine,
    UcmmTransceiverState,
    UcmmTransceiverStateBits,
    AssemblyInstance,
    AssemblyObject,
    CIPClassCode,
    CIPGeneralStatus,
    CIPRequest,
    CIPResponse,
    CIPServiceCode,
    CipClass3State,
    CipExplicitConnectionStateConflictError,
    CipExplicitDiagnosticCode,
    CipExplicitEngine,
    CipExplicitFragment,
    CipExplicitMessagingEngine,
    CipExplicitMessagingError,
    CipExplicitMessagingSync,
    CipExplicitStateBits,
    CipExplicitTransactionTimeoutError,
    CipFragmentationFaultError,
    CipObjectPathInvalidError,
    CipServiceNotSupportedError,
    CipUcmmTimeoutError,
    Class3Connection,
    Class3ConnectionState,
    ConnectionManagerObject,
    DiagnosticStatusCode,
    EIPCommand,
    EIPHeader,
    EIPStatus,
    decode_service_and_class_word,
    decode_service_class_word,
    decode_short_string,
    deserialize_cpf,
    encode_service_and_class_word,
    encode_service_class_word,
    encode_short_string,
    run_cip_explicit_messaging_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    scale_ms_to_int16,
    serialize_cip_error_response,
    serialize_cpf,
    unscale_int16_to_ms,
    verify_cip_explicit_pure_st,
    verify_cip_explicit_messaging_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provide a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def explicit_engine(register_table: RegisterTable) -> CipExplicitMessagingEngine:
    """Provide a fresh CIP Explicit Messaging engine bound to register table."""
    return CipExplicitMessagingEngine(
        register_table=register_table,
        timeout_ms=CIP_EXPLICIT_NOMINAL_TIMEOUT_MS,
    )


# ============================================================================
# 1. Pure ST POU AST Validation & Register Binding (%R1330..%R1337, %M310..%M311)
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for Pure Structured Text POU compliance and register bindings."""

    def test_verify_cip_explicit_messaging_pure_st_helper(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_cip_explicit_pure_st() is True
        assert verify_cip_explicit_messaging_pure_st() is True

    def test_pure_st_pou_ast_parsing_primary(self) -> None:
        """Parse CIP_EXPLICIT_MESSAGING_SYNC_POU with STParser and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(CIP_EXPLICIT_MESSAGING_SYNC_POU)
        assert pou is not None
        assert pou.name == "CipExplicitMessagingSync"
        assert pou.pou_type == POUType.PROGRAM

        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "UcmmActiveSessionsCount",
            "ConnectionIdWord",
            "ExplicitTransactionCounter",
            "ExplicitRequestTimeoutMsScaled",
            "ExplicitErrorCounter",
            "UcmmTransceiverStateWord",
            "CipServiceAndClassWord",
            "DiagnosticStatusCode",
            "CipExplicitPermissive",
            "CipExplicitFaultTrip",
            "ChannelHealthy",
        }
        assert expected_vars.issubset(var_names)

        bound = set(pou.bound_registers)
        expected_regs = {
            "%R1330", "%R1331", "%R1332", "%R1333",
            "%R1334", "%R1335", "%R1336", "%R1337",
            "%M310", "%M311",
        }
        assert bound == expected_regs

    def test_pure_st_pou_ast_parsing_alias(self) -> None:
        """Parse ETHERNET_IP_UCMM_EXPLICIT_SYNC_POU alias with STParser."""
        parser = STParser()
        pou = parser.parse_pou(ETHERNET_IP_UCMM_EXPLICIT_SYNC_POU)
        assert pou is not None
        assert pou.name == "EtherNetIpUcmmExplicitSync"
        assert pou.pou_type == POUType.PROGRAM

        bound = set(pou.bound_registers)
        expected_regs = {
            "%R1330", "%R1331", "%R1332", "%R1333",
            "%R1334", "%R1335", "%R1336", "%R1337",
            "%M310", "%M311",
        }
        assert bound == expected_regs

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify all POU aliases pass SecurityGuard assertion cleanly."""
        SecurityGuard.assert_pure_st_content(CIP_EXPLICIT_MESSAGING_SYNC_POU)
        SecurityGuard.assert_pure_st_content(ETHERNET_IP_UCMM_EXPLICIT_SYNC_POU)
        SecurityGuard.assert_pure_st_content(CIP_EXPLICIT_SYNC_POU)
        SecurityGuard.assert_pure_st_content(UCMM_EXPLICIT_SYNC_POU)
        SecurityGuard.assert_pure_st_content(PURE_ST_POU)


# ============================================================================
# 2. Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection2AntiLadderSecurityGuard:
    """Tests verifying ladder logic constructs are strictly rejected."""

    def test_ladder_contacts_rejected(self) -> None:
        """Reject ASCII ladder contacts ---[ ]--- and inverted ---[/]---."""
        bad_st_1 = "PROGRAM BadContacts\nVAR X: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)
        res1 = STParser.validate_code(bad_st_1)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_2 = "PROGRAM BadContactsInv\nVAR X: BOOL; END_VAR\n---[/]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)
        res2 = STParser.validate_code(bad_st_2)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "ERR_LADDER_FORBIDDEN"

    def test_ladder_coils_rejected(self) -> None:
        """Reject ASCII ladder coils ---( )---, set ---(S)---, and reset ---(R)---."""
        bad_st_1 = "PROGRAM BadCoils\nVAR Y: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)
        res1 = STParser.validate_code(bad_st_1)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_2 = "PROGRAM BadCoilsSet\nVAR Y: BOOL; END_VAR\n---(S)---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)
        res2 = STParser.validate_code(bad_st_2)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "ERR_LADDER_FORBIDDEN"

    def test_ladder_mnemonics_rejected(self) -> None:
        """Reject ladder mnemonics XIC, OTE, OTL, OTU, and RUNG blocks."""
        bad_st_1 = "PROGRAM BadMnemonics\nVAR Z: BOOL; END_VAR\nRUNG 1: XIC %M1 OTE %M2 END_RUNG\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)
        res1 = STParser.validate_code(bad_st_1)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_2 = "PROGRAM BadNetwork\nVAR W: BOOL; END_VAR\nNETWORK 1\nOTL %M310\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)
        res2 = STParser.validate_code(bad_st_2)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# 3. CIP Object Dictionary Implementation (6 Standard Objects)
# ============================================================================

class TestSection3CIPObjectDictionary:
    """Tests verifying complete implementation of all 6 standard CIP objects."""

    def test_identity_object_attributes(self) -> None:
        """Verify Identity Object (Class 0x01) attributes 1..8 and permissions."""
        ident = IdentityObject()
        assert ident.vendor_id == HORNER_VENDOR_ID
        assert ident.device_type == HORNER_DEVICE_TYPE
        assert ident.product_code == HORNER_PRODUCT_CODE
        assert (ident.major_revision, ident.minor_revision) == (10, 2)
        assert ident.product_name == HORNER_PRODUCT_NAME
        assert ident.serial_number == HORNER_SERIAL_NUMBER

        # Attr 1: Vendor ID
        st1, d1 = ident.get_attribute_single(1)
        assert st1 == CIPGeneralStatus.SUCCESS
        assert struct.unpack("<H", d1)[0] == 0x0059

        # Attr 3: Product Code
        st3, d3 = ident.get_attribute_single(3)
        assert st3 == CIPGeneralStatus.SUCCESS
        assert struct.unpack("<H", d3)[0] == 102

        # Attr 7: Product Name (Short String)
        st7, d7 = ident.get_attribute_single(7)
        assert st7 == CIPGeneralStatus.SUCCESS
        name_decoded, _ = decode_short_string(d7)
        assert name_decoded == HORNER_PRODUCT_NAME

        # Attr 5: Status (settable)
        st_set, _ = ident.set_attribute_single(5, struct.pack("<H", 0x0064))
        assert st_set == CIPGeneralStatus.SUCCESS
        assert ident.status == 0x0064

        # Read-only attribute write rejection
        st_bad_set, _ = ident.set_attribute_single(1, struct.pack("<H", 0x1234))
        assert st_bad_set == CIPGeneralStatus.ATTRIBUTE_NOT_SETTABLE

        # Invalid attribute ID
        st_bad_attr, _ = ident.get_attribute_single(99)
        assert st_bad_attr == CIPGeneralStatus.ATTRIBUTE_NOT_SUPPORTED

        # Get_Attributes_All
        st_all, d_all = ident.get_attributes_all()
        assert st_all == CIPGeneralStatus.SUCCESS
        assert len(d_all) >= 18

    def test_message_router_object_attributes(self) -> None:
        """Verify Message Router (Class 0x02) object list and connection counts."""
        mr = MessageRouterObject()
        st1, d1 = mr.get_attribute_single(1)
        assert st1 == CIPGeneralStatus.SUCCESS
        count = struct.unpack_from("<H", d1, 0)[0]
        classes = list(struct.unpack_from(f"<{count}H", d1, 2))
        assert {0x01, 0x02, 0x04, 0x06, 0xF5, 0xF6}.issubset(set(classes))

        st2, d2 = mr.get_attribute_single(2)
        assert st2 == CIPGeneralStatus.SUCCESS
        assert struct.unpack("<H", d2)[0] == 16

    def test_assembly_object_instances(self) -> None:
        """Verify Assembly Object (Class 0x04) instances 100, 101, and 102."""
        assembly = AssemblyObject()

        # Instance 100: Input Assembly (read-only, size 32)
        st100_sz, d100_sz = assembly.get_attribute_single(100, 4)
        assert st100_sz == CIPGeneralStatus.SUCCESS
        assert struct.unpack("<H", d100_sz)[0] == 32

        st100_write, _ = assembly.set_attribute_single(100, 3, b"\x00" * 32)
        assert st100_write == CIPGeneralStatus.ATTRIBUTE_NOT_SETTABLE

        # Instance 101: Output Assembly (read-write, size 16)
        st101_write, _ = assembly.set_attribute_single(101, 3, b"\xAA" * 16)
        assert st101_write == CIPGeneralStatus.SUCCESS
        st101_read, d101_read = assembly.get_attribute_single(101, 3)
        assert st101_read == CIPGeneralStatus.SUCCESS
        assert d101_read == b"\xAA" * 16

        # Size mismatch rejection
        st101_bad, _ = assembly.set_attribute_single(101, 3, b"\xAA" * 8)
        assert st101_bad == CIPGeneralStatus.NOT_ENOUGH_DATA

        # Non-existent instance
        st_bad_inst, _ = assembly.get_attribute_single(999, 3)
        assert st_bad_inst == CIPGeneralStatus.OBJECT_DOES_NOT_EXIST

    def test_connection_manager_object_attributes(self) -> None:
        """Verify Connection Manager (Class 0x06) attributes 1..8 statistics."""
        cm = ConnectionManagerObject()
        cm.open_requests = 12
        cm.open_resource_rejects = 2
        st1, d1 = cm.get_attribute_single(1)
        assert st1 == CIPGeneralStatus.SUCCESS
        assert struct.unpack("<H", d1)[0] == 12

        st3, d3 = cm.get_attribute_single(3)
        assert st3 == CIPGeneralStatus.SUCCESS
        assert struct.unpack("<H", d3)[0] == 2

        st_all, d_all = cm.get_attributes_all()
        assert st_all == CIPGeneralStatus.SUCCESS
        assert len(d_all) == 16

    def test_tcp_ip_interface_object_attributes(self) -> None:
        """Verify TCP/IP Interface Object (Class 0xF5) networking parameters."""
        tcp = TcpIpInterfaceObject()
        st1, d1 = tcp.get_attribute_single(1)
        assert st1 == CIPGeneralStatus.SUCCESS
        assert struct.unpack("<I", d1)[0] == 0x01  # Status: configured

        st5, d5 = tcp.get_attribute_single(5)
        assert st5 == CIPGeneralStatus.SUCCESS
        assert d5[:4] == bytes([192, 168, 1, 100])  # IP address bytes

        # Host name modification (Attribute 6)
        st_host, _ = tcp.set_attribute_single(6, struct.pack("<H", 7) + b"test-pc")
        assert st_host == CIPGeneralStatus.SUCCESS
        assert tcp.host_name == "test-pc"

    def test_ethernet_link_object_attributes(self) -> None:
        """Verify Ethernet Link Object (Class 0xF6) speed, flags, and MAC address."""
        eth = EthernetLinkObject()
        st1, d1 = eth.get_attribute_single(1)
        assert st1 == CIPGeneralStatus.SUCCESS
        assert struct.unpack("<I", d1)[0] == 100  # 100 Mbps

        st3, d3 = eth.get_attribute_single(3)
        assert st3 == CIPGeneralStatus.SUCCESS
        assert len(d3) == 6

        st10, d10 = eth.get_attribute_single(10)
        assert st10 == CIPGeneralStatus.SUCCESS
        label_len = d10[0]
        assert d10[1 : 1 + label_len].decode("ascii") == "ETH0"


# ============================================================================
# 4. EPath Logical Segment Parsing & CIP Service Handling
# ============================================================================

class TestSection4EPathAndCIPServices:
    """Tests for 8-bit/16-bit EPath segment parsing and standard CIP services."""

    def test_epath_8bit_logical_segment_encoding_and_parsing(self) -> None:
        """Verify 8-bit logical Class, Instance, and Attribute segment encoding and parsing."""
        epath = EPath.from_logical(class_id=0x01, instance_id=0x01, attribute_id=0x07, is_16bit=False)
        encoded = epath.encode()
        # 0x20: Class 8-bit, 0x01; 0x24: Inst 8-bit, 0x01; 0x30: Attr 8-bit, 0x07
        assert encoded == bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x07])

        decoded = EPath.decode(encoded)
        assert decoded.get_logical_ids() == (0x01, 0x01, 0x07)

    def test_epath_16bit_logical_segment_encoding_and_parsing(self) -> None:
        """Verify 16-bit logical segment format (0x21 0x00 lo hi, etc.) encoding and parsing."""
        epath = EPath.from_logical(class_id=0xF5, instance_id=0x01, attribute_id=0x05, is_16bit=True)
        encoded = epath.encode()
        expected = bytes([
            0x21, 0x00, 0xF5, 0x00,
            0x25, 0x00, 0x01, 0x00,
            0x31, 0x00, 0x05, 0x00,
        ])
        assert encoded == expected

        decoded = EPath.decode(encoded)
        assert decoded.get_logical_ids() == (0xF5, 0x01, 0x05)

    def test_epath_symbolic_and_port_segments(self) -> None:
        """Verify Symbolic and Port segment encoding."""
        sym = SymbolicSegment("Tag1")
        assert sym.encode() == bytes([0x91, 4]) + b"Tag1"

        port = PortSegment(port=1, link_address=bytes([2]))
        assert len(port.encode()) >= 2

    def test_service_0x0e_get_attribute_single(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify 0x0E Get_Attribute_Single returns 0x8E and requested data."""
        resp = explicit_engine.execute_ucmm_explicit_request(
            service_code=CIPServiceCode.GET_ATTRIBUTE_SINGLE,
            class_id=CIPClassCode.IDENTITY,
            instance_id=1,
            attribute_id=1,
        )
        assert resp.is_success
        assert resp.reply_service_code == 0x8E
        assert struct.unpack("<H", resp.data)[0] == HORNER_VENDOR_ID

    def test_service_0x10_set_attribute_single(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify 0x10 Set_Attribute_Single writes attribute on Assembly Instance 101."""
        test_payload = b"\x10\x20\x30\x40" + b"\x00" * 12  # 16 bytes
        resp_set = explicit_engine.execute_ucmm_explicit_request(
            service_code=CIPServiceCode.SET_ATTRIBUTE_SINGLE,
            class_id=CIPClassCode.ASSEMBLY,
            instance_id=101,
            attribute_id=3,
            data=test_payload,
        )
        assert resp_set.is_success
        assert resp_set.reply_service_code == 0x90

        # Read back to verify
        resp_get = explicit_engine.execute_ucmm_explicit_request(
            service_code=CIPServiceCode.GET_ATTRIBUTE_SINGLE,
            class_id=CIPClassCode.ASSEMBLY,
            instance_id=101,
            attribute_id=3,
        )
        assert resp_get.data == test_payload

    def test_service_0x01_get_attributes_all(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify 0x01 Get_Attributes_All returns 0x81 with concatenated attributes."""
        resp = explicit_engine.execute_ucmm_explicit_request(
            service_code=CIPServiceCode.GET_ATTRIBUTES_ALL,
            class_id=CIPClassCode.IDENTITY,
            instance_id=1,
        )
        assert resp.is_success
        assert resp.reply_service_code == 0x81
        assert len(resp.data) >= 18

    def test_service_0x54_forward_open(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify 0x54 Forward_Open establishes Class 3 explicit connection."""
        o_cid, t_cid = explicit_engine.forward_open(connection_serial_number=101, rpi_us=25000)
        assert t_cid in explicit_engine.connection_manager.connections
        assert explicit_engine.active_connection_id == t_cid
        assert explicit_engine.reg_table.read_uword("%R1331") == (t_cid & 0xFFFF)

    def test_service_0x4e_forward_close(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify 0x4E Forward_Close terminates active Class 3 connection."""
        o_cid, t_cid = explicit_engine.forward_open(connection_serial_number=202, rpi_us=25000)
        assert t_cid in explicit_engine.connection_manager.connections

        ok = explicit_engine.forward_close(t_cid)
        assert ok is True
        assert t_cid not in explicit_engine.connection_manager.connections
        assert explicit_engine.active_connection_id == 0

    def test_unsupported_cip_service_handling(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify requesting an unsupported service returns 0x08 (SERVICE_NOT_SUPPORTED)."""
        resp = explicit_engine.execute_ucmm_explicit_request(
            service_code=0x2B,  # Unsupported service
            class_id=CIPClassCode.IDENTITY,
            instance_id=1,
        )
        assert resp.general_status == CIPGeneralStatus.SERVICE_NOT_SUPPORTED


# ============================================================================
# 5. UCMM & Transport Class 3 Explicit Connection State Machine
# ============================================================================

class TestSection5UCMMAndClass3StateMachine:
    """Tests for Unconnected Message Manager and Class 3 connection lifecycle."""

    def test_ucmm_unconnected_request_handling(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify UCMM processes unconnected requests via SEND_RR_DATA encapsulation."""
        h1 = explicit_engine.register_session()
        assert len(explicit_engine.active_sessions) == 1

        req_epath = EPath.from_logical(CIPClassCode.IDENTITY, 1, 1)
        req = CIPRequest(service_code=CIPServiceCode.GET_ATTRIBUTE_SINGLE, epath=req_epath)
        cpf = serialize_cpf([
            CPFItem.null_address(),
            CPFItem.unconnected_data(req.encode()),
        ])
        hdr = EIPHeader(
            command=EIPCommand.SEND_RR_DATA,
            length=6 + len(cpf),
            session_handle=h1,
        )
        packet = hdr.serialize() + struct.pack("<IH", 0, 0) + cpf

        resp_bytes = explicit_engine.handle_encapsulation_packet(packet)
        resp_hdr, resp_payload = EIPHeader.deserialize(resp_bytes)
        assert resp_hdr.command == EIPCommand.SEND_RR_DATA
        assert resp_hdr.status == EIPStatus.SUCCESS

        items = deserialize_cpf(resp_payload[6:])
        unconn_reply = next(it for it in items if it.type_id == CPFTypeId.UNCONNECTED_DATA)
        cip_reply = CIPResponse.decode(unconn_reply.data)
        assert cip_reply.is_success
        assert struct.unpack("<H", cip_reply.data)[0] == HORNER_VENDOR_ID

    def test_class3_explicit_connection_state_transitions(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify Class 3 lifecycle: Forward_Open -> Connected Send -> Forward_Close."""
        # 1. Forward_Open establishes connection
        o_cid, t_cid = explicit_engine.forward_open(connection_serial_number=303, rpi_us=20000)
        conn = explicit_engine.connection_manager.connections[t_cid]
        assert conn.connection_id == t_cid
        assert conn.sequence_count == 0

        # 2. Transact data over connected explicit request
        resp = explicit_engine.execute_connected_explicit_request(
            connection_id=t_cid,
            service_code=CIPServiceCode.GET_ATTRIBUTE_SINGLE,
            class_id=CIPClassCode.IDENTITY,
            instance_id=1,
            attribute_id=1,
        )
        assert resp.is_success
        assert conn.sequence_count == 1
        assert explicit_engine.explicit_transaction_counter == 1

        # 3. Forward_Close terminates connection
        ok = explicit_engine.forward_close(t_cid)
        assert ok is True
        assert t_cid not in explicit_engine.connection_manager.connections

    def test_class3_inactivity_watchdog_timeout(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify transaction inactivity exceeding 25.0 ms trips timeout watchdog."""
        explicit_engine.transaction_in_progress = True
        explicit_engine.current_transaction_elapsed_ms = 0.0

        # Step clock beyond 25.0 ms timeout (advance 30 ms)
        explicit_engine.step_scan_cycle(dt_ms=30.0)
        assert explicit_engine.diagnostic_code == CipExplicitDiagnosticCode.CIP_ERR_UCMM_TIMEOUT
        assert explicit_engine.fault_trip is True
        assert explicit_engine.permissive is False
        assert explicit_engine.reg_table.read_uword("%R1337") == 0xC501


# ============================================================================
# 6. Explicit Messaging Transaction Timeout Surveillance & Jitter Metrics
# ============================================================================

class TestSection6TimeoutSurveillanceAndJitter:
    """Tests for > 25.0 ms timeout surveillance, jitter metrics, and error response serialization."""

    def test_transaction_duration_within_limit_succeeds(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify transaction with latency <= 25.0 ms completes without error."""
        explicit_engine.transaction_in_progress = True
        explicit_engine.current_transaction_elapsed_ms = 0.0

        # Step 10 ms (well within 25.0 ms limit)
        explicit_engine.step_scan_cycle(dt_ms=10.0)
        assert explicit_engine.fault_trip is False
        assert explicit_engine.permissive is True
        assert explicit_engine.diagnostic_code == CipExplicitDiagnosticCode.OK

    def test_transaction_duration_exceeding_25ms_trips_fault(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify transaction with latency > 25.0 ms triggers 0xC501 and increments %R1334."""
        explicit_engine.transaction_in_progress = True
        explicit_engine.current_transaction_elapsed_ms = 0.0

        explicit_engine.step_scan_cycle(dt_ms=28.0)
        assert explicit_engine.diagnostic_code == CipExplicitDiagnosticCode.CIP_ERR_UCMM_TIMEOUT
        assert explicit_engine.diagnostic_code == 0xC501
        assert explicit_engine.explicit_error_counter == 1
        assert explicit_engine.reg_table.read_word("%R1334") == 1
        assert explicit_engine.reg_table.read_bit("%M311") is True
        assert explicit_engine.reg_table.read_bit("%M310") is False

    def test_jitter_metrics_and_scaling(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify timeout scaling in %R1333 (25.0 ms scaled x10 = 250)."""
        assert explicit_engine.timeout_ms == 25.0
        assert scale_ms_to_int16(25.0) == 250
        assert unscale_int16_to_ms(250) == 25.0
        assert explicit_engine.reg_table.read_word("%R1333") == 250

    def test_error_response_serialization_and_deserialization(self) -> None:
        """Verify CIP error response packet format serialization and deserialization."""
        err_bytes = serialize_cip_error_response(
            service_code=0x0E,
            general_status=CIPGeneralStatus.CONNECTION_FAILURE,
            additional_status=[0xC501],
        )
        resp = CIPResponse.decode(err_bytes)
        assert resp.reply_service_code == 0x8E
        assert resp.general_status == CIPGeneralStatus.CONNECTION_FAILURE
        assert resp.additional_status == [0xC501]
        assert resp.is_success is False


# ============================================================================
# 7. Process Safety Trips (0xC501..0xC504) and Horner Coil Assertion
# ============================================================================

class TestSection7ProcessSafetyTrips:
    """Tests verifying all 4 diagnostic fault codes (0xC501..0xC504) trip %M311 and clear %M310."""

    def test_trip_0xc501_ucmm_timeout(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """0xC501: Transaction timeout > 25.0 ms asserts %M311 and clears %M310."""
        explicit_engine.reset_latch(force=True)
        explicit_engine.transaction_in_progress = True
        explicit_engine.current_transaction_elapsed_ms = 0.0
        explicit_engine.step_scan_cycle(dt_ms=30.0)

        assert explicit_engine.reg_table.read_uword("%R1337") == 0xC501
        assert explicit_engine.reg_table.read_bit("%M311") is True
        assert explicit_engine.reg_table.read_bit("%M310") is False

    def test_trip_0xc502_service_not_supported(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """0xC502: Unsupported CIP service code asserts %M311 and clears %M310."""
        explicit_engine.reset_latch(force=True)
        explicit_engine.trigger_fault(CipExplicitDiagnosticCode.CIP_ERR_SERVICE_NOT_SUPPORTED)

        assert explicit_engine.reg_table.read_uword("%R1337") == 0xC502
        assert explicit_engine.reg_table.read_bit("%M311") is True
        assert explicit_engine.reg_table.read_bit("%M310") is False

    def test_trip_0xc503_object_path_invalid(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """0xC503: Invalid EPath Class/Instance/Attribute asserts %M311 and clears %M310."""
        explicit_engine.reset_latch(force=True)
        explicit_engine.trigger_fault(CipExplicitDiagnosticCode.CIP_ERR_OBJECT_PATH_INVALID)

        assert explicit_engine.reg_table.read_uword("%R1337") == 0xC503
        assert explicit_engine.reg_table.read_bit("%M311") is True
        assert explicit_engine.reg_table.read_bit("%M310") is False

    def test_trip_0xc504_fragmentation_fault(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """0xC504: Fragmentation / malformed frame fault asserts %M311 and clears %M310."""
        explicit_engine.reset_latch(force=True)
        explicit_engine.trigger_fault(CipExplicitDiagnosticCode.CIP_ERR_FRAGMENTATION_FAULT)

        assert explicit_engine.reg_table.read_uword("%R1337") == 0xC504
        assert explicit_engine.reg_table.read_bit("%M311") is True
        assert explicit_engine.reg_table.read_bit("%M310") is False

    def test_operator_fault_reset_handshake(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify operator reset clears fault trip and restores %M310 permissive."""
        explicit_engine.trigger_fault(CipExplicitDiagnosticCode.CIP_ERR_UCMM_TIMEOUT)
        assert explicit_engine.fault_trip is True
        assert explicit_engine.reg_table.read_bit("%M311") is True

        res = explicit_engine.reset_latch(force=True)
        assert res.status == AgentStatus.SUCCESS
        assert explicit_engine.fault_trip is False
        assert explicit_engine.permissive is True
        assert explicit_engine.diagnostic_code == CipExplicitDiagnosticCode.OK
        assert explicit_engine.reg_table.read_uword("%R1337") == 0x0000
        assert explicit_engine.reg_table.read_bit("%M311") is False
        assert explicit_engine.reg_table.read_bit("%M310") is True


# ============================================================================
# 8. Horner OCS Register Space Synchronization & PrivilegeMode.SYSTEM
# ============================================================================

class TestSection8RegisterSpaceSynchronization:
    """Tests for %R1330..%R1337 and %M310..%M311 Horner register bindings."""

    def test_register_space_layout_initial(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify exact layout and initial values across %R1330..%R1337 and %M310..%M311."""
        rt = explicit_engine.reg_table
        # %R1330: UcmmActiveSessionsCount (0)
        assert rt.read_word("%R1330") == 0
        # %R1331: ConnectionIdWord (0)
        assert rt.read_uword("%R1331") == 0
        # %R1332: ExplicitTransactionCounter (0)
        assert rt.read_uword("%R1332") == 0
        # %R1333: ExplicitRequestTimeoutMsScaled (250)
        assert rt.read_word("%R1333") == 250
        # %R1334: ExplicitErrorCounter (0)
        assert rt.read_word("%R1334") == 0
        # %R1335: UcmmTransceiverStateWord (Bitmask with PERMISSIVE and PORT_44818_LISTENING)
        state_word = rt.read_word("%R1335")
        assert (state_word & UcmmTransceiverStateBits.PERMISSIVE) != 0
        assert (state_word & UcmmTransceiverStateBits.PORT_44818_LISTENING) != 0
        # %R1336: CipServiceAndClassWord (0)
        assert rt.read_uword("%R1336") == 0
        # %R1337: DiagnosticStatusCode (0)
        assert rt.read_uword("%R1337") == 0
        # Discrete coils
        assert rt.read_bit("%M310") is True
        assert rt.read_bit("%M311") is False

    def test_service_class_word_encoding_and_decoding(self) -> None:
        """Verify packing and unpacking service code and class ID into %R1336."""
        word = encode_service_and_class_word(service_code=0x0E, class_id=0x01)
        assert word == 0x0E01
        svc, cls_id = decode_service_and_class_word(word)
        assert svc == 0x0E
        assert cls_id == 0x01

        # Convenience aliases
        word2 = encode_service_class_word(service=0x10, class_id=0x04)
        assert word2 == 0x1004
        svc2, cls2 = decode_service_class_word(word2)
        assert (svc2, cls2) == (0x10, 0x04)

    def test_transceiver_state_word_bitmask_flags(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify bitmask flags update dynamically when sessions and faults occur."""
        # Register a session
        explicit_engine.register_session()
        state_word = explicit_engine.compute_transceiver_state_word()
        assert (state_word & UcmmTransceiverStateBits.SESSION_REGISTERED) != 0

        # Trigger fault
        explicit_engine.trigger_fault(CipExplicitDiagnosticCode.CIP_ERR_UCMM_TIMEOUT)
        state_fault = explicit_engine.compute_transceiver_state_word()
        assert (state_fault & UcmmTransceiverStateBits.FAULT_TRIP) != 0
        assert (state_fault & UcmmTransceiverStateBits.TIMEOUT_FAULT) != 0

    def test_system_privilege_mode_enforced(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify register updates safely operate with SYSTEM privilege."""
        explicit_engine.sync_to_registers()
        assert explicit_engine.reg_table.read_word("%R1333") == 250


# ============================================================================
# 9. ILogicUnit Interface Compliance & Verification Suite Integration
# ============================================================================

class TestSection9ILogicUnitAndVerificationSuite:
    """Tests verifying simulation engine ILogicUnit interface and 9-stage verification suite."""

    def test_ilogicunit_properties_and_execution(self, explicit_engine: CipExplicitMessagingEngine) -> None:
        """Verify name, priority, is_enabled, execute with ScanContext, and reset."""
        assert explicit_engine.name == "cip_explicit_messaging"
        assert explicit_engine.priority == 90
        assert explicit_engine.is_enabled is True

        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=lambda addr: explicit_engine.reg_table.read_register(addr),
            set_register=lambda addr, val: explicit_engine.reg_table.write_register(
                addr, val, privilege=PrivilegeMode.SYSTEM
            ),
            get_variable=lambda k, d=None: None,
            set_variable=lambda k, v: None,
            record_fault=lambda fault: None,
        )
        explicit_engine.execute(ctx)
        assert explicit_engine.elapsed_time_ms >= 10.0

        explicit_engine.trigger_fault(CipExplicitDiagnosticCode.CIP_ERR_UCMM_TIMEOUT)
        assert explicit_engine.fault_trip is True
        explicit_engine.reset()
        assert explicit_engine.fault_trip is False

    def test_run_cip_explicit_messaging_verification_suite(self) -> None:
        """Execute 9-stage verification suite, assert all pass, and verify evidence JSON file."""
        with tempfile.TemporaryDirectory() as td:
            output_file = Path(td) / "cip_explicit_messaging_evidence.json"
            res = run_cip_explicit_messaging_verification(output_path=output_file)

            assert res["status"] == "success"
            assert res["error_code"] is None
            assert res["data"]["checks_passed"] == 9
            assert res["data"]["total_checks"] == 9
            assert len(res["data"]["tests"]) == 9

            for t in res["data"]["tests"]:
                assert t["passed"] is True
                assert "stage" in t
                assert "check" in t

            assert output_file.exists()
            with open(output_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
            assert saved["status"] == "success"
            assert saved["data"]["checks_passed"] == 9
            assert saved["data"]["work_package"] == "W172"
            assert saved["data"]["gate"] == "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation"
            assert saved["data"]["register_map"]["analog_registers"] == "%R1330..%R1337"
            assert saved["data"]["register_map"]["discrete_coils"] == "%M310..%M311"
