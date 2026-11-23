"""Comprehensive Unit and Integration Test Suite for Industrial Modbus TCP Multi-Client Gateway & Transaction Multiplexer Engine.

Work Package: W175 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation
   (%R1360..%R1367, %M317..%M318).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: MBAP header encoding, parsing, length checks, and Protocol ID validation.
4. Section 4: Multi-client connection pool management (up to 16 concurrent sockets) and client IP/Unit ID mapping.
5. Section 5: Transaction multiplexing FIFO queue, transaction ID round-trip tracking, and latency calculation.
6. Section 6: Socket timeout surveillance (> 50.0 ms) and connection lifecycle transitions.
7. Section 7: Process safety trips (0xC801, 0xC802, 0xC803, 0xC804) and Horner coil assertion (%M317, %M318).
8. Section 8: Horner OCS register space synchronization (%R1360..%R1367, %M317..%M318) with PrivilegeMode.SYSTEM.
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
from jev_cscape.telemetry.modbus_tcp_gateway import (
    ClientConnection,
    ClientConnectionState,
    ClientOverflowError,
    DiagnosticStatusCode,
    DownstreamRoute,
    EX_GATEWAY_PATH_UNAVAILABLE,
    EX_GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND,
    EX_ILLEGAL_DATA_ADDRESS,
    EX_ILLEGAL_DATA_VALUE,
    EX_ILLEGAL_FUNCTION,
    EX_SLAVE_DEVICE_FAILURE,
    FC_READ_COILS,
    FC_READ_DISCRETE_INPUTS,
    FC_READ_HOLDING_REGISTERS,
    FC_READ_INPUT_REGISTERS,
    FC_WRITE_MULTIPLE_COILS,
    FC_WRITE_MULTIPLE_REGISTERS,
    FC_WRITE_SINGLE_COIL,
    FC_WRITE_SINGLE_REGISTER,
    GatewayState,
    GatewayStateBits,
    MAX_CLIENT_CONNECTIONS,
    MAX_QUEUE_DEPTH,
    MBAP_HEADER_LENGTH,
    MODBUS_PROTOCOL_ID,
    MODBUS_TCP_DEFAULT_PORT,
    MODBUS_TCP_GATEWAY_POU,
    MODBUS_TCP_GATEWAY_SYNC_POU,
    MalformedMbapError,
    MbapHeader,
    ModbusTcpAdu,
    ModbusTcpClientOverflowError,
    ModbusTcpGateway,
    ModbusTcpGatewayDiagnosticCode,
    ModbusTcpGatewayEngine,
    ModbusTcpGatewayError,
    ModbusTcpGatewaySync,
    ModbusTcpMalformedMbapError,
    ModbusTcpMultiplexerEngine,
    ModbusTcpTransaction,
    ModbusTcpTransactionTimeoutError,
    ModbusTcpUnitIdUnreachableError,
    NOMINAL_LATENCY_SCALED,
    NOMINAL_ROUND_TRIP_LATENCY_MS,
    PURE_ST_POU,
    SOCKET_TIMEOUT_THRESHOLD_MS,
    TCP_MULTI_CLIENT_MULTIPLEXER_SYNC_POU,
    TCP_MULTIPLEXER_SYNC_POU,
    TcpMultiClientMultiplexerSync,
    TcpMultiClientMultiplexerSyncEngine,
    TransactionStatus,
    TransactionTimeoutError,
    UnitIdUnreachableError,
    decode_client_ip_unit_id_word,
    encode_client_ip_unit_id_word,
    run_modbus_tcp_gateway_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    verify_modbus_tcp_gateway_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provide a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def gateway_engine(register_table: RegisterTable) -> ModbusTcpGatewayEngine:
    """Provide a fresh Modbus TCP Gateway engine bound to register table."""
    return ModbusTcpGatewayEngine(
        max_clients=MAX_CLIENT_CONNECTIONS,
        socket_timeout_ms=SOCKET_TIMEOUT_THRESHOLD_MS,
        nominal_latency_ms=NOMINAL_ROUND_TRIP_LATENCY_MS,
        register_table=register_table,
    )


# ============================================================================
# 1. Pure ST POU AST Validation & Register Binding (%R1360..%R1367, %M317..%M318)
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for Pure Structured Text POU compliance and register bindings."""

    def test_verify_modbus_tcp_gateway_pure_st_helper(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_modbus_tcp_gateway_pure_st() is True

    def test_pure_st_pou_ast_parsing_primary(self) -> None:
        """Parse MODBUS_TCP_GATEWAY_SYNC_POU with STParser and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(MODBUS_TCP_GATEWAY_SYNC_POU)
        assert pou is not None
        assert pou.name == "ModbusTcpGatewaySync"
        assert pou.pou_type == POUType.PROGRAM

        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "ActiveTcpClientsCount",
            "TransactionIdTrackingWord",
            "GatewayRoundTripLatencyMsScaled",
            "MultiplexerQueueDepth",
            "SocketTimeoutErrorCounter",
            "GatewayStateWord",
            "ClientIpAndUnitIdWord",
            "DiagnosticStatusCode",
            "ModbusTcpGatewayPermissive",
            "ModbusTcpGatewayFaultTrip",
            "GatewayHealthy",
        }
        assert expected_vars.issubset(var_names)

        bound = set(pou.bound_registers)
        expected_regs = {
            "%R1360", "%R1361", "%R1362", "%R1363",
            "%R1364", "%R1365", "%R1366", "%R1367",
            "%M317", "%M318",
        }
        assert bound == expected_regs

    def test_pure_st_pou_ast_parsing_multiplexer_alias(self) -> None:
        """Parse TCP_MULTI_CLIENT_MULTIPLEXER_SYNC_POU alias with STParser."""
        parser = STParser()
        pou = parser.parse_pou(TCP_MULTI_CLIENT_MULTIPLEXER_SYNC_POU)
        assert pou is not None
        assert pou.name == "TcpMultiClientMultiplexerSync"
        assert pou.pou_type == POUType.PROGRAM

        bound = set(pou.bound_registers)
        expected_regs = {
            "%R1360", "%R1361", "%R1362", "%R1363",
            "%R1364", "%R1365", "%R1366", "%R1367",
            "%M317", "%M318",
        }
        assert bound == expected_regs

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify all POU aliases pass SecurityGuard assertion cleanly."""
        SecurityGuard.assert_pure_st_content(MODBUS_TCP_GATEWAY_SYNC_POU)
        SecurityGuard.assert_pure_st_content(TCP_MULTI_CLIENT_MULTIPLEXER_SYNC_POU)
        SecurityGuard.assert_pure_st_content(PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(MODBUS_TCP_GATEWAY_POU)
        SecurityGuard.assert_pure_st_content(TCP_MULTIPLEXER_SYNC_POU)


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
        """Reject ladder mnemonics XIC, OTE, OTL, OTU, and RUNG/NETWORK blocks."""
        bad_st_1 = "PROGRAM BadMnemonics\nVAR Z: BOOL; END_VAR\nRUNG 1: XIC %M1 OTE %M2 END_RUNG\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)
        res1 = STParser.validate_code(bad_st_1)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_2 = "PROGRAM BadNetwork\nVAR W: BOOL; END_VAR\nNETWORK 1\nOTL %M317\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)
        res2 = STParser.validate_code(bad_st_2)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# 3. MBAP Header Encoding, Parsing, Length Checks & Protocol ID Validation
# ============================================================================

class TestSection3MBAPHeader:
    """Tests for Modbus Application Protocol (MBAP) Header encoding and decoding."""

    def test_mbap_header_serialization_round_trip(self) -> None:
        """Verify 7-byte encoding and decoding with standard parameters."""
        hdr = MbapHeader(transaction_id=0xABCD, protocol_id=0x0000, length=6, unit_id=3)
        raw = hdr.serialize()
        assert len(raw) == MBAP_HEADER_LENGTH
        assert raw == struct.pack(">HHHB", 0xABCD, 0x0000, 6, 3)

        decoded = MbapHeader.deserialize(raw)
        assert decoded.transaction_id == 0xABCD
        assert decoded.protocol_id == 0x0000
        assert decoded.length == 6
        assert decoded.unit_id == 3

    def test_mbap_header_minimum_length_validation(self) -> None:
        """Verify that deserializing truncated header (< 7 bytes) raises MalformedMbapError."""
        with pytest.raises(ModbusTcpMalformedMbapError):
            MbapHeader.deserialize(b"\x00\x01\x00\x00\x00")

    def test_mbap_header_protocol_id_validation(self) -> None:
        """Verify non-zero protocol ID is rejected in ADU deserialization."""
        bad_adu = struct.pack(">HHHB", 1, 0x0001, 2, 1) + bytes([FC_READ_HOLDING_REGISTERS])
        with pytest.raises(ModbusTcpMalformedMbapError) as exc_info:
            ModbusTcpAdu.deserialize(bad_adu)
        assert "Invalid Protocol Identifier" in str(exc_info.value)

    def test_modbus_tcp_adu_serialization_round_trip(self) -> None:
        """Verify full ADU serialization and deserialization."""
        adu = ModbusTcpAdu.create_read_holding_registers(
            transaction_id=42, unit_id=1, start_address=1360, count=8
        )
        raw = adu.serialize()
        assert len(raw) == 12  # 7 MBAP + 1 FC + 4 data

        decoded = ModbusTcpAdu.deserialize(raw)
        assert decoded.transaction_id == 42
        assert decoded.protocol_id == 0x0000
        assert decoded.unit_id == 1
        assert decoded.function_code == FC_READ_HOLDING_REGISTERS
        assert len(decoded.pdu_data) == 4

        start_addr, count = struct.unpack(">HH", decoded.pdu_data)
        assert start_addr == 1360
        assert count == 8

    def test_modbus_tcp_adu_factory_methods(self) -> None:
        """Verify factory helper methods for coils, inputs, registers, and exceptions."""
        adu_coils = ModbusTcpAdu.create_read_coils(transaction_id=1, unit_id=1, start_address=317, count=2)
        assert adu_coils.function_code == FC_READ_COILS

        adu_di = ModbusTcpAdu.create_read_discrete_inputs(transaction_id=2, unit_id=1, start_address=1, count=8)
        assert adu_di.function_code == FC_READ_DISCRETE_INPUTS

        adu_ir = ModbusTcpAdu.create_read_input_registers(transaction_id=3, unit_id=1, start_address=1, count=4)
        assert adu_ir.function_code == FC_READ_INPUT_REGISTERS

        adu_wsc = ModbusTcpAdu.create_write_single_coil(transaction_id=4, unit_id=1, address=317, value=True)
        assert adu_wsc.function_code == FC_WRITE_SINGLE_COIL

        adu_wsr = ModbusTcpAdu.create_write_single_register(transaction_id=5, unit_id=1, address=1360, value=42)
        assert adu_wsr.function_code == FC_WRITE_SINGLE_REGISTER

        adu_wmr = ModbusTcpAdu.create_write_multiple_registers(
            transaction_id=6, unit_id=1, start_address=100, values=[10, 20, 30]
        )
        assert adu_wmr.function_code == FC_WRITE_MULTIPLE_REGISTERS

        adu_ex = ModbusTcpAdu.create_exception_response(
            transaction_id=7, unit_id=1, function_code=FC_READ_HOLDING_REGISTERS, exception_code=EX_ILLEGAL_DATA_ADDRESS
        )
        assert adu_ex.function_code == (FC_READ_HOLDING_REGISTERS | 0x80)
        assert adu_ex.pdu_data[0] == EX_ILLEGAL_DATA_ADDRESS

    def test_modbus_tcp_adu_truncated_payload_rejected(self) -> None:
        """Verify ADU with truncated payload according to MBAP length field is rejected."""
        # MBAP specifies length = 6 (5 bytes PDU expected), but only 2 bytes provided
        short_raw = struct.pack(">HHHB", 1, 0, 6, 1) + bytes([FC_READ_HOLDING_REGISTERS, 0x00])
        with pytest.raises(ModbusTcpMalformedMbapError):
            ModbusTcpAdu.deserialize(short_raw)

    def test_modbus_tcp_adu_invalid_length_field_rejected(self) -> None:
        """Verify length field < 2 in MBAP raises MalformedMbapError."""
        invalid_len_raw = struct.pack(">HHHB", 1, 0, 1, 1) + bytes([FC_READ_HOLDING_REGISTERS])
        with pytest.raises(ModbusTcpMalformedMbapError):
            ModbusTcpAdu.deserialize(invalid_len_raw)


# ============================================================================
# 4. Multi-Client Connection Pool Management (16 Sockets & IP/Unit ID Mapping)
# ============================================================================

class TestSection4MultiClientConnectionPool:
    """Tests for multi-client socket connection pool and routing tables."""

    def test_connect_single_client(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Connect single client socket and verify attributes."""
        conn = gateway_engine.connect_client(ip_address="192.168.1.50", port=50201)
        assert conn.client_id == 1
        assert conn.ip_address == "192.168.1.50"
        assert conn.port == 50201
        assert conn.state == ClientConnectionState.CONNECTED
        assert gateway_engine.get_active_clients_count() == 1
        assert gateway_engine.register_table.read_word("%R1360") == 1

    def test_connect_multiple_clients_up_to_16(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Connect up to 16 concurrent client sockets successfully."""
        clients: List[ClientConnection] = []
        for i in range(16):
            c = gateway_engine.connect_client(ip_address=f"192.168.2.{i + 1}", port=50000 + i)
            clients.append(c)

        assert gateway_engine.get_active_clients_count() == 16
        assert gateway_engine.register_table.read_word("%R1360") == 16
        for c in clients:
            assert gateway_engine.get_client(c.client_id) is c

    def test_client_capacity_overflow_17th_client_trips_c801(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify that attempting to connect a 17th client trips 0xC801 and raises ClientOverflowError."""
        for i in range(16):
            gateway_engine.connect_client(ip_address=f"10.0.0.{i + 1}", port=50100 + i)
        assert gateway_engine.get_active_clients_count() == 16

        with pytest.raises(ModbusTcpClientOverflowError):
            gateway_engine.connect_client(ip_address="10.0.0.17", port=50117)

        assert gateway_engine.fault_trip is True
        assert gateway_engine.permissive is False
        assert gateway_engine.diagnostic_code == ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_CLIENT_OVERFLOW
        assert gateway_engine.register_table.read_uword("%R1367") == 0xC801
        assert gateway_engine.register_table.read_bit("%M318") is True
        assert gateway_engine.register_table.read_bit("%M317") is False

    def test_disconnect_and_reconnect_client_lifecycle(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify disconnecting and reconnecting clients correctly updates counts and states."""
        c1 = gateway_engine.connect_client("192.168.1.10", 50201)
        c2 = gateway_engine.connect_client("192.168.1.11", 50202)
        assert gateway_engine.get_active_clients_count() == 2

        # Disconnect c1
        res_disc = gateway_engine.disconnect_client(c1.client_id)
        assert res_disc.status == AgentStatus.SUCCESS
        assert gateway_engine.get_active_clients_count() == 1
        assert c1.state == ClientConnectionState.CLOSED

        # Reconnect c1
        res_reconn = gateway_engine.reconnect_client(c1.client_id)
        assert res_reconn.status == AgentStatus.SUCCESS
        assert gateway_engine.get_active_clients_count() == 2
        assert c1.state == ClientConnectionState.CONNECTED

    def test_client_ip_and_unit_id_word_encoding(self) -> None:
        """Verify encoding and decoding client IP lower octet and Unit ID into %R1366."""
        word = encode_client_ip_unit_id_word(client_ip="192.168.1.105", unit_id=2)
        assert word == ((105 << 8) | 2)
        last_octet, uid = decode_client_ip_unit_id_word(word)
        assert last_octet == 105
        assert uid == 2

        # Integer octet variant
        word2 = encode_client_ip_unit_id_word(client_ip=42, unit_id=5)
        assert word2 == ((42 << 8) | 5)
        last_octet2, uid2 = decode_client_ip_unit_id_word(word2)
        assert (last_octet2, uid2) == (42, 5)

    def test_downstream_route_management(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify downstream slave routes configuration and reachability toggling."""
        assert 2 in gateway_engine.downstream_routes
        assert gateway_engine.downstream_routes[2].is_reachable is True

        gateway_engine.set_downstream_reachability(2, False)
        assert gateway_engine.downstream_routes[2].is_reachable is False

        gateway_engine.set_downstream_reachability(2, True)
        assert gateway_engine.downstream_routes[2].is_reachable is True


# ============================================================================
# 5. Transaction Multiplexing FIFO Queue & Round-Trip Tracking
# ============================================================================

class TestSection5TransactionMultiplexing:
    """Tests for FIFO transaction multiplexing, round-trip tracking, and latency."""

    def test_fifo_queue_ordering_across_clients(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify requests from multiple clients are enqueued and processed FIFO."""
        c1 = gateway_engine.connect_client("192.168.1.101", 50201)
        c2 = gateway_engine.connect_client("192.168.1.102", 50202)

        adu1 = ModbusTcpAdu.create_read_holding_registers(transaction_id=101, unit_id=1, start_address=1, count=1)
        adu2 = ModbusTcpAdu.create_read_holding_registers(transaction_id=102, unit_id=1, start_address=2, count=1)
        adu3 = ModbusTcpAdu.create_read_holding_registers(transaction_id=201, unit_id=1, start_address=3, count=1)

        gateway_engine.enqueue_request(c1.client_id, adu1)
        gateway_engine.enqueue_request(c1.client_id, adu2)
        gateway_engine.enqueue_request(c2.client_id, adu3)

        assert len(gateway_engine.request_queue) == 3
        assert gateway_engine.register_table.read_word("%R1363") == 3

        # Process FIFO order
        tx1 = gateway_engine.process_next_transaction()
        assert tx1 is not None and tx1.transaction_id == 101 and tx1.client_id == c1.client_id

        tx2 = gateway_engine.process_next_transaction()
        assert tx2 is not None and tx2.transaction_id == 102 and tx2.client_id == c1.client_id

        tx3 = gateway_engine.process_next_transaction()
        assert tx3 is not None and tx3.transaction_id == 201 and tx3.client_id == c2.client_id

        assert len(gateway_engine.request_queue) == 0
        assert gateway_engine.register_table.read_word("%R1363") == 0

    def test_process_next_transaction_updates_monotonic_tracking(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify processing transactions increments the monotonic tracking word (%R1361)."""
        c = gateway_engine.connect_client("192.168.1.10", 50201)
        adu = ModbusTcpAdu.create_read_holding_registers(transaction_id=5, unit_id=1, start_address=10, count=2)
        gateway_engine.enqueue_request(c.client_id, adu)

        assert gateway_engine.transaction_id_counter == 0
        gateway_engine.process_next_transaction()
        assert gateway_engine.transaction_id_counter == 1
        assert gateway_engine.register_table.read_uword("%R1361") == 1

    def test_dispatch_response_to_matching_client_socket(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify response is dispatched to the originating client's buffer."""
        c1 = gateway_engine.connect_client("192.168.1.101", 50201)
        c2 = gateway_engine.connect_client("192.168.1.102", 50202)

        adu1 = ModbusTcpAdu.create_read_holding_registers(transaction_id=101, unit_id=1, start_address=10, count=1)
        adu2 = ModbusTcpAdu.create_read_holding_registers(transaction_id=202, unit_id=1, start_address=20, count=1)

        gateway_engine.enqueue_request(c1.client_id, adu1)
        gateway_engine.enqueue_request(c2.client_id, adu2)

        gateway_engine.process_next_transaction()
        gateway_engine.process_next_transaction()

        assert len(c1.dispatched_responses) == 1
        assert c1.dispatched_responses[0].transaction_id == 101

        assert len(c2.dispatched_responses) == 1
        assert c2.dispatched_responses[0].transaction_id == 202

    def test_empty_queue_process_returns_none(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify calling process_next_transaction on empty queue safely returns None."""
        assert gateway_engine.process_next_transaction() is None

    def test_queue_depth_bounding_up_to_32(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify queue rejects excess requests beyond MAX_QUEUE_DEPTH (32)."""
        c = gateway_engine.connect_client("192.168.1.10", 50201)
        for i in range(MAX_QUEUE_DEPTH):
            adu = ModbusTcpAdu.create_read_holding_registers(transaction_id=i + 1, unit_id=1, start_address=1, count=1)
            res = gateway_engine.enqueue_request(c.client_id, adu)
            assert res.status == AgentStatus.SUCCESS

        assert len(gateway_engine.request_queue) == MAX_QUEUE_DEPTH

        # 33rd request
        excess_adu = ModbusTcpAdu.create_read_holding_registers(transaction_id=999, unit_id=1, start_address=1, count=1)
        res_overflow = gateway_engine.enqueue_request(c.client_id, excess_adu)
        assert res_overflow.status == AgentStatus.FAILED
        assert res_overflow.error_code == "ERR_QUEUE_OVERFLOW"

    def test_local_ocs_register_read_holding_registers(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify Unit ID 1 accesses local Horner OCS %R registers directly."""
        safe_write_word(gateway_engine.register_table, "%R250", 12345)
        c = gateway_engine.connect_client("192.168.1.10", 50201)

        adu = ModbusTcpAdu.create_read_holding_registers(transaction_id=1, unit_id=1, start_address=250, count=1)
        gateway_engine.enqueue_request(c.client_id, adu)
        tx = gateway_engine.process_next_transaction()

        assert tx is not None and tx.response_adu is not None
        assert tx.response_adu.function_code == FC_READ_HOLDING_REGISTERS
        val = struct.unpack(">H", tx.response_adu.pdu_data[1:3])[0]
        assert val == 12345

    def test_downstream_virtual_device_routing(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify Unit ID 2 routes to FlowTransmitter_FT101 downstream node."""
        c = gateway_engine.connect_client("192.168.1.10", 50201)
        # Unit ID 2 register 100 has default 1250
        adu = ModbusTcpAdu.create_read_holding_registers(transaction_id=10, unit_id=2, start_address=100, count=1)
        gateway_engine.enqueue_request(c.client_id, adu)
        tx = gateway_engine.process_next_transaction()

        assert tx is not None and tx.response_adu is not None
        val = struct.unpack(">H", tx.response_adu.pdu_data[1:3])[0]
        assert val == 1250


# ============================================================================
# 6. Socket Timeout Surveillance (> 50.0 ms) & Lifecycle Transitions
# ============================================================================

class TestSection6SocketTimeoutSurveillance:
    """Tests for socket timeout surveillance (> 50.0 ms) and connection lifecycle."""

    def test_nominal_round_trip_latency_tracking(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify nominal latency (1.5 ms) is scaled x10 (15) into %R1362."""
        c = gateway_engine.connect_client("192.168.1.10", 50201)
        adu = ModbusTcpAdu.create_read_holding_registers(transaction_id=1, unit_id=1, start_address=1, count=1)
        gateway_engine.enqueue_request(c.client_id, adu, simulated_latency_ms=1.5)
        gateway_engine.process_next_transaction(simulated_latency_override_ms=1.5)

        assert gateway_engine.last_round_trip_latency_ms == pytest.approx(1.5, rel=1e-3)
        assert gateway_engine.register_table.read_word("%R1362") == 15
        assert gateway_engine.permissive is True
        assert gateway_engine.fault_trip is False

    def test_latency_exceeding_50ms_trips_c802(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify transaction latency > 50.0 ms trips 0xC802, de-asserts %M317, and asserts %M318."""
        c = gateway_engine.connect_client("192.168.1.10", 50201)
        adu = ModbusTcpAdu.create_read_holding_registers(transaction_id=2, unit_id=1, start_address=1, count=1)
        gateway_engine.enqueue_request(c.client_id, adu, simulated_latency_ms=55.0)
        tx = gateway_engine.process_next_transaction(simulated_latency_override_ms=55.0)

        assert tx is not None
        assert tx.status == TransactionStatus.TIMED_OUT
        assert gateway_engine.fault_trip is True
        assert gateway_engine.permissive is False
        assert gateway_engine.diagnostic_code == ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_TRANSACTION_TIMEOUT
        assert gateway_engine.register_table.read_uword("%R1367") == 0xC802
        assert gateway_engine.register_table.read_bit("%M318") is True
        assert gateway_engine.register_table.read_bit("%M317") is False

    def test_socket_timeout_error_counter_increments(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify socket timeout errors increment %R1364."""
        c = gateway_engine.connect_client("192.168.1.10", 50201)
        assert gateway_engine.socket_timeout_error_counter == 0

        adu = ModbusTcpAdu.create_read_holding_registers(transaction_id=1, unit_id=1, start_address=1, count=1)
        gateway_engine.enqueue_request(c.client_id, adu, simulated_latency_ms=60.0)
        gateway_engine.process_next_transaction(simulated_latency_override_ms=60.0)

        assert gateway_engine.socket_timeout_error_counter == 1
        assert gateway_engine.register_table.read_word("%R1364") == 1

    def test_gateway_state_machine_transitions(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify state transitions between LISTENING, MULTIPLEXING, DISPATCHING, and FAULT."""
        assert gateway_engine.state == GatewayState.LISTENING
        c = gateway_engine.connect_client("192.168.1.10", 50201)

        adu = ModbusTcpAdu.create_read_holding_registers(transaction_id=1, unit_id=1, start_address=1, count=1)
        gateway_engine.enqueue_request(c.client_id, adu)
        assert gateway_engine.state == GatewayState.MULTIPLEXING_REQUEST

        gateway_engine.process_next_transaction()
        assert gateway_engine.state == GatewayState.LISTENING

        gateway_engine.trigger_fault(ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_TRANSACTION_TIMEOUT)
        assert gateway_engine.state == GatewayState.GATEWAY_FAULT

    def test_scan_cycle_timeout_advancement(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify scan_step advances internal simulation clock."""
        t0 = gateway_engine.elapsed_time_ms
        gateway_engine.scan_step(dt=0.010)
        assert gateway_engine.elapsed_time_ms == pytest.approx(t0 + 10.0, rel=1e-3)


# ============================================================================
# 7. Process Safety Trips (0xC801..0xC804) & Horner Coils (%M317, %M318)
# ============================================================================

class TestSection7ProcessSafetyTrips:
    """Tests for safety interlock trips, coils %M317/%M318, and latched reset."""

    def test_trip_c801_client_overflow(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Trip 0xC801: Client pool capacity overflow (> 16)."""
        gateway_engine.trigger_fault(ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_CLIENT_OVERFLOW)
        assert gateway_engine.diagnostic_code == 0xC801
        assert gateway_engine.register_table.read_uword("%R1367") == 0xC801
        assert gateway_engine.register_table.read_bit("%M318") is True
        assert gateway_engine.register_table.read_bit("%M317") is False

    def test_trip_c802_transaction_timeout(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Trip 0xC802: Transaction round-trip timeout (> 50.0 ms)."""
        gateway_engine.trigger_fault(ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_TRANSACTION_TIMEOUT)
        assert gateway_engine.diagnostic_code == 0xC802
        assert gateway_engine.register_table.read_uword("%R1367") == 0xC802
        assert gateway_engine.register_table.read_bit("%M318") is True
        assert gateway_engine.register_table.read_bit("%M317") is False

    def test_trip_c803_malformed_mbap(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Trip 0xC803: Malformed MBAP header or invalid protocol ID."""
        c = gateway_engine.connect_client("192.168.1.10", 50201)
        bad_mbap = struct.pack(">HHHB", 1, 0x0001, 2, 1) + bytes([FC_READ_HOLDING_REGISTERS])
        res = gateway_engine.enqueue_request(c.client_id, bad_mbap)

        assert res.status == AgentStatus.FAILED
        assert gateway_engine.diagnostic_code == 0xC803
        assert gateway_engine.register_table.read_uword("%R1367") == 0xC803
        assert gateway_engine.register_table.read_bit("%M318") is True
        assert gateway_engine.register_table.read_bit("%M317") is False

    def test_trip_c804_unit_id_unreachable(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Trip 0xC804: Destination Unit ID unreachable or not mapped."""
        c = gateway_engine.connect_client("192.168.1.10", 50201)
        # Unit ID 5 is configured unreachable
        adu = ModbusTcpAdu.create_read_holding_registers(transaction_id=1, unit_id=5, start_address=100, count=1)
        gateway_engine.enqueue_request(c.client_id, adu)
        gateway_engine.process_next_transaction()

        assert gateway_engine.diagnostic_code == 0xC804
        assert gateway_engine.register_table.read_uword("%R1367") == 0xC804
        assert gateway_engine.register_table.read_bit("%M318") is True
        assert gateway_engine.register_table.read_bit("%M317") is False

    def test_safety_latch_persists_across_scan_steps(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify latched fault condition persists until explicit reset."""
        gateway_engine.trigger_fault(ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_CLIENT_OVERFLOW)
        assert gateway_engine.fault_trip is True

        for _ in range(5):
            gateway_engine.scan_step(dt=0.001)
            assert gateway_engine.fault_trip is True
            assert gateway_engine.permissive is False

    def test_manual_operator_reset_restores_permissive(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify reset_fault restores permissive coil %M317 and clears %M318."""
        gateway_engine.trigger_fault(ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_TRANSACTION_TIMEOUT)
        assert gateway_engine.fault_trip is True

        res = gateway_engine.reset_fault(force=True)
        assert res.status == AgentStatus.SUCCESS
        assert gateway_engine.fault_trip is False
        assert gateway_engine.permissive is True
        assert gateway_engine.diagnostic_code == ModbusTcpGatewayDiagnosticCode.OK
        assert gateway_engine.register_table.read_uword("%R1367") == 0x0000
        assert gateway_engine.register_table.read_bit("%M318") is False
        assert gateway_engine.register_table.read_bit("%M317") is True


# ============================================================================
# 8. Horner OCS Register Space Synchronization & PrivilegeMode.SYSTEM
# ============================================================================

class TestSection8RegisterSpaceSynchronization:
    """Tests for %R1360..%R1367 and %M317..%M318 Horner register bindings."""

    def test_register_space_layout_initial(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify initial register values across %R1360..%R1367 and %M317..%M318."""
        rt = gateway_engine.register_table
        # %R1360: ActiveTcpClientsCount (0)
        assert rt.read_word("%R1360") == 0
        # %R1361: TransactionIdTrackingWord (0)
        assert rt.read_uword("%R1361") == 0
        # %R1362: GatewayRoundTripLatencyMsScaled (15 = 1.5 ms)
        assert rt.read_word("%R1362") == 15
        # %R1363: MultiplexerQueueDepth (0)
        assert rt.read_word("%R1363") == 0
        # %R1364: SocketTimeoutErrorCounter (0)
        assert rt.read_word("%R1364") == 0
        # %R1365: GatewayStateWord (Listening and Permissive)
        state_word = rt.read_word("%R1365")
        assert (state_word & int(GatewayStateBits.LISTENER_ACTIVE)) != 0
        assert (state_word & int(GatewayStateBits.PERMISSIVE)) != 0
        # %R1366: ClientIpAndUnitIdWord
        assert rt.read_uword("%R1366") == encode_client_ip_unit_id_word("127.0.0.1", 1)
        # %R1367: DiagnosticStatusCode (0x0000)
        assert rt.read_uword("%R1367") == 0
        # Discrete coils
        assert rt.read_bit("%M317") is True
        assert rt.read_bit("%M318") is False

    def test_system_privilege_mode_enforced(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify safe write helpers use PrivilegeMode.SYSTEM."""
        rt = gateway_engine.register_table
        safe_write_word(rt, "%R1362", 20)
        safe_write_uword(rt, "%R1361", 500)
        safe_write_bit(rt, "%M317", True)

        assert rt.read_word("%R1362") == 20
        assert rt.read_uword("%R1361") == 500
        assert rt.read_bit("%M317") is True

    def test_gateway_state_word_bitmask_flags(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify bitmask flags update dynamically on client connections and fault injection."""
        c = gateway_engine.connect_client("192.168.1.50", 50201)
        state_word = gateway_engine.compute_gateway_state_word()
        assert (state_word & int(GatewayStateBits.CLIENT_CONNECTED)) != 0

        # Inject timeout fault
        gateway_engine.trigger_fault(ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_TRANSACTION_TIMEOUT)
        state_fault = gateway_engine.compute_gateway_state_word()
        assert (state_fault & int(GatewayStateBits.FAULT_TRIP)) != 0
        assert (state_fault & int(GatewayStateBits.TRANSACTION_TIMEOUT_FAULT)) != 0


# ============================================================================
# 9. ILogicUnit Interface Compliance & Verification Suite Integration
# ============================================================================

class TestSection9ILogicUnitAndVerificationSuite:
    """Tests verifying simulation engine ILogicUnit interface and 9-stage verification suite."""

    def test_ilogicunit_properties_and_execution(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify name, priority, is_enabled, execute with ScanContext, and reset."""
        assert gateway_engine.name == "modbus_tcp_gateway"
        assert gateway_engine.priority == 95
        assert gateway_engine.is_enabled is True

        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=lambda addr: gateway_engine.register_table.read_register(addr),
            set_register=lambda addr, val: gateway_engine.register_table.write_register(
                addr, val, privilege=PrivilegeMode.SYSTEM
            ),
            get_variable=lambda k, d=None: None,
            set_variable=lambda k, v: None,
            record_fault=lambda fault: None,
        )
        gateway_engine.execute(ctx)
        assert gateway_engine.elapsed_time_ms >= 10.0

    def test_ilogicunit_reset_lifecycle(self, gateway_engine: ModbusTcpGatewayEngine) -> None:
        """Verify reset restores engine to healthy state."""
        gateway_engine.trigger_fault(ModbusTcpGatewayDiagnosticCode.GATEWAY_ERR_TRANSACTION_TIMEOUT)
        assert gateway_engine.fault_trip is True

        gateway_engine.reset()
        assert gateway_engine.fault_trip is False
        assert gateway_engine.permissive is True
        assert gateway_engine.diagnostic_code == ModbusTcpGatewayDiagnosticCode.OK

    def test_run_modbus_tcp_gateway_verification_suite(self) -> None:
        """Execute 9-stage verification suite, assert all pass, and verify evidence JSON file."""
        with tempfile.TemporaryDirectory() as td:
            output_file = Path(td) / "modbus_tcp_gateway_evidence.json"
            res = run_modbus_tcp_gateway_verification(output_path=output_file)

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
            assert saved["data"]["work_package"] == "W175"
            assert saved["data"]["gate"] == "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation"
            assert saved["data"]["register_map"]["analog_registers"] == "%R1360..%R1367"
            assert saved["data"]["register_map"]["discrete_coils"] == "%M317..%M318"
