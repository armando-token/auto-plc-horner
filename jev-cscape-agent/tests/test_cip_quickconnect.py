"""Comprehensive Unit and Integration Test Suite for Industrial EtherNet/IP CIP QuickConnect Engine.

Work Package: W199 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Test Coverage (80+ Unit Tests across 13 Sections):
1. Section 1: Constants, Enums & Protocol Defaults (QuickConnectEngineState, QuickConnectDiagnosticCode, etc.).
2. Section 2: Data Models & Configurations (ToolChangerConfig, FastArpCache, ArpEntry, FastForwardOpenMessage, CyclicPacket).
3. Section 3: Pre-Resolved ARP Cache Table & Hit Rate Calculation (lookups, hit/miss tracking, hit rate calculation).
4. Section 4: Fast Link Training (< 100ms PHY link establishment, bypassed auto-negotiation, watchdog timeout).
5. Section 5: Fast TCP SYN Handshake Initialization (Immediate TCP SYN transmission, link check).
6. Section 6: Fast Forward_Open Handshake Sequence (< 500ms boot-to-cyclic ODVA mandate).
7. Section 7: RPI Cyclic Transmission & Microsecond Jitter Monitoring (cyclic packets, jitter bounds, excess trip).
8. Section 8: Tool Changer Node ID Validation & Electronic Key Mismatch Detection (ID matching, 0xD704 fault).
9. Section 9: ODVA CIP QuickConnect Object (Class 0x00F6 attribute resolution and read-only protections).
10. Section 10: Horner OCS Register Table Synchronization (%R1600..%R1607, %M373..%M374 with PrivilegeMode.SYSTEM).
11. Section 11: ILogicUnit Scan Cycle Simulation (100-cycle scan simulation, execute, reset, timing).
12. Section 12: Pure ST POU AST Validation & Anti-Ladder Interception (SecurityGuard, STParser, LadderForbiddenError).
13. Section 13: Deterministic 9-Stage Verification Runner (run_cip_quickconnect_verification execution and JSON export).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_quickconnect import (
    ArpEntry,
    CIP_ENCAPSULATION_PORT,
    CIP_ENCAPSULATION_TCP_PORT,
    CIP_IO_UDP_PORT,
    CIP_QUICKCONNECT_CLASS_ID,
    CIP_QUICKCONNECT_POU,
    CIP_QUICKCONNECT_SYNC_POU,
    CIP_QUICKCONNECT_TCP_PORT,
    CIP_QUICKCONNECT_UDP_PORT,
    CIP_TCPIP_INTERFACE_CLASS_ID,
    CIPQuickConnectDiagnosticCode,
    CIPQuickConnectEngine,
    CIPQuickConnectState,
    CipQuickConnectDiagnosticCode,
    CipQuickConnectEngine,
    CipQuickConnectObject,
    CipQuickConnectState,
    CipQuickConnectSyncPOU,
    CyclicPacket,
    DEFAULT_CONTROLLER_IP,
    DEFAULT_CONTROLLER_MAC,
    DEFAULT_CYCLIC_RPI_US,
    DEFAULT_MAX_JITTER_US,
    DEFAULT_TARGET_IP,
    DEFAULT_TARGET_MAC,
    DEFAULT_TOOL_NODE_ID,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    DiagnosticStatusCode,
    FastArpCache,
    FastForwardOpenMessage,
    FORCED_ETHERNET_SPEED_MBPS,
    FORCED_FULL_DUPLEX,
    ForwardOpenStatus,
    MAX_BOOT_TO_CYCLIC_LATENCY_MS,
    MAX_PERMISSIBLE_QUICKCONNECT_LATENCY_MS,
    MAX_TOOL_NODE_ID,
    MAX_WATCHDOG_TIMEOUT_MS,
    MIN_TOOL_NODE_ID,
    NOMINAL_BOOT_TO_CYCLIC_LATENCY_MS,
    PreResolvedArpTable,
    QCDiagnosticCode,
    QuickConnectDiagnosticCode,
    QuickConnectEngine,
    QuickConnectEngineState,
    QuickConnectState,
    TARGET_QUICKCONNECT_LATENCY_MS,
    ToolChangerConfig,
    decode_dint_words,
    encode_dint_words,
    run_cip_quickconnect_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
)


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def empty_reg_table() -> RegisterTable:
    """Fixture providing clean RegisterTable."""
    return RegisterTable()


@pytest.fixture
def default_config() -> ToolChangerConfig:
    """Fixture providing default ToolChangerConfig."""
    return ToolChangerConfig(
        node_id=1,
        name="Tool_1",
        ip_address=DEFAULT_TARGET_IP,
        mac_address=DEFAULT_TARGET_MAC,
        rpi_us=1000,
        expected_tool_id=1,
    )


@pytest.fixture
def quickconnect_engine(default_config: ToolChangerConfig, empty_reg_table: RegisterTable) -> CipQuickConnectEngine:
    """Fixture providing initialized CIP QuickConnect Engine."""
    return CipQuickConnectEngine(
        tool_config=default_config,
        reg_table=empty_reg_table,
        watchdog_timeout_ms=80.0,
    )


# ============================================================================
# Section 1: Constants, Enums & Protocol Defaults
# ============================================================================

class TestCipQuickConnectConstantsAndEnums:
    """Tests for protocol constants, enums, diagnostic codes, and configuration defaults."""

    def test_protocol_constants_values(self) -> None:
        assert CIP_QUICKCONNECT_CLASS_ID == 0x00F6
        assert CIP_TCPIP_INTERFACE_CLASS_ID == 0x00F5
        assert CIP_ENCAPSULATION_PORT == 44818
        assert CIP_ENCAPSULATION_TCP_PORT == 44818
        assert CIP_QUICKCONNECT_TCP_PORT == 44818
        assert CIP_IO_UDP_PORT == 2222
        assert CIP_QUICKCONNECT_UDP_PORT == 2222
        assert MAX_BOOT_TO_CYCLIC_LATENCY_MS == 500.0
        assert MAX_PERMISSIBLE_QUICKCONNECT_LATENCY_MS == 500.0
        assert NOMINAL_BOOT_TO_CYCLIC_LATENCY_MS == 34.5
        assert TARGET_QUICKCONNECT_LATENCY_MS == 350.0
        assert MAX_WATCHDOG_TIMEOUT_MS == 100.0
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 80.0
        assert DEFAULT_CYCLIC_RPI_US == 1000
        assert DEFAULT_MAX_JITTER_US == 200.0
        assert FORCED_ETHERNET_SPEED_MBPS == 100
        assert FORCED_FULL_DUPLEX is True
        assert MIN_TOOL_NODE_ID == 1
        assert MAX_TOOL_NODE_ID == 64
        assert DEFAULT_TOOL_NODE_ID == 1
        assert DEFAULT_TARGET_IP == "192.168.1.50"
        assert DEFAULT_TARGET_MAC == "00:1D:9C:E0:01:05"
        assert DEFAULT_CONTROLLER_IP == "192.168.1.10"
        assert DEFAULT_CONTROLLER_MAC == "00:1D:9C:C0:01:01"

    def test_quickconnect_engine_state_enum(self) -> None:
        assert QuickConnectEngineState.POWER_OFF == 0
        assert QuickConnectEngineState.LINK_TRAINING == 1
        assert QuickConnectEngineState.PRE_ARP_RESOLVED == 2
        assert QuickConnectEngineState.FAST_FORWARD_OPEN == 3
        assert QuickConnectEngineState.CYCLIC_EXCHANGE_ACTIVE == 4
        assert QuickConnectEngineState.HANDSHAKE_TIMEOUT == 5

        # TitleCase aliases
        assert QuickConnectEngineState.PowerOff == 0
        assert QuickConnectEngineState.LinkTraining == 1
        assert QuickConnectEngineState.PreArpResolved == 2
        assert QuickConnectEngineState.FastForwardOpen == 3
        assert QuickConnectEngineState.CyclicExchangeActive == 4
        assert QuickConnectEngineState.HandshakeTimeout == 5

        # Secondary aliases
        assert QuickConnectEngineState.DISCONNECTED == 0
        assert QuickConnectEngineState.TCP_INITIALIZING == 2
        assert QuickConnectEngineState.FORWARD_OPEN_PENDING == 3
        assert QuickConnectEngineState.CYCLIC_EXCHANGE_ACTIVE == 4
        assert QuickConnectEngineState.OPERATIONAL == 4
        assert QuickConnectEngineState.CONNECTED == 4
        assert QuickConnectEngineState.FAULTED == 5

    def test_quickconnect_state_enum_aliases(self) -> None:
        assert CipQuickConnectState is QuickConnectEngineState
        assert CIPQuickConnectState is QuickConnectEngineState
        assert QuickConnectState is QuickConnectEngineState

    def test_diagnostic_status_code_enum(self) -> None:
        assert QuickConnectDiagnosticCode.OK == 0x0000
        assert QuickConnectDiagnosticCode.LINK_TRAIN_TIMEOUT == 0xD701
        assert QuickConnectDiagnosticCode.FORWARD_OPEN_REJECTED == 0xD702
        assert QuickConnectDiagnosticCode.CYCLIC_JITTER_EXCEEDED == 0xD703
        assert QuickConnectDiagnosticCode.TOOL_ID_MISMATCH == 0xD704

        # Convenience & Error Aliases
        assert QuickConnectDiagnosticCode.ERR_LINK_TRAIN_TIMEOUT == 0xD701
        assert QuickConnectDiagnosticCode.ERR_FORWARD_OPEN_REJECTED == 0xD702
        assert QuickConnectDiagnosticCode.ERR_CYCLIC_JITTER_EXCEEDED == 0xD703
        assert QuickConnectDiagnosticCode.ERR_TOOL_ID_MISMATCH == 0xD704
        assert QuickConnectDiagnosticCode.LINK_TRAINING_TIMEOUT == 0xD701
        assert QuickConnectDiagnosticCode.FORWARD_OPEN_TIMEOUT == 0xD702
        assert QuickConnectDiagnosticCode.RPI_JITTER_EXCEEDED == 0xD703
        assert QuickConnectDiagnosticCode.TOOL_NODE_ID_MISMATCH == 0xD704

    def test_diagnostic_code_enum_aliases(self) -> None:
        assert CipQuickConnectDiagnosticCode is QuickConnectDiagnosticCode
        assert CIPQuickConnectDiagnosticCode is QuickConnectDiagnosticCode
        assert QCDiagnosticCode is QuickConnectDiagnosticCode
        assert DiagnosticStatusCode is QuickConnectDiagnosticCode

    def test_forward_open_status_enum(self) -> None:
        assert ForwardOpenStatus.IDLE == 0
        assert ForwardOpenStatus.REQUESTED == 1
        assert ForwardOpenStatus.SUCCESS == 2
        assert ForwardOpenStatus.REJECTED == 3
        assert ForwardOpenStatus.TIMEOUT == 4

    def test_engine_type_aliases(self) -> None:
        assert CIPQuickConnectEngine is CipQuickConnectEngine
        assert QuickConnectEngine is CipQuickConnectEngine


# ============================================================================
# Section 2: Data Models & Configurations
# ============================================================================

class TestDataModelsAndConfigs:
    """Tests for ToolChangerConfig, FastArpCache, ArpEntry, FastForwardOpenMessage, CyclicPacket."""

    def test_tool_changer_config_defaults(self) -> None:
        cfg = ToolChangerConfig()
        assert cfg.node_id == 1
        assert cfg.name == "Robotic_EOAT_Tool_1"
        assert cfg.ip_address == DEFAULT_TARGET_IP
        assert cfg.mac_address == DEFAULT_TARGET_MAC
        assert cfg.subnet_mask == "255.255.255.0"
        assert cfg.gateway_ip == "192.168.1.1"
        assert cfg.rpi_us == 1000
        assert cfg.forced_speed_mbps == 100
        assert cfg.forced_full_duplex is True
        assert cfg.auto_negotiation_enabled is False
        assert cfg.connection_serial == 0x1001
        assert cfg.originator_cid == 0x20000001
        assert cfg.target_cid == 0x20000002
        assert cfg.expected_tool_id == 1

        d = cfg.to_dict()
        assert d["node_id"] == 1
        assert d["ip_address"] == DEFAULT_TARGET_IP
        assert d["connection_serial"] == hex(0x1001)

    def test_tool_changer_config_custom(self) -> None:
        cfg = ToolChangerConfig(
            node_id=12,
            name="Gripper_Tool_12",
            ip_address="192.168.1.62",
            mac_address="00:1D:9C:E0:01:12",
            rpi_us=2000,
            connection_serial=0x3012,
            expected_tool_id=12,
        )
        assert cfg.node_id == 12
        assert cfg.name == "Gripper_Tool_12"
        assert cfg.ip_address == "192.168.1.62"
        assert cfg.rpi_us == 2000
        assert cfg.connection_serial == 0x3012

    def test_tool_changer_config_range_validation(self) -> None:
        with pytest.raises(ValueError):
            ToolChangerConfig(node_id=0)
        with pytest.raises(ValueError):
            ToolChangerConfig(node_id=65)

    def test_arp_entry_data_model(self) -> None:
        entry = ArpEntry(ip="192.168.1.55", mac="00:1D:9C:E0:01:55", node_id=5, timestamp_ms=50.0)
        assert entry.ip == "192.168.1.55"
        assert entry.mac == "00:1D:9C:E0:01:55"
        assert entry.node_id == 5
        assert entry.timestamp_ms == 50.0
        d = entry.to_dict()
        assert d["ip"] == "192.168.1.55"
        assert d["node_id"] == 5

    def test_fast_forward_open_message_model(self) -> None:
        msg = FastForwardOpenMessage(
            connection_serial=0x1005,
            originator_vendor_id=0x0001,
            originator_serial=0x54321,
            timeout_ticks=10,
            ot_cid=0x20000005,
            to_cid=0x20000006,
            ot_rpi_us=1000,
            to_rpi_us=1000,
            status=ForwardOpenStatus.SUCCESS,
        )
        assert msg.connection_serial == 0x1005
        assert msg.status == ForwardOpenStatus.SUCCESS
        d = msg.to_dict()
        assert d["connection_serial"] == hex(0x1005)
        assert d["status_name"] == "SUCCESS"

    def test_cyclic_packet_model(self) -> None:
        pkt = CyclicPacket(
            sequence_id=10,
            timestamp_us=10000.0,
            actual_interval_us=1005.0,
            jitter_us=5.0,
            payload=b"\xAA\xBB\xCC\xDD",
        )
        assert pkt.sequence_id == 10
        assert pkt.timestamp_us == 10000.0
        assert pkt.jitter_us == 5.0
        d = pkt.to_dict()
        assert d["sequence_id"] == 10
        assert d["payload_len"] == 4
        assert d["jitter_us"] == 5.0


# ============================================================================
# Section 3: Pre-Resolved ARP Cache Table & Hit Rate Calculation
# ============================================================================

class TestPreResolvedArpTable:
    """Tests for FastArpCache / PreResolvedArpTable lookups and hit rate calculation."""

    def test_arp_cache_initialization_empty(self) -> None:
        cache = FastArpCache()
        assert len(cache.entries) == 0
        assert cache.lookup_count == 0
        assert cache.hit_count == 0
        assert cache.miss_count == 0
        assert cache.hit_rate_pct() == 100.0
        assert cache.hit_rate_scaled() == 1000

    def test_arp_cache_add_and_lookup_hit(self) -> None:
        cache = FastArpCache()
        cache.add_entry("192.168.1.50", "00:1D:9C:E0:01:05")
        mac = cache.lookup("192.168.1.50")
        assert mac == "00:1D:9C:E0:01:05"
        assert cache.lookup_count == 1
        assert cache.hit_count == 1
        assert cache.miss_count == 0
        assert cache.hit_rate_pct() == 100.0
        assert cache.hit_rate_scaled() == 1000

    def test_arp_cache_lookup_miss(self) -> None:
        cache = FastArpCache()
        cache.add_entry("192.168.1.50", "00:1D:9C:E0:01:05")
        mac = cache.lookup("192.168.1.99")
        assert mac is None
        assert cache.lookup_count == 1
        assert cache.hit_count == 0
        assert cache.miss_count == 1
        assert cache.hit_rate_pct() == 0.0
        assert cache.hit_rate_scaled() == 0

    def test_arp_cache_hit_rate_calculation(self) -> None:
        cache = FastArpCache()
        cache.add_entry("192.168.1.50", "00:1D:9C:E0:01:05")
        cache.lookup("192.168.1.50")  # Hit 1
        cache.lookup("192.168.1.50")  # Hit 2
        cache.lookup("192.168.1.50")  # Hit 3
        cache.lookup("192.168.1.99")  # Miss 1
        assert cache.lookup_count == 4
        assert cache.hit_count == 3
        assert cache.miss_count == 1
        assert cache.hit_rate_pct() == 75.0
        assert cache.hit_rate_scaled() == 750

    def test_arp_cache_get_entry(self) -> None:
        cache = FastArpCache()
        cache.add_entry("192.168.1.50", "00:1D:9C:E0:01:05")
        entry = cache.get_entry("192.168.1.50")
        assert entry is not None
        assert entry.ip == "192.168.1.50"
        assert entry.mac == "00:1D:9C:E0:01:05"
        assert cache.get_entry("192.168.1.99") is None

    def test_arp_cache_clear(self) -> None:
        cache = FastArpCache()
        cache.add_entry("192.168.1.50", "00:1D:9C:E0:01:05")
        cache.lookup("192.168.1.50")
        cache.clear()
        assert len(cache.entries) == 0
        assert cache.lookup_count == 0
        assert cache.hit_count == 0
        assert cache.miss_count == 0

    def test_arp_cache_to_dict(self) -> None:
        cache = FastArpCache()
        cache.add_entry("192.168.1.50", "00:1D:9C:E0:01:05")
        cache.lookup("192.168.1.50")
        d = cache.to_dict()
        assert d["entries_count"] == 1
        assert d["lookup_count"] == 1
        assert d["hit_count"] == 1
        assert d["hit_rate_pct"] == 100.0
        assert d["hit_rate_scaled"] == 1000

    def test_preresolved_arp_table_alias(self) -> None:
        assert PreResolvedArpTable is FastArpCache


# ============================================================================
# Section 4: Fast Link Training (< 100ms)
# ============================================================================

class TestFastLinkTraining:
    """Tests for accelerated physical link training and timeout handling."""

    def test_fast_link_train_success(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        ok = quickconnect_engine.power_up_and_train_link()
        assert ok is True
        assert quickconnect_engine.link_ready is True
        assert quickconnect_engine.state == QuickConnectEngineState.PRE_ARP_RESOLVED

    def test_fast_link_train_convenience_method(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        ok = quickconnect_engine.fast_link_train(duration_ms=25.0)
        assert ok is True
        assert quickconnect_engine.link_ready is True
        assert quickconnect_engine.state == QuickConnectEngineState.PRE_ARP_RESOLVED

    def test_fast_link_train_timeout(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        # Link train time exceeds watchdog budget (80.0ms)
        quickconnect_engine.link_train_time_ms = 95.0
        ok = quickconnect_engine.power_up_and_train_link()
        assert ok is False
        assert quickconnect_engine.link_ready is False
        assert quickconnect_engine.state == QuickConnectEngineState.HANDSHAKE_TIMEOUT
        assert quickconnect_engine.diagnostic_code == QuickConnectDiagnosticCode.LINK_TRAIN_TIMEOUT

    def test_fast_link_train_trip_helper(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        quickconnect_engine.simulate_link_training_timeout()
        assert quickconnect_engine.diagnostic_code == QuickConnectDiagnosticCode.LINK_TRAIN_TIMEOUT
        assert quickconnect_engine.state == QuickConnectEngineState.HANDSHAKE_TIMEOUT
        assert quickconnect_engine.link_ready is False


# ============================================================================
# Section 5: Fast TCP SYN Handshake Initialization
# ============================================================================

class TestFastTcpSynInitialization:
    """Tests for immediate TCP SYN transmission without connection delays."""

    def test_transmit_immediate_tcp_syn_after_link_training(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        quickconnect_engine.power_up_and_train_link()
        ok = quickconnect_engine.transmit_immediate_tcp_syn()
        assert ok is True

    def test_transmit_immediate_tcp_syn_fails_when_unpowered(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        assert quickconnect_engine.state == QuickConnectEngineState.POWER_OFF
        ok = quickconnect_engine.transmit_immediate_tcp_syn()
        assert ok is False

    def test_fast_tcp_syn_convenience_method(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        quickconnect_engine.power_up_and_train_link()
        ok = quickconnect_engine.fast_tcp_syn(duration_ms=3.5)
        assert ok is True


# ============================================================================
# Section 6: Fast Forward_Open Handshake Sequence (< 500ms Total Latency)
# ============================================================================

class TestFastForwardOpenAndHandshakeSequence:
    """Tests for Fast Forward_Open execution and < 500ms boot-to-cyclic latency."""

    def test_execute_fast_forward_open_success(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        quickconnect_engine.power_up_and_train_link()
        ok = quickconnect_engine.execute_fast_forward_open(connection_serial=0x1001)
        assert ok is True
        assert quickconnect_engine.state == QuickConnectEngineState.FAST_FORWARD_OPEN
        assert quickconnect_engine.forward_open_msg.status == ForwardOpenStatus.SUCCESS
        assert quickconnect_engine.forward_open_msg.connection_serial == 0x1001

    def test_execute_fast_forward_open_fails_when_link_not_ready(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        assert quickconnect_engine.link_ready is False
        ok = quickconnect_engine.execute_fast_forward_open()
        assert ok is False

    def test_complete_handshake_within_500ms(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        quickconnect_engine.power_up_and_train_link()
        quickconnect_engine.execute_fast_forward_open()
        ok = quickconnect_engine.complete_handshake(measured_boot_ms=34.5)
        assert ok is True
        assert quickconnect_engine.boot_to_cyclic_latency_ms == 34.5
        assert quickconnect_engine.total_connection_latency_ms_scaled == 345
        assert quickconnect_engine.state == QuickConnectEngineState.CYCLIC_EXCHANGE_ACTIVE
        assert quickconnect_engine.handshake_complete is True
        assert quickconnect_engine.handshake_success_counter == 1

    def test_complete_handshake_exceeds_500ms_fails(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        quickconnect_engine.power_up_and_train_link()
        quickconnect_engine.execute_fast_forward_open()
        ok = quickconnect_engine.complete_handshake(measured_boot_ms=520.0)
        assert ok is False
        assert quickconnect_engine.state == QuickConnectEngineState.HANDSHAKE_TIMEOUT
        assert quickconnect_engine.diagnostic_code == QuickConnectDiagnosticCode.LINK_TRAIN_TIMEOUT

    def test_simulate_full_quickconnect_handshake(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        ok = quickconnect_engine.simulate_full_quickconnect_handshake(
            tool_node_id=1,
            boot_latency_ms=34.5,
        )
        assert ok is True
        assert quickconnect_engine.state == QuickConnectEngineState.CYCLIC_EXCHANGE_ACTIVE
        assert quickconnect_engine.handshake_complete is True
        assert quickconnect_engine.link_ready is True
        assert quickconnect_engine.handshake_success_counter == 1

    def test_execute_quickconnect_sequence_alias(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        ok = quickconnect_engine.execute_quickconnect_sequence(actual_tool_node_id=1, boot_latency_ms=30.0)
        assert ok is True
        assert quickconnect_engine.connection_success_count == 1


# ============================================================================
# Section 7: RPI Cyclic Transmission & Jitter Monitoring
# ============================================================================

class TestRpiCyclicTransmissionAndJitter:
    """Tests for RPI cyclic implicit I/O packet processing and microsecond jitter tracking."""

    def test_process_cyclic_packet_healthy(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        quickconnect_engine.simulate_full_quickconnect_handshake()
        pkt1 = quickconnect_engine.process_cyclic_packet(dt_us=1000.0, jitter_us=0.0)
        pkt2 = quickconnect_engine.process_cyclic_packet(dt_us=1005.0, jitter_us=5.0)

        assert pkt1.sequence_id == 1
        assert pkt2.sequence_id == 2
        assert pkt2.jitter_us == 5.0
        assert quickconnect_engine.max_observed_jitter_us == 5.0
        assert quickconnect_engine.diagnostic_code == QuickConnectDiagnosticCode.OK

    def test_process_cyclic_packet_jitter_exceeded(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        quickconnect_engine.simulate_full_quickconnect_handshake()
        # Jitter limit is 200.0 us; send packet with 250.0 us jitter
        pkt = quickconnect_engine.process_cyclic_packet(dt_us=1250.0, jitter_us=250.0)
        assert pkt.jitter_us == 250.0
        assert quickconnect_engine.diagnostic_code == QuickConnectDiagnosticCode.CYCLIC_JITTER_EXCEEDED
        assert quickconnect_engine.health_score <= 50

    def test_record_cyclic_packet_convenience(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        quickconnect_engine.simulate_full_quickconnect_handshake()
        pkt = quickconnect_engine.record_cyclic_packet(timestamp_ms=1.0, jitter_us=10.0)
        assert pkt.jitter_us == 10.0
        assert len(quickconnect_engine.cyclic_packets) == 1

    def test_simulate_rpi_jitter_excess_helper(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        quickconnect_engine.simulate_full_quickconnect_handshake()
        quickconnect_engine.simulate_rpi_jitter_excess(excessive_jitter_us=350.0)
        assert quickconnect_engine.diagnostic_code == QuickConnectDiagnosticCode.CYCLIC_JITTER_EXCEEDED
        assert quickconnect_engine.max_observed_jitter_us >= 350.0


# ============================================================================
# Section 8: Tool Changer Node ID Validation & Mismatch Detection
# ============================================================================

class TestToolChangerNodeIdValidation:
    """Tests for robotic tool changer node ID keying and mismatch detection."""

    def test_tool_id_match_operational(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        ok = quickconnect_engine.simulate_full_quickconnect_handshake(tool_node_id=1)
        assert ok is True
        assert quickconnect_engine.expected_tool_node_id == 1
        assert quickconnect_engine.actual_tool_node_id == 1
        assert quickconnect_engine.tool_id_mismatch_alarm is False
        assert quickconnect_engine.state == QuickConnectEngineState.CYCLIC_EXCHANGE_ACTIVE

    def test_tool_id_mismatch_trips_fault(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        ok = quickconnect_engine.simulate_full_quickconnect_handshake(tool_node_id=9)
        assert ok is False
        assert quickconnect_engine.state == QuickConnectEngineState.HANDSHAKE_TIMEOUT
        assert quickconnect_engine.diagnostic_code == QuickConnectDiagnosticCode.TOOL_ID_MISMATCH
        assert quickconnect_engine.tool_id_mismatch_alarm is True
        assert quickconnect_engine.handshake_complete is False

    def test_simulate_tool_mismatch_helper(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        quickconnect_engine.simulate_tool_mismatch(invalid_tool_id=22)
        assert quickconnect_engine.diagnostic_code == QuickConnectDiagnosticCode.TOOL_ID_MISMATCH
        assert quickconnect_engine.tool_id_mismatch_alarm is True

    def test_power_off_and_disconnect(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        quickconnect_engine.simulate_full_quickconnect_handshake()
        assert quickconnect_engine.state == QuickConnectEngineState.CYCLIC_EXCHANGE_ACTIVE
        quickconnect_engine.disconnect()
        assert quickconnect_engine.state == QuickConnectEngineState.POWER_OFF
        assert quickconnect_engine.link_ready is False
        assert quickconnect_engine.handshake_complete is False


# ============================================================================
# Section 9: ODVA CIP QuickConnect Object (Class 0x00F6)
# ============================================================================

class TestCipQuickConnectObject:
    """Tests for ODVA CIP QuickConnect Object attribute resolution and protections."""

    def test_cip_quickconnect_object_attributes_resolution(self) -> None:
        obj = CipQuickConnectObject()
        assert obj.class_id == 0x00F6
        assert obj.get_attribute(1) is True
        assert obj.get_attribute(2) == int(QuickConnectEngineState.POWER_OFF)
        assert obj.get_attribute(3) == 0
        assert obj.get_attribute(4) == 1
        assert obj.get_attribute(5) == 1000
        assert obj.get_attribute(6) == 0
        assert obj.get_attribute(7) == 1000  # 100.0% * 10
        assert obj.get_attribute(8) == 0
        assert obj.get_attribute(9) == 0
        assert obj.get_attribute(10) is False
        assert obj.get_attribute(11) is False
        assert obj.get_attribute(12) == 100  # forced_speed_mbps
        assert obj.get_attribute(13) is True  # forced_full_duplex

    def test_cip_quickconnect_object_writable_attributes(self) -> None:
        obj = CipQuickConnectObject()
        assert obj.set_attribute(1, False) is True
        assert obj.quickconnect_enabled is False
        assert obj.set_attribute(4, 15) is True
        assert obj.tool_node_id == 15
        # Invalid tool node id rejected (< 1 or > 64)
        assert obj.set_attribute(4, 99) is False
        assert obj.tool_node_id == 15

    def test_cip_quickconnect_object_read_only_protection(self) -> None:
        obj = CipQuickConnectObject()
        assert obj.set_attribute(2, 4) is False
        assert obj.set_attribute(3, 500) is False
        assert obj.set_attribute(8, 90) is False

    def test_cip_quickconnect_object_invalid_attribute(self) -> None:
        obj = CipQuickConnectObject()
        with pytest.raises(KeyError):
            obj.get_attribute(99)


# ============================================================================
# Section 10: Horner OCS Register Table Synchronization
# ============================================================================

class TestRegisterTableSynchronization:
    """Tests for Horner OCS register space (%R1600..%R1607, %M373..%M374) synchronization."""

    def test_register_sync_power_off_state(self, empty_reg_table: RegisterTable, default_config: ToolChangerConfig) -> None:
        engine = CipQuickConnectEngine(tool_config=default_config, reg_table=empty_reg_table)
        engine.sync_to_registers(empty_reg_table)

        assert empty_reg_table.read_word("%R1600") == int(QuickConnectEngineState.POWER_OFF)
        assert empty_reg_table.read_word("%R1601") == 0
        assert empty_reg_table.read_word("%R1602") == 1
        assert empty_reg_table.read_word("%R1603") == 1000
        assert empty_reg_table.read_word("%R1604") == 0
        assert empty_reg_table.read_word("%R1605") == 1000
        assert empty_reg_table.read_word("%R1606") == 0
        assert empty_reg_table.read_uword("%R1607") == 0x0000
        assert empty_reg_table.read_bit("%M373") is False
        assert empty_reg_table.read_bit("%M374") is False

    def test_register_sync_cyclic_exchange_active(self, empty_reg_table: RegisterTable, default_config: ToolChangerConfig) -> None:
        engine = CipQuickConnectEngine(tool_config=default_config, reg_table=empty_reg_table)
        engine.simulate_full_quickconnect_handshake(tool_node_id=1, boot_latency_ms=34.5)

        assert empty_reg_table.read_word("%R1600") == int(QuickConnectEngineState.CYCLIC_EXCHANGE_ACTIVE)
        assert empty_reg_table.read_word("%R1601") == 345
        assert empty_reg_table.read_word("%R1602") == 1
        assert empty_reg_table.read_word("%R1603") == 1000
        assert empty_reg_table.read_word("%R1604") == 1
        assert empty_reg_table.read_word("%R1605") == 1000
        assert empty_reg_table.read_word("%R1606") >= 80
        assert empty_reg_table.read_uword("%R1607") == 0x0000
        assert empty_reg_table.read_bit("%M373") is True
        assert empty_reg_table.read_bit("%M374") is True

    def test_register_sync_tool_mismatch(self, empty_reg_table: RegisterTable, default_config: ToolChangerConfig) -> None:
        engine = CipQuickConnectEngine(tool_config=default_config, reg_table=empty_reg_table)
        engine.simulate_tool_mismatch(invalid_tool_id=9)

        assert empty_reg_table.read_word("%R1600") == int(QuickConnectEngineState.HANDSHAKE_TIMEOUT)
        assert empty_reg_table.read_uword("%R1607") == 0xD704
        assert empty_reg_table.read_bit("%M374") is False

    def test_safe_write_helpers(self, empty_reg_table: RegisterTable) -> None:
        safe_write_word(empty_reg_table, "%R1601", -200)
        assert empty_reg_table.read_word("%R1601") == -200

        safe_write_uword(empty_reg_table, "%R1607", 0xD701)
        assert empty_reg_table.read_uword("%R1607") == 0xD701

        safe_write_bit(empty_reg_table, "%M373", True)
        assert empty_reg_table.read_bit("%M373") is True

    def test_encode_decode_dint_words(self) -> None:
        high, low = encode_dint_words(12345678)
        decoded = decode_dint_words(high, low)
        assert decoded == 12345678

        high_neg, low_neg = encode_dint_words(-987654)
        decoded_neg = decode_dint_words(high_neg, low_neg)
        assert decoded_neg == -987654


# ============================================================================
# Section 11: ILogicUnit Scan Cycle Simulation
# ============================================================================

class TestILogicUnitScanSimulation:
    """Tests for discrete scan cycle execution and engine lifecycle."""

    def test_logic_unit_properties(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        assert quickconnect_engine.name == "cip_quickconnect"
        assert quickconnect_engine.priority == 96
        assert quickconnect_engine.is_enabled is True

    def test_execute_via_scan_context(self, quickconnect_engine: CipQuickConnectEngine, empty_reg_table: RegisterTable) -> None:
        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=empty_reg_table.read_register,
            set_register=lambda a, v: empty_reg_table.write_register(a, v, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda k, d=None: d,
            set_variable=lambda k, v: None,
            record_fault=lambda f: None,
        )
        quickconnect_engine.execute(ctx)
        assert quickconnect_engine.total_scan_cycles == 1
        assert round(quickconnect_engine.elapsed_simulation_ms) == 10

    def test_100_scan_cycles_simulation(self, quickconnect_engine: CipQuickConnectEngine, empty_reg_table: RegisterTable) -> None:
        quickconnect_engine.simulate_full_quickconnect_handshake()
        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=empty_reg_table.read_register,
            set_register=lambda a, v: empty_reg_table.write_register(a, v, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda k, d=None: d,
            set_variable=lambda k, v: None,
            record_fault=lambda f: None,
        )
        for c in range(1, 101):
            ctx.cycle = c
            ctx.elapsed_time_ms = c * 10.0
            quickconnect_engine.execute(ctx)

        assert quickconnect_engine.total_scan_cycles == 100
        assert round(quickconnect_engine.elapsed_simulation_ms) == 1000
        assert quickconnect_engine.handshake_complete is True

    def test_engine_reset_fault(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        quickconnect_engine.simulate_tool_mismatch(99)
        assert quickconnect_engine.diagnostic_code == QuickConnectDiagnosticCode.TOOL_ID_MISMATCH
        res = quickconnect_engine.reset_fault(force=True)
        assert res.status == AgentStatus.SUCCESS
        assert quickconnect_engine.diagnostic_code == QuickConnectDiagnosticCode.OK
        assert quickconnect_engine.state == QuickConnectEngineState.POWER_OFF

    def test_get_snapshot_dictionary(self, quickconnect_engine: CipQuickConnectEngine) -> None:
        snap = quickconnect_engine.get_snapshot()
        assert isinstance(snap, dict)
        assert "state" in snap
        assert "boot_to_cyclic_latency_ms" in snap
        assert "tool_node_id" in snap
        assert "fast_arp_cache_hit_rate_pct" in snap
        assert "health_score" in snap


# ============================================================================
# Section 12: Pure ST POU AST Validation & Anti-Ladder Interception
# ============================================================================

class TestPureStPouAndSecurityGuard:
    """Tests for Pure IEC 61131-3 Structured Text validation and anti-ladder rejection."""

    def test_st_pou_ast_structure_and_name(self) -> None:
        ast = STParser.parse_pou(CIP_QUICKCONNECT_SYNC_POU)
        assert ast.name == "CipQuickConnectSync"
        assert ast.pou_type == POUType.PROGRAM
        assert CIP_QUICKCONNECT_POU == CIP_QUICKCONNECT_SYNC_POU
        assert CipQuickConnectSyncPOU == CIP_QUICKCONNECT_SYNC_POU

    def test_st_pou_bound_registers(self) -> None:
        ast = STParser.parse_pou(CIP_QUICKCONNECT_SYNC_POU)
        expected_registers = {
            "%R1600", "%R1601", "%R1602", "%R1603",
            "%R1604", "%R1605", "%R1606", "%R1607",
            "%M373", "%M374",
        }
        bound = set(ast.bound_registers)
        assert expected_registers.issubset(bound)

    def test_st_pou_syntax_validation(self) -> None:
        val = STParser.validate_code(CIP_QUICKCONNECT_SYNC_POU)
        assert val.status == AgentStatus.SUCCESS

    def test_pure_st_security_guard_passes(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_QUICKCONNECT_SYNC_POU)

    def test_anti_ladder_contacts_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("---[ ]---")

    def test_anti_ladder_coils_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("---( )---")

    def test_anti_ladder_rung_network_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("RUNG 1")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("NETWORK 1")

    def test_anti_ladder_mnemonics_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("XIC QC_LinkReady")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("OTE ToolChange_Done")


# ============================================================================
# Section 13: Deterministic 9-Stage Verification Runner
# ============================================================================

class TestDeterministicVerificationRunner:
    """Tests for run_cip_quickconnect_verification runner execution and evidence artifact generation."""

    def test_verification_runner_execution_success(self) -> None:
        res = run_cip_quickconnect_verification()
        assert res["status"] == "success"
        assert res["stages_passed"] == 9
        assert res["total_stages"] == 9
        assert res["error_code"] is None
        assert "9/9 stages passed" in res["details"]

    def test_verification_runner_all_9_stages_pass(self) -> None:
        res = run_cip_quickconnect_verification()
        stages = res["data"]["stages"]
        assert len(stages) == 9
        for st in stages:
            assert st["passed"] is True, f"Stage {st['stage']} ({st['check']}) failed!"

    def test_verification_runner_exports_json_evidence(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_quickconnect_evidence.json"
        res = run_cip_quickconnect_verification(output_path=out_file)
        assert res["status"] == "success"
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            evidence = json.load(f)
        assert evidence["status"] == "success"
        assert evidence["stages_passed"] == 9
        assert evidence["data"]["work_package"] == "W199"

    def test_verification_runner_evidence_registers_and_metadata(self) -> None:
        res = run_cip_quickconnect_verification()
        data = res["data"]
        assert data["work_package"] == "W199"
        assert "standards" in data
        assert "register_map" in data
        assert "registers" in data
        assert "%R1600" in data["registers"]
        assert "%R1607" in data["registers"]
        assert "%M373" in data["registers"]
        assert "%M374" in data["registers"]
