"""Unit Tests for Sparkplug B Historical Store-and-Forward Engine (W094).

Gate G8 Telemetry Quality & Industrial Protocol Adapters / Gate G4 Simulation.
"""

from __future__ import annotations

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.sparkplug_store_forward import (
    SFState,
    SpoolPolicy,
    SFErrorCode,
    SFStatusBits,
    SpooledMetric,
    StoreAndForwardConfig,
    SparkplugStoreAndForwardEngine,
    SPARKPLUG_STORE_FORWARD_PURE_ST_POU,
    run_sparkplug_sf_verification,
)


class TestSparkplugStoreForward:
    """Test suite for W094 Sparkplug B Store-and-Forward Engine."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify Pure ST POU validation and AST symbol bindings."""
        SecurityGuard.assert_pure_st_content(SPARKPLUG_STORE_FORWARD_PURE_ST_POU)
        res = STParser.validate_code(SPARKPLUG_STORE_FORWARD_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(SPARKPLUG_STORE_FORWARD_PURE_ST_POU)
        assert ast.name == "SparkplugStoreAndForwardSync"
        assert ast.pou_type == POUType.PROGRAM
        assert "%R550" in ast.bound_registers
        assert "%R557" in ast.bound_registers
        assert "%M128" in ast.bound_registers
        assert "%M129" in ast.bound_registers

    def test_ladder_construct_interception(self) -> None:
        """Verify ladder contacts and coils are intercepted fail-closed."""
        bad_st = """
        PROGRAM LadderSF
        VAR Contact : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_protobuf_serialization_historical_flag(self) -> None:
        """Test binary Protobuf wire serialization with is_historical flag."""
        reg_table = RegisterTable()
        engine = SparkplugStoreAndForwardEngine(register_table=reg_table)

        m_live = SpooledMetric(
            name="Temperature",
            value=85.5,
            datatype=9,
            timestamp_ms=1700000000000,
            is_historical=False,
        )
        proto_live = engine.serialize_metric_protobuf(m_live)
        assert b"\x28\x01" not in proto_live  # Not historical

        m_hist = SpooledMetric(
            name="Temperature",
            value=85.5,
            datatype=9,
            timestamp_ms=1700000000000,
            is_historical=True,
        )
        proto_hist = engine.serialize_metric_protobuf(m_hist)
        assert b"\x28\x01" in proto_hist  # Field 5 varint 1 (is_historical = True)

    def test_offline_spooling_drop_oldest(self) -> None:
        """Test spool buffer queueing and DROP_OLDEST FIFO eviction."""
        cfg = StoreAndForwardConfig(max_capacity=5, spool_policy=SpoolPolicy.DROP_OLDEST)
        engine = SparkplugStoreAndForwardEngine(config=cfg)

        engine.handle_disconnect()
        assert engine.state == SFState.BUFFERING_DISCONNECTED

        # Ingest 5 items (fill buffer)
        for i in range(5):
            assert engine.ingest_metric(f"Tag_{i}", float(i)) is True
        assert len(engine.buffer) == 5
        assert engine.buffer[0].metrics[0].name == "Tag_0"

        # Ingest 6th item -> should evict Tag_0 and keep Tag_5
        assert engine.ingest_metric("Tag_5", 5.0) is True
        assert len(engine.buffer) == 5
        assert engine.buffer[0].metrics[0].name == "Tag_1"
        assert engine.buffer[-1].metrics[0].name == "Tag_5"
        assert engine.dropped_msg_count == 1

    def test_offline_spooling_block_newest(self) -> None:
        """Test spool buffer queueing and BLOCK_NEWEST rejection."""
        cfg = StoreAndForwardConfig(max_capacity=5, spool_policy=SpoolPolicy.BLOCK_NEWEST)
        engine = SparkplugStoreAndForwardEngine(config=cfg)

        engine.handle_disconnect()
        for i in range(5):
            assert engine.ingest_metric(f"Tag_{i}", float(i)) is True

        # Ingest 6th item -> should be rejected
        assert engine.ingest_metric("Tag_5", 5.0) is False
        assert len(engine.buffer) == 5
        assert engine.buffer[0].metrics[0].name == "Tag_0"
        assert engine.buffer[-1].metrics[0].name == "Tag_4"
        assert engine.dropped_msg_count == 1

    def test_reconnection_and_session_birth(self) -> None:
        """Test session reconnect, bdSeq increment, and seq reset."""
        engine = SparkplugStoreAndForwardEngine()
        engine.handle_disconnect()
        engine.ingest_metric("Pressure", 25.0)

        initial_bdseq = engine.bd_seq
        engine.handle_reconnect_start()

        assert engine.broker_connected is True
        assert engine.bd_seq == initial_bdseq + 1
        assert engine.seq == 2  # NBIRTH (0) and DBIRTH (1) consumed
        assert engine.state == SFState.DRAINING_REPLAY

    def test_throttled_historical_replay(self) -> None:
        """Test paced drainage of buffered historical records."""
        cfg = StoreAndForwardConfig(max_capacity=100, default_replay_rate=10)
        engine = SparkplugStoreAndForwardEngine(config=cfg)

        engine.handle_disconnect()
        for i in range(35):
            engine.ingest_metric(f"Sensor_{i}", float(i))

        engine.handle_reconnect_start()
        assert len(engine.buffer) == 35

        # Step 1: drain 10 messages
        b1 = engine.step_replay()
        assert len(b1) == 10
        assert len(engine.buffer) == 25
        assert engine.replayed_msg_count == 10

        # Step 2: drain next 10 messages
        b2 = engine.step_replay()
        assert len(b2) == 10
        assert len(engine.buffer) == 15

        # Step 3 & 4: complete drainage
        engine.step_replay()
        engine.step_replay()
        assert len(engine.buffer) == 0
        assert engine.replayed_msg_count == 35
        assert engine.state == SFState.ONLINE

    def test_drain_time_estimation_calculation(self) -> None:
        """Test calculation of active drain time remaining."""
        cfg = StoreAndForwardConfig(max_capacity=100, default_replay_rate=20)
        engine = SparkplugStoreAndForwardEngine(config=cfg)

        engine.handle_disconnect()
        for i in range(60):
            engine.ingest_metric(f"M_{i}", float(i))

        engine.handle_reconnect_start()
        # 60 messages at 20 msgs/s = 3 seconds
        assert engine.drain_time_remaining == 3

    def test_sequence_number_rollover(self) -> None:
        """Test modulo-256 sequence number rollover."""
        engine = SparkplugStoreAndForwardEngine()
        engine.seq = 254
        assert engine.next_seq() == 254
        assert engine.next_seq() == 255
        assert engine.next_seq() == 0
        assert engine.next_seq() == 1

    def test_horner_ocs_register_synchronization(self) -> None:
        """Test Horner analog registers %R550..%R557 and coils %M128..%M129."""
        reg_table = RegisterTable()
        cfg = StoreAndForwardConfig(max_capacity=100, default_replay_rate=10)
        engine = SparkplugStoreAndForwardEngine(config=cfg, register_table=reg_table)

        engine.handle_disconnect()
        for i in range(85):
            engine.ingest_metric(f"Tag_{i}", float(i))

        assert reg_table.read_word("%R550") == 85
        assert reg_table.read_word("%R551") == 85  # 85%
        assert reg_table.read_word("%R552") == 10  # 10 msgs/s
        assert reg_table.read_bit("%M129") is True  # High water warn >= 80%

        r557 = reg_table.read_word("%R557")
        assert bool(r557 & SFStatusBits.SF_ENABLED)
        assert bool(r557 & SFStatusBits.SPOOLING_ACTIVE)
        assert bool(r557 & SFStatusBits.BUFFER_HIGH_WARN)

    def test_run_verification_runner_end_to_end(self, tmp_path) -> None:
        """Test end-to-end 9-stage verification runner function."""
        ev_file = tmp_path / "sf_evidence.json"
        res = run_sparkplug_sf_verification(evidence_path=str(ev_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert ev_file.exists()
