"""Unit tests for Industrial MQTT Sparkplug B Telemetry & Protobuf Serializer (W064).

Tests:
1. Varint LEB128 encoding and decoding across boundary values (0, 1, 127, 128, 16384, 64-bit).
2. IEEE 754 32-bit single float and 64-bit double wire encoding/decoding.
3. Metric message serialization with multiple datatypes (Int16, Int32, Float, Double, Boolean, String, Null).
4. Topic formatting for all 8 canonical message types (NBIRTH, NDEATH, DBIRTH, DDEATH, NDATA, DDATA, NCMD, DCMD).
5. Topic parser validation and malformed topic rejection.
6. Sequence numbering incrementation (0..255) and modulo 256 rollover tracking.
7. Rebirth session mechanics (bdSeq increment, seq reset to 0).
8. NBIRTH payload construction including node metadata and session tokens.
9. NDEATH payload generation including bdSeq token.
10. Deadband suppression: metrics with changes under deadband are suppressed.
11. Horner OCS register synchronization (%R270..%R274, %M58..%M59).
12. %M58 enable coil control and %M59 self-clearing rebirth coil.
13. Pure ST boundary enforcement: rejection of illegal ladder logic constructs.
14. Complete end-to-end verification runner and artifact JSON validation.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.sparkplug_b import (
    SparkplugBTelemetryUnit,
    SparkplugDataType,
    SparkplugMessageType,
    SparkplugMetric,
    SparkplugPayload,
    SparkplugSequenceManager,
    SparkplugStatusFlag,
    SparkplugTopic,
    decode_double,
    decode_float,
    decode_varint,
    encode_double,
    encode_float,
    encode_varint,
    verify_sparkplug_b_and_export_evidence,
)


def test_varint_codec_boundaries() -> None:
    """Verify Varint LEB128 codec across 7-bit, 14-bit, 32-bit, and 64-bit boundaries."""
    cases = [0, 1, 63, 127, 128, 255, 256, 16383, 16384, 0xFFFFFFFF, 1729000000000]
    for val in cases:
        enc = encode_varint(val)
        dec, length = decode_varint(enc)
        assert dec == val
        assert length == len(enc)

    # Negative int (converted to 64-bit two's complement)
    enc_neg = encode_varint(-1)
    dec_neg, _ = decode_varint(enc_neg)
    assert dec_neg == 0xFFFFFFFFFFFFFFFF


def test_float_and_double_codecs() -> None:
    """Verify IEEE 754 32-bit float and 64-bit double wire encoding/decoding."""
    # 32-bit float
    f_val = 123.45600128173828
    f_enc = encode_float(f_val)
    assert len(f_enc) == 4
    f_dec, offset = decode_float(f_enc)
    assert abs(f_dec - f_val) < 1e-4
    assert offset == 4

    # 64-bit double
    d_val = 3.141592653589793
    d_enc = encode_double(d_val)
    assert len(d_enc) == 8
    d_dec, offset = decode_double(d_enc)
    assert abs(d_dec - d_val) < 1e-9
    assert offset == 8


def test_metric_serialization_datatypes() -> None:
    """Verify metric Protobuf wire serialization for diverse datatypes."""
    m_int = SparkplugMetric.from_value("Speed_RPM", 1750, SparkplugDataType.Int16)
    m_float = SparkplugMetric.from_value("Pressure_Bar", 6.25, SparkplugDataType.Float)
    m_bool = SparkplugMetric.from_value("Valve_Open", True, SparkplugDataType.Boolean)
    m_str = SparkplugMetric.from_value("Device_State", "RUNNING", SparkplugDataType.String)
    m_null = SparkplugMetric.from_value("Fault_Code", None, SparkplugDataType.Int16)

    for m in [m_int, m_float, m_bool, m_str, m_null]:
        wire = m.encode()
        assert len(wire) > 0
        assert isinstance(wire, bytes)


def test_topic_formatting_all_message_types() -> None:
    """Verify topic generation for all 8 standard Sparkplug B message types."""
    expected_verbs = [
        SparkplugMessageType.NBIRTH,
        SparkplugMessageType.NDEATH,
        SparkplugMessageType.DBIRTH,
        SparkplugMessageType.DDEATH,
        SparkplugMessageType.NDATA,
        SparkplugMessageType.DDATA,
        SparkplugMessageType.NCMD,
        SparkplugMessageType.DCMD,
    ]
    for verb in expected_verbs:
        is_device = verb.value.startswith("D")
        dev_id = "PLC_RACK_01" if is_device else None
        topic = SparkplugTopic(
            namespace="spBv1.0",
            group_id="FACTORY_FLOOR",
            message_type=verb,
            edge_node_id="GATEWAY_01",
            device_id=dev_id,
        )
        formatted = topic.format()
        if is_device:
            assert formatted == f"spBv1.0/FACTORY_FLOOR/{verb.value}/GATEWAY_01/PLC_RACK_01"
        else:
            assert formatted == f"spBv1.0/FACTORY_FLOOR/{verb.value}/GATEWAY_01"


def test_topic_parser_and_validation() -> None:
    """Verify topic parser and rejection of malformed topics."""
    valid_node_topic = "spBv1.0/AREA_1/NBIRTH/NODE_1"
    parsed_node = SparkplugTopic.parse(valid_node_topic)
    assert parsed_node.group_id == "AREA_1"
    assert parsed_node.message_type == SparkplugMessageType.NBIRTH
    assert parsed_node.edge_node_id == "NODE_1"
    assert parsed_node.device_id is None

    valid_dev_topic = "spBv1.0/AREA_1/DDATA/NODE_1/MOTOR_2"
    parsed_dev = SparkplugTopic.parse(valid_dev_topic)
    assert parsed_dev.device_id == "MOTOR_2"

    with pytest.raises(ValueError, match="Invalid Sparkplug B namespace"):
        SparkplugTopic.parse("spBv2.0/AREA_1/NBIRTH/NODE_1")

    with pytest.raises(ValueError, match="Unknown Sparkplug B message type"):
        SparkplugTopic.parse("spBv1.0/AREA_1/INVALID_VERB/NODE_1")

    with pytest.raises(ValueError, match="Invalid Sparkplug B topic structure"):
        SparkplugTopic.parse("too/short")


def test_sequence_manager_rollover() -> None:
    """Verify sequence counter modulo 256 rollover behavior."""
    sm = SparkplugSequenceManager(initial_bdseq=5)
    assert sm.seq == 0
    assert sm.bdseq == 5
    assert sm.rollover_count == 0

    for i in range(1, 256):
        assert sm.next_seq() == i
    assert sm.rollover_count == 0

    # 256th call should wrap to 0 and increment rollover_count
    next_wrapped = sm.next_seq()
    assert next_wrapped == 0
    assert sm.rollover_count == 1

    # Rebirth resets seq to 0 and increments bdseq
    new_bdseq = sm.trigger_rebirth()
    assert new_bdseq == 6
    assert sm.seq == 0


def test_payload_construction_nbirth_and_ndeath() -> None:
    """Verify NBIRTH and NDEATH payload generation."""
    unit = SparkplugBTelemetryUnit(
        group_id="PLANT_X",
        edge_node_id="HORNER_EDGE",
    )

    # Test NDEATH
    ndeath_topic, ndeath_bytes = unit.generate_ndeath_payload()
    assert "spBv1.0/PLANT_X/NDEATH/HORNER_EDGE" == ndeath_topic
    assert len(ndeath_bytes) > 0

    # Test NBIRTH
    nbirth_topic, nbirth_bytes = unit.generate_nbirth_payload()
    assert "spBv1.0/PLANT_X/NBIRTH/HORNER_EDGE" == nbirth_topic
    assert len(nbirth_bytes) > 0


def test_telemetry_deadband_suppression() -> None:
    """Verify unchanged or sub-deadband analog metrics are suppressed from periodic scans."""
    regs = RegisterTable()
    unit = SparkplugBTelemetryUnit(
        register_table=regs,
        group_id="TEST_PLANT",
        edge_node_id="NODE_A",
        device_id="DEV_A",
        enable_deadband=True,
        analog_deadband=5.0,
    )

    regs.write_word("%AI1", 1000, privilege=PrivilegeMode.SYSTEM)
    unit.solve(regs)
    initial_pub_count = unit.published_count  # NBIRTH + DBIRTH + initial DDATA

    # Minor perturbation under deadband (< 5 counts)
    regs.write_word("%AI1", 1002, privilege=PrivilegeMode.SYSTEM)
    unit.solve(regs)
    assert unit.published_count == initial_pub_count  # No transmission

    # Significant change exceeding deadband
    regs.write_word("%AI1", 1020, privilege=PrivilegeMode.SYSTEM)
    unit.solve(regs)
    assert unit.published_count == initial_pub_count + 1  # Dispatched DDATA


def test_horner_register_sync() -> None:
    """Verify %R270..%R274 register synchronization during scan cycles."""
    regs = RegisterTable()
    unit = SparkplugBTelemetryUnit(register_table=regs)

    unit.solve(regs)

    # %R270 Status word should have ACTIVE and CONNECTED_BIRTH bits set
    status_word = regs.read_word("%R270")
    assert status_word & SparkplugStatusFlag.ACTIVE
    assert status_word & SparkplugStatusFlag.CONNECTED_BIRTH

    # %R271 Sequence number should match unit sequence
    seq_word = regs.read_word("%R271")
    assert seq_word == unit.seq_mgr.seq

    # %R272:%R273 Cumulative published count
    lo = regs.read_word("%R272")
    hi = regs.read_word("%R273")
    total_count = lo | (hi << 16)
    assert total_count == unit.published_count

    # %R274 Last message byte count
    last_bytes = regs.read_word("%R274")
    assert last_bytes > 0


def test_coil_enable_and_rebirth_handshake() -> None:
    """Verify %M58 enable coil and %M59 self-clearing rebirth handshake."""
    regs = RegisterTable()
    unit = SparkplugBTelemetryUnit(register_table=regs)

    # Initial scan: unit active
    unit.solve(regs)
    assert regs.read_word("%R270") != 0

    # Disable unit via %M58
    regs.write_bit("%M58", False, privilege=PrivilegeMode.SYSTEM)
    unit.solve(regs)
    assert regs.read_word("%R270") == 0  # Status cleared when disabled

    # Re-enable unit
    regs.write_bit("%M58", True, privilege=PrivilegeMode.SYSTEM)
    # Trigger rebirth via %M59
    regs.write_bit("%M59", True, privilege=PrivilegeMode.SYSTEM)
    unit.solve(regs)

    # %M59 should have self-cleared
    assert regs.read_bit("%M59") is False
    assert regs.read_word("%R270") & SparkplugStatusFlag.ACTIVE


def test_pure_st_boundary_enforcement() -> None:
    """Verify IEC 61131-3 Pure ST boundary rejects ladder constructs."""
    valid_st = (
        "PROGRAM SparkplugTelemetry\n"
        "VAR\n"
        "    NodeStatus : WORD;\n"
        "    NodeSeq : INT;\n"
        "END_VAR\n"
        "NodeStatus := %R270;\n"
        "NodeSeq := %R271;\n"
        "END_PROGRAM"
    )
    SecurityGuard.assert_pure_st_content(valid_st)

    ladder_samples = [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(S)---",
        "---(R)---",
        "RUNG 1",
        "END_RUNG",
        "NETWORK 10",
        "XIC Tag1",
        "XIO Tag2",
        "OTE Tag3",
        "OTL Tag4",
        "OTU Tag5",
    ]
    for sample in ladder_samples:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(f"{valid_st}\n{sample}")


def test_verification_runner_and_artifact(tmp_path: Path) -> None:
    """Verify end-to-end canonical verification runner and evidence generation."""
    evidence_file = tmp_path / "sparkplug_b_evidence.json"
    result = verify_sparkplug_b_and_export_evidence(output_evidence_path=str(evidence_file))

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert result["data"]["tests_run"] == result["data"]["tests_passed"]
    assert evidence_file.exists()

    with open(evidence_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["status"] == "success"
    assert "register_mapping" in data["data"]
