"""Unit and integration tests for BACnet/IP Telemetry Protocol Engine.

Work Package: W076 (Gate G8 / G4)
Verifies:
- BVLL framing (Type 0x81, Unicast, Broadcast, Forwarded)
- NPDU header framing and NPCI control flags
- BACnet Application Tag and Context Tag codecs
- BACnetObjectID bit packing and validation
- APDU Confirmed-Request, SimpleACK, ComplexACK, and Unconfirmed-Request
- ReadProperty and SubscribeCOV service handling
- UnconfirmedCOVNotification serialization and parsing
- BACnetServerEngine register updates and RegisterTable synchronization
- Pure ST POU AST parsing and variable binding extraction (%R370..%R375, %M86..%M87)
- Hard fail-closed rejection of forbidden ladder logic constructs
"""

from __future__ import annotations

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import RegisterTable
from jev_cscape.telemetry.bacnet import (
    ApplicationTag,
    BACNET_TELEMETRY_ST_CODE,
    BACnetBitString,
    BACnetObjectID,
    BACnetObjectType,
    BACnetPropertyIdentifier,
    BACnetServerEngine,
    BVLLFunction,
    BVLLHeader,
    ComplexACKPDU,
    ConfirmedRequestPDU,
    ConfirmedServiceChoice,
    COVSubscription,
    NPDUHeader,
    PDUType,
    SimpleACKPDU,
    StatusFlags,
    UnconfirmedCOVNotification,
    UnconfirmedRequestPDU,
    UnconfirmedServiceChoice,
    decode_application_data,
    encode_application_data,
    encode_context_data,
)


def test_bvll_header_serialization() -> None:
    """Verify BVLL header serialization and parsing."""
    hdr = BVLLHeader(bvll_type=0x81, function=BVLLFunction.ORIGINAL_UNICAST_NPDU, length=24)
    raw = hdr.serialize()
    assert len(raw) == 4
    assert raw[0] == 0x81
    assert raw[1] == 0x0A
    assert raw[2:4] == b"\x00\x18"

    parsed, off = BVLLHeader.parse(raw)
    assert off == 4
    assert parsed.bvll_type == 0x81
    assert parsed.function == BVLLFunction.ORIGINAL_UNICAST_NPDU
    assert parsed.length == 24


def test_npdu_header_serialization() -> None:
    """Verify NPDU header serialization and parsing with and without routing."""
    # Basic unrouted NPDU
    npdu = NPDUHeader(expecting_reply=True, priority=1)
    raw = npdu.serialize()
    assert len(raw) == 2
    assert raw[0] == 0x01
    assert raw[1] & 0x04 != 0  # expecting reply
    assert raw[1] & 0x03 == 1  # priority 1

    parsed, off = NPDUHeader.parse(raw)
    assert off == 2
    assert parsed.version == 0x01
    assert parsed.expecting_reply is True
    assert parsed.priority == 1

    # Routed NPDU with DNET/DADR
    npdu_routed = NPDUHeader(
        dnet_present=True,
        dnet=10,
        dadr=b"\x01\x02",
        hop_count=255,
    )
    raw_routed = npdu_routed.serialize()
    parsed_routed, off_r = NPDUHeader.parse(raw_routed)
    assert parsed_routed.dnet_present is True
    assert parsed_routed.dnet == 10
    assert parsed_routed.dadr == b"\x01\x02"
    assert parsed_routed.hop_count == 255


def test_bacnet_object_id_bit_packing() -> None:
    """Verify BACnet 32-bit Object Identifier encoding and decoding."""
    oid = BACnetObjectID(BACnetObjectType.ANALOG_INPUT, 42)
    assert oid.object_type == BACnetObjectType.ANALOG_INPUT
    assert oid.instance == 42
    raw = oid.encode()
    assert len(raw) == 4

    decoded = BACnetObjectID.decode(raw)
    assert decoded.object_type == BACnetObjectType.ANALOG_INPUT
    assert decoded.instance == 42

    # High instance and device type
    dev_oid = BACnetObjectID(BACnetObjectType.DEVICE, 123456)
    assert dev_oid.object_type == BACnetObjectType.DEVICE
    assert dev_oid.instance == 123456
    decoded_dev = BACnetObjectID.decode(dev_oid.encode())
    assert decoded_dev == dev_oid

    # Range errors
    with pytest.raises(ValueError):
        BACnetObjectID(1024, 0)
    with pytest.raises(ValueError):
        BACnetObjectID(0, 0x400000)


def test_application_tag_codecs() -> None:
    """Verify BACnet primitive application tag encoding and decoding."""
    # Boolean
    raw_true = encode_application_data(ApplicationTag.BOOLEAN, True)
    assert raw_true == b"\x11"
    val, tag, _ = decode_application_data(raw_true)
    assert val is True
    assert tag == ApplicationTag.BOOLEAN

    raw_false = encode_application_data(ApplicationTag.BOOLEAN, False)
    assert raw_false == b"\x10"
    val, tag, _ = decode_application_data(raw_false)
    assert val is False

    # Unsigned Int
    raw_u = encode_application_data(ApplicationTag.UNSIGNED_INT, 42000)
    val_u, _, _ = decode_application_data(raw_u)
    assert val_u == 42000

    # Signed Int
    raw_s = encode_application_data(ApplicationTag.SIGNED_INT, -128)
    val_s, _, _ = decode_application_data(raw_s)
    assert val_s == -128

    # Real (float32)
    raw_r = encode_application_data(ApplicationTag.REAL, 72.5)
    val_r, _, _ = decode_application_data(raw_r)
    assert abs(val_r - 72.5) < 1e-4

    # Object Identifier
    oid = BACnetObjectID(BACnetObjectType.ANALOG_VALUE, 1)
    raw_oid = encode_application_data(ApplicationTag.OBJECT_IDENTIFIER, oid)
    val_oid, _, _ = decode_application_data(raw_oid)
    assert val_oid == oid


def test_bit_string_and_status_flags() -> None:
    """Verify BACnet bit string and StatusFlags handling."""
    flags = StatusFlags(in_alarm=True, fault=False, overridden=True, out_of_service=False)
    bits = flags.to_bits()
    assert bits == [True, False, True, False]

    bs = BACnetBitString.from_bool_list(bits)
    assert bs.unused_bits == 4
    assert bs.get_bit(0) is True
    assert bs.get_bit(1) is False
    assert bs.get_bit(2) is True
    assert bs.get_bit(3) is False

    raw = encode_application_data(ApplicationTag.BIT_STRING, flags)
    decoded_bs, _, _ = decode_application_data(raw)
    flags_restored = StatusFlags(
        in_alarm=decoded_bs.get_bit(0),
        fault=decoded_bs.get_bit(1),
        overridden=decoded_bs.get_bit(2),
        out_of_service=decoded_bs.get_bit(3),
    )
    assert flags_restored == flags


def test_confirmed_request_and_ack_codecs() -> None:
    """Verify ConfirmedRequest, SimpleACK, and ComplexACK APDU serialization and parsing."""
    req = ConfirmedRequestPDU(
        invoke_id=5,
        service_choice=ConfirmedServiceChoice.READ_PROPERTY,
        service_data=b"\x0C\x00\x00\x00\x00\x19\x55",
    )
    raw_req = req.serialize()
    assert raw_req[0] == 0x02  # SA=1
    assert raw_req[2] == 5     # Invoke ID
    assert raw_req[3] == 12    # ReadProperty

    parsed_req = ConfirmedRequestPDU.parse(raw_req)
    assert parsed_req.invoke_id == 5
    assert parsed_req.service_choice == ConfirmedServiceChoice.READ_PROPERTY
    assert parsed_req.service_data == req.service_data

    # Simple ACK
    sack = SimpleACKPDU(invoke_id=5, service_choice=ConfirmedServiceChoice.WRITE_PROPERTY)
    raw_sack = sack.serialize()
    assert raw_sack == b"\x20\x05\x0F"
    parsed_sack = SimpleACKPDU.parse(raw_sack)
    assert parsed_sack.invoke_id == 5
    assert parsed_sack.service_choice == ConfirmedServiceChoice.WRITE_PROPERTY

    # Complex ACK
    cack = ComplexACKPDU(invoke_id=5, service_choice=ConfirmedServiceChoice.READ_PROPERTY, service_data=b"\x12\x34")
    raw_cack = cack.serialize()
    parsed_cack = ComplexACKPDU.parse(raw_cack)
    assert parsed_cack.invoke_id == 5
    assert parsed_cack.service_choice == ConfirmedServiceChoice.READ_PROPERTY
    assert parsed_cack.service_data == b"\x12\x34"


def test_unconfirmed_cov_notification_roundtrip() -> None:
    """Verify UnconfirmedCOVNotification serialization and roundtrip parsing."""
    notif = UnconfirmedCOVNotification(
        subscriber_process_id=42,
        initiating_device_id=BACnetObjectID(BACnetObjectType.DEVICE, 100),
        monitored_object_id=BACnetObjectID(BACnetObjectType.ANALOG_INPUT, 0),
        time_remaining=300,
        present_value=23.5,
        status_flags=StatusFlags(in_alarm=False, fault=False, overridden=True, out_of_service=False),
    )
    raw = notif.serialize()
    assert len(raw) > 20

    parsed = UnconfirmedCOVNotification.parse(raw)
    assert parsed.subscriber_process_id == 42
    assert parsed.initiating_device_id == BACnetObjectID(BACnetObjectType.DEVICE, 100)
    assert parsed.monitored_object_id == BACnetObjectID(BACnetObjectType.ANALOG_INPUT, 0)
    assert parsed.time_remaining == 300
    assert abs(parsed.present_value - 23.5) < 1e-4
    assert parsed.status_flags.overridden is True
    assert parsed.status_flags.in_alarm is False


def test_cov_subscription_evaluation() -> None:
    """Verify COV deadband trigger logic for analog and discrete values."""
    sub = COVSubscription(
        subscriber_process_id=1,
        monitored_object_id=BACnetObjectID(BACnetObjectType.ANALOG_INPUT, 0),
        issue_confirmed=False,
        lifetime=300,
        cov_increment=1.0,
    )
    st = StatusFlags()

    # Initial reporting always triggers
    assert sub.evaluate_trigger(50.0, st) is True
    sub.mark_reported(50.0, st)

    # Change within deadband (0.5 < 1.0) -> No trigger
    assert sub.evaluate_trigger(50.5, st) is False

    # Change exceeding deadband (1.2 >= 1.0) -> Trigger
    assert sub.evaluate_trigger(51.2, st) is True
    sub.mark_reported(51.2, st)

    # Status flag change -> Trigger immediately
    st_alarm = StatusFlags(in_alarm=True)
    assert sub.evaluate_trigger(51.2, st_alarm) is True


def test_bacnet_server_read_property_and_subscribe_cov() -> None:
    """Verify BACnetServerEngine handling of ReadProperty and SubscribeCOV packets."""
    engine = BACnetServerEngine(device_id=100)
    engine.update_registers(ai0_pv_scaled=6850, bi0_state=1, enable=True)
    assert abs(engine.ai0_pv - 68.5) < 1e-4
    assert engine.status_word & 0x0001 != 0  # Active
    assert engine.status_word & 0x0002 != 0  # UDP bound

    # 1. Simulate ReadProperty Request for AI:0, Present_Value (85)
    req_payload = (
        encode_context_data(0, engine.ai0_oid.encode())
        + encode_context_data(1, b"\x55")  # Property 85
    )
    req_apdu = ConfirmedRequestPDU(
        invoke_id=1,
        service_choice=ConfirmedServiceChoice.READ_PROPERTY,
        service_data=req_payload,
    )
    bvll_pkt = engine._wrap_pdu(req_apdu.serialize(), expecting_reply=True)
    resp = engine.handle_packet(bvll_pkt)
    assert resp is not None
    assert engine.last_service_choice == 12

    # Parse response BVLL + NPDU + APDU
    b_resp, off = BVLLHeader.parse(resp)
    n_resp, n_off = NPDUHeader.parse(resp[off:])
    apdu_resp = resp[off + n_off:]
    parsed_cack = ComplexACKPDU.parse(apdu_resp)
    assert parsed_cack.invoke_id == 1
    assert parsed_cack.service_choice == ConfirmedServiceChoice.READ_PROPERTY

    # 2. Simulate SubscribeCOV Request
    sub_payload = (
        encode_context_data(0, b"\x01")  # Subscriber Process 1
        + encode_context_data(1, engine.ai0_oid.encode())  # AI:0
    )
    sub_apdu = ConfirmedRequestPDU(
        invoke_id=2,
        service_choice=ConfirmedServiceChoice.SUBSCRIBE_COV,
        service_data=sub_payload,
    )
    bvll_sub = engine._wrap_pdu(sub_apdu.serialize(), expecting_reply=True)
    resp_sub = engine.handle_packet(bvll_sub)
    assert resp_sub is not None
    assert len(engine.subscriptions) == 1
    assert engine.status_word & 0x0004 != 0  # COV active


def test_bacnet_server_cov_broadcast_packet() -> None:
    """Verify build_cov_notification produces well-formed broadcast packet."""
    engine = BACnetServerEngine(device_id=100)
    engine.update_registers(ai0_pv_scaled=7500, bi0_state=0, enable=True)
    pkt = engine.build_cov_notification(engine.ai0_oid, subscriber_process_id=10)

    bvll, off = BVLLHeader.parse(pkt)
    assert bvll.function == BVLLFunction.ORIGINAL_BROADCAST_NPDU
    npdu, n_off = NPDUHeader.parse(pkt[off:])
    unconf = UnconfirmedRequestPDU.parse(pkt[off + n_off:])
    assert unconf.service_choice == UnconfirmedServiceChoice.UNCONFIRMED_COV_NOTIFICATION
    notif = UnconfirmedCOVNotification.parse(unconf.service_data)
    assert notif.subscriber_process_id == 10
    assert abs(notif.present_value - 75.0) < 1e-4


def test_register_table_synchronization() -> None:
    """Verify bidirectional synchronization with Horner OCS RegisterTable."""
    engine = BACnetServerEngine()
    table = RegisterTable()

    table.write_register("%R374", 8250)
    table.write_register("%R375", 3)  # Active + In_Alarm
    table.write_register("%M86", True)
    table.write_register("%M87", True)

    engine.sync_from_register_table(table)
    assert engine.ai0_scaled_pv == 8250
    assert abs(engine.ai0_pv - 82.5) < 1e-4
    assert engine.bi0_pv is True
    assert engine.bi0_status.in_alarm is True

    engine.sync_to_register_table(table)
    assert table.read_register("%R370") & 0x0001 != 0
    assert table.read_register("%R374") == 8250


def test_bacnet_st_pou_ast_parsing_and_bindings() -> None:
    """Verify IEC 61131-3 Pure ST POU syntax and register bindings."""
    val = STParser.validate_code(BACNET_TELEMETRY_ST_CODE)
    assert val.status == AgentStatus.SUCCESS
    assert val.error_code is None

    ast = STParser.parse_pou(BACNET_TELEMETRY_ST_CODE)
    assert ast.name == "BacnetTelemetryServer"
    assert ast.pou_type == POUType.PROGRAM
    expected_bindings = {
        "%R370", "%R371", "%R372", "%R373", "%R374", "%R375", "%M86", "%M87"
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
        "XIC EnableServer",
        "XIO TriggerManualCOV",
        "OTE StatusWord",
        "OTL BitServerActive",
        "OTU BitProtocolError",
    ],
)
def test_bacnet_forbidden_ladder_constructs_rejected(ladder_artifact: str) -> None:
    """Verify ladder logic tokens are strictly rejected with ERR_LADDER_FORBIDDEN."""
    bad_code = f"{BACNET_TELEMETRY_ST_CODE}\n{ladder_artifact}\n"
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_code)
    res = STParser.validate_code(bad_code)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "ERR_LADDER_FORBIDDEN"
    assert res.data["ladder_rejected"] is True
