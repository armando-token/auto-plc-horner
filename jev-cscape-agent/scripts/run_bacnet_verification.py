"""BACnet/IP Building Automation Telemetry Engine Verification Runner.

Work Package: W076 (Gate G8 / G4)
Standard: ANSI/ASHRAE Standard 135 Annex J & Clauses 20/21
Exports:
- artifacts/telemetry/bacnet_evidence.json
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Dict

from jev_cscape.simulation.register_table import RegisterTable
from jev_cscape.telemetry.bacnet import (
    ApplicationTag,
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
    encode_application_data,
    encode_context_data,
)


def run_bacnet_verification(
    output_evidence_path: Path = Path("artifacts/telemetry/bacnet_evidence.json"),
) -> Dict[str, Any]:
    """Execute end-to-end verification of BACnet/IP telemetry engine and APDU server."""
    output_evidence_path.parent.mkdir(parents=True, exist_ok=True)
    engine = BACnetServerEngine(device_id=100)
    checks: Dict[str, Any] = {}

    # Check 1: BVLL & NPDU Framing and Routing
    bvll = BVLLHeader(bvll_type=0x81, function=BVLLFunction.ORIGINAL_UNICAST_NPDU, length=24)
    raw_bvll = bvll.serialize()
    parsed_bvll, _ = BVLLHeader.parse(raw_bvll)

    npdu = NPDUHeader(expecting_reply=True, priority=1, dnet_present=True, dnet=101, hop_count=254)
    raw_npdu = npdu.serialize()
    parsed_npdu, _ = NPDUHeader.parse(raw_npdu)

    framing_ok = (
        parsed_bvll.function == BVLLFunction.ORIGINAL_UNICAST_NPDU
        and parsed_bvll.length == 24
        and parsed_npdu.expecting_reply is True
        and parsed_npdu.dnet == 101
        and parsed_npdu.hop_count == 254
    )
    checks["bvll_npdu_framing"] = {
        "status": "passed" if framing_ok else "failed",
        "bvll_type": hex(parsed_bvll.bvll_type),
        "bvll_function": parsed_bvll.function.name,
        "npdu_version": parsed_npdu.version,
        "expecting_reply": parsed_npdu.expecting_reply,
        "dnet": parsed_npdu.dnet,
    }

    # Check 2: ReadProperty Service and ComplexACK Dispatch
    engine.update_registers(ai0_pv_scaled=7250, bi0_state=1, enable=True)
    req_payload = (
        encode_context_data(0, engine.ai0_oid.encode())
        + encode_context_data(1, b"\x55")  # Present_Value (85)
    )
    req_apdu = ConfirmedRequestPDU(
        invoke_id=1,
        service_choice=ConfirmedServiceChoice.READ_PROPERTY,
        service_data=req_payload,
    )
    pkt_read = engine._wrap_pdu(req_apdu.serialize(), expecting_reply=True)
    resp_read = engine.handle_packet(pkt_read)
    assert resp_read is not None

    b_hdr, b_off = BVLLHeader.parse(resp_read)
    _, n_off = NPDUHeader.parse(resp_read[b_off:])
    cack = ComplexACKPDU.parse(resp_read[b_off + n_off:])
    read_ok = (
        cack.invoke_id == 1
        and cack.service_choice == ConfirmedServiceChoice.READ_PROPERTY
        and len(cack.service_data) > 0
    )
    checks["read_property_service"] = {
        "status": "passed" if read_ok else "failed",
        "invoke_id": cack.invoke_id,
        "service_choice": cack.service_choice.name,
        "response_byte_length": len(resp_read),
    }

    # Check 3: SubscribeCOV Registration and Trigger Logic
    sub_payload = (
        encode_context_data(0, b"\x05")  # Subscriber Process 5
        + encode_context_data(1, engine.ai0_oid.encode())  # Monitored AI:0
    )
    sub_apdu = ConfirmedRequestPDU(
        invoke_id=2,
        service_choice=ConfirmedServiceChoice.SUBSCRIBE_COV,
        service_data=sub_payload,
    )
    pkt_sub = engine._wrap_pdu(sub_apdu.serialize(), expecting_reply=True)
    resp_sub = engine.handle_packet(pkt_sub)
    assert resp_sub is not None

    b_sub, b_soff = BVLLHeader.parse(resp_sub)
    _, n_soff = NPDUHeader.parse(resp_sub[b_soff:])
    sack = SimpleACKPDU.parse(resp_sub[b_soff + n_soff:])
    cov_reg_ok = sack.invoke_id == 2 and len(engine.subscriptions) == 1

    # Evaluate subscription triggers
    sub_inst = engine.subscriptions[0]
    st_flags = StatusFlags()
    trig1 = sub_inst.evaluate_trigger(72.5, st_flags)  # Initial -> True
    sub_inst.mark_reported(72.5, st_flags)
    trig2 = sub_inst.evaluate_trigger(72.7, st_flags)  # Delta 0.2 < 0.5 -> False
    trig3 = sub_inst.evaluate_trigger(73.2, st_flags)  # Delta 0.7 >= 0.5 -> True

    cov_ok = cov_reg_ok and trig1 and not trig2 and trig3
    checks["cov_subscription_and_triggers"] = {
        "status": "passed" if cov_ok else "failed",
        "subscription_count": len(engine.subscriptions),
        "initial_trigger": trig1,
        "sub_deadband_suppressed": not trig2,
        "deadband_exceeded_triggered": trig3,
    }

    # Check 4: UnconfirmedCOVNotification Wire Generation and Parsing
    cov_pkt = engine.build_cov_notification(engine.ai0_oid, subscriber_process_id=5)
    b_cov, b_coff = BVLLHeader.parse(cov_pkt)
    _, n_coff = NPDUHeader.parse(cov_pkt[b_coff:])
    unconf_req = UnconfirmedRequestPDU.parse(cov_pkt[b_coff + n_coff:])
    parsed_notif = UnconfirmedCOVNotification.parse(unconf_req.service_data)

    notif_ok = (
        b_cov.function == BVLLFunction.ORIGINAL_BROADCAST_NPDU
        and unconf_req.service_choice == UnconfirmedServiceChoice.UNCONFIRMED_COV_NOTIFICATION
        and parsed_notif.subscriber_process_id == 5
        and abs(parsed_notif.present_value - 72.5) < 1e-3
    )
    checks["cov_notification_wire"] = {
        "status": "passed" if notif_ok else "failed",
        "bvll_broadcast": b_cov.function.name,
        "subscriber_process_id": parsed_notif.subscriber_process_id,
        "monitored_object": str(parsed_notif.monitored_object_id),
        "reported_pv": parsed_notif.present_value,
    }

    # Check 5: Horner OCS RegisterTable Synchronization
    table = RegisterTable()
    table.write_register("%R374", 8840)  # 88.40 EU
    table.write_register("%R375", 1)     # Binary Active
    table.write_register("%M86", True)   # Enable Server
    table.write_register("%M87", True)   # Trigger Manual COV

    engine.sync_from_register_table(table)
    engine.sync_to_register_table(table)

    reg_ok = (
        engine.ai0_scaled_pv == 8840
        and abs(engine.ai0_pv - 88.4) < 1e-4
        and engine.bi0_pv is True
        and (table.read_register("%R370") & 0x0001 != 0)
        and (table.read_register("%R370") & 0x0008 != 0)  # COV sent bit
    )
    checks["register_table_synchronization"] = {
        "status": "passed" if reg_ok else "failed",
        "r370_status_word": table.read_register("%R370"),
        "r374_scaled_pv": table.read_register("%R374"),
        "r375_bi_pv": table.read_register("%R375"),
        "m86_enable": table.read_register("%M86"),
    }

    all_passed = all(c["status"] == "passed" for c in checks.values())
    evidence = {
        "work_package": "W076",
        "gate": "G8",
        "component": "Industrial BACnet/IP Telemetry Protocol Engine & APDU Server",
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "overall_status": "success" if all_passed else "failed",
        "registers": {
            "%R370": engine.status_word,
            "%R371": engine.packets_received,
            "%R372": engine.packets_sent,
            "%R373": engine.last_service_choice,
            "%R374": engine.ai0_scaled_pv,
            "%R375": engine.bi0_raw_status,
            "%M86": engine.enable_server,
            "%M87": engine.trigger_manual_cov,
        },
        "checks": checks,
    }

    with open(output_evidence_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    return evidence


if __name__ == "__main__":
    res = run_bacnet_verification()
    print(json.dumps(res, indent=2))
