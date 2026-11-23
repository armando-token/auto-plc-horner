"""IEC 60870-5-104 Telemetry Protocol Server Verification Runner.

Work Package: W073 (Gate G8 / G4)
Standard: IEC 60870-5-104:2006
Exports: artifacts/telemetry/iec104_evidence.json
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Dict

from jev_cscape.telemetry.iec104 import (
    APCIFormat,
    CP56Time2a,
    IEC104ServerEngine,
    IFrame,
    SCO,
    SIQ,
    SFrame,
    UFrame,
    UFunction,
    decode_asdu_type1,
    decode_asdu_type13,
    decode_asdu_type30,
    decode_asdu_type45,
    decode_asdu_type100,
    deserialize_apci,
    encode_asdu_type100,
    encode_asdu_type45,
)


def run_iec104_verification(
    output_path: Path = Path("artifacts/telemetry/iec104_evidence.json"),
) -> Dict[str, Any]:
    """Execute end-to-end verification of IEC 60870-5-104 protocol server."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    engine = IEC104ServerEngine(common_addr=1)
    checks: Dict[str, Any] = {}

    # Check 1: CP56Time2a Timestamp Codec
    dt_ref = datetime.datetime(2026, 10, 3, 15, 45, 30, 500000)
    ts = CP56Time2a(dt=dt_ref, summer_time=True)
    raw_ts = ts.encode()
    dec_ts = CP56Time2a.decode(raw_ts)
    checks["cp56time2a_codec"] = {
        "status": "passed" if dec_ts.dt == dt_ref and dec_ts.summer_time is True else "failed",
        "encoded_bytes_hex": raw_ts.hex(),
        "decoded_iso": dec_ts.dt.isoformat(),
        "byte_length": len(raw_ts),
    }

    # Check 2: U-Frame STARTDT Handshake
    u_act = UFrame(function=UFunction.STARTDT_ACT).serialize()
    resp_u = engine.process_incoming_apdu(u_act)
    resp_frame = deserialize_apci(resp_u[0]) if resp_u else None
    checks["startdt_handshake"] = {
        "status": "passed" if isinstance(resp_frame, UFrame) and resp_frame.function == UFunction.STARTDT_CON else "failed",
        "startdt_active": engine.startdt_active,
        "frames_sent": engine.frames_sent_counter,
    }

    # Check 3: General Interrogation Sequence (ASDU 100)
    gi_req = encode_asdu_type100(qoi=20, ioa=0, cause=6, common_addr=1)
    iframe_gi = IFrame(send_seq=0, recv_seq=0, asdu=gi_req).serialize()
    resp_gi = engine.process_incoming_apdu(iframe_gi)
    checks["general_interrogation"] = {
        "status": "passed" if len(resp_gi) == 5 else "failed",
        "frames_returned": len(resp_gi),
        "frame_types": [deserialize_apci(f).format.value for f in resp_gi],
    }

    # Check 4: Select-Before-Operate Single Command (ASDU 45)
    cmd_sel = encode_asdu_type45(ioa=3001, sco=SCO(state=True, select=True), cause=6)
    iframe_sel = IFrame(send_seq=1, recv_seq=1, asdu=cmd_sel).serialize()
    resp_sel = engine.process_incoming_apdu(iframe_sel)
    checks["sbo_select_operate"] = {
        "status": "passed" if engine.single_cmd_status == 2 and len(resp_sel) == 2 else "failed",
        "single_cmd_status": engine.single_cmd_status,
        "status_word_hex": f"0x{engine.status_word:04X}",
    }

    # Check 5: Spontaneous Event Generation (ASDU 30 with CP56Time2a)
    evt_bytes = engine.emit_spontaneous_event(ioa=1001, value=True)
    frame_evt = deserialize_apci(evt_bytes)
    assert isinstance(frame_evt, IFrame)
    hdr_evt, objs_evt = decode_asdu_type30(frame_evt.asdu)
    checks["spontaneous_event"] = {
        "status": "passed" if hdr_evt.type_id == 30 and hdr_evt.cause == 3 else "failed",
        "asdu_type_id": hdr_evt.type_id,
        "cause_of_transmission": hdr_evt.cause,
        "ioa": objs_evt[0][0],
        "value": objs_evt[0][1].value,
        "timestamp": objs_evt[0][2].dt.isoformat(),
    }

    all_passed = all(c["status"] == "passed" for c in checks.values())
    evidence = {
        "work_package": "W073",
        "gate": "G8",
        "protocol": "IEC 60870-5-104:2006",
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "overall_status": "success" if all_passed else "failed",
        "registers": {
            "%R340": engine.status_word,
            "%R341": engine.frames_received_counter,
            "%R342": engine.frames_sent_counter,
            "%R343": engine.last_asdu_type_id,
            "%R344": engine.measured_analog_pv1,
            "%R345": engine.single_cmd_status,
            "%M79": engine.enable_server,
            "%M80": engine.trigger_spontaneous,
        },
        "checks": checks,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    return evidence


if __name__ == "__main__":
    res = run_iec104_verification()
    print(json.dumps(res, indent=2))
