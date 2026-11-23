"""Verification Runner for Industrial EtherNet/IP & CIP Telemetry Adapter.

Work Package: W079 (Gate G8 / G4)
Generates: artifacts/telemetry/ethernet_ip_evidence.json
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import sys
import time

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.telemetry.ethernet_ip import (
    CIPDataType,
    CIPDataTypeCodec,
    CIPGeneralStatus,
    CIPRequest,
    CIPResponse,
    CIPServiceCode,
    CPFItem,
    CPFTypeId,
    EIPCommand,
    EIPHeader,
    EIPStatus,
    EPATH,
    EIP_CIP_ST_POU,
    EtherNetIpAdapterEngine,
    IdentityObject,
    LogicalSegment,
    LogicalType,
    SymbolicSegment,
    deserialize_cpf,
    serialize_cpf,
    validate_pure_st,
)


def run_verification() -> int:
    print("=" * 80)
    print("  JEV Cscape Agent: EtherNet/IP & CIP Protocol Telemetry Verification (W079)")
    print("=" * 80)

    checks_passed = 0
    total_checks = 6

    # 1. 24-octet Encapsulation Header & CPF Framing
    print("[*] Stage 1: Verifying 24-octet EIP Header & CPF Item Codecs...")
    hdr = EIPHeader(command=EIPCommand.REGISTER_SESSION, length=4, session_handle=0x12345678, sender_context=b"TEST0001")
    raw_hdr = hdr.serialize()
    assert len(raw_hdr) == 24, "Header must be exactly 24 octets"
    deser_hdr, _ = EIPHeader.deserialize(raw_hdr)
    assert deser_hdr.session_handle == 0x12345678
    assert deser_hdr.sender_context == b"TEST0001"

    null_item = CPFItem.null_address()
    unconn_item = CPFItem.unconnected_data(b"\x0E\x03\x20\x01\x24\x01\x30\x01")
    cpf_bytes = serialize_cpf([null_item, unconn_item])
    deser_items = deserialize_cpf(cpf_bytes)
    assert len(deser_items) == 2
    assert deser_items[0].type_id == CPFTypeId.NULL_ADDRESS
    assert deser_items[1].type_id == CPFTypeId.UNCONNECTED_DATA
    print("    [PASS] Encapsulation header and CPF item codecs verified.")
    checks_passed += 1

    # 2. CIP Identity Object (Class 0x01)
    print("[*] Stage 2: Verifying CIP Identity Object (Class 0x01, Instance 0x01)...")
    ident = IdentityObject()
    s1, d1 = ident.get_attribute_single(1)  # Vendor ID
    assert s1 == CIPGeneralStatus.SUCCESS
    vendor_id = struct.unpack("<H", d1)[0]
    assert vendor_id == 0x0059, "Vendor ID must match Horner Electric (0x0059)"

    s7, d7 = ident.get_attribute_single(7)  # Product Name
    assert s7 == CIPGeneralStatus.SUCCESS
    prod_name = d7[1 : 1 + d7[0]].decode("ascii")
    assert prod_name == "HE-EXL1E2"
    print(f"    [PASS] Identity Object verified: Vendor=0x{vendor_id:04X} (Horner Electric), Product='{prod_name}'.")
    checks_passed += 1

    # 3. CIP Assembly Object (Class 0x04) Input & Output instances
    print("[*] Stage 3: Verifying CIP Assembly Object (Class 0x04) Input/Output instances...")
    engine = EtherNetIpAdapterEngine()
    in_buf = engine.input_assembly.read_buffer()
    assert len(in_buf) == 32
    assert engine.input_assembly.write_buffer(b"\x00" * 32) == CIPGeneralStatus.ATTRIBUTE_NOT_SETTABLE
    out_payload = b"\xAA" * 16
    assert engine.output_assembly.write_buffer(out_payload) == CIPGeneralStatus.SUCCESS
    assert engine.output_assembly.read_buffer() == out_payload
    print("    [PASS] Assembly Object verified: Input 32-byte read-only, Output 16-byte read-write.")
    checks_passed += 1

    # 4. Symbolic Tag Read/Write (0x4C / 0x4D)
    print("[*] Stage 4: Verifying CIP Read_Tag and Write_Tag services...")
    reg_req = EIPHeader(command=EIPCommand.REGISTER_SESSION, length=4).serialize() + struct.pack("<HH", 1, 0)
    sess_handle = EIPHeader.deserialize(engine.handle_packet(reg_req))[0].session_handle

    # Read Tag
    path = EPATH.from_tag("SolidsDischargeTemp")
    read_cip = CIPRequest(service_code=CIPServiceCode.READ_TAG, epath=path, data=struct.pack("<H", 1)).encode()
    send_payload = struct.pack("<IH", 0, 0) + serialize_cpf([CPFItem.null_address(), CPFItem.unconnected_data(read_cip)])
    resp_raw = engine.handle_packet(EIPHeader(command=EIPCommand.SEND_RR_DATA, length=len(send_payload), session_handle=sess_handle).serialize() + send_payload)
    cpf_resp = deserialize_cpf(EIPHeader.deserialize(resp_raw)[1][6:])
    data_item = next(it for it in cpf_resp if it.type_id == CPFTypeId.UNCONNECTED_DATA)
    cip_resp = CIPResponse.decode(data_item.data)
    assert cip_resp.general_status == CIPGeneralStatus.SUCCESS
    dtype, temp_val = struct.unpack("<Hf", cip_resp.data)
    assert abs(temp_val - 1050.0) < 1e-3

    # Write Tag
    val_b = CIPDataTypeCodec.encode(CIPDataType.REAL, 1085.5)
    write_payload = struct.pack("<HH", int(CIPDataType.REAL), 1) + val_b
    write_cip = CIPRequest(service_code=CIPServiceCode.WRITE_TAG, epath=path, data=write_payload).encode()
    send_w = struct.pack("<IH", 0, 0) + serialize_cpf([CPFItem.null_address(), CPFItem.unconnected_data(write_cip)])
    engine.handle_packet(EIPHeader(command=EIPCommand.SEND_RR_DATA, length=len(send_w), session_handle=sess_handle).serialize() + send_w)
    assert abs(engine.named_tags["SolidsDischargeTemp"][1] - 1085.5) < 1e-3
    print(f"    [PASS] Symbolic Tag Read/Write verified: read={temp_val:.1f}, written=1085.5.")
    checks_passed += 1

    # 5. Horner Register Table Synchronization (%R400..%R405, %M93..%M94)
    print("[*] Stage 5: Verifying Horner OCS Register Reflection...")
    engine.sync_registers()
    status_w = engine.registers.read_register("%R400")
    assert status_w & 0x0001 != 0, "Bit 0 (EIP Server Active) must be set"
    assert status_w & 0x0002 != 0, "Bit 1 (Active Session) must be set"
    assert engine.registers.read_register("%R401") == 1
    assert engine.registers.read_register("%R402") > 0
    assert engine.registers.read_register("%R403") > 0
    print(f"    [PASS] Registers synchronized: %R400=0x{status_w:04X}, Sessions=%R401={engine.registers.read_register('%R401')}.")
    checks_passed += 1

    # 6. Pure ST POU & Forbidden Ladder Logic Rejection Guard
    print("[*] Stage 6: Verifying IEC 61131-3 Pure ST POU & Ladder Rejection Guard...")
    st_res = validate_pure_st()
    assert st_res.status == AgentStatus.SUCCESS, "ST parsing must succeed"

    # Test forbidden ladder rejection
    ladder_tokens = ["---[ ]---", "---( )---", "RUNG 1", "XIC EnableAdapter"]
    for token in ladder_tokens:
        tainted = f"{EIP_CIP_ST_POU}\n{token}\n"
        try:
            SecurityGuard.assert_pure_st_content(tainted)
            raise AssertionError(f"Failed to reject ladder construct: {token}")
        except LadderForbiddenError:
            pass
    print("    [PASS] Pure ST validated; forbidden ladder constructs strictly rejected.")
    checks_passed += 1

    # Export evidence JSON
    evidence = {
        "status": "success",
        "error_code": None,
        "details": f"EtherNet/IP & CIP Protocol Telemetry Adapter verified cleanly ({checks_passed}/{total_checks} checks passed).",
        "data": {
            "work_package": "W079",
            "gate": "Gate G8 / G4",
            "checks_passed": checks_passed,
            "total_checks": total_checks,
            "vendor_id": "0x0059 (Horner Electric)",
            "product_name": "HE-EXL1E2",
            "product_code": 102,
            "revision": "10.2",
            "input_assembly_size_bytes": 32,
            "output_assembly_size_bytes": 16,
            "registered_session_handle": f"0x{sess_handle:08X}",
            "registers": {
                "%R400": status_w,
                "%R401": engine.registers.read_register("%R401"),
                "%R402": engine.registers.read_register("%R402"),
                "%R403": engine.registers.read_register("%R403"),
                "%R404": engine.registers.read_register("%R404"),
                "%R405": engine.registers.read_register("%R405"),
                "%M93": engine.registers.read_register("%M93"),
                "%M94": engine.registers.read_register("%M94"),
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    out_file = Path("artifacts/telemetry/ethernet_ip_evidence.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    print(f"[*] Evidence exported to: {out_file}")
    print("[SUCCESS] EtherNet/IP verification completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(run_verification())
