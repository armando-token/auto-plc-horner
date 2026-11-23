"""Tests for Industrial PROFINET IO RT and DCP Protocol Telemetry Adapter Engine.

Work Package: W082 (Gate G8 / G4)
"""

import json
import os
import struct
import tempfile
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.profinet import (
    DCPOption,
    DCPSuboptionControl,
    DCPSuboptionDevice,
    DCPSuboptionIP,
    DCPServiceId,
    DCPServiceType,
    DCPBlock,
    DCPPacket,
    IOStatusQuality,
    ProfinetAdapterEngine,
    ProfinetConstants,
    ProfinetRTCyclicFrame,
    ProfinetStatusBits,
    PROFINET_PURE_ST_POU,
    run_profinet_verification,
)


class TestProfinetPureST:
    def test_pure_st_pou_valid(self):
        result = STParser.validate_code(PROFINET_PURE_ST_POU)
        assert result.status == AgentStatus.SUCCESS
        ast = STParser.parse_pou(PROFINET_PURE_ST_POU)
        assert ast.name == "ProfinetIoRtAdapter"
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {"%R430", "%R431", "%R432", "%R433", "%R434", "%R435", "%M100", "%M101"}
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_forbidden_ladder_constructs_rejected(self):
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad ---[ ]--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad ---[/]--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad ---( )--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad RUNG 1: XIC %M100 OTE %M101 END_RUNG END_PROGRAM")


class TestProfinetDCP:
    def test_dcp_block_roundtrip(self):
        blk = DCPBlock(
            option=DCPOption.DEVICE_PROPERTIES,
            suboption=DCPSuboptionDevice.STATION_NAME,
            payload=b"station-alpha",
            block_status=0x0000,
        )
        wire = blk.serialize(is_response=True)
        unpacked, rem = DCPBlock.deserialize(wire, is_response=True)
        assert rem == b""
        assert unpacked.option == DCPOption.DEVICE_PROPERTIES
        assert unpacked.suboption == DCPSuboptionDevice.STATION_NAME
        assert unpacked.payload == b"station-alpha"
        assert unpacked.block_status == 0x0000

    def test_dcp_packet_roundtrip(self):
        pkt = DCPPacket(
            frame_id=ProfinetConstants.FRAME_ID_DCP_IDENT_REQ,
            service_id=DCPServiceId.IDENTIFY,
            service_type=DCPServiceType.REQUEST,
            xid=0x12345678,
            response_delay=0x0000,
            blocks=[
                DCPBlock(option=DCPOption.ALL_SELECTOR, suboption=0xFF, payload=b"")
            ],
        )
        wire = pkt.serialize()
        parsed = DCPPacket.deserialize(wire)
        assert parsed.frame_id == ProfinetConstants.FRAME_ID_DCP_IDENT_REQ
        assert parsed.service_id == DCPServiceId.IDENTIFY
        assert parsed.service_type == DCPServiceType.REQUEST
        assert parsed.xid == 0x12345678
        assert len(parsed.blocks) == 1

    def test_dcp_truncated_deserialization_error(self):
        with pytest.raises(ValueError):
            DCPBlock.deserialize(b"\x01\x02")
        with pytest.raises(ValueError):
            DCPPacket.deserialize(b"\x01\x02\x03\x04")


class TestProfinetRTCyclic:
    def test_cyclic_frame_roundtrip(self):
        frame = ProfinetRTCyclicFrame(
            frame_id=0x8005,
            slot1_data=b"\xAA" * 32,
            slot1_iops=IOStatusQuality.GOOD,
            slot2_data=b"\x55" * 16,
            slot2_iops=IOStatusQuality.GOOD,
            cycle_counter=42,
        )
        wire = frame.serialize()
        assert len(wire) == 56
        unpacked = ProfinetRTCyclicFrame.deserialize(wire)
        assert unpacked.frame_id == 0x8005
        assert unpacked.slot1_data == b"\xAA" * 32
        assert unpacked.slot1_iops == IOStatusQuality.GOOD
        assert unpacked.slot2_data == b"\x55" * 16
        assert unpacked.slot2_iops == IOStatusQuality.GOOD
        assert unpacked.cycle_counter == 42


class TestProfinetAdapterEngine:
    def test_engine_initialization_and_dcp_discovery(self):
        rt = RegisterTable()
        engine = ProfinetAdapterEngine(register_table=rt)
        assert rt.read_bit("%M100") is True
        assert rt.read_word("%R430") & ProfinetStatusBits.ENGINE_ACTIVE

        # Send Identify Request
        ident_pkt = DCPPacket(
            frame_id=ProfinetConstants.FRAME_ID_DCP_IDENT_REQ,
            service_id=DCPServiceId.IDENTIFY,
            service_type=DCPServiceType.REQUEST,
            xid=0xAABBCCDD,
            blocks=[DCPBlock(option=DCPOption.ALL_SELECTOR, suboption=0xFF, payload=b"")],
        )
        resp_bytes = engine.handle_dcp_packet(ident_pkt.serialize())
        assert resp_bytes is not None

        resp_pkt = DCPPacket.deserialize(resp_bytes)
        assert resp_pkt.frame_id == ProfinetConstants.FRAME_ID_DCP_IDENT_RESP
        assert resp_pkt.xid == 0xAABBCCDD
        assert engine.dcp_identified is True
        assert rt.read_word("%R434") == DCPServiceId.IDENTIFY
        assert rt.read_word("%R430") & ProfinetStatusBits.DCP_IDENTIFIED

    def test_engine_dcp_set_ip_and_station_name(self):
        rt = RegisterTable()
        engine = ProfinetAdapterEngine(register_table=rt)

        set_pkt = DCPPacket(
            frame_id=ProfinetConstants.FRAME_ID_DCP_GET_SET,
            service_id=DCPServiceId.SET,
            service_type=DCPServiceType.REQUEST,
            xid=0x11223344,
            blocks=[
                DCPBlock(
                    option=DCPOption.IP_PARAMETER,
                    suboption=DCPSuboptionIP.IP_PARAMETER,
                    payload=bytes([10, 0, 0, 50, 255, 255, 0, 0, 10, 0, 0, 1]),
                ),
                DCPBlock(
                    option=DCPOption.DEVICE_PROPERTIES,
                    suboption=DCPSuboptionDevice.STATION_NAME,
                    payload=b"new-horner-station",
                ),
            ],
        )
        resp = engine.handle_dcp_packet(set_pkt.serialize())
        assert resp is not None
        assert engine.ip_address == "10.0.0.50"
        assert engine.subnet_mask == "255.255.0.0"
        assert engine.gateway == "10.0.0.1"
        assert engine.station_name == "new-horner-station"

    def test_engine_cyclic_io_data_exchange(self):
        rt = RegisterTable()
        # Seed some analog registers in Slot 1
        rt.write_word("%R436", 1234, privilege=PrivilegeMode.SYSTEM)
        rt.write_word("%R437", 5678, privilege=PrivilegeMode.SYSTEM)
        rt.write_bit("%M105", True, privilege=PrivilegeMode.SYSTEM)

        engine = ProfinetAdapterEngine(register_table=rt)
        rx_frame = ProfinetRTCyclicFrame(
            frame_id=0x8000,
            slot1_data=b"\x00" * 32,
            slot1_iops=IOStatusQuality.GOOD,
            slot2_data=b"\x00" * 16,
            slot2_iops=IOStatusQuality.GOOD,
            cycle_counter=10,
        )
        tx_bytes = engine.handle_cyclic_frame(rx_frame.serialize())
        assert tx_bytes is not None

        tx_frame = ProfinetRTCyclicFrame.deserialize(tx_bytes)
        assert tx_frame.cycle_counter == 1
        assert tx_frame.slot1_iops == IOStatusQuality.GOOD
        assert engine.cyclic_rx_count == 1
        assert engine.cyclic_tx_count == 1
        assert rt.read_word("%R430") & ProfinetStatusBits.CYCLIC_IO_ACTIVE

        # Verify packed analog value in Slot 1
        # %R436 is index 6 in Slot 1 (%R430 + 6)
        r436_val = struct.unpack_from(">H", tx_frame.slot1_data, 6 * 2)[0]
        assert r436_val == 1234

        # Verify packed discrete bit in Slot 2 (%M105 is index 5)
        assert tx_frame.slot2_data[5] == 1

    def test_engine_consumer_fault_detection(self):
        rt = RegisterTable()
        engine = ProfinetAdapterEngine(register_table=rt)

        bad_frame = ProfinetRTCyclicFrame(
            frame_id=0x8000,
            slot1_iops=IOStatusQuality.BAD,
            slot2_iops=IOStatusQuality.GOOD,
        )
        engine.handle_cyclic_frame(bad_frame.serialize())
        assert engine.consumer_fault is True
        assert rt.read_word("%R430") & ProfinetStatusBits.CONSUMER_FAULT_BAD

    def test_engine_disabled_when_m100_false(self):
        rt = RegisterTable()
        engine = ProfinetAdapterEngine(register_table=rt)
        rt.write_bit("%M100", False, privilege=PrivilegeMode.SYSTEM)

        ident_pkt = DCPPacket(
            frame_id=ProfinetConstants.FRAME_ID_DCP_IDENT_REQ,
            service_id=DCPServiceId.IDENTIFY,
            service_type=DCPServiceType.REQUEST,
        )
        assert engine.handle_dcp_packet(ident_pkt.serialize()) is None

        rx_frame = ProfinetRTCyclicFrame(frame_id=0x8000)
        assert engine.handle_cyclic_frame(rx_frame.serialize()) is None

    def test_engine_reset_counters_handshake(self):
        rt = RegisterTable()
        engine = ProfinetAdapterEngine(register_table=rt)

        rx_frame = ProfinetRTCyclicFrame(frame_id=0x8000)
        engine.handle_cyclic_frame(rx_frame.serialize())
        engine.handle_cyclic_frame(rx_frame.serialize())
        assert engine.cyclic_rx_count == 2

        rt.write_bit("%M101", True, privilege=PrivilegeMode.SYSTEM)
        engine.handle_cyclic_frame(rx_frame.serialize())
        assert engine.cyclic_rx_count == 1
        assert rt.read_bit("%M101") is False

    def test_full_verification_runner(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_path = os.path.join(tmp_dir, "profinet_evidence.json")
            evidence = run_profinet_verification(ev_path)
            assert evidence["status"] == "success"
            assert evidence["error_code"] is None
            assert os.path.exists(ev_path)
            with open(ev_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert len(data["data"]["tests"]) == 7
            assert all(t["passed"] for t in data["data"]["tests"])
