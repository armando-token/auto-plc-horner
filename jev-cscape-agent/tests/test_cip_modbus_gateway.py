"""Comprehensive Unit and Integration Test Suite for CIP Modbus Gateway Protocol Engine.

Work Package: W223 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Test Coverage (70+ Unit Tests across 10 Sections):
1. Section 1: Constants, Protocol Identifiers, & Operational Enums.
2. Section 2: Endianness Conversions & Word Swapping (16-bit & 32-bit Word/Byte Swaps, Floats).
3. Section 3: CRC-16 & LRC Calculation & Validation (Modbus RTU & ASCII).
4. Section 4: Function Code Translation to CIP Services (FC 01, 02, 03, 04, 05, 06, 16).
5. Section 5: Request/Response FIFO Queuing & Transaction Flow.
6. Section 6: Timeout Surveillance (0xEF03, %M430) & Fault Handling (0xEF01, 0xEF02, 0xEF04).
7. Section 7: Horner OCS Register Synchronization (%R1840..%R1847, %M429..%M430 with PrivilegeMode.SYSTEM).
8. Section 8: ILogicUnit 100-Cycle Simulation Scan & Reset Integration.
9. Section 9: Pure IEC 61131-3 ST POU Validation & SecurityGuard Anti-Ladder Rejection.
10. Section 10: Deterministic 9-Stage Verification Runner (run_cip_modbus_gateway_verification execution & JSON export).
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_modbus_gateway import (
    CIP_CLASS_MODBUS_GATEWAY,
    CIP_MODBUS_GATEWAY_CLASS_ID,
    CIP_MODBUS_GATEWAY_ENGINE,
    CIP_MODBUS_GATEWAY_POU,
    CIP_MODBUS_GATEWAY_SYNC_POU,
    CIP_MODBUS_SYNC_POU,
    CIP_MODBUS_TRANSLATOR_CLASS_ID,
    CIP_SERVICE_GET_ATTRIBUTE_ALL,
    CIP_SERVICE_GET_ATTRIBUTE_LIST,
    CIP_SERVICE_GET_ATTRIBUTE_SINGLE,
    CIP_SERVICE_SET_ATTRIBUTE_ALL,
    CIP_SERVICE_SET_ATTRIBUTE_LIST,
    CIP_SERVICE_SET_ATTRIBUTE_SINGLE,
    DEFAULT_POLL_INTERVAL_S,
    DEFAULT_TRANSACTION_TIMEOUT_MS,
    DEFAULT_TRANSACTION_TIMEOUT_S,
    FC_READ_COILS,
    FC_READ_DISCRETE_INPUTS,
    FC_READ_HOLDING_REGISTERS,
    FC_READ_INPUT_REGISTERS,
    FC_WRITE_MULTIPLE_COILS,
    FC_WRITE_MULTIPLE_REGISTERS,
    FC_WRITE_SINGLE_COIL,
    FC_WRITE_SINGLE_REGISTER,
    MAX_QUEUE_DEPTH,
    MAX_REGISTER_ADDRESS,
    MODBUS_COIL_BASE,
    MODBUS_DISCRETE_BASE,
    MODBUS_HOLDING_REG_BASE,
    MODBUS_INPUT_REG_BASE,
    CipModbusDiagnosticCode,
    CipModbusErrorCode,
    CipModbusGateway,
    CipModbusGatewayEngine,
    CipModbusGatewaySnapshot,
    CipModbusGatewayState,
    CipModbusTransaction,
    CipRequest,
    CipResponse,
    CipServiceCode,
    GatewayOperationalState,
    ModbusFunctionCode,
    ModbusRequest,
    ModbusResponse,
    append_crc16,
    calculate_crc16,
    calculate_lrc,
    check_frame_crc16,
    cip_to_modbus_float32,
    cip_to_modbus_uint16,
    cip_to_modbus_uint32,
    decode_cip_attributes,
    decode_modbus_registers,
    encode_cip_attributes,
    encode_modbus_registers,
    float32_to_cip_bytes,
    float32_to_modbus_bytes,
    modbus_to_cip_float32,
    modbus_to_cip_uint16,
    modbus_to_cip_uint32,
    run_cip_modbus_gateway_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    swap_bytes_16,
    swap_words_32,
    translate_cip_to_modbus_response,
    translate_modbus_to_cip,
    uint32_to_words,
    validate_crc16,
    validate_lrc,
    verify_cip_modbus_gateway_pure_st,
    words_to_uint32,
)


# ============================================================================
# Section 1: Constants, Protocol Identifiers, & Operational Enums
# ============================================================================

class TestConstantsAndEnums:
    """Tests for protocol identifiers, function codes, operational states, and diagnostics."""

    def test_class_ids_and_engine_identifier(self) -> None:
        assert CIP_MODBUS_TRANSLATOR_CLASS_ID == 0x44
        assert CIP_MODBUS_GATEWAY_CLASS_ID == 0x44
        assert CIP_CLASS_MODBUS_GATEWAY == 0x44
        assert CIP_MODBUS_GATEWAY_ENGINE == "cip_modbus_gateway"

    def test_gateway_operational_states(self) -> None:
        assert GatewayOperationalState.STOPPED == 0
        assert GatewayOperationalState.STARTING == 1
        assert GatewayOperationalState.OPERATIONAL == 2
        assert GatewayOperationalState.FAULTED == 3
        assert GatewayOperationalState.DEGRADED == 4

    def test_gateway_operational_state_aliases(self) -> None:
        assert GatewayOperationalState.Stopped == 0
        assert GatewayOperationalState.Operational == 2
        assert GatewayOperationalState.Faulted == 3
        assert CipModbusGatewayState.OPERATIONAL == 2
        assert CipModbusGatewayState.FAULTED == 3

    def test_modbus_function_codes(self) -> None:
        assert ModbusFunctionCode.READ_COILS == 0x01
        assert ModbusFunctionCode.READ_DISCRETE_INPUTS == 0x02
        assert ModbusFunctionCode.READ_HOLDING_REGISTERS == 0x03
        assert ModbusFunctionCode.READ_INPUT_REGISTERS == 0x04
        assert ModbusFunctionCode.WRITE_SINGLE_COIL == 0x05
        assert ModbusFunctionCode.WRITE_SINGLE_REGISTER == 0x06
        assert ModbusFunctionCode.WRITE_MULTIPLE_COILS == 0x0F
        assert ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS == 0x10

    def test_modbus_function_code_constants(self) -> None:
        assert FC_READ_COILS == 0x01
        assert FC_READ_DISCRETE_INPUTS == 0x02
        assert FC_READ_HOLDING_REGISTERS == 0x03
        assert FC_READ_INPUT_REGISTERS == 0x04
        assert FC_WRITE_SINGLE_COIL == 0x05
        assert FC_WRITE_SINGLE_REGISTER == 0x06
        assert FC_WRITE_MULTIPLE_COILS == 0x0F
        assert FC_WRITE_MULTIPLE_REGISTERS == 0x10

    def test_cip_service_codes(self) -> None:
        assert CipServiceCode.GET_ATTRIBUTE_ALL == 0x01
        assert CipServiceCode.SET_ATTRIBUTE_ALL == 0x02
        assert CipServiceCode.GET_ATTRIBUTE_LIST == 0x03
        assert CipServiceCode.SET_ATTRIBUTE_LIST == 0x04
        assert CipServiceCode.RESET == 0x05
        assert CipServiceCode.GET_ATTRIBUTE_SINGLE == 0x0E
        assert CipServiceCode.SET_ATTRIBUTE_SINGLE == 0x10

    def test_cip_service_code_constants(self) -> None:
        assert CIP_SERVICE_GET_ATTRIBUTE_SINGLE == 0x0E
        assert CIP_SERVICE_SET_ATTRIBUTE_SINGLE == 0x10
        assert CIP_SERVICE_GET_ATTRIBUTE_LIST == 0x03
        assert CIP_SERVICE_SET_ATTRIBUTE_LIST == 0x04

    def test_cip_modbus_diagnostic_codes(self) -> None:
        assert CipModbusDiagnosticCode.OK == 0x0000
        assert CipModbusDiagnosticCode.ILLEGAL_FUNCTION == 0xEF01
        assert CipModbusDiagnosticCode.ILLEGAL_DATA_ADDRESS == 0xEF02
        assert CipModbusDiagnosticCode.TRANSACTION_TIMEOUT == 0xEF03
        assert CipModbusDiagnosticCode.CRC_FAULT == 0xEF04
        assert CipModbusDiagnosticCode.ILLEGAL_DATA_VALUE == 0xEF05
        assert CipModbusDiagnosticCode.GATEWAY_BUSY == 0xEF06

    def test_cip_modbus_diagnostic_code_aliases(self) -> None:
        assert CipModbusDiagnosticCode.Ok == 0x0000
        assert CipModbusDiagnosticCode.IllegalFunction == 0xEF01
        assert CipModbusDiagnosticCode.IllegalAddress == 0xEF02
        assert CipModbusDiagnosticCode.TransactionTimeout == 0xEF03
        assert CipModbusDiagnosticCode.CrcFault == 0xEF04
        assert CipModbusErrorCode.TRANSACTION_TIMEOUT == 0xEF03

    def test_default_timing_and_queue_constants(self) -> None:
        assert DEFAULT_TRANSACTION_TIMEOUT_MS == 250.0
        assert DEFAULT_TRANSACTION_TIMEOUT_S == 0.250
        assert MAX_QUEUE_DEPTH == 32
        assert DEFAULT_POLL_INTERVAL_S == 0.010

    def test_memory_map_register_constants_present_in_pou(self) -> None:
        pou = CIP_MODBUS_SYNC_POU
        for reg in [
            "%R1840", "%R1841", "%R1842", "%R1843",
            "%R1844", "%R1845", "%R1846", "%R1847",
            "%M429", "%M430",
        ]:
            assert reg in pou


# ============================================================================
# Section 2: Endianness Conversions & Word Swapping
# ============================================================================

class TestEndiannessConversions:
    """Tests for byte-swapping, word-swapping, integer and float translations."""

    def test_swap_bytes_16(self) -> None:
        assert swap_bytes_16(0x1234) == 0x3412
        assert swap_bytes_16(0x0001) == 0x0100
        assert swap_bytes_16(0xABCD) == 0xCDAB
        assert swap_bytes_16(0xFFFF) == 0xFFFF
        assert swap_bytes_16(0x0000) == 0x0000

    def test_swap_words_32(self) -> None:
        assert swap_words_32(0x12345678) == 0x56781234
        assert swap_words_32(0x00010002) == 0x00020001
        assert swap_words_32(0xAAAABBBB) == 0xBBBBAAAA

    def test_modbus_to_cip_uint16(self) -> None:
        # Modbus big-endian 0x1234 -> CIP little-endian representation 0x3412
        assert modbus_to_cip_uint16(0x1234) == 0x3412
        assert modbus_to_cip_uint16(1000) == swap_bytes_16(1000)

    def test_cip_to_modbus_uint16(self) -> None:
        assert cip_to_modbus_uint16(0x3412) == 0x1234
        assert cip_to_modbus_uint16(0x0102) == 0x0201

    def test_uint16_round_trip(self) -> None:
        for val in [0, 1, 255, 256, 1234, 32767, 65535]:
            cip_val = modbus_to_cip_uint16(val)
            restored = cip_to_modbus_uint16(cip_val)
            assert restored == val

    def test_modbus_to_cip_uint32_standard(self) -> None:
        # 0x12345678 -> bytes: 12 34 56 78 -> unpack little-endian: 0x78563412
        assert modbus_to_cip_uint32(0x12345678, word_swap=False) == 0x78563412

    def test_modbus_to_cip_uint32_word_swap(self) -> None:
        # 0x12345678 with word swap -> words (56 78)(12 34) -> unpack LE: 0x34127856
        assert modbus_to_cip_uint32(0x12345678, word_swap=True) == 0x34127856

    def test_cip_to_modbus_uint32_round_trip(self) -> None:
        for val in [0, 42, 100000, 0x12345678, 0xFFFFFFFF]:
            cip_val = modbus_to_cip_uint32(val, word_swap=False)
            mb_val = cip_to_modbus_uint32(cip_val, word_swap=False)
            assert mb_val == val

    def test_words_to_uint32_big_endian(self) -> None:
        assert words_to_uint32(0x1234, 0x5678, big_endian=True) == 0x12345678

    def test_words_to_uint32_little_endian(self) -> None:
        assert words_to_uint32(0x1234, 0x5678, big_endian=False) == 0x56781234

    def test_uint32_to_words_round_trip(self) -> None:
        val = 0x12345678
        h, l = uint32_to_words(val, big_endian=True)
        assert h == 0x1234
        assert l == 0x5678
        assert words_to_uint32(h, l, big_endian=True) == val

    def test_float32_modbus_to_cip_and_reverse(self) -> None:
        pi_val = 3.1415927
        mb_bytes = float32_to_modbus_bytes(pi_val)
        cip_bytes = float32_to_cip_bytes(pi_val)
        assert len(mb_bytes) == 4
        assert len(cip_bytes) == 4
        assert mb_bytes == cip_bytes[::-1]

        parsed_mb = modbus_to_cip_float32(mb_bytes)
        parsed_cip = cip_to_modbus_float32(cip_bytes)
        assert abs(parsed_mb - pi_val) < 1e-6
        assert abs(parsed_cip - pi_val) < 1e-6

    def test_encode_decode_modbus_registers(self) -> None:
        regs = [100, 200, 300, 65530]
        encoded = encode_modbus_registers(regs)
        assert len(encoded) == 8
        decoded = decode_modbus_registers(encoded)
        assert decoded == regs

    def test_encode_decode_cip_attributes(self) -> None:
        attrs = [10, 20, 30]
        encoded = encode_cip_attributes(attrs)
        assert len(encoded) == 6
        decoded = decode_cip_attributes(encoded)
        assert decoded == attrs

    def test_invalid_register_payload_length_raises(self) -> None:
        with pytest.raises(ValueError):
            decode_modbus_registers(b"\x00\x01\x02")
        with pytest.raises(ValueError):
            decode_cip_attributes(b"\x00")


# ============================================================================
# Section 3: CRC-16 & LRC Calculation & Validation
# ============================================================================

class TestCrcAndLrcValidation:
    """Tests for Modbus RTU CRC-16 and ASCII LRC checksum logic."""

    def test_calculate_crc16_standard_frame(self) -> None:
        # Standard Modbus frame: [0x01, 0x03, 0x00, 0x00, 0x00, 0x0A]
        frame = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
        crc = calculate_crc16(frame)
        assert crc == 0xCDC5

    def test_calculate_crc16_empty_frame(self) -> None:
        assert calculate_crc16(b"") == 0xFFFF

    def test_validate_crc16_valid(self) -> None:
        frame = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
        assert validate_crc16(frame, 0xCDC5) is True

    def test_validate_crc16_invalid(self) -> None:
        frame = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
        assert validate_crc16(frame, 0x0000) is False
        assert validate_crc16(frame, 0xCDC4) is False

    def test_append_crc16(self) -> None:
        frame = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
        frame_with_crc = append_crc16(frame)
        assert len(frame_with_crc) == len(frame) + 2
        # RTU standard appends low byte first (0xC5) then high byte (0xCD)
        assert frame_with_crc[-2:] == struct.pack("<H", 0xCDC5)

    def test_check_frame_crc16_valid(self) -> None:
        frame = bytes([0x02, 0x01, 0x00, 0x00, 0x00, 0x08])
        frame_with_crc = append_crc16(frame)
        assert check_frame_crc16(frame_with_crc) is True

    def test_check_frame_crc16_corrupt(self) -> None:
        frame = bytes([0x02, 0x01, 0x00, 0x00, 0x00, 0x08])
        frame_with_crc = append_crc16(frame)
        corrupted = frame_with_crc[:-2] + b"\x00\x00"
        assert check_frame_crc16(corrupted) is False

    def test_check_frame_crc16_short_frame(self) -> None:
        assert check_frame_crc16(b"\x01\x02") is False
        assert check_frame_crc16(b"") is False

    def test_calculate_lrc_standard(self) -> None:
        frame = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
        # Sum = 1 + 3 + 0 + 0 + 0 + 10 = 14 = 0x0E; Two's complement = -14 = 242 = 0xF2
        lrc = calculate_lrc(frame)
        assert lrc == 0xF2

    def test_validate_lrc_valid_and_invalid(self) -> None:
        frame = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
        assert validate_lrc(frame, 0xF2) is True
        assert validate_lrc(frame, 0xF3) is False
        assert validate_lrc(frame, 0x00) is False


# ============================================================================
# Section 4: Function Code Translation to CIP Services
# ============================================================================

class TestFunctionCodeTranslation:
    """Tests for translating Modbus FCs (01, 02, 03, 04, 05, 06, 16) into CIP Services."""

    def test_translate_fc01_read_coils(self) -> None:
        req = ModbusRequest(transaction_id=1, unit_id=1, function_code=ModbusFunctionCode.READ_COILS, address=10, quantity=8)
        cip_req = translate_modbus_to_cip(req)
        assert cip_req.transaction_id == 1
        assert cip_req.service_code == CipServiceCode.GET_ATTRIBUTE_SINGLE
        assert cip_req.class_id == CIP_MODBUS_TRANSLATOR_CLASS_ID
        assert cip_req.instance_id == 10
        assert cip_req.attribute_id == 1

    def test_translate_fc02_read_discrete_inputs(self) -> None:
        req = ModbusRequest(transaction_id=2, unit_id=1, function_code=ModbusFunctionCode.READ_DISCRETE_INPUTS, address=20, quantity=4)
        cip_req = translate_modbus_to_cip(req)
        assert cip_req.service_code == CipServiceCode.GET_ATTRIBUTE_SINGLE
        assert cip_req.attribute_id == 2
        assert cip_req.instance_id == 20

    def test_translate_fc03_read_holding_registers_single(self) -> None:
        req = ModbusRequest(transaction_id=3, unit_id=1, function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS, address=100, quantity=1)
        cip_req = translate_modbus_to_cip(req)
        assert cip_req.service_code == CipServiceCode.GET_ATTRIBUTE_SINGLE
        assert cip_req.attribute_id == 3
        assert cip_req.instance_id == 100

    def test_translate_fc03_read_holding_registers_multiple(self) -> None:
        req = ModbusRequest(transaction_id=4, unit_id=1, function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS, address=100, quantity=5)
        cip_req = translate_modbus_to_cip(req)
        assert cip_req.service_code == CipServiceCode.GET_ATTRIBUTE_LIST
        assert cip_req.attribute_id == 3
        assert cip_req.instance_id == 100

    def test_translate_fc04_read_input_registers(self) -> None:
        req = ModbusRequest(transaction_id=5, unit_id=1, function_code=ModbusFunctionCode.READ_INPUT_REGISTERS, address=500, quantity=1)
        cip_req = translate_modbus_to_cip(req)
        assert cip_req.service_code == CipServiceCode.GET_ATTRIBUTE_SINGLE
        assert cip_req.attribute_id == 4
        assert cip_req.instance_id == 500

    def test_translate_fc05_write_single_coil_true(self) -> None:
        req = ModbusRequest(transaction_id=6, unit_id=1, function_code=ModbusFunctionCode.WRITE_SINGLE_COIL, address=15, quantity=1, values=[0xFF00])
        cip_req = translate_modbus_to_cip(req)
        assert cip_req.service_code == CipServiceCode.SET_ATTRIBUTE_SINGLE
        assert cip_req.attribute_id == 1
        assert cip_req.instance_id == 15
        assert struct.unpack("<?", cip_req.data)[0] is True

    def test_translate_fc05_write_single_coil_false(self) -> None:
        req = ModbusRequest(transaction_id=7, unit_id=1, function_code=ModbusFunctionCode.WRITE_SINGLE_COIL, address=15, quantity=1, values=[0x0000])
        cip_req = translate_modbus_to_cip(req)
        assert struct.unpack("<?", cip_req.data)[0] is False

    def test_translate_fc06_write_single_register(self) -> None:
        req = ModbusRequest(transaction_id=8, unit_id=1, function_code=ModbusFunctionCode.WRITE_SINGLE_REGISTER, address=200, quantity=1, values=[1234])
        cip_req = translate_modbus_to_cip(req)
        assert cip_req.service_code == CipServiceCode.SET_ATTRIBUTE_SINGLE
        assert cip_req.attribute_id == 3
        assert cip_req.instance_id == 200
        val = struct.unpack("<H", cip_req.data)[0]
        assert val == 1234

    def test_translate_fc16_write_multiple_registers(self) -> None:
        req = ModbusRequest(transaction_id=9, unit_id=1, function_code=ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS, address=300, quantity=3, values=[10, 20, 30])
        cip_req = translate_modbus_to_cip(req)
        assert cip_req.service_code == CipServiceCode.SET_ATTRIBUTE_LIST
        assert cip_req.attribute_id == 3
        count = struct.unpack("<H", cip_req.data[:2])[0]
        assert count == 3
        vals = [struct.unpack("<H", cip_req.data[2 + i*2 : 4 + i*2])[0] for i in range(3)]
        assert vals == [10, 20, 30]

    def test_translate_unsupported_function_code_raises(self) -> None:
        req = ModbusRequest(transaction_id=10, unit_id=1, function_code=0x18, address=0)
        with pytest.raises(ValueError):
            translate_modbus_to_cip(req)

    def test_translate_cip_response_to_modbus_holding_registers(self) -> None:
        req = ModbusRequest(transaction_id=11, unit_id=1, function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS, address=50, quantity=2)
        # CIP returns little-endian values [100, 200]
        cip_data = encode_cip_attributes([100, 200])
        cip_resp = CipResponse(transaction_id=11, service_code=CipServiceCode.GET_ATTRIBUTE_LIST, general_status=0x00, data=cip_data)
        mb_resp = translate_cip_to_modbus_response(cip_resp, req)
        assert mb_resp.transaction_id == 11
        assert mb_resp.is_exception is False
        assert mb_resp.values == [100, 200]

    def test_translate_cip_error_response_to_modbus_exception(self) -> None:
        req = ModbusRequest(transaction_id=12, unit_id=1, function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS, address=50)
        cip_resp = CipResponse(transaction_id=12, service_code=CipServiceCode.GET_ATTRIBUTE_SINGLE, general_status=0x14)
        mb_resp = translate_cip_to_modbus_response(cip_resp, req)
        assert mb_resp.is_exception is True
        assert mb_resp.exception_code == 0x02  # Illegal data address


# ============================================================================
# Section 5: Request/Response FIFO Queuing & Transaction Flow
# ============================================================================

class TestTransactionQueuingAndFlow:
    """Tests for FIFO queuing depth, dispatch, and auto-completion."""

    def test_enqueue_valid_request(self) -> None:
        engine = CipModbusGatewayEngine()
        req = ModbusRequest(1, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 10, 1)
        tx = engine.enqueue_request(req)
        assert tx.transaction_id == 1
        assert engine.active_transaction_count == 1
        assert engine.last_modbus_fc == 0x03
        assert engine.last_cip_service == 0x0E

    def test_enqueue_fifo_order_execution(self) -> None:
        engine = CipModbusGatewayEngine()
        engine.enqueue_request(ModbusRequest(10, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 1, 1))
        engine.enqueue_request(ModbusRequest(20, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 2, 1))
        engine.enqueue_request(ModbusRequest(30, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 3, 1))
        assert engine.active_transaction_count == 3

        p1 = engine.process_next_transaction()
        p2 = engine.process_next_transaction()
        p3 = engine.process_next_transaction()

        assert p1 is not None and p1.transaction_id == 10
        assert p2 is not None and p2.transaction_id == 20
        assert p3 is not None and p3.transaction_id == 30
        assert engine.active_transaction_count == 0
        assert engine.total_transactions_processed == 3

    def test_enqueue_queue_depth_overflow_raises_error(self) -> None:
        engine = CipModbusGatewayEngine(max_queue_depth=3)
        engine.enqueue_request(ModbusRequest(1, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 1, 1))
        engine.enqueue_request(ModbusRequest(2, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 2, 1))
        engine.enqueue_request(ModbusRequest(3, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 3, 1))
        assert engine.active_transaction_count == 3

        with pytest.raises(OverflowError):
            engine.enqueue_request(ModbusRequest(4, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 4, 1))
        assert engine.diagnostic_code == CipModbusDiagnosticCode.GATEWAY_BUSY

    def test_enqueue_illegal_function_code_raises_and_sets_0xef01(self) -> None:
        engine = CipModbusGatewayEngine()
        with pytest.raises(ValueError):
            engine.enqueue_request(ModbusRequest(1, 1, 0x70, 0))
        assert engine.diagnostic_code == CipModbusDiagnosticCode.ILLEGAL_FUNCTION
        assert engine.operational_state == GatewayOperationalState.DEGRADED

    def test_enqueue_illegal_address_negative_raises_and_sets_0xef02(self) -> None:
        engine = CipModbusGatewayEngine()
        with pytest.raises(ValueError):
            engine.enqueue_request(ModbusRequest(1, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, -1))
        assert engine.diagnostic_code == CipModbusDiagnosticCode.ILLEGAL_DATA_ADDRESS
        assert engine.operational_state == GatewayOperationalState.DEGRADED

    def test_enqueue_illegal_address_exceeds_max_raises_and_sets_0xef02(self) -> None:
        engine = CipModbusGatewayEngine()
        with pytest.raises(ValueError):
            engine.enqueue_request(ModbusRequest(1, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 70000))
        assert engine.diagnostic_code == CipModbusDiagnosticCode.ILLEGAL_DATA_ADDRESS

    def test_process_next_empty_queue_returns_none(self) -> None:
        engine = CipModbusGatewayEngine()
        assert engine.process_next_transaction() is None

    def test_process_write_single_register_updates_virtual_holding_register(self) -> None:
        engine = CipModbusGatewayEngine()
        req = ModbusRequest(1, 1, ModbusFunctionCode.WRITE_SINGLE_REGISTER, address=45, values=[789])
        engine.enqueue_request(req)
        tx = engine.process_next_transaction()
        assert tx is not None and tx.is_completed is True
        assert engine._virtual_holding_registers[45] == 789

    def test_process_write_single_coil_updates_virtual_coil(self) -> None:
        engine = CipModbusGatewayEngine()
        req = ModbusRequest(1, 1, ModbusFunctionCode.WRITE_SINGLE_COIL, address=12, values=[0xFF00])
        engine.enqueue_request(req)
        engine.process_next_transaction()
        assert engine._virtual_coils[12] is True

    def test_complete_transaction_explicit_response(self) -> None:
        engine = CipModbusGatewayEngine()
        req = ModbusRequest(55, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, address=10, quantity=1)
        engine.enqueue_request(req)
        cip_resp = CipResponse(transaction_id=55, service_code=CipServiceCode.GET_ATTRIBUTE_SINGLE, general_status=0x00, data=encode_cip_attributes([500]))
        mb_resp = engine.complete_transaction(55, cip_resp)
        assert mb_resp is not None
        assert mb_resp.values == [500]
        assert engine.total_transactions_processed == 1


# ============================================================================
# Section 6: Timeout Surveillance & Interlock Handling
# ============================================================================

class TestTimeoutSurveillanceAndInterlocks:
    """Tests for transaction round-trip timeout handling, 0xEF03, and %M430 trip."""

    def test_transaction_timeout_triggers_0xef03(self) -> None:
        engine = CipModbusGatewayEngine(timeout_ms=50.0)
        engine.enqueue_request(ModbusRequest(1, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 10, 1))
        # Advance simulation clock past 50 ms timeout
        engine.scan_step(dt=0.060)
        assert engine.is_timeout_tripped is True
        assert engine.diagnostic_code == CipModbusDiagnosticCode.TRANSACTION_TIMEOUT
        assert engine.operational_state == GatewayOperationalState.FAULTED
        assert engine.is_engine_active is False
        assert engine.timeout_count == 1

    def test_transaction_timeout_asserts_m430_and_clears_m429(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt, timeout_ms=40.0)
        engine.enqueue_request(ModbusRequest(2, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 10, 1))
        assert rt.read_bit("%M429") is True
        assert rt.read_bit("%M430") is False

        # Advance past timeout
        engine.scan_step(dt=0.050)
        assert rt.read_bit("%M430") is True
        assert rt.read_bit("%M429") is False

    def test_explicit_trip_timeout(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        engine.trip_timeout()
        assert engine.is_timeout_tripped is True
        assert engine.diagnostic_code == CipModbusDiagnosticCode.TRANSACTION_TIMEOUT
        assert rt.read_bit("%M430") is True
        assert rt.read_bit("%M429") is False

    def test_clear_faults_restores_operational_state(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        engine.trip_timeout()
        assert engine.is_timeout_tripped is True
        engine.clear_faults()
        assert engine.is_timeout_tripped is False
        assert engine.diagnostic_code == CipModbusDiagnosticCode.OK
        assert engine.operational_state == GatewayOperationalState.OPERATIONAL
        assert rt.read_bit("%M430") is False
        assert rt.read_bit("%M429") is True

    def test_report_crc_fault_increments_count_and_sets_0xef04(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        engine.report_crc_fault()
        assert engine.crc_fault_count == 1
        assert engine.diagnostic_code == CipModbusDiagnosticCode.CRC_FAULT
        assert engine.operational_state == GatewayOperationalState.DEGRADED
        assert (rt.read_word("%R1847") & 0xFFFF) == 0xEF04

    def test_multiple_timeouts_increment_counter(self) -> None:
        engine = CipModbusGatewayEngine(timeout_ms=20.0)
        for i in range(3):
            engine.enqueue_request(ModbusRequest(i + 1, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 10, 1))
            engine.scan_step(dt=0.030)
            engine.clear_faults()
        assert engine.timeout_count == 3


# ============================================================================
# Section 7: Horner OCS Register Table Synchronization
# ============================================================================

class TestHornerRegisterSynchronization:
    """Tests for %R1840..%R1847, %M429..%M430 synchronization with PrivilegeMode.SYSTEM."""

    def test_register_sync_privilege_mode_system(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        # Should not raise PermissionError
        engine.sync_to_registers(privilege=PrivilegeMode.SYSTEM)

    def test_r1840_operational_state_sync(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        assert rt.read_word("%R1840") == int(GatewayOperationalState.OPERATIONAL)
        engine.operational_state = GatewayOperationalState.DEGRADED
        engine.sync_to_registers()
        assert rt.read_word("%R1840") == int(GatewayOperationalState.DEGRADED)

    def test_r1841_active_transaction_count_sync(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        engine.enqueue_request(ModbusRequest(1, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 10, 1))
        engine.enqueue_request(ModbusRequest(2, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 20, 1))
        assert rt.read_word("%R1841") == 2

    def test_r1842_total_transactions_processed_sync(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        engine.enqueue_request(ModbusRequest(1, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 10, 1))
        engine.process_next_transaction()
        assert rt.read_word("%R1842") == 1

    def test_r1843_crc_fault_count_sync(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        engine.report_crc_fault()
        engine.report_crc_fault()
        assert rt.read_word("%R1843") == 2

    def test_r1844_timeout_count_sync(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        engine.trip_timeout()
        assert rt.read_word("%R1844") == 1

    def test_r1845_and_r1846_last_fc_and_cip_service_sync(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        engine.enqueue_request(ModbusRequest(1, 1, ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS, 100, 2, values=[1, 2]))
        assert rt.read_word("%R1845") == 0x10  # FC 16
        assert rt.read_word("%R1846") == 0x04  # Set Attribute List

    def test_r1847_diagnostic_code_read_word_signed_masking(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        engine.trip_timeout()
        # reg_table.read_word returns signed 16-bit int; mask with & 0xFFFF when comparing hex status codes!
        raw_val = rt.read_word("%R1847")
        assert (raw_val & 0xFFFF) == 0xEF03

    def test_r1847_diagnostic_code_read_uword(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        engine.report_illegal_function(0x99)
        assert rt.read_uword("%R1847") == 0xEF01

    def test_m429_and_m430_coils_sync(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        assert rt.read_bit("%M429") is True
        assert rt.read_bit("%M430") is False

        engine.trip_timeout()
        assert rt.read_bit("%M429") is False
        assert rt.read_bit("%M430") is True

    def test_telemetry_snapshot_dataclass_fidelity(self) -> None:
        engine = CipModbusGatewayEngine()
        snap = engine.get_snapshot()
        assert isinstance(snap, CipModbusGatewaySnapshot)
        assert snap.state == GatewayOperationalState.OPERATIONAL
        d = snap.to_dict()
        assert "state" in d
        assert "diagnostic_code_hex" in d
        assert "engine_active" in d


# ============================================================================
# Section 8: ILogicUnit Scan Cycle Simulation & Reset
# ============================================================================

class TestILogicUnitSimulation:
    """Tests for ILogicUnit interface, scan_step, ScanContext, and reset."""

    def test_ilogicunit_properties(self) -> None:
        engine = CipModbusGatewayEngine()
        assert engine.name == "cip_modbus_gateway"
        assert engine.priority == 95
        assert engine.is_enabled is True

    def test_ilogicunit_execute_scan_context(self) -> None:
        engine = CipModbusGatewayEngine()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        engine.execute(context=ctx)
        assert engine.total_scan_cycles == 1
        assert abs(engine.elapsed_simulation_s - 0.02) < 1e-4

    def test_ilogicunit_100_cycle_soak_execution(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        for c in range(100):
            ctx = ScanContext(cycle=c, dt_ms=10.0, elapsed_time_ms=c * 10.0, dt=0.01)
            engine.execute(context=ctx)
        assert engine.total_scan_cycles == 100
        assert abs(engine.elapsed_simulation_s - 1.0) < 1e-6
        assert rt.read_word("%R1840") == int(GatewayOperationalState.OPERATIONAL)

    def test_ilogicunit_reset_restores_nominal_state(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        engine.trip_timeout()
        assert engine.is_timeout_tripped is True
        assert rt.read_bit("%M430") is True

        engine.reset()
        assert engine.is_timeout_tripped is False
        assert engine.operational_state == GatewayOperationalState.OPERATIONAL
        assert rt.read_bit("%M430") is False
        assert rt.read_bit("%M429") is True
        assert rt.read_uword("%R1847") == 0x0000

    def test_ilogicunit_reset_clears_active_and_pending_transactions(self) -> None:
        engine = CipModbusGatewayEngine()
        engine.enqueue_request(ModbusRequest(1, 1, ModbusFunctionCode.READ_HOLDING_REGISTERS, 10, 1))
        assert engine.active_transaction_count == 1
        engine.reset()
        assert engine.active_transaction_count == 0

    def test_ilogicunit_is_enabled_toggle(self) -> None:
        rt = RegisterTable()
        engine = CipModbusGatewayEngine(reg_table=rt)
        engine.is_enabled = False
        assert engine.is_enabled is False
        assert engine.is_engine_active is False
        assert engine.operational_state == GatewayOperationalState.STOPPED
        assert rt.read_bit("%M429") is False

    def test_ilogicunit_execute_when_disabled_noop(self) -> None:
        engine = CipModbusGatewayEngine()
        engine.is_enabled = False
        ctx = ScanContext(cycle=1, dt_ms=10.0, elapsed_time_ms=10.0, dt=0.01)
        engine.execute(context=ctx)
        assert engine.total_scan_cycles == 0


# ============================================================================
# Section 9: Pure ST POU Validation & SecurityGuard Anti-Ladder Rejection
# ============================================================================

class TestPureSTPOUAndSecurityGuard:
    """Tests for IEC 61131-3 Pure Structured Text parsing and ladder rejection."""

    def test_security_guard_assert_pure_st_content_passes(self) -> None:
        # Must pass without raising LadderForbiddenError
        SecurityGuard.assert_pure_st_content(CIP_MODBUS_SYNC_POU)

    def test_st_parser_validate_code_success(self) -> None:
        val = STParser.validate_code(CIP_MODBUS_SYNC_POU)
        assert val.status == AgentStatus.SUCCESS

    def test_st_parser_parse_pou_ast_and_bound_registers(self) -> None:
        ast = STParser.parse_pou(CIP_MODBUS_SYNC_POU)
        assert ast.name == "CipModbusSync"
        expected_regs = {
            "%R1840", "%R1841", "%R1842", "%R1843",
            "%R1844", "%R1845", "%R1846", "%R1847",
            "%M429", "%M430",
        }
        bound = set(ast.bound_registers)
        assert expected_regs.issubset(bound)

    def test_anti_ladder_rejects_contact_construct(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(
                "PROGRAM BadPOU\nVAR X:BOOL;\nEND_VAR\n---[ ]---\nEND_PROGRAM"
            )

    def test_anti_ladder_rejects_coil_construct(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(
                "PROGRAM BadPOU\nVAR X:BOOL;\nEND_VAR\n---( )---\nEND_PROGRAM"
            )

    def test_anti_ladder_rejects_rung_delimiters(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(
                "PROGRAM BadPOU\nVAR X:BOOL;\nEND_VAR\nRUNG 1\nEND_PROGRAM"
            )

    def test_anti_ladder_rejects_ladder_mnemonics_xic(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(
                "PROGRAM BadPOU\nVAR X:BOOL;\nEND_VAR\nXIC RelayCoil\nEND_PROGRAM"
            )

    def test_anti_ladder_rejects_ladder_mnemonics_ote(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(
                "PROGRAM BadPOU\nVAR X:BOOL;\nEND_VAR\nOTE RelayCoil\nEND_PROGRAM"
            )

    def test_verify_cip_modbus_gateway_pure_st_helper(self) -> None:
        assert verify_cip_modbus_gateway_pure_st() is True


# ============================================================================
# Section 10: Deterministic 9-Stage Verification Runner
# ============================================================================

class TestVerificationRunner:
    """Tests for run_cip_modbus_gateway_verification execution and evidence export."""

    def test_verification_runner_executes_cleanly(self) -> None:
        report = run_cip_modbus_gateway_verification()
        assert isinstance(report, dict)
        assert report.get("status") in ("success", "failed", "blocked", "inconclusive")

    def test_verification_runner_returns_success_contract(self) -> None:
        report = run_cip_modbus_gateway_verification()
        assert report["status"] == "success"
        assert report["error_code"] is None
        assert "data" in report

    def test_verification_runner_passes_all_9_stages(self) -> None:
        report = run_cip_modbus_gateway_verification()
        stages = report["data"]["stages"]
        assert len(stages) == 9
        assert report["data"]["stages_passed"] == 9
        for s in stages:
            assert s["passed"] is True, f"Stage {s['stage']} failed: {s.get('details')}"

    def test_verification_runner_exports_json_evidence(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_modbus_gateway_evidence_test.json"
        report = run_cip_modbus_gateway_verification(output_path=out_file)
        assert out_file.exists()
        assert report["status"] == "success"

        with open(out_file, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["status"] == "success"
        assert loaded["data"]["total_stages"] == 9

    def test_verification_runner_json_evidence_integrity(self) -> None:
        default_evidence = Path("artifacts/telemetry/cip_modbus_gateway_evidence.json")
        if default_evidence.exists():
            with open(default_evidence, "r", encoding="utf-8") as f:
                evidence = json.load(f)
            assert evidence["status"] == "success"
            assert len(evidence["data"]["stages"]) == 9
