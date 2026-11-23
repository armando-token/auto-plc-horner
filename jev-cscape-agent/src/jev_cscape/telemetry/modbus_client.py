"""Modbus RTU / TCP Master Client Protocol Engine.

Provides a pure-software in-memory Modbus Master Client implementation supporting:
- Protocol framing: Modbus RTU (CRC-16-IBM) and Modbus TCP (MBAP header)
- Standard function codes:
    * FC 01: Read Coils (%Q / %M)
    * FC 02: Read Discrete Inputs (%I)
    * FC 03: Read Holding Registers (%R / %AQ)
    * FC 04: Read Input Registers (%AI)
    * FC 05: Write Single Coil
    * FC 06: Write Single Register
    * FC 15: Write Multiple Coils
    * FC 16: Write Multiple Registers
- Exception code decoding (0x01..0x04)
- Transaction sequence tracking, configurable retries, and strict 4-state contract returns.
- Pure in-memory transport callback: zero physical COM ports, zero external network sockets.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.telemetry.modbus_stack import (
    ModbusExceptionCode,
    ModbusFunctionCode,
    ModbusMemoryStack,
    ModbusPDU,
    compute_crc16,
)


class ModbusProtocolMode(str, Enum):
    """Modbus protocol framing mode."""

    RTU = "RTU"
    TCP = "TCP"


@dataclass
class ModbusMasterTelemetry:
    """Telemetry counters for Modbus master transactions."""

    requests_sent: int = 0
    responses_received: int = 0
    crc_errors: int = 0
    timeouts: int = 0
    retries_attempted: int = 0
    exceptions_received: int = 0
    successful_transactions: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "requests_sent": self.requests_sent,
            "responses_received": self.responses_received,
            "crc_errors": self.crc_errors,
            "timeouts": self.timeouts,
            "retries_attempted": self.retries_attempted,
            "exceptions_received": self.exceptions_received,
            "successful_transactions": self.successful_transactions,
        }


class ModbusMasterClient:
    """Pure-software in-memory Modbus Master Client."""

    def __init__(
        self,
        transport: Callable[[bytes], bytes],
        protocol_mode: ModbusProtocolMode = ModbusProtocolMode.RTU,
        default_unit_id: int = 1,
        max_retries: int = 2,
        timeout_ms: float = 1000.0,
    ) -> None:
        """Initialize ModbusMasterClient.

        Args:
            transport: In-memory callable dispatching request frame to server and returning response frame.
            protocol_mode: RTU (with CRC-16) or TCP (with MBAP header).
            default_unit_id: Default slave/unit ID (1..247).
            max_retries: Max retry attempts on transport/CRC errors.
            timeout_ms: Virtual timeout in milliseconds.
        """
        self.transport = transport
        self.protocol_mode = protocol_mode
        self.default_unit_id = default_unit_id
        self.max_retries = max(0, max_retries)
        self.timeout_ms = timeout_ms
        self.transaction_id: int = 0
        self.telemetry = ModbusMasterTelemetry()

    @classmethod
    def create_in_memory_rtu(cls, memory_stack: ModbusMemoryStack, unit_id: int = 1) -> ModbusMasterClient:
        """Create an RTU master client directly bound to an in-memory ModbusMemoryStack."""
        return cls(
            transport=memory_stack.process_rtu_frame,
            protocol_mode=ModbusProtocolMode.RTU,
            default_unit_id=unit_id,
        )

    @classmethod
    def create_in_memory_tcp(cls, memory_stack: ModbusMemoryStack, unit_id: int = 1) -> ModbusMasterClient:
        """Create a TCP master client directly bound to an in-memory ModbusMemoryStack."""
        return cls(
            transport=memory_stack.process_tcp_frame,
            protocol_mode=ModbusProtocolMode.TCP,
            default_unit_id=unit_id,
        )

    def _next_transaction_id(self) -> int:
        self.transaction_id = (self.transaction_id + 1) & 0xFFFF
        if self.transaction_id == 0:
            self.transaction_id = 1
        return self.transaction_id

    def build_request_frame(self, pdu: ModbusPDU, unit_id: int) -> Tuple[bytes, int]:
        """Build binary request frame (RTU or TCP).

        Returns:
            Tuple of (frame_bytes, transaction_id). For RTU, transaction_id is 0.
        """
        pdu_bytes = pdu.serialize()
        if self.protocol_mode == ModbusProtocolMode.RTU:
            unit_byte = bytes([unit_id & 0xFF])
            payload = unit_byte + pdu_bytes
            crc = compute_crc16(payload)
            crc_bytes = struct.pack("<H", crc)
            return payload + crc_bytes, 0

        # TCP mode: MBAP header (TransactionID [2], ProtocolID [2]=0, Length [2], UnitID [1])
        trans_id = self._next_transaction_id()
        length = len(pdu_bytes) + 1  # PDU + UnitID
        mbap = struct.pack(">HHHB", trans_id, 0, length, unit_id & 0xFF)
        return mbap + pdu_bytes, trans_id

    def parse_response_frame(
        self,
        frame: bytes,
        expected_unit_id: int,
        expected_fc: ModbusFunctionCode,
        expected_trans_id: int = 0,
    ) -> Tuple[Optional[ModbusPDU], Optional[str], Optional[ModbusExceptionCode]]:
        """Parse received response frame.

        Returns:
            (pdu, error_code, exception_code)
        """
        if not frame:
            return None, "ERR_MODBUS_EMPTY_RESPONSE", None

        if self.protocol_mode == ModbusProtocolMode.RTU:
            if len(frame) < 5:  # Min RTU: Unit(1) + FC(1) + Data/Exc(1) + CRC(2)
                return None, "ERR_MODBUS_FRAME_TOO_SHORT", None

            payload = frame[:-2]
            received_crc = struct.unpack("<H", frame[-2:])[0]
            expected_crc = compute_crc16(payload)
            if received_crc != expected_crc:
                return None, "ERR_MODBUS_CRC_MISMATCH", None

            unit_id = payload[0]
            if unit_id != expected_unit_id:
                return None, "ERR_MODBUS_UNIT_ID_MISMATCH", None

            pdu_bytes = payload[1:]
        else:
            # TCP mode
            if len(frame) < 9:  # Min TCP: MBAP(7) + FC(1) + Data/Exc(1)
                return None, "ERR_MODBUS_FRAME_TOO_SHORT", None

            trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", frame[:7])
            if trans_id != expected_trans_id:
                return None, "ERR_MODBUS_TRANSACTION_ID_MISMATCH", None
            if proto_id != 0:
                return None, "ERR_MODBUS_PROTOCOL_ID_INVALID", None
            if unit_id != expected_unit_id:
                return None, "ERR_MODBUS_UNIT_ID_MISMATCH", None

            pdu_bytes = frame[7:]

        if not pdu_bytes:
            return None, "ERR_MODBUS_EMPTY_PDU", None

        fc_byte = pdu_bytes[0]
        # Check exception response: FC | 0x80
        if fc_byte == (int(expected_fc) | 0x80):
            if len(pdu_bytes) >= 2:
                exc_val = pdu_bytes[1]
                try:
                    exc_code = ModbusExceptionCode(exc_val)
                except ValueError:
                    exc_code = ModbusExceptionCode.SLAVE_DEVICE_FAILURE
                return None, f"ERR_MODBUS_EXCEPTION_{exc_code.name}", exc_code
            return None, "ERR_MODBUS_EXCEPTION_UNKNOWN", ModbusExceptionCode.SLAVE_DEVICE_FAILURE

        if fc_byte != int(expected_fc):
            return None, "ERR_MODBUS_UNEXPECTED_FUNCTION_CODE", None

        try:
            pdu = ModbusPDU.deserialize(pdu_bytes)
            return pdu, None, None
        except Exception as exc:
            return None, f"ERR_MODBUS_PDU_DECODE_FAILED: {exc}", None

    def execute_pdu(
        self,
        pdu: ModbusPDU,
        unit_id: Optional[int] = None,
    ) -> ExecutionResult:
        """Execute a Modbus transaction with retries on transient errors."""
        effective_unit_id = unit_id if unit_id is not None else self.default_unit_id
        last_error_code: Optional[str] = None
        last_details: str = ""

        for attempt in range(self.max_retries + 1):
            self.telemetry.requests_sent += 1
            if attempt > 0:
                self.telemetry.retries_attempted += 1

            request_frame, trans_id = self.build_request_frame(pdu, effective_unit_id)

            try:
                response_frame = self.transport(request_frame)
            except Exception as exc:
                last_error_code = "ERR_MODBUS_TRANSPORT_FAULT"
                last_details = f"Transport callable failed: {exc}"
                continue

            self.telemetry.responses_received += 1
            resp_pdu, error_code, exc_code = self.parse_response_frame(
                response_frame,
                expected_unit_id=effective_unit_id,
                expected_fc=pdu.function_code,
                expected_trans_id=trans_id,
            )

            if exc_code is not None:
                # Modbus exception response is deterministic: do not retry
                self.telemetry.exceptions_received += 1
                return ExecutionResult(
                    status=AgentStatus.FAILED,
                    error_code=error_code,
                    details=f"Modbus exception {exc_code.name} (0x{exc_code.value:02X}) returned by slave {effective_unit_id}.",
                    data={
                        "unit_id": effective_unit_id,
                        "function_code": int(pdu.function_code),
                        "exception_code": exc_code.value,
                        "exception_name": exc_code.name,
                        "attempts": attempt + 1,
                    },
                )

            if error_code is None and resp_pdu is not None:
                self.telemetry.successful_transactions += 1
                try:
                    fc_name = ModbusFunctionCode(pdu.function_code).name
                except Exception:
                    fc_name = str(pdu.function_code)
                return ExecutionResult(
                    status=AgentStatus.SUCCESS,
                    error_code=None,
                    details=f"Modbus transaction {fc_name} succeeded.",
                    data={
                        "unit_id": effective_unit_id,
                        "function_code": int(resp_pdu.function_code),
                        "data_payload": resp_pdu.data.hex(),
                        "attempts": attempt + 1,
                        "protocol_mode": self.protocol_mode.value,
                    },
                )

            last_error_code = error_code
            last_details = f"Frame validation failed on attempt {attempt + 1}: {error_code}"
            if error_code == "ERR_MODBUS_CRC_MISMATCH":
                self.telemetry.crc_errors += 1
            elif error_code in ("ERR_MODBUS_EMPTY_RESPONSE", "ERR_MODBUS_FRAME_TOO_SHORT"):
                self.telemetry.timeouts += 1

        return ExecutionResult(
            status=AgentStatus.FAILED,
            error_code=last_error_code or "ERR_MODBUS_MAX_RETRIES_EXCEEDED",
            details=f"Modbus transaction failed after {self.max_retries + 1} attempts. Last error: {last_details}",
            data={
                "unit_id": effective_unit_id,
                "function_code": int(pdu.function_code),
                "attempts": self.max_retries + 1,
                "telemetry": self.telemetry.to_dict(),
            },
        )

    # -------------------------------------------------------------------------
    # High-level Modbus Client Function Methods
    # -------------------------------------------------------------------------

    def read_coils(self, start_address: int, count: int, unit_id: Optional[int] = None) -> ExecutionResult:
        """FC 01: Read Coils (%Q / %M)."""
        if count < 1 or count > 2000:
            return ExecutionResult.failed(
                "ERR_MODBUS_INVALID_QUANTITY",
                f"Read coil quantity must be between 1 and 2000, got {count}",
            )
        req_pdu = ModbusPDU(
            function_code=ModbusFunctionCode.READ_COILS,
            data=struct.pack(">HH", start_address, count),
        )
        res = self.execute_pdu(req_pdu, unit_id=unit_id)
        if res.status != AgentStatus.SUCCESS:
            return res

        raw_data = bytes.fromhex(res.data["data_payload"])
        if len(raw_data) < 1:
            return ExecutionResult.failed("ERR_MODBUS_PAYLOAD_CORRUPT", "Empty response data")

        byte_count = raw_data[0]
        bit_bytes = raw_data[1:]
        expected_bytes = (count + 7) // 8
        if byte_count != expected_bytes or len(bit_bytes) < byte_count:
            return ExecutionResult.failed("ERR_MODBUS_PAYLOAD_MISMATCH", "Byte count mismatch")

        bits: List[bool] = []
        for i in range(count):
            byte_idx = i // 8
            bit_idx = i % 8
            bit_val = bool((bit_bytes[byte_idx] >> bit_idx) & 0x01)
            bits.append(bit_val)

        res.data["bits"] = bits
        res.data["count"] = count
        res.data["start_address"] = start_address
        return res

    def read_discrete_inputs(self, start_address: int, count: int, unit_id: Optional[int] = None) -> ExecutionResult:
        """FC 02: Read Discrete Inputs (%I)."""
        if count < 1 or count > 2000:
            return ExecutionResult.failed(
                "ERR_MODBUS_INVALID_QUANTITY",
                f"Read input quantity must be between 1 and 2000, got {count}",
            )
        req_pdu = ModbusPDU(
            function_code=ModbusFunctionCode.READ_DISCRETE_INPUTS,
            data=struct.pack(">HH", start_address, count),
        )
        res = self.execute_pdu(req_pdu, unit_id=unit_id)
        if res.status != AgentStatus.SUCCESS:
            return res

        raw_data = bytes.fromhex(res.data["data_payload"])
        if len(raw_data) < 1:
            return ExecutionResult.failed("ERR_MODBUS_PAYLOAD_CORRUPT", "Empty response data")

        byte_count = raw_data[0]
        bit_bytes = raw_data[1:]
        expected_bytes = (count + 7) // 8
        if byte_count != expected_bytes or len(bit_bytes) < byte_count:
            return ExecutionResult.failed("ERR_MODBUS_PAYLOAD_MISMATCH", "Byte count mismatch")

        bits: List[bool] = []
        for i in range(count):
            byte_idx = i // 8
            bit_idx = i % 8
            bit_val = bool((bit_bytes[byte_idx] >> bit_idx) & 0x01)
            bits.append(bit_val)

        res.data["bits"] = bits
        res.data["count"] = count
        res.data["start_address"] = start_address
        return res

    def read_holding_registers(
        self,
        start_address: int,
        count: int,
        unit_id: Optional[int] = None,
        signed: bool = True,
    ) -> ExecutionResult:
        """FC 03: Read Holding Registers (%R / %AQ)."""
        if count < 1 or count > 125:
            return ExecutionResult.failed(
                "ERR_MODBUS_INVALID_QUANTITY",
                f"Read register quantity must be between 1 and 125, got {count}",
            )
        req_pdu = ModbusPDU(
            function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS,
            data=struct.pack(">HH", start_address, count),
        )
        res = self.execute_pdu(req_pdu, unit_id=unit_id)
        if res.status != AgentStatus.SUCCESS:
            return res

        raw_data = bytes.fromhex(res.data["data_payload"])
        if len(raw_data) < 1 + count * 2:
            return ExecutionResult.failed("ERR_MODBUS_PAYLOAD_TRUNCATED", "Holding register response truncated")

        byte_count = raw_data[0]
        if byte_count != count * 2:
            return ExecutionResult.failed("ERR_MODBUS_BYTE_COUNT_MISMATCH", f"Expected {count * 2} bytes, got {byte_count}")

        registers: List[int] = []
        fmt = ">h" if signed else ">H"
        for i in range(count):
            word_bytes = raw_data[1 + i * 2 : 3 + i * 2]
            val = struct.unpack(fmt, word_bytes)[0]
            registers.append(val)

        res.data["registers"] = registers
        res.data["count"] = count
        res.data["start_address"] = start_address
        return res

    def read_input_registers(
        self,
        start_address: int,
        count: int,
        unit_id: Optional[int] = None,
        signed: bool = True,
    ) -> ExecutionResult:
        """FC 04: Read Input Registers (%AI)."""
        if count < 1 or count > 125:
            return ExecutionResult.failed(
                "ERR_MODBUS_INVALID_QUANTITY",
                f"Read input register quantity must be between 1 and 125, got {count}",
            )
        req_pdu = ModbusPDU(
            function_code=ModbusFunctionCode.READ_INPUT_REGISTERS,
            data=struct.pack(">HH", start_address, count),
        )
        res = self.execute_pdu(req_pdu, unit_id=unit_id)
        if res.status != AgentStatus.SUCCESS:
            return res

        raw_data = bytes.fromhex(res.data["data_payload"])
        if len(raw_data) < 1 + count * 2:
            return ExecutionResult.failed("ERR_MODBUS_PAYLOAD_TRUNCATED", "Input register response truncated")

        byte_count = raw_data[0]
        if byte_count != count * 2:
            return ExecutionResult.failed("ERR_MODBUS_BYTE_COUNT_MISMATCH", f"Expected {count * 2} bytes, got {byte_count}")

        registers: List[int] = []
        fmt = ">h" if signed else ">H"
        for i in range(count):
            word_bytes = raw_data[1 + i * 2 : 3 + i * 2]
            val = struct.unpack(fmt, word_bytes)[0]
            registers.append(val)

        res.data["registers"] = registers
        res.data["count"] = count
        res.data["start_address"] = start_address
        return res

    def write_single_coil(self, address: int, value: bool, unit_id: Optional[int] = None) -> ExecutionResult:
        """FC 05: Write Single Coil (%Q / %M)."""
        val_code = 0xFF00 if value else 0x0000
        req_pdu = ModbusPDU(
            function_code=ModbusFunctionCode.WRITE_SINGLE_COIL,
            data=struct.pack(">HH", address, val_code),
        )
        res = self.execute_pdu(req_pdu, unit_id=unit_id)
        if res.status != AgentStatus.SUCCESS:
            return res

        raw_data = bytes.fromhex(res.data["data_payload"])
        if len(raw_data) < 4:
            return ExecutionResult.failed("ERR_MODBUS_PAYLOAD_TRUNCATED", "Write coil response truncated")

        echo_addr, echo_val = struct.unpack(">HH", raw_data[:4])
        if echo_addr != address or echo_val != val_code:
            return ExecutionResult.failed("ERR_MODBUS_ECHO_MISMATCH", "Write single coil echo mismatch")

        res.data["address"] = address
        res.data["written_value"] = value
        return res

    def write_single_register(self, address: int, value: int, unit_id: Optional[int] = None) -> ExecutionResult:
        """FC 06: Write Single Register (%R / %AQ)."""
        val_code = value & 0xFFFF
        req_pdu = ModbusPDU(
            function_code=ModbusFunctionCode.WRITE_SINGLE_REGISTER,
            data=struct.pack(">HH", address, val_code),
        )
        res = self.execute_pdu(req_pdu, unit_id=unit_id)
        if res.status != AgentStatus.SUCCESS:
            return res

        raw_data = bytes.fromhex(res.data["data_payload"])
        if len(raw_data) < 4:
            return ExecutionResult.failed("ERR_MODBUS_PAYLOAD_TRUNCATED", "Write register response truncated")

        echo_addr, echo_val = struct.unpack(">HH", raw_data[:4])
        if echo_addr != address or echo_val != val_code:
            return ExecutionResult.failed("ERR_MODBUS_ECHO_MISMATCH", "Write single register echo mismatch")

        res.data["address"] = address
        res.data["written_value"] = value
        return res

    def write_multiple_coils(
        self,
        start_address: int,
        values: List[bool],
        unit_id: Optional[int] = None,
    ) -> ExecutionResult:
        """FC 15: Write Multiple Coils (%Q / %M)."""
        count = len(values)
        if count < 1 or count > 1968:
            return ExecutionResult.failed(
                "ERR_MODBUS_INVALID_QUANTITY",
                f"Write coil count must be between 1 and 1968, got {count}",
            )

        byte_count = (count + 7) // 8
        bit_bytes = bytearray(byte_count)
        for i, val in enumerate(values):
            if val:
                bit_bytes[i // 8] |= 1 << (i % 8)

        payload = struct.pack(">HHB", start_address, count, byte_count) + bytes(bit_bytes)
        req_pdu = ModbusPDU(
            function_code=ModbusFunctionCode.WRITE_MULTIPLE_COILS,
            data=payload,
        )
        res = self.execute_pdu(req_pdu, unit_id=unit_id)
        if res.status != AgentStatus.SUCCESS:
            return res

        raw_data = bytes.fromhex(res.data["data_payload"])
        if len(raw_data) < 4:
            return ExecutionResult.failed("ERR_MODBUS_PAYLOAD_TRUNCATED", "Write multiple coils response truncated")

        echo_addr, echo_count = struct.unpack(">HH", raw_data[:4])
        if echo_addr != start_address or echo_count != count:
            return ExecutionResult.failed("ERR_MODBUS_ECHO_MISMATCH", "Write multiple coils echo mismatch")

        res.data["start_address"] = start_address
        res.data["coils_written"] = count
        return res

    def write_multiple_registers(
        self,
        start_address: int,
        values: List[int],
        unit_id: Optional[int] = None,
    ) -> ExecutionResult:
        """FC 16: Write Multiple Registers (%R / %AQ)."""
        count = len(values)
        if count < 1 or count > 123:
            return ExecutionResult.failed(
                "ERR_MODBUS_INVALID_QUANTITY",
                f"Write register count must be between 1 and 123, got {count}",
            )

        byte_count = count * 2
        word_bytes = bytearray()
        for val in values:
            word_bytes.extend(struct.pack(">H", val & 0xFFFF))

        payload = struct.pack(">HHB", start_address, count, byte_count) + bytes(word_bytes)
        req_pdu = ModbusPDU(
            function_code=ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS,
            data=payload,
        )
        res = self.execute_pdu(req_pdu, unit_id=unit_id)
        if res.status != AgentStatus.SUCCESS:
            return res

        raw_data = bytes.fromhex(res.data["data_payload"])
        if len(raw_data) < 4:
            return ExecutionResult.failed("ERR_MODBUS_PAYLOAD_TRUNCATED", "Write multiple registers response truncated")

        echo_addr, echo_count = struct.unpack(">HH", raw_data[:4])
        if echo_addr != start_address or echo_count != count:
            return ExecutionResult.failed("ERR_MODBUS_ECHO_MISMATCH", "Write multiple registers echo mismatch")

        res.data["start_address"] = start_address
        res.data["registers_written"] = count
        return res
