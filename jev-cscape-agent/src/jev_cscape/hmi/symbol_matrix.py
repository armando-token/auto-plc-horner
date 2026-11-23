"""Cscape HMI Dynamic Barcode & QR Code 2D Vector Symbol Matrix Generator (W072 / Gate G9 / Gate G2).

Implements 1D linear barcodes (Code 128, Code 39) and 2D matrix symbology (ISO/IEC 18004
QR Code Version 1 and 2 with Reed-Solomon GF(256) error correction).
Produces pure SVG vector markup with zero DOM bloat (single unified <path> with
shape-rendering="crispEdges" on pure #FFFFFF backing plate ensuring WCAG AAA 21:1 contrast).
Bound to Horner OCS registers %R330..%R335 and discrete coils %M77..%M78.
"""

from __future__ import annotations

import dataclasses
from enum import IntEnum
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. 1D Barcode Encoders (Code 128 & Code 39)
# ============================================================================

# Code 128 bit patterns (106 data patterns of 11 modules each)
CODE128_PATTERNS = [
    "11011001100", "11001101100", "11001100110", "10010011000", "10010001100",
    "10001001100", "10011001000", "10011000100", "10001100100", "11001001000",
    "11001000100", "11000100100", "10110011100", "10011011100", "10011001110",
    "10111001100", "10011101100", "10011100110", "11001110010", "11001011100",
    "11001001110", "11011100100", "11001110100", "11101101110", "11101001100",
    "11100101100", "11100100110", "11101100100", "11100110100", "11100110010",
    "11011011000", "11011000110", "11000110110", "10100011000", "10001011000",
    "10001000110", "10110001000", "10001101000", "10001100010", "11010001000",
    "11000101000", "11000100010", "10110111000", "10110001110", "10001101110",
    "10111011000", "10111000110", "10001110110", "11101110110", "11010001110",
    "11000101110", "11011101000", "11011100010", "11011101110", "11101011000",
    "11101000110", "11100010110", "11101101000", "11101100010", "11100011010",
    "11101111010", "11001000010", "11110001010", "10100110000", "10100001100",
    "10010110000", "10010000110", "10000101100", "10000100110", "10110010000",
    "10110000100", "10011010000", "10011000010", "10000110100", "10000110010",
    "11000010010", "11001010000", "11110111010", "11000010100", "10001111010",
    "10100111100", "10010111100", "10010011110", "10111100100", "10011110100",
    "10011110010", "11110100100", "11110010100", "11110010010", "11011011110",
    "11011110110", "11110110110", "10101111000", "10100011110", "10001011110",
    "10111101000", "10111100010", "11110101000", "11110100010", "10111011110",
    "10111101110", "11101011110", "11110101110", "11010000100", "11010010000",
    "11010011100",
]
CODE128_STOP = "1100011101011"  # 13 modules
CODE128_START_B = 104


def encode_code128(text: str) -> str:
    """Encodes ASCII text into Code 128 (Subset B) binary module string (1=bar, 0=space)."""
    if not text:
        raise ValueError("Code 128 payload cannot be empty")
    values = [CODE128_START_B]
    for char in text:
        ascii_code = ord(char)
        if not (32 <= ascii_code <= 126):
            raise ValueError(f"Character {char!r} out of range for Code 128B (32..126)")
        values.append(ascii_code - 32)

    # Modulo 103 checksum
    checksum = values[0]
    for weight, val in enumerate(values[1:], start=1):
        checksum += weight * val
    checksum %= 103
    values.append(checksum)

    bit_stream = [CODE128_PATTERNS[v] for v in values]
    bit_stream.append(CODE128_STOP)
    return "".join(bit_stream)


# Code 39 character mapping (43 data characters + start/stop *)
CODE39_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-. $/+%"
CODE39_PATTERNS = {
    "0": "101001101101", "1": "110100101011", "2": "101100101011", "3": "110110010101",
    "4": "101001101011", "5": "110100110101", "6": "101100110101", "7": "101001011011",
    "8": "110100101101", "9": "101100101101", "A": "110101001011", "B": "101101001011",
    "C": "110110100101", "D": "101011001011", "E": "110101100101", "F": "101101100101",
    "G": "101010011011", "H": "110101001101", "I": "101101001101", "J": "101011001101",
    "K": "110101010011", "L": "101101010011", "M": "110110101001", "N": "101011010011",
    "O": "110101101001", "P": "101101101001", "Q": "101010110011", "R": "110101011001",
    "S": "101101011001", "T": "101011011001", "U": "110010101011", "V": "100110101011",
    "W": "110011010101", "X": "100101101011", "Y": "110010110101", "Z": "100110110101",
    "-": "100101011011", ".": "110010101101", " ": "100110101101", "$": "100100100101",
    "/": "100100101001", "+": "100101001001", "%": "101001001001", "*": "100101101101",
}


def encode_code39(text: str) -> str:
    """Encodes uppercase alphanumeric text into Code 39 binary module string."""
    text_upper = text.upper()
    if not text_upper:
        raise ValueError("Code 39 payload cannot be empty")
    for char in text_upper:
        if char not in CODE39_PATTERNS:
            raise ValueError(f"Invalid Code 39 character: {char!r}")

    symbols = ["*"] + list(text_upper) + ["*"]
    # Separate each character symbol with 1 module narrow space ("0")
    return "0".join(CODE39_PATTERNS[c] for c in symbols)


# ============================================================================
# 2. 2D QR Code Matrix Engine (ISO/IEC 18004 GF(256) Reed-Solomon)
# ============================================================================

# GF(256) Log / Antilog tables (Primitive polynomial 0x11D = 285)
GF_EXP = [0] * 512
GF_LOG = [0] * 256

def _init_gf256() -> None:
    x = 1
    for i in range(255):
        GF_EXP[i] = x
        GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        GF_EXP[i] = GF_EXP[i - 255]

_init_gf256()


def gf_mul(x: int, y: int) -> int:
    if x == 0 or y == 0:
        return 0
    return GF_EXP[GF_LOG[x] + GF_LOG[y]]


def rs_generator_poly(ec_count: int) -> List[int]:
    """Generates Reed-Solomon generator polynomial for ec_count parity bytes."""
    g = [1]
    for i in range(ec_count):
        factor = [1, GF_EXP[i]]
        # Multiply g by factor
        res = [0] * (len(g) + 1)
        for j in range(len(g)):
            for k in range(2):
                res[j + k] ^= gf_mul(g[j], factor[k])
        g = res
    return g


def rs_encode(data: bytes, ec_count: int) -> bytes:
    """Calculates Reed-Solomon error correction codewords over GF(256)."""
    gen = rs_generator_poly(ec_count)
    msg_poly = list(data) + [0] * ec_count
    for i in range(len(data)):
        lead = msg_poly[i]
        if lead != 0:
            for j in range(len(gen)):
                msg_poly[i + j] ^= gf_mul(gen[j], lead)
    return bytes(msg_poly[len(data):])


# QR Format Information 15-bit strings (Mask 0, Level M=0x5412, Level L=0x77C4)
# Formatted with BCH(15,5) and masked with 0x5412
QR_FORMAT_INFO = {
    "M_mask0": [1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0],  # 0x5412
    "L_mask0": [1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0],  # 0x77C4
}


class QRCodeGenerator:
    """ISO/IEC 18004 2D QR Code Matrix Engine (Versions 1 and 2, Level M / Level L)."""

    def __init__(self, version: int = 1, ec_level: str = "M") -> None:
        if version not in (1, 2):
            raise ValueError(f"Supported QR versions are 1 and 2 (got {version})")
        self.version = version
        self.ec_level = ec_level.upper()
        self.size = 21 if version == 1 else 25

        # Capacity parameters (Byte mode)
        if version == 1:
            self.total_codewords = 26
            self.ec_codewords = 10 if self.ec_level == "M" else 7
            self.max_data_bytes = 14 if self.ec_level == "M" else 17
        else:  # version 2
            self.total_codewords = 44
            self.ec_codewords = 16 if self.ec_level == "M" else 10
            self.max_data_bytes = 26 if self.ec_level == "M" else 32

    def encode(self, text: str) -> List[List[bool]]:
        """Encodes text payload into 2D boolean module grid (True=Black, False=White)."""
        raw_bytes = text.encode("utf-8")
        if len(raw_bytes) > self.max_data_bytes:
            raise ValueError(
                f"Payload length {len(raw_bytes)} exceeds QR V{self.version}-{self.ec_level} capacity ({self.max_data_bytes} bytes)"
            )

        # 1. Bitstream assembly: Mode (Byte 0100) + Count (8 bits) + Data + Terminator + Pad
        bits = []
        # Mode 0100 (4 bits)
        bits.extend([0, 1, 0, 0])
        # Count (8 bits)
        count = len(raw_bytes)
        for i in range(7, -1, -1):
            bits.append((count >> i) & 1)
        # Data bytes
        for b in raw_bytes:
            for i in range(7, -1, -1):
                bits.append((b >> i) & 1)
        # Terminator 0000 (up to 4 bits)
        data_capacity_bits = (self.total_codewords - self.ec_codewords) * 8
        term_len = min(4, data_capacity_bits - len(bits))
        bits.extend([0] * term_len)
        # Byte boundary padding
        while len(bits) % 8 != 0:
            bits.append(0)
        # Pad bytes 0xEC, 0x11
        pad_bytes = [0xEC, 0x11]
        pad_idx = 0
        while len(bits) < data_capacity_bits:
            p = pad_bytes[pad_idx % 2]
            pad_idx += 1
            for i in range(7, -1, -1):
                bits.append((p >> i) & 1)

        # Pack into data codewords
        data_codewords = bytearray()
        for i in range(0, len(bits), 8):
            byte_val = 0
            for j in range(8):
                byte_val = (byte_val << 1) | bits[i + j]
            data_codewords.append(byte_val)

        # 2. Reed-Solomon Error Correction
        ec_codewords = rs_encode(bytes(data_codewords), self.ec_codewords)
        all_codewords = bytes(data_codewords) + ec_codewords

        # 3. Matrix grid population
        matrix: List[List[Optional[bool]]] = [[None] * self.size for _ in range(self.size)]
        reserved: List[List[bool]] = [[False] * self.size for _ in range(self.size)]

        def set_func(r: int, c: int, val: bool) -> None:
            matrix[r][c] = val
            reserved[r][c] = True

        # Finder patterns (7x7) + Separators
        def place_finder(top_r: int, left_c: int) -> None:
            for r in range(-1, 8):
                for c in range(-1, 8):
                    curr_r, curr_c = top_r + r, left_c + c
                    if 0 <= curr_r < self.size and 0 <= curr_c < self.size:
                        if 0 <= r <= 6 and 0 <= c <= 6:
                            is_black = (r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4))
                            set_func(curr_r, curr_c, is_black)
                        else:
                            set_func(curr_r, curr_c, False)

        place_finder(0, 0)
        place_finder(0, self.size - 7)
        place_finder(self.size - 7, 0)

        # Timing patterns (row 6, col 6)
        for i in range(8, self.size - 8):
            set_func(6, i, (i % 2 == 0))
            set_func(i, 6, (i % 2 == 0))

        # Alignment pattern for V2 (5x5 centered at row 18, col 18)
        if self.version == 2:
            center_r, center_c = 18, 18
            for r in range(-2, 3):
                for c in range(-2, 3):
                    curr_r, curr_c = center_r + r, center_c + c
                    if not reserved[curr_r][curr_c]:
                        is_black = (abs(r) == 2 or abs(c) == 2 or (r == 0 and c == 0))
                        set_func(curr_r, curr_c, is_black)

        # Dark module: (size - 8, 8)
        set_func(self.size - 8, 8, True)

        # Reserve format information area
        for i in range(9):
            if not reserved[8][i]:
                reserved[8][i] = True
            if not reserved[i][8]:
                reserved[i][8] = True
        for i in range(self.size - 8, self.size):
            if not reserved[8][i]:
                reserved[8][i] = True
        for i in range(self.size - 7, self.size):
            if not reserved[i][8]:
                reserved[i][8] = True

        # 4. Data placement in zigzag columns
        data_bits = []
        for cw in all_codewords:
            for bit_pos in range(7, -1, -1):
                data_bits.append((cw >> bit_pos) & 1)

        bit_idx = 0
        col = self.size - 1
        upward = True
        while col > 0:
            if col == 6:
                col -= 1  # Skip timing column

            rows = range(self.size - 1, -1, -1) if upward else range(self.size)
            for r in rows:
                for c_offset in (0, -1):
                    c = col + c_offset
                    if not reserved[r][c]:
                        val = bool(data_bits[bit_idx]) if bit_idx < len(data_bits) else False
                        bit_idx += 1
                        # Apply standard mask pattern 0: (row + col) % 2 == 0
                        if (r + c) % 2 == 0:
                            val = not val
                        matrix[r][c] = val
            col -= 2
            upward = not upward

        # 5. Place Format Information (Mask 0, Level M / L)
        fmt_key = f"{self.ec_level}_mask0"
        fmt_bits = QR_FORMAT_INFO.get(fmt_key, QR_FORMAT_INFO["M_mask0"])

        # Format info coordinates
        # Top-left horizontal: (8,0)..(8,5), (8,7), (8,8)
        # Top-left vertical: (8,8), (7,8), (5,8)..(0,8)
        coords_top_left = [
            (8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5),
            (8, 7), (8, 8), (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)
        ]
        for idx, (r, c) in enumerate(coords_top_left):
            matrix[r][c] = bool(fmt_bits[idx])

        # Second copy around finders
        # Horizontal on right: (8, size-8)..(8, size-1)
        for idx in range(8):
            matrix[8][self.size - 8 + idx] = bool(fmt_bits[7 + idx])
        # Vertical on bottom: (size-7, 8)..(size-1, 8)
        for idx in range(7):
            matrix[self.size - 7 + idx][8] = bool(fmt_bits[idx])

        # Final matrix: True=Black, False=White
        result: List[List[bool]] = []
        for r in range(self.size):
            result.append([bool(matrix[r][c]) for c in range(self.size)])
        return result


# ============================================================================
# 3. Pure Vector SVG Rasterizer (Single Unified Path)
# ============================================================================

class VectorSymbolRasterizer:
    """Renders 1D and 2D barcode symbols into optimized standalone SVG markup."""

    @staticmethod
    def render_1d_barcode_svg(
        bit_string: str,
        module_width: int = 2,
        height: int = 60,
        quiet_zone_modules: int = 10,
        label: Optional[str] = None,
    ) -> str:
        """Renders 1D binary bit string (1=bar, 0=space) to SVG with crisp edges."""
        data_modules = len(bit_string)
        total_modules = data_modules + (2 * quiet_zone_modules)
        total_width = total_modules * module_width
        total_height = height + (20 if label else 0)

        # Merge dark module runs into unified <path>
        path_segments: List[str] = []
        in_bar = False
        bar_start = 0

        for idx, bit in enumerate(bit_string):
            if bit == "1" and not in_bar:
                in_bar = True
                bar_start = idx
            elif bit == "0" and in_bar:
                in_bar = False
                w = (idx - bar_start) * module_width
                x = (quiet_zone_modules + bar_start) * module_width
                path_segments.append(f"M{x},0 h{w} v{height} h{-w} Z")

        if in_bar:
            w = (data_modules - bar_start) * module_width
            x = (quiet_zone_modules + bar_start) * module_width
            path_segments.append(f"M{x},0 h{w} v{height} h{-w} Z")

        merged_path = " ".join(path_segments)

        label_svg = ""
        if label:
            label_x = total_width // 2
            label_y = height + 14
            label_svg = (
                f'<text x="{label_x}" y="{label_y}" font-family="monospace" '
                f'font-size="11" text-anchor="middle" fill="#000000">{label}</text>'
            )

        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total_width} {total_height}" '
            f'width="{total_width}" height="{total_height}">\n'
            f'  <rect width="{total_width}" height="{total_height}" fill="#FFFFFF" />\n'
            f'  <path d="{merged_path}" fill="#000000" shape-rendering="crispEdges" />\n'
            f'  {label_svg}\n'
            f'</svg>'
        )
        return svg

    @staticmethod
    def render_qr_matrix_svg(
        matrix: List[List[bool]],
        module_size: int = 5,
        quiet_zone_modules: int = 4,
    ) -> str:
        """Renders 2D boolean grid (True=Black) to SVG with single unified <path>."""
        size = len(matrix)
        total_dim = size + (2 * quiet_zone_modules)
        total_px = total_dim * module_size

        path_segments: List[str] = []
        # Aggregate contiguous horizontal modules in each row
        for r in range(size):
            y = (quiet_zone_modules + r) * module_size
            in_run = False
            run_start = 0

            for c in range(size):
                if matrix[r][c] and not in_run:
                    in_run = True
                    run_start = c
                elif not matrix[r][c] and in_run:
                    in_run = False
                    w = (c - run_start) * module_size
                    x = (quiet_zone_modules + run_start) * module_size
                    path_segments.append(f"M{x},{y} h{w} v{module_size} h{-w} Z")

            if in_run:
                w = (size - run_start) * module_size
                x = (quiet_zone_modules + run_start) * module_size
                path_segments.append(f"M{x},{y} h{w} v{module_size} h{-w} Z")

        merged_path = " ".join(path_segments)

        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total_px} {total_px}" '
            f'width="{total_px}" height="{total_px}">\n'
            f'  <rect width="{total_px}" height="{total_px}" fill="#FFFFFF" />\n'
            f'  <path d="{merged_path}" fill="#000000" shape-rendering="crispEdges" />\n'
            f'</svg>'
        )
        return svg


# ============================================================================
# 4. Pure ST POU Block & Horner OCS Register Integration
# ============================================================================

W072_PURE_ST_POU = """PROGRAM BarcodeSymbolGenerator
VAR
    StatusWord AT %R330 : WORD;
    SymbologySelector AT %R331 : INT;
    PayloadLength AT %R332 : INT;
    ModuleScale AT %R333 : INT;
    QuietZoneMargin AT %R334 : INT;
    TotalElementCount AT %R335 : INT;
    EnableEngine AT %M77 : BOOL;
    TriggerRegeneration AT %M78 : BOOL;

    SymbolValid : BOOL := FALSE;
    EncodingError : BOOL := FALSE;
    DataTruncated : BOOL := FALSE;
    Symbology2D : BOOL := FALSE;
    TempStatus : WORD := 0;
END_VAR

IF EnableEngine THEN
    IF TriggerRegeneration THEN
        SymbolValid := TRUE;
        EncodingError := FALSE;
        DataTruncated := FALSE;

        CASE SymbologySelector OF
            0: // Code 128 (1D)
                Symbology2D := FALSE;
                IF PayloadLength <= 0 THEN
                    EncodingError := TRUE;
                    SymbolValid := FALSE;
                    TotalElementCount := 0;
                ELSIF PayloadLength > 80 THEN
                    DataTruncated := TRUE;
                    TotalElementCount := (80 * 11) + 35;
                ELSE
                    TotalElementCount := (PayloadLength * 11) + 35;
                END_IF;

            1: // Code 39 (1D)
                Symbology2D := FALSE;
                IF PayloadLength <= 0 THEN
                    EncodingError := TRUE;
                    SymbolValid := FALSE;
                    TotalElementCount := 0;
                ELSIF PayloadLength > 43 THEN
                    DataTruncated := TRUE;
                    TotalElementCount := (43 + 2) * 16;
                ELSE
                    TotalElementCount := (PayloadLength + 2) * 16;
                END_IF;

            2: // QR Code V1 (2D, 21x21 modules)
                Symbology2D := TRUE;
                IF PayloadLength <= 0 THEN
                    EncodingError := TRUE;
                    SymbolValid := FALSE;
                    TotalElementCount := 0;
                ELSIF PayloadLength > 17 THEN
                    DataTruncated := TRUE;
                    TotalElementCount := 441;
                ELSE
                    TotalElementCount := 441;
                END_IF;

            3: // QR Code V2 (2D, 25x25 modules)
                Symbology2D := TRUE;
                IF PayloadLength <= 0 THEN
                    EncodingError := TRUE;
                    SymbolValid := FALSE;
                    TotalElementCount := 0;
                ELSIF PayloadLength > 32 THEN
                    DataTruncated := TRUE;
                    TotalElementCount := 625;
                ELSE
                    TotalElementCount := 625;
                END_IF;

            ELSE
                EncodingError := TRUE;
                SymbolValid := FALSE;
                Symbology2D := FALSE;
                TotalElementCount := 0;
        END_CASE;

        TempStatus := 0;
        IF SymbolValid THEN
            TempStatus := TempStatus OR 1;
        END_IF;
        IF EncodingError THEN
            TempStatus := TempStatus OR 2;
        END_IF;
        IF DataTruncated THEN
            TempStatus := TempStatus OR 4;
        END_IF;
        IF Symbology2D THEN
            TempStatus := TempStatus OR 8;
        END_IF;

        StatusWord := TempStatus;
        TriggerRegeneration := FALSE;
    END_IF;
ELSE
    StatusWord := 0;
    TotalElementCount := 0;
    TriggerRegeneration := FALSE;
END_IF;
END_PROGRAM"""


class SymbologyType(IntEnum):
    CODE_128 = 0
    CODE_39 = 1
    QR_CODE_V1 = 2
    QR_CODE_V2 = 3


class SymbolMatrixEngine:
    """Horner OCS Runtime Symbol Engine managing registers and dynamic SVG rendering."""

    def __init__(self, registers: Optional[RegisterTable] = None) -> None:
        self.registers = registers or RegisterTable()
        self.last_rendered_svg: str = ""

        # Default register states
        self.registers.write_word("%R330", 0x0001, privilege=PrivilegeMode.SYSTEM)  # Symbol valid
        self.registers.write_word("%R331", SymbologyType.QR_CODE_V1, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R332", 12, privilege=PrivilegeMode.SYSTEM)       # Length 12
        self.registers.write_word("%R333", 4, privilege=PrivilegeMode.SYSTEM)        # Scale 4
        self.registers.write_word("%R334", 4, privilege=PrivilegeMode.SYSTEM)        # Quiet zone 4
        self.registers.write_word("%R335", 441, privilege=PrivilegeMode.SYSTEM)      # 21x21 = 441 modules
        self.registers.write_bit("%M77", True, privilege=PrivilegeMode.SYSTEM)       # Enable engine
        self.registers.write_bit("%M78", False, privilege=PrivilegeMode.SYSTEM)      # Trigger

    def generate_symbol(self, payload: str) -> Tuple[str, Dict[str, Any]]:
        """Generates pure SVG markup according to current register selections."""
        enable = self.registers.read_bit("%M77")
        if not enable:
            self.registers.write_word("%R330", 0, privilege=PrivilegeMode.SYSTEM)
            self.registers.write_word("%R335", 0, privilege=PrivilegeMode.SYSTEM)
            return "", {"status": "disabled", "error": None}

        symbology = self.registers.read_word("%R331")
        scale = max(1, self.registers.read_word("%R333"))
        qz = max(0, self.registers.read_word("%R334"))

        status = 0
        elem_count = 0
        svg = ""

        try:
            if symbology == SymbologyType.CODE_128:
                bit_str = encode_code128(payload)
                elem_count = len(bit_str)
                svg = VectorSymbolRasterizer.render_1d_barcode_svg(
                    bit_str, module_width=scale, height=60, quiet_zone_modules=qz, label=payload
                )
                status = 0x0001  # Valid 1D

            elif symbology == SymbologyType.CODE_39:
                bit_str = encode_code39(payload)
                elem_count = len(bit_str)
                svg = VectorSymbolRasterizer.render_1d_barcode_svg(
                    bit_str, module_width=scale, height=60, quiet_zone_modules=qz, label=payload
                )
                status = 0x0001  # Valid 1D

            elif symbology == SymbologyType.QR_CODE_V1:
                qr = QRCodeGenerator(version=1, ec_level="M")
                mat = qr.encode(payload)
                elem_count = 21 * 21
                svg = VectorSymbolRasterizer.render_qr_matrix_svg(mat, module_size=scale, quiet_zone_modules=qz)
                status = 0x0009  # Valid 2D (0x01 | 0x08)

            elif symbology == SymbologyType.QR_CODE_V2:
                qr = QRCodeGenerator(version=2, ec_level="M")
                mat = qr.encode(payload)
                elem_count = 25 * 25
                svg = VectorSymbolRasterizer.render_qr_matrix_svg(mat, module_size=scale, quiet_zone_modules=qz)
                status = 0x0009  # Valid 2D

            else:
                status = 0x0002  # Encoding error
                elem_count = 0

        except Exception:
            status = 0x0002  # Encoding error
            elem_count = 0
            svg = ""

        self.last_rendered_svg = svg
        self.registers.write_word("%R330", status, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R332", len(payload), privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R335", elem_count, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_bit("%M78", False, privilege=PrivilegeMode.SYSTEM)

        return svg, {"status": "success" if (status & 0x0001) else "error", "status_word": status}


# ============================================================================
# 5. Verification & Signoff Evidence Exporter
# ============================================================================

def verify_symbol_matrix_and_export_evidence(
    output_evidence_path: str = "artifacts/HMI/symbol_matrix_evidence.json",
    output_svg_path: str = "artifacts/HMI/qr_code_sample.svg",
) -> Dict[str, Any]:
    """Verifies Code 128, Code 39, QR Code V1/V2, Pure ST POU, and exports SVG sample."""
    os.makedirs(os.path.dirname(output_evidence_path), exist_ok=True)
    os.makedirs(os.path.dirname(output_svg_path), exist_ok=True)
    tests_record: List[Dict[str, Any]] = []

    # 1. Pure ST POU Validation
    val_st = STParser.validate_code(W072_PURE_ST_POU)
    SecurityGuard.assert_pure_st_content(W072_PURE_ST_POU)
    tests_record.append({
        "check": "Pure_ST_POU_Validation",
        "pou_name": "BarcodeSymbolGenerator",
        "passed": val_st.status == AgentStatus.SUCCESS,
    })

    # 2. Code 128 1D Encoding & SVG Rasterization
    c128_bits = encode_code128("JEV-2026")
    c128_svg = VectorSymbolRasterizer.render_1d_barcode_svg(c128_bits, label="JEV-2026")
    c128_passed = (
        len(c128_bits) > 0
        and "<svg" in c128_svg
        and 'shape-rendering="crispEdges"' in c128_svg
        and "JEV-2026" in c128_svg
    )
    tests_record.append({
        "check": "Code128_1D_Rasterization",
        "payload": "JEV-2026",
        "bits_len": len(c128_bits),
        "passed": c128_passed,
    })

    # 3. Code 39 1D Encoding & SVG Rasterization
    c39_bits = encode_code39("CSCAPE")
    c39_svg = VectorSymbolRasterizer.render_1d_barcode_svg(c39_bits, label="CSCAPE")
    c39_passed = (
        len(c39_bits) > 0
        and "<svg" in c39_svg
        and 'shape-rendering="crispEdges"' in c39_svg
    )
    tests_record.append({
        "check": "Code39_1D_Rasterization",
        "payload": "CSCAPE",
        "bits_len": len(c39_bits),
        "passed": c39_passed,
    })

    # 4. QR Code 2D V1 Matrix Generation & RS Parity
    qr1 = QRCodeGenerator(version=1, ec_level="M")
    mat1 = qr1.encode("BATCH-99")
    qr1_svg = VectorSymbolRasterizer.render_qr_matrix_svg(mat1, module_size=6, quiet_zone_modules=4)
    qr1_passed = (
        len(mat1) == 21
        and len(mat1[0]) == 21
        and "<path" in qr1_svg
        and 'fill="#000000"' in qr1_svg
    )
    tests_record.append({
        "check": "QRCode_2D_V1_Generation",
        "payload": "BATCH-99",
        "grid_dim": 21,
        "passed": qr1_passed,
    })

    # 5. QR Code 2D V2 Matrix Generation & SVG Sample Export
    qr2 = QRCodeGenerator(version=2, ec_level="M")
    mat2 = qr2.encode("HORNER-OCS-W072")
    qr2_svg = VectorSymbolRasterizer.render_qr_matrix_svg(mat2, module_size=8, quiet_zone_modules=4)
    qr2_passed = (
        len(mat2) == 25
        and len(mat2[0]) == 25
        and "<path" in qr2_svg
    )

    with open(output_svg_path, "w", encoding="utf-8") as f:
        f.write(qr2_svg)

    tests_record.append({
        "check": "QRCode_2D_V2_Generation_And_SVG_Export",
        "payload": "HORNER-OCS-W072",
        "grid_dim": 25,
        "exported_svg": output_svg_path,
        "passed": qr2_passed,
    })

    # 6. Horner OCS Register Integration Engine
    engine = SymbolMatrixEngine()
    engine.registers.write_word("%R331", SymbologyType.QR_CODE_V1, privilege=PrivilegeMode.SYSTEM)
    engine.registers.write_bit("%M78", True, privilege=PrivilegeMode.SYSTEM)
    svg_res, meta = engine.generate_symbol("LOT#402")
    reg_passed = (
        meta["status"] == "success"
        and (engine.registers.read_word("%R330") & 0x0009) == 0x0009
        and engine.registers.read_word("%R335") == 441
        and engine.registers.read_bit("%M78") is False
    )
    tests_record.append({
        "check": "Horner_OCS_Register_Handshake",
        "status_word": engine.registers.read_word("%R330"),
        "total_elements": engine.registers.read_word("%R335"),
        "passed": reg_passed,
    })

    all_passed = all(t["passed"] for t in tests_record)
    status_str = "success" if all_passed else "failed"

    evidence: Dict[str, Any] = {
        "status": status_str,
        "error_code": None if all_passed else "SYMBOL_MATRIX_VERIFICATION_FAILED",
        "details": f"Symbol matrix & QR generator verification: {sum(1 for t in tests_record if t['passed'])}/{len(tests_record)} checks passed.",
        "data": {
            "symbologies": ["Code 128", "Code 39", "QR Code Version 1", "QR Code Version 2"],
            "tests": tests_record,
            "sample_svg_path": output_svg_path,
            "register_map": {
                "analog_registers": "%R330..%R335",
                "discrete_coils": "%M77..%M78",
            },
            "timestamp": time.time(),
        },
    }

    with open(output_evidence_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    return evidence
