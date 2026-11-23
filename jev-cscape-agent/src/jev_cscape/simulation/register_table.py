"""Horner OCS Register State Space, Memory Image, and Double-Buffering Table.

Work Package: W019 (Gate G4)
Classification: TESTED_MOCK [offline/DEV only]

Manages bit-addressed and word-addressed Horner APG OCS register channels (%I,
%Q, %M, %D, %K, %S, %SR, %AI, %AQ, %R, %IG, %QG, %AIG, %AQG), boundary
checking, bit-slicing (%R100.1..%R100.16), multi-word 32-bit types (DINT, UDINT,
REAL) across consecutive 16-bit registers, double-buffered scan cycle state,
system register/bit emulation, and snapshot diffing.
"""

from __future__ import annotations

from enum import Enum
import math
import re
import struct
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pydantic import BaseModel, Field

from jev_cscape.automation.channel_matrix import ChannelAccess, ChannelMatrix, ChannelType


class WordOrder(str, Enum):
    """Word order (endianness) for multi-word types across consecutive 16-bit registers."""
    LOW_WORD_FIRST = "LOW_WORD_FIRST"    # Horner OCS native standard: Base = Low Word, Base+1 = High Word
    HIGH_WORD_FIRST = "HIGH_WORD_FIRST"  # Modbus swapped standard: Base = High Word, Base+1 = Low Word


class PrivilegeMode(str, Enum):
    """Access privilege level for register read/write operations."""
    APPLICATION = "APPLICATION"  # User logic execution mode (enforces read-only protection)
    SYSTEM = "SYSTEM"            # Internal simulation engine / hardware driver mode
    USER = "APPLICATION"        # Compatibility alias for user logic execution mode


class ReadOnlyChannelError(PermissionError):
    """Raised when application logic attempts to write to a read-only Horner OCS channel."""
    pass


# Extended 14-channel matrix for complete Horner OCS memory map
EXTENDED_CHANNELS: Dict[str, ChannelType] = {
    **ChannelMatrix.CHANNELS,
    "%IG": ChannelType(
        prefix="%IG",
        name="Global Digital Inputs",
        element_type="BOOL",
        bit_width=1,
        range_min=1,
        range_max=2048,
        access=ChannelAccess.READ_ONLY,
        description="Network global digital input contact states (CsCAN).",
    ),
    "%QG": ChannelType(
        prefix="%QG",
        name="Global Digital Outputs",
        element_type="BOOL",
        bit_width=1,
        range_min=1,
        range_max=2048,
        access=ChannelAccess.READ_WRITE,
        description="Network global digital output coil states (CsCAN).",
    ),
    "%AIG": ChannelType(
        prefix="%AIG",
        name="Global Analog Inputs",
        element_type="INT",
        bit_width=16,
        range_min=1,
        range_max=512,
        access=ChannelAccess.READ_ONLY,
        description="Network global analog input words (CsCAN).",
    ),
    "%AQG": ChannelType(
        prefix="%AQG",
        name="Global Analog Outputs",
        element_type="INT",
        bit_width=16,
        range_min=1,
        range_max=512,
        access=ChannelAccess.READ_WRITE,
        description="Network global analog output words (CsCAN).",
    ),
}

_BIT_SLICE_REGEX = re.compile(r"^%([A-Z]+)(\d+)(?:\.(\d+))?$", re.IGNORECASE)


class RegisterAddress(BaseModel):
    """Parsed and validated Horner OCS register reference with optional bit slice."""
    raw: str
    clean: str
    prefix: str
    index: int
    bit_slice: Optional[int] = None
    channel_type: ChannelType

    @property
    def is_bit_slice(self) -> bool:
        """True if the address references a specific bit of a word register."""
        return self.bit_slice is not None

    @property
    def word_address(self) -> str:
        """Returns the base word register string without the bit slice."""
        return f"{self.prefix}{self.index}"


class BitSliceOps:
    """Bit-slicing and bit-packing operations for 16-bit word registers.

    Adheres strictly to Horner APG 1-based bit indexing:
    - Bit 1 is LSB (bit index 0, mask 0x0001, weight 2^0)
    - Bit 16 is MSB (bit index 15, mask 0x8000, weight 2^15)
    """

    @staticmethod
    def extract_bit(word_val: int, bit: int) -> bool:
        """Extract a single boolean bit (1..16) from a 16-bit integer."""
        if not (1 <= bit <= 16):
            raise ValueError(f"Bit slice index {bit} out of range (1..16).")
        u16 = int(word_val) & 0xFFFF
        return bool((u16 >> (bit - 1)) & 1)

    @staticmethod
    def pack_bit(word_val: int, bit: int, value: bool) -> int:
        """Mutate a single bit (1..16) in a 16-bit integer without corrupting adjacent bits.

        Returns a signed 16-bit integer in range [-32768, 32767].
        """
        if not (1 <= bit <= 16):
            raise ValueError(f"Bit slice index {bit} out of range (1..16).")
        u16 = int(word_val) & 0xFFFF
        mask = 1 << (bit - 1)
        if value:
            u16 = u16 | mask
        else:
            u16 = u16 & (~mask & 0xFFFF)
        # Convert to signed 16-bit
        return u16 if u16 <= 32767 else u16 - 65536


def float_to_words(val: float, word_order: WordOrder = WordOrder.LOW_WORD_FIRST) -> Tuple[int, int]:
    """Packs a 32-bit IEEE 754 single-precision float into two 16-bit signed integer words."""
    raw_bytes = struct.pack("<f", float(val))
    low_u, high_u = struct.unpack("<HH", raw_bytes)
    w_low = low_u if low_u <= 32767 else low_u - 65536
    w_high = high_u if high_u <= 32767 else high_u - 65536
    if word_order == WordOrder.HIGH_WORD_FIRST:
        return w_high, w_low
    return w_low, w_high


def words_to_float(w1: int, w2: int, word_order: WordOrder = WordOrder.LOW_WORD_FIRST) -> float:
    """Unpacks two 16-bit integer words into an IEEE 754 single-precision float."""
    low_w, high_w = (w2, w1) if word_order == WordOrder.HIGH_WORD_FIRST else (w1, w2)
    raw_bytes = struct.pack("<HH", low_w & 0xFFFF, high_w & 0xFFFF)
    return struct.unpack("<f", raw_bytes)[0]


def dint_to_words(val: int, word_order: WordOrder = WordOrder.LOW_WORD_FIRST) -> Tuple[int, int]:
    """Packs a 32-bit signed DINT integer into two 16-bit signed integer words."""
    v = int(val)
    if not (-2147483648 <= v <= 2147483647):
        raise OverflowError(f"Value {v} out of range for 32-bit signed DINT [-2147483648, 2147483647]")
    raw_bytes = struct.pack("<i", v)
    low_u, high_u = struct.unpack("<HH", raw_bytes)
    w_low = low_u if low_u <= 32767 else low_u - 65536
    w_high = high_u if high_u <= 32767 else high_u - 65536
    if word_order == WordOrder.HIGH_WORD_FIRST:
        return w_high, w_low
    return w_low, w_high


def words_to_dint(w1: int, w2: int, word_order: WordOrder = WordOrder.LOW_WORD_FIRST) -> int:
    """Unpacks two 16-bit integer words into a 32-bit signed DINT integer."""
    low_w, high_w = (w2, w1) if word_order == WordOrder.HIGH_WORD_FIRST else (w1, w2)
    raw_bytes = struct.pack("<HH", low_w & 0xFFFF, high_w & 0xFFFF)
    return struct.unpack("<i", raw_bytes)[0]


def udint_to_words(val: int, word_order: WordOrder = WordOrder.LOW_WORD_FIRST) -> Tuple[int, int]:
    """Packs a 32-bit unsigned UDINT integer into two 16-bit signed integer words."""
    v = int(val)
    if not (0 <= v <= 4294967295):
        raise OverflowError(f"Value {v} out of range for 32-bit unsigned UDINT [0, 4294967295]")
    raw_bytes = struct.pack("<I", v)
    low_u, high_u = struct.unpack("<HH", raw_bytes)
    w_low = low_u if low_u <= 32767 else low_u - 65536
    w_high = high_u if high_u <= 32767 else high_u - 65536
    if word_order == WordOrder.HIGH_WORD_FIRST:
        return w_high, w_low
    return w_low, w_high


def words_to_udint(w1: int, w2: int, word_order: WordOrder = WordOrder.LOW_WORD_FIRST) -> int:
    """Unpacks two 16-bit integer words into a 32-bit unsigned UDINT integer."""
    low_w, high_w = (w2, w1) if word_order == WordOrder.HIGH_WORD_FIRST else (w1, w2)
    raw_bytes = struct.pack("<HH", low_w & 0xFFFF, high_w & 0xFFFF)
    return struct.unpack("<I", raw_bytes)[0]


class RegisterTable:
    """In-memory data store and double-buffering engine for Horner APG OCS registers.

    Provides discrete bit, 16-bit word, and multi-word (32-bit DINT/UDINT/REAL) access,
    bit-slicing (%R100.1..%R100.16), range and access validation, double-buffering,
    system register (%SR) and system bit (%S) emulation, and snapshot diffing.
    """

    INPUT_PREFIXES: Set[str] = {"%I", "%AI", "%K", "%IG", "%AIG"}
    OUTPUT_PREFIXES: Set[str] = {"%Q", "%AQ", "%QG", "%AQG"}
    READ_ONLY_PREFIXES: Set[str] = {"%I", "%AI", "%K", "%S", "%SR", "%IG", "%AIG"}
    WORD_PREFIXES: Set[str] = {"%R", "%AI", "%AQ", "%SR", "%AIG", "%AQG"}
    BIT_PREFIXES: Set[str] = {"%I", "%Q", "%M", "%D", "%K", "%S", "%IG", "%QG"}

    def __init__(self, default_dt_ms: float = 10.0) -> None:
        self.default_dt_ms: float = float(default_dt_ms)
        self.privilege_mode: PrivilegeMode = PrivilegeMode.APPLICATION

        # Double-buffered memory partitions
        self.pending_inputs: Dict[str, Any] = {}
        self.latched_inputs: Dict[str, Any] = {}
        self.staged_writes: Dict[str, Any] = {}
        self.committed_memory: Dict[str, Any] = {}

        # System bits and diagnostic registers
        self.system_bits: Dict[str, bool] = {}
        self.system_registers: Dict[str, int] = {}

        self.initialize_system_registers()

    def initialize_system_registers(self) -> None:
        """Initialize default Horner system registers and system bits prior to scan 0."""
        self.system_registers = {
            "%SR1": 0,                                        # Scan cycle counter
            "%SR2": 1,                                        # System mode (1 = RUN/SIMULATION, 3 = FAULT)
            "%SR3": 0,                                        # Scan count low 16 bits
            "%SR4": 0,                                        # Scan count high 16 bits
            "%SR5": int(round(self.default_dt_ms)),           # Scan duration in integer ms
        }
        self.system_bits = {
            "%S1": True,   # First scan pulse
            "%S2": True,   # Network OK
            "%S3": False,  # 10ms clock pulse
            "%S4": False,  # 100ms clock pulse
            "%S5": False,  # 1000ms clock pulse
            "%S7": True,   # Always ON (ALW_ON)
            "%S8": False,  # Always OFF (ALW_OFF)
            "%S9": False,  # 10s clock pulse
        }

    # --- Address Resolution & Parsing ---

    @staticmethod
    def normalize_address(address: str) -> str:
        """Normalize address string with uppercase letters and leading '%' symbol."""
        clean = address.strip().upper()
        if not clean.startswith("%"):
            clean = "%" + clean
        return clean

    @classmethod
    def parse_address(cls, address: str) -> RegisterAddress:
        """Parse and validate an OCS register reference supporting bit-slicing notation."""
        clean = cls.normalize_address(address)
        match = _BIT_SLICE_REGEX.match(clean)
        if not match:
            raise ValueError(f"Invalid register address format: '{address}'. Expected e.g. %R100, %I1, %R100.1")

        pfx = "%" + match.group(1).upper()
        idx = int(match.group(2))
        bit_slice = int(match.group(3)) if match.group(3) is not None else None

        ctype = EXTENDED_CHANNELS.get(pfx)
        if not ctype:
            raise ValueError(f"Unrecognized memory prefix '{pfx}'.")

        if idx < ctype.range_min or idx > ctype.range_max:
            raise ValueError(
                f"Index {idx} out of range for {pfx} ({ctype.range_min}..{ctype.range_max})."
            )

        if bit_slice is not None:
            if ctype.element_type != "INT":
                raise TypeError(
                    f"Bit-slicing '{clean}' is only permitted on 16-bit word registers, not {ctype.element_type} channel {pfx}."
                )
            if bit_slice < 1 or bit_slice > 16:
                raise ValueError(
                    f"Bit slice index {bit_slice} out of range (1..16) for register '{pfx}{idx}'. "
                    f"Horner OCS restricts bit addressing to 1..16."
                )

        return RegisterAddress(
            raw=address,
            clean=clean,
            prefix=pfx,
            index=idx,
            bit_slice=bit_slice,
            channel_type=ctype,
        )

    def get_consecutive_addresses(self, base_address: str, word_count: int = 2) -> List[str]:
        """Resolves consecutive register addresses ensuring channel bounds compliance."""
        reg = self.parse_address(base_address)
        if reg.is_bit_slice:
            raise TypeError(f"Consecutive address allocation cannot start from a bit-slice '{base_address}'.")

        if reg.channel_type.element_type != "INT":
            raise TypeError(
                f"Multi-word access requires 16-bit register channel, got {reg.prefix} ({reg.channel_type.element_type})."
            )

        max_idx = reg.index + word_count - 1
        if max_idx > reg.channel_type.range_max:
            raise IndexError(
                f"Multi-word allocation starting at {base_address} with length {word_count} "
                f"exceeds maximum channel boundary {reg.prefix}{reg.channel_type.range_max} (overflows to {reg.prefix}{max_idx})."
            )

        return [f"{reg.prefix}{reg.index + i}" for i in range(word_count)]

    # --- Core Value Access (Read / Write) ---

    def read_register(self, address: str) -> Any:
        """Read register value conforming to double-buffering & memory latching semantics."""
        reg = self.parse_address(address)
        clean = reg.clean

        # Bit-slicing read
        if reg.is_bit_slice:
            word_val = self.read_word(reg.word_address)
            return BitSliceOps.extract_bit(word_val, reg.bit_slice)  # type: ignore[arg-type]

        # 1. Read-your-own-writes: logic can read its own uncommitted staged writes
        if clean in self.staged_writes:
            return self.staged_writes[clean]

        # 2. Frozen latched inputs during active scan
        if clean in self.latched_inputs:
            return self.latched_inputs[clean]

        # 3. System bits
        if clean in self.system_bits:
            return self.system_bits[clean]

        # 4. System registers
        if clean in self.system_registers:
            return self.system_registers[clean]

        # 5. Committed memory (outputs, markers, holding registers)
        if clean in self.committed_memory:
            return self.committed_memory[clean]

        # 6. Pending inputs if accessed before first scan
        if clean in self.pending_inputs:
            return self.pending_inputs[clean]

        # Default values
        return 0 if reg.channel_type.element_type == "INT" else False

    def write_register(
        self,
        address: str,
        value: Any,
        privilege: Optional[PrivilegeMode] = None,
    ) -> None:
        """Write to memory. During Phase 2, writes to outputs/markers are staged."""
        reg = self.parse_address(address)
        clean = reg.clean
        mode = privilege or self.privilege_mode

        # System bits & system registers protection
        if clean.startswith("%SR") or clean.startswith("%S") and not reg.is_bit_slice:
            if mode != PrivilegeMode.SYSTEM:
                # Tamper resistance: user logic write attempts are rejected or ignored
                return

        # Bit-slicing write
        if reg.is_bit_slice:
            word_addr = reg.word_address
            # Check read-only permission on base word
            if reg.channel_type.access == ChannelAccess.READ_ONLY and mode != PrivilegeMode.SYSTEM:
                raise ReadOnlyChannelError(
                    f"Register '{word_addr}' is READ-ONLY in Horner OCS memory model."
                )
            current_word = self.read_word(word_addr)
            new_word = BitSliceOps.pack_bit(current_word, reg.bit_slice, bool(value))  # type: ignore[arg-type]
            self.write_word(word_addr, new_word, privilege=mode)
            return

        # Application mode read-only channel check
        if reg.channel_type.access == ChannelAccess.READ_ONLY and mode != PrivilegeMode.SYSTEM:
            # If written via write_register outside scan (e.g. environment setup)
            if clean.startswith(tuple(self.INPUT_PREFIXES)):
                self.pending_inputs[clean] = value
                return
            raise ReadOnlyChannelError(
                f"Register '{clean}' is READ-ONLY in Horner OCS memory model."
            )

        # Redirect physical inputs to pending inputs
        if clean.startswith(tuple(self.INPUT_PREFIXES)):
            self.pending_inputs[clean] = value
            return

        self.staged_writes[clean] = value

    def set_register(self, address: str, value: Any) -> None:
        """Convenience alias for write_register."""
        self.write_register(address, value)

    # --- Discrete Bit Access ---

    def read_bit(self, address: str) -> bool:
        """Read a discrete Boolean address (%I, %Q, %M, %S, or %R.bit)."""
        val = self.read_register(address)
        return bool(val) if val is not None else False

    def write_bit(
        self,
        address: str,
        value: bool,
        privilege: Optional[PrivilegeMode] = None,
    ) -> None:
        """Write a discrete Boolean address (%I, %Q, %M, or %R.bit). Rejects %S writes."""
        reg = self.parse_address(address)
        mode = privilege or self.privilege_mode

        if reg.prefix == "%S" and not reg.is_bit_slice and mode != PrivilegeMode.SYSTEM:
            raise ReadOnlyChannelError(f"System bit '{reg.clean}' is read-only for application logic.")

        if reg.channel_type.access == ChannelAccess.READ_ONLY and mode != PrivilegeMode.SYSTEM and not reg.is_bit_slice:
            raise ReadOnlyChannelError(f"Channel '{reg.clean}' is READ-ONLY in Horner OCS memory model.")

        val_bool = bool(value)
        if reg.is_bit_slice:
            self.write_register(reg.clean, val_bool, privilege=mode)
        elif reg.prefix in self.INPUT_PREFIXES:
            self.set_input(reg.clean, val_bool)
        else:
            self.write_register(reg.clean, val_bool, privilege=mode)

    # --- 16-Bit Word Access ---

    def read_word(self, address: str) -> int:
        """Read a 16-bit signed integer (-32768..32767) from a word register."""
        val = self.read_register(address)
        if val is None:
            return 0
        v = int(val) & 0xFFFF
        return v if v <= 32767 else v - 65536

    def read_uword(self, address: str) -> int:
        """Read a 16-bit unsigned integer (0..65535) from a word register."""
        return self.read_word(address) & 0xFFFF

    def write_word(
        self,
        address: str,
        value: int,
        privilege: Optional[PrivilegeMode] = None,
    ) -> None:
        """Write a 16-bit signed integer (-32768..32767) to a word register."""
        reg = self.parse_address(address)
        mode = privilege or self.privilege_mode

        if reg.prefix == "%SR" and mode != PrivilegeMode.SYSTEM:
            raise ReadOnlyChannelError(
                f"System register '{reg.clean}' is READ-ONLY. Only engine internal scan can update %SR."
            )

        if reg.channel_type.access == ChannelAccess.READ_ONLY and mode != PrivilegeMode.SYSTEM:
            raise ReadOnlyChannelError(
                f"Register '{reg.clean}' is READ-ONLY in Horner OCS memory model."
            )

        val_16 = int(value) & 0xFFFF
        if val_16 > 32767:
            val_16 = val_16 - 65536

        if reg.prefix in self.INPUT_PREFIXES:
            self.set_input(reg.clean, val_16)
        else:
            self.write_register(reg.clean, val_16, privilege=mode)

    # --- Convenience Analog/Discrete Aliases ---

    def get_analog(self, address: str) -> int:
        """Convenience alias for read_word."""
        return self.read_word(address)

    def set_analog(self, address: str, value: int, privilege: Optional[PrivilegeMode] = None) -> None:
        """Convenience alias for write_word."""
        self.write_word(address, value, privilege=privilege)

    def get_discrete(self, address: str) -> bool:
        """Convenience alias for read_bit."""
        return self.read_bit(address)

    def set_discrete(self, address: str, value: bool, privilege: Optional[PrivilegeMode] = None) -> None:
        """Convenience alias for write_bit."""
        self.write_bit(address, value, privilege=privilege)

    # --- 32-Bit Multi-Word Access ---

    def read_dint(
        self,
        base_address: str,
        word_order: WordOrder = WordOrder.LOW_WORD_FIRST,
    ) -> int:
        """Reads a 32-bit signed DINT across two consecutive 16-bit registers."""
        w1_addr, w2_addr = self.get_consecutive_addresses(base_address, 2)
        w1 = self.read_word(w1_addr)
        w2 = self.read_word(w2_addr)
        return words_to_dint(w1, w2, word_order=word_order)

    def write_dint(
        self,
        base_address: str,
        value: int,
        word_order: WordOrder = WordOrder.LOW_WORD_FIRST,
        privilege: Optional[PrivilegeMode] = None,
    ) -> None:
        """Writes a 32-bit signed DINT across two consecutive 16-bit registers."""
        w1_addr, w2_addr = self.get_consecutive_addresses(base_address, 2)
        w1_val, w2_val = dint_to_words(value, word_order=word_order)
        self.write_word(w1_addr, w1_val, privilege=privilege)
        self.write_word(w2_addr, w2_val, privilege=privilege)

    def read_udint(
        self,
        base_address: str,
        word_order: WordOrder = WordOrder.LOW_WORD_FIRST,
    ) -> int:
        """Reads a 32-bit unsigned UDINT across two consecutive 16-bit registers."""
        w1_addr, w2_addr = self.get_consecutive_addresses(base_address, 2)
        w1 = self.read_word(w1_addr)
        w2 = self.read_word(w2_addr)
        return words_to_udint(w1, w2, word_order=word_order)

    def write_udint(
        self,
        base_address: str,
        value: int,
        word_order: WordOrder = WordOrder.LOW_WORD_FIRST,
        privilege: Optional[PrivilegeMode] = None,
    ) -> None:
        """Writes a 32-bit unsigned UDINT across two consecutive 16-bit registers."""
        w1_addr, w2_addr = self.get_consecutive_addresses(base_address, 2)
        w1_val, w2_val = udint_to_words(value, word_order=word_order)
        self.write_word(w1_addr, w1_val, privilege=privilege)
        self.write_word(w2_addr, w2_val, privilege=privilege)

    def read_real(
        self,
        base_address: str,
        word_order: WordOrder = WordOrder.LOW_WORD_FIRST,
    ) -> float:
        """Reads a 32-bit IEEE 754 single-precision REAL across two consecutive registers."""
        w1_addr, w2_addr = self.get_consecutive_addresses(base_address, 2)
        w1 = self.read_word(w1_addr)
        w2 = self.read_word(w2_addr)
        return words_to_float(w1, w2, word_order=word_order)

    def write_real(
        self,
        base_address: str,
        value: float,
        word_order: WordOrder = WordOrder.LOW_WORD_FIRST,
        privilege: Optional[PrivilegeMode] = None,
    ) -> None:
        """Writes a 32-bit IEEE 754 single-precision REAL across two consecutive registers."""
        w1_addr, w2_addr = self.get_consecutive_addresses(base_address, 2)
        w1_val, w2_val = float_to_words(value, word_order=word_order)
        self.write_word(w1_addr, w1_val, privilege=privilege)
        self.write_word(w2_addr, w2_val, privilege=privilege)

    # --- System / Hardware Simulation Helpers ---

    def set_input(self, address: str, value: Any) -> None:
        """External environment sets a pending input (latched at start of next scan)."""
        clean = self.normalize_address(address)
        self.pending_inputs[clean] = value

    def force_input(self, address: str, value: Any) -> None:
        """System force input directly into both pending and latched input tables."""
        clean = self.normalize_address(address)
        self.pending_inputs[clean] = value
        self.latched_inputs[clean] = value

    def set_system_register(self, address_or_idx: Union[str, int], value: int) -> None:
        """System-privileged write to a %SR diagnostic register."""
        if isinstance(address_or_idx, int):
            addr = f"%SR{address_or_idx}"
        else:
            addr = self.normalize_address(address_or_idx)
        self.system_registers[addr] = int(value) & 0xFFFF

    def set_system_bit(self, address_or_idx: Union[str, int], value: bool) -> None:
        """System-privileged write to a %S system bit."""
        if isinstance(address_or_idx, int):
            addr = f"%S{address_or_idx}"
        else:
            addr = self.normalize_address(address_or_idx)
        self.system_bits[addr] = bool(value)

    def read_system_bit(self, index: int) -> bool:
        """Read a Horner system bit by 1-based integer index (e.g. 1 -> %S1)."""
        return self.system_bits.get(f"%S{index}", False)

    def get_committed_output(self, address: str) -> Any:
        """Read strictly from committed output memory table (external observer view)."""
        clean = self.normalize_address(address)
        return self.committed_memory.get(clean, False)

    # --- Scan Phase Lifecycle Operations ---

    def latch_inputs(self) -> None:
        """Phase 1: Snapshot pending external inputs into frozen latched table."""
        self.latched_inputs = dict(self.pending_inputs)

    def update_system(
        self,
        current_cycle: int,
        dt_ms: float,
        elapsed_time_ms: float,
        elapsed_us: int,
    ) -> None:
        """Phase 2: Advance Horner system bits and diagnostic registers."""
        # %S1: First scan pulse (True strictly on cycle 0, False thereafter)
        self.system_bits["%S1"] = (current_cycle == 0)
        self.system_bits["%S2"] = True   # Network OK
        self.system_bits["%S7"] = True   # Always ON (ALW_ON)
        self.system_bits["%S8"] = False  # Always OFF (ALW_OFF)

        # Clock pulse square waves (50% duty cycle)
        rounded_t = round(elapsed_time_ms, 3)
        self.system_bits["%S3"] = bool((int(rounded_t / 10.0)) % 2 == 1)
        self.system_bits["%S4"] = bool((int(rounded_t / 100.0)) % 2 == 1)
        self.system_bits["%S5"] = bool((int(rounded_t / 1000.0)) % 2 == 1)
        self.system_bits["%S9"] = bool((int(rounded_t / 10000.0)) % 2 == 1)

        # System Registers
        cycle_num = current_cycle + 1
        self.system_registers["%SR1"] = cycle_num & 0xFFFF
        self.system_registers["%SR2"] = 1  # RUN mode
        self.system_registers["%SR3"] = cycle_num & 0xFFFF
        self.system_registers["%SR4"] = (cycle_num >> 16) & 0xFFFF
        self.system_registers["%SR5"] = int(round(dt_ms))

    def rollback_staged(self) -> None:
        """Discard uncommitted staged writes on logic fault and latch fault mode."""
        self.staged_writes.clear()
        self.system_registers["%SR2"] = 3  # FAULTED

    def commit_staged(self) -> List[str]:
        """Phase 3: Atomically commit staged writes to committed memory."""
        modified: List[str] = []
        for k, v in self.staged_writes.items():
            if self.committed_memory.get(k) != v:
                modified.append(k)
        self.committed_memory.update(self.staged_writes)
        self.staged_writes.clear()
        return modified

    def set_delta_t(self, delta_t_ms: float) -> None:
        """Update default scan interval and %SR5."""
        self.default_dt_ms = float(delta_t_ms)
        self.system_registers["%SR5"] = int(round(delta_t_ms))

    def clear_fault(self) -> None:
        """Clear active fault state in %SR2."""
        self.system_registers["%SR2"] = 1  # RUN mode

    def reset(self) -> None:
        """Clear all register banks and re-initialize system state."""
        self.pending_inputs.clear()
        self.latched_inputs.clear()
        self.staged_writes.clear()
        self.committed_memory.clear()
        self.system_bits.clear()
        self.initialize_system_registers()

    # --- Snapshot & Diffing Operations ---

    def snapshot(self) -> Dict[str, Any]:
        """Capture an immutable deep copy snapshot of all register tables."""
        return {
            "pending_inputs": dict(self.pending_inputs),
            "latched_inputs": dict(self.latched_inputs),
            "staged_writes": dict(self.staged_writes),
            "committed_memory": dict(self.committed_memory),
            "system_bits": dict(self.system_bits),
            "system_registers": dict(self.system_registers),
        }

    def restore_snapshot(self, snap: Dict[str, Any]) -> None:
        """Restore memory state from a previous snapshot."""
        self.pending_inputs = dict(snap.get("pending_inputs", {}))
        self.latched_inputs = dict(snap.get("latched_inputs", {}))
        self.staged_writes = dict(snap.get("staged_writes", {}))
        self.committed_memory = dict(snap.get("committed_memory", {}))
        self.system_bits = dict(snap.get("system_bits", {}))
        self.system_registers = dict(snap.get("system_registers", {}))

    def diff(self, other_snap: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate delta between this table's committed memory and another snapshot."""
        other_committed = other_snap.get("committed_memory", {})
        all_keys = set(self.committed_memory.keys()) | set(other_committed.keys())
        mutations: Dict[str, Dict[str, Any]] = {}

        for k in sorted(all_keys):
            old_val = other_committed.get(k, 0 if k.startswith(tuple(self.WORD_PREFIXES)) else False)
            new_val = self.committed_memory.get(k, 0 if k.startswith(tuple(self.WORD_PREFIXES)) else False)
            if old_val != new_val:
                mutations[k] = {"old_value": old_val, "new_value": new_val}

        return {
            "mutations_count": len(mutations),
            "registers": mutations,
        }

    def export_snapshot_components(
        self,
    ) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, bool], Dict[str, int]]:
        """Return shallow copies of memory partitions for CycleSnapshot construction."""
        latched_in = dict(self.latched_inputs)
        committed_out = {
            k: v for k, v in self.committed_memory.items()
            if k.startswith(tuple(self.OUTPUT_PREFIXES))
        }
        internal_regs = {
            k: v for k, v in self.committed_memory.items()
            if not k.startswith(tuple(self.OUTPUT_PREFIXES | self.INPUT_PREFIXES))
        }
        return (
            latched_in,
            committed_out,
            internal_regs,
            dict(self.committed_memory),
            dict(self.system_bits),
            dict(self.system_registers),
        )

    # Convenience aliases
    get_word = read_word
    get_bit = read_bit
    set_word = write_word
    set_bit = write_bit

