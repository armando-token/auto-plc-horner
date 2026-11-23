"""Horner OCS Register and Channel Memory Matrix.

Models the complete OCS memory map: %I, %Q, %M, %D, %K, %AI, %AQ, %R, %SR,
providing register parsing, range validation, access rules, and overlap checks.
"""

from enum import Enum
import re
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


class ChannelAccess(str, Enum):
    """Memory channel read/write accessibility."""
    READ_ONLY = "RO"
    READ_WRITE = "RW"


class ChannelType(BaseModel):
    """Specification of an OCS memory register prefix."""
    prefix: str
    name: str
    element_type: str
    bit_width: int
    range_min: int
    range_max: int
    access: ChannelAccess
    description: str


class ParsedRegister(BaseModel):
    """Parsed Horner OCS register reference."""
    raw: str
    prefix: str
    index: int
    channel_type: ChannelType
    is_valid: bool
    error: Optional[str] = None


class ChannelMatrix:
    """Master registry and validator for Horner OCS memory channels."""

    CHANNELS: Dict[str, ChannelType] = {
        "%I": ChannelType(
            prefix="%I",
            name="Digital Inputs",
            element_type="BOOL",
            bit_width=1,
            range_min=1,
            range_max=2048,
            access=ChannelAccess.READ_ONLY,
            description="Physical digital input contact states."
        ),
        "%Q": ChannelType(
            prefix="%Q",
            name="Digital Outputs",
            element_type="BOOL",
            bit_width=1,
            range_min=1,
            range_max=2048,
            access=ChannelAccess.READ_WRITE,
            description="Physical digital output coil states."
        ),
        "%M": ChannelType(
            prefix="%M",
            name="Internal Markers",
            element_type="BOOL",
            bit_width=1,
            range_min=1,
            range_max=2048,
            access=ChannelAccess.READ_WRITE,
            description="Internal Boolean memory bits."
        ),
        "%D": ChannelType(
            prefix="%D",
            name="Display Bits",
            element_type="BOOL",
            bit_width=1,
            range_min=1,
            range_max=2048,
            access=ChannelAccess.READ_WRITE,
            description="Screen navigation and screen active bits."
        ),
        "%K": ChannelType(
            prefix="%K",
            name="Keypad Bits",
            element_type="BOOL",
            bit_width=1,
            range_min=1,
            range_max=128,
            access=ChannelAccess.READ_ONLY,
            description="Hard key and function key states."
        ),
        "%AI": ChannelType(
            prefix="%AI",
            name="Analog Inputs",
            element_type="INT",
            bit_width=16,
            range_min=1,
            range_max=512,
            access=ChannelAccess.READ_ONLY,
            description="Physical analog input words (raw counts)."
        ),
        "%AQ": ChannelType(
            prefix="%AQ",
            name="Analog Outputs",
            element_type="INT",
            bit_width=16,
            range_min=1,
            range_max=512,
            access=ChannelAccess.READ_WRITE,
            description="Physical analog output words."
        ),
        "%R": ChannelType(
            prefix="%R",
            name="General Holding Registers",
            element_type="INT",
            bit_width=16,
            range_min=1,
            range_max=9999,
            access=ChannelAccess.READ_WRITE,
            description="16-bit word storage for variables, timers, and calculations."
        ),
        "%SR": ChannelType(
            prefix="%SR",
            name="System Registers",
            element_type="INT",
            bit_width=16,
            range_min=1,
            range_max=256,
            access=ChannelAccess.READ_ONLY,
            description="Diagnostic system registers (clock, scan time, battery status)."
        ),
        "%S": ChannelType(
            prefix="%S",
            name="System Bits",
            element_type="BOOL",
            bit_width=1,
            range_min=1,
            range_max=16,
            access=ChannelAccess.READ_ONLY,
            description="System status and clock bits (%S1 first scan, %S7 always ON, %S8 always OFF)."
        ),
    }

    _REG_PATTERN = re.compile(r"^%([A-Z]+)(\d+)$", re.I)

    @classmethod
    def parse_register(cls, address: str) -> ParsedRegister:
        """Parse and validate an OCS register string (e.g. %R100, %AI4, %Q1)."""
        clean = address.strip().upper()
        if not clean.startswith("%"):
            clean = "%" + clean

        match = cls._REG_PATTERN.match(clean)
        if not match:
            return ParsedRegister(
                raw=address,
                prefix="",
                index=0,
                channel_type=cls.CHANNELS["%R"],
                is_valid=False,
                error=f"Invalid register format: '{address}'. Expected format like %R1, %AI2, %Q1.",
            )

        pfx = "%" + match.group(1).upper()
        idx = int(match.group(2))

        ctype = cls.CHANNELS.get(pfx)
        if not ctype:
            return ParsedRegister(
                raw=address,
                prefix=pfx,
                index=idx,
                channel_type=cls.CHANNELS["%R"],
                is_valid=False,
                error=f"Unrecognized memory prefix '{pfx}'. Valid prefixes: {list(cls.CHANNELS.keys())}",
            )

        if idx < ctype.range_min or idx > ctype.range_max:
            return ParsedRegister(
                raw=address,
                prefix=pfx,
                index=idx,
                channel_type=ctype,
                is_valid=False,
                error=f"Index {idx} out of range for {pfx} ({ctype.range_min}..{ctype.range_max}).",
            )

        return ParsedRegister(
            raw=address,
            prefix=pfx,
            index=idx,
            channel_type=ctype,
            is_valid=True,
            error=None,
        )

    @classmethod
    def export_matrix(cls) -> Dict[str, Any]:
        """Export full OCS channel specification as dictionary."""
        return {
            "channels_count": len(cls.CHANNELS),
            "channels": {k: v.model_dump() for k, v in cls.CHANNELS.items()},
        }
