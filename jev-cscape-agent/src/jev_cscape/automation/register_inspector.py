"""Horner OCS Register State Space Inspector and Formatter.

Work Package: W019 (Gate G4)
Classification: TESTED_MOCK [offline/DEV only]

Provides address range expansion (%R1..%R10), channel-specific filtering,
zero-dependency ASCII table formatting, and JSON serialization for terminal
inspection and AI telemetry.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Union

from jev_cscape.simulation.register_table import EXTENDED_CHANNELS, RegisterTable


class RegisterInspector:
    """Inspector and formatter for Horner APG OCS register state."""

    _RANGE_REGEX = re.compile(
        r"^%?([A-Z]+)(\d+)(?:\s*(?:\.\.|\-)\s*%?([A-Z]+)?(\d+))?$",
        re.IGNORECASE,
    )

    @classmethod
    def parse_range(cls, range_expr: str) -> List[str]:
        """Expand range expression (e.g. '%R1..%R10', '%I1-8', or '%R100') into list of addresses."""
        clean = range_expr.strip()
        match = cls._RANGE_REGEX.match(clean)
        if not match:
            raise ValueError(
                f"Invalid register range format: '{range_expr}'. "
                f"Expected format like '%R1..%R10', '%I1-8', or '%R100'."
            )

        start_pfx = "%" + match.group(1).upper()
        start_idx = int(match.group(2))
        end_pfx_group = match.group(3)
        end_idx_group = match.group(4)

        if end_idx_group is None:
            # Single address
            return [f"{start_pfx}{start_idx}"]

        end_pfx = ("%" + end_pfx_group.upper()) if end_pfx_group else start_pfx
        end_idx = int(end_idx_group)

        if start_pfx != end_pfx:
            raise ValueError(
                f"Mismatched channel prefixes in range: {start_pfx} vs {end_pfx}."
            )

        if start_idx > end_idx:
            raise ValueError(
                f"Range start index ({start_idx}) cannot be greater than end index ({end_idx})."
            )

        # Max range safety limit (prevent runaway allocations)
        if (end_idx - start_idx + 1) > 10_000:
            raise ValueError(
                f"Range span ({end_idx - start_idx + 1}) exceeds maximum inspection limit of 10,000 registers."
            )

        return [f"{start_pfx}{i}" for i in range(start_idx, end_idx + 1)]

    @classmethod
    def inspect(
        cls,
        table: RegisterTable,
        addresses: Optional[List[str]] = None,
        channel: Optional[str] = None,
        nonzero_only: bool = False,
    ) -> Dict[str, Any]:
        """Inspect table state for given addresses or whole channel."""
        target_addrs: List[str] = []

        if addresses:
            for expr in addresses:
                target_addrs.extend(cls.parse_range(expr))
        elif channel:
            pfx = channel.strip().upper()
            if not pfx.startswith("%"):
                pfx = "%" + pfx
            ctype = EXTENDED_CHANNELS.get(pfx)
            if not ctype:
                raise ValueError(f"Unrecognized channel prefix '{channel}'.")
            # For whole channel, collect non-default or first N
            max_inspect = min(ctype.range_max, 100) if not nonzero_only else ctype.range_max
            target_addrs = [f"{pfx}{i}" for i in range(ctype.range_min, max_inspect + 1)]
        else:
            # Default: inspect %R1..%R10, %I1..%I8, %Q1..%Q8, %SR1..%SR5, %S1..%S8
            target_addrs = (
                [f"%R{i}" for i in range(1, 11)]
                + [f"%I{i}" for i in range(1, 9)]
                + [f"%Q{i}" for i in range(1, 9)]
                + [f"%SR{i}" for i in range(1, 6)]
                + [f"%S{i}" for i in range(1, 9)]
            )

        results: List[Dict[str, Any]] = []

        for addr in target_addrs:
            try:
                reg = table.parse_address(addr)
            except ValueError:
                continue

            val = table.read_register(addr)
            is_nonzero = bool(val != 0 if reg.channel_type.element_type == "INT" else val)

            if nonzero_only and not is_nonzero:
                continue

            results.append(
                {
                    "address": reg.clean,
                    "value": val,
                    "type": reg.channel_type.element_type,
                    "access": reg.channel_type.access.value,
                    "description": reg.channel_type.name,
                }
            )

        return {
            "count": len(results),
            "nonzero_only": nonzero_only,
            "registers": results,
        }

    @staticmethod
    def format_table(data: Dict[str, Any]) -> str:
        """Format inspected register results as an ASCII terminal table."""
        regs = data.get("registers", [])
        if not regs:
            return "No registers matched the query criteria."

        headers = ["Address", "Value", "Type", "Access", "Channel Name"]
        col_widths = [10, 10, 8, 8, 26]

        lines: List[str] = []
        # Header line
        header_str = " | ".join(h.ljust(w) for h, w in zip(headers, col_widths))
        sep_str = "-+-".join("-" * w for w in col_widths)
        lines.append(header_str)
        lines.append(sep_str)

        for item in regs:
            val_str = str(item["value"])
            row = [
                item["address"].ljust(col_widths[0]),
                val_str.ljust(col_widths[1]),
                item["type"].ljust(col_widths[2]),
                item["access"].ljust(col_widths[3]),
                item["description"].ljust(col_widths[4]),
            ]
            lines.append(" | ".join(row))

        lines.append(f"\nTotal: {len(regs)} registers displayed.")
        return "\n".join(lines)

    @staticmethod
    def format_json(data: Dict[str, Any], indent: int = 2) -> str:
        """Format inspected register results as formatted JSON."""
        return json.dumps(data, indent=indent)
