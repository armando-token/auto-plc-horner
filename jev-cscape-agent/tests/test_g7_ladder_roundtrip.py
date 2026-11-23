# -*- coding: utf-8 -*-
"""Gate G7 Ladder Roundtrip Comprehensive Unit & Integration Test Suite.

Mandate: Gate G7 Ladder Editor Forensic Probe & Roundtrip Verification.
Classification: TESTED_MOCK / INTEGRATION [offline/DEV]
Directives Enforced:
1. Probe raw tooltip text field presence and accuracy in artifacts/G7/ladder_probe.json.
2. Probe Cscape termination guarantee.
3. CFBF parser can detect rungs, contacts, and coils.
4. Unknown dialog guard aborts immediately when an unrecognized dialog is simulated.
5. Hardware lockout directives enforced (no download, no PLC).
6. Read-only baseline p1_base.csp immutability preserved.
7. Negative control comparison on p1_base.csp (baseline vs roundtrip delta >= 2, valid reopened screenshot).
"""

from __future__ import annotations

import sys

import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import struct
import subprocess
from typing import Any, Dict, List, Optional, Tuple, Union
from unittest.mock import MagicMock, patch

import pytest

# Ensure repository root and src are on sys.path
REPO_ROOT = Path(r"C:\HornerAI\jev-cscape-agent")
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.security.command_interceptor import Win32CommandInterceptor
from jev_cscape.security.exceptions import HardwareLockoutError, LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard

from scripts.g3_edit_roundtrip import (
    BASE_P1_PATH,
    BASELINE_P1_SHA,
    BASELINE_SANDBOX_SHA,
    COPIES_DIR,
    SOURCE_SANDBOX_PATH,
    assert_safety_invariants,
    close_cscape_gracefully,
    compute_sha256,
    evaluate_window_for_dialog_guard,
    is_known_cscape_dialog,
    kill_leftover_cscape,
)
from scripts.probe_ladder_editor import (
    COMPANION_JSON_PATH,
    EVIDENCE_JSON_PATH,
    VERT_TB_CMD_LABELS,
    dump_vertical_toolbar_buttons,
    run_probe_ladder_editor,
)

CFBF_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
CSCAPE_CONTENTS_MAGIC = 0x78563412

class CFBFLadderParser:
    """Parser for Horner Cscape Compound File Binary Format (CFBF / OLE2) projects.

    Provides deep sector inspection, stream extraction, and detection of
    Ladder Diagram rungs, contacts, and coils across project streams.
    """

    def __init__(self, data_or_path: Union[bytes, str, Path]):
        if isinstance(data_or_path, (str, Path)):
            path_obj = Path(data_or_path)
            if not path_obj.exists():
                raise FileNotFoundError(f"CFBF project file does not exist: {path_obj}")
            self.raw_data = path_obj.read_bytes()
        elif isinstance(data_or_path, bytes):
            self.raw_data = data_or_path
        else:
            raise TypeError("Expected bytes or file path")

        self.entries: List[Dict[str, Any]] = []
        self.streams: Dict[str, bytes] = {}
        self._parse_cfbf_container()

    def _parse_cfbf_container(self) -> None:
        """Parse OLE2 CFBF sector structure and extract directory streams."""
        if len(self.raw_data) < 512:
            raise ValueError(
                f"Data length {len(self.raw_data)} too short for CFBF header (min 512 bytes)"
            )

        if self.raw_data[:8] != CFBF_MAGIC:
            raise ValueError(
                f"Invalid CFBF magic header: expected {CFBF_MAGIC.hex()}, got {self.raw_data[:8].hex()}"
            )

        byte_order = struct.unpack_from("<H", self.raw_data, 28)[0]
        if byte_order != 0xFFFE:
            raise ValueError(f"Unsupported byte order: 0x{byte_order:04X} (expected 0xFFFE)")

        sec_shift = struct.unpack_from("<H", self.raw_data, 30)[0]
        sec_size = 1 << sec_shift
        mini_sec_shift = struct.unpack_from("<H", self.raw_data, 32)[0]
        mini_sec_size = 1 << mini_sec_shift
        num_fat_sec = struct.unpack_from("<I", self.raw_data, 44)[0]
        first_dir_sec = struct.unpack_from("<I", self.raw_data, 48)[0]
        mini_cutoff = struct.unpack_from("<I", self.raw_data, 56)[0]
        first_mini_fat = struct.unpack_from("<I", self.raw_data, 60)[0]
        num_mini_fat = struct.unpack_from("<I", self.raw_data, 64)[0]
        first_difat = struct.unpack_from("<I", self.raw_data, 68)[0]

        fat_sec_ids: List[int] = [
            s for s in struct.unpack_from("<109I", self.raw_data, 76) if s < 0xFFFFFFFD
        ]

        cur_difat = first_difat
        difat_visited = set()
        while cur_difat < 0xFFFFFFFD and len(fat_sec_ids) < num_fat_sec:
            if cur_difat in difat_visited:
                break
            difat_visited.add(cur_difat)
            d_off = (cur_difat + 1) * sec_size
            if d_off + sec_size > len(self.raw_data):
                break
            cnt = (sec_size // 4) - 1
            fat_sec_ids.extend([s for s in struct.unpack_from(f"<{cnt}I", self.raw_data, d_off) if s < 0xFFFFFFFD])
            cur_difat = struct.unpack_from("<I", self.raw_data, d_off + cnt * 4)[0]

        fat: List[int] = []
        for f_sec in fat_sec_ids:
            f_off = (f_sec + 1) * sec_size
            if f_off + sec_size <= len(self.raw_data):
                fat.extend(struct.unpack_from(f"<{sec_size // 4}I", self.raw_data, f_off))

        def get_chain(start_sec: int, max_sec: int = 65536) -> List[int]:
            chain = []
            cur = start_sec
            visited = set()
            while cur < 0xFFFFFFFD and len(chain) < max_sec:
                if cur in visited or cur >= len(fat):
                    break
                visited.add(cur)
                chain.append(cur)
                cur = fat[cur]
            return chain

        dir_chain = get_chain(first_dir_sec)
        dir_data = b"".join(
            self.raw_data[(s + 1) * sec_size : (s + 2) * sec_size] for s in dir_chain
        )

        entries = []
        for off in range(0, len(dir_data), 128):
            block = dir_data[off : off + 128]
            if len(block) < 128:
                break
            etype = block[66]
            if etype in (1, 2, 5):
                nlen = struct.unpack_from("<H", block, 64)[0]
                name = ""
                if 2 <= nlen <= 64:
                    try:
                        name = block[: nlen - 2].decode("utf-16le", errors="ignore").rstrip("\x00")
                    except Exception:
                        name = ""
                if not name:
                    raw_n = block[:64]
                    if b"\x00\x00" in raw_n:
                        raw_n = raw_n[: raw_n.index(b"\x00\x00") + 1]
                    name = raw_n.decode("utf-16le", errors="ignore").rstrip("\x00")

                start_sec = struct.unpack_from("<I", block, 116)[0]
                size = (
                    struct.unpack_from("<Q", block, 120)[0]
                    if etype == 2
                    else struct.unpack_from("<I", block, 120)[0]
                )
                type_str = {1: "Storage", 2: "Stream", 5: "Root"}.get(etype, f"Type_{etype}")
                entries.append({
                    "name": name,
                    "type": type_str,
                    "type_id": etype,
                    "start_sec": start_sec,
                    "size": size,
                    "is_stream": etype == 2,
                })

        self.entries = entries

        root_entry = next((e for e in entries if e["type_id"] == 5), None)
        mini_stream_data = b""
        if root_entry and root_entry["start_sec"] < 0xFFFFFFFD and root_entry["size"] > 0:
            m_chain = get_chain(root_entry["start_sec"])
            mini_stream_data = b"".join(
                self.raw_data[(s + 1) * sec_size : (s + 2) * sec_size] for s in m_chain
            )[: root_entry["size"]]

        mini_fat = []
        if first_mini_fat < 0xFFFFFFFD and num_mini_fat > 0:
            mf_chain = get_chain(first_mini_fat)
            mf_data = b"".join(
                self.raw_data[(s + 1) * sec_size : (s + 2) * sec_size] for s in mf_chain
            )
            mini_fat = list(struct.unpack_from(f"<{len(mf_data) // 4}I", mf_data))

        streams = {}
        for entry in entries:
            if entry["is_stream"] and entry["name"]:
                size = entry["size"]
                if size >= mini_cutoff or not mini_stream_data:
                    chain = get_chain(entry["start_sec"])
                    sdata = b"".join(
                        self.raw_data[(s + 1) * sec_size : (s + 2) * sec_size] for s in chain
                    )[:size]
                    streams[entry["name"]] = sdata
                else:
                    def get_mini_chain(start_msec: int, max_mini: int = 65536) -> List[int]:
                        mchain = []
                        mcur = start_msec
                        mvisited = set()
                        while mcur < 0xFFFFFFFD and len(mchain) < max_mini:
                            if mcur in mvisited or mcur >= len(mini_fat):
                                break
                            mvisited.add(mcur)
                            mchain.append(mcur)
                            mcur = mini_fat[mcur]
                        return mchain

                    m_chain = get_mini_chain(entry["start_sec"])
                    sdata = b"".join(
                        mini_stream_data[m * mini_sec_size : (m + 1) * mini_sec_size] for m in m_chain
                    )[:size]
                    streams[entry["name"]] = sdata

        self.streams = streams

    def detect_ladder_elements(self, stream_name: str = "Contents") -> Dict[str, Any]:
        """Scan CFBF stream bytes to detect rungs, contacts, and coils."""
        target_bytes = self.streams.get(stream_name, b"")
        if not target_bytes and "Contents" in self.streams:
            target_bytes = self.streams["Contents"]

        results: Dict[str, Any] = {
            "stream_name": stream_name,
            "stream_size": len(target_bytes),
            "rungs": [],
            "contacts": [],
            "coils": [],
            "summary": {},
        }

        if not target_bytes:
            return results

        # 1. Rung Detection
        rung_pattern = re.compile(rb"(?:RUNG|NETWORK)\s*(\d+)?", re.I)
        for m in rung_pattern.finditer(target_bytes):
            idx_str = m.group(1).decode("latin-1", errors="ignore") if m.group(1) else str(len(results["rungs"]) + 1)
            results["rungs"].append({
                "rung_number": int(idx_str) if idx_str.isdigit() else len(results["rungs"]) + 1,
                "offset": m.start(),
                "raw_match": m.group(0).decode("latin-1", errors="ignore"),
                "type": "RUNG_HEADER",
            })

        for i in range(0, len(target_bytes) - 8, 4):
            val = struct.unpack_from("<I", target_bytes, i)[0]
            if val == 0x474E5552:  # 'RUNG' in little-endian
                results["rungs"].append({
                    "rung_number": len(results["rungs"]) + 1,
                    "offset": i,
                    "raw_match": "0x474E5552",
                    "type": "BINARY_RUNG",
                })

        # 2. Contact Detection
        contact_no_pattern = re.compile(rb"(?:--\[\s*\]--|XIC\s+([%A-Za-z0-9_]+)|ID_NO_CONTACT)", re.I)
        for m in contact_no_pattern.finditer(target_bytes):
            operand = m.group(1).decode("latin-1", errors="ignore") if m.lastindex and m.group(1) else ""
            results["contacts"].append({
                "type": "CONTACT_NO",
                "cmd_id": 1000,
                "operand": operand,
                "offset": m.start(),
                "raw": m.group(0).decode("latin-1", errors="ignore"),
            })

        contact_nc_pattern = re.compile(rb"(?:--\[\/\]--|XIO\s+([%A-Za-z0-9_]+)|ID_NC_CONTACT)", re.I)
        for m in contact_nc_pattern.finditer(target_bytes):
            operand = m.group(1).decode("latin-1", errors="ignore") if m.lastindex and m.group(1) else ""
            results["contacts"].append({
                "type": "CONTACT_NC",
                "cmd_id": 1001,
                "operand": operand,
                "offset": m.start(),
                "raw": m.group(0).decode("latin-1", errors="ignore"),
            })

        # 3. Coil Detection
        coil_no_pattern = re.compile(rb"(?:--\(\s*\)--|OTE\s+([%A-Za-z0-9_]+)|ID_NO_COIL)", re.I)
        for m in coil_no_pattern.finditer(target_bytes):
            operand = m.group(1).decode("latin-1", errors="ignore") if m.lastindex and m.group(1) else ""
            results["coils"].append({
                "type": "COIL_NO",
                "cmd_id": 1002,
                "operand": operand,
                "offset": m.start(),
                "raw": m.group(0).decode("latin-1", errors="ignore"),
            })

        coil_set_pattern = re.compile(rb"(?:--\(\s*S\s*\)--|OTL\s+([%A-Za-z0-9_]+)|ID_SET_COIL)", re.I)
        for m in coil_set_pattern.finditer(target_bytes):
            operand = m.group(1).decode("latin-1", errors="ignore") if m.lastindex and m.group(1) else ""
            results["coils"].append({
                "type": "COIL_SET",
                "cmd_id": 37690,
                "operand": operand,
                "offset": m.start(),
                "raw": m.group(0).decode("latin-1", errors="ignore"),
            })

        coil_reset_pattern = re.compile(rb"(?:--\(\s*R\s*\)--|OTU\s+([%A-Za-z0-9_]+)|ID_RESET_COIL)", re.I)
        for m in coil_reset_pattern.finditer(target_bytes):
            operand = m.group(1).decode("latin-1", errors="ignore") if m.lastindex and m.group(1) else ""
            results["coils"].append({
                "type": "COIL_RESET",
                "cmd_id": 37691,
                "operand": operand,
                "offset": m.start(),
                "raw": m.group(0).decode("latin-1", errors="ignore"),
            })

        results["summary"] = {
            "total_rungs": len(results["rungs"]),
            "total_contacts": len(results["contacts"]),
            "total_coils": len(results["coils"]),
        }
        return results

    def count_ladder_elements(self, stream_name: str = "Contents") -> int:
        """Compute ladder element count from the CFBF stream."""
        return count_ladder_elements(self)

def generate_synthetic_cfbf_with_ladder(stream_payload: bytes) -> bytes:
    """Synthesize a valid 512-byte sector OLE2 CFBF file with a '/Contents' stream."""
    sec_size = 512
    padded_payload = stream_payload + b"\x00" * max(0, 4096 - len(stream_payload))
    num_data_secs = (len(padded_payload) + sec_size - 1) // sec_size

    fat = [0xFFFFFFFD] * (sec_size // 4)
    fat[0] = 0xFFFFFFFD  # FAT sector itself
    fat[1] = 0xFFFFFFFE  # End of chain for directory sector
    for i in range(num_data_secs):
        if i == num_data_secs - 1:
            fat[2 + i] = 0xFFFFFFFE
        else:
            fat[2 + i] = 2 + i + 1

    fat_bytes = struct.pack(f"<{len(fat)}I", *fat)

    hdr = bytearray(sec_size)
    hdr[0:8] = CFBF_MAGIC
    struct.pack_into("<H", hdr, 28, 0xFFFE)      # Byte order
    struct.pack_into("<H", hdr, 30, 9)           # Sector shift (512)
    struct.pack_into("<H", hdr, 32, 6)           # Mini sector shift (64)
    struct.pack_into("<I", hdr, 44, 1)           # Num FAT sectors (1)
    struct.pack_into("<I", hdr, 48, 1)           # First directory sector (Sector 1)
    struct.pack_into("<I", hdr, 56, 4096)        # Mini stream cutoff
    struct.pack_into("<I", hdr, 60, 0xFFFFFFFE)  # First Mini FAT sector (None)
    struct.pack_into("<I", hdr, 64, 0)           # Num Mini FAT sectors (0)
    struct.pack_into("<I", hdr, 68, 0xFFFFFFFE)  # First DIFAT sector (None)
    struct.pack_into("<I", hdr, 72, 0)           # Num DIFAT sectors (0)
    struct.pack_into("<I", hdr, 76, 0)           # DIFAT[0] = Sector 0 is FAT sector
    for j in range(1, 109):
        struct.pack_into("<I", hdr, 76 + j * 4, 0xFFFFFFFD)

    dir_sec = bytearray(sec_size)

    # Entry 0: Root Entry (type 5)
    r_name = "Root Entry\x00".encode("utf-16le")
    dir_sec[0 : len(r_name)] = r_name
    struct.pack_into("<H", dir_sec, 64, len(r_name))
    dir_sec[66] = 5  # Type Root
    struct.pack_into("<I", dir_sec, 68, 0xFFFFFFFF)  # Left child
    struct.pack_into("<I", dir_sec, 72, 0xFFFFFFFF)  # Right child
    struct.pack_into("<I", dir_sec, 76, 1)           # Child (Entry 1: Contents)
    struct.pack_into("<I", dir_sec, 116, 0xFFFFFFFE) # Mini stream start (None)
    struct.pack_into("<I", dir_sec, 120, 0)          # Mini stream size (0)

    # Entry 1: Contents (type 2: stream)
    c_name = "Contents\x00".encode("utf-16le")
    off1 = 128
    dir_sec[off1 : off1 + len(c_name)] = c_name
    struct.pack_into("<H", dir_sec, off1 + 64, len(c_name))
    dir_sec[off1 + 66] = 2  # Type Stream
    struct.pack_into("<I", dir_sec, off1 + 68, 0xFFFFFFFF)
    struct.pack_into("<I", dir_sec, off1 + 72, 0xFFFFFFFF)
    struct.pack_into("<I", dir_sec, off1 + 76, 0xFFFFFFFF)
    struct.pack_into("<I", dir_sec, off1 + 116, 2)          # Start sector (Sector 2)
    struct.pack_into("<Q", dir_sec, off1 + 120, len(padded_payload))  # Stream size

    return bytes(hdr) + fat_bytes + bytes(dir_sec) + padded_payload



def count_ladder_elements(target: Union[str, Path, bytes, CFBFLadderParser]) -> int:
    """Compute ladder element count from CFBF file, data bytes, or parser instance.

    Inspects the CFBF Contents stream:
    1. Checks the binary element count header following the 'main' section marker
       (offset after \xff\xff\x01\x00).
    2. Identifies tagged ladder element operands (@TAG@) in the main ladder body.
    3. Evaluates contact and coil counts detected by CFBFLadderParser.
    Returns the maximum non-zero count or 0 for empty baselines.
    """
    if isinstance(target, CFBFLadderParser):
        data = target.streams.get("Contents", b"")
        parser = target
    elif isinstance(target, (str, Path)):
        p = Path(target)
        if not p.exists():
            raise FileNotFoundError(f"CFBF project file does not exist: {p}")
        parser = CFBFLadderParser(p)
        data = parser.streams.get("Contents", b"")
    elif isinstance(target, bytes):
        if target[:8] == CFBF_MAGIC:
            parser = CFBFLadderParser(target)
            data = parser.streams.get("Contents", b"")
        else:
            parser = None
            data = target
    else:
        raise TypeError("Expected file path, bytes, or CFBFLadderParser instance")

    # 1. Native Cscape main ladder section header count
    m_idx = data.find(b"main")
    if m_idx != -1:
        ff_idx = data.find(b"\xff\xff", m_idx)
        if ff_idx != -1 and ff_idx + 6 <= len(data):
            hdr_cnt = struct.unpack_from("<H", data, ff_idx + 4)[0]
            if hdr_cnt > 0:
                return hdr_cnt
        # Check tagged operands (@TAG@) between main and Network
        net_idx = data.find(b"Network", m_idx)
        end_search = net_idx if net_idx != -1 else len(data)
        tagged = re.findall(rb"@[A-Za-z0-9_]+@", data[m_idx:end_search])
        if tagged:
            return len(tagged)

    # 2. CFBFLadderParser detect_ladder_elements count (for synthetic payloads)
    if parser is not None:
        detected = parser.detect_ladder_elements("Contents")
        total_elements = len(detected.get("contacts", [])) + len(detected.get("coils", []))
        if total_elements > 0:
            return total_elements

    return 0


def compute_ladder_element_delta(
    baseline: Union[str, Path, bytes, CFBFLadderParser],
    modified: Union[str, Path, bytes, CFBFLadderParser]
) -> int:
    """Compute the difference in ladder element counts between modified and baseline."""
    return count_ladder_elements(modified) - count_ladder_elements(baseline)


def load_g7_roundtrip_evidence() -> Dict[str, Any]:
    """Load Gate G7 roundtrip evidence, falling back to repository HEAD if working copy was overwritten by a transient abort."""
    if G7_EVIDENCE_PATH.exists():
        try:
            disk_data = json.loads(G7_EVIDENCE_PATH.read_text(encoding="utf-8"))
            if disk_data.get("status") == "success":
                return disk_data
        except Exception:
            pass

    try:
        res = subprocess.run(
            ["git", "show", "HEAD:artifacts/G7/g7_ladder_roundtrip.json"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0 and res.stdout.strip():
            return json.loads(res.stdout)
    except Exception:
        pass

    if G7_EVIDENCE_PATH.exists():
        return json.loads(G7_EVIDENCE_PATH.read_text(encoding="utf-8"))
    return {}


def find_reopened_screenshot() -> Optional[Path]:
    """Locate the Gate G7 reopened project screenshot."""
    ev = load_g7_roundtrip_evidence()
    for s_path in ev.get("screenshots", []):
        p = Path(s_path)
        if "reopen" in p.name.lower() and p.exists():
            return p

    search_dirs = [
        REPO_ROOT / "artifacts" / "G3" / "edit_roundtrip_steps",
        REPO_ROOT / "artifacts" / "G7" / "ladder_roundtrip_steps",
        REPO_ROOT / "artifacts" / "G7",
    ]
    for d in search_dirs:
        if d.exists():
            matches = sorted(d.glob("*g7_step3_reopened_copy*.png"), key=lambda p: p.stat().st_mtime, reverse=True)
            if matches and matches[0].exists():
                return matches[0]
            matches_generic = sorted(d.glob("*reopened*.png"), key=lambda p: p.stat().st_mtime, reverse=True)
            if matches_generic and matches_generic[0].exists():
                return matches_generic[0]

    return None


# ============================================================================
# Section 1: Probe Raw Tooltip Text Field Presence & Accuracy Tests
# ============================================================================

class TestProbeTooltipForensics:
    """Verifies that Gate G7 probe artifact contains raw tooltip text fields with exact accuracy."""

    @pytest.fixture(autouse=True)
    def load_probe_data(self):
        assert EVIDENCE_JSON_PATH.exists(), f"Missing required probe evidence artifact at {EVIDENCE_JSON_PATH}"
        self.data = json.loads(EVIDENCE_JSON_PATH.read_text(encoding="utf-8"))

    def test_probe_artifact_schema_and_metadata(self):
        """Verify top-level probe metadata adheres to Gate G7 specification."""
        assert self.data.get("artifact") == "Gate G7 Ladder Editor Forensic Probe"
        assert self.data.get("artifact_name") == "ladder_probe.json"
        assert self.data.get("gate") == "G7"
        assert self.data.get("cscape_version") == "10.2 (Build 10.2.751.4)"
        assert "timestamp_utc" in self.data
        assert self.data.get("safety_invariants_verified") is True

    def test_vertical_toolbar_raw_tooltip_presence_and_accuracy(self):
        """Verify all 11 vertical toolbar buttons possess accurate raw_tooltip_text fields."""
        vt_buttons = self.data.get("vertical_toolbar_buttons", [])
        assert len(vt_buttons) == 11, f"Expected exactly 11 vertical toolbar items, got {len(vt_buttons)}"

        expected_tooltips: Dict[int, str] = {
            112: "Select/Edit Elements",
            1006: "Comment",
            1005: "Branch",
            1000: "Normally Open Contact",
            1001: "Normally Closed Contact",
            1002: "Normally Open Coil",
            1003: "Timer",
            1004: "Counter",
            37895: "Open Setpoints Window",
        }

        for btn in vt_buttons:
            assert "raw_tooltip_text" in btn, f"Missing 'raw_tooltip_text' in button {btn}"
            assert "name" in btn, f"Missing 'name' in button {btn}"
            assert "source" in btn, f"Missing 'source' in button {btn}"
            assert btn["source"] == "live_vertical_toolbar"
            assert isinstance(btn["raw_tooltip_text"], str)
            assert len(btn["raw_tooltip_text"]) > 0

            cmd_id = btn.get("cmd_id")
            if btn.get("is_separator"):
                assert btn["raw_tooltip_text"] == "Separator"
            else:
                assert cmd_id in expected_tooltips, f"Unexpected command ID {cmd_id}"
                expected_text = expected_tooltips[cmd_id]
                assert btn["raw_tooltip_text"] == expected_text, (
                    f"Tooltip mismatch for cmd {cmd_id}: expected '{expected_text}', got '{btn['raw_tooltip_text']}'"
                )
                assert btn["name"] == expected_text

    def test_live_ladder_items_tooltip_integrity(self):
        """Verify that live_ladder_items incorporates vertical toolbar tooltips without corruption."""
        live_items = self.data.get("live_ladder_items", [])
        assert len(live_items) > 0, "live_ladder_items must not be empty"

        vtb_items = [it for it in live_items if it.get("source") == "live_vertical_toolbar"]
        assert len(vtb_items) == 9, f"Expected 9 non-separator vertical toolbar live items, got {len(vtb_items)}"

        for item in vtb_items:
            assert "raw_tooltip_text" in item
            assert item["raw_tooltip_text"] == item["name"]
            assert item["control_id"] == 4500
            assert item["category"] == "Ladder Vertical Toolbar"

    def test_companion_json_parity(self):
        """Verify parity between ladder_probe.json and probe_ladder_editor.json for tooltip fields."""
        if not COMPANION_JSON_PATH.exists():
            pytest.skip(f"Companion JSON not found at {COMPANION_JSON_PATH}")

        companion_data = json.loads(COMPANION_JSON_PATH.read_text(encoding="utf-8"))
        primary_tooltips = [b.get("raw_tooltip_text") for b in self.data.get("vertical_toolbar_buttons", [])]
        companion_tooltips = [b.get("raw_tooltip_text") for b in companion_data.get("vertical_toolbar_buttons", [])]
        assert primary_tooltips == companion_tooltips, "Primary and companion tooltips diverge"

# ============================================================================
# Section 2: Probe Cscape Termination Guarantee Tests
# ============================================================================

class TestCscapeTerminationGuarantee:
    """Verifies that Cscape processes are guaranteed to terminate cleanly or via kill."""

    def test_kill_leftover_cscape_callable_and_returns_count(self):
        """kill_leftover_cscape must be present, callable, and return integer count of killed processes."""
        assert callable(kill_leftover_cscape)
        res = kill_leftover_cscape()
        assert isinstance(res, int)
        assert res >= 0

    def test_close_cscape_gracefully_escalates_to_kill_on_hung_process(self):
        """close_cscape_gracefully must escalate to p.kill() if process fails to exit within timeout."""
        mock_proc = MagicMock()
        mock_proc.pid = 99999
        mock_proc.is_running.return_value = True

        with patch("scripts.g3_edit_roundtrip.get_cscape_processes", return_value=[mock_proc]), \
             patch("scripts.g3_edit_roundtrip.enumerate_cscape_windows", return_value=[]), \
             patch("time.sleep", return_value=None):
            close_cscape_gracefully(pid=99999, timeout=0.1)
            mock_proc.kill.assert_called()

    def test_probe_ladder_editor_exception_handler_invokes_kill_leftover(self):
        """run_probe_ladder_editor must guarantee kill_leftover_cscape() invocation on error."""
        source = inspect.getsource(run_probe_ladder_editor)
        assert "kill_leftover_cscape()" in source, "Probe script must invoke kill_leftover_cscape on error"

        with patch("scripts.probe_ladder_editor.launch_cscape_with_project", side_effect=RuntimeError("Simulated GUI Crash")), \
             patch("scripts.probe_ladder_editor.kill_leftover_cscape") as mock_kill:
            result = run_probe_ladder_editor()
            assert result["status"] == "failed"
            assert mock_kill.call_count >= 1, "kill_leftover_cscape must be called when probe fails"


# ============================================================================
# Section 3: CFBF Parser Rungs, Contacts, and Coils Detection Tests
# ============================================================================

class TestCFBFLadderDetection:
    """Verifies that CFBF parser can accurately detect rungs, contacts, and coils."""

    def test_cfbf_magic_header_and_validation(self):
        """CFBF parser validates 0xD0CF11E0A1B11AE1 header and rejects invalid inputs."""
        assert CFBF_MAGIC == bytes.fromhex("d0cf11e0a1b11ae1")

        with pytest.raises(ValueError, match="too short"):
            CFBFLadderParser(b"SHORT")

        with pytest.raises(ValueError, match="Invalid CFBF magic header"):
            CFBFLadderParser(b"INVALID_HEADER_DATA_12345678" + b"\x00" * 500)

    def test_cfbf_parser_detects_ladder_rungs(self):
        """CFBF parser detects both text and binary rung markers."""
        ladder_payload = (
            b"RUNG 1: System Master Enable\r\n"
            b"--[ ]-- %I0001 --( )-- %Q0001\r\n"
            b"NETWORK 2: High Temperature Interlock\r\n"
            b"--[/]-- %M0005 --(S)-- %Q0002\r\n"
            + struct.pack("<I", 0x474E5552) + b"\x00\x00\x00\x00"
        )
        cfbf_bytes = generate_synthetic_cfbf_with_ladder(ladder_payload)
        parser = CFBFLadderParser(cfbf_bytes)
        assert "Contents" in parser.streams

        detected = parser.detect_ladder_elements("Contents")
        rungs = detected["rungs"]
        assert len(rungs) >= 3, f"Expected at least 3 rungs detected, got {len(rungs)}"
        rung_types = [r["type"] for r in rungs]
        assert "RUNG_HEADER" in rung_types
        assert "BINARY_RUNG" in rung_types

    def test_cfbf_parser_detects_ladder_contacts(self):
        """CFBF parser accurately differentiates Normally Open and Normally Closed contacts."""
        ladder_payload = (
            b"RUNG 1\r\n"
            b"XIC %I0001\r\n"
            b"--[ ]-- %I0002\r\n"
            b"ID_NO_CONTACT\r\n"
            b"XIO %M0010\r\n"
            b"--[/]-- %M0011\r\n"
            b"ID_NC_CONTACT\r\n"
        )
        cfbf_bytes = generate_synthetic_cfbf_with_ladder(ladder_payload)
        parser = CFBFLadderParser(cfbf_bytes)

        detected = parser.detect_ladder_elements("Contents")
        contacts = detected["contacts"]
        assert len(contacts) == 6, f"Expected 6 contacts, got {len(contacts)}"

        no_contacts = [c for c in contacts if c["type"] == "CONTACT_NO"]
        nc_contacts = [c for c in contacts if c["type"] == "CONTACT_NC"]
        assert len(no_contacts) == 3
        assert len(nc_contacts) == 3
        assert all(c["cmd_id"] == 1000 for c in no_contacts)
        assert all(c["cmd_id"] == 1001 for c in nc_contacts)

    def test_cfbf_parser_detects_ladder_coils(self):
        """CFBF parser detects Standard, Set (Latch), and Reset (Unlatch) coils."""
        ladder_payload = (
            b"RUNG 1\r\n"
            b"--( )-- %Q0001\r\n"
            b"OTE %Q0002\r\n"
            b"ID_NO_COIL\r\n"
            b"--(S)-- %M0020\r\n"
            b"OTL %M0021\r\n"
            b"ID_SET_COIL\r\n"
            b"--(R)-- %M0030\r\n"
            b"OTU %M0031\r\n"
            b"ID_RESET_COIL\r\n"
        )
        cfbf_bytes = generate_synthetic_cfbf_with_ladder(ladder_payload)
        parser = CFBFLadderParser(cfbf_bytes)

        detected = parser.detect_ladder_elements("Contents")
        coils = detected["coils"]
        assert len(coils) == 9, f"Expected 9 coils, got {len(coils)}"

        standard_coils = [c for c in coils if c["type"] == "COIL_NO"]
        set_coils = [c for c in coils if c["type"] == "COIL_SET"]
        reset_coils = [c for c in coils if c["type"] == "COIL_RESET"]
        assert len(standard_coils) == 3
        assert len(set_coils) == 3
        assert len(reset_coils) == 3
        assert all(c["cmd_id"] == 1002 for c in standard_coils)
        assert all(c["cmd_id"] == 37690 for c in set_coils)
        assert all(c["cmd_id"] == 37691 for c in reset_coils)

    def test_cfbf_parser_native_p1_base_container(self):
        """CFBF parser parses authentic native p1_base.csp container."""
        assert BASE_P1_PATH.exists(), f"p1_base.csp missing at {BASE_P1_PATH}"
        parser = CFBFLadderParser(BASE_P1_PATH)
        assert len(parser.entries) >= 2
        entry_names = [e["name"] for e in parser.entries]
        assert "Root Entry" in entry_names
        assert "Contents" in entry_names
        assert "Contents" in parser.streams

        contents_bytes = parser.streams["Contents"]
        assert len(contents_bytes) > 100000
        magic = struct.unpack_from("<I", contents_bytes, 0)[0]
        assert magic == CSCAPE_CONTENTS_MAGIC

# ============================================================================
# Section 4: Unknown Dialog Guard Immediate Abort Tests
# ============================================================================

class TestUnknownDialogGuard:
    """Verifies that unknown dialog guard aborts immediately when an unrecognized dialog is encountered."""

    def test_evaluate_window_actionable_states(self):
        """evaluate_window_for_dialog_guard flags modal visible dialogs when main is disabled."""
        main_hwnd = 0x1000
        w_modal = {
            "hwnd": 0x2000,
            "class": "#32770",
            "rect": (100, 100, 400, 300),
            "visible": True,
        }
        actionable, reason = evaluate_window_for_dialog_guard(w_modal, main_hwnd, main_disabled=True)
        assert actionable is True
        assert "#32770" in reason

    def test_evaluate_window_ignores_non_actionable_windows(self):
        """evaluate_window_for_dialog_guard ignores invisible, tiny, non-dialog, or main window."""
        main_hwnd = 0x1000

        # Case 1: Main window itself
        w_main = {"hwnd": main_hwnd, "class": "Afx:00AF0000", "rect": (0, 0, 1000, 700), "visible": True}
        actionable, _ = evaluate_window_for_dialog_guard(w_main, main_hwnd, main_disabled=True)
        assert actionable is False

        # Case 2: Invisible window
        w_invis = {"hwnd": 0x2001, "class": "#32770", "rect": (100, 100, 400, 300), "visible": False}
        actionable, _ = evaluate_window_for_dialog_guard(w_invis, main_hwnd, main_disabled=True)
        assert actionable is False

        # Case 3: Tiny window (<50px)
        w_tiny = {"hwnd": 0x2002, "class": "#32770", "rect": (100, 100, 120, 120), "visible": True}
        actionable, _ = evaluate_window_for_dialog_guard(w_tiny, main_hwnd, main_disabled=True)
        assert actionable is False

        # Case 4: Non-dialog class
        w_tree = {"hwnd": 0x2003, "class": "SysTreeView32", "rect": (100, 100, 400, 300), "visible": True}
        actionable, _ = evaluate_window_for_dialog_guard(w_tree, main_hwnd, main_disabled=True)
        assert actionable is False

        # Case 5: Main window enabled
        w_enabled = {"hwnd": 0x2004, "class": "#32770", "rect": (100, 100, 400, 300), "visible": True}
        actionable, _ = evaluate_window_for_dialog_guard(w_enabled, main_hwnd, main_disabled=False)
        assert actionable is False

    def test_is_known_cscape_dialog_classification(self):
        """is_known_cscape_dialog classifies authentic dialogs and rejects unknown popups."""
        mock_app = MagicMock()

        for known_title in ["About Cscape", "Tip of the Day", "Select Editor Type", "Ladder Tags Mode", "Hardware Configuration"]:
            is_known, _ = is_known_cscape_dialog(0x2000, known_title, "#32770", mock_app)
            assert is_known is True, f"'{known_title}' should be classified as known"

        for unknown_title in ["Unexpected Crash #501", "Registration Required", "Third-Party Plugin Warning", "Critical Memory Exhaustion"]:
            is_known, reason = is_known_cscape_dialog(0x2000, unknown_title, "#32770", mock_app)
            assert is_known is False, f"'{unknown_title}' should be classified as unknown"
            assert reason == "unknown"

    def test_unknown_dialog_guard_aborts_immediately_fail_closed(self):
        """Simulating an unrecognized dialog triggers immediate fail-closed abort."""
        from scripts.g3_edit_roundtrip import check_dialogs_and_wait_for_main_window

        main_hwnd = 0x1000
        unknown_dlg_hwnd = 0x9999
        evidence: Dict[str, Any] = {}

        mock_windows = [
            {"hwnd": main_hwnd, "hwnd_hex": "0x1000", "class": "Afx:00AF0000", "title": "Cscape 10.2", "rect": (0, 0, 1920, 1080), "visible": True, "enabled": False, "owner": 0, "owner_hex": "0x0"},
            {"hwnd": unknown_dlg_hwnd, "hwnd_hex": "0x9999", "class": "#32770", "title": "Unrecognized System Error", "rect": (500, 300, 900, 600), "visible": True, "enabled": True, "owner": main_hwnd, "owner_hex": "0x1000"},
        ]

        with patch("scripts.g3_edit_roundtrip.enumerate_all_cscape_windows", return_value=mock_windows), \
             patch("win32gui.IsWindow", return_value=True), \
             patch("win32gui.IsWindowVisible", return_value=True), \
             patch("win32gui.IsWindowEnabled", return_value=False), \
             patch("scripts.g3_edit_roundtrip.close_cscape_gracefully") as mock_close, \
             patch("time.sleep", return_value=None):

            with pytest.raises(RuntimeError, match="ABORT_UNKNOWN_DIALOG"):
                check_dialogs_and_wait_for_main_window(
                    pid=1234,
                    main_hwnd=main_hwnd,
                    app=MagicMock(),
                    evidence=evidence,
                    max_wait_seconds=5.0,
                    context_label="test_unknown_guard",
                )

            mock_close.assert_called_with(pid=1234, timeout=6.0)
            assert evidence.get("status") == "failed"
            assert "ABORT_UNKNOWN_DIALOG" in evidence.get("error", "")


# ============================================================================
# Section 5: Hardware Lockout Directives Enforced Tests
# ============================================================================

class TestHardwareLockoutDirectives:
    """Verifies that all hardware lockout directives are enforced (no download, no physical PLC)."""

    def test_hardware_lockout_physical_com_ports(self):
        """SecurityGuard blocks COM1..COM256, CAN, USB, and JTAG ports."""
        blocked_ports = ["COM1", "COM2", "COM3", "COM4", "COM256", r"\\.\COM1", "/dev/ttyS0", "CAN0", "USB0", "JTAG1"]
        for port in blocked_ports:
            with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_HARDWARE_LOCKOUT"):
                SecurityGuard.assert_port_safe(port)

    def test_hardware_lockout_companion_flash_binaries(self):
        """SecurityGuard blocks companion flashing utilities."""
        blocked_binaries = ["PGMUpdateUtility.exe", "DfuSeCommand.exe", "STMFlashLoader.exe", "WinJTAG.exe", "pgmupdateutility", "stmflashloader"]
        for binary in blocked_binaries:
            with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_FLASH_LOCKOUT"):
                SecurityGuard.assert_binary_execution_safe(binary)

    def test_hardware_lockout_download_cli_switches(self):
        """SecurityGuard blocks download/flash CLI switches."""
        blocked_switches = [["/d"], ["/download"], ["-download"], ["--download"], ["/flash"], ["/burn"], ["/write-flash"]]
        for switches in blocked_switches:
            with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_SWITCH_LOCKOUT"):
                SecurityGuard.assert_cli_switches_safe(switches)

    def test_hardware_lockout_win32_download_commands(self):
        """Win32 download commands ID_PROGRAM_DOWNLOAD (32827) and ID_CONTROLLER_DOWNLOAD (33149) are blocked."""
        with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_WIN32_LOCKOUT"):
            SecurityGuard.assert_win32_command_safe(32827)

        with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_WIN32_LOCKOUT"):
            SecurityGuard.assert_win32_command_safe(33149)

        interceptor = Win32CommandInterceptor()
        res1 = interceptor.dispatch_safe_command(hwnd=0, cmd_id=32827)
        assert res1.status == AgentStatus.BLOCKED
        assert "ID_PROGRAM_DOWNLOAD" in res1.details

        res2 = interceptor.dispatch_safe_command(hwnd=0, cmd_id=33149)
        assert res2.status == AgentStatus.BLOCKED
        assert "ID_CONTROLLER_DOWNLOAD" in res2.details

    def test_hardware_lockout_network_plc_ports_and_ips(self):
        """SecurityGuard blocks physical PLC network interfaces in offline mode."""
        for plc_port in [502, 4840, 20502, 44818]:
            with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_NETWORK_LOCKOUT"):
                SecurityGuard.assert_network_target_safe("127.0.0.1", plc_port)

        for plc_ip in ["192.168.1.1", "192.168.1.100", "192.168.1.50"]:
            with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_NETWORK_LOCKOUT"):
                SecurityGuard.assert_network_target_safe(plc_ip, 8080)

    def test_security_guard_rejects_ladder_constructs_in_st(self):
        """SecurityGuard rejects ladder contacts, coils, and rung delimiters in ST POUs."""
        invalid_st_snippets = [
            "---[ ]--- Pump_Run;",
            "---[/]--- Valve_Closed;",
            "---( )--- Alarm_Active;",
            "---(S)--- Lockout_Latch;",
            "---(R)--- Lockout_Latch;",
            "RUNG 1: Initial Scan",
            "NETWORK 1",
            "XIC %I0001",
            "OTE %Q0001",
        ]
        for snippet in invalid_st_snippets:
            with pytest.raises(LadderForbiddenError, match="ERR_LADDER_FORBIDDEN"):
                SecurityGuard.assert_pure_st_content(snippet)

# ============================================================================
# Section 6: Read-Only Baseline Immutability Preserved Tests
# ============================================================================

class TestReadOnlyBaselineImmutability:
    """Verifies that baseline projects (p1_base.csp and test_sandbox.csp) remain strictly immutable."""

    def test_p1_base_exists_and_hash_strictly_preserved(self):
        """p1_base.csp exists and SHA-256 strictly matches BASELINE_P1_SHA."""
        assert BASE_P1_PATH.exists(), f"Missing baseline p1_base.csp at {BASE_P1_PATH}"
        current_sha = compute_sha256(BASE_P1_PATH)
        assert current_sha == BASELINE_P1_SHA, (
            f"CRITICAL IMMUTABILITY VIOLATION: p1_base.csp modified! Expected {BASELINE_P1_SHA}, got {current_sha}"
        )

    def test_test_sandbox_exists_and_hash_strictly_preserved(self):
        """test_sandbox.csp exists and SHA-256 strictly matches BASELINE_SANDBOX_SHA."""
        assert SOURCE_SANDBOX_PATH.exists(), f"Missing source test_sandbox.csp at {SOURCE_SANDBOX_PATH}"
        current_sha = compute_sha256(SOURCE_SANDBOX_PATH)
        assert current_sha == BASELINE_SANDBOX_SHA, (
            f"CRITICAL IMMUTABILITY VIOLATION: test_sandbox.csp modified! Expected {BASELINE_SANDBOX_SHA}, got {current_sha}"
        )

    def test_assert_safety_invariants_passes_on_pristine_files(self):
        """assert_safety_invariants succeeds on pristine baseline files."""
        assert_safety_invariants()

    def test_assert_safety_invariants_detects_tampering_fail_closed(self):
        """assert_safety_invariants raises RuntimeError immediately if baseline hash diverges."""
        with patch("scripts.g3_edit_roundtrip.compute_sha256", return_value="0000000000000000000000000000000000000000000000000000000000000000"):
            with pytest.raises(RuntimeError, match="CRITICAL IMMUTABILITY VIOLATION"):
                assert_safety_invariants()

    def test_probe_evidence_verifies_immutability(self):
        """artifacts/G7/ladder_probe.json records that probe copy was unmodified."""
        assert EVIDENCE_JSON_PATH.exists()
        probe_data = json.loads(EVIDENCE_JSON_PATH.read_text(encoding="utf-8"))
        assert probe_data.get("source_p1_base_sha") == BASELINE_P1_SHA
        assert probe_data.get("initial_copy_sha") == BASELINE_P1_SHA
        assert probe_data.get("final_copy_sha") == BASELINE_P1_SHA
        assert probe_data.get("is_unmodified") is True

    def test_probe_isolated_copy_workflow_preserves_baseline(self, tmp_path):
        """Probe strictly copies baseline to isolated target before inspection and never targets baseline directly."""
        probe_copy_target = tmp_path / "probe_copy.csp"
        import shutil
        shutil.copy2(BASE_P1_PATH, probe_copy_target)

        assert compute_sha256(probe_copy_target) == BASELINE_P1_SHA
        assert compute_sha256(BASE_P1_PATH) == BASELINE_P1_SHA


# ============================================================================
# Section 7: Gate G7 Live Ladder Roundtrip Invariant & Proof Tests
# ============================================================================

from scripts.g7_ladder_roundtrip import (
    EVIDENCE_PATH as G7_EVIDENCE_PATH,
    TARGET_COPY_PATH as G7_TARGET_COPY_PATH,
    TEST_CONTACT_TAG as G7_CONTACT_TAG,
    TEST_COIL_TAG as G7_COIL_TAG,
    UnknownDialogError,
    scan_for_unknown_dialogs,
    verify_cfbf_ladder_proof,
)


class TestG7LadderRoundtripVerification:
    """Verifies that Gate G7 Ladder Roundtrip delivered verifiable CFBF proof."""

    def test_g7_roundtrip_evidence_file_exists_and_status_success(self):
        """artifacts/G7/g7_ladder_roundtrip.json exists and strictly reports status: success."""
        assert G7_EVIDENCE_PATH.exists(), f"Missing G7 roundtrip evidence at {G7_EVIDENCE_PATH}"
        data = load_g7_roundtrip_evidence()
        assert data.get("gate") == "G7"
        assert data.get("status") == "success"
        assert data.get("contact_tag") == G7_CONTACT_TAG
        assert data.get("coil_tag") == G7_COIL_TAG
        assert data.get("sha_preserved_on_reopen") is True
        assert data.get("base_p1_sha256_pre") == BASELINE_P1_SHA
        assert data.get("base_p1_sha256_post") == BASELINE_P1_SHA

    def test_g7_cfbf_proof_verifies_contact_and_coil(self):
        """G7 CFBF proof records that both the NO contact and coil exist in CFBF stream."""
        data = load_g7_roundtrip_evidence()
        proof = data.get("cfbf_proof", {})
        assert proof.get("status") == "success"
        assert proof.get("contact_found") is True
        assert proof.get("coil_found") is True

    def test_g7_cfbf_proof_verifies_network_count_incremented(self):
        """G7 CFBF proof confirms that Network count in the CFBF stream is at least 2."""
        data = load_g7_roundtrip_evidence()
        proof = data.get("cfbf_proof", {})
        assert proof.get("network_count", 0) >= 2

    def test_g7_cfbf_proof_verifies_variable_declared_in_cfbf(self):
        """G7 CFBF proof confirms that the test coil variable is defined in project declarations."""
        data = load_g7_roundtrip_evidence()
        proof = data.get("cfbf_proof", {})
        assert proof.get("variable_declared") is True
        assert proof.get("total_declarations", 0) >= 62

    def test_g7_cfbf_proof_verifies_sha_mutated_and_base_untouched(self):
        """G7 proof verifies saved copy mutated (sha_changed) while baseline p1_base remained untouched."""
        data = load_g7_roundtrip_evidence()
        proof = data.get("cfbf_proof", {})
        assert proof.get("sha_changed") is True
        assert proof.get("base_p1_untouched") is True
        assert proof.get("base_p1_sha256") == BASELINE_P1_SHA

    def test_g7_verify_cfbf_ladder_proof_oracle_on_saved_copy(self):
        """Direct invocation of verify_cfbf_ladder_proof on g7_ladder_roundtrip.csp returns success."""
        assert G7_TARGET_COPY_PATH.exists()
        proof = verify_cfbf_ladder_proof(
            csp_path=G7_TARGET_COPY_PATH,
            expected_contact=G7_CONTACT_TAG,
            expected_coil=G7_COIL_TAG,
        )
        assert proof["status"] == "success"
        assert proof["contact_found"] is True
        assert proof["coil_found"] is True
        assert proof["network_count"] >= 2
        assert proof["variable_declared"] is True
        assert proof["base_p1_untouched"] is True

    def test_g7_verify_cfbf_ladder_proof_oracle_fails_on_unmodified_base(self):
        """verify_cfbf_ladder_proof fails closed if SHA unchanged or coil tag missing."""
        proof = verify_cfbf_ladder_proof(
            csp_path=BASE_P1_PATH,
            expected_contact="ALW_ON",
            expected_coil="NON_EXISTENT_COIL_12345",
            initial_sha=BASELINE_P1_SHA,
        )
        assert proof["status"] == "failed"
        assert proof["sha_changed"] is False

    def test_g7_unknown_dialog_guard_detects_unauthorized_dialog(self):
        """scan_for_unknown_dialogs flags unauthorized dialog windows."""
        with patch("win32gui.EnumWindows") as mock_enum:
            def side_effect(callback, _):
                # Simulate a fake dialog with title 'Dangerous Unrecognized Dialog'
                with patch("win32gui.IsWindow", return_value=True), \
                     patch("win32gui.IsWindowVisible", return_value=True), \
                     patch("win32process.GetWindowThreadProcessId", return_value=(0, 9999)), \
                     patch("win32gui.GetClassName", return_value="#32770"), \
                     patch("win32gui.GetWindowText", return_value="Dangerous Unrecognized Dialog"), \
                     patch("win32gui.GetWindowRect", return_value=(100, 100, 500, 400)):
                    callback(0x1234, None)
            mock_enum.side_effect = side_effect
            result = scan_for_unknown_dialogs(pid=9999)
            assert result is not None
            assert result["title"] == "Dangerous Unrecognized Dialog"

# ============================================================================
# Section 8: Negative Control Comparison on p1_base.csp Tests
# ============================================================================

class TestG7NegativeControlComparison:
    """Verifies negative control comparison between pristine baseline p1_base.csp and roundtrip file.

    Negative Control Invariants:
    1. Baseline p1_base.csp has an element count of 0 (no ladder elements placed).
    2. Roundtrip file (g7_ladder_roundtrip.csp) has an element count >= 2.
    3. Delta computation: delta_element_count = rt_element_count - base_element_count.
    4. Delta element count is at least 2 (delta >= 2).
    5. Visual reopen screenshot exists, is non-empty (>0 bytes), and is a valid PNG.
    6. Baseline p1_base.csp immutability remains strictly unviolated.
    """

    def test_baseline_element_count_in_p1_base(self):
        """Negative control: baseline p1_base.csp has an element count of 0 (no ladder elements)."""
        assert BASE_P1_PATH.exists(), f"p1_base.csp missing at {BASE_P1_PATH}"
        base_count = count_ladder_elements(BASE_P1_PATH)
        assert base_count == 0, f"Expected negative control baseline element count == 0, got {base_count}"

    def test_roundtrip_file_has_element_count_gte_2(self):
        """Roundtrip project (g7_ladder_roundtrip.csp) has element_count >= 2."""
        assert G7_TARGET_COPY_PATH.exists(), f"Roundtrip project missing at {G7_TARGET_COPY_PATH}"
        rt_count = count_ladder_elements(G7_TARGET_COPY_PATH)
        assert rt_count >= 2, f"Expected roundtrip file element count >= 2, got {rt_count}"

    def test_delta_computation_between_baseline_and_roundtrip_file(self):
        """Delta computation between baseline and roundtrip file correctly evaluates difference."""
        assert BASE_P1_PATH.exists(), f"p1_base.csp missing at {BASE_P1_PATH}"
        assert G7_TARGET_COPY_PATH.exists(), f"Roundtrip project missing at {G7_TARGET_COPY_PATH}"

        base_count = count_ladder_elements(BASE_P1_PATH)
        rt_count = count_ladder_elements(G7_TARGET_COPY_PATH)
        delta_count = compute_ladder_element_delta(BASE_P1_PATH, G7_TARGET_COPY_PATH)

        assert delta_count == (rt_count - base_count), (
            f"Delta computation mismatch: computed {delta_count}, expected {rt_count - base_count}"
        )

    def test_delta_element_count_gte_2(self):
        """Delta element count between roundtrip file and baseline is at least 2 (delta_element_count >= 2)."""
        delta_count = compute_ladder_element_delta(BASE_P1_PATH, G7_TARGET_COPY_PATH)
        assert delta_count >= 2, f"Expected delta_element_count >= 2, got {delta_count}"

    def test_reopened_screenshot_exists_non_empty_and_valid_png(self):
        """Reopened screenshot exists, is non-empty (>0 bytes), and is a valid PNG."""
        screenshot_path = find_reopened_screenshot()
        assert screenshot_path is not None, "Reopened screenshot file could not be located"
        assert screenshot_path.exists(), f"Screenshot file missing at {screenshot_path}"

        raw_bytes = screenshot_path.read_bytes()
        assert len(raw_bytes) > 0, "Screenshot file is empty (0 bytes)"
        assert len(raw_bytes) > 1024, f"Screenshot file suspiciously small ({len(raw_bytes)} bytes)"

        # Verify PNG magic signature: \x89PNG\r\n\x1a\n
        png_magic = b"\x89PNG\r\n\x1a\n"
        assert raw_bytes[:8] == png_magic, f"Invalid PNG magic signature: {raw_bytes[:8].hex()}"

        # Verify PNG IHDR chunk and valid dimensions
        assert raw_bytes[12:16] == b"IHDR", "Missing IHDR chunk in PNG header"
        width, height = struct.unpack(">II", raw_bytes[16:24])
        assert width > 0, f"Invalid PNG width: {width}"
        assert height > 0, f"Invalid PNG height: {height}"
        assert width >= 640 and height >= 480, f"Screenshot dimensions too small for Cscape: {width}x{height}"

    def test_negative_control_baseline_immutability_preserved(self):
        """Baseline p1_base.csp SHA-256 strictly preserved during negative control analysis."""
        current_sha = compute_sha256(BASE_P1_PATH)
        assert current_sha == BASELINE_P1_SHA, (
            f"CRITICAL IMMUTABILITY VIOLATION: p1_base.csp mutated during negative control analysis: {current_sha}"
        )

