r"""Gate G3 Diagnostic Probe: IEC Variables Editor Deep Window & Control Forensics.

USER EXECUTION DIRECTIVE:
Run this script from a normal interactive PowerShell terminal on the visible desktop:
    cd C:\HornerAI\jev-cscape-agent
    python scripts/probe_iec_editor.py

FUNCTIONALITY & VERIFICATION:
1. Asserts fail-closed hardware lockout and source file immutability (p1_base.csp, test_sandbox.csp).
2. Copies work/disposable/p1_base.csp to fresh copy work/disposable/copies/probe_iec_editor.csp.
3. Kills any leftover Cscape processes and configures registry for clean startup.
4. Launches Cscape 10.2 targeting probe_iec_editor.csp on the visible desktop (winsta0\Default).
5. Handles all startup dialogs and waits until main window is enabled.
6. Opens Program Variables pane (verifying SysTreeView32 inside W5EditTL).
7. Re-locates Global Variables row, selects it, right-clicks, and opens 'Edit Variables as Text'.
8. Pauses to allow the IEC Variables Editor tab and all child views to fully initialize.
9. Locates active MDI editor child window and MDIClient container.
10. Dumps every child window under the IEC editor:
    - HWND (int and hex)
    - Parent HWND
    - Window Class Name
    - Control ID (GetDlgCtrlID)
    - Screen Bounding Rect (left, top, right, bottom, width, height)
    - Visibility and Enabled states
    - WM_GETTEXTLENGTH
11. Probes each child window using 4 text extraction techniques (NO KEYSTROKES):
    - Method A: WM_GETTEXT (standard Win32 Unicode & ANSI messages)
    - Method B: Scintilla SCI_GETTEXT (direct + cross-process WoW64 VirtualAllocEx buffer)
    - Method C: RichEdit EM_STREAMOUT / EM_GETTEXTEX / EM_GETTEXTRANGE (cross-process WoW64)
    - Method D: UIAutomation (UIA) TextPattern, ValuePattern, and window_text
    Logs extracted text length and first 200 characters for each method.
12. Inspects IEC / XML / CSV Sub-Tabs:
    - Win32 SysTabControl32 inspection via TCM_GETITEMCOUNT, TCM_GETCURSEL, and TCM_GETITEMW (WoW64)
    - UIA Tab and TabItem accessibility inspection (names, selection states, bounding rects)
13. Captures screenshots: full window and cropped IEC editor tab.
14. Exports complete structured forensics to artifacts/G3/iec_editor_probe.json and artifacts/logs/probe_iec_editor.log.
15. Closes active editor tab and Cscape gracefully WITHOUT SAVING (answers 'No' to any prompt).
16. Enforces read-only execution: asserts copy SHA-256 unchanged and base projects untouched.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil
import win32con
import win32gui
import win32process
from PIL import Image, ImageGrab
import pywinauto
from pywinauto import Application, mouse
from pywinauto.win32structures import RECT

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.contracts import AgentStatus
from jev_cscape.security.command_interceptor import Win32CommandInterceptor
from jev_cscape.security.guard import SecurityGuard

# Re-use proven navigation & lifecycle functions from g3_edit_roundtrip
from scripts.g3_edit_roundtrip import (
    assert_safety_invariants,
    close_active_editor_tab,
    close_cscape_gracefully,
    compute_sha256,
    configure_cscape_registry,
    dismiss_popup_menu,
    find_program_variables_treeview,
    handle_startup_dialogs_and_wait_for_main_window,
    inspect_context_menu_items,
    kill_leftover_cscape,
    launch_cscape_with_project,
    open_program_variables_pane,
    relocate_global_variables_row,
    wait_until_no_dialogs_and_main_ready,
    BASE_P1_PATH,
    BASELINE_P1_SHA,
    BASELINE_SANDBOX_SHA,
    COPIES_DIR,
    SOURCE_SANDBOX_PATH,
)

# Setup logging
LOG_DIR = REPO_ROOT / "artifacts" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
G3_DIR = REPO_ROOT / "artifacts" / "G3"
G3_DIR.mkdir(parents=True, exist_ok=True)

PROBE_COPY_PATH = COPIES_DIR / "probe_iec_editor.csp"
EVIDENCE_JSON_PATH = G3_DIR / "iec_editor_probe.json"
FULL_SCREENSHOT_PATH = G3_DIR / "probe_iec_editor_full.png"
TAB_SCREENSHOT_PATH = G3_DIR / "probe_iec_editor_tab.png"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "probe_iec_editor.log", mode="w", encoding="utf-8"),
    ],
)
logger = logging.getLogger("probe_iec_editor")

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# Process VM access rights
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04

# Tab Control Messages
TCM_FIRST = 0x1300
TCM_GETITEMCOUNT = TCM_FIRST + 4   # 0x1304
TCM_GETITEMA = TCM_FIRST + 5       # 0x1305
TCM_GETITEMRECT = TCM_FIRST + 10   # 0x130A
TCM_GETCURSEL = TCM_FIRST + 11     # 0x130B
TCM_GETITEMW = TCM_FIRST + 60      # 0x133C
TCIF_TEXT = 0x0001

# Scintilla Messages
SCI_GETLENGTH = 2006
SCI_GETTEXT = 2182
SCI_GETTEXTLENGTH = 2183

# RichEdit Messages
EM_GETSELTEXT = 1086
EM_STREAMOUT = 1097
EM_GETTEXTRANGE = 1099
EM_GETTEXTEX = 1118
SF_TEXT = 1
SF_RTF = 2
SF_UNICODE = 16


# 32-bit Win32 structures for WoW64 cross-process memory interaction
class TCITEMW32(ctypes.Structure):
    """32-bit TCITEMW layout for Tab Control communication in WoW64."""
    _pack_ = 1
    _fields_ = [
        ("mask", ctypes.c_uint32),
        ("dwState", ctypes.c_uint32),
        ("dwStateMask", ctypes.c_uint32),
        ("pszText", ctypes.c_uint32),
        ("cchTextMax", ctypes.c_int32),
        ("iImage", ctypes.c_int32),
        ("lParam", ctypes.c_int32),
    ]


class CHARRANGE32(ctypes.Structure):
    """32-bit CHARRANGE layout for RichEdit."""
    _pack_ = 1
    _fields_ = [
        ("cpMin", ctypes.c_int32),
        ("cpMax", ctypes.c_int32),
    ]


class TEXTRANGEW32(ctypes.Structure):
    """32-bit TEXTRANGEW layout for EM_GETTEXTRANGE."""
    _pack_ = 1
    _fields_ = [
        ("chrg", CHARRANGE32),
        ("lpstrText", ctypes.c_uint32),
    ]


class GETTEXTEX32(ctypes.Structure):
    """32-bit GETTEXTEX layout for EM_GETTEXTEX."""
    _pack_ = 1
    _fields_ = [
        ("cb", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("codepage", ctypes.c_uint32),
        ("lpDefaultChar", ctypes.c_uint32),
        ("lpUsedDefChar", ctypes.c_uint32),
    ]


class RECT32(ctypes.Structure):
    """32-bit RECT layout for Win32 API calls."""
    _pack_ = 1
    _fields_ = [
        ("left", ctypes.c_int32),
        ("top", ctypes.c_int32),
        ("right", ctypes.c_int32),
        ("bottom", ctypes.c_int32),
    ]


def sanitize_snippet(text: str, max_chars: int = 200) -> str:
    """Format and truncate text snippet for readable logging and JSON export."""
    if not text:
        return ""
    clean = text.replace("\r", " ").replace("\n", " ").strip()
    clean = re.sub(r"\s+", " ", clean)
    if len(clean) > max_chars:
        return clean[:max_chars] + "..."
    return clean


def capture_window_screenshot(hwnd: int, out_path: Path) -> Optional[str]:
    """Capture screenshot of a window handle or full desktop."""
    try:
        img = None
        if hwnd and win32gui.IsWindow(hwnd):
            rect = win32gui.GetWindowRect(hwnd)
            w = rect[2] - rect[0]
            h = rect[3] - rect[1]
            if w > 10 and h > 10:
                img = ImageGrab.grab(bbox=rect)
        if img is None:
            img = ImageGrab.grab()
        img.save(str(out_path))
        logger.info(f"Screenshot saved: {out_path}")
        return str(out_path)
    except Exception as e:
        logger.warning(f"Could not capture screenshot for {out_path.name}: {e}")
        return None


def find_mdi_containers(main_hwnd: int) -> Tuple[Optional[int], Optional[int], List[int]]:
    """Locate MDIClient, active MDI child window, and all child windows of MDIClient."""
    mdi_client_hwnd = None
    mdi_children: List[int] = []

    def enum_mdi_client(h: int, _: Any) -> bool:
        nonlocal mdi_client_hwnd
        try:
            cls = win32gui.GetClassName(h).lower()
            if "mdiclient" in cls:
                mdi_client_hwnd = h
                return False
        except Exception:
            pass
        return True

    try:
        win32gui.EnumChildWindows(main_hwnd, enum_mdi_client, None)
    except Exception:
        pass

    active_mdi_hwnd = None
    if mdi_client_hwnd and win32gui.IsWindow(mdi_client_hwnd):
        try:
            active_mdi_hwnd = user32.SendMessageW(mdi_client_hwnd, 0x0229, 0, 0)  # WM_MDIGETACTIVE
        except Exception:
            active_mdi_hwnd = None

        def enum_mdi_child(h: int, _: Any) -> bool:
            try:
                parent = win32gui.GetParent(h)
                if parent == mdi_client_hwnd:
                    mdi_children.append(h)
            except Exception:
                pass
            return True

        try:
            win32gui.EnumChildWindows(mdi_client_hwnd, enum_mdi_child, None)
        except Exception:
            pass

    return mdi_client_hwnd, active_mdi_hwnd, mdi_children


def dump_child_windows_hierarchy(root_hwnd: int) -> List[Dict[str, Any]]:
    """Recursively enumerate all child windows under root_hwnd, capturing deep metadata."""
    records: List[Dict[str, Any]] = []

    def enum_cb(h: int, _: Any) -> bool:
        try:
            if not win32gui.IsWindow(h):
                return True
            cls_name = win32gui.GetClassName(h)
            parent = win32gui.GetParent(h)
            ctrl_id = user32.GetDlgCtrlID(h)
            rect = win32gui.GetWindowRect(h)
            visible = bool(win32gui.IsWindowVisible(h))
            enabled = bool(win32gui.IsWindowEnabled(h))
            text_len = user32.SendMessageW(h, win32con.WM_GETTEXTLENGTH, 0, 0)

            rec = {
                "hwnd": h,
                "hwnd_hex": hex(h),
                "parent_hwnd": parent,
                "parent_hwnd_hex": hex(parent) if parent else "0x0",
                "class_name": cls_name,
                "control_id": ctrl_id,
                "rect": list(rect),
                "width": rect[2] - rect[0],
                "height": rect[3] - rect[1],
                "visible": visible,
                "enabled": enabled,
                "wm_gettextlength": int(text_len),
            }
            records.append(rec)
        except Exception as e:
            logger.warning(f"Error inspecting child window {hex(h)}: {e}")
        return True

    try:
        win32gui.EnumChildWindows(root_hwnd, enum_cb, None)
    except Exception as e:
        logger.warning(f"Error enumerating child windows for root {hex(root_hwnd)}: {e}")

    return records


# =========================================================================
# 4 Method Text Extraction Forensic Probes (ZERO KEYSTROKES)
# =========================================================================

def probe_wm_gettext(hwnd: int) -> Dict[str, Any]:
    """Method A: Read text via standard Win32 WM_GETTEXT (Unicode and ANSI)."""
    result: Dict[str, Any] = {
        "success": False,
        "length": 0,
        "first_200_chars": "",
        "encoding": None,
    }
    try:
        # Unicode attempt
        length_w = user32.SendMessageW(hwnd, win32con.WM_GETTEXTLENGTH, 0, 0)
        buf_size_w = max(length_w + 1024, 65536)
        buf_w = ctypes.create_unicode_buffer(buf_size_w)
        res_w = user32.SendMessageW(hwnd, win32con.WM_GETTEXT, buf_size_w, buf_w)
        if res_w > 0 and buf_w.value:
            txt = buf_w.value
            result["success"] = True
            result["length"] = len(txt)
            result["first_200_chars"] = sanitize_snippet(txt, 200)
            result["encoding"] = "Unicode (WM_GETTEXTW)"
            return result

        # ANSI fallback
        length_a = user32.SendMessageA(hwnd, win32con.WM_GETTEXTLENGTH, 0, 0)
        buf_size_a = max(length_a + 1024, 65536)
        buf_a = ctypes.create_string_buffer(buf_size_a)
        res_a = user32.SendMessageA(hwnd, win32con.WM_GETTEXT, buf_size_a, buf_a)
        if res_a > 0 and buf_a.value:
            txt_a = buf_a.value.decode("latin1", errors="replace")
            result["success"] = True
            result["length"] = len(txt_a)
            result["first_200_chars"] = sanitize_snippet(txt_a, 200)
            result["encoding"] = "ANSI (WM_GETTEXTA)"
            return result
    except Exception as e:
        result["error"] = str(e)

    return result


def probe_scintilla_gettext(hwnd: int, pid: int) -> Dict[str, Any]:
    """Method B: Read text via Scintilla SCI_GETTEXT (direct + cross-process WoW64 VirtualAllocEx)."""
    result: Dict[str, Any] = {
        "success": False,
        "length": 0,
        "first_200_chars": "",
        "direct_attempt": {"length": 0, "first_200_chars": "", "error": None},
        "wow64_remote_attempt": {"length": 0, "first_200_chars": "", "error": None},
    }

    try:
        # Check Scintilla length messages
        len_sci = user32.SendMessageW(hwnd, SCI_GETTEXTLENGTH, 0, 0)
        if len_sci <= 0:
            len_sci = user32.SendMessageW(hwnd, SCI_GETLENGTH, 0, 0)

        result["scintilla_detected_length"] = len_sci

        # 1. Direct in-process buffer attempt
        if len_sci > 0:
            try:
                buf_size = len_sci + 4
                buf = ctypes.create_string_buffer(buf_size)
                res = user32.SendMessageW(hwnd, SCI_GETTEXT, buf_size, buf)
                if res > 0 and buf.value:
                    txt = buf.value.decode("utf-8", errors="replace")
                    result["direct_attempt"]["length"] = len(txt)
                    result["direct_attempt"]["first_200_chars"] = sanitize_snippet(txt, 200)
                    if not result["success"]:
                        result["success"] = True
                        result["length"] = len(txt)
                        result["first_200_chars"] = sanitize_snippet(txt, 200)
            except Exception as e:
                result["direct_attempt"]["error"] = str(e)

        # 2. Cross-process WoW64 VirtualAllocEx attempt
        h_proc = kernel32.OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
            False,
            pid
        )
        if h_proc:
            try:
                alloc_size = max(len_sci + 64, 65536)
                remote_buf = kernel32.VirtualAllocEx(h_proc, None, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
                if remote_buf:
                    try:
                        # Clear remote buffer
                        zero_buf = (ctypes.c_char * 256)()
                        written = ctypes.c_size_t(0)
                        kernel32.WriteProcessMemory(h_proc, remote_buf, zero_buf, 256, ctypes.byref(written))

                        # Send SCI_GETTEXT passing remote 32-bit address
                        res_remote = user32.SendMessageW(hwnd, SCI_GETTEXT, alloc_size, remote_buf)
                        if res_remote > 0:
                            read_size = min(int(res_remote) + 2, alloc_size)
                            raw_out = (ctypes.c_char * read_size)()
                            read_bytes = ctypes.c_size_t(0)
                            if kernel32.ReadProcessMemory(h_proc, remote_buf, raw_out, read_size, ctypes.byref(read_bytes)):
                                txt = raw_out.value.decode("utf-8", errors="replace")
                                result["wow64_remote_attempt"]["length"] = len(txt)
                                result["wow64_remote_attempt"]["first_200_chars"] = sanitize_snippet(txt, 200)
                                if not result["success"]:
                                    result["success"] = True
                                    result["length"] = len(txt)
                                    result["first_200_chars"] = sanitize_snippet(txt, 200)
                    finally:
                        kernel32.VirtualFreeEx(h_proc, remote_buf, 0, MEM_RELEASE)
            finally:
                kernel32.CloseHandle(h_proc)
    except Exception as e:
        result["error"] = str(e)

    return result


def probe_em_streamout_and_richedit(hwnd: int, pid: int) -> Dict[str, Any]:
    """Method C: Probe RichEdit text retrieval via EM_GETTEXTEX, EM_GETTEXTRANGE, and EM_STREAMOUT."""
    result: Dict[str, Any] = {
        "success": False,
        "length": 0,
        "first_200_chars": "",
        "em_gettextex": {"length": 0, "first_200_chars": "", "error": None},
        "em_gettextrange": {"length": 0, "first_200_chars": "", "error": None},
        "em_streamout_probe": {"res": 0, "note": None},
    }

    h_proc = kernel32.OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        False,
        pid
    )
    if not h_proc:
        result["error"] = f"OpenProcess failed: {ctypes.GetLastError()}"
        return result

    try:
        remote_base = kernel32.VirtualAllocEx(h_proc, None, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote_base:
            result["error"] = f"VirtualAllocEx failed: {ctypes.GetLastError()}"
            return result

        try:
            # 1. Probe EM_GETTEXTEX (1118) via WoW64 remote struct
            try:
                struct_size = ctypes.sizeof(GETTEXTEX32)
                buf_remote_addr = (remote_base + struct_size + 32) & 0xFFFFFFFF
                buf_max_bytes = 60000

                gt = GETTEXTEX32()
                gt.cb = buf_max_bytes
                gt.flags = 1  # GT_USECRLF
                gt.codepage = 1200  # CP_WINUNICODE
                gt.lpDefaultChar = 0
                gt.lpUsedDefChar = 0

                written = ctypes.c_size_t(0)
                kernel32.WriteProcessMemory(h_proc, remote_base, ctypes.byref(gt), struct_size, ctypes.byref(written))

                res_ex = user32.SendMessageW(hwnd, EM_GETTEXTEX, remote_base, buf_remote_addr)
                if res_ex > 0:
                    read_len = min(int(res_ex) * 2 + 4, buf_max_bytes)
                    raw_buf = (ctypes.c_char * read_len)()
                    read_bytes = ctypes.c_size_t(0)
                    if kernel32.ReadProcessMemory(h_proc, buf_remote_addr, raw_buf, read_len, ctypes.byref(read_bytes)):
                        txt = raw_buf.raw.decode("utf-16le", errors="replace").split("\x00")[0]
                        result["em_gettextex"]["length"] = len(txt)
                        result["em_gettextex"]["first_200_chars"] = sanitize_snippet(txt, 200)
                        if not result["success"] and len(txt) > 0:
                            result["success"] = True
                            result["length"] = len(txt)
                            result["first_200_chars"] = sanitize_snippet(txt, 200)
            except Exception as e:
                result["em_gettextex"]["error"] = str(e)

            # 2. Probe EM_GETTEXTRANGE (1099) via WoW64 remote struct
            try:
                tr_struct_size = ctypes.sizeof(TEXTRANGEW32)
                tr_buf_addr = (remote_base + tr_struct_size + 32) & 0xFFFFFFFF
                tr_max_bytes = 60000

                tr = TEXTRANGEW32()
                tr.chrg.cpMin = 0
                tr.chrg.cpMax = 30000
                tr.lpstrText = tr_buf_addr

                written = ctypes.c_size_t(0)
                kernel32.WriteProcessMemory(h_proc, remote_base, ctypes.byref(tr), tr_struct_size, ctypes.byref(written))

                res_tr = user32.SendMessageW(hwnd, EM_GETTEXTRANGE, 0, remote_base)
                if res_tr > 0:
                    read_len = min(int(res_tr) * 2 + 4, tr_max_bytes)
                    raw_buf = (ctypes.c_char * read_len)()
                    read_bytes = ctypes.c_size_t(0)
                    if kernel32.ReadProcessMemory(h_proc, tr_buf_addr, raw_buf, read_len, ctypes.byref(read_bytes)):
                        txt = raw_buf.raw.decode("utf-16le", errors="replace").split("\x00")[0]
                        result["em_gettextrange"]["length"] = len(txt)
                        result["em_gettextrange"]["first_200_chars"] = sanitize_snippet(txt, 200)
                        if not result["success"] and len(txt) > 0:
                            result["success"] = True
                            result["length"] = len(txt)
                            result["first_200_chars"] = sanitize_snippet(txt, 200)
            except Exception as e:
                result["em_gettextrange"]["error"] = str(e)

            # 3. Document EM_STREAMOUT (1097) cross-process architecture
            # In Windows WoW64, EM_STREAMOUT requires an EDITSTREAMCALLBACK function pointer
            # located in Cscape's 32-bit execution space. Without in-process DLL injection,
            # EM_GETTEXTEX and EM_GETTEXTRANGE provide identical, safe text stream extraction.
            result["em_streamout_probe"]["note"] = (
                "EM_STREAMOUT requires in-proc 32-bit EDITSTREAMCALLBACK pointer. "
                "Tested companion RichEdit messages EM_GETTEXTEX and EM_GETTEXTRANGE with remote memory buffers."
            )
        finally:
            kernel32.VirtualFreeEx(h_proc, remote_base, 0, MEM_RELEASE)
    finally:
        kernel32.CloseHandle(h_proc)

    return result


def probe_uia_text(hwnd: int, app_uia: Application) -> Dict[str, Any]:
    """Method D: Probe UIAutomation (UIA) TextPattern, ValuePattern, and window_text."""
    result: Dict[str, Any] = {
        "success": False,
        "length": 0,
        "first_200_chars": "",
        "patterns_supported": [],
        "text_pattern": {"available": False, "length": 0, "first_200_chars": ""},
        "value_pattern": {"available": False, "length": 0, "first_200_chars": ""},
        "window_text": {"length": 0, "first_200_chars": ""},
    }

    try:
        ctrl = app_uia.window(handle=hwnd)
        if not ctrl.exists():
            return result

        # 1. Window text check
        try:
            wt = (ctrl.window_text() or "").strip()
            if wt:
                result["window_text"]["length"] = len(wt)
                result["window_text"]["first_200_chars"] = sanitize_snippet(wt, 200)
                if not result["success"]:
                    result["success"] = True
                    result["length"] = len(wt)
                    result["first_200_chars"] = sanitize_snippet(wt, 200)
        except Exception:
            pass

        # 2. TextPattern check
        try:
            if hasattr(ctrl, "iface_text") and ctrl.iface_text:
                result["patterns_supported"].append("TextPattern")
                result["text_pattern"]["available"] = True
                doc_range = ctrl.iface_text.DocumentRange
                if doc_range:
                    txt = doc_range.GetText(-1)
                    if txt:
                        result["text_pattern"]["length"] = len(txt)
                        result["text_pattern"]["first_200_chars"] = sanitize_snippet(txt, 200)
                        result["success"] = True
                        result["length"] = len(txt)
                        result["first_200_chars"] = sanitize_snippet(txt, 200)
        except Exception as e:
            result["text_pattern"]["error"] = str(e)

        # 3. ValuePattern check
        try:
            if hasattr(ctrl, "iface_value") and ctrl.iface_value:
                result["patterns_supported"].append("ValuePattern")
                result["value_pattern"]["available"] = True
                val = ctrl.iface_value.CurrentValue
                if val:
                    result["value_pattern"]["length"] = len(val)
                    result["value_pattern"]["first_200_chars"] = sanitize_snippet(val, 200)
                    if not result["success"]:
                        result["success"] = True
                        result["length"] = len(val)
                        result["first_200_chars"] = sanitize_snippet(val, 200)
        except Exception as e:
            result["value_pattern"]["error"] = str(e)

        # 4. Descendant introspection for nested Document/Edit
        try:
            for desc in ctrl.descendants():
                c_type = desc.element_info.control_type
                if c_type in ["Document", "Edit", "Text"]:
                    d_txt = (desc.window_text() or "").strip()
                    if d_txt and len(d_txt) > result["length"]:
                        result["success"] = True
                        result["length"] = len(d_txt)
                        result["first_200_chars"] = sanitize_snippet(d_txt, 200)
                        result["patterns_supported"].append(f"Descendant_{c_type}")
        except Exception:
            pass
    except Exception as e:
        result["error"] = str(e)

    return result


# =========================================================================
# Sub-Tabs Inspection (IEC / XML / CSV)
# =========================================================================

def inspect_sub_tabs(main_hwnd: int, active_mdi: Optional[int], pid: int, app_uia: Application) -> List[Dict[str, Any]]:
    """Inspect sub-tabs (IEC, XML, CSV) via Win32 SysTabControl32 and UIAutomation Tab controls."""
    sub_tabs: List[Dict[str, Any]] = []
    seen_tabs: set = set()

    # 1. Win32 SysTabControl32 Inspection
    tab_hwnds: List[int] = []

    def enum_tabs(h: int, _: Any) -> bool:
        try:
            cls = win32gui.GetClassName(h)
            if "SysTabControl32" in cls or "CTabCtrl" in cls or "tab" in cls.lower():
                tab_hwnds.append(h)
        except Exception:
            pass
        return True

    search_roots = [active_mdi, main_hwnd]
    for r in search_roots:
        if r and win32gui.IsWindow(r):
            try:
                win32gui.EnumChildWindows(r, enum_tabs, None)
            except Exception:
                pass

    h_proc = kernel32.OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        False,
        pid
    )

    remote_base = None
    if h_proc:
        try:
            remote_base = kernel32.VirtualAllocEx(h_proc, None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        except Exception:
            remote_base = None

    try:
        for th in tab_hwnds:
            try:
                item_count = user32.SendMessageW(th, TCM_GETITEMCOUNT, 0, 0)
                cur_sel = user32.SendMessageW(th, TCM_GETCURSEL, 0, 0)
                th_rect = win32gui.GetWindowRect(th)

                logger.info(f"Discovered SysTabControl32 HWND {hex(th)}: item_count={item_count}, cur_sel={cur_sel}, rect={th_rect}")

                for idx in range(max(0, item_count)):
                    tab_name = f"Tab_{idx}"
                    tab_rect = None

                    if h_proc and remote_base:
                        try:
                            # 1. Query tab text via TCM_GETITEMW (0x133C)
                            text_remote = (remote_base + 128) & 0xFFFFFFFF
                            zero_buf = (ctypes.c_char * 512)()
                            written = ctypes.c_size_t(0)
                            kernel32.WriteProcessMemory(h_proc, text_remote, zero_buf, 512, ctypes.byref(written))

                            item = TCITEMW32()
                            item.mask = TCIF_TEXT
                            item.pszText = text_remote
                            item.cchTextMax = 256
                            kernel32.WriteProcessMemory(h_proc, remote_base, ctypes.byref(item), ctypes.sizeof(item), ctypes.byref(written))

                            res = user32.SendMessageW(th, TCM_GETITEMW, idx, remote_base)
                            if res:
                                raw_buf = (ctypes.c_char * 512)()
                                read_bytes = ctypes.c_size_t(0)
                                if kernel32.ReadProcessMemory(h_proc, text_remote, raw_buf, 512, ctypes.byref(read_bytes)):
                                    txt = raw_buf.raw.decode("utf-16le", errors="ignore").split("\x00")[0].strip()
                                    if txt:
                                        tab_name = txt

                            # 2. Query tab rect via TCM_GETITEMRECT (0x130A)
                            rect_remote = (remote_base + 64) & 0xFFFFFFFF
                            res_r = user32.SendMessageW(th, TCM_GETITEMRECT, idx, rect_remote)
                            if res_r:
                                rect_out = RECT32()
                                read_bytes = ctypes.c_size_t(0)
                                if kernel32.ReadProcessMemory(h_proc, rect_remote, ctypes.byref(rect_out), ctypes.sizeof(rect_out), ctypes.byref(read_bytes)):
                                    pt_tl = wintypes.POINT(rect_out.left, rect_out.top)
                                    pt_br = wintypes.POINT(rect_out.right, rect_out.bottom)
                                    user32.ClientToScreen(th, ctypes.byref(pt_tl))
                                    user32.ClientToScreen(th, ctypes.byref(pt_br))
                                    tab_rect = [pt_tl.x, pt_tl.y, pt_br.x, pt_br.y]
                        except Exception as e:
                            logger.warning(f"Error querying SysTabControl32 item {idx}: {e}")

                    tab_info = {
                        "source": "Win32_SysTabControl32",
                        "tab_control_hwnd": hex(th),
                        "index": idx,
                        "name": tab_name,
                        "is_selected": (idx == cur_sel),
                        "rect": tab_rect,
                    }
                    tab_key = (hex(th), idx, tab_name)
                    if tab_key not in seen_tabs:
                        seen_tabs.add(tab_key)
                        sub_tabs.append(tab_info)
            except Exception as e:
                logger.warning(f"Error inspecting SysTabControl32 {hex(th)}: {e}")
    finally:
        if h_proc and remote_base:
            kernel32.VirtualFreeEx(h_proc, remote_base, 0, MEM_RELEASE)
        if h_proc:
            kernel32.CloseHandle(h_proc)

    # 2. UIAutomation Tab and TabItem Inspection
    try:
        cscape_ui = app_uia.window(handle=main_hwnd)
        for tab_item in cscape_ui.descendants(control_type="TabItem"):
            try:
                name = (getattr(tab_item.element_info, "name", "") or tab_item.window_text() or "").strip()
                is_selected = False
                try:
                    if hasattr(tab_item, "iface_selection_item") and tab_item.iface_selection_item:
                        is_selected = bool(tab_item.iface_selection_item.CurrentIsSelected)
                except Exception:
                    pass

                rect = None
                try:
                    r = tab_item.rectangle()
                    rect = [r.left, r.top, r.right, r.bottom]
                except Exception:
                    pass

                tab_key = ("UIA_TabItem", name, str(rect))
                if tab_key not in seen_tabs:
                    seen_tabs.add(tab_key)
                    sub_tabs.append({
                        "source": "UIA_TabItem",
                        "name": name,
                        "is_selected": is_selected,
                        "rect": rect,
                        "automation_id": getattr(tab_item.element_info, "automation_id", ""),
                        "class_name": getattr(tab_item.element_info, "class_name", ""),
                    })
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Error in UIA TabItem inspection: {e}")

    return sub_tabs


# =========================================================================
# Main Probe Execution Pipeline
# =========================================================================

def run_probe_iec_editor() -> int:
    """Execute complete forensic inspection of the IEC Variables Editor."""
    logger.info("=" * 80)
    logger.info("STARTING READ-ONLY FORENSIC PROBE: IEC Variables Editor Window Hierarchy")
    logger.info("=" * 80)

    probe_data: Dict[str, Any] = {
        "probe": "G3_IEC_VARIABLES_EDITOR_FORENSICS",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": "inconclusive",
        "copy_path": str(PROBE_COPY_PATH),
        "initial_sha256": None,
        "final_sha256": None,
        "file_mutated": False,
        "mdi_client_hwnd": None,
        "active_mdi_child": {},
        "sub_tabs": [],
        "children_count": 0,
        "children_dump": [],
        "screenshots": {},
        "summary": {},
    }

    app = None
    pid = None
    main_hwnd = None

    try:
        # Step 1: Assert safety invariants & immutability of base projects
        assert_safety_invariants()

        # Step 2: Kill any pre-existing Cscape processes
        logger.info("Terminating any leftover Cscape processes before probe...")
        kill_leftover_cscape()

        # Step 3: Copy p1_base.csp to probe_iec_editor.csp
        logger.info(f"Copying '{BASE_P1_PATH.name}' to fresh copy '{PROBE_COPY_PATH}'...")
        COPIES_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(BASE_P1_PATH, PROBE_COPY_PATH)
        initial_sha = compute_sha256(PROBE_COPY_PATH)
        probe_data["initial_sha256"] = initial_sha
        logger.info(f"Disposable probe copy initialized. SHA-256: {initial_sha}")

        # Step 4: Configure registry for clean startup
        configure_cscape_registry(PROBE_COPY_PATH)

        # Step 5: Launch Cscape with probe_iec_editor.csp on visible desktop
        logger.info("Launching Cscape 10.2 on visible desktop...")
        app, pid, main_hwnd = launch_cscape_with_project(PROBE_COPY_PATH)
        main_win = app.window(handle=main_hwnd)
        main_win.set_focus()
        time.sleep(2.0)

        # Step 6: Handle startup dialogs and wait for main window enabled
        handle_startup_dialogs_and_wait_for_main_window(pid, main_hwnd, app, {})

        app_uia = Application(backend="uia").connect(process=pid)
        cscape_ui = app_uia.window(handle=main_hwnd)

        # Step 7: Open Program Variables pane
        evidence_dummy: Dict[str, Any] = {}
        open_program_variables_pane(pid, main_hwnd, main_win, app_uia, cscape_ui, evidence_dummy)
        time.sleep(1.0)

        # Step 8: Locate child SysTreeView32 inside W5EditTL
        tv_hwnd, w5_hwnd = find_program_variables_treeview(pid, main_hwnd)
        if not tv_hwnd:
            raise RuntimeError("Could not locate child SysTreeView32 in Program Variables pane!")

        # Step 9: Re-locate Global Variables row, click row first, right-click, assert context menu
        logger.info("Relocating Global Variables row...")
        cx, cy, target_rect, gv_hitem = relocate_global_variables_row(
            pid=pid, tv_hwnd=tv_hwnd, w5_hwnd=w5_hwnd, app=app, main_hwnd=main_hwnd
        )
        logger.info(f"Selecting Global Variables row at screen point ({cx}, {cy})...")
        mouse.click(button="left", coords=(cx, cy))
        time.sleep(0.5)

        logger.info(f"Right-clicking Global Variables row at screen point ({cx}, {cy})...")
        mouse.click(button="right", coords=(cx, cy))
        time.sleep(1.0)

        menu_items, popup_h = inspect_context_menu_items(app_uia)
        logger.info(f"Context menu detected ({len(menu_items)} items): {menu_items}")

        has_edit_as_text = any("as text" in it.lower() or "edit variables" in it.lower() for it in menu_items)
        if not has_edit_as_text:
            dismiss_popup_menu(popup_h)
            raise RuntimeError(f"Context menu missing 'Edit Variables as Text'. Observed: {menu_items}")

        # Step 10: Click 'Edit Variables as Text' (ZERO keystrokes to editor)
        clicked = False
        if popup_h:
            try:
                popup_win = app_uia.window(handle=popup_h)
                for it in popup_win.descendants(control_type="MenuItem"):
                    t = (getattr(it.element_info, "name", "") or it.window_text() or "").strip()
                    if "as text" in t.lower() or "edit variables" in t.lower():
                        logger.info(f"Clicking MenuItem '{t}' via popup UIA...")
                        it.click_input()
                        clicked = True
                        break
            except Exception as e:
                logger.warning(f"Popup UIA click note: {e}")

        if not clicked:
            for idx, item in enumerate(menu_items):
                if "as text" in item.lower() or "edit variables" in item.lower():
                    logger.info(f"Targeting menu item '{item}' via keyboard...")
                    pywinauto.keyboard.send_keys("{DOWN}" * (idx + 1) + "{ENTER}")
                    clicked = True
                    break

        if not clicked and popup_h:
            user32.PostMessageW(popup_h, win32con.WM_CHAR, ord('t'), 0)
            clicked = True

        logger.info("Waiting 3.0s for IEC Variables Editor tab and child controls to render...")
        time.sleep(3.0)

        # Step 11: Capture Full Window Screenshot
        ss_full = capture_window_screenshot(main_hwnd, FULL_SCREENSHOT_PATH)
        probe_data["screenshots"]["full"] = ss_full

        # Step 12: Identify MDIClient and Active MDI Child
        mdi_client_hwnd, active_mdi, mdi_children = find_mdi_containers(main_hwnd)
        probe_data["mdi_client_hwnd"] = hex(mdi_client_hwnd) if mdi_client_hwnd else None
        logger.info(f"MDIClient HWND: {hex(mdi_client_hwnd) if mdi_client_hwnd else 'None'}")
        logger.info(f"Active MDI Child HWND: {hex(active_mdi) if active_mdi else 'None'}")
        logger.info(f"MDIClient Children HWNDs: {[hex(c) for c in mdi_children]}")

        target_mdi = active_mdi or (mdi_children[0] if mdi_children else None)
        if target_mdi and win32gui.IsWindow(target_mdi):
            mdi_title = win32gui.GetWindowText(target_mdi)
            mdi_cls = win32gui.GetClassName(target_mdi)
            mdi_rect = list(win32gui.GetWindowRect(target_mdi))
            probe_data["active_mdi_child"] = {
                "hwnd": target_mdi,
                "hwnd_hex": hex(target_mdi),
                "title": mdi_title,
                "class": mdi_cls,
                "rect": mdi_rect,
            }
            logger.info(f"Target MDI Editor Window: '{mdi_title}' (HWND {hex(target_mdi)}, class='{mdi_cls}', rect={mdi_rect})")
            ss_tab = capture_window_screenshot(target_mdi, TAB_SCREENSHOT_PATH)
            probe_data["screenshots"]["tab"] = ss_tab
        else:
            logger.warning("Active MDI child window not directly resolved; using MDIClient as root.")
            target_mdi = mdi_client_hwnd

        # Step 13: Inspect IEC / XML / CSV Sub-Tabs
        logger.info("Inspecting Sub-Tabs (IEC, XML, CSV)...")
        sub_tabs = inspect_sub_tabs(main_hwnd, target_mdi, pid, app_uia)
        probe_data["sub_tabs"] = sub_tabs
        logger.info(f"Sub-Tabs Discovered ({len(sub_tabs)}):")
        for st in sub_tabs:
            logger.info(f"  - [{st.get('source')}] Name: '{st.get('name')}', Selected: {st.get('is_selected')}, Rect: {st.get('rect')}")

        # Step 14: Dump Every Child Window under IEC Editor
        logger.info("Dumping Child Window Hierarchy under IEC Editor...")
        children_dump = []
        target_roots = [target_mdi]
        if mdi_client_hwnd and mdi_client_hwnd != target_mdi:
            target_roots.append(mdi_client_hwnd)

        all_child_records = []
        seen_child_hwnds = set()
        for root in target_roots:
            if root and win32gui.IsWindow(root):
                for rec in dump_child_windows_hierarchy(root):
                    if rec["hwnd"] not in seen_child_hwnds:
                        seen_child_hwnds.add(rec["hwnd"])
                        all_child_records.append(rec)

        logger.info(f"Total Unique Child Windows Enumerated: {len(all_child_records)}")

        # Step 15: Try 4 Text Extraction Methods on Each Child Window
        logger.info("=" * 80)
        logger.info("PROBING 4 TEXT EXTRACTION METHODS ON EACH CHILD WINDOW (ZERO KEYSTROKES)")
        logger.info("=" * 80)

        for idx, child in enumerate(all_child_records, start=1):
            ch_hwnd = child["hwnd"]
            cls_name = child["class_name"]
            ctrl_id = child["control_id"]
            rect = child["rect"]

            logger.info(f"\n[{idx}/{len(all_child_records)}] Inspecting HWND {hex(ch_hwnd)} (Class='{cls_name}', ID={ctrl_id}, Rect={rect})")

            # Method A: WM_GETTEXT
            res_wm = probe_wm_gettext(ch_hwnd)
            logger.info(f"  - Method A (WM_GETTEXT): Success={res_wm['success']}, Length={res_wm['length']}, Chars='{res_wm['first_200_chars'][:80]}...'")

            # Method B: Scintilla SCI_GETTEXT
            res_sci = probe_scintilla_gettext(ch_hwnd, pid)
            logger.info(f"  - Method B (SCI_GETTEXT): Success={res_sci['success']}, Length={res_sci['length']}, Chars='{res_sci['first_200_chars'][:80]}...'")

            # Method C: RichEdit EM_STREAMOUT / EM_GETTEXTEX / EM_GETTEXTRANGE
            res_em = probe_em_streamout_and_richedit(ch_hwnd, pid)
            logger.info(f"  - Method C (EM_STREAMOUT/RichEdit): Success={res_em['success']}, Length={res_em['length']}, Chars='{res_em['first_200_chars'][:80]}...'")

            # Method D: UIAutomation (UIA)
            res_uia = probe_uia_text(ch_hwnd, app_uia)
            logger.info(f"  - Method D (UIA): Success={res_uia['success']}, Length={res_uia['length']}, Patterns={res_uia['patterns_supported']}, Chars='{res_uia['first_200_chars'][:80]}...'")

            child["methods"] = {
                "WM_GETTEXT": res_wm,
                "SCI_GETTEXT": res_sci,
                "EM_STREAMOUT": res_em,
                "UIA": res_uia,
            }
            children_dump.append(child)

        probe_data["children_count"] = len(children_dump)
        probe_data["children_dump"] = children_dump

        # Build Forensic Summary
        successful_methods_map: Dict[str, List[str]] = {}
        for ch in children_dump:
            succ = []
            for m_name, m_res in ch["methods"].items():
                if m_res.get("success"):
                    succ.append(m_name)
            if succ:
                successful_methods_map[ch["hwnd_hex"]] = succ

        probe_data["summary"] = {
            "total_children_inspected": len(children_dump),
            "windows_with_text": len(successful_methods_map),
            "successful_methods_map": successful_methods_map,
            "sub_tabs_detected": [st.get("name") for st in sub_tabs],
        }

        # Step 16: Close active editor tab and Cscape cleanly WITHOUT SAVING
        logger.info("\nClosing active editor tab via close_active_editor_tab (Ctrl+F4, answering No to any prompt)...")
        close_active_editor_tab(main_win, main_hwnd, pid=pid, app=app, evidence={})
        time.sleep(1.0)

        logger.info("Closing Cscape gracefully without saving...")
        close_cscape_gracefully(pid=pid, timeout=6.0)

        # Step 17: Assert read-only safety: file on disk was NOT mutated
        final_sha = compute_sha256(PROBE_COPY_PATH)
        probe_data["final_sha256"] = final_sha
        file_mutated = (final_sha != initial_sha)
        probe_data["file_mutated"] = file_mutated

        if file_mutated:
            raise RuntimeError(f"IMMUTABILITY VIOLATION: probe copy '{PROBE_COPY_PATH.name}' was mutated! (Initial={initial_sha}, Final={final_sha})")

        logger.info(f"[PASS] Read-only integrity verified: file SHA-256 unchanged ({initial_sha[:16]}...).")
        assert_safety_invariants()

        probe_data["status"] = "success"

        # Step 18: Save Structured JSON Evidence
        with open(EVIDENCE_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(probe_data, f, indent=2)
        logger.info(f"Forensic findings saved: {EVIDENCE_JSON_PATH}")

        # Step 19: Print Summary Table to stdout
        logger.info("=" * 80)
        logger.info("IEC VARIABLES EDITOR FORENSIC PROBE SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Status: {probe_data['status'].upper()}")
        logger.info(f"Active MDI Window: {probe_data['active_mdi_child'].get('title')} ({probe_data['active_mdi_child'].get('class')})")
        logger.info(f"Sub-Tabs Found: {probe_data['summary']['sub_tabs_detected']}")
        logger.info(f"Child Windows Inspected: {probe_data['summary']['total_children_inspected']}")
        logger.info(f"Windows Yielding Text: {probe_data['summary']['windows_with_text']}")
        for h_hex, methods in successful_methods_map.items():
            logger.info(f"  - HWND {h_hex}: Text successfully extracted via: {', '.join(methods)}")
        logger.info("=" * 80)
        return 0

    except Exception as e:
        logger.error(f"Probe execution failed: {e}", exc_info=True)
        probe_data["status"] = "failed"
        probe_data["error"] = str(e)
        try:
            if pid:
                close_cscape_gracefully(pid=pid, timeout=4.0)
        except Exception:
            pass
        with open(EVIDENCE_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(probe_data, f, indent=2)
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deep forensic probe of Cscape IEC Variables Editor window hierarchy.")
    args = parser.parse_args()
    code = run_probe_iec_editor()
    sys.exit(code)
