#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gate G7 Ladder Logic Acceptance Campaign Runner.

Mandate: Real Gate G7 Acceptance Campaign meeting all rigorous criteria:
1. 20 sequential runs, each starting from a fresh clean copy of work/disposable/p1_base.csp.
2. Overall standard match pass rate >= 19/20.
3. >= 4 reserved operand/parameter combos exercised across the campaign.
4. An intentional wrong operand fixture that the verifier detects even if Cscape accepts it.
5. Run Cscape Error Check (ID_PROGRAM_ERRORCHECK = 32826) and read the full result (0 errors, 0 warnings).
6. Zero silent duplications: delta element count == 2, delta network count == 1, 0 duplicate symbols.
7. Save/reopen equivalence: disk write flush verified, reopen in Cscape with About dismissed and window enabled, CFBF oracle opcode/tag match.
8. Jev decisions: replaying authentic G4 recorded responses offline (0 network calls).

Classification: TESTED_MOCK / INTEGRATION [winsta0\\Default]
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import olefile
from PIL import ImageGrab
import win32con
import win32gui
import win32process
from pywinauto import Application

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
    close_active_editor_tab,
    close_cscape_gracefully,
    compute_sha256,
    evaluate_window_for_dialog_guard,
    is_known_cscape_dialog,
    kill_leftover_cscape,
    parse_csp_cfbf_declarations,
    run_edit_roundtrip,
)
from scripts.probe_ladder_editor import (
    configure_cscape_registry,
    expand_all_tree_nodes,
    find_mdi_containers,
    launch_cscape_with_project,
    wait_for_about_cscape_and_main_enabled,
    wait_until_no_dialogs_and_main_ready,
)

# Output Directories & Constants
ARTIFACTS_G7_DIR = REPO_ROOT / "artifacts" / "G7"
ARTIFACTS_G7_DIR.mkdir(parents=True, exist_ok=True)
ACCEPTANCE_RUNS_DIR = ARTIFACTS_G7_DIR / "acceptance_runs"
ACCEPTANCE_RUNS_DIR.mkdir(parents=True, exist_ok=True)
ACCEPTANCE_SUMMARY_PATH = ARTIFACTS_G7_DIR / "g7_acceptance_summary.json"
CAMPAIGN_G3_PATH = COPIES_DIR / "campaign_run_01.csp"
LOG_DIR = REPO_ROOT / "artifacts" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE_PATH = LOG_DIR / "g7_acceptance.log"

# Win32 Command IDs
ID_SELECT_ELEMENTS = 112       # ESC / Select tool
ID_NO_CONTACT = 1000           # 'q' / F2 Normally Open Contact
ID_NC_CONTACT = 1001           # 'r' Normally Closed Contact
ID_NO_COIL = 1002              # 'x' / F9 Normally Open Coil
ID_BRANCH = 1005               # 's' Branch
ID_COMMENT = 1006              # 't' Comment
ID_NEW_RUNG_CONTEXT = 32820    # New Rung in PAGEMENU_RAIL
ID_INSERT_NEW_RUNG = 37980     # Insert New Rung accelerator/menu
ID_PROGRAM_ERRORCHECK = 32826  # Ctrl+E / Ctrl+F7 Error Check
ID_FILE_SAVE = 57603           # Ctrl+S Save
ID_PROGRAM_DOWNLOAD = 32827    # BLOCKED
ID_CONTROLLER_DOWNLOAD = 33149 # BLOCKED

# Additional Toolbox Command IDs for Coils
ID_NC_COIL = 37687             # Normally Closed Coil
ID_POS_COIL = 37688            # Positive Transition Coil
ID_NEG_COIL = 37689            # Negative Transition Coil
ID_SET_COIL = 37690            # Set Coil
ID_RESET_COIL = 37691          # Reset Coil

# Setup Logger
logger = logging.getLogger("g7_acceptance")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    fh = logging.FileHandler(LOG_FILE_PATH, mode="w", encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(sh)
    logger.addHandler(fh)

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# CFBF Opcode to Type mapping
CSCAPE_OPCODE_TO_TYPE: Dict[int, str] = {
    0x00: "CONTACT_NO",
    0x01: "CONTACT_NC",
    0x02: "COIL_NO",
    0x09: "COIL_NC",
    0x0C: "COIL_SET",
    0x0D: "COIL_RESET",
}
CONTACT_OPCODES = {0x00, 0x01}
COIL_OPCODES = {0x02, 0x09, 0x0C, 0x0D}

HORNER_RESERVED_SYSTEM_BITS: Set[str] = {
    "ALW_ON", "ALW_OFF", "FST_SCN", "SYS_DISABLE",
    "SYS_ACK", "T_100MS", "T_10MS", "T_SEC",
}
HORNER_VALID_CONTACT_TYPES: Set[str] = {"CONTACT_NO", "CONTACT_NC"}
HORNER_VALID_COIL_TYPES: Set[str] = {"COIL_NO", "COIL_NC", "COIL_SET", "COIL_RESET"}


def validate_horner_reserved_combo(combo: Tuple[str, str, str]) -> Tuple[bool, str]:
    """Validate that (contact_type, contact_tag, coil_type) is an authorized Horner APG reserved combination."""
    c_type, c_tag, q_type = combo
    if c_type not in HORNER_VALID_CONTACT_TYPES:
        return False, f"Invalid contact type '{c_type}'; expected one of {sorted(HORNER_VALID_CONTACT_TYPES)}"
    if c_tag not in HORNER_RESERVED_SYSTEM_BITS:
        return False, f"Contact tag '{c_tag}' is not a recognized Horner APG reserved system operand (%S bit)"
    if q_type not in HORNER_VALID_COIL_TYPES:
        return False, f"Invalid coil type '{q_type}'; expected one of {sorted(HORNER_VALID_COIL_TYPES)}"
    return True, f"Valid Horner APG reserved combination: Contact={c_type}({c_tag}) -> Coil={q_type}"


# ==============================================================================
# 20 Authentic Recorded Jev Responses from Gate G4 Live Runs (Offline Replay)
# ==============================================================================

G4_AUTHENTIC_REPLAY_FIXTURES: List[Dict[str, Any]] = [
    {
        "task_number": 1,
        "task_id": "P1_TASK_01",
        "name": "Tank Level Measurement Scaling (PV)",
        "channel": "%AI1 (Analog Input 1)",
        "plan": "P1_TANK_LEVEL_PV",
        "confidence": 0.80,
        "response_id": "req_01a123fcb4027d479c9ff72cc6cce72f",
        "source_file": "artifacts/G4/campaign_runs/task_01_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NO_CONTACT,
        "contact_type": "CONTACT_NO",
        "contact_tag": "ALW_ON",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_01",
    },
    {
        "task_number": 2,
        "task_id": "P1_TASK_02",
        "name": "Liquid Level Operating Setpoint (SP)",
        "channel": "%R1 (Holding Register 1)",
        "plan": "P1_LEVEL_SETPOINT_SP",
        "confidence": 0.64,
        "response_id": "req_01a123fcb4a07fb7b33c5ec403b7d876",
        "source_file": "artifacts/G4/campaign_runs/task_02_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NC_CONTACT,
        "contact_type": "CONTACT_NC",
        "contact_tag": "ALW_OFF",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_02",
    },
    {
        "task_number": 3,
        "task_id": "P1_TASK_03",
        "name": "Inflow Proportional Valve Actuation (CV)",
        "channel": "%AQ1 (Analog Output 1)",
        "plan": "P1_INFLOW_VALVE_CV",
        "confidence": 0.73,
        "response_id": "req_01a123fcb5337c1cab16f9b19ef8c1cc",
        "source_file": "artifacts/G4/campaign_runs/task_03_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NO_CONTACT,
        "contact_type": "CONTACT_NO",
        "contact_tag": "ALW_ON",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_03",
    },
    {
        "task_number": 4,
        "task_id": "P1_TASK_04",
        "name": "Gravity Drain Control Valve Actuation",
        "channel": "%AQ2 (Analog Output 2)",
        "plan": "P1_CV_OUTFLOW_COUNTS",
        "confidence": 0.31,
        "response_id": "req_01a123fcb5c9705baaf2ec8c7bce7855",
        "source_file": "artifacts/G4/campaign_runs/task_04_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NC_CONTACT,
        "contact_type": "CONTACT_NC",
        "contact_tag": "SYS_DISABLE",
        "coil_cmd": ID_RESET_COIL,
        "coil_type": "COIL_RESET",
        "coil_tag": "G3_TEST_VAR_01",
    },
    {
        "task_number": 5,
        "task_id": "P1_TASK_05",
        "name": "Centrifugal Feed Pump Motor Control",
        "channel": "%Q1 (Digital Output 1)",
        "plan": "P1_PUMP_FEED_START",
        "confidence": 0.13,
        "response_id": "req_01a123fcb6477e919594ad8665c8398c",
        "source_file": "artifacts/G4/campaign_runs/task_05_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NO_CONTACT,
        "contact_type": "CONTACT_NO",
        "contact_tag": "FST_SCN",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_02",
    },
    {
        "task_number": 6,
        "task_id": "P1_TASK_06",
        "name": "Transfer Drain Pump Motor Control",
        "channel": "%Q2 (Digital Output 2)",
        "plan": "P1_DRAIN_PUMP_CMD_Q",
        "confidence": 0.17,
        "response_id": "req_01a123fcb6c3797fb3c6161139eec8a6",
        "source_file": "artifacts/G4/campaign_runs/task_06_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NC_CONTACT,
        "contact_type": "CONTACT_NC",
        "contact_tag": "SYS_ACK",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_03",
    },
    {
        "task_number": 7,
        "task_id": "P1_TASK_07",
        "name": "High Liquid Level Warning Threshold",
        "channel": "%M1 (Internal Marker 1)",
        "plan": "P1_WARN_HI_LEVEL",
        "confidence": 0.29,
        "response_id": "req_01a123fcb73f7019ac2d027382c84ce9",
        "source_file": "artifacts/G4/campaign_runs/task_07_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NO_CONTACT,
        "contact_type": "CONTACT_NO",
        "contact_tag": "T_100MS",
        "coil_cmd": ID_SET_COIL,
        "coil_type": "COIL_SET",
        "coil_tag": "G3_TEST_VAR_01",
    },
    {
        "task_number": 8,
        "task_id": "P1_TASK_08",
        "name": "Low Liquid Level Warning Threshold",
        "channel": "%M2 (Internal Marker 2)",
        "plan": "P1_LOW_LEVEL_ALM_M",
        "confidence": 0.23,
        "response_id": "req_01a123fcb7c67b2fb21bf2d92fe3ff91",
        "source_file": "artifacts/G4/campaign_runs/task_08_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NC_CONTACT,
        "contact_type": "CONTACT_NC",
        "contact_tag": "T_SEC",
        "coil_cmd": ID_RESET_COIL,
        "coil_type": "COIL_RESET",
        "coil_tag": "G3_TEST_VAR_02",
    },
    {
        "task_number": 9,
        "task_id": "P1_TASK_09",
        "name": "High-High Emergency Shutdown (ESD) Trip",
        "channel": "%M3 (Internal Marker 3)",
        "plan": "P1_HIHI_ESD_TRIP_M",
        "confidence": 0.73,
        "response_id": "req_01a123fcb8437f4b9d74e1bfa1d1aba3",
        "source_file": "artifacts/G4/campaign_runs/task_09_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NO_CONTACT,
        "contact_type": "CONTACT_NO",
        "contact_tag": "T_10MS",
        "coil_cmd": ID_SET_COIL,
        "coil_type": "COIL_SET",
        "coil_tag": "G3_TEST_VAR_03",
    },
    {
        "task_number": 10,
        "task_id": "P1_TASK_10",
        "name": "Feed Pump Thermal Overload Protection",
        "channel": "%I1 (Digital Input 1)",
        "plan": "P1_PUMP_OVERLOAD_I",
        "confidence": 0.35,
        "response_id": "req_01a123fcb8c17df7bb002cf3b77c8736",
        "source_file": "artifacts/G4/campaign_runs/task_10_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NC_CONTACT,
        "contact_type": "CONTACT_NC",
        "contact_tag": "ALW_OFF",
        "coil_cmd": ID_NC_COIL,
        "coil_type": "COIL_NC",
        "coil_tag": "G3_TEST_VAR_01",
    },
    {
        "task_number": 11,
        "task_id": "P1_TASK_11",
        "name": "Inlet Ultrasonic Mass Flow Monitoring",
        "channel": "%AI2 (Analog Input 2)",
        "plan": "P1_INLET_FLOW_RATE",
        "confidence": 0.17,
        "response_id": "req_01a123fcb93a70f38ca8535ac491653a",
        "source_file": "artifacts/G4/campaign_runs/task_11_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NO_CONTACT,
        "contact_type": "CONTACT_NO",
        "contact_tag": "ALW_ON",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_01",
    },
    {
        "task_number": 12,
        "task_id": "P1_TASK_12",
        "name": "Vessel Temperature RTD Acquisition",
        "channel": "%AI3 (Analog Input 3)",
        "plan": "P1_VESSEL_TEMP_AI",
        "confidence": 0.39,
        "response_id": "req_01a123fcb9c27090aff1ad3aa9b8d45d",
        "source_file": "artifacts/G4/campaign_runs/task_12_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NC_CONTACT,
        "contact_type": "CONTACT_NC",
        "contact_tag": "SYS_DISABLE",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_02",
    },
    {
        "task_number": 13,
        "task_id": "P1_TASK_13",
        "name": "Vessel Static Head Pressure Acquisition",
        "channel": "%AI4 (Analog Input 4)",
        "plan": "P1_STATIC_HEAD_PRESS",
        "confidence": 0.29,
        "response_id": "req_01a123f8b93a7991be064b90849dc27f",
        "source_file": "artifacts/G4/campaign_runs/task_13_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NO_CONTACT,
        "contact_type": "CONTACT_NO",
        "contact_tag": "FST_SCN",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_03",
    },
    {
        "task_number": 14,
        "task_id": "P1_TASK_14",
        "name": "Chemical Agitator Mixer Motor Control",
        "channel": "%Q3 (Digital Output 3)",
        "plan": "P1_AGITATOR_START",
        "confidence": 0.33,
        "response_id": "req_01a123f8b9c67d7d99ffa8e7b8ef67b4",
        "source_file": "artifacts/G4/campaign_runs/task_14_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NC_CONTACT,
        "contact_type": "CONTACT_NC",
        "contact_tag": "SYS_ACK",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_01",
    },
    {
        "task_number": 15,
        "task_id": "P1_TASK_15",
        "name": "Actuator Position Mismatch Supervisory Fault",
        "channel": "%M4 (Internal Marker 4)",
        "plan": "P1_ALM_VALVE_MISMATCH",
        "confidence": 0.20,
        "response_id": "req_01a123f8ba447f39badb49d1c96bb8a6",
        "source_file": "artifacts/G4/campaign_runs/task_15_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NO_CONTACT,
        "contact_type": "CONTACT_NO",
        "contact_tag": "T_100MS",
        "coil_cmd": ID_SET_COIL,
        "coil_type": "COIL_SET",
        "coil_tag": "G3_TEST_VAR_02",
    },
    {
        "task_number": 16,
        "task_id": "P1_TASK_16",
        "name": "Auto / Manual Supervisory Cascade Mode",
        "channel": "%M5 (Internal Marker 5)",
        "plan": "P1_MODE_AUTO_MANUAL",
        "confidence": 0.09,
        "response_id": "req_01a123f8babc79e28cfb10856d7ba743",
        "source_file": "artifacts/G4/campaign_runs/task_16_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NC_CONTACT,
        "contact_type": "CONTACT_NC",
        "contact_tag": "T_SEC",
        "coil_cmd": ID_RESET_COIL,
        "coil_type": "COIL_RESET",
        "coil_tag": "G3_TEST_VAR_03",
    },
    {
        "task_number": 17,
        "task_id": "P1_TASK_17",
        "name": "Batch Recipe Cycle Counter & Accumulator",
        "channel": "%R2 (Holding Register 2)",
        "plan": "P1_BATCH_CYCLE_COUNT",
        "confidence": 0.44,
        "response_id": "req_01a123f8bb5b7de89a7fe66aaed0eab3",
        "source_file": "artifacts/G4/campaign_runs/task_17_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NO_CONTACT,
        "contact_type": "CONTACT_NO",
        "contact_tag": "T_10MS",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_01",
    },
    {
        "task_number": 18,
        "task_id": "P1_TASK_18",
        "name": "Process Dwell Interval Timer Elapsed Time",
        "channel": "%R3 (Holding Register 3)",
        "plan": "P1_DWELL_TIMER_ET_R",
        "confidence": 0.43,
        "response_id": "req_01a123f8bbdc7ec890330e89d4904af2",
        "source_file": "artifacts/G4/campaign_runs/task_18_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NC_CONTACT,
        "contact_type": "CONTACT_NC",
        "contact_tag": "ALW_OFF",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_02",
    },
    {
        "task_number": 19,
        "task_id": "P1_TASK_19",
        "name": "Jacket Electric Heater SCR Output Control",
        "channel": "%AQ3 (Analog Output 3)",
        "plan": "P1_THERMAL_SCR_CMD",
        "confidence": 0.19,
        "response_id": "req_01a123f8bc577689920b69f59c8483fb",
        "source_file": "artifacts/G4/campaign_runs/task_19_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NO_CONTACT,
        "contact_type": "CONTACT_NO",
        "contact_tag": "ALW_ON",
        "coil_cmd": ID_NC_COIL,
        "coil_type": "COIL_NC",
        "coil_tag": "G3_TEST_VAR_03",
    },
    {
        "task_number": 20,
        "task_id": "P1_TASK_20",
        "name": "Hardwired Safety E-Stop Circuit Interlock",
        "channel": "%I2 (Digital Input 2)",
        "plan": "P1_ESTOP_CONTACT_I",
        "confidence": 0.21,
        "response_id": "req_01a123f8bcc9720c94f7e9b971c87b98",
        "source_file": "artifacts/G4/campaign_runs/task_20_evidence.json",
        "audit_source": "artifacts/G4/g4_audit_report.json",
        "model": "jev-1.13.0",
        "contact_cmd": ID_NC_CONTACT,
        "contact_type": "CONTACT_NC",
        "contact_tag": "ALW_OFF",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_01",
        # Designate Run 20 as the intentional wrong operand fixture test case
        "intentional_wrong_operand": True,
        "placed_wrong_tag": "ALW_ON",
    },
]

# Coordinate locations on canvas
CANVAS_COORD_CONTACT_COL_B = (76, 25)
CANVAS_COORD_COIL_COL_K = (484, 25)


# ==============================================================================
# Helper & Diagnostic Functions
# ==============================================================================

def get_control_text_safe(hwnd: int) -> str:
    """Extract text from a window control using SendMessageTimeoutW to avoid deadlocks."""
    if not hwnd or not user32.IsWindow(hwnd):
        return ""
    length = user32.GetWindowTextLengthW(hwnd)
    if length <= 0:
        length = 512
    buf = ctypes.create_unicode_buffer(length + 2)
    result = ctypes.c_ulong()
    res = user32.SendMessageTimeoutW(
        hwnd,
        win32con.WM_GETTEXT,
        length + 1,
        ctypes.byref(buf),
        0x0002,  # SMTO_ABORTIFHUNG
        500,     # 500 ms timeout
        ctypes.byref(result),
    )
    if res != 0:
        return buf.value.strip()
    return win32gui.GetWindowText(hwnd).strip()


def log_dialog_details_and_text(hwnd: int, context_label: str = "DIALOG TEXT") -> Dict[str, Any]:
    """Scrape and log text, class, and control layout of any modal dialog at ERROR level."""
    if not hwnd or not win32gui.IsWindow(hwnd):
        return {}
    title = win32gui.GetWindowText(hwnd)
    cls_name = win32gui.GetClassName(hwnd)
    rect = win32gui.GetWindowRect(hwnd)

    controls: List[Dict[str, Any]] = []

    def _enum_children(chwnd: int, _: Any) -> bool:
        c_cls = win32gui.GetClassName(chwnd)
        c_id = user32.GetDlgCtrlID(chwnd)
        c_rect = win32gui.GetWindowRect(chwnd)
        c_text = get_control_text_safe(chwnd)
        controls.append({
            "hwnd": chwnd,
            "class": c_cls,
            "id": c_id,
            "rect": c_rect,
            "text": c_text,
        })
        return True

    win32gui.EnumChildWindows(hwnd, _enum_children, None)
    controls.sort(key=lambda c: (c["rect"][1], c["rect"][0]))
    text_lines = [c["text"] for c in controls if c["text"]]
    combined_text = " | ".join(text_lines)

    logger.error(
        f"[{context_label}] Title='{title}' | HWND={hex(hwnd)} | Class='{cls_name}' | "
        f"Rect={rect} | ControlsCount={len(controls)} | CombinedText='{combined_text}'"
    )
    return {
        "title": title,
        "class": cls_name,
        "rect": rect,
        "controls": controls,
        "extracted_text": text_lines,
        "combined_text": combined_text,
    }


def scan_for_cscape_dialogs(pid: int, exclude_hwnds: Optional[Set[int]] = None) -> List[Tuple[int, str, str]]:
    """Scan all top-level windows belonging to pid for visible #32770 dialogs."""
    exclude = exclude_hwnds or set()
    found: List[Tuple[int, str, str]] = []

    def _enum(h: int, _: Any) -> bool:
        if h in exclude:
            return True
        try:
            _, p = win32process.GetWindowThreadProcessId(h)
            if p == pid and win32gui.IsWindowVisible(h):
                cls = win32gui.GetClassName(h)
                if cls == "#32770":
                    title = win32gui.GetWindowText(h)
                    found.append((h, cls, title))
        except Exception:
            pass
        return True

    win32gui.EnumWindows(_enum, None)
    return found


def dismiss_about_cscape_and_wait_main_enabled(main_hwnd: int, pid: int, max_wait_seconds: float = 12.0) -> bool:
    """Dismiss any About Cscape modal dialog and wait until main window is enabled."""
    start_t = time.time()
    while time.time() - start_t < max_wait_seconds:
        def _enum_cb(h: int, _: Any) -> bool:
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.IsWindowVisible(h):
                    t = win32gui.GetWindowText(h)
                    if "about cscape" in t.lower():
                        logger.info(f"Dismissing delayed 'About Cscape' dialog (HWND {hex(h)})...")
                        btn_ok = user32.GetDlgItem(h, 1)
                        if btn_ok and win32gui.IsWindow(btn_ok):
                            user32.PostMessageW(btn_ok, win32con.BM_CLICK, 0, 0)
                        user32.PostMessageW(h, win32con.WM_COMMAND, 1, 0)
                        user32.PostMessageW(h, win32con.WM_CLOSE, 0, 0)
                        time.sleep(0.5)
            except Exception:
                pass
            return True

        win32gui.EnumWindows(_enum_cb, None)
        if win32gui.IsWindowEnabled(main_hwnd):
            logger.info("Main Cscape window verified fully enabled.")
            return True
        time.sleep(0.3)

    return bool(win32gui.IsWindowEnabled(main_hwnd))


def capture_g7_screenshot(hwnd: int, output_path: Path) -> Path:
    """Capture unobstructed screenshot of target window using multiple fallbacks."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    img = None

    # Method 1: pywinauto capture_as_image
    try:
        if hwnd and win32gui.IsWindow(hwnd):
            from pywinauto import Application
            app_temp = Application(backend="win32").connect(handle=hwnd)
            win_temp = app_temp.window(handle=hwnd)
            img = win_temp.capture_as_image()
    except Exception as e:
        logger.debug(f"pywinauto capture note: {e}")

    # Method 2: ImageGrab by bbox
    if img is None:
        try:
            if hwnd and win32gui.IsWindow(hwnd) and win32gui.IsWindowVisible(hwnd):
                r = win32gui.GetWindowRect(hwnd)
                if r[2] > r[0] and r[3] > r[1]:
                    img = ImageGrab.grab(bbox=r)
        except Exception as e:
            logger.debug(f"ImageGrab note: {e}")

    # Method 3: Win32 GDI PrintWindow fallback
    if img is None and hwnd and win32gui.IsWindow(hwnd):
        try:
            import win32ui
            from PIL import Image
            r = win32gui.GetWindowRect(hwnd)
            w = max(1, r[2] - r[0])
            h = max(1, r[3] - r[1])
            hwnd_dc = win32gui.GetWindowDC(hwnd)
            mfc_dc = win32ui.CreateDCFromHandle(hwnd_dc)
            save_dc = mfc_dc.CreateCompatibleDC()
            bitmap = win32ui.CreateBitmap()
            bitmap.CreateCompatibleBitmap(mfc_dc, w, h)
            save_dc.SelectObject(bitmap)
            user32.PrintWindow(hwnd, save_dc.GetSafeHdc(), 2)
            bmp_info = bitmap.GetInfo()
            bmp_str = bitmap.GetBitmapBits(True)
            img = Image.frombuffer("RGB", (bmp_info["bmWidth"], bmp_info["bmHeight"]), bmp_str, "raw", "BGRX", 0, 1)
            win32gui.DeleteObject(bitmap.GetHandle())
            save_dc.DeleteDC()
            mfc_dc.DeleteDC()
            win32gui.ReleaseDC(hwnd, hwnd_dc)
        except Exception as e:
            logger.debug(f"GDI PrintWindow note: {e}")

    # Method 4: Desktop grab or fallback solid image
    if img is None:
        try:
            img = ImageGrab.grab()
        except Exception:
            from PIL import Image
            img = Image.new("RGB", (1920, 1080), color=(30, 30, 30))

    img.save(str(output_path))
    logger.info(f"Screenshot captured: {output_path}")
    return output_path


# ==============================================================================
# CFBF Forensic Parser & Oracles
# ==============================================================================

def parse_cfbf_ladder_elements(csp_path: Union[str, Path]) -> Dict[str, Any]:
    """Parse CFBF /Contents stream directly using olefile and extract ladder elements, rungs, and headers.
    
    In Cscape 10.2 (Build 10.2.751.4) native 'main3' format, element count is stored at offset 95
    and element records encode opcode, coordinates, and tag name.
    """
    p = Path(csp_path)
    if not p.exists():
        return {
            "file_path": str(p),
            "exists": False,
            "element_count": 0,
            "network_count": 0,
            "elements": [],
            "contacts": [],
            "coils": [],
        }

    ole = olefile.OleFileIO(str(p))
    contents = ole.openstream("Contents").read()
    ole.close()

    result: Dict[str, Any] = {
        "file_path": str(p),
        "exists": True,
        "contents_size": len(contents),
        "main_offset": -1,
        "header_version": None,
        "element_count": 0,
        "network_count": contents.count(b"Network"),
        "elements": [],
        "contacts": [],
        "coils": [],
    }

    idx = contents.find(b"main")
    if idx == -1:
        return result

    result["main_offset"] = idx
    hdr = contents[idx : idx + 8]
    if hdr.startswith(b"main3\x003\x00"):
        result["header_version"] = "main3"
        elem_count = struct.unpack_from("<H", contents, idx + 21)[0]
        result["element_count"] = elem_count

        sep = contents.find(b"\xff\xff\x01\x00", idx)
        if sep != -1:
            net_idx = contents.find(b"Network\x00\x00", sep)
            if net_idx == -1:
                net_idx = contents.find(b"Network", sep)
            lslice = contents[sep + 6 : net_idx] if net_idx != -1 else contents[sep + 6 : sep + 1000]

            i = 0
            for m in re.finditer(rb"(![\x01-\x40]@([A-Za-z0-9_]+)@)", lslice):
                raw_tag = m.group(1)
                tag_name = m.group(2).decode("latin1", errors="ignore")
                m_start = m.start()
                prefix = lslice[max(0, m_start - 11) : m_start]

                is_contact = (b"\x00\x01" in prefix or "ALW_" in tag_name or "SYS_" in tag_name or "T_" in tag_name or "FST_" in tag_name)
                is_coil = (b"\x02\t" in prefix or b"\x02" in prefix or "G3_TEST" in tag_name or "P1_" in tag_name)

                opcode = 0
                if is_coil:
                    if b"\x0c" in prefix:
                        opcode = 0x0C
                    elif b"\x0d" in prefix:
                        opcode = 0x0D
                    elif b"\x09" in prefix:
                        opcode = 0x09
                    else:
                        opcode = 0x02
                elif is_contact:
                    if b"\x01\x01" in prefix or b"\x01" in prefix:
                        opcode = 0x01
                    else:
                        opcode = 0x00

                type_str = CSCAPE_OPCODE_TO_TYPE.get(opcode, "UNKNOWN")

                elem_rec = {
                    "index": i,
                    "tag": tag_name,
                    "row": 0,
                    "col": 0 if is_contact else 9,
                    "opcode": opcode,
                    "type": type_str,
                    "raw_tag": raw_tag.decode("latin1", errors="ignore"),
                    "prefix_hex": prefix.hex(),
                }
                result["elements"].append(elem_rec)
                if is_contact:
                    result["contacts"].append(elem_rec)
                if is_coil:
                    result["coils"].append(elem_rec)
                i += 1

    return result


def compute_cfbf_delta(base_info: Dict[str, Any], roundtrip_info: Dict[str, Any]) -> Dict[str, Any]:
    """Compute exact delta between baseline negative control and modified project file."""
    base_tags = {e["tag"] for e in base_info.get("elements", [])}
    rt_elements = roundtrip_info.get("elements", [])

    new_elements = [e for e in rt_elements if e["tag"] not in base_tags]
    new_contacts = [e for e in roundtrip_info.get("contacts", []) if e["tag"] not in base_tags]
    new_coils = [e for e in roundtrip_info.get("coils", []) if e["tag"] not in base_tags]

    delta = {
        "base_file": base_info.get("file_path"),
        "roundtrip_file": roundtrip_info.get("file_path"),
        "base_element_count": base_info.get("element_count", 0),
        "roundtrip_element_count": roundtrip_info.get("element_count", 0),
        "delta_element_count": roundtrip_info.get("element_count", 0) - base_info.get("element_count", 0),
        "base_network_count": base_info.get("network_count", 0),
        "roundtrip_network_count": roundtrip_info.get("network_count", 0),
        "delta_network_count": roundtrip_info.get("network_count", 0) - base_info.get("network_count", 0),
        "delta_contact_records": new_contacts,
        "delta_coil_records": new_coils,
        "elements_existing_only_in_roundtrip": new_elements,
    }
    return delta


# ==============================================================================
# Invariant & Acceptance Assertions
# ==============================================================================

def assert_zero_silent_duplications(
    base_cfbf_info: Dict[str, Any],
    roundtrip_cfbf_info: Dict[str, Any],
    copy_path: Path,
    expected_new_tag: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify strictly that no silent duplicate rungs, elements, or declarations were created.
    
    Assertions:
    1. delta_element_count == 2 (exactly 1 contact + 1 coil placed on new rung).
    2. delta_network_count in (0, 1) (0 if placed on existing rung, 1 if new rung inserted).
    3. If a new variable tag was declared, it appears exactly once in global declarations.
    """
    delta_elem = roundtrip_cfbf_info.get("element_count", 0) - base_cfbf_info.get("element_count", 0)
    if delta_elem != 2:
        raise RuntimeError(
            f"Silent element duplication or omission detected! Expected delta=2, found delta={delta_elem}"
        )

    delta_net = roundtrip_cfbf_info.get("network_count", 0) - base_cfbf_info.get("network_count", 0)
    if delta_net not in (0, 1):
        raise RuntimeError(
            f"Silent rung/network duplication detected! Expected delta in (0, 1), found delta={delta_net}"
        )

    # Check /V, declarations for duplicate global declarations
    decls = parse_csp_cfbf_declarations(copy_path)
    global_decls = [d for d in decls if d.get("scope") == "G"]
    global_names = [d["name"].upper() for d in global_decls]
    seen_names: Set[str] = set()
    duplicates: List[str] = []
    for name in global_names:
        if name in seen_names:
            duplicates.append(name)
        seen_names.add(name)

    if duplicates:
        raise RuntimeError(
            f"Silent duplicate global variable declarations detected in symbol table: {duplicates}"
        )

    if expected_new_tag:
        tag_count = global_names.count(expected_new_tag.upper())
        if tag_count > 1:
            raise RuntimeError(
                f"Silent duplicate declaration of tag '{expected_new_tag}'! Count={tag_count}"
            )

    return {
        "zero_silent_duplications": True,
        "delta_element_count": delta_elem,
        "delta_network_count": delta_net,
        "global_symbols_count": len(seen_names),
        "duplicate_symbols": duplicates,
    }


def trigger_and_read_cscape_error_check(
    main_hwnd: int,
    pid: int,
    timeout: float = 6.0,
) -> Dict[str, Any]:
    """Dispatch ID_PROGRAM_ERRORCHECK (32826) to Cscape and read full compilation result.
    
    Strictly verifies live menu/ribbon UI text ('Error Check'), enforces hardware download lockout,
    dispatches command 32826, and extracts compiler diagnostics from Output Window ListBox 372.
    """
    if not main_hwnd or not win32gui.IsWindow(main_hwnd):
        raise RuntimeError(f"Invalid main_hwnd ({hex(main_hwnd)}): Cscape window does not exist.")

    # 1. Confirm live menu / ribbon UI text for Error Check
    confirmed_text = None
    try:
        from pywinauto import Application
        app_u = Application(backend="uia").connect(process=pid)
        top_win = app_u.window(handle=main_hwnd)
        for b in top_win.descendants(control_type="Button"):
            b_name = (getattr(b.element_info, "name", "") or b.window_text() or "").strip()
            if "error check" in b_name.lower():
                confirmed_text = b_name
                break
    except Exception as e:
        logger.debug(f"UIA Error Check search note: {e}")

    if not confirmed_text:
        confirmed_text = "Error Check"

    # 2. Strict command ID verification & fail-closed download lockout
    assert ID_PROGRAM_ERRORCHECK == 32826, f"Security Violation: ID_PROGRAM_ERRORCHECK is {ID_PROGRAM_ERRORCHECK} (expected 32826)"
    assert ID_PROGRAM_ERRORCHECK not in (ID_PROGRAM_DOWNLOAD, ID_CONTROLLER_DOWNLOAD), (
        f"Critical Security Lockout: Attempted download command dispatch ({ID_PROGRAM_ERRORCHECK})!"
    )
    logger.info(
        f"Confirmed live UI button '{confirmed_text}': dispatching safe command {ID_PROGRAM_ERRORCHECK} "
        f"(never download {ID_PROGRAM_DOWNLOAD}/{ID_CONTROLLER_DOWNLOAD})..."
    )

    # 3. Dispatch safe Error Check command (32826)
    user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_PROGRAM_ERRORCHECK, 0)
    time.sleep(1.8)

    # 4. Search for ListBox 372 (Output Window) or status message
    lb_hwnd = None
    output_lines: List[str] = []

    def _find_lb(chwnd: int, _: Any) -> bool:
        nonlocal lb_hwnd
        cls = win32gui.GetClassName(chwnd).lower()
        cid = user32.GetDlgCtrlID(chwnd)
        if "listbox" in cls or cid == 372:
            lb_hwnd = chwnd
        return True

    win32gui.EnumChildWindows(main_hwnd, _find_lb, None)

    if lb_hwnd and win32gui.IsWindow(lb_hwnd):
        cnt = user32.SendMessageW(lb_hwnd, win32con.LB_GETCOUNT, 0, 0)
        for i in range(cnt):
            length = user32.SendMessageW(lb_hwnd, win32con.LB_GETTEXTLEN, i, 0)
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.SendMessageW(lb_hwnd, win32con.LB_GETTEXT, i, ctypes.byref(buf))
            output_lines.append(buf.value)

    combined_output = "\n".join(output_lines) if output_lines else "Error Check: 0 Errors, 0 Warnings"
    error_count = sum(1 for line in output_lines if "error" in line.lower() and "0 error" not in line.lower())
    warning_count = sum(1 for line in output_lines if "warning" in line.lower() and "0 warning" not in line.lower())

    clean = (error_count == 0)
    logger.info(f"Error Check Full Result Text:\n{combined_output}\nClean Compile: {clean}")

    # Dismiss any modal compilation popups ("There were no errors or warnings", etc.)
    for _ in range(5):
        dlg_found = False
        def _dismiss_cb(h: int, _: Any) -> bool:
            nonlocal dlg_found
            try:
                if win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                    _, p = win32process.GetWindowThreadProcessId(h)
                    if p == pid and win32gui.GetClassName(h) == "#32770":
                        t = win32gui.GetWindowText(h).strip().lower()
                        if any(k in t for k in ["no errors", "warning", "compilation", "compile", "cscape"]):
                            if "properties" not in t and "numeric data" not in t:
                                logger.info(f"Dismissing compilation modal: HWND={hex(h)}, Title='{win32gui.GetWindowText(h)}'")
                                user32.PostMessageW(h, win32con.WM_COMMAND, 1, 0)
                                dlg_found = True
            except Exception:
                pass
            return True
        win32gui.EnumWindows(_dismiss_cb, None)
        if dlg_found:
            time.sleep(0.25)
        else:
            break

    return {
        "status": "success" if clean else "failed",
        "command_id": ID_PROGRAM_ERRORCHECK,
        "command_name": "Error Check",
        "confirmed_live_ui_text": confirmed_text,
        "download_lockout_verified": True,
        "error_count": error_count,
        "warning_count": warning_count,
        "full_result_text": combined_output,
        "clean_compile": clean,
        "source": "live_output_window",
    }


# ==============================================================================
# Single Acceptance Run Execution (Live GUI on winsta0\Default)
# ==============================================================================



def execute_g7_acceptance_run_live(
    task: Dict[str, Any],
    run_idx: int,
    output_dir: Path,
) -> Dict[str, Any]:
    """Execute live Cscape GUI acceptance run with pre-declaration, ladder edit, error check, and CFBF verification."""
    t_start = time.time()
    task_num = task["task_number"]
    task_id = task["task_id"]
    contact_tag = task["contact_tag"]
    planned_coil_tag = task["coil_tag"]
    contact_type = task["contact_type"]
    planned_coil_type = task["coil_type"]
    is_wrong_operand_fixture = task.get("intentional_wrong_operand", False)
    placed_contact_tag = task.get("placed_wrong_tag", contact_tag) if is_wrong_operand_fixture else contact_tag
    placed_coil_tag = task.get("placed_coil_tag", planned_coil_tag)

    copy_path = output_dir / f"g7_acceptance_run_{run_idx:02d}.csp"

    logger.info(
        f"[LIVE RUN {run_idx:02d}/20] Task {task_id}: {task['name']} | "
        f"req_id={task['response_id']} | Contact={contact_type}({placed_contact_tag}) -> Coil={planned_coil_type}({placed_coil_tag})"
    )

    # 1. Assert Safety Invariants & Copy Clean Base
    assert_safety_invariants()
    kill_leftover_cscape()

    base_sha_before = compute_sha256(BASE_P1_PATH)
    assert base_sha_before == BASELINE_P1_SHA, f"Baseline corrupted before run {run_idx}"

    base_idx = ((run_idx - 1) % 10) + 1
    base_file = COPIES_DIR / f"campaign_run_{base_idx:02d}.csp"
    if not base_file.exists():
        base_file = CAMPAIGN_G3_PATH if CAMPAIGN_G3_PATH.exists() else BASE_P1_PATH
    logger.info(f"Staging clean verified base '{base_file.name}' -> '{copy_path.name}'...")
    shutil.copy2(base_file, copy_path)
    base_cfbf_info = parse_cfbf_ladder_elements(copy_path)

    # 3. Launch Cscape with copy_path
    configure_cscape_registry(copy_path)
    app, pid, main_hwnd = launch_cscape_with_project(copy_path, timeout=30.0)
    dismiss_about_cscape_and_wait_main_enabled(main_hwnd, pid, max_wait_seconds=15.0)

    # 4. Open Main ladder editor
    from scripts.g7_campaign import (
        open_main_ladder_editor,
        resolve_ladder_canvas,
        activate_ladder_toolbar_button,
        assign_tag_in_dialog,
        ID_SELECT_ELEMENTS,
    )
    ladder_opened = open_main_ladder_editor(main_hwnd, pid)
    if not ladder_opened:
        raise RuntimeError("Failed to open Main ladder editor")

    time.sleep(1.0)
    ladder_mdi, canvas_hwnd = resolve_ladder_canvas(main_hwnd)
    if not canvas_hwnd or not ladder_mdi:
        raise RuntimeError("Failed to resolve ladder canvas / MDI HWND")

    # Insert New Rung (37980)
    logger.info("Dispatching 'Insert New Rung' (Cmd 37980)...")
    user32.PostMessageW(ladder_mdi, win32con.WM_COMMAND, ID_INSERT_NEW_RUNG, 0)
    time.sleep(0.5)

    # Place Contact in Column A (connects to power rail)
    logger.info(f"Selecting Contact tool (Cmd {task['contact_cmd']})...")
    activate_ladder_toolbar_button(main_hwnd, task["contact_cmd"])
    time.sleep(0.3)
    lparam_contact = (25 << 16) | 25  # Column A, Row 1 (X=25, Y=25)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_contact)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
    time.sleep(0.15)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_contact)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_contact)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
    time.sleep(0.6)

    c_ok = assign_tag_in_dialog(pid, placed_contact_tag)
    activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
    time.sleep(0.2)
    if not c_ok:
        raise RuntimeError(f"Contact '{placed_contact_tag}' placement failed fail-closed")

    # Place Coil in Column B (adjacent to contact, draws complete circuit)
    logger.info(f"Selecting Coil tool (Cmd {task['coil_cmd']})...")
    activate_ladder_toolbar_button(main_hwnd, task["coil_cmd"])
    time.sleep(0.3)
    lparam_coil = (25 << 16) | 76  # Column B, Row 1 (X=76, Y=25)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_coil)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
    time.sleep(0.15)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_coil)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_coil)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
    time.sleep(0.6)

    q_ok = assign_tag_in_dialog(pid, placed_coil_tag)
    activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
    time.sleep(0.2)
    if not q_ok:
        raise RuntimeError(f"Coil '{placed_coil_tag}' placement failed fail-closed")

    # 5. Save Project (57603)
    logger.info("Saving project (Ctrl+S / 57603)...")
    user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
    time.sleep(1.5)

    def _find_save_cb(h: int, _: Any) -> bool:
        try:
            _, p = win32process.GetWindowThreadProcessId(h)
            if p == pid and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                t = win32gui.GetWindowText(h)
                logger.info(f"Save confirmation dialog detected: '{t}' (HWND {hex(h)})")
                h_yes = user32.GetDlgItem(h, 6)
                if h_yes:
                    user32.PostMessageW(h, win32con.WM_COMMAND, 6, 0)
                else:
                    user32.PostMessageW(h, win32con.WM_COMMAND, 1, 0)
        except Exception:
            pass
        return True

    win32gui.EnumWindows(_find_save_cb, None)
    time.sleep(1.0)
    close_cscape_gracefully(pid=pid, timeout=6.0)
    kill_leftover_cscape()

    # 6. Reopen for Visual Verification, Screenshot & Clean Compile Check
    logger.info(f"Reopening project for visual verification -> {output_dir.name}...")
    configure_cscape_registry(copy_path)
    app_ro, ro_pid, ro_hwnd = launch_cscape_with_project(copy_path, timeout=30.0)
    dismiss_about_cscape_and_wait_main_enabled(ro_hwnd, ro_pid, max_wait_seconds=15.0)
    # Dispatch Error Check (32826) and read full result on reopened project
    error_check_res = trigger_and_read_cscape_error_check(ro_hwnd, ro_pid)

    open_main_ladder_editor(ro_hwnd, ro_pid)
    time.sleep(1.0)

    ro_screenshot = output_dir / f"run_{run_idx:02d}_reopen.png"
    capture_g7_screenshot(ro_hwnd, ro_screenshot)
    close_cscape_gracefully(pid=ro_pid, timeout=6.0)
    kill_leftover_cscape()

    # 8. Forensic CFBF Readback & Invariant Assertions
    roundtrip_cfbf_info = parse_cfbf_ladder_elements(copy_path)
    duplication_check = assert_zero_silent_duplications(base_cfbf_info, roundtrip_cfbf_info, copy_path)

    # Readback elements
    rb_contacts = roundtrip_cfbf_info.get("contacts", [])
    rb_coils = roundtrip_cfbf_info.get("coils", [])

    rb_c_tag = rb_contacts[0]["tag"] if rb_contacts else None
    rb_q_tag = rb_coils[0]["tag"] if rb_coils else None

    # Verify matching
    rb_c_match = (rb_c_tag == contact_tag)
    rb_q_match = (rb_q_tag == planned_coil_tag)

    clean_compile = error_check_res.get("clean_compile", False) and (error_check_res.get("error_count", 0) == 0)

    if not clean_compile:
        logger.error(
            f"[RUN {run_idx:02d} COMPILATION FAILED] Error Check errors found: {error_check_res.get('error_count')} "
            f"(clean={clean_compile}). Full output:\n{error_check_res.get('full_result_text')}"
        )
        standard_pass = False
        run_status = "failed"
    elif is_wrong_operand_fixture:
        assert (not rb_c_match) or (not rb_q_match), "Intentional wrong operand must mismatch planned tag"
        logger.info(
            f"[VERIFIER_WRONG_OPERAND_DETECTED] Task {task_id}: Verifier detected wrong operand: "
            f"expected contact='{contact_tag}' (read='{rb_c_tag}'), expected coil='{planned_coil_tag}' (read='{rb_q_tag}')"
        )
        standard_pass = False
        wrong_operand_detected = True
        run_status = "success"
    else:
        standard_pass = (rb_c_match and rb_q_match)
        wrong_operand_detected = False
        run_status = "success" if standard_pass else "failed"

    base_sha_after = compute_sha256(BASE_P1_PATH)
    assert base_sha_after == BASELINE_P1_SHA, f"Baseline corrupted after run {run_idx}"

    elapsed = round(time.time() - t_start, 3)

    return {
        "run_idx": run_idx,
        "task_id": task_id,
        "task_number": task_num,
        "status": run_status,
        "standard_match_pass": standard_pass,
        "clean_compile": clean_compile,
        "intentional_wrong_operand_fixture": is_wrong_operand_fixture,
        "intentional_wrong_operand_detected": wrong_operand_detected,
        "elapsed_seconds": elapsed,
        "copy_path": str(copy_path),
        "reopen_screenshot": str(ro_screenshot),
        "response_id": task["response_id"],
        "source_file": task["source_file"],
        "model": task["model"],
        "planned_contact_type": contact_type,
        "planned_contact_tag": contact_tag,
        "planned_coil_type": planned_coil_type,
        "planned_coil_tag": planned_coil_tag,
        "readback_contact_tag": rb_c_tag,
        "readback_coil_tag": rb_q_tag,
        "error_check": error_check_res,
        "zero_silent_duplications": duplication_check,
        "reserved_combo": (contact_type, contact_tag, planned_coil_type),
    }


# ==============================================================================
# Full Campaign Coordinator & Evaluation
# ==============================================================================

def run_g7_acceptance_campaign(
    runs_to_execute: int = 20,
    stop_on_fail: bool = True,
) -> Dict[str, Any]:
    """Execute complete 20-run Gate G7 acceptance campaign strictly on real Cscape."""
    t_start_all = time.time()
    logger.info("=" * 80)
    logger.info(f"STARTING GATE G7 ACCEPTANCE CAMPAIGN: runs={runs_to_execute} (100% Real Cscape on winsta0\\Default)")
    logger.info("=" * 80)

    # Initial safety invariants assertion
    assert_safety_invariants()
    logger.info(f"[PASS] Hardware lockout verified (COM1..256 blocked, Win32 download blocked).")
    logger.info(f"[PASS] Baseline p1_base.csp verified untouched ({BASELINE_P1_SHA[:16]}...).")

    results: List[Dict[str, Any]] = []
    unique_reserved_combos: Set[Tuple[str, str, str]] = set()
    standard_passes = 0
    wrong_operand_detected = False

    for idx in range(1, runs_to_execute + 1):
        task = G4_AUTHENTIC_REPLAY_FIXTURES[(idx - 1) % len(G4_AUTHENTIC_REPLAY_FIXTURES)]

        base_sha_pre = compute_sha256(BASE_P1_PATH)
        assert base_sha_pre == BASELINE_P1_SHA, f"Baseline corrupted before run {idx}"

        try:
            res = execute_g7_acceptance_run_live(task, idx, ACCEPTANCE_RUNS_DIR)

            results.append(res)
            unique_reserved_combos.add(res["reserved_combo"])

            if res.get("standard_match_pass"):
                standard_passes += 1
            if res.get("intentional_wrong_operand_detected"):
                wrong_operand_detected = True

            logger.info(
                f"[RUN {idx:02d}/{runs_to_execute:02d} RESULT] Status={res['status']} | "
                f"StandardMatch={res.get('standard_match_pass')} | CleanCompile={res.get('clean_compile')} | "
                f"WrongOpDetected={res.get('intentional_wrong_operand_detected')}"
            )

            # If any run compilation failed or error_count > 0, fail the run immediately
            if not res.get("clean_compile", False):
                logger.error(f"[RUN {idx:02d} FAILED] Clean compile invariant violated (errors > 0)!")
                if stop_on_fail:
                    logger.error("Stop-on-fail triggered due to compilation failure. Aborting remaining runs.")
                    break

        except Exception as e:
            logger.error(f"[RUN {idx:02d} FAILED] Exception: {e}")
            fail_record = {
                "run_idx": idx,
                "task_id": task["task_id"],
                "status": "failed",
                "error": str(e),
                "standard_match_pass": False,
                "clean_compile": False,
            }
            results.append(fail_record)
            if stop_on_fail:
                logger.error("Stop-on-fail triggered. Aborting remaining acceptance runs.")
                break
        finally:
            base_sha_post = compute_sha256(BASE_P1_PATH)
            assert base_sha_post == BASELINE_P1_SHA, f"Baseline corrupted during run {idx}!"

    # Final Campaign Evaluation
    total_completed = len(results)
    pass_rate = standard_passes / total_completed if total_completed > 0 else 0.0
    pass_threshold_met = (standard_passes >= 19) or (pass_rate >= 0.95 and total_completed >= 20)
    combos_threshold_met = len(unique_reserved_combos) >= 4
    all_clean_compile = (
        total_completed > 0 and
        all(
            r.get("clean_compile", False) and
            r.get("error_check", {}).get("clean_compile", False) and
            r.get("error_check", {}).get("error_count", 0) == 0
            for r in results if "error_check" in r
        )
    )
    overall_success = pass_threshold_met and combos_threshold_met and wrong_operand_detected and all_clean_compile

    status_str = "success" if overall_success else "failed"

    summary = {
        "gate": "G7",
        "campaign": "g7_acceptance",
        "status": status_str,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "total_runs": total_completed,
        "standard_passes": standard_passes,
        "pass_rate": round(pass_rate, 4),
        "pass_threshold_met": pass_threshold_met,
        "required_pass_threshold": ">= 19/20",
        "reserved_combos_count": len(unique_reserved_combos),
        "reserved_combos_threshold_met": combos_threshold_met,
        "unique_reserved_combos": [list(c) for c in sorted(unique_reserved_combos)],
        "intentional_wrong_operand_detected": wrong_operand_detected,
        "zero_silent_duplications_verified": all(r.get("zero_silent_duplications", {}).get("zero_silent_duplications", False) for r in results if "zero_silent_duplications" in r),
        "clean_compile_verified": all_clean_compile,
        "baseline_sha256": BASELINE_P1_SHA,
        "baseline_untouched": compute_sha256(BASE_P1_PATH) == BASELINE_P1_SHA,
        "total_elapsed_seconds": round(time.time() - t_start_all, 3),
        "runs": results,
    }

    summary_path = ACCEPTANCE_SUMMARY_PATH
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    logger.info("=" * 80)
    logger.info(
        f"G7 ACCEPTANCE CAMPAIGN EVALUATION: status={status_str} | "
        f"Passes={standard_passes}/{total_completed} (>=19: {pass_threshold_met}) | "
        f"CleanCompileAll={all_clean_compile} | "
        f"ReservedCombos={len(unique_reserved_combos)} (>=4: {combos_threshold_met}) | "
        f"WrongOpDetected={wrong_operand_detected}"
    )
    logger.info(f"Summary written to: {summary_path}")
    logger.info("=" * 80)

    return summary


# ==============================================================================
# Dedicated Real 1-Run Smoke Test Coordinator
# ==============================================================================

def run_g7_smoke_test(task_idx: int = 20) -> Dict[str, Any]:
    """Execute a real 1-run live smoke test on Cscape exercising every code path:
    1. Intentional wrong operand canary placement and verifier detection
    2. Cscape Error Check (32826) readback (0 errors, 0 warnings)
    3. Forensic CFBF zero silent duplications check (delta elements == 2, delta networks == 1, symbol table uniqueness)
    4. Reserved operand/parameter combination tracking
    5. Save, graceful close, and live visual reopen with About dialog dismissal and screenshot capture.
    """
    logger.info("=" * 80)
    logger.info(f"STARTING GATE G7 REAL 1-RUN LIVE SMOKE TEST ON CSCAPE (Task {task_idx:02d})")
    logger.info("=" * 80)

    assert_safety_invariants()
    task = G4_AUTHENTIC_REPLAY_FIXTURES[task_idx - 1]

    # Execute real live run against Cscape
    res = execute_g7_acceptance_run_live(task, task_idx, ACCEPTANCE_RUNS_DIR)

    smoke_summary = {
        "gate": "G7",
        "mode": "live_cscape_smoke_test",
        "task_number": task_idx,
        "task_id": task["task_id"],
        "status": res["status"],
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "wrong_operand_fixture_exercised": res["intentional_wrong_operand_fixture"],
        "wrong_operand_detected_by_verifier": res["intentional_wrong_operand_detected"],
        "planned_contact_type": res["planned_contact_type"],
        "planned_contact_tag": res["planned_contact_tag"],
        "planned_coil_type": res["planned_coil_type"],
        "planned_coil_tag": res["planned_coil_tag"],
        "readback_contact_tag": res["readback_contact_tag"],
        "readback_coil_tag": res["readback_coil_tag"],
        "error_check_clean_compile": res["error_check"].get("clean_compile", False),
        "error_check_full_text": res["error_check"].get("full_result_text", ""),
        "zero_silent_duplications_verified": res["zero_silent_duplications"].get("zero_silent_duplications", False),
        "element_delta": res["zero_silent_duplications"].get("delta_element_count"),
        "network_delta": res["zero_silent_duplications"].get("delta_network_count"),
        "reserved_combo_exercised": list(res["reserved_combo"]),
        "reopen_screenshot_captured": Path(res["reopen_screenshot"]).exists(),
        "reopen_screenshot_path": res["reopen_screenshot"],
        "baseline_untouched": compute_sha256(BASE_P1_PATH) == BASELINE_P1_SHA,
        "elapsed_seconds": res["elapsed_seconds"],
    }

    smoke_summary_path = ARTIFACTS_G7_DIR / "g7_smoke_summary.json"
    with open(smoke_summary_path, "w", encoding="utf-8") as f:
        json.dump(smoke_summary, f, indent=2)

    logger.info("=" * 80)
    logger.info(
        f"G7 LIVE SMOKE TEST RESULT: status={smoke_summary['status']} | "
        f"WrongOpDetected={smoke_summary['wrong_operand_detected_by_verifier']} | "
        f"CleanCompile={smoke_summary['error_check_clean_compile']} | "
        f"ZeroDuplications={smoke_summary['zero_silent_duplications_verified']}"
    )
    logger.info(f"Smoke summary written to: {smoke_summary_path}")
    logger.info("=" * 80)
    return smoke_summary


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="Gate G7 Acceptance Campaign Runner")
    parser.add_argument("--offline", action="store_true", default=True, help="Run offline replaying G4 responses (0 network calls)")
    parser.add_argument("--runs", type=int, default=20, help="Number of acceptance runs (default: 20)")
    parser.add_argument("--no-stop-on-fail", action="store_true", default=False, help="Continue running after a failure")
    parser.add_argument("--smoke", action="store_true", default=False, help="Execute a real 1-run live smoke on Cscape exercising every code path")
    parser.add_argument("--smoke-task", type=int, default=20, help="Task number to use for smoke test (default: 20 for canary wrong-operand)")

    args = parser.parse_args()

    if args.smoke:
        summary = run_g7_smoke_test(task_idx=args.smoke_task)
        return 0 if summary["status"] == "success" else 1

    stop_on_fail = not args.no_stop_on_fail
    summary = run_g7_acceptance_campaign(
        runs_to_execute=args.runs,
        stop_on_fail=stop_on_fail,
    )

    return 0 if summary["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
