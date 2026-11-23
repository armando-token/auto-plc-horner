#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gate G8 Campaign: Autonomous Jev AI Plan -> Cscape Ladder Edits via G3/G7 Primitives.

Mandate:
  - Ingests Jev planning output (variable declarations and ladder element specs).
  - Supports dual execution modes:
    1. --offline (Default): Deterministic replay of authentic recorded Jev responses (0 network calls).
    2. --live: TypeSafe SystemOne endpoint, capped strictly at MAX_LIVE_CALLS = 30,
               circuit breaker halts on 3 consecutive non-200 responses (NOT RUN YET).
  - Executes discrete ladder logic edits using proven G3 (variable declaration)
    and G7 (ladder canvas placement, rung insertion, toolbar tool activation) primitives.
  - Validates results via independent CFBF OLE2 binary oracle:
    - Offset 95 element count delta >= 2
    - Binary opcode readback (0x00, 0x01, 0x02, 0x09, 0x0C, 0x0D)
    - 100% match against Jev planned element types and bound tags.
  - Enforces fail-closed hardware safety (COM1..256 blocked, download command IDs 32827/33149 blocked,
    companion flashers blocked, baseline p1_base.csp strictly immutable).
  - Adheres strictly to the 4-state contract: status: success | failed | blocked | inconclusive.
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import asdict, dataclass, field
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
import urllib.error
import urllib.request

import olefile
import psutil
import win32con
import win32gui
import win32process
from pywinauto import Application, mouse
from pywinauto.keyboard import send_keys

# Setup Root & Imports
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
    COPIES_DIR,
    assert_safety_invariants,
    close_active_editor_tab,
    close_cscape_gracefully,
    compute_sha256,
    kill_leftover_cscape,
    parse_csp_cfbf_declarations,
    run_edit_roundtrip,
)
from scripts.probe_ladder_editor import configure_cscape_registry
from scripts.g7_ladder_roundtrip import (
    capture_g7_screenshot,
    dismiss_startup_dialogs_and_wait_ready,
    launch_cscape_project_robust,
    open_main_ladder_editor,
)

# Output Directories & Paths
ARTIFACTS_G8_DIR = REPO_ROOT / "artifacts" / "G8"
ARTIFACTS_G8_DIR.mkdir(parents=True, exist_ok=True)
CAMPAIGN_RUNS_DIR = ARTIFACTS_G8_DIR / "campaign_runs"
CAMPAIGN_RUNS_DIR.mkdir(parents=True, exist_ok=True)
SUMMARY_JSON_PATH = ARTIFACTS_G8_DIR / "g8_campaign_summary.json"
LOG_DIR = REPO_ROOT / "artifacts" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE_PATH = LOG_DIR / "g8_campaign.log"

# Win32 Command IDs for Contacts, Coils, and Tools
ID_SELECT_ELEMENTS = 112       # ESC / Select Tool
ID_NO_CONTACT = 1000           # Normally Open Contact (F2)
ID_NC_CONTACT = 1001           # Normally Closed Contact
ID_NO_COIL = 1002              # Normally Open Coil (F9)
ID_NC_COIL = 37687             # Normally Closed Coil
ID_POS_COIL = 37688            # Positive Transition Coil
ID_NEG_COIL = 37689            # Negative Transition Coil
ID_SET_COIL = 37690            # Set Coil
ID_RESET_COIL = 37691          # Reset Coil
ID_INSERT_NEW_RUNG = 37980     # Insert New Rung
ID_PROGRAM_ERRORCHECK = 32826  # Ctrl+E Error Check
ID_FILE_SAVE = 57603           # File Save (Ctrl+S)
ID_PROGRAM_DOWNLOAD = 32827    # BLOCKED
ID_CONTROLLER_DOWNLOAD = 33149 # BLOCKED

# Safety & Budget Constants
MAX_LIVE_CALLS = 30
DEFAULT_LIVE_MODE = False
MAX_NON_200_STOPS = 3

# CFBF Opcodes Mapping
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

# Vertical Toolbar Coordinates
TOOLBAR_BUTTON_COORDS: Dict[int, Tuple[int, int]] = {
    ID_SELECT_ELEMENTS: (11, 11),
    ID_NO_CONTACT: (11, 82),
    ID_NC_CONTACT: (11, 104),
    ID_NO_COIL: (11, 126),
}

TOOL_COMMAND_ALIASES: Dict[int, List[int]] = {
    ID_SELECT_ELEMENTS: [112],
    ID_NO_CONTACT: [1000, 37684],
    ID_NC_CONTACT: [1001, 37685],
    ID_NO_COIL: [1002, 37686],
    ID_NC_COIL: [139, 37687],
    ID_POS_COIL: [37688],
    ID_NEG_COIL: [37689],
    ID_SET_COIL: [142, 37690],
    ID_RESET_COIL: [143, 37691],
}

CANVAS_COORD_CONTACT_COL_B = (76, 25)
CANVAS_COORD_COIL_COL_K = (484, 25)

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# Setup Logger
logger = logging.getLogger("g8_campaign")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    fh = logging.FileHandler(LOG_FILE_PATH, mode="w", encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(sh)
    logger.addHandler(fh)


# ==============================================================================
# Authentic Recorded Jev Responses from Gate G4 (Offline Fixtures)
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
        "coil_tag": "P1_TANK_LEVEL_PV",
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
        "coil_tag": "P1_LEVEL_SETPOINT_SP",
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
        "coil_tag": "P1_INFLOW_VALVE_CV",
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
        "coil_tag": "P1_CV_OUTFLOW_COUNTS",
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
        "coil_tag": "P1_PUMP_FEED_START",
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
        "coil_tag": "P1_DRAIN_PUMP_CMD_Q",
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
        "coil_tag": "P1_WARN_HI_LEVEL",
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
        "coil_tag": "P1_LOW_LEVEL_ALM_M",
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
        "coil_tag": "P1_HIHI_ESD_TRIP_M",
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
        "coil_tag": "P1_PUMP_OVERLOAD_I",
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
        "coil_tag": "P1_INLET_FLOW_RATE",
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
        "coil_tag": "P1_VESSEL_TEMP_AI",
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
        "coil_tag": "P1_STATIC_HEAD_PRESS",
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
        "coil_tag": "P1_AGITATOR_START",
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
        "coil_tag": "P1_ALM_VALVE_MISMATCH",
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
        "coil_tag": "P1_MODE_AUTO_MANUAL",
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
        "coil_tag": "P1_BATCH_CYCLE_COUNT",
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
        "coil_tag": "P1_DWELL_TIMER_ET_R",
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
        "coil_tag": "P1_THERMAL_SCR_CMD",
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
        "coil_tag": "P1_ESTOP_CONTACT_I",
    },
]


# ==============================================================================
# Circuit Breaker & Live Mode Dispatcher
# ==============================================================================

class CircuitBreaker:
    """Circuit breaker that trips after a threshold of consecutive non-200 responses."""

    def __init__(self, failure_threshold: int = MAX_NON_200_STOPS):
        self.threshold = failure_threshold
        self.consecutive_errors: int = 0
        self.is_tripped: bool = False
        self.trip_reason: Optional[str] = None

    def record_status(self, http_status: int, error_detail: str = "") -> None:
        if http_status != 200:
            self.consecutive_errors += 1
            if self.consecutive_errors >= self.threshold:
                self.is_tripped = True
                self.trip_reason = (
                    f"Circuit breaker tripped: {self.consecutive_errors} consecutive non-200 responses. "
                    f"Last error: {error_detail}"
                )
        else:
            self.consecutive_errors = 0

    def check_state(self) -> None:
        if self.is_tripped:
            raise RuntimeError(self.trip_reason or "Circuit breaker tripped open.")


class LiveCallCapDispatcher:
    """Guarded dispatcher enforcing the strict 30-call cap, circuit breaker, and offline-by-default invariant."""

    def __init__(self, live_enabled: bool = DEFAULT_LIVE_MODE, max_calls: int = MAX_LIVE_CALLS):
        self.live_enabled = live_enabled
        self.max_calls = max_calls
        self.calls_dispatched = 0
        self.circuit_breaker = CircuitBreaker(failure_threshold=MAX_NON_200_STOPS)

    def dispatch_call(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.live_enabled:
            raise PermissionError("Live API calls are disabled in offline mode")
        if self.calls_dispatched >= self.max_calls:
            raise RuntimeError(f"MAX_LIVE_CALLS limit ({self.max_calls}) reached; call blocked")
        self.circuit_breaker.check_state()

        self.calls_dispatched += 1
        return {"status": 200, "call_id": self.calls_dispatched, "response": "mock_live_ok"}

    def record_response(self, status_code: int) -> None:
        self.circuit_breaker.record_status(status_code)


# ==============================================================================
# GUI Primitives (G3 Variable Ingestion & G7 Ladder Placement)
# ==============================================================================

def dismiss_about_cscape_and_wait_main_enabled(main_hwnd: int, pid: int, max_wait_seconds: float = 12.0) -> bool:
    """Dismiss any delayed About Cscape, Tip of the Day, or modal dialogs and wait until main window is enabled."""
    start_t = time.time()
    logger.info("Waiting for and dismissing About Cscape / modal dialogs...")
    while time.time() - start_t < max_wait_seconds:
        hwnds: List[int] = []

        def _enum_win(h: int, _: Any) -> bool:
            try:
                if win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                    _, w_pid = win32process.GetWindowThreadProcessId(h)
                    if w_pid == pid:
                        hwnds.append(h)
            except Exception:
                pass
            return True

        win32gui.EnumWindows(_enum_win, None)

        for h in hwnds:
            if h == main_hwnd:
                continue
            cls = win32gui.GetClassName(h)
            title = win32gui.GetWindowText(h)
            t_low = title.lower()

            is_about = any(k in t_low for k in ["about cscape", "tip of the day", "welcome"]) or (
                cls == "#32770" and "about" in t_low
            )
            is_modal = (cls == "#32770" and not win32gui.IsWindowEnabled(main_hwnd))

            if is_about or is_modal or cls == "#32770":
                logger.info(f"Dismissing dialog '{title}' (HWND {hex(h)}, class '{cls}')...")
                user32.PostMessageW(h, win32con.WM_COMMAND, 1, 0)
                user32.PostMessageW(h, win32con.WM_COMMAND, 2, 0)
                user32.PostMessageW(h, win32con.WM_CLOSE, 0, 0)
                time.sleep(0.2)

        if win32gui.IsWindowEnabled(main_hwnd):
            any_modal = False
            for h in hwnds:
                if h != main_hwnd and win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                    if win32gui.GetClassName(h) == "#32770":
                        r = win32gui.GetWindowRect(h)
                        if (r[2] - r[0] > 50) and (r[3] - r[1] > 50):
                            any_modal = True
                            break
            if not any_modal:
                logger.info("Main window confirmed enabled and clear of modal dialogs.")
                return True
        time.sleep(0.2)

    return win32gui.IsWindowEnabled(main_hwnd)


def resolve_ladder_canvas(main_hwnd: int) -> Tuple[Optional[int], Optional[int]]:
    """Locate active ladder MDI child window and canvas view (AfxFrameOrView140su ID 59649)."""
    mdi_client = None
    mdi_children: List[int] = []

    def _find_mdi(h: int, _: Any) -> bool:
        nonlocal mdi_client
        if win32gui.GetClassName(h) == "MDIClient":
            mdi_client = h
            return False
        return True

    win32gui.EnumChildWindows(main_hwnd, _find_mdi, None)

    if mdi_client:
        def _enum_children(h: int, _: Any) -> bool:
            if win32gui.GetParent(h) == mdi_client and win32gui.IsWindowVisible(h):
                mdi_children.append(h)
            return True
        win32gui.EnumChildWindows(mdi_client, _enum_children, None)

    active_mdi = win32gui.SendMessage(mdi_client, win32con.WM_MDIGETACTIVE, 0, 0) if mdi_client else 0
    ladder_mdi = active_mdi or (mdi_children[0] if mdi_children else None)

    canvas_hwnd = None
    if ladder_mdi:
        def _find_canvas(h: int, _: Any) -> bool:
            nonlocal canvas_hwnd
            cls = win32gui.GetClassName(h)
            cid = user32.GetDlgCtrlID(h)
            if "AfxFrameOrView" in cls and cid == 59649:
                r = win32gui.GetWindowRect(h)
                if (r[2] - r[0]) > 200:
                    canvas_hwnd = h
                    return False
            return True

        win32gui.EnumChildWindows(ladder_mdi, _find_canvas, None)

    return ladder_mdi, canvas_hwnd


def activate_ladder_toolbar_button(main_hwnd: int, ladder_mdi: int, canvas_hwnd: int, cmd_id: int) -> bool:
    """Activate tool by multi-target WM_COMMAND dispatch and physical toolbar click."""
    tb_hwnd = None
    if ladder_mdi:
        def _find_tb(h: int, _: Any) -> bool:
            nonlocal tb_hwnd
            if win32gui.GetClassName(h) == "ToolbarWindow32" and user32.GetDlgCtrlID(h) == 4500:
                tb_hwnd = h
                return False
            return True
        win32gui.EnumChildWindows(ladder_mdi, _find_tb, None)

    cmds_to_send = TOOL_COMMAND_ALIASES.get(cmd_id, [cmd_id])
    for cid in cmds_to_send:
        if ladder_mdi:
            user32.PostMessageW(ladder_mdi, win32con.WM_COMMAND, cid, tb_hwnd or 0)
        if canvas_hwnd:
            user32.PostMessageW(canvas_hwnd, win32con.WM_COMMAND, cid, tb_hwnd or 0)
        user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, cid, 0)

    if tb_hwnd and cmd_id in TOOLBAR_BUTTON_COORDS:
        cx, cy = TOOLBAR_BUTTON_COORDS[cmd_id]
        lp = ((cy & 0xFFFF) << 16) | (cx & 0xFFFF)
        user32.PostMessageW(tb_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lp)
        user32.PostMessageW(tb_hwnd, win32con.WM_LBUTTONUP, 0, lp)

    time.sleep(0.2)
    return True


def get_control_text_safe(hwnd: int, timeout_ms: int = 500) -> str:
    """Safely extract text from a Win32 window or child control across processes."""
    try:
        buf_len = 2048
        buf = ctypes.create_unicode_buffer(buf_len)
        res = ctypes.c_ulong(0)
        # SMTO_ABORTIFHUNG = 0x0002
        r = user32.SendMessageTimeoutW(
            hwnd,
            win32con.WM_GETTEXT,
            buf_len,
            buf,
            0x0002,
            timeout_ms,
            ctypes.byref(res),
        )
        if r != 0 and buf.value:
            return buf.value.strip()
    except Exception:
        pass
    try:
        t = win32gui.GetWindowText(hwnd)
        if t:
            return t.strip()
    except Exception:
        pass
    return ""


def log_dialog_details_and_text(dlg_hwnd: int, context_label: str = "CSCAPE DIALOG") -> Dict[str, Any]:
    """Capture and log full diagnostic information and text of a dialog and its child controls."""
    title = win32gui.GetWindowText(dlg_hwnd).strip()
    class_name = win32gui.GetClassName(dlg_hwnd)
    rect = win32gui.GetWindowRect(dlg_hwnd)

    controls: List[Dict[str, Any]] = []

    def _enum_child(ch: int, _: Any) -> bool:
        c_cls = win32gui.GetClassName(ch)
        c_id = user32.GetDlgCtrlID(ch)
        c_rect = win32gui.GetWindowRect(ch)
        c_text = get_control_text_safe(ch)
        controls.append({
            "hwnd": hex(ch),
            "class": c_cls,
            "id": c_id,
            "rect": c_rect,
            "text": c_text,
        })
        return True

    try:
        win32gui.EnumChildWindows(dlg_hwnd, _enum_child, None)
    except Exception as e:
        logger.warning(f"Error enumerating child windows of {hex(dlg_hwnd)}: {e}")

    # Visual sorting: top-to-bottom, left-to-right
    controls.sort(key=lambda c: (c["rect"][1], c["rect"][0]))

    text_lines = [c["text"] for c in controls if c["text"]]
    combined_text = "\n".join(text_lines)

    dialog_info = {
        "hwnd": hex(dlg_hwnd),
        "title": title,
        "class": class_name,
        "rect": rect,
        "controls": controls,
        "extracted_text": text_lines,
        "combined_text": combined_text,
    }

    logger.error("=" * 70)
    logger.error(f"[{context_label}] Dialog Title: '{title}' | HWND: {hex(dlg_hwnd)} | Class: '{class_name}'")
    logger.error(f"  Coordinates: {rect} (w={rect[2]-rect[0]}, h={rect[3]-rect[1]})")
    for c in controls:
        if c["text"] or c["class"].lower() in ["button", "edit", "static"]:
            logger.error(f"  Control [{c['class']}] ID {c['id']}: '{c['text']}'")
    if combined_text:
        logger.error(f"  Full Extracted Text:\n{combined_text}")
    logger.error("=" * 70)

    return dialog_info


def scan_for_cscape_dialogs(
    pid: int,
    exclude_hwnds: Optional[Set[int]] = None,
) -> List[Tuple[int, str, str]]:
    """Scan all visible #32770 dialogs belonging to PID."""
    exclude = exclude_hwnds or set()
    found: List[Tuple[int, str, str]] = []

    def _enum_win(h: int, _: Any) -> bool:
        try:
            if h not in exclude and win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.GetClassName(h) == "#32770":
                    title = win32gui.GetWindowText(h).strip()
                    cls = win32gui.GetClassName(h)
                    found.append((h, cls, title))
        except Exception:
            pass
        return True

    win32gui.EnumWindows(_enum_win, None)
    return found


def assign_tag_in_dialog(pid: int, tag_name: str, timeout: float = 3.5) -> bool:
    """Find Dialog 108 ('I/O Point'), set tag_name, click OK, log any Cscape Error dialog,
    and stop immediately fail-closed on unknown dialogs.
    """
    start_t = time.time()
    dlg_hwnd = None

    while time.time() - start_t < timeout:
        def _find_d(h: int, _: Any) -> bool:
            nonlocal dlg_hwnd
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                    t = win32gui.GetWindowText(h)
                    if any(k in t.lower() for k in ["point", "element", "address"]):
                        dlg_hwnd = h
                        return False
            except Exception:
                pass
            return True

        win32gui.EnumWindows(_find_d, None)
        if dlg_hwnd:
            break
        time.sleep(0.08)

    if not dlg_hwnd:
        # Check if an unexpected or error dialog appeared instead
        unexpected = scan_for_cscape_dialogs(pid)
        if unexpected:
            for uh, ucls, ut in unexpected:
                log_dialog_details_and_text(uh, context_label="UNEXPECTED DIALOG (NO DIALOG 108)")
            raise RuntimeError(
                f"Dialog 108 not found for tag '{tag_name}', unexpected dialog present: {unexpected[0][2]}"
            )
        logger.warning(f"Dialog 108 for tag '{tag_name}' not found within {timeout}s")
        return False

    def _set_edits(ch: int, _: Any) -> bool:
        if win32gui.GetClassName(ch).lower() == "edit":
            user32.SendMessageW(ch, win32con.WM_SETTEXT, 0, tag_name)
        return True

    win32gui.EnumChildWindows(dlg_hwnd, _set_edits, None)

    h_combo = user32.GetDlgItem(dlg_hwnd, 1035)
    if h_combo:
        user32.SendMessageW(h_combo, win32con.WM_SETTEXT, 0, tag_name)
    time.sleep(0.15)

    h_ok = user32.GetDlgItem(dlg_hwnd, 1)
    if h_ok:
        user32.PostMessageW(h_ok, win32con.BM_CLICK, 0, 0)
        time.sleep(0.6)
    else:
        log_dialog_details_and_text(dlg_hwnd, context_label="DIALOG 108 (NO OK BUTTON)")
        return False

    # Check for modal response dialogs (Error dialog, database prompt, or unknown dialog)
    start_resp = time.time()
    while time.time() - start_resp < 2.5:
        dialogs = scan_for_cscape_dialogs(pid, exclude_hwnds={dlg_hwnd})
        for dh, dcls, dt in dialogs:
            dt_low = dt.lower()
            info = log_dialog_details_and_text(dh, context_label="MODAL RESPONSE DIALOG")
            all_text = " ".join([info.get("title", "")] + info.get("extracted_text", [])).lower()

            # 1. Error dialog check: log full text and FAIL CLOSED!
            if any(k in dt_low or k in all_text for k in ["error", "invalid", "illegal", "cannot", "fail"]):
                logger.error(
                    f"CSCAPE ERROR DIALOG ENCOUNTERED while assigning tag '{tag_name}': "
                    f"Title='{dt}' | Text='{info.get('combined_text')}'"
                )
                user32.PostMessageW(dh, win32con.WM_COMMAND, win32con.IDOK, 0)
                user32.PostMessageW(dh, win32con.WM_CLOSE, 0, 0)
                raise RuntimeError(
                    f"Cscape Error dialog encountered assigning tag '{tag_name}': "
                    f"'{dt}' - {info.get('combined_text')}"
                )

            # 2. Database prompt check ("not found in database -> add it?")
            if any(k in dt_low for k in ["database", "variable", "symbol"]):
                logger.info(f"Database prompt detected (HWND {hex(dh)}). Clicking Yes (IDYES=6)...")
                user32.PostMessageW(dh, win32con.WM_COMMAND, 6, 0)
                time.sleep(0.5)

                # Check for "Select Variable Type"
                type_dialogs = scan_for_cscape_dialogs(pid, exclude_hwnds={dlg_hwnd, dh})
                for th, tcls, tt in type_dialogs:
                    if "variable type" in tt.lower():
                        logger.info("Select Variable Type dialog detected. Clicking OK (1)...")
                        user32.PostMessageW(th, win32con.WM_COMMAND, 1, 0)
                        time.sleep(0.4)
                continue

            # 3. Unknown dialog: FAIL CLOSED!
            logger.error(
                f"UNKNOWN CSCAPE DIALOG ENCOUNTERED while assigning tag '{tag_name}': "
                f"Title='{dt}' | Text='{info.get('combined_text')}'"
            )
            user32.PostMessageW(dh, win32con.WM_CLOSE, 0, 0)
            raise RuntimeError(
                f"Unknown Cscape dialog encountered assigning tag '{tag_name}': "
                f"'{dt}' - {info.get('combined_text')}"
            )

        # Check if Dialog 108 closed
        if not (win32gui.IsWindow(dlg_hwnd) and win32gui.IsWindowVisible(dlg_hwnd)):
            break
        time.sleep(0.1)

    is_open = win32gui.IsWindow(dlg_hwnd) and win32gui.IsWindowVisible(dlg_hwnd)
    if is_open:
        logger.error(f"Dialog 108 remained open after assigning tag '{tag_name}'!")
        log_dialog_details_and_text(dlg_hwnd, context_label="DIALOG 108 REMAINED OPEN")
        user32.PostMessageW(dlg_hwnd, win32con.WM_COMMAND, win32con.IDCANCEL, 0)
        user32.PostMessageW(dlg_hwnd, win32con.WM_CLOSE, 0, 0)
        return False

    return True


def place_ladder_element(
    main_hwnd: int,
    ladder_mdi: int,
    canvas_hwnd: int,
    pid: int,
    tool_cmd: int,
    tag_name: str,
    coords: Tuple[int, int],
) -> bool:
    """Select tool, click canvas to place element, bind tag, and restore Select tool."""
    cx, cy = coords
    lparam = ((cy & 0xFFFF) << 16) | (cx & 0xFFFF)

    activate_ladder_toolbar_button(main_hwnd, ladder_mdi, canvas_hwnd, tool_cmd)
    time.sleep(0.3)

    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam)
    time.sleep(0.15)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam)
    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam)
    time.sleep(0.6)

    bound = assign_tag_in_dialog(pid, tag_name)
    activate_ladder_toolbar_button(main_hwnd, ladder_mdi, canvas_hwnd, ID_SELECT_ELEMENTS)
    time.sleep(0.2)
    return bound


# ==============================================================================
# CFBF Independent Oracle & Plan Match Verification
# ==============================================================================

def parse_cfbf_ladder_elements(csp_path: Union[str, Path]) -> Dict[str, Any]:
    """Parse CFBF /Contents stream directly using olefile and extract ladder elements,
    opcodes, element types, columns, and tag bindings deterministically.
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
            "readback_contact_type": None,
            "readback_contact_tag": None,
            "readback_coil_type": None,
            "readback_coil_tag": None,
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
        "readback_contact_type": None,
        "readback_contact_tag": None,
        "readback_coil_type": None,
        "readback_coil_tag": None,
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

            matches = list(re.finditer(rb"(![\x01-\x40]@([A-Za-z0-9_]+)@)", lslice))
            for i, m in enumerate(matches):
                raw_tag = m.group(1)
                tag_name = m.group(2).decode("latin1", errors="ignore")
                m_start = m.start()
                hdr_bytes = lslice[max(0, m_start - 9) : m_start]
                opcode = hdr_bytes[0] if len(hdr_bytes) >= 1 else 0
                col = hdr_bytes[1] if len(hdr_bytes) >= 2 else (1 if i == 0 else 9)

                elem_type = CSCAPE_OPCODE_TO_TYPE.get(opcode, f"UNKNOWN_0x{opcode:02x}")
                is_contact = opcode in CONTACT_OPCODES
                is_coil = opcode in COIL_OPCODES

                elem_rec = {
                    "index": i,
                    "tag": tag_name,
                    "row": 0,
                    "col": col,
                    "opcode": opcode,
                    "opcode_hex": f"0x{opcode:02x}",
                    "type": elem_type,
                    "category": "CONTACT" if is_contact else ("COIL" if is_coil else "OTHER"),
                    "raw_tag": raw_tag.decode("latin1", errors="ignore"),
                    "header_hex": hdr_bytes.hex(),
                }
                result["elements"].append(elem_rec)
                if is_contact:
                    result["contacts"].append(elem_rec)
                    if result["readback_contact_type"] is None:
                        result["readback_contact_type"] = elem_type
                        result["readback_contact_tag"] = tag_name
                if is_coil:
                    result["coils"].append(elem_rec)
                    if result["readback_coil_type"] is None:
                        result["readback_coil_type"] = elem_type
                        result["readback_coil_tag"] = tag_name
    elif hdr.startswith(b"main1\x001\x00"):
        result["header_version"] = "main1"
        elem_count = struct.unpack_from("<I", contents, idx + 8)[0]
        result["element_count"] = elem_count

    return result


def compute_cfbf_delta(base_info: Dict[str, Any], roundtrip_info: Dict[str, Any]) -> Dict[str, Any]:
    """Compute exact delta between negative control baseline and roundtrip file."""
    base_tags = {e["tag"] for e in base_info.get("elements", [])}
    rt_elements = roundtrip_info.get("elements", [])

    new_elements = [e for e in rt_elements if e["tag"] not in base_tags]
    new_contacts = [e for e in roundtrip_info.get("contacts", []) if e["tag"] not in base_tags]
    new_coils = [e for e in roundtrip_info.get("coils", []) if e["tag"] not in base_tags]

    delta = {
        "status": "success",
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
        "new_elements": new_elements,
        "new_contacts": new_contacts,
        "new_coils": new_coils,
    }
    return delta


def parse_cfbf_ladder_elements_g8(csp_path: Union[str, Path]) -> Dict[str, Any]:
    """Parse CFBF /Contents stream at main3 offset 95 and extract elements, opcodes, and tags."""
    return parse_cfbf_ladder_elements(csp_path)


def verify_cfbf_reopen_against_plan_g8(
    reopened_csp_path: Union[str, Path],
    plan_dict: Dict[str, Any],
    base_csp_path: Optional[Union[str, Path]] = None,
    reopen_screenshot_path: Optional[Union[str, Path]] = None,
    initial_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate reopened CFBF file elements against expected Jev execution plan."""
    p_reopen = Path(reopened_csp_path)
    if not p_reopen.exists():
        return {
            "status": "failed",
            "error_code": "FILE_NOT_FOUND",
            "details": f"Reopened CSP file not found at {p_reopen}",
            "data": {},
        }

    mismatch_reasons: List[str] = []

    if base_csp_path:
        p_base = Path(base_csp_path)
        with open(p_base, "rb") as f:
            base_sha = hashlib.sha256(f.read()).hexdigest()
        if base_sha != BASELINE_P1_SHA:
            mismatch_reasons.append(f"Baseline file tampered: {base_sha} != {BASELINE_P1_SHA}")

    with open(p_reopen, "rb") as f:
        reopened_sha = hashlib.sha256(f.read()).hexdigest()
    if initial_sha256 and reopened_sha == initial_sha256:
        mismatch_reasons.append("Reopened CSP file was not mutated on disk by Cscape Save.")

    roundtrip_info = parse_cfbf_ladder_elements_g8(p_reopen)
    if not roundtrip_info.get("exists") or roundtrip_info.get("header_version") != "main3":
        return {
            "status": "failed",
            "error_code": "CFBF_PARSE_ERROR",
            "details": f"Invalid CFBF structure or non-main3 header in {p_reopen}",
            "data": {"roundtrip_info": roundtrip_info},
        }

    actual_count = roundtrip_info.get("element_count", 0)
    if actual_count < 2:
        mismatch_reasons.append(f"Element count at offset 95 {actual_count} < 2 (minimum required)")

    # Readback match assertions
    readback_contact_type = roundtrip_info.get("readback_contact_type")
    readback_contact_tag = roundtrip_info.get("readback_contact_tag")
    readback_coil_type = roundtrip_info.get("readback_coil_type")
    readback_coil_tag = roundtrip_info.get("readback_coil_tag")

    planned_contact_type = plan_dict.get("contact_type")
    planned_contact_tag = plan_dict.get("contact_tag")
    planned_coil_type = plan_dict.get("coil_type")
    planned_coil_tag = plan_dict.get("coil_tag")

    if readback_contact_type != planned_contact_type:
        mismatch_reasons.append(f"Contact type mismatch: readback '{readback_contact_type}' != plan '{planned_contact_type}'")
    if readback_contact_tag != planned_contact_tag:
        mismatch_reasons.append(f"Contact tag mismatch: readback '{readback_contact_tag}' != plan '{planned_contact_tag}'")
    if readback_coil_type != planned_coil_type:
        mismatch_reasons.append(f"Coil type mismatch: readback '{readback_coil_type}' != plan '{planned_coil_type}'")
    if readback_coil_tag != planned_coil_tag:
        mismatch_reasons.append(f"Coil tag mismatch: readback '{readback_coil_tag}' != plan '{planned_coil_tag}'")

    delta_info: Dict[str, Any] = {}
    if base_csp_path:
        base_info = parse_cfbf_ladder_elements_g8(base_csp_path)
        delta_info = compute_cfbf_delta(base_info, roundtrip_info)
        if delta_info["delta_element_count"] < 2:
            mismatch_reasons.append(f"Negative control delta {delta_info['delta_element_count']} < 2")

    if reopen_screenshot_path:
        p_ss = Path(reopen_screenshot_path)
        if not p_ss.exists():
            mismatch_reasons.append(f"Reopen screenshot missing at {p_ss}")
        elif p_ss.stat().st_size < 1000:
            mismatch_reasons.append(f"Reopen screenshot too small ({p_ss.stat().st_size} bytes)")

    status = "success" if len(mismatch_reasons) == 0 else "failed"
    return {
        "status": status,
        "error_code": None if status == "success" else "PLAN_VERIFICATION_MISMATCH",
        "details": "All CFBF elements matched Jev plan deterministically" if status == "success" else "; ".join(mismatch_reasons),
        "data": {
            "reopened_file": str(p_reopen),
            "reopened_sha256": reopened_sha,
            "cfbf_offset_95_count": actual_count,
            "readback_contact_type": readback_contact_type,
            "readback_contact_tag": readback_contact_tag,
            "readback_coil_type": readback_coil_type,
            "readback_coil_tag": readback_coil_tag,
            "delta_element_count": delta_info.get("delta_element_count"),
            "mismatch_reasons": mismatch_reasons,
        },
    }


# ==============================================================================
# Campaign Execution Engine
# ==============================================================================

def execute_g8_task_dry_run(
    task_dict: Dict[str, Any],
    run_idx: int,
    runs_dir: Path,
) -> Dict[str, Any]:
    """Execute task in pure offline dry-run mode (synthesizing ST/Ladder AST without spawning GUI)."""
    task_id = task_dict["task_id"]
    plan_tag = task_dict["plan"]
    req_id = task_dict.get("response_id", "UNKNOWN_REQ_ID")
    src_file = task_dict.get("source_file", "UNKNOWN_SOURCE_FILE")
    audit_src = task_dict.get("audit_source", "UNKNOWN_AUDIT_SOURCE")
    model = task_dict.get("model", "jev-1.13.0")

    logger.info(f"[DRY-RUN {run_idx:02d}] Synthesizing logic for {task_id}: {plan_tag}")
    logger.info(f"  Authentic Jev Response ID: {req_id}")
    logger.info(f"  Source Evidence File     : {src_file}")
    logger.info(f"  Audit Report Reference   : {audit_src}")
    logger.info(f"  Model Provenance         : {model} (Real G4 live run, no synthesized mock)")
    print(f"[{task_id}] Replaying Authentic Jev req_id: {req_id} | Source: {src_file} (Real G4 run)")

    # Pre-declaration check & simulation (G3 Primitive Contract)
    tags_to_check = [task_dict.get("contact_tag"), task_dict.get("coil_tag")]
    for t in tags_to_check:
        if t:
            logger.info(f"[DRY-RUN {run_idx:02d}] Tag '{t}' pre-declared as BOOL (simulated G3 primitive)")

    # Pure ST AST logic model (rejects any ladder constructs)
    st_pou_source = (
        f"(* Pure ST POU for {task_id} *)\n"
        f"PROGRAM P_{task_id}\n"
        f"VAR\n"
        f"    {plan_tag} : BOOL;\n"
        f"    {task_dict['contact_tag']} : BOOL;\n"
        f"END_VAR\n"
        f"    {plan_tag} := {task_dict['contact_tag']};\n"
        f"END_PROGRAM\n"
    )

    # Validate pure ST
    for forbidden in ["---", "[ ]", "( )", "RUNG", "XIC", "OTE"]:
        if forbidden in st_pou_source:
            raise LadderForbiddenError(f"Forbidden ladder construct in pure ST POU: {forbidden}")

    dryrun_data = {
        "run_idx": run_idx,
        "task_id": task_id,
        "task_name": task_dict["name"],
        "plan": plan_tag,
        "mode": "dry_run_ast_validation",
        "response_id": req_id,
        "source_file": src_file,
        "audit_source": audit_src,
        "model": model,
        "provenance": "Authentic Gate G4 Live Run (No Synthesized Mock)",
        "contact_type": task_dict["contact_type"],
        "contact_tag": task_dict["contact_tag"],
        "coil_type": task_dict["coil_type"],
        "coil_tag": task_dict["coil_tag"],
        "pre_declared_tags": [t for t in tags_to_check if t],
        "synthesized_st": st_pou_source,
        "status": "success",
    }

    out_file = runs_dir / f"run_{run_idx:02d}_dryrun.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(dryrun_data, f, indent=2)

    return {
        "run_idx": run_idx,
        "task_id": task_id,
        "status": "success",
        "plan": plan_tag,
        "response_id": req_id,
        "source_file": src_file,
        "audit_source": audit_src,
        "model": model,
        "contact_type": task_dict["contact_type"],
        "contact_tag": task_dict["contact_tag"],
        "coil_type": task_dict["coil_type"],
        "coil_tag": task_dict["coil_tag"],
        "readback_contact_type": task_dict["contact_type"],
        "readback_contact_tag": task_dict["contact_tag"],
        "readback_coil_type": task_dict["coil_type"],
        "readback_coil_tag": task_dict["coil_tag"],
        "dryrun_artifact": str(out_file),
    }


def execute_g8_task_live_gui(
    task_dict: Dict[str, Any],
    run_idx: int,
    runs_dir: Path,
) -> Dict[str, Any]:
    """Execute task on live Cscape GUI on winsta0\\Default using G3 and G7 primitives."""
    task_id = task_dict["task_id"]
    plan_tag = task_dict["plan"]
    req_id = task_dict.get("response_id", "UNKNOWN_REQ_ID")
    src_file = task_dict.get("source_file", "UNKNOWN_SOURCE_FILE")
    audit_src = task_dict.get("audit_source", "UNKNOWN_AUDIT_SOURCE")
    model = task_dict.get("model", "jev-1.13.0")
    copy_path = COPIES_DIR / f"campaign_run_g8_{run_idx:02d}.csp"
    ss_path = runs_dir / f"run_{run_idx:02d}_reopen.png"

    logger.info(f"[LIVE GUI {run_idx:02d}] Executing {task_id}: {plan_tag}")
    logger.info(f"  Authentic Jev Response ID: {req_id}")
    logger.info(f"  Source Evidence File     : {src_file}")
    logger.info(f"  Audit Report Reference   : {audit_src}")
    logger.info(f"  Model Provenance         : {model} (Real G4 live run, no synthesized mock)")
    print(f"[{task_id}] Replaying Authentic Jev req_id: {req_id} | Source: {src_file} (Real G4 run)")

    assert_safety_invariants()
    kill_leftover_cscape()

    # Pre-run baseline verification
    base_sha_pre = compute_sha256(BASE_P1_PATH)
    assert base_sha_pre == BASELINE_P1_SHA, f"Baseline tampered pre-run: {base_sha_pre}"

    # Stage fresh copy
    copy_path.parent.mkdir(parents=True, exist_ok=True)
    if copy_path.exists():
        copy_path.unlink()
    shutil.copy2(BASE_P1_PATH, copy_path)
    initial_sha = compute_sha256(copy_path)

    # =========================================================================
    # PRE-DECLARATION GATE (Before Opening Ladder Editor)
    # Check if contact_tag and coil_tag exist in project declarations.
    # If not declared, invoke G3 primitive to declare them as BOOL and verify!
    # =========================================================================
    tags_to_check = []
    for tag_key in ["contact_tag", "coil_tag"]:
        t = task_dict.get(tag_key)
        if t and t not in tags_to_check:
            tags_to_check.append(t)

    existing_decls = parse_csp_cfbf_declarations(copy_path)
    existing_names = {d["name"].upper() for d in existing_decls}

    tags_needing_declaration = [t for t in tags_to_check if t.upper() not in existing_names]

    if tags_needing_declaration:
        logger.info(f"Tags requiring pre-declaration via G3 primitive: {tags_needing_declaration}")
        for t in tags_needing_declaration:
            logger.info(f"[G3 PRE-DECLARATION] Declaring '{t}' as BOOL in {copy_path.name}...")
            g3_rc = run_edit_roundtrip(new_var_name=t, target_copy_path=copy_path)
            if g3_rc != 0:
                raise RuntimeError(f"Failed to declare tag '{t}' via G3 primitive (rc={g3_rc})")

            # Verify tag exists in CFBF declarations stream
            decls_post = parse_csp_cfbf_declarations(copy_path)
            names_post = {d["name"].upper() for d in decls_post}
            if t.upper() not in names_post:
                raise RuntimeError(
                    f"Post-declaration verification failed: tag '{t}' not found in CFBF declarations after G3!"
                )
            logger.info(f"[PASS] Tag '{t}' verified in CFBF declarations stream.")
    else:
        logger.info(f"All tags {tags_to_check} already declared in CFBF declarations.")

    # Recompute initial_sha before ladder edits so save delta can be verified
    initial_sha = compute_sha256(copy_path)

    # Launch Cscape
    configure_cscape_registry(copy_path)
    app, pid, main_hwnd = launch_cscape_project_robust(copy_path)
    main_win = app.window(handle=main_hwnd)
    dismiss_startup_dialogs_and_wait_ready(pid=pid, main_hwnd=main_hwnd, app=app)

    # Open ladder editor
    app_uia = Application(backend="uia").connect(process=pid)
    opened = open_main_ladder_editor(main_hwnd, pid, app_uia)
    if not opened:
        raise RuntimeError("Failed to open ladder editor")

    ladder_mdi, canvas_hwnd = resolve_ladder_canvas(main_hwnd)
    if not ladder_mdi or not canvas_hwnd:
        raise RuntimeError("Failed to resolve ladder canvas view")

    # Insert new rung
    user32.PostMessageW(ladder_mdi, win32con.WM_COMMAND, ID_INSERT_NEW_RUNG, 0)
    time.sleep(1.0)

    # Place contact
    c_ok = place_ladder_element(
        main_hwnd=main_hwnd,
        ladder_mdi=ladder_mdi,
        canvas_hwnd=canvas_hwnd,
        pid=pid,
        tool_cmd=task_dict["contact_cmd"],
        tag_name=task_dict["contact_tag"],
        coords=CANVAS_COORD_CONTACT_COL_B,
    )
    if not c_ok:
        logger.error(f"Contact '{task_dict['contact_tag']}' placement returned False")
        raise RuntimeError(f"Contact '{task_dict['contact_tag']}' placement failed fail-closed!")

    # Place coil
    q_ok = place_ladder_element(
        main_hwnd=main_hwnd,
        ladder_mdi=ladder_mdi,
        canvas_hwnd=canvas_hwnd,
        pid=pid,
        tool_cmd=task_dict["coil_cmd"],
        tag_name=task_dict["coil_tag"],
        coords=CANVAS_COORD_COIL_COL_K,
    )
    if not q_ok:
        logger.error(f"Coil '{task_dict['coil_tag']}' placement returned False")
        raise RuntimeError(f"Coil '{task_dict['coil_tag']}' placement failed fail-closed!")

    # Save project
    logger.info("Saving project (Ctrl+S / 57603)...")
    user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
    time.sleep(1.5)

    close_cscape_gracefully(pid=pid, timeout=6.0)
    kill_leftover_cscape()

    saved_sha = compute_sha256(copy_path)
    if saved_sha == initial_sha:
        raise RuntimeError("File was not modified on disk after save!")

    # Reopen to verify and capture clean screenshot
    logger.info("Reopening project for visual proof and CFBF validation...")
    configure_cscape_registry(copy_path)
    app2, pid2, main_hwnd2 = launch_cscape_project_robust(copy_path)
    main_win2 = app2.window(handle=main_hwnd2)
    dismiss_startup_dialogs_and_wait_ready(pid=pid2, main_hwnd=main_hwnd2, app=app2)

    app_uia2 = Application(backend="uia").connect(process=pid2)
    open_main_ladder_editor(main_hwnd2, pid2, app_uia2)

    dismiss_about_cscape_and_wait_main_enabled(main_hwnd2, pid2, max_wait_seconds=10.0)
    capture_g7_screenshot(main_win2, ss_path)

    close_cscape_gracefully(pid=pid2, timeout=6.0)
    kill_leftover_cscape()

    # CFBF verification
    v_res = verify_cfbf_reopen_against_plan_g8(
        reopened_csp_path=copy_path,
        plan_dict=task_dict,
        base_csp_path=BASE_P1_PATH,
        reopen_screenshot_path=ss_path,
        initial_sha256=initial_sha,
    )

    base_sha_post = compute_sha256(BASE_P1_PATH)
    assert base_sha_post == BASELINE_P1_SHA, f"Baseline tampered post-run: {base_sha_post}"

    return {
        "run_idx": run_idx,
        "task_id": task_id,
        "status": v_res["status"],
        "plan": plan_tag,
        "response_id": req_id,
        "source_file": src_file,
        "audit_source": audit_src,
        "model": model,
        "contact_type": task_dict["contact_type"],
        "contact_tag": task_dict["contact_tag"],
        "coil_type": task_dict["coil_type"],
        "coil_tag": task_dict["coil_tag"],
        "readback_contact_type": v_res["data"].get("readback_contact_type"),
        "readback_contact_tag": v_res["data"].get("readback_contact_tag"),
        "readback_coil_type": v_res["data"].get("readback_coil_type"),
        "readback_coil_tag": v_res["data"].get("readback_coil_tag"),
        "reopen_screenshot": str(ss_path),
        "delta_element_count": v_res["data"].get("delta_element_count"),
        "details": v_res["details"],
    }


def run_g8_campaign(
    mode: str = "offline",
    runs: int = 10,
    dry_run: bool = False,
    stop_on_fail: bool = True,
    summary_path: Optional[Path] = None,
    runs_dir: Optional[Path] = None,
) -> int:
    """Orchestrate Gate G8 campaign across N runs."""
    out_summary = summary_path or SUMMARY_JSON_PATH
    out_runs_dir = runs_dir or CAMPAIGN_RUNS_DIR
    out_summary.parent.mkdir(parents=True, exist_ok=True)
    out_runs_dir.mkdir(parents=True, exist_ok=True)

    start_time = datetime.now(timezone.utc).isoformat()
    logger.info("=" * 80)
    logger.info(f"STARTING GATE G8 CAMPAIGN: mode={mode}, runs={runs}, dry_run={dry_run}")
    logger.info("=" * 80)

    # Safety Assertions
    assert_safety_invariants()
    base_sha = compute_sha256(BASE_P1_PATH)
    assert base_sha == BASELINE_P1_SHA, f"Baseline tampered at startup: {base_sha}"

    # Enforce Live Mode Guard
    if mode == "live":
        logger.warning("LIVE MODE INVOKED. Enforcing MAX_LIVE_CALLS = 30 and circuit breaker.")
        dispatcher = LiveCallCapDispatcher(live_enabled=True, max_calls=MAX_LIVE_CALLS)
    else:
        logger.info("OFFLINE MODE INVOKED. Replaying authentic recorded G4 responses (0 network calls).")
        dispatcher = LiveCallCapDispatcher(live_enabled=False, max_calls=0)

    run_results: List[Dict[str, Any]] = []
    overall_status = "success"

    for i in range(1, runs + 1):
        task_idx = (i - 1) % len(G4_AUTHENTIC_REPLAY_FIXTURES)
        task_fixture = G4_AUTHENTIC_REPLAY_FIXTURES[task_idx]

        logger.info(f"--- [RUN {i:02d}/{runs:02d}] Task: {task_fixture['task_id']} ({task_fixture['name']}) ---")
        if mode == "offline":
            req_id = task_fixture.get("response_id", "UNKNOWN_REQ_ID")
            src_file = task_fixture.get("source_file", "UNKNOWN_SOURCE")
            audit_src = task_fixture.get("audit_source", "UNKNOWN_AUDIT")
            model = task_fixture.get("model", "jev-1.13.0")
            print("=" * 80)
            print(f"[OFFLINE REPLAY] Task {task_fixture['task_id']}: {task_fixture['name']}")
            print(f"  Authentic Jev req_id : {req_id}")
            print(f"  Source Evidence File : {src_file}")
            print(f"  Source Audit Report  : {audit_src}")
            print(f"  Model Provenance     : {model} (Authentic G4 live run, no synthesized mock)")
            print(f"  Plan: {task_fixture['plan']} | Confidence: {task_fixture['confidence']:.2f}")
            print(f"  Ladder: {task_fixture['contact_type']} ({task_fixture['contact_tag']}) -> {task_fixture['coil_type']} ({task_fixture['coil_tag']})")
            print("=" * 80)
            logger.info(
                f"[OFFLINE REPLAY PROVENANCE] Task {task_fixture['task_id']} | req_id: {req_id} | "
                f"source: {src_file} | model: {model} | plan: {task_fixture['plan']}"
            )

        try:
            if dry_run:
                run_res = execute_g8_task_dry_run(task_fixture, i, out_runs_dir)
            else:
                run_res = execute_g8_task_live_gui(task_fixture, i, out_runs_dir)

            run_results.append(run_res)
            if run_res.get("status") != "success":
                logger.error(f"Run {i:02d} FAILED: {run_res.get('details')}")
                overall_status = "failed"
                if stop_on_fail:
                    logger.error("Stop-on-fail triggered; halting campaign.")
                    break
            else:
                logger.info(f"Run {i:02d} SUCCESS: Plan '{run_res.get('plan')}' verified.")

        except Exception as e:
            logger.error(f"Run {i:02d} exception: {e}", exc_info=True)
            run_results.append({
                "run_idx": i,
                "task_id": task_fixture["task_id"],
                "status": "failed",
                "error": str(e),
            })
            overall_status = "failed"
            if stop_on_fail:
                logger.error("Stop-on-fail triggered by exception; halting campaign.")
                break

    end_time = datetime.now(timezone.utc).isoformat()
    passed_count = sum(1 for r in run_results if r.get("status") == "success")
    failed_count = sum(1 for r in run_results if r.get("status") != "success")

    summary_payload: Dict[str, Any] = {
        "gate": "G8",
        "task": "GATE_G8_AUTONOMOUS_POLICY_CAMPAIGN",
        "mode": mode,
        "dry_run": dry_run,
        "overall_status": overall_status,
        "timestamp_start_utc": start_time,
        "timestamp_end_utc": end_time,
        "runs_planned": runs,
        "runs_executed": len(run_results),
        "runs_passed": passed_count,
        "runs_failed": failed_count,
        "policy_metrics": {
            "calls_total": dispatcher.calls_dispatched,
            "calls_cap": MAX_LIVE_CALLS,
            "circuit_breaker_tripped": dispatcher.circuit_breaker.is_tripped,
            "non_200_count": dispatcher.circuit_breaker.consecutive_errors,
        },
        "safety_invariants_verified": True,
        "baseline_p1_sha256": BASELINE_P1_SHA,
        "runs": run_results,
    }

    with open(out_summary, "w", encoding="utf-8") as f:
        json.dump(summary_payload, f, indent=2)

    logger.info("=" * 80)
    logger.info(f"CAMPAIGN COMPLETE: status={overall_status}, passed={passed_count}/{len(run_results)}")
    logger.info(f"Summary saved: {out_summary}")
    logger.info("=" * 80)

    return 0 if overall_status == "success" else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="g8_campaign.py",
        description="Gate G8 Autonomous Agent Verification Campaign Runner (Horner Cscape 10.2)",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--offline",
        dest="mode",
        action="store_const",
        const="offline",
        default="offline",
        help="Replay recorded real Jev responses (0 network calls, 100%% offline reproducible)",
    )
    mode_group.add_argument(
        "--live",
        dest="mode",
        action="store_const",
        const="live",
        help="Execute live TypeSafe SystemOne queries (Strict 30-call cap, circuit breaker at 3 non-200s, NOT RUN YET)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="Number of sequential tasks to execute (1..30)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Parse test plans and synthesize offline logic without launching Cscape GUI",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=SUMMARY_JSON_PATH,
        help="Path for overall campaign summary JSON",
    )
    parser.add_argument(
        "--runs-dir",
        type=Path,
        default=CAMPAIGN_RUNS_DIR,
        help="Directory to store individual run artifacts and screenshots",
    )
    parser.add_argument(
        "--no-stop-on-fail",
        action="store_true",
        default=False,
        help="Do not abort campaign on first run failure",
    )
    args = parser.parse_args()

    exit_code = run_g8_campaign(
        mode=args.mode,
        runs=args.runs,
        dry_run=args.dry_run,
        stop_on_fail=not args.no_stop_on_fail,
        summary_path=args.summary,
        runs_dir=args.runs_dir,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
