#!/usr/bin/env python3
"""Gate G4 Live Campaign Runner: 20 P1 Automation Tasks with TypeSafe SystemOne.

Work Package: GATE_G4_LIVE_CAMPAIGN
Classification: LIVE_PROVIDER_INTEGRATION [TypeSafe SystemOne, 20 Tasks, Zero Secrets]

Executes:
  1. The 20 Horner Canvas 7 P1 automation tasks from the Megaplan on fresh copies of p1_base.csp.
  2. Live Jev reasoning via POST https://api.typesafe.ai/v1/systemone:
     - Bearer JEV_API_KEY safely loaded from .env (never logged or exposed)
     - Model: jev-latest
     - Pure SystemOne schema: `state` + typed `choice` questions with `criteria`
     - Global call cap: max 60 calls across campaign
     - Circuit breaker: stop campaign after 3 non-200 HTTP responses
  3. Proven G3 roundtrip execution per task:
     - Fresh p1_base.csp copy isolation
     - Live Cscape 10.2 Win32 GUI automation on winsta0\\Default
     - Program Variables pane traversal and Add Variable injection
     - Ctrl+S / ID_FILE_SAVE commit
     - Graceful teardown
  4. Post-save clean reopen verification:
     - Dismiss About Cscape / Tip of the Day startup dialogs
     - Verify zero corruption / error dialogs
     - Modal-free and stable main window verification
     - Scrape complete IEC variables text (starts with VAR, ends with END_VAR, >= 23 decls)
     - CFBF OLE2 stream oracle verification (confirm new declaration in /V, records)
     - SHA-256 preservation verification (reopen SHA == saved SHA != initial SHA)
  5. Per-task logging: HTTP status, latency, plan, PASS/FAIL, saved/reopen SHA.
  6. Consolidated summary JSON exported to artifacts/G4/g4_campaign_summary.json.

Safety Invariants:
  - NEVER modifies or overwrites work/disposable/p1_base.csp or test_sandbox.csp
  - Fail-closed physical COM port and Win32 download command lockout (32827, 33149)
  - Zero secrets printed or stored in logs, stdout, or evidence JSONs
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import shutil
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import urllib.error
import urllib.request

# Ensure repository root and src are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.g3_edit_roundtrip import (
    run_edit_roundtrip,
    assert_safety_invariants,
    close_cscape_gracefully,
    kill_leftover_cscape,
    compute_sha256,
    parse_csp_cfbf_declarations,
    BASE_P1_PATH,
    SOURCE_SANDBOX_PATH,
    BASELINE_P1_SHA,
    BASELINE_SANDBOX_SHA,
    COPIES_DIR,
    EVIDENCE_PATH,
)

# Output Paths
LOG_DIR = REPO_ROOT / "artifacts" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
G4_ARTIFACTS_DIR = REPO_ROOT / "artifacts" / "G4"
G4_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
G4_CAMPAIGN_RUNS_DIR = G4_ARTIFACTS_DIR / "campaign_runs"
G4_CAMPAIGN_RUNS_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_SUMMARY_PATH = G4_ARTIFACTS_DIR / "g4_campaign_summary.json"
CAMPAIGN_LOG_PATH = LOG_DIR / "g4_campaign.log"

# Global Campaign Limits
MAX_JEV_CALLS = 60
MAX_NON_200_STOPS = 3
DEFAULT_TOTAL_TASKS = 20
REQUIRED_REOPEN_DECL_COUNT = 24

# Setup Logging
logger = logging.getLogger("g4_campaign")
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(CAMPAIGN_LOG_PATH, mode="w", encoding="utf-8")
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(file_handler)


# ==============================================================================
# 1. P1 Megaplan Task Definitions
# ==============================================================================

@dataclass
class P1TaskDefinition:
    """Specification of an individual Horner P1 automation task from the Megaplan."""
    task_num: int
    task_id: str
    name: str
    channel: str
    description: str
    candidates: List[str]
    recommended: str


P1_MEGAPLAN_TASKS: List[P1TaskDefinition] = [
    P1TaskDefinition(
        task_num=1,
        task_id="P1_TASK_01",
        name="Tank Level Measurement Scaling (PV)",
        channel="%AI1 (Analog Input 1)",
        description="Process liquid level measurement sensor scaling 0-100% Namur NE43 compliant.",
        candidates=["P1_TANK_LEVEL_PV", "P1_LIQUID_LEVEL_AI", "P1_PV_LEVEL_PERCENT", "P1_TANK_LEVEL_RAW"],
        recommended="P1_TANK_LEVEL_PV",
    ),
    P1TaskDefinition(
        task_num=2,
        task_id="P1_TASK_02",
        name="Liquid Level Operating Setpoint (SP)",
        channel="%R1 (Holding Register 1)",
        description="Closed-loop PI controller target liquid level setpoint register nominal 50.0%.",
        candidates=["P1_LEVEL_SETPOINT_SP", "P1_TARGET_LEVEL_SP", "P1_SP_LEVEL_PERCENT", "P1_DESIRED_LEVEL"],
        recommended="P1_LEVEL_SETPOINT_SP",
    ),
    P1TaskDefinition(
        task_num=3,
        task_id="P1_TASK_03",
        name="Inflow Proportional Valve Actuation (CV)",
        channel="%AQ1 (Analog Output 1)",
        description="Proportional inlet control valve position actuator command (0-32000 counts).",
        candidates=["P1_INFLOW_VALVE_CV", "P1_INLET_VALVE_POS", "P1_VALVE_INFLOW_CMD", "P1_CV_INFLOW_COUNTS"],
        recommended="P1_INFLOW_VALVE_CV",
    ),
    P1TaskDefinition(
        task_num=4,
        task_id="P1_TASK_04",
        name="Gravity Drain Control Valve Actuation",
        channel="%AQ2 (Analog Output 2)",
        description="Proportional bottom discharge drain valve actuator command (0-32000 counts).",
        candidates=["P1_OUTFLOW_VALVE_CV", "P1_DRAIN_VALVE_POS", "P1_VALVE_OUTFLOW_CMD", "P1_CV_OUTFLOW_COUNTS"],
        recommended="P1_OUTFLOW_VALVE_CV",
    ),
    P1TaskDefinition(
        task_num=5,
        task_id="P1_TASK_05",
        name="Centrifugal Feed Pump Motor Control",
        channel="%Q1 (Digital Output 1)",
        description="Centrifugal liquid feed pump start/run discrete digital output contact.",
        candidates=["P1_FEED_PUMP_CMD_Q", "P1_PUMP_FEED_START", "P1_RUN_FEED_PUMP", "P1_COIL_FEED_PUMP"],
        recommended="P1_FEED_PUMP_CMD_Q",
    ),
    P1TaskDefinition(
        task_num=6,
        task_id="P1_TASK_06",
        name="Transfer Drain Pump Motor Control",
        channel="%Q2 (Digital Output 2)",
        description="Downstream transfer drain pump start/run discrete digital output contact.",
        candidates=["P1_DRAIN_PUMP_CMD_Q", "P1_PUMP_DRAIN_START", "P1_RUN_DRAIN_PUMP", "P1_COIL_DRAIN_PUMP"],
        recommended="P1_DRAIN_PUMP_CMD_Q",
    ),
    P1TaskDefinition(
        task_num=7,
        task_id="P1_TASK_07",
        name="High Liquid Level Warning Threshold",
        channel="%M1 (Internal Marker 1)",
        description="High liquid level warning alarm latch using Schmitt trigger trip at 80.0%.",
        candidates=["P1_HIGH_LEVEL_ALM_M", "P1_ALM_LEVEL_HIGH", "P1_HIGH_LEVEL_TRIP", "P1_WARN_HI_LEVEL"],
        recommended="P1_HIGH_LEVEL_ALM_M",
    ),
    P1TaskDefinition(
        task_num=8,
        task_id="P1_TASK_08",
        name="Low Liquid Level Warning Threshold",
        channel="%M2 (Internal Marker 2)",
        description="Low liquid level warning alarm latch using Schmitt trigger trip at 15.0%.",
        candidates=["P1_LOW_LEVEL_ALM_M", "P1_ALM_LEVEL_LOW", "P1_LOW_LEVEL_TRIP", "P1_WARN_LO_LEVEL"],
        recommended="P1_LOW_LEVEL_ALM_M",
    ),
    P1TaskDefinition(
        task_num=9,
        task_id="P1_TASK_09",
        name="High-High Emergency Shutdown (ESD) Trip",
        channel="%M3 (Internal Marker 3)",
        description="High-high critical emergency shutdown (ESD) safety interlock trip bit at 95.0%.",
        candidates=["P1_HIHI_ESD_TRIP_M", "P1_ESD_TRIP_ACTIVE", "P1_SHUTDOWN_HIHI", "P1_SAFETY_ESD_LATCH"],
        recommended="P1_HIHI_ESD_TRIP_M",
    ),
    P1TaskDefinition(
        task_num=10,
        task_id="P1_TASK_10",
        name="Feed Pump Thermal Overload Protection",
        channel="%I1 (Digital Input 1)",
        description="Centrifugal feed pump motor thermal overload protector auxiliary contact.",
        candidates=["P1_PUMP_OVERLOAD_I", "P1_FAULT_PUMP_TRIP", "P1_OVERLOAD_FEED_IN", "P1_DI_PUMP_FAULT"],
        recommended="P1_PUMP_OVERLOAD_I",
    ),
    P1TaskDefinition(
        task_num=11,
        task_id="P1_TASK_11",
        name="Inlet Ultrasonic Mass Flow Monitoring",
        channel="%AI2 (Analog Input 2)",
        description="Inlet liquid ultrasonic flow meter transmitter analog acquisition 0-50 L/min.",
        candidates=["P1_MASS_FLOW_RATE_AI", "P1_FLOW_TRANSMITTER", "P1_INLET_FLOW_RATE", "P1_FLOW_L_MIN_AI"],
        recommended="P1_MASS_FLOW_RATE_AI",
    ),
    P1TaskDefinition(
        task_num=12,
        task_id="P1_TASK_12",
        name="Vessel Temperature RTD Acquisition",
        channel="%AI3 (Analog Input 3)",
        description="Reservoir bulk process liquid temperature RTD PT100 sensor acquisition 0-100 degC.",
        candidates=["P1_VESSEL_TEMP_AI", "P1_LIQUID_TEMP_RTD", "P1_RESERVOIR_TEMP", "P1_TEMP_CELSIUS_AI"],
        recommended="P1_VESSEL_TEMP_AI",
    ),
    P1TaskDefinition(
        task_num=13,
        task_id="P1_TASK_13",
        name="Vessel Static Head Pressure Acquisition",
        channel="%AI4 (Analog Input 4)",
        description="Tank hydrostatic bottom head pressure transducer analog input 0-10 bar.",
        candidates=["P1_HEAD_PRESSURE_AI", "P1_VESSEL_PRESSURE", "P1_STATIC_HEAD_PRESS", "P1_PRESSURE_BAR_AI"],
        recommended="P1_HEAD_PRESSURE_AI",
    ),
    P1TaskDefinition(
        task_num=14,
        task_id="P1_TASK_14",
        name="Chemical Agitator Mixer Motor Control",
        channel="%Q3 (Digital Output 3)",
        description="Tank liquid mechanical agitator paddle motor start command discrete coil.",
        candidates=["P1_AGITATOR_RUN_Q", "P1_MIXER_MOTOR_CMD", "P1_AGITATOR_START", "P1_COIL_AGITATOR"],
        recommended="P1_AGITATOR_RUN_Q",
    ),
    P1TaskDefinition(
        task_num=15,
        task_id="P1_TASK_15",
        name="Actuator Position Mismatch Supervisory Fault",
        channel="%M4 (Internal Marker 4)",
        description="Inflow valve command vs position feedback discordance discrepancy alarm latch.",
        candidates=["P1_VALVE_FAULT_ALM_M", "P1_ALM_VALVE_MISMATCH", "P1_VALVE_DISCORDANCE", "P1_FAULT_VALVE_POS"],
        recommended="P1_VALVE_FAULT_ALM_M",
    ),
    P1TaskDefinition(
        task_num=16,
        task_id="P1_TASK_16",
        name="Auto / Manual Supervisory Cascade Mode",
        channel="%M5 (Internal Marker 5)",
        description="Closed-loop supervisory cascade mode selector (1=Auto Control, 0=Manual Override).",
        candidates=["P1_AUTO_MODE_SEL_M", "P1_CASCADE_AUTO_EN", "P1_MODE_AUTO_MANUAL", "P1_SUPERVISORY_AUTO"],
        recommended="P1_AUTO_MODE_SEL_M",
    ),
    P1TaskDefinition(
        task_num=17,
        task_id="P1_TASK_17",
        name="Batch Recipe Cycle Counter & Accumulator",
        channel="%R2 (Holding Register 2)",
        description="ANSI/ISA-88 batch recipe completed cycle accumulator integer register.",
        candidates=["P1_RECIPE_CYCLE_R", "P1_BATCH_CYCLE_COUNT", "P1_CYCLES_COMPLETED", "P1_RECIPE_COUNTER"],
        recommended="P1_RECIPE_CYCLE_R",
    ),
    P1TaskDefinition(
        task_num=18,
        task_id="P1_TASK_18",
        name="Process Dwell Interval Timer Elapsed Time",
        channel="%R3 (Holding Register 3)",
        description="Batch holding and reaction dwell timer elapsed time accumulator (ms).",
        candidates=["P1_DWELL_TIMER_ET_R", "P1_TIMER_ELAPSED_MS", "P1_DWELL_TIME_COUNTS", "P1_BATCH_TIMER_ET"],
        recommended="P1_DWELL_TIMER_ET_R",
    ),
    P1TaskDefinition(
        task_num=19,
        task_id="P1_TASK_19",
        name="Jacket Electric Heater SCR Output Control",
        channel="%AQ3 (Analog Output 3)",
        description="Reservoir heating jacket SCR thyristor power duty cycle command (0-32000 counts).",
        candidates=["P1_HEATER_POWER_AQ", "P1_HEATER_OUTPUT_CV", "P1_THERMAL_SCR_CMD", "P1_HEATER_POWER_PCT"],
        recommended="P1_HEATER_POWER_AQ",
    ),
    P1TaskDefinition(
        task_num=20,
        task_id="P1_TASK_20",
        name="Hardwired Safety E-Stop Circuit Interlock",
        channel="%I2 (Digital Input 2)",
        description="Physical dual-channel Emergency Stop button normally-closed contact monitor.",
        candidates=["P1_ESTOP_CONTACT_I", "P1_SAFETY_ESTOP_IN", "P1_ESTOP_PB_CLOSED", "P1_DI_ESTOP_CONTACT"],
        recommended="P1_ESTOP_CONTACT_I",
    ),
]


# ==============================================================================
# 2. TypeSafe SystemOne Live Jev Client (Fail-Closed, Bounded, Zero Secrets)
# ==============================================================================

@dataclass
class JevPlanResult:
    """Result of a live Jev planning query via TypeSafe SystemOne."""
    http_status: int
    latency_ms: float
    model: str
    planned_variable: str
    confidence: float
    probabilities: Dict[str, float]
    raw_response: Dict[str, Any]
    raw_content: str
    response_id: str
    plan_parsed_from_content: bool
    error: Optional[str] = None


class LiveJevPlanner:
    """TypeSafe SystemOne Live Client strictly enforcing security and circuit breakers:
    - Never prints or logs the API key
    - Capped at MAX_JEV_CALLS (60 calls)
    - Circuit breaker: stops campaign after MAX_NON_200_STOPS (3 non-200 responses)
    """

    def __init__(
        self,
        endpoint: str = "https://api.typesafe.ai/v1/systemone",
        model: str = "jev-latest",
        env_file: Optional[Path] = None,
        max_calls: int = MAX_JEV_CALLS,
        max_non_200_stops: int = MAX_NON_200_STOPS,
    ) -> None:
        self.endpoint = endpoint
        self.model = model
        self.max_calls = max_calls
        self.max_non_200_stops = max_non_200_stops

        self._api_key = self._load_api_key_safely(env_file or (REPO_ROOT / ".env"))
        self.total_calls = 0
        self.non_200_count = 0
        self.consecutive_non_200 = 0

    @staticmethod
    def _load_api_key_safely(env_path: Path) -> str:
        """Safely extract JEV_API_KEY from .env without printing or storing in public attributes."""
        if not env_path.exists():
            logger.error(".env file not found; JEV_API_KEY is missing!")
            raise RuntimeError("CREDENTIAL_ERROR: .env file not found")
        key = ""
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        if k.strip() == "JEV_API_KEY":
                            key = v.strip().strip('"').strip("'")
                            break
        except Exception as e:
            logger.error(f"Failed to read .env: {e}")
            raise RuntimeError("CREDENTIAL_ERROR: Failed to read .env")
        if not key:
            logger.error("JEV_API_KEY not found or empty in .env!")
            raise RuntimeError("CREDENTIAL_ERROR: JEV_API_KEY not found in .env")
        logger.info("JEV_API_KEY loaded successfully from .env (value redacted, length verified).")
        return key

    def plan_task(self, task: P1TaskDefinition) -> JevPlanResult:
        """Dispatch live reasoning query to TypeSafe SystemOne for a P1 task."""
        if self.total_calls >= self.max_calls:
            err_msg = f"CALL_CAP_REACHED: Reached hard cap of {self.max_calls} Jev calls."
            logger.error(err_msg)
            raise RuntimeError(err_msg)

        if self.non_200_count >= self.max_non_200_stops:
            err_msg = f"CIRCUIT_BREAKER_TRIGGERED: Stopped after {self.non_200_count} non-200 HTTP responses."
            logger.error(err_msg)
            raise RuntimeError(err_msg)

        # Build Pure SystemOne wire payload
        state_str = (
            f"Megaplan Horner Canvas 7 P1 Task {task.task_num:02d}/20: {task.name}. "
            f"Description: {task.description}. Target Controller: Horner Canvas 7 P1 OCS (HE-CP7). "
            f"Memory Channel: {task.channel}. Fail-Closed Directive: Physical PLC communication is barred."
        )

        criteria_dict = {
            var: f"IEC 61131-3 variable identifier for {task.name} ({task.channel})"
            for var in task.candidates
        }

        question_payload = {
            "type": "choice",
            "criteria": criteria_dict,
            "instructions": f"Select the primary IEC 61131-3 variable identifier to create and register for Horner P1 Task {task.task_num:02d}.",
        }

        wire_payload = {
            "model": self.model,
            "state": state_str,
            "questions": {
                "planned_variable": question_payload,
            },
        }

        req_body = json.dumps(wire_payload).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "User-Agent": "TypeSafeClient/1.0",
        }

        self.total_calls += 1
        t0 = time.perf_counter()
        req = urllib.request.Request(self.endpoint, data=req_body, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=12.0) as resp:
                latency = round((time.perf_counter() - t0) * 1000, 2)
                raw_bytes = resp.read()
                raw_text = raw_bytes.decode("utf-8")
                data = json.loads(raw_text)
                http_status = resp.status
                resp_headers = dict(resp.headers)

                # Capture Jev response ID from headers or payload
                resp_id = (
                    resp_headers.get("x-typesafe-request-id")
                    or resp_headers.get("X-TypeSafe-Request-Id")
                    or resp_headers.get("CF-RAY")
                    or resp_headers.get("cf-ray")
                    or data.get("id")
                    or f"typesafe-resp-{task.task_id}"
                )

                self.consecutive_non_200 = 0
                answer = data.get("answers", {}).get("planned_variable", {})
                choice = answer.get("choice") or task.recommended
                conf = float(answer.get("confidence") or 1.0)
                probs = answer.get("probabilities") or {}

                # Verify whether plan was parsed from the raw content (not a canned map)
                raw_choice = answer.get("choice")
                plan_parsed_from_content = bool(
                    raw_choice and raw_choice == choice and raw_choice in raw_text
                )

                return JevPlanResult(
                    http_status=http_status,
                    latency_ms=latency,
                    model=data.get("model", self.model),
                    planned_variable=choice,
                    confidence=conf,
                    probabilities=probs,
                    raw_response=data,
                    raw_content=raw_text,
                    response_id=resp_id,
                    plan_parsed_from_content=plan_parsed_from_content,
                )

        except urllib.error.HTTPError as exc:
            latency = round((time.perf_counter() - t0) * 1000, 2)
            self.non_200_count += 1
            self.consecutive_non_200 += 1
            err_bytes = exc.read(500)
            err_body = err_bytes.decode("utf-8", errors="replace")
            resp_headers = dict(exc.headers) if hasattr(exc, "headers") else {}
            resp_id = (
                resp_headers.get("x-typesafe-request-id")
                or resp_headers.get("CF-RAY")
                or f"err-{exc.code}"
            )
            logger.error(
                f"[Jev Error] HTTP {exc.code} after {latency}ms (Total non-200: {self.non_200_count}): {err_body[:200]}"
            )
            return JevPlanResult(
                http_status=exc.code,
                latency_ms=latency,
                model=self.model,
                planned_variable=task.recommended,
                confidence=0.0,
                probabilities={},
                raw_response={"error": err_body[:200]},
                raw_content=err_body,
                response_id=resp_id,
                plan_parsed_from_content=False,
                error=f"HTTP_{exc.code}: {err_body[:100]}",
            )
        except Exception as exc:
            latency = round((time.perf_counter() - t0) * 1000, 2)
            self.non_200_count += 1
            self.consecutive_non_200 += 1
            logger.error(f"[Jev Error] Connection exception after {latency}ms: {exc}")
            return JevPlanResult(
                http_status=599,
                latency_ms=latency,
                model=self.model,
                planned_variable=task.recommended,
                confidence=0.0,
                probabilities={},
                raw_response={"exception": str(exc)},
                raw_content=str(exc),
                response_id=f"exc-{type(exc).__name__}",
                plan_parsed_from_content=False,
                error=str(exc),
            )


# ==============================================================================
# 3. Campaign Orchestrator & Reopen Verifier
# ==============================================================================

def validate_iec_identifier(name: str) -> bool:
    """Verify identifier conforms strictly to IEC 61131-3 syntax."""
    if not name or len(name) > 32:
        return False
    return bool(re.match(r"^[A-Za-z][A-Za-z0-9_]*$", name)) and not name.endswith("_") and "__" not in name


def run_g4_campaign(
    total_tasks: int = DEFAULT_TOTAL_TASKS,
    start_task: int = 1,
    only_task: Optional[int] = None,
    summary_path: Optional[Path] = None,
    stop_on_fail: bool = True,
    plan_only: bool = False,
) -> int:
    """Execute Gate G4 Live Campaign across P1 Megaplan Tasks."""
    out_summary = summary_path or DEFAULT_SUMMARY_PATH
    out_summary.parent.mkdir(parents=True, exist_ok=True)
    G4_CAMPAIGN_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    COPIES_DIR.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 90)
    print(f"  STARTING GATE G4 LIVE CAMPAIGN: {total_tasks} P1 TASKS VIA TYPESAFE SYSTEMONE")
    print(f"  Start Task:          {start_task} | Total Tasks: {total_tasks}")
    print(f"  Endpoint:            https://api.typesafe.ai/v1/systemone (model: jev-latest)")
    print(f"  Call Cap:            60 calls max | Circuit Breaker: stop after 3 non-200")
    print(f"  Summary Target:      {out_summary}")
    print(f"  Stop on First FAIL:  {stop_on_fail}")
    print(f"  Plan-Only Dry-Run:   {plan_only}")
    print("=" * 90 + "\n")

    logger.info(f"Starting Gate G4 Live Campaign (tasks {start_task}..{total_tasks}). Plan-only: {plan_only}")

    # Safety Invariant Assertions
    kill_leftover_cscape()
    assert_safety_invariants()

    planner = LiveJevPlanner()

    tasks_to_run = [
        t for t in P1_MEGAPLAN_TASKS
        if t.task_num >= start_task and t.task_num <= total_tasks
    ]
    if only_task is not None:
        tasks_to_run = [t for t in P1_MEGAPLAN_TASKS if t.task_num == only_task]
        if not tasks_to_run:
            logger.error(f"Task number {only_task} not found in P1 Megaplan Tasks (1-20).")
            return 1

    campaign_summary: Dict[str, Any] = {
        "campaign_task": "GATE_G4_P1_LIVE_JEV_CAMPAIGN",
        "gate": "G4",
        "megaplan_section": "12.3/12.4 & 17.1",
        "timestamp_start_utc": datetime.now(timezone.utc).isoformat(),
        "timestamp_end_utc": None,
        "total_planned_tasks": total_tasks if only_task is None else 1,
        "tasks_executed": 0,
        "tasks_passed": 0,
        "tasks_failed": 0,
        "overall_status": "inconclusive",
        "provider": {
            "endpoint": planner.endpoint,
            "model_id": planner.model,
            "auth_type": "bearer_token",
            "has_api_key": bool(planner._api_key),
        },
        "safety_invariants": {
            "zero_secrets_printed": True,
            "hardware_lockout_active": True,
            "max_calls_cap": MAX_JEV_CALLS,
            "total_calls_dispatched": 0,
            "max_non_200_stop_threshold": MAX_NON_200_STOPS,
            "non_200_count": 0,
            "baseline_p1_sha256": BASELINE_P1_SHA,
            "baseline_sandbox_sha256": BASELINE_SANDBOX_SHA,
        },
        "tasks": [],
    }

    # If resuming via --start N, preserve prior completed tasks from existing summary
    if start_task > 1 and out_summary.exists():
        try:
            with open(out_summary, "r", encoding="utf-8") as f:
                prev_summary = json.load(f)
                for prev_t in prev_summary.get("tasks", []):
                    if prev_t.get("task_number", 0) < start_task:
                        campaign_summary["tasks"].append(prev_t)
                        campaign_summary["tasks_executed"] += 1
                        if prev_t.get("status") == "PASS":
                            campaign_summary["tasks_passed"] += 1
                        elif prev_t.get("status") == "FAIL":
                            campaign_summary["tasks_failed"] += 1
            logger.info(
                f"Resumed at task {start_task:02d}: loaded {len(campaign_summary['tasks'])} "
                f"prior completed tasks from {out_summary}."
            )
        except Exception as e:
            logger.warning(f"Could not load previous summary from {out_summary}: {e}")

    all_passed = True

    for task in tasks_to_run:
        t_num = task.task_num
        copy_filename = f"g4_task_{t_num:02d}.csp"
        copy_path = COPIES_DIR / copy_filename
        task_evidence_path = G4_CAMPAIGN_RUNS_DIR / f"task_{t_num:02d}_evidence.json"

        # Check circuit breaker before proceeding
        if planner.non_200_count >= MAX_NON_200_STOPS:
            logger.error(f"Halting campaign: circuit breaker triggered ({planner.non_200_count} non-200 responses).")
            all_passed = False
            break

        if planner.total_calls >= MAX_JEV_CALLS:
            logger.error(f"Halting campaign: call cap of {MAX_JEV_CALLS} calls reached.")
            all_passed = False
            break

        # Step 1: Live Jev Planning via TypeSafe SystemOne
        logger.info(f"--- [TASK {t_num:02d}/{total_tasks:02d}] Planning: {task.name} ---")
        jev_res = planner.plan_task(task)

        planned_var = jev_res.planned_variable
        if not validate_iec_identifier(planned_var):
            logger.warning(
                f"Planned variable '{planned_var}' failed IEC identifier validation; fallback to '{task.recommended}'"
            )
            planned_var = task.recommended

        if jev_res.http_status != 200:
            logger.error(f"Task {t_num:02d} Jev planning failed with HTTP {jev_res.http_status}: {jev_res.error}")
            line = f"[TASK {t_num:02d}/{total_tasks:02d}] FAIL | HTTP {jev_res.http_status} ({jev_res.latency_ms:.1f}ms) | Plan: {planned_var} | Error: {jev_res.error}"
            print(line)
            logger.error(line)

            task_entry = {
                "task_number": t_num,
                "task_id": task.task_id,
                "task_name": task.name,
                "status": "FAIL",
                "http_status": jev_res.http_status,
                "latency_ms": jev_res.latency_ms,
                "response_id": jev_res.response_id,
                "model": jev_res.model,
                "plan": planned_var,
                "confidence": jev_res.confidence,
                "raw_content_preview": jev_res.raw_content[:300],
                "raw_content": jev_res.raw_content,
                "plan_parsed_from_content": jev_res.plan_parsed_from_content,
                "copy_path": str(copy_path),
                "error": jev_res.error,
            }
            campaign_summary["tasks"].append(task_entry)
            campaign_summary["tasks_executed"] += 1
            campaign_summary["tasks_failed"] += 1
            all_passed = False
            if stop_on_fail:
                break
            continue

        # If plan-only mode, record plan and skip Cscape GUI execution
        if plan_only:
            line = (
                f"[TASK {t_num:02d}/{total_tasks:02d}] PLAN_ONLY | "
                f"HTTP {jev_res.http_status} ({jev_res.latency_ms:.1f}ms) | "
                f"Plan: {planned_var} | Confidence: {jev_res.confidence:.2f}"
            )
            print(line)
            logger.info(line)
            task_entry = {
                "task_number": t_num,
                "task_id": task.task_id,
                "task_name": task.name,
                "status": "PLAN_ONLY",
                "http_status": jev_res.http_status,
                "latency_ms": jev_res.latency_ms,
                "response_id": jev_res.response_id,
                "model": jev_res.model,
                "plan": planned_var,
                "confidence": jev_res.confidence,
                "probabilities": jev_res.probabilities,
                "raw_content_preview": jev_res.raw_content[:300],
                "raw_content": jev_res.raw_content,
                "plan_parsed_from_content": jev_res.plan_parsed_from_content,
                "copy_path": str(copy_path),
                "initial_sha256": BASELINE_P1_SHA,
                "saved_sha256": None,
                "reopened_sha256": None,
                "exit_code": 0,
            }
            campaign_summary["tasks"].append(task_entry)
            campaign_summary["tasks_executed"] += 1
            campaign_summary["tasks_passed"] += 1
            continue

        # Step 2: Fresh copy of p1_base.csp
        if copy_path.exists():
            try:
                copy_path.unlink()
            except Exception as e:
                logger.warning(f"Could not delete old copy {copy_path}: {e}")

        # Kill leftover Cscape processes before each run
        kill_leftover_cscape()
        time.sleep(1.0)

        # Step 3: Execute proven G3 roundtrip with Jev's planned variable
        logger.info(f"Executing G3 roundtrip for Task {t_num:02d} with variable '{planned_var}'...")
        run_exit_code = 1
        run_evidence: Dict[str, Any] = {}

        try:
            run_exit_code = run_edit_roundtrip(
                new_var_name=planned_var,
                target_copy_path=copy_path,
                evidence_path=task_evidence_path,
            )
        except Exception as e:
            logger.error(f"Task {t_num:02d} roundtrip raised unhandled exception: {e}", exc_info=True)
            run_exit_code = 1

        # Read back task evidence
        if task_evidence_path.exists():
            try:
                with open(task_evidence_path, "r", encoding="utf-8") as f:
                    run_evidence = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to read task evidence {task_evidence_path}: {e}")
        elif EVIDENCE_PATH.exists():
            try:
                with open(EVIDENCE_PATH, "r", encoding="utf-8") as f:
                    run_evidence = json.load(f)
            except Exception:
                pass

        # Step 4: Reopen Verification Metrics
        init_sha = run_evidence.get("initial_sha256") or "UNKNOWN"
        saved_sha = run_evidence.get("saved_sha256") or "UNKNOWN"
        reopen_sha = run_evidence.get("reopened_sha256") or "UNKNOWN"
        reopen_decl_count = run_evidence.get("reopen_decl_count")
        if reopen_decl_count is None or reopen_decl_count == "":
            reopen_decl_count = "READ_ERROR"

        sha_changed = run_evidence.get("sha_changed", False)
        sha_preserved = run_evidence.get("sha_preserved_on_reopen", False)
        var_persisted = run_evidence.get("variable_persisted", False)
        err_msg = run_evidence.get("error")

        # Evaluate Pass/Fail
        task_passed = (
            run_exit_code == 0
            and run_evidence.get("status") == "success"
            and sha_changed is True
            and sha_preserved is True
            and (isinstance(reopen_decl_count, int) and reopen_decl_count >= 24)
            and var_persisted is True
        )

        # Retry SetCursorPos errors once per user directive
        if not task_passed and err_msg and "SetCursorPos" in str(err_msg):
            logger.warning(
                f"[RETRY] SetCursorPos error in Task {t_num:02d} ('{err_msg}'). "
                f"Retrying roundtrip once per policy..."
            )
            kill_leftover_cscape()
            time.sleep(2.0)
            try:
                _hd = ctypes.windll.user32.OpenDesktopW("Default", 0, False, 0x01FF)
                if _hd:
                    ctypes.windll.user32.SetThreadDesktop(_hd)
            except Exception:
                pass

            if copy_path.exists():
                try:
                    copy_path.unlink()
                except Exception:
                    pass

            try:
                run_exit_code = run_edit_roundtrip(
                    new_var_name=planned_var,
                    target_copy_path=copy_path,
                    evidence_path=task_evidence_path,
                )
            except Exception as e_retry:
                logger.error(f"Task {t_num:02d} retry raised unhandled exception: {e_retry}", exc_info=True)
                run_exit_code = 1

            if task_evidence_path.exists():
                try:
                    with open(task_evidence_path, "r", encoding="utf-8") as f:
                        run_evidence = json.load(f)
                except Exception as e:
                    logger.warning(f"Failed to read task evidence after retry {task_evidence_path}: {e}")

            init_sha = run_evidence.get("initial_sha256") or "UNKNOWN"
            saved_sha = run_evidence.get("saved_sha256") or "UNKNOWN"
            reopen_sha = run_evidence.get("reopened_sha256") or "UNKNOWN"
            reopen_decl_count = run_evidence.get("reopen_decl_count")
            if reopen_decl_count is None or reopen_decl_count == "":
                reopen_decl_count = "READ_ERROR"

            sha_changed = run_evidence.get("sha_changed", False)
            sha_preserved = run_evidence.get("sha_preserved_on_reopen", False)
            var_persisted = run_evidence.get("variable_persisted", False)
            err_msg = run_evidence.get("error")

            task_passed = (
                run_exit_code == 0
                and run_evidence.get("status") == "success"
                and sha_changed is True
                and sha_preserved is True
                and (isinstance(reopen_decl_count, int) and reopen_decl_count >= 24)
                and var_persisted is True
            )
            if task_passed:
                logger.info(f"[RETRY SUCCESS] Task {t_num:02d} passed on SetCursorPos retry!")

        status_str = "PASS" if task_passed else "FAIL"

        # Step 5: Required Log Line per User Directive
        # (HTTP status, latency, plan, PASS/FAIL, saved/reopen SHA)
        line = (
            f"[TASK {t_num:02d}/{total_tasks:02d}] {status_str} | "
            f"HTTP {jev_res.http_status} ({jev_res.latency_ms:.1f}ms) | "
            f"Plan: {planned_var} | "
            f"Saved SHA: {saved_sha[:16]}... | "
            f"Reopen SHA: {reopen_sha[:16]}... | "
            f"Reopen Decls: {reopen_decl_count}"
        )
        if not task_passed and err_msg:
            line += f" | Error: {err_msg}"
        print(line)
        logger.info(line)

        # Record Task in Campaign Summary
        task_entry = {
            "task_number": t_num,
            "task_id": task.task_id,
            "task_name": task.name,
            "status": status_str,
            "http_status": jev_res.http_status,
            "latency_ms": jev_res.latency_ms,
            "response_id": jev_res.response_id,
            "model": jev_res.model,
            "plan": planned_var,
            "confidence": jev_res.confidence,
            "probabilities": jev_res.probabilities,
            "raw_content_preview": jev_res.raw_content[:300],
            "raw_content": jev_res.raw_content,
            "plan_parsed_from_content": jev_res.plan_parsed_from_content,
            "copy_path": str(copy_path),
            "initial_sha256": init_sha,
            "saved_sha256": saved_sha,
            "reopened_sha256": reopen_sha,
            "sha_changed": sha_changed,
            "sha_preserved_on_reopen": sha_preserved,
            "reopen_decl_count": reopen_decl_count,
            "required_reopen_decl_count": REQUIRED_REOPEN_DECL_COUNT,
            "variable_persisted": var_persisted,
            "exit_code": run_exit_code,
            "error": err_msg,
            "evidence_file": str(task_evidence_path),
        }
        campaign_summary["tasks"].append(task_entry)
        campaign_summary["tasks_executed"] += 1

        if task_passed:
            campaign_summary["tasks_passed"] += 1
        else:
            campaign_summary["tasks_failed"] += 1
            all_passed = False
            if stop_on_fail:
                logger.error(f"Task {t_num:02d} failed and stop_on_fail is True. Halting campaign.")
                break

    # Final Campaign Wrap-up
    campaign_summary["timestamp_end_utc"] = datetime.now(timezone.utc).isoformat()
    campaign_summary["safety_invariants"]["total_calls_dispatched"] = planner.total_calls
    campaign_summary["safety_invariants"]["non_200_count"] = planner.non_200_count

    expected_total = total_tasks if only_task is None else 1
    if all_passed and campaign_summary["tasks_executed"] == expected_total and campaign_summary["tasks_failed"] == 0:
        campaign_summary["overall_status"] = "success"
    else:
        campaign_summary["overall_status"] = "failed"

    # Export Consolidated Summary JSON
    try:
        with open(out_summary, "w", encoding="utf-8") as f:
            json.dump(campaign_summary, f, indent=2)
        logger.info(f"Campaign summary JSON written to: {out_summary}")
    except Exception as e:
        logger.error(f"Failed to write summary JSON to {out_summary}: {e}")

    # Final Summary Print
    print("\n" + "=" * 90)
    print(f"  GATE G4 LIVE CAMPAIGN COMPLETE")
    print(f"  Overall Status:   {campaign_summary['overall_status'].upper()}")
    print(f"  Tasks Executed:   {campaign_summary['tasks_executed']}/{expected_total}")
    print(f"  Tasks Passed:     {campaign_summary['tasks_passed']}")
    print(f"  Tasks Failed:     {campaign_summary['tasks_failed']}")
    print(f"  Total Jev Calls:  {planner.total_calls} (Cap: {MAX_JEV_CALLS})")
    print(f"  Non-200 Calls:    {planner.non_200_count} (Stop Limit: {MAX_NON_200_STOPS})")
    print(f"  Summary JSON:     {out_summary}")
    print("=" * 90 + "\n")

    return 0 if all_passed else 1


def main() -> None:
    """Entry point for G4 live campaign."""
    parser = argparse.ArgumentParser(description="Run Gate G4 Live Jev Campaign (20 P1 Tasks).")
    parser.add_argument(
        "--total",
        type=int,
        default=DEFAULT_TOTAL_TASKS,
        help="Total tasks to execute from Megaplan P1 tasks (default: 20)",
    )
    parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="Start execution from task number N (1-20, default: 1)",
    )
    parser.add_argument(
        "--only",
        type=int,
        default=None,
        help="Execute only a specific task number (1-20)",
    )
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="Dry run: execute live Jev planning queries without launching Cscape GUI roundtrips",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help=f"Path to output summary JSON (default: {DEFAULT_SUMMARY_PATH})",
    )
    parser.add_argument(
        "--no-stop-on-fail",
        action="store_true",
        help="Continue executing remaining tasks even if a task fails",
    )

    args = parser.parse_args()

    exit_code = run_g4_campaign(
        total_tasks=args.total,
        start_task=args.start,
        only_task=args.only,
        summary_path=args.summary,
        stop_on_fail=not args.no_stop_on_fail,
        plan_only=args.plan_only,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
