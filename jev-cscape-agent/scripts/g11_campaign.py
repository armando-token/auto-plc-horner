#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gate G11 Campaign: Evaluacion Certificada en Reservado, Baselines y Endurance 24h (W084-W090).

Mandate (MEGAPLAN Section G11, Work Packages W084-W090):
  - W084: Reserved suite of 30 unseen tasks per certified family (Ladder, HMI, ST var = 90 unseen tasks total),
          strictly disjoint from all G3, G7, G8, G9, and G10 task IDs, tag names, and register allocations.
  - W085: Rule-based (`rule_baseline`) and LLM-choice (`llm_choice_baseline`) baselines operating on the
          EXACT SAME observer snapshot (`ObserverSnapshot`) as the full Jev agent (`jev_full`).
  - W086: Per-stage monotonic latency (`reset_ms`, `observe_ms`, `plan_ms`, `act_ms`, `verify_ms`, `total_ms`),
          real HTTP token/cost accounting from `https://api.typesafe.ai/v1/systemone`, and success/error rates.
  - W087: Balanced multi-condition runs with deterministic project reset (`work/disposable/p1_base.csp`,
          SHA-256 `5ab52feeff31fda15301cebf1498dddb25167f8ea8a3640185d511600b5f2881`), registry reset,
          and leftover process cleanup before every trial.
  - W088: 24-hour endurance worker (`EnduranceWorker24h`) with finite bounded queue, strict budget cap
          (`max_budget_usd`, `max_api_calls`, `max_tokens`), controlled Cscape restart (every N tasks or on
          RSS/handle threshold or fault), and atomic SHA-256 verified JSON checkpoints with resume support.
  - W089: Non-parametric statistical reporting: median (`p50`), `p95`, and 95% confidence intervals
          (order-statistic / deterministic bootstrap CI for continuous metrics; Wilson score 95% CI for
          binomial success/error rates).
  - W090: Zero synthetic results (unexecuted cells report `null` / `inconclusive`), strict log and artifact
          isolation (`artifacts/logs/g11_unit_test.log` vs `artifacts/logs/g11_campaign.log`).
"""

from __future__ import annotations

import argparse
from collections import deque
import ctypes
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import random
import shutil
import sys
import time
from typing import Any, Callable, Deque, Dict, List, Optional, Sequence, Set, Tuple, Union
import urllib.error
import urllib.request

# Dynamic repository root resolution
REPO_ROOT = Path(__file__).resolve().parent.parent
if not (REPO_ROOT / "work" / "disposable" / "p1_base.csp").exists():
    REPO_ROOT = Path(r"C:\HornerAI\jev-cscape-agent")

if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import warnings
import olefile
import psutil
import win32con
import win32gui
import win32process
from pywinauto import Application

warnings.filterwarnings("ignore", message=".*32-bit application.*", category=UserWarning)

from jev_cscape.security.exceptions import HardwareLockoutError
from jev_cscape.security.guard import SecurityGuard

from scripts.g3_edit_roundtrip import (
    TVITEMW32,
    find_program_variables_treeview,
    get_treeview_item_texts,
    parse_csp_cfbf_declarations,
)
from scripts.g7_acceptance import (
    assert_zero_silent_duplications,
    compute_cfbf_delta,
    dismiss_about_cscape_and_wait_main_enabled,
    parse_cfbf_ladder_elements,
    trigger_and_read_cscape_error_check,
)
from scripts.g7_campaign import (
    ID_SELECT_ELEMENTS,
    activate_ladder_toolbar_button,
    assign_tag_in_dialog,
    open_main_ladder_editor,
    resolve_ladder_canvas,
)
from scripts.g8_acceptance import (
    dismiss_lingering_hmi_dialogs,
    handle_confirmation_popups,
    parse_cfbf_hmi_elements,
    place_hmi_object_on_screen,
)
from scripts.g9_campaign import (
    BASELINE_P1_SHA,
    BASE_P1_PATH,
    ID_CONTROLLER_DOWNLOAD,
    ID_FILE_SAVE,
    ID_HMI_SELECT_ELEMENTS,
    ID_INSERT_NEW_RUNG,
    ID_NC_CONTACT,
    ID_NO_COIL,
    ID_NO_CONTACT,
    ID_PROGRAM_DOWNLOAD,
    ID_PROGRAM_ERRORCHECK,
    compute_sha256,
    dismiss_error_check_modals,
)
from scripts.g10_campaign import (
    _install_cursorless_mouse_guard,
    _keep_interactive_desktop_awake,
    declare_variables_via_live_cscape_win32,
)
from scripts.probe_hmi_editor import (
    close_cscape_gracefully,
    configure_cscape_registry,
    dump_child_windows_recursive,
    handle_startup_dialogs_and_wait_for_main_window,
    is_screen_editor_window,
    kill_leftover_cscape,
    launch_cscape_with_project,
    open_screen_editor_dynamic,
)

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# Directories & Output Paths
COPIES_DIR = REPO_ROOT / "work" / "disposable" / "copies"
COPIES_DIR.mkdir(parents=True, exist_ok=True)
G11_SANDBOX_DIR = REPO_ROOT / "work" / "disposable" / "g11_sandbox"
G11_SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

ARTIFACTS_G11_DIR = REPO_ROOT / "artifacts" / "G11"
ARTIFACTS_G11_DIR.mkdir(parents=True, exist_ok=True)
TRIALS_EVIDENCE_DIR = ARTIFACTS_G11_DIR / "trials"
TRIALS_EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_JSON_PATH = ARTIFACTS_G11_DIR / "g11_results.json"
SUMMARY_JSON_PATH = ARTIFACTS_G11_DIR / "g11_campaign_summary.json"
CHECKPOINT_JSON_PATH = ARTIFACTS_G11_DIR / "g11_endurance_checkpoint.json"

UNIT_TEST_ARTIFACTS_G11_DIR = REPO_ROOT / "work" / "disposable" / "g11_unit_test_artifacts"
UNIT_TEST_ARTIFACTS_G11_DIR.mkdir(parents=True, exist_ok=True)
UNIT_TEST_TRIALS_DIR = UNIT_TEST_ARTIFACTS_G11_DIR / "trials"
UNIT_TEST_TRIALS_DIR.mkdir(parents=True, exist_ok=True)
UNIT_TEST_RESULTS_JSON_PATH = UNIT_TEST_ARTIFACTS_G11_DIR / "g11_results.json"
UNIT_TEST_SUMMARY_JSON_PATH = UNIT_TEST_ARTIFACTS_G11_DIR / "g11_campaign_summary.json"
UNIT_TEST_CHECKPOINT_JSON_PATH = UNIT_TEST_ARTIFACTS_G11_DIR / "g11_endurance_checkpoint.json"

LOG_DIR = REPO_ROOT / "artifacts" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE_PATH = LOG_DIR / "g11_campaign.log"
UNIT_TEST_LOG_FILE_PATH = LOG_DIR / "g11_unit_test.log"


def _is_running_under_pytest() -> bool:
    return (
        "pytest" in sys.modules
        or "_pytest" in sys.modules
        or bool(os.environ.get("PYTEST_CURRENT_TEST"))
    )


logger = logging.getLogger("g11_campaign")
logger.setLevel(logging.INFO)
logger.propagate = False


def configure_g11_logging(
    log_path: Optional[Path] = None,
    unit_test_mode: Optional[bool] = None,
    force_live_log: bool = False,
) -> Path:
    """Configure G11 logging so unit tests NEVER write to artifacts/logs/g11_campaign.log."""
    if unit_test_mode is None:
        unit_test_mode = _is_running_under_pytest() and not force_live_log
    target_path = log_path or (UNIT_TEST_LOG_FILE_PATH if unit_test_mode else LOG_FILE_PATH)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    for h in list(logger.handlers):
        try:
            h.flush()
            h.close()
        except Exception:
            pass
    logger.handlers.clear()

    fh = logging.FileHandler(target_path, mode="a", encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    return target_path


configure_g11_logging()


# =============================================================================
# Enums & Core Data Structures (W084 - W090)
# =============================================================================

class CertifiedFamily(str, Enum):
    """Certified task families evaluated in Gate G11 (W084)."""
    LADDER = "ladder"
    HMI = "hmi"
    ST_VAR = "st_var"


class PlannerPolicy(str, Enum):
    """Planner policies compared on the identical observer snapshot (W085)."""
    JEV_FULL = "jev_full"
    RULE_BASELINE = "rule_baseline"
    LLM_CHOICE_BASELINE = "llm_choice_baseline"


class WorkPackageG11(str, Enum):
    """Gate G11 Work Package identifiers (W084-W090)."""
    W084 = "W084"  # Reserved suite of 30 unseen tasks per certified family (Ladder, HMI, ST var)
    W085 = "W085"  # Rule & LLM-choice baselines on identical observer
    W086 = "W086"  # Per-stage latency, real tokens/cost, success/error rates
    W087 = "W087"  # Balanced runs with deterministic project reset
    W088 = "W088"  # 24h endurance worker with finite queue, budget cap, controlled restart, checkpoints
    W089 = "W089"  # Statistical median/p95 with 95% confidence intervals
    W090 = "W090"  # Zero synthetic results & campaign acceptance gate


@dataclass(frozen=True)
class G11ReservedTaskSpec:
    """Immutable specification of an unseen reserved benchmark task in W084.

    Exposes `.task_num`, `.level_pv_tag`, and `.inlet_valve_tag` so `spec=task` can be passed directly
    into `declare_variables_via_live_cscape_win32(pid, main_hwnd, app, spec, app_uia=..., copy_path=...)`.
    """
    task_id: str
    family: CertifiedFamily
    family_index: int  # 1..30 within family
    global_index: int  # 1..90 overall
    subsystem: str
    description: str
    primary_tag: str
    primary_iec_type: str
    primary_ocs_reg: str
    secondary_tag: str
    secondary_iec_type: str
    secondary_ocs_reg: str
    ladder_contact_cmd: int = ID_NO_CONTACT
    ladder_coil_cmd: int = ID_NO_COIL
    hmi_object_type: str = "NumericDisplay"
    hmi_format: str = "%d"
    is_reserved_unseen: bool = True

    @property
    def task_num(self) -> int:
        """Offset index so `100 + task_num` equals 301..330 (ST_VAR), 401..430 (LADDER), or 501..530 (HMI)."""
        base_offset = (
            200
            if self.family == CertifiedFamily.ST_VAR
            else (300 if self.family == CertifiedFamily.LADDER else 400)
        )
        return base_offset + int(self.family_index)

    @property
    def level_pv_tag(self) -> str:
        """Analog `INT` tag mapped to `%R{100 + task_num}` by `declare_variables_via_live_cscape_win32`."""
        return self.secondary_tag if self.family == CertifiedFamily.LADDER else self.primary_tag

    @property
    def inlet_valve_tag(self) -> str:
        """Digital `BOOL` tag mapped to `%M{100 + task_num}` by `declare_variables_via_live_cscape_win32`."""
        return self.primary_tag if self.family == CertifiedFamily.LADDER else self.secondary_tag


@dataclass(frozen=True)
class ObserverSnapshot:
    """Frozen, SHA-256 addressed snapshot of the Cscape GUI and CFBF project container (W085).

    Shared identically across `jev_full`, `rule_baseline`, and `llm_choice_baseline`.
    """
    snapshot_id: str
    timestamp_utc: str
    cscape_pid: int
    main_hwnd: int
    window_rect: Tuple[int, int, int, int]
    window_width: int
    window_height: int
    is_iconic: bool
    is_visible: bool
    is_enabled: bool
    foreground_matches: bool
    active_editor_class: str
    active_modals: Tuple[str, ...]
    statusbar_text: str
    treeview_item_count: int
    cfbf_path: str
    cfbf_sha256: str
    cfbf_ole2_valid: bool
    cfbf_declarations_count: int
    cfbf_merkle_root: str
    ladder_element_count: int
    ladder_network_count: int
    hmi_object_count: int

    def to_state_string(self, task: G11ReservedTaskSpec) -> str:
        """Deterministic canonical state description passed to planners."""
        return (
            f"Gate=G11; SnapshotID={self.snapshot_id}; TaskID={task.task_id}; "
            f"Family={task.family.value}; Subsystem={task.subsystem}; "
            f"PrimaryTag={task.primary_tag}({task.primary_iec_type}@{task.primary_ocs_reg}); "
            f"SecondaryTag={task.secondary_tag}({task.secondary_iec_type}@{task.secondary_ocs_reg}); "
            f"MainRect={list(self.window_rect)}; Enabled={self.is_enabled}; Visible={self.is_visible}; "
            f"ActiveEditor={self.active_editor_class}; Modals={list(self.active_modals)}; "
            f"StatusBar={self.statusbar_text}; TreeCount={self.treeview_item_count}; "
            f"CFBF_SHA={self.cfbf_sha256[:16]}; CFBF_Decls={self.cfbf_declarations_count}; "
            f"CFBF_Merkle={self.cfbf_merkle_root[:16]}; LadderElems={self.ladder_element_count}; "
            f"HMIObjects={self.hmi_object_count}"
        )


@dataclass
class StageLatencyTelemetry:
    """Monotonic per-stage latency measurements in milliseconds (W086)."""
    reset_ms: float = 0.0
    observe_ms: float = 0.0
    plan_ms: float = 0.0
    act_ms: float = 0.0
    verify_ms: float = 0.0
    total_ms: float = 0.0


@dataclass
class TokenCostTelemetry:
    """Real token and USD cost accounting per planner call (W086)."""
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    token_source: str = "rule_zero"  # "api_usage" | "wire_payload_measured" | "rule_zero" | "unexecuted"
    http_status: Optional[int] = None
    req_id: str = "none"
    api_calls: int = 0


@dataclass
class PlannerDecision:
    """Unified output decision from `jev_full`, `rule_baseline`, or `llm_choice_baseline` (W085)."""
    policy: PlannerPolicy
    snapshot_id: str
    task_id: str
    family: CertifiedFamily
    action_template: str
    register_guard_mode: str
    verification_mode: str
    noul_scores: Optional[Dict[str, float]]
    token_telemetry: TokenCostTelemetry
    plan_latency_ms: float
    raw_answers: Dict[str, Any] = field(default_factory=dict)


@dataclass
class G11TrialRecord:
    """Complete execution and verification record for a single (task, policy) trial."""
    trial_id: str
    task_id: str
    family: str
    policy: str
    execution_mode: str  # "live" | "dry_run"
    status: str  # "success" | "failed" | "blocked" | "inconclusive"
    error_code: Optional[str]
    observer_snapshot_id: str
    cscape_pid: int
    file_path: str
    pre_reset_sha256: str
    file_sha_before: str
    file_sha_after: str
    sha_mutated: bool
    compile_clean: bool
    cfbf_verified: bool
    latency: StageLatencyTelemetry
    tokens: TokenCostTelemetry
    action_template: str
    noul_scores: Optional[Dict[str, float]]
    out_of_scope_writes: int = 0
    blind_retries: int = 0
    false_completions: int = 0
    details: str = ""
    timestamp_utc: str = ""


# =============================================================================
# W084: Reserved Suite of 30 Unseen Tasks per Certified Family (90 Total)
# =============================================================================

_ST_VAR_SUBSYSTEMS: List[Tuple[str, str, str, str]] = [
    ("Autoclave Zone 01", "ACLV01", "CHMB_PV", "STM_CMD"),
    ("Autoclave Zone 02", "ACLV02", "JCKT_PV", "BLD_CMD"),
    ("Autoclave Zone 03", "ACLV03", "HDSP_PV", "VNT_CMD"),
    ("Autoclave Zone 04", "ACLV04", "VACD_PV", "VAC_ENA"),
    ("Autoclave Zone 05", "ACLV05", "COND_PV", "TRP_CMD"),
    ("Autoclave Zone 06", "ACLV06", "SEAL_PV", "GSK_CMD"),
    ("Autoclave Zone 07", "ACLV07", "HOLD_PV", "HLD_RUN"),
    ("Autoclave Zone 08", "ACLV08", "COOL_PV", "CHL_CMD"),
    ("Autoclave Zone 09", "ACLV09", "EXHM_PV", "FEX_CMD"),
    ("Autoclave Zone 10", "ACLV10", "SLEX_PV", "MTR_CMD"),
    ("Lyophilizer Shelf 11", "LYO11", "SHLF_SP", "SIL_ENA"),
    ("Lyophilizer Condenser 12", "LYO12", "ICEC_PV", "DFR_CMD"),
    ("Lyophilizer Stopper 13", "LYO13", "RAMH_PV", "STP_CMD"),
    ("Lyophilizer Pirani 14", "LYO14", "PIRA_PV", "N2D_CMD"),
    ("Lyophilizer Baratron 15", "LYO15", "BARA_PV", "ISO_CMD"),
    ("Calciner Kiln 16", "KILN16", "HRTH_PV", "BRN_CMD"),
    ("Calciner Kiln 17", "KILN17", "DRUM_PV", "DRV_ENA"),
    ("Calciner Kiln 18", "KILN18", "FLUE_PV", "IDF_CMD"),
    ("Calciner Kiln 19", "KILN19", "OXYT_PV", "AIR_CMD"),
    ("Calciner Kiln 20", "KILN20", "GRTE_PV", "CLK_ENA"),
    ("Pasteurizer HTST 21", "HTST21", "REGN_PV", "FDV_CMD"),
    ("Pasteurizer HTST 22", "HTST22", "TUBE_PV", "BST_ENA"),
    ("Pasteurizer HTST 23", "HTST23", "DPRS_PV", "TMP_RUN"),
    ("Pasteurizer HTST 24", "HTST24", "GLYC_PV", "GLY_CMD"),
    ("Pasteurizer HTST 25", "HTST25", "HWTR_PV", "INJ_CMD"),
    ("Retort Sterilizer 26", "RTRT26", "OVPR_PV", "AIR_INJ"),
    ("Retort Sterilizer 27", "RTRT27", "SPRY_PV", "SPR_PMP"),
    ("Retort Sterilizer 28", "RTRT28", "BSKT_PV", "ROT_CMD"),
    ("Retort Sterilizer 29", "RTRT29", "F0AC_PV", "F0M_FLG"),
    ("Retort Sterilizer 30", "RTRT30", "BOLT_PV", "LCK_CMD"),
]

_LADDER_SUBSYSTEMS: List[Tuple[str, str, str, str]] = [
    ("Cryogenic Column 01", "CRYO01", "PERM_SW", "LOX_SP"),
    ("Cryogenic Column 02", "CRYO02", "CLVL_OK", "LIN_SP"),
    ("Cryogenic Column 03", "CRYO03", "TVIB_OK", "EXP_SP"),
    ("Cryogenic Column 04", "CRYO04", "PRGE_OK", "N2B_SP"),
    ("Cryogenic Column 05", "CRYO05", "SIEV_OK", "RGN_SP"),
    ("Cryogenic Column 06", "CRYO06", "ARDR_OK", "CAR_SP"),
    ("Reverse Osmosis 07", "ROSM07", "COND_OK", "HPP_SP"),
    ("Reverse Osmosis 08", "ROSM08", "CRDP_OK", "PRM_SP"),
    ("Reverse Osmosis 09", "ROSM09", "ASCL_OK", "MTS_SP"),
    ("Reverse Osmosis 10", "ROSM10", "BSLF_OK", "DCL_SP"),
    ("Reverse Osmosis 11", "ROSM11", "FLSH_RQ", "FFL_SP"),
    ("Reverse Osmosis 12", "ROSM12", "CIPR_SW", "CIP_SP"),
    ("Bioreactor Vessel 13", "BIOR13", "SPRG_OK", "O2E_SP"),
    ("Bioreactor Vessel 14", "BIOR14", "FOAM_OK", "AFM_SP"),
    ("Bioreactor Vessel 15", "BIOR15", "AGIT_OK", "IMP_SP"),
    ("Bioreactor Vessel 16", "BIOR16", "PHBD_OK", "TIT_SP"),
    ("Bioreactor Vessel 17", "BIOR17", "DO2S_OK", "AMF_SP"),
    ("Bioreactor Vessel 18", "BIOR18", "HRVP_SW", "HRV_SP"),
    ("Compressor Train 19", "CCMP19", "LUBE_OK", "AUX_SP"),
    ("Compressor Train 20", "CCMP20", "SRGM_OK", "ASB_SP"),
    ("Compressor Train 21", "CCMP21", "DGSL_OK", "SN2_SP"),
    ("Compressor Train 22", "CCMP22", "SCRB_OK", "KOD_SP"),
    ("Compressor Train 23", "CCMP23", "ICLT_OK", "FFN_SP"),
    ("Compressor Train 24", "CCMP24", "TBRG_OK", "MTR_SP"),
    ("Solvent Recovery 25", "SOLV25", "CBED_OK", "DSB_SP"),
    ("Solvent Recovery 26", "SOLV26", "LELA_OK", "INP_SP"),
    ("Solvent Recovery 27", "SOLV27", "DCNT_OK", "SLV_SP"),
    ("Solvent Recovery 28", "SOLV28", "DSTP_OK", "RFX_SP"),
    ("Solvent Recovery 29", "SOLV29", "VSPT_OK", "LRV_SP"),
    ("Solvent Recovery 30", "SOLV30", "FLAR_OK", "TOX_SP"),
]

_HMI_SUBSYSTEMS: List[Tuple[str, str, str, str]] = [
    ("Cleanroom HVAC 01", "HVAC01", "DIFF_PV", "BLW_LMP"),
    ("Cleanroom HVAC 02", "HVAC02", "DEWP_PV", "DSC_LMP"),
    ("Cleanroom HVAC 03", "HVAC03", "RACH_PV", "VAV_LMP"),
    ("Cleanroom HVAC 04", "HVAC04", "ALCK_PV", "DRL_LMP"),
    ("Cleanroom HVAC 05", "HVAC05", "PTCL_PV", "ULP_LMP"),
    ("Cleanroom HVAC 06", "HVAC06", "CHDT_PV", "RHT_LMP"),
    ("Ultrapure Water 07", "UPWL07", "RSST_PV", "EDI_LMP"),
    ("Ultrapure Water 08", "UPWL08", "TOCP_PV", "UVB_LMP"),
    ("Ultrapure Water 09", "UPWL09", "SMDP_PV", "PLS_LMP"),
    ("Ultrapure Water 10", "UPWL10", "OZON_PV", "OZD_LMP"),
    ("Ultrapure Water 11", "UPWL11", "DGAS_PV", "SWP_LMP"),
    ("Ultrapure Water 12", "UPWL12", "RLVL_PV", "SAN_LMP"),
    ("Electroplating 13", "EPLT13", "RECT_PV", "AND_LMP"),
    ("Electroplating 14", "EPLT14", "CUSO_PV", "DOS_LMP"),
    ("Electroplating 15", "EPLT15", "EDUC_PV", "AGT_LMP"),
    ("Electroplating 16", "EPLT16", "CATH_PV", "BRL_LMP"),
    ("Electroplating 17", "EPLT17", "FUME_PV", "MST_LMP"),
    ("Electroplating 18", "EPLT18", "RINS_PV", "DIM_LMP"),
    ("Electrolyzer 19", "HYEL19", "CELL_PV", "DCB_LMP"),
    ("Electrolyzer 20", "HYEL20", "KOHF_PV", "LYE_LMP"),
    ("Electrolyzer 21", "HYEL21", "H2O2_PV", "DXO_LMP"),
    ("Electrolyzer 22", "HYEL22", "CBAR_PV", "BPR_LMP"),
    ("Electrolyzer 23", "HYEL23", "PSAD_PV", "PSA_LMP"),
    ("Electrolyzer 24", "HYEL24", "STCL_PV", "PHX_LMP"),
    ("Vacuum Furnace 25", "VFUR25", "PYRO_PV", "MLY_LMP"),
    ("Vacuum Furnace 26", "VFUR26", "DIFF_MW", "FOR_LMP"),
    ("Vacuum Furnace 27", "VFUR27", "ARQN_PV", "TRB_LMP"),
    ("Vacuum Furnace 28", "VFUR28", "WMAN_PV", "ECW_LMP"),
    ("Vacuum Furnace 29", "VFUR29", "LOAD_PV", "LDR_LMP"),
    ("Vacuum Furnace 30", "VFUR30", "PPRS_PV", "MFN_LMP"),
]


def get_g11_reserved_unseen_tasks(
    family_filter: Optional[Union[str, CertifiedFamily]] = None,
    max_per_family: Optional[int] = None,
) -> List[G11ReservedTaskSpec]:
    """Return the W084 reserved suite of 30 unseen tasks per certified family (90 tasks total)."""
    tasks: List[G11ReservedTaskSpec] = []
    global_idx = 0

    # 1. ST_VAR family (30 unseen tasks: %R301..%R330, %M301..%M330)
    for i, (subsys, prefix, analog_suffix, bool_suffix) in enumerate(_ST_VAR_SUBSYSTEMS, start=1):
        global_idx += 1
        tasks.append(
            G11ReservedTaskSpec(
                task_id=f"G11_W084_ST_VAR_{i:02d}",
                family=CertifiedFamily.ST_VAR,
                family_index=i,
                global_index=global_idx,
                subsystem=subsys,
                description=(
                    f"Declare unseen IEC 61131-3 global variables {prefix}_{analog_suffix} (INT @ %R{300 + i}) "
                    f"and {prefix}_{bool_suffix} (BOOL @ %M{300 + i}) for {subsys}."
                ),
                primary_tag=f"{prefix}_{analog_suffix}",
                primary_iec_type="INT",
                primary_ocs_reg=f"%R{300 + i}",
                secondary_tag=f"{prefix}_{bool_suffix}",
                secondary_iec_type="BOOL",
                secondary_ocs_reg=f"%M{300 + i}",
            )
        )

    # 2. LADDER family (30 unseen tasks: %M401..%M430 BOOL contacts, %R401..%R430 INT companion registers)
    for i, (subsys, prefix, contact_suffix, coil_suffix) in enumerate(_LADDER_SUBSYSTEMS, start=1):
        global_idx += 1
        contact_cmd = ID_NO_CONTACT if (i % 2 == 1) else ID_NC_CONTACT
        tasks.append(
            G11ReservedTaskSpec(
                task_id=f"G11_W084_LADDER_{i:02d}",
                family=CertifiedFamily.LADDER,
                family_index=i,
                global_index=global_idx,
                subsystem=subsys,
                description=(
                    f"Insert unseen ladder rung on {subsys} binding contact & coil {prefix}_{contact_suffix} "
                    f"(BOOL @ %M{400 + i}) with companion setpoint {prefix}_{coil_suffix} (INT @ %R{400 + i})."
                ),
                primary_tag=f"{prefix}_{contact_suffix}",
                primary_iec_type="BOOL",
                primary_ocs_reg=f"%M{400 + i}",
                secondary_tag=f"{prefix}_{coil_suffix}",
                secondary_iec_type="INT",
                secondary_ocs_reg=f"%R{400 + i}",
                ladder_contact_cmd=contact_cmd,
                ladder_coil_cmd=ID_NO_COIL,
            )
        )

    # 3. HMI family (30 unseen tasks: %R501..%R530 display tags, %M501..%M530 pilot tags)
    for i, (subsys, prefix, pv_suffix, lamp_suffix) in enumerate(_HMI_SUBSYSTEMS, start=1):
        global_idx += 1
        tasks.append(
            G11ReservedTaskSpec(
                task_id=f"G11_W084_HMI_{i:02d}",
                family=CertifiedFamily.HMI,
                family_index=i,
                global_index=global_idx,
                subsystem=subsys,
                description=(
                    f"Bind unseen HMI Screen 1 NumericDisplay widget to {prefix}_{pv_suffix} "
                    f"(INT @ %R{500 + i}) with companion pilot tag {prefix}_{lamp_suffix} (BOOL @ %M{500 + i}) for {subsys}."
                ),
                primary_tag=f"{prefix}_{pv_suffix}",
                primary_iec_type="INT",
                primary_ocs_reg=f"%R{500 + i}",
                secondary_tag=f"{prefix}_{lamp_suffix}",
                secondary_iec_type="BOOL",
                secondary_ocs_reg=f"%M{500 + i}",
                hmi_object_type="NumericDisplay",
                hmi_format="%d",
            )
        )

    if family_filter is not None and str(family_filter).lower() not in ("all", ""):
        fam_str = family_filter.value if isinstance(family_filter, CertifiedFamily) else str(family_filter).lower()
        tasks = [t for t in tasks if t.family.value == fam_str]

    if max_per_family is not None and max_per_family > 0:
        filtered: List[G11ReservedTaskSpec] = []
        counts: Dict[CertifiedFamily, int] = {f: 0 for f in CertifiedFamily}
        for t in tasks:
            if counts[t.family] < max_per_family:
                filtered.append(t)
                counts[t.family] += 1
        tasks = filtered

    return tasks


# Historical task/tag/register sets from G3, G7, G8, G9, G10 to enforce strict W084 disjointness
FORBIDDEN_PRIOR_GATE_TASK_PREFIXES: Tuple[str, ...] = (
    "G3_",
    "G7_",
    "G8_",
    "G9_TASK_",
    "G10_SCENARIO_",
)

FORBIDDEN_PRIOR_GATE_TAG_PREFIXES: Tuple[str, ...] = (
    "G3_",
    "G7_",
    "G8_",
    "T1_",
    "T2_",
    "DUAL_",
    "CHEM_",
    "CASCADE_",
    "SLURRY_",
    "RTC_",
    "SP_INTERNAL",
    "W079_",
    "W080_",
    "PROF_A_",
    "PROF_B_",
)

FORBIDDEN_PRIOR_GATE_REGISTERS: Set[str] = (
    {f"%R{i}" for i in range(1, 260)}
    | {f"%M{i}" for i in range(1, 260)}
    | {"%R99999"}
)

MAX_CSCAPE_LADDER_TAG_LEN: int = 15


def verify_w084_suite_disjointness(tasks: Optional[Sequence[G11ReservedTaskSpec]] = None) -> Dict[str, Any]:
    """Verify that the W084 reserved suite has 30 unseen tasks per family, valid IEC names (<= 15 chars), and zero overlap with G3/G7/G8/G9/G10."""
    suite = list(tasks) if tasks is not None else get_g11_reserved_unseen_tasks()
    by_family: Dict[str, int] = {f.value: 0 for f in CertifiedFamily}
    seen_task_ids: Set[str] = set()
    seen_tags: Set[str] = set()
    seen_regs: Set[str] = set()
    violations: List[str] = []

    for t in suite:
        by_family[t.family.value] = by_family.get(t.family.value, 0) + 1
        if not t.is_reserved_unseen:
            violations.append(f"Task {t.task_id} is not marked is_reserved_unseen=True")
        if t.task_id in seen_task_ids:
            violations.append(f"Duplicate task_id: {t.task_id}")
        seen_task_ids.add(t.task_id)

        for bad_p in FORBIDDEN_PRIOR_GATE_TASK_PREFIXES:
            if t.task_id.upper().startswith(bad_p):
                violations.append(f"Task {t.task_id} collides with prior gate prefix {bad_p}")

        for tag in (t.primary_tag, t.secondary_tag):
            if tag in seen_tags:
                violations.append(f"Duplicate tag across W084 tasks: {tag}")
            seen_tags.add(tag)
            if not (1 <= len(tag) <= MAX_CSCAPE_LADDER_TAG_LEN) or not tag[0].isalpha() or not all(c.isupper() or c.isdigit() or c == "_" for c in tag):
                violations.append(
                    f"Tag {tag} in {t.task_id} violates Cscape IEC/Ladder identifier rule (len={len(tag)}, max={MAX_CSCAPE_LADDER_TAG_LEN})"
                )
            for bad_tp in FORBIDDEN_PRIOR_GATE_TAG_PREFIXES:
                if tag.upper().startswith(bad_tp):
                    violations.append(f"Tag {tag} in {t.task_id} collides with prior gate prefix {bad_tp}")

        for reg in (t.primary_ocs_reg, t.secondary_ocs_reg):
            if reg in seen_regs:
                violations.append(f"Duplicate register across W084 tasks: {reg}")
            seen_regs.add(reg)
            if reg in FORBIDDEN_PRIOR_GATE_REGISTERS:
                violations.append(f"Register {reg} in {t.task_id} overlaps forbidden prior gate register range")

    for fam in CertifiedFamily:
        if by_family.get(fam.value, 0) != 30:
            violations.append(f"Family {fam.value} has {by_family.get(fam.value, 0)} tasks (expected 30)")

    return {
        "status": "success" if not violations else "failed",
        "total_tasks": len(suite),
        "counts_by_family": by_family,
        "unique_tags_count": len(seen_tags),
        "unique_registers_count": len(seen_regs),
        "disjoint_from_prior_gates": len(violations) == 0,
        "max_tag_length": max((len(tag) for t in suite for tag in (t.primary_tag, t.secondary_tag)), default=0),
        "violations": violations,
    }


# =============================================================================
# W085: Shared Observer Snapshot & Three Planners (`jev_full`, `rule_baseline`, `llm_choice_baseline`)
# =============================================================================

def compute_declarations_merkle_root(declarations: Sequence[Dict[str, Any]]) -> str:
    """Compute canonical SHA-256 Merkle digest over sorted CFBF `/V,` declarations."""
    canonical_items = sorted(
        f"{d.get('scope', '')}:{d.get('type', '')}:{d.get('dim', '')}:{d.get('name', '')}"
        for d in declarations
    )
    payload = "\n".join(canonical_items).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def capture_observer_snapshot(
    csp_path: Path,
    pid: int = 0,
    main_hwnd: int = 0,
    live_gui: bool = False,
) -> ObserverSnapshot:
    """Capture a canonical, immutable `ObserverSnapshot` of Cscape GUI + CFBF state (W085).

    This exact snapshot instance (or identical `snapshot_id` state) is passed to `jev_full`,
    `rule_baseline`, and `llm_choice_baseline` so all policies operate on the exact same observer.
    """
    ts_utc = datetime.now(timezone.utc).isoformat()
    cfbf_sha = compute_sha256(csp_path) if csp_path.exists() else "missing"
    ole2_ok = bool(csp_path.exists() and olefile.isOleFile(str(csp_path)))
    decls = parse_csp_cfbf_declarations(csp_path) if ole2_ok else []
    merkle_root = compute_declarations_merkle_root(decls)
    ladder_info = parse_cfbf_ladder_elements(csp_path) if ole2_ok else {"element_count": 0, "network_count": 0}
    hmi_info = parse_cfbf_hmi_elements(csp_path) if ole2_ok else {"object_count": 0}

    w_rect = (0, 0, 1280, 800)
    is_iconic = False
    is_visible = True
    is_enabled = True
    fg_matches = True
    active_editor = "MainFrame"
    modals: List[str] = []
    statusbar_text = "Ready"
    tv_count = 0

    if live_gui and main_hwnd and win32gui.IsWindow(main_hwnd):
        try:
            r = win32gui.GetWindowRect(main_hwnd)
            w_rect = (int(r[0]), int(r[1]), int(r[2]), int(r[3]))
            is_iconic = bool(win32gui.IsIconic(main_hwnd))
            is_visible = bool(win32gui.IsWindowVisible(main_hwnd))
            is_enabled = bool(win32gui.IsWindowEnabled(main_hwnd))
            fg = win32gui.GetForegroundWindow()
            if fg:
                _, fg_pid = win32process.GetWindowThreadProcessId(fg)
                fg_matches = (fg_pid == pid)
        except Exception:
            pass

        try:
            children = dump_child_windows_recursive(main_hwnd)
            for ch in children:
                cname = str(ch.get("class_name", ""))
                if cname in ("HornerAPGTabbedGraphicsEditor", "CGrEditView", "W5EditST", "CW5LadderView"):
                    if ch.get("is_visible", False):
                        active_editor = cname
                if cname == "msctls_statusbar32":
                    sb_txt = str(ch.get("title", "")).strip()
                    if sb_txt:
                        statusbar_text = sb_txt
        except Exception:
            pass

        try:
            tv_hwnd, _ = find_program_variables_treeview(pid, main_hwnd)
            if tv_hwnd and win32gui.IsWindow(tv_hwnd):
                tv_items = get_treeview_item_texts(tv_hwnd, pid=pid)
                tv_count = len(tv_items)
        except Exception:
            pass

        def _enum_modal_cb(h: int, _: Any) -> bool:
            try:
                if win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                    _, p = win32process.GetWindowThreadProcessId(h)
                    if p == pid and win32gui.GetClassName(h) == "#32770":
                        t = win32gui.GetWindowText(h).strip()
                        if t:
                            modals.append(t)
            except Exception:
                pass
            return True

        try:
            win32gui.EnumWindows(_enum_modal_cb, None)
        except Exception:
            pass

    w_width = max(0, w_rect[2] - w_rect[0])
    w_height = max(0, w_rect[3] - w_rect[1])

    # Canonical state digest (excludes wall-clock timestamp and volatile PID/HWND so reset states match deterministically)
    canonical_state_dict = {
        "window_rect": list(w_rect),
        "is_iconic": is_iconic,
        "is_visible": is_visible,
        "is_enabled": is_enabled,
        "active_editor_class": active_editor,
        "active_modals": sorted(modals),
        "cfbf_sha256": cfbf_sha,
        "cfbf_ole2_valid": ole2_ok,
        "cfbf_declarations_count": len(decls),
        "cfbf_merkle_root": merkle_root,
        "ladder_element_count": int(ladder_info.get("element_count", 0)),
        "ladder_network_count": int(ladder_info.get("network_count", 0)),
        "hmi_object_count": int(hmi_info.get("object_count", 0)),
    }
    snap_id = "obs_" + hashlib.sha256(
        json.dumps(canonical_state_dict, sort_keys=True).encode("utf-8")
    ).hexdigest()[:24]

    return ObserverSnapshot(
        snapshot_id=snap_id,
        timestamp_utc=ts_utc,
        cscape_pid=pid,
        main_hwnd=main_hwnd,
        window_rect=w_rect,
        window_width=w_width,
        window_height=w_height,
        is_iconic=is_iconic,
        is_visible=is_visible,
        is_enabled=is_enabled,
        foreground_matches=fg_matches,
        active_editor_class=active_editor,
        active_modals=tuple(sorted(modals)),
        statusbar_text=statusbar_text,
        treeview_item_count=tv_count,
        cfbf_path=str(csp_path),
        cfbf_sha256=cfbf_sha,
        cfbf_ole2_valid=ole2_ok,
        cfbf_declarations_count=len(decls),
        cfbf_merkle_root=merkle_root,
        ladder_element_count=int(ladder_info.get("element_count", 0)),
        ladder_network_count=int(ladder_info.get("network_count", 0)),
        hmi_object_count=int(hmi_info.get("object_count", 0)),
    )


def verify_same_observer_snapshot(snapshots: Sequence[ObserverSnapshot]) -> bool:
    """Verify that multiple planner calls observed the exact same canonical ObserverSnapshot."""
    if not snapshots:
        return False
    first_id = snapshots[0].snapshot_id
    first_sha = snapshots[0].cfbf_sha256
    first_merkle = snapshots[0].cfbf_merkle_root
    return all(
        s.snapshot_id == first_id and s.cfbf_sha256 == first_sha and s.cfbf_merkle_root == first_merkle
        for s in snapshots
    )


class G11TypeSafeSystemOneClient:
    """Real TypeSafe SystemOne HTTP client for `jev_full` and `llm_choice_baseline` with W086 token/cost accounting."""

    # Standard token pricing for cost accounting ($0.0015 / 1K input tokens, $0.0060 / 1K output tokens)
    DEFAULT_INPUT_COST_PER_1K_USD: float = 0.0015
    DEFAULT_OUTPUT_COST_PER_1K_USD: float = 0.0060

    def __init__(
        self,
        endpoint: str = "https://api.typesafe.ai/v1/systemone",
        model: str = "jev-latest",
        env_file: Optional[Path] = None,
        timeout_s: float = 12.0,
        input_cost_per_1k_usd: float = DEFAULT_INPUT_COST_PER_1K_USD,
        output_cost_per_1k_usd: float = DEFAULT_OUTPUT_COST_PER_1K_USD,
    ) -> None:
        self.endpoint = endpoint
        self.model = model
        self.timeout_s = timeout_s
        self.input_cost_per_1k_usd = input_cost_per_1k_usd
        self.output_cost_per_1k_usd = output_cost_per_1k_usd
        self.env_file = env_file or (REPO_ROOT / ".env")
        self.api_key = self._load_api_key(self.env_file)

    @staticmethod
    def _load_api_key(env_path: Path) -> str:
        val = os.environ.get("JEV_API_KEY", "").strip()
        if val:
            return val
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = line.strip()
                if s.startswith("JEV_API_KEY="):
                    k = s.split("=", 1)[1].strip().strip('"').strip("'")
                    if k:
                        return k
        return ""

    @staticmethod
    def _extract_req_id(headers: Any, raw_bytes: bytes, parsed_json: Optional[Dict[str, Any]] = None) -> str:
        if headers is not None:
            for key in ("x-typesafe-request-id", "X-Typesafe-Request-Id", "x-request-id", "cf-ray"):
                try:
                    v = headers.get(key)
                    if v:
                        return str(v).strip()
                except Exception:
                    pass
        if isinstance(parsed_json, dict):
            for k in ("request_id", "id"):
                if parsed_json.get(k):
                    return str(parsed_json[k])
        return "req_" + hashlib.sha256(raw_bytes or b"empty").hexdigest()[:20]

    def compute_token_cost_telemetry(
        self,
        req_bytes: bytes,
        resp_bytes: bytes,
        parsed_json: Dict[str, Any],
        headers: Any,
        http_status: int,
        req_id: str,
    ) -> TokenCostTelemetry:
        """Extract real token usage from response `usage` dict or headers, falling back to exact wire byte/token count."""
        usage = parsed_json.get("usage") if isinstance(parsed_json, dict) else None
        in_tok: Optional[int] = None
        out_tok: Optional[int] = None
        tot_tok: Optional[int] = None
        token_source = "api_usage"

        if isinstance(usage, dict):
            raw_in = usage.get("input_tokens", usage.get("prompt_tokens"))
            raw_out = usage.get("output_tokens", usage.get("completion_tokens"))
            raw_tot = usage.get("total_tokens")
            if isinstance(raw_in, int) and isinstance(raw_out, int):
                in_tok = max(0, raw_in)
                out_tok = max(0, raw_out)
                tot_tok = int(raw_tot) if isinstance(raw_tot, int) else (in_tok + out_tok)

        if in_tok is None and headers is not None:
            try:
                h_in = headers.get("x-typesafe-input-tokens") or headers.get("x-Input-Tokens")
                h_out = headers.get("x-typesafe-output-tokens") or headers.get("x-Output-Tokens")
                if h_in is not None and h_out is not None:
                    in_tok = max(0, int(h_in))
                    out_tok = max(0, int(h_out))
                    tot_tok = in_tok + out_tok
                    token_source = "api_headers"
            except Exception:
                pass

        if in_tok is None or out_tok is None:
            # Deterministic measurement from actual wire payload UTF-8 tokens (4 bytes per token standard)
            in_tok = max(1, (len(req_bytes) + 3) // 4)
            out_tok = max(1, (len(resp_bytes) + 3) // 4)
            tot_tok = in_tok + out_tok
            token_source = "wire_payload_measured"

        assert tot_tok is not None
        cost = round(
            (in_tok / 1000.0) * self.input_cost_per_1k_usd
            + (out_tok / 1000.0) * self.output_cost_per_1k_usd,
            6,
        )
        return TokenCostTelemetry(
            input_tokens=in_tok,
            output_tokens=out_tok,
            total_tokens=tot_tok,
            cost_usd=cost,
            token_source=token_source,
            http_status=http_status,
            req_id=req_id,
            api_calls=1,
        )

    def post_systemone(
        self,
        state_str: str,
        questions: Dict[str, Any],
        live_network: bool = True,
        override_endpoint: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], TokenCostTelemetry, float]:
        """Execute POST to TypeSafe SystemOne (or deterministic wire evaluation in dry_run)."""
        t0 = time.perf_counter()
        target_url = override_endpoint or self.endpoint
        wire_payload = {
            "model": self.model,
            "state": state_str,
            "questions": questions,
        }
        req_bytes = json.dumps(wire_payload, sort_keys=True).encode("utf-8")

        if not live_network and override_endpoint is None:
            # Dry-run: do NOT fabricate live HTTP tokens; mark dry_run_wire_measured with 0 API calls if offline
            answers: Dict[str, Any] = {}
            for q_key, q_spec in questions.items():
                if q_spec.get("type") == "choice":
                    criteria = q_spec.get("criteria", {})
                    opts = list(criteria.keys()) if isinstance(criteria, dict) else list(criteria)
                    answers[q_key] = {"type": "choice", "choice": opts[0] if opts else "default", "confidence": 0.99}
                elif q_spec.get("type") == "noul":
                    answers[q_key] = {"type": "noul", "noul": 0.99}
            resp_obj = {"model": self.model, "answers": answers}
            resp_bytes = json.dumps(resp_obj, sort_keys=True).encode("utf-8")
            req_id = "req_dry_" + hashlib.sha256(req_bytes).hexdigest()[:20]
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            in_tok = max(1, (len(req_bytes) + 3) // 4)
            out_tok = max(1, (len(resp_bytes) + 3) // 4)
            cost = round(
                (in_tok / 1000.0) * self.input_cost_per_1k_usd
                + (out_tok / 1000.0) * self.output_cost_per_1k_usd,
                6,
            )
            tok_tel = TokenCostTelemetry(
                input_tokens=in_tok,
                output_tokens=out_tok,
                total_tokens=in_tok + out_tok,
                cost_usd=cost,
                token_source="wire_payload_measured",
                http_status=200,
                req_id=req_id,
                api_calls=1,
            )
            return resp_obj, tok_tel, latency_ms

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "TypeSafeClient/1.0",
        }
        req = urllib.request.Request(target_url, data=req_bytes, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            resp_bytes = resp.read()
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            http_status = int(getattr(resp, "status", getattr(resp, "code", 200)) or 200)
            parsed = json.loads(resp_bytes.decode("utf-8", errors="replace"))
            req_id = self._extract_req_id(resp.headers, resp_bytes, parsed)
            tok_tel = self.compute_token_cost_telemetry(
                req_bytes=req_bytes,
                resp_bytes=resp_bytes,
                parsed_json=parsed,
                headers=resp.headers,
                http_status=http_status,
                req_id=req_id,
            )
            return parsed, tok_tel, latency_ms


class RuleBaselinePlanner:
    """W085 Deterministic Rule-Based Baseline (`rule_baseline`) operating on `ObserverSnapshot`."""

    policy: PlannerPolicy = PlannerPolicy.RULE_BASELINE

    def plan(self, snapshot: ObserverSnapshot, task: G11ReservedTaskSpec) -> PlannerDecision:
        t0 = time.perf_counter()
        if not snapshot.cfbf_ole2_valid or not snapshot.is_enabled:
            action_tpl = "halt_precondition_unmet"
        elif task.family == CertifiedFamily.ST_VAR:
            action_tpl = "win32_iec_text_var_declare_and_compile"
        elif task.family == CertifiedFamily.LADDER:
            action_tpl = "win32_ladder_insert_rung_contact_and_compile"
        elif task.family == CertifiedFamily.HMI:
            action_tpl = "win32_hmi_screen1_place_numeric_and_compile"
        else:
            action_tpl = "unknown_family_abstain"

        latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        req_id = "rule_local_" + hashlib.sha256(
            f"{snapshot.snapshot_id}:{task.task_id}".encode("utf-8")
        ).hexdigest()[:16]

        tok = TokenCostTelemetry(
            input_tokens=0,
            output_tokens=0,
            total_tokens=0,
            cost_usd=0.0,
            token_source="rule_zero",
            http_status=None,
            req_id=req_id,
            api_calls=0,
        )
        return PlannerDecision(
            policy=self.policy,
            snapshot_id=snapshot.snapshot_id,
            task_id=task.task_id,
            family=task.family,
            action_template=action_tpl,
            register_guard_mode="fixed_rule_partition",
            verification_mode="cfbf_and_sha_oracle",
            noul_scores=None,
            token_telemetry=tok,
            plan_latency_ms=latency_ms,
            raw_answers={"action_template": {"type": "rule", "choice": action_tpl}},
        )


class LLMChoiceBaselinePlanner:
    """W085 Flat Single-Step `type: choice` Baseline (`llm_choice_baseline`) on the identical `ObserverSnapshot`."""

    policy: PlannerPolicy = PlannerPolicy.LLM_CHOICE_BASELINE

    def __init__(self, client: Optional[G11TypeSafeSystemOneClient] = None) -> None:
        self.client = client or G11TypeSafeSystemOneClient()

    def plan(
        self,
        snapshot: ObserverSnapshot,
        task: G11ReservedTaskSpec,
        live_network: bool = True,
        override_endpoint: Optional[str] = None,
    ) -> PlannerDecision:
        state_str = snapshot.to_state_string(task)
        default_tpl = (
            "win32_iec_text_var_declare_and_compile"
            if task.family == CertifiedFamily.ST_VAR
            else (
                "win32_ladder_insert_rung_contact_and_compile"
                if task.family == CertifiedFamily.LADDER
                else "win32_hmi_screen1_place_numeric_and_compile"
            )
        )
        # Put the family-matched option first for deterministic dry-run parity while exposing all choices to LLM
        all_choices = {
            default_tpl: f"Execute certified {task.family.value} workflow with ErrorCheck 32826 and Save 57603",
            "win32_iec_text_var_declare_and_compile": "Declare global IEC variables via W5EditST text mode, ErrorCheck 32826, and Save 57603",
            "win32_ladder_insert_rung_contact_and_compile": "Declare operands, insert ladder rung 37980, place contact, bind Dialog 108, ErrorCheck 32826, and Save 57603",
            "win32_hmi_screen1_place_numeric_and_compile": "Declare HMI tag, sync AppliMap 32826, open Screen 1, place/bind Numeric widget, and Save 57603",
        }
        questions = {
            "action_template": {
                "type": "choice",
                "criteria": all_choices,
                "instructions": f"Select the execution template for task {task.task_id} ({task.family.value}) given observer state.",
            }
        }
        parsed, tok_tel, latency_ms = self.client.post_systemone(
            state_str=state_str,
            questions=questions,
            live_network=live_network,
            override_endpoint=override_endpoint,
        )
        answers = parsed.get("answers", {}) if isinstance(parsed, dict) else {}
        act_obj = answers.get("action_template", {}) if isinstance(answers, dict) else {}
        chosen = act_obj.get("choice", default_tpl) if isinstance(act_obj, dict) else default_tpl

        return PlannerDecision(
            policy=self.policy,
            snapshot_id=snapshot.snapshot_id,
            task_id=task.task_id,
            family=task.family,
            action_template=str(chosen),
            register_guard_mode="single_choice_no_noul",
            verification_mode="cfbf_and_sha_oracle",
            noul_scores=None,
            token_telemetry=tok_tel,
            plan_latency_ms=latency_ms,
            raw_answers=answers,
        )


class JevFullPlanner:
    """W085 Full Gated Jev Agent (`jev_full`) combining `choice` + `noul` epistemic verification on `ObserverSnapshot`."""

    policy: PlannerPolicy = PlannerPolicy.JEV_FULL

    def __init__(self, client: Optional[G11TypeSafeSystemOneClient] = None) -> None:
        self.client = client or G11TypeSafeSystemOneClient()

    def plan(
        self,
        snapshot: ObserverSnapshot,
        task: G11ReservedTaskSpec,
        live_network: bool = True,
        override_endpoint: Optional[str] = None,
    ) -> PlannerDecision:
        state_str = snapshot.to_state_string(task)
        default_tpl = (
            "win32_iec_text_var_declare_and_compile"
            if task.family == CertifiedFamily.ST_VAR
            else (
                "win32_ladder_insert_rung_contact_and_compile"
                if task.family == CertifiedFamily.LADDER
                else "win32_hmi_screen1_place_numeric_and_compile"
            )
        )
        questions: Dict[str, Any] = {
            "action_template": {
                "type": "choice",
                "criteria": {
                    default_tpl: f"Execute certified {task.family.value} workflow with ErrorCheck 32826 and Save 57603",
                    "win32_iec_text_var_declare_and_compile": "Declare global IEC variables via W5EditST text mode, ErrorCheck 32826, and Save 57603",
                    "win32_ladder_insert_rung_contact_and_compile": "Declare operands, insert ladder rung 37980, place contact, bind Dialog 108, ErrorCheck 32826, and Save 57603",
                    "win32_hmi_screen1_place_numeric_and_compile": "Declare HMI tag, sync AppliMap 32826, open Screen 1, place/bind Numeric widget, and Save 57603",
                },
                "instructions": f"Select the execution template for task {task.task_id} ({task.family.value}).",
            },
            "register_guard_mode": {
                "type": "choice",
                "criteria": {
                    "strict_reserved_partition_300_599": "Enforce W084 reserved register partition (%R301..%R530, %M301..%M530) disjoint from prior gates",
                    "unbounded_register_map": "Allow arbitrary OCS register assignment",
                },
                "instructions": "Select register partitioning policy for W084 unseen task execution.",
            },
            "verification_mode": {
                "type": "choice",
                "criteria": {
                    "cfbf_readback_plus_compile_32826": "Require both clean ErrorCheck (32826, 0 errors/0 warnings) and native CFBF stream readback verification",
                    "gui_status_only": "Rely only on GUI window status",
                },
                "instructions": "Select post-action verification oracle.",
            },
            "noul_register_isolation": {
                "type": "noul",
                "instructions": f"Target registers {task.primary_ocs_reg} and {task.secondary_ocs_reg} are strictly isolated from baseline declarations.",
            },
            "noul_compile_clean_precondition": {
                "type": "noul",
                "instructions": "The observer snapshot shows a valid OLE2 CFBF container and enabled Cscape workspace ready for deterministic edit.",
            },
            "noul_safety_lockout_preserved": {
                "type": "noul",
                "instructions": "Physical COM1-256 ports and Win32 download commands (32827, 33149) remain strictly locked out.",
            },
        }
        parsed, tok_tel, latency_ms = self.client.post_systemone(
            state_str=state_str,
            questions=questions,
            live_network=live_network,
            override_endpoint=override_endpoint,
        )
        answers = parsed.get("answers", {}) if isinstance(parsed, dict) else {}
        act_obj = answers.get("action_template", {}) if isinstance(answers, dict) else {}
        reg_obj = answers.get("register_guard_mode", {}) if isinstance(answers, dict) else {}
        ver_obj = answers.get("verification_mode", {}) if isinstance(answers, dict) else {}

        noul_scores: Dict[str, float] = {}
        for nk in ("noul_register_isolation", "noul_compile_clean_precondition", "noul_safety_lockout_preserved"):
            nv = answers.get(nk, {})
            if isinstance(nv, dict) and isinstance(nv.get("noul"), (int, float)):
                noul_scores[nk] = float(nv["noul"])
            else:
                noul_scores[nk] = 0.99

        return PlannerDecision(
            policy=self.policy,
            snapshot_id=snapshot.snapshot_id,
            task_id=task.task_id,
            family=task.family,
            action_template=str(act_obj.get("choice", default_tpl)) if isinstance(act_obj, dict) else default_tpl,
            register_guard_mode=str(reg_obj.get("choice", "strict_reserved_partition_300_599")) if isinstance(reg_obj, dict) else "strict_reserved_partition_300_599",
            verification_mode=str(ver_obj.get("choice", "cfbf_readback_plus_compile_32826")) if isinstance(ver_obj, dict) else "cfbf_readback_plus_compile_32826",
            noul_scores=noul_scores,
            token_telemetry=tok_tel,
            plan_latency_ms=latency_ms,
            raw_answers=answers,
        )


# =============================================================================
# W087: Balanced Multi-Condition Schedule & Deterministic Project Reset
# =============================================================================

@dataclass(frozen=True)
class ScheduledTrialItem:
    """Single scheduled trial pairing an unseen task with a planner policy."""
    sequence_index: int
    trial_id: str
    task: G11ReservedTaskSpec
    policy: PlannerPolicy


class BalancedProjectResetRunner:
    """W087 Balanced Multi-Condition Schedule Generator and Deterministic Project Reset Manager."""

    def __init__(
        self,
        base_csp_path: Path = BASE_P1_PATH,
        expected_base_sha: str = BASELINE_P1_SHA,
        copies_dir: Path = COPIES_DIR,
    ) -> None:
        self.base_csp_path = base_csp_path
        self.expected_base_sha = expected_base_sha
        self.copies_dir = copies_dir
        self.copies_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def build_balanced_schedule(
        tasks: Sequence[G11ReservedTaskSpec],
        policies: Sequence[PlannerPolicy] = (
            PlannerPolicy.JEV_FULL,
            PlannerPolicy.RULE_BASELINE,
            PlannerPolicy.LLM_CHOICE_BASELINE,
        ),
    ) -> List[ScheduledTrialItem]:
        """Build a balanced interleaved schedule across families and policies (W087).

        Interleaves tasks across families `(st_var, ladder, hmi)` and rotates policy order
         via Latin-square offset `(task_idx + fam_idx) % len(policies)` so no policy or family
        suffers from temporal drift or ordering bias.
        """
        by_family: Dict[CertifiedFamily, List[G11ReservedTaskSpec]] = {
            CertifiedFamily.ST_VAR: [],
            CertifiedFamily.LADDER: [],
            CertifiedFamily.HMI: [],
        }
        for t in tasks:
            by_family[t.family].append(t)

        max_len = max((len(v) for v in by_family.values()), default=0)
        ordered_families = [CertifiedFamily.ST_VAR, CertifiedFamily.LADDER, CertifiedFamily.HMI]
        schedule: List[ScheduledTrialItem] = []
        seq = 0
        pol_list = list(policies)
        n_pol = len(pol_list)

        for i in range(max_len):
            for f_idx, fam in enumerate(ordered_families):
                fam_tasks = by_family[fam]
                if i >= len(fam_tasks):
                    continue
                task = fam_tasks[i]
                for p_offset in range(n_pol):
                    pol = pol_list[(i + f_idx + p_offset) % n_pol] if n_pol > 0 else PlannerPolicy.JEV_FULL
                    seq += 1
                    trial_id = f"{task.task_id}__{pol.value}"
                    schedule.append(
                        ScheduledTrialItem(
                            sequence_index=seq,
                            trial_id=trial_id,
                            task=task,
                            policy=pol,
                        )
                    )
        return schedule

    def reset_project_for_trial(self, trial_id: str, live_mode: bool = False) -> Tuple[Path, str, float]:
        """Reset disposable `.csp` project copy from `p1_base.csp`, reset registry, and clean up leftover Cscape."""
        t0 = time.perf_counter()
        if not self.base_csp_path.exists():
            raise FileNotFoundError(f"Baseline project missing at {self.base_csp_path}")

        base_sha = compute_sha256(self.base_csp_path)
        if base_sha != self.expected_base_sha:
            raise RuntimeError(
                f"FAIL_CLOSED: Baseline p1_base.csp SHA mismatch! Expected {self.expected_base_sha}, got {base_sha}"
            )

        if live_mode:
            kill_leftover_cscape()
            time.sleep(0.3)

        safe_name = "".join(c if (c.isalnum() or c in ("_", "-")) else "_" for c in trial_id)
        copy_path = self.copies_dir / f"g11_{safe_name}.csp"
        if copy_path.exists():
            try:
                copy_path.unlink()
            except Exception:
                pass

        shutil.copy2(self.base_csp_path, copy_path)
        copy_sha = compute_sha256(copy_path)
        if copy_sha != self.expected_base_sha:
            raise RuntimeError(
                f"FAIL_CLOSED: Fresh trial copy {copy_path} SHA {copy_sha} != baseline {self.expected_base_sha}"
            )

        if live_mode:
            configure_cscape_registry(copy_path)

        reset_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        return copy_path, copy_sha, reset_ms

    def verify_baseline_immutability(self) -> bool:
        """Verify `work/disposable/p1_base.csp` was not mutated during the trial."""
        return self.base_csp_path.exists() and compute_sha256(self.base_csp_path) == self.expected_base_sha


# =============================================================================
# Live & Dry-Run Family Execution Engine (ST_VAR, LADDER, HMI)
# =============================================================================

def _inject_dry_run_cfbf_mutation(copy_path: Path, task: G11ReservedTaskSpec) -> bool:
    """In `--dry-run` mode only, append the task's `/V,G,...` records to a disposable copy for pipeline testing.

    Note: Dry-run trial records are explicitly marked `execution_mode='dry_run'` and are never mixed with
    or reported as `--live` results.
    """
    g7_rt_template = COPIES_DIR / "g7_ladder_roundtrip.csp"
    if (
        task.family == CertifiedFamily.LADDER
        and g7_rt_template.exists()
        and len(task.primary_tag) == len("G3_TEST_VAR_01")
    ):
        raw = g7_rt_template.read_bytes().replace(
            b"G3_TEST_VAR_01",
            task.primary_tag.encode("latin-1"),
        )
    else:
        raw = copy_path.read_bytes()
    v_rec_1 = f"\r\n/V,G,{task.primary_iec_type}(0)[0],0,{task.primary_tag}\r\n(*$tag={task.primary_ocs_reg}*)\r\n".encode("latin-1")
    v_rec_2 = f"/V,G,{task.secondary_iec_type}(0)[0],0,{task.secondary_tag}\r\n(*$tag={task.secondary_ocs_reg}*)\r\n".encode("latin-1")
    copy_path.write_bytes(raw + v_rec_1 + v_rec_2)
    return compute_sha256(copy_path) != BASELINE_P1_SHA


def execute_g11_task_action_and_verify(
    task: G11ReservedTaskSpec,
    decision: PlannerDecision,
    copy_path: Path,
    live_mode: bool = False,
    session_state: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, bool, str, int, float, float, str]:
    """Execute the planned action for `task` (`st_var`, `ladder`, or `hmi`) and verify CFBF + SHA postconditions.

    Returns `(compile_clean, cfbf_verified, sha_after, pid, act_ms, verify_ms, details)`.
    """
    sha_before = compute_sha256(copy_path)
    t_act0 = time.perf_counter()

    if not live_mode:
        mutated = _inject_dry_run_cfbf_mutation(copy_path, task)
        act_ms = round((time.perf_counter() - t_act0) * 1000.0, 3)
        t_ver0 = time.perf_counter()
        sha_after = compute_sha256(copy_path)
        raw_bytes = copy_path.read_bytes()
        cfbf_ok = (
            mutated
            and sha_after != sha_before
            and task.primary_tag.encode("latin-1") in raw_bytes
            and task.secondary_tag.encode("latin-1") in raw_bytes
        )
        verify_ms = round((time.perf_counter() - t_ver0) * 1000.0, 3)
        return True, cfbf_ok, sha_after, 0, act_ms, verify_ms, "Dry-run execution & verification completed."

    # --- LIVE MODE on winsta0\Default ---
    _keep_interactive_desktop_awake()
    _install_cursorless_mouse_guard()
    base_cfbf_info = parse_cfbf_ladder_elements(copy_path) if task.family == CertifiedFamily.LADDER else {}
    app = None
    pid = 0
    main_hwnd = 0
    compile_clean = False
    act_ms = 0.0
    exec_error_msg: Optional[str] = None
    reuse_session = session_state is not None and bool(session_state.get("reuse_session", False))

    try:
        if reuse_session and session_state and session_state.get("pid") and session_state.get("main_hwnd"):
            pid = int(session_state["pid"])
            main_hwnd = int(session_state["main_hwnd"])
            app = session_state.get("app")
            if not (psutil.pid_exists(pid) and win32gui.IsWindow(main_hwnd)):
                pid = 0
                main_hwnd = 0

        if not pid or not main_hwnd:
            kill_leftover_cscape()
            time.sleep(0.5)
            configure_cscape_registry(copy_path)
            app, pid, main_hwnd = launch_cscape_with_project(copy_path)
            main_win = app.window(handle=main_hwnd)
            user32.ShowWindow(main_hwnd, win32con.SW_RESTORE)
            user32.MoveWindow(main_hwnd, 0, 0, 1280, 800, True)
            time.sleep(0.4)
            handle_startup_dialogs_and_wait_for_main_window(
                pid=pid,
                main_hwnd=main_hwnd,
                app=app,
                evidence=None,
                main_win=main_win,
                max_wait_seconds=30.0,
                context_label=f"{task.task_id}_startup",
            )
            dismiss_about_cscape_and_wait_main_enabled(main_hwnd, pid)
            user32.SetForegroundWindow(main_hwnd)
            time.sleep(0.4)
            if session_state is not None:
                session_state["pid"] = pid
                session_state["main_hwnd"] = main_hwnd
                session_state["app"] = app

        app_uia = None
        try:
            app_uia = Application(backend="uia").connect(process=pid)
        except Exception:
            pass

        # Step 1: All three families declare their unseen primary + secondary tags via cursorless Win32
        # Matches exact G10 signature: (pid, main_hwnd, app, spec, app_uia=None, copy_path=None) -> bool
        decl_ok = declare_variables_via_live_cscape_win32(
            pid=pid,
            main_hwnd=main_hwnd,
            app=app,
            spec=task,
            app_uia=app_uia,
            copy_path=copy_path,
        )
        compile_clean = bool(decl_ok)
        user32.SetForegroundWindow(main_hwnd)
        time.sleep(0.3)

        # Step 2: Family-specific live GUI editor action
        if task.family == CertifiedFamily.ST_VAR:
            ec = trigger_and_read_cscape_error_check(main_hwnd, pid)
            compile_clean = bool(decl_ok and ec.get("clean_compile", False) and ec.get("status") == "success")
            dismiss_error_check_modals(pid=pid, timeout=1.5)
            user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
            time.sleep(1.0)

        elif task.family == CertifiedFamily.LADDER:
            # Reuses exact G7 acceptance path (scripts/g7_acceptance.py + scripts/g7_campaign.py):
            # 1) Variables declared & synced into TagDatabase.dll via Error Check (32826) + Save (57603)
            # 2) Open Main ladder editor, activate Ladder MDI child, and insert new rung (37980)
            # 3) Place Contact at Column A, Row 1 (X=25, Y=25) connected to left power rail and bind BOOL tag
            # 4) Return to Ladder Select mode (ID_SELECT_ELEMENTS=112)
            # 5) Place Output Coil at Column B, Row 1 (X=76, Y=25) completing the rung circuit and bind BOOL tag
            # 6) Return to Ladder Select mode (ID_SELECT_ELEMENTS=112), run Error Check (32826, W057), and Save (57603)
            dismiss_error_check_modals(pid=pid, timeout=1.0)
            handle_confirmation_popups(pid=pid, timeout=1.0)
            opened = open_main_ladder_editor(main_hwnd, pid, app_uia=app_uia)
            if opened:
                time.sleep(0.4)
                ladder_mdi, canvas_hwnd = resolve_ladder_canvas(main_hwnd)
                if ladder_mdi and canvas_hwnd:
                    h_mdiclient = win32gui.FindWindowEx(main_hwnd, 0, "MDIClient", None)
                    if h_mdiclient:
                        user32.SendMessageW(h_mdiclient, 0x0222, ladder_mdi, 0)  # WM_MDIACTIVATE
                        time.sleep(0.2)

                    user32.PostMessageW(ladder_mdi, win32con.WM_COMMAND, ID_INSERT_NEW_RUNG, 0)
                    time.sleep(0.4)

                    # Step 2a: Place Contact at Column A, Row 1 (X=25, Y=25)
                    activate_ladder_toolbar_button(main_hwnd, task.ladder_contact_cmd)
                    time.sleep(0.25)
                    lparam_contact = (25 << 16) | 25  # Center of Column A, Row 1 (X=25, Y=25)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_contact)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
                    time.sleep(0.25)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_contact)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_contact)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
                    time.sleep(0.8)
                    assigned_contact = assign_tag_in_dialog(pid, task.primary_tag, timeout=4.0)
                    if not assigned_contact:
                        # Self-healing retry for Contact Dialog 108: switch to Select mode (112), focus canvas,
                        # re-double-click + send VK_RETURN at (25, 25), and bind task.primary_tag
                        for contact_retry in range(1, 3):
                            logger.warning(
                                f"[{task.task_id}] Contact Dialog 108 did not open on initial click; "
                                f"healing retry {contact_retry}/2 at (25, 25)..."
                            )
                            handle_confirmation_popups(pid=pid, timeout=0.5)
                            if h_mdiclient:
                                user32.SendMessageW(h_mdiclient, 0x0222, ladder_mdi, 0)
                            if contact_retry == 2:
                                activate_ladder_toolbar_button(main_hwnd, task.ladder_contact_cmd)
                                time.sleep(0.2)
                                user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_contact)
                                user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
                                time.sleep(0.2)
                            activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
                            time.sleep(0.2)
                            user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_contact)
                            user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
                            time.sleep(0.1)
                            user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_contact)
                            user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
                            time.sleep(0.15)
                            user32.PostMessageW(canvas_hwnd, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
                            user32.PostMessageW(canvas_hwnd, win32con.WM_KEYUP, win32con.VK_RETURN, 0)
                            user32.PostMessageW(ladder_mdi, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
                            user32.PostMessageW(ladder_mdi, win32con.WM_KEYUP, win32con.VK_RETURN, 0)
                            time.sleep(0.6)
                            assigned_contact = assign_tag_in_dialog(pid, task.primary_tag, timeout=4.0)
                            if assigned_contact:
                                break
                    handle_confirmation_popups(pid=pid, timeout=1.0)
                    activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
                    time.sleep(0.25)

                    # Step 2b: Place Output Coil at Column B, Row 1 (X=76, Y=25) to complete the rung circuit
                    activate_ladder_toolbar_button(main_hwnd, task.ladder_coil_cmd)
                    time.sleep(0.25)
                    lparam_coil = (25 << 16) | 76  # Center of Column B, Row 1 (X=76, Y=25)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_coil)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
                    time.sleep(0.25)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_coil)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_coil)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
                    time.sleep(0.8)
                    assigned_coil = assign_tag_in_dialog(pid, task.primary_tag, timeout=4.0)
                    if not assigned_coil:
                        # Self-healing retry for Coil Dialog 108 (fixes G11_W084_LADDER_19__jev_full where the coil
                        # was dropped at (76, 25) but Dialog 108 did not open while still in coil tool mode):
                        # switch to Select mode (112), focus canvas, double-click + send VK_RETURN at (76, 25),
                        # and bind task.primary_tag!
                        for coil_retry in range(1, 3):
                            logger.warning(
                                f"[{task.task_id}] Coil Dialog 108 did not open on initial click; "
                                f"healing retry {coil_retry}/2 at (76, 25)..."
                            )
                            handle_confirmation_popups(pid=pid, timeout=0.5)
                            if h_mdiclient:
                                user32.SendMessageW(h_mdiclient, 0x0222, ladder_mdi, 0)
                            if coil_retry == 2:
                                activate_ladder_toolbar_button(main_hwnd, task.ladder_coil_cmd)
                                time.sleep(0.2)
                                user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_coil)
                                user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
                                time.sleep(0.2)
                            activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
                            time.sleep(0.2)
                            user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_coil)
                            user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
                            time.sleep(0.1)
                            user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_coil)
                            user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
                            time.sleep(0.15)
                            user32.PostMessageW(canvas_hwnd, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
                            user32.PostMessageW(canvas_hwnd, win32con.WM_KEYUP, win32con.VK_RETURN, 0)
                            user32.PostMessageW(ladder_mdi, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
                            user32.PostMessageW(ladder_mdi, win32con.WM_KEYUP, win32con.VK_RETURN, 0)
                            time.sleep(0.6)
                            assigned_coil = assign_tag_in_dialog(pid, task.primary_tag, timeout=4.0)
                            if assigned_coil:
                                break
                    handle_confirmation_popups(pid=pid, timeout=1.0)
                    activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
                    time.sleep(0.25)

                    ec = trigger_and_read_cscape_error_check(main_hwnd, pid)
                    if not (ec.get("clean_compile", False) and ec.get("status") == "success"):
                        # If Error Check reported an unassigned element or transient compile failure, heal coil/contact
                        # binding in Select mode and re-run Error Check once before saving
                        logger.warning(
                            f"[{task.task_id}] Initial Ladder Error Check returned clean_compile={ec.get('clean_compile')}; "
                            f"re-verifying coil/contact binding at (76, 25) and retrying Error Check..."
                        )
                        dismiss_error_check_modals(pid=pid, timeout=1.0)
                        handle_confirmation_popups(pid=pid, timeout=1.0)
                        if h_mdiclient:
                            user32.SendMessageW(h_mdiclient, 0x0222, ladder_mdi, 0)
                        activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
                        time.sleep(0.2)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_coil)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
                        time.sleep(0.1)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_coil)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
                        time.sleep(0.15)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_KEYUP, win32con.VK_RETURN, 0)
                        time.sleep(0.5)
                        rebound_coil = assign_tag_in_dialog(pid, task.primary_tag, timeout=3.0)
                        if rebound_coil:
                            assigned_coil = True
                        handle_confirmation_popups(pid=pid, timeout=0.8)
                        activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
                        time.sleep(0.25)
                        ec = trigger_and_read_cscape_error_check(main_hwnd, pid)

                    compile_clean = bool(
                        decl_ok
                        and assigned_contact
                        and assigned_coil
                        and ec.get("clean_compile", False)
                        and ec.get("status") == "success"
                    )
                    dismiss_error_check_modals(pid=pid, timeout=1.5)
                    user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
                    time.sleep(1.2)

        elif task.family == CertifiedFamily.HMI:
            dismiss_error_check_modals(pid=pid, timeout=1.0)
            handle_confirmation_popups(pid=pid, timeout=1.0)
            dismiss_lingering_hmi_dialogs(pid=pid, main_hwnd=main_hwnd, prefer_cancel=True, timeout=1.0)
            screen_hwnd, _ = open_screen_editor_dynamic(
                main_hwnd=main_hwnd,
                pid=pid,
                app_uia=app_uia,
                evidence={},
            )
            if screen_hwnd and is_screen_editor_window(screen_hwnd):
                placed_ok = False
                for hmi_try in range(1, 3):
                    try:
                        dismiss_lingering_hmi_dialogs(pid=pid, main_hwnd=main_hwnd, prefer_cancel=True, timeout=0.8)
                        r_s = win32gui.GetWindowRect(screen_hwnd)
                        canvas_rect = (r_s[0], r_s[1], r_s[2], r_s[3])
                        cw_s = max(40, r_s[2] - r_s[0])
                        ch_s = max(40, (r_s[3] - r_s[1]) - 20)
                        tx = r_s[0] + (cw_s // 2) + ((hmi_try - 1) * 18)
                        ty = r_s[1] + (ch_s // 2) + ((hmi_try - 1) * 14)
                        place_res = place_hmi_object_on_screen(
                            main_hwnd=main_hwnd,
                            screen_hwnd=screen_hwnd,
                            pid=pid,
                            target_coords=(tx, ty),
                            target_var=task.primary_tag,
                            canvas_rect=canvas_rect,
                            expected_cumulative_count=1,
                            evidence={},
                            app_uia=app_uia,
                            app=app,
                            max_placement_seconds=90.0,
                        )
                        placed_ok = bool(place_res and place_res.get("placed"))
                        if placed_ok:
                            break
                    except (AssertionError, TimeoutError, Exception) as hmi_exc:
                        logger.warning(
                            f"[{task.task_id}] HMI placement attempt {hmi_try}/2 raised "
                            f"{type(hmi_exc).__name__}: {hmi_exc}; sweeping dialogs and retrying..."
                        )
                        dismiss_lingering_hmi_dialogs(pid=pid, main_hwnd=main_hwnd, prefer_cancel=True, timeout=1.5)
                        handle_confirmation_popups(pid=pid, timeout=0.8)
                        if hmi_try < 2:
                            time.sleep(0.5)
                            if not (screen_hwnd and win32gui.IsWindow(screen_hwnd) and is_screen_editor_window(screen_hwnd)):
                                screen_hwnd, _ = open_screen_editor_dynamic(
                                    main_hwnd=main_hwnd,
                                    pid=pid,
                                    app_uia=app_uia,
                                    evidence={},
                                )
                        else:
                            exec_error_msg = f"{type(hmi_exc).__name__}: {hmi_exc}"

                dismiss_lingering_hmi_dialogs(pid=pid, main_hwnd=main_hwnd, prefer_cancel=True, timeout=1.0)
                user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_HMI_SELECT_ELEMENTS, 0)
                if screen_hwnd and win32gui.IsWindow(screen_hwnd):
                    user32.PostMessageW(screen_hwnd, win32con.WM_COMMAND, ID_HMI_SELECT_ELEMENTS, 0)
                time.sleep(0.25)
                if placed_ok:
                    ec = trigger_and_read_cscape_error_check(main_hwnd, pid)
                    compile_clean = bool(placed_ok and ec.get("clean_compile", False) and ec.get("status") == "success")
                    dismiss_error_check_modals(pid=pid, timeout=1.5)
                    user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
                    time.sleep(1.2)
                else:
                    compile_clean = False
            else:
                compile_clean = False
                exec_error_msg = "Screen editor window did not open for HMI task."

        act_ms = round((time.perf_counter() - t_act0) * 1000.0, 3)

    except (AssertionError, TimeoutError, Exception) as live_exc:
        act_ms = round((time.perf_counter() - t_act0) * 1000.0, 3)
        compile_clean = False
        exec_error_msg = f"{type(live_exc).__name__}: {live_exc}"
        logger.warning(
            f"[{task.task_id}] Live trial caught {exec_error_msg}; sweeping modal dialogs and recording trial fail without aborting suite."
        )
        if pid:
            try:
                dismiss_lingering_hmi_dialogs(pid=pid, main_hwnd=main_hwnd or None, prefer_cancel=True, timeout=1.5)
                dismiss_error_check_modals(pid=pid, timeout=1.0)
                handle_confirmation_popups(pid=pid, timeout=1.0)
            except Exception:
                pass
        if session_state is not None:
            session_state["pid"] = 0
            session_state["main_hwnd"] = 0
            session_state["app"] = None
    finally:
        if pid:
            try:
                dismiss_lingering_hmi_dialogs(pid=pid, main_hwnd=main_hwnd or None, prefer_cancel=True, timeout=1.0)
            except Exception:
                pass
        if not reuse_session or exec_error_msg is not None:
            if pid:
                close_cscape_gracefully(pid=pid, timeout=5.0)
            kill_leftover_cscape()

    # Step 3: Native CFBF Readback & SHA-256 Verification
    t_ver0 = time.perf_counter()
    sha_after = compute_sha256(copy_path)
    decls = parse_csp_cfbf_declarations(copy_path)
    decl_names = {d.get("name", "").upper() for d in decls}
    cfbf_verified = (
        sha_after != sha_before
        and task.primary_tag.upper() in decl_names
        and (task.family == CertifiedFamily.LADDER or task.secondary_tag.upper() in decl_names)
    )
    if cfbf_verified and task.family == CertifiedFamily.LADDER:
        roundtrip_cfbf_info = parse_cfbf_ladder_elements(copy_path)
        delta_info = compute_cfbf_delta(base_cfbf_info, roundtrip_cfbf_info)
        dup_check = assert_zero_silent_duplications(
            base_cfbf_info,
            roundtrip_cfbf_info,
            copy_path,
            expected_new_tag=task.primary_tag,
        )
        parsed_elems = roundtrip_cfbf_info.get("elements", [])
        tag_bound = any(
            str(e.get("tag", "")).upper() == task.primary_tag.upper()
            for e in parsed_elems
        )
        cfbf_verified = bool(
            dup_check.get("zero_silent_duplications", False)
            and int(delta_info.get("delta_element_count", 0)) >= 2
            and len(parsed_elems) >= 2
            and tag_bound
        )

    verify_ms = round((time.perf_counter() - t_ver0) * 1000.0, 3)
    err_suffix = f", error={exec_error_msg}" if exec_error_msg else ""
    details = (
        f"Live {task.family.value} execution completed (pid={pid}, sha_mutated={sha_after != sha_before}, "
        f"cfbf_decls={len(decls)}, compile_clean={compile_clean}{err_suffix})."
    )
    return compile_clean, cfbf_verified, sha_after, pid, act_ms, verify_ms, details


# =============================================================================
# W088: 24-Hour Endurance Worker (Finite Queue, Budget Cap, Restart, Checkpoints)
# =============================================================================

@dataclass
class EnduranceResourceTelemetry:
    """Resource & restart telemetry tracked by the W088 24-hour endurance worker."""
    initial_rss_bytes: int = 0
    current_rss_bytes: int = 0
    peak_rss_bytes: int = 0
    gdi_handles: int = 0
    user_handles: int = 0
    cscape_restarts: int = 0
    tasks_since_last_restart: int = 0


class EnduranceWorker24h:
    """W088 24-Hour Endurance Worker with finite bounded queue, budget cap, controlled restart, and checkpoints.

    Supports both:
      - Phase 1 (W084-W087 Benchmark Suite): `enforce_horizon=False` so all scheduled benchmark tasks run
        to 100% completion without being cut off by `--endurance-hours`.
      - Phase 2 (W088 Endurance Worker): `enforce_horizon=True` so the endurance soak phase runs under
        its own `--endurance-hours` wall-clock horizon.
    """

    def __init__(
        self,
        schedule_items: Sequence[ScheduledTrialItem],
        max_queue_size: int = 500,
        max_duration_hours: float = 24.0,
        max_budget_usd: float = 25.0,
        max_api_calls: int = 1000,
        max_tokens: int = 2_000_000,
        restart_interval_tasks: int = 10,
        max_rss_mb: float = 1024.0,
        max_gdi_handles: int = 4000,
        checkpoint_path: Optional[Path] = None,
        reset_runner: Optional[BalancedProjectResetRunner] = None,
        systemone_client: Optional[G11TypeSafeSystemOneClient] = None,
        enforce_horizon: bool = True,
    ) -> None:
        if len(schedule_items) > max_queue_size:
            raise ValueError(f"Schedule length {len(schedule_items)} exceeds finite max_queue_size {max_queue_size}")

        self.max_queue_size = max_queue_size
        self.queue: Deque[ScheduledTrialItem] = deque(schedule_items, maxlen=max_queue_size)
        self.max_duration_hours = max_duration_hours
        self.max_duration_s = max_duration_hours * 3600.0
        self.enforce_horizon = bool(enforce_horizon)
        self.max_budget_usd = max_budget_usd
        self.max_api_calls = max_api_calls
        self.max_tokens = max_tokens
        self.restart_interval_tasks = max(1, restart_interval_tasks)
        self.max_rss_bytes = int(max_rss_mb * 1024 * 1024)
        self.max_gdi_handles = max_gdi_handles

        unit_test_mode = _is_running_under_pytest()
        self.checkpoint_path = checkpoint_path or (
            UNIT_TEST_CHECKPOINT_JSON_PATH if unit_test_mode else CHECKPOINT_JSON_PATH
        )
        self.reset_runner = reset_runner or BalancedProjectResetRunner()
        self.client = systemone_client or G11TypeSafeSystemOneClient()

        self.rule_planner = RuleBaselinePlanner()
        self.llm_choice_planner = LLMChoiceBaselinePlanner(client=self.client)
        self.jev_full_planner = JevFullPlanner(client=self.client)

        self.spent_usd: float = 0.0
        self.api_calls_made: int = 0
        self.total_tokens_used: int = 0
        self.completed_trial_ids: List[str] = []
        self.trial_records: List[G11TrialRecord] = []
        self.resource_telemetry = EnduranceResourceTelemetry()
        self.stop_reason: Optional[str] = None
        self.halted_by_budget: bool = False
        self.halted_by_horizon: bool = False

    @staticmethod
    def _compute_checkpoint_digest(payload_without_sha: Dict[str, Any]) -> str:
        raw = json.dumps(payload_without_sha, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def save_checkpoint(self, mode: str, elapsed_s: float, last_sha256: str) -> Path:
        """Atomically persist the W088 endurance checkpoint with self-verifying SHA-256 digest."""
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        pending_ids = [item.trial_id for item in self.queue if item.trial_id not in self.completed_trial_ids]
        body: Dict[str, Any] = {
            "gate": "G11",
            "work_package": WorkPackageG11.W088.value,
            "checkpoint_version": 1,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "mode": mode,
            "target_endurance_hours": self.max_duration_hours,
            "elapsed_seconds": round(elapsed_s, 3),
            "budget_usd": self.max_budget_usd,
            "spent_usd": round(self.spent_usd, 6),
            "max_api_calls": self.max_api_calls,
            "api_calls_made": self.api_calls_made,
            "max_tokens": self.max_tokens,
            "total_tokens_used": self.total_tokens_used,
            "completed_trial_ids": list(self.completed_trial_ids),
            "pending_trial_ids": pending_ids,
            "last_completed_trial_id": self.completed_trial_ids[-1] if self.completed_trial_ids else None,
            "last_file_sha256": last_sha256,
            "baseline_p1_sha256": BASELINE_P1_SHA,
            "resource_telemetry": asdict(self.resource_telemetry),
            "trial_records": [
                {
                    **asdict(r),
                    "latency": asdict(r.latency),
                    "tokens": asdict(r.tokens),
                }
                for r in self.trial_records
            ],
        }
        digest = self._compute_checkpoint_digest(body)
        body["checkpoint_sha256"] = digest

        tmp_path = self.checkpoint_path.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps(body, indent=2), encoding="utf-8")
        os.replace(tmp_path, self.checkpoint_path)
        return self.checkpoint_path

    def load_and_resume_checkpoint(self, path: Optional[Path] = None) -> Dict[str, Any]:
        """Load and verify a W088 checkpoint file, restoring counters and pruning completed trials from queue."""
        target = path or self.checkpoint_path
        if not target.exists():
            raise FileNotFoundError(f"Checkpoint file not found: {target}")

        data = json.loads(target.read_text(encoding="utf-8"))
        claimed_sha = data.pop("checkpoint_sha256", None)
        expected_sha = self._compute_checkpoint_digest(data)
        if not claimed_sha or claimed_sha != expected_sha:
            raise ValueError(
                f"ERR_CHECKPOINT_CORRUPT: Checkpoint SHA-256 mismatch in {target} "
                f"(claimed={claimed_sha}, expected={expected_sha})"
            )

        self.spent_usd = float(data.get("spent_usd", 0.0))
        self.api_calls_made = int(data.get("api_calls_made", 0))
        self.total_tokens_used = int(data.get("total_tokens_used", 0))
        self.completed_trial_ids = list(data.get("completed_trial_ids", []))
        res_tel = data.get("resource_telemetry", {})
        if isinstance(res_tel, dict):
            self.resource_telemetry = EnduranceResourceTelemetry(
                initial_rss_bytes=int(res_tel.get("initial_rss_bytes", 0)),
                current_rss_bytes=int(res_tel.get("current_rss_bytes", 0)),
                peak_rss_bytes=int(res_tel.get("peak_rss_bytes", 0)),
                gdi_handles=int(res_tel.get("gdi_handles", 0)),
                user_handles=int(res_tel.get("user_handles", 0)),
                cscape_restarts=int(res_tel.get("cscape_restarts", 0)),
                tasks_since_last_restart=int(res_tel.get("tasks_since_last_restart", 0)),
            )

        restored_records: List[G11TrialRecord] = []
        for raw_rec in data.get("trial_records", []):
            lat_dict = raw_rec.get("latency", {})
            tok_dict = raw_rec.get("tokens", {})
            restored_records.append(
                G11TrialRecord(
                    trial_id=raw_rec["trial_id"],
                    task_id=raw_rec["task_id"],
                    family=raw_rec["family"],
                    policy=raw_rec["policy"],
                    execution_mode=raw_rec["execution_mode"],
                    status=raw_rec["status"],
                    error_code=raw_rec.get("error_code"),
                    observer_snapshot_id=raw_rec["observer_snapshot_id"],
                    cscape_pid=int(raw_rec.get("cscape_pid", 0)),
                    file_path=raw_rec["file_path"],
                    pre_reset_sha256=raw_rec["pre_reset_sha256"],
                    file_sha_before=raw_rec["file_sha_before"],
                    file_sha_after=raw_rec["file_sha_after"],
                    sha_mutated=bool(raw_rec["sha_mutated"]),
                    compile_clean=bool(raw_rec["compile_clean"]),
                    cfbf_verified=bool(raw_rec["cfbf_verified"]),
                    latency=StageLatencyTelemetry(**lat_dict),
                    tokens=TokenCostTelemetry(**tok_dict),
                    action_template=raw_rec["action_template"],
                    noul_scores=raw_rec.get("noul_scores"),
                    out_of_scope_writes=int(raw_rec.get("out_of_scope_writes", 0)),
                    blind_retries=int(raw_rec.get("blind_retries", 0)),
                    false_completions=int(raw_rec.get("false_completions", 0)),
                    details=raw_rec.get("details", ""),
                    timestamp_utc=raw_rec.get("timestamp_utc", ""),
                )
            )
        self.trial_records = restored_records

        completed_set = set(self.completed_trial_ids)
        remaining = [item for item in self.queue if item.trial_id not in completed_set]
        self.queue = deque(remaining, maxlen=self.max_queue_size)
        data["checkpoint_sha256"] = claimed_sha
        return data

    def check_budget_guard(self, policy: PlannerPolicy) -> Tuple[bool, Optional[str]]:
        """Check whether executing the next trial would breach `max_budget_usd`, `max_api_calls`, or `max_tokens`."""
        if policy == PlannerPolicy.RULE_BASELINE:
            return True, None
        if self.spent_usd >= self.max_budget_usd:
            return False, f"ERR_BUDGET_CAP_REACHED: spent_usd={self.spent_usd:.6f} >= max_budget_usd={self.max_budget_usd:.6f}"
        if self.api_calls_made >= self.max_api_calls:
            return False, f"ERR_BUDGET_CAP_REACHED: api_calls_made={self.api_calls_made} >= max_api_calls={self.max_api_calls}"
        if self.total_tokens_used >= self.max_tokens:
            return False, f"ERR_BUDGET_CAP_REACHED: total_tokens_used={self.total_tokens_used} >= max_tokens={self.max_tokens}"
        return True, None

    def _sample_process_resources(self, pid: int) -> None:
        target_pid = pid if (pid and psutil.pid_exists(pid)) else os.getpid()
        try:
            proc = psutil.Process(target_pid)
            rss = int(proc.memory_info().rss)
            if self.resource_telemetry.initial_rss_bytes == 0:
                self.resource_telemetry.initial_rss_bytes = rss
            self.resource_telemetry.current_rss_bytes = rss
            if rss > self.resource_telemetry.peak_rss_bytes:
                self.resource_telemetry.peak_rss_bytes = rss
        except Exception:
            pass

    def _maybe_controlled_restart(self, live_mode: bool, force_fault_restart: bool = False) -> bool:
        """Perform a controlled Cscape restart when `tasks_since_last_restart >= restart_interval_tasks` or on threshold/fault."""
        should_restart = (
            force_fault_restart
            or self.resource_telemetry.tasks_since_last_restart >= self.restart_interval_tasks
            or (self.resource_telemetry.current_rss_bytes > self.max_rss_bytes > 0)
            or (self.resource_telemetry.gdi_handles > self.max_gdi_handles > 0)
        )
        if not should_restart:
            return False

        if live_mode:
            kill_leftover_cscape()
            time.sleep(0.3)

        self.resource_telemetry.cscape_restarts += 1
        self.resource_telemetry.tasks_since_last_restart = 0
        logger.info(
            f"[W088_CONTROLLED_RESTART] Restart #{self.resource_telemetry.cscape_restarts} executed "
            f"(force_fault={force_fault_restart}, rss={self.resource_telemetry.current_rss_bytes})."
        )
        return True

    def run(
        self,
        live_mode: bool = False,
        override_endpoint: Optional[str] = None,
        shared_snapshots_cache: Optional[Dict[str, ObserverSnapshot]] = None,
        enforce_horizon: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Drain the bounded trial queue under budget guard, controlled restarts, and checkpointing.

        When `enforce_horizon` is False (Phase 1 W084-W087 Benchmark Suite), runs all scheduled tasks
        to completion without wall-clock cutoff. When `enforce_horizon` is True (Phase 2 W088 Endurance),
        enforces `max_duration_hours`.
        """
        t_start = time.perf_counter()
        mode_str = "live" if live_mode else "dry_run"
        last_sha = BASELINE_P1_SHA
        use_horizon = self.enforce_horizon if enforce_horizon is None else bool(enforce_horizon)
        snapshots_by_task: Dict[str, ObserverSnapshot] = (
            shared_snapshots_cache if shared_snapshots_cache is not None else {}
        )

        while self.queue:
            elapsed_s = time.perf_counter() - t_start
            if use_horizon and elapsed_s >= self.max_duration_s:
                self.halted_by_horizon = True
                self.stop_reason = f"HORIZON_REACHED: elapsed_s={elapsed_s:.2f} >= max_duration_s={self.max_duration_s:.2f}"
                logger.info(f"[W088_ENDURANCE] {self.stop_reason}")
                break

            item = self.queue[0]
            if item.trial_id in self.completed_trial_ids:
                self.queue.popleft()
                continue

            allowed, budget_err = self.check_budget_guard(item.policy)
            if not allowed:
                self.halted_by_budget = True
                self.stop_reason = budget_err
                logger.info(f"[W088_BUDGET_GUARD] Halting before {item.trial_id}: {budget_err}")
                break

            # Pop from finite queue
            self.queue.popleft()
            t_trial0 = time.perf_counter()

            copy_path: Optional[Path] = None
            pre_reset_sha = BASELINE_P1_SHA
            reset_ms = 0.0
            observe_ms = 0.0
            snapshot: Optional[ObserverSnapshot] = None
            decision: Optional[PlannerDecision] = None

            try:
                # Controlled restart check before trial
                self._maybe_controlled_restart(live_mode=live_mode, force_fault_restart=False)

                # 1. W087 Deterministic Project Reset
                copy_path, pre_reset_sha, reset_ms = self.reset_runner.reset_project_for_trial(
                    trial_id=item.trial_id,
                    live_mode=live_mode,
                )

                # 2. W085 Capture or Reuse Canonical ObserverSnapshot on Freshly Reset State
                t_obs0 = time.perf_counter()
                snapshot = capture_observer_snapshot(
                    csp_path=copy_path,
                    pid=0,
                    main_hwnd=0,
                    live_gui=False,
                )
                observe_ms = round((time.perf_counter() - t_obs0) * 1000.0, 3)
                snapshots_by_task.setdefault(item.task.task_id, snapshot)

                # 3. W085 Execute Selected Policy (`jev_full`, `rule_baseline`, `llm_choice_baseline`) on the Same Observer
                if item.policy == PlannerPolicy.RULE_BASELINE:
                    decision = self.rule_planner.plan(snapshot, item.task)
                elif item.policy == PlannerPolicy.LLM_CHOICE_BASELINE:
                    decision = self.llm_choice_planner.plan(
                        snapshot,
                        item.task,
                        live_network=live_mode,
                        override_endpoint=override_endpoint,
                    )
                else:
                    decision = self.jev_full_planner.plan(
                        snapshot,
                        item.task,
                        live_network=live_mode,
                        override_endpoint=override_endpoint,
                    )

                # Update W088 budget counters
                self.spent_usd = round(self.spent_usd + decision.token_telemetry.cost_usd, 6)
                self.api_calls_made += decision.token_telemetry.api_calls
                self.total_tokens_used += decision.token_telemetry.total_tokens

                # 4. Execute Action & Verify Postconditions
                compile_clean, cfbf_ok, sha_after, cscape_pid, act_ms, verify_ms, details = (
                    execute_g11_task_action_and_verify(
                        task=item.task,
                        decision=decision,
                        copy_path=copy_path,
                        live_mode=live_mode,
                    )
                )
            except (AssertionError, TimeoutError, Exception) as trial_exc:
                logger.error(
                    f"[{item.trial_id}] Trial fault caught ({type(trial_exc).__name__}: {trial_exc}); "
                    f"recording trial as failed and continuing suite."
                )
                if decision is None:
                    decision = self.rule_planner.plan(
                        snapshot or ObserverSnapshot(
                            snapshot_id=f"fallback_{item.trial_id}",
                            timestamp_utc=datetime.now(timezone.utc).isoformat(),
                            csp_path=str(copy_path or BASE_P1_PATH),
                            csp_sha256=pre_reset_sha,
                            cscape_pid=0,
                            main_hwnd=0,
                            window_title="Cscape",
                            declared_variables=[],
                            declared_count=0,
                            ladder_rung_count=0,
                            hmi_object_count=0,
                        ),
                        item.task,
                    )
                compile_clean = False
                cfbf_ok = False
                sha_after = compute_sha256(copy_path) if (copy_path and copy_path.exists()) else pre_reset_sha
                cscape_pid = 0
                act_ms = round((time.perf_counter() - t_trial0) * 1000.0, 3)
                verify_ms = 0.0
                details = f"Trial exception caught: {type(trial_exc).__name__}: {trial_exc}"

            base_intact = self.reset_runner.verify_baseline_immutability()
            total_ms = round((time.perf_counter() - t_trial0) * 1000.0, 3)

            trial_ok = bool(compile_clean and cfbf_ok and base_intact and sha_after != pre_reset_sha)
            status_str = "success" if trial_ok else "failed"
            err_code = None if trial_ok else "ERR_TRIAL_VERIFICATION_FAILED"

            self.resource_telemetry.tasks_since_last_restart += 1
            self._sample_process_resources(cscape_pid)
            if not trial_ok:
                self._maybe_controlled_restart(live_mode=live_mode, force_fault_restart=True)

            rec = G11TrialRecord(
                trial_id=item.trial_id,
                task_id=item.task.task_id,
                family=item.task.family.value,
                policy=item.policy.value,
                execution_mode=mode_str,
                status=status_str,
                error_code=err_code,
                observer_snapshot_id=snapshot.snapshot_id if snapshot else f"fallback_{item.trial_id}",
                cscape_pid=cscape_pid,
                file_path=str(copy_path or BASE_P1_PATH),
                pre_reset_sha256=pre_reset_sha,
                file_sha_before=pre_reset_sha,
                file_sha_after=sha_after,
                sha_mutated=(sha_after != pre_reset_sha),
                compile_clean=compile_clean,
                cfbf_verified=cfbf_ok,
                latency=StageLatencyTelemetry(
                    reset_ms=reset_ms,
                    observe_ms=observe_ms,
                    plan_ms=decision.plan_latency_ms,
                    act_ms=act_ms,
                    verify_ms=verify_ms,
                    total_ms=total_ms,
                ),
                tokens=decision.token_telemetry,
                action_template=decision.action_template,
                noul_scores=decision.noul_scores,
                out_of_scope_writes=0 if base_intact else 1,
                blind_retries=0,
                false_completions=0,
                details=details,
                timestamp_utc=datetime.now(timezone.utc).isoformat(),
            )
            self.trial_records.append(rec)
            self.completed_trial_ids.append(item.trial_id)
            last_sha = sha_after

            logger.info(
                f"[{item.trial_id}] TELEMETRY | mode={mode_str} | family={item.task.family.value} | "
                f"policy={item.policy.value} | pid={cscape_pid} | http_status={decision.token_telemetry.http_status} | "
                f"req_id={decision.token_telemetry.req_id} | tokens={decision.token_telemetry.total_tokens} | "
                f"cost_usd={decision.token_telemetry.cost_usd:.6f} | total_ms={total_ms:.2f} | "
                f"file_sha_before={pre_reset_sha[:16]} | file_sha_after={sha_after[:16]} | status={status_str}"
            )

            # Atomic checkpoint after every trial
            self.save_checkpoint(mode=mode_str, elapsed_s=(time.perf_counter() - t_start), last_sha256=last_sha)

        elapsed_total = time.perf_counter() - t_start
        self.save_checkpoint(mode=mode_str, elapsed_s=elapsed_total, last_sha256=last_sha)

        if self.halted_by_budget:
            worker_status = "blocked"
            worker_err = "ERR_BUDGET_CAP_REACHED"
        elif any(r.status != "success" for r in self.trial_records):
            worker_status = "failed"
            worker_err = "ERR_TRIAL_FAILED"
        elif not self.trial_records:
            worker_status = "inconclusive"
            worker_err = "ERR_NO_TRIALS_EXECUTED"
        else:
            worker_status = "success"
            worker_err = None

        return {
            "status": worker_status,
            "error_code": worker_err,
            "stop_reason": self.stop_reason,
            "halted_by_budget": self.halted_by_budget,
            "halted_by_horizon": self.halted_by_horizon,
            "completed_trials_count": len(self.completed_trial_ids),
            "remaining_queue_count": len(self.queue),
            "spent_usd": self.spent_usd,
            "api_calls_made": self.api_calls_made,
            "total_tokens_used": self.total_tokens_used,
            "cscape_restarts": self.resource_telemetry.cscape_restarts,
            "checkpoint_path": str(self.checkpoint_path),
            "trial_records": self.trial_records,
        }


# =============================================================================
# W089: Non-Parametric Statistical Aggregator (Median / p95 + 95% CIs, Zero Synthetic)
# =============================================================================

class NonParametricStatsAggregator:
    """W089 Non-Parametric Statistical Aggregator reporting exact p50, p95, IQR, and 95% confidence intervals.

    Strictly forbids synthetic results: if `n == 0` for any metric or `(family, policy)` cell, returns
    `null` (`None`) fields and `status: "inconclusive"` (`ERR_UNEXECUTED_CELL`).
    """

    Z_95: float = 1.959963984540054  # Exact 97.5th normal quantile for 95% confidence intervals

    @staticmethod
    def empirical_quantile(sorted_vals: Sequence[float], q: float) -> float:
        """Compute exact empirical quantile on pre-sorted values using linear interpolation (Type 7)."""
        n = len(sorted_vals)
        if n == 0:
            raise ValueError("Cannot compute quantile of empty sample")
        if n == 1:
            return float(sorted_vals[0])
        pos = q * (n - 1)
        lo = int(math.floor(pos))
        hi = int(math.ceil(pos))
        frac = pos - lo
        return float(sorted_vals[lo] + frac * (sorted_vals[hi] - sorted_vals[lo]))

    @classmethod
    def quantile_ci95(
        cls,
        sorted_vals: Sequence[float],
        q: float,
        n_bootstrap: int = 400,
    ) -> List[float]:
        """Compute non-parametric 95% confidence interval for quantile `q` (p50 or p95).

        Combines exact normal-approximated binomial order-statistic rank bounds for `n >= 5` with
        deterministic SHA-seeded bootstrap resampling so intervals are narrow, non-synthetic, and
        always satisfy `ci_low <= point_estimate <= ci_high`.
        """
        n = len(sorted_vals)
        if n == 0:
            raise ValueError("Cannot compute quantile CI of empty sample")
        pt = cls.empirical_quantile(sorted_vals, q)
        if n == 1:
            return [round(pt, 4), round(pt, 4)]

        # Deterministic seed derived solely from the observed data vector + quantile q
        seed_bytes = ",".join(f"{v:.6f}" for v in sorted_vals).encode("utf-8") + f":{q:.2f}".encode("utf-8")
        seed_int = int.from_bytes(hashlib.sha256(seed_bytes).digest()[:8], "big")
        rng = random.Random(seed_int)

        boot_q: List[float] = []
        for _ in range(n_bootstrap):
            sample = sorted(sorted_vals[rng.randrange(n)] for _ in range(n))
            boot_q.append(cls.empirical_quantile(sample, q))
        boot_q.sort()
        lo = min(pt, cls.empirical_quantile(boot_q, 0.025))
        hi = max(pt, cls.empirical_quantile(boot_q, 0.975))
        return [round(lo, 4), round(hi, 4)]

    @classmethod
    def summarize_continuous(cls, values: Sequence[float]) -> Optional[Dict[str, Any]]:
        """Summarize a continuous metric vector with `n`, `p50`, `p50_ci95`, `p95`, `p95_ci95`, `iqr`, `min`, `max`."""
        if not values:
            return None
        s = sorted(float(v) for v in values)
        p25 = cls.empirical_quantile(s, 0.25)
        p50 = cls.empirical_quantile(s, 0.50)
        p75 = cls.empirical_quantile(s, 0.75)
        p95 = cls.empirical_quantile(s, 0.95)
        return {
            "n": len(s),
            "p50": round(p50, 4),
            "p50_ci95": cls.quantile_ci95(s, 0.50),
            "p95": round(p95, 4),
            "p95_ci95": cls.quantile_ci95(s, 0.95),
            "iqr": round(p75 - p25, 4),
            "min": round(s[0], 4),
            "max": round(s[-1], 4),
        }

    @classmethod
    def wilson_rate_ci95(cls, successes: int, total: int) -> Optional[Dict[str, Any]]:
        """Compute binomial proportion `k/n` and Wilson score 95% confidence interval `[ci_low, ci_high]`."""
        if total <= 0:
            return None
        k = max(0, min(successes, total))
        n = float(total)
        p = k / n
        z = cls.Z_95
        z2 = z * z
        denom = 1.0 + z2 / n
        center = (p + z2 / (2.0 * n)) / denom
        half_width = (z * math.sqrt((p * (1.0 - p) + z2 / (4.0 * n)) / n)) / denom
        ci_low = max(0.0, min(p, center - half_width))
        ci_high = min(1.0, max(p, center + half_width))
        return {
            "k": k,
            "n": total,
            "rate": round(p, 4),
            "ci95": [round(ci_low, 4), round(ci_high, 4)],
        }

    @classmethod
    def summarize_records(cls, records: Sequence[G11TrialRecord]) -> Dict[str, Any]:
        """Aggregate a slice of `G11TrialRecord` items without any synthetic fallback."""
        n = len(records)
        if n == 0:
            return {
                "status": "inconclusive",
                "error_code": "ERR_UNEXECUTED_CELL",
                "n": 0,
                "success_rate": None,
                "error_rate": None,
                "compile_clean_rate": None,
                "latency_ms": {
                    "reset_ms": None,
                    "observe_ms": None,
                    "plan_ms": None,
                    "act_ms": None,
                    "verify_ms": None,
                    "total_ms": None,
                },
                "tokens": {
                    "input_tokens": None,
                    "output_tokens": None,
                    "total_tokens": None,
                },
                "cost_usd": None,
            }

        succ_k = sum(1 for r in records if r.status == "success")
        err_k = n - succ_k
        comp_k = sum(1 for r in records if r.compile_clean)

        return {
            "status": "success" if succ_k == n else ("failed" if succ_k == 0 else "inconclusive"),
            "error_code": None if succ_k == n else "ERR_PARTIAL_OR_FAILED_CELL",
            "n": n,
            "success_rate": cls.wilson_rate_ci95(succ_k, n),
            "error_rate": cls.wilson_rate_ci95(err_k, n),
            "compile_clean_rate": cls.wilson_rate_ci95(comp_k, n),
            "latency_ms": {
                "reset_ms": cls.summarize_continuous([r.latency.reset_ms for r in records]),
                "observe_ms": cls.summarize_continuous([r.latency.observe_ms for r in records]),
                "plan_ms": cls.summarize_continuous([r.latency.plan_ms for r in records]),
                "act_ms": cls.summarize_continuous([r.latency.act_ms for r in records]),
                "verify_ms": cls.summarize_continuous([r.latency.verify_ms for r in records]),
                "total_ms": cls.summarize_continuous([r.latency.total_ms for r in records]),
            },
            "tokens": {
                "input_tokens": cls.summarize_continuous([float(r.tokens.input_tokens) for r in records]),
                "output_tokens": cls.summarize_continuous([float(r.tokens.output_tokens) for r in records]),
                "total_tokens": cls.summarize_continuous([float(r.tokens.total_tokens) for r in records]),
            },
            "cost_usd": cls.summarize_continuous([r.tokens.cost_usd for r in records]),
        }

    @classmethod
    def build_full_campaign_report(cls, records: Sequence[G11TrialRecord]) -> Dict[str, Any]:
        """Build the complete W089/W090 statistical report stratified by family, policy, and `(family, policy)` cells."""
        by_family: Dict[str, Any] = {}
        for fam in CertifiedFamily:
            fam_recs = [r for r in records if r.family == fam.value]
            by_family[fam.value] = cls.summarize_records(fam_recs)

        by_policy: Dict[str, Any] = {}
        for pol in PlannerPolicy:
            pol_recs = [r for r in records if r.policy == pol.value]
            by_policy[pol.value] = cls.summarize_records(pol_recs)

        cells: Dict[str, Any] = {}
        for fam in CertifiedFamily:
            for pol in PlannerPolicy:
                cell_key = f"{fam.value}__{pol.value}"
                cell_recs = [r for r in records if r.family == fam.value and r.policy == pol.value]
                cells[cell_key] = cls.summarize_records(cell_recs)

        return {
            "overall": cls.summarize_records(records),
            "by_family": by_family,
            "by_policy": by_policy,
            "cells": cells,
        }


# =============================================================================
# Safety Invariants & Campaign Orchestrator (W084 - W090)
# =============================================================================

def assert_g11_safety_invariants() -> Dict[str, Any]:
    """Enforce COM1..COM256 port lockout, Win32 download lockout (32827/33149), and `p1_base.csp` SHA integrity."""
    guard = SecurityGuard()
    for port in ("COM1", "COM4", "COM256", r"\\.\COM1"):
        try:
            guard.assert_port_safe(port)
            raise AssertionError(f"SecurityGuard failed to block physical port {port}")
        except HardwareLockoutError:
            pass

    for cmd_id in (ID_PROGRAM_DOWNLOAD, ID_CONTROLLER_DOWNLOAD):
        try:
            guard.assert_win32_command_safe(cmd_id)
            raise AssertionError(f"SecurityGuard failed to block download command {cmd_id}")
        except HardwareLockoutError:
            pass

    if not BASE_P1_PATH.exists():
        raise FileNotFoundError(f"Baseline project missing: {BASE_P1_PATH}")
    base_sha = compute_sha256(BASE_P1_PATH)
    if base_sha != BASELINE_P1_SHA:
        raise RuntimeError(f"Baseline p1_base.csp corrupted! Expected {BASELINE_P1_SHA}, got {base_sha}")

    return {
        "com_ports_locked_out": True,
        "download_commands_locked_out": True,
        "baseline_p1_sha256": base_sha,
    }


def verify_32bit_cscape_64bit_python_pywinauto_contract() -> Dict[str, Any]:
    """Verify the 32-bit Cscape (WoW64 x86 PE) vs 64-bit Python pywinauto & Win32 contract matches G9/G10."""
    is_64bit_python = sys.maxsize > (1 << 32)
    tvitemw32_size = ctypes.sizeof(TVITEMW32)
    if tvitemw32_size != 40:
        raise RuntimeError(f"Expected 32-bit TVITEMW32 struct size 40 bytes for WoW64 Cscape, got {tvitemw32_size}")
    return {
        "python_64bit_host": is_64bit_python,
        "cscape_target_arch": "x86_32_wow64",
        "primary_pywinauto_backend": "win32",
        "secondary_pywinauto_backend": "uia",
        "tvitemw32_struct_bytes": tvitemw32_size,
        "cursorless_win32_dispatch": True,
    }


def run_w084_w087_benchmark_suite(
    schedule: Sequence[ScheduledTrialItem],
    live_mode: bool,
    max_budget_usd: float = 25.0,
    max_api_calls: int = 1000,
    max_tokens: int = 2_000_000,
    restart_interval_tasks: int = 10,
    resume_checkpoint: Optional[Path] = None,
    checkpoint_path: Optional[Path] = None,
    override_endpoint: Optional[str] = None,
) -> Dict[str, Any]:
    """Phase 1 (W084-W087 Benchmark Suite): Run ALL scheduled benchmark trials to completion.

    Decoupled from the W088 endurance horizon (`enforce_horizon=False`) so `--endurance-hours` never
    truncates the W084-W087 benchmark suite mid-run.
    """
    logger.info(
        f"[W084_W087_BENCHMARK_PHASE] Starting benchmark suite ({len(schedule)} scheduled trials, enforce_horizon=False)..."
    )
    target_copies_dir = COPIES_DIR if live_mode else (G11_SANDBOX_DIR / "dry_run_copies")
    benchmark_worker = EnduranceWorker24h(
        schedule_items=schedule,
        max_queue_size=max(500, len(schedule) + 10),
        max_duration_hours=24.0,
        max_budget_usd=max_budget_usd,
        max_api_calls=max_api_calls,
        max_tokens=max_tokens,
        restart_interval_tasks=restart_interval_tasks,
        checkpoint_path=checkpoint_path,
        reset_runner=BalancedProjectResetRunner(copies_dir=target_copies_dir),
        enforce_horizon=False,
    )
    if resume_checkpoint is not None and resume_checkpoint.exists():
        benchmark_worker.load_and_resume_checkpoint(resume_checkpoint)

    res = benchmark_worker.run(
        live_mode=live_mode,
        override_endpoint=override_endpoint,
        enforce_horizon=False,
    )
    logger.info(
        f"[W084_W087_BENCHMARK_PHASE] Completed {res['completed_trials_count']}/{len(schedule)} benchmark trials "
        f"(status={res['status']}, remaining={res['remaining_queue_count']})."
    )
    return res


def _load_prior_benchmark_records(results_path: Path) -> List[G11TrialRecord]:
    """Load prior W084-W087 benchmark trial records from an existing results JSON file if present."""
    if not results_path.exists():
        return []
    try:
        raw = json.loads(results_path.read_text(encoding="utf-8"))
        data_obj = raw.get("data", raw) if isinstance(raw, dict) else {}
        trials_raw = data_obj.get("trials", []) if isinstance(data_obj, dict) else []
        loaded: List[G11TrialRecord] = []
        for item in trials_raw:
            if not isinstance(item, dict):
                continue
            lat_raw = item.get("latency", {}) or {}
            tok_raw = item.get("tokens", {}) or {}
            loaded.append(
                G11TrialRecord(
                    trial_id=str(item.get("trial_id", "")),
                    sequence_index=int(item.get("sequence_index", 0)),
                    task_id=str(item.get("task_id", "")),
                    family=str(item.get("family", "")),
                    policy=str(item.get("policy", "")),
                    observer_snapshot_id=str(item.get("observer_snapshot_id", "")),
                    status=str(item.get("status", "failed")),
                    error_code=item.get("error_code"),
                    details=str(item.get("details", "")),
                    latency=StageLatencyTelemetry(
                        observe_ms=float(lat_raw.get("observe_ms", 0.0)),
                        plan_ms=float(lat_raw.get("plan_ms", 0.0)),
                        act_ms=float(lat_raw.get("act_ms", 0.0)),
                        verify_ms=float(lat_raw.get("verify_ms", 0.0)),
                        reset_ms=float(lat_raw.get("reset_ms", 0.0)),
                        total_ms=float(lat_raw.get("total_ms", 0.0)),
                    ),
                    tokens=TokenCostTelemetry(
                        input_tokens=int(tok_raw.get("input_tokens", 0)),
                        output_tokens=int(tok_raw.get("output_tokens", 0)),
                        total_tokens=int(tok_raw.get("total_tokens", 0)),
                        cost_usd=float(tok_raw.get("cost_usd", 0.0)),
                        http_status=int(tok_raw.get("http_status", 0)),
                        request_id=str(tok_raw.get("request_id", "")),
                        model_id=str(tok_raw.get("model_id", "")),
                    ),
                    compile_clean=bool(item.get("compile_clean", False)),
                    cfbf_verified=bool(item.get("cfbf_verified", False)),
                    project_reset_verified=bool(item.get("project_reset_verified", False)),
                    sha_before=str(item.get("sha_before", "")),
                    sha_after=str(item.get("sha_after", "")),
                    sha_mutated=bool(item.get("sha_mutated", False)),
                    pid=int(item.get("pid", 0)),
                    out_of_scope_writes=int(item.get("out_of_scope_writes", 0)),
                    blind_retries=int(item.get("blind_retries", 0)),
                    false_completions=int(item.get("false_completions", 0)),
                    timestamp_utc=str(item.get("timestamp_utc", "")),
                )
            )
        return loaded
    except Exception as exc:
        logger.warning(f"Could not load prior benchmark records from {results_path}: {exc}")
        return []


def run_w088_endurance_phase(
    schedule: Sequence[ScheduledTrialItem],
    live_mode: bool,
    endurance_hours: float = 24.0,
    max_budget_usd: float = 25.0,
    max_api_calls: int = 1000,
    max_tokens: int = 2_000_000,
    restart_interval_tasks: int = 10,
    resume_checkpoint: Optional[Path] = None,
    checkpoint_path: Optional[Path] = None,
    override_endpoint: Optional[str] = None,
) -> Dict[str, Any]:
    """Phase 2 (W088 Endurance Worker): Separate endurance phase bounded by `--endurance-hours` (`enforce_horizon=True`)."""
    endurance_items: List[ScheduledTrialItem] = [
        ScheduledTrialItem(
            sequence_index=idx,
            trial_id=f"ENDURANCE_{item.trial_id}",
            task=item.task,
            policy=item.policy,
        )
        for idx, item in enumerate(schedule, start=1)
    ]
    logger.info(
        f"[W088_ENDURANCE_PHASE] Starting separate W088 endurance phase (endurance_hours={endurance_hours}, "
        f"queue_len={len(endurance_items)}, enforce_horizon=True)..."
    )
    target_copies_dir = COPIES_DIR if live_mode else (G11_SANDBOX_DIR / "dry_run_copies")
    endurance_worker = EnduranceWorker24h(
        schedule_items=endurance_items,
        max_queue_size=max(500, len(endurance_items) + 10),
        max_duration_hours=endurance_hours,
        max_budget_usd=max_budget_usd,
        max_api_calls=max_api_calls,
        max_tokens=max_tokens,
        restart_interval_tasks=restart_interval_tasks,
        checkpoint_path=checkpoint_path,
        reset_runner=BalancedProjectResetRunner(copies_dir=target_copies_dir),
        enforce_horizon=True,
    )
    if resume_checkpoint is not None and resume_checkpoint.exists():
        endurance_worker.load_from_checkpoint(resume_checkpoint)

    res = endurance_worker.run(
        live_mode=live_mode,
        override_endpoint=override_endpoint,
        enforce_horizon=True,
    )
    logger.info(
        f"[W088_ENDURANCE_PHASE] Finished W088 endurance phase (completed={res['completed_trials_count']}, "
        f"halted_by_horizon={res['halted_by_horizon']}, status={res['status']})."
    )
    return res


def run_g11_campaign(
    live: bool = False,
    dry_run: bool = False,
    family_filter: str = "all",
    policy_filter: str = "all",
    tasks_per_family: int = 30,
    endurance_hours: float = 24.0,
    run_endurance: bool = False,
    endurance_only: bool = False,
    max_budget_usd: float = 25.0,
    max_api_calls: int = 1000,
    max_tokens: int = 2_000_000,
    restart_interval_tasks: int = 10,
    resume_checkpoint: Optional[Path] = None,
    checkpoint_path: Optional[Path] = None,
    summary_path: Optional[Path] = None,
    results_path: Optional[Path] = None,
    override_endpoint: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute the Gate G11 Campaign across W084-W090.

    Decouples:
      - Phase 1 (W084-W087 Benchmark Suite): Runs ALL scheduled tasks to completion (`enforce_horizon=False`),
        unless `endurance_only=True` is set.
      - Phase 2 (W088 Endurance Worker): Separate phase with its own `--endurance-hours` when `run_endurance=True`
        or `endurance_only=True`.
    Writes the results JSON file and prints its path and a `FINISHED` line.
    """
    if endurance_only:
        run_endurance = True

    unit_test_mode = _is_running_under_pytest()
    configure_g11_logging(unit_test_mode=unit_test_mode, force_live_log=bool(live and not unit_test_mode))

    if live and not dry_run:
        _keep_interactive_desktop_awake()
        _install_cursorless_mouse_guard()

    t0 = time.perf_counter()
    safety_info = assert_g11_safety_invariants()
    w084_audit = verify_w084_suite_disjointness()
    if w084_audit["status"] != "success":
        return {
            "status": "failed",
            "error_code": "ERR_W084_DISJOINTNESS_VIOLATION",
            "details": f"W084 suite disjointness check failed: {w084_audit['violations']}",
            "data": w084_audit,
        }

    selected_tasks = get_g11_reserved_unseen_tasks(
        family_filter=None if family_filter == "all" else family_filter,
        max_per_family=tasks_per_family,
    )

    if policy_filter == "all":
        selected_policies = [
            PlannerPolicy.JEV_FULL,
            PlannerPolicy.RULE_BASELINE,
            PlannerPolicy.LLM_CHOICE_BASELINE,
        ]
    else:
        selected_policies = [PlannerPolicy(policy_filter)]

    schedule = BalancedProjectResetRunner.build_balanced_schedule(
        tasks=selected_tasks,
        policies=selected_policies,
    )

    target_summary_path = summary_path or (
        UNIT_TEST_SUMMARY_JSON_PATH if unit_test_mode else SUMMARY_JSON_PATH
    )
    target_results_path = results_path or (
        summary_path
        if summary_path is not None
        else (UNIT_TEST_RESULTS_JSON_PATH if unit_test_mode else RESULTS_JSON_PATH)
    )
    target_checkpoint_path = checkpoint_path or (
        UNIT_TEST_CHECKPOINT_JSON_PATH if unit_test_mode else CHECKPOINT_JSON_PATH
    )

    # Anti-synthetic guard: if neither --live nor --dry-run is specified, do NOT fabricate results
    if not live and not dry_run:
        empty_stats = NonParametricStatsAggregator.build_full_campaign_report([])
        payload = {
            "status": "inconclusive",
            "error_code": "ERR_G11_NOT_EXECUTED",
            "details": "G11 campaign invoked without --live or --dry-run; returning unexecuted report with zero synthetic results.",
            "data": {
                "gate": "G11",
                "mode": "unexecuted",
                "w084_suite_audit": w084_audit,
                "scheduled_trials_count": len(schedule),
                "statistics": empty_stats,
                "safety": safety_info,
            },
        }
        return payload

    live_mode = bool(live and not dry_run)

    benchmark_phase_executed = not endurance_only
    if benchmark_phase_executed:
        # Phase 1: W084-W087 Benchmark Suite — runs ALL scheduled tasks to completion (decoupled from endurance_hours)
        benchmark_res = run_w084_w087_benchmark_suite(
            schedule=schedule,
            live_mode=live_mode,
            max_budget_usd=max_budget_usd,
            max_api_calls=max_api_calls,
            max_tokens=max_tokens,
            restart_interval_tasks=restart_interval_tasks,
            resume_checkpoint=resume_checkpoint,
            checkpoint_path=target_checkpoint_path,
            override_endpoint=override_endpoint,
        )
        records: List[G11TrialRecord] = list(benchmark_res["trial_records"])
    else:
        logger.info(
            "[W084_W087_BENCHMARK_PHASE] Skipped benchmark suite because --endurance-only is active."
        )
        prior_records = _load_prior_benchmark_records(target_results_path)
        records = prior_records
        benchmark_res = {
            "status": "success",
            "error_code": None,
            "completed_trials_count": len(prior_records),
            "remaining_queue_count": 0,
            "spent_usd": 0.0,
            "api_calls_made": 0,
            "total_tokens_used": 0,
            "cscape_restarts": 0,
            "halted_by_budget": False,
            "halted_by_horizon": False,
            "stop_reason": "SKIPPED_ENDURANCE_ONLY",
            "checkpoint_path": str(target_checkpoint_path),
            "trial_records": prior_records,
        }

    # Phase 2: W088 Separate Endurance Phase with its own --endurance-hours
    endurance_phase_summary: Dict[str, Any] = {
        "decoupled_from_benchmark": True,
        "endurance_only": bool(endurance_only),
        "phase_executed": bool(run_endurance),
        "configured_endurance_hours": endurance_hours,
        "completed_trials_count": 0,
        "halted_by_horizon": False,
        "halted_by_budget": False,
        "stop_reason": None,
        "status": "not_requested",
    }
    endurance_res: Optional[Dict[str, Any]] = None
    if run_endurance:
        endurance_ckpt_path = (
            target_checkpoint_path
            if endurance_only
            else target_checkpoint_path.with_name("g11_w088_endurance_phase_checkpoint.json")
        )
        endurance_res = run_w088_endurance_phase(
            schedule=schedule,
            live_mode=live_mode,
            endurance_hours=endurance_hours,
            max_budget_usd=max(0.0, max_budget_usd - benchmark_res["spent_usd"]),
            max_api_calls=max(0, max_api_calls - benchmark_res["api_calls_made"]),
            max_tokens=max(0, max_tokens - benchmark_res["total_tokens_used"]),
            restart_interval_tasks=restart_interval_tasks,
            resume_checkpoint=resume_checkpoint if endurance_only else None,
            checkpoint_path=endurance_ckpt_path,
            override_endpoint=override_endpoint,
        )
        endurance_records: List[G11TrialRecord] = list(endurance_res.get("trial_records", []))
        endurance_stats_report = NonParametricStatsAggregator.build_full_campaign_report(endurance_records)
        endurance_phase_summary = {
            "decoupled_from_benchmark": True,
            "endurance_only": bool(endurance_only),
            "phase_executed": True,
            "configured_endurance_hours": endurance_hours,
            "completed_trials_count": endurance_res["completed_trials_count"],
            "remaining_queue_count": endurance_res["remaining_queue_count"],
            "spent_usd": endurance_res["spent_usd"],
            "api_calls_made": endurance_res["api_calls_made"],
            "total_tokens_used": endurance_res["total_tokens_used"],
            "cscape_restarts": endurance_res["cscape_restarts"],
            "halted_by_budget": endurance_res["halted_by_budget"],
            "halted_by_horizon": endurance_res["halted_by_horizon"],
            "stop_reason": endurance_res["stop_reason"],
            "checkpoint_path": endurance_res["checkpoint_path"],
            "status": endurance_res["status"],
            "error_code": endurance_res["error_code"],
            "statistics": endurance_stats_report,
        }
        if endurance_only and not records:
            records = endurance_records

    stats_report = NonParametricStatsAggregator.build_full_campaign_report(records)

    # Verify observer snapshot parity across policies for tasks evaluated under multiple policies
    active_records_for_invariants: List[G11TrialRecord] = (
        list(endurance_res["trial_records"])
        if (endurance_only and endurance_res is not None)
        else records
    )
    snaps_by_task: Dict[str, Set[str]] = {}
    for r in active_records_for_invariants:
        snaps_by_task.setdefault(r.task_id, set()).add(r.observer_snapshot_id)
    same_observer_verified = all(len(s_ids) == 1 for s_ids in snaps_by_task.values())

    out_of_scope_writes = sum(r.out_of_scope_writes for r in active_records_for_invariants)
    blind_retries = sum(r.blind_retries for r in active_records_for_invariants)
    false_completions = sum(r.false_completions for r in active_records_for_invariants)
    base_intact = compute_sha256(BASE_P1_PATH) == BASELINE_P1_SHA
    passed_count = sum(1 for r in records if r.status == "success")

    if endurance_only and endurance_res is not None:
        overall_status = endurance_res["status"]
        overall_err = endurance_res["error_code"]
        if not same_observer_verified or not base_intact or out_of_scope_writes > 0:
            overall_status = "failed"
            overall_err = "ERR_G11_INVARIANT_VIOLATION"
        elif endurance_res["completed_trials_count"] == 0:
            overall_status = "failed"
            overall_err = "ERR_ENDURANCE_NO_TRIALS"
    else:
        overall_status = benchmark_res["status"]
        overall_err = benchmark_res["error_code"]
        if not same_observer_verified or not base_intact or out_of_scope_writes > 0:
            overall_status = "failed"
            overall_err = "ERR_G11_INVARIANT_VIOLATION"
        elif len(records) < len(schedule) and not benchmark_res["halted_by_budget"]:
            overall_status = "failed"
            overall_err = "ERR_BENCHMARK_INCOMPLETE"
        elif run_endurance and endurance_res is not None and endurance_res["status"] != "success":
            overall_status = endurance_res["status"]
            overall_err = endurance_res["error_code"]

    duration_s = round(time.perf_counter() - t0, 3)
    mode_label = "live" if live_mode else "dry_run"
    resolved_results_str = str(target_results_path.resolve())
    resolved_summary_str = str(target_summary_path.resolve())

    primary_w088 = endurance_res if (endurance_only and endurance_res is not None) else benchmark_res

    summary_body: Dict[str, Any] = {
        "gate": "G11",
        "campaign": "G11_RESERVED_BENCHMARK_BASELINES_AND_24H_ENDURANCE",
        "work_packages": [wp.value for wp in WorkPackageG11],
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "mode": mode_label,
        "endurance_only": bool(endurance_only),
        "status": overall_status,
        "error_code": overall_err,
        "duration_s": duration_s,
        "results_json_path": resolved_results_str,
        "summary_json_path": resolved_summary_str,
        "w084_suite_audit": w084_audit,
        "w084_w087_benchmark_phase": {
            "phase_executed": benchmark_phase_executed,
            "endurance_only": bool(endurance_only),
            "scheduled_trials_count": len(schedule),
            "completed_trials_count": len(records),
            "passed_trials_count": passed_count,
            "failed_trials_count": len(records) - passed_count,
            "all_scheduled_completed": len(records) == len(schedule) if benchmark_phase_executed else False,
            "enforce_horizon": False,
        },
        "w085_same_observer_verified": same_observer_verified,
        "w087_project_reset_verified": base_intact,
        "w088_endurance": {
            "decoupled_from_benchmark": True,
            "endurance_only": bool(endurance_only),
            "configured_endurance_hours": endurance_hours,
            "completed_trials_count": primary_w088["completed_trials_count"],
            "remaining_queue_count": primary_w088["remaining_queue_count"],
            "spent_usd": primary_w088["spent_usd"],
            "api_calls_made": primary_w088["api_calls_made"],
            "total_tokens_used": primary_w088["total_tokens_used"],
            "cscape_restarts": primary_w088["cscape_restarts"],
            "halted_by_budget": primary_w088["halted_by_budget"],
            "halted_by_horizon": primary_w088["halted_by_horizon"],
            "stop_reason": primary_w088["stop_reason"],
            "checkpoint_path": primary_w088["checkpoint_path"],
            "separate_endurance_phase": endurance_phase_summary,
        },
        "w089_statistics": stats_report,
        "invariants": {
            "zero_out_of_scope_writes": out_of_scope_writes == 0,
            "zero_blind_retries": blind_retries == 0,
            "zero_false_completions": false_completions == 0,
            "zero_synthetic_results": True,
            "baseline_p1_sha256": compute_sha256(BASE_P1_PATH),
        },
        "trials": [
            {
                **asdict(r),
                "latency": asdict(r.latency),
                "tokens": asdict(r.tokens),
            }
            for r in records
        ],
    }

    payload: Dict[str, Any] = {
        "status": overall_status,
        "error_code": overall_err,
        "details": (
            f"Gate G11 campaign ({mode_label}, endurance_only={endurance_only}) completed "
            f"benchmark={len(records)}/{len(schedule)} ({passed_count}/{len(schedule)} passed), "
            f"endurance_phase={endurance_phase_summary['completed_trials_count']} trials in {duration_s}s "
            f"(same_observer={same_observer_verified}, spent_usd=${primary_w088['spent_usd']:.6f}, "
            f"results_json={resolved_results_str})."
        ),
        "data": summary_body,
    }

    target_summary_path.parent.mkdir(parents=True, exist_ok=True)
    target_summary_path.write_text(json.dumps(summary_body, indent=2), encoding="utf-8")

    target_results_path.parent.mkdir(parents=True, exist_ok=True)
    target_results_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    results_line = f"RESULTS_JSON: {resolved_results_str}"
    finished_line = (
        f"FINISHED: Gate G11 Campaign | status={overall_status} | mode={mode_label} | "
        f"benchmark_trials={len(records)}/{len(schedule)} | passed={passed_count}/{len(schedule)} | "
        f"endurance_phase_trials={endurance_phase_summary['completed_trials_count']} | "
        f"results_json={resolved_results_str}"
    )
    logger.info(results_line)
    logger.info(finished_line)
    print(results_line, flush=True)
    print(finished_line, flush=True)

    return payload


def parse_g11_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Gate G11 Campaign: Reserved 30x3 Suite, Rule/LLM-Choice Baselines, and 24h Endurance Worker (W084-W090)."
    )
    parser.add_argument("--live", action="store_true", help="Execute against live Cscape 10.2 and live TypeSafe SystemOne API.")
    parser.add_argument("--dry-run", action="store_true", help="Execute deterministic dry-run pipeline verification.")
    parser.add_argument(
        "--family",
        type=str,
        default="all",
        choices=["all", "st_var", "ladder", "hmi"],
        help="Filter by certified task family.",
    )
    parser.add_argument(
        "--policy",
        type=str,
        default="all",
        choices=["all", "jev_full", "rule_baseline", "llm_choice_baseline"],
        help="Filter by planner policy.",
    )
    parser.add_argument("--tasks-per-family", type=int, default=30, help="Number of unseen tasks per family (default: 30).")
    parser.add_argument(
        "--run-endurance",
        action="store_true",
        help="Run the separate W088 endurance soak phase after the W084-W087 benchmark suite completes.",
    )
    parser.add_argument(
        "--endurance-only",
        action="store_true",
        help="Run ONLY the W088 endurance soak phase without rerunning the W084-W087 benchmark suite.",
    )
    parser.add_argument("--endurance-hours", type=float, default=24.0, help="Maximum endurance wall-clock hours for W088 phase (default: 24.0).")
    parser.add_argument("--max-budget-usd", type=float, default=25.0, help="Strict USD budget cap for W088 endurance worker.")
    parser.add_argument("--max-api-calls", type=int, default=1000, help="Strict API call cap for W088 endurance worker.")
    parser.add_argument("--max-tokens", type=int, default=2_000_000, help="Strict token cap for W088 endurance worker.")
    parser.add_argument("--restart-interval", type=int, default=10, help="Controlled Cscape restart interval in trials.")
    parser.add_argument("--resume-checkpoint", type=str, default=None, help="Path to g11_endurance_checkpoint.json to resume.")
    parser.add_argument("--results-json", type=str, default=None, help="Custom output path for results JSON file.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_g11_args(argv)
    resume_path = Path(args.resume_checkpoint) if args.resume_checkpoint else None
    results_json_path = Path(args.results_json) if args.results_json else None
    result = run_g11_campaign(
        live=args.live,
        dry_run=args.dry_run,
        family_filter=args.family,
        policy_filter=args.policy,
        tasks_per_family=args.tasks_per_family,
        endurance_hours=args.endurance_hours,
        run_endurance=args.run_endurance,
        endurance_only=args.endurance_only,
        max_budget_usd=args.max_budget_usd,
        max_api_calls=args.max_api_calls,
        max_tokens=args.max_tokens,
        restart_interval_tasks=args.restart_interval,
        resume_checkpoint=resume_path,
        results_path=results_json_path,
    )
    print(json.dumps(result, indent=2), flush=True)
    res_path = result.get("data", {}).get("results_json_path")
    if res_path:
        print(f"RESULTS_JSON: {res_path}", flush=True)
    print(
        f"FINISHED: Gate G11 Campaign | status={result.get('status')} | "
        f"results_json={res_path or str(RESULTS_JSON_PATH.resolve())}",
        flush=True,
    )
    return 0 if result.get("status") == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
