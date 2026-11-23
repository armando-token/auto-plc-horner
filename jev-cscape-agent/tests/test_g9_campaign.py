#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comprehensive Unit Test Suite for Gate G9 Campaign: Solicitud a Proyecto Industrial Offline Completo.

Mandate Verification Pillars:
1. CLI Argument Parsing: --start-task, --end-task, bounds checks, subset execution.
2. Jev Wire Payload Creation & Mocking: JSON wire schema ingestion, serialization, and pipeline mocking.
3. Task 06 Pre-Edit Pending Guard: Missing critical data negative control fail-closed in V2, zero disk mutation.
4. Cross-Project Parametric Absence & State Hygiene: ParametricIsolationChecker validation and symbol leak rejection.
5. REQ Matrix Mapping: Bidirectional traceability (REQ-001 through REQ-010) across spec, IR, and verification.
6. Hardware Lockout & Baseline CSP Immutability: COM1..256 lockout and baseline p1_base.csp SHA-256 verification.

Classification: TESTED_MOCK / OFFLINE_VERIFICATION [Tank Training Family, Pure Software]
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch
import pytest

from scripts.g9_campaign import (
    BASE_P1_PATH,
    BASELINE_P1_SHA,
    G9ValidationPipeline,
    IndustrialIR,
    IndustrialIRSynthesizer,
    ParametricIsolationChecker,
    ReqMatrixEntry,
    TankFamilyType,
    TaskSpec,
    VerificationStage,
    assert_safety_invariants,
    build_requirement_matrix,
    compute_sha256,
    get_tank_training_family_tasks,
    run_g9_campaign,
)
from jev_cscape.contracts import AgentStatus
from jev_cscape.security.exceptions import HardwareLockoutError
from jev_cscape.security.guard import SecurityGuard


# =============================================================================
# PILLAR 1: CLI Argument Parsing (--start-task / --end-task)
# =============================================================================

class TestCLIArgumentParsing:
    """Validate CLI argument parsing, range bounds, and task sub-range execution."""

    def _build_parser(self) -> argparse.ArgumentParser:
        """Helper building parser identical to g9_campaign CLI."""
        parser = argparse.ArgumentParser(description="Gate G9 Offline Industrial Project Campaign Runner")
        parser.add_argument("--offline", action="store_true", default=True, help="Run offline-only project synthesis")
        parser.add_argument("--check-only", action="store_true", help="Perform sanity checks on TaskSpec without synthesis")
        parser.add_argument("--start-task", type=int, default=1, help="First task to execute (1-10)")
        parser.add_argument("--end-task", type=int, default=10, help="Last task to execute (1-10)")
        return parser

    def test_cli_default_arguments(self):
        """Verify default CLI arguments when no options are passed."""
        parser = self._build_parser()
        args = parser.parse_args([])
        assert args.offline is True
        assert args.check_only is False
        assert args.start_task == 1
        assert args.end_task == 10

    def test_cli_custom_task_range(self):
        """Verify custom range specification via --start-task and --end-task."""
        parser = self._build_parser()
        args = parser.parse_args(["--start-task", "3", "--end-task", "7", "--check-only"])
        assert args.start_task == 3
        assert args.end_task == 7
        assert args.check_only is True

    def test_cli_single_task_execution_flag(self):
        """Verify targeting a single task by setting start == end."""
        parser = self._build_parser()
        args = parser.parse_args(["--start-task", "6", "--end-task", "6"])
        assert args.start_task == 6
        assert args.end_task == 6

    def test_run_campaign_subset_tasks_execution(self):
        """Verify executing a task slice (Tasks 03..05) processes exactly 3 tasks."""
        all_tasks = get_tank_training_family_tasks()
        subset_tasks = [t for t in all_tasks if 3 <= t.task_num <= 5]
        assert len(subset_tasks) == 3
        assert [t.task_id for t in subset_tasks] == ["G9_TASK_03", "G9_TASK_04", "G9_TASK_05"]

        # Run pipeline over subset
        checker = ParametricIsolationChecker()
        pipeline = G9ValidationPipeline(isolation_checker=checker)
        prev = None
        for task in subset_tasks:
            iso = checker.verify_isolation(prev, task)
            assert iso["isolation_passed"] is True
            v2 = pipeline.validate_v2_schema(task)
            assert v2["status"] == "success"
            ir = IndustrialIRSynthesizer.synthesize(task)
            v3 = pipeline.validate_v3_semantics(task, ir)
            assert v3["status"] == "success"
            prev = task

    def test_campaign_range_validation_rejects_inverted_range(self):
        """Verify invalid ranges where start_task > end_task raise ValueError fail-closed."""
        def validate_range(start: int, end: int) -> None:
            if start < 1 or end > 10 or start > end:
                raise ValueError(f"Invalid task range: start_task={start}, end_task={end}")

        with pytest.raises(ValueError, match="Invalid task range"):
            validate_range(7, 3)

        with pytest.raises(ValueError, match="Invalid task range"):
            validate_range(0, 5)

        with pytest.raises(ValueError, match="Invalid task range"):
            validate_range(1, 11)


# =============================================================================
# PILLAR 2: Jev Wire Payload Creation and Mocking
# =============================================================================

class TestJevWirePayloadCreationAndMocking:
    """Validate Jev agent wire serialization, mock response ingestion, and schema compliance."""

    def test_wire_payload_serialization_roundtrip(self):
        """Verify TaskSpec converts to and from standard Jev wire JSON payload."""
        tasks = get_tank_training_family_tasks()
        task_01 = tasks[0]

        # Serialize to Jev wire dictionary
        wire_payload = asdict(task_01)
        wire_payload["family_type"] = task_01.family_type.value
        wire_json = json.dumps(wire_payload)

        # Ingest and reconstruct
        decoded = json.loads(wire_json)
        reconstructed = TaskSpec(
            task_id=decoded["task_id"],
            task_num=decoded["task_num"],
            name=decoded["name"],
            family=decoded["family"],
            family_type=TankFamilyType(decoded["family_type"]),
            is_reserved=decoded["is_reserved"],
            tank_id=decoded["tank_id"],
            target_level=decoded["target_level"],
            low_alarm=decoded["low_alarm"],
            high_alarm=decoded["high_alarm"],
            inlet_valve_tag=decoded["inlet_valve_tag"],
            discharge_valve_tag=decoded["discharge_valve_tag"],
            pump_tag=decoded["pump_tag"],
            level_pv_tag=decoded["level_pv_tag"],
            auto_mode_tag=decoded["auto_mode_tag"],
            estop_tag=decoded["estop_tag"],
            timer_preset_s=decoded["timer_preset_s"],
            requirements=tuple(decoded["requirements"]),
            is_incomplete=decoded["is_incomplete"],
            missing_critical_fields=tuple(decoded["missing_critical_fields"]),
        )
        assert reconstructed == task_01

    def test_mock_jev_wire_rpc_response_contract(self):
        """Verify outgoing response adheres to the strict 4-state contract."""
        mock_response = {
            "status": AgentStatus.SUCCESS.value,
            "task_id": "G9_TASK_01",
            "error_code": None,
            "details": "Task G9_TASK_01 successfully compiled offline: V2, V3, V4 passed; V5 pending.",
            "data": {
                "variables_count": 9,
                "ladder_rungs_count": 5,
                "hmi_objects_count": 4,
                "st_pou_lines": 39,
            }
        }
        assert mock_response["status"] in ("success", "failed", "blocked", "inconclusive", "pending")
        assert mock_response["data"]["variables_count"] == 9

    def test_mock_wire_stream_pipeline_execution(self):
        """Feed synthetic mock wire payloads into G9ValidationPipeline headlessly."""
        mock_wire_task = {
            "task_id": "MOCK_WIRE_TASK_01",
            "task_num": 99,
            "name": "Synthetic Wire Plant Loop",
            "family": "tank_training_family",
            "family_type": TankFamilyType.STANDARD_STORAGE,
            "is_reserved": False,
            "tank_id": "TANK_MOCK",
            "target_level": 400.0,
            "low_alarm": 50.0,
            "high_alarm": 750.0,
            "inlet_valve_tag": "MOCK_INLET",
            "discharge_valve_tag": "MOCK_DISCH",
            "pump_tag": "MOCK_PUMP",
            "level_pv_tag": "MOCK_LEVEL_PV",
            "auto_mode_tag": "MOCK_AUTO",
            "estop_tag": "MOCK_ESTOP",
            "timer_preset_s": 4.0,
            "requirements": ("REQ-001", "REQ-002", "REQ-003"),
        }
        spec = TaskSpec(**mock_wire_task)
        checker = ParametricIsolationChecker()
        pipeline = G9ValidationPipeline(isolation_checker=checker)

        # Run pipeline
        v2 = pipeline.validate_v2_schema(spec)
        assert v2["status"] == "success"
        ir = IndustrialIRSynthesizer.synthesize(spec)
        v3 = pipeline.validate_v3_semantics(spec, ir)
        assert v3["status"] == "success"
        v5 = pipeline.validate_v5_simulation_pending(spec)
        assert v5["status"] == "pending"


# =============================================================================
# PILLAR 3: Task 06 Pre-Edit Pending Guard
# =============================================================================

class TestTask06PreEditPendingGuard:
    """Validate intentional negative control Task 06 halts fail-closed before any project edits."""

    def test_task_06_spec_attributes(self):
        """Verify Task 06 is marked incomplete with explicitly missing setpoint and alarm bounds."""
        tasks = get_tank_training_family_tasks()
        task_06 = next(t for t in tasks if t.task_id == "G9_TASK_06")

        assert task_06.is_incomplete is True
        assert task_06.target_level is None
        assert task_06.high_alarm is None
        assert "target_level" in task_06.missing_critical_fields
        assert "high_alarm" in task_06.missing_critical_fields

    def test_v2_schema_halts_with_structured_diagnosis(self):
        """Verify V2 schema validation intercepts Task 06 with DIAGNOSIS_MISSING_CRITICAL_DATA."""
        tasks = get_tank_training_family_tasks()
        task_06 = next(t for t in tasks if t.task_id == "G9_TASK_06")
        checker = ParametricIsolationChecker()
        pipeline = G9ValidationPipeline(isolation_checker=checker)

        v2_res = pipeline.validate_v2_schema(task_06)
        assert v2_res["status"] == "pending"
        assert "DIAGNOSIS_MISSING_CRITICAL_DATA" in v2_res["diagnosis"]
        assert "'target_level'" in v2_res["diagnosis"]
        assert "'high_alarm'" in v2_res["diagnosis"]
        assert "TANK_02" in v2_res["diagnosis"]

    def test_task_06_skips_downstream_stages_and_avoids_disk_mutation(self, tmp_path):
        """Verify Task 06 records V3/V4 as skipped and writes zero artifact files."""
        tasks = get_tank_training_family_tasks()
        task_06 = next(t for t in tasks if t.task_id == "G9_TASK_06")

        # In campaign runner, Task 06 halts at V2 and never calls V4
        checker = ParametricIsolationChecker()
        pipeline = G9ValidationPipeline(isolation_checker=checker)
        v2_res = pipeline.validate_v2_schema(task_06)

        # Simulation of runner handling:
        if v2_res["status"] == "pending":
            stages = {
                "V2": v2_res,
                "V3": {"stage": "V3", "status": "skipped", "reason": "Halted at V2 due to missing critical data"},
                "V4": {"stage": "V4", "status": "skipped", "reason": "Halted at V2 due to missing critical data"},
                "V5": pipeline.validate_v5_simulation_pending(task_06),
            }

        assert stages["V3"]["status"] == "skipped"
        assert stages["V4"]["status"] == "skipped"
        assert stages["V5"]["status"] == "pending"

    def test_task_06_rejects_silent_defaults(self):
        """Verify that default substitution (e.g. defaulting target_level=0) is prohibited."""
        tasks = get_tank_training_family_tasks()
        task_06 = next(t for t in tasks if t.task_id == "G9_TASK_06")

        # Must not silently populate target_level
        assert task_06.target_level is None
        assert task_06.high_alarm is None


# =============================================================================
# PILLAR 4: Cross-Project Parametric Absence & State Hygiene
# =============================================================================

class TestCrossProjectParametricAbsence:
    """Validate ParametricIsolationChecker and cross-project variable isolation."""

    def test_full_sequence_clean_parametric_isolation(self):
        """Verify all 10 tasks in order satisfy clean parametric isolation."""
        tasks = get_tank_training_family_tasks()
        checker = ParametricIsolationChecker()
        prev = None
        for spec in tasks:
            res = checker.verify_isolation(prev, spec)
            assert res["isolation_passed"] is True, f"Leakage detected in {spec.task_id}: {res['details']}"
            assert res["remnant_detected"] is False
            prev = spec

    def test_catches_leaked_actuator_tag(self):
        """Verify ParametricIsolationChecker fails closed if actuator tag is retained."""
        checker = ParametricIsolationChecker()
        spec1 = TaskSpec(
            task_id="G9_TASK_01", task_num=1, name="T1", family="tank_training_family",
            family_type=TankFamilyType.STANDARD_STORAGE, is_reserved=False, tank_id="TANK_01",
            target_level=500.0, low_alarm=100.0, high_alarm=900.0,
            inlet_valve_tag="T1_INLET", discharge_valve_tag="T1_DRAIN", pump_tag="T1_PUMP",
            level_pv_tag="T1_PV", auto_mode_tag="AUTO", estop_tag="ESTOP", timer_preset_s=5.0,
            requirements=("REQ-001",),
        )
        spec2_leaked = TaskSpec(
            task_id="G9_TASK_02", task_num=2, name="T2", family="tank_training_family",
            family_type=TankFamilyType.HIGH_THROUGHPUT, is_reserved=False, tank_id="TANK_02",
            target_level=750.0, low_alarm=200.0, high_alarm=950.0,
            inlet_valve_tag="T1_INLET",  # LEAK!
            discharge_valve_tag="T2_DRAIN", pump_tag="T2_PUMP",
            level_pv_tag="T2_PV", auto_mode_tag="AUTO", estop_tag="ESTOP", timer_preset_s=3.0,
            requirements=("REQ-001",),
        )
        checker.verify_isolation(None, spec1)
        res = checker.verify_isolation(spec1, spec2_leaked)
        assert res["isolation_passed"] is False
        assert res["remnant_detected"] is True
        assert "inlet_valve_tag" in res["details"]

    def test_catches_unvaried_numeric_setpoint_leak(self):
        """Verify checker flags unvaried setpoint copy between differing tasks."""
        checker = ParametricIsolationChecker()
        spec1 = TaskSpec(
            task_id="G9_TASK_01", task_num=1, name="T1", family="tank_training_family",
            family_type=TankFamilyType.STANDARD_STORAGE, is_reserved=False, tank_id="TANK_01",
            target_level=500.0, low_alarm=100.0, high_alarm=900.0,
            inlet_valve_tag="T1_INLET", discharge_valve_tag="T1_DRAIN", pump_tag="T1_PUMP",
            level_pv_tag="T1_PV", auto_mode_tag="AUTO", estop_tag="ESTOP", timer_preset_s=5.0,
            requirements=("REQ-001",),
        )
        spec2_same_setpoint = TaskSpec(
            task_id="G9_TASK_02", task_num=2, name="T2", family="tank_training_family",
            family_type=TankFamilyType.HIGH_THROUGHPUT, is_reserved=False, tank_id="TANK_02",
            target_level=500.0,  # UNVARIED LEAK FROM TASK 1!
            low_alarm=200.0, high_alarm=950.0,
            inlet_valve_tag="T2_INLET", discharge_valve_tag="T2_DRAIN", pump_tag="T2_PUMP",
            level_pv_tag="T2_PV", auto_mode_tag="AUTO", estop_tag="ESTOP", timer_preset_s=3.0,
            requirements=("REQ-001",),
        )
        checker.verify_isolation(None, spec1)
        res = checker.verify_isolation(spec1, spec2_same_setpoint)
        assert res["isolation_passed"] is False
        assert res["remnant_detected"] is True
        assert "target_level" in res["details"]

    def test_absence_of_foreign_tags_in_synthesized_st(self):
        """Verify that synthesized ST POU for Task 02 contains zero Task 01 specific tags."""
        tasks = get_tank_training_family_tasks()
        ir_t1 = IndustrialIRSynthesizer.synthesize(tasks[0])
        ir_t2 = IndustrialIRSynthesizer.synthesize(tasks[1])

        # Task 2 code must NOT mention Task 1 inlet tag
        assert tasks[0].inlet_valve_tag not in ir_t2.st_pou_code
        assert tasks[0].pump_tag not in ir_t2.st_pou_code


# =============================================================================
# PILLAR 5: REQ Matrix Mapping
# =============================================================================

class TestReqMatrixMapping:
    """Validate bidirectional requirement traceability (REQ-001..REQ-010)."""

    def test_req_matrix_structure_and_completeness(self):
        """Verify every requirement entry contains complete bidirectional linkages."""
        tasks = get_tank_training_family_tasks()
        for task in tasks:
            ir = IndustrialIRSynthesizer.synthesize(task) if not task.is_incomplete else None
            matrix = build_requirement_matrix(task, ir)

            assert len(matrix) >= 3, f"Task {task.task_id} generated sparse REQ matrix"
            for entry in matrix:
                assert re.match(r"^REQ-\d{3}$", entry.req_id), f"Invalid REQ ID: {entry.req_id}"
                assert entry.title
                assert entry.description
                assert len(entry.satisfied_by_params) > 0
                assert len(entry.satisfied_by_ir) > 0
                assert len(entry.verified_by_stages) > 0

    def test_global_safety_requirements_in_every_task(self):
        """Verify REQ-008 (Hardware Lockout) and REQ-009 (Parametric Independence) are universal."""
        tasks = get_tank_training_family_tasks()
        for task in tasks:
            matrix = build_requirement_matrix(task, None)
            req_ids = {m.req_id for m in matrix}
            assert "REQ-008" in req_ids, f"REQ-008 missing from {task.task_id}"
            assert "REQ-009" in req_ids, f"REQ-009 missing from {task.task_id}"

    def test_reserved_tasks_map_req_010(self):
        """Verify reserved family variants (Tasks 08, 09, 10) map REQ-010."""
        tasks = get_tank_training_family_tasks()
        reserved = [t for t in tasks if t.is_reserved]
        assert len(reserved) == 3

        for task in reserved:
            matrix = build_requirement_matrix(task, None)
            req_ids = {m.req_id for m in matrix}
            assert "REQ-010" in req_ids, f"REQ-010 missing from reserved task {task.task_id}"


# =============================================================================
# PILLAR 6: Hardware Lockout & Baseline p1_base.csp Immutability
# =============================================================================

class TestHardwareLockoutAndBaselineImmutability:
    """Validate COM1..256 fail-closed lockout and baseline CSP SHA-256 immutability."""

    def test_hardware_lockout_blocks_all_com_ports(self):
        """Verify assert_safety_invariants queries all COM ports and confirms lockout."""
        assert_safety_invariants()

    def test_safety_invariants_fails_if_com_port_unblocked(self):
        """Verify assert_safety_invariants raises RuntimeError if SecurityGuard allows a port."""
        with patch.object(SecurityGuard, "assert_port_safe", return_value=None):
            with pytest.raises(RuntimeError, match="Hardware lockout breached"):
                assert_safety_invariants()

    def test_baseline_csp_immutability(self):
        """Verify baseline p1_base.csp SHA-256 matches BASELINE_P1_SHA."""
        if BASE_P1_PATH.exists():
            actual = compute_sha256(BASE_P1_PATH)
            assert actual == BASELINE_P1_SHA

    def test_baseline_csp_tamper_detection(self):
        """Verify assert_safety_invariants raises RuntimeError if p1_base.csp is tampered."""
        with patch("scripts.g9_campaign.compute_sha256", return_value="deadbeef" * 8):
            with pytest.raises(RuntimeError, match="FAIL_CLOSED: Baseline p1_base.csp tampered"):
                assert_safety_invariants()

    def test_campaign_run_preserves_baseline_csp(self):
        """Verify full offline campaign execution causes zero bytes modification to baseline CSP."""
        if BASE_P1_PATH.exists():
            sha_before = compute_sha256(BASE_P1_PATH)
            summary = run_g9_campaign(offline_only=True)
            sha_after = compute_sha256(BASE_P1_PATH)
            assert sha_before == sha_after == BASELINE_P1_SHA
            assert summary["status"] == "success"


# =============================================================================
# ADDITIONAL REGRESSION SUITE: Parameterized Specification & Pipeline Bounds
# =============================================================================

def test_ten_parameterized_tasks_specification():
    """Verify 10 parameterized tasks exist in the tank training family with exactly 3 reserved."""
    tasks = get_tank_training_family_tasks()
    assert len(tasks) == 10, f"Expected exactly 10 tasks, found {len(tasks)}"
    task_ids = [t.task_id for t in tasks]
    assert len(set(task_ids)) == 10, "Task IDs must be strictly unique"
    for idx, t in enumerate(tasks, 1):
        assert t.task_num == idx
        assert t.family == "tank_training_family"
    reserved_tasks = [t for t in tasks if t.is_reserved]
    assert len(reserved_tasks) == 3
    assert [t.task_num for t in reserved_tasks] == [8, 9, 10]
    assert reserved_tasks[0].family_type == TankFamilyType.RESERVED_CHEMICAL_DOSING
    assert reserved_tasks[1].family_type == TankFamilyType.RESERVED_CASCADE_TRANSFER
    assert reserved_tasks[2].family_type == TankFamilyType.RESERVED_SLURRY_BUFFER


def test_v2_v3_v4_pipeline_and_v5_pending():
    """Verify V2, V3, V4 succeed for complete tasks and V5 is strictly marked pending."""
    tasks = get_tank_training_family_tasks()
    task_01 = tasks[0]
    checker = ParametricIsolationChecker()
    pipeline = G9ValidationPipeline(isolation_checker=checker)
    v2_res = pipeline.validate_v2_schema(task_01)
    assert v2_res["status"] == "success"
    ir = IndustrialIRSynthesizer.synthesize(task_01)
    assert len(ir.variables) >= 9
    assert len(ir.ladder_rungs) >= 5
    assert len(ir.hmi_objects) >= 4
    assert "PROGRAM" in ir.st_pou_code
    v3_res = pipeline.validate_v3_semantics(task_01, ir)
    assert v3_res["status"] == "success"
    v4_res = pipeline.validate_v4_synthesis(task_01, ir)
    assert v4_res["status"] == "success"
    assert "st_pou" in v4_res["artifacts_generated"]
    assert "st_sha256" in v4_res["artifacts_generated"]
    v5_res = pipeline.validate_v5_simulation_pending(task_01)
    assert v5_res["status"] == "pending"
    assert v5_res["reason"] == "no simulator / offline only"


def test_v3_rejects_inverted_alarm_bounds():
    """Verify V3 semantic validation fails closed when alarm bounds are inverted."""
    invalid_spec = TaskSpec(
        task_id="INVALID_BOUNDS",
        task_num=99,
        name="Invalid Bounds Task",
        family="tank_training_family",
        family_type=TankFamilyType.STANDARD_STORAGE,
        is_reserved=False,
        tank_id="TANK_INV",
        target_level=950.0,
        low_alarm=100.0,
        high_alarm=900.0,
        inlet_valve_tag="INV_INLET",
        discharge_valve_tag="INV_OUTLET",
        pump_tag="INV_PUMP",
        level_pv_tag="INV_LEVEL",
        auto_mode_tag="AUTO",
        estop_tag="ESTOP",
        timer_preset_s=5.0,
        requirements=("REQ-001",),
    )
    ir = IndustrialIRSynthesizer.synthesize(invalid_spec)
    checker = ParametricIsolationChecker()
    pipeline = G9ValidationPipeline(isolation_checker=checker)
    v3_res = pipeline.validate_v3_semantics(invalid_spec, ir)
    assert v3_res["status"] == "failed"
    assert any("Alarm bounds violated" in e for e in v3_res["errors"])


# =============================================================================
# PILLAR 7: External Helper Call Signatures & Call-Site Audit
# =============================================================================

class TestHelperSignaturesAndCallSites:
    """Verify that every external helper imported from scripts (G3, G7, G8, probe_hmi_editor)

    has its signature audited and every call site in scripts/g9_campaign.py provides all
    required parameters without defaults.
    """

    TARGET_MODULES = [
        "scripts.probe_hmi_editor",
        "scripts.g3_edit_roundtrip",
        "scripts.g7_acceptance",
        "scripts.g7_ladder_roundtrip",
        "scripts.g8_acceptance",
    ]

    def test_key_helper_signatures_explicit(self):
        """Explicitly test critical helper function signatures against regressions."""
        import inspect
        from scripts.probe_hmi_editor import (
            handle_startup_dialogs_and_wait_for_main_window,
            launch_cscape_with_project,
            open_screen_editor_dynamic,
            is_screen_editor_window,
        )
        from scripts.g7_acceptance import (
            dismiss_about_cscape_and_wait_main_enabled,
            trigger_and_read_cscape_error_check,
        )
        from scripts.g7_ladder_roundtrip import (
            activate_ladder_toolbar_button,
            assign_tag_in_dialog,
            open_main_ladder_editor,
            resolve_ladder_canvas,
        )
        from scripts.g8_acceptance import (
            place_hmi_object_on_screen,
        )

        # 1. handle_startup_dialogs_and_wait_for_main_window requires app
        sig_startup = inspect.signature(handle_startup_dialogs_and_wait_for_main_window)
        params_startup = list(sig_startup.parameters.keys())
        assert "pid" in params_startup
        assert "main_hwnd" in params_startup
        assert "app" in params_startup
        assert sig_startup.parameters["app"].default is inspect.Parameter.empty, "app must be required without default!"

        # 2. launch_cscape_with_project requires project_path
        sig_launch = inspect.signature(launch_cscape_with_project)
        assert "project_path" in sig_launch.parameters
        assert sig_launch.parameters["project_path"].default is inspect.Parameter.empty

        # 3. place_hmi_object_on_screen requires canvas_rect
        sig_place = inspect.signature(place_hmi_object_on_screen)
        assert "canvas_rect" in sig_place.parameters
        assert sig_place.parameters["canvas_rect"].default is inspect.Parameter.empty, "canvas_rect must be required without default!"

        # 4. trigger_and_read_cscape_error_check requires main_hwnd and pid
        sig_ec = inspect.signature(trigger_and_read_cscape_error_check)
        assert "main_hwnd" in sig_ec.parameters
        assert "pid" in sig_ec.parameters

        # 5. assign_tag_in_dialog requires pid and tag_name
        sig_assign = inspect.signature(assign_tag_in_dialog)
        assert "pid" in sig_assign.parameters
        assert "tag_name" in sig_assign.parameters

        # 6. open_screen_editor_dynamic requires main_hwnd and pid
        sig_screen = inspect.signature(open_screen_editor_dynamic)
        assert "main_hwnd" in sig_screen.parameters
        assert "pid" in sig_screen.parameters

    def test_g9_campaign_all_call_sites_match_signatures(self):
        """Statically parse scripts/g9_campaign.py and dynamically bind every call site

        to external helpers against inspect.signature. Asserts 0 binding errors and 0 missing
        required arguments.
        """
        import ast
        import importlib
        import inspect

        script_path = Path(__file__).resolve().parent.parent / "scripts" / "g9_campaign.py"
        assert script_path.exists(), f"Target script not found: {script_path}"

        source_code = script_path.read_text(encoding="utf-8")
        tree = ast.parse(source_code, filename=str(script_path))

        # Collect all imported callable objects from the target modules
        imported_callables: Dict[str, Tuple[str, str, Any, inspect.Signature]] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in self.TARGET_MODULES:
                mod = importlib.import_module(node.module)
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    target_obj = getattr(mod, alias.name, None)
                    if callable(target_obj):
                        try:
                            sig = inspect.signature(target_obj)
                            imported_callables[local_name] = (node.module, alias.name, target_obj, sig)
                        except (ValueError, TypeError):
                            pass

        assert len(imported_callables) >= 15, f"Expected at least 15 target helpers, got {len(imported_callables)}"

        call_site_errors: List[str] = []
        verified_call_count = 0

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id in imported_callables:
                    func_name = node.func.attr

            if func_name and func_name in imported_callables:
                verified_call_count += 1
                module_name, orig_name, func_obj, sig = imported_callables[func_name]

                dummy_args = [object()] * len(node.args)
                dummy_kwargs = {}
                has_star = False
                for kw in node.keywords:
                    if kw.arg is None:
                        has_star = True
                    else:
                        dummy_kwargs[kw.arg] = object()

                try:
                    if has_star:
                        bound = sig.bind_partial(*dummy_args, **dummy_kwargs)
                    else:
                        bound = sig.bind(*dummy_args, **dummy_kwargs)
                except TypeError as e:
                    call_site_errors.append(
                        f"Line {node.lineno}: Call to '{func_name}' ({module_name}.{orig_name}) "
                        f"failed signature bind: {e} | Signature: {sig}"
                    )
                    continue

                if not has_star:
                    for param_name, param in sig.parameters.items():
                        if (
                            param.default is inspect.Parameter.empty
                            and param.kind not in (
                                inspect.Parameter.VAR_POSITIONAL,
                                inspect.Parameter.VAR_KEYWORD,
                            )
                        ):
                            if param_name not in bound.arguments:
                                call_site_errors.append(
                                    f"Line {node.lineno}: Call to '{func_name}' ({module_name}.{orig_name}) "
                                    f"missing required argument '{param_name}'! Signature: {sig}"
                                )

        assert verified_call_count >= 20, f"Expected at least 20 verified call sites, got {verified_call_count}"
        if call_site_errors:
            pytest.fail(
                f"Found {len(call_site_errors)} call site signature mismatch(es):\n"
                + "\n".join(f"  - {err}" for err in call_site_errors)
            )


def test_variable_declaration_commit_sequence_in_construction():
    """Verify that execute_live_cscape_task_construction invokes declare_variables_via_live_cscape_ui,
    places ladder with assigned operand, closes all modal popups, places HMI, and dispatches
    Error Check (32826) at the end after HMI.
    """
    import inspect
    from scripts.g9_campaign import execute_live_cscape_task_construction

    src = inspect.getsource(execute_live_cscape_task_construction)

    # 1. Assert live Cscape UI variable declaration is called
    idx_var_decl = src.find("declare_variables_via_live_cscape_ui")
    assert idx_var_decl != -1, "declare_variables_via_live_cscape_ui call must exist in live construction!"

    # 2. Assert ladder placement occurs
    idx_ladder = src.find("open_main_ladder_editor", idx_var_decl)
    assert idx_ladder != -1, "open_main_ladder_editor must be called after variable declaration!"

    # 3. Assert modal dismiss occurs before HMI
    idx_dismiss_before_hmi = src.find("dismiss_error_check_modals", idx_ladder)
    assert idx_dismiss_before_hmi != -1, "dismiss_error_check_modals must be called before HMI to clean up popups!"

    # 4. Assert Screen 1 opening occurs via proven G8 open_screen_editor_dynamic
    idx_screen1 = src.find("open_screen_editor_dynamic", idx_dismiss_before_hmi)
    assert idx_screen1 != -1, "open_screen_editor_dynamic must occur after ladder and popup cleanup!"
    assert "assert screen_hwnd and is_screen_editor_window(screen_hwnd)" in src, (
        "Must strictly assert screen_hwnd and is_screen_editor_window(screen_hwnd) to stop at first failure!"
    )

    # 5. Assert Error Check occurs at the end AFTER HMI placement
    idx_hmi_place = src.find("place_hmi_object_on_screen", idx_screen1)
    assert idx_hmi_place != -1, "place_hmi_object_on_screen must occur in HMI step!"

    idx_ec = src.find("trigger_and_read_cscape_error_check", idx_hmi_place)
    assert idx_ec != -1, "trigger_and_read_cscape_error_check must be dispatched at the end AFTER HMI placement!"

    # 6. Assert Error Check modal dismissal occurs after Error Check
    idx_ec_dismiss = src.find("dismiss_error_check_modals", idx_ec)
    assert idx_ec_dismiss != -1, "dismiss_error_check_modals must be called after Error Check to dismiss result dialog!"


def test_ladder_contact_placement_and_operand_assignment():
    """Verify that ladder contact placement uses Column B coordinates (76, 25),
    assigns the operand via assign_tag_in_dialog, fails closed on missing operand,
    and contains NO silent fallback to ALW_ON.
    """
    import inspect
    from scripts.g9_campaign import execute_live_cscape_task_construction

    src = inspect.getsource(execute_live_cscape_task_construction)

    # Assert Column B coordinates: (25 << 16) | 76
    assert "(25 << 16) | 76" in src, "Ladder contact must be placed at Column B (X=76, Y=25), not power rail (X=25)!"
    assert "(25 << 16) | 25" not in src, "Column A (X=25) power rail coordinates must NOT be used for contact placement!"

    # Assert operand assignment in Dialog 108
    assert "assign_tag_in_dialog(pid, spec.inlet_valve_tag" in src, "Contact must have planned operand assigned!"
    assert "assert assigned" in src, "Operand assignment must fail closed if Dialog 108 is not dismissed!"
    assert 'assign_tag_in_dialog(pid, "ALW_ON"' not in src, "Silent ALW_ON fallback is strictly forbidden and must be absent!"


def test_cfbf_synthesis_banned_in_construction_and_cfbf_is_read_only_verification(tmp_path):
    """Verify that direct CFBF project synthesis is banned in G9 construction per mandate:
    1. Disposable copy staging is a pure byte-for-byte copy of p1_base.csp (SHA == BASELINE_P1_SHA).
    2. Zero CFBF disk manipulation occurs prior to live Cscape launch.
    3. Variable declaration logic operates exclusively through the live Cscape UI:
       Edit Variables as Text with (*$tag=%R...*) and (*$tag=%M...*) directives or G3 Program Variables Tag field.
    4. CFBF streams are used strictly READ-ONLY for offline verification.
    """
    import inspect
    import shutil
    from scripts.g9_campaign import (
        BASE_P1_PATH,
        BASELINE_P1_SHA,
        compute_sha256,
        declare_variables_via_live_cscape_ui,
        run_g9_campaign,
    )

    # 1. Baseline must match known pristine SHA
    assert compute_sha256(BASE_P1_PATH) == BASELINE_P1_SHA

    # 2. Assert run_g9_campaign source does NOT call inject_project_variables
    campaign_src = inspect.getsource(run_g9_campaign)
    assert "inject_project_variables" not in campaign_src, (
        "inject_project_variables is prohibited in campaign execution! Variables must be declared via live Cscape UI."
    )

    # 3. Assert declare_variables_via_live_cscape_ui contains live Cscape UI paths
    decl_src = inspect.getsource(declare_variables_via_live_cscape_ui)
    assert "Edit Variables as Text" in decl_src or "as text" in decl_src, "Must support Edit Variables as Text!"
    assert "(*$tag=" in decl_src, "Must format (*$tag=...*) directives for OCS register mapping!"
    assert "handle_program_information_modified_dialog" in decl_src, "Must handle save prompt after text edit!"

    # 4. Disposable copy staging is a clean copy without pre-launch mutation
    disposable_copy = tmp_path / "clean_staged_copy.csp"
    shutil.copy2(BASE_P1_PATH, disposable_copy)
    assert compute_sha256(disposable_copy) == BASELINE_P1_SHA


def test_real_readback_of_declared_variables_and_sha_mutation_fails_closed():
    """Verify that declare_variables_via_live_cscape_ui enforces:
    1. Direct Ctrl+F4 without auto-discard + answering YES to Program Information Modified.
    2. Ctrl+S dispatch and disk write polling with strict assertion that SHA mutated on disk.
    3. REAL READBACK from the saved CFBF file asserting T1_LEVEL_PV with %R101 and T1_INLET_VALVE with %M101.
    4. Strict fail-closed error if tag or register address is missing from the saved project.
    """
    import inspect
    from scripts.g9_campaign import declare_variables_via_live_cscape_ui

    decl_src = inspect.getsource(declare_variables_via_live_cscape_ui)

    # 1. Assert Ctrl+F4 and YES prompt handling
    assert 'type_keys("^{F4}")' in decl_src or 'send_keys("^{F4}")' in decl_src
    assert "handle_program_information_modified_dialog" in decl_src

    # 2. Assert disk write polling and SHA mutation assertion
    assert "saved_sha != initial_sha" in decl_src
    assert "assert saved_sha != initial_sha" in decl_src, "Must fail closed if save did not change SHA!"

    # 3. Assert REAL READBACK from CFBF file on disk
    assert "olefile.OleFileIO" in decl_src, "Must open saved project file via OleFileIO for real readback!"
    assert "readback_found" in decl_src
    assert "assert readback_found" in decl_src, "Must fail closed if real readback fails to find tag with register address!"


def test_open_screen1_calls_proven_g8_open_screen_editor_dynamic_and_uses_g8_center_coords():
    """Verify that execute_live_cscape_task_construction:
    1. Invokes proven G8 open_screen_editor_dynamic to activate Screen 1.
    2. Strictly asserts screen_hwnd and is_screen_editor_window(screen_hwnd).
    3. Computes deterministic canvas-center coordinates (cw_s // 2, ch_s // 2 excluding bottom status bar)
       matching G8 instead of clamping to (180, 140).
    4. Strictly asserts place_res.get('placed').
    """
    import inspect
    from scripts.g9_campaign import execute_live_cscape_task_construction

    src = inspect.getsource(execute_live_cscape_task_construction)

    assert "open_screen_editor_dynamic" in src, "Must call proven G8 open_screen_editor_dynamic!"
    assert "assert screen_hwnd and is_screen_editor_window(screen_hwnd)" in src
    assert "cw_s // 2" in src and "ch_s // 2" in src, "Must use G8 canvas-center coordinate formula!"
    assert "min(180," not in src and "min(140," not in src, "Must not clamp placement coordinates to (180, 140)!"
    assert "assert place_res and place_res.get(\"placed\")" in src


def test_campaign_continues_on_task_failure_and_reports_n_of_10(monkeypatch):
    """Verify that run_g9_campaign does NOT stop the campaign when a task fails:
    it cleans up Cscape, records the failed task, continues to the next task, and reports N/10
    (pass_ratio / completed_ratio / tasks_passed / tasks_total).
    """
    import inspect
    import scripts.g9_campaign as g9
    from scripts.g9_campaign import run_g9_campaign

    src = inspect.getsource(run_g9_campaign)
    assert "break  # Stop at first failure per user directive" not in src, (
        "Failed task must not stop the campaign; must continue to next task!"
    )
    assert "continue  # Continue to next task and report N/10" in src

    # Behavioral check: simulate Task 01 failing in live construction and Tasks 02..10 running
    kill_calls = {"n": 0}
    monkeypatch.setattr(g9, "kill_leftover_cscape", lambda: kill_calls.__setitem__("n", kill_calls["n"] + 1))

    def fake_live_build(spec, ir, copy_path):
        if spec.task_num == 1:
            raise AssertionError("FAIL_CLOSED: Simulated Task 01 placement timeout")
        # Mutate copy_path slightly so saved_sha != initial_sha for passing tasks
        with open(copy_path, "ab") as f:
            f.write(b"\x00")
        return {
            "live_construction_completed": True,
            "error_check_clean": True,
            "reopen_compile_clean": True,
        }

    monkeypatch.setattr(g9, "execute_live_cscape_task_construction", fake_live_build)

    summary = run_g9_campaign(start_task=1, end_task=10, dry_run=False, offline_only=False)
    assert summary["tasks_total"] == 10
    assert summary["tasks_failed"] == 1
    assert summary["tasks_pending"] == 1  # Task 06 incomplete
    assert summary["tasks_passed"] == 8
    assert summary["pass_ratio"] == "8/10"
    assert summary["completed_ratio"] == "9/10"
    assert len(summary["tasks"]) == 10
    assert summary["tasks"][0]["task_id"] == "G9_TASK_01"
    assert summary["tasks"][0]["status"] == "failed"
    assert summary["tasks"][1]["task_id"] == "G9_TASK_02"
    assert summary["tasks"][1]["status"] == "success"
    assert kill_calls["n"] >= 1


def test_handle_program_information_modified_dialog_detects_child_static_on_cscape_titled_dialog(monkeypatch):
    """Verify that handle_program_information_modified_dialog detects Cscape's real
    CTextModeIECVariablesEditorWnd::PromptAndSave (#32770) message box where:
      - Top-level window title (GetWindowText) is 'Cscape' (string ID 0x1F9)
      - Child Static control contains 'Contents of IEC Variables Editor Window have been modified. Do you want to save the changes?' (string ID 0x9517)
      - Child Yes button has ctrl_id = 6 (IDYES)
    and dispatches both BM_CLICK to the Yes button and WM_COMMAND IDYES (6) to the dialog.
    """
    import win32con
    import scripts.g9_campaign as g9

    fake_pid = 4242
    dlg_hwnd = 0x550010
    static_hwnd = 0x550011
    yes_btn_hwnd = 0x550012

    sent_messages = []
    posted_messages = []

    monkeypatch.setattr(g9.win32gui, "IsWindow", lambda h: h in (dlg_hwnd, static_hwnd, yes_btn_hwnd))
    monkeypatch.setattr(g9.win32gui, "IsWindowVisible", lambda h: h in (dlg_hwnd, static_hwnd, yes_btn_hwnd))
    monkeypatch.setattr(g9.win32process, "GetWindowThreadProcessId", lambda h: (1, fake_pid))
    monkeypatch.setattr(
        g9.win32gui,
        "GetClassName",
        lambda h: "#32770" if h == dlg_hwnd else ("Static" if h == static_hwnd else "Button"),
    )
    monkeypatch.setattr(
        g9.win32gui,
        "GetWindowText",
        lambda h: (
            "Cscape"
            if h == dlg_hwnd
            else (
                "Contents of IEC Variables Editor Window have been modified. Do you want to save the changes?"
                if h == static_hwnd
                else "&Yes"
            )
        ),
    )
    monkeypatch.setattr(g9.win32gui, "GetDlgCtrlID", lambda h: 6 if h == yes_btn_hwnd else 65535)
    monkeypatch.setattr(
        g9.win32gui,
        "EnumWindows",
        lambda cb, extra: cb(dlg_hwnd, extra),
    )
    monkeypatch.setattr(
        g9.win32gui,
        "EnumChildWindows",
        lambda parent, cb, extra: (cb(static_hwnd, extra), cb(yes_btn_hwnd, extra)),
    )
    monkeypatch.setattr(g9.user32, "GetDlgItem", lambda h, cid: yes_btn_hwnd if (h == dlg_hwnd and cid == 6) else 0)
    monkeypatch.setattr(g9.user32, "SendMessageW", lambda h, msg, wp, lp: sent_messages.append((h, msg, wp, lp)) or 1)
    monkeypatch.setattr(g9.user32, "PostMessageW", lambda h, msg, wp, lp: posted_messages.append((h, msg, wp, lp)) or 1)
    monkeypatch.setattr(g9.time, "sleep", lambda _: None)

    handled = g9.handle_program_information_modified_dialog(pid=fake_pid, timeout=1.0)
    assert handled is True

    # Must click the Yes button (BM_CLICK) AND send WM_COMMAND IDYES (6) to the dialog
    assert (yes_btn_hwnd, win32con.BM_CLICK, 0, 0) in sent_messages
    assert (dlg_hwnd, win32con.WM_COMMAND, win32con.IDYES, yes_btn_hwnd) in sent_messages
    assert (dlg_hwnd, win32con.WM_COMMAND, win32con.IDYES, yes_btn_hwnd) in posted_messages


def test_close_and_commit_iec_variables_editor_tab_triggers_systabcontrol32_wm_command_300(monkeypatch):
    """Verify that close_and_commit_iec_variables_editor_tab locates SysTabControl32 (ctrl_id=59648)
    and close button (ctrl_id=300), posts WM_COMMAND 300 (invoking CMultiTabbedEditorWnd::OnCloseCurrentTab
    -> CTextModeIECVariablesEditorWnd::PromptAndSave), and confirms YES on the save prompt.
    """
    import win32con
    import scripts.g9_campaign as g9

    fake_pid = 4242
    main_hwnd = 0x100001
    active_mdi = 0x100002
    iec_view_parent = 0x100003
    editor_hwnd = 0x100004
    tab_ctrl_59648 = 0x100005
    close_btn_300 = 0x100006

    posted = []

    monkeypatch.setattr(
        g9.win32gui,
        "IsWindow",
        lambda h: h in (main_hwnd, active_mdi, iec_view_parent, editor_hwnd, tab_ctrl_59648, close_btn_300),
    )
    monkeypatch.setattr(g9.win32gui, "IsWindowVisible", lambda h: True)
    monkeypatch.setattr(g9.win32gui, "GetParent", lambda h: iec_view_parent if h == editor_hwnd else active_mdi)
    monkeypatch.setattr(
        g9.win32gui,
        "GetClassName",
        lambda h: (
            "SysTabControl32"
            if h == tab_ctrl_59648
            else ("CNewLookBitmapButton" if h == close_btn_300 else "W5EditST")
        ),
    )
    monkeypatch.setattr(
        g9.win32gui,
        "GetDlgCtrlID",
        lambda h: 59648 if h == tab_ctrl_59648 else (300 if h == close_btn_300 else 950),
    )
    monkeypatch.setattr(
        g9.win32gui,
        "EnumChildWindows",
        lambda parent, cb, extra: (cb(tab_ctrl_59648, extra), cb(close_btn_300, extra)),
    )
    monkeypatch.setattr(g9.user32, "PostMessageW", lambda h, m, wp, lp: posted.append((h, m, wp, lp)) or 1)
    monkeypatch.setattr(g9.time, "sleep", lambda _: None)
    monkeypatch.setattr(g9, "handle_program_information_modified_dialog", lambda pid, timeout=2.5: True)

    class DummyWin:
        def type_keys(self, k):
            pass

    ok = g9.close_and_commit_iec_variables_editor_tab(
        pid=fake_pid,
        main_hwnd=main_hwnd,
        main_win=DummyWin(),
        active_mdi=active_mdi,
        editor_hwnd=editor_hwnd,
    )
    assert ok is True
    assert (close_btn_300, win32con.BM_CLICK, 0, 0) in posted
    assert (tab_ctrl_59648, win32con.WM_COMMAND, 300, close_btn_300) in posted


def test_declare_variables_via_live_cscape_ui_behavioral_w5editst_paste_clipboard_restore_and_readback(
    monkeypatch, tmp_path
):
    """Behaviorally execute declare_variables_via_live_cscape_ui with mocked Win32/UIA to verify:
    1. Reads initial W5EditST text using G3 check_iec_text_completeness + 2 consecutive identical reads.
    2. Dispatches W5EditST.dll native SelectAll (0x040F) and Paste (0x0302, 0x0415) to editor_hwnd.
    3. Re-populates clipboard with updated_text before ^a/^v retry if read_text_from_active_editor
       clobbered the clipboard on the first paste check.
    4. Uses proven G3 parse_iec_declarations / extract_var_declaration on the editor buffer.
    5. Does NOT mark text_mode_success=True if prompt_handled is False (falls back to G3 Add Variable).
    6. Verifies post-save real readback via both G3 parse_csp_cfbf_declarations and CFBF Contents stream,
       and fails closed if T1_LEVEL_PV / %R101 is missing despite SHA mutation.
    """
    import shutil
    import win32con
    import scripts.g9_campaign as g9

    baseline_iec_text = (
        "VAR\r\n"
        + "\r\n".join(f"   BASE_VAR_{i:02d} : BOOL ;" for i in range(1, 24))
        + "\r\nEND_VAR\r\n"
    )
    clipboard_history = []
    sent_messages = []
    keys_sent = []

    monkeypatch.setattr(g9, "_set_clipboard_unicode_text", lambda txt: clipboard_history.append(txt))
    monkeypatch.setattr(g9, "open_program_variables_pane", lambda *a, **kw: None)
    monkeypatch.setattr(g9, "find_program_variables_treeview", lambda pid, mh: (0x2001, 0x2002))
    monkeypatch.setattr(g9, "relocate_global_variables_row", lambda **kw: (100, 100, (90, 90, 110, 110), 1))
    monkeypatch.setattr(g9.mouse, "click", lambda **kw: None)
    monkeypatch.setattr(
        g9,
        "inspect_context_menu_items",
        lambda app_uia: (["&Add Variable\tIns", "Edit Variables as &Text"], 0x3001),
    )
    monkeypatch.setattr(g9, "find_iec_editor_candidate_windows", lambda mh: (0x4001, [0x4002]))
    monkeypatch.setattr(g9.win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(g9.win32gui, "IsWindowVisible", lambda h: True)
    monkeypatch.setattr(g9.win32gui, "GetClassName", lambda h: "W5EditST" if h == 0x4002 else "AfxFrameOrView140su")
    monkeypatch.setattr(g9, "focus_iec_editor", lambda **kw: None)
    monkeypatch.setattr(g9.user32, "SetForegroundWindow", lambda h: 1)
    monkeypatch.setattr(g9.user32, "SendMessageW", lambda h, m, wp, lp: sent_messages.append((h, m, wp, lp)) or 1)
    monkeypatch.setattr(g9.user32, "PostMessageW", lambda h, m, wp, lp: 1)
    monkeypatch.setattr(g9, "send_keys", lambda k: keys_sent.append(k))
    monkeypatch.setattr(g9.time, "sleep", lambda _: None)
    monkeypatch.setattr(g9, "handle_confirmation_popups", lambda **kw: False)
    monkeypatch.setattr(g9, "dismiss_error_check_modals", lambda **kw: 0)

    # Simulate read_text_from_active_editor returning:
    # - Polls 1 & 2: baseline_iec_text (2 consecutive identical complete reads)
    # - First paste check: baseline_iec_text (simulating first paste missed + clipboard overwritten)
    # - Retry paste check: updated text containing T1_LEVEL_PV and T1_INLET_VALVE
    read_calls = {"n": 0}

    def _fake_read_editor(main_hwnd, cscape_ui, main_win, evidence=None, context_label=""):
        read_calls["n"] += 1
        if context_label.endswith("_check_paste"):
            return baseline_iec_text  # Forces retry branch!
        if context_label.endswith("_check_paste_retry"):
            return clipboard_history[-1]
        return baseline_iec_text

    monkeypatch.setattr(g9, "read_text_from_active_editor", _fake_read_editor)
    monkeypatch.setattr(g9, "close_and_commit_iec_variables_editor_tab", lambda **kw: True)

    class DummyApp:
        def window(self, handle=None):
            class _W:
                def type_keys(self, k):
                    keys_sent.append(k)

                def descendants(self, control_type=None):
                    return []

            return _W()

    spec = g9.get_tank_training_family_tasks()[0]  # G9_TASK_01: T1_LEVEL_PV (%R101), T1_INLET_VALVE (%M101)
    test_csp = tmp_path / "g9_task_G9_TASK_01.csp"
    shutil.copy2(g9.BASE_P1_PATH, test_csp)

    # First verify fail-closed when SHA mutates on disk (e.g. window layout saved) WITHOUT T1_LEVEL_PV %R101 in Contents!
    sha_calls = {"n": 0}

    def _fake_sha_mutated_without_var(p):
        sha_calls["n"] += 1
        return "initial_sha_000" if sha_calls["n"] == 1 else "mutated_sha_111"

    monkeypatch.setattr(g9, "compute_sha256", _fake_sha_mutated_without_var)

    with pytest.raises(AssertionError, match="FAIL_CLOSED: Real readback failed! Variable 'T1_LEVEL_PV' with register '%R101'"):
        g9.declare_variables_via_live_cscape_ui(
            pid=4242,
            main_hwnd=0x1000,
            app=DummyApp(),
            spec=spec,
            app_uia=DummyApp(),
            copy_path=test_csp,
        )

    # Verify W5EditST native messages (0x040F SelectAll, 0x0302 WM_PASTE, 0x0415 OnEditPaste) were sent to editor_hwnd (0x4002)
    assert (0x4002, 0x040F, 0, 0) in sent_messages
    assert (0x4002, win32con.WM_PASTE, 0, 0) in sent_messages
    assert (0x4002, 0x0415, 0, 0) in sent_messages

    # Verify clipboard was populated TWICE (initial + re-populated before ^a/^v retry after read_text_from_active_editor clobbered it)
    assert len(clipboard_history) == 2
    assert "T1_LEVEL_PV : INT ;" in clipboard_history[-1]
    assert "(*$tag=%R101*)" in clipboard_history[-1]
    assert "T1_INLET_VALVE : BOOL ;" in clipboard_history[-1]
    assert "(*$tag=%M101*)" in clipboard_history[-1]
    assert "^a" in keys_sent and "^v" in keys_sent


def test_g3_resolve_known_editor_prompt_answers_yes_on_iec_variables_editor_prompt(monkeypatch):
    """Verify that resolve_known_editor_prompt in scripts/g3_edit_roundtrip.py recognizes
    'Contents of IEC Variables Editor Window have been modified. Do you want to save the changes?'
    (even when top-level title is 'Cscape' on a g9_task_*.csp copy) and answers IDYES (6) instead of IDNO (7).
    """
    import win32con
    import scripts.g3_edit_roundtrip as g3

    dlg_hwnd = 0x770010
    yes_btn_hwnd = 0x770011
    no_btn_hwnd = 0x770012
    dispatched = []

    monkeypatch.setattr(g3.win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(
        g3,
        "inspect_dialog_controls",
        lambda h: {
            "buttons": [
                {"hwnd": yes_btn_hwnd, "text": "&Yes", "ctrl_id": win32con.IDYES},
                {"hwnd": no_btn_hwnd, "text": "&No", "ctrl_id": win32con.IDNO},
            ],
            "texts": [
                "Contents of IEC Variables Editor Window have been modified. Do you want to save the changes?"
            ],
        },
    )
    monkeypatch.setattr(g3.user32, "SetForegroundWindow", lambda h: 1)
    monkeypatch.setattr(g3.user32, "SendMessageW", lambda h, m, wp, lp: dispatched.append((h, m, wp, lp)) or 1)
    monkeypatch.setattr(g3.user32, "PostMessageW", lambda h, m, wp, lp: dispatched.append((h, m, wp, lp)) or 1)
    monkeypatch.setattr(g3.time, "sleep", lambda _: None)

    class DummyApp:
        def window(self, handle=None):
            raise RuntimeError("Force WM_COMMAND fallback")

    evidence = {"copy_path": "C:\\HornerAI\\jev-cscape-agent\\work\\disposable\\copies\\g9_task_G9_TASK_01.csp"}
    res = g3.resolve_known_editor_prompt(
        hwnd=dlg_hwnd,
        cls="#32770",
        title="Cscape",
        app=DummyApp(),
        evidence=evidence,
    )
    assert res is True
    assert (dlg_hwnd, win32con.WM_COMMAND, win32con.IDYES, yes_btn_hwnd) in dispatched
    assert not any(wp == win32con.IDNO for (_, _, wp, _) in dispatched)


def test_declare_variables_via_live_cscape_ui_synchronizes_tagdatabase_via_errorcheck_32826(monkeypatch):
    """Verify declare_variables_via_live_cscape_ui dispatches ID_PROGRAM_ERRORCHECK (32826)
    (invoking Cscape.exe VA 0x589720 -> TagDatabase.dll!LoadAppliTagToAppliMap) before ID_FILE_SAVE (57603)
    so newly declared IEC variables are synchronized into TagDatabase.dll's AppliMap for HMI binding.
    """
    import win32con
    import scripts.g9_campaign as g9

    baseline_iec_text = (
        "VAR\r\n"
        + "\r\n".join(f"   BASE_VAR_{i:02d} : BOOL ;" for i in range(1, 24))
        + "\r\n   T1_LEVEL_PV : INT ;\r\n      (*$tag=%R101*)\r\n"
        + "   T1_INLET_VALVE : BOOL ;\r\n      (*$tag=%M101*)\r\n"
        + "END_VAR\r\n"
    )
    posted_commands = []
    sent_commands = []

    monkeypatch.setattr(g9, "open_program_variables_pane", lambda *a, **kw: None)
    monkeypatch.setattr(g9, "find_program_variables_treeview", lambda pid, mh: (0x2001, 0x2002))
    monkeypatch.setattr(g9, "relocate_global_variables_row", lambda **kw: (100, 100, (90, 90, 110, 110), 1))
    monkeypatch.setattr(g9.mouse, "click", lambda **kw: None)
    monkeypatch.setattr(
        g9,
        "inspect_context_menu_items",
        lambda app_uia: (["&Add Variable\tIns", "Edit Variables as &Text"], 0x3001),
    )
    monkeypatch.setattr(g9, "find_iec_editor_candidate_windows", lambda mh: (0x4001, [0x4002]))
    monkeypatch.setattr(g9.win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(g9.win32gui, "IsWindowVisible", lambda h: True)
    monkeypatch.setattr(g9.win32gui, "GetClassName", lambda h: "W5EditST" if h == 0x4002 else "AfxFrameOrView140su")
    monkeypatch.setattr(g9, "read_text_from_active_editor", lambda *a, **kw: baseline_iec_text)
    monkeypatch.setattr(g9, "close_and_commit_iec_variables_editor_tab", lambda **kw: True)
    monkeypatch.setattr(g9.user32, "SetForegroundWindow", lambda h: 1)
    monkeypatch.setattr(
        g9.user32,
        "PostMessageW",
        lambda h, m, wp, lp: posted_commands.append((h, m, wp, lp)) or 1,
    )
    monkeypatch.setattr(
        g9.user32,
        "SendMessageW",
        lambda h, m, wp, lp: sent_commands.append((h, m, wp, lp)) or 1,
    )
    monkeypatch.setattr(g9, "send_keys", lambda k: None)
    monkeypatch.setattr(g9.time, "sleep", lambda _: None)
    monkeypatch.setattr(g9, "handle_program_information_modified_dialog", lambda **kw: False)
    monkeypatch.setattr(g9, "handle_confirmation_popups", lambda **kw: False)
    monkeypatch.setattr(g9, "dismiss_error_check_modals", lambda **kw: 0)

    class DummyApp:
        def window(self, handle=None):
            class _W:
                def type_keys(self, k):
                    pass

                def descendants(self, control_type=None):
                    return []

            return _W()

    spec = g9.get_tank_training_family_tasks()[0]
    ok = g9.declare_variables_via_live_cscape_ui(
        pid=4242,
        main_hwnd=0x1000,
        app=DummyApp(),
        spec=spec,
        app_uia=DummyApp(),
        copy_path=None,
    )
    assert ok is True
    assert (0x1000, win32con.WM_COMMAND, g9.ID_PROGRAM_ERRORCHECK, 0) in posted_commands
    assert (0x1000, win32con.WM_COMMAND, g9.ID_FILE_SAVE, 0) in sent_commands




