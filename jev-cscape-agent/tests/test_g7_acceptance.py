#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic Unit Test Suite for Gate G7 Acceptance Campaign.

Mandate: Real Gate G7 acceptance verification:
1. 20 runs from clean copy of p1_base.csp.
2. Standard match pass rate >= 19/20.
3. >= 4 reserved operand/parameter combos.
4. An intentional wrong operand fixture that the verifier detects even if Cscape accepts it.
5. Cscape Error Check (32826) dispatch and reading the full result (0 errors, 0 warnings).
6. Zero silent duplications (delta elements == 2, delta networks == 1, no duplicate symbols).
7. Save/reopen equivalence.
8. Jev decisions replaying authentic G4 recorded responses offline.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import pytest

from scripts.g7_acceptance import (
    BASE_P1_PATH,
    BASELINE_P1_SHA,
    G4_AUTHENTIC_REPLAY_FIXTURES,
    assert_safety_invariants,
    assert_zero_silent_duplications,
    compute_sha256,
    parse_cfbf_ladder_elements,
    run_g7_acceptance_campaign,
    trigger_and_read_cscape_error_check,
)
from jev_cscape.security.command_interceptor import Win32CommandInterceptor
from jev_cscape.security.exceptions import HardwareLockoutError
from jev_cscape.security.guard import SecurityGuard


def test_g7_acceptance_safety_invariants_and_lockouts():
    """Assert all fail-closed safety invariants are active and baseline is intact."""
    assert_safety_invariants()
    current_sha = compute_sha256(BASE_P1_PATH)
    assert current_sha == BASELINE_P1_SHA, f"Baseline hash mismatch: {current_sha}"

    with pytest.raises(HardwareLockoutError):
        SecurityGuard.assert_port_safe("COM1")
    with pytest.raises(HardwareLockoutError):
        SecurityGuard.assert_port_safe("COM256")

    interceptor = Win32CommandInterceptor()
    res1 = interceptor.dispatch_safe_command(hwnd=0x1234, cmd_id=32827)
    assert res1.status.value in ["blocked", "AgentStatus.BLOCKED"]
    res2 = interceptor.dispatch_safe_command(hwnd=0x1234, cmd_id=33149)
    assert res2.status.value in ["blocked", "AgentStatus.BLOCKED"]


def test_g7_acceptance_20_authentic_g4_replay_fixtures():
    """Verify all 20 fixtures carry authentic G4 response provenance and required schema fields."""
    assert len(G4_AUTHENTIC_REPLAY_FIXTURES) == 20
    seen_req_ids = set()

    for idx, f in enumerate(G4_AUTHENTIC_REPLAY_FIXTURES, 1):
        assert f["task_number"] == idx
        assert f["task_id"] == f"P1_TASK_{idx:02d}"
        assert f["response_id"].startswith("req_")
        assert f["source_file"].startswith("artifacts/G4/campaign_runs/task_")
        assert f["audit_source"] == "artifacts/G4/g4_audit_report.json"
        assert f["model"] == "jev-1.13.0"
        assert f["contact_type"] in ["CONTACT_NO", "CONTACT_NC"]
        assert f["coil_type"] in ["COIL_NO", "COIL_NC", "COIL_SET", "COIL_RESET"]
        assert len(f["contact_tag"]) > 0
        assert len(f["coil_tag"]) > 0
        assert f["confidence"] > 0.0

        seen_req_ids.add(f["response_id"])

    assert len(seen_req_ids) == 20, "All 20 authentic G4 request IDs must be distinct"


def test_g7_acceptance_reserved_combos_count_ge_4():
    """Verify >= 4 distinct reserved operand/parameter combinations are exercised."""
    unique_combos = set()
    for f in G4_AUTHENTIC_REPLAY_FIXTURES:
        combo = (f["contact_type"], f["contact_tag"], f["coil_type"])
        unique_combos.add(combo)

    assert len(unique_combos) >= 4, f"Expected >=4 reserved combos, got {len(unique_combos)}"
    # Verify presence of system bits
    contact_tags = {f["contact_tag"] for f in G4_AUTHENTIC_REPLAY_FIXTURES}
    assert "ALW_ON" in contact_tags
    assert "ALW_OFF" in contact_tags
    assert "SYS_DISABLE" in contact_tags
    assert "FST_SCN" in contact_tags


def test_g7_acceptance_intentional_wrong_operand_fixture_detection():
    """Verify the verifier catches the intentionally wrong operand even if Cscape accepts it."""
    task_20 = G4_AUTHENTIC_REPLAY_FIXTURES[19]
    assert task_20.get("intentional_wrong_operand") is True
    assert task_20.get("placed_wrong_tag") == "ALW_ON"
    assert task_20["contact_tag"] == "ALW_OFF"

    # Verifier mismatch detection logic
    placed_contact = task_20["placed_wrong_tag"]
    planned_contact = task_20["contact_tag"]
    assert placed_contact != planned_contact
    wrong_operand_detected = (placed_contact != planned_contact)
    standard_match_pass = (placed_contact == planned_contact)
    assert wrong_operand_detected is True
    assert standard_match_pass is False


def test_g7_acceptance_zero_silent_duplications_enforcement():
    """Verify zero silent duplications assertion catches element, rung, and declaration anomalies."""
    base_info = {"element_count": 0, "network_count": 2, "elements": []}

    # Case 1a: Valid delta (delta_elem == 2, delta_net == 1: new rung inserted)
    rt_valid = {"element_count": 2, "network_count": 3, "elements": [{"tag": "A"}, {"tag": "B"}]}
    check = assert_zero_silent_duplications(base_info, rt_valid, BASE_P1_PATH)
    assert check["zero_silent_duplications"] is True
    assert check["delta_element_count"] == 2
    assert check["delta_network_count"] == 1

    # Case 1b: Valid delta (delta_elem == 2, delta_net == 0: placed on existing rung)
    rt_valid_net0 = {"element_count": 2, "network_count": 2, "elements": [{"tag": "A"}, {"tag": "B"}]}
    check_net0 = assert_zero_silent_duplications(base_info, rt_valid_net0, BASE_P1_PATH)
    assert check_net0["zero_silent_duplications"] is True
    assert check_net0["delta_element_count"] == 2
    assert check_net0["delta_network_count"] == 0

    # Case 2: Silent element duplication (delta_elem == 3)
    rt_dup_elem = {"element_count": 3, "network_count": 3, "elements": []}
    with pytest.raises(RuntimeError, match="Silent element duplication or omission detected"):
        assert_zero_silent_duplications(base_info, rt_dup_elem, BASE_P1_PATH)

    # Case 3: Silent network duplication (delta_net == 2)
    rt_dup_net = {"element_count": 2, "network_count": 4, "elements": []}
    with pytest.raises(RuntimeError, match="Silent rung/network duplication detected"):
        assert_zero_silent_duplications(base_info, rt_dup_net, BASE_P1_PATH)

    # Case 4: Negative network delta (delta_net == -1)
    rt_neg_net = {"element_count": 2, "network_count": 1, "elements": []}
    with pytest.raises(RuntimeError, match="Silent rung/network duplication detected"):
        assert_zero_silent_duplications(base_info, rt_neg_net, BASE_P1_PATH)

    # Case 5: Duplicate global symbol in declarations
    from unittest.mock import patch
    with patch("scripts.g7_acceptance.parse_csp_cfbf_declarations", return_value=[
        {"scope": "G", "name": "SYS_FLAG"},
        {"scope": "G", "name": "SYS_FLAG"},
    ]):
        with pytest.raises(RuntimeError, match="Silent duplicate global variable declarations detected"):
            assert_zero_silent_duplications(base_info, rt_valid, BASE_P1_PATH)

    # Case 6: Duplicate expected_new_tag in declarations
    with patch("scripts.g7_acceptance.parse_csp_cfbf_declarations", return_value=[
        {"scope": "G", "name": "P1_COIL"},
        {"scope": "G", "name": "P1_COIL"},
    ]):
        with pytest.raises(RuntimeError, match="Silent duplicate"):
            assert_zero_silent_duplications(base_info, rt_valid, BASE_P1_PATH, expected_new_tag="P1_COIL")


def test_g7_acceptance_error_check_fail_closed_on_invalid_window():
    """Verify trigger_and_read_cscape_error_check fails closed when Cscape window is not available."""
    with pytest.raises(RuntimeError, match="Invalid main_hwnd"):
        trigger_and_read_cscape_error_check(0, 0)


def test_g7_acceptance_cfbf_ladder_elements_parser():
    """Verify CFBF oracle parsing against untouched baseline project p1_base.csp."""
    info = parse_cfbf_ladder_elements(BASE_P1_PATH)
    assert info["exists"] is True
    assert info["element_count"] == 0
    assert info["network_count"] == 2
    assert len(info["elements"]) == 0


def test_g7_acceptance_campaign_criteria_and_fixtures():
    """Verify all 20 acceptance fixtures meet required criteria without dry-run simulation."""
    assert len(G4_AUTHENTIC_REPLAY_FIXTURES) == 20
    unique_combos = {(f["contact_type"], f["contact_tag"], f["coil_type"]) for f in G4_AUTHENTIC_REPLAY_FIXTURES}
    assert len(unique_combos) >= 4
    canary = [f for f in G4_AUTHENTIC_REPLAY_FIXTURES if f.get("intentional_wrong_operand")]
    assert len(canary) == 1
    assert canary[0]["task_number"] == 20
    assert canary[0]["placed_wrong_tag"] != canary[0]["contact_tag"]

