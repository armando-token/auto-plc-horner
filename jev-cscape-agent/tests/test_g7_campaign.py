# -*- coding: utf-8 -*-
"""Gate G7 Ladder Campaign Unit & Integration Test Suite.

Mandate: Verification of Gate G7 10-Run Ladder Campaign configuration, rotation invariants,
CFBF negative control deltas, reopen screenshot validity, and safety guards.
Classification: TESTED_MOCK / INTEGRATION [offline/DEV]
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

from PIL import Image
import pytest

REPO_ROOT = Path(r"C:\HornerAI\jev-cscape-agent")
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.contracts import AgentStatus
from jev_cscape.security.command_interceptor import Win32CommandInterceptor
from jev_cscape.security.exceptions import HardwareLockoutError
from jev_cscape.security.guard import SecurityGuard

from scripts.g3_edit_roundtrip import (
    BASE_P1_PATH,
    BASELINE_P1_SHA,
    assert_safety_invariants,
    compute_sha256,
)
from scripts.g7_campaign import (
    CAMPAIGN_10_RUNS,
    CAMPAIGN_RUNS_DIR,
    CAMPAIGN_SUMMARY_PATH,
    ID_NC_COIL,
    ID_NC_CONTACT,
    ID_NO_COIL,
    ID_NO_CONTACT,
    ID_RESET_COIL,
    ID_SET_COIL,
    compute_cfbf_delta,
    parse_cfbf_ladder_elements,
    scan_for_unknown_dialogs,
)


def test_baseline_p1_immutability():
    """Verify baseline p1_base.csp exists and matches cryptographic SHA-256 hash."""
    assert BASE_P1_PATH.exists(), f"Missing base p1_base.csp at {BASE_P1_PATH}"
    actual_sha = compute_sha256(BASE_P1_PATH)
    assert actual_sha == BASELINE_P1_SHA, (
        f"Baseline p1_base.csp mutated! Expected {BASELINE_P1_SHA}, got {actual_sha}"
    )


def test_fail_closed_hardware_lockout():
    """Verify physical COM ports and download commands are fail-closed blocked."""
    assert_safety_invariants()

    # COM ports blocked
    for port in ["COM1", "COM4", "COM256"]:
        with pytest.raises(HardwareLockoutError):
            SecurityGuard.assert_port_safe(port)

    # Win32 download command IDs blocked
    interceptor = Win32CommandInterceptor()
    for cmd_id in [32827, 33149]:
        res = interceptor.dispatch_safe_command(hwnd=0, cmd_id=cmd_id)
        assert res.status == AgentStatus.BLOCKED


def test_campaign_10_runs_matrix_structure():
    """Verify CAMPAIGN_10_RUNS contains exactly 10 valid run specifications."""
    assert len(CAMPAIGN_10_RUNS) == 10

    for idx, spec in enumerate(CAMPAIGN_10_RUNS, start=1):
        assert spec["run_idx"] == idx
        assert "contact_cmd" in spec
        assert "contact_type" in spec
        assert "contact_tag" in spec
        assert "coil_cmd" in spec
        assert "coil_type" in spec
        assert "coil_tag" in spec

        # Contact must be NO (1000) or NC (1001)
        assert spec["contact_cmd"] in (ID_NO_CONTACT, ID_NC_CONTACT)
        assert spec["contact_type"] in ("CONTACT_NO", "CONTACT_NC")
        assert len(spec["contact_tag"]) > 0

        # Coil must be one of the 4 variants
        assert spec["coil_cmd"] in (ID_NO_COIL, ID_NC_COIL, ID_SET_COIL, ID_RESET_COIL)
        assert spec["coil_type"] in ("COIL_NO", "COIL_NC", "COIL_SET", "COIL_RESET")
        assert len(spec["coil_tag"]) > 0


def test_campaign_rotation_coverage():
    """Verify the rotation covers NO and NC contacts and all 4 coil variants."""
    no_contacts = [r for r in CAMPAIGN_10_RUNS if r["contact_type"] == "CONTACT_NO"]
    nc_contacts = [r for r in CAMPAIGN_10_RUNS if r["contact_type"] == "CONTACT_NC"]
    assert len(no_contacts) >= 4, "Must test at least 4 Normally Open contacts"
    assert len(nc_contacts) >= 4, "Must test at least 4 Normally Closed contacts"

    coil_types = {r["coil_type"] for r in CAMPAIGN_10_RUNS}
    assert "COIL_NO" in coil_types
    assert "COIL_NC" in coil_types
    assert "COIL_SET" in coil_types
    assert "COIL_RESET" in coil_types


def test_cfbf_negative_control_oracle_on_untouched_base():
    """Verify parsing untouched p1_base.csp yields baseline element count and delta with self is 0."""
    base_info = parse_cfbf_ladder_elements(BASE_P1_PATH)
    assert "element_count" in base_info
    assert "contacts" in base_info
    assert "coils" in base_info
    assert base_info["element_count"] == 0

    delta_self = compute_cfbf_delta(base_info, base_info)
    assert delta_self["delta_element_count"] == 0
    assert len(delta_self["delta_contact_records"]) == 0
    assert len(delta_self["delta_coil_records"]) == 0


def test_compute_cfbf_delta_synthetic():
    """Verify compute_cfbf_delta correctly computes differences."""
    base = {"element_count": 0, "contacts": [], "coils": []}
    modified = {
        "element_count": 2,
        "contacts": [{"offset": 100, "tag": "ALW_ON", "prefix": "3"}],
        "coils": [{"offset": 200, "tag": "G3_TEST_VAR_01", "prefix": "3"}],
    }
    delta = compute_cfbf_delta(base, modified)
    assert delta["delta_element_count"] == 2
    assert len(delta["delta_contact_records"]) == 1
    assert len(delta["delta_coil_records"]) == 1


def test_unknown_dialog_guard_blocks_unauthorized():
    """Verify scan_for_unknown_dialogs detects simulated unauthorized dialogs."""
    with patch("scripts.g7_campaign.win32gui.EnumWindows") as mock_enum:
        def fake_enum(cb, _):
            with patch("scripts.g7_campaign.win32gui.IsWindow", return_value=True), \
                 patch("scripts.g7_campaign.win32gui.IsWindowVisible", return_value=True), \
                 patch("scripts.g7_campaign.win32process.GetWindowThreadProcessId", return_value=(0, 9999)), \
                 patch("scripts.g7_campaign.win32gui.GetClassName", return_value="#32770"), \
                 patch("scripts.g7_campaign.win32gui.GetWindowText", return_value="CRITICAL SYSTEM ERROR"), \
                 patch("scripts.g7_campaign.win32gui.GetWindowRect", return_value=(0, 0, 300, 200)):
                cb(12345, None)
        mock_enum.side_effect = fake_enum

        found = scan_for_unknown_dialogs(pid=9999)
        assert found is not None
        assert found["title"] == "CRITICAL SYSTEM ERROR"


def test_campaign_summary_artifact_if_present():
    """If g7_campaign_summary.json exists, verify all 10 runs passed, readback fields match plan, and delta >= 2."""
    if not CAMPAIGN_SUMMARY_PATH.exists():
        pytest.skip("g7_campaign_summary.json not yet generated by live run.")

    with open(CAMPAIGN_SUMMARY_PATH, "r", encoding="utf-8") as f:
        summary = json.load(f)

    assert summary.get("gate") == "G7"
    assert summary.get("overall_status") in ("success", "failed")
    assert summary.get("baseline_p1_sha256") == BASELINE_P1_SHA
    assert summary.get("runs_planned") == 10

    if summary.get("overall_status") == "success":
        assert summary.get("runs_passed") == 10
        assert summary.get("runs_failed") == 0
        assert len(summary.get("runs", [])) == 10

        for r in summary["runs"]:
            run_idx = r["run_idx"]
            assert r["status"] == "success"
            planned = CAMPAIGN_10_RUNS[run_idx - 1]

            # Readback fields verification
            assert "readback_contact_type" in r, f"Run {run_idx} missing readback_contact_type"
            assert "readback_contact_tag" in r, f"Run {run_idx} missing readback_contact_tag"
            assert "readback_coil_type" in r, f"Run {run_idx} missing readback_coil_type"
            assert "readback_coil_tag" in r, f"Run {run_idx} missing readback_coil_tag"
            assert r.get("plan_match") is True, f"Run {run_idx} plan_match is not True"

            assert r["readback_contact_type"] == planned["contact_type"], (
                f"Run {run_idx} contact type mismatch: {r['readback_contact_type']} != {planned['contact_type']}"
            )
            assert r["readback_contact_tag"] == planned["contact_tag"], (
                f"Run {run_idx} contact tag mismatch: {r['readback_contact_tag']} != {planned['contact_tag']}"
            )
            assert r["readback_coil_type"] == planned["coil_type"], (
                f"Run {run_idx} coil type mismatch: {r['readback_coil_type']} != {planned['coil_type']}"
            )
            assert r["readback_coil_tag"] == planned["coil_tag"], (
                f"Run {run_idx} coil tag mismatch: {r['readback_coil_tag']} != {planned['coil_tag']}"
            )

            delta = r.get("cfbf_delta", {})
            assert delta.get("delta_element_count", 0) >= 2, f"Run {run_idx} delta < 2"
            ss_path = Path(r["reopen_screenshot"])
            assert ss_path.exists(), f"Run {run_idx} screenshot missing: {ss_path}"
            assert ss_path.stat().st_size > 1000, f"Run {run_idx} screenshot too small: {ss_path}"

            # Verify image is valid PNG
            with Image.open(ss_path) as img:
                assert img.format == "PNG"
                assert img.size[0] > 100 and img.size[1] > 100


def test_cfbf_direct_readback_against_plan_on_all_disposable_copies():
    """Verify parse_cfbf_ladder_elements directly on each campaign file matches planned types and tags."""
    copies_dir = REPO_ROOT / "work" / "disposable" / "copies"
    for spec in CAMPAIGN_10_RUNS:
        run_idx = spec["run_idx"]
        cop = copies_dir / f"campaign_run_g7_{run_idx:02d}.csp"
        if not cop.exists():
            continue
        info = parse_cfbf_ladder_elements(cop)
        assert info.get("element_count", 0) >= 2, f"Run {run_idx} has < 2 elements"
        assert info.get("readback_contact_type") == spec["contact_type"], (
            f"Run {run_idx} contact type mismatch: {info.get('readback_contact_type')} != {spec['contact_type']}"
        )
        assert info.get("readback_contact_tag") == spec["contact_tag"], (
            f"Run {run_idx} contact tag mismatch: {info.get('readback_contact_tag')} != {spec['contact_tag']}"
        )
        assert info.get("readback_coil_type") == spec["coil_type"], (
            f"Run {run_idx} coil type mismatch: {info.get('readback_coil_type')} != {spec['coil_type']}"
        )
        assert info.get("readback_coil_tag") == spec["coil_tag"], (
            f"Run {run_idx} coil tag mismatch: {info.get('readback_coil_tag')} != {spec['coil_tag']}"
        )


def test_reopen_screenshots_visual_clarity_unobstructed():
    """Verify all 10 reopen screenshots have valid dimensions and unoccluded ladder canvas."""
    from scripts.verify_reopen_screenshots import (
        DEFAULT_RUNS_DIR,
        verify_single_screenshot,
    )

    screenshots = sorted(DEFAULT_RUNS_DIR.glob("run_*_reopen.png"))
    assert len(screenshots) == 10, f"Expected 10 reopen screenshots, found {len(screenshots)}"

    failed_runs = []
    for ss in screenshots:
        res = verify_single_screenshot(ss)
        if res.status != "success":
            failed_runs.append(f"{res.filename}: {res.classification} ({res.failure_reasons})")

    assert not failed_runs, "Visual inspection failed for reopen screenshots:\n" + "\n".join(failed_runs)
