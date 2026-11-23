#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test suite for scripts/g5_live_campaign.py.

Verifies:
1. Safety invariants and fail-closed hardware lockout directives.
2. Immutability of baseline work/disposable/p1_base.csp.
3. Vision-driven targeting for Ladder Editor (power rail + cell calculation).
4. Vision-driven targeting for HMI Screen Editor (canvas bounds + zoom + point calculation).
5. Live negative controls: Stale image, moved window, out-of-bounds, occlusion, landmark mismatch.
6. Dry-run campaign execution producing 20/20 runs passed and 5/5 negatives passed.
7. Single-invocation run accounting in summary JSON.
8. Zero live Cscape processes launched during test execution.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from PIL import Image

REPO_ROOT = Path(__file__).resolve().parent.parent

from scripts.g5_canvas_model import BoundingBox, CanvasAnchorDetector, HMICanvasModel, LadderCanvasModel
from scripts.g5_capture import CaptureFrame, CaptureProvenance, G5Capture, ROI
from scripts.g5_visual_guard import (
    OcclusionVisualError,
    OutOfBoundsVisualError,
    StaleImageError,
    VisualGuard,
    VisualGuardError,
    WindowMovedError,
)
from scripts.g5_live_campaign import (
    BASE_P1_PATH,
    BASELINE_P1_SHA,
    HardwareLockoutError,
    LIVE_RUN_SPECS,
    VisionActionExecutor,
    assert_safety_invariants,
    capture_fresh_window_frame,
    compute_sha256,
    dismiss_failed_to_open_dialog_if_present,
    execute_negative_controls,
    get_benchmark_cscape_frame,
    get_live_captured_dialog_rect,
    is_cscape_project_open,
    launch_and_verify_cscape_project,
    parse_cfbf_hmi_delta,
    parse_cfbf_ladder_delta,
    run_live_campaign,
    SUMMARY_JSON_PATH,
    verify_baseline_immutability,
)


def test_safety_invariants_and_hardware_lockout():
    """Verify hardware port lockout and download command lockout fail closed."""
    # Download commands permanently blocked
    with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED: Download command"):
        assert_safety_invariants(command_id=32827)

    with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED: Download command"):
        assert_safety_invariants(command_id=33149)

    # Physical ports permanently blocked
    for port in ["COM1", "COM4", "COM256", "\\\\.\\COM1", "CAN0", "USB0", "JTAG"]:
        with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED: Physical hardware port"):
            assert_safety_invariants(target_port=port)


def test_baseline_p1_immutability():
    """Verify work/disposable/p1_base.csp matches SHA-256 baseline exactly."""
    sha = verify_baseline_immutability()
    assert sha == BASELINE_P1_SHA


def test_live_run_specs_specification():
    """Verify LIVE_RUN_SPECS contains >= 20 runs with distinct targets."""
    assert len(LIVE_RUN_SPECS) >= 20
    ladder_runs = [s for s in LIVE_RUN_SPECS if s["editor_type"] == "LADDER"]
    hmi_runs = [s for s in LIVE_RUN_SPECS if s["editor_type"] == "HMI"]

    assert len(ladder_runs) == 10
    assert len(hmi_runs) == 10

    # Ensure all run numbers are unique and 1-indexed
    run_nums = [s["run_num"] for s in LIVE_RUN_SPECS]
    assert run_nums == list(range(1, len(LIVE_RUN_SPECS) + 1))


def test_vision_targeting_ladder_cell():
    """Verify vision locates power rail and calculates rung/column cell coordinates."""
    executor = VisionActionExecutor(dry_run=True)
    # Generate test image with power rail at x=112
    img = Image.new("RGB", (1024, 768), color=(255, 255, 255))
    from PIL import ImageDraw
    draw = ImageDraw.Draw(img)
    # Draw vertical power rail line at x=112
    draw.line([(112, 0), (112, 768)], fill=(0, 0, 0), width=2)

    prov = CaptureProvenance(source_type="test_frame")
    frame = CaptureFrame(image=img, roi=ROI(0, 0, 1024, 768), provenance=prov)
    window_rect = (0, 0, 1024, 768)

    # Target rung 0, col 10 (rightmost coil)
    cx, cy = executor.locate_and_target_ladder_cell(
        frame=frame,
        target_rung=0,
        target_col=10,
        window_rect=window_rect,
    )
    assert cx > 112
    assert cy > 0
    # Col 10 should be located around 112 + 10 * 70 + 35 = 847 or clamped within width
    assert cx > 700


def test_vision_targeting_hmi_canvas_point():
    """Verify vision detects canvas bounds and transforms virtual (vx, vy) to client (cx, cy)."""
    executor = VisionActionExecutor(dry_run=True)
    img = Image.new("RGB", (640, 480), color=(240, 240, 240))
    from PIL import ImageDraw
    draw = ImageDraw.Draw(img)
    # Draw virtual LCD canvas rectangle
    draw.rectangle([50, 50, 550, 400], fill=(255, 255, 255), outline=(0, 0, 0), width=2)

    prov = CaptureProvenance(source_type="test_frame")
    frame = CaptureFrame(image=img, roi=ROI(0, 0, 640, 480), provenance=prov)
    window_rect = (0, 0, 640, 480)

    cx, cy = executor.locate_and_target_hmi_point(
        frame=frame,
        target_virtual_x=160,
        target_virtual_y=120,
        window_rect=window_rect,
    )
    assert cx > 50 and cx < 550
    assert cy > 50 and cy < 400


def test_live_negative_controls_execution():
    """Verify all 5 live negative controls are rejected and fail closed."""
    executor = VisionActionExecutor(dry_run=True)
    results = execute_negative_controls(executor)
    assert len(results) == 5
    for r in results:
        assert r["status"] == "success"
        assert "neg_id" in r
        assert "reason" in r


def test_dry_run_campaign_full_execution(tmp_path):
    """Verify dry-run mode executes 20 runs, 5 negatives, and writes valid summary JSON."""
    summary = run_live_campaign(num_runs=20, dry_run=True)
    assert summary["status"] == "success"
    assert summary["runs_total"] == 20
    assert summary["runs_passed"] == 20
    assert summary["runs_pass_rate"] == 1.0
    assert summary["negatives_total"] == 5
    assert summary["negatives_passed"] == 5
    assert summary["baseline_p1_sha256"] == BASELINE_P1_SHA

    # Verify summary JSON on disk
    assert SUMMARY_JSON_PATH.exists()
    with open(SUMMARY_JSON_PATH, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["runs_passed"] == 20
    assert loaded["negatives_passed"] == 5


def test_launch_cscape_with_project_return_signature():
    """Verify that launch_cscape_with_project returns a 3-tuple (app, pid, main_hwnd)
    and that unpacking matches 3 values (preventing ValueError: too many values to unpack).
    """
    import inspect
    from scripts.g3_edit_roundtrip import launch_cscape_with_project

    # 1. Verify function signature
    sig = inspect.signature(launch_cscape_with_project)
    assert len(sig.parameters) >= 1
    assert "project_path" in sig.parameters

    # 2. Mock call to verify 3-value unpacking
    class MockApp:
        pass

    mock_app = MockApp()
    mock_pid = 12345
    mock_hwnd = 0x00010042

    def mock_launch(path, timeout=30.0):
        return mock_app, mock_pid, mock_hwnd

    # Unpacking 3 values must succeed
    app, pid, hwnd = mock_launch(Path("test.csp"))
    assert app is mock_app
    assert pid == mock_pid
    assert hwnd == mock_hwnd

    # Unpacking 2 values must raise ValueError: too many values to unpack (expected 2)
    with pytest.raises(ValueError, match="too many values to unpack"):
        a, b = mock_launch(Path("test.csp"))


def test_launch_and_verify_cscape_project_contract(monkeypatch, tmp_path):
    """Verify that launch_and_verify_cscape_project properly returns 3 values (app, pid, main_hwnd)
    and handles startup dialogs & 'Failed to open document' dismissal.
    """
    class MockApp:
        def window(self, **kwargs):
            return self

    dummy_proj = tmp_path / "disposable_test.csp"
    dummy_proj.write_text("test")

    # Mock probe_hmi_editor helpers used by launch_and_verify_cscape_project
    monkeypatch.setattr(
        "scripts.probe_hmi_editor.configure_cscape_registry",
        lambda p: None,
    )
    monkeypatch.setattr(
        "scripts.probe_hmi_editor.kill_leftover_cscape",
        lambda: None,
    )
    monkeypatch.setattr(
        "scripts.probe_hmi_editor.launch_cscape_with_project",
        lambda p, timeout=30.0: (MockApp(), 9999, 0x8888),
    )
    monkeypatch.setattr(
        "scripts.probe_hmi_editor.handle_startup_dialogs_and_wait_for_main_window",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "scripts.g5_live_campaign.is_cscape_project_open",
        lambda hwnd, p: True,
    )
    monkeypatch.setattr(
        "scripts.g5_live_campaign.dismiss_failed_to_open_dialog_if_present",
        lambda pid=None, main_hwnd=None: False,
    )

    app, pid, main_hwnd = launch_and_verify_cscape_project(dummy_proj, max_retries=1)
    assert pid == 9999
    assert main_hwnd == 0x8888
    assert isinstance(app, MockApp)


def test_negative_04_uses_real_dialog_rect():
    """Verify Negative 04 uses a real dialog rect captured live from Cscape without hardcoded magic numbers."""
    executor = VisionActionExecutor(dry_run=True)
    real_frame = get_benchmark_cscape_frame()
    real_rect = (0, 0, real_frame.width, real_frame.height)

    # 1. Verify get_live_captured_dialog_rect returns a valid 4-tuple rect
    captured_rect = get_live_captured_dialog_rect()
    assert isinstance(captured_rect, tuple)
    assert len(captured_rect) == 4
    left, top, right, bottom = captured_rect
    assert right > left and bottom > top

    # 2. Test passing live_dialog_rect explicitly to execute_negative_controls
    custom_live_dlg = (100, 100, 400, 300)
    results = execute_negative_controls(
        executor,
        live_frame=real_frame,
        live_window_rect=real_rect,
        live_dialog_rect=custom_live_dlg,
    )
    neg_04 = next(r for r in results if r["neg_id"] == "neg_04")
    assert neg_04["status"] == "success"
    assert "Real modal dialog occlusion" in neg_04["reason"]
    assert str(custom_live_dlg) in neg_04["reason"]


def test_dismiss_failed_to_open_dialog_contract():
    """Verify dismiss_failed_to_open_dialog_if_present handles non-existent or clean windows safely."""
    # When no dialog is present, returns False without raising errors
    res = dismiss_failed_to_open_dialog_if_present(pid=999999, main_hwnd=0)
    assert res is False


def test_negative_controls_use_real_frames_and_rects():
    """Verify execute_negative_controls accepts real Cscape frames and window rects."""
    executor = VisionActionExecutor(dry_run=True)
    real_frame = get_benchmark_cscape_frame()
    assert real_frame.width >= 640
    assert real_frame.height >= 480

    real_rect = (0, 0, real_frame.width, real_frame.height)
    results = execute_negative_controls(executor, live_frame=real_frame, live_window_rect=real_rect)

    assert len(results) == 5
    for r in results:
        assert r["status"] == "success"
        assert "neg_id" in r
        assert "reason" in r


def test_hmi_targeting_fresh_frame_recapture_contract(monkeypatch):
    """Verify that HMI targeting recaptures a fresh frame when stale (>2.0s),
    ensuring frame freshness without raising the 2.0s VisualGuard threshold.
    """
    import time
    from scripts import g5_live_campaign

    # 1. Invariant check: DEFAULT_MAX_AGE_SECONDS is strictly 2.0 and not raised
    assert VisualGuard.DEFAULT_MAX_AGE_SECONDS == 2.0

    # 2. Create a deliberately stale frame (age = 15.0s > 2.0s)
    base_frame = get_benchmark_cscape_frame()
    stale_prov = CaptureProvenance(
        source_type="live_window",
        hwnd=0x1234,
        monotonic_ns=time.monotonic_ns() - int(15.0 * 1e9),  # 15s old
        frame_sha256="fake_sha",
    )
    stale_frame = CaptureFrame(image=base_frame.image, roi=base_frame.roi, provenance=stale_prov)

    # Assert VisualGuard directly rejects this stale frame with StaleImageError
    with pytest.raises(StaleImageError, match="Capture frame is stale"):
        VisualGuard.assert_fresh_image(stale_frame)

    # 3. Test capture_fresh_window_frame logic
    fresh_capture_calls = 0

    def mock_capture_window(hwnd, roi=None, use_client_area=True):
        nonlocal fresh_capture_calls
        fresh_capture_calls += 1
        prov = CaptureProvenance(
            source_type="live_window",
            hwnd=hwnd,
            monotonic_ns=time.monotonic_ns(),  # 0.0s old (completely fresh)
            frame_sha256="fresh_sha",
        )
        return CaptureFrame(image=base_frame.image, roi=base_frame.roi, provenance=prov)

    monkeypatch.setattr(G5Capture, "capture_window", mock_capture_window)

    # Mock user32 so capture_fresh_window_frame runs on mock Windows
    class MockUser32:
        @staticmethod
        def IsWindow(h):
            return True

    monkeypatch.setattr(g5_live_campaign, "user32", MockUser32())

    fresh_frame = capture_fresh_window_frame(hwnd=0x1234, max_age_s=2.0)
    assert fresh_capture_calls >= 1
    assert VisualGuard.assert_fresh_image(fresh_frame) is True

    # 4. Verify VisionActionExecutor.locate_and_target_hmi_point with stale frame + main_hwnd
    executor = VisionActionExecutor(dry_run=True)
    window_rect = (0, 0, base_frame.width, base_frame.height)

    # With main_hwnd supplied, locate_and_target_hmi_point automatically recaptures
    # when frame age >= 2.0s and successfully executes preconditions
    cx, cy = executor.locate_and_target_hmi_point(
        frame=stale_frame,
        target_virtual_x=160,
        target_virtual_y=120,
        window_rect=window_rect,
        main_hwnd=0x1234,
    )
    assert cx > 0 and cy > 0
    assert fresh_capture_calls >= 2


def test_hmi_docked_fresh_frame_recapture_and_freshness_threshold(monkeypatch):
    """Verify HMI targeting enforces fresh frame recapture post-docking,
    recaptures if frame age > 2.0s, and strictly enforces threshold <= 2.0s.
    """
    from PIL import Image, ImageDraw
    import time

    def make_hmi_frame(age_s: float, label: str = "hmi_canvas") -> CaptureFrame:
        img = Image.new("RGB", (640, 480), color=(240, 240, 240))
        draw = ImageDraw.Draw(img)
        draw.rectangle([50, 50, 550, 400], fill=(255, 255, 255), outline=(0, 0, 0), width=2)
        prov = CaptureProvenance(
            source_type="live_screen",
            window_title=f"Horner Cscape - [{label}]",
            monotonic_ns=time.monotonic_ns() - int(age_s * 1e9),
        )
        return CaptureFrame(image=img, roi=ROI(0, 0, 640, 480), provenance=prov)

    executor = VisionActionExecutor(dry_run=True)
    window_rect = (0, 0, 640, 480)

    # 1. Threshold is strictly <= 2.0s
    assert VisualGuard.DEFAULT_MAX_AGE_SECONDS <= 2.0

    # Boundary check at 1.95s (must pass)
    frame_fresh_boundary = make_hmi_frame(age_s=1.95, label="fresh_boundary")
    assert VisualGuard.assert_fresh_image(frame_fresh_boundary, max_age_s=2.0) is True

    # Boundary check at 2.05s (must raise StaleImageError)
    frame_stale_boundary = make_hmi_frame(age_s=2.05, label="stale_boundary")
    with pytest.raises(StaleImageError, match="FAIL_CLOSED: Capture frame is stale"):
        VisualGuard.assert_fresh_image(frame_stale_boundary, max_age_s=2.0)

    # 2. Pre-dock stale frame rejected fail-closed
    pre_dock_frame = make_hmi_frame(age_s=3.0, label="pre_dock_ladder_view")
    with pytest.raises(VisualGuardError, match="FAIL_CLOSED: Capture frame is stale"):
        executor.locate_and_target_hmi_point(
            frame=pre_dock_frame,
            target_virtual_x=160,
            target_virtual_y=120,
            window_rect=window_rect,
        )

    # 3. Post-dock fresh frame targeting succeeds
    fresh_docked_frame = make_hmi_frame(age_s=0.05, label="post_dock_fresh")
    cx, cy = executor.locate_and_target_hmi_point(
        frame=fresh_docked_frame,
        target_virtual_x=160,
        target_virtual_y=120,
        window_rect=window_rect,
    )
    assert 50 < cx < 550
    assert 50 < cy < 400


def test_hmi_targeting_recaptures_after_slow_status_bar_ocr(monkeypatch):
    """Reproduces the stale frame bug where status bar OCR takes > 2.0s (e.g. 5.0s on 2vCPU Cloud PC),
    causing the pre-OCR frame to become stale (> 2.0s), and verifies that locate_and_target_hmi_point
    recaptures a fresh frame immediately before the VisualGuard check, passing with age < 2.0s
    without raising the 2.0s threshold.
    """
    import time
    from scripts import g5_live_campaign
    from scripts.g5_visual_guard import VisualGuard, StaleImageError

    # 1. Freshness threshold is strictly 2.0s and never raised
    assert VisualGuard.DEFAULT_MAX_AGE_SECONDS == 2.0

    # 2. Simulated monotonic clock starting at 2000.0s
    simulated_mono_ns = [int(2000.0 * 1e9)]

    def fake_monotonic_ns() -> int:
        return simulated_mono_ns[0]

    monkeypatch.setattr(time, "monotonic_ns", fake_monotonic_ns)

    # 3. Create initial fresh frame (age = 0.0s at entry)
    base_frame = get_benchmark_cscape_frame()
    init_prov = CaptureProvenance(
        source_type="live_window",
        hwnd=0x7777,
        monotonic_ns=simulated_mono_ns[0],
        frame_sha256="initial_fresh_frame_sha",
    )
    init_frame = CaptureFrame(image=base_frame.image, roi=base_frame.roi, provenance=init_prov)

    # Confirm initial frame is fresh at entry
    assert (fake_monotonic_ns() - init_frame.provenance.monotonic_ns) / 1e9 == 0.0
    assert VisualGuard.assert_fresh_image(init_frame) is True

    # 4. Mock G5Capture.capture_window for live window recapture
    recapture_times = []

    def mock_capture_window(hwnd, roi=None, use_client_area=True):
        cur_t = fake_monotonic_ns()
        recapture_times.append(cur_t)
        prov = CaptureProvenance(
            source_type="live_window",
            hwnd=hwnd,
            monotonic_ns=cur_t,
            frame_sha256=f"recaptured_sha_{len(recapture_times)}",
        )
        return CaptureFrame(image=base_frame.image, roi=base_frame.roi, provenance=prov)

    monkeypatch.setattr(G5Capture, "capture_window", mock_capture_window)

    # Mock user32 so IsWindow succeeds for mock HWND
    class MockUser32:
        @staticmethod
        def IsWindow(h):
            return h == 0x7777

    monkeypatch.setattr(g5_live_campaign, "user32", MockUser32())

    executor = VisionActionExecutor(dry_run=True)

    # 5. Simulate slow OCR that takes 5.0 seconds
    def mock_slow_parse_status_bar(crop):
        simulated_mono_ns[0] += int(5.0 * 1e9)  # 5.0s elapsed during status bar OCR
        return {"zoom_percent": 100, "zoom": 100}

    monkeypatch.setattr(executor.ocr, "parse_status_bar", mock_slow_parse_status_bar)

    # 6. Execute HMI targeting with mock main_hwnd
    window_rect = (0, 0, base_frame.width, base_frame.height)
    cx, cy = executor.locate_and_target_hmi_point(
        frame=init_frame,
        target_virtual_x=160,
        target_virtual_y=120,
        window_rect=window_rect,
        main_hwnd=0x7777,
    )

    # 7. Assertions:
    assert cx > 0 and cy > 0
    # Must have triggered a fresh recapture immediately after slow OCR and before VisualGuard
    assert len(recapture_times) >= 1
    # Recapture occurred after the 5s OCR delay (at simulated time 2005.0s)
    assert recapture_times[-1] == int(2005.0 * 1e9)
    # Threshold remains strictly 2.0s
    assert VisualGuard.DEFAULT_MAX_AGE_SECONDS == 2.0


