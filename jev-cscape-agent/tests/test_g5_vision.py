"""
Tests for G5 Vision Subsystem
Covers:
- W038 Capture Module (g5_capture.py): ROI, DPI, timestamping, cryptographic provenance
- W039 OCR Module (g5_ocr.py): registers, tags, numbers, status bar parsing
- W041 Canvas Model (g5_canvas_model.py): Ladder & HMI geometry, anchors, grid snap, transforms
- W043 Visual Guard (g5_visual_guard.py): freshness, stationary window, out-of-bounds, occlusion
- Dataset Integrity (manifest.json): >=50 scenes, 70% train / 30% reserved split, SHA-256 validation
- Acceptance Campaign (g5_acceptance.py): 20 actions, 5 negatives, baseline immutability
- Hardware Safety Lockout: COM ports, download commands blocked fail-closed
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import time

from PIL import Image, ImageDraw
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.g5_canvas_model import (
    AnchorPoint,
    BoundingBox,
    CanvasAnchorDetector,
    HMICanvasModel,
    LadderCanvasModel,
)
from scripts.g5_capture import (
    CaptureFrame,
    CaptureProvenance,
    G5Capture,
    ROI,
    get_dpi_scale_factor,
    set_process_dpi_aware,
)
from scripts.g5_ocr import G5OCR, _GLOBAL_TPL_CACHE, OCRResult, OCRToken
from scripts.g5_visual_guard import (
    OcclusionVisualError,
    OutOfBoundsVisualError,
    StaleImageError,
    VisualGuard,
    VisualGuardError,
    WindowMovedError,
)
from scripts.g5_acceptance import (
    BASELINE_P1_PATH,
    BASELINE_P1_SHA,
    HardwareLockoutError,
    SUMMARY_JSON_PATH,
    assert_safety_invariants,
    compute_sha256,
    run_g5_acceptance_campaign,
    verify_baseline_immutability,
)

MANIFEST_PATH = REPO_ROOT / "artifacts" / "G5" / "dataset" / "manifest.json"


# =============================================================================
# W038 Capture Tests
# =============================================================================

def test_w038_roi_geometry():
    roi = ROI(left=10, top=20, right=110, bottom=120)
    assert roi.width == 100
    assert roi.height == 100
    assert roi.to_tuple() == (10, 20, 110, 120)
    assert roi.contains(50, 50)
    assert not roi.contains(5, 50)

    # Scaling
    scaled = roi.scale(1.5)
    assert scaled.left == 15
    assert scaled.top == 30
    assert scaled.width == 150

    # Normalization to 96 DPI
    norm = roi.normalize_to_96dpi(144)
    assert norm.width < roi.width


def test_w038_capture_provenance_and_crypto(tmp_path):
    img = Image.new("RGB", (64, 64), color=(100, 150, 200))
    prov = CaptureProvenance(
        source_type="offline_file",
        hwnd=12345,
        window_title="Test Cscape Window",
        dpi=96,
        dpi_scale=1.0,
    )
    frame = CaptureFrame(image=img, roi=ROI(0, 0, 64, 64), provenance=prov)
    assert frame.sha256 != ""
    assert len(frame.sha256) == 64

    # Save with sidecar
    out_file = tmp_path / "test_frame.png"
    frame.save(out_file)
    assert out_file.exists()
    sidecar = out_file.with_suffix(".json")
    assert sidecar.exists()

    with open(sidecar, "r", encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["sha256"] == frame.sha256
    assert meta["provenance"]["window_title"] == "Test Cscape Window"

    # Reload from disk
    reloaded = CaptureFrame.from_file(out_file)
    assert reloaded.sha256 == frame.sha256
    assert reloaded.width == 64
    assert reloaded.height == 64


def test_w038_sub_roi_crop():
    img = Image.new("RGB", (200, 200), color=(255, 255, 255))
    prov = CaptureProvenance(source_type="test")
    frame = CaptureFrame(image=img, roi=ROI(0, 0, 200, 200), provenance=prov)
    sub = frame.crop_roi(ROI(20, 30, 80, 110))
    assert sub.width == 60
    assert sub.height == 80
    assert sub.roi.to_tuple() == (20, 30, 80, 110)
    assert sub.sha256 != frame.sha256


# =============================================================================
# W039 OCR Tests
# =============================================================================

def test_w039_recognize_ocs_registers():
    ocr = G5OCR()
    img = Image.new("RGB", (320, 50), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((10, 10), "%R100 %AI1 %AQ5", fill=(0, 0, 0), font=_GLOBAL_TPL_CACHE._font)
    res = ocr.recognize(img)
    regs = [t[0] for t in res.get_registers()]
    assert "%R100" in regs
    assert "%AI1" in regs
    assert "%AQ5" in regs


def test_w039_recognize_horner_tags():
    ocr = G5OCR()
    img = Image.new("RGB", (380, 50), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((10, 10), "RTC_SEC RTC_MIN P1_TANK_LEVEL_PV", fill=(0, 0, 0), font=_GLOBAL_TPL_CACHE._font)
    res = ocr.recognize(img)
    tags = [t[0] for t in res.get_tags()]
    assert "RTC_SEC" in tags
    assert "RTC_MIN" in tags
    assert "P1_TANK_LEVEL_PV" in tags


def test_w039_parse_status_bar():
    ocr = G5OCR()
    # Test coordinates
    img_coords = Image.new("RGB", (180, 30), color=(240, 240, 240))
    draw = ImageDraw.Draw(img_coords)
    draw.text((10, 8), "208, 126", fill=(0, 0, 0), font=_GLOBAL_TPL_CACHE._font)
    parsed = ocr.parse_status_bar(img_coords)
    assert parsed.get("coords") == (208, 126)

    # Test objects and zoom
    img_status = Image.new("RGB", (280, 30), color=(240, 240, 240))
    draw_s = ImageDraw.Draw(img_status)
    draw_s.text((10, 8), "Screen: 1* Zoom: 120%", fill=(0, 0, 0), font=_GLOBAL_TPL_CACHE._font)
    parsed_s = ocr.parse_status_bar(img_status)
    assert parsed_s.get("screen") == "1*"
    assert parsed_s.get("zoom_percent") == 120


# =============================================================================
# W041 Canvas Model Tests
# =============================================================================

def test_w041_ladder_canvas_geometry():
    ladder = LadderCanvasModel(canvas_width=800, canvas_height=600, rung_height=60, col_width=70)
    assert ladder.is_valid_cell(0, 0)
    assert ladder.is_valid_cell(3, 10)
    assert not ladder.is_valid_cell(-1, 0)
    assert not ladder.is_valid_cell(0, 15)

    c0 = ladder.rung_col_to_client(0, 0)
    coil_target = ladder.get_coil_target(0)
    assert coil_target[0] > c0[0]

    r, c = ladder.client_to_rung_col(c0[0], c0[1])
    assert (r, c) == (0, 0)

    rails = ladder.get_power_rails()
    assert "left_rail" in rails
    assert "right_rail" in rails


def test_w041_hmi_canvas_geometry_and_transforms():
    hmi = HMICanvasModel(virtual_width=320, virtual_height=240, zoom_percent=120, viewport_offset_x=40, viewport_offset_y=30)
    assert hmi.is_valid_virtual(160, 120)
    assert not hmi.is_valid_virtual(350, 120)
    assert not hmi.is_valid_virtual(-5, 50)

    # Transform check
    cx, cy = hmi.virtual_to_client(100, 100)
    assert cx == int(round(40 + 100 * 1.2))
    assert cy == int(round(30 + 100 * 1.2))

    # Roundtrip transform
    screen_origin = (100, 100)
    sx, sy = hmi.client_to_screen(cx, cy, screen_origin)
    cx_back, cy_back = hmi.screen_to_client(sx, sy, screen_origin)
    vx_back, vy_back = hmi.client_to_virtual(cx_back, cy_back)
    assert abs(vx_back - 100.0) < 1.0
    assert abs(vy_back - 100.0) < 1.0


def test_w041_nine_point_anchors():
    box = BoundingBox(left=20, top=30, right=120, bottom=130)
    assert box.width == 100
    assert box.height == 100
    assert box.center_x == 70
    assert box.center_y == 80

    anchors = box.all_anchors()
    assert len(anchors) == 9
    assert anchors["NW"] == (20, 30)
    assert anchors["N"] == (70, 30)
    assert anchors["NE"] == (120, 30)
    assert anchors["W"] == (20, 80)
    assert anchors["CENTER"] == (70, 80)
    assert anchors["E"] == (120, 80)
    assert anchors["SW"] == (20, 130)
    assert anchors["S"] == (70, 130)
    assert anchors["SE"] == (120, 130)


def test_w041_grid_snapping():
    hmi = HMICanvasModel(grid_size=8)
    assert hmi.snap_virtual_to_grid(23.9, 45.1) == (24, 48)
    assert hmi.snap_virtual_to_grid(23.9, 45.1, custom_grid=16) == (16, 48)


def test_w041_visual_landmark_detector():
    img = Image.new("RGB", (500, 400), color=(128, 128, 128))
    draw = ImageDraw.Draw(img)
    draw.rectangle([40, 40, 460, 360], fill=(255, 255, 255))
    bounds = CanvasAnchorDetector.detect_canvas_bounds_from_image(img)
    assert abs(bounds.left - 40) <= 2
    assert abs(bounds.top - 40) <= 2

    # Status bar ROI
    sb_box = CanvasAnchorDetector.detect_status_bar_roi(img, expected_height=24)
    assert sb_box.top == 400 - 24
    assert sb_box.bottom == 400


# =============================================================================
# W043 Visual Guard Tests
# =============================================================================

def test_w043_visual_guard_freshness():
    dummy = Image.new("RGB", (50, 50), color=(255, 255, 255))
    fresh_prov = CaptureProvenance(source_type="live_screen", monotonic_ns=time.monotonic_ns())
    fresh_frame = CaptureFrame(image=dummy, roi=ROI(0, 0, 50, 50), provenance=fresh_prov)
    assert VisualGuard.assert_fresh_image(fresh_frame, max_age_s=2.0) is True

    stale_prov = CaptureProvenance(
        source_type="live_screen",
        monotonic_ns=time.monotonic_ns() - int(5.0 * 1e9),
    )
    stale_frame = CaptureFrame(image=dummy, roi=ROI(0, 0, 50, 50), provenance=stale_prov)
    with pytest.raises(StaleImageError):
        VisualGuard.assert_fresh_image(stale_frame, max_age_s=2.0)


def test_w043_visual_guard_stationary_window():
    base = (100, 100, 800, 600)
    same = (101, 100, 799, 600)  # Drift 1px <= 2px tolerance
    assert VisualGuard.assert_window_stationary(same, base, tolerance=2) is True

    moved = (106, 100, 800, 600)  # Drift 6px > 2px tolerance
    with pytest.raises(WindowMovedError):
        VisualGuard.assert_window_stationary(moved, base, tolerance=2)


def test_w043_visual_guard_canvas_bounds():
    canvas = BoundingBox(50, 50, 450, 350)
    assert VisualGuard.assert_coordinate_within_canvas(100, 100, canvas, margin=5) is True

    with pytest.raises(OutOfBoundsVisualError):
        VisualGuard.assert_coordinate_within_canvas(45, 100, canvas, margin=5)

    with pytest.raises(OutOfBoundsVisualError):
        VisualGuard.assert_coordinate_within_canvas(100, 352, canvas, margin=5)


def test_w043_visual_guard_occlusion():
    target = BoundingBox(100, 100, 150, 150)
    non_overlap = [(300, 300, 500, 500)]
    assert VisualGuard.assert_no_occlusion(target, non_overlap) is True

    overlap = [(120, 120, 400, 400)]
    with pytest.raises(OcclusionVisualError):
        VisualGuard.assert_no_occlusion(target, overlap)


def test_w043_composite_verification():
    dummy = Image.new("RGB", (100, 100), color=(255, 255, 255))
    prov = CaptureProvenance(source_type="live_screen", monotonic_ns=time.monotonic_ns())
    frame = CaptureFrame(image=dummy, roi=ROI(0, 0, 100, 100), provenance=prov)
    canvas = BoundingBox(10, 10, 90, 90)

    res = VisualGuard.verify_action_preconditions(
        frame=frame,
        target_coords=(50, 50),
        canvas_bounds=canvas,
        current_window_rect=(0, 0, 500, 500),
        baseline_window_rect=(0, 0, 500, 500),
    )
    assert res["status"] == "success"


# =============================================================================
# Dataset & Acceptance Campaign Tests
# =============================================================================

def test_dataset_manifest_and_reserved_split():
    assert MANIFEST_PATH.exists(), f"Manifest missing at {MANIFEST_PATH}"
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest["total_scenes"] >= 50
    split_summary = manifest["split_summary"]
    assert split_summary["train"] >= 35
    assert split_summary["reserved"] >= 15
    assert split_summary["train"] + split_summary["reserved"] == manifest["total_scenes"]

    scenes_dir = MANIFEST_PATH.parent / "scenes"
    for scene in manifest["scenes"]:
        img_path = scenes_dir / scene["file_name"]
        assert img_path.exists()
        sidecar_path = scenes_dir / f"{scene['scene_id']}.json"
        assert sidecar_path.exists()


def test_g5_offline_acceptance_campaign():
    summary = run_g5_acceptance_campaign()
    assert summary["status"] == "success"
    assert summary["actions_passed"] >= 19
    assert summary["actions_total"] == 20
    assert summary["negatives_passed"] == 5
    assert summary["negatives_total"] == 5
    assert summary["baseline_p1_sha256"] == BASELINE_P1_SHA
    assert SUMMARY_JSON_PATH.exists()


def test_safety_and_baseline_immutability():
    # Verify baseline CSP matches exact expected hash
    assert BASELINE_P1_PATH.exists()
    sha = compute_sha256(BASELINE_P1_PATH)
    assert sha == BASELINE_P1_SHA

    # Verify download commands blocked
    with pytest.raises(HardwareLockoutError):
        assert_safety_invariants(command_id=32827)
    with pytest.raises(HardwareLockoutError):
        assert_safety_invariants(command_id=33149)

    # Verify COM ports blocked
    with pytest.raises(HardwareLockoutError):
        assert_safety_invariants(target_port="COM3")
    with pytest.raises(HardwareLockoutError):
        assert_safety_invariants(target_port="CAN0")
