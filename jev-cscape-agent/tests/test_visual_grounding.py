"""Tests for Vision Grounding Engine and UI Pane Analyzer (Work Package W028, Gate G9).

Validates:
1. WindowRegion bounding box properties, containment, relative points, and bounds validation.
2. Contrast and element visibility metrics (WCAG contrast ratio, RMS contrast).
3. Visual region segmentation on live Cscape GDI screenshot (cscape_live_window.png).
4. Visual region segmentation on synthetic bitmaps and in-memory byte buffers.
5. Adaptive proportional fallback on uniform/flat bitmaps.
6. Fallback coordinate resolution for unexposed MFC controls.
7. Strict 4-state engineering contract compliance (AgentStatus.SUCCESS | FAILED | BLOCKED | INCONCLUSIVE).
"""

import io
from pathlib import Path
from typing import Dict, List, Tuple
import pytest
from PIL import Image, ImageDraw

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.contracts.contract_validator import ContractValidator
from jev_cscape.vision.grounding import (
    DEFAULT_FALLBACK_CONTROLS,
    DEFAULT_SCREENSHOT_PATH,
    SUPPORTED_RESOLUTIONS,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_LARGE_TEXT_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    FallbackCoordinate,
    VisionAnalysisReport,
    VisionGroundingEngine,
    WindowRegion,
    calculate_contrast_ratio,
    calculate_relative_luminance,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def synthetic_cscape_bitmap() -> Image.Image:
    """Create a synthetic 1000x600 image representing Cscape workspace layout."""
    w, h = 1000, 600
    img = Image.new("RGB", (w, h), (240, 240, 240))
    draw = ImageDraw.Draw(img)

    # Ribbon / Menu bar: top 0..140
    draw.rectangle([0, 0, w, 140], fill=(200, 220, 245))
    draw.line([0, 140, w, 140], fill=(120, 140, 180), width=2)

    # Status Bar: bottom 575..600
    draw.rectangle([0, 575, w, h], fill=(180, 200, 230))
    draw.line([0, 575, w, 575], fill=(100, 120, 150), width=2)

    # Project Navigator: left 0..250, y=140..575
    draw.rectangle([0, 140, 250, 575], fill=(255, 255, 255))
    draw.line([250, 140, 250, 575], fill=(160, 160, 160), width=2)

    # Central Editor Viewport: 250..1000, y=140..380
    draw.rectangle([250, 140, w, 380], fill=(210, 210, 210))
    draw.line([250, 380, w, 380], fill=(150, 180, 220), width=3)

    # Output Window: 250..1000, y=380..575
    draw.rectangle([250, 380, w, 575], fill=(250, 250, 250))

    return img


@pytest.fixture
def memory_buffer_png(synthetic_cscape_bitmap: Image.Image) -> bytes:
    """PNG bytes in memory."""
    buf = io.BytesIO()
    synthetic_cscape_bitmap.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def uniform_bitmap() -> Image.Image:
    """Uniform flat 800x600 image without sharp gradient edges."""
    return Image.new("RGB", (800, 600), (128, 128, 128))


# ---------------------------------------------------------------------------
# Unit Tests: WindowRegion Model & Helpers
# ---------------------------------------------------------------------------

def test_window_region_properties_and_helpers():
    """Verify geometry helpers on WindowRegion."""
    region = WindowRegion(
        name="test_pane",
        left=100,
        top=50,
        right=300,
        bottom=250,
        width=200,
        height=200,
        confidence=0.95,
        contrast_ratio=3.5,
        rms_contrast=40.0,
        is_visible=True,
    )

    assert region.center == (200, 150)
    assert region.center_x == 200
    assert region.center_y == 150
    assert region.bounding_box == (100, 50, 300, 250)

    # Containment
    assert region.contains(100, 50)
    assert region.contains(200, 150)
    assert not region.contains(300, 250)  # boundary is exclusive on right/bottom
    assert not region.contains(50, 150)

    # Relative point
    assert region.get_relative_point(0.0, 0.0) == (100, 50)
    assert region.get_relative_point(0.5, 0.5) == (200, 150)
    assert region.get_relative_point(1.0, 1.0) == (300, 250)

    # Out of range relative point
    with pytest.raises(ValueError):
        region.get_relative_point(-0.1, 0.5)
    with pytest.raises(ValueError):
        region.get_relative_point(0.5, 1.2)


def test_window_region_bounds_validation():
    """Verify bounds validation under various geometric configurations."""
    valid_region = WindowRegion(
        name="valid",
        left=0,
        top=0,
        right=800,
        bottom=600,
        width=800,
        height=600,
    )
    assert valid_region.validate_bounds(max_width=800, max_height=600) is True

    # Exceeds max dimensions
    assert valid_region.validate_bounds(max_width=700, max_height=600) is False
    assert valid_region.validate_bounds(max_width=800, max_height=500) is False

    # Inverted or mismatched dimensions
    invalid_region = WindowRegion(
        name="invalid",
        left=200,
        top=100,
        right=100,  # right < left
        bottom=300,
        width=100,
        height=200,
    )
    assert invalid_region.validate_bounds(max_width=800, max_height=600) is False


def test_window_region_intersection():
    """Verify bounding box intersection logic."""
    r1 = WindowRegion(name="r1", left=0, top=0, right=100, bottom=100, width=100, height=100)
    r2 = WindowRegion(name="r2", left=50, top=50, right=150, bottom=150, width=100, height=100)
    r3 = WindowRegion(name="r3", left=200, top=200, right=300, bottom=300, width=100, height=100)

    assert r1.intersects(r2) is True
    assert r2.intersects(r1) is True
    assert r1.intersects(r3) is False
    assert r2.intersects(r3) is False


# ---------------------------------------------------------------------------
# Unit Tests: Contrast & Element Visibility Metrics
# ---------------------------------------------------------------------------

def test_contrast_and_element_visibility():
    """Verify WCAG contrast ratio, RMS contrast, and visibility calculation."""
    engine = VisionGroundingEngine()

    # Flat uniform white image
    flat_img = Image.new("RGB", (100, 100), (255, 255, 255))
    cr, rms, vis = engine.compute_contrast_metrics(flat_img)
    assert cr == 1.0
    assert rms == 0.0

    # High-contrast patterned image
    pattern_img = Image.new("RGB", (100, 100), (0, 0, 0))
    draw = ImageDraw.Draw(pattern_img)
    draw.rectangle([25, 25, 75, 75], fill=(255, 255, 255))
    cr, rms, vis = engine.compute_contrast_metrics(pattern_img)
    assert cr > 5.0
    assert rms > 50.0
    assert vis is True

    # Zero-dimension crop edge case
    empty_crop = Image.new("RGB", (0, 0))
    cr, rms, vis = engine.compute_contrast_metrics(empty_crop)
    assert cr == 1.0
    assert rms == 0.0
    assert vis is False


# ---------------------------------------------------------------------------
# Unit Tests: Region Segmentation on Synthetic & Memory Images
# ---------------------------------------------------------------------------

def test_segmentation_with_synthetic_bitmap(synthetic_cscape_bitmap: Image.Image):
    """Verify that synthetic Cscape layout extracts all 5 regions correctly."""
    engine = VisionGroundingEngine()
    regions = engine.segment_regions(synthetic_cscape_bitmap)

    assert len(regions) == 5
    required_keys = {"ribbon_menu_bar", "project_navigator", "editor_viewport", "output_window", "status_bar"}
    assert set(regions.keys()) == required_keys

    # Check boundaries align reasonably with synthetic layout
    ribbon = regions["ribbon_menu_bar"]
    status = regions["status_bar"]
    nav = regions["project_navigator"]
    editor = regions["editor_viewport"]
    output = regions["output_window"]

    assert ribbon.top == 0
    assert ribbon.width == 1000
    assert 120 <= ribbon.bottom <= 160

    assert status.bottom == 600
    assert status.width == 1000
    assert 560 <= status.top <= 585

    assert nav.left == 0
    assert 200 <= nav.right <= 300
    assert nav.top == ribbon.bottom
    assert nav.bottom == status.top

    assert editor.left == nav.right
    assert editor.right == 1000
    assert editor.top == ribbon.bottom
    assert editor.bottom == output.top

    assert output.left == nav.right
    assert output.right == 1000
    assert output.bottom == status.top


def test_segmentation_with_memory_buffer(memory_buffer_png: bytes):
    """Verify segmentation directly from in-memory byte buffer."""
    engine = VisionGroundingEngine()
    regions = engine.segment_regions(memory_buffer_png)

    assert len(regions) == 5
    for name, region in regions.items():
        assert region.width > 0
        assert region.height > 0
        assert region.is_visible is True


def test_proportional_fallback_on_uniform_bitmap(uniform_bitmap: Image.Image):
    """Verify that when no edge gradients exist, adaptive proportional fallback succeeds."""
    engine = VisionGroundingEngine()
    regions = engine.segment_regions(uniform_bitmap)

    assert len(regions) == 5
    for name, region in regions.items():
        assert region.validate_bounds(800, 600) is True
        assert region.width > 0
        assert region.height > 0


# ---------------------------------------------------------------------------
# Integration Tests: Live Cscape Screenshot (if present on disk)
# ---------------------------------------------------------------------------

def test_segmentation_with_live_screenshot():
    """Verify segmentation on live Cscape GDI screenshot at artifacts/logs/cscape_live_window.png."""
    screenshot_path = Path(DEFAULT_SCREENSHOT_PATH)
    if not screenshot_path.exists():
        pytest.skip(f"Live screenshot {DEFAULT_SCREENSHOT_PATH} not found on disk.")

    engine = VisionGroundingEngine(default_screenshot_path=str(screenshot_path))
    regions = engine.segment_regions()

    assert len(regions) == 5
    ribbon = regions["ribbon_menu_bar"]
    nav = regions["project_navigator"]
    editor = regions["editor_viewport"]
    output = regions["output_window"]
    status = regions["status_bar"]

    # Image is 1278x566
    assert ribbon.left == 0
    assert ribbon.right == 1278
    assert status.left == 0
    assert status.right == 1278
    assert status.bottom == 566

    # Verify Project Navigator splitter around 312px
    assert 280 <= nav.right <= 350
    assert nav.left == 0

    # Verify Editor and Output dock pane alignment
    assert editor.left == nav.right
    assert editor.right == 1278
    assert output.left == nav.right
    assert output.right == 1278
    assert editor.bottom == output.top

    # Check that all regions report visibility and non-zero contrast
    for r in [ribbon, nav, editor, output, status]:
        assert r.is_visible is True
        assert r.contrast_ratio >= 1.0


# ---------------------------------------------------------------------------
# Unit Tests: Fallback Coordinates for Unexposed MFC Controls
# ---------------------------------------------------------------------------

def test_fallback_coordinates_resolution(synthetic_cscape_bitmap: Image.Image):
    """Verify fallback coordinate resolution for all registered unexposed MFC controls."""
    engine = VisionGroundingEngine()
    regions = engine.segment_regions(synthetic_cscape_bitmap)
    coords = engine.get_all_fallback_coordinates(regions=regions)

    assert len(coords) == len(DEFAULT_FALLBACK_CONTROLS)

    for control_name, fallback in coords.items():
        assert fallback.control_name == control_name
        parent_region = regions[fallback.region_name]

        # Ensure resolved coordinate is strictly inside the parent region
        assert parent_region.contains(fallback.x, fallback.y), (
            f"Control '{control_name}' coord ({fallback.x}, {fallback.y}) outside region '{parent_region.name}' "
            f"bounds {parent_region.bounding_box}"
        )
        assert fallback.is_visible is True
        assert fallback.confidence > 0.0


def test_specific_critical_fallback_controls(synthetic_cscape_bitmap: Image.Image):
    """Verify specific unexposed MFC control fallbacks."""
    engine = VisionGroundingEngine()
    regions = engine.segment_regions(synthetic_cscape_bitmap)

    # 1. Error check button on ribbon
    ec_coord = engine.get_control_fallback_coordinates("ribbon_error_check", regions=regions)
    assert ec_coord.region_name == "ribbon_menu_bar"
    assert regions["ribbon_menu_bar"].contains(ec_coord.x, ec_coord.y)

    # 2. Project Navigator tree
    nav_coord = engine.get_control_fallback_coordinates("project_navigator_tree", regions=regions)
    assert nav_coord.region_name == "project_navigator"
    assert regions["project_navigator"].contains(nav_coord.x, nav_coord.y)

    # 3. Output ListBox
    out_coord = engine.get_control_fallback_coordinates("output_listbox", regions=regions)
    assert out_coord.region_name == "output_window"
    assert regions["output_window"].contains(out_coord.x, out_coord.y)

    # 4. Editor origin (Rung 1 drop point)
    ed_coord = engine.get_control_fallback_coordinates("editor_origin", regions=regions)
    assert ed_coord.region_name == "editor_viewport"
    assert regions["editor_viewport"].contains(ed_coord.x, ed_coord.y)

    # 5. Status bar target PLC
    sb_coord = engine.get_control_fallback_coordinates("status_bar_target_plc", regions=regions)
    assert sb_coord.region_name == "status_bar"
    assert regions["status_bar"].contains(sb_coord.x, sb_coord.y)


def test_custom_fallback_control_registration(synthetic_cscape_bitmap: Image.Image):
    """Verify registering a custom fallback control."""
    engine = VisionGroundingEngine()
    engine.register_fallback_control(
        control_name="custom_zoom_slider",
        region_name="status_bar",
        rel_x=0.90,
        rel_y=0.50,
        description="Zoom slider anchor on status bar",
    )

    regions = engine.segment_regions(synthetic_cscape_bitmap)
    coord = engine.get_control_fallback_coordinates("custom_zoom_slider", regions=regions)

    assert coord.control_name == "custom_zoom_slider"
    assert coord.region_name == "status_bar"
    assert regions["status_bar"].contains(coord.x, coord.y)


def test_fallback_control_exceptions(synthetic_cscape_bitmap: Image.Image):
    """Verify KeyError is raised for unknown control and ValueError for invalid anchors."""
    engine = VisionGroundingEngine()

    with pytest.raises(KeyError, match="Unknown unexposed MFC control"):
        engine.get_control_fallback_coordinates("non_existent_control", source=synthetic_cscape_bitmap)

    with pytest.raises(ValueError, match="Relative anchors must be within"):
        engine.register_fallback_control("bad_anchor", "status_bar", rel_x=1.5, rel_y=0.5)


# ---------------------------------------------------------------------------
# Contract Verification Tests: Strict 4-State Contract
# ---------------------------------------------------------------------------

def test_analyze_contract_success(synthetic_cscape_bitmap: Image.Image):
    """Verify that analyze() returns ExecutionResult.success with complete structured report."""
    engine = VisionGroundingEngine()
    result = engine.analyze(synthetic_cscape_bitmap)

    assert result.status == AgentStatus.SUCCESS
    assert result.error_code is None
    assert "successfully segmented" in result.details
    assert "dimensions" in result.data
    assert "regions" in result.data
    assert "fallback_controls" in result.data

    # Verify compliance with JEV ContractValidator
    report = ContractValidator.validate_and_remediate(result)
    assert report.is_valid is True
    assert len(report.violations) == 0
    assert report.enforced_status == AgentStatus.SUCCESS


def test_analyze_image_not_found():
    """Verify that analyze() fails with ERR_VISION_IMAGE_NOT_FOUND when file does not exist."""
    engine = VisionGroundingEngine()
    result = engine.analyze("non_existent_path_to_window.png")

    assert result.status == AgentStatus.FAILED
    assert result.error_code == "ERR_VISION_IMAGE_NOT_FOUND"


def test_analyze_invalid_image_data():
    """Verify that analyze() fails with ERR_VISION_INVALID_IMAGE on corrupt byte buffer."""
    engine = VisionGroundingEngine()
    result = engine.analyze(b"corrupt_non_image_bytes")

    assert result.status == AgentStatus.FAILED
    assert result.error_code == "ERR_VISION_INVALID_IMAGE"


def test_analyze_image_too_small():
    """Verify that analyze() fails cleanly when image dimensions are too small to segment."""
    tiny_img = Image.new("RGB", (20, 20), (255, 255, 255))
    engine = VisionGroundingEngine()
    result = engine.analyze(tiny_img)

    assert result.status == AgentStatus.FAILED
    assert result.error_code == "ERR_VISION_SEGMENTATION_FAILED"


# ---------------------------------------------------------------------------
# Unit Tests: WCAG 2.1 AAA Contrast & Relative Luminance (Gate G9)
# ---------------------------------------------------------------------------

def test_wcag_21_relative_luminance_precision():
    """Verify relative luminance follows W3C WCAG 2.1 specifications:
    L = 0.2126 * R_lin + 0.7152 * G_lin + 0.0722 * B_lin
    """
    # 1. Pure primary colors (sRGB)
    l_red = calculate_relative_luminance("#FF0000")
    l_green = calculate_relative_luminance("#00FF00")
    l_blue = calculate_relative_luminance("#0000FF")
    l_white = calculate_relative_luminance("#FFFFFF")
    l_black = calculate_relative_luminance("#000000")

    assert abs(l_red - 0.2126) < 1e-4
    assert abs(l_green - 0.7152) < 1e-4
    assert abs(l_blue - 0.0722) < 1e-4
    assert abs(l_white - 1.0) < 1e-4
    assert abs(l_black - 0.0) < 1e-6

    # 2. Channel linearization threshold test (c <= 0.04045 vs c > 0.04045)
    c_low = 0.040
    c_high = 0.500
    assert abs(srgb_channel_to_linear(c_low) - (0.040 / 12.92)) < 1e-6
    assert abs(srgb_channel_to_linear(c_high) - (((0.500 + 0.055) / 1.055) ** 2.4)) < 1e-6

    # 3. Tuple input support (ints 0..255 and floats 0.0..1.0)
    assert abs(calculate_relative_luminance((255, 0, 0)) - 0.2126) < 1e-4
    assert abs(calculate_relative_luminance((0.0, 1.0, 0.0)) - 0.7152) < 1e-4

    # 4. Engine staticmethod bindings
    assert abs(VisionGroundingEngine.calculate_relative_luminance("#FFFFFF") - 1.0) < 1e-4


def test_wcag_21_contrast_ratio_formula():
    """Verify Contrast Ratio = (L1 + 0.05) / (L2 + 0.05) properties:
    - Maximum possible contrast ratio (pure white on pure black): 21.0:1
    - Minimum possible contrast ratio (identical colors): 1.0:1
    - Symmetry: CR(c1, c2) == CR(c2, c1)
    """
    # Maximum contrast: White on Black
    cr_max = calculate_contrast_ratio("#FFFFFF", "#000000")
    assert abs(cr_max - 21.0) < 1e-4

    # Minimum contrast: Identical colors
    cr_min_white = calculate_contrast_ratio("#FFFFFF", "#FFFFFF")
    cr_min_black = calculate_contrast_ratio("#000000", "#000000")
    cr_min_gray = calculate_contrast_ratio("#808080", "#808080")
    assert abs(cr_min_white - 1.0) < 1e-4
    assert abs(cr_min_black - 1.0) < 1e-4
    assert abs(cr_min_gray - 1.0) < 1e-4

    # Symmetry
    cr_ab = calculate_contrast_ratio("#39FF14", "#0B0F19")
    cr_ba = calculate_contrast_ratio("#0B0F19", "#39FF14")
    assert abs(cr_ab - cr_ba) < 1e-6

    # Luminance floats direct input
    assert abs(calculate_contrast_ratio(1.0, 0.0) - 21.0) < 1e-4


def test_wcag_edge_cases_no_zero_division():
    """Ensure edge cases like extreme dark, pure white, pure black, and low-contrast
    grayscale patches return valid mathematical metrics without division by zero or negative values.
    """
    engine = VisionGroundingEngine()

    # 1. Extreme dark colors (#000000, #010101, #000002)
    dark_colors = ["#000000", "#010101", "#000002", "#000100", (0, 0, 0), (1, 1, 1)]
    for dc in dark_colors:
        lum = calculate_relative_luminance(dc)
        assert 0.0 <= lum <= 0.01, f"Expected near-zero luminance for dark color {dc}, got {lum}"
        cr = calculate_contrast_ratio(dc, "#000000")
        assert 1.0 <= cr <= 1.05, f"Expected cr near 1.0 for dark color {dc}, got {cr}"

    # 2. Low-contrast grayscale color pairs
    cr_low = calculate_contrast_ratio("#7F7F7F", "#808080")
    assert 1.0 <= cr_low < 1.05
    assert not (cr_low < 1.0)

    # 3. Image patch edge cases in compute_contrast_metrics
    # Pure black 50x50 patch
    black_patch = Image.new("RGB", (50, 50), (0, 0, 0))
    cr_b, rms_b, vis_b = engine.compute_contrast_metrics(black_patch)
    assert cr_b == 1.0
    assert rms_b == 0.0
    assert vis_b is True

    # Extreme dark 50x50 patch (#010101)
    ext_dark_patch = Image.new("RGB", (50, 50), (1, 1, 1))
    cr_ed, rms_ed, vis_ed = engine.compute_contrast_metrics(ext_dark_patch)
    assert cr_ed == 1.0
    assert rms_ed == 0.0
    assert vis_ed is True

    # Pure white 50x50 patch (#FFFFFF)
    white_patch = Image.new("RGB", (50, 50), (255, 255, 255))
    cr_w, rms_w, vis_w = engine.compute_contrast_metrics(white_patch)
    assert cr_w == 1.0
    assert rms_w == 0.0
    assert vis_w is True

    # Low-contrast 50x50 grayscale patch (half 127, half 128)
    low_contrast_patch = Image.new("RGB", (50, 50), (127, 127, 127))
    draw_lc = ImageDraw.Draw(low_contrast_patch)
    draw_lc.rectangle([25, 0, 50, 50], fill=(128, 128, 128))
    cr_lc, rms_lc, vis_lc = engine.compute_contrast_metrics(low_contrast_patch)
    assert 1.0 <= cr_lc <= 1.05
    assert rms_lc >= 0.0
    assert vis_lc is True

    # Tiny sub-5x5 patches (1x1, 2x2, 4x4)
    for dim in [(1, 1), (2, 2), (4, 4)]:
        tiny = Image.new("RGB", dim, (10, 20, 30))
        cr_t, rms_t, vis_t = engine.compute_contrast_metrics(tiny)
        assert cr_t >= 1.0
        assert rms_t >= 0.0
        assert vis_t is False  # Sub-5x5 is marked not visible on Cscape workspace

    # Degenerate zero-dimension crop
    zero_crop = Image.new("RGB", (0, 0))
    cr_z, rms_z, vis_z = engine.compute_contrast_metrics(zero_crop)
    assert cr_z == 1.0
    assert rms_z == 0.0
    assert vis_z is False


def test_wcag_aaa_compliance_dark_scada_theme():
    """Verify WCAG 2.1 AAA compliance on dark SCADA theme palette:
    - Background: #0B0F19 (SCADA dark background, lum ~ 0.00483)
    - Cyan Accent: #00FFCC (telemetry & normal state, cr ~ 14.75 >= 7.0 WCAG AAA)
    - Neon Green Accent: #39FF14 (nominal status & run state, cr ~ 14.12 >= 7.0 WCAG AAA)
    - Pure White Accent: #FFFFFF (high-contrast text & badges, cr ~ 19.15 >= 18.0 WCAG AAA badge)
    """
    scada_bg = "#0B0F19"
    accent_cyan = "#00FFCC"
    accent_green = "#39FF14"
    accent_white = "#FFFFFF"

    # 1. Background relative luminance verification
    bg_lum = calculate_relative_luminance(scada_bg)
    assert 0.0045 <= bg_lum <= 0.0055, f"Expected #0B0F19 lum ~0.00483, got {bg_lum}"

    # 2. Cyan accent (#00FFCC) WCAG AAA compliance (> 7.0:1)
    cr_cyan = calculate_contrast_ratio(accent_cyan, scada_bg)
    assert cr_cyan >= WCAG_AAA_TEXT_CONTRAST_TARGET, (
        f"Cyan {accent_cyan} contrast {cr_cyan:.2f} must exceed WCAG AAA text target 7.0:1"
    )
    assert 14.0 <= cr_cyan <= 15.5
    assert validate_wcag_aaa_contrast(accent_cyan, scada_bg, WCAG_AAA_TEXT_CONTRAST_TARGET) is True

    # 3. Neon green accent (#39FF14) WCAG AAA compliance (> 7.0:1)
    cr_green = calculate_contrast_ratio(accent_green, scada_bg)
    assert cr_green >= WCAG_AAA_TEXT_CONTRAST_TARGET, (
        f"Green {accent_green} contrast {cr_green:.2f} must exceed WCAG AAA text target 7.0:1"
    )
    assert 13.5 <= cr_green <= 15.0
    assert validate_wcag_aaa_contrast(accent_green, scada_bg, WCAG_AAA_TEXT_CONTRAST_TARGET) is True

    # 4. Pure white accent (#FFFFFF) WCAG AAA decoupled badge compliance (> 18.0:1)
    cr_white = calculate_contrast_ratio(accent_white, scada_bg)
    assert cr_white >= WCAG_AAA_BADGE_CONTRAST_TARGET, (
        f"White {accent_white} contrast {cr_white:.2f} must exceed WCAG AAA badge target 18.0:1"
    )
    assert 18.5 <= cr_white <= 20.0
    assert validate_wcag_aaa_contrast(accent_white, scada_bg, WCAG_AAA_BADGE_CONTRAST_TARGET) is True


def test_wcag_aaa_dark_scada_image_patches():
    """Verify compute_contrast_metrics accurately detects WCAG AAA contrast
    on synthetic dark SCADA image patches with #0B0F19 background.
    """
    engine = VisionGroundingEngine()
    bg_rgb = (11, 15, 25)  # #0B0F19

    # 1. Cyan accent patch (#0B0F19 background with #00FFCC accent box)
    cyan_img = Image.new("RGB", (100, 100), bg_rgb)
    draw_cyan = ImageDraw.Draw(cyan_img)
    draw_cyan.rectangle([25, 25, 75, 75], fill=(0, 255, 204))  # #00FFCC
    cr_c, rms_c, vis_c = engine.compute_contrast_metrics(cyan_img)

    assert vis_c is True
    assert rms_c > 50.0
    assert cr_c >= WCAG_AAA_TEXT_CONTRAST_TARGET, (
        f"Image patch cyan contrast {cr_c} must exceed WCAG AAA text target 7.0:1"
    )
    assert 13.0 <= cr_c <= 16.0

    # 2. Neon green accent patch (#0B0F19 background with #39FF14 accent box)
    green_img = Image.new("RGB", (100, 100), bg_rgb)
    draw_green = ImageDraw.Draw(green_img)
    draw_green.rectangle([25, 25, 75, 75], fill=(57, 255, 20))  # #39FF14
    cr_g, rms_g, vis_g = engine.compute_contrast_metrics(green_img)

    assert vis_g is True
    assert rms_g > 50.0
    assert cr_g >= WCAG_AAA_TEXT_CONTRAST_TARGET, (
        f"Image patch green contrast {cr_g} must exceed WCAG AAA text target 7.0:1"
    )
    assert 13.0 <= cr_g <= 16.0

    # 3. White accent badge patch (#0B0F19 background with #FFFFFF badge box)
    white_img = Image.new("RGB", (100, 100), bg_rgb)
    draw_white = ImageDraw.Draw(white_img)
    draw_white.rectangle([25, 25, 75, 75], fill=(255, 255, 255))  # #FFFFFF
    cr_w, rms_w, vis_w = engine.compute_contrast_metrics(white_img)

    assert vis_w is True
    assert rms_w > 50.0
    assert cr_w >= WCAG_AAA_BADGE_CONTRAST_TARGET, (
        f"Image patch white badge contrast {cr_w} must exceed WCAG AAA badge target 18.0:1"
    )
    assert 18.0 <= cr_w <= 20.5


# ---------------------------------------------------------------------------
# Unit Tests: Multi-Resolution Offline Mock Grounding (Gate G9)
# ---------------------------------------------------------------------------

def test_supported_resolutions_definition():
    """Verify SUPPORTED_RESOLUTIONS contains canonical Cscape workspace dimensions."""
    expected = {
        "SVGA": (800, 600),
        "XGA": (1024, 768),
        "SXGA": (1280, 1024),
        "FHD": (1920, 1080),
    }
    assert SUPPORTED_RESOLUTIONS == expected
    for name, (w, h) in SUPPORTED_RESOLUTIONS.items():
        assert w >= 800
        assert h >= 600


@pytest.mark.parametrize("res_name,dimensions", [
    ("SVGA", (800, 600)),
    ("XGA", (1024, 768)),
    ("SXGA", (1280, 1024)),
    ("FHD", (1920, 1080)),
])
def test_multi_resolution_offline_mock_grounding(res_name: str, dimensions: Tuple[int, int]):
    """Verify offline mock grounding across all supported resolutions (SVGA, XGA, SXGA, FHD):
    1. Proportional fallback segmentation on uniform mock bitmaps.
    2. Edge-detected segmentation on synthetic mock layouts with pane borders.
    3. Strict containment of all registered unexposed MFC fallback controls within parent region bounds.
    4. Compliance with strict 4-state engineering contract via ContractValidator.
    """
    width, height = dimensions
    engine = VisionGroundingEngine()

    # -----------------------------------------------------------------------
    # Part 1: Proportional Fallback Segmentation on Uniform Mock Bitmap
    # -----------------------------------------------------------------------
    uniform_mock = Image.new("RGB", (width, height), (128, 128, 128))

    # 1.1 End-to-end analyze() contract check
    result_uniform = engine.analyze(uniform_mock)
    assert result_uniform.status == AgentStatus.SUCCESS, (
        f"analyze() failed on uniform {res_name} ({width}x{height}): {result_uniform.details}"
    )
    assert result_uniform.error_code is None
    assert "successfully segmented" in result_uniform.details
    assert result_uniform.data["dimensions"] == {"width": width, "height": height}

    report_uniform = ContractValidator.validate_and_remediate(result_uniform)
    assert report_uniform.is_valid is True
    assert len(report_uniform.violations) == 0

    # 1.2 Region segmentation geometry validation
    regions = engine.segment_regions(uniform_mock)
    assert len(regions) == 5
    required_keys = {"ribbon_menu_bar", "project_navigator", "editor_viewport", "output_window", "status_bar"}
    assert set(regions.keys()) == required_keys

    for r_name, r in regions.items():
        assert r.validate_bounds(width, height) is True, (
            f"Region '{r_name}' failed bounds validation for {res_name}: {r.bounding_box}"
        )
        assert r.width > 0
        assert r.height > 0
        assert r.is_visible is True
        assert r.confidence >= 0.85

    # Geometric tiling and partitioning assertions
    ribbon = regions["ribbon_menu_bar"]
    nav = regions["project_navigator"]
    editor = regions["editor_viewport"]
    output = regions["output_window"]
    status = regions["status_bar"]

    assert ribbon.left == 0 and ribbon.top == 0 and ribbon.right == width
    assert status.left == 0 and status.right == width and status.bottom == height
    assert nav.left == 0 and nav.top == ribbon.bottom and nav.bottom == status.top
    assert editor.left == nav.right and editor.top == ribbon.bottom and editor.right == width
    assert output.left == nav.right and output.top == editor.bottom and output.bottom == status.top and output.right == width

    # 1.3 Strict containment of all registered fallback controls
    fallback_coords = engine.get_all_fallback_coordinates(regions=regions)
    assert len(fallback_coords) == len(DEFAULT_FALLBACK_CONTROLS)

    for ctrl_name, fb in fallback_coords.items():
        parent_region = regions[fb.region_name]
        assert parent_region.contains(fb.x, fb.y), (
            f"Control '{ctrl_name}' coord ({fb.x}, {fb.y}) outside parent region '{fb.region_name}' "
            f"bounds {parent_region.bounding_box} on {res_name} ({width}x{height})"
        )
        assert parent_region.left <= fb.x < parent_region.right
        assert parent_region.top <= fb.y < parent_region.bottom
        assert fb.is_visible is True
        assert fb.confidence > 0.0

    # -----------------------------------------------------------------------
    # Part 2: Segmentation on Synthetic Patterned Mock Bitmap with Drawn Borders
    # -----------------------------------------------------------------------
    synthetic_mock = Image.new("RGB", (width, height), (240, 240, 240))
    draw = ImageDraw.Draw(synthetic_mock)

    # Proportionally scaled pane boundaries
    syn_ribbon_h = int(height * 0.20)
    syn_status_h = 26
    syn_status_y = height - syn_status_h
    syn_split_x = int(width * 0.25)
    syn_out_y = syn_ribbon_h + int((syn_status_y - syn_ribbon_h) * 0.50)

    # Draw distinct pane backgrounds & dividing borders
    draw.rectangle([0, 0, width, syn_ribbon_h], fill=(200, 220, 245))
    draw.line([0, syn_ribbon_h, width, syn_ribbon_h], fill=(100, 120, 160), width=2)

    draw.rectangle([0, syn_status_y, width, height], fill=(180, 200, 230))
    draw.line([0, syn_status_y, width, syn_status_y], fill=(90, 110, 140), width=2)

    draw.rectangle([0, syn_ribbon_h, syn_split_x, syn_status_y], fill=(255, 255, 255))
    draw.line([syn_split_x, syn_ribbon_h, syn_split_x, syn_status_y], fill=(150, 150, 150), width=2)

    draw.rectangle([syn_split_x, syn_ribbon_h, width, syn_out_y], fill=(215, 215, 215))
    draw.line([syn_split_x, syn_out_y, width, syn_out_y], fill=(140, 170, 210), width=2)

    draw.rectangle([syn_split_x, syn_out_y, width, syn_status_y], fill=(250, 250, 250))

    result_synthetic = engine.analyze(synthetic_mock)
    assert result_synthetic.status == AgentStatus.SUCCESS, (
        f"analyze() failed on synthetic {res_name} ({width}x{height}): {result_synthetic.details}"
    )

    syn_regions = engine.segment_regions(synthetic_mock)
    assert len(syn_regions) == 5
    for r_name, r in syn_regions.items():
        assert r.validate_bounds(width, height) is True
        assert r.width > 0
        assert r.height > 0

    syn_coords = engine.get_all_fallback_coordinates(regions=syn_regions)
    for ctrl_name, fb in syn_coords.items():
        parent_region = syn_regions[fb.region_name]
        assert parent_region.contains(fb.x, fb.y), (
            f"Control '{ctrl_name}' coord ({fb.x}, {fb.y}) outside parent '{fb.region_name}' "
            f"on synthetic {res_name}"
        )

    # -----------------------------------------------------------------------
    # Part 3: Extreme Boundary Coordinates Containment Verification
    # -----------------------------------------------------------------------
    boundary_engine = VisionGroundingEngine()
    boundary_engine.register_fallback_control("ctrl_origin", "ribbon_menu_bar", 0.0, 0.0, "Top-left origin")
    boundary_engine.register_fallback_control("ctrl_corner", "editor_viewport", 1.0, 1.0, "Bottom-right corner")
    boundary_engine.register_fallback_control("ctrl_near_max", "output_window", 0.999, 0.999, "Near-maximum corner")
    boundary_engine.register_fallback_control("ctrl_min_max", "status_bar", 0.0, 1.0, "Bottom-left boundary")

    b_coords = boundary_engine.get_all_fallback_coordinates(regions=regions)
    for c_name in ["ctrl_origin", "ctrl_corner", "ctrl_near_max", "ctrl_min_max"]:
        b_fb = b_coords[c_name]
        p_reg = regions[b_fb.region_name]
        assert p_reg.contains(b_fb.x, b_fb.y), (
            f"Boundary control '{c_name}' coord ({b_fb.x}, {b_fb.y}) not contained in '{p_reg.name}' "
            f"{p_reg.bounding_box} on {res_name}"
        )

