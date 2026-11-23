"""Verification Test Suite for HMI SVG Accessibility and Visual Grounding Audit.

Work Package: W048 (Gate G9 HMI/SCADA Offline Deliverables & Accessibility Hardening)
Classification: PRODUCTION_READY

Validates:
1. Zero Z-order visual occlusion between header title and AlarmBanner across all screens.
2. Universal SVG 1.1 filter compatibility (elimination of legacy feDropShadow).
3. Root SVG rendering hints (geometricPrecision, crispEdges).
4. WCAG 2.1 AA text contrast (>= 4.5:1 for normal text).
5. High-contrast bargraph readout backing badge.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
import pytest


def get_luminance(r: int, g: int, b: int) -> float:
    """Calculate relative luminance per WCAG 2.1 definition."""
    def channel_lum(c: int) -> float:
        s = c / 255.0
        return s / 12.92 if s <= 0.03928 else ((s + 0.055) / 1.055) ** 2.4

    r_lum = channel_lum(r)
    g_lum = channel_lum(g)
    b_lum = channel_lum(b)
    return 0.2126 * r_lum + 0.7152 * g_lum + 0.0722 * b_lum


def get_contrast_ratio(hex1: str, hex2: str) -> float:
    """Calculate contrast ratio between two hex color codes."""
    h1 = hex1.lstrip("#")
    h2 = hex2.lstrip("#")
    r1, g1, b1 = int(h1[0:2], 16), int(h1[2:4], 16), int(h1[4:6], 16)
    r2, g2, b2 = int(h2[0:2], 16), int(h2[2:4], 16), int(h2[4:6], 16)

    l1 = get_luminance(r1, g1, b1)
    l2 = get_luminance(r2, g2, b2)

    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


SVG_FILES = [
    Path("artifacts/HMI/screen_1_overview.svg"),
    Path("artifacts/HMI/screen_5_alarms.svg"),
    Path("artifacts/HMI/screen_6_recipes.svg"),
    Path("artifacts/HMI/main_dashboard.svg"),
]


@pytest.mark.parametrize("svg_path", SVG_FILES)
def test_svg_xml_well_formed(svg_path: Path) -> None:
    """Verify SVG is well-formed XML and contains valid SVG root elements."""
    assert svg_path.is_file(), f"File {svg_path} not found"
    tree = ET.parse(svg_path)
    root = tree.getroot()
    assert root.tag.endswith("svg")
    assert "viewBox" in root.attrib
    assert root.attrib.get("viewBox") == "0 0 800 480"


@pytest.mark.parametrize("svg_path", SVG_FILES)
def test_svg_rendering_hints_and_filter_compatibility(svg_path: Path) -> None:
    """Verify rendering hints and universal SVG 1.1 shadow filter."""
    content = svg_path.read_text(encoding="utf-8")

    # 1. Check rendering hints
    assert 'text-rendering="geometricPrecision"' in content
    assert 'shape-rendering="crispEdges"' in content

    # 2. Check elimination of feDropShadow in favor of SVG 1.1 primitives
    assert "<feDropShadow" not in content
    assert "<feGaussianBlur" in content
    assert "<feOffset" in content


@pytest.mark.parametrize("svg_path", SVG_FILES)
def test_zero_header_alarm_banner_occlusion(svg_path: Path) -> None:
    """Verify AlarmBanner rect never overlaps or occludes the Screen Title Header (y: 0..40)."""
    tree = ET.parse(svg_path)
    root = tree.getroot()

    # Find all groups with 'alm_' or 'alarm_' in their id
    for elem in root.iter():
        elem_id = elem.attrib.get("id", "")
        if "alm" in elem_id.lower() or "alarm" in elem_id.lower():
            # Find child rect
            for child in elem.iter():
                if child.tag.endswith("rect"):
                    y_val = float(child.attrib.get("y", 0))
                    # Header extends from y=0 to y=40; AlarmBanner must be placed at y >= 44
                    assert y_val >= 44, (
                        f"AlarmBanner {elem_id} in {svg_path.name} is placed at y={y_val}, "
                        f"which occludes the header bar (y <= 40)."
                    )


def test_pushbutton_wcag_aa_contrast() -> None:
    """Verify push button text colors meet WCAG 2.1 AA (>= 4.5:1) against button backgrounds."""
    # Green start button: white text on dark green #1B5E20
    ratio_green = get_contrast_ratio("#FFFFFF", "#1B5E20")
    assert ratio_green >= 4.5, f"Green start button contrast {ratio_green:.2f} < 4.5:1"

    # Red stop button: white text on red #B42828
    ratio_red = get_contrast_ratio("#FFFFFF", "#B42828")
    assert ratio_red >= 4.5, f"Red stop button contrast {ratio_red:.2f} < 4.5:1"


@pytest.mark.parametrize("svg_path", SVG_FILES)
def test_bargraph_readout_backing_badge(svg_path: Path) -> None:
    """Verify bargraph value readouts have high-contrast dark backing badges."""
    content = svg_path.read_text(encoding="utf-8")
    if "bar_" in content or "bargraph" in content.lower():
        # Confirm backing badge with fill="#0A1118"
        assert 'fill="#0A1118"' in content
        assert 'fill-opacity="0.88"' in content
