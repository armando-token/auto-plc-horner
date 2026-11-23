"""Comprehensive Unit and Integration Test Suite for HMI Vector Renderer.

Work Package: W038 (Gate G9 HMI/SCADA Offline Deliverables)
Classification: PRODUCTION_READY

Validates:
1. HMIScreenRenderer SVG compilation across all 7 Horner OCS screen element archetypes.
2. W3C XML validity via standard xml.etree.ElementTree parsing.
3. RegisterTable overlay mechanics for dynamic digital and analog values.
4. Exporting offline SVG artifacts to disk.
5. Loading and rendering the canonical plant dashboard screen.
"""

from __future__ import annotations

import json
from pathlib import Path
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.hmi.models import (
    AlarmBanner,
    AlarmItem,
    Bargraph,
    BargraphOrientation,
    ColorRGB,
    HMIElementType,
    HMIScreen,
    IndicatorLamp,
    IndicatorLampShape,
    NavigationButton,
    NumericDataEntry,
    NumericDataType,
    PushButton,
    PushButtonMode,
    TrendChart,
    TrendPen,
)
from jev_cscape.hmi.renderer import HMIScreenRenderer, escape_text
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable, float_to_words


@pytest.fixture
def empty_screen() -> HMIScreen:
    """Fixture providing a minimal 800x480 screen."""
    return HMIScreen(
        screen_id=1,
        name="Empty Canvas",
        resolution=(800, 480),
        background_color=ColorRGB(r=15, g=23, b=42),
    )


@pytest.fixture
def rich_screen() -> HMIScreen:
    """Fixture providing a rich HMI screen with all element archetypes."""
    screen = HMIScreen(
        screen_id=10,
        name="Unit Test Process Overview",
        resolution=(800, 480),
        background_color=ColorRGB(r=15, g=23, b=42),
    )
    # 1. PushButton
    screen.elements.append(
        PushButton(
            element_id="btn_pump_start",
            label="START PUMP",
            on_label="PUMP ACTIVE",
            off_label="PUMP STOPPED",
            x=50,
            y=60,
            width=120,
            height=40,
            bound_register="%Q1",
            button_type=PushButtonMode.TOGGLE,
            on_color=ColorRGB(r=46, g=204, b=113),
            off_color=ColorRGB(r=52, g=73, b=94),
        )
    )
    # 2. NumericDataEntry
    screen.elements.append(
        NumericDataEntry(
            element_id="num_level_pv",
            label="Tank 1 Level PV",
            x=200,
            y=60,
            width=140,
            height=40,
            bound_register="%R1",
            data_type=NumericDataType.REAL,
            decimal_places=2,
            engineering_units="%",
            foreground_color=ColorRGB(r=0, g=255, b=255),
        )
    )
    # 3. Bargraph (Vertical)
    screen.elements.append(
        Bargraph(
            element_id="bar_level_v",
            label="Level Gauge",
            x=370,
            y=60,
            width=40,
            height=180,
            bound_register="%AI1",
            orientation=BargraphOrientation.VERTICAL,
            min_value=0.0,
            max_value=100.0,
            high_alarm_limit=80.0,
            low_alarm_limit=20.0,
        )
    )
    # 4. Bargraph (Horizontal)
    screen.elements.append(
        Bargraph(
            element_id="bar_flow_h",
            label="Inflow Rate",
            x=450,
            y=60,
            width=180,
            height=30,
            bound_register="%AI3",
            orientation=BargraphOrientation.HORIZONTAL,
            min_value=0.0,
            max_value=10.0,
            high_alarm_limit=8.5,
        )
    )
    # 5. IndicatorLamp
    screen.elements.append(
        IndicatorLamp(
            element_id="lamp_valve_open",
            label="Inlet Valve Open",
            x=50,
            y=120,
            width=30,
            height=30,
            bound_register="%M1",
            shape=IndicatorLampShape.ROUND,
            on_color=ColorRGB(r=46, g=204, b=113),
            off_color=ColorRGB(r=100, g=100, b=100),
        )
    )
    # 6. TrendChart
    screen.elements.append(
        TrendChart(
            element_id="chart_levels",
            label="Cascade Level History",
            x=50,
            y=260,
            width=500,
            height=160,
            pens=[
                TrendPen(bound_register="%AI1", label="Tank 1", color=ColorRGB(r=46, g=204, b=113)),
                TrendPen(bound_register="%AI2", label="Tank 2", color=ColorRGB(r=52, g=152, b=219)),
            ],
        )
    )
    # 7. AlarmBanner
    screen.elements.append(
        AlarmBanner(
            element_id="banner_alarms",
            x=50,
            y=430,
            width=700,
            height=35,
            alarms=[
                AlarmItem(alarm_id="T1_HI", bit_register="%M2", message="CRITICAL: Tank 1 Level High!"),
            ],
            background_color=ColorRGB(r=44, g=62, b=80),
            banner_color=ColorRGB(r=192, g=57, b=43),
        )
    )
    # 8. NavigationButton
    screen.elements.append(
        NavigationButton(
            element_id="nav_to_recipes",
            label="Recipe Setup",
            x=580,
            y=300,
            width=140,
            height=40,
            target_screen_id=2,
            target_screen_name="Recipes",
        )
    )
    return screen


def test_escape_text_helper() -> None:
    """Verify XML escaping function prevents script or malformed entity injection."""
    raw = 'Tank 1 <Level> & "High" \'Alarm\''
    escaped = escape_text(raw)
    assert "&lt;" in escaped
    assert "&gt;" in escaped
    assert "&amp;" in escaped
    assert "&quot;" in escaped


def test_render_empty_screen(empty_screen: HMIScreen) -> None:
    """Verify empty screen produces valid W3C XML with viewBox and header."""
    renderer = HMIScreenRenderer()
    svg = renderer.render_svg(empty_screen)

    assert "<?xml" in svg
    assert '<svg xmlns="http://www.w3.org/2000/svg"' in svg
    assert 'viewBox="0 0 800 480"' in svg

    # Validate XML parsing
    root = ET.fromstring(svg)
    assert root.tag.endswith("svg")
    assert root.attrib["width"] == "800"
    assert root.attrib["height"] == "480"


def test_render_rich_screen_xml_validity(rich_screen: HMIScreen) -> None:
    """Verify rich screen compiles without XML syntax errors."""
    renderer = HMIScreenRenderer()
    svg = renderer.render_svg(rich_screen)

    root = ET.fromstring(svg)
    assert root.tag.endswith("svg")

    # Verify key elements rendered in DOM
    assert "btn_pump_start" in svg
    assert "num_level_pv" in svg
    assert "bar_level_v" in svg
    assert "bar_flow_h" in svg
    assert "lamp_valve_open" in svg
    assert "chart_levels" in svg
    assert "banner_alarms" in svg
    assert "nav_to_recipes" in svg


def test_renderer_with_register_table(rich_screen: HMIScreen) -> None:
    """Verify dynamic register table values are reflected in SVG output."""
    regs = RegisterTable()
    regs.privilege_mode = PrivilegeMode.SYSTEM

    # Set digital and analog points
    regs.write_bit("%Q1", True)
    w1, w2 = float_to_words(73.45)
    regs.write_word("%R1", w1)
    regs.write_word("%R2", w2)
    regs.write_word("%AI1", 24000)  # 75% on 0..32000
    regs.write_bit("%M1", True)     # Valve lamp ON
    regs.write_bit("%M2", True)     # Alarm active!

    renderer = HMIScreenRenderer()
    svg = renderer.render_svg(rich_screen, registers=regs)

    # Check button pressed label
    assert "PUMP ACTIVE" in svg

    # Check numeric value formatted
    assert "73.45 %" in svg

    # Check alarm active message
    assert "CRITICAL: Tank 1 Level High!" in svg

    # XML parse check
    root = ET.fromstring(svg)
    assert root is not None


def test_export_svg_to_disk(tmp_path: Path, rich_screen: HMIScreen) -> None:
    """Verify SVG export writes readable file to target disk path."""
    renderer = HMIScreenRenderer()
    out_file = tmp_path / "test_hmi_screen.svg"
    res_path = renderer.export_svg(rich_screen, out_file)

    assert res_path.is_file()
    content = res_path.read_text(encoding="utf-8")
    assert "<svg" in content
    assert "</svg>" in content

    # XML parse verification
    tree = ET.parse(res_path)
    assert tree.getroot() is not None


def test_load_and_render_canonical_dashboard(tmp_path: Path) -> None:
    """Verify loading artifacts/HMI/main_dashboard_screen.json and rendering SVG."""
    dash_file = Path("artifacts/HMI/main_dashboard_screen.json")
    if not dash_file.is_file():
        pytest.skip("main_dashboard_screen.json not present")

    with open(dash_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    screen = HMIScreen.model_validate(data)
    renderer = HMIScreenRenderer()

    out_file = tmp_path / "main_dashboard.svg"
    renderer.export_svg(screen, out_file)

    assert out_file.is_file()
    assert out_file.stat().st_size > 1000

    tree = ET.parse(out_file)
    assert tree.getroot() is not None
