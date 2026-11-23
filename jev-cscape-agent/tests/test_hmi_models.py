"""Comprehensive Test Suite for Horner OCS HMI Models and Screen Engine.

Work Package: W020 (Gate G4)
Classification: TESTED_MOCK [offline/DEV only]

Tests cover:
- HMI Element Object Models (Pushbutton, Numeric Entry, Bargraph, Lamp, Trend, Alarm, Navigation)
- ColorRGB and AnimationRule evaluation
- Register binding and dynamic read from Horner RegisterTable
- Numeric formatting, data types (INT, REAL, DINT), and engineering units
- Simulated operator touch events and writebacks (%M, %D, %R, %AQ)
- Security level access enforcement
- Read-only protection for elements and physical input channels (%AI)
- Animation color shifts and blinking behaviors
- JSON serialization roundtrip and dashboard artifact loading
"""

import json
from pathlib import Path
import pytest

from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.hmi.models import (
    AlarmBanner,
    AlarmItem,
    AnimationConditionType,
    AnimationRule,
    Bargraph,
    BargraphOrientation,
    ColorRGB,
    HMIElementType,
    HMIScreen,
    HMIScreenElement,
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
from jev_cscape.hmi.screen_engine import (
    HMIScreenEngine,
    RenderedElement,
    RenderedScreen,
    TouchResult,
)


# ==============================================================================
# 1. ColorRGB Tests
# ==============================================================================

class TestColorRGB:
    """Test RGB color representation and conversion utilities."""

    def test_color_rgb_defaults_and_hex(self):
        c = ColorRGB(r=255, g=128, b=0)
        assert c.to_hex() == "#FF8000"
        assert c.to_hex(include_alpha=True) == "#FF8000FF"

    def test_color_rgb_from_hex(self):
        c_6 = ColorRGB.from_hex("#00FF80")
        assert c_6.r == 0
        assert c_6.g == 255
        assert c_6.b == 128
        assert c_6.a == 1.0

        c_3 = ColorRGB.from_hex("#F00")
        assert c_3.r == 255
        assert c_3.g == 0
        assert c_3.b == 0

        c_8 = ColorRGB.from_hex("#FF000080")
        assert c_8.r == 255
        assert c_8.g == 0
        assert c_8.b == 0
        assert pytest.approx(c_8.a, rel=0.01) == 0.502

    def test_color_presets(self):
        assert ColorRGB.red().to_hex() == "#FF0000"
        assert ColorRGB.green().to_hex() == "#00FF00"
        assert ColorRGB.black().to_hex() == "#000000"
        assert ColorRGB.white().to_hex() == "#FFFFFF"


# ==============================================================================
# 2. AnimationRule Tests
# ==============================================================================

class TestAnimationRule:
    """Test dynamic color animation condition evaluation."""

    def test_boolean_condition_evaluation(self):
        rule_on = AnimationRule(
            rule_name="on_rule",
            condition_type=AnimationConditionType.BOOLEAN,
            target_value=True,
            color=ColorRGB.green(),
        )
        assert rule_on.evaluate(True) is True
        assert rule_on.evaluate(1) is True
        assert rule_on.evaluate(False) is False
        assert rule_on.evaluate(0) is False
        assert rule_on.evaluate(None) is False

    def test_numeric_threshold_evaluation(self):
        rule_high = AnimationRule(
            rule_name="high_threshold",
            condition_type=AnimationConditionType.GREATER_THAN,
            target_value=85.0,
            color=ColorRGB.red(),
            blink=True,
        )
        assert rule_high.evaluate(85.1) is True
        assert rule_high.evaluate(85.0) is False
        assert rule_high.evaluate(84.9) is False
        assert rule_high.blink is True

    def test_range_condition_evaluation(self):
        rule_range = AnimationRule(
            rule_name="operating_range",
            condition_type=AnimationConditionType.RANGE,
            min_value=40.0,
            max_value=60.0,
            color=ColorRGB.yellow(),
        )
        assert rule_range.evaluate(50.0) is True
        assert rule_range.evaluate(40.0) is True
        assert rule_range.evaluate(60.0) is True
        assert rule_range.evaluate(39.9) is False
        assert rule_range.evaluate(60.1) is False

    def test_condition_register_normalization(self):
        rule = AnimationRule(
            rule_name="test_norm",
            condition_register="m10",
            condition_type=AnimationConditionType.BOOLEAN,
            color=ColorRGB.red(),
        )
        assert rule.condition_register == "%M10"


# ==============================================================================
# 3. Element Models and Formatting Tests
# ==============================================================================

class TestElementModels:
    """Test specialized HMI screen element models."""

    def test_pushbutton_model(self):
        btn = PushButton(
            element_id="btn_start",
            x=50,
            y=100,
            width=120,
            height=40,
            bound_register="%M1",
            button_type=PushButtonMode.TOGGLE,
            on_label="STARTED",
            off_label="STOPPED",
        )
        assert btn.element_type == HMIElementType.PUSHBUTTON
        assert btn.bound_register == "%M1"
        assert btn.contains_point(60, 110) is True
        assert btn.contains_point(10, 10) is False

    def test_numeric_data_entry_formatting(self):
        ne_int = NumericDataEntry(
            element_id="ne_rpm",
            bound_register="%R100",
            data_type=NumericDataType.INT,
            engineering_units="RPM",
            decimal_places=0,
        )
        assert ne_int.format_value(1750) == "1750 RPM"
        assert ne_int.format_value(None) == "--- RPM"

        ne_real = NumericDataEntry(
            element_id="ne_temp",
            bound_register="%R101",
            data_type=NumericDataType.REAL,
            engineering_units="°C",
            decimal_places=2,
        )
        assert ne_real.format_value(72.548) == "72.55 °C"

        ne_custom = NumericDataEntry(
            element_id="ne_custom",
            format_string="0x%04X",
        )
        assert ne_custom.format_value(255) == "0x00FF"

    def test_bargraph_fill_and_alarm(self):
        bg = Bargraph(
            element_id="bg_level",
            min_value=0.0,
            max_value=200.0,
            low_alarm_limit=20.0,
            high_alarm_limit=180.0,
        )
        assert bg.calculate_fill_percentage(100.0) == 50.0
        assert bg.calculate_fill_percentage(-10.0) == 0.0
        assert bg.calculate_fill_percentage(250.0) == 100.0

        assert bg.is_alarm_active(15.0) is True
        assert bg.is_alarm_active(100.0) is False
        assert bg.is_alarm_active(190.0) is True

    def test_indicator_lamp_model(self):
        lamp = IndicatorLamp(
            element_id="lamp_status",
            shape=IndicatorLampShape.ROUND,
            bound_register="%Q1",
            legend_text="RUN",
        )
        assert lamp.element_type == HMIElementType.INDICATOR_LAMP
        assert lamp.bound_register == "%Q1"

    def test_trend_chart_model_pen_sync(self):
        trend = TrendChart(
            element_id="trend_pv",
            pen_registers=["%AI1", "%R50"],
            pen_colors=[ColorRGB.blue(), ColorRGB.red()],
        )
        assert len(trend.pens) == 2
        assert trend.pens[0].bound_register == "%AI1"
        assert trend.pens[1].bound_register == "%R50"

    def test_alarm_banner_model_sync(self):
        alarm = AlarmBanner(
            element_id="alrm_banner",
            alarm_bits=["%M1", "%M2"],
            alarm_messages={"%M1": "Low Pressure", "%M2": "High Temp"},
        )
        assert len(alarm.alarms) == 2
        assert alarm.alarms[0].message == "Low Pressure"
        assert alarm.alarms[1].message == "High Temp"


# ==============================================================================
# 4. Screen Layout and Serialization Tests
# ==============================================================================

class TestHMIScreen:
    """Test HMIScreen container, element lookup, and JSON serialization."""

    def test_screen_element_management(self):
        screen = HMIScreen(
            screen_id=1,
            screen_name="Overview",
            resolution=(800, 480),
        )
        btn = PushButton(element_id="btn_1", bound_register="%M1")
        nav = NavigationButton(element_id="nav_1", target_screen_id=2)

        screen.add_element(btn)
        screen.navigation_buttons.append(nav)

        assert screen.get_element("btn_1") is btn
        assert screen.get_element("nav_1") is nav
        assert screen.get_element("nonexistent") is None

        assert screen.remove_element("btn_1") is True
        assert screen.get_element("btn_1") is None
        assert screen.remove_element("btn_1") is False

    def test_screen_polymorphic_json_roundtrip(self):
        screen = HMIScreen(
            screen_id=10,
            screen_name="Serialization Test",
            resolution=(800, 480),
            elements=[
                PushButton(element_id="btn1", bound_register="%M10", on_label="YES"),
                NumericDataEntry(element_id="ne1", bound_register="%R1", engineering_units="kg"),
                Bargraph(element_id="bg1", min_value=0.0, max_value=50.0),
                IndicatorLamp(element_id="lamp1", bound_register="%Q2"),
                TrendChart(element_id="tr1", pen_registers=["%AI1"]),
                AlarmBanner(element_id="ab1", alarm_bits=["%M5"]),
            ],
            navigation_buttons=[
                NavigationButton(element_id="nav1", target_screen_id=20)
            ],
        )

        dumped = screen.model_dump_json()
        loaded = HMIScreen.model_validate_json(dumped)

        assert loaded.screen_id == 10
        assert len(loaded.elements) == 6
        assert isinstance(loaded.elements[0], PushButton)
        assert isinstance(loaded.elements[1], NumericDataEntry)
        assert isinstance(loaded.elements[2], Bargraph)
        assert isinstance(loaded.elements[3], IndicatorLamp)
        assert isinstance(loaded.elements[4], TrendChart)
        assert isinstance(loaded.elements[5], AlarmBanner)
        assert isinstance(loaded.navigation_buttons[0], NavigationButton)


# ==============================================================================
# 5. Screen Engine Rendering and Animation Tests
# ==============================================================================

class TestScreenEngineRendering:
    """Test HMIScreenEngine dynamic value rendering and animation rules."""

    def test_render_numeric_and_bargraph_values(self):
        reg_table = RegisterTable()
        reg_table.write_word("%R100", 1250)
        reg_table.force_input("%AI1", 75)  # Physical analog input simulated via force_input
        reg_table.commit_staged()

        engine = HMIScreenEngine(register_table=reg_table)
        screen = HMIScreen(
            screen_id=1,
            screen_name="Process Screen",
            elements=[
                NumericDataEntry(
                    element_id="ne_speed",
                    bound_register="%R100",
                    engineering_units="RPM",
                ),
                Bargraph(
                    element_id="bg_level",
                    bound_register="%AI1",
                    min_value=0.0,
                    max_value=100.0,
                ),
            ],
        )
        engine.register_screen(screen)

        rendered = engine.render_screen(1)
        ne_rendered = rendered.rendered_elements["ne_speed"]
        bg_rendered = rendered.rendered_elements["bg_level"]

        assert ne_rendered.raw_value == 1250
        assert ne_rendered.display_text == "1250 RPM"

        assert bg_rendered.raw_value == 75
        assert bg_rendered.fill_percentage == 75.0

    def test_render_real_float_consecutive_registers(self):
        reg_table = RegisterTable()
        # Write REAL 45.67 to %R200 (%R200 + %R201)
        reg_table.write_real("%R200", 45.67)
        reg_table.commit_staged()

        engine = HMIScreenEngine(register_table=reg_table)
        screen = HMIScreen(
            screen_id=1,
            screen_name="Float Screen",
            elements=[
                NumericDataEntry(
                    element_id="ne_flow",
                    bound_register="%R200",
                    data_type=NumericDataType.REAL,
                    decimal_places=2,
                    engineering_units="L/min",
                )
            ],
        )
        engine.register_screen(screen)

        rendered = engine.render_screen()
        flow_elem = rendered.rendered_elements["ne_flow"]
        assert pytest.approx(flow_elem.raw_value, rel=1e-4) == 45.67
        assert flow_elem.display_text == "45.67 L/min"

    def test_animation_color_shift_and_blinking(self):
        reg_table = RegisterTable()
        reg_table.write_word("%R50", 95)  # Critical high temperature
        reg_table.commit_staged()

        engine = HMIScreenEngine(register_table=reg_table)
        screen = HMIScreen(
            screen_id=1,
            screen_name="Temp Screen",
            elements=[
                NumericDataEntry(
                    element_id="temp_disp",
                    bound_register="%R50",
                    background_color=ColorRGB.dark_gray(),
                    animation_rules=[
                        AnimationRule(
                            rule_name="overtemp_alarm",
                            condition_type=AnimationConditionType.GREATER_THAN,
                            target_value=90.0,
                            color=ColorRGB.red(),
                            blink=True,
                            priority=5,
                        )
                    ],
                )
            ],
        )
        engine.register_screen(screen)

        rendered = engine.render_screen()
        temp_elem = rendered.rendered_elements["temp_disp"]
        assert temp_elem.effective_background_color.to_hex() == "#FF0000"
        assert temp_elem.is_blinking is True

        # Now lower the temperature and re-render
        reg_table.write_word("%R50", 65)
        reg_table.commit_staged()
        rendered_normal = engine.render_screen()
        temp_norm = rendered_normal.rendered_elements["temp_disp"]
        assert temp_norm.effective_background_color.to_hex() == ColorRGB.dark_gray().to_hex()
        assert temp_norm.is_blinking is False

    def test_dynamic_visibility_via_register(self):
        reg_table = RegisterTable()
        reg_table.write_bit("%M5", False)
        reg_table.commit_staged()

        engine = HMIScreenEngine(register_table=reg_table)
        screen = HMIScreen(
            screen_id=1,
            screen_name="Vis Screen",
            elements=[
                PushButton(
                    element_id="hidden_btn",
                    bound_register="%M1",
                    visibility_register="%M5",
                )
            ],
        )
        engine.register_screen(screen)

        rendered = engine.render_screen()
        assert rendered.rendered_elements["hidden_btn"].is_visible is False
        assert rendered.rendered_elements["hidden_btn"].is_touchable is False

        # Make visible via %M5
        reg_table.write_bit("%M5", True)
        reg_table.commit_staged()
        rendered_vis = engine.render_screen()
        assert rendered_vis.rendered_elements["hidden_btn"].is_visible is True
        assert rendered_vis.rendered_elements["hidden_btn"].is_touchable is True


# ==============================================================================
# 6. Screen Engine Simulated Touch Events Tests
# ==============================================================================

class TestScreenEngineTouchInteractions:
    """Test simulated touch events and RegisterTable memory writebacks."""

    def test_pushbutton_toggle_writeback(self):
        reg_table = RegisterTable()
        assert reg_table.read_bit("%M1") is False

        engine = HMIScreenEngine(register_table=reg_table, auto_commit=True)
        screen = HMIScreen(
            screen_id=1,
            screen_name="Button Screen",
            elements=[
                PushButton(
                    element_id="btn_motor",
                    bound_register="%M1",
                    button_type=PushButtonMode.TOGGLE,
                )
            ],
        )
        engine.register_screen(screen)

        res1 = engine.touch_element("btn_motor", touch_action="TAP")
        assert res1.success is True
        assert res1.new_value is True
        assert reg_table.read_bit("%M1") is True

        res2 = engine.touch_element("btn_motor", touch_action="TAP")
        assert res2.success is True
        assert res2.new_value is False
        assert reg_table.read_bit("%M1") is False

    def test_pushbutton_momentary_press_and_release(self):
        reg_table = RegisterTable()
        engine = HMIScreenEngine(register_table=reg_table, auto_commit=True)
        screen = HMIScreen(
            screen_id=1,
            screen_name="Jog Screen",
            elements=[
                PushButton(
                    element_id="btn_jog",
                    bound_register="%M2",
                    button_type=PushButtonMode.MOMENTARY,
                )
            ],
        )
        engine.register_screen(screen)

        # Press
        res_press = engine.press_pushbutton("btn_jog")
        assert res_press.success is True
        assert reg_table.read_bit("%M2") is True

        # Release
        res_rel = engine.release_pushbutton("btn_jog")
        assert res_rel.success is True
        assert reg_table.read_bit("%M2") is False

    def test_numeric_entry_writeback_to_r_and_aq(self):
        reg_table = RegisterTable()
        engine = HMIScreenEngine(register_table=reg_table, auto_commit=True)
        screen = HMIScreen(
            screen_id=1,
            screen_name="Setpoint Screen",
            elements=[
                NumericDataEntry(
                    element_id="ne_setpoint",
                    bound_register="%R50",
                    data_type=NumericDataType.INT,
                    min_value=0.0,
                    max_value=100.0,
                ),
                NumericDataEntry(
                    element_id="ne_valve_aq",
                    bound_register="%AQ1",
                    data_type=NumericDataType.INT,
                    min_value=0.0,
                    max_value=1000.0,
                ),
            ],
        )
        engine.register_screen(screen)

        # Write to %R50
        res_r = engine.enter_numeric_value("ne_setpoint", 75)
        assert res_r.success is True
        assert reg_table.read_word("%R50") == 75

        # Write to %AQ1 (Analog output)
        res_aq = engine.enter_numeric_value("ne_valve_aq", 850)
        assert res_aq.success is True
        assert reg_table.read_word("%AQ1") == 850

    def test_numeric_entry_bounds_protection(self):
        reg_table = RegisterTable()
        engine = HMIScreenEngine(register_table=reg_table, auto_commit=True)
        screen = HMIScreen(
            screen_id=1,
            screen_name="Bounds Screen",
            elements=[
                NumericDataEntry(
                    element_id="ne_bounded",
                    bound_register="%R10",
                    min_value=10.0,
                    max_value=50.0,
                )
            ],
        )
        engine.register_screen(screen)

        # Out-of-bounds high
        res_high = engine.enter_numeric_value("ne_bounded", 55)
        assert res_high.success is False
        assert res_high.error_code == "OUT_OF_BOUNDS"
        assert reg_table.read_word("%R10") == 0

        # Out-of-bounds low
        res_low = engine.enter_numeric_value("ne_bounded", 5)
        assert res_low.success is False
        assert res_low.error_code == "OUT_OF_BOUNDS"
        assert reg_table.read_word("%R10") == 0

    def test_read_only_element_and_channel_protection(self):
        reg_table = RegisterTable()
        engine = HMIScreenEngine(register_table=reg_table)
        screen = HMIScreen(
            screen_id=1,
            screen_name="RO Screen",
            elements=[
                NumericDataEntry(
                    element_id="ne_ro_display",
                    bound_register="%R1",
                    is_read_only=True,
                ),
                NumericDataEntry(
                    element_id="ne_ai_input",
                    bound_register="%AI1",  # Physical analog input is read-only
                    is_read_only=False,
                ),
            ],
        )
        engine.register_screen(screen)

        # Read-only element
        res_elem_ro = engine.enter_numeric_value("ne_ro_display", 100)
        assert res_elem_ro.success is False
        assert res_elem_ro.error_code == "READ_ONLY_ELEMENT"

        # Read-only channel (%AI)
        res_chan_ro = engine.enter_numeric_value("ne_ai_input", 50)
        assert res_chan_ro.success is False
        assert res_chan_ro.error_code == "READ_ONLY_CHANNEL"

    def test_security_level_access_denial(self):
        reg_table = RegisterTable()
        # Operator security level 0
        engine = HMIScreenEngine(register_table=reg_table, operator_security_level=0)
        screen = HMIScreen(
            screen_id=1,
            screen_name="Security Screen",
            elements=[
                PushButton(
                    element_id="btn_admin_reset",
                    bound_register="%M99",
                    security_level=2,  # Requires supervisor level 2
                )
            ],
        )
        engine.register_screen(screen)

        # Denied
        res_denied = engine.touch_element("btn_admin_reset")
        assert res_denied.success is False
        assert res_denied.error_code == "SECURITY_DENIED"
        assert reg_table.read_bit("%M99") is False

        # Elevated privilege level 2 succeeds
        engine.operator_security_level = 2
        res_allowed = engine.touch_element("btn_admin_reset")
        assert res_allowed.success is True
        assert reg_table.read_bit("%M99") is True

    def test_coordinate_hit_testing(self):
        reg_table = RegisterTable()
        engine = HMIScreenEngine(register_table=reg_table)
        screen = HMIScreen(
            screen_id=1,
            screen_name="Hit Test Screen",
            elements=[
                PushButton(
                    element_id="btn_pos",
                    x=100,
                    y=200,
                    width=100,
                    height=50,
                    bound_register="%M1",
                )
            ],
        )
        engine.register_screen(screen)

        # Hit inside
        res_hit = engine.handle_touch_at(150, 225)
        assert res_hit.success is True
        assert res_hit.element_id == "btn_pos"

        # Hit outside
        res_miss = engine.handle_touch_at(50, 50)
        assert res_miss.success is False
        assert res_miss.error_code == "HIT_MISSED"

    def test_navigation_button_switches_active_screen(self):
        engine = HMIScreenEngine()
        screen1 = HMIScreen(
            screen_id=1,
            screen_name="Main",
            navigation_buttons=[
                NavigationButton(element_id="nav_to_2", target_screen_id=2)
            ],
        )
        screen2 = HMIScreen(
            screen_id=2,
            screen_name="Alarms",
            navigation_buttons=[
                NavigationButton(element_id="nav_to_1", target_screen_id=1)
            ],
        )
        engine.register_screen(screen1)
        engine.register_screen(screen2)

        assert engine.active_screen_id == 1
        res = engine.touch_element("nav_to_2")
        assert res.success is True
        assert res.action == "NAVIGATE"
        assert engine.active_screen_id == 2


# ==============================================================================
# 7. Sample Dashboard Artifact Verification
# ==============================================================================

class TestDashboardArtifact:
    """Test loading and execution of artifacts/HMI/main_dashboard_screen.json."""

    def test_dashboard_json_exists_and_parses(self):
        artifact_path = Path("artifacts/HMI/main_dashboard_screen.json")
        assert artifact_path.exists(), "Artifact main_dashboard_screen.json must exist"

        content = artifact_path.read_text(encoding="utf-8")
        screen = HMIScreen.model_validate_json(content)

        assert screen.screen_id == 1
        assert screen.screen_name == "Main Process Dashboard"
        assert screen.resolution == (800, 480)
        assert len(screen.elements) >= 8
        assert len(screen.navigation_buttons) >= 2

    def test_dashboard_runtime_interaction_and_rendering(self):
        artifact_path = Path("artifacts/HMI/main_dashboard_screen.json")
        screen = HMIScreen.model_validate_json(artifact_path.read_text(encoding="utf-8"))

        reg_table = RegisterTable()
        # Set initial process conditions
        reg_table.force_input("%AI1", 68)  # PV Level = 68% (Physical analog input simulated via force_input)
        reg_table.write_real("%R100", 70.0)  # SP Level = 70.0%
        reg_table.write_bit("%M1", False)  # Pump stopped
        reg_table.commit_staged()

        engine = HMIScreenEngine(register_table=reg_table, auto_commit=True)
        engine.register_screen(screen)

        # 1. Render initial state
        rendered_init = engine.render_screen()
        assert rendered_init.rendered_elements["pump1_start_stop"].display_text == "PUMP STOPPED"
        assert rendered_init.rendered_elements["tank1_level_bargraph"].fill_percentage == 68.0

        # 2. Touch pump start/stop button
        res_btn = engine.touch_element("pump1_start_stop")
        assert res_btn.success is True
        assert reg_table.read_bit("%M1") is True

        # 3. Re-render and observe changed label
        rendered_running = engine.render_screen()
        assert rendered_running.rendered_elements["pump1_start_stop"].display_text == "PUMP RUNNING"

        # 4. Operator enters new SP = 82.5%
        res_sp = engine.enter_numeric_value("level_sp_entry", 82.5)
        assert res_sp.success is True
        assert pytest.approx(reg_table.read_real("%R100"), rel=1e-3) == 82.5

        # 5. Operator enters valve command %AQ1 = 450 mA
        res_valve = engine.enter_numeric_value("valve_out_aq", 450)
        assert res_valve.success is True
        assert reg_table.read_word("%AQ1") == 450

        # 6. Trigger alarm %M10 and verify banner and lamp
        reg_table.write_bit("%M10", True)
        reg_table.commit_staged()
        rendered_alarm = engine.render_screen()

        banner_elem = rendered_alarm.rendered_elements["alarm_banner_1"]
        assert "TANK 1 HIGH HIGH LEVEL ALARM" in banner_elem.active_alarms
        assert banner_elem.is_blinking is True

        alarm_lamp = rendered_alarm.rendered_elements["high_alarm_lamp"]
        assert alarm_lamp.is_blinking is True
        assert alarm_lamp.effective_background_color.to_hex() == "#FF0000"
