"""Horner OCS HMI Screen Engine and Runtime Execution Environment.

Work Package: W020 (Gate G4)
Classification: TESTED_MOCK [offline/DEV only]

Manages active screen lifecycle, binds Horner OCS RegisterTable memory to graphical
elements, renders dynamic screen states, evaluates animation rules, and processes
simulated operator touch events (pushbutton actuations, numeric keypad input, and screen
navigation) with strict security level validation and memory channel protection.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pydantic import BaseModel, Field

from jev_cscape.automation.channel_matrix import ChannelAccess
from jev_cscape.simulation.register_table import (
    PrivilegeMode,
    ReadOnlyChannelError,
    RegisterTable,
)
from jev_cscape.hmi.models import (
    AlarmBanner,
    AnimationRule,
    Bargraph,
    ColorRGB,
    HMIElementType,
    HMIScreen,
    HMIScreenElement,
    IndicatorLamp,
    NavigationButton,
    NumericDataEntry,
    NumericDataType,
    PushButton,
    PushButtonMode,
    TrendChart,
)


class RenderedElement(BaseModel):
    """Rendered graphical element state for an HMI screen cycle."""
    element_id: str = Field(..., description="Element ID")
    element_type: HMIElementType = Field(..., description="Element type")
    x: int = Field(..., description="Pixel X")
    y: int = Field(..., description="Pixel Y")
    width: int = Field(..., description="Pixel width")
    height: int = Field(..., description="Pixel height")
    bound_register: Optional[str] = Field(default=None, description="Bound register")
    raw_value: Any = Field(default=None, description="Raw register value")
    display_text: str = Field(default="", description="Rendered display string")
    fill_percentage: Optional[float] = Field(default=None, description="Bargraph fill percentage (0..100)")
    effective_background_color: ColorRGB = Field(..., description="Calculated background color")
    effective_foreground_color: ColorRGB = Field(..., description="Calculated foreground/text color")
    is_visible: bool = Field(default=True, description="Whether currently visible")
    is_touchable: bool = Field(default=True, description="Whether currently interactive")
    is_blinking: bool = Field(default=False, description="Whether element is in blinking state")
    is_alarm_active: bool = Field(default=False, description="Alarm state flag")
    trend_values: Dict[str, float] = Field(default_factory=dict, description="Current pen values for trend")
    active_alarms: List[str] = Field(default_factory=list, description="Active alarm messages for banner")


class RenderedScreen(BaseModel):
    """Complete rendered state snapshot of an active Horner OCS HMI screen."""
    screen_id: int = Field(..., description="Screen ID")
    screen_name: str = Field(..., description="Screen name")
    resolution: Tuple[int, int] = Field(..., description="Screen resolution")
    background_color: ColorRGB = Field(..., description="Screen canvas color")
    rendered_elements: Dict[str, RenderedElement] = Field(
        default_factory=dict,
        description="Keyed map of element_id to RenderedElement"
    )
    rendered_navigation_buttons: List[RenderedElement] = Field(
        default_factory=list,
        description="Rendered navigation buttons"
    )


class TouchResult(BaseModel):
    """Result payload of a simulated HMI touch interaction."""
    success: bool = Field(..., description="Whether touch action succeeded")
    element_id: Optional[str] = Field(default=None, description="Target element ID")
    action: str = Field(..., description="Performed touch action")
    new_value: Any = Field(default=None, description="Resulting register value after action")
    error_code: Optional[str] = Field(default=None, description="Error code if failed")
    message: str = Field(default="", description="Descriptive status message")
    navigated_to_screen_id: Optional[int] = Field(default=None, description="New active screen ID if navigated")


class HMIScreenEngine:
    """Horner OCS HMI Screen Engine and Runtime Execution Environment.

    Binds an in-memory RegisterTable to one or more HMIScreen layouts, evaluating
    animations and handling simulated touch actions.
    """

    def __init__(
        self,
        register_table: Optional[RegisterTable] = None,
        operator_security_level: int = 0,
        auto_commit: bool = True,
    ) -> None:
        self.register_table: RegisterTable = register_table if register_table is not None else RegisterTable()
        self.screens: Dict[int, HMIScreen] = {}
        self.active_screen_id: Optional[int] = None
        self.operator_security_level: int = int(operator_security_level)
        self.auto_commit: bool = auto_commit
        self.acknowledged_alarms: Set[str] = set()

    # --- Screen Management ---

    def register_screen(self, screen: HMIScreen) -> None:
        """Register an HMI screen with the engine."""
        self.screens[screen.screen_id] = screen
        if self.active_screen_id is None:
            self.active_screen_id = screen.screen_id

    def add_screen(self, screen: HMIScreen) -> None:
        """Alias for register_screen."""
        self.register_screen(screen)

    def set_active_screen(self, screen_id: int) -> HMIScreen:
        """Switch the engine's active screen."""
        if screen_id not in self.screens:
            raise KeyError(f"Screen ID {screen_id} is not registered in HMIScreenEngine.")
        self.active_screen_id = screen_id
        return self.screens[screen_id]

    @property
    def active_screen(self) -> HMIScreen:
        """Return the currently active HMIScreen."""
        if self.active_screen_id is None or self.active_screen_id not in self.screens:
            raise RuntimeError("No active screen is currently set in HMIScreenEngine.")
        return self.screens[self.active_screen_id]

    def get_screen(self, screen_id: int) -> Optional[HMIScreen]:
        """Retrieve screen by ID or None."""
        return self.screens.get(screen_id)

    # --- Register Reading & Evaluation ---

    def read_element_value(self, element: HMIScreenElement) -> Any:
        """Read current live value from RegisterTable for an element's bound_register."""
        if not element.bound_register:
            return None

        clean_reg = RegisterTable.normalize_address(element.bound_register)
        reg_addr = self.register_table.parse_address(clean_reg)

        # Discrete bit channels (%I, %Q, %M, %D, %S) or bit-slice (%R.b)
        if reg_addr.is_bit_slice or reg_addr.channel_type.element_type == "BOOL":
            return self.register_table.read_bit(clean_reg)

        # Word channels (%R, %AI, %AQ, %SR, %AIG, %AQG)
        if isinstance(element, NumericDataEntry):
            if element.data_type == NumericDataType.REAL:
                return self.register_table.read_real(clean_reg)
            elif element.data_type == NumericDataType.DINT:
                return self.register_table.read_dint(clean_reg)
            elif element.data_type == NumericDataType.UDINT:
                return self.register_table.read_udint(clean_reg)
            elif element.data_type == NumericDataType.UINT:
                return self.register_table.read_uword(clean_reg)
            else:
                return self.register_table.read_word(clean_reg)

        return self.register_table.read_word(clean_reg)

    def evaluate_element_visibility(self, element: HMIScreenElement) -> bool:
        """Evaluate static and dynamic visibility flags for an element."""
        if not element.is_visible:
            return False
        if element.visibility_register:
            clean_reg = RegisterTable.normalize_address(element.visibility_register)
            return bool(self.register_table.read_bit(clean_reg))
        return True

    def evaluate_animation_rules(
        self,
        element: HMIScreenElement,
        element_value: Any,
    ) -> Tuple[ColorRGB, ColorRGB, bool]:
        """Evaluate element animation rules to compute effective colors and blinking.

        Returns (effective_background_color, effective_foreground_color, is_blinking).
        """
        # Determine baseline colors based on element archetype defaults
        bg = element.background_color or ColorRGB.dark_gray()
        fg = element.foreground_color or ColorRGB.white()
        blink = False

        if isinstance(element, PushButton):
            bg = element.on_color if bool(element_value) else element.off_color
        elif isinstance(element, IndicatorLamp):
            if element.multi_state_colors and element_value in element.multi_state_colors:
                bg = element.multi_state_colors[element_value]
            elif bool(element_value):
                bg = element.on_color
            else:
                bg = element.off_color
        elif isinstance(element, Bargraph):
            num_val = float(element_value or 0.0)
            if element.is_alarm_active(num_val):
                bg = element.alarm_color or ColorRGB.red()
            else:
                bg = element.fill_color
        elif isinstance(element, AlarmBanner):
            bg = element.banner_color
        elif isinstance(element, NavigationButton):
            bg = element.button_color

        # Sort animation rules by ascending priority (highest priority overrides)
        sorted_rules = sorted(element.animation_rules, key=lambda r: r.priority)

        for rule in sorted_rules:
            # Condition register source
            if rule.condition_register:
                cond_clean = RegisterTable.normalize_address(rule.condition_register)
                cond_addr = self.register_table.parse_address(cond_clean)
                if cond_addr.is_bit_slice or cond_addr.channel_type.element_type == "BOOL":
                    val_to_eval = self.register_table.read_bit(cond_clean)
                else:
                    val_to_eval = self.register_table.read_word(cond_clean)
            else:
                val_to_eval = element_value

            if rule.evaluate(val_to_eval):
                if rule.target_property == "background_color":
                    bg = rule.color
                elif rule.target_property == "foreground_color":
                    fg = rule.color
                if rule.blink:
                    blink = True

        return bg, fg, blink

    # --- Screen Rendering ---

    def render_element(self, element: HMIScreenElement) -> RenderedElement:
        """Render a single HMIScreenElement against RegisterTable memory."""
        is_vis = self.evaluate_element_visibility(element)
        raw_val = self.read_element_value(element) if is_vis else None
        bg_col, fg_col, is_blink = self.evaluate_animation_rules(element, raw_val)

        display_txt = element.label
        fill_pct: Optional[float] = None
        alarm_active = False
        trend_vals: Dict[str, float] = {}
        active_alarms_list: List[str] = []

        if isinstance(element, PushButton):
            display_txt = element.on_label if bool(raw_val) else element.off_label
        elif isinstance(element, NumericDataEntry):
            display_txt = element.format_value(raw_val)
        elif isinstance(element, Bargraph):
            num_v = float(raw_val or 0.0)
            fill_pct = element.calculate_fill_percentage(num_v)
            alarm_active = element.is_alarm_active(num_v)
            display_txt = f"{num_v:.1f}%" if not element.label else f"{element.label}: {num_v:.1f}%"
        elif isinstance(element, IndicatorLamp):
            display_txt = element.legend_text or ("ON" if bool(raw_val) else "OFF")
        elif isinstance(element, TrendChart):
            for pen in element.pens:
                clean_pen = pen.bound_register
                try:
                    p_addr = self.register_table.parse_address(clean_pen)
                    if p_addr.channel_type.element_type == "BOOL" or p_addr.is_bit_slice:
                        v = 1.0 if self.register_table.read_bit(clean_pen) else 0.0
                    else:
                        v = float(self.register_table.read_word(clean_pen))
                    trend_vals[clean_pen] = v
                except Exception:
                    trend_vals[clean_pen] = 0.0
            display_txt = element.label or "Trend Chart"
        elif isinstance(element, AlarmBanner):
            for alarm in element.alarms:
                try:
                    is_active = self.register_table.read_bit(alarm.bit_register)
                    if is_active:
                        alarm_active = True
                        active_alarms_list.append(alarm.message)
                except Exception:
                    pass
            display_txt = " | ".join(active_alarms_list) if active_alarms_list else "SYSTEM OK - NO ALARMS"
            if active_alarms_list and element.flash_unack:
                is_blink = True
        elif isinstance(element, NavigationButton):
            display_txt = element.label or (element.target_screen_name or f"Screen {element.target_screen_id}")

        return RenderedElement(
            element_id=element.element_id,
            element_type=element.element_type,
            x=element.x,
            y=element.y,
            width=element.width,
            height=element.height,
            bound_register=element.bound_register,
            raw_value=raw_val,
            display_text=display_txt,
            fill_percentage=fill_pct,
            effective_background_color=bg_col,
            effective_foreground_color=fg_col,
            is_visible=is_vis,
            is_touchable=element.is_touchable and is_vis,
            is_blinking=is_blink,
            is_alarm_active=alarm_active,
            trend_values=trend_vals,
            active_alarms=active_alarms_list,
        )

    def render_screen(self, screen_id: Optional[int] = None) -> RenderedScreen:
        """Render the complete active or specified screen."""
        target_id = screen_id if screen_id is not None else self.active_screen_id
        if target_id is None or target_id not in self.screens:
            raise KeyError(f"Screen ID {target_id} not found in HMIScreenEngine.")

        screen = self.screens[target_id]
        rendered_elems: Dict[str, RenderedElement] = {}
        for elem in screen.elements:
            rendered_elems[elem.element_id] = self.render_element(elem)

        rendered_navs: List[RenderedElement] = []
        for nav in screen.navigation_buttons:
            rendered_navs.append(self.render_element(nav))

        return RenderedScreen(
            screen_id=screen.screen_id,
            screen_name=screen.screen_name,
            resolution=screen.resolution,
            background_color=screen.background_color,
            rendered_elements=rendered_elems,
            rendered_navigation_buttons=rendered_navs,
        )

    # --- Simulated Touch Handling ---

    def handle_touch_at(
        self,
        x: int,
        y: int,
        touch_action: str = "TAP",
        value: Any = None,
    ) -> TouchResult:
        """Simulate touch event by screen coordinates (x, y).

        Hit-tests elements in reverse z-order (topmost first) including navigation buttons.
        """
        screen = self.active_screen

        # Check navigation buttons first
        for nav in reversed(screen.navigation_buttons):
            if nav.contains_point(x, y):
                return self.touch_element(nav.element_id, touch_action=touch_action, value=value)

        # Check screen elements
        for elem in reversed(screen.elements):
            if elem.contains_point(x, y):
                return self.touch_element(elem.element_id, touch_action=touch_action, value=value)

        return TouchResult(
            success=False,
            action=touch_action,
            error_code="HIT_MISSED",
            message=f"No interactive element found at coordinates ({x}, {y})",
        )

    def touch_element(
        self,
        element_id: str,
        touch_action: str = "TAP",
        value: Any = None,
    ) -> TouchResult:
        """Simulate touch interaction directly on a specific element ID."""
        screen = self.active_screen
        element = screen.get_element(element_id)

        if element is None:
            return TouchResult(
                success=False,
                element_id=element_id,
                action=touch_action,
                error_code="ELEMENT_NOT_FOUND",
                message=f"Element '{element_id}' does not exist on active screen {screen.screen_id}.",
            )

        # Security permission check
        if self.operator_security_level < element.security_level:
            return TouchResult(
                success=False,
                element_id=element_id,
                action=touch_action,
                error_code="SECURITY_DENIED",
                message=(
                    f"Operator security level {self.operator_security_level} is insufficient. "
                    f"Element '{element_id}' requires level {element.security_level}."
                ),
            )

        # Visibility and touchability check
        if not element.is_touchable or not self.evaluate_element_visibility(element):
            return TouchResult(
                success=False,
                element_id=element_id,
                action=touch_action,
                error_code="NOT_INTERACTIVE",
                message=f"Element '{element_id}' is hidden or non-touchable.",
            )

        # Navigation Button handling
        if isinstance(element, NavigationButton):
            dest_id = element.target_screen_id
            if dest_id not in self.screens:
                return TouchResult(
                    success=False,
                    element_id=element_id,
                    action="NAVIGATE",
                    error_code="INVALID_TARGET_SCREEN",
                    message=f"Destination screen ID {dest_id} does not exist.",
                )
            self.set_active_screen(dest_id)
            return TouchResult(
                success=True,
                element_id=element_id,
                action="NAVIGATE",
                navigated_to_screen_id=dest_id,
                new_value=dest_id,
                message=f"Navigated to screen {dest_id} ('{element.target_screen_name or dest_id}').",
            )

        # PushButton handling
        if isinstance(element, PushButton):
            if not element.bound_register:
                return TouchResult(
                    success=False,
                    element_id=element_id,
                    action=touch_action,
                    error_code="UNBOUND_REGISTER",
                    message=f"PushButton '{element_id}' has no bound_register configured.",
                )

            clean_reg = RegisterTable.normalize_address(element.bound_register)
            new_bit_val: bool

            if element.button_type == PushButtonMode.TOGGLE:
                current_bit = self.register_table.read_bit(clean_reg)
                new_bit_val = not current_bit
                self.register_table.write_bit(clean_reg, new_bit_val)
            elif element.button_type == PushButtonMode.MOMENTARY:
                if touch_action in ("PRESS", "TAP"):
                    new_bit_val = True
                    element.is_pressed = True
                elif touch_action == "RELEASE":
                    new_bit_val = False
                    element.is_pressed = False
                else:
                    new_bit_val = True
                self.register_table.write_bit(clean_reg, new_bit_val)
            elif element.button_type == PushButtonMode.SET:
                new_bit_val = True
                self.register_table.write_bit(clean_reg, True)
            elif element.button_type == PushButtonMode.RESET:
                new_bit_val = False
                self.register_table.write_bit(clean_reg, False)
            else:
                return TouchResult(
                    success=False,
                    element_id=element_id,
                    action=touch_action,
                    error_code="UNKNOWN_BUTTON_MODE",
                    message=f"Unknown button mode '{element.button_type}'.",
                )

            if self.auto_commit:
                self.register_table.commit_staged()

            return TouchResult(
                success=True,
                element_id=element_id,
                action=touch_action,
                new_value=new_bit_val,
                message=f"PushButton '{element_id}' wrote {new_bit_val} to {clean_reg}.",
            )

        # NumericDataEntry handling
        if isinstance(element, NumericDataEntry):
            if element.is_read_only:
                return TouchResult(
                    success=False,
                    element_id=element_id,
                    action=touch_action,
                    error_code="READ_ONLY_ELEMENT",
                    message=f"NumericDataEntry '{element_id}' is configured as read-only.",
                )

            if value is None:
                return TouchResult(
                    success=False,
                    element_id=element_id,
                    action=touch_action,
                    error_code="MISSING_VALUE",
                    message=f"No numeric value provided for NumericDataEntry '{element_id}'.",
                )

            try:
                num_val = float(value)
            except (ValueError, TypeError):
                return TouchResult(
                    success=False,
                    element_id=element_id,
                    action=touch_action,
                    error_code="INVALID_NUMERIC_FORMAT",
                    message=f"Value '{value}' could not be parsed as a number.",
                )

            # Bounds validation
            if num_val < element.min_value or num_val > element.max_value:
                return TouchResult(
                    success=False,
                    element_id=element_id,
                    action=touch_action,
                    error_code="OUT_OF_BOUNDS",
                    message=(
                        f"Value {num_val} violates configured bounds "
                        f"[{element.min_value}, {element.max_value}]."
                    ),
                )

            if not element.bound_register:
                return TouchResult(
                    success=False,
                    element_id=element_id,
                    action=touch_action,
                    error_code="UNBOUND_REGISTER",
                    message=f"NumericDataEntry '{element_id}' has no bound_register.",
                )

            clean_reg = RegisterTable.normalize_address(element.bound_register)

            # Write to RegisterTable with channel protection
            try:
                if element.data_type == NumericDataType.REAL:
                    self.register_table.write_real(clean_reg, float(num_val))
                elif element.data_type == NumericDataType.DINT:
                    self.register_table.write_dint(clean_reg, int(round(num_val)))
                elif element.data_type == NumericDataType.UDINT:
                    self.register_table.write_udint(clean_reg, int(round(num_val)))
                elif element.data_type == NumericDataType.UINT:
                    self.register_table.write_word(clean_reg, int(round(num_val)) & 0xFFFF)
                else:
                    self.register_table.write_word(clean_reg, int(round(num_val)))

                if self.auto_commit:
                    self.register_table.commit_staged()

            except ReadOnlyChannelError as ro_err:
                return TouchResult(
                    success=False,
                    element_id=element_id,
                    action=touch_action,
                    error_code="READ_ONLY_CHANNEL",
                    message=str(ro_err),
                )

            return TouchResult(
                success=True,
                element_id=element_id,
                action="ENTER_VALUE",
                new_value=num_val,
                message=f"Wrote {num_val} to {clean_reg}.",
            )

        # AlarmBanner interaction (Acknowledge Alarms)
        if isinstance(element, AlarmBanner):
            for alarm in element.alarms:
                self.acknowledged_alarms.add(alarm.bit_register)
            return TouchResult(
                success=True,
                element_id=element_id,
                action="ACK_ALARMS",
                message="All active alarms acknowledged.",
            )

        return TouchResult(
            success=False,
            element_id=element_id,
            action=touch_action,
            error_code="UNSUPPORTED_ELEMENT_INTERACTION",
            message=f"Element archetype '{element.element_type}' does not accept touch inputs.",
        )

    # --- Convenience Helpers ---

    def press_pushbutton(self, element_id: str) -> TouchResult:
        """Simulate touch press on a pushbutton element."""
        return self.touch_element(element_id, touch_action="PRESS")

    def release_pushbutton(self, element_id: str) -> TouchResult:
        """Simulate touch release on a pushbutton element."""
        return self.touch_element(element_id, touch_action="RELEASE")

    def enter_numeric_value(self, element_id: str, value: Union[int, float]) -> TouchResult:
        """Simulate numeric keypad value entry on a NumericDataEntry element."""
        return self.touch_element(element_id, touch_action="ENTER_VALUE", value=value)
