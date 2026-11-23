"""Horner OCS HMI Screen Object Models and Graphics Primitives.

Work Package: W020 (Gate G4)
Classification: TESTED_MOCK [offline/DEV only]

Defines data models for Horner APG OCS HMI screens and graphical elements
(Pushbuttons, Numeric Entry/Display, Bargraphs, Indicator Lamps, Trend Charts,
and Alarm Banners), color representations, animation rules, and screen layouts
targeting Horner OCS XL7 / P1 (800x480 WVGA) and related operator interfaces.
"""

from __future__ import annotations

from enum import Enum
import math
import re
from typing import Annotated, Any, Dict, List, Literal, Optional, Tuple, Union
from pydantic import BaseModel, Field, field_validator, model_validator

from jev_cscape.simulation.register_table import RegisterTable


class HMIElementType(str, Enum):
    """Horner OCS HMI graphical screen element types."""
    PUSHBUTTON = "PUSHBUTTON"
    NUMERIC_ENTRY = "NUMERIC_ENTRY"
    BARGRAPH = "BARGRAPH"
    INDICATOR_LAMP = "INDICATOR_LAMP"
    TREND_CHART = "TREND_CHART"
    ALARM_BANNER = "ALARM_BANNER"
    NAVIGATION_BUTTON = "NAVIGATION_BUTTON"


class PushButtonMode(str, Enum):
    """Operating modes for Horner OCS HMI Pushbutton objects."""
    TOGGLE = "TOGGLE"          # Toggles bit state on each press
    MOMENTARY = "MOMENTARY"    # High while pressed, low when released
    SET = "SET"                # Forces bit to 1 on press
    RESET = "RESET"            # Forces bit to 0 on press


class NumericDataType(str, Enum):
    """Numeric data encoding across Horner OCS registers."""
    INT = "INT"      # 16-bit signed integer (-32768..32767)
    UINT = "UINT"    # 16-bit unsigned integer (0..65535)
    DINT = "DINT"    # 32-bit signed integer (consecutive registers)
    UDINT = "UDINT"  # 32-bit unsigned integer (consecutive registers)
    REAL = "REAL"    # 32-bit IEEE 754 single-precision float


class BargraphOrientation(str, Enum):
    """Orientation of Bargraph elements."""
    VERTICAL = "VERTICAL"
    HORIZONTAL = "HORIZONTAL"


class IndicatorLampShape(str, Enum):
    """Geometric shape of Indicator Lamp elements."""
    ROUND = "ROUND"
    RECTANGULAR = "RECTANGULAR"


class AnimationConditionType(str, Enum):
    """Condition comparison types for HMI dynamic color animation rules."""
    BOOLEAN = "BOOLEAN"              # True when boolean state matches target_value
    EQUAL = "EQUAL"                  # Equal to target_value
    NOT_EQUAL = "NOT_EQUAL"          # Not equal to target_value
    GREATER_THAN = "GREATER_THAN"    # Register value > target_value
    LESS_THAN = "LESS_THAN"          # Register value < target_value
    GREATER_EQUAL = "GREATER_EQUAL"  # Register value >= target_value
    LESS_EQUAL = "LESS_EQUAL"        # Register value <= target_value
    RANGE = "RANGE"                  # min_value <= value <= max_value


class ColorRGB(BaseModel):
    """RGB/RGBA Color representation for Horner OCS HMI graphic elements."""
    r: int = Field(default=0, ge=0, le=255, description="Red component (0-255)")
    g: int = Field(default=0, ge=0, le=255, description="Green component (0-255)")
    b: int = Field(default=0, ge=0, le=255, description="Blue component (0-255)")
    a: float = Field(default=1.0, ge=0.0, le=1.0, description="Alpha opacity (0.0-1.0)")

    def to_hex(self, include_alpha: bool = False) -> str:
        """Format color as uppercase hexadecimal string."""
        if include_alpha:
            alpha_int = int(round(self.a * 255))
            return f"#{self.r:02X}{self.g:02X}{self.b:02X}{alpha_int:02X}"
        return f"#{self.r:02X}{self.g:02X}{self.b:02X}"

    @classmethod
    def from_hex(cls, hex_str: str) -> "ColorRGB":
        """Parse RGB/RGBA color from hex string (#RGB, #RRGGBB, #RRGGBBAA)."""
        clean = hex_str.strip().lstrip("#")
        if len(clean) == 3:
            r = int(clean[0] * 2, 16)
            g = int(clean[1] * 2, 16)
            b = int(clean[2] * 2, 16)
            return cls(r=r, g=g, b=b, a=1.0)
        elif len(clean) == 6:
            r = int(clean[0:2], 16)
            g = int(clean[2:4], 16)
            b = int(clean[4:6], 16)
            return cls(r=r, g=g, b=b, a=1.0)
        elif len(clean) == 8:
            r = int(clean[0:2], 16)
            g = int(clean[2:4], 16)
            b = int(clean[4:6], 16)
            a = round(int(clean[6:8], 16) / 255.0, 3)
            return cls(r=r, g=g, b=b, a=a)
        raise ValueError(f"Invalid hexadecimal color format: '{hex_str}'")

    # Standard industrial color presets
    @classmethod
    def black(cls) -> "ColorRGB":
        return cls(r=0, g=0, b=0)

    @classmethod
    def white(cls) -> "ColorRGB":
        return cls(r=255, g=255, b=255)

    @classmethod
    def red(cls) -> "ColorRGB":
        return cls(r=255, g=0, b=0)

    @classmethod
    def green(cls) -> "ColorRGB":
        return cls(r=0, g=255, b=0)

    @classmethod
    def blue(cls) -> "ColorRGB":
        return cls(r=0, g=120, b=255)

    @classmethod
    def yellow(cls) -> "ColorRGB":
        return cls(r=255, g=255, b=0)

    @classmethod
    def amber(cls) -> "ColorRGB":
        return cls(r=255, g=191, b=0)

    @classmethod
    def dark_gray(cls) -> "ColorRGB":
        return cls(r=40, g=40, b=40)

    @classmethod
    def light_gray(cls) -> "ColorRGB":
        return cls(r=200, g=200, b=200)

    @classmethod
    def panel_bg(cls) -> "ColorRGB":
        return cls(r=30, g=30, b=30)


class AnimationRule(BaseModel):
    """Dynamic styling animation rule based on bit or word register states.

    Allows elements to dynamically alter colors (background, text/foreground, border)
    or blink based on Horner register conditions.
    """
    rule_name: str = Field(default="default_rule", description="Descriptive rule label")
    condition_register: Optional[str] = Field(
        default=None,
        description="Register to evaluate. If None, uses element's bound_register."
    )
    condition_type: AnimationConditionType = Field(
        default=AnimationConditionType.BOOLEAN,
        description="Type of comparison"
    )
    target_value: Optional[Union[bool, int, float, str]] = Field(
        default=None,
        description="Target value for BOOLEAN, EQUAL, NOT_EQUAL, or threshold comparisons"
    )
    min_value: Optional[float] = Field(
        default=None,
        description="Lower range bound for RANGE condition"
    )
    max_value: Optional[float] = Field(
        default=None,
        description="Upper range bound for RANGE condition"
    )
    target_property: str = Field(
        default="background_color",
        description="Property to animate: 'background_color', 'foreground_color', 'border_color'"
    )
    color: ColorRGB = Field(..., description="Applied color when rule condition matches")
    blink: bool = Field(default=False, description="Whether element blinks when active")
    priority: int = Field(default=0, description="Evaluation priority (higher wins on conflict)")

    @field_validator("condition_register")
    @classmethod
    def validate_register(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return RegisterTable.normalize_address(v)
        return None

    def evaluate(self, current_val: Any) -> bool:
        """Evaluate if the condition holds true for current_val."""
        if current_val is None:
            return False

        if self.condition_type == AnimationConditionType.BOOLEAN:
            expected = bool(self.target_value) if self.target_value is not None else True
            return bool(current_val) == expected

        try:
            num_val = float(current_val)
        except (ValueError, TypeError):
            # Non-numeric fallback for EQUAL/NOT_EQUAL
            if self.condition_type == AnimationConditionType.EQUAL:
                return current_val == self.target_value
            elif self.condition_type == AnimationConditionType.NOT_EQUAL:
                return current_val != self.target_value
            return False

        if self.condition_type == AnimationConditionType.EQUAL:
            if self.target_value is None:
                return False
            return math.isclose(num_val, float(self.target_value), rel_tol=1e-5, abs_tol=1e-5)
        elif self.condition_type == AnimationConditionType.NOT_EQUAL:
            if self.target_value is None:
                return True
            return not math.isclose(num_val, float(self.target_value), rel_tol=1e-5, abs_tol=1e-5)
        elif self.condition_type == AnimationConditionType.GREATER_THAN:
            return num_val > float(self.target_value or 0.0)
        elif self.condition_type == AnimationConditionType.LESS_THAN:
            return num_val < float(self.target_value or 0.0)
        elif self.condition_type == AnimationConditionType.GREATER_EQUAL:
            return num_val >= float(self.target_value or 0.0)
        elif self.condition_type == AnimationConditionType.LESS_EQUAL:
            return num_val <= float(self.target_value or 0.0)
        elif self.condition_type == AnimationConditionType.RANGE:
            low_ok = self.min_value is None or num_val >= self.min_value
            high_ok = self.max_value is None or num_val <= self.max_value
            return low_ok and high_ok

        return False


class HMIScreenElement(BaseModel):
    """Base model for all Horner OCS graphical screen objects."""
    element_id: str = Field(..., description="Unique element identifier on screen")
    element_type: HMIElementType = Field(..., description="Element archetype")
    x: int = Field(default=0, ge=0, description="X coordinate in pixels")
    y: int = Field(default=0, ge=0, description="Y coordinate in pixels")
    width: int = Field(default=100, gt=0, description="Width in pixels")
    height: int = Field(default=40, gt=0, description="Height in pixels")
    label: str = Field(default="", description="Descriptive label or legend")
    bound_register: Optional[str] = Field(
        default=None,
        description="Bound Horner OCS register reference (%M, %D, %R, %AI, %AQ, %I, %Q, %SR)"
    )
    security_level: int = Field(
        default=0,
        ge=0,
        le=15,
        description="Operator security level required to interact (0=Public/Operator, 1+=Supervisor)"
    )
    is_visible: bool = Field(default=True, description="Static visibility flag")
    is_touchable: bool = Field(default=True, description="Touch interactivity flag")
    visibility_register: Optional[str] = Field(
        default=None,
        description="Optional bit register driving dynamic visibility (%M, %D, %I, %Q)"
    )
    background_color: Optional[ColorRGB] = Field(default=None, description="Base background color")
    foreground_color: Optional[ColorRGB] = Field(default=None, description="Base text/foreground color")
    border_color: Optional[ColorRGB] = Field(default=None, description="Border color")
    animation_rules: List[AnimationRule] = Field(
        default_factory=list,
        description="Dynamic color/state animation rules"
    )

    @field_validator("bound_register", "visibility_register")
    @classmethod
    def validate_registers(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.strip():
            return RegisterTable.normalize_address(v)
        return None

    def contains_point(self, px: int, py: int) -> bool:
        """Hit test checking if (px, py) is within the bounding rectangle."""
        return (self.x <= px <= self.x + self.width) and (self.y <= py <= self.y + self.height)


class PushButton(HMIScreenElement):
    """Horner OCS Pushbutton element for discrete bit control."""
    element_type: Literal[HMIElementType.PUSHBUTTON] = HMIElementType.PUSHBUTTON
    button_type: PushButtonMode = Field(
        default=PushButtonMode.TOGGLE,
        description="PushButton operational mode: TOGGLE, MOMENTARY, SET, RESET"
    )
    on_label: str = Field(default="ON", description="Label displayed when bound bit is True")
    off_label: str = Field(default="OFF", description="Label displayed when bound bit is False")
    on_color: ColorRGB = Field(
        default_factory=lambda: ColorRGB(r=0, g=200, b=0),
        description="Background color when ON"
    )
    off_color: ColorRGB = Field(
        default_factory=lambda: ColorRGB(r=80, g=80, b=80),
        description="Background color when OFF"
    )
    confirm_dialog: bool = Field(
        default=False,
        description="Whether operator must confirm before state changes"
    )
    is_pressed: bool = Field(default=False, description="Transient physical touch press state")


class NumericDataEntry(HMIScreenElement):
    """Horner OCS Numeric Data Entry and Display element."""
    element_type: Literal[HMIElementType.NUMERIC_ENTRY] = HMIElementType.NUMERIC_ENTRY
    data_type: NumericDataType = Field(
        default=NumericDataType.INT,
        description="Register data encoding: INT, UINT, DINT, UDINT, REAL"
    )
    format_string: Optional[str] = Field(
        default=None,
        description="Custom printf-style format string (e.g. '%.2f', '%5d')"
    )
    decimal_places: int = Field(default=0, ge=0, le=6, description="Number of decimal places")
    min_value: float = Field(default=-32768.0, description="Minimum acceptable entry value")
    max_value: float = Field(default=32767.0, description="Maximum acceptable entry value")
    engineering_units: str = Field(default="", description="Units suffix (e.g. 'PSI', '°C', 'RPM')")
    is_read_only: bool = Field(
        default=False,
        description="If True, behaves as display-only; if False, allows touch keypad entry"
    )

    def format_value(self, raw_val: Union[int, float, None]) -> str:
        """Format numeric value according to data type, decimal places, and units."""
        if raw_val is None:
            return f"--- {self.engineering_units}".strip()

        if self.format_string:
            try:
                base = self.format_string % raw_val
            except Exception:
                base = str(raw_val)
        elif self.data_type == NumericDataType.REAL:
            base = f"{float(raw_val):.{self.decimal_places}f}"
        else:
            if self.decimal_places > 0:
                base = f"{float(raw_val):.{self.decimal_places}f}"
            else:
                base = f"{int(round(float(raw_val)))}"

        if self.engineering_units:
            return f"{base} {self.engineering_units}"
        return base


class Bargraph(HMIScreenElement):
    """Horner OCS Bargraph indicator for process variable visualization."""
    element_type: Literal[HMIElementType.BARGRAPH] = HMIElementType.BARGRAPH
    orientation: BargraphOrientation = Field(
        default=BargraphOrientation.VERTICAL,
        description="Display orientation: VERTICAL or HORIZONTAL"
    )
    min_value: float = Field(default=0.0, description="Lower scale limit")
    max_value: float = Field(default=100.0, description="Upper scale limit")
    fill_color: ColorRGB = Field(
        default_factory=lambda: ColorRGB(r=0, g=150, b=255),
        description="Normal bar fill color"
    )
    empty_color: ColorRGB = Field(
        default_factory=lambda: ColorRGB(r=50, g=50, b=50),
        description="Empty background color behind bar"
    )
    low_alarm_limit: Optional[float] = Field(default=None, description="Low alarm trip point")
    high_alarm_limit: Optional[float] = Field(default=None, description="High alarm trip point")
    alarm_color: Optional[ColorRGB] = Field(
        default_factory=lambda: ColorRGB(r=255, g=0, b=0),
        description="Color when value trips alarm limits"
    )
    show_ticks: bool = Field(default=True, description="Render scale tick marks")

    def calculate_fill_percentage(self, value: float) -> float:
        """Calculate clamped bar fill percentage [0.0, 100.0]."""
        span = self.max_value - self.min_value
        if span <= 0:
            return 0.0
        pct = ((value - self.min_value) / span) * 100.0
        return max(0.0, min(100.0, pct))

    def is_alarm_active(self, value: float) -> bool:
        """Check whether value violates configured low or high alarm limits."""
        if self.low_alarm_limit is not None and value <= self.low_alarm_limit:
            return True
        if self.high_alarm_limit is not None and value >= self.high_alarm_limit:
            return True
        return False


class IndicatorLamp(HMIScreenElement):
    """Horner OCS Indicator Lamp element for discrete or multi-state status display."""
    element_type: Literal[HMIElementType.INDICATOR_LAMP] = HMIElementType.INDICATOR_LAMP
    shape: IndicatorLampShape = Field(
        default=IndicatorLampShape.ROUND,
        description="Geometric shape: ROUND or RECTANGULAR"
    )
    on_color: ColorRGB = Field(
        default_factory=lambda: ColorRGB(r=0, g=255, b=0),
        description="Color when state is True / 1"
    )
    off_color: ColorRGB = Field(
        default_factory=lambda: ColorRGB(r=40, g=40, b=40),
        description="Color when state is False / 0"
    )
    legend_text: str = Field(default="", description="Legend text inside or alongside lamp")
    multi_state_colors: Optional[Dict[int, ColorRGB]] = Field(
        default=None,
        description="Optional dictionary mapping integer word values to distinct colors"
    )


class TrendPen(BaseModel):
    """Configuration for a single trend pen in TrendChart."""
    bound_register: str = Field(..., description="Horner register address e.g. %AI1, %R100")
    label: str = Field(default="", description="Pen descriptive label")
    color: ColorRGB = Field(..., description="Trace color")
    min_val: float = Field(default=0.0, description="Scale minimum for this pen")
    max_val: float = Field(default=100.0, description="Scale maximum for this pen")

    @property
    def register(self) -> str:
        """Compatibility property for register address."""
        return self.bound_register

    @field_validator("bound_register")
    @classmethod
    def validate_pen_reg(cls, v: str) -> str:
        return RegisterTable.normalize_address(v)


class TrendChart(HMIScreenElement):
    """Horner OCS Real-time Trend Chart element."""
    element_type: Literal[HMIElementType.TREND_CHART] = HMIElementType.TREND_CHART
    pen_registers: List[str] = Field(
        default_factory=list,
        description="List of bound register addresses for trending"
    )
    pen_colors: List[ColorRGB] = Field(
        default_factory=list,
        description="Colors corresponding to pen_registers"
    )
    pens: List[TrendPen] = Field(
        default_factory=list,
        description="Structured pen configurations"
    )
    time_span_seconds: int = Field(default=60, gt=0, description="Horizontal time window in seconds")
    min_y: float = Field(default=0.0, description="Vertical minimum scale")
    max_y: float = Field(default=100.0, description="Vertical maximum scale")
    sample_rate_ms: int = Field(default=1000, gt=0, description="Sample acquisition period in ms")
    grid_lines: bool = Field(default=True, description="Display background grid lines")

    @model_validator(mode="after")
    def sync_pens(self) -> "TrendChart":
        """Synchronize pen_registers/pen_colors with pens list."""
        if not self.pens and self.pen_registers:
            colors = self.pen_colors or [ColorRGB.blue()] * len(self.pen_registers)
            for i, reg in enumerate(self.pen_registers):
                c = colors[i] if i < len(colors) else ColorRGB.blue()
                self.pens.append(TrendPen(bound_register=reg, label=reg, color=c, min_val=self.min_y, max_val=self.max_y))
        elif self.pens and not self.pen_registers:
            self.pen_registers = [p.bound_register for p in self.pens]
            self.pen_colors = [p.color for p in self.pens]
        return self


class AlarmItem(BaseModel):
    """Alarm definition for AlarmBanner."""
    alarm_id: str = Field(..., description="Unique alarm identifier")
    bit_register: str = Field(..., description="Trigger bit register (%M, %D, %I, %Q)")
    message: str = Field(..., description="Alarm announcement text")
    severity: str = Field(default="HIGH", description="Severity: INFO, WARNING, HIGH, CRITICAL")
    color: Optional[ColorRGB] = Field(default=None, description="Custom banner color when active")

    @field_validator("bit_register")
    @classmethod
    def validate_alarm_bit(cls, v: str) -> str:
        return RegisterTable.normalize_address(v)


class AlarmBanner(HMIScreenElement):
    """Horner OCS Alarm Banner element for annunciating active plant alarms."""
    element_type: Literal[HMIElementType.ALARM_BANNER] = HMIElementType.ALARM_BANNER
    max_displayed_alarms: int = Field(default=5, gt=0, description="Maximum visible alarms")
    alarm_bits: List[str] = Field(
        default_factory=list,
        description="List of bit registers driving alarms"
    )
    alarm_messages: Dict[str, str] = Field(
        default_factory=dict,
        description="Mapping from register address to alarm description"
    )
    alarms: List[AlarmItem] = Field(
        default_factory=list,
        description="Structured alarm definitions"
    )
    banner_color: ColorRGB = Field(
        default_factory=lambda: ColorRGB(r=200, g=30, b=30),
        description="Banner background color when alarms are active"
    )
    flash_unack: bool = Field(default=True, description="Flash banner on unacknowledged alarms")

    @model_validator(mode="after")
    def sync_alarms(self) -> "AlarmBanner":
        """Synchronize alarm_bits/alarm_messages with alarms list."""
        if not self.alarms and self.alarm_bits:
            for bit in self.alarm_bits:
                clean_bit = RegisterTable.normalize_address(bit)
                msg = self.alarm_messages.get(clean_bit, f"Alarm active on {clean_bit}")
                self.alarms.append(AlarmItem(alarm_id=clean_bit, bit_register=clean_bit, message=msg))
        elif self.alarms and not self.alarm_bits:
            self.alarm_bits = [a.bit_register for a in self.alarms]
            self.alarm_messages = {a.bit_register: a.message for a in self.alarms}
        return self


class NavigationButton(HMIScreenElement):
    """Button for switching between Horner OCS HMI screens."""
    element_type: Literal[HMIElementType.NAVIGATION_BUTTON] = HMIElementType.NAVIGATION_BUTTON
    target_screen_id: int = Field(..., ge=1, description="ID of destination screen")
    target_screen_name: Optional[str] = Field(default=None, description="Name of destination screen")
    button_color: ColorRGB = Field(
        default_factory=lambda: ColorRGB(r=70, g=70, b=90),
        description="Navigation button color"
    )


# Union type allowing discriminated polymorphism across HMI screen elements
HMIElementUnion = Annotated[
    Union[
        PushButton,
        NumericDataEntry,
        Bargraph,
        IndicatorLamp,
        TrendChart,
        AlarmBanner,
        NavigationButton,
    ],
    Field(discriminator="element_type"),
]


class HMIScreen(BaseModel):
    """Horner OCS Complete Screen Layout and Graphical Definition.

    Standard Horner OCS XL7 / P1 screen resolution is 800x480 WVGA.
    Supports both graphical element layout and topological supervisory navigation.
    """
    screen_id: int = Field(..., ge=1, description="Unique screen number (1..65535)")
    screen_name: Optional[str] = Field(default=None, description="Descriptive screen name")
    name: Optional[str] = Field(default=None, description="Screen name alias for navigation")
    subtitle: Optional[str] = Field(default=None, description="Optional subtitle")
    description: Optional[str] = Field(default=None, description="Optional description")
    required_permission: Any = Field(default="OPERATOR", description="Required security level")
    active_register: Optional[str] = Field(default=None, description="Screen active bit register (%D)")
    category: Optional[str] = Field(default="GENERAL", description="Screen category")
    resolution: Tuple[int, int] = Field(
        default=(800, 480),
        description="Screen pixel dimensions (Width, Height). Default: 800x480 for Horner XL7/P1"
    )
    background_color: ColorRGB = Field(
        default_factory=lambda: ColorRGB(r=30, g=30, b=30),
        description="Screen background canvas color"
    )
    elements: List[HMIElementUnion] = Field(
        default_factory=list,
        description="Ordered list of graphical screen elements"
    )
    navigation_buttons: List[NavigationButton] = Field(
        default_factory=list,
        description="Screen-level navigation buttons"
    )

    @model_validator(mode="before")
    @classmethod
    def pre_sync_names(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "name" in data and "screen_name" not in data:
                data["screen_name"] = data["name"]
            elif "screen_name" in data and "name" not in data:
                data["name"] = data["screen_name"]
        return data

    @model_validator(mode="after")
    def post_sync_names(self) -> "HMIScreen":
        if self.screen_name is None and self.name is not None:
            self.screen_name = self.name
        elif self.name is None and self.screen_name is not None:
            self.name = self.screen_name
        return self

    @property
    def display_name(self) -> str:
        """Formatted display name including subtitle if distinct."""
        n = self.name or self.screen_name or f"Screen {self.screen_id}"
        if self.subtitle and self.subtitle != n:
            return f"{n} ({self.subtitle})"
        return n

    @property
    def width(self) -> int:
        """Width in pixels from resolution tuple."""
        return self.resolution[0]

    @property
    def height(self) -> int:
        """Height in pixels from resolution tuple."""
        return self.resolution[1]

    def add_element(self, element: HMIScreenElement) -> None:
        """Add a graphical element to the screen."""
        self.elements.append(element)  # type: ignore[arg-type]

    def get_element(self, element_id: str) -> Optional[HMIScreenElement]:
        """Look up an element by its ID among elements and navigation buttons."""
        for elem in self.elements:
            if elem.element_id == element_id:
                return elem
        for nav in self.navigation_buttons:
            if nav.element_id == element_id:
                return nav
        return None

    def remove_element(self, element_id: str) -> bool:
        """Remove an element by ID. Returns True if removed."""
        for i, elem in enumerate(self.elements):
            if elem.element_id == element_id:
                self.elements.pop(i)
                return True
        for i, nav in enumerate(self.navigation_buttons):
            if nav.element_id == element_id:
                self.navigation_buttons.pop(i)
                return True
        return False
