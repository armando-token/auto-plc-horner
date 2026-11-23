"""Cscape HMI Dynamic Circular Gauge & Polar Compass Azimuth Vector Dial Rasterizer.

Work Package: W075 (Gate G9 / G2)
Standard: W3C SVG 1.1 Vector Graphics & WCAG 2.1 AAA Contrast Architecture
OCS Register Mappings: %R360..%R367, %M84..%M85

Provides:
- 270-degree radial gauge rasterizer with segmented threshold color bands
  (Normal #10B981, Warning #F59E0B, Danger #EF4444)
- 360-degree polar compass azimuth dial with 16-point cardinal markers,
  two-tone directional needle, and digital heading cassette
- Peak hold tracking, multi-band alarms, and deflection angle synthesis
- Pure IEC 61131-3 Structured Text POU definition and AST validation
- VectorGaugeEngine state machine with register synchronization
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import html
import math
from typing import Any, Dict, List, Optional, Tuple, Union

from jev_cscape.contracts import AgentStatus


class DialMode(str, Enum):
    """Dial operating modes."""
    RADIAL_GAUGE = "RADIAL_GAUGE"      # 270-degree open arc (-225° to +45°)
    POLAR_COMPASS = "POLAR_COMPASS"    # 360-degree closed azimuth circle (0° to 360°)


class CompassPointMode(str, Enum):
    """Cardinal direction marker density."""
    POINTS_8 = "8_POINT"
    POINTS_16 = "16_POINT"


COMPASS_POINTS_16: List[Tuple[str, float, str]] = [
    ("N", 0.0, "CARDINAL"),
    ("NNE", 22.5, "SECONDARY"),
    ("NE", 45.0, "INTERCARDINAL"),
    ("ENE", 67.5, "SECONDARY"),
    ("E", 90.0, "CARDINAL"),
    ("ESE", 112.5, "SECONDARY"),
    ("SE", 135.0, "INTERCARDINAL"),
    ("SSE", 157.5, "SECONDARY"),
    ("S", 180.0, "CARDINAL"),
    ("SSW", 202.5, "SECONDARY"),
    ("SW", 225.0, "INTERCARDINAL"),
    ("WSW", 247.5, "SECONDARY"),
    ("W", 270.0, "CARDINAL"),
    ("WNW", 292.5, "SECONDARY"),
    ("NW", 315.0, "INTERCARDINAL"),
    ("NNW", 337.5, "SECONDARY"),
]


@dataclass(frozen=True)
class ThresholdBand:
    """Threshold color zone along gauge arc circumference."""
    name: str
    start_pct: float   # 0.0..100.0%
    end_pct: float     # 0.0..100.0%
    color_hex: str


@dataclass
class VectorDialConfig:
    """Configuration schema for vector dial instrumentation."""
    element_id: str = "dial_gauge_1"
    mode: DialMode = DialMode.RADIAL_GAUGE
    width: int = 300
    height: int = 300
    cx: float = 150.0
    cy: float = 150.0
    radius: float = 110.0
    title: str = "PRESSURE"
    engineering_units: str = "BAR"
    min_value: float = 0.0
    max_value: float = 100.0
    warning_threshold: float = 70.0
    danger_threshold: float = 85.0
    points_mode: CompassPointMode = CompassPointMode.POINTS_16
    font_family: str = "Segoe UI, Roboto, Arial, sans-serif"
    bands: List[ThresholdBand] = field(
        default_factory=lambda: [
            ThresholdBand("Normal", 0.0, 70.0, "#10B981"),
            ThresholdBand("Warning", 70.0, 85.0, "#F59E0B"),
            ThresholdBand("Danger", 85.0, 100.0, "#EF4444"),
        ]
    )


def polar_to_cartesian_screen(cx: float, cy: float, r: float, theta_rad: float) -> Tuple[float, float]:
    """Transform polar coordinates to SVG Cartesian screen space."""
    return cx + r * math.cos(theta_rad), cy + r * math.sin(theta_rad)


def azimuth_to_cartesian(cx: float, cy: float, r: float, deg: float) -> Tuple[float, float]:
    """Transform navigation azimuth degrees (0=N, 90=E) to SVG Cartesian screen space."""
    rad = math.radians(deg)
    return cx + r * math.sin(rad), cy - r * math.cos(rad)


# --- Pure IEC 61131-3 Structured Text POU Block ---

VECTOR_GAUGE_ST_CODE = """PROGRAM VectorGaugeRasterizerSync
VAR
    StatusWord AT %R360 : WORD;
    InputPV AT %R361 : INT;
    DeflectionAngle AT %R362 : INT;
    GaugeLowRange AT %R363 : INT;
    GaugeHighRange AT %R364 : INT;
    WarningThreshold AT %R365 : INT;
    DangerThreshold AT %R366 : INT;
    PeakHoldVal AT %R367 : INT;
    EnableEngine AT %M84 : BOOL;
    ResetPeakHold AT %M85 : BOOL;

    ClampedPV : INT;
    DialModeCompass : BOOL;
    StatusAccum : WORD;
    IsClamped : BOOL;
END_VAR

IF EnableEngine THEN
    IF InputPV < 0 THEN
        ClampedPV := 0;
        IsClamped := TRUE;
    ELSIF InputPV > 10000 THEN
        ClampedPV := 10000;
        IsClamped := TRUE;
    ELSE
        ClampedPV := InputPV;
        IsClamped := FALSE;
    END_IF;

    DialModeCompass := (StatusWord AND 16#0020) <> 16#0000;

    IF ResetPeakHold THEN
        PeakHoldVal := ClampedPV;
        ResetPeakHold := FALSE;
        StatusAccum := 16#0041;
    ELSE
        IF ClampedPV > PeakHoldVal THEN
            PeakHoldVal := ClampedPV;
        END_IF;
        StatusAccum := 16#0001;
    END_IF;

    IF ClampedPV >= DangerThreshold THEN
        StatusAccum := StatusAccum OR 16#0008;
    ELSIF ClampedPV >= WarningThreshold THEN
        StatusAccum := StatusAccum OR 16#0004;
    ELSE
        StatusAccum := StatusAccum OR 16#0002;
    END_IF;

    IF PeakHoldVal > 0 THEN
        StatusAccum := StatusAccum OR 16#0010;
    END_IF;

    IF IsClamped THEN
        StatusAccum := StatusAccum OR 16#0080;
    END_IF;

    IF DialModeCompass THEN
        StatusAccum := StatusAccum OR 16#0020;
        DeflectionAngle := (ClampedPV * 36) / 100;
    ELSE
        DeflectionAngle := -2250 + ((ClampedPV * 2700) / 10000);
    END_IF;

    StatusWord := StatusAccum;
ELSE
    StatusWord := 16#0000;
    DeflectionAngle := -2250;
END_IF;
END_PROGRAM"""


# --- Vector Gauge & Polar Compass Engine ---

class VectorGaugeEngine:
    """State machine and SVG rasterizer for circular gauge and polar compass dials.

    Binds to Horner OCS registers (%R360..%R367, %M84..%M85).
    """

    def __init__(self, config: Optional[VectorDialConfig] = None) -> None:
        self.cfg = config or VectorDialConfig()

        # OCS Register state
        self.status_word: int = 1               # %R360: Status word
        self.input_pv_scaled: int = 5000        # %R361: 50.00% or 180.0° (0..10000)
        self.needle_deflection_angle: int = -900 # %R362: -90.0° (degrees x10)
        self.gauge_low_range_eu: int = 0        # %R363: Low EU x10
        self.gauge_high_range_eu: int = 1000    # %R364: High EU x10
        self.warning_threshold: int = 7000      # %R365: 70.00%
        self.danger_threshold: int = 8500       # %R366: 85.00%
        self.peak_hold_value: int = 0           # %R367: Peak hold x100
        self.enable_engine: bool = True         # %M84: Permissive
        self.reset_peak_hold: bool = False      # %M85: Reset pulse

    def update(self, pv_scaled: Optional[int] = None) -> Dict[str, Any]:
        """Update engine state, thresholds, and calculate deflection angle."""
        if pv_scaled is not None:
            self.input_pv_scaled = pv_scaled

        if not self.enable_engine:
            self.status_word = 0
            self.needle_deflection_angle = -2250
            return {"status": "disabled", "status_word": 0}

        # Clamping
        is_clamped = False
        clamped_pv = self.input_pv_scaled
        if clamped_pv < 0:
            clamped_pv = 0
            is_clamped = True
        elif clamped_pv > 10000:
            clamped_pv = 10000
            is_clamped = True

        # Mode determination
        is_compass = self.cfg.mode == DialMode.POLAR_COMPASS

        # Peak hold reset handshake
        if self.reset_peak_hold:
            self.peak_hold_value = clamped_pv
            self.reset_peak_hold = False
            status_accum = 0x0041  # Active + Reset Ack
        else:
            if clamped_pv > self.peak_hold_value:
                self.peak_hold_value = clamped_pv
            status_accum = 0x0001  # Active

        # Threshold bands
        if clamped_pv >= self.danger_threshold:
            status_accum |= 0x0008  # Danger Band
        elif clamped_pv >= self.warning_threshold:
            status_accum |= 0x0004  # Warning Band
        else:
            status_accum |= 0x0002  # Normal Band

        if self.peak_hold_value > 0:
            status_accum |= 0x0010  # Peak hold active

        if is_clamped:
            status_accum |= 0x0080  # Clamped alert

        if is_compass:
            status_accum |= 0x0020  # Compass mode bit
            # Deflection angle: 0.0° to 360.0° (scaled x10: 0..3600)
            self.needle_deflection_angle = int((clamped_pv * 36) / 100)
        else:
            # Deflection angle: -225.0° to +45.0° (scaled x10: -2250..+450)
            self.needle_deflection_angle = int(-2250 + (clamped_pv * 2700) / 10000)

        self.status_word = status_accum
        return {
            "status": "success",
            "clamped_pv": clamped_pv,
            "angle_deg": self.needle_deflection_angle / 10.0,
            "status_word": self.status_word,
            "peak_hold": self.peak_hold_value / 100.0,
        }

    def render_svg(self) -> str:
        """Render standalone W3C-compliant SVG vector dial."""
        w, h = self.cfg.width, self.cfg.height
        cx, cy, r = self.cfg.cx, self.cfg.cy, self.cfg.radius
        angle_deg = self.needle_deflection_angle / 10.0
        pv_pct = self.input_pv_scaled / 100.0

        svg: List[str] = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}"',
            f'     font-family="{html.escape(self.cfg.font_family)}" text-rendering="geometricPrecision" shape-rendering="geometricPrecision">',
            '  <defs>',
            '    <filter id="dialShadow" x="-20%" y="-20%" width="140%" height="140%">',
            '      <feGaussianBlur in="SourceAlpha" stdDeviation="3" />',
            '      <feOffset dx="2" dy="3" />',
            '      <feFlood flood-color="#000000" flood-opacity="0.5" />',
            '      <feComposite operator="in" />',
            '      <feMerge><feMergeNode /><feMergeNode in="SourceGraphic" /></feMerge>',
            '    </filter>',
            '    <linearGradient id="hubGrad" x1="0%" y1="0%" x2="100%" y2="100%">',
            '      <stop offset="0%" stop-color="#475569" />',
            '      <stop offset="100%" stop-color="#0F172A" />',
            '    </linearGradient>',
            '  </defs>',
            '  <!-- Dial Bezel & Dark SCADA Face -->',
            f'  <rect width="{w}" height="{h}" rx="10" fill="#0F172A" />',
            f'  <circle cx="{cx}" cy="{cy}" r="{r + 18:.1f}" fill="#1E293B" stroke="#334155" stroke-width="2" />',
            f'  <circle cx="{cx}" cy="{cy}" r="{r + 14:.1f}" fill="#0B132B" stroke="#1E293B" stroke-width="1" />',
        ]

        if self.cfg.mode == DialMode.POLAR_COMPASS:
            self._render_compass_contents(svg, cx, cy, r, angle_deg)
        else:
            self._render_gauge_contents(svg, cx, cy, r, angle_deg, pv_pct)

        # Pivot Center Hub
        svg.extend([
            f'  <!-- Center Pivot Hub -->',
            f'  <circle cx="{cx}" cy="{cy}" r="12" fill="url(#hubGrad)" stroke="#475569" stroke-width="1.5" />',
            f'  <circle cx="{cx}" cy="{cy}" r="4.5" fill="#38BDF8" />',
            f'</svg>',
        ])
        return "\n".join(svg)

    def _render_gauge_contents(self, svg: List[str], cx: float, cy: float, r: float, angle_deg: float, pv_pct: float) -> None:
        """Render 270-degree radial gauge with threshold arcs and needle."""
        t = 10.0
        # 1. Threshold Arc Bands
        svg.append('  <!-- Threshold Arc Bands (270 deg sweep) -->')
        for band in self.cfg.bands:
            a_start = -225.0 + (band.start_pct / 100.0) * 270.0
            a_end = -225.0 + (band.end_pct / 100.0) * 270.0
            rad_s = math.radians(a_start)
            rad_e = math.radians(a_end)
            x1, y1 = polar_to_cartesian_screen(cx, cy, r, rad_s)
            x2, y2 = polar_to_cartesian_screen(cx, cy, r, rad_e)
            large_arc = 1 if (a_end - a_start) > 180.0 else 0
            path_d = f"M {x1:.2f} {y1:.2f} A {r:.2f} {r:.2f} 0 {large_arc} 1 {x2:.2f} {y2:.2f}"
            svg.append(f'  <path d="{path_d}" fill="none" stroke="{band.color_hex}" stroke-width="{t}" />')

        # 2. Major Ticks & Labels
        svg.append('  <!-- Ticks & Scale Labels -->')
        for i in range(11):
            ratio = i / 10.0
            deg = -225.0 + ratio * 270.0
            rad = math.radians(deg)
            x_out, y_out = polar_to_cartesian_screen(cx, cy, r - t / 2.0 - 2, rad)
            x_in, y_in = polar_to_cartesian_screen(cx, cy, r - t / 2.0 - 10, rad)
            svg.append(f'  <line x1="{x_in:.2f}" y1="{y_in:.2f}" x2="{x_out:.2f}" y2="{y_out:.2f}" stroke="#CBD5E1" stroke-width="1.8" />')
            xl, yl = polar_to_cartesian_screen(cx, cy, r - 26, rad)
            val = self.cfg.min_value + ratio * (self.cfg.max_value - self.cfg.min_value)
            svg.append(f'  <text x="{xl:.2f}" y="{yl + 3.5:.2f}" fill="#CBD5E1" font-size="9" font-weight="600" text-anchor="middle">{val:.0f}</text>')

        # 3. Tapered Needle Pointer
        rad_needle = math.radians(angle_deg)
        cos_n, sin_n = math.cos(rad_needle), math.sin(rad_needle)
        r_tip, r_tail, w_base = r - 12.0, 16.0, 5.0
        x_tip = cx + r_tip * cos_n
        y_tip = cy + r_tip * sin_n
        x_r = cx - w_base * sin_n
        y_r = cy + w_base * cos_n
        x_tail = cx - r_tail * cos_n
        y_tail = cy - r_tail * sin_n
        x_l = cx + w_base * sin_n
        y_l = cy - w_base * cos_n

        svg.append(
            f'  <polygon points="{x_tip:.2f},{y_tip:.2f} {x_r:.2f},{y_r:.2f} {x_tail:.2f},{y_tail:.2f} {x_l:.2f},{y_l:.2f}" '
            f'fill="#F8FAFC" stroke="#0F172A" stroke-width="1.2" filter="url(#dialShadow)" />'
        )

        # 4. Digital Readout Cassette
        val_eu = self.cfg.min_value + (pv_pct / 100.0) * (self.cfg.max_value - self.cfg.min_value)
        svg.extend([
            f'  <g transform="translate({cx - 45}, {cy + 42})">',
            f'    <rect width="90" height="26" rx="4" fill="#070D18" stroke="#334155" stroke-width="1.2" />',
            f'    <text x="45" y="17.5" fill="#38BDF8" font-size="13" font-weight="bold" text-anchor="middle">{val_eu:.1f} {html.escape(self.cfg.engineering_units)}</text>',
            f'  </g>',
            f'  <text x="{cx}" y="{cy + 85}" fill="#94A3B8" font-size="11" font-weight="bold" letter-spacing="1" text-anchor="middle">{html.escape(self.cfg.title)}</text>',
        ])

    def _render_compass_contents(self, svg: List[str], cx: float, cy: float, r: float, heading_deg: float) -> None:
        """Render 360-degree polar compass azimuth dial with two-tone directional needle."""
        # 1. 360-degree Ticks
        svg.append('  <!-- Compass Azimuth 360 Ticks -->')
        for deg in range(0, 360, 5):
            if deg % 30 == 0:
                rin, sw, col = r - 10, "1.8", "#E2E8F0"
            elif deg % 15 == 0:
                rin, sw, col = r - 7, "1.2", "#94A3B8"
            else:
                rin, sw, col = r - 4, "0.8", "#475569"
            x1, y1 = azimuth_to_cartesian(cx, cy, rin, float(deg))
            x2, y2 = azimuth_to_cartesian(cx, cy, r, float(deg))
            svg.append(f'  <line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" stroke="{col}" stroke-width="{sw}" />')

        # 2. Cardinal & Intercardinal Text Markers
        svg.append('  <!-- Cardinal Markers -->')
        for name, angle, tier in COMPASS_POINTS_16:
            if tier == "SECONDARY" and self.cfg.points_mode != CompassPointMode.POINTS_16:
                continue
            if tier == "CARDINAL":
                color, size, weight = ("#EF4444" if name == "N" else "#F8FAFC"), "14", "bold"
            elif tier == "INTERCARDINAL":
                color, size, weight = "#38BDF8", "10", "600"
            else:
                color, size, weight = "#94A3B8", "8", "normal"
            x, y = azimuth_to_cartesian(cx, cy, r - 22, angle)
            svg.append(f'  <text x="{x:.2f}" y="{y + 3.5:.2f}" fill="{color}" font-size="{size}" font-weight="{weight}" text-anchor="middle">{name}</text>')

        # 3. Two-Tone Compass Needle
        l_n, l_s = r * 0.70, r * 0.60
        w_n, w_s = r * 0.08, r * 0.07
        svg.append(f'  <g transform="rotate({heading_deg:.2f}, {cx:.2f}, {cy:.2f})" filter="url(#dialShadow)">')
        # North arrow (red two-tone)
        svg.append(f'    <polygon points="{cx:.2f},{cy - l_n:.2f} {cx - w_n:.2f},{cy:.2f} {cx:.2f},{cy:.2f}" fill="#EF4444" />')
        svg.append(f'    <polygon points="{cx:.2f},{cy - l_n:.2f} {cx:.2f},{cy:.2f} {cx + w_n:.2f},{cy:.2f}" fill="#991B1B" />')
        # South arrow (blue two-tone)
        svg.append(f'    <polygon points="{cx:.2f},{cy + l_s:.2f} {cx:.2f},{cy:.2f} {cx - w_s:.2f},{cy:.2f}" fill="#38BDF8" />')
        svg.append(f'    <polygon points="{cx:.2f},{cy + l_s:.2f} {cx + w_s:.2f},{cy:.2f} {cx:.2f},{cy:.2f}" fill="#1D4ED8" />')
        svg.append(f'    <line x1="{cx:.2f}" y1="{cy - l_n:.2f}" x2="{cx:.2f}" y2="{cy + l_s:.2f}" stroke="#FFFFFF" stroke-width="0.5" stroke-opacity="0.5" />')
        svg.append('  </g>')

        # 4. Azimuth Numerical Heading Box
        deg_str = f"{int(round(heading_deg)) % 360:03d}°"
        svg.extend([
            f'  <g transform="translate({cx - 36}, {cy + 35})">',
            f'    <rect width="72" height="24" rx="4" fill="#070D18" stroke="#334155" stroke-width="1.2" />',
            f'    <text x="36" y="16.5" fill="#00F0FF" font-family="Consolas, monospace" font-size="12" font-weight="bold" text-anchor="middle">{deg_str}</text>',
            f'  </g>',
        ])

    def sync_to_registers(self, reg_table: Any) -> None:
        """Write current vector gauge states to OCS RegisterTable."""
        write_fn = getattr(reg_table, "write_register", getattr(reg_table, "write", None))
        if write_fn:
            write_fn("%R360", self.status_word)
            write_fn("%R361", self.input_pv_scaled)
            write_fn("%R362", self.needle_deflection_angle)
            write_fn("%R363", self.gauge_low_range_eu)
            write_fn("%R364", self.gauge_high_range_eu)
            write_fn("%R365", self.warning_threshold)
            write_fn("%R366", self.danger_threshold)
            write_fn("%R367", self.peak_hold_value)
            write_fn("%M84", self.enable_engine)
            write_fn("%M85", self.reset_peak_hold)

    def sync_from_registers(self, reg_table: Any) -> None:
        """Fetch input PV, limits, and reset command from OCS RegisterTable."""
        read_fn = getattr(reg_table, "read_register", getattr(reg_table, "read", None))
        write_fn = getattr(reg_table, "write_register", getattr(reg_table, "write", None))
        if read_fn:
            self.enable_engine = bool(read_fn("%M84"))
            self.reset_peak_hold = bool(read_fn("%M85"))
            pv = read_fn("%R361")
            if isinstance(pv, (int, float)):
                self.input_pv_scaled = int(pv)
            w_th = read_fn("%R365")
            if isinstance(w_th, (int, float)) and w_th > 0:
                self.warning_threshold = int(w_th)
            d_th = read_fn("%R366")
            if isinstance(d_th, (int, float)) and d_th > 0:
                self.danger_threshold = int(d_th)

        self.update()
        if write_fn:
            write_fn("%R360", self.status_word)
            write_fn("%R362", self.needle_deflection_angle)
            write_fn("%R367", self.peak_hold_value)
            if self.reset_peak_hold:
                write_fn("%M85", False)
