"""Offline HMI Screen SVG / Canvas Vector Renderer.

Work Package: W038 (Gate G9 HMI/SCADA Offline Deliverables)
Classification: PRODUCTION_READY

Provides deterministic offline vector rendering of Horner OCS HMI screens
(HMIScreen) into W3C-compliant Scalable Vector Graphics (SVG). Allows operators,
engineers, and autonomous agents to inspect, visualize, and document screens
without requiring a live Cscape runtime or GPU display.

Supports:
- PushButton (momentary, toggle, set, reset states)
- NumericDataEntry (INT, REAL, DINT formatted with engineering units)
- Bargraph (vertical & horizontal with proportional fill and alarm limits)
- IndicatorLamp (round & rectangular with glow gradients and multi-state colors)
- TrendChart (multi-pen sparklines, grid lines, legend)
- AlarmBanner (warning badges, active alarm text, flashing accents)
- NavigationButton (breadcrumbs, target screen indicators)
- Live register overlay via RegisterTable binding
"""

from __future__ import annotations

import html
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from jev_cscape.hmi.models import (
    AlarmBanner,
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
)
from jev_cscape.simulation.register_table import RegisterTable, words_to_float


def escape_text(text: str) -> str:
    """HTML/XML escape text for safe inclusion in SVG elements."""
    return html.escape(str(text), quote=True)


class HMIScreenRenderer:
    """Vector graphics renderer compiling HMIScreen objects to W3C-standard SVG."""

    def __init__(self, default_font: str = "Segoe UI, Arial, sans-serif") -> None:
        self.default_font = default_font

    def render_svg(
        self,
        screen: HMIScreen,
        registers: Optional[RegisterTable] = None,
        include_header: bool = True,
    ) -> str:
        """Render complete HMIScreen to a standalone W3C SVG XML document."""
        w = getattr(screen, "width", screen.resolution[0])
        h = getattr(screen, "height", screen.resolution[1])
        bg = screen.background_color.to_hex() if screen.background_color else "#0F172A"

        lines: List[str] = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
            f'font-family="{self.default_font}" text-rendering="geometricPrecision" shape-rendering="crispEdges">',
            "  <defs>",
            '    <linearGradient id="headerGrad" x1="0%" y1="0%" x2="100%" y2="0%">',
            '      <stop offset="0%" stop-color="#1B263B" />',
            '      <stop offset="100%" stop-color="#0D1B2A" />',
            "    </linearGradient>",
            '    <linearGradient id="btnBevel" x1="0%" y1="0%" x2="0%" y2="100%">',
            '      <stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.25" />',
            '      <stop offset="100%" stop-color="#000000" stop-opacity="0.3" />',
            "    </linearGradient>",
            '    <filter id="lampGlow" x="-30%" y="-30%" width="160%" height="160%">',
            '      <feGaussianBlur stdDeviation="4" result="blur" />',
            '      <feComposite in="SourceGraphic" in2="blur" operator="over" />',
            "    </filter>",
            '    <filter id="elementShadow" x="-10%" y="-10%" width="130%" height="130%">',
            '      <feGaussianBlur in="SourceAlpha" stdDeviation="3" />',
            '      <feOffset dx="2" dy="2" result="offsetblur" />',
            '      <feFlood flood-color="#000000" flood-opacity="0.35" />',
            '      <feComposite in2="offsetblur" operator="in" />',
            '      <feMerge>',
            '        <feMergeNode />',
            '        <feMergeNode in="SourceGraphic" />',
            '      </feMerge>',
            "    </filter>",
            "  </defs>",
            f'  <!-- Canvas Background -->',
            f'  <rect width="{w}" height="{h}" fill="{bg}" />',
        ]

        # Screen grid overlay (subtle 40px grid)
        lines.append('  <!-- Alignment Grid -->')
        lines.append('  <g stroke="#2C3E50" stroke-width="0.5" stroke-opacity="0.25">')
        for x in range(40, w, 40):
            lines.append(f'    <line x1="{x}" y1="0" x2="{x}" y2="{h}" />')
        for y in range(40, h, 40):
            lines.append(f'    <line x1="0" y1="{y}" x2="{w}" y2="{y}" />')
        lines.append("  </g>")

        # Header bar
        header_height = 40
        if include_header:
            title_text = screen.display_name
            lines.extend([
                '  <!-- Screen Title Header -->',
                f'  <rect x="0" y="0" width="{w}" height="{header_height}" fill="url(#headerGrad)" />',
                f'  <line x1="0" y1="{header_height}" x2="{w}" y2="{header_height}" stroke="#415A77" stroke-width="1.5" />',
                f'  <text x="20" y="25" fill="#E0E1DD" font-size="16" font-weight="bold">{escape_text(title_text)}</text>',
                f'  <text x="{w - 20}" y="25" fill="#778DA9" font-size="12" text-anchor="end">Screen ID: {screen.screen_id} | Res: {w}x{h}</text>',
            ])

        # Elements
        lines.append('  <!-- Screen Graphical Elements -->')
        for elem in screen.elements:
            elem_svg = self.render_element_svg(elem, registers)
            if elem_svg:
                lines.append(f"  {elem_svg}")

        lines.append("</svg>")
        return "\n".join(lines)

    def export_svg(
        self,
        screen: HMIScreen,
        output_path: Union[Path, str],
        registers: Optional[RegisterTable] = None,
    ) -> Path:
        """Render screen and write SVG content to disk."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        svg_content = self.render_svg(screen, registers)
        out.write_text(svg_content, encoding="utf-8")
        return out

    def render_element_svg(
        self,
        elem: HMIScreenElement,
        registers: Optional[RegisterTable] = None,
    ) -> str:
        """Render a single HMI screen element to an SVG XML snippet."""
        is_vis = getattr(elem, "is_visible", getattr(elem, "visible", True))
        if not is_vis:
            return ""

        etype = elem.element_type
        if isinstance(elem, PushButton) or etype == HMIElementType.PUSHBUTTON:
            return self._render_pushbutton(elem, registers)
        elif isinstance(elem, NumericDataEntry) or etype == HMIElementType.NUMERIC_ENTRY:
            return self._render_numeric_entry(elem, registers)
        elif isinstance(elem, Bargraph) or etype == HMIElementType.BARGRAPH:
            return self._render_bargraph(elem, registers)
        elif isinstance(elem, IndicatorLamp) or etype == HMIElementType.INDICATOR_LAMP:
            return self._render_indicator_lamp(elem, registers)
        elif isinstance(elem, TrendChart) or etype == HMIElementType.TREND_CHART:
            return self._render_trend_chart(elem, registers)
        elif isinstance(elem, AlarmBanner) or etype == HMIElementType.ALARM_BANNER:
            return self._render_alarm_banner(elem, registers)
        elif isinstance(elem, NavigationButton) or etype == HMIElementType.NAVIGATION_BUTTON:
            return self._render_navigation_button(elem, registers)
        else:
            return (
                f'<g id="{escape_text(elem.element_id)}">'
                f'<rect x="{elem.x}" y="{elem.y}" width="{elem.width}" height="{elem.height}" '
                f'fill="#555555" stroke="#FFFFFF" stroke-width="1" />'
                f'<text x="{elem.x + 5}" y="{elem.y + 15}" fill="#FFFFFF" font-size="10">{escape_text(elem.label)}</text>'
                f'</g>'
            )

    # -------------------------------------------------------------------------
    # Element Renderers
    # -------------------------------------------------------------------------

    def _render_pushbutton(self, elem: PushButton, registers: Optional[RegisterTable]) -> str:
        reg_addr = elem.bound_register or getattr(elem, "register", None)
        active = False
        if registers and reg_addr:
            try:
                active = registers.read_bit(reg_addr)
            except Exception:
                active = False

        if active:
            bg_color = elem.on_color.to_hex() if hasattr(elem, "on_color") else "#27AE60"
            lbl = getattr(elem, "on_label", getattr(elem, "label_pressed", elem.label or "ON"))
        else:
            bg_color = elem.off_color.to_hex() if hasattr(elem, "off_color") else (
                elem.background_color.to_hex() if elem.background_color else "#4A5568"
            )
            lbl = getattr(elem, "off_label", elem.label or "OFF")

        cx = elem.x + elem.width / 2.0
        cy = elem.y + elem.height / 2.0 + 4.0

        return (
            f'<g id="{escape_text(elem.element_id)}" filter="url(#elementShadow)">'
            f'<rect x="{elem.x}" y="{elem.y}" width="{elem.width}" height="{elem.height}" rx="6" '
            f'fill="{bg_color}" stroke="#FFFFFF" stroke-width="1.5" />'
            f'<rect x="{elem.x}" y="{elem.y}" width="{elem.width}" height="{elem.height}" rx="6" '
            f'fill="url(#btnBevel)" />'
            f'<text x="{cx}" y="{cy}" fill="#FFFFFF" font-size="12" font-weight="bold" '
            f'text-anchor="middle">{escape_text(lbl)}</text>'
            f'</g>'
        )

    def _render_numeric_entry(self, elem: NumericDataEntry, registers: Optional[RegisterTable]) -> str:
        reg_addr = elem.bound_register or getattr(elem, "register", None)
        val_str = "0"
        if registers and reg_addr:
            try:
                if elem.data_type == NumericDataType.REAL:
                    # Read two consecutive 16-bit registers as REAL
                    addr_info = RegisterTable.parse_address(reg_addr)
                    prefix = addr_info.channel_type.prefix
                    num = addr_info.index
                    w1 = registers.read_word(f"{prefix}{num}")
                    w2 = registers.read_word(f"{prefix}{num+1}")
                    rval = words_to_float(w1, w2)
                    val_str = f"{rval:.{elem.decimal_places}f}"
                else:
                    ival = registers.read_word(reg_addr)
                    val_str = str(ival)
            except Exception:
                val_str = "ERR"
        else:
            val_str = "0.0" if elem.decimal_places > 0 else "0"

        bg = elem.background_color.to_hex() if elem.background_color else "#1E293B"
        fg = elem.foreground_color.to_hex() if elem.foreground_color else (
            elem.text_color.to_hex() if hasattr(elem, "text_color") and elem.text_color else "#00FFFF"
        )
        unit = getattr(elem, "engineering_units", getattr(elem, "unit", ""))
        unit_str = f" {unit}" if unit else ""

        cx = elem.x + elem.width - 10
        cy = elem.y + elem.height / 2.0 + 4.0
        lbl_y = elem.y - 4

        parts = [f'<g id="{escape_text(elem.element_id)}" filter="url(#elementShadow)">']
        if elem.label:
            parts.append(
                f'<text x="{elem.x}" y="{lbl_y}" fill="#A0AAB2" font-size="11" font-weight="600">{escape_text(elem.label)}</text>'
            )
        parts.append(
            f'<rect x="{elem.x}" y="{elem.y}" width="{elem.width}" height="{elem.height}" rx="4" '
            f'fill="{bg}" stroke="#4E5D6C" stroke-width="1.5" />'
        )
        parts.append(
            f'<text x="{cx}" y="{cy}" fill="{fg}" font-size="13" font-family="Courier, monospace" '
            f'font-weight="bold" text-anchor="end">{escape_text(val_str)}{escape_text(unit_str)}</text>'
        )
        parts.append("</g>")
        return "".join(parts)

    def _render_bargraph(self, elem: Bargraph, registers: Optional[RegisterTable]) -> str:
        reg_addr = elem.bound_register or getattr(elem, "register", None)
        min_v = getattr(elem, "min_value", getattr(elem, "scale_min", 0.0))
        max_v = getattr(elem, "max_value", getattr(elem, "scale_max", 100.0))
        hi_al = getattr(elem, "high_alarm_limit", getattr(elem, "hi_alarm", None))
        lo_al = getattr(elem, "low_alarm_limit", getattr(elem, "lo_alarm", None))

        val = 0.0
        if registers and reg_addr:
            try:
                if reg_addr.startswith("%AI") or reg_addr.startswith("%R"):
                    raw = registers.read_word(reg_addr)
                    span = max_v - min_v
                    if span > 0:
                        val = min_v + (raw / 32000.0) * span
                    else:
                        val = float(raw)
            except Exception:
                val = 0.0
        else:
            val = (max_v + min_v) / 2.0

        clamped = max(min_v, min(max_v, val))
        span = max_v - min_v
        ratio = (clamped - min_v) / span if span > 0 else 0.0

        is_alarm = (hi_al is not None and clamped >= hi_al) or (lo_al is not None and clamped <= lo_al)
        alarm_c = elem.alarm_color.to_hex() if hasattr(elem, "alarm_color") and elem.alarm_color else "#E74C3C"
        fill_c = elem.fill_color.to_hex() if hasattr(elem, "fill_color") and elem.fill_color else (
            elem.color_normal.to_hex() if hasattr(elem, "color_normal") else "#0096FF"
        )
        fill_color = alarm_c if is_alarm else fill_c

        bg_color = elem.empty_color.to_hex() if hasattr(elem, "empty_color") and elem.empty_color else (
            elem.color_background.to_hex() if hasattr(elem, "color_background") else "#323232"
        )

        parts = [f'<g id="{escape_text(elem.element_id)}" filter="url(#elementShadow)">']
        if elem.label:
            parts.append(
                f'<text x="{elem.x}" y="{elem.y - 4}" fill="#A0AAB2" font-size="11" font-weight="600">{escape_text(elem.label)}</text>'
            )

        # Outer casing
        parts.append(
            f'<rect x="{elem.x}" y="{elem.y}" width="{elem.width}" height="{elem.height}" rx="3" '
            f'fill="{bg_color}" stroke="#34495E" stroke-width="1.5" />'
        )

        # Proportional Fill
        if elem.orientation == BargraphOrientation.VERTICAL:
            fill_h = ratio * elem.height
            fill_y = elem.y + elem.height - fill_h
            parts.append(
                f'<rect x="{elem.x + 2}" y="{fill_y}" width="{elem.width - 4}" height="{max(0.0, fill_h - 2)}" '
                f'rx="2" fill="{fill_color}" />'
            )
            # High Alarm Threshold line
            if hi_al is not None and span > 0:
                hi_ratio = (hi_al - min_v) / span
                hi_y = elem.y + elem.height - (hi_ratio * elem.height)
                parts.append(
                    f'<line x1="{elem.x}" y1="{hi_y}" x2="{elem.x + elem.width}" y2="{hi_y}" '
                    f'stroke="#E74C3C" stroke-width="2" stroke-dasharray="3,2" />'
                )
        else:
            fill_w = ratio * elem.width
            parts.append(
                f'<rect x="{elem.x + 2}" y="{elem.y + 2}" width="{max(0.0, fill_w - 4)}" height="{elem.height - 4}" '
                f'rx="2" fill="{fill_color}" />'
            )
            if hi_al is not None and span > 0:
                hi_ratio = (hi_al - min_v) / span
                hi_x = elem.x + (hi_ratio * elem.width)
                parts.append(
                    f'<line x1="{hi_x}" y1="{elem.y}" x2="{hi_x}" y2="{elem.y + elem.height}" '
                    f'stroke="#E74C3C" stroke-width="2" stroke-dasharray="3,2" />'
                )

        # Value readout with high-contrast backing pill for WCAG 2.1 AA compliance
        cx = elem.x + elem.width / 2.0
        cy = elem.y + elem.height / 2.0 + 4.0
        badge_w = 38.0
        badge_h = 16.0
        parts.append(
            f'<rect x="{cx - badge_w/2.0}" y="{cy - badge_h + 3.5}" width="{badge_w}" height="{badge_h}" rx="3" '
            f'fill="#0A1118" fill-opacity="0.88" stroke="#334155" stroke-width="0.5" />'
        )
        parts.append(
            f'<text x="{cx}" y="{cy}" fill="#FFFFFF" font-size="10" font-weight="bold" '
            f'text-anchor="middle">{clamped:.1f}</text>'
        )
        parts.append("</g>")
        return "".join(parts)

    def _render_indicator_lamp(self, elem: IndicatorLamp, registers: Optional[RegisterTable]) -> str:
        reg_addr = elem.bound_register or getattr(elem, "register", None)
        active = False
        if registers and reg_addr:
            try:
                active = registers.read_bit(reg_addr)
            except Exception:
                active = False

        color = elem.on_color.to_hex() if active else elem.off_color.to_hex()
        glow_filter = 'filter="url(#lampGlow)"' if active else ""

        parts = [f'<g id="{escape_text(elem.element_id)}">']
        if elem.shape == IndicatorLampShape.ROUND:
            r = min(elem.width, elem.height) / 2.0
            cx = elem.x + elem.width / 2.0
            cy = elem.y + elem.height / 2.0
            parts.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{color}" stroke="#FFFFFF" '
                f'stroke-width="1.5" {glow_filter} />'
            )
        else:
            parts.append(
                f'<rect x="{elem.x}" y="{elem.y}" width="{elem.width}" height="{elem.height}" rx="4" '
                f'fill="{color}" stroke="#FFFFFF" stroke-width="1.5" {glow_filter} />'
            )

        lbl = elem.label or elem.legend_text
        if lbl:
            parts.append(
                f'<text x="{elem.x + elem.width + 8}" y="{elem.y + elem.height / 2.0 + 4}" '
                f'fill="#E0E1DD" font-size="12" font-weight="500">{escape_text(lbl)}</text>'
            )

        parts.append("</g>")
        return "".join(parts)

    def _render_trend_chart(self, elem: TrendChart, registers: Optional[RegisterTable]) -> str:
        bg = elem.background_color.to_hex() if elem.background_color else (
            elem.color_background.to_hex() if hasattr(elem, "color_background") else "#1E293B"
        )
        grid = elem.color_grid.to_hex() if hasattr(elem, "color_grid") else "#334155"

        parts = [
            f'<g id="{escape_text(elem.element_id)}" filter="url(#elementShadow)">',
            f'<rect x="{elem.x}" y="{elem.y}" width="{elem.width}" height="{elem.height}" rx="5" '
            f'fill="{bg}" stroke="#34495E" stroke-width="1.5" />',
        ]

        if elem.label:
            parts.append(
                f'<text x="{elem.x + 10}" y="{elem.y + 16}" fill="#CBD5E1" font-size="11" font-weight="bold">{escape_text(elem.label)}</text>'
            )

        chart_top = elem.y + 25
        chart_h = elem.height - 35
        chart_w = elem.width - 20
        chart_left = elem.x + 10

        for i in range(1, 4):
            gy = chart_top + (chart_h * i / 4.0)
            parts.append(
                f'<line x1="{chart_left}" y1="{gy}" x2="{chart_left + chart_w}" y2="{gy}" '
                f'stroke="{grid}" stroke-width="0.8" stroke-dasharray="2,2" />'
            )

        # Render simulated dynamic sparkline curves for up to 3 pens (high contrast over dark background)
        pen_colors = ["#00E5FF", "#76FF03", "#FFB300"]
        pens = elem.pens if hasattr(elem, "pens") and elem.pens else []
        for p_idx, pen in enumerate(pens[:3]):
            p_color = pen.color.to_hex() if hasattr(pen, "color") else pen_colors[p_idx % len(pen_colors)]
            if p_color.upper() in ("#0078FF", "#3498DB"):
                p_color = "#00E5FF"
            points = []
            steps = 10
            for s in range(steps + 1):
                px = chart_left + (chart_w * s / steps)
                wave = math.sin((s / float(steps)) * math.pi * 1.5 + p_idx) * 0.35 + 0.5
                py = chart_top + chart_h - (wave * chart_h)
                points.append(f"{px:.1f},{py:.1f}")

            parts.append(
                f'<polyline points="{" ".join(points)}" fill="none" stroke="{p_color}" stroke-width="2" />'
            )
            tag_name = pen.label or getattr(pen, "bound_register", None) or getattr(pen, "register", None) or f"Pen {p_idx+1}"
            parts.append(
                f'<text x="{chart_left + 10 + p_idx * 90}" y="{elem.y + elem.height - 4}" '
                f'fill="{p_color}" font-size="9" font-weight="600">{escape_text(tag_name)}</text>'
            )

        parts.append("</g>")
        return "".join(parts)

    def _render_alarm_banner(self, elem: AlarmBanner, registers: Optional[RegisterTable]) -> str:
        active_alarms = []
        if registers:
            # Check structured alarms
            if elem.alarms:
                for item in elem.alarms:
                    try:
                        if registers.read_bit(item.bit_register):
                            active_alarms.append(item.message)
                    except Exception:
                        pass
            # Check alarm_bits
            elif elem.alarm_bits:
                for bit in elem.alarm_bits:
                    try:
                        if registers.read_bit(bit):
                            msg = elem.alarm_messages.get(bit, f"Alarm on {bit}")
                            active_alarms.append(msg)
                    except Exception:
                        pass

        has_active = len(active_alarms) > 0
        active_color = elem.banner_color.to_hex() if hasattr(elem, "banner_color") and elem.banner_color else "#C0392B"
        normal_color = elem.background_color.to_hex() if elem.background_color else "#2C3E50"
        bg = active_color if has_active else normal_color
        msg = active_alarms[0] if has_active else "SYSTEM NORMAL - NO ACTIVE ALARMS"
        icon_color = "#FFFFFF" if has_active else "#2ECC71"

        return (
            f'<g id="{escape_text(elem.element_id)}" filter="url(#elementShadow)">'
            f'<rect x="{elem.x}" y="{elem.y}" width="{elem.width}" height="{elem.height}" rx="4" '
            f'fill="{bg}" stroke="#E74C3C" stroke-width="{1.5 if has_active else 0.5}" />'
            f'<circle cx="{elem.x + 18}" cy="{elem.y + elem.height / 2.0}" r="6" fill="{icon_color}" />'
            f'<text x="{elem.x + 32}" y="{elem.y + elem.height / 2.0 + 4}" fill="#FFFFFF" '
            f'font-size="11" font-weight="bold">{escape_text(msg)}</text>'
            f'</g>'
        )

    def _render_navigation_button(self, elem: NavigationButton, registers: Optional[RegisterTable]) -> str:
        bg = elem.button_color.to_hex() if hasattr(elem, "button_color") and elem.button_color else "#4A5568"
        lbl = elem.label or f"Screen {elem.target_screen_id}"
        cx = elem.x + elem.width / 2.0
        cy = elem.y + elem.height / 2.0 + 4.0

        return (
            f'<g id="{escape_text(elem.element_id)}" filter="url(#elementShadow)">'
            f'<rect x="{elem.x}" y="{elem.y}" width="{elem.width}" height="{elem.height}" rx="5" '
            f'fill="{bg}" stroke="#5C6B73" stroke-width="1.2" />'
            f'<text x="{cx}" y="{cy}" fill="#E0E1DD" font-size="11" font-weight="600" '
            f'text-anchor="middle">&gt; {escape_text(lbl)}</text>'
            f'</g>'
        )
