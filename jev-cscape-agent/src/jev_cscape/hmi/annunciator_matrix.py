"""Cscape HMI Dynamic Multi-State Graphic Annunciator Matrix & Alarm Panel Rasterizer.

Work Package: W081 (Gate G9 HMI Graphics / Gate G2 UI Engine)
Standard: ISA-18.1 / ISA-18.2 Annunciator Sequences, W3C SVG 1.1 Vector Graphics & WCAG 2.1 AAA Contrast
Horner OCS Register Mappings:
- %R420: Status Word (Bit 0: Active, Bit 1: Any Unack, Bit 2: Horn Active, Bit 3: First-Out Latched, Bit 4: Flash Phase, Bit 5: Lamp Test)
- %R421: Total Active Alarm Count (0..16)
- %R422: Unacknowledged Alarm Count (0..16)
- %R423: First-Out Tile Index (-1 if none, 0..15)
- %R424: Selected Tile Index (0..15)
- %R425: Tile 0..3 State Bitfield (2 bits/tile: 00=Normal, 01=Unack, 10=Ack, 11=Ringback)
- %R426: Tile 4..7 State Bitfield (2 bits/tile)
- %R427: Tile 8..11 State Bitfield (2 bits/tile)
- %M98: Operator Acknowledge (ACK) Pushbutton
- %M99: Operator Silence / Reset Pushbutton
"""

from __future__ import annotations

import dataclasses
from enum import Enum, IntEnum
import html
import math
from typing import Any, Callable, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


class AlarmPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"
    NORMAL = "NORMAL"


class AnnunciatorState(str, Enum):
    NORMAL = "NORMAL"
    UNACKNOWLEDGED = "UNACKNOWLEDGED"
    SILENCED = "SILENCED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RETURNED_UNACKNOWLEDGED = "RETURNED_UNACKNOWLEDGED"  # Ringback


class LampFlashMode(str, Enum):
    OFF = "OFF"
    FAST_FLASH = "FAST_FLASH"
    SLOW_FLASH = "SLOW_FLASH"
    STEADY = "STEADY"


PRIORITY_GLYPHS: Dict[AlarmPriority, str] = {
    AlarmPriority.CRITICAL: "◆",
    AlarmPriority.HIGH: "▼",
    AlarmPriority.MEDIUM: "■",
    AlarmPriority.INFO: "●",
    AlarmPriority.NORMAL: "✔",
}


@dataclasses.dataclass
class AnnunciatorTile:
    """Individual alarm window annunciator tile."""
    tag_name: str
    label: str
    status_line: str = ""
    priority: AlarmPriority = AlarmPriority.CRITICAL
    state: AnnunciatorState = AnnunciatorState.NORMAL
    lamp_mode: LampFlashMode = LampFlashMode.OFF
    is_first_out: bool = False
    is_lit: Optional[bool] = None
    point_id: str = ""
    trip_timestamp: str = ""

    def evaluate_lit(self, cycle_time_sec: float = 0.0) -> bool:
        if self.is_lit is not None:
            return self.is_lit
        if self.lamp_mode == LampFlashMode.OFF:
            return False
        if self.lamp_mode == LampFlashMode.STEADY:
            return True
        if self.lamp_mode == LampFlashMode.FAST_FLASH:
            # 2.0 Hz -> 0.5s period
            return (cycle_time_sec % 0.5) < 0.25
        if self.lamp_mode == LampFlashMode.SLOW_FLASH:
            # 0.5 Hz -> 2.0s period
            return (cycle_time_sec % 2.0) < 1.0
        return False


def wrap_label(text: str, max_chars_per_line: int = 20, max_lines: int = 2) -> List[str]:
    """Auto-wrap label text respecting word boundaries."""
    clean_text = " ".join(text.strip().split())
    if not clean_text:
        return []
    words = clean_text.split()
    lines: List[str] = []
    current_line: List[str] = []
    current_len = 0
    idx = 0
    while idx < len(words):
        w = words[idx]
        needed = len(w) if not current_line else current_len + 1 + len(w)
        if needed <= max_chars_per_line:
            current_line.append(w)
            current_len = needed
            idx += 1
        else:
            if not current_line:
                current_line.append(w[:max(1, max_chars_per_line - 3)] + "...")
                lines.append(" ".join(current_line))
                current_line = []
                current_len = 0
                idx += 1
            else:
                lines.append(" ".join(current_line))
                current_line = []
                current_len = 0
            if len(lines) == max_lines - 1:
                remaining = " ".join(words[idx:])
                if len(remaining) > max_chars_per_line:
                    truncated = remaining[:max(1, max_chars_per_line - 3)].rstrip() + "..."
                    lines.append(truncated)
                else:
                    lines.append(remaining)
                return lines
    if current_line and len(lines) < max_lines:
        lines.append(" ".join(current_line))
    return lines[:max_lines]


@dataclasses.dataclass
class AnnunciatorPanelConfig:
    """Styling and dimension configuration for annunciator matrix panel."""
    viewbox_width: int = 800
    viewbox_height: int = 480
    cols: int = 4
    rows: int = 3
    tile_width: float = 178.0
    tile_height: float = 100.0
    gap_x: float = 12.0
    gap_y: float = 12.0
    margin_x: Optional[float] = None
    margin_y: Optional[float] = None
    panel_title: str = "SCADA PROCESS ALARM ANNUNCIATOR"
    sub_title: str = "AREA 01 — FEEDWATER & CONDENSER TRAIN"
    include_header: bool = True
    header_height: float = 46.0
    include_operator_strip: bool = True
    operator_strip_height: float = 38.0
    panel_bg_color: str = "#0B0F19"
    bezel_color: str = "#1E293B"
    bezel_border_color: str = "#334155"
    bezel_corner_radius: float = 4.0
    lens_inset: float = 6.0
    lens_corner_radius: float = 2.5
    font_family_sans: str = "system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
    font_family_mono: str = "'Consolas', 'Courier New', 'SFMono-Regular', monospace"
    enable_css_animations: bool = True
    cycle_time_sec: float = 0.0
    unack_count: Optional[int] = None
    horn_sounding: Optional[bool] = None
    lamp_test_active: bool = False


class AnnunciatorSVGGenerator:
    """Vector SVG generator conforming to WCAG 2.1 AAA contrast."""

    PRIORITY_PALETTE = {
        AlarmPriority.CRITICAL: {
            "lit_top": "#EF4444", "lit_bottom": "#991B1B", "lit_rim": "#FCA5A5",
            "unlit_top": "#1E1214", "unlit_bottom": "#12090B", "unlit_rim": "#3B1C22",
            "text_hdr": "#FFFFFF", "text_lbl": "#FEF2F2", "text_sts": "#FEE2E2",
            "pill_bg": "rgba(69, 10, 10, 0.70)", "pill_rim": "#F87171"
        },
        AlarmPriority.HIGH: {
            "lit_top": "#F59E0B", "lit_bottom": "#B45309", "lit_rim": "#FDE68A",
            "unlit_top": "#1E180E", "unlit_bottom": "#120F08", "unlit_rim": "#3D2E16",
            "text_hdr": "#FFFFFF", "text_lbl": "#FFFBEB", "text_sts": "#FEF3C7",
            "pill_bg": "rgba(69, 26, 3, 0.70)", "pill_rim": "#FBBF24"
        },
        AlarmPriority.MEDIUM: {
            "lit_top": "#FACC15", "lit_bottom": "#A16207", "lit_rim": "#FEF08A",
            "unlit_top": "#1E1D0C", "unlit_bottom": "#121206", "unlit_rim": "#3C3814",
            "text_hdr": "#0F172A", "text_lbl": "#1E293B", "text_sts": "#0F172A",
            "pill_bg": "rgba(254, 240, 138, 0.85)", "pill_rim": "#CA8A04"
        },
        AlarmPriority.INFO: {
            "lit_top": "#06B6D4", "lit_bottom": "#0E7490", "lit_rim": "#A5F3FC",
            "unlit_top": "#0C1820", "unlit_bottom": "#060F16", "unlit_rim": "#15324E",
            "text_hdr": "#FFFFFF", "text_lbl": "#ECFEFF", "text_sts": "#CFFAFE",
            "pill_bg": "rgba(8, 51, 68, 0.70)", "pill_rim": "#38BDF8"
        },
        AlarmPriority.NORMAL: {
            "lit_top": "#10B981", "lit_bottom": "#065F46", "lit_rim": "#6EE7B7",
            "unlit_top": "#182030", "unlit_bottom": "#0F172A", "unlit_rim": "#334155",
            "text_hdr": "#FFFFFF", "text_lbl": "#F0FDF4", "text_sts": "#D1FAE5",
            "pill_bg": "rgba(6, 78, 59, 0.70)", "pill_rim": "#34D399"
        },
    }

    UNLIT_STYLING = {
        "text_hdr": "#94A3B8", "text_lbl": "#64748B", "text_sts": "#475569",
        "pill_bg": "rgba(15, 23, 42, 0.60)", "pill_rim": "#334155", "sep": "#334155"
    }

    def __init__(self, config: Optional[AnnunciatorPanelConfig] = None) -> None:
        self.config = config or AnnunciatorPanelConfig()

    def render(self, tiles: List[AnnunciatorTile]) -> str:
        cfg = self.config
        vb_w, vb_h = cfg.viewbox_width, cfg.viewbox_height
        grid_w = (cfg.cols * cfg.tile_width) + ((cfg.cols - 1) * cfg.gap_x)
        grid_h = (cfg.rows * cfg.tile_height) + ((cfg.rows - 1) * cfg.gap_y)
        margin_x = cfg.margin_x if cfg.margin_x is not None else max(10.0, (vb_w - grid_w) / 2.0)
        hdr_h = cfg.header_height if cfg.include_header else 0.0
        strip_h = cfg.operator_strip_height if cfg.include_operator_strip else 0.0
        avail_h = vb_h - hdr_h - strip_h
        margin_y = cfg.margin_y if cfg.margin_y is not None else hdr_h + max(8.0, (avail_h - grid_h) / 2.0)

        unack_count = cfg.unack_count if cfg.unack_count is not None else sum(
            1 for t in tiles if t.state in (AnnunciatorState.UNACKNOWLEDGED, AnnunciatorState.SILENCED)
        )
        horn_sounding = cfg.horn_sounding if cfg.horn_sounding is not None else any(
            t.state == AnnunciatorState.UNACKNOWLEDGED for t in tiles
        )
        active_count = sum(1 for t in tiles if t.state != AnnunciatorState.NORMAL)

        lines = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {vb_w} {vb_h}" width="{vb_w}" height="{vb_h}" class="cscape-annunciator-matrix">']
        lines.append(self._render_defs())
        lines.append(f'  <rect width="{vb_w}" height="{vb_h}" fill="url(#panel-chassis-grad)"/>')
        lines.append(f'  <rect x="1" y="1" width="{vb_w - 2}" height="{vb_h - 2}" fill="none" stroke="#1E293B" stroke-width="1.5"/>')

        if cfg.include_header:
            lines.append(self._render_header(vb_w, hdr_h, unack_count, active_count, horn_sounding))

        lines.append('  <g id="annunciator-grid">')
        total_slots = cfg.cols * cfg.rows
        for slot_idx in range(total_slots):
            c = slot_idx % cfg.cols
            r = slot_idx // cfg.cols
            tx = margin_x + c * (cfg.tile_width + cfg.gap_x)
            ty = margin_y + r * (cfg.tile_height + cfg.gap_y)
            t_data = tiles[slot_idx] if slot_idx < len(tiles) else None
            lines.append(self._render_tile(tx, ty, t_data, slot_idx))
        lines.append('  </g>')

        if cfg.include_operator_strip:
            lines.append(self._render_operator_strip(vb_w, vb_h, strip_h, horn_sounding, unack_count, cfg.lamp_test_active))

        lines.append('</svg>')
        return "\n".join(lines)

    def _render_defs(self) -> str:
        cfg = self.config
        defs = ['  <defs>', '    <style type="text/css">', '      <![CDATA[']
        defs.append(f'        .cscape-annunciator-matrix {{ font-family: {cfg.font_family_sans}; }}')
        defs.append('        .tag-header { font-size: 13px; font-weight: 700; text-anchor: middle; letter-spacing: 0.8px; }')
        defs.append('        .desc-line { font-size: 11px; font-weight: 500; text-anchor: middle; }')
        defs.append(f'        .status-value {{ font-family: {cfg.font_family_mono}; font-size: 10px; font-weight: 700; text-anchor: middle; letter-spacing: 0.5px; }}')
        defs.append('        .header-title { font-size: 15px; font-weight: 800; letter-spacing: 1.2px; fill: #F8FAFC; }')
        defs.append('        .header-subtitle { font-size: 11px; font-weight: 500; letter-spacing: 0.6px; fill: #94A3B8; }')
        if cfg.enable_css_animations:
            defs.append('        @keyframes fast-blink { 0%, 49.9% { opacity: 1.0; } 50%, 100% { opacity: 0.28; } }')
            defs.append('        @keyframes slow-blink { 0%, 49.9% { opacity: 1.0; } 50%, 100% { opacity: 0.28; } }')
            defs.append('        .flash-fast { animation: fast-blink 0.5s infinite steps(1, end); }')
            defs.append('        .flash-slow { animation: slow-blink 2.0s infinite steps(1, end); }')
        defs.append('      ]]>')
        defs.append('    </style>')
        defs.append('    <filter id="tile-drop-shadow" x="-8%" y="-8%" width="120%" height="125%" filterUnits="userSpaceOnUse">')
        defs.append('      <feDropShadow dx="0" dy="2.5" stdDeviation="3.0" flood-color="#000000" flood-opacity="0.65"/>')
        defs.append('    </filter>')
        defs.append('    <linearGradient id="panel-chassis-grad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#0F172A"/><stop offset="50%" stop-color="#0B0F19"/><stop offset="100%" stop-color="#070A10"/></linearGradient>')
        defs.append('    <linearGradient id="bezel-metallic-grad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#2D3748"/><stop offset="40%" stop-color="#1E293B"/><stop offset="100%" stop-color="#0F172A"/></linearGradient>')
        defs.append('    <linearGradient id="lens-sheen-grad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.22"/><stop offset="40%" stop-color="#FFFFFF" stop-opacity="0.05"/><stop offset="100%" stop-color="#FFFFFF" stop-opacity="0.0"/></linearGradient>')

        for prio, pal in self.PRIORITY_PALETTE.items():
            slug = prio.value.lower()
            defs.append(f'    <linearGradient id="lens-grad-{slug}-lit" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="{pal["lit_top"]}"/><stop offset="100%" stop-color="{pal["lit_bottom"]}"/></linearGradient>')
            defs.append(f'    <linearGradient id="lens-grad-{slug}-unlit" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="{pal["unlit_top"]}"/><stop offset="100%" stop-color="{pal["unlit_bottom"]}"/></linearGradient>')
        defs.append('  </defs>')
        return "\n".join(defs)

    def _render_header(self, vb_w: float, hdr_h: float, unack_cnt: int, act_cnt: int, horn: bool) -> str:
        cfg = self.config
        lines = ['  <g id="panel-header">']
        lines.append(f'    <rect width="{vb_w}" height="{hdr_h}" fill="#0F172A" stroke="#1E293B" stroke-width="1"/>')
        lines.append(f'    <line x1="0" y1="{hdr_h}" x2="{vb_w}" y2="{hdr_h}" stroke="#334155" stroke-width="1.2"/>')
        lines.append(f'    <text x="24" y="22" class="header-title">{html.escape(cfg.panel_title)}</text>')
        lines.append(f'    <text x="24" y="38" class="header-subtitle">{html.escape(cfg.sub_title)}</text>')
        bx = vb_w - 24.0
        bx -= 90.0
        col_act = "#EF4444" if act_cnt > 0 else "#10B981"
        lines.append(f'    <rect x="{bx}" y="11" width="90" height="24" rx="4" fill="#1E293B" stroke="{col_act}" stroke-width="1.2"/>')
        lines.append(f'    <text x="{bx + 45}" y="27" font-size="11" font-weight="700" fill="{col_act}" text-anchor="middle">ACTIVE: {act_cnt}</text>')
        bx -= 105.0
        col_unack = "#F59E0B" if unack_cnt > 0 else "#64748B"
        lines.append(f'    <rect x="{bx}" y="11" width="95" height="24" rx="4" fill="#1E293B" stroke="{col_unack}" stroke-width="1.2"/>')
        lines.append(f'    <text x="{bx + 47.5}" y="27" font-size="11" font-weight="700" fill="{col_unack}" text-anchor="middle">UNACK: {unack_cnt}</text>')
        bx -= 95.0
        f_horn = "#EF4444" if horn else "#1E293B"
        s_horn = "#F87171" if horn else "#475569"
        t_horn = "#FFFFFF" if horn else "#94A3B8"
        lbl_horn = "HORN ON" if horn else "HORN OFF"
        lines.append(f'    <rect x="{bx}" y="11" width="85" height="24" rx="4" fill="{f_horn}" stroke="{s_horn}" stroke-width="1.2"/>')
        lines.append(f'    <text x="{bx + 42.5}" y="27" font-size="11" font-weight="700" fill="{t_horn}" text-anchor="middle">{lbl_horn}</text>')
        lines.append('  </g>')
        return "\n".join(lines)

    def _render_tile(self, tx: float, ty: float, tile: Optional[AnnunciatorTile], idx: int) -> str:
        cfg = self.config
        tw, th = cfg.tile_width, cfg.tile_height
        inset = cfg.lens_inset
        lw, lh = tw - 2 * inset, th - 2 * inset
        rxb, rxl = cfg.bezel_corner_radius, cfg.lens_corner_radius

        lines = [f'    <g id="tile-{idx}" transform="translate({tx:.1f}, {ty:.1f})">']
        lines.append(f'      <rect width="{tw:.1f}" height="{th:.1f}" rx="{rxb:.1f}" fill="url(#bezel-metallic-grad)" stroke="{cfg.bezel_border_color}" stroke-width="1.5" filter="url(#tile-drop-shadow)"/>')
        lines.append(f'      <line x1="2" y1="2" x2="{tw - 2:.1f}" y2="2" stroke="#64748B" stroke-width="1" stroke-opacity="0.8"/>')
        lines.append(f'      <line x1="2" y1="2" x2="2" y2="{th - 2:.1f}" stroke="#64748B" stroke-width="1" stroke-opacity="0.8"/>')
        lines.append(f'      <line x1="2" y1="{th - 1.5:.1f}" x2="{tw - 1.5:.1f}" y2="{th - 1.5:.1f}" stroke="#070A10" stroke-width="1.2"/>')
        lines.append(f'      <line x1="{tw - 1.5:.1f}" y1="2" x2="{tw - 1.5:.1f}" y2="{th - 1.5:.1f}" stroke="#070A10" stroke-width="1.2"/>')

        if not tile:
            lines.append(f'      <rect x="{inset:.1f}" y="{inset:.1f}" width="{lw:.1f}" height="{lh:.1f}" rx="{rxl:.1f}" fill="#111827" stroke="#1F2937" stroke-width="1"/>')
            lines.append(f'      <text x="{tw / 2:.1f}" y="{th / 2 + 4:.1f}" font-size="11" font-weight="600" fill="#374151" text-anchor="middle">SPARE</text>')
            lines.append('    </g>')
            return "\n".join(lines)

        is_lit = True if cfg.lamp_test_active else tile.evaluate_lit(cfg.cycle_time_sec)
        slug = tile.priority.value.lower()
        pal = self.PRIORITY_PALETTE.get(tile.priority, self.PRIORITY_PALETTE[AlarmPriority.CRITICAL])
        flash_cls = ""
        if cfg.enable_css_animations and not cfg.lamp_test_active:
            if tile.lamp_mode == LampFlashMode.FAST_FLASH:
                flash_cls = " flash-fast"
            elif tile.lamp_mode == LampFlashMode.SLOW_FLASH:
                flash_cls = " flash-slow"

        lens_grad = f"lens-grad-{slug}-lit" if is_lit else f"lens-grad-{slug}-unlit"
        stroke_c = pal["lit_rim"] if is_lit else pal["unlit_rim"]
        stroke_w = "1.5" if is_lit else "1.0"

        lines.append(f'      <g class="lens-container{flash_cls}">')
        lines.append(f'        <rect x="{inset:.1f}" y="{inset:.1f}" width="{lw:.1f}" height="{lh:.1f}" rx="{rxl:.1f}" fill="url(#{lens_grad})" stroke="{stroke_c}" stroke-width="{stroke_w}"/>')
        lines.append(f'        <path d="M {inset} {inset + 1} Q {tw / 2} {inset + 14} {tw - inset} {inset + 1} L {tw - inset} {inset + 28} Q {tw / 2} {inset + 38} {inset} {inset + 28} Z" fill="url(#lens-sheen-grad)"/>')

        if is_lit:
            hdr_c, lbl_c, sts_c = pal["text_hdr"], pal["text_lbl"], pal["text_sts"]
            pill_bg, pill_rim = pal["pill_bg"], pal["pill_rim"]
            sep_c, sep_op = "#FFFFFF", "0.35"
        else:
            hdr_c, lbl_c, sts_c = self.UNLIT_STYLING["text_hdr"], self.UNLIT_STYLING["text_lbl"], self.UNLIT_STYLING["text_sts"]
            pill_bg, pill_rim = self.UNLIT_STYLING["pill_bg"], self.UNLIT_STYLING["pill_rim"]
            sep_c, sep_op = self.UNLIT_STYLING["sep"], "0.4"

        t_shad = ' style="filter: drop-shadow(0 1px 2px rgba(0,0,0,0.85));"' if (is_lit and tile.priority != AlarmPriority.MEDIUM) else ""
        cx = tw / 2.0
        y_tag = inset + 17.0

        glyph = PRIORITY_GLYPHS.get(tile.priority, "")
        fo_marker = "★ " if tile.is_first_out else ""
        hdr_display = f"{fo_marker}{glyph} {tile.tag_name}" if glyph else f"{fo_marker}{tile.tag_name}"

        lines.append(f'        <text x="{cx:.1f}" y="{y_tag:.1f}" class="tag-header" fill="{hdr_c}"{t_shad}>{html.escape(hdr_display)}</text>')
        y_sep = inset + 24.5
        lines.append(f'        <line x1="{cx - 62:.1f}" y1="{y_sep:.1f}" x2="{cx + 62:.1f}" y2="{y_sep:.1f}" stroke="{sep_c}" stroke-opacity="{sep_op}" stroke-width="0.8"/>')

        d_lines = wrap_label(tile.label, max_chars_per_line=20, max_lines=2)
        if len(d_lines) == 1:
            lines.append(f'        <text x="{cx:.1f}" y="{inset + 42.0:.1f}" class="desc-line" fill="{lbl_c}"{t_shad}>{html.escape(d_lines[0])}</text>')
        elif len(d_lines) >= 2:
            lines.append(f'        <text x="{cx:.1f}" y="{inset + 37.0:.1f}" class="desc-line" fill="{lbl_c}"{t_shad}>{html.escape(d_lines[0])}</text>')
            lines.append(f'        <text x="{cx:.1f}" y="{inset + 51.5:.1f}" class="desc-line" fill="{lbl_c}"{t_shad}>{html.escape(d_lines[1])}</text>')

        sts_str = tile.status_line or tile.state.value
        if sts_str:
            pw, ph = lw - 22.0, 16.5
            px = cx - (pw / 2.0)
            py = inset + lh - ph - 4.5
            lines.append(f'        <rect x="{px:.1f}" y="{py:.1f}" width="{pw:.1f}" height="{ph:.1f}" rx="3" fill="{pill_bg}" stroke="{pill_rim}" stroke-width="0.8"/>')
            lines.append(f'        <text x="{cx:.1f}" y="{py + 12.0:.1f}" class="status-value" fill="{sts_c}">{html.escape(sts_str)}</text>')

        lines.append('      </g>')
        lines.append('    </g>')
        return "\n".join(lines)

    def _render_operator_strip(self, vb_w: float, vb_h: float, strip_h: float, horn: bool, unack: int, test: bool) -> str:
        sy = vb_h - strip_h
        lines = [f'  <g id="operator-toolbar" transform="translate(0, {sy:.1f})">']
        lines.append(f'    <rect width="{vb_w}" height="{strip_h}" fill="#0F172A" stroke="#1E293B" stroke-width="1"/>')
        lines.append(f'    <line x1="0" y1="0" x2="{vb_w}" y2="0" stroke="#334155" stroke-width="1.2"/>')
        buttons = [
            ("%M98", "ACKNOWLEDGE", "#EF4444" if unack > 0 else "#64748B", unack > 0),
            ("%M99", "SILENCE / RESET", "#F59E0B" if horn else "#06B6D4", horn),
            ("TEST", "LAMP TEST", "#FFFFFF" if test else "#94A3B8", test),
        ]
        bw, bh, gap = 190.0, strip_h - 10.0, 20.0
        tot_w = (len(buttons) * bw) + ((len(buttons) - 1) * gap)
        sx = (vb_w - tot_w) / 2.0
        for i, (addr, lbl, col, act) in enumerate(buttons):
            bx = sx + i * (bw + gap)
            f = "#1E293B" if not act else "#334155"
            b = col if act else "#475569"
            dot_col = col if act else "#334155"
            lines.append(f'    <g id="btn-{addr.replace("%", "").replace(" ", "_")}" transform="translate({bx:.1f}, 5.0)">')
            lines.append(f'      <rect width="{bw}" height="{bh}" rx="4" fill="{f}" stroke="{b}" stroke-width="1.2"/>')
            lines.append(f'      <circle cx="16" cy="{bh / 2:.1f}" r="4" fill="{dot_col}" stroke="{b}" stroke-width="0.8"/>')
            lines.append(f'      <text x="30" y="{bh / 2 + 4:.1f}" font-size="11" font-weight="700" fill="#F8FAFC">{lbl}</text>')
            lines.append(f'      <text x="{bw - 12}" y="{bh / 2 + 3:.1f}" font-size="9" font-family="{self.config.font_family_mono}" font-weight="600" fill="#64748B" text-anchor="end">{addr}</text>')
            lines.append('    </g>')
        lines.append('  </g>')
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Annunciator State Machine & Matrix Engine
# ---------------------------------------------------------------------------

class AnnunciatorMatrixEngine:
    """ISA-18.1 Annunciator State Machine and Horner OCS Controller Engine."""

    def __init__(
        self,
        tiles: Optional[List[AnnunciatorTile]] = None,
        config: Optional[AnnunciatorPanelConfig] = None,
        register_table: Optional[RegisterTable] = None,
        sequence_mode: str = "M",
    ) -> None:
        self.config = config or AnnunciatorPanelConfig()
        self.registers: RegisterTable = register_table or RegisterTable()
        self.sequence_mode: str = sequence_mode.upper()  # 'A' = Auto-reset, 'M' = Manual reset with Ringback
        self.tiles: List[AnnunciatorTile] = tiles or self._create_default_tiles()
        self.rasterizer = AnnunciatorSVGGenerator(self.config)

        self.first_out_latched: bool = False
        self.first_out_index: int = -1
        self.horn_active: bool = False
        self.flash_phase: bool = False
        self.lamp_test_active: bool = False
        self.selected_tile_idx: int = 0
        self.cycle_time_s: float = 0.0

        # Initialize default register mapping
        self.sync_to_register_table(self.registers)

    def _create_default_tiles(self) -> List[AnnunciatorTile]:
        return [
            AnnunciatorTile("P-101A TRIP", "FEED PUMP BEARING HIGH TEMP", "NORMAL", AlarmPriority.CRITICAL),
            AnnunciatorTile("P-101B TRIP", "AUX PUMP HYDRAULIC LOW PRESS", "NORMAL", AlarmPriority.CRITICAL),
            AnnunciatorTile("TK-201 HIGH", "STORAGE TANK OVERFLOW WARNING", "NORMAL", AlarmPriority.HIGH),
            AnnunciatorTile("TK-201 LOW", "STORAGE TANK MINIMUM LEVEL", "NORMAL", AlarmPriority.HIGH),
            AnnunciatorTile("HX-301 LEAK", "HEAT EXCHANGER TUBE LEAK", "NORMAL", AlarmPriority.CRITICAL),
            AnnunciatorTile("V-102 FAULT", "CONDENSER BYPASS VALVE MISMATCH", "NORMAL", AlarmPriority.MEDIUM),
            AnnunciatorTile("V-104 STALL", "DEAERATOR INLET ISOLATION", "NORMAL", AlarmPriority.MEDIUM),
            AnnunciatorTile("GEN-1 FLT", "MAIN GENERATOR STATOR TEMP", "NORMAL", AlarmPriority.HIGH),
            AnnunciatorTile("NET-01 STALE", "MODBUS TELEMETRY POLLING TIMEOUT", "NORMAL", AlarmPriority.INFO),
            AnnunciatorTile("UPS-1 BATT", "CONTROL PANEL 24V UPS ON BATTERY", "NORMAL", AlarmPriority.INFO),
            AnnunciatorTile("CALIB DUE", "STEAM FLOWMETER CALIBRATION DUE", "NORMAL", AlarmPriority.INFO),
            AnnunciatorTile("SYS OK", "ALL INTERLOCKS NORMAL AND ACTIVE", "NORMAL", AlarmPriority.NORMAL),
        ]

    def trip_alarm(self, tile_idx: int, status_line: str = "", timestamp: str = "") -> None:
        """Trip an alarm tile following ISA-18.1 Sequence A / M and first-out latching."""
        if 0 <= tile_idx < len(self.tiles):
            tile = self.tiles[tile_idx]
            if tile.state in (AnnunciatorState.NORMAL, AnnunciatorState.RETURNED_UNACKNOWLEDGED):
                tile.state = AnnunciatorState.UNACKNOWLEDGED
                tile.lamp_mode = LampFlashMode.FAST_FLASH
                tile.status_line = status_line or "TRIP / ALARM"
                tile.trip_timestamp = timestamp
                self.horn_active = True

                if not self.first_out_latched:
                    self.first_out_latched = True
                    self.first_out_index = tile_idx
                    tile.is_first_out = True

    def clear_alarm(self, tile_idx: int) -> None:
        """Process condition returns to normal."""
        if 0 <= tile_idx < len(self.tiles):
            tile = self.tiles[tile_idx]
            if tile.state == AnnunciatorState.ACKNOWLEDGED:
                if self.sequence_mode == "M":
                    tile.state = AnnunciatorState.RETURNED_UNACKNOWLEDGED
                    tile.lamp_mode = LampFlashMode.SLOW_FLASH
                    tile.status_line = "RINGBACK"
                else:
                    tile.state = AnnunciatorState.NORMAL
                    tile.lamp_mode = LampFlashMode.OFF
                    tile.status_line = "NORMAL"
                    tile.is_first_out = False
            elif tile.state == AnnunciatorState.UNACKNOWLEDGED:
                if self.sequence_mode == "M":
                    tile.state = AnnunciatorState.RETURNED_UNACKNOWLEDGED
                    tile.lamp_mode = LampFlashMode.SLOW_FLASH
                    tile.status_line = "CLEAR / UNACK"
                else:
                    tile.state = AnnunciatorState.NORMAL
                    tile.lamp_mode = LampFlashMode.OFF
                    tile.status_line = "NORMAL"
                    tile.is_first_out = False

            # Check if all cleared
            if all(t.state == AnnunciatorState.NORMAL for t in self.tiles):
                self.first_out_latched = False
                self.first_out_index = -1
                self.horn_active = False

    def operator_ack(self) -> None:
        """Operator presses ACK (%M98). Silences horn, latches flashing tiles to steady."""
        self.horn_active = False
        for tile in self.tiles:
            if tile.state in (AnnunciatorState.UNACKNOWLEDGED, AnnunciatorState.SILENCED):
                tile.state = AnnunciatorState.ACKNOWLEDGED
                tile.lamp_mode = LampFlashMode.STEADY

    def operator_silence_reset(self) -> None:
        """Operator presses Silence / Reset (%M99).

        If horn sounding: silences horn.
        If horn silent: resets Ringback tiles to Normal and clears first-out if all clear.
        """
        if self.horn_active:
            self.horn_active = False
            for tile in self.tiles:
                if tile.state == AnnunciatorState.UNACKNOWLEDGED:
                    tile.state = AnnunciatorState.SILENCED
        else:
            for tile in self.tiles:
                if tile.state == AnnunciatorState.RETURNED_UNACKNOWLEDGED:
                    tile.state = AnnunciatorState.NORMAL
                    tile.lamp_mode = LampFlashMode.OFF
                    tile.status_line = "NORMAL"
                    tile.is_first_out = False

            if all(t.state == AnnunciatorState.NORMAL for t in self.tiles):
                self.first_out_latched = False
                self.first_out_index = -1

    def operator_lamp_test(self, active: bool) -> None:
        """Activate or deactivate lamp test mode."""
        self.lamp_test_active = active
        self.config.lamp_test_active = active

    def step(self, dt: float = 0.1) -> None:
        """Advance time step, toggle flash phases, and evaluate lamp states."""
        self.cycle_time_s += dt
        self.config.cycle_time_sec = self.cycle_time_s
        self.flash_phase = (self.cycle_time_s % 0.5) < 0.25

    def sync_from_register_table(self, table: RegisterTable) -> None:
        """Read operator inputs and selections from Horner OCS register space."""
        pb_ack = bool(table.read_register("%M98"))
        pb_silence_reset = bool(table.read_register("%M99"))
        selected_idx = int(table.read_register("%R424"))

        if 0 <= selected_idx < len(self.tiles):
            self.selected_tile_idx = selected_idx

        if pb_ack:
            self.operator_ack()
            prev_priv = table.privilege_mode
            table.privilege_mode = PrivilegeMode.SYSTEM
            table.write_register("%M98", False)
            table.privilege_mode = prev_priv

        if pb_silence_reset:
            self.operator_silence_reset()
            prev_priv = table.privilege_mode
            table.privilege_mode = PrivilegeMode.SYSTEM
            table.write_register("%M99", False)
            table.privilege_mode = prev_priv

    def sync_to_register_table(self, table: RegisterTable) -> None:
        """Write annunciator status, counts, and tile bitfields into Horner OCS registers."""
        prev_priv = table.privilege_mode
        table.privilege_mode = PrivilegeMode.SYSTEM
        try:
            total_active = sum(1 for t in self.tiles if t.state != AnnunciatorState.NORMAL)
            unack_count = sum(1 for t in self.tiles if t.state in (AnnunciatorState.UNACKNOWLEDGED, AnnunciatorState.SILENCED))

            # Status Word (%R420):
            # Bit 0: Engine Active (1)
            # Bit 1: Any Unacknowledged Alarm Present
            # Bit 2: Audible Horn Active
            # Bit 3: First-Out Alarm Latched
            # Bit 4: Flash Phase State (0/1)
            # Bit 5: Lamp Test Active
            status_w = 0x0001
            if unack_count > 0:
                status_w |= 0x0002
            if self.horn_active:
                status_w |= 0x0004
            if self.first_out_latched:
                status_w |= 0x0008
            if self.flash_phase:
                status_w |= 0x0010
            if self.lamp_test_active:
                status_w |= 0x0020

            table.write_register("%R420", status_w)
            table.write_register("%R421", total_active)
            table.write_register("%R422", unack_count)
            table.write_register("%R423", self.first_out_index)
            table.write_register("%R424", self.selected_tile_idx)

            # Pack 2 bits per tile: 00=Normal, 01=Unack, 10=Ack, 11=Ringback
            state_codes = {
                AnnunciatorState.NORMAL: 0,
                AnnunciatorState.UNACKNOWLEDGED: 1,
                AnnunciatorState.SILENCED: 1,
                AnnunciatorState.ACKNOWLEDGED: 2,
                AnnunciatorState.RETURNED_UNACKNOWLEDGED: 3,
            }

            def pack_tile_states(start_idx: int, count: int) -> int:
                val = 0
                for i in range(count):
                    idx = start_idx + i
                    code = state_codes.get(self.tiles[idx].state, 0) if idx < len(self.tiles) else 0
                    val |= (code & 0x03) << (i * 2)
                return val

            table.write_register("%R425", pack_tile_states(0, 4))
            table.write_register("%R426", pack_tile_states(4, 4))
            table.write_register("%R427", pack_tile_states(8, 4))

        finally:
            table.privilege_mode = prev_priv

    def render_svg(self) -> str:
        """Render standalone W3C SVG 1.1 vector graphics."""
        self.config.unack_count = sum(
            1 for t in self.tiles if t.state in (AnnunciatorState.UNACKNOWLEDGED, AnnunciatorState.SILENCED)
        )
        self.config.horn_sounding = self.horn_active
        self.config.lamp_test_active = self.lamp_test_active
        return self.rasterizer.render(self.tiles)


# ---------------------------------------------------------------------------
# Pure Structured Text POU Definition & Ladder Rejection Guard
# ---------------------------------------------------------------------------

ANNUNCIATOR_ST_CODE = """PROGRAM W081_AnnunciatorEngine
VAR
    StatusWord AT %R420 : INT := 1;
    TotalActiveCount AT %R421 : INT := 0;
    UnackCount AT %R422 : INT := 0;
    FirstOutIndex AT %R423 : INT := -1;
    SelectedIndex AT %R424 : INT := 0;
    Tiles0to3State AT %R425 : INT := 0;
    Tiles4to7State AT %R426 : INT := 0;
    Tiles8to11State AT %R427 : INT := 0;
    PbAck AT %M98 : BOOL := FALSE;
    PbSilenceReset AT %M99 : BOOL := FALSE;
END_VAR
VAR
    AlarmTrip0 : BOOL := FALSE;
    AlarmTrip1 : BOOL := FALSE;
    AlarmTrip2 : BOOL := FALSE;
    AlarmTrip3 : BOOL := FALSE;
    AlarmTrip4 : BOOL := FALSE;
    AlarmTrip5 : BOOL := FALSE;
    AlarmTrip6 : BOOL := FALSE;
    AlarmTrip7 : BOOL := FALSE;
    AlarmTrip8 : BOOL := FALSE;
    AlarmTrip9 : BOOL := FALSE;
    AlarmTrip10 : BOOL := FALSE;
    AlarmTrip11 : BOOL := FALSE;

    TileState0 : INT := 0;
    TileState1 : INT := 0;
    TileState2 : INT := 0;
    TileState3 : INT := 0;
    TileState4 : INT := 0;
    TileState5 : INT := 0;
    TileState6 : INT := 0;
    TileState7 : INT := 0;
    TileState8 : INT := 0;
    TileState9 : INT := 0;
    TileState10 : INT := 0;
    TileState11 : INT := 0;

    HornActive : BOOL := FALSE;
    FirstOutLatched : BOOL := FALSE;
    FlashPhase : BOOL := FALSE;
    LampTestActive : BOOL := FALSE;
    ScanCounter : INT := 0;
    TempStatus : INT := 0;
END_VAR

// Phase generator
ScanCounter := ScanCounter + 1;
IF ScanCounter >= 25 THEN
    ScanCounter := 0;
    FlashPhase := NOT FlashPhase;
END_IF;

// Operator Acknowledge Pushbutton (%M98)
IF PbAck THEN
    IF TileState0 = 1 THEN TileState0 := 2; END_IF;
    IF TileState1 = 1 THEN TileState1 := 2; END_IF;
    IF TileState2 = 1 THEN TileState2 := 2; END_IF;
    IF TileState3 = 1 THEN TileState3 := 2; END_IF;
    IF TileState4 = 1 THEN TileState4 := 2; END_IF;
    IF TileState5 = 1 THEN TileState5 := 2; END_IF;
    IF TileState6 = 1 THEN TileState6 := 2; END_IF;
    IF TileState7 = 1 THEN TileState7 := 2; END_IF;
    IF TileState8 = 1 THEN TileState8 := 2; END_IF;
    IF TileState9 = 1 THEN TileState9 := 2; END_IF;
    IF TileState10 = 1 THEN TileState10 := 2; END_IF;
    IF TileState11 = 1 THEN TileState11 := 2; END_IF;
    HornActive := FALSE;
    PbAck := FALSE;
END_IF;

// Operator Silence / Reset Pushbutton (%M99)
IF PbSilenceReset THEN
    IF HornActive THEN
        HornActive := FALSE;
    ELSE
        IF TileState0 = 3 THEN TileState0 := 0; END_IF;
        IF TileState1 = 3 THEN TileState1 := 0; END_IF;
        IF TileState2 = 3 THEN TileState2 := 0; END_IF;
        IF TileState3 = 3 THEN TileState3 := 0; END_IF;
        IF TileState4 = 3 THEN TileState4 := 0; END_IF;
        IF TileState5 = 3 THEN TileState5 := 0; END_IF;
        IF TileState6 = 3 THEN TileState6 := 0; END_IF;
        IF TileState7 = 3 THEN TileState7 := 0; END_IF;
        IF TileState8 = 3 THEN TileState8 := 0; END_IF;
        IF TileState9 = 3 THEN TileState9 := 0; END_IF;
        IF TileState10 = 3 THEN TileState10 := 0; END_IF;
        IF TileState11 = 3 THEN TileState11 := 0; END_IF;
        IF TotalActiveCount = 0 THEN
            FirstOutLatched := FALSE;
            FirstOutIndex := -1;
        END_IF;
    END_IF;
    PbSilenceReset := FALSE;
END_IF;

// Total Active and Unack Counts
TotalActiveCount := 0;
UnackCount := 0;

IF TileState0 <> 0 THEN TotalActiveCount := TotalActiveCount + 1; END_IF;
IF TileState0 = 1 THEN UnackCount := UnackCount + 1; END_IF;
IF TileState1 <> 0 THEN TotalActiveCount := TotalActiveCount + 1; END_IF;
IF TileState1 = 1 THEN UnackCount := UnackCount + 1; END_IF;
IF TileState2 <> 0 THEN TotalActiveCount := TotalActiveCount + 1; END_IF;
IF TileState2 = 1 THEN UnackCount := UnackCount + 1; END_IF;
IF TileState3 <> 0 THEN TotalActiveCount := TotalActiveCount + 1; END_IF;
IF TileState3 = 1 THEN UnackCount := UnackCount + 1; END_IF;

// State Bitfields Packing
Tiles0to3State := TileState0 + (TileState1 * 4) + (TileState2 * 16) + (TileState3 * 64);
Tiles4to7State := TileState4 + (TileState5 * 4) + (TileState6 * 16) + (TileState7 * 64);
Tiles8to11State := TileState8 + (TileState9 * 4) + (TileState10 * 16) + (TileState11 * 64);

// Status Word (%R420) Bit Packing
TempStatus := 1;
IF UnackCount > 0 THEN TempStatus := TempStatus + 2; END_IF;
IF HornActive THEN TempStatus := TempStatus + 4; END_IF;
IF FirstOutLatched THEN TempStatus := TempStatus + 8; END_IF;
IF FlashPhase THEN TempStatus := TempStatus + 16; END_IF;
IF LampTestActive THEN TempStatus := TempStatus + 32; END_IF;
StatusWord := TempStatus;

END_PROGRAM
"""


def validate_pure_st() -> ExecutionResult:
    """Validate ANNUNCIATOR_ST_CODE for pure ST syntax and no forbidden ladder logic."""
    SecurityGuard.assert_pure_st_content(ANNUNCIATOR_ST_CODE)
    return STParser.validate_code(ANNUNCIATOR_ST_CODE)
