"""Cscape HMI Dynamic Interactive Data Table & Column Virtualizer Rasterizer.

Work Package: W078 (Gate G9 / G2)
Standard: W3C SVG 1.1 Vector Graphics & WCAG 2.1 AAA Accessibility Contrast
Horner OCS Register Mappings:
- %R390: Status Word (Bit 0: Active, Bit 1: Sorting Active, Bit 2: Selected Valid, Bit 3: Overrun Warn, Bit 4: Virtual Scroll Active, Bit 5: Reverse Sort)
- %R391: Total Row Count (0..1000)
- %R392: Visible Window Start Row (0-based)
- %R393: Visible Row Page Size (nominal 10)
- %R394: Selected Row Index (-1 if none)
- %R395: Active Sort Column Index (0..7)
- %R396: Sort Direction (0: Ascending, 1: Descending)
- %R397: Total Column Count
- %M91: Enable Data Table Engine
- %M92: Trigger Sort / Filter Refresh
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple


class SortDirection(IntEnum):
    ASCENDING = 0
    DESCENDING = 1


class ColumnAlignment(IntEnum):
    LEFT = 0
    CENTER = 1
    RIGHT = 2


class StatusSeverity(IntEnum):
    NORMAL = 0
    WARNING = 1
    ALARM = 2


@dataclass
class ColumnDef:
    """Definition for a grid table column."""
    id: str
    title: str
    width: int
    alignment: ColumnAlignment = ColumnAlignment.LEFT
    is_monospace: bool = False
    is_badge: bool = False


@dataclass
class TableRow:
    """Row record in data table."""
    id: int
    timestamp: str
    tag: str
    value: float
    units: str
    status: StatusSeverity
    action: str = "VIEW"

    def get_cell_value(self, col_id: str) -> Any:
        if col_id == "id":
            return self.id
        elif col_id == "timestamp":
            return self.timestamp
        elif col_id == "tag":
            return self.tag
        elif col_id == "value":
            return self.value
        elif col_id == "units":
            return self.units
        elif col_id == "status":
            return self.status
        elif col_id == "action":
            return self.action
        return ""


@dataclass
class DataTableConfig:
    """Visual geometry and styling for HMI table rasterizer."""
    viewbox_width: int = 800
    viewbox_height: int = 480
    frame_x: int = 40
    frame_y: int = 34
    header_height: int = 36
    row_height: int = 30
    page_size: int = 10
    scrollbar_width: int = 16
    font_family: str = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    monospace_font: str = "'Consolas', 'Courier New', monospace"


class DataTableEngine:
    """Dynamic tabular vector rasterizer with virtual scrolling and WCAG AAA compliance."""

    DEFAULT_COLUMNS: List[ColumnDef] = [
        ColumnDef("id", "ID", 60, ColumnAlignment.CENTER),
        ColumnDef("timestamp", "TIMESTAMP", 140, ColumnAlignment.LEFT),
        ColumnDef("tag", "TAG NAME", 120, ColumnAlignment.LEFT),
        ColumnDef("value", "VALUE", 100, ColumnAlignment.RIGHT, is_monospace=True),
        ColumnDef("units", "UNIT", 60, ColumnAlignment.CENTER),
        ColumnDef("status", "STATUS", 120, ColumnAlignment.CENTER, is_badge=True),
        ColumnDef("action", "ACTION", 80, ColumnAlignment.CENTER),
    ]

    def __init__(
        self,
        config: Optional[DataTableConfig] = None,
        columns: Optional[List[ColumnDef]] = None,
    ) -> None:
        self.cfg = config or DataTableConfig()
        self.columns = columns or list(self.DEFAULT_COLUMNS)
        self.rows: List[TableRow] = []

        # Horner Registers State
        self.status_word: int = 0
        self.total_rows: int = 0
        self.start_row: int = 0
        self.page_size: int = self.cfg.page_size
        self.selected_row_idx: int = -1
        self.sort_col_idx: int = 0
        self.sort_dir: SortDirection = SortDirection.ASCENDING
        self.total_cols: int = len(self.columns)
        self.enable_engine: bool = True
        self.trigger_sort_refresh: bool = False

    def load_rows(self, rows: List[TableRow]) -> None:
        """Load data rows into table buffer."""
        self.rows = list(rows)
        self.total_rows = len(self.rows)
        self.update(self.start_row, self.selected_row_idx)

    def sort_data(self, col_index: int, direction: SortDirection) -> None:
        """Sort buffer by specified column index and direction."""
        if not (0 <= col_index < len(self.columns)):
            return
        col = self.columns[col_index]
        self.sort_col_idx = col_index
        self.sort_dir = direction

        reverse = (direction == SortDirection.DESCENDING)
        self.rows.sort(key=lambda r: r.get_cell_value(col.id), reverse=reverse)
        self.update(self.start_row, self.selected_row_idx)

    def update(
        self,
        start_row: int = 0,
        selected_row: int = -1,
        sort_col: Optional[int] = None,
        sort_dir: Optional[int] = None,
        enable: bool = True,
        trigger_sort: bool = False,
    ) -> None:
        """Update viewport state, bounds clamping, and Horner registers."""
        self.enable_engine = enable
        self.trigger_sort_refresh = trigger_sort

        if not self.enable_engine:
            self.status_word = 0
            return

        self.total_rows = len(self.rows)
        self.total_cols = len(self.columns)
        self.page_size = max(1, min(100, self.cfg.page_size))

        # Sort trigger handling
        sort_active = False
        if trigger_sort:
            sort_active = True
            if sort_col is not None and 0 <= sort_col < len(self.columns):
                self.sort_col_idx = sort_col
            if sort_dir is not None:
                self.sort_dir = SortDirection(sort_dir & 0x01)
            self.sort_data(self.sort_col_idx, self.sort_dir)
            self.trigger_sort_refresh = False

        # Virtual scroll window calculations
        max_start = max(0, self.total_rows - self.page_size)
        clamped_start = max(0, min(max_start, start_row))
        self.start_row = clamped_start

        # Selection validation
        selected_valid = (0 <= selected_row < self.total_rows)
        self.selected_row_idx = selected_row if selected_valid else -1

        # Overrun warning
        row_overrun = (start_row < 0 or start_row > max_start or (selected_row >= self.total_rows and self.total_rows > 0))
        virtual_scroll = (self.total_rows > self.page_size)
        reverse_sort = (self.sort_dir == SortDirection.DESCENDING)

        # Synthesize Status Word
        # Bit 0: Active, Bit 1: Sorting, Bit 2: Sel Valid, Bit 3: Overrun, Bit 4: VirtScroll, Bit 5: Reverse
        st = 0x0001
        if sort_active:
            st |= 0x0002
        if selected_valid:
            st |= 0x0004
        if row_overrun:
            st |= 0x0008
        if virtual_scroll:
            st |= 0x0010
        if reverse_sort:
            st |= 0x0020

        self.status_word = st

    def render_svg(self) -> str:
        """Generate standalone W3C SVG 1.1/2.0 markup conforming to WCAG 2.1 AAA contrast."""
        cfg = self.cfg
        cols = self.columns
        visible_rows = self.rows[self.start_row : self.start_row + self.page_size]
        total_col_width = sum(c.width for c in cols)
        table_width = total_col_width + cfg.scrollbar_width + 4
        table_height = cfg.header_height + (cfg.page_size * cfg.row_height) + 2

        out: List[str] = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {cfg.viewbox_width} {cfg.viewbox_height}" '
            f'width="{cfg.viewbox_width}" height="{cfg.viewbox_height}" '
            f'font-family="{cfg.font_family}" shape-rendering="crispEdges" role="grid" aria-label="Process Data Table">',
            "  <defs>",
        ]

        # Column clipping paths
        curr_x = cfg.frame_x
        for col in cols:
            out.append(
                f'    <clipPath id="clip-{col.id}">'
                f'<rect x="{curr_x + 4}" y="0" width="{col.width - 8}" height="{cfg.viewbox_height}" />'
                f"</clipPath>"
            )
            curr_x += col.width

        out.extend([
            "  </defs>",
            "  <!-- Table Background Enclosure -->",
            f'  <rect x="{cfg.frame_x}" y="{cfg.frame_y}" width="{table_width}" height="{table_height}" '
            f'rx="4" fill="#0F172A" stroke="#334155" stroke-width="1" />',
            "  <!-- Header Row -->",
            f'  <rect x="{cfg.frame_x}" y="{cfg.frame_y}" width="{table_width}" height="{cfg.header_height}" '
            f'fill="#1E293B" />',
            f'  <line x1="{cfg.frame_x}" y1="{cfg.frame_y + cfg.header_height}" '
            f'x2="{cfg.frame_x + table_width}" y2="{cfg.frame_y + cfg.header_height}" '
            f'stroke="#475569" stroke-width="1.5" />',
        ])

        # Header Cells
        curr_x = cfg.frame_x
        for idx, col in enumerate(cols):
            text_x = curr_x + 8
            anchor = "start"
            if col.alignment == ColumnAlignment.CENTER:
                text_x = curr_x + (col.width // 2)
                anchor = "middle"
            elif col.alignment == ColumnAlignment.RIGHT:
                text_x = curr_x + col.width - 8
                anchor = "end"

            sort_indicator = ""
            if idx == self.sort_col_idx:
                arrow = "&#x25BC;" if self.sort_dir == SortDirection.DESCENDING else "&#x25B2;"
                sort_indicator = f" {arrow}"

            out.append(
                f'  <text x="{text_x}" y="{cfg.frame_y + 23}" fill="#CBD5E1" font-size="11" '
                f'font-weight="700" letter-spacing="0.05em" text-anchor="{anchor}">'
                f'{col.title}{sort_indicator}</text>'
            )
            curr_x += col.width

        # Data Rows
        body_y = cfg.frame_y + cfg.header_height
        for r_idx in range(self.page_size):
            row_y = body_y + (r_idx * cfg.row_height)
            actual_row_idx = self.start_row + r_idx

            if actual_row_idx < len(self.rows):
                row_data = self.rows[actual_row_idx]
                is_selected = (actual_row_idx == self.selected_row_idx)

                # Background fill: Selected #1E3A8A, Alternating #1E293B / #0F172A
                if is_selected:
                    bg_color = "#1E3A8A"
                elif actual_row_idx % 2 == 1:
                    bg_color = "#1E293B"
                else:
                    bg_color = "#0F172A"

                out.append(
                    f'  <rect x="{cfg.frame_x}" y="{row_y}" width="{total_col_width}" '
                    f'height="{cfg.row_height}" fill="{bg_color}" />'
                )

                # 4px Left accent border for selected row (#38BDF8)
                if is_selected:
                    out.append(
                        f'  <rect x="{cfg.frame_x}" y="{row_y}" width="4" '
                        f'height="{cfg.row_height}" fill="#38BDF8" />'
                    )

                # Row divider line
                out.append(
                    f'  <line x1="{cfg.frame_x}" y1="{row_y + cfg.row_height}" '
                    f'x2="{cfg.frame_x + total_col_width}" y2="{row_y + cfg.row_height}" '
                    f'stroke="#334155" stroke-width="1" />'
                )

                # Render Cell Values
                c_x = cfg.frame_x
                for col in cols:
                    cell_val = row_data.get_cell_value(col.id)

                    if col.is_badge:
                        # Status Pill Badge with AAA contrast & redundant geometry
                        severity = StatusSeverity(int(cell_val)) if isinstance(cell_val, (int, StatusSeverity)) else StatusSeverity.NORMAL
                        badge_w = 90
                        badge_h = 20
                        badge_x = c_x + (col.width - badge_w) // 2
                        badge_y = row_y + (cfg.row_height - badge_h) // 2

                        if severity == StatusSeverity.ALARM:
                            b_bg, b_txt, b_stroke, b_glyph, b_label = "#7F1D1D", "#FEE2E2", "#DC2626", "&#x25A0;", "ALARM"
                        elif severity == StatusSeverity.WARNING:
                            b_bg, b_txt, b_stroke, b_glyph, b_label = "#78350F", "#FDE68A", "#D97706", "&#x25B2;", "WARN"
                        else:
                            b_bg, b_txt, b_stroke, b_glyph, b_label = "#064E3B", "#A7F3D0", "#059669", "&#x25CF;", "NORM"

                        out.extend([
                            f'  <g role="status" aria-label="{b_label}">',
                            f'    <rect x="{badge_x}" y="{badge_y}" width="{badge_w}" height="{badge_h}" '
                            f'rx="10" fill="{b_bg}" stroke="{b_stroke}" stroke-width="1" />',
                            f'    <text x="{badge_x + badge_w // 2}" y="{badge_y + 14}" fill="{b_txt}" '
                            f'font-size="10" font-weight="700" text-anchor="middle">{b_glyph} {b_label}</text>',
                            f"  </g>",
                        ])
                    else:
                        font_style = f'font-family="{cfg.monospace_font}" ' if col.is_monospace else ""
                        text_x = c_x + 8
                        anchor = "start"
                        if col.alignment == ColumnAlignment.CENTER:
                            text_x = c_x + (col.width // 2)
                            anchor = "middle"
                        elif col.alignment == ColumnAlignment.RIGHT:
                            text_x = c_x + col.width - 8
                            anchor = "end"

                        display_text = f"{cell_val:.2f}" if isinstance(cell_val, float) else str(cell_val)
                        txt_color = "#F8FAFC" if not is_selected else "#FFFFFF"
                        if col.id in ("id", "units"):
                            txt_color = "#CBD5E1"

                        out.append(
                            f'  <text x="{text_x}" y="{row_y + 19}" fill="{txt_color}" font-size="12" '
                            f'{font_style}text-anchor="{anchor}" clip-path="url(#clip-{col.id})">'
                            f"{display_text}</text>"
                        )
                    c_x += col.width
            else:
                # Empty row placeholder
                bg_color = "#1E293B" if r_idx % 2 == 1 else "#0F172A"
                out.extend([
                    f'  <rect x="{cfg.frame_x}" y="{row_y}" width="{total_col_width}" '
                    f'height="{cfg.row_height}" fill="{bg_color}" />',
                    f'  <line x1="{cfg.frame_x}" y1="{row_y + cfg.row_height}" '
                    f'x2="{cfg.frame_x + total_col_width}" y2="{row_y + cfg.row_height}" '
                    f'stroke="#334155" stroke-width="1" />',
                ])

        # Vertical Scrollbar
        sb_x = cfg.frame_x + total_col_width + 2
        sb_y = body_y
        sb_h = cfg.page_size * cfg.row_height

        # Scroll track
        out.append(
            f'  <rect x="{sb_x}" y="{sb_y}" width="{cfg.scrollbar_width}" height="{sb_h}" '
            f'rx="2" fill="#1E293B" stroke="#334155" stroke-width="1" />'
        )

        # Scroll thumb
        if self.total_rows > self.page_size:
            ratio = self.page_size / self.total_rows
            thumb_h = max(24, int(sb_h * ratio))
            max_scroll = self.total_rows - self.page_size
            scroll_pos = (self.start_row / max_scroll) if max_scroll > 0 else 0.0
            thumb_y = sb_y + int(scroll_pos * (sb_h - thumb_h))
            out.append(
                f'  <rect x="{sb_x + 2}" y="{thumb_y}" width="{cfg.scrollbar_width - 4}" '
                f'height="{thumb_h}" rx="2" fill="#475569" stroke="#64748B" stroke-width="1" />'
            )

        out.append("</svg>")
        return "\n".join(out)

    def sync_to_register_table(self, reg_table: Any) -> None:
        """Write table status and cursor variables to Horner OCS RegisterTable."""
        write_fn = getattr(reg_table, "write_register", getattr(reg_table, "write", None))
        if write_fn is None:
            return
        write_fn("%R390", self.status_word)
        write_fn("%R391", min(1000, self.total_rows))
        write_fn("%R392", self.start_row)
        write_fn("%R393", self.page_size)
        write_fn("%R394", self.selected_row_idx)
        write_fn("%R395", self.sort_col_idx)
        write_fn("%R396", int(self.sort_dir))
        write_fn("%R397", self.total_cols)
        write_fn("%M91", self.enable_engine)
        write_fn("%M92", self.trigger_sort_refresh)

    def sync_from_register_table(self, reg_table: Any) -> None:
        """Read scroll and sort controls from Horner OCS RegisterTable."""
        read_fn = getattr(reg_table, "read_register", getattr(reg_table, "read", None))
        if read_fn is None:
            return
        enable = bool(read_fn("%M91"))
        trigger_sort = bool(read_fn("%M92"))
        start_row = int(read_fn("%R392"))
        selected_idx = int(read_fn("%R394"))
        sort_col = int(read_fn("%R395"))
        sort_dir = int(read_fn("%R396"))

        self.update(
            start_row=start_row,
            selected_row=selected_idx,
            sort_col=sort_col,
            sort_dir=sort_dir,
            enable=enable,
            trigger_sort=trigger_sort,
        )


# ---------------------------------------------------------------------------
# Pure Structured Text POU Definition
# ---------------------------------------------------------------------------

DATA_TABLE_ST_CODE = """PROGRAM DataTableGridRasterizerSync
VAR
    StatusWord AT %R390 : WORD;
    TotalRowCount AT %R391 : INT;
    VisibleStartRow AT %R392 : INT;
    PageSize AT %R393 : INT;
    SelectedRowIndex AT %R394 : INT;
    ActiveSortCol AT %R395 : INT;
    SortDirection AT %R396 : INT;
    TotalColCount AT %R397 : INT;
    EnableEngine AT %M91 : BOOL;
    TriggerSortRefresh AT %M92 : BOOL;

    ClampedRowCount : INT;
    ClampedPageSize : INT;
    MaxStartRow : INT;
    ClampedStartRow : INT;
    SelectedValid : BOOL;
    RowOverrun : BOOL;
    VirtualScroll : BOOL;
    ReverseSort : BOOL;
    SortActive : BOOL;
    StatusAccum : WORD;
END_VAR

IF EnableEngine THEN
    IF TotalRowCount < 0 THEN
        ClampedRowCount := 0;
        RowOverrun := TRUE;
    ELSIF TotalRowCount > 1000 THEN
        ClampedRowCount := 1000;
        RowOverrun := TRUE;
    ELSE
        ClampedRowCount := TotalRowCount;
        RowOverrun := FALSE;
    END_IF;

    IF PageSize <= 0 THEN
        ClampedPageSize := 10;
    ELSIF PageSize > 100 THEN
        ClampedPageSize := 100;
    ELSE
        ClampedPageSize := PageSize;
    END_IF;

    IF ClampedRowCount > ClampedPageSize THEN
        VirtualScroll := TRUE;
        MaxStartRow := ClampedRowCount - ClampedPageSize;
    ELSE
        VirtualScroll := FALSE;
        MaxStartRow := 0;
    END_IF;

    IF VisibleStartRow < 0 THEN
        ClampedStartRow := 0;
        RowOverrun := TRUE;
    ELSIF VisibleStartRow > MaxStartRow THEN
        ClampedStartRow := MaxStartRow;
        RowOverrun := TRUE;
    ELSE
        ClampedStartRow := VisibleStartRow;
    END_IF;
    VisibleStartRow := ClampedStartRow;

    IF SelectedRowIndex >= 0 AND SelectedRowIndex < ClampedRowCount THEN
        SelectedValid := TRUE;
    ELSE
        SelectedValid := FALSE;
        IF SelectedRowIndex >= ClampedRowCount AND ClampedRowCount > 0 THEN
            RowOverrun := TRUE;
        END_IF;
    END_IF;

    IF TotalColCount <= 0 THEN
        TotalColCount := 1;
    ELSIF TotalColCount > 8 THEN
        TotalColCount := 8;
    END_IF;

    IF ActiveSortCol < 0 THEN
        ActiveSortCol := 0;
    ELSIF ActiveSortCol >= TotalColCount THEN
        ActiveSortCol := TotalColCount - 1;
    END_IF;

    IF SortDirection = 1 THEN
        ReverseSort := TRUE;
    ELSE
        ReverseSort := FALSE;
        SortDirection := 0;
    END_IF;

    IF TriggerSortRefresh THEN
        SortActive := TRUE;
        TriggerSortRefresh := FALSE;
    ELSE
        SortActive := FALSE;
    END_IF;

    StatusAccum := 16#0001;

    IF SortActive THEN
        StatusAccum := StatusAccum OR 16#0002;
    END_IF;

    IF SelectedValid THEN
        StatusAccum := StatusAccum OR 16#0004;
    END_IF;

    IF RowOverrun THEN
        StatusAccum := StatusAccum OR 16#0008;
    END_IF;

    IF VirtualScroll THEN
        StatusAccum := StatusAccum OR 16#0010;
    END_IF;

    IF ReverseSort THEN
        StatusAccum := StatusAccum OR 16#0020;
    END_IF;

    StatusWord := StatusAccum;
ELSE
    StatusWord := 16#0000;
    SortActive := FALSE;
    SelectedValid := FALSE;
    RowOverrun := FALSE;
    VirtualScroll := FALSE;
    ReverseSort := FALSE;
END_IF;
END_PROGRAM
"""
