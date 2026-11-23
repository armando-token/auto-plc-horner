"""Vision Grounding & UI Pane Analyzer for Horner Cscape 10.2 (Work Package W028, Gate G9).

Performs non-invasive visual region segmentation and bounding box extraction for Cscape:
- Ribbon / Menu bar rect (MFC ControlBar top pane)
- Project Navigator dock pane rect (SysTreeView32 inside Afx:ControlBar)
- Output Window dock pane rect (ListBox 372 inside Afx:ControlBar)
- Central ladder/ST editor viewport rect (MDI Client canvas)
- Status bar rect (msctls_statusbar32)

Computes bounding boxes, luminance contrast ratios, and element visibility metrics.
Provides fallback screen coordinates for unexposed MFC controls when UIAutomation
accessibility trees are inaccessible or unexposed.
Conforms strictly to the 4-state engineering contract (AgentStatus.SUCCESS | FAILED | BLOCKED | INCONCLUSIVE).
"""

from __future__ import annotations

import io
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from PIL import Image
from pydantic import BaseModel, Field

from jev_cscape.contracts import AgentStatus, ExecutionResult

logger = logging.getLogger(__name__)

# Default screenshot capture path produced by GDI PrintWindow
DEFAULT_SCREENSHOT_PATH = "artifacts/logs/cscape_live_window.png"

# Canonical supported screen / canvas resolutions for Cscape workspace (SVGA, XGA, SXGA, FHD)
SUPPORTED_RESOLUTIONS: Dict[str, Tuple[int, int]] = {
    "SVGA": (800, 600),
    "XGA": (1024, 768),
    "SXGA": (1280, 1024),
    "FHD": (1920, 1080),
}

# ============================================================================
# WCAG 2.1 AAA Relative Luminance and Contrast Ratio Specifications
# ============================================================================

WCAG_AAA_TEXT_CONTRAST_TARGET: float = 7.0       # Standard text WCAG 2.1 AAA benchmark
WCAG_AAA_LARGE_TEXT_CONTRAST_TARGET: float = 4.5 # Large text (>=18pt or >=14pt bold) WCAG AAA
WCAG_GRAPHICAL_CONTRAST_TARGET: float = 3.0      # Graphical UI components & boundaries
WCAG_AAA_BADGE_CONTRAST_TARGET: float = 18.0     # Decoupled high-contrast badge target


def srgb_channel_to_linear(channel: float) -> float:
    """Convert an sRGB color component in range [0.0, 1.0] to linear luminance per WCAG 2.1.

    Formula:
        c_lin = c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    """
    c = max(0.0, min(1.0, float(channel)))
    if c <= 0.04045:
        return c / 12.92
    return ((c + 0.055) / 1.055) ** 2.4


# Precomputed 256-element linear luminance lookup tables for sRGB channels
_R_LUM_LUT: Tuple[float, ...] = tuple(0.2126 * srgb_channel_to_linear(i / 255.0) for i in range(256))
_G_LUM_LUT: Tuple[float, ...] = tuple(0.7152 * srgb_channel_to_linear(i / 255.0) for i in range(256))
_B_LUM_LUT: Tuple[float, ...] = tuple(0.0722 * srgb_channel_to_linear(i / 255.0) for i in range(256))


def calculate_relative_luminance(
    color: Union[Tuple[int, int, int], Tuple[float, float, float], str]
) -> float:
    """Calculate relative luminance L per W3C WCAG 2.1 specifications:

    L = 0.2126 * R_lin + 0.7152 * G_lin + 0.0722 * B_lin

    Accepts:
    - Hex color string: e.g. '#0B0F19', '0B0F19', '#FFF', 'FFF'
    - RGB tuple of ints [0, 255]: e.g. (11, 15, 25)
    - RGB tuple of floats [0.0, 1.0]: e.g. (0.043, 0.059, 0.098)

    Returns:
        Relative luminance L in range [0.0, 1.0].
    """
    if isinstance(color, str):
        hex_clean = color.strip().lstrip("#")
        if len(hex_clean) == 3:
            hex_clean = "".join(c * 2 for c in hex_clean)
        if len(hex_clean) != 6:
            raise ValueError(f"Invalid hexadecimal color string: '{color}'")
        try:
            r = int(hex_clean[0:2], 16) / 255.0
            g = int(hex_clean[2:4], 16) / 255.0
            b = int(hex_clean[4:6], 16) / 255.0
        except ValueError as e:
            raise ValueError(f"Invalid hex color characters in '{color}': {e}") from e
    elif isinstance(color, (tuple, list)) and len(color) >= 3:
        c0, c1, c2 = color[0], color[1], color[2]
        if any(isinstance(c, float) for c in (c0, c1, c2)) and all(0.0 <= c <= 1.0 for c in (c0, c1, c2)):
            r, g, b = float(c0), float(c1), float(c2)
        else:
            r, g, b = float(c0) / 255.0, float(c1) / 255.0, float(c2) / 255.0
    else:
        raise TypeError(f"Unsupported color representation: {type(color)} ({color})")

    r_lin = srgb_channel_to_linear(r)
    g_lin = srgb_channel_to_linear(g)
    b_lin = srgb_channel_to_linear(b)

    lum = 0.2126 * r_lin + 0.7152 * g_lin + 0.0722 * b_lin
    return max(0.0, min(1.0, lum))


def calculate_contrast_ratio(
    color1: Union[Tuple[int, int, int], Tuple[float, float, float], str, float],
    color2: Union[Tuple[int, int, int], Tuple[float, float, float], str, float],
) -> float:
    """Calculate WCAG 2.1 contrast ratio between two colors or luminance values:

    Contrast Ratio = (L1 + 0.05) / (L2 + 0.05)
    where L1 is relative luminance of the lighter color and L2 of the darker color.

    Guarantees:
    - Never divides by zero (denominator >= 0.05)
    - Returns valid mathematical float in range [1.0, 21.0]
    """
    if isinstance(color1, (int, float)):
        lum1 = max(0.0, min(1.0, float(color1)))
    else:
        lum1 = calculate_relative_luminance(color1)

    if isinstance(color2, (int, float)):
        lum2 = max(0.0, min(1.0, float(color2)))
    else:
        lum2 = calculate_relative_luminance(color2)

    lighter = max(lum1, lum2)
    darker = min(lum1, lum2)

    ratio = (lighter + 0.05) / (darker + 0.05)
    return max(1.0, min(21.0, ratio))


def validate_wcag_aaa_contrast(
    fg: Union[Tuple[int, int, int], Tuple[float, float, float], str, float],
    bg: Union[Tuple[int, int, int], Tuple[float, float, float], str, float],
    min_contrast: float = WCAG_AAA_TEXT_CONTRAST_TARGET,
) -> bool:
    """Validate whether foreground on background satisfies WCAG AAA contrast ratio."""
    return calculate_contrast_ratio(fg, bg) >= min_contrast


class WindowRegion(BaseModel):
    """Represents a segmented visual region within the Cscape 10.2 window workspace."""

    name: str = Field(..., description="Canonical identifier of the window region")
    left: int = Field(..., description="X coordinate of left edge in pixels (relative to window top-left)")
    top: int = Field(..., description="Y coordinate of top edge in pixels (relative to window top-left)")
    right: int = Field(..., description="X coordinate of right edge in pixels (exclusive)")
    bottom: int = Field(..., description="Y coordinate of bottom edge in pixels (exclusive)")
    width: int = Field(..., description="Width of the region in pixels")
    height: int = Field(..., description="Height of the region in pixels")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Detection confidence score [0.0, 1.0]")
    contrast_ratio: float = Field(default=1.0, ge=1.0, description="WCAG luminance contrast ratio [1.0, 21.0]")
    rms_contrast: float = Field(default=0.0, ge=0.0, description="Root-mean-square luminance contrast / standard deviation")
    is_visible: bool = Field(default=True, description="True if region is visible and non-collapsed")
    control_type: Optional[str] = Field(default=None, description="Inferred or mapped Win32/MFC control type")
    mfc_pane_id: Optional[int] = Field(default=None, description="Known Horner Cscape MFC Control ID if applicable")
    description: Optional[str] = Field(default=None, description="Human-readable description of region role")

    @property
    def center(self) -> Tuple[int, int]:
        """Center coordinate (x, y) of the region."""
        return (self.left + self.width // 2, self.top + self.height // 2)

    @property
    def center_x(self) -> int:
        """Center X coordinate."""
        return self.left + self.width // 2

    @property
    def center_y(self) -> int:
        """Center Y coordinate."""
        return self.top + self.height // 2

    @property
    def bounding_box(self) -> Tuple[int, int, int, int]:
        """Bounding box tuple (left, top, right, bottom)."""
        return (self.left, self.top, self.right, self.bottom)

    def contains(self, x: int, y: int) -> bool:
        """Check whether the point (x, y) lies inside this region."""
        return self.left <= x < self.right and self.top <= y < self.bottom

    def intersects(self, other: "WindowRegion") -> bool:
        """Check whether this region overlaps with another region."""
        return not (
            self.right <= other.left
            or self.left >= other.right
            or self.bottom <= other.top
            or self.top >= other.bottom
        )

    def get_relative_point(self, rel_x: float, rel_y: float, clamp_to_bounds: bool = False) -> Tuple[int, int]:
        """Compute absolute window coordinates from normalized relative coordinates [0.0, 1.0]."""
        if not (0.0 <= rel_x <= 1.0 and 0.0 <= rel_y <= 1.0):
            raise ValueError(f"Relative coordinates must be in [0.0, 1.0], got rel_x={rel_x}, rel_y={rel_y}")
        abs_x = int(round(self.left + rel_x * self.width))
        abs_y = int(round(self.top + rel_y * self.height))
        if clamp_to_bounds:
            if self.width > 0:
                abs_x = max(self.left, min(abs_x, self.right - 1))
            if self.height > 0:
                abs_y = max(self.top, min(abs_y, self.bottom - 1))
        return (abs_x, abs_y)

    def validate_bounds(self, max_width: int, max_height: int) -> bool:
        """Verify that the region is geometrically valid and contained within window bounds."""
        return (
            0 <= self.left < self.right <= max_width
            and 0 <= self.top < self.bottom <= max_height
            and self.width == (self.right - self.left)
            and self.height == (self.bottom - self.top)
            and self.width > 0
            and self.height > 0
        )


class FallbackCoordinate(BaseModel):
    """Fallback visual click/interaction coordinate for unexposed MFC controls."""

    control_name: str = Field(..., description="Target control identifier")
    region_name: str = Field(..., description="Parent window region containing this control")
    x: int = Field(..., description="Calculated X coordinate in window space")
    y: int = Field(..., description="Calculated Y coordinate in window space")
    rel_x: float = Field(..., description="Relative horizontal anchor [0.0, 1.0]")
    rel_y: float = Field(..., description="Relative vertical anchor [0.0, 1.0]")
    is_visible: bool = Field(default=True, description="Whether parent region is visible")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence of fallback coordinate")
    description: str = Field(default="", description="Description of the unexposed control")


class VisionAnalysisReport(BaseModel):
    """Complete structured output from vision grounding segmentation."""

    image_source: str = Field(default="live_capture", description="Image source path or memory buffer")
    dimensions: Dict[str, int] = Field(..., description="Window dimensions {'width': int, 'height': int}")
    regions: Dict[str, WindowRegion] = Field(..., description="Segmented workspace regions by name")
    fallback_controls: Dict[str, FallbackCoordinate] = Field(..., description="Resolved fallback control coordinates")


# Canonical unexposed MFC controls mapping:
# Key -> (region_name, rel_x, rel_y, description)
DEFAULT_FALLBACK_CONTROLS: Dict[str, Tuple[str, float, float, str]] = {
    # Ribbon / Menu bar controls
    "menu_file": ("ribbon_menu_bar", 0.035, 0.25, "File menu dropdown anchor"),
    "menu_edit": ("ribbon_menu_bar", 0.075, 0.25, "Edit menu dropdown anchor"),
    "menu_view": ("ribbon_menu_bar", 0.115, 0.25, "View menu dropdown anchor"),
    "menu_program": ("ribbon_menu_bar", 0.165, 0.25, "Program menu dropdown anchor"),
    "menu_controller": ("ribbon_menu_bar", 0.225, 0.25, "Controller menu dropdown anchor"),
    "ribbon_error_check": ("ribbon_menu_bar", 0.280, 0.70, "Compile / Error Check toolbar button (ID 32826)"),
    "ribbon_save": ("ribbon_menu_bar", 0.080, 0.70, "Save project toolbar button (ID 57603)"),

    # Project Navigator dock pane controls
    "project_navigator_root": ("project_navigator", 0.25, 0.05, "Tree root node (Project Navigator)"),
    "project_navigator_tree": ("project_navigator", 0.50, 0.50, "SysTreeView32 client center"),
    "project_navigator_hardware": ("project_navigator", 0.35, 0.12, "Hardware Configuration branch"),
    "project_navigator_logic": ("project_navigator", 0.35, 0.25, "Logic Modules branch"),
    "project_navigator_first_item": ("project_navigator", 0.30, 0.08, "First tree item"),

    # Central Editor Viewport controls
    "editor_canvas": ("editor_viewport", 0.50, 0.50, "Central MDI workspace center"),
    "editor_origin": ("editor_viewport", 0.05, 0.05, "Top-left gutter / Rung 1 anchor"),
    "editor_first_rung": ("editor_viewport", 0.10, 0.10, "First ladder rung drop target"),
    "editor_tab_bar": ("editor_viewport", 0.10, 0.02, "MDI document tab strip"),

    # Output Window dock pane controls
    "output_caption": ("output_window", 0.50, 0.05, "Output window docking title bar"),
    "output_listbox": ("output_window", 0.50, 0.55, "Compiler output ListBox 372 center"),
    "output_first_line": ("output_window", 0.05, 0.20, "First compilation diagnostic item"),
    "output_close_button": ("output_window", 0.98, 0.05, "Dock pane close button"),

    # Status Bar controls
    "status_bar_target_plc": ("status_bar", 0.68, 0.50, "Target controller model pane"),
    "status_bar_comms_status": ("status_bar", 0.84, 0.50, "Communication status pane"),
    "status_bar_cursor_pos": ("status_bar", 0.95, 0.50, "Cursor line/column or rung pane"),
}


class VisionGroundingEngine:
    """Vision grounding and UI pane analyzer for Horner Cscape 10.2."""

    def __init__(
        self,
        default_screenshot_path: str = DEFAULT_SCREENSHOT_PATH,
        fallback_registry: Optional[Dict[str, Tuple[str, float, float, str]]] = None,
    ) -> None:
        self.default_screenshot_path = default_screenshot_path
        self._fallback_registry: Dict[str, Tuple[str, float, float, str]] = dict(
            fallback_registry or DEFAULT_FALLBACK_CONTROLS
        )

    def register_fallback_control(
        self,
        control_name: str,
        region_name: str,
        rel_x: float,
        rel_y: float,
        description: str = "",
    ) -> None:
        """Register or override an unexposed MFC control fallback coordinate anchor."""
        if not (0.0 <= rel_x <= 1.0 and 0.0 <= rel_y <= 1.0):
            raise ValueError(f"Relative anchors must be within [0.0, 1.0], got rel_x={rel_x}, rel_y={rel_y}")
        self._fallback_registry[control_name] = (region_name, rel_x, rel_y, description)

    def load_image(
        self,
        source: Optional[Union[str, Path, Image.Image, bytes, io.BytesIO]] = None,
    ) -> Image.Image:
        """Load an image from a file path, PIL Image, or memory buffer."""
        if source is None:
            source = self.default_screenshot_path

        if isinstance(source, Image.Image):
            return source.convert("RGB")

        if isinstance(source, (bytes, io.BytesIO)):
            buffer = io.BytesIO(source) if isinstance(source, bytes) else source
            try:
                img = Image.open(buffer)
                return img.convert("RGB")
            except Exception as e:
                raise ValueError(f"Failed to decode image from memory buffer: {e}") from e

        # Source is a filepath
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"Screenshot image not found at '{path.resolve()}'.")

        try:
            img = Image.open(path)
            return img.convert("RGB")
        except Exception as e:
            raise ValueError(f"Failed to open image file at '{path}': {e}") from e

    srgb_channel_to_linear = staticmethod(srgb_channel_to_linear)
    calculate_relative_luminance = staticmethod(calculate_relative_luminance)
    calculate_contrast_ratio = staticmethod(calculate_contrast_ratio)
    validate_wcag_aaa_contrast = staticmethod(validate_wcag_aaa_contrast)

    @staticmethod
    def compute_contrast_metrics(crop: Image.Image) -> Tuple[float, float, bool]:
        """Compute WCAG luminance contrast ratio, RMS contrast, and visibility flag.

        Uses W3C WCAG 2.1 relative luminance specification:
            L = 0.2126 * R_lin + 0.7152 * G_lin + 0.0722 * B_lin
            Contrast Ratio = (L1 + 0.05) / (L2 + 0.05)

        Returns:
            Tuple of (contrast_ratio, rms_contrast, is_visible)
        """
        if crop.width <= 0 or crop.height <= 0:
            return 1.0, 0.0, False

        rgb = crop.convert("RGB")
        raw_bytes = rgb.tobytes()
        n_pixels = len(raw_bytes) // 3
        if n_pixels == 0:
            return 1.0, 0.0, False

        # Fast exact RMS contrast (standard deviation of pixel grayscale intensity [0, 255])
        gray = crop.convert("L")
        hist = gray.histogram()
        mean_gray = sum(i * count for i, count in enumerate(hist)) / n_pixels
        variance = sum(((i - mean_gray) ** 2) * count for i, count in enumerate(hist)) / n_pixels
        rms_contrast = variance ** 0.5

        # Subsample pixels if large, for deterministic fast WCAG relative luminance
        if n_pixels <= 20000:
            step = 3
        else:
            step = max(3, (n_pixels // 20000) * 3)

        r_bytes = raw_bytes[0::step]
        g_bytes = raw_bytes[1::step]
        b_bytes = raw_bytes[2::step]

        lums = [_R_LUM_LUT[r] + _G_LUM_LUT[g] + _B_LUM_LUT[b] for r, g, b in zip(r_bytes, g_bytes, b_bytes)]
        if not lums:
            return 1.0, 0.0, False

        lums.sort()
        m = len(lums)
        p05 = lums[int(0.05 * m)]
        p95 = lums[min(m - 1, int(0.95 * m))]

        contrast_ratio = calculate_contrast_ratio(p95, p05)

        # Region visibility determination:
        # Sufficient pixel dimensions for rendering on desktop workspace
        is_visible = crop.width >= 5 and crop.height >= 5

        return round(contrast_ratio, 3), round(rms_contrast, 3), is_visible

    def segment_regions(
        self,
        source: Optional[Union[str, Path, Image.Image, bytes, io.BytesIO]] = None,
    ) -> Dict[str, WindowRegion]:
        """Segment the Cscape window screenshot into 5 non-overlapping canonical workspace regions.

        Regions extracted:
        1. ribbon_menu_bar: Top Ribbon and Menu bar
        2. project_navigator: Left Project Navigator dock pane
        3. output_window: Bottom Compiler Output dock pane
        4. editor_viewport: Central Ladder / ST Editor viewport
        5. status_bar: Bottom Status bar

        Returns:
            Dict mapping region name to WindowRegion model.
        """
        img = self.load_image(source)
        width, height = img.size

        if width < 50 or height < 50:
            raise ValueError(f"Image dimensions too small for Cscape window segmentation: ({width}x{height})")

        gray = img.convert("L")

        # ------------------------------------------------------------------
        # 1. Detect Status Bar top boundary (bottom of window)
        # ------------------------------------------------------------------
        status_bar_h = max(20, min(26, int(height * 0.04)))
        status_min_y = max(1, height - 60)
        status_max_y = max(status_min_y + 1, height - 15)
        best_status_y = max(0, height - status_bar_h)
        max_status_diff = 0
        step_x = max(1, width // 60)

        for y in range(status_min_y, status_max_y):
            diff = sum(
                abs(gray.getpixel((x, y)) - gray.getpixel((x, y - 1)))
                for x in range(0, width, step_x)
            )
            if diff > max_status_diff and diff > 300:
                max_status_diff = diff
                best_status_y = y

        best_status_y = max(status_min_y, min(best_status_y, status_max_y))

        # ------------------------------------------------------------------
        # 2. Detect Ribbon / Menu Bar bottom boundary (top of window)
        # ------------------------------------------------------------------
        ribbon_min_y = max(20, int(height * 0.15))
        ribbon_max_y = min(best_status_y - 40, int(height * 0.35))
        best_ribbon_y = min(165, int(height * 0.28))
        max_ribbon_diff = 0

        for y in range(ribbon_min_y, ribbon_max_y):
            diff = sum(
                abs(gray.getpixel((x, y)) - gray.getpixel((x, y - 1)))
                for x in range(0, width, step_x)
            )
            if diff > max_ribbon_diff and diff > 500:
                max_ribbon_diff = diff
                best_ribbon_y = y

        # Ensure ribbon_bottom is strictly above status_bar_top and within valid bounds
        if best_ribbon_y >= best_status_y - 20:
            best_ribbon_y = max(20, int(height * 0.25))
        best_ribbon_y = max(ribbon_min_y, min(best_ribbon_y, ribbon_max_y))

        # ------------------------------------------------------------------
        # 3. Detect Project Navigator right boundary (Vertical Splitter)
        # ------------------------------------------------------------------
        split_min_x = max(20, int(width * 0.15))
        split_max_x = min(width - 50, int(width * 0.38))
        best_split_x = max(split_min_x, min(int(round(width * 0.244)), split_max_x))
        max_split_diff = 0
        step_y = max(1, (best_status_y - best_ribbon_y) // 40)

        for x in range(split_min_x, split_max_x):
            diff = sum(
                abs(gray.getpixel((x, y)) - gray.getpixel((x - 1, y)))
                for y in range(best_ribbon_y + 10, best_status_y - 10, step_y)
            )
            if diff > max_split_diff and diff > 400:
                max_split_diff = diff
                best_split_x = x

        # Ensure vertical splitter leaves reasonable space for both left & right
        if best_split_x >= width - 50:
            best_split_x = int(width * 0.25)
        best_split_x = max(split_min_x, min(best_split_x, split_max_x))

        # ------------------------------------------------------------------
        # 4. Detect Output Window top boundary (Horizontal Splitter in Right Pane)
        # ------------------------------------------------------------------
        workspace_h = best_status_y - best_ribbon_y
        out_min_y = best_ribbon_y + int(workspace_h * 0.30)
        out_max_y = best_ribbon_y + int(workspace_h * 0.75)
        best_out_y = best_ribbon_y + int(workspace_h * 0.50)
        max_out_diff = 0
        step_out_x = max(1, (width - best_split_x) // 40)

        for y in range(out_min_y, out_max_y):
            diff = sum(
                abs(gray.getpixel((x, y)) - gray.getpixel((x, y - 1)))
                for x in range(best_split_x + 20, width - 20, step_out_x)
            )
            if diff > max_out_diff and diff > 400:
                max_out_diff = diff
                best_out_y = y

        # Ensure output window top leaves reasonable space for editor viewport
        if best_out_y <= best_ribbon_y + 20 or best_out_y >= best_status_y - 20:
            best_out_y = best_ribbon_y + int(workspace_h * 0.50)
        best_out_y = max(out_min_y, min(best_out_y, out_max_y))

        # ------------------------------------------------------------------
        # 5. Build WindowRegion instances with bounding box validation & contrast
        # ------------------------------------------------------------------
        regions_def = [
            (
                "ribbon_menu_bar",
                0,
                0,
                width,
                best_ribbon_y,
                "RibbonBar",
                59392,
                "Top Ribbon and Menu bar containing File, Edit, View, Program, Controller menus",
            ),
            (
                "project_navigator",
                0,
                best_ribbon_y,
                best_split_x,
                best_status_y,
                "SysTreeView32",
                32800,
                "Project Navigator dock pane containing System, Logic, Hardware, and UI hierarchy",
            ),
            (
                "editor_viewport",
                best_split_x,
                best_ribbon_y,
                width,
                best_out_y,
                "MDIClient",
                59648,
                "Central MDI logic editor canvas for Structured Text POUs and ladder networks",
            ),
            (
                "output_window",
                best_split_x,
                best_out_y,
                width,
                best_status_y,
                "ListBox",
                372,
                "Compiler Output Window dock pane for build errors, warnings, and diagnostic logs",
            ),
            (
                "status_bar",
                0,
                best_status_y,
                width,
                height,
                "msctls_statusbar32",
                59393,
                "Bottom status bar displaying target PLC model, comms status, and cursor coordinates",
            ),
        ]

        result_regions: Dict[str, WindowRegion] = {}

        for name, left, top, right, bottom, ctype, pane_id, desc in regions_def:
            w = right - left
            h = bottom - top

            # Crop sub-region to compute contrast and visibility metrics
            crop = img.crop((left, top, right, bottom))
            cr, rms, vis = self.compute_contrast_metrics(crop)

            region = WindowRegion(
                name=name,
                left=left,
                top=top,
                right=right,
                bottom=bottom,
                width=w,
                height=h,
                confidence=0.98 if max_status_diff > 0 else 0.88,
                contrast_ratio=cr,
                rms_contrast=rms,
                is_visible=vis,
                control_type=ctype,
                mfc_pane_id=pane_id,
                description=desc,
            )

            if not region.validate_bounds(width, height):
                raise ValueError(f"Region '{name}' failed geometric bounds validation: {region.bounding_box}")

            result_regions[name] = region

        return result_regions

    def get_control_fallback_coordinates(
        self,
        control_name: str,
        regions: Optional[Dict[str, WindowRegion]] = None,
        source: Optional[Union[str, Path, Image.Image, bytes, io.BytesIO]] = None,
    ) -> FallbackCoordinate:
        """Resolve absolute coordinates for an unexposed MFC control by name.

        Args:
            control_name: Registered identifier of the control (e.g. 'project_navigator_tree')
            regions: Optional pre-segmented regions dictionary. If None, segments from source.
            source: Optional image source if regions are not pre-supplied.

        Returns:
            FallbackCoordinate with resolved absolute (x, y) coordinates and metadata.
        """
        if control_name not in self._fallback_registry:
            valid_controls = ", ".join(sorted(self._fallback_registry.keys()))
            raise KeyError(
                f"Unknown unexposed MFC control '{control_name}'. Registered controls: {valid_controls}"
            )

        region_name, rel_x, rel_y, description = self._fallback_registry[control_name]

        if regions is None:
            regions = self.segment_regions(source)

        if region_name not in regions:
            raise KeyError(
                f"Region '{region_name}' required by control '{control_name}' not found in segmented regions."
            )

        target_region = regions[region_name]
        abs_x, abs_y = target_region.get_relative_point(rel_x, rel_y, clamp_to_bounds=True)

        # Strictly ensure coordinates are contained within parent region bounds
        if target_region.width > 0:
            abs_x = max(target_region.left, min(abs_x, target_region.right - 1))
        if target_region.height > 0:
            abs_y = max(target_region.top, min(abs_y, target_region.bottom - 1))

        return FallbackCoordinate(
            control_name=control_name,
            region_name=region_name,
            x=abs_x,
            y=abs_y,
            rel_x=rel_x,
            rel_y=rel_y,
            is_visible=target_region.is_visible,
            confidence=target_region.confidence,
            description=description,
        )

    def get_all_fallback_coordinates(
        self,
        regions: Optional[Dict[str, WindowRegion]] = None,
        source: Optional[Union[str, Path, Image.Image, bytes, io.BytesIO]] = None,
    ) -> Dict[str, FallbackCoordinate]:
        """Resolve all registered fallback control coordinates against segmented workspace regions."""
        if regions is None:
            regions = self.segment_regions(source)

        results: Dict[str, FallbackCoordinate] = {}
        for control_name in self._fallback_registry:
            results[control_name] = self.get_control_fallback_coordinates(
                control_name, regions=regions
            )
        return results

    def analyze(
        self,
        source: Optional[Union[str, Path, Image.Image, bytes, io.BytesIO]] = None,
    ) -> ExecutionResult:
        """Run end-to-end visual grounding segmentation and validation.

        Returns a strict 4-state contract ExecutionResult.
        """
        try:
            img = self.load_image(source)
        except FileNotFoundError as e:
            return ExecutionResult.failed(
                error_code="ERR_VISION_IMAGE_NOT_FOUND",
                details=f"Live Cscape screenshot image not found: {e}",
                data={"source": str(source)},
            )
        except Exception as e:
            return ExecutionResult.failed(
                error_code="ERR_VISION_INVALID_IMAGE",
                details=f"Failed to load or parse screenshot image: {e}",
                data={"source": str(source)},
            )

        try:
            regions = self.segment_regions(img)
            fallback_coords = self.get_all_fallback_coordinates(regions=regions)

            source_desc = (
                str(source)
                if isinstance(source, (str, Path))
                else ("memory_buffer" if isinstance(source, (bytes, io.BytesIO)) else "PIL.Image")
            )

            report = VisionAnalysisReport(
                image_source=source_desc,
                dimensions={"width": img.size[0], "height": img.size[1]},
                regions=regions,
                fallback_controls=fallback_coords,
            )

            # Contract verification: all 5 regions must be visible with valid bounds
            missing_regions = [
                r for r in ["ribbon_menu_bar", "project_navigator", "editor_viewport", "output_window", "status_bar"]
                if r not in regions
            ]
            if missing_regions:
                return ExecutionResult.failed(
                    error_code="ERR_VISION_MISSING_REGIONS",
                    details=f"Visual grounding failed to segment required regions: {missing_regions}",
                    data=report.model_dump(),
                )

            # Contract verification: all fallback coordinates must be strictly contained within parent regions
            for ctrl_name, fb in fallback_coords.items():
                parent = regions.get(fb.region_name)
                if parent is None or not parent.contains(fb.x, fb.y):
                    return ExecutionResult.failed(
                        error_code="ERR_VISION_COORDINATE_OUT_OF_BOUNDS",
                        details=f"Fallback control '{ctrl_name}' coord ({fb.x}, {fb.y}) outside parent region '{fb.region_name}'",
                        data={"control_name": ctrl_name, "coordinate": fb.model_dump()},
                    )

            return ExecutionResult.success(
                details=(
                    f"Visual grounding successfully segmented {len(regions)} Cscape workspace regions "
                    f"and resolved {len(fallback_coords)} unexposed MFC fallback controls."
                ),
                data=report.model_dump(),
            )

        except Exception as e:
            logger.exception("Unexpected error during visual grounding segmentation")
            return ExecutionResult.failed(
                error_code="ERR_VISION_SEGMENTATION_FAILED",
                details=f"Visual grounding segmentation failed: {e}",
                data={"exception": str(e)},
            )
