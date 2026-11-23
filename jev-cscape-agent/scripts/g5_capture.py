#!/usr/bin/env python3
"""
G5 Vision Pipeline: Screen & Window Capture Module (W038)
Provides high-fidelity ROI cropping, DPI-aware coordinate scaling,
monotonic timestamping, and cryptographic provenance for Horner Cscape 10.2 automation.

Complies with Horner Cscape FastMCP & Autonomous Agent Directives:
- Fail-closed error handling
- Zero hardware port access
- Offline deterministic replay support
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from PIL import Image, ImageGrab

# Configure logger
logger = logging.getLogger("g5_capture")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


# =============================================================================
# DPI & Win32 Structures
# =============================================================================

PROCESS_PER_MONITOR_DPI_AWARE_V2 = 2
STANDARD_DPI = 96.0  # 100% Windows display scaling baseline

user32 = ctypes.windll.user32 if os.name == "nt" else None
shcore = ctypes.windll.shcore if (os.name == "nt" and hasattr(ctypes.windll, "shcore")) else None


def set_process_dpi_aware() -> bool:
    """Initialize Per-Monitor DPI awareness V2 fail-closed."""
    if os.name != "nt" or not user32:
        return False
    try:
        if shcore and hasattr(shcore, "SetProcessDpiAwareness"):
            shcore.SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE_V2)
            return True
        elif hasattr(user32, "SetProcessDPIAware"):
            return bool(user32.SetProcessDPIAware())
    except Exception as e:
        logger.debug(f"DPI awareness initialization note: {e}")
    return False


def get_window_dpi(hwnd: int) -> int:
    """Get the active DPI for a given window handle, defaulting to 96."""
    if os.name != "nt" or not user32 or not hwnd:
        return 96
    try:
        if hasattr(user32, "GetDpiForWindow"):
            dpi = user32.GetDpiForWindow(hwnd)
            if dpi > 0:
                return dpi
        hdc = user32.GetDC(hwnd)
        if hdc:
            gdi32 = ctypes.windll.gdi32
            LOGPIXELSX = 88
            dpi = gdi32.GetDeviceCaps(hdc, LOGPIXELSX)
            user32.ReleaseDC(hwnd, hdc)
            if dpi > 0:
                return dpi
    except Exception as e:
        logger.debug(f"Get window DPI error: {e}")
    return 96


def get_dpi_scale_factor(hwnd: int = 0) -> float:
    """Compute DPI scaling factor relative to 96 standard DPI."""
    dpi = get_window_dpi(hwnd)
    return dpi / STANDARD_DPI


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class ROI:
    """Region of Interest bounding box (left, top, right, bottom)."""
    left: int
    top: int
    right: int
    bottom: int

    @property
    def width(self) -> int:
        return max(0, self.right - self.left)

    @property
    def height(self) -> int:
        return max(0, self.bottom - self.top)

    def to_tuple(self) -> Tuple[int, int, int, int]:
        return (self.left, self.top, self.right, self.bottom)

    def contains(self, x: int, y: int) -> bool:
        return self.left <= x <= self.right and self.top <= y <= self.bottom

    def scale(self, factor: float) -> ROI:
        return ROI(
            left=int(round(self.left * factor)),
            top=int(round(self.top * factor)),
            right=int(round(self.right * factor)),
            bottom=int(round(self.bottom * factor)),
        )

    def normalize_to_96dpi(self, dpi: int) -> ROI:
        scale = STANDARD_DPI / float(dpi)
        return self.scale(scale)


@dataclass
class CaptureProvenance:
    """Cryptographic provenance and hardware/window metadata for a capture."""
    source_type: str  # "live_hwnd", "live_screen", "offline_file"
    hwnd: Optional[int] = None
    window_title: Optional[str] = None
    window_class: Optional[str] = None
    dpi: int = 96
    dpi_scale: float = 1.0
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    timestamp_epoch: float = field(default_factory=time.time)
    monotonic_ns: int = field(default_factory=time.monotonic_ns)
    frame_sha256: str = ""
    file_path: Optional[str] = None
    window_rect: Optional[Tuple[int, int, int, int]] = None
    client_rect: Optional[Tuple[int, int, int, int]] = None


@dataclass
class CaptureFrame:
    """A captured image frame containing pixel data and provenance."""
    image: Image.Image
    roi: ROI
    provenance: CaptureProvenance

    @property
    def width(self) -> int:
        return self.image.width

    @property
    def height(self) -> int:
        return self.image.height

    @property
    def sha256(self) -> str:
        if not self.provenance.frame_sha256:
            self.provenance.frame_sha256 = hashlib.sha256(self.image.tobytes()).hexdigest()
        return self.provenance.frame_sha256

    def crop_roi(self, sub_roi: Union[ROI, Tuple[int, int, int, int]]) -> CaptureFrame:
        """Extract a sub-ROI from the current capture frame."""
        if isinstance(sub_roi, tuple):
            sub_roi = ROI(*sub_roi)

        # Clamp sub_roi within image bounds
        clamped_left = max(0, min(self.image.width, sub_roi.left))
        clamped_top = max(0, min(self.image.height, sub_roi.top))
        clamped_right = max(clamped_left, min(self.image.width, sub_roi.right))
        clamped_bottom = max(clamped_top, min(self.image.height, sub_roi.bottom))

        cropped_img = self.image.crop((clamped_left, clamped_top, clamped_right, clamped_bottom))
        sub_provenance = CaptureProvenance(
            source_type=f"sub_roi({self.provenance.source_type})",
            hwnd=self.provenance.hwnd,
            window_title=self.provenance.window_title,
            window_class=self.provenance.window_class,
            dpi=self.provenance.dpi,
            dpi_scale=self.provenance.dpi_scale,
            timestamp_utc=self.provenance.timestamp_utc,
            timestamp_epoch=self.provenance.timestamp_epoch,
            monotonic_ns=self.provenance.monotonic_ns,
            frame_sha256=hashlib.sha256(cropped_img.tobytes()).hexdigest(),
            file_path=self.provenance.file_path,
            window_rect=self.provenance.window_rect,
            client_rect=self.provenance.client_rect,
        )
        return CaptureFrame(
            image=cropped_img,
            roi=ROI(clamped_left, clamped_top, clamped_right, clamped_bottom),
            provenance=sub_provenance,
        )

    def save(self, output_path: Union[str, Path], save_sidecar: bool = True) -> Path:
        """Save frame to disk alongside JSON metadata sidecar."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        self.image.save(output_path)
        if save_sidecar:
            sidecar_path = output_path.with_suffix(".json")
            meta = {
                "image_path": str(output_path),
                "width": self.width,
                "height": self.height,
                "roi": self.roi.to_tuple(),
                "sha256": self.sha256,
                "provenance": asdict(self.provenance),
            }
            with open(sidecar_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
        return output_path

    @classmethod
    def from_file(
        cls,
        image_path: Union[str, Path],
        roi: Optional[Union[ROI, Tuple[int, int, int, int]]] = None,
        dpi: int = 96,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CaptureFrame:
        """Load an offline capture frame from disk."""
        path = Path(image_path)
        if not path.exists():
            raise FileNotFoundError(f"Offline capture file not found: {path}")

        img = Image.open(path).convert("RGB")
        img_roi = ROI(0, 0, img.width, img.height)
        if roi is not None:
            if isinstance(roi, tuple):
                roi = ROI(*roi)
            img = img.crop(roi.to_tuple())
            img_roi = roi

        sidecar_path = path.with_suffix(".json")
        loaded_meta: Dict[str, Any] = {}
        if sidecar_path.exists():
            try:
                with open(sidecar_path, "r", encoding="utf-8") as f:
                    loaded_meta = json.load(f).get("provenance", {})
            except Exception as e:
                logger.debug(f"Sidecar load note: {e}")

        if metadata:
            loaded_meta.update(metadata)

        sha = hashlib.sha256(img.tobytes()).hexdigest()
        prov = CaptureProvenance(
            source_type=loaded_meta.get("source_type", "offline_file"),
            hwnd=loaded_meta.get("hwnd"),
            window_title=loaded_meta.get("window_title"),
            window_class=loaded_meta.get("window_class"),
            dpi=loaded_meta.get("dpi", dpi),
            dpi_scale=loaded_meta.get("dpi_scale", dpi / STANDARD_DPI),
            timestamp_utc=loaded_meta.get("timestamp_utc", datetime.now(timezone.utc).isoformat()),
            timestamp_epoch=loaded_meta.get("timestamp_epoch", time.time()),
            monotonic_ns=loaded_meta.get("monotonic_ns", time.monotonic_ns()),
            frame_sha256=sha,
            file_path=str(path),
            window_rect=loaded_meta.get("window_rect"),
            client_rect=loaded_meta.get("client_rect"),
        )
        return cls(image=img, roi=img_roi, provenance=prov)


# =============================================================================
# Screen & Window Capture Engine
# =============================================================================

class G5Capture:
    """
    High-fidelity Capture Engine supporting live HWND / desktop capture
    and offline test replay.
    """

    def __init__(self, init_dpi_awareness: bool = True) -> None:
        if init_dpi_awareness:
            set_process_dpi_aware()

    @staticmethod
    def capture_from_file(
        image_path: Union[str, Path],
        roi: Optional[Union[ROI, Tuple[int, int, int, int]]] = None,
        dpi: int = 96,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CaptureFrame:
        """Load an offline capture frame from disk."""
        return CaptureFrame.from_file(image_path, roi=roi, dpi=dpi, metadata=metadata)

    @staticmethod
    def capture_screen(roi: Optional[Union[ROI, Tuple[int, int, int, int]]] = None) -> CaptureFrame:
        """Capture the full desktop or bounding box ROI."""
        t_utc = datetime.now(timezone.utc).isoformat()
        t_epoch = time.time()
        t_mono = time.monotonic_ns()

        bbox = None
        if roi:
            if isinstance(roi, ROI):
                bbox = roi.to_tuple()
            else:
                bbox = roi

        img = ImageGrab.grab(bbox=bbox)
        frame_roi = ROI(bbox[0], bbox[1], bbox[2], bbox[3]) if bbox else ROI(0, 0, img.width, img.height)
        sha = hashlib.sha256(img.tobytes()).hexdigest()

        prov = CaptureProvenance(
            source_type="live_screen",
            dpi=96,
            dpi_scale=1.0,
            timestamp_utc=t_utc,
            timestamp_epoch=t_epoch,
            monotonic_ns=t_mono,
            frame_sha256=sha,
        )
        return CaptureFrame(image=img, roi=frame_roi, provenance=prov)

    @staticmethod
    def capture_window(
        hwnd: int,
        roi: Optional[Union[ROI, Tuple[int, int, int, int]]] = None,
        use_client_area: bool = True,
    ) -> CaptureFrame:
        """Capture a live window or child control via Win32 API."""
        if os.name != "nt" or not user32:
            raise RuntimeError("Live window capture requires Windows win32 environment.")

        if not user32.IsWindow(hwnd):
            raise ValueError(f"Invalid window handle: {hwnd}")

        t_utc = datetime.now(timezone.utc).isoformat()
        t_epoch = time.time()
        t_mono = time.monotonic_ns()

        dpi = get_window_dpi(hwnd)
        dpi_scale = dpi / STANDARD_DPI

        # Query window rect and client rect
        rect = wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        win_rect = (rect.left, rect.top, rect.right, rect.bottom)

        c_rect = wintypes.RECT()
        user32.GetClientRect(hwnd, ctypes.byref(c_rect))
        client_rect = (c_rect.left, c_rect.top, c_rect.right, c_rect.bottom)

        target_rect = client_rect if use_client_area else win_rect
        w = target_rect[2] - target_rect[0]
        h = target_rect[3] - target_rect[1]

        if w <= 0 or h <= 0:
            raise ValueError(f"Window {hwnd} has non-positive dimensions ({w}x{h}).")

        # Capture via PrintWindow or BitBlt
        import win32gui
        import win32ui
        import win32con

        hwnd_dc = win32gui.GetDC(hwnd) if use_client_area else win32gui.GetWindowDC(hwnd)
        mfc_dc = win32ui.CreateDCFromHandle(hwnd_dc)
        save_dc = mfc_dc.CreateCompatibleDC()

        save_bitmap = win32ui.CreateBitmap()
        save_bitmap.CreateCompatibleBitmap(mfc_dc, w, h)
        save_dc.SelectObject(save_bitmap)

        # PrintWindow flag PW_CLIENTONLY = 1
        PW_CLIENTONLY = 1
        pw_res = user32.PrintWindow(hwnd, save_dc.GetSafeHdc(), PW_CLIENTONLY if use_client_area else 0)
        if not pw_res:
            # Fallback to BitBlt
            save_dc.BitBlt((0, 0), (w, h), mfc_dc, (0, 0), win32con.SRCCOPY)

        bmp_info = save_bitmap.GetInfo()
        bmp_str = save_bitmap.GetBitmapBits(True)
        img = Image.frombuffer(
            "RGB",
            (bmp_info["bmWidth"], bmp_info["bmHeight"]),
            bmp_str,
            "raw",
            "BGRX",
            0,
            1,
        )

        # Clean up DC objects
        win32gui.DeleteObject(save_bitmap.GetHandle())
        save_dc.DeleteDC()
        mfc_dc.DeleteDC()
        win32gui.ReleaseDC(hwnd, hwnd_dc)

        # Sub-crop ROI if specified
        frame_roi = ROI(0, 0, w, h)
        if roi:
            if isinstance(roi, tuple):
                roi = ROI(*roi)
            img = img.crop(roi.to_tuple())
            frame_roi = roi

        title = win32gui.GetWindowText(hwnd)
        cls_name = win32gui.GetClassName(hwnd)
        sha = hashlib.sha256(img.tobytes()).hexdigest()

        prov = CaptureProvenance(
            source_type="live_hwnd",
            hwnd=hwnd,
            window_title=title,
            window_class=cls_name,
            dpi=dpi,
            dpi_scale=dpi_scale,
            timestamp_utc=t_utc,
            timestamp_epoch=t_epoch,
            monotonic_ns=t_mono,
            frame_sha256=sha,
            window_rect=win_rect,
            client_rect=client_rect,
        )
        return CaptureFrame(image=img, roi=frame_roi, provenance=prov)


# Self-test when executed directly
if __name__ == "__main__":
    import sys
    print("G5 Capture Module (W038) initialized.")
    dpi_aware = set_process_dpi_aware()
    print(f"DPI awareness initialized: {dpi_aware}")
    print("Capture engine ready.")
    sys.exit(0)
