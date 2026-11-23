"""Modal Dialog Sweeper Engine for Cscape 10.2 Windows Host.

Detects, logs, and dismisses non-blocking modal dialogs (#32770, 'Tip of the Day',
and MFC child message boxes) on the interactive desktop (winsta0\\Default) without
stealing UI focus or interfering with the Single GUI Agent boundary.
"""

from datetime import datetime, timezone
from enum import Enum
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set
import win32con
import win32gui
import win32process
from pydantic import BaseModel, Field

from jev_cscape.contracts import ExecutionResult, AgentStatus

logger = logging.getLogger(__name__)


class DialogType(str, Enum):
    """Classification of recognized Cscape modal popups."""
    TIP_OF_THE_DAY = "tip_of_the_day"
    INITIAL_PROMPT = "initial_prompt"
    FILE_LOCK_PROMPT = "file_lock_prompt"
    GENERIC_MODAL = "generic_modal"
    UNKNOWN = "unknown"


class DiscoveredDialog(BaseModel):
    """Structured descriptor of a discovered modal dialog window."""
    hwnd: int
    hwnd_hex: str
    pid: int
    title: str
    class_name: str
    dialog_type: DialogType
    buttons: List[Dict[str, Any]] = Field(default_factory=list)


class DismissalRecord(BaseModel):
    """Audit entry documenting an automated modal dismissal."""
    hwnd: int
    hwnd_hex: str
    dialog_type: DialogType
    title: str
    action_taken: str
    timestamp_utc: str


class SweepReport(BaseModel):
    """Aggregate result from a synchronous or background sweep cycle."""
    detected_count: int = 0
    dismissed_count: int = 0
    dialogs: List[DiscoveredDialog] = Field(default_factory=list)
    dismissals: List[DismissalRecord] = Field(default_factory=list)


class DialogSweeper:
    """Non-intrusive detector and dismissal engine for Cscape modal dialogs."""

    # Well-known button IDs in standard Win32 dialogs
    BTN_OK = win32con.IDOK          # 1
    BTN_CANCEL = win32con.IDCANCEL  # 2
    BTN_YES = 6
    BTN_NO = 7
    BTN_CLOSE = 8

    def __init__(self, target_pids: Optional[Set[int]] = None):
        self.target_pids = target_pids or set()
        self._sweeper_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._dismissal_history: List[DismissalRecord] = []
        self._history_lock = threading.Lock()

    def set_target_pids(self, pids: Set[int]) -> None:
        """Update the set of Cscape process IDs to inspect."""
        self.target_pids = set(pids)

    def classify_dialog(self, title: str, class_name: str) -> DialogType:
        """Classify a window by its title and window class."""
        t_lower = title.lower().strip()
        if "tip of the day" in t_lower:
            return DialogType.TIP_OF_THE_DAY
        if any(keyword in t_lower for keyword in ["allow user to choose", "open last", "blank program", "startup option"]):
            return DialogType.INITIAL_PROMPT
        if any(keyword in t_lower for keyword in ["file in use", "read-only", "already open", "sharing violation"]):
            return DialogType.FILE_LOCK_PROMPT
        if class_name == "#32770":
            return DialogType.GENERIC_MODAL
        return DialogType.UNKNOWN

    def enumerate_child_buttons(self, hwnd: int) -> List[Dict[str, Any]]:
        """Enumerate buttons within a dialog."""
        buttons: List[Dict[str, Any]] = []

        def child_cb(child_hwnd, _):
            try:
                cls_name = win32gui.GetClassName(child_hwnd)
                if cls_name.lower() == "button":
                    btn_text = win32gui.GetWindowText(child_hwnd)
                    btn_id = win32gui.GetDlgCtrlID(child_hwnd)
                    is_enabled = win32gui.IsWindowEnabled(child_hwnd)
                    is_visible = win32gui.IsWindowVisible(child_hwnd)
                    buttons.append({
                        "hwnd": child_hwnd,
                        "hwnd_hex": hex(child_hwnd),
                        "id": btn_id,
                        "text": btn_text,
                        "is_enabled": bool(is_enabled),
                        "is_visible": bool(is_visible),
                    })
            except Exception:
                pass
            return True

        try:
            win32gui.EnumChildWindows(hwnd, child_cb, None)
        except Exception:
            pass
        return buttons

    def find_dialogs(self, pids: Optional[Set[int]] = None) -> List[DiscoveredDialog]:
        """Scan top-level windows for modal dialogs belonging to target PIDs."""
        filter_pids = pids if pids is not None else self.target_pids
        discovered: List[DiscoveredDialog] = []

        def enum_cb(hwnd, _):
            try:
                if not win32gui.IsWindow(hwnd) or not win32gui.IsWindowVisible(hwnd):
                    return True

                _, win_pid = win32process.GetWindowThreadProcessId(hwnd)
                if filter_pids and win_pid not in filter_pids:
                    return True

                cls_name = win32gui.GetClassName(hwnd)
                title = win32gui.GetWindowText(hwnd)

                dtype = self.classify_dialog(title, cls_name)
                # Consider it a candidate if it's #32770 or matches a known popup title
                if cls_name == "#32770" or dtype != DialogType.UNKNOWN:
                    buttons = self.enumerate_child_buttons(hwnd)
                    discovered.append(DiscoveredDialog(
                        hwnd=hwnd,
                        hwnd_hex=hex(hwnd),
                        pid=win_pid,
                        title=title,
                        class_name=cls_name,
                        dialog_type=dtype,
                        buttons=buttons,
                    ))
            except Exception:
                pass
            return True

        try:
            win32gui.EnumWindows(enum_cb, None)
        except Exception:
            pass
        return discovered

    def dismiss_dialog(self, dialog: DiscoveredDialog) -> bool:
        """Dismiss a dialog using non-blocking Win32 messages."""
        hwnd = dialog.hwnd
        if not win32gui.IsWindow(hwnd):
            return False

        action = ""
        # 1. Specialized handling for Tip of the Day
        if dialog.dialog_type == DialogType.TIP_OF_THE_DAY:
            # Dismiss Tip of the Day: send IDOK (1) or find the Close button
            close_btn = next((b for b in dialog.buttons if "close" in b["text"].lower() or b["id"] in [self.BTN_OK, self.BTN_CANCEL]), None)
            cmd_id = close_btn["id"] if close_btn else self.BTN_OK
            win32gui.PostMessage(hwnd, win32con.WM_COMMAND, cmd_id, 0)
            action = f"PostMessage WM_COMMAND id={cmd_id}"

        # 2. Initial prompt / Allow Dialog
        elif dialog.dialog_type == DialogType.INITIAL_PROMPT:
            # Dismiss initial dialog by pressing OK or Enter
            ok_btn = next((b for b in dialog.buttons if b["id"] == self.BTN_OK or "ok" in b["text"].lower()), None)
            cmd_id = ok_btn["id"] if ok_btn else self.BTN_OK
            win32gui.PostMessage(hwnd, win32con.WM_COMMAND, cmd_id, 0)
            action = f"PostMessage WM_COMMAND id={cmd_id} (OK)"

        # 3. File in use prompt: Dismiss with Cancel or Close
        elif dialog.dialog_type == DialogType.FILE_LOCK_PROMPT:
            cancel_btn = next((b for b in dialog.buttons if b["id"] in [self.BTN_CANCEL, self.BTN_OK]), None)
            cmd_id = cancel_btn["id"] if cancel_btn else self.BTN_CANCEL
            win32gui.PostMessage(hwnd, win32con.WM_COMMAND, cmd_id, 0)
            action = f"PostMessage WM_COMMAND id={cmd_id} (Cancel/OK)"

        # 4. Generic #32770 dialog
        else:
            # Prefer OK if available, else Cancel, else WM_CLOSE
            btn = next((b for b in dialog.buttons if b["id"] in [self.BTN_OK, self.BTN_CANCEL]), None)
            if btn:
                try:
                    import ctypes
                    ctypes.windll.user32.PostMessageW(btn["hwnd"], 0x00F5, 0, 0)
                except Exception:
                    pass
                win32gui.PostMessage(hwnd, win32con.WM_COMMAND, btn["id"], btn["hwnd"])
                action = f"PostMessage WM_COMMAND id={btn['id']}"
            else:
                win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
                action = "PostMessage WM_CLOSE"

        now_utc = datetime.now(timezone.utc).isoformat()
        rec = DismissalRecord(
            hwnd=hwnd,
            hwnd_hex=dialog.hwnd_hex,
            dialog_type=dialog.dialog_type,
            title=dialog.title,
            action_taken=action,
            timestamp_utc=now_utc,
        )
        with self._history_lock:
            self._dismissal_history.append(rec)

        logger.info(f"Dismissed modal dialog '{dialog.title}' (HWND {dialog.hwnd_hex}): {action}")
        return True

    def sweep_once(self, pids: Optional[Set[int]] = None) -> SweepReport:
        """Perform a single synchronous detection and dismissal sweep."""
        dialogs = self.find_dialogs(pids=pids)
        dismissed = 0
        dismissals: List[DismissalRecord] = []

        for d in dialogs:
            if self.dismiss_dialog(d):
                dismissed += 1
                with self._history_lock:
                    if self._dismissal_history:
                        dismissals.append(self._dismissal_history[-1])

        return SweepReport(
            detected_count=len(dialogs),
            dismissed_count=dismissed,
            dialogs=dialogs,
            dismissals=dismissals,
        )

    def start_background_sweeper(self, poll_interval: float = 0.5) -> None:
        """Start non-intrusive background sweeper thread."""
        if self._sweeper_thread and self._sweeper_thread.is_alive():
            return

        self._stop_event.clear()

        def _worker():
            while not self._stop_event.is_set():
                try:
                    self.sweep_once()
                except Exception as e:
                    logger.debug(f"Error during background sweep: {e}")
                self._stop_event.wait(poll_interval)

        self._sweeper_thread = threading.Thread(
            target=_worker,
            name="JevDialogSweeperThread",
            daemon=True,
        )
        self._sweeper_thread.start()

    def stop_background_sweeper(self, timeout: float = 2.0) -> None:
        """Stop background sweeper thread cleanly."""
        self._stop_event.set()
        if self._sweeper_thread and self._sweeper_thread.is_alive():
            self._sweeper_thread.join(timeout=timeout)
        self._sweeper_thread = None

    @property
    def is_running(self) -> bool:
        """Return True if background sweeper thread is actively polling."""
        return bool(self._sweeper_thread and self._sweeper_thread.is_alive())

    def get_dismissal_history(self) -> List[DismissalRecord]:
        """Retrieve copy of all recorded dismissals."""
        with self._history_lock:
            return list(self._dismissal_history)

    def execute_contract_sweep(self, pids: Optional[Set[int]] = None) -> ExecutionResult:
        """Perform sweep and return strict 4-state ExecutionResult."""
        report = self.sweep_once(pids=pids)
        details = (
            f"Dialog sweeper completed: detected {report.detected_count}, "
            f"dismissed {report.dismissed_count} dialog(s)."
        )
        return ExecutionResult.success(
            details=details,
            data=report.model_dump(),
        )
