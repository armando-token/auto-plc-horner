"""Cscape Process Lifecycle and Non-Destructive Window Inspector.

Ensures proper window resolution on the interactive desktop (winsta0\\Default)
without hardcoded HWNDs, handling modal dialogs (#32770, Tip of the Day),
and gathering structured diagnostic evidence.
"""

import ctypes
import ctypes.wintypes
import os
import subprocess
import time
from typing import Any, Dict, List, Optional
import winreg
import win32con
import win32gui
import win32process
import psutil

from jev_cscape.contracts import ExecutionResult, AgentStatus

DEFAULT_CSCAPE_PATH = r"C:\Program Files (x86)\Cscape 10.2\Cscape.exe"

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32


class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.wintypes.DWORD),
        ("lpReserved", ctypes.c_wchar_p),
        ("lpDesktop", ctypes.c_wchar_p),
        ("lpTitle", ctypes.c_wchar_p),
        ("dwX", ctypes.wintypes.DWORD),
        ("dwY", ctypes.wintypes.DWORD),
        ("dwXSize", ctypes.wintypes.DWORD),
        ("dwYSize", ctypes.wintypes.DWORD),
        ("dwXCountChars", ctypes.wintypes.DWORD),
        ("dwYCountChars", ctypes.wintypes.DWORD),
        ("dwFillAttribute", ctypes.wintypes.DWORD),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("wShowWindow", ctypes.wintypes.WORD),
        ("cbReserved2", ctypes.wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", ctypes.wintypes.HANDLE),
        ("hStdOutput", ctypes.wintypes.HANDLE),
        ("hStdError", ctypes.wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.wintypes.HANDLE),
        ("hThread", ctypes.wintypes.HANDLE),
        ("dwProcessId", ctypes.wintypes.DWORD),
        ("dwThreadId", ctypes.wintypes.DWORD),
    ]


class CscapeLifecycleController:
    """Manages Cscape process startup, window inspection, and clean teardown."""

    def __init__(self, cscape_exe: str = DEFAULT_CSCAPE_PATH):
        self.cscape_exe = os.path.abspath(cscape_exe)
        self.cscape_dir = os.path.dirname(self.cscape_exe)

    @staticmethod
    def ensure_desktop():
        """Attach thread to interactive user desktop."""
        try:
            hd = user32.OpenDesktopW("Default", 0, False, 0x01FF)
            if hd:
                user32.SetThreadDesktop(hd)
                return hd
        except Exception:
            pass
        return None

    @staticmethod
    def configure_registry(project_path: Optional[str] = None):
        """Configure Cscape registry keys for clean non-interactive modal suppression."""
        try:
            k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Horner_Electric\Cscape\Editor")
            winreg.SetValueEx(k, "AllowUserToChooseProgram", 0, winreg.REG_DWORD, 0)
            winreg.SetValueEx(k, "OpenLast", 0, winreg.REG_DWORD, 1 if project_path else 0)
            winreg.SetValueEx(k, "CreateBlankProgram", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(k)

            k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Horner_Electric\Cscape\Setup")
            winreg.SetValueEx(k, "CscapeExitedCorrectly", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(k)

            if project_path:
                k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Horner_Electric\Cscape\Recent File List")
                winreg.SetValueEx(k, "File1", 0, winreg.REG_SZ, str(os.path.abspath(project_path)))
                winreg.CloseKey(k)

            k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Horner_Electric\Cscape\IECEditor")
            winreg.SetValueEx(k, "EnableDragDrop", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(k, "UndoRedoStackSize", 0, winreg.REG_DWORD, 16)
            winreg.SetValueEx(k, "TabSize", 0, winreg.REG_DWORD, 4)
            winreg.CloseKey(k)

            k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Horner_Electric\Cscape\HornerIDReg")
            winreg.SetValueEx(k, "HornerKeepMeLoggedIn", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(k)
        except Exception:
            pass

    def find_cscape_processes(self) -> List[psutil.Process]:
        """Find all running Cscape.exe processes."""
        cscape_procs = []
        for p in psutil.process_iter(["pid", "name"]):
            try:
                if p.info["name"] and p.info["name"].lower() == "cscape.exe":
                    cscape_procs.append(p)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return cscape_procs

    def find_cscape_windows(self, pid: Optional[int] = None) -> List[Dict[str, Any]]:
        """Enumerate top-level windows belonging to Cscape."""
        self.ensure_desktop()
        if pid is not None:
            pids = {pid}
        else:
            procs = self.find_cscape_processes()
            pids = {p.pid for p in procs}
        if not pids:
            return []

        windows = []

        def enum_cb(hwnd, extra):
            try:
                _, window_pid = win32process.GetWindowThreadProcessId(hwnd)
                if window_pid in pids:
                    title = win32gui.GetWindowText(hwnd)
                    cls_name = win32gui.GetClassName(hwnd)
                    is_visible = win32gui.IsWindowVisible(hwnd)
                    rect = win32gui.GetWindowRect(hwnd)
                    windows.append({
                        "hwnd": hwnd,
                        "hwnd_hex": hex(hwnd),
                        "pid": window_pid,
                        "title": title,
                        "class_name": cls_name,
                        "is_visible": bool(is_visible),
                        "rect": {
                            "left": rect[0],
                            "top": rect[1],
                            "right": rect[2],
                            "bottom": rect[3],
                            "width": rect[2] - rect[0],
                            "height": rect[3] - rect[1],
                        }
                    })
            except Exception:
                pass
            return True

        try:
            win32gui.EnumWindows(enum_cb, None)
        except Exception:
            pass
        return windows

    def find_main_window(self, pid: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Locate the primary Cscape application window."""
        windows = self.find_cscape_windows(pid=pid)
        if not windows and pid is not None:
            windows = self.find_cscape_windows()
        for w in windows:
            if w["class_name"] == "#32770" or w["title"].startswith("GDI+") or "tooltips" in w["class_name"].lower():
                continue
            if "cscape" in w["title"].lower() and w["is_visible"]:
                return w
        for w in windows:
            if w["is_visible"] and w["class_name"] != "#32770" and not w["title"].startswith("GDI+") and "tooltips" not in w["class_name"].lower():
                return w
        return None

    def find_modal_dialogs(self, pid: Optional[int] = None) -> List[Dict[str, Any]]:
        """Detect open modal dialogs (#32770)."""
        windows = self.find_cscape_windows(pid=pid)
        return [w for w in windows if w["class_name"] == "#32770" and w["is_visible"]]

    def dismiss_startup_dialogs(self, pid: Optional[int] = None) -> int:
        """Find and dismiss Cscape modal dialogs (#32770, Tip of the Day, About, Summary Info)."""
        dialogs = self.find_modal_dialogs(pid=pid)
        dismissed = 0
        for d in dialogs:
            hwnd = d["hwnd"]
            children = []
            def cb(ch, _):
                if win32gui.GetClassName(ch).lower() == "button":
                    children.append((ch, win32gui.GetDlgCtrlID(ch)))
                return True
            try:
                win32gui.EnumChildWindows(hwnd, cb, None)
            except Exception:
                pass
            ok_btn = next((ch for ch, cid in children if cid == 1), None)
            if ok_btn:
                user32.PostMessageW(ok_btn, 0x00F5, 0, 0)
            user32.PostMessageW(hwnd, win32con.WM_COMMAND, 1, ok_btn or 0)
            dismissed += 1
        return dismissed

    def dismiss_tip_of_the_day(self, pid: Optional[int] = None) -> bool:
        """Find and dismiss 'Tip of the Day' popup dialog."""
        return self.dismiss_startup_dialogs(pid=pid) > 0

    def launch(self, project_path: Optional[str] = None, timeout: float = 25.0) -> ExecutionResult:
        """Launch Cscape 10.2 within the interactive session on winsta0\\Default."""
        if not os.path.isfile(self.cscape_exe):
            return ExecutionResult.failed(
                error_code="CSCAPE_EXE_NOT_FOUND",
                details=f"Cscape executable not found at '{self.cscape_exe}'",
            )

        self.ensure_desktop()
        self.configure_registry(project_path)

        # Terminate any stale Cscape processes before launching new instance
        for p in self.find_cscape_processes():
            try:
                p.kill()
            except Exception:
                pass
        time.sleep(0.5)

        args = [self.cscape_exe]
        if project_path:
            abs_proj = os.path.abspath(project_path)
            if not os.path.isfile(abs_proj):
                return ExecutionResult.failed(
                    error_code="PROJECT_FILE_NOT_FOUND",
                    details=f"Project file not found at '{abs_proj}'",
                )
            args.append(abs_proj)

        try:
            proc = subprocess.Popen(args, cwd=self.cscape_dir)
            pid = proc.pid
        except Exception as e:
            return ExecutionResult.failed(
                error_code="CREATE_PROCESS_FAILED",
                details=f"subprocess.Popen failed: {e}",
            )

        # Wait for main window to appear
        start_time = time.time()
        main_win = None
        while time.time() - start_time < timeout:
            self.dismiss_startup_dialogs(pid=pid)
            main_win = self.find_main_window(pid=pid)
            if main_win and main_win["is_visible"]:
                break
            time.sleep(0.5)

        # Dismiss any trailing dialogs after main window appears
        time.sleep(0.5)
        self.dismiss_startup_dialogs(pid=pid)

        if not main_win:
            return ExecutionResult.inconclusive(
                details=f"Cscape process launched (PID {pid}), but main window did not become visible within {timeout}s.",
                data={"pid": pid},
            )

        evidence = self.inspect()
        return ExecutionResult.success(
            details=f"Cscape 10.2 successfully launched and verified visible on interactive desktop (PID {pid}, HWND {main_win['hwnd_hex']}).",
            data=evidence.data,
        )

    def inspect(self) -> ExecutionResult:
        """Inspect current Cscape process and window state."""
        procs = self.find_cscape_processes()
        if not procs:
            return ExecutionResult.failed(
                error_code="CSCAPE_NOT_RUNNING",
                details="No running Cscape.exe process detected.",
            )

        windows = self.find_cscape_windows()
        main_win = self.find_main_window()
        modals = self.find_modal_dialogs()

        data = {
            "processes_count": len(procs),
            "pids": [p.pid for p in procs],
            "main_window": main_win,
            "all_windows": windows,
            "modal_dialogs": modals,
            "is_visible": bool(main_win and main_win.get("is_visible")),
            "desktop_session": {
                "window_station": "WinSta0",
                "desktop": "Default",
            }
        }

        if main_win and main_win["is_visible"]:
            return ExecutionResult.success(
                details=f"Cscape visible on desktop with PID {main_win['pid']} and HWND {main_win['hwnd_hex']}.",
                data=data,
            )
        else:
            return ExecutionResult.inconclusive(
                details="Cscape process running, but main window is not visible or obscured.",
                data=data,
            )

    def close(self, timeout: float = 5.0) -> ExecutionResult:
        """Cleanly close running Cscape process via WM_CLOSE."""
        main_win = self.find_main_window()
        if main_win:
            win32gui.PostMessage(main_win["hwnd"], win32con.WM_CLOSE, 0, 0)
            start_time = time.time()
            while time.time() - start_time < timeout:
                if not self.find_cscape_processes():
                    return ExecutionResult.success(details="Cscape closed cleanly via WM_CLOSE.")
                time.sleep(0.5)

        # Terminate if still running
        procs = self.find_cscape_processes()
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        return ExecutionResult.success(details="Cscape closed.")
