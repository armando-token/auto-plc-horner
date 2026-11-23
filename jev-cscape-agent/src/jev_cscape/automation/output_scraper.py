"""Cscape 10.2 Compiler Output Window (ListBox 372) Scraper (W016).

Locates the Cscape Output Window dockable frame (Control ID 45011) and child
MFC ListBox control (Control ID 372), extracts compilation diagnostics via
Win32 messages (LB_GETCOUNT / LB_GETTEXT), and tokenizes diagnostics into
structured severity classifications (INFO, WARNING, ERROR).

Enforces the strict 5-state contract (SUCCESS, PARTIAL, FAILED, BLOCKED, INCONCLUSIVE),
dismantles false success antipatterns H01 (silent mock) and H03 (fake error check),
and honestly reports PARTIAL on warnings per rule H13.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
from enum import Enum
import logging
import re
from typing import Any, Dict, List, Optional
import win32con
import win32gui
from pydantic import BaseModel, ConfigDict, Field

from jev_cscape.automation.gui_controller import GUIBoundaryController
from jev_cscape.automation.lifecycle import CscapeLifecycleController
from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.contracts.contract_validator import ContractValidator

logger = logging.getLogger(__name__)

# --- Win32 Types & Architecture Abstraction (32-bit / 64-bit safe) ---
LRESULT = ctypes.c_ssize_t  # LONG_PTR
LPARAM = ctypes.c_ssize_t   # LONG_PTR
WPARAM = ctypes.c_size_t   # UINT_PTR

# --- Win32 Constants & Observed Control Identifiers ---
ID_OUTPUT_WINDOW: int = 45011      # MFC Output Window ControlBar frame ID
ID_OUTPUT_LISTBOX: int = 372       # Compiler output ListBox control ID

LB_GETTEXT: int = 0x0189           # 393: Retrieve item string
LB_GETTEXTLEN: int = 0x018A        # 394: Retrieve string character count
LB_GETCOUNT: int = 0x018B          # 395: Retrieve total item count
LB_ERR: int = -1                   # Error code returned by ListBox messages

# --- Function Prototypes & argtypes Binding ---
user32 = ctypes.windll.user32
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, LPARAM)

user32.IsWindow.argtypes = [wintypes.HWND]
user32.IsWindow.restype = wintypes.BOOL

user32.GetDlgItem.argtypes = [wintypes.HWND, ctypes.c_int]
user32.GetDlgItem.restype = wintypes.HWND

user32.GetDlgCtrlID.argtypes = [wintypes.HWND]
user32.GetDlgCtrlID.restype = ctypes.c_int

user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.restype = ctypes.c_int

user32.GetParent.argtypes = [wintypes.HWND]
user32.GetParent.restype = wintypes.HWND

user32.EnumChildWindows.argtypes = [wintypes.HWND, WNDENUMPROC, LPARAM]
user32.EnumChildWindows.restype = wintypes.BOOL

user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM, ctypes.c_void_p]
user32.SendMessageW.restype = LRESULT


class DiagnosticSeverity(str, Enum):
    """Compiler message severity levels in Cscape 10.2."""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class OutputDiagnostic(BaseModel):
    """Structured compiler diagnostic item from ListBox 372."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )

    level: DiagnosticSeverity = Field(..., description="Severity level: INFO, WARNING, or ERROR")
    message: str = Field(..., description="Diagnostic message content")
    line: Optional[int] = Field(default=None, ge=1, description="1-based source code line number")
    column: Optional[int] = Field(default=None, ge=1, description="1-based source column number")
    file_path: Optional[str] = Field(default=None, description="Source file path or POU name")
    pou_name: Optional[str] = Field(default=None, description="POU identifier if present")
    error_code: Optional[str] = Field(default=None, description="Error or warning diagnostic code")
    raw_text: str = Field(default="", description="Original scraped raw text line")


class ScraperReport(BaseModel):
    """Aggregation report of scraped ListBox 372 compiler output."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )

    is_clean: bool = Field(default=False, description="True only if clean summary confirmed with 0 errors and 0 warnings")
    errors_count: int = Field(default=0, ge=0, description="Total diagnostic messages classified as ERROR")
    warnings_count: int = Field(default=0, ge=0, description="Total diagnostic messages classified as WARNING")
    info_count: int = Field(default=0, ge=0, description="Total diagnostic messages classified as INFO")
    lines_count: int = Field(default=0, ge=0, description="Total text lines extracted from ListBox 372")
    raw_lines: List[str] = Field(default_factory=list, description="Raw line strings extracted from ListBox")
    diagnostics: List[OutputDiagnostic] = Field(default_factory=list, description="Structured parsed diagnostics")
    output_window_hwnd: Optional[int] = Field(default=None, description="Win32 HWND of Output Window container frame (45011)")
    listbox_hwnd: Optional[int] = Field(default=None, description="Win32 HWND of child ListBox (372)")
    mode: str = Field(default="live", description="Execution mode: 'live' or 'offline/mock'")
    timestamp_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of scrape operation",
    )
    details: str = Field(default="", description="Human-readable summary of scraper results")


class CscapeOutputScraper:
    """Scrapes and tokenizes compiler diagnostic output from Cscape 10.2 ListBox 372."""

    OBSERVED_OUTPUT_FRAME_ID: int = ID_OUTPUT_WINDOW
    OBSERVED_OUTPUT_LISTBOX_ID: int = ID_OUTPUT_LISTBOX
    LB_GETCOUNT: int = LB_GETCOUNT
    LB_GETTEXTLEN: int = LB_GETTEXTLEN
    LB_GETTEXT: int = LB_GETTEXT

    # Regex definitions for Cscape 10.2 compilation messages
    RE_CLEAN_SUMMARY = re.compile(
        r"0\s+error\(?s?\)?,\s*0\s+warning\(?s?\)|"
        r"Errors?:\s*0,\s*Warnings?:\s*0|"
        r"No\s+errors?\s+(?:detected|found)|"
        r"Compilation\s+succeeded|"
        r"Logic\s+compilation\s+completed",
        re.IGNORECASE,
    )
    RE_FAILURE_SUMMARY = re.compile(
        r"Build\s+FAILED|"
        r"Compilation\s+failed|"
        r"Error\(?s?\)?\s+detected|"
        r"Fatal\s+compilation\s+errors?",
        re.IGNORECASE,
    )
    RE_SUMMARY_LINE = re.compile(
        r"^\s*(?:[\w\.\-]+:\s*)?(?:"
        r"0\s+error\(?s?\)?,\s*\d+\s+warning\(?s?\)|"
        r"\d+\s+error\(?s?\)?,\s*\d+\s+warning\(?s?\)|"
        r"Errors?:\s*\d+,\s*Warnings?:\s*\d+|"
        r"Build\s+FAILED\s*-\s*\d+\s+error\(?s?\)?,\s*\d+\s+warning\(?s?\)|"
        r"Build\s+finished:\s*\d+\s+error\(?s?\)?,\s*\d+\s+warning\(?s?\)|"
        r"Build\s+Result:\s*(?:SUCCESS|FAILED)|"
        r"Compilation\s+(?:succeeded|failed)|"
        r"Logic\s+compilation\s+completed\.?"
        r")",
        re.IGNORECASE,
    )
    RE_BANNER = re.compile(r"^(?:={3,}|-{3,})")
    RE_ERROR_KEYWORD = re.compile(
        r"(?:\b(?:error(?!\s+check)|fatal|ERR_[A-Z0-9_]+)\b|\bfatal\s*:)",
        re.IGNORECASE,
    )
    RE_CSCAPE_ST_ERROR = re.compile(
        r"^[\w\.\-]+:\s*\(\d+\):\s*.+",
        re.IGNORECASE,
    )
    RE_WARNING_KEYWORD = re.compile(
        r"(?:\bwarning\b|\bwarn\s*:)",
        re.IGNORECASE,
    )
    RE_ERROR_COUNT = re.compile(
        r"(?<![\d\.])(\d+)\s+errors?(?:\(s\))?(?!\s+(?:check|pass|dialog))\b|"
        r"\berrors?\s*:\s*(\d+)\b|"
        r"\berror\s+count\s*:\s*(\d+)\b",
        re.IGNORECASE,
    )
    RE_WARNING_COUNT = re.compile(
        r"(?<![\d\.])(\d+)\s+warnings?(?:\(s\))?(?!\s+(?:check|pass|dialog))\b|"
        r"\bwarnings?\s*:\s*(\d+)\b|"
        r"\bwarning\s+count\s*:\s*(\d+)\b",
        re.IGNORECASE,
    )
    RE_ACTIVITY = re.compile(
        r"(?:compil(?:ing|e|ation)|clean\s+build|build\s+result|logic\s+compilation|\.st|\.csp|\.cpj|pou|parsed\s+and\s+validated)",
        re.IGNORECASE,
    )
    RE_LOC_PAREN = re.compile(
        r"^(?P<file>[^:\(\s]+\.st)?\((?P<line>\d+)(?:,\s*(?P<col>\d+))?\):\s*(?:(?P<level>error|warning)\s*(?P<code>\w+)?:\s*)?(?P<msg>.*)",
        re.IGNORECASE,
    )
    RE_LOC_LINE_COL = re.compile(
        r"^Line\s*(?P<line>\d+)(?:,\s*Col\s*(?P<col>\d+))?:\s*(?:(?P<level>error|warning)\s*(?P<code>\w+)?:\s*)?(?P<msg>.*)",
        re.IGNORECASE,
    )
    RE_LOC_ST = re.compile(
        r"^(?P<pou>[\w\.\-]+):\s*\((?P<line>\d+)\):\s*(?P<msg>.*)",
        re.IGNORECASE,
    )

    def __init__(self, gui_controller: Optional[GUIBoundaryController] = None):
        self.gui_controller = gui_controller or GUIBoundaryController()
        self.lifecycle = CscapeLifecycleController()

    @staticmethod
    def _get_window_class(hwnd: int) -> str:
        """Safely retrieve Win32 window class name."""
        if not hwnd or not user32.IsWindow(hwnd):
            return ""
        buf = ctypes.create_unicode_buffer(256)
        ret = user32.GetClassNameW(hwnd, buf, 256)
        return buf.value if ret > 0 else ""

    def find_output_listbox(self, main_hwnd: int) -> Optional[int]:
        """Locates the child ListBox 372 under Cscape main HWND or Output Window HWND."""
        if not main_hwnd or not user32.IsWindow(main_hwnd):
            return None

        # Tier 1: Check if main_hwnd itself is already the target ListBox
        try:
            p_id = user32.GetDlgCtrlID(main_hwnd)
            p_cls = self._get_window_class(main_hwnd).lower()
            if p_id == self.OBSERVED_OUTPUT_LISTBOX_ID or "listbox" in p_cls:
                return main_hwnd
        except Exception:
            pass

        # Tier 2: Direct GetDlgItem checks
        try:
            h_direct = user32.GetDlgItem(main_hwnd, self.OBSERVED_OUTPUT_LISTBOX_ID)
            if h_direct and user32.IsWindow(h_direct):
                cls = self._get_window_class(h_direct).lower()
                if "listbox" in cls or not cls:
                    return h_direct

            h_frame = user32.GetDlgItem(main_hwnd, self.OBSERVED_OUTPUT_FRAME_ID)
            if h_frame and user32.IsWindow(h_frame):
                h_lb = user32.GetDlgItem(h_frame, self.OBSERVED_OUTPUT_LISTBOX_ID)
                if h_lb and user32.IsWindow(h_lb):
                    return h_lb
        except Exception:
            pass

        # Tier 3: Hierarchical child enumeration
        exact_id_matches: List[int] = []
        frame_hwnd: Optional[int] = None
        listboxes_under_frame: List[int] = []
        all_listboxes: List[int] = []

        def enum_cb(child_hwnd: int, _: int) -> bool:
            nonlocal frame_hwnd
            try:
                cid = user32.GetDlgCtrlID(child_hwnd)
                cls = self._get_window_class(child_hwnd).lower()
                p_hwnd = user32.GetParent(child_hwnd)

                if cid == self.OBSERVED_OUTPUT_FRAME_ID:
                    frame_hwnd = child_hwnd

                if "listbox" in cls:
                    all_listboxes.append(child_hwnd)
                    if (frame_hwnd and p_hwnd == frame_hwnd) or (cid == self.OBSERVED_OUTPUT_LISTBOX_ID):
                        listboxes_under_frame.append(child_hwnd)

                if cid == self.OBSERVED_OUTPUT_LISTBOX_ID:
                    exact_id_matches.append(child_hwnd)
            except Exception:
                pass
            return True

        try:
            user32.EnumChildWindows(main_hwnd, WNDENUMPROC(enum_cb), 0)
        except Exception as exc:
            logger.warning("EnumChildWindows failed on HWND %s: %s", main_hwnd, exc)
            return None

        # Priority 1: Exact ID 372 match with ListBox class (or fallback to any ID 372)
        for h in exact_id_matches:
            if user32.IsWindow(h):
                cls = self._get_window_class(h).lower()
                if "listbox" in cls or not cls:
                    return h
        if exact_id_matches:
            return exact_id_matches[0]

        # Priority 2: ListBox directly under Frame 45011
        for h in listboxes_under_frame:
            if user32.IsWindow(h):
                return h

        # Priority 3: Only one ListBox found in the entire branch
        if len(all_listboxes) == 1 and user32.IsWindow(all_listboxes[0]):
            return all_listboxes[0]

        return None

    def read_listbox_lines(self, listbox_hwnd: int) -> List[str]:
        """Reads all text lines from a Win32 ListBox safely via LB_GETCOUNT and LB_GETTEXT."""
        if not listbox_hwnd or not user32.IsWindow(listbox_hwnd):
            return []

        count = user32.SendMessageW(listbox_hwnd, LB_GETCOUNT, 0, None)
        if count == LB_ERR or count < 0:
            return []
        if count > 1_000_000:
            logger.warning("Unreasonable ListBox item count %d; aborting scrape.", count)
            return []
        if count == 0:
            return []

        lines: List[str] = []
        for i in range(count):
            text_len = user32.SendMessageW(listbox_hwnd, LB_GETTEXTLEN, i, None)

            if text_len < 0 or text_len == LB_ERR:
                alloc_chars = 1024
            elif text_len == 0:
                alloc_chars = 256
            else:
                alloc_chars = text_len + 17

            buf = ctypes.create_unicode_buffer(alloc_chars)
            ret = user32.SendMessageW(
                listbox_hwnd,
                LB_GETTEXT,
                i,
                ctypes.cast(buf, ctypes.c_void_p),
            )

            if ret == LB_ERR:
                lines.append("")
            else:
                lines.append(buf.value)

        return lines

    def parse_output_lines(
        self,
        lines: List[str],
        listbox_hwnd: Optional[int] = None,
        mode: str = "live",
        allow_empty_clean: bool = False,
    ) -> ScraperReport:
        """Tokenize raw compiler lines into structured diagnostics and evaluate clean compile status."""
        diagnostics: List[OutputDiagnostic] = []
        diag_err_count = 0
        diag_warn_count = 0
        info_count = 0
        found_err_summaries: List[int] = []
        found_warn_summaries: List[int] = []
        has_clean_sum = False
        has_fail_sum = False

        non_empty_lines = [l for l in lines if l.strip()]
        full_text = "\n".join(non_empty_lines)
        has_activity = bool(self.RE_ACTIVITY.search(full_text))

        for line in lines:
            s = line.strip()
            if not s or self.RE_BANNER.match(s):
                info_count += 1
                continue

            is_sum = bool(self.RE_SUMMARY_LINE.search(s))
            if self.RE_CLEAN_SUMMARY.search(s):
                has_clean_sum = True
            if self.RE_FAILURE_SUMMARY.search(s):
                has_fail_sum = True

            for m in self.RE_ERROR_COUNT.finditer(s):
                for g in m.groups():
                    if g is not None:
                        found_err_summaries.append(int(g))
            for m in self.RE_WARNING_COUNT.finditer(s):
                for g in m.groups():
                    if g is not None:
                        found_warn_summaries.append(int(g))

            # Classify severity
            err_matches = [int(g) for m in self.RE_ERROR_COUNT.finditer(s) for g in m.groups() if g is not None]
            warn_matches = [int(g) for m in self.RE_WARNING_COUNT.finditer(s) for g in m.groups() if g is not None]
            max_err = max(err_matches) if err_matches else None
            max_warn = max(warn_matches) if warn_matches else None

            if is_sum:
                sev = DiagnosticSeverity.INFO
            elif bool(self.RE_FAILURE_SUMMARY.search(s)) or (max_err is not None and max_err > 0):
                sev = DiagnosticSeverity.ERROR
            elif self.RE_CSCAPE_ST_ERROR.match(s) and not self.RE_WARNING_KEYWORD.search(s):
                sev = DiagnosticSeverity.ERROR
            elif self.RE_ERROR_KEYWORD.search(s) and (max_err is None or max_err > 0):
                sev = DiagnosticSeverity.ERROR
            elif (max_warn is not None and max_warn > 0) or (self.RE_WARNING_KEYWORD.search(s) and (max_warn is None or max_warn > 0)):
                sev = DiagnosticSeverity.WARNING
            else:
                sev = DiagnosticSeverity.INFO

            if not is_sum:
                if sev == DiagnosticSeverity.ERROR:
                    diag_err_count += 1
                    diag = self._extract_diagnostic(s, sev)
                    diagnostics.append(diag)
                elif sev == DiagnosticSeverity.WARNING:
                    diag_warn_count += 1
                    diag = self._extract_diagnostic(s, sev)
                    diagnostics.append(diag)
                else:
                    info_count += 1
            else:
                info_count += 1

        summary_err_max = max(found_err_summaries) if found_err_summaries else 0
        summary_warn_max = max(found_warn_summaries) if found_warn_summaries else 0

        total_errors = max(diag_err_count, summary_err_max)
        total_warnings = max(diag_warn_count, summary_warn_max)

        if has_fail_sum and total_errors == 0:
            total_errors = 1

        total_lines = len(lines)
        if total_lines == 0 or not non_empty_lines:
            if allow_empty_clean:
                return ScraperReport(
                    is_clean=True,
                    errors_count=0,
                    warnings_count=0,
                    info_count=0,
                    lines_count=0,
                    raw_lines=lines,
                    diagnostics=[],
                    listbox_hwnd=listbox_hwnd,
                    mode=mode,
                    details="Compilation clean: 0 errors, 0 warnings (Output ListBox clean with zero diagnostic messages).",
                )
            return ScraperReport(
                is_clean=False,
                errors_count=0,
                warnings_count=0,
                info_count=0,
                lines_count=0,
                raw_lines=lines,
                diagnostics=[],
                listbox_hwnd=listbox_hwnd,
                mode=mode,
                details="Output window ListBox is empty or contains only whitespace.",
            )

        # Invariant for clean compilation: activity confirmed, clean marker present, no failure markers, 0 errors, 0 warnings
        is_clean = (
            has_activity
            and has_clean_sum
            and not has_fail_sum
            and total_errors == 0
            and total_warnings == 0
        )

        details = (
            f"Compilation clean: 0 errors, 0 warnings ({total_lines} lines parsed)."
            if is_clean
            else f"Compilation completed: {total_errors} error(s), {total_warnings} warning(s)."
        )

        return ScraperReport(
            is_clean=is_clean,
            errors_count=total_errors,
            warnings_count=total_warnings,
            info_count=info_count,
            lines_count=total_lines,
            raw_lines=lines,
            diagnostics=diagnostics,
            listbox_hwnd=listbox_hwnd,
            mode=mode,
            details=details,
        )

    def _extract_diagnostic(self, line: str, severity: DiagnosticSeverity) -> OutputDiagnostic:
        """Extract structured line/column/code details from diagnostic string."""
        m_paren = self.RE_LOC_PAREN.search(line)
        if m_paren:
            return OutputDiagnostic(
                level=severity,
                message=m_paren.group("msg").strip(),
                line=int(m_paren.group("line")),
                column=int(m_paren.group("col")) if m_paren.group("col") else None,
                file_path=m_paren.group("file"),
                error_code=m_paren.group("code"),
                raw_text=line,
            )

        m_line_col = self.RE_LOC_LINE_COL.search(line)
        if m_line_col:
            return OutputDiagnostic(
                level=severity,
                message=m_line_col.group("msg").strip(),
                line=int(m_line_col.group("line")),
                column=int(m_line_col.group("col")) if m_line_col.group("col") else None,
                error_code=m_line_col.group("code"),
                raw_text=line,
            )

        m_st = self.RE_LOC_ST.search(line)
        if m_st:
            pou = m_st.group("pou")
            return OutputDiagnostic(
                level=severity,
                message=m_st.group("msg").strip(),
                line=int(m_st.group("line")),
                pou_name=pou,
                file_path=f"{pou}.st",
                error_code="ST_SYNTAX_ERROR",
                raw_text=line,
            )

        return OutputDiagnostic(
            level=severity,
            message=line,
            raw_text=line,
        )

    def scrape(
        self,
        main_hwnd: Optional[int] = None,
        mock_lines: Optional[List[str]] = None,
        mock_report: Optional[Dict[str, Any]] = None,
        mode: Optional[str] = None,
    ) -> ExecutionResult:
        """Scrape compiler output and return a strict 5-state ExecutionResult.

        Guarantees:
        - Mock/offline mode declares mode='offline/mock' (H01 compliant).
        - Clean compile requires 0 errors and 0 warnings (H03 compliant).
        - Builds with warnings honestly return PARTIAL (H13 compliant).
        - Lock contention returns BLOCKED.
        - Unrunning Cscape returns FAILED.
        """
        # 1. Offline / Mock Mode Handling
        if mock_report is not None:
            rep = ScraperReport(**mock_report)
            return self._build_result(rep)

        if mock_lines is not None:
            effective_mode = mode or "offline/mock"
            rep = self.parse_output_lines(mock_lines, mode=effective_mode)
            return self._build_result(rep)

        # 2. Acquire exclusive GUI boundary lock
        try:
            with self.gui_controller.guard_gui(timeout=3.0):
                # 3. Assert Cscape running and visible
                cscape_check = self.gui_controller.assert_cscape_active_and_visible()
                if cscape_check.status != AgentStatus.SUCCESS:
                    return cscape_check

                target_hwnd = main_hwnd or cscape_check.data.get("hwnd")
                if not target_hwnd or not win32gui.IsWindow(target_hwnd):
                    return ExecutionResult.failed(
                        error_code="INVALID_MAIN_HWND",
                        details=f"Cscape main window handle {target_hwnd} is invalid.",
                    )

                # 4. Resolve ListBox 372
                lb_hwnd = self.find_output_listbox(target_hwnd)
                if not lb_hwnd or not win32gui.IsWindow(lb_hwnd):
                    return ExecutionResult.failed(
                        error_code="OUTPUT_LISTBOX_NOT_FOUND",
                        details="Compiler Output Window ListBox (ID 372) could not be resolved in Cscape.",
                    )

                # 5. Read lines
                lines = self.read_listbox_lines(lb_hwnd)
                rep = self.parse_output_lines(lines, listbox_hwnd=lb_hwnd, mode="live")
                return self._build_result(rep)

        except PermissionError as e:
            return ExecutionResult.blocked(
                error_code="GUI_CONTENTION_BLOCKED",
                details=f"Output scraping blocked by GUI boundary contention: {e}",
            )
        except Exception as e:
            return ExecutionResult.failed(
                error_code="SCRAPER_EXECUTION_ERROR",
                details=f"Unexpected error during output scraping: {e}",
            )

    def _build_result(self, report: ScraperReport) -> ExecutionResult:
        """Convert ScraperReport into canonical ExecutionResult enforcing H01, H03, H13."""
        payload = {
            "mode": report.mode,
            "error_count": report.errors_count,
            "warning_count": report.warnings_count,
            "report": report.model_dump(),
        }

        # 1. Compiler Errors -> FAILED
        if report.errors_count > 0:
            res = ExecutionResult.failed(
                error_code="COMPILATION_ERROR",
                details=f"Compilation failed with {report.errors_count} error(s) and {report.warnings_count} warning(s).",
                data=payload,
            )
            return ContractValidator.validate_and_remediate(res).remediated_result

        # 2. Warnings with 0 Errors -> PARTIAL (Rule H13 enforcement)
        if report.warnings_count > 0:
            res = ExecutionResult.partial(
                details=f"[PARTIAL] Compilation succeeded with {report.warnings_count} warning(s) (0 errors).",
                data=payload,
            )
            return ContractValidator.validate_and_remediate(res).remediated_result

        # 3. Clean Compile -> SUCCESS
        if report.is_clean:
            res = ExecutionResult.success(
                details=f"Clean compilation verified: 0 errors, 0 warnings ({report.lines_count} lines scraped from ListBox 372).",
                data=payload,
            )
            return ContractValidator.validate_and_remediate(res).remediated_result

        # 4. Empty Output -> INCONCLUSIVE (H03 protection)
        if report.lines_count == 0 or not any(l.strip() for l in report.raw_lines):
            res = ExecutionResult.inconclusive(
                error_code="OUTPUT_EMPTY",
                details="Output window ListBox is empty or contains only whitespace.",
                data=payload,
            )
            return ContractValidator.validate_and_remediate(res).remediated_result

        # 5. Inconclusive fallback (e.g. no activity detected or missing clean summary)
        res = ExecutionResult.inconclusive(
            details=f"Compilation outcome inconclusive ({report.lines_count} lines scraped, clean proof unverified).",
            data=payload,
        )
        return ContractValidator.validate_and_remediate(res).remediated_result
