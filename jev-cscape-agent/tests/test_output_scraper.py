"""Tests for CscapeOutputScraper MFC ListBox 372 scraper and error check verification.

Verifies:
1. Empty output window -> AgentStatus.INCONCLUSIVE (H03 protection)
2. Clean compile (0 errors, 0 warnings) -> AgentStatus.SUCCESS, is_clean=True
3. Compile with syntax errors -> AgentStatus.FAILED, is_clean=False, structured diagnostics
4. Compile with warnings -> AgentStatus.PARTIAL (H13 honest status, is_clean=False)
5. Fail-closed when Cscape is not running -> AgentStatus.FAILED, CSCAPE_NOT_RUNNING
6. Explicit offline/mock mode -> mode='offline/mock', H01 compliant
7. Single GUI boundary contention -> AgentStatus.BLOCKED
8. Compiler dispatcher trigger_and_scrape integration
"""

import pytest
from unittest.mock import MagicMock, patch

from jev_cscape.automation.output_scraper import (
    CscapeOutputScraper,
    DiagnosticSeverity,
    OutputDiagnostic,
    ScraperReport,
)
from jev_cscape.automation.compiler import CscapeCompilerDispatcher, CompilationResult
from jev_cscape.automation.gui_controller import GUIBoundaryController
from jev_cscape.contracts import AgentStatus
from jev_cscape.contracts.contract_validator import ContractValidator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_compile_lines():
    return [
        "=== Horner Cscape 10.2 Compile Pass: TankLevelClosedLoop ===",
        "Clean Build: True",
        "Mode: IEC 61131-3 Structured Text",
        "Logic: Checking Logic...",
        "Logic: Parsing IEC 61131-3 logic...",
        "Main (ST): Compiling structured text...",
        "Symbols: Resolving variable mappings (%R, %AI, %AQ)...",
        "TankLevelClosedLoop: 0 error(s), 0 warning(s)",
        "Build Result: SUCCESS",
    ]


@pytest.fixture
def syntax_error_lines():
    return [
        "=== Horner Cscape 10.2 Compile Pass ===",
        "Logic: Checking Logic...",
        "MainControl.st(14,5): error K51001: Syntax error near 'END_IF'",
        "STBlock1: (7): Kp: Unknown identifier",
        "Build FAILED - 2 error(s), 0 warning(s)",
    ]


@pytest.fixture
def warning_compile_lines():
    return [
        "=== Horner Cscape 10.2 Compile Pass ===",
        "Logic: Checking Logic...",
        "FB_Motor.st(22): warning: Unused variable 'bAux'",
        "Warn : Screen set as first screen is empty.Screen 1",
        "Main: 0 error(s), 2 warning(s)",
        "Build Result: SUCCESS",
    ]


@pytest.fixture
def mixed_compile_lines():
    return [
        "=== Horner Cscape 10.2 Compile Pass ===",
        "Logic: Checking Logic...",
        "MainControl.st(14,5): error K51001: Syntax error near 'END_IF'",
        "FB_Motor.st(22): warning: Unused variable 'bAux'",
        "Build FAILED - 1 error(s), 1 warning(s)",
    ]


# ---------------------------------------------------------------------------
# Unit & Integration Tests
# ---------------------------------------------------------------------------

def test_output_scraper_constants():
    """Verify observed Win32 identifiers and messages for Cscape 10.2."""
    scraper = CscapeOutputScraper()
    assert scraper.OBSERVED_OUTPUT_FRAME_ID == 45011
    assert scraper.OBSERVED_OUTPUT_LISTBOX_ID == 372
    assert scraper.LB_GETCOUNT == 0x018B
    assert scraper.LB_GETTEXTLEN == 0x018A
    assert scraper.LB_GETTEXT == 0x0189


def test_output_scraper_empty_output_window():
    """Test 1: Empty output window returns INCONCLUSIVE (H03 protection)."""
    scraper = CscapeOutputScraper()

    # Empty line list
    res_empty = scraper.scrape(mock_lines=[], mode="offline/mock")
    assert res_empty.status == AgentStatus.INCONCLUSIVE
    assert res_empty.error_code == "OUTPUT_EMPTY"
    rep_empty = res_empty.data.get("report", {})
    assert rep_empty.get("lines_count") == 0
    assert rep_empty.get("is_clean") is False

    # Lines with only whitespace
    res_ws = scraper.scrape(mock_lines=["   ", "\t  ", ""], mode="offline/mock")
    assert res_ws.status == AgentStatus.INCONCLUSIVE
    assert res_ws.error_code == "OUTPUT_EMPTY"


def test_output_scraper_clean_compile(clean_compile_lines):
    """Test 2: Clean compile with 0 errors, 0 warnings returns SUCCESS and is_clean=True."""
    scraper = CscapeOutputScraper()
    res = scraper.scrape(mock_lines=clean_compile_lines, mode="offline/mock")

    assert res.status == AgentStatus.SUCCESS
    assert res.data["mode"] == "offline/mock"
    report = ScraperReport(**res.data["report"])
    assert report.is_clean is True
    assert report.errors_count == 0
    assert report.warnings_count == 0
    assert report.lines_count == len(clean_compile_lines)

    # Validate against H01-H13 false success rules
    val = ContractValidator.validate_and_remediate(res)
    assert val.is_valid is True
    assert val.enforced_status == AgentStatus.SUCCESS


def test_output_scraper_syntax_errors(syntax_error_lines):
    """Test 3: Syntax error detection extracts line, col, error_code and returns FAILED."""
    scraper = CscapeOutputScraper()
    res = scraper.scrape(mock_lines=syntax_error_lines, mode="offline/mock")

    assert res.status == AgentStatus.FAILED
    assert res.error_code == "COMPILATION_ERROR"
    report = ScraperReport(**res.data["report"])
    assert report.is_clean is False
    assert report.errors_count == 2
    assert len(report.diagnostics) >= 2

    d0 = report.diagnostics[0]
    assert d0.level == DiagnosticSeverity.ERROR
    assert d0.line == 14
    assert d0.column == 5
    assert d0.error_code == "K51001"
    assert "Syntax error" in d0.message

    d1 = report.diagnostics[1]
    assert d1.level == DiagnosticSeverity.ERROR
    assert d1.line == 7
    assert d1.pou_name == "STBlock1"
    assert "Unknown identifier" in d1.message


def test_output_scraper_warnings(warning_compile_lines):
    """Test 4: Compilation with warnings (0 errors) returns PARTIAL per Rule H13."""
    scraper = CscapeOutputScraper()
    res = scraper.scrape(mock_lines=warning_compile_lines, mode="offline/mock")

    # Clean compile strictly requires 0 errors and 0 warnings
    assert res.status == AgentStatus.PARTIAL
    report = ScraperReport(**res.data["report"])
    assert report.is_clean is False
    assert report.errors_count == 0
    assert report.warnings_count == 2
    assert res.data.get("warning_count") == 2

    # Verify diagnostic extracted
    w0 = report.diagnostics[0]
    assert w0.level == DiagnosticSeverity.WARNING
    assert w0.line == 22
    assert "Unused variable" in w0.message

    # Validate contract integrity: H13 enforces PARTIAL status
    val = ContractValidator.validate_and_remediate(res)
    assert val.enforced_status == AgentStatus.PARTIAL


def test_output_scraper_fail_closed_when_cscape_not_running(monkeypatch):
    """Test 5: Live scrape fails closed when Cscape process is not running."""
    from jev_cscape.automation.lifecycle import CscapeLifecycleController

    scraper = CscapeOutputScraper()
    monkeypatch.setattr(CscapeLifecycleController, "find_cscape_processes", lambda self: [])

    res = scraper.scrape()
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "CSCAPE_NOT_RUNNING"


def test_output_scraper_offline_mock_mode(clean_compile_lines):
    """Test 6: Explicit mode='offline/mock' returns verified mock report (H01 compliant)."""
    scraper = CscapeOutputScraper()
    res = scraper.scrape(mock_lines=clean_compile_lines, mode="offline/mock")

    assert res.status == AgentStatus.SUCCESS
    assert res.data["mode"] == "offline/mock"

    # ContractValidator confirms no H01_SILENT_MOCK violation
    val = ContractValidator.validate_and_remediate(res)
    assert val.is_valid is True
    assert not any(v.pattern.value == "H01_SILENT_MOCK" for v in val.violations)


def test_output_scraper_mixed_errors_and_warnings(mixed_compile_lines):
    """Test 7: Mixed errors and warnings prioritize FAILED status with exact counts."""
    scraper = CscapeOutputScraper()
    res = scraper.scrape(mock_lines=mixed_compile_lines, mode="offline/mock")

    assert res.status == AgentStatus.FAILED
    report = ScraperReport(**res.data["report"])
    assert report.is_clean is False
    assert report.errors_count == 1
    assert report.warnings_count == 1


def test_output_scraper_gui_contention_blocked(tmp_path):
    """Test 8: Concurrent GUI access fails closed with BLOCKED status."""
    lock_file = str(tmp_path / "scraper_contention.lock")
    gui_ctrl = GUIBoundaryController(lock_path=lock_file)
    scraper = CscapeOutputScraper(gui_controller=gui_ctrl)

    holder = GUIBoundaryController(lock_path=lock_file)
    acq_res = holder.acquire_lock()
    assert acq_res.status == AgentStatus.SUCCESS

    res = scraper.scrape()
    assert res.status == AgentStatus.BLOCKED
    assert res.error_code == "GUI_CONTENTION_BLOCKED"

    holder.release_lock()


def test_compiler_dispatcher_trigger_and_scrape_mock_clean(clean_compile_lines):
    """Test 9: CscapeCompilerDispatcher.trigger_and_scrape clean mock execution."""
    disp = CscapeCompilerDispatcher()
    res = disp.trigger_and_scrape(mock_lines=clean_compile_lines)

    assert res.status == AgentStatus.SUCCESS
    assert res.data["mode"] == "offline/mock"
    assert res.data["error_count"] == 0
    assert res.data["warning_count"] == 0
    assert res.data["report"]["is_clean"] is True


def test_compiler_dispatcher_trigger_and_scrape_mock_warnings(warning_compile_lines):
    """Test 10: trigger_and_scrape with warnings honestly returns PARTIAL."""
    disp = CscapeCompilerDispatcher()
    res = disp.trigger_and_scrape(mock_lines=warning_compile_lines)

    assert res.status == AgentStatus.PARTIAL
    assert res.data["mode"] == "offline/mock"
    assert res.data["warning_count"] == 2
    assert res.data["report"]["is_clean"] is False


def test_compiler_dispatcher_trigger_and_scrape_mock_errors(syntax_error_lines):
    """Test 11: trigger_and_scrape with errors returns FAILED."""
    disp = CscapeCompilerDispatcher()
    res = disp.trigger_and_scrape(mock_lines=syntax_error_lines)

    assert res.status == AgentStatus.FAILED
    assert res.error_code == "COMPILATION_ERROR"
    assert res.data["mode"] == "offline/mock"
    assert res.data["error_count"] == 2
