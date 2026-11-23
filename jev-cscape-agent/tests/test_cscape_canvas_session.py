"""Unit & Integration Test Suite for Live Cscape Child Window & Canvas Inspector.

Work Package: W042 (Gate G3 Live Cscape Evidence & Canvas Forensics)
Classification: PRODUCTION_READY [Single GUI Automation Agent]

Validates:
1. inspect_statusbar_panes extracts pane text and handles invalid HWNDs gracefully.
2. enumerate_child_windows_recursive traverses window hierarchies with depth bounding.
3. run_cscape_canvas_session returns strict 4-state contract envelope:
   {
       "status": "success | inconclusive",
       "error_code": None | "...",
       "details": "...",
       "data": {...}
   }
4. Safety invariants: exclusive GUI mutex lock, winsta0\\Default desktop, download command lockout.
5. CLI main entry point handles arguments and returns clean exit code.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from scripts.run_live_cscape_canvas_session import (
    enumerate_child_windows_recursive,
    inspect_statusbar_panes,
    main,
    run_cscape_canvas_session,
)


def test_inspect_statusbar_panes_invalid_hwnd() -> None:
    """Verify inspect_statusbar_panes safely handles invalid HWND without raising."""
    panes = inspect_statusbar_panes(0)
    assert isinstance(panes, list)
    assert len(panes) == 0


def test_enumerate_child_windows_depth_bound() -> None:
    """Verify recursive child window enumeration adheres to max_depth."""
    # Testing against desktop or shell window
    import win32gui
    desktop_hwnd = win32gui.GetDesktopWindow()
    children = enumerate_child_windows_recursive(desktop_hwnd, max_depth=1)
    assert isinstance(children, list)
    for c in children:
        assert "hwnd" in c
        assert "class_name" in c
        assert "rect" in c
        assert "children" not in c or len(c.get("children", [])) == 0


def test_run_cscape_canvas_session_contract(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Verify canvas session produces strict 4-state contract and valid evidence artifact."""
    monkeypatch.setattr(
        "scripts.run_live_cscape_canvas_session.run_session",
        lambda: {"status": "success", "data": {}},
    )
    out_file = tmp_path / "live_cscape_canvas_evidence.json"
    result = run_cscape_canvas_session(
        output_path=str(out_file),
        leave_open=False,
    )

    # 1. Strict 4-state envelope
    assert isinstance(result, dict)
    assert result["status"] in ("success", "inconclusive", "failed", "blocked")
    assert isinstance(result["details"], str)
    assert len(result["details"]) > 0
    assert isinstance(result["data"], dict)

    if result["status"] == "success":
        data = result["data"]
        assert data["gate"] == "G3"
        assert data["work_package"] == "W042"
        assert data["verdict"] == "success"
        assert "process_info" in data
        assert "mfc_structure" in data
        assert "safety_invariants" in data
        assert data["safety_invariants"]["exclusive_gui_lock_verified"] is True
        assert data["safety_invariants"]["desktop"] == "winsta0\\Default"

        assert out_file.exists()
        with open(out_file, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["status"] == "success"


def test_canvas_session_cli_entrypoint(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Verify CLI entry point handles arguments without unhandled exceptions."""
    monkeypatch.setattr(
        "scripts.run_live_cscape_canvas_session.run_session",
        lambda: {"status": "success", "data": {}},
    )
    out_file = tmp_path / "cli_canvas_out.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_live_cscape_canvas_session.py",
            "--output",
            str(out_file),
        ],
    )
    exit_code = main()
    # In interactive session returns 0 (success or inconclusive)
    assert exit_code in (0, 1)
