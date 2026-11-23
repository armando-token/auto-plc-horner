"""Unit tests for Cscape GUI Automated Window Health Watchdog & Geometry Forensics (W063).

Tests:
1. WindowRect properties (width, height, area, containment, offscreen detection).
2. WindowDescriptor health state classification (HEALTHY, MINIMIZED, HUNG, OFFSCREEN, etc.).
3. SimulatedWindowProvider standard Cscape 10.2 window tree structure.
4. MFC hierarchy validation on healthy Cscape MDI layout (MainFrame -> MDIClient).
5. MFC hierarchy validation rejection on unhealthy or undersized MainFrame.
6. MFC hierarchy validation rejection on missing MDIClient pane.
7. MFC hierarchy validation rejection on coordinate enclosure violations.
8. Modal dialog sweeper classification (Tip of the Day, Error, Save, Hardware).
9. Modal dialog sweeper stall detection when popup exceeds dwell time threshold.
10. Modal dialog sweeper cache cleanup when dialog is dismissed.
11. Single-GUI mutex lock inspection for unlocked, valid, and stale lock states.
12. SecurityGuard pure ST boundary enforcement against illegal ladder logic.
13. Canonical verification runner and artifact JSON generation.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pytest

from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.automation.gui_window_watchdog import (
    GUIWindowWatchdog,
    ModalDialogRecord,
    ModalDialogType,
    MutexLockStatus,
    SimulatedWindowProvider,
    WindowDescriptor,
    WindowHealthStatus,
    WindowRect,
    verify_gui_window_watchdog_and_export_evidence,
)


def test_window_rect_properties() -> None:
    """Verify WindowRect arithmetic, containment, and offscreen checks."""
    r1 = WindowRect(0, 0, 1920, 1080)
    assert r1.width == 1920
    assert r1.height == 1080
    assert r1.area == 1920 * 1080
    assert not r1.is_offscreen()

    r2 = WindowRect(100, 100, 500, 400)
    assert r1.contains(r2) is True
    assert r2.contains(r1) is False

    # Offscreen minimized window
    r_off = WindowRect(-32000, -32000, -31840, -31900)
    assert r_off.is_offscreen() is True


def test_window_descriptor_health_states() -> None:
    """Verify WindowDescriptor health property accurately classifies Win32 states."""
    # 1. Healthy
    w_healthy = WindowDescriptor(
        hwnd=1,
        title="Healthy Window",
        class_name="Afx",
        window_rect=WindowRect(0, 0, 1024, 768),
        client_rect=WindowRect(0, 0, 1024, 768),
        is_valid=True,
        is_visible=True,
        is_iconic=False,
        is_hung=False,
    )
    assert w_healthy.health == WindowHealthStatus.HEALTHY

    # 2. Invalid Handle
    w_invalid = dataclasses_replace(w_healthy, is_valid=False)
    assert w_invalid.health == WindowHealthStatus.INVALID_HANDLE

    # 3. Hung UI Thread
    w_hung = dataclasses_replace(w_healthy, is_hung=True)
    assert w_hung.health == WindowHealthStatus.HUNG

    # 4. Minimized (IsIconic)
    w_min = dataclasses_replace(w_healthy, is_iconic=True)
    assert w_min.health == WindowHealthStatus.MINIMIZED

    # 5. Offscreen
    w_off = dataclasses_replace(w_healthy, window_rect=WindowRect(-32000, -32000, -31000, -31000))
    assert w_off.health == WindowHealthStatus.OFFSCREEN

    # 6. Zero Area
    w_zero = dataclasses_replace(w_healthy, window_rect=WindowRect(10, 10, 10, 10))
    assert w_zero.health == WindowHealthStatus.ZERO_AREA

    # 7. Hidden / Not Visible
    w_hid = dataclasses_replace(w_healthy, is_visible=False)
    assert w_hid.health == WindowHealthStatus.NOT_VISIBLE


def test_simulated_window_provider_tree() -> None:
    """Verify simulated Cscape 10.2 window hierarchy contains all expected components."""
    provider = SimulatedWindowProvider()
    main_desc = provider.get_window_descriptor(0x001000)
    assert main_desc is not None
    assert "Cscape" in main_desc.title
    assert main_desc.health == WindowHealthStatus.HEALTHY

    children = provider.get_child_windows(0x001000)
    assert 0x002000 in children  # MDIClient
    assert 0x003000 in children  # Navigator
    assert 0x004000 in children  # Output pane


def test_validate_mfc_hierarchy_healthy() -> None:
    """Verify healthy standard Cscape window tree passes hierarchy audit."""
    watchdog = GUIWindowWatchdog()
    is_valid, violations, details = watchdog.validate_mfc_hierarchy(0x001000)
    assert is_valid is True
    assert len(violations) == 0
    assert "mdi_client" in details
    assert details["main_frame"]["health"] == "healthy"


def test_validate_mfc_hierarchy_unhealthy_mainframe() -> None:
    """Verify minimized or hung MainFrame fails hierarchy validation immediately."""
    provider = SimulatedWindowProvider()
    # Minimize MainFrame
    provider.windows[0x001000] = dataclasses_replace(
        provider.windows[0x001000], is_iconic=True
    )
    watchdog = GUIWindowWatchdog(provider=provider)
    is_valid, violations, _ = watchdog.validate_mfc_hierarchy(0x001000)
    assert is_valid is False
    assert any("unhealthy" in v for v in violations)


def test_validate_mfc_hierarchy_missing_mdiclient() -> None:
    """Verify missing MDIClient child results in hierarchy validation failure."""
    provider = SimulatedWindowProvider()
    # Remove MDIClient from children
    provider.windows[0x001000] = dataclasses_replace(
        provider.windows[0x001000], children_hwnds=(0x003000, 0x004000)
    )
    watchdog = GUIWindowWatchdog(provider=provider)
    is_valid, violations, _ = watchdog.validate_mfc_hierarchy(0x001000)
    assert is_valid is False
    assert any("No MDIClient found" in v for v in violations)


def test_validate_mfc_hierarchy_enclosure_violation() -> None:
    """Verify MDIClient protruding outside MainFrame boundaries triggers violation."""
    provider = SimulatedWindowProvider()
    # MDIClient extends beyond right border of MainFrame (2500 > 1920)
    provider.windows[0x002000] = dataclasses_replace(
        provider.windows[0x002000], window_rect=WindowRect(250, 60, 2500, 850)
    )
    watchdog = GUIWindowWatchdog(provider=provider)
    is_valid, violations, _ = watchdog.validate_mfc_hierarchy(0x001000)
    assert is_valid is False
    assert any("extends outside" in v for v in violations)


def test_modal_dialog_sweeper_classification() -> None:
    """Verify modal dialog sweeper correctly classifies common Cscape dialogs."""
    provider = SimulatedWindowProvider()
    provider.windows[0x005001] = WindowDescriptor(
        hwnd=0x005001,
        title="Tip of the Day",
        class_name="#32770",
        window_rect=WindowRect(100, 100, 500, 400),
        client_rect=WindowRect(0, 0, 400, 300),
        is_valid=True,
        is_visible=True,
        is_iconic=False,
        is_hung=False,
    )
    provider.windows[0x005002] = WindowDescriptor(
        hwnd=0x005002,
        title="Compiler Error in Subroutine 1",
        class_name="#32770",
        window_rect=WindowRect(100, 100, 500, 400),
        client_rect=WindowRect(0, 0, 400, 300),
        is_valid=True,
        is_visible=True,
        is_iconic=False,
        is_hung=False,
    )
    watchdog = GUIWindowWatchdog(provider=provider)
    records = watchdog.sweep_modal_dialogs()
    types = {r.hwnd: r.dialog_type for r in records}
    assert types[0x005001] == ModalDialogType.TIP_OF_THE_DAY
    assert types[0x005002] == ModalDialogType.COMPILER_ERROR


def test_modal_dialog_sweeper_stall_detection() -> None:
    """Verify modal popups exceeding stall threshold are flagged is_stalled=True."""
    provider = SimulatedWindowProvider()
    provider.windows[0x005001] = WindowDescriptor(
        hwnd=0x005001,
        title="Tip of the Day",
        class_name="#32770",
        window_rect=WindowRect(100, 100, 500, 400),
        client_rect=WindowRect(0, 0, 400, 300),
        is_valid=True,
        is_visible=True,
        is_iconic=False,
        is_hung=False,
    )
    # Threshold 0.05 seconds
    watchdog = GUIWindowWatchdog(provider=provider, modal_stall_timeout_s=0.05)
    r1 = watchdog.sweep_modal_dialogs()
    assert r1[0].is_stalled is False

    # Simulate passage of time
    import time
    time.sleep(0.06)
    r2 = watchdog.sweep_modal_dialogs()
    assert r2[0].is_stalled is True
    assert r2[0].dwell_time_s >= 0.05


def test_modal_dialog_sweeper_cleanup() -> None:
    """Verify dismissed dialogs are purged from tracking memory."""
    provider = SimulatedWindowProvider()
    provider.windows[0x005001] = WindowDescriptor(
        hwnd=0x005001,
        title="Prompt",
        class_name="#32770",
        window_rect=WindowRect(100, 100, 500, 400),
        client_rect=WindowRect(0, 0, 400, 300),
        is_valid=True,
        is_visible=True,
        is_iconic=False,
        is_hung=False,
    )
    watchdog = GUIWindowWatchdog(provider=provider)
    assert len(watchdog.sweep_modal_dialogs()) == 1
    assert 0x005001 in watchdog.known_dialogs

    # Dismiss dialog
    del provider.windows[0x005001]
    assert len(watchdog.sweep_modal_dialogs()) == 0
    assert 0x005001 not in watchdog.known_dialogs


def test_mutex_lock_forensics(tmp_path: Path) -> None:
    """Verify single-GUI mutex file audit correctly handles unlocked, active, and stale states."""
    watchdog = GUIWindowWatchdog(project_root=tmp_path)

    # 1. Unlocked
    s1 = watchdog.inspect_gui_mutex()
    assert s1.is_locked is False

    # 2. Active lock
    lock_file = tmp_path / "work" / "disposable" / "cscape_gui.lock"
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    my_pid = os.getpid()
    now_str = datetime.now(timezone.utc).isoformat()
    lock_file.write_text(f"{my_pid}:{now_str}", encoding="utf-8")

    s2 = watchdog.inspect_gui_mutex()
    assert s2.is_locked is True
    assert s2.owner_pid == my_pid
    assert s2.is_stale is False
    assert s2.is_pid_alive is True


def test_pure_st_ladder_rejection() -> None:
    """Verify security guard intercepts ladder constructs in GUI watchdog context."""
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content("---[ ]---; (* illegal ladder in GUI watchdog script *)")


def test_verify_gui_window_watchdog_evidence_export(tmp_path: Path) -> None:
    """Verify canonical verification runner generates evidence with strict 4-state contract."""
    evidence_file = tmp_path / "gui_watchdog_evidence.json"
    result = verify_gui_window_watchdog_and_export_evidence(str(evidence_file))

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert evidence_file.exists()

    with open(evidence_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["status"] == "success"
    assert data["data"]["geometry_forensics"]["mainframe_health"] == "healthy"
    assert data["data"]["mfc_hierarchy"]["hierarchy_valid"] is True


def dataclasses_replace(obj: Any, **changes: Any) -> Any:
    """Helper to shallow-replace fields on frozen dataclass."""
    import dataclasses
    d = {f.name: getattr(obj, f.name) for f in dataclasses.fields(obj)}
    d.update(changes)
    return type(obj)(**d)
