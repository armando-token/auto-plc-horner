"""Tests for DialogSweeper modal detection, classification, and dismissal engine."""

import time
import pytest
from unittest.mock import MagicMock, patch

from jev_cscape.automation.dialog_sweeper import (
    DialogSweeper,
    DialogType,
    DiscoveredDialog,
    DismissalRecord,
    SweepReport,
)
from jev_cscape.contracts import AgentStatus


def test_dialog_classification():
    sweeper = DialogSweeper()

    assert sweeper.classify_dialog("Tip of the Day", "#32770") == DialogType.TIP_OF_THE_DAY
    assert sweeper.classify_dialog("Cscape - Tip of the Day", "Afx:00B90000") == DialogType.TIP_OF_THE_DAY
    assert sweeper.classify_dialog("Allow user to choose program", "#32770") == DialogType.INITIAL_PROMPT
    assert sweeper.classify_dialog("File in use: project.csp", "#32770") == DialogType.FILE_LOCK_PROMPT
    assert sweeper.classify_dialog("Information", "#32770") == DialogType.GENERIC_MODAL
    assert sweeper.classify_dialog("Cscape Main Frame", "Afx:Main") == DialogType.UNKNOWN


def test_dialog_models():
    dialog = DiscoveredDialog(
        hwnd=12345,
        hwnd_hex="0x3039",
        pid=999,
        title="Tip of the Day",
        class_name="#32770",
        dialog_type=DialogType.TIP_OF_THE_DAY,
        buttons=[{"hwnd": 12346, "hwnd_hex": "0x303a", "id": 1, "text": "Close", "is_enabled": True, "is_visible": True}]
    )
    assert dialog.hwnd == 12345
    assert dialog.dialog_type == DialogType.TIP_OF_THE_DAY
    assert len(dialog.buttons) == 1


@patch("win32gui.PostMessage")
@patch("win32gui.IsWindow", return_value=True)
def test_dismiss_tip_of_the_day(mock_is_window, mock_post_message):
    sweeper = DialogSweeper()
    dialog = DiscoveredDialog(
        hwnd=5001,
        hwnd_hex="0x1389",
        pid=1234,
        title="Tip of the Day",
        class_name="#32770",
        dialog_type=DialogType.TIP_OF_THE_DAY,
        buttons=[{"hwnd": 5002, "hwnd_hex": "0x138a", "id": 1, "text": "Close", "is_enabled": True, "is_visible": True}]
    )

    dismissed = sweeper.dismiss_dialog(dialog)
    assert dismissed is True
    mock_post_message.assert_called_once()
    args, _ = mock_post_message.call_args
    assert args[0] == 5001  # hwnd
    assert args[2] == 1     # button IDOK/Close

    history = sweeper.get_dismissal_history()
    assert len(history) == 1
    assert history[0].hwnd == 5001
    assert history[0].dialog_type == DialogType.TIP_OF_THE_DAY


@patch("win32gui.PostMessage")
@patch("win32gui.IsWindow", return_value=True)
def test_dismiss_initial_prompt(mock_is_window, mock_post_message):
    sweeper = DialogSweeper()
    dialog = DiscoveredDialog(
        hwnd=6001,
        hwnd_hex="0x1771",
        pid=1234,
        title="Allow user to choose program",
        class_name="#32770",
        dialog_type=DialogType.INITIAL_PROMPT,
        buttons=[{"hwnd": 6002, "hwnd_hex": "0x1772", "id": 1, "text": "OK", "is_enabled": True, "is_visible": True}]
    )

    dismissed = sweeper.dismiss_dialog(dialog)
    assert dismissed is True
    mock_post_message.assert_called_once()


def test_contract_sweep_empty():
    sweeper = DialogSweeper(target_pids={99999})
    res = sweeper.execute_contract_sweep()
    assert res.status == AgentStatus.SUCCESS
    assert res.error_code is None
    assert "detected 0" in res.details
    assert res.data["detected_count"] == 0
    assert res.data["dismissed_count"] == 0


def test_background_sweeper_lifecycle():
    sweeper = DialogSweeper(target_pids={99999})
    assert not sweeper.is_running

    sweeper.start_background_sweeper(poll_interval=0.1)
    assert sweeper.is_running

    time.sleep(0.2)
    sweeper.stop_background_sweeper(timeout=1.0)
    assert not sweeper.is_running
