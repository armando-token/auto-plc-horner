"""Tests for ProjectNavigatorWalker using observed UIA evidence and fail-closed checks."""

import pytest
from jev_cscape.automation.navigator_walker import (
    ProjectNavigatorWalker,
    NavigatorPaneInfo,
    TreeNodeInfo,
)
from jev_cscape.automation.gui_controller import GUIBoundaryController
from jev_cscape.contracts import AgentStatus


@pytest.fixture
def mock_tree_data():
    return {
        "pane_found": True,
        "pane_name": "Project Navigator",
        "pane_class": "Afx:ControlBar:b90000:8:10003:10",
        "pane_auto_id": "45012",
        "tree_hwnd": 0x123456,
        "tree_hwnd_hex": "0x123456",
        "tree_class": "SysTreeView32",
        "tree_auto_id": "300",
        "is_visible": True,
        "item_count": 5,
        "root_items": [
            {
                "name": "Project Navigator",
                "control_type": "TreeItemControl",
                "class_name": "",
                "automation_id": "",
                "bounding_rect": {"left": 47, "top": 165, "right": 143, "bottom": 183, "width": 96, "height": 18},
                "children": [
                    {
                        "name": "System",
                        "control_type": "TreeItemControl",
                        "class_name": "",
                        "automation_id": "",
                        "bounding_rect": None,
                        "children": [],
                    },
                    {
                        "name": "Hardware Configuration",
                        "control_type": "TreeItemControl",
                        "class_name": "",
                        "automation_id": "",
                        "bounding_rect": None,
                        "children": [],
                    },
                    {
                        "name": "Logic",
                        "control_type": "TreeItemControl",
                        "class_name": "",
                        "automation_id": "",
                        "bounding_rect": None,
                        "children": [
                            {
                                "name": "Main (ST)",
                                "control_type": "TreeItemControl",
                                "class_name": "",
                                "automation_id": "",
                                "bounding_rect": None,
                                "children": [],
                            }
                        ],
                    },
                    {
                        "name": "Graphics",
                        "control_type": "TreeItemControl",
                        "class_name": "",
                        "automation_id": "",
                        "bounding_rect": None,
                        "children": [],
                    },
                ],
            }
        ],
        "rect": {"left": 9, "top": 165, "right": 307, "bottom": 540, "width": 298, "height": 375},
    }


def test_walker_initialization():
    walker = ProjectNavigatorWalker()
    assert walker.OBSERVED_PANE_NAME == "Project Navigator"
    assert walker.OBSERVED_TREE_CLASS == "SysTreeView32"
    assert walker.OBSERVED_TREE_CTRL_ID == 300
    assert walker.OBSERVED_PANE_AUTO_ID == "45012"


def test_offline_mock_inspection(mock_tree_data):
    walker = ProjectNavigatorWalker()
    res = walker.inspect_tree(mock_data=mock_tree_data)

    assert res.status == AgentStatus.SUCCESS
    assert res.data["mode"] == "offline/mock"
    pane = res.data["pane_info"]
    assert pane["pane_found"] is True
    assert pane["tree_class"] == "SysTreeView32"
    assert pane["tree_auto_id"] == "300"
    assert pane["item_count"] == 5
    assert len(pane["root_items"]) == 1
    assert pane["root_items"][0]["name"] == "Project Navigator"


def test_offline_mock_node_presence(mock_tree_data):
    walker = ProjectNavigatorWalker()
    insp_res = walker.inspect_tree(mock_data=mock_tree_data)
    assert insp_res.status == AgentStatus.SUCCESS

    # Verify present top-level and nested nodes
    assert walker.verify_node_presence("Logic", insp_res).status == AgentStatus.SUCCESS
    assert walker.verify_node_presence("Hardware Configuration", insp_res).status == AgentStatus.SUCCESS
    assert walker.verify_node_presence("Main (ST)", insp_res).status == AgentStatus.SUCCESS
    assert walker.verify_node_presence("System", insp_res).status == AgentStatus.SUCCESS
    assert walker.verify_node_presence("Graphics", insp_res).status == AgentStatus.SUCCESS

    # Verify absent node returns failed with NODE_NOT_FOUND
    absent_res = walker.verify_node_presence("NonExistent_POU", insp_res)
    assert absent_res.status == AgentStatus.FAILED
    assert absent_res.error_code == "NODE_NOT_FOUND"


def test_fail_closed_when_cscape_not_running(monkeypatch):
    from jev_cscape.automation.lifecycle import CscapeLifecycleController
    walker = ProjectNavigatorWalker()
    monkeypatch.setattr(CscapeLifecycleController, "find_cscape_processes", lambda self: [])
    
    res = walker.inspect_tree()
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "CSCAPE_NOT_RUNNING"


def test_contention_blocked(tmp_path):
    lock_file = str(tmp_path / "contention_test.lock")
    gui_ctrl = GUIBoundaryController(lock_path=lock_file)
    walker = ProjectNavigatorWalker(gui_controller=gui_ctrl)

    # Acquire lock in another controller instance first
    holder = GUIBoundaryController(lock_path=lock_file)
    acq_res = holder.acquire_lock()
    assert acq_res.status == AgentStatus.SUCCESS

    # Inspecting should fail closed with status: blocked
    res = walker.inspect_tree()
    assert res.status == AgentStatus.BLOCKED
    assert res.error_code == "GUI_CONTENTION_BLOCKED"

    # Cleanup
    holder.release_lock()
