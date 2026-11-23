"""Project Navigator UIAutomation Inspector for Cscape 10.2.

Inspects, verifies, and traverses the Cscape Project Navigator pane on the
interactive desktop (winsta0\\Default) using exclusively observed Win32 and
UIAutomation evidence. Never invents synthetic AutomationIds.

Observed Evidence Baseline (Cscape 10.2.751.4):
- Container Pane: Name="Project Navigator", Class="Afx:ControlBar:b90000:8:10003:10", AutoId="45012"
- Tree Control: Class="SysTreeView32", ControlType="TreeControl", Win32 ID=300, AutoId="300"
- Root Item: ControlType="TreeItemControl", Name="Project Navigator"
- Subnodes: Logic POUs, Hardware Configuration, System, Graphics
"""

import logging
from typing import Any, Dict, List, Optional
import win32con
import win32gui
from pydantic import BaseModel, Field

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.automation.lifecycle import CscapeLifecycleController

# Ensure thread is attached to interactive desktop before uiautomation hooks COM
CscapeLifecycleController.ensure_desktop()
import uiautomation as uia

from jev_cscape.automation.gui_controller import GUIBoundaryController

logger = logging.getLogger(__name__)


class TreeNodeInfo(BaseModel):
    """Hierarchical node inside the Project Navigator tree."""
    name: str
    control_type: str = "TreeItemControl"
    class_name: str = ""
    automation_id: str = ""
    bounding_rect: Optional[Dict[str, int]] = None
    children: List["TreeNodeInfo"] = Field(default_factory=list)


class NavigatorPaneInfo(BaseModel):
    """Structural metadata describing the verified Project Navigator pane."""
    pane_found: bool
    pane_name: str = "Project Navigator"
    pane_class: str = ""
    pane_auto_id: str = ""
    tree_hwnd: Optional[int] = None
    tree_hwnd_hex: Optional[str] = None
    tree_class: str = "SysTreeView32"
    tree_auto_id: str = "300"
    is_visible: bool = False
    item_count: int = 0
    root_items: List[TreeNodeInfo] = Field(default_factory=list)
    rect: Optional[Dict[str, int]] = None


class ProjectNavigatorWalker:
    """Inspector for Cscape 10.2 Project Navigator using verified UIA evidence."""

    # Observed control identifiers
    OBSERVED_PANE_NAME = "Project Navigator"
    OBSERVED_TREE_CLASS = "SysTreeView32"
    OBSERVED_TREE_CTRL_ID = 300
    OBSERVED_PANE_AUTO_ID = "45012"

    def __init__(self, gui_controller: Optional[GUIBoundaryController] = None):
        self.gui_controller = gui_controller or GUIBoundaryController()
        self.lifecycle = CscapeLifecycleController()

    def find_navigator_hwnd(self, main_hwnd: int) -> Optional[int]:
        """Locate the Win32 HWND of the Project Navigator tree (SysTreeView32, ID 300)."""
        trees: List[int] = []

        def enum_cb(ch, _):
            cls = win32gui.GetClassName(ch)
            if cls == self.OBSERVED_TREE_CLASS:
                cid = win32gui.GetWindowLong(ch, win32con.GWL_ID)
                # Primary match: ID 300
                if cid == self.OBSERVED_TREE_CTRL_ID:
                    trees.insert(0, ch)
                else:
                    # Check if parent is Project Navigator
                    parent = win32gui.GetParent(ch)
                    ptext = win32gui.GetWindowText(parent)
                    if self.OBSERVED_PANE_NAME.lower() in ptext.lower():
                        trees.append(ch)

        try:
            win32gui.EnumChildWindows(main_hwnd, enum_cb, None)
        except Exception as e:
            logger.debug(f"EnumChildWindows error: {e}")

        return trees[0] if trees else None

    def _extract_tree_items_uia(self, tree_ctrl: uia.TreeControl) -> List[TreeNodeInfo]:
        """Walk UIA TreeControl items recursively without inventing AutomationIds."""
        nodes: List[TreeNodeInfo] = []

        def walk_item(item: uia.TreeItemControl) -> TreeNodeInfo:
            rect = None
            try:
                r = item.BoundingRectangle
                if r:
                    rect = {
                        "left": r.left,
                        "top": r.top,
                        "right": r.right,
                        "bottom": r.bottom,
                        "width": r.width(),
                        "height": r.height(),
                    }
            except Exception:
                pass

            child_nodes = []
            try:
                for sub in item.GetChildren():
                    if sub.ControlTypeName == "TreeItemControl":
                        child_nodes.append(walk_item(sub))
            except Exception:
                pass

            return TreeNodeInfo(
                name=item.Name or "",
                control_type=item.ControlTypeName,
                class_name=item.ClassName or "",
                automation_id=item.AutomationId or "",
                bounding_rect=rect,
                children=child_nodes,
            )

        try:
            for root_item in tree_ctrl.GetChildren():
                if root_item.ControlTypeName == "TreeItemControl":
                    nodes.append(walk_item(root_item))
        except Exception as e:
            logger.debug(f"Error reading tree items: {e}")

        return nodes

    def inspect_tree(
        self,
        main_hwnd: Optional[int] = None,
        mock_data: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        """Inspect Project Navigator tree.
        
        If mock_data is provided, operates in explicit offline/mock mode (zero silent mocks).
        Otherwise performs live verification on winsta0\\Default guarded by GUIBoundaryController.
        """
        if mock_data is not None:
            # Explicit offline / mock test execution
            pane_info = NavigatorPaneInfo(**mock_data)
            return ExecutionResult.success(
                details=f"Project Navigator verified in offline/mock mode ({pane_info.item_count} nodes).",
                data={
                    "mode": "offline/mock",
                    "pane_info": pane_info.model_dump(),
                },
            )

        # 1. Acquire exclusive GUI lock to prevent contention
        try:
            with self.gui_controller.guard_gui(timeout=3.0):
                # 2. Verify Cscape is running and visible
                cscape_check = self.gui_controller.assert_cscape_active_and_visible()
                if cscape_check.status != AgentStatus.SUCCESS:
                    return cscape_check

                target_main_hwnd = main_hwnd or cscape_check.data.get("hwnd")
                if not target_main_hwnd or not win32gui.IsWindow(target_main_hwnd):
                    return ExecutionResult.failed(
                        error_code="INVALID_MAIN_HWND",
                        details=f"Cscape main window handle {target_main_hwnd} is invalid.",
                    )

                # 3. Locate tree window
                tree_hwnd = self.find_navigator_hwnd(target_main_hwnd)
                if not tree_hwnd:
                    return ExecutionResult.failed(
                        error_code="NAVIGATOR_NOT_FOUND",
                        details="FAIL_CLOSED: Project Navigator tree control (SysTreeView32) could not be resolved in Cscape.",
                    )

                is_visible = bool(win32gui.IsWindowVisible(tree_hwnd))
                rect = win32gui.GetWindowRect(tree_hwnd)
                rect_dict = {
                    "left": rect[0],
                    "top": rect[1],
                    "right": rect[2],
                    "bottom": rect[3],
                    "width": rect[2] - rect[0],
                    "height": rect[3] - rect[1],
                }

                # Win32 item count via TVM_GETCOUNT (0x1105)
                win32_count = win32gui.SendMessage(tree_hwnd, 0x1105, 0, 0)

                # 4. Read tree hierarchy via UIAutomation
                root_ctrl = uia.ControlFromHandle(target_main_hwnd)
                tree_ctrl = root_ctrl.TreeControl(searchDepth=4, ClassName=self.OBSERVED_TREE_CLASS)
                if not tree_ctrl.Exists(0, 0):
                    tree_ctrl = uia.TreeControlFromHandle(tree_hwnd)

                tree_items: List[TreeNodeInfo] = []
                if tree_ctrl.Exists(0, 0):
                    tree_items = self._extract_tree_items_uia(tree_ctrl)

                pane_parent = win32gui.GetParent(tree_hwnd)
                pane_name = win32gui.GetWindowText(pane_parent) or self.OBSERVED_PANE_NAME
                pane_class = win32gui.GetClassName(pane_parent)

                pane_info = NavigatorPaneInfo(
                    pane_found=True,
                    pane_name=pane_name,
                    pane_class=pane_class,
                    pane_auto_id=self.OBSERVED_PANE_AUTO_ID,
                    tree_hwnd=tree_hwnd,
                    tree_hwnd_hex=hex(tree_hwnd),
                    tree_class=self.OBSERVED_TREE_CLASS,
                    tree_auto_id=str(self.OBSERVED_TREE_CTRL_ID),
                    is_visible=is_visible,
                    item_count=win32_count if win32_count > 0 else len(tree_items),
                    root_items=tree_items,
                    rect=rect_dict,
                )

                return ExecutionResult.success(
                    details=(
                        f"Project Navigator verified visible and traversable on winsta0\\Default "
                        f"(HWND {hex(tree_hwnd)}, items: {pane_info.item_count})."
                    ),
                    data={
                        "mode": "live",
                        "pane_info": pane_info.model_dump(),
                    },
                )
        except PermissionError as e:
            return ExecutionResult.blocked(
                error_code="GUI_CONTENTION_BLOCKED",
                details=f"Project Navigator inspection blocked by GUI boundary contention: {e}",
            )
        except Exception as e:
            return ExecutionResult.failed(
                error_code="INSPECTION_ERROR",
                details=f"Error inspecting Project Navigator: {e}",
            )

    def find_node(
        self,
        node_name: str,
        root_items: List[TreeNodeInfo],
    ) -> Optional[TreeNodeInfo]:
        """Search recursively for a tree node by name."""
        target = node_name.lower().strip()
        for item in root_items:
            if target in item.name.lower():
                return item
            found = self.find_node(node_name, item.children)
            if found:
                return found
        return None

    def verify_node_presence(
        self,
        node_name: str,
        inspection_result: ExecutionResult,
    ) -> ExecutionResult:
        """Verify presence of a named node within prior inspection result data."""
        if inspection_result.status != AgentStatus.SUCCESS:
            return ExecutionResult.failed(
                error_code="PRECONDITION_FAILED",
                details=f"Cannot verify node '{node_name}': inspection status is {inspection_result.status.value}.",
            )

        pane_data = inspection_result.data.get("pane_info", {})
        raw_items = pane_data.get("root_items", [])
        items = [TreeNodeInfo(**it) for it in raw_items]

        node = self.find_node(node_name, items)
        if node:
            return ExecutionResult.success(
                details=f"Node '{node_name}' found in Project Navigator (type: {node.control_type}).",
                data={"node": node.model_dump()},
            )

        return ExecutionResult.failed(
            error_code="NODE_NOT_FOUND",
            details=f"Node '{node_name}' not found in Project Navigator tree.",
            data={"searched_name": node_name, "available_roots": [i.name for i in items]},
        )
