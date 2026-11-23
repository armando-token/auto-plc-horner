"""Navigation Map for Cscape 10.2 GUI Workspace.

Defines the complete menu hierarchy, command IDs, docking panes, and keyboard
accelerators for navigating Horner Cscape 10.2 on winsta0\\Default.
Enforces blocked command designations for physical download operations.
"""

from enum import Enum
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CommandSafety(str, Enum):
    """Safety classification of a Win32 command."""
    SAFE = "safe"
    BLOCKED = "blocked"
    RESTRICTED = "restricted"


class NavCommand(BaseModel):
    """Represents an executable menu item or accelerator in Cscape."""
    id: int
    name: str
    menu_path: str
    accelerator: Optional[str] = None
    safety: CommandSafety = CommandSafety.SAFE
    description: str


class DockingPane(BaseModel):
    """Represents a docking pane or window region in Cscape MFC workspace."""
    name: str
    pane_id: int
    window_class: str
    uia_control_type: str
    description: str


class NavigationMap:
    """Master topological navigation map for Cscape 10.2."""

    COMMANDS: List[NavCommand] = [
        # File Menu
        NavCommand(id=57600, name="ID_FILE_NEW", menu_path="File -> New", accelerator="Ctrl+N", description="Create new project"),
        NavCommand(id=57601, name="ID_FILE_OPEN", menu_path="File -> Open...", accelerator="Ctrl+O", description="Open existing .csp/.cpj project"),
        NavCommand(id=57602, name="ID_FILE_CLOSE", menu_path="File -> Close", description="Close active project"),
        NavCommand(id=57603, name="ID_FILE_SAVE", menu_path="File -> Save", accelerator="Ctrl+S", description="Save active project"),
        NavCommand(id=57604, name="ID_FILE_SAVE_AS", menu_path="File -> Save As...", description="Save project under new path"),
        NavCommand(id=57665, name="ID_APP_EXIT", menu_path="File -> Exit", accelerator="Alt+F4", description="Exit Cscape application"),

        # Edit Menu
        NavCommand(id=57643, name="ID_EDIT_UNDO", menu_path="Edit -> Undo", accelerator="Ctrl+Z", description="Undo last edit"),
        NavCommand(id=57644, name="ID_EDIT_REDO", menu_path="Edit -> Redo", accelerator="Ctrl+Y", description="Redo last edit"),
        NavCommand(id=57635, name="ID_EDIT_CUT", menu_path="Edit -> Cut", accelerator="Ctrl+X", description="Cut selected elements"),
        NavCommand(id=57634, name="ID_EDIT_COPY", menu_path="Edit -> Copy", accelerator="Ctrl+C", description="Copy selected elements"),
        NavCommand(id=57637, name="ID_EDIT_PASTE", menu_path="Edit -> Paste", accelerator="Ctrl+V", description="Paste clipboard elements"),

        # View Menu
        NavCommand(id=32800, name="ID_VIEW_PROJECT_NAVIGATOR", menu_path="View -> Project Navigator", description="Toggle Project Navigator dockable pane"),
        NavCommand(id=32801, name="ID_VIEW_OUTPUT_WINDOW", menu_path="View -> Output Window", description="Toggle compilation output ListBox pane"),
        NavCommand(id=59393, name="ID_VIEW_STATUS_BAR", menu_path="View -> Status Bar", description="Toggle bottom status bar"),

        # Program Menu
        NavCommand(id=32826, name="ID_PROGRAM_ERRORCHECK", menu_path="Program -> Error Check", accelerator="Ctrl+F7", description="Compile and validate project logic"),
        NavCommand(id=32827, name="ID_PROGRAM_DOWNLOAD", menu_path="Program -> Download", safety=CommandSafety.BLOCKED, description="BLOCKED: Program download to physical PLC"),
        NavCommand(id=32828, name="ID_PROGRAM_UPLOAD", menu_path="Program -> Upload", safety=CommandSafety.RESTRICTED, description="RESTRICTED: Program upload from PLC"),

        # Controller Menu
        NavCommand(id=33140, name="ID_CONTROLLER_HARDWARE", menu_path="Controller -> Hardware Configuration", description="Open controller hardware configuration dialog"),
        NavCommand(id=33149, name="ID_CONTROLLER_DOWNLOAD", menu_path="Controller -> Download", safety=CommandSafety.BLOCKED, description="BLOCKED: Controller firmware/program download"),
        NavCommand(id=33142, name="ID_CONTROLLER_IONAMES", menu_path="Controller -> I/O Names", description="Open I/O Name variable mapping editor"),
    ]

    PANES: List[DockingPane] = [
        DockingPane(
            name="Project Navigator",
            pane_id=32800,
            window_class="SysTreeCtrl32",
            uia_control_type="Tree",
            description="Hierarchical navigation tree containing System, Logic POUs, Hardware, and Graphics."
        ),
        DockingPane(
            name="Compiler Output Pane",
            pane_id=372,
            window_class="ListBox",
            uia_control_type="List",
            description="Compilation diagnostic messages, warnings, and error reports from ID_PROGRAM_ERRORCHECK."
        ),
        DockingPane(
            name="MDI Logic Workspace",
            pane_id=59648,
            window_class="MDIClient",
            uia_control_type="Pane",
            description="Active editor canvas for Structured Text POUs and ladder networks."
        ),
        DockingPane(
            name="Status Bar",
            pane_id=59393,
            window_class="msctls_statusbar32",
            uia_control_type="StatusBar",
            description="Status bar displaying cursor coordinates, target PLC model, and comms status."
        ),
    ]

    @classmethod
    def get_command_by_id(cls, cmd_id: int) -> Optional[NavCommand]:
        """Find command by Win32 command ID."""
        for c in cls.COMMANDS:
            if c.id == cmd_id:
                return c
        return None

    @classmethod
    def get_command_by_name(cls, name: str) -> Optional[NavCommand]:
        """Find command by name."""
        name_lower = name.lower()
        for c in cls.COMMANDS:
            if c.name.lower() == name_lower:
                return c
        return None

    @classmethod
    def get_blocked_commands(cls) -> List[NavCommand]:
        """Return list of all commands blocked by fail-closed safety policy."""
        return [c for c in cls.COMMANDS if c.safety == CommandSafety.BLOCKED]

    @classmethod
    def export_topology(cls) -> Dict[str, Any]:
        """Export full Cscape 10.2 navigation topology as dictionary."""
        return {
            "version": "10.2.751.4",
            "menus_count": len(cls.COMMANDS),
            "panes_count": len(cls.PANES),
            "commands": [c.model_dump() for c in cls.COMMANDS],
            "panes": [p.model_dump() for p in cls.PANES],
            "blocked_command_ids": [c.id for c in cls.get_blocked_commands()],
        }
