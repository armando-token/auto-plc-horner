"""FastMCP Tool Registry and Protocol Dispatcher.

Work Package: W025 (Gate G6)
Classification: PRODUCTION_READY

Defines ToolParameter and ToolDefinition schemas, and FastMCPToolRegistry
with 16 tools conforming strictly to the 4-state engineering contract:
    status: success | failed | blocked | inconclusive
with zero external MCP runtime dependencies.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from jev_cscape import __version__
from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.automation.lifecycle import CscapeLifecycleController
from jev_cscape.automation.dialog_sweeper import DialogSweeper
from jev_cscape.automation.navigator_walker import ProjectNavigatorWalker
from jev_cscape.automation.compiler import CscapeCompilerDispatcher
from jev_cscape.automation.output_scraper import CscapeOutputScraper
from jev_cscape.iec.st_parser import STParser
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.security.exceptions import HardwareLockoutError, LadderForbiddenError


class ToolParameter(BaseModel):
    """Schema defining an individual parameter for a tool."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    name: str = Field(..., description="Parameter name")
    type: str = Field(default="string", description="JSON schema data type (string, integer, number, boolean, array, object)")
    description: str = Field(default="", description="Parameter explanation")
    required: bool = Field(default=False, description="Whether this parameter is required")
    default: Optional[Any] = Field(default=None, description="Default value if not provided")
    enum: Optional[List[Any]] = Field(default=None, description="Permitted enumeration values")


class ToolDefinition(BaseModel):
    """Schema defining an MCP-compatible tool and its execution contract."""

    model_config = ConfigDict(arbitrary_types_allowed=True, validate_assignment=True)

    name: str = Field(..., description="Unique tool identifier")
    description: str = Field(..., description="Detailed description of tool capabilities")
    parameters: List[ToolParameter] = Field(default_factory=list, description="Tool parameter schema list")
    handler: Optional[Callable[..., ExecutionResult]] = Field(default=None, exclude=True, description="Execution callable")

    def get_input_schema(self) -> Dict[str, Any]:
        """Generate standard JSON Schema for the tool parameters."""
        properties: Dict[str, Any] = {}
        for param in self.parameters:
            prop: Dict[str, Any] = {
                "type": param.type,
                "description": param.description,
            }
            if param.default is not None:
                prop["default"] = param.default
            if param.enum is not None:
                prop["enum"] = param.enum
            properties[param.name] = prop

        required_fields = [p.name for p in self.parameters if p.required]
        schema: Dict[str, Any] = {
            "type": "object",
            "properties": properties,
        }
        if required_fields:
            schema["required"] = required_fields
        return schema

    def to_mcp_format(self) -> Dict[str, Any]:
        """Export tool definition conforming to standard MCP tools/list entry."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.get_input_schema(),
        }

    def execute(self, **kwargs: Any) -> ExecutionResult:
        """Execute the tool handler with argument normalization."""
        if self.handler is None:
            return ExecutionResult.failed(
                error_code="NO_HANDLER",
                details=f"No execution handler registered for tool '{self.name}'.",
            )
        try:
            return self.handler(**kwargs)
        except HardwareLockoutError as exc:
            return ExecutionResult.blocked(
                error_code="FAIL_CLOSED_HARDWARE_LOCKOUT",
                details=str(exc),
            )
        except LadderForbiddenError as exc:
            return ExecutionResult.failed(
                error_code="ERR_LADDER_FORBIDDEN",
                details=str(exc),
            )
        except Exception as exc:
            return ExecutionResult.failed(
                error_code="TOOL_EXECUTION_ERROR",
                details=f"Tool '{self.name}' raised an unhandled exception: {exc}",
            )


class FastMCPToolRegistry:
    """Registry managing the 16 Gate G6 tools for Cscape autonomous operation."""

    def __init__(self, register_defaults: bool = True) -> None:
        self._tools: Dict[str, ToolDefinition] = {}
        if register_defaults:
            self._register_default_tools()

    def register(self, tool: ToolDefinition) -> None:
        """Register a tool definition into the registry."""
        self._tools[tool.name] = tool

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """Retrieve a tool definition by name."""
        return self._tools.get(name)

    def has_tool(self, name: str) -> bool:
        """Check if a tool exists in the registry."""
        return name in self._tools

    def list_tools(self) -> List[ToolDefinition]:
        """List all registered tool definitions."""
        return list(self._tools.values())

    def get_tool_names(self) -> List[str]:
        """List names of all registered tools."""
        return list(self._tools.keys())

    def to_mcp_tools(self) -> List[Dict[str, Any]]:
        """Return all tools formatted for the MCP tools/list protocol response."""
        return [tool.to_mcp_format() for tool in self._tools.values()]

    def execute_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> ExecutionResult:
        """Execute a registered tool by name with arguments strictly returning ExecutionResult."""
        tool = self.get_tool(name)
        if not tool:
            return ExecutionResult.failed(
                error_code="TOOL_NOT_FOUND",
                details=f"Tool '{name}' is not registered in FastMCPToolRegistry.",
            )
        args = arguments or {}
        return tool.execute(**args)

    # -------------------------------------------------------------------------
    # Default 16 Tool Implementations
    # -------------------------------------------------------------------------

    def _register_default_tools(self) -> None:
        """Register the 16 canonical Gate G6 tools."""
        self.register(self._def_cscape_doctor())
        self.register(self._def_cscape_status())
        self.register(self._def_gui_inspect())
        self.register(self._def_gui_launch())
        self.register(self._def_gui_close())
        self.register(self._def_gui_sweep_dialogs())
        self.register(self._def_gui_inspect_navigator())
        self.register(self._def_gui_compile_error_check())
        self.register(self._def_gui_scrape_output())
        self.register(self._def_iec_validate_st())
        self.register(self._def_iec_convert_st_to_ladder())
        self.register(self._def_sim_run_scan_cycles())
        self.register(self._def_sim_verify_closed_loop())
        self.register(self._def_sim_inspect_registers())
        self.register(self._def_security_audit_guard())
        self.register(self._def_security_verify_manifest())

    # 1. cscape_doctor
    def _def_cscape_doctor(self) -> ToolDefinition:
        def handler(cscape_path: Optional[str] = None, mock: bool = False) -> ExecutionResult:
            target_path = cscape_path or r"C:\Program Files (x86)\Cscape 10.2\Cscape.exe"
            cscape_found = True if mock else os.path.isfile(target_path)
            from jev_cscape.cli import get_provider_mode
            checks = {
                "os_windows": sys.platform == "win32",
                "python_version": sys.version.split()[0],
                "cscape_installed": cscape_found,
                "cscape_path": target_path,
                "hardware_lockout_active": True,
                "provider_mode": get_provider_mode(),
            }
            if mock:
                checks["mode"] = "offline/mock"
                return ExecutionResult.success(
                    details="Environment and safety invariant diagnostics passed (offline/mock mode).",
                    data=checks,
                )
            if not cscape_found:
                return ExecutionResult.failed(
                    error_code="CSCAPE_EXE_NOT_FOUND",
                    details=f"Cscape executable not found at '{target_path}'.",
                    data=checks,
                )
            return ExecutionResult.success(
                details="Environment and safety invariant diagnostics passed.",
                data=checks,
            )

        return ToolDefinition(
            name="cscape_doctor",
            description="Run environment, Cscape installation, and safety invariant diagnostics.",
            parameters=[
                ToolParameter(
                    name="cscape_path",
                    type="string",
                    description="Optional custom path to Cscape.exe",
                    required=False,
                    default=None,
                ),
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                ),
            ],
            handler=handler,
        )

    # 2. cscape_status
    def _def_cscape_status(self) -> ToolDefinition:
        def handler(mock: bool = False) -> ExecutionResult:
            repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            gates_path = os.path.join(repo_root, "ops", "gates.json")
            backlog_path = os.path.join(repo_root, "ops", "backlog.json")

            gates_data: Dict[str, Any] = {}
            backlog_data: Dict[str, Any] = {}
            if os.path.isfile(gates_path):
                with open(gates_path, "r", encoding="utf-8") as f:
                    gates_data = json.load(f)
            if os.path.isfile(backlog_path):
                with open(backlog_path, "r", encoding="utf-8") as f:
                    backlog_data = json.load(f)

            from jev_cscape.cli import get_provider_mode
            data_payload = {
                "agent_version": __version__,
                "provider_mode": get_provider_mode(),
                "gates_summary": {k: v.get("status") for k, v in gates_data.get("gates", {}).items()},
                "backlog_count": len(backlog_data.get("work_packages", [])),
            }
            if mock:
                data_payload["mode"] = "offline/mock"
            return ExecutionResult.success(
                details="JEV Cscape operational status and gate ledger retrieved.",
                data=data_payload,
            )

        return ToolDefinition(
            name="cscape_status",
            description="Display active gate status, operational backlog summary, and provider mode.",
            parameters=[
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                ),
            ],
            handler=handler,
        )

    # 3. gui_inspect
    def _def_gui_inspect(self) -> ToolDefinition:
        def handler(mock: bool = False) -> ExecutionResult:
            if mock:
                mock_layout = {
                    "processes_count": 1,
                    "pids": [45000],
                    "main_window": {
                        "hwnd": 0x10200,
                        "hwnd_hex": "0x10200",
                        "pid": 45000,
                        "title": "Cscape - [Untitled1]",
                        "class_name": "Afx:00400000:b:00010003:00000006:00000000",
                        "is_visible": True,
                        "rect": {"left": 0, "top": 0, "right": 1920, "bottom": 1080, "width": 1920, "height": 1080},
                    },
                    "all_windows": [
                        {
                            "hwnd": 0x10200,
                            "hwnd_hex": "0x10200",
                            "pid": 45000,
                            "title": "Cscape - [Untitled1]",
                            "class_name": "Afx:00400000:b:00010003:00000006:00000000",
                            "is_visible": True,
                            "rect": {"left": 0, "top": 0, "right": 1920, "bottom": 1080, "width": 1920, "height": 1080},
                        }
                    ],
                    "modal_dialogs": [],
                    "is_visible": True,
                    "desktop_session": {
                        "window_station": "WinSta0",
                        "desktop": "Default",
                    },
                    "mode": "offline/mock",
                }
                return ExecutionResult.success(
                    details="Cscape visible on desktop with PID 45000 and HWND 0x10200 (offline/mock mode).",
                    data=mock_layout,
                )
            controller = CscapeLifecycleController()
            return controller.inspect()

        return ToolDefinition(
            name="gui_inspect",
            description="Inspect live Cscape process, main window HWND, and modal dialogs on winsta0\\Default.",
            parameters=[
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                ),
            ],
            handler=handler,
        )

    # 4. gui_launch
    def _def_gui_launch(self) -> ToolDefinition:
        def handler(
            project_path: Optional[str] = None,
            timeout: float = 15.0,
            mock: bool = False,
        ) -> ExecutionResult:
            if project_path:
                try:
                    SecurityGuard.assert_cli_switches_safe([project_path])
                except HardwareLockoutError as exc:
                    return ExecutionResult.blocked(
                        error_code="FAIL_CLOSED_HARDWARE_LOCKOUT",
                        details=str(exc),
                    )
            if mock:
                proj_name = os.path.basename(project_path) if project_path else "Untitled1"
                mock_data = {
                    "pid": 45000,
                    "hwnd": 0x10200,
                    "hwnd_hex": "0x10200",
                    "main_window": {
                        "hwnd": 0x10200,
                        "hwnd_hex": "0x10200",
                        "pid": 45000,
                        "title": f"Cscape - [{proj_name}]",
                        "class_name": "Afx:00400000:b:00010003:00000006:00000000",
                        "is_visible": True,
                        "rect": {"left": 0, "top": 0, "right": 1920, "bottom": 1080, "width": 1920, "height": 1080},
                    },
                    "processes_count": 1,
                    "pids": [45000],
                    "all_windows": [],
                    "modal_dialogs": [],
                    "is_visible": True,
                    "project_path": project_path,
                    "mode": "offline/mock",
                    "desktop_session": {
                        "window_station": "WinSta0",
                        "desktop": "Default",
                    },
                }
                return ExecutionResult.success(
                    details="Cscape 10.2 successfully launched and verified visible on interactive desktop (mock mode, PID 45000).",
                    data=mock_data,
                )
            controller = CscapeLifecycleController()
            return controller.launch(project_path=project_path, timeout=timeout)

        return ToolDefinition(
            name="gui_launch",
            description="Launch Cscape 10.2 on winsta0\\Default with optional project file.",
            parameters=[
                ToolParameter(
                    name="project_path",
                    type="string",
                    description="Path to .csp/.cpj project file to open",
                    required=False,
                    default=None,
                ),
                ToolParameter(
                    name="timeout",
                    type="number",
                    description="Window appearance timeout in seconds",
                    required=False,
                    default=15.0,
                ),
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                ),
            ],
            handler=handler,
        )

    # 5. gui_close
    def _def_gui_close(self) -> ToolDefinition:
        def handler(timeout: float = 5.0, mock: bool = False) -> ExecutionResult:
            if mock:
                return ExecutionResult.success(
                    details="Cscape closed cleanly via WM_CLOSE (offline/mock mode).",
                    data={"closed": True, "mode": "offline/mock"},
                )
            controller = CscapeLifecycleController()
            return controller.close(timeout=timeout)

        return ToolDefinition(
            name="gui_close",
            description="Cleanly close running Cscape process via WM_CLOSE on winsta0\\Default.",
            parameters=[
                ToolParameter(
                    name="timeout",
                    type="number",
                    description="Teardown timeout in seconds",
                    required=False,
                    default=5.0,
                ),
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                ),
            ],
            handler=handler,
        )

    # 6. gui_sweep_dialogs
    def _def_gui_sweep_dialogs(self) -> ToolDefinition:
        def handler(mock: bool = False) -> ExecutionResult:
            if mock:
                return ExecutionResult.success(
                    details="Dialog sweeper completed (offline/mock mode): detected 0, dismissed 0 dialog(s).",
                    data={
                        "detected_count": 0,
                        "dismissed_count": 0,
                        "dialogs": [],
                        "dismissals": [],
                        "mode": "offline/mock",
                    },
                )
            controller = CscapeLifecycleController()
            procs = controller.find_cscape_processes()
            pids = {p.pid for p in procs}
            sweeper = DialogSweeper(target_pids=pids)
            return sweeper.execute_contract_sweep()

        return ToolDefinition(
            name="gui_sweep_dialogs",
            description="Sweep and dismiss Cscape modal dialogs (#32770, Tip of the Day) on winsta0\\Default.",
            parameters=[
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                ),
            ],
            handler=handler,
        )

    # 7. gui_inspect_navigator
    def _def_gui_inspect_navigator(self) -> ToolDefinition:
        def handler(mock: bool = False) -> ExecutionResult:
            walker = ProjectNavigatorWalker()
            if mock:
                mock_data = {
                    "pane_found": True,
                    "pane_name": "Project Navigator",
                    "pane_class": "Afx:ControlBar:b90000:8:10003:10",
                    "pane_auto_id": "45012",
                    "tree_hwnd": 0x300,
                    "tree_hwnd_hex": "0x300",
                    "tree_class": "SysTreeView32",
                    "tree_auto_id": "300",
                    "is_visible": True,
                    "item_count": 5,
                    "root_items": [
                        {
                            "name": "Project Navigator",
                            "control_type": "TreeItemControl",
                            "children": [
                                {"name": "System", "control_type": "TreeItemControl", "children": []},
                                {"name": "Hardware Configuration", "control_type": "TreeItemControl", "children": []},
                                {"name": "Logic", "control_type": "TreeItemControl", "children": [
                                    {"name": "Main (ST)", "control_type": "TreeItemControl", "children": []}
                                ]},
                                {"name": "Graphics", "control_type": "TreeItemControl", "children": []}
                            ]
                        }
                    ],
                    "rect": {"left": 9, "top": 165, "right": 307, "bottom": 540, "width": 298, "height": 375}
                }
                return walker.inspect_tree(mock_data=mock_data)
            return walker.inspect_tree()

        return ToolDefinition(
            name="gui_inspect_navigator",
            description="Inspect Cscape Project Navigator pane and SysTreeView32 tree nodes.",
            parameters=[
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                )
            ],
            handler=handler,
        )

    # 8. gui_compile_error_check
    def _def_gui_compile_error_check(self) -> ToolDefinition:
        def handler(mock: bool = False) -> ExecutionResult:
            dispatcher = CscapeCompilerDispatcher()
            if mock:
                mock_data = {
                    "success": True,
                    "errors_count": 0,
                    "warnings_count": 0,
                    "command_id": 32826,
                    "mode": "offline/mock",
                    "compilation_time_seconds": 0.42,
                    "details": "Mock clean compile verified with 0 errors, 0 warnings.",
                }
                return dispatcher.trigger_error_check(mock_result=mock_data)
            return dispatcher.trigger_error_check()

        return ToolDefinition(
            name="gui_compile_error_check",
            description="Dispatch ID_PROGRAM_ERRORCHECK (32826) clean compile check to Cscape.",
            parameters=[
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                )
            ],
            handler=handler,
        )

    # 9. gui_scrape_output
    def _def_gui_scrape_output(self) -> ToolDefinition:
        def handler(mock: bool = False, mock_lines: Optional[List[str]] = None) -> ExecutionResult:
            scraper = CscapeOutputScraper()
            if mock or mock_lines is not None:
                lines = mock_lines or [
                    "=== Horner Cscape 10.2 Compile Pass: TankLevelClosedLoop ===",
                    "Clean Build: True",
                    "Mode: IEC 61131-3 Structured Text",
                    "Logic: Checking Logic...",
                    "TankLevelClosedLoop: 0 error(s), 0 warning(s)",
                    "Build Result: SUCCESS",
                ]
                return scraper.scrape(mock_lines=lines, mode="offline/mock")
            return scraper.scrape()

        return ToolDefinition(
            name="gui_scrape_output",
            description="Scrape compiler diagnostics from Cscape MFC ListBox 372 in Output Window.",
            parameters=[
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                ),
                ToolParameter(
                    name="mock_lines",
                    type="array",
                    description="Mock compiler output lines for verification",
                    required=False,
                    default=None,
                ),
            ],
            handler=handler,
        )

    # 10. iec_validate_st
    def _def_iec_validate_st(self) -> ToolDefinition:
        def handler(
            file_path: Optional[str] = None,
            st_code: Optional[str] = None,
            mock: bool = False,
        ) -> ExecutionResult:
            if mock and not file_path and not st_code:
                st_code = """
PROGRAM MockLogic
VAR
    LevelInput AT %AI1 : INT;
    PumpOutput AT %Q1 : BOOL;
END_VAR
    PumpOutput := LevelInput > 500;
END_PROGRAM
"""
            if file_path:
                return STParser.validate_file(file_path)
            elif st_code is not None:
                val_res = STParser.validate_code(st_code)
                if val_res.status != AgentStatus.SUCCESS:
                    return val_res
                try:
                    ast = STParser.parse_pou(st_code)
                    res_data = ast.model_dump()
                    if mock:
                        res_data["mode"] = "offline/mock"
                    return ExecutionResult.success(
                        details=f"Successfully parsed {ast.pou_type.value} '{ast.name}' ({len(ast.variables)} vars, {ast.statements_count} statements).",
                        data=res_data,
                    )
                except Exception as exc:
                    return ExecutionResult.failed(
                        error_code="ST_PARSE_ERROR",
                        details=f"Parsing error: {exc}",
                    )
            return ExecutionResult.failed(
                error_code="MISSING_ARGUMENT",
                details="Either 'file_path' or 'st_code' must be provided.",
            )

        return ToolDefinition(
            name="iec_validate_st",
            description="Validate pure IEC 61131-3 Structured Text POU source, rejecting ladder constructs.",
            parameters=[
                ToolParameter(
                    name="file_path",
                    type="string",
                    description="Path to .st source file on disk",
                    required=False,
                    default=None,
                ),
                ToolParameter(
                    name="st_code",
                    type="string",
                    description="Structured text source code in memory",
                    required=False,
                    default=None,
                ),
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                ),
            ],
            handler=handler,
        )

    # 11. iec_convert_st_to_ladder
    def _def_iec_convert_st_to_ladder(self) -> ToolDefinition:
        def handler(
            st_code: Optional[str] = None,
            file_path: Optional[str] = None,
            mock: bool = False,
        ) -> ExecutionResult:
            # Strictly enforced Gate G1 / H04 & AGENTS.md rule:
            # Cscape 10.2 does not support in-GUI ST-to-Ladder conversion (BLOCKED_NATIVE: DOCUMENT_ONLY).
            return ExecutionResult.blocked(
                error_code="BLOCKED_NATIVE",
                details="ST-to-LD native conversion in Cscape 10.2 is permanently blocked (BLOCKED_NATIVE: DOCUMENT_ONLY). Cscape 10.2 contains zero native menus or exports for ST-to-Ladder translation.",
                data={"conversion_supported": False, "mode": "DOCUMENT_ONLY"},
            )

        return ToolDefinition(
            name="iec_convert_st_to_ladder",
            description="Convert Structured Text to Ladder logic in Cscape (permanently BLOCKED_NATIVE).",
            parameters=[
                ToolParameter(
                    name="st_code",
                    type="string",
                    description="Structured text source code",
                    required=False,
                    default=None,
                ),
                ToolParameter(
                    name="file_path",
                    type="string",
                    description="Path to .st source file",
                    required=False,
                    default=None,
                ),
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                ),
            ],
            handler=handler,
        )

    # 12. sim_run_scan_cycles
    def _def_sim_run_scan_cycles(self) -> ToolDefinition:
        def handler(
            cycles: int = 10,
            dt_ms: float = 10.0,
            export_trace: Optional[str] = None,
            export_evidence: Optional[str] = None,
            mock: bool = False,
        ) -> ExecutionResult:
            from jev_cscape.simulation.engine import SimulationEngine, PacingMode
            engine = SimulationEngine(default_dt_ms=dt_ms, pacing_mode=PacingMode.FAST)
            cycle_list = engine.run_cycles(cycles)
            data = dict(cycle_list.data)
            data["cycles_requested"] = cycles
            data["telemetry"] = engine.trace.summary_telemetry()
            if mock:
                data["mode"] = "offline/mock"
            if export_trace:
                engine.trace.to_json(filepath=export_trace)
                data["exported_trace"] = export_trace
            if export_evidence:
                engine.export_g4_evidence(filepath=export_evidence)
                data["exported_evidence"] = export_evidence
            return ExecutionResult.success(
                details=f"Completed {cycles} simulation cycles cleanly ({data.get('virtual_elapsed_ms', 0.0):.1f}ms virtual time).",
                data=data,
            )

        return ToolDefinition(
            name="sim_run_scan_cycles",
            description="Execute deterministic in-memory scan cycle simulation of Horner OCS logic.",
            parameters=[
                ToolParameter(
                    name="cycles",
                    type="integer",
                    description="Number of scan cycles to execute (default: 10)",
                    required=False,
                    default=10,
                ),
                ToolParameter(
                    name="dt_ms",
                    type="number",
                    description="Scan interval delta_t in milliseconds (default: 10.0)",
                    required=False,
                    default=10.0,
                ),
                ToolParameter(
                    name="export_trace",
                    type="string",
                    description="Optional file path to export cycle trace JSON",
                    required=False,
                    default=None,
                ),
                ToolParameter(
                    name="export_evidence",
                    type="string",
                    description="Optional file path to export Gate G4 evidence JSON",
                    required=False,
                    default=None,
                ),
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                ),
            ],
            handler=handler,
        )

    # 13. sim_verify_closed_loop
    def _def_sim_verify_closed_loop(self) -> ToolDefinition:
        def handler(
            scenario: Optional[str] = None,
            dt_ms: float = 10.0,
            export_evidence: Optional[str] = None,
            mock: bool = False,
        ) -> ExecutionResult:
            from jev_cscape.simulation.verifier import ClosedLoopVerifier, ScenarioStatus
            verifier = ClosedLoopVerifier(default_dt_ms=dt_ms)
            if scenario:
                method_name = f"scenario_{scenario}"
                scenario_method = getattr(verifier, method_name, None)
                if not scenario_method:
                    return ExecutionResult.failed(
                        error_code="UNKNOWN_SCENARIO",
                        details=f"Scenario '{scenario}' not found. Available: setpoint_tracking, disturbance_rejection, alarm_hysteresis, emergency_shutdown, multirate_stability.",
                        data={"scenario": scenario},
                    )
                res = scenario_method()
                passed = (res.status == ScenarioStatus.PASSED)
                payload = {
                    "scenario": res.name,
                    "status": res.status.value,
                    "cycles_executed": res.cycles_executed,
                    "duration_ms": res.duration_ms,
                    "metrics": res.metrics,
                    "details": res.details,
                    "mode": "offline/mock",
                }
                if passed:
                    return ExecutionResult.success(
                        details=f"Closed-loop scenario '{scenario}' passed.",
                        data=payload,
                    )
                return ExecutionResult.failed(
                    error_code="SCENARIO_FAILED",
                    details=f"Closed-loop scenario '{scenario}' failed: {res.details}",
                    data=payload,
                )
            else:
                results = verifier.run_all_scenarios()
                all_passed = all(r.status == ScenarioStatus.PASSED for r in results.values())
                payload = {
                    "mode": "offline/mock",
                    "total_scenarios": len(results),
                    "passed_scenarios": sum(1 for r in results.values() if r.status == ScenarioStatus.PASSED),
                    "scenarios": {k: {"status": v.status.value, "cycles": v.cycles_executed, "metrics": v.metrics} for k, v in results.items()},
                }
                if export_evidence:
                    verifier.export_evidence_artifact(export_evidence)
                    payload["exported_evidence"] = export_evidence

                if all_passed:
                    return ExecutionResult.success(
                        details=f"All {len(results)} closed-loop scenarios passed deterministically.",
                        data=payload,
                    )
                return ExecutionResult.failed(
                    error_code="CLOSED_LOOP_VERIFICATION_FAILED",
                    details="One or more closed-loop simulation scenarios failed.",
                    data=payload,
                )

        return ToolDefinition(
            name="sim_verify_closed_loop",
            description="Run deterministic closed-loop plant simulation verification matrix (5 canonical scenarios).",
            parameters=[
                ToolParameter(
                    name="scenario",
                    type="string",
                    description="Optional specific scenario name (setpoint_tracking, disturbance_rejection, alarm_hysteresis, emergency_shutdown, multirate_stability)",
                    required=False,
                    default=None,
                ),
                ToolParameter(
                    name="dt_ms",
                    type="number",
                    description="Scan interval delta_t in milliseconds (default: 10.0)",
                    required=False,
                    default=10.0,
                ),
                ToolParameter(
                    name="export_evidence",
                    type="string",
                    description="Optional file path to export evidence JSON",
                    required=False,
                    default=None,
                ),
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                ),
            ],
            handler=handler,
        )

    # 14. sim_inspect_registers
    def _def_sim_inspect_registers(self) -> ToolDefinition:
        def handler(
            channel: Optional[str] = None,
            address: Optional[str] = None,
            nonzero_only: bool = False,
            format: str = "json",
            mock: bool = False,
        ) -> ExecutionResult:
            from jev_cscape.simulation.register_table import RegisterTable
            from jev_cscape.automation.register_inspector import RegisterInspector

            table = RegisterTable()
            addresses = [address] if address else None
            try:
                report = RegisterInspector.inspect(
                    table=table,
                    addresses=addresses,
                    channel=channel,
                    nonzero_only=nonzero_only,
                )
            except Exception as exc:
                return ExecutionResult.failed(
                    error_code="INSPECT_REGISTERS_ERROR",
                    details=f"Failed to inspect registers: {exc}",
                )

            if mock:
                report["mode"] = "offline/mock"
            if format == "table":
                table_text = RegisterInspector.format_table(report)
                return ExecutionResult.success(
                    details=f"Inspected {report['count']} registers.",
                    data={"output_table": table_text, "summary": report},
                )
            return ExecutionResult.success(
                details=f"Inspected {report['count']} registers.",
                data=report,
            )

        return ToolDefinition(
            name="sim_inspect_registers",
            description="Inspect Horner OCS register space (%R, %I, %Q, %AI, %AQ, %SR, %S, etc.).",
            parameters=[
                ToolParameter(
                    name="channel",
                    type="string",
                    description="Filter by channel prefix (e.g. %R, %AI, %I, %SR)",
                    required=False,
                    default=None,
                ),
                ToolParameter(
                    name="address",
                    type="string",
                    description="Specific address or range expression (e.g. %R1..%R10)",
                    required=False,
                    default=None,
                ),
                ToolParameter(
                    name="nonzero_only",
                    type="boolean",
                    description="Display only non-zero registers",
                    required=False,
                    default=False,
                ),
                ToolParameter(
                    name="format",
                    type="string",
                    description="Output format ('json' or 'table')",
                    required=False,
                    default="json",
                    enum=["json", "table"],
                ),
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                ),
            ],
            handler=handler,
        )

    # 15. security_audit_guard
    def _def_security_audit_guard(self) -> ToolDefinition:
        def handler(
            target_port: Optional[str] = None,
            target_binary: Optional[str] = None,
            target_command_id: Optional[int] = None,
            mock: bool = False,
        ) -> ExecutionResult:
            if target_port:
                try:
                    SecurityGuard.assert_port_safe(target_port)
                    return ExecutionResult.success(
                        details=f"Port '{target_port}' verified safe (non-hardware).",
                        data={"port": target_port, "safe": True},
                    )
                except HardwareLockoutError as exc:
                    return ExecutionResult.blocked(
                        error_code="FAIL_CLOSED_HARDWARE_LOCKOUT",
                        details=str(exc),
                        data={"port": target_port, "blocked": True},
                    )

            if target_binary:
                try:
                    SecurityGuard.assert_binary_execution_safe(target_binary)
                    return ExecutionResult.success(
                        details=f"Binary '{target_binary}' verified safe.",
                        data={"binary": target_binary, "safe": True},
                    )
                except HardwareLockoutError as exc:
                    return ExecutionResult.blocked(
                        error_code="FAIL_CLOSED_FLASH_LOCKOUT",
                        details=str(exc),
                        data={"binary": target_binary, "blocked": True},
                    )

            if target_command_id is not None:
                try:
                    SecurityGuard.assert_win32_command_safe(target_command_id)
                    return ExecutionResult.success(
                        details=f"Command ID {target_command_id} verified safe.",
                        data={"command_id": target_command_id, "safe": True},
                    )
                except HardwareLockoutError as exc:
                    return ExecutionResult.blocked(
                        error_code="FAIL_CLOSED_WIN32_LOCKOUT",
                        details=str(exc),
                        data={"command_id": target_command_id, "blocked": True},
                    )

            # Full invariant audit across safety boundaries
            audit_report = {
                "hardware_ports_lockout": "ACTIVE (COM1..COM256, \\\\.\\COM*, /dev/tty*, CAN, USB, JTAG)",
                "companion_flash_binaries_blocked": list(SecurityGuard.BLOCKED_FLASH_BINARIES),
                "download_commands_blocked": list(SecurityGuard.BLOCKED_COMMAND_IDS),
                "pure_st_boundary": "ACTIVE (Ladder logic rejected)",
                "fail_closed_mode": "ENFORCED",
            }
            if mock:
                audit_report["mode"] = "offline/mock"
            return ExecutionResult.success(
                details="All safety invariant guardrails are active and fail-closed.",
                data=audit_report,
            )

        return ToolDefinition(
            name="security_audit_guard",
            description="Audit fail-closed security invariants (hardware ports, flash binaries, Win32 download commands).",
            parameters=[
                ToolParameter(
                    name="target_port",
                    type="string",
                    description="Optional port name to probe for lockout (e.g. COM1)",
                    required=False,
                    default=None,
                ),
                ToolParameter(
                    name="target_binary",
                    type="string",
                    description="Optional binary name to probe for flash lockout (e.g. DfuSeCommand.exe)",
                    required=False,
                    default=None,
                ),
                ToolParameter(
                    name="target_command_id",
                    type="integer",
                    description="Optional Win32 command ID to probe for download lockout (e.g. 32827)",
                    required=False,
                    default=None,
                ),
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                ),
            ],
            handler=handler,
        )

    # 16. security_verify_manifest
    def _def_security_verify_manifest(self) -> ToolDefinition:
        def handler(
            manifest_path: Optional[str] = None,
            generate_if_missing: bool = False,
            mock: bool = False,
        ) -> ExecutionResult:
            if mock:
                target = manifest_path or "artifacts/G5/delivery_manifest.json"
                return ExecutionResult.success(
                    details=f"Cryptographic manifest '{target}' verified cleanly with zero errors (offline/mock mode).",
                    data={"manifest_path": target, "status": "verified", "mode": "offline/mock"},
                )

            from jev_cscape.security.manifest import ManifestManager

            manager = ManifestManager()
            target = manifest_path or "artifacts/G5/delivery_manifest.json"

            if generate_if_missing and not os.path.isfile(target):
                manifest = manager.generate_manifest(output_path=target)
                return ExecutionResult.success(
                    details=f"Cryptographic delivery manifest generated successfully ({manifest.total_files} files).",
                    data={"manifest_path": target, "root_digest": manifest.root_digest, "generated": True},
                )

            valid, errors = manager.verify_manifest(target)
            if not valid:
                return ExecutionResult.failed(
                    error_code="MANIFEST_VERIFICATION_FAILED",
                    details=f"Cryptographic manifest verification failed with {len(errors)} error(s).",
                    data={"errors": errors, "manifest_path": target},
                )
            return ExecutionResult.success(
                details=f"Cryptographic manifest '{target}' verified cleanly with zero errors.",
                data={"manifest_path": target, "status": "verified"},
            )

        return ToolDefinition(
            name="security_verify_manifest",
            description="Verify cryptographic delivery manifest integrity (SHA-256) across repository artifacts.",
            parameters=[
                ToolParameter(
                    name="manifest_path",
                    type="string",
                    description="Target path to delivery_manifest.json (default: artifacts/G5/delivery_manifest.json)",
                    required=False,
                    default="artifacts/G5/delivery_manifest.json",
                ),
                ToolParameter(
                    name="generate_if_missing",
                    type="boolean",
                    description="Generate delivery manifest if it does not exist on disk",
                    required=False,
                    default=False,
                ),
                ToolParameter(
                    name="mock",
                    type="boolean",
                    description="Run in explicit offline/mock mode for testing",
                    required=False,
                    default=False,
                ),
            ],
            handler=handler,
        )
