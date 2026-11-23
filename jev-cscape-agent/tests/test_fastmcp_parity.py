"""Tests for FastMCP Tool Registry and Protocol Server Parity (Gate G6, W025).

Validates:
1. Registration and schema definitions of all 16 canonical tools.
2. Parameter validation and JSON-Schema conversion.
3. Strict 4-state contract execution (success, failed, blocked, inconclusive).
4. Full JSON-RPC 2.0 protocol compliance (initialize, ping, tools/list, tools/call).
5. Zero external MCP runtime package dependencies.
6. Absolute zero references to legacy external MCP packages in source code.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.agents.registry import (
    FastMCPToolRegistry,
    ToolDefinition,
    ToolParameter,
)
from jev_cscape.agents.server import (
    FastMCPServer,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
)


EXPECTED_16_TOOLS = [
    "cscape_doctor",
    "cscape_status",
    "gui_inspect",
    "gui_launch",
    "gui_close",
    "gui_sweep_dialogs",
    "gui_inspect_navigator",
    "gui_compile_error_check",
    "gui_scrape_output",
    "iec_validate_st",
    "iec_convert_st_to_ladder",
    "sim_run_scan_cycles",
    "sim_verify_closed_loop",
    "sim_inspect_registers",
    "security_audit_guard",
    "security_verify_manifest",
]


def test_registry_registers_all_16_canonical_tools() -> None:
    """Verify registry initializes with exactly the 16 designed tools."""
    registry = FastMCPToolRegistry()
    tools = registry.list_tools()
    tool_names = registry.get_tool_names()

    assert len(tools) == 16, f"Expected 16 tools, got {len(tools)}"
    for name in EXPECTED_16_TOOLS:
        assert name in tool_names, f"Missing tool: {name}"
        assert registry.has_tool(name) is True
        tool = registry.get_tool(name)
        assert tool is not None
        assert tool.name == name
        assert len(tool.description) > 0


def test_tool_parameter_and_json_schemas() -> None:
    """Verify input schemas are conformant JSON-Schema objects."""
    registry = FastMCPToolRegistry()
    for tool in registry.list_tools():
        schema = tool.get_input_schema()
        assert schema.get("type") == "object"
        assert "properties" in schema
        assert isinstance(schema["properties"], dict)

        mcp_format = tool.to_mcp_format()
        assert mcp_format["name"] == tool.name
        assert mcp_format["description"] == tool.description
        assert mcp_format["inputSchema"] == schema


def test_cscape_status_execution_contract() -> None:
    """Verify cscape_status execution adheres strictly to 4-state contract."""
    registry = FastMCPToolRegistry()
    res = registry.execute_tool("cscape_status")
    assert isinstance(res, ExecutionResult)
    assert res.status == AgentStatus.SUCCESS
    assert "agent_version" in res.data
    assert "gates_summary" in res.data


def test_cscape_doctor_execution_contract() -> None:
    """Verify cscape_doctor execution returns canonical ExecutionResult."""
    registry = FastMCPToolRegistry()
    res = registry.execute_tool("cscape_doctor")
    assert isinstance(res, ExecutionResult)
    assert res.status in (AgentStatus.SUCCESS, AgentStatus.FAILED)
    assert "os_windows" in res.data
    assert "python_version" in res.data


def test_iec_validate_st_pure_code_and_ladder_rejection() -> None:
    """Verify iec_validate_st accepts pure ST and rejects ladder constructs."""
    registry = FastMCPToolRegistry()

    # Valid pure ST
    pure_st = """
    PROGRAM MainLogic
    VAR
        LevelInput AT %AI1 : INT;
        PumpOutput AT %Q1 : BOOL;
    END_VAR
        PumpOutput := LevelInput > 500;
    END_PROGRAM
    """
    res_valid = registry.execute_tool("iec_validate_st", {"st_code": pure_st})
    assert res_valid.status == AgentStatus.SUCCESS
    assert res_valid.data["name"] == "MainLogic"

    # Forbidden Ladder logic construct
    ladder_st = """
    PROGRAM LadderSnippet
    VAR
        StartBtn : BOOL;
    END_VAR
        ---[ ]--- StartBtn ---( )---
    END_PROGRAM
    """
    res_ladder = registry.execute_tool("iec_validate_st", {"st_code": ladder_st})
    assert res_ladder.status == AgentStatus.FAILED
    assert res_ladder.error_code == "ERR_LADDER_FORBIDDEN"


def test_iec_convert_st_to_ladder_permanently_blocked() -> None:
    """Verify iec_convert_st_to_ladder fails closed with BLOCKED_NATIVE."""
    registry = FastMCPToolRegistry()
    res = registry.execute_tool("iec_convert_st_to_ladder", {"st_code": "x := 1;"})
    assert res.status == AgentStatus.BLOCKED
    assert res.error_code == "BLOCKED_NATIVE"
    assert res.data["conversion_supported"] is False


def test_simulation_tools_execution() -> None:
    """Verify sim_run_scan_cycles and sim_verify_closed_loop execution."""
    registry = FastMCPToolRegistry()

    # 1. sim_run_scan_cycles
    res_sim = registry.execute_tool("sim_run_scan_cycles", {"cycles": 5, "dt_ms": 10.0})
    assert res_sim.status == AgentStatus.SUCCESS
    assert res_sim.data["cycles_requested"] == 5
    assert "telemetry" in res_sim.data

    # 2. sim_verify_closed_loop (specific scenario: emergency_shutdown)
    res_loop = registry.execute_tool("sim_verify_closed_loop", {"scenario": "emergency_shutdown"})
    assert res_loop.status == AgentStatus.SUCCESS
    assert res_loop.data["scenario"] == "emergency_shutdown"
    assert res_loop.data["status"] == "passed"

    # 3. sim_inspect_registers
    res_regs = registry.execute_tool("sim_inspect_registers", {"channel": "%R", "format": "json"})
    assert res_regs.status == AgentStatus.SUCCESS
    assert "count" in res_regs.data


def test_security_audit_guard_tool() -> None:
    """Verify security_audit_guard tool intercepts physical ports, flash tools, and download commands."""
    registry = FastMCPToolRegistry()

    # Port probe
    res_port = registry.execute_tool("security_audit_guard", {"target_port": "COM1"})
    assert res_port.status == AgentStatus.BLOCKED
    assert res_port.error_code == "FAIL_CLOSED_HARDWARE_LOCKOUT"

    # Binary probe
    res_bin = registry.execute_tool("security_audit_guard", {"target_binary": "DfuSeCommand.exe"})
    assert res_bin.status == AgentStatus.BLOCKED
    assert res_bin.error_code == "FAIL_CLOSED_FLASH_LOCKOUT"

    # Download command ID probe
    res_cmd = registry.execute_tool("security_audit_guard", {"target_command_id": 32827})
    assert res_cmd.status == AgentStatus.BLOCKED
    assert res_cmd.error_code == "FAIL_CLOSED_WIN32_LOCKOUT"

    # Full audit
    res_full = registry.execute_tool("security_audit_guard")
    assert res_full.status == AgentStatus.SUCCESS
    assert "hardware_ports_lockout" in res_full.data


def test_gui_offline_mock_tools() -> None:
    """Verify GUI automation tools operate safely in mock mode."""
    registry = FastMCPToolRegistry()

    # 1. gui_launch with prohibited download switch fails closed even in mock mode
    res_launch_blocked = registry.execute_tool("gui_launch", {"project_path": "/download", "mock": True})
    assert res_launch_blocked.status == AgentStatus.BLOCKED
    assert res_launch_blocked.error_code == "FAIL_CLOSED_HARDWARE_LOCKOUT"

    # 2. gui_launch returns mock launch info when mock=True
    res_launch = registry.execute_tool("gui_launch", {"project_path": "TankControl.csp", "mock": True})
    assert res_launch.status == AgentStatus.SUCCESS
    assert res_launch.data["pid"] == 45000
    assert res_launch.data["hwnd"] == 0x10200
    assert res_launch.data["main_window"]["is_visible"] is True
    assert "TankControl.csp" in res_launch.data["main_window"]["title"]

    # 3. gui_inspect returns mock layout when mock=True
    res_inspect = registry.execute_tool("gui_inspect", {"mock": True})
    assert res_inspect.status == AgentStatus.SUCCESS
    assert res_inspect.data["processes_count"] == 1
    assert res_inspect.data["main_window"]["is_visible"] is True
    assert res_inspect.data["desktop_session"]["desktop"] == "Default"

    # 4. gui_sweep_dialogs returns 0 swept dialogs in mock mode
    res_sweep = registry.execute_tool("gui_sweep_dialogs", {"mock": True})
    assert res_sweep.status == AgentStatus.SUCCESS
    assert res_sweep.data["detected_count"] == 0
    assert res_sweep.data["dismissed_count"] == 0
    assert res_sweep.data["dialogs"] == []
    assert res_sweep.data["dismissals"] == []

    # 5. gui_close returns success in mock mode
    res_close = registry.execute_tool("gui_close", {"mock": True})
    assert res_close.status == AgentStatus.SUCCESS
    assert res_close.data["closed"] is True

    # 6. gui_compile_error_check returns 0 errors 0 warnings in mock mode
    res_comp = registry.execute_tool("gui_compile_error_check", {"mock": True})
    assert res_comp.status == AgentStatus.SUCCESS
    assert res_comp.data["error_count"] == 0
    assert res_comp.data["warning_count"] == 0

    # 7. gui_scrape_output returns clean output in mock mode
    res_scrape = registry.execute_tool("gui_scrape_output", {"mock": True})
    assert res_scrape.status == AgentStatus.SUCCESS
    assert res_scrape.data["error_count"] == 0
    assert res_scrape.data["warning_count"] == 0

    # 8. gui_inspect_navigator returns mock tree in mock mode
    res_nav = registry.execute_tool("gui_inspect_navigator", {"mock": True})
    assert res_nav.status == AgentStatus.SUCCESS
    assert res_nav.data["pane_info"]["pane_found"] is True
    assert len(res_nav.data["pane_info"]["root_items"]) > 0


def test_all_16_canonical_tools_mock_execution() -> None:
    """Verify all 16 canonical tools support offline mock execution conforming to 4-state contract."""
    registry = FastMCPToolRegistry()

    assert len(EXPECTED_16_TOOLS) == 16
    for tool_name in EXPECTED_16_TOOLS:
        res = registry.execute_tool(tool_name, {"mock": True})
        assert isinstance(res, ExecutionResult), f"Tool {tool_name} must return ExecutionResult"
        # Strict 4-state contract: status must be one of success, failed, blocked, inconclusive
        assert res.status in (
            AgentStatus.SUCCESS,
            AgentStatus.FAILED,
            AgentStatus.BLOCKED,
            AgentStatus.INCONCLUSIVE,
        ), f"Tool {tool_name} returned non-conforming status: {res.status}"

        # In mock mode, only iec_convert_st_to_ladder must be blocked (BLOCKED_NATIVE);
        # all other 15 tools succeed cleanly in mock mode
        if tool_name == "iec_convert_st_to_ladder":
            assert res.status == AgentStatus.BLOCKED
            assert res.error_code == "BLOCKED_NATIVE"
        else:
            assert res.status == AgentStatus.SUCCESS, (
                f"Tool {tool_name} failed in mock mode: status={res.status}, "
                f"error_code={res.error_code}, details={res.details}"
            )


def test_server_initialize_protocol() -> None:
    """Verify FastMCPServer handles MCP initialize handshake."""
    server = FastMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    }
    resp = server.handle_request(req)
    assert resp is not None
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 1
    assert "result" in resp
    assert resp["result"]["protocolVersion"] == "2024-11-05"
    assert resp["result"]["serverInfo"]["name"] == "jev-cscape-agent"


def test_server_tools_list_protocol() -> None:
    """Verify FastMCPServer tools/list returns exactly the 16 tools."""
    server = FastMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    }
    resp = server.handle_request(req)
    assert resp is not None
    assert resp["id"] == 2
    tools = resp["result"]["tools"]
    assert len(tools) == 16
    tool_names = [t["name"] for t in tools]
    for expected in EXPECTED_16_TOOLS:
        assert expected in tool_names


def test_server_tools_call_protocol() -> None:
    """Verify FastMCPServer tools/call dispatches and returns 4-state contract."""
    server = FastMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "cscape_status",
            "arguments": {},
        },
    }
    resp = server.handle_request(req)
    assert resp is not None
    assert resp["id"] == 3
    result = resp["result"]
    assert result["isError"] is False
    assert len(result["content"]) > 0
    assert result["execution_result"]["status"] == "success"


def test_server_json_rpc_error_handling() -> None:
    """Verify standard JSON-RPC 2.0 error responses."""
    server = FastMCPServer()

    # Parse Error
    resp_parse = server.handle_message("{broken json")
    assert resp_parse is not None
    parsed = json.loads(resp_parse)
    assert parsed["error"]["code"] == PARSE_ERROR

    # Invalid Request (missing jsonrpc 2.0)
    resp_inv = server.handle_request({"id": 10, "method": "ping"})
    assert resp_inv is not None
    assert resp_inv["error"]["code"] == INVALID_REQUEST

    # Method Not Found
    resp_nometh = server.handle_request({"jsonrpc": "2.0", "id": 11, "method": "non_existent_method"})
    assert resp_nometh is not None
    assert resp_nometh["error"]["code"] == METHOD_NOT_FOUND


def test_server_notifications_handling() -> None:
    """Verify JSON-RPC 2.0 notifications lacking 'id' return None without errors or exceptions."""
    server = FastMCPServer()

    # 1. Standard notifications return None
    assert server.handle_request({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert server.handle_request({"jsonrpc": "2.0", "method": "ping"}) is None
    assert server.handle_request({"jsonrpc": "2.0", "method": "tools/list"}) is None
    assert server.handle_request({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "cscape_status", "arguments": {}},
    }) is None
    assert server.handle_request({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    }) is None

    # 2. Notifications with errors return None rather than raising exceptions or returning error dicts
    # Missing/invalid jsonrpc
    assert server.handle_request({"method": "ping"}) is None
    assert server.handle_request({"jsonrpc": "1.0", "method": "ping"}) is None
    # Invalid method type
    assert server.handle_request({"jsonrpc": "2.0", "method": 12345}) is None
    # Invalid params type
    assert server.handle_request({"jsonrpc": "2.0", "method": "ping", "params": "not-a-dict"}) is None
    # Non-existent method
    assert server.handle_request({"jsonrpc": "2.0", "method": "non_existent_method"}) is None
    # Tool call failure / exception inside execution
    assert server.handle_request({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": 999},  # name must be string
    }) is None

    # 3. Via handle_message
    msg_notify = '{"jsonrpc": "2.0", "method": "ping"}'
    assert server.handle_message(msg_notify) is None

    msg_notify_err = '{"jsonrpc": "2.0", "method": "non_existent"}'
    assert server.handle_message(msg_notify_err) is None


def test_server_empty_message_and_whitespace_error_handling() -> None:
    """Verify handle_message returns standard JSON-RPC 2.0 PARSE_ERROR for empty/whitespace input."""
    server = FastMCPServer()

    # Empty string
    resp_empty = server.handle_message("")
    assert resp_empty is not None
    data_empty = json.loads(resp_empty)
    assert data_empty["jsonrpc"] == "2.0"
    assert data_empty["id"] is None
    assert data_empty["error"]["code"] == PARSE_ERROR

    # Whitespace only string
    resp_ws = server.handle_message("   \n\t  ")
    assert resp_ws is not None
    data_ws = json.loads(resp_ws)
    assert data_ws["jsonrpc"] == "2.0"
    assert data_ws["id"] is None
    assert data_ws["error"]["code"] == PARSE_ERROR

    # Non-string input
    resp_nonstr = server.handle_message(None)  # type: ignore[arg-type]
    assert resp_nonstr is not None
    data_nonstr = json.loads(resp_nonstr)
    assert data_nonstr["jsonrpc"] == "2.0"
    assert data_nonstr["id"] is None
    assert data_nonstr["error"]["code"] == INVALID_REQUEST


def test_server_batch_arrays_handling() -> None:
    """Verify handle_message gracefully handles empty batch arrays, mixed batches, and notification batches."""
    server = FastMCPServer()

    # 1. Empty batch array returns standard JSON-RPC 2.0 INVALID_REQUEST error
    resp_empty_batch = server.handle_message("[]")
    assert resp_empty_batch is not None
    data_empty_batch = json.loads(resp_empty_batch)
    assert data_empty_batch["jsonrpc"] == "2.0"
    assert data_empty_batch["id"] is None
    assert data_empty_batch["error"]["code"] == INVALID_REQUEST

    resp_ws_empty_batch = server.handle_message("   [  ]   ")
    assert resp_ws_empty_batch is not None
    data_ws_empty = json.loads(resp_ws_empty_batch)
    assert data_ws_empty["error"]["code"] == INVALID_REQUEST

    # 2. Batch with invalid non-dict items
    resp_invalid_items = server.handle_message("[1, 2]")
    assert resp_invalid_items is not None
    data_invalid_items = json.loads(resp_invalid_items)
    assert isinstance(data_invalid_items, list)
    assert len(data_invalid_items) == 2
    assert all(item["error"]["code"] == INVALID_REQUEST for item in data_invalid_items)

    # 3. Batch containing only notifications returns None (no response)
    batch_notifications = json.dumps([
        {"jsonrpc": "2.0", "method": "ping"},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ])
    assert server.handle_message(batch_notifications) is None

    # 4. Batch containing mixed notifications and requests returns responses only for requests
    batch_mixed = json.dumps([
        {"jsonrpc": "2.0", "method": "ping"},  # notification
        {"jsonrpc": "2.0", "id": 42, "method": "ping"},  # request
    ])
    resp_mixed = server.handle_message(batch_mixed)
    assert resp_mixed is not None
    data_mixed = json.loads(resp_mixed)
    assert isinstance(data_mixed, list)
    assert len(data_mixed) == 1
    assert data_mixed[0]["id"] == 42
    assert "result" in data_mixed[0]


def test_zero_external_mcp_runtime_dependency() -> None:
    """Verify agents module has ZERO external MCP runtime dependencies."""
    from jev_cscape.agents import registry, server
    # Assert neither module imports any external 'mcp' top-level package
    import sys
    assert "mcp" not in sys.modules or sys.modules["mcp"] is None, "External 'mcp' package should not be loaded."


def test_zero_references_to_legacy_horner_cscape_mcp() -> None:
    """Verify absolutely zero references to legacy external horner-cscape-mcp package in agents."""
    agents_dir = Path(__file__).parent.parent / "src" / "jev_cscape" / "agents"
    banned_token = "horner" + "-cscape-" + "mcp"

    for file_path in agents_dir.glob("*.py"):
        content = file_path.read_text(encoding="utf-8").lower()
        assert banned_token not in content, f"Banned package reference found in {file_path}"
