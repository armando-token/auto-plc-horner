"""FastMCP Standalone JSON-RPC 2.0 Server.

Work Package: W025 (Gate G6)
Classification: PRODUCTION_READY

Implements zero-dependency JSON-RPC 2.0 protocol handling for MCP tools:
- tools/list
- tools/call
- initialize
- ping
conforming strictly to the 4-state engineering contract.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional, TextIO

from jev_cscape import __version__
from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.agents.registry import FastMCPToolRegistry


# Standard JSON-RPC 2.0 Error Codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class FastMCPServer:
    """Standalone JSON-RPC 2.0 server exposing FastMCP tool registry."""

    PROTOCOL_VERSION = "2024-11-05"
    SERVER_NAME = "jev-cscape-agent"

    def __init__(self, registry: Optional[FastMCPToolRegistry] = None) -> None:
        self.registry = registry or FastMCPToolRegistry()

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single JSON-RPC 2.0 request dictionary and return response dict.

        Per JSON-RPC 2.0 specification:
        - A notification is a Request object without an 'id' member.
        - The server MUST NOT reply to a Notification (must return None),
          even if errors (invalid request, method not found, invalid params, internal error) occur.
        """
        if not isinstance(request, dict):
            return self._build_error(None, INVALID_REQUEST, "Invalid Request: expected JSON object.")

        # Notification check: requests lacking an 'id' field are notifications
        is_notification = ("id" not in request)
        req_id = request.get("id")

        # Validate JSON-RPC 2.0 envelope
        if request.get("jsonrpc") != "2.0":
            if is_notification:
                return None
            return self._build_error(req_id, INVALID_REQUEST, "Invalid Request: 'jsonrpc' must be '2.0'.")

        method = request.get("method")
        if not isinstance(method, str):
            if is_notification:
                return None
            return self._build_error(req_id, INVALID_REQUEST, "Invalid Request: 'method' must be a string.")

        params = request.get("params") or {}
        if not isinstance(params, dict):
            if is_notification:
                return None
            return self._build_error(req_id, INVALID_PARAMS, "Invalid params: must be a JSON object.")

        # Dispatch method
        try:
            if method == "initialize":
                res = self._handle_initialize(params)
                return None if is_notification else self._build_result(req_id, res)

            elif method == "notifications/initialized":
                # MCP client initialized notification
                return None

            elif method == "ping":
                return None if is_notification else self._build_result(req_id, {})

            elif method == "tools/list":
                res = self._handle_tools_list(params)
                return None if is_notification else self._build_result(req_id, res)

            elif method == "tools/call":
                res = self._handle_tools_call(params)
                return None if is_notification else self._build_result(req_id, res)

            else:
                if is_notification:
                    return None
                return self._build_error(req_id, METHOD_NOT_FOUND, f"Method not found: '{method}'.")

        except Exception as exc:
            if is_notification:
                return None
            return self._build_error(req_id, INTERNAL_ERROR, f"Internal server error: {exc}")

    def handle_message(self, message_str: str) -> Optional[str]:
        """Parse raw JSON message string, process it, and return response JSON string."""
        if not isinstance(message_str, str):
            err_resp = self._build_error(None, INVALID_REQUEST, "Invalid Request: message must be a string.")
            return json.dumps(err_resp)

        stripped = message_str.strip()
        if not stripped:
            err_resp = self._build_error(None, PARSE_ERROR, "Parse error: empty message or whitespace.")
            return json.dumps(err_resp)

        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            err_resp = self._build_error(None, PARSE_ERROR, f"Parse error: {exc}")
            return json.dumps(err_resp)

        if isinstance(payload, list):
            # Batch request
            if not payload:
                err_resp = self._build_error(None, INVALID_REQUEST, "Invalid Request: batch array cannot be empty.")
                return json.dumps(err_resp)

            responses = []
            for item in payload:
                if isinstance(item, dict):
                    resp = self.handle_request(item)
                    if resp is not None:
                        responses.append(resp)
                else:
                    responses.append(
                        self._build_error(None, INVALID_REQUEST, "Invalid Request: batch item must be a JSON object.")
                    )
            return json.dumps(responses) if responses else None
        elif isinstance(payload, dict):
            resp = self.handle_request(payload)
            return json.dumps(resp) if resp is not None else None
        else:
            err_resp = self._build_error(None, INVALID_REQUEST, "Invalid Request: expected JSON object or array.")
            return json.dumps(err_resp)

    # -------------------------------------------------------------------------
    # Internal Method Handlers
    # -------------------------------------------------------------------------

    def _handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP protocol initialize handshake."""
        return {
            "protocolVersion": self.PROTOCOL_VERSION,
            "capabilities": {
                "tools": {
                    "listChanged": False,
                }
            },
            "serverInfo": {
                "name": self.SERVER_NAME,
                "version": __version__,
            },
        }

    def _handle_tools_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP tools/list method returning 16 Gate G6 tools."""
        return {
            "tools": self.registry.to_mcp_tools()
        }

    def _handle_tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP tools/call method executing a tool conforming to 4-state contract."""
        tool_name = params.get("name")
        if not tool_name or not isinstance(tool_name, str):
            raise ValueError("Tool call requires parameter 'name' as a string.")

        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            raise ValueError("Tool arguments must be a dictionary.")

        exec_res: ExecutionResult = self.registry.execute_tool(tool_name, arguments)
        is_error = exec_res.status in (AgentStatus.FAILED, AgentStatus.BLOCKED)

        # Build standard MCP tool call payload alongside canonical ExecutionResult
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(exec_res.model_dump(), indent=2),
                }
            ],
            "isError": is_error,
            "execution_result": exec_res.model_dump(),
        }

    # -------------------------------------------------------------------------
    # Helper Envelopes
    # -------------------------------------------------------------------------

    @staticmethod
    def _build_result(req_id: Any, result: Any) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result,
        }

    @staticmethod
    def _build_error(req_id: Any, code: int, message: str, data: Optional[Any] = None) -> Dict[str, Any]:
        err_body: Dict[str, Any] = {
            "code": code,
            "message": message,
        }
        if data is not None:
            err_body["data"] = data
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": err_body,
        }

    def run_stdio(self, input_stream: Optional[TextIO] = None, output_stream: Optional[TextIO] = None) -> None:
        """Run line-by-line stdio server loop."""
        in_s = input_stream or sys.stdin
        out_s = output_stream or sys.stdout

        for line in in_s:
            resp_str = self.handle_message(line)
            if resp_str:
                out_s.write(resp_str + "\n")
                out_s.flush()
