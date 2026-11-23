# Multi-Agent Hierarchy & FastMCP Tool Parity (Gate G6, W025)

## 1. Overview & Architectural Boundaries

Work Package **W025** implements the **FastMCP Tool Registry** and **JSON-RPC 2.0 Protocol Server** for the JEV Cscape Agent architecture.
This implementation satisfies the following non-negotiable invariants:
1. **Zero External MCP Runtime Dependencies**: Fully self-contained implementation with standard Python libraries (`json`, `sys`, `typing`, `pydantic`). Zero external `mcp` package imports.
2. **Absolute Clean Room Separation**: Zero references to or dependencies upon legacy external MCP packages (`horner-cscape-mcp`).
3. **Strict 4-State Engineering Contract**: Every tool execution strictly returns an `ExecutionResult` envelope:
   ```json
   {
     "status": "success | failed | blocked | inconclusive",
     "error_code": "STRING_OR_NULL",
     "details": "Factual description of outcome",
     "data": {}
   }
   ```
4. **Fail-Closed Hardware & Flash Safety**: Download commands (`32827`, `33149`), physical communication ports (`COM1..COM256`), companion flasher binaries (`DfuSeCommand.exe`, `PGMUpdateUtility.exe`, `STMFlashLoader.exe`, `WinJTAG.exe`), and ST->LD conversion (`BLOCKED_NATIVE`) fail closed with `status: blocked`.

---

## 2. The 16 Canonical Gate G6 Tools

| # | Tool Identifier | Layer | Purpose | Contract Guard / Failure Mode |
|---|---|---|---|---|
| 1 | `cscape_doctor` | Environment | Verifies OS platform, Python version, Cscape executable path, and safety locks | `CSCAPE_EXE_NOT_FOUND` if executable absent |
| 2 | `cscape_status` | Orchestration | Retrieves active gate milestones (`G0..G12`) and operational backlog | Always succeeds with structured ledger |
| 3 | `gui_inspect` | GUI Automation | Probes Cscape main window HWND and modal popups on `winsta0\Default` | Fail-closed if process not running |
| 4 | `gui_launch` | GUI Automation | Launches Cscape 10.2 within interactive session with optional project | Blocks on prohibited switches (`FAIL_CLOSED_HARDWARE_LOCKOUT`) |
| 5 | `gui_close` | GUI Automation | Cleanly closes running Cscape process via `WM_CLOSE` | Returns teardown status |
| 6 | `gui_sweep_dialogs` | GUI Automation | Detects and dismisses modal dialogs (`#32770`, Tip of the Day) | Audits dismissed window handles |
| 7 | `gui_inspect_navigator` | GUI Automation | Inspects Cscape Project Navigator pane (`SysTreeView32`, ID 300) | Traverses observed UIA tree nodes |
| 8 | `gui_compile_error_check` | GUI Automation | Dispatches `ID_PROGRAM_ERRORCHECK` (`32826`) clean compile check | Scrapes 0 errors / 0 warnings |
| 9 | `gui_scrape_output` | GUI Automation | Scrapes diagnostic text from MFC ListBox (`372`) in Output Window (`45011`) | Parses line count and error/warning counts |
| 10 | `iec_validate_st` | IEC 61131-3 | Validates pure Structured Text AST and rejects ladder constructs | Fails closed on ladder with `ERR_LADDER_FORBIDDEN` |
| 11 | `iec_convert_st_to_ladder` | IEC 61131-3 | Translates Structured Text to Ladder logic in Cscape | Permanently blocked (`BLOCKED_NATIVE: DOCUMENT_ONLY`) |
| 12 | `sim_run_scan_cycles` | Simulation | Executes deterministic in-memory scan cycle simulation engine | Returns virtual elapsed time & cycle telemetry |
| 13 | `sim_verify_closed_loop` | Simulation | Runs closed-loop validation matrix across the 5 canonical scenarios | Verifies setpoint regulation & ESD de-energization |
| 14 | `sim_inspect_registers` | Simulation | Inspects Horner OCS register space (`%R`, `%I`, `%Q`, `%AI`, `%AQ`, `%SR`, `%S`) | Formats structured register values |
| 15 | `security_audit_guard` | Safety Guard | Audits fail-closed locks on COM ports, flasher tools, and download commands | Probed targets return `FAIL_CLOSED_*` |
| 16 | `security_verify_manifest` | Security Guard | Verifies cryptographic SHA-256 delivery manifest across artifacts | Reports `MANIFEST_VERIFICATION_FAILED` if tampered |

---

## 3. FastMCPServer Protocol Conformance

`FastMCPServer` implements standard JSON-RPC 2.0 communication supporting:
- `initialize`: Returns server name (`jev-cscape-agent`), version, protocol version (`2024-11-05`), and tool capabilities.
- `ping`: Lightweight liveness check.
- `tools/list`: Returns JSON schemas for all 16 tools conforming to standard MCP `inputSchema` specifications.
- `tools/call`: Dispatches to `FastMCPToolRegistry.execute_tool`, returning standard MCP `content` blocks alongside the canonical `execution_result` payload.
- Standard JSON-RPC 2.0 Error Codes:
  - `-32700`: Parse error
  - `-32600`: Invalid Request
  - `-32601`: Method not found
  - `-32602`: Invalid params
  - `-32603`: Internal error
- `run_stdio()`: Lightweight, zero-dependency stream processor for stdio pipes.

---

## 4. Verification Evidence

All 15 test suites in [test_fastmcp_parity.py](file:///C:/HornerAI/jev-cscape-agent/tests/test_fastmcp_parity.py) pass deterministically:
- 16 tools registered with valid JSON-Schema parameter specifications.
- Strict 4-state contract verified across success, failed, and blocked scenarios.
- ST->LD conversion verified permanently blocked with `BLOCKED_NATIVE`.
- Security guard verified actively blocking COM ports, flash tools, and download commands.
- Zero external MCP runtime imports confirmed.
- Zero references to legacy external MCP packages confirmed.
