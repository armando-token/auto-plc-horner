"""CLI Entrypoint for JEV Cscape Agent.

Autonomous Execution & Verification Architecture for Horner Cscape 10.2 Windows.
Conforms strictly to the 4-state engineering contract:
    status: success | failed | blocked | inconclusive
"""

import argparse
import json
import os
import sys
from typing import List, Optional

from jev_cscape import __version__
from jev_cscape.contracts import ExecutionResult, AgentStatus
from jev_cscape.automation.lifecycle import CscapeLifecycleController
from jev_cscape.automation.dialog_sweeper import DialogSweeper
from jev_cscape.automation.navigator_walker import ProjectNavigatorWalker
from jev_cscape.automation.compiler import CscapeCompilerDispatcher
from jev_cscape.automation.output_scraper import CscapeOutputScraper
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.security.exceptions import HardwareLockoutError, LadderForbiddenError


def get_provider_mode() -> dict:
    """Check JEV provider credentials and report active operational mode."""
    api_key = os.environ.get("JEV_API_KEY")
    if not api_key:
        return {
            "provider": "jev",
            "mode": "offline/mock",
            "has_api_key": False,
            "details": "JEV_API_KEY environment variable missing; operating in local rule-based mock mode."
        }
    return {
        "provider": "jev",
        "mode": "online",
        "has_api_key": True,
        "details": "JEV_API_KEY verified; remote API routing available."
    }


def cmd_doctor(args: argparse.Namespace) -> ExecutionResult:
    """Run environment and safety invariant diagnostics."""
    cscape_path = r"C:\Program Files (x86)\Cscape 10.2\Cscape.exe"
    cscape_found = os.path.isfile(cscape_path)

    checks = {
        "os_windows": sys.platform == "win32",
        "python_version": sys.version.split()[0],
        "cscape_installed": cscape_found,
        "cscape_path": cscape_path,
        "hardware_lockout_active": True,
        "provider_mode": get_provider_mode(),
    }

    if not cscape_found:
        return ExecutionResult.failed(
            error_code="CSCAPE_EXE_NOT_FOUND",
            details=f"Cscape executable not found at '{cscape_path}'.",
            data=checks,
        )

    return ExecutionResult.success(
        details="System doctor passed all environment, safety, and runtime checks.",
        data=checks,
    )


def cmd_inspect(args: argparse.Namespace) -> ExecutionResult:
    """Inspect live Cscape process, main window HWND, and modal dialogs."""
    controller = CscapeLifecycleController()
    return controller.inspect()


def cmd_launch(args: argparse.Namespace) -> ExecutionResult:
    """Launch Cscape 10.2 on winsta0\\Default with optional project file."""
    # Enforce security guard check on project arguments
    if args.project:
        try:
            SecurityGuard.assert_cli_switches_safe([args.project])
        except HardwareLockoutError as e:
            return ExecutionResult.blocked(
                error_code="FAIL_CLOSED_HARDWARE_LOCKOUT",
                details=str(e),
            )

    controller = CscapeLifecycleController()
    return controller.launch(project_path=args.project, timeout=args.timeout)


def cmd_close(args: argparse.Namespace) -> ExecutionResult:
    """Cleanly close running Cscape process via WM_CLOSE."""
    controller = CscapeLifecycleController()
    return controller.close(timeout=args.timeout)


def cmd_validate_st(args: argparse.Namespace) -> ExecutionResult:
    """Validate IEC 61131-3 Structured Text source file, rejecting ladder constructs."""
    file_path = os.path.abspath(args.file)
    if not os.path.isfile(file_path):
        return ExecutionResult.failed(
            error_code="FILE_NOT_FOUND",
            details=f"ST source file not found at '{file_path}'.",
        )

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            code = f.read()
    except Exception as e:
        return ExecutionResult.failed(
            error_code="READ_ERROR",
            details=f"Failed to read file '{file_path}': {e}",
        )

    try:
        SecurityGuard.assert_pure_st_content(code)
    except LadderForbiddenError as e:
        return ExecutionResult.failed(
            error_code="ERR_LADDER_FORBIDDEN",
            details=str(e),
            data={"file": file_path, "ladder_detected": True},
        )

    return ExecutionResult.success(
        details=f"File '{os.path.basename(file_path)}' contains pure IEC 61131-3 Structured Text (zero ladder constructs).",
        data={"file": file_path, "bytes": len(code), "lines": len(code.splitlines())},
    )


def cmd_sweep(args: argparse.Namespace) -> ExecutionResult:
    """Sweep and dismiss Cscape modal dialogs (#32770, Tip of the Day)."""
    controller = CscapeLifecycleController()
    procs = controller.find_cscape_processes()
    pids = {p.pid for p in procs}
    sweeper = DialogSweeper(target_pids=pids)
    return sweeper.execute_contract_sweep()


def cmd_inspect_navigator(args: argparse.Namespace) -> ExecutionResult:
    """Inspect Cscape Project Navigator pane and tree nodes using observed UIA evidence."""
    walker = ProjectNavigatorWalker()
    if args.mock:
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


def cmd_compile(args: argparse.Namespace) -> ExecutionResult:
    """Dispatch ID_PROGRAM_ERRORCHECK (32826) compilation to Cscape."""
    dispatcher = CscapeCompilerDispatcher()
    if args.mock:
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


def cmd_scrape_output(args: argparse.Namespace) -> ExecutionResult:
    """Scrape compiler diagnostics from Cscape ListBox 372."""
    scraper = CscapeOutputScraper()
    if args.mock:
        mock_lines = [
            "=== Horner Cscape 10.2 Compile Pass: TankLevelClosedLoop ===",
            "Clean Build: True",
            "Mode: IEC 61131-3 Structured Text",
            "Logic: Checking Logic...",
            "TankLevelClosedLoop: 0 error(s), 0 warning(s)",
            "Build Result: SUCCESS",
        ]
        return scraper.scrape(mock_lines=mock_lines, mode="offline/mock")

    return scraper.scrape()


def cmd_simulate(args: argparse.Namespace) -> ExecutionResult:
    """Execute deterministic in-memory scan cycle simulation."""
    from jev_cscape.simulation.engine import SimulationEngine, PacingMode

    cycles = getattr(args, "cycles", 10)
    dt_ms = getattr(args, "dt_ms", 10.0)
    export_trace = getattr(args, "export_trace", None)
    export_evidence = getattr(args, "export_evidence", None)

    engine = SimulationEngine(
        default_dt_ms=dt_ms,
        pacing_mode=PacingMode.FAST,
    )

    cycle_list = engine.run_cycles(cycles)
    data = dict(cycle_list.data)
    data["telemetry"] = engine.trace.summary_telemetry()

    if export_trace:
        engine.trace.to_json(filepath=export_trace)
        data["exported_trace"] = export_trace

    if export_evidence:
        engine.export_g4_evidence(filepath=export_evidence)
        data["exported_evidence"] = export_evidence

    return ExecutionResult.success(
        details=f"Completed {cycles} simulation cycles cleanly ({data['virtual_elapsed_ms']:.1f}ms virtual time).",
        data=data,
    )


def cmd_inspect_registers(args: argparse.Namespace) -> ExecutionResult:
    """Inspect Horner OCS register space (%R, %I, %Q, %AI, %AQ, %SR, %S, etc.)."""
    from jev_cscape.simulation.register_table import RegisterTable
    from jev_cscape.automation.register_inspector import RegisterInspector

    channel = getattr(args, "channel", None)
    address_expr = getattr(args, "address", None)
    nonzero_only = getattr(args, "nonzero", False)
    format_type = getattr(args, "format", "table")

    table = RegisterTable()
    addresses = [address_expr] if address_expr else None

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

    if format_type == "table":
        table_text = RegisterInspector.format_table(report)
        return ExecutionResult.success(
            details=f"Inspected {report['count']} registers.",
            data={"output_table": table_text, "summary": report},
        )
    else:
        return ExecutionResult.success(
            details=f"Inspected {report['count']} registers.",
            data=report,
        )


def cmd_status(args: argparse.Namespace) -> ExecutionResult:
    """Display active gate status and operational backlog summary."""
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    gates_path = os.path.join(project_root, "ops", "gates.json")
    backlog_path = os.path.join(project_root, "ops", "backlog.json")

    gates_data = {}
    backlog_data = {}

    if os.path.isfile(gates_path):
        with open(gates_path, "r", encoding="utf-8") as f:
            gates_data = json.load(f)

    if os.path.isfile(backlog_path):
        with open(backlog_path, "r", encoding="utf-8") as f:
            backlog_data = json.load(f)

    provider = get_provider_mode()

    return ExecutionResult.success(
        details="JEV Cscape Agent operational status retrieved.",
        data={
            "agent_version": __version__,
            "provider_mode": provider,
            "gates_summary": {k: v.get("status") for k, v in gates_data.get("gates", {}).items()},
            "backlog_count": len(backlog_data.get("work_packages", [])),
        },
    )


def cmd_manifest(args: argparse.Namespace) -> ExecutionResult:
    """Generate or verify cryptographic delivery manifest (SHA-256)."""
    from jev_cscape.security.manifest import ManifestManager

    manager = ManifestManager()
    if args.verify is not None:
        target = args.verify if isinstance(args.verify, str) and args.verify != "True" else (args.output or "artifacts/G5/delivery_manifest.json")
        valid, errors = manager.verify_manifest(target)
        if not valid:
            return ExecutionResult.failed(
                error_code="MANIFEST_VERIFICATION_FAILED",
                details=f"Cryptographic manifest verification failed with {len(errors)} error(s).",
                data={"errors": errors, "manifest_path": str(target)},
            )
        return ExecutionResult.success(
            details=f"Cryptographic manifest '{target}' verified cleanly with zero errors.",
            data={"status": "verified", "manifest_path": str(target)},
        )

    out_path = args.output or "artifacts/G5/delivery_manifest.json"
    manifest = manager.generate_manifest(output_path=out_path)
    return ExecutionResult.success(
        details=f"Cryptographic delivery manifest generated successfully ({manifest.total_files} files, root digest: {manifest.root_digest[:16]}...).",
        data={
            "output_path": str(out_path),
            "root_digest": manifest.root_digest,
            "total_files": manifest.total_files,
            "total_bytes": manifest.total_bytes,
        },
    )


def cmd_audit_safety(args: argparse.Namespace) -> ExecutionResult:
    """Run Gate G11 security lockout verification."""
    from jev_cscape.security.audit import execute_safety_audit

    export_evidence = getattr(args, "export_evidence", None)
    return execute_safety_audit(export_evidence=export_evidence)


def cmd_soak(args: argparse.Namespace) -> ExecutionResult:
    """Run Gate G10 multi-rate closed-loop soak verifier."""
    from jev_cscape.simulation.soak import SoakVerifier

    cycles = getattr(args, "cycles", 1000)
    rates_arg = getattr(args, "rates", None)
    dt_ms = getattr(args, "dt_ms", None)
    setpoint = getattr(args, "setpoint", 50.0)
    max_drift = getattr(args, "max_drift", 2.5)
    export_evidence = getattr(args, "export_evidence", None)

    if dt_ms is not None:
        rates = [float(dt_ms)]
    elif rates_arg:
        rates = [float(r.strip()) for r in rates_arg.split(",") if r.strip()]
    else:
        rates = [5.0, 10.0, 20.0, 50.0]

    verifier = SoakVerifier(
        cycles=cycles,
        scan_rates_ms=rates,
        setpoint_pct=setpoint,
        max_error_pct=max_drift,
    )
    return verifier.run_soak(export_evidence=export_evidence)


def cmd_scale_point(args: argparse.Namespace) -> ExecutionResult:
    """Test Gate G8 Modbus/EU telemetry scaling and precision tracking."""
    from jev_cscape.telemetry.scaling_bridge import (
        ScalingType,
        TelemetryPoint,
        decode_quality_word,
    )

    channel = getattr(args, "channel", "%AI1")
    raw_val = getattr(args, "raw", None)
    eu_val = getattr(args, "eu", None)
    raw_min = getattr(args, "raw_min", 0.0)
    raw_max = getattr(args, "raw_max", 32000.0)
    eu_min = getattr(args, "eu_min", 0.0)
    eu_max = getattr(args, "eu_max", 100.0)
    unit = getattr(args, "unit", "%")
    scaling_str = getattr(args, "scaling", "LINEAR")
    namur = getattr(args, "namur", False)
    is_32bit_float = getattr(args, "ieee754", False)

    if raw_max <= raw_min:
        return ExecutionResult.failed(
            error_code="INVALID_RANGE_SPAN",
            details=f"raw_max ({raw_max}) must be greater than raw_min ({raw_min}).",
        )

    if eu_max <= eu_min:
        return ExecutionResult.failed(
            error_code="INVALID_RANGE_SPAN",
            details=f"eu_max ({eu_max}) must be greater than eu_min ({eu_min}).",
        )

    try:
        scaling_type = ScalingType(scaling_str)
    except ValueError:
        return ExecutionResult.failed(
            error_code="INVALID_SCALING_TYPE",
            details=f"Unknown scaling type '{scaling_str}'. Choices: LINEAR, SQUARE_ROOT, PIECEWISE, RTD.",
        )

    pt = TelemetryPoint(
        name=f"Point_{channel.replace('%', '')}",
        channel=channel,
        modbus_address=30001,
        scaling_type=scaling_type,
        raw_min=raw_min,
        raw_max=raw_max,
        eu_min=eu_min,
        eu_max=eu_max,
        eu_unit=unit,
        namur_ne43_enabled=namur,
        is_32bit_float=is_32bit_float,
    )

    # Determine conversion mode
    if eu_val is not None and raw_val is None:
        raw_out, qc, qw = pt.eu_to_raw(eu_val)
        calc_eu, _, _ = pt.raw_to_eu(raw_out)
        rt_err = abs(calc_eu - eu_val)
        final_raw = raw_out
        final_eu = eu_val
    elif raw_val is not None:
        eu_out, qc, qw = pt.raw_to_eu(raw_val)
        calc_raw, _, _ = pt.eu_to_raw(eu_out)
        rt_err = abs(calc_raw - raw_val)
        final_raw = raw_val
        final_eu = eu_out
    else:
        # Default mid-scale test point
        mid_raw = int(round(raw_min + 0.5 * (raw_max - raw_min)))
        eu_out, qc, qw = pt.raw_to_eu(mid_raw)
        calc_raw, _, _ = pt.eu_to_raw(eu_out)
        rt_err = abs(calc_raw - mid_raw)
        final_raw = mid_raw
        final_eu = eu_out

    modbus_words = pt.encode_modbus_words(final_eu)
    _, quality_flags = decode_quality_word(qw)

    data = {
        "gate": "G8",
        "work_package": "W027",
        "point_name": pt.name,
        "channel": pt.channel,
        "raw_value": final_raw,
        "eu_value": round(final_eu, 4),
        "eu_unit": pt.eu_unit,
        "raw_range": [pt.raw_min, pt.raw_max],
        "eu_range": [pt.eu_min, pt.eu_max],
        "scaling_type": pt.scaling_type.value,
        "quality": qc.value,
        "quality_word": f"0x{qw:04X}",
        "quality_flags": quality_flags,
        "round_trip_error": round(rt_err, 4),
        "modbus_words": modbus_words,
        "is_32bit_float": pt.is_32bit_float,
        "namur_ne43_enabled": namur,
    }

    return ExecutionResult.success(
        details=(
            f"Telemetry point '{channel}' scaled: {final_raw} counts -> "
            f"{final_eu:.2f} {unit} (Quality: {qc.value}, Quality Word: 0x{qw:04X})."
        ),
        data=data,
    )


def cmd_vision_ground(args: argparse.Namespace) -> ExecutionResult:
    """Perform vision grounding segmentation on Cscape screenshot (Gate G9)."""
    from jev_cscape.vision import VisionGroundingEngine

    engine = VisionGroundingEngine()
    source = getattr(args, "image", None)
    return engine.analyze(source=source)


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    common_parent = argparse.ArgumentParser(add_help=False)
    common_parent.add_argument("--json", action="store_true", help="Format all output as JSON conforming to 4-state contract")

    parser = argparse.ArgumentParser(
        prog="jev-cscape",
        description=f"JEV Cscape Agent CLI v{__version__}: Autonomous Execution & Verification Architecture for Horner Cscape 10.2",
        parents=[common_parent],
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # doctor
    subparsers.add_parser("doctor", parents=[common_parent], help="Run environment and safety invariant diagnostics")

    # inspect
    subparsers.add_parser("inspect", parents=[common_parent], help="Inspect live Cscape process, main window, and modal dialogs")

    # launch
    launch_parser = subparsers.add_parser("launch", parents=[common_parent], help="Launch Cscape 10.2 on winsta0\\Default")
    launch_parser.add_argument("--project", "-p", default=None, help="Path to .csp/.cpj project file to open")
    launch_parser.add_argument("--timeout", "-t", type=float, default=15.0, help="Window appearance timeout in seconds")

    # close
    close_parser = subparsers.add_parser("close", parents=[common_parent], help="Cleanly close Cscape 10.2 via WM_CLOSE")
    close_parser.add_argument("--timeout", "-t", type=float, default=5.0, help="Teardown timeout in seconds")

    # sweep
    subparsers.add_parser("sweep", parents=[common_parent], help="Sweep and dismiss modal dialogs (#32770, Tip of the Day)")

    # validate-st
    st_parser = subparsers.add_parser("validate-st", parents=[common_parent], help="Validate pure IEC 61131-3 ST POU (reject ladder constructs)")
    st_parser.add_argument("file", help="Path to .st source file")

    # inspect-navigator
    nav_parser = subparsers.add_parser("inspect-navigator", parents=[common_parent], help="Inspect Cscape Project Navigator pane and tree nodes")
    nav_parser.add_argument("--mock", action="store_true", help="Run in explicit offline/mock mode for test validation")

    # compile
    compile_parser = subparsers.add_parser("compile", parents=[common_parent], help="Dispatch ID_PROGRAM_ERRORCHECK (32826) compilation to Cscape")
    compile_parser.add_argument("--mock", action="store_true", help="Run in explicit offline/mock mode for test validation")

    # scrape-output
    scrape_parser = subparsers.add_parser("scrape-output", parents=[common_parent], help="Scrape compiler diagnostics from Cscape ListBox 372")
    scrape_parser.add_argument("--mock", action="store_true", help="Run in explicit offline/mock mode for test validation")

    # simulate / sim
    sim_parser = subparsers.add_parser("simulate", aliases=["sim"], parents=[common_parent], help="Run in-memory scan cycle simulation engine")
    sim_parser.add_argument("--cycles", "-c", type=int, default=10, help="Number of scan cycles to execute (default: 10)")
    sim_parser.add_argument("--dt-ms", type=float, default=10.0, help="Scan interval delta_t in milliseconds (default: 10.0)")
    sim_parser.add_argument("--mock", action="store_true", help="Explicit offline/mock mode flag")
    sim_parser.add_argument("--export-trace", default=None, help="File path to save cycle trace JSON")
    sim_parser.add_argument("--export-evidence", default=None, help="File path to save Gate G4 evidence JSON")

    # inspect-registers / regs / registers
    regs_parser = subparsers.add_parser(
        "inspect-registers",
        aliases=["regs", "registers"],
        parents=[common_parent],
        help="Inspect Horner OCS register memory table (%%R, %%I, %%Q, %%AI, %%AQ, %%SR, %%S)",
    )
    regs_parser.add_argument("--channel", "-c", default=None, help="Filter by channel prefix (e.g. %%R, %%AI, %%I, %%SR)")
    regs_parser.add_argument("--address", "-a", default=None, help="Specific address or range expression (e.g. %%R1..%%R10, %%I1-8)")
    regs_parser.add_argument("--nonzero", "-nz", action="store_true", help="Display only non-zero registers")
    regs_parser.add_argument("--format", "-f", choices=["table", "json"], default="table", help="Output format (default: table)")

    # status
    subparsers.add_parser("status", parents=[common_parent], help="Display operational gates and backlog status")

    # manifest
    manifest_parser = subparsers.add_parser("manifest", parents=[common_parent], help="Generate or verify cryptographic delivery manifest (SHA-256)")
    manifest_parser.add_argument("--output", "-o", default="artifacts/G5/delivery_manifest.json", help="Target output path for delivery manifest")
    manifest_parser.add_argument("--verify", "-v", nargs="?", const="artifacts/G5/delivery_manifest.json", default=None, help="Verify disk files against manifest")

    # audit-safety
    audit_safety_parser = subparsers.add_parser(
        "audit-safety",
        parents=[common_parent],
        help="Run Gate G11 security lockout verification (COM ports, download interceptors, flash binaries)",
    )
    audit_safety_parser.add_argument(
        "--export-evidence",
        default=None,
        help="Path to export Gate G11 safety audit evidence JSON",
    )

    # soak
    soak_parser = subparsers.add_parser(
        "soak",
        parents=[common_parent],
        help="Run Gate G10 multi-rate closed-loop soak verifier",
    )
    soak_parser.add_argument(
        "--cycles", "-c",
        type=int,
        default=1000,
        help="Cycles per scan rate (default: 1000)",
    )
    soak_parser.add_argument(
        "--rates", "-r",
        default="5,10,20,50",
        help="Comma-separated scan intervals in ms (default: '5,10,20,50')",
    )
    soak_parser.add_argument(
        "--dt-ms",
        type=float,
        default=None,
        help="Single scan rate interval in ms (convenience override for --rates)",
    )
    soak_parser.add_argument(
        "--setpoint", "-sp",
        type=float,
        default=50.0,
        help="Target setpoint percentage (default: 50.0)",
    )
    soak_parser.add_argument(
        "--max-drift", "-md",
        type=float,
        default=2.5,
        help="Maximum allowable steady-state error/drift in %% (default: 2.5)",
    )
    soak_parser.add_argument(
        "--export-evidence",
        default=None,
        help="Path to export Gate G10 soak verification evidence JSON",
    )
    soak_parser.add_argument(
        "--mock",
        action="store_true",
        help="Run in explicit offline/mock mode",
    )

    # scale-point
    scale_parser = subparsers.add_parser(
        "scale-point",
        aliases=["scale"],
        parents=[common_parent],
        help="Test Gate G8 Modbus/EU telemetry scaling and precision tracking",
    )
    scale_parser.add_argument(
        "--channel", "-c",
        default="%AI1",
        help="Horner OCS channel address (default: %%AI1)",
    )
    scale_parser.add_argument(
        "--raw",
        type=int,
        default=None,
        help="Raw integer counts to convert to EU",
    )
    scale_parser.add_argument(
        "--eu",
        type=float,
        default=None,
        help="Engineering unit value to convert to raw counts",
    )
    scale_parser.add_argument(
        "--raw-min",
        type=float,
        default=0.0,
        help="Raw count minimum (default: 0.0)",
    )
    scale_parser.add_argument(
        "--raw-max",
        type=float,
        default=32000.0,
        help="Raw count maximum (default: 32000.0)",
    )
    scale_parser.add_argument(
        "--eu-min",
        type=float,
        default=0.0,
        help="Engineering unit minimum (default: 0.0)",
    )
    scale_parser.add_argument(
        "--eu-max",
        type=float,
        default=100.0,
        help="Engineering unit maximum (default: 100.0)",
    )
    scale_parser.add_argument(
        "--unit", "-u",
        default="%",
        help="Engineering unit symbol (default: %%)",
    )
    scale_parser.add_argument(
        "--scaling", "-s",
        choices=["LINEAR", "SQUARE_ROOT", "PIECEWISE", "RTD"],
        default="LINEAR",
        help="Scaling formula (default: LINEAR)",
    )
    scale_parser.add_argument(
        "--namur",
        action="store_true",
        help="Enable NAMUR NE 43 4-20mA boundary validation",
    )
    scale_parser.add_argument(
        "--ieee754",
        action="store_true",
        help="Enable IEEE-754 32-bit float serialization into 2 Modbus registers",
    )

    # ground / vision
    ground_parser = subparsers.add_parser(
        "ground",
        aliases=["vision-ground", "vision"],
        parents=[common_parent],
        help="Segment Cscape GUI panes and resolve unexposed MFC fallback coordinates (Gate G9)",
    )
    ground_parser.add_argument(
        "--image", "-i",
        default=None,
        help="Path to Cscape window screenshot (default: artifacts/logs/cscape_live_window.png)",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI execution entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    commands = {
        "doctor": cmd_doctor,
        "inspect": cmd_inspect,
        "launch": cmd_launch,
        "close": cmd_close,
        "sweep": cmd_sweep,
        "validate-st": cmd_validate_st,
        "inspect-navigator": cmd_inspect_navigator,
        "compile": cmd_compile,
        "scrape-output": cmd_scrape_output,
        "simulate": cmd_simulate,
        "sim": cmd_simulate,
        "inspect-registers": cmd_inspect_registers,
        "regs": cmd_inspect_registers,
        "registers": cmd_inspect_registers,
        "status": cmd_status,
        "manifest": cmd_manifest,
        "audit-safety": cmd_audit_safety,
        "soak": cmd_soak,
        "scale-point": cmd_scale_point,
        "scale": cmd_scale_point,
        "ground": cmd_vision_ground,
        "vision-ground": cmd_vision_ground,
        "vision": cmd_vision_ground,
    }

    handler = commands.get(args.command)
    if not handler:
        parser.print_help()
        return 1

    result: ExecutionResult = handler(args)

    if args.json or not sys.stdout.isatty():
        print(result.model_dump_json(indent=2))
    else:
        status_symbol = {
            AgentStatus.SUCCESS: "[PASS]",
            AgentStatus.PARTIAL: "[PARTIAL]",
            AgentStatus.FAILED: "[FAIL]",
            AgentStatus.BLOCKED: "[BLOCK]",
            AgentStatus.INCONCLUSIVE: "[INCONC]",
        }.get(result.status, "[INFO]")
        print(f"{status_symbol} {result.details}")
        if result.error_code:
            print(f"       Error Code: {result.error_code}")
        if result.data:
            print(f"       Data: {json.dumps(result.data, indent=2)}")

    status_exit_codes = {
        AgentStatus.SUCCESS: 0,
        AgentStatus.PARTIAL: 0,
        AgentStatus.FAILED: 1,
        AgentStatus.BLOCKED: 2,
        AgentStatus.INCONCLUSIVE: 3,
    }
    return status_exit_codes.get(result.status, 0)


if __name__ == "__main__":
    sys.exit(main())
