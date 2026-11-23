#!/usr/bin/env python3
"""Deterministic 9-Stage Verification Runner for ODVA CIP Safety Over PROFINET / PROFIsafe Gateway Bridge (W301).

Work Package: W301 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Standards:
  - ODVA CIP Safety Volume 5 (IEC 61784-3-2 / IEC 61508 SIL 3)
  - PI PROFIsafe Profile V1/V2 (IEC 61784-3-3 / IEC 61508 SIL 3)
Memory Layout:
  - Registers: %R2620..%R2627
  - Discrete Coils: %M611..%M612
Status Contract: Strict 4-State JSON output (success | failed | blocked | inconclusive)

Stages:
  1. protocol_constants_registers_and_diagnostics: %R2620..%R2627, %M611..%M612, 0xEE41..0xEE46.
  2. dual_safety_crc_calculations: CIP CRC-S1 (0x5935), CRC-S2 (0x755B), PROFIsafe F-CRC (0x5D6DCB / 0x1EDC6F41).
  3. gateway_state_machine: Transitions (IDLE -> CONNECTING -> FORWARDING -> FAULT) and recovery.
  4. cip_safety_to_profisafe_translation: Ingress CIP Safety -> Egress PROFIsafe with CRC & latency bounds.
  5. profisafe_to_cip_safety_translation: Ingress PROFIsafe -> Egress CIP Safety with dual CRC generation.
  6. safety_crc_fault_interceptions: Tamper detection & fail-safe substitution (0xEE41, 0xEE42).
  7. latency_watchdog_and_f_status_trips: Latency overrun (0xEE45), Watchdog timeout (0xEE43), SNN mismatch (0xEE46).
  8. horner_ocs_register_synchronization: Bit-exact register synchronization and signed 16-bit masks.
  9. pure_st_pou_and_ladder_rejection: Pure IEC 61131-3 ST POU verification and LadderForbiddenError rejection.

Generates:
  artifacts/telemetry/cip_safety_profisafe_evidence.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Union

# Ensure repository root and src/ are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# ANSI terminal formatting constants matching repo conventions
ESC_RESET = "\033[0m"
ESC_BOLD = "\033[1m"
ESC_DIM = "\033[2m"
ESC_GREEN = "\033[92m"
ESC_RED = "\033[91m"
ESC_YELLOW = "\033[93m"
ESC_CYAN = "\033[96m"


def format_stage_badge(passed: bool, status: Optional[str] = None) -> str:
    """Format an ANSI-colored stage status badge."""
    norm_status = (status or "").lower()
    if norm_status == "blocked":
        return f"{ESC_YELLOW}{ESC_BOLD}[BLOCKED]{ESC_RESET}"
    if norm_status == "inconclusive":
        return f"{ESC_YELLOW}{ESC_BOLD}[INCONCLUSIVE]{ESC_RESET}"
    if passed or norm_status in ("passed", "pass", "success"):
        return f"{ESC_GREEN}{ESC_BOLD}[PASS]{ESC_RESET}"
    return f"{ESC_RED}{ESC_BOLD}[FAIL]{ESC_RESET}"


def format_stage_result(
    stage: int | str,
    name: str,
    passed: bool,
    timing_ms: Optional[float] = None,
    details: str = "",
    status: Optional[str] = None,
) -> str:
    """Format a single stage line with ANSI colored badge, timing, and description."""
    badge = format_stage_badge(passed, status)
    timing_str = f" ({timing_ms:.3f} ms)" if timing_ms is not None else ""
    line = f"  Stage {stage}: {badge} {name}{timing_str}"
    if details:
        line += f"\n    {ESC_DIM}{details}{ESC_RESET}"
    return line


# ============================================================================
# Main 9-Stage Verification Suite Execution
# ============================================================================

def execute_9stage_verification_suite(
    output_path: Optional[Union[str, Path]] = None,
    work_package: str = "W301",
    quick: bool = False,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W301.

    Delegates to the verified telemetry engine implementation and ensures
    deterministic cryptographic SHA-256 digests and strict 4-state contract.
    """
    from jev_cscape.telemetry.cip_safety_profisafe import (
        run_cip_safety_profisafe_verification as _core_runner,
        ST_PROGRAM_CIP_SAFETY_PROFISAFE_SYNC,
    )

    # Determine output path if specified
    out_file = Path(output_path).resolve() if output_path else None

    # Execute core verification runner
    evidence = _core_runner(
        project_root=REPO_ROOT,
        output_path=out_file,
        work_package=work_package,
        quick=quick,
        **kwargs,
    )

    # Ensure cryptographic SHA-256 digests exist
    data = evidence.setdefault("data", {})
    if "sha256_digests" not in data:
        pou_sha256 = hashlib.sha256(ST_PROGRAM_CIP_SAFETY_PROFISAFE_SYNC.encode("utf-8")).hexdigest()
        stages_sha256 = hashlib.sha256(json.dumps(data.get("stages", []), sort_keys=True).encode("utf-8")).hexdigest()
        data["sha256_digests"] = {
            "pou_sha256": pou_sha256,
            "stages_sha256": stages_sha256,
        }

    # Ensure output file is written if path provided
    if out_file:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence


# Module alias matching testing conventions
run_cip_safety_profisafe_verification = execute_9stage_verification_suite


# ============================================================================
# CLI Entrypoint
# ============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for W301 verification runner."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Execute W301 CIP Safety Over PROFINET / PROFIsafe Gateway Bridge 9-Stage Verification Suite"
    )
    parser.add_argument(
        "positional_path",
        nargs="?",
        default=None,
        help="Optional positional path for output evidence JSON file",
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="flag_path",
        default=None,
        help="Path to output JSON evidence artifact (default: artifacts/telemetry/cip_safety_profisafe_evidence.json)",
    )
    parser.add_argument(
        "--quick",
        "-q",
        action="store_true",
        default=False,
        help="Execute quick verification mode (reduced simulation cycles)",
    )
    parser.add_argument(
        "--work-package",
        "-w",
        default="W301",
        help="Work package ID (default: W301)",
    )
    parser.add_argument(
        "--json",
        "--json-only",
        action="store_true",
        help="Emit raw JSON report only (no ANSI stdout banner)",
    )
    args = parser.parse_args(argv)

    selected_path = args.flag_path or args.positional_path
    if selected_path:
        evidence_path = Path(selected_path).resolve()
    else:
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_profisafe_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print("=" * 80)
        print(f"  {ESC_BOLD}JEV Cscape Agent: ODVA CIP Safety Over PROFINET / PROFIsafe Verification ({args.work_package}){ESC_RESET}")
        print("=" * 80)

    t0 = time.perf_counter()
    try:
        evidence = execute_9stage_verification_suite(
            output_path=evidence_path,
            work_package=args.work_package,
            quick=args.quick,
        )
    except Exception as exc:
        print(f"\n[{ESC_RED}{ESC_BOLD}EXCEPTION{ESC_RESET}] Verification suite crashed with unhandled exception:")
        print(f"  {type(exc).__name__}: {exc}")
        print("=" * 80)
        return 1
    elapsed_total_ms = (time.perf_counter() - t0) * 1000.0

    # Ensure evidence file was written
    if not evidence_path.exists() or evidence_path.stat().st_size == 0:
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    if args.json:
        print(json.dumps(evidence, indent=2))
        return 0 if evidence.get("status") == "success" else 1

    stages = evidence.get("data", {}).get("stages", [])
    for stg in stages:
        stage_num = stg.get("stage", "?")
        stage_name = stg.get("name") or stg.get("check", "unnamed_stage")
        passed = stg.get("passed", False)
        timing = stg.get("timing_ms") or stg.get("duration_ms")
        details = stg.get("details", "")
        status = stg.get("status")
        print(format_stage_result(stage_num, stage_name, passed, timing, details, status))

    passed_count = evidence.get("stages_passed", sum(1 for s in stages if s.get("passed", False)))
    total_count = evidence.get("total_stages", len(stages))
    status_str = evidence.get("status", "unknown")

    print("-" * 80)
    status_badge = (
        f"{ESC_GREEN}{ESC_BOLD}{status_str.upper()}{ESC_RESET}"
        if status_str == "success"
        else f"{ESC_RED}{ESC_BOLD}{status_str.upper()}{ESC_RESET}"
    )
    print(f"[*] Outcome: {passed_count}/{total_count} checks passed across {len(stages)} verification stages (in {elapsed_total_ms:.2f} ms).")
    print(f"[*] Status: {status_badge}")
    print(f"[*] Evidence artifact saved: {ESC_CYAN}{evidence_path}{ESC_RESET}")
    print("=" * 80)

    return 0 if status_str == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
