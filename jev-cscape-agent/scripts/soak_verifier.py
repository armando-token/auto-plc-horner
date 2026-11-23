"""Gate G10 Multi-Rate Closed-Loop Long-Term Soak & Stability Verification Script.

Work Package: W029 (Gate G10)
Classification: TESTED_MOCK [offline/DEV only]

Integrates:
1. Horner OCS scan cycle simulation engine (SimulationEngine).
2. Horner 14-channel register table memory model (RegisterTable).
3. First-principles plant process model (TankLevelPlantModel).
4. IEC 61131-3 closed-loop control logic (ClosedLoopPIController).

Validates:
1. Long-term soak execution across scan cycles (default 100,000 cycles) across multiple rates (5ms, 10ms, 20ms, 50ms).
2. Memory telemetry via tracemalloc & psutil verifying zero memory leak (< 100KB heap growth over 100k cycles).
3. Bounded level tracking (steady-state error <= 1.0%), zero numerical divergence, and zero NaN values.
4. Generates deterministic JSON evidence artifact at artifacts/G10/soak_verification_evidence.json.
5. Returns strict 4-state contract response.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Union

# Add src to python path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root / "src") not in sys.path:
    sys.path.insert(0, str(repo_root / "src"))

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.simulation.engine import SimulationEngine
from jev_cscape.simulation.plant_model import (
    PlantModelLogicUnit,
    TankConfig,
    TankLevelPlantModel,
)
from jev_cscape.simulation.register_table import RegisterTable
from jev_cscape.simulation.verifier import ClosedLoopPIController
from jev_cscape.simulation.soak import (
    SoakMemoryMetrics,
    SoakRateMetrics,
    SoakVerifier,
)


def run_soak_verification(
    total_cycles: int = 100_000,
    scan_rates_ms: Optional[List[float]] = None,
    setpoint_pct: float = 50.0,
    max_error_pct: float = 1.0,
    max_heap_growth_kb: float = 100.0,
    output_path: str = "artifacts/G10/soak_verification_evidence.json",
    repo_root_override: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute multi-rate closed-loop long-term soak verification and produce evidence.

    Returns strict 4-state contract dictionary:
    {"status": "success | failed | blocked | inconclusive", "error_code": null, "details": "...", "data": {...}}
    """
    rates = scan_rates_ms or [5.0, 10.0, 20.0, 50.0]
    effective_repo_root = repo_root_override or repo_root

    verifier = SoakVerifier(
        total_cycles=total_cycles,
        scan_rates_ms=rates,
        setpoint_pct=setpoint_pct,
        max_error_pct=max_error_pct,
        max_heap_growth_kb=max_heap_growth_kb,
        noise_sigma=0.0,
    )

    result = verifier.run_soak(
        export_evidence=output_path,
        repo_root=effective_repo_root,
    )

    contract_status = result.status.value
    # Map to strict 4-state engineering contract
    if contract_status not in ("success", "failed", "blocked", "inconclusive"):
        contract_status = "success" if contract_status == "passed" else "failed"

    return {
        "status": contract_status,
        "error_code": result.error_code,
        "details": result.details,
        "data": result.data,
    }


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point for long-term soak verification runner."""
    parser = argparse.ArgumentParser(
        description="Gate G10 Multi-Rate Closed-Loop Long-Term Soak Verification Runner"
    )
    parser.add_argument(
        "--cycles",
        "-c",
        type=int,
        default=100_000,
        help="Total scan cycles across all rates (default: 100000)",
    )
    parser.add_argument(
        "--rates",
        nargs="+",
        type=float,
        default=[5.0, 10.0, 20.0, 50.0],
        help="List of scan intervals in ms (default: 5.0 10.0 20.0 50.0)",
    )
    parser.add_argument(
        "--setpoint",
        "-s",
        type=float,
        default=50.0,
        help="Target liquid level setpoint percentage (default: 50.0)",
    )
    parser.add_argument(
        "--max-error",
        type=float,
        default=1.0,
        help="Maximum allowed steady-state error percentage (default: 1.0)",
    )
    parser.add_argument(
        "--max-heap-growth",
        type=float,
        default=100.0,
        help="Maximum allowed heap memory growth in KB (default: 100.0)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="artifacts/G10/soak_verification_evidence.json",
        help="Evidence output path (default: artifacts/G10/soak_verification_evidence.json)",
    )

    args = parser.parse_args(argv)

    report = run_soak_verification(
        total_cycles=args.cycles,
        scan_rates_ms=args.rates,
        setpoint_pct=args.setpoint,
        max_error_pct=args.max_error,
        max_heap_growth_kb=args.max_heap_growth,
        output_path=args.output,
    )

    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
