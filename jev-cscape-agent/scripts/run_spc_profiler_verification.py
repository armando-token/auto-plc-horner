"""Canonical verification runner for Statistical Process Control (SPC) & Cpk Capability Profiler.

Work Package: W054 (Gate G10 / G4)
Classification: VERIFICATION [strict 4-state engineering contract]

Produces:
- artifacts/benchmarks/spc_profiler_evidence.json
"""

from __future__ import annotations

import json
from pathlib import Path
import random
import sys
import time
from typing import Any, Dict, List, Optional

from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.spc_profiler import SPCProfiler


def run_spc_profiler_verification(
    output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute complete verification across Shewhart control limits, Western Electric rules, and Cpk capability."""
    evidence_dir = Path("artifacts/benchmarks")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    target_output = output_path or (evidence_dir / "spc_profiler_evidence.json")

    start_time = time.perf_counter()
    assertions: List[Dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # Scenario 1: Stable In-Control Process (High Cpk >= 1.33)
    # -------------------------------------------------------------------------
    rng = random.Random(42)
    profiler = SPCProfiler(usl=56.0, lsl=44.0, target=50.0, window_size=50)

    # Ingest 50 normally distributed samples around 50.0 with sigma = 0.8
    samples_in_control = [rng.gauss(50.0, 0.8) for _ in range(50)]
    profiler.ingest_batch(samples_in_control)

    m1 = profiler.compute_metrics()
    assertions.append({
        "check": "in_control_process_capability",
        "passed": (
            m1 is not None
            and m1.capability is not None
            and m1.capability.is_capable_133
            and m1.capability.cpk >= 1.5
            and not m1.violations.any_violation
            and abs(m1.mean - 50.0) < 0.5
        ),
        "details": f"In-control: Cp={m1.capability.cp if m1 and m1.capability else None}, Cpk={m1.capability.cpk if m1 and m1.capability else None}, Mean={m1.mean if m1 else None:.2f}, Violations={m1.violations.any_violation if m1 else None}",
    })

    # -------------------------------------------------------------------------
    # Scenario 2: Western Electric Rule 1 (Point beyond 3-sigma / outside UCL)
    # -------------------------------------------------------------------------
    # Inject extreme outlier at 57.0 (well above UCL ~52.4)
    profiler.ingest_sample(57.0)
    m2 = profiler.compute_metrics()

    assertions.append({
        "check": "western_electric_rule1_beyond_3sigma",
        "passed": (
            m2 is not None
            and m2.violations.rule1_beyond_3sigma
            and m2.violations.any_violation
        ),
        "details": f"Rule 1: outlier=57.0 > UCL={m2.control_limits.ucl if m2 else None:.2f}, triggered={m2.violations.rule1_beyond_3sigma if m2 else None}",
    })

    # -------------------------------------------------------------------------
    # Scenario 3: Western Electric Rule 2 (2 of 3 points in Zone A > 2-sigma)
    # -------------------------------------------------------------------------
    profiler.reset()
    # Fill baseline with mean=50.0, sigma=1.0
    profiler.ingest_batch([50.0 + (i % 3 - 1) * 0.5 for i in range(30)])
    # Inject 2 points above +2.2 sigma (e.g. 52.5 when sigma~1.0)
    profiler.ingest_sample(52.5)
    profiler.ingest_sample(50.2)
    profiler.ingest_sample(52.6)  # 2 out of 3 in Zone A

    m3 = profiler.compute_metrics()
    assertions.append({
        "check": "western_electric_rule2_zone_a",
        "passed": (
            m3 is not None
            and m3.violations.rule2_zone_a
        ),
        "details": f"Rule 2 triggered: {m3.violations.rule2_zone_a if m3 else None}",
    })

    # -------------------------------------------------------------------------
    # Scenario 4: Western Electric Rule 4 (8 consecutive points on same side of CL)
    # -------------------------------------------------------------------------
    profiler.reset()
    # Baseline
    profiler.ingest_batch([50.0 + (i % 2) * 0.2 - 0.1 for i in range(20)])
    # Inject 8 consecutive points slightly above CL (> 50.0)
    for _ in range(8):
        profiler.ingest_sample(50.6)

    m4 = profiler.compute_metrics()
    assertions.append({
        "check": "western_electric_rule4_mean_shift",
        "passed": (
            m4 is not None
            and m4.violations.rule4_mean_shift
        ),
        "details": f"Rule 4 mean shift triggered: {m4.violations.rule4_mean_shift if m4 else None}",
    })

    # -------------------------------------------------------------------------
    # Scenario 5: Process Mean Shift and Degraded Cpk (< 1.0)
    # -------------------------------------------------------------------------
    profiler.reset()
    # Severe shift towards USL (mean=54.5, USL=56.0, sigma=1.0 -> (56-54.5)/3 = 0.5 Cpk)
    profiler.ingest_batch([54.5 + (i % 3 - 1) * 0.8 for i in range(30)])
    m5 = profiler.compute_metrics()

    assertions.append({
        "check": "degraded_process_capability",
        "passed": (
            m5 is not None
            and m5.capability is not None
            and not m5.capability.is_capable_133
            and m5.capability.cpk < 1.0
            and m5.capability.centering_factor_k > 0.5
        ),
        "details": f"Shifted: Cpk={m5.capability.cpk if m5 and m5.capability else None}, k={m5.capability.centering_factor_k if m5 and m5.capability else None}",
    })

    # -------------------------------------------------------------------------
    # Scenario 6: Horner OCS Register Table Synchronization
    # -------------------------------------------------------------------------
    reg_table = RegisterTable()
    m_sync = profiler.sync_to_registers(reg_table)

    m25_r1 = reg_table.read_bit("%M25")
    m28_r4 = reg_table.read_bit("%M28")
    r210_cp = reg_table.read_word("%R210")
    r211_cpk = reg_table.read_word("%R211")
    r212_mean = reg_table.read_word("%R212")

    assertions.append({
        "check": "horner_register_synchronization",
        "passed": (
            m_sync is not None
            and r210_cp > 0
            and r211_cpk > 0
            and r212_mean > 0
            and abs(r212_mean - int(round(m_sync.mean * 10.0))) <= 1
        ),
        "details": f"Registers: R210(Cp*100)={r210_cp}, R211(Cpk*100)={r211_cpk}, R212(Mean*10)={r212_mean}, M25={m25_r1}, M28={m28_r4}",
    })

    # Summary and Export
    all_passed = all(a["passed"] for a in assertions)
    duration_ms = (time.perf_counter() - start_time) * 1000.0

    evidence_payload = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "ERR_SPC_VERIFICATION_FAILED",
        "details": f"Statistical Process Control verification completed: {sum(1 for a in assertions if a['passed'])}/{len(assertions)} assertions passed in {duration_ms:.2f} ms.",
        "data": {
            "all_passed": all_passed,
            "duration_ms": duration_ms,
            "assertions": assertions,
            "final_metrics": m_sync.to_dict() if m_sync else None,
        },
    }

    with open(target_output, "w", encoding="utf-8") as f:
        json.dump(evidence_payload, f, indent=2)

    return evidence_payload


if __name__ == "__main__":
    result = run_spc_profiler_verification()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
