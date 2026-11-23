"""Packed Absorption Column Mass Transfer ODE Verification Runner.

Work Package: W074 (Gate G7 / G4)
Standard: Whitman Two-Film Theory & Sherwood-Leva GPDC Flooding Hydraulics
Exports: artifacts/simulation/packed_column_evidence.json
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Dict

from jev_cscape.simulation.packed_column import (
    PackedAbsorptionColumn,
    PackedAbsorptionConfig,
    PackedColumnSupervisor,
)


def run_packed_column_verification(
    output_path: Path = Path("artifacts/simulation/packed_column_evidence.json"),
) -> Dict[str, Any]:
    """Execute end-to-end verification of packed absorption column simulation."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    sup = PackedColumnSupervisor()
    checks: Dict[str, Any] = {}

    # Check 1: Two-Film Mass Transfer & van 't Hoff Equilibrium
    col = sup.column
    m_25 = col.compute_henry_m(25.0)
    m_50 = col.compute_henry_m(50.0)
    k_og_a = col.compute_k_og_a(25.0)
    checks["two_film_and_vant_hoff"] = {
        "status": "passed" if m_50 > m_25 and k_og_a > 0.0 else "failed",
        "henry_m_at_25c": round(m_25, 4),
        "henry_m_at_50c": round(m_50, 4),
        "k_og_a_at_25c": round(k_og_a, 4),
    }

    # Check 2: GPDC Sherwood-Leva Hydraulics
    l_vol = 120.0 / 60000.0  # 120 L/min -> m3/s
    g_vol = 850.0 / 3600.0   # 850 m3/h -> m3/s
    hyd = col.compute_hydraulics(l_vol, g_vol)
    checks["gpdc_flooding_hydraulics"] = {
        "status": "passed" if 0.0 < hyd["pct_flooding"] < 80.0 and hyd["dp_total_mbar"] > 0 else "failed",
        "superficial_gas_velocity_m_s": round(hyd["u_g_m_s"], 4),
        "flooding_gas_velocity_m_s": round(hyd["u_flood_m_s"], 4),
        "flooding_percentage": round(hyd["pct_flooding"], 2),
        "differential_pressure_mbar": round(hyd["dp_total_mbar"], 2),
    }

    # Check 3: Closed-Loop Steady-State Removal Efficiency
    sup.solute_gas_inflow = 5000  # 500.0 ppm
    sup.gas_flow_rate = 8500      # 850.0 m3/h
    for _ in range(30):
        sup.step(dt_s=0.1)
    checks["scrubbing_removal_efficiency"] = {
        "status": "passed" if sup.solute_removal_eff >= 9000 and sup.solute_gas_outlet <= 500 else "failed",
        "inflow_ppm": sup.solute_gas_inflow / 10.0,
        "outlet_ppm": sup.solute_gas_outlet / 10.0,
        "removal_efficiency_pct": sup.solute_removal_eff / 100.0,
    }

    # Check 4: Auto Solvent Optimization
    checks["auto_solvent_optimization"] = {
        "status": "passed" if sup.liquid_solvent_inflow >= 1000 and sup.auto_liquid_opt else "failed",
        "optimized_liquid_flow_l_min": sup.liquid_solvent_inflow / 10.0,
        "auto_mode_active": sup.auto_liquid_opt,
    }

    # Check 5: Flooding Alarm & Reset Cycle
    sup_fault = PackedColumnSupervisor()
    sup_fault.gas_flow_rate = 14000  # High gas flow -> flooding
    sup_fault.step(dt_s=0.1)
    alarm_latched = sup_fault.flooding_alarm_latched

    # Reset
    sup_fault.gas_flow_rate = 8500
    for _ in range(20):
        sup_fault.step(dt_s=0.1)
    sup_fault.reset_alarms = True
    sup_fault.step(dt_s=0.1)
    alarm_cleared = not sup_fault.flooding_alarm_latched and (sup_fault.column_status_word & 0x0001 != 0)

    checks["alarm_latching_and_reset"] = {
        "status": "passed" if alarm_latched and alarm_cleared else "failed",
        "alarm_latched_on_high_gas": alarm_latched,
        "alarm_cleared_on_reset": alarm_cleared,
    }

    all_passed = all(c["status"] == "passed" for c in checks.values())
    evidence = {
        "work_package": "W074",
        "gate": "G7",
        "model": "Counter-Current Packed Absorption Column Mass Transfer ODE",
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "overall_status": "success" if all_passed else "failed",
        "registers": {
            "%R350": sup.solute_gas_inflow,
            "%R351": sup.solute_gas_outlet,
            "%R352": sup.solute_removal_eff,
            "%R353": sup.liquid_solvent_inflow,
            "%R354": sup.gas_flow_rate,
            "%R355": sup.column_pressure_drop,
            "%R356": sup.column_flooding_index,
            "%R357": sup.column_status_word,
            "%M81": sup.enable_simulation,
            "%M82": sup.auto_liquid_opt,
            "%M83": sup.reset_alarms,
        },
        "checks": checks,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    return evidence


if __name__ == "__main__":
    res = run_packed_column_verification()
    print(json.dumps(res, indent=2))
