"""Tubular Catalytic Plug-Flow Reactor (PFR) Verification Runner.

Work Package: W077 (Gate G7 / G4)
Standard: Method of Lines, Upwind Finite Volume Formulation
Exports:
- artifacts/simulation/pfr_reactor_evidence.json
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Dict

from jev_cscape.simulation.pfr_reactor import PFRConfig, TubularPFRSimulator
from jev_cscape.simulation.register_table import RegisterTable


def run_pfr_reactor_verification(
    output_evidence_path: Path = Path("artifacts/simulation/pfr_reactor_evidence.json"),
) -> Dict[str, Any]:
    """Execute end-to-end verification of Tubular Catalytic PFR ODE simulation."""
    output_evidence_path.parent.mkdir(parents=True, exist_ok=True)
    sim = TubularPFRSimulator()
    checks: Dict[str, Any] = {}

    # Check 1: Dynamic Conversion & Hot-Spot Peak Tracking
    for _ in range(35):
        sim.step(dt_s=0.05)

    conv_ok = sim.conversion_pct > 80.0
    hotspot_ok = 110.0 <= sim.t_max_c <= 180.0 and 0.0 <= sim.z_hot_pct <= 100.0
    checks["conversion_and_hotspot"] = {
        "status": "passed" if conv_ok and hotspot_ok else "failed",
        "conversion_pct": round(sim.conversion_pct, 2),
        "t_max_c": round(sim.t_max_c, 2),
        "z_hot_pct": round(sim.z_hot_pct, 1),
    }

    # Check 2: Rigorous Conservation Residuals (< 1e-10)
    step_res = sim.step(dt_s=0.05)
    cons = step_res["conservation"]
    checks["conservation_residuals"] = {
        "status": "passed" if cons["mass_conserved"] and cons["energy_conserved"] else "failed",
        "mass_residual": cons["mass_residual"],
        "energy_residual": cons["energy_residual"],
        "mass_conserved_1e10": cons["mass_conserved"],
        "energy_conserved_1e10": cons["energy_conserved"],
    }

    # Check 3: Thermal Runaway Alarm Latching & Handshake Reset
    sim_runaway = TubularPFRSimulator()
    sim_runaway.temperature_k = [485.0] * sim_runaway.N  # ~211.85 °C > 200 °C
    sim_runaway.step(dt_s=0.05)
    latched = sim_runaway.thermal_runaway_latched and (sim_runaway.status_word & 0x0004 != 0)

    sim_runaway.temperature_k = [385.0] * sim_runaway.N
    sim_runaway.reset_alarms = True
    sim_runaway.step(dt_s=0.05)
    cleared = (not sim_runaway.thermal_runaway_latched) and (not sim_runaway.reset_alarms)

    checks["thermal_runaway_and_reset"] = {
        "status": "passed" if latched and cleared else "failed",
        "runaway_latched_at_high_temp": latched,
        "runaway_cleared_on_reset": cleared,
    }

    # Check 4: Emergency Coolant Flood Mitigation Quench
    t_pre_flood = sim.t_max_c
    sim.emergency_coolant_override = True
    for _ in range(25):
        sim.step(dt_s=0.05)
    t_post_flood = sim.t_max_c

    quench_ok = sim.coolant_flood_active and (t_post_flood < t_pre_flood)
    checks["emergency_coolant_flood_quench"] = {
        "status": "passed" if quench_ok else "failed",
        "pre_flood_t_max_c": round(t_pre_flood, 2),
        "post_flood_t_max_c": round(t_post_flood, 2),
        "flood_active_flag": sim.coolant_flood_active,
    }

    # Check 5: Horner OCS RegisterTable Synchronization
    table = RegisterTable()
    table.write_register("%R380", 2000)  # 20.00 mol/m3
    table.write_register("%R385", 1100)  # 110.0 °C
    table.write_register("%M88", True)
    table.write_register("%M89", False)
    table.write_register("%M90", False)

    sim_sync = TubularPFRSimulator()
    sim_sync.sync_from_register_table(table)
    for _ in range(35):
        sim_sync.step(dt_s=0.05)
    sim_sync.sync_to_register_table(table)

    r_sync_ok = (
        table.read_register("%R380") == 2000
        and table.read_register("%R381") > 0
        and table.read_register("%R382") > 7000  # Conversion > 70%
        and table.read_register("%R383") > 1000  # T_max > 100 °C
        and (table.read_register("%R387") & 0x0001 != 0)  # Normal status
    )
    checks["register_table_synchronization"] = {
        "status": "passed" if r_sync_ok else "failed",
        "r380_inlet_conc": table.read_register("%R380"),
        "r381_outlet_conc": table.read_register("%R381"),
        "r382_conversion": table.read_register("%R382"),
        "r383_t_max": table.read_register("%R383"),
        "r387_status_word": table.read_register("%R387"),
    }

    all_passed = all(c["status"] == "passed" for c in checks.values())
    evidence = {
        "work_package": "W077",
        "gate": "G7",
        "component": "Tubular Catalytic Plug-Flow Reactor (PFR) Kinetics & Thermal Runaway ODE",
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "overall_status": "success" if all_passed else "failed",
        "registers": {
            "%R380": int(round(sim_sync.inlet_c_a * 100.0)),
            "%R381": int(round(sim_sync.c_a[-1] * 100.0)),
            "%R382": int(round(sim_sync.conversion_pct * 100.0)),
            "%R383": int(round(sim_sync.t_max_c * 10.0)),
            "%R384": int(round(sim_sync.z_hot_pct * 10.0)),
            "%R385": int(round((sim_sync.coolant_t_k - 273.15) * 10.0)),
            "%R386": int(round(sim_sync.parametric_sensitivity * 100.0)),
            "%R387": sim_sync.status_word,
            "%M88": sim_sync.enable_loop,
            "%M89": sim_sync.emergency_coolant_override,
            "%M90": sim_sync.reset_alarms,
        },
        "checks": checks,
    }

    with open(output_evidence_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    return evidence


if __name__ == "__main__":
    res = run_pfr_reactor_verification()
    print(json.dumps(res, indent=2))
