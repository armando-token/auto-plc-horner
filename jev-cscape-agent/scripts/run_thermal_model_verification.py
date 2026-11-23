"""Canonical verification runner for First-Principles Plant Thermal Dynamics & Heat Exchanger ODE Simulation.

Work Package: W053 (Gate G7 / G4)
Classification: VERIFICATION [strict 4-state engineering contract]

Produces:
- artifacts/simulation/thermal_model_evidence.json
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional

from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.thermal_model import (
    CounterFlowHeatExchanger,
    HeatExchangerConfig,
    HeaterActuator,
    RTDSensorModel,
    TankThermalPlantModel,
    ThermalConfig,
    ThermalModelLogicUnit,
)
from jev_cscape.telemetry.scaling_bridge import QualityCode


def run_thermal_model_verification(
    output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute complete thermodynamic verification across heat exchanger, heater, sensor, and plant models."""
    evidence_dir = Path("artifacts/simulation")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    target_output = output_path or (evidence_dir / "thermal_model_evidence.json")

    start_time = time.perf_counter()
    assertions: List[Dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # 1. CounterFlowHeatExchanger Verification
    # -------------------------------------------------------------------------
    hx = CounterFlowHeatExchanger(HeatExchangerConfig(U_hx=1000.0, A_hx=2.0, cp_hot=4184.0, cp_cold=4184.0))

    # Case A: Balanced streams (C_r == 1.0)
    # m_dot_h = 0.5 kg/s, m_dot_c = 0.5 kg/s -> C_h = 2092 W/K, C_c = 2092 W/K
    # UA = 2000 W/K -> NTU = 2000 / 2092 = 0.95602
    # epsilon = NTU / (1 + NTU) = 0.95602 / 1.95602 = 0.48876
    st_balanced = hx.step(T_hot_in=90.0, T_cold_in=20.0, m_dot_hot=0.5, m_dot_cold=0.5)
    assertions.append({
        "check": "hx_balanced_energy_conservation",
        "passed": (
            st_balanced.energy_residual < 1e-9
            and abs(st_balanced.epsilon - (st_balanced.NTU / (1.0 + st_balanced.NTU))) < 1e-4
            and st_balanced.T_hot_out < 90.0
            and st_balanced.T_cold_out > 20.0
        ),
        "details": f"Balanced: epsilon={st_balanced.epsilon:.4f}, residual={st_balanced.energy_residual:.2e} W, T_h_out={st_balanced.T_hot_out:.2f} C, T_c_out={st_balanced.T_cold_out:.2f} C",
    })

    # Case B: Unbalanced streams (C_r == 0.5)
    st_unbalanced = hx.step(T_hot_in=90.0, T_cold_in=20.0, m_dot_hot=0.25, m_dot_cold=0.5)
    assertions.append({
        "check": "hx_unbalanced_energy_conservation",
        "passed": (
            st_unbalanced.energy_residual < 1e-9
            and st_unbalanced.q_hx > 0.0
            and st_unbalanced.T_hot_out >= 20.0
            and st_unbalanced.T_cold_out <= 90.0
        ),
        "details": f"Unbalanced: q_hx={st_unbalanced.q_hx:.1f} W, residual={st_unbalanced.energy_residual:.2e} W",
    })

    # Case C: Zero flow singularity guard
    st_zero = hx.step(T_hot_in=90.0, T_cold_in=20.0, m_dot_hot=0.0, m_dot_cold=0.5)
    assertions.append({
        "check": "hx_zero_flow_guard",
        "passed": st_zero.q_hx == 0.0 and st_zero.epsilon == 0.0 and st_zero.energy_residual == 0.0,
        "details": "Zero flow correctly yields zero heat transfer without division by zero",
    })

    # -------------------------------------------------------------------------
    # 2. HeaterActuator Thermal Lag & Interlock
    # -------------------------------------------------------------------------
    heater = HeaterActuator(Q_max=10000.0, tau_heater=2.0)
    # Step at normal level (height = 1.0 m)
    p1 = heater.step(cmd_percent=100.0, dt=1.0, liquid_height=1.0)
    p2 = heater.step(cmd_percent=100.0, dt=15.0, liquid_height=1.0)
    # Dry-run trip (height = 0.001 m < 0.005 m cutoff)
    p_dry = heater.step(cmd_percent=100.0, dt=10.0, liquid_height=0.001)

    assertions.append({
        "check": "heater_lag_and_dry_run_interlock",
        "passed": (
            0.0 < p1 < p2
            and abs(p2 - 10000.0) < 100.0
            and p_dry < 100.0  # Powers down toward 0 when dry
        ),
        "details": f"Heater: t=1s -> {p1:.1f}W, t=16s -> {p2:.1f}W, dry-run trip -> {p_dry:.1f}W",
    })

    # -------------------------------------------------------------------------
    # 3. RTDSensorModel Signal Conditioning & Namur NE43
    # -------------------------------------------------------------------------
    sensor = RTDSensorModel(name="RTD_Test", tau_sensor=1.0, sigma_noise=0.0, seed=42)
    # Advance to 75.0 °C (25 steps * 0.5s = 12.5s >> tau=1.0s)
    for _ in range(25):
        t_m, ma, raw, qc, qw = sensor.step(75.0, dt=0.5)

    # In normal range (75 C / 150 C span = 0.5 -> 12.0 mA -> 16000 counts)
    assertions.append({
        "check": "rtd_normal_signal_conditioning",
        "passed": (
            abs(t_m - 75.0) < 0.1
            and abs(ma - 12.0) < 0.1
            and abs(raw - 16000) <= 20
            and qc == QualityCode.GOOD
        ),
        "details": f"RTD normal: T={t_m:.2f} C, I={ma:.2f} mA, raw={raw}, quality={qc.name}",
    })

    # Burnout fault injection
    sensor.burnout_fault = True
    _, ma_burn, raw_burn, qc_burn, _ = sensor.step(75.0, dt=0.1)
    sensor.burnout_fault = False

    assertions.append({
        "check": "rtd_burnout_namur_fault",
        "passed": ma_burn < 3.6 and raw_burn < 0 and qc_burn == QualityCode.BAD,
        "details": f"RTD burnout: I={ma_burn:.2f} mA, raw={raw_burn}, quality={qc_burn.name}",
    })

    # -------------------------------------------------------------------------
    # 4. TankThermalPlantModel Closed-Loop Dynamics
    # -------------------------------------------------------------------------
    plant = TankThermalPlantModel(ThermalConfig(T_initial=25.0, T_ambient=20.0, tank_area=1.0))

    # Heat up phase: 60 seconds with 80% heater power
    t_start = plant.temperature
    for _ in range(60):
        res = plant.step(
            dt=1.0,
            liquid_height=1.0,
            inflow_rate_lps=0.1,
            T_inflow=20.0,
            heater_cmd_pct=80.0,
        )
    t_heated = plant.temperature

    # Cooling phase: 60 seconds with 0% heater power
    for _ in range(60):
        res = plant.step(
            dt=1.0,
            liquid_height=1.0,
            inflow_rate_lps=0.5,
            T_inflow=20.0,
            heater_cmd_pct=0.0,
        )
    t_cooled = plant.temperature

    assertions.append({
        "check": "plant_heating_and_cooling_transients",
        "passed": t_heated > t_start and t_cooled < t_heated,
        "details": f"Transient: initial={t_start:.2f} C -> heated={t_heated:.2f} C -> cooled={t_cooled:.2f} C",
    })

    # -------------------------------------------------------------------------
    # 5. ThermalModelLogicUnit Horner OCS Register Integration
    # -------------------------------------------------------------------------
    reg_table = RegisterTable()
    # Set level in %AI1 (24000 counts = 1.5 m)
    reg_table.write_word("%AI1", 24000, privilege=PrivilegeMode.SYSTEM)
    # Set heater demand in %AQ2 (16000 counts = 50.0%)
    reg_table.write_word("%AQ2", 16000, privilege=PrivilegeMode.SYSTEM)

    unit = ThermalModelLogicUnit(setpoint_c=65.0)

    # Execute 30 scan cycles (dt = 0.1 s)
    for _ in range(30):
        unit.execute_logic(reg_table, dt=0.1)

    rtd1_counts = reg_table.read_word("%AI3")
    rtd2_counts = reg_table.read_word("%AI4")
    t_ctrl_scaled = reg_table.read_word("%R154")
    status_w = reg_table.read_word("%R150")
    m5_high = reg_table.read_bit("%M5")

    assertions.append({
        "check": "horner_register_synchronization",
        "passed": (
            rtd1_counts > 0
            and rtd2_counts > 0
            and t_ctrl_scaled > 0
            and (status_w & 0x01) == 0x01  # Bit 0: HEATER_RUNNING
            and (status_w & 0x02) == 0x02  # Bit 1: RTD1_HEALTHY
            and m5_high is False           # High alarm not tripped at nominal temp
        ),
        "details": f"Registers: AI3={rtd1_counts}, AI4={rtd2_counts}, R154={t_ctrl_scaled} (tenths C), R150={hex(status_w)}",
    })

    # Summary and Export
    all_passed = all(a["passed"] for a in assertions)
    duration_ms = (time.perf_counter() - start_time) * 1000.0

    evidence_payload = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "ERR_THERMAL_VERIFICATION_FAILED",
        "details": f"Plant thermal dynamics verification completed: {sum(1 for a in assertions if a['passed'])}/{len(assertions)} assertions passed in {duration_ms:.2f} ms.",
        "data": {
            "all_passed": all_passed,
            "duration_ms": duration_ms,
            "assertions": assertions,
            "final_temperature_c": plant.temperature,
            "heat_exchanger_residual_w": st_balanced.energy_residual,
        },
    }

    with open(target_output, "w", encoding="utf-8") as f:
        json.dump(evidence_payload, f, indent=2)

    return evidence_payload


if __name__ == "__main__":
    result = run_thermal_model_verification()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
