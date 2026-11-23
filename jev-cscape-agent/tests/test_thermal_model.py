"""Unit and integration test suite for Plant Thermal Dynamics & Heat Exchanger ODE Simulation.

Work Package: W053 (Gate G7 / G4)
Classification: TEST [first-principles thermodynamics, zero hardware dependencies]
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

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
from scripts.run_thermal_model_verification import run_thermal_model_verification


def test_heat_exchanger_energy_conservation() -> None:
    hx = CounterFlowHeatExchanger(HeatExchangerConfig(U_hx=1200.0, A_hx=3.0))

    # Balanced streams
    st1 = hx.step(T_hot_in=85.0, T_cold_in=15.0, m_dot_hot=1.0, m_dot_cold=1.0)
    assert st1.energy_residual < 1e-9
    assert st1.epsilon > 0.0
    assert 15.0 < st1.T_cold_out < 85.0
    assert 15.0 < st1.T_hot_out < 85.0

    # Unbalanced streams (C_r != 1.0)
    st2 = hx.step(T_hot_in=95.0, T_cold_in=25.0, m_dot_hot=0.4, m_dot_cold=1.2)
    assert st2.energy_residual < 1e-9
    assert st2.q_hx > 0.0


def test_heat_exchanger_zero_flow_and_negative_flow_guards() -> None:
    hx = CounterFlowHeatExchanger()

    # Zero hot flow
    st_zero_hot = hx.step(T_hot_in=80.0, T_cold_in=20.0, m_dot_hot=0.0, m_dot_cold=1.0)
    assert st_zero_hot.q_hx == 0.0
    assert st_zero_hot.epsilon == 0.0
    assert st_zero_hot.T_hot_out == 80.0
    assert st_zero_hot.T_cold_out == 20.0

    # Zero cold flow
    st_zero_cold = hx.step(T_hot_in=80.0, T_cold_in=20.0, m_dot_hot=1.0, m_dot_cold=0.0)
    assert st_zero_cold.q_hx == 0.0
    assert st_zero_cold.epsilon == 0.0


def test_heater_actuator_lag_and_saturation() -> None:
    heater = HeaterActuator(Q_max=12000.0, tau_heater=1.5)

    # Initial state
    assert heater.current_power == 0.0

    # Step command 50% (target 6000 W)
    heater.step(cmd_percent=50.0, dt=1.5, liquid_height=1.0)
    assert 3000.0 < heater.current_power < 4500.0  # Approx 63.2% of 6000 = 3792 W

    # Converge to 50%
    heater.step(cmd_percent=50.0, dt=10.0, liquid_height=1.0)
    assert abs(heater.current_power - 6000.0) < 50.0

    # Saturation check: cmd > 100% clamps to Q_max
    heater.step(cmd_percent=150.0, dt=10.0, liquid_height=1.0)
    assert abs(heater.current_power - 12000.0) < 50.0


def test_heater_dry_run_interlock() -> None:
    heater = HeaterActuator(Q_max=10000.0, tau_heater=1.0)
    heater.current_power = 8000.0

    # Liquid level dry (0.002 m < 0.005 m cutoff)
    p_after = heater.step(cmd_percent=100.0, dt=5.0, liquid_height=0.002)
    assert p_after < 100.0  # Target was forced to 0 W


def test_rtd_sensor_dynamics_and_noise() -> None:
    sensor = RTDSensorModel(name="RTD_Test", tau_sensor=1.0, sigma_noise=0.02, seed=99)

    # Advance towards 60.0 °C
    for _ in range(15):
        t_m, ma, raw, qc, qw = sensor.step(60.0, dt=0.5)

    assert abs(t_m - 60.0) < 0.1
    # 60 C / 150 C = 0.4 -> 4.0 + 0.4 * 16.0 = 10.4 mA
    assert abs(ma - 10.4) < 0.1
    assert abs(raw - int(0.4 * 32000)) <= 30
    assert qc == QualityCode.GOOD


def test_rtd_sensor_fault_injection() -> None:
    sensor = RTDSensorModel(name="RTD_Fault", tau_sensor=1.0, sigma_noise=0.0)

    # Burnout
    sensor.burnout_fault = True
    _, ma_b, raw_b, qc_b, qw_b = sensor.step(50.0, dt=0.1)
    assert ma_b < 3.6
    assert raw_b < 0
    assert qc_b == QualityCode.BAD

    sensor.burnout_fault = False

    # Short
    sensor.short_fault = True
    _, ma_s, raw_s, qc_s, qw_s = sensor.step(50.0, dt=0.1)
    assert ma_s > 21.0
    assert raw_s > 32000
    assert qc_s == QualityCode.BAD


def test_tank_thermal_plant_heating_cooling_cycles() -> None:
    cfg = ThermalConfig(T_initial=20.0, T_ambient=20.0, tank_area=1.0)
    plant = TankThermalPlantModel(config=cfg)

    # Heat up
    for _ in range(30):
        step_res = plant.step(
            dt=1.0,
            liquid_height=1.0,
            inflow_rate_lps=0.0,
            T_inflow=20.0,
            heater_cmd_pct=100.0,
        )

    t_hot = plant.temperature
    assert t_hot > 20.0
    assert step_res["q_heat"] > 0.0

    # Cool down
    for _ in range(30):
        step_res = plant.step(
            dt=1.0,
            liquid_height=1.0,
            inflow_rate_lps=0.5,
            T_inflow=15.0,
            heater_cmd_pct=0.0,
        )

    t_cooled = plant.temperature
    assert t_cooled < t_hot


def test_thermal_logic_unit_register_synchronization() -> None:
    reg_table = RegisterTable()
    reg_table.write_word("%AI1", 16000, privilege=PrivilegeMode.SYSTEM)  # 1.0 m level
    reg_table.write_word("%AQ2", 24000, privilege=PrivilegeMode.SYSTEM)  # 75.0% heater

    unit = ThermalModelLogicUnit(setpoint_c=70.0)

    # Execute 20 cycles
    for _ in range(20):
        unit.execute_logic(reg_table, dt=0.1)

    # Check registers
    raw_ai3 = reg_table.read_word("%AI3")
    raw_ai4 = reg_table.read_word("%AI4")
    r151_sp = reg_table.read_word("%R151")
    r152_t1 = reg_table.read_word("%R152")
    r154_ctrl = reg_table.read_word("%R154")
    r155_u = reg_table.read_word("%R155")
    r150_stat = reg_table.read_word("%R150")

    assert raw_ai3 > 0
    assert raw_ai4 > 0
    assert r151_sp == 700  # 70.0 °C
    assert r152_t1 > 0
    assert r154_ctrl > 0
    assert r155_u == 750  # 75.0%
    assert (r150_stat & 0x01) == 0x01  # Heater running


def test_thermal_verification_runner_contract(tmp_path: Path) -> None:
    test_evidence_file = tmp_path / "thermal_evidence_test.json"
    result = run_thermal_model_verification(output_path=test_evidence_file)

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert result["data"]["all_passed"] is True
    assert test_evidence_file.exists()

    with open(test_evidence_file, "r", encoding="utf-8") as f:
        payload = json.load(f)
    assert payload["status"] == "success"
    assert len(payload["data"]["assertions"]) >= 8
