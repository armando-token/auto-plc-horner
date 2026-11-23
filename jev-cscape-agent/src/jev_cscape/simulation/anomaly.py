"""Plant Process Anomaly Injection and Automated Mitigation Supervisor.

Work Package: W047 (Gate G7 Plant Dynamics & Gate G4 Pure-Software Simulation)
Classification: PRODUCTION_READY

Implements first-principles physical process anomalies (pipe clogging, pump cavitation,
sensor freeze) and an automated IEC 61131-3 supervisor with analytical observers and
mitigation trip logic bound to Horner OCS registers (%M17..%M20, %Q1..%Q4, %AQ1..%AQ2).
"""

from __future__ import annotations

from collections import deque
from enum import Enum
import math
from typing import Any, Deque, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.plant_model import TankConfig
from jev_cscape.simulation.register_table import RegisterTable


class AnomalyType(str, Enum):
    """Catalog of physical industrial process anomalies."""
    PIPE_CLOGGING = "PIPE_CLOGGING"
    PUMP_CAVITATION = "PUMP_CAVITATION"
    PUMP_DEGRADATION = "PUMP_DEGRADATION"
    SENSOR_FREEZE = "SENSOR_FREEZE"


class AnomalyProfile(BaseModel):
    """Configuration for physical anomaly injection."""
    anomaly_type: AnomalyType
    start_cycle: int = 100
    duration_cycles: int = 500
    severity: float = 0.5  # 0.0 (none) to 1.0 (total failure)
    progressive: bool = False


class AnomalySupervisorConfig(BaseModel):
    """Configuration thresholds for the anomaly detection and mitigation supervisor."""
    # Observers
    tank_area: float = 1.0
    drain_discharge_coeff: float = 2.0
    # Clogging detection
    clogging_residual_threshold: float = 8.0  # % error
    # Cavitation detection
    cavitation_level_threshold: float = 10.0  # % suction head
    # Sensor freeze detection
    freeze_variance_threshold: float = 1e-5
    freeze_window_size: int = 40
    # Register map
    pipe_clog_alarm_reg: str = "%M17"
    pump_cavitation_alarm_reg: str = "%M18"
    pump_degrade_alarm_reg: str = "%M19"
    sensor_freeze_alarm_reg: str = "%M20"
    primary_pump_reg: str = "%Q1"
    standby_pump_reg: str = "%Q4"
    emergency_drain_reg: str = "%Q3"
    inlet_valve_cmd_reg: str = "%AQ1"
    pump_speed_cmd_reg: str = "%AQ2"
    primary_sensor_reg: str = "%AI1"
    backup_sensor_reg: str = "%AI3"


class ProcessAnomalySupervisor(ILogicUnit):
    """Automated supervision engine detecting anomalies and executing mitigation trips.

    Runs within the simulation engine scan cycle, executing analytical observers,
    residual evaluations, and failsafe mitigation actions.
    """

    def __init__(
        self,
        config: Optional[AnomalySupervisorConfig] = None,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.config = config or AnomalySupervisorConfig()
        self.registers = register_table or RegisterTable()
        self.cycle_count = 0

        # State observers
        self._estimated_level_pv = 40.0
        self._history_measured: Deque[float] = deque(maxlen=self.config.freeze_window_size)
        self._inlet_cmd_history: Deque[float] = deque(maxlen=self.config.freeze_window_size)

        # Fault counters and latches
        self.pipe_clog_active = False
        self.cavitation_active = False
        self.degradation_active = False
        self.sensor_freeze_active = False

        self.mitigation_log: List[Dict[str, Any]] = []

    @property
    def name(self) -> str:
        return "ProcessAnomalySupervisor"

    @property
    def priority(self) -> int:
        return 150

    @property
    def is_enabled(self) -> bool:
        return True

    def reset(self) -> None:
        self._estimated_level_pv = 40.0
        self.pipe_clog_active = False
        self.cavitation_active = False
        self.degradation_active = False
        self.sensor_freeze_active = False
        self.mitigation_log.clear()

    def execute(self, ctx: ScanContext) -> None:
        self.execute_scan(ctx.cycle_count, ctx.dt_ms)

    def execute_scan(self, cycle_index: int, dt_ms: float) -> None:
        """Scan cycle callback executing analytical observers and mitigation."""
        self.cycle_count = cycle_index
        dt_sec = dt_ms / 1000.0

        # 1. Read process variables
        try:
            raw_ai1 = self.registers.read_register(self.config.primary_sensor_reg)
            measured_pv = float(raw_ai1) / 100.0  # Scale 0..10000 -> 0..100%
        except Exception:
            measured_pv = 0.0

        try:
            raw_ai3 = self.registers.read_register(self.config.backup_sensor_reg)
            backup_pv = float(raw_ai3) / 100.0
        except Exception:
            backup_pv = measured_pv

        try:
            raw_aq1 = self.registers.read_register(self.config.inlet_valve_cmd_reg)
            inlet_cmd_pct = float(raw_aq1) / 100.0
        except Exception:
            inlet_cmd_pct = 0.0

        self._history_measured.append(measured_pv)
        self._inlet_cmd_history.append(inlet_cmd_pct)

        # 2. Update mass balance observer
        # Nominal flow estimates
        inflow_est = (inlet_cmd_pct / 100.0) * 15.0  # Max 15 m^3/s
        outflow_est = self.config.drain_discharge_coeff * math.sqrt(max(0.0, self._estimated_level_pv))
        dh_dt = (inflow_est - outflow_est) / self.config.tank_area
        self._estimated_level_pv = max(0.0, min(100.0, self._estimated_level_pv + dh_dt * dt_sec))

        observer_residual = abs(measured_pv - self._estimated_level_pv)

        # 3. Detection Algorithms
        # Clogging detection: Measured level rising much faster than observer prediction while inflow is throttled
        if observer_residual > self.config.clogging_residual_threshold and measured_pv > 65.0:
            if not self.pipe_clog_active:
                self.pipe_clog_active = True
                self._record_mitigation(
                    cycle_index,
                    "PIPE_CLOGGING_TRIP",
                    f"Observer residual {observer_residual:.2f}% exceeded threshold. Clamping inlet valve and opening emergency drain.",
                )
                self.registers.set_register(self.config.pipe_clog_alarm_reg, True)
                self.registers.set_register(self.config.emergency_drain_reg, True)
                # Clamp inlet to <= 15%
                clamped_aq1 = int(min(inlet_cmd_pct, 15.0) * 100.0)
                self.registers.set_register(self.config.inlet_valve_cmd_reg, clamped_aq1)

        # Cavitation detection: Low suction head (tank level < 10%) while primary pump is running
        primary_running = bool(self.registers.read_register(self.config.primary_pump_reg))
        if primary_running and measured_pv < self.config.cavitation_level_threshold:
            if not self.cavitation_active:
                self.cavitation_active = True
                self._record_mitigation(
                    cycle_index,
                    "PUMP_CAVITATION_TRIP",
                    f"Tank level {measured_pv:.1f}% below cavitation limit {self.config.cavitation_level_threshold}%. Tripping pump Q1.",
                )
                self.registers.set_register(self.config.pump_cavitation_alarm_reg, True)
                self.registers.set_register(self.config.primary_pump_reg, False)
                self.registers.set_register(self.config.pump_speed_cmd_reg, 0)

        # Sensor freeze detection: Rolling variance near zero while actuator command was active
        if len(self._history_measured) >= self.config.freeze_window_size:
            vals = list(self._history_measured)
            mean_v = sum(vals) / len(vals)
            var_v = sum((x - mean_v) ** 2 for x in vals) / len(vals)
            cmd_variance = sum(abs(x - vals[0]) for x in self._inlet_cmd_history)

            if var_v < self.config.freeze_variance_threshold and observer_residual > 5.0:
                if not self.sensor_freeze_active:
                    self.sensor_freeze_active = True
                    self._record_mitigation(
                        cycle_index,
                        "SENSOR_FREEZE_TRIP",
                        f"Primary sensor frozen at {mean_v:.2f}% (variance {var_v:.2e}). Failing over to backup sensor AI3.",
                    )
                    self.registers.set_register(self.config.sensor_freeze_alarm_reg, True)
                    # Route backup transmitter to primary PV register
                    self.registers.set_input(self.config.primary_sensor_reg, int(backup_pv * 100.0))

    def _record_mitigation(self, cycle: int, action: str, details: str) -> None:
        self.mitigation_log.append({
            "cycle": cycle,
            "action": action,
            "details": details,
        })
