"""Industrial ODVA CIP Energy Management Specification & Power Quality Telemetry Engine.

Work Package: W190 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Standards:
- ODVA CIP Energy Management Specification (Energy Object Class 0x4E, Energy Base Object Class 0x4F).
- Power and energy telemetry: Active Power (kW), Reactive Power (kVAR), Apparent Power (kVA),
  Power Factor (cos phi), Active Energy Accumulation (kWh), Total Harmonic Distortion THD (%).
- Operating energy states: 0=Non-Operational, 1=Operational/Normal, 2=Standby, 3=EnergySaving, 4=Sleep, 5=Faulted.
- IEEE 519: Recommended Practice and Requirements for Harmonic Control in Electric Power Systems.
- IEC 61131-3 Programmable Controllers - Part 3: Programming Languages (Structured Text).
- Horner OCS Memory Space: %R1510..%R1517, %M352..%M353.

Architecture:
1. Strict Pure IEC 61131-3 Structured Text POU:
   - 'CipEnergyManagementSync' bound to Horner OCS memory space (%R1510..%R1517, %M352..%M353).
   - Anti-ladder security guard: Intercepts ladder constructs with ERR_LADDER_FORBIDDEN
     using SecurityGuard.assert_pure_st_content and STParser.

2. ODVA CIP Energy Object Class 0x4E & Base Energy Object Class 0x4F:
   - CipEnergyState (IntEnum: NonOperational=0, Operational=1, Standby=2, EnergySaving=3, Sleep=4, Faulted=5).
   - CipEnergyPowerType (IntEnum: Active=1, Reactive=2, Apparent=3).
   - CipEnergyDiagnosticCode (IntEnum: OK=0x0000, 0xD101..0xD104).
   - CipEnergySnapshot dataclass (active_kw, reactive_kvar, apparent_kva, pf, energy_kwh, thd_pct).
   - CipEnergyObject: ODVA Class 0x4E / Class 0x4F attributes tracking energy baseline,
     peak demand threshold (kW), and power factor alarm (< 0.85).

3. Power Triangle Math & Quality Telemetry:
   - 3-phase power triangle calculation: S = sqrt(P^2 + Q^2), PF = P / S.
   - High-precision active energy integration: kWh = sum(P * dt / 3600.0).
   - Power quality THD harmonic calculation (IEEE 519: > 5.0% warning, > 8.0% trip).
   - Peak demand threshold detection and energy-saving state transition.
   - Process safety interlocks & diagnostic trips (0xD101..0xD104).

4. Horner OCS Memory Space Integration:
   - %R1510: ActivePowerKwScaled (INT16, scaled x10 kW, e.g. 1250 = 125.0 kW)
   - %R1511: ReactivePowerKvarScaled (INT16, scaled x10 kVAR, e.g. 450 = 45.0 kVAR)
   - %R1512: ApparentPowerKvaScaled (INT16, scaled x10 kVA, e.g. 1328 = 132.8 kVA)
   - %R1513: PowerFactorScaled (INT16, scaled x1000, e.g. 941 = 0.941)
   - %R1514: EnergyAccumulationKwhHighWord (INT16)
   - %R1515: EnergyAccumulationKwhLowWord (INT16, signed)
   - %R1516: TotalHarmonicDistortionThdScaled (INT16, scaled x10 %, e.g. 32 = 3.2 %)
   - %R1517: DiagnosticStatusCode (0x0000=OK, 0xD101..0xD104)
   - %M352: EnergyMeteringHealthy (BOOL, True when power quality and metering are normal)
   - %M353: EnergyPeakDemandTrip (BOOL, True on peak demand breach or THD trip)
   - PrivilegeMode.SYSTEM used for all RegisterTable writes.

5. Deterministic 9-Stage Verification Suite:
   - run_cip_energy_verification(output_path: Optional[str] = None) -> Dict[str, Any]
   - Returns strict 4-state contract response: {'status': 'success', 'stages_passed': 9, 'total_stages': 9, 'data': {...}}.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import json
import math
from pathlib import Path
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import HardwareLockoutError, LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Threshold Definitions (ODVA CIP Energy & IEEE 519)
# ============================================================================

CIP_ENERGY_CLASS_ID: int = 0x4E       # ODVA CIP Energy Object Class ID
CIP_ENERGY_BASE_CLASS_ID: int = 0x4F  # ODVA CIP Energy Base Object Class ID

NOMINAL_LINE_VOLTAGE_RMS: float = 480.0       # 480 V nominal 3-phase line-to-line
NOMINAL_SYSTEM_FREQUENCY_HZ: float = 60.0     # 60.0 Hz nominal frequency
DEFAULT_PEAK_DEMAND_THRESHOLD_KW: float = 150.0 # 150.0 kW default peak demand threshold
DEFAULT_ENERGY_BASELINE_KW: float = 50.0       # 50.0 kW baseline power
POWER_FACTOR_ALARM_THRESHOLD: float = 0.85    # PF < 0.85 triggers low PF alarm

# IEEE 519 Power Quality Thresholds
IEEE519_THD_WARNING_THRESHOLD_PCT: float = 5.0 # 5.0% THD warning threshold
IEEE519_THD_TRIP_THRESHOLD_PCT: float = 8.0    # 8.0% THD trip threshold

# Voltage Sag / Swell Limits (ANSI C84.1 Range A: +/- 10%)
VOLTAGE_SAG_THRESHOLD_VOLTS: float = 432.0     # 480V * 0.90
VOLTAGE_SWELL_THRESHOLD_VOLTS: float = 528.0   # 480V * 1.10

# Reverse Power Protection Limit (kW)
REVERSE_POWER_TRIP_THRESHOLD_KW: float = -0.1  # P < -0.1 kW indicates generator backfeed

# Phase Imbalance Limit (%)
PHASE_IMBALANCE_LIMIT_PCT: float = 3.0         # Imbalance > 3.0% triggers trip


# ============================================================================
# 2. Protocol Enums & Diagnostic Codes
# ============================================================================

class CipEnergyState(IntEnum):
    """ODVA CIP Energy Base Object (Class 0x4F) Operating Energy States."""
    NON_OPERATIONAL = 0  # Device de-energized, unmetered, or out of service
    OPERATIONAL     = 1  # Standard operational running state with active metering
    STANDBY         = 2  # Low-power standby state (idle equipment)
    ENERGY_SAVING   = 3  # Active load reduction / demand-shedding state
    SLEEP           = 4  # Deep low-power sleep state
    FAULTED         = 5  # Tripped due to electrical, thermal, or diagnostic fault

    # Compatibility Aliases
    NonOperational = 0
    Operational    = 1
    Normal         = 1
    NORMAL         = 1
    Standby        = 2
    EnergySaving   = 3
    Sleep          = 4
    Faulted        = 5


class CipEnergyPowerType(IntEnum):
    """ODVA CIP Energy Power and Telemetry Measurement Types."""
    ACTIVE   = 1  # Real / Active Power (kW)
    REACTIVE = 2  # Reactive Power (kVAR)
    APPARENT = 3  # Apparent Power (kVA)

    # Aliases
    Active   = 1
    Real     = 1
    Reactive = 2
    Apparent = 3


class CipEnergyDiagnosticCode(IntEnum):
    """Horner OCS %R1517 Diagnostic Event Codes for CIP Energy (W190)."""
    OK                  = 0x0000  # Normal healthy metering and power quality
    VOLTAGE_SAG_SWELL   = 0xD101  # Voltage sag (<432V) or swell (>528V) event
    THD_LIMIT_EXCEEDED  = 0xD102  # Total Harmonic Distortion exceeded IEEE 519 trip threshold (>8.0%)
    REVERSE_POWER_TRIP  = 0xD103  # Reverse power backfeed detected (P < -0.1 kW)
    PHASE_IMBALANCE     = 0xD104  # Voltage or current unbalance exceeded limit (>3.0%)

    # Convenience aliases
    ERR_VOLTAGE_SAG_SWELL   = 0xD101
    ERR_THD_LIMIT_EXCEEDED  = 0xD102
    ERR_REVERSE_POWER_TRIP  = 0xD103
    ERR_PHASE_IMBALANCE     = 0xD104
    CIP_ENERGY_ERR_VOLTAGE_SAG_SWELL  = 0xD101
    CIP_ENERGY_ERR_THD_LIMIT_EXCEEDED = 0xD102
    CIP_ENERGY_ERR_REVERSE_POWER_TRIP = 0xD103
    CIP_ENERGY_ERR_PHASE_IMBALANCE    = 0xD104
    VoltageSagSwell         = 0xD101
    ThdLimitExceeded        = 0xD102
    ReversePowerTrip        = 0xD103
    PhaseImbalance          = 0xD104


# ============================================================================
# 3. Telemetry Snapshot Dataclass
# ============================================================================

@dataclass
class CipEnergySnapshot:
    """Comprehensive instantaneous energy and power quality telemetry snapshot."""
    active_kw: float = 0.0
    reactive_kvar: float = 0.0
    apparent_kva: float = 0.0
    pf: float = 1.0
    energy_kwh: float = 0.0
    thd_pct: float = 0.0
    energy_state: CipEnergyState = CipEnergyState.OPERATIONAL
    diagnostic_code: CipEnergyDiagnosticCode = CipEnergyDiagnosticCode.OK
    voltage_rms: float = NOMINAL_LINE_VOLTAGE_RMS
    current_rms: float = 0.0
    frequency_hz: float = NOMINAL_SYSTEM_FREQUENCY_HZ
    timestamp_s: float = 0.0
    peak_demand_tripped: bool = False
    metering_healthy: bool = True
    power_factor_alarm: bool = False
    thd_warning: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert snapshot to primitive dictionary."""
        return {
            "active_kw": round(self.active_kw, 3),
            "reactive_kvar": round(self.reactive_kvar, 3),
            "apparent_kva": round(self.apparent_kva, 3),
            "pf": round(self.pf, 4),
            "energy_kwh": round(self.energy_kwh, 4),
            "thd_pct": round(self.thd_pct, 2),
            "energy_state": self.energy_state.name,
            "diagnostic_code": hex(int(self.diagnostic_code)),
            "voltage_rms": round(self.voltage_rms, 2),
            "current_rms": round(self.current_rms, 2),
            "frequency_hz": round(self.frequency_hz, 2),
            "timestamp_s": round(self.timestamp_s, 3),
            "peak_demand_tripped": self.peak_demand_tripped,
            "metering_healthy": self.metering_healthy,
            "power_factor_alarm": self.power_factor_alarm,
            "thd_warning": self.thd_warning,
        }


# ============================================================================
# 4. Math & Physical Calculation Helpers
# ============================================================================

def calculate_power_triangle(active_kw: float, reactive_kvar: float) -> Tuple[float, float]:
    """Calculate apparent power S (kVA) and power factor PF from active P and reactive Q.

    Formulas:
        S = sqrt(P^2 + Q^2)
        PF = P / S   (for S > 0, else 1.0; clamped to [-1.0, 1.0])
    """
    p = float(active_kw)
    q = float(reactive_kvar)
    s = math.sqrt(p * p + q * q)
    if s < 1e-9:
        pf = 1.0
    else:
        pf = p / s
        pf = max(-1.0, min(1.0, pf))
    return s, pf


def calculate_3phase_power(
    v_line_rms: float,
    i_line_rms: float,
    pf: float = 1.0,
) -> Tuple[float, float, float]:
    """Calculate 3-phase power triangle (P kW, Q kVAR, S kVA) from balanced RMS line measurements.

    Formulas:
        S = (sqrt(3) * V_LL * I_L) / 1000.0  (kVA)
        P = S * PF                           (kW)
        Q = sqrt(max(0, S^2 - P^2))          (kVAR)
    """
    v = max(0.0, float(v_line_rms))
    i = max(0.0, float(i_line_rms))
    pf_clamped = max(-1.0, min(1.0, float(pf)))

    s = (math.sqrt(3.0) * v * i) / 1000.0
    p = s * pf_clamped
    q_sq = max(0.0, s * s - p * p)
    q = math.sqrt(q_sq)
    return p, q, s


def calculate_thd(fundamental_rms: float, harmonic_rms_values: Sequence[float]) -> float:
    """Compute Total Harmonic Distortion (%) per IEEE 519 definition.

    Formula:
        THD = (sqrt(sum(V_h^2)) / V_1) * 100.0%
    """
    v1 = float(fundamental_rms)
    if v1 <= 1e-6 or not harmonic_rms_values:
        return 0.0

    sum_sq = sum(float(h) ** 2 for h in harmonic_rms_values)
    harmonic_rss = math.sqrt(sum_sq)
    return (harmonic_rss / v1) * 100.0


def encode_dint_words(value_32: int) -> Tuple[int, int]:
    """Encode 32-bit integer into (high_word, low_word) signed INT16 pair for Horner OCS."""
    val = int(value_32) & 0xFFFFFFFF
    high = (val >> 16) & 0xFFFF
    low = val & 0xFFFF
    high_s = high - 65536 if high > 32767 else high
    low_s = low - 65536 if low > 32767 else low
    return high_s, low_s


def decode_dint_words(high_word: int, low_word: int) -> int:
    """Reconstruct 32-bit signed integer from Horner OCS (high_word, low_word) pair."""
    h = int(high_word) & 0xFFFF
    l = int(low_word) & 0xFFFF
    val_32 = (h << 16) | l
    if val_32 >= 0x80000000:
        val_32 -= 0x100000000
    return val_32


def safe_write_word(rt: RegisterTable, address: str, value: int) -> None:
    """Safely write signed 16-bit word to RegisterTable with SYSTEM privilege."""
    val_16 = int(value) & 0xFFFF
    if val_16 > 32767:
        val_16 -= 65536
    rt.write_word(address, val_16, privilege=PrivilegeMode.SYSTEM)


def safe_write_uword(rt: RegisterTable, address: str, value: int) -> None:
    """Safely write unsigned 16-bit word to RegisterTable with SYSTEM privilege."""
    val_16 = int(value) & 0xFFFF
    if val_16 > 32767:
        val_16 -= 65536
    rt.write_word(address, val_16, privilege=PrivilegeMode.SYSTEM)


def safe_write_bit(rt: RegisterTable, address: str, value: bool) -> None:
    """Safely write discrete coil bit to RegisterTable with SYSTEM privilege."""
    rt.write_bit(address, bool(value), privilege=PrivilegeMode.SYSTEM)


# ============================================================================
# 5. Pure IEC 61131-3 Structured Text POU
# ============================================================================

CIP_ENERGY_MANAGEMENT_SYNC_POU: str = """PROGRAM CipEnergyManagementSync
VAR
    (* Horner OCS Mapped Registers (W190 - CIP Energy Management Engine) *)
    ActivePowerKwScaled          AT %R1510 : INT;    (* Active Power scaled x10 kW (1250 = 125.0 kW) *)
    ReactivePowerKvarScaled      AT %R1511 : INT;    (* Reactive Power scaled x10 kVAR (450 = 45.0 kVAR) *)
    ApparentPowerKvaScaled       AT %R1512 : INT;    (* Apparent Power scaled x10 kVA (1328 = 132.8 kVA) *)
    PowerFactorScaled            AT %R1513 : INT;    (* Power Factor scaled x1000 (941 = 0.941) *)
    EnergyAccumulationKwhHighWord AT %R1514 : INT;   (* Energy Accumulation High Word (kWh) *)
    EnergyAccumulationKwhLowWord  AT %R1515 : INT;   (* Energy Accumulation Low Word (kWh, signed) *)
    TotalHarmonicDistortionThdScaled AT %R1516 : INT; (* Total Harmonic Distortion scaled x10 % (32 = 3.2 %) *)
    DiagnosticStatusCode         AT %R1517 : UINT;   (* Diagnostic Status Code (0x0000=OK, 0xD101..0xD104) *)

    (* Discrete Metering & Process Safety Coils *)
    EnergyMeteringHealthy        AT %M352  : BOOL;   (* TRUE when power quality & metering normal *)
    EnergyPeakDemandTrip         AT %M353  : BOOL;   (* TRUE on peak demand breach or THD trip *)
END_VAR
VAR
    EnergyManagementActive       : BOOL;
    PowerFactorWarning           : BOOL;
END_VAR

(* Power Quality & Diagnostic Interlock Evaluation *)
IF (DiagnosticStatusCode <> 0) OR EnergyPeakDemandTrip THEN
    EnergyMeteringHealthy := FALSE;
    EnergyManagementActive := FALSE;
ELSE
    EnergyMeteringHealthy := TRUE;
    EnergyManagementActive := TRUE;
END_IF;

IF (PowerFactorScaled < 850) AND (ApparentPowerKvaScaled > 10) THEN
    PowerFactorWarning := TRUE;
ELSE
    PowerFactorWarning := FALSE;
END_IF;
END_PROGRAM
"""

CipEnergyManagementSyncPOU = CIP_ENERGY_MANAGEMENT_SYNC_POU
CIP_ENERGY_POU = CIP_ENERGY_MANAGEMENT_SYNC_POU


# ============================================================================
# 6. ODVA CIP Energy Object (Class 0x4E) & Base Energy Object (Class 0x4F)
# ============================================================================

@dataclass
class CipEnergyObject:
    """ODVA CIP Energy Management Specification - Energy Object Implementation.

    Supports:
    - Energy Object (Class 0x4E) attributes:
        1: EnergyType (1 = Electrical)
        2: ActiveEnergyKwh (float)
        3: ApparentEnergyKvah (float)
        4: ReactiveEnergyKvarh (float)
        5: ActivePowerKw (float)
        6: ReactivePowerKvar (float)
        7: ApparentPowerKva (float)
        8: PowerFactor (float, cos phi)
        9: VoltageRms (float, V)
        10: CurrentRms (float, A)
        11: TotalHarmonicDistortionThd (float, %)
        12: PeakDemandKw (float, max kW recorded)
        13: PeakDemandThresholdKw (float, kW threshold)
        14: EnergyBaselineKw (float, baseline power)
        15: PowerFactorAlarm (bool, True if PF < 0.85)
        16: DiagnosticStatusCode (int, 0x0000 or 0xD101..0xD104)

    - Energy Base Object (Class 0x4F) attributes:
        1: EnergyState (CipEnergyState)
        2: SupportedEnergyStates (int bitmask, 0x3F = bits 0..5)
        3: RequestedEnergyState (CipEnergyState)
        4: TimeToStateTransitionMs (int)
        5: ConsumedEnergyKwh (float)
        6: EnergyAccuracyClass (float, e.g. 0.2 for 0.2% revenue meter)
    """

    class_id: int = CIP_ENERGY_CLASS_ID
    instance_id: int = 1

    # Telemetry Attributes (Class 0x4E)
    energy_type: int = 1  # 1 = Electrical
    active_energy_kwh: float = 0.0
    apparent_energy_kvah: float = 0.0
    reactive_energy_kvarh: float = 0.0
    active_power_kw: float = 0.0
    reactive_power_kvar: float = 0.0
    apparent_power_kva: float = 0.0
    power_factor: float = 1.0
    voltage_rms: float = NOMINAL_LINE_VOLTAGE_RMS
    current_rms: float = 0.0
    thd_pct: float = 0.0
    peak_demand_kw: float = 0.0
    peak_demand_threshold_kw: float = DEFAULT_PEAK_DEMAND_THRESHOLD_KW
    energy_baseline_kw: float = DEFAULT_ENERGY_BASELINE_KW
    power_factor_alarm: bool = False
    diagnostic_code: CipEnergyDiagnosticCode = CipEnergyDiagnosticCode.OK

    # Base Energy Attributes (Class 0x4F)
    energy_state: CipEnergyState = CipEnergyState.OPERATIONAL
    supported_energy_states: int = 0x3F  # All states 0..5 supported
    requested_energy_state: CipEnergyState = CipEnergyState.OPERATIONAL
    time_to_transition_ms: int = 0
    accuracy_class: float = 0.2

    def __post_init__(self) -> None:
        self.evaluate_alarms()

    def evaluate_alarms(self) -> None:
        """Evaluate power factor alarm and peak demand threshold."""
        # Power factor alarm threshold (< 0.85 when load is active)
        if self.apparent_power_kva > 1.0 and abs(self.power_factor) < POWER_FACTOR_ALARM_THRESHOLD:
            self.power_factor_alarm = True
        else:
            self.power_factor_alarm = False

        # Peak demand tracking
        if self.active_power_kw > self.peak_demand_kw:
            self.peak_demand_kw = self.active_power_kw

    def get_attribute_single(self, attribute_id: int, class_id: Optional[int] = None) -> Any:
        """Get attribute value by ID conforming to ODVA CIP specification."""
        target_class = class_id if class_id is not None else self.class_id

        if target_class == CIP_ENERGY_CLASS_ID:
            attrs_4e = {
                1: self.energy_type,
                2: self.active_energy_kwh,
                3: self.apparent_energy_kvah,
                4: self.reactive_energy_kvarh,
                5: self.active_power_kw,
                6: self.reactive_power_kvar,
                7: self.apparent_power_kva,
                8: self.power_factor,
                9: self.voltage_rms,
                10: self.current_rms,
                11: self.thd_pct,
                12: self.peak_demand_kw,
                13: self.peak_demand_threshold_kw,
                14: self.energy_baseline_kw,
                15: self.power_factor_alarm,
                16: int(self.diagnostic_code),
            }
            if attribute_id in attrs_4e:
                return attrs_4e[attribute_id]
            raise KeyError(f"ODVA CIP Energy Object (Class 0x4E) does not support Attribute ID {attribute_id}")

        elif target_class == CIP_ENERGY_BASE_CLASS_ID:
            attrs_4f = {
                1: int(self.energy_state),
                2: self.supported_energy_states,
                3: int(self.requested_energy_state),
                4: self.time_to_transition_ms,
                5: self.active_energy_kwh,
                6: self.accuracy_class,
            }
            if attribute_id in attrs_4f:
                return attrs_4f[attribute_id]
            raise KeyError(f"ODVA CIP Base Energy Object (Class 0x4F) does not support Attribute ID {attribute_id}")

        raise ValueError(f"Unsupported CIP Energy Class ID 0x{target_class:02X}")

    def set_attribute_single(self, attribute_id: int, value: Any, class_id: Optional[int] = None) -> bool:
        """Set writable attribute value by ID conforming to ODVA CIP specification."""
        target_class = class_id if class_id is not None else self.class_id

        if target_class == CIP_ENERGY_CLASS_ID:
            if attribute_id == 13:
                self.peak_demand_threshold_kw = max(0.0, float(value))
                self.evaluate_alarms()
                return True
            elif attribute_id == 14:
                self.energy_baseline_kw = max(0.0, float(value))
                return True
            raise PermissionError(f"Class 0x4E Attribute ID {attribute_id} is read-only or not settable")

        elif target_class == CIP_ENERGY_BASE_CLASS_ID:
            if attribute_id == 3:
                req_state = CipEnergyState(int(value))
                self.requested_energy_state = req_state
                self.energy_state = req_state
                return True
            raise PermissionError(f"Class 0x4F Attribute ID {attribute_id} is read-only or not settable")

        raise ValueError(f"Unsupported CIP Energy Class ID 0x{target_class:02X}")

    def get_attribute_all(self, class_id: Optional[int] = None) -> Dict[int, Any]:
        """Query all attributes dictionary for given CIP Class."""
        target_class = class_id if class_id is not None else self.class_id
        if target_class == CIP_ENERGY_CLASS_ID:
            return {
                1: self.energy_type,
                2: self.active_energy_kwh,
                3: self.apparent_energy_kvah,
                4: self.reactive_energy_kvarh,
                5: self.active_power_kw,
                6: self.reactive_power_kvar,
                7: self.apparent_power_kva,
                8: self.power_factor,
                9: self.voltage_rms,
                10: self.current_rms,
                11: self.thd_pct,
                12: self.peak_demand_kw,
                13: self.peak_demand_threshold_kw,
                14: self.energy_baseline_kw,
                15: self.power_factor_alarm,
                16: int(self.diagnostic_code),
            }
        elif target_class == CIP_ENERGY_BASE_CLASS_ID:
            return {
                1: int(self.energy_state),
                2: self.supported_energy_states,
                3: int(self.requested_energy_state),
                4: self.time_to_transition_ms,
                5: self.active_energy_kwh,
                6: self.accuracy_class,
            }
        raise ValueError(f"Unsupported CIP Energy Class ID 0x{target_class:02X}")


# ============================================================================
# 7. CipEnergyEngine (ILogicUnit)
# ============================================================================

class CipEnergyEngine(ILogicUnit):
    """Industrial ODVA CIP Energy & Power Quality Telemetry Simulation Engine."""

    def __init__(
        self,
        baseline_kw: float = DEFAULT_ENERGY_BASELINE_KW,
        peak_demand_threshold_kw: float = DEFAULT_PEAK_DEMAND_THRESHOLD_KW,
        reg_table: Optional[RegisterTable] = None,
        nominal_voltage_rms: float = NOMINAL_LINE_VOLTAGE_RMS,
        nominal_frequency_hz: float = NOMINAL_SYSTEM_FREQUENCY_HZ,
    ) -> None:
        self.reg_table: Optional[RegisterTable] = reg_table
        self.nominal_voltage_rms = float(nominal_voltage_rms)
        self.nominal_frequency_hz = float(nominal_frequency_hz)
        self.peak_demand_threshold_kw = float(peak_demand_threshold_kw)
        self.baseline_kw = float(baseline_kw)

        # Telemetry State Variables
        self.active_power_kw: float = 0.0
        self.reactive_power_kvar: float = 0.0
        self.apparent_power_kva: float = 0.0
        self.power_factor: float = 1.0
        self.energy_accumulation_kwh: float = 0.0
        self.thd_pct: float = 0.0
        self.voltage_rms: float = self.nominal_voltage_rms
        self.current_rms: float = 0.0
        self.frequency_hz: float = self.nominal_frequency_hz
        self.phase_imbalance_pct: float = 0.0

        # CIP Objects & Operating States
        self.cip_object = CipEnergyObject(
            energy_baseline_kw=self.baseline_kw,
            peak_demand_threshold_kw=self.peak_demand_threshold_kw,
            voltage_rms=self.voltage_rms,
        )
        self.state: CipEnergyState = CipEnergyState.OPERATIONAL
        self.diagnostic_code: CipEnergyDiagnosticCode = CipEnergyDiagnosticCode.OK

        # Process Safety Interlock Latches
        self.is_metering_healthy: bool = True
        self.is_peak_demand_tripped: bool = False
        self.is_thd_tripped: bool = False
        self.thd_warning_active: bool = False
        self.power_factor_alarm_active: bool = False

        # Simulation & Scan Watchdogs
        self.elapsed_simulation_ms: float = 0.0
        self.total_scan_cycles: int = 0
        self._enabled: bool = True

        if self.reg_table is not None:
            self.sync_to_registers()

    # ------------------------------------------------------------------------
    # ILogicUnit Interface Implementation
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "cip_energy"

    @property
    def priority(self) -> int:
        return 93

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def execute(self, ctx: ScanContext) -> None:
        """Execute one discrete scan cycle within Horner simulation framework."""
        dt_ms = getattr(ctx, "dt_ms", 10.0)
        self.scan_step(dt=dt_ms / 1000.0)

    def reset(self) -> None:
        """Reset internal engine state and clear latched fault trips."""
        self.reset_fault(force=True)

    # ------------------------------------------------------------------------
    # Discrete Scan Cycle Execution & Energy Integration
    # ------------------------------------------------------------------------

    def scan_step(self, dt: float = 0.01) -> Dict[str, Any]:
        """Advance discrete simulation clock, integrate active energy, and evaluate safety."""
        dt_s = max(0.0, float(dt))
        self.elapsed_simulation_ms += dt_s * 1000.0
        self.total_scan_cycles += 1

        # 1. Integrate Active Energy Accumulation (kWh = kW * dt / 3600.0)
        if self.diagnostic_code != CipEnergyDiagnosticCode.REVERSE_POWER_TRIP:
            energy_increment_kwh = self.active_power_kw * (dt_s / 3600.0)
            self.energy_accumulation_kwh += energy_increment_kwh

        # 2. Evaluate Continuous Process Safety Interlocks & Limits
        self._evaluate_safety_limits()

        # 3. Synchronize Internal CipEnergyObject
        self._update_cip_object()

        # 4. Synchronize Horner Register Table
        self.sync_to_registers()

        return self.get_snapshot().to_dict()

    # ------------------------------------------------------------------------
    # Telemetry Update & Measurement APIs
    # ------------------------------------------------------------------------

    def update_telemetry(
        self,
        active_kw: float,
        reactive_kvar: float,
        voltage_rms: Optional[float] = None,
        thd_pct: Optional[float] = None,
        current_rms: Optional[float] = None,
        imbalance_pct: Optional[float] = None,
    ) -> None:
        """Update instantaneous electrical measurements and re-evaluate power triangle."""
        self.active_power_kw = float(active_kw)
        self.reactive_power_kvar = float(reactive_kvar)

        # 3-Phase Power Triangle Math
        self.apparent_power_kva, self.power_factor = calculate_power_triangle(
            self.active_power_kw, self.reactive_power_kvar
        )

        if voltage_rms is not None:
            self.voltage_rms = float(voltage_rms)
        if thd_pct is not None:
            self.thd_pct = max(0.0, float(thd_pct))
        if current_rms is not None:
            self.current_rms = max(0.0, float(current_rms))
        elif self.voltage_rms > 1.0:
            # Derived balanced line current from apparent power: I = S*1000 / (sqrt(3)*V)
            self.current_rms = (self.apparent_power_kva * 1000.0) / (math.sqrt(3.0) * self.voltage_rms)

        if imbalance_pct is not None:
            self.phase_imbalance_pct = max(0.0, float(imbalance_pct))

        self._evaluate_safety_limits()
        self._update_cip_object()
        self.sync_to_registers()

    def set_3phase_measurements(
        self,
        v_line_rms: float,
        i_line_rms: float,
        pf: float = 1.0,
        thd_pct: float = 0.0,
    ) -> None:
        """Update 3-phase line measurements directly calculating P, Q, and S."""
        p, q, s = calculate_3phase_power(v_line_rms, i_line_rms, pf)
        self.active_power_kw = p
        self.reactive_power_kvar = q
        self.apparent_power_kva = s
        self.power_factor = float(pf)
        self.voltage_rms = float(v_line_rms)
        self.current_rms = float(i_line_rms)
        self.thd_pct = max(0.0, float(thd_pct))

        self._evaluate_safety_limits()
        self._update_cip_object()
        self.sync_to_registers()

    def set_harmonic_spectrum(self, fundamental_rms: float, harmonics: Sequence[float]) -> float:
        """Set discrete harmonic components and compute IEEE 519 Total Harmonic Distortion."""
        thd = calculate_thd(fundamental_rms, harmonics)
        self.thd_pct = thd
        self.voltage_rms = float(fundamental_rms)
        self._evaluate_safety_limits()
        self._update_cip_object()
        self.sync_to_registers()
        return thd

    # ------------------------------------------------------------------------
    # Safety Limits, Threshold Checking, & State Management
    # ------------------------------------------------------------------------

    def _evaluate_safety_limits(self) -> None:
        """Evaluate electrical limits, trip conditions, and energy state transitions."""
        # 1. Reverse Power Trip (P < -0.1 kW)
        if self.active_power_kw < REVERSE_POWER_TRIP_THRESHOLD_KW:
            self.trip_fault(
                CipEnergyDiagnosticCode.REVERSE_POWER_TRIP,
                f"Reverse power backfeed ({self.active_power_kw:.2f} kW < {REVERSE_POWER_TRIP_THRESHOLD_KW} kW)",
            )
            return

        # 2. Voltage Sag / Swell Check (432V .. 528V)
        if self.voltage_rms < VOLTAGE_SAG_THRESHOLD_VOLTS or self.voltage_rms > VOLTAGE_SWELL_THRESHOLD_VOLTS:
            self.trip_fault(
                CipEnergyDiagnosticCode.VOLTAGE_SAG_SWELL,
                f"Voltage excursion ({self.voltage_rms:.1f} V outside {VOLTAGE_SAG_THRESHOLD_VOLTS}..{VOLTAGE_SWELL_THRESHOLD_VOLTS} V)",
            )
            return

        # 3. Phase Imbalance Check (> 3.0%)
        if self.phase_imbalance_pct > PHASE_IMBALANCE_LIMIT_PCT:
            self.trip_fault(
                CipEnergyDiagnosticCode.PHASE_IMBALANCE,
                f"Phase imbalance ({self.phase_imbalance_pct:.1f}% > {PHASE_IMBALANCE_LIMIT_PCT}%)",
            )
            return

        # 4. IEEE 519 THD Quality Evaluation
        if self.thd_pct > IEEE519_THD_TRIP_THRESHOLD_PCT:
            self.is_thd_tripped = True
            self.is_peak_demand_tripped = True
            self.trip_fault(
                CipEnergyDiagnosticCode.THD_LIMIT_EXCEEDED,
                f"THD trip ({self.thd_pct:.2f}% > {IEEE519_THD_TRIP_THRESHOLD_PCT}%)",
            )
            return
        elif self.thd_pct > IEEE519_THD_WARNING_THRESHOLD_PCT:
            self.thd_warning_active = True
        else:
            self.thd_warning_active = False

        # 5. Peak Demand Threshold Check
        if self.active_power_kw > self.peak_demand_threshold_kw:
            self.is_peak_demand_tripped = True
            # Transition to energy saving state if operational
            if self.state == CipEnergyState.OPERATIONAL:
                self.state = CipEnergyState.ENERGY_SAVING

        # 6. Power Factor Alarm Evaluation (< 0.85 when load is active)
        if self.apparent_power_kva > 1.0 and abs(self.power_factor) < POWER_FACTOR_ALARM_THRESHOLD:
            self.power_factor_alarm_active = True
        else:
            self.power_factor_alarm_active = False

        # 7. Health Status Synthesis (%M352)
        if (
            self.diagnostic_code == CipEnergyDiagnosticCode.OK
            and not self.is_peak_demand_tripped
            and not self.is_thd_tripped
            and self.thd_pct <= IEEE519_THD_WARNING_THRESHOLD_PCT
            and not self.power_factor_alarm_active
        ):
            self.is_metering_healthy = True
        else:
            self.is_metering_healthy = False

    def _update_cip_object(self) -> None:
        """Update internal CipEnergyObject instance attributes."""
        self.cip_object.active_power_kw = self.active_power_kw
        self.cip_object.reactive_power_kvar = self.reactive_power_kvar
        self.cip_object.apparent_power_kva = self.apparent_power_kva
        self.cip_object.power_factor = self.power_factor
        self.cip_object.active_energy_kwh = self.energy_accumulation_kwh
        self.cip_object.thd_pct = self.thd_pct
        self.cip_object.voltage_rms = self.voltage_rms
        self.cip_object.current_rms = self.current_rms
        self.cip_object.energy_state = self.state
        self.cip_object.diagnostic_code = self.diagnostic_code
        self.cip_object.peak_demand_threshold_kw = self.peak_demand_threshold_kw
        self.cip_object.energy_baseline_kw = self.baseline_kw
        self.cip_object.evaluate_alarms()

    # ------------------------------------------------------------------------
    # Fault Handling & Diagnostic Trips
    # ------------------------------------------------------------------------

    def trip_fault(self, code: CipEnergyDiagnosticCode, details: str = "") -> None:
        """Latch diagnostic fault code, deassert health permissive, and transition state."""
        self.diagnostic_code = code
        self.is_metering_healthy = False
        self.state = CipEnergyState.FAULTED
        if code == CipEnergyDiagnosticCode.THD_LIMIT_EXCEEDED:
            self.is_thd_tripped = True
            self.is_peak_demand_tripped = True
        self.sync_to_registers()

    def reset_fault(self, force: bool = False) -> None:
        """Reset latched diagnostic fault trips if conditions have cleared."""
        if force:
            self.diagnostic_code = CipEnergyDiagnosticCode.OK
            self.is_peak_demand_tripped = False
            self.is_thd_tripped = False
            self.thd_warning_active = False
            self.power_factor_alarm_active = False
            self.phase_imbalance_pct = 0.0
            self.voltage_rms = self.nominal_voltage_rms
            if self.active_power_kw < 0.0:
                self.active_power_kw = 0.0
            if self.thd_pct > IEEE519_THD_WARNING_THRESHOLD_PCT:
                self.thd_pct = 0.0
            self.state = CipEnergyState.OPERATIONAL
            self.is_metering_healthy = True
        else:
            self._evaluate_safety_limits()

        self._update_cip_object()
        self.sync_to_registers()

    def simulate_voltage_sag_swell(self, voltage_rms: float = 400.0) -> None:
        """Simulate voltage sag or swell excursion (0xD101)."""
        self.voltage_rms = float(voltage_rms)
        self.trip_fault(
            CipEnergyDiagnosticCode.VOLTAGE_SAG_SWELL,
            f"Simulated voltage excursion ({self.voltage_rms:.1f} V)",
        )

    def simulate_thd_limit_exceeded(self, thd_pct: float = 9.5) -> None:
        """Simulate severe harmonic distortion exceeding IEEE 519 trip threshold (0xD102)."""
        self.thd_pct = float(thd_pct)
        self.is_thd_tripped = True
        self.is_peak_demand_tripped = True
        self.trip_fault(
            CipEnergyDiagnosticCode.THD_LIMIT_EXCEEDED,
            f"Simulated THD trip ({self.thd_pct:.2f}%)",
        )

    def simulate_reverse_power_trip(self, power_kw: float = -5.0) -> None:
        """Simulate reverse power generator backfeed trip (0xD103)."""
        self.active_power_kw = float(power_kw)
        self.trip_fault(
            CipEnergyDiagnosticCode.REVERSE_POWER_TRIP,
            f"Simulated reverse power backfeed ({self.active_power_kw:.2f} kW)",
        )

    def simulate_phase_imbalance(self, imbalance_pct: float = 4.5) -> None:
        """Simulate severe phase voltage/current unbalance trip (0xD104)."""
        self.phase_imbalance_pct = float(imbalance_pct)
        self.trip_fault(
            CipEnergyDiagnosticCode.PHASE_IMBALANCE,
            f"Simulated phase imbalance ({self.phase_imbalance_pct:.1f}%)",
        )

    def request_energy_state(self, target_state: CipEnergyState) -> bool:
        """Request energy state transition (ODVA Base Energy Object Class 0x4F)."""
        if self.diagnostic_code != CipEnergyDiagnosticCode.OK:
            # Cannot exit FAULTED state without resetting fault
            return False
        self.state = CipEnergyState(int(target_state))
        self.cip_object.energy_state = self.state
        self.cip_object.requested_energy_state = self.state
        self.sync_to_registers()
        return True

    # ------------------------------------------------------------------------
    # Horner OCS Register Table Synchronization (%R1510..%R1517, %M352..%M353)
    # ------------------------------------------------------------------------

    def sync_to_registers(self, reg_table: Optional[RegisterTable] = None) -> None:
        """Synchronize telemetry state to Horner OCS memory map with PrivilegeMode.SYSTEM.

        Register Table Layout:
        - %R1510: ActivePowerKwScaled (INT16, scaled x10 kW, e.g. 1250 = 125.0 kW)
        - %R1511: ReactivePowerKvarScaled (INT16, scaled x10 kVAR, e.g. 450 = 45.0 kVAR)
        - %R1512: ApparentPowerKvaScaled (INT16, scaled x10 kVA, e.g. 1328 = 132.8 kVA)
        - %R1513: PowerFactorScaled (INT16, scaled x1000, e.g. 941 = 0.941)
        - %R1514: EnergyAccumulationKwhHighWord (INT16)
        - %R1515: EnergyAccumulationKwhLowWord (INT16, signed)
        - %R1516: TotalHarmonicDistortionThdScaled (INT16, scaled x10 %, e.g. 32 = 3.2 %)
        - %R1517: DiagnosticStatusCode (0x0000=OK, 0xD101..0xD104)
        - %M352: EnergyMeteringHealthy (BOOL, True when power quality and metering are normal)
        - %M353: EnergyPeakDemandTrip (BOOL, True on peak demand breach or THD trip)
        """
        rt = reg_table if reg_table is not None else self.reg_table
        if rt is None:
            return

        # %R1510: ActivePowerKwScaled (INT16, scaled x10 kW)
        p_scaled = int(round(self.active_power_kw * 10.0))
        p_clamped = max(-32768, min(32767, p_scaled))
        safe_write_word(rt, "%R1510", p_clamped)

        # %R1511: ReactivePowerKvarScaled (INT16, scaled x10 kVAR)
        q_scaled = int(round(self.reactive_power_kvar * 10.0))
        q_clamped = max(-32768, min(32767, q_scaled))
        safe_write_word(rt, "%R1511", q_clamped)

        # %R1512: ApparentPowerKvaScaled (INT16, scaled x10 kVA)
        s_scaled = int(round(self.apparent_power_kva * 10.0))
        s_clamped = max(0, min(32767, s_scaled))
        safe_write_word(rt, "%R1512", s_clamped)

        # %R1513: PowerFactorScaled (INT16, scaled x1000)
        pf_scaled = int(round(self.power_factor * 1000.0))
        pf_clamped = max(-1000, min(1000, pf_scaled))
        safe_write_word(rt, "%R1513", pf_clamped)

        # %R1514..%R1515: EnergyAccumulationKwh (High/Low Words, INT16)
        e_int32 = int(round(self.energy_accumulation_kwh))
        high_word, low_word = encode_dint_words(e_int32)
        safe_write_word(rt, "%R1514", high_word)
        safe_write_word(rt, "%R1515", low_word)

        # %R1516: TotalHarmonicDistortionThdScaled (INT16, scaled x10 %)
        thd_scaled = int(round(self.thd_pct * 10.0))
        thd_clamped = max(0, min(32767, thd_scaled))
        safe_write_word(rt, "%R1516", thd_clamped)

        # %R1517: DiagnosticStatusCode (0x0000=OK, 0xD101..0xD104)
        safe_write_uword(rt, "%R1517", int(self.diagnostic_code))

        # %M352: EnergyMeteringHealthy (BOOL)
        safe_write_bit(rt, "%M352", self.is_metering_healthy)

        # %M353: EnergyPeakDemandTrip (BOOL)
        safe_write_bit(rt, "%M353", self.is_peak_demand_tripped)

    def get_snapshot(self) -> CipEnergySnapshot:
        """Capture current telemetry snapshot dataclass."""
        return CipEnergySnapshot(
            active_kw=self.active_power_kw,
            reactive_kvar=self.reactive_power_kvar,
            apparent_kva=self.apparent_power_kva,
            pf=self.power_factor,
            energy_kwh=self.energy_accumulation_kwh,
            thd_pct=self.thd_pct,
            energy_state=self.state,
            diagnostic_code=self.diagnostic_code,
            voltage_rms=self.voltage_rms,
            current_rms=self.current_rms,
            frequency_hz=self.frequency_hz,
            timestamp_s=self.elapsed_simulation_ms / 1000.0,
            peak_demand_tripped=self.is_peak_demand_tripped,
            metering_healthy=self.is_metering_healthy,
            power_factor_alarm=self.power_factor_alarm_active,
            thd_warning=self.thd_warning_active,
        )


# ============================================================================
# 8. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_cip_energy_verification(
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W190.

    Stages:
    1. POU ST syntax validation and anti-ladder check.
    2. ODVA Class 0x4E Energy Object attribute resolution.
    3. 3-phase power triangle calculation (P, Q, S, PF).
    4. High-precision active energy integration (kWh).
    5. Power quality THD harmonic calculation and IEEE 519 checks.
    6. Peak demand threshold detection and energy-saving state transition.
    7. Register table synchronization (%R1510..%R1517, %M352..%M353).
    8. Discrete ILogicUnit 100-cycle scan simulation.
    9. Process safety interlock and diagnostic fault trip testing (0xD101..0xD104).

    Returns strict 4-state contract response dictionary:
        {'status': 'success', 'stages_passed': 9, 'total_stages': 9, 'data': {...}}
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: POU ST syntax validation and anti-ladder check
    # ------------------------------------------------------------------------
    val_pou = STParser.validate_code(CIP_ENERGY_MANAGEMENT_SYNC_POU)
    ast_pou = STParser.parse_pou(CIP_ENERGY_MANAGEMENT_SYNC_POU)

    expected_regs = {
        "%R1510", "%R1511", "%R1512", "%R1513",
        "%R1514", "%R1515", "%R1516", "%R1517",
        "%M352", "%M353",
    }
    bound_regs = set(ast_pou.bound_registers)

    ladder_rejected = True
    for bad_construct in ["---[ ]---", "---( )---", "RUNG 1", "XIC EnergyMeter_Pulse"]:
        try:
            SecurityGuard.assert_pure_st_content(
                f"PROGRAM BadEnergy\nVAR X : BOOL;\nEND_VAR\n{bad_construct}\nEND_PROGRAM"
            )
            ladder_rejected = False
        except LadderForbiddenError:
            pass

    # Verify pure ST passes without error
    SecurityGuard.assert_pure_st_content(CIP_ENERGY_MANAGEMENT_SYNC_POU)

    s1_pass = (
        val_pou.status == AgentStatus.SUCCESS
        and ast_pou.name == "CipEnergyManagementSync"
        and expected_regs.issubset(bound_regs)
        and ladder_rejected is True
    )
    test_results.append({
        "stage": 1,
        "check": "POU_ST_Syntax_Validation_And_Anti_Ladder_Check",
        "passed": s1_pass,
        "details": f"POU 'CipEnergyManagementSync' verified clean; {len(bound_regs)} registers bound; ladder constructs rejected.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: ODVA Class 0x4E Energy Object attribute resolution
    # ------------------------------------------------------------------------
    cip_obj = CipEnergyObject(
        energy_baseline_kw=50.0,
        peak_demand_threshold_kw=150.0,
        active_power_kw=125.0,
        reactive_power_kvar=45.0,
        apparent_power_kva=132.85,
        power_factor=0.941,
        thd_pct=3.2,
    )

    attr_p = cip_obj.get_attribute_single(5, CIP_ENERGY_CLASS_ID)       # Active power kW
    attr_q = cip_obj.get_attribute_single(6, CIP_ENERGY_CLASS_ID)       # Reactive power kVAR
    attr_s = cip_obj.get_attribute_single(7, CIP_ENERGY_CLASS_ID)       # Apparent power kVA
    attr_pf = cip_obj.get_attribute_single(8, CIP_ENERGY_CLASS_ID)      # Power factor
    attr_thd = cip_obj.get_attribute_single(11, CIP_ENERGY_CLASS_ID)    # THD %
    attr_thresh = cip_obj.get_attribute_single(13, CIP_ENERGY_CLASS_ID) # Peak demand threshold
    attr_pf_alarm_init = cip_obj.get_attribute_single(15, CIP_ENERGY_CLASS_ID)

    # Class 0x4F attributes
    attr_state = cip_obj.get_attribute_single(1, CIP_ENERGY_BASE_CLASS_ID)
    attr_supp_states = cip_obj.get_attribute_single(2, CIP_ENERGY_BASE_CLASS_ID)

    # Test set attribute and alarm trigger
    cip_obj.set_attribute_single(13, 200.0, CIP_ENERGY_CLASS_ID)
    attr_thresh_updated = cip_obj.get_attribute_single(13, CIP_ENERGY_CLASS_ID)

    # Induce PF alarm (< 0.85)
    cip_obj.power_factor = 0.78
    cip_obj.evaluate_alarms()
    attr_pf_alarm_active = cip_obj.get_attribute_single(15, CIP_ENERGY_CLASS_ID)

    s2_pass = (
        attr_p == 125.0
        and attr_q == 45.0
        and attr_s == 132.85
        and attr_pf == 0.941
        and attr_thd == 3.2
        and attr_thresh == 150.0
        and attr_thresh_updated == 200.0
        and attr_pf_alarm_init is False
        and attr_pf_alarm_active is True
        and attr_state == int(CipEnergyState.OPERATIONAL)
        and attr_supp_states == 0x3F
    )
    test_results.append({
        "stage": 2,
        "check": "ODVA_Class_0x4E_Energy_Object_Attribute_Resolution",
        "passed": s2_pass,
        "details": "ODVA Class 0x4E and Class 0x4F attributes resolved deterministically; alarms verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: 3-phase power triangle calculation (P, Q, S, PF)
    # ------------------------------------------------------------------------
    p_test = 125.0
    q_test = 45.0
    s_calc, pf_calc = calculate_power_triangle(p_test, q_test)

    expected_s = math.sqrt(125.0**2 + 45.0**2)  # sqrt(17650) ~ 132.85330255586
    expected_pf = 125.0 / expected_s            # ~ 0.94088744

    # Balanced 3-phase calculation: V=480V, I=160A, PF=0.941
    p_3ph, q_3ph, s_3ph = calculate_3phase_power(480.0, 160.0, pf=0.941)
    expected_s_3ph = (math.sqrt(3.0) * 480.0 * 160.0) / 1000.0  # ~ 133.0207 kVA
    expected_p_3ph = expected_s_3ph * 0.941

    s3_pass = (
        abs(s_calc - expected_s) < 1e-4
        and abs(pf_calc - expected_pf) < 1e-4
        and abs(s_3ph - expected_s_3ph) < 1e-4
        and abs(p_3ph - expected_p_3ph) < 1e-4
    )
    test_results.append({
        "stage": 3,
        "check": "Three_Phase_Power_Triangle_Calculation",
        "passed": s3_pass,
        "details": f"Power triangle verified: P={p_test}kW, Q={q_test}kVAR -> S={s_calc:.2f}kVA, PF={pf_calc:.4f}.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: High-precision active energy integration (kWh)
    # ------------------------------------------------------------------------
    engine_integ = CipEnergyEngine()
    engine_integ.active_power_kw = 120.0  # 120.0 kW constant load

    # Integrate 3600 seconds (1 hour) at 120 kW -> exactly 120.0 kWh
    dt_step = 10.0  # 10s steps
    steps = 360     # 360 * 10 = 3600s
    for _ in range(steps):
        engine_integ.scan_step(dt=dt_step)

    expected_kwh = 120.0
    actual_kwh = engine_integ.energy_accumulation_kwh

    s4_pass = abs(actual_kwh - expected_kwh) < 1e-6
    test_results.append({
        "stage": 4,
        "check": "High_Precision_Active_Energy_Integration",
        "passed": s4_pass,
        "details": f"Energy integration verified: 120.0 kW over 1h accumulated {actual_kwh:.6f} kWh (target: {expected_kwh:.6f}).",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Power quality THD harmonic calculation and IEEE 519 checks
    # ------------------------------------------------------------------------
    engine_thd = CipEnergyEngine()

    # Normal harmonic test: 480V fundamental, V3=9.6V, V5=12.0V -> THD ~ 3.20%
    thd_normal = engine_thd.set_harmonic_spectrum(480.0, [9.6, 12.0])
    is_normal_healthy = (
        thd_normal < IEEE519_THD_WARNING_THRESHOLD_PCT
        and engine_thd.diagnostic_code == CipEnergyDiagnosticCode.OK
        and engine_thd.is_metering_healthy is True
    )

    # Severe harmonic test: 480V fundamental, V3=30.0V, V5=35.0V -> THD ~ 9.60% (> 8.0% trip)
    thd_trip = engine_thd.set_harmonic_spectrum(480.0, [30.0, 35.0])
    is_trip_tripped = (
        thd_trip > IEEE519_THD_TRIP_THRESHOLD_PCT
        and engine_thd.diagnostic_code == CipEnergyDiagnosticCode.THD_LIMIT_EXCEEDED
        and engine_thd.is_metering_healthy is False
        and engine_thd.is_peak_demand_tripped is True
        and engine_thd.state == CipEnergyState.FAULTED
    )

    s5_pass = (
        abs(thd_normal - 3.20156) < 0.05
        and abs(thd_trip - 9.60416) < 0.05
        and is_normal_healthy
        and is_trip_tripped
    )
    test_results.append({
        "stage": 5,
        "check": "Power_Quality_THD_Calculation_And_IEEE_519_Checks",
        "passed": s5_pass,
        "details": f"THD harmonic spectrum verified: 3.2% normal (<5%), 9.6% trip (>8%) correctly triggered 0xD102.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Peak demand threshold detection and energy-saving state transition
    # ------------------------------------------------------------------------
    engine_demand = CipEnergyEngine(peak_demand_threshold_kw=150.0)
    engine_demand.update_telemetry(active_kw=120.0, reactive_kvar=40.0)

    pre_trip_state = engine_demand.state
    pre_trip_flag = engine_demand.is_peak_demand_tripped

    # Surge power above 150.0 kW threshold
    engine_demand.update_telemetry(active_kw=165.0, reactive_kvar=55.0)

    post_trip_state = engine_demand.state
    post_trip_flag = engine_demand.is_peak_demand_tripped

    s6_pass = (
        pre_trip_state == CipEnergyState.OPERATIONAL
        and pre_trip_flag is False
        and post_trip_state == CipEnergyState.ENERGY_SAVING
        and post_trip_flag is True
    )
    test_results.append({
        "stage": 6,
        "check": "Peak_Demand_Threshold_Detection_And_State_Transition",
        "passed": s6_pass,
        "details": "Peak demand breach (>150kW) asserted trip coil and transitioned to ENERGY_SAVING state.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Register table synchronization (%R1510..%R1517, %M352..%M353)
    # ------------------------------------------------------------------------
    rt = RegisterTable()
    engine_reg = CipEnergyEngine(reg_table=rt)

    engine_reg.active_power_kw = 125.0
    engine_reg.reactive_power_kvar = 45.0
    engine_reg.apparent_power_kva = 132.8
    engine_reg.power_factor = 0.941
    engine_reg.energy_accumulation_kwh = 50000.0
    engine_reg.thd_pct = 3.2
    engine_reg.diagnostic_code = CipEnergyDiagnosticCode.OK
    engine_reg.is_metering_healthy = True
    engine_reg.is_peak_demand_tripped = False

    engine_reg.sync_to_registers()

    r1510 = rt.read_word("%R1510")  # Active power scaled x10: 1250
    r1511 = rt.read_word("%R1511")  # Reactive power scaled x10: 450
    r1512 = rt.read_word("%R1512")  # Apparent power scaled x10: 1328
    r1513 = rt.read_word("%R1513")  # Power factor scaled x1000: 941
    r1514 = rt.read_word("%R1514")  # Energy high word
    r1515 = rt.read_word("%R1515")  # Energy low word
    r1516 = rt.read_word("%R1516")  # THD scaled x10: 32
    r1517 = rt.read_uword("%R1517") # Diagnostic code: 0x0000
    m352 = rt.read_bit("%M352")     # Metering healthy: True
    m353 = rt.read_bit("%M353")     # Peak demand trip: False

    reconstructed_energy = decode_dint_words(r1514, r1515)

    s7_pass = (
        r1510 == 1250
        and r1511 == 450
        and r1512 == 1328
        and r1513 == 941
        and reconstructed_energy == 50000
        and r1516 == 32
        and r1517 == 0x0000
        and m352 is True
        and m353 is False
    )
    test_results.append({
        "stage": 7,
        "check": "Register_Table_Synchronization",
        "passed": s7_pass,
        "details": f"Horner OCS memory mapped accurately: %R1510={r1510}, %R1513={r1513}, Energy={reconstructed_energy}kWh, %M352={m352}.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Discrete ILogicUnit 100-cycle scan simulation
    # ------------------------------------------------------------------------
    rt_sim = RegisterTable()
    engine_sim = CipEnergyEngine(reg_table=rt_sim)
    engine_sim.update_telemetry(active_kw=100.0, reactive_kvar=30.0)

    initial_energy = engine_sim.energy_accumulation_kwh
    for _ in range(100):
        engine_sim.scan_step(dt=0.01)  # 10ms discrete scan

    final_energy = engine_sim.energy_accumulation_kwh
    expected_energy_inc = 100.0 * (1.0 / 3600.0)  # 100 * 0.01s = 1.0s elapsed

    s8_pass = (
        engine_sim.total_scan_cycles == 100
        and abs(engine_sim.elapsed_simulation_ms - 1000.0) < 1e-4
        and abs((final_energy - initial_energy) - expected_energy_inc) < 1e-6
        and rt_sim.read_word("%R1510") == 1000
    )
    test_results.append({
        "stage": 8,
        "check": "Discrete_ILogicUnit_100_Cycle_Scan_Simulation",
        "passed": s8_pass,
        "details": f"100-cycle simulation executed smoothly: 1000ms elapsed; energy incremented {final_energy - initial_energy:.6f} kWh.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Process safety interlock and diagnostic fault trip testing
    # ------------------------------------------------------------------------
    rt_fault = RegisterTable()
    engine_fault = CipEnergyEngine(reg_table=rt_fault)

    # 1. Voltage Sag/Swell (0xD101)
    engine_fault.simulate_voltage_sag_swell(380.0)
    sag_code = rt_fault.read_uword("%R1517")
    sag_healthy = rt_fault.read_bit("%M352")
    engine_fault.reset()

    # 2. THD Limit Exceeded (0xD102)
    engine_fault.simulate_thd_limit_exceeded(10.2)
    thd_code = rt_fault.read_uword("%R1517")
    thd_healthy = rt_fault.read_bit("%M352")
    thd_trip_bit = rt_fault.read_bit("%M353")
    engine_fault.reset()

    # 3. Reverse Power Trip (0xD103)
    engine_fault.simulate_reverse_power_trip(-15.0)
    rev_code = rt_fault.read_uword("%R1517")
    rev_healthy = rt_fault.read_bit("%M352")
    engine_fault.reset()

    # 4. Phase Imbalance (0xD104)
    engine_fault.simulate_phase_imbalance(4.8)
    imb_code = rt_fault.read_uword("%R1517")
    imb_healthy = rt_fault.read_bit("%M352")
    engine_fault.reset()

    # Verify return to normal state
    reset_code = rt_fault.read_uword("%R1517")
    reset_healthy = rt_fault.read_bit("%M352")
    reset_trip_bit = rt_fault.read_bit("%M353")

    s9_pass = (
        sag_code == 0xD101 and sag_healthy is False
        and thd_code == 0xD102 and thd_healthy is False and thd_trip_bit is True
        and rev_code == 0xD103 and rev_healthy is False
        and imb_code == 0xD104 and imb_healthy is False
        and reset_code == 0x0000 and reset_healthy is True and reset_trip_bit is False
    )
    test_results.append({
        "stage": 9,
        "check": "Process_Safety_Interlock_And_Diagnostic_Fault_Trip_Testing",
        "passed": s9_pass,
        "details": "All 4 diagnostic trips (0xD101..0xD104) verified; register interlocking and reset behavior validated.",
    })

    # ------------------------------------------------------------------------
    # Aggregate Strict 4-State Engineering Contract
    # ------------------------------------------------------------------------
    passed_count = sum(1 for r in test_results if r["passed"])
    total_count = len(test_results)
    all_passed = (passed_count == total_count and total_count == 9)

    response_payload: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "stages_passed": passed_count,
        "total_stages": total_count,
        "details": (
            "All 9 deterministic verification stages passed successfully."
            if all_passed
            else f"{total_count - passed_count} verification stages failed."
        ),
        "data": {
            "stages": test_results,
            "standards": [
                "ODVA CIP Energy Management Specification (Class 0x4E, Class 0x4F)",
                "IEEE 519 Harmonic Control in Electric Power Systems",
                "IEC 61131-3 Pure Structured Text ONLY",
                "Horner OCS Memory Layout (%R1510..%R1517, %M352..%M353)",
            ],
            "timestamp": time.time(),
        },
    }

    if output_path is not None:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(response_payload, f, indent=2)

    return response_payload
