"""Modbus Register Scaling Bridge and Telemetry Quality Tracker.

Work Package: W027 (Gate G8)
Classification: PRODUCTION [industrial telemetry & closed-loop simulation]

Provides:
- ScalingType: LINEAR, SQUARE_ROOT, PIECEWISE, RTD.
- QualityCode: GOOD, UNCERTAIN, BAD and 16-bit OPC UA / OPC DA quality word bit flags
  (SENSOR_FAILURE, CONFIG_ERROR, EU_EXCEEDED, BURNOUT, SHORT_CIRCUIT, PRECISION_LOSS, etc.).
- NamurNE43Validator: 4-20mA monitoring (3.8-20.5mA valid, <3.6mA burnout, >21mA short-circuit).
- TelemetryPoint: Point definition with bidirectional conversion (raw integer counts <-> EU float),
  IEEE 754 precision loss tracking, NaN/Inf sanitization, and Modbus word-order handling.
- ModbusScalingBridge: Register mapping (input/holding registers), word-order handling
  (LOW_WORD_FIRST vs HIGH_WORD_FIRST), and synchronization with Horner OCS RegisterTable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntFlag
import math
import struct
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from jev_cscape.simulation.register_table import (
    PrivilegeMode,
    RegisterTable,
    WordOrder,
    float_to_words,
    words_to_float,
)


class ScalingType(str, Enum):
    """Scaling algorithm applied between raw integer counts and Engineering Units."""
    LINEAR = "LINEAR"
    SQUARE_ROOT = "SQUARE_ROOT"
    PIECEWISE = "PIECEWISE"
    RTD = "RTD"


class QualityCode(str, Enum):
    """Major quality indicator adhering to OPC UA / OPC DA standards."""
    GOOD = "GOOD"
    UNCERTAIN = "UNCERTAIN"
    BAD = "BAD"


class OPCQualityFlag(IntFlag):
    """16-bit OPC UA / OPC DA quality word bit flags and diagnostic masks.

    Layout adheres to OPC Data Access 2.05/3.0 & OPC Unified Architecture Part 8:
    - Bits [7:6]: Major Quality (00=Bad, 01=Uncertain, 11=Good)
    - Bits [5:2]: Diagnostic Substatus
    - Bits [1:0]: Limit Status (00=None, 01=Low, 10=High, 11=Constant)
    - Bits [15:8]: Extended Diagnostic / Telemetry Flags (High Byte)
    """
    # Major Quality (Bits 6..7)
    BAD = 0x0000
    UNCERTAIN = 0x0040
    GOOD = 0x00C0
    MAJOR_QUALITY_MASK = 0x00C0

    # Substatus (Bits 2..5)
    CONFIG_ERROR = 0x0004
    NOT_CONNECTED = 0x0008
    DEVICE_FAILURE = 0x000C
    SENSOR_FAILURE = 0x0010
    LAST_KNOWN_VALUE = 0x0014
    COMM_FAILURE = 0x0018
    OUT_OF_SERVICE = 0x001C
    LAST_USABLE_VALUE = 0x0044
    SENSOR_NOT_ACCURATE = 0x0050
    EU_EXCEEDED = 0x0054
    SUB_NORMAL = 0x0058

    # Limit Status (Bits 0..1)
    LIMIT_NONE = 0x0000
    LOW_LIMITED = 0x0001
    HIGH_LIMITED = 0x0002
    CONSTANT = 0x0003
    LIMIT_MASK = 0x0003

    # Extended Quality / Diagnostic Flags (Upper Byte: Bits 8..15)
    BURNOUT = 0x0100           # Loop open / sensor burnout (<3.6mA)
    SHORT_CIRCUIT = 0x0200     # Loop short-circuit (>21.0mA)
    PRECISION_LOSS = 0x0400    # IEEE 754 single precision truncation detected
    OVERFLOW = 0x0800          # Upper measuring span exceeded (>20.5mA or math overflow)
    UNDERFLOW = 0x1000         # Lower measuring span undershoot (<3.8mA or math underflow)
    NAN_INF_FAULT = 0x2000     # NaN or Infinity sanitized
    EXT_CONFIG_ERROR = 0x4000  # Upper byte mirror for configuration error
    EXT_SENSOR_FAILURE = 0x8000 # Upper byte mirror for physical sensor failure


def encode_quality_word(
    quality: QualityCode,
    substatus: int = 0,
    limit: int = 0,
    extended_flags: int = 0,
) -> int:
    """Encodes major quality, substatus, limit bits, and extended flags into a 16-bit word."""
    base = 0x00C0 if quality == QualityCode.GOOD else (
        0x0040 if quality == QualityCode.UNCERTAIN else 0x0000
    )
    word = (base & 0x00C0) | (substatus & 0x003C) | (limit & 0x0003) | (extended_flags & 0xFF00)
    return word & 0xFFFF


def decode_quality_word(quality_word: int) -> Tuple[QualityCode, List[str]]:
    """Decodes a 16-bit quality word into a QualityCode and a list of active diagnostic flags."""
    qw = quality_word & 0xFFFF
    major_bits = qw & 0x00C0
    if major_bits == 0x00C0:
        qc = QualityCode.GOOD
    elif major_bits == 0x0040:
        qc = QualityCode.UNCERTAIN
    else:
        qc = QualityCode.BAD

    flags: List[str] = [qc.value]

    # Substatus
    sub = qw & 0x003C
    if sub == OPCQualityFlag.CONFIG_ERROR:
        flags.append("CONFIG_ERROR")
    elif sub == OPCQualityFlag.NOT_CONNECTED:
        flags.append("NOT_CONNECTED")
    elif sub == OPCQualityFlag.DEVICE_FAILURE:
        flags.append("DEVICE_FAILURE")
    elif sub == OPCQualityFlag.SENSOR_FAILURE:
        flags.append("SENSOR_FAILURE")
    elif sub == OPCQualityFlag.COMM_FAILURE:
        flags.append("COMM_FAILURE")
    elif sub == OPCQualityFlag.OUT_OF_SERVICE:
        flags.append("OUT_OF_SERVICE")
    elif sub == (OPCQualityFlag.EU_EXCEEDED & 0x003C):
        flags.append("EU_EXCEEDED")

    # Limits
    lim = qw & 0x0003
    if lim == OPCQualityFlag.LOW_LIMITED:
        flags.append("LOW_LIMITED")
    elif lim == OPCQualityFlag.HIGH_LIMITED:
        flags.append("HIGH_LIMITED")
    elif lim == OPCQualityFlag.CONSTANT:
        flags.append("CONSTANT")

    # Extended high byte flags
    if qw & OPCQualityFlag.BURNOUT:
        flags.append("BURNOUT")
    if qw & OPCQualityFlag.SHORT_CIRCUIT:
        flags.append("SHORT_CIRCUIT")
    if qw & OPCQualityFlag.PRECISION_LOSS:
        flags.append("PRECISION_LOSS")
    if qw & OPCQualityFlag.OVERFLOW:
        flags.append("OVERFLOW")
    if qw & OPCQualityFlag.UNDERFLOW:
        flags.append("UNDERFLOW")
    if qw & OPCQualityFlag.NAN_INF_FAULT:
        flags.append("NAN_INF_FAULT")
    if qw & OPCQualityFlag.EXT_CONFIG_ERROR:
        flags.append("EXT_CONFIG_ERROR")
    if qw & OPCQualityFlag.EXT_SENSOR_FAILURE:
        flags.append("EXT_SENSOR_FAILURE")

    return qc, flags


@dataclass
class NamurValidationResult:
    """Result of NAMUR NE 43 loop current validation."""
    current_ma: float
    is_valid: bool
    quality_code: QualityCode
    quality_word: int
    failure_mode: Optional[str] = None  # None, "BURNOUT", "UNDERRANGE", "OVERRANGE", "SHORT_CIRCUIT", "NAN_INF"
    message: str = ""


class NamurNE43Validator:
    """NAMUR NE 43 Standard 4-20mA Current Loop Monitor and Fault Detector.

    Operating zones per NAMUR NE 43:
    - I < 3.6 mA: Failure signal - Burnout / Open Loop (Quality: BAD, SENSOR_FAILURE | BURNOUT)
    - 3.6 mA <= I < 3.8 mA: Measuring under-range (Quality: UNCERTAIN, UNDERFLOW | LOW_LIMITED)
    - 3.8 mA <= I <= 20.5 mA: Valid extended measurement range (Quality: GOOD)
    - 20.5 mA < I <= 21.0 mA: Measuring over-range (Quality: UNCERTAIN, OVERFLOW | HIGH_LIMITED)
    - I > 21.0 mA: Failure signal - Short Circuit / Saturation (Quality: BAD, SENSOR_FAILURE | SHORT_CIRCUIT)
    """

    BURNOUT_THRESHOLD_MA: float = 3.6
    VALID_MIN_MA: float = 3.8
    NOMINAL_MIN_MA: float = 4.0
    NOMINAL_MAX_MA: float = 20.0
    VALID_MAX_MA: float = 20.5
    SHORT_CIRCUIT_THRESHOLD_MA: float = 21.0

    @classmethod
    def raw_to_current(
        cls,
        raw_counts: float,
        raw_min_4ma: float = 0.0,
        raw_max_20ma: float = 32000.0,
    ) -> float:
        """Converts raw analog input counts to loop current in milliamperes (mA).

        Horner OCS 4-20mA analog modules typically scale 4mA -> raw_min (0) and 20mA -> raw_max (32000).
        """
        span_raw = raw_max_20ma - raw_min_4ma
        if span_raw == 0:
            return 0.0
        return cls.NOMINAL_MIN_MA + ((raw_counts - raw_min_4ma) / span_raw) * (cls.NOMINAL_MAX_MA - cls.NOMINAL_MIN_MA)

    @classmethod
    def current_to_raw(
        cls,
        current_ma: float,
        raw_min_4ma: float = 0.0,
        raw_max_20ma: float = 32000.0,
    ) -> int:
        """Converts loop current in milliamperes (mA) to raw analog counts."""
        span_raw = raw_max_20ma - raw_min_4ma
        span_ma = cls.NOMINAL_MAX_MA - cls.NOMINAL_MIN_MA
        raw_val = raw_min_4ma + ((current_ma - cls.NOMINAL_MIN_MA) / span_ma) * span_raw
        return int(round(raw_val))

    @classmethod
    def validate_current(cls, current_ma: float) -> NamurValidationResult:
        """Validates loop current against NAMUR NE 43 thresholds."""
        if math.isnan(current_ma) or math.isinf(current_ma):
            qw = encode_quality_word(
                QualityCode.BAD,
                substatus=OPCQualityFlag.SENSOR_FAILURE,
                extended_flags=OPCQualityFlag.NAN_INF_FAULT | OPCQualityFlag.EXT_SENSOR_FAILURE,
            )
            return NamurValidationResult(
                current_ma=current_ma,
                is_valid=False,
                quality_code=QualityCode.BAD,
                quality_word=qw,
                failure_mode="NAN_INF",
                message="Invalid NaN/Inf current reading",
            )

        if current_ma < cls.BURNOUT_THRESHOLD_MA:
            qw = encode_quality_word(
                QualityCode.BAD,
                substatus=OPCQualityFlag.SENSOR_FAILURE,
                limit=OPCQualityFlag.LOW_LIMITED,
                extended_flags=OPCQualityFlag.BURNOUT | OPCQualityFlag.UNDERFLOW | OPCQualityFlag.EXT_SENSOR_FAILURE,
            )
            return NamurValidationResult(
                current_ma=current_ma,
                is_valid=False,
                quality_code=QualityCode.BAD,
                quality_word=qw,
                failure_mode="BURNOUT",
                message=f"NAMUR NE43 Burnout Failure ({current_ma:.2f} mA < {cls.BURNOUT_THRESHOLD_MA} mA)",
            )

        if current_ma < cls.VALID_MIN_MA:
            qw = encode_quality_word(
                QualityCode.UNCERTAIN,
                substatus=OPCQualityFlag.SENSOR_NOT_ACCURATE,
                limit=OPCQualityFlag.LOW_LIMITED,
                extended_flags=OPCQualityFlag.UNDERFLOW,
            )
            return NamurValidationResult(
                current_ma=current_ma,
                is_valid=False,
                quality_code=QualityCode.UNCERTAIN,
                quality_word=qw,
                failure_mode="UNDERRANGE",
                message=f"NAMUR NE43 Under-range Warning ({current_ma:.2f} mA in [{cls.BURNOUT_THRESHOLD_MA}, {cls.VALID_MIN_MA}) mA)",
            )

        if current_ma <= cls.VALID_MAX_MA:
            qw = encode_quality_word(QualityCode.GOOD)
            return NamurValidationResult(
                current_ma=current_ma,
                is_valid=True,
                quality_code=QualityCode.GOOD,
                quality_word=qw,
                failure_mode=None,
                message=f"NAMUR NE43 Normal Signal ({current_ma:.2f} mA in [{cls.VALID_MIN_MA}, {cls.VALID_MAX_MA}] mA)",
            )

        if current_ma <= cls.SHORT_CIRCUIT_THRESHOLD_MA:
            qw = encode_quality_word(
                QualityCode.UNCERTAIN,
                substatus=OPCQualityFlag.SENSOR_NOT_ACCURATE,
                limit=OPCQualityFlag.HIGH_LIMITED,
                extended_flags=OPCQualityFlag.OVERFLOW,
            )
            return NamurValidationResult(
                current_ma=current_ma,
                is_valid=False,
                quality_code=QualityCode.UNCERTAIN,
                quality_word=qw,
                failure_mode="OVERRANGE",
                message=f"NAMUR NE43 Over-range Warning ({current_ma:.2f} mA in ({cls.VALID_MAX_MA}, {cls.SHORT_CIRCUIT_THRESHOLD_MA}] mA)",
            )

        # current_ma > SHORT_CIRCUIT_THRESHOLD_MA
        qw = encode_quality_word(
            QualityCode.BAD,
            substatus=OPCQualityFlag.SENSOR_FAILURE,
            limit=OPCQualityFlag.HIGH_LIMITED,
            extended_flags=OPCQualityFlag.SHORT_CIRCUIT | OPCQualityFlag.OVERFLOW | OPCQualityFlag.EXT_SENSOR_FAILURE,
        )
        return NamurValidationResult(
            current_ma=current_ma,
            is_valid=False,
            quality_code=QualityCode.BAD,
            quality_word=qw,
            failure_mode="SHORT_CIRCUIT",
            message=f"NAMUR NE43 Short-Circuit Failure ({current_ma:.2f} mA > {cls.SHORT_CIRCUIT_THRESHOLD_MA} mA)",
        )

    @classmethod
    def validate_raw(
        cls,
        raw_counts: float,
        raw_min_4ma: float = 0.0,
        raw_max_20ma: float = 32000.0,
    ) -> NamurValidationResult:
        """Validates raw counts by converting to current and checking NAMUR NE 43 rules."""
        current_ma = cls.raw_to_current(raw_counts, raw_min_4ma, raw_max_20ma)
        return cls.validate_current(current_ma)


class ModbusRegisterType(str, Enum):
    """Modbus register block types."""
    HOLDING = "HOLDING"  # Function Code 03/06/16 (4xxxx Read/Write)
    INPUT = "INPUT"      # Function Code 04 (3xxxx Read-Only)


@dataclass
class TelemetryPoint:
    """Configured industrial telemetry point with scaling and quality diagnostics.

    Handles bidirectional conversion between raw OCS register counts and Engineering Units,
    precision loss detection, and word order serialization.
    """
    name: str
    channel: str                                # OCS channel address, e.g. "%AI1", "%AQ1", "%R101"
    modbus_address: int                         # Modbus register address (0-based or 1-based convention)
    modbus_register_type: ModbusRegisterType = ModbusRegisterType.INPUT
    scaling_type: ScalingType = ScalingType.LINEAR
    raw_min: float = 0.0                        # Raw count at minimum EU (default 0 for Horner 4-20mA)
    raw_max: float = 32000.0                    # Raw count at maximum EU (default 32000 for Horner 4-20mA)
    eu_min: float = 0.0                         # Engineering unit minimum span
    eu_max: float = 100.0                       # Engineering unit maximum span
    eu_unit: str = "%"                          # Unit description (%, m3/h, degC, kPa, etc.)
    word_order: WordOrder = WordOrder.LOW_WORD_FIRST
    is_32bit_float: bool = True                 # True: 2 Modbus registers (IEEE 754 float32); False: 1 register (int16)
    quality_modbus_address: Optional[int] = None # Optional dedicated Modbus address for 16-bit quality word

    # Namur NE43 parameters
    namur_ne43_enabled: bool = False
    namur_raw_4ma: float = 0.0
    namur_raw_20ma: float = 32000.0

    # Square Root flow meter parameters
    low_flow_cutoff_percent: float = 0.0        # Cutoff % of span below which flow is forced to eu_min

    # Piecewise interpolation points: sorted list of (raw, eu) calibration pairs
    piecewise_points: Optional[List[Tuple[float, float]]] = None

    # RTD parameters
    rtd_mode: str = "TENTHS_DEG_C"             # "TENTHS_DEG_C" (Horner 0.1 degC counts) or "RESISTANCE" (Ohms)
    rtd_r0: float = 100.0                       # Base resistance at 0°C (PT100=100.0, PT1000=1000.0)
    rtd_a: float = 3.9083e-3                    # Callendar-Van Dusen A coefficient
    rtd_b: float = -5.775e-7                    # Callendar-Van Dusen B coefficient

    # Runtime live state
    current_raw: Optional[int] = None
    current_eu: Optional[float] = None
    current_quality: QualityCode = QualityCode.GOOD
    current_quality_word: int = 0x00C0
    precision_loss_detected: bool = False
    last_update_timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if self.piecewise_points:
            # Sort piecewise points strictly by raw count
            self.piecewise_points = sorted(self.piecewise_points, key=lambda p: p[0])

    # -------------------------------------------------------------------------
    # Bidirectional Conversion: Raw Counts <-> Engineering Units
    # -------------------------------------------------------------------------

    def raw_to_eu(self, raw_counts: int) -> Tuple[float, QualityCode, int]:
        """Converts raw integer counts to engineering units with quality validation.

        Returns (eu_float, QualityCode, 16_bit_quality_word).
        """
        # 1. NaN / Inf sanitization on input
        if math.isnan(raw_counts) or math.isinf(raw_counts):
            qw = encode_quality_word(
                QualityCode.BAD,
                substatus=OPCQualityFlag.CONFIG_ERROR,
                extended_flags=OPCQualityFlag.NAN_INF_FAULT | OPCQualityFlag.EXT_CONFIG_ERROR,
            )
            return self.eu_min, QualityCode.BAD, qw

        active_substatus = 0
        active_limit = OPCQualityFlag.LIMIT_NONE
        active_ext_flags = 0
        quality = QualityCode.GOOD

        # 2. Namur NE43 validation if enabled (4-20mA loop monitoring)
        if self.namur_ne43_enabled:
            namur_res = NamurNE43Validator.validate_raw(
                raw_counts, self.namur_raw_4ma, self.namur_raw_20ma
            )
            quality = namur_res.quality_code
            active_ext_flags |= (namur_res.quality_word & 0xFF00)
            active_substatus = namur_res.quality_word & 0x003C
            active_limit = namur_res.quality_word & 0x0003

        # 3. Scaling calculation
        eu_val = self.eu_min
        span_raw = self.raw_max - self.raw_min
        span_eu = self.eu_max - self.eu_min

        if self.scaling_type == ScalingType.LINEAR:
            if span_raw == 0:
                quality = QualityCode.BAD
                active_substatus = OPCQualityFlag.CONFIG_ERROR
                active_ext_flags |= OPCQualityFlag.EXT_CONFIG_ERROR
                eu_val = self.eu_min
            else:
                eu_val = self.eu_min + ((raw_counts - self.raw_min) / span_raw) * span_eu

        elif self.scaling_type == ScalingType.SQUARE_ROOT:
            if span_raw == 0:
                quality = QualityCode.BAD
                active_substatus = OPCQualityFlag.CONFIG_ERROR
                active_ext_flags |= OPCQualityFlag.EXT_CONFIG_ERROR
                eu_val = self.eu_min
            else:
                normalized = (raw_counts - self.raw_min) / span_raw
                if normalized < 0.0:
                    normalized = 0.0
                    if quality != QualityCode.BAD:
                        quality = QualityCode.UNCERTAIN
                    active_ext_flags |= OPCQualityFlag.UNDERFLOW
                    active_limit = OPCQualityFlag.LOW_LIMITED

                # Low-flow cutoff enforcement (e.g. 2% of span forced to 0 flow)
                if self.low_flow_cutoff_percent > 0.0 and (normalized * 100.0) < self.low_flow_cutoff_percent:
                    eu_val = self.eu_min
                else:
                    eu_val = self.eu_min + math.sqrt(normalized) * span_eu

        elif self.scaling_type == ScalingType.PIECEWISE:
            if not self.piecewise_points or len(self.piecewise_points) < 2:
                quality = QualityCode.BAD
                active_substatus = OPCQualityFlag.CONFIG_ERROR
                active_ext_flags |= OPCQualityFlag.EXT_CONFIG_ERROR
                eu_val = self.eu_min
            else:
                pts = self.piecewise_points
                if raw_counts <= pts[0][0]:
                    # Lower clamp / extrapolation
                    eu_val = pts[0][1]
                    active_limit = OPCQualityFlag.LOW_LIMITED
                elif raw_counts >= pts[-1][0]:
                    # Upper clamp / extrapolation
                    eu_val = pts[-1][1]
                    active_limit = OPCQualityFlag.HIGH_LIMITED
                else:
                    for i in range(len(pts) - 1):
                        r0, e0 = pts[i]
                        r1, e1 = pts[i + 1]
                        if r0 <= raw_counts <= r1:
                            seg_span = r1 - r0
                            if seg_span == 0:
                                eu_val = e0
                            else:
                                t = (raw_counts - r0) / seg_span
                                eu_val = e0 + t * (e1 - e0)
                            break

        elif self.scaling_type == ScalingType.RTD:
            if self.rtd_mode == "TENTHS_DEG_C":
                # Standard Horner OCS RTD module: 254 counts = 25.4 degC
                eu_val = float(raw_counts) / 10.0
            else:
                # Callendar-Van Dusen platinum RTD equation (DIN EN 60751)
                r_val = float(raw_counts)
                r0 = self.rtd_r0
                a = self.rtd_a
                b = self.rtd_b
                if r_val <= 0.0:
                    quality = QualityCode.BAD
                    active_substatus = OPCQualityFlag.SENSOR_FAILURE
                    active_ext_flags |= OPCQualityFlag.UNDERFLOW | OPCQualityFlag.EXT_SENSOR_FAILURE
                    eu_val = self.eu_min
                elif r_val >= r0:
                    # T >= 0 °C: R(T) = R0 * (1 + A*T + B*T^2)
                    # B*T^2 + A*T + (1 - R/R0) = 0
                    disc = (a * a) - 4.0 * b * (1.0 - (r_val / r0))
                    if disc >= 0.0:
                        eu_val = (-a + math.sqrt(disc)) / (2.0 * b)
                    else:
                        quality = QualityCode.BAD
                        active_substatus = OPCQualityFlag.SENSOR_FAILURE
                        active_ext_flags |= OPCQualityFlag.EXT_SENSOR_FAILURE
                        eu_val = self.eu_max
                else:
                    # Linearized approximation for T < 0 °C
                    eu_val = (r_val / r0 - 1.0) / a

        # 4. Range limit checks on calculated EU
        if span_eu != 0:
            if eu_val < min(self.eu_min, self.eu_max):
                active_limit = OPCQualityFlag.LOW_LIMITED
                if quality != QualityCode.BAD:
                    quality = QualityCode.UNCERTAIN
                    active_substatus = OPCQualityFlag.EU_EXCEEDED
                active_ext_flags |= OPCQualityFlag.UNDERFLOW
            elif eu_val > max(self.eu_min, self.eu_max):
                active_limit = OPCQualityFlag.HIGH_LIMITED
                if quality != QualityCode.BAD:
                    quality = QualityCode.UNCERTAIN
                    active_substatus = OPCQualityFlag.EU_EXCEEDED
                active_ext_flags |= OPCQualityFlag.OVERFLOW

        # 5. IEEE 754 single-precision loss detection
        prec_loss = self._check_precision_loss(eu_val)
        if prec_loss:
            active_ext_flags |= OPCQualityFlag.PRECISION_LOSS

        # 6. NaN / Inf sanitization on calculated EU
        if math.isnan(eu_val) or math.isinf(eu_val):
            quality = QualityCode.BAD
            active_substatus = OPCQualityFlag.SENSOR_FAILURE
            active_ext_flags |= OPCQualityFlag.NAN_INF_FAULT | OPCQualityFlag.EXT_SENSOR_FAILURE
            eu_val = self.eu_min

        qw = encode_quality_word(
            quality=quality,
            substatus=active_substatus,
            limit=active_limit,
            extended_flags=active_ext_flags,
        )

        return float(eu_val), quality, qw

    def eu_to_raw(self, eu_value: float) -> Tuple[int, QualityCode, int]:
        """Converts engineering units to raw integer counts with precision and limit checks.

        Returns (raw_int_counts, QualityCode, 16_bit_quality_word).
        """
        # 1. NaN / Inf sanitization
        if math.isnan(eu_value) or math.isinf(eu_value):
            qw = encode_quality_word(
                QualityCode.BAD,
                substatus=OPCQualityFlag.CONFIG_ERROR,
                extended_flags=OPCQualityFlag.NAN_INF_FAULT | OPCQualityFlag.EXT_CONFIG_ERROR,
            )
            return int(self.raw_min), QualityCode.BAD, qw

        active_substatus = 0
        active_limit = OPCQualityFlag.LIMIT_NONE
        active_ext_flags = 0
        quality = QualityCode.GOOD

        span_raw = self.raw_max - self.raw_min
        span_eu = self.eu_max - self.eu_min

        raw_cont: float = self.raw_min

        if self.scaling_type == ScalingType.LINEAR:
            if span_eu == 0:
                quality = QualityCode.BAD
                active_substatus = OPCQualityFlag.CONFIG_ERROR
                active_ext_flags |= OPCQualityFlag.EXT_CONFIG_ERROR
                raw_cont = self.raw_min
            else:
                raw_cont = self.raw_min + ((eu_value - self.eu_min) / span_eu) * span_raw

        elif self.scaling_type == ScalingType.SQUARE_ROOT:
            if span_eu == 0:
                quality = QualityCode.BAD
                active_substatus = OPCQualityFlag.CONFIG_ERROR
                active_ext_flags |= OPCQualityFlag.EXT_CONFIG_ERROR
                raw_cont = self.raw_min
            else:
                norm = (eu_value - self.eu_min) / span_eu
                if norm < 0.0:
                    norm = 0.0
                    if quality != QualityCode.BAD:
                        quality = QualityCode.UNCERTAIN
                    active_ext_flags |= OPCQualityFlag.UNDERFLOW
                    active_limit = OPCQualityFlag.LOW_LIMITED
                raw_cont = self.raw_min + (norm ** 2) * span_raw

        elif self.scaling_type == ScalingType.PIECEWISE:
            if not self.piecewise_points or len(self.piecewise_points) < 2:
                quality = QualityCode.BAD
                active_substatus = OPCQualityFlag.CONFIG_ERROR
                active_ext_flags |= OPCQualityFlag.EXT_CONFIG_ERROR
                raw_cont = self.raw_min
            else:
                pts = self.piecewise_points
                # Monotonic assumption: test start and end
                is_ascending = pts[-1][1] >= pts[0][1]
                e_min = pts[0][1] if is_ascending else pts[-1][1]
                e_max = pts[-1][1] if is_ascending else pts[0][1]

                if eu_value <= e_min:
                    raw_cont = pts[0][0] if is_ascending else pts[-1][0]
                    active_limit = OPCQualityFlag.LOW_LIMITED
                elif eu_value >= e_max:
                    raw_cont = pts[-1][0] if is_ascending else pts[0][0]
                    active_limit = OPCQualityFlag.HIGH_LIMITED
                else:
                    found = False
                    for i in range(len(pts) - 1):
                        r0, e0 = pts[i]
                        r1, e1 = pts[i + 1]
                        if min(e0, e1) <= eu_value <= max(e0, e1):
                            seg_eu = e1 - e0
                            if seg_eu == 0:
                                raw_cont = r0
                            else:
                                t = (eu_value - e0) / seg_eu
                                raw_cont = r0 + t * (r1 - r0)
                            found = True
                            break
                    if not found:
                        raw_cont = pts[0][0]

        elif self.scaling_type == ScalingType.RTD:
            if self.rtd_mode == "TENTHS_DEG_C":
                raw_cont = eu_value * 10.0
            else:
                # Callendar-Van Dusen forward calculation: T -> R
                t_val = eu_value
                r0 = self.rtd_r0
                a = self.rtd_a
                b = self.rtd_b
                if t_val >= 0.0:
                    raw_cont = r0 * (1.0 + a * t_val + b * (t_val ** 2))
                else:
                    raw_cont = r0 * (1.0 + a * t_val)

        # Precision loss check
        if self._check_precision_loss(eu_value):
            active_ext_flags |= OPCQualityFlag.PRECISION_LOSS

        # Rounding and int16 boundary clamping
        raw_int = int(round(raw_cont))
        if raw_int < -32768:
            raw_int = -32768
            active_limit = OPCQualityFlag.LOW_LIMITED
            active_ext_flags |= OPCQualityFlag.UNDERFLOW
            if quality != QualityCode.BAD:
                quality = QualityCode.UNCERTAIN
        elif raw_int > 32767:
            raw_int = 32767
            active_limit = OPCQualityFlag.HIGH_LIMITED
            active_ext_flags |= OPCQualityFlag.OVERFLOW
            if quality != QualityCode.BAD:
                quality = QualityCode.UNCERTAIN

        # Namur NE43 check on calculated raw count if enabled
        if self.namur_ne43_enabled:
            namur_res = NamurNE43Validator.validate_raw(
                raw_int, self.namur_raw_4ma, self.namur_raw_20ma
            )
            if not namur_res.is_valid:
                quality = namur_res.quality_code
                active_ext_flags |= (namur_res.quality_word & 0xFF00)
                active_substatus = namur_res.quality_word & 0x003C
                active_limit = namur_res.quality_word & 0x0003

        qw = encode_quality_word(
            quality=quality,
            substatus=active_substatus,
            limit=active_limit,
            extended_flags=active_ext_flags,
        )

        return raw_int, quality, qw

    def _check_precision_loss(self, value: float) -> bool:
        """Detects whether single-precision IEEE 754 truncation causes significant loss."""
        if math.isnan(value) or math.isinf(value):
            return True
        try:
            if abs(value) > 16777216.0:
                return True
            packed = struct.pack("<f", float(value))
            f32 = struct.unpack("<f", packed)[0]
            diff = abs(value - f32)
            return diff > 1e-3
        except (OverflowError, struct.error):
            return True

    # -------------------------------------------------------------------------
    # Modbus Serialization: 16-bit Words <-> Engineering Units
    # -------------------------------------------------------------------------

    def encode_modbus_words(self, eu_value: Optional[float] = None) -> List[int]:
        """Packs the point's EU value into 16-bit Modbus words respecting configured word order.

        Returns a list of 16-bit unsigned integers [0..65535].
        If is_32bit_float is True: returns 2 words (IEEE 754 single-precision float).
        If is_32bit_float is False: returns 1 word (16-bit integer raw count).
        """
        val = eu_value if eu_value is not None else (self.current_eu if self.current_eu is not None else self.eu_min)

        if not self.is_32bit_float:
            raw_val, _, _ = self.eu_to_raw(val)
            return [raw_val & 0xFFFF]

        # 32-bit single-precision IEEE 754
        w1, w2 = float_to_words(float(val), word_order=self.word_order)
        return [w1 & 0xFFFF, w2 & 0xFFFF]

    def decode_modbus_words(self, words: Sequence[int]) -> Tuple[float, QualityCode, int]:
        """Unpacks 16-bit Modbus words into an EU value respecting configured word order."""
        if not words:
            qw = encode_quality_word(QualityCode.BAD, substatus=OPCQualityFlag.CONFIG_ERROR)
            return self.eu_min, QualityCode.BAD, qw

        if not self.is_32bit_float:
            raw_w = words[0] & 0xFFFF
            signed_raw = raw_w if raw_w <= 32767 else raw_w - 65536
            return self.raw_to_eu(signed_raw)

        if len(words) < 2:
            qw = encode_quality_word(QualityCode.BAD, substatus=OPCQualityFlag.CONFIG_ERROR)
            return self.eu_min, QualityCode.BAD, qw

        w1 = words[0] & 0xFFFF
        w2 = words[1] & 0xFFFF

        # Signed conversion for words_to_float
        s_w1 = w1 if w1 <= 32767 else w1 - 65536
        s_w2 = w2 if w2 <= 32767 else w2 - 65536

        eu_float = words_to_float(s_w1, s_w2, word_order=self.word_order)

        # Validate quality on unpacked float
        raw_int, qc, qw = self.eu_to_raw(eu_float)
        return eu_float, qc, qw

    def update_from_raw(self, raw_counts: int) -> float:
        """Updates internal live state from a raw register count reading."""
        eu_val, qc, qw = self.raw_to_eu(raw_counts)
        self.current_raw = raw_counts
        self.current_eu = eu_val
        self.current_quality = qc
        self.current_quality_word = qw
        self.precision_loss_detected = bool(qw & OPCQualityFlag.PRECISION_LOSS)
        self.last_update_timestamp = time.time()
        return eu_val

    def update_from_eu(self, eu_value: float) -> int:
        """Updates internal live state from an Engineering Unit float."""
        raw_int, qc, qw = self.eu_to_raw(eu_value)
        self.current_raw = raw_int
        self.current_eu = eu_value
        self.current_quality = qc
        self.current_quality_word = qw
        self.precision_loss_detected = bool(qw & OPCQualityFlag.PRECISION_LOSS)
        self.last_update_timestamp = time.time()
        return raw_int


class ModbusScalingBridge:
    """Industrial Modbus Register Scaling Bridge & Telemetry Quality Gateway.

    Maintains bidirectional synchronization between Horner OCS channel space (%AI, %AQ, %R)
    and Modbus input/holding registers with word-order endianness handling and quality tracking.
    """

    def __init__(self) -> None:
        self._points: Dict[str, TelemetryPoint] = {}
        self._channel_map: Dict[str, str] = {}
        self._holding_map: Dict[int, str] = {}
        self._input_map: Dict[int, str] = {}
        self._quality_map: Dict[int, str] = {}

        # Modbus register tables (16-bit unsigned words, 0..65535)
        self._holding_registers: Dict[int, int] = {}
        self._input_registers: Dict[int, int] = {}

    # -------------------------------------------------------------------------
    # Point Registration & Lookup
    # -------------------------------------------------------------------------

    def register_point(self, point: TelemetryPoint) -> None:
        """Registers a telemetry point and maps it to Modbus registers."""
        name = point.name
        self._points[name] = point
        self._channel_map[point.channel.upper()] = name

        addr = point.modbus_address
        word_count = 2 if point.is_32bit_float else 1

        if point.modbus_register_type == ModbusRegisterType.HOLDING:
            for offset in range(word_count):
                self._holding_map[addr + offset] = name
        else:
            for offset in range(word_count):
                self._input_map[addr + offset] = name

        if point.quality_modbus_address is not None:
            self._quality_map[point.quality_modbus_address] = name

        # Initialize registers from defaults
        self._refresh_point_registers(point)

    def get_point(self, name: str) -> Optional[TelemetryPoint]:
        """Retrieves a telemetry point by its unique name."""
        return self._points.get(name)

    def get_point_by_channel(self, channel: str) -> Optional[TelemetryPoint]:
        """Retrieves a telemetry point by its OCS channel address (e.g. '%AI1')."""
        name = self._channel_map.get(channel.upper())
        return self._points.get(name) if name else None

    def get_point_by_address(
        self,
        address: int,
        reg_type: ModbusRegisterType = ModbusRegisterType.HOLDING,
    ) -> Optional[TelemetryPoint]:
        """Retrieves a telemetry point mapped to a Modbus register address."""
        mapping = self._holding_map if reg_type == ModbusRegisterType.HOLDING else self._input_map
        name = mapping.get(address)
        return self._points.get(name) if name else None

    @property
    def points(self) -> Dict[str, TelemetryPoint]:
        """Returns all registered points."""
        return dict(self._points)

    # -------------------------------------------------------------------------
    # Modbus Low-Level Register Read / Write
    # -------------------------------------------------------------------------

    def read_modbus_registers(
        self,
        start_address: int,
        count: int,
        reg_type: ModbusRegisterType = ModbusRegisterType.HOLDING,
    ) -> List[int]:
        """Reads a contiguous block of 16-bit Modbus registers."""
        table = self._holding_registers if reg_type == ModbusRegisterType.HOLDING else self._input_registers
        result: List[int] = []
        for i in range(count):
            addr = start_address + i
            result.append(table.get(addr, 0) & 0xFFFF)
        return result

    def write_modbus_registers(
        self,
        start_address: int,
        words: List[int],
        reg_type: ModbusRegisterType = ModbusRegisterType.HOLDING,
    ) -> None:
        """Writes a contiguous block of 16-bit Modbus registers and updates mapped points."""
        table = self._holding_registers if reg_type == ModbusRegisterType.HOLDING else self._input_registers
        mapping = self._holding_map if reg_type == ModbusRegisterType.HOLDING else self._input_map

        # 1. Update low-level register table
        for i, val in enumerate(words):
            addr = start_address + i
            table[addr] = int(val) & 0xFFFF

        # 2. Identify affected points and trigger decoding
        affected_points = set()
        for i in range(len(words)):
            addr = start_address + i
            if addr in mapping:
                affected_points.add(mapping[addr])

        for pt_name in affected_points:
            pt = self._points[pt_name]
            base_addr = pt.modbus_address
            word_count = 2 if pt.is_32bit_float else 1
            pt_words = [table.get(base_addr + k, 0) for k in range(word_count)]
            eu_val, qc, qw = pt.decode_modbus_words(pt_words)
            pt.current_eu = eu_val
            pt.current_quality = qc
            pt.current_quality_word = qw
            pt.precision_loss_detected = bool(qw & OPCQualityFlag.PRECISION_LOSS)
            pt.current_raw, _, _ = pt.eu_to_raw(eu_val)
            pt.last_update_timestamp = time.time()

            # Refresh quality register if mapped
            if pt.quality_modbus_address is not None:
                table[pt.quality_modbus_address] = qw & 0xFFFF

    # -------------------------------------------------------------------------
    # High-Level Value Updates
    # -------------------------------------------------------------------------

    def update_point_raw(self, name_or_channel: str, raw_counts: int) -> float:
        """Updates a point from raw PLC counts, scales to EU, and refreshes Modbus registers."""
        pt = self.get_point(name_or_channel) or self.get_point_by_channel(name_or_channel)
        if not pt:
            raise KeyError(f"Telemetry point '{name_or_channel}' not found.")

        eu_val = pt.update_from_raw(raw_counts)
        self._refresh_point_registers(pt)
        return eu_val

    def update_point_eu(self, name_or_channel: str, eu_value: float) -> int:
        """Updates a point from an EU float, scales to raw counts, and refreshes Modbus registers."""
        pt = self.get_point(name_or_channel) or self.get_point_by_channel(name_or_channel)
        if not pt:
            raise KeyError(f"Telemetry point '{name_or_channel}' not found.")

        raw_val = pt.update_from_eu(eu_value)
        self._refresh_point_registers(pt)
        return raw_val

    def _refresh_point_registers(self, point: TelemetryPoint) -> None:
        """Packs point values into the appropriate Modbus register table."""
        words = point.encode_modbus_words()
        table = self._holding_registers if point.modbus_register_type == ModbusRegisterType.HOLDING else self._input_registers

        base_addr = point.modbus_address
        for offset, w in enumerate(words):
            table[base_addr + offset] = w & 0xFFFF

        if point.quality_modbus_address is not None:
            table[point.quality_modbus_address] = point.current_quality_word & 0xFFFF

    # -------------------------------------------------------------------------
    # Synchronization with Horner OCS RegisterTable
    # -------------------------------------------------------------------------

    def sync_from_ocs(self, reg_table: RegisterTable) -> Dict[str, float]:
        """Synchronizes OCS register table into telemetry bridge.

        Reads analog inputs (%AI) and intermediate word registers (%R),
        scales them to Engineering Units, performs quality checks, and updates Modbus map.
        """
        results: Dict[str, float] = {}
        for name, pt in self._points.items():
            # Only sync inputs / reads from OCS
            ch = pt.channel.upper()
            try:
                raw_count = reg_table.read_word(ch)
                eu_val = self.update_point_raw(name, raw_count)
                results[name] = eu_val
            except Exception:
                # Channel reading failed or not initialized
                pt.current_quality = QualityCode.BAD
                pt.current_quality_word = encode_quality_word(
                    QualityCode.BAD,
                    substatus=OPCQualityFlag.COMM_FAILURE,
                    extended_flags=OPCQualityFlag.EXT_SENSOR_FAILURE,
                )
                self._refresh_point_registers(pt)
                results[name] = pt.eu_min

        return results

    def sync_to_ocs(
        self,
        reg_table: RegisterTable,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> Dict[str, int]:
        """Synchronizes telemetry bridge setpoints / commands into OCS register table.

        Writes holding register values (%AQ, %R) back to Horner OCS registers.
        """
        results: Dict[str, int] = {}
        for name, pt in self._points.items():
            if pt.modbus_register_type == ModbusRegisterType.HOLDING:
                ch = pt.channel.upper()
                raw_val = pt.current_raw if pt.current_raw is not None else int(pt.raw_min)
                try:
                    reg_table.write_word(ch, raw_val, privilege=privilege)
                    results[name] = raw_val
                except Exception:
                    # Write failed (e.g. read-only channel violation)
                    pt.current_quality = QualityCode.BAD
                    pt.current_quality_word = encode_quality_word(
                        QualityCode.BAD,
                        substatus=OPCQualityFlag.CONFIG_ERROR,
                        extended_flags=OPCQualityFlag.EXT_CONFIG_ERROR,
                    )
        return results

    # -------------------------------------------------------------------------
    # Diagnostic & Quality Reporting
    # -------------------------------------------------------------------------

    def get_quality_summary(self) -> Dict[str, Any]:
        """Returns diagnostic ledger of all points and aggregate quality statistics."""
        good_count = 0
        uncertain_count = 0
        bad_count = 0
        point_details: Dict[str, Any] = {}

        for name, pt in self._points.items():
            if pt.current_quality == QualityCode.GOOD:
                good_count += 1
            elif pt.current_quality == QualityCode.UNCERTAIN:
                uncertain_count += 1
            else:
                bad_count += 1

            _, flags = decode_quality_word(pt.current_quality_word)

            point_details[name] = {
                "channel": pt.channel,
                "modbus_address": pt.modbus_address,
                "modbus_type": pt.modbus_register_type.value,
                "scaling": pt.scaling_type.value,
                "raw_value": pt.current_raw,
                "eu_value": pt.current_eu,
                "eu_unit": pt.eu_unit,
                "quality": pt.current_quality.value,
                "quality_word": f"0x{pt.current_quality_word:04X}",
                "quality_flags": flags,
                "precision_loss": pt.precision_loss_detected,
                "word_order": pt.word_order.value,
                "last_timestamp": pt.last_update_timestamp,
            }

        return {
            "total_points": len(self._points),
            "good_count": good_count,
            "uncertain_count": uncertain_count,
            "bad_count": bad_count,
            "points": point_details,
        }
