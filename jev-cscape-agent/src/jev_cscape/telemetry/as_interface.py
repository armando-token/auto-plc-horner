"""Industrial AS-Interface (AS-i v3.0 / EN 50295 / IEC 62026-2) Protocol Engine & Safety at Work Manager.

Work Package: W136 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Implements:
1. Physical Layer & Manchester APM Modulation (2-Wire Yellow Cable):
   - Alternating Pulse Modulation (APM) over unshielded 2-wire yellow ribbon cable.
   - Nominal 30V DC bus power supply with superimposed bidirectional communication pulses.
   - Baud rate: 167 kbit/s nominal (bit time T_bit = 6.0 us, pulse width T_pulse = 2.0 us).
   - 14-bit Master Request Frame (84.0 us) and 7-bit Slave Response Frame (42.0 us).
   - Even parity validation (PB) and strict framing delimiters (SB=0, EB=1).
   - Analytical transaction duration: 26 bit times = 156.0 us.
2. Extended A/B Addressing & Master Scan Cycle:
   - Standard addressing: up to 31 standard slaves (1..31) in 5ms scan cycle.
   - Extended A/B addressing: up to 62 slaves (1A..31A, 1B..31B) in 10ms split-phase cycle.
   - Alternating split-phase execution (Phase A 5ms, Phase B 5ms).
   - List management: LPS (Projected), LAS (Active), LDS (Detected), LPF (Peripheral Fault).
3. Safety at Work (SaW - EN 50295 / IEC 62026-2 / ISO 13849-1 PL e / IEC 62061 SIL 3):
   - 8x4-bit dynamic pseudo-random rolling code sequence generation and real-time monitoring.
   - Support for E-Stop, Safety Light Curtain, and Protective Gate Interlock devices.
   - Continuous dynamic code stream evaluation in < 40ms fail-safe reaction time.
   - Detection of static zero code (0x00), sequence desynchronization, corrupted nibbles,
     and frozen dynamic codes.
   - Dual redundant safety channel (Ch1, Ch2) discrepancy surveillance (timeout > 100ms).
4. Process Safety Interlocks & Diagnostics:
   - 0xA101: ASI_ERR_SAFETY_CODE_TRIP (dynamic safety sequence corrupted or E-stop activated)
             -> asserts %M227 (AsiSafetyAtWorkTrip), clears %M226 (AsiMasterActive).
   - 0xA102: ASI_ERR_CHANNEL_DISCREPANCY (dual safety input discrepancy timeout > 100ms)
             -> asserts %M227 (AsiSafetyAtWorkTrip).
   - 0xA103: ASI_ERR_SLAVE_OFFLINE (configured slave missing from LAS List of Active Slaves).
   - 0xA104: ASI_ERR_APM_NOISE_FAULT (Manchester bit timing or telegram error).
5. Horner OCS Memory Space Integration:
   - %R970: StatusWord / ActiveSlaveCount (0..62 slaves).
   - %R971: SafetyCodeSequenceWord (16-bit uint, dynamic safety sequence tracking).
   - %R972: CycleCounter (16-bit uint, master scan cycle counter).
   - %R973: PrimaryProcessInputScaled (INT16, scaled x10).
   - %R974: SecondaryProcessInputScaled (INT16, scaled x10).
   - %R975: TelegramErrorCounter (16-bit uint).
   - %R976: SafeChannelStatusWord (16-bit uint, channel 1 & channel 2 status).
   - %R977: DiagnosticStatusCode (0x0000=OK, 0xA101, 0xA102, 0xA103, 0xA104).
   - %M226: AsiMasterActive (BOOL, True when master online and communicating).
   - %M227: AsiSafetyAtWorkTrip (BOOL, True on safety trip or E-stop).
6. Pure IEC 61131-3 Structured Text (ST) POUs:
   - 'AsiSafetySync' and alias 'AsiNetworkSync' with strict anti-ladder guard.
7. Deterministic 9-Stage Verification Suite:
   - Autonomous verification returning strict 4-state contract JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import json
import math
from pathlib import Path
import struct
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Timing Definitions
# ============================================================================

ASI_BAUD_RATE_HZ: float = 166666.67        # 167 kbit/s nominal
ASI_BIT_TIME_US: float = 6.0               # 6.0 us nominal bit time
ASI_PULSE_TIME_US: float = 2.0             # 2.0 us APM pulse width
ASI_REQUEST_BITS: int = 14                 # Master request frame length (bits)
ASI_RESPONSE_BITS: int = 7                 # Slave response frame length (bits)
ASI_SLAVE_PAUSE_BITS: int = 3              # Slave turnaround pause (bits)
ASI_MASTER_PAUSE_BITS: int = 2             # Master guard pause (bits)
ASI_TRANSACTION_BITS: int = 26             # 14 + 3 + 7 + 2 = 26 bits
ASI_TRANSACTION_TIME_US: float = 156.0     # 26 * 6.0 us = 156.0 us

ASI_STANDARD_CYCLE_TIME_MS: float = 5.0    # 5.0 ms for <= 31 standard slaves
ASI_EXTENDED_CYCLE_TIME_MS: float = 10.0   # 10.0 ms for 62 extended A/B slaves
ASI_MAX_STANDARD_SLAVES: int = 31          # 31 standard slaves (1..31)
ASI_MAX_EXTENDED_SLAVES: int = 62          # 62 A/B slaves (1A..31A, 1B..31B)
ASI_MAX_SLAVES: int = 62
ASI_MAX_BANK_A_SLAVES: int = 31
ASI_MAX_BANK_B_SLAVES: int = 31

ASI_SAW_MAX_REACTION_TIME_S: float = 0.040 # 40 ms fail-safe reaction threshold
ASI_SAW_MAX_RESPONSE_TIME_MS: float = 40.0
ASI_DISCREPANCY_TIMEOUT_S: float = 0.100   # 100 ms dual-channel discrepancy threshold
ASI_SAW_DEFAULT_DISCREPANCY_TIMEOUT_S: float = 0.100

ASI_CABLE_NOMINAL_VOLTAGE_V: float = 30.0  # 30V DC bus power supply
ASI_APM_PULSE_VOLTAGE_V: float = 2.5       # Nominal +/- 2.5V modulation impulse
ASI_MAX_CABLE_LENGTH_M: float = 100.0      # 100m maximum cable length without repeater
ASI_APM_NOISE_THRESHOLD_V: float = 1.2     # Noise amplitude threshold triggering fault
ASI_BIT_TIMING_JITTER_TOLERANCE_PCT: float = 0.03  # 3% maximum bit timing jitter

# Master request frame bit positions (Bit 13 down to Bit 0)
REQ_SB_SHIFT: int   = 13
REQ_CB_SHIFT: int   = 12
REQ_ADDR_SHIFT: int = 7
REQ_INFO_SHIFT: int = 2
REQ_PB_SHIFT: int   = 1
REQ_EB_SHIFT: int   = 0

# Slave response frame bit positions (Bit 6 down to Bit 0)
RESP_SB_SHIFT: int   = 6
RESP_INFO_SHIFT: int = 2
RESP_PB_SHIFT: int   = 1
RESP_EB_SHIFT: int   = 0

# Safety at Work 8x4-bit dynamic pseudo-random sequence tables
SAW_ESTOP_SEQUENCE: Tuple[int, ...] = (0x0E, 0x0B, 0x07, 0x0D, 0x09, 0x06, 0x03, 0x05)
SAW_LIGHT_CURTAIN_SEQUENCE: Tuple[int, ...] = (0x0D, 0x07, 0x0B, 0x0E, 0x05, 0x03, 0x06, 0x09)
SAW_GATE_INTERLOCK_SEQUENCE: Tuple[int, ...] = (0x0B, 0x0E, 0x0D, 0x07, 0x06, 0x09, 0x05, 0x03)
SAW_GENERIC_SEQUENCE: Tuple[int, ...] = (0x09, 0x05, 0x06, 0x03, 0x0E, 0x0B, 0x0D, 0x07)
SAW_NOMINAL_SEQUENCE: Tuple[int, ...] = SAW_ESTOP_SEQUENCE


# ============================================================================
# 2. Exceptions
# ============================================================================

class AsiError(Exception):
    """Base exception for all AS-Interface protocol and runtime faults."""
    pass


class AsiSafetyTripError(AsiError):
    """Raised when Safety at Work sequence fails, freezes, or E-Stop is engaged."""
    pass


class AsiDiscrepancyError(AsiError):
    """Raised when dual redundant safety channels exceed 100ms discrepancy timeout."""
    pass


class AsiSlaveOfflineError(AsiError):
    """Raised when a projected slave is missing from the List of Active Slaves (LAS)."""
    pass


class AsiAPMNoiseError(AsiError):
    """Raised when Manchester APM bit timing jitter or line noise exceeds thresholds."""
    pass


class AsiFramingError(AsiError):
    """Raised when start bit, end bit, parity, or frame length is invalid."""
    pass


class AsiTimingError(AsiError):
    """Raised when master scan cycle timing or slave response pauses exceed specifications."""
    pass


# Compatibility aliases
ASInterfaceError = AsiError
SafetyAtWorkTripError = AsiSafetyTripError
DiscrepancyTimeoutError = AsiDiscrepancyError
FrameFormatError = AsiFramingError
SequenceDesyncError = AsiSafetyTripError
SlaveCapacityExceededError = AsiError
SlaveAddressingError = AsiError


# ============================================================================
# 3. Enumerations & Status Bitmasks
# ============================================================================

class AsiSlaveBank(IntEnum):
    """AS-Interface Slave Addressing Bank."""
    STANDARD = 0  # Standard Slave (Address 1..31)
    BANK_A   = 1  # Extended A-Slave (Address 1A..31A)
    BANK_B   = 2  # Extended B-Slave (Address 1B..31B)


class AsiMasterPhase(IntEnum):
    """AS-Interface Master Operational Phases (IEC 62026-2)."""
    INITIALIZATION = 1            # Reset, clear registries, verify bus DC voltage
    DETECTION_CONFIGURATION = 2   # Scan address space, verify projected vs detected
    ACTIVATION = 3                # Parameter downloading and safety synchronization
    NORMAL_OPERATION = 4          # Cyclic split-phase Data_Exchange active


class AsiCommandType(IntEnum):
    """AS-Interface Telegram Command Types."""
    DATA_EXCHANGE         = 0     # CB=0: Cyclic process I/O data exchange (DEXG)
    WRITE_PARAMETER       = 1     # CB=0: Parameter write (WPAR)
    SET_OFFLINE           = 2     # CB=1, Info=0x0F: Set slave to offline state
    READ_STATUS           = 3     # CB=1, Info=0x1D: Read slave status nibble
    READ_IO_CONFIG        = 4     # CB=1, Info=0x1E: Read 4-bit IO code
    READ_ID_CODE          = 5     # CB=1, Info=0x1F: Read 4-bit standard ID code
    READ_EXT_ID1          = 6     # CB=1, Info=0x1C: Read Extended ID1 code
    WRITE_EXT_ID1         = 7     # CB=1: Write Extended ID1 code
    ADDRESS_ASSIGNMENT    = 8     # CB=1: Reprogram address of slave at Addr 0
    RESET_SLAVE           = 9     # CB=1, Info=0x0C: Reset slave device


class AsiSafetyDeviceType(IntEnum):
    """AS-i Safety at Work Device Categories."""
    ESTOP           = 1  # Emergency Stop Pushbutton
    LIGHT_CURTAIN   = 2  # Optoelectronic Safety Light Curtain
    GATE_INTERLOCK  = 3  # Protective Guard Door Interlock
    GENERIC_SAFETY  = 4  # Generic SIL 3 Safety Sensor


class AsiDiagnosticCode(IntEnum):
    """Horner OCS %R977 Process Safety & Protocol Diagnostic Event Codes."""
    OK                          = 0x0000  # Communication normal, all safety monitors healthy
    ASI_ERR_SAFETY_CODE_TRIP    = 0xA101  # SaW dynamic sequence corrupted, frozen, or E-stop
    ASI_ERR_CHANNEL_DISCREPANCY = 0xA102  # Dual safety channel discrepancy timeout > 100ms
    ASI_ERR_SLAVE_OFFLINE       = 0xA103  # Configured slave missing from LAS
    ASI_ERR_APM_NOISE_FAULT     = 0xA104  # Manchester APM bit timing jitter or telegram error

    # Convenience aliases
    SAFETY_CODE_TRIP            = 0xA101
    CHANNEL_DISCREPANCY         = 0xA102
    SLAVE_OFFLINE               = 0xA103
    APM_NOISE_FAULT             = 0xA104


class AsiStatusBits(IntFlag):
    """Horner OCS %R970 Master Status Word Bitmasks."""
    MASTER_ACTIVE        = 1 << 0   # Bit 0 (0x0001): Master online and communicating
    NORMAL_OPERATION     = 1 << 1   # Bit 1 (0x0002): In Phase 4 Normal Operation
    SAW_MONITOR_HEALTHY  = 1 << 2   # Bit 2 (0x0004): Safety at Work monitor in sync and untripped
    APM_LINE_GOOD        = 1 << 3   # Bit 3 (0x0008): 30V DC bus power and APM waveforms nominal
    EXTENDED_AB_MODE     = 1 << 4   # Bit 4 (0x0010): Extended A/B addressing active
    SAFETY_TRIP          = 1 << 5   # Bit 5 (0x0020): SaW safety code trip active (0xA101)
    CHANNEL_DISCREPANCY  = 1 << 6   # Bit 6 (0x0040): Dual-channel discrepancy timeout active (0xA102)
    SLAVE_OFFLINE        = 1 << 7   # Bit 7 (0x0080): Configured slave missing from LAS (0xA103)
    APM_NOISE_FAULT      = 1 << 8   # Bit 8 (0x0100): APM noise or telegram error (0xA104)
    AUTO_ADDRESS_ACTIVE  = 1 << 9   # Bit 9 (0x0200): Automatic slave replacement active


class AsiSafeChannelStatusBits(IntFlag):
    """Horner OCS %R976 Safe Channel Status Word Bitmasks."""
    CH1_ACTIVE           = 1 << 0   # Bit 0 (0x0001): Dual safety channel 1 closed/healthy
    CH2_ACTIVE           = 1 << 1   # Bit 1 (0x0002): Dual safety channel 2 closed/healthy
    DISCREPANCY_ACTIVE   = 1 << 2   # Bit 2 (0x0004): Discrepancy detected (timer running)
    DISCREPANCY_FAULT    = 1 << 3   # Bit 3 (0x0008): Discrepancy timeout exceeded (> 100ms)
    SAW_STREAM_SYNC      = 1 << 4   # Bit 4 (0x0010): Dynamic safety sequence in valid synchronization
    SAFETY_HEALTHY       = 1 << 5   # Bit 5 (0x0020): All safety inputs and dynamic streams healthy
    ESTOP_CLOSED         = 1 << 6   # Bit 6 (0x0040): E-stop closed (unpressed)
    GUARD_LOCKED         = 1 << 7   # Bit 7 (0x0080): Protective gate interlock closed and locked


# Compatibility aliases
ASInterfacePhase = AsiMasterPhase
ASInterfaceSlaveBank = AsiSlaveBank
ASInterfaceCommandType = AsiCommandType
ASInterfaceDiagnosticCode = AsiDiagnosticCode
ASInterfaceStatusBits = AsiStatusBits
ASInterfaceSafeChannelStatusBits = AsiSafeChannelStatusBits


# ============================================================================
# 4. Analytical Formulas & Framing Helpers
# ============================================================================

def calc_transaction_time_us(bit_time_us: float = ASI_BIT_TIME_US) -> float:
    """Compute analytical duration of a single AS-i transaction slot (26 bit times = 156.0 us)."""
    return ASI_TRANSACTION_BITS * bit_time_us


def calculate_transaction_time_us(bit_time_us: float = ASI_BIT_TIME_US) -> float:
    """Analytical duration compatibility helper."""
    return calc_transaction_time_us(bit_time_us)


def calc_cycle_time_ms(slave_count: int, is_extended_ab: bool = False) -> float:
    """Compute standard or extended AS-i cycle time in milliseconds."""
    if is_extended_ab or slave_count > ASI_MAX_STANDARD_SLAVES:
        return ASI_EXTENDED_CYCLE_TIME_MS
    return ASI_STANDARD_CYCLE_TIME_MS


def calculate_cycle_time_us(
    n_slaves: int,
    n_mgmt_slots: int = 2,
    bit_time_us: float = ASI_BIT_TIME_US,
) -> float:
    """Compute analytical cycle time in microseconds: T_cycle = (N_slaves + 2) * 156.0 us."""
    total_slots = n_slaves + n_mgmt_slots
    return total_slots * calc_transaction_time_us(bit_time_us)


def compute_master_request_pb(sb: int, cb: int, address: int, info: int) -> int:
    """Compute Even Parity Bit for 14-bit Master Request Frame.

    PB = SB ^ CB ^ A4 ^ A3 ^ A2 ^ A1 ^ A0 ^ I4 ^ I3 ^ I2 ^ I1 ^ I0
    Ensures total number of set bits is even.
    """
    a_xor = (
        ((address >> 4) & 1)
        ^ ((address >> 3) & 1)
        ^ ((address >> 2) & 1)
        ^ ((address >> 1) & 1)
        ^ (address & 1)
    )
    i_xor = (
        ((info >> 4) & 1)
        ^ ((info >> 3) & 1)
        ^ ((info >> 2) & 1)
        ^ ((info >> 1) & 1)
        ^ (info & 1)
    )
    return (sb & 1) ^ (cb & 1) ^ a_xor ^ i_xor


def compute_slave_response_pb(sb: int, info: int) -> int:
    """Compute Even Parity Bit for 7-bit Slave Response Frame.

    PB = SB ^ I3 ^ I2 ^ I1 ^ I0
    Ensures total number of set bits is even.
    """
    i_xor = (
        ((info >> 3) & 1)
        ^ ((info >> 2) & 1)
        ^ ((info >> 1) & 1)
        ^ (info & 1)
    )
    return (sb & 1) ^ i_xor


def scale_process_input_to_int16(val: float, scale_factor: float = 10.0) -> int:
    """Scale floating-point process input to INT16 register units."""
    scaled = int(round(val * scale_factor))
    return max(-32768, min(32767, scaled))


compute_request_pb = compute_master_request_pb
compute_response_pb = compute_slave_response_pb


# ============================================================================
# 5. Telegram Frame Entities
# ============================================================================

@dataclass
class AsiMasterRequestFrame:
    """AS-Interface 14-bit Master Request Frame Data Link Entity."""
    command: AsiCommandType
    address: int              # 0..31
    info: int                 # 0..31 (5 bits)
    cb: int = 0               # Control bit: 0=data, 1=command
    sb: int = 0               # Start Bit: 0
    pb: int = 0               # Even Parity Bit
    eb: int = 1               # End Bit: 1

    def encode_raw_word(self) -> int:
        """Encode request frame into 14-bit unsigned integer."""
        self.pb = compute_master_request_pb(self.sb, self.cb, self.address, self.info)
        return (
            ((self.sb & 1) << REQ_SB_SHIFT)
            | ((self.cb & 1) << REQ_CB_SHIFT)
            | ((self.address & 0x1F) << REQ_ADDR_SHIFT)
            | ((self.info & 0x1F) << REQ_INFO_SHIFT)
            | ((self.pb & 1) << REQ_PB_SHIFT)
            | (self.eb & 1)
        )

    def encode_apm_pulses(self) -> List[int]:
        """Encode request frame into physical 28-pulse APM Manchester sequence."""
        return encode_apm_manchester(self.encode_raw_word(), ASI_REQUEST_BITS)

    @classmethod
    def decode_raw_word(cls, word: int) -> Tuple[Optional[AsiMasterRequestFrame], str]:
        """Decode and validate a 14-bit word into an AsiMasterRequestFrame."""
        if word < 0 or word > 0x3FFF:
            return None, "ERR_FRAME_LENGTH"
        sb = (word >> REQ_SB_SHIFT) & 1
        if sb != 0:
            return None, "ERR_START_BIT"
        eb = (word >> REQ_EB_SHIFT) & 1
        if eb != 1:
            return None, "ERR_END_BIT"
        cb = (word >> REQ_CB_SHIFT) & 1
        address = (word >> REQ_ADDR_SHIFT) & 0x1F
        info = (word >> REQ_INFO_SHIFT) & 0x1F
        received_pb = (word >> REQ_PB_SHIFT) & 1
        expected_pb = compute_master_request_pb(sb, cb, address, info)
        if received_pb != expected_pb:
            return None, "ERR_PARITY"

        cmd = AsiCommandType.DATA_EXCHANGE if cb == 0 else AsiCommandType.READ_STATUS
        return cls(
            command=cmd,
            address=address,
            info=info,
            cb=cb,
            sb=sb,
            pb=received_pb,
            eb=eb,
        ), "OK"


@dataclass
class AsiSlaveResponseFrame:
    """AS-Interface 7-bit Slave Response Frame Data Link Entity."""
    info: int                 # 0..15 (4 bits)
    sb: int = 0               # Start Bit: 0
    pb: int = 0               # Even Parity Bit
    eb: int = 1               # End Bit: 1

    def encode_raw_word(self) -> int:
        """Encode response frame into 7-bit unsigned integer."""
        self.pb = compute_slave_response_pb(self.sb, self.info)
        return (
            ((self.sb & 1) << RESP_SB_SHIFT)
            | ((self.info & 0x0F) << RESP_INFO_SHIFT)
            | ((self.pb & 1) << RESP_PB_SHIFT)
            | (self.eb & 1)
        )

    def encode_apm_pulses(self) -> List[int]:
        """Encode response frame into physical 14-pulse APM Manchester sequence."""
        return encode_apm_manchester(self.encode_raw_word(), ASI_RESPONSE_BITS)

    @classmethod
    def decode_raw_word(cls, word: int) -> Tuple[Optional[AsiSlaveResponseFrame], str]:
        """Decode and validate a 7-bit word into an AsiSlaveResponseFrame."""
        if word < 0 or word > 0x7F:
            return None, "ERR_FRAME_LENGTH"
        sb = (word >> RESP_SB_SHIFT) & 1
        if sb != 0:
            return None, "ERR_START_BIT"
        eb = (word >> RESP_EB_SHIFT) & 1
        if eb != 1:
            return None, "ERR_END_BIT"
        info = (word >> RESP_INFO_SHIFT) & 0x0F
        received_pb = (word >> RESP_PB_SHIFT) & 1
        expected_pb = compute_slave_response_pb(sb, info)
        if received_pb != expected_pb:
            return None, "ERR_PARITY"

        return cls(info=info, sb=sb, pb=received_pb, eb=eb), "OK"


def encode_apm_manchester(data_word: int, bit_count: int) -> List[int]:
    """Encode binary word into Alternating Pulse Modulation (APM) Manchester pulses."""
    pulses: List[int] = []
    current_polarity = 1
    for i in range(bit_count - 1, -1, -1):
        bit = (data_word >> i) & 1
        if bit == 0:
            pulses.append(current_polarity)
            pulses.append(-current_polarity)
            current_polarity = -current_polarity
        else:
            pulses.append(0)
            pulses.append(0)
    return pulses


def decode_apm_manchester(pulses: List[int]) -> int:
    """Decode Alternating Pulse Modulation (APM) Manchester pulses back to integer."""
    if len(pulses) % 2 != 0:
        raise AsiFramingError(f"Pulse sequence length {len(pulses)} is not even.")
    decoded = 0
    for i in range(0, len(pulses), 2):
        p1, p2 = pulses[i], pulses[i + 1]
        decoded <<= 1
        if (p1 != 0 or p2 != 0) and (p1 == -p2):
            pass  # Bit 0
        elif p1 == 0 and p2 == 0:
            decoded |= 1  # Bit 1
        else:
            raise AsiFramingError(f"Invalid APM pulse transition at offset {i}: [{p1}, {p2}]")
    return decoded


# Compatibility frame aliases
ASInterfaceRequestFrame = AsiMasterRequestFrame
ASInterfaceResponseFrame = AsiSlaveResponseFrame


# ============================================================================
# 6. Physical Layer Simulation (Manchester APM & 2-Wire Yellow Cable)
# ============================================================================

class ManchesterAPMSimulator:
    """Simulates Manchester Alternating Pulse Modulation (APM) over 30V DC 2-wire ribbon cable."""

    def __init__(
        self,
        nominal_voltage_v: float = ASI_CABLE_NOMINAL_VOLTAGE_V,
        pulse_amplitude_v: float = ASI_APM_PULSE_VOLTAGE_V,
        cable_length_m: float = 50.0,
    ):
        self.nominal_voltage_v = nominal_voltage_v
        self.pulse_amplitude_v = pulse_amplitude_v
        self.cable_length_m = min(cable_length_m, ASI_MAX_CABLE_LENGTH_M)
        self.attenuation_per_m = 0.005  # 0.5V attenuation per 100m
        self.noise_amplitude_v = 0.0
        self.jitter_us = 0.0

    def verify_apm_bit_timing(
        self,
        measured_bit_time_us: float,
        tolerance_pct: float = ASI_BIT_TIMING_JITTER_TOLERANCE_PCT,
    ) -> bool:
        """Verify measured bit timing against nominal 6.0 us within tolerance (default 3%)."""
        min_allowed = ASI_BIT_TIME_US * (1.0 - tolerance_pct)
        max_allowed = ASI_BIT_TIME_US * (1.0 + tolerance_pct)
        return min_allowed <= measured_bit_time_us <= max_allowed

    def simulate_pulse_train(
        self,
        bits: Union[int, List[int]],
        bit_count: int = 14,
        noise_v: float = 0.0,
        jitter_us: float = 0.0,
    ) -> List[Tuple[float, float]]:
        """Simulate physical Manchester APM pulse train waveform on 2-wire yellow cable.

        In AS-i APM, bit 0 produces an alternating positive/negative pulse pair (2.0 us width),
        while bit 1 produces no modulation pulse. Returns list of (time_us, voltage_v) samples.
        """
        self.noise_amplitude_v = noise_v
        self.jitter_us = jitter_us

        bit_list: List[int] = []
        if isinstance(bits, int):
            for i in range(bit_count - 1, -1, -1):
                bit_list.append((bits >> i) & 1)
        else:
            bit_list = list(bits)[:bit_count]

        samples: List[Tuple[float, float]] = []
        current_time_us = 0.0
        pulse_polarity = 1  # Alternates: +1, -1, +1, -1...

        # Line attenuation factor
        att_factor = max(0.6, 1.0 - (self.cable_length_m * self.attenuation_per_m))
        eff_pulse_amp = self.pulse_amplitude_v * att_factor

        for bit in bit_list:
            # Add jitter to bit duration
            actual_bit_time = ASI_BIT_TIME_US + jitter_us

            if bit == 0:
                # Active APM modulation pulse pair
                v_pulse_pos = self.nominal_voltage_v + (eff_pulse_amp * pulse_polarity) + noise_v
                v_pulse_neg = self.nominal_voltage_v - (eff_pulse_amp * pulse_polarity) + noise_v
                v_idle = self.nominal_voltage_v + noise_v

                # First half of pulse (1.0 us)
                samples.append((round(current_time_us, 3), v_pulse_pos))
                # Second half of pulse (1.0 us)
                samples.append((round(current_time_us + 1.0, 3), v_pulse_neg))
                # Idle for remaining bit time (4.0 us)
                samples.append((round(current_time_us + ASI_PULSE_TIME_US, 3), v_idle))
                samples.append((round(current_time_us + actual_bit_time, 3), v_idle))

                # Alternate pulse polarity for DC balance
                pulse_polarity = -pulse_polarity
            else:
                # Bit 1: Idle DC voltage (no APM pulse)
                v_idle = self.nominal_voltage_v + noise_v
                samples.append((round(current_time_us, 3), v_idle))
                samples.append((round(current_time_us + actual_bit_time, 3), v_idle))

            current_time_us += actual_bit_time

        return samples

    def check_physical_layer_integrity(
        self,
        noise_v: float = 0.0,
        jitter_us: float = 0.0,
    ) -> Tuple[bool, Optional[str]]:
        """Validate physical layer parameters against noise and jitter limits."""
        if abs(noise_v) > ASI_APM_NOISE_THRESHOLD_V:
            return False, "ERR_APM_NOISE_EXCESSIVE"
        if abs(jitter_us) > (ASI_BIT_TIME_US * 0.10):  # > 10% jitter (0.6 us)
            return False, "ERR_APM_JITTER_EXCESSIVE"
        if self.cable_length_m > ASI_MAX_CABLE_LENGTH_M:
            return False, "ERR_CABLE_LENGTH_EXCEEDED"
        return True, None


# ============================================================================
# 7. Safety at Work (SaW) Subsystem & Dynamic Code Generator
# ============================================================================

def generate_safety_code_sequence(
    device_type: AsiSafetyDeviceType = AsiSafetyDeviceType.ESTOP,
    seed: int = 0,
) -> Tuple[int, ...]:
    """Generate deterministic 8x4-bit dynamic safety code sequence table."""
    if device_type == AsiSafetyDeviceType.ESTOP:
        base = list(SAW_ESTOP_SEQUENCE)
    elif device_type == AsiSafetyDeviceType.LIGHT_CURTAIN:
        base = list(SAW_LIGHT_CURTAIN_SEQUENCE)
    elif device_type == AsiSafetyDeviceType.GATE_INTERLOCK:
        base = list(SAW_GATE_INTERLOCK_SEQUENCE)
    else:
        base = list(SAW_GENERIC_SEQUENCE)

    if seed != 0:
        rot = seed % len(base)
        base = base[rot:] + base[:rot]

    return tuple(base)


def verify_saw_code_sequence(sequence: Tuple[int, ...]) -> bool:
    """Validate that an 8-step SaW code sequence satisfies safety requirements."""
    if len(sequence) != 8:
        return False
    if any(n <= 0 or n > 15 for n in sequence):
        return False
    for i in range(len(sequence)):
        if sequence[i] == sequence[(i + 1) % len(sequence)]:
            return False
    return True


class DualChannelDiscrepancyDetector:
    """Detects discrepancies between redundant safety channels."""

    def __init__(self, discrepancy_timeout_s: float = ASI_DISCREPANCY_TIMEOUT_S):
        self.discrepancy_timeout_s = discrepancy_timeout_s
        self.is_in_discrepancy: bool = False
        self.discrepancy_start_time: float = 0.0
        self.is_tripped: bool = False

    def evaluate(self, ch1: bool, ch2: bool, current_time: float) -> Tuple[bool, Optional[str]]:
        if self.is_tripped:
            return False, "ERR_SAW_CHANNEL_DISCREPANCY_LATCHED"
        if ch1 == ch2:
            self.is_in_discrepancy = False
            self.discrepancy_start_time = 0.0
            return True, None
        if not self.is_in_discrepancy:
            self.is_in_discrepancy = True
            self.discrepancy_start_time = current_time
            return True, None
        elapsed = current_time - self.discrepancy_start_time
        if elapsed > self.discrepancy_timeout_s:
            self.is_tripped = True
            return False, f"ERR_SAW_CHANNEL_DISCREPANCY: elapsed {elapsed * 1000.0:.1f}ms > {self.discrepancy_timeout_s * 1000.0:.1f}ms"
        return True, None

    def reset(self) -> None:
        self.is_in_discrepancy = False
        self.discrepancy_start_time = 0.0
        self.is_tripped = False


@dataclass
class AsiSafetyDevice:
    """AS-i Safety at Work Slave Device Entity with Dual Channel Monitoring."""
    device_id: int
    address: int
    bank: AsiSlaveBank = AsiSlaveBank.STANDARD
    device_type: AsiSafetyDeviceType = AsiSafetyDeviceType.ESTOP
    channel_1: bool = True               # Dual safety channel 1 (closed=True)
    channel_2: bool = True               # Dual safety channel 2 (closed=True)
    sequence_table: Tuple[int, ...] = field(default_factory=lambda: SAW_ESTOP_SEQUENCE)
    current_step: int = 0
    is_tripped: bool = False
    discrepancy_timer_s: float = 0.0
    discrepancy_active: bool = False
    discrepancy_tripped: bool = False
    discrepancy_timeout_s: float = ASI_DISCREPANCY_TIMEOUT_S

    def __post_init__(self) -> None:
        if self.sequence_table is None or len(self.sequence_table) != 8:
            self.sequence_table = generate_safety_code_sequence(self.device_type)

    def set_channels(self, ch1: bool, ch2: bool) -> None:
        """Update dual redundant safety input contacts."""
        self.channel_1 = ch1
        self.channel_2 = ch2
        if ch1 != ch2:
            self.discrepancy_active = True
        else:
            self.discrepancy_active = False
            if not self.discrepancy_tripped:
                self.discrepancy_timer_s = 0.0

    def update_discrepancy(self, dt_s: float) -> bool:
        """Step discrepancy surveillance timer. Returns True if discrepancy fault tripped."""
        if self.channel_1 != self.channel_2:
            self.discrepancy_active = True
            self.discrepancy_timer_s += dt_s
            if self.discrepancy_timer_s > self.discrepancy_timeout_s:
                self.discrepancy_tripped = True
                self.is_tripped = True
                return True
        else:
            self.discrepancy_active = False
            if not self.discrepancy_tripped:
                self.discrepancy_timer_s = 0.0
        return self.discrepancy_tripped

    def get_next_dynamic_nibble(self, force_corrupt: bool = False, force_zero: bool = False) -> int:
        """Produce the next 4-bit dynamic safety code nibble."""
        if force_zero or not self.channel_1 or not self.channel_2 or self.is_tripped:
            return 0x00  # Static zero code on open contacts / safety trip

        if force_corrupt:
            val = (self.sequence_table[self.current_step] ^ 0x05) & 0x0F
            if val == 0:
                val = 0x01
            return val

        val = self.sequence_table[self.current_step] & 0x0F
        self.current_step = (self.current_step + 1) % len(self.sequence_table)
        return val


class AsiSafetyMonitor:
    """AS-i Safety at Work (SIL 3 / PL e) Real-Time Dynamic Code Stream Monitor."""

    def __init__(
        self,
        expected_sequence: Optional[Tuple[int, ...]] = None,
        max_reaction_time_s: float = ASI_SAW_MAX_REACTION_TIME_S,
        discrepancy_timeout_s: float = ASI_DISCREPANCY_TIMEOUT_S,
    ):
        self.expected_sequence = expected_sequence or SAW_ESTOP_SEQUENCE
        self.sequence_len = len(self.expected_sequence)
        self.max_reaction_time_s = max_reaction_time_s
        self.discrepancy_timeout_s = discrepancy_timeout_s

        self.current_expected_step: int = 0
        self.is_latched_trip: bool = False
        self.trip_reason: Optional[str] = None
        self.last_update_time: float = time.time()
        self.consecutive_valid_codes: int = 0
        self.last_received_code: int = 0
        self.discrepancy_fault_latched: bool = False

    def reset_safety(self) -> None:
        """Operator manual reset handshake to clear latched safety trip."""
        self.is_latched_trip = False
        self.discrepancy_fault_latched = False
        self.trip_reason = None
        self.current_expected_step = 0
        self.last_update_time = time.time()
        self.consecutive_valid_codes = 0
        self.last_received_code = 0

    def evaluate_code_nibble(
        self,
        nibble: int,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Evaluate continuous dynamic safety code nibble within < 40ms threshold.

        Returns (is_healthy, trip_reason).
        """
        if self.is_latched_trip:
            return False, self.trip_reason

        now = current_time if current_time is not None else time.time()
        elapsed = now - self.last_update_time

        # Check 1: Static zero code (E-stop pressed or line dropout)
        if (nibble & 0x0F) == 0x00:
            self.is_latched_trip = True
            self.trip_reason = "ERR_SAW_STATIC_ZERO_CODE"
            return False, self.trip_reason

        # Check 2: Dynamic code stream timeout (> 40ms)
        if elapsed > self.max_reaction_time_s and self.consecutive_valid_codes > 0:
            self.is_latched_trip = True
            self.trip_reason = "ERR_SAW_STREAM_TIMEOUT"
            return False, self.trip_reason

        # Check 3: Static frozen code (identical non-zero nibble repeated)
        if self.consecutive_valid_codes > 0 and nibble == self.last_received_code:
            expected_current = self.expected_sequence[self.current_expected_step]
            prev_expected = self.expected_sequence[(self.current_expected_step - 1) % self.sequence_len]
            if expected_current != prev_expected:
                self.is_latched_trip = True
                self.trip_reason = "ERR_SAW_FROZEN_CODE"
                return False, self.trip_reason

        # Check 4: Sequence table value match
        expected_code = self.expected_sequence[self.current_expected_step] & 0x0F
        if (nibble & 0x0F) != expected_code:
            self.is_latched_trip = True
            self.trip_reason = (
                f"ERR_SAW_CODE_MISMATCH: Step {self.current_expected_step} "
                f"expected {expected_code:#X}, got {nibble:#X}"
            )
            return False, self.trip_reason

        # Advance step & record health
        self.last_received_code = nibble & 0x0F
        self.current_expected_step = (self.current_expected_step + 1) % self.sequence_len
        self.last_update_time = now
        self.consecutive_valid_codes += 1
        return True, None

    def trigger_discrepancy_trip(self) -> None:
        """Trigger dual channel discrepancy trip fault (0xA102)."""
        self.is_latched_trip = True
        self.discrepancy_fault_latched = True
        self.trip_reason = "ERR_SAW_DUAL_CHANNEL_DISCREPANCY_TIMEOUT"

    @property
    def current_step(self) -> int:
        return self.current_expected_step

    @current_step.setter
    def current_step(self, val: int) -> None:
        self.current_expected_step = val

    @property
    def diagnostic_code(self) -> AsiDiagnosticCode:
        if self.is_latched_trip:
            if self.discrepancy_fault_latched:
                return AsiDiagnosticCode.ASI_ERR_CHANNEL_DISCREPANCY
            if self.trip_reason == "ERR_SAW_STREAM_TIMEOUT":
                return AsiDiagnosticCode.ASI_ERR_SAFETY_CODE_TRIP
            return AsiDiagnosticCode.ASI_ERR_SAFETY_CODE_TRIP
        return AsiDiagnosticCode.OK

    def process_code_nibble(self, nibble: int, current_time: Optional[float] = None) -> bool:
        """Compatibility method: evaluate dynamic code nibble and return boolean."""
        ok, _ = self.evaluate_code_nibble(nibble, current_time=current_time)
        return ok

    def process_dual_channel_inputs(self, ch1: bool, ch2: bool, current_time: Optional[float] = None) -> bool:
        """Compatibility method: evaluate dual-channel inputs against discrepancy."""
        if self.is_latched_trip:
            return False
        now = current_time if current_time is not None else time.time()
        if not hasattr(self, "_dual_detector"):
            self._dual_detector = DualChannelDiscrepancyDetector(self.discrepancy_timeout_s)
        ok, reason = self._dual_detector.evaluate(ch1, ch2, now)
        if not ok:
            self.trigger_discrepancy_trip()
            return False
        return True


# Aliases for compatibility
AsiSafetyAtWorkMonitor = AsiSafetyMonitor
ASInterfaceSafetyMonitor = AsiSafetyMonitor
ASInterfaceSafetyDevice = AsiSafetyDevice
ASInterfaceSafetyDeviceType = AsiSafetyDeviceType
generate_saw_code_table = generate_safety_code_sequence


# ============================================================================
# 8. Slave Node Profile & Descriptor
# ============================================================================

@dataclass
class AsiSlaveDescriptor:
    """AS-Interface Slave Node Profile and Runtime State."""
    address: int                            # 0..31
    bank: AsiSlaveBank = AsiSlaveBank.STANDARD
    io_code: int = 0x7                      # Default 4 DI / 4 DO
    id_code: int = 0x0                      # 0x0 for standard, 0x0A for extended A/B
    ext_id1: int = 0x0                      # Bit 3: 0=A, 1=B
    ext_id2: int = 0x0                      # Device profile
    di_nibble: int = 0x0                    # Process Data Input (4 bits)
    do_nibble: int = 0x0                    # Process Data Output (4 bits)
    parameter_nibble: int = 0xF             # Parameter latch (P3..P0)
    is_online: bool = True
    is_safety_slave: bool = False
    safety_device: Optional[AsiSafetyDevice] = None
    consecutive_errors: int = 0
    transient_errors: int = 0

    @property
    def key(self) -> str:
        """Formatted node key, e.g. '1', '1A', '2B', or '0'."""
        if self.address == 0:
            return "0"
        if self.bank == AsiSlaveBank.STANDARD:
            return str(self.address)
        suffix = "B" if self.bank == AsiSlaveBank.BANK_B else "A"
        return f"{self.address}{suffix}"


ASInterfaceSlaveDescriptor = AsiSlaveDescriptor


# ============================================================================
# 9. AS-Interface Master Protocol Engine
# ============================================================================

class AsiMaster:
    """Industrial AS-Interface (EN 50295 / IEC 62026-2) Master Engine.

    Synchronizes real-time bus metrics, Manchester APM telemetry, and SaW dynamic
    safety monitoring into Horner OCS registers (%R970..%R977, %M226..%M227).
    """

    def __init__(
        self,
        register_table: Optional[RegisterTable] = None,
        is_extended_ab: bool = False,
    ):
        self.reg_table = register_table or RegisterTable()
        self.is_extended_ab = is_extended_ab
        self.phase: AsiMasterPhase = AsiMasterPhase.INITIALIZATION
        self.status_bits: AsiStatusBits = AsiStatusBits.MASTER_ACTIVE | AsiStatusBits.APM_LINE_GOOD
        if self.is_extended_ab:
            self.status_bits |= AsiStatusBits.EXTENDED_AB_MODE
        self.safe_channel_status: AsiSafeChannelStatusBits = (
            AsiSafeChannelStatusBits.CH1_ACTIVE
            | AsiSafeChannelStatusBits.CH2_ACTIVE
            | AsiSafeChannelStatusBits.SAW_STREAM_SYNC
            | AsiSafeChannelStatusBits.SAFETY_HEALTHY
            | AsiSafeChannelStatusBits.ESTOP_CLOSED
            | AsiSafeChannelStatusBits.GUARD_LOCKED
        )
        self.diagnostic_code: AsiDiagnosticCode = AsiDiagnosticCode.OK

        # Slave registries (IEC 62026-2 standard lists)
        self.lps: Dict[str, AsiSlaveDescriptor] = {}  # List of Projected Slaves (Configured)
        self.las: Dict[str, AsiSlaveDescriptor] = {}  # List of Active Slaves
        self.lds: Dict[str, AsiSlaveDescriptor] = {}  # List of Detected Slaves
        self.lpf: Set[str] = set()                    # List of Peripheral Faults
        self.configured_slaves: Dict[str, AsiSlaveDescriptor] = self.lps
        self.detected_slaves: Dict[str, AsiSlaveDescriptor] = self.lds
        self.missing_slaves: Set[str] = set()
        self.replacement_slave: Optional[AsiSlaveDescriptor] = None

        # Subsystems
        self.apm_sim = ManchesterAPMSimulator()
        self.safety_monitor = AsiSafetyMonitor()
        self.safety_devices: Dict[str, AsiSafetyDevice] = {}

        # Scan metrics
        self.cycle_counter: int = 0
        self.current_split_phase: AsiSlaveBank = AsiSlaveBank.BANK_A
        self.cycle_time_ms: float = ASI_EXTENDED_CYCLE_TIME_MS if is_extended_ab else ASI_STANDARD_CYCLE_TIME_MS
        self.cycle_time_us: float = 0.0
        self.primary_pv: float = 0.0
        self.secondary_sv: float = 0.0
        self.telegram_error_counter: int = 0
        self.total_transfers: int = 0
        self.bus_power_good: bool = True

        # Initialize registers
        self._sync_registers()

    @property
    def active_slave_count(self) -> int:
        """Count of currently active slaves in LAS."""
        return len(self.las)

    @property
    def status_word(self) -> int:
        """Formatted %R970 word: High byte = ActiveSlaveCount, Low byte = StatusBits."""
        count_byte = min(62, self.active_slave_count) & 0xFF
        flags_byte = int(self.status_bits) & 0xFF
        return (count_byte << 8) | flags_byte

    def register_slave(self, slave: AsiSlaveDescriptor) -> None:
        """Configure a projected slave into LPS and LAS."""
        key = slave.key
        self.lps[key] = slave
        self.las[key] = slave
        self.lds[key] = slave

        if slave.is_safety_slave:
            if slave.safety_device is None:
                dev = AsiSafetyDevice(
                    device_id=slave.address,
                    address=slave.address,
                    bank=slave.bank,
                    device_type=AsiSafetyDeviceType.ESTOP,
                )
                slave.safety_device = dev
            self.safety_devices[key] = slave.safety_device

        if slave.bank in (AsiSlaveBank.BANK_A, AsiSlaveBank.BANK_B) or len(self.lps) > ASI_MAX_STANDARD_SLAVES:
            self.is_extended_ab = True
            self.cycle_time_ms = ASI_EXTENDED_CYCLE_TIME_MS
            self.status_bits |= AsiStatusBits.EXTENDED_AB_MODE

        self._sync_registers()

    def add_configured_slave(self, slave: AsiSlaveDescriptor) -> None:
        """Compatibility alias for register_slave."""
        self.register_slave(slave)

    def advance_phase(self, phase: AsiMasterPhase) -> None:
        """Transition master operational phase."""
        self.phase = phase
        if phase == AsiMasterPhase.NORMAL_OPERATION:
            self.status_bits |= AsiStatusBits.NORMAL_OPERATION
        else:
            self.status_bits &= ~AsiStatusBits.NORMAL_OPERATION
        self._sync_registers()

    def set_bus_power(self, power_ok: bool) -> None:
        """Simulate APF (AS-i Power Fail) 30V line monitoring."""
        self.bus_power_good = power_ok
        if power_ok:
            self.status_bits |= AsiStatusBits.APM_LINE_GOOD
            if self.diagnostic_code == AsiDiagnosticCode.ASI_ERR_APM_NOISE_FAULT:
                self.diagnostic_code = AsiDiagnosticCode.OK
        else:
            self.status_bits &= ~AsiStatusBits.APM_LINE_GOOD
            self.status_bits |= AsiStatusBits.APM_NOISE_FAULT
            self.diagnostic_code = AsiDiagnosticCode.ASI_ERR_APM_NOISE_FAULT
        self._sync_registers()

    def trigger_safety_trip(self, code: AsiDiagnosticCode = AsiDiagnosticCode.ASI_ERR_SAFETY_CODE_TRIP) -> None:
        """Assert fail-safe safety trip (%M227=True, %M226=False)."""
        self.diagnostic_code = code
        self.status_bits |= AsiStatusBits.SAFETY_TRIP
        self.status_bits &= ~AsiStatusBits.SAW_MONITOR_HEALTHY
        self.safe_channel_status &= ~AsiSafeChannelStatusBits.SAFETY_HEALTHY
        self.safe_channel_status &= ~AsiSafeChannelStatusBits.SAW_STREAM_SYNC
        self.safe_channel_status |= AsiSafeChannelStatusBits.DISCREPANCY_FAULT
        self._sync_registers()

    def reset_safety(self) -> None:
        """Execute operator manual safety reset handshake."""
        self.safety_monitor.reset_safety()
        for dev in self.safety_devices.values():
            dev.is_tripped = False
            dev.discrepancy_tripped = False
            dev.discrepancy_timer_s = 0.0
            dev.discrepancy_active = False

        self.status_bits &= ~AsiStatusBits.SAFETY_TRIP
        self.status_bits &= ~AsiStatusBits.CHANNEL_DISCREPANCY
        self.status_bits |= AsiStatusBits.SAW_MONITOR_HEALTHY
        self.status_bits |= AsiStatusBits.MASTER_ACTIVE

        self.safe_channel_status = (
            AsiSafeChannelStatusBits.CH1_ACTIVE
            | AsiSafeChannelStatusBits.CH2_ACTIVE
            | AsiSafeChannelStatusBits.SAW_STREAM_SYNC
            | AsiSafeChannelStatusBits.SAFETY_HEALTHY
            | AsiSafeChannelStatusBits.ESTOP_CLOSED
            | AsiSafeChannelStatusBits.GUARD_LOCKED
        )
        self.diagnostic_code = AsiDiagnosticCode.OK
        self._sync_registers()

    def poll_slave(
        self,
        slave: AsiSlaveDescriptor,
        force_error: bool = False,
        force_timeout: bool = False,
    ) -> Tuple[bool, Optional[int]]:
        """Simulate Master Request / Slave Response Data_Exchange transaction."""
        req = AsiMasterRequestFrame(
            command=AsiCommandType.DATA_EXCHANGE,
            address=slave.address,
            info=slave.do_nibble & 0x0F,
            cb=0,
        )
        _ = req.encode_raw_word()
        self.total_transfers += 1

        if force_error or force_timeout or not slave.is_online or not self.bus_power_good:
            self.telegram_error_counter += 1
            slave.consecutive_errors += 1
            if slave.consecutive_errors >= 3:
                slave.is_online = False
                self.missing_slaves.add(slave.key)
                if slave.key in self.las:
                    del self.las[slave.key]
                self.status_bits |= AsiStatusBits.SLAVE_OFFLINE
                self.diagnostic_code = AsiDiagnosticCode.ASI_ERR_SLAVE_OFFLINE
            return False, None

        slave.consecutive_errors = 0
        if slave.is_safety_slave and slave.safety_device:
            resp_nibble = slave.safety_device.get_next_dynamic_nibble()
        else:
            resp_nibble = slave.di_nibble & 0x0F

        resp = AsiSlaveResponseFrame(info=resp_nibble)
        _ = resp.encode_raw_word()
        return True, resp_nibble

    def simulate_slave_poll(
        self,
        slave: AsiSlaveDescriptor,
        force_parity_err: bool = False,
        force_timeout: bool = False,
    ) -> Tuple[bool, Optional[AsiSlaveResponseFrame]]:
        """Compatibility method for test suites."""
        ok, nibble = self.poll_slave(slave, force_error=force_parity_err, force_timeout=force_timeout)
        if ok and nibble is not None:
            return True, AsiSlaveResponseFrame(info=nibble)
        return False, None

    def introduce_replacement_slave_at_zero(
        self,
        io_code: int = 0x7,
        id_code: int = 0x0,
    ) -> None:
        """Introduce an unconfigured replacement slave at Address 0."""
        self.replacement_slave = AsiSlaveDescriptor(
            address=0,
            bank=AsiSlaveBank.STANDARD,
            io_code=io_code,
            id_code=id_code,
            is_online=True,
        )
        self.status_bits |= AsiStatusBits.AUTO_ADDRESS_ACTIVE
        self._sync_registers()

    def evaluate_auto_addressing(self) -> Optional[str]:
        """Automatically re-address replacement slave at Address 0 if exactly 1 slave is missing."""
        if len(self.missing_slaves) != 1 or self.replacement_slave is None:
            return None

        missing_key = next(iter(self.missing_slaves))
        target_slave = self.lps.get(missing_key)
        if target_slave is None:
            return None

        if (
            self.replacement_slave.io_code == target_slave.io_code
            and self.replacement_slave.id_code == target_slave.id_code
        ):
            target_slave.is_online = True
            target_slave.consecutive_errors = 0
            self.las[missing_key] = target_slave
            self.missing_slaves.remove(missing_key)
            self.replacement_slave = None
            self.status_bits &= ~AsiStatusBits.SLAVE_OFFLINE
            self.status_bits &= ~AsiStatusBits.AUTO_ADDRESS_ACTIVE
            if self.diagnostic_code == AsiDiagnosticCode.ASI_ERR_SLAVE_OFFLINE:
                self.diagnostic_code = AsiDiagnosticCode.OK
            self._sync_registers()
            return f"AUTO_ADDRESSED_{missing_key}"

        return None

    def step_scan_cycle(
        self,
        elapsed_s: float = 0.005,
        pv_val: Optional[float] = None,
        sv_val: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Execute one complete master scan cycle across active slaves."""
        self.cycle_counter = (self.cycle_counter + 1) & 0xFFFF

        if pv_val is not None:
            self.primary_pv = pv_val
        if sv_val is not None:
            self.secondary_sv = sv_val

        # Select slaves to poll based on split-phase
        slaves_to_poll: List[AsiSlaveDescriptor] = []
        for key, slave in list(self.las.items()):
            if slave.bank == AsiSlaveBank.STANDARD or slave.bank == self.current_split_phase:
                slaves_to_poll.append(slave)

        polls_ok = 0
        for slave in slaves_to_poll:
            if slave.is_safety_slave and slave.safety_device:
                disc_tripped = slave.safety_device.update_discrepancy(elapsed_s)
                if disc_tripped:
                    self.safety_monitor.trigger_discrepancy_trip()
                    self.status_bits |= AsiStatusBits.CHANNEL_DISCREPANCY
                    self.safe_channel_status |= AsiSafeChannelStatusBits.DISCREPANCY_FAULT
                    self.trigger_safety_trip(AsiDiagnosticCode.ASI_ERR_CHANNEL_DISCREPANCY)

            ok, nibble = self.poll_slave(slave)
            if ok and nibble is not None:
                polls_ok += 1
                if slave.is_safety_slave:
                    saw_ok, reason = self.safety_monitor.evaluate_code_nibble(nibble)
                    if not saw_ok:
                        self.trigger_safety_trip(AsiDiagnosticCode.ASI_ERR_SAFETY_CODE_TRIP)

        # Toggle split-phase
        if self.is_extended_ab:
            self.current_split_phase = (
                AsiSlaveBank.BANK_B if self.current_split_phase == AsiSlaveBank.BANK_A else AsiSlaveBank.BANK_A
            )
            self.cycle_time_ms = ASI_EXTENDED_CYCLE_TIME_MS
        else:
            self.cycle_time_ms = ASI_STANDARD_CYCLE_TIME_MS

        self.cycle_time_us = calculate_cycle_time_us(len(slaves_to_poll))

        # Check missing projected slaves
        for key in self.lps:
            if key not in self.las:
                self.status_bits |= AsiStatusBits.SLAVE_OFFLINE
                if self.diagnostic_code == AsiDiagnosticCode.OK:
                    self.diagnostic_code = AsiDiagnosticCode.ASI_ERR_SLAVE_OFFLINE

        self._sync_registers()
        return {
            "cycle_counter": self.cycle_counter,
            "split_phase": "BANK_A" if self.current_split_phase == AsiSlaveBank.BANK_B else "BANK_B",
            "active_slaves": len(self.las),
            "polls_successful": polls_ok,
            "successful_polls": polls_ok,
            "diagnostic_code": f"0x{self.diagnostic_code:04X}",
        }

    def execute_bus_cycle(self) -> Dict[str, Any]:
        """Compatibility alias for step_scan_cycle."""
        return self.step_scan_cycle()

    def _sync_registers(self) -> None:
        """Synchronize in-memory engine state with Horner OCS register space (%R970..%R977, %M226..%M227)."""
        # %R970: StatusWord / ActiveSlaveCount (0..62 slaves)
        self.reg_table.write_word("%R970", self.status_word, privilege=PrivilegeMode.SYSTEM)

        # %R971: SafetyCodeSequenceWord (16-bit uint, dynamic safety sequence tracking)
        seq_word = (
            ((self.safety_monitor.current_expected_step & 0x0F) << 12)
            | ((self.safety_monitor.last_received_code & 0x0F) << 8)
            | (self.safety_monitor.consecutive_valid_codes & 0xFF)
        )
        self.reg_table.write_word("%R971", seq_word & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %R972: CycleCounter (16-bit uint)
        self.reg_table.write_word("%R972", self.cycle_counter & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %R973: PrimaryProcessInputScaled (INT16, scaled x10)
        pv_scaled = scale_process_input_to_int16(self.primary_pv, scale_factor=10.0)
        self.reg_table.write_word("%R973", pv_scaled, privilege=PrivilegeMode.SYSTEM)

        # %R974: SecondaryProcessInputScaled (INT16, scaled x10)
        sv_scaled = scale_process_input_to_int16(self.secondary_sv, scale_factor=10.0)
        self.reg_table.write_word("%R974", sv_scaled, privilege=PrivilegeMode.SYSTEM)

        # %R975: TelegramErrorCounter (16-bit uint)
        self.reg_table.write_word("%R975", self.telegram_error_counter & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %R976: SafeChannelStatusWord (16-bit uint, channel 1 & channel 2 status)
        self.reg_table.write_word("%R976", int(self.safe_channel_status) & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %R977: DiagnosticStatusCode (16-bit uint: 0x0000, 0xA101..0xA104)
        self.reg_table.write_word("%R977", int(self.diagnostic_code) & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %M227: AsiSafetyAtWorkTrip (BOOL, True on safety trip or E-stop)
        is_tripped = (
            self.diagnostic_code in (
                AsiDiagnosticCode.ASI_ERR_SAFETY_CODE_TRIP,
                AsiDiagnosticCode.ASI_ERR_CHANNEL_DISCREPANCY,
            )
            or bool(self.status_bits & (AsiStatusBits.SAFETY_TRIP | AsiStatusBits.CHANNEL_DISCREPANCY))
            or self.safety_monitor.is_latched_trip
        )
        self.reg_table.write_bit("%M227", is_tripped, privilege=PrivilegeMode.SYSTEM)

        # %M226: AsiMasterActive (BOOL, True when master online and communicating)
        is_active = (
            not is_tripped
            and bool(self.status_bits & AsiStatusBits.MASTER_ACTIVE)
            and self.diagnostic_code == AsiDiagnosticCode.OK
            and self.bus_power_good
        )
        self.reg_table.write_bit("%M226", is_active, privilege=PrivilegeMode.SYSTEM)


# Aliases for architecture compatibility
AsiMasterEngine = AsiMaster
AsiProtocolEngine = AsiMaster
ASInterfaceMasterEngine = AsiMaster


# ============================================================================
# 10. Pure IEC 61131-3 Structured Text POUs
# ============================================================================

ASI_SAFETY_SYNC_PURE_ST_POU: str = """PROGRAM AsiSafetySync
VAR
    StatusWord AT %R970 : WORD;
    SafetyCodeSequenceWord AT %R971 : UINT;
    CycleCounter AT %R972 : UINT;
    PrimaryProcessInputScaled AT %R973 : INT;
    SecondaryProcessInputScaled AT %R974 : INT;
    TelegramErrorCounter AT %R975 : UINT;
    SafeChannelStatusWord AT %R976 : WORD;
    DiagnosticStatusCode AT %R977 : WORD;
    AsiMasterActive AT %M226 : BOOL;
    AsiSafetyAtWorkTrip AT %M227 : BOOL;

    SafetyCodeTripFault : BOOL;
    ChannelDiscrepancyTripFault : BOOL;
    SlaveOfflineFault : BOOL;
    ApmNoiseFault : BOOL;
END_VAR

SafetyCodeTripFault := (DiagnosticStatusCode = 16#A101) OR ((SafeChannelStatusWord AND 16#0008) <> 0);
ChannelDiscrepancyTripFault := (DiagnosticStatusCode = 16#A102) OR ((SafeChannelStatusWord AND 16#0008) <> 0);
SlaveOfflineFault := (DiagnosticStatusCode = 16#A103);
ApmNoiseFault := (DiagnosticStatusCode = 16#A104);

IF SafetyCodeTripFault OR ChannelDiscrepancyTripFault THEN
    AsiSafetyAtWorkTrip := TRUE;
    AsiMasterActive := FALSE;
ELSE
    AsiSafetyAtWorkTrip := FALSE;
    IF (StatusWord AND 16#0001) <> 0 AND NOT SlaveOfflineFault AND NOT ApmNoiseFault THEN
        AsiMasterActive := TRUE;
    ELSE
        AsiMasterActive := FALSE;
    END_IF;
END_IF;
END_PROGRAM
"""

ASI_NETWORK_SYNC_PURE_ST_POU: str = """PROGRAM AsiNetworkSync
VAR
    ActiveSlaveCount AT %R970 : INT;
    SafetyCodeSequenceWord AT %R971 : UINT;
    CycleCounter AT %R972 : UINT;
    PrimaryProcessInputScaled AT %R973 : INT;
    SecondaryProcessInputScaled AT %R974 : INT;
    TelegramErrorCounter AT %R975 : UINT;
    SafeChannelStatusWord AT %R976 : WORD;
    DiagnosticStatusCode AT %R977 : WORD;
    AsiMasterActive AT %M226 : BOOL;
    AsiSafetyAtWorkTrip AT %M227 : BOOL;
END_VAR

IF (DiagnosticStatusCode = 16#A101) OR (DiagnosticStatusCode = 16#A102) THEN
    AsiSafetyAtWorkTrip := TRUE;
    AsiMasterActive := FALSE;
ELSE
    AsiSafetyAtWorkTrip := FALSE;
    IF (ActiveSlaveCount > 0) AND (DiagnosticStatusCode = 16#0000) THEN
        AsiMasterActive := TRUE;
    ELSE
        AsiMasterActive := FALSE;
    END_IF;
END_IF;
END_PROGRAM
"""

# Compatibility aliases
ASI_PURE_ST_POU: str = ASI_SAFETY_SYNC_PURE_ST_POU
ASI_SAFETY_POU: str = ASI_SAFETY_SYNC_PURE_ST_POU
ASI_NETWORK_POU: str = ASI_NETWORK_SYNC_PURE_ST_POU
ASI_SAFETY_TELEMETRY_SYNC_PURE_ST_POU: str = ASI_SAFETY_SYNC_PURE_ST_POU.replace(
    "PROGRAM AsiSafetySync", "PROGRAM ASiSafetyTelemetrySync"
)
AS_INTERFACE_SAFETY_TELEMETRY_SYNC_PURE_ST_POU: str = ASI_SAFETY_TELEMETRY_SYNC_PURE_ST_POU


def verify_as_interface_pure_st() -> bool:
    """Validate AsiSafetySync and AsiNetworkSync POUs with STParser and SecurityGuard."""
    # 1. Assert pure ST content on both POUs
    SecurityGuard.assert_pure_st_content(ASI_SAFETY_SYNC_PURE_ST_POU)
    SecurityGuard.assert_pure_st_content(ASI_NETWORK_SYNC_PURE_ST_POU)

    # 2. Parse AST via STParser
    parser = STParser()
    pou_safety = parser.parse_pou(ASI_SAFETY_SYNC_PURE_ST_POU)
    pou_net = parser.parse_pou(ASI_NETWORK_SYNC_PURE_ST_POU)

    if not pou_safety or not pou_net:
        return False

    safety_ok = (
        pou_safety.name == "AsiSafetySync"
        and pou_safety.pou_type == POUType.PROGRAM
        and "%R970" in pou_safety.bound_registers
        and "%R977" in pou_safety.bound_registers
        and "%M226" in pou_safety.bound_registers
        and "%M227" in pou_safety.bound_registers
    )

    net_ok = (
        pou_net.name == "AsiNetworkSync"
        and pou_net.pou_type == POUType.PROGRAM
        and "%R970" in pou_net.bound_registers
        and "%R977" in pou_net.bound_registers
        and "%M226" in pou_net.bound_registers
        and "%M227" in pou_net.bound_registers
    )

    return safety_ok and net_ok


def verify_asi_safety_pure_st() -> bool:
    """Convenience alias for pure ST validation."""
    return verify_as_interface_pure_st()


# ============================================================================
# 11. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_as_interface_verification(
    output_path: Optional[str] = None,
    evidence_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute complete 9-stage verification suite for AS-Interface Protocol Engine (W136).

    Returns strict 4-state contract JSON.
    """
    tests_record: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
    # ------------------------------------------------------------------------
    st_ok = verify_as_interface_pure_st()
    res_safety = STParser.validate_code(ASI_SAFETY_SYNC_PURE_ST_POU)
    res_net = STParser.validate_code(ASI_NETWORK_SYNC_PURE_ST_POU)
    s1_pass = st_ok and (res_safety.status == AgentStatus.SUCCESS) and (res_net.status == AgentStatus.SUCCESS)
    tests_record.append({
        "stage": 1,
        "check": "Pure_ST_POU_AST_Symbol_Binding",
        "passed": s1_pass,
        "details": "Validated AsiSafetySync and AsiNetworkSync POUs with bound registers %R970..%R977, %M226..%M227.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Anti-Ladder Security Guard Rejection
    # ------------------------------------------------------------------------
    bad_contacts = "PROGRAM BadContacts\nVAR X: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM"
    bad_rungs = "PROGRAM BadRungs\nRUNG 1:\n  XIC(Start) OTE(Motor);\nEND_PROGRAM"
    rejected_cnt = 0
    for bad_code in (bad_contacts, bad_rungs):
        try:
            SecurityGuard.assert_pure_st_content(bad_code)
        except LadderForbiddenError:
            rejected_cnt += 1
    s2_pass = (rejected_cnt == 2)
    tests_record.append({
        "stage": 2,
        "check": "Anti_Ladder_Security_Guard_Rejection",
        "passed": s2_pass,
        "details": "Asserted LadderForbiddenError on ladder contacts, coils, rungs, and mnemonics.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Manchester APM Bit Timing & Cable Physical Layer Simulation
    # ------------------------------------------------------------------------
    apm = ManchesterAPMSimulator(cable_length_m=50.0)
    waveform = apm.simulate_pulse_train(0x2A55, bit_count=14)
    timing_ok = apm.verify_apm_bit_timing(6.0)
    timing_jitter_fail = not apm.verify_apm_bit_timing(6.5, tolerance_pct=0.03)
    phys_ok, _ = apm.check_physical_layer_integrity(noise_v=0.2, jitter_us=0.05)
    phys_noise_fail, err_noise = apm.check_physical_layer_integrity(noise_v=1.5)
    s3_pass = (
        len(waveform) > 20
        and timing_ok
        and timing_jitter_fail
        and phys_ok
        and (not phys_noise_fail)
        and err_noise == "ERR_APM_NOISE_EXCESSIVE"
    )
    tests_record.append({
        "stage": 3,
        "check": "Manchester_APM_Bit_Timing_And_Physical_Layer",
        "passed": s3_pass,
        "details": "Verified 167 kbit/s APM pulse modulation (T_bit=6.0us), jitter boundaries, and noise limits.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: AS-i Master Scan Cycle Engine & Extended A/B Addressing
    # ------------------------------------------------------------------------
    master_std = AsiMaster(register_table=RegisterTable(), is_extended_ab=False)
    for addr in range(1, 32):
        master_std.register_slave(AsiSlaveDescriptor(address=addr, bank=AsiSlaveBank.STANDARD))

    master_ext = AsiMaster(register_table=RegisterTable(), is_extended_ab=True)
    for addr in range(1, 32):
        master_ext.register_slave(AsiSlaveDescriptor(address=addr, bank=AsiSlaveBank.BANK_A))
        master_ext.register_slave(AsiSlaveDescriptor(address=addr, bank=AsiSlaveBank.BANK_B))

    s4_pass = (
        master_std.active_slave_count == 31
        and master_std.cycle_time_ms == ASI_STANDARD_CYCLE_TIME_MS
        and master_ext.active_slave_count == 62
        and master_ext.cycle_time_ms == ASI_EXTENDED_CYCLE_TIME_MS
        and bool(master_ext.status_bits & AsiStatusBits.EXTENDED_AB_MODE)
    )
    tests_record.append({
        "stage": 4,
        "check": "Master_Scan_Cycle_And_Extended_AB_Addressing",
        "passed": s4_pass,
        "details": "Verified 5ms standard cycle for 31 slaves and 10ms split-phase cycle for 62 A/B slaves.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Safety at Work (SaW) Dynamic Code Sequence Generation
    # ------------------------------------------------------------------------
    estop_seq = generate_safety_code_sequence(AsiSafetyDeviceType.ESTOP)
    curtain_seq = generate_safety_code_sequence(AsiSafetyDeviceType.LIGHT_CURTAIN)
    interlock_seq = generate_safety_code_sequence(AsiSafetyDeviceType.GATE_INTERLOCK)

    s5_pass = (
        len(estop_seq) == 8
        and len(curtain_seq) == 8
        and len(interlock_seq) == 8
        and all(0 < n < 0x0F for n in estop_seq)
        and all(0 < n < 0x0F for n in curtain_seq)
        and all(0 < n < 0x0F for n in interlock_seq)
        and estop_seq != curtain_seq
    )
    tests_record.append({
        "stage": 5,
        "check": "Safety_At_Work_Dynamic_Code_Sequence_Generation",
        "passed": s5_pass,
        "details": "Verified deterministic 8x4-bit dynamic sequence tables for E-stop, Light Curtain, and Gate Interlock.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: SaW Safety Monitor Fast Evaluation (< 40ms Trip)
    # ------------------------------------------------------------------------
    mon = AsiSafetyMonitor(expected_sequence=SAW_ESTOP_SEQUENCE, max_reaction_time_s=0.040)
    for step in range(4):
        ok, _ = mon.evaluate_code_nibble(SAW_ESTOP_SEQUENCE[step])
        assert ok is True

    # Test static zero trip
    mon_zero = AsiSafetyMonitor(expected_sequence=SAW_ESTOP_SEQUENCE)
    zero_ok, zero_reason = mon_zero.evaluate_code_nibble(0x00)

    # Test code mismatch trip
    mon_mismatch = AsiSafetyMonitor(expected_sequence=SAW_ESTOP_SEQUENCE)
    bad_ok, bad_reason = mon_mismatch.evaluate_code_nibble(0x02)

    # Test timeout trip (> 40ms)
    mon_time = AsiSafetyMonitor(expected_sequence=SAW_ESTOP_SEQUENCE, max_reaction_time_s=0.040)
    mon_time.evaluate_code_nibble(SAW_ESTOP_SEQUENCE[0])
    time_ok, time_reason = mon_time.evaluate_code_nibble(SAW_ESTOP_SEQUENCE[1], current_time=time.time() + 0.050)

    s6_pass = (
        mon.consecutive_valid_codes == 4
        and zero_ok is False
        and zero_reason == "ERR_SAW_STATIC_ZERO_CODE"
        and bad_ok is False
        and "ERR_SAW_CODE_MISMATCH" in str(bad_reason)
        and time_ok is False
        and time_reason == "ERR_SAW_STREAM_TIMEOUT"
    )
    tests_record.append({
        "stage": 6,
        "check": "SaW_Safety_Monitor_Fast_Evaluation",
        "passed": s6_pass,
        "details": "Asserted < 40ms fail-safe trip on static zero code (0x00), sequence mismatch, and step timeout.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Dual Redundant Safety Channel Discrepancy Monitoring
    # ------------------------------------------------------------------------
    safe_dev = AsiSafetyDevice(
        device_id=5,
        address=5,
        device_type=AsiSafetyDeviceType.ESTOP,
        discrepancy_timeout_s=0.100,
    )
    # Channels in sync
    safe_dev.set_channels(ch1=True, ch2=True)
    trip_sync = safe_dev.update_discrepancy(dt_s=0.020)

    # Discrepancy introduced for 50ms (transient, <= 100ms)
    safe_dev.set_channels(ch1=False, ch2=True)
    safe_dev.update_discrepancy(dt_s=0.050)
    trip_50ms = safe_dev.discrepancy_tripped

    # Discrepancy exceeds 100ms
    safe_dev.update_discrepancy(dt_s=0.060)  # total 110ms
    trip_110ms = safe_dev.discrepancy_tripped

    s7_pass = (
        trip_sync is False
        and trip_50ms is False
        and trip_110ms is True
        and safe_dev.is_tripped is True
    )
    tests_record.append({
        "stage": 7,
        "check": "Dual_Redundant_Safety_Channel_Discrepancy",
        "passed": s7_pass,
        "details": "Verified transient discrepancy tolerance (50ms <= 100ms) and discrepancy trip (> 100ms).",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Process Safety Interlocks & Horner OCS Memory Space Sync
    # ------------------------------------------------------------------------
    rt = RegisterTable()
    mgr = AsiMaster(register_table=rt)
    dev_estop = AsiSafetyDevice(device_id=1, address=1, device_type=AsiSafetyDeviceType.ESTOP)
    mgr.register_slave(AsiSlaveDescriptor(address=1, is_safety_slave=True, safety_device=dev_estop))
    mgr.advance_phase(AsiMasterPhase.NORMAL_OPERATION)
    mgr.step_scan_cycle(pv_val=45.6, sv_val=12.3)

    r970 = rt.read_uword("%R970")
    r971 = rt.read_uword("%R971")
    r972 = rt.read_uword("%R972")
    r973 = rt.read_word("%R973")
    r974 = rt.read_word("%R974")
    r975 = rt.read_uword("%R975")
    r976 = rt.read_uword("%R976")
    r977 = rt.read_uword("%R977")
    m226 = rt.read_bit("%M226")
    m227 = rt.read_bit("%M227")

    # Trigger safety code trip 0xA101
    mgr.trigger_safety_trip(AsiDiagnosticCode.ASI_ERR_SAFETY_CODE_TRIP)
    trip_m227 = rt.read_bit("%M227")
    trip_m226 = rt.read_bit("%M226")
    code_a101 = rt.read_uword("%R977")

    s8_pass = (
        bool(r970 & AsiStatusBits.MASTER_ACTIVE)
        and (r970 >> 8) & 0x7F == 1
        and r972 == 1
        and r973 == 456
        and r974 == 123
        and r975 == 0
        and r977 == 0x0000
        and m226 is True
        and m227 is False
        and trip_m227 is True
        and trip_m226 is False
        and code_a101 == 0xA101
    )
    tests_record.append({
        "stage": 8,
        "check": "Horner_OCS_Memory_Space_Synchronization",
        "passed": s8_pass,
        "details": "Verified %R970..%R977 bindings, PV/SV scaling (45.6->456), and 0xA101 trip (%M227=TRUE, %M226=FALSE).",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Closed-Loop Scan Cycle Simulation & Trip Recovery Pipeline
    # ------------------------------------------------------------------------
    sim_master = AsiMaster(register_table=RegisterTable())
    sim_dev = AsiSafetyDevice(device_id=2, address=2, device_type=AsiSafetyDeviceType.ESTOP)
    sim_master.register_slave(AsiSlaveDescriptor(address=2, is_safety_slave=True, safety_device=sim_dev))
    sim_master.advance_phase(AsiMasterPhase.NORMAL_OPERATION)

    # Step normal cycles
    for _ in range(10):
        sim_master.step_scan_cycle(pv_val=50.0, sv_val=25.0)

    # Inject E-stop trip (static zero code)
    sim_dev.channel_1 = False
    sim_master.step_scan_cycle()
    assert sim_master.reg_table.read_bit("%M227") is True
    assert sim_master.reg_table.read_bit("%M226") is False

    # Operator Reset Handshake
    sim_dev.channel_1 = True
    sim_dev.channel_2 = True
    sim_master.reset_safety()

    rec_m226 = sim_master.reg_table.read_bit("%M226")
    rec_m227 = sim_master.reg_table.read_bit("%M227")
    rec_code = sim_master.reg_table.read_uword("%R977")

    s9_pass = (rec_m226 is True and rec_m227 is False and rec_code == 0x0000)
    tests_record.append({
        "stage": 9,
        "check": "Closed_Loop_Simulation_And_Trip_Recovery",
        "passed": s9_pass,
        "details": "Simulated closed-loop scan cycle, tripped E-stop, and recovered cleanly via operator reset handshake.",
    })

    all_passed = all(t["passed"] for t in tests_record)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": (
            f"Industrial AS-Interface (AS-i v3.0 / SaW) Protocol Engine verified cleanly "
            f"({sum(1 for t in tests_record if t['passed'])}/{len(tests_record)} checks passed)."
        ),
        "data": {
            "work_package": "W136",
            "gate": "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation",
            "component": "Industrial AS-Interface (AS-i) Safety at Work & Actuator-Sensor Telemetry Engine",
            "checks_passed": sum(1 for t in tests_record if t["passed"]),
            "total_checks": len(tests_record),
            "tests": tests_record,
            "metrics": {
                "baud_rate_hz": ASI_BAUD_RATE_HZ,
                "bit_time_us": ASI_BIT_TIME_US,
                "transaction_time_us": ASI_TRANSACTION_TIME_US,
                "standard_cycle_time_ms": ASI_STANDARD_CYCLE_TIME_MS,
                "extended_cycle_time_ms": ASI_EXTENDED_CYCLE_TIME_MS,
                "saw_max_reaction_time_s": ASI_SAW_MAX_REACTION_TIME_S,
                "discrepancy_timeout_s": ASI_DISCREPANCY_TIMEOUT_S,
                "max_standard_slaves": ASI_MAX_STANDARD_SLAVES,
                "max_extended_slaves": ASI_MAX_EXTENDED_SLAVES,
            },
            "register_map": {
                "status_word_active_slave_count": "%R970",
                "safety_code_sequence_word": "%R971",
                "cycle_counter": "%R972",
                "primary_process_input_scaled": "%R973",
                "secondary_process_input_scaled": "%R974",
                "telegram_error_counter": "%R975",
                "safe_channel_status_word": "%R976",
                "diagnostic_status_code": "%R977",
                "asi_master_active": "%M226",
                "asi_safety_at_work_trip": "%M227",
            },
            "diagnostic_codes": {
                "0x0000": "OK",
                "0xA101": "ASI_ERR_SAFETY_CODE_TRIP",
                "0xA102": "ASI_ERR_CHANNEL_DISCREPANCY",
                "0xA103": "ASI_ERR_SLAVE_OFFLINE",
                "0xA104": "ASI_ERR_APM_NOISE_FAULT",
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    target_path = output_path or evidence_path
    if target_path:
        out_p = Path(target_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence


# Alias for verification
run_asi_verification = run_as_interface_verification
