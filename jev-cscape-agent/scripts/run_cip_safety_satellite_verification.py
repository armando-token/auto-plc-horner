#!/usr/bin/env python3
"""Deterministic 9-Stage Verification Runner for Industrial ODVA CIP Safety Over Satellite Protocol Engine (W307).

Work Package: W307 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [ODVA CIP Safety Over Satellite / Low Earth Orbit (LEO) Telemetry Bridge]
Status Contract: Strict 4-State JSON output (success | failed | blocked | inconclusive) & evidence emission.

Standards & Specifications:
- ODVA CIP Networks Library Volume 5: CIP Safety Specification (IEC 61784-3-2 / IEC 61508 SIL 3):
  - CIP Safety Over Satellite / Low Earth Orbit (LEO) Telemetry Bridge (DVB-S2X / 3GPP Rel-17 NTN)
  - Safe Satellite State Machine (%R2680 High Byte):
    0: DISCONNECTED (Ground terminal offline or carrier lost)
    1: LINK_SEARCH (Satellite beacon detection & ephemeris tracking active)
    2: DOPPLER_ACQUIRING (Carrier frequency lock & Doppler compensation active)
    3: ONLINE_TRACKING (Operational functional safety data exchange active)
    4: SAFETY_TRIP (Fail-safe interlock tripped; safe state asserted)
- Dual-Channel Diversified Safety Frame Transmission:
  - Diversified Sequence Counters (Primary seq rolling 0..65535, Secondary seq_div = ~seq & 0xFFFF)
  - Dual 16-bit Safety CRCs:
    - CRC-S1: Generator polynomial 0x5935 (init 0x0000) over process data payload
    - CRC-S2: Generator polynomial 0x755B (init 0x0000) over inverted header fields
  - Electronic Product ID (EPID) 32-bit CRC32 Hash & Authentication ("HORNER-OCS-LEO-SAT-SIL3")
- Non-Terrestrial Network (NTN) Environmental & Orbital Surveillance:
  - Low Earth Orbit (LEO) altitude: 550 km nominal (300..1200 km)
  - Doppler frequency shift: -35,000 to +35,000 Hz (nominal 0 Hz; trips 0xEE61 if |Doppler| > 35,000 Hz)
  - Round-Trip Time (RTT) / propagation latency: 5..500 ms (nominal 25 ms; trips 0xEE62 if > 120 ms)
  - Carrier SNR fade margin: 0..35 dB (nominal 15 dB; trips 0xEE63 if < 6 dB)
  - LEO Satcom silence watchdog timeout: 250.0 ms nominal threshold (trips 0xEE64)
  - Auth / Dual CRC Safety Fault: trips 0xEE65 on CRC-S1 or CRC-S2 checksum corruption
- Horner OCS Memory Space:
  - Analog registers %R2680..%R2687:
    - %R2680: REG_CIP_SATELLITE_STATUS (High byte = State, Low byte = Modulation)
    - %R2681: REG_CIP_SATELLITE_SEQUENCE (Rolling sequence counter 0..65535)
    - %R2682: REG_CIP_SATELLITE_DOPPLER_SHIFT (Signed 16-bit integer Doppler shift in Hz)
    - %R2683: REG_CIP_SATELLITE_RTT_LATENCY (Round-trip time propagation latency in ms)
    - %R2684: REG_CIP_SATELLITE_SNR_MARGIN (Carrier SNR fade margin in dB)
    - %R2685: REG_CIP_SATELLITE_DIAGNOSTIC_CODE (Diagnostic code: 0x0000 OK, 0xEE61..0xEE65)
    - %R2686: REG_CIP_SATELLITE_PASS_REMAINING_SEC (LEO pass remaining window in seconds)
    - %R2687: REG_CIP_SATELLITE_PACKET_LOSS_COUNTER (Dropped / lost packet counter)
  - Discrete coils %M625..%M626:
    - %M625: COIL_CIP_SATELLITE_ONLINE (BOOL, True nominally when authenticated & healthy)
    - %M626: COIL_CIP_SATELLITE_TRIP (BOOL, False nominally, True on safety trip or safe stop)
- Implements ILogicUnit interface with scan_step(dt_ms, context), step(dt, context), execute(context), reset().
- Implements sync_to_registers(reg_table, privilege=PrivilegeMode.SYSTEM).
- Includes pure IEC 61131-3 Structured Text POU 'CipSafetySatelliteSync' validated via
  SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).
- Strictly rejects ladder logic constructs with ERR_LADDER_FORBIDDEN / LadderForbiddenError.

Deterministic 9-Stage Verification Sequence:
  Stage 1: environment
  Stage 2: protocol_constants_and_register_mappings
  Stage 3: odva_cip_safety_dual_crc_mathematics
  Stage 4: leo_satellite_orbit_and_doppler_tracking
  Stage 5: propagation_delay_and_carrier_fade_trips
  Stage 6: safety_interlock_trips_and_fault_recovery
  Stage 7: register_table_synchronization
  Stage 8: pure_st_pou_and_anti_ladder_rejection
  Stage 9: simulation_soak_100_cycles_and_evidence_emission

Generates:
  artifacts/telemetry/cip_safety_satellite_evidence.json
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import hashlib
import json
import math
from pathlib import Path
import platform
import struct
import sys
import time
import tracemalloc
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
import zlib

# Ensure repository root and src/ are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = REPO_ROOT / "src"
for p in (str(REPO_ROOT), str(SRC_PATH)):
    if p not in sys.path:
        sys.path.insert(0, p)

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

# Import core protocol engine, constants, and ST definitions
from jev_cscape.telemetry.cip_safety_satellite import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_SATELLITE_CLASS_ID,
    NOMINAL_DOPPLER_HZ,
    MAX_ALLOWED_DOPPLER_HZ,
    NOMINAL_RTT_MS,
    MAX_ALLOWED_RTT_MS,
    NOMINAL_SNR_DB,
    MIN_ALLOWED_SNR_DB,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    DEFAULT_SAFETY_EPID,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    REG_CIP_SATELLITE_STATUS,
    REG_CIP_SATELLITE_SEQUENCE,
    REG_CIP_SATELLITE_DOPPLER_SHIFT,
    REG_CIP_SATELLITE_RTT_LATENCY,
    REG_CIP_SATELLITE_SNR_MARGIN,
    REG_CIP_SATELLITE_DIAGNOSTIC_CODE,
    REG_CIP_SATELLITE_PASS_REMAINING_SEC,
    REG_CIP_SATELLITE_PACKET_LOSS_COUNTER,
    COIL_CIP_SATELLITE_ONLINE,
    COIL_CIP_SATELLITE_TRIP,
    DIAG_OK,
    DIAG_ERR_DOPPLER_EXCEEDED,
    DIAG_ERR_PROPAGATION_DELAY_EXCEEDED,
    DIAG_ERR_CARRIER_FADE_MARGIN_TRIP,
    DIAG_ERR_WATCHDOG_COMM_TIMEOUT,
    DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
    DiagnosticCode,
    SatelliteState,
    ModulationScheme,
    CIPSatelliteSafetyEngine,
    CIPSatellitePacket,
    create_valid_satellite_packet,
    compute_crc_s1,
    compute_crc_s2,
    compute_epid_hash,
    CIP_SAFETY_SATELLITE_SYNC_POU,
    verify_cip_safety_satellite_pure_st,
)

NOMINAL_SATELLITE_ALTITUDE_KM: float = 550.0        # Low Earth Orbit nominal altitude (550 km)
EARTH_RADIUS_KM: float = 6371.0                     # Mean Earth radius in km
SPEED_OF_LIGHT_KM_S: float = 299792.458             # Speed of light in km/s


def calculate_leo_slant_range(
    elevation_deg: float,
    altitude_km: float = NOMINAL_SATELLITE_ALTITUDE_KM,
    r_earth_km: float = EARTH_RADIUS_KM,
) -> float:
    """Compute geometric slant range from ground station to LEO satellite in km."""
    rad = math.radians(max(0.0, min(90.0, float(elevation_deg))))
    sin_el = math.sin(rad)
    d = math.sqrt((r_earth_km * sin_el) ** 2 + 2.0 * r_earth_km * altitude_km + altitude_km ** 2) - (r_earth_km * sin_el)
    return float(max(altitude_km, d))


def calculate_leo_propagation_delay_ms(
    slant_range_km: float,
    processing_overhead_ms: float = 20.0,
) -> float:
    """Compute round-trip propagation and transponder processing delay in milliseconds."""
    one_way_ms = (float(slant_range_km) / SPEED_OF_LIGHT_KM_S) * 1000.0
    return float(2.0 * one_way_ms + processing_overhead_ms)


def calculate_leo_doppler_shift_hz(
    carrier_freq_hz: float = 14.25e9,
    radial_velocity_km_s: float = 0.0,
) -> float:
    """Compute Doppler frequency shift in Hz for given carrier frequency and radial velocity."""
    v_m_s = float(radial_velocity_km_s) * 1000.0
    c_m_s = SPEED_OF_LIGHT_KM_S * 1000.0
    return float(-carrier_freq_hz * (v_m_s / c_m_s))


def compute_epid_hash(epid: Union[str, bytes]) -> int:
    """Compute 32-bit CRC32 hash of Electronic Product ID (EPID)."""
    data = epid.encode("utf-8") if isinstance(epid, str) else bytes(epid)
    return zlib.crc32(data) & 0xFFFFFFFF




# ============================================================================
# ANSI Formatting Helpers
# ============================================================================

ESC_RESET = "\033[0m"
ESC_BOLD = "\033[1m"
ESC_DIM = "\033[2m"
ESC_GREEN = "\033[92m"
ESC_RED = "\033[91m"
ESC_YELLOW = "\033[93m"
ESC_CYAN = "\033[96m"


def format_stage_badge(passed: bool, status: Optional[str] = None) -> str:
    """Format strict 4-state contract ANSI badge."""
    norm_status = (status or "").lower()
    if norm_status == "blocked":
        return f"{ESC_YELLOW}{ESC_BOLD}[BLOCKED]{ESC_RESET}"
    if norm_status == "inconclusive":
        return f"{ESC_YELLOW}{ESC_BOLD}[INCONCLUSIVE]{ESC_RESET}"
    if passed or norm_status in ("passed", "pass", "success"):
        return f"{ESC_GREEN}{ESC_BOLD}[PASS]{ESC_RESET}"
    return f"{ESC_RED}{ESC_BOLD}[FAIL]{ESC_RESET}"


def format_stage_result(
    stage: int | str,
    name: str,
    passed: bool,
    timing_ms: Optional[float] = None,
    details: str = "",
    status: Optional[str] = None,
) -> str:
    """Format a single stage line with ANSI colored badge, timing, and description."""
    badge = format_stage_badge(passed, status)
    timing_str = f" ({timing_ms:.3f} ms)" if timing_ms is not None else ""
    line = f"  Stage {stage}: {badge} {name}{timing_str}"
    if details:
        line += f"\n    {ESC_DIM}{details}{ESC_RESET}"
    return line


# ============================================================================
# Main Deterministic 9-Stage Verification Suite
# ============================================================================

def execute_9stage_verification_suite(
    output_path: Optional[Union[str, Path]] = None,
    work_package: str = "W307",
    quick: bool = False,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W307 CIP Safety Over Satellite.

    Stages:
      Stage 1: environment
      Stage 2: protocol_constants_and_register_mappings
      Stage 3: odva_cip_safety_dual_crc_mathematics
      Stage 4: leo_satellite_orbit_and_doppler_tracking
      Stage 5: propagation_delay_and_carrier_fade_trips
      Stage 6: safety_interlock_trips_and_fault_recovery
      Stage 7: register_table_synchronization
      Stage 8: pure_st_pou_and_anti_ladder_rejection
      Stage 9: simulation_soak_100_cycles_and_evidence_emission
    """
    stages_log: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: environment
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    py_ver = sys.version_info
    py_ok = (py_ver.major == 3 and py_ver.minor >= 8)
    plat_str = platform.platform()

    deps_ok = True
    try:
        from jev_cscape.contracts import AgentStatus, ExecutionResult
        from jev_cscape.iec.st_parser import STParser, POUType
        from jev_cscape.security.guard import SecurityGuard
        from jev_cscape.security.exceptions import LadderForbiddenError
        from jev_cscape.simulation.register_table import RegisterTable, PrivilegeMode
        from jev_cscape.simulation.engine import ILogicUnit, ScanContext
    except ImportError:
        deps_ok = False

    s1_passed = py_ok and deps_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 1,
        "name": "environment",
        "check": "Verify Python version, OS platform, and core dependencies",
        "passed": bool(s1_passed),
        "timing_ms": round(t1, 3),
        "details": f"Python {py_ver.major}.{py_ver.minor}.{py_ver.micro} on {plat_str}. Dependencies verified: {deps_ok}.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: protocol_constants_and_register_mappings
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    class_ids_ok = (
        CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        and CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        and CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        and CIP_SAFETY_SATELLITE_CLASS_ID == 0x2F
    )

    conn_states_ok = (
        int(SatelliteState.DISCONNECTED) == 0
        and int(SatelliteState.LINK_SEARCH) == 1
        and int(SatelliteState.DOPPLER_ACQUIRING) == 2
        and int(SatelliteState.ONLINE_TRACKING) == 3
        and int(SatelliteState.SAFETY_TRIP) == 4
    )

    diag_codes_ok = (
        int(DIAG_OK) == 0x0000
        and int(DIAG_ERR_DOPPLER_EXCEEDED) == 0xEE61
        and int(DIAG_ERR_PROPAGATION_DELAY_EXCEEDED) == 0xEE62
        and int(DIAG_ERR_CARRIER_FADE_MARGIN_TRIP) == 0xEE63
        and int(DIAG_ERR_WATCHDOG_COMM_TIMEOUT) == 0xEE64
        and int(DIAG_ERR_DUAL_CRC_SAFETY_FAULT) == 0xEE65
        # Signed 16-bit equality tests
        and DIAG_ERR_DOPPLER_EXCEEDED == (0xEE61 - 0x10000)
        and (DIAG_ERR_DOPPLER_EXCEEDED & 0xFFFF) == 0xEE61
        and DIAG_ERR_PROPAGATION_DELAY_EXCEEDED == (0xEE62 - 0x10000)
        and (DIAG_ERR_PROPAGATION_DELAY_EXCEEDED & 0xFFFF) == 0xEE62
        and DIAG_ERR_CARRIER_FADE_MARGIN_TRIP == (0xEE63 - 0x10000)
        and (DIAG_ERR_CARRIER_FADE_MARGIN_TRIP & 0xFFFF) == 0xEE63
        and DIAG_ERR_WATCHDOG_COMM_TIMEOUT == (0xEE64 - 0x10000)
        and (DIAG_ERR_WATCHDOG_COMM_TIMEOUT & 0xFFFF) == 0xEE64
        and DIAG_ERR_DUAL_CRC_SAFETY_FAULT == (0xEE65 - 0x10000)
        and (DIAG_ERR_DUAL_CRC_SAFETY_FAULT & 0xFFFF) == 0xEE65
    )

    regs_ok = (
        REG_CIP_SATELLITE_STATUS == "%R2680"
        and REG_CIP_SATELLITE_SEQUENCE == "%R2681"
        and REG_CIP_SATELLITE_DOPPLER_SHIFT == "%R2682"
        and REG_CIP_SATELLITE_RTT_LATENCY == "%R2683"
        and REG_CIP_SATELLITE_SNR_MARGIN == "%R2684"
        and REG_CIP_SATELLITE_DIAGNOSTIC_CODE == "%R2685"
        and REG_CIP_SATELLITE_PASS_REMAINING_SEC == "%R2686"
        and REG_CIP_SATELLITE_PACKET_LOSS_COUNTER == "%R2687"
        and COIL_CIP_SATELLITE_ONLINE == "%M625"
        and COIL_CIP_SATELLITE_TRIP == "%M626"
    )

    s2_passed = class_ids_ok and conn_states_ok and diag_codes_ok and regs_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 2,
        "name": "protocol_constants_and_register_mappings",
        "check": "Verify connection states, diagnostic codes (0xEE61-0xEE65), register offsets (%R2680..%R2687, %M625..%M626)",
        "passed": bool(s2_passed),
        "timing_ms": round(t1, 3),
        "details": "Class IDs (0x39, 0x3A, 0x3B, 0x2F), states (0..4), diagnostic codes (0x0000, 0xEE61..0xEE65), and register mappings (%R2680..%R2687, %M625..%M626) verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: odva_cip_safety_dual_crc_mathematics
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sample_payload = b"Horner-ODVA-CIP-Safety-Satellite-W307-Payload"
    sample_header = (1042).to_bytes(2, "big") + (55000).to_bytes(4, "big")
    inv_header = bytes(~b & 0xFF for b in sample_header)

    c1 = compute_crc_s1(sample_payload)
    c2 = compute_crc_s2(inv_header)
    c1_again = compute_crc_s1(sample_payload)
    c2_again = compute_crc_s2(inv_header)

    crc_det = (c1 == c1_again) and (c2 == c2_again) and (c1 != 0) and (c2 != 0) and (c1 != c2)

    # Single-bit corruption detection
    mutated = bytearray(sample_payload)
    mutated[0] ^= 0x01
    c1_mut = compute_crc_s1(bytes(mutated))
    crc_mut_detected = (c1_mut != c1)

    # Packet model validate_crcs check
    pkt = create_valid_satellite_packet(payload=sample_payload, sequence=1042, timestamp_ms=55000)
    pkt_valid = pkt.validate_crcs()
    raw = pkt.pack()
    unpacked = CIPSatellitePacket.unpack(raw)
    unpack_ok = unpacked.validate_crcs() and unpacked.payload == sample_payload

    # EPID hash validation
    epid_h = compute_epid_hash(DEFAULT_SAFETY_EPID)
    epid_ok = (epid_h != 0) and (epid_h == compute_epid_hash(DEFAULT_SAFETY_EPID))

    s3_passed = (
        crc_det
        and crc_mut_detected
        and pkt_valid
        and unpack_ok
        and epid_ok
        and (CIP_SAFETY_CRC_S1_POLY == 0x5935)
        and (CIP_SAFETY_CRC_S2_POLY == 0x755B)
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 3,
        "name": "odva_cip_safety_dual_crc_mathematics",
        "check": "Verify dual CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B) mathematics and corruption detection",
        "passed": bool(s3_passed),
        "timing_ms": round(t1, 3),
        "details": f"CRC-S1=0x{c1:04X}, CRC-S2=0x{c2:04X}. Dual polynomial mathematics, packet serialization round-trip, and EPID hash verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: leo_satellite_orbit_and_doppler_tracking
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # Slant range geometry check
    d_zenith = calculate_leo_slant_range(elevation_deg=90.0)
    d_45 = calculate_leo_slant_range(elevation_deg=45.0)
    d_10 = calculate_leo_slant_range(elevation_deg=10.0)
    geom_ok = (d_zenith == 550.0) and (d_45 > d_zenith) and (d_10 > d_45)

    # Delay kinematics check
    delay_zenith = calculate_leo_propagation_delay_ms(d_zenith)
    delay_45 = calculate_leo_propagation_delay_ms(d_45)
    delay_ok = (20.0 < delay_zenith < 25.0) and (delay_45 > delay_zenith)

    # Doppler shift tracking calculations
    f_dop_zero = calculate_leo_doppler_shift_hz(14.25e9, radial_velocity_km_s=0.0)
    f_dop_app = calculate_leo_doppler_shift_hz(14.25e9, radial_velocity_km_s=-0.5)
    f_dop_rec = calculate_leo_doppler_shift_hz(14.25e9, radial_velocity_km_s=0.5)
    doppler_math_ok = (f_dop_zero == 0.0) and (f_dop_app > 0) and (f_dop_rec < 0)

    # Nominal tracking in engine
    eng4 = CIPSatelliteSafetyEngine()
    eng4.connect()
    rx_nom = create_valid_satellite_packet(
        doppler_hz=NOMINAL_DOPPLER_HZ,
        rtt_ms=NOMINAL_RTT_MS,
        snr_db=NOMINAL_SNR_DB,
    )
    nom_ok = eng4.receive_packet(rx_nom)
    tracking_ok = (
        nom_ok is True
        and eng4.is_healthy is True
        and eng4.is_safe_stop_tripped is False
        and eng4.diagnostic_code == DIAG_OK
        and eng4.doppler_hz == 0.0
        and eng4.rtt_ms == 25.0
        and eng4.snr_db == 15.0
    )

    s4_passed = geom_ok and delay_ok and doppler_math_ok and tracking_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 4,
        "name": "leo_satellite_orbit_and_doppler_tracking",
        "check": "Verify orbital geometry, Doppler shift tracking, and nominal telemetry",
        "passed": bool(s4_passed),
        "timing_ms": round(t1, 3),
        "details": f"LEO geometry (zenith slant {d_zenith:.1f}km, 45deg {d_45:.1f}km) and nominal tracking (Doppler 0Hz, RTT 25ms, SNR 15dB) passed.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: propagation_delay_and_carrier_fade_trips
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng5 = CIPSatelliteSafetyEngine()
    eng5.connect()

    # 1. Excessive propagation delay / RTT trip (0xEE62)
    eng5.inject_propagation_delay(rtt_ms=150.0)
    trip_delay_ok = (
        eng5.diagnostic_code == DIAG_ERR_PROPAGATION_DELAY_EXCEEDED
        and eng5.diagnostic_code == 0xEE62
        and eng5.is_safe_stop_tripped is True
        and eng5.is_healthy is False
        and eng5.state == SatelliteState.SAFETY_TRIP
    )
    eng5.clear_fault()
    rec_delay_ok = (eng5.is_safe_stop_tripped is False and eng5.diagnostic_code == DIAG_OK)

    # 2. Carrier fade margin degradation trip (0xEE63)
    eng5.connect()
    eng5.inject_carrier_fade(snr_db=4.0)
    trip_fade_ok = (
        eng5.diagnostic_code == DIAG_ERR_CARRIER_FADE_MARGIN_TRIP
        and eng5.diagnostic_code == 0xEE63
        and eng5.is_safe_stop_tripped is True
        and eng5.is_healthy is False
        and eng5.state == SatelliteState.SAFETY_TRIP
    )
    eng5.clear_fault()
    rec_fade_ok = (eng5.is_safe_stop_tripped is False and eng5.diagnostic_code == DIAG_OK)

    s5_passed = trip_delay_ok and rec_delay_ok and trip_fade_ok and rec_fade_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 5,
        "name": "propagation_delay_and_carrier_fade_trips",
        "check": "Verify propagation delay (> 120 ms -> 0xEE62) and carrier fade (< 6 dB -> 0xEE63)",
        "passed": bool(s5_passed),
        "timing_ms": round(t1, 3),
        "details": "Propagation delay surge (150 ms -> 0xEE62) and carrier fade (4.0 dB -> 0xEE63) successfully tripped and recovered.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: safety_interlock_trips_and_fault_recovery
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng6 = CIPSatelliteSafetyEngine(watchdog_timeout_ms=250.0)

    # 1. Doppler shift excursion trip (0xEE61)
    eng6.connect()
    eng6.inject_doppler_exceeded(doppler_hz=40000.0)
    trip_dop_ok = (
        eng6.diagnostic_code == DIAG_ERR_DOPPLER_EXCEEDED
        and eng6.diagnostic_code == 0xEE61
        and eng6.is_safe_stop_tripped is True
    )
    eng6.clear_fault()

    # 2. Watchdog silence timeout trip (0xEE64)
    eng6.connect()
    for _ in range(26):
        eng6.scan_step(dt=0.01)
    trip_wd_ok = (
        eng6.diagnostic_code == DIAG_ERR_WATCHDOG_COMM_TIMEOUT
        and eng6.diagnostic_code == 0xEE64
        and eng6.is_safe_stop_tripped is True
    )
    eng6.clear_fault()

    # 3. Dual CRC safety fault trip (0xEE65)
    eng6.connect()
    bad_pkt = create_valid_satellite_packet()
    bad_pkt.crc_s1 = 0x5432  # Invalidate CRC
    rx_bad_ok = eng6.receive_packet(bad_pkt)
    trip_crc_ok = (
        rx_bad_ok is False
        and eng6.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        and eng6.diagnostic_code == 0xEE65
        and eng6.is_safe_stop_tripped is True
    )
    eng6.clear_fault()
    rec_all_ok = (eng6.diagnostic_code == DIAG_OK and eng6.is_safe_stop_tripped is False)

    s6_passed = trip_dop_ok and trip_wd_ok and trip_crc_ok and rec_all_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 6,
        "name": "safety_interlock_trips_and_fault_recovery",
        "check": "Verify Doppler (0xEE61), watchdog (0xEE64), CRC (0xEE65), and clean recovery",
        "passed": bool(s6_passed),
        "timing_ms": round(t1, 3),
        "details": "All fault trips (0xEE61, 0xEE64, 0xEE65) fired exact codes with safe stop asserted and clean recovery.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: register_table_synchronization
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt7 = RegisterTable()
    eng7 = CIPSatelliteSafetyEngine(register_table=rt7)
    eng7.connect()
    eng7.sync_to_registers(rt7, privilege=PrivilegeMode.USER)

    w_stat = rt7.read_word(REG_CIP_SATELLITE_STATUS) & 0xFFFF
    w_seq = rt7.read_uword(REG_CIP_SATELLITE_SEQUENCE)
    w_dop = rt7.read_word(REG_CIP_SATELLITE_DOPPLER_SHIFT)
    w_rtt = rt7.read_word(REG_CIP_SATELLITE_RTT_LATENCY)
    w_snr = rt7.read_word(REG_CIP_SATELLITE_SNR_MARGIN)
    w_diag = rt7.read_uword(REG_CIP_SATELLITE_DIAGNOSTIC_CODE)
    b_online = rt7.read_bit(COIL_CIP_SATELLITE_ONLINE)
    b_trip = rt7.read_bit(COIL_CIP_SATELLITE_TRIP)

    nom_sync_ok = (
        (w_stat >> 8) == int(SatelliteState.ONLINE_TRACKING)
        and w_dop == 0
        and w_rtt == 25
        and w_snr == 15
        and w_diag == 0x0000
        and b_online is True
        and b_trip is False
    )

    # Negative Doppler and signed masking tests
    eng7.doppler_hz = -15000.0
    eng7.sync_to_registers(rt7)
    w_dop_neg = rt7.read_word(REG_CIP_SATELLITE_DOPPLER_SHIFT)
    neg_dop_ok = (w_dop_neg == -15000) and ((w_dop_neg & 0xFFFF) == 0xC568)

    # Fault code signed/unsigned masking
    eng7.trip_safety(DIAG_ERR_DOPPLER_EXCEEDED)
    eng7.sync_to_registers(rt7)
    u_diag = rt7.read_uword(REG_CIP_SATELLITE_DIAGNOSTIC_CODE)
    s_diag = rt7.read_word(REG_CIP_SATELLITE_DIAGNOSTIC_CODE)
    mask_diag_ok = (u_diag == 0xEE61) and (s_diag == -4511) and ((s_diag & 0xFFFF) == 0xEE61)

    s7_passed = nom_sync_ok and neg_dop_ok and mask_diag_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 7,
        "name": "register_table_synchronization",
        "check": "Verify RegisterTable reads/writes and bitwise signed masks across %R2680..%R2687 and %M625..%M626",
        "passed": bool(s7_passed),
        "timing_ms": round(t1, 3),
        "details": "Bit-exact synchronization and 16-bit signed wrapping verified across %R2680..%R2687 and %M625..%M626.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: pure_st_pou_and_anti_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    st_syntax_ok = verify_cip_safety_satellite_pure_st(CIP_SAFETY_SATELLITE_SYNC_POU)

    ladder_snippets = [
        "PROGRAM LadderTest\n VAR x : BOOL; END_VAR\n ---[ ]--- x;\n END_PROGRAM",
        "PROGRAM LadderTest\n VAR x : BOOL; END_VAR\n ---[/]--- x;\n END_PROGRAM",
        "PROGRAM LadderTest\n VAR y : BOOL; END_VAR\n ---( )--- y;\n END_PROGRAM",
        "PROGRAM LadderTest\n VAR y : BOOL; END_VAR\n ---(S)--- y;\n END_PROGRAM",
        "PROGRAM LadderTest\n VAR y : BOOL; END_VAR\n ---(R)--- y;\n END_PROGRAM",
        "PROGRAM LadderTest\n RUNG 1\n END_PROGRAM",
        "PROGRAM LadderTest\n NETWORK 10\n END_PROGRAM",
        "PROGRAM LadderTest\n XIC(Contact1);\n END_PROGRAM",
        "PROGRAM LadderTest\n OTE(Coil1);\n END_PROGRAM",
    ]
    ladder_rejected = 0
    for snippet in ladder_snippets:
        try:
            SecurityGuard.assert_pure_st_content(snippet)
        except LadderForbiddenError:
            ladder_rejected += 1
        except Exception:
            pass

    anti_ladder_ok = (ladder_rejected == len(ladder_snippets))
    s8_passed = st_syntax_ok and anti_ladder_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 8,
        "name": "pure_st_pou_and_anti_ladder_rejection",
        "check": "Verify ST POU 'CipSafetySatelliteSync' and LadderForbiddenError on ladder syntax",
        "passed": bool(s8_passed),
        "timing_ms": round(t1, 3),
        "details": f"Pure ST POU verified. Rejected {ladder_rejected}/{len(ladder_snippets)} ladder constructs with LadderForbiddenError.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: simulation_soak_100_cycles_and_evidence_emission
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sim_cycles = 10 if quick else 100
    rt9 = RegisterTable()
    eng9 = CIPSatelliteSafetyEngine(register_table=rt9)
    eng9.connect()

    tracemalloc.start()
    for cycle in range(1, sim_cycles + 1):
        pkt = eng9.transmit_packet()
        eng9.receive_packet(pkt)
        res = eng9.scan_step(dt=0.01, register_table=rt9)
        assert res.status == AgentStatus.SUCCESS
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    soak_ok = (
        eng9.sequence_counter == sim_cycles
        and eng9.is_safe_stop_tripped is False
        and eng9.is_healthy is True
        and eng9.diagnostic_code == DIAG_OK
        and rt9.read_bit(COIL_CIP_SATELLITE_ONLINE) is True
        and rt9.read_bit(COIL_CIP_SATELLITE_TRIP) is False
        and peak_mem < 2 * 1024 * 1024
    )

    all_stages_passed = all(stg["passed"] for stg in stages_log) and soak_ok
    passed_count = sum(1 for stg in stages_log if stg["passed"]) + (1 if soak_ok else 0)

    # Generate cryptographic SHA-256 digests
    pou_sha256 = hashlib.sha256(CIP_SAFETY_SATELLITE_SYNC_POU.encode("utf-8")).hexdigest()
    stages_summary_str = json.dumps(stages_log, sort_keys=True)
    stages_sha256 = hashlib.sha256(stages_summary_str.encode("utf-8")).hexdigest()

    evidence_dict: Dict[str, Any] = {
        "status": "success" if all_stages_passed else "failed",
        "error_code": None if all_stages_passed else "ERR_STAGE_FAILED",
        "details": (
            f"All 9 Industrial ODVA CIP Safety Over Satellite (W307) stages passed deterministically "
            f"(PASSED {passed_count}/9 stages)."
            if all_stages_passed
            else f"Verification failed with {passed_count}/9 stages passing."
        ),
        "work_package": work_package,
        "stages_passed": passed_count,
        "total_stages": 9,
        "passed_stages": passed_count,
        "data": {
            "work_package": work_package,
            "gate": "G8",
            "protocol": "Industrial ODVA CIP Safety Over Satellite (LEO / DVB-S2X / 3GPP NTN)",
            "standards": [
                "ODVA CIP Safety Volume 5",
                "IEC 61784-3-2",
                "IEC 61508 SIL 3",
                "DVB-S2X",
                "3GPP Rel-17/18 NTN",
            ],
            "registers": [
                "%R2680..%R2687",
                "%M625..%M626",
            ],
            "diagnostic_codes": {
                "0x0000": "OK",
                "0xEE61": "ERR_DOPPLER_EXCEEDED",
                "0xEE62": "ERR_PROPAGATION_DELAY_EXCEEDED",
                "0xEE63": "ERR_CARRIER_FADE_MARGIN_TRIP",
                "0xEE64": "ERR_WATCHDOG_COMM_TIMEOUT",
                "0xEE65": "ERR_DUAL_CRC_SAFETY_FAULT",
            },
            "sha256_digests": {
                "pou_sha256": pou_sha256,
                "stages_sha256": stages_sha256,
            },
            "checks_passed": passed_count,
            "total_checks": 9,
            "stages": stages_log,
        },
    }

    t1 = (time.perf_counter() - t0) * 1000.0
    stage_9_entry = {
        "stage": 9,
        "name": "simulation_soak_100_cycles_and_evidence_emission",
        "check": f"Verify multi-cycle ILogicUnit execution ({sim_cycles} cycles) and emit evidence JSON",
        "passed": bool(soak_ok),
        "timing_ms": round(t1, 3),
        "details": f"Executed {sim_cycles} continuous scan cycles. Zero errors, peak memory: {peak_mem / 1024:.1f} KB.",
    }
    stages_log.append(stage_9_entry)

    # Save evidence file if path provided
    if output_path:
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence_dict, f, indent=2)

    return evidence_dict


# Backwards compatibility and standard aliases
run_cip_safety_satellite_verification = execute_9stage_verification_suite
run_deterministic_9stage_suite = execute_9stage_verification_suite


# ============================================================================
# CLI Entrypoint
# ============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for W307 verification runner."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Execute W307 CIP Safety Over Satellite 9-Stage Verification Suite"
    )
    parser.add_argument(
        "positional_path",
        nargs="?",
        default=None,
        help="Optional positional path for output evidence JSON file",
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="flag_path",
        default=None,
        help="Path to output JSON evidence artifact (default: artifacts/telemetry/cip_safety_satellite_evidence.json)",
    )
    parser.add_argument(
        "--quick",
        "-q",
        action="store_true",
        default=False,
        help="Execute quick verification mode (reduced simulation cycles)",
    )
    parser.add_argument(
        "--work-package",
        "-w",
        default="W307",
        help="Work package ID (default: W307)",
    )
    parser.add_argument(
        "--json",
        "--json-only",
        action="store_true",
        help="Emit raw JSON report only (no ANSI stdout banner)",
    )
    args = parser.parse_args(argv)

    selected_path = args.flag_path or args.positional_path
    if selected_path:
        evidence_path = Path(selected_path).resolve()
    else:
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_satellite_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print("=" * 80)
        print(f"  {ESC_BOLD}JEV Cscape Agent: ODVA CIP Safety Over Satellite Verification ({args.work_package}){ESC_RESET}")
        print("=" * 80)

    t0 = time.perf_counter()
    try:
        evidence = execute_9stage_verification_suite(
            output_path=evidence_path,
            work_package=args.work_package,
            quick=args.quick,
        )
    except Exception as exc:
        print(f"\n[{ESC_RED}{ESC_BOLD}EXCEPTION{ESC_RESET}] Verification suite crashed with unhandled exception:")
        print(f"  {type(exc).__name__}: {exc}")
        print("=" * 80)
        return 1
    elapsed_total_ms = (time.perf_counter() - t0) * 1000.0

    # Ensure evidence file was written
    if not evidence_path.exists() or evidence_path.stat().st_size == 0:
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    if args.json:
        print(json.dumps(evidence, indent=2))
        return 0 if evidence.get("status") == "success" else 1

    stages = evidence.get("data", {}).get("stages", [])
    for stg in stages:
        stage_num = stg.get("stage", "?")
        stage_name = stg.get("name") or stg.get("check", "unnamed_stage")
        passed = stg.get("passed", False)
        timing = stg.get("timing_ms") or stg.get("duration_ms")
        details = stg.get("details", "")
        status = stg.get("status")
        print(format_stage_result(stage_num, stage_name, passed, timing, details, status))

    passed_count = evidence.get("stages_passed", sum(1 for s in stages if s.get("passed", False)))
    total_count = evidence.get("total_stages", len(stages))
    status_str = evidence.get("status", "unknown")

    print("-" * 80)
    status_badge = (
        f"{ESC_GREEN}{ESC_BOLD}{status_str.upper()}{ESC_RESET}"
        if status_str == "success"
        else f"{ESC_RED}{ESC_BOLD}{status_str.upper()}{ESC_RESET}"
    )
    print(f"[*] Outcome: {passed_count}/{total_count} checks passed across {len(stages)} verification stages (in {elapsed_total_ms:.2f} ms).")
    print(f"[*] Status: {status_badge}")
    print(f"[*] Evidence artifact saved: {ESC_CYAN}{evidence_path}{ESC_RESET}")
    print("=" * 80)

    return 0 if status_str == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
