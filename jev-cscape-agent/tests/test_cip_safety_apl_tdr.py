"""Comprehensive Unit Test Suite for Wave W325 CIP Safety Over Ethernet-APL Cable Diagnostics & TDR Engine.

Work Package: W325 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over Ethernet-APL Cable Diagnostics & Time-Domain Reflectometry (TDR) Engine.

Covers Comprehensive Deterministic Unit Tests across 15 Mandatory Test Classes (80+ Tests):
1. TestTDRProtocolConstantsEnumsAndDiagnostics
2. TestDualSafetyCrcMathematics
3. TestPacketModelAndBinarySerialization
4. TestTDRPulsePropagationAndTelemetry
5. TestCableOpenCircuitFaultInjectionAndTrip
6. TestCableShortCircuitFaultInjectionAndTrip
7. TestImpedanceMismatchFaultInjectionAndTrip
8. TestReturnLossExcursionFaultInjectionAndTrip
9. TestDualCrcCorruptionInjectionAndTrip
10. TestTDRPulseAttenuationInjectionAndTrip
11. TestSafeStopInterlockAndCoils
12. TestRegisterTableSynchronization
13. TestPureIEC61131StructuredTextAndSecurity
14. TestILogicUnitComplianceAndSimulationSoak
15. TestVerificationRunner9StagesAndCli
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import tracemalloc
from typing import Any, Dict, List
import pytest
import zlib

REPO_ROOT = Path(__file__).resolve().parent.parent

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.telemetry.cip_safety_apl_tdr import (
    CIP_SAFETY_CRC_INIT,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CIP_SAFETY_APL_TDR_EPID,
    COIL_CIP_APL_TDR_ONLINE,
    COIL_CIP_APL_TDR_SAFETY_TRIP,
    DIAG_ERR_CABLE_OPEN_CIRCUIT,
    DIAG_ERR_CABLE_SHORT_CIRCUIT,
    DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
    DIAG_ERR_IMPEDANCE_MISMATCH,
    DIAG_ERR_RETURN_LOSS_EXCURSION,
    DIAG_ERR_TDR_PULSE_ATTENUATION,
    DIAG_OK,
    MIN_HEALTHY_RETURN_LOSS_DB,
    NOMINAL_CABLE_IMPEDANCE_OHM,
    NOMINAL_NVP_PERCENT,
    REG_CIP_APL_TDR_CABLE_LENGTH_M,
    REG_CIP_APL_TDR_DIAGNOSTIC_CODE,
    REG_CIP_APL_TDR_FAULT_DISTANCE_M,
    REG_CIP_APL_TDR_IMPEDANCE_OHM,
    REG_CIP_APL_TDR_PROPAGATION_VEL_PERCENT,
    REG_CIP_APL_TDR_REFLECTION_COEFF,
    REG_CIP_APL_TDR_RETURN_LOSS_DB,
    REG_CIP_APL_TDR_STATUS,
    ST_PROGRAM_CIP_SAFETY_APL_TDR_SYNC,
    CableFaultType,
    CIPAPLTDRPacket,
    CIPAPLTDRSafetyEngine,
    DiagnosticCode,
    TDROperatingState,
    compute_crc_s1,
    compute_crc_s2,
    compute_epid_hash,
    create_valid_apl_tdr_packet,
    run_cip_safety_apl_tdr_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    verify_cip_safety_apl_tdr_pure_st,
    verify_dual_crc_s,
)


class TestTDRProtocolConstantsEnumsAndDiagnostics:
    """Class 1: Protocol constants, registers, coils, and safe signed/unsigned diagnostic comparisons."""

    def test_registers_and_coils_mapped(self):
        assert REG_CIP_APL_TDR_STATUS == "%R2860"
        assert REG_CIP_APL_TDR_CABLE_LENGTH_M == "%R2861"
        assert REG_CIP_APL_TDR_FAULT_DISTANCE_M == "%R2862"
        assert REG_CIP_APL_TDR_IMPEDANCE_OHM == "%R2863"
        assert REG_CIP_APL_TDR_RETURN_LOSS_DB == "%R2864"
        assert REG_CIP_APL_TDR_PROPAGATION_VEL_PERCENT == "%R2865"
        assert REG_CIP_APL_TDR_REFLECTION_COEFF == "%R2866"
        assert REG_CIP_APL_TDR_DIAGNOSTIC_CODE == "%R2867"
        assert COIL_CIP_APL_TDR_ONLINE == "%M667"
        assert COIL_CIP_APL_TDR_SAFETY_TRIP == "%M668"

    def test_diagnostic_codes_values(self):
        assert int(DiagnosticCode.DIAG_OK) == 0x0000
        assert int(DiagnosticCode.DIAG_ERR_CABLE_OPEN_CIRCUIT) == 0xEEC1
        assert int(DiagnosticCode.DIAG_ERR_CABLE_SHORT_CIRCUIT) == 0xEEC2
        assert int(DiagnosticCode.DIAG_ERR_IMPEDANCE_MISMATCH) == 0xEEC3
        assert int(DiagnosticCode.DIAG_ERR_RETURN_LOSS_EXCURSION) == 0xEEC4
        assert int(DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT) == 0xEEC5
        assert int(DiagnosticCode.DIAG_ERR_TDR_PULSE_ATTENUATION) == 0xEEC6

    def test_diagnostic_signed_comparison(self):
        # 0xEEC1 as signed 16-bit is 0xEEC1 - 0x10000 = -4415
        s16 = 0xEEC1 - 0x10000
        assert DiagnosticCode.DIAG_ERR_CABLE_OPEN_CIRCUIT == 0xEEC1
        assert DiagnosticCode.DIAG_ERR_CABLE_OPEN_CIRCUIT == s16
        assert DiagnosticCode.DIAG_ERR_CABLE_OPEN_CIRCUIT != 0x0000

    def test_enums_members(self):
        assert TDROperatingState.DE_ENERGIZED == 0
        assert TDROperatingState.MONITORING == 2
        assert TDROperatingState.SAFETY_TRIP == 5
        assert CableFaultType.NONE == 0
        assert CableFaultType.OPEN_CIRCUIT == 1
        assert CableFaultType.SHORT_CIRCUIT == 2


class TestDualSafetyCrcMathematics:
    """Class 2: ODVA CIP Safety dual CRC-S1 / CRC-S2 calculations."""

    def test_crc_polynomial_constants(self):
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0x0000

    def test_crc_s1_and_s2_deterministic(self):
        data = b"TDR_ETHERNET_APL_CABLE_SIL3"
        c1 = compute_crc_s1(data)
        c2 = compute_crc_s2(data)
        assert c1 != c2
        assert compute_crc_s1(data) == c1
        assert compute_crc_s2(data) == c2

    def test_bit_perturbation_detection(self):
        data = b"SAFE_DATA_123"
        c1 = compute_crc_s1(data)
        c2 = compute_crc_s2(data)
        assert verify_dual_crc_s(data, c1, c2) is True
        # Tamper single bit
        tampered = bytearray(data)
        tampered[0] ^= 0x01
        assert verify_dual_crc_s(bytes(tampered), c1, c2) is False

    def test_epid_hash(self):
        h = compute_epid_hash(CIP_SAFETY_APL_TDR_EPID)
        assert isinstance(h, int)
        assert h == (zlib.crc32(CIP_SAFETY_APL_TDR_EPID.encode("utf-8")) & 0xFFFFFFFF)


class TestPacketModelAndBinarySerialization:
    """Class 3: CIPAPLTDRPacket model, serialization, and CRC verification."""

    def test_packet_creation_and_sealing(self):
        pkt = create_valid_apl_tdr_packet(session_id=0x2860, sequence_number=10)
        assert pkt.is_valid()
        assert pkt.crc_s1 != 0
        assert pkt.crc_s2 != 0

    def test_packet_tampering_detection(self):
        pkt = create_valid_apl_tdr_packet(session_id=0x2860)
        assert pkt.is_valid()
        # Tamper with impedance
        pkt.impedance_ohm = 145.0
        assert not pkt.is_valid()


class TestTDRPulsePropagationAndTelemetry:
    """Class 4: Nominal TDR measurements and connect/disconnect."""

    def test_nominal_measurements(self):
        engine = CIPAPLTDRSafetyEngine(cable_length_m=200.0)
        engine.connect()
        engine.scan_step()

        assert engine.state == TDROperatingState.MONITORING
        assert engine.measured_impedance_ohm == 100.0
        assert engine.reflection_coeff == 0.0
        assert engine.return_loss_db >= 20.0
        assert engine.fault_distance_m == 0.0
        assert engine.coil_online is True
        assert engine.coil_safety_trip is False

    def test_disconnect(self):
        engine = CIPAPLTDRSafetyEngine()
        engine.connect()
        assert engine.coil_online is True
        engine.disconnect()
        assert engine.state == TDROperatingState.DE_ENERGIZED
        engine.scan_step()
        assert engine.coil_online is False


class TestCableOpenCircuitFaultInjectionAndTrip:
    """Class 5: Cable open-circuit fault injection (0xEEC1)."""

    def test_open_circuit_injection(self):
        engine = CIPAPLTDRSafetyEngine()
        engine.connect()
        engine.inject_open_circuit(distance_m=85.5)
        engine.scan_step()

        assert engine.state == TDROperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_CABLE_OPEN_CIRCUIT
        assert engine.fault_distance_m == 85.5
        assert engine.reflection_coeff > 0.700
        assert engine.coil_online is False
        assert engine.coil_safety_trip is True

    def test_clear_fault_after_open_circuit(self):
        engine = CIPAPLTDRSafetyEngine()
        engine.connect()
        engine.inject_open_circuit(distance_m=85.5)
        engine.scan_step()
        assert engine.state == TDROperatingState.SAFETY_TRIP

        engine.clear_fault()
        assert engine.state == TDROperatingState.MONITORING
        assert engine.diagnostic_code == DIAG_OK
        assert engine.coil_online is True
        assert engine.coil_safety_trip is False


class TestCableShortCircuitFaultInjectionAndTrip:
    """Class 6: Cable short-circuit fault injection (0xEEC2)."""

    def test_short_circuit_injection(self):
        engine = CIPAPLTDRSafetyEngine()
        engine.connect()
        engine.inject_short_circuit(distance_m=35.0)
        engine.scan_step()

        assert engine.state == TDROperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_CABLE_SHORT_CIRCUIT
        assert engine.fault_distance_m == 35.0
        assert engine.reflection_coeff < -0.700
        assert engine.coil_online is False
        assert engine.coil_safety_trip is True


class TestImpedanceMismatchFaultInjectionAndTrip:
    """Class 7: Cable impedance mismatch fault injection (0xEEC3)."""

    def test_impedance_mismatch_injection(self):
        engine = CIPAPLTDRSafetyEngine()
        engine.connect()
        engine.inject_impedance_mismatch(impedance_ohm=150.0, distance_m=120.0)
        engine.scan_step()

        assert engine.state == TDROperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_IMPEDANCE_MISMATCH
        assert abs(engine.measured_impedance_ohm - 100.0) > 25.0
        assert engine.coil_safety_trip is True


class TestReturnLossExcursionFaultInjectionAndTrip:
    """Class 8: Cable return loss degradation excursion (0xEEC4)."""

    def test_return_loss_injection(self):
        engine = CIPAPLTDRSafetyEngine()
        engine.connect()
        engine.inject_return_loss_fault(return_loss_db=8.5)
        engine.scan_step()

        assert engine.state == TDROperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_RETURN_LOSS_EXCURSION
        assert engine.return_loss_db < MIN_HEALTHY_RETURN_LOSS_DB
        assert engine.coil_safety_trip is True


class TestDualCrcCorruptionInjectionAndTrip:
    """Class 9: Dual CRC corruption fault injection (0xEEC5)."""

    def test_crc_fault_injection(self):
        engine = CIPAPLTDRSafetyEngine()
        engine.connect()
        engine.inject_crc_fault()
        engine.scan_step()

        assert engine.state == TDROperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert engine.coil_safety_trip is True

    def test_receive_corrupted_packet(self):
        engine = CIPAPLTDRSafetyEngine()
        engine.connect()
        pkt = create_valid_apl_tdr_packet()
        pkt.crc_s1 ^= 0xFFFF  # Corrupt CRC
        ok = engine.receive_packet(pkt)
        assert ok is False
        assert engine.state == TDROperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT


class TestTDRPulseAttenuationInjectionAndTrip:
    """Class 10: TDR pulse attenuation fault injection (0xEEC6)."""

    def test_pulse_attenuation_injection(self):
        engine = CIPAPLTDRSafetyEngine()
        engine.connect()
        engine.inject_pulse_attenuation(amplitude_mv=100.0)
        engine.scan_step()

        assert engine.state == TDROperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_TDR_PULSE_ATTENUATION
        assert engine.pulse_amplitude_mv < 200.0
        assert engine.coil_safety_trip is True


class TestSafeStopInterlockAndCoils:
    """Class 11: Fail-safe interlocks and coil assertion."""

    def test_coil_mutual_exclusivity_on_trip(self):
        engine = CIPAPLTDRSafetyEngine()
        engine.connect()
        engine.scan_step()
        assert engine.coil_online is True
        assert engine.coil_safety_trip is False

        # Trip
        engine.inject_open_circuit()
        engine.scan_step()
        assert engine.coil_online is False
        assert engine.coil_safety_trip is True


class TestRegisterTableSynchronization:
    """Class 12: Bit-exact synchronization to Horner OCS registers."""

    def test_register_synchronization(self):
        rt = RegisterTable()
        engine = CIPAPLTDRSafetyEngine(register_table=rt, cable_length_m=250.0, nvp_pct=67.0)
        engine.connect()
        engine.scan_step()

        assert rt.read_word(REG_CIP_APL_TDR_STATUS) == int(TDROperatingState.MONITORING)
        assert rt.read_word(REG_CIP_APL_TDR_CABLE_LENGTH_M) == 2500
        assert rt.read_word(REG_CIP_APL_TDR_IMPEDANCE_OHM) == 1000
        assert rt.read_word(REG_CIP_APL_TDR_PROPAGATION_VEL_PERCENT) == 670
        assert rt.read_bit(COIL_CIP_APL_TDR_ONLINE) is True
        assert rt.read_bit(COIL_CIP_APL_TDR_SAFETY_TRIP) is False

    def test_trip_synchronization(self):
        rt = RegisterTable()
        engine = CIPAPLTDRSafetyEngine(register_table=rt)
        engine.connect()
        engine.inject_short_circuit(distance_m=50.0)
        engine.scan_step()

        assert (rt.read_word(REG_CIP_APL_TDR_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEEC2
        assert rt.read_word(REG_CIP_APL_TDR_FAULT_DISTANCE_M) == 500
        assert rt.read_bit(COIL_CIP_APL_TDR_ONLINE) is False
        assert rt.read_bit(COIL_CIP_APL_TDR_SAFETY_TRIP) is True


class TestPureIEC61131StructuredTextAndSecurity:
    """Class 13: Pure ST POU validation and anti-ladder construct rejection."""

    def test_pure_st_pou_validity(self):
        assert verify_cip_safety_apl_tdr_pure_st() is True

    def test_anti_ladder_security_guard(self):
        ladder_snippets = [
            "PROGRAM LadderTest VAR x : BOOL; END_VAR ---[ ]--- x; END_PROGRAM",
            "PROGRAM LadderTest VAR x : BOOL; END_VAR ---[/]--- x; END_PROGRAM",
            "PROGRAM LadderTest VAR y : BOOL; END_VAR ---( )--- y; END_PROGRAM",
            "PROGRAM LadderTest VAR y : BOOL; END_VAR ---(S)--- y; END_PROGRAM",
            "PROGRAM LadderTest VAR y : BOOL; END_VAR ---(R)--- y; END_PROGRAM",
            "PROGRAM LadderTest RUNG 1 END_PROGRAM",
            "PROGRAM LadderTest NETWORK 10 END_PROGRAM",
            "PROGRAM LadderTest XIC(StartPB); END_PROGRAM",
            "PROGRAM LadderTest OTE(MotorCoil); END_PROGRAM",
        ]
        for bad in ladder_snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad)


class TestILogicUnitComplianceAndSimulationSoak:
    """Class 14: ILogicUnit compliance and 100-cycle continuous simulation soak."""

    def test_ilogicunit_interface(self):
        engine = CIPAPLTDRSafetyEngine()
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "CIPAPLTDRSafetyEngine"
        assert engine.priority == 1
        assert engine.is_enabled is True
        engine.is_enabled = False
        assert engine.is_enabled is False

    def test_simulation_soak_100_cycles(self):
        engine = CIPAPLTDRSafetyEngine()
        engine.connect()
        tracemalloc.start()
        for i in range(100):
            engine.scan_step()
            pkt = engine.send_packet()
            assert pkt.is_valid()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        # Memory growth must be bounded
        assert peak < 50 * 1024 * 1024  # Under 50 MB


class TestVerificationRunner9StagesAndCli:
    """Class 15: 9-stage verification runner and CLI execution."""

    def test_run_verification_direct(self):
        res = run_cip_safety_apl_tdr_verification()
        assert res.get("status") == "success"
        assert res.get("stages_passed") == 9
        assert len(res.get("data", {}).get("stages", [])) == 9

    def test_cli_execution_with_temp_artifact(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            res = run_cip_safety_apl_tdr_verification(output_path=tmp_path)
            assert res.get("status") == "success"
            assert tmp_path.exists()
            with open(tmp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data.get("status") == "success"
            assert data.get("stages_passed") == 9
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


class TestParameterizationAndEdgeCases:
    """Class 16: Parameterized variations and boundary tests."""

    @pytest.mark.parametrize("impedance,expected_diag", [
        (100.0, DiagnosticCode.DIAG_OK),
        (125.0, DiagnosticCode.DIAG_OK),
        (75.0, DiagnosticCode.DIAG_OK),
        (126.0, DiagnosticCode.DIAG_ERR_IMPEDANCE_MISMATCH),
        (74.0, DiagnosticCode.DIAG_ERR_IMPEDANCE_MISMATCH),
        (200.0, DiagnosticCode.DIAG_ERR_IMPEDANCE_MISMATCH),
        (50.0, DiagnosticCode.DIAG_ERR_IMPEDANCE_MISMATCH),
        (1000.0, DiagnosticCode.DIAG_ERR_CABLE_OPEN_CIRCUIT),
        (10.0, DiagnosticCode.DIAG_ERR_CABLE_SHORT_CIRCUIT),
    ])
    def test_impedance_boundaries(self, impedance, expected_diag):
        engine = CIPAPLTDRSafetyEngine()
        engine.connect()
        if impedance >= 1000.0:
            engine.inject_open_circuit()
        elif impedance <= 10.0:
            engine.inject_short_circuit()
        elif abs(impedance - 100.0) > 25.0:
            engine.inject_impedance_mismatch(impedance_ohm=impedance)
        else:
            engine.measured_impedance_ohm = impedance
        engine.scan_step()
        assert engine.diagnostic_code == expected_diag

    @pytest.mark.parametrize("dist_m", [10.0, 50.0, 100.0, 150.0, 200.0, 500.0, 1000.0])
    def test_fault_distance_parameterization(self, dist_m):
        engine = CIPAPLTDRSafetyEngine(cable_length_m=1000.0)
        engine.connect()
        engine.inject_open_circuit(distance_m=dist_m)
        engine.scan_step()
        assert engine.fault_distance_m == dist_m
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert rt.read_word(REG_CIP_APL_TDR_FAULT_DISTANCE_M) == int(dist_m * 10.0)

    @pytest.mark.parametrize("rl_db", [5.0, 8.0, 10.0, 12.0, 13.9])
    def test_return_loss_trip_thresholds(self, rl_db):
        engine = CIPAPLTDRSafetyEngine()
        engine.connect()
        engine.inject_return_loss_fault(return_loss_db=rl_db)
        engine.scan_step()
        assert engine.state == TDROperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_RETURN_LOSS_EXCURSION

    @pytest.mark.parametrize("code", [
        DiagnosticCode.DIAG_OK,
        DiagnosticCode.DIAG_ERR_CABLE_OPEN_CIRCUIT,
        DiagnosticCode.DIAG_ERR_CABLE_SHORT_CIRCUIT,
        DiagnosticCode.DIAG_ERR_IMPEDANCE_MISMATCH,
        DiagnosticCode.DIAG_ERR_RETURN_LOSS_EXCURSION,
        DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
        DiagnosticCode.DIAG_ERR_TDR_PULSE_ATTENUATION,
    ])
    def test_diagnostic_code_properties(self, code):
        assert str(code).startswith("0x")
        assert repr(code).startswith("DiagnosticCode.")
        val_u16 = int(code) & 0xFFFF
        assert (code & 0xFFFF) == val_u16
        assert (0xFFFF & code) == val_u16
        assert hash(code) == hash(val_u16)

    @pytest.mark.parametrize("state", [
        TDROperatingState.DE_ENERGIZED,
        TDROperatingState.CALIBRATING,
        TDROperatingState.MONITORING,
        TDROperatingState.DEGRADED,
        TDROperatingState.FAULT_LOCKOUT,
        TDROperatingState.SAFETY_TRIP,
    ])
    def test_state_enum_roundtrip(self, state):
        assert TDROperatingState(int(state)) == state

    @pytest.mark.parametrize("fault", [
        CableFaultType.NONE,
        CableFaultType.OPEN_CIRCUIT,
        CableFaultType.SHORT_CIRCUIT,
        CableFaultType.IMPEDANCE_MISMATCH,
        CableFaultType.WATER_INGRESS,
        CableFaultType.CABLE_CUT,
    ])
    def test_fault_enum_roundtrip(self, fault):
        assert CableFaultType(int(fault)) == fault

    @pytest.mark.parametrize("nvp_pct", [50.0, 60.0, 67.0, 70.0, 80.0])
    def test_nvp_variations(self, nvp_pct):
        engine = CIPAPLTDRSafetyEngine(nvp_pct=nvp_pct)
        engine.connect()
        engine.scan_step()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert rt.read_word(REG_CIP_APL_TDR_PROPAGATION_VEL_PERCENT) == int(nvp_pct * 10.0)

    @pytest.mark.parametrize("refl", [-0.9, -0.5, 0.0, 0.3, 0.8])
    def test_reflection_coeff_registers(self, refl):
        engine = CIPAPLTDRSafetyEngine()
        engine.connect()
        engine.reflection_coeff = refl
        engine.scan_step()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert rt.read_word(REG_CIP_APL_TDR_REFLECTION_COEFF) == int(round(refl * 1000.0))

    def test_cli_subprocess_execution(self):
        cmd = [sys.executable, "scripts/run_cip_safety_apl_tdr_verification.py", "--json"]
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
        assert res.returncode == 0
        data = json.loads(res.stdout)
        assert data.get("status") == "success"
        assert data.get("stages_passed") == 9
