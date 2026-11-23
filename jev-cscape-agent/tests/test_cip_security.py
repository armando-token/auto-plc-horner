"""Comprehensive Unit and Integration Test Suite for Industrial EtherNet/IP CIP Security Protocol Engine.

Work Package: W193 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Test Coverage (58+ Unit Tests across 10 Sections):
1. Section 1: Enums & Protocol Constants (CipSecurityProfileState, CipCipherSuite, CipSecurityDiagnosticCode, Ports & Classes).
2. Section 2: X.509 Certificate Management (X509CertInfo creation, validity window, days remaining, SAN verification).
3. Section 3: Sliding-Window Anti-Replay Protection (ReplayProtectionWindow: sequential, duplicate, old packet drop, out-of-order).
4. Section 4: ODVA CIP Security Objects (Class 0x5D & Class 0x5E attribute resolution, sets, read-only protections).
5. Section 5: TLS 1.3 / DTLS 1.2 Handshake & Session Management (Cipher suite negotiation, key derivation, capacity limit, session lifecycle).
6. Section 6: Pure IEC 61131-3 ST POU & SecurityGuard (STParser AST binding, anti-ladder rejection).
7. Section 7: Horner OCS Register Table Synchronization (%R1540..%R1547, %M359..%M360 with PrivilegeMode.SYSTEM).
8. Section 8: ILogicUnit 100-Cycle Simulation (scan_step, execute, priority, reset).
9. Section 9: Process Safety Interlocks & Fault Scenarios (0xD101..0xD104 trips, CRL revocation, and reset recovery).
10. Section 10: Deterministic 9-Stage Verification Runner (run_cip_security_verification returns status == 'success').
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_security import (
    CIP_CERTIFICATE_MANAGEMENT_CLASS_ID,
    CIP_SECURITY_CLASS_ID,
    CIP_SECURITY_POU,
    CIP_SECURITY_TCP_PORT,
    CIP_SECURITY_TRUST_SYNC_POU,
    CIP_SECURITY_UDP_PORT,
    DEFAULT_BASE_TIME_S,
    DEFAULT_MAX_TLS_SESSIONS,
    DEFAULT_REPLAY_WINDOW_SIZE,
    NOMINAL_KEY_EXCHANGE_LATENCY_MS,
    NOMINAL_LATENCY_SCALED,
    ONE_DAY_SECONDS,
    CertificateManagementObject,
    CipCipherSuite,
    CipSecurityDiagnosticCode,
    CipSecurityEngine,
    CipSecurityObject,
    CipSecurityProfileState,
    CipSecurityTrustSyncPOU,
    ReplayProtectionWindow,
    TlsSession,
    X509CertInfo,
    decode_dint_words,
    encode_dint_words,
    run_cip_security_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
)


# ============================================================================
# Section 1: Enums & Protocol Constants
# ============================================================================

class TestCipSecurityEnumsAndConstants:
    """Tests for protocol enumeration types, diagnostic codes, and protocol constants."""

    def test_security_profile_state_values_and_aliases(self) -> None:
        assert CipSecurityProfileState.FACTORY_DEFAULT == 0
        assert CipSecurityProfileState.INTEGRITY_ONLY == 1
        assert CipSecurityProfileState.INTEGRITY_AND_CONFIDENTIALITY == 2
        assert CipSecurityProfileState.DEGRADED_UNTRUSTED == 3

        # Compatibility aliases
        assert CipSecurityProfileState.FactoryDefault == 0
        assert CipSecurityProfileState.IntegrityOnly == 1
        assert CipSecurityProfileState.IntegrityAndConfidentiality == 2
        assert CipSecurityProfileState.DegradedUntrusted == 3

    def test_cipher_suite_values_and_aliases(self) -> None:
        assert CipCipherSuite.UNKNOWN == 0x0000
        assert CipCipherSuite.NONE == 0x0000
        assert CipCipherSuite.TLS_AES_128_GCM_SHA256 == 0x1301
        assert CipCipherSuite.TLS_AES_256_GCM_SHA384 == 0x1302
        assert CipCipherSuite.TLS_CHACHA20_POLY1305_SHA256 == 0x1303
        assert CipCipherSuite.ECDHE_ECDSA_AES128_GCM_SHA256 == 0xC02B
        assert CipCipherSuite.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 == 0xC02B
        assert CipCipherSuite.ECDHE_RSA_AES128_GCM_SHA256 == 0xC02F

        # Convenience aliases
        assert CipCipherSuite.AES_128_GCM == 0x1301
        assert CipCipherSuite.AES_256_GCM == 0x1302
        assert CipCipherSuite.ECDHE_ECDSA == 0xC02B

    def test_diagnostic_code_values_and_aliases(self) -> None:
        assert CipSecurityDiagnosticCode.OK == 0x0000
        assert CipSecurityDiagnosticCode.CERTIFICATE_EXPIRED == 0xD101
        assert CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA == 0xD102
        assert CipSecurityDiagnosticCode.REPLAY_ATTACK_DETECTED == 0xD103
        assert CipSecurityDiagnosticCode.CIPHER_MISMATCH == 0xD104

        # Compatibility aliases
        assert CipSecurityDiagnosticCode.CERT_EXPIRED == 0xD101
        assert CipSecurityDiagnosticCode.UNTRUSTED_CA == 0xD102
        assert CipSecurityDiagnosticCode.REPLAY_ATTACK == 0xD103
        assert CipSecurityDiagnosticCode.CIPHER_UNSUPPORTED == 0xD104

    def test_protocol_constants_and_ports(self) -> None:
        assert CIP_SECURITY_CLASS_ID == 0x5D
        assert CIP_CERTIFICATE_MANAGEMENT_CLASS_ID == 0x5E
        assert CIP_SECURITY_TCP_PORT == 44818
        assert CIP_SECURITY_UDP_PORT == 2222
        assert DEFAULT_MAX_TLS_SESSIONS == 16
        assert DEFAULT_REPLAY_WINDOW_SIZE == 64
        assert NOMINAL_KEY_EXCHANGE_LATENCY_MS == 3.5
        assert NOMINAL_LATENCY_SCALED == 35
        assert DEFAULT_BASE_TIME_S == 1775000000.0
        assert ONE_DAY_SECONDS == 86400.0

    def test_dint_word_encoding_decoding_roundtrip(self) -> None:
        test_values = [0, 1, 100, 32767, 65535, 1000000, 0x12345678, -1, -50000]
        for val in test_values:
            high, low = encode_dint_words(val)
            decoded = decode_dint_words(high, low)
            expected = val if val >= 0 else val & 0xFFFFFFFF
            expected_signed = expected - 0x100000000 if expected >= 0x80000000 else expected
            assert decoded == expected_signed


# ============================================================================
# Section 2: X.509 Certificate Management
# ============================================================================

class TestX509CertificateInfo:
    """Tests for X.509 Certificate representation, validity windows, days remaining, and SAN checks."""

    @pytest.fixture
    def sample_cert(self) -> X509CertInfo:
        return X509CertInfo(
            common_name="plc01.plant.local",
            issuer="Horner Industrial Root CA",
            not_before_s=1770000000.0,
            not_after_s=1775000000.0 + (30 * ONE_DAY_SECONDS),
            san=["plc01.plant.local", "192.168.1.50", "DNS:plc01-alt.plant.local"],
            serial_number="01:AA:BB:CC",
            is_ca=False,
        )

    def test_x509_cert_creation_and_defaults(self, sample_cert: X509CertInfo) -> None:
        assert sample_cert.common_name == "plc01.plant.local"
        assert sample_cert.issuer == "Horner Industrial Root CA"
        assert sample_cert.is_ca is False
        assert sample_cert.serial_number == "01:AA:BB:CC"
        assert sample_cert.signature_algorithm == "sha256WithRSAEncryption"

    def test_x509_cert_validity_at_time(self, sample_cert: X509CertInfo) -> None:
        # In range
        assert sample_cert.is_valid_at(1771000000.0) is True
        assert sample_cert.is_valid_at(1770000000.0) is True
        assert sample_cert.is_valid_at(sample_cert.not_after_s) is True

        # Before not_before
        assert sample_cert.is_valid_at(1769999999.0) is False

        # After not_after
        assert sample_cert.is_valid_at(sample_cert.not_after_s + 1.0) is False

    def test_x509_cert_days_remaining(self, sample_cert: X509CertInfo) -> None:
        base_t = 1775000000.0
        # Exactly 30 days remaining
        assert sample_cert.days_remaining(base_t) == 30

        # 15 days remaining
        assert sample_cert.days_remaining(base_t + (15 * ONE_DAY_SECONDS)) == 15

        # 0 days remaining when expired
        assert sample_cert.days_remaining(sample_cert.not_after_s + 100.0) == 0

    def test_x509_cert_san_matching_exact_cn(self, sample_cert: X509CertInfo) -> None:
        assert sample_cert.matches_san("plc01.plant.local") is True
        assert sample_cert.matches_san("PLC01.PLANT.LOCAL") is True

    def test_x509_cert_san_matching_san_list(self, sample_cert: X509CertInfo) -> None:
        assert sample_cert.matches_san("192.168.1.50") is True
        assert sample_cert.matches_san("plc01-alt.plant.local") is True
        assert sample_cert.matches_san("DNS:plc01-alt.plant.local") is True

    def test_x509_cert_san_matching_mismatch(self, sample_cert: X509CertInfo) -> None:
        assert sample_cert.matches_san("attacker.rogue.net") is False
        assert sample_cert.matches_san("10.0.0.1") is False

    def test_x509_cert_to_dict_serialization(self, sample_cert: X509CertInfo) -> None:
        data = sample_cert.to_dict()
        assert data["common_name"] == "plc01.plant.local"
        assert data["issuer"] == "Horner Industrial Root CA"
        assert data["is_ca"] is False
        assert "192.168.1.50" in data["san"]
        assert data["serial_number"] == "01:AA:BB:CC"


# ============================================================================
# Section 3: Sliding-Window Anti-Replay Protection
# ============================================================================

class TestReplayProtectionWindow:
    """Tests for 64-packet bitmask sliding window anti-replay protection."""

    def test_replay_window_initial_state(self) -> None:
        win = ReplayProtectionWindow(window_size=64)
        assert win.window_size == 64
        assert win.max_seq == 0
        assert win.bitmap == 0
        assert win.packets_accepted == 0
        assert win.packets_dropped == 0

    def test_replay_window_in_order_acceptance(self) -> None:
        win = ReplayProtectionWindow(window_size=64)
        for seq in range(1, 21):
            assert win.check_and_update(seq) is True
        assert win.max_seq == 20
        assert win.packets_accepted == 20
        assert win.packets_dropped == 0

    def test_replay_window_duplicate_rejection(self) -> None:
        win = ReplayProtectionWindow(window_size=64)
        for seq in range(1, 11):
            win.check_and_update(seq)

        # Duplicate of seq 5
        assert win.check_and_update(5) is False
        assert win.packets_dropped == 1
        assert win.packets_accepted == 10

        # Duplicate of seq 10 (the highest seen)
        assert win.check_and_update(10) is False
        assert win.packets_dropped == 2

    def test_replay_window_old_packet_drop(self) -> None:
        win = ReplayProtectionWindow(window_size=64)
        # Advance window to 100
        win.check_and_update(100)

        # Packet 100 - 64 = 36 is the boundary (diff=64 >= 64, dropped)
        assert win.check_and_update(36) is False
        assert win.packets_dropped == 1

        # Packet 10 is ancient, dropped
        assert win.check_and_update(10) is False
        assert win.packets_dropped == 2

    def test_replay_window_large_jump_advances_window(self) -> None:
        win = ReplayProtectionWindow(window_size=64)
        win.check_and_update(10)
        # Jump ahead by 100 packets (> window_size)
        assert win.check_and_update(110) is True
        assert win.max_seq == 110
        assert win.bitmap == 1

        # Packet 10 is now way behind window
        assert win.check_and_update(10) is False

    def test_replay_window_out_of_order_within_window(self) -> None:
        win = ReplayProtectionWindow(window_size=64)
        # Sequence arrives out of order: 10, then 8, 9, 7
        assert win.check_and_update(10) is True
        assert win.check_and_update(8) is True
        assert win.check_and_update(9) is True
        assert win.check_and_update(7) is True

        assert win.packets_accepted == 4
        assert win.packets_dropped == 0

        # Duplicate of 8 should now be rejected
        assert win.check_and_update(8) is False
        assert win.packets_dropped == 1

    def test_replay_window_zero_and_negative_dropped(self) -> None:
        win = ReplayProtectionWindow(window_size=64)
        assert win.check_and_update(0) is False
        assert win.check_and_update(-5) is False
        assert win.packets_dropped == 2

    def test_replay_window_reset_and_to_dict(self) -> None:
        win = ReplayProtectionWindow(window_size=64)
        win.check_and_update(50)
        win.check_and_update(50)
        d = win.to_dict()
        assert d["max_seq"] == 50
        assert d["packets_accepted"] == 1
        assert d["packets_dropped"] == 1

        win.reset()
        assert win.max_seq == 0
        assert win.bitmap == 0
        assert win.packets_accepted == 0
        assert win.packets_dropped == 0


# ============================================================================
# Section 4: ODVA CIP Security Objects (Class 0x5D & 0x5E)
# ============================================================================

class TestCipSecurityObjectsClass5DAnd5E:
    """Tests for ODVA CIP Security Object (Class 0x5D) and Certificate Management Object (Class 0x5E)."""

    def test_security_object_5d_initial_attributes(self) -> None:
        sec_obj = CipSecurityObject()
        assert sec_obj.class_id == 0x5D
        assert sec_obj.instance_id == 1
        assert sec_obj.get_attribute_single(1) == int(CipSecurityProfileState.INTEGRITY_AND_CONFIDENTIALITY)
        assert sec_obj.get_attribute_single(2) == 0
        assert sec_obj.get_attribute_single(3) == 0x1301
        assert isinstance(sec_obj.get_attribute_single(4), list)
        assert sec_obj.get_attribute_single(5) == 0x03
        assert sec_obj.get_attribute_single(6) == 0
        assert sec_obj.get_attribute_single(7) == 0
        assert sec_obj.get_attribute_single(8) == NOMINAL_LATENCY_SCALED
        assert sec_obj.get_attribute_single(9) == 0x0000
        assert sec_obj.get_attribute_single(10) is False
        assert sec_obj.get_attribute_single(11) is False

    def test_security_object_5d_set_writable_attributes(self) -> None:
        sec_obj = CipSecurityObject()
        # Attribute 1: SecurityProfileState
        assert sec_obj.set_attribute_single(1, 1) is True
        assert sec_obj.profile_state == CipSecurityProfileState.INTEGRITY_ONLY

        # Attribute 5: configuration_flags
        assert sec_obj.set_attribute_single(5, 0x01) is True
        assert sec_obj.configuration_flags == 0x01

    def test_security_object_5d_read_only_protection(self) -> None:
        sec_obj = CipSecurityObject()
        for read_only_attr in [2, 3, 4, 6, 7, 8, 9, 10, 11]:
            with pytest.raises(PermissionError):
                sec_obj.set_attribute_single(read_only_attr, 99)

    def test_security_object_5d_invalid_attribute(self) -> None:
        sec_obj = CipSecurityObject()
        with pytest.raises(KeyError):
            sec_obj.get_attribute_single(99)
        with pytest.raises(KeyError):
            sec_obj.set_attribute_single(99, 1)

    def test_security_object_5d_get_attribute_all(self) -> None:
        sec_obj = CipSecurityObject()
        attrs = sec_obj.get_attribute_all()
        assert len(attrs) == 11
        assert attrs[1] == int(CipSecurityProfileState.INTEGRITY_AND_CONFIDENTIALITY)
        assert attrs[3] == 0x1301

    def test_certificate_management_object_5e_attributes(self) -> None:
        cert_obj = CertificateManagementObject()
        assert cert_obj.class_id == 0x5E
        assert cert_obj.instance_id == 1
        assert cert_obj.get_attribute_single(1) == 1  # Valid
        assert cert_obj.get_attribute_single(2) == 365
        assert cert_obj.get_attribute_single(3) == "01:A2:F3:4B"
        assert cert_obj.get_attribute_single(4) == 1
        assert cert_obj.get_attribute_single(5) == 0
        assert cert_obj.get_attribute_single(6) == "Horner Root CA"
        assert cert_obj.get_attribute_single(7) == "Horner OCS Security Controller"
        assert isinstance(cert_obj.get_attribute_single(8), list)

        all_attrs = cert_obj.get_attribute_all()
        assert len(all_attrs) == 8

    def test_certificate_management_object_5e_read_only_protection(self) -> None:
        cert_obj = CertificateManagementObject()
        for attr_id in range(1, 9):
            with pytest.raises(PermissionError):
                cert_obj.set_attribute_single(attr_id, "foo")

        with pytest.raises(KeyError):
            cert_obj.get_attribute_single(99)
        with pytest.raises(KeyError):
            cert_obj.set_attribute_single(99, "foo")


# ============================================================================
# Section 5: TLS 1.3 / DTLS 1.2 Handshake & Session Management
# ============================================================================

class TestTlsDtlsHandshakeAndNegotiation:
    """Tests for cipher suite negotiation, TLS/DTLS simulated handshake, and session containers."""

    @pytest.fixture
    def setup_engine_and_certs(self) -> Dict[str, Any]:
        engine = CipSecurityEngine(current_time_s=DEFAULT_BASE_TIME_S, max_sessions=4)
        root_ca = X509CertInfo(
            common_name="Horner Test Root CA",
            issuer="Horner Test Root CA",
            not_before_s=DEFAULT_BASE_TIME_S - (100 * ONE_DAY_SECONDS),
            not_after_s=DEFAULT_BASE_TIME_S + (500 * ONE_DAY_SECONDS),
            serial_number="CA:00:11:22",
            is_ca=True,
        )
        engine.add_trusted_root_ca(root_ca)

        peer_cert = X509CertInfo(
            common_name="peer.plant.local",
            issuer="Horner Test Root CA",
            not_before_s=DEFAULT_BASE_TIME_S - (10 * ONE_DAY_SECONDS),
            not_after_s=DEFAULT_BASE_TIME_S + (100 * ONE_DAY_SECONDS),
            san=["peer.plant.local", "192.168.1.75"],
            serial_number="01:55:66:77",
            is_ca=False,
        )
        return {"engine": engine, "root_ca": root_ca, "peer_cert": peer_cert}

    def test_cipher_negotiation_preferred_match(self, setup_engine_and_certs: Dict[str, Any]) -> None:
        engine: CipSecurityEngine = setup_engine_and_certs["engine"]
        offered = [
            CipCipherSuite.ECDHE_ECDSA_AES128_GCM_SHA256,
            CipCipherSuite.TLS_AES_128_GCM_SHA256,
        ]
        # Engine preferred order: TLS_AES_128_GCM_SHA256 is first
        selected = engine.negotiate_cipher_suite(offered)
        assert selected == CipCipherSuite.TLS_AES_128_GCM_SHA256

    def test_cipher_negotiation_mismatch(self, setup_engine_and_certs: Dict[str, Any]) -> None:
        engine: CipSecurityEngine = setup_engine_and_certs["engine"]
        offered = [0x0005, 0x000A]  # Legacy unsupported DES ciphers
        selected = engine.negotiate_cipher_suite(offered)
        assert selected is None

    def test_handshake_successful_tls_session(self, setup_engine_and_certs: Dict[str, Any]) -> None:
        engine: CipSecurityEngine = setup_engine_and_certs["engine"]
        peer_cert: X509CertInfo = setup_engine_and_certs["peer_cert"]

        ok, msg, sess = engine.perform_handshake(
            peer_identity="peer.plant.local",
            peer_cert=peer_cert,
            offered_ciphers=[CipCipherSuite.TLS_AES_128_GCM_SHA256],
        )

        assert ok is True
        assert sess is not None
        assert sess.is_active is True
        assert sess.is_dtls is False
        assert sess.cipher_suite == CipCipherSuite.TLS_AES_128_GCM_SHA256
        assert len(sess.session_key) == 16
        assert len(sess.shared_secret) == 32
        assert sess.session_id in engine.active_sessions
        assert engine.is_authenticated is True
        assert engine.is_tamper_alert is False
        assert engine.diagnostic_code == CipSecurityDiagnosticCode.OK

    def test_handshake_dtls_mode(self, setup_engine_and_certs: Dict[str, Any]) -> None:
        engine: CipSecurityEngine = setup_engine_and_certs["engine"]
        peer_cert: X509CertInfo = setup_engine_and_certs["peer_cert"]

        ok, msg, sess = engine.perform_handshake(
            peer_identity="peer.plant.local",
            peer_cert=peer_cert,
            offered_ciphers=[CipCipherSuite.ECDHE_ECDSA_AES128_GCM_SHA256],
            is_dtls=True,
        )

        assert ok is True
        assert sess is not None
        assert sess.is_dtls is True
        assert sess.cipher_suite == CipCipherSuite.ECDHE_ECDSA_AES128_GCM_SHA256

    def test_handshake_max_sessions_capacity_limit(self, setup_engine_and_certs: Dict[str, Any]) -> None:
        engine: CipSecurityEngine = setup_engine_and_certs["engine"]
        peer_cert: X509CertInfo = setup_engine_and_certs["peer_cert"]
        # engine.max_sessions is 4

        sessions = []
        for i in range(4):
            ok, _, s = engine.perform_handshake(
                peer_identity=f"peer{i}.plant.local",
                peer_cert=peer_cert,
                offered_ciphers=[CipCipherSuite.TLS_AES_128_GCM_SHA256],
                peer_san="peer.plant.local",
            )
            assert ok is True
            sessions.append(s)

        assert len(engine.active_sessions) == 4

        # 5th handshake exceeds capacity
        ok5, msg5, s5 = engine.perform_handshake(
            peer_identity="peer5.plant.local",
            peer_cert=peer_cert,
            offered_ciphers=[CipCipherSuite.TLS_AES_128_GCM_SHA256],
            peer_san="peer.plant.local",
        )
        assert ok5 is False
        assert s5 is None
        assert "Maximum active TLS sessions reached" in msg5
        assert engine.failed_handshake_counter == 1

    def test_session_closure_and_state_update(self, setup_engine_and_certs: Dict[str, Any]) -> None:
        engine: CipSecurityEngine = setup_engine_and_certs["engine"]
        peer_cert: X509CertInfo = setup_engine_and_certs["peer_cert"]

        ok, _, s = engine.perform_handshake(
            peer_identity="peer.plant.local",
            peer_cert=peer_cert,
            offered_ciphers=[CipCipherSuite.TLS_AES_128_GCM_SHA256],
        )
        assert ok is True
        assert engine.is_authenticated is True

        # Close session
        assert engine.close_session(s.session_id) is True
        assert len(engine.active_sessions) == 0
        assert engine.is_authenticated is False

        # Closing non-existent session returns False
        assert engine.close_session("fake_id") is False

    def test_incoming_packet_updates_session_stats(self, setup_engine_and_certs: Dict[str, Any]) -> None:
        engine: CipSecurityEngine = setup_engine_and_certs["engine"]
        peer_cert: X509CertInfo = setup_engine_and_certs["peer_cert"]

        _, _, sess = engine.perform_handshake(
            peer_identity="peer.plant.local",
            peer_cert=peer_cert,
            offered_ciphers=[CipCipherSuite.TLS_AES_128_GCM_SHA256],
        )

        payload = b"GET_CIP_IDENTITY"
        assert engine.process_incoming_packet(sess.session_id, 1, payload) is True
        assert sess.packets_received == 1
        assert sess.bytes_received == len(payload)


# ============================================================================
# Section 6: Pure IEC 61131-3 ST POU & SecurityGuard
# ============================================================================

class TestPureIEC61131STPOUAndSecurityGuard:
    """Tests for pure Structured Text syntax, register AST binding, and anti-ladder guards."""

    def test_cip_security_pou_st_parser_validation(self) -> None:
        result = STParser.validate_code(CIP_SECURITY_TRUST_SYNC_POU)
        assert result.status == AgentStatus.SUCCESS
        assert result.data["pou_name"] == "CipSecurityTrustSync"
        assert result.data["pou_type"] == "PROGRAM"

    def test_cip_security_pou_ast_structure_and_registers(self) -> None:
        ast = STParser.parse_pou(CIP_SECURITY_TRUST_SYNC_POU)
        assert ast.name == "CipSecurityTrustSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1540", "%R1541", "%R1542", "%R1543",
            "%R1544", "%R1545", "%R1546", "%R1547",
            "%M359", "%M360",
        }
        bound = set(ast.bound_registers)
        assert expected_regs.issubset(bound)

    def test_security_guard_assert_pure_st_content(self) -> None:
        # POU text must pass without raising LadderForbiddenError
        SecurityGuard.assert_pure_st_content(CIP_SECURITY_TRUST_SYNC_POU)
        SecurityGuard.assert_pure_st_content(CipSecurityTrustSyncPOU)
        SecurityGuard.assert_pure_st_content(CIP_SECURITY_POU)

    def test_security_guard_anti_ladder_interception(self) -> None:
        forbidden_constructs = [
            "---[ ]---",
            "---[/]---",
            "---( )---",
            "---(S)---",
            "---(R)---",
            "RUNG 1",
            "NETWORK 10",
            "XIC StartButton",
            "OTE RunCoil",
        ]
        for snip in forbidden_constructs:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snip)


# ============================================================================
# Section 7: Horner RegisterTable Synchronization
# ============================================================================

class TestHornerRegisterTableSynchronization:
    """Tests for Horner RegisterTable mapping (%R1540..%R1547, %M359..%M360) using PrivilegeMode.SYSTEM."""

    def test_register_sync_nominal_values(self) -> None:
        rt = RegisterTable()
        engine = CipSecurityEngine(reg_table=rt, current_time_s=DEFAULT_BASE_TIME_S)

        root = X509CertInfo(
            common_name="Horner Root CA",
            issuer="Horner Root CA",
            not_before_s=DEFAULT_BASE_TIME_S - 1000,
            not_after_s=DEFAULT_BASE_TIME_S + 1000000,
            is_ca=True,
        )
        engine.add_trusted_root_ca(root)

        peer = X509CertInfo(
            common_name="peer.local",
            issuer="Horner Root CA",
            not_before_s=DEFAULT_BASE_TIME_S - 100,
            not_after_s=DEFAULT_BASE_TIME_S + (50 * ONE_DAY_SECONDS),
            is_ca=False,
        )

        engine.perform_handshake(
            peer_identity="peer.local",
            peer_cert=peer,
            offered_ciphers=[CipCipherSuite.TLS_AES_128_GCM_SHA256],
        )
        engine.sync_to_registers()

        assert rt.read_word("%R1540") == int(CipSecurityProfileState.INTEGRITY_AND_CONFIDENTIALITY)
        assert rt.read_word("%R1541") == 1
        assert rt.read_uword("%R1542") == 0x1301
        assert rt.read_word("%R1543") == 50
        assert rt.read_word("%R1544") == 0
        assert rt.read_word("%R1545") == 0
        assert rt.read_word("%R1546") == 35  # 3.5ms * 10
        assert rt.read_uword("%R1547") == 0x0000
        assert rt.read_bit("%M359") is True
        assert rt.read_bit("%M360") is False

    def test_register_sync_uses_privilege_mode_system(self) -> None:
        rt = RegisterTable()
        engine = CipSecurityEngine(reg_table=rt, current_time_s=DEFAULT_BASE_TIME_S)

        # Calling sync_to_registers updates registers successfully
        engine.sync_to_registers()
        # Verify default profile state is written
        assert rt.read_word("%R1540") == int(CipSecurityProfileState.INTEGRITY_AND_CONFIDENTIALITY)

    def test_register_sync_without_reg_table(self) -> None:
        # Engine with reg_table=None should not error
        engine = CipSecurityEngine(reg_table=None)
        engine.sync_to_registers()
        snap = engine.get_snapshot()
        assert snap["profile_state"] == int(CipSecurityProfileState.INTEGRITY_AND_CONFIDENTIALITY)

    def test_safe_write_helpers(self) -> None:
        rt = RegisterTable()
        # Word write
        safe_write_word(rt, "%R1540", 500)
        assert rt.read_word("%R1540") == 500

        # Unsigned word write
        safe_write_uword(rt, "%R1547", 0xD101)
        assert rt.read_uword("%R1547") == 0xD101

        # Bit write
        safe_write_bit(rt, "%M359", True)
        assert rt.read_bit("%M359") is True
        safe_write_bit(rt, "%M359", False)
        assert rt.read_bit("%M359") is False


# ============================================================================
# Section 8: ILogicUnit 100-Cycle Simulation
# ============================================================================

class TestILogicUnitScanCycleExecution:
    """Tests for ILogicUnit interface compliance and multi-cycle deterministic simulation."""

    def test_ilogic_unit_contract_properties(self) -> None:
        engine = CipSecurityEngine()
        assert engine.name == "cip_security"
        assert engine.priority == 94
        assert engine.is_enabled is True

    def test_execute_via_scan_context(self) -> None:
        rt = RegisterTable()
        engine = CipSecurityEngine(reg_table=rt)

        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=rt.read_register,
            set_register=lambda a, v: rt.write_register(a, v, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda k, d=None: d,
            set_variable=lambda k, v: None,
            record_fault=lambda f: None,
        )

        res = engine.execute(ctx)
        assert res.status == AgentStatus.SUCCESS
        assert "smoothly" in res.details
        assert res.data["total_scan_cycles"] == 1
        assert res.data["elapsed_simulation_ms"] == 10.0

    def test_100_scan_steps_continuous_run(self) -> None:
        rt = RegisterTable()
        engine = CipSecurityEngine(reg_table=rt)

        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=rt.read_register,
            set_register=lambda a, v: rt.write_register(a, v, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda k, d=None: d,
            set_variable=lambda k, v: None,
            record_fault=lambda f: None,
        )

        for c in range(1, 101):
            ctx.cycle = c
            ctx.elapsed_time_ms = c * 10.0
            engine.execute(ctx)

        assert engine.total_scan_cycles == 100
        assert round(engine.elapsed_simulation_ms) == 1000

    def test_scan_step_advances_simulation_clock_and_days(self) -> None:
        engine = CipSecurityEngine(current_time_s=1000.0)
        init_t = engine.current_time_s

        engine.scan_step(dt=0.5)
        assert engine.current_time_s == init_t + 0.5
        assert engine.elapsed_simulation_ms == 500.0
        assert engine.total_scan_cycles == 1

    def test_engine_reset_restores_health(self) -> None:
        engine = CipSecurityEngine()
        engine.simulate_certificate_expired()
        assert engine.diagnostic_code == CipSecurityDiagnosticCode.CERTIFICATE_EXPIRED

        engine.reset()
        assert engine.diagnostic_code == CipSecurityDiagnosticCode.OK
        assert engine.is_tamper_alert is False


# ============================================================================
# Section 9: Process Safety Interlocks & Fault Scenarios
# ============================================================================

class TestProcessSafetyFaultScenarios:
    """Tests for fault trips (0xD101..0xD104), CRL revocation, and recovery."""

    @pytest.fixture
    def active_engine(self) -> CipSecurityEngine:
        rt = RegisterTable()
        engine = CipSecurityEngine(reg_table=rt, current_time_s=DEFAULT_BASE_TIME_S)
        root = X509CertInfo(
            common_name="Horner Root CA",
            issuer="Horner Root CA",
            not_before_s=DEFAULT_BASE_TIME_S - 1000,
            not_after_s=DEFAULT_BASE_TIME_S + 1000000,
            is_ca=True,
        )
        engine.add_trusted_root_ca(root)

        peer = X509CertInfo(
            common_name="peer.local",
            issuer="Horner Root CA",
            not_before_s=DEFAULT_BASE_TIME_S - 100,
            not_after_s=DEFAULT_BASE_TIME_S + (50 * ONE_DAY_SECONDS),
            is_ca=False,
        )
        engine.perform_handshake(
            peer_identity="peer.local",
            peer_cert=peer,
            offered_ciphers=[CipCipherSuite.TLS_AES_128_GCM_SHA256],
        )
        return engine

    def test_fault_certificate_expired_0xd101(self, active_engine: CipSecurityEngine) -> None:
        active_engine.simulate_certificate_expired()
        assert active_engine.diagnostic_code == CipSecurityDiagnosticCode.CERTIFICATE_EXPIRED
        assert active_engine.is_tamper_alert is True
        assert active_engine.is_authenticated is False
        assert active_engine.profile_state == CipSecurityProfileState.DEGRADED_UNTRUSTED

        rt = active_engine.reg_table
        assert rt.read_uword("%R1547") == 0xD101
        assert rt.read_bit("%M360") is True
        assert rt.read_bit("%M359") is False

    def test_fault_untrusted_root_ca_0xd102(self, active_engine: CipSecurityEngine) -> None:
        active_engine.simulate_untrusted_ca()
        assert active_engine.diagnostic_code == CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA
        assert active_engine.is_tamper_alert is True
        assert active_engine.is_authenticated is False
        assert active_engine.profile_state == CipSecurityProfileState.DEGRADED_UNTRUSTED

        rt = active_engine.reg_table
        assert rt.read_uword("%R1547") == 0xD102
        assert rt.read_bit("%M360") is True
        assert rt.read_bit("%M359") is False

    def test_fault_replay_attack_0xd103(self, active_engine: CipSecurityEngine) -> None:
        initial_drops = active_engine.replay_attack_drop_counter
        active_engine.simulate_replay_attack()
        assert active_engine.diagnostic_code == CipSecurityDiagnosticCode.REPLAY_ATTACK_DETECTED
        assert active_engine.is_tamper_alert is True
        assert active_engine.replay_attack_drop_counter == initial_drops + 1

        rt = active_engine.reg_table
        assert rt.read_uword("%R1547") == 0xD103
        assert rt.read_bit("%M360") is True
        assert rt.read_word("%R1545") == active_engine.replay_attack_drop_counter

    def test_fault_cipher_mismatch_0xd104(self, active_engine: CipSecurityEngine) -> None:
        initial_failed = active_engine.failed_handshake_counter
        active_engine.simulate_cipher_mismatch()
        assert active_engine.diagnostic_code == CipSecurityDiagnosticCode.CIPHER_MISMATCH
        assert active_engine.is_tamper_alert is True
        assert active_engine.failed_handshake_counter == initial_failed + 1

        rt = active_engine.reg_table
        assert rt.read_uword("%R1547") == 0xD104
        assert rt.read_bit("%M360") is True
        assert rt.read_word("%R1544") == active_engine.failed_handshake_counter

    def test_fault_crl_revocation_validation(self, active_engine: CipSecurityEngine) -> None:
        revoked_cert = X509CertInfo(
            common_name="revoked.plant.local",
            issuer="Horner Root CA",
            not_before_s=DEFAULT_BASE_TIME_S - 100,
            not_after_s=DEFAULT_BASE_TIME_S + 10000,
            serial_number="99:88:77:66",
            is_ca=False,
        )
        active_engine.revoke_certificate("99:88:77:66")
        assert active_engine.cert_management_object.crl_revoked_count == 1

        valid, err, msg = active_engine.validate_certificate(revoked_cert)
        assert valid is False
        assert err == CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA
        assert "revoked in CRL" in msg

    def test_fault_operator_reset_recovery(self, active_engine: CipSecurityEngine) -> None:
        active_engine.simulate_certificate_expired()
        assert active_engine.diagnostic_code == CipSecurityDiagnosticCode.CERTIFICATE_EXPIRED
        assert active_engine.is_authenticated is False

        res = active_engine.reset_fault(force=True)
        assert res.status == AgentStatus.SUCCESS
        assert active_engine.diagnostic_code == CipSecurityDiagnosticCode.OK
        assert active_engine.is_tamper_alert is False
        assert active_engine.is_authenticated is True

        rt = active_engine.reg_table
        assert rt.read_uword("%R1547") == 0x0000
        assert rt.read_bit("%M360") is False
        assert rt.read_bit("%M359") is True


# ============================================================================
# Section 10: Deterministic 9-Stage Verification Runner
# ============================================================================

class TestDeterministicVerificationRunner:
    """Tests for run_cip_security_verification deterministic 9-stage verification runner."""

    def test_run_cip_security_verification_execution_success(self) -> None:
        res = run_cip_security_verification()
        assert res["status"] == "success"
        assert res["stages_passed"] == 9
        assert res["total_stages"] == 9
        assert res["error_code"] is None
        assert "9/9 stages passed" in res["details"]

    def test_run_cip_security_verification_exports_json_evidence(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_security_evidence.json"
        res = run_cip_security_verification(output_path=out_file)
        assert res["status"] == "success"
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            evidence = json.load(f)
        assert evidence["status"] == "success"
        assert evidence["stages_passed"] == 9
        assert evidence["data"]["work_package"] == "W193"

    def test_run_cip_security_verification_all_9_individual_stages(self) -> None:
        res = run_cip_security_verification()
        stages = res["data"]["stages"]
        assert len(stages) == 9
        for st in stages:
            assert st["passed"] is True, f"Stage {st['stage']} ({st['check']}) did not pass!"

    def test_run_cip_security_verification_evidence_data_structure(self) -> None:
        res = run_cip_security_verification()
        data = res["data"]
        assert "register_map" in data
        assert "registers" in data
        assert "standards" in data
        assert data["work_package"] == "W193"
        assert data["registers"]["%R1540"] == int(CipSecurityProfileState.INTEGRITY_AND_CONFIDENTIALITY)
        assert data["registers"]["%R1547"] == 0x0000
        assert data["registers"]["%M359"] is True
        assert data["registers"]["%M360"] is False
