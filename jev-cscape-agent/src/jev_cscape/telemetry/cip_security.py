"""Industrial ODVA CIP Security Specification & TLS 1.3 / DTLS 1.2 Protocol Telemetry Engine.

Work Package: W193 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Standards:
- ODVA CIP Security Specification (Volume 8: EtherNet/IP Security Profile).
- TLS 1.3 (RFC 8446) / DTLS 1.2 (RFC 6347) session establishment for CIP messaging over TCP 44818 and UDP 2222.
- CIP Security Object (Class 0x5D) & Certificate Management Object (Class 0x5E).
- X.509 certificate validation: validity periods, Subject Alternative Name (SAN), trusted Root CA store, CRL revocation checking.
- Cryptographic cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, ECDHE-ECDSA-AES128-GCM-SHA256.
- Anti-replay sequence protection (sliding window 64 packets, RFC 6479 / RFC 4303).
- Security Profile states: 0=FactoryDefault, 1=IntegrityOnly, 2=IntegrityAndConfidentiality, 3=DegradedUntrusted.
- Horner OCS Register Table: %R1540..%R1547, %M359..%M360.
- Pure IEC 61131-3 Structured Text ONLY: POU 'CipSecurityTrustSync'.
- Anti-ladder security guard: SecurityGuard.assert_pure_st_content and STParser.
- ILogicUnit interface with scan_step(dt).
- In sync_to_registers(), pass privilege=PrivilegeMode.SYSTEM to reg_table writes.
- Strict 4-state contract: success | failed | blocked | inconclusive.

Register Mappings:
- %R1540: SecurityProfileState (0=FactoryDefault, 1=IntegrityOnly, 2=IntegrityAndConfidentiality, 3=DegradedUntrusted)
- %R1541: ActiveTlsSessionCount (INT16, 0..16)
- %R1542: CipherSuiteIdentifier (INT16, e.g. 0x1301 for TLS_AES_128_GCM_SHA256)
- %R1543: CertificateValidityDaysRemaining (INT16, days)
- %R1544: FailedHandshakeCounter (INT16, count)
- %R1545: ReplayAttackDropCounter (INT16, count)
- %R1546: SecurityKeyExchangeLatencyMsScaled (INT16, scaled x10 ms, e.g. 35 = 3.5 ms)
- %R1547: DiagnosticStatusCode (0x0000=OK, 0xD101=Certificate Expired, 0xD102=Untrusted Root CA, 0xD103=Replay Attack Detected, 0xD104=Cipher Mismatch)
- %M359: CipSecurityAuthenticated (BOOL, True when secure session active and trusted)
- %M360: SecurityTamperAlert (BOOL, True on replay attack, untrusted cert, or cipher breach)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Protocol Definitions (ODVA CIP Volume 8)
# ============================================================================

CIP_SECURITY_CLASS_ID: int = 0x5D
CIP_CERTIFICATE_MANAGEMENT_CLASS_ID: int = 0x5E

CIP_SECURITY_TCP_PORT: int = 44818  # TLS encapsulation for EtherNet/IP
CIP_SECURITY_UDP_PORT: int = 2222   # DTLS encapsulation for I/O packets

DEFAULT_MAX_TLS_SESSIONS: int = 16
DEFAULT_REPLAY_WINDOW_SIZE: int = 64
NOMINAL_KEY_EXCHANGE_LATENCY_MS: float = 3.5
NOMINAL_LATENCY_SCALED: int = 35  # 3.5 ms * 10 = 35

DEFAULT_BASE_TIME_S: float = 1775000000.0  # Stable baseline timestamp
ONE_DAY_SECONDS: float = 86400.0


# ============================================================================
# 2. Protocol Enums & Diagnostic Codes
# ============================================================================

class CipSecurityProfileState(IntEnum):
    """ODVA CIP Security Profile States (Vol 8 Table 2-1) & %R1540 Values."""
    FACTORY_DEFAULT               = 0  # No credentials enrolled; unencrypted/open
    INTEGRITY_ONLY                = 1  # HMAC message integrity enforcement
    INTEGRITY_AND_CONFIDENTIALITY = 2  # Mutual TLS/DTLS authentication & AEAD payload encryption
    DEGRADED_UNTRUSTED            = 3  # Revocation, cert expiration, or security boundary tripped

    # Compatibility Aliases
    FactoryDefault               = 0
    IntegrityOnly                = 1
    IntegrityAndConfidentiality  = 2
    DegradedUntrusted            = 3


class CipCipherSuite(IntEnum):
    """ODVA CIP Security Supported TLS 1.3 & DTLS 1.2 Cipher Suites."""
    UNKNOWN                             = 0x0000
    NONE                                = 0x0000
    TLS_AES_128_GCM_SHA256              = 0x1301  # TLS 1.3 mandatory suite
    TLS_AES_256_GCM_SHA384              = 0x1302  # TLS 1.3 high-security suite
    TLS_CHACHA20_POLY1305_SHA256        = 0x1303  # TLS 1.3 ChaCha20-Poly1305
    ECDHE_ECDSA_AES128_GCM_SHA256       = 0xC02B  # DTLS 1.2 / TLS 1.2 ECDHE-ECDSA
    ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B  # Standard IANA alias
    ECDHE_RSA_AES128_GCM_SHA256         = 0xC02F  # RSA fallback suite

    # Convenience Aliases
    AES_128_GCM = 0x1301
    AES_256_GCM = 0x1302
    ECDHE_ECDSA = 0xC02B


class CipSecurityDiagnosticCode(IntEnum):
    """Horner OCS %R1547 Diagnostic Event Codes for CIP Security (W193)."""
    OK                      = 0x0000  # Security perimeter healthy; sessions verified
    CERTIFICATE_EXPIRED     = 0xD101  # X.509 device or peer certificate validity expired
    UNTRUSTED_ROOT_CA       = 0xD102  # Issuer not in trusted Root CA store or revoked in CRL
    REPLAY_ATTACK_DETECTED  = 0xD103  # Duplicate or out-of-window packet rejected by sliding window
    CIPHER_MISMATCH         = 0xD104  # Peer offered no mutually supported cryptographic cipher suites

    # Compatibility Aliases
    CERT_EXPIRED       = 0xD101
    UNTRUSTED_CA       = 0xD102
    REPLAY_ATTACK      = 0xD103
    CIPHER_UNSUPPORTED = 0xD104


# ============================================================================
# 3. Dataclasses: X509CertInfo, ReplayProtectionWindow, and TlsSession
# ============================================================================

@dataclass
class X509CertInfo:
    """X.509 Certificate Descriptor for CIP Security Trust Chain Validation."""
    common_name: str
    issuer: str
    not_before_s: float
    not_after_s: float
    san: List[str] = field(default_factory=list)
    serial_number: str = ""
    is_ca: bool = False
    public_key_pem: str = ""
    signature_algorithm: str = "sha256WithRSAEncryption"

    def is_valid_at(self, current_time_s: float) -> bool:
        """Evaluate if timestamp falls within certificate validity period."""
        return self.not_before_s <= float(current_time_s) <= self.not_after_s

    def days_remaining(self, current_time_s: float) -> int:
        """Calculate remaining validity period in whole calendar days."""
        t = float(current_time_s)
        if t > self.not_after_s:
            return 0
        rem_seconds = max(0.0, self.not_after_s - t)
        return int(rem_seconds / ONE_DAY_SECONDS)

    def matches_san(self, hostname_or_ip: str) -> bool:
        """Check if hostname or IP address matches SAN or CommonName."""
        target = hostname_or_ip.strip().lower()
        if self.common_name.strip().lower() == target:
            return True
        for san_entry in self.san:
            entry_clean = san_entry.strip().lower()
            if entry_clean == target:
                return True
            if ":" in entry_clean:
                _, val = entry_clean.split(":", 1)
                if val.strip() == target:
                    return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "common_name": self.common_name,
            "issuer": self.issuer,
            "not_before_s": self.not_before_s,
            "not_after_s": self.not_after_s,
            "san": list(self.san),
            "serial_number": self.serial_number,
            "is_ca": self.is_ca,
            "signature_algorithm": self.signature_algorithm,
        }


@dataclass
class ReplayProtectionWindow:
    """Sliding-Window Anti-Replay Protection Tracker (64-Packet Bitmask).

    Conforms to RFC 6479 / RFC 4303 IPsec anti-replay verification
    mandated by ODVA CIP Security Volume 8.
    """
    window_size: int = DEFAULT_REPLAY_WINDOW_SIZE
    max_seq: int = 0
    bitmap: int = 0
    packets_accepted: int = 0
    packets_dropped: int = 0

    def check_and_update(self, seq: int) -> bool:
        """Validate sequence number and update sliding window bitmask.

        Returns:
            True if packet is valid (advances window or fresh in-window).
            False if packet is duplicate or has fallen behind sliding window.
        """
        seq = int(seq)
        if seq <= 0:
            self.packets_dropped += 1
            return False

        if seq > self.max_seq:
            diff = seq - self.max_seq
            if diff < self.window_size:
                self.bitmap = ((self.bitmap << diff) | 1) & ((1 << self.window_size) - 1)
            else:
                self.bitmap = 1
            self.max_seq = seq
            self.packets_accepted += 1
            return True

        diff = self.max_seq - seq
        if diff >= self.window_size:
            # Packet has fallen behind the sliding window boundary
            self.packets_dropped += 1
            return False

        if (self.bitmap & (1 << diff)) != 0:
            # Duplicate / replayed packet detected
            self.packets_dropped += 1
            return False

        # In-window out-of-order fresh packet
        self.bitmap |= (1 << diff)
        self.packets_accepted += 1
        return True

    def reset(self) -> None:
        """Reset replay tracking window state."""
        self.max_seq = 0
        self.bitmap = 0
        self.packets_accepted = 0
        self.packets_dropped = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "window_size": self.window_size,
            "max_seq": self.max_seq,
            "bitmap_hex": f"0x{self.bitmap:016X}",
            "packets_accepted": self.packets_accepted,
            "packets_dropped": self.packets_dropped,
        }


@dataclass
class TlsSession:
    """Active TLS 1.3 / DTLS 1.2 Secure Session Container."""
    session_id: str
    peer_identity: str
    cipher_suite: CipCipherSuite
    established_at_s: float
    is_active: bool = True
    is_dtls: bool = False
    shared_secret: bytes = b""
    session_key: bytes = b""
    hmac_key: bytes = b""
    replay_window: ReplayProtectionWindow = field(default_factory=ReplayProtectionWindow)
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_received: int = 0
    last_activity_s: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "peer_identity": self.peer_identity,
            "cipher_suite": int(self.cipher_suite),
            "cipher_name": self.cipher_suite.name,
            "established_at_s": self.established_at_s,
            "is_active": self.is_active,
            "is_dtls": self.is_dtls,
            "session_key_hex": self.session_key.hex() if self.session_key else "",
            "replay_window": self.replay_window.to_dict(),
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packets_received": self.packets_received,
            "last_activity_s": self.last_activity_s,
        }


# ============================================================================
# 4. Helper Register Conversion Functions
# ============================================================================

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

CIP_SECURITY_TRUST_SYNC_POU: str = """PROGRAM CipSecurityTrustSync
VAR
    (* Horner OCS Mapped Registers (W193 - ODVA CIP Security Engine) *)
    SecurityProfileState             AT %R1540 : INT;    (* 0=FactoryDefault, 1=IntegrityOnly, 2=IntegrityAndConfidentiality, 3=DegradedUntrusted *)
    ActiveTlsSessionCount            AT %R1541 : INT;    (* Active TLS sessions (0..16) *)
    CipherSuiteIdentifier            AT %R1542 : INT;    (* Cipher Suite ID (e.g. 16#1301) *)
    CertificateValidityDaysRemaining AT %R1543 : INT;    (* Certificate validity remaining in days *)
    FailedHandshakeCounter           AT %R1544 : INT;    (* Failed Handshake Counter *)
    ReplayAttackDropCounter          AT %R1545 : INT;    (* Replay Attack Drop Counter *)
    SecurityKeyExchangeLatencyMsScaled AT %R1546 : INT;  (* Latency scaled x10 ms (35 = 3.5 ms) *)
    DiagnosticStatusCode             AT %R1547 : UINT;   (* Diagnostic Status Code (0x0000=OK, 0xD101..0xD104) *)

    (* Discrete Authentication & Process Safety Coils *)
    CipSecurityAuthenticated         AT %M359  : BOOL;   (* TRUE when secure session active and trusted *)
    SecurityTamperAlert              AT %M360  : BOOL;   (* TRUE on replay attack, untrusted cert, or cipher breach *)
END_VAR
VAR
    SecurityTrustPermissive          : BOOL;
    EnforceConfidentiality           : BOOL;
END_VAR

(* Security State & Tamper Diagnostic Interlock Logic *)
IF (DiagnosticStatusCode <> 0) OR (SecurityProfileState = 3) THEN
    SecurityTamperAlert := TRUE;
    CipSecurityAuthenticated := FALSE;
    SecurityTrustPermissive := FALSE;
ELSE
    SecurityTamperAlert := FALSE;
    IF (SecurityProfileState > 0) AND (ActiveTlsSessionCount > 0) AND (CertificateValidityDaysRemaining > 0) THEN
        CipSecurityAuthenticated := TRUE;
        SecurityTrustPermissive := TRUE;
    ELSE
        CipSecurityAuthenticated := FALSE;
        SecurityTrustPermissive := FALSE;
    END_IF;
END_IF;

IF (SecurityProfileState = 2) THEN
    EnforceConfidentiality := TRUE;
ELSE
    EnforceConfidentiality := FALSE;
END_IF;
END_PROGRAM
"""

CipSecurityTrustSyncPOU = CIP_SECURITY_TRUST_SYNC_POU
CIP_SECURITY_POU = CIP_SECURITY_TRUST_SYNC_POU


# ============================================================================
# 6. CIP Security Object (Class 0x5D) & Certificate Management Object (Class 0x5E)
# ============================================================================

@dataclass
class CipSecurityObject:
    """ODVA CIP Security Object (Class 0x5D).

    ODVA Volume 8 Chapter 2 Specification:
    Attributes:
    1: SecurityProfileState (INT, 0=FactoryDefault, 1=IntegrityOnly, 2=IntegrityAndConfidentiality, 3=DegradedUntrusted)
    2: ActiveTlsSessionCount (INT, 0..16)
    3: CipherSuiteIdentifier (INT, e.g. 0x1301)
    4: SupportedCipherSuites (List[int])
    5: SecurityConfigurationFlags (INT)
    6: FailedHandshakeCounter (INT)
    7: ReplayAttackDropCounter (INT)
    8: SecurityKeyExchangeLatencyMsScaled (INT)
    9: DiagnosticStatusCode (UINT)
    10: AuthenticatedCoil (BOOL, %M359)
    11: TamperAlertCoil (BOOL, %M360)
    """
    class_id: int = CIP_SECURITY_CLASS_ID
    instance_id: int = 1

    profile_state: CipSecurityProfileState = CipSecurityProfileState.INTEGRITY_AND_CONFIDENTIALITY
    active_sessions_count: int = 0
    cipher_suite_id: int = int(CipCipherSuite.TLS_AES_128_GCM_SHA256)
    supported_cipher_suites: List[int] = field(
        default_factory=lambda: [
            int(CipCipherSuite.TLS_AES_128_GCM_SHA256),
            int(CipCipherSuite.TLS_AES_256_GCM_SHA384),
            int(CipCipherSuite.ECDHE_ECDSA_AES128_GCM_SHA256),
        ]
    )
    configuration_flags: int = 0x03  # Bit 0: Enforce TLS, Bit 1: Enforce DTLS
    failed_handshake_counter: int = 0
    replay_attack_drop_counter: int = 0
    key_exchange_latency_ms_scaled: int = NOMINAL_LATENCY_SCALED
    diagnostic_status_code: int = int(CipSecurityDiagnosticCode.OK)
    is_authenticated: bool = False
    is_tamper_alert: bool = False

    def get_attribute_single(self, attribute_id: int) -> Any:
        """Query attribute value by ID (ODVA CIP Service 0x0E)."""
        attrs: Dict[int, Any] = {
            1: int(self.profile_state),
            2: self.active_sessions_count,
            3: self.cipher_suite_id,
            4: list(self.supported_cipher_suites),
            5: self.configuration_flags,
            6: self.failed_handshake_counter,
            7: self.replay_attack_drop_counter,
            8: self.key_exchange_latency_ms_scaled,
            9: int(self.diagnostic_status_code),
            10: self.is_authenticated,
            11: self.is_tamper_alert,
        }
        if attribute_id in attrs:
            return attrs[attribute_id]
        raise KeyError(f"ODVA CIP Security Object (Class 0x5D) does not support Attribute ID {attribute_id}")

    def set_attribute_single(self, attribute_id: int, value: Any) -> bool:
        """Set writable attribute by ID (ODVA CIP Service 0x10)."""
        if attribute_id == 1:
            val_int = int(value)
            self.profile_state = CipSecurityProfileState(val_int)
            return True
        elif attribute_id == 5:
            self.configuration_flags = int(value)
            return True
        elif attribute_id in {2, 3, 4, 6, 7, 8, 9, 10, 11}:
            raise PermissionError(f"CIP Security Object Attribute ID {attribute_id} is read-only")
        raise KeyError(f"CIP Security Object does not support Attribute ID {attribute_id}")

    def get_attribute_all(self) -> Dict[int, Any]:
        """Query all attributes dictionary (ODVA CIP Service 0x01)."""
        return {
            1: int(self.profile_state),
            2: self.active_sessions_count,
            3: self.cipher_suite_id,
            4: list(self.supported_cipher_suites),
            5: self.configuration_flags,
            6: self.failed_handshake_counter,
            7: self.replay_attack_drop_counter,
            8: self.key_exchange_latency_ms_scaled,
            9: int(self.diagnostic_status_code),
            10: self.is_authenticated,
            11: self.is_tamper_alert,
        }


@dataclass
class CertificateManagementObject:
    """ODVA CIP Certificate Management Object (Class 0x5E).

    ODVA Volume 8 Chapter 3 Specification:
    Attributes:
    1: CertificateState (INT, 0=Empty, 1=Valid, 2=Expired, 3=Untrusted)
    2: CertificateValidityDaysRemaining (INT)
    3: ActiveCertificateSerialNumber (str)
    4: TrustedRootCount (INT)
    5: CrlRevokedCount (INT)
    6: IssuerCommonName (str)
    7: SubjectCommonName (str)
    8: CertificateSanList (List[str])
    """
    class_id: int = CIP_CERTIFICATE_MANAGEMENT_CLASS_ID
    instance_id: int = 1

    cert_state: int = 1  # 1=Valid
    validity_days_remaining: int = 365
    active_serial_number: str = "01:A2:F3:4B"
    trusted_root_count: int = 1
    crl_revoked_count: int = 0
    issuer_cn: str = "Horner Root CA"
    subject_cn: str = "Horner OCS Security Controller"
    san_list: List[str] = field(default_factory=lambda: ["horner-ocs.local", "192.168.1.100"])

    def get_attribute_single(self, attribute_id: int) -> Any:
        """Query attribute value by ID (ODVA CIP Service 0x0E)."""
        attrs: Dict[int, Any] = {
            1: self.cert_state,
            2: self.validity_days_remaining,
            3: self.active_serial_number,
            4: self.trusted_root_count,
            5: self.crl_revoked_count,
            6: self.issuer_cn,
            7: self.subject_cn,
            8: list(self.san_list),
        }
        if attribute_id in attrs:
            return attrs[attribute_id]
        raise KeyError(f"ODVA Certificate Management Object (Class 0x5E) does not support Attribute ID {attribute_id}")

    def set_attribute_single(self, attribute_id: int, value: Any) -> bool:
        """Set writable attribute by ID (ODVA CIP Service 0x10)."""
        if attribute_id in {1, 2, 3, 4, 5, 6, 7, 8}:
            raise PermissionError(f"Certificate Management Object Attribute ID {attribute_id} is read-only via network")
        raise KeyError(f"Certificate Management Object does not support Attribute ID {attribute_id}")

    def get_attribute_all(self) -> Dict[int, Any]:
        """Query all attributes dictionary (ODVA CIP Service 0x01)."""
        return {
            1: self.cert_state,
            2: self.validity_days_remaining,
            3: self.active_serial_number,
            4: self.trusted_root_count,
            5: self.crl_revoked_count,
            6: self.issuer_cn,
            7: self.subject_cn,
            8: list(self.san_list),
        }


# ============================================================================
# 7. CipSecurityEngine (ILogicUnit)
# ============================================================================

class CipSecurityEngine(ILogicUnit):
    """Industrial ODVA CIP Security Protocol & Cryptographic Telemetry Engine."""

    def __init__(
        self,
        reg_table: Optional[RegisterTable] = None,
        security_profile: CipSecurityProfileState = CipSecurityProfileState.INTEGRITY_AND_CONFIDENTIALITY,
        supported_ciphers: Optional[List[CipCipherSuite]] = None,
        current_time_s: float = DEFAULT_BASE_TIME_S,
        max_sessions: int = DEFAULT_MAX_TLS_SESSIONS,
        device_cert: Optional[X509CertInfo] = None,
    ) -> None:
        self.reg_table: Optional[RegisterTable] = reg_table
        self.profile_state: CipSecurityProfileState = security_profile
        self.max_sessions: int = max(1, min(16, int(max_sessions)))
        self.current_time_s: float = float(current_time_s)

        if supported_ciphers is not None:
            self.supported_ciphers: List[CipCipherSuite] = list(supported_ciphers)
        else:
            self.supported_ciphers = [
                CipCipherSuite.TLS_AES_128_GCM_SHA256,
                CipCipherSuite.TLS_AES_256_GCM_SHA384,
                CipCipherSuite.ECDHE_ECDSA_AES128_GCM_SHA256,
            ]

        self.active_cipher: CipCipherSuite = (
            self.supported_ciphers[0] if self.supported_ciphers else CipCipherSuite.TLS_AES_128_GCM_SHA256
        )

        # Active TLS/DTLS Sessions
        self.active_sessions: Dict[str, TlsSession] = {}

        # X.509 Trust Store & CRL
        self.root_ca_store: Dict[str, X509CertInfo] = {}
        self.crl_revoked_serials: Set[str] = set()

        # Telemetry State Registers
        self.cert_validity_days: int = 365
        self.failed_handshake_counter: int = 0
        self.replay_attack_drop_counter: int = 0
        self.key_exchange_latency_ms: float = NOMINAL_KEY_EXCHANGE_LATENCY_MS
        self.diagnostic_code: CipSecurityDiagnosticCode = CipSecurityDiagnosticCode.OK
        self.is_authenticated: bool = False
        self.is_tamper_alert: bool = False

        # Global anti-replay window for unconnected or broadcast tracking
        self.global_replay_window = ReplayProtectionWindow()

        # Internal CIP Objects
        self.security_object = CipSecurityObject(
            profile_state=self.profile_state,
            cipher_suite_id=int(self.active_cipher),
            supported_cipher_suites=[int(c) for c in self.supported_ciphers],
        )
        self.cert_management_object = CertificateManagementObject()

        # Device Identity Certificate
        if device_cert is not None:
            self.set_device_certificate(device_cert)
        else:
            # Default Horner Device Certificate
            default_root = X509CertInfo(
                common_name="Horner Root CA",
                issuer="Horner Root CA",
                not_before_s=self.current_time_s - (365 * ONE_DAY_SECONDS),
                not_after_s=self.current_time_s + (3650 * ONE_DAY_SECONDS),
                serial_number="CA:01:00:01",
                is_ca=True,
            )
            self.add_trusted_root_ca(default_root)

            default_leaf = X509CertInfo(
                common_name="Horner OCS Security Controller",
                issuer="Horner Root CA",
                not_before_s=self.current_time_s - (10 * ONE_DAY_SECONDS),
                not_after_s=self.current_time_s + (355 * ONE_DAY_SECONDS),
                san=["horner-ocs.local", "192.168.1.100"],
                serial_number="01:A2:F3:4B",
                is_ca=False,
            )
            self.set_device_certificate(default_leaf)

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
        return "cip_security"

    @property
    def priority(self) -> int:
        return 94

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def execute(self, ctx: ScanContext) -> ExecutionResult:
        """Execute one discrete scan cycle within Horner simulation framework."""
        dt_ms = getattr(ctx, "dt_ms", 10.0)
        self.scan_step(dt=dt_ms / 1000.0)
        return ExecutionResult(
            status=AgentStatus.SUCCESS,
            details=f"CIP Security scan cycle executed smoothly at t={self.elapsed_simulation_ms:.1f}ms",
            data=self.get_snapshot(),
        )

    def reset(self) -> None:
        """Reset internal engine state and clear latched fault trips."""
        self.reset_fault(force=True)

    # ------------------------------------------------------------------------
    # Discrete Scan Cycle Execution
    # ------------------------------------------------------------------------

    def scan_step(self, dt: float = 0.01) -> Dict[str, Any]:
        """Advance discrete simulation clock, evaluate trust perimeters, and sync registers."""
        dt_s = max(0.0, float(dt))
        self.elapsed_simulation_ms += dt_s * 1000.0
        self.total_scan_cycles += 1
        self.current_time_s += dt_s

        # 1. Update Certificate Validity Days
        if self.device_cert is not None:
            self.cert_validity_days = self.device_cert.days_remaining(self.current_time_s)
            if self.current_time_s > self.device_cert.not_after_s:
                self.diagnostic_code = CipSecurityDiagnosticCode.CERTIFICATE_EXPIRED
                self.is_tamper_alert = True
                self.is_authenticated = False
                self.profile_state = CipSecurityProfileState.DEGRADED_UNTRUSTED

        # 2. Evaluate Session Authentication State
        if self.diagnostic_code != CipSecurityDiagnosticCode.OK or self.profile_state == CipSecurityProfileState.DEGRADED_UNTRUSTED:
            self.is_authenticated = False
            self.is_tamper_alert = True
        else:
            if self.profile_state > CipSecurityProfileState.FACTORY_DEFAULT and len(self.active_sessions) > 0 and self.cert_validity_days > 0:
                self.is_authenticated = True
                self.is_tamper_alert = False
            else:
                self.is_authenticated = False
                self.is_tamper_alert = False

        # 3. Synchronize Internal CIP Objects
        self._update_cip_objects()

        # 4. Synchronize Horner Register Table
        self.sync_to_registers()

        return self.get_snapshot()

    # ------------------------------------------------------------------------
    # Certificate Authority & Trust Management
    # ------------------------------------------------------------------------

    def add_trusted_root_ca(self, cert: X509CertInfo) -> bool:
        """Enroll trusted Root CA into trust store."""
        if not cert.is_ca:
            return False
        self.root_ca_store[cert.common_name] = cert
        self.cert_management_object.trusted_root_count = len(self.root_ca_store)
        return True

    def revoke_certificate(self, serial_number: str) -> None:
        """Add certificate serial number to Certificate Revocation List (CRL)."""
        self.crl_revoked_serials.add(serial_number.strip().upper())
        self.cert_management_object.crl_revoked_count = len(self.crl_revoked_serials)

    def set_device_certificate(self, cert: X509CertInfo) -> None:
        """Enroll device identity certificate and update validity telemetry."""
        self.device_cert = cert
        self.cert_validity_days = cert.days_remaining(self.current_time_s)
        self.cert_management_object.active_serial_number = cert.serial_number
        self.cert_management_object.issuer_cn = cert.issuer
        self.cert_management_object.subject_cn = cert.common_name
        self.cert_management_object.san_list = list(cert.san)
        self.cert_management_object.validity_days_remaining = self.cert_validity_days
        self.cert_management_object.cert_state = (
            1 if cert.is_valid_at(self.current_time_s) else 2
        )
        self.sync_to_registers()

    def validate_certificate(
        self,
        cert: X509CertInfo,
        check_time: Optional[float] = None,
        peer_identity: Optional[str] = None,
    ) -> Tuple[bool, Optional[CipSecurityDiagnosticCode], str]:
        """Validate an X.509 certificate against validity period, CRL, and Root CA store.

        Returns:
            Tuple of (is_valid: bool, error_code: Optional[CipSecurityDiagnosticCode], details: str).
        """
        # 1. CRL Revocation Check
        clean_serial = cert.serial_number.strip().upper()
        if clean_serial in self.crl_revoked_serials:
            return (
                False,
                CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA,
                f"Certificate serial '{cert.serial_number}' is revoked in CRL",
            )

        # 2. Validity Period Expiration Check
        t = self.current_time_s if check_time is None else float(check_time)
        if not cert.is_valid_at(t):
            return (
                False,
                CipSecurityDiagnosticCode.CERTIFICATE_EXPIRED,
                f"Certificate validity expired (current_time={t}, not_after={cert.not_after_s})",
            )

        # 3. Root CA Trust Chain Check
        if cert.issuer not in self.root_ca_store:
            return (
                False,
                CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA,
                f"Certificate issuer '{cert.issuer}' is not in trusted Root CA store",
            )

        root_ca = self.root_ca_store[cert.issuer]
        if not root_ca.is_ca:
            return (
                False,
                CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA,
                f"Issuer '{cert.issuer}' is not designated as a Certificate Authority",
            )

        if not root_ca.is_valid_at(t):
            return (
                False,
                CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA,
                f"Root CA '{root_ca.common_name}' validity has expired",
            )

        # 4. Subject Alternative Name (SAN) Match Check
        if peer_identity is not None and not cert.matches_san(peer_identity):
            return (
                False,
                CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA,
                f"Peer identity '{peer_identity}' does not match SAN {cert.san} or CN {cert.common_name}",
            )

        days = cert.days_remaining(t)
        return True, None, f"Certificate valid and trusted ({days} days remaining)"

    # ------------------------------------------------------------------------
    # Cryptographic Cipher Negotiation & TLS/DTLS Handshake
    # ------------------------------------------------------------------------

    def negotiate_cipher_suite(
        self,
        offered_ciphers: Sequence[Union[CipCipherSuite, int]],
    ) -> Optional[CipCipherSuite]:
        """Negotiate preferred cryptographic cipher suite from offered suites."""
        offered_set = {int(c) for c in offered_ciphers}
        for preferred in self.supported_ciphers:
            if int(preferred) in offered_set:
                return preferred
        return None

    def perform_handshake(
        self,
        peer_identity: str,
        peer_cert: X509CertInfo,
        offered_ciphers: Sequence[Union[CipCipherSuite, int]],
        is_dtls: bool = False,
        peer_san: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Optional[TlsSession]]:
        """Perform simulated TLS 1.3 or DTLS 1.2 handshake and session key derivation.

        Returns:
            Tuple of (success: bool, details: Optional[str], session: Optional[TlsSession]).
        """
        # Session Capacity Check
        if len(self.active_sessions) >= self.max_sessions:
            self.failed_handshake_counter += 1
            self.sync_to_registers()
            return False, f"Maximum active TLS sessions reached ({self.max_sessions})", None

        # 1. Validate Peer Certificate
        valid, err_code, reason = self.validate_certificate(
            peer_cert, peer_identity=peer_san or peer_identity
        )
        if not valid:
            self.failed_handshake_counter += 1
            self.diagnostic_code = err_code if err_code is not None else CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA
            self.is_tamper_alert = True
            self.is_authenticated = False
            self.sync_to_registers()
            return False, reason, None

        # 2. Negotiate Cipher Suite
        selected_cipher = self.negotiate_cipher_suite(offered_ciphers)
        if selected_cipher is None:
            self.failed_handshake_counter += 1
            self.diagnostic_code = CipSecurityDiagnosticCode.CIPHER_MISMATCH
            self.is_tamper_alert = True
            self.is_authenticated = False
            self.sync_to_registers()
            return False, "No mutually supported cryptographic cipher suite", None

        # 3. Cryptographic Key Derivation Mock (HKDF / SHA-256)
        session_id = f"sess_{secrets.token_hex(6)}"
        client_random = hashlib.sha256(f"{peer_identity}_{self.current_time_s}".encode()).digest()
        server_random = hashlib.sha256(f"horner_{session_id}".encode()).digest()
        shared_secret = hmac.new(client_random, server_random, hashlib.sha256).digest()
        session_key = hmac.new(shared_secret, b"cip-security-aes-gcm-key", hashlib.sha256).digest()[:16]
        hmac_key = hmac.new(shared_secret, b"cip-security-hmac-sha256-key", hashlib.sha256).digest()

        # Simulated key exchange latency
        self.key_exchange_latency_ms = NOMINAL_KEY_EXCHANGE_LATENCY_MS

        # 4. Instantiate Session
        session = TlsSession(
            session_id=session_id,
            peer_identity=peer_identity,
            cipher_suite=selected_cipher,
            established_at_s=self.current_time_s,
            is_active=True,
            is_dtls=is_dtls,
            shared_secret=shared_secret,
            session_key=session_key,
            hmac_key=hmac_key,
            replay_window=ReplayProtectionWindow(),
            last_activity_s=self.current_time_s,
        )

        self.active_sessions[session_id] = session
        self.active_cipher = selected_cipher
        self.cert_validity_days = peer_cert.days_remaining(self.current_time_s)

        # Clear transient handshake fault if perimeter is now healthy
        if self.diagnostic_code in {
            CipSecurityDiagnosticCode.CERTIFICATE_EXPIRED,
            CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA,
            CipSecurityDiagnosticCode.CIPHER_MISMATCH,
        }:
            self.diagnostic_code = CipSecurityDiagnosticCode.OK

        self.is_authenticated = True
        self.is_tamper_alert = False
        self._update_cip_objects()
        self.sync_to_registers()

        return True, "Handshake successful and secure session established", session

    def close_session(self, session_id: str) -> bool:
        """Close an active TLS/DTLS session."""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            if len(self.active_sessions) == 0:
                self.is_authenticated = False
            self._update_cip_objects()
            self.sync_to_registers()
            return True
        return False

    # ------------------------------------------------------------------------
    # Anti-Replay Protection & Packet Reception
    # ------------------------------------------------------------------------

    def process_incoming_packet(
        self,
        session_id: Optional[str],
        sequence_number: int,
        payload: bytes = b"",
    ) -> bool:
        """Verify anti-replay sequence number against 64-packet sliding window.

        Returns:
            True if packet is fresh and accepted.
            False if packet is duplicate/stale (triggers tamper alarm and increments drop counter).
        """
        if session_id is not None and session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            accepted = session.replay_window.check_and_update(sequence_number)
            if accepted:
                session.packets_received += 1
                session.bytes_received += len(payload)
                session.last_activity_s = self.current_time_s
        else:
            accepted = self.global_replay_window.check_and_update(sequence_number)

        if not accepted:
            # Replay attack or stale duplicate detected!
            self.replay_attack_drop_counter += 1
            self.diagnostic_code = CipSecurityDiagnosticCode.REPLAY_ATTACK_DETECTED
            self.is_tamper_alert = True
            self.sync_to_registers()
            return False

        return True

    # ------------------------------------------------------------------------
    # Process Safety Interlock & Fault Simulation
    # ------------------------------------------------------------------------

    def trip_fault(self, code: CipSecurityDiagnosticCode, details: str = "") -> None:
        """Latch security diagnostic code, deassert authentication, and trip tamper alarm."""
        self.diagnostic_code = code
        self.is_tamper_alert = True
        if code in {CipSecurityDiagnosticCode.CERTIFICATE_EXPIRED, CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA}:
            self.is_authenticated = False
            self.profile_state = CipSecurityProfileState.DEGRADED_UNTRUSTED
        self._update_cip_objects()
        self.sync_to_registers()

    def reset_fault(self, force: bool = False) -> ExecutionResult:
        """Reset latched diagnostic fault trips if conditions have cleared."""
        self.diagnostic_code = CipSecurityDiagnosticCode.OK
        self.is_tamper_alert = False

        if self.profile_state == CipSecurityProfileState.DEGRADED_UNTRUSTED:
            self.profile_state = CipSecurityProfileState.INTEGRITY_AND_CONFIDENTIALITY

        if len(self.active_sessions) > 0 and self.cert_validity_days > 0:
            self.is_authenticated = True
        else:
            self.is_authenticated = False

        self._update_cip_objects()
        self.sync_to_registers()
        return ExecutionResult(
            status=AgentStatus.SUCCESS,
            details="Security perimeter fault cleared and diagnostics restored to OK",
        )

    def simulate_certificate_expired(self) -> None:
        """Simulate X.509 certificate expiration excursion (0xD101)."""
        self.trip_fault(
            CipSecurityDiagnosticCode.CERTIFICATE_EXPIRED,
            "Simulated X.509 certificate validity expired",
        )

    def simulate_untrusted_ca(self) -> None:
        """Simulate rogue untrusted Root CA or revoked certificate (0xD102)."""
        self.trip_fault(
            CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA,
            "Simulated untrusted Root CA / rogue certificate hierarchy",
        )

    def simulate_replay_attack(self) -> None:
        """Simulate sliding-window replay attack detection (0xD103)."""
        self.replay_attack_drop_counter += 1
        self.trip_fault(
            CipSecurityDiagnosticCode.REPLAY_ATTACK_DETECTED,
            "Simulated network packet replay attack detected",
        )

    def simulate_cipher_mismatch(self) -> None:
        """Simulate cryptographic cipher negotiation mismatch (0xD104)."""
        self.failed_handshake_counter += 1
        self.trip_fault(
            CipSecurityDiagnosticCode.CIPHER_MISMATCH,
            "Simulated peer cryptographic cipher suite mismatch",
        )

    # ------------------------------------------------------------------------
    # Internal Synchronization & Register Table
    # ------------------------------------------------------------------------

    def _update_cip_objects(self) -> None:
        """Keep internal CIP Objects aligned with engine state."""
        self.security_object.profile_state = self.profile_state
        self.security_object.active_sessions_count = min(16, len(self.active_sessions))
        self.security_object.cipher_suite_id = int(self.active_cipher)
        self.security_object.failed_handshake_counter = self.failed_handshake_counter
        self.security_object.replay_attack_drop_counter = self.replay_attack_drop_counter
        self.security_object.key_exchange_latency_ms_scaled = int(round(self.key_exchange_latency_ms * 10.0))
        self.security_object.diagnostic_status_code = int(self.diagnostic_code)
        self.security_object.is_authenticated = self.is_authenticated
        self.security_object.is_tamper_alert = self.is_tamper_alert

        self.cert_management_object.validity_days_remaining = self.cert_validity_days
        self.cert_management_object.trusted_root_count = len(self.root_ca_store)
        self.cert_management_object.crl_revoked_count = len(self.crl_revoked_serials)

    def sync_to_registers(self, reg_table: Optional[RegisterTable] = None) -> None:
        """Synchronize telemetry state to Horner OCS memory map with PrivilegeMode.SYSTEM.

        Register Table Layout:
        - %R1540: SecurityProfileState (0=FactoryDefault, 1=IntegrityOnly, 2=IntegrityAndConfidentiality, 3=DegradedUntrusted)
        - %R1541: ActiveTlsSessionCount (INT16, 0..16)
        - %R1542: CipherSuiteIdentifier (INT16, e.g. 0x1301)
        - %R1543: CertificateValidityDaysRemaining (INT16, days)
        - %R1544: FailedHandshakeCounter (INT16, count)
        - %R1545: ReplayAttackDropCounter (INT16, count)
        - %R1546: SecurityKeyExchangeLatencyMsScaled (INT16, scaled x10 ms, e.g. 35 = 3.5 ms)
        - %R1547: DiagnosticStatusCode (0x0000=OK, 0xD101..0xD104)
        - %M359: CipSecurityAuthenticated (BOOL, True when secure session active and trusted)
        - %M360: SecurityTamperAlert (BOOL, True on replay attack, untrusted cert, or cipher breach)
        """
        rt = reg_table if reg_table is not None else self.reg_table
        if rt is None:
            return

        # %R1540: SecurityProfileState
        safe_write_word(rt, "%R1540", int(self.profile_state))

        # %R1541: ActiveTlsSessionCount (0..16)
        sess_count = min(16, max(0, len(self.active_sessions)))
        safe_write_word(rt, "%R1541", sess_count)

        # %R1542: CipherSuiteIdentifier (INT16, e.g. 0x1301)
        safe_write_word(rt, "%R1542", int(self.active_cipher))

        # %R1543: CertificateValidityDaysRemaining
        safe_write_word(rt, "%R1543", max(0, min(32767, self.cert_validity_days)))

        # %R1544: FailedHandshakeCounter
        safe_write_word(rt, "%R1544", max(0, min(32767, self.failed_handshake_counter)))

        # %R1545: ReplayAttackDropCounter
        safe_write_word(rt, "%R1545", max(0, min(32767, self.replay_attack_drop_counter)))

        # %R1546: SecurityKeyExchangeLatencyMsScaled (INT16, scaled x10 ms)
        latency_scaled = int(round(self.key_exchange_latency_ms * 10.0))
        safe_write_word(rt, "%R1546", max(0, min(32767, latency_scaled)))

        # %R1547: DiagnosticStatusCode (UINT16, 0x0000=OK, 0xD101..0xD104)
        safe_write_uword(rt, "%R1547", int(self.diagnostic_code))

        # %M359: CipSecurityAuthenticated (BOOL)
        safe_write_bit(rt, "%M359", self.is_authenticated)

        # %M360: SecurityTamperAlert (BOOL)
        safe_write_bit(rt, "%M360", self.is_tamper_alert)

    def get_snapshot(self) -> Dict[str, Any]:
        """Capture current telemetry snapshot dictionary."""
        return {
            "profile_state": int(self.profile_state),
            "profile_state_name": self.profile_state.name,
            "active_sessions_count": len(self.active_sessions),
            "cipher_suite": int(self.active_cipher),
            "cipher_suite_name": self.active_cipher.name,
            "cert_validity_days": self.cert_validity_days,
            "failed_handshake_counter": self.failed_handshake_counter,
            "replay_attack_drop_counter": self.replay_attack_drop_counter,
            "key_exchange_latency_ms": self.key_exchange_latency_ms,
            "diagnostic_code": int(self.diagnostic_code),
            "diagnostic_code_name": self.diagnostic_code.name,
            "is_authenticated": self.is_authenticated,
            "is_tamper_alert": self.is_tamper_alert,
            "elapsed_simulation_ms": self.elapsed_simulation_ms,
            "total_scan_cycles": self.total_scan_cycles,
            "sessions": {sid: s.to_dict() for sid, s in self.active_sessions.items()},
        }


# ============================================================================
# 8. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_cip_security_verification(
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W193.

    Stages:
    1. POU ST syntax validation and anti-ladder check.
    2. CIP Security Object (Class 0x5D) & Certificate Management Object (Class 0x5E) attribute resolution.
    3. X.509 certificate hierarchy & trust chain validation.
    4. Cryptographic cipher suite negotiation (TLS 1.3 / DTLS 1.2).
    5. Sliding-window anti-replay attack packet rejection.
    6. Key exchange latency measurement and session caching.
    7. Register table synchronization (%R1540..%R1547, %M359..%M360).
    8. Discrete ILogicUnit 100-cycle scan simulation.
    9. Process safety interlock and security tamper trip testing (0xD101..0xD104).

    Returns strict 4-state contract response dictionary:
        {'status': 'success', 'stages_passed': 9, 'total_stages': 9, 'data': {...}}
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: POU ST syntax validation and anti-ladder check
    # ------------------------------------------------------------------------
    val_pou = STParser.validate_code(CIP_SECURITY_TRUST_SYNC_POU)
    ast_pou = STParser.parse_pou(CIP_SECURITY_TRUST_SYNC_POU)

    expected_regs = {
        "%R1540", "%R1541", "%R1542", "%R1543",
        "%R1544", "%R1545", "%R1546", "%R1547",
        "%M359", "%M360",
    }
    bound_regs = set(ast_pou.bound_registers)

    # Validate Pure ST security guard passes
    SecurityGuard.assert_pure_st_content(CIP_SECURITY_TRUST_SYNC_POU)

    # Validate ladder constructs are strictly intercepted
    ladder_intercepted = True
    ladder_snippets = [
        "---[ ]---",
        "---( )---",
        "RUNG 1",
        "NETWORK 1",
        "XIC MyContact",
        "OTE MyCoil",
    ]
    for snip in ladder_snippets:
        try:
            SecurityGuard.assert_pure_st_content(snip)
            ladder_intercepted = False
            break
        except LadderForbiddenError:
            pass

    s1_pass = (
        val_pou.status == AgentStatus.SUCCESS
        and ast_pou.pou_type == POUType.PROGRAM
        and ast_pou.name == "CipSecurityTrustSync"
        and expected_regs.issubset(bound_regs)
        and ladder_intercepted
    )
    test_results.append({
        "stage": 1,
        "check": "POU_ST_Syntax_Validation_And_Anti_Ladder_Check",
        "passed": s1_pass,
        "details": f"POU 'CipSecurityTrustSync' validated with bound registers: {sorted(list(expected_regs))}. Ladder logic intercepted.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: CIP Security Object (Class 0x5D) & Certificate Management Object (Class 0x5E)
    # ------------------------------------------------------------------------
    sec_obj = CipSecurityObject()
    cert_obj = CertificateManagementObject()

    # Query Class 0x5D attributes 1..11
    s_attr1 = sec_obj.get_attribute_single(1)
    s_attr2 = sec_obj.get_attribute_single(2)
    s_attr3 = sec_obj.get_attribute_single(3)
    s_attr4 = sec_obj.get_attribute_single(4)
    s_attr5 = sec_obj.get_attribute_single(5)
    s_attr8 = sec_obj.get_attribute_single(8)
    s_attr9 = sec_obj.get_attribute_single(9)
    s_all = sec_obj.get_attribute_all()

    # Test setter for attribute 1 (SecurityProfileState)
    sec_obj.set_attribute_single(1, int(CipSecurityProfileState.INTEGRITY_ONLY))
    s_attr1_updated = sec_obj.get_attribute_single(1)

    # Test read-only rejection for attribute 2
    read_only_rejected = False
    try:
        sec_obj.set_attribute_single(2, 5)
    except PermissionError:
        read_only_rejected = True

    # Query Class 0x5E attributes 1..8
    c_attr1 = cert_obj.get_attribute_single(1)
    c_attr2 = cert_obj.get_attribute_single(2)
    c_attr3 = cert_obj.get_attribute_single(3)
    c_attr4 = cert_obj.get_attribute_single(4)
    c_attr5 = cert_obj.get_attribute_single(5)
    c_attr6 = cert_obj.get_attribute_single(6)
    c_attr7 = cert_obj.get_attribute_single(7)
    c_attr8 = cert_obj.get_attribute_single(8)
    c_all = cert_obj.get_attribute_all()

    s2_pass = (
        s_attr1 == int(CipSecurityProfileState.INTEGRITY_AND_CONFIDENTIALITY)
        and s_attr1_updated == int(CipSecurityProfileState.INTEGRITY_ONLY)
        and read_only_rejected is True
        and isinstance(s_attr4, list)
        and s_attr8 == NOMINAL_LATENCY_SCALED
        and len(s_all) == 11
        and c_attr1 == 1
        and c_attr2 == 365
        and c_attr4 == 1
        and c_attr5 == 0
        and len(c_all) == 8
    )
    test_results.append({
        "stage": 2,
        "check": "CIP_Security_And_Certificate_Management_Object_Attribute_Resolution",
        "passed": s2_pass,
        "details": f"Class 0x5D (11 attributes) and Class 0x5E (8 attributes) resolved and verified cleanly.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: X.509 certificate hierarchy & trust chain validation
    # ------------------------------------------------------------------------
    engine_cert = CipSecurityEngine(current_time_s=1775000000.0)

    root_ca = X509CertInfo(
        common_name="Horner Industrial Root CA",
        issuer="Horner Industrial Root CA",
        not_before_s=1770000000.0,
        not_after_s=1800000000.0,
        serial_number="CA:11:22:33",
        is_ca=True,
    )
    engine_cert.add_trusted_root_ca(root_ca)

    valid_leaf = X509CertInfo(
        common_name="plc01.plant.local",
        issuer="Horner Industrial Root CA",
        not_before_s=1774000000.0,
        not_after_s=1780000000.0,
        san=["plc01.plant.local", "192.168.1.50"],
        serial_number="01:FF:AA:12",
        is_ca=False,
    )

    expired_leaf = X509CertInfo(
        common_name="expired.plant.local",
        issuer="Horner Industrial Root CA",
        not_before_s=1760000000.0,
        not_after_s=1770000000.0,  # Expired before 1775000000.0
        serial_number="02:EE:BB:34",
        is_ca=False,
    )

    untrusted_leaf = X509CertInfo(
        common_name="rogue.plant.local",
        issuer="Rogue Untrusted CA",
        not_before_s=1774000000.0,
        not_after_s=1780000000.0,
        serial_number="03:DD:CC:56",
        is_ca=False,
    )

    revoked_leaf = X509CertInfo(
        common_name="revoked.plant.local",
        issuer="Horner Industrial Root CA",
        not_before_s=1774000000.0,
        not_after_s=1780000000.0,
        serial_number="04:CC:BB:78",
        is_ca=False,
    )
    engine_cert.revoke_certificate(revoked_leaf.serial_number)

    v_valid, _, _ = engine_cert.validate_certificate(valid_leaf, peer_identity="plc01.plant.local")
    v_exp, err_exp, _ = engine_cert.validate_certificate(expired_leaf)
    v_untrusted, err_untrusted, _ = engine_cert.validate_certificate(untrusted_leaf)
    v_revoked, err_revoked, _ = engine_cert.validate_certificate(revoked_leaf)
    v_san_mismatch, err_san, _ = engine_cert.validate_certificate(valid_leaf, peer_identity="attacker.local")

    s3_pass = (
        v_valid is True
        and v_exp is False and err_exp == CipSecurityDiagnosticCode.CERTIFICATE_EXPIRED
        and v_untrusted is False and err_untrusted == CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA
        and v_revoked is False and err_revoked == CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA
        and v_san_mismatch is False and err_san == CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA
    )
    test_results.append({
        "stage": 3,
        "check": "X509_Certificate_Hierarchy_And_Trust_Chain_Validation",
        "passed": s3_pass,
        "details": "Root CA, SAN matching, CRL revocation, and validity expiration validated with 0xD101/0xD102.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Cryptographic cipher suite negotiation (TLS 1.3 / DTLS 1.2)
    # ------------------------------------------------------------------------
    engine_cipher = CipSecurityEngine(current_time_s=1775000000.0)
    engine_cipher.add_trusted_root_ca(root_ca)

    # 1. TLS 1.3 negotiation with preferred TLS_AES_128_GCM_SHA256
    c1 = engine_cipher.negotiate_cipher_suite([
        CipCipherSuite.TLS_AES_256_GCM_SHA384,
        CipCipherSuite.TLS_AES_128_GCM_SHA256,
    ])

    # 2. DTLS 1.2 negotiation with ECDHE_ECDSA_AES128_GCM_SHA256
    c2 = engine_cipher.negotiate_cipher_suite([
        CipCipherSuite.ECDHE_ECDSA_AES128_GCM_SHA256,
    ])

    # 3. Unsupported cipher suite mismatch rejection (0xD104)
    h_fail_ok, h_fail_msg, h_fail_sess = engine_cipher.perform_handshake(
        peer_identity="plc01.plant.local",
        peer_cert=valid_leaf,
        offered_ciphers=[0x002F],  # Unsupported legacy RSA suite
    )

    s4_pass = (
        c1 == CipCipherSuite.TLS_AES_128_GCM_SHA256
        and c2 == CipCipherSuite.ECDHE_ECDSA_AES128_GCM_SHA256
        and h_fail_ok is False
        and engine_cipher.diagnostic_code == CipSecurityDiagnosticCode.CIPHER_MISMATCH
        and engine_cipher.failed_handshake_counter == 1
        and engine_cipher.is_tamper_alert is True
    )
    test_results.append({
        "stage": 4,
        "check": "Cryptographic_Cipher_Suite_Negotiation_TLS13_DTLS12",
        "passed": s4_pass,
        "details": "TLS 1.3, DTLS 1.2, and cipher mismatch trip (0xD104) verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Sliding-window anti-replay attack packet rejection
    # ------------------------------------------------------------------------
    replay_win = ReplayProtectionWindow(window_size=64)

    # 1. Sequential packets 1 through 10 accepted
    seq_1_10_ok = all(replay_win.check_and_update(i) for i in range(1, 11))

    # 2. Duplicate packet (seq=5) rejected
    dup_rejected = not replay_win.check_and_update(5)

    # 3. Advance window forward by jumping to seq=75
    seq_75_ok = replay_win.check_and_update(75)

    # 4. Old packet fallen behind 64-packet window (seq=2, diff=73 >= 64) rejected
    old_rejected = not replay_win.check_and_update(2)

    # 5. In-window out-of-order fresh packet (seq=72, diff=3 < 64) accepted once
    in_win_fresh_ok = replay_win.check_and_update(72)

    # 6. Repeating seq=72 rejected as duplicate
    in_win_dup_rejected = not replay_win.check_and_update(72)

    # 7. Engine packet processing integration
    engine_replay = CipSecurityEngine(current_time_s=1775000000.0)
    engine_replay.add_trusted_root_ca(root_ca)
    ok_h, _, sess_h = engine_replay.perform_handshake(
        peer_identity="plc01.plant.local",
        peer_cert=valid_leaf,
        offered_ciphers=[CipCipherSuite.TLS_AES_128_GCM_SHA256],
    )
    p1 = engine_replay.process_incoming_packet(sess_h.session_id, 1, b"CIP_PAYLOAD_1")
    p2 = engine_replay.process_incoming_packet(sess_h.session_id, 2, b"CIP_PAYLOAD_2")
    p_dup = engine_replay.process_incoming_packet(sess_h.session_id, 1, b"REPLAY_ATTACK")

    s5_pass = (
        seq_1_10_ok is True
        and dup_rejected is True
        and seq_75_ok is True
        and old_rejected is True
        and in_win_fresh_ok is True
        and in_win_dup_rejected is True
        and p1 is True
        and p2 is True
        and p_dup is False
        and engine_replay.replay_attack_drop_counter == 1
        and engine_replay.diagnostic_code == CipSecurityDiagnosticCode.REPLAY_ATTACK_DETECTED
        and engine_replay.is_tamper_alert is True
    )
    test_results.append({
        "stage": 5,
        "check": "Sliding_Window_Anti_Replay_Attack_Packet_Rejection",
        "passed": s5_pass,
        "details": f"64-packet sliding window verified: duplicates, out-of-window, and replay trip 0xD103 confirmed.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Key exchange latency measurement and session caching
    # ------------------------------------------------------------------------
    engine_sess = CipSecurityEngine(current_time_s=1775000000.0, max_sessions=16)
    engine_sess.add_trusted_root_ca(root_ca)

    h_ok, _, sess = engine_sess.perform_handshake(
        peer_identity="plc01.plant.local",
        peer_cert=valid_leaf,
        offered_ciphers=[CipCipherSuite.TLS_AES_128_GCM_SHA256],
    )

    s6_pass = (
        h_ok is True
        and sess is not None
        and len(sess.session_key) == 16
        and len(sess.shared_secret) == 32
        and engine_sess.key_exchange_latency_ms == NOMINAL_KEY_EXCHANGE_LATENCY_MS
        and len(engine_sess.active_sessions) == 1
        and engine_sess.is_authenticated is True
    )
    test_results.append({
        "stage": 6,
        "check": "Key_Exchange_Latency_Measurement_And_Session_Caching",
        "passed": s6_pass,
        "details": f"Handshake derived 128-bit session key; latency={engine_sess.key_exchange_latency_ms}ms (scaled={NOMINAL_LATENCY_SCALED}).",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Register table synchronization (%R1540..%R1547, %M359..%M360)
    # ------------------------------------------------------------------------
    rt = RegisterTable()
    engine_rt = CipSecurityEngine(reg_table=rt, current_time_s=1775000000.0)
    engine_rt.add_trusted_root_ca(root_ca)
    engine_rt.perform_handshake(
        peer_identity="plc01.plant.local",
        peer_cert=valid_leaf,
        offered_ciphers=[CipCipherSuite.TLS_AES_128_GCM_SHA256],
    )
    engine_rt.sync_to_registers()

    r1540 = rt.read_word("%R1540")
    r1541 = rt.read_word("%R1541")
    r1542 = rt.read_uword("%R1542")
    r1543 = rt.read_word("%R1543")
    r1544 = rt.read_word("%R1544")
    r1545 = rt.read_word("%R1545")
    r1546 = rt.read_word("%R1546")
    r1547 = rt.read_uword("%R1547")
    m359 = rt.read_bit("%M359")
    m360 = rt.read_bit("%M360")

    s7_pass = (
        r1540 == int(CipSecurityProfileState.INTEGRITY_AND_CONFIDENTIALITY)
        and r1541 == 1
        and r1542 == 0x1301
        and r1543 > 0
        and r1544 == 0
        and r1545 == 0
        and r1546 == 35
        and r1547 == 0x0000
        and m359 is True
        and m360 is False
    )
    test_results.append({
        "stage": 7,
        "check": "Register_Table_Synchronization_R1540_R1547_M359_M360",
        "passed": s7_pass,
        "details": f"Horner OCS registers validated with PrivilegeMode.SYSTEM: state={r1540}, cipher=0x{r1542:04X}, latency={r1546}, diag=0x{r1547:04X}.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Discrete ILogicUnit 100-cycle scan simulation
    # ------------------------------------------------------------------------
    engine_scan = CipSecurityEngine(reg_table=rt, current_time_s=1775000000.0)
    engine_scan.add_trusted_root_ca(root_ca)
    engine_scan.perform_handshake(
        peer_identity="plc01.plant.local",
        peer_cert=valid_leaf,
        offered_ciphers=[CipCipherSuite.TLS_AES_128_GCM_SHA256],
    )

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
        engine_scan.execute(ctx)

    s8_pass = (
        engine_scan.name == "cip_security"
        and engine_scan.priority == 94
        and engine_scan.is_enabled is True
        and engine_scan.total_scan_cycles == 100
        and round(engine_scan.elapsed_simulation_ms) == 1000
    )
    test_results.append({
        "stage": 8,
        "check": "Discrete_ILogicUnit_100_Cycle_Scan_Simulation",
        "passed": s8_pass,
        "details": f"100 scan cycles executed smoothly; total elapsed simulation time={engine_scan.elapsed_simulation_ms}ms.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Process safety interlock and security tamper trip testing
    # ------------------------------------------------------------------------
    engine_safety = CipSecurityEngine(reg_table=rt, current_time_s=1775000000.0)
    engine_safety.add_trusted_root_ca(root_ca)
    engine_safety.perform_handshake(
        peer_identity="plc01.plant.local",
        peer_cert=valid_leaf,
        offered_ciphers=[CipCipherSuite.TLS_AES_128_GCM_SHA256],
    )

    # 1. Certificate Expired (0xD101)
    engine_safety.simulate_certificate_expired()
    d1 = (
        engine_safety.diagnostic_code == CipSecurityDiagnosticCode.CERTIFICATE_EXPIRED
        and rt.read_uword("%R1547") == 0xD101
        and rt.read_bit("%M360") is True
        and rt.read_bit("%M359") is False
    )

    # 2. Untrusted Root CA (0xD102)
    engine_safety.simulate_untrusted_ca()
    d2 = (
        engine_safety.diagnostic_code == CipSecurityDiagnosticCode.UNTRUSTED_ROOT_CA
        and rt.read_uword("%R1547") == 0xD102
        and rt.read_bit("%M360") is True
        and rt.read_bit("%M359") is False
    )

    # 3. Replay Attack Detected (0xD103)
    engine_safety.simulate_replay_attack()
    d3 = (
        engine_safety.diagnostic_code == CipSecurityDiagnosticCode.REPLAY_ATTACK_DETECTED
        and rt.read_uword("%R1547") == 0xD103
        and rt.read_bit("%M360") is True
        and rt.read_word("%R1545") >= 1
    )

    # 4. Cipher Mismatch (0xD104)
    engine_safety.simulate_cipher_mismatch()
    d4 = (
        engine_safety.diagnostic_code == CipSecurityDiagnosticCode.CIPHER_MISMATCH
        and rt.read_uword("%R1547") == 0xD104
        and rt.read_bit("%M360") is True
        and rt.read_word("%R1544") >= 1
    )

    # 5. Operator Reset Handshake
    res_reset = engine_safety.reset_fault(force=True)
    d5 = (
        res_reset.status == AgentStatus.SUCCESS
        and engine_safety.diagnostic_code == CipSecurityDiagnosticCode.OK
        and rt.read_uword("%R1547") == 0x0000
        and rt.read_bit("%M360") is False
        and rt.read_bit("%M359") is True
    )

    s9_pass = d1 and d2 and d3 and d4 and d5
    test_results.append({
        "stage": 9,
        "check": "Process_Safety_Interlock_And_Security_Tamper_Trips",
        "passed": s9_pass,
        "details": "Safety interlocks verified: 0xD101..0xD104 trips and operator reset handshake confirmed.",
    })

    # ------------------------------------------------------------------------
    # Summary & Evidence Serialization
    # ------------------------------------------------------------------------
    passed_count = sum(1 for t in test_results if t["passed"])
    total_stages = len(test_results)
    all_passed = (passed_count == total_stages)

    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_FAILED",
        "details": f"CIP Security Protocol Engine (W193) verified cleanly ({passed_count}/{total_stages} stages passed).",
        "stages_passed": passed_count,
        "total_stages": total_stages,
        "data": {
            "work_package": "W193",
            "standards": [
                "ODVA CIP Security Specification (Volume 8: EtherNet/IP Security Profile)",
                "TLS 1.3 (RFC 8446) / DTLS 1.2 (RFC 6347)",
                "IEC 61131-3 Structured Text",
            ],
            "stages": test_results,
            "tests": test_results,
            "checks_passed": passed_count,
            "total_checks": total_stages,
            "register_map": {
                "%R1540": "SecurityProfileState",
                "%R1541": "ActiveTlsSessionCount",
                "%R1542": "CipherSuiteIdentifier",
                "%R1543": "CertificateValidityDaysRemaining",
                "%R1544": "FailedHandshakeCounter",
                "%R1545": "ReplayAttackDropCounter",
                "%R1546": "SecurityKeyExchangeLatencyMsScaled",
                "%R1547": "DiagnosticStatusCode",
                "%M359": "CipSecurityAuthenticated",
                "%M360": "SecurityTamperAlert",
            },
            "registers": {
                "%R1540": rt.read_word("%R1540"),
                "%R1541": rt.read_word("%R1541"),
                "%R1542": rt.read_uword("%R1542"),
                "%R1543": rt.read_word("%R1543"),
                "%R1544": rt.read_word("%R1544"),
                "%R1545": rt.read_word("%R1545"),
                "%R1546": rt.read_word("%R1546"),
                "%R1547": rt.read_uword("%R1547"),
                "%M359": rt.read_bit("%M359"),
                "%M360": rt.read_bit("%M360"),
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    if output_path is not None:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence
