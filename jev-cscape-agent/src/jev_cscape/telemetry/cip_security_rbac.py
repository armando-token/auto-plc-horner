"""Industrial ODVA EtherNet/IP CIP Security Role-Based Access Control (RBAC) & Token Authorization Protocol Engine.

Work Package: W217 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Standards & Specifications:
- ODVA CIP Networks Library Volume 8: CIP Security Specification:
  - Class 0x5D: Certificate Management Object (X.509 certificate validation, CRL check,
    leaf / intermediate / CA trust chain validation).
  - Class 0x5E: CIP Security RBAC Object (Security Roles, Capability Bitmasks, Token Authentication).
- Security Profiles:
  - Profile 0: None / Factory Default (open/unencrypted).
  - Profile 1: CIP Security with Integrity (HMAC-SHA256 integrity only).
  - Profile 2: CIP Security with Confidentiality (TLS 1.3 / DTLS 1.2 PSK and X.509 AEAD encryption).
  - Profile 3: CIP Security with Confidentiality and Authentication (TLS/DTLS + X.509 Mutual Auth + RBAC).
- Canonical Roles (ODVA Volume 8 Table 5-2):
  - Administrator (Role 1): Complete administrative control (Read, Write, Configure, FirmwareUpdate, SafetyReset).
  - Engineer (Role 2): Engineering and maintenance control (Read, Write, Configure).
  - Operator (Role 3): Production line operation and safety reset (Read, Write, SafetyReset).
  - Auditor (Role 4): Security auditing, diagnostic logs, and compliance telemetry (Read only).
  - ViewOnly (Role 5): Unprivileged monitoring (Read only).
- Cryptographically Signed Bearer Tokens:
  - HMAC-SHA256 signature verification over claims payload.
  - Claims parsing: Subject, Roles, IssuedAt, ExpiresAt, Nonce, Issuer, Audience.
  - Expiration watchdog timer and automatic lifetime countdown.
- Access Control Matrix (Permission Table):
  - Capabilities: Read (0x01), Write (0x02), Configure (0x04), FirmwareUpdate (0x08), SafetyReset (0x10).
  - Per-class and per-instance authorization checking.
- Revocation Checks:
  - Certificate Revocation List (CRL) check for X.509 certificates (0xE904).
  - Token Blacklist enforcement for revoked bearer token nonces/subjects (%R1785).
- Horner OCS Register Table (%R1780..%R1787, %M415..%M416):
  - %R1780: ActiveSecurityProfile (0=None, 1=IntegrityOnly, 2=Confidentiality, 3=ConfidentialityAndAuth)
  - %R1781: AuthenticatedSessionCount (INT16, 0..16)
  - %R1782: ActiveRoleBitmask (INT16 bitmask of active session roles)
  - %R1783: TokenRemainingLifetimeSec (INT16, 0..3600 s)
  - %R1784: AccessViolationCounter (INT16)
  - %R1785: RevokedTokenAttemptCounter (INT16)
  - %R1786: SecurityState (0=Unconfigured, 1=FactoryDefault, 2=SecureRun, 3=SecurityLockout)
  - %R1787: DiagnosticStatusCode (0x0000=OK, 0xE901=TOKEN_EXPIRED, 0xE902=UNAUTHORIZED_ROLE,
            0xE903=SIGNATURE_VERIFICATION_FAILED, 0xE904=CERTIFICATE_REVOKED)
  - %M415:  CipSecurityRbacActive (BOOL)
  - %M416:  SecurityViolationTripActive (BOOL)
- Implements ILogicUnit interface with scan_step(dt: float, context: Optional[ScanContext] = None) -> None,
  name, priority, is_enabled, execute, reset.
- Implements sync_to_registers(reg_table: RegisterTable, privilege: PrivilegeMode = PrivilegeMode.SYSTEM).
- Includes pure IEC 61131-3 Structured Text POU 'CipSecurityRbacSync' validated via
  SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).
- Deterministic 9-stage verification suite run_cip_security_rbac_verification(output_path) returning
  strict 4-state contract JSON.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sys
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import HardwareLockoutError, LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Protocol Definitions (ODVA CIP Volume 8)
# ============================================================================

CIP_CERTIFICATE_MANAGEMENT_CLASS_ID: int = 0x5D  # Class 0x5D: Certificate Management Object
CIP_SECURITY_RBAC_CLASS_ID: int = 0x5E           # Class 0x5E: CIP Security RBAC Object

CIP_SECURITY_RBAC_TCP_PORT: int = 44818          # TLS encapsulation for EtherNet/IP
CIP_SECURITY_RBAC_UDP_PORT: int = 2222           # DTLS encapsulation for I/O packets

# Standard CIP Class References
CIP_IDENTITY_CLASS_ID: int = 0x01
CIP_MESSAGE_ROUTER_CLASS_ID: int = 0x02
CIP_ASSEMBLY_CLASS_ID: int = 0x04
CIP_CONNECTION_MANAGER_CLASS_ID: int = 0x06
CIP_SAFETY_SUPERVISOR_CLASS_ID: int = 0x39
CIP_CONTROLLER_CONFIG_CLASS_ID: int = 0x64

MAX_AUTHENTICATED_SESSIONS: int = 16
MAX_TOKEN_LIFETIME_SEC: int = 3600               # 1 hour maximum token duration for %R1783
DEFAULT_TOKEN_SECRET: bytes = b"cip-security-rbac-secret-key-2026-horner-ocs"
DEFAULT_BASE_TIME_S: float = 1775000000.0        # Deterministic simulation epoch timestamp
ONE_DAY_SECONDS: float = 86400.0


# ============================================================================
# 2. Exceptions
# ============================================================================

class CipSecurityRbacError(Exception):
    """Base exception for CIP Security RBAC protocol errors."""
    pass


class CipSecurityRbacForgedTokenError(CipSecurityRbacError):
    """Raised when HMAC-SHA256 signature verification fails or token is tampered (0xE903)."""
    pass


class CipSecurityRbacTokenExpiredError(CipSecurityRbacError):
    """Raised when bearer token expiration is exceeded (0xE901)."""
    pass


class CipSecurityRbacTokenRevokedError(CipSecurityRbacError):
    """Raised when bearer token or certificate is revoked (0xE904 / Blacklist)."""
    pass


class CipSecurityRbacUnauthorizedRoleError(CipSecurityRbacError):
    """Raised when active role bitmask lacks permission for requested action (0xE902)."""
    pass


# ============================================================================
# 3. Protocol Enums, Roles, & Diagnostic Codes
# ============================================================================

class CipSecurityProfile(IntEnum):
    """ODVA CIP Security Profiles (Volume 8 Table 2-1) & %R1780 Values."""
    NONE                        = 0  # No security / Factory Default
    INTEGRITY_ONLY              = 1  # HMAC-SHA256 message integrity enforcement
    CONFIDENTIALITY             = 2  # TLS 1.3 / DTLS 1.2 AEAD encryption (PSK or X.509)
    CONFIDENTIALITY_AND_AUTH    = 3  # Mutual X.509 TLS/DTLS encryption and RBAC token auth

    # Compatibility Aliases
    None_                       = 0
    IntegrityOnly               = 1
    Confidentiality             = 2
    ConfidentialityAndAuth      = 3
    FACTORY_DEFAULT             = 0
    FactoryDefault              = 0


ActiveSecurityProfile = CipSecurityProfile


class CipSecurityRole(IntEnum):
    """Canonical CIP Security RBAC Roles per ODVA Volume 8 Table 5-2."""
    ADMINISTRATOR = 1  # Role 1: Complete administrative control
    ENGINEER      = 2  # Role 2: Configuration, engineering, parameter writes
    OPERATOR      = 3  # Role 3: Daily operation, process writes, safety reset
    AUDITOR       = 4  # Role 4: Telemetry, event logs, security audit reading
    VIEW_ONLY     = 5  # Role 5: Read-only display and monitoring
    MAINTENANCE   = 6  # Role 6: Maintenance and diagnostics

    # Compatibility Aliases
    Administrator = 1
    Engineer      = 2
    Operator      = 3
    Auditor       = 4
    ViewOnly      = 5
    Maintenance   = 6


SecurityRole = CipSecurityRole
CipRole = CipSecurityRole


class RoleBitmask(IntFlag):
    """Active Role Bitmask (%R1782) encoding active session roles."""
    NONE          = 0x00
    ADMINISTRATOR = 1 << 0  # Bit 0 (0x01)
    ENGINEER      = 1 << 1  # Bit 1 (0x02)
    OPERATOR      = 1 << 2  # Bit 2 (0x04)
    AUDITOR       = 1 << 3  # Bit 3 (0x08)
    VIEW_ONLY     = 1 << 4  # Bit 4 (0x10)
    MAINTENANCE   = 1 << 5  # Bit 5 (0x20)
    ALL           = 0x1F

    # Compatibility Aliases
    Administrator = 1 << 0
    Engineer      = 1 << 1
    Operator      = 1 << 2
    Auditor       = 1 << 3
    ViewOnly      = 1 << 4


class CipAction(IntFlag):
    """Capability and Action Bitmasks for Access Control Matrix."""
    NONE            = 0x00
    READ            = 1 << 0  # Bit 0 (0x01): Read attributes / telemetry
    WRITE           = 1 << 1  # Bit 1 (0x02): Write setpoints / process variables
    CONFIGURE       = 1 << 2  # Bit 2 (0x04): Change network, I/O, or hardware config
    FIRMWARE_UPDATE = 1 << 3  # Bit 3 (0x08): Upload firmware or update system binary
    SAFETY_RESET    = 1 << 4  # Bit 4 (0x10): Clear safety trips or reset safety circuits
    ALL             = 0x1F

    # Compatibility Aliases
    Read            = 1 << 0
    Write           = 1 << 1
    Configure       = 1 << 2
    FirmwareUpdate  = 1 << 3
    SafetyReset     = 1 << 4


CapabilityBitmask = CipAction
CipCapability = CipAction
CipRbacAction = CipAction


class CipSecurityState(IntEnum):
    """Horner OCS %R1786 Security Engine States."""
    UNCONFIGURED    = 0  # Initializing or credentials unassigned
    FACTORY_DEFAULT = 1  # Default profile, open communication permitted
    SECURE_RUN      = 2  # Cryptographic RBAC security enforced in production
    SECURITY_LOCKOUT= 3  # Security boundary tripped; unauthorized access clamp

    # Compatibility Aliases
    Unconfigured    = 0
    FactoryDefault  = 1
    SecureRun       = 2
    SecurityLockout = 3


SecurityState = CipSecurityState
CipRbacSessionState = CipSecurityState


class CipSecurityRbacDiagnosticCode(IntEnum):
    """Horner OCS %R1787 Diagnostic Event Codes for CIP Security RBAC (W217)."""
    OK                            = 0x0000  # Normal healthy operation
    TOKEN_EXPIRED                 = 0xE901  # Bearer token validity expired
    UNAUTHORIZED_ROLE             = 0xE902  # Active role lacks capability for requested action
    SIGNATURE_VERIFICATION_FAILED = 0xE903  # HMAC-SHA256 signature verification failed / tampered
    CERTIFICATE_REVOKED           = 0xE904  # Certificate serial found in CRL or trust chain severed

    # Compatibility Aliases
    ERR_OK                  = 0x0000
    ERR_TOKEN_EXPIRED       = 0xE901
    ERR_UNAUTHORIZED_ROLE   = 0xE902
    ERR_SIGNATURE_FAILED    = 0xE903
    ERR_CERT_REVOKED        = 0xE904


DiagnosticStatusCode = CipSecurityRbacDiagnosticCode


# ============================================================================
# 4. Helper Functions: Register Safe Writes & Bitmask Conversions
# ============================================================================

def role_to_bitmask(role: Union[CipSecurityRole, int, str]) -> int:
    """Convert canonical role to single bit representation."""
    if isinstance(role, str):
        role_map = {
            "ADMINISTRATOR": CipSecurityRole.ADMINISTRATOR,
            "ENGINEER": CipSecurityRole.ENGINEER,
            "OPERATOR": CipSecurityRole.OPERATOR,
            "AUDITOR": CipSecurityRole.AUDITOR,
            "VIEW_ONLY": CipSecurityRole.VIEW_ONLY,
            "VIEWONLY": CipSecurityRole.VIEW_ONLY,
        }
        val = int(role_map.get(role.strip().upper(), 0))
    else:
        val = int(role)

    if 1 <= val <= 5:
        return 1 << (val - 1)
    return 0


def roles_to_bitmask(roles: Iterable[Union[CipSecurityRole, int, str]]) -> int:
    """Aggregate a collection of roles into an INT16 bitmask."""
    mask = 0
    for r in roles:
        mask |= role_to_bitmask(r)
    return mask


def bitmask_to_roles(mask: int) -> List[CipSecurityRole]:
    """Decode bitmask into list of active canonical roles."""
    roles: List[CipSecurityRole] = []
    for r in CipSecurityRole:
        bit = 1 << (int(r) - 1)
        if (mask & bit) != 0:
            roles.append(r)
    return roles


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

CIP_SECURITY_RBAC_SYNC_POU: str = """PROGRAM CipSecurityRbacSync
VAR
    (* Horner OCS Mapped Registers (W217 - CIP Security RBAC Engine) *)
    ActiveSecurityProfile       AT %R1780 : INT;    (* 0=None, 1=IntegrityOnly, 2=Confidentiality, 3=ConfidentialityAndAuth *)
    AuthenticatedSessionCount   AT %R1781 : INT;    (* Active Authenticated Sessions Count (0..16) *)
    ActiveRoleBitmask           AT %R1782 : INT;    (* Bitmask of Active Session Roles *)
    TokenRemainingLifetimeSec   AT %R1783 : INT;    (* Token Remaining Lifetime in Seconds (0..3600) *)
    AccessViolationCounter      AT %R1784 : INT;    (* Accumulated Access Violation Counter *)
    RevokedTokenAttemptCounter  AT %R1785 : INT;    (* Revoked / Blacklisted Token Attempt Counter *)
    SecurityState               AT %R1786 : INT;    (* 0=Unconfigured, 1=FactoryDefault, 2=SecureRun, 3=SecurityLockout *)
    DiagnosticStatusCode        AT %R1787 : UINT;   (* 0x0000=OK, 0xE901..0xE904 *)

    (* Discrete RBAC Status & Safety Interlocks *)
    CipSecurityRbacActive       AT %M415  : BOOL;   (* TRUE when secure profile active and >= 1 session authenticated *)
    SecurityViolationTripActive AT %M416  : BOOL;   (* TRUE on access violation, expired token, or revocation *)
END_VAR
VAR
    InternalRbacLoopOk          : BOOL;
END_VAR

IF SecurityViolationTripActive OR (DiagnosticStatusCode <> 0) THEN
    CipSecurityRbacActive := FALSE;
    SecurityViolationTripActive := TRUE;
    SecurityState := 3;
    InternalRbacLoopOk := FALSE;
ELSIF AuthenticatedSessionCount > 0 AND ActiveSecurityProfile >= 1 THEN
    SecurityViolationTripActive := FALSE;
    CipSecurityRbacActive := TRUE;
    SecurityState := 2;
    InternalRbacLoopOk := TRUE;
ELSE
    CipSecurityRbacActive := FALSE;
    IF SecurityState <> 3 THEN
        IF ActiveSecurityProfile = 0 THEN
            SecurityState := 1;
        ELSE
            SecurityState := 0;
        END_IF;
    END_IF;
    InternalRbacLoopOk := FALSE;
END_IF;
END_PROGRAM
"""

CIP_SECURITY_RBAC_POU = CIP_SECURITY_RBAC_SYNC_POU
CipSecurityRbacSyncPOU = CIP_SECURITY_RBAC_SYNC_POU


def verify_cip_security_rbac_pure_st() -> bool:
    """Assert pure IEC 61131-3 Structured Text and zero ladder logic constructs."""
    SecurityGuard.assert_pure_st_content(CIP_SECURITY_RBAC_SYNC_POU)
    res = STParser.validate_code(CIP_SECURITY_RBAC_SYNC_POU)
    return res.status == AgentStatus.SUCCESS


# ============================================================================
# 6. X.509 Certificate Descriptor & Trust Chain Manager (Class 0x5D)
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
    parent_serial: str = ""
    public_key_pem: str = ""
    signature_algorithm: str = "sha256WithRSAEncryption"

    @classmethod
    def create(
        cls,
        serial: str = "01",
        cn: str = "Root CA",
        is_ca: bool = False,
        issuer: str = "",
        issuer_cn: str = "",
        parent_serial: str = "",
        not_before_s: float = DEFAULT_BASE_TIME_S - ONE_DAY_SECONDS,
        not_after_s: float = DEFAULT_BASE_TIME_S + ONE_DAY_SECONDS * 365,
        san: Optional[List[str]] = None,
    ) -> "X509CertInfo":
        iss = issuer_cn or issuer or cn
        return cls(
            common_name=cn,
            issuer=iss,
            not_before_s=not_before_s,
            not_after_s=not_after_s,
            san=san or [],
            serial_number=serial,
            is_ca=is_ca,
            parent_serial=parent_serial,
        )

    def is_valid_at(self, current_time_s: float) -> bool:
        """Evaluate if timestamp falls within certificate validity period."""
        return self.not_before_s <= float(current_time_s) <= self.not_after_s

    def days_remaining(self, current_time_s: float) -> int:
        """Calculate remaining validity period in whole calendar days."""
        t = float(current_time_s)
        if t > self.not_after_s:
            return 0
        rem_seconds = max(0.0, self.not_after_s - t)
        return int(rem_seconds // ONE_DAY_SECONDS)

    def matches_san(self, identity: str) -> bool:
        """Check if target host or IP matches SAN list or Common Name."""
        clean_id = identity.strip().lower()
        if clean_id == self.common_name.strip().lower():
            return True
        for alt in self.san:
            if clean_id == alt.strip().lower():
                return True
        return False


class CertificateManager:
    """Cryptographic Trust Chain and Certificate Revocation List (CRL) Manager."""

    def __init__(self) -> None:
        self.root_ca_store: Dict[str, X509CertInfo] = {}
        self.intermediate_ca_store: Dict[str, X509CertInfo] = {}
        self.installed_certs: Dict[str, X509CertInfo] = {}
        self.crl_revoked_serials: Set[str] = set()

    def add_trusted_root_ca(self, cert: X509CertInfo) -> bool:
        """Enroll trusted Root CA into trust store."""
        if not cert.is_ca:
            return False
        self.root_ca_store[cert.common_name.strip()] = cert
        return True

    def install_ca_certificate(self, cert: X509CertInfo) -> bool:
        """Alias for add_trusted_root_ca."""
        return self.add_trusted_root_ca(cert)

    def add_intermediate_ca(self, cert: X509CertInfo) -> bool:
        """Enroll intermediate CA into intermediate store."""
        if not cert.is_ca:
            return False
        self.intermediate_ca_store[cert.common_name.strip()] = cert
        return True

    def install_certificate(self, cert: X509CertInfo) -> None:
        """Install device or client certificate."""
        self.installed_certs[cert.serial_number.strip().upper()] = cert

    def revoke_certificate(self, serial_number: str, reason: str = "") -> None:
        """Add certificate serial number to Certificate Revocation List (CRL)."""
        self.crl_revoked_serials.add(serial_number.strip().upper())

    def is_revoked(self, serial_number: str) -> bool:
        """Check if certificate serial number is revoked in CRL."""
        return serial_number.strip().upper() in self.crl_revoked_serials

    def validate_chain(
        self,
        cert: X509CertInfo,
        current_time_s: float,
        peer_identity: Optional[str] = None,
    ) -> Tuple[bool, Optional[CipSecurityRbacDiagnosticCode], str]:
        """Validate an X.509 certificate through leaf -> intermediate -> Root CA trust chain."""
        clean_serial = cert.serial_number.strip().upper()

        # 1. CRL Check on leaf certificate
        if clean_serial in self.crl_revoked_serials:
            return (
                False,
                CipSecurityRbacDiagnosticCode.CERTIFICATE_REVOKED,
                f"Leaf certificate serial '{cert.serial_number}' is revoked in CRL",
            )

        # 2. Expiration check on leaf certificate
        if not cert.is_valid_at(current_time_s):
            return (
                False,
                CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED,
                f"Certificate '{cert.common_name}' validity expired at t={current_time_s}",
            )

        # 3. Follow issuer trust chain
        current_issuer_name = cert.issuer.strip()
        chain_depth = 0
        max_chain_depth = 8

        while chain_depth < max_chain_depth:
            # Case A: Issuer is an intermediate CA
            if current_issuer_name in self.intermediate_ca_store:
                inter_ca = self.intermediate_ca_store[current_issuer_name]
                if self.is_revoked(inter_ca.serial_number):
                    return (
                        False,
                        CipSecurityRbacDiagnosticCode.CERTIFICATE_REVOKED,
                        f"Intermediate CA '{inter_ca.common_name}' is revoked in CRL",
                    )
                if not inter_ca.is_valid_at(current_time_s):
                    return (
                        False,
                        CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED,
                        f"Intermediate CA '{inter_ca.common_name}' validity expired",
                    )
                current_issuer_name = inter_ca.issuer.strip()
                chain_depth += 1
                continue

            # Case B: Issuer is a trusted Root CA
            if current_issuer_name in self.root_ca_store:
                root_ca = self.root_ca_store[current_issuer_name]
                if not root_ca.is_ca:
                    return (
                        False,
                        CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED,
                        f"Root '{root_ca.common_name}' is not designated as Certificate Authority",
                    )
                if self.is_revoked(root_ca.serial_number):
                    return (
                        False,
                        CipSecurityRbacDiagnosticCode.CERTIFICATE_REVOKED,
                        f"Root CA '{root_ca.common_name}' is revoked in CRL",
                    )
                if not root_ca.is_valid_at(current_time_s):
                    return (
                        False,
                        CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED,
                        f"Root CA '{root_ca.common_name}' validity expired",
                    )
                break

            # Case C: Issuer unknown
            return (
                False,
                CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED,
                f"Certificate issuer '{current_issuer_name}' not found in trusted Root/Intermediate CA store",
            )

        # 4. Peer SAN / CN Identity Verification
        if peer_identity is not None and not cert.matches_san(peer_identity):
            return (
                False,
                CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE,
                f"Peer identity '{peer_identity}' does not match SAN {cert.san} or CN '{cert.common_name}'",
            )

        return (True, None, f"Certificate '{cert.common_name}' trust chain verified successfully")


CrlManager = CertificateManager


@dataclass
class CertificateManagementObject:
    """ODVA CIP Certificate Management Object (Class 0x5D).

    Attributes:
    1: CertificateState (INT, 0=Unconfigured, 1=Valid, 2=Expired, 3=Revoked)
    2: MaxCertificates (INT, default 16)
    3: InstalledCertificateCount (INT)
    4: CertificateChainStatus (INT, 0=Valid, 1=Invalid, 2=UntrustedCA, 3=Revoked)
    5: TrustedCaCount (INT)
    6: CrlRevokedCount (INT)
    7: ActiveSerialNumber (STRING)
    8: ActiveIssuerCn (STRING)
    9: ActiveSubjectCn (STRING)
    """
    class_id: int = CIP_CERTIFICATE_MANAGEMENT_CLASS_ID
    instance_id: int = 1

    cert_state: int = 1
    max_certificates: int = 16
    installed_certificate_count: int = 0
    chain_status: int = 0
    trusted_ca_count: int = 0
    crl_revoked_count: int = 0
    active_serial_number: str = ""
    active_issuer_cn: str = ""
    active_subject_cn: str = ""

    def get_attribute_single(self, attribute_id: int) -> Any:
        """Query attribute by ID (ODVA CIP Service 0x0E)."""
        attrs: Dict[int, Any] = {
            1: self.cert_state,
            2: self.max_certificates,
            3: self.installed_certificate_count,
            4: self.chain_status,
            5: self.trusted_ca_count,
            6: self.crl_revoked_count,
            7: self.active_serial_number,
            8: self.active_issuer_cn,
            9: self.active_subject_cn,
        }
        if attribute_id in attrs:
            return attrs[attribute_id]
        raise KeyError(f"Certificate Management Object (Class 0x5D) does not support Attribute ID {attribute_id}")

    def set_attribute_single(self, attribute_id: int, value: Any) -> bool:
        """Set attribute by ID (ODVA CIP Service 0x10)."""
        if attribute_id in {1, 2, 3, 4, 5, 6, 7, 8, 9}:
            raise PermissionError(f"Certificate Management Object Attribute ID {attribute_id} is read-only via CIP network")
        raise KeyError(f"Certificate Management Object does not support Attribute ID {attribute_id}")

    def get_attribute_all(self) -> Dict[int, Any]:
        """Query all attributes (ODVA CIP Service 0x01)."""
        return {
            1: self.cert_state,
            2: self.max_certificates,
            3: self.installed_certificate_count,
            4: self.chain_status,
            5: self.trusted_ca_count,
            6: self.crl_revoked_count,
            7: self.active_serial_number,
            8: self.active_issuer_cn,
            9: self.active_subject_cn,
        }


# ============================================================================
# 7. Cryptographically Signed Bearer Tokens & HMAC-SHA256 Engine
# ============================================================================

@dataclass
class BearerTokenClaims:
    """Claims payload within an ODVA CIP Security Bearer Token."""
    subject: str
    roles: List[CipSecurityRole]
    issued_at: float
    expires_at: float
    nonce: str
    issuer: str = "Horner-CIP-Security-Auth-Server"
    audience: str = "Horner-OCS-PLC"

    @property
    def role_bitmask(self) -> int:
        """Bitwise OR of all roles contained in token."""
        return roles_to_bitmask(self.roles)

    def remaining_lifetime(self, current_time_s: float) -> float:
        """Calculate remaining valid lifetime in seconds."""
        return max(0.0, self.expires_at - float(current_time_s))

    def is_expired(self, current_time_s: float) -> bool:
        """Check if current time is past expiration timestamp."""
        return float(current_time_s) >= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        """Serialize claims to dictionary representation."""
        return {
            "sub": self.subject,
            "roles": [int(r) for r in self.roles],
            "iat": self.issued_at,
            "exp": self.expires_at,
            "nonce": self.nonce,
            "iss": self.issuer,
            "aud": self.audience,
        }

    def to_json(self) -> str:
        """Serialize claims to canonical compact JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


TokenClaims = BearerTokenClaims


class BearerToken:
    """Compact cryptographically signed bearer token encoder and validator."""

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    @staticmethod
    def _b64url_decode(data_str: str) -> bytes:
        padding = "=" * ((4 - len(data_str) % 4) % 4)
        return base64.urlsafe_b64decode((data_str + padding).encode("ascii"))

    @classmethod
    def encode(cls, claims: BearerTokenClaims, secret_key: bytes) -> str:
        """Generate cryptographically signed bearer token string (HMAC-SHA256)."""
        header = {"alg": "HS256", "typ": "CIP-BEARER-TOKEN"}
        hdr_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        payload_bytes = claims.to_json().encode("utf-8")

        hdr_b64 = cls._b64url_encode(hdr_bytes)
        payload_b64 = cls._b64url_encode(payload_bytes)
        signing_input = f"{hdr_b64}.{payload_b64}".encode("ascii")

        sig = hmac.new(secret_key, signing_input, hashlib.sha256).digest()
        sig_b64 = cls._b64url_encode(sig)

        return f"{hdr_b64}.{payload_b64}.{sig_b64}"

    @classmethod
    def decode(
        cls,
        token_str: str,
        secret_key: bytes,
        current_time_s: float,
        blacklist: Optional[Set[str]] = None,
    ) -> Tuple[bool, Optional[CipSecurityRbacDiagnosticCode], Optional[BearerTokenClaims], str]:
        """Validate bearer token signature, claims, expiration, and revocation status."""
        raw = extract_bearer_token(token_str)
        parts = raw.split(".")
        if len(parts) != 3:
            return (
                False,
                CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED,
                None,
                "Malformed token structure (expected header.payload.signature)",
            )

        hdr_b64, payload_b64, sig_b64 = parts

        # 1. Verify HMAC-SHA256 Signature
        signing_input = f"{hdr_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(secret_key, signing_input, hashlib.sha256).digest()
        try:
            actual_sig = cls._b64url_decode(sig_b64)
        except Exception as exc:
            return (
                False,
                CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED,
                None,
                f"Failed to base64url decode token signature: {exc}",
            )

        if not hmac.compare_digest(expected_sig, actual_sig):
            return (
                False,
                CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED,
                None,
                "HMAC-SHA256 signature verification failed (tampered token)",
            )

        # 2. Parse Claims JSON
        try:
            payload_json = cls._b64url_decode(payload_b64).decode("utf-8")
            data = json.loads(payload_json)
            roles = [CipSecurityRole(int(r)) for r in data.get("roles", [])]
            claims = BearerTokenClaims(
                subject=str(data.get("sub", "anonymous")),
                roles=roles,
                issued_at=float(data.get("iat", 0.0)),
                expires_at=float(data.get("exp", 0.0)),
                nonce=str(data.get("nonce", "")),
                issuer=str(data.get("iss", "Horner-CIP-Security-Auth-Server")),
                audience=str(data.get("aud", "Horner-OCS-PLC")),
            )
        except Exception as exc:
            return (
                False,
                CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED,
                None,
                f"Invalid claims payload: {exc}",
            )

        # 3. Blacklist / Revocation check
        if blacklist is not None:
            if claims.nonce in blacklist or claims.subject in blacklist:
                return (
                    False,
                    CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE,
                    claims,
                    f"Token nonce '{claims.nonce}' or subject '{claims.subject}' is revoked in token blacklist",
                )

        # 4. Expiration check
        if claims.is_expired(current_time_s):
            return (
                False,
                CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED,
                claims,
                f"Bearer token expired at t={claims.expires_at} (current_time={current_time_s})",
            )

        return (True, None, claims, "Bearer token verified and accepted")


def extract_bearer_token(authorization_header_or_str: str) -> str:
    """Extract raw bearer token string from HTTP Authorization header or raw token."""
    s = authorization_header_or_str.strip()
    if s.lower().startswith("bearer "):
        return s[7:].strip()
    return s


def parse_token_claims(token_str: str) -> BearerTokenClaims:
    """Parse and deserialize claims payload without cryptographic signature verification."""
    raw = extract_bearer_token(token_str)
    parts = raw.split(".")
    if len(parts) < 2:
        raise ValueError("Malformed bearer token: missing claims segment")
    payload_json = BearerToken._b64url_decode(parts[1]).decode("utf-8")
    data = json.loads(payload_json)
    roles = [CipSecurityRole(int(r)) for r in data.get("roles", [])]
    return BearerTokenClaims(
        subject=str(data.get("sub", "anonymous")),
        roles=roles,
        issued_at=float(data.get("iat", 0.0)),
        expires_at=float(data.get("exp", 0.0)),
        nonce=str(data.get("nonce", "")),
        issuer=str(data.get("iss", "Horner-CIP-Security-Auth-Server")),
        audience=str(data.get("aud", "Horner-OCS-PLC")),
    )


def verify_bearer_token(
    token_str: str,
    secret_key: bytes,
    current_time_s: float = DEFAULT_BASE_TIME_S,
    blacklist: Optional[Set[str]] = None,
) -> Tuple[bool, Optional[CipSecurityRbacDiagnosticCode], Optional[BearerTokenClaims], str]:
    """Verify cryptographically signed bearer token signature, expiration, and revocation."""
    raw = extract_bearer_token(token_str)
    return BearerToken.decode(raw, secret_key, current_time_s, blacklist)


def create_bearer_token(
    subject: str,
    roles: Sequence[Union[CipSecurityRole, int, str]],
    lifetime_sec: float = 3600.0,
    secret_key: bytes = DEFAULT_TOKEN_SECRET,
    current_time_s: float = DEFAULT_BASE_TIME_S,
    nonce: Optional[str] = None,
    issuer: str = "Horner-CIP-Security-Auth-Server",
    audience: str = "Horner-OCS-PLC",
) -> str:
    """Convenience helper to mint signed bearer tokens for tests and simulations."""
    parsed_roles: List[CipSecurityRole] = []
    for r in roles:
        if isinstance(r, CipSecurityRole):
            parsed_roles.append(r)
        elif isinstance(r, int):
            parsed_roles.append(CipSecurityRole(r))
        elif isinstance(r, str):
            parsed_roles.append(CipSecurityRole[r.strip().upper()])

    token_nonce = nonce if nonce is not None else secrets.token_hex(8)
    claims = BearerTokenClaims(
        subject=subject,
        roles=parsed_roles,
        issued_at=float(current_time_s),
        expires_at=float(current_time_s + lifetime_sec),
        nonce=token_nonce,
        issuer=issuer,
        audience=audience,
    )
    return BearerToken.encode(claims, secret_key)


generate_bearer_token = create_bearer_token


# ============================================================================
# 8. Access Control Matrix (Permission Table)
# ============================================================================

class AccessControlMatrix:
    """Fine-grained CIP Object / Instance Role-Based Access Control Matrix."""

    def __init__(self) -> None:
        # Default canonical role capabilities per ODVA Volume 8 Table 5-2
        self.default_role_capabilities: Dict[CipSecurityRole, CipAction] = {
            CipSecurityRole.ADMINISTRATOR: (
                CipAction.READ | CipAction.WRITE | CipAction.CONFIGURE |
                CipAction.FIRMWARE_UPDATE | CipAction.SAFETY_RESET
            ),
            CipSecurityRole.ENGINEER: (
                CipAction.READ | CipAction.WRITE | CipAction.CONFIGURE
            ),
            CipSecurityRole.OPERATOR: (
                CipAction.READ | CipAction.WRITE | CipAction.SAFETY_RESET
            ),
            CipSecurityRole.AUDITOR: (
                CipAction.READ
            ),
            CipSecurityRole.VIEW_ONLY: (
                CipAction.READ
            ),
        }

        # Fine-grained object overrides: (class_id, instance_id or None) -> {role: CipAction}
        self.object_rules: Dict[Tuple[int, Optional[int]], Dict[CipSecurityRole, CipAction]] = {}
        self._initialize_standard_cip_rules()

    def _initialize_standard_cip_rules(self) -> None:
        """Populate standard ODVA EtherNet/IP object access control policies."""
        # Class 0x5D: Certificate Management Object (Admins only for configure)
        self.object_rules[(CIP_CERTIFICATE_MANAGEMENT_CLASS_ID, None)] = {
            CipSecurityRole.ADMINISTRATOR: CipAction.READ | CipAction.WRITE | CipAction.CONFIGURE,
            CipSecurityRole.ENGINEER: CipAction.READ,
            CipSecurityRole.OPERATOR: CipAction.NONE,
            CipSecurityRole.AUDITOR: CipAction.READ,
            CipSecurityRole.VIEW_ONLY: CipAction.NONE,
        }

        # Class 0x5E: CIP Security RBAC Object
        self.object_rules[(CIP_SECURITY_RBAC_CLASS_ID, None)] = {
            CipSecurityRole.ADMINISTRATOR: CipAction.READ | CipAction.WRITE | CipAction.CONFIGURE,
            CipSecurityRole.ENGINEER: CipAction.READ,
            CipSecurityRole.OPERATOR: CipAction.NONE,
            CipSecurityRole.AUDITOR: CipAction.READ,
            CipSecurityRole.VIEW_ONLY: CipAction.NONE,
        }

        # Class 0x01: Identity Object (Firmware updates restricted to Administrator)
        self.object_rules[(CIP_IDENTITY_CLASS_ID, None)] = {
            CipSecurityRole.ADMINISTRATOR: CipAction.READ | CipAction.WRITE | CipAction.CONFIGURE | CipAction.FIRMWARE_UPDATE,
            CipSecurityRole.ENGINEER: CipAction.READ | CipAction.CONFIGURE,
            CipSecurityRole.OPERATOR: CipAction.READ,
            CipSecurityRole.AUDITOR: CipAction.READ,
            CipSecurityRole.VIEW_ONLY: CipAction.READ,
        }

        # Class 0x39: Safety Supervisor Object (Safety reset allowed for Admin & Operator)
        self.object_rules[(CIP_SAFETY_SUPERVISOR_CLASS_ID, None)] = {
            CipSecurityRole.ADMINISTRATOR: CipAction.READ | CipAction.WRITE | CipAction.CONFIGURE | CipAction.SAFETY_RESET,
            CipSecurityRole.ENGINEER: CipAction.READ | CipAction.CONFIGURE,
            CipSecurityRole.OPERATOR: CipAction.READ | CipAction.SAFETY_RESET,
            CipSecurityRole.AUDITOR: CipAction.READ,
            CipSecurityRole.VIEW_ONLY: CipAction.READ,
        }

    def set_rule(
        self,
        object_class: int,
        instance_id: Optional[int],
        role: CipSecurityRole,
        allowed_actions: CipAction,
    ) -> None:
        """Configure fine-grained permission override for an object class/instance."""
        key = (object_class, instance_id)
        if key not in self.object_rules:
            self.object_rules[key] = {}
        self.object_rules[key][role] = allowed_actions

    def get_allowed_actions(
        self,
        role: CipSecurityRole,
        object_class: int,
        instance_id: int = 1,
    ) -> CipAction:
        """Resolve effective permitted actions for a specific role and object target."""
        # 1. Check exact (class, instance) match
        if (object_class, instance_id) in self.object_rules:
            rules = self.object_rules[(object_class, instance_id)]
            if role in rules:
                return rules[role]

        # 2. Check wildcard (class, None) match
        if (object_class, None) in self.object_rules:
            rules = self.object_rules[(object_class, None)]
            if role in rules:
                return rules[role]

        # 3. Fallback to default canonical role capabilities
        return self.default_role_capabilities.get(role, CipAction.NONE)

    def is_allowed(
        self,
        roles: Union[CipSecurityRole, int, Sequence[CipSecurityRole]],
        object_class: int,
        instance_id: int,
        action: CipAction,
    ) -> bool:
        """Evaluate if any of the supplied roles permits the requested action."""
        if action == CipAction.NONE:
            return True

        if isinstance(roles, CipSecurityRole):
            active_roles = [roles]
        elif isinstance(roles, int):
            active_roles = bitmask_to_roles(roles)
        else:
            active_roles = list(roles)

        for r in active_roles:
            allowed = self.get_allowed_actions(r, object_class, instance_id)
            if (allowed & action) == action:
                return True

        return False


RbacAuthorizationMatrix = AccessControlMatrix


# ============================================================================
# 9. CIP Security RBAC Object (Class 0x5E)
# ============================================================================

@dataclass
class CipSecurityRbacObject:
    """ODVA CIP Security RBAC Object (Class 0x5E).

    Attributes:
    1: ActiveSecurityProfile (INT, 0=None, 1=IntegrityOnly, 2=Confidentiality, 3=ConfidentialityAndAuth)
    2: CanonicalRoleCount (INT, 5)
    3: ActiveRoleBitmask (INT, %R1782)
    4: AuthenticatedSessionCount (INT, %R1781)
    5: TokenRemainingLifetimeSec (INT, %R1783)
    6: AccessViolationCounter (INT, %R1784)
    7: RevokedTokenAttemptCounter (INT, %R1785)
    8: SecurityState (INT, %R1786)
    9: DiagnosticStatusCode (UINT, %R1787)
    10: CapabilitiesBitmask (INT, cumulative capability of active sessions)
    """
    class_id: int = CIP_SECURITY_RBAC_CLASS_ID
    instance_id: int = 1

    profile: int = int(CipSecurityProfile.CONFIDENTIALITY_AND_AUTH)
    role_count: int = 5
    active_role_mask: int = 0
    session_count: int = 0
    token_remaining_lifetime: int = 0
    access_violations: int = 0
    revoked_token_attempts: int = 0
    security_state: int = int(CipSecurityState.SECURE_RUN)
    diagnostic_code: int = int(CipSecurityRbacDiagnosticCode.OK)
    capabilities_bitmask: int = int(CipAction.ALL)

    def get_attribute_single(self, attribute_id: int) -> Any:
        """Query attribute value by ID (ODVA CIP Service 0x0E)."""
        attrs: Dict[int, Any] = {
            1: self.profile,
            2: self.role_count,
            3: self.active_role_mask,
            4: self.session_count,
            5: self.token_remaining_lifetime,
            6: self.access_violations,
            7: self.revoked_token_attempts,
            8: self.security_state,
            9: self.diagnostic_code,
            10: self.capabilities_bitmask,
        }
        if attribute_id in attrs:
            return attrs[attribute_id]
        raise KeyError(f"CIP Security RBAC Object (Class 0x5E) does not support Attribute ID {attribute_id}")

    def set_attribute_single(self, attribute_id: int, value: Any) -> bool:
        """Set writable attribute by ID (ODVA CIP Service 0x10)."""
        if attribute_id == 1:
            val_int = int(value)
            self.profile = val_int
            return True
        if attribute_id in {2, 3, 4, 5, 6, 7, 8, 9, 10}:
            raise PermissionError(f"CIP Security RBAC Object Attribute ID {attribute_id} is read-only via CIP network")
        raise KeyError(f"CIP Security RBAC Object does not support Attribute ID {attribute_id}")

    def get_attribute_all(self) -> Dict[int, Any]:
        """Query all attributes (ODVA CIP Service 0x01)."""
        return {
            1: self.profile,
            2: self.role_count,
            3: self.active_role_mask,
            4: self.session_count,
            5: self.token_remaining_lifetime,
            6: self.access_violations,
            7: self.revoked_token_attempts,
            8: self.security_state,
            9: self.diagnostic_code,
            10: self.capabilities_bitmask,
        }


# ============================================================================
# 10. RbacSession & Session State Tracking
# ============================================================================

@dataclass
class RbacSession:
    """Active authenticated session established via Bearer Token."""
    session_id: str
    claims: BearerTokenClaims
    established_at_s: float
    last_activity_s: float
    is_active: bool = True

    @property
    def subject(self) -> str:
        return self.claims.subject

    @property
    def roles(self) -> List[CipSecurityRole]:
        return self.claims.roles

    @property
    def role_bitmask(self) -> int:
        return self.claims.role_bitmask

    def remaining_lifetime(self, current_time_s: float) -> float:
        return self.claims.remaining_lifetime(current_time_s)

    def is_expired(self, current_time_s: float) -> bool:
        return self.claims.is_expired(current_time_s)

    def has_role(self, role: CipSecurityRole) -> bool:
        return role in self.claims.roles

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "subject": self.subject,
            "roles": [int(r) for r in self.roles],
            "role_bitmask": self.role_bitmask,
            "established_at_s": self.established_at_s,
            "last_activity_s": self.last_activity_s,
            "is_active": self.is_active,
        }


# ============================================================================
# 11. CipSecurityRbacEngine (ILogicUnit)
# ============================================================================

class CipSecurityRbacEngine(ILogicUnit):
    """Industrial ODVA EtherNet/IP CIP Security RBAC & Token Authorization Protocol Engine."""

    def __init__(
        self,
        reg_table: Optional[RegisterTable] = None,
        security_profile: CipSecurityProfile = CipSecurityProfile.CONFIDENTIALITY_AND_AUTH,
        current_time_s: float = DEFAULT_BASE_TIME_S,
        secret_key: bytes = DEFAULT_TOKEN_SECRET,
        max_sessions: int = MAX_AUTHENTICATED_SESSIONS,
    ) -> None:
        self.reg_table: Optional[RegisterTable] = reg_table
        self.profile: CipSecurityProfile = security_profile
        self.current_time_s: float = float(current_time_s)
        self.secret_key: bytes = secret_key
        self.max_sessions: int = max(1, min(16, int(max_sessions)))

        # Subsystems
        self.access_matrix: AccessControlMatrix = AccessControlMatrix()
        self.cert_manager: CertificateManager = CertificateManager()
        self.token_blacklist: Set[str] = set()

        # CIP Objects
        self.cert_management_object: CertificateManagementObject = CertificateManagementObject()
        self.rbac_object: CipSecurityRbacObject = CipSecurityRbacObject(profile=int(self.profile))

        # Active Session Space
        self.active_sessions: Dict[str, RbacSession] = {}

        # Telemetry & Diagnostics
        self.state: CipSecurityState = CipSecurityState.SECURE_RUN
        self.diagnostic_code: CipSecurityRbacDiagnosticCode = CipSecurityRbacDiagnosticCode.OK
        self.access_violation_counter: int = 0
        self.revoked_token_attempt_counter: int = 0
        self.is_rbac_active: bool = False
        self.is_violation_trip_active: bool = False

        # Simulation & Scan Watchdogs
        self.elapsed_simulation_ms: float = 0.0
        self.total_scan_cycles: int = 0
        self._enabled: bool = True

        self._refresh_aggregate_state()
        if self.reg_table is not None:
            self.sync_to_registers()

    # ------------------------------------------------------------------------
    # ILogicUnit Interface Implementation
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        """Unique identifier for this logic unit."""
        return "CipSecurityRbacEngine"

    @property
    def priority(self) -> int:
        """Execution priority (lower integer executes earlier)."""
        return 96

    @property
    def is_enabled(self) -> bool:
        """Whether the logic unit participates in the scan."""
        return self._enabled

    def execute(self, ctx: ScanContext) -> None:
        """Execute logic evaluation for this cycle."""
        dt_ms = getattr(ctx, "dt_ms", 10.0)
        dt_s = dt_ms / 1000.0 if dt_ms is not None else 0.010
        self.scan_step(dt=dt_s, context=ctx)

    def reset(self) -> None:
        """Reset internal unit state to initial conditions."""
        self.reset_fault(force=True)

    # ------------------------------------------------------------------------
    # Discrete Scan Cycle Execution
    # ------------------------------------------------------------------------

    def scan_step(self, dt: float, context: Optional[ScanContext] = None) -> None:
        """Advance discrete simulation clock, evaluate expiration watchdogs, and sync registers."""
        dt_s = max(0.0, float(dt))
        self.elapsed_simulation_ms += dt_s * 1000.0
        self.total_scan_cycles += 1
        self.current_time_s += dt_s

        # 1. Token Expiration Watchdog: Purge expired sessions
        expired_session_ids: List[str] = []
        for sid, sess in list(self.active_sessions.items()):
            if sess.is_expired(self.current_time_s):
                expired_session_ids.append(sid)

        for sid in expired_session_ids:
            del self.active_sessions[sid]
            self.access_violation_counter += 1
            self.diagnostic_code = CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED
            self.is_violation_trip_active = True

        # 2. Update aggregate metrics and registers
        self._refresh_aggregate_state()
        if self.reg_table is not None:
            self.sync_to_registers()

    # ------------------------------------------------------------------------
    # Token Authentication & RBAC Enforcement
    # ------------------------------------------------------------------------

    def authenticate_token(
        self,
        token_str: str,
    ) -> Tuple[bool, Optional[CipSecurityRbacDiagnosticCode], Optional[RbacSession], str]:
        """Validate signed bearer token and instantiate active session if authorized."""
        # Check capacity
        if len(self.active_sessions) >= self.max_sessions:
            return (
                False,
                None,
                None,
                f"Session capacity exceeded (max {self.max_sessions} active sessions)",
            )

        # Validate token
        is_valid, err_code, claims, details = BearerToken.decode(
            token_str=token_str,
            secret_key=self.secret_key,
            current_time_s=self.current_time_s,
            blacklist=self.token_blacklist,
        )

        if not is_valid:
            if err_code == CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED:
                self.access_violation_counter += 1
                self.diagnostic_code = CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED
                self.is_violation_trip_active = True
            elif err_code == CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE:
                # Blacklisted / Revoked token attempt
                self.revoked_token_attempt_counter += 1
                self.diagnostic_code = CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE
                self.is_violation_trip_active = True
            elif err_code == CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED:
                self.access_violation_counter += 1
                self.diagnostic_code = CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED
                self.is_violation_trip_active = True

            self._refresh_aggregate_state()
            if self.reg_table is not None:
                self.sync_to_registers()
            return False, err_code, None, details

        assert claims is not None

        # Create session
        session_id = f"rbac_sess_{claims.nonce[:8]}_{secrets.token_hex(4)}"
        session = RbacSession(
            session_id=session_id,
            claims=claims,
            established_at_s=self.current_time_s,
            last_activity_s=self.current_time_s,
            is_active=True,
        )
        self.active_sessions[session_id] = session

        # Clear transient trip if now clean
        if self.diagnostic_code in {
            CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED,
            CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED,
            CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE,
        }:
            self.diagnostic_code = CipSecurityRbacDiagnosticCode.OK
            self.is_violation_trip_active = False

        self._refresh_aggregate_state()
        if self.reg_table is not None:
            self.sync_to_registers()

        return True, None, session, f"Authenticated session '{session_id}' established for '{claims.subject}'"

    def close_session(self, session_id: str) -> bool:
        """Terminate an active RBAC session."""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            self._refresh_aggregate_state()
            if self.reg_table is not None:
                self.sync_to_registers()
            return True
        return False

    def revoke_token(self, token_nonce_or_id: str) -> None:
        """Add bearer token nonce to blacklist and terminate associated active sessions."""
        clean_nonce = token_nonce_or_id.strip()
        self.token_blacklist.add(clean_nonce)

        to_remove = [
            sid for sid, s in self.active_sessions.items()
            if s.claims.nonce == clean_nonce or s.claims.subject == clean_nonce
        ]
        for sid in to_remove:
            del self.active_sessions[sid]

        self._refresh_aggregate_state()
        if self.reg_table is not None:
            self.sync_to_registers()

    def authorize_action(
        self,
        session_id: str,
        object_class: int,
        instance_id: int,
        action: CipAction,
    ) -> bool:
        """Verify if active session holds permission to perform action on CIP object/instance."""
        if session_id not in self.active_sessions:
            self.access_violation_counter += 1
            self.diagnostic_code = CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE
            self.is_violation_trip_active = True
            self._refresh_aggregate_state()
            if self.reg_table is not None:
                self.sync_to_registers()
            return False

        session = self.active_sessions[session_id]

        # 1. Expiration check on session
        if session.is_expired(self.current_time_s):
            del self.active_sessions[session_id]
            self.access_violation_counter += 1
            self.diagnostic_code = CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED
            self.is_violation_trip_active = True
            self._refresh_aggregate_state()
            if self.reg_table is not None:
                self.sync_to_registers()
            return False

        # 2. Permission check against Access Control Matrix
        allowed = self.access_matrix.is_allowed(
            roles=session.role_bitmask,
            object_class=object_class,
            instance_id=instance_id,
            action=action,
        )

        session.last_activity_s = self.current_time_s

        if not allowed:
            self.access_violation_counter += 1
            self.diagnostic_code = CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE
            self.is_violation_trip_active = True
            self._refresh_aggregate_state()
            if self.reg_table is not None:
                self.sync_to_registers()
            return False

        return True

    # ------------------------------------------------------------------------
    # Certificate Hierarchy & CRL Operations
    # ------------------------------------------------------------------------

    def validate_certificate(
        self,
        cert: X509CertInfo,
        check_time: Optional[float] = None,
        peer_identity: Optional[str] = None,
    ) -> Tuple[bool, Optional[CipSecurityRbacDiagnosticCode], str]:
        """Validate certificate trust chain and enforce CRL checks."""
        t = self.current_time_s if check_time is None else float(check_time)
        ok, err, msg = self.cert_manager.validate_chain(cert, t, peer_identity)
        if not ok and err is not None:
            self.diagnostic_code = err
            self.is_violation_trip_active = True
            self._refresh_aggregate_state()
            if self.reg_table is not None:
                self.sync_to_registers()
        return ok, err, msg

    def revoke_certificate(self, serial_number: str) -> None:
        """Enroll certificate serial number into CRL and trip if actively used."""
        self.cert_manager.revoke_certificate(serial_number)
        self.cert_management_object.crl_revoked_count = len(self.cert_manager.crl_revoked_serials)
        if self.cert_management_object.active_serial_number.strip().upper() == serial_number.strip().upper():
            self.diagnostic_code = CipSecurityRbacDiagnosticCode.CERTIFICATE_REVOKED
            self.is_violation_trip_active = True
        self._refresh_aggregate_state()
        if self.reg_table is not None:
            self.sync_to_registers()

    # ------------------------------------------------------------------------
    # Fault Handling & Operator Reset
    # ------------------------------------------------------------------------

    def trip_fault(self, code: CipSecurityRbacDiagnosticCode, details: str = "") -> None:
        """Trip security violation interlock and latch diagnostic status code."""
        self.diagnostic_code = code
        self.is_violation_trip_active = True
        self.state = CipSecurityState.SECURITY_LOCKOUT
        self._refresh_aggregate_state()
        if self.reg_table is not None:
            self.sync_to_registers()

    def reset_fault(self, force: bool = False) -> ExecutionResult:
        """Operator manual reset pulse to clear latched faults."""
        self.diagnostic_code = CipSecurityRbacDiagnosticCode.OK
        self.is_violation_trip_active = False

        if self.profile == CipSecurityProfile.NONE:
            self.state = CipSecurityState.FACTORY_DEFAULT
        else:
            self.state = CipSecurityState.SECURE_RUN

        self._refresh_aggregate_state()
        if self.reg_table is not None:
            self.sync_to_registers()

        return ExecutionResult.success(details="Security RBAC fault cleared and diagnostics restored to OK")

    def simulate_token_expired(self) -> None:
        """Simulate bearer token expiration excursion (0xE901)."""
        self.access_violation_counter += 1
        self.trip_fault(
            CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED,
            "Simulated bearer token lifetime expired",
        )

    def simulate_unauthorized_role(self) -> None:
        """Simulate unauthorized role capability access attempt (0xE902)."""
        self.access_violation_counter += 1
        self.trip_fault(
            CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE,
            "Simulated access attempt rejected due to unauthorized role",
        )

    def simulate_signature_failure(self) -> None:
        """Simulate HMAC-SHA256 signature verification failure (0xE903)."""
        self.access_violation_counter += 1
        self.trip_fault(
            CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED,
            "Simulated HMAC-SHA256 bearer token signature forgery or corruption",
        )

    def simulate_certificate_revoked(self) -> None:
        """Simulate X.509 certificate revocation in CRL (0xE904)."""
        self.trip_fault(
            CipSecurityRbacDiagnosticCode.CERTIFICATE_REVOKED,
            "Simulated certificate serial found in Certificate Revocation List (CRL)",
        )

    # ------------------------------------------------------------------------
    # State Synchronization & Register Table
    # ------------------------------------------------------------------------

    def _refresh_aggregate_state(self) -> None:
        """Compute aggregated role bitmask, token lifetime, and coil interlocks."""
        # 1. Aggregate role bitmask
        agg_mask = 0
        min_rem_s = float(MAX_TOKEN_LIFETIME_SEC)
        has_sessions = len(self.active_sessions) > 0

        for sess in self.active_sessions.values():
            agg_mask |= sess.role_bitmask
            rem = sess.remaining_lifetime(self.current_time_s)
            if rem < min_rem_s:
                min_rem_s = rem

        self.active_role_bitmask: int = agg_mask
        self.token_remaining_lifetime_sec: int = int(round(min_rem_s)) if has_sessions else 0
        if self.token_remaining_lifetime_sec > MAX_TOKEN_LIFETIME_SEC:
            self.token_remaining_lifetime_sec = MAX_TOKEN_LIFETIME_SEC
        if self.token_remaining_lifetime_sec < 0:
            self.token_remaining_lifetime_sec = 0

        # 2. Evaluate Discrete Coils
        has_trip = (
            self.is_violation_trip_active
            or (self.diagnostic_code != CipSecurityRbacDiagnosticCode.OK)
            or (self.state == CipSecurityState.SECURITY_LOCKOUT)
        )

        if has_trip:
            self.is_violation_trip_active = True
            self.is_rbac_active = False
            self.state = CipSecurityState.SECURITY_LOCKOUT
        else:
            self.is_violation_trip_active = False
            if self.profile > CipSecurityProfile.NONE and has_sessions:
                self.is_rbac_active = True
                self.state = CipSecurityState.SECURE_RUN
            else:
                self.is_rbac_active = False
                if self.profile == CipSecurityProfile.NONE:
                    self.state = CipSecurityState.FACTORY_DEFAULT
                else:
                    self.state = CipSecurityState.SECURE_RUN

        # 3. Synchronize CIP Objects
        self.rbac_object.profile = int(self.profile)
        self.rbac_object.active_role_mask = self.active_role_bitmask
        self.rbac_object.session_count = min(16, len(self.active_sessions))
        self.rbac_object.token_remaining_lifetime = self.token_remaining_lifetime_sec
        self.rbac_object.access_violations = self.access_violation_counter
        self.rbac_object.revoked_token_attempts = self.revoked_token_attempt_counter
        self.rbac_object.security_state = int(self.state)
        self.rbac_object.diagnostic_code = int(self.diagnostic_code)

        cum_cap = 0
        for r in bitmask_to_roles(self.active_role_bitmask):
            cum_cap |= int(self.access_matrix.default_role_capabilities.get(r, CipAction.NONE))
        self.rbac_object.capabilities_bitmask = cum_cap

        self.cert_management_object.installed_certificate_count = len(self.cert_manager.installed_certs)
        self.cert_management_object.trusted_ca_count = len(self.cert_manager.root_ca_store)
        self.cert_management_object.crl_revoked_count = len(self.cert_manager.crl_revoked_serials)

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Synchronize telemetry state to Horner OCS memory map (%R1780..%R1787, %M415..%M416).

        Register Table Layout:
        - %R1780: ActiveSecurityProfile (0=None, 1=IntegrityOnly, 2=Confidentiality, 3=ConfidentialityAndAuth)
        - %R1781: AuthenticatedSessionCount (INT16, 0..16)
        - %R1782: ActiveRoleBitmask (INT16 bitmask of active session roles)
        - %R1783: TokenRemainingLifetimeSec (INT16, 0..3600 s)
        - %R1784: AccessViolationCounter (INT16)
        - %R1785: RevokedTokenAttemptCounter (INT16)
        - %R1786: SecurityState (0=Unconfigured, 1=FactoryDefault, 2=SecureRun, 3=SecurityLockout)
        - %R1787: DiagnosticStatusCode (0x0000=OK, 0xE901..0xE904)
        - %M415:  CipSecurityRbacActive (BOOL)
        - %M416:  SecurityViolationTripActive (BOOL)
        """
        rt = reg_table if reg_table is not None else self.reg_table
        if rt is None:
            return

        # %R1780: ActiveSecurityProfile (INT16)
        safe_write_word(rt, "%R1780", int(self.profile))

        # %R1781: AuthenticatedSessionCount (INT16, 0..16)
        sess_count = min(16, max(0, len(self.active_sessions)))
        safe_write_word(rt, "%R1781", sess_count)

        # %R1782: ActiveRoleBitmask (INT16)
        safe_write_word(rt, "%R1782", self.active_role_bitmask)

        # %R1783: TokenRemainingLifetimeSec (INT16, 0..3600)
        safe_write_word(rt, "%R1783", self.token_remaining_lifetime_sec)

        # %R1784: AccessViolationCounter (INT16)
        safe_write_word(rt, "%R1784", min(32767, self.access_violation_counter))

        # %R1785: RevokedTokenAttemptCounter (INT16)
        safe_write_word(rt, "%R1785", min(32767, self.revoked_token_attempt_counter))

        # %R1786: SecurityState (INT16, 0..3)
        safe_write_word(rt, "%R1786", int(self.state))

        # %R1787: DiagnosticStatusCode (UINT16, 0x0000, 0xE901..0xE904)
        safe_write_uword(rt, "%R1787", int(self.diagnostic_code))

        # %M415: CipSecurityRbacActive (BOOL)
        safe_write_bit(rt, "%M415", self.is_rbac_active)

        # %M416: SecurityViolationTripActive (BOOL)
        safe_write_bit(rt, "%M416", self.is_violation_trip_active)

    def get_snapshot(self) -> Dict[str, Any]:
        """Capture current telemetry snapshot dictionary."""
        return {
            "profile": int(self.profile),
            "profile_name": self.profile.name,
            "state": int(self.state),
            "state_name": self.state.name,
            "active_sessions_count": len(self.active_sessions),
            "active_role_bitmask": self.active_role_bitmask,
            "token_remaining_lifetime_sec": self.token_remaining_lifetime_sec,
            "access_violation_counter": self.access_violation_counter,
            "revoked_token_attempt_counter": self.revoked_token_attempt_counter,
            "diagnostic_code": int(self.diagnostic_code),
            "diagnostic_code_name": self.diagnostic_code.name,
            "is_rbac_active": self.is_rbac_active,
            "is_violation_trip_active": self.is_violation_trip_active,
            "elapsed_simulation_ms": self.elapsed_simulation_ms,
            "total_scan_cycles": self.total_scan_cycles,
            "sessions": {sid: s.to_dict() for sid, s in self.active_sessions.items()},
        }


CipRbacEngine = CipSecurityRbacEngine
CipSecurityRbac = CipSecurityRbacEngine
CipSecurityRbacProtocolEngine = CipSecurityRbacEngine


# ============================================================================
# 12. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_cip_security_rbac_verification(
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute deterministic 9-stage verification suite for W217.

    Stages:
    1. Pure ST POU Validation & Anti-Ladder Security Guard Interception.
    2. CIP Security Volume 8 Class 0x5D (Cert Management) & Class 0x5E (RBAC) Object Models.
    3. X.509 Certificate Hierarchy (Leaf -> Intermediate -> CA), SAN, & CRL Revocation (0xE904).
    4. Canonical Roles (Administrator, Engineer, Operator, Auditor, ViewOnly) & Capability Bitmasks.
    5. Cryptographically Signed Bearer Token Generation & HMAC-SHA256 Signature Verification (0xE903).
    6. Access Control Matrix (Permission Table) Enforcement & Unauthorized Role Rejection (0xE902).
    7. Token Expiration Watchdog & Token Blacklist Enforcement (0xE901 & Revoked Counter).
    8. Discrete ILogicUnit 100-Cycle Simulation Execution (scan_step, execute, priority, reset).
    9. Horner OCS Register Table Synchronization (%R1780..%R1787, %M415..%M416) & Trip Interlock.
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU Validation & Anti-Ladder Security Guard Interception
    # ------------------------------------------------------------------------
    SecurityGuard.assert_pure_st_content(CIP_SECURITY_RBAC_SYNC_POU)
    val_st = STParser.validate_code(CIP_SECURITY_RBAC_SYNC_POU)
    ast_st = STParser.parse_pou(CIP_SECURITY_RBAC_SYNC_POU)

    # Synthetic ladder logic injection must be firmly rejected
    ladder_corrupted = CIP_SECURITY_RBAC_SYNC_POU + "\n---[ ]------( )---\n"
    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content(ladder_corrupted)
    except LadderForbiddenError:
        ladder_rejected = True

    s1_pass = (
        val_st.status == AgentStatus.SUCCESS
        and ast_st.name == "CipSecurityRbacSync"
        and ast_st.pou_type == POUType.PROGRAM
        and len(ast_st.variables) >= 11
        and "%R1780" in ast_st.bound_registers
        and "%R1787" in ast_st.bound_registers
        and "%M415" in ast_st.bound_registers
        and "%M416" in ast_st.bound_registers
        and ladder_rejected is True
    )
    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_Validation_And_Anti_Ladder_Interception",
        "passed": s1_pass,
        "details": f"POU '{ast_st.name}' compiled with {len(ast_st.variables)} registers; ladder injection rejected.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: CIP Security Volume 8 Class 0x5D & Class 0x5E Object Resolution
    # ------------------------------------------------------------------------
    cert_obj = CertificateManagementObject()
    cert_obj.installed_certificate_count = 3
    cert_obj.trusted_ca_count = 2
    cert_obj.crl_revoked_count = 1
    cert_obj.active_serial_number = "01:23:45:67"
    cert_obj.active_issuer_cn = "Horner Root CA"
    cert_obj.active_subject_cn = "Horner OCS Controller"

    rbac_obj = CipSecurityRbacObject()
    rbac_obj.profile = int(CipSecurityProfile.CONFIDENTIALITY_AND_AUTH)
    rbac_obj.session_count = 4
    rbac_obj.active_role_mask = 0x07
    rbac_obj.token_remaining_lifetime = 1800
    rbac_obj.access_violations = 0
    rbac_obj.revoked_token_attempts = 0
    rbac_obj.security_state = int(CipSecurityState.SECURE_RUN)
    rbac_obj.diagnostic_code = 0x0000

    # Query Class 0x5D attributes 1..9
    c_attrs = [cert_obj.get_attribute_single(i) for i in range(1, 10)]
    c_all = cert_obj.get_attribute_all()

    # Query Class 0x5E attributes 1..10
    r_attrs = [rbac_obj.get_attribute_single(i) for i in range(1, 11)]
    r_all = rbac_obj.get_attribute_all()

    # Read-only test
    ro_rejected = False
    try:
        cert_obj.set_attribute_single(1, 99)
    except PermissionError:
        ro_rejected = True

    s2_pass = (
        len(c_attrs) == 9
        and len(c_all) == 9
        and c_attrs[0] == 1
        and c_attrs[1] == 16
        and c_attrs[2] == 3
        and len(r_attrs) == 10
        and len(r_all) == 10
        and r_attrs[0] == int(CipSecurityProfile.CONFIDENTIALITY_AND_AUTH)
        and r_attrs[1] == 5
        and r_attrs[2] == 0x07
        and ro_rejected is True
    )
    test_results.append({
        "stage": 2,
        "check": "CIP_Security_Object_Models_Class_0x5D_And_0x5E_Resolution",
        "passed": s2_pass,
        "details": f"Class 0x5D (9 attributes) and Class 0x5E (10 attributes) queried and read-only verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: X.509 Certificate Hierarchy, SAN, and CRL Revocation (0xE904)
    # ------------------------------------------------------------------------
    cm = CertificateManager()
    root_ca = X509CertInfo(
        common_name="Horner Industrial Root CA",
        issuer="Horner Industrial Root CA",
        not_before_s=1770000000.0,
        not_after_s=1800000000.0,
        serial_number="CA:01:00:01",
        is_ca=True,
    )
    cm.add_trusted_root_ca(root_ca)

    inter_ca = X509CertInfo(
        common_name="Horner Plant 1 Intermediate CA",
        issuer="Horner Industrial Root CA",
        not_before_s=1771000000.0,
        not_after_s=1790000000.0,
        serial_number="INT:02:00:02",
        is_ca=True,
    )
    cm.add_intermediate_ca(inter_ca)

    valid_leaf = X509CertInfo(
        common_name="controller01.plant1.local",
        issuer="Horner Plant 1 Intermediate CA",
        not_before_s=1774000000.0,
        not_after_s=1780000000.0,
        san=["controller01.plant1.local", "192.168.1.100"],
        serial_number="LF:03:00:03",
        is_ca=False,
    )

    expired_leaf = X509CertInfo(
        common_name="old.plant1.local",
        issuer="Horner Plant 1 Intermediate CA",
        not_before_s=1760000000.0,
        not_after_s=1770000000.0,
        serial_number="LF:04:00:04",
        is_ca=False,
    )

    revoked_leaf = X509CertInfo(
        common_name="compromised.plant1.local",
        issuer="Horner Plant 1 Intermediate CA",
        not_before_s=1774000000.0,
        not_after_s=1780000000.0,
        serial_number="LF:05:00:05",
        is_ca=False,
    )
    cm.revoke_certificate(revoked_leaf.serial_number)

    ok_chain, _, _ = cm.validate_chain(valid_leaf, 1775000000.0, peer_identity="192.168.1.100")
    ok_exp, err_exp, _ = cm.validate_chain(expired_leaf, 1775000000.0)
    ok_rev, err_rev, _ = cm.validate_chain(revoked_leaf, 1775000000.0)
    ok_san, err_san, _ = cm.validate_chain(valid_leaf, 1775000000.0, peer_identity="attacker.rogue.net")

    s3_pass = (
        ok_chain is True
        and ok_exp is False and err_exp == CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED
        and ok_rev is False and err_rev == CipSecurityRbacDiagnosticCode.CERTIFICATE_REVOKED
        and ok_san is False and err_san == CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE
    )
    test_results.append({
        "stage": 3,
        "check": "X509_Certificate_Hierarchy_And_CRL_Revocation_Validation",
        "passed": s3_pass,
        "details": "Trust chain (Root->Intermediate->Leaf), SAN, expired token, and CRL revocation (0xE904) verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Canonical Roles & Capability Bitmask Encoding/Decoding
    # ------------------------------------------------------------------------
    # Verify the 5 canonical roles and their bit positions
    r_admin = role_to_bitmask(CipSecurityRole.ADMINISTRATOR)
    r_eng = role_to_bitmask(CipSecurityRole.ENGINEER)
    r_op = role_to_bitmask(CipSecurityRole.OPERATOR)
    r_audit = role_to_bitmask(CipSecurityRole.AUDITOR)
    r_view = role_to_bitmask(CipSecurityRole.VIEW_ONLY)

    combined_mask = roles_to_bitmask([
        CipSecurityRole.ADMINISTRATOR,
        CipSecurityRole.OPERATOR,
    ])
    decoded_roles = bitmask_to_roles(combined_mask)

    acm = AccessControlMatrix()
    cap_admin = acm.default_role_capabilities[CipSecurityRole.ADMINISTRATOR]
    cap_eng = acm.default_role_capabilities[CipSecurityRole.ENGINEER]
    cap_op = acm.default_role_capabilities[CipSecurityRole.OPERATOR]
    cap_audit = acm.default_role_capabilities[CipSecurityRole.AUDITOR]
    cap_view = acm.default_role_capabilities[CipSecurityRole.VIEW_ONLY]

    s4_pass = (
        r_admin == 0x01
        and r_eng == 0x02
        and r_op == 0x04
        and r_audit == 0x08
        and r_view == 0x10
        and combined_mask == 0x05
        and len(decoded_roles) == 2
        and CipSecurityRole.ADMINISTRATOR in decoded_roles
        and CipSecurityRole.OPERATOR in decoded_roles
        and cap_admin == CipAction.ALL
        and (cap_eng & CipAction.CONFIGURE) != 0
        and (cap_eng & CipAction.FIRMWARE_UPDATE) == 0
        and (cap_op & CipAction.SAFETY_RESET) != 0
        and cap_audit == CipAction.READ
        and cap_view == CipAction.READ
    )
    test_results.append({
        "stage": 4,
        "check": "Canonical_Roles_And_Capability_Bitmasks_Encoding_Decoding",
        "passed": s4_pass,
        "details": "Canonical Roles 1..5, bitmasks 0x01..0x10, and default capability matrices verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Bearer Token Generation & HMAC-SHA256 Signature Verification
    # ------------------------------------------------------------------------
    secret_key = b"stage-5-hmac-sha256-test-key-32bytes!"
    valid_token = create_bearer_token(
        subject="alice.engineer",
        roles=[CipSecurityRole.ENGINEER],
        lifetime_sec=1800.0,
        secret_key=secret_key,
        current_time_s=1775000000.0,
        nonce="nonce_alice_01",
    )

    # 1. Decode valid token
    ok_tok, err_tok, claims_tok, _ = BearerToken.decode(
        token_str=valid_token,
        secret_key=secret_key,
        current_time_s=1775000000.0,
    )

    # 2. Tamper with signature
    parts = valid_token.split(".")
    tampered_sig_token = f"{parts[0]}.{parts[1]}.tampered_sig"
    ok_tamp, err_tamp, _, _ = BearerToken.decode(
        token_str=tampered_sig_token,
        secret_key=secret_key,
        current_time_s=1775000000.0,
    )

    # 3. Wrong secret key
    ok_wrong_key, err_wrong_key, _, _ = BearerToken.decode(
        token_str=valid_token,
        secret_key=b"completely-wrong-secret-key-bytes!",
        current_time_s=1775000000.0,
    )

    s5_pass = (
        ok_tok is True
        and claims_tok is not None
        and claims_tok.subject == "alice.engineer"
        and claims_tok.roles == [CipSecurityRole.ENGINEER]
        and ok_tamp is False
        and err_tamp == CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED
        and ok_wrong_key is False
        and err_wrong_key == CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED
    )
    test_results.append({
        "stage": 5,
        "check": "Signed_Bearer_Token_Generation_And_HMAC_SHA256_Verification",
        "passed": s5_pass,
        "details": "HMAC-SHA256 token claims validated; tampering and incorrect secret trip 0xE903.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Access Control Matrix Enforcement & Unauthorized Role Rejection
    # ------------------------------------------------------------------------
    engine_rbac = CipSecurityRbacEngine(
        current_time_s=1775000000.0,
        secret_key=secret_key,
    )

    tok_op = create_bearer_token(
        subject="bob.operator",
        roles=[CipSecurityRole.OPERATOR],
        lifetime_sec=1800.0,
        secret_key=secret_key,
        current_time_s=1775000000.0,
    )
    ok_sess_op, _, sess_op, _ = engine_rbac.authenticate_token(tok_op)
    assert sess_op is not None

    tok_audit = create_bearer_token(
        subject="charlie.auditor",
        roles=[CipSecurityRole.AUDITOR],
        lifetime_sec=1800.0,
        secret_key=secret_key,
        current_time_s=1775000000.0,
    )
    ok_sess_audit, _, sess_audit, _ = engine_rbac.authenticate_token(tok_audit)
    assert sess_audit is not None

    # Operator: permitted Read on Assembly, permitted SafetyReset on Safety Supervisor
    auth_op_read = engine_rbac.authorize_action(sess_op.session_id, CIP_ASSEMBLY_CLASS_ID, 1, CipAction.READ)
    auth_op_write = engine_rbac.authorize_action(sess_op.session_id, CIP_ASSEMBLY_CLASS_ID, 1, CipAction.WRITE)
    auth_op_reset = engine_rbac.authorize_action(sess_op.session_id, CIP_SAFETY_SUPERVISOR_CLASS_ID, 1, CipAction.SAFETY_RESET)

    # Operator: forbidden FirmwareUpdate on Identity object -> triggers 0xE902
    auth_op_fw = engine_rbac.authorize_action(sess_op.session_id, CIP_IDENTITY_CLASS_ID, 1, CipAction.FIRMWARE_UPDATE)
    err_op_fw = engine_rbac.diagnostic_code

    # Auditor: forbidden Write on Assembly object -> triggers 0xE902
    auth_audit_write = engine_rbac.authorize_action(sess_audit.session_id, CIP_ASSEMBLY_CLASS_ID, 1, CipAction.WRITE)

    s6_pass = (
        auth_op_read is True
        and auth_op_write is True
        and auth_op_reset is True
        and auth_op_fw is False
        and err_op_fw == CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE
        and auth_audit_write is False
        and engine_rbac.access_violation_counter >= 2
        and engine_rbac.is_violation_trip_active is True
    )
    test_results.append({
        "stage": 6,
        "check": "Access_Control_Matrix_Enforcement_And_Unauthorized_Role_Rejection",
        "passed": s6_pass,
        "details": "Fine-grained permissions verified: unauthorized actions rejected with 0xE902.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Token Expiration Watchdog & Token Blacklist Enforcement
    # ------------------------------------------------------------------------
    engine_watchdog = CipSecurityRbacEngine(
        current_time_s=1775000000.0,
        secret_key=secret_key,
    )

    # 1. Blacklist check
    revoked_nonce = "blacklisted_nonce_99"
    tok_blacklisted = create_bearer_token(
        subject="mallory.revoked",
        roles=[CipSecurityRole.ADMINISTRATOR],
        lifetime_sec=1800.0,
        secret_key=secret_key,
        current_time_s=1775000000.0,
        nonce=revoked_nonce,
    )
    engine_watchdog.revoke_token(revoked_nonce)

    ok_auth_bl, err_bl, _, _ = engine_watchdog.authenticate_token(tok_blacklisted)
    bl_counter_incremented = (engine_watchdog.revoked_token_attempt_counter == 1)

    # 2. Token expiration in scan_step
    tok_short = create_bearer_token(
        subject="dave.temporary",
        roles=[CipSecurityRole.OPERATOR],
        lifetime_sec=2.0,  # 2 seconds only
        secret_key=secret_key,
        current_time_s=1775000000.0,
    )
    ok_auth_short, _, sess_short, _ = engine_watchdog.authenticate_token(tok_short)
    assert sess_short is not None

    # Step simulation clock forward 3 seconds (past expiration)
    engine_watchdog.scan_step(dt=3.0)

    s7_pass = (
        ok_auth_bl is False
        and err_bl == CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE
        and bl_counter_incremented is True
        and ok_auth_short is True
        and sess_short.session_id not in engine_watchdog.active_sessions
        and engine_watchdog.diagnostic_code == CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED
        and engine_watchdog.is_violation_trip_active is True
    )
    test_results.append({
        "stage": 7,
        "check": "Token_Expiration_Watchdog_And_Token_Blacklist_Enforcement",
        "passed": s7_pass,
        "details": "Revoked token attempt counted in %R1785; expired token purged and tripped with 0xE901.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Discrete ILogicUnit 100-Cycle Simulation
    # ------------------------------------------------------------------------
    engine_sim = CipSecurityRbacEngine(
        current_time_s=1775000000.0,
        secret_key=secret_key,
    )

    tok_long = create_bearer_token(
        subject="system.service",
        roles=[CipSecurityRole.ENGINEER],
        lifetime_sec=100.0,
        secret_key=secret_key,
        current_time_s=1775000000.0,
    )
    engine_sim.authenticate_token(tok_long)

    # Execute 100 scan cycles of 10 ms (1.0 s total simulation time)
    for _ in range(100):
        ctx = ScanContext(dt_ms=10.0)
        engine_sim.execute(ctx)

    s8_pass = (
        engine_sim.name == "CipSecurityRbacEngine"
        and engine_sim.priority == 96
        and engine_sim.is_enabled is True
        and engine_sim.total_scan_cycles == 100
        and round(engine_sim.elapsed_simulation_ms) == 1000
        and engine_sim.token_remaining_lifetime_sec == 99
    )
    test_results.append({
        "stage": 8,
        "check": "Discrete_ILogicUnit_100_Cycle_Simulation_Execution",
        "passed": s8_pass,
        "details": f"100 scan cycles executed cleanly; simulation time={engine_sim.elapsed_simulation_ms}ms.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Horner OCS Register Table Synchronization & Safety Trip Interlocks
    # ------------------------------------------------------------------------
    rt = RegisterTable()
    engine_rt = CipSecurityRbacEngine(
        reg_table=rt,
        current_time_s=1775000000.0,
        secret_key=secret_key,
    )

    tok_admin = create_bearer_token(
        subject="admin01",
        roles=[CipSecurityRole.ADMINISTRATOR],
        lifetime_sec=1200.0,
        secret_key=secret_key,
        current_time_s=1775000000.0,
    )
    engine_rt.authenticate_token(tok_admin)

    # Verify normal synchronized state
    r1780 = rt.read_word("%R1780")
    r1781 = rt.read_word("%R1781")
    r1782 = rt.read_word("%R1782")
    r1783 = rt.read_word("%R1783")
    r1786 = rt.read_word("%R1786")
    r1787 = rt.read_uword("%R1787")
    m415 = rt.read_bit("%M415")
    m416 = rt.read_bit("%M416")

    sync_healthy = (
        r1780 == int(CipSecurityProfile.CONFIDENTIALITY_AND_AUTH)
        and r1781 == 1
        and r1782 == 0x01
        and r1783 == 1200
        and r1786 == int(CipSecurityState.SECURE_RUN)
        and r1787 == 0x0000
        and m415 is True
        and m416 is False
    )

    # 1. Simulate Token Expired trip (0xE901)
    engine_rt.simulate_token_expired()
    t1 = (
        rt.read_uword("%R1787") == 0xE901
        and rt.read_bit("%M416") is True
        and rt.read_bit("%M415") is False
    )

    # 2. Simulate Unauthorized Role trip (0xE902)
    engine_rt.simulate_unauthorized_role()
    t2 = (
        rt.read_uword("%R1787") == 0xE902
        and rt.read_bit("%M416") is True
    )

    # 3. Simulate Signature Verification Failure trip (0xE903)
    engine_rt.simulate_signature_failure()
    t3 = (
        rt.read_uword("%R1787") == 0xE903
        and rt.read_bit("%M416") is True
    )

    # 4. Simulate Certificate Revoked trip (0xE904)
    engine_rt.simulate_certificate_revoked()
    t4 = (
        rt.read_uword("%R1787") == 0xE904
        and rt.read_bit("%M416") is True
    )

    # 5. Operator Reset Recovery
    res_reset = engine_rt.reset_fault(force=True)
    t5 = (
        res_reset.status == AgentStatus.SUCCESS
        and rt.read_uword("%R1787") == 0x0000
        and rt.read_bit("%M416") is False
        and rt.read_bit("%M415") is True
        and rt.read_word("%R1786") == int(CipSecurityState.SECURE_RUN)
    )

    s9_pass = sync_healthy and t1 and t2 and t3 and t4 and t5
    test_results.append({
        "stage": 9,
        "check": "Horner_OCS_Register_Table_Synchronization_And_Safety_Trips",
        "passed": s9_pass,
        "details": "%R1780..%R1787, %M415, %M416 mapped cleanly; 0xE901..0xE904 trips and reset verified.",
    })

    # ------------------------------------------------------------------------
    # Evidence Assembly & Contract JSON
    # ------------------------------------------------------------------------
    passed_count = sum(1 for t in test_results if t["passed"])
    total_stages = len(test_results)
    all_passed = (passed_count == total_stages)

    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_FAILED",
        "details": f"CIP Security RBAC & Token Authorization Protocol Engine (W217) verified cleanly ({passed_count}/{total_stages} stages passed).",
        "stages_passed": passed_count,
        "total_stages": total_stages,
        "data": {
            "work_package": "W217",
            "standards": [
                "ODVA CIP Networks Library Volume 8: CIP Security Specification",
                "ODVA Volume 8 Table 5-2: Security Roles & Capability Bitmasks",
                "IEC 61131-3 Structured Text",
            ],
            "stages": test_results,
            "tests": test_results,
            "checks_passed": passed_count,
            "total_checks": total_stages,
            "register_map": {
                "%R1780": "ActiveSecurityProfile",
                "%R1781": "AuthenticatedSessionCount",
                "%R1782": "ActiveRoleBitmask",
                "%R1783": "TokenRemainingLifetimeSec",
                "%R1784": "AccessViolationCounter",
                "%R1785": "RevokedTokenAttemptCounter",
                "%R1786": "SecurityState",
                "%R1787": "DiagnosticStatusCode",
                "%M415": "CipSecurityRbacActive",
                "%M416": "SecurityViolationTripActive",
            },
            "registers": {
                "%R1780": rt.read_word("%R1780"),
                "%R1781": rt.read_word("%R1781"),
                "%R1782": rt.read_word("%R1782"),
                "%R1783": rt.read_word("%R1783"),
                "%R1784": rt.read_word("%R1784"),
                "%R1785": rt.read_word("%R1785"),
                "%R1786": rt.read_word("%R1786"),
                "%R1787": rt.read_uword("%R1787"),
                "%M415": rt.read_bit("%M415"),
                "%M416": rt.read_bit("%M416"),
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
