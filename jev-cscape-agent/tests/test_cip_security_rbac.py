"""Comprehensive Unit and Integration Test Suite for W217 CIP Security RBAC Protocol Engine.

Work Package: W217 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers 60+ Unit Tests across 11 Sections:
1. Section 1: Constants, Enums, Security Profiles, & Role Definitions (Administrator..ViewOnly).
2. Section 2: Pure ST POU AST Parsing, Symbol Binding, & Anti-Ladder Security Guard (%R1780..%R1787, %M415..%M416).
3. Section 3: Bearer Token HMAC-SHA256 Generation, Verification, Claims Parsing, & Tampering Rejection.
4. Section 4: Expiration Watchdog Enforcement and Token Expired Trip (0xE901).
5. Section 5: Role-Based Authorization Matrix & Unauthorized Role Access Trip (0xE902).
6. Section 6: Signature Validation Failure and Forged Token Trip (0xE903).
7. Section 7: CRL Certificate Revocation & Blacklisted Token Trip (0xE904).
8. Section 8: Safe-State Clamp on Security Violation Asserting %M416 & Updating Status.
9. Section 9: Horner OCS Register Synchronization (%R1780..%R1787, %M415..%M416) with PrivilegeMode.SYSTEM.
10. Section 10: ILogicUnit scan_step Cycle Integration and Reset.
11. Section 11: 9-Stage Verification Runner run_cip_security_rbac_verification Deterministic Execution & JSON Export.
"""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any, Dict, List, Set
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_security_rbac import (
    CIP_CERTIFICATE_MANAGEMENT_CLASS_ID,
    CIP_SECURITY_RBAC_CLASS_ID,
    CIP_SECURITY_RBAC_POU,
    CIP_SECURITY_RBAC_SYNC_POU,
    CIP_SECURITY_RBAC_TCP_PORT,
    CIP_SECURITY_RBAC_UDP_PORT,
    DEFAULT_BASE_TIME_S,
    DEFAULT_TOKEN_SECRET,
    MAX_AUTHENTICATED_SESSIONS,
    MAX_TOKEN_LIFETIME_SEC,
    AccessControlMatrix,
    BearerToken,
    BearerTokenClaims,
    CertificateManagementObject,
    CertificateManager,
    CipAction,
    CipRbacAction,
    CipRbacEngine,
    CipRbacSessionState,
    CipRole,
    CipSecurityProfile,
    CipSecurityRbac,
    CipSecurityRbacDiagnosticCode,
    CipSecurityRbacEngine,
    CipSecurityRbacError,
    CipSecurityRbacForgedTokenError,
    CipSecurityRbacObject,
    CipSecurityRbacProtocolEngine,
    CipSecurityRbacTokenExpiredError,
    CipSecurityRbacTokenRevokedError,
    CipSecurityRbacUnauthorizedRoleError,
    CipSecurityRole,
    CipSecurityState,
    CrlManager,
    RbacAuthorizationMatrix,
    RbacSession,
    RoleBitmask,
    TokenClaims,
    X509CertInfo,
    bitmask_to_roles,
    create_bearer_token,
    extract_bearer_token,
    generate_bearer_token,
    parse_token_claims,
    role_to_bitmask,
    roles_to_bitmask,
    run_cip_security_rbac_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    verify_bearer_token,
    verify_cip_security_rbac_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provide a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def rbac_engine(register_table: RegisterTable) -> CipSecurityRbacEngine:
    """Provide a fresh CipSecurityRbacEngine bound to a register table."""
    return CipSecurityRbacEngine(
        reg_table=register_table,
        security_profile=CipSecurityProfile.CONFIDENTIALITY_AND_AUTH,
        current_time_s=DEFAULT_BASE_TIME_S,
        secret_key=DEFAULT_TOKEN_SECRET,
    )


# ============================================================================
# Section 1: Constants, Enums, Profiles, & Role Definitions
# ============================================================================

class TestSection1ConstantsAndEnums:
    """Validate ODVA Volume 8 CIP Security protocol constants, enums, and role mappings."""

    def test_class_ids_and_ports(self) -> None:
        assert CIP_CERTIFICATE_MANAGEMENT_CLASS_ID == 0x5D
        assert CIP_SECURITY_RBAC_CLASS_ID == 0x5E
        assert CIP_SECURITY_RBAC_TCP_PORT == 44818
        assert CIP_SECURITY_RBAC_UDP_PORT == 2222

    def test_session_and_timing_defaults(self) -> None:
        assert MAX_AUTHENTICATED_SESSIONS == 16
        assert MAX_TOKEN_LIFETIME_SEC == 3600
        assert DEFAULT_BASE_TIME_S == 1775000000.0
        assert isinstance(DEFAULT_TOKEN_SECRET, bytes)

    def test_security_profiles_and_aliases(self) -> None:
        assert CipSecurityProfile.NONE == 0
        assert CipSecurityProfile.INTEGRITY_ONLY == 1
        assert CipSecurityProfile.CONFIDENTIALITY == 2
        assert CipSecurityProfile.CONFIDENTIALITY_AND_AUTH == 3

        # Compatibility aliases
        assert CipSecurityProfile.FactoryDefault == 0
        assert CipSecurityProfile.IntegrityOnly == 1
        assert CipSecurityProfile.Confidentiality == 2
        assert CipSecurityProfile.ConfidentialityAndAuth == 3

    def test_canonical_roles_odva_volume_8(self) -> None:
        assert CipSecurityRole.ADMINISTRATOR == 1
        assert CipSecurityRole.ENGINEER == 2
        assert CipSecurityRole.OPERATOR == 3
        assert CipSecurityRole.AUDITOR == 4
        assert CipSecurityRole.VIEW_ONLY == 5

        # Type aliases
        assert CipRole.ADMINISTRATOR == 1
        assert CipRole.VIEW_ONLY == 5

    def test_role_bitmask_flags(self) -> None:
        assert RoleBitmask.NONE == 0x00
        assert RoleBitmask.ADMINISTRATOR == 1 << 0
        assert RoleBitmask.ENGINEER == 1 << 1
        assert RoleBitmask.OPERATOR == 1 << 2
        assert RoleBitmask.AUDITOR == 1 << 3
        assert RoleBitmask.VIEW_ONLY == 1 << 4
        assert RoleBitmask.ALL == 0x1F

    def test_role_to_bitmask_conversions(self) -> None:
        assert role_to_bitmask(CipSecurityRole.ADMINISTRATOR) == 0x01
        assert role_to_bitmask(CipSecurityRole.ENGINEER) == 0x02
        assert role_to_bitmask(CipSecurityRole.OPERATOR) == 0x04
        assert role_to_bitmask(CipSecurityRole.AUDITOR) == 0x08
        assert role_to_bitmask(CipSecurityRole.VIEW_ONLY) == 0x10
        assert role_to_bitmask("ADMINISTRATOR") == 0x01
        assert role_to_bitmask("view_only") == 0x10

    def test_roles_to_bitmask_and_bitmask_to_roles(self) -> None:
        roles = [CipSecurityRole.ADMINISTRATOR, CipSecurityRole.OPERATOR]
        mask = roles_to_bitmask(roles)
        assert mask == 0x05  # 0x01 | 0x04

        decoded = bitmask_to_roles(mask)
        assert CipSecurityRole.ADMINISTRATOR in decoded
        assert CipSecurityRole.OPERATOR in decoded
        assert len(decoded) == 2

    def test_cip_action_capability_bitmasks(self) -> None:
        assert CipAction.NONE == 0x00
        assert CipAction.READ == 1 << 0
        assert CipAction.WRITE == 1 << 1
        assert CipAction.CONFIGURE == 1 << 2
        assert CipAction.FIRMWARE_UPDATE == 1 << 3
        assert CipAction.SAFETY_RESET == 1 << 4
        assert CipAction.ALL == 0x1F

        # Aliases
        assert CipRbacAction.READ == 1 << 0
        assert CipRbacAction.WRITE == 1 << 1

    def test_security_states_and_aliases(self) -> None:
        assert CipSecurityState.UNCONFIGURED == 0
        assert CipSecurityState.FACTORY_DEFAULT == 1
        assert CipSecurityState.SECURE_RUN == 2
        assert CipSecurityState.SECURITY_LOCKOUT == 3

        # Aliases
        assert CipRbacSessionState.SECURE_RUN == 2

    def test_diagnostic_codes_and_aliases(self) -> None:
        assert CipSecurityRbacDiagnosticCode.OK == 0x0000
        assert CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED == 0xE901
        assert CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE == 0xE902
        assert CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED == 0xE903
        assert CipSecurityRbacDiagnosticCode.CERTIFICATE_REVOKED == 0xE904

        # Error Aliases
        assert CipSecurityRbacDiagnosticCode.ERR_TOKEN_EXPIRED == 0xE901
        assert CipSecurityRbacDiagnosticCode.ERR_UNAUTHORIZED_ROLE == 0xE902
        assert CipSecurityRbacDiagnosticCode.ERR_SIGNATURE_FAILED == 0xE903
        assert CipSecurityRbacDiagnosticCode.ERR_CERT_REVOKED == 0xE904


# ============================================================================
# Section 2: Pure ST POU Validation & Anti-Ladder Security Guard
# ============================================================================

class TestSection2PureSTPOU:
    """Verify IEC 61131-3 Pure Structured Text POU and Anti-Ladder Security Guard."""

    def test_verify_cip_security_rbac_pure_st_helper(self) -> None:
        assert verify_cip_security_rbac_pure_st() is True

    def test_security_guard_pure_st_content(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_SECURITY_RBAC_SYNC_POU)

    def test_st_parser_pou_validation(self) -> None:
        result = STParser.validate_code(CIP_SECURITY_RBAC_SYNC_POU)
        assert result.status == AgentStatus.SUCCESS

    def test_st_parser_ast_and_bound_registers(self) -> None:
        ast = STParser.parse_pou(CIP_SECURITY_RBAC_SYNC_POU)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "CipSecurityRbacSync"
        expected_regs = {
            "%R1780", "%R1781", "%R1782", "%R1783",
            "%R1784", "%R1785", "%R1786", "%R1787",
            "%M415", "%M416",
        }
        for reg in expected_regs:
            assert reg in ast.bound_registers

    def test_anti_ladder_contacts_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR END_VAR\n  ---[ ]---( )---\nEND_PROGRAM")

    def test_anti_ladder_coils_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR END_VAR\n  ---(S)---\nEND_PROGRAM")

    def test_anti_ladder_rungs_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR END_VAR\n  RUNG 1: XIC(Start) OTE(Motor);\nEND_PROGRAM")

    def test_anti_ladder_network_delimiter_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test VAR END_VAR\n  NETWORK 1\nEND_PROGRAM")


# ============================================================================
# Section 3: Bearer Token HMAC-SHA256 Generation & Tampering Rejection
# ============================================================================

class TestSection3BearerTokenHMAC:
    """Validate Bearer Token encoding, decoding, claims parsing, and tampering rejection."""

    def test_claims_serialization_roundtrip(self) -> None:
        claims = BearerTokenClaims(
            subject="operator_alice",
            roles=[CipSecurityRole.OPERATOR],
            issued_at=DEFAULT_BASE_TIME_S,
            expires_at=DEFAULT_BASE_TIME_S + 3600.0,
            nonce="nonce_12345678",
        )
        d = claims.to_dict()
        assert d["sub"] == "operator_alice"
        assert d["roles"] == [3]
        assert claims.role_bitmask == 0x04

        j = claims.to_json()
        assert "operator_alice" in j

    def test_claims_lifetime_and_expiration(self) -> None:
        claims = BearerTokenClaims(
            subject="test_user",
            roles=[CipSecurityRole.VIEW_ONLY],
            issued_at=1000.0,
            expires_at=1100.0,
            nonce="nonce_test",
        )
        assert claims.remaining_lifetime(1050.0) == 50.0
        assert claims.remaining_lifetime(1150.0) == 0.0
        assert claims.is_expired(1099.9) is False
        assert claims.is_expired(1100.0) is True
        assert claims.is_expired(1101.0) is True

    def test_generate_and_verify_bearer_token(self) -> None:
        token = create_bearer_token(
            subject="engineer_bob",
            roles=[CipSecurityRole.ENGINEER],
            lifetime_sec=1800.0,
            secret_key=DEFAULT_TOKEN_SECRET,
            current_time_s=DEFAULT_BASE_TIME_S,
        )
        assert token.count(".") == 2

        ok, err, claims, details = verify_bearer_token(
            token_str=token,
            secret_key=DEFAULT_TOKEN_SECRET,
            current_time_s=DEFAULT_BASE_TIME_S + 100.0,
        )
        assert ok is True
        assert err is None
        assert claims is not None
        assert claims.subject == "engineer_bob"
        assert claims.roles == [CipSecurityRole.ENGINEER]

    def test_verify_bearer_token_with_authorization_header_prefix(self) -> None:
        token = create_bearer_token(
            subject="admin_carol",
            roles=[CipSecurityRole.ADMINISTRATOR],
            secret_key=DEFAULT_TOKEN_SECRET,
            current_time_s=DEFAULT_BASE_TIME_S,
        )
        header_val = f"Bearer {token}"
        ok, err, claims, _ = verify_bearer_token(
            token_str=header_val,
            secret_key=DEFAULT_TOKEN_SECRET,
            current_time_s=DEFAULT_BASE_TIME_S,
        )
        assert ok is True
        assert claims is not None
        assert claims.subject == "admin_carol"

    def test_parse_token_claims_unverified(self) -> None:
        token = create_bearer_token(
            subject="auditor_dan",
            roles=[CipSecurityRole.AUDITOR],
            secret_key=DEFAULT_TOKEN_SECRET,
            current_time_s=DEFAULT_BASE_TIME_S,
        )
        parsed = parse_token_claims(token)
        assert parsed.subject == "auditor_dan"
        assert parsed.roles == [CipSecurityRole.AUDITOR]

    def test_tampered_payload_rejection(self) -> None:
        token = create_bearer_token(
            subject="view_only_user",
            roles=[CipSecurityRole.VIEW_ONLY],
            secret_key=DEFAULT_TOKEN_SECRET,
            current_time_s=DEFAULT_BASE_TIME_S,
        )
        parts = token.split(".")
        # Tamper payload part by altering one character
        tampered_payload = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")
        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

        ok, err, _, details = verify_bearer_token(
            token_str=tampered_token,
            secret_key=DEFAULT_TOKEN_SECRET,
            current_time_s=DEFAULT_BASE_TIME_S,
        )
        assert ok is False
        assert err == CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED
        assert "tampered" in details.lower() or "signature" in details.lower()

    def test_tampered_signature_rejection(self) -> None:
        token = create_bearer_token(
            subject="operator_user",
            roles=[CipSecurityRole.OPERATOR],
            secret_key=DEFAULT_TOKEN_SECRET,
            current_time_s=DEFAULT_BASE_TIME_S,
        )
        parts = token.split(".")
        tampered_sig = parts[2][:-1] + ("X" if parts[2][-1] != "X" else "Y")
        tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

        ok, err, _, _ = verify_bearer_token(
            token_str=tampered_token,
            secret_key=DEFAULT_TOKEN_SECRET,
            current_time_s=DEFAULT_BASE_TIME_S,
        )
        assert ok is False
        assert err == CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED

    def test_incorrect_secret_key_rejection(self) -> None:
        token = create_bearer_token(
            subject="admin_user",
            roles=[CipSecurityRole.ADMINISTRATOR],
            secret_key=b"correct-secret-key-111",
            current_time_s=DEFAULT_BASE_TIME_S,
        )
        ok, err, _, _ = verify_bearer_token(
            token_str=token,
            secret_key=b"attacker-wrong-secret-222",
            current_time_s=DEFAULT_BASE_TIME_S,
        )
        assert ok is False
        assert err == CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED

    def test_malformed_token_parts_rejection(self) -> None:
        ok, err, _, _ = verify_bearer_token(
            token_str="invalid_header_payload_missing_signature",
            secret_key=DEFAULT_TOKEN_SECRET,
            current_time_s=DEFAULT_BASE_TIME_S,
        )
        assert ok is False
        assert err == CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED


# ============================================================================
# Section 4: Expiration Watchdog & Token Expired Trip (0xE901)
# ============================================================================

class TestSection4ExpirationWatchdog:
    """Verify bearer token lifetime tracking, watchdog enforcement, and 0xE901 trip."""

    def test_verify_bearer_token_expired_fails(self) -> None:
        token = create_bearer_token(
            subject="expiring_user",
            roles=[CipSecurityRole.OPERATOR],
            lifetime_sec=100.0,
            secret_key=DEFAULT_TOKEN_SECRET,
            current_time_s=1000.0,
        )
        # Check before expiration (valid)
        ok, err, _, _ = verify_bearer_token(token, DEFAULT_TOKEN_SECRET, current_time_s=1090.0)
        assert ok is True

        # Check after expiration (expired)
        ok, err, _, details = verify_bearer_token(token, DEFAULT_TOKEN_SECRET, current_time_s=1101.0)
        assert ok is False
        assert err == CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED
        assert "expired" in details.lower()

    def test_engine_scan_step_watchdog_purges_expired_sessions(self, rbac_engine: CipSecurityRbacEngine) -> None:
        tok = create_bearer_token(
            subject="short_lived_user",
            roles=[CipSecurityRole.OPERATOR],
            lifetime_sec=10.0,
            secret_key=rbac_engine.secret_key,
            current_time_s=rbac_engine.current_time_s,
        )
        ok, _, sess, _ = rbac_engine.authenticate_token(tok)
        assert ok is True
        assert sess is not None
        assert len(rbac_engine.active_sessions) == 1

        # Advance scan clock past expiration (15 seconds)
        rbac_engine.scan_step(15.0)

        assert len(rbac_engine.active_sessions) == 0
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED
        assert rbac_engine.is_violation_trip_active is True
        assert rbac_engine.access_violation_counter >= 1

    def test_authorize_action_on_expired_session_trips_0xE901(self, rbac_engine: CipSecurityRbacEngine) -> None:
        tok = create_bearer_token(
            subject="exp_test_op",
            roles=[CipSecurityRole.OPERATOR],
            lifetime_sec=5.0,
            secret_key=rbac_engine.secret_key,
            current_time_s=rbac_engine.current_time_s,
        )
        ok, _, sess, _ = rbac_engine.authenticate_token(tok)
        assert ok is True
        assert sess is not None

        # Advance current time directly without scan_step
        rbac_engine.current_time_s += 10.0

        # Attempt authorization
        allowed = rbac_engine.authorize_action(
            session_id=sess.session_id,
            object_class=0x04,
            instance_id=1,
            action=CipAction.READ,
        )
        assert allowed is False
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED
        assert rbac_engine.is_violation_trip_active is True
        assert sess.session_id not in rbac_engine.active_sessions

    def test_simulate_token_expired_asserts_0xE901(self, rbac_engine: CipSecurityRbacEngine) -> None:
        rbac_engine.simulate_token_expired()
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.TOKEN_EXPIRED
        assert rbac_engine.is_violation_trip_active is True
        assert rbac_engine.state == CipSecurityState.SECURITY_LOCKOUT


# ============================================================================
# Section 5: Role-Based Authorization Matrix & Unauthorized Role Trip (0xE902)
# ============================================================================

class TestSection5AuthorizationMatrix:
    """Verify role-based access matrix and 0xE902 unauthorized role access rejection."""

    def test_access_matrix_default_view_only(self) -> None:
        matrix = AccessControlMatrix()
        # ViewOnly role can READ but cannot WRITE or CONFIGURE
        assert matrix.is_allowed(RoleBitmask.VIEW_ONLY, 0x04, 1, CipAction.READ) is True
        assert matrix.is_allowed(RoleBitmask.VIEW_ONLY, 0x04, 1, CipAction.WRITE) is False
        assert matrix.is_allowed(RoleBitmask.VIEW_ONLY, 0x64, 1, CipAction.CONFIGURE) is False
        assert matrix.is_allowed(RoleBitmask.VIEW_ONLY, 0x39, 1, CipAction.SAFETY_RESET) is False

    def test_access_matrix_default_operator(self) -> None:
        matrix = AccessControlMatrix()
        # Operator can READ, WRITE, and SAFETY_RESET, but cannot CONFIGURE or FIRMWARE_UPDATE
        assert matrix.is_allowed(RoleBitmask.OPERATOR, 0x04, 1, CipAction.READ) is True
        assert matrix.is_allowed(RoleBitmask.OPERATOR, 0x04, 1, CipAction.WRITE) is True
        assert matrix.is_allowed(RoleBitmask.OPERATOR, 0x39, 1, CipAction.SAFETY_RESET) is True
        assert matrix.is_allowed(RoleBitmask.OPERATOR, 0x64, 1, CipAction.CONFIGURE) is False
        assert matrix.is_allowed(RoleBitmask.OPERATOR, 0x01, 1, CipAction.FIRMWARE_UPDATE) is False

    def test_access_matrix_default_engineer(self) -> None:
        matrix = AccessControlMatrix()
        # Engineer can READ, WRITE, and CONFIGURE, but cannot FIRMWARE_UPDATE or SAFETY_RESET
        assert matrix.is_allowed(RoleBitmask.ENGINEER, 0x04, 1, CipAction.READ) is True
        assert matrix.is_allowed(RoleBitmask.ENGINEER, 0x04, 1, CipAction.WRITE) is True
        assert matrix.is_allowed(RoleBitmask.ENGINEER, 0x64, 1, CipAction.CONFIGURE) is True
        assert matrix.is_allowed(RoleBitmask.ENGINEER, 0x01, 1, CipAction.FIRMWARE_UPDATE) is False

    def test_access_matrix_default_administrator(self) -> None:
        matrix = AccessControlMatrix()
        # Administrator has ALL permissions
        assert matrix.is_allowed(RoleBitmask.ADMINISTRATOR, 0x04, 1, CipAction.READ) is True
        assert matrix.is_allowed(RoleBitmask.ADMINISTRATOR, 0x04, 1, CipAction.WRITE) is True
        assert matrix.is_allowed(RoleBitmask.ADMINISTRATOR, 0x64, 1, CipAction.CONFIGURE) is True
        assert matrix.is_allowed(RoleBitmask.ADMINISTRATOR, 0x01, 1, CipAction.FIRMWARE_UPDATE) is True
        assert matrix.is_allowed(RoleBitmask.ADMINISTRATOR, 0x39, 1, CipAction.SAFETY_RESET) is True

    def test_engine_authorize_action_success_for_authorized_role(self, rbac_engine: CipSecurityRbacEngine) -> None:
        tok = create_bearer_token(
            subject="operator_bob",
            roles=[CipSecurityRole.OPERATOR],
            secret_key=rbac_engine.secret_key,
            current_time_s=rbac_engine.current_time_s,
        )
        ok, _, sess, _ = rbac_engine.authenticate_token(tok)
        assert ok is True
        assert sess is not None

        # Write setpoint is permitted for Operator
        allowed = rbac_engine.authorize_action(
            session_id=sess.session_id,
            object_class=0x04,
            instance_id=1,
            action=CipAction.WRITE,
        )
        assert allowed is True
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.OK
        assert rbac_engine.is_violation_trip_active is False

    def test_engine_authorize_action_failure_trips_0xE902(self, rbac_engine: CipSecurityRbacEngine) -> None:
        tok = create_bearer_token(
            subject="view_only_charlie",
            roles=[CipSecurityRole.VIEW_ONLY],
            secret_key=rbac_engine.secret_key,
            current_time_s=rbac_engine.current_time_s,
        )
        ok, _, sess, _ = rbac_engine.authenticate_token(tok)
        assert ok is True
        assert sess is not None

        # Write setpoint is FORBIDDEN for ViewOnly
        allowed = rbac_engine.authorize_action(
            session_id=sess.session_id,
            object_class=0x04,
            instance_id=1,
            action=CipAction.WRITE,
        )
        assert allowed is False
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE
        assert rbac_engine.is_violation_trip_active is True
        assert rbac_engine.access_violation_counter >= 1

    def test_engine_authorize_action_unknown_session_trips_0xE902(self, rbac_engine: CipSecurityRbacEngine) -> None:
        allowed = rbac_engine.authorize_action(
            session_id="non_existent_session_id",
            object_class=0x04,
            instance_id=1,
            action=CipAction.READ,
        )
        assert allowed is False
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE
        assert rbac_engine.is_violation_trip_active is True

    def test_simulate_unauthorized_role_asserts_0xE902(self, rbac_engine: CipSecurityRbacEngine) -> None:
        rbac_engine.simulate_unauthorized_role()
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE
        assert rbac_engine.is_violation_trip_active is True
        assert rbac_engine.state == CipSecurityState.SECURITY_LOCKOUT


# ============================================================================
# Section 6: Signature Validation Failure & Forged Token Trip (0xE903)
# ============================================================================

class TestSection6SignatureValidationFailure:
    """Verify forged/tampered token rejection, 0xE903 trip, and violation counters."""

    def test_authenticate_token_with_invalid_signature_trips_0xE903(self, rbac_engine: CipSecurityRbacEngine) -> None:
        tok = create_bearer_token(
            subject="attacker",
            roles=[CipSecurityRole.ADMINISTRATOR],
            secret_key=b"wrong-attacker-secret-key-1234",
            current_time_s=rbac_engine.current_time_s,
        )
        ok, err, sess, details = rbac_engine.authenticate_token(tok)
        assert ok is False
        assert err == CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED
        assert sess is None
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED
        assert rbac_engine.is_violation_trip_active is True
        assert rbac_engine.access_violation_counter == 1

    def test_authenticate_token_tampered_payload_trips_0xE903(self, rbac_engine: CipSecurityRbacEngine) -> None:
        tok = create_bearer_token(
            subject="legit_user",
            roles=[CipSecurityRole.OPERATOR],
            secret_key=rbac_engine.secret_key,
            current_time_s=rbac_engine.current_time_s,
        )
        parts = tok.split(".")
        corrupted = f"{parts[0]}.{parts[1][:-4]}AAAA.{parts[2]}"

        ok, err, _, _ = rbac_engine.authenticate_token(corrupted)
        assert ok is False
        assert err == CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED
        assert rbac_engine.is_violation_trip_active is True

    def test_simulate_signature_failure_asserts_0xE903(self, rbac_engine: CipSecurityRbacEngine) -> None:
        rbac_engine.simulate_signature_failure()
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED
        assert rbac_engine.is_violation_trip_active is True
        assert rbac_engine.state == CipSecurityState.SECURITY_LOCKOUT


# ============================================================================
# Section 7: CRL Certificate Revocation & Blacklisted Token Trip (0xE904)
# ============================================================================

class TestSection7CertificateRevocationAndBlacklist:
    """Verify X.509 CRL checks, token blacklisting, and 0xE904 trip."""

    def test_certificate_hierarchy_validation_clean(self) -> None:
        mgr = CertificateManager()
        root = X509CertInfo.create(serial="01", cn="Root CA", is_ca=True)
        leaf = X509CertInfo.create(serial="02", cn="PLC Node", issuer_cn="Root CA", parent_serial="01")
        mgr.install_ca_certificate(root)
        mgr.install_certificate(leaf)

        ok, err, msg = mgr.validate_chain(leaf, current_time_s=DEFAULT_BASE_TIME_S)
        assert ok is True
        assert err is None

    def test_certificate_revocation_in_crl(self) -> None:
        mgr = CertificateManager()
        root = X509CertInfo.create(serial="01", cn="Root CA", is_ca=True)
        leaf = X509CertInfo.create(serial="02", cn="Compromised Node", issuer_cn="Root CA", parent_serial="01")
        mgr.install_ca_certificate(root)
        mgr.install_certificate(leaf)
        mgr.revoke_certificate("02", reason="Private key compromised")

        ok, err, msg = mgr.validate_chain(leaf, current_time_s=DEFAULT_BASE_TIME_S)
        assert ok is False
        assert err == CipSecurityRbacDiagnosticCode.CERTIFICATE_REVOKED
        assert "revoked" in msg.lower()

    def test_engine_revoke_certificate_active_trips_0xE904(self, rbac_engine: CipSecurityRbacEngine) -> None:
        rbac_engine.cert_management_object.active_serial_number = "CERT_SER_99"
        rbac_engine.revoke_certificate("CERT_SER_99")
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.CERTIFICATE_REVOKED
        assert rbac_engine.is_violation_trip_active is True

    def test_engine_revoke_token_purges_active_sessions(self, rbac_engine: CipSecurityRbacEngine) -> None:
        tok = create_bearer_token(
            subject="rogue_user",
            roles=[CipSecurityRole.OPERATOR],
            nonce="nonce_rogue_11",
            secret_key=rbac_engine.secret_key,
            current_time_s=rbac_engine.current_time_s,
        )
        ok, _, sess, _ = rbac_engine.authenticate_token(tok)
        assert ok is True
        assert len(rbac_engine.active_sessions) == 1

        # Revoke the token nonce
        rbac_engine.revoke_token("nonce_rogue_11")
        assert len(rbac_engine.active_sessions) == 0
        assert "nonce_rogue_11" in rbac_engine.token_blacklist

    def test_authenticate_blacklisted_token_increments_revoked_counter(self, rbac_engine: CipSecurityRbacEngine) -> None:
        tok = create_bearer_token(
            subject="bad_subject",
            roles=[CipSecurityRole.MAINTENANCE],
            nonce="blacklisted_nonce_77",
            secret_key=rbac_engine.secret_key,
            current_time_s=rbac_engine.current_time_s,
        )
        rbac_engine.token_blacklist.add("blacklisted_nonce_77")

        ok, err, sess, _ = rbac_engine.authenticate_token(tok)
        assert ok is False
        assert rbac_engine.revoked_token_attempt_counter == 1
        assert rbac_engine.is_violation_trip_active is True

    def test_simulate_certificate_revoked_asserts_0xE904(self, rbac_engine: CipSecurityRbacEngine) -> None:
        rbac_engine.simulate_certificate_revoked()
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.CERTIFICATE_REVOKED
        assert rbac_engine.is_violation_trip_active is True
        assert rbac_engine.state == CipSecurityState.SECURITY_LOCKOUT


# ============================================================================
# Section 8: Safe-State Clamp on Security Violation (%M416 Asserted)
# ============================================================================

class TestSection8SafeStateClamp:
    """Verify safe-state clamp assertion (%M416), privilege lockout, and operator reset."""

    def test_trip_fault_asserts_clamp_and_status(self, rbac_engine: CipSecurityRbacEngine) -> None:
        rbac_engine.trip_fault(CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE, details="Role violation")
        assert rbac_engine.is_violation_trip_active is True
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE
        assert rbac_engine.state == CipSecurityState.SECURITY_LOCKOUT

        rt = rbac_engine.reg_table
        assert rt is not None
        assert rt.read_bit("%M416") is True
        assert rt.read_uword("%R1787") == 0xE902

    def test_clamp_blocks_action_and_resets_on_operator_pulse(self, rbac_engine: CipSecurityRbacEngine) -> None:
        tok = create_bearer_token(
            subject="normal_user",
            roles=[CipSecurityRole.OPERATOR],
            secret_key=rbac_engine.secret_key,
            current_time_s=rbac_engine.current_time_s,
        )
        rbac_engine.authenticate_token(tok)

        # Trigger safe-state trip
        rbac_engine.trip_fault(CipSecurityRbacDiagnosticCode.SIGNATURE_VERIFICATION_FAILED)
        assert rbac_engine.is_violation_trip_active is True

        # Operator manual reset pulse
        res = rbac_engine.reset_fault(force=True)
        assert res.status == AgentStatus.SUCCESS
        assert rbac_engine.is_violation_trip_active is False
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.OK

        rt = rbac_engine.reg_table
        assert rt is not None
        assert rt.read_bit("%M416") is False
        assert rt.read_uword("%R1787") == 0x0000


# ============================================================================
# Section 9: Horner OCS Register Synchronization (%R1780..%R1787, %M415..%M416)
# ============================================================================

class TestSection9RegisterSynchronization:
    """Verify Horner OCS register map synchronization with PrivilegeMode.SYSTEM."""

    def test_register_map_addresses_and_ranges(self, rbac_engine: CipSecurityRbacEngine) -> None:
        rt = rbac_engine.reg_table
        assert rt is not None

        # Verify initial register values
        assert rt.read_word("%R1780") == int(CipSecurityProfile.CONFIDENTIALITY_AND_AUTH)
        assert rt.read_word("%R1781") == 0  # 0 active sessions
        assert rt.read_word("%R1782") == 0  # active role bitmask
        assert rt.read_word("%R1783") == 0  # remaining lifetime
        assert rt.read_word("%R1784") == 0  # access violations
        assert rt.read_word("%R1785") == 0  # revoked token attempts
        assert rt.read_word("%R1786") == int(CipSecurityState.SECURE_RUN)
        assert rt.read_uword("%R1787") == 0x0000
        assert rt.read_bit("%M415") is False
        assert rt.read_bit("%M416") is False

    def test_register_sync_after_authentication(self, rbac_engine: CipSecurityRbacEngine) -> None:
        tok = create_bearer_token(
            subject="operator_dan",
            roles=[CipSecurityRole.OPERATOR],
            lifetime_sec=1200.0,
            secret_key=rbac_engine.secret_key,
            current_time_s=rbac_engine.current_time_s,
        )
        rbac_engine.authenticate_token(tok)
        rt = rbac_engine.reg_table
        assert rt is not None

        assert rt.read_word("%R1781") == 1      # 1 active session
        assert rt.read_word("%R1782") == 0x04   # Operator bitmask (1 << 2)
        assert rt.read_word("%R1783") == 1200   # 1200 seconds remaining
        assert rt.read_bit("%M415") is True     # Active session authenticated
        assert rt.read_bit("%M416") is False    # No trip active

    def test_register_sync_multiple_sessions_aggregates_bitmask(self, rbac_engine: CipSecurityRbacEngine) -> None:
        tok1 = create_bearer_token(
            subject="engineer_user",
            roles=[CipSecurityRole.ENGINEER],
            secret_key=rbac_engine.secret_key,
            current_time_s=rbac_engine.current_time_s,
        )
        tok2 = create_bearer_token(
            subject="operator_user",
            roles=[CipSecurityRole.OPERATOR],
            secret_key=rbac_engine.secret_key,
            current_time_s=rbac_engine.current_time_s,
        )
        rbac_engine.authenticate_token(tok1)
        rbac_engine.authenticate_token(tok2)

        rt = rbac_engine.reg_table
        assert rt is not None
        assert rt.read_word("%R1781") == 2
        # Bitmask must combine Engineer (0x02) and Operator (0x04) -> 0x06
        assert rt.read_word("%R1782") == 0x06

    def test_safe_write_helpers_with_system_privilege(self, register_table: RegisterTable) -> None:
        safe_write_word(register_table, "%R1780", 3)
        safe_write_uword(register_table, "%R1787", 0xE901)
        safe_write_bit(register_table, "%M416", True)

        assert register_table.read_word("%R1780") == 3
        assert register_table.read_uword("%R1787") == 0xE901
        assert register_table.read_bit("%M416") is True


# ============================================================================
# Section 10: ILogicUnit Scan Cycle Integration & Simulation
# ============================================================================

class TestSection10ILogicUnitIntegration:
    """Verify ILogicUnit interface compliance, 100-cycle scan simulation, and reset."""

    def test_ilogic_unit_properties(self, rbac_engine: CipSecurityRbacEngine) -> None:
        assert isinstance(rbac_engine, ILogicUnit)
        assert rbac_engine.name == "CipSecurityRbacEngine"
        assert rbac_engine.priority == 96
        assert rbac_engine.is_enabled is True

    def test_ilogic_unit_100_cycle_simulation(self, rbac_engine: CipSecurityRbacEngine) -> None:
        # Authenticate an operator session
        tok = create_bearer_token(
            subject="sim_user",
            roles=[CipSecurityRole.OPERATOR],
            lifetime_sec=3600.0,
            secret_key=rbac_engine.secret_key,
            current_time_s=rbac_engine.current_time_s,
        )
        rbac_engine.authenticate_token(tok)

        # Run 100 cycles at 10 ms each
        ctx = ScanContext(cycle=0, dt_ms=10.0)
        for i in range(1, 101):
            ctx.cycle = i
            rbac_engine.execute(ctx)

        assert rbac_engine.total_scan_cycles == 100
        assert pytest.approx(rbac_engine.elapsed_simulation_ms, 0.1) == 1000.0
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.OK

        rt = rbac_engine.reg_table
        assert rt is not None
        assert rt.read_bit("%M415") is True
        assert rt.read_bit("%M416") is False

    def test_ilogic_unit_reset_contract(self, rbac_engine: CipSecurityRbacEngine) -> None:
        rbac_engine.trip_fault(CipSecurityRbacDiagnosticCode.UNAUTHORIZED_ROLE)
        assert rbac_engine.is_violation_trip_active is True

        rbac_engine.reset()
        assert rbac_engine.is_violation_trip_active is False
        assert rbac_engine.diagnostic_code == CipSecurityRbacDiagnosticCode.OK

    def test_session_capacity_limit(self, rbac_engine: CipSecurityRbacEngine) -> None:
        # Capacity is 16
        for i in range(16):
            tok = create_bearer_token(
                subject=f"user_{i}",
                roles=[CipSecurityRole.VIEW_ONLY],
                secret_key=rbac_engine.secret_key,
                current_time_s=rbac_engine.current_time_s,
            )
            ok, _, _, _ = rbac_engine.authenticate_token(tok)
            assert ok is True

        assert len(rbac_engine.active_sessions) == 16

        # 17th token exceeds capacity
        overflow_tok = create_bearer_token(
            subject="overflow_user",
            roles=[CipSecurityRole.VIEW_ONLY],
            secret_key=rbac_engine.secret_key,
            current_time_s=rbac_engine.current_time_s,
        )
        ok, _, _, details = rbac_engine.authenticate_token(overflow_tok)
        assert ok is False
        assert "capacity exceeded" in details.lower()


# ============================================================================
# Section 11: 9-Stage Verification Runner & Evidence JSON Export
# ============================================================================

class TestSection11VerificationRunner:
    """Verify deterministic execution and JSON evidence export of 9-stage verification runner."""

    def test_run_cip_security_rbac_verification_returns_success(self) -> None:
        result = run_cip_security_rbac_verification()
        assert isinstance(result, dict)
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["stages_passed"] == 9
        assert result["total_stages"] == 9

        data = result["data"]
        assert data["work_package"] == "W217"
        assert len(data["stages"]) == 9
        for s in data["stages"]:
            assert s["passed"] is True

    def test_run_cip_security_rbac_verification_writes_json(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_security_rbac_evidence_test.json"
        result = run_cip_security_rbac_verification(output_path=str(out_file))

        assert out_file.exists()
        with open(out_file, "r", encoding="utf-8") as f:
            saved = json.load(f)

        assert saved["status"] == "success"
        assert saved["stages_passed"] == 9
        assert "%R1780" in saved["data"]["register_map"]
        assert "%M416" in saved["data"]["register_map"]

    def test_verification_runner_registers_snapshot(self) -> None:
        result = run_cip_security_rbac_verification()
        regs = result["data"]["registers"]
        assert "%R1780" in regs
        assert "%R1787" in regs
        assert "%M415" in regs
        assert "%M416" in regs
