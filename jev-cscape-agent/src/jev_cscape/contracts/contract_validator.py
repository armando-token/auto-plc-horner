"""Contract Validator and False-Success Dismantler (H01–H13).

Enforces honest status classification (SUCCESS, PARTIAL, FAILED, BLOCKED, INCONCLUSIVE)
across all agent execution payloads, eliminating silent mocks, phantom HWNDs,
premature gate victories, and unverified successes.
"""

from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from jev_cscape.contracts import AgentStatus, ExecutionResult


class FalseSuccessPattern(str, Enum):
    """Catalog of false success antipatterns H01–H13 in Cscape automation."""
    H01_SILENT_MOCK = "H01_SILENT_MOCK"
    H02_GLOBAL_ALLOW_AS_OPEN = "H02_GLOBAL_ALLOW_AS_OPEN"
    H03_FAKE_ERROR_CHECK = "H03_FAKE_ERROR_CHECK"
    H04_FAKE_ST_LD_CONVERSION = "H04_FAKE_ST_LD_CONVERSION"
    H05_PHANTOM_HWND = "H05_PHANTOM_HWND"
    H06_BLIND_CLICK = "H06_BLIND_CLICK"
    H07_PREMATURE_GATE_VICTORY = "H07_PREMATURE_GATE_VICTORY"
    H08_SUBJECTIVE_STATUS = "H08_SUBJECTIVE_STATUS"
    H09_UNCHECKED_FILE_LOCK = "H09_UNCHECKED_FILE_LOCK"
    H10_DIALOG_DEADLOCK = "H10_DIALOG_DEADLOCK"
    H11_STRATON_RUNTIME_FALLBACK = "H11_STRATON_RUNTIME_FALLBACK"
    H12_SIMULATED_HARDWARE_SUCCESS = "H12_SIMULATED_HARDWARE_SUCCESS"
    H13_PARTIAL_POU_MARKED_FULL_SUCCESS = "H13_PARTIAL_POU_MARKED_FULL_SUCCESS"


class FalseSuccessViolation(BaseModel):
    """Record of a detected false-success pattern violation."""
    pattern: FalseSuccessPattern
    rule: str
    remediation: str
    context: Dict[str, Any] = Field(default_factory=dict)


class ValidationReport(BaseModel):
    """Validation report analyzing an ExecutionResult for contract integrity."""
    is_valid: bool
    original_status: str
    enforced_status: AgentStatus
    violations: List[FalseSuccessViolation] = Field(default_factory=list)
    remediated_result: ExecutionResult


class ContractValidator:
    """Audits and enforces honest 4-state / 5-state contract compliance."""

    SUBJECTIVE_TERMS: Set[str] = {
        "verified", "100%", "perfect", "done", "complete", "all_passed",
        "working", "flawless", "finished", "guaranteed"
    }

    STRATON_QUARANTINE_TERMS: Set[str] = {
        "appli.k5p", "appli.cpo", "k5dbxs.ini", "t5rti", "t5simul",
        "quarantine/straton_k5_legacy"
    }

    HARDWARE_TERMS: List[re.Pattern] = [
        re.compile(r"\bcom\d+\b", re.I),
        re.compile(r"\bdownload(?:ed)?\s+to\s+plc\b", re.I),
        re.compile(r"\bflashed\s+controller\b", re.I),
        re.compile(r"\bcontroller\s+download\s+success\b", re.I),
    ]

    @classmethod
    def get_catalog(cls) -> Dict[str, Dict[str, str]]:
        """Return the H01–H13 false-success catalog metadata."""
        return {
            FalseSuccessPattern.H01_SILENT_MOCK.value: {
                "name": "Silent Mock Success",
                "description": "Mocked/offline subsystem returning success without explicitly declaring 'mode': 'offline/mock'.",
                "enforcement": "Must declare 'mode': 'offline/mock' in execution payload or result data.",
            },
            FalseSuccessPattern.H02_GLOBAL_ALLOW_AS_OPEN.value: {
                "name": "Global Allow Dialog Suppression as Project Open",
                "description": "Dismissing startup prompt and assuming project opened without verifying main window title/project name.",
                "enforcement": "Requires verification of project document node or window title containing project filename.",
            },
            FalseSuccessPattern.H03_FAKE_ERROR_CHECK.value: {
                "name": "Fake Error Check Compilation",
                "description": "Reporting 0 errors without reading MFC ListBox 372 compiler output pane.",
                "enforcement": "Requires scraper data showing line count and explicit error/warning string counts from ListBox 372.",
            },
            FalseSuccessPattern.H04_FAKE_ST_LD_CONVERSION.value: {
                "name": "Fake ST-to-Ladder Conversion",
                "description": "Claiming in-GUI ST->LD conversion in Cscape 10.2 (which is BLOCKED_NATIVE).",
                "enforcement": "Must fail closed with status: blocked and error_code: BLOCKED_NATIVE.",
            },
            FalseSuccessPattern.H05_PHANTOM_HWND.value: {
                "name": "Phantom HWND / Invisible Window",
                "description": "Claiming GUI success when HWND is 0, minimized, off-screen, or invisible on winsta0\\Default.",
                "enforcement": "Must verify HWND > 0, IsWindowVisible == True, rect.width > 0, rect.height > 0.",
            },
            FalseSuccessPattern.H06_BLIND_CLICK.value: {
                "name": "Blind Click / Unverified Message Dispatch",
                "description": "Posting WM_COMMAND without asserting subsequent UI state change.",
                "enforcement": "Must confirm target window state change or dialog dismissal within timeout.",
            },
            FalseSuccessPattern.H07_PREMATURE_GATE_VICTORY.value: {
                "name": "Premature Gate Victory / Gate Skip",
                "description": "Declaring G1–G5 complete without verifiable deliverables or audit log evidence.",
                "enforcement": "Gates are strictly evidence-gated; G2+/G5 cannot be claimed done without step-by-step audit.",
            },
            FalseSuccessPattern.H08_SUBJECTIVE_STATUS.value: {
                "name": "Subjective Status Invented",
                "description": "Using subjective non-standard status strings like 'VERIFIED' or '100%'.",
                "enforcement": "Strictly limited to canonical enum: success, partial, failed, blocked, inconclusive.",
            },
            FalseSuccessPattern.H09_UNCHECKED_FILE_LOCK.value: {
                "name": "Unchecked File-Lock Collision",
                "description": "Opening project without checking sharing violations or file lock status.",
                "enforcement": "Check for file-lock modal dialogs and verify file access prior to dispatch.",
            },
            FalseSuccessPattern.H10_DIALOG_DEADLOCK.value: {
                "name": "Dialog Deadlock / Unhandled Popup",
                "description": "Background execution blocked on unhandled modal popup dialog (#32770).",
                "enforcement": "Dialog sweeper active during all modal-spawning operations.",
            },
            FalseSuccessPattern.H11_STRATON_RUNTIME_FALLBACK.value: {
                "name": "Straton K5 Runtime Fallback",
                "description": "Attempting to invoke legacy Copa-Data Straton K5 tools or quarantined files.",
                "enforcement": "Straton files are quarantined; active paths must have zero Straton dependencies.",
            },
            FalseSuccessPattern.H12_SIMULATED_HARDWARE_SUCCESS.value: {
                "name": "Simulated Hardware Port / Download Success",
                "description": "Claiming physical PLC download or COM connection succeeded.",
                "enforcement": "Physical hardware is permanently banned; must fail closed with HardwareLockoutError.",
            },
            FalseSuccessPattern.H13_PARTIAL_POU_MARKED_FULL_SUCCESS.value: {
                "name": "Partial POU Import Marked Full Success",
                "description": "Marking operation SUCCESS when warnings, missing variables, or partial POU items occurred.",
                "enforcement": "Must be honestly classified as PARTIAL or INCONCLUSIVE.",
            },
        }

    @classmethod
    def validate_and_remediate(cls, result: ExecutionResult) -> ValidationReport:
        """Analyze an ExecutionResult, detect false successes, and produce a remediated result."""
        violations: List[FalseSuccessViolation] = []
        original_status_str = result.status.value
        enforced_status = result.status
        remediated_details = result.details
        remediated_data = dict(result.data)
        remediated_error_code = result.error_code

        # H08: Check for subjective status in details or data
        details_lower = result.details.lower()
        for term in cls.SUBJECTIVE_TERMS:
            if re.search(rf"\b{re.escape(term)}\b", details_lower) and "status: success" not in details_lower:
                # Flag as subjective notice if used as pseudo-status
                if f"status: {term}" in details_lower or f"status={term}" in details_lower:
                    violations.append(FalseSuccessViolation(
                        pattern=FalseSuccessPattern.H08_SUBJECTIVE_STATUS,
                        rule="Statuses must strictly belong to canonical enum (success, partial, failed, blocked, inconclusive).",
                        remediation="Normalize pseudo-status to canonical enum.",
                        context={"subjective_term": term}
                    ))

        # H04: Check for fake ST->LD conversion
        if "st->ld" in details_lower or "st to ladder" in details_lower:
            if result.status == AgentStatus.SUCCESS and "offline" not in details_lower and "diagram" not in details_lower:
                violations.append(FalseSuccessViolation(
                    pattern=FalseSuccessPattern.H04_FAKE_ST_LD_CONVERSION,
                    rule="Cscape 10.2 contains zero native menus/exports for ST->LD conversion (BLOCKED_NATIVE).",
                    remediation="Demote status to BLOCKED with error_code BLOCKED_NATIVE.",
                    context={"details": result.details}
                ))
                enforced_status = AgentStatus.BLOCKED
                remediated_error_code = "BLOCKED_NATIVE"
                remediated_details = "ST-to-LD native conversion in Cscape 10.2 is permanently blocked (BLOCKED_NATIVE: DOCUMENT_ONLY)."

        # H11: Check for Straton runtime fallback
        for strat_term in cls.STRATON_QUARANTINE_TERMS:
            if strat_term in details_lower or any(strat_term in str(v).lower() for v in result.data.values()):
                violations.append(FalseSuccessViolation(
                    pattern=FalseSuccessPattern.H11_STRATON_RUNTIME_FALLBACK,
                    rule="Zero Copa-Data Straton K5 files or processes permitted in active code paths.",
                    remediation="Reject execution with error_code STRATON_QUARANTINED.",
                    context={"straton_term": strat_term}
                ))
                enforced_status = AgentStatus.BLOCKED
                remediated_error_code = "STRATON_QUARANTINED"
                remediated_details = f"Operation rejected: active path referenced quarantined Straton artifact '{strat_term}'."

        # H12: Check for physical hardware download claims
        for pat in cls.HARDWARE_TERMS:
            if pat.search(details_lower) or any(pat.search(str(v).lower()) for v in result.data.values()):
                if result.status == AgentStatus.SUCCESS:
                    violations.append(FalseSuccessViolation(
                        pattern=FalseSuccessPattern.H12_SIMULATED_HARDWARE_SUCCESS,
                        rule="Physical hardware downloads and COM port operations are strictly banned by safety policy.",
                        remediation="Demote status to BLOCKED with error_code FAIL_CLOSED_HARDWARE_LOCKOUT.",
                        context={"matched_pattern": pat.pattern}
                    ))
                    enforced_status = AgentStatus.BLOCKED
                    remediated_error_code = "FAIL_CLOSED_HARDWARE_LOCKOUT"
                    remediated_details = "Physical hardware port / download operation blocked by fail-closed safety guardrail."

        # H05: Phantom HWND check
        main_win = result.data.get("main_window")
        if isinstance(main_win, dict):
            hwnd = main_win.get("hwnd", 0)
            is_visible = main_win.get("is_visible", False)
            rect = main_win.get("rect", {})
            width = rect.get("width", 0) if isinstance(rect, dict) else 0
            height = rect.get("height", 0) if isinstance(rect, dict) else 0

            if result.status == AgentStatus.SUCCESS and (hwnd == 0 or not is_visible or width <= 0 or height <= 0):
                violations.append(FalseSuccessViolation(
                    pattern=FalseSuccessPattern.H05_PHANTOM_HWND,
                    rule="Main window must have non-zero HWND, is_visible == True, and positive dimensions.",
                    remediation="Demote status to INCONCLUSIVE or FAILED with error_code PHANTOM_HWND.",
                    context={"hwnd": hwnd, "is_visible": is_visible, "width": width, "height": height}
                ))
                enforced_status = AgentStatus.INCONCLUSIVE
                remediated_error_code = "PHANTOM_HWND"
                remediated_details = f"Cscape window handle ({hwnd}) is invisible or has zero dimensions."

        # H01: Silent Mock check
        is_mock = result.data.get("is_mock", False) or "mock" in details_lower or "simulated" in details_lower
        provider_mode = result.data.get("provider_mode", {})
        has_explicit_mock_declaration = (
            isinstance(provider_mode, dict) and provider_mode.get("mode") == "offline/mock"
        ) or "mode" in result.data and result.data["mode"] == "offline/mock"

        if is_mock and result.status == AgentStatus.SUCCESS and not has_explicit_mock_declaration:
            violations.append(FalseSuccessViolation(
                pattern=FalseSuccessPattern.H01_SILENT_MOCK,
                rule="Mock or offline execution must explicitly declare 'mode': 'offline/mock'.",
                remediation="Inject explicit mock declaration into result payload.",
                context={"is_mock": True}
            ))
            remediated_data["mode"] = "offline/mock"

        # H13: Partial POU / Warnings marked full SUCCESS -> demote to PARTIAL
        warning_count = result.data.get("warning_count", 0)
        uninitialized_count = result.data.get("uninitialized_count", 0)
        partial_elements = result.data.get("partial_elements", [])
        has_degradations = (
            warning_count > 0 or
            uninitialized_count > 0 or
            bool(partial_elements) or
            "partially" in details_lower or
            "partial success" in details_lower
        )

        if result.status == AgentStatus.SUCCESS and has_degradations:
            violations.append(FalseSuccessViolation(
                pattern=FalseSuccessPattern.H13_PARTIAL_POU_MARKED_FULL_SUCCESS,
                rule="Operations with partial imports, warnings, or uninitialized items must be classified as PARTIAL.",
                remediation="Downgrade status from SUCCESS to PARTIAL.",
                context={
                    "warning_count": warning_count,
                    "uninitialized_count": uninitialized_count,
                    "partial_elements": partial_elements
                }
            ))
            enforced_status = AgentStatus.PARTIAL
            remediated_details = f"[PARTIAL] {result.details} (Warnings: {warning_count}, Uninitialized: {uninitialized_count})"

        # Create remediated ExecutionResult
        remediated_result = ExecutionResult(
            status=enforced_status,
            error_code=remediated_error_code,
            details=remediated_details,
            data=remediated_data,
        )

        is_valid = len(violations) == 0

        return ValidationReport(
            is_valid=is_valid,
            original_status=original_status_str,
            enforced_status=enforced_status,
            violations=violations,
            remediated_result=remediated_result,
        )
