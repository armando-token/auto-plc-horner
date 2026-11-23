"""Tests for ContractValidator and H01–H13 false-success dismantling."""

import pytest
from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.contracts.contract_validator import (
    ContractValidator,
    FalseSuccessPattern,
    ValidationReport,
)


def test_clean_success_result():
    res = ExecutionResult.success(
        details="Project validated cleanly.",
        data={"pous_count": 5}
    )
    report = ContractValidator.validate_and_remediate(res)
    assert report.is_valid is True
    assert len(report.violations) == 0
    assert report.enforced_status == AgentStatus.SUCCESS


def test_h01_silent_mock_detection():
    # An execution result claiming success with mock indicators but without explicit mode declaration
    res = ExecutionResult.success(
        details="Compiled successfully via simulated offline engine.",
        data={"is_mock": True}
    )
    report = ContractValidator.validate_and_remediate(res)
    assert report.is_valid is False
    assert any(v.pattern == FalseSuccessPattern.H01_SILENT_MOCK for v in report.violations)
    assert report.remediated_result.data["mode"] == "offline/mock"


def test_h04_fake_st_ld_conversion_blocked():
    res = ExecutionResult.success(
        details="Successfully converted ST to Ladder logic in Cscape.",
        data={"converted": True}
    )
    report = ContractValidator.validate_and_remediate(res)
    assert report.is_valid is False
    assert report.enforced_status == AgentStatus.BLOCKED
    assert report.remediated_result.error_code == "BLOCKED_NATIVE"
    assert any(v.pattern == FalseSuccessPattern.H04_FAKE_ST_LD_CONVERSION for v in report.violations)


def test_h05_phantom_hwnd_demoted():
    res = ExecutionResult.success(
        details="Cscape window ready.",
        data={
            "main_window": {
                "hwnd": 0,
                "is_visible": False,
                "rect": {"width": 0, "height": 0}
            }
        }
    )
    report = ContractValidator.validate_and_remediate(res)
    assert report.is_valid is False
    assert report.enforced_status == AgentStatus.INCONCLUSIVE
    assert report.remediated_result.error_code == "PHANTOM_HWND"
    assert any(v.pattern == FalseSuccessPattern.H05_PHANTOM_HWND for v in report.violations)


def test_h11_straton_runtime_fallback_blocked():
    res = ExecutionResult.success(
        details="Loaded project logic using appli.k5p template.",
        data={"template": "appli.k5p"}
    )
    report = ContractValidator.validate_and_remediate(res)
    assert report.is_valid is False
    assert report.enforced_status == AgentStatus.BLOCKED
    assert report.remediated_result.error_code == "STRATON_QUARANTINED"
    assert any(v.pattern == FalseSuccessPattern.H11_STRATON_RUNTIME_FALLBACK for v in report.violations)


def test_h12_simulated_hardware_success_blocked():
    res = ExecutionResult.success(
        details="Controller download success over COM3.",
        data={"port": "COM3"}
    )
    report = ContractValidator.validate_and_remediate(res)
    assert report.is_valid is False
    assert report.enforced_status == AgentStatus.BLOCKED
    assert report.remediated_result.error_code == "FAIL_CLOSED_HARDWARE_LOCKOUT"
    assert any(v.pattern == FalseSuccessPattern.H12_SIMULATED_HARDWARE_SUCCESS for v in report.violations)


def test_h13_partial_marked_success_demoted_to_partial():
    res = ExecutionResult.success(
        details="Imported project logic with minor warnings.",
        data={
            "warning_count": 3,
            "uninitialized_count": 1,
            "pous_count": 4
        }
    )
    report = ContractValidator.validate_and_remediate(res)
    assert report.is_valid is False
    assert report.enforced_status == AgentStatus.PARTIAL
    assert "[PARTIAL]" in report.remediated_result.details
    assert any(v.pattern == FalseSuccessPattern.H13_PARTIAL_POU_MARKED_FULL_SUCCESS for v in report.violations)


def test_already_honest_partial_intact():
    res = ExecutionResult.partial(
        details="Project opened with 2 uninitialized graphical elements.",
        data={"uninitialized_count": 2}
    )
    report = ContractValidator.validate_and_remediate(res)
    assert report.enforced_status == AgentStatus.PARTIAL


def test_catalog_retrieval():
    catalog = ContractValidator.get_catalog()
    assert len(catalog) == 13
    assert "H01_SILENT_MOCK" in catalog
    assert "H13_PARTIAL_POU_MARKED_FULL_SUCCESS" in catalog
