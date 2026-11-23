"""Comprehensive Test Suite for Cscape Compiler Diagnostic Classifier.

Work Package: W046 (Gate G3 Live Cscape Forensics & Clean Compile Verification)
Classification: PRODUCTION_READY
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.automation.diagnostic_classifier import (
    CscapeDiagnosticClassifier,
    DiagnosticCategory,
)
from jev_cscape.automation.output_scraper import DiagnosticSeverity
from jev_cscape.contracts import AgentStatus
from scripts.run_diagnostic_classification import (
    CANONICAL_CLEAN_LOG,
    CANONICAL_FAULTY_LOG,
    run_diagnostic_classification,
)


def test_classify_clean_log() -> None:
    """Verify clean log produces clean compilation verdict with 0 errors and 0 warnings."""
    classifier = CscapeDiagnosticClassifier()
    report = classifier.classify_lines(CANONICAL_CLEAN_LOG)

    assert report.is_clean_compilation is True
    assert report.total_errors == 0
    assert report.total_warnings == 0
    assert report.has_ladder_violations is False
    assert report.has_cyclic_dependencies is False


def test_classify_syntax_error() -> None:
    """Verify syntax error is extracted with location and code."""
    classifier = CscapeDiagnosticClassifier()
    line = "MainControl.st(14,5): error K51001: Syntax error near 'END_IF'"
    diag = classifier.classify_line(line)

    assert diag is not None
    assert diag.category == DiagnosticCategory.SYNTAX_ERROR
    assert diag.severity == DiagnosticSeverity.ERROR
    assert diag.canonical_code == "ERR_SYNTAX"
    assert diag.line == 14
    assert diag.column == 5
    assert diag.file_path == "MainControl.st"
    assert "syntax" in diag.remediation_hint.lower()


def test_classify_undeclared_identifier() -> None:
    """Verify undeclared identifier extracts offending symbol."""
    classifier = CscapeDiagnosticClassifier()
    line = "STBlock1: (7): FlowSetpoint: Unknown identifier"
    diag = classifier.classify_line(line)

    assert diag is not None
    assert diag.category == DiagnosticCategory.UNDECLARED_IDENTIFIER
    assert diag.severity == DiagnosticSeverity.ERROR
    assert diag.canonical_code == "ERR_UNDECLARED_TAG"
    assert diag.pou_name == "STBlock1"
    assert diag.line == 7
    assert diag.symbol == "FlowSetpoint"
    assert "FlowSetpoint" in diag.remediation_hint


def test_classify_type_mismatch() -> None:
    """Verify type mismatch error is categorized properly."""
    classifier = CscapeDiagnosticClassifier()
    line = "MainControl.st(32,10): error CS2010: Type mismatch: cannot convert 'REAL' to 'INT'"
    diag = classifier.classify_line(line)

    assert diag is not None
    assert diag.category == DiagnosticCategory.TYPE_MISMATCH
    assert diag.severity == DiagnosticSeverity.ERROR
    assert diag.canonical_code == "ERR_TYPE_MISMATCH"
    assert diag.file_path == "MainControl.st"
    assert diag.line == 32
    assert "conversion" in diag.remediation_hint.lower()


def test_classify_ladder_construct_forbidden() -> None:
    """Verify ladder construct injection is intercepted with ERR_LADDER_FORBIDDEN."""
    classifier = CscapeDiagnosticClassifier()
    line = "ERR_LADDER_FORBIDDEN: Forbidden ladder construct '---[ ]---' detected at line 97"
    diag = classifier.classify_line(line)

    assert diag is not None
    assert diag.category == DiagnosticCategory.LADDER_CONSTRUCT_FORBIDDEN
    assert diag.severity == DiagnosticSeverity.ERROR
    assert diag.canonical_code == "ERR_LADDER_FORBIDDEN"
    assert "ladder" in diag.remediation_hint.lower()


def test_classify_cyclic_dependency() -> None:
    """Verify cyclic recursion between POUs is detected."""
    classifier = CscapeDiagnosticClassifier()
    line = "Error: Cyclic dependency detected between 'FB_Tank1' and 'FB_Tank2'"
    diag = classifier.classify_line(line)

    assert diag is not None
    assert diag.category == DiagnosticCategory.CYCLIC_DEPENDENCY
    assert diag.severity == DiagnosticSeverity.ERROR
    assert diag.canonical_code == "ERR_CYCLIC_DEP"
    assert "cyclic" in diag.remediation_hint.lower()


def test_classify_out_of_range_register() -> None:
    """Verify out-of-range register error is categorized."""
    classifier = CscapeDiagnosticClassifier()
    line = "MemoryMap: error: %R15000 out of range register (valid: 1..9999)"
    diag = classifier.classify_line(line)

    assert diag is not None
    assert diag.category == DiagnosticCategory.OUT_OF_RANGE_REGISTER
    assert diag.severity == DiagnosticSeverity.ERROR
    assert diag.canonical_code == "ERR_REG_BOUNDS"
    assert "%R" in diag.remediation_hint


def test_classify_unused_variable() -> None:
    """Verify unused variable warning is categorized with warning severity."""
    classifier = CscapeDiagnosticClassifier()
    line = "Warning: Variable 'temp_buf' is never used"
    diag = classifier.classify_line(line)

    assert diag is not None
    assert diag.category == DiagnosticCategory.UNUSED_VARIABLE
    assert diag.severity == DiagnosticSeverity.WARNING
    assert diag.canonical_code == "WARN_UNUSED_VAR"
    assert diag.symbol == "temp_buf"


def test_export_report(tmp_path: Path) -> None:
    """Verify export_report writes valid JSON to disk."""
    classifier = CscapeDiagnosticClassifier()
    report = classifier.classify_lines(CANONICAL_FAULTY_LOG)
    out_file = tmp_path / "report.json"

    data = classifier.export_report(report, out_file)
    assert out_file.is_file()
    assert data["total_errors"] >= 6
    assert data["has_ladder_violations"] is True
    assert data["has_cyclic_dependencies"] is True


def test_run_diagnostic_classification_runner(tmp_path: Path) -> None:
    """Verify canonical script runner executes without errors in tmp directory."""
    out_file = tmp_path / "evidence.json"
    res = run_diagnostic_classification(output_path=str(out_file))

    assert res.status == AgentStatus.SUCCESS
    assert out_file.is_file()
    with open(out_file, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["status"] == "success"
    assert loaded["clean_log_verification"]["is_clean_compilation"] is True
    assert loaded["faulty_log_verification"]["is_clean_compilation"] is False
