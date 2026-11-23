"""Cscape Compiler Diagnostic Classifier and Log Forensics Engine.

Work Package: W046 (Gate G3 Live Cscape Forensics & Clean Compile Verification)
Classification: PRODUCTION_READY

Provides deterministic categorization and remediation guidance for Cscape 10.2
compiler messages extracted from Win32 Afx:ControlBar ListBox 372.
"""

from __future__ import annotations

from enum import Enum
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from jev_cscape.automation.output_scraper import DiagnosticSeverity, OutputDiagnostic


class DiagnosticCategory(str, Enum):
    """Categorization taxonomy for Cscape compiler diagnostic messages."""
    SYNTAX_ERROR = "SYNTAX_ERROR"
    UNDECLARED_IDENTIFIER = "UNDECLARED_IDENTIFIER"
    TYPE_MISMATCH = "TYPE_MISMATCH"
    LADDER_CONSTRUCT_FORBIDDEN = "LADDER_CONSTRUCT_FORBIDDEN"
    CYCLIC_DEPENDENCY = "CYCLIC_DEPENDENCY"
    OUT_OF_RANGE_REGISTER = "OUT_OF_RANGE_REGISTER"
    UNUSED_VARIABLE = "UNUSED_VARIABLE"
    CONFIGURATION_WARNING = "CONFIGURATION_WARNING"
    GENERAL_ERROR = "GENERAL_ERROR"
    GENERAL_WARNING = "GENERAL_WARNING"
    GENERAL_INFO = "GENERAL_INFO"


class ClassifiedDiagnostic(BaseModel):
    """Structured diagnostic record with severity, category, and remediation guidance."""
    category: DiagnosticCategory
    severity: DiagnosticSeverity
    canonical_code: str
    message: str
    file_path: Optional[str] = None
    pou_name: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    symbol: Optional[str] = None
    remediation_hint: str
    raw_text: str


class DiagnosticClassificationReport(BaseModel):
    """Aggregate compilation forensics report."""
    total_lines_analyzed: int
    total_errors: int
    total_warnings: int
    total_info: int
    is_clean_compilation: bool
    by_category: Dict[str, int] = Field(default_factory=dict)
    offending_symbols: List[str] = Field(default_factory=list)
    affected_pous: List[str] = Field(default_factory=list)
    has_ladder_violations: bool = False
    has_cyclic_dependencies: bool = False
    diagnostics: List[ClassifiedDiagnostic] = Field(default_factory=list)


# Classification Regex Rules
RE_LADDER = re.compile(
    r"(?:ERR_LADDER_FORBIDDEN|Forbidden\s+ladder\s+construct|---\[\s*[ /]?\s*\]---|---\(\s*[SR]?\s*\)---|\b(?:RUNG|NETWORK|XIC|XIO|OTE|OTL|OTU)\b)",
    re.IGNORECASE,
)
RE_CYCLIC = re.compile(
    r"(?:Cyclic\s+dependency|Circular\s+(?:reference|call)|Recursion\s+is\s+not\s+permitted)",
    re.IGNORECASE,
)
RE_UNDECLARED = re.compile(
    r"(?:Unknown\s+identifier|Symbol\s+['\"]?([A-Za-z0-9_%]+)['\"]?\s+not\s+found|Undeclared\s+identifier\s+['\"]?([A-Za-z0-9_%]+)['\"]?|^([\w%]+)\s*:\s*Unknown\s+identifier)",
    re.IGNORECASE,
)
RE_TYPE_MISMATCH = re.compile(
    r"(?:Type\s+mismatch|cannot\s+convert\s+['\"]?(\w+)['\"]?\s+to\s+['\"]?(\w+)['\"]?|Incompatible\s+types|Cannot\s+assign)",
    re.IGNORECASE,
)
RE_REG_BOUNDS = re.compile(
    r"(?:out\s+of\s+range\s+register|invalid\s+register\s+address|register\s+exceeds\s+bounds|%[RAIQM]\d+\s+out\s+of\s+range)",
    re.IGNORECASE,
)
RE_UNUSED_VAR = re.compile(
    r"(?:Variable\s+['\"]?(\w+)['\"]?\s+is\s+never\s+used|Unused\s+variable)",
    re.IGNORECASE,
)
RE_SYNTAX = re.compile(
    r"(?:Syntax\s+error|unexpected\s+token|K5\d+|CS\d+|missing\s+['\"][;:]['\"]|unclosed\s+block)",
    re.IGNORECASE,
)
RE_CONFIG_WARN = re.compile(
    r"(?:Screen\s+contains\s+no\s+elements|Unassigned\s+channel|Hardware\s+target\s+mismatch|Configuration\s+warning)",
    re.IGNORECASE,
)

RE_FILE_LINE = re.compile(
    r"^(?:(?P<file>[^:\(\s]+\.st)?\((?P<line>\d+)(?:,\s*(?P<col>\d+))?\)|(?P<pou>[\w\.\-]+):\s*\((?P<line2>\d+)\)|Line\s*(?P<line3>\d+)):\s*(?P<rest>.*)",
    re.IGNORECASE,
)


class CscapeDiagnosticClassifier:
    """Classifies compiler diagnostic lines into actionable forensic categories."""

    def classify_line(self, line: str) -> Optional[ClassifiedDiagnostic]:
        """Classify a single raw compiler log line."""
        trimmed = line.strip()
        if not trimmed:
            return None

        # Ignore decorative banners
        if trimmed.startswith("===") or trimmed.startswith("---"):
            return None

        # Parse location metadata if present
        file_path: Optional[str] = None
        pou_name: Optional[str] = None
        line_num: Optional[int] = None
        col_num: Optional[int] = None
        content = trimmed

        m_loc = RE_FILE_LINE.match(trimmed)
        if m_loc:
            file_path = m_loc.group("file")
            pou_name = m_loc.group("pou")
            l_str = m_loc.group("line") or m_loc.group("line2") or m_loc.group("line3")
            if l_str:
                line_num = int(l_str)
            col_str = m_loc.group("col")
            if col_str:
                col_num = int(col_str)
            content = m_loc.group("rest")

        # Determine severity
        is_error = bool(
            re.search(r"\b(?:error|fatal|ERR_[A-Z0-9_]+)\b", content, re.IGNORECASE)
            or re.search(r"build\s+failed|compilation\s+failed", content, re.IGNORECASE)
            or "error" in trimmed.lower()
        )
        is_warn = bool(re.search(r"\b(?:warning|warn)\b", content, re.IGNORECASE))

        if is_error:
            severity = DiagnosticSeverity.ERROR
        elif is_warn:
            severity = DiagnosticSeverity.WARNING
        else:
            severity = DiagnosticSeverity.INFO

        # Summary line check: e.g. "0 error(s), 0 warning(s)"
        if re.search(r"\d+\s+error\(s\)", content, re.IGNORECASE):
            return ClassifiedDiagnostic(
                category=DiagnosticCategory.GENERAL_INFO,
                severity=DiagnosticSeverity.INFO,
                canonical_code="INFO_BUILD_SUMMARY",
                message=content,
                file_path=file_path,
                pou_name=pou_name,
                line=line_num,
                column=col_num,
                symbol=None,
                remediation_hint="Build summary record.",
                raw_text=trimmed,
            )

        # Rule 1: Ladder Construct Injection
        if RE_LADDER.search(content):
            return ClassifiedDiagnostic(
                category=DiagnosticCategory.LADDER_CONSTRUCT_FORBIDDEN,
                severity=DiagnosticSeverity.ERROR,
                canonical_code="ERR_LADDER_FORBIDDEN",
                message=content,
                file_path=file_path,
                pou_name=pou_name,
                line=line_num,
                column=col_num,
                symbol=None,
                remediation_hint="Remove forbidden ladder contacts/coils. Refactor POU to pure IEC 61131-3 Structured Text.",
                raw_text=trimmed,
            )

        # Rule 2: Cyclic Dependency
        if RE_CYCLIC.search(content):
            return ClassifiedDiagnostic(
                category=DiagnosticCategory.CYCLIC_DEPENDENCY,
                severity=DiagnosticSeverity.ERROR,
                canonical_code="ERR_CYCLIC_DEP",
                message=content,
                file_path=file_path,
                pou_name=pou_name,
                line=line_num,
                column=col_num,
                symbol=None,
                remediation_hint="Break cyclic recursion between POUs using sequential scan cycle staging.",
                raw_text=trimmed,
            )

        # Rule 3: Out-of-Range Register
        if RE_REG_BOUNDS.search(content):
            return ClassifiedDiagnostic(
                category=DiagnosticCategory.OUT_OF_RANGE_REGISTER,
                severity=DiagnosticSeverity.ERROR,
                canonical_code="ERR_REG_BOUNDS",
                message=content,
                file_path=file_path,
                pou_name=pou_name,
                line=line_num,
                column=col_num,
                symbol=None,
                remediation_hint="Verify Horner OCS register bounds (%R 1..4096, %AI 1..512, %Q 1..2048).",
                raw_text=trimmed,
            )

        # Rule 4: Undeclared Tag / Unknown Identifier
        m_und = RE_UNDECLARED.search(content)
        if m_und:
            sym = next((g for g in m_und.groups() if g), None)
            return ClassifiedDiagnostic(
                category=DiagnosticCategory.UNDECLARED_IDENTIFIER,
                severity=DiagnosticSeverity.ERROR,
                canonical_code="ERR_UNDECLARED_TAG",
                message=content,
                file_path=file_path,
                pou_name=pou_name,
                line=line_num,
                column=col_num,
                symbol=sym,
                remediation_hint=f"Declare symbol '{sym}' in VAR..END_VAR block or assign valid Horner OCS register.",
                raw_text=trimmed,
            )

        # Rule 5: Type Mismatch
        if RE_TYPE_MISMATCH.search(content):
            return ClassifiedDiagnostic(
                category=DiagnosticCategory.TYPE_MISMATCH,
                severity=DiagnosticSeverity.ERROR,
                canonical_code="ERR_TYPE_MISMATCH",
                message=content,
                file_path=file_path,
                pou_name=pou_name,
                line=line_num,
                column=col_num,
                symbol=None,
                remediation_hint="Insert explicit IEC type conversion function (e.g. REAL_TO_INT, TRUNC).",
                raw_text=trimmed,
            )

        # Rule 6: Syntax Error
        if RE_SYNTAX.search(content) or severity == DiagnosticSeverity.ERROR:
            return ClassifiedDiagnostic(
                category=DiagnosticCategory.SYNTAX_ERROR,
                severity=DiagnosticSeverity.ERROR,
                canonical_code="ERR_SYNTAX",
                message=content,
                file_path=file_path,
                pou_name=pou_name,
                line=line_num,
                column=col_num,
                symbol=None,
                remediation_hint="Check Structured Text syntax: semicolons, matching IF..END_IF, and variable assignments (:=).",
                raw_text=trimmed,
            )

        # Rule 7: Unused Variable
        m_unv = RE_UNUSED_VAR.search(content)
        if m_unv:
            sym = m_unv.group(1)
            return ClassifiedDiagnostic(
                category=DiagnosticCategory.UNUSED_VARIABLE,
                severity=DiagnosticSeverity.WARNING,
                canonical_code="WARN_UNUSED_VAR",
                message=content,
                file_path=file_path,
                pou_name=pou_name,
                line=line_num,
                column=col_num,
                symbol=sym,
                remediation_hint=f"Remove unused variable declaration '{sym}' to optimize memory footprint.",
                raw_text=trimmed,
            )

        # Rule 8: Configuration Warning
        if RE_CONFIG_WARN.search(content) or severity == DiagnosticSeverity.WARNING:
            return ClassifiedDiagnostic(
                category=DiagnosticCategory.CONFIGURATION_WARNING,
                severity=DiagnosticSeverity.WARNING,
                canonical_code="WARN_CONFIG",
                message=content,
                file_path=file_path,
                pou_name=pou_name,
                line=line_num,
                column=col_num,
                symbol=None,
                remediation_hint="Review controller target hardware profile and screen configuration.",
                raw_text=trimmed,
            )

        # Fallback INFO
        return ClassifiedDiagnostic(
            category=DiagnosticCategory.GENERAL_INFO,
            severity=DiagnosticSeverity.INFO,
            canonical_code="INFO_GENERAL",
            message=content,
            file_path=file_path,
            pou_name=pou_name,
            line=line_num,
            column=col_num,
            symbol=None,
            remediation_hint="Informational compiler trace.",
            raw_text=trimmed,
        )

    def classify_lines(self, lines: List[str]) -> DiagnosticClassificationReport:
        """Classify a list of raw Cscape compiler output strings."""
        diags: List[ClassifiedDiagnostic] = []
        by_category: Dict[str, int] = {c.value: 0 for c in DiagnosticCategory}
        symbols: List[str] = []
        pous: List[str] = []
        has_ladder = False
        has_cyclic = False

        total_err = 0
        total_warn = 0
        total_info = 0

        for line in lines:
            d = self.classify_line(line)
            if not d:
                continue

            diags.append(d)
            by_category[d.category.value] = by_category.get(d.category.value, 0) + 1

            if d.severity == DiagnosticSeverity.ERROR:
                total_err += 1
            elif d.severity == DiagnosticSeverity.WARNING:
                total_warn += 1
            else:
                total_info += 1

            if d.symbol and d.symbol not in symbols:
                symbols.append(d.symbol)
            if d.pou_name and d.pou_name not in pous:
                pous.append(d.pou_name)

            if d.category == DiagnosticCategory.LADDER_CONSTRUCT_FORBIDDEN:
                has_ladder = True
            elif d.category == DiagnosticCategory.CYCLIC_DEPENDENCY:
                has_cyclic = True

        is_clean = total_err == 0 and total_warn == 0

        return DiagnosticClassificationReport(
            total_lines_analyzed=len(lines),
            total_errors=total_err,
            total_warnings=total_warn,
            total_info=total_info,
            is_clean_compilation=is_clean,
            by_category=by_category,
            offending_symbols=symbols,
            affected_pous=pous,
            has_ladder_violations=has_ladder,
            has_cyclic_dependencies=has_cyclic,
            diagnostics=diags,
        )

    def export_report(
        self,
        report: DiagnosticClassificationReport,
        output_file: Path | str,
    ) -> Dict[str, Any]:
        """Export classification report to structured JSON file."""
        target = Path(output_file)
        target.parent.mkdir(parents=True, exist_ok=True)
        data = report.model_dump(mode="json")
        target.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data
