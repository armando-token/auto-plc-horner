"""IEC 61131-3 Structured Text (ST) Parser and Ladder Logic Rejection Guard.

Strictly parses .st POUs (PROGRAM, FUNCTION_BLOCK, FUNCTION), extracts typed variable
blocks and register bindings (%R, %I, %Q, %M), and aggressively detects and rejects
any embedded ladder logic constructs with ERR_LADDER_FORBIDDEN.
"""

from enum import Enum
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.automation.channel_matrix import ChannelMatrix


class POUType(str, Enum):
    """Supported IEC 61131-3 POU categories."""
    PROGRAM = "PROGRAM"
    FUNCTION_BLOCK = "FUNCTION_BLOCK"
    FUNCTION = "FUNCTION"


class VarScope(str, Enum):
    """Variable declaration scopes in IEC 61131-3."""
    VAR = "VAR"
    VAR_INPUT = "VAR_INPUT"
    VAR_OUTPUT = "VAR_OUTPUT"
    VAR_IN_OUT = "VAR_IN_OUT"
    VAR_GLOBAL = "VAR_GLOBAL"
    VAR_TEMP = "VAR_TEMP"


class STVariable(BaseModel):
    """Parsed IEC 61131-3 variable declaration."""
    name: str
    scope: VarScope
    data_type: str
    initial_value: Optional[str] = None
    address_binding: Optional[str] = None
    binding_valid: bool = True
    binding_error: Optional[str] = None


class POUAST(BaseModel):
    """Abstract Syntax Tree descriptor for a single parsed Structured Text POU."""
    name: str
    pou_type: POUType
    return_type: Optional[str] = None
    variables: List[STVariable] = Field(default_factory=list)
    raw_statements: List[str] = Field(default_factory=list)
    statements_count: int = 0
    bound_registers: List[str] = Field(default_factory=list)


class STParser:
    """Parser and safety validation engine for IEC 61131-3 Structured Text."""

    def __init__(self, pou_type: Optional[POUType] = None) -> None:
        self.pou_type = pou_type

    def parse(self, code: str) -> POUAST:
        """Parse structured text code into POUAST."""
        return self.parse_pou(code)

    # POU header patterns
    _POU_HEADER_PATTERN = re.compile(
        r"^\s*(PROGRAM|FUNCTION_BLOCK|FUNCTION)\s+([A-Za-z0-9_]+)(?:\s*:\s*([A-Za-z0-9_]+))?",
        re.MULTILINE | re.I
    )

    # Variable block patterns
    _VAR_BLOCK_PATTERN = re.compile(
        r"\b(VAR_INPUT|VAR_OUTPUT|VAR_IN_OUT|VAR_GLOBAL|VAR_TEMP|VAR)\b(.*?)\bEND_VAR\b",
        re.DOTALL | re.I
    )

    # Individual variable declaration pattern: Name [AT %Address] : Type [:= InitVal];
    _VAR_DECL_PATTERN = re.compile(
        r"([A-Za-z0-9_,\s]+)(?:\s+AT\s+([%A-Za-z0-9_]+))?\s*:\s*([A-Za-z0-9_]+)(?:\s*:=\s*([^;]+))?\s*;",
        re.I
    )

    # Standard IEC data types
    IEC_DATA_TYPES = {
        "BOOL", "SINT", "INT", "DINT", "LINT",
        "USINT", "UINT", "UDINT", "ULINT",
        "REAL", "LREAL", "TIME", "DATE",
        "TIME_OF_DAY", "TOD", "DATE_AND_TIME", "DT",
        "STRING", "BYTE", "WORD", "DWORD", "LWORD"
    }

    @classmethod
    def validate_code(cls, code: str) -> ExecutionResult:
        """Validate source code against ladder constructs and basic ST syntax."""
        # 1. Enforce zero ladder constructs
        try:
            SecurityGuard.assert_pure_st_content(code)
        except LadderForbiddenError as e:
            return ExecutionResult.failed(
                error_code="ERR_LADDER_FORBIDDEN",
                details=str(e),
                data={"ladder_rejected": True}
            )

        # 2. Check POU header existence
        match = cls._POU_HEADER_PATTERN.search(code)
        if not match:
            return ExecutionResult.failed(
                error_code="ST_NO_POU_HEADER",
                details="No valid PROGRAM, FUNCTION_BLOCK, or FUNCTION declaration found.",
            )

        pou_type_str = match.group(1).upper()
        pou_name = match.group(2)

        # 3. Check matching END delimiter
        end_delimiter = f"END_{pou_type_str}"
        if not re.search(rf"\b{end_delimiter}\b", code, re.I):
            return ExecutionResult.failed(
                error_code="ST_UNTERMINATED_POU",
                details=f"Unterminated {pou_type_str} '{pou_name}'. Expected '{end_delimiter}'.",
            )

        # Strip line and block comments before structural token counting
        clean_code = re.sub(r"//.*$", "", code, flags=re.MULTILINE)
        clean_code = re.sub(r"\(\*.*?\*\)", "", clean_code, flags=re.DOTALL)

        # 4. Check for unclosed variable blocks
        var_starts = len(re.findall(r"\b(VAR_INPUT|VAR_OUTPUT|VAR_IN_OUT|VAR_GLOBAL|VAR_TEMP|VAR)\b", clean_code, re.I))
        var_ends = len(re.findall(r"\bEND_VAR\b", clean_code, re.I))
        if var_starts != var_ends:
            return ExecutionResult.failed(
                error_code="ST_UNCLOSED_VAR_BLOCK",
                details=f"Variable block mismatch: {var_starts} VAR declarations but {var_ends} END_VAR closures.",
            )

        # 5. Check control structure matching
        control_blocks = [
            ("IF", "END_IF"),
            ("CASE", "END_CASE"),
            ("FOR", "END_FOR"),
            ("WHILE", "END_WHILE"),
            ("REPEAT", "UNTIL"),
        ]
        for start_kw, end_kw in control_blocks:
            starts = len(re.findall(rf"\b{start_kw}\b", clean_code, re.I))
            ends = len(re.findall(rf"\b{end_kw}\b", clean_code, re.I))
            if starts != ends:
                return ExecutionResult.failed(
                    error_code="ST_UNCLOSED_CONTROL_BLOCK",
                    details=f"Control block mismatch: {starts} '{start_kw}' blocks but {ends} '{end_kw}' closures.",
                )

        return ExecutionResult.success(
            details=f"IEC 61131-3 Structured Text syntax valid for {pou_type_str} '{pou_name}'.",
            data={"pou_name": pou_name, "pou_type": pou_type_str}
        )

    validate_syntax = validate_code

    @classmethod
    def parse_pou(cls, code: str) -> POUAST:
        """Parse structured text code into a structured POUAST."""
        # Ladder check first
        SecurityGuard.assert_pure_st_content(code)

        # Match header
        header_match = cls._POU_HEADER_PATTERN.search(code)
        if not header_match:
            raise ValueError("ST_NO_POU_HEADER: Cannot parse POU without PROGRAM/FUNCTION_BLOCK/FUNCTION header.")

        pou_type = POUType(header_match.group(1).upper())
        pou_name = header_match.group(2)
        return_type = header_match.group(3)

        # Extract variables
        variables: List[STVariable] = []
        bound_registers: List[str] = []

        for block_match in cls._VAR_BLOCK_PATTERN.finditer(code):
            scope_str = block_match.group(1).upper()
            scope = VarScope(scope_str)
            block_body = block_match.group(2)

            for decl_match in cls._VAR_DECL_PATTERN.finditer(block_body):
                names_raw = decl_match.group(1)
                at_binding = decl_match.group(2)
                data_type = decl_match.group(3).upper()
                init_val = decl_match.group(4)

                var_names = [n.strip() for n in names_raw.split(",") if n.strip()]
                for vname in var_names:
                    binding_valid = True
                    binding_err = None
                    if at_binding:
                        parsed_reg = ChannelMatrix.parse_register(at_binding)
                        binding_valid = parsed_reg.is_valid
                        binding_err = parsed_reg.error
                        if binding_valid:
                            bound_registers.append(parsed_reg.raw)

                    st_var = STVariable(
                        name=vname,
                        scope=scope,
                        data_type=data_type,
                        initial_value=init_val.strip() if init_val else None,
                        address_binding=at_binding.strip() if at_binding else None,
                        binding_valid=binding_valid,
                        binding_error=binding_err,
                    )
                    variables.append(st_var)

        # Extract logic body (between last END_VAR and END_POU)
        end_pou_kw = f"END_{pou_type.value}"
        var_end_indices = [m.end() for m in re.finditer(r"\bEND_VAR\b", code, re.I)]
        body_start = max(var_end_indices) if var_end_indices else header_match.end()

        end_match = re.search(rf"\b{end_pou_kw}\b", code, re.I)
        body_end = end_match.start() if end_match else len(code)

        logic_body = code[body_start:body_end].strip()
        statements = [line.strip() for line in logic_body.splitlines() if line.strip() and not line.strip().startswith("//")]

        return POUAST(
            name=pou_name,
            pou_type=pou_type,
            return_type=return_type,
            variables=variables,
            raw_statements=statements,
            statements_count=len(statements),
            bound_registers=bound_registers,
        )

    @classmethod
    def parse_to_ast(cls, code: str) -> ExecutionResult:
        """Parse structured text code into AST and return ExecutionResult."""
        try:
            ast = cls.parse_pou(code)
            return ExecutionResult.success(
                details=f"Successfully parsed {ast.pou_type.value} '{ast.name}'.",
                data=ast.model_dump(),
            )
        except Exception as e:
            return ExecutionResult.failed(
                error_code="ST_PARSE_ERROR",
                details=str(e),
            )

    @classmethod
    def validate_file(cls, file_path: str) -> ExecutionResult:
        """Read and validate a .st file from disk."""
        abs_path = os.path.abspath(file_path)
        if not os.path.isfile(abs_path):
            return ExecutionResult.failed(
                error_code="FILE_NOT_FOUND",
                details=f"Source file not found at '{abs_path}'.",
            )

        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                code = f.read()
        except Exception as e:
            return ExecutionResult.failed(
                error_code="READ_ERROR",
                details=f"Failed to read '{abs_path}': {e}",
            )

        val_res = cls.validate_code(code)
        if val_res.status != AgentStatus.SUCCESS:
            return val_res

        try:
            ast = cls.parse_pou(code)
            return ExecutionResult.success(
                details=f"Successfully parsed {ast.pou_type.value} '{ast.name}' ({len(ast.variables)} vars, {ast.statements_count} statements).",
                data=ast.model_dump(),
            )
        except Exception as e:
            return ExecutionResult.failed(
                error_code="ST_PARSE_ERROR",
                details=f"Parsing error in '{os.path.basename(abs_path)}': {e}",
            )
