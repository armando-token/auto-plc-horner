"""Tests for STParser IEC 61131-3 syntax parsing and ladder logic rejection."""

import pytest
from jev_cscape.iec.st_parser import STParser, POUType, VarScope
from jev_cscape.contracts import AgentStatus


def test_parse_valid_program():
    code = """
    PROGRAM TankLevelControl
    VAR
        CurrentLevel AT %AI1 : REAL := 0.0;
        PumpRunning AT %M1 : BOOL := FALSE;
        TargetSetpoint AT %R100 : REAL := 50.0;
        AlarmHigh AT %Q1 : BOOL;
    END_VAR
    VAR_INPUT
        EnableAuto : BOOL;
    END_VAR
    VAR_OUTPUT
        StatusWord : INT;
    END_VAR

    IF EnableAuto THEN
        IF CurrentLevel < TargetSetpoint THEN
            PumpRunning := TRUE;
        ELSIF CurrentLevel >= TargetSetpoint THEN
            PumpRunning := FALSE;
        END_IF;
    END_IF;

    AlarmHigh := CurrentLevel > 90.0;
    END_PROGRAM
    """
    val = STParser.validate_code(code)
    assert val.status == AgentStatus.SUCCESS

    ast = STParser.parse_pou(code)
    assert ast.name == "TankLevelControl"
    assert ast.pou_type == POUType.PROGRAM
    assert len(ast.variables) == 6
    assert "%AI1" in ast.bound_registers
    assert "%M1" in ast.bound_registers
    assert "%R100" in ast.bound_registers
    assert "%Q1" in ast.bound_registers
    assert ast.statements_count > 0


def test_parse_valid_function_block():
    code = """
    FUNCTION_BLOCK MotorStarter
    VAR_INPUT
        StartCmd : BOOL;
        StopCmd : BOOL;
    END_VAR
    VAR_OUTPUT
        MotorRun : BOOL;
    END_VAR
    VAR
        InternalLatch : BOOL;
    END_VAR

    IF StopCmd THEN
        InternalLatch := FALSE;
    ELSIF StartCmd THEN
        InternalLatch := TRUE;
    END_IF;
    MotorRun := InternalLatch;
    END_FUNCTION_BLOCK
    """
    val = STParser.validate_code(code)
    assert val.status == AgentStatus.SUCCESS

    ast = STParser.parse_pou(code)
    assert ast.name == "MotorStarter"
    assert ast.pou_type == POUType.FUNCTION_BLOCK
    assert len(ast.variables) == 4


@pytest.mark.parametrize("ladder_artifact", [
    "---[ ]---",
    "---[/]---",
    "---( )---",
    "---(S)---",
    "---(R)---",
    "RUNG 10",
    "NETWORK 1",
    "XIC PushButton",
    "OTE MotorContact",
])
def test_reject_ladder_constructs_with_err_ladder_forbidden(ladder_artifact: str):
    code = f"""
    PROGRAM TestPOU
    VAR
        x : BOOL;
    END_VAR
    {ladder_artifact}
    x := TRUE;
    END_PROGRAM
    """
    res = STParser.validate_code(code)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "ERR_LADDER_FORBIDDEN"
    assert res.data["ladder_rejected"] is True


def test_missing_pou_header():
    code = """
    VAR
        x : BOOL;
    END_VAR
    x := TRUE;
    """
    res = STParser.validate_code(code)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "ST_NO_POU_HEADER"


def test_unclosed_control_block():
    code = """
    PROGRAM UnclosedIf
    VAR
        x : BOOL;
    END_VAR
    IF x THEN
        x := FALSE;
    // Missing END_IF
    END_PROGRAM
    """
    res = STParser.validate_code(code)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "ST_UNCLOSED_CONTROL_BLOCK"


def test_unclosed_var_block():
    code = """
    PROGRAM BadVar
    VAR
        x : BOOL;
    // Missing END_VAR
    x := TRUE;
    END_PROGRAM
    """
    res = STParser.validate_code(code)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "ST_UNCLOSED_VAR_BLOCK"


def test_invalid_register_binding():
    code = """
    PROGRAM BadBinding
    VAR
        BadReg AT %R99999 : INT;
    END_VAR
    BadReg := 1;
    END_PROGRAM
    """
    ast = STParser.parse_pou(code)
    var = ast.variables[0]
    assert var.name == "BadReg"
    assert var.binding_valid is False
    assert "out of range" in var.binding_error


def test_validate_file(tmp_path):
    st_file = tmp_path / "ValidTest.st"
    st_file.write_text("""
    PROGRAM ValidTest
    VAR
        flag AT %M5 : BOOL;
    END_VAR
    flag := TRUE;
    END_PROGRAM
    """, encoding="utf-8")

    res = STParser.validate_file(str(st_file))
    assert res.status == AgentStatus.SUCCESS
    assert res.data["name"] == "ValidTest"
