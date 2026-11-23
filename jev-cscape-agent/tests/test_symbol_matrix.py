"""Unit tests for Cscape HMI Barcode & QR Code Symbol Generator (W072 / Gate G9 / Gate G2)."""

from __future__ import annotations

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.hmi.symbol_matrix import (
    QRCodeGenerator,
    SymbolMatrixEngine,
    SymbologyType,
    VectorSymbolRasterizer,
    W072_PURE_ST_POU,
    encode_code128,
    encode_code39,
)
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. 1D Barcode Encoding Tests
# ============================================================================

def test_code128_encoding_and_structure():
    """Verify Code 128 encodes ASCII text with 11-module characters and 13-module stop."""
    payload = "TEST128"
    bits = encode_code128(payload)
    # Start (11) + 7 data chars (77) + Checksum (11) + Stop (13) = 112 modules
    assert len(bits) == 112
    assert bits.startswith("11010010000")  # Start B pattern
    assert bits.endswith("1100011101011")   # Stop pattern


def test_code128_empty_or_invalid_raises():
    """Verify empty or non-ASCII characters raise ValueError."""
    with pytest.raises(ValueError, match="cannot be empty"):
        encode_code128("")
    with pytest.raises(ValueError, match="out of range"):
        encode_code128("TEST\u0100")


def test_code39_encoding_and_structure():
    """Verify Code 39 encodes uppercase alphanumeric text with * start/stop."""
    payload = "CSCAPE"
    bits = encode_code39(payload)
    # 8 symbols (start + 6 chars + stop) of 12 bits separated by 7 narrow spaces (1 bit each)
    # 8 * 12 + 7 = 103 modules
    assert len(bits) == 103
    assert bits.startswith("100101101101")  # * pattern
    assert bits.endswith("100101101101")    # * pattern


def test_code39_invalid_character_raises():
    """Verify lower-case converted or invalid symbols raise."""
    assert len(encode_code39("abc")) > 0  # auto uppercase
    with pytest.raises(ValueError, match="Invalid Code 39 character"):
        encode_code39("INVALID#")


# ============================================================================
# 2. 2D QR Code Matrix & Reed-Solomon Tests
# ============================================================================

def test_qr_code_v1_matrix_dimensions():
    """Verify QR Code Version 1 produces exact 21x21 boolean grid."""
    qr = QRCodeGenerator(version=1, ec_level="M")
    matrix = qr.encode("HELLO")
    assert len(matrix) == 21
    assert all(len(row) == 21 for row in matrix)

    # Top-left finder center is Black
    assert matrix[3][3] is True
    # White ring around center
    assert matrix[1][1] is False


def test_qr_code_v2_matrix_dimensions():
    """Verify QR Code Version 2 produces exact 25x25 boolean grid."""
    qr = QRCodeGenerator(version=2, ec_level="M")
    matrix = qr.encode("BATCH-999-OK")
    assert len(matrix) == 25
    assert all(len(row) == 25 for row in matrix)

    # Alignment pattern center at (18, 18) is Black
    assert matrix[18][18] is True


def test_qr_code_capacity_overflow_raises():
    """Verify exceeding version payload capacity raises ValueError."""
    qr = QRCodeGenerator(version=1, ec_level="M")
    # Max bytes is 14
    with pytest.raises(ValueError, match="exceeds QR V1-M capacity"):
        qr.encode("THIS_STRING_IS_TOO_LONG_FOR_V1_M")


# ============================================================================
# 3. Vector SVG Rasterizer Tests
# ============================================================================

def test_vector_rasterizer_svg_crisp_edges_and_contrast():
    """Verify generated SVG contains crispEdges, #FFFFFF background, and #000000 path."""
    qr = QRCodeGenerator(version=1, ec_level="M")
    matrix = qr.encode("ABC")
    svg = VectorSymbolRasterizer.render_qr_matrix_svg(matrix, module_size=5, quiet_zone_modules=4)

    assert '<svg xmlns="http://www.w3.org/2000/svg"' in svg
    assert 'fill="#FFFFFF"' in svg
    assert 'fill="#000000"' in svg
    assert 'shape-rendering="crispEdges"' in svg
    # Total dimension: (21 + 8) * 5 = 145 px
    assert 'viewBox="0 0 145 145"' in svg


# ============================================================================
# 4. Horner OCS Register Integration & Pure ST POU Tests
# ============================================================================

def test_symbol_matrix_engine_register_integration():
    """Verify SymbolMatrixEngine updates Horner OCS registers upon symbol generation."""
    regs = RegisterTable()
    engine = SymbolMatrixEngine(registers=regs)
    regs.write_word("%R331", SymbologyType.CODE_128, privilege=PrivilegeMode.SYSTEM)
    svg, meta = engine.generate_symbol("RUN-2026")

    assert meta["status"] == "success"
    assert (regs.read_word("%R330") & 0x0001) != 0
    assert regs.read_word("%R332") == len("RUN-2026")
    assert regs.read_word("%R335") > 0
    assert len(svg) > 0


def test_w072_st_pou_ast_parsing_and_bindings():
    """Verify IEC 61131-3 Pure ST AST parsing and bound registers."""
    val = STParser.validate_code(W072_PURE_ST_POU)
    assert val.status == AgentStatus.SUCCESS
    ast = STParser.parse_pou(W072_PURE_ST_POU)
    assert ast.name == "BarcodeSymbolGenerator"
    assert ast.pou_type == POUType.PROGRAM
    expected_bindings = {"%R330", "%R331", "%R332", "%R333", "%R334", "%R335", "%M77", "%M78"}
    assert set(ast.bound_registers) == expected_bindings


@pytest.mark.parametrize(
    "ladder_artifact",
    [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(S)---",
        "---(R)---",
        "RUNG 1",
        "END_RUNG",
        "NETWORK 5",
        "XIC EnableEngine",
        "XIO TriggerRegeneration",
        "OTE StatusWord",
        "OTL SymbolValid",
        "OTU EncodingError",
    ],
)
def test_w072_forbidden_ladder_constructs_rejected(ladder_artifact: str):
    """Verify ladder logic tokens are strictly rejected with ERR_LADDER_FORBIDDEN."""
    tainted = f"{W072_PURE_ST_POU}\n{ladder_artifact}"
    val = STParser.validate_code(tainted)
    assert val.status == AgentStatus.FAILED
    assert val.error_code == "ERR_LADDER_FORBIDDEN"
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(tainted)
