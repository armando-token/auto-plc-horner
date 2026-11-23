"""Tests for Modbus Protocol Resilience Fuzzer & Boundary Security Harness.

Work Package: W055 (Gate G8 / G11)
"""

import json
from pathlib import Path
import pytest

from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.modbus_stack import (
    ModbusExceptionCode,
    ModbusFunctionCode,
    ModbusMemoryStack,
)
from jev_cscape.telemetry.modbus_fuzzer import (
    FuzzVectorCategory,
    ModbusFuzzVector,
    ModbusFuzzerRunner,
    ModbusFuzzerSuite,
    verify_modbus_fuzzer_and_export_evidence,
)


def test_fuzzer_suite_generation_completeness():
    """Verify that ModbusFuzzerSuite generates expected deterministic vector categories."""
    vectors = ModbusFuzzerSuite.generate_all_vectors()
    assert len(vectors) >= 30

    categories = {v.category for v in vectors}
    assert FuzzVectorCategory.TRUNCATED_FRAME in categories
    assert FuzzVectorCategory.CORRUPTED_CRC in categories
    assert FuzzVectorCategory.INVALID_MBAP in categories
    assert FuzzVectorCategory.ILLEGAL_FUNCTION in categories
    assert FuzzVectorCategory.INVALID_ADDRESS in categories
    assert FuzzVectorCategory.INVALID_QUANTITY in categories
    assert FuzzVectorCategory.MALFORMED_PAYLOAD in categories


def test_truncated_rtu_frame_rejection():
    """Verify that truncated RTU frames (< 4 bytes) are rejected with ValueError without crashing."""
    runner = ModbusFuzzerRunner(unit_id=1)
    trunc_vecs = ModbusFuzzerSuite.generate_truncated_vectors()
    rtu_trunc = [v for v in trunc_vecs if v.protocol == "RTU"]
    assert len(rtu_trunc) >= 4

    for vec in rtu_trunc:
        res = runner.evaluate_vector(vec)
        assert res.passed is True
        assert res.handled_safely is True
        assert res.response_type == "value_error_caught"


def test_corrupted_crc_rtu_rejection():
    """Verify that frames with bad CRC-16 are cleanly rejected with ValueError."""
    runner = ModbusFuzzerRunner(unit_id=1)
    crc_vecs = ModbusFuzzerSuite.generate_corrupted_crc_vectors()
    assert len(crc_vecs) >= 5

    for vec in crc_vecs:
        res = runner.evaluate_vector(vec)
        assert res.passed is True
        assert res.handled_safely is True
        assert res.response_type == "value_error_caught"


def test_invalid_mbap_tcp_rejection():
    """Verify that invalid MBAP protocol IDs are rejected."""
    runner = ModbusFuzzerRunner(unit_id=1)
    mbap_vecs = ModbusFuzzerSuite.generate_invalid_mbap_vectors()
    assert len(mbap_vecs) >= 2

    for vec in mbap_vecs:
        res = runner.evaluate_vector(vec)
        assert res.passed is True
        assert res.handled_safely is True
        assert res.response_type == "value_error_caught"


def test_illegal_function_code_exception_pdu():
    """Verify that illegal function codes return 0x01 ILLEGAL_FUNCTION exception PDU."""
    runner = ModbusFuzzerRunner(unit_id=1)
    fc_vecs = ModbusFuzzerSuite.generate_illegal_function_vectors()
    assert len(fc_vecs) >= 10

    for vec in fc_vecs:
        res = runner.evaluate_vector(vec)
        assert res.passed is True
        assert res.handled_safely is True
        assert res.response_type == "exception_pdu"
        assert res.exception_code == int(ModbusExceptionCode.ILLEGAL_FUNCTION)


def test_invalid_address_exception_pdu():
    """Verify that requests outside table boundaries return 0x02 ILLEGAL_DATA_ADDRESS."""
    runner = ModbusFuzzerRunner(unit_id=1)
    addr_vecs = ModbusFuzzerSuite.generate_invalid_address_vectors()
    assert len(addr_vecs) >= 8

    for vec in addr_vecs:
        res = runner.evaluate_vector(vec)
        assert res.passed is True
        assert res.handled_safely is True
        assert res.response_type == "exception_pdu"
        assert res.exception_code == int(ModbusExceptionCode.ILLEGAL_DATA_ADDRESS)


def test_invalid_quantity_exception_pdu():
    """Verify that requests with illegal count return 0x03 ILLEGAL_DATA_VALUE."""
    runner = ModbusFuzzerRunner(unit_id=1)
    qty_vecs = ModbusFuzzerSuite.generate_invalid_quantity_vectors()
    assert len(qty_vecs) >= 8

    for vec in qty_vecs:
        res = runner.evaluate_vector(vec)
        assert res.passed is True
        assert res.handled_safely is True
        assert res.response_type == "exception_pdu"
        assert res.exception_code == int(ModbusExceptionCode.ILLEGAL_DATA_VALUE)


def test_stochastic_mutation_campaign_zero_crashes():
    """Verify that 500 pseudo-random mutations produce 0 unhandled crashes and high throughput."""
    runner = ModbusFuzzerRunner(unit_id=1)
    summary = runner.run_stochastic_mutation_campaign(num_mutations=500, seed=42)

    assert summary.total_vectors_tested == 500
    assert summary.unhandled_crashes == 0
    assert summary.is_safe is True
    assert summary.throughput_vectors_per_sec > 100.0


def test_verify_and_export_evidence(tmp_path: Path):
    """Verify canonical export runner creates valid JSON deliverable with status success."""
    out_file = tmp_path / "modbus_fuzzer_evidence.json"
    result = verify_modbus_fuzzer_and_export_evidence(str(out_file))

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert out_file.exists()

    with open(out_file, "r", encoding="utf-8") as f:
        loaded = json.load(f)

    assert loaded["status"] == "success"
    assert loaded["data"]["work_package"] == "W055"
    assert loaded["data"]["gate"] == "G8"
    assert loaded["data"]["deterministic_suite"]["pass_rate_percent"] == 100.0
    assert loaded["data"]["stochastic_campaign"]["unhandled_crashes"] == 0
