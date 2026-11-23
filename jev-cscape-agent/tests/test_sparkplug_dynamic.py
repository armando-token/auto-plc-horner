"""Unit tests for Industrial MQTT Sparkplug B Dynamic Metric Definition & Complex UDT Datagroup Engine.

Work Package: W091 (Gate G8 Telemetry Quality & Industrial Protocol Adapters / Gate G4 Simulation)
Classification: PRODUCTION_READY
"""

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.sparkplug_dynamic import (
    CircularTemplateError,
    CorruptedPayloadError,
    ParameterTypeError,
    ParameterType,
    SparkplugDataType,
    SparkplugDynamicMetricEngine,
    SparkplugMetric,
    SparkplugParameter,
    SparkplugPayload,
    SparkplugStatusBits,
    SparkplugTemplate,
    SPARKPLUG_DYNAMIC_PURE_ST_POU,
    TemplateUndefinedError,
    decode_varint,
    encode_varint,
    run_sparkplug_dynamic_verification,
)


class TestSparkplugDynamicPureST:
    """Tests for IEC 61131-3 Pure ST compliance and anti-ladder security."""

    def test_pure_st_security_guard(self) -> None:
        """Verify Pure ST POU passes security guard assertion."""
        SecurityGuard.assert_pure_st_content(SPARKPLUG_DYNAMIC_PURE_ST_POU)

    def test_ladder_constructs_rejected(self) -> None:
        """Verify ladder contacts, coils, and rungs trigger LadderForbiddenError."""
        ladder_snippets = [
            SPARKPLUG_DYNAMIC_PURE_ST_POU + "\n---[ ]---",
            SPARKPLUG_DYNAMIC_PURE_ST_POU + "\n---( )---",
            SPARKPLUG_DYNAMIC_PURE_ST_POU + "\nRUNG 1",
            SPARKPLUG_DYNAMIC_PURE_ST_POU + "\nNETWORK 1",
            SPARKPLUG_DYNAMIC_PURE_ST_POU + "\nXIC MyBit",
        ]
        for snip in ladder_snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snip)

    def test_st_parser_validation_and_ast(self) -> None:
        """Verify ST parser validates syntax and extracts AST properly."""
        val = STParser.validate_code(SPARKPLUG_DYNAMIC_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(SPARKPLUG_DYNAMIC_PURE_ST_POU)
        assert ast.name == "SparkplugDynamicMetricSync"
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = ["%R520", "%R521", "%R522", "%R523", "%R524", "%R525"]
        for reg in expected_regs:
            assert reg in ast.bound_registers
        expected_coils = ["%M121", "%M122"]
        for coil in expected_coils:
            assert coil in ast.bound_registers


class TestSparkplugProtobufEncoding:
    """Tests for pure-Python Protobuf encoding and decoding."""

    def test_varint_encode_decode(self) -> None:
        """Verify LEB128 varint roundtrip across multiple integer boundaries."""
        test_values = [0, 1, 127, 128, 300, 16384, 0xFFFFFFFF, 0x1234567890ABCDEF]
        for val in test_values:
            encoded = encode_varint(val)
            decoded, offset = decode_varint(encoded)
            assert decoded == val
            assert offset == len(encoded)

    def test_corrupted_varint_trapping(self) -> None:
        """Verify corrupted/overflowing varint raises CorruptedPayloadError."""
        # Unending continuation bits (overflow > 70 bits)
        bad_bytes = b"\x80" * 12
        with pytest.raises(CorruptedPayloadError):
            decode_varint(bad_bytes)

        # Truncated varint
        with pytest.raises(CorruptedPayloadError):
            decode_varint(b"\x80", offset=1)


class TestSparkplugTemplateAndInstanceLifecycle:
    """Tests for template definitions, parameters, and instances."""

    def test_template_definition_and_nbirth(self) -> None:
        """Verify template definition registration and NBIRTH payload generation."""
        engine = SparkplugDynamicMetricEngine()
        tpl = SparkplugTemplate(
            version="1.0.0",
            parameters=[
                SparkplugParameter("Prefix", ParameterType.STRING, "MOTOR"),
                SparkplugParameter("PowerKW", ParameterType.FLOAT, 45.0),
            ],
            metrics=[
                SparkplugMetric("${Prefix}/RPM", SparkplugDataType.FLOAT, value=1800.0),
            ],
        )
        engine.register_template_definition("DriveTemplate", tpl)
        assert "DriveTemplate" in engine.template_definitions

        nbirth = engine.generate_nbirth_payload()
        assert nbirth.seq == 0
        assert any(m.name == "_types_/DriveTemplate" for m in nbirth.metrics)
        assert engine.last_tx_bytes > 0

    def test_template_instantiation_with_overrides(self) -> None:
        """Verify template instantiation, macro replacement, and DBIRTH payload."""
        engine = SparkplugDynamicMetricEngine()
        tpl = SparkplugTemplate(
            version="1.0.0",
            parameters=[
                SparkplugParameter("Prefix", ParameterType.STRING, "MOTOR"),
                SparkplugParameter("PowerKW", ParameterType.FLOAT, 45.0),
            ],
            metrics=[
                SparkplugMetric("${Prefix}/RPM", SparkplugDataType.FLOAT, value=1800.0),
            ],
        )
        engine.register_template_definition("DriveTemplate", tpl)

        overrides = [
            SparkplugParameter("Prefix", ParameterType.STRING, "PUMP_FEED"),
            SparkplugParameter("PowerKW", ParameterType.FLOAT, 90.0),
        ]
        inst = engine.instantiate_template("Assets/Pump01", "DriveTemplate", overrides)
        assert inst.template_value is not None
        assert not inst.template_value.is_definition
        assert inst.template_value.template_ref == "DriveTemplate"
        assert inst.template_value.metrics[0].name == "PUMP_FEED/RPM"

        dbirth = engine.generate_dbirth_payload("DEVICES")
        assert any(m.name == "Assets/Pump01" for m in dbirth.metrics)

    def test_undefined_template_error(self) -> None:
        """Verify referencing non-existent template raises TemplateUndefinedError."""
        engine = SparkplugDynamicMetricEngine()
        with pytest.raises(TemplateUndefinedError):
            engine.instantiate_template("Ghost", "DoesNotExist")
        assert engine.schema_error_latched

    def test_parameter_type_mismatch_error(self) -> None:
        """Verify overriding parameter with wrong datatype raises ParameterTypeError."""
        engine = SparkplugDynamicMetricEngine()
        tpl = SparkplugTemplate(
            version="1.0.0",
            parameters=[SparkplugParameter("SetFreq", ParameterType.FLOAT, 60.0)],
        )
        engine.register_template_definition("Inverter", tpl)

        bad_override = [SparkplugParameter("SetFreq", ParameterType.STRING, "NOT_A_FLOAT")]
        with pytest.raises(ParameterTypeError):
            engine.instantiate_template("Assets/Inv01", "Inverter", bad_override)
        assert engine.schema_error_latched

    def test_circular_template_nesting_detection(self) -> None:
        """Verify self-referential nested templates raise CircularTemplateError."""
        engine = SparkplugDynamicMetricEngine()
        # Create nested template referencing same name
        nested_tpl = SparkplugTemplate(
            version="1.0.0",
            template_ref="LoopTemplate",
        )
        parent_tpl = SparkplugTemplate(
            version="1.0.0",
            metrics=[
                SparkplugMetric("SubModule", SparkplugDataType.TEMPLATE, template_value=nested_tpl)
            ],
        )
        with pytest.raises(CircularTemplateError):
            engine.register_template_definition("LoopTemplate", parent_tpl)


class TestSparkplugSequenceAndRBE:
    """Tests for sequence modulo 256, deadband filtering, and rebirth."""

    def test_sequence_number_rollover(self) -> None:
        """Verify sequence counter increments monotonically modulo 256."""
        engine = SparkplugDynamicMetricEngine()
        engine.seq = 254
        s1 = engine.next_sequence()
        assert s1 == 254
        s2 = engine.next_sequence()
        assert s2 == 255
        s3 = engine.next_sequence()
        assert s3 == 0
        assert engine.rollover_count == 1

    def test_deadband_differential_filtering(self) -> None:
        """Verify RBE suppresses sub-deadband changes and sends supra-deadband deltas."""
        engine = SparkplugDynamicMetricEngine()
        engine.deadbands["ReactorTemp"] = 5.0

        # Baseline
        d1 = engine.evaluate_ddata_scan({"ReactorTemp": 100.0})
        assert d1 is not None and len(d1.metrics) == 1

        # Sub-deadband (+2.0 < 5.0) -> Suppressed
        d2 = engine.evaluate_ddata_scan({"ReactorTemp": 102.0})
        assert d2 is None
        assert engine.delta_suppressed

        # Supra-deadband (+10.0 > 5.0) -> Dispatched
        d3 = engine.evaluate_ddata_scan({"ReactorTemp": 112.0})
        assert d3 is not None and len(d3.metrics) == 1
        assert d3.metrics[0].value == 112.0

    def test_rebirth_trigger_workflow(self) -> None:
        """Verify rebirth workflow resets sequence to 0 and increments bdSeq."""
        reg_table = RegisterTable()
        engine = SparkplugDynamicMetricEngine(register_table=reg_table)
        engine.seq = 150
        reg_table.write_bit("%M122", True, privilege=PrivilegeMode.SYSTEM)
        engine.sync_registers()

        assert not reg_table.read_bit("%M122")
        assert engine.bd_seq == 1
        assert engine.seq <= 2


class TestSparkplugHornerRegisters:
    """Tests for Horner OCS register space synchronization."""

    def test_register_synchronization(self) -> None:
        """Verify %R520..%R525 reflect active engine telemetry metrics."""
        reg_table = RegisterTable()
        engine = SparkplugDynamicMetricEngine(register_table=reg_table)
        tpl = SparkplugTemplate(version="1.0.0")
        engine.register_template_definition("T1", tpl)
        engine.generate_nbirth_payload()

        r520 = reg_table.read_word("%R520")
        r521 = reg_table.read_word("%R521")
        r522 = reg_table.read_word("%R522")
        r523 = reg_table.read_word("%R523")

        assert bool(r520 & SparkplugStatusBits.ACTIVE)
        assert bool(r520 & SparkplugStatusBits.CONNECTED_BIRTH)
        assert bool(r520 & SparkplugStatusBits.TEMPLATE_REGISTERED)
        assert r521 == 1  # seq after nbirth
        assert r522 == 1  # template count
        assert r523 == 1  # msg count low

    def test_engine_disable_coil(self) -> None:
        """Verify turning off %M121 zeros StatusWord."""
        reg_table = RegisterTable()
        engine = SparkplugDynamicMetricEngine(register_table=reg_table)
        reg_table.write_bit("%M121", False, privilege=PrivilegeMode.SYSTEM)
        engine.sync_registers()
        assert reg_table.read_word("%R520") == 0


class TestSparkplugVerificationRunner:
    """Tests for the 9-stage verification runner."""

    def test_run_verification(self, tmp_path) -> None:
        """Verify 9-stage verification passes and writes evidence artifact."""
        out_file = tmp_path / "sparkplug_evidence.json"
        res = run_sparkplug_dynamic_verification(str(out_file))
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert out_file.exists()
