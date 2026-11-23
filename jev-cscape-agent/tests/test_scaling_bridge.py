"""Comprehensive Unit Test Suite for Modbus Register Scaling Bridge & Quality Tracker.

Work Package: W027 (Gate G8)
Classification: TESTED_MOCK [offline telemetry & simulation]

Tests:
1. Linear scaling bidirectional conversion (%AI/%AQ <-> EU).
2. Square root scaling for flow meters with low-flow cutoff.
3. Piecewise linear interpolation and RTD temperature scaling.
4. NAMUR NE 43 loop current monitoring (valid, burnout <3.6mA, short-circuit >21mA).
5. 16-bit OPC UA quality word flags and encoding/decoding.
6. Modbus register word order handling (LOW_WORD_FIRST vs HIGH_WORD_FIRST).
7. IEEE 754 precision loss detection and NaN/Inf sanitization.
8. ModbusScalingBridge register mapping and synchronization with Horner OCS RegisterTable.
"""

import math
import struct
import pytest

from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable, WordOrder
from jev_cscape.telemetry.scaling_bridge import (
    ModbusRegisterType,
    ModbusScalingBridge,
    NamurNE43Validator,
    NamurValidationResult,
    OPCQualityFlag,
    QualityCode,
    ScalingType,
    TelemetryPoint,
    decode_quality_word,
    encode_quality_word,
)


class TestOPCQualityWord:
    """Test 16-bit OPC UA / OPC DA quality word encoding and decoding."""

    def test_encode_and_decode_good_quality(self):
        qw = encode_quality_word(QualityCode.GOOD)
        assert qw == 0x00C0
        qc, flags = decode_quality_word(qw)
        assert qc == QualityCode.GOOD
        assert "GOOD" in flags

    def test_encode_and_decode_uncertain_with_substatus(self):
        qw = encode_quality_word(
            QualityCode.UNCERTAIN,
            substatus=OPCQualityFlag.EU_EXCEEDED,
            limit=OPCQualityFlag.HIGH_LIMITED,
            extended_flags=OPCQualityFlag.OVERFLOW,
        )
        assert (qw & OPCQualityFlag.MAJOR_QUALITY_MASK) == OPCQualityFlag.UNCERTAIN
        assert (qw & OPCQualityFlag.LIMIT_MASK) == OPCQualityFlag.HIGH_LIMITED
        assert bool(qw & OPCQualityFlag.OVERFLOW)

        qc, flags = decode_quality_word(qw)
        assert qc == QualityCode.UNCERTAIN
        assert "HIGH_LIMITED" in flags
        assert "OVERFLOW" in flags

    def test_encode_and_decode_bad_with_sensor_failure_and_burnout(self):
        qw = encode_quality_word(
            QualityCode.BAD,
            substatus=OPCQualityFlag.SENSOR_FAILURE,
            limit=OPCQualityFlag.LOW_LIMITED,
            extended_flags=OPCQualityFlag.BURNOUT | OPCQualityFlag.UNDERFLOW,
        )
        assert (qw & OPCQualityFlag.MAJOR_QUALITY_MASK) == OPCQualityFlag.BAD
        assert bool(qw & OPCQualityFlag.SENSOR_FAILURE)
        assert bool(qw & OPCQualityFlag.BURNOUT)
        assert bool(qw & OPCQualityFlag.UNDERFLOW)

        qc, flags = decode_quality_word(qw)
        assert qc == QualityCode.BAD
        assert "SENSOR_FAILURE" in flags
        assert "BURNOUT" in flags
        assert "UNDERFLOW" in flags


class TestNamurNE43Validator:
    """Test NAMUR NE 43 4-20mA current loop monitoring."""

    def test_burnout_detection_below_3_6ma(self):
        # Current < 3.6 mA is burnout failure
        res = NamurNE43Validator.validate_current(3.2)
        assert not res.is_valid
        assert res.quality_code == QualityCode.BAD
        assert res.failure_mode == "BURNOUT"
        assert bool(res.quality_word & OPCQualityFlag.BURNOUT)
        assert bool(res.quality_word & OPCQualityFlag.SENSOR_FAILURE)

    def test_underrange_warning_between_3_6_and_3_8ma(self):
        # 3.6 mA <= I < 3.8 mA is measuring under-range warning
        res = NamurNE43Validator.validate_current(3.7)
        assert not res.is_valid
        assert res.quality_code == QualityCode.UNCERTAIN
        assert res.failure_mode == "UNDERRANGE"
        assert bool(res.quality_word & OPCQualityFlag.UNDERFLOW)
        assert bool(res.quality_word & OPCQualityFlag.LOW_LIMITED)

    def test_valid_operating_range_between_3_8_and_20_5ma(self):
        # 3.8 mA <= I <= 20.5 mA is valid operating range
        for ma in [3.8, 4.0, 12.0, 20.0, 20.5]:
            res = NamurNE43Validator.validate_current(ma)
            assert res.is_valid, f"Expected valid at {ma} mA"
            assert res.quality_code == QualityCode.GOOD
            assert res.failure_mode is None
            assert (res.quality_word & OPCQualityFlag.MAJOR_QUALITY_MASK) == OPCQualityFlag.GOOD

    def test_overrange_warning_between_20_5_and_21_0ma(self):
        # 20.5 mA < I <= 21.0 mA is measuring over-range warning
        res = NamurNE43Validator.validate_current(20.8)
        assert not res.is_valid
        assert res.quality_code == QualityCode.UNCERTAIN
        assert res.failure_mode == "OVERRANGE"
        assert bool(res.quality_word & OPCQualityFlag.OVERFLOW)
        assert bool(res.quality_word & OPCQualityFlag.HIGH_LIMITED)

    def test_short_circuit_detection_above_21ma(self):
        # Current > 21.0 mA is short-circuit failure
        res = NamurNE43Validator.validate_current(21.5)
        assert not res.is_valid
        assert res.quality_code == QualityCode.BAD
        assert res.failure_mode == "SHORT_CIRCUIT"
        assert bool(res.quality_word & OPCQualityFlag.SHORT_CIRCUIT)
        assert bool(res.quality_word & OPCQualityFlag.SENSOR_FAILURE)

    def test_raw_to_current_conversion_and_raw_validation(self):
        # 4mA = 0 counts, 20mA = 32000 counts
        ma_4 = NamurNE43Validator.raw_to_current(0, raw_min_4ma=0, raw_max_20ma=32000)
        assert pytest.approx(ma_4, abs=1e-3) == 4.0

        ma_20 = NamurNE43Validator.raw_to_current(32000, raw_min_4ma=0, raw_max_20ma=32000)
        assert pytest.approx(ma_20, abs=1e-3) == 20.0

        ma_12 = NamurNE43Validator.raw_to_current(16000, raw_min_4ma=0, raw_max_20ma=32000)
        assert pytest.approx(ma_12, abs=1e-3) == 12.0

        # Validate raw burnout (-1000 counts -> 3.5mA)
        res_burnout = NamurNE43Validator.validate_raw(-1000, raw_min_4ma=0, raw_max_20ma=32000)
        assert res_burnout.failure_mode == "BURNOUT"
        assert res_burnout.quality_code == QualityCode.BAD

        # Validate raw short-circuit (35000 counts -> 21.5mA)
        res_short = NamurNE43Validator.validate_raw(35000, raw_min_4ma=0, raw_max_20ma=32000)
        assert res_short.failure_mode == "SHORT_CIRCUIT"
        assert res_short.quality_code == QualityCode.BAD


class TestTelemetryPointLinearScaling:
    """Test Linear scaling bidirectional conversion and quality assessment."""

    def test_linear_scaling_full_span(self):
        pt = TelemetryPoint(
            name="TANK_LEVEL",
            channel="%AI1",
            modbus_address=30001,
            scaling_type=ScalingType.LINEAR,
            raw_min=0.0,
            raw_max=32000.0,
            eu_min=0.0,
            eu_max=100.0,
            eu_unit="%",
        )

        # Raw -> EU
        eu_0, qc_0, _ = pt.raw_to_eu(0)
        assert pytest.approx(eu_0, abs=1e-2) == 0.0
        assert qc_0 == QualityCode.GOOD

        eu_50, qc_50, _ = pt.raw_to_eu(16000)
        assert pytest.approx(eu_50, abs=1e-2) == 50.0
        assert qc_50 == QualityCode.GOOD

        eu_100, qc_100, _ = pt.raw_to_eu(32000)
        assert pytest.approx(eu_100, abs=1e-2) == 100.0
        assert qc_100 == QualityCode.GOOD

        # EU -> Raw
        raw_0, _, _ = pt.eu_to_raw(0.0)
        assert raw_0 == 0

        raw_50, _, _ = pt.eu_to_raw(50.0)
        assert raw_50 == 16000

        raw_100, _, _ = pt.eu_to_raw(100.0)
        assert raw_100 == 32000

    def test_linear_scaling_with_negative_eu_range(self):
        pt = TelemetryPoint(
            name="CHILLER_TEMP",
            channel="%AI2",
            modbus_address=30003,
            scaling_type=ScalingType.LINEAR,
            raw_min=4000.0,
            raw_max=20000.0,
            eu_min=-20.0,
            eu_max=80.0,
            eu_unit="degC",
        )

        eu_min, _, _ = pt.raw_to_eu(4000)
        assert pytest.approx(eu_min, abs=1e-2) == -20.0

        eu_mid, _, _ = pt.raw_to_eu(12000)
        assert pytest.approx(eu_mid, abs=1e-2) == 30.0

        eu_max, _, _ = pt.raw_to_eu(20000)
        assert pytest.approx(eu_max, abs=1e-2) == 80.0

        # Reverse
        raw_mid, _, _ = pt.eu_to_raw(30.0)
        assert raw_mid == 12000

    def test_linear_scaling_with_namur_monitoring(self):
        pt = TelemetryPoint(
            name="PRESSURE_4_20MA",
            channel="%AI3",
            modbus_address=30005,
            scaling_type=ScalingType.LINEAR,
            raw_min=0.0,
            raw_max=32000.0,
            eu_min=0.0,
            eu_max=10.0,
            eu_unit="bar",
            namur_ne43_enabled=True,
            namur_raw_4ma=0.0,
            namur_raw_20ma=32000.0,
        )

        # Normal value (16000 counts = 12mA = 5 bar)
        eu_norm, qc_norm, qw_norm = pt.raw_to_eu(16000)
        assert pytest.approx(eu_norm, abs=1e-2) == 5.0
        assert qc_norm == QualityCode.GOOD

        # Burnout condition: raw = -1200 counts (< 3.6mA)
        eu_burn, qc_burn, qw_burn = pt.raw_to_eu(-1200)
        assert qc_burn == QualityCode.BAD
        assert bool(qw_burn & OPCQualityFlag.BURNOUT)

        # Short-circuit condition: raw = 36000 counts (> 21mA)
        eu_short, qc_short, qw_short = pt.raw_to_eu(36000)
        assert qc_short == QualityCode.BAD
        assert bool(qw_short & OPCQualityFlag.SHORT_CIRCUIT)


class TestTelemetryPointSquareRootScaling:
    """Test Square Root scaling (flow meters based on differential pressure)."""

    def test_sqrt_flow_scaling_profile(self):
        # Differential pressure transmitter: Flow Q = Q_max * sqrt(DP / DP_max)
        pt = TelemetryPoint(
            name="VENTURI_FLOW",
            channel="%AI4",
            modbus_address=30007,
            scaling_type=ScalingType.SQUARE_ROOT,
            raw_min=0.0,
            raw_max=32000.0,
            eu_min=0.0,
            eu_max=500.0,
            eu_unit="m3/h",
            low_flow_cutoff_percent=0.0,
        )

        # 0% DP (0 counts) -> 0 m3/h
        eu_0, _, _ = pt.raw_to_eu(0)
        assert pytest.approx(eu_0, abs=1e-2) == 0.0

        # 25% DP (8000 counts) -> sqrt(0.25) * 500 = 0.5 * 500 = 250 m3/h
        eu_25, _, _ = pt.raw_to_eu(8000)
        assert pytest.approx(eu_25, abs=1e-2) == 250.0

        # 100% DP (32000 counts) -> sqrt(1.0) * 500 = 500 m3/h
        eu_100, _, _ = pt.raw_to_eu(32000)
        assert pytest.approx(eu_100, abs=1e-2) == 500.0

        # Reverse conversion: EU -> Raw
        # 250 m3/h (50% flow) -> 25% DP (8000 counts)
        raw_25, _, _ = pt.eu_to_raw(250.0)
        assert raw_25 == 8000

        # 500 m3/h -> 32000 counts
        raw_100, _, _ = pt.eu_to_raw(500.0)
        assert raw_100 == 32000

    def test_low_flow_cutoff_enforcement(self):
        # Low flow cutoff: below 2.0% DP span, flow is forced to 0.0
        pt = TelemetryPoint(
            name="ORIFICE_FLOW",
            channel="%AI5",
            modbus_address=30009,
            scaling_type=ScalingType.SQUARE_ROOT,
            raw_min=0.0,
            raw_max=32000.0,
            eu_min=0.0,
            eu_max=100.0,
            eu_unit="L/min",
            low_flow_cutoff_percent=2.0,  # Cutoff at 2% DP (640 counts)
        )

        # Raw = 320 counts (1% DP < 2% cutoff) -> flow forced to 0.0
        eu_cutoff, _, _ = pt.raw_to_eu(320)
        assert pytest.approx(eu_cutoff, abs=1e-2) == 0.0

        # Raw = 1280 counts (4% DP > 2% cutoff) -> sqrt(0.04) * 100 = 20 L/min
        eu_active, _, _ = pt.raw_to_eu(1280)
        assert pytest.approx(eu_active, abs=1e-2) == 20.0


class TestPiecewiseAndRTDScaling:
    """Test Piecewise calibration curve and RTD temperature scaling."""

    def test_piecewise_linear_interpolation(self):
        # Non-linear tank volume curve
        calibration_points = [
            (0.0, 0.0),
            (5000.0, 10.0),
            (15000.0, 50.0),
            (32000.0, 200.0),
        ]
        pt = TelemetryPoint(
            name="TANK_VOLUME",
            channel="%AI6",
            modbus_address=30011,
            scaling_type=ScalingType.PIECEWISE,
            eu_min=0.0,
            eu_max=200.0,
            eu_unit="m3",
            piecewise_points=calibration_points,
        )

        # Exactly on calibration point
        eu_mid, _, _ = pt.raw_to_eu(5000)
        assert pytest.approx(eu_mid, abs=1e-2) == 10.0

        # Midpoint of first segment: raw = 2500 -> EU = 5.0
        eu_interp1, _, _ = pt.raw_to_eu(2500)
        assert pytest.approx(eu_interp1, abs=1e-2) == 5.0

        # Midpoint of second segment: raw = 10000 -> EU = 10 + 0.5 * (50 - 10) = 30.0
        eu_interp2, _, _ = pt.raw_to_eu(10000)
        assert pytest.approx(eu_interp2, abs=1e-2) == 30.0

        # Reverse conversion
        raw_rev, _, _ = pt.eu_to_raw(30.0)
        assert raw_rev == 10000

    def test_rtd_tenths_deg_c_mode(self):
        # Standard Horner HE-RTD module format: raw count is 0.1 degC
        pt = TelemetryPoint(
            name="REACTOR_TEMP",
            channel="%AI7",
            modbus_address=30013,
            scaling_type=ScalingType.RTD,
            rtd_mode="TENTHS_DEG_C",
            eu_min=-50.0,
            eu_max=250.0,
            eu_unit="degC",
        )

        eu_val, qc, _ = pt.raw_to_eu(254)  # 25.4 degC
        assert pytest.approx(eu_val, abs=1e-2) == 25.4
        assert qc == QualityCode.GOOD

        eu_neg, _, _ = pt.raw_to_eu(-150)  # -15.0 degC
        assert pytest.approx(eu_neg, abs=1e-2) == -15.0

        # Reverse
        raw_rev, _, _ = pt.eu_to_raw(25.4)
        assert raw_rev == 254

    def test_rtd_resistance_callendar_van_dusen(self):
        # PT100 platinum RTD: 100.0 ohms at 0 degC, approx 138.51 ohms at 100 degC
        pt = TelemetryPoint(
            name="PT100_SENSOR",
            channel="%AI8",
            modbus_address=30015,
            scaling_type=ScalingType.RTD,
            rtd_mode="RESISTANCE",
            rtd_r0=100.0,
            eu_min=-200.0,
            eu_max=600.0,
            eu_unit="degC",
        )

        # 100.0 ohms -> 0.0 degC
        eu_0, _, _ = pt.raw_to_eu(100)
        assert pytest.approx(eu_0, abs=0.1) == 0.0

        # 138.5 ohms -> ~100.0 degC
        eu_100, _, _ = pt.raw_to_eu(138)
        assert 98.0 <= eu_100 <= 100.0

        # Reverse: 0.0 degC -> 100 ohms
        raw_0, _, _ = pt.eu_to_raw(0.0)
        assert raw_0 == 100


class TestPrecisionLossAndNanSanitization:
    """Test IEEE 754 precision loss detection and NaN/Inf sanitization."""

    def test_ieee754_precision_loss_detection(self):
        # A float with high mantissa precision that cannot be preserved in float32
        pt = TelemetryPoint(
            name="PRECISION_TEST",
            channel="%AI9",
            modbus_address=30017,
            scaling_type=ScalingType.LINEAR,
            raw_min=0.0,
            raw_max=10000000.0,
            eu_min=0.0,
            eu_max=1234567.89,
        )

        # Converting a value like 1234567.89 to float32 loses precision
        _, _, qw = pt.eu_to_raw(1234567.89)
        assert bool(qw & OPCQualityFlag.PRECISION_LOSS)

    def test_nan_and_inf_sanitization(self):
        pt = TelemetryPoint(
            name="NAN_TEST",
            channel="%AI10",
            modbus_address=30019,
            scaling_type=ScalingType.LINEAR,
            eu_min=0.0,
            eu_max=100.0,
        )

        # Input NaN float
        raw_nan, qc_nan, qw_nan = pt.eu_to_raw(float("nan"))
        assert raw_nan == 0
        assert qc_nan == QualityCode.BAD
        assert bool(qw_nan & OPCQualityFlag.NAN_INF_FAULT)

        # Input Inf float
        raw_inf, qc_inf, qw_inf = pt.eu_to_raw(float("inf"))
        assert raw_inf == 0
        assert qc_inf == QualityCode.BAD
        assert bool(qw_inf & OPCQualityFlag.NAN_INF_FAULT)


class TestModbusWordOrder:
    """Test Modbus word order endianness handling (LOW_WORD_FIRST vs HIGH_WORD_FIRST)."""

    def test_word_order_endianness_swapping(self):
        test_val = 123.456

        pt_low = TelemetryPoint(
            name="FLOAT_LOW",
            channel="%AI11",
            modbus_address=30021,
            word_order=WordOrder.LOW_WORD_FIRST,
        )
        words_low = pt_low.encode_modbus_words(test_val)

        pt_high = TelemetryPoint(
            name="FLOAT_HIGH",
            channel="%AI12",
            modbus_address=30023,
            word_order=WordOrder.HIGH_WORD_FIRST,
        )
        words_high = pt_high.encode_modbus_words(test_val)

        # Words should be swapped between low-word-first and high-word-first
        assert words_low[0] == words_high[1]
        assert words_low[1] == words_high[0]

        # Decoding with matching word order reconstructs original value
        unpacked_low, _, _ = pt_low.decode_modbus_words(words_low)
        unpacked_high, _, _ = pt_high.decode_modbus_words(words_high)

        assert pytest.approx(unpacked_low, abs=1e-3) == test_val
        assert pytest.approx(unpacked_high, abs=1e-3) == test_val

        # Decoding with inverted word order produces corrupt value
        corrupt, _, _ = pt_low.decode_modbus_words(words_high)
        assert abs(corrupt - test_val) > 10.0


class TestModbusScalingBridgeIntegration:
    """Test full ModbusScalingBridge mapping, register updates, and OCS synchronization."""

    def test_bridge_registration_and_modbus_register_io(self):
        bridge = ModbusScalingBridge()

        pt1 = TelemetryPoint(
            name="LEVEL_PT",
            channel="%AI1",
            modbus_address=30001,
            modbus_register_type=ModbusRegisterType.INPUT,
            scaling_type=ScalingType.LINEAR,
            raw_min=0.0,
            raw_max=32000.0,
            eu_min=0.0,
            eu_max=100.0,
            eu_unit="%",
            quality_modbus_address=30003,
        )
        bridge.register_point(pt1)

        # Update point from raw OCS counts (16000 counts = 50%)
        eu_val = bridge.update_point_raw("LEVEL_PT", 16000)
        assert pytest.approx(eu_val, abs=1e-2) == 50.0

        # Read Modbus input registers (addresses 30001..30003)
        regs = bridge.read_modbus_registers(30001, 3, reg_type=ModbusRegisterType.INPUT)
        assert len(regs) == 3

        # First 2 words contain float 50.0
        unpacked_eu = pt1.decode_modbus_words([regs[0], regs[1]])[0]
        assert pytest.approx(unpacked_eu, abs=1e-2) == 50.0

        # Third word contains quality word (0x00C0 = GOOD)
        assert regs[2] == 0x00C0

    def test_bridge_holding_register_write_decoding(self):
        bridge = ModbusScalingBridge()

        pt_sp = TelemetryPoint(
            name="FLOW_SP",
            channel="%AQ1",
            modbus_address=40001,
            modbus_register_type=ModbusRegisterType.HOLDING,
            scaling_type=ScalingType.LINEAR,
            raw_min=0.0,
            raw_max=32000.0,
            eu_min=0.0,
            eu_max=200.0,
            eu_unit="m3/h",
            word_order=WordOrder.LOW_WORD_FIRST,
        )
        bridge.register_point(pt_sp)

        # Encode float 150.0 into 2 words and write via Modbus holding registers
        words = pt_sp.encode_modbus_words(150.0)
        bridge.write_modbus_registers(40001, words, reg_type=ModbusRegisterType.HOLDING)

        # Check that point internal state updated
        assert pytest.approx(pt_sp.current_eu, abs=1e-2) == 150.0
        # 150 / 200 * 32000 = 24000 counts
        assert pt_sp.current_raw == 24000

    def test_bridge_synchronization_with_ocs_register_table(self):
        reg_table = RegisterTable()
        bridge = ModbusScalingBridge()

        pt_ai = TelemetryPoint(
            name="PRESSURE_IN",
            channel="%AI1",
            modbus_address=30001,
            modbus_register_type=ModbusRegisterType.INPUT,
            scaling_type=ScalingType.LINEAR,
            raw_min=0.0,
            raw_max=32000.0,
            eu_min=0.0,
            eu_max=10.0,
            eu_unit="bar",
        )
        pt_aq = TelemetryPoint(
            name="VALVE_OUT",
            channel="%AQ1",
            modbus_address=40001,
            modbus_register_type=ModbusRegisterType.HOLDING,
            scaling_type=ScalingType.LINEAR,
            raw_min=0.0,
            raw_max=32000.0,
            eu_min=0.0,
            eu_max=100.0,
            eu_unit="%",
        )
        bridge.register_point(pt_ai)
        bridge.register_point(pt_aq)

        # 1. OCS %AI1 set to 8000 counts (2.5 bar)
        reg_table.write_word("%AI1", 8000, privilege=PrivilegeMode.SYSTEM)

        # Sync from OCS into bridge
        sync_results = bridge.sync_from_ocs(reg_table)
        assert pytest.approx(sync_results["PRESSURE_IN"], abs=1e-2) == 2.5
        assert pytest.approx(pt_ai.current_eu, abs=1e-2) == 2.5

        # 2. Update VALVE_OUT EU setpoint to 75.0% (24000 counts)
        bridge.update_point_eu("VALVE_OUT", 75.0)

        # Sync to OCS register table
        sync_to_results = bridge.sync_to_ocs(reg_table, privilege=PrivilegeMode.SYSTEM)
        assert sync_to_results["VALVE_OUT"] == 24000
        assert reg_table.read_word("%AQ1") == 24000

    def test_bridge_quality_summary_reporting(self):
        bridge = ModbusScalingBridge()

        pt_good = TelemetryPoint(
            name="PT_GOOD",
            channel="%AI1",
            modbus_address=30001,
            scaling_type=ScalingType.LINEAR,
            namur_ne43_enabled=True,
        )
        pt_bad = TelemetryPoint(
            name="PT_BAD",
            channel="%AI2",
            modbus_address=30003,
            scaling_type=ScalingType.LINEAR,
            namur_ne43_enabled=True,
        )
        bridge.register_point(pt_good)
        bridge.register_point(pt_bad)

        # pt_good = normal 16000 counts (12mA)
        bridge.update_point_raw("PT_GOOD", 16000)
        # pt_bad = burnout -1500 counts (<3.6mA)
        bridge.update_point_raw("PT_BAD", -1500)

        summary = bridge.get_quality_summary()
        assert summary["total_points"] == 2
        assert summary["good_count"] == 1
        assert summary["bad_count"] == 1
        assert summary["points"]["PT_GOOD"]["quality"] == "GOOD"
        assert summary["points"]["PT_BAD"]["quality"] == "BAD"
        assert "BURNOUT" in summary["points"]["PT_BAD"]["quality_flags"]
