"""Comprehensive Unit Test Suite for Horner OCS RegisterTable.

Work Package: W019 (Gate G4)
Classification: TESTED_MOCK [offline/DEV only]

Tests full 14-channel Horner OCS register space, bit-slicing (%R100.1..%R100.16),
multi-word 32-bit types (DINT, UDINT, REAL), access privilege enforcement,
double-buffering, and snapshot diffing.
"""

import math
import pytest

from jev_cscape.automation.channel_matrix import ChannelAccess
from jev_cscape.simulation.register_table import (
    BitSliceOps,
    EXTENDED_CHANNELS,
    PrivilegeMode,
    ReadOnlyChannelError,
    RegisterAddress,
    RegisterTable,
    WordOrder,
    dint_to_words,
    float_to_words,
    udint_to_words,
    words_to_dint,
    words_to_float,
    words_to_udint,
)


class TestRegisterAddressParsing:
    """Test register address parsing and boundary enforcement."""

    def test_parse_valid_word_registers(self):
        reg_r = RegisterTable.parse_address("%R100")
        assert reg_r.prefix == "%R"
        assert reg_r.index == 100
        assert reg_r.bit_slice is None
        assert not reg_r.is_bit_slice
        assert reg_r.channel_type.access == ChannelAccess.READ_WRITE

        reg_ai = RegisterTable.parse_address("%AI4")
        assert reg_ai.prefix == "%AI"
        assert reg_ai.index == 4
        assert reg_ai.channel_type.access == ChannelAccess.READ_ONLY

        reg_sr = RegisterTable.parse_address("%SR256")
        assert reg_sr.prefix == "%SR"
        assert reg_sr.index == 256

    def test_parse_extended_global_channels(self):
        reg_ig = RegisterTable.parse_address("%IG50")
        assert reg_ig.prefix == "%IG"
        assert reg_ig.index == 50
        assert reg_ig.channel_type.access == ChannelAccess.READ_ONLY

        reg_qg = RegisterTable.parse_address("%QG12")
        assert reg_qg.prefix == "%QG"
        assert reg_qg.index == 12
        assert reg_qg.channel_type.access == ChannelAccess.READ_WRITE

        reg_aig = RegisterTable.parse_address("%AIG5")
        assert reg_aig.prefix == "%AIG"
        assert reg_aig.index == 5
        assert reg_aig.channel_type.access == ChannelAccess.READ_ONLY

        reg_aqg = RegisterTable.parse_address("%AQG8")
        assert reg_aqg.prefix == "%AQG"
        assert reg_aqg.index == 8
        assert reg_aqg.channel_type.access == ChannelAccess.READ_WRITE

    def test_parse_valid_bit_slice(self):
        reg = RegisterTable.parse_address("%R100.1")
        assert reg.prefix == "%R"
        assert reg.index == 100
        assert reg.bit_slice == 1
        assert reg.is_bit_slice
        assert reg.word_address == "%R100"

        reg16 = RegisterTable.parse_address("%R100.16")
        assert reg16.bit_slice == 16

        reg_ai_slice = RegisterTable.parse_address("%AI1.8")
        assert reg_ai_slice.prefix == "%AI"
        assert reg_ai_slice.bit_slice == 8

    def test_out_of_range_indices_rejected(self):
        with pytest.raises(ValueError, match="out of range for %R"):
            RegisterTable.parse_address("%R10000")

        with pytest.raises(ValueError, match="out of range for %SR"):
            RegisterTable.parse_address("%SR257")

        with pytest.raises(ValueError, match="out of range for %AI"):
            RegisterTable.parse_address("%AI513")

        with pytest.raises(ValueError, match="out of range for %S"):
            RegisterTable.parse_address("%S17")

        with pytest.raises(ValueError, match="out of range for %K"):
            RegisterTable.parse_address("%K129")

    def test_invalid_bit_slices_rejected(self):
        with pytest.raises(ValueError, match="out of range"):
            RegisterTable.parse_address("%R100.0")

        with pytest.raises(ValueError, match="out of range"):
            RegisterTable.parse_address("%R100.17")

        # Bit slice on discrete channel is illegal
        with pytest.raises(TypeError, match="only permitted on 16-bit word registers"):
            RegisterTable.parse_address("%I1.1")

        with pytest.raises(TypeError, match="only permitted on 16-bit word registers"):
            RegisterTable.parse_address("%Q1.5")


class TestBitSliceOps:
    """Test BitSliceOps extraction and packing mechanics."""

    def test_extract_bits_1_based(self):
        # 0x0001: bit 1 is True, all others False
        assert BitSliceOps.extract_bit(0x0001, 1) is True
        assert BitSliceOps.extract_bit(0x0001, 2) is False

        # 0x8000: bit 16 is True, all others False
        assert BitSliceOps.extract_bit(0x8000, 16) is True
        assert BitSliceOps.extract_bit(0x8000, 1) is False

        # 0x00AA = 0b0000000010101010 -> bits 2, 4, 6, 8 True
        val = 0x00AA
        for bit in range(1, 17):
            expected = bool((val >> (bit - 1)) & 1)
            assert BitSliceOps.extract_bit(val, bit) == expected

    def test_pack_bit_preserves_adjacent_bits(self):
        word = 0x0000
        # Set bit 1 (LSB)
        word = BitSliceOps.pack_bit(word, 1, True)
        assert word == 1

        # Set bit 4 (weight 8)
        word = BitSliceOps.pack_bit(word, 4, True)
        assert word == 9  # 1 + 8

        # Clear bit 1
        word = BitSliceOps.pack_bit(word, 1, False)
        assert word == 8

        # Set bit 16 (MSB, signed 16-bit negative)
        word = BitSliceOps.pack_bit(word, 16, True)
        assert BitSliceOps.extract_bit(word, 16) is True
        assert BitSliceOps.extract_bit(word, 4) is True
        assert BitSliceOps.extract_bit(word, 1) is False


class TestWordAndBitAccess:
    """Test basic word and discrete bit access and clamping."""

    def test_write_and_read_word_clamping(self):
        table = RegisterTable()
        table.write_word("%R1", 100)
        table.commit_staged()
        assert table.read_word("%R1") == 100

        # Max positive signed 16-bit
        table.write_word("%R2", 32767)
        table.commit_staged()
        assert table.read_word("%R2") == 32767

        # Negative value
        table.write_word("%R3", -100)
        table.commit_staged()
        assert table.read_word("%R3") == -100

        # Overflow wraps to signed 16-bit: 65535 -> -1
        table.write_word("%R4", 65535)
        table.commit_staged()
        assert table.read_word("%R4") == -1
        assert table.read_uword("%R4") == 65535

    def test_discrete_bits_read_write(self):
        table = RegisterTable()
        table.write_bit("%Q1", True)
        table.write_bit("%M5", True)
        table.commit_staged()

        assert table.read_bit("%Q1") is True
        assert table.read_bit("%Q2") is False
        assert table.read_bit("%M5") is True

    def test_bit_slicing_integration_with_word(self):
        table = RegisterTable()
        # Initial word is 0
        assert table.read_word("%R50") == 0
        assert table.read_bit("%R50.1") is False

        # Set bit 1 via bit slicing
        table.write_bit("%R50.1", True)
        table.commit_staged()
        assert table.read_bit("%R50.1") is True
        assert table.read_word("%R50") == 1

        # Set bit 2 via bit slicing
        table.write_bit("%R50.2", True)
        table.commit_staged()
        assert table.read_word("%R50") == 3

        # Mutate entire word directly, assert bit slice reflects change
        table.write_word("%R50", 0x8000)
        table.commit_staged()
        assert table.read_bit("%R50.16") is True
        assert table.read_bit("%R50.1") is False


class TestAccessPrivilegeControl:
    """Test read-only protection in application mode vs system mode."""

    def test_application_mode_rejects_read_only_channel_writes(self):
        table = RegisterTable()
        table.privilege_mode = PrivilegeMode.APPLICATION

        with pytest.raises(ReadOnlyChannelError):
            table.write_bit("%S1", False)

        with pytest.raises(ReadOnlyChannelError):
            table.write_word("%SR1", 50)

        with pytest.raises(ReadOnlyChannelError):
            table.write_word("%AI1", 1234)

        with pytest.raises(ReadOnlyChannelError):
            table.write_bit("%K1", True)

        with pytest.raises(ReadOnlyChannelError):
            table.write_bit("%IG1", True)

        with pytest.raises(ReadOnlyChannelError):
            table.write_word("%AIG1", 100)

    def test_system_mode_allows_writes(self):
        table = RegisterTable()
        table.privilege_mode = PrivilegeMode.SYSTEM

        table.write_word("%SR1", 1234)
        assert table.read_word("%SR1") == 1234

        table.write_word("%AI1", 4000)
        table.latch_inputs()
        assert table.read_word("%AI1") == 4000

    def test_system_helper_methods(self):
        table = RegisterTable()
        table.set_input("%AI2", 8192)
        table.latch_inputs()
        assert table.read_word("%AI2") == 8192

        table.set_system_register("%SR5", 25)
        assert table.read_word("%SR5") == 25

        table.set_system_bit("%S2", False)
        assert table.read_bit("%S2") is False


class TestMultiWord32BitTypes:
    """Test 32-bit DINT, UDINT, and REAL conversions across consecutive registers."""

    def test_dint_conversions(self):
        table = RegisterTable()
        values = [0, 1, -1, 100000, -100000, 2147483647, -2147483648]
        for v in values:
            table.write_dint("%R101", v)
            table.commit_staged()
            assert table.read_dint("%R101") == v

    def test_udint_conversions(self):
        table = RegisterTable()
        values = [0, 1, 65535, 65536, 1000000, 4294967295]
        for v in values:
            table.write_udint("%R201", v)
            table.commit_staged()
            assert table.read_udint("%R201") == v

    def test_real_conversions(self):
        table = RegisterTable()
        values = [0.0, 1.0, -1.0, 55.0, 123.456, -987.654, float("inf"), float("-inf")]
        for v in values:
            table.write_real("%R301", v)
            table.commit_staged()
            read_back = table.read_real("%R301")
            if math.isinf(v):
                assert math.isinf(read_back)
                assert (v > 0) == (read_back > 0)
            else:
                assert pytest.approx(read_back, rel=1e-5) == v

    def test_horner_word_order_low_word_first(self):
        # Horner OCS standard: %R101 = Low Word, %R102 = High Word
        # 55.0 in IEEE 754: 0x425c0000
        # Low word: 0x0000 (0), High word: 0x425c (16988)
        table = RegisterTable()
        table.write_real("%R101", 55.0, word_order=WordOrder.LOW_WORD_FIRST)
        table.commit_staged()

        assert table.read_word("%R101") == 0
        assert table.read_word("%R102") == 16988

    def test_modbus_swapped_word_order(self):
        # Modbus swapped: %R101 = High Word, %R102 = Low Word
        table = RegisterTable()
        table.write_real("%R101", 55.0, word_order=WordOrder.HIGH_WORD_FIRST)
        table.commit_staged()

        assert table.read_word("%R101") == 16988
        assert table.read_word("%R102") == 0
        assert pytest.approx(table.read_real("%R101", word_order=WordOrder.HIGH_WORD_FIRST), 1e-5) == 55.0

    def test_consecutive_register_boundary_overflow_rejected(self):
        table = RegisterTable()
        # %R has range 1..9999. Allocating 2 words at %R9999 overflows to %R10000
        with pytest.raises(IndexError, match="exceeds maximum channel boundary"):
            table.write_dint("%R9999", 100)

        with pytest.raises(IndexError, match="exceeds maximum channel boundary"):
            table.read_real("%R9999")


class TestDoubleBufferingAndPhasing:
    """Test double-buffering, input latching, output staging, and transactional rollback."""

    def test_input_latching_isolation(self):
        table = RegisterTable()
        table.set_input("%I1", True)

        # Before latching, latched inputs are empty
        assert "%I1" not in table.latched_inputs

        # Phase 1: latch
        table.latch_inputs()
        assert table.read_bit("%I1") is True

        # External write mid-scan updates pending but not latched
        table.set_input("%I1", False)
        assert table.read_bit("%I1") is True  # Still True during active scan

        # Next scan latches the new value
        table.latch_inputs()
        assert table.read_bit("%I1") is False

    def test_output_staging_and_commit(self):
        table = RegisterTable()
        table.write_register("%Q1", True)
        table.write_register("%AQ1", 1200)

        # Before commit: staged has values, committed does not
        assert table.staged_writes["%Q1"] is True
        assert table.get_committed_output("%Q1") is False

        # Read-your-own-writes returns staged value
        assert table.read_register("%Q1") is True
        assert table.read_word("%AQ1") == 1200

        # Phase 3: commit
        modified = table.commit_staged()
        assert "%Q1" in modified
        assert "%AQ1" in modified
        assert table.get_committed_output("%Q1") is True
        assert table.read_word("%AQ1") == 1200
        assert len(table.staged_writes) == 0

    def test_transactional_rollback_on_fault(self):
        table = RegisterTable()
        table.write_register("%Q1", True)
        table.write_word("%R1", 999)

        # Trigger rollback on unhandled fault
        table.rollback_staged()

        # Staged writes discarded
        assert len(table.staged_writes) == 0
        assert table.get_committed_output("%Q1") is False
        assert table.read_word("%R1") == 0
        assert table.read_word("%SR2") == 3  # FAULTED


class TestSnapshotsAndDiffing:
    """Test snapshot creation, diffing, and restoration."""

    def test_snapshot_and_diff(self):
        table = RegisterTable()
        snap1 = table.snapshot()

        table.write_word("%R100", 1500)
        table.write_word("%AQ1", 32000)
        table.commit_staged()

        diff_result = table.diff(snap1)
        assert diff_result["mutations_count"] == 2
        assert diff_result["registers"]["%R100"]["new_value"] == 1500
        assert diff_result["registers"]["%AQ1"]["new_value"] == 32000

    def test_restore_snapshot(self):
        table = RegisterTable()
        table.write_word("%R10", 777)
        table.commit_staged()
        snap = table.snapshot()

        table.write_word("%R10", 888)
        table.commit_staged()
        assert table.read_word("%R10") == 888

        table.restore_snapshot(snap)
        assert table.read_word("%R10") == 777
