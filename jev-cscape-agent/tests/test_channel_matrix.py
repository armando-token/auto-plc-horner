"""Tests for ChannelMatrix Horner OCS register parsing and range validation."""

import pytest
from jev_cscape.automation.channel_matrix import ChannelMatrix, ChannelAccess


def test_channels_count():
    matrix = ChannelMatrix.export_matrix()
    assert matrix["channels_count"] == 10
    assert "%R" in matrix["channels"]
    assert "%AI" in matrix["channels"]
    assert "%I" in matrix["channels"]
    assert "%S" in matrix["channels"]


def test_parse_valid_registers():
    r1 = ChannelMatrix.parse_register("%R100")
    assert r1.is_valid is True
    assert r1.prefix == "%R"
    assert r1.index == 100
    assert r1.channel_type.access == ChannelAccess.READ_WRITE

    ai1 = ChannelMatrix.parse_register("%AI4")
    assert ai1.is_valid is True
    assert ai1.prefix == "%AI"
    assert ai1.index == 4
    assert ai1.channel_type.access == ChannelAccess.READ_ONLY

    q12 = ChannelMatrix.parse_register("Q12")
    assert q12.is_valid is True
    assert q12.prefix == "%Q"
    assert q12.index == 12

    s1 = ChannelMatrix.parse_register("%S1")
    assert s1.is_valid is True
    assert s1.prefix == "%S"
    assert s1.index == 1
    assert s1.channel_type.access == ChannelAccess.READ_ONLY


def test_parse_out_of_range_register():
    r_bad = ChannelMatrix.parse_register("%R10000")  # max is 9999
    assert r_bad.is_valid is False
    assert "out of range" in r_bad.error

    sr_bad = ChannelMatrix.parse_register("%SR300")  # max is 256
    assert sr_bad.is_valid is False
    assert "out of range" in sr_bad.error

    s_bad = ChannelMatrix.parse_register("%S20")  # max is 16
    assert s_bad.is_valid is False
    assert "out of range" in s_bad.error


def test_parse_invalid_prefix():
    bad_pfx = ChannelMatrix.parse_register("%ZZ99")
    assert bad_pfx.is_valid is False
    assert "Unrecognized memory prefix" in bad_pfx.error
