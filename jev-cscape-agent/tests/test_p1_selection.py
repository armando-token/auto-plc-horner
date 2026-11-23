"""Tests for P1FieldSelector controller model selection and I/O allocation."""

import pytest
from jev_cscape.automation.p1_selection import P1FieldSelector, ControllerSeries


def test_list_target_ids():
    targets = P1FieldSelector.list_target_ids()
    assert "P1_CANVAS_M1" in targets
    assert "P1_CANVAS_M2" in targets
    assert "P1_CANVAS_M3" in targets
    assert "P1_CANVAS_M5" in targets


def test_get_profile():
    prof = P1FieldSelector.get_profile("P1_CANVAS_M3")
    assert prof is not None
    assert prof.series == ControllerSeries.CANVAS_P1
    assert prof.io_profile.analog_outputs == 2
    assert prof.io_profile.digital_inputs == 12


def test_validate_io_allocation_within_limits():
    res = P1FieldSelector.validate_io_allocation(
        target_id="P1_CANVAS_M3",
        used_digital_in=8,
        used_digital_out=10,
        used_analog_in=2,
        used_analog_out=1,
    )
    assert res["valid"] is True
    assert len(res["violations"]) == 0


def test_validate_io_allocation_exceeded():
    res = P1FieldSelector.validate_io_allocation(
        target_id="P1_CANVAS_M1",
        used_digital_in=16,  # Model 1 has only 12
        used_digital_out=4,
        used_analog_in=1,
        used_analog_out=2,   # Model 1 has 0 AO
    )
    assert res["valid"] is False
    assert len(res["violations"]) >= 2
