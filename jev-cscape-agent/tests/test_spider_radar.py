"""Tests for Cscape HMI Dynamic Spider / Radar Polar Diagnostic Pentagon Chart.

Work Package: W084 (Gate G9 / G2)
"""

import json
import os
import tempfile
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.spider_radar import (
    DiagnosticState,
    RadarChartSVGGenerator,
    RadarMetric,
    SpiderChartEngine,
    SpiderChartStatusBits,
    SPIDER_CHART_PURE_ST_POU,
    run_spider_radar_verification,
)
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


class TestSpiderRadarPureST:
    def test_pure_st_pou_valid(self):
        result = STParser.validate_code(SPIDER_CHART_PURE_ST_POU)
        assert result.status == AgentStatus.SUCCESS
        ast = STParser.parse_pou(SPIDER_CHART_PURE_ST_POU)
        assert ast.name == "SpiderChartRasterizerSync"
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {"%R450", "%R451", "%R452", "%R453", "%R454", "%R455", "%R456", "%R457", "%M105", "%M106"}
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_forbidden_ladder_constructs_rejected(self):
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad ---[ ]--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad ---[/]--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad ---( )--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad RUNG 1: XIC %M105 OTE %M106 END_RUNG END_PROGRAM")


class TestRadarMetric:
    def test_metric_normalization_and_states(self):
        m = RadarMetric(
            name="Vibration",
            tag="VS-101",
            unit="mm/s",
            min_val=0.0,
            max_val=10.0,
            golden_val=2.0,
            current_val=2.0,
            warn_high=5.0,
            crit_high=8.0,
        )
        assert m.normalized_golden == 0.20
        assert m.normalized_current == 0.20
        assert m.state == DiagnosticState.NORMAL
        assert m.delta == 0.0
        assert m.delta_pct == 0.0

        # Warning
        m.current_val = 6.0
        assert m.state == DiagnosticState.WARNING
        assert m.delta == 4.0
        assert m.delta_pct == 200.0

        # Critical
        m.current_val = 9.0
        assert m.state == DiagnosticState.CRITICAL


class TestSpiderSVGGenerator:
    def test_svg_generation_and_elementtree(self):
        gen = RadarChartSVGGenerator()
        metrics = SpiderChartEngine.DEFAULT_METRICS
        svg = gen.generate_svg(metrics, show_golden=True)
        assert "<svg" in svg
        assert "</svg>" in svg
        root = ET.fromstring(svg)
        assert root.tag.endswith("svg")
        # Ensure scorecard panel and radar dial exist
        elem_ids = [el.attrib.get("id") for el in root.iter() if "id" in el.attrib]
        assert "radar-dial-group" in elem_ids
        assert "scorecard-panel" in elem_ids
        assert "legend-group" in elem_ids


class TestSpiderChartEngine:
    def test_engine_initialization_and_sync(self):
        rt = RegisterTable()
        engine = SpiderChartEngine(register_table=rt)
        assert rt.read_bit("%M105") is True
        status_word = rt.read_word("%R450")
        assert status_word & SpiderChartStatusBits.ACTIVE
        assert status_word & SpiderChartStatusBits.GOLDEN_OVERLAY_ENABLED
        assert status_word & SpiderChartStatusBits.SELECTED_AXIS_VALID

        # Check %R452..%R456
        assert rt.read_word("%R452") > 800  # Thermal Eff 86.2%
        assert rt.read_word("%R457") > 800  # Composite Health

    def test_out_of_spec_alarm(self):
        rt = RegisterTable()
        engine = SpiderChartEngine(register_table=rt)
        engine.update_axis_value(1, 9.5)  # Vibration critical
        status_word = rt.read_word("%R450")
        assert status_word & SpiderChartStatusBits.OUT_OF_SPEC_ALARM

    def test_golden_overlay_toggle(self):
        rt = RegisterTable()
        engine = SpiderChartEngine(register_table=rt)
        assert engine.golden_overlay_enabled is True

        rt.write_bit("%M106", True, privilege=PrivilegeMode.SYSTEM)
        engine.sync_from_metrics_to_registers()
        assert engine.golden_overlay_enabled is False
        assert (rt.read_word("%R450") & SpiderChartStatusBits.GOLDEN_OVERLAY_ENABLED) == 0
        assert rt.read_bit("%M106") is False

    def test_engine_disabled(self):
        rt = RegisterTable()
        engine = SpiderChartEngine(register_table=rt)
        rt.write_bit("%M105", False, privilege=PrivilegeMode.SYSTEM)
        engine.sync_from_metrics_to_registers()
        assert rt.read_word("%R450") == 0
        assert rt.read_word("%R457") == 0

    def test_full_verification_runner(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_path = os.path.join(tmp_dir, "spider_radar_evidence.json")
            svg_path = os.path.join(tmp_dir, "spider_sample.svg")
            evidence = run_spider_radar_verification(ev_path, svg_path)
            assert evidence["status"] == "success"
            assert evidence["error_code"] is None
            assert os.path.exists(ev_path)
            assert os.path.exists(svg_path)
            with open(ev_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert len(data["data"]["tests"]) == 7
            assert all(t["passed"] for t in data["data"]["tests"])
