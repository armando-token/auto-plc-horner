"""Unit tests for Cscape HMI Dynamic Sankey Energy & Mass Flow Diagram Vector Canvas.

Work Package: W087 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY
"""

import math
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.sankey_flow import (
    FlowCategory,
    SankeyDiagramEngine,
    SankeyLink,
    SankeyNode,
    SankeyStatusBits,
    SANKEY_FLOW_PURE_ST_POU,
    run_sankey_flow_verification,
)
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


class TestSankeyPureSTPOU:
    """Tests for IEC 61131-3 Pure ST POU compliance and anti-ladder security."""

    def test_pure_st_security_guard(self) -> None:
        """Verify Pure ST POU passes security guard assertion."""
        SecurityGuard.assert_pure_st_content(SANKEY_FLOW_PURE_ST_POU)

    def test_ladder_constructs_rejected(self) -> None:
        """Verify ladder contacts, coils, and rungs trigger LadderForbiddenError."""
        ladder_snippets = [
            SANKEY_FLOW_PURE_ST_POU + "\n---[ ]---",
            SANKEY_FLOW_PURE_ST_POU + "\n---( )---",
            SANKEY_FLOW_PURE_ST_POU + "\nRUNG 1",
            SANKEY_FLOW_PURE_ST_POU + "\nNETWORK 1",
            SANKEY_FLOW_PURE_ST_POU + "\nXIC MyTag",
        ]
        for snip in ladder_snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snip)

    def test_st_parser_validation_and_ast(self) -> None:
        """Verify ST parser validates syntax and extracts AST properly."""
        val = STParser.validate_code(SANKEY_FLOW_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(SANKEY_FLOW_PURE_ST_POU)
        assert ast.name == "SankeyFlowRasterizerSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {"%R480", "%R481", "%R482", "%R483", "%R484", "%R485", "%R486", "%R487", "%M112", "%M113"}
        for reg in expected_regs:
            assert reg in ast.bound_registers


class TestSankeyGraphTopology:
    """Tests for graph topology, nodes, links, and models."""

    def test_default_network_structure(self) -> None:
        """Verify default plant cogeneration nodes and links."""
        engine = SankeyDiagramEngine()
        assert len(engine.nodes) == 11
        assert len(engine.links) == 10

        # Levels check
        levels = [n.level for n in engine.nodes.values()]
        assert levels.count(0) == 3  # Sources
        assert levels.count(1) == 2  # Conversion
        assert levels.count(2) == 2  # Turbines & Heat Exchangers
        assert levels.count(3) == 4  # Sinks and Losses (SINK_POWER, SINK_HEAT, LOSS_FLUE, LOSS_COND)

    def test_node_throughput_property(self) -> None:
        """Verify node throughput computation."""
        node = SankeyNode(node_id="TEST", name="Test Node", level=1, inflow=500.0, outflow=500.0)
        assert node.throughput == 500.0

        node.inflow = 600.0
        node.outflow = 400.0
        assert node.throughput == 600.0


class TestSankeyConservationAndMetrics:
    """Tests for Kirchhoff flow continuity and energy metrics."""

    def test_kirchhoff_conservation_balanced(self) -> None:
        """Verify default cogeneration network is perfectly balanced."""
        engine = SankeyDiagramEngine()
        is_balanced, max_imb, imbalances = engine.validate_conservation(epsilon=1e-4)
        assert is_balanced
        assert max_imb < 1e-4
        assert not engine.conservation_fault
        for nid, delta in imbalances.items():
            assert delta < 1e-4, f"Node {nid} has imbalance {delta}"

    def test_kirchhoff_conservation_fault(self) -> None:
        """Verify flow imbalance is detected when leak occurs."""
        engine = SankeyDiagramEngine()
        # Alter fuel gas flow
        engine.links[0].flow_value -= 25.0
        is_balanced, max_imb, imbalances = engine.validate_conservation(epsilon=1e-4)
        assert not is_balanced
        assert max_imb >= 25.0
        assert engine.conservation_fault
        assert "CONV_BOILER" in imbalances

    def test_compute_metrics_sum_to_100_percent(self) -> None:
        """Verify energy accounting sums to 100% of input energy."""
        engine = SankeyDiagramEngine()
        metrics = engine.compute_metrics()
        assert metrics["total_inflow_kw"] == 1250.0  # 800 + 350 + 100
        assert metrics["useful_outflow_kw"] == 1025.0  # 450 + 335 + 240
        assert metrics["total_losses_kw"] == 225.0  # 140 + 85
        assert metrics["efficiency_pct"] == 82.0
        assert metrics["flue_loss_pct"] == 11.2
        assert metrics["condenser_loss_pct"] == 6.8

        total_alloc = metrics["efficiency_pct"] + metrics["flue_loss_pct"] + metrics["condenser_loss_pct"]
        assert abs(total_alloc - 100.0) < 0.1


class TestSankeyLayoutAndGeometry:
    """Tests for layout partitioning, collision prevention, and Bézier ribbons."""

    def test_node_vertical_spacing_no_overlap(self) -> None:
        """Verify vertical gaps between adjacent nodes in each level are >= 16px."""
        engine = SankeyDiagramEngine()
        for lvl in range(4):
            lvl_nodes = sorted([n for n in engine.nodes.values() if n.level == lvl], key=lambda n: n.y)
            for i in range(len(lvl_nodes) - 1):
                gap = lvl_nodes[i + 1].y - (lvl_nodes[i].y + lvl_nodes[i].height)
                assert gap >= 16.0, f"Overlap at level {lvl} between {lvl_nodes[i].name} and {lvl_nodes[i+1].name}: gap={gap}"

    def test_bezier_path_generation_syntax(self) -> None:
        """Verify cubic Bézier ribbon S-curve syntax and control points."""
        engine = SankeyDiagramEngine()
        for link in engine.links:
            path_str = engine.generate_bezier_path(link)
            assert path_str.startswith("M ")
            assert " C " in path_str
            assert " L " in path_str
            assert path_str.endswith(" Z")

            # Check that ribbon height matches link specification
            assert link.ribbon_height > 0.0


class TestSankeySVGRendering:
    """Tests for SVG 1.1 vector graphics generation and accessibility."""

    def test_svg_xml_well_formedness(self) -> None:
        """Verify rendered SVG is well-formed XML and parseable by ElementTree."""
        engine = SankeyDiagramEngine()
        svg_xml = engine.render_svg()
        root = ET.fromstring(svg_xml)
        assert root.tag.endswith("svg")
        assert root.attrib["width"] == "1200"
        assert root.attrib["height"] == "750"

    def test_svg_contains_required_elements(self) -> None:
        """Verify required groups, defs, gradients, and scorecards exist."""
        engine = SankeyDiagramEngine()
        svg_xml = engine.render_svg()
        assert "sankey-header" in svg_xml
        assert "sankey-scorecard-panel" in svg_xml
        assert "sankey-ribbons-group" in svg_xml
        assert "sankey-nodes-group" in svg_xml
        assert "sankey-legend" in svg_xml
        assert "linearGradient" in svg_xml
        assert "82.0%" in svg_xml
        assert "BALANCED" in svg_xml


class TestSankeyRegisterSynchronization:
    """Tests for Horner OCS %R480..%R487 register table synchronization."""

    def test_register_sync_normal_operation(self) -> None:
        """Verify register sync under normal balanced operation."""
        reg_table = RegisterTable()
        engine = SankeyDiagramEngine(register_table=reg_table)
        engine.sync_to_registers()

        r480 = reg_table.read_word("%R480")
        assert r480 & SankeyStatusBits.ACTIVE
        assert not (r480 & SankeyStatusBits.CONSERVATION_FAULT)
        assert not (r480 & SankeyStatusBits.LOW_EFFICIENCY_WARN)
        assert not (r480 & SankeyStatusBits.HIGH_LOSS_ALARM)

        assert reg_table.read_word("%R481") == 12500  # 1250.0 kW * 10
        assert reg_table.read_word("%R482") == 10250  # 1025.0 kW * 10
        assert reg_table.read_word("%R483") == 2250   # 225.0 kW * 10
        assert reg_table.read_word("%R484") == 820    # 82.0% * 10
        assert reg_table.read_word("%R485") == 112    # 11.2% * 10
        assert reg_table.read_word("%R486") == 68     # 6.8% * 10
        assert reg_table.read_word("%R487") == 0      # Selected path

    def test_engine_disabled_state(self) -> None:
        """Verify disabling %M112 clears status word %R480."""
        reg_table = RegisterTable()
        engine = SankeyDiagramEngine(register_table=reg_table)
        reg_table.write_bit("%M112", False, privilege=PrivilegeMode.SYSTEM)
        engine.sync_to_registers()
        assert reg_table.read_word("%R480") == 0

    def test_trip_and_reset_handshake(self) -> None:
        """Verify conservation fault trip latches and resets via %M113."""
        reg_table = RegisterTable()
        engine = SankeyDiagramEngine(register_table=reg_table)

        # Induce flow imbalance
        engine.links[0].flow_value = 500.0  # Gas drop from 800 to 500
        engine.validate_conservation()
        engine.sync_to_registers()

        r480_fault = reg_table.read_word("%R480")
        assert r480_fault & SankeyStatusBits.CONSERVATION_FAULT

        # Restore flow and pulse reset coil %M113
        engine.links[0].flow_value = 800.0
        engine.validate_conservation()
        reg_table.write_bit("%M113", True, privilege=PrivilegeMode.SYSTEM)
        engine.sync_to_registers()

        assert not reg_table.read_bit("%M113")  # Reset coil cleared automatically
        r480_cleared = reg_table.read_word("%R480")
        assert not (r480_cleared & SankeyStatusBits.CONSERVATION_FAULT)


class TestSankeyVerificationRunner:
    """Tests for complete 9-stage verification runner."""

    def test_verification_runner_execution(self, tmp_path) -> None:
        """Verify run_sankey_flow_verification passes all 9 stages."""
        evidence_file = tmp_path / "sankey_evidence.json"
        svg_file = tmp_path / "sankey.svg"

        evidence = run_sankey_flow_verification(
            evidence_path=str(evidence_file),
            svg_path=str(svg_file),
        )

        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert evidence["data"]["checks_passed"] == 9
        assert evidence["data"]["total_checks"] == 9
        assert evidence_file.exists()
        assert svg_file.exists()
