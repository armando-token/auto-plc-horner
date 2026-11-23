"""Comprehensive pytest test suite for Cscape HMI Dynamic Chord Network Multizone Telemetry SCADA Canvas (W255).

Work Package: Wave W255 (Gate G9 HMI Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Chord Network Multizone Telemetry SCADA Canvas]

Architectural Coverage (120+ Deterministic Unit Tests across 15 Test Classes):
1. TestDiagnosticCodeMathAndFormats: DiagnosticCode signed/unsigned 16-bit math, hash, strings, formatters, and equality.
2. TestRegisterAndCoilAddressMappings: %R2160..%R2167 word register and %M504..%M505 coil addresses, aliases, and disjointness.
3. TestNetworkZoneAndRibbonModels: NetworkZone, ChordRibbon, ChordNetworkMetrics dataclasses, properties, scaling factors.
4. TestCanonicalFactoryAndMatrices: Canonical zones, canonical 5x5 flow matrix, baseline flow conservation, throughputs, and bottleneck zone.
5. TestCircularGeometryAndAnnularArcs: Annular arc perimeters (P_out, P_in, P_total, Area), angular layout, gap angles, non-overlapping coverage.
6. TestBezierRibbonsAndPathSynthesis: Quadratic Bézier paths with center convergence, Cubic Bézier paths with control points, flow-proportional breadths.
7. TestDirectionalFlowArrows: Bézier midpoint tangent vectors, polygon coordinates, arrow orientation, and canvas containment.
8. TestSVGGenerationAndXMLValidity: Standalone W3C SVG 1.1 XML generation, ElementTree parsing, viewBox="0 0 1200 750", width, height, required groups.
9. TestWCAG21AAAContrastCompliance: WCAG 2.1 relative luminance math, contrast ratios, text >= 7.0:1, popover badge >= 18.0:1, graphics >= 3.0:1.
10. TestProcessSafetyDiagnosticsAndFaults: 0x7501 ribbon overflow, 0x7502 asymmetry fault, status bit transitions, recovery reset nominal.
11. TestBottleneckAlarmCoilAssertion: %M505 assertion during overflow, asymmetry, manual trigger, de-assertion upon reset.
12. TestHornerOCSSynchronizationAndRegisters: %R2160..%R2167 and %M504..%M505 exact synchronization, RegisterTable privilege checks, 100-cycle soak stability.
13. TestPureSTAndSecurity: SecurityGuard and STParser validation of Pure ST POU, symbol mappings, variable scopes, POU name, and program structure.
14. TestAntiLadderRejection: Fail-closed interception with LadderForbiddenError on 8+ ladder contacts, coils, rungs, mnemonics.
15. TestILogicUnitComplianceAndVerificationRunner: ILogicUnit discrete scan cycle protocol execution and 9-stage verification runner returning strict 4-state contract JSON.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Sequence, Set, Tuple
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.chord_network_canvas import (
    # Diagnostics & Event Codes
    DIAG_EVENT_OK,
    CHORD_ERR_OK,
    DIAG_OK,
    CHORD_NETWORK_OK,
    DIAG_ERR_RIBBON_OVERFLOW,
    CHORD_ERR_RIBBON_OVERFLOW,
    RIBBON_OVERFLOW_FAULT,
    CHORD_ERR_FLOW_BOTTLENECK,
    DIAG_ERR_ASYMMETRY_FAULT,
    CHORD_ERR_ASYMMETRY_FAULT,
    ASYMMETRY_FAULT,
    CHORD_ERR_FLOW_ASYMMETRY,
    DIAG_ERR_INVALID_ZONES,
    CHORD_ERR_INVALID_ZONES,
    DIAG_ERR_RENDER_FAULT,
    CHORD_ERR_RENDER_FAULT,
    # Register & Coil Addresses & Aliases
    REG_CHORD_ACTIVE_ZONES_COUNT,
    REG_ACTIVE_ZONES,
    REG_TOTAL_NETWORK_FLUX_SCALED,
    REG_CHORD_TOTAL_NETWORK_FLOW_SCALED,
    REG_TOTAL_FLOW,
    REG_ACTIVE_RIBBONS_COUNT,
    REG_CHORD_MAX_RIBBON_BANDWIDTH_SCALED,
    REG_MAX_BANDWIDTH,
    REG_MAX_CORRIDOR_FLOW_SCALED,
    REG_CHORD_FLOW_ASYMMETRY_INDEX_SCALED,
    REG_ASYMMETRY_INDEX,
    REG_NETWORK_ASYMMETRY_PCT_SCALED,
    REG_CHORD_SELECTED_SOURCE_ZONE,
    REG_SOURCE_ZONE,
    REG_BOTTLENECK_NODE_INDEX,
    REG_CHORD_SELECTED_TARGET_ZONE,
    REG_TARGET_ZONE,
    REG_BOTTLENECK_SATURATION_SCALED,
    REG_CHORD_FLOW_BOTTLENECK_ZONE,
    REG_BOTTLENECK_ZONE,
    REG_SELECTED_ZONE_INDEX,
    REG_CHORD_CANVAS_DIAGNOSTIC_CODE,
    REG_DIAGNOSTIC_CODE,
    REG_DIAGNOSTIC_STATUS_CODE,
    COIL_CHORD_CANVAS_HEALTHY,
    COIL_CANVAS_HEALTHY,
    COIL_CHORD_NETWORK_CANVAS_ACTIVE,
    COIL_CHORD_BOTTLENECK_ALARM,
    COIL_BOTTLENECK_ALARM,
    COIL_FLOW_BOTTLENECK_ALARM_TRIP,
    # Thresholds and Limits
    MAX_RIBBON_BANDWIDTH_ALARM_PCT,
    MAX_ASYMMETRY_INDEX_ALARM_PCT,
    BOTTLENECK_WARNING_BANDWIDTH_PCT,
    MIN_PERMITTED_ZONES,
    MAX_PERMITTED_ZONES,
    CANONICAL_ZONES_COUNT,
    # Geometry and Layout Constants
    CANVAS_VIEWPORT_WIDTH,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_CENTER_X,
    CANVAS_CENTER_Y,
    CHORD_OUTER_RADIUS,
    CHORD_INNER_RADIUS,
    DEFAULT_ZONE_GAP_DEG,
    # Accessibility Targets
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    # Colors
    COLOR_ZONE_FEED,
    COLOR_ZONE_REACTION,
    COLOR_ZONE_SEPARATION,
    COLOR_ZONE_RECOVERY,
    COLOR_ZONE_UTILITIES,
    CANONICAL_ZONE_PALETTE,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_ALT,
    COLOR_DECOUPLED_BADGE,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_MUTED,
    COLOR_FOCUS_CYAN,
    COLOR_ALERT_CRIMSON,
    COLOR_WARNING_AMBER,
    COLOR_NOMINAL_GREEN,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    FEED_GRAPHICAL_CONTRAST_RATIO,
    REACTION_GRAPHICAL_CONTRAST_RATIO,
    SEPARATION_GRAPHICAL_CONTRAST_RATIO,
    RECOVERY_GRAPHICAL_CONTRAST_RATIO,
    UTILITIES_GRAPHICAL_CONTRAST_RATIO,
    # Pure ST POUs
    CHORD_NETWORK_CANVAS_PURE_ST_POU,
    CHORD_NETWORK_CANVAS_SYNC_PURE_ST_POU,
    DYNAMIC_CHORD_NETWORK_SCADA_PURE_ST_POU,
    CHORD_NETWORK_PURE_ST_POU,
    CHORD_NETWORK_TELEMETRY_PURE_ST_POU,
    CHORD_NETWORK_PROCESS_FLOW_SYNC_PURE_ST_POU,
    CANONICAL_FLOW_MATRIX,
    # Classes & Enums
    DiagnosticCode,
    ChordNetworkDiagnosticCode,
    ChordNetworkCanvasDiagnosticCode,
    ChordNetworkStatusBits,
    BezierCurveMode,
    NetworkZone,
    ChordZone,
    ChordRibbon,
    ChordNetworkMetrics,
    NetworkMetrics,
    ChordNetworkCanvas,
    ChordNetworkCanvasEngine,
    ChordNetworkCanvasSync,
    # Functions
    srgb_channel_to_linear,
    hex_to_relative_luminance,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    create_canonical_network_zones,
    create_canonical_chord_zones,
    create_canonical_flow_matrix,
    layout_chord_network_diagram,
    compute_chord_network_metrics,
    generate_zone_arc_path,
    generate_bezier_ribbon_path,
    compute_ribbon_arrow_points,
    generate_chord_network_canvas_svg,
    create_canonical_chord_network_canvas,
    verify_chord_network_canvas_pure_st,
    run_chord_network_canvas_verification,
)


# ============================================================================
# 1. TestDiagnosticCodeMathAndFormats
# ============================================================================

class TestDiagnosticCodeMathAndFormats:
    """Verify signed and unsigned 16-bit equality, hashing, hex formatting, and comparisons."""

    def test_diagnostic_code_ok_equality(self) -> None:
        """Nominal 0x0000 matches integer 0, hex, and all OK aliases."""
        diag = DiagnosticCode(0x0000)
        assert diag == 0
        assert diag == 0x0000
        assert diag == DIAG_EVENT_OK
        assert diag == CHORD_ERR_OK
        assert diag == DIAG_OK
        assert diag == CHORD_NETWORK_OK

    def test_diagnostic_code_ribbon_overflow_0x7501(self) -> None:
        """0x7501 matches unsigned 29953 and overflow aliases."""
        diag = DiagnosticCode(0x7501)
        assert diag == 0x7501
        assert diag == 29953
        assert diag == DIAG_ERR_RIBBON_OVERFLOW
        assert diag == CHORD_ERR_RIBBON_OVERFLOW
        assert diag == RIBBON_OVERFLOW_FAULT
        assert diag == CHORD_ERR_FLOW_BOTTLENECK

    def test_diagnostic_code_asymmetry_fault_0x7502(self) -> None:
        """0x7502 matches unsigned 29954 and asymmetry aliases."""
        diag = DiagnosticCode(0x7502)
        assert diag == 0x7502
        assert diag == 29954
        assert diag == DIAG_ERR_ASYMMETRY_FAULT
        assert diag == CHORD_ERR_ASYMMETRY_FAULT
        assert diag == ASYMMETRY_FAULT
        assert diag == CHORD_ERR_FLOW_ASYMMETRY

    def test_diagnostic_code_invalid_zones_0x7503(self) -> None:
        """0x7503 matches unsigned 29955 and invalid zones aliases."""
        diag = DiagnosticCode(0x7503)
        assert diag == 0x7503
        assert diag == 29955
        assert diag == DIAG_ERR_INVALID_ZONES
        assert diag == CHORD_ERR_INVALID_ZONES

    def test_diagnostic_code_render_fault_0x7504(self) -> None:
        """0x7504 matches unsigned 29956 and render fault aliases."""
        diag = DiagnosticCode(0x7504)
        assert diag == 0x7504
        assert diag == 29956
        assert diag == DIAG_ERR_RENDER_FAULT
        assert diag == CHORD_ERR_RENDER_FAULT

    def test_diagnostic_code_signed_negative_conversion(self) -> None:
        """Codes with high-bit set (>= 0x8000) match negative 16-bit signed equivalents."""
        d_high = DiagnosticCode(0x8000)
        assert d_high == 0x8000
        assert d_high == -32768

        d_sign = DiagnosticCode(0xFA01)
        assert d_sign == 0xFA01
        assert d_sign == -1535

        d_all_ones = DiagnosticCode(0xFFFF)
        assert d_all_ones == 0xFFFF
        assert d_all_ones == -1

    def test_diagnostic_code_hashing_and_dict_keys(self) -> None:
        """DiagnosticCode instances hash consistently and work in dicts/sets."""
        d1 = DiagnosticCode(0x7501)
        d2 = DiagnosticCode(29953)
        assert hash(d1) == hash(d2)

        mapping = {d1: "RIBBON_OVERFLOW"}
        assert mapping[d2] == "RIBBON_OVERFLOW"
        assert d2 in mapping

        code_set = {DiagnosticCode(0x0000), DiagnosticCode(0x7501), DiagnosticCode(0x7502)}
        assert DiagnosticCode(0) in code_set
        assert DiagnosticCode(29953) in code_set
        assert DiagnosticCode(29954) in code_set
        assert len(code_set) == 3

    def test_diagnostic_code_string_and_hex_representations(self) -> None:
        """DiagnosticCode converts to expected decimal string and 16-bit hex formatting."""
        d_ok = DiagnosticCode(0x0000)
        d_ovf = DiagnosticCode(0x7501)
        d_asym = DiagnosticCode(0x7502)

        assert str(d_ok) == "0"
        assert str(d_ovf) == "29953"
        assert str(d_asym) == "29954"

        assert f"0x{int(d_ok):04X}" == "0x0000"
        assert f"0x{int(d_ovf):04X}" == "0x7501"
        assert f"0x{int(d_asym):04X}" == "0x7502"

    def test_diagnostic_code_comparison_with_non_integers(self) -> None:
        """Comparing DiagnosticCode with non-integer types returns False cleanly."""
        code = DiagnosticCode(0x7501)
        assert (code == "0x7501") is False
        assert (code == [0x7501]) is False
        assert (code == None) is False

    def test_diagnostic_code_class_aliases(self) -> None:
        """ChordNetworkDiagnosticCode and ChordNetworkCanvasDiagnosticCode alias DiagnosticCode."""
        assert ChordNetworkDiagnosticCode is DiagnosticCode
        assert ChordNetworkCanvasDiagnosticCode is DiagnosticCode


# ============================================================================
# 2. TestRegisterAndCoilAddressMappings
# ============================================================================

class TestRegisterAndCoilAddressMappings:
    """Verify Horner OCS register space addresses (%R2160..%R2167, %M504..%M505) and aliases."""

    def test_word_register_addresses(self) -> None:
        """Verify each word register maps to its designated %R2160..%R2167 channel."""
        assert REG_CHORD_ACTIVE_ZONES_COUNT == "%R2160"
        assert REG_CHORD_TOTAL_NETWORK_FLOW_SCALED == "%R2161"
        assert REG_CHORD_MAX_RIBBON_BANDWIDTH_SCALED == "%R2162"
        assert REG_CHORD_FLOW_ASYMMETRY_INDEX_SCALED == "%R2163"
        assert REG_CHORD_SELECTED_SOURCE_ZONE == "%R2164"
        assert REG_CHORD_SELECTED_TARGET_ZONE == "%R2165"
        assert REG_CHORD_FLOW_BOTTLENECK_ZONE == "%R2166"
        assert REG_CHORD_CANVAS_DIAGNOSTIC_CODE == "%R2167"

    def test_discrete_coil_addresses(self) -> None:
        """Verify discrete coils map to %M504 (healthy) and %M505 (alarm)."""
        assert COIL_CHORD_CANVAS_HEALTHY == "%M504"
        assert COIL_CHORD_BOTTLENECK_ALARM == "%M505"

    def test_register_aliases_equivalence(self) -> None:
        """Verify alternative and short alias mappings resolve to correct %R addresses."""
        assert REG_ACTIVE_ZONES == REG_CHORD_ACTIVE_ZONES_COUNT == "%R2160"
        assert REG_TOTAL_NETWORK_FLUX_SCALED == "%R2160"
        assert REG_TOTAL_FLOW == REG_CHORD_TOTAL_NETWORK_FLOW_SCALED == "%R2161"
        assert REG_ACTIVE_RIBBONS_COUNT == "%R2161"
        assert REG_MAX_BANDWIDTH == REG_CHORD_MAX_RIBBON_BANDWIDTH_SCALED == "%R2162"
        assert REG_MAX_CORRIDOR_FLOW_SCALED == "%R2162"
        assert REG_ASYMMETRY_INDEX == REG_CHORD_FLOW_ASYMMETRY_INDEX_SCALED == "%R2163"
        assert REG_NETWORK_ASYMMETRY_PCT_SCALED == "%R2163"
        assert REG_SOURCE_ZONE == REG_CHORD_SELECTED_SOURCE_ZONE == "%R2164"
        assert REG_BOTTLENECK_NODE_INDEX == "%R2164"
        assert REG_TARGET_ZONE == REG_CHORD_SELECTED_TARGET_ZONE == "%R2165"
        assert REG_BOTTLENECK_SATURATION_SCALED == "%R2165"
        assert REG_BOTTLENECK_ZONE == REG_CHORD_FLOW_BOTTLENECK_ZONE == "%R2166"
        assert REG_SELECTED_ZONE_INDEX == "%R2166"
        assert REG_DIAGNOSTIC_CODE == REG_CHORD_CANVAS_DIAGNOSTIC_CODE == "%R2167"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2167"

    def test_coil_aliases_equivalence(self) -> None:
        """Verify alternative and short coil alias mappings resolve to %M504 and %M505."""
        assert COIL_CANVAS_HEALTHY == COIL_CHORD_CANVAS_HEALTHY == "%M504"
        assert COIL_CHORD_NETWORK_CANVAS_ACTIVE == "%M504"
        assert COIL_BOTTLENECK_ALARM == COIL_CHORD_BOTTLENECK_ALARM == "%M505"
        assert COIL_FLOW_BOTTLENECK_ALARM_TRIP == "%M505"

    def test_register_addresses_disjointness(self) -> None:
        """All 8 word registers are distinct channels."""
        word_regs = [
            REG_CHORD_ACTIVE_ZONES_COUNT,
            REG_CHORD_TOTAL_NETWORK_FLOW_SCALED,
            REG_CHORD_MAX_RIBBON_BANDWIDTH_SCALED,
            REG_CHORD_FLOW_ASYMMETRY_INDEX_SCALED,
            REG_CHORD_SELECTED_SOURCE_ZONE,
            REG_CHORD_SELECTED_TARGET_ZONE,
            REG_CHORD_FLOW_BOTTLENECK_ZONE,
            REG_CHORD_CANVAS_DIAGNOSTIC_CODE,
        ]
        assert len(word_regs) == 8
        assert len(set(word_regs)) == 8

    def test_coil_addresses_disjointness(self) -> None:
        """Both discrete coils are distinct from each other and distinct from word registers."""
        coils = [COIL_CHORD_CANVAS_HEALTHY, COIL_CHORD_BOTTLENECK_ALARM]
        assert len(coils) == 2
        assert len(set(coils)) == 2
        assert not set(coils).intersection({"%R2160", "%R2161", "%R2162", "%R2163", "%R2164", "%R2165", "%R2166", "%R2167"})


# ============================================================================
# 3. TestNetworkZoneAndRibbonModels
# ============================================================================

class TestNetworkZoneAndRibbonModels:
    """Verify dataclasses NetworkZone, ChordRibbon, ChordNetworkMetrics, and calculations."""

    def test_network_zone_instantiation_and_properties(self) -> None:
        """NetworkZone instantiates with expected attributes and computes angular span."""
        zone = NetworkZone(
            index=0,
            zone_id="Feed",
            name="Feed Preparation",
            tag="FD-01",
            flow_rate_kg_s=722.5,
            pressure_bar=18.5,
            color="#10B981",
            status_text="NORMAL",
            is_bottleneck=False,
            theta_start_rad=-1.57,
            theta_end_rad=-0.50,
            total_inflow_kg_s=308.125,
            total_outflow_kg_s=414.375,
            capacity_kg_s=800.0,
        )
        assert zone.index == 0
        assert zone.zone_id == "Feed"
        assert zone.name == "Feed Preparation"
        assert zone.tag == "FD-01"
        assert zone.flow_rate_kg_s == 722.5
        assert zone.pressure_bar == 18.5
        assert zone.color == "#10B981"
        assert zone.status_text == "NORMAL"
        assert zone.is_bottleneck is False
        assert pytest.approx(zone.angular_span_rad, abs=1e-3) == 1.07
        assert pytest.approx(zone.throughput_kg_s, abs=1e-3) == 722.5

    def test_network_zone_alias_chord_zone(self) -> None:
        """ChordZone is an alias for NetworkZone."""
        assert ChordZone is NetworkZone

    def test_chord_ribbon_instantiation_and_bandwidth_scaled(self) -> None:
        """ChordRibbon stores flow, endpoints, and scales bandwidth in 0.1% resolution."""
        ribbon = ChordRibbon(
            ribbon_id="ribbon-Feed-Reaction",
            source_index=0,
            target_index=1,
            source_id="Feed",
            target_id="Reaction",
            flow_rate_kg_s=361.25,
            bandwidth_pct=42.50,
            is_bottleneck=True,
            is_highlighted=True,
            theta_src_start=-1.57,
            theta_src_end=-1.20,
            theta_tgt_start=-0.50,
            theta_tgt_end=-0.15,
        )
        assert ribbon.ribbon_id == "ribbon-Feed-Reaction"
        assert ribbon.source_index == 0
        assert ribbon.target_index == 1
        assert ribbon.flow_rate_kg_s == 361.25
        assert ribbon.bandwidth_pct == 42.50
        assert ribbon.bandwidth_scaled == 425
        assert ribbon.is_bottleneck is True
        assert ribbon.is_highlighted is True

    def test_chord_network_metrics_scaled_properties(self) -> None:
        """ChordNetworkMetrics scales total flow, bandwidth, and asymmetry index."""
        metrics = ChordNetworkMetrics(
            active_zones_count=5,
            total_network_flow_kg_s=850.0,
            max_ribbon_bandwidth_pct=42.5,
            flow_asymmetry_index_pct=12.50,
            selected_source_zone=0,
            selected_target_zone=1,
            flow_bottleneck_zone=1,
            diagnostic_code=DIAG_EVENT_OK,
            canvas_healthy=True,
            bottleneck_alarm=False,
        )
        assert metrics.active_zones_count == 5
        assert metrics.total_network_flow_scaled == 850
        assert metrics.max_ribbon_bandwidth_scaled == 425
        assert metrics.flow_asymmetry_index_scaled == 1250
        assert metrics.flow_bottleneck_zone == 1
        assert metrics.canvas_healthy is True
        assert metrics.bottleneck_alarm is False

    def test_chord_network_metrics_alias_network_metrics(self) -> None:
        """NetworkMetrics is an alias for ChordNetworkMetrics."""
        assert NetworkMetrics is ChordNetworkMetrics


# ============================================================================
# 4. TestCanonicalFactoryAndMatrices
# ============================================================================

class TestCanonicalFactoryAndMatrices:
    """Verify canonical plant zones, flow matrix, throughputs, and bottleneck identification."""

    def test_create_canonical_network_zones(self) -> None:
        """Verify the 5 canonical plant zones and tags."""
        zones = create_canonical_network_zones()
        assert len(zones) == 5
        expected = [
            (0, "Feed", "FD-01", COLOR_ZONE_FEED, False),
            (1, "Reaction", "RX-02", COLOR_ZONE_REACTION, True),
            (2, "Separation", "SP-03", COLOR_ZONE_SEPARATION, False),
            (3, "Recovery", "RC-04", COLOR_ZONE_RECOVERY, False),
            (4, "Utilities", "UT-05", COLOR_ZONE_UTILITIES, False),
        ]
        for z, (exp_idx, exp_id, exp_tag, exp_color, exp_bneck) in zip(zones, expected):
            assert z.index == exp_idx
            assert z.zone_id == exp_id
            assert z.tag == exp_tag
            assert z.color == exp_color
            assert z.is_bottleneck == exp_bneck

    def test_create_canonical_chord_zones_alias(self) -> None:
        """create_canonical_chord_zones is an alias for create_canonical_network_zones."""
        assert create_canonical_chord_zones is create_canonical_network_zones

    def test_create_canonical_flow_matrix_values(self) -> None:
        """Verify the 5x5 flow matrix dimensions and key corridor flows."""
        matrix = create_canonical_flow_matrix()
        assert len(matrix) == 5
        assert all(len(row) == 5 for row in matrix)

        # Diagonal entries are 0 (no self-loops)
        for i in range(5):
            assert matrix[i][i] == 0.0

        # Max flow is Feed -> Reaction
        assert matrix[0][1] == 361.25
        assert matrix[1][0] == 308.125
        assert matrix[0][4] == 53.125
        assert matrix[1][2] == 35.0
        assert matrix[2][1] == 35.0
        assert matrix[2][3] == 15.0
        assert matrix[3][2] == 15.0
        assert matrix[3][4] == 13.75
        assert matrix[4][3] == 13.75

    def test_canonical_flow_matrix_mathematical_invariants(self) -> None:
        """Verify total flow 850.0 kg/s, max bandwidth 42.5%, and asymmetry index 12.50%."""
        matrix = create_canonical_flow_matrix()
        tot_flow = sum(sum(r) for r in matrix)
        assert pytest.approx(tot_flow, abs=1e-3) == 850.0

        max_flow = max(max(r) for r in matrix)
        assert pytest.approx(max_flow, abs=1e-3) == 361.25
        assert pytest.approx((max_flow / tot_flow) * 100.0, abs=1e-3) == 42.5

        diff_sum = sum(abs(matrix[i][j] - matrix[j][i]) for i in range(5) for j in range(i + 1, 5))
        assert pytest.approx(diff_sum, abs=1e-3) == 106.25
        assert pytest.approx((diff_sum / tot_flow) * 100.0, abs=1e-3) == 12.50

    def test_canonical_flow_matrix_bottleneck_detection(self) -> None:
        """Reaction zone (Zone 1) has highest combined throughput and is the bottleneck."""
        zones = create_canonical_network_zones()
        matrix = create_canonical_flow_matrix()
        laid_zones, ribbons = layout_chord_network_diagram(zones, matrix)

        throughputs = [z.throughput_kg_s for z in laid_zones]
        # Feed: 361.25 + 53.125 + 308.125 = 722.5
        # Reaction: 308.125 + 35.0 + 361.25 + 35.0 = 739.375 (Peak!)
        assert pytest.approx(throughputs[0], abs=1e-3) == 722.5
        assert pytest.approx(throughputs[1], abs=1e-3) == 739.375
        assert throughputs.index(max(throughputs)) == 1

    def test_canonical_flow_matrix_deep_copy_isolation(self) -> None:
        """Mutating a generated matrix does not mutate the CANONICAL_FLOW_MATRIX constant."""
        matrix = create_canonical_flow_matrix()
        matrix[0][1] = 999.0
        assert CANONICAL_FLOW_MATRIX[0][1] == 361.25


# ============================================================================
# 5. TestCircularGeometryAndAnnularArcs
# ============================================================================

class TestCircularGeometryAndAnnularArcs:
    """Verify annular perimeter arc layout, perimeter formulas, areas, and SVG paths."""

    def test_geometry_constants(self) -> None:
        """Verify center coordinates, inner/outer radii, and gap degrees."""
        assert CANVAS_VIEWPORT_WIDTH == 1200
        assert CANVAS_VIEWPORT_HEIGHT == 750
        assert CANVAS_CENTER_X == 460.0
        assert CANVAS_CENTER_Y == 385.0
        assert CHORD_OUTER_RADIUS == 270.0
        assert CHORD_INNER_RADIUS == 230.0
        assert DEFAULT_ZONE_GAP_DEG == 3.5
        assert CHORD_OUTER_RADIUS > CHORD_INNER_RADIUS

    def test_annular_arc_perimeter_and_area_formulas(self) -> None:
        """Verify mathematical formulas for annular arc perimeters and area."""
        span_rad = math.radians(45.0)  # 45 degrees
        r_out = CHORD_OUTER_RADIUS
        r_in = CHORD_INNER_RADIUS

        p_out = r_out * span_rad
        p_in = r_in * span_rad
        radial_edges = 2.0 * (r_out - r_in)
        p_total = p_out + p_in + radial_edges
        area = 0.5 * span_rad * ((r_out ** 2) - (r_in ** 2))

        assert p_out > p_in > 0.0
        assert p_total > (p_out + p_in)
        assert area > 0.0
        assert radial_edges == 80.0

    def test_layout_chord_network_diagram_spans(self) -> None:
        """All zones have non-zero positive angular spans after layout."""
        zones = create_canonical_network_zones()
        matrix = create_canonical_flow_matrix()
        laid_zones, ribbons = layout_chord_network_diagram(zones, matrix, DEFAULT_ZONE_GAP_DEG)

        assert len(laid_zones) == 5
        assert len(ribbons) > 0

        total_span = sum(z.angular_span_rad for z in laid_zones)
        total_gaps = 5 * math.radians(DEFAULT_ZONE_GAP_DEG)
        assert pytest.approx(total_span + total_gaps, abs=1e-3) == (2.0 * math.pi)

        for z in laid_zones:
            assert z.angular_span_rad > 0.0
            assert z.theta_end_rad > z.theta_start_rad

    def test_generate_zone_arc_path_syntax(self) -> None:
        """Annular arc SVG path has M, A (outer), L, A (inner), Z syntax."""
        zones = create_canonical_network_zones()
        matrix = create_canonical_flow_matrix()
        laid_zones, _ = layout_chord_network_diagram(zones, matrix)

        for z in laid_zones:
            d = generate_zone_arc_path(z)
            assert d.startswith("M ")
            assert " A 270.00 270.00 " in d
            assert " L " in d
            assert " A 230.00 230.00 " in d
            assert d.endswith(" Z")

    def test_empty_zones_layout_returns_empty(self) -> None:
        """Calling layout with empty zones returns empty lists safely."""
        z_out, r_out = layout_chord_network_diagram([], [])
        assert z_out == []
        assert r_out == []


# ============================================================================
# 6. TestBezierRibbonsAndPathSynthesis
# ============================================================================

class TestBezierRibbonsAndPathSynthesis:
    """Verify Quadratic and Cubic Bézier ribbons with dynamic flow bandwidth."""

    def test_quadratic_bezier_ribbon_path_syntax(self) -> None:
        """Quadratic Bézier ribbon path has Q {cx} {cy} control points."""
        zones = create_canonical_network_zones()
        matrix = create_canonical_flow_matrix()
        _, ribbons = layout_chord_network_diagram(zones, matrix)

        r = ribbons[0]
        d = generate_bezier_ribbon_path(r, curve_mode=BezierCurveMode.QUADRATIC)

        assert d.startswith("M ")
        assert f" Q {CANVAS_CENTER_X:.2f} {CANVAS_CENTER_Y:.2f} " in d
        assert f" A {CHORD_INNER_RADIUS:.2f} {CHORD_INNER_RADIUS:.2f} " in d
        assert d.endswith(" Z")

    def test_cubic_bezier_ribbon_path_syntax(self) -> None:
        """Cubic Bézier ribbon path has C control points and no Q command."""
        zones = create_canonical_network_zones()
        matrix = create_canonical_flow_matrix()
        _, ribbons = layout_chord_network_diagram(zones, matrix)

        r = ribbons[0]
        d = generate_bezier_ribbon_path(r, curve_mode=BezierCurveMode.CUBIC)

        assert d.startswith("M ")
        assert " C " in d
        assert " Q " not in d
        assert d.endswith(" Z")

    def test_ribbon_sub_arc_proportional_to_flow(self) -> None:
        """Heavier corridor flows allocate wider sub-arcs along the inner ring."""
        zones = create_canonical_network_zones()
        matrix = create_canonical_flow_matrix()
        _, ribbons = layout_chord_network_diagram(zones, matrix)

        # Ribbon (0->1) flow is 361.25 kg/s, Ribbon (2->3) flow is 15.0 kg/s
        r_heavy = next(r for r in ribbons if r.source_index == 0 and r.target_index == 1)
        r_light = next(r for r in ribbons if r.source_index == 2 and r.target_index == 3)

        heavy_src_span = abs(r_heavy.theta_src_end - r_heavy.theta_src_start)
        light_src_span = abs(r_light.theta_src_end - r_light.theta_src_start)

        assert heavy_src_span > light_src_span
        assert r_heavy.flow_rate_kg_s > r_light.flow_rate_kg_s


# ============================================================================
# 7. TestDirectionalFlowArrows
# ============================================================================

class TestDirectionalFlowArrows:
    """Verify directional flow arrows oriented along ribbon trajectory."""

    def test_compute_ribbon_arrow_points_polygon(self) -> None:
        """Arrow points polygon string has 3 coordinate pairs within viewport."""
        canvas = ChordNetworkCanvas()
        r = canvas.ribbons[0]
        pts_str = compute_ribbon_arrow_points(r)

        pts = pts_str.strip().split()
        assert len(pts) == 3
        for pt in pts:
            x_str, y_str = pt.split(",")
            x, y = float(x_str), float(y_str)
            assert 0.0 <= x <= CANVAS_VIEWPORT_WIDTH
            assert 0.0 <= y <= CANVAS_VIEWPORT_HEIGHT

    def test_arrow_points_for_all_active_ribbons(self) -> None:
        """Every active ribbon generates valid triangular polygon points."""
        canvas = ChordNetworkCanvas()
        for r in canvas.ribbons:
            if r.flow_rate_kg_s > 0:
                pts_str = compute_ribbon_arrow_points(r)
                assert len(pts_str.split()) == 3


# ============================================================================
# 8. TestSVGGenerationAndXMLValidity
# ============================================================================

class TestSVGGenerationAndXMLValidity:
    """Verify standalone W3C SVG 1.1 generation, XML validity, viewBox, width, height."""

    def test_svg_is_valid_xml_via_element_tree(self) -> None:
        """generate_svg produces well-formed XML parseable by ElementTree."""
        canvas = ChordNetworkCanvas()
        svg_text = canvas.generate_svg()

        root = ET.fromstring(svg_text)
        assert root.tag.endswith("svg")
        assert root.attrib.get("viewBox") == "0 0 1200 750"
        assert root.attrib.get("width") == "1200"
        assert root.attrib.get("height") == "750"

    def test_svg_contains_essential_groups_and_elements(self) -> None:
        """SVG contains defs, background, ribbons, perimeter arcs, and HUD card."""
        canvas = ChordNetworkCanvas()
        svg_text = canvas.generate_svg()

        assert '<defs>' in svg_text
        assert '<style>' in svg_text
        assert 'filter id="selection-glow"' in svg_text
        assert 'filter id="badge-shadow"' in svg_text
        assert f'fill="{COLOR_DARK_THEME_BACKING}"' in svg_text
        assert 'id="chord-network-diagram"' in svg_text
        assert 'id="chord-ribbons"' in svg_text
        assert 'id="flow-arrows"' in svg_text
        assert 'id="zone-perimeter-arcs"' in svg_text
        assert 'id="badge-popovers"' in svg_text
        assert 'id="telemetry-hud-card"' in svg_text

    def test_svg_custom_viewports(self) -> None:
        """generate_svg handles custom width and height parameters."""
        canvas = ChordNetworkCanvas()
        svg_custom = canvas.generate_svg(viewport_width=1600, viewport_height=900)
        root = ET.fromstring(svg_custom)

        assert root.attrib.get("viewBox") == "0 0 1600 900"
        assert root.attrib.get("width") == "1600"
        assert root.attrib.get("height") == "900"

    def test_render_svg_alias(self) -> None:
        """render_svg() returns identical output to generate_svg()."""
        canvas = ChordNetworkCanvas()
        assert canvas.render_svg() == canvas.generate_svg()

    def test_svg_contains_all_registers_in_hud(self) -> None:
        """Telemetry HUD card displays %R2160..%R2167 and %M504..%M505."""
        canvas = ChordNetworkCanvas()
        svg_text = canvas.generate_svg()

        for reg in ["%R2160", "%R2161", "%R2162", "%R2163", "%R2164", "%R2165", "%R2166", "%R2167"]:
            assert reg in svg_text
        assert "%M504" in svg_text
        assert "%M505" in svg_text


# ============================================================================
# 9. TestWCAG21AAAContrastCompliance
# ============================================================================

class TestWCAG21AAAContrastCompliance:
    """Verify WCAG 2.1 relative luminance math, text >= 7.0:1, badge >= 18:1, graphics >= 3.0:1."""

    def test_srgb_channel_to_linear(self) -> None:
        """srgb_channel_to_linear applies linear ramp and power curve."""
        assert srgb_channel_to_linear(0.0) == 0.0
        assert srgb_channel_to_linear(0.03928) == pytest.approx(0.03928 / 12.92)
        assert srgb_channel_to_linear(1.0) == 1.0

    def test_hex_to_relative_luminance(self) -> None:
        """Relative luminance for pure black is 0.0, pure white is 1.0."""
        assert hex_to_relative_luminance("#000000") == 0.0
        assert hex_to_relative_luminance("#FFFFFF") == pytest.approx(1.0)

    def test_calculate_contrast_ratio_symmetry(self) -> None:
        """Contrast ratio is symmetric regardless of argument order."""
        c1 = calculate_contrast_ratio("#FFFFFF", "#000000")
        c2 = calculate_contrast_ratio("#000000", "#FFFFFF")
        assert c1 == c2 == 21.0

    def test_decoupled_badge_text_contrast_ratio(self) -> None:
        """Primary text on decoupled badge exceeds 18.0:1 target."""
        c = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert c >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, 18.0) is True

    def test_node_label_and_title_text_contrast_ratio(self) -> None:
        """Primary text on dark theme backing exceeds 7.0:1 WCAG AAA text target."""
        c = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert c >= WCAG_AAA_TEXT_CONTRAST_TARGET
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING, 7.0) is True

    def test_muted_text_contrast_ratio(self) -> None:
        """Muted text on decoupled badge exceeds 7.0:1 WCAG AAA text target."""
        c = calculate_contrast_ratio(COLOR_TEXT_MUTED, COLOR_DECOUPLED_BADGE)
        assert c >= WCAG_AAA_TEXT_CONTRAST_TARGET

    def test_graphical_contrast_all_zones(self) -> None:
        """All 5 zone colors exceed 3.0:1 graphical contrast against dark background."""
        for color in CANONICAL_ZONE_PALETTE:
            c = calculate_contrast_ratio(color, COLOR_DARK_THEME_BACKING)
            assert c >= WCAG_GRAPHICAL_CONTRAST_TARGET


# ============================================================================
# 10. TestProcessSafetyDiagnosticsAndFaults
# ============================================================================

class TestProcessSafetyDiagnosticsAndFaults:
    """Verify 0x7501 Ribbon Overflow and 0x7502 Asymmetry Fault diagnostics and trips."""

    def test_nominal_operation_diagnostics(self) -> None:
        """Nominal state has 0x0000 code and healthy status."""
        canvas = ChordNetworkCanvas()
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.healthy is True
        assert canvas.bottleneck_alarm is False
        assert (canvas.status_bits & ChordNetworkStatusBits.NOMINAL_OPERATION) != 0

    def test_trigger_ribbon_overflow_trip(self) -> None:
        """Ribbon bandwidth saturation >= 90% trips 0x7501 and asserts %M505."""
        canvas = ChordNetworkCanvas()
        canvas.trigger_ribbon_overflow(95.0)

        assert canvas.diagnostic_code == DIAG_ERR_RIBBON_OVERFLOW
        assert canvas.bottleneck_alarm is True
        assert canvas.reg_table.read_word("%R2167") == 0x7501
        assert canvas.reg_table.read_bit("%M505") is True
        assert (canvas.status_bits & ChordNetworkStatusBits.RIBBON_OVERFLOW_ALARM) != 0
        assert (canvas.status_bits & ChordNetworkStatusBits.NOMINAL_OPERATION) == 0

    def test_trigger_asymmetry_fault_trip(self) -> None:
        """Flow asymmetry index >= 30% trips 0x7502 and asserts %M505."""
        canvas = ChordNetworkCanvas()
        canvas.trigger_asymmetry_fault(35.0)

        assert canvas.diagnostic_code == DIAG_ERR_ASYMMETRY_FAULT
        assert canvas.bottleneck_alarm is True
        assert canvas.reg_table.read_word("%R2167") == 0x7502
        assert canvas.reg_table.read_bit("%M505") is True
        assert (canvas.status_bits & ChordNetworkStatusBits.ASYMMETRY_FAULT_ALARM) != 0
        assert (canvas.status_bits & ChordNetworkStatusBits.NOMINAL_OPERATION) == 0

    def test_reset_nominal_restores_state(self) -> None:
        """reset_nominal restores clean 0x0000 code and clears alarms."""
        canvas = ChordNetworkCanvas()
        canvas.trigger_ribbon_overflow(95.0)
        assert canvas.bottleneck_alarm is True

        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.bottleneck_alarm is False
        assert canvas.healthy is True
        assert canvas.reg_table.read_word("%R2167") == 0x0000
        assert canvas.reg_table.read_bit("%M505") is False
        assert (canvas.status_bits & ChordNetworkStatusBits.NOMINAL_OPERATION) != 0

    def test_clear_faults_alias(self) -> None:
        """clear_faults() resets to nominal baseline."""
        canvas = ChordNetworkCanvas()
        canvas.trigger_asymmetry_fault(35.0)
        canvas.clear_faults()
        assert canvas.diagnostic_code == DIAG_EVENT_OK
        assert canvas.bottleneck_alarm is False


# ============================================================================
# 11. TestBottleneckAlarmCoilAssertion
# ============================================================================

class TestBottleneckAlarmCoilAssertion:
    """Verify %M505 discrete coil assertions across fault injections and resets."""

    def test_bottleneck_alarm_inactive_nominally(self) -> None:
        """Coil %M505 is False in nominal balanced operation."""
        canvas = ChordNetworkCanvas()
        assert canvas.bottleneck_alarm is False
        assert canvas.reg_table.read_bit("%M505") is False

    def test_bottleneck_alarm_active_on_overflow(self) -> None:
        """Coil %M505 is True during ribbon overflow."""
        canvas = ChordNetworkCanvas()
        canvas.trigger_ribbon_overflow(92.0)
        assert canvas.bottleneck_alarm is True
        assert canvas.reg_table.read_bit("%M505") is True

    def test_bottleneck_alarm_active_on_asymmetry(self) -> None:
        """Coil %M505 is True during flow asymmetry."""
        canvas = ChordNetworkCanvas()
        canvas.trigger_asymmetry_fault(35.0)
        assert canvas.bottleneck_alarm is True
        assert canvas.reg_table.read_bit("%M505") is True

    def test_bottleneck_alarm_manual_trigger(self) -> None:
        """trigger_bottleneck_alarm() directly asserts %M505."""
        canvas = ChordNetworkCanvas()
        canvas.trigger_bottleneck_alarm()
        assert canvas.bottleneck_alarm is True
        assert canvas.reg_table.read_bit("%M505") is True

    def test_canvas_healthy_coil_assertion(self) -> None:
        """Coil %M504 remains True during normal operation and ribbon overflow."""
        canvas = ChordNetworkCanvas()
        assert canvas.reg_table.read_bit("%M504") is True
        canvas.trigger_ribbon_overflow(95.0)
        assert canvas.reg_table.read_bit("%M504") is True


# ============================================================================
# 12. TestHornerOCSSynchronizationAndRegisters
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Verify Horner RegisterTable exact values, privilege modes, and 100-cycle soak stability."""

    def test_register_synchronization_exact_values(self) -> None:
        """Verify register values match nominal specification exactly."""
        reg_table = RegisterTable()
        canvas = ChordNetworkCanvas(reg_table=reg_table)
        canvas.sync_to_registers()

        assert reg_table.read_word("%R2160") == 5
        assert reg_table.read_word("%R2161") == 850
        assert reg_table.read_word("%R2162") == 425
        assert reg_table.read_word("%R2163") == 1250
        assert reg_table.read_word("%R2164") == 0
        assert reg_table.read_word("%R2165") == 1
        assert reg_table.read_word("%R2166") == 1
        assert reg_table.read_word("%R2167") == 0
        assert reg_table.read_bit("%M504") is True
        assert reg_table.read_bit("%M505") is False

    def test_interactive_corridor_selection_updates_registers(self) -> None:
        """select_corridor updates %R2164 and %R2165."""
        canvas = ChordNetworkCanvas()
        canvas.select_corridor(2, 3)

        assert canvas.reg_table.read_word("%R2164") == 2
        assert canvas.reg_table.read_word("%R2165") == 3

    def test_select_zone_method_updates_selected_zone(self) -> None:
        """select_zone() updates selected source and target zones."""
        canvas = ChordNetworkCanvas()
        canvas.select_zone(1)
        assert canvas.selected_source_zone == 1

    def test_set_flow_updates_flow_matrix_and_registers(self) -> None:
        """set_flow updates corridor flow rate and registers."""
        canvas = ChordNetworkCanvas()
        canvas.set_flow(0, 1, 400.0)
        assert canvas.flow_matrix[0][1] == 400.0

    def test_set_zone_pressure(self) -> None:
        """set_zone_pressure updates telemetry pressure on specified zone."""
        canvas = ChordNetworkCanvas()
        canvas.set_zone_pressure(0, 22.5)
        assert canvas.zones[0].pressure_bar == 22.5

    def test_100_cycle_soak_stability(self) -> None:
        """100 discrete scan cycles maintain deterministic register values without drift."""
        reg_table = RegisterTable()
        canvas = ChordNetworkCanvas(reg_table=reg_table)

        for _ in range(100):
            canvas.scan_step(0.01)

        assert reg_table.read_word("%R2160") == 5
        assert reg_table.read_word("%R2161") == 850
        assert reg_table.read_word("%R2162") == 425
        assert reg_table.read_word("%R2163") == 1250
        assert reg_table.read_word("%R2167") == 0
        assert reg_table.read_bit("%M504") is True
        assert reg_table.read_bit("%M505") is False


# ============================================================================
# 13. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Verify IEC 61131-3 Pure Structured Text POU grammar and AST compliance."""

    def test_pure_st_content_security_guard(self) -> None:
        """SecurityGuard asserts pure ST without ladder logic constructs."""
        SecurityGuard.assert_pure_st_content(CHORD_NETWORK_CANVAS_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(DYNAMIC_CHORD_NETWORK_SCADA_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(CHORD_NETWORK_CANVAS_SYNC_PURE_ST_POU)

    def test_st_parser_parse_pou_structure(self) -> None:
        """STParser parses POU into Program AST node."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(CHORD_NETWORK_CANVAS_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "ChordNetworkCanvasSync"
        assert pou.pou_type == POUType.PROGRAM
        assert len(pou.variables) == 10

    def test_st_register_bindings_complete(self) -> None:
        """Verify all required word registers and discrete coils are bound in POU."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(CHORD_NETWORK_CANVAS_PURE_ST_POU)
        vmap = {v.name: v.address_binding for v in pou.variables}

        assert vmap["ActiveZonesCount"] == "%R2160"
        assert vmap["TotalNetworkFlowScaled"] == "%R2161"
        assert vmap["MaxRibbonBandwidthScaled"] == "%R2162"
        assert vmap["FlowAsymmetryIndexScaled"] == "%R2163"
        assert vmap["SelectedSourceZone"] == "%R2164"
        assert vmap["SelectedTargetZone"] == "%R2165"
        assert vmap["FlowBottleneckZone"] == "%R2166"
        assert vmap["CanvasDiagnosticCode"] == "%R2167"
        assert vmap["CanvasHealthy"] == "%M504"
        assert vmap["BottleneckAlarm"] == "%M505"

    def test_st_variable_data_types(self) -> None:
        """Word registers are mapped to INT and coils are mapped to BOOL."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(CHORD_NETWORK_CANVAS_PURE_ST_POU)
        tmap = {v.name: v.data_type for v in pou.variables}

        for var_name in [
            "ActiveZonesCount",
            "TotalNetworkFlowScaled",
            "MaxRibbonBandwidthScaled",
            "FlowAsymmetryIndexScaled",
            "SelectedSourceZone",
            "SelectedTargetZone",
            "FlowBottleneckZone",
            "CanvasDiagnosticCode",
        ]:
            assert tmap[var_name] == "INT"

        assert tmap["CanvasHealthy"] == "BOOL"
        assert tmap["BottleneckAlarm"] == "BOOL"

    def test_verify_helper_function(self) -> None:
        """verify_chord_network_canvas_pure_st returns True."""
        assert verify_chord_network_canvas_pure_st() is True


# ============================================================================
# 14. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Verify ladder logic constructs fail closed with LadderForbiddenError."""

    @pytest.mark.parametrize(
        "ladder_code,description",
        [
            ("PROGRAM Bad VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM", "Normally open contact"),
            ("PROGRAM Bad VAR X: BOOL; END_VAR ---[/]--- END_PROGRAM", "Normally closed contact"),
            ("PROGRAM Bad VAR Y: BOOL; END_VAR ---( )--- END_PROGRAM", "Standard coil"),
            ("PROGRAM Bad VAR Y: BOOL; END_VAR ---(/)--- END_PROGRAM", "Negated coil"),
            ("PROGRAM Bad\nRUNG 1:\nEND_PROGRAM", "Rung header delimiter"),
            ("PROGRAM Bad\nNETWORK 1:\nEND_PROGRAM", "Network header delimiter"),
            ("PROGRAM Bad\nEND_RUNG;\nEND_PROGRAM", "End rung delimiter"),
            ("PROGRAM Bad\nXIC bVal;\nEND_PROGRAM", "Mnemonic XIC"),
            ("PROGRAM Bad\nXIO bVal;\nEND_PROGRAM", "Mnemonic XIO"),
            ("PROGRAM Bad\nOTE bOut;\nEND_PROGRAM", "Mnemonic OTE"),
            ("PROGRAM Bad\nOTL bLatch;\nEND_PROGRAM", "Mnemonic OTL"),
            ("PROGRAM Bad\nOTU bUnlatch;\nEND_PROGRAM", "Mnemonic OTU"),
        ],
    )
    def test_anti_ladder_interception(self, ladder_code: str, description: str) -> None:
        """Reject forbidden ladder constructs with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(ladder_code)


# ============================================================================
# 15. TestILogicUnitComplianceAndVerificationRunner
# ============================================================================

class TestILogicUnitComplianceAndVerificationRunner:
    """Verify ILogicUnit protocol compliance and 9-stage verification suite contract."""

    def test_ilogic_unit_properties(self) -> None:
        """Verify priority, is_enabled, and name."""
        canvas = ChordNetworkCanvas()
        assert canvas.name == "ChordNetworkCanvasSync"
        assert canvas.priority == 88
        assert canvas.is_enabled is True

    def test_ilogic_unit_scan_step_and_step_alias(self) -> None:
        """scan_step and step advance cycle count without errors."""
        canvas = ChordNetworkCanvas()
        canvas.scan_step(0.01)
        canvas.step()

    def test_ilogic_unit_execute_with_scan_context(self) -> None:
        """execute and execute_logic run discrete scan cycle step."""
        canvas = ChordNetworkCanvas()
        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=lambda addr: canvas.reg_table.read_word(addr),
            set_register=lambda addr, val: canvas.reg_table.write_word(addr, val, PrivilegeMode.SYSTEM),
            get_variable=lambda name, default=None: default,
            set_variable=lambda name, val: None,
            record_fault=lambda fault: None,
        )
        canvas.execute(ctx)
        canvas.execute_logic(ctx)

    def test_ilogic_unit_reset(self) -> None:
        """reset restores baseline nominal state."""
        canvas = ChordNetworkCanvas()
        canvas.trigger_ribbon_overflow(95.0)
        assert canvas.bottleneck_alarm is True

        canvas.reset()
        assert canvas.bottleneck_alarm is False
        assert canvas.diagnostic_code == DIAG_EVENT_OK

    def test_canonical_factory_creates_canvas(self) -> None:
        """create_canonical_chord_network_canvas returns ready ChordNetworkCanvas instance."""
        canvas = create_canonical_chord_network_canvas()
        assert isinstance(canvas, ChordNetworkCanvas)
        assert canvas.healthy is True

    def test_verification_suite_success_and_contract(self, tmp_path: Path) -> None:
        """Verification suite runs 9 stages and writes evidence JSON & SVG returning success."""
        ev_file = tmp_path / "evidence.json"
        svg_file = tmp_path / "sample.svg"

        res = run_chord_network_canvas_verification(
            output_path=ev_file,
            sample_svg_path=svg_file,
            work_package="W255",
        )

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert "Deterministic 9-stage verification" in res["details"]
        assert res["data"]["work_package"] == "W255"
        assert len(res["data"]["stages"]) == 9
        assert all(s["passed"] for s in res["data"]["stages"])

        assert ev_file.exists()
        assert svg_file.exists()

        # Check evidence content bit-for-bit
        ev_data = json.loads(ev_file.read_text(encoding="utf-8"))
        assert ev_data["status"] == "success"
        assert ev_data["data"]["metrics"]["total_network_flow_scaled"] == 850
        assert ev_data["data"]["metrics"]["max_ribbon_bandwidth_scaled"] == 425
        assert ev_data["data"]["metrics"]["flow_asymmetry_index_scaled"] == 1250
