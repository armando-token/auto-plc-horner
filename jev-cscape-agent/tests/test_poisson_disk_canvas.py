"""Comprehensive Unit Test Suite for Cscape HMI Dynamic Spatial Poisson-Disk Sampling SCADA Canvas (W288).

Work Package: W288 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Poisson-Disk Sampling SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Covers:
1. Constants, viewport dimensions, color palettes, status bits, and diagnostic codes (0x8301..0x8305)
2. Bridson's fast Poisson-disk sampling algorithm and spatial acceleration grid
3. Inter-sensor minimum distance r_min constraint validation
4. Domain boundary containment [0, 1200] x [0, 750]
5. Spatial void / intrusion anomaly injection and clearing (%M582 / 0x8305)
6. W3C SVG 1.1 vector generation, valid XML, WCAG 2.1 AAA contrast
7. Horner OCS register space synchronization (%R2490..%R2497, %M581..%M582)
8. Pure IEC 61131-3 Structured Text validation & anti-ladder rejection
9. ILogicUnit interface compliance (scan_step, step, execute, reset, multi-cycle soak)
10. Deterministic 9-stage verification runner execution and artifact export
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.poisson_disk_canvas import (
    CANVAS_VIEWPORT_WIDTH,
    CANVAS_VIEWPORT_HEIGHT,
    TOTAL_DOMAIN_AREA,
    COLOR_SCADA_BG,
    COLOR_DARK_SURFACE,
    COLOR_DECOUPLED_BADGE,
    COLOR_BORDER,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_MUTED,
    COLOR_SAMPLE_NODE,
    COLOR_SAMPLE_BORDER,
    COLOR_EXCLUSION_DISK,
    COLOR_ACTIVE_FRONTIER,
    COLOR_NOMINAL_EMERALD,
    COLOR_ALARM_CRIMSON,
    REG_POISSON_SAMPLE_COUNT,
    REG_POISSON_ACTIVE_QUEUE_LEN,
    REG_POISSON_MIN_DISTANCE_PX,
    REG_POISSON_COVERAGE_PCT,
    REG_POISSON_GRID_CELL_SIZE,
    REG_POISSON_SELECTED_SAMPLE_ID,
    REG_POISSON_DENSITY_INDEX,
    REG_POISSON_DIAGNOSTIC_CODE,
    COIL_POISSON_SAMPLING_ACTIVE,
    COIL_POISSON_VOID_INTRUSION_ALARM,
    DiagnosticCode,
    PoissonDiagnosticCode,
    DIAG_OK,
    DIAG_ERR_DEGENERATE_RADIUS,
    DIAG_ERR_QUEUE_OVERFLOW,
    DIAG_ERR_SPATIAL_VOID_INTRUSION,
    PoissonStatusBits,
    PoissonPoint,
    PoissonMetrics,
    ST_PROGRAM_POISSON_DISK_CANVAS_SYNC,
    POISSON_DISK_CANVAS_PURE_ST_POU,
    PoissonDiskCanvasSync,
    verify_poisson_disk_canvas_pure_st,
    PoissonDiskCanvasEngine,
    generate_poisson_disk_canvas_svg,
    run_poisson_disk_canvas_verification,
)


def _srgb_to_linear(c_norm: float) -> float:
    """Convert normalized sRGB channel [0, 1] to linear factor for WCAG 2.1."""
    if c_norm <= 0.03928:
        return c_norm / 12.92
    return ((c_norm + 0.055) / 1.055) ** 2.4


def _hex_to_relative_luminance(hex_str: str) -> float:
    """Calculate relative luminance from hex color string."""
    h = hex_str.lstrip("#")
    r, g, b = int(h[0:2], 16) / 255.0, int(h[2:4], 16) / 255.0, int(h[4:6], 16) / 255.0
    return 0.2126 * _srgb_to_linear(r) + 0.7152 * _srgb_to_linear(g) + 0.0722 * _srgb_to_linear(b)


def _calculate_contrast_ratio(hex1: str, hex2: str) -> float:
    """Calculate WCAG 2.1 contrast ratio between two hex colors."""
    l1 = _hex_to_relative_luminance(hex1)
    l2 = _hex_to_relative_luminance(hex2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


class TestPoissonDiskConstantsAndDiagnostics:
    """Test suite for W288 constants, viewport dimensions, and diagnostic code definitions."""

    def test_viewport_and_domain_constants(self) -> None:
        """Verify canvas dimensions and bounding domain area."""
        assert CANVAS_VIEWPORT_WIDTH == 1200.0
        assert CANVAS_VIEWPORT_HEIGHT == 750.0
        assert TOTAL_DOMAIN_AREA == 1200.0 * 750.0
        assert TOTAL_DOMAIN_AREA == 900000.0

    def test_palette_and_theme_constants(self) -> None:
        """Verify high-contrast SCADA theme color definitions."""
        assert COLOR_SCADA_BG == "#0D1117"
        assert COLOR_DARK_SURFACE == "#161B22"
        assert COLOR_DECOUPLED_BADGE == "#050811"
        assert COLOR_BORDER == "#334155"
        assert COLOR_TEXT_PRIMARY == "#FFFFFF"
        assert COLOR_TEXT_MUTED == "#CBD5E1"
        assert COLOR_SAMPLE_NODE == "#38BDF8"
        assert COLOR_SAMPLE_BORDER == "#0284C7"
        assert COLOR_EXCLUSION_DISK == "#0284C7"
        assert COLOR_ACTIVE_FRONTIER == "#F59E0B"
        assert COLOR_NOMINAL_EMERALD == "#10B981"
        assert COLOR_ALARM_CRIMSON == "#EF4444"

    def test_register_and_coil_addresses(self) -> None:
        """Verify Horner OCS register space addresses (%R2490..%R2497, %M581..%M582)."""
        assert REG_POISSON_SAMPLE_COUNT == "%R2490"
        assert REG_POISSON_ACTIVE_QUEUE_LEN == "%R2491"
        assert REG_POISSON_MIN_DISTANCE_PX == "%R2492"
        assert REG_POISSON_COVERAGE_PCT == "%R2493"
        assert REG_POISSON_GRID_CELL_SIZE == "%R2494"
        assert REG_POISSON_SELECTED_SAMPLE_ID == "%R2495"
        assert REG_POISSON_DENSITY_INDEX == "%R2496"
        assert REG_POISSON_DIAGNOSTIC_CODE == "%R2497"
        assert COIL_POISSON_SAMPLING_ACTIVE == "%M581"
        assert COIL_POISSON_VOID_INTRUSION_ALARM == "%M582"

    def test_status_bits_enumeration(self) -> None:
        """Verify PoissonStatusBits flag values."""
        assert PoissonStatusBits.SAMPLING_ACTIVE == 1 << 0
        assert PoissonStatusBits.SAMPLING_COMPLETE == 1 << 1
        assert PoissonStatusBits.VOID_INTRUSION_ALARM == 1 << 2
        assert PoissonStatusBits.DEGENERATE_FAULT == 1 << 3
        assert PoissonStatusBits.SVG_RENDER_VALID == 1 << 4

    def test_diagnostic_codes_values_and_representations(self) -> None:
        """Verify diagnostic codes 0x0000 and 0x8301..0x8305 with signed/unsigned equivalence."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_DEGENERATE_RADIUS == 0x8303
        assert DIAG_ERR_QUEUE_OVERFLOW == 0x8304
        assert DIAG_ERR_SPATIAL_VOID_INTRUSION == 0x8305
        assert PoissonDiagnosticCode is DiagnosticCode

        # Test diagnostic code range 0x8301..0x8305
        codes_expected = {
            0x8301: (33537, -31999, "0x8301"),
            0x8302: (33538, -31998, "0x8302"),
            0x8303: (33539, -31997, "0x8303"),
            0x8304: (33540, -31996, "0x8304"),
            0x8305: (33541, -31995, "0x8305"),
        }
        for hex_val, (u_val, s_val, hex_str) in codes_expected.items():
            diag = DiagnosticCode(hex_val)
            assert diag == hex_val
            assert diag == u_val
            assert diag == s_val
            assert str(diag) == hex_str
            assert repr(diag) == f"DiagnosticCode({hex_str})"
            assert hash(diag) == hash(u_val)


class TestBridsonAlgorithmAndSpatialGrid:
    """Test suite for Bridson's fast Poisson-disk sampling algorithm and spatial acceleration grid."""

    def test_spatial_grid_dimensions_and_cell_size(self) -> None:
        """Verify acceleration grid cell size formula w = r_min / sqrt(2)."""
        r_min = 80.0
        engine = PoissonDiskCanvasEngine(r_min=r_min, seed=42)
        expected_cell_size = r_min / math.sqrt(2.0)
        assert abs(engine.cell_size - expected_cell_size) < 1e-6

        expected_cols = int(math.ceil(1200.0 / expected_cell_size))
        expected_rows = int(math.ceil(750.0 / expected_cell_size))
        assert engine.grid_cols == expected_cols
        assert engine.grid_rows == expected_rows
        assert len(engine.grid) == engine.grid_rows
        assert len(engine.grid[0]) == engine.grid_cols

    def test_initial_center_seed_point(self) -> None:
        """Verify initial seed point is seeded at center of domain."""
        engine = PoissonDiskCanvasEngine(r_min=80.0, seed=42)
        assert len(engine.samples) >= 1
        p0 = engine.samples[0]
        assert p0.id == 1
        assert p0.x == 600.0
        assert p0.y == 375.0
        assert p0.tag == "SN-101"

    def test_sampling_completion_and_queue_exhaustion(self) -> None:
        """Verify active queue is fully exhausted and sampling marked complete."""
        engine = PoissonDiskCanvasEngine(r_min=80.0, seed=42)
        assert engine.sampling_complete is True
        assert len(engine.active_queue) == 0
        assert len(engine.samples) > 20
        assert engine.diagnostic_code == DIAG_OK

    def test_candidate_validation_boundary_rejection(self) -> None:
        """Verify _is_valid_candidate strictly rejects points outside domain boundaries."""
        engine = PoissonDiskCanvasEngine(r_min=80.0, seed=42)
        assert engine._is_valid_candidate(-1.0, 100.0) is False
        assert engine._is_valid_candidate(1200.1, 100.0) is False
        assert engine._is_valid_candidate(100.0, -0.5) is False
        assert engine._is_valid_candidate(100.0, 750.5) is False

    def test_candidate_validation_proximity_rejection(self) -> None:
        """Verify _is_valid_candidate rejects points closer than r_min to existing sample."""
        engine = PoissonDiskCanvasEngine(r_min=80.0, seed=42)
        p0 = engine.samples[0]
        # Attempt candidate at distance r_min * 0.5 (too close)
        cand_x = p0.x + (engine.r_min * 0.5)
        cand_y = p0.y
        assert engine._is_valid_candidate(cand_x, cand_y) is False

    def test_degenerate_radius_detection(self) -> None:
        """Verify degenerate radius <= 0 or > viewport dimension triggers diagnostic 0x8303."""
        # Non-positive radius
        eng_neg = PoissonDiskCanvasEngine(r_min=0.0)
        assert eng_neg.diagnostic_code == DIAG_ERR_DEGENERATE_RADIUS
        assert len(eng_neg.samples) == 0

        # Radius exceeding viewport min dimension
        eng_huge = PoissonDiskCanvasEngine(r_min=1500.0)
        assert eng_huge.diagnostic_code == DIAG_ERR_DEGENERATE_RADIUS
        assert len(eng_huge.samples) == 0


class TestGeometricConstraintsAndBoundaryContainment:
    """Test suite for geometric constraints and boundary containment."""

    @pytest.mark.parametrize("r_min,seed", [(60.0, 10), (80.0, 42), (100.0, 99)])
    def test_pairwise_minimum_distance_constraint(self, r_min: float, seed: int) -> None:
        """Verify strictly every sample pair (i, j) satisfies distance >= r_min * 0.999."""
        engine = PoissonDiskCanvasEngine(r_min=r_min, seed=seed)
        samples = engine.samples
        n = len(samples)
        assert n > 10

        min_found_dist = float("inf")
        for i in range(n):
            for j in range(i + 1, n):
                dist = math.hypot(samples[i].x - samples[j].x, samples[i].y - samples[j].y)
                if dist < min_found_dist:
                    min_found_dist = dist
                assert dist >= r_min * 0.999, f"Samples {i} and {j} too close: {dist} < {r_min}"

        assert min_found_dist >= r_min * 0.999

    @pytest.mark.parametrize("r_min,seed", [(70.0, 7), (80.0, 42), (90.0, 123)])
    def test_domain_containment(self, r_min: float, seed: int) -> None:
        """Verify 100% of generated sample points are strictly within [0, 1200] x [0, 750]."""
        engine = PoissonDiskCanvasEngine(r_min=r_min, seed=seed)
        assert len(engine.samples) > 0
        for s in engine.samples:
            assert 0.0 <= s.x <= CANVAS_VIEWPORT_WIDTH, f"Sample x out of bounds: {s.x}"
            assert 0.0 <= s.y <= CANVAS_VIEWPORT_HEIGHT, f"Sample y out of bounds: {s.y}"

    def test_packing_density_and_coverage_metrics(self) -> None:
        """Verify PoissonMetrics snapshot calculations for coverage and density index."""
        engine = PoissonDiskCanvasEngine(r_min=80.0, seed=42)
        metrics = engine.metrics
        assert metrics.sample_count == len(engine.samples)
        assert metrics.active_queue_len == 0
        assert metrics.min_distance_px == 80.0
        assert metrics.grid_cell_size_px == engine.cell_size
        assert metrics.coverage_pct > 10.0
        assert metrics.density_index > 0.0
        assert metrics.is_complete is True
        assert metrics.void_alarm is False


class TestSpatialVoidIntrusionAnomaly:
    """Test suite for spatial void / intrusion anomaly injection and clearing (%M582 / 0x8305)."""

    def test_void_intrusion_alarm_assertion(self) -> None:
        """Verify inject_void_anomaly sets void_alarm, diagnostic 0x8305, %M582, and fails scan_step."""
        reg_table = RegisterTable()
        engine = PoissonDiskCanvasEngine(r_min=80.0, seed=42, register_table=reg_table)

        # Baseline nominal state
        assert engine.void_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert reg_table.read_bit(COIL_POISSON_VOID_INTRUSION_ALARM) is False
        assert reg_table.read_bit(COIL_POISSON_SAMPLING_ACTIVE) is True

        # Inject anomaly
        engine.inject_void_anomaly()
        assert engine.void_alarm is True
        assert engine.diagnostic_code == DIAG_ERR_SPATIAL_VOID_INTRUSION
        assert reg_table.read_bit(COIL_POISSON_VOID_INTRUSION_ALARM) is True
        assert reg_table.read_bit(COIL_POISSON_SAMPLING_ACTIVE) is False
        assert (reg_table.read_word(REG_POISSON_DIAGNOSTIC_CODE) & 0xFFFF) == 0x8305
        assert DIAG_ERR_SPATIAL_VOID_INTRUSION == reg_table.read_word(REG_POISSON_DIAGNOSTIC_CODE)

        # Scan step evaluation under alarm
        res = engine.scan_step()
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "0x8305"
        assert res.data["void_alarm"] is True

    def test_void_intrusion_alarm_clearing(self) -> None:
        """Verify clear_anomalies resets alarm, diagnostic 0x0000, %M582, and succeeds scan_step."""
        reg_table = RegisterTable()
        engine = PoissonDiskCanvasEngine(r_min=80.0, seed=42, register_table=reg_table)
        engine.inject_void_anomaly()

        # Clear anomaly
        engine.clear_anomalies()
        assert engine.void_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert reg_table.read_bit(COIL_POISSON_VOID_INTRUSION_ALARM) is False
        assert reg_table.read_bit(COIL_POISSON_SAMPLING_ACTIVE) is True
        assert reg_table.read_word(REG_POISSON_DIAGNOSTIC_CODE) == 0x0000

        # Scan step evaluation under nominal
        res = engine.scan_step()
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None
        assert res.data["void_alarm"] is False


class TestW3CSVGAndWCAGAAAContrast:
    """Test suite for W3C SVG 1.1 markup generation, XML validity, and WCAG 2.1 AAA contrast."""

    def test_svg_xml_validity_and_structure(self) -> None:
        """Verify generated SVG produces valid XML tree with required attributes and layers."""
        engine = PoissonDiskCanvasEngine(r_min=80.0, seed=42)
        svg_str = generate_poisson_disk_canvas_svg(engine)

        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg")
        assert root.attrib["viewBox"] == f"0 0 {int(CANVAS_VIEWPORT_WIDTH)} {int(CANVAS_VIEWPORT_HEIGHT)}"
        assert root.attrib["width"] == str(int(CANVAS_VIEWPORT_WIDTH))
        assert root.attrib["height"] == str(int(CANVAS_VIEWPORT_HEIGHT))

        # Check background rect
        rects = [el for el in root.iter() if el.tag.endswith("rect")]
        assert len(rects) >= 3  # bg, hud card, status pill
        assert rects[0].attrib["fill"] == COLOR_SCADA_BG

        # Check exclusion circles and sensor node groups
        circles = [el for el in root.iter() if el.tag.endswith("circle")]
        assert len(circles) >= len(engine.samples) * 2  # 1 exclusion disk + 1 node per sample

        # Check sensor node group id formatting
        assert "poisson-node-1" in svg_str
        assert "sensor-node" in svg_str
        assert "SN-101" in svg_str

    def test_svg_nominal_vs_alarm_rendering(self) -> None:
        """Verify SVG reflects nominal vs alarm status pill formatting."""
        engine = PoissonDiskCanvasEngine(r_min=80.0, seed=42)

        # Nominal SVG
        svg_nominal = generate_poisson_disk_canvas_svg(engine)
        assert "POISSON DISTRIBUTION NOMINAL" in svg_nominal
        assert COLOR_NOMINAL_EMERALD in svg_nominal

        # Alarm SVG
        engine.inject_void_anomaly()
        svg_alarm = generate_poisson_disk_canvas_svg(engine)
        assert "VOID / INTRUSION ALARM" in svg_alarm
        assert COLOR_ALARM_CRIMSON in svg_alarm

    def test_wcag_21_aaa_contrast_ratios(self) -> None:
        """Verify high-contrast dark theme elements meet WCAG 2.1 AAA ratio (> 18:1 badge, > 7:1 text)."""
        # Primary white on decoupled badge (#FFFFFF on #050811)
        cr_badge = _calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert cr_badge >= 18.0, f"Decoupled badge contrast {cr_badge:.2f} < 18:1"

        # Primary white on SCADA dark background (#FFFFFF on #0D1117)
        cr_bg = _calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_SCADA_BG)
        assert cr_bg >= 15.0, f"Primary text on background contrast {cr_bg:.2f} < 15:1"

        # Muted text on decoupled badge (#CBD5E1 on #050811)
        cr_muted = _calculate_contrast_ratio(COLOR_TEXT_MUTED, COLOR_DECOUPLED_BADGE)
        assert cr_muted >= 12.0, f"Muted text contrast {cr_muted:.2f} < 12:1"

        # Sensor node cyan on SCADA background (#38BDF8 on #0D1117)
        cr_sensor = _calculate_contrast_ratio(COLOR_SAMPLE_NODE, COLOR_SCADA_BG)
        assert cr_sensor >= 7.0, f"Sensor node contrast {cr_sensor:.2f} < 7:1"


class TestHornerOCSRegisterSpaceSync:
    """Test suite for Horner OCS memory space synchronization (%R2490..%R2497, %M581..%M582)."""

    def test_register_synchronization_values(self) -> None:
        """Verify synchronization of metrics into %R2490..%R2497 and %M581..%M582."""
        reg_table = RegisterTable()
        engine = PoissonDiskCanvasEngine(r_min=80.0, seed=42, register_table=reg_table)
        engine.sync_to_registers(reg_table)

        m = engine.metrics
        assert reg_table.read_word(REG_POISSON_SAMPLE_COUNT) == len(engine.samples)
        assert reg_table.read_word(REG_POISSON_ACTIVE_QUEUE_LEN) == 0
        assert reg_table.read_word(REG_POISSON_MIN_DISTANCE_PX) == int(round(80.0 * 10.0))
        assert reg_table.read_word(REG_POISSON_COVERAGE_PCT) == int(round(m.coverage_pct * 10.0))
        assert reg_table.read_word(REG_POISSON_GRID_CELL_SIZE) == int(round(engine.cell_size * 10.0))
        assert reg_table.read_word(REG_POISSON_SELECTED_SAMPLE_ID) == 1
        assert reg_table.read_word(REG_POISSON_DENSITY_INDEX) == int(round(m.density_index * 10.0))
        assert reg_table.read_word(REG_POISSON_DIAGNOSTIC_CODE) == 0x0000

        assert reg_table.read_bit(COIL_POISSON_SAMPLING_ACTIVE) is True
        assert reg_table.read_bit(COIL_POISSON_VOID_INTRUSION_ALARM) is False

    def test_privilege_modes_register_access(self) -> None:
        """Verify sync_to_registers functions under both USER and SYSTEM privilege modes."""
        reg_table = RegisterTable()
        engine = PoissonDiskCanvasEngine(r_min=80.0, seed=42)

        engine.sync_to_registers(reg_table, privilege=PrivilegeMode.USER)
        assert reg_table.read_word(REG_POISSON_SAMPLE_COUNT) == len(engine.samples)

        engine.sync_to_registers(reg_table, privilege=PrivilegeMode.SYSTEM)
        assert reg_table.read_word(REG_POISSON_SAMPLE_COUNT) == len(engine.samples)


class TestPureSTAndLadderInterception:
    """Test suite for Pure IEC 61131-3 Structured Text validation & anti-ladder rejection."""

    def test_pure_st_pou_ast_validation(self) -> None:
        """Verify Pure ST POU validation, AST generation, and register binding."""
        assert verify_poisson_disk_canvas_pure_st() is True
        SecurityGuard.assert_pure_st_content(POISSON_DISK_CANVAS_PURE_ST_POU)

        res = STParser.validate_code(POISSON_DISK_CANVAS_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(POISSON_DISK_CANVAS_PURE_ST_POU)
        assert ast.name == "PoissonDiskCanvasSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R2490", "%R2491", "%R2492", "%R2493",
            "%R2494", "%R2495", "%R2496", "%R2497",
            "%M581", "%M582",
        }
        for reg in expected_regs:
            assert reg in ast.bound_registers, f"Register {reg} missing from AST bindings"

    def test_anti_ladder_contacts_rejection(self) -> None:
        """Verify ladder contacts '---[ ]---' are rejected fail-closed."""
        bad_st = "PROGRAM P VAR b : BOOL; END_VAR ---[ ]--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_anti_ladder_coils_rejection(self) -> None:
        """Verify ladder coils '---( )---' are rejected fail-closed."""
        bad_st = "PROGRAM P VAR b : BOOL; END_VAR ---( )--- END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_anti_ladder_rung_delimiters_rejection(self) -> None:
        """Verify ladder rung delimiters 'RUNG' are rejected fail-closed."""
        bad_st = "PROGRAM P VAR b : BOOL; END_VAR RUNG 1: A := B; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_anti_ladder_mnemonics_rejection(self) -> None:
        """Verify ladder mnemonics 'XIC' and 'OTE' are rejected fail-closed."""
        bad_st = "PROGRAM P VAR b : BOOL; END_VAR XIC b; OTE c; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)


class TestILogicUnitComplianceAndSimulation:
    """Test suite for ILogicUnit interface compliance and scan cycle simulation."""

    def test_ilogicunit_interface_properties(self) -> None:
        """Verify PoissonDiskCanvasEngine implements ILogicUnit properties."""
        assert issubclass(PoissonDiskCanvasEngine, ILogicUnit)
        engine = PoissonDiskCanvasEngine(r_min=80.0, seed=42)
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "PoissonDiskCanvasEngine"
        assert engine.priority == 100
        assert engine.is_enabled is True

    def test_ilogicunit_methods(self) -> None:
        """Verify scan_step, step, execute, and reset methods."""
        reg_table = RegisterTable()
        engine = PoissonDiskCanvasEngine(r_min=80.0, seed=42, register_table=reg_table)

        # scan_step
        res = engine.scan_step()
        assert res.status == AgentStatus.SUCCESS
        assert engine.cycle_count == 1

        # step
        engine.step()
        assert engine.cycle_count == 2

        # execute with ScanContext
        ctx = ScanContext(cycle=3, dt_ms=10.0, register_table=reg_table)
        engine.execute(ctx)
        assert engine.cycle_count == 3

        # reset
        sample_count_before = len(engine.samples)
        engine.inject_void_anomaly()
        assert engine.void_alarm is True

        engine.reset()
        assert engine.void_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert len(engine.samples) == sample_count_before

    def test_simulation_scan_cycle_soak(self) -> None:
        """Verify multi-cycle scan execution stability across 50 consecutive cycles."""
        reg_table = RegisterTable()
        engine = PoissonDiskCanvasEngine(r_min=80.0, seed=42, register_table=reg_table)

        for cycle in range(1, 51):
            ctx = ScanContext(cycle=cycle, dt_ms=10.0, register_table=reg_table)
            engine.execute(ctx)
            assert reg_table.read_word(REG_POISSON_SAMPLE_COUNT) == len(engine.samples)
            assert reg_table.read_bit(COIL_POISSON_SAMPLING_ACTIVE) is True
            assert reg_table.read_bit(COIL_POISSON_VOID_INTRUSION_ALARM) is False

        assert engine.cycle_count == 50


class TestVerificationRunner9Stages:
    """Test suite for W288 deterministic 9-stage verification runner execution."""

    def test_9_stage_verification_runner_passes(self) -> None:
        """Verify run_poisson_disk_canvas_verification executes all 9 stages successfully."""
        evidence = run_poisson_disk_canvas_verification()
        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert "PASSED (9/9 stages)" in evidence["details"]
        assert evidence["data"]["work_package"] == "W288"
        assert evidence["data"]["gate"] == "G9"
        assert evidence["data"]["checks_passed"] == 9
        assert evidence["data"]["total_checks"] == 9

        stages = evidence["data"]["stages"]
        assert len(stages) == 9

        expected_stage_names = [
            "init_and_domain",
            "minimum_distance_constraint",
            "spatial_grid_acceleration",
            "domain_containment",
            "packing_density_metrics",
            "void_intrusion_alarm",
            "wcag_aaa_svg_rendering",
            "horner_ocs_register_sync",
            "pure_st_pou_and_ladder_rejection",
        ]
        for idx, expected_name in enumerate(expected_stage_names, start=1):
            stage = stages[idx - 1]
            assert stage["stage"] == idx
            assert stage["name"] == expected_name
            assert stage["passed"] is True
            assert stage["timing_ms"] >= 0.0

    def test_9_stage_verification_artifact_export(self, tmp_path: Path) -> None:
        """Verify runner outputs valid JSON evidence and SVG vector files."""
        json_file = tmp_path / "poisson_evidence.json"
        svg_file = tmp_path / "poisson_canvas.svg"

        evidence = run_poisson_disk_canvas_verification(
            output_path=str(json_file),
            sample_svg_path=str(svg_file),
            work_package="W288",
        )
        assert evidence["status"] == "success"
        assert json_file.exists()
        assert svg_file.exists()

        # Validate JSON content
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["checks_passed"] == 9

        # Validate SVG content
        with open(svg_file, "r", encoding="utf-8") as f:
            svg_content = f.read()
        root = ET.fromstring(svg_content)
        assert root.tag.endswith("svg")
        assert "sensor-node" in svg_content
