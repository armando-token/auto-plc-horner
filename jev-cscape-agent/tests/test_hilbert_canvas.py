"""Comprehensive Unit Test Suite for Cscape HMI Dynamic Spatial Hilbert / Morton SCADA Canvas (W306).

Work Package: W306 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Hilbert / Morton Space-Filling Curve SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Covers:
1. Constants, viewport dimensions, color palettes, status bits, and diagnostic codes (0x841B, 0x841C, 0x841D)
2. Hilbert curve 2D algorithms: d2xy, xy2d, order 1..8, bijective roundtrips, unit Manhattan steps, bounds checks
3. Morton Z-order curve bit interleaving (xy2z) and de-interleaving (z2xy) roundtrips
4. HilbertRect geometry: dimensions, area, containment, intersection, and degenerate handling
5. Continuous-to-discrete spatial transformations: coord_to_grid, grid_to_coord, coord_to_hilbert, hilbert_to_coord, coord_to_morton, morton_to_coord
6. Equipment object lifecycle: insertion, tag defaults, removal, clearing, and dynamic order re-indexing
7. 1D Hilbert range queries (query_range_hilbert) and 2D components mapping
8. Continuous point (query_point), circular (query_radius), and rectangular (query_rect) window queries
9. 1D locality-preserving proximity hazard detection, collision violation counting, and cluster hazard alarm assertion (%M624 / 0x841B)
10. W3C SVG 1.1 vector graphic generation, valid XML parsing, equipment symbol grounding, and WCAG 2.1 AAA contrast (> 18:1)
11. Horner OCS register table synchronization (%R2670..%R2677, %M623..%M624) with signed 16-bit masking
12. Pure IEC 61131-3 Structured Text validation & anti-ladder rejection with LadderForbiddenError
13. ILogicUnit interface compliance (scan_step, step, execute, reset, multi-cycle soak)
14. Deterministic 9-stage verification runner execution and artifact export
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.hilbert_canvas import (
    CANVAS_VIEWPORT_WIDTH,
    CANVAS_VIEWPORT_HEIGHT,
    HILBERT_GRID_DOMAIN,
    TOTAL_DOMAIN_AREA,
    MIN_CURVE_ORDER,
    MAX_CURVE_ORDER,
    DEFAULT_CURVE_ORDER,
    DEFAULT_HAZARD_THRESHOLD,
    COLOR_SCADA_BG,
    COLOR_DARK_SURFACE,
    COLOR_DECOUPLED_BADGE,
    COLOR_BORDER,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_MUTED,
    COLOR_NOMINAL_EMERALD,
    COLOR_WARNING_AMBER,
    COLOR_ALARM_CRIMSON,
    COLOR_RETICLE_CYAN,
    COLOR_GRADIENT_CYAN,
    COLOR_GRADIENT_EMERALD,
    COLOR_GRADIENT_AMBER,
    COLOR_GRADIENT_MAGENTA,
    ORDER_COLORS,
    REG_W306_TOTAL_OBJECTS,
    REG_W306_CURVE_ORDER,
    REG_W306_ACTIVE_SEGMENTS,
    REG_W306_PRIMARY_INDEX,
    REG_W306_QUERY_INDEX,
    REG_W306_HAZARD_VIOLATIONS,
    REG_W306_STATUS_WORD,
    REG_W306_DIAGNOSTIC_CODE,
    COIL_W306_CANVAS_ONLINE,
    COIL_W306_HAZARD_ALARM,
    REG_HILBERT_TOTAL_OBJECTS,
    REG_HILBERT_CURVE_ORDER,
    REG_HILBERT_ACTIVE_SEGMENTS,
    REG_HILBERT_PRIMARY_INDEX,
    REG_HILBERT_QUERY_INDEX,
    REG_HILBERT_HAZARD_VIOLATIONS,
    REG_HILBERT_STATUS_WORD,
    REG_HILBERT_DIAGNOSTIC_CODE,
    COIL_HILBERT_CANVAS_ONLINE,
    COIL_HILBERT_HAZARD_ALARM,
    COIL_HILBERT_PROXIMITY_HAZARD,
    DiagnosticCode,
    HilbertDiagnosticCode,
    DIAG_OK,
    DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD,
    DIAG_ERR_INVALID_CURVE_ORDER,
    DIAG_ERR_OUT_OF_BOUNDS,
    SPATIAL_HILBERT_PROXIMITY_HAZARD,
    INVALID_CURVE_ORDER,
    OUT_OF_BOUNDS,
    HilbertStatusBits,
    HilbertRect,
    Rect,
    SpatialObject,
    SpatialPoint,
    HilbertMetrics,
    HilbertCanvasEngine,
    HilbertCanvas,
    d2xy,
    xy2d,
    xy2z,
    z2xy,
    hilbert_d2xy,
    hilbert_xy2d,
    morton_xy2z,
    morton_z2xy,
    hilbert_range_to_2d_cells,
    hilbert_color_at_t,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    generate_hilbert_canvas_svg,
    create_canonical_hilbert_canvas,
    ST_PROGRAM_W306_HILBERT_CANVAS_SYNC,
    ST_PROGRAM_HILBERT_CANVAS_SYNC,
    verify_hilbert_canvas_pure_st,
    run_hilbert_canvas_verification,
)


# ============================================================================
# 1. Constants, Palette & Diagnostics Tests
# ============================================================================

class TestHilbertConstantsAndDiagnostics:
    def test_viewport_and_order_constants(self) -> None:
        assert CANVAS_VIEWPORT_WIDTH == 1200.0
        assert CANVAS_VIEWPORT_HEIGHT == 750.0
        assert HILBERT_GRID_DOMAIN == 1024.0
        assert TOTAL_DOMAIN_AREA == 1200.0 * 750.0
        assert MIN_CURVE_ORDER == 1
        assert MAX_CURVE_ORDER == 8
        assert DEFAULT_CURVE_ORDER == 3
        assert DEFAULT_HAZARD_THRESHOLD == 50.0

    def test_palette_and_gradient_constants(self) -> None:
        assert COLOR_SCADA_BG == "#0D1117"
        assert COLOR_DARK_SURFACE == "#161B22"
        assert COLOR_DECOUPLED_BADGE == "#05080C"
        assert COLOR_TEXT_PRIMARY == "#FFFFFF"
        assert COLOR_GRADIENT_CYAN == "#06B6D4"
        assert COLOR_GRADIENT_EMERALD == "#10B981"
        assert COLOR_GRADIENT_AMBER == "#F59E0B"
        assert COLOR_GRADIENT_MAGENTA == "#D946EF"
        assert len(ORDER_COLORS) == 8

    def test_register_mappings_and_coils(self) -> None:
        assert REG_W306_TOTAL_OBJECTS == "%R2670"
        assert REG_W306_CURVE_ORDER == "%R2671"
        assert REG_W306_ACTIVE_SEGMENTS == "%R2672"
        assert REG_W306_PRIMARY_INDEX == "%R2673"
        assert REG_W306_QUERY_INDEX == "%R2674"
        assert REG_W306_HAZARD_VIOLATIONS == "%R2675"
        assert REG_W306_STATUS_WORD == "%R2676"
        assert REG_W306_DIAGNOSTIC_CODE == "%R2677"

        assert COIL_W306_CANVAS_ONLINE == "%M623"
        assert COIL_W306_HAZARD_ALARM == "%M624"

        # Aliases
        assert REG_HILBERT_TOTAL_OBJECTS == "%R2670"
        assert REG_HILBERT_CURVE_ORDER == "%R2671"
        assert REG_HILBERT_ACTIVE_SEGMENTS == "%R2672"
        assert REG_HILBERT_PRIMARY_INDEX == "%R2673"
        assert REG_HILBERT_QUERY_INDEX == "%R2674"
        assert REG_HILBERT_HAZARD_VIOLATIONS == "%R2675"
        assert REG_HILBERT_STATUS_WORD == "%R2676"
        assert REG_HILBERT_DIAGNOSTIC_CODE == "%R2677"
        assert COIL_HILBERT_CANVAS_ONLINE == "%M623"
        assert COIL_HILBERT_HAZARD_ALARM == "%M624"
        assert COIL_HILBERT_PROXIMITY_HAZARD == "%M624"

    def test_diagnostic_codes_values_and_equality(self) -> None:
        assert int(DIAG_OK) == 0x0000
        assert int(DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD) == 0x841B
        assert int(DIAG_ERR_INVALID_CURVE_ORDER) == 0x841C
        assert int(DIAG_ERR_OUT_OF_BOUNDS) == 0x841D

        # 16-bit signed/unsigned equivalence
        assert DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD == 0x841B
        assert DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD == 0x841B - 0x10000
        assert DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD == SPATIAL_HILBERT_PROXIMITY_HAZARD
        assert DIAG_ERR_INVALID_CURVE_ORDER == INVALID_CURVE_ORDER
        assert DIAG_ERR_OUT_OF_BOUNDS == OUT_OF_BOUNDS

    def test_status_bits(self) -> None:
        assert HilbertStatusBits.ONLINE == 0x0001
        assert HilbertStatusBits.CONFLICT_DETECTED == 0x0002
        assert HilbertStatusBits.CURVE_GENERATED == 0x0004
        assert HilbertStatusBits.HIGH_DENSITY == 0x0008


# ============================================================================
# 2. Hilbert & Morton Space-Filling Curve Algorithm Tests
# ============================================================================

class TestSpaceFillingCurveAlgorithms:
    def test_hilbert_bijective_roundtrip_orders_1_to_4(self) -> None:
        for order in range(1, 5):
            total_cells = 1 << (2 * order)
            for d in range(total_cells):
                gx, gy = d2xy(order, d)
                d_calc = xy2d(order, gx, gy)
                assert d_calc == d, f"Mismatch at order={order}, d={d}: got {d_calc}"

    def test_hilbert_sampled_roundtrip_orders_5_to_8(self) -> None:
        for order in [5, 6, 7, 8]:
            n = 1 << order
            total_cells = 1 << (2 * order)
            test_indices = [
                0, 1, 2, 3,
                total_cells // 4,
                total_cells // 2,
                3 * total_cells // 4,
                total_cells - 2,
                total_cells - 1,
            ]
            for d in test_indices:
                gx, gy = d2xy(order, d)
                assert 0 <= gx < n
                assert 0 <= gy < n
                assert xy2d(order, gx, gy) == d

    def test_hilbert_consecutive_step_manhattan_distance(self) -> None:
        for order in range(1, 4):
            total_cells = 1 << (2 * order)
            for d in range(total_cells - 1):
                x1, y1 = d2xy(order, d)
                x2, y2 = d2xy(order, d + 1)
                dist = abs(x1 - x2) + abs(y1 - y2)
                assert dist == 1, f"Step distance != 1 at order={order}, d={d} -> d+1"

    def test_hilbert_order_bounds_rejection(self) -> None:
        with pytest.raises(ValueError, match="Hilbert curve order must be 1..8"):
            d2xy(0, 0)
        with pytest.raises(ValueError, match="Hilbert curve order must be 1..8"):
            d2xy(9, 0)
        with pytest.raises(ValueError, match="Hilbert curve order must be 1..8"):
            xy2d(0, 0, 0)
        with pytest.raises(ValueError, match="Hilbert curve order must be 1..8"):
            xy2d(9, 0, 0)

    def test_hilbert_coordinate_out_of_bounds_rejection(self) -> None:
        with pytest.raises(ValueError, match="out of bounds"):
            xy2d(2, 4, 2)  # Order 2 has N=4, max coordinate is 3
        with pytest.raises(ValueError, match="out of bounds"):
            xy2d(2, -1, 0)
        with pytest.raises(ValueError, match="out of bounds"):
            d2xy(2, 16)  # Order 2 has 16 cells, indices 0..15

    def test_morton_interleaving_and_deinterleaving_roundtrip(self) -> None:
        for x in range(32):
            for y in range(32):
                z = xy2z(x, y)
                rx, ry = z2xy(z)
                assert (rx, ry) == (x, y)

    def test_morton_order_bounded_wrappers(self) -> None:
        for order in [2, 3]:
            n = 1 << order
            for x in range(n):
                for y in range(n):
                    z = morton_xy2z(order, x, y)
                    rx, ry = morton_z2xy(order, z)
                    assert (rx, ry) == (x, y)

    def test_hilbert_range_to_2d_cells(self) -> None:
        cells = hilbert_range_to_2d_cells(2, 0, 3)
        assert len(cells) == 4
        assert cells[0] == (0, 0)
        assert cells[1] == (1, 0)
        assert cells[2] == (1, 1)
        assert cells[3] == (0, 1)

    def test_hilbert_color_at_t_endpoints(self) -> None:
        c0 = hilbert_color_at_t(0.0)
        c_mid1 = hilbert_color_at_t(0.333333)
        c_mid2 = hilbert_color_at_t(0.666667)
        c1 = hilbert_color_at_t(1.0)

        assert c0.startswith("#")
        assert len(c0) == 7
        assert c1.startswith("#")
        assert len(c1) == 7


# ============================================================================
# 3. Geometry & Spatial Object Tests
# ============================================================================

class TestHilbertGeometryAndObjects:
    def test_hilbert_rect_properties_and_containment(self) -> None:
        rect = HilbertRect(100.0, 150.0, 200.0, 100.0)
        assert rect.min_x == 100.0
        assert rect.min_y == 150.0
        assert rect.max_x == 300.0
        assert rect.max_y == 250.0
        assert rect.width == 200.0
        assert rect.height == 100.0
        assert rect.area == 20000.0

        assert rect.contains_coord(150.0, 200.0)
        assert not rect.contains_coord(50.0, 200.0)
        assert rect.contains_point((150.0, 200.0))

    def test_hilbert_rect_intersection(self) -> None:
        r1 = HilbertRect(100.0, 100.0, 200.0, 200.0)
        r2 = HilbertRect(250.0, 250.0, 100.0, 100.0)
        r3 = HilbertRect(400.0, 400.0, 50.0, 50.0)

        assert r1.intersects_rect(r2)
        assert not r1.intersects_rect(r3)

    def test_spatial_object_initialization(self) -> None:
        obj = SpatialObject(id=1, x=200.0, y=150.0, equip_type="pump")
        assert obj.id == 1
        assert obj.tag == "PUM-01"
        assert obj.hazard_radius == 25.0


# ============================================================================
# 4. Engine Core Logic, Queries & Hazard Detection Tests
# ============================================================================

class TestHilbertCanvasEngine:
    def test_engine_initialization_and_resolution(self) -> None:
        eng = HilbertCanvasEngine(order=3)
        assert eng.order == 3
        assert eng.grid_dimension == 8
        assert eng.total_cells == 64
        assert eng.active_segments_count == 63
        assert eng.viewport_width == 1200.0
        assert eng.viewport_height == 750.0
        assert eng.diagnostic_code == DIAG_OK
        assert eng.alarm_active is False

    def test_coordinate_mapping(self) -> None:
        eng = HilbertCanvasEngine(order=2, viewport_width=400.0, viewport_height=400.0)
        # N=4, cell_size = 100x100
        # point at (50, 50) -> grid (0, 0)
        gx, gy = eng.coord_to_grid(50.0, 50.0)
        assert (gx, gy) == (0, 0)
        assert eng.coord_to_hilbert(50.0, 50.0) == 0

        # grid (0, 0) -> center (50, 50)
        cx, cy = eng.grid_to_coord(0, 0)
        assert (cx, cy) == (50.0, 50.0)

    def test_insert_and_remove_object(self) -> None:
        eng = HilbertCanvasEngine(order=3)
        obj1 = eng.insert_object(200.0, 150.0, obj_id=1, equip_type="valve")
        assert obj1.id == 1
        assert len(eng.objects) == 1
        assert eng.primary_object_id == 1

        obj2 = eng.insert_object(400.0, 300.0, obj_id=2, equip_type="pump")
        assert len(eng.objects) == 2

        removed = eng.remove_object(1)
        assert removed is True
        assert len(eng.objects) == 1
        assert eng.primary_object_id == 2

    def test_dynamic_order_change_reindexing(self) -> None:
        eng = HilbertCanvasEngine(order=2)
        obj = eng.insert_object(100.0, 100.0, obj_id=1)
        h2 = obj.hilbert_index

        eng.set_order(4)
        assert eng.order == 4
        assert eng.grid_dimension == 16
        assert eng.total_cells == 256
        assert eng.active_segments_count == 255
        # Index changed according to finer order
        assert obj.hilbert_index != h2 or obj.grid_x != 0

    def test_range_query_hilbert(self) -> None:
        eng = HilbertCanvasEngine(order=3)
        eng.insert_object(100.0, 100.0, obj_id=1)
        eng.insert_object(300.0, 200.0, obj_id=2)
        eng.insert_object(800.0, 600.0, obj_id=3)

        matches = eng.query_range_hilbert(0, 63)
        assert len(matches) == 3

        comps = eng.hilbert_range_to_2d_components(0, 3)
        assert len(comps) == 4
        assert comps[0]["hilbert_index"] == 0

    def test_point_and_radius_queries(self) -> None:
        eng = HilbertCanvasEngine(order=3)
        eng.insert_object(200.0, 200.0, obj_id=1)
        eng.insert_object(210.0, 205.0, obj_id=2)
        eng.insert_object(900.0, 600.0, obj_id=3)

        near_pts = eng.query_point(200.0, 200.0, tolerance=20.0)
        assert len(near_pts) >= 1
        assert near_pts[0].id == 1

        rad_pts = eng.query_radius(200.0, 200.0, radius=50.0)
        assert len(rad_pts) == 2

    def test_proximity_hazard_detection_and_alarm(self) -> None:
        eng = HilbertCanvasEngine(order=3, hazard_threshold=50.0)
        # Objects placed 14 px apart (< 50 px threshold)
        eng.insert_object(300.0, 300.0, obj_id=1, hazard_radius=30.0)
        eng.insert_object(310.0, 310.0, obj_id=2, hazard_radius=30.0)

        hazards = eng.detect_hazards()
        assert len(hazards) >= 1
        assert eng.hazard_violations_count >= 1
        assert eng.alarm_active is True
        assert eng.diagnostic_code == DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD
        assert (eng.status_word & HilbertStatusBits.CONFLICT_DETECTED) != 0

        # Clear alarm
        eng.remove_object(2)
        eng.clear_alarm()
        assert eng.alarm_active is False
        assert eng.diagnostic_code == DIAG_OK
        assert (eng.status_word & HilbertStatusBits.CONFLICT_DETECTED) == 0

    def test_high_density_cluster_detection(self) -> None:
        eng = HilbertCanvasEngine(order=2)  # Coarse grid (4x4)
        # Place 3 objects in the exact same cell
        eng.insert_object(50.0, 50.0, obj_id=1, hazard_radius=5.0)
        eng.insert_object(60.0, 60.0, obj_id=2, hazard_radius=5.0)
        eng.insert_object(70.0, 70.0, obj_id=3, hazard_radius=5.0)

        hazards = eng.detect_hazards()
        cluster_hazards = [h for h in hazards if h.get("type") == "high_density_cluster"]
        assert len(cluster_hazards) >= 1
        assert (eng.status_word & HilbertStatusBits.HIGH_DENSITY) != 0


# ============================================================================
# 5. SVG Visual Grounding & WCAG 2.1 AAA Contrast Tests
# ============================================================================

class TestSvgGenerationAndWcagContrast:
    def test_contrast_ratio_calculation(self) -> None:
        # White text on black/very dark surface
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert ratio >= 18.0
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)

    def test_svg_generation_valid_xml_and_elements(self) -> None:
        eng = create_canonical_hilbert_canvas(sample_count=12, order=3, seed=42)
        eng.set_query_point(300.0, 200.0)
        svg_str = generate_hilbert_canvas_svg(eng)

        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg")
        assert "viewBox" in root.attrib
        assert "hilbert-curve-polyline" in svg_str
        assert "equipment-symbol" in svg_str
        assert "hud-telemetry-scorecard" in svg_str
        assert "hilbert-query-reticle" in svg_str


# ============================================================================
# 6. Horner OCS Register Table Synchronization Tests
# ============================================================================

class TestHornerOcsRegisterSync:
    def test_bit_exact_register_sync(self) -> None:
        eng = HilbertCanvasEngine(order=3)
        eng.insert_object(150.0, 200.0, obj_id=1, equip_type="valve")
        eng.insert_object(600.0, 400.0, obj_id=2, equip_type="tank")
        eng.set_query_point(500.0, 300.0)

        rt = RegisterTable()
        eng.sync_to_registers(rt)

        assert rt.read_word(REG_W306_TOTAL_OBJECTS) == 2
        assert rt.read_word(REG_W306_CURVE_ORDER) == 3
        assert rt.read_word(REG_W306_ACTIVE_SEGMENTS) == 63
        assert rt.read_word(REG_W306_PRIMARY_INDEX) == eng.primary_hilbert_index
        assert rt.read_word(REG_W306_QUERY_INDEX) == eng.query_point_index
        assert rt.read_word(REG_W306_HAZARD_VIOLATIONS) == eng.hazard_violations_count
        assert (rt.read_word(REG_W306_STATUS_WORD) & 0x0001) != 0
        assert (rt.read_word(REG_W306_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
        assert rt.read_bit(COIL_W306_CANVAS_ONLINE) is True
        assert rt.read_bit(COIL_W306_HAZARD_ALARM) is False

    def test_register_sync_under_alarm(self) -> None:
        eng = HilbertCanvasEngine(order=3, hazard_threshold=60.0)
        eng.insert_object(300.0, 300.0, obj_id=1, hazard_radius=40.0)
        eng.insert_object(310.0, 310.0, obj_id=2, hazard_radius=40.0)

        rt = RegisterTable()
        eng.sync_to_registers(rt)

        assert rt.read_word(REG_W306_HAZARD_VIOLATIONS) >= 1
        assert (rt.read_word(REG_W306_DIAGNOSTIC_CODE) & 0xFFFF) == 0x841B
        assert rt.read_bit(COIL_W306_HAZARD_ALARM) is True
        assert (rt.read_word(REG_W306_STATUS_WORD) & HilbertStatusBits.CONFLICT_DETECTED) != 0


# ============================================================================
# 7. Pure IEC 61131-3 Structured Text & Anti-Ladder Validation Tests
# ============================================================================

class TestPureSTAndSecurityRejection:
    def test_pure_st_pou_syntax_validation(self) -> None:
        assert verify_hilbert_canvas_pure_st() is True

        parser = STParser()
        res = parser.parse(ST_PROGRAM_W306_HILBERT_CANVAS_SYNC)
        assert res is not None
        assert res.pou_type == POUType.PROGRAM
        assert res.name == "HilbertCanvasSync"

    def test_ladder_contacts_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR x: BOOL; END_VAR ---[ ]--- END_PROGRAM")

    def test_ladder_coils_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR x: BOOL; END_VAR ---( )--- END_PROGRAM")

    def test_ladder_delimiters_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P RUNG 1: X := 1; END_PROGRAM")

    def test_ladder_mnemonics_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P XIC(Tag1) END_PROGRAM")


# ============================================================================
# 8. ILogicUnit Interface Compliance Tests
# ============================================================================

class TestILogicUnitCompliance:
    def test_ilogic_unit_properties(self) -> None:
        eng = HilbertCanvasEngine(order=3)
        assert isinstance(eng, ILogicUnit)
        assert eng.name == "HilbertCanvasEngine"
        assert eng.priority == 100
        assert eng.is_enabled is True

    def test_scan_step_with_args_and_kwargs(self) -> None:
        eng = HilbertCanvasEngine(order=3)
        eng.insert_object(200.0, 200.0, obj_id=1)
        res = eng.scan_step(None, dummy_arg=123)
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert eng.cycle_count == 1

    def test_step_and_execute(self) -> None:
        eng = HilbertCanvasEngine(order=3)
        eng.step()
        assert eng.cycle_count == 1
        res = eng.execute()
        assert res.status == AgentStatus.SUCCESS
        assert eng.cycle_count == 2

    def test_reset_restores_clean_state(self) -> None:
        eng = HilbertCanvasEngine(order=3)
        eng.insert_object(200.0, 200.0, obj_id=1)
        eng.inject_proximity_hazard_alarm()
        assert eng.alarm_active is True

        eng.reset()
        assert len(eng.objects) == 0
        assert eng.alarm_active is False
        assert eng.diagnostic_code == DIAG_OK
        assert eng.cycle_count == 0

    def test_simulation_scan_cycle_soak(self) -> None:
        eng = create_canonical_hilbert_canvas(sample_count=8, order=3, seed=123)
        ctx = ScanContext(cycle=0)

        for i in range(25):
            ctx.cycle = i
            res = eng.scan_step(ctx)
            assert res.status in (AgentStatus.SUCCESS, AgentStatus.FAILED)
        assert eng.cycle_count == 25


# ============================================================================
# 9. Deterministic 9-Stage Verification Suite Tests
# ============================================================================

class TestDeterministicVerificationRunner:
    def test_9_stage_verification_runner_execution(self) -> None:
        results = run_hilbert_canvas_verification()
        assert results["status"] == "success"
        assert results["error_code"] is None
        assert results["data"]["checks_passed"] == 9
        assert results["data"]["total_checks"] == 9
        assert len(results["data"]["stages"]) == 9
        for stg in results["data"]["stages"]:
            assert stg["passed"] is True

    def test_verification_runner_artifact_generation(self, tmp_path: Path) -> None:
        out_json = tmp_path / "hilbert_verification.json"
        out_svg = tmp_path / "hilbert_canvas.svg"

        results = run_hilbert_canvas_verification(
            output_path=out_json,
            sample_svg_path=out_svg,
        )
        assert results["status"] == "success"
        assert out_json.exists()
        assert out_svg.exists()

        data = json.loads(out_json.read_text(encoding="utf-8"))
        assert data["status"] == "success"
        assert "<svg" in out_svg.read_text(encoding="utf-8")


# ============================================================================
# 10. Key Requirements & Boundary Enforcement Verification Tests
# ============================================================================

class TestHilbertCanvasKeyRequirements:
    """Explicit tests addressing all W306 specification requirements."""

    def test_hilbert_xy2d_and_d2xy_inverse_roundtrips_orders_1_to_6(self) -> None:
        """Test Hilbert xy2d and d2xy inverse round-trips for orders 1..6."""
        for order in range(1, 7):
            total_cells = 1 << (2 * order)
            for d in range(total_cells):
                gx, gy = d2xy(order, d)
                d_rec = xy2d(order, gx, gy)
                assert d_rec == d, f"Order {order} inverse roundtrip failed at d={d}: got {d_rec}"
                gx_rec, gy_rec = d2xy(order, d_rec)
                assert (gx_rec, gy_rec) == (gx, gy)

    def test_morton_z_order_bit_interleaving_and_inverse(self) -> None:
        """Test Morton Z-order bit-interleaving and inverse."""
        for x in range(32):
            for y in range(32):
                z = xy2z(x, y)
                rx, ry = z2xy(z)
                assert (rx, ry) == (x, y)
                # Verify exact bit-interleaving logic: bit i of x -> 2*i, bit i of y -> 2*i + 1
                for i in range(5):
                    bit_x = (x >> i) & 1
                    bit_y = (y >> i) & 1
                    assert (z >> (2 * i)) & 1 == bit_x
                    assert (z >> (2 * i + 1)) & 1 == bit_y

        # Order-bounded morton calls
        for order in [1, 2, 3, 4, 5]:
            n = 1 << order
            for gx in range(n):
                for gy in range(n):
                    z = morton_xy2z(order, gx, gy)
                    rx, ry = morton_z2xy(order, z)
                    assert (rx, ry) == (gx, gy)

    def test_spatial_locality_metrics_and_1d_to_2d_neighborhood_preservation(self) -> None:
        """Test spatial locality metrics and 1D-to-2D neighborhood preservation."""
        eng = HilbertCanvasEngine(order=3)
        # Unit steps along curve strictly preserve 2D grid neighborhood
        for d in range(eng.total_cells - 1):
            x1, y1 = d2xy(eng.order, d)
            x2, y2 = d2xy(eng.order, d + 1)
            manhattan = abs(x1 - x2) + abs(y1 - y2)
            assert manhattan == 1, f"Neighborhood broken between d={d} and d={d+1}"

        # Locality preservation ratio: Hölder condition D_2D / sqrt(Delta_1D) <= 3.0
        import random
        rng = random.Random(999)
        for order in [2, 3, 4]:
            cells = 1 << (2 * order)
            for _ in range(40):
                d1 = rng.randint(0, cells - 1)
                d2 = rng.randint(0, cells - 1)
                if d1 == d2:
                    continue
                gx1, gy1 = d2xy(order, d1)
                gx2, gy2 = d2xy(order, d2)
                d_2d = math.hypot(gx2 - gx1, gy2 - gy1)
                delta_1d = abs(d1 - d2)
                assert d_2d / math.sqrt(delta_1d) <= 3.0

    def test_proximity_hazard_detection_m624_and_diagnostic_code_841b(self) -> None:
        """Test proximity hazard detection (%M624, diagnostic code 0x841B)."""
        eng = HilbertCanvasEngine(order=3, hazard_threshold=50.0)
        # Insert two objects very close to each other (10 px apart, threshold 50 px)
        eng.insert_object(400.0, 300.0, obj_id=1, hazard_radius=25.0)
        eng.insert_object(410.0, 300.0, obj_id=2, hazard_radius=25.0)

        hazards = eng.detect_hazards()
        assert len(hazards) >= 1
        assert eng.hazard_violations_count >= 1
        assert eng.alarm_active is True
        assert (int(eng.diagnostic_code) & 0xFFFF) == 0x841B
        assert eng.diagnostic_code == DIAG_ERR_SPATIAL_HILBERT_PROXIMITY_HAZARD

        rt = RegisterTable()
        eng.sync_to_registers(rt)
        # Verify discrete coil %M624 trips
        assert rt.read_bit("%M624") is True
        assert rt.read_bit(COIL_W306_HAZARD_ALARM) is True
        # Verify diagnostic register %R2677 matches 0x841B
        assert (rt.read_word("%R2677") & 0xFFFF) == 0x841B
        assert (rt.read_word(REG_W306_DIAGNOSTIC_CODE) & 0xFFFF) == 0x841B

    def test_svg_1_1_generation_polyline_paths_and_wcag_aaa_contrast(self) -> None:
        """Test SVG 1.1 generation, valid XML, polyline paths, element styling, and WCAG AAA contrast ratio calculation."""
        eng = create_canonical_hilbert_canvas(sample_count=10, order=3, seed=77)
        eng.insert_object(250.0, 250.0, obj_id=99, equip_type="valve")
        eng.set_query_point(250.0, 250.0)

        svg = generate_hilbert_canvas_svg(eng)
        root = ET.fromstring(svg)
        assert root.tag.endswith("svg")
        assert root.attrib.get("version") == "1.1"

        # Polyline path check
        polylines = [e for e in root.iter() if e.tag.endswith("polyline")]
        assert len(polylines) > 0
        poly = polylines[0]
        assert "points" in poly.attrib
        assert len(poly.attrib["points"].split()) > 10

        # Element styling checks
        assert "url(#hilbert-gradient)" in svg or "stroke=" in svg
        assert "class=" in svg
        assert "equipment-symbol" in svg
        assert "hud-telemetry-scorecard" in svg

        # WCAG 2.1 AAA contrast ratio (> 18:1)
        cr = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert cr >= 18.0
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, target_ratio=18.0)

    def test_ilogicunit_interface_methods_full_contract(self) -> None:
        """Test ILogicUnit interface methods (scan_step with args/kwargs, step, execute, reset)."""
        eng = HilbertCanvasEngine(order=3)
        assert isinstance(eng, ILogicUnit)
        assert eng.name == "HilbertCanvasEngine"
        assert eng.priority == 100
        assert eng.is_enabled is True

        # scan_step with args/kwargs
        res_scan = eng.scan_step(None, 42, "extra_arg", param="debug_value")
        assert isinstance(res_scan, ExecutionResult)
        assert res_scan.status == AgentStatus.SUCCESS
        assert eng.cycle_count == 1

        # step with args/kwargs
        eng.step("step_arg", kwarg_key="val")
        assert eng.cycle_count == 2

        # execute with args/kwargs
        res_exec = eng.execute(None, flag=True)
        assert isinstance(res_exec, ExecutionResult)
        assert res_exec.status == AgentStatus.SUCCESS
        assert eng.cycle_count == 3

        # reset
        eng.insert_object(300.0, 300.0, obj_id=1)
        eng.inject_proximity_hazard_alarm()
        assert eng.alarm_active is True
        eng.reset()
        assert eng.cycle_count == 0
        assert len(eng.objects) == 0
        assert eng.alarm_active is False
        assert eng.diagnostic_code == DIAG_OK

    def test_horner_register_table_signed_16bit_masking(self) -> None:
        """Test Horner RegisterTable sync with signed 16-bit masking (rt.read_word(...) & 0xFFFF) == expected."""
        eng = HilbertCanvasEngine(order=4)
        rt = RegisterTable()

        # Check positive and negative 16-bit masking
        test_values = [
            ("%R2670", 128, 128),
            ("%R2671", 4, 4),
            ("%R2677", 0x841B, 0x841B),
            ("%R2677", 0x0000, 0x0000),
            ("%R2677", -1, 0xFFFF),
            ("%R2677", -32768, 0x8000),
            ("%R2675", 65535, 0xFFFF),
        ]
        for reg, val, expected in test_values:
            rt.write_word(reg, val & 0xFFFF)
            assert (rt.read_word(reg) & 0xFFFF) == expected

        # Engine sync masking
        eng.sync_to_registers(rt)
        assert (rt.read_word(REG_W306_CURVE_ORDER) & 0xFFFF) == 4
        assert (rt.read_word(REG_W306_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

    def test_pure_st_pou_parsing_and_ladder_forbidden_rejection(self) -> None:
        """Test pure ST POU parsing with STParser and LadderForbiddenError on ladder contacts/coils."""
        assert verify_hilbert_canvas_pure_st() is True
        parser = STParser()
        ast = parser.parse(ST_PROGRAM_W306_HILBERT_CANVAS_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "HilbertCanvasSync"

        # Reject ladder contacts
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test ---[ ]--- END_PROGRAM")

        # Reject ladder coils
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test ---( )--- END_PROGRAM")

        # Reject ladder rungs
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test RUNG 1: X := 1; END_PROGRAM")

        # Reject ladder mnemonics
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Test XIC Tag1; END_PROGRAM")

    def test_run_hilbert_canvas_verification_all_9_stages_clean(self) -> None:
        """Test run_hilbert_canvas_verification() passing all 9 stages."""
        res = run_hilbert_canvas_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["stages"]) == 9
        for stage in res["data"]["stages"]:
            assert stage["passed"] is True
