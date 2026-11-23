"""Comprehensive Unit Test Suite for Cscape HMI Dynamic Spatial Centroidal Voronoi Tessellation (CVT) SCADA Canvas (W285).

Work Package: W285 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: TEST_SUITE [Centroidal Voronoi Tessellation Lloyd Relaxation SCADA Canvas]
Coverage:
- Constants, Diagnostic Codes, Status Bits, and Geometry Helpers
- Point2D, Polygon2D, Sutherland-Hodgman Polygon Clipping, and Shoelace Area
- Analytical Green's Theorem Centroid Integration & Energy Calculation
- GeneratorSite, CVTCell, and CvtMetrics Dataclasses
- CVTCanvasEngine Lloyd's Relaxation Iterations and Convergence
- Monotonic Gersho CVT Energy Functional Decrease
- Site Drift & Partition Discontinuity Alarm Detection (%M575 / 0x8205)
- Degenerate Site Configurations (< 3 sites)
- Standalone W3C SVG 1.1 Generation & WCAG 2.1 AAA Contrast Compliance
- Horner OCS Register Space Synchronization (%R2460..%R2467, %M574..%M575)
- Pure IEC 61131-3 Structured Text POU Syntax & Anti-Ladder Security Guard Validation
- ILogicUnit Lifecycle Compliance (scan_step, lloyd_step, reset)
- Deterministic 9-Stage Verification Suite Runner
"""

from __future__ import annotations

import math
from pathlib import Path
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.cvt_canvas import (
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COLOR_SCADA_BG,
    COLOR_TEXT_PRIMARY,
    COLOR_DECOUPLED_BADGE,
    COLOR_TEXT_MUTED,
    CVTCanvas,
    CVTCanvasEngine,
    CVTCell,
    CVTStatusBits,
    CvtCell,
    CvtDiagnosticCode,
    CvtMetrics,
    DiagnosticCode,
    DIAG_ERR_DEGENERATE_GEOMETRY,
    DIAG_ERR_SITE_DRIFT_DISCONTINUITY,
    DIAG_OK,
    GeneratorSite,
    Point2D,
    Polygon2D,
    REG_W285_AREA_RESIDUAL,
    REG_W285_CONVERGENCE_ENERGY,
    REG_W285_DIAGNOSTIC_CODE,
    REG_W285_ENERGY_FUNCTIONAL,
    REG_W285_ITERATION_COUNT,
    REG_W285_LLOYD_ITERATION,
    REG_W285_MAX_CENTROID_SHIFT,
    REG_W285_MAX_SHIFT,
    REG_W285_MEAN_AREA,
    REG_W285_MEAN_CENTROID_SHIFT,
    REG_W285_SELECTED_PARTITION,
    REG_W285_SITE_COUNT,
    REG_W285_STATUS_WORD,
    REG_W285_UNIFORMITY_INDEX,
    COIL_W285_CANVAS_ACTIVE,
    COIL_W285_CONVERGENCE_REACHED,
    COIL_W285_DRIFT_ALARM,
    COIL_W285_SITE_DRIFT_ALARM,
    ST_PROGRAM_CVT_CANVAS_SYNC,
    TOTAL_DOMAIN_AREA,
    calculate_polygon_cvt_energy,
    calculate_contrast_ratio,
    validate_wcag_aaa_contrast,
    clip_polygon_halfplane,
    compute_polygon_centroid_and_area,
    compute_polygon_second_moment,
    create_canonical_domain_rect,
    create_canonical_generator_sites,
    create_canonical_sites,
    generate_cvt_canvas_svg,
    run_cvt_canvas_verification,
    verify_cvt_canvas_pure_st,
)
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import RegisterTable


# ============================================================================
# 1. Constants, Diagnostic Codes & Status Bits
# ============================================================================

class TestConstantsAndDiagnostics:
    def test_domain_geometry_constants(self):
        assert CANVAS_VIEWPORT_WIDTH == 1200.0
        assert CANVAS_VIEWPORT_HEIGHT == 750.0
        assert TOTAL_DOMAIN_AREA == 900000.0

    def test_diagnostic_codes_equality(self):
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_SITE_DRIFT_DISCONTINUITY == 0x8205
        assert DIAG_ERR_DEGENERATE_GEOMETRY == 0x8202

        # Test signed vs unsigned 16-bit representation
        val_drift = int(DIAG_ERR_SITE_DRIFT_DISCONTINUITY)
        assert val_drift == 0x8205
        assert DIAG_ERR_SITE_DRIFT_DISCONTINUITY == -32251
        assert hash(DIAG_ERR_SITE_DRIFT_DISCONTINUITY) == hash(0x8205)

    def test_cvt_status_bits(self):
        assert CVTStatusBits.CANVAS_ACTIVE == 1 << 0
        assert CVTStatusBits.CVT_COMPUTED == 1 << 1
        assert CVTStatusBits.CVT_CONVERGED == 1 << 2
        assert CVTStatusBits.DRIFT_DISCONTINUITY_ALARM == 1 << 3
        assert CVTStatusBits.DEGENERATE_FAULT == 1 << 4
        assert CVTStatusBits.SVG_RENDER_VALID == 1 << 5
        assert CVTStatusBits.ENERGY_MONOTONIC_VALID == 1 << 6

    def test_register_and_coil_addresses(self):
        assert REG_W285_STATUS_WORD == "%R2460"
        assert REG_W285_SITE_COUNT == "%R2461"
        assert REG_W285_LLOYD_ITERATION == "%R2462"
        assert REG_W285_MAX_CENTROID_SHIFT == "%R2463"
        assert REG_W285_MEAN_CENTROID_SHIFT == "%R2464"
        assert REG_W285_ENERGY_FUNCTIONAL == "%R2465"
        assert REG_W285_AREA_RESIDUAL == "%R2466"
        assert REG_W285_DIAGNOSTIC_CODE == "%R2467"

        assert COIL_W285_CANVAS_ACTIVE == "%M574"
        assert COIL_W285_DRIFT_ALARM == "%M575"


# ============================================================================
# 2. Point2D, Polygon2D and Spatial Geometry Primitives
# ============================================================================

class TestSpatialGeometryPrimitives:
    def test_point2d_operations(self):
        p1 = Point2D(10.0, 20.0, point_id=1)
        p2 = Point2D(13.0, 24.0, point_id=2)
        assert p1.distance_to(p2) == pytest.approx(5.0, abs=1e-6)
        assert p1.coords == (10.0, 20.0)

    def test_polygon2d_shoelace_area_and_centroid(self):
        rect = Polygon2D([
            Point2D(0.0, 0.0),
            Point2D(100.0, 0.0),
            Point2D(100.0, 50.0),
            Point2D(0.0, 50.0),
        ])
        area = rect.shoelace_area()
        assert area == pytest.approx(5000.0, abs=1e-6)

        c = rect.centroid()
        assert c.x == pytest.approx(50.0, abs=1e-6)
        assert c.y == pytest.approx(25.0, abs=1e-6)

    def test_sutherland_hodgman_halfplane_clip(self):
        rect = Polygon2D([
            Point2D(0.0, 0.0),
            Point2D(100.0, 0.0),
            Point2D(100.0, 100.0),
            Point2D(0.0, 100.0),
        ])
        clipped = rect.clip_halfplane(Point2D(50.0, 50.0), Point2D(1.0, 0.0))
        assert clipped.shoelace_area() == pytest.approx(5000.0, abs=1e-4)
        for v in clipped.vertices:
            assert v.x <= 50.0001

    def test_compute_polygon_helpers(self):
        coords = [(0.0, 0.0), (100.0, 0.0), (100.0, 50.0), (0.0, 50.0)]
        cent, area = compute_polygon_centroid_and_area(coords)
        assert area == pytest.approx(5000.0, abs=1e-6)
        assert cent == pytest.approx((50.0, 25.0), abs=1e-6)

        moment = compute_polygon_second_moment(coords, Point2D(50.0, 25.0))
        assert moment > 0.0


# ============================================================================
# 3. Canonical Setup & Generator Sites
# ============================================================================

class TestCanonicalSetup:
    def test_canonical_sites_count_and_bounds(self):
        sites = create_canonical_generator_sites()
        assert len(sites) == 12
        for s in sites:
            assert 0.0 <= s.pos.x <= CANVAS_VIEWPORT_WIDTH
            assert 0.0 <= s.pos.y <= CANVAS_VIEWPORT_HEIGHT
            assert s.id >= 1
            assert len(s.tag) > 0

    def test_canonical_domain_rect(self):
        domain = create_canonical_domain_rect()
        assert len(domain.vertices) == 4
        assert domain.shoelace_area() == pytest.approx(TOTAL_DOMAIN_AREA, abs=1e-6)


# ============================================================================
# 4. CVT Engine, Lloyd's Relaxation & Monotonic Energy
# ============================================================================

class TestCVTEngineRelaxation:
    def test_initial_cell_generation(self):
        engine = CVTCanvasEngine()
        assert len(engine.cells) == 12

        total_cell_area = sum(c.area for c in engine.cells.values())
        assert total_cell_area == pytest.approx(TOTAL_DOMAIN_AREA, rel=1e-4)

    def test_lloyd_relaxation_step_reduces_max_shift(self):
        engine = CVTCanvasEngine()
        initial_shift = engine.lloyd_step()
        assert initial_shift > 0.0

        shifts = [initial_shift]
        for _ in range(5):
            shifts.append(engine.lloyd_step())

        assert shifts[-1] < shifts[0]
        assert engine.lloyd_iteration == 6

    def test_gersho_energy_monotonic_decrease(self):
        engine = CVTCanvasEngine()
        initial_energy = engine.total_energy

        energies = [initial_energy]
        for _ in range(5):
            engine.lloyd_step()
            energies.append(engine.total_energy)

        # Gersho energy should be monotonically non-increasing
        for i in range(len(energies) - 1):
            assert energies[i+1] <= energies[i] * 1.0001

    def test_relaxation_convergence_termination(self):
        engine = CVTCanvasEngine(convergence_tolerance=20.0, max_iterations=50)
        diag = engine.relax_until_converged()
        assert engine.lloyd_iteration <= 50
        assert engine.max_centroid_shift <= 20.0 or engine.lloyd_iteration == 50


# ============================================================================
# 5. Site Drift & Disruption Detection
# ============================================================================

class TestSiteDriftDetection:
    def test_site_disruption_triggers_alarm(self):
        engine = CVTCanvasEngine(drift_threshold=75.0)
        for _ in range(5):
            engine.lloyd_step()

        # Force a large disruption on site 4
        engine.inject_site_disruption(site_id=4, offset_x=220.0, offset_y=-160.0)

        assert engine.drift_alarm is True
        assert engine.diagnostic_code == DIAG_ERR_SITE_DRIFT_DISCONTINUITY

        reg_table = RegisterTable()
        engine.sync_to_registers(reg_table)
        assert reg_table.read_bit("%M575") is True
        assert (reg_table.read_word("%R2467") & 0xFFFF) == 0x8205

        # Clear disruption
        engine.clear_site_disruption(site_id=4)
        assert engine.drift_alarm is False
        assert engine.diagnostic_code == DIAG_OK


# ============================================================================
# 6. Degenerate Geometry Handling
# ============================================================================

class TestDegenerateGeometry:
    def test_insufficient_sites_handling(self):
        few_sites = [
            GeneratorSite(1, "S1", Point2D(100.0, 300.0), Point2D(100.0, 300.0)),
            GeneratorSite(2, "S2", Point2D(300.0, 300.0), Point2D(300.0, 300.0)),
        ]
        engine = CVTCanvasEngine(sites=few_sites)
        assert engine.degenerate_geometry is True
        assert engine.diagnostic_code == DIAG_ERR_DEGENERATE_GEOMETRY


# ============================================================================
# 7. Standalone W3C SVG 1.1 Vector Rendering & WCAG 2.1 AAA
# ============================================================================

class TestSVGRenderingAndWCAG:
    def test_svg_generation_valid_xml(self):
        engine = CVTCanvasEngine()
        for _ in range(3):
            engine.lloyd_step()
        svg_str = generate_cvt_canvas_svg(engine)

        assert "<svg" in svg_str
        assert "</svg>" in svg_str
        assert f'viewBox="0 0 {int(CANVAS_VIEWPORT_WIDTH)} {int(CANVAS_VIEWPORT_HEIGHT)}"' in svg_str

        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg")

    def test_wcag_contrast_dark_theme(self):
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert ratio >= 18.0

        val = validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, min_contrast=18.0)
        assert val.is_compliant is True


# ============================================================================
# 8. Horner OCS Memory Space Register Synchronization
# ============================================================================

class TestRegisterTableSynchronization:
    def test_register_sync_nominal(self):
        engine = CVTCanvasEngine()
        for _ in range(5):
            engine.lloyd_step()

        table = RegisterTable()
        engine.sync_to_registers(table)

        assert table.read_bit("%M574") is True
        assert table.read_bit("%M575") is False

        assert table.read_word("%R2461") == 12  # Site count
        assert table.read_word("%R2462") == 5   # Iteration count
        assert (table.read_word("%R2467") & 0xFFFF) == 0x0000

    def test_register_sync_on_drift(self):
        engine = CVTCanvasEngine(drift_threshold=75.0)
        for _ in range(3):
            engine.lloyd_step()
        engine.inject_site_disruption(site_id=2, offset_x=200.0, offset_y=-150.0)

        table = RegisterTable()
        engine.sync_to_registers(table)

        assert table.read_bit("%M575") is True
        assert (table.read_word("%R2467") & 0xFFFF) == 0x8205


# ============================================================================
# 9. Pure IEC 61131-3 Structured Text & Anti-Ladder Guard
# ============================================================================

class TestPureSTAndLadderRejection:
    def test_pure_st_pou_valid(self):
        assert verify_cvt_canvas_pure_st() is True

    def test_forbidden_ladder_constructs_rejected(self):
        ladder_snippets = [
            "PROGRAM Test RUNG 1 ---[ ]--- %I001 ---( )--- %Q001; END_PROGRAM",
            "PROGRAM Test XIC(%I001) OTE(%Q001); END_PROGRAM",
            "PROGRAM Test NETWORK 1: LD %I001 ST %Q001; END_PROGRAM",
        ]
        for snip in ladder_snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snip)


# ============================================================================
# 10. ILogicUnit Lifecycle Compliance
# ============================================================================

class TestILogicUnitCompliance:
    def test_scan_step(self):
        engine = CVTCanvasEngine()
        res = engine.scan_step()
        assert res["cycle"] == 1
        assert res["sites"] == 12

    def test_metrics_properties(self):
        engine = CVTCanvasEngine()
        metrics = engine.metrics
        assert metrics.site_count == 12
        assert metrics.mean_cell_area > 0.0


# ============================================================================
# 11. Deterministic 9-Stage Verification Suite Runner
# ============================================================================

class TestVerificationSuiteRunner:
    def test_run_cvt_canvas_verification_passes_all_stages(self):
        res = run_cvt_canvas_verification()
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
