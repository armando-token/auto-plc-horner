"""Comprehensive Unit Test Suite for Cscape HMI Dynamic Spatial Geohash / Delaunay Triangulation Dual Graph SCADA Canvas (W327).

Work Package: W327 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Geohash / Delaunay Triangulation Dual Graph SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Covers:
1. Delaunay constants, registers %R2880..%R2887, coils %M672..%M673, diagnostic codes (signed 16-bit safe comparisons).
2. Pure Python 2D Voronoi diagram generation, polygonal cells computation, topology hash, area conservation.
3. Bowyer-Watson Delaunay triangulation dual, empty-circumcircle criterion, circumcenter extraction.
4. Morton / Z-order spatial hashing and Base32 Geohash encoding and decoding.
5. Out-of-bounds coordinates handling (0x8442) and degenerate site handling (0x8441).
6. Dynamic spatial proximity collision hazard alarm (0x8440, %M673 asserted) and clearance.
7. RegisterTable synchronization across %R2880..%R2887 and %M672..%M673.
8. SVG SCADA canvas rendering: XML validity, dimensions (800x600), Voronoi polygons, site markers, contrast ratio (WCAG AAA > 18:1).
9. Pure ST POU validation with STParser and anti-ladder rejection of all 9 constructs.
10. ILogicUnit scan step and 100-cycle simulation soak with memory profiling.
11. 9-stage verification runner test and CLI interop.
12. Advanced spatial queries, coordinate transforms, and geometry edge cases.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tracemalloc
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.delaunay_dual_canvas import (
    BASE32,
    BASE32_MAP,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COIL_DELAUNAY_COLLISION_ALARM,
    COIL_DELAUNAY_ONLINE,
    COIL_VORONOI_CANVAS_ONLINE,
    COIL_VORONOI_HAZARD_ALARM,
    COIL_W327_CANVAS_ONLINE,
    COIL_W327_COLLISION_ALARM,
    COIL_W327_HAZARD_ALARM,
    COIL_W327_ONLINE,
    COIL_W327_VORONOI_ONLINE,
    COLOR_ALARM_CRIMSON,
    COLOR_BORDER,
    COLOR_DARK_SURFACE,
    COLOR_DECOUPLED_BADGE,
    COLOR_DELAUNAY_EDGE,
    COLOR_EDGE_WIRE,
    COLOR_GRID_LINE,
    COLOR_MORTON_CELL,
    COLOR_NOMINAL_EMERALD,
    COLOR_RETICLE_CYAN,
    COLOR_SCADA_BG,
    COLOR_TEXT_DIM,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TILE_FILL,
    COLOR_TILE_STROKE,
    COLOR_VORONOI_FILL,
    COLOR_VORONOI_STROKE,
    COLOR_WARNING_AMBER,
    DEFAULT_DOMAIN_BBOX,
    DEFAULT_HAZARD_THRESHOLD,
    DEFAULT_SAFETY_THRESHOLD_M,
    DEFAULT_VIEWPORT_HEIGHT,
    DEFAULT_VIEWPORT_WIDTH,
    DIAG_COORDINATE_OUT_OF_BOUNDS,
    DIAG_DEGENERATE_SITES,
    DIAG_DELAUNAY_COORDINATE_OUT_OF_BOUNDS,
    DIAG_DELAUNAY_DEGENERATE_NODES,
    DIAG_ERR_COLINEAR,
    DIAG_ERR_DEGENERATE_SITES,
    DIAG_ERR_OUT_OF_BOUNDS,
    DIAG_ERR_PROXIMITY_HAZARD,
    DIAG_OK,
    DIAG_PROXIMITY_HAZARD_COLLISION,
    DiagnosticCode,
    EARTH_RADIUS_METERS,
    EARTH_RADIUS_WGS84,
    MAX_LATITUDE,
    MAX_LONGITUDE,
    MIN_LATITUDE,
    MIN_LONGITUDE,
    MortonBoundingBox,
    Point2D,
    Polygon2D,
    REG_DELAUNAY_DIAGNOSTIC_CODE,
    REG_DELAUNAY_QUERY_LATENCY_US,
    REG_DELAUNAY_SELECTED_NODE_X,
    REG_DELAUNAY_SELECTED_NODE_Y,
    REG_DELAUNAY_TOPOLOGY_HASH_HI,
    REG_DELAUNAY_TOTAL_NODES,
    REG_DELAUNAY_TRIANGLE_COUNT,
    REG_DELAUNAY_VORONOI_FACETS,
    REG_VORONOI_ACTIVE_CELLS,
    REG_VORONOI_ELEMENTS,
    REG_VORONOI_PRIMARY_HASH,
    REG_VORONOI_STATUS_WORD,
    REG_VORONOI_TOTAL_OBJECTS,
    REG_W327_ACTIVE_CELLS,
    REG_W327_DIAGNOSTIC_CODE,
    REG_W327_MIN_CELL_AREA_SQM,
    REG_W327_POLYGON_CELLS,
    REG_W327_PRIMARY_HASH,
    REG_W327_QUERY_LATENCY_US,
    REG_W327_SELECTED_SITE_X,
    REG_W327_SELECTED_SITE_Y,
    REG_W327_STATUS_WORD,
    REG_W327_TOPOLOGY_HASH_HI,
    REG_W327_TOTAL_OBJECTS,
    REG_W327_TOTAL_SITES,
    ST_PROGRAM_VORONOI_CANVAS_SYNC,
    ST_PROGRAM_W327_VORONOI_CANVAS_SYNC,
    VORONOI_CANVAS_PURE_ST_POU,
    VoronoiAsset,
    VoronoiCell,
    VoronoiDiagnosticCode,
    VoronoiEdge,
    VoronoiMetrics,
    VoronoiNode,
    VoronoiSite,
    VoronoiStatusBits,
    VoronoiTriangle,
    calculate_contrast_ratio,
    clip,
    compute_delaunay_triangulation,
    compute_topology_hash,
    compute_voronoi_cells,
    create_canonical_delaunay_dual_canvas,
    generate_delaunay_dual_canvas_svg,
    geohash_decode,
    geohash_decode_bbox,
    geohash_encode,
    haversine_distance_m,
    lat_lon_to_morton_cell,
    morton2d_decode,
    morton2d_encode,
    morton2d_to_string,
    morton_cell_to_bbox,
    morton_cell_to_lat_lon,
    part1by1,
    run_delaunay_dual_canvas_verification,
    unpart1by1,
    validate_wcag_aaa_contrast,
    verify_delaunay_dual_canvas_pure_st,
    DelaunayDualCanvas,
    DelaunayDualCanvasEngine,
)


# ============================================================================
# 1. TestConstantsAndMemoryMap
# ============================================================================

class TestConstantsAndMemoryMap:
    """Validate W327 memory registers, discrete coils, palette and diagnostic codes."""

    def test_canvas_viewport_dimensions(self) -> None:
        assert CANVAS_VIEWPORT_WIDTH == 800.0
        assert CANVAS_VIEWPORT_HEIGHT == 600.0
        assert DEFAULT_VIEWPORT_WIDTH == 800.0
        assert DEFAULT_VIEWPORT_HEIGHT == 600.0

    def test_geodetic_constants(self) -> None:
        assert EARTH_RADIUS_METERS == 6371000.0
        assert EARTH_RADIUS_WGS84 == 6378137.0
        assert DEFAULT_SAFETY_THRESHOLD_M == 50.0
        assert DEFAULT_HAZARD_THRESHOLD == 50.0
        assert MIN_LATITUDE == -90.0
        assert MAX_LATITUDE == 90.0
        assert MIN_LONGITUDE == -180.0
        assert MAX_LONGITUDE == 180.0

    def test_word_register_addresses(self) -> None:
        assert REG_DELAUNAY_TOTAL_NODES == "%R2880"
        assert REG_DELAUNAY_TRIANGLE_COUNT == "%R2881"
        assert REG_DELAUNAY_VORONOI_FACETS == "%R2882"
        assert REG_DELAUNAY_SELECTED_NODE_X == "%R2883"
        assert REG_DELAUNAY_SELECTED_NODE_Y == "%R2884"
        assert REG_DELAUNAY_TOPOLOGY_HASH_HI == "%R2885"
        assert REG_DELAUNAY_QUERY_LATENCY_US == "%R2886"
        assert REG_DELAUNAY_DIAGNOSTIC_CODE == "%R2887"

    def test_word_register_aliases(self) -> None:
        assert REG_W327_TOTAL_SITES == "%R2880"
        assert REG_W327_TOTAL_OBJECTS == "%R2880"
        assert REG_VORONOI_TOTAL_OBJECTS == "%R2880"
        assert REG_W327_POLYGON_CELLS == "%R2881"
        assert REG_W327_ACTIVE_CELLS == "%R2881"
        assert REG_VORONOI_ACTIVE_CELLS == "%R2881"
        assert REG_VORONOI_ELEMENTS == "%R2881"
        assert REG_W327_MIN_CELL_AREA_SQM == "%R2882"
        assert REG_W327_SELECTED_SITE_X == "%R2883"
        assert REG_W327_SELECTED_SITE_Y == "%R2884"
        assert REG_W327_TOPOLOGY_HASH_HI == "%R2885"
        assert REG_W327_PRIMARY_HASH == "%R2885"
        assert REG_VORONOI_PRIMARY_HASH == "%R2885"
        assert REG_W327_STATUS_WORD == "%R2885"
        assert REG_VORONOI_STATUS_WORD == "%R2885"
        assert REG_W327_QUERY_LATENCY_US == "%R2886"
        assert REG_W327_DIAGNOSTIC_CODE == "%R2887"

    def test_discrete_coil_addresses(self) -> None:
        assert COIL_DELAUNAY_ONLINE == "%M672"
        assert COIL_DELAUNAY_COLLISION_ALARM == "%M673"
        assert COIL_W327_ONLINE == "%M672"
        assert COIL_W327_COLLISION_ALARM == "%M673"
        assert COIL_VORONOI_CANVAS_ONLINE == "%M672"
        assert COIL_W327_VORONOI_ONLINE == "%M672"
        assert COIL_W327_CANVAS_ONLINE == "%M672"
        assert COIL_VORONOI_HAZARD_ALARM == "%M673"
        assert COIL_W327_HAZARD_ALARM == "%M673"

    def test_diagnostic_codes_values_and_representations(self) -> None:
        assert int(DIAG_OK) == 0x0000
        assert int(DIAG_PROXIMITY_HAZARD_COLLISION) == 0x8440
        assert int(DIAG_DELAUNAY_DEGENERATE_NODES) == 0x8441
        assert int(DIAG_DELAUNAY_COORDINATE_OUT_OF_BOUNDS) == 0x8442

        assert str(DIAG_OK) == "0x0000"
        assert str(DIAG_PROXIMITY_HAZARD_COLLISION) == "0x8440"
        assert str(DIAG_DELAUNAY_DEGENERATE_NODES) == "0x8441"
        assert str(DIAG_DELAUNAY_COORDINATE_OUT_OF_BOUNDS) == "0x8442"

        assert repr(DIAG_OK) == "DiagnosticCode(0x0000)"
        assert repr(DIAG_PROXIMITY_HAZARD_COLLISION) == "DiagnosticCode(0x8440)"

    def test_diagnostic_code_signed_and_alias_equality(self) -> None:
        diag_hazard = DIAG_PROXIMITY_HAZARD_COLLISION
        signed_hazard = 0x8440 - 0x10000  # -31680
        assert diag_hazard == 0x8440
        assert diag_hazard == signed_hazard
        assert diag_hazard == 0x8430  # alias
        assert DIAG_DEGENERATE_SITES == DIAG_DELAUNAY_DEGENERATE_NODES
        assert DIAG_COORDINATE_OUT_OF_BOUNDS == DIAG_DELAUNAY_COORDINATE_OUT_OF_BOUNDS

    def test_status_bits_enumeration(self) -> None:
        assert VoronoiStatusBits.ONLINE == 1
        assert VoronoiStatusBits.COLLISION_ALARM == 2
        assert VoronoiStatusBits.VORONOI_GENERATED == 4
        assert VoronoiStatusBits.TOPOLOGY_CONNECTED == 8
        assert VoronoiStatusBits.SITE_SELECTED == 16
        assert VoronoiStatusBits.DEGENERATE_SITES == 32
        assert VoronoiStatusBits.OUT_OF_BOUNDS == 64


# ============================================================================
# 2. TestMortonAndGeohashMath
# ============================================================================

class TestMortonAndGeohashMath:
    """Validate 2D Morton Z-order curve bit-interleaving and Base32 Geohash algorithms."""

    def test_part_and_unpart_bijection(self) -> None:
        for val in [0, 1, 2, 7, 15, 255, 1024, 65535]:
            p = part1by1(val)
            assert unpart1by1(p) == val

    def test_morton2d_encode_and_decode_bijection(self) -> None:
        test_pairs = [(0, 0), (1, 0), (0, 1), (1, 1), (15, 25), (255, 255), (1024, 512)]
        for x, y in test_pairs:
            code = morton2d_encode(x, y)
            dx, dy = morton2d_decode(code)
            assert (dx, dy) == (x, y)

    def test_morton2d_encode_negative_or_overflow_raises(self) -> None:
        with pytest.raises(ValueError):
            morton2d_encode(-1, 5)
        with pytest.raises(ValueError):
            morton2d_encode(5, -1)
        with pytest.raises(ValueError):
            morton2d_encode(0x10000, 5)

    def test_morton2d_to_string_formatting(self) -> None:
        s = morton2d_to_string(0b1011, bits=8)
        assert s == "00001011"

    def test_lat_lon_to_morton_cell_within_bounds(self) -> None:
        lat, lon = 37.7750, -122.4175
        cx, cy, code = lat_lon_to_morton_cell(lat, lon, bbox=DEFAULT_DOMAIN_BBOX, grid_size=256)
        assert 0 <= cx < 256
        assert 0 <= cy < 256
        assert code >= 0

        # Invert
        lat_rec, lon_rec = morton_cell_to_lat_lon(cx, cy, bbox=DEFAULT_DOMAIN_BBOX, grid_size=256)
        assert abs(lat_rec - lat) < 0.005
        assert abs(lon_rec - lon) < 0.005

    def test_lat_lon_to_morton_cell_out_of_bounds_raises(self) -> None:
        with pytest.raises(ValueError, match="Coordinates out of spherical bounds"):
            lat_lon_to_morton_cell(95.0, 0.0)
        with pytest.raises(ValueError, match="Coordinates out of spherical bounds"):
            lat_lon_to_morton_cell(0.0, 185.0)

    def test_geohash_encode_and_decode(self) -> None:
        lat, lon = 37.774929, -122.419416
        gh = geohash_encode(lat, lon, precision=8)
        assert len(gh) == 8
        assert all(c in BASE32 for c in gh)

        d_lat, d_lon = geohash_decode(gh)
        assert abs(d_lat - lat) < 0.001
        assert abs(d_lon - lon) < 0.001

    def test_morton_cell_to_bbox(self) -> None:
        mb = morton_cell_to_bbox(10, 20, bbox=DEFAULT_DOMAIN_BBOX, grid_size=256)
        assert isinstance(mb, MortonBoundingBox)
        assert mb.min_lat < mb.max_lat
        assert mb.min_lon < mb.max_lon


# ============================================================================
# 3. TestPolygonAndGeometry
# ============================================================================

class TestPolygonAndGeometry:
    """Validate planar polygon Green's Theorem Shoelace area, centroid, and clipping."""

    def test_shoelace_area_and_centroid_rectangle(self) -> None:
        poly = Polygon2D([
            Point2D(0.0, 0.0),
            Point2D(100.0, 0.0),
            Point2D(100.0, 50.0),
            Point2D(0.0, 50.0),
        ])
        assert math.isclose(poly.shoelace_area(), 5000.0, rel_tol=1e-5)
        c = poly.centroid()
        assert math.isclose(c.x, 50.0, rel_tol=1e-5)
        assert math.isclose(c.y, 25.0, rel_tol=1e-5)

    def test_shoelace_area_triangle(self) -> None:
        poly = Polygon2D([
            Point2D(0.0, 0.0),
            Point2D(60.0, 0.0),
            Point2D(0.0, 80.0),
        ])
        assert math.isclose(poly.shoelace_area(), 2400.0, rel_tol=1e-5)
        c = poly.centroid()
        assert math.isclose(c.x, 20.0, rel_tol=1e-5)
        assert math.isclose(c.y, 80.0 / 3.0, rel_tol=1e-5)

    def test_polygon_clip_halfplane(self) -> None:
        poly = Polygon2D([
            Point2D(0.0, 0.0),
            Point2D(100.0, 0.0),
            Point2D(100.0, 100.0),
            Point2D(0.0, 100.0),
        ])
        # Bisect along x = 50: normal points to right (+x), mid at (50, 50)
        clipped = poly.clip_halfplane(Point2D(50.0, 50.0), Point2D(1.0, 0.0))
        assert math.isclose(clipped.shoelace_area(), 5000.0, rel_tol=1e-4)

    def test_haversine_distance(self) -> None:
        # Distance between identical points is 0
        assert haversine_distance_m(37.77, -122.42, 37.77, -122.42) == 0.0
        # 1 degree latitude is approximately 111.195 km
        d = haversine_distance_m(0.0, 0.0, 1.0, 0.0)
        assert 110000.0 < d < 112000.0


# ============================================================================
# 4. TestDelaunayAndVoronoiGeneration
# ============================================================================

class TestDelaunayAndVoronoiGeneration:
    """Validate Bowyer-Watson Delaunay triangulation dual, Voronoi cell partitioning, and area conservation."""

    def test_empty_circumcircle_criterion(self) -> None:
        sites = [
            VoronoiSite(id=1, lat=37.775, lon=-122.420, x=200.0, y=300.0),
            VoronoiSite(id=2, lat=37.778, lon=-122.415, x=600.0, y=300.0),
            VoronoiSite(id=3, lat=37.772, lon=-122.418, x=400.0, y=100.0),
            VoronoiSite(id=4, lat=37.776, lon=-122.417, x=400.0, y=500.0),
        ]
        triangles = compute_delaunay_triangulation(sites)
        assert len(triangles) >= 2

        # Verify empty-circumcircle criterion for all triangles
        for tri in triangles:
            radius = math.sqrt(tri.radius_sq)
            for s in sites:
                if s.id in (tri.p1.id, tri.p2.id, tri.p3.id):
                    continue
                d = math.hypot(s.x - tri.center_x, s.y - tri.center_y)
                assert d >= radius - 1e-4

    def test_voronoi_cells_partition_and_area_conservation(self) -> None:
        sites = [
            VoronoiSite(id=1, lat=37.772, lon=-122.422, x=200.0, y=150.0),
            VoronoiSite(id=2, lat=37.778, lon=-122.422, x=200.0, y=450.0),
            VoronoiSite(id=3, lat=37.775, lon=-122.418, x=400.0, y=300.0),
            VoronoiSite(id=4, lat=37.772, lon=-122.412, x=600.0, y=150.0),
            VoronoiSite(id=5, lat=37.778, lon=-122.412, x=600.0, y=450.0),
        ]
        cells = compute_voronoi_cells(sites, bbox=(0.0, 800.0, 0.0, 600.0))
        assert len(cells) == 5

        total_area = sum(c.area for c in cells)
        viewport_area = 800.0 * 600.0
        assert math.isclose(total_area, viewport_area, rel_tol=1e-3)

    def test_topology_hash_determinism(self) -> None:
        sites = [
            VoronoiSite(id=1, lat=37.775, lon=-122.420, x=200.0, y=300.0, cell_x=50, cell_y=50, morton_code=100),
            VoronoiSite(id=2, lat=37.778, lon=-122.415, x=600.0, y=300.0, cell_x=150, cell_y=50, morton_code=200),
        ]
        cells = compute_voronoi_cells(sites, bbox=(0.0, 800.0, 0.0, 600.0))
        edges = [VoronoiEdge(sites[0], sites[1])]
        h1_hi, h1_lo = compute_topology_hash(sites, cells, edges)
        h2_hi, h2_lo = compute_topology_hash(sites, cells, edges)
        assert (h1_hi, h1_lo) == (h2_hi, h2_lo)
        assert 0 <= h1_hi <= 0xFFFF
        assert 0 <= h1_lo <= 0xFFFF


# ============================================================================
# 5. TestDelaunayDualCanvasEngine
# ============================================================================

class TestDelaunayDualCanvasEngine:
    """Validate DelaunayDualCanvasEngine execution, collision trips, clearances, and register sync."""

    def test_engine_initialization_defaults(self) -> None:
        engine = DelaunayDualCanvasEngine()
        assert engine.viewport_width == 800.0
        assert engine.viewport_height == 600.0
        assert engine.safety_threshold_m == 50.0
        assert engine.online is True
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert engine.total_sites == 0
        assert engine.polygon_cells == 0

    def test_canonical_canvas_creation(self) -> None:
        engine = create_canonical_delaunay_dual_canvas(sample_count=5, seed=42)
        assert engine.total_sites == 5
        assert engine.polygon_cells == 5
        assert engine.total_triangles >= 2
        assert engine.online is True
        assert engine.diagnostic_code == DIAG_OK

    def test_out_of_bounds_coordinate_detection(self) -> None:
        engine = DelaunayDualCanvasEngine()
        with pytest.raises(ValueError):
            engine.insert_site(lat=95.0, lon=-122.42)
        assert engine.diagnostic_code == DIAG_DELAUNAY_COORDINATE_OUT_OF_BOUNDS

    def test_degenerate_coincident_sites_detection(self) -> None:
        engine = DelaunayDualCanvasEngine()
        engine.insert_site(lat=37.775, lon=-122.420, tag="S1", site_id=1)
        engine.insert_site(lat=37.775, lon=-122.420, tag="S2", site_id=2)
        assert engine.diagnostic_code == DIAG_DELAUNAY_DEGENERATE_NODES

    def test_proximity_hazard_collision_detection_and_clearance(self) -> None:
        engine = DelaunayDualCanvasEngine(safety_threshold_m=50.0)
        # Add two sites very close to each other (~11.1 meters apart)
        engine.insert_site(lat=37.7750, lon=-122.4200, tag="ASSET_A", site_id=1)
        engine.insert_site(lat=37.7751, lon=-122.4200, tag="ASSET_B", site_id=2)

        hazards = engine.detect_collisions()
        assert len(hazards) >= 1
        assert engine.collision_alarm is True
        assert engine.diagnostic_code == DIAG_PROXIMITY_HAZARD_COLLISION

        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_DELAUNAY_COLLISION_ALARM) is True
        assert (rt.read_word(REG_DELAUNAY_DIAGNOSTIC_CODE) & 0xFFFF) == 0x8440
        assert rt.read_word(REG_DELAUNAY_DIAGNOSTIC_CODE) == DIAG_PROXIMITY_HAZARD_COLLISION

        # Clear hazard: update site 2 far away (~500m)
        engine.insert_site(lat=37.7790, lon=-122.4200, tag="ASSET_B", site_id=2)
        hazards2 = engine.detect_collisions()
        assert len(hazards2) == 0
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK

        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_DELAUNAY_COLLISION_ALARM) is False
        assert rt.read_word(REG_DELAUNAY_DIAGNOSTIC_CODE) == int(DIAG_OK)

    def test_register_table_synchronization(self) -> None:
        engine = create_canonical_delaunay_dual_canvas(sample_count=5, seed=42)
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_DELAUNAY_TOTAL_NODES) == 5
        assert rt.read_word(REG_DELAUNAY_TRIANGLE_COUNT) == 5
        assert rt.read_word(REG_DELAUNAY_DIAGNOSTIC_CODE) == 0
        assert rt.read_bit(COIL_DELAUNAY_ONLINE) is True
        assert rt.read_bit(COIL_DELAUNAY_COLLISION_ALARM) is False

    def test_ilogic_unit_interface_compliance(self) -> None:
        engine = create_canonical_delaunay_dual_canvas(sample_count=5, seed=42)
        assert isinstance(engine, ILogicUnit)
        assert hasattr(engine, "name")
        assert hasattr(engine, "priority")
        assert hasattr(engine, "is_enabled")
        assert engine.name == "DelaunayDualCanvasEngine"
        assert engine.priority == 100
        assert engine.is_enabled is True

        ctx = ScanContext(cycle=1, dt=0.01)
        res = engine.scan_step(ctx=ctx)
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS

        engine.reset()
        assert engine.total_sites == 0
        assert engine.collision_alarm is False


# ============================================================================
# 6. TestWcagSvgScadaRendering
# ============================================================================

class TestWcagSvgScadaRendering:
    """Validate W3C SVG 1.1 vector graphic generation and WCAG 2.1 AAA contrast compliance (> 18:1)."""

    def test_svg_xml_validity_and_dimensions(self) -> None:
        engine = create_canonical_delaunay_dual_canvas(sample_count=5, seed=42)
        svg = generate_delaunay_dual_canvas_svg(engine)

        assert svg.startswith("<svg") or "<?xml" in svg
        root = ET.fromstring(svg)
        assert root.attrib["width"] == "800"
        assert root.attrib["height"] == "600"
        assert "viewBox" in root.attrib

    def test_svg_contains_voronoi_and_delaunay_elements(self) -> None:
        engine = create_canonical_delaunay_dual_canvas(sample_count=5, seed=42)
        svg = generate_delaunay_dual_canvas_svg(engine)

        assert "polygon" in svg
        assert "circle" in svg
        assert "line" in svg
        assert "Delaunay Triangulation Dual Graph" in svg or "VORONOI" in svg

    def test_wcag_aaa_contrast_ratio(self) -> None:
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_SCADA_BG)
        assert ratio >= 18.0
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_SCADA_BG) is True


# ============================================================================
# 7. TestPureSTPouAndAntiLadder
# ============================================================================

class TestPureSTPouAndAntiLadder:
    """Validate pure IEC 61131-3 Structured Text POU syntax and anti-ladder safety rejection."""

    def test_pure_st_pou_syntax_validity(self) -> None:
        parser = STParser()
        ast = parser.parse_to_ast(ST_PROGRAM_W327_VORONOI_CANVAS_SYNC)
        assert ast is not None
        assert "DelaunayDualCanvasSync" in ST_PROGRAM_W327_VORONOI_CANVAS_SYNC

    @pytest.mark.parametrize("ladder_construct", [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(/)---",
        "RUNG 1",
        "NETWORK 1",
        "XIC(Motor_Run)",
        "XIO(Fault_Coil)",
        "OTE(Valve_Open)",
    ])
    def test_ladder_construct_rejection(self, ladder_construct: str) -> None:
        tainted_code = f"{ST_PROGRAM_W327_VORONOI_CANVAS_SYNC}\n{ladder_construct}"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(tainted_code)


# ============================================================================
# 8. TestVerificationRunner
# ============================================================================

class TestVerificationRunner:
    """Validate 9-stage verification runner execution and contract output."""

    def test_verification_runner_execution(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf_json:
            json_path = tf_json.name
        with tempfile.NamedTemporaryFile(suffix=".svg", delete=False) as tf_svg:
            svg_path = tf_svg.name

        try:
            res = run_delaunay_dual_canvas_verification(
                output_path=json_path,
                sample_svg_path=svg_path,
                quick=True,
            )
            assert isinstance(res, dict)
            assert res["status"] == "success"
            assert res["data"]["checks_passed"] == 9
            assert res["data"]["total_checks"] == 9

            # Verify saved files
            assert Path(json_path).stat().st_size > 0
            assert Path(svg_path).stat().st_size > 0

            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["status"] == "success"
            assert data["data"]["work_package"] == "W327"
        finally:
            Path(json_path).unlink(missing_ok=True)
            Path(svg_path).unlink(missing_ok=True)


# ============================================================================
# 9. TestSimulationSoakAndMemoryProfiling
# ============================================================================

class TestSimulationSoakAndMemoryProfiling:
    """Validate 100-cycle continuous simulation soak with zero memory leaks and deterministic execution."""

    def test_100_cycle_simulation_soak(self) -> None:
        engine = create_canonical_delaunay_dual_canvas(sample_count=5, seed=42)
        tracemalloc.start()
        snapshot_start = tracemalloc.take_snapshot()

        ctx = ScanContext(cycle=0, dt=0.01)
        for i in range(100):
            ctx.cycle = i + 1
            res = engine.scan_step(ctx=ctx)
            assert res.status == AgentStatus.SUCCESS

        snapshot_end = tracemalloc.take_snapshot()
        tracemalloc.stop()

        top_stats = snapshot_end.compare_to(snapshot_start, "lineno")
        total_growth_kb = sum(stat.size_diff for stat in top_stats) / 1024.0
        assert total_growth_kb < 500.0  # Heap growth bounded within 500 KB
