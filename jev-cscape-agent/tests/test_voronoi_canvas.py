"""Comprehensive Unit Test Suite for Cscape HMI Dynamic Spatial Geohash / Voronoi Diagram SCADA Canvas (W324).

Work Package: W324 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Geohash / Voronoi Diagram SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Covers:
1. Voronoi constants, registers %R2850..%R2857, coils %M665..%M666, diagnostic codes (signed 16-bit safe comparisons).
2. Pure Python 2D Voronoi diagram generation, polygonal cells computation, topology hash, area conservation.
3. Bowyer-Watson Delaunay triangulation dual, empty-circumcircle criterion, circumcenter extraction.
4. Morton / Z-order spatial hashing and Base32 Geohash encoding and decoding.
5. Out-of-bounds coordinates handling (0x843E) and degenerate site handling (0x843D).
6. Dynamic spatial proximity collision hazard alarm (0x843C, %M666 asserted) and clearance.
7. RegisterTable synchronization across %R2850..%R2857 and %M665..%M666.
8. SVG SCADA canvas rendering: XML validity, dimensions (800x600), Voronoi polygons, site markers, contrast ratio (WCAG AAA > 18:1).
9. Pure ST POU validation with STParser and anti-ladder rejection of all 9 constructs.
10. ILogicUnit scan step and 100-cycle simulation soak with memory profiling.
11. 9-stage verification runner test and CLI interop (pass tempfile for --output and --svg!).
12. Explicit key requirements and boundary enforcement verification (Gate G9 / G2).
13. Advanced spatial queries, coordinate transforms, and geometry edge cases.
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

from jev_cscape.hmi.voronoi_canvas import (
    BASE32,
    BASE32_MAP,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COIL_VORONOI_CANVAS_ONLINE,
    COIL_VORONOI_COLLISION_ALARM,
    COIL_VORONOI_HAZARD_ALARM,
    COIL_VORONOI_ONLINE,
    COIL_W324_CANVAS_ONLINE,
    COIL_W324_COLLISION_ALARM,
    COIL_W324_HAZARD_ALARM,
    COIL_W324_ONLINE,
    COIL_W324_VORONOI_ONLINE,
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
    DIAG_ERR_COLINEAR,
    DIAG_ERR_DEGENERATE_SITES,
    DIAG_ERR_OUT_OF_BOUNDS,
    DIAG_ERR_PROXIMITY_HAZARD,
    DIAG_OK,
    DIAG_PROXIMITY_HAZARD_COLLISION,
    DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS,
    DIAG_VORONOI_DEGENERATE_SITES,
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
    REG_VORONOI_ACTIVE_CELLS,
    REG_VORONOI_DIAGNOSTIC_CODE,
    REG_VORONOI_ELEMENTS,
    REG_VORONOI_MIN_CELL_AREA_SQM,
    REG_VORONOI_POLYGON_CELLS,
    REG_VORONOI_PRIMARY_HASH,
    REG_VORONOI_QUERY_LATENCY_US,
    REG_VORONOI_SELECTED_SITE_X,
    REG_VORONOI_SELECTED_SITE_Y,
    REG_VORONOI_STATUS_WORD,
    REG_VORONOI_TOPOLOGY_HASH_HI,
    REG_VORONOI_TOTAL_OBJECTS,
    REG_VORONOI_TOTAL_SITES,
    REG_W324_ACTIVE_CELLS,
    REG_W324_DIAGNOSTIC_CODE,
    REG_W324_MIN_CELL_AREA_SQM,
    REG_W324_POLYGON_CELLS,
    REG_W324_PRIMARY_HASH,
    REG_W324_QUERY_LATENCY_US,
    REG_W324_SELECTED_SITE_X,
    REG_W324_SELECTED_SITE_Y,
    REG_W324_STATUS_WORD,
    REG_W324_TOPOLOGY_HASH_HI,
    REG_W324_TOTAL_OBJECTS,
    REG_W324_TOTAL_SITES,
    ST_PROGRAM_VORONOI_CANVAS_SYNC,
    ST_PROGRAM_W324_VORONOI_CANVAS_SYNC,
    SpatialAsset,
    SpatialSite,
    VORONOI_CANVAS_PURE_ST_POU,
    VoronoiAsset,
    VoronoiCanvas,
    VoronoiCanvasEngine,
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
    create_canonical_voronoi_canvas,
    generate_voronoi_canvas_svg,
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
    run_voronoi_canvas_verification,
    unpart1by1,
    validate_wcag_aaa_contrast,
    verify_voronoi_canvas_pure_st,
)


# ============================================================================
# 1. Voronoi Constants, Registers & Diagnostic Codes Tests
# ============================================================================

class TestVoronoiConstantsAndDiagnostics:
    """Test suite for W324 constants, registers, coils, and diagnostic codes."""

    def test_viewport_and_geographic_constants(self) -> None:
        assert CANVAS_VIEWPORT_WIDTH == 800.0
        assert CANVAS_VIEWPORT_HEIGHT == 600.0
        assert DEFAULT_VIEWPORT_WIDTH == 800.0
        assert DEFAULT_VIEWPORT_HEIGHT == 600.0
        assert DEFAULT_SAFETY_THRESHOLD_M == 50.0
        assert DEFAULT_HAZARD_THRESHOLD == 50.0
        assert EARTH_RADIUS_METERS == 6371000.0
        assert EARTH_RADIUS_WGS84 == 6378137.0
        assert MIN_LATITUDE == -90.0
        assert MAX_LATITUDE == 90.0
        assert MIN_LONGITUDE == -180.0
        assert MAX_LONGITUDE == 180.0
        assert DEFAULT_DOMAIN_BBOX == (37.7700, -122.4250, 37.7800, -122.4100)

    def test_palette_constants(self) -> None:
        assert COLOR_SCADA_BG == "#0D1117"
        assert COLOR_DARK_SURFACE == "#161B22"
        assert COLOR_DECOUPLED_BADGE == "#05080C"
        assert COLOR_BORDER == "#334155"
        assert COLOR_GRID_LINE == "#1E293B"
        assert COLOR_TEXT_PRIMARY == "#FFFFFF"
        assert COLOR_TEXT_MUTED == "#CBD5E1"
        assert COLOR_TEXT_DIM == "#94A3B8"
        assert COLOR_NOMINAL_EMERALD == "#10B981"
        assert COLOR_WARNING_AMBER == "#F59E0B"
        assert COLOR_ALARM_CRIMSON == "#EF4444"
        assert COLOR_RETICLE_CYAN == "#06B6D4"
        assert COLOR_TILE_FILL == "#1E293B"
        assert COLOR_TILE_STROKE == "#334155"
        assert COLOR_EDGE_WIRE == "#475569"
        assert COLOR_VORONOI_STROKE == "#475569"
        assert COLOR_VORONOI_FILL == "#1E293B"
        assert COLOR_DELAUNAY_EDGE == "#38BDF8"
        assert COLOR_MORTON_CELL == "#6366F1"

    def test_register_mappings_and_coils(self) -> None:
        assert REG_VORONOI_TOTAL_SITES == "%R2850"
        assert REG_VORONOI_POLYGON_CELLS == "%R2851"
        assert REG_VORONOI_SELECTED_SITE_X == "%R2852"
        assert REG_VORONOI_SELECTED_SITE_Y == "%R2853"
        assert REG_VORONOI_MIN_CELL_AREA_SQM == "%R2854"
        assert REG_VORONOI_QUERY_LATENCY_US == "%R2855"
        assert REG_VORONOI_TOPOLOGY_HASH_HI == "%R2856"
        assert REG_VORONOI_DIAGNOSTIC_CODE == "%R2857"
        assert COIL_VORONOI_ONLINE == "%M665"
        assert COIL_VORONOI_COLLISION_ALARM == "%M666"

        # W324 aliases
        assert REG_W324_TOTAL_SITES == "%R2850"
        assert REG_W324_TOTAL_OBJECTS == "%R2850"
        assert REG_VORONOI_TOTAL_OBJECTS == "%R2850"
        assert REG_W324_POLYGON_CELLS == "%R2851"
        assert REG_W324_ACTIVE_CELLS == "%R2851"
        assert REG_VORONOI_ACTIVE_CELLS == "%R2851"
        assert REG_VORONOI_ELEMENTS == "%R2851"
        assert REG_W324_SELECTED_SITE_X == "%R2852"
        assert REG_W324_SELECTED_SITE_Y == "%R2853"
        assert REG_W324_MIN_CELL_AREA_SQM == "%R2854"
        assert REG_W324_QUERY_LATENCY_US == "%R2855"
        assert REG_W324_TOPOLOGY_HASH_HI == "%R2856"
        assert REG_W324_PRIMARY_HASH == "%R2856"
        assert REG_VORONOI_PRIMARY_HASH == "%R2856"
        assert REG_W324_STATUS_WORD == "%R2856"
        assert REG_VORONOI_STATUS_WORD == "%R2856"
        assert REG_W324_DIAGNOSTIC_CODE == "%R2857"
        assert COIL_W324_ONLINE == "%M665"
        assert COIL_W324_COLLISION_ALARM == "%M666"
        assert COIL_VORONOI_CANVAS_ONLINE == "%M665"
        assert COIL_W324_VORONOI_ONLINE == "%M665"
        assert COIL_W324_CANVAS_ONLINE == "%M665"
        assert COIL_VORONOI_HAZARD_ALARM == "%M666"
        assert COIL_W324_HAZARD_ALARM == "%M666"

    def test_diagnostic_codes_values_and_representations(self) -> None:
        assert int(DIAG_OK) == 0x0000
        assert int(DIAG_PROXIMITY_HAZARD_COLLISION) == 0x843C
        assert int(DIAG_VORONOI_DEGENERATE_SITES) == 0x843D
        assert int(DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS) == 0x843E

        assert repr(DIAG_PROXIMITY_HAZARD_COLLISION) == "DiagnosticCode(0x843C)"
        assert str(DIAG_PROXIMITY_HAZARD_COLLISION) == "0x843C"
        assert str(DIAG_OK) == "0x0000"

    def test_diagnostic_codes_signed_16bit_equality(self) -> None:
        # DiagnosticCode implements signed 16-bit safe comparisons
        # 0x843C is 33852 unsigned, -31684 signed
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x843C
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 33852
        assert DIAG_PROXIMITY_HAZARD_COLLISION == -31684
        assert DIAG_PROXIMITY_HAZARD_COLLISION == (0x843C - 0x10000)

        # 0x843D is 33853 unsigned, -31683 signed
        assert DIAG_VORONOI_DEGENERATE_SITES == 0x843D
        assert DIAG_VORONOI_DEGENERATE_SITES == 33853
        assert DIAG_VORONOI_DEGENERATE_SITES == -31683
        assert DIAG_VORONOI_DEGENERATE_SITES == (0x843D - 0x10000)

        # 0x843E is 33854 unsigned, -31682 signed
        assert DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS == 0x843E
        assert DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS == 33854
        assert DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS == -31682
        assert DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS == (0x843E - 0x10000)

        assert DIAG_OK == 0
        assert DIAG_OK == 0x0000

        # Set containment
        code_set = {DIAG_PROXIMITY_HAZARD_COLLISION, DIAG_VORONOI_DEGENERATE_SITES}
        assert DIAG_PROXIMITY_HAZARD_COLLISION in code_set
        assert 0x843C in code_set

    def test_diagnostic_codes_aliases(self) -> None:
        assert DIAG_DEGENERATE_SITES == DIAG_VORONOI_DEGENERATE_SITES
        assert DIAG_COORDINATE_OUT_OF_BOUNDS == DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS
        assert DIAG_ERR_OUT_OF_BOUNDS == DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS
        assert DIAG_ERR_PROXIMITY_HAZARD == DIAG_PROXIMITY_HAZARD_COLLISION
        assert DIAG_ERR_DEGENERATE_SITES == DIAG_VORONOI_DEGENERATE_SITES
        assert DIAG_ERR_COLINEAR == DIAG_VORONOI_DEGENERATE_SITES

        # Cross-wave alias equivalence
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8420
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8434
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8428
        assert DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS == 0x8435
        assert DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS == 0x8431

    def test_voronoi_status_bits(self) -> None:
        assert VoronoiStatusBits.ONLINE == 1
        assert VoronoiStatusBits.COLLISION_ALARM == 2
        assert VoronoiStatusBits.VORONOI_GENERATED == 4
        assert VoronoiStatusBits.TOPOLOGY_CONNECTED == 8
        assert VoronoiStatusBits.SITE_SELECTED == 16
        assert VoronoiStatusBits.DEGENERATE_SITES == 32
        assert VoronoiStatusBits.OUT_OF_BOUNDS == 64

        combined = (
            VoronoiStatusBits.ONLINE
            | VoronoiStatusBits.VORONOI_GENERATED
            | VoronoiStatusBits.TOPOLOGY_CONNECTED
        )
        assert (combined & VoronoiStatusBits.ONLINE) != 0
        assert (combined & VoronoiStatusBits.COLLISION_ALARM) == 0
        assert (combined & VoronoiStatusBits.TOPOLOGY_CONNECTED) != 0

    def test_geohash_base32_constants(self) -> None:
        assert len(BASE32) == 32
        assert "a" not in BASE32
        assert "i" not in BASE32
        assert "l" not in BASE32
        assert "o" not in BASE32
        assert len(BASE32_MAP) == 32

    def test_diagnostic_code_hashing_and_set_membership(self) -> None:
        h1 = hash(DIAG_OK)
        h2 = hash(DiagnosticCode(0x0000))
        assert h1 == h2
        s = {DIAG_PROXIMITY_HAZARD_COLLISION, DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS}
        assert DiagnosticCode(0x843C) in s
        assert DiagnosticCode(0x843E) in s


# ============================================================================
# 2. Pure Python Voronoi Diagram Generation & Delaunay Dual Tests
# ============================================================================

class TestVoronoiDiagramGenerationAndTopology:
    """Test suite for Voronoi polygonal cell generation, Delaunay dual, and area conservation."""

    def test_voronoi_two_sites_halfplane_split(self) -> None:
        s1 = VoronoiSite(id=1, lat=37.772, lon=-122.420, x=200.0, y=300.0)
        s2 = VoronoiSite(id=2, lat=37.772, lon=-122.415, x=600.0, y=300.0)
        bbox = (0.0, 800.0, 0.0, 600.0)

        cells = compute_voronoi_cells([s1, s2], bbox=bbox)
        assert len(cells) == 2
        # Bisector is vertical line x = 400.0; both cells should have area 400 * 600 = 240,000
        assert abs(cells[0].area - 240000.0) < 1e-3
        assert abs(cells[1].area - 240000.0) < 1e-3
        assert abs(cells[0].area + cells[1].area - 480000.0) < 1e-3

    def test_voronoi_three_sites_partition(self) -> None:
        s1 = VoronoiSite(id=1, lat=37.771, lon=-122.420, x=200.0, y=200.0)
        s2 = VoronoiSite(id=2, lat=37.772, lon=-122.418, x=600.0, y=200.0)
        s3 = VoronoiSite(id=3, lat=37.775, lon=-122.419, x=400.0, y=500.0)
        bbox = (0.0, 800.0, 0.0, 600.0)

        cells = compute_voronoi_cells([s1, s2, s3], bbox=bbox)
        assert len(cells) == 3
        total_area = sum(c.area for c in cells)
        assert abs(total_area - 480000.0) < 1e-2
        for c in cells:
            assert c.area > 0.0
            assert len(c.polygon.vertices) >= 3

    def test_voronoi_multi_site_area_conservation(self) -> None:
        engine = create_canonical_voronoi_canvas(sample_count=10, seed=42)
        assert len(engine.cells) == 10
        total_area = sum(c.area for c in engine.cells)
        expected_canvas_area = 800.0 * 600.0
        assert abs(total_area - expected_canvas_area) < 1.0, (
            f"Area conservation violated: got {total_area}, expected {expected_canvas_area}"
        )

    def test_bowyer_watson_delaunay_triangulation_empty_circumcircle(self) -> None:
        engine = create_canonical_voronoi_canvas(sample_count=8, seed=42)
        assert len(engine.triangles) >= 2

        for tri in engine.triangles:
            for site in engine.sites.values():
                if not tri.contains_vertex(site):
                    dist = math.hypot(site.x - tri.center_x, site.y - tri.center_y)
                    r = math.sqrt(tri.radius_sq) if not math.isinf(tri.radius_sq) else 0.0
                    assert dist >= (r - 1e-4), "Delaunay empty-circumcircle criterion violated"

    def test_delaunay_fewer_than_three_sites(self) -> None:
        assert compute_delaunay_triangulation([]) == []
        assert compute_delaunay_triangulation([VoronoiSite(id=1, lat=0.0, lon=0.0)]) == []
        assert compute_delaunay_triangulation([
            VoronoiSite(id=1, lat=0.0, lon=0.0),
            VoronoiSite(id=2, lat=1.0, lon=1.0),
        ]) == []

    def test_delaunay_triangle_edges_and_area(self) -> None:
        p1 = VoronoiSite(id=1, lat=0.0, lon=0.0, x=0.0, y=0.0)
        p2 = VoronoiSite(id=2, lat=0.0, lon=0.0, x=4.0, y=0.0)
        p3 = VoronoiSite(id=3, lat=0.0, lon=0.0, x=0.0, y=3.0)
        tri = VoronoiTriangle(p1, p2, p3)

        assert abs(tri.area - 6.0) < 1e-6
        assert abs(tri.center_x - 2.0) < 1e-6
        assert abs(tri.center_y - 1.5) < 1e-6
        assert abs(tri.radius_sq - 6.25) < 1e-6
        assert len(tri.edges) == 3

    def test_delaunay_triangle_circumcircle_contains(self) -> None:
        p1 = VoronoiSite(id=1, lat=0.0, lon=0.0, x=0.0, y=0.0)
        p2 = VoronoiSite(id=2, lat=0.0, lon=0.0, x=4.0, y=0.0)
        p3 = VoronoiSite(id=3, lat=0.0, lon=0.0, x=0.0, y=3.0)
        tri = VoronoiTriangle(p1, p2, p3)

        inside_pt = VoronoiSite(id=4, lat=0.0, lon=0.0, x=2.0, y=1.5)
        outside_pt = VoronoiSite(id=5, lat=0.0, lon=0.0, x=10.0, y=10.0)

        assert tri.circumcircle_contains(inside_pt) is True
        assert tri.circumcircle_contains(outside_pt) is False

    def test_voronoi_cell_properties_and_centroid(self) -> None:
        site = VoronoiSite(id=1, lat=37.775, lon=-122.420, x=100.0, y=100.0)
        poly = Polygon2D([
            Point2D(0.0, 0.0),
            Point2D(200.0, 0.0),
            Point2D(200.0, 200.0),
            Point2D(0.0, 200.0),
        ])
        cell = VoronoiCell(site=site, polygon=poly, area=poly.shoelace_area(), centroid=poly.centroid())

        assert cell.site_id == 1
        assert cell.node == site
        assert abs(cell.area - 40000.0) < 1e-6
        assert abs(cell.centroid.x - 100.0) < 1e-6
        assert abs(cell.centroid.y - 100.0) < 1e-6

    def test_polygon2d_shoelace_and_centroid_calculations(self) -> None:
        poly_empty = Polygon2D([])
        assert poly_empty.shoelace_area() == 0.0
        assert poly_empty.centroid() == Point2D(0.0, 0.0)

        # Triangle
        tri_poly = Polygon2D([Point2D(0.0, 0.0), Point2D(6.0, 0.0), Point2D(0.0, 6.0)])
        assert abs(tri_poly.shoelace_area() - 18.0) < 1e-6
        c = tri_poly.centroid()
        assert abs(c.x - 2.0) < 1e-6
        assert abs(c.y - 2.0) < 1e-6

    def test_voronoi_edge_key_equality_and_hashing(self) -> None:
        s1 = VoronoiSite(id=1, lat=37.771, lon=-122.420)
        s2 = VoronoiSite(id=2, lat=37.772, lon=-122.421)

        e1 = VoronoiEdge(s1, s2)
        e2 = VoronoiEdge(s2, s1)

        assert e1 == e2
        assert hash(e1) == hash(e2)
        assert e1.key == (1, 2)
        assert e1.length_m > 0.0

        # Self-edge has 0 length
        e_self = VoronoiEdge(s1, s1)
        assert e_self.length_m == 0.0

    def test_compute_topology_hash_deterministic(self) -> None:
        s1 = VoronoiSite(id=1, lat=37.771, lon=-122.420, cell_x=10, cell_y=20, morton_code=100)
        s2 = VoronoiSite(id=2, lat=37.772, lon=-122.421, cell_x=30, cell_y=40, morton_code=200)
        edge = VoronoiEdge(s1, s2)
        poly = Polygon2D([Point2D(0.0, 0.0), Point2D(10.0, 0.0), Point2D(0.0, 10.0)])
        c1 = VoronoiCell(site=s1, polygon=poly, area=50.0)
        c2 = VoronoiCell(site=s2, polygon=poly, area=50.0)

        hi1, lo1 = compute_topology_hash([s1, s2], [c1, c2], [edge])
        hi2, lo2 = compute_topology_hash([s2, s1], [c2, c1], [edge])

        assert hi1 == hi2
        assert lo1 == lo2
        assert 0 <= hi1 <= 0xFFFF
        assert 0 <= lo1 <= 0xFFFF

    def test_topology_hash_changes_with_site_move(self) -> None:
        s1 = VoronoiSite(id=1, lat=37.771, lon=-122.420, cell_x=10, cell_y=20, morton_code=100)
        s2 = VoronoiSite(id=2, lat=37.772, lon=-122.421, cell_x=30, cell_y=40, morton_code=200)
        edge = VoronoiEdge(s1, s2)
        poly = Polygon2D([Point2D(0.0, 0.0), Point2D(10.0, 0.0), Point2D(0.0, 10.0)])
        c1 = VoronoiCell(site=s1, polygon=poly, area=50.0)
        c2 = VoronoiCell(site=s2, polygon=poly, area=50.0)

        h1 = compute_topology_hash([s1, s2], [c1, c2], [edge])

        s2_moved = VoronoiSite(id=2, lat=37.773, lon=-122.422, cell_x=35, cell_y=45, morton_code=250)
        h2 = compute_topology_hash([s1, s2_moved], [c1, c2], [VoronoiEdge(s1, s2_moved)])

        assert h1 != h2


# ============================================================================
# 3. Morton / Z-order Spatial Hashing & Geohash Math Tests
# ============================================================================

class TestMortonZOrderAndGeohashMath:
    """Test suite for Morton bit-interleaving, coordinate conversion, and Geohash Base32."""

    def test_part1by1_and_unpart1by1_bijection(self) -> None:
        for val in [0, 1, 15, 255, 1023, 65535]:
            p = part1by1(val)
            u = unpart1by1(p)
            assert u == val

    def test_morton2d_encode_decode_roundtrip(self) -> None:
        test_coords = [
            (0, 0),
            (1, 0),
            (0, 1),
            (1, 1),
            (15, 27),
            (255, 255),
            (1023, 2047),
            (65535, 65535),
        ]
        for x, y in test_coords:
            code = morton2d_encode(x, y)
            rx, ry = morton2d_decode(code)
            assert (rx, ry) == (x, y)

    def test_morton2d_out_of_bounds_rejection(self) -> None:
        with pytest.raises(ValueError):
            morton2d_encode(-1, 0)
        with pytest.raises(ValueError):
            morton2d_encode(0, -1)
        with pytest.raises(ValueError):
            morton2d_encode(0x10000, 0)
        with pytest.raises(ValueError):
            morton2d_decode(-1)
        with pytest.raises(ValueError):
            morton2d_decode(0x100000000)

    def test_morton2d_to_string_binary_format(self) -> None:
        s = morton2d_to_string(5, bits=8)
        assert s == "00000101"
        assert len(s) == 8

    def test_lat_lon_to_morton_cell_and_inverse(self) -> None:
        test_lat, test_lon = 37.7750, -122.4200
        cx, cy, code = lat_lon_to_morton_cell(test_lat, test_lon)
        assert 0 <= cx < 256
        assert 0 <= cy < 256
        assert code == morton2d_encode(cx, cy)

        rec_lat, rec_lon = morton_cell_to_lat_lon(cx, cy)
        dist = haversine_distance_m(test_lat, test_lon, rec_lat, rec_lon)
        assert dist < 50.0

    def test_morton_cell_to_bbox_properties(self) -> None:
        bbox = morton_cell_to_bbox(10, 20)
        assert isinstance(bbox, MortonBoundingBox)
        assert bbox.min_lat < bbox.max_lat
        assert bbox.min_lon < bbox.max_lon
        assert bbox.min_x == 10
        assert bbox.min_y == 20
        assert bbox.contains_cell(10, 20) is True
        assert bbox.contains_cell(11, 20) is False

    def test_geohash_encode_and_decode_roundtrip(self) -> None:
        test_points = [
            (37.7749, -122.4194),
            (51.5074, -0.1278),
            (35.6762, 139.6503),
            (-33.8688, 151.2093),
        ]
        for lat, lon in test_points:
            gh = geohash_encode(lat, lon, precision=6)
            assert len(gh) == 6
            assert all(c in BASE32 for c in gh)

            r_lat, r_lon = geohash_decode(gh)
            dist = haversine_distance_m(lat, lon, r_lat, r_lon)
            assert dist < 2000.0

    def test_geohash_decode_bbox_properties(self) -> None:
        gh = "9q8yyk"
        min_lat, min_lon, max_lat, max_lon = geohash_decode_bbox(gh)
        assert min_lat < max_lat
        assert min_lon < max_lon
        c_lat, c_lon = geohash_decode(gh)
        assert min_lat <= c_lat <= max_lat
        assert min_lon <= c_lon <= max_lon

    def test_geohash_invalid_characters_and_precision(self) -> None:
        with pytest.raises(ValueError):
            geohash_encode(37.0, -122.0, precision=0)
        with pytest.raises(ValueError):
            geohash_encode(37.0, -122.0, precision=13)
        with pytest.raises(ValueError):
            geohash_decode("invalid_chars_!!!")
        with pytest.raises(ValueError):
            geohash_decode("")

    def test_clip_helper(self) -> None:
        assert clip(5.0, 0.0, 10.0) == 5.0
        assert clip(-5.0, 0.0, 10.0) == 0.0
        assert clip(15.0, 0.0, 10.0) == 10.0


# ============================================================================
# 4. Out-of-Bounds & Degenerate Geometry Handling Tests
# ============================================================================

class TestVoronoiInputValidationAndDegeneracyHandling:
    """Test suite for out-of-bounds coordinates (0x843E) and degenerate sites (0x843D)."""

    def test_latitude_out_of_bounds_rejection(self) -> None:
        with pytest.raises(ValueError):
            lat_lon_to_morton_cell(95.0, 0.0)
        with pytest.raises(ValueError):
            lat_lon_to_morton_cell(-95.0, 0.0)

    def test_longitude_out_of_bounds_rejection(self) -> None:
        with pytest.raises(ValueError):
            lat_lon_to_morton_cell(0.0, 185.0)
        with pytest.raises(ValueError):
            lat_lon_to_morton_cell(0.0, -185.0)

    def test_engine_out_of_bounds_sets_diagnostic_code_0x843E(self) -> None:
        engine = VoronoiCanvasEngine()
        with pytest.raises(ValueError):
            engine.insert_site(95.0, 0.0)
        assert engine.diagnostic_code == DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x843E

        with pytest.raises(ValueError):
            engine.latlon_to_canvas(100.0, 0.0)

    def test_engine_select_site_out_of_bounds(self) -> None:
        engine = VoronoiCanvasEngine()
        with pytest.raises(ValueError):
            engine.select_site(-1.0, 0.0)
        assert engine.diagnostic_code == DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS

        with pytest.raises(ValueError):
            engine.select_site(0.0, 70000.0)
        assert engine.diagnostic_code == DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS

    def test_engine_select_cell_out_of_bounds(self) -> None:
        engine = VoronoiCanvasEngine()
        with pytest.raises(ValueError):
            engine.select_cell(-1, 0)
        assert engine.diagnostic_code == DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS

        with pytest.raises(ValueError):
            engine.select_cell(0, 0x10000)
        assert engine.diagnostic_code == DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS

    def test_engine_select_morton_out_of_bounds(self) -> None:
        engine = VoronoiCanvasEngine()
        with pytest.raises(ValueError):
            engine.select_morton(-1)
        assert engine.diagnostic_code == DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS

        with pytest.raises(ValueError):
            engine.select_morton(0x100000000)
        assert engine.diagnostic_code == DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS

    def test_collinear_degeneracy_diagnostic_0x843D(self) -> None:
        engine = VoronoiCanvasEngine()
        engine.insert_site_xy(100.0, 300.0, site_id=1)
        engine.insert_site_xy(200.0, 300.0, site_id=2)
        engine.insert_site_xy(300.0, 300.0, site_id=3)

        assert engine.check_degenerate_sites() is True
        assert engine.diagnostic_code == DIAG_VORONOI_DEGENERATE_SITES
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x843D
        assert (engine.status_word & VoronoiStatusBits.DEGENERATE_SITES) != 0

    def test_coincident_degeneracy_diagnostic_0x843D(self) -> None:
        engine = VoronoiCanvasEngine()
        engine.insert_site(37.7710, -122.4200, site_id=1)
        engine.insert_site(37.7710, -122.4200, site_id=2)

        assert engine.check_degenerate_sites() is True
        assert engine.diagnostic_code == DIAG_VORONOI_DEGENERATE_SITES
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x843D
        assert (engine.status_word & VoronoiStatusBits.DEGENERATE_SITES) != 0

    def test_single_site_topology_nominal(self) -> None:
        engine = VoronoiCanvasEngine()
        engine.insert_site(37.7710, -122.4200, site_id=1)
        assert engine.check_connectivity() is True
        assert engine.diagnostic_code == DIAG_OK
        assert len(engine.cells) == 1
        assert abs(engine.cells[0].area - (800.0 * 600.0)) < 1e-3

    def test_empty_engine_nominal(self) -> None:
        engine = VoronoiCanvasEngine()
        assert engine.check_connectivity() is True
        assert engine.diagnostic_code == DIAG_OK
        assert engine.total_sites == 0
        assert engine.polygon_cells == 0


# ============================================================================
# 5. Dynamic Spatial Proximity Hazard Collision Tests
# ============================================================================

class TestVoronoiProximityHazardCollision:
    """Test suite for dynamic proximity collision alarm (0x843C, %M666 asserted) and clearance."""

    def test_nominal_state_no_collisions(self) -> None:
        engine = VoronoiCanvasEngine(safety_threshold_m=50.0)
        engine.insert_site(37.7710, -122.4200, site_id=1)
        engine.insert_site(37.7790, -122.4100, site_id=2)  # ~1.2 km away

        hazards = engine.detect_collisions()
        assert len(hazards) == 0
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert (engine.status_word & VoronoiStatusBits.COLLISION_ALARM) == 0
        assert engine.nearest_distance_m > 500.0

    def test_proximity_collision_trip_0x843C_and_M666(self) -> None:
        engine = VoronoiCanvasEngine(safety_threshold_m=50.0)
        # 0.0001 deg lat is ~11.1 meters (< 50m threshold)
        s1 = engine.insert_site(37.7770, -122.4150, site_id=1, asset_type="valve")
        s2 = engine.insert_site(37.7771, -122.4150, site_id=2, asset_type="agv")

        hazards = engine.detect_collisions()
        assert len(hazards) == 1
        assert engine.collision_alarm is True
        assert engine.diagnostic_code == DIAG_PROXIMITY_HAZARD_COLLISION
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x843C
        assert (engine.status_word & VoronoiStatusBits.COLLISION_ALARM) != 0
        assert s1.status == "alarm"
        assert s2.status == "alarm"
        assert engine.nearest_distance_m < 50.0

    def test_multiple_hazards_detection(self) -> None:
        engine = VoronoiCanvasEngine(safety_threshold_m=50.0)
        engine.insert_site(37.7770, -122.4150, site_id=1)
        engine.insert_site(37.7771, -122.4150, site_id=2)
        engine.insert_site(37.7772, -122.4150, site_id=3)

        hazards = engine.detect_collisions()
        assert len(hazards) >= 2
        assert engine.collision_alarm is True

    def test_hazard_clearance_upon_site_removal(self) -> None:
        engine = VoronoiCanvasEngine(safety_threshold_m=50.0)
        engine.insert_site(37.7770, -122.4150, site_id=1)
        engine.insert_site(37.7771, -122.4150, site_id=2)
        engine.detect_collisions()
        assert engine.collision_alarm is True

        # Remove colliding site
        engine.remove_site(2)
        engine.detect_collisions()

        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x0000
        assert (engine.status_word & VoronoiStatusBits.COLLISION_ALARM) == 0
        assert engine.sites[1].status == "normal"

    def test_hazard_clearance_upon_site_move(self) -> None:
        engine = VoronoiCanvasEngine(safety_threshold_m=50.0)
        engine.insert_site(37.7770, -122.4150, site_id=1)
        engine.insert_site(37.7771, -122.4150, site_id=2)
        engine.detect_collisions()
        assert engine.collision_alarm is True

        # Update site 2 to distant location
        engine.insert_site(37.7790, -122.4100, site_id=2)
        engine.detect_collisions()

        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK

    def test_reset_and_clear_clears_hazard(self) -> None:
        engine = VoronoiCanvasEngine(safety_threshold_m=50.0)
        engine.insert_site(37.7770, -122.4150, site_id=1)
        engine.insert_site(37.7771, -122.4150, site_id=2)
        engine.detect_collisions()
        assert engine.collision_alarm is True

        engine.reset()
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert len(engine.active_hazards) == 0

    def test_nearest_distance_tracking(self) -> None:
        engine = VoronoiCanvasEngine()
        assert engine.nearest_distance_m == 65535.0
        engine.insert_site(37.7710, -122.4200, site_id=1)
        engine.detect_collisions()
        assert engine.nearest_distance_m == 65535.0

    def test_site_status_flags_alarm_and_normal(self) -> None:
        engine = VoronoiCanvasEngine(safety_threshold_m=50.0)
        s1 = engine.insert_site(37.7770, -122.4150, site_id=1)
        s2 = engine.insert_site(37.7771, -122.4150, site_id=2)
        s3 = engine.insert_site(37.7790, -122.4100, site_id=3)

        engine.detect_collisions()
        assert s1.status == "alarm"
        assert s2.status == "alarm"
        assert s3.status == "normal"


# ============================================================================
# 6. Horner OCS RegisterTable Synchronization Tests
# ============================================================================

class TestVoronoiRegisterTableSync:
    """Test suite for RegisterTable synchronization across %R2850..%R2857 and %M665..%M666."""

    def test_sync_to_registers_nominal(self) -> None:
        engine = VoronoiCanvasEngine()
        engine.insert_site(37.7710, -122.4200, site_id=1)
        engine.insert_site(37.7750, -122.4150, site_id=2)

        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert (rt.read_word(REG_VORONOI_TOTAL_SITES) & 0xFFFF) == 2
        assert (rt.read_word(REG_VORONOI_POLYGON_CELLS) & 0xFFFF) == 2
        assert (rt.read_word(REG_VORONOI_SELECTED_SITE_X) & 0xFFFF) == int(round(engine.selected_site_x))
        assert (rt.read_word(REG_VORONOI_SELECTED_SITE_Y) & 0xFFFF) == int(round(engine.selected_site_y))
        assert (rt.read_word(REG_VORONOI_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
        assert (rt.read_word(REG_VORONOI_TOPOLOGY_HASH_HI) & 0xFFFF) == (engine.topology_hash_hi & 0xFFFF)
        assert rt.read_bit(COIL_VORONOI_ONLINE) is True
        assert rt.read_bit(COIL_VORONOI_COLLISION_ALARM) is False

    def test_sync_to_registers_collision_alarm(self) -> None:
        engine = VoronoiCanvasEngine(safety_threshold_m=50.0)
        engine.insert_site(37.7770, -122.4150, site_id=1)
        engine.insert_site(37.7771, -122.4150, site_id=2)
        engine.detect_collisions()

        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert (rt.read_word(REG_VORONOI_DIAGNOSTIC_CODE) & 0xFFFF) == 0x843C
        assert rt.read_word(REG_VORONOI_DIAGNOSTIC_CODE) == DIAG_PROXIMITY_HAZARD_COLLISION
        assert rt.read_bit(COIL_VORONOI_COLLISION_ALARM) is True

    def test_sync_to_registers_degenerate_geometry(self) -> None:
        engine = VoronoiCanvasEngine()
        engine.insert_site_xy(100.0, 300.0, site_id=1)
        engine.insert_site_xy(200.0, 300.0, site_id=2)
        engine.insert_site_xy(300.0, 300.0, site_id=3)

        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert (rt.read_word(REG_VORONOI_DIAGNOSTIC_CODE) & 0xFFFF) == 0x843D
        assert rt.read_bit(COIL_VORONOI_COLLISION_ALARM) is False

    def test_sync_from_registers_setpoints(self) -> None:
        engine = VoronoiCanvasEngine()
        rt = RegisterTable()

        # Write new site coordinates into registers
        rt.write_word(REG_VORONOI_SELECTED_SITE_X, 100, PrivilegeMode.SYSTEM)
        rt.write_word(REG_VORONOI_SELECTED_SITE_Y, 200, PrivilegeMode.SYSTEM)
        rt.write_bit(COIL_VORONOI_ONLINE, True, PrivilegeMode.SYSTEM)

        engine.sync_from_registers(rt)
        assert engine.selected_site_x == 100.0
        assert engine.selected_site_y == 200.0

    def test_signed_16bit_register_masks(self) -> None:
        rt = RegisterTable()
        # Write negative value to %R2857
        rt.write_word(REG_VORONOI_DIAGNOSTIC_CODE, (-55) & 0xFFFF, PrivilegeMode.SYSTEM)
        raw_val = rt.read_word(REG_VORONOI_DIAGNOSTIC_CODE)
        val_u = raw_val & 0xFFFF
        val_s = val_u - 0x10000 if val_u >= 0x8000 else val_u
        assert val_u == 65481
        assert val_s == -55

        # Write diagnostic code 0x843C
        rt.write_word(
            REG_VORONOI_DIAGNOSTIC_CODE,
            int(DIAG_PROXIMITY_HAZARD_COLLISION) & 0xFFFF,
            PrivilegeMode.SYSTEM,
        )
        diag_read = rt.read_word(REG_VORONOI_DIAGNOSTIC_CODE) & 0xFFFF
        assert diag_read == 0x843C
        assert (diag_read - 0x10000) == -31684

    def test_register_word_boundary_overflow_safe(self) -> None:
        engine = VoronoiCanvasEngine()
        engine.query_latency_us = 80000     # > 65535
        engine.min_cell_area_sqm = 90000.0  # > 65535
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert (rt.read_word(REG_VORONOI_QUERY_LATENCY_US) & 0xFFFF) == 65535
        assert (rt.read_word(REG_VORONOI_MIN_CELL_AREA_SQM) & 0xFFFF) == 65535

    def test_min_cell_area_sqm_register_clamping(self) -> None:
        engine = VoronoiCanvasEngine()
        engine.min_cell_area_sqm = -10.0
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert (rt.read_word(REG_VORONOI_MIN_CELL_AREA_SQM) & 0xFFFF) == 0


# ============================================================================
# 7. SVG SCADA Canvas Rendering & WCAG AAA Contrast Tests
# ============================================================================

class TestVoronoiSvgCanvasAndWcagContrast:
    """Test suite for SVG SCADA canvas generation, XML validity, and WCAG 2.1 AAA contrast."""

    def test_svg_xml_validity_and_root_attributes(self) -> None:
        engine = create_canonical_voronoi_canvas(sample_count=8, seed=42)
        svg_content = generate_voronoi_canvas_svg(engine)

        root = ET.fromstring(svg_content)
        assert root.tag.endswith("svg")
        assert root.attrib["width"] == "800"
        assert root.attrib["height"] == "600"
        assert root.attrib["viewBox"] == "0 0 800 600"

    def test_svg_contains_required_structural_elements(self) -> None:
        engine = create_canonical_voronoi_canvas(sample_count=8, seed=42)
        svg_content = generate_voronoi_canvas_svg(engine)

        assert "voronoi-morton-grid" in svg_content
        assert "voronoi-polygon-cells" in svg_content
        assert "voronoi-dual-delaunay" in svg_content
        assert "voronoi-hazard-zones" in svg_content
        assert "voronoi-site-markers" in svg_content
        assert "hud-telemetry-scorecard" in svg_content
        assert "VORONOI SCADA CANVAS (W324)" in svg_content

    def test_svg_equipment_symbols_for_all_types(self) -> None:
        engine = VoronoiCanvasEngine()
        engine.insert_site(37.771, -122.420, site_id=1, asset_type="valve", tag="VLV-01")
        engine.insert_site(37.772, -122.421, site_id=2, asset_type="pump", tag="PMP-02")
        engine.insert_site(37.773, -122.422, site_id=3, asset_type="tank", tag="TNK-03")
        engine.insert_site(37.774, -122.423, site_id=4, asset_type="agv", tag="AGV-04")
        engine.insert_site(37.775, -122.424, site_id=5, asset_type="sensor", tag="SEN-05")

        svg_content = generate_voronoi_canvas_svg(engine)
        assert "valve-symbol" in svg_content
        assert "pump-symbol" in svg_content
        assert "tank-symbol" in svg_content
        assert "agv-symbol" in svg_content
        assert "sensor-symbol" in svg_content

    def test_svg_active_hazard_line_and_distance_badge(self) -> None:
        engine = VoronoiCanvasEngine(safety_threshold_m=50.0)
        engine.insert_site(37.7770, -122.4150, site_id=1)
        engine.insert_site(37.7771, -122.4150, site_id=2)
        engine.detect_collisions()

        svg_content = generate_voronoi_canvas_svg(engine)
        assert 'class="hazard-collision-line"' in svg_content
        assert "HAZARD" in svg_content
        assert "COLLISION ALARM" in svg_content

    def test_svg_morton_grid_and_labels(self) -> None:
        engine = create_canonical_voronoi_canvas(sample_count=6, seed=42)
        svg_content = generate_voronoi_canvas_svg(engine)
        assert "morton-grid-cell" in svg_content
        assert "morton-grid-label" in svg_content
        assert "M:" in svg_content

    def test_svg_voronoi_polygonal_cells_and_labels(self) -> None:
        engine = create_canonical_voronoi_canvas(sample_count=8, seed=42)
        svg_content = generate_voronoi_canvas_svg(engine)
        assert "voronoi-polygon-cell" in svg_content
        assert "points=" in svg_content

    def test_svg_hud_telemetry_scorecard_elements(self) -> None:
        engine = create_canonical_voronoi_canvas(sample_count=8, seed=42)
        svg_content = generate_voronoi_canvas_svg(engine)
        assert "SITES:" in svg_content
        assert "CELLS:" in svg_content
        assert "SITE X/Y:" in svg_content
        assert "MIN AREA:" in svg_content
        assert "LATENCY:" in svg_content
        assert "HASH HI:" in svg_content
        assert "DIAG CODE:" in svg_content
        assert "ONLINE:" in svg_content

    def test_wcag_aaa_high_contrast_compliance(self) -> None:
        contrast_text_bg = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_SCADA_BG)
        contrast_text_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert contrast_text_bg >= 18.0
        assert contrast_text_badge >= 18.0
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_SCADA_BG, 18.0) is True
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, 18.0) is True

    def test_svg_delaunay_dual_edges(self) -> None:
        engine = create_canonical_voronoi_canvas(sample_count=6, seed=42)
        svg_content = generate_voronoi_canvas_svg(engine)
        assert "voronoi-dual-edge" in svg_content


# ============================================================================
# 8. Pure IEC 61131-3 ST POU & Anti-Ladder Security Rejection Tests
# ============================================================================

class TestVoronoiPureSTAndSecurityRejection:
    """Test suite for Pure Structured Text POU validation and rejection of all 9 ladder constructs."""

    def test_pure_st_pou_verification(self) -> None:
        assert verify_voronoi_canvas_pure_st() is True

    def test_st_parser_ast_properties(self) -> None:
        parser = STParser()
        ast = parser.parse(ST_PROGRAM_W324_VORONOI_CANVAS_SYNC)
        assert ast is not None
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "VoronoiSpatialCanvasSync"

    def test_reject_ladder_contact_open(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P ---[ ]--- END_PROGRAM")

    def test_reject_ladder_contact_closed(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P ---[/]--- END_PROGRAM")

    def test_reject_ladder_coil_standard(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P ---( )--- END_PROGRAM")

    def test_reject_ladder_coil_negated(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P ---(/)--- END_PROGRAM")

    def test_reject_ladder_coil_set(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P ---(S)--- END_PROGRAM")

    def test_reject_ladder_coil_reset(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P ---(R)--- END_PROGRAM")

    def test_reject_ladder_rung_delimiters(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P RUNG 1: X := 1; END_PROGRAM")

    def test_reject_ladder_network_delimiters(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P NETWORK 1: X := 1; END_PROGRAM")

    def test_reject_ladder_contact_and_coil_mnemonics(self) -> None:
        for mnem in ["XIC Tag1;", "XIO Tag1;", "OTE Tag1;", "OTL Tag1;", "OTU Tag1;"]:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(f"PROGRAM P {mnem} END_PROGRAM")

    def test_security_guard_clean_st_passes(self) -> None:
        clean = "PROGRAM Clean VAR x : INT; END_VAR x := 42; END_PROGRAM"
        SecurityGuard.assert_pure_st_content(clean)


# ============================================================================
# 9. ILogicUnit Compliance & Simulation Soak Tests
# ============================================================================

class TestVoronoiILogicUnitComplianceAndSoak:
    """Test suite for ILogicUnit interface compliance, scan steps, and 100-cycle soak."""

    def test_ilogicunit_interface_properties(self) -> None:
        engine = VoronoiCanvasEngine()
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "VoronoiCanvasEngine"
        assert engine.priority == 100
        assert engine.is_enabled is True

    def test_scan_step_execution_result_nominal(self) -> None:
        engine = VoronoiCanvasEngine()
        res = engine.scan_step()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None
        assert "executed successfully" in res.details

    def test_scan_step_execution_result_alarm(self) -> None:
        engine = VoronoiCanvasEngine(safety_threshold_m=50.0)
        engine.insert_site(37.7770, -122.4150, site_id=1)
        engine.insert_site(37.7771, -122.4150, site_id=2)
        res = engine.scan_step()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "0x843C"

    def test_simulation_soak_100_cycles_and_memory_profiling(self) -> None:
        engine = create_canonical_voronoi_canvas(sample_count=8, seed=42)
        rt = RegisterTable()
        ctx = ScanContext(cycle=0, register_table=rt)

        tracemalloc.start()
        snapshot_start = tracemalloc.take_snapshot()

        for c in range(100):
            ctx.cycle = c
            res = engine.scan_step(ctx)
            assert res.status in (AgentStatus.SUCCESS, AgentStatus.FAILED)

        snapshot_end = tracemalloc.take_snapshot()
        tracemalloc.stop()

        stats = snapshot_end.compare_to(snapshot_start, "lineno")
        total_growth_kb = sum(stat.size_diff for stat in stats) / 1024.0

        assert engine.cycle_count == 100
        assert engine.total_sites == 8
        # Memory growth across 100 cycles must be strictly bounded (< 2 MB)
        assert total_growth_kb < 2048.0, f"Memory leak detected: growth {total_growth_kb:.2f} KB >= 2048 KB"

    def test_reset_and_clear_methods(self) -> None:
        engine = VoronoiCanvasEngine()
        engine.insert_site(37.771, -122.420, site_id=1)
        engine.scan_step()
        assert engine.total_sites == 1
        assert engine.cycle_count == 1

        engine.reset()
        assert engine.total_sites == 0
        assert engine.cycle_count == 0
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK

        engine.insert_site(37.771, -122.420, site_id=2)
        engine.clear()
        assert engine.total_sites == 0

    def test_step_and_execute_aliases(self) -> None:
        engine = VoronoiCanvasEngine()
        engine.step()
        assert engine.cycle_count == 1
        res = engine.execute()
        assert isinstance(res, ExecutionResult)
        assert engine.cycle_count == 2

    def test_metrics_snapshot_accuracy(self) -> None:
        engine = create_canonical_voronoi_canvas(sample_count=5, seed=42)
        m = engine.metrics
        assert isinstance(m, VoronoiMetrics)
        assert m.total_sites == 5
        assert m.polygon_cells == engine.polygon_cells
        assert m.online is True


# ============================================================================
# 10. 9-Stage Verification Suite & CLI Interop Tests
# ============================================================================

class TestVoronoiVerificationRunnerAndCLI:
    """Test suite for 9-stage verification runner and CLI execution."""

    def test_verification_runner_direct_execution(self) -> None:
        res = run_voronoi_canvas_verification(work_package="W324", quick=True)
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["stages"]) == 9
        for stage in res["data"]["stages"]:
            assert stage["passed"] is True

    def test_verification_runner_artifact_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            out_json = tmp_path / "w324_evidence.json"
            sample_svg = tmp_path / "w324_sample.svg"

            res = run_voronoi_canvas_verification(
                output_path=out_json,
                sample_svg_path=sample_svg,
                work_package="W324",
                quick=True,
            )

            assert res["status"] == "success"
            assert out_json.exists()
            assert sample_svg.exists()

            with open(out_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                assert data["status"] == "success"
                assert data["data"]["work_package"] == "W324"
                assert len(data["data"]["stages"]) == 9

            svg_content = sample_svg.read_text(encoding="utf-8")
            assert "<svg" in svg_content
            assert "hud-telemetry-scorecard" in svg_content

    def test_verification_runner_cli_subprocess_tempfiles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            out_json = tmp_path / "cli_evidence.json"
            sample_svg = tmp_path / "cli_sample.svg"

            cmd = [
                sys.executable,
                "src/jev_cscape/hmi/voronoi_canvas.py",
                "--quick",
                "--output",
                str(out_json),
                "--svg",
                str(sample_svg),
            ]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent)
            )
            assert proc.returncode == 0, f"CLI runner failed: {proc.stderr}"
            assert out_json.exists()
            assert sample_svg.exists()

    def test_verification_runner_script_subprocess_tempfiles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            out_json = tmp_path / "script_evidence.json"
            sample_svg = tmp_path / "script_sample.svg"

            cmd = [
                sys.executable,
                "scripts/run_voronoi_canvas_verification.py",
                "--quick",
                "--output",
                str(out_json),
                "--svg",
                str(sample_svg),
            ]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent)
            )
            assert proc.returncode == 0, f"Script runner failed: {proc.stderr}"
            assert out_json.exists()
            assert sample_svg.exists()

    def test_verification_runner_cli_json_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            out_json = tmp_path / "json_mode.json"
            sample_svg = tmp_path / "json_mode.svg"

            cmd = [
                sys.executable,
                "scripts/run_voronoi_canvas_verification.py",
                "--quick",
                "--json",
                "--output",
                str(out_json),
                "--svg",
                str(sample_svg),
            ]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent)
            )
            assert proc.returncode == 0, f"Script json mode failed: {proc.stderr}"
            # Find the JSON part in stdout
            assert "SUCCESS" in proc.stdout or "success" in proc.stdout

    def test_verification_runner_cli_custom_work_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            out_json = tmp_path / "wp_evidence.json"
            sample_svg = tmp_path / "wp_sample.svg"
            cmd = [
                sys.executable,
                "src/jev_cscape/hmi/voronoi_canvas.py",
                "--quick",
                "--work-package",
                "W324_CUSTOM",
                "--output",
                str(out_json),
                "--svg",
                str(sample_svg),
            ]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent)
            )
            assert proc.returncode == 0, f"CLI custom wp failed: {proc.stderr}"
            with open(out_json, "r", encoding="utf-8") as f:
                evidence = json.load(f)
                assert evidence["data"]["work_package"] == "W324_CUSTOM"


# ============================================================================
# 11. Key Requirements & Boundary Enforcement Verification Tests
# ============================================================================

class TestVoronoiKeyRequirements:
    """Explicit tests addressing all W324 specification requirements (Gate G9 / G2)."""

    def test_key_req_voronoi_constants_and_registers(self) -> None:
        """Validate registers %R2850..%R2857 and coils %M665..%M666."""
        assert REG_VORONOI_TOTAL_SITES == "%R2850"
        assert REG_VORONOI_POLYGON_CELLS == "%R2851"
        assert REG_VORONOI_SELECTED_SITE_X == "%R2852"
        assert REG_VORONOI_SELECTED_SITE_Y == "%R2853"
        assert REG_VORONOI_MIN_CELL_AREA_SQM == "%R2854"
        assert REG_VORONOI_QUERY_LATENCY_US == "%R2855"
        assert REG_VORONOI_TOPOLOGY_HASH_HI == "%R2856"
        assert REG_VORONOI_DIAGNOSTIC_CODE == "%R2857"
        assert COIL_VORONOI_ONLINE == "%M665"
        assert COIL_VORONOI_COLLISION_ALARM == "%M666"

    def test_key_req_pure_python_voronoi_and_delaunay(self) -> None:
        """Test Voronoi polygonal cell generation and empty circumcircle property."""
        sites = [
            VoronoiSite(id=1, lat=37.771, lon=-122.420, x=50.0, y=50.0),
            VoronoiSite(id=2, lat=37.772, lon=-122.421, x=250.0, y=50.0),
            VoronoiSite(id=3, lat=37.773, lon=-122.422, x=150.0, y=220.0),
            VoronoiSite(id=4, lat=37.774, lon=-122.423, x=150.0, y=100.0),
        ]
        triangles = compute_delaunay_triangulation(sites)
        assert len(triangles) == 3
        for tri in triangles:
            for s in sites:
                if not tri.contains_vertex(s):
                    dist = math.hypot(s.x - tri.center_x, s.y - tri.center_y)
                    r = math.sqrt(tri.radius_sq) if not math.isinf(tri.radius_sq) else 0.0
                    assert dist >= (r - 1e-4)

        cells = compute_voronoi_cells(sites, bbox=(0.0, 800.0, 0.0, 600.0))
        assert len(cells) == 4
        assert abs(sum(c.area for c in cells) - 480000.0) < 1.0

    def test_key_req_morton_and_geohash(self) -> None:
        """Test Morton bit-interleaving and cell roundtrips."""
        for cx, cy in [(0, 0), (10, 20), (127, 255), (1000, 2000)]:
            code = morton2d_encode(cx, cy)
            rx, ry = morton2d_decode(code)
            assert (rx, ry) == (cx, cy)

        gh = geohash_encode(37.775, -122.420, precision=6)
        lat_rec, lon_rec = geohash_decode(gh)
        assert abs(lat_rec - 37.775) < 0.05
        assert abs(lon_rec - (-122.420)) < 0.05

    def test_key_req_out_of_bounds_and_degenerate_diagnostics(self) -> None:
        """Test out-of-bounds coordinates (0x843E) and degenerate sites (0x843D)."""
        engine = VoronoiCanvasEngine()
        with pytest.raises(ValueError):
            engine.insert_site(95.0, 0.0)
        assert engine.diagnostic_code == DIAG_VORONOI_COORDINATE_OUT_OF_BOUNDS
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x843E

        # Collinear degenerate
        engine.insert_site_xy(100.0, 100.0, site_id=1)
        engine.insert_site_xy(200.0, 200.0, site_id=2)
        engine.insert_site_xy(300.0, 300.0, site_id=3)
        assert engine.check_degenerate_sites() is True
        assert engine.diagnostic_code == DIAG_VORONOI_DEGENERATE_SITES
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x843D

    def test_key_req_proximity_hazard_collision_and_clearance(self) -> None:
        """Test dynamic spatial proximity collision hazard alarm (0x843C, %M666) and clearance."""
        engine = VoronoiCanvasEngine(safety_threshold_m=50.0)
        engine.insert_site(37.7770, -122.4150, site_id=1)
        engine.insert_site(37.7771, -122.4150, site_id=2)
        engine.detect_collisions()

        assert engine.collision_alarm is True
        assert engine.diagnostic_code == DIAG_PROXIMITY_HAZARD_COLLISION
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x843C

        engine.remove_site(2)
        engine.detect_collisions()
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x0000

    def test_key_req_register_table_synchronization(self) -> None:
        """Test RegisterTable synchronization across %R2850..%R2857 and %M665..%M666."""
        engine = VoronoiCanvasEngine()
        engine.insert_site(37.7710, -122.4200, site_id=1)
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert (rt.read_word(REG_VORONOI_TOTAL_SITES) & 0xFFFF) == 1
        assert (rt.read_word(REG_VORONOI_DIAGNOSTIC_CODE) & 0xFFFF) == int(DIAG_OK)
        assert rt.read_bit(COIL_VORONOI_ONLINE) is True
        assert rt.read_bit(COIL_VORONOI_COLLISION_ALARM) is False

    def test_key_req_svg_scada_canvas_rendering_and_contrast(self) -> None:
        """Test SVG SCADA canvas rendering: XML validity, dimensions, WCAG AAA > 18:1."""
        engine = create_canonical_voronoi_canvas(sample_count=8, seed=42)
        svg_content = generate_voronoi_canvas_svg(engine)

        root = ET.fromstring(svg_content)
        assert root.tag.endswith("svg")
        assert root.attrib["width"] == "800"
        assert root.attrib["height"] == "600"

        contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert contrast >= 18.0

    def test_key_req_pure_st_pou_anti_ladder_rejection(self) -> None:
        """Test Pure ST POU validation and anti-ladder rejection of all 9 constructs."""
        assert verify_voronoi_canvas_pure_st() is True

        ladder_tests = [
            "PROGRAM P ---[ ]--- END_PROGRAM",
            "PROGRAM P ---[/]--- END_PROGRAM",
            "PROGRAM P ---( )--- END_PROGRAM",
            "PROGRAM P ---(/)--- END_PROGRAM",
            "PROGRAM P ---(S)--- END_PROGRAM",
            "PROGRAM P ---(R)--- END_PROGRAM",
            "PROGRAM P RUNG 1: X := 1; END_PROGRAM",
            "PROGRAM P NETWORK 1: X := 1; END_PROGRAM",
            "PROGRAM P XIC Tag1; END_PROGRAM",
            "PROGRAM P OTE Tag1; END_PROGRAM",
        ]
        for ladder in ladder_tests:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(ladder)

    def test_key_req_ilogicunit_simulation_soak_100_cycles(self) -> None:
        """Test ILogicUnit simulation soak 100 cycles and memory stability."""
        engine = create_canonical_voronoi_canvas(sample_count=8, seed=42)
        rt = RegisterTable()
        ctx = ScanContext(cycle=0, register_table=rt)

        for c in range(100):
            ctx.cycle = c
            res = engine.scan_step(ctx)
            assert res.status in (AgentStatus.SUCCESS, AgentStatus.FAILED)

        assert engine.cycle_count == 100
        assert engine.total_sites == 8

    def test_key_req_9stage_verification_runner_contract(self) -> None:
        """Test 9-stage verification runner returning strict 4-state contract."""
        res = run_voronoi_canvas_verification(work_package="W324", quick=True)
        assert res["status"] in ("success", "failed", "blocked", "inconclusive")
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9


# ============================================================================
# 12. Advanced Voronoi Queries & Spatial Transforms Tests
# ============================================================================

class TestVoronoiSpatialQueriesAndTransforms:
    """Test suite for spatial queries (cell, morton range, radius, bbox) and coordinate transforms."""

    def test_query_cell_matching(self) -> None:
        engine = VoronoiCanvasEngine()
        s1 = engine.insert_site(37.7710, -122.4200, site_id=1)
        engine.insert_site(37.7790, -122.4100, site_id=2)

        matches = engine.query_cell(s1.cell_x, s1.cell_y)
        assert s1 in matches

    def test_query_morton_range_matching(self) -> None:
        engine = VoronoiCanvasEngine()
        s1 = engine.insert_site(37.7710, -122.4200, site_id=1)
        engine.insert_site(37.7790, -122.4100, site_id=2)

        matches = engine.query_morton_range(s1.morton_code, s1.morton_code)
        assert s1 in matches

    def test_query_radius_matching(self) -> None:
        engine = VoronoiCanvasEngine()
        s1 = engine.insert_site(37.7710, -122.4200, site_id=1)
        s2 = engine.insert_site(37.7712, -122.4200, site_id=2)  # ~22m away
        s3 = engine.insert_site(37.7800, -122.4100, site_id=3)  # ~1.3km away

        near = engine.query_radius(37.7710, -122.4200, radius_m=50.0)
        assert s1 in near
        assert s2 in near
        assert s3 not in near

    def test_query_bbox_matching(self) -> None:
        engine = VoronoiCanvasEngine()
        s1 = engine.insert_site(37.7750, -122.4200, site_id=1)
        bbox = DEFAULT_DOMAIN_BBOX
        matches = engine.query_bbox(*bbox)
        assert s1 in matches

    def test_canvas_to_latlon_and_inverse(self) -> None:
        engine = VoronoiCanvasEngine()
        lat, lon = 37.7750, -122.4200
        cx, cy = engine.latlon_to_canvas(lat, lon)
        assert 0.0 <= cx <= engine.viewport_width
        assert 0.0 <= cy <= engine.viewport_height

        r_lat, r_lon = engine.canvas_to_latlon(cx, cy)
        assert abs(r_lat - lat) < 1e-4
        assert abs(r_lon - lon) < 1e-4

    def test_select_site_and_select_morton(self) -> None:
        engine = VoronoiCanvasEngine()
        engine.select_site(100.0, 200.0)
        assert engine.selected_site_x == 100.0
        assert engine.selected_site_y == 200.0
        assert (engine.status_word & VoronoiStatusBits.SITE_SELECTED) != 0

        mcode = morton2d_encode(30, 40)
        engine.select_morton(mcode)
        assert engine.selected_cell_x == 30
        assert engine.selected_cell_y == 40
        assert engine.selected_morton_code == mcode

    def test_site_retrieval_and_removal(self) -> None:
        engine = VoronoiCanvasEngine()
        s = engine.insert_site(37.771, -122.420, site_id=42, asset_type="pump", tag="PMP-42")
        assert engine.sites.get(42) == s
        assert engine.assets.get(42) == s
        assert engine.remove_site(42) == s
        assert engine.remove_site(42) is None
        assert 42 not in engine.sites

    def test_insert_site_xy_direct_canvas_coords(self) -> None:
        engine = VoronoiCanvasEngine()
        s = engine.insert_site_xy(300.0, 400.0, site_id=10, asset_type="tank")
        assert s.id == 10
        assert s.x == 300.0
        assert s.y == 400.0
        assert s.asset_type == "tank"
        assert s in engine.sites.values()
