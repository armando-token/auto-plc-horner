"""Comprehensive Unit Test Suite for Cscape HMI Dynamic Spatial Geohash / Morton Bounding Box Mesh SCADA Canvas (W321).

Work Package: W321 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Geohash / Morton Mesh SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Covers:
1. Mesh constants, registers %R2820..%R2827, coils %M658..%M659, diagnostic codes (signed 16-bit safe comparisons).
2. Pure Python planar triangulation, mesh edges and facets computation, topology hash.
3. Morton / Z-order spatial hashing and range queries.
4. Out-of-bounds latitude/longitude inputs handling (0x843A) and disconnected topology handling (0x8439).
5. Dynamic spatial proximity collision hazard alarm (0x8438, %M659 asserted) and clearance.
6. RegisterTable synchronization across %R2820..%R2827 and %M658..%M659.
7. SVG SCADA canvas rendering: XML validity, dimensions (800x600), wireframe mesh, asset count, contrast ratio (WCAG AAA > 18:1).
8. Pure ST POU validation with STParser and anti-ladder rejection of all 9 constructs.
9. ILogicUnit scan step and 100-cycle simulation soak with memory profiling.
10. 9-stage verification runner test and CLI interop (pass tempfile for --output and --svg!).
11. Explicit key requirements and boundary enforcement verification (Gate G9 / G2).
12. Advanced planar mesh topology edge cases & spatial queries.
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

from jev_cscape.hmi.mesh_canvas import (
    BASE32,
    BASE32_MAP,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COIL_MESH_CANVAS_ONLINE,
    COIL_MESH_COLLISION_ALARM,
    COIL_MESH_HAZARD_ALARM,
    COIL_MESH_ONLINE,
    COIL_W321_CANVAS_ONLINE,
    COIL_W321_COLLISION_ALARM,
    COIL_W321_HAZARD_ALARM,
    COIL_W321_MESH_ONLINE,
    COIL_W321_ONLINE,
    COLOR_ALARM_CRIMSON,
    COLOR_BORDER,
    COLOR_DARK_SURFACE,
    COLOR_DECOUPLED_BADGE,
    COLOR_EDGE_WIRE,
    COLOR_GRID_LINE,
    COLOR_NOMINAL_EMERALD,
    COLOR_RETICLE_CYAN,
    COLOR_SCADA_BG,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TILE_FILL,
    COLOR_TILE_STROKE,
    COLOR_WARNING_AMBER,
    DEFAULT_DOMAIN_BBOX,
    DEFAULT_HAZARD_THRESHOLD,
    DEFAULT_SAFETY_THRESHOLD_M,
    DEFAULT_VIEWPORT_HEIGHT,
    DEFAULT_VIEWPORT_WIDTH,
    DIAG_COORDINATE_OUT_OF_BOUNDS,
    DIAG_ERR_OUT_OF_BOUNDS,
    DIAG_ERR_PROXIMITY_HAZARD,
    DIAG_ERR_TOPOLOGY_DISCONNECTED,
    DIAG_MESH_COORDINATE_OUT_OF_BOUNDS,
    DIAG_OK,
    DIAG_PROXIMITY_HAZARD_COLLISION,
    DIAG_TOPOLOGY_DISCONNECTED,
    DiagnosticCode,
    EARTH_RADIUS_METERS,
    EARTH_RADIUS_WGS84,
    MAX_LATITUDE,
    MAX_LONGITUDE,
    MESH_CANVAS_PURE_ST_POU,
    MIN_LATITUDE,
    MIN_LONGITUDE,
    MeshAsset,
    MeshCanvas,
    MeshCanvasEngine,
    MeshDiagnosticCode,
    MeshEdge,
    MeshMetrics,
    MeshNode,
    MeshStatusBits,
    MeshTriangle,
    MortonBoundingBox,
    REG_MESH_ACTIVE_EDGES,
    REG_MESH_DIAGNOSTIC_CODE,
    REG_MESH_NEAREST_DISTANCE_M,
    REG_MESH_QUERY_LATENCY_US,
    REG_MESH_SELECTED_CELL_X,
    REG_MESH_SELECTED_CELL_Y,
    REG_MESH_TOPOLOGY_HASH_HI,
    REG_MESH_TOTAL_NODES,
    REG_W321_ACTIVE_EDGES,
    REG_W321_DIAGNOSTIC_CODE,
    REG_W321_NEAREST_DISTANCE_M,
    REG_W321_QUERY_LATENCY_US,
    REG_W321_SELECTED_CELL_X,
    REG_W321_SELECTED_CELL_Y,
    REG_W321_TOPOLOGY_HASH_HI,
    REG_W321_TOTAL_NODES,
    ST_PROGRAM_MESH_CANVAS_SYNC,
    ST_PROGRAM_W321_MESH_CANVAS_SYNC,
    SpatialAsset,
    SpatialNode,
    calculate_contrast_ratio,
    clip,
    compute_delaunay_triangulation,
    compute_topology_hash,
    create_canonical_mesh_canvas,
    generate_mesh_canvas_svg,
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
    run_mesh_canvas_verification,
    unpart1by1,
    validate_wcag_aaa_contrast,
    verify_mesh_canvas_pure_st,
)


# ============================================================================
# 1. Mesh Constants, Registers & Diagnostic Codes Tests
# ============================================================================

class TestMeshConstantsAndDiagnostics:
    """Test suite for W321 constants, registers, coils, and diagnostic codes."""

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
        assert COLOR_NOMINAL_EMERALD == "#10B981"
        assert COLOR_WARNING_AMBER == "#F59E0B"
        assert COLOR_ALARM_CRIMSON == "#EF4444"
        assert COLOR_RETICLE_CYAN == "#06B6D4"
        assert COLOR_TILE_FILL == "#1E293B"
        assert COLOR_TILE_STROKE == "#334155"
        assert COLOR_EDGE_WIRE == "#475569"

    def test_register_mappings_and_coils(self) -> None:
        assert REG_MESH_TOTAL_NODES == "%R2820"
        assert REG_MESH_ACTIVE_EDGES == "%R2821"
        assert REG_MESH_SELECTED_CELL_X == "%R2822"
        assert REG_MESH_SELECTED_CELL_Y == "%R2823"
        assert REG_MESH_NEAREST_DISTANCE_M == "%R2824"
        assert REG_MESH_QUERY_LATENCY_US == "%R2825"
        assert REG_MESH_TOPOLOGY_HASH_HI == "%R2826"
        assert REG_MESH_DIAGNOSTIC_CODE == "%R2827"
        assert COIL_MESH_ONLINE == "%M658"
        assert COIL_MESH_COLLISION_ALARM == "%M659"

        # W321 aliases
        assert REG_W321_TOTAL_NODES == "%R2820"
        assert REG_W321_ACTIVE_EDGES == "%R2821"
        assert REG_W321_SELECTED_CELL_X == "%R2822"
        assert REG_W321_SELECTED_CELL_Y == "%R2823"
        assert REG_W321_NEAREST_DISTANCE_M == "%R2824"
        assert REG_W321_QUERY_LATENCY_US == "%R2825"
        assert REG_W321_TOPOLOGY_HASH_HI == "%R2826"
        assert REG_W321_DIAGNOSTIC_CODE == "%R2827"
        assert COIL_W321_ONLINE == "%M658"
        assert COIL_W321_COLLISION_ALARM == "%M659"
        assert COIL_MESH_CANVAS_ONLINE == "%M658"
        assert COIL_W321_MESH_ONLINE == "%M658"
        assert COIL_W321_CANVAS_ONLINE == "%M658"
        assert COIL_MESH_HAZARD_ALARM == "%M659"
        assert COIL_W321_HAZARD_ALARM == "%M659"

    def test_diagnostic_codes_values_and_representations(self) -> None:
        assert int(DIAG_OK) == 0x0000
        assert int(DIAG_PROXIMITY_HAZARD_COLLISION) == 0x8438
        assert int(DIAG_TOPOLOGY_DISCONNECTED) == 0x8439
        assert int(DIAG_MESH_COORDINATE_OUT_OF_BOUNDS) == 0x843A

        assert repr(DIAG_PROXIMITY_HAZARD_COLLISION) == "DiagnosticCode(0x8438)"
        assert str(DIAG_PROXIMITY_HAZARD_COLLISION) == "0x8438"
        assert str(DIAG_OK) == "0x0000"

    def test_diagnostic_codes_signed_16bit_equality(self) -> None:
        # DiagnosticCode implements signed 16-bit safe comparisons
        # 0x8438 is 33848 unsigned, -31688 signed
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8438
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 33848
        assert DIAG_PROXIMITY_HAZARD_COLLISION == -31688
        assert DIAG_PROXIMITY_HAZARD_COLLISION == (0x8438 - 0x10000)

        # 0x8439 is 33849 unsigned, -31687 signed
        assert DIAG_TOPOLOGY_DISCONNECTED == 0x8439
        assert DIAG_TOPOLOGY_DISCONNECTED == 33849
        assert DIAG_TOPOLOGY_DISCONNECTED == -31687
        assert DIAG_TOPOLOGY_DISCONNECTED == (0x8439 - 0x10000)

        # 0x843A is 33850 unsigned, -31686 signed
        assert DIAG_MESH_COORDINATE_OUT_OF_BOUNDS == 0x843A
        assert DIAG_MESH_COORDINATE_OUT_OF_BOUNDS == 33850
        assert DIAG_MESH_COORDINATE_OUT_OF_BOUNDS == -31686
        assert DIAG_MESH_COORDINATE_OUT_OF_BOUNDS == (0x843A - 0x10000)

        assert DIAG_OK == 0
        assert DIAG_OK == 0x0000

        # Set containment
        code_set = {DIAG_PROXIMITY_HAZARD_COLLISION, DIAG_TOPOLOGY_DISCONNECTED}
        assert DIAG_PROXIMITY_HAZARD_COLLISION in code_set
        assert 0x8438 in code_set

    def test_diagnostic_codes_aliases(self) -> None:
        assert DIAG_COORDINATE_OUT_OF_BOUNDS == DIAG_MESH_COORDINATE_OUT_OF_BOUNDS
        assert DIAG_ERR_OUT_OF_BOUNDS == DIAG_MESH_COORDINATE_OUT_OF_BOUNDS
        assert DIAG_ERR_PROXIMITY_HAZARD == DIAG_PROXIMITY_HAZARD_COLLISION
        assert DIAG_ERR_TOPOLOGY_DISCONNECTED == DIAG_TOPOLOGY_DISCONNECTED

        # Cross-wave alias equivalence
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8434
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8430
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8428
        assert DIAG_MESH_COORDINATE_OUT_OF_BOUNDS == 0x8435
        assert DIAG_MESH_COORDINATE_OUT_OF_BOUNDS == 0x8431

    def test_mesh_status_bits(self) -> None:
        assert MeshStatusBits.ONLINE == 1
        assert MeshStatusBits.COLLISION_ALARM == 2
        assert MeshStatusBits.MESH_GENERATED == 4
        assert MeshStatusBits.TOPOLOGY_CONNECTED == 8
        assert MeshStatusBits.CELL_SELECTED == 16

        combined = MeshStatusBits.ONLINE | MeshStatusBits.MESH_GENERATED | MeshStatusBits.TOPOLOGY_CONNECTED
        assert (combined & MeshStatusBits.ONLINE) != 0
        assert (combined & MeshStatusBits.COLLISION_ALARM) == 0
        assert (combined & MeshStatusBits.TOPOLOGY_CONNECTED) != 0

    def test_geohash_base32_constants(self) -> None:
        assert len(BASE32) == 32
        assert "a" not in BASE32
        assert "i" not in BASE32
        assert "l" not in BASE32
        assert "o" not in BASE32
        assert len(BASE32_MAP) == 32


# ============================================================================
# 2. Pure Python Planar Triangulation & Mesh Topologies Tests
# ============================================================================

class TestMeshDelaunayTriangulationAndTopology:
    """Test suite for Bowyer-Watson Delaunay triangulation, planar edges, and topology hash."""

    def test_delaunay_three_nodes_single_triangle(self) -> None:
        nodes = [
            MeshAsset(id=1, lat=37.771, lon=-122.420, x=100.0, y=100.0),
            MeshAsset(id=2, lat=37.772, lon=-122.421, x=200.0, y=100.0),
            MeshAsset(id=3, lat=37.773, lon=-122.422, x=150.0, y=200.0),
        ]
        triangles = compute_delaunay_triangulation(nodes)
        assert len(triangles) == 1
        tri = triangles[0]
        assert {tri.p1.id, tri.p2.id, tri.p3.id} == {1, 2, 3}
        assert tri.area > 0.0
        assert not math.isinf(tri.radius_sq)

    def test_delaunay_four_nodes_convex_quad(self) -> None:
        nodes = [
            MeshAsset(id=1, lat=37.771, lon=-122.420, x=0.0, y=0.0),
            MeshAsset(id=2, lat=37.772, lon=-122.421, x=100.0, y=0.0),
            MeshAsset(id=3, lat=37.773, lon=-122.422, x=100.0, y=100.0),
            MeshAsset(id=4, lat=37.774, lon=-122.423, x=0.0, y=100.0),
        ]
        triangles = compute_delaunay_triangulation(nodes)
        assert len(triangles) == 2
        total_area = sum(t.area for t in triangles)
        assert abs(total_area - 10000.0) < 1e-4

    def test_delaunay_empty_circumcircle_criterion(self) -> None:
        engine = create_canonical_mesh_canvas(sample_count=8, seed=42)
        assert len(engine.triangles) >= 2

        for tri in engine.triangles:
            for node in engine.assets.values():
                if not tri.contains_vertex(node):
                    dist = math.hypot(node.x - tri.center_x, node.y - tri.center_y)
                    r = math.sqrt(tri.radius_sq) if not math.isinf(tri.radius_sq) else 0.0
                    assert dist >= (r - 1e-4), "Delaunay empty-circumcircle criterion violated"

    def test_delaunay_fewer_than_three_nodes(self) -> None:
        assert compute_delaunay_triangulation([]) == []
        assert compute_delaunay_triangulation([MeshAsset(id=1, lat=0.0, lon=0.0)]) == []
        assert compute_delaunay_triangulation([
            MeshAsset(id=1, lat=0.0, lon=0.0),
            MeshAsset(id=2, lat=1.0, lon=1.0),
        ]) == []

    def test_delaunay_triangle_edges_and_area(self) -> None:
        p1 = MeshAsset(id=1, lat=0.0, lon=0.0, x=0.0, y=0.0)
        p2 = MeshAsset(id=2, lat=0.0, lon=0.0, x=4.0, y=0.0)
        p3 = MeshAsset(id=3, lat=0.0, lon=0.0, x=0.0, y=3.0)
        tri = MeshTriangle(p1, p2, p3)

        assert abs(tri.area - 6.0) < 1e-6
        assert abs(tri.center_x - 2.0) < 1e-6
        assert abs(tri.center_y - 1.5) < 1e-6
        assert abs(tri.radius_sq - 6.25) < 1e-6
        assert len(tri.edges) == 3

    def test_delaunay_triangle_circumcircle_contains(self) -> None:
        p1 = MeshAsset(id=1, lat=0.0, lon=0.0, x=0.0, y=0.0)
        p2 = MeshAsset(id=2, lat=0.0, lon=0.0, x=4.0, y=0.0)
        p3 = MeshAsset(id=3, lat=0.0, lon=0.0, x=0.0, y=3.0)
        tri = MeshTriangle(p1, p2, p3)

        inside_pt = MeshAsset(id=4, lat=0.0, lon=0.0, x=2.0, y=1.5)
        outside_pt = MeshAsset(id=5, lat=0.0, lon=0.0, x=10.0, y=10.0)

        assert tri.circumcircle_contains(inside_pt) is True
        assert tri.circumcircle_contains(outside_pt) is False

    def test_mesh_edge_key_equality_and_hashing(self) -> None:
        a1 = MeshAsset(id=1, lat=37.771, lon=-122.420)
        a2 = MeshAsset(id=2, lat=37.772, lon=-122.421)

        e1 = MeshEdge(a1, a2)
        e2 = MeshEdge(a2, a1)

        assert e1 == e2
        assert hash(e1) == hash(e2)
        assert e1.key == (1, 2)
        assert e1.length_m > 0.0

        # Self-edge has 0 length
        e_self = MeshEdge(a1, a1)
        assert e_self.length_m == 0.0

    def test_mesh_asset_distance_and_haversine(self) -> None:
        a1 = MeshAsset(id=1, lat=37.7749, lon=-122.4194, x=10.0, y=20.0)
        a2 = MeshAsset(id=2, lat=37.7749, lon=-122.4194, x=40.0, y=60.0)

        assert abs(a1.distance_to(a2) - 50.0) < 1e-6
        assert a1.haversine_to(a2) == 0.0

    def test_compute_topology_hash_deterministic(self) -> None:
        a1 = MeshAsset(id=1, lat=37.771, lon=-122.420, cell_x=10, cell_y=20, morton_code=100)
        a2 = MeshAsset(id=2, lat=37.772, lon=-122.421, cell_x=30, cell_y=40, morton_code=200)
        edge = MeshEdge(a1, a2)

        hi1, lo1 = compute_topology_hash([a1, a2], [edge])
        hi2, lo2 = compute_topology_hash([a2, a1], [edge])

        assert hi1 == hi2
        assert lo1 == lo2
        assert 0 <= hi1 <= 0xFFFF
        assert 0 <= lo1 <= 0xFFFF

    def test_topology_hash_changes_with_node_move(self) -> None:
        a1 = MeshAsset(id=1, lat=37.771, lon=-122.420, cell_x=10, cell_y=20, morton_code=100)
        a2 = MeshAsset(id=2, lat=37.772, lon=-122.421, cell_x=30, cell_y=40, morton_code=200)
        edge = MeshEdge(a1, a2)

        h1 = compute_topology_hash([a1, a2], [edge])

        a2_moved = MeshAsset(id=2, lat=37.773, lon=-122.422, cell_x=35, cell_y=45, morton_code=250)
        h2 = compute_topology_hash([a1, a2_moved], [MeshEdge(a1, a2_moved)])

        assert h1 != h2


# ============================================================================
# 3. Morton / Z-order Spatial Hashing & Geohash Math Tests
# ============================================================================

class TestMortonZOrderAndGeohash:
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
# 4. Out-of-Bounds & Disconnected Topology Error Handling Tests
# ============================================================================

class TestMeshInputValidationAndErrorHandling:
    """Test suite for out-of-bounds coordinates (0x843A) and disconnected topology (0x8439)."""

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

    def test_engine_out_of_bounds_sets_diagnostic_code_0x843A(self) -> None:
        engine = MeshCanvasEngine()
        with pytest.raises(ValueError):
            engine.insert_asset(95.0, 0.0)
        assert engine.diagnostic_code == DIAG_MESH_COORDINATE_OUT_OF_BOUNDS
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x843A

        with pytest.raises(ValueError):
            engine.latlon_to_canvas(100.0, 0.0)

    def test_engine_select_cell_out_of_bounds(self) -> None:
        engine = MeshCanvasEngine()
        with pytest.raises(ValueError):
            engine.select_cell(-1, 0)
        assert engine.diagnostic_code == DIAG_MESH_COORDINATE_OUT_OF_BOUNDS

        with pytest.raises(ValueError):
            engine.select_cell(0, 0x10000)
        assert engine.diagnostic_code == DIAG_MESH_COORDINATE_OUT_OF_BOUNDS

    def test_engine_select_morton_out_of_bounds(self) -> None:
        engine = MeshCanvasEngine()
        with pytest.raises(ValueError):
            engine.select_morton(-1)
        assert engine.diagnostic_code == DIAG_MESH_COORDINATE_OUT_OF_BOUNDS

        with pytest.raises(ValueError):
            engine.select_morton(0x100000000)
        assert engine.diagnostic_code == DIAG_MESH_COORDINATE_OUT_OF_BOUNDS

    def test_disconnected_topology_diagnostic_0x8439(self) -> None:
        engine = MeshCanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1, asset_type="sensor")
        engine.insert_asset(37.7790, -122.4110, asset_id=2, asset_type="pump")

        # Emulate network disconnection by clearing edges
        engine.edges = []
        engine.detect_collisions(safety_threshold_m=10.0)

        assert engine.check_connectivity() is False
        assert engine.diagnostic_code == DIAG_TOPOLOGY_DISCONNECTED
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8439
        assert (engine.status_word & MeshStatusBits.TOPOLOGY_CONNECTED) == 0

    def test_single_node_topology_nominal(self) -> None:
        engine = MeshCanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        assert engine.check_connectivity() is True
        assert engine.diagnostic_code == DIAG_OK

    def test_empty_engine_nominal(self) -> None:
        engine = MeshCanvasEngine()
        assert engine.check_connectivity() is True
        assert engine.diagnostic_code == DIAG_OK
        assert engine.total_nodes == 0
        assert engine.active_edges == 0


# ============================================================================
# 5. Dynamic Spatial Proximity Hazard Collision Tests
# ============================================================================

class TestMeshProximityHazardCollision:
    """Test suite for dynamic proximity collision alarm (0x8438, %M659 asserted) and clearance."""

    def test_nominal_state_no_collisions(self) -> None:
        engine = MeshCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        engine.insert_asset(37.7790, -122.4100, asset_id=2)  # ~1.2 km away

        hazards = engine.detect_collisions()
        assert len(hazards) == 0
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert (engine.status_word & MeshStatusBits.COLLISION_ALARM) == 0
        assert engine.nearest_distance_m > 500.0

    def test_proximity_collision_trip_0x8438_and_M659(self) -> None:
        engine = MeshCanvasEngine(safety_threshold_m=50.0)
        # 0.0001 deg lat is ~11.1 meters (< 50m threshold)
        a1 = engine.insert_asset(37.7770, -122.4150, asset_id=1, asset_type="valve")
        a2 = engine.insert_asset(37.7771, -122.4150, asset_id=2, asset_type="agv")

        hazards = engine.detect_collisions()
        assert len(hazards) == 1
        assert engine.collision_alarm is True
        assert engine.diagnostic_code == DIAG_PROXIMITY_HAZARD_COLLISION
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8438
        assert (engine.status_word & MeshStatusBits.COLLISION_ALARM) != 0
        assert a1.status == "alarm"
        assert a2.status == "alarm"
        assert engine.nearest_distance_m < 50.0

    def test_multiple_hazards_detection(self) -> None:
        engine = MeshCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.insert_asset(37.7772, -122.4150, asset_id=3)

        hazards = engine.detect_collisions()
        assert len(hazards) >= 2
        assert engine.collision_alarm is True

    def test_hazard_clearance_upon_asset_removal(self) -> None:
        engine = MeshCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.detect_collisions()
        assert engine.collision_alarm is True

        # Remove colliding asset
        engine.remove_asset(2)
        engine.detect_collisions()

        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x0000
        assert (engine.status_word & MeshStatusBits.COLLISION_ALARM) == 0
        assert engine.assets[1].status == "normal"

    def test_hazard_clearance_upon_asset_move(self) -> None:
        engine = MeshCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.detect_collisions()
        assert engine.collision_alarm is True

        # Update asset 2 to distant location
        engine.insert_asset(37.7790, -122.4100, asset_id=2)
        engine.detect_collisions()

        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK

    def test_reset_and_clear_clears_hazard(self) -> None:
        engine = MeshCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.detect_collisions()
        assert engine.collision_alarm is True

        engine.reset()
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert len(engine.active_hazards) == 0

    def test_nearest_distance_tracking(self) -> None:
        engine = MeshCanvasEngine()
        assert engine.nearest_distance_m == 65535.0
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        engine.detect_collisions()
        assert engine.nearest_distance_m == 65535.0


# ============================================================================
# 6. Horner OCS RegisterTable Synchronization Tests
# ============================================================================

class TestMeshRegisterTableSync:
    """Test suite for RegisterTable synchronization across %R2820..%R2827 and %M658..%M659."""

    def test_sync_to_registers_nominal(self) -> None:
        engine = MeshCanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        engine.insert_asset(37.7750, -122.4150, asset_id=2)

        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_MESH_TOTAL_NODES) == 2
        assert rt.read_word(REG_MESH_ACTIVE_EDGES) == 1
        assert rt.read_word(REG_MESH_SELECTED_CELL_X) == engine.selected_cell_x
        assert rt.read_word(REG_MESH_SELECTED_CELL_Y) == engine.selected_cell_y
        assert rt.read_word(REG_MESH_DIAGNOSTIC_CODE) == 0x0000
        assert rt.read_bit(COIL_MESH_ONLINE) is True
        assert rt.read_bit(COIL_MESH_COLLISION_ALARM) is False

    def test_sync_to_registers_collision_alarm(self) -> None:
        engine = MeshCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.detect_collisions()

        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert (rt.read_word(REG_MESH_DIAGNOSTIC_CODE) & 0xFFFF) == 0x8438
        assert rt.read_word(REG_MESH_DIAGNOSTIC_CODE) == DIAG_PROXIMITY_HAZARD_COLLISION
        assert rt.read_bit(COIL_MESH_COLLISION_ALARM) is True
        assert rt.read_word(REG_MESH_NEAREST_DISTANCE_M) < 50

    def test_sync_to_registers_disconnected_topology(self) -> None:
        engine = MeshCanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        engine.insert_asset(37.7790, -122.4110, asset_id=2)
        engine.edges = []
        engine.detect_collisions(safety_threshold_m=10.0)

        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert (rt.read_word(REG_MESH_DIAGNOSTIC_CODE) & 0xFFFF) == 0x8439
        assert rt.read_bit(COIL_MESH_COLLISION_ALARM) is False

    def test_sync_from_registers_setpoints(self) -> None:
        engine = MeshCanvasEngine()
        rt = RegisterTable()

        # Write new cell coordinates into registers
        rt.write_word(REG_MESH_SELECTED_CELL_X, 100, PrivilegeMode.SYSTEM)
        rt.write_word(REG_MESH_SELECTED_CELL_Y, 200, PrivilegeMode.SYSTEM)
        rt.write_bit(COIL_MESH_ONLINE, True, PrivilegeMode.SYSTEM)

        engine.sync_from_registers(rt)
        assert engine.selected_cell_x == 100
        assert engine.selected_cell_y == 200
        assert engine.selected_morton_code == morton2d_encode(100, 200)

    def test_signed_16bit_register_masks(self) -> None:
        rt = RegisterTable()
        # Write negative value to %R2827
        rt.write_word(REG_MESH_DIAGNOSTIC_CODE, (-55) & 0xFFFF, PrivilegeMode.SYSTEM)
        raw_val = rt.read_word(REG_MESH_DIAGNOSTIC_CODE)
        val_u = raw_val & 0xFFFF
        val_s = val_u - 0x10000 if val_u >= 0x8000 else val_u
        assert val_u == 65481
        assert val_s == -55

        # Write diagnostic code 0x8438
        rt.write_word(REG_MESH_DIAGNOSTIC_CODE, int(DIAG_PROXIMITY_HAZARD_COLLISION) & 0xFFFF, PrivilegeMode.SYSTEM)
        diag_read = rt.read_word(REG_MESH_DIAGNOSTIC_CODE) & 0xFFFF
        assert diag_read == 0x8438
        assert (diag_read - 0x10000) == -31688

    def test_register_word_boundary_overflow_safe(self) -> None:
        engine = MeshCanvasEngine()
        engine.nearest_distance_m = 70000.0  # > 65535
        engine.query_latency_us = 80000     # > 65535
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert (rt.read_word(REG_MESH_NEAREST_DISTANCE_M) & 0xFFFF) == 65535
        assert (rt.read_word(REG_MESH_QUERY_LATENCY_US) & 0xFFFF) == 65535


# ============================================================================
# 7. SVG SCADA Canvas Rendering & WCAG AAA Contrast Tests
# ============================================================================

class TestMeshSvgCanvasAndWcagContrast:
    """Test suite for SVG SCADA canvas generation, XML validity, and WCAG 2.1 AAA contrast."""

    def test_svg_xml_validity_and_root_attributes(self) -> None:
        engine = create_canonical_mesh_canvas(sample_count=8, seed=42)
        svg_content = generate_mesh_canvas_svg(engine)

        root = ET.fromstring(svg_content)
        assert root.tag.endswith("svg")
        assert root.attrib["width"] == "800"
        assert root.attrib["height"] == "600"
        assert root.attrib["viewBox"] == "0 0 800 600"

    def test_svg_contains_required_structural_elements(self) -> None:
        engine = create_canonical_mesh_canvas(sample_count=8, seed=42)
        svg_content = generate_mesh_canvas_svg(engine)

        assert "mesh-morton-grid" in svg_content
        assert "mesh-wireframe-triangles" in svg_content
        assert "mesh-active-edges" in svg_content
        assert "mesh-hazard-zones" in svg_content
        assert "mesh-asset-markers" in svg_content
        assert "hud-telemetry-scorecard" in svg_content
        assert "MORTON MESH SCADA CANVAS" in svg_content

    def test_svg_equipment_symbols_for_all_types(self) -> None:
        engine = MeshCanvasEngine()
        engine.insert_asset(37.771, -122.420, asset_id=1, asset_type="valve", tag="VLV-01")
        engine.insert_asset(37.772, -122.421, asset_id=2, asset_type="pump", tag="PMP-02")
        engine.insert_asset(37.773, -122.422, asset_id=3, asset_type="tank", tag="TNK-03")
        engine.insert_asset(37.774, -122.423, asset_id=4, asset_type="agv", tag="AGV-04")
        engine.insert_asset(37.775, -122.424, asset_id=5, asset_type="sensor", tag="SEN-05")

        svg_content = generate_mesh_canvas_svg(engine)
        assert "valve-symbol" in svg_content
        assert "pump-symbol" in svg_content
        assert "tank-symbol" in svg_content
        assert "agv-symbol" in svg_content
        assert "sensor-symbol" in svg_content

    def test_svg_active_hazard_line_and_distance_badge(self) -> None:
        engine = MeshCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.detect_collisions()

        svg_content = generate_mesh_canvas_svg(engine)
        assert 'class="hazard-collision-line"' in svg_content
        assert "HAZARD" in svg_content
        assert "COLLISION ALARM" in svg_content

    def test_svg_morton_grid_and_labels(self) -> None:
        engine = create_canonical_mesh_canvas(sample_count=6, seed=42)
        svg_content = generate_mesh_canvas_svg(engine)
        assert "morton-grid-cell" in svg_content
        assert "morton-grid-label" in svg_content
        assert "M:" in svg_content

    def test_svg_wireframe_triangles_and_edges(self) -> None:
        engine = create_canonical_mesh_canvas(sample_count=10, seed=42)
        svg_content = generate_mesh_canvas_svg(engine)
        assert "mesh-triangle" in svg_content
        assert "mesh-wireframe-edge" in svg_content

    def test_svg_hud_telemetry_scorecard_elements(self) -> None:
        engine = create_canonical_mesh_canvas(sample_count=8, seed=42)
        svg_content = generate_mesh_canvas_svg(engine)
        assert "NODES:" in svg_content
        assert "EDGES:" in svg_content
        assert "CELL X/Y:" in svg_content
        assert "MORTON:" in svg_content
        assert "NEAREST DIST:" in svg_content
        assert "TRIANGLES:" in svg_content

    def test_wcag_aaa_high_contrast_compliance(self) -> None:
        contrast_text_bg = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_SCADA_BG)
        contrast_text_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert contrast_text_bg >= 18.0
        assert contrast_text_badge >= 18.0
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_SCADA_BG, 18.0) is True
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, 18.0) is True


# ============================================================================
# 8. Pure IEC 61131-3 ST POU & Anti-Ladder Security Rejection Tests
# ============================================================================

class TestMeshPureSTAndSecurityRejection:
    """Test suite for Pure Structured Text POU validation and rejection of all 9 ladder constructs."""

    def test_pure_st_pou_verification(self) -> None:
        assert verify_mesh_canvas_pure_st() is True

    def test_st_parser_ast_properties(self) -> None:
        parser = STParser()
        ast = parser.parse(ST_PROGRAM_W321_MESH_CANVAS_SYNC)
        assert ast is not None
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "MeshSpatialCanvasSync"

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

class TestMeshILogicUnitComplianceAndSoak:
    """Test suite for ILogicUnit interface compliance, scan steps, and 100-cycle soak."""

    def test_ilogicunit_interface_properties(self) -> None:
        engine = MeshCanvasEngine()
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "MeshCanvasEngine"
        assert engine.priority == 100
        assert engine.is_enabled is True

    def test_scan_step_execution_result_nominal(self) -> None:
        engine = MeshCanvasEngine()
        res = engine.scan_step()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None
        assert "executed successfully" in res.details

    def test_scan_step_execution_result_alarm(self) -> None:
        engine = MeshCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        res = engine.scan_step()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "0x8438"

    def test_simulation_soak_100_cycles_and_memory_profiling(self) -> None:
        engine = create_canonical_mesh_canvas(sample_count=8, seed=42)
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
        assert engine.total_nodes == 8
        # Memory growth across 100 cycles must be strictly bounded (< 2 MB)
        assert total_growth_kb < 2048.0, f"Memory leak detected: growth {total_growth_kb:.2f} KB >= 2048 KB"

    def test_reset_and_clear_methods(self) -> None:
        engine = MeshCanvasEngine()
        engine.insert_asset(37.771, -122.420, asset_id=1)
        engine.scan_step()
        assert engine.total_nodes == 1
        assert engine.cycle_count == 1

        engine.reset()
        assert engine.total_nodes == 0
        assert engine.cycle_count == 0
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK

        engine.insert_asset(37.771, -122.420, asset_id=2)
        engine.clear()
        assert engine.total_nodes == 0

    def test_step_and_execute_aliases(self) -> None:
        engine = MeshCanvasEngine()
        engine.step()
        assert engine.cycle_count == 1
        res = engine.execute()
        assert isinstance(res, ExecutionResult)
        assert engine.cycle_count == 2

    def test_metrics_snapshot_accuracy(self) -> None:
        engine = create_canonical_mesh_canvas(sample_count=5, seed=42)
        m = engine.metrics
        assert isinstance(m, MeshMetrics)
        assert m.total_nodes == 5
        assert m.active_edges == engine.active_edges
        assert m.total_triangles == engine.total_triangles
        assert m.online is True


# ============================================================================
# 10. 9-Stage Verification Suite & CLI Interop Tests
# ============================================================================

class TestMeshVerificationRunnerAndCLI:
    """Test suite for 9-stage verification runner and CLI execution."""

    def test_verification_runner_direct_execution(self) -> None:
        res = run_mesh_canvas_verification(work_package="W321", quick=True)
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
            out_json = tmp_path / "w321_evidence.json"
            sample_svg = tmp_path / "w321_sample.svg"

            res = run_mesh_canvas_verification(
                output_path=out_json,
                sample_svg_path=sample_svg,
                work_package="W321",
                quick=True,
            )

            assert res["status"] == "success"
            assert out_json.exists()
            assert sample_svg.exists()

            with open(out_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                assert data["status"] == "success"
                assert data["data"]["work_package"] == "W321"
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
                "scripts/run_mesh_canvas_verification.py",
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

    def test_verification_runner_cli_json_mode(self) -> None:
        cmd = [
            sys.executable,
            "scripts/run_mesh_canvas_verification.py",
            "--quick",
            "--json",
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent)
        )
        assert proc.returncode == 0, f"CLI json mode failed: {proc.stderr}"
        parsed = json.loads(proc.stdout)
        assert parsed["status"] == "success"
        assert parsed["data"]["checks_passed"] == 9

    def test_verification_runner_cli_custom_work_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            out_json = tmp_path / "wp_evidence.json"
            cmd = [
                sys.executable,
                "scripts/run_mesh_canvas_verification.py",
                "--quick",
                "--work-package",
                "W321_CUSTOM",
                "--output",
                str(out_json),
            ]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent)
            )
            assert proc.returncode == 0, f"CLI custom wp failed: {proc.stderr}"
            with open(out_json, "r", encoding="utf-8") as f:
                evidence = json.load(f)
                assert evidence["data"]["work_package"] == "W321_CUSTOM"


# ============================================================================
# 11. Key Requirements & Boundary Enforcement Verification Tests
# ============================================================================

class TestMeshCanvasKeyRequirements:
    """Explicit tests addressing all W321 specification requirements (Gate G9 / G2)."""

    def test_key_req_mesh_constants_and_registers(self) -> None:
        """Validate registers %R2820..%R2827 and coils %M658..%M659."""
        assert REG_MESH_TOTAL_NODES == "%R2820"
        assert REG_MESH_ACTIVE_EDGES == "%R2821"
        assert REG_MESH_SELECTED_CELL_X == "%R2822"
        assert REG_MESH_SELECTED_CELL_Y == "%R2823"
        assert REG_MESH_NEAREST_DISTANCE_M == "%R2824"
        assert REG_MESH_QUERY_LATENCY_US == "%R2825"
        assert REG_MESH_TOPOLOGY_HASH_HI == "%R2826"
        assert REG_MESH_DIAGNOSTIC_CODE == "%R2827"
        assert COIL_MESH_ONLINE == "%M658"
        assert COIL_MESH_COLLISION_ALARM == "%M659"

    def test_key_req_pure_python_planar_delaunay_triangulation(self) -> None:
        """Test Delaunay triangulation and empty circumcircle property."""
        nodes = [
            MeshAsset(id=1, lat=37.771, lon=-122.420, x=50.0, y=50.0),
            MeshAsset(id=2, lat=37.772, lon=-122.421, x=250.0, y=50.0),
            MeshAsset(id=3, lat=37.773, lon=-122.422, x=150.0, y=220.0),
            MeshAsset(id=4, lat=37.774, lon=-122.423, x=150.0, y=100.0),
        ]
        triangles = compute_delaunay_triangulation(nodes)
        assert len(triangles) == 3
        for tri in triangles:
            for n in nodes:
                if not tri.contains_vertex(n):
                    dist = math.hypot(n.x - tri.center_x, n.y - tri.center_y)
                    r = math.sqrt(tri.radius_sq) if not math.isinf(tri.radius_sq) else 0.0
                    assert dist >= (r - 1e-4)

    def test_key_req_morton_zorder_spatial_indexing(self) -> None:
        """Test Morton bit-interleaving and cell roundtrips."""
        for cx, cy in [(0, 0), (10, 20), (127, 255), (1000, 2000)]:
            code = morton2d_encode(cx, cy)
            rx, ry = morton2d_decode(code)
            assert (rx, ry) == (cx, cy)

    def test_key_req_out_of_bounds_and_disconnected_diagnostics(self) -> None:
        """Test out-of-bounds coordinates (0x843A) and disconnected topology (0x8439)."""
        engine = MeshCanvasEngine()
        with pytest.raises(ValueError):
            engine.insert_asset(95.0, 0.0)
        assert engine.diagnostic_code == DIAG_MESH_COORDINATE_OUT_OF_BOUNDS
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x843A

        # Disconnected
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        engine.insert_asset(37.7790, -122.4110, asset_id=2)
        engine.edges = []
        engine.detect_collisions(safety_threshold_m=10.0)
        assert engine.diagnostic_code == DIAG_TOPOLOGY_DISCONNECTED
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8439

    def test_key_req_proximity_hazard_collision_and_clearance(self) -> None:
        """Test dynamic spatial proximity collision hazard alarm (0x8438, %M659) and clearance."""
        engine = MeshCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.detect_collisions()

        assert engine.collision_alarm is True
        assert engine.diagnostic_code == DIAG_PROXIMITY_HAZARD_COLLISION
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8438

        engine.remove_asset(2)
        engine.detect_collisions()
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x0000

    def test_key_req_register_table_synchronization(self) -> None:
        """Test RegisterTable synchronization across %R2820..%R2827 and %M658..%M659."""
        engine = MeshCanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_MESH_TOTAL_NODES) == 1
        assert rt.read_word(REG_MESH_DIAGNOSTIC_CODE) == int(DIAG_OK)
        assert rt.read_bit(COIL_MESH_ONLINE) is True
        assert rt.read_bit(COIL_MESH_COLLISION_ALARM) is False

    def test_key_req_svg_scada_canvas_rendering_and_contrast(self) -> None:
        """Test SVG SCADA canvas rendering: XML validity, dimensions, WCAG AAA > 18:1."""
        engine = create_canonical_mesh_canvas(sample_count=8, seed=42)
        svg_content = generate_mesh_canvas_svg(engine)

        root = ET.fromstring(svg_content)
        assert root.tag.endswith("svg")
        assert root.attrib["width"] == "800"
        assert root.attrib["height"] == "600"

        contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert contrast >= 18.0

    def test_key_req_pure_st_pou_anti_ladder_rejection(self) -> None:
        """Test Pure ST POU validation and anti-ladder rejection of all 9 constructs."""
        assert verify_mesh_canvas_pure_st() is True

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
        engine = create_canonical_mesh_canvas(sample_count=8, seed=42)
        rt = RegisterTable()
        ctx = ScanContext(cycle=0, register_table=rt)

        for c in range(100):
            ctx.cycle = c
            res = engine.scan_step(ctx)
            assert res.status in (AgentStatus.SUCCESS, AgentStatus.FAILED)

        assert engine.cycle_count == 100
        assert engine.total_nodes == 8

    def test_key_req_9stage_verification_runner_contract(self) -> None:
        """Test 9-stage verification runner returning strict 4-state contract."""
        res = run_mesh_canvas_verification(work_package="W321", quick=True)
        assert res["status"] in ("success", "failed", "blocked", "inconclusive")
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9


# ============================================================================
# 12. Advanced Planar Mesh Topology Edge Cases & Spatial Queries Tests
# ============================================================================

class TestMeshSpatialQueriesAndTransforms:
    """Test suite for spatial queries (cell, morton range, radius, bbox) and coordinate transforms."""

    def test_query_cell_matching(self) -> None:
        engine = MeshCanvasEngine()
        a1 = engine.insert_asset(37.7710, -122.4200, asset_id=1)
        engine.insert_asset(37.7790, -122.4100, asset_id=2)

        matches = engine.query_cell(a1.cell_x, a1.cell_y)
        assert a1 in matches

    def test_query_morton_range_matching(self) -> None:
        engine = MeshCanvasEngine()
        a1 = engine.insert_asset(37.7710, -122.4200, asset_id=1)
        engine.insert_asset(37.7790, -122.4100, asset_id=2)

        matches = engine.query_morton_range(a1.morton_code, a1.morton_code)
        assert a1 in matches

    def test_query_radius_matching(self) -> None:
        engine = MeshCanvasEngine()
        a1 = engine.insert_asset(37.7710, -122.4200, asset_id=1)
        a2 = engine.insert_asset(37.7712, -122.4200, asset_id=2)  # ~22m away
        a3 = engine.insert_asset(37.7800, -122.4100, asset_id=3)  # ~1.3km away

        near = engine.query_radius(37.7710, -122.4200, radius_m=50.0)
        assert a1 in near
        assert a2 in near
        assert a3 not in near

    def test_query_bbox_matching(self) -> None:
        engine = MeshCanvasEngine()
        a1 = engine.insert_asset(37.7750, -122.4200, asset_id=1)
        bbox = DEFAULT_DOMAIN_BBOX
        matches = engine.query_bbox(*bbox)
        assert a1 in matches

    def test_canvas_to_latlon_and_inverse(self) -> None:
        engine = MeshCanvasEngine()
        lat, lon = 37.7750, -122.4200
        cx, cy = engine.latlon_to_canvas(lat, lon)
        assert 0.0 <= cx <= engine.viewport_width
        assert 0.0 <= cy <= engine.viewport_height

        r_lat, r_lon = engine.canvas_to_latlon(cx, cy)
        assert abs(r_lat - lat) < 1e-4
        assert abs(r_lon - lon) < 1e-4

    def test_select_cell_and_select_morton(self) -> None:
        engine = MeshCanvasEngine()
        engine.select_cell(10, 20)
        assert engine.selected_cell_x == 10
        assert engine.selected_cell_y == 20
        assert (engine.status_word & MeshStatusBits.CELL_SELECTED) != 0

        mcode = morton2d_encode(30, 40)
        engine.select_morton(mcode)
        assert engine.selected_cell_x == 30
        assert engine.selected_cell_y == 40
        assert engine.selected_morton_code == mcode

    def test_asset_retrieval_and_removal(self) -> None:
        engine = MeshCanvasEngine()
        a = engine.insert_asset(37.771, -122.420, asset_id=42, asset_type="pump", tag="PMP-42")
        assert engine.assets.get(42) == a
        assert engine.remove_asset(42) == a
        assert engine.remove_asset(42) is None
        assert 42 not in engine.assets
